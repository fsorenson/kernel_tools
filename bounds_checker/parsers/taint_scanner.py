"""
Intra-procedural taint scanner for kernel C code.

Tracks server-supplied values from their origin (calls to endian-conversion
and unaligned-read functions) through assignments and expressions to dangerous
sinks (memcpy, kmalloc, array indexing, etc.) without an intervening bounds check.

Categories detected:
  A — tainted value → pointer arithmetic → used as ptr argument to memory op
  B — tainted value → size argument to memory op or allocator
  C — tainted value → array subscript

Each finding includes the taint source location, the sink location, and a
"possibly_guarded" flag indicating whether a conditional on the tainted variable
appears between the source and sink (line-number heuristic; the LLM stage
reasons about it more carefully).
"""

from kernel_analysis.parsers.c_parser import (
    _walk, node_text, get_source_line,
    find_calls_to, extract_local_array_decls, find_alloc_vars,
    ALLOC_FUNCS, TYPE_NODES,
)


# ---------------------------------------------------------------------------
# Taint sources: functions that return server/network-supplied values
# ---------------------------------------------------------------------------

TAINT_SOURCES = frozenset({
    # Unaligned LE reads (most common in SMB/CIFS)
    'get_unaligned_le16', 'get_unaligned_le32', 'get_unaligned_le64',
    'get_unaligned_le8',
    # Unaligned BE reads (NFS, others)
    'get_unaligned_be16', 'get_unaligned_be32', 'get_unaligned_be64',
    'get_unaligned_be8',
    # Endian conversion from __le/__be struct fields
    'le16_to_cpu', 'le32_to_cpu', 'le64_to_cpu',
    'be16_to_cpu', 'be32_to_cpu', 'be64_to_cpu',
    # In-place endian store/load helpers that return the value
    'le16_to_cpus', 'le32_to_cpus', 'le64_to_cpus',
    # ntohs / ntohl (network byte order, used in some subsystems)
    'ntohs', 'ntohl', 'ntohe',
})

# ---------------------------------------------------------------------------
# Dangerous sinks: functions where a tainted argument is a bug
# ---------------------------------------------------------------------------

# Maps function name → argument role classification:
#   'size_args'   — argument indices that are sizes/lengths (Category B)
#   'ptr_args'    — argument indices that are destination/source pointers
#                   where a tainted value used in pointer arithmetic lands (Category A)
#   'alloc'       — True if this is an allocator (size_args is the allocation size)
#
# Argument indices are 0-based.

DANGEROUS_SINKS = {
    # Memory operations
    'memcpy':            {'size_args': [2], 'ptr_args': [0, 1]},
    'memmove':           {'size_args': [2], 'ptr_args': [0, 1]},
    'memset':            {'size_args': [2], 'ptr_args': [0]},
    'memcmp':            {'size_args': [2], 'ptr_args': [0, 1]},
    # String operations
    'strncpy':           {'size_args': [2], 'ptr_args': [0]},
    'strlcpy':           {'size_args': [2], 'ptr_args': [0]},
    'strlcat':           {'size_args': [2], 'ptr_args': [0]},
    'strncmp':           {'size_args': [2]},
    'strncat':           {'size_args': [2], 'ptr_args': [0]},
    'snprintf':          {'size_args': [1], 'ptr_args': [0]},
    'scnprintf':         {'size_args': [1], 'ptr_args': [0]},
    # User-space copy
    'copy_to_user':      {'size_args': [2], 'ptr_args': [1]},
    'copy_from_user':    {'size_args': [2], 'ptr_args': [0]},
    '__copy_to_user':    {'size_args': [2], 'ptr_args': [1]},
    '__copy_from_user':  {'size_args': [2], 'ptr_args': [0]},
    'put_user':          {'size_args': []},   # single value — flag if ptr is tainted
    # Allocation — size argument
    'kmalloc':           {'size_args': [0], 'alloc': True},
    'kzalloc':           {'size_args': [0], 'alloc': True},
    'kvmalloc':          {'size_args': [0], 'alloc': True},
    'kvzalloc':          {'size_args': [0], 'alloc': True},
    'vmalloc':           {'size_args': [0], 'alloc': True},
    'vzalloc':           {'size_args': [0], 'alloc': True},
    '__kmalloc':         {'size_args': [0], 'alloc': True},
    'kmalloc_node':      {'size_args': [0], 'alloc': True},
    'kzalloc_node':      {'size_args': [0], 'alloc': True},
    'krealloc':          {'size_args': [1], 'alloc': True},
    'devm_kmalloc':      {'size_args': [1], 'alloc': True},
    'devm_kzalloc':      {'size_args': [1], 'alloc': True},
    # Two-argument allocators (count × element size): both args are relevant
    'kcalloc':           {'size_args': [0, 1], 'alloc': True, 'is_counted': True},
    'kmalloc_array':     {'size_args': [0, 1], 'alloc': True, 'is_counted': True},
    'devm_kcalloc':      {'size_args': [1, 2], 'alloc': True, 'is_counted': True},
}

# For Category C: these operators produce a subscript expression
_SUBSCRIPT_NODE = 'subscript_expression'


# ---------------------------------------------------------------------------
# Expression taint analysis helpers
# ---------------------------------------------------------------------------

def _node_has_taint_source_call(node, source):
    """Return the first TAINT_SOURCES function name found in node, or None."""
    for n in _walk(node):
        if n.type != 'call_expression':
            continue
        fn_id = next((c for c in n.children if c.type == 'identifier'), None)
        if fn_id:
            name = node_text(fn_id, source)
            if name in TAINT_SOURCES:
                return name
    return None


def _node_references_tainted_var(node, source, tainted):
    """Return first tainted variable name found in node's identifiers, or None."""
    for n in _walk(node):
        if n.type == 'identifier':
            name = node_text(n, source)
            if name in tainted:
                return name
    return None


def _extract_lhs_var(assign_node, source):
    """
    Extract the variable name from the left-hand side of an assignment or
    init_declarator.  Returns None for complex LHS patterns (struct member, etc.).
    """
    # assignment_expression: [lhs, op, rhs]
    if assign_node.type == 'assignment_expression':
        lhs = assign_node.children[0]
        if lhs.type == 'identifier':
            return node_text(lhs, source)
        # Ignore struct member assignments — we don't track field-level taint
        return None
    # init_declarator: [declarator, '=', initializer]
    if assign_node.type == 'init_declarator':
        decl = assign_node.children[0]
        if decl.type == 'identifier':
            return node_text(decl, source)
        # pointer_declarator: *var = ...
        if decl.type == 'pointer_declarator':
            ident = next((c for c in decl.children if c.type == 'identifier'), None)
            if ident:
                return node_text(ident, source)
    return None


def _arg_nodes(call_node):
    """Return the non-punctuation argument nodes for a call_expression."""
    arg_list = next(
        (c for c in call_node.children if c.type == 'argument_list'), None
    )
    if not arg_list:
        return []
    return [c for c in arg_list.children if c.type not in ('(', ')', ',')]


# ---------------------------------------------------------------------------
# Guard / check detection
# ---------------------------------------------------------------------------

def _find_guards_between(fn_body, var_names, line_lo, line_hi, source):
    """
    Return True if any if_statement between line_lo and line_hi has a
    condition that references any variable in var_names.
    This is a line-number heuristic — does not account for control flow.
    """
    for node in _walk(fn_body):
        if node.type != 'if_statement':
            continue
        stmt_line = node.start_point[0] + 1
        if stmt_line <= line_lo or stmt_line >= line_hi:
            continue
        cond = node.child_by_field_name('condition')
        if cond is None:
            continue
        for n in _walk(cond):
            if n.type == 'identifier' and node_text(n, source) in var_names:
                return True
    return False


# ---------------------------------------------------------------------------
# Main per-function taint scan
# ---------------------------------------------------------------------------

def scan_function(fn_name, fn_def_node, fn_body, source, filepath):
    """
    Scan one function body for taint flows from TAINT_SOURCES to DANGEROUS_SINKS.

    Returns a list of finding dicts, one per (taint_source, sink) pair:
      {
        'function':        str,
        'file':            str,
        'category':        'A'|'B'|'C',
        'severity':        'high'|'medium',
        'taint_source_fn': str,      # e.g. 'get_unaligned_le16'
        'tainted_var':     str,      # variable name that carries the taint
        'taint_line':      int,
        'taint_snippet':   str,
        'sink_fn':         str,      # e.g. 'memcpy'
        'sink_line':       int,
        'sink_snippet':    str,
        'sink_arg_index':  int,      # which argument is tainted
        'sink_arg_role':   str,      # 'size', 'pointer', 'subscript', 'count'
        'possibly_guarded': bool,
        'reason':          str,
      }
    """
    findings = []

    # tainted: {var_name: {'source_fn': str, 'line': int, 'kind': 'value'|'pointer'}}
    # 'value'   — holds a numeric server-supplied value (Category B/C risk)
    # 'pointer' — holds a pointer derived from server-supplied arithmetic (Category A risk)
    tainted = {}

    # Walk the function body in source order, updating taint state and checking sinks
    for node in _walk(fn_body):

        # ── Taint source: direct assignment or init with taint source in RHS ──
        if node.type in ('assignment_expression', 'init_declarator'):
            children = node.children
            if len(children) < 3 or children[1].type != '=':
                continue
            rhs = children[2]
            lhs_var = _extract_lhs_var(node, source)
            if lhs_var is None:
                continue

            src_fn = _node_has_taint_source_call(rhs, source)
            if src_fn:
                # Determine kind: if the RHS also has binary arithmetic mixing a
                # pointer with the tainted value, it's a pointer taint.
                # Otherwise it's a value taint.
                rhs_text = node_text(rhs, source)
                kind = 'pointer' if '+' in rhs_text or '-' in rhs_text else 'value'
                tainted[lhs_var] = {
                    'source_fn': src_fn,
                    'line': node.start_point[0] + 1,
                    'kind': kind,
                }
                continue

            # Propagation: RHS references an already-tainted variable
            ref = _node_references_tainted_var(rhs, source, tainted)
            if ref:
                ref_kind = tainted[ref]['kind']
                # Propagated through arithmetic → pointer taint; direct copy → same kind
                rhs_text = node_text(rhs, source)
                kind = 'pointer' if ('+' in rhs_text or '-' in rhs_text or
                                     ref_kind == 'pointer') else 'value'
                tainted[lhs_var] = {
                    'source_fn': tainted[ref]['source_fn'],
                    'line': tainted[ref]['line'],   # keep the original source line
                    'kind': kind,
                }

        # ── Sink: dangerous function call ──
        elif node.type == 'call_expression':
            fn_id = next((c for c in node.children if c.type == 'identifier'), None)
            if not fn_id:
                continue
            sink_fn = node_text(fn_id, source)
            sink_info = DANGEROUS_SINKS.get(sink_fn)
            if not sink_info:
                continue

            args = _arg_nodes(node)
            sink_line = node.start_point[0] + 1
            sink_snippet = get_source_line(source, sink_line)

            # Check size arguments (Categories B and overflow)
            for idx in sink_info.get('size_args', []):
                if idx >= len(args):
                    continue
                arg = args[idx]
                role = 'count' if sink_info.get('is_counted') and idx == sink_info['size_args'][0] else 'size'

                # Direct taint source in argument expression
                src_fn = _node_has_taint_source_call(arg, source)
                tainted_var = None
                taint_line = sink_line

                if src_fn:
                    tainted_var = node_text(arg, source)[:40]
                    taint_line = sink_line  # same line
                else:
                    ref = _node_references_tainted_var(arg, source, tainted)
                    if ref:
                        src_fn = tainted[ref]['source_fn']
                        tainted_var = ref
                        taint_line = tainted[ref]['line']

                if src_fn:
                    guarded = _find_guards_between(
                        fn_body, {tainted_var} if tainted_var else set(),
                        taint_line, sink_line, source
                    )
                    findings.append({
                        'function': fn_name,
                        'file': str(filepath),
                        'category': 'B',
                        'severity': 'high',
                        'taint_source_fn': src_fn,
                        'tainted_var': tainted_var or '(inline)',
                        'taint_line': taint_line,
                        'taint_snippet': get_source_line(source, taint_line),
                        'sink_fn': sink_fn,
                        'sink_line': sink_line,
                        'sink_snippet': sink_snippet,
                        'sink_arg_index': idx,
                        'sink_arg_role': role,
                        'possibly_guarded': guarded,
                        'reason': (
                            f"server-supplied value from {src_fn}() used as {role} "
                            f"argument {idx} to {sink_fn}() without bounds check"
                        ),
                    })

            # Check pointer arguments (Category A)
            for idx in sink_info.get('ptr_args', []):
                if idx >= len(args):
                    continue
                arg = args[idx]
                ref = _node_references_tainted_var(arg, source, tainted)
                if not ref:
                    continue
                info = tainted[ref]
                if info['kind'] != 'pointer':
                    continue  # Only flag pointer-tainted values as ptr args
                taint_line = info['line']
                guarded = _find_guards_between(
                    fn_body, {ref}, taint_line, sink_line, source
                )
                findings.append({
                    'function': fn_name,
                    'file': str(filepath),
                    'category': 'A',
                    'severity': 'high',
                    'taint_source_fn': info['source_fn'],
                    'tainted_var': ref,
                    'taint_line': taint_line,
                    'taint_snippet': get_source_line(source, taint_line),
                    'sink_fn': sink_fn,
                    'sink_line': sink_line,
                    'sink_snippet': sink_snippet,
                    'sink_arg_index': idx,
                    'sink_arg_role': 'pointer',
                    'possibly_guarded': guarded,
                    'reason': (
                        f"pointer derived from server-supplied {info['source_fn']}() "
                        f"used as pointer argument {idx} to {sink_fn}() "
                        f"without bounds check"
                    ),
                })

        # ── Category C: array subscript with tainted index ──
        elif node.type == _SUBSCRIPT_NODE:
            # subscript_expression: [array, '[', index, ']']
            idx_node = next(
                (c for c in node.children if c.type not in ('[', ']') and
                 c != node.children[0]),
                None,
            )
            if idx_node is None:
                continue

            src_fn = _node_has_taint_source_call(idx_node, source)
            ref = None
            taint_line = node.start_point[0] + 1

            if src_fn:
                pass  # direct taint source inline in subscript
            else:
                ref = _node_references_tainted_var(idx_node, source, tainted)
                if ref:
                    src_fn = tainted[ref]['source_fn']
                    taint_line = tainted[ref]['line']

            if not src_fn:
                continue

            sink_line = node.start_point[0] + 1
            sink_snippet = get_source_line(source, sink_line)
            guarded = _find_guards_between(
                fn_body, {ref} if ref else set(),
                taint_line, sink_line, source
            )
            findings.append({
                'function': fn_name,
                'file': str(filepath),
                'category': 'C',
                'severity': 'high',
                'taint_source_fn': src_fn,
                'tainted_var': ref or node_text(idx_node, source)[:40],
                'taint_line': taint_line,
                'taint_snippet': get_source_line(source, taint_line),
                'sink_fn': '[]',
                'sink_line': sink_line,
                'sink_snippet': sink_snippet,
                'sink_arg_index': 0,
                'sink_arg_role': 'subscript',
                'possibly_guarded': guarded,
                'reason': (
                    f"server-supplied value from {src_fn}() used as array subscript "
                    f"without bounds check"
                ),
            })

    # Deduplicate: same (category, tainted_var, sink_fn, sink_line)
    seen = set()
    unique = []
    for f in findings:
        key = (f['category'], f['tainted_var'], f['sink_fn'], f['sink_line'])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def scan_files(source_paths, verbose=False):
    """
    Scan a list of source files and return all taint findings.

    Returns list of finding dicts (see scan_function for schema).
    """
    from kernel_analysis.parsers.c_parser import parse_file, find_functions

    all_findings = []
    for path in source_paths:
        try:
            tree, source = parse_file(path)
        except Exception as e:
            if verbose:
                print(f"  [skip {path}: {e}]")
            continue
        for fn in find_functions(tree, source):
            findings = scan_function(
                fn['name'], fn['node'], fn['body'], source, path
            )
            all_findings.extend(findings)

    return all_findings
