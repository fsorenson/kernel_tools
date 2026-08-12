"""
Intra-procedural taint scanner for kernel C code.

Tracks server-supplied values from their origin (calls to endian-conversion
and unaligned-read functions) through assignments and expressions to dangerous
sinks (memcpy, kmalloc, array indexing, etc.) without an intervening bounds check.

Categories detected:
  A — tainted value → pointer arithmetic → used as ptr argument to memory op
  B — tainted value → size argument to memory op or allocator
  C — tainted value → array subscript
  F — tainted value → loop iteration count
  H — tainted wide value stored in a narrower integer type (silent truncation)

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

# Maps each taint source to its natural return-value bit width.
# Used by Category H to detect when a wide server-supplied value is stored
# in a narrower integer type (silent truncation).
TAINT_SOURCE_WIDTHS = {
    'get_unaligned_le8':  8,  'get_unaligned_be8':  8,
    'get_unaligned_le16': 16, 'get_unaligned_be16': 16,
    'get_unaligned_le32': 32, 'get_unaligned_be32': 32,
    'get_unaligned_le64': 64, 'get_unaligned_be64': 64,
    'le16_to_cpu': 16, 'be16_to_cpu': 16, 'le16_to_cpus': 16,
    'le32_to_cpu': 32, 'be32_to_cpu': 32, 'le32_to_cpus': 32,
    'le64_to_cpu': 64, 'be64_to_cpu': 64, 'le64_to_cpus': 64,
    'ntohs': 16, 'ntohl': 32, 'ntohe': 32,
}

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
# Category H: type-width narrowing tables
# ---------------------------------------------------------------------------

# Maps C integer type names → bit width.  Only covers types that actually
# appear in kernel protocol parsing code; excludes pointer types.
_TYPE_WIDTHS = {
    # Kernel u/s typedefs
    'u8': 8,  '__u8': 8,  's8': 8,  '__s8': 8,
    'u16': 16, '__u16': 16, 's16': 16, '__s16': 16,
    'u32': 32, '__u32': 32, 's32': 32, '__s32': 32,
    'u64': 64, '__u64': 64, 's64': 64, '__s64': 64,
    # Endian-annotated types (same underlying width)
    '__le16': 16, '__be16': 16,
    '__le32': 32, '__be32': 32,
    '__le64': 64, '__be64': 64,
    # POSIX fixed-width
    'uint8_t': 8,  'int8_t': 8,
    'uint16_t': 16, 'int16_t': 16,
    'uint32_t': 32, 'int32_t': 32,
    'uint64_t': 64, 'int64_t': 64,
    # C primitives (kernel assumes LP64)
    'char': 8,  'unsigned char': 8,
    'short': 16, 'unsigned short': 16,
    'int': 32,  'unsigned int': 32, 'unsigned': 32,
    'long': 64, 'unsigned long': 64,
}


def _get_type_width(type_text):
    """Return bit width of a C integer type string, or None if unknown/pointer."""
    return _TYPE_WIDTHS.get(type_text.strip())


def _build_local_widths(fn_body, source):
    """
    Return {var_name: bit_width} for integer variables declared in fn_body.
    Skips pointer declarators; only covers scalar integer locals.

    Variables declared multiple times with conflicting widths (e.g. same name
    in if/else branches with different types) are excluded — we can't safely
    determine the intended width without scope tracking.
    """
    widths = {}
    conflicts = set()
    for n in _walk(fn_body):
        if n.type != 'declaration':
            continue
        type_node = n.child_by_field_name('type')
        if type_node is None:
            continue
        width = _get_type_width(node_text(type_node, source))
        if width is None:
            continue
        for child in n.children:
            if child.type == 'init_declarator':
                decl = child.children[0] if child.children else None
                if decl and decl.type == 'identifier':
                    name = node_text(decl, source)
                    if name in widths and widths[name] != width:
                        conflicts.add(name)
                    elif name not in conflicts:
                        widths[name] = width
            elif child.type == 'identifier':
                name = node_text(child, source)
                if name in widths and widths[name] != width:
                    conflicts.add(name)
                elif name not in conflicts:
                    widths[name] = width
            # pointer_declarator → skip (not an integer scalar)
    for name in conflicts:
        widths.pop(name, None)
    return widths


# Overflow-safe size helpers: if any of these wrap the size argument (or an
# operand within it), the arithmetic is already overflow-checked — don't flag.
_SAFE_SIZE_HELPERS = frozenset({
    'array_size',           # array_size(n, size) → SIZE_MAX on overflow
    'array3_size',          # array3_size(a, b, c)
    'size_mul',             # 5.8+: size_mul(a, b)
    'size_add',             # 5.8+: size_add(a, b)
    'struct_size',          # struct_size(p, member, n) for trailing-array allocs
    'check_mul_overflow',   # explicit check; caller handles the error path
    'check_add_overflow',
    'saturate_add',
})


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


def _find_overflow_in_size_arg(arg_node, source, tainted):
    """
    Detect integer overflow risk in a size/length argument.

    Checks whether the argument is a top-level binary * or + expression
    where at least one operand carries taint — without a safe overflow
    wrapper (_SAFE_SIZE_HELPERS) guarding the expression.

    Only examines the outermost binary expression (unwrapping one layer of
    parens/casts) to avoid multiple findings for chains like a * b * c.

    Returns a list with at most one dict:
        {'op', 'lhs_text', 'rhs_text', 'taint_source', 'tainted_var',
         'taint_line', 'taint_kind'}
    or [] if no overflow risk is found.
    """
    def _is_safe_call(node):
        if node.type != 'call_expression':
            return False
        fn_id = next((c for c in node.children if c.type == 'identifier'), None)
        return fn_id is not None and node_text(fn_id, source) in _SAFE_SIZE_HELPERS

    # If the whole arg is a safe helper, bail immediately.
    if _is_safe_call(arg_node):
        return []

    # Unwrap one layer of parentheses or cast to find the binary expression.
    target = arg_node
    if arg_node.type in ('parenthesized_expression', 'cast_expression'):
        for child in arg_node.children:
            if child.type == 'binary_expression':
                target = child
                break

    if target.type != 'binary_expression':
        return []

    op_types = {c.type for c in target.children}
    if '*' not in op_types and '+' not in op_types:
        return []
    op = '*' if '*' in op_types else '+'

    lhs = target.children[0]
    rhs = target.children[-1]

    # If either operand is itself a safe helper, the expression is protected.
    if _is_safe_call(lhs) or _is_safe_call(rhs):
        return []

    # Find taint in either operand.
    taint_src = tainted_var = taint_line_v = None
    taint_kind = 'value'
    for side in (lhs, rhs):
        src = _node_has_taint_source_call(side, source)
        if src:
            taint_src, tainted_var = src, node_text(side, source)[:60]
            taint_line_v = target.start_point[0] + 1
            break
        ref = _node_references_tainted_var(side, source, tainted)
        if ref:
            taint_src = tainted[ref]['source_fn']
            tainted_var = ref
            taint_line_v = tainted[ref]['line']
            taint_kind = tainted[ref]['kind']
            break

    if not taint_src:
        return []

    return [{
        'op':          op,
        'lhs_text':    node_text(lhs, source)[:60],
        'rhs_text':    node_text(rhs, source)[:60],
        'taint_source': taint_src,
        'tainted_var': tainted_var,
        'taint_line':  taint_line_v,
        'taint_kind':  taint_kind,
    }]


def _collect_tainted_args(args, source, tainted, call_line):
    """
    Return {arg_idx: taint_info} for arguments that carry taint.
    taint_info: {'var', 'source_fn', 'line', 'kind'}
    """
    result = {}
    for i, arg in enumerate(args):
        src = _node_has_taint_source_call(arg, source)
        if src:
            result[i] = {
                'var': node_text(arg, source)[:60],
                'source_fn': src,
                'line': call_line,
                'kind': 'value',
            }
        else:
            ref = _node_references_tainted_var(arg, source, tainted)
            if ref:
                info = tainted[ref]
                result[i] = {
                    'var': ref,
                    'source_fn': info['source_fn'],
                    'line': info['line'],
                    'kind': info['kind'],
                }
    return result


# ---------------------------------------------------------------------------
# Guard / check detection
# ---------------------------------------------------------------------------

_GUARD_CMP_OPS   = frozenset({'<', '<=', '>', '>=', '==', '!='})
_GUARD_TERM_STMTS = frozenset({
    'return_statement', 'goto_statement', 'break_statement', 'continue_statement',
})
_GUARD_TERM_CALLS = frozenset({
    'BUG', 'BUG_ON', 'BUG_ON_NULL', 'panic',
    'WARN', 'WARN_ON', 'WARN_ON_ONCE',
})


def _find_guards_between(fn_body, var_names, line_lo, line_hi, source):
    """
    Return True if a plausible bounds check on a variable in var_names appears
    between line_lo and line_hi.

    Two requirements beyond the original line-range check:

    1. Condition must contain a relational comparison (< <= > >= == !=) with
       at least one operand that references a variable in var_names.  This
       eliminates bare zero-tests (if (X)) and conditions that reference the
       variable in a non-comparison context.

    2. The check must actually gate the dangerous use, via either:
       a. Early-exit pattern: consequence or alternative contains a terminal
          statement (return/goto/break/continue/BUG/panic), OR
       b. Guarded-use pattern: the sink line (line_hi) falls textually inside
          the consequence or alternative, meaning the dangerous call only
          executes when the check passes.
    """
    if not var_names:
        return False

    def _cond_has_relational_var(cond_node):
        for n in _walk(cond_node):
            if n.type != 'binary_expression':
                continue
            if not any(c.type in _GUARD_CMP_OPS for c in n.children):
                continue
            for ident in _walk(n):
                if ident.type == 'identifier' and node_text(ident, source) in var_names:
                    return True
        return False

    def _has_terminal(subtree):
        for n in _walk(subtree):
            if n.type in _GUARD_TERM_STMTS:
                return True
            if n.type == 'call_expression':
                fn_id = next((c for c in n.children if c.type == 'identifier'), None)
                if fn_id and node_text(fn_id, source) in _GUARD_TERM_CALLS:
                    return True
        return False

    for node in _walk(fn_body):
        if node.type != 'if_statement':
            continue
        stmt_line = node.start_point[0] + 1
        if stmt_line <= line_lo or stmt_line >= line_hi:
            continue

        cond = node.child_by_field_name('condition')
        if cond is None or not _cond_has_relational_var(cond):
            continue

        consequence = node.child_by_field_name('consequence')
        alternative = node.child_by_field_name('alternative')

        # Early-exit pattern
        if consequence and _has_terminal(consequence):
            return True
        if alternative and _has_terminal(alternative):
            return True

        # Guarded-use pattern: dangerous call is inside this branch
        for branch in (consequence, alternative):
            if branch is None:
                continue
            b_lo = branch.start_point[0] + 1
            b_hi = branch.end_point[0] + 1
            if b_lo <= line_hi <= b_hi:
                return True

    return False


# ---------------------------------------------------------------------------
# Core taint walk (shared by intra and cross-function modes)
# ---------------------------------------------------------------------------

def _scan_body(fn_name, fn_body, source, filepath, initial_taint=None):
    """
    Core taint walk for one function body.

    initial_taint: optional {var_name: {'source_fn', 'line', 'kind'}} to pre-seed
        the taint state.  Used by cross-function Phase 1 (parameter simulation):
        treat a specific parameter as if it were tainted on entry.

    Returns:
        findings  — list of finding dicts (same schema as scan_function)
        call_events — list of {callee, line, call_snippet, tainted_args}
            for every call_expression that received at least one tainted argument.
            Used by cross-function Phase 2 to identify dangerous call sites.
    """
    tainted = dict(initial_taint) if initial_taint else {}
    findings = []
    call_events = []

    # Pre-build integer width map for Cat H narrowing detection.
    var_widths = _build_local_widths(fn_body, source)

    for node in _walk(fn_body):

        # ── Category H: type-width narrowing in declarations ──
        # Handled here (on declaration, not init_declarator) so we have the
        # declared type of the LHS without needing a parent-node lookup.
        if node.type == 'declaration':
            type_node = node.child_by_field_name('type')
            if type_node is None:
                continue
            dest_type = node_text(type_node, source)
            dest_width = _get_type_width(dest_type)
            if dest_width is None:
                continue
            for child in node.children:
                if child.type != 'init_declarator' or len(child.children) < 3:
                    continue
                decl_node = child.children[0]
                if decl_node.type != 'identifier':
                    continue   # pointer declarator — skip
                dest_var = node_text(decl_node, source)
                rhs = child.children[2]
                line = child.start_point[0] + 1

                src_fn_h = _node_has_taint_source_call(rhs, source)
                src_width_h = TAINT_SOURCE_WIDTHS.get(src_fn_h) if src_fn_h else None
                ref_h = None
                if src_fn_h is None:
                    ref_h = _node_references_tainted_var(rhs, source, tainted)
                    if ref_h:
                        src_fn_h = tainted[ref_h]['source_fn']
                        src_width_h = tainted[ref_h].get('width')

                if src_fn_h and src_width_h and src_width_h > dest_width:
                    guard_vars = {ref_h} if ref_h else set()
                    taint_ln = tainted[ref_h]['line'] if ref_h else line
                    guarded_h = _find_guards_between(
                        fn_body, guard_vars, taint_ln, line, source,
                    ) if guard_vars and taint_ln < line else False
                    snippet = get_source_line(source, line)
                    findings.append({
                        'function':        fn_name,
                        'file':            str(filepath),
                        'category':        'H',
                        'severity':        'medium',
                        'taint_source_fn': src_fn_h,
                        'tainted_var':     dest_var,
                        'taint_line':      line,
                        'taint_snippet':   snippet,
                        'sink_fn':         'narrowing_assignment',
                        'sink_line':       line,
                        'sink_snippet':    snippet,
                        'sink_arg_index':  0,
                        'sink_arg_role':   'narrowed_value',
                        'src_width':       src_width_h,
                        'dest_width':      dest_width,
                        'dest_type':       dest_type,
                        'possibly_guarded': guarded_h,
                        'reason': (
                            f"{src_width_h}-bit value from {src_fn_h}() silently "
                            f"truncated to {dest_width}-bit {dest_type} in {dest_var!r}; "
                            f"a later bounds check on {dest_var!r} may pass even when "
                            f"the original value would not"
                        ),
                    })
            continue   # skip the rest of the loop body for declaration nodes

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
                rhs_text = node_text(rhs, source)
                kind = 'pointer' if '+' in rhs_text or '-' in rhs_text else 'value'
                tainted[lhs_var] = {
                    'source_fn': src_fn,
                    'line': node.start_point[0] + 1,
                    'kind': kind,
                    'width': TAINT_SOURCE_WIDTHS.get(src_fn),
                }
                # Cat H: assignment_expression narrowing (not init_declarator —
                # that case is handled in the declaration branch above).
                if (node.type == 'assignment_expression' and lhs_var in var_widths):
                    dest_width_h = var_widths[lhs_var]
                    src_width_h = TAINT_SOURCE_WIDTHS.get(src_fn)
                    if src_width_h and src_width_h > dest_width_h:
                        line_h = node.start_point[0] + 1
                        snippet_h = get_source_line(source, line_h)
                        findings.append({
                            'function':        fn_name,
                            'file':            str(filepath),
                            'category':        'H',
                            'severity':        'medium',
                            'taint_source_fn': src_fn,
                            'tainted_var':     lhs_var,
                            'taint_line':      line_h,
                            'taint_snippet':   snippet_h,
                            'sink_fn':         'narrowing_assignment',
                            'sink_line':       line_h,
                            'sink_snippet':    snippet_h,
                            'sink_arg_index':  0,
                            'sink_arg_role':   'narrowed_value',
                            'src_width':       src_width_h,
                            'dest_width':      dest_width_h,
                            'dest_type':       f'u{dest_width_h}',
                            'possibly_guarded': False,
                            'reason': (
                                f"{src_width_h}-bit value from {src_fn}() silently "
                                f"truncated to {dest_width_h}-bit {lhs_var!r}; "
                                f"a later bounds check on {lhs_var!r} may pass even "
                                f"when the original value would not"
                            ),
                        })
                continue

            ref = _node_references_tainted_var(rhs, source, tainted)
            if ref:
                ref_kind = tainted[ref]['kind']
                rhs_text = node_text(rhs, source)
                kind = 'pointer' if ('+' in rhs_text or '-' in rhs_text or
                                     ref_kind == 'pointer') else 'value'
                tainted[lhs_var] = {
                    'source_fn': tainted[ref]['source_fn'],
                    'line': tainted[ref]['line'],   # keep the original source line
                    'kind': kind,
                    'width': tainted[ref].get('width'),  # propagate source width
                }
                # Cat H: narrowing via tainted variable (assignment_expression only)
                if (node.type == 'assignment_expression' and lhs_var in var_widths):
                    dest_width_h = var_widths[lhs_var]
                    src_width_h = tainted[ref].get('width')
                    if src_width_h and src_width_h > dest_width_h:
                        line_h = node.start_point[0] + 1
                        src_fn_h = tainted[ref]['source_fn']
                        snippet_h = get_source_line(source, line_h)
                        taint_ln_h = tainted[ref]['line']
                        guarded_h = _find_guards_between(
                            fn_body, {ref}, taint_ln_h, line_h, source,
                        ) if taint_ln_h < line_h else False
                        findings.append({
                            'function':        fn_name,
                            'file':            str(filepath),
                            'category':        'H',
                            'severity':        'medium',
                            'taint_source_fn': src_fn_h,
                            'tainted_var':     lhs_var,
                            'taint_line':      line_h,
                            'taint_snippet':   snippet_h,
                            'sink_fn':         'narrowing_assignment',
                            'sink_line':       line_h,
                            'sink_snippet':    snippet_h,
                            'sink_arg_index':  0,
                            'sink_arg_role':   'narrowed_value',
                            'src_width':       src_width_h,
                            'dest_width':      dest_width_h,
                            'dest_type':       f'u{dest_width_h}',
                            'possibly_guarded': guarded_h,
                            'reason': (
                                f"{src_width_h}-bit value (via {ref!r}, from "
                                f"{src_fn_h}()) silently truncated to "
                                f"{dest_width_h}-bit {lhs_var!r}; a later bounds "
                                f"check on {lhs_var!r} may pass even when the "
                                f"original value would not"
                            ),
                        })

        # ── Sink / call site ──
        elif node.type == 'call_expression':
            fn_id = next((c for c in node.children if c.type == 'identifier'), None)
            if not fn_id:
                continue
            callee = node_text(fn_id, source)
            args = _arg_nodes(node)
            call_line = node.start_point[0] + 1

            # Emit call event for any call with tainted arguments; used by
            # cross-function Phase 2 to match against param_sink_map.
            t_args = _collect_tainted_args(args, source, tainted, call_line)
            if t_args:
                call_events.append({
                    'callee': callee,
                    'line': call_line,
                    'call_snippet': get_source_line(source, call_line),
                    'tainted_args': t_args,
                })

            sink_info = DANGEROUS_SINKS.get(callee)
            if not sink_info:
                continue

            sink_fn = callee
            sink_line = call_line
            sink_snippet = get_source_line(source, sink_line)

            # Check size arguments (Category B)
            for idx in sink_info.get('size_args', []):
                if idx >= len(args):
                    continue
                arg = args[idx]
                role = ('count' if sink_info.get('is_counted') and
                        idx == sink_info['size_args'][0] else 'size')

                src_fn = _node_has_taint_source_call(arg, source)
                tainted_var = None
                taint_line = sink_line

                if src_fn:
                    tainted_var = node_text(arg, source)[:40]
                    taint_line = sink_line
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

            # Integer overflow check: tainted value in multiplicative/additive
            # size expression (e.g., kmalloc(count * sizeof(foo))).
            # Emits a separate 'size_mul_overflow' finding; the dedup pass at
            # the end of _scan_body suppresses the redundant plain Cat B for
            # the same (sink_fn, sink_line, arg_idx).
            for idx in sink_info.get('size_args', []):
                if idx >= len(args):
                    continue
                for hit in _find_overflow_in_size_arg(args[idx], source, tainted):
                    guarded = _find_guards_between(
                        fn_body, {hit['tainted_var']},
                        hit['taint_line'], sink_line, source,
                    )
                    op_word = 'multiplication' if hit['op'] == '*' else 'addition'
                    findings.append({
                        'function':        fn_name,
                        'file':            str(filepath),
                        'category':        'B',
                        'severity':        'high',
                        'overflow':        True,
                        'overflow_op':     hit['op'],
                        'overflow_lhs':    hit['lhs_text'],
                        'overflow_rhs':    hit['rhs_text'],
                        'taint_source_fn': hit['taint_source'],
                        'tainted_var':     hit['tainted_var'],
                        'taint_line':      hit['taint_line'],
                        'taint_snippet':   get_source_line(source, hit['taint_line']),
                        'sink_fn':         sink_fn,
                        'sink_line':       sink_line,
                        'sink_snippet':    sink_snippet,
                        'sink_arg_index':  idx,
                        'sink_arg_role':   'size_mul_overflow',
                        'possibly_guarded': guarded,
                        'reason': (
                            f"integer overflow risk: {hit['lhs_text']} {hit['op']} "
                            f"{hit['rhs_text']} passed as size to {sink_fn}(); "
                            f"tainted {hit['tainted_var']} (from {hit['taint_source']}()) "
                            f"could cause {op_word} to wrap, producing an undersized "
                            f"allocation — use kmalloc_array() or check_mul_overflow()"
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

        # ── Category F: loop with server-supplied iteration bound ──
        elif node.type in ('for_statement', 'while_statement', 'do_statement'):
            cond = node.child_by_field_name('condition')
            if cond is None:
                continue

            loop_line = node.start_point[0] + 1
            src_fn = ref = None
            taint_line = loop_line

            # Walk condition for a relational comparison (< <= > >=) that
            # involves a tainted variable.  Equality checks (== !=) are state
            # tests, not iteration bounds — skip them.
            for n in _walk(cond):
                if n.type != 'binary_expression':
                    continue
                if not any(c.type in ('<', '<=', '>', '>=') for c in n.children):
                    continue
                ref = _node_references_tainted_var(n, source, tainted)
                if ref:
                    src_fn = tainted[ref]['source_fn']
                    taint_line = tainted[ref]['line']
                    break
                src_fn = _node_has_taint_source_call(n, source)
                if src_fn:
                    break

            if src_fn is None:
                continue

            tainted_var_name = ref or '(inline)'
            loop_type = {
                'for_statement':   'for_loop',
                'while_statement': 'while_loop',
                'do_statement':    'do_loop',
            }[node.type]

            sink_line = loop_line
            sink_snippet = get_source_line(source, sink_line)
            guarded = _find_guards_between(
                fn_body, {ref} if ref else set(),
                taint_line, sink_line, source,
            )
            findings.append({
                'function':        fn_name,
                'file':            str(filepath),
                'category':        'F',
                'severity':        'medium',
                'taint_source_fn': src_fn,
                'tainted_var':     tainted_var_name,
                'taint_line':      taint_line,
                'taint_snippet':   get_source_line(source, taint_line),
                'sink_fn':         loop_type,
                'sink_line':       sink_line,
                'sink_snippet':    sink_snippet,
                'sink_arg_index':  0,
                'sink_arg_role':   'loop_bound',
                'possibly_guarded': guarded,
                'reason': (
                    f"server-supplied value {tainted_var_name!r} "
                    f"(from {src_fn}()) controls loop iteration count "
                    f"without validation against buffer size"
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

    # Deduplicate and resolve conflicts between overflow and plain Cat B.
    # When an overflow finding and a plain Cat B cover the same
    # (function, sink_fn, sink_line, arg_idx), suppress the plain Cat B —
    # the overflow finding is more specific and has the right fix suggestion.
    overflow_locs = {
        (f['function'], f['sink_fn'], f['sink_line'], f['sink_arg_index'])
        for f in findings if f.get('overflow')
    }

    seen = set()
    unique = []
    for f in findings:
        loc = (f['function'], f['sink_fn'], f['sink_line'], f['sink_arg_index'])
        if (f['category'] == 'B' and not f.get('overflow') and
                f['sink_arg_role'] in ('size', 'count') and loc in overflow_locs):
            continue   # superseded by the more specific overflow finding
        key = (f['category'], f.get('sink_arg_role', ''), f['tainted_var'],
               f['sink_fn'], f['sink_line'])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique, call_events


# ---------------------------------------------------------------------------
# Public API
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
    findings, _ = _scan_body(fn_name, fn_body, source, filepath)
    return findings


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
            findings, _ = _scan_body(
                fn['name'], fn['body'], source, path
            )
            all_findings.extend(findings)

    return all_findings
