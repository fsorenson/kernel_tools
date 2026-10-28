"""
Stage 1.5: Caller enumeration for findings in static functions.

For each finding in a static function, scans all source files for direct
call sites of that function and returns per-call-site context.  The result
annotates each finding with caller_context before Stage 2 sees it.

Step A: find_call_sites() — locate call sites in the scanned file set.
Step B: identify_taint_param(), annotate_with_guards() — guard detection
        per call site using one-hop variable derivation from the argument.
Step C: annotate_findings() — full pipeline wired into the stages.
"""

import re

from kernel_analysis.parsers.c_parser import (
    parse_file, find_functions, find_calls_to, node_text, get_source_line,
    _walk,
)
from bounds_checker.parsers.taint_scanner import _find_guards_between


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Node types that represent a type specifier or qualifier — not a variable name.
_TYPE_NODE_TYPES = frozenset({
    'type_identifier', 'primitive_type', 'sized_type_specifier',
    'struct_specifier', 'union_specifier', 'enum_specifier',
    'type_qualifier', 'storage_class_specifier',
})

# C keywords and common kernel type names to exclude from identifier extraction.
_C_KEYWORDS = frozenset({
    'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'break', 'continue',
    'return', 'goto', 'default', 'sizeof', 'typedef', 'extern', 'static',
    'auto', 'register', 'const', 'volatile', 'inline', 'restrict',
    'int', 'char', 'short', 'long', 'float', 'double', 'void',
    'signed', 'unsigned', 'struct', 'union', 'enum',
    'NULL', 'true', 'false',
    'u8', 'u16', 'u32', 'u64', 's8', 's16', 's32', 's64',
    '__le16', '__le32', '__le64', '__be16', '__be32', '__be64',
    'GFP_KERNEL', 'GFP_ATOMIC', 'GFP_NOFS',
})


# ---------------------------------------------------------------------------
# Parameter name extraction
# ---------------------------------------------------------------------------

def _param_name_from_decl(param_decl_node, source):
    """
    Extract the variable name from a parameter_declaration node.

    The parameter name lives in the declarator subtree, not in the type
    subtree.  For `u32 extra`, the identifier is a direct child.  For
    `struct hdr *h`, it is inside a pointer_declarator child.
    """
    # Find the first child that is NOT a type specifier / qualifier.
    declarator = None
    for child in param_decl_node.children:
        if child.is_named and child.type not in _TYPE_NODE_TYPES:
            declarator = child
            break
    if declarator is None:
        return None
    # Walk the declarator subtree and return the last identifier found.
    last = None
    for n in _walk(declarator):
        if n.type == 'identifier':
            last = n
    return node_text(last, source) if last is not None else None


def fn_param_names(fn_def_node, source):
    """
    Return the ordered list of parameter names for a function_definition.

    Parameters with no determinable name (e.g., plain `void`) are None.
    """
    params = []

    def _scan_param_list(param_list):
        for child in param_list.children:
            if child.is_named and child.type == 'parameter_declaration':
                params.append(_param_name_from_decl(child, source))

    for child in fn_def_node.children:
        if child.type == 'function_declarator':
            for sub in child.children:
                if sub.type == 'parameter_list':
                    _scan_param_list(sub)
            break
        if child.type == 'pointer_declarator':
            # `static T *fn(params)` shape — find function_declarator inside.
            for inner in _walk(child):
                if inner.type == 'function_declarator':
                    for sub in inner.children:
                        if sub.type == 'parameter_list':
                            _scan_param_list(sub)
                    break
            break
    return params


# ---------------------------------------------------------------------------
# Taint parameter identification
# ---------------------------------------------------------------------------

def _arg_idents(arg_text):
    """Identifier names in an argument text string, keywords excluded."""
    return frozenset(
        t for t in re.findall(r'\b[A-Za-z_]\w*\b', arg_text)
        if t not in _C_KEYWORDS
    )


def identify_taint_param(finding, fn_body, source):
    """
    Return (param_name, param_index) for the parameter that roots the taint
    chain in this finding, or None if not determinable.

    Locates the taint source call expression on taint_line, collects the
    identifiers in its arguments, and intersects with the function's formal
    parameter list.  The first match (lowest parameter index) is returned.
    """
    taint_line = finding.get('taint_line')
    taint_fn   = finding.get('taint_source_fn')
    if not taint_line or not taint_fn:
        return None

    fn_def = fn_body.parent
    if fn_def is None or fn_def.type != 'function_definition':
        return None

    params = fn_param_names(fn_def, source)
    param_set = {p for p in params if p is not None}
    if not param_set:
        return None

    for _call, _name, arg_nodes, line in find_calls_to(fn_body, source, [taint_fn]):
        if line != taint_line:
            continue
        idents = set()
        for a in arg_nodes:
            for n in _walk(a):
                if n.type == 'identifier':
                    idents.add(node_text(n, source))
        matches = idents & param_set
        if matches:
            for idx, name in enumerate(params):
                if name in matches:
                    return (name, idx)
    return None


# ---------------------------------------------------------------------------
# Per-call-site guard detection
# ---------------------------------------------------------------------------

def _one_hop_derived(fn_body, root_names, source, call_line):
    """
    Variables in the caller that are assigned from expressions mentioning any
    name in root_names, before call_line.

    A single pass (one hop): does not chase chains like a→b→c.  Catches the
    common pattern where a struct pointer argument `h` is the source and the
    guard compares a field-derived local `len = le16_to_cpu(h->len)`.
    """
    derived = set(root_names)
    for n in _walk(fn_body):
        line = n.start_point[0] + 1
        if line >= call_line:
            continue
        if n.type == 'init_declarator':
            lhs = n.child_by_field_name('declarator')
            rhs = n.child_by_field_name('value')
        elif n.type == 'assignment_expression':
            # Only plain `=` assignments, not compound `+=` etc.
            op_node = next((c for c in n.children if not c.is_named), None)
            if op_node is None or node_text(op_node, source) != '=':
                continue
            lhs = n.child_by_field_name('left')
            rhs = n.child_by_field_name('right')
        else:
            continue
        if lhs is None or rhs is None or lhs.type != 'identifier':
            continue
        lhs_name = node_text(lhs, source)
        if lhs_name in derived:
            continue
        rhs_idents = {node_text(c, source) for c in _walk(rhs) if c.type == 'identifier'}
        if rhs_idents & derived:
            derived.add(lhs_name)
    return frozenset(derived)


def annotate_with_guards(call_sites, param_idx):
    """
    Add 'guarded' (bool | None) and 'guard_kind' (str) to each call site.

    `param_idx` is the 0-based index of the taint-originating parameter.
    None means the parameter could not be identified; all sites get
    guarded=None.

    Files are parsed once per unique file path.
    """
    if param_idx is None:
        for cs in call_sites:
            cs['guarded']    = None
            cs['guard_kind'] = 'param-unknown'
        return call_sites

    # Group by file to parse each file at most once.
    by_file = {}
    for cs in call_sites:
        by_file.setdefault(cs['file'], []).append(cs)

    for filepath, sites in by_file.items():
        try:
            tree, source = parse_file(filepath)
        except Exception:
            for cs in sites:
                cs['guarded']    = None
                cs['guard_kind'] = 'parse-error'
            continue

        fn_bodies = {f['name']: f['body'] for f in find_functions(tree, source)}

        for cs in sites:
            caller  = cs.get('caller_fn', '')
            call_ln = cs.get('line', 0)
            args    = cs.get('args', [])
            fn_body = fn_bodies.get(caller)

            if not caller or fn_body is None:
                cs['guarded']    = None
                cs['guard_kind'] = 'no-body'
                continue

            if param_idx >= len(args):
                cs['guarded']    = None
                cs['guard_kind'] = 'no-arg'
                continue

            # Variable names rooted in the argument at param_idx.
            root = _arg_idents(args[param_idx])
            if not root:
                cs['guarded']    = False
                cs['guard_kind'] = 'no-arg-names'
                continue

            # Expand to include one-hop derived variables.
            var_names = _one_hop_derived(fn_body, root, source, call_ln)

            guard = _find_guards_between(fn_body, var_names, 0, call_ln, source)
            cs['guarded']    = guard.found
            cs['guard_kind'] = guard.kind

    return call_sites


# ---------------------------------------------------------------------------
# Static storage-class detection
# ---------------------------------------------------------------------------

def is_static_fn(fn_def_node, source):
    """
    True if the function_definition node carries `static` storage class.

    Only the function_definition node is searched (not the declarator),
    which is where tree-sitter places the storage_class_specifier child.
    """
    for child in fn_def_node.children:
        if child.type == 'storage_class_specifier':
            if node_text(child, source).strip() == 'static':
                return True
    return False


# ---------------------------------------------------------------------------
# Snippet extraction
# ---------------------------------------------------------------------------

def _snippet(source, call_line, context=5):
    """
    `context` lines before call_line plus call_line itself, joined by newlines.

    call_line is 1-indexed.  Lines outside the file are silently omitted.
    """
    lines = source.split(b'\n')
    lo = max(0, call_line - 1 - context)   # 0-indexed start
    hi = call_line - 1                      # 0-indexed, inclusive
    return '\n'.join(
        lines[i].decode('utf-8', errors='replace').rstrip()
        for i in range(lo, min(hi + 1, len(lines)))
    )


# ---------------------------------------------------------------------------
# Call-site discovery
# ---------------------------------------------------------------------------

def find_call_sites(fn_name, paths, context_lines=5):
    """
    Scan all files in `paths` for direct calls to `fn_name`.

    Returns a list of dicts, one per call site:
      file        — source file path (str)
      line        — 1-based line number of the call expression
      caller_fn   — name of the enclosing function, or '' if at file scope
      args        — list of argument text strings, one per argument
      snippet     — `context_lines` preceding lines + the call line

    Only direct calls are found (identifier-named call expressions).
    Function pointer calls and macro-obscured calls are not matched.
    """
    results = []

    for path in paths:
        try:
            tree, source = parse_file(str(path))
        except Exception:
            continue

        # Build a range list for enclosing-function lookup.
        fn_ranges = [
            (f['start_line'], f['end_line'], f['name'])
            for f in find_functions(tree, source)
        ]

        for call_node, _, arg_nodes, call_line in find_calls_to(
                tree.root_node, source, [fn_name]):

            # Find the innermost enclosing function by line range.
            caller = ''
            for start, end, name in fn_ranges:
                if start <= call_line <= end:
                    caller = name
                    break

            arg_texts = [node_text(a, source) for a in arg_nodes]
            results.append({
                'file':      str(path),
                'line':      call_line,
                'caller_fn': caller,
                'args':      arg_texts,
                'arg_names': [_arg_idents(t) for t in arg_texts],
                'snippet':   _snippet(source, call_line, context_lines),
            })

    return results
