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

import json
import re
from pathlib import Path

from kernel_analysis.parsers.c_parser import (
    parse_file, find_functions, find_calls_to, node_text, get_source_line,
    _walk,
)
from bounds_checker.parsers.taint_scanner import _find_guards_between, _has_sizeof_guard


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


# ---------------------------------------------------------------------------
# Efficient multi-function call-site index
# ---------------------------------------------------------------------------

def build_call_site_index(fn_names, paths, context_lines=5):
    """
    Scan each file in `paths` ONCE and collect call sites for all fn_names.

    Returns {fn_name: [call_site_dict]}.  Equivalent to calling
    find_call_sites() for each name separately but parses each file only once,
    which matters when there are many unique function names with findings.
    """
    index = {name: [] for name in fn_names}
    fn_set = set(fn_names)
    if not fn_set:
        return index

    for path in paths:
        try:
            tree, source = parse_file(str(path))
        except Exception:
            continue

        fn_ranges = [
            (f['start_line'], f['end_line'], f['name'])
            for f in find_functions(tree, source)
        ]

        for call_node, name, arg_nodes, call_line in find_calls_to(
                tree.root_node, source, fn_set):
            caller = ''
            for start, end, fn in fn_ranges:
                if start <= call_line <= end:
                    caller = fn
                    break
            arg_texts = [node_text(a, source) for a in arg_nodes]
            index[name].append({
                'file':      str(path),
                'line':      call_line,
                'caller_fn': caller,
                'args':      arg_texts,
                'arg_names': [_arg_idents(t) for t in arg_texts],
                'snippet':   _snippet(source, call_line, context_lines),
            })

    return index


# ---------------------------------------------------------------------------
# Cat I: caller-side sizeof guard check
# ---------------------------------------------------------------------------

def annotate_cat_i_sizeof_guard(call_sites, param_idx, struct_type):
    """
    For each call site of a Cat I static function, check whether the caller
    has a sizeof(struct_type) or sizeof(*arg_var) guard before the call.

    Unlike annotate_with_guards (which checks VALUE bounds on the tainted
    argument), this checks for a SIZE check: `if (len < sizeof(*rsp))` or
    `if (len < sizeof(struct smb2_read_rsp))` anywhere before the call line.

    `param_idx` is the 0-based index of the struct pointer parameter.
    `struct_type` is the struct name (e.g. 'smb2_read_rsp').
    """
    if param_idx is None:
        for cs in call_sites:
            cs['guarded']    = None
            cs['guard_kind'] = 'param-unknown'
        return call_sites

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
            caller   = cs.get('caller_fn', '')
            call_ln  = cs.get('line', 0)
            args     = cs.get('args', [])
            fn_body  = fn_bodies.get(caller)

            if not caller or fn_body is None:
                cs['guarded']    = None
                cs['guard_kind'] = 'no-body'
                continue

            # Resolve the argument variable name at param_idx (for text match).
            # Fall back to struct-type-name-only match when the arg is complex.
            arg_var = None
            if param_idx < len(args):
                arg_text = args[param_idx].strip()
                if (arg_text.isidentifier()
                        and arg_text not in _C_KEYWORDS):
                    arg_var = arg_text

            guarded = _has_sizeof_guard(
                fn_body, arg_var, struct_type, call_ln, source
            )
            cs['guarded']    = guarded
            cs['guard_kind'] = 'sizeof_check' if guarded else ''

    return call_sites


def annotate_cat_i_findings(findings, paths):
    """
    Attach caller_context to Cat I findings in static functions where
    ptr_var (tainted_var) is a function parameter, not a locally-cast variable.

    At each call site of the static function, checks whether the caller has a
    sizeof(struct T) guard before the call — if all callers do, the finding
    is a dispatch-layer false positive.  This complements Stage 2 prompt
    item 2e (Cat I dispatch-layer check) by resolving the question statically.

    Annotates in place; only Cat I findings with determinable = True receive
    a caller_context.  Non-static functions and locally-cast variables get
    determinable = False with a reason string.
    """
    cat_i = [f for f in findings
             if f.get('category') == 'I' and f.get('propagation') == 'intra']
    if not cat_i:
        return

    # ── Step 1: Parse callee files to check static-ness and param membership ──
    file_cache = {}

    def _fdata(fp):
        if fp not in file_cache:
            try:
                tree, source = parse_file(fp)
                file_cache[fp] = {
                    'source': source,
                    'fns': {fn['name']: fn for fn in find_functions(tree, source)},
                }
            except Exception:
                file_cache[fp] = None
        return file_cache[fp]

    static_fns  = set()
    param_idxs  = {}   # (fn_name, ptr_var) -> int or None

    for f in cat_i:
        fn_name  = f.get('function')
        filepath = f.get('file')
        ptr_var  = f.get('tainted_var')
        if not (fn_name and filepath and ptr_var):
            continue
        fdata = _fdata(filepath)
        if not fdata:
            continue
        fn_info = fdata['fns'].get(fn_name)
        if fn_info is None:
            continue
        source = fdata['source']
        if not is_static_fn(fn_info['node'], source):
            continue
        static_fns.add(fn_name)
        params = fn_param_names(fn_info['node'], source)
        key = (fn_name, ptr_var)
        param_idxs[key] = params.index(ptr_var) if ptr_var in params else None

    if not static_fns:
        return

    # ── Step 2: Build call-site index for all static Cat I functions at once ──
    cs_index = build_call_site_index(static_fns, paths)

    # ── Step 3: Annotate each Cat I finding ──
    for f in cat_i:
        fn_name    = f.get('function')
        filepath   = f.get('file')
        ptr_var    = f.get('tainted_var')
        struct_type = f.get('taint_source_fn')

        if fn_name not in static_fns:
            f['caller_context'] = {'determinable': False, 'reason': 'not-static'}
            continue

        key       = (fn_name, ptr_var)
        param_idx = param_idxs.get(key)

        if param_idx is None:
            # ptr_var is a locally-cast variable, not a parameter; the
            # function IS the direct receiver, so caller checks don't apply.
            f['caller_context'] = {
                'determinable': False,
                'reason': 'not-parameter',
            }
            continue

        raw_sites = cs_index.get(fn_name, [])
        if not raw_sites:
            f['caller_context'] = {
                'determinable': False,
                'reason':       'no-call-sites',
                'param_idx':    param_idx,
            }
            continue

        cs = [dict(s) for s in raw_sites]
        annotate_cat_i_sizeof_guard(cs, param_idx, struct_type)

        all_guarded = bool(cs) and all(s.get('guarded') is True for s in cs)

        f['caller_context'] = {
            'determinable':        True,
            'param_name':          ptr_var,
            'param_idx':           param_idx,
            'call_site_count':     len(cs),
            'all_callers_guarded': all_guarded,
            'call_sites': [
                {k: v for k, v in s.items() if k not in _OMIT_FROM_SITE}
                for s in cs
            ],
        }


# ---------------------------------------------------------------------------
# Full pipeline: annotate a findings list
# ---------------------------------------------------------------------------

_OMIT_FROM_SITE = frozenset({'arg_names'})   # frozensets are not JSON-safe


def annotate_findings(findings, paths):
    """
    Attach caller_context to each finding in the list, in place.

    For static functions, caller_context includes:
      determinable        — True
      param_name          — formal parameter that roots the taint, or None
      param_idx           — 0-based index of that parameter, or None
      call_site_count     — number of direct call sites found
      all_callers_guarded — True iff every call site guards param before calling
      call_sites          — list of per-site dicts (file, line, caller_fn,
                            args, snippet, guarded, guard_kind)

    For non-static or otherwise undeterminable functions:
      determinable — False
      reason       — short string explaining why

    All files in `paths` are parsed once (via build_call_site_index) rather
    than once per unique function name.
    """
    # Parse the defining files to get fn_def / fn_body (cached by filepath).
    file_cache = {}

    def _fdata(filepath):
        if filepath not in file_cache:
            try:
                tree, source = parse_file(filepath)
                file_cache[filepath] = {
                    'source': source,
                    'fns':    {f['name']: f for f in find_functions(tree, source)},
                }
            except Exception:
                file_cache[filepath] = None
        return file_cache[filepath]

    # Identify which functions are static (need the defining file).
    # Simultaneously decide which fn_names need call-site enumeration.
    static_fns = set()
    for f in findings:
        fn_name  = f.get('function')
        filepath = f.get('file')
        if not fn_name or not filepath:
            continue
        fdata = _fdata(filepath)
        if fdata is None:
            continue
        fn_info = fdata['fns'].get(fn_name)
        if fn_info and is_static_fn(fn_info['node'], fdata['source']):
            static_fns.add(fn_name)

    # Build call-site index for all static functions in one file-scan pass.
    cs_index = build_call_site_index(static_fns, paths) if static_fns else {}

    # Annotate each finding.
    for finding in findings:
        fn_name  = finding.get('function')
        filepath = finding.get('file')
        if not fn_name or not filepath:
            continue

        fdata = _fdata(filepath)
        if not fdata:
            finding['caller_context'] = {'determinable': False, 'reason': 'parse-error'}
            continue

        fn_info = fdata['fns'].get(fn_name)
        if fn_info is None:
            finding['caller_context'] = {'determinable': False, 'reason': 'fn-not-found'}
            continue

        source  = fdata['source']
        fn_def  = fn_info['node']
        fn_body = fn_info['body']

        if not is_static_fn(fn_def, source):
            finding['caller_context'] = {'determinable': False, 'reason': 'not-static'}
            continue

        param_result = identify_taint_param(finding, fn_body, source)
        param_name   = param_result[0] if param_result else None
        param_idx    = param_result[1] if param_result else None

        raw_sites = cs_index.get(fn_name, [])
        if not raw_sites:
            finding['caller_context'] = {
                'determinable': False, 'reason': 'no-call-sites',
                'param_name': param_name, 'param_idx': param_idx,
            }
            continue

        cs = [dict(s) for s in raw_sites]
        annotate_with_guards(cs, param_idx)

        all_guarded = (
            param_idx is not None
            and all(s.get('guarded') is True for s in cs)
        )

        finding['caller_context'] = {
            'determinable':        True,
            'param_name':          param_name,
            'param_idx':           param_idx,
            'call_site_count':     len(cs),
            'all_callers_guarded': all_guarded,
            'call_sites': [
                {k: v for k, v in s.items() if k not in _OMIT_FROM_SITE}
                for s in cs
            ],
        }

    return findings


# ---------------------------------------------------------------------------
# Stage entry point
# ---------------------------------------------------------------------------

def _resolve_paths(cfg):
    """Resolve scan targets to a flat list of Path objects."""
    from pathlib import Path as _P
    kernel_source = cfg.get('kernel_source', '')
    c_paths = []
    for d in cfg['target'].get('source_dirs', []):
        root = _P(kernel_source) / d
        c_paths += sorted(root.rglob('*.c')) + sorted(root.rglob('*.h'))
    for sp in cfg['target'].get('source_paths', []):
        sp = _P(sp)
        if sp.is_dir():
            c_paths += sorted(sp.rglob('*.c')) + sorted(sp.rglob('*.h'))
        else:
            c_paths.append(sp)
    return c_paths


def run(cfg, run_dir, stage1_output, verbose=False):
    """
    Annotate Stage 1 findings with caller_context.

    `stage1_output` is modified in place (caller_context added to each
    finding).  Writes stage1_5_callers.json with aggregate statistics.
    """
    findings = stage1_output.get('findings', [])
    if not findings:
        print("Stage 1.5 (callers): no findings to annotate.")
        return None

    paths = _resolve_paths(cfg)
    n_paths = len(paths)
    print(f"Stage 1.5 (callers): annotating {len(findings)} finding(s) "
          f"across {n_paths} source file(s) ...")

    annotate_findings(findings, paths)
    annotate_cat_i_findings(findings, paths)

    n_det      = sum(1 for f in findings
                     if f.get('caller_context', {}).get('determinable'))
    n_guarded  = sum(1 for f in findings
                     if f.get('caller_context', {}).get('all_callers_guarded'))
    n_not_static = sum(1 for f in findings
                       if f.get('caller_context', {}).get('reason') == 'not-static')
    n_cat_i_det = sum(
        1 for f in findings
        if f.get('category') == 'I'
        and f.get('caller_context', {}).get('determinable')
    )
    n_cat_i_guarded = sum(
        1 for f in findings
        if f.get('category') == 'I'
        and f.get('caller_context', {}).get('all_callers_guarded')
    )

    print(f"Stage 1.5: {n_det} annotated "
          f"({n_guarded} fully guarded, {n_not_static} non-static)")
    if n_cat_i_det or n_cat_i_guarded:
        print(f"Stage 1.5 Cat I: {n_cat_i_det} caller-checked"
              f" ({n_cat_i_guarded} all-callers-guarded)")

    output = {
        'stage':                       'caller_enumeration',
        'files_scanned':               n_paths,
        'findings_annotated':          n_det,
        'all_callers_guarded':         n_guarded,
        'not_static':                  n_not_static,
        'cat_i_caller_checked':        n_cat_i_det,
        'cat_i_all_callers_guarded':   n_cat_i_guarded,
        'total_findings':              len(findings),
    }
    out_path = Path(run_dir) / 'stage1_5_callers.json'
    out_path.write_text(json.dumps(output, indent=2))
    print(f"Stage 1.5 output: {out_path}")
    return output
