"""
Cross-function taint propagation for the bounds checker.

Two-pass analysis:

  Phase 1 — build_param_sink_map():
    For each function F, for each parameter p_i: simulate "what if p_i were
    tainted?" using the same taint walk as Stage 1.  Record which (parameter
    index → sink) pairs are reachable within F.

  Phase 2 — scan_cross_function_calls():
    For each caller function G, run the normal intra-procedural taint walk and
    intercept call-site events.  When a tainted variable is passed as argument N
    to a function whose parameter N is in param_sink_map, emit a cross-function
    finding anchored to the caller (where the bounds check should go).

Scope: one-hop only (caller → direct callee).  Multi-hop chains are not yet
supported; they appear as chains of <param:N> source tags which Phase 2 filters.
"""

from pathlib import Path

from kernel_analysis.parsers.c_parser import (
    _walk, node_text, get_source_line, parse_file, find_functions,
)
from bounds_checker.parsers.taint_scanner import (
    _scan_body, _find_guards_between,
)


# ---------------------------------------------------------------------------
# Parameter name extraction
# ---------------------------------------------------------------------------

def _get_param_names(fn_def_node, source):
    """
    Return [(param_idx, param_name)] from a function definition node.

    Uses tree-sitter 'identifier' nodes (not 'type_identifier') inside each
    parameter_declaration — the last identifier is the parameter name for both
    plain and pointer declarator forms.  Skips variadic '...' entries and
    unnamed parameters.
    """
    params = []
    for n in _walk(fn_def_node):
        if n.type == 'parameter_list':
            for child in n.children:
                if child.type == 'variadic_parameter':
                    continue
                if child.type != 'parameter_declaration':
                    continue
                # 'identifier' nodes inside a parameter_declaration are the
                # parameter name (void*, struct foo*, etc. use 'type_identifier'
                # for the type part, not 'identifier').
                idents = [
                    node_text(c, source)
                    for c in _walk(child)
                    if c.type == 'identifier'
                ]
                if idents:
                    params.append(idents[-1])
            break  # Pre-order DFS: first parameter_list is the function's own
    return list(enumerate(params))


# ---------------------------------------------------------------------------
# Phase 1: build parameter → sink map
# ---------------------------------------------------------------------------

def build_param_sink_map(c_paths, verbose=False):
    """
    For every function in c_paths, determine which parameters, if tainted,
    flow to a dangerous sink within that function.

    Returns:
        {
            fn_name: {
                param_idx: [
                    {
                        'param_name':      str,
                        'category':        'A'|'B'|'C',
                        'severity':        str,
                        'sink_fn':         str,
                        'sink_line':       int,
                        'sink_snippet':    str,
                        'sink_arg_index':  int,
                        'sink_arg_role':   str,
                        'callee_guards':   bool,  # possibly_guarded in callee
                        'callee_file':     str,
                    },
                    ...
                ]
            }
        }

    A function name that appears in multiple files gets the last definition
    seen (kernel function names are unique within a subsystem).
    """
    param_sink_map = {}

    for path in c_paths:
        try:
            tree, source = parse_file(path)
        except Exception as e:
            if verbose:
                print(f"  [xfn skip {path}: {e}]")
            continue

        for fn in find_functions(tree, source):
            fn_name = fn['name']
            params = _get_param_names(fn['node'], source)
            if not params:
                continue

            fn_param_sinks = {}

            for param_idx, param_name in params:
                initial_taint = {
                    param_name: {
                        'source_fn': f'<param:{param_idx}>',
                        'line': fn['start_line'],
                        'kind': 'value',
                    }
                }
                findings, _ = _scan_body(
                    fn_name, fn['body'], source, path,
                    initial_taint=initial_taint,
                )
                if not findings:
                    continue

                sink_descs = []
                seen = set()
                for f in findings:
                    key = (f['sink_fn'], f['sink_line'], f['sink_arg_index'])
                    if key in seen:
                        continue
                    seen.add(key)
                    sink_descs.append({
                        'param_name':     param_name,
                        'category':       f['category'],
                        'severity':       f['severity'],
                        'sink_fn':        f['sink_fn'],
                        'sink_line':      f['sink_line'],
                        'sink_snippet':   f['sink_snippet'],
                        'sink_arg_index': f['sink_arg_index'],
                        'sink_arg_role':  f['sink_arg_role'],
                        'callee_guards':  f['possibly_guarded'],
                        'callee_file':    str(path),
                    })

                fn_param_sinks[param_idx] = sink_descs

            if fn_param_sinks:
                param_sink_map[fn_name] = fn_param_sinks

    if verbose:
        n_params = sum(len(v) for v in param_sink_map.values())
        print(f"  param_sink_map: {len(param_sink_map)} function(s), "
              f"{n_params} taint-propagating parameter(s)")

    return param_sink_map


# ---------------------------------------------------------------------------
# Phase 2: scan call sites for tainted argument → propagating parameter match
# ---------------------------------------------------------------------------

def scan_cross_function_calls(c_paths, param_sink_map, verbose=False):
    """
    Scan caller functions for call sites that pass a tainted value to a
    function whose parameter reaches a dangerous sink (per param_sink_map).

    Returns a list of cross-function finding dicts — same base schema as
    intra-procedural findings with these extra fields:
        'propagation':      'cross_function'
        'callee_fn':        str
        'callee_file':      str
        'call_site_line':   int
        'call_site_snippet': str
    """
    if not param_sink_map:
        return []

    findings = []

    for path in c_paths:
        try:
            tree, source = parse_file(path)
        except Exception as e:
            if verbose:
                print(f"  [xfn skip {path}: {e}]")
            continue

        for fn in find_functions(tree, source):
            caller_name = fn['name']

            # Phase 2 uses normal intra taint walk — no initial_taint.
            # call_events carries {callee, line, call_snippet, tainted_args}.
            _, call_events = _scan_body(caller_name, fn['body'], source, path)

            for ev in call_events:
                callee = ev['callee']
                if callee not in param_sink_map:
                    continue
                callee_params = param_sink_map[callee]

                for arg_idx, taint_info in ev['tainted_args'].items():
                    # One-hop only: reject chains where the caller's taint itself
                    # came from a parameter (would be multi-hop propagation).
                    if taint_info['source_fn'].startswith('<param:'):
                        continue

                    if arg_idx not in callee_params:
                        continue

                    # Check if the caller guards the value before the call
                    caller_guarded = _find_guards_between(
                        fn['body'],
                        {taint_info['var']},
                        taint_info['line'],
                        ev['line'],
                        source,
                    )

                    for sink_desc in callee_params[arg_idx]:
                        possibly_guarded = (caller_guarded or
                                            sink_desc['callee_guards'])
                        callee_short = Path(sink_desc['callee_file']).name

                        findings.append({
                            'function':          caller_name,
                            'file':              str(path),
                            'propagation':       'cross_function',
                            'callee_fn':         callee,
                            'callee_file':       sink_desc['callee_file'],
                            'category':          sink_desc['category'],
                            'severity':          sink_desc['severity'],
                            # Taint origin (in caller)
                            'taint_source_fn':   taint_info['source_fn'],
                            'tainted_var':       taint_info['var'],
                            'taint_line':        taint_info['line'],
                            'taint_snippet':     get_source_line(source, taint_info['line']),
                            # Call site (in caller)
                            'call_site_line':    ev['line'],
                            'call_site_snippet': ev['call_snippet'],
                            # Sink (in callee)
                            'sink_fn':           sink_desc['sink_fn'],
                            'sink_line':         sink_desc['sink_line'],
                            'sink_snippet':      sink_desc['sink_snippet'],
                            'sink_arg_index':    sink_desc['sink_arg_index'],
                            'sink_arg_role':     sink_desc['sink_arg_role'],
                            'possibly_guarded':  possibly_guarded,
                            'reason': (
                                f"tainted {taint_info['var']} "
                                f"(from {taint_info['source_fn']}() "
                                f"line {taint_info['line']}) "
                                f"passed to {callee}() arg {arg_idx} "
                                f"(line {ev['line']}), which uses it as "
                                f"{sink_desc['sink_arg_role']} in "
                                f"{sink_desc['sink_fn']}() "
                                f"({callee_short}:{sink_desc['sink_line']})"
                            ),
                        })

    # Deduplicate by (caller, callee, tainted_var, sink_fn, sink_line)
    seen = set()
    unique = []
    for f in findings:
        key = (f['function'], f['callee_fn'], f['tainted_var'],
               f['sink_fn'], f['sink_line'])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
