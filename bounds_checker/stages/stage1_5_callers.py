"""
Stage 1.5: Caller enumeration for findings in static functions.

For each finding in a static function, scans all source files for direct
call sites of that function and returns per-call-site context.  The result
will annotate each finding with caller_context before Stage 2 sees it.

Step A (this module): find_call_sites() — locate call sites in the scanned
file set.  Step B will add guard detection per call site.  Step C will wire
annotate_findings() into the full pipeline.
"""

from kernel_analysis.parsers.c_parser import (
    parse_file, find_functions, find_calls_to, node_text, get_source_line,
)


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

            results.append({
                'file':      str(path),
                'line':      call_line,
                'caller_fn': caller,
                'args':      [node_text(a, source) for a in arg_nodes],
                'snippet':   _snippet(source, call_line, context_lines),
            })

    return results
