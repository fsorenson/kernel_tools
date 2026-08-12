"""
Stage 2: LLM Deep Analysis for bounds / data validation findings.

Feeds each flagged finding from Stage 1 to Claude for reasoning about:
  - Whether the tainted value is genuinely server-supplied
  - Whether any present bounds check is actually sufficient
  - Real impact (OOB read/write, integer overflow, undersized allocation, etc.)
  - Suggested fix

Groups findings by function, sends full or windowed source context.

Gated behind --llm flag.  Uses AnthropicVertex when ANTHROPIC_VERTEX_PROJECT_ID
is set; falls back to Anthropic() with ANTHROPIC_API_KEY.
"""

import json
import os
import re
import sys
import textwrap
from collections import defaultdict
from pathlib import Path

from kernel_analysis.parsers.c_parser import parse_file, find_functions
from bounds_checker.report import write_reports


_MAX_FN_LINES = 150
_WINDOW_LINES = 60
_VERTEX_REGION = os.environ.get('CLOUD_ML_REGION', 'us-east5')
if _VERTEX_REGION == 'global':
    _VERTEX_REGION = 'us-east5'

_CATEGORY_LABELS = {
    'A': 'server-supplied value → pointer arithmetic → memory operation',
    'B': 'server-supplied value → size/length/allocation argument',
    'C': 'server-supplied value → array subscript',
}

_IMPACT_CHOICES = (
    'oob_read', 'oob_write', 'integer_overflow', 'undersized_alloc',
    'stack_overflow', 'info_disclosure', 'none'
)


# ---------------------------------------------------------------------------
# Anthropic client
# ---------------------------------------------------------------------------

def _make_client():
    project_id = os.environ.get('ANTHROPIC_VERTEX_PROJECT_ID')
    if project_id:
        from anthropic import AnthropicVertex
        return AnthropicVertex(project_id=project_id, region=_VERTEX_REGION)
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if api_key:
        from anthropic import Anthropic
        return Anthropic(api_key=api_key)
    raise RuntimeError(
        'No Anthropic credentials: set ANTHROPIC_VERTEX_PROJECT_ID or ANTHROPIC_API_KEY'
    )


# ---------------------------------------------------------------------------
# Stage entry point
# ---------------------------------------------------------------------------

def run(cfg, run_dir, stage1_output, verbose=False, debug=False, thinking_budget=0):
    """
    Analyze Stage 1 taint findings with the LLM.

    stage1_output: dict from stage1_taint_scan.run() or loaded from JSON.
    """
    if not cfg.get('llm', {}).get('enabled'):
        print("Stage 2 (LLM): disabled — pass --llm to enable")
        return None

    model = (
        cfg.get('llm', {}).get('model')
        or os.environ.get('ANTHROPIC_DEFAULT_SONNET_MODEL', 'claude-sonnet-4-6')
    )

    findings = stage1_output.get('findings', [])
    if not findings:
        print("Stage 2 (LLM): no findings to analyze.")
        return None

    try:
        client = _make_client()
    except RuntimeError as e:
        print(f"Stage 2 (LLM): {e}", file=sys.stderr)
        return None

    if thinking_budget and thinking_budget < 1024:
        thinking_budget = 1024

    # Group by (function, file)
    fn_groups = defaultdict(list)
    for f in findings:
        fn_groups[(f['function'], f['file'])].append(f)

    suffix = (f', extended thinking ({thinking_budget} tokens)' if thinking_budget
              else ', debug' if debug else '')
    print(f"Stage 2 (LLM): analyzing {len(fn_groups)} function(s) with {model}{suffix}")

    run_dir = Path(run_dir)
    debug_path = run_dir / 'stage2_llm_analysis.debug'
    debug_fh = open(debug_path, 'w') if (debug or thinking_budget) else None
    if debug_fh:
        print(f"  debug log: {debug_path}")

    all_analyses = []

    try:
        for (fn_name, filepath), fn_findings in sorted(fn_groups.items()):
            short_file = Path(filepath).name
            print(f"  {fn_name}() [{short_file}] ...", end=' ', flush=True)

            fn_source = _extract_fn_source(filepath, fn_name, fn_findings)
            if fn_source is None:
                print("[source not found]")
                continue

            prompt = _build_prompt(fn_name, short_file, fn_source, fn_findings)

            try:
                result = _call_llm(client, model, prompt, verbose,
                                   thinking_budget=thinking_budget,
                                   debug_fh=debug_fh,
                                   fn_label=f"{fn_name}() [{short_file}]")
                result['function'] = fn_name
                result['file'] = short_file
                all_analyses.append(result)
                assessment = result.get('assessment', '?')
                conf = result.get('confidence', '?')
                real_n = sum(1 for f in result.get('findings', []) if f.get('real_bug'))
                print(f"[{assessment}, {conf}, {real_n}/{len(fn_findings)} real]")
            except Exception as exc:
                print(f"[error: {exc}]")
                if verbose:
                    import traceback; traceback.print_exc()
                if debug_fh:
                    debug_fh.write(f"\n[ERROR] {fn_name}(): {exc}\n")
                all_analyses.append({
                    'function': fn_name,
                    'file': short_file,
                    'assessment': 'error',
                    'error': str(exc),
                    'findings': [],
                })
    finally:
        if debug_fh:
            debug_fh.close()

    output = {
        'stage':              'llm_analysis',
        'model':              model,
        'source_dirs':        stage1_output.get('source_dirs', []),
        'functions_analyzed': len(all_analyses),
        'analyses':           all_analyses,
    }

    out_path = run_dir / 'stage2_llm_analysis.json'
    out_path.write_text(json.dumps(output, indent=2))
    print(f"\nStage 2 output: {out_path}")

    _print_summary(all_analyses, verbose)
    write_reports(run_dir, stage1_output, output)
    return output


# ---------------------------------------------------------------------------
# Source extraction (mirrors race finder Stage 6)
# ---------------------------------------------------------------------------

def _extract_fn_source(filepath, fn_name, findings):
    """Full source for short functions; windowed excerpt for long ones."""
    try:
        tree, source = parse_file(Path(filepath))
    except Exception:
        return None

    src_lines = source.decode('utf-8', errors='replace').splitlines()

    for fn in find_functions(tree, source):
        if fn['name'] != fn_name:
            continue

        s, e = fn['start_line'], fn['end_line']
        total = e - s + 1

        if total <= _MAX_FN_LINES:
            return '\n'.join(
                f"{s+i:5}: {line}" for i, line in enumerate(src_lines[s-1:e])
            )

        # Large function: signature block + windows around taint/sink lines.
        # For cross-function findings the sink is in the callee; window around
        # the call_site_line in the caller instead.
        finding_lines = set()
        for f in findings:
            finding_lines.add(f['taint_line'])
            if f.get('propagation') == 'cross_function':
                finding_lines.add(f.get('call_site_line', f['sink_line']))
            else:
                finding_lines.add(f['sink_line'])

        include = set(range(s, min(s + 12, e + 1)))
        for fl in finding_lines:
            lo = max(s, fl - _WINDOW_LINES)
            hi = min(e, fl + _WINDOW_LINES)
            include.update(range(lo, hi + 1))

        result = []
        prev = None
        for lineno in sorted(include):
            if prev is not None and lineno > prev + 1:
                gap = lineno - prev - 1
                result.append(f"       /* ... {gap} lines omitted ... */")
            result.append(f"{lineno:5}: {src_lines[lineno-1]}")
            prev = lineno
        return '\n'.join(result)

    return None


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

_SYSTEM = """\
You are a Linux kernel security reviewer specializing in bounds checking and \
input validation.  You review static analysis findings for missing or \
insufficient validation of server-supplied or user-supplied values before \
they are used in memory operations, allocations, or array indexing.

Respond only with the JSON object requested — no markdown fences, no prose.
"""

_PROMPT_TEMPLATE = """\
## Function: {fn_name}() in {short_file}

```c
{fn_source}
```

## Taint analysis findings

The static scanner flagged the following flows from server-supplied data \
sources to dangerous sinks.  A "possibly guarded" flag means the scanner \
detected a conditional referencing the tainted variable between the source \
and sink — but it does NOT verify that the check is sufficient.

{findings_text}

## Analysis task

For each finding above, determine:

1. **Taint is genuinely server-supplied**: is the flagged value actually \
   read from a network packet / server response, or is it an internal \
   computation that incidentally passes through an endian-conversion call?

2. **Bounds check present and sufficient**: if "possibly guarded", is the \
   conditional actually a proper bounds check for this specific value, or is \
   it checking something unrelated?  Note: a check on one field (e.g., BCC \
   byte count) does NOT protect against an out-of-range DataOffset in the \
   same message.

3. **Real bug**: combining the above, is this a genuine missing-validation bug?

4. **Impact** (choose one if real bug, else "none"):
   oob_read, oob_write, integer_overflow, undersized_alloc, \
   stack_overflow, info_disclosure

5. **Observable symptom**: what a kernel developer or support engineer would \
   see (e.g., "kernel panic from heap corruption", "BUG: KASAN: slab-out-of-bounds \
   in foo", "NULL dereference in bar"); empty string for false positives.

6. **Suggested fix**: the minimal correct fix — usually: validate the \
   server-supplied field against known buffer bounds before using it \
   (lower bound, upper bound), or use a safe counted allocator \
   (kmalloc_array instead of kmalloc(count*size)).

7. **CVE pattern**: is this similar to a known vulnerability class? \
   (e.g., "CVE-2022-NNNN style DataOffset OOB", "SMB negotiation response \
   integer overflow") — empty string if no known match.

Return ONLY valid JSON:
{{
  "assessment": "real_bug" | "false_positive" | "needs_validation" | "mixed",
  "confidence": "high" | "medium" | "low",
  "overall_notes": "<key observations about this function's validation discipline>",
  "findings": [
    {{
      "finding_index": <int matching #N above>,
      "taint_is_server_supplied": <true|false>,
      "bounds_check_present": <true|false>,
      "bounds_check_sufficient": <true|false>,
      "real_bug": <true|false>,
      "impact": "<impact category or empty>",
      "symptom": "<observable symptom or empty>",
      "suggested_fix": "<fix description or empty>",
      "cve_pattern": "<known pattern or empty>",
      "notes": "<any other relevant observation>"
    }}
  ]
}}
"""


def _format_findings(findings):
    lines = []
    for i, f in enumerate(findings, 1):
        cat = f['category']
        cat_label = _CATEGORY_LABELS.get(cat, cat)
        guard_tag = 'yes (check heuristic — may not be sufficient)' if f['possibly_guarded'] else 'no'
        xfn = f.get('propagation') == 'cross_function'

        entry = (
            f"#{i}  Category {cat}: {cat_label}"
        )
        if xfn:
            entry += f"  [CROSS-FUNCTION via {f['callee_fn']}()]"
        entry += (
            f"\n    Taint source: {f['taint_source_fn']}()  line {f['taint_line']}\n"
            f"    Taint snippet:  {f['taint_snippet']}\n"
            f"    Tainted variable: {f['tainted_var']}\n"
        )
        if xfn:
            entry += (
                f"    Call site: line {f['call_site_line']}  "
                f"passes {f['tainted_var']} to {f['callee_fn']}()\n"
                f"    Call snippet:   {f['call_site_snippet']}\n"
                f"    Sink (in {f['callee_fn']}()): "
                f"{f['sink_fn']}()  line {f['sink_line']}  "
                f"(arg {f['sink_arg_index']}, role={f['sink_arg_role']})\n"
                f"    Sink snippet:   {f['sink_snippet']}\n"
                f"    Note: the sink is in the callee, but the fix may belong "
                f"in THIS function (validate before calling {f['callee_fn']}()) "
                f"or in {f['callee_fn']}() itself (validate its parameter).\n"
            )
        else:
            entry += (
                f"    Sink: {f['sink_fn']}()  line {f['sink_line']}  "
                f"(arg {f['sink_arg_index']}, role={f['sink_arg_role']})\n"
                f"    Sink snippet:   {f['sink_snippet']}\n"
            )
        entry += (
            f"    Possibly guarded: {guard_tag}\n"
            f"    Scanner reason: {f['reason']}"
        )
        lines.append(entry)
    return '\n\n'.join(lines)


def _build_prompt(fn_name, short_file, fn_source, findings):
    return _PROMPT_TEMPLATE.format(
        fn_name=fn_name,
        short_file=short_file,
        fn_source=fn_source,
        findings_text=_format_findings(findings),
    )


# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------

def _call_llm(client, model, prompt, verbose,
              thinking_budget=0, debug_fh=None, fn_label=''):
    _JSON_TOKENS = 3072
    kwargs = dict(
        model=model,
        max_tokens=_JSON_TOKENS + thinking_budget if thinking_budget else _JSON_TOKENS,
        system=_SYSTEM,
        messages=[{'role': 'user', 'content': prompt}],
    )
    if thinking_budget:
        kwargs['thinking'] = {'type': 'enabled', 'budget_tokens': thinking_budget}

    if debug_fh:
        _write_debug(debug_fh, f'PROMPT — {fn_label}', prompt)

    msg = client.messages.create(**kwargs)

    thinking_text = ''
    response_text = ''
    for block in msg.content:
        if block.type == 'thinking':
            thinking_text = block.thinking
        elif block.type == 'text':
            response_text = block.text.strip()

    if debug_fh:
        if thinking_text:
            _write_debug(debug_fh, f'THINKING — {fn_label}', thinking_text)
        usage = msg.usage
        _write_debug(debug_fh, f'RESPONSE — {fn_label}', response_text,
                     footer=(f"stop={msg.stop_reason}  "
                             f"in={usage.input_tokens}  out={usage.output_tokens}"))

    if verbose:
        print(f"[{len(response_text)} chars]", end=' ')

    # Strip accidental fences, then use raw_decode to find the first valid JSON object
    text = re.sub(r'^```(?:json)?\s*', '', response_text, flags=re.MULTILINE)
    text = re.sub(r'\s*```$', '', text, flags=re.MULTILINE).strip()

    start = text.find('{')
    if start == -1:
        raise ValueError(f"No JSON object in response: {text[:200]!r}")
    decoder = json.JSONDecoder()
    try:
        obj, _ = decoder.raw_decode(text, start)
        return obj
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON parse error: {e}\n{text[start:start+300]}")


def _write_debug(fh, title, body, footer=None):
    bar = '=' * 80
    fh.write(f"\n{bar}\n{title}\n{bar}\n{body}\n")
    if footer:
        fh.write(f"\n[{footer}]\n")
    fh.flush()


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------

def _wrap(text, prefix, width=100):
    sub = ' ' * len(prefix)
    return textwrap.fill(str(text), width=width, initial_indent=prefix,
                         subsequent_indent=sub, break_long_words=False)


def _print_summary(analyses, verbose):
    _LABEL = {
        'real_bug': 'BUG', 'false_positive': 'FP',
        'needs_validation': 'VALIDATE', 'mixed': 'MIXED', 'error': 'ERROR',
    }

    print(f"\n=== Stage 2 LLM Analysis Results ===")

    total_real = sum(
        sum(1 for f in a.get('findings', []) if f.get('real_bug'))
        for a in analyses
    )
    total_fp = sum(
        sum(1 for f in a.get('findings', []) if not f.get('real_bug'))
        for a in analyses
    )
    print(f"  {len(analyses)} function(s)  |  "
          f"{total_real} real bug(s)  |  {total_fp} false positive(s)\n")

    for a in analyses:
        fn = a.get('function', '?')
        assessment = a.get('assessment', 'error')
        conf = a.get('confidence', '?')
        label = _LABEL.get(assessment, assessment.upper())

        print(f"  {fn}():  [{label}]  confidence={conf}")

        notes = a.get('overall_notes', '')
        if notes:
            print(_wrap(notes, '    '))

        for f in a.get('findings', []):
            idx = f.get('finding_index', '?')
            real = f.get('real_bug', False)
            impact = f.get('impact', '')
            symptom = f.get('symptom', '')
            fix = f.get('suggested_fix', '')
            cve = f.get('cve_pattern', '')
            tag = 'BUG' if real else 'fp'

            impact_str = f'  impact={impact}' if impact and real else ''
            print(f"    #{idx} [{tag}]{impact_str}")

            if real:
                if symptom:
                    print(_wrap(symptom, '         symptom: '))
                if fix and (verbose or True):
                    print(_wrap(fix, '         fix: '))
                if cve:
                    print(_wrap(cve, '         cve_pattern: '))
            elif verbose:
                notes_f = f.get('notes', '')
                if notes_f:
                    print(_wrap(notes_f, '         (fp) '))

        print()
