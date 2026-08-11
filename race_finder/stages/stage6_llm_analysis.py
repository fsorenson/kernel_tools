"""
Stage 6: LLM Deep Analysis

Feeds each confirmed HIGH finding (non-suppressed) to Claude for concurrency
reasoning.  Groups findings by function so each function is analyzed once with
full source context.

Gated behind --llm flag.  Uses AnthropicVertex when ANTHROPIC_VERTEX_PROJECT_ID
is set; falls back to Anthropic() with ANTHROPIC_API_KEY.
"""

import json
import os
import re
import sys

from pathlib import Path
from collections import defaultdict

from ..parsers.c_parser import parse_file, find_functions


_MAX_FN_LINES = 150   # send full source for functions up to this length
_WINDOW_LINES = 55    # ± context lines around findings in large functions
_VERTEX_REGION = os.environ.get('CLOUD_ML_REGION', 'us-east5')
# us-east5 is the standard Claude-on-Vertex region; 'global' is not a valid endpoint
if _VERTEX_REGION == 'global':
    _VERTEX_REGION = 'us-east5'


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
        'No Anthropic credentials. Set ANTHROPIC_VERTEX_PROJECT_ID or ANTHROPIC_API_KEY.'
    )


def run(cfg, run_dir, stage1_output, stage2_output, verbose=False,
        debug=False, thinking_budget=0):
    """
    Analyze confirmed HIGH findings from Stage 2 with the LLM.

    stage2_output may be the live dict from stage2_lock_scan.run(), or loaded
    from stage2_lock_scan.json in a prior run directory.

    debug=True writes full prompts and raw responses to stage6_llm_analysis.debug.
    thinking_budget>0 enables extended thinking (implies debug); minimum 1024.
    """
    if not cfg.get('llm', {}).get('enabled'):
        print("Stage 6: disabled — pass --llm to enable")
        return None

    struct_info = stage1_output['result']
    model = (
        cfg.get('llm', {}).get('model')
        or os.environ.get('ANTHROPIC_DEFAULT_SONNET_MODEL', 'claude-sonnet-4-6')
    )

    findings_src = stage2_output.get('findings', [])
    high_findings = [
        f for f in findings_src
        if f['severity'] == 'high' and f.get('revised_severity') != 'suppressed'
    ]

    if not high_findings:
        print("Stage 6: no confirmed HIGH findings to analyze.")
        return None

    try:
        client = _make_client()
    except RuntimeError as e:
        print(f"Stage 6: {e}", file=sys.stderr)
        return None

    if thinking_budget and thinking_budget < 1024:
        print(f"Stage 6: --llm-thinking minimum is 1024; using 1024 instead of {thinking_budget}")
        thinking_budget = 1024

    fn_names = sorted({f['function'] for f in high_findings})
    suffix = ''
    if thinking_budget:
        suffix = f', extended thinking ({thinking_budget} token budget)'
    elif debug:
        suffix = ', debug logging enabled'
    print(f"Stage 6: analyzing {len(fn_names)} functions with {model}{suffix}")

    debug_path = run_dir / 'stage6_llm_analysis.debug'
    debug_fh = open(debug_path, 'w') if (debug or thinking_budget) else None
    if debug_fh:
        print(f"Stage 6 debug log: {debug_path}")

    # Group by (function, file) — same function may appear in multiple files
    # (unlikely, but guard against it)
    fn_groups = defaultdict(list)
    for f in high_findings:
        fn_groups[(f['function'], f['file'])].append(f)

    struct_context = _build_struct_context(struct_info)
    all_analyses = []

    try:
        for (fn_name, filepath), fn_findings in sorted(fn_groups.items()):
            short_file = filepath.rsplit('/', 1)[-1]
            print(f"  {fn_name}() [{short_file}] ...", end=' ', flush=True)

            fn_source = _extract_fn_source(filepath, fn_name, fn_findings)
            if fn_source is None:
                print("[source not found]")
                continue

            prompt = _build_prompt(struct_context, fn_name, short_file, fn_source, fn_findings)

            try:
                result = _call_llm(client, model, prompt, verbose,
                                   thinking_budget=thinking_budget, debug_fh=debug_fh,
                                   fn_label=f"{fn_name}() [{short_file}]")
                result['function'] = fn_name
                result['file'] = short_file
                all_analyses.append(result)
                verdict = result.get('assessment', '?')
                conf = result.get('confidence', '?')
                print(f"[{verdict}, {conf}]")
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
                })
    finally:
        if debug_fh:
            debug_fh.close()

    output = {
        'stage': 'llm_analysis',
        'struct': struct_info['struct_name'],
        'model': model,
        'functions_analyzed': len(all_analyses),
        'analyses': all_analyses,
    }

    out_path = run_dir / 'stage6_llm_analysis.json'
    with open(out_path, 'w') as fh:
        json.dump(output, fh, indent=2)
    print(f"\nStage 6 output: {out_path}")

    _print_summary(all_analyses, verbose)
    return output


def _build_struct_context(struct_info):
    lines = [f"struct {struct_info['struct_name']}:"]
    if struct_info.get('locks'):
        lines.append(f"  Embedded locks: {', '.join(struct_info['locks'])}")
    for region in struct_info.get('protected_regions', []):
        lines.append(f"  {region['lock']} protects: {', '.join(region['fields'])}")
    suspicious = struct_info.get('suspicious_fields', [])
    if suspicious:
        lines.append("  Unprotected suspicious fields:")
        for s in suspicious:
            lines.append(f"    {s['name']}: {s['reason']}")
    bf_groups = struct_info.get('bitfield_groups', [])
    if bf_groups:
        lines.append(
            "  Bitfield co-location groups (any write to a member is a "
            "read-modify-write of the entire storage word — concurrent writes "
            "to different members race even under different locks):"
        )
        for g in bf_groups:
            prots = g.get('protections', [])
            if g.get('inner_type'):
                suffix = f"  (embedded {g['inner_type']} in field '{g['embedded_in']}')"
            else:
                suffix = ''
            lines.append(f"    [{', '.join(g['fields'])}]{suffix}  protections: {', '.join(prots)}")
    return '\n'.join(lines)


def _extract_fn_source(filepath, fn_name, findings):
    """
    Return annotated source lines for fn_name.
    Full function if <= _MAX_FN_LINES; windowed excerpt otherwise.
    """
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
            return '\n'.join(f"{s+i:5}: {line}" for i, line in enumerate(src_lines[s-1:e]))

        # Large function — signature block + windows around each finding
        finding_lines = sorted({f['line'] for f in findings})
        include = set(range(s, min(s + 10, e + 1)))   # opening signature
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


def _build_prompt(struct_context, fn_name, short_file, fn_source, findings):
    findings_text = []
    for i, f in enumerate(findings, 1):
        parts = [
            f"#{i}: line {f['line']} field='{f['field']}' access={f['access_type']}",
            f"     reason: {f['reason']}",
        ]
        if f.get('expected_lock'):
            parts.append(f"     expected lock: {f['expected_lock']}")
        cg = f.get('call_graph', {})
        conc = cg.get('conclusion', '') if cg else ''
        if conc == 'no_callers_found':
            parts.append("     call graph: no callers in analyzed files (likely exported/VFS-called)")
        elif conc == 'ops_registered_no_sites_found':
            regs = cg.get('ops_registrations', [])
            reg_str = ', '.join(f".{r['field']} ({r['file']})" for r in regs)
            parts.append(f"     call graph: registered in ops struct as {reg_str} "
                         f"but no indirect call sites found in analyzed files")
        elif 'indirect_callers' in conc or 'indirect_callers_hold' in conc or conc == 'no_indirect_callers_hold_lock':
            regs = cg.get('ops_registrations', [])
            reg_str = ', '.join(f".{r['field']} ({r['file']})" for r in regs)
            indirect = cg.get('indirect_callers', [])
            parts.append(f"     call graph: called via ops dispatch ({reg_str}), conclusion={conc}")
            for site in indirect[:4]:
                parts.append(f"       {site}")
        elif 'callers_lack' in conc:
            without = cg.get('without_lock', [])[:3]
            with_ = cg.get('with_lock', [])[:3]
            parts.append(f"     call graph: MIXED — {len(cg.get('without_lock',[]))} callers lack lock, "
                         f"{len(cg.get('with_lock',[]))} hold it")
            if without:
                parts.append(f"       without lock: {', '.join(without)}")
            if with_:
                parts.append(f"       with lock:    {', '.join(with_)}")
        elif 'no_callers_hold' in conc:
            without = cg.get('without_lock', [])[:3]
            parts.append("     call graph: no callers hold the required lock")
            if without:
                parts.append(f"       callers: {', '.join(without)}")
        parts.append(f"     snippet: {f['snippet']}")
        findings_text.append('\n'.join(parts))

    return f"""\
You are a Linux kernel concurrency expert reviewing race condition tool output \
for the CIFS/SMB client (fs/smb/client/).

## Struct context

{struct_context}

## Function: {fn_name}() in {short_file}

```c
{fn_source}
```

## Findings flagged as HIGH severity

{chr(10).join(findings_text)}

## Analysis task

For each finding, determine:
1. Real race or false positive? Consider: object lifecycle exclusivity, \
serialization through other means (session mutex, refcount drain, SES_EXITING \
status, etc.), whether VFS-called functions have implicit serialization.
2. If real: what is the exact race window and consequence?
3. Impact: the technical consequence of the race (choose one: \
"system_crash", "data_corruption", "use_after_free", "resource_leak", \
"protocol_violation", "wrong_behavior", "none").
4. Symptom: what a user or support engineer would observe — a concise \
plain-English phrase such as "kernel oops in cifsFileInfo_put", \
"mount fails with EIO", "file size stale after write", \
"unexpected reconnection loop", "server file handle not closed on client exit". \
Empty string for false positives.
5. Recommended fix (acquire correct lock, use atomic op, use set_bit() / \
clear_bit() for bitfield races, add data_race() / READ_ONCE() annotation, \
or document as intentional).

Respond with JSON only — no prose before or after the JSON block:
{{
  "assessment": "real_race" | "false_positive" | "needs_annotation" | "mixed",
  "confidence": "high" | "medium" | "low",
  "findings": [
    {{
      "finding_index": <int matching #N above>,
      "field": "<field_name>",
      "real_race": <true|false>,
      "race_scenario": "<concise description or empty string if false positive>",
      "impact": "<impact category or empty string if false positive>",
      "symptom": "<observable symptom or empty string if false positive>",
      "suggested_fix": "<fix or empty string>"
    }}
  ],
  "overall_notes": "<key observations about the function's locking discipline>"
}}"""


def _call_llm(client, model, prompt, verbose,
              thinking_budget=0, debug_fh=None, fn_label=''):
    _JSON_TOKENS = 3072
    create_kwargs = dict(
        model=model,
        max_tokens=_JSON_TOKENS + thinking_budget if thinking_budget else _JSON_TOKENS,
        system=(
            "You are a Linux kernel concurrency expert. "
            "Respond only with the JSON object requested — no markdown fences, no prose."
        ),
        messages=[{'role': 'user', 'content': prompt}],
    )
    if thinking_budget:
        create_kwargs['thinking'] = {'type': 'enabled', 'budget_tokens': thinking_budget}

    if debug_fh:
        _write_debug_section(debug_fh, f'PROMPT — {fn_label}', prompt)

    msg = client.messages.create(**create_kwargs)

    # Extract thinking and text blocks separately
    thinking_text = ''
    response_text = ''
    for block in msg.content:
        if block.type == 'thinking':
            thinking_text = block.thinking
        elif block.type == 'text':
            response_text = block.text.strip()

    if debug_fh:
        if thinking_text:
            _write_debug_section(debug_fh, f'THINKING — {fn_label}', thinking_text)
        usage = msg.usage
        meta = (f"stop_reason={msg.stop_reason}  "
                f"input_tokens={usage.input_tokens}  "
                f"output_tokens={usage.output_tokens}")
        if thinking_budget and hasattr(usage, 'cache_read_input_tokens'):
            meta += f"  thinking_tokens≈{thinking_budget}"
        _write_debug_section(debug_fh, f'RESPONSE — {fn_label}', response_text, footer=meta)

    if verbose:
        print(f"\n    [{len(response_text)} chars]", end=' ')

    # Strip any accidental markdown fence
    text = re.sub(r'^```(?:json)?\s*', '', response_text)
    text = re.sub(r'\s*```$', '', text)

    m = re.search(r'\{.*\}', text, re.DOTALL)
    if not m:
        raise ValueError(f"No JSON in response: {text[:200]!r}")
    return json.loads(m.group(0))


def _write_debug_section(fh, title, body, footer=None):
    bar = '=' * 80
    fh.write(f"\n{bar}\n{title}\n{bar}\n{body}\n")
    if footer:
        fh.write(f"\n[{footer}]\n")
    fh.flush()


def _print_summary(analyses, verbose):
    import textwrap

    def _wrap(text, prefix, width=100):
        """Fill text with prefix on first line; subsequent lines aligned to text start."""
        subsequent = ' ' * len(prefix)
        return textwrap.fill(text, width=width, initial_indent=prefix,
                             subsequent_indent=subsequent, break_long_words=False)

    print(f"\n=== Stage 6: LLM Analysis Results ===")
    for a in analyses:
        fn = a.get('function', '?')
        assessment = a.get('assessment', 'error')
        conf = a.get('confidence', '?')

        label = {'real_race': 'REAL', 'false_positive': 'FP', 'needs_annotation': 'ANNOTATE',
                 'mixed': 'MIXED', 'error': 'ERROR'}.get(assessment, assessment.upper())
        print(f"\n  {fn}(): [{label}] confidence={conf}")

        notes = a.get('overall_notes', '')
        if notes:
            print(_wrap(notes, '    '))

        for f in a.get('findings', []):
            real = f.get('real_race')
            field = f.get('field', '?')
            scenario = f.get('race_scenario', '')
            impact = f.get('impact', '')
            symptom = f.get('symptom', '')
            fix = f.get('suggested_fix', '')
            tag = 'RACE' if real else 'fp'
            impact_str = f'  impact={impact}' if impact and real else ''
            print(f"    [{tag}] field={field}{impact_str}")
            if symptom and real:
                print(_wrap(symptom, '      symptom: '))
            if scenario and real:
                print(_wrap(scenario, '      scenario: '))
            if fix and verbose:
                print(_wrap(fix, '      fix: '))
