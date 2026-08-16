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
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import nullcontext
from pathlib import Path

from kernel_analysis.parsers.c_parser import parse_file, find_functions
from bounds_checker.report import write_reports


_MAX_FN_LINES = 150
_MAX_CALLEE_LINES = 80   # callee helpers are usually compact; show whole body if possible
_WINDOW_LINES = 60
_VERTEX_REGION = os.environ.get('CLOUD_ML_REGION', 'us-east5')
if _VERTEX_REGION == 'global':
    _VERTEX_REGION = 'us-east5'

_CATEGORY_LABELS = {
    'A':     'server-supplied value → pointer arithmetic → memory operation',
    'B':     'server-supplied value → size/length/allocation argument',
    'B_OVF': 'integer overflow: server-supplied value in multiplicative/additive size expression',
    'C':     'server-supplied value → array subscript',
    'D':     'strlen/strlcpy on server-supplied pointer without null-termination guarantee',
    'E':     'tainted pointer dereference: struct field access via pointer derived from server offset',
    'F':     'server-supplied value controls loop iteration count without buffer bounds validation',
    'G1':    'copy_from_user/copy_to_user return value unchecked: partial copy treated as success',
    'G2':    'unvalidated size argument to copy_from_user/copy_to_user: user-controlled size',
    'H':     'server-supplied wide value silently truncated to narrower integer type',
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
# Batched analysis helpers
# ---------------------------------------------------------------------------

# Max findings per LLM call.  Above ~20 the output JSON routinely hits the
# 8192-token cap before all finding objects are written.
_BATCH_SIZE = 20

_ASSESSMENT_SEVERITY = {
    'real_bug': 4, 'mixed': 3, 'needs_validation': 2, 'false_positive': 1, 'error': 0,
}
_CONFIDENCE_ORDER = {'high': 2, 'medium': 1, 'low': 0}


def _analyze_fn(client, model, fn_name, short_file, fn_source, fn_findings,
                verbose, thinking_budget, debug_fh, debug_lock=None):
    """
    Run LLM analysis for all findings in one function, splitting into batches
    of _BATCH_SIZE when needed.  Batch finding_index values are remapped to
    function-global 1-based indices before merging.
    """
    if len(fn_findings) <= _BATCH_SIZE:
        callee_sources = _collect_callee_sources(fn_findings)
        prompt = _build_prompt(fn_name, short_file, fn_source, fn_findings, callee_sources)
        return _call_llm(client, model, prompt, verbose,
                         n_findings=len(fn_findings),
                         thinking_budget=thinking_budget,
                         debug_fh=debug_fh,
                         fn_label=f"{fn_name}() [{short_file}]",
                         debug_lock=debug_lock)

    total     = len(fn_findings)
    n_batches = (total + _BATCH_SIZE - 1) // _BATCH_SIZE
    all_fr    = []
    assessments = []
    confidences = []
    notes     = []

    for b, batch_start in enumerate(range(0, total, _BATCH_SIZE), 1):
        batch = fn_findings[batch_start:batch_start + _BATCH_SIZE]
        label = f"{fn_name}() [{short_file}] batch {b}/{n_batches}"
        callee_sources = _collect_callee_sources(batch)
        prompt = _build_prompt(fn_name, short_file, fn_source, batch, callee_sources)

        if verbose:
            print(f"[b{b}/{n_batches}]", end=' ', flush=True)

        result = _call_llm(client, model, prompt, verbose,
                           n_findings=len(batch),
                           thinking_budget=thinking_budget,
                           debug_fh=debug_fh,
                           fn_label=label,
                           debug_lock=debug_lock)

        # Remap batch-local 1-based finding_index to function-global 1-based
        for fr in result.get('findings', []):
            fr['finding_index'] = fr.get('finding_index', 0) + batch_start
        all_fr.extend(result.get('findings', []))
        assessments.append(result.get('assessment', 'error'))
        confidences.append(result.get('confidence', 'low'))
        notes.append(result.get('overall_notes', ''))

    merged_assessment  = max(assessments, key=lambda a: _ASSESSMENT_SEVERITY.get(a, 0))
    merged_confidence  = min(confidences, key=lambda c: _CONFIDENCE_ORDER.get(c, 0))
    merged_notes       = ' | '.join(n for n in notes if n)
    return {
        'assessment':   merged_assessment,
        'confidence':   merged_confidence,
        'overall_notes': merged_notes,
        'findings':     all_fr,
    }


# ---------------------------------------------------------------------------
# Stage entry point
# ---------------------------------------------------------------------------

def run(cfg, run_dir, stage1_output, verbose=False, debug=False, thinking_budget=0, n_workers=1):
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

    all_findings = stage1_output.get('findings', [])
    if not all_findings:
        print("Stage 2 (LLM): no findings to analyze.")
        return None

    # Optionally restrict LLM analysis to a subset of categories.
    llm_cats = cfg.get('llm', {}).get('categories')
    if llm_cats:
        llm_cat_set = set(llm_cats)
        findings = [f for f in all_findings if f['category'] in llm_cat_set]
        if not findings:
            print(f"Stage 2 (LLM): no findings for LLM categories "
                  f"{', '.join(sorted(llm_cat_set))}.")
            return None
    else:
        llm_cat_set = None
        findings = all_findings

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

    workers_str = f', {n_workers} workers' if n_workers > 1 else ''
    suffix = (f', extended thinking ({thinking_budget} tokens)' if thinking_budget
              else ', debug' if debug else '')
    cat_str = (f', cats={",".join(sorted(llm_cat_set))}'
               f' ({len(findings)}/{len(all_findings)} findings)'
               if llm_cat_set else '')
    print(f"Stage 2 (LLM): analyzing {len(fn_groups)} function(s) with {model}{suffix}{workers_str}{cat_str}")

    run_dir = Path(run_dir)
    debug_path = run_dir / 'stage2_llm_analysis.debug'
    debug_fh = open(debug_path, 'w') if (debug or thinking_budget) else None
    if debug_fh:
        print(f"  debug log: {debug_path}")

    # One lock protects all debug file writes; uncontested when n_workers == 1.
    debug_lock = threading.Lock() if debug_fh else None

    all_analyses = []
    total_fns = len(fn_groups)
    done_count = 0

    def _work(fn_name, filepath, fn_findings):
        fn_source = _extract_fn_source(filepath, fn_name, fn_findings)
        short_file = Path(filepath).name
        if fn_source is None:
            return fn_name, filepath, fn_findings, None, None
        try:
            result = _analyze_fn(
                client, model, fn_name, short_file, fn_source, fn_findings,
                verbose, thinking_budget, debug_fh, debug_lock,
            )
            return fn_name, filepath, fn_findings, result, None
        except Exception as exc:
            if verbose:
                import traceback; traceback.print_exc()
            if debug_fh:
                with (debug_lock or nullcontext()):
                    debug_fh.write(f"\n[ERROR] {fn_name}(): {exc}\n")
                    debug_fh.flush()
            return fn_name, filepath, fn_findings, None, exc

    try:
        with ThreadPoolExecutor(max_workers=n_workers) as executor:
            futures = {
                executor.submit(_work, fn_name, filepath, fn_findings): (fn_name, filepath)
                for (fn_name, filepath), fn_findings in sorted(fn_groups.items())
            }
            for future in as_completed(futures):
                done_count += 1
                progress = f"[{done_count}/{total_fns}]"
                try:
                    fn_name, filepath, fn_findings, result, exc = future.result()
                except Exception as e:
                    key = futures[future]
                    print(f"  {progress} {key[0]}() [unexpected error: {e}]")
                    continue

                short_file = Path(filepath).name
                n = len(fn_findings)
                n_batches = (n + _BATCH_SIZE - 1) // _BATCH_SIZE
                batch_tag = f' [{n_batches} batches]' if n_batches > 1 else ''

                if result is None and exc is None:
                    print(f"  {progress} {fn_name}() [{short_file}] [source not found]")
                elif exc is not None:
                    print(f"  {progress} {fn_name}() [{short_file}]{batch_tag} [error: {exc}]")
                    all_analyses.append({
                        'function': fn_name,
                        'file': filepath,
                        'assessment': 'error',
                        'error': str(exc),
                        'findings': [],
                    })
                else:
                    result['function'] = fn_name
                    result['file'] = filepath
                    all_analyses.append(result)
                    assessment = result.get('assessment', '?')
                    conf = result.get('confidence', '?')
                    real_n = sum(1 for f in result.get('findings', []) if f.get('real_bug'))
                    print(f"  {progress} {fn_name}() [{short_file}]{batch_tag} "
                          f"[{assessment}, {conf}, {real_n}/{n} real]")
    finally:
        if debug_fh:
            debug_fh.close()

    output = {
        'stage':              'llm_analysis',
        'model':              model,
        'source_dirs':        stage1_output.get('source_dirs', []),
        'llm_categories':     sorted(llm_cat_set) if llm_cat_set else None,
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


def _extract_callee_source(callee_file, callee_fn, sink_line):
    """
    Extract the source of a callee function referenced by a cross-function
    finding.  Full body when compact; windowed around sink_line otherwise.
    """
    try:
        tree, source = parse_file(Path(callee_file))
    except Exception:
        return None

    src_lines = source.decode('utf-8', errors='replace').splitlines()

    for fn in find_functions(tree, source):
        if fn['name'] != callee_fn:
            continue

        s, e = fn['start_line'], fn['end_line']

        if e - s + 1 <= _MAX_CALLEE_LINES:
            return '\n'.join(
                f"{s+i:5}: {line}" for i, line in enumerate(src_lines[s-1:e])
            )

        # Large helper: signature block + window around the sink line.
        half = _WINDOW_LINES // 2
        include = set(range(s, min(s + 8, e + 1)))
        include.update(range(max(s, sink_line - half), min(e, sink_line + half) + 1))

        result = []
        prev = None
        for lineno in sorted(include):
            if prev is not None and lineno > prev + 1:
                result.append(f"       /* ... {lineno - prev - 1} lines omitted ... */")
            result.append(f"{lineno:5}: {src_lines[lineno-1]}")
            prev = lineno
        return '\n'.join(result)

    return None


def _collect_callee_sources(findings):
    """
    For each unique (callee_fn, callee_file) pair among cross-function findings,
    extract the callee's source.  Returns {(callee_fn, short_file): source}.
    """
    seen = set()
    result = {}
    for f in findings:
        if f.get('propagation') != 'cross_function':
            continue
        callee_fn   = f.get('callee_fn')
        callee_file = f.get('callee_file')
        if not callee_fn or not callee_file:
            continue
        key = (callee_fn, callee_file)
        if key in seen:
            continue
        seen.add(key)
        src = _extract_callee_source(callee_file, callee_fn, f['sink_line'])
        if src:
            result[(callee_fn, Path(callee_file).name)] = src
    return result


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

_SYSTEM = """\
You are a Linux kernel security reviewer specializing in bounds checking and \
input validation.  You review static analysis findings for missing or \
insufficient validation of server-supplied or user-supplied values before \
they are used in memory operations, allocations, or array indexing.

Common false positive patterns in kernel taint analysis:

1. Locally-written struct fields: le32_to_cpu(ptr->field) marks the value as
   tainted, but if ptr points to a struct the kernel BUILT (allocated locally
   with kzalloc/kmalloc/stack/compound-literal, then filled with
   cpu_to_le32(constant) or a compile-time constant), the round-tripped value
   is NOT server-supplied.  Check whether the struct is a server RESPONSE
   (populated from a received network buffer) or a locally-constructed REQUEST.
   Functions that call a request-initialisation helper (e.g. smb2_plain_req_init,
   cifs_buf_get, small_smb2_init) before the flagged use are building a request,
   not parsing a response.

2. Validation call chains: when a function calls a dedicated validation helper
   BEFORE the flagged pointer use, determine whether that helper covers the
   flagged offset and size.  smb2_validate_iov(offset, len, iov, min_len) and
   smb2_validate_and_copy_iov() verify that offset+len fits within the iov and
   len >= min_len — subsequent field accesses on the validated struct pointer
   ARE protected.  dacl_offset_valid() + validate_dacl() together validate an
   ACL pointer before use in the CALLER; findings about the callee's internal
   accesses inside validate_dacl() are usually false positives because that
   function IS the validator.  validate_t2() in the current patched kernel
   validates that both DataOffset+min_data_size and ParameterOffset+min_param_size
   fall within the actual received packet boundary (frame_end computed from
   get_bcc + header overhead) — if the caller passes sizeof(the_accessed_struct)
   as min_data, the DataOffset-derived pointer is within the received buffer.

3. Static function call-site preconditions: a static function that is only
   ever called in contexts where a validation gate has already succeeded
   inherits that gate's protection.  When the source shows all call sites
   going through the same validator, treat the callee's accesses as protected.

4. Callee-internal validation: when a cross-function finding reports a sink
   inside a helper, the helper may validate its argument internally before
   operating on it.  The callee source is included in the prompt (when
   available) — check it to determine whether the tainted parameter is
   validated before the flagged sink.

Respond only with the JSON object requested — no markdown fences, no prose.
"""

_PROMPT_TEMPLATE = """\
## Function: {fn_name}() in {short_file}

```c
{fn_source}
```
{callee_sources_section}
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
   computation that passes through an endian-conversion call?  If the \
   taint source is le32_to_cpu(ptr->field), check whether 'ptr' was \
   received from the server (a response buffer) or was allocated and \
   initialised by the kernel in this function (a locally-built request).  \
   If the kernel wrote 'field' via cpu_to_le32(constant) before reading it \
   back, the value is locally controlled — not server-supplied.

2. **Bounds check present and sufficient**: if "possibly guarded", is the \
   conditional actually a proper bounds check for this specific value, or is \
   it checking something unrelated?  Note: a check on one field (e.g., BCC \
   byte count) does NOT protect against an out-of-range DataOffset in the \
   same message.  Also consider validation call chains one level deep: \
   smb2_validate_iov()/smb2_validate_and_copy_iov() verify offset+len fits \
   within the iov — accesses to the validated struct are protected.  \
   dacl_offset_valid()+validate_dacl() in the CALLER protect ACL field \
   accesses outside the validator itself.  validate_t2() in the patched \
   kernel validates DataOffset+min_data ≤ actual packet boundary — \
   DataOffset-derived pointers are safe when min_data ≥ sizeof of the \
   accessed struct (min_param and min_data guard ParameterOffset and \
   DataOffset independently; passing 0 for one skips its minimum-size \
   check but the unconditional offset+count ≤ frame_end check still runs \
   for both).  For static functions only reachable after a validation \
   gate, they inherit that gate's guarantee.  For cross-function sinks, \
   check the callee source (included above when available) to determine \
   whether the callee validates its argument before the flagged operation.

2a. **Counterexample test** (apply when bounds_check_present is true): \
   before setting bounds_check_sufficient to false, construct a concrete \
   counterexample — specific numeric values of the tainted field(s) that \
   would pass every visible guard yet still cause OOB access.  If the \
   guards are tight enough that no such counterexample exists, set \
   bounds_check_sufficient to true even if the check structure looks \
   unusual.  State in the "notes" field whether you found a counterexample \
   or could not construct one.

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
        overflow = f.get('overflow', False)
        cat_key = f'{cat}_OVF' if overflow else cat
        cat_label = _CATEGORY_LABELS.get(cat_key, _CATEGORY_LABELS.get(cat, cat))
        guard_tag = 'yes (check heuristic — may not be sufficient)' if f['possibly_guarded'] else 'no'
        xfn = f.get('propagation') == 'cross_function'

        entry = (
            f"#{i}  Category {cat}: {cat_label}"
        )
        if overflow:
            entry += (
                f"\n    Overflow expression: {f['overflow_lhs']} "
                f"{f['overflow_op']} {f['overflow_rhs']}"
                f"\n    Safe fix: use kmalloc_array() or check_mul_overflow() "
                f"instead of raw {'multiplication' if f['overflow_op'] == '*' else 'addition'}"
            )
        if xfn:
            entry += f"  [CROSS-FUNCTION via {f['callee_fn']}()]"
        entry += (
            f"\n    Taint source: {f['taint_source_fn']}()  line {f['taint_line']}\n"
            f"    Taint snippet:  {f['taint_snippet']}\n"
            f"    Tainted variable: {f['tainted_var']}\n"
        )
        if xfn:
            read_only_callee = f.get('callee_is_read_only', False)
            entry += (
                f"    Call site: line {f['call_site_line']}  "
                f"passes {f['tainted_var']} to {f['callee_fn']}()\n"
                f"    Call snippet:   {f['call_site_snippet']}\n"
                f"    Sink (in {f['callee_fn']}()): "
                f"{f['sink_fn']}()  line {f['sink_line']}  "
                f"(arg {f['sink_arg_index']}, role={f['sink_arg_role']})\n"
                f"    Sink snippet:   {f['sink_snippet']}\n"
            )
            if read_only_callee:
                entry += (
                    f"    Note: {f['callee_fn']}() is a READ-ONLY function "
                    f"(comparator, debug output, or non-mutating accessor) — "
                    f"it cannot cause OOB writes, memory corruption, or undersized "
                    f"allocations.  Assess only whether an OOB READ inside this callee "
                    f"is (a) reachable with a plausible server-supplied value and "
                    f"(b) exploitable in the kernel context (e.g. leaks kernel memory "
                    f"to an attacker).  If the callee's internal access is bounded by "
                    f"its own parameter validation or the kernel's memory-safe access "
                    f"patterns, mark as false positive.\n"
                )
            else:
                entry += (
                    f"    Note: the sink is in the callee, but the fix may belong "
                    f"in THIS function (validate before calling {f['callee_fn']}()) "
                    f"or in {f['callee_fn']}() itself (validate its parameter).  "
                    f"False positive if {f['callee_fn']}() is a validation function "
                    f"called specifically to validate the tainted argument — accesses "
                    f"inside the validator are part of the validation logic, not "
                    f"vulnerable sinks.  Check the callee source included above.\n"
                )
        elif f.get('sink_arg_role') == 'string_arg':
            entry += (
                f"    String sink: {f['sink_fn']}() arg {f['sink_arg_index']}  "
                f"line {f['sink_line']}\n"
                f"    Sink snippet:   {f['sink_snippet']}\n"
                f"    Note: {f['sink_fn']}() assumes the argument is null-terminated "
                f"within the accessible buffer.  strlcpy() limits the *destination* "
                f"copy but still calls strlen() on the source.  False positive if the "
                f"caller established a maximum length via strnlen() or memchr() before "
                f"this call, or if the string came from a trusted (kernel-internal) "
                f"source rather than server-supplied packet data.\n"
            )
        elif f.get('sink_arg_role') == 'tainted_ptr_deref':
            entry += (
                f"    Pointer deref: {f['tainted_var']}->{f.get('field_name','?')}  "
                f"line {f['sink_line']}\n"
                f"    Deref snippet:  {f['sink_snippet']}\n"
                f"    Note: verify that offset + sizeof(*{f['tainted_var']}) <= packet_end "
                f"before the struct pointer is created.  False positive if: "
                f"(a) smb2_validate_iov() or smb2_validate_and_copy_iov() was called "
                f"with this offset and the struct size before the dereference; "
                f"(b) dacl_offset_valid()+validate_dacl() were called in this function "
                f"and the dereference is in the caller, not inside the validator; "
                f"(c) the struct was allocated locally by the kernel (not received from "
                f"the server) and any le32_to_cpu() reads are of locally-written fields.\n"
            )
        elif f.get('sink_arg_role') == 'narrowed_value':
            entry += (
                f"    Truncation: {f.get('src_width','?')}-bit source → "
                f"{f.get('dest_width','?')}-bit {f.get('dest_type','')}  "
                f"line {f['sink_line']}\n"
                f"    Note: flag as false positive if the RHS expression uses "
                f"masking (& 0xFF, & 0xFFFF) or right-shift that limits the "
                f"value to the destination width before assignment.\n"
            )
        elif f.get('sink_arg_role') == 'loop_bound':
            entry += (
                f"    Loop: {f['sink_fn']}  line {f['sink_line']}\n"
                f"    Loop snippet:   {f['sink_snippet']}\n"
                f"    Note: three forms of protection are each sufficient: "
                f"(a) pre-loop: total bytes iterated ({f['tainted_var']} * sizeof(element)) "
                f"validated against the packet/buffer length before the loop; "
                f"(b) per-iteration: loop body has a bounds check (e.g. "
                f"'if (ptr >= end) break/return') that terminates the loop before OOB — "
                f"in this case the iteration count being unvalidated does not matter; "
                f"(c) prior full-traversal: a function called before this loop on the same "
                f"pointer/buffer already walked every element with per-step bounds checks — "
                f"if that prior traversal would have returned early on any invalid element, "
                f"the loop here is already protected by that earlier validation.\n"
            )
        elif f.get('sink_arg_role') == 'retval_discarded':
            entry += (
                f"    Call: {f['sink_fn']}()  line {f['sink_line']}\n"
                f"    Snippet:        {f['sink_snippet']}\n"
                f"    Note: {f['sink_fn']}() returns the number of bytes NOT copied; "
                f"0 = success, non-zero = partial or failed copy.  Discarding this "
                f"value means a partial copy is silently treated as success.  False "
                f"positive if the function is intentionally best-effort and callers "
                f"are robust to partial data.\n"
            )
        elif f.get('sink_arg_role') == 'retval_unchecked':
            entry += (
                f"    Call: {f['sink_fn']}()  line {f['sink_line']}\n"
                f"    Snippet:        {f['sink_snippet']}\n"
                f"    Assigned to:    {f['tainted_var']!r} (never checked against zero)\n"
                f"    Note: {f['sink_fn']}() returns bytes NOT copied; "
                f"0 = success, non-zero = partial/failed copy.  False positive if "
                f"the variable is checked or returned along every subsequent path, "
                f"or if the copy is intentionally best-effort.\n"
            )
        elif f.get('sink_arg_role') == 'unvalidated_size':
            entry += (
                f"    Call: {f['sink_fn']}()  size arg [{f['sink_arg_index']}]  "
                f"line {f['sink_line']}\n"
                f"    Snippet:        {f['sink_snippet']}\n"
                f"    Size expression: {f['tainted_var']!r}\n"
                f"    Note: if the size is user-controlled (e.g. read via get_user "
                f"or from a user-supplied struct), it must be validated against the "
                f"destination buffer length before the copy.  False positive if the "
                f"size comes from a kernel-internal, already-validated source.\n"
            )
        elif f.get('sink_arg_role') == 'size':
            entry += (
                f"    Size arg: {f['sink_fn']}()  arg {f['sink_arg_index']}  "
                f"line {f['sink_line']}\n"
                f"    Sink snippet:   {f['sink_snippet']}\n"
                f"    Note: for size-argument findings, check TWO independent "
                f"questions: (a) is {f['tainted_var']} bounded against the SOURCE "
                f"buffer (no OOB read of input)? (b) is it bounded against the "
                f"DESTINATION buffer or type size (no OOB write of output)?  A "
                f"guard covering source but not destination (or vice versa) is "
                f"incomplete.  If {f['tainted_var']} comes from a helper function, "
                f"consider what that function's maximum return value can be — if it "
                f"is structurally bounded (e.g. capped by a sizeof or a max-count "
                f"constant), the destination check may already be satisfied.\n"
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


def _build_prompt(fn_name, short_file, fn_source, findings, callee_sources=None):
    if callee_sources:
        parts = ['\n## Callee function source(s) — cross-function finding context\n']
        for (callee_fn, callee_short_file), src in sorted(callee_sources.items()):
            parts.append(f'\n### {callee_fn}() in {callee_short_file}\n```c\n{src}\n```\n')
        callee_section = ''.join(parts)
    else:
        callee_section = ''
    return _PROMPT_TEMPLATE.format(
        fn_name=fn_name,
        short_file=short_file,
        fn_source=fn_source,
        callee_sources_section=callee_section,
        findings_text=_format_findings(findings),
    )


# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------

def _call_llm(client, model, prompt, verbose,
              n_findings=1, thinking_budget=0, debug_fh=None, fn_label='', debug_lock=None):
    # Scale output budget with findings count; cap at the model's hard limit.
    # Base: 1024 tokens for outer JSON + overall_notes.
    # Per finding: ~512 tokens for 10 fields (some with multi-sentence strings).
    _BASE  = 1024
    _PER   = 512
    _MIN   = 3072
    _MAX   = 8192
    json_tokens = min(_MAX, max(_MIN, _BASE + n_findings * _PER))
    kwargs = dict(
        model=model,
        max_tokens=json_tokens + thinking_budget if thinking_budget else json_tokens,
        system=_SYSTEM,
    )
    if thinking_budget:
        kwargs['thinking'] = {'type': 'enabled', 'budget_tokens': thinking_budget}

    _RETRY_NOTE = (
        "IMPORTANT: your previous response was not valid JSON.  "
        "Output ONLY the JSON object — nothing before the opening brace, "
        "nothing after the closing brace, no markdown fences, no prose.\n\n"
    )

    _ctx = debug_lock if debug_lock is not None else nullcontext()

    def _dbg(title, body, footer=None):
        if debug_fh:
            with _ctx:
                _write_debug(debug_fh, title, body, footer)

    def _dbg_raw(text):
        if debug_fh:
            with _ctx:
                debug_fh.write(text)
                debug_fh.flush()

    last_exc = None
    for attempt in range(2):
        msg_prompt = (_RETRY_NOTE + prompt) if attempt else prompt
        kwargs['messages'] = [{'role': 'user', 'content': msg_prompt}]

        _dbg(f"{'PROMPT (retry)' if attempt else 'PROMPT'} — {fn_label}", msg_prompt)

        msg = client.messages.create(**kwargs)

        thinking_text = ''
        response_text = ''
        for block in msg.content:
            if block.type == 'thinking':
                thinking_text = block.thinking
            elif block.type == 'text':
                response_text = block.text.strip()

        if thinking_text:
            _dbg(f'THINKING — {fn_label}', thinking_text)
        usage = msg.usage
        _dbg(f'RESPONSE — {fn_label}', response_text,
             footer=(f"stop={msg.stop_reason}  "
                     f"in={usage.input_tokens}  out={usage.output_tokens}"))

        if msg.stop_reason == 'max_tokens':
            raise ValueError(
                f"output truncated at {json_tokens} tokens ({len(response_text)} chars) — "
                f"response cut mid-JSON; consider using --thinking or reducing findings per function"
            )

        if verbose:
            suffix = ' (retry)' if attempt else ''
            print(f"[{len(response_text)} chars{suffix}]", end=' ')

        # Strip accidental fences, then use raw_decode to find the first valid JSON object
        text = re.sub(r'^```(?:json)?\s*', '', response_text, flags=re.MULTILINE)
        text = re.sub(r'\s*```$', '', text, flags=re.MULTILINE).strip()

        start = text.find('{')
        if start == -1:
            last_exc = ValueError(f"No JSON object in response: {text[:200]!r}")
            continue
        decoder = json.JSONDecoder()
        try:
            obj, _ = decoder.raw_decode(text, start)
            return obj
        except json.JSONDecodeError as e:
            last_exc = ValueError(f"JSON parse error: {e}\n{text[start:start+300]}")
            _dbg_raw(f"\n[JSON parse failed on attempt {attempt}, "
                     f"{'retrying' if attempt == 0 else 'giving up'}]: {e}\n")

    raise last_exc


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
