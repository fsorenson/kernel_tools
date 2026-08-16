"""
Report formatter for bounds checker Stage 1 + Stage 2 output.

Writes:
  <run_dir>/report.md   — Markdown (grep-friendly, GitHub-renderable)
  <run_dir>/report.html — Self-contained HTML with inline CSS
"""

import html as html_mod
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def write_reports(run_dir, stage1_output, stage2_output, formats=('md', 'html')):
    """
    Write report files into run_dir.

    stage1_output: dict from stage1_taint_scan.run() (or loaded from JSON).
    stage2_output: dict from stage2_llm_analysis.run() (or loaded from JSON).
    formats: iterable of 'md' and/or 'html'.
    """
    run_dir = Path(run_dir)
    ctx = _build_context(run_dir, stage1_output, stage2_output)

    written = []
    if 'md' in formats:
        path = run_dir / 'report.md'
        path.write_text(_render_md(ctx), encoding='utf-8')
        written.append(path)
    if 'html' in formats:
        path = run_dir / 'report.html'
        path.write_text(_render_html(ctx), encoding='utf-8')
        written.append(path)

    for p in written:
        print(f"  Report: {p}")

    write_summary(run_dir, stage1_output, stage2_output, formats)
    return written


# ---------------------------------------------------------------------------
# Context assembly
# ---------------------------------------------------------------------------

_CAT_LABEL = {
    'A': 'Cat A — server offset → pointer → memory op',
    'B': 'Cat B — server value → size/alloc argument',
    'C': 'Cat C — server value → array subscript',
    'D': 'Cat D — strlen/strlcpy on server-supplied buffer (no null-termination guarantee)',
    'E': 'Cat E — tainted pointer dereference (->field access beyond packet bounds)',
    'F':  'Cat F — server value → loop iteration count',
    'G1': 'Cat G1 — copy_from/to_user return value unchecked (partial copy = success)',
    'G2': 'Cat G2 — unvalidated size argument to copy_from/to_user',
    'H':  'Cat H — server value → narrow integer type (silent truncation)',
}
_ASSESSMENT_LABEL = {
    'real_bug': 'BUG', 'false_positive': 'FP',
    'needs_validation': 'VALIDATE', 'mixed': 'MIXED', 'error': 'ERROR',
}


def _rel_path(filepath, kernel_root):
    """Convert absolute filepath to repo-relative path (e.g. fs/smb/client/cifssmb.c)."""
    if not filepath:
        return ''
    if kernel_root:
        try:
            return str(Path(filepath).relative_to(kernel_root))
        except ValueError:
            pass
    return Path(filepath).name


def _infer_kernel_root(source_dirs, filepaths):
    """Guess kernel root from source_dirs and sample absolute filepaths."""
    for sd in source_dirs:
        marker = '/' + sd.lstrip('/')
        for fp in filepaths:
            idx = fp.find(marker)
            if idx >= 0:
                return fp[:idx]
    return ''


def _build_context(run_dir, s1, s2):
    """Assemble everything the renderers need in one dict."""
    # Group stage1 findings by (function, file) so we can cross-ref by index
    s1_groups = defaultdict(list)
    for f in s1.get('findings', []):
        s1_groups[(f['function'], f['file'])].append(f)

    # Resolve kernel root for relative-path display
    kernel_root = (s1.get('kernel_source', '')
                   or _infer_kernel_root(
                       s1.get('source_dirs', []),
                       [f['file'] for f in s1.get('findings', [])[:50]],
                   ))

    # Index stage2 analyses for fast lookup.
    # stage2 now stores filepath in 'file'; also accept old basename-only format.
    s2_by_fn = {}
    for a in s2.get('analyses', []):
        s2_by_fn[(a['function'], a['file'])] = a

    # Build per-function sections, sorted by (filepath, fn_name) so the same
    # source file's functions appear together and grouped by directory.
    sections = []
    for (fn_name, filepath), s1_findings in sorted(s1_groups.items(),
                                                    key=lambda kv: (kv[0][1], kv[0][0])):
        short_file = Path(filepath).name
        rp = _rel_path(filepath, kernel_root)
        dp = str(Path(rp).parent) if rp and Path(rp).parent != Path('.') else rp
        analysis = (s2_by_fn.get((fn_name, filepath))
                    or s2_by_fn.get((fn_name, short_file), {}))
        # Build per-finding merged rows
        lkp = {f['finding_index']: f for f in analysis.get('findings', [])}
        rows = []
        for i, s1f in enumerate(s1_findings, 1):
            llm = lkp.get(i, {})
            xfn = s1f.get('propagation') == 'cross_function'
            overflow = s1f.get('overflow', False)
            if overflow:
                cat_label = (f"Cat {s1f['category']} — integer overflow: "
                             f"{s1f.get('overflow_lhs','')} "
                             f"{s1f.get('overflow_op','*')} "
                             f"{s1f.get('overflow_rhs','')}")
            else:
                cat_label = _CAT_LABEL.get(s1f['category'], s1f['category'])
            rows.append({
                'idx':             i,
                'propagation':     s1f.get('propagation', 'intra'),
                'overflow':        overflow,
                'overflow_op':     s1f.get('overflow_op', ''),
                'overflow_lhs':    s1f.get('overflow_lhs', ''),
                'overflow_rhs':    s1f.get('overflow_rhs', ''),
                'category':        s1f['category'],
                'cat_label':       cat_label,
                'taint_source_fn': s1f['taint_source_fn'],
                'taint_line':      s1f['taint_line'],
                'taint_snippet':   s1f['taint_snippet'],
                'tainted_var':     s1f['tainted_var'],
                # cross-function extras
                'callee_fn':           s1f.get('callee_fn', ''),
                'callee_file':         s1f.get('callee_file', ''),
                'callee_is_read_only': s1f.get('callee_is_read_only', False),
                'call_site_line':      s1f.get('call_site_line', ''),
                'call_site_snippet':   s1f.get('call_site_snippet', ''),
                'sink_fn':         s1f['sink_fn'],
                'sink_line':       s1f['sink_line'],
                'sink_snippet':    s1f['sink_snippet'],
                'sink_arg_index':  s1f['sink_arg_index'],
                'sink_arg_role':   s1f['sink_arg_role'],
                'src_width':       s1f.get('src_width'),
                'dest_width':      s1f.get('dest_width'),
                'dest_type':       s1f.get('dest_type', ''),
                'field_name':      s1f.get('field_name', ''),
                'possibly_guarded': s1f['possibly_guarded'],
                'reason':          s1f['reason'],
                # LLM fields (may be missing if no LLM run)
                'real_bug':        llm.get('real_bug'),
                'taint_server':    llm.get('taint_is_server_supplied'),
                'check_present':   llm.get('bounds_check_present'),
                'check_sufficient':llm.get('bounds_check_sufficient'),
                'impact':          llm.get('impact', ''),
                'symptom':         llm.get('symptom', ''),
                'suggested_fix':   llm.get('suggested_fix', ''),
                'cve_pattern':     llm.get('cve_pattern', ''),
                'notes':           llm.get('notes', ''),
            })

        assessment = analysis.get('assessment', 'unknown')
        sections.append({
            'fn_name':       fn_name,
            'short_file':    short_file,
            'rel_path':      rp,
            'dir_path':      dp,
            'filepath':      filepath,
            'assessment':    assessment,
            'label':         _ASSESSMENT_LABEL.get(assessment, assessment.upper()),
            'confidence':    analysis.get('confidence', '—'),
            'overall_notes': analysis.get('overall_notes', ''),
            'error':         analysis.get('error', ''),
            'findings':      rows,
            'real_count':    sum(1 for r in rows if r['real_bug']),
            'fp_count':      sum(1 for r in rows if r['real_bug'] is False),
            'unanalyzed':    sum(1 for r in rows if r['real_bug'] is None),
        })

    # Totals
    total_real = sum(s['real_count'] for s in sections)
    total_fp   = sum(s['fp_count']   for s in sections)
    total_unk  = sum(s['unanalyzed'] for s in sections)
    s1_by_cat  = {}
    for f in s1.get('findings', []):
        s1_by_cat.setdefault(f['category'], 0)
        s1_by_cat[f['category']] += 1

    # Precompute per-directory stats for TOC and summary grouping
    dir_stats = {}
    for s in sections:
        dp = s['dir_path']
        if dp not in dir_stats:
            dir_stats[dp] = {'count': 0, 'real': 0, 'fp': 0, 'unk': 0}
        dir_stats[dp]['count'] += 1
        dir_stats[dp]['real'] += s['real_count']
        dir_stats[dp]['fp']   += s['fp_count']
        dir_stats[dp]['unk']  += s['unanalyzed']

    run_name = run_dir.name
    now_str  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    return {
        'run_name':    run_name,
        'run_dir':     str(run_dir),
        'now_str':     now_str,
        'model':       s2.get('model', '—'),
        'source_dirs': s1.get('source_dirs', []),
        'files_scanned': s1.get('files_scanned', 0),
        'kernel_git':  s1.get('kernel_git', {}),
        's1_total':    s1.get('findings_count', 0),
        's1_by_cat':   s1_by_cat,
        'fn_analyzed': s2.get('functions_analyzed', len(sections)),
        'total_real':  total_real,
        'total_fp':    total_fp,
        'total_unk':   total_unk,
        'sections':    sections,
        'dir_stats':   dir_stats,
        'has_llm':     bool(s2.get('analyses')),
    }


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def _git_md_block(git):
    """Return Markdown lines for the kernel git block, or [] if no info."""
    if not git or not git.get('version'):
        return []
    lines = []
    ver    = git.get('version', '')
    branch = git.get('branch', '')
    commits = git.get('commits', [])
    base   = git.get('base_ref', '')

    lines.append(f"**Kernel:** `{ver}`  ")
    if branch:
        lines.append(f"**Branch:** `{branch}`  ")
    if commits:
        base_label = f" since `{base}`" if base else ''
        lines.append(f"**Local commits**{base_label} ({len(commits)}):  ")
        for c in commits:
            lines.append(f"- `{c['hash']}` {c['subject']}")
    elif base:
        lines.append(f"**Local commits:** none (at `{base}` tip)  ")
    return lines


def _render_md(ctx):
    buf = []
    W = buf.append

    W(f"# Bounds Checker Report — {ctx['run_name']}\n")
    W(f"**Date:** {ctx['now_str']}  ")
    W(f"**Model:** {ctx['model']}  ")
    W(f"**Source:** {', '.join(ctx['source_dirs'])}  ")
    W(f"**Files scanned:** {ctx['files_scanned']}\n")

    for line in _git_md_block(ctx.get('kernel_git', {})):
        W(line)
    W("")

    cat_parts = ', '.join(f"Cat {c}: {n}" for c, n in sorted(ctx['s1_by_cat'].items()))
    W(f"**Stage 1 findings:** {ctx['s1_total']} ({cat_parts})  ")
    if ctx['has_llm']:
        W(f"**Stage 2 LLM:**  "
          f"{ctx['total_real']} real bug(s)  |  "
          f"{ctx['total_fp']} false positive(s)  |  "
          f"{ctx['total_unk']} unanalyzed\n")
    else:
        W("**Stage 2 LLM:** not run\n")

    W("\n---\n")

    # Contents — grouped by directory
    W("## Contents\n")
    current_dir = None
    for s in ctx['sections']:
        dp = s['dir_path']
        if dp != current_dir:
            if current_dir is not None:
                W("")
            ds = ctx['dir_stats'][dp]
            dir_hdr = f"### `{dp}/`"
            if ctx['has_llm']:
                dir_hdr += (f" — {ds['count']} function{'s' if ds['count'] != 1 else ''}"
                            f", {ds['real']} real, {ds['fp']} FP")
            else:
                dir_hdr += f" — {ds['count']} function{'s' if ds['count'] != 1 else ''}"
            W(dir_hdr + "\n")
            current_dir = dp
        anchor = _anchor(s['fn_name'], s['rel_path'])
        badge_str = f" — **{s['label']}**" if ctx['has_llm'] and s['assessment'] != 'unknown' else ''
        W(f"- [{s['fn_name']}()](#{anchor}) — `{s['short_file']}`{badge_str}")
    W("")

    W("\n---\n")

    # Summary table (LLM columns only when LLM ran), grouped by directory
    W("## Summary\n")
    current_dir = None
    if ctx['has_llm']:
        W("| Function | File | Assessment | Conf | Real | FP | Unanalyzed |")
        W("|---|---|---|---|---|---|---|")
        for s in ctx['sections']:
            dp = s['dir_path']
            if dp != current_dir:
                ds = ctx['dir_stats'][dp]
                W(f"| **`{dp}/`** ({ds['count']} fn)"
                  f" | | | | **{ds['real']}** | **{ds['fp']}** | **{ds['unk']}** |")
                current_dir = dp
            anchor = _anchor(s['fn_name'], s['rel_path'])
            W(f"| [{s['fn_name']}()](#{anchor}) "
              f"| {s['rel_path']} "
              f"| {s['label']} "
              f"| {s['confidence']} "
              f"| {s['real_count']} "
              f"| {s['fp_count']} "
              f"| {s['unanalyzed']} |")
    else:
        W("| Function | File | Findings |")
        W("|---|---|---|")
        for s in ctx['sections']:
            dp = s['dir_path']
            if dp != current_dir:
                ds = ctx['dir_stats'][dp]
                W(f"| **`{dp}/`** ({ds['count']} fn) | | {ds['count']} |")
                current_dir = dp
            W(f"| {s['fn_name']} | {s['rel_path']} | {len(s['findings'])} |")
    W("")

    # Per-function sections
    W("\n---\n")
    W("## Function Details\n")
    for s in ctx['sections']:
        anchor = _anchor(s['fn_name'], s['rel_path'])
        W(f'### <a name="{anchor}"></a>{s["fn_name"]}() — `{s["rel_path"]}`\n')
        if ctx['has_llm'] and s['assessment'] != 'unknown':
            W(f"**Assessment:** {s['label']}  |  **Confidence:** {s['confidence']}\n")
            if s['error']:
                W(f"> **Error:** {s['error']}\n")
            elif s['overall_notes']:
                W(f"> {s['overall_notes']}\n")

        for r in s['findings']:
            _md_finding(buf, r, ctx['has_llm'])

        W("")

    return '\n'.join(buf)


def _anchor(fn_name, rel_path=''):
    fn_slug = re.sub(r'[^a-z0-9]+', '-', fn_name.lower()).strip('-')
    if rel_path:
        path_slug = re.sub(r'[^a-z0-9]+', '-', rel_path.lower()).strip('-')
        return f"{fn_slug}--{path_slug}"
    return fn_slug


def _md_finding(buf, r, has_llm):
    W = buf.append
    verdict = ''
    if has_llm:
        if r['real_bug'] is True:
            verdict = f" — **BUG** ({r['impact'] or 'impact unknown'})"
        elif r['real_bug'] is False:
            verdict = " — ~~false positive~~"
        else:
            verdict = " — *unanalyzed*"

    xfn = r.get('propagation') == 'cross_function'
    ovf = r.get('overflow', False)
    ro_tag = ' *(read-only callee)*' if xfn and r.get('callee_is_read_only') else ''
    xfn_tag = f" — cross-function via `{r['callee_fn']}()`{ro_tag}" if xfn else ''
    ovf_tag = ' — **INTEGER OVERFLOW**' if ovf else ''
    W(f"#### Finding #{r['idx']} — Category {r['category']}{xfn_tag}{ovf_tag}{verdict}\n")
    W(f"| Field | Value |")
    W(f"|---|---|")
    W(f"| Category | {r['cat_label']} |")
    W(f"| Taint source | `{r['taint_source_fn']}()` line {r['taint_line']} |")
    W(f"| Taint snippet | `{r['taint_snippet']}` |")
    W(f"| Tainted var | `{r['tainted_var']}` |")
    if ovf:
        W(f"| Overflow expr | `{r['overflow_lhs']} {r['overflow_op']} {r['overflow_rhs']}` |")
        W(f"| Safe fix | `kmalloc_array()` or `check_mul_overflow()` |")
    if xfn:
        W(f"| Call site | line {r['call_site_line']} — passes `{r['tainted_var']}` to `{r['callee_fn']}()` |")
        W(f"| Call snippet | `{r['call_site_snippet']}` |")
    role = r['sink_arg_role']
    if role == 'narrowed_value':
        W(f"| Truncation | line {r['sink_line']}: "
          f"{r.get('src_width','?')}-bit → {r.get('dest_width','?')}-bit `{r.get('dest_type','')}` |")
    elif role == 'loop_bound':
        W(f"| Loop | `{r['sink_fn']}` line {r['sink_line']} |")
    elif role == 'subscript':
        W(f"| {'Subscript (in callee)' if xfn else 'Subscript'} | `{r['sink_fn']}` line {r['sink_line']} |")
    elif role == 'string_arg':
        W(f"| String sink | `{r['sink_fn']}()` arg {r['sink_arg_index']} line {r['sink_line']} |")
    elif role == 'tainted_ptr_deref':
        W(f"| Pointer deref | `{r['tainted_var']}->{r.get('field_name','?')}` line {r['sink_line']} |")
    elif role == 'retval_discarded':
        W(f"| Retval discarded | `{r['sink_fn']}()` line {r['sink_line']} — return value not captured |")
    elif role == 'retval_unchecked':
        W(f"| Retval unchecked | `{r['sink_fn']}()` line {r['sink_line']} — "
          f"`{r['tainted_var']}` never checked against zero |")
    elif role == 'unvalidated_size':
        W(f"| Unvalidated size | `{r['sink_fn']}()` arg {r['sink_arg_index']} line {r['sink_line']} — "
          f"size `{r['tainted_var']}` |")
    elif xfn:
        W(f"| Sink (in callee) | `{r['sink_fn']}()` line {r['sink_line']} (arg {r['sink_arg_index']}, role={role}) |")
    else:
        W(f"| Sink | `{r['sink_fn']}()` line {r['sink_line']} (arg {r['sink_arg_index']}, role={role}) |")
    W(f"| Sink snippet | `{r['sink_snippet']}` |")
    W(f"| Possibly guarded | {'yes (heuristic)' if r['possibly_guarded'] else 'no'} |")

    if has_llm and r['real_bug'] is True:
        W(f"| Server-supplied | {'yes' if r['taint_server'] else 'no'} |")
        W(f"| Check present | {'yes' if r['check_present'] else 'no'} |")
        W(f"| Check sufficient | {'yes' if r['check_sufficient'] else 'no'} |")
        if r['symptom']:
            W(f"\n**Symptom:** {r['symptom']}\n")
        if r['suggested_fix']:
            W(f"**Fix:** {r['suggested_fix']}\n")
        if r['cve_pattern']:
            W(f"**CVE pattern:** {r['cve_pattern']}\n")
    elif has_llm and r['real_bug'] is False and r['notes']:
        W(f"\n*Dismissed:* {r['notes']}\n")

    W("")


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

_CSS = """\
:root {
  --bg: #f8f8f8; --fg: #222; --border: #ccc;
  --code-bg: #eee; --hdr-bg: #2a3d5a; --hdr-fg: #fff;
  --bug: #c00; --fp: #2a7a2a; --mixed: #b06000; --validate: #1a5fa8;
  --err: #666; --unknown: #888;
  --oob_write: #8b0000; --oob_read: #c00; --integer_overflow: #b06000;
  --undersized_alloc: #b06000; --stack_overflow: #6a0dad;
  --info_disclosure: #1a5fa8; --none: #666;
}
* { box-sizing: border-box; }
body { font-family: 'Liberation Mono', 'Courier New', monospace;
       font-size: 13px; background: var(--bg); color: var(--fg);
       margin: 0; padding: 0; }
h1 { background: var(--hdr-bg); color: var(--hdr-fg);
     margin: 0; padding: 16px 24px; font-size: 18px; }
.meta { background: #e8edf3; padding: 10px 24px;
        border-bottom: 1px solid var(--border); line-height: 1.8; }
.meta span { margin-right: 24px; }
.meta .key { color: #555; font-weight: bold; }
main { padding: 16px 24px; }
h2 { font-size: 15px; border-bottom: 2px solid var(--hdr-bg);
     padding-bottom: 4px; margin-top: 28px; }
h3 { font-size: 13px; background: #dde4ee; padding: 6px 10px;
     margin: 18px 0 6px; border-left: 4px solid var(--hdr-bg); }
h4 { font-size: 12px; margin: 12px 0 4px; padding: 4px 8px;
     border-left: 3px solid #aaa; background: #f0f0f0; }
h4.bug  { border-color: var(--bug);      background: #fff0f0; }
h4.fp   { border-color: var(--fp);       background: #f0fff0; }
h4.unk  { border-color: var(--unknown);  background: #f8f8f8; }
table { border-collapse: collapse; margin: 6px 0; width: 100%; }
td, th { border: 1px solid var(--border); padding: 4px 8px;
         vertical-align: top; }
th { background: #dde; text-align: left; }
.summary-table td:nth-child(3) { font-weight: bold; }
code { background: var(--code-bg); padding: 1px 4px; border-radius: 2px; }
.badge { display: inline-block; padding: 1px 7px; border-radius: 3px;
         color: #fff; font-weight: bold; font-size: 11px; }
.badge.BUG      { background: var(--bug); }
.badge.FP       { background: var(--fp); }
.badge.MIXED    { background: var(--mixed); }
.badge.VALIDATE { background: var(--validate); }
.badge.ERROR    { background: var(--err); }
.badge.unknown  { background: var(--unknown); }
.impact { display: inline-block; padding: 1px 6px; border-radius: 3px;
          color: #fff; font-size: 11px; font-weight: bold; }
.impact.oob_write        { background: var(--oob_write); }
.impact.oob_read         { background: var(--oob_read); }
.impact.integer_overflow { background: var(--integer_overflow); }
.impact.undersized_alloc { background: var(--undersized_alloc); }
.impact.stack_overflow   { background: var(--stack_overflow); }
.impact.info_disclosure  { background: var(--info_disclosure); }
.fix  { background: #e8ffe8; border-left: 3px solid var(--fp);
        padding: 6px 10px; margin: 6px 0; }
.sym  { background: #fff0e0; border-left: 3px solid var(--mixed);
        padding: 6px 10px; margin: 6px 0; }
.cve  { background: #f0e8ff; border-left: 3px solid var(--stack_overflow);
        padding: 6px 10px; margin: 6px 0; }
.note { background: #f8f8f8; border-left: 3px solid #aaa;
        padding: 4px 10px; margin: 4px 0; color: #555; }
.overall { background: #fafbff; border: 1px solid #c8d4e8;
           padding: 8px 12px; margin: 6px 0 10px; font-style: italic; }
.toc { column-count: unset; }
.toc details { margin-bottom: 2px; }
.toc-dir-hdr { cursor: pointer; color: var(--hdr-bg); font-weight: bold;
               padding: 2px 4px; user-select: none; }
.toc-dir { margin-left: 16px; column-count: 2; column-gap: 20px; padding: 2px 0 4px; }
.toc a { display: block; padding: 1px 0; text-decoration: none; color: #1a5fa8; }
.toc a:hover { text-decoration: underline; }
tr.dir-hdr { background: #dde4ee; }
tr.dir-hdr td { font-weight: bold; padding: 3px 8px; color: var(--hdr-bg); }
.fp-dim { color: #888; }
"""


def _e(s):
    """HTML-escape a value."""
    return html_mod.escape(str(s) if s is not None else '')


def _badge(assessment):
    label = _ASSESSMENT_LABEL.get(assessment, assessment.upper())
    return f'<span class="badge {label}">{label}</span>'


def _impact_badge(impact):
    if not impact or impact == 'none':
        return ''
    cls = impact.replace(' ', '_')
    return f' <span class="impact {cls}">{_e(impact)}</span>'


def _html_git_block(W, git):
    """Emit an HTML git-info block inside the meta bar (collapsible commit list)."""
    if not git or not git.get('version'):
        return
    ver     = _e(git.get('version', ''))
    branch  = _e(git.get('branch', ''))
    commits = git.get('commits', [])
    base    = _e(git.get('base_ref', ''))

    W(f'<span><span class="key">Kernel:</span> <code>{ver}</code></span>')
    if branch:
        W(f'<span><span class="key">Branch:</span> <code>{branch}</code></span>')
    if commits:
        label = f"since <code>{base}</code>" if base else "local"
        W(f'<span style="display:block;margin-top:4px">'
          f'<details><summary style="cursor:pointer;color:#1a5fa8">'
          f'{len(commits)} local commit(s) {label}</summary>'
          f'<ol style="margin:4px 0 0 1.5em;padding:0;font-size:11px">')
        for c in commits:
            W(f'<li><code>{_e(c["hash"])}</code> {_e(c["subject"])}</li>')
        W('</ol></details></span>')
    elif base:
        W(f'<span><span class="key">Local commits:</span> '
          f'none (at <code>{base}</code> tip)</span>')


def _render_html(ctx):
    lines = []
    W = lines.append

    W('<!DOCTYPE html>')
    W('<html lang="en"><head><meta charset="utf-8">')
    W(f'<title>Bounds Checker — {_e(ctx["run_name"])}</title>')
    W(f'<style>{_CSS}</style></head><body>')
    W(f'<h1>Bounds Checker Report &mdash; {_e(ctx["run_name"])}</h1>')

    # Meta bar
    W('<div class="meta">')
    cat_parts = ' &nbsp;|&nbsp; '.join(
        f"Cat {c}: {n}" for c, n in sorted(ctx['s1_by_cat'].items())
    )
    W(f'<span><span class="key">Date:</span> {_e(ctx["now_str"])}</span>')
    W(f'<span><span class="key">Model:</span> {_e(ctx["model"])}</span>')
    W(f'<span><span class="key">Source:</span> {_e(", ".join(ctx["source_dirs"]))}</span>')
    W(f'<span><span class="key">Files:</span> {ctx["files_scanned"]}</span>')
    W(f'<span><span class="key">Stage 1:</span> {ctx["s1_total"]} findings ({cat_parts})</span>')
    if ctx['has_llm']:
        W(f'<span><span class="key">Stage 2:</span> '
          f'<b style="color:var(--bug)">{ctx["total_real"]} real</b> &nbsp;|&nbsp; '
          f'{ctx["total_fp"]} FP &nbsp;|&nbsp; '
          f'{ctx["total_unk"]} unanalyzed</span>')
    else:
        W('<span><span class="key">Stage 2:</span> not run</span>')
    _html_git_block(W, ctx.get('kernel_git', {}))
    W('</div><main>')

    # Table of contents — grouped by directory
    W('<h2>Contents</h2><div class="toc">')
    current_dir = None
    for s in ctx['sections']:
        dp = s['dir_path']
        if dp != current_dir:
            if current_dir is not None:
                W('</div></details>')
            ds = ctx['dir_stats'][dp]
            # Open dirs that have real bugs; always open when only one directory
            has_bugs = ds['real'] > 0
            open_attr = ' open' if has_bugs or len(ctx['dir_stats']) == 1 else ''
            summary_txt = f"{_e(dp)}/ ({ds['count']} function{'s' if ds['count'] != 1 else ''})"
            if ctx['has_llm']:
                summary_txt += f" &mdash; {ds['real']} real, {ds['fp']} FP"
            W(f'<details{open_attr}>'
              f'<summary class="toc-dir-hdr">{summary_txt}</summary>'
              f'<div class="toc-dir">')
            current_dir = dp
        anchor = _anchor(s['fn_name'], s['rel_path'])
        badge = _badge(s['assessment']) if ctx['has_llm'] and s['assessment'] != 'unknown' else ''
        W(f'<a href="#{anchor}">{_e(s["fn_name"])}() &mdash; {_e(s["short_file"])} {badge}</a>')
    if current_dir is not None:
        W('</div></details>')
    W('</div>')

    # Summary table
    W('<h2>Summary</h2>')
    W('<table class="summary-table">')
    current_dir = None
    if ctx['has_llm']:
        W('<tr><th>Function</th><th>File</th><th>Assessment</th>'
          '<th>Confidence</th><th>Real</th><th>FP</th><th>Unanalyzed</th></tr>')
        for s in ctx['sections']:
            dp = s['dir_path']
            if dp != current_dir:
                ds = ctx['dir_stats'][dp]
                W(f'<tr class="dir-hdr"><td colspan="7">{_e(dp)}/'
                  f' &mdash; {ds["count"]} function{"s" if ds["count"] != 1 else ""}'
                  f', {ds["real"]} real, {ds["fp"]} FP</td></tr>')
                current_dir = dp
            anchor = _anchor(s['fn_name'], s['rel_path'])
            W(f'<tr>'
              f'<td><a href="#{anchor}">{_e(s["fn_name"])}()</a></td>'
              f'<td>{_e(s["rel_path"])}</td>'
              f'<td>{_badge(s["assessment"])}</td>'
              f'<td>{_e(s["confidence"])}</td>'
              f'<td style="color:var(--bug)">{s["real_count"]}</td>'
              f'<td style="color:var(--fp)">{s["fp_count"]}</td>'
              f'<td>{s["unanalyzed"]}</td>'
              f'</tr>')
    else:
        W('<tr><th>Function</th><th>File</th><th>Findings</th></tr>')
        for s in ctx['sections']:
            dp = s['dir_path']
            if dp != current_dir:
                ds = ctx['dir_stats'][dp]
                W(f'<tr class="dir-hdr"><td colspan="3">{_e(dp)}/'
                  f' &mdash; {ds["count"]} function{"s" if ds["count"] != 1 else ""}</td></tr>')
                current_dir = dp
            W(f'<tr><td>{_e(s["fn_name"])}()</td>'
              f'<td>{_e(s["rel_path"])}</td>'
              f'<td>{len(s["findings"])}</td></tr>')
    W('</table>')

    # Per-function sections
    W('<h2>Function Details</h2>')
    for s in ctx['sections']:
        anchor = _anchor(s['fn_name'], s['rel_path'])
        badge = _badge(s['assessment']) if ctx['has_llm'] and s['assessment'] != 'unknown' else ''
        conf = f'confidence={_e(s["confidence"])}' if ctx['has_llm'] else ''
        W(f'<h3 id="{anchor}">{_e(s["fn_name"])}() &mdash; '
          f'<code>{_e(s["rel_path"])}</code> {badge} {conf}</h3>')

        if ctx['has_llm']:
            if s['error']:
                W(f'<div class="note"><b>Error:</b> {_e(s["error"])}</div>')
            elif s['overall_notes']:
                W(f'<div class="overall">{_e(s["overall_notes"])}</div>')

        for r in s['findings']:
            _html_finding(lines, r, ctx['has_llm'])

    W('</main></body></html>')
    return '\n'.join(lines)


def _html_finding(lines, r, has_llm):
    W = lines.append

    real = r['real_bug']
    if has_llm:
        if real is True:
            hcls = 'bug'
            verdict = f'<b style="color:var(--bug)">BUG</b>{_impact_badge(r["impact"])}'
        elif real is False:
            hcls = 'fp'
            verdict = '<span style="color:var(--fp)">false positive</span>'
        else:
            hcls = 'unk'
            verdict = '<span style="color:var(--unknown)">unanalyzed</span>'
    else:
        hcls = 'unk'
        verdict = ''

    verdict_sep = ' &mdash; ' if verdict else ''
    xfn = r.get('propagation') == 'cross_function'
    ovf = r.get('overflow', False)
    ro_str = ' <span style="color:#888;font-style:italic">(read-only callee)</span>' \
             if xfn and r.get('callee_is_read_only') else ''
    xfn_str = (f' &mdash; cross-function via <code>{_e(r["callee_fn"])}()</code>{ro_str}'
               if xfn else '')
    ovf_str = ' &mdash; <b style="color:var(--oob_write)">INTEGER OVERFLOW</b>' if ovf else ''
    W(f'<h4 class="{hcls}">Finding #{r["idx"]} &mdash; Category {_e(r["category"])}'
      f'{xfn_str}{ovf_str}{verdict_sep}{verdict}</h4>')

    W('<table>')
    W(f'<tr><th>Category</th><td>{_e(r["cat_label"])}</td></tr>')
    W(f'<tr><th>Taint source</th><td>'
      f'<code>{_e(r["taint_source_fn"])}()</code> line {r["taint_line"]}</td></tr>')
    W(f'<tr><th>Taint snippet</th><td><code>{_e(r["taint_snippet"])}</code></td></tr>')
    W(f'<tr><th>Tainted var</th><td><code>{_e(r["tainted_var"])}</code></td></tr>')
    if ovf:
        W(f'<tr><th>Overflow expr</th><td><code>{_e(r["overflow_lhs"])} '
          f'{_e(r["overflow_op"])} {_e(r["overflow_rhs"])}</code></td></tr>')
        W(f'<tr><th>Safe fix</th><td><code>kmalloc_array()</code> or '
          f'<code>check_mul_overflow()</code></td></tr>')
    if xfn:
        W(f'<tr><th>Call site</th><td>line {r["call_site_line"]} &mdash; '
          f'passes <code>{_e(r["tainted_var"])}</code> to '
          f'<code>{_e(r["callee_fn"])}()</code></td></tr>')
        W(f'<tr><th>Call snippet</th><td><code>{_e(r["call_site_snippet"])}</code></td></tr>')
    role = r['sink_arg_role']
    if role == 'narrowed_value':
        W(f'<tr><th>Truncation</th><td>line {r["sink_line"]}: '
          f'{r.get("src_width","?")} → {r.get("dest_width","?")}-bit '
          f'<code>{_e(r.get("dest_type",""))}</code></td></tr>')
    elif role == 'loop_bound':
        W(f'<tr><th>Loop</th><td>'
          f'<code>{_e(r["sink_fn"])}</code> line {r["sink_line"]}</td></tr>')
    elif role == 'subscript':
        lbl = 'Subscript (in callee)' if xfn else 'Subscript'
        W(f'<tr><th>{lbl}</th><td>'
          f'<code>{_e(r["sink_fn"])}</code> line {r["sink_line"]}</td></tr>')
    elif role == 'string_arg':
        W(f'<tr><th>String sink</th><td>'
          f'<code>{_e(r["sink_fn"])}()</code> arg {r["sink_arg_index"]} '
          f'line {r["sink_line"]}</td></tr>')
    elif role == 'tainted_ptr_deref':
        W(f'<tr><th>Pointer deref</th><td>'
          f'<code>{_e(r["tainted_var"])}->{_e(r.get("field_name","?"))}</code> '
          f'line {r["sink_line"]}</td></tr>')
    elif role == 'retval_discarded':
        W(f'<tr><th>Retval discarded</th><td>'
          f'<code>{_e(r["sink_fn"])}()</code> line {r["sink_line"]} &mdash; '
          f'return value not captured</td></tr>')
    elif role == 'retval_unchecked':
        W(f'<tr><th>Retval unchecked</th><td>'
          f'<code>{_e(r["sink_fn"])}()</code> line {r["sink_line"]} &mdash; '
          f'<code>{_e(r["tainted_var"])}</code> never checked against zero</td></tr>')
    elif role == 'unvalidated_size':
        W(f'<tr><th>Unvalidated size</th><td>'
          f'<code>{_e(r["sink_fn"])}()</code> arg {r["sink_arg_index"]} '
          f'line {r["sink_line"]} &mdash; size <code>{_e(r["tainted_var"])}</code></td></tr>')
    elif xfn:
        W(f'<tr><th>Sink (in callee)</th><td>'
          f'<code>{_e(r["sink_fn"])}()</code> line {r["sink_line"]} '
          f'(arg {r["sink_arg_index"]}, role={_e(role)})</td></tr>')
    else:
        W(f'<tr><th>Sink</th><td>'
          f'<code>{_e(r["sink_fn"])}()</code> line {r["sink_line"]} '
          f'(arg {r["sink_arg_index"]}, role={_e(role)})</td></tr>')
    W(f'<tr><th>Sink snippet</th><td><code>{_e(r["sink_snippet"])}</code></td></tr>')
    guarded = 'yes (heuristic)' if r['possibly_guarded'] else 'no'
    W(f'<tr><th>Possibly guarded</th><td>{guarded}</td></tr>')
    if has_llm and real is True:
        W(f'<tr><th>Server-supplied</th>'
          f'<td>{"yes" if r["taint_server"] else "no"}</td></tr>')
        W(f'<tr><th>Check present</th>'
          f'<td>{"yes" if r["check_present"] else "no"}</td></tr>')
        W(f'<tr><th>Check sufficient</th>'
          f'<td>{"yes" if r["check_sufficient"] else "no"}</td></tr>')
    W('</table>')

    if has_llm:
        if real is True:
            if r['symptom']:
                W(f'<div class="sym"><b>Symptom:</b> {_e(r["symptom"])}</div>')
            if r['suggested_fix']:
                W(f'<div class="fix"><b>Fix:</b> {_e(r["suggested_fix"])}</div>')
            if r['cve_pattern']:
                W(f'<div class="cve"><b>CVE pattern:</b> {_e(r["cve_pattern"])}</div>')
        elif real is False and r['notes']:
            W(f'<div class="note fp-dim"><i>Dismissed:</i> {_e(r["notes"])}</div>')


# ---------------------------------------------------------------------------
# Priority summary (cross-file ranked list)
# ---------------------------------------------------------------------------

# Scoring weights — tune here without touching the renderers.
_IMPACT_SCORE = {
    'oob_write': 100, 'stack_overflow': 90, 'oob_read': 80,
    'integer_overflow': 60, 'undersized_alloc': 60, 'info_disclosure': 40,
}
_CAT_BASE = {'A': 50, 'E': 50, 'C': 40, 'B': 40, 'F': 30, 'G1': 30, 'G2': 40, 'H': 20}

_TIERS = [
    (250, 'Critical'),   # LLM-confirmed real bug
    (100, 'High'),       # unanalyzed, unguarded, dangerous category
    (60,  'Medium'),     # unanalyzed/guarded or lower-category
    (0,   'Low'),        # likely false positive, low-risk
]

_SUMMARY_TOP_N = 30     # rows shown in the "top findings" MD table


def _score_finding(s1f, llm):
    score = _CAT_BASE.get(s1f['category'], 10)
    real  = llm.get('real_bug')
    if real is True:
        score += 200 + _IMPACT_SCORE.get(llm.get('impact', ''), 0)
    elif real is None:
        score += 50    # unanalyzed — assume it could be real
    if not s1f['possibly_guarded']:
        score += 20
    if s1f.get('overflow'):
        score += 30
    return score


def _tier_label(score):
    for threshold, label in _TIERS:
        if score >= threshold:
            return label
    return 'Low'


def _sink_label(s1f):
    role = s1f.get('sink_arg_role', '')
    if role == 'narrowed_value':
        return 'truncation'
    if role == 'loop_bound':
        return 'loop bound'
    if role == 'subscript':
        xfn = s1f.get('propagation') == 'cross_function'
        return 'subscript (callee)' if xfn else 'subscript'
    if role == 'tainted_ptr_deref':
        return f"{s1f['tainted_var']}->{s1f.get('field_name', '?')}"
    if role == 'retval_discarded':
        return f"{s1f['sink_fn']}() retval discarded"
    if role == 'retval_unchecked':
        return f"{s1f['sink_fn']}() retval unchecked"
    if role == 'unvalidated_size':
        return f"{s1f['sink_fn']}() unvalidated size"
    if s1f.get('overflow'):
        return (f"{s1f.get('overflow_lhs','')} "
                f"{s1f.get('overflow_op','*')} "
                f"{s1f.get('overflow_rhs','')}")
    xfn = s1f.get('propagation') == 'cross_function'
    callee = s1f.get('callee_fn', '')
    if xfn and callee:
        return f"{s1f['sink_fn']}() in {callee}()"
    return f"{s1f['sink_fn']}()"


def _llm_verdict(llm, has_llm):
    if not has_llm:
        return '—'
    real = llm.get('real_bug')
    if real is True:
        impact = llm.get('impact', '')
        return f"BUG:{impact}" if impact and impact != 'none' else 'BUG'
    if real is False:
        return 'FP'
    return '?'


def _build_scored_rows(stage1_output, stage2_output):
    """Return sorted list of (score, s1f, llm, rel_path)."""
    kernel_root = (stage1_output.get('kernel_source', '')
                   or _infer_kernel_root(
                       stage1_output.get('source_dirs', []),
                       [f['file'] for f in stage1_output.get('findings', [])[:50]],
                   ))

    s2_by_fn = {}
    for a in stage2_output.get('analyses', []):
        s2_by_fn[(a['function'], a['file'])] = a

    s1_groups = defaultdict(list)
    for f in stage1_output.get('findings', []):
        s1_groups[(f['function'], f['file'])].append(f)

    rows = []
    for (fn_name, filepath), s1_findings in s1_groups.items():
        short_file = Path(filepath).name
        rp = _rel_path(filepath, kernel_root)
        analysis = (s2_by_fn.get((fn_name, filepath))
                    or s2_by_fn.get((fn_name, short_file), {}))
        lkp = {f['finding_index']: f for f in analysis.get('findings', [])}
        for i, s1f in enumerate(s1_findings, 1):
            llm = lkp.get(i, {})
            score = _score_finding(s1f, llm)
            rows.append((score, s1f, llm, rp))

    rows.sort(key=lambda x: (-x[0], x[1]['function'], x[1]['sink_line']))
    return rows


def write_summary(run_dir, stage1_output, stage2_output, formats=('md', 'html')):
    """Write cross-file priority summary (summary.md / summary.html)."""
    run_dir  = Path(run_dir)
    has_llm  = bool(stage2_output.get('analyses'))
    rows     = _build_scored_rows(stage1_output, stage2_output)
    now_str  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    run_name = run_dir.name
    source_dirs = stage1_output.get('source_dirs', [])
    git_info    = stage1_output.get('kernel_git', {})

    written = []
    if 'md' in formats:
        path = run_dir / 'summary.md'
        path.write_text(
            _render_summary_md(rows, has_llm, run_name, now_str, source_dirs, git_info),
            encoding='utf-8',
        )
        written.append(path)
    if 'html' in formats:
        path = run_dir / 'summary.html'
        path.write_text(
            _render_summary_html(rows, has_llm, run_name, now_str, source_dirs, git_info),
            encoding='utf-8',
        )
        written.append(path)

    for p in written:
        print(f"  Summary: {p}")
    return written


# -- Stat helpers ------------------------------------------------------------

def _cat_counts(rows):
    counts = {}
    for _, s1f, _, _ in rows:
        counts[s1f['category']] = counts.get(s1f['category'], 0) + 1
    return counts


def _tier_counts(rows, has_llm):
    counts = {}
    for score, s1f, llm, _ in rows:
        t = _tier_label(score)
        counts[t] = counts.get(t, 0) + 1
    return counts


def _file_counts(rows):
    counts = {}
    for _, s1f, _, rel_path in rows:
        counts[rel_path] = counts.get(rel_path, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


# -- Markdown renderer -------------------------------------------------------

def _render_summary_md(rows, has_llm, run_name, now_str, source_dirs, git_info=None):
    buf = []
    W = buf.append

    W(f"# Priority Summary — {run_name}\n")
    W(f"**Date:** {now_str}  ")
    W(f"**Source:** {', '.join(source_dirs)}  ")
    W(f"**Total findings:** {len(rows)}\n")

    for line in _git_md_block(git_info or {}):
        W(line)
    W("")

    # Tier breakdown
    tier_cts = _tier_counts(rows, has_llm)
    tier_parts = '  |  '.join(
        f"**{t}:** {tier_cts.get(t, 0)}"
        for t, _ in [('Critical', None), ('High', None),
                     ('Medium', None), ('Low', None)]
        if tier_cts.get(t, 0)
    )
    W(f"**Tier breakdown:** {tier_parts}\n")

    cat_cts = _cat_counts(rows)
    cat_parts = '  '.join(
        f"Cat {c}: {n}" for c, n in sorted(cat_cts.items())
    )
    W(f"**By category:** {cat_parts}\n")

    if has_llm:
        real_n  = sum(1 for _, _, llm, _ in rows if llm.get('real_bug') is True)
        fp_n    = sum(1 for _, _, llm, _ in rows if llm.get('real_bug') is False)
        unk_n   = sum(1 for _, _, llm, _ in rows if llm.get('real_bug') is None)
        W(f"**LLM:** {real_n} real bug(s)  |  {fp_n} FP  |  {unk_n} unanalyzed\n")

    W("\n---\n")

    # Top-N table (always show; truncate with note if more)
    top = rows[:_SUMMARY_TOP_N]
    W(f"## Top {min(len(rows), _SUMMARY_TOP_N)} Findings by Priority\n")
    llm_hdr = ' LLM |' if has_llm else ''
    W(f"| # | Tier | Cat | Function | File | Variable | Sink | Guard |{llm_hdr}")
    W(f"|---|---|---|---|---|---|---|---|{'---|' if has_llm else ''}")
    for rank, (score, s1f, llm, rel_path) in enumerate(top, 1):
        tier  = _tier_label(score)
        guard = 'yes?' if s1f['possibly_guarded'] else 'no'
        sink  = _sink_label(s1f)
        vrdt  = _llm_verdict(llm, has_llm)
        llm_col = f' {vrdt} |' if has_llm else ''
        W(f"| {rank} | {tier} | {s1f['category']} | `{s1f['function']}` "
          f"| {rel_path} | `{s1f['tainted_var']}` "
          f"| {sink} | {guard} |{llm_col}")

    if len(rows) > _SUMMARY_TOP_N:
        W(f"\n*{len(rows) - _SUMMARY_TOP_N} lower-priority findings not shown — "
          f"see report.md for full details.*\n")

    W("")

    # Per-tier sections (all findings, grouped)
    W("---\n")
    W("## All Findings by Tier\n")
    current_tier = None
    for rank, (score, s1f, llm, rel_path) in enumerate(rows, 1):
        tier = _tier_label(score)
        if tier != current_tier:
            W(f"### {tier}\n")
            W(f"| # | Score | Cat | Function | File | Variable | Sink | Guard |"
              f"{' LLM |' if has_llm else ''}")
            W(f"|---|---|---|---|---|---|---|---|{'---|' if has_llm else ''}")
            current_tier = tier
        guard = 'yes?' if s1f['possibly_guarded'] else 'no'
        sink  = _sink_label(s1f)
        vrdt  = _llm_verdict(llm, has_llm)
        llm_col = f' {vrdt} |' if has_llm else ''
        W(f"| {rank} | {score} | {s1f['category']} | `{s1f['function']}` "
          f"| {rel_path} | `{s1f['tainted_var']}` "
          f"| {sink} | {guard} |{llm_col}")
    W("")

    # Files with most findings
    W("---\n")
    W("## Findings by File\n")
    W("| File | Findings |")
    W("|---|---|")
    for fname, n in _file_counts(rows).items():
        W(f"| {fname} | {n} |")
    W("")

    return '\n'.join(buf)


# -- HTML summary renderer ---------------------------------------------------

_SUMMARY_CSS = """\
:root {
  --bg: #f8f8f8; --fg: #222; --border: #ccc;
  --hdr-bg: #2a3d5a; --hdr-fg: #fff; --code-bg: #eee;
  --critical: #8b0000; --high: #c00; --medium: #b06000; --low: #555;
  --fp: #2a7a2a; --bug: #c00; --unknown: #888;
}
* { box-sizing: border-box; }
body { font-family: 'Liberation Mono','Courier New',monospace; font-size:12px;
       background:var(--bg); color:var(--fg); margin:0; padding:0; }
h1 { background:var(--hdr-bg); color:var(--hdr-fg); margin:0;
     padding:14px 20px; font-size:16px; }
.meta { background:#e8edf3; padding:8px 20px; border-bottom:1px solid var(--border);
        line-height:1.8; }
.meta span { margin-right:20px; }
.meta .key { color:#555; font-weight:bold; }
main { padding:14px 20px; }
h2 { font-size:14px; border-bottom:2px solid var(--hdr-bg);
     padding-bottom:3px; margin-top:22px; }
table { border-collapse:collapse; width:100%; margin:6px 0; }
td,th { border:1px solid var(--border); padding:3px 6px; vertical-align:top; }
th { background:#dde; text-align:left; white-space:nowrap; }
tr:hover { background:#fffbe6; }
code { background:var(--code-bg); padding:1px 3px; border-radius:2px; }
.tier-Critical { color:var(--critical); font-weight:bold; }
.tier-High     { color:var(--high);     font-weight:bold; }
.tier-Medium   { color:var(--medium);   font-weight:bold; }
.tier-Low      { color:var(--low); }
.verdict-bug   { color:var(--bug);  font-weight:bold; }
.verdict-fp    { color:var(--fp);   font-style:italic; }
.verdict-unk   { color:var(--unknown); }
.guard-yes     { color:#888; }
.guard-no      { color:var(--high); font-weight:bold; }
.score-bar     { display:inline-block; background:#b06000;
                 height:8px; vertical-align:middle; border-radius:2px; }
"""


def _summary_row_html(W, rank, score, s1f, llm, rel_path, has_llm, max_score):
    tier   = _tier_label(score)
    guard  = s1f['possibly_guarded']
    sink   = _e(_sink_label(s1f))
    vrdt   = _llm_verdict(llm, has_llm)

    vcls = ('verdict-bug' if vrdt.startswith('BUG')
            else 'verdict-fp' if vrdt == 'FP'
            else 'verdict-unk')
    gcls = 'guard-yes' if guard else 'guard-no'
    bar_w = max(2, int(80 * score / max(max_score, 1)))

    llm_col = (f'<td class="{vcls}">{_e(vrdt)}</td>' if has_llm else '')
    W(f'<tr>'
      f'<td>{rank}</td>'
      f'<td><span class="tier-{tier}">{tier}</span></td>'
      f'<td>'
      f'<span class="score-bar" style="width:{bar_w}px" title="{score}"></span>'
      f' {score}</td>'
      f'<td>{_e(s1f["category"])}</td>'
      f'<td><code>{_e(s1f["function"])}</code></td>'
      f'<td>{_e(rel_path)}</td>'
      f'<td><code>{_e(s1f["tainted_var"])}</code></td>'
      f'<td>{sink}</td>'
      f'<td class="{gcls}">{"yes?" if guard else "no"}</td>'
      f'{llm_col}'
      f'</tr>')


def _render_summary_html(rows, has_llm, run_name, now_str, source_dirs, git_info=None):
    lines = []
    W = lines.append

    W('<!DOCTYPE html>')
    W('<html lang="en"><head><meta charset="utf-8">')
    W(f'<title>Priority Summary — {_e(run_name)}</title>')
    W(f'<style>{_SUMMARY_CSS}</style></head><body>')
    W(f'<h1>Priority Summary &mdash; {_e(run_name)}</h1>')

    # Meta bar
    tier_cts = _tier_counts(rows, has_llm)
    cat_cts  = _cat_counts(rows)
    W('<div class="meta">')
    W(f'<span><span class="key">Date:</span> {_e(now_str)}</span>')
    W(f'<span><span class="key">Source:</span> {_e(", ".join(source_dirs))}</span>')
    W(f'<span><span class="key">Total:</span> {len(rows)} findings</span>')
    for tier, _ in [('Critical', None), ('High', None), ('Medium', None), ('Low', None)]:
        n = tier_cts.get(tier, 0)
        if n:
            cls = f'tier-{tier}'
            W(f'<span><span class="key">{tier}:</span> '
              f'<span class="{cls}">{n}</span></span>')
    cat_str = ' &nbsp; '.join(f"Cat {c}: {n}" for c, n in sorted(cat_cts.items()))
    W(f'<span><span class="key">By category:</span> {cat_str}</span>')
    if has_llm:
        real_n = sum(1 for _, _, llm, _ in rows if llm.get('real_bug') is True)
        fp_n   = sum(1 for _, _, llm, _ in rows if llm.get('real_bug') is False)
        unk_n  = sum(1 for _, _, llm, _ in rows if llm.get('real_bug') is None)
        W(f'<span><span class="key">LLM:</span> '
          f'<span class="verdict-bug">{real_n} real</span> &nbsp;|&nbsp; '
          f'{fp_n} FP &nbsp;|&nbsp; {unk_n} unanalyzed</span>')
    _html_git_block(W, git_info or {})
    W('</div><main>')

    # Full ranked table
    W('<h2>All Findings — Ranked by Priority</h2>')
    llm_th = '<th>LLM</th>' if has_llm else ''
    W('<table>')
    W(f'<tr><th>#</th><th>Tier</th><th>Score</th><th>Cat</th>'
      f'<th>Function</th><th>File</th><th>Variable</th>'
      f'<th>Sink</th><th>Guard</th>{llm_th}</tr>')

    max_score = rows[0][0] if rows else 1
    for rank, (score, s1f, llm, rel_path) in enumerate(rows, 1):
        _summary_row_html(W, rank, score, s1f, llm, rel_path, has_llm, max_score)

    W('</table>')

    # Files with most findings
    W('<h2>Findings by File</h2>')
    W('<table><tr><th>File</th><th>Findings</th></tr>')
    for fname, n in _file_counts(rows).items():
        W(f'<tr><td>{_e(fname)}</td><td>{n}</td></tr>')
    W('</table>')

    W('</main></body></html>')
    return '\n'.join(lines)
