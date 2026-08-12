"""
Report formatter for bounds checker Stage 1 + Stage 2 output.

Writes:
  <run_dir>/report.md   — Markdown (grep-friendly, GitHub-renderable)
  <run_dir>/report.html — Self-contained HTML with inline CSS
"""

import html as html_mod
import json
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
    return written


# ---------------------------------------------------------------------------
# Context assembly
# ---------------------------------------------------------------------------

_CAT_LABEL = {
    'A': 'Cat A — server offset → pointer → memory op',
    'B': 'Cat B — server value → size/alloc argument',
    'C': 'Cat C — server value → array subscript',
}
_ASSESSMENT_LABEL = {
    'real_bug': 'BUG', 'false_positive': 'FP',
    'needs_validation': 'VALIDATE', 'mixed': 'MIXED', 'error': 'ERROR',
}


def _build_context(run_dir, s1, s2):
    """Assemble everything the renderers need in one dict."""
    # Group stage1 findings by (function, file) so we can cross-ref by index
    s1_groups = defaultdict(list)
    for f in s1.get('findings', []):
        s1_groups[(f['function'], f['file'])].append(f)

    # Index stage2 analyses for fast lookup
    s2_by_fn = {(a['function'], a['file']): a for a in s2.get('analyses', [])}

    # Build per-function sections, sorted alphabetically
    sections = []
    for (fn_name, filepath), s1_findings in sorted(s1_groups.items()):
        short_file = Path(filepath).name
        analysis = s2_by_fn.get((fn_name, short_file)) or s2_by_fn.get((fn_name, filepath), {})
        # Build per-finding merged rows
        lkp = {f['finding_index']: f for f in analysis.get('findings', [])}
        rows = []
        for i, s1f in enumerate(s1_findings, 1):
            llm = lkp.get(i, {})
            rows.append({
                'idx':             i,
                'category':        s1f['category'],
                'cat_label':       _CAT_LABEL.get(s1f['category'], s1f['category']),
                'taint_source_fn': s1f['taint_source_fn'],
                'taint_line':      s1f['taint_line'],
                'taint_snippet':   s1f['taint_snippet'],
                'tainted_var':     s1f['tainted_var'],
                'sink_fn':         s1f['sink_fn'],
                'sink_line':       s1f['sink_line'],
                'sink_snippet':    s1f['sink_snippet'],
                'sink_arg_index':  s1f['sink_arg_index'],
                'sink_arg_role':   s1f['sink_arg_role'],
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

    run_name = run_dir.name
    now_str  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    return {
        'run_name':    run_name,
        'run_dir':     str(run_dir),
        'now_str':     now_str,
        'model':       s2.get('model', '—'),
        'source_dirs': s1.get('source_dirs', []),
        'files_scanned': s1.get('files_scanned', 0),
        's1_total':    s1.get('findings_count', 0),
        's1_by_cat':   s1_by_cat,
        'fn_analyzed': s2.get('functions_analyzed', len(sections)),
        'total_real':  total_real,
        'total_fp':    total_fp,
        'total_unk':   total_unk,
        'sections':    sections,
        'has_llm':     bool(s2.get('analyses')),
    }


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def _render_md(ctx):
    buf = []
    W = buf.append

    W(f"# Bounds Checker Report — {ctx['run_name']}\n")
    W(f"**Date:** {ctx['now_str']}  ")
    W(f"**Model:** {ctx['model']}  ")
    W(f"**Source:** {', '.join(ctx['source_dirs'])}  ")
    W(f"**Files scanned:** {ctx['files_scanned']}\n")

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

    # Summary table (LLM columns only when LLM ran)
    W("## Summary\n")
    if ctx['has_llm']:
        W("| Function | File | Assessment | Conf | Real | FP | Unanalyzed |")
        W("|---|---|---|---|---|---|---|")
        for s in ctx['sections']:
            W(f"| [{s['fn_name']}](#{_anchor(s['fn_name'])}) "
              f"| {s['short_file']} "
              f"| {s['label']} "
              f"| {s['confidence']} "
              f"| {s['real_count']} "
              f"| {s['fp_count']} "
              f"| {s['unanalyzed']} |")
    else:
        W("| Function | File | Findings |")
        W("|---|---|---|")
        for s in ctx['sections']:
            W(f"| {s['fn_name']} | {s['short_file']} | {len(s['findings'])} |")
    W("")

    # Per-function sections
    W("\n---\n")
    W("## Function Details\n")
    for s in ctx['sections']:
        W(f"### {s['fn_name']}() — `{s['short_file']}`\n")
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


def _anchor(name):
    return name.lower().replace('_', '-').replace(' ', '-')


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

    W(f"#### Finding #{r['idx']} — Category {r['category']}{verdict}\n")
    W(f"| Field | Value |")
    W(f"|---|---|")
    W(f"| Category | {r['cat_label']} |")
    W(f"| Taint source | `{r['taint_source_fn']}()` line {r['taint_line']} |")
    W(f"| Taint snippet | `{r['taint_snippet']}` |")
    W(f"| Tainted var | `{r['tainted_var']}` |")
    W(f"| Sink | `{r['sink_fn']}()` line {r['sink_line']} (arg {r['sink_arg_index']}, role={r['sink_arg_role']}) |")
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
.toc { column-count: 2; column-gap: 24px; }
.toc a { display: block; padding: 2px 0; text-decoration: none; color: #1a5fa8; }
.toc a:hover { text-decoration: underline; }
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
    W('</div><main>')

    # Table of contents
    W('<h2>Contents</h2><div class="toc">')
    for s in ctx['sections']:
        anchor = _anchor(s['fn_name'])
        badge = _badge(s['assessment']) if ctx['has_llm'] and s['assessment'] != 'unknown' else ''
        W(f'<a href="#{anchor}">{_e(s["fn_name"])}() &mdash; {_e(s["short_file"])} {badge}</a>')
    W('</div>')

    # Summary table
    W('<h2>Summary</h2>')
    W('<table class="summary-table">')
    if ctx['has_llm']:
        W('<tr><th>Function</th><th>File</th><th>Assessment</th>'
          '<th>Confidence</th><th>Real</th><th>FP</th><th>Unanalyzed</th></tr>')
        for s in ctx['sections']:
            anchor = _anchor(s['fn_name'])
            W(f'<tr>'
              f'<td><a href="#{anchor}">{_e(s["fn_name"])}()</a></td>'
              f'<td>{_e(s["short_file"])}</td>'
              f'<td>{_badge(s["assessment"])}</td>'
              f'<td>{_e(s["confidence"])}</td>'
              f'<td style="color:var(--bug)">{s["real_count"]}</td>'
              f'<td style="color:var(--fp)">{s["fp_count"]}</td>'
              f'<td>{s["unanalyzed"]}</td>'
              f'</tr>')
    else:
        W('<tr><th>Function</th><th>File</th><th>Findings</th></tr>')
        for s in ctx['sections']:
            W(f'<tr><td>{_e(s["fn_name"])}()</td>'
              f'<td>{_e(s["short_file"])}</td>'
              f'<td>{len(s["findings"])}</td></tr>')
    W('</table>')

    # Per-function sections
    W('<h2>Function Details</h2>')
    for s in ctx['sections']:
        anchor = _anchor(s['fn_name'])
        badge = _badge(s['assessment']) if ctx['has_llm'] and s['assessment'] != 'unknown' else ''
        conf = f'confidence={_e(s["confidence"])}' if ctx['has_llm'] else ''
        W(f'<h3 id="{anchor}">{_e(s["fn_name"])}() &mdash; '
          f'<code>{_e(s["short_file"])}</code> {badge} {conf}</h3>')

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
    W(f'<h4 class="{hcls}">Finding #{r["idx"]} &mdash; Category {_e(r["category"])}'
      f'{verdict_sep}{verdict}</h4>')

    W('<table>')
    W(f'<tr><th>Category</th><td>{_e(r["cat_label"])}</td></tr>')
    W(f'<tr><th>Taint source</th><td>'
      f'<code>{_e(r["taint_source_fn"])}()</code> line {r["taint_line"]}</td></tr>')
    W(f'<tr><th>Taint snippet</th><td><code>{_e(r["taint_snippet"])}</code></td></tr>')
    W(f'<tr><th>Tainted var</th><td><code>{_e(r["tainted_var"])}</code></td></tr>')
    W(f'<tr><th>Sink</th><td>'
      f'<code>{_e(r["sink_fn"])}()</code> line {r["sink_line"]} '
      f'(arg {r["sink_arg_index"]}, role={_e(r["sink_arg_role"])})</td></tr>')
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
