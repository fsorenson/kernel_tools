"""
Report Generator: Consolidated per-struct race condition report.

Synthesizes Stage 1 (struct map), Stage 2 (lock scan), Stage 4 (TOCTOU),
and Stage 6 (LLM analysis) into a single Markdown report and a self-contained
HTML file.  If stage outputs are not passed in directly, the generator scans
all prior run directories for the most recent artifact of each stage.

Output files:
  <run_dir>/report_<struct>.md
  <run_dir>/report_<struct>.html
"""

import json
import glob
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(cfg, run_dir, stage1_output=None, stage2_output=None,
        stage4_output=None, stage6_output=None, verbose=False):
    struct_name = cfg['target'].get('name') or 'unknown'
    kernel_source = str(cfg['kernel_source'])
    output_base = run_dir.parent

    # Load any stage that wasn't passed in
    def _load(key, filename, provided):
        if provided:
            return provided
        pattern = str(output_base / f'*_{struct_name}' / filename)
        matches = sorted(glob.glob(pattern))
        if matches:
            with open(matches[-1]) as f:
                return json.load(f)
        return None

    s1 = _load('struct_map', 'stage1_struct_map.json', stage1_output)
    s2 = _load('lock_scan', 'stage2_lock_scan.json', stage2_output)
    s4 = _load('toctou', 'stage4_toctou.json', stage4_output)
    s6 = _load('llm', 'stage6_llm_analysis.json', stage6_output)

    if not s1:
        print("Report: stage 1 output not found — run struct_map first", file=sys.stderr)
        return None
    if not s2:
        print("Report: stage 2 output not found — run lock_scan first", file=sys.stderr)
        return None

    md = _build_markdown(struct_name, kernel_source, s1, s2, s4, s6)
    html = _build_html(struct_name, md)

    md_path = run_dir / f'report_{struct_name}.md'
    html_path = run_dir / f'report_{struct_name}.html'

    md_path.write_text(md, encoding='utf-8')
    html_path.write_text(html, encoding='utf-8')

    print(f"Report (Markdown): {md_path}")
    print(f"Report (HTML):     {html_path}")

    if verbose:
        stages = ['Stage 1', 'Stage 2',
                  'Stage 4' if s4 else 'Stage 4 (not available)',
                  'Stage 6' if s6 else 'Stage 6 (not available)']
        print(f"  Sources: {', '.join(stages)}")

    return {'markdown': str(md_path), 'html': str(html_path)}


# ---------------------------------------------------------------------------
# Markdown builder
# ---------------------------------------------------------------------------

def _build_markdown(struct_name, kernel_source, s1, s2, s4, s6):
    parts = []

    struct_info = s1.get('result', s1)  # stage1 wraps in 'result'
    llm_by_fn = _index_llm(s6)

    high_confirmed = [f for f in s2['findings']
                      if f['severity'] == 'high' and f.get('revised_severity') != 'suppressed']
    high_suppressed = [f for f in s2['findings']
                       if f.get('revised_severity') == 'suppressed']
    medium = [f for f in s2['findings'] if f['severity'] == 'medium']
    low = [f for f in s2['findings'] if f['severity'] == 'low']
    toctou = (s4 or {}).get('findings', [])

    llm_real = [a for a in llm_by_fn.values() if a.get('assessment') == 'real_race']
    llm_fp = [a for a in llm_by_fn.values() if a.get('assessment') == 'false_positive']
    llm_annot = [a for a in llm_by_fn.values() if a.get('assessment') == 'needs_annotation']
    llm_mixed = [a for a in llm_by_fn.values() if a.get('assessment') == 'mixed']

    # ---- Header ----
    parts.append(f"# Race Condition Analysis: `struct {struct_name}`\n")
    parts.append(
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  \n"
        f"**Kernel source:** `{kernel_source}`  \n"
        f"**Struct defined in:** `{_short(struct_info.get('file','?'))}:{struct_info.get('line','?')}`  \n"
        f"**Files scanned:** {s2.get('files_scanned', '?')}\n"
    )

    # ---- Executive summary ----
    parts.append("\n## Executive Summary\n")
    parts.append("| Category | Count |")
    parts.append("|---|---|")
    parts.append(f"| Struct fields analyzed | {len(struct_info.get('fields', []))} |")
    parts.append(f"| Embedded lock fields | {len(struct_info.get('locks', []))} |")
    parts.append(f"| Suspicious (unprotected) fields | {len(struct_info.get('suspicious_fields', []))} |")
    parts.append(f"| **HIGH findings (confirmed)** | **{len(high_confirmed)}** |")
    parts.append(f"| HIGH findings (suppressed — caller-lock helpers) | {len(high_suppressed)} |")
    parts.append(f"| MEDIUM findings | {len(medium)} |")
    parts.append(f"| LOW findings | {len(low)} |")
    parts.append(f"| TOCTOU patterns | {len(toctou)} |")
    if s6:
        parts.append(f"| LLM: confirmed real races | {sum(len(a.get('findings',[])) for a in llm_real)} findings in {len(llm_real)} functions |")
        parts.append(f"| LLM: needs annotation only | {len(llm_annot)} functions |")
        parts.append(f"| LLM: confirmed false positives | {len(llm_fp)} functions |")
    parts.append("")

    if s6:
        parts.append("### LLM Assessment by Function\n")
        parts.append("| Function | File | Assessment | Confidence |")
        parts.append("|---|---|---|---|")
        for fn, a in sorted(llm_by_fn.items()):
            badge = _assessment_badge(a.get('assessment', '?'))
            conf = a.get('confidence', '?')
            parts.append(f"| `{fn}()` | `{a.get('file','?')}` | {badge} | {conf} |")
        parts.append("")

    # ---- Struct overview ----
    parts.append("\n## Struct Overview\n")

    parts.append("### Embedded Locks\n")
    parts.append("| Lock field | Type | Protects |")
    parts.append("|---|---|---|")
    lock_names = set(struct_info.get('locks', []))
    field_map = {f['name']: f for f in struct_info.get('fields', [])}
    region_map = {}
    for r in struct_info.get('protected_regions', []):
        region_map[r['lock']] = ', '.join(f'`{n}`' for n in r['fields'])
    for lname in sorted(lock_names):
        fi = field_map.get(lname, {})
        ftype = fi.get('type', '?')
        protects = region_map.get(lname, '—')
        parts.append(f"| `{lname}` | `{ftype}` | {protects} |")
    parts.append("")

    parts.append("### Suspicious Fields (No Stated Protection)\n")
    parts.append("| Field | Type | Reason |")
    parts.append("|---|---|---|")
    for s in struct_info.get('suspicious_fields', []):
        fi = field_map.get(s['name'], {})
        parts.append(f"| `{s['name']}` | `{fi.get('type','?')}` | {s['reason']} |")
    parts.append("")

    # ---- Confirmed race conditions ----
    parts.append("\n## Confirmed Race Conditions\n")
    parts.append(
        "Functions with HIGH severity findings where static analysis confirms the required "
        "lock is never acquired within the function."
    )
    parts.append("")

    # Group by function
    fn_groups = defaultdict(list)
    for f in high_confirmed:
        fn_groups[f['function']].append(f)

    for fn_name, fn_findings in sorted(fn_groups.items()):
        llm = llm_by_fn.get(fn_name, {})
        llm_assessment = llm.get('assessment', 'not_analyzed')
        fn_file = fn_findings[0]['file']
        expected_lock = fn_findings[0].get('expected_lock')

        # Section header
        badge = _assessment_badge(llm_assessment)
        parts.append(f"### `{fn_name}()` — {_short(fn_file)} {badge}\n")

        # Quick summary
        fields_hit = sorted({f['field'] for f in fn_findings})
        parts.append(f"**Fields:** {', '.join(f'`{x}`' for x in fields_hit)}  ")
        if expected_lock:
            parts.append(f"**Required lock:** `{expected_lock}`  ")

        # Call graph summary from first finding
        cg = fn_findings[0].get('call_graph', {})
        conc = cg.get('conclusion', '')
        if 'no_callers_found' in conc:
            parts.append("**Call graph:** no callers found in analyzed files (VFS-called or exported)  ")
        elif 'callers_lack' in conc:
            without = cg.get('without_lock', [])
            with_ = cg.get('with_lock', [])
            parts.append(f"**Call graph:** MIXED — {len(without)} callers lack lock, {len(with_)} hold it  ")
        elif 'no_callers_hold' in conc:
            parts.append("**Call graph:** no callers hold required lock  ")
        parts.append("")

        # Per-finding evidence
        parts.append("**Evidence:**\n")
        seen_lines = set()
        for f in fn_findings:
            if f['line'] in seen_lines:
                continue
            seen_lines.add(f['line'])
            access = f['access_type']
            parts.append(f"- Line {f['line']} — `{f['field']}` ({access}): `{f['snippet'].strip()}`")
        parts.append("")

        # Call graph detail
        if cg and 'callers_lack' in conc:
            without = cg.get('without_lock', [])[:5]
            with_ = cg.get('with_lock', [])[:3]
            if without:
                parts.append(f"**Callers without `{expected_lock}`:** " +
                              ', '.join(f'`{c}`' for c in without))
            if with_:
                parts.append(f"**Callers with lock:** " +
                              ', '.join(f'`{c}`' for c in with_))
            parts.append("")
        elif cg and 'no_callers_hold' in conc:
            without = cg.get('without_lock', [])[:5]
            if without:
                parts.append(f"**Callers (none hold lock):** " +
                              ', '.join(f'`{c}`' for c in without))
            parts.append("")

        # LLM analysis
        if llm:
            if llm.get('overall_notes'):
                parts.append(f"**Analysis:** {llm['overall_notes']}\n")
            llm_findings = llm.get('findings', [])
            if llm_findings:
                parts.append("**Recommended fixes:**\n")
                for lf in llm_findings:
                    field = lf.get('field', '?')
                    real = lf.get('real_race', False)
                    fix = lf.get('suggested_fix', '')
                    scenario = lf.get('race_scenario', '')
                    if real and scenario:
                        parts.append(f"- `{field}`: {scenario}")
                        if fix:
                            parts.append(f"  - *Fix:* {fix}")
                    elif not real:
                        parts.append(f"- `{field}`: *(false positive)* {fix}")
                parts.append("")

        parts.append("---\n")

    # ---- TOCTOU ----
    if toctou:
        parts.append("\n## TOCTOU Patterns\n")
        parts.append(
            "Check-then-act sequences where the field is read in an `if`/`while`/`for` "
            "condition and accessed again in the body without the required lock held between them."
        )
        parts.append("")

        by_sev = defaultdict(list)
        for t in toctou:
            by_sev[t['severity']].append(t)

        for sev in ['high', 'medium', 'low']:
            grp = by_sev.get(sev, [])
            if not grp:
                continue
            parts.append(f"### {sev.upper()} TOCTOU ({len(grp)} findings)\n")
            parts.append("| Function | File | Field | Pattern | Check | Use |")
            parts.append("|---|---|---|---|---|---|")
            for t in grp:
                fn = t['function']
                short_f = _short(t['file'])
                field = t['field']
                pattern = t['pattern']
                parts.append(
                    f"| `{fn}()` | `{short_f}` | `{field}` | {pattern} "
                    f"| L{t['check_line']} | L{t['use_line']} |"
                )
            parts.append("")
            # Detail for first few
            for t in grp[:3]:
                parts.append(f"**`{t['function']}()`** — `{t['field']}` ({t['pattern']})")
                parts.append(f"```c")
                parts.append(f"// Check (line {t['check_line']}):")
                parts.append(f"{t['check_snippet'].strip()}")
                parts.append(f"// Use   (line {t['use_line']}):")
                parts.append(f"{t['use_snippet'].strip()}")
                parts.append(f"```")
                if t.get('expected_lock'):
                    parts.append(f"`{t['expected_lock']}` not held at either point.\n")
                parts.append("")

    # ---- Annotation candidates ----
    annot_fns = {a['function']: a for a in llm_annot}
    mixed_fns = {a['function']: a for a in llm_mixed}
    all_annot = {**annot_fns, **mixed_fns}

    if all_annot:
        parts.append("\n## Annotation Candidates\n")
        parts.append(
            "Functions where locking is impractical (VFS-called, display paths, atomic ops) "
            "but data races should be annotated with `READ_ONCE()` / `data_race()` / `WRITE_ONCE()` "
            "for KCSAN correctness."
        )
        parts.append("")
        for fn_name, a in sorted(all_annot.items()):
            parts.append(f"### `{fn_name}()`\n")
            if a.get('overall_notes'):
                parts.append(f"{a['overall_notes']}\n")
            for lf in a.get('findings', []):
                field = lf.get('field', '?')
                fix = lf.get('suggested_fix', '')
                real = lf.get('real_race', True)
                tag = 'annotate' if real else 'no change'
                if fix:
                    parts.append(f"- `{field}` ({tag}): {fix}")
            parts.append("")

    # ---- Suppressed (caller-lock helpers) ----
    if high_suppressed:
        parts.append("\n## Caller-Lock Helper Functions\n")
        parts.append(
            "Functions suppressed because **all callers hold the required lock** — "
            "they implement a caller-lock helper pattern.  "
            "The lock contract should be documented with `lockdep_assert_held()`."
        )
        parts.append("")

        supp_by_fn = defaultdict(list)
        for f in high_suppressed:
            supp_by_fn[f['function']].append(f)
        for fn_name, fn_findings in sorted(supp_by_fn.items()):
            lock = fn_findings[0].get('expected_lock', '?')
            cg = fn_findings[0].get('call_graph', {})
            callers = cg.get('with_lock', [])
            parts.append(f"- **`{fn_name}()`** — requires `{lock}` from caller  ")
            if callers:
                parts.append(f"  Callers: " + ', '.join(f'`{c}`' for c in callers[:4]))
        parts.append("")

    # ---- LLM false positives ----
    if llm_fp:
        parts.append("\n## LLM-Confirmed False Positives\n")
        parts.append(
            "HIGH findings dismissed by LLM analysis as false positives "
            "(typically because the lock is held via a path not visible to the static scanner)."
        )
        parts.append("")
        for a in llm_fp:
            fn = a['function']
            parts.append(f"### `{fn}()`\n")
            if a.get('overall_notes'):
                parts.append(f"{a['overall_notes']}\n")
            for lf in a.get('findings', []):
                field = lf.get('field', '?')
                fix = lf.get('suggested_fix', '')
                parts.append(f"- `{field}`: {fix}" if fix else f"- `{field}`: no action needed")
            parts.append("")

    # ---- Medium summary ----
    if medium:
        parts.append("\n## Medium Findings Summary\n")
        parts.append(
            "These functions acquire the required lock in some branches but not all. "
            "Branch-insensitive scanning means some of these may be false positives from "
            "early-return unlock paths."
        )
        parts.append("")
        fn_med = defaultdict(list)
        for f in medium:
            fn_med[f['function']].append(f)
        parts.append("| Function | File | Accesses | Lock | Fields |")
        parts.append("|---|---|---|---|---|")
        for fn_name, flist in sorted(fn_med.items()):
            short_f = _short(flist[0]['file'])
            lock = flist[0].get('expected_lock', '?')
            fields = ', '.join(f'`{x}`' for x in sorted({f['field'] for f in flist}))
            parts.append(f"| `{fn_name}()` | `{short_f}` | {len(flist)} | `{lock}` | {fields} |")
        parts.append("")

    # ---- Appendix: full field map ----
    parts.append("\n## Appendix: Full Field Map\n")
    parts.append("| Field | Type | Protection | Flags |")
    parts.append("|---|---|---|---|")
    for f in struct_info.get('fields', []):
        if f.get('is_lock'):
            continue
        flags = []
        if f.get('is_atomic'): flags.append('atomic')
        if f.get('is_refcount'): flags.append('refcount')
        if f.get('is_state'): flags.append('state')
        prot = f'`{f["protection"]}`' if f.get('protection') else '—'
        ftype = f.get('type', '?')
        parts.append(f"| `{f['name']}` | `{ftype}` | {prot} | {', '.join(flags) or '—'} |")
    parts.append("")

    parts.append(
        f"\n---\n*Generated by [search_kernel_races](https://github.com/fsorenson/) "
        f"on {datetime.now().strftime('%Y-%m-%d')}*\n"
    )

    return '\n'.join(parts)


# ---------------------------------------------------------------------------
# HTML builder
# ---------------------------------------------------------------------------

_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
       font-size: 14px; line-height: 1.6; color: #24292e; max-width: 1100px; margin: 0 auto;
       padding: 20px 40px; background: #fff; }
h1 { font-size: 2em; border-bottom: 2px solid #e1e4e8; padding-bottom: .3em; }
h2 { font-size: 1.5em; border-bottom: 1px solid #e1e4e8; padding-bottom: .3em; margin-top: 2em; }
h3 { font-size: 1.15em; margin-top: 1.5em; }
code { background: #f6f8fa; border-radius: 3px; padding: .2em .4em;
       font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
       font-size: 85%; }
pre { background: #f6f8fa; border-radius: 6px; padding: 16px; overflow: auto;
      font-size: 85%; line-height: 1.45; }
pre code { background: none; padding: 0; }
table { border-collapse: collapse; width: 100%; margin-bottom: 1em; }
th { background: #f6f8fa; font-weight: 600; }
th, td { border: 1px solid #dfe2e5; padding: 6px 13px; text-align: left; }
tr:nth-child(even) { background: #fafbfc; }
hr { border: none; border-top: 1px solid #e1e4e8; margin: 2em 0; }
.badge { display: inline-block; border-radius: 12px; padding: 2px 10px;
         font-size: 12px; font-weight: 600; }
.badge-real  { background: #ffeef0; color: #b31d28; border: 1px solid #f97583; }
.badge-fp    { background: #f0fff4; color: #22863a; border: 1px solid #34d058; }
.badge-annot { background: #fff8c5; color: #735c0f; border: 1px solid #e3b341; }
.badge-mixed { background: #fff3cd; color: #856404; border: 1px solid #ffc107; }
.badge-na    { background: #f1f8ff; color: #0366d6; border: 1px solid #79b8ff; }
blockquote { border-left: 4px solid #dfe2e5; margin: 0; padding: 0 1em; color: #6a737d; }
"""

_BADGE_MAP = {
    'real_race':        ('<span class="badge badge-real">REAL RACE</span>', 'REAL RACE'),
    'false_positive':   ('<span class="badge badge-fp">FALSE POSITIVE</span>', 'FALSE POSITIVE'),
    'needs_annotation': ('<span class="badge badge-annot">NEEDS ANNOTATION</span>', 'NEEDS ANNOTATION'),
    'mixed':            ('<span class="badge badge-mixed">MIXED</span>', 'MIXED'),
    'not_analyzed':     ('<span class="badge badge-na">NOT ANALYZED</span>', 'NOT ANALYZED'),
    'error':            ('<span class="badge badge-na">ERROR</span>', 'ERROR'),
}


def _assessment_badge(assessment, html=False):
    entry = _BADGE_MAP.get(assessment, _BADGE_MAP['not_analyzed'])
    return entry[0] if html else entry[1]


def _md_to_html_basic(md):
    """Very basic Markdown→HTML conversion for the subset we generate."""
    lines = md.split('\n')
    out = []
    in_table = False
    in_code = False
    in_list = False

    i = 0
    while i < len(lines):
        line = lines[i]

        # Fenced code blocks
        if line.strip().startswith('```'):
            if not in_code:
                lang = line.strip()[3:].strip()
                out.append(f'<pre><code class="language-{lang}">')
                in_code = True
            else:
                out.append('</code></pre>')
                in_code = False
            i += 1
            continue
        if in_code:
            out.append(_esc(line))
            i += 1
            continue

        # Close list if needed
        stripped = line.strip()

        # Headings
        m = re.match(r'^(#{1,4})\s+(.*)', line)
        if m:
            if in_list: out.append('</ul>'); in_list = False
            if in_table: out.append('</table>'); in_table = False
            level = len(m.group(1))
            text = _inline(m.group(2))
            anchor = re.sub(r'[^a-z0-9-]', '', text.lower().replace(' ', '-').replace('`', ''))
            out.append(f'<h{level} id="{anchor}">{text}</h{level}>')
            i += 1
            continue

        # Tables
        if '|' in line and stripped.startswith('|'):
            if in_list: out.append('</ul>'); in_list = False
            if not in_table:
                out.append('<table>'); in_table = True
                # header row
                cells = [c.strip() for c in stripped.strip('|').split('|')]
                out.append('<thead><tr>' + ''.join(f'<th>{_inline(c)}</th>' for c in cells) + '</tr></thead><tbody>')
                i += 1
                # skip separator row
                if i < len(lines) and re.match(r'^\|[-| :]+\|', lines[i].strip()):
                    i += 1
                continue
            else:
                cells = [c.strip() for c in stripped.strip('|').split('|')]
                out.append('<tr>' + ''.join(f'<td>{_inline(c)}</td>' for c in cells) + '</tr>')
                i += 1
                continue
        elif in_table:
            out.append('</tbody></table>'); in_table = False

        # Horizontal rule
        if re.match(r'^---+\s*$', stripped):
            if in_list: out.append('</ul>'); in_list = False
            out.append('<hr>')
            i += 1
            continue

        # Unordered list
        m = re.match(r'^[ \t]*[-*]\s+(.*)', line)
        if m:
            if not in_list:
                out.append('<ul>'); in_list = True
            out.append(f'<li>{_inline(m.group(1))}</li>')
            i += 1
            continue
        elif in_list and stripped == '':
            out.append('</ul>'); in_list = False

        # Bold lines starting with **
        if stripped.startswith('**') and stripped.endswith('**') and stripped.count('**') == 2:
            out.append(f'<p><strong>{_inline(stripped[2:-2])}</strong></p>')
            i += 1
            continue

        # Blank line → paragraph break
        if stripped == '':
            if in_list: pass  # handled above or next iter
            else: out.append('')
            i += 1
            continue

        # Regular paragraph line
        out.append(f'<p>{_inline(line)}</p>')
        i += 1

    if in_list: out.append('</ul>')
    if in_table: out.append('</tbody></table>')
    if in_code: out.append('</code></pre>')

    return '\n'.join(out)


def _esc(s):
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _inline(text):
    """Convert inline Markdown (code, bold, italic) to HTML."""
    # Escape HTML first but preserve backtick regions
    parts = re.split(r'(`[^`]+`)', text)
    result = []
    for p in parts:
        if p.startswith('`') and p.endswith('`'):
            inner = _esc(p[1:-1])
            result.append(f'<code>{inner}</code>')
        else:
            p = _esc(p)
            p = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', p)
            p = re.sub(r'\*(.+?)\*', r'<em>\1</em>', p)
            p = re.sub(r'_(.+?)_', r'<em>\1</em>', p)
            # Links: [text](url)
            p = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', p)
            result.append(p)
    return ''.join(result)


def _build_html(struct_name, md):
    # Replace assessment badge text with HTML badges before converting
    for key, (html_badge, text_badge) in _BADGE_MAP.items():
        md = md.replace(text_badge, html_badge)

    body = _md_to_html_basic(md)
    title = f"Race Analysis: struct {struct_name}"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
{_CSS}
</style>
</head>
<body>
{body}
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _index_llm(s6):
    """Return {fn_name: analysis_dict} from stage6 output."""
    if not s6:
        return {}
    return {a['function']: a for a in s6.get('analyses', [])}


def _short(filepath):
    """Return last two path components for display."""
    parts = filepath.replace('\\', '/').rstrip('/').split('/')
    return '/'.join(parts[-2:]) if len(parts) >= 2 else filepath
