#!/usr/bin/env python3
"""
Aggregate race_finder results across all struct runs into a ranked summary.

Reads all run directories under runs/, takes the most recent run per struct,
and produces a prioritized table showing confirmed races, their impact, and
observable symptoms.

Usage:
    python3 tools/aggregate_findings.py [--runs-dir runs/] [--csv out.csv]
                                        [--json out.json] [--no-found]
"""

import argparse
import csv
import json
import sys
from pathlib import Path


# Impact tier → numeric score (higher = more severe)
_IMPACT_SCORE = {
    'system_crash':       100,
    'use_after_free':      90,
    'data_corruption':     80,
    'protocol_violation':  60,
    'resource_leak':       40,
    'wrong_behavior':      20,
}

_CONFIDENCE_MUL = {'high': 1.0, 'medium': 0.6, 'low': 0.3}


def _priority(row):
    """
    Numeric priority score — higher means tackle sooner.

    Tier ordering (descending):
      5000+  LLM-confirmed real races (by llm_priority_score)
      3000+  HIGH findings with no LLM pass yet (by confirmed HIGH count)
      1000+  MEDIUM findings only
         0   LOW / no findings
        -1   Struct not found
    """
    if row['status'] == 'not_found':
        return -1
    if row.get('status') == 'stage6':
        real = row.get('real_count', 0)
        if real > 0:
            # LLM confirmed — primary sort by llm_priority_score
            return 5000 + row.get('llm_priority_score', 0) + real * 0.1
        else:
            # LLM-analyzed and cleared — put below unanalyzed HIGH findings
            return 500 + row.get('fp_count', 0) * 0.1
    # No LLM
    high = row.get('high_confirmed', 0)
    med  = row.get('medium', 0)
    if high > 0:
        return 3000 + high * 10 + med
    if med > 0:
        return 1000 + med
    return row.get('low', 0) * 0.1


def _load_stage1(run_dir):
    p = run_dir / 'stage1_struct_map.json'
    if not p.exists():
        return None
    with open(p) as f:
        data = json.load(f)
    r = data.get('result', {})
    return {
        'struct_name':      r.get('struct_name', '?'),
        'file':             r.get('file', ''),
        'field_count':      len(r.get('fields', [])),
        'lock_count':       len(r.get('locks', [])),
        'suspicious_count': len(r.get('suspicious_fields', [])),
        'locks':            r.get('locks', []),
    }


def _load_stage2(run_dir):
    p = run_dir / 'stage2_lock_scan.json'
    if not p.exists():
        return None
    with open(p) as f:
        data = json.load(f)
    findings = data.get('findings', [])
    high_confirmed = sum(
        1 for f in findings
        if f.get('severity') == 'high' and f.get('revised_severity') != 'suppressed'
    )
    high_suppressed = sum(
        1 for f in findings
        if f.get('severity') == 'high' and f.get('revised_severity') == 'suppressed'
    )
    medium = sum(1 for f in findings if f.get('severity') == 'medium')
    low    = sum(1 for f in findings if f.get('severity') == 'low')
    return {
        'high_confirmed':  high_confirmed,
        'high_suppressed': high_suppressed,
        'medium':          medium,
        'low':             low,
        'total':           len(findings),
        'files_scanned':   data.get('files_scanned', 0),
    }


def _load_stage4(run_dir):
    p = run_dir / 'stage4_toctou.json'
    if not p.exists():
        return None
    with open(p) as f:
        data = json.load(f)
    findings = data.get('findings', [])
    return {
        'toctou_high':   sum(1 for f in findings if f.get('severity') == 'high'),
        'toctou_medium': sum(1 for f in findings if f.get('severity') == 'medium'),
        'toctou_low':    sum(1 for f in findings if f.get('severity') == 'low'),
    }


def _load_stage6(run_dir):
    p = run_dir / 'stage6_llm_analysis.json'
    if not p.exists():
        return None
    with open(p) as f:
        data = json.load(f)

    real_races = []
    false_positives = []
    annotation_candidates = []
    priority_score = 0.0

    for analysis in data.get('analyses', []):
        conf = analysis.get('confidence', 'low')
        mul  = _CONFIDENCE_MUL.get(conf, 0.3)
        for finding in analysis.get('findings', []):
            if not finding.get('real_race'):
                false_positives.append(finding.get('field', '?'))
                continue
            impact  = finding.get('impact', '') or ''
            symptom = finding.get('symptom', '') or ''
            isc     = _IMPACT_SCORE.get(impact, 10)
            priority_score = max(priority_score, isc * mul)

            if analysis.get('assessment') == 'needs_annotation':
                annotation_candidates.append({
                    'field':   finding.get('field', '?'),
                    'impact':  impact,
                    'symptom': symptom,
                    'conf':    conf,
                    'fn':      analysis.get('function', '?'),
                })
            else:
                real_races.append({
                    'field':    finding.get('field', '?'),
                    'impact':   impact,
                    'symptom':  symptom,
                    'scenario': finding.get('race_scenario', ''),
                    'fix':      finding.get('suggested_fix', ''),
                    'conf':     conf,
                    'fn':       analysis.get('function', '?'),
                })

    # Best impact/symptom for the summary line
    best = max(real_races, key=lambda r: _IMPACT_SCORE.get(r['impact'], 0)) \
           if real_races else None

    return {
        'real_count':        len(real_races),
        'fp_count':          len(false_positives),
        'annotation_count':  len(annotation_candidates),
        'real_races':        real_races,
        'annotation_candidates': annotation_candidates,
        'best_impact':       best['impact']  if best else '',
        'best_symptom':      best['symptom'] if best else '',
        'best_conf':         best['conf']    if best else '',
        'llm_priority_score': priority_score,
        'model':             data.get('model', ''),
    }


def _collect_runs(runs_dir):
    """
    For each struct name, find its most recent run directory.
    Returns dict: struct_name → Path.
    """
    latest = {}
    for d in sorted(runs_dir.iterdir()):
        if not d.is_dir():
            continue
        # Timestamp prefix separates at first underscore after the date part
        # Format: YYYYMMDD_HHMMSS_structname
        parts = d.name.split('_', 2)
        if len(parts) < 3:
            continue
        struct = parts[2]
        latest[struct] = d   # sorted → last wins = most recent
    return latest


def aggregate(runs_dir):
    runs = _collect_runs(runs_dir)
    rows = []

    for struct_name, run_dir in sorted(runs.items()):
        s1 = _load_stage1(run_dir)
        if s1 is None:
            rows.append({
                'struct_name': struct_name,
                'run_dir':     str(run_dir),
                'status':      'not_found',
                'high_confirmed': 0,
                'llm_priority_score': 0,
            })
            continue

        s2 = _load_stage2(run_dir)
        s4 = _load_stage4(run_dir)
        s6 = _load_stage6(run_dir)

        stages = 'stage1'
        if s2: stages = 'stage2'
        if s4: stages = 'stage4'
        if s6: stages = 'stage6'

        row = {
            'struct_name':   struct_name,
            'run_dir':       str(run_dir),
            'status':        stages,
            'file':          s1['file'].replace('/home/src/linux/', ''),
            'field_count':   s1['field_count'],
            'lock_count':    s1['lock_count'],
            'suspicious_count': s1['suspicious_count'],
            'locks':         ', '.join(s1['locks']),
        }
        if s2:
            row.update(s2)
        if s4:
            row.update(s4)
        if s6:
            row.update(s6)

        row.setdefault('high_confirmed', 0)
        row.setdefault('llm_priority_score', 0)
        rows.append(row)

    rows.sort(key=_priority, reverse=True)
    return rows


def _fmt_impact(row):
    imp = row.get('best_impact', '')
    return imp.replace('_', ' ') if imp else '-'


def _fmt_symptom(row, width=40):
    s = row.get('best_symptom', '') or '-'
    return s[:width] + ('…' if len(s) > width else '')


def print_table(rows, show_not_found=True, out=sys.stdout):
    # Separate tiers for display
    llm_real    = [r for r in rows if r.get('status') == 'stage6'
                   and r.get('real_count', 0) > 0]
    llm_cleared = [r for r in rows if r.get('status') == 'stage6'
                   and r.get('real_count', 0) == 0]
    no_llm_high = [r for r in rows if r.get('status') in ('stage2', 'stage4')
                   and r.get('high_confirmed', 0) > 0]
    no_high     = [r for r in rows if r.get('status') in ('stage1', 'stage2', 'stage4')
                   and r.get('high_confirmed', 0) == 0]
    not_found   = [r for r in rows if r.get('status') == 'not_found']

    def _header(title):
        print(f'\n{"=" * 100}', file=out)
        print(f'  {title}', file=out)
        print(f'{"=" * 100}', file=out)

    def _col_header():
        print(f'{"Struct":<32} {"H":>4} {"LLM":>4} {"Impact":<20} {"Symptom":<42} {"Conf":<6}', file=out)
        print('-' * 110, file=out)

    if llm_real:
        _header(f'LLM-confirmed real races ({len(llm_real)} structs) — ACTION REQUIRED')
        _col_header()
        for r in llm_real:
            real = r.get('real_count', 0)
            h    = r.get('high_confirmed', 0)
            conf = r.get('best_conf', '-') or '-'
            print(f"{r['struct_name']:<32} {h:>4} {real:>4} "
                  f"{_fmt_impact(r):<20} {_fmt_symptom(r):<42} {conf:<6}", file=out)

    if llm_cleared:
        _header(f'LLM-analyzed, no real races ({len(llm_cleared)} structs)')
        print(f'{"Struct":<32} {"HIGH":>6} {"FP":>6} {"Annotate":>9}', file=out)
        print('-' * 60, file=out)
        for r in sorted(llm_cleared, key=lambda x: x.get('high_confirmed', 0), reverse=True):
            h   = r.get('high_confirmed', 0)
            fp  = r.get('fp_count', 0)
            ann = r.get('annotation_count', 0)
            print(f"  {r['struct_name']:<30} {h:>6} {fp:>6} {ann:>9}", file=out)

    if no_llm_high:
        _header(f'HIGH findings, no LLM analysis ({len(no_llm_high)} structs)')
        print(f'{"Struct":<32} {"HIGH":>6} {"MED":>6} {"TOCTOU_H":>9}', file=out)
        print('-' * 60, file=out)
        for r in sorted(no_llm_high, key=lambda x: x.get('high_confirmed', 0), reverse=True):
            h  = r.get('high_confirmed', 0)
            m  = r.get('medium', 0)
            th = r.get('toctou_high', 0)
            print(f"{r['struct_name']:<32} {h:>6} {m:>6} {th:>9}", file=out)

    if no_high:
        _header(f'No HIGH findings ({len(no_high)} structs — LOW/MEDIUM or stage1 only)')
        for r in no_high:
            m   = r.get('medium', 0)
            low = r.get('low', 0)
            print(f"  {r['struct_name']:<32}  med={m}  low={low}", file=out)

    if show_not_found and not_found:
        _header(f'Struct not found in headers ({len(not_found)} structs)')
        for r in not_found:
            print(f"  {r['struct_name']}", file=out)

    print(f'\n{"=" * 100}', file=out)
    total_real = sum(r.get('real_count', 0) for r in rows)
    total_high = sum(r.get('high_confirmed', 0) for r in rows)
    print(f'  Total structs: {len(rows)}  |  Total HIGH confirmed: {total_high}'
          f'  |  LLM-confirmed real races: {total_real}', file=out)
    print(f'{"=" * 100}\n', file=out)


def write_csv(rows, path):
    fields = [
        'struct_name', 'status', 'file', 'high_confirmed', 'high_suppressed',
        'medium', 'low', 'toctou_high', 'toctou_medium',
        'real_count', 'fp_count', 'annotation_count',
        'best_impact', 'best_symptom', 'best_conf', 'llm_priority_score',
        'field_count', 'lock_count', 'suspicious_count', 'locks',
    ]
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)
    print(f'CSV written: {path}')


def write_json(rows, path):
    with open(path, 'w') as f:
        json.dump(rows, f, indent=2)
    print(f'JSON written: {path}')


def main():
    p = argparse.ArgumentParser(description='Aggregate race_finder results across all struct runs')
    p.add_argument('--runs-dir', default='runs/', help='Directory containing run subdirectories')
    p.add_argument('--csv',  metavar='PATH', help='Write CSV summary to this path')
    p.add_argument('--json', metavar='PATH', help='Write full JSON to this path')
    p.add_argument('--no-not-found', action='store_true',
                   help='Omit the "struct not found" section from terminal output')
    args = p.parse_args()

    runs_dir = Path(args.runs_dir)
    if not runs_dir.exists():
        print(f'Error: runs directory not found: {runs_dir}', file=sys.stderr)
        sys.exit(1)

    rows = aggregate(runs_dir)
    print_table(rows, show_not_found=not args.no_not_found)

    if args.csv:
        write_csv(rows, args.csv)
    if args.json:
        write_json(rows, args.json)


if __name__ == '__main__':
    main()
