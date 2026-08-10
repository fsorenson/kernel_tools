"""
Stage 4: TOCTOU (Time-Of-Check-Time-Of-Use) Detector

Finds check-then-act sequences on struct fields where the field is read in
an if/while/for condition and then accessed in the corresponding body, with
no required lock held at either point.  Between the check and the use,
another thread can modify the field — invalidating the assumption the check
was meant to enforce.

Known false positive sources (same as Stage 2):
  - Branch-insensitive lock tracking: early-return unlock paths cause the
    scanner to see the lock as released at subsequent accesses that are
    actually guarded on the non-early-return path.
  - Teardown paths: once a session is removed from the global list and
    ses_status set to SES_EXITING, no concurrent access is expected.
  - Atomic bit ops: field name matches (e.g. 'flags') fire even when the
    actual operation is an atomic test_bit / clear_bit on a different bit.
"""

import json
import sys
from collections import Counter

from ..parsers.c_parser import (
    parse_file,
    find_functions,
    find_lock_events,
    lock_state_at,
    find_alloc_vars,
    find_toctou_candidates,
)


def run(cfg, run_dir, stage1_output, verbose=False):
    struct_info = stage1_output['result']
    struct_name = struct_info['struct_name']

    lock_field_names = set(struct_info['locks'])
    field_map = {f['name']: f for f in struct_info['fields']}
    suspicious_names = {s['name'] for s in struct_info['suspicious_fields']}

    embedded_protected = {
        f['name']: f['protection']
        for f in struct_info['fields']
        if f.get('protection') and f['protection'] in lock_field_names
    }

    target_fields = (suspicious_names | set(embedded_protected)) - lock_field_names

    if not target_fields:
        print("Stage 4: no target fields to scan", file=sys.stderr)
        return None

    source_dirs = cfg['target'].get('source_dirs') or []
    kernel_source = cfg['kernel_source']

    all_findings = []
    files_scanned = 0
    files_errored = 0

    for rel_dir in source_dirs:
        dir_path = kernel_source / rel_dir
        if not dir_path.exists():
            print(f"  [warn] source dir not found: {rel_dir}", file=sys.stderr)
            continue
        for c_path in sorted(dir_path.rglob('*.c')):
            try:
                findings = _scan_file(
                    c_path, target_fields, field_map,
                    lock_field_names, suspicious_names,
                    embedded_protected, verbose,
                )
                all_findings.extend(findings)
                files_scanned += 1
            except Exception as exc:
                if verbose:
                    print(f"  [error] {c_path.name}: {exc}")
                files_errored += 1

    all_findings.sort(key=lambda f: (
        {'high': 0, 'medium': 1, 'low': 2}.get(f['severity'], 3),
        f['file'],
        f['check_line'],
    ))

    output = {
        'stage': 'toctou',
        'struct': struct_name,
        'files_scanned': files_scanned,
        'files_errored': files_errored,
        'total_findings': len(all_findings),
        'findings': all_findings,
    }

    out_path = run_dir / 'stage4_toctou.json'
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"Stage 4 output: {out_path}")

    _print_summary(all_findings, files_scanned, verbose)
    return output


def _scan_file(c_path, target_fields, field_map,
               lock_field_names, suspicious_names, embedded_protected, verbose):
    tree, source = parse_file(c_path)
    rel = str(c_path)
    findings = []

    for fn in find_functions(tree, source):
        body = fn['body']
        fn_name = fn['name']

        alloc_vars = find_alloc_vars(body, source)
        lock_events = find_lock_events(body, lock_field_names, source)

        candidates = find_toctou_candidates(body, target_fields, alloc_vars, source)
        for cand in candidates:
            field = cand['field']
            finfo = field_map.get(field, {})
            expected_lock = embedded_protected.get(field)

            check_held = lock_state_at(lock_events, cand['check_line'])
            use_held = lock_state_at(lock_events, cand['use_line'])

            # Skip if either the check or the use is under the required lock
            if expected_lock:
                if expected_lock in check_held or expected_lock in use_held:
                    continue
            # For suspicious fields with no required lock, skip if any lock is held at use
            elif use_held:
                continue

            severity = _severity(finfo, cand['use_access_type'], expected_lock)

            findings.append({
                'severity': severity,
                'file': rel,
                'function': fn_name,
                'field': field,
                'field_type': finfo.get('type', ''),
                'obj': cand['obj'],
                'pattern': f"check_then_{cand['use_access_type']}",
                'check_line': cand['check_line'],
                'use_line': cand['use_line'],
                'check_snippet': cand['check_snippet'],
                'use_snippet': cand['use_snippet'],
                'expected_lock': expected_lock,
                'check_locks_held': sorted(check_held),
                'use_locks_held': sorted(use_held),
            })

    if verbose and findings:
        print(f"  [{c_path.name}] {len(findings)} TOCTOU finding(s)")

    return findings


def _severity(finfo, use_access_type, expected_lock):
    is_refcount = finfo.get('is_refcount') and not finfo.get('is_atomic')

    if expected_lock:
        return 'high' if use_access_type == 'write' else 'medium'
    if is_refcount:
        return 'high' if use_access_type == 'write' else 'medium'
    return 'low'


def _print_summary(findings, files_scanned, verbose):
    high = [f for f in findings if f['severity'] == 'high']
    medium = [f for f in findings if f['severity'] == 'medium']
    low = [f for f in findings if f['severity'] == 'low']

    print(f"\n=== Stage 4: TOCTOU Detector ({files_scanned} files) ===")
    print(f"  Total findings: {len(findings)}")
    print(f"  HIGH:   {len(high)}")
    print(f"  MEDIUM: {len(medium)}")
    print(f"  LOW:    {len(low)}")

    if high:
        print(f"\n  HIGH TOCTOU findings:")
        for f in high:
            rel = f['file'].split('fs/smb/')[-1] if 'fs/smb' in f['file'] else f['file']
            print(
                f"\n  [HIGH] {rel}  {f['function']}()  "
                f"field={f['field']}  pattern={f['pattern']}"
            )
            if f['expected_lock']:
                print(f"    requires: {f['expected_lock']}")
            print(f"    check ({f['check_line']}): {f['check_snippet']}")
            print(f"    use   ({f['use_line']}):   {f['use_snippet']}")

    if medium:
        if verbose:
            print(f"\n  MEDIUM TOCTOU findings:")
            for f in medium:
                rel = f['file'].split('fs/smb/')[-1] if 'fs/smb' in f['file'] else f['file']
                print(
                    f"\n  [MEDIUM] {rel}  {f['function']}()  "
                    f"field={f['field']}  pattern={f['pattern']}"
                )
                if f['expected_lock']:
                    print(f"    requires: {f['expected_lock']}")
                print(f"    check ({f['check_line']}): {f['check_snippet']}")
                print(f"    use   ({f['use_line']}):   {f['use_snippet']}")
        else:
            print(f"\n  MEDIUM TOCTOU findings by function (--verbose for detail):")
            fn_counts = Counter(f['function'] for f in medium)
            for fn, cnt in fn_counts.most_common(10):
                ex = next(f for f in medium if f['function'] == fn)
                lock = ex['expected_lock'] or 'no known lock'
                print(f"    {fn}(): {cnt} check-then-read on '{ex['field']}'  [{lock}]")

    if low and verbose:
        print(f"\n  LOW TOCTOU findings:")
        fn_counts = Counter(f['function'] for f in low)
        for fn, cnt in fn_counts.most_common(10):
            ex = next(f for f in low if f['function'] == fn)
            print(f"    {fn}(): {cnt} unprotected check-then-use on '{ex['field']}'")
