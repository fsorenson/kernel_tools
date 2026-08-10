"""
Stage 2: Lock Usage Scanner + Call Graph Annotation

For each .c file in the target source directories, finds accesses to fields
of the target struct and checks whether the appropriate lock is held at the
point of access.

Two categories of findings:
  1. Fields with explicit protection (from stage 1): access without that lock held.
  2. Suspicious fields (no stated protection): all accesses flagged for review.

Analysis is intra-procedural with linear (branch-insensitive) lock tracking.
A lock 'held' at line N means a lock-acquire call appeared before line N and
no unlock call appeared between that acquire and line N, in textual order.
This may produce false positives when locking is conditional.

Call graph annotation:
  After finding all HIGH findings (lock never acquired in function), a reverse
  call-site map is built from all analyzed .c files.  Each HIGH finding is then
  annotated with the lock state at every call site that reaches that function.
  If all callers hold the required lock, the finding is suppressed (the function
  is a caller-lock helper); if some callers don't, those are listed explicitly.
"""

import json
import sys

from ..parsers.c_parser import (
    parse_file,
    find_functions,
    find_field_accesses,
    find_lock_events,
    find_lock_wrappers,
    find_ops_registrations,
    find_indirect_call_sites,
    lock_state_at,
    collect_call_sites,
    find_alloc_vars,
    build_var_type_map,
)
from ..analysis.call_graph import (
    build_callee_to_callers,
    annotate_findings,
    call_graph_impact,
)


def run(cfg, run_dir, stage1_output, verbose=False):
    struct_info = stage1_output['result']
    struct_name = struct_info['struct_name']

    lock_field_names = set(struct_info['locks'])
    field_map = {f['name']: f for f in struct_info['fields']}

    suspicious_names = {s['name'] for s in struct_info['suspicious_fields']}

    # Bitfield unit → [field names]; used to report co-located fields in findings.
    bitfield_unit_map = {}
    for f in struct_info['fields']:
        uid = f.get('bitfield_unit')
        if uid is not None:
            bitfield_unit_map.setdefault(uid, []).append(f['name'])

    embedded_protected = {
        f['name']: f['protection']
        for f in struct_info['fields']
        if f.get('protection') and f['protection'] in lock_field_names
    }

    external_protected = {
        f['name']: f['protection']
        for f in struct_info['fields']
        if f.get('protection') and f['protection'] not in lock_field_names
    }

    target_fields = (
        suspicious_names | set(embedded_protected) | set(external_protected)
    ) - lock_field_names

    if not target_fields:
        print("Stage 2: no target fields to scan", file=sys.stderr)
        return None

    source_dirs = cfg['target'].get('source_dirs') or []
    kernel_source = cfg['kernel_source']

    # Collect all .c paths first so we can run wrapper discovery in one pass
    c_paths = []
    for rel_dir in source_dirs:
        dir_path = kernel_source / rel_dir
        if not dir_path.exists():
            print(f"  [warn] source dir not found: {rel_dir}", file=sys.stderr)
            continue
        c_paths.extend(sorted(dir_path.rglob('*.c')))

    # Discover lock/unlock wrapper functions before the main scan
    extra_lock_funcs, extra_unlock_funcs = find_lock_wrappers(c_paths)
    if extra_lock_funcs or extra_unlock_funcs:
        all_wrappers = sorted(extra_lock_funcs | extra_unlock_funcs)
        print(f"  Lock wrappers discovered: {', '.join(all_wrappers)}")

    all_findings = []
    all_fn_call_data = {}   # fn_name -> {file, call_sites}
    files_scanned = 0
    files_errored = 0
    total_init_suppressed = 0

    for c_path in c_paths:
        try:
            findings, fn_call_data, init_suppressed = _scan_file(
                c_path, struct_name, target_fields, field_map,
                lock_field_names, suspicious_names,
                embedded_protected, external_protected,
                extra_lock_funcs, extra_unlock_funcs,
                bitfield_unit_map, verbose,
            )
            all_findings.extend(findings)
            all_fn_call_data.update(fn_call_data)
            total_init_suppressed += init_suppressed
            files_scanned += 1
        except Exception as exc:
            if verbose:
                print(f"  [error] {c_path.name}: {exc}")
            files_errored += 1

    # Build call graph and annotate HIGH findings
    callee_to_callers = build_callee_to_callers(all_fn_call_data)
    annotate_findings(all_findings, callee_to_callers)

    # Indirect call graph: resolve function-pointer dispatch for functions that
    # appear unresolvable via direct-call graph ("no_callers_found").  Many
    # kernel helpers are invoked through ops vtables (server->ops->set_fid()),
    # which the direct call graph cannot follow.
    _annotate_indirect_callers(
        all_findings, c_paths, lock_field_names,
        extra_lock_funcs, extra_unlock_funcs, verbose,
    )

    cg_impact = call_graph_impact(all_findings)

    # Sort: confirmed HIGH first, then suppressed HIGH, medium, low; within each by file+line
    all_findings.sort(key=lambda f: (
        _sev_sort_key(f),
        f['file'],
        f['line'],
    ))

    output = {
        'stage': 'lock_scan',
        'struct': struct_name,
        'files_scanned': files_scanned,
        'files_errored': files_errored,
        'fields_checked': sorted(target_fields),
        'lock_wrappers_discovered': sorted(extra_lock_funcs | extra_unlock_funcs),
        'init_context_suppressed': total_init_suppressed,
        'total_findings': len(all_findings),
        'call_graph_impact': cg_impact,
        'findings': all_findings,
    }

    out_path = run_dir / 'stage2_lock_scan.json'
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"Stage 2 output: {out_path}")

    _print_summary(all_findings, files_scanned, cg_impact,
                   total_init_suppressed, verbose)
    return output


def _annotate_indirect_callers(findings, c_paths, lock_field_names,
                                extra_lock_funcs, extra_unlock_funcs, verbose):
    """
    For HIGH findings whose direct call graph returned 'no_callers_found',
    attempt to resolve indirect dispatch through ops vtables.

    Strategy:
      1. Collect the set of unresolved function names.
      2. Scan all source files for initializer_pair registrations (.field = func).
      3. For each registered field name, scan for indirect call sites (->field()).
      4. Annotate the findings with the resolved callers and their lock state.
         If every indirect caller holds the expected lock, suppress the finding.
    """
    no_caller_findings = [
        f for f in findings
        if f.get('severity') == 'high'
        and f.get('call_graph', {}).get('conclusion') == 'no_callers_found'
        and f.get('expected_lock')
    ]
    if not no_caller_findings:
        return

    target_fns = {f['function'] for f in no_caller_findings}
    ops_regs = find_ops_registrations(c_paths, target_fns)
    if not ops_regs:
        return

    # Build field_name → {func_names} reverse map
    field_to_funcs = {}
    for func_name, regs in ops_regs.items():
        for (_file, field_name) in regs:
            field_to_funcs.setdefault(field_name, set()).add(func_name)

    all_field_names = set(field_to_funcs)
    indirect_sites = find_indirect_call_sites(
        c_paths, all_field_names, extra_lock_funcs, extra_unlock_funcs,
    )

    if verbose and ops_regs:
        for fn, regs in ops_regs.items():
            fields = ', '.join(f'{field} ({p.rsplit("/",1)[-1]})' for p, field in regs)
            print(f"  [ops] {fn} registered as: {fields}")

    for f in no_caller_findings:
        fn_name = f['function']
        if fn_name not in ops_regs:
            continue

        expected = f['expected_lock']
        regs = ops_regs[fn_name]
        reg_field_names = {field for (_, field) in regs}

        # Collect indirect call sites across all registered field names
        all_sites = []
        for field_name in reg_field_names:
            all_sites.extend(indirect_sites.get(field_name, []))

        f['call_graph']['ops_registrations'] = [
            {'file': p.rsplit('/', 1)[-1], 'field': field}
            for (p, field) in regs
        ]

        if not all_sites:
            f['call_graph']['conclusion'] = 'ops_registered_no_sites_found'
            continue

        # Lock-state assessment using raw lock argument text.
        # The expected_lock (e.g. 'lock_sem') won't appear literally in the
        # caller's code; instead look for any argument text containing it.
        def _holds_expected(site):
            return any(expected in arg for arg in site['locks_held'])

        with_lock    = [s for s in all_sites if _holds_expected(s)]
        without_lock = [s for s in all_sites if not _holds_expected(s)]

        def _site_label(s):
            return (f"{s['caller_fn']} "
                    f"({s['file'].rsplit('/',1)[-1]}:{s['line']}) "
                    f"locks=[{', '.join(s['locks_held'])}]")

        f['call_graph']['indirect_callers'] = [_site_label(s) for s in all_sites[:6]]

        if not without_lock:
            f['call_graph']['conclusion'] = 'all_indirect_callers_hold_lock'
            f['revised_severity'] = 'suppressed'
        elif not with_lock:
            f['call_graph']['conclusion'] = 'no_indirect_callers_hold_lock'
        else:
            f['call_graph']['conclusion'] = (
                f'{len(without_lock)}_indirect_callers_lack_lock_'
                f'{len(with_lock)}_hold_it'
            )


def _obj_struct_matches(obj_text, var_types, target_struct):
    """
    Return True if the object expression is compatible with target_struct.
    Handles plain identifiers and array-subscript expressions (bkt[i]).
    Unknown objects (not in var_types) are kept conservatively.
    """
    # Strip array subscript: "bkt[i]" → "bkt", "bkt[sample[j]]" → "bkt"
    base = obj_text[:obj_text.index('[')] if '[' in obj_text else obj_text
    base = base.strip()
    if base not in var_types:
        return True  # unknown type — keep conservatively
    return var_types[base] == target_struct


def _sev_sort_key(f):
    """Sort key: confirmed HIGH < suppressed HIGH < medium < low."""
    if f['severity'] == 'high':
        return 0 if f.get('revised_severity') != 'suppressed' else 1
    return _sev_key(f['severity']) + 1


def _sev_key(sev):
    return {'high': 0, 'medium': 1, 'low': 2, 'suppressed': 3}.get(sev, 4)


def _scan_file(c_path, struct_name, target_fields, field_map,
               lock_field_names, suspicious_names,
               embedded_protected, external_protected,
               extra_lock_funcs, extra_unlock_funcs,
               bitfield_unit_map, verbose):
    """
    Parse one .c file.
    Returns (findings_list, fn_call_data_dict, init_suppressed_count).
    fn_call_data_dict: {fn_name: {'file': str, 'call_sites': [...]}}
    """
    tree, source = parse_file(c_path)
    rel = str(c_path)
    findings = []
    fn_call_data = {}
    init_suppressed = 0

    for fn in find_functions(tree, source):
        body = fn['body']
        fn_name = fn['name']

        lock_events = find_lock_events(body, lock_field_names, source,
                                        extra_lock_funcs, extra_unlock_funcs)
        fn_acquires = {ev['lock_name'] for ev in lock_events if ev['kind'] == 'lock'}

        # Collect call sites for this function (used by call graph pass)
        sites = collect_call_sites(body, lock_events, source)
        fn_call_data[fn_name] = {'file': rel, 'call_sites': sites}

        # Variables holding freshly-allocated objects — lock not needed for their fields
        alloc_vars = find_alloc_vars(body, source)

        accesses = find_field_accesses(body, target_fields, source)
        if not accesses:
            continue

        # Filter accesses where the object variable's declared type is known
        # and doesn't match our target struct — eliminates same-field-name hits
        # in unrelated structs (e.g. bucket->count vs cifs_ses->count).
        var_types = build_var_type_map(fn['node'], body, source)
        if var_types:
            accesses = [
                a for a in accesses
                if _obj_struct_matches(a['obj'], var_types, struct_name)
            ]
        if not accesses:
            continue

        # Filter out accesses where the object is a freshly-allocated (not yet published) variable
        if alloc_vars:
            filtered = [a for a in accesses if a['obj'] not in alloc_vars]
            init_suppressed += len(accesses) - len(filtered)
            accesses = filtered
        if not accesses:
            continue

        for acc in accesses:
            field = acc['field']
            line = acc['line']
            access_type = acc['access_type']
            finfo = field_map.get(field, {})
            held_at_access = lock_state_at(lock_events, line)

            if field in suspicious_names:
                if finfo.get('is_refcount') and not finfo.get('is_atomic'):
                    severity = 'high'
                    reason = 'non-atomic refcount with no stated protection'
                elif finfo.get('bitfield_unit') is not None and access_type == 'write':
                    uid = finfo['bitfield_unit']
                    co_located = [n for n in bitfield_unit_map.get(uid, []) if n != field]
                    severity = 'high'
                    reason = (
                        'write to co-located bitfield is an RMW on the storage word'
                        + (f'; races with concurrent writes to: {", ".join(co_located)}'
                           if co_located else '')
                    )
                else:
                    severity = 'low'
                    reason = 'state/flag field with no stated protection'
                findings.append(_make_finding(
                    rel, fn_name, line, field, finfo,
                    expected_lock=None,
                    held=held_at_access,
                    access_type=access_type,
                    snippet=acc['snippet'],
                    obj=acc['obj'],
                    severity=severity,
                    reason=reason,
                ))

            elif field in embedded_protected:
                expected = embedded_protected[field]
                if expected not in held_at_access:
                    if expected not in fn_acquires:
                        severity = 'high'
                        reason = f'access without {expected} (never acquired in this function)'
                    else:
                        severity = 'medium'
                        reason = f'access without {expected} at this point (branch-insensitive)'
                    findings.append(_make_finding(
                        rel, fn_name, line, field, finfo,
                        expected_lock=expected,
                        held=held_at_access,
                        access_type=access_type,
                        snippet=acc['snippet'],
                        obj=acc['obj'],
                        severity=severity,
                        reason=reason,
                    ))

            elif field in external_protected:
                findings.append(_make_finding(
                    rel, fn_name, line, field, finfo,
                    expected_lock=external_protected[field],
                    held=held_at_access,
                    access_type=access_type,
                    snippet=acc['snippet'],
                    obj=acc['obj'],
                    severity='low',
                    reason=f'protected by external lock {external_protected[field]} (not verified)',
                ))

    if verbose and (findings or init_suppressed):
        msg = f"  [{c_path.name}] {len(findings)} findings"
        if init_suppressed:
            msg += f"  ({init_suppressed} init-context suppressed)"
        print(msg)

    return findings, fn_call_data, init_suppressed


def _make_finding(file, function, line, field, finfo,
                  expected_lock, held, access_type, snippet, obj,
                  severity, reason):
    return {
        'severity': severity,
        'file': file,
        'function': function,
        'line': line,
        'field': field,
        'field_type': finfo.get('type', ''),
        'obj': obj,
        'access_type': access_type,
        'expected_lock': expected_lock,
        'locks_held': sorted(held),
        'snippet': snippet,
        'reason': reason,
    }


def _print_summary(findings, files_scanned, cg_impact, init_suppressed, verbose):
    confirmed_high = [
        f for f in findings
        if f['severity'] == 'high' and f.get('revised_severity') != 'suppressed'
    ]
    suppressed = [
        f for f in findings
        if f.get('revised_severity') == 'suppressed'
    ]
    medium = [f for f in findings if f['severity'] == 'medium']
    low = [f for f in findings if f['severity'] == 'low']

    print(f"\n=== Stage 2: Lock Scan ({files_scanned} files) ===")
    print(f"  Total findings: {len(findings)}")
    print(f"  HIGH (confirmed):  {len(confirmed_high)}")
    print(f"  HIGH (suppressed): {len(suppressed)}"
          f"  ← all callers hold required lock")
    print(f"  MEDIUM:            {len(medium)}")
    print(f"  LOW:               {len(low)}")
    if init_suppressed:
        print(f"  Init-context suppressed: {init_suppressed}"
              f"  ← accesses on freshly-allocated objects")

    # Suppressed function summary (always shown)
    if suppressed:
        supp_fns = sorted({f['function'] for f in suppressed})
        print(f"\n  Suppressed functions (caller-lock helpers):")
        for fn in supp_fns:
            # Show the lock and one example caller
            example = next(f for f in suppressed if f['function'] == fn)
            cg = example.get('call_graph', {})
            callers = cg.get('with_lock', [])
            lock = example.get('expected_lock', '?')
            print(f"    {fn}()  [requires {lock}]")
            for c in callers[:3]:
                print(f"      ← {c}")
            if len(callers) > 3:
                print(f"      ... and {len(callers)-3} more")

    # Confirmed HIGH findings
    if confirmed_high:
        print(f"\n  Confirmed HIGH findings:")
        # Deduplicate by (function, field) for the summary header
        seen_fn_field = set()
        for f in confirmed_high:
            key = (f['function'], f['field'])
            rel_file = f['file'].split('fs/smb/')[-1] if 'fs/smb' in f['file'] else f['file']
            print(
                f"\n  [HIGH] {rel_file}:{f['line']}  "
                f"{f['function']}()  field={f['field']}  {f['access_type']}"
            )
            print(f"    reason: {f['reason']}")
            if f.get('expected_lock'):
                print(f"    expected: {f['expected_lock']}  held: {f['locks_held'] or 'none'}")
            print(f"    snippet: {f['snippet']}")
            cg = f.get('call_graph', {})
            if cg:
                conc = cg.get('conclusion', '')
                if conc == 'no_callers_found':
                    print(f"    call graph: no callers found in analyzed files")
                elif conc == 'ops_registered_no_sites_found':
                    regs = cg.get('ops_registrations', [])
                    reg_str = ', '.join(f"{r['field']} ({r['file']})" for r in regs)
                    print(f"    call graph: ops-registered ({reg_str}) but no indirect call sites found")
                elif 'indirect_callers_hold_lock' in conc or 'indirect_callers_lack' in conc or conc == 'no_indirect_callers_hold_lock':
                    regs = cg.get('ops_registrations', [])
                    reg_str = ', '.join(f".{r['field']}" for r in regs)
                    print(f"    call graph: ops dispatch ({reg_str}) — {conc}")
                    for c in cg.get('indirect_callers', [])[:4]:
                        print(f"      {c}")
                elif 'no_callers_hold' in conc:
                    print(f"    call graph: no callers hold {f['expected_lock']}")
                    for c in cg.get('with_lock', [])[:2]:
                        print(f"      with lock: {c}")
                    for c in cg.get('without_lock', [])[:2]:
                        print(f"      WITHOUT:   {c}")
                elif 'callers_lack' in conc:
                    print(f"    call graph: MIXED — {conc}")
                    for c in cg.get('without_lock', [])[:3]:
                        print(f"      WITHOUT lock: {c}")
                    for c in cg.get('with_lock', [])[:2]:
                        print(f"      with lock:    {c}")

    # MEDIUM findings (always printed, without call graph detail)
    if medium and not verbose:
        # Summarize by function
        from collections import Counter
        fn_counts = Counter(f['function'] for f in medium)
        print(f"\n  MEDIUM findings by function (use --verbose for details):")
        for fn, cnt in fn_counts.most_common(10):
            example = next(f for f in medium if f['function'] == fn)
            lock = example.get('expected_lock', '?')
            print(f"    {fn}(): {cnt} access(es) without {lock}")
    elif medium and verbose:
        print(f"\n  MEDIUM findings:")
        for f in medium:
            rel_file = f['file'].split('fs/smb/')[-1] if 'fs/smb' in f['file'] else f['file']
            print(
                f"\n  [MEDIUM] {rel_file}:{f['line']}  "
                f"{f['function']}()  field={f['field']}  {f['access_type']}"
            )
            print(f"    {f['reason']}")
            print(f"    snippet: {f['snippet']}")
