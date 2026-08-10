"""
Call graph builder and annotation for Stage 2 findings.

Builds a callee→callers reverse map across all analyzed .c files, capturing
the lock state held at each call site.  Used to re-classify HIGH findings
that arise from helper functions requiring the caller to hold a lock.

Limitations:
- Direct calls only; function-pointer dispatch cannot be resolved statically.
- Only callers within the analyzed source_dirs are tracked; external callers
  (other subsystems, exported-symbol users) appear as "no callers found".
- Single-level analysis: transitive lock passing (A holds lock → calls B
  which calls C that accesses the field) requires two-level caller lookup;
  this implementation only looks one level up.
"""

from collections import defaultdict


def build_callee_to_callers(all_fn_call_data):
    """
    Build the reverse call-site map from per-function call site data.

    all_fn_call_data: {fn_name: {'file': str,
                                  'call_sites': [{'callee', 'line', 'locks_held'}]}}

    Returns: {callee_name: [{'fn', 'file', 'line', 'locks_held'}, ...]}
    Each entry represents one call site (a single caller may appear multiple
    times if it calls the callee from multiple locations or lock contexts).
    """
    result = defaultdict(list)
    for fn_name, data in all_fn_call_data.items():
        file_ = data['file']
        for site in data.get('call_sites', []):
            result[site['callee']].append({
                'fn': fn_name,
                'file': file_,
                'line': site['line'],
                'locks_held': site['locks_held'],
            })
    return dict(result)


def annotate_findings(findings, callee_to_callers):
    """
    Annotate HIGH findings with caller lock-state information.
    Adds 'call_graph' and 'revised_severity' keys to matching findings.
    Operates in-place.

    Conclusions:
      all_callers_hold_lock   — every call site holds the expected lock;
                                the function is a caller-lock helper → suppressed
      no_callers_hold_lock    — no call site holds it → confirmed HIGH
      mixed                   — some call sites hold it, some don't;
                                lists which callers lack the lock → confirmed HIGH
      no_callers_found        — function not called from analyzed files
                                (likely exported or called via function pointer)
    """
    for f in findings:
        if f['severity'] != 'high' or not f.get('expected_lock'):
            continue
        fn_name = f['function']
        expected = f['expected_lock']

        sites = callee_to_callers.get(fn_name, [])
        if not sites:
            f['call_graph'] = {'conclusion': 'no_callers_found'}
            continue

        with_lock = [s for s in sites if expected in s['locks_held']]
        without_lock = [s for s in sites if expected not in s['locks_held']]

        f['call_graph'] = {
            'callers_total': len(sites),
            'with_lock': [_site_label(s) for s in with_lock],
            'without_lock': [_site_label(s) for s in without_lock],
        }

        if not without_lock:
            f['call_graph']['conclusion'] = 'all_callers_hold_lock'
            f['revised_severity'] = 'suppressed'
        elif not with_lock:
            f['call_graph']['conclusion'] = 'no_callers_hold_lock'
        else:
            f['call_graph']['conclusion'] = (
                f'{len(without_lock)}_callers_lack_lock_'
                f'{len(with_lock)}_hold_it'
            )


def call_graph_impact(findings):
    """
    Summarize how call graph annotation changed the HIGH finding set.
    Returns a dict suitable for inclusion in the stage output JSON.
    """
    high = [f for f in findings if f['severity'] == 'high']
    suppressed = [f for f in high if f.get('revised_severity') == 'suppressed']
    no_callers = [f for f in high
                  if f.get('call_graph', {}).get('conclusion') == 'no_callers_found']
    mixed = [f for f in high
             if 'callers_lack_lock' in f.get('call_graph', {}).get('conclusion', '')]
    confirmed_no_lock = [f for f in high
                         if f.get('call_graph', {}).get('conclusion') == 'no_callers_hold_lock']

    # Unique function names in each category (multiple findings per fn for multiple accesses)
    def _fns(lst):
        seen = {}
        for f in lst:
            seen[f['function']] = f
        return list(seen.keys())

    return {
        'original_high_count': len(high),
        'suppressed_count': len(suppressed),
        'suppressed_functions': _fns(suppressed),
        'confirmed_no_lock_count': len(confirmed_no_lock),
        'mixed_count': len(mixed),
        'no_callers_found_count': len(no_callers),
        'no_callers_found_functions': _fns(no_callers),
    }


def _site_label(site):
    short = site['file'].rsplit('/', 1)[-1]
    return f"{site['fn']} ({short}:{site['line']})"
