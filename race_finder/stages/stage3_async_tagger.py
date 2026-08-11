"""
Stage 3: Async/Callback Path Tagger

Scans the target source directories for registrations of functions as async
callbacks or deferred handlers: workqueue work items (INIT_WORK,
INIT_DELAYED_WORK), RCU callbacks (call_rcu), timer handlers (timer_setup),
IRQ handlers (request_irq), tasklets, and kernel threads (kthread_create/run).

These functions execute outside the normal call stack of their callers, so they
inherit no lock state and may run concurrently with any code that holds the
locks they need.  Stage 3 tags them so that Stage 2 can annotate findings in
these functions with async-context notes instead of treating them as ordinary
helper functions.

Output: stage3_async_tags.json — {func_name: {async_kind, context_note,
                                               registrations: [...]}}
"""

import json
from pathlib import Path

from ..parsers.c_parser import find_async_registrations

# Human-readable descriptions for each async kind
_KIND_LABEL = {
    'workqueue':    'workqueue handler',
    'rcu_callback': 'RCU callback',
    'timer':        'timer callback',
    'irq_handler':  'IRQ/threaded-IRQ handler',
    'tasklet':      'tasklet handler',
    'kthread':      'kernel thread',
    'napi_poll':    'NAPI poll handler',
}


def run(cfg, run_dir, verbose=False):
    """
    Scan source directories for async callback registrations.
    Returns the stage output dict.
    """
    source_dirs = cfg['target'].get('source_dirs') or []
    kernel_source = cfg['kernel_source']

    c_paths = []
    for rel_dir in source_dirs:
        dir_path = kernel_source / rel_dir
        if not dir_path.exists():
            continue
        c_paths.extend(sorted(dir_path.rglob('*.c')))

    if not c_paths:
        print("Stage 3: no .c files found in source_dirs", flush=True)
        return None

    async_fns = find_async_registrations(c_paths)

    if verbose:
        for fn, info in sorted(async_fns.items()):
            vias = sorted({r['via'] for r in info['registrations']})
            files = sorted({Path(r['file']).name for r in info['registrations']})
            print(f"  [{info['async_kind']}] {fn}  via={vias}  in={files}")

    by_kind = {}
    for fn, info in async_fns.items():
        by_kind.setdefault(info['async_kind'], []).append(fn)

    summary_parts = [
        f"{len(fns)} {_KIND_LABEL.get(kind, kind)}"
        for kind, fns in sorted(by_kind.items())
    ]
    print(f"Stage 3: {len(async_fns)} async functions found "
          f"({', '.join(summary_parts) if summary_parts else 'none'})")

    output = {
        'stage': 'async_tagger',
        'files_scanned': len(c_paths),
        'async_functions': async_fns,
    }

    out_path = run_dir / 'stage3_async_tags.json'
    with open(out_path, 'w') as fh:
        json.dump(output, fh, indent=2)
    print(f"Stage 3 output: {out_path}")

    return output
