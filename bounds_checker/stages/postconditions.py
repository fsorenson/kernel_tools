"""
Validator postconditions table: seed file + LLM pre-pass for unknown functions.

Workflow:
  1. Load the distributed seed file (bounds_checker/data/validator_postconditions.json).
  2. When a guard callee is too large for body inclusion (> _MAX_GUARD_LINES) but
     small enough to analyze (≤ MAX_PREPASS_BODY_LINES), check the table.
     If absent or checksum-stale, run an LLM pre-pass to extract the postcondition.
  3. At the end of a run, write newly-derived entries to {run_dir}/new_postconditions.json
     and print a count.  The user merges these back into the seed file.

Staleness detection uses SHA-256 of the raw function body text (lines
start_line..end_line inclusive), truncated to 16 hex chars.
"""

import hashlib
import json
import threading
from pathlib import Path

from kernel_analysis.parsers.c_parser import parse_file, find_functions


_SEED_FILE = Path(__file__).parent.parent / 'data' / 'validator_postconditions.json'

# Functions with body > this limit are candidates for the pre-pass (not body inclusion).
# Must match _MAX_GUARD_LINES in stage2_llm_analysis.py.
_GUARD_LINES_LIMIT = 60

# Pre-pass upper limit: bodies larger than this are too complex to summarize reliably.
MAX_PREPASS_BODY_LINES = 200

_PREPASS_SYSTEM = """\
You are a Linux kernel code analyst.  You will be given a C function body and must
extract its memory-safety postcondition in structured JSON.  Focus only on whether
the function validates that offsets, sizes, or counts are within buffer or packet
boundaries, and what the caller can rely on after a successful return.
"""

_PREPASS_PROMPT = """\
Analyze this Linux kernel function and describe its memory-safety postcondition.

Function: {fn_name}() in {short_file}

```c
{fn_source}
```

Answer the following in JSON (no markdown fences, no prose outside the JSON):

- is_validator (bool): does this function validate that offsets, sizes, or counts \
fit within a buffer or packet boundary?
- postcondition (string): if is_validator is true, describe in 1-2 sentences what \
a caller knows on return 0 / non-NULL (what memory regions are verified safe). \
Empty string if not a validator.
- is_self_validator (bool): is this function itself the validation logic — i.e., \
findings about array/pointer accesses INSIDE this function are part of the \
validation process (not vulnerable sinks)?  Set true for functions like \
validate_dacl() whose internal pointer arithmetic IS the bounds walk.
- confidence ("high"|"medium"|"low"): how certain are you of this assessment?

Return ONLY valid JSON:
{{
  "is_validator": <true|false>,
  "postcondition": "<string>",
  "is_self_validator": <true|false>,
  "confidence": "high"|"medium"|"low"
}}
"""


def fn_checksum(filepath, fn_start, fn_end):
    """SHA-256[:16] of raw function body text (lines fn_start..fn_end inclusive)."""
    try:
        src = Path(filepath).read_bytes().decode('utf-8', errors='replace')
        lines = src.splitlines()
        body = '\n'.join(lines[fn_start - 1:fn_end])
        return hashlib.sha256(body.encode()).hexdigest()[:16]
    except Exception:
        return None


def load_seed(seed_file=None):
    """Load the seed file. Returns {fn_name: entry_dict}."""
    path = Path(seed_file or _SEED_FILE)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text()).get('entries', {})
    except Exception:
        return {}


class PostconditionManager:
    """
    Thread-safe manager for the validator postconditions table.

    Holds the loaded seed, accumulates new/updated entries from the LLM
    pre-pass, and writes them to the run output directory at the end of a run.

    Thread safety: multiple _work() threads may call maybe_prepass() concurrently.
    A per-function lock via _pending prevents redundant parallel pre-passes for
    the same function name.  Workers that lose the race return None for this run
    (the function will be in the table for the next run).
    """

    def __init__(self, seed, client, model):
        self._table   = dict(seed)   # fn_name -> entry dict (seed + pre-pass results)
        self._new     = {}           # newly-derived entries not in the seed
        self._lock    = threading.Lock()
        self._pending = set()        # fn_names currently being pre-passed
        self._client  = client
        self._model   = model

    def get(self, fn_name, checksum):
        """
        Return the entry dict if fn_name is in the table and the checksum matches,
        else None (absent or stale).
        """
        with self._lock:
            entry = self._table.get(fn_name)
        if entry and entry.get('checksum') == checksum:
            return entry
        return None

    def maybe_prepass(self, fn_name, filepath, fn_start, fn_end):
        """
        If fn_name is a pre-pass candidate (body 61–MAX_PREPASS_BODY_LINES lines)
        and is not already in the table with a valid checksum, run the LLM pre-pass.

        Non-blocking: if another worker is already pre-passing fn_name, return None
        immediately (the entry will be in the table for the next run).

        Returns the entry dict on success, None if skipped or on error.
        """
        body_lines = fn_end - fn_start + 1
        if body_lines <= _GUARD_LINES_LIMIT or body_lines > MAX_PREPASS_BODY_LINES:
            return None

        checksum = fn_checksum(filepath, fn_start, fn_end)
        if checksum is None:
            return None

        # Fast path: already cached with matching checksum.
        existing = self.get(fn_name, checksum)
        if existing is not None:
            return existing

        # Try to claim the pre-pass slot.
        with self._lock:
            if fn_name in self._pending:
                return None
            self._pending.add(fn_name)

        try:
            entry = _run_prepass(self._client, self._model,
                                 filepath, fn_name, fn_start, fn_end, checksum)
            if entry:
                with self._lock:
                    self._table[fn_name] = entry
                    self._new[fn_name]   = entry
            return entry
        finally:
            with self._lock:
                self._pending.discard(fn_name)

    def write_new(self, run_dir):
        """
        Write newly-derived entries to {run_dir}/new_postconditions.json.
        Returns the count of new entries written.
        """
        with self._lock:
            new = dict(self._new)
        if not new:
            return 0
        out_path = Path(run_dir) / 'new_postconditions.json'
        out_path.write_text(json.dumps({'entries': new}, indent=2))
        return len(new)


def _run_prepass(client, model, filepath, fn_name, fn_start, fn_end, checksum):
    """
    Run the LLM on the function body to extract its postcondition.

    Returns a completed entry dict ready for the table, or None on failure.
    """
    try:
        src_lines = Path(filepath).read_bytes().decode('utf-8', errors='replace').splitlines()
        fn_source  = '\n'.join(
            f"{lineno}: {src_lines[lineno - 1]}"
            for lineno in range(fn_start, fn_end + 1)
        )
    except Exception:
        return None

    prompt = _PREPASS_PROMPT.format(
        fn_name=fn_name,
        short_file=Path(filepath).name,
        fn_source=fn_source,
    )

    try:
        response = client.messages.create(
            model=model,
            max_tokens=512,
            system=_PREPASS_SYSTEM,
            messages=[{'role': 'user', 'content': prompt}],
        )
        text = response.content[0].text.strip()
        data = json.loads(text)
    except Exception:
        return None

    # Reject if LLM says it's not a validator (store as negative cache entry).
    entry = {
        'checksum':        checksum,
        'file_hint':       str(filepath),
        'is_validator':    bool(data.get('is_validator', False)),
        'is_self_validator': bool(data.get('is_self_validator', False)),
        'postcondition':   data.get('postcondition', ''),
        'confidence':      data.get('confidence', 'low'),
    }
    return entry
