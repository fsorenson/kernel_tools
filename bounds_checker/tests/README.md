# Bounds checker test suite

## Running

```sh
# Both stages (no API calls):
python3 bounds_checker/tests/run_all.py

# Stage 1 scanner only (fast, ~1s):
python3 bounds_checker/tests/run_stage1.py

# Stage 1.7 SMT only (~20s):
python3 bounds_checker/tests/run_stage17.py
```

Exit code: 0 if all pass, 1 if any fail.

## Files

| File | Purpose |
|---|---|
| `probe_stage1.c` | Test cases for the Stage 1 taint scanner: one positive and one or more control/FP cases per category (A–H, L) |
| `probe_smt.c` | Test cases for Stage 1.7 SMT refinement: guard-kind cases, CFG cases, path-condition edge cases |
| `run_stage1.py` | Stage 1 harness: runs `scan_files()` + `scan_copy_user_files()` and checks findings against `EXPECTED` |
| `run_stage17.py` | Stage 1.7 harness: runs scanner + SMT and checks each finding's verdict against `EXPECT` |
| `run_all.py` | Runs both; Stage 2 (LLM) is omitted (requires API credentials and is non-deterministic) |

## Naming convention in probe_stage1.c

| Prefix | Meaning |
|---|---|
| `bug_X_*` | Must produce Cat X finding, `possibly_guarded=False` |
| `guarded_X_*` | Must produce Cat X finding, `possibly_guarded=True` |
| `fp_X_*` | Stage 1 fires with `possibly_guarded=True`; Stage 1.7 retires it (the finding is not a real bug, but the scanner cannot see that without the SMT layer) |

Functions with `no_finding` in the expected table must produce NO finding for ANY category.

## Expected outcomes table (summary)

Stage 1 tests cover: Cat A (tainted ptr → memory op), B (tainted size → alloc), C (subscript), D (strlen without NUL guarantee), E (ptr deref from tainted offset), F (loop bound), G1 (copy retval unchecked), G2 (unvalidated copy size), H (narrowing assignment), L (tainted shift amount).

Stage 1.7 tests cover: signed/unsigned ceiling guards, offset lookahead, bitmask, masked shift, guard-kills-and-retaints, CFG dominance, goto patterns.

## Adding test cases

1. Add the function to `probe_stage1.c` following the naming convention.
2. Add an entry to `EXPECTED` in `run_stage1.py`.
3. Run `python3 bounds_checker/tests/run_stage1.py` to verify.

For SMT cases, add to `probe_smt.c` and `EXPECT` in `run_stage17.py`.

## Stage 2 (LLM) testing

Not automated here.  The canonical approach is to run the full pipeline against a
known subsystem (`fs/smb/client`), then compare the LLM's verdicts against the
hand-verified ground-truth findings maintained in the `kcsan-stats_findings.txt`
reference.  Stage 2 is deliberately excluded from CI to avoid LLM API costs on
every run.
