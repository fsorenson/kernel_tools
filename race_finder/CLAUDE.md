# race_finder

Data race / TOCTOU finder for Linux kernel C.

Entry point: `main.py` → `race_finder/cli.py`. Config: `config.yaml` in project root.

## Architecture

Six-stage pipeline:
1. **struct_map** — extract structs, embedded locks, state fields, lock-protection annotations from headers
2. **lock_scan** — detect field accesses without enclosing lock acquire; flag unprotected reads/writes
3. **async_tag** — identify workqueue handlers, RCU callbacks, timer handlers, other async contexts
4. **toctou** — check-then-act sequences on the same state field that aren't atomic; multi-step transitions with observable intermediate states
5. *(Stage 5: call graph builder — caller annotation for HIGH findings)* — implemented per features.md
6. **llm_analysis** — LLM deep analysis for flagged functions; gated behind `--llm` flag

## Implemented features

P0 (core pipeline), P1 (analysis depth including Stage 5 call graph), and most P2 (report formatter) are complete per `features.md`. Initialization filter (suppress findings on freshly-allocated objects) is implemented.

## Deferred / not implemented

- Coccinelle script generator (P2)
- KCSAN annotation suggester (P2)
- Debug patch generator (P2)
- Kernel-wide header search outside `source_dirs` (P2.5)
- Multi-target parallel analysis, CVE cross-reference, progress dashboard, incremental re-analysis (P3)

## Constraints

- Do NOT commit or push unless explicitly asked
- Currently parked — not the active development focus
- `tools/reproducer_designer.py`: interactive LLM-guided reproducer generator for found races (separate utility, not part of the pipeline)
