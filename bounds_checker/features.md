# Bounds / Data Validation Checker — Feature List

Companion tool to the race finder.  Detects missing or insufficient
validation of server-supplied (or user-supplied) values before use in
memory operations, allocations, or array indexing.

Shares generic parsing infrastructure from `kernel_analysis/parsers/`.

---

## P0 — Core Pipeline (MVP)

- [x] Shared parser infrastructure — `kernel_analysis/parsers/c_parser.py` provides
      `parse_file`, `find_functions`, `find_calls_to`, `extract_local_array_decls`,
      `find_alloc_vars`, and `build_var_type_map`; no duplication needed

- [x] Config and CLI — `bounds_checker/config.py` + `bounds_checker/cli.py`;
      YAML config with `source_dirs`, `taint_sources`, `dangerous_sinks`,
      `categories` (default: all)

- [x] Stage 1: Taint scanner — per-function intra-procedural taint flow analysis
      - [x] **Category A**: server-supplied value → pointer arithmetic → memory op
            (e.g., `DataOffset` field → `base + offset` → `memcpy(ptr, ...)`)
      - [x] **Category B**: server-supplied value → size/alloc argument
            (e.g., `kmalloc(le32_to_cpu(hdr->Size))`, direct size arg to memcpy)
      - [x] **Category C**: server-supplied value → array subscript without bounds check
            (e.g., `arr[le16_to_cpu(hdr->Index)]` without `if (idx >= ARRAY_SIZE(arr))`)

- [x] Stage 2: LLM deep analysis — feed taint findings to Claude API for
      false-positive filtering, severity assessment, and fix suggestions;
      analogous to race finder Stage 6

## P1 — Additional Categories

- [ ] **Category D**: unterminated string / missing null-termination guarantee —
      `strlen()` / `strlcpy()` on a server-supplied buffer with no guarantee
      a null byte exists within bounds; guard pattern is `strnlen(buf, max)`

- [ ] **Category E**: nested struct field access beyond packet bounds — accessing
      `pkt->nested.field` where `nested` is located at a server-supplied offset
      without first verifying `offset + sizeof(nested) <= pkt_end`

- [ ] **Category F**: variable-length protocol array iterated without count validation —
      `for (i = 0; i < server_count; i++) use(&arr[i])` without checking
      `server_count * sizeof(entry) <= remaining_bytes`

- [ ] **Category G1**: `copy_from_user` / `copy_to_user` return value unchecked —
      partial copy treated as success

- [ ] **Category G2**: user-supplied size used before validation — size checked
      after use rather than before

## P2 — Depth and Quality

- [ ] Cross-function taint propagation — one-hop: when a function receives a
      tainted value as a parameter and passes it to a sink, trace back to callers
      to identify the origin; analogous to race finder Stage 5

- [ ] Integer overflow detection — flag `a * b` or `a + b` passed directly to
      `kmalloc`/`memcpy`/etc. without `check_mul_overflow`, `size_add`,
      `size_mul`, or `kmalloc_array`; separate from Category B basic size check

- [ ] Guard detection improvement — current MVP uses a line-number heuristic
      (if any `if` referencing the tainted var appears between source and sink,
      mark "possibly guarded"); improve with control-flow awareness

- [ ] Type width narrowing (Category H) — server-supplied `u32` stored in `u16` or
      `int` intermediate; the narrowing silently caps the value, allowing a check
      on the narrowed copy to pass for values that wouldn't pass on the original

- [ ] Configurable taint sources and sinks — allow per-project YAML extension of
      the default `TAINT_SOURCES` and `DANGEROUS_SINKS` sets for non-CIFS subsystems
      (e.g., NFS uses `be32_to_cpu`, block drivers have their own idioms)

## P3 — Output and Integration

- [x] Markdown / HTML report formatter — per-file findings with source snippets,
      taint flow explanation, suggested fix; written after Stage 1 (static only)
      and overwritten after Stage 2 (with LLM assessment, impact badges, fix text)

- [ ] Integration with race finder run dirs — optionally consume race finder
      Stage 1 struct map to annotate which tainted fields belong to which struct

- [ ] Multi-struct / cross-file summary — aggregate findings across a full
      subsystem directory into a ranked list by severity

- [ ] Reproducer designer integration — pipe high-confidence bounds findings
      into `tools/reproducer_designer.py` for test case generation
