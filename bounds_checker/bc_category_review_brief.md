# Bounds checker — category list for completeness review

A static analyzer for Linux kernel C (tree-sitter, no compilation). Stage 1 is a
per-function taint/pattern scanner; Stage 2 sends surviving findings to an LLM
for adjudication. Unit of analysis is one function, with a one-hop cross-function
pass for tainted values passed as arguments.

**Taint model:** a value is tainted if it comes from a scalar endian helper —
`get_unaligned_{le,be}{8,16,32,64}()`, `{le,be}{16,32,64}_to_cpu()`, `ntohs/ntohl`
— or is derived from one by arithmetic. Anything that does not pass through one
of those helpers is untainted, including buffers returned by a callee and values
read from struct fields that were not endian-converted at this site.

## Implemented categories

| Cat | Sink | Description |
|---|---|---|
| A | `memcpy`/`memmove`/`memset`/`copy_{to,from}_user` etc. | Tainted value reaches a pointer or length argument of a memory operation |
| B | `kmalloc`/`kzalloc`/`kcalloc`/`kmalloc_array`/`vmalloc`/`devm_*` | Tainted value reaches an allocation size argument; flagged separately when the size expression is a `*` or `+` that can overflow |
| C | `arr[idx]` | Tainted value used as an array subscript |
| D | `strlen`/`strlcpy`/`strcat`/`strcpy` | String function applied to a buffer with no guarantee of a terminator in bounds. Requires the string pointer itself to be taint-derived via offset arithmetic |
| E | `p->field` | Dereference of a pointer computed from a tainted offset, without first checking the resulting pointer against the packet end |
| F | `for (i = 0; i < n; i++)` | Tainted value used as a loop iteration bound |
| G1 | `copy_{to,from}_user` | Return value discarded or never compared against zero — a partial copy is treated as success |
| G2 | `copy_{to,from}_user` | Size argument is user-supplied and unvalidated at the call |
| H | declaration / assignment | Tainted value of width N stored into a narrower integer type; the truncated copy is what later bounds checks see |

Suppression common to all: a heuristic `possibly_guarded` flag set when a
comparison or a `check_*_overflow()`/`size_{add,mul}()` call mentioning the
tainted variable appears between the taint source and the sink.

## Designed but not implemented

- **G3** — `kmalloc` (not `kzalloc`) of a struct with padding, then `copy_to_user`:
  uninitialized-byte infoleak. Needs per-field write coverage.

## What is deliberately out of scope

- Values that never pass through an endian helper (see taint model above)
- Transitive taint beyond one call hop
- Anything requiring an invariant established more than one frame up
- Purely local overflow with no server-supplied input — a sibling tool
  (`syntactic_lint`) covers narrow-integer wrap, pointer/length pairing, and
  scan loops with no taint requirement at all

## The review question

Which classes of kernel bounds, length, offset, or integer-range bug that occur
in real protocol-parsing and driver code are not covered by A–H? For each gap:
name the bug class, give a concrete kernel or CVE example, state the sink and
the guard whose absence defines it, and say whether it is detectable from a
single function body given the taint model above.
