# Race Condition Finder — Feature List

Prioritized. Check marks indicate completed features.

---

## P0 — Core Pipeline (MVP)

- [x] Stage 1: Structure/lock mapper — extract structs, embedded locks, state fields, and lock-protection annotations from kernel headers
- [x] Stage 2: Lock-usage scanner — detect field accesses in .c files without an enclosing lock acquire, flag unprotected reads/writes to state/refcount fields
- [ ] Stage 3: Async/callback path tagger — identify workqueue handlers (INIT_WORK, queue_work), RCU callbacks (call_rcu), timer handlers, completion callbacks, and other async contexts where normal locking assumptions break

## P1 — Analysis Depth

- [x] Stage 4: TOCTOU detector — identify check-then-act sequences on the same state field that aren't atomic, flag multi-step state transitions with observable intermediate states
- [x] Stage 5: Call graph builder — direct-call caller-callee map with lock-state at each call site; HIGH findings annotated with callers that lack the required lock; helper functions where all callers hold the lock are suppressed
- [x] Stage 6: LLM deep analysis — feed flagged functions + struct map to Claude API for concurrency reasoning; gated behind --llm flag; outputs structured per-finding confidence scores

- [x] Initialization filter — suppress findings on freshly-allocated objects (kzalloc/kzalloc_obj/kmem_cache_alloc etc.) that have not yet been published; detected by tracking which variables in each function are assigned from kernel allocator calls

## P2 — Formalization & Output

- [ ] Coccinelle script generator — emit .cocci semantic patches that encode identified race patterns for broader kernel-wide scanning
- [ ] KCSAN annotation suggester — recommend WRITE_ONCE/READ_ONCE/data_race() placements for racy accesses that can't be immediately fixed
- [ ] Debug patch generator — suggest mdelay()/cond_resched() injection points to widen race windows for testing; mark locations for explicit schedule() calls in interrupt-disabled paths
- [x] Markdown/HTML report formatter — consolidated per-struct report: struct map, flagged fields, per-finding evidence, suggested fixes

## P2.5 — VFS-Layer Struct Support

- [ ] VFS inode lock family — add `inode_lock`, `inode_unlock`, `inode_lock_shared`, `inode_unlock_shared`, `inode_trylock`, `lock_two_inodes`, `filemap_invalidate_lock` (and shared/unlock variants) to LOCK_FUNCS/UNLOCK_FUNCS so that `i_rwsem`-protected field accesses are correctly tracked
- [ ] Type-aware field matching — track the declared type of the object variable (e.g., distinguish `inode->i_flags` from another struct's `i_flags`) to reduce false positives when targeting structs with generic field names (`i_size`, `i_flags`, `i_count`, `i_ino`)
- [ ] Kernel-wide header search — allow `headers:` to reference files outside `source_dirs` (e.g., `include/linux/fs.h` for `struct inode`, `include/linux/dcache.h` for `struct dentry`) so VFS-layer structs can be targeted without hardcoding paths

## P3 — Scale & Integration

- [ ] Multi-target parallel analysis — analyze multiple structs or subsystem directories concurrently
- [ ] CVE/fix cross-reference — search fixes.git / git log for similar patterns already fixed upstream; surface commit messages for comparison
- [ ] Userspace reproducer harness generator — skeleton test programs using /proc/sys or ioctls to trigger racy paths under controlled concurrency
- [ ] Progress dashboard / live UI — terminal or web-based view of pipeline progress and live findings
- [ ] Incremental re-analysis — re-run only stages whose inputs changed (kernel source updated, config changed)
- [ ] Multi-struct dependency analysis — when struct A embeds or references struct B, propagate lock requirements across struct boundaries
