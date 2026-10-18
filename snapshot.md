Please update the project CLAUDE.md files to preserve important context
before I run /clear.

## File structure to use

- `CLAUDE.md` at the project root: project inventory, shared code,
  cross-cutting conventions that apply to all tools.
- A `CLAUDE.md` inside each tool subdirectory (e.g. `bounds_checker/CLAUDE.md`,
  `syntactic_lint/CLAUDE.md`): that tool's architecture, design decisions,
  active deferred items, and next steps.
- Do NOT duplicate content that lives in a dedicated reference document
  (e.g. `bc_category_review_brief.md`). Reference it by path instead.

## What to capture (things /clear would destroy)

- Architectural decisions and the reasoning behind them ("we chose X over Y
  because Z")
- Scope boundaries and why they exist (what is deliberately out of scope and why)
- Deferred work items with enough detail to resume them cold
- In-progress or partially-implemented features not yet committed
- Active next steps — the specific tasks queued for the next session
- Conventions and constraints the user has stated (commit policy, attribution
  format, coding style preferences specific to this project)

## What NOT to capture (already in code, git, or reference docs)

- Function signatures, file paths to stable files, or anything readable from
  the repo itself
- Bug fix history (that's in git log)
- Full category taxonomy (that's in bc_category_review_brief.md)
- Content already in ~/.claude/CLAUDE.md (user profile, kernel expertise, etc.)

## Update rules

- If a CLAUDE.md already exists, read it first, then update in place.
  Do not overwrite — merge and reconcile.
- Move completed tasks to a brief `## Recently completed` section (one line
  each; no detail needed — git log has it).
- Keep each file under ~150 lines. If it grows beyond that, the content is
  too granular — summarize.
- Use present-tense, imperative declarations ("Stage 1.7 uses bitvector
  arithmetic"), not narrative ("we decided to use bitvector arithmetic").
- Flag any decision or deferred item that has a known expiry condition
  ("deferred until alias analysis is available") so future sessions can
  prune stale entries.

## Sections for each tool CLAUDE.md

1. **Architecture** — the pipeline / component model in 3–5 bullets. No
   function-level detail.
2. **Key design decisions** — non-obvious choices and their rationale. Only
   include things that would surprise a reader of the code and that aren't
   explained by a comment in the code itself.
3. **Scope** — what is in scope, what is deliberately out of scope, and why.
4. **Deferred items** — things designed but not implemented, with the
   implementation prerequisite stated.
5. **Active next steps** — the specific tasks queued for the next session,
   ordered by priority. Remove entries as they are committed.
6. **Constraints** — standing rules that apply every session (e.g., "do not
   commit unless explicitly asked").

## Sections for the root CLAUDE.md

1. **Project inventory** — one line per tool: what it does, its entry point,
   its status (active / stable / prototype).
2. **Shared code** — which modules are shared across tools and who owns them.
3. **Cross-cutting conventions** — git attribution format, commit policy,
   related external resources (kernel source path, test dirs, review brief).
4. **Active work** — which tool is currently the focus of development.

When done, list the files you wrote or updated and note anything you were
unable to capture because the conversation context was already compacted.
