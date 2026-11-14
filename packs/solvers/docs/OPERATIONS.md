# Operations

How the master is run around an event. Commands are `python -m ctf ...` from the master checkout
(`.venv/bin/python`). Per-event instructions live with the event (B-189), not here.

## The master stays current (B-038)

Events consume the master; they do not fork it for keeps. Each event starts from a tagged master
commit, and after the event everything it learned is either folded back into the master or dropped
on purpose. A gate enforces it: the next event cannot be tagged while an earlier event's live fix is
missing from the commit it would start from.

Why: in 2026, live fixes stayed uncommitted in event working trees and never reached the next
event (PINK+ forked from a commit that never received CSCTF's same-week fixes; nothing learned in
three events reached `solvers/`; the Huntress retro counts unfolded live fixes as its most repeatable
loss).

Anchors (git tags in the master):

| tag | meaning | made by |
|---|---|---|
| `event/<slug>/start` | the master commit the event started from | `python -m ctf promote start <slug>` |

The decisions live in `events/<slug>/promotion.json` (committed in the master; schema in
`ctf/promote.py`). The gate is `python -m ctf fold-audit` (`ctf/foldaudit.py`).

### Pre-event

1. `python -m ctf fold-audit --all` — every earlier event is folded (exit 0).
2. `python -m ctf promote start <slug>` — tags `event/<slug>/start` at master HEAD. It runs the same
   audit against HEAD first and refuses (exit 1) while any earlier event has an unfolded fix, or has
   a start tag, has ended and has no promotion record.
3. Make the event checkout from that tag (a clone, or `git worktree add ../<slug> event/<slug>/start`).
   A clone needs the tags (`git fetch --tags`) or `promote inventory --base <commit>` later.

### During the event

Fix in the event checkout as needed. Committing there is better than not, but the inventory also
finds uncommitted and untracked changes. Do not commit `.ctf/`, tokens or challenge files.

### Post-event checklist

1. **Inventory.** `python -m ctf promote inventory <slug> --fork <event checkout> --workspace <event workdir>`
   lists every file that differs from `event/<slug>/start` (state `committed`, `uncommitted` or
   `untracked`; deletions too) and every script in the workdir (attachment folders such as `files/`
   are skipped; `.git`, `.ctf`, virtualenvs and caches are never read). Each entry gets a proposal:
   - a change to a master file: **fold** (same path), with a regression test that fails without it;
   - an event script (`solve_ww.py`, `sa.py`, `12-baby-rsa/solve.py`): **engine**, with the module,
     manifest sidecar and test paths per `docs/BUILDING.md` (lane `common` is a guess);
   - challenge data and outputs: **drop**;
   - content already identical in the master: **fold** (nothing to do).
   It writes `events/<slug>/promotion.json`. Re-running it keeps decisions whose content did not
   change; a decided entry that left the tree is kept and marked stale.
2. **Review.** `python -m ctf promote show <slug> [--pending]`.
3. **Decide** each entry:
   - `promote decide <slug> <entry> --engine [--lane L --name N]` (or explicit `--module/--manifest/--test`)
   - `promote decide <slug> <entry> --fold [--dest PATH ...] [--commit SHA]` (`--commit` when the fix
     was adapted rather than copied: the master commit that did the fold. It must come after
     `event/<slug>/start` and change one of the dest paths; `decide` refuses it otherwise, and the
     gate re-checks it and that it is in the target's history. Make the fold commit first, then
     record it.)
   - `promote decide <slug> <entry> --drop --reason "..."` (a reason is required)
   - `promote accept <slug> <entry ...>|--all` takes the proposals as they are.
4. **Do the work** in the master: copy or adapt each fold, write each engine (module + manifest +
   test that names the module; an engine module must differ from its content at the start tag),
   commit, and commit `events/<slug>/promotion.json`. The gate reads the record from the working
   tree but fails until that exact record is committed at the target: the next event's checkout
   carries the decisions only if they are committed.
5. **Gate.** `python -m ctf fold-audit <slug> --fork <event checkout> --workspace <event workdir>`:
   exit 0 when every entry is decided and reached master HEAD; exit 1 naming each unfolded fix
   (undecided, content differs, file absent, engine incomplete or unchanged since the start tag,
   folding commit not in history, at or before the start tag or not touching the dest, the record
   not committed at the target, or a change in the fork/workspace that is not in the record or
   changed after it); exit 2 when it
   cannot run (no record, no tag, not a git checkout). `--target REF` audits another commit.
6. Post-event builds of to_build items are refused by the B-008 gate
   (`python -m ctf build-plan check <id>`) until this audit passes: fold first, then build.
7. The next event's `promote start` re-runs the audit for every event (step 2 of pre-event).

Every inventory, decision, audit and start tag is also appended to the event's ledger
(`promote.inventory`, `promote.decide`, `fold_audit.check`, `promote.start`).
