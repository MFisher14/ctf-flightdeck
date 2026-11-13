# Building in this repo

How to add an engine, how to run one, which test markers to use, and how parallel builders stay off
each other's files. The interfaces themselves are in [CONTRACTS.md](CONTRACTS.md); this file is the
working procedure on top of them.

## Running engines (and any Python here)

Use one of two entry points. Both pick the right interpreter, put every engine folder on `sys.path`
in the same order as the test suite, run in isolated mode (`-I`: `PYTHONPATH`, `PYTHONHOME` and the
user site are ignored), and record the run in the event ledger.

```sh
python -m ctf run <engine> [args...]       # engine = id (toolkits.network), name (network), file
tools/ctfpy <engine> [args...]             # the same, without needing the venv on PATH
tools/ctfpy solvers/web/js_recon.py x.js   # a script, exactly like `python <script>`
tools/ctfpy -c 'import network; ...'       # a snippet; flat engine imports just work
tools/ctfpy -m ctf engines list            # a module
tools/ctfpy --info                         # which python, repo, sys.path and workdir are in use
```

- `tools/ctfpy` finds its interpreter in this order: `$CTF_PYTHON`, `<checkout>/.venv`, the main
  checkout's `.venv` (a fresh worktree has none). If none exists it exits 2 and says so.
- A fresh worktree has no `.venv`, so bare `.venv/bin/python` fails there. `python -m ctf worktree-venv`
  links the worktree's `.venv` to the master checkout's venv (found through git, or `--venv`/`$CTF_VENV`):
  the same pinned interpreter and packages, no editable install. Only the first source given is used
  (`--venv`, else `$CTF_VENV`, else the master's): an unusable one exits 2 and never falls through to
  the next. The root ignore file lists `.venv` with no trailing slash, because the link is a symlink and
  git sees it as a file; where no pattern covers it, the command first adds `.venv` to `info/exclude`,
  so the link is never committed. A worktree with its own real `.venv` is never touched; `--force` only
  replaces a link that points elsewhere. Run from a subdirectory, it links the checkout's top level; in
  the master checkout itself it says the `.venv` is the master venv and exits 0.
- Arguments pass straight through; there is no shell in between, so no zsh globbing or quoting
  surprises, and no `CTF_WORKDIR=... .venv/bin/python` prefix to type.
- `CTF_WORKDIR` is exported to the engine when it is unset but the current event (`CTF_EVENT`)
  resolves one, so carried engines that read it directly find it.
- Each engine run appends `{"event": "engine.run", "engine", "via", "exit_code", "seconds",
  "status"?, "challenge_id"?}` to `<workdir>/ledger.jsonl`. With no resolvable workdir the engine still
  runs and stderr says the run was not recorded and why. Turn recording off on purpose with
  `--no-ledger` or `CTF_ENGINE_LEDGER=0`. `python -m ctf engines usage` turns the records into
  real-use counts, including how many active engines never ran.
- What runs depends on the manifest entry: a carried CLI script (`cli:python <script>`, tag
  `legacy-output`) runs as `__main__`; a contract function (`module:function`) runs as
  `ctf run <id> <challenge_dir> [--opt key=value]... [--event slug]` and prints the `SolverResult`
  JSON; an import-only carried module (tag `library`) is refused with a message, not guessed at.

Existing import paths keep working: nothing was renamed, there is no editable install, and the
engine `sys.path` is the one `conftest.py` builds. On top of the flat imports, each engine is also
importable by its dotted path from the repo root — `solvers.<lane>.<module>` (e.g.
`import solvers.toolkits.memory_depth`). The five identifier-named lanes resolve through the `solvers`
namespace package; the three dash-named lanes (`script-analysis`, `metadata-forensics`,
`mobile-android`) resolve under their underscore spelling (`solvers.script_analysis`, ...) through a
`sys.meta_path` finder that `ctf/__init__.py` installs (see `ctf/solverpkg.py`). `solvers` has no
`__init__.py` on purpose — it stays a namespace package so the checkout's copy wins over any stray one
(SH-06) — so the dash-named lanes cannot be renamed and the finder is the alias layer. Two caveats: the
underscore names resolve only after `import ctf` (the suite and the runner always import it), and the
dotted and flat imports of one file are two separate module objects, so module-level state exists twice
when both forms are used in one process; pick one form per process for a module that keeps state.

## Adding an engine

1. **Module**: `solvers/<lane>/<engine>.py`. New engines implement the contract entry
   `solve(challenge_dir: Path, profile: EventProfile, **opts) -> SolverResult` (CONTRACTS.md 6-7).
   Use `ctf.flagfmt` to find flags, `ctf.paths` for locations, `ctf.env` for settings. Pick a basename
   no other engine uses: flat imports pick one file silently (lint `duplicate-basename`). The carried
   pairs that share a name are listed in `docs/coverage/duplicate-basenames.toml`; to use one of them
   from another folder, load the exact file (`from _shadowed import common_module`), never
   `import <name>` (lint `ambiguous-import`).
2. **Manifest**: `solvers/<lane>/<engine>.manifest.toml` beside it. Write it by hand, or run
   `python -m ctf engines generate` (it writes inferred manifests for every engine module without
   one, never overwrites an existing file, and gives a new engine a file route when its code tests for
   a distinctive format) and then correct what it inferred. Minimum:

   ```toml
   id = "crypto.rsa_small_e"                  # <lane>.<name>; a dashed lane folder becomes _ here
   lane = "crypto"
   entry = "solvers.crypto.rsa_small_e:solve" # dotted repo path; a dashed folder is fine here
   capabilities = ["executes", "rsa"]         # executes | analysis | plan | library, then topic tags
   needs_tools = ["py:gmpy2"]                 # same names as the needs_tool marker
   cost_class = "cheap"

   [[routes]]
   category = ["crypto"]
   keywords = ["small e", "cube root"]        # lower-case substrings of the description
   files = ["magic:-----BEGIN PUBLIC KEY", "ext:.pem", "name:*.pub"]
   priority = 65                              # always set it; lint treats a missing one as ambiguous
   ```

   A route matches when every condition it states holds (category AND a keyword AND a file).
   Prefer keyword or file routes over bare-category ones: a bare category route claims the whole
   category and needs a priority no other bare route in that category uses.
3. **Test**: `tests/test_<lane>_<engine>.py`, with fixtures built inside the test. Use the markers
   below for anything external.
4. **Check** before committing:

   ```sh
   python -m ctf engines lint                 # exit 1 on an error
   python -m ctf engines route crypto "an rsa key with small e"   # does it route where you meant?
   python -m ctf engines generate             # regenerate the route table, CAPABILITIES.md, ENGINES.md
   python -m ctf engines generate --check     # exit 1 when any of them is stale (writes nothing)
   ```

To have intake (`python -m ctf intake`, B-002) run the engine on every challenge's files with no
model, add an `[intake]` table: which files it takes (`match`, route matcher syntax), how they are
passed (`run = "per-file"` with `args` naming `{file}`, `all-files` with `{files}`, `folder` with
`{folder}`, or `challenge` for a module:function engine), and `select = "files"` to run on a file
match whatever the category (default `route`: only when the router routes the challenge here). Keep
it cheap (`cost_class = "cheap"`, a `timeout`), offline (intake denies engines the network), and set
`spawns = true` if it starts other programs. Test it: intake runs it on a synthetic file and its
output says what it found. Schema and rules: docs/CONTRACTS.md sections 6 and 19.

Routing lives only in the manifests (R-10). `ctf/triage.py` names no engine: `triage.suggest()` ranks
every engine whose route matches by its manifest priority, read from `ctf/engines/route_table.jsonl`,
which `generate` renders from the manifests. A manifest change reaches triage only after
`python -m ctf engines generate` (`tests/test_engines_routetable.py` fails until then). Priority bands
of the carried routes: category lists 49 and down, keyword nudges 60 and up, inferred file routes 30
and down; pick a priority that puts your engine where it belongs relative to those.
`python -m ctf engines generate --file-routes` appends an inferred file route to each unrouted engine
whose code tests for a distinctive format (ctf/engines/fileroutes.py says which formats count).

### Route lint

`python -m ctf engines lint` reports `schema`, `duplicate-id`, `orphan-manifest`,
`unmanifested-engine`, `missing-entry`, `no-route`, `match-all-route`, `route-conflict` (two engines
claim the same keyword, file matcher or bare category in overlapping categories, and a priority is
missing or equal), `duplicate-basename` (a shared basename not documented in
`docs/coverage/duplicate-basenames.toml`, or an entry there that no longer matches),
`stale-duplicate-doc` and `ambiguous-import` (a flat import of a shared basename from a folder that
does not win it) as errors; `unknown-category`, `id-lane` and `cli-tool-undeclared` as warnings.

`docs/coverage/lint-baseline.txt` lists the `no-route` errors the carried engines had when B-186
landed and the `ambiguous-import` errors R-10 found. Those are reported as `known`. The file only shrinks: when you route
one of them, run `python -m ctf engines lint --shrink-baseline` (the repo test fails on a baseline
line that no longer fires). Never add a line; give the new engine a route, or `status = "retired"`.

### Coverage matrix

`docs/coverage/ENGINES.md` is generated from the manifests and the test files (class, status, cost,
routed categories, needs, number of test files that reach each engine).
`tests/test_engines_coverage.py` fails when it is stale. It changes when an engine, a manifest or a
test that imports an engine changes, so regenerate it rather than merging it by hand.

## Test markers

From `ctf/testing/pytest_plugin.py` (CONTRACTS.md section 9):

| marker | use it when |
|---|---|
| `@pytest.mark.needs_tool("radare2", "py:cv2")` | the test needs a binary on PATH or an importable module |
| `@pytest.mark.needs_realdata` / `needs_realdata("sub")` | it reads the real-challenge corpus |
| `@pytest.mark.live` | it would touch a network service (never runs unless `--run-live`/`CTF_RUN_LIVE=1`) |
| `@pytest.mark.slow` | tag only; `-m "not slow"` deselects it |

A missing dependency is a skip with a named reason and shows in the `NOT RUN` summary, never a
pass. Do not `importorskip` inside a test body when a marker fits; never `if not available: return`.

Run tests from the checkout root with the shared venv:
`~/ctf-tools/.venv/bin/python -m pytest tests/test_x.py` (add `-n 4` for big runs).

Every `tests/test_*.py` is a pytest module: checks are asserts inside `test_*` functions, and a file
that can also run by hand does so only under `if __name__ == "__main__":` (the usual body is
`sys.exit(pytest.main([__file__, "-q"]))`). A file that calls `sys.exit()` or raises `SystemExit` at
import aborts the whole session at collection (INTERNALERROR on every worker, nothing runs);
`tests/test_suite_tools.py` fails if one appears, and `tools/suite.py` refuses to start, naming it.
Do not hide a file with `collect_ignore`. `tests/real/` is the one folder collected differently
(its conftest runs each Huntress script in a child process; CONTRACTS.md section 9). Put tests in
`tests/`: pytest.ini sets `testpaths = tests`, so a `test_*.py` or `selftest*.py` elsewhere never runs
unless a test under `tests/` runs or imports it, and `python -m ctf integrity collected` flags it (`stray`).

`ctf gate run` is strict about tests that did not run (B-196): a green file with a `needs_tool`,
`needs_realdata` or plain skip is `NOTRUN` (red). `live`, `xfail` and `known-fail` are accepted
(`tests/gate.toml` `not_run_ok`). Measured from the merge queue's full-suite junit of 2026-11-12 on the
build machine, a strict `--full` run marks 41 files NOTRUN: 33 with a plain skip (mostly opt-ins such as
`CTF_REAL_CHALLENGES` unset or `CTF_DOCKER_VERIFY` off), 4 `needs_tool`, 4 `needs_realdata`. A builder
checking only its own item passes, by name, the kinds it cannot satisfy and says so in its report:
`ctf gate run --allow-not-run needs_tool --allow-not-run needs_realdata` (add `--allow-not-run skip` only
for an opt-in skip it has read). Avoid `--allow-not-run any`; the summary still counts what did not run
(`notrun=N`). A run that allowed a kind never stores a warm result for a file that did not fully run, so
a later strict run re-runs it.

## Running the full suite

The bare `~/ctf-tools/.venv/bin/python -m pytest` collects and runs everything (pytest.ini adds
`--continue-on-collection-errors`, so a file whose optional package is missing is one error, not a
stopped run). For a run you will compare or report, use the runner, which is the recipe recorded in
`docs/migration/BASELINE.md`:

```sh
.venv/bin/python tools/suite.py [--junit PATH] [-n N] [--no-sandbox] [-- PYTEST_ARGS...]
```

- macOS `sandbox-exec` with the committed profile `tools/suite.sb`: outbound network is denied
  except loopback, so a test reaches only the fake services it starts on 127.0.0.1. Without
  sandbox-exec (not macOS) it exits 2 and asks for `--no-sandbox`. Seatbelt does not nest: inside
  another sandbox-exec, pass `--no-sandbox` (the outer sandbox still applies).
- `-n 8` xdist workers by default (`-n 0` for one process), `--timeout 300`, `-p no:cacheprovider`,
  `--continue-on-collection-errors`, `-q -rfE`, junit XML to PATH (default a timestamped file in the
  temp folder; the path is printed at the end). Arguments after `--` go to pytest.
- Exit status is pytest's; 2 when it refuses to start (an import-time exit in a test file, no
  sandbox-exec, the profile or a pytest plugin missing).
- The pytest interpreter (B-153, `ctf.pyinterp`): `--python PATH`, else `$CTF_PYTHON`, else the
  checkout's `.venv`, else the main checkout's `.venv` (a linked worktree has none), else the one
  running the script; the choice is printed first. So `python3 tools/suite.py` in a fresh worktree runs
  pytest with the main checkout's venv. `ctf gate` resolves its pytest children the same way.

Compare two runs test by test:

```sh
.venv/bin/python tools/junit_diff.py OLD.xml NEW.xml [--rerun-root CHECKOUT] [--rerun 3]
    [--known-flaky FILE] [--baseline tests/gate_baseline.toml] [--no-sandbox] [--json OUT.json]
    [--fail-on-regression]
```

`--baseline` reads the tracked baseline ledger (B-153): tests it lists that went bad are reported as
`BASELINE <key> (<kind> since <date>: <reason>)`, apart from the newly bad ones. Add an entry with
`python -m ctf gate baseline add <node id> --kind flaky|env|stale|broken --reason "..."`; remove it in
the commit that fixes the test.

Quick and full gates (B-153): `python -m ctf gate run --lane L` is the builder's check and must fit in
five minutes (`[budget]` in `tests/gate.toml`; exit 3 over it, `python -m ctf gate budget` lists every
lane's estimate). `ctf/` and `solvers/toolkits/` are split into several lanes so each fits; the hubs
nearly every test imports (`ctf/__init__.py`, `paths`, `env`, `event`, `flagfmt`, the cli package) are in
no lane, so a change to one is gated with `--base` and the full gate (`python -m ctf gate budget` names
every test file in no lane). `[budget] full_only` files never run
in a lane gate; every lane run names them. `python -m ctf gate prearm` is the separate pre-arm gate: preflight (interpreter,
clean tree, baseline ledger, loopback bind, the generated-file checks and the guard lint), then a full
index-free run in which an ENV file fails. Tests that start a fake service use the `loopback` fixture
(`ctf/testing/loopback.py`), so a sandbox-denied bind reads as ENV, not as a failure.

It prints both runs' status counts and the tests that are newly failing or erroring (`NEW BAD`),
fixed, added and removed. With `--rerun-root`, each newly bad test is re-run alone `--rerun` times in
that checkout under the same sandbox and classified `regression` (failed every time), `passes_alone`
(flaky or load-dependent: judge it) or `unresolved` (its node id could not be rebuilt, or it neither
passed nor failed). `--known-flaky` lists junit keys (`<classname>::<name>`, one per line) to report
apart. It exits 0 (1 with `--fail-on-regression` while a newly bad test is not `passes_alone`), 2 on
a missing or unreadable input.

Test ids must be the same in every process: xdist aborts a run with "Different tests were collected
between gwN and gwM" when workers disagree. Build values that carry the clock (gzip and zip bytes,
dates) or a hash order (sets) at test time, pin them (`gzip.compress(..., mtime=0)`, `ZipInfo(name,
date_time=...)`, `sorted(...)`), or pass `ids=`. Check a file or the tree (`tests/test_collect_ids_stable.py`
holds the whole tree to it):

```sh
.venv/bin/python -m ctf.testing.collect_ids tests/test_x.py   # or: tests
```

It collects twice, the second time with the clock 400 days ahead and another hash seed, and exits 0
(identical ids and collection errors), 1 (prints the diff) or 2 (a collection failed to run).

## Parallel builders: staying off shared files

Every registry is a directory, so adding things means adding files:

| to add | add this file | do not edit |
|---|---|---|
| an engine | `solvers/<lane>/<name>.py` + `<name>.manifest.toml` + `tests/test_<lane>_<name>.py` | `ctf/triage.py`, `docs/CAPABILITIES.md`, `ctf/engines/route_table.jsonl` (regenerate them) |
| a CLI command | `ctf/cli/<name>.py` (`HELP`, `add_arguments`, `run`) + a test | `ctf/cli/__init__.py` |
| a platform kind | `ctf/platform/<kind>.py` | adapters of other kinds |
| a submit check | a function registered with `gate.add_check(fn)` | `ctf/platform/policy.py` |
| an event | `events/<slug>/event.toml` | other events' folders |
| a build record | `docs/build-log/<item>.md` | other items' logs |

Generated files (`ctf/engines/route_table.jsonl`, `docs/CAPABILITIES.md`, `docs/coverage/ENGINES.md`)
are never merged by hand: after merging branches, run `python -m ctf engines generate` and
`python -m ctf engines lint`. They change whenever any branch adds an engine, edits a manifest or a
route, or changes the first sentence of an engine's docstring, so two branches that each regenerated
still leave a stale merge: whoever merges (a builder merging the base branch, the merge queue after
each merge) regenerates and commits the result; on a conflict in one of them, take either side and
regenerate. `python -m ctf engines generate --check` exits 1 until then. The lint baseline is the one shared file a builder may need to touch,
and only to delete lines (`--shrink-baseline`), so concurrent edits are deletions that merge cleanly.

When a shared file must change anyway, keep the edit minimal, isolated (append rather than reorder)
and list it in your build log.

### One worktree per builder, one integrator (B-147)

`ctf worktree` and `ctf integrate` are the two halves (`ctf/worktree.py`; the contract is the
`worktree` and `integrate` rows of the command table in [CONTRACTS.md](CONTRACTS.md)).

```sh
python -m ctf worktree create B-147 ../wt-B-147      # before the builder starts: branch item/B-147
python -m ctf worktree list
git config ctftools.integrationBranch <branch>       # once per repo (or --integration-branch / $CTF_INTEGRATION_BRANCH)
python -m ctf integrate plan --items to_build.json   # the merge order; changes nothing
python -m ctf integrate run  --items to_build.json [--keep-going]
```

- A builder commits only in its own worktree (`ctf worktree-commit`), after
  `python -m ctf worktree-venv` if it needs the venv there.
- `integrate run` is run in the integration checkout, on the integration branch, with a clean tree.
  It merges the `item/<id>` branches in BUILD-PLAN dependency order, each as one merge commit that
  also carries the regenerated files, then runs `ctf gate run --base <the commit before the merge>`.
  A step that fails (conflict, regeneration, red gate) is rolled back, so the branch only ever holds
  green merges; `--keep-going` then continues with the items that do not depend on the failed one.
  A branch that is already in the integration branch is reported `already-merged` and left alone.
- An item whose dependency is not in the queue but has a local `item/<dep>` branch that is not
  merged yet is `skipped`, naming the dependency: queue the dependency too, or merge it first. A
  dependency with no local branch (merged long ago, or never built) does not hold its dependent.
- Ctrl-C during a step rolls that step back before the interrupt propagates. If the integrator is
  killed outright mid-step, its merge is still on the branch and never passed the gate: the next
  `integrate run` exits 2 naming it and the commit to `git reset --hard` to, then runs normally.
- The gate must not write into the checkout (ignored paths are fine). If a failed step leaves an
  untracked file behind, the queue stops and names it: remove it and run again.
- `integrate guard` refuses a hand commit on the integration branch, a hand merge included. It is
  opt-in: it does nothing until a checkout's hooks call `python -m ctf integrate guard`, and this
  repo's `.githooks` do not call it. Wire it into both `pre-commit` (every `git commit`, concluding
  a merge included) and `pre-merge-commit` (a merge commit `git merge` makes on its own). git runs
  no hook for a fast-forward merge, `git reset` or `git branch -f`, so the guard cannot refuse
  those. Do not wire it while a merge process still commits to the integration branch by hand
  (suite logs, integration fixes): those commits would be refused.
- `ctf lanes integrate` ([lanes.md](lanes.md)) is the Codex-lane counterpart: it audits lane results
  (file ownership, collisions, CAPABILITIES bullets) and with `--merge` merges the clean lane
  branches in dependency order, but it does not regenerate the generated files or run a gate.
  `ctf integrate run` is the queue that does both, for any local item branches.

### Register before spawn, claim files and folds, take the idle lock for timing (B-213)

`ctf work` keeps one registry for every worktree of the repo (under the git common dir; section 68 of
[CONTRACTS.md](CONTRACTS.md)). Whoever spawns a builder, Claude, Codex or a person, registers it first:

```sh
python -m ctf work start item/B-213 --harness claude --worktree ../wt-B-213 \
    --row B-213 --file ctf/workreg.py --file 'tests/test_workreg*.py' --fold csctf:fork:tools/unpack.py
python -m ctf work list                    # who is working: harness, branch, pid, rows, claims, stale ones
python -m ctf work check --file solvers/dex/   # would this clash? (read-only, exit 1 naming the owner)
python -m ctf work leave item/B-213        # done: frees its claims
python -m ctf work idle-run -- .venv/bin/python -m pytest tests/test_timing.py   # a timing suite
python -m ctf work idle-run --shared -- <heavy build>                           # timing suites wait for it
```

`ctf worktree create B-213 ../wt-B-213 --harness claude --file ctf/workreg.py ...` does the `start` and the
worktree in one step (nothing is created on a clash), and `ctf integrate run` makes the agents of every
branch it merged leave the registry, so a builder made and merged that way needs no `start` or `leave` of
its own.

- `start` registers nothing when anything clashes (another live agent's row, file, fold, branch or
  worktree) and names every clash; spawn only on exit 0. Rows are B-138 backlog rows, so a done or
  unknown row is refused. A directory claim ends in `/`; globs are exact (`ctf/*.py` does not clash with
  `ctf/*.md`).
- A record goes stale when its `--pid` dies, its `--ttl` lapses without `ctf work heartbeat`, or its
  `--worktree` is removed; stale claims stop blocking and are reaped on the next change. The registry
  never stops a process.
- `ctf gate run --idle-lock` and `ctf adapt gate --idle-lock` take the idle lock themselves; set
  `CTF_IDLE_LOCK=1` to make that the default on a build night, `--no-idle-lock` for one run.
