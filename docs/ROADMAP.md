# Roadmap

## M0: clickable mock (now)

A Textual console with **fake, scripted data**: no models, no network, no real challenges.

- `uv run flightdeck mock` opens the console with the scenarios in `CONSOLE-SPEC.md`.
- Fake lanes tick over time (turns, tokens, dollars, actions) so it feels live.
- Every intervention key does something visible to the fake lane.
- Every alert type from the spec fires at least once.
- 43-challenge wave with `max_lanes` 16 is usable (scrolling, attention sort, queue).
- `flightdeck mock --screenshot DIR` saves SVG screenshots of key states for review.
- Tests: Textual pilot tests that keys change lane state and that attention sort orders alerts first.

**Exit:** the player reviews the mock and signs off on layout and controls (changes go in DECISIONS.md).

## M1: thin working slice

Phase 1 agent model (D5a): flightdeck's own loop against an OpenAI-compatible endpoint (OpenRouter).

- Manual adapter: point at a folder of challenge dirs (handout files + `challenge.json`).
- Lean agent loop per lane: fresh context per challenge, small prefix (target under 6K tokens),
  few tools (shell, read file, http, python, submit-candidate), tool output truncated with overflow
  written to a file, per-call budget meter.
- Lanes run in Docker or on the host per `containerized` (D9); `max_lanes` with a queue (D8).
- Console from M0 wired to real lanes: pause, hint, redirect, fork, kill, take over.
- Quick answers (parked at the M0 review): the needs-you card and the fleet's why line number their
  options (`1` approve, `2`… the suggestions, `0` decline) and one key answers, no Enter (in the
  focus view only while the chat box is empty). A decline for candidate flags, live-box and budget
  requests, so "no" does not mean killing the lane.
- Per-lane tokens and turns, dollars with API pricing; per-lane caps that stop the lane.
- Append-only event log (JSONL) per run.
- OpenRouter: send a stable `session_id` per lane for sticky prompt caching; do not set
  `provider.order` (it disables sticky routing). Record cache hits reported by the API.
- Practice set: 10 to 20 synthetic or freely licensed challenges to run the slice on.

**Exit:** the player plays the practice set through the console and it feels right.

## M2: bring what you have

- External agent drivers: `claude` and `codex` CLIs as subprocess lanes; evaluate ACP for others.
- L1 plugin contract (`SolverResult`) and runner; script importer that wraps a folder of scripts with a
  generated manifest (no rewriting of user code); every engine run sandboxed.
- CTFd adapter (fixtures and a local CTFd only during development).
- Pre-flight: event profile + rules → stage policies (auto/confirm/manual/off); egress allowlist.
- Team mode: claims, teammate-solved stop, live-box courtesy.

## M3: detectors and practice

- Real detectors for every alert in the spec (rules first; an optional cheap-model judge for
  "ignores the hint").
- Escalation with a compact state summary.
- Optional local model role (D15): evaluate Cactus and an OpenAI-compatible local server (Ollama,
  llama.cpp or MLX) on triage hints, the "ignores the hint" detector and lane summaries. Measure
  accuracy against rules-only before enabling by default.
- Practice mode: replay an archived board offline, scored against an answers file kept outside the
  handout.

## M4: post-flight and build

- Post-flight timeline: where lanes stalled, where an intervention helped, cost per solve.
- Gap report: which challenges no L1 solver reached and why.
- Writeup drafts.
- Build mode: turn gaps into solvers; a solver is done only when a test shows a raw handout reaches it
  through the router.

## Later (parked at the M0 review, not scheduled)

- **Phone control.** Today: run flightdeck in tmux and attach over SSH (needs a compact layout for
  50–60 columns). Option: serve the same console in a browser (textual-serve); touches D4 and must be
  locked down. Best: push a notification when a lane needs you, with approve and decline from the
  phone; needs its own sign-in and permission design.
- **Nerd Font look.** Opt-in powerline glyphs for truly slanted header segments and rounded chip ends
  in terminals that draw them; plain Unicode stays the default.
- Batch approve (several waiting flags at once), dismissing an alert without intervening.

## v0.1.0: go public

M0 to M2 done, docs and quickstart, secret scan `--all` clean, history reviewed, MIT license, a
recorded demo.
