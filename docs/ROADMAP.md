# Roadmap

## M0: clickable mock (built)

A Textual console with **fake, scripted data**: no models, no network, no real challenges.

- `uv run flightdeck mock` opens the console with the scenarios in `CONSOLE-SPEC.md`.
- Fake lanes tick over time (turns, tokens, dollars, actions) so it feels live.
- Every intervention key does something visible to the fake lane.
- Every alert type from the spec fires at least once.
- 43-challenge wave with `max_lanes` 16 is usable (scrolling, attention sort, queue).
- `flightdeck mock --screenshot DIR` saves SVG screenshots of key states for review.
- Tests: Textual pilot tests that keys change lane state and that attention sort orders alerts first.

**Exit:** the player reviews the mock and signs off on layout and controls (changes go in DECISIONS.md).

## M1: thin working slice (built)

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

## M2: bring what you have (built)

- External agent drivers: `claude` and `codex` CLIs as subprocess lanes; evaluate ACP for others.
- L1 plugin contract (`SolverResult`) and runner; script importer that wraps a folder of scripts with a
  generated manifest (no rewriting of user code); every engine run sandboxed.
- CTFd adapter (fixtures and a local CTFd only during development).
- Pre-flight: event profile + rules → stage policies (auto/confirm/manual/off); egress allowlist.
- Team mode: claims, teammate-solved stop, live-box courtesy.

Not done in M2: evaluating ACP for other agents; a per-origin egress allowlist (a docker lane gets
no network, or the open bridge network once its instance is allowed); a real capture of the
`claude` and `codex` streams (the driver is tested against a fake CLI built from their docs).

## M3: detectors and practice (built)

- Real detectors for every alert in the spec (rules first; an optional cheap-model judge for
  "ignores the hint").
- Escalation with a compact state summary.
- Optional local model role (D15): evaluate Cactus and an OpenAI-compatible local server (Ollama,
  llama.cpp or MLX) on triage hints, the "ignores the hint" detector and lane summaries. Measure
  accuracy against rules-only before enabling by default.
- Cactus Needle (Apache-2.0/MIT; a 14-30 MB tool-calling model that runs on the CPU in
  milliseconds): an adapter in this repo plus an optional extra, `pip install
  ctf-flightdeck[cactus]` (pinned versions; their package fetches its engine and weights on first
  use; nothing of theirs bundled here); its anonymous telemetry switched off by default
  (NEEDLE_TELEMETRY=0, DO_NOT_TRACK=1, CACTUS_TELEMETRY=0). Jobs: which technique or L1 engine fits
  a challenge, whether a lane follows the hint, a typed or spoken command to an intervention.
  Needle does not run on MLX (a custom architecture) and does not need to at its size.
- MLX for lanes: `flightdeck init --provider mlx` for a local MLX server that speaks the OpenAI API
  with tool calling (lanes need tools; `mlx_lm.server`'s tool support is unclear, vllm-mlx and
  mlx-openai-server document it), and a doctor check that the server answers.
- Practice mode: replay an archived board offline, scored against an answers file kept outside the
  handout.

Not done in M3: Needle is an adapter only (one job: which of a few named options fits a text), not
wired into runs, because the spike found it no better than keyword rules; the hint judge is built
but not switched on in runs (it would spend tokens); MLX lanes are untested against a real MLX
server (init and doctor support it). Since M3, the light role (`[light]`, P15) runs the hint judge
in a run once a light model is set, on any of its four model engines (`openai`, `anthropic`,
`cactus` for Cactus Needle, or `decider`); `rules`, the default, sets no model, and with it there
is no judge. MLX lanes have since run on a real MLX server, in the benchmark behind the local
models `flightdeck init` suggests.

## M4: post-flight and build (built)

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
- **A host sandbox without Docker.** Strands Box (Apache-2.0: OS isolation with deny-by-default
  policies, an egress gateway and credentials injected outside the agent) could make `--host` lanes
  safe. Watch it: in November 2026 it was a preview for Apple silicon and Linux ARM64 only, with no
  Linux x86-64.

## v0.1.0: go public (released 2026-11-11)

M0 to M4 built (M5, Autopilot, comes after v0.1.0: below), docs and quickstart, secret scan
`--all` clean, history reviewed, MIT license, a recorded demo.

**Easy to run (the player's requirement: people won't use it if it's hard).** A new player gets from
nothing to a running console in a few minutes, without reading the architecture:

- One-line install or no install: `pip install ctf-flightdeck` (in a virtual environment),
  `pipx install ctf-flightdeck` or `uv tool install ctf-flightdeck`, or `uvx ctf-flightdeck mock` to try
  it; each tested from the built wheel in a clean environment (publishing to PyPI is the player's
  call at release time). Python 3.12+; macOS and Linux (Windows through WSL).
- `flightdeck` with no setup offers the next step instead of an error; `flightdeck init` asks a few
  questions (provider, models, Docker or host) and writes the config; `flightdeck doctor` checks
  Python, Docker, the lane image, the key variable and the config, and says how to fix each problem.
- The mock and the practice set ship inside the package: `flightdeck mock` and `flightdeck practice`
  work right after installing, with no clone.
- A lane image that works out of the box, built or pulled only by a command the player runs.
- A three-command quickstart at the top of the README, tested on a clean machine.

## 0.2.0: a model per small job

Measured per job before it was built (docs/MODELS.md): a light engine per job in the config,
a flag check that can only hold an auto-submit (never cause one), routing at lane start (the
instance by rule, a category guess only where the board names none, the specialist family),
and a recon brief as a fenced data section of a lane's opening brief. eval-local scores each
job the way a run uses it.

## M5: Autopilot (after v0.1.0)

Engage autopilot and flightdeck runs the event end to end while you are away; take the controls
back at any time (D20). A sketch, decided in detail when M5 starts:

- **Every stage as automatic as the event's rules allow.** Pull, L1, agents, submit and live
  instances at `auto` where the profile permits, never looser. Flags a lane claims are submitted;
  everything else waits.
- **Scheduled.** Start at the event's start time, pull new waves on a timer, stop at the end. When
  the queue runs dry, unsolved challenges go round again on the next model up, within the budget.
- **Interventions by rule.** A stalled lane escalates one rung, a lane that gave up is forked onto
  another model, a looping lane is killed, a lane that ignores the hint is redirected to it. Code
  decides (D15); a light model may confirm.
- **Guardrails.** A run budget (dollars and tokens) is required to engage; at the budget no new lane
  starts. No guessed flags, no last try spent, no refused request rerouted, nothing reached but a
  challenge's own instance.
- **Disengage.** Budget reached, the platform locking out or failing, the model API failing for every
  lane, a challenge down to its last try, a human check (a CAPTCHA): autopilot holds the queue, raises
  an alert and logs why, for the post-flight report.
- **Headless, and a way to reach you.** Run without the console (a status file to start with); an
  opt-in notification (webhook or phone push) when a flag lands or autopilot disengages.
