# Roadmap

What is released, what comes next, what is still open, and how the first release was built.
[CHANGELOG.md](../CHANGELOG.md) says what each release changed for players.

## Released: 0.2.0, a model per small job (2026-11-12)

Each job was measured before it was built ([MODELS.md](MODELS.md)). The light model does small
jobs for a run, and the rules come first in every one:

- **judge**: the hint judge of 0.1.0. When the rules raise an "ignores the hint" alert, the light
  model may take it down.
- **route**: at a lane's start, a guess at the challenge's category where the board names none,
  and the specialist family it suits, which is the kind of specialist the challenge calls for (ten
  kinds, such as audio signals, image steganography, modern cryptography or web requests).
  Whether a challenge needs a live instance stays a rule.
- **recon**: a first look at the handout, added to a lane's opening brief as a fenced data
  section.
- **flagcheck**: a check on a flag before it is submitted without you. It can only hold an
  auto-submit, never cause one.

`[light] jobs` lists the jobs a run gives the light model, and a `[light.<job>]` table gives a
job an engine of its own. `flightdeck eval-local` scores each job the way a run uses it.

With it: model advice for a machine you describe and a guide by memory, and the fixes that a
rehearsal against a real CTFd, a security review and the first pricing issue asked for.

## Released: 0.1.0, the first public release (2026-11-11)

M0 to M4 built (below), docs and a quickstart, the MIT license, the secret scan
(`.githooks/secret_scan.py --all`) clean in CI, and a screenshot gallery
([SCREENSHOTS.md](SCREENSHOTS.md)).

**Easy to run: people won't use it if it's hard.** A new player gets from nothing to a running
console in a few minutes, without reading the architecture:

- One-line install or no install: `pip install ctf-flightdeck` (in a virtual environment),
  `pipx install ctf-flightdeck` or `uv tool install ctf-flightdeck`, or `uvx ctf-flightdeck mock` to
  try it; each tested from the built wheel in a clean environment; on PyPI since 2026-11-11.
  Python 3.12+; macOS and Linux (Windows through WSL).
- `flightdeck` with no setup offers the next step instead of an error; `flightdeck init` asks a few
  questions (provider, models, Docker or host) and writes the config; `flightdeck doctor` checks
  Python, Docker, the lane image, the key variable and the config, and says how to fix each problem.
- The mock and the practice set ship inside the package: `flightdeck mock` and `flightdeck practice`
  work right after installing, with no clone.
- A lane image that works out of the box, built only by a command the player runs.
- A quickstart at the top of the README, tested on a clean machine.

## Next: M5, Autopilot

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
- **Headless, and a way to reach you.** Built ahead of the rest of M5: `play --headless` runs
  without the console by the same rules (an approval waits, nothing is approved) and stops on
  SIGTERM as quitting does; every run writes `status.json`; an opt-in webhook is told when a flag
  is accepted, a lane needs you, or the queue is held or autopilot disengages, and never gets a
  flag ([the guide](GUIDE.md#headless-runs-and-notifications)). Still open: a phone push, and
  approving from the phone (Later: phone control).

## Still open from M0 to M4

Planned in a milestone and not built:

- **ACP agents.** The coding-agent lanes are the `claude` and `codex` CLIs only.
- **A real capture of the `claude` and `codex` streams.** The driver is tested against a fake CLI
  built from their docs, and so is a coding-agent lane's fenced network (below): it has not been
  run with the real CLIs.
- **Timeline replay in `play`.** Releasing a board wave by wave from its `timeline.json` is built
  and tested, but `play` releases the whole board at the start. Scoring a past run against the
  board's answers works (`flightdeck score`).

Built since (2026-11-12, issue #14): **the per-origin egress allowlist.** A Docker lane that may
reach its instance reaches only the hosts and ports its challenge's `urls` name, and a
coding-agent lane its CLI's API, through an internal Docker network and a proxy per host; it is
never on the bridge network (P9; the guide's [Docker or host](GUIDE.md#docker-or-host)). That is
the guardrail Autopilot needs: nothing reached but a challenge's own instance.

## Later (not scheduled)

- **Phone control.** Today: run flightdeck in tmux and attach over SSH (the console has a compact
  layout from 64 columns down). Option: serve the same console in a browser (textual-serve);
  touches D4 and must be locked down. Best: push a notification when a lane needs you, with approve and decline from the
  phone; needs its own sign-in and permission design.
- **Nerd Font look.** Opt-in powerline glyphs for truly slanted header segments and rounded chip ends
  in terminals that draw them; plain Unicode stays the default.
- **Installs beyond PyPI.** Built, and first used by the release after 0.2.0: the release
  workflow builds a `.deb` for amd64 and arm64 that brings its own Python (Debian 12 has 3.11),
  installs each in a clean Debian 12 container and attaches them to the GitHub release, and it
  writes the Homebrew formula (`brew install mfisher14/tap/ctf-flightdeck`) to the tap
  (`packaging/`, and Releases in [CONTRIBUTING.md](../CONTRIBUTING.md)). The tap repository and
  its token are the maintainer's to create, and no `brew install` of the formula has been run
  yet. Left: a signed apt repository, so `apt upgrade` finds a new release. Homebrew's own
  repository and Debian's archives once the project is notable enough for them.
- **A host sandbox without Docker.** Strands Box (Apache-2.0: OS isolation with deny-by-default
  policies, an egress gateway and credentials injected outside the agent) could make `--host` lanes
  safe. Watch it: in November 2026 it was a preview for Apple silicon and Linux ARM64 only, with no
  Linux x86-64.

## Done: M0 to M4

The milestones behind 0.1.0, as they were planned and what each left open. What they built, as a
player sees it, is under 0.1.0 in [CHANGELOG.md](../CHANGELOG.md).

### M0: clickable mock

A Textual console with **fake, scripted data**: no models, no network, no real challenges.

- `uv run flightdeck mock` opens the console with the scenarios in `CONSOLE-SPEC.md`.
- Fake lanes tick over time (turns, tokens, dollars, actions) so it feels live.
- Every intervention key does something visible to the fake lane.
- Every alert type from the spec fires at least once.
- 43-challenge wave with `max_lanes` 16 is usable (scrolling, attention sort, queue).
- `flightdeck mock --screenshot DIR` saves SVG screenshots of key states for review.
- Tests: Textual pilot tests that keys change lane state and that attention sort orders alerts first.

**Exit (met):** layout and controls agreed on the mock and recorded in DECISIONS.md (D16).

### M1: thin working slice

Phase 1 agent model (D5a): flightdeck's own loop against an OpenAI-compatible endpoint (OpenRouter).

- Manual adapter: point at a folder of challenge dirs (handout files + `challenge.json`).
- Lean agent loop per lane: fresh context per challenge, small prefix (target under 6K tokens),
  few tools (shell, read file, http, python, submit-candidate), tool output truncated with overflow
  written to a file, per-call budget meter.
- Lanes run in Docker or on the host per `[lanes] runtime` (D9); `max_lanes` with a queue (D8).
- Console from M0 wired to real lanes: pause, hint, redirect, fork, kill, take over.
- Quick answers (deferred from M0): the needs-you card and the fleet's why line number their
  options (an approval: `1` approve, `0` decline; otherwise the alert's suggestions, numbered from
  `1`) and one key answers, no Enter (in the focus view only while the chat box is empty). A
  decline for candidate flags, live-box and budget requests, so "no" does not mean killing the
  lane.
- Per-lane tokens and turns, dollars with API pricing; per-lane caps that stop the lane.
- Append-only event log (JSONL) per run.
- OpenRouter: send a stable `session_id` per lane for sticky prompt caching; do not set
  `provider.order` (it disables sticky routing). Record cache hits reported by the API.
- Practice set: 10 to 20 synthetic or freely licensed challenges to run the slice on.

**Exit (met):** the practice set plays end to end through the console.

### M2: bring what you have

- External agent drivers: `claude` and `codex` CLIs as subprocess lanes; evaluate ACP for others.
- L1 plugin contract (`SolverResult`) and runner; script importer that wraps a folder of scripts with a
  generated manifest (no rewriting of user code); every engine run sandboxed.
- CTFd adapter (fixtures and a local CTFd only during development).
- Pre-flight: event profile + rules → stage policies (auto/confirm/manual/off); egress allowlist.
- Team mode: claims, teammate-solved stop, live-box courtesy.

Not done in M2: evaluating ACP, the per-origin egress allowlist and a real capture of the CLI
streams (under "Still open" above; the egress allowlist was built later, issue #14).

### M3: detectors and practice

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
  with tool calling (`mlx_lm.server` passes tool calls for Qwen3.5 9B and Gemma 4 12B, not for
  gpt-oss 20B or Phi-4-mini: [MODELS.md](MODELS.md)), and a doctor check that the server answers.
- Practice mode: replay an archived board offline, scored against an answers file kept outside the
  handout.

How M3 came out: the light model (`[light]`, P15) runs the hint judge once one is set, on any of
four model engines (`openai`, `anthropic`, `cactus` for Cactus Needle, `decider`); with `rules`,
the default, there is no judge. In a first trial Needle did no better than keyword rules, so
nothing uses it unless you choose it. MLX lanes have run on a real MLX server, in the benchmark
behind the local models `init` suggests. Of practice mode, scoring is built; the replay is under
"Still open" above.

### M4: post-flight and build

- Post-flight timeline: where lanes stalled, where an intervention helped, cost per solve.
- Gap report: which challenges no L1 solver reached and why.
- Writeup drafts.
- Build mode: turn gaps into solvers; a solver is done only when a test shows a raw handout reaches it
  through the router.
