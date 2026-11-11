# Changelog

What changed for players, newest first. Milestones are in [docs/ROADMAP.md](docs/ROADMAP.md).

## Unreleased

### Model APIs

- The Anthropic API for flightdeck's own lanes: `flightdeck init --provider anthropic` (Claude
  Haiku, Sonnet and Opus 5.5 with their prices), with OpenRouter offered as a fallback when
  `OPENROUTER_API_KEY` is set: a lane whose calls keep failing moves there for the rest of its
  context and says so. Any config can name a `[fallback]` API; `flightdeck doctor` checks its key.

### The console

- Closing the terminal, an SSH drop or a SIGTERM during a run now stops every lane and closes
  every workspace, as quitting does (before, lane commands, containers and paused agent CLIs
  kept running); `play` exits with 128 plus the signal's number.
- `q` while lanes are open asks first and says what quitting stops; `y` quits, `n` or `esc` stays.
  On the way out, `play` names any flag that was still waiting for your approval.
- The key line always shows `? help` and `q quit`, and keeps approve, decline and the commands on
  a narrow terminal.
- Help and the `/` menu say what take-over and decline do in a run; `flightdeck config` says "no
  dollar cap" instead of "$no cap".

### M4: after a run

- `flightdeck report RUN_DIR`: the post-flight report (where lanes stalled, which of your
  interventions helped, cost per solve), written to `report.md` in the run folder.
- `flightdeck writeups RUN_DIR`: a writeup draft per solved challenge from its lane's transcript
  (`--redact` hides the flags).
- `flightdeck gaps RUN_DIR`: the challenges no L1 solver solved, and why; with `--pack`, which of
  your engines would reach them now.
- Build mode: `flightdeck build gap CHALLENGE_DIR --pack PACK` writes a new engine stub, its
  manifest and a test that passes only when a raw handout reaches the engine and it finds the
  flag (kept as a hash); `flightdeck build check PACK` runs those tests (`[build]` extra).

### M3: detectors and practice

- The course alerts are real now: effort against a challenge's points and solves, ignoring the
  description's hint, the wrong direction on web, loops and stalls. An alert you just answered
  stays quiet for a few turns.
- Escalation and the long-context refresh hand the model a compact summary of the lane: its
  plan, newest steps, files, flags and what became of them, alerts and your messages.
- A flag the platform rejected, or that you declined, is never asked about or submitted again on
  that challenge, by any lane, and an escalated model hears about it.
- Practice mode: `flightdeck score RUN_DIR` scores a past run against the board's answers, and a
  run on a board with answers ends with that scorecard.
- `flightdeck eval-local`: measure a local model (Ollama, an MLX server) against the rules on
  small jobs before trusting it. Cactus Needle, a small on-device model, is an optional extra
  (`pip install "ctf-flightdeck[cactus]"`) with its telemetry turned off; nothing uses it unless
  you ask.

### M2: bring what you have

- L1 solver packs: your no-model solvers, each with a small manifest saying which challenges it
  fits (`flightdeck l1 import` writes them for a folder of scripts, without changing the scripts).
  With `[l1] pack` in the config (or `--pack`), a lane runs the engines routed to its challenge
  before its first model call; a flag one finds waits for your approval, so a solve can cost no
  tokens at all.
- `flightdeck preflight event.toml`: what an event's rules allow, and how far flightdeck goes on
  its own at each stage (pull, L1, agents, submit, live instance).
- The live instance policy: under `confirm` a lane asks before it may reach its challenge's
  instance, and until you say yes its container has no network.
- `flightdeck play FOLDER --event event.toml`: play an event by its rules. A CTFd board is pulled
  into the folder, new waves are added as they appear, the flags you approve are submitted
  through CTFd, and your team's solves stop your lanes on those challenges. The token comes from
  the environment variable the profile names and goes only to that CTFd.
- Team mode: `flightdeck team init DIR`, then `--team-dir DIR`: teammates share claims,
  live-box holds and solves through a synced folder.
- `--agent claude` or `--agent codex`: lanes are that coding-agent CLI, with its own login and
  models (`[agents]` in the config), behind the same controls; `flightdeck doctor --agent claude`
  checks it first.

### Easier to start

- `flightdeck` on its own says what it is and the next step on your machine; a missing config
  points at `flightdeck init`; a path under a `~user` that does not exist is a message, not a
  traceback.

### M1: a working slice

- `flightdeck play BOARD`: agent lanes play a folder of challenges against an OpenAI-compatible API
  (OpenRouter by default), each lane in its own Docker container or on the host, from the M0
  console. Lanes start cheapest-first; `max_lanes` run at once and the rest queue.
- `flightdeck practice`: 14 small synthetic challenges that ship with flightdeck, checked by hash.
- `flightdeck init` writes a config by asking a few questions; `flightdeck doctor` checks the setup
  and says how to fix each problem; `flightdeck image build` builds the lane image once.
- Flags wait for you: `a`/`1` submits, `d`/`0` declines. On a board that cannot check flags you
  submit by hand and say whether it was accepted.
- `t` hands you the lane's real shell (its container in Docker); exit it to hand the lane back,
  and the lane hears what you changed. Other lanes keep working meanwhile.
- Per-lane token and dollar caps (an alert at 80%, an approval at 100%), cost from the API or
  your config's prices, cached tokens counted.
- A lane whose history passes 50k prompt tokens continues in a fresh context with a summary, so a
  long lane does not get more expensive with every turn.
- Every run writes an append-only `events.jsonl` and each lane's full transcript.
- Docker lanes get no network unless their challenge has a live instance.

### M0: the console mock

- `flightdeck mock`: the console on scripted data (fleet view and focus view, alerts, every
  intervention), with `--screenshot` for headless SVGs.
