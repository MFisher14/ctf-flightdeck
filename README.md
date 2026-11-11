# ctf-flightdeck

A terminal harness for playing CTFs with AI agents, where **you** run the loop.

flightdeck pulls the board, runs your own no-model solvers first, starts agent lanes in parallel,
and submits flags, while you watch every lane on one console and step in when one goes the wrong
way: a hint, a redirect, a fork, a kill, or taking over its shell yourself.

Bring what you have: an API key (OpenRouter, OpenAI or a local model server), a coding-agent CLI
(Claude Code, Codex), a folder of solver scripts.

> **Status: pre-release (v0.1.0 coming).** Milestones M0 to M4 are built: the console, agent
> lanes, your L1 solvers, CTFd events, team mode, alerts, practice scoring, post-flight reports.
> See [`docs/ROADMAP.md`](docs/ROADMAP.md) and [`CHANGELOG.md`](CHANGELOG.md).

## Quickstart

Needs Python 3.12+ on macOS or Linux (Windows through WSL), and Docker for the safest setup.

```sh
pipx install ctf-flightdeck     # or: uv tool install ctf-flightdeck   (from a clone: uv tool install .)
flightdeck init                 # a few questions; writes your config and says what to do next
flightdeck practice             # 14 small practice challenges that ship with flightdeck
```

`flightdeck` on its own says what to do next on your machine, and `flightdeck doctor` checks
everything (Python, the config, the API key variable, Docker, the lane image) and says how to fix
each problem. No setup at all: `flightdeck mock` opens the console on scripted data and spends
nothing.

## Play a board

```sh
flightdeck play ~/ctf/some-board --max-lanes 4
```

A board is a folder of challenge folders, each with a `challenge.json` and its handout files
(format in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)). Lanes start cheapest-first; the rest
queue. Every lane is a model conversation, capped per lane by `token_cap` and `dollar_cap` (an
alert at 80%, your approval at 100%).

A flag a lane finds waits for you: `a` or `1` submits it, `d` or `0` declines. A flag found wrong
is never asked about again. The console raises an alert when a lane spends big on a low-value
challenge, ignores what the description hints at, heads the wrong way on web, loops or stalls.
`t` takes over a lane's shell (exit it to hand the lane back), `e` escalates it to a stronger
model with a summary of what it did, `f` forks it, `?` shows every key.

Docker lanes get no network unless their challenge has a live instance. `--host` runs lane
commands as you, on this machine, where a lane can read your files and your API key: use Docker,
a disposable VM, or a separate low-limit key. Every run writes an append-only `events.jsonl` and
each lane's transcript; a board with answers (like the practice set) ends with a scorecard.

## Play an event

Write down what the event's rules allow, check it, and play by it:

```sh
flightdeck preflight --example > event.toml      # then edit it from the event's rules
flightdeck preflight event.toml                   # what flightdeck will do at each stage, and any problem
export CTFD_TOKEN=...                             # the variable event.toml names (never the token itself)
flightdeck play ~/ctf/event-board --event event.toml
```

With a CTFd event, flightdeck pulls the board into that folder, adds new waves as they appear,
submits the flags you approve through CTFd and follows your team's solves. Each stage (pull, L1,
agents, submit, live instance) runs as the profile's policy says: `auto`, `confirm` (you say yes
first), `manual` or `off`, never looser than the rules. Under `confirm` for live instances, a lane
asks before it may reach its challenge's instance and has no network until you allow it.

Team mode shares claims, live-box holds and solves through a folder your teammates sync (a network
drive, Syncthing): `flightdeck team init DIR` once, then `--team-dir DIR`. Your lanes never work a
challenge a teammate solved.

`--agent claude` (or `codex`) runs lanes as that coding-agent CLI, with its own login and models
(`[agents]` in your config), behind the same controls. Check it first with
`flightdeck doctor --agent claude`.

## Your solvers first (L1)

Point flightdeck at a folder of your no-model solvers and every lane runs the ones that fit its
challenge before its first model call; a flag one finds waits for your approval, so a solve can
cost no tokens at all.

```sh
flightdeck l1 import ~/ctf/solvers        # manifests for a folder of plain scripts (the scripts are never changed)
flightdeck l1 route ~/ctf/solvers ~/ctf/some-board/crab-walk   # which engines a challenge reaches, and why
flightdeck play ~/ctf/some-board --pack ~/ctf/solvers          # or set [l1] pack in your config
```

## After a run

```sh
flightdeck report RUN_DIR      # where lanes stalled, which interventions helped, cost per solve
flightdeck writeups RUN_DIR    # a writeup draft per solved challenge (--redact hides the flags)
flightdeck score RUN_DIR       # the run scored against the board's answers
flightdeck gaps RUN_DIR        # the challenges your L1 solvers did not solve, and why
flightdeck build gap CHALLENGE_DIR --pack ~/ctf/solvers   # a new engine stub with a test that must pass
```

## Try the mock

```sh
flightdeck mock                      # the default scenario: every alert, then a 43-challenge wave
flightdeck mock --scenario wave      # also: sstv, overthinking, web, team, flag
flightdeck mock --screenshot DIR     # headless: SVGs of the key moments
```

Two views. The **fleet** shows the board and every lane, sorted by what needs you; keys act on the
selected lane: `p` pause, `h` hint, `r` redirect, `f` fork, `k` kill, `e` escalate, `t` take over,
`a` approve, `d` decline, `1`-`9`/`0` quick answers, `c` claim (team), `/` commands, `s` sort, `?`
help, `q` quit. **Enter** opens a lane full screen: its transcript, the files it changed with
diffs, and a chat box (plain text is a message to the lane; `/redirect`, `/approve`, `/diff` and
the rest are commands; `esc` goes back). In the mock, `space` freezes the clock and `.` steps it.
All challenges, teammates and flags there are invented.

## Optional extras

- `ctf-flightdeck[cactus]`: Cactus Needle, a small on-device model, for experiments
  (`flightdeck eval-local` measures a local model against the rules first). Its telemetry is
  turned off. Nothing uses it unless you ask.
- `ctf-flightdeck[build]`: pytest, for `flightdeck build check`.

## Docs

[Vision](docs/VISION.md) · [Decisions](docs/DECISIONS.md) · [Roadmap](docs/ROADMAP.md) ·
[Console spec](docs/CONSOLE-SPEC.md) · [Architecture](docs/ARCHITECTURE.md) ·
[Changelog](CHANGELOG.md)

Development: `uv run pytest`. `ctfdeck` is an alias for `flightdeck`.

## License

MIT. See [LICENSE](LICENSE).
