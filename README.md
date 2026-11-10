# ctf-flightdeck

A terminal harness for playing CTFs with AI agents, where **you** run the loop.

flightdeck pulls and triages the board, runs your no-model solvers first, spins up agent lanes in
parallel, and submits flags, while you watch every lane on one console and step in when one goes the
wrong way: a hint, a redirect, a fork, a kill, or taking over yourself.

Bring what you have: an API key, an OpenRouter account, a coding-agent CLI, a folder of Python scripts.

> **Status: pre-alpha.** Milestone M0, a clickable console mock with fake data, is ready for review.
> Nothing talks to a model or a CTF yet. See [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Try the mock (M0)

Needs Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```sh
uv run flightdeck mock                      # the default scenario: every alert, then a 43-challenge wave
uv run flightdeck mock --scenario wave      # also: sstv, overthinking, web, team, flag
uv run flightdeck mock --solo --host --max-lanes 8
uv run flightdeck mock --screenshot .flightdeck/shots   # headless: SVGs of the key moments (git-ignored dir)
```

Two views. The **fleet** shows the board and every lane, sorted by what needs you; keys act on the
selected lane: `p` pause, `h` hint, `r` redirect, `f` fork, `k` kill, `e` escalate, `t` take over,
`a` approve, `c` claim (team), `/` commands, `s` sort, `?` help, `q` quit. **Enter** opens a lane full
screen: its transcript, the files it changed with diffs, and a chat box (plain text is a message to
the lane; `/redirect`, `/approve`, `/diff` and the rest are commands; `esc` goes back). In the mock,
`space` freezes the clock and `.` steps it. All challenges, teammates and flags are invented.
`ctfdeck` is an alias for `flightdeck`. Tests: `uv run pytest`.

## Ideas

- **CTF-aware.** Points, solve counts, categories, waves of 40+ challenges, flag formats, teammates.
- **You stay in control.** Alerts when a lane spends big on a 50-pointer, ignores what the description
  hints at, loops or stalls. One key to intervene.
- **Rules first.** Every stage (pull, solve, submit...) can be auto, confirm, manual or off, set by a
  pre-flight check of the event's rules.
- **Solo or team.** Team mode never works a solved challenge and stays off teammates' live boxes.
- **Cheap by design.** Fresh, small context per challenge, per-lane caps, tokens and dollars on screen.

## Docs

[Vision](docs/VISION.md) · [Decisions](docs/DECISIONS.md) · [Roadmap](docs/ROADMAP.md) ·
[Console spec](docs/CONSOLE-SPEC.md) · [Architecture](docs/ARCHITECTURE.md)

## License

MIT. See [LICENSE](LICENSE).
