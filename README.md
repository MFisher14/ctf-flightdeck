# ctf-flightdeck

A terminal harness for playing CTFs with AI agents, where **you** run the loop.

flightdeck pulls and triages the board, runs your no-model solvers first, spins up agent lanes in
parallel, and submits flags, while you watch every lane on one console and step in when one goes the
wrong way: a hint, a redirect, a fork, a kill, or taking over yourself.

Bring what you have: an API key, an OpenRouter account, a coding-agent CLI, a folder of Python scripts.

> **Status: pre-alpha.** Nothing to install yet. Milestone M0 (a clickable console mock) is in progress.
> See [`docs/ROADMAP.md`](docs/ROADMAP.md).

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
