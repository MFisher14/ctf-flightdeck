# ctf-flightdeck

A terminal harness for playing CTFs with AI agents, where **you** run the loop.

flightdeck pulls and triages the board, runs your no-model solvers first, spins up agent lanes in
parallel, and submits flags, while you watch every lane on one console and step in when one goes the
wrong way: a hint, a redirect, a fork, a kill, or taking over yourself.

Bring what you have: an API key, an OpenRouter account, a coding-agent CLI, a folder of Python scripts.

> **Status: pre-alpha, milestone M1.** Agent lanes play a folder of challenges against an
> OpenAI-compatible API (OpenRouter by default), in Docker or on the host, from the M0 console.
> No platform adapters yet (CTFd is M2). See [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Play a board (M1)

A board is a folder of challenge folders, each with a `challenge.json` and its handout files
(format in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)). The repo ships a synthetic practice set
in [`src/ctf_flightdeck/practice/`](src/ctf_flightdeck/practice/README.md) (`flightdeck practice` plays it).

```sh
uv run flightdeck init            # a few questions; writes ~/.config/ctf-flightdeck/config.toml
export OPENROUTER_API_KEY=...     # the variable init named; flightdeck never stores the key
uv run flightdeck image build     # once, for Docker lanes: builds the lane image (python3 and CTF tools)
uv run flightdeck doctor          # checks everything and says how to fix what is missing
uv run flightdeck practice        # the bundled practice set: 14 small synthetic challenges
uv run flightdeck play ~/ctf/some-board --max-lanes 4
```

`play` spends tokens: every lane is a model conversation, capped per lane by `token_cap` and
`dollar_cap` (at 80% you get an alert, at 100% the lane waits for your approval). Lanes start
cheapest-first. A flag a lane finds waits for you: `a` or `1` submits it, `d` or `0` declines. With
an `answers.sha256.json` (practice) flightdeck checks flags itself; without one you submit by hand
and tell it how it went. `t` takes over a lane's shell; exit the shell to hand it back. Every run
writes an append-only `events.jsonl` and each lane's full transcript (`lanes/`) under the run folder.
Docker lanes get no network unless their challenge has a live instance. `--host` runs lane commands
as you, on this machine, where a lane can read your files and your API key: use Docker, a disposable
VM, or a separate low-limit key.

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
`a` approve, `d` decline, `1`-`9`/`0` quick answers, `c` claim (team), `/` commands, `s` sort, `?`
help, `q` quit. **Enter** opens a lane full
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
