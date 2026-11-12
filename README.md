<h1 align="center">ctf-flightdeck</h1>

<p align="center"><b>Play CTFs with a fleet of AI agents, and stay the pilot.</b><br>
One terminal console: every challenge, every agent, every flag. You step in with one key.</p>

<p align="center">
<a href="https://pypi.org/project/ctf-flightdeck/"><img alt="PyPI version" src="https://img.shields.io/pypi/v/ctf-flightdeck"></a>
<a href="https://pypi.org/project/ctf-flightdeck/"><img alt="Python versions" src="https://img.shields.io/pypi/pyversions/ctf-flightdeck"></a>
<a href="https://github.com/MFisher14/ctf-flightdeck/actions/workflows/tests.yml"><img alt="Tests" src="https://github.com/MFisher14/ctf-flightdeck/actions/workflows/tests.yml/badge.svg"></a>
<a href="https://github.com/MFisher14/ctf-flightdeck/blob/main/LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-blue"></a>
<a href="https://github.com/MFisher14/ctf-flightdeck/blob/main/CONTRIBUTING.md"><img alt="Pull requests welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen"></a>
</p>

![The fleet view: a board of eight challenges on the left; on the right, six agent lanes sorted by what needs you, with chips for a found flag, a lane that ignores the hint, a web lane heading the wrong way and a live box a teammate holds; under the list, the found flag with 1 to submit it and 0 not to](https://raw.githubusercontent.com/MFisher14/ctf-flightdeck/main/docs/screenshots/fleet.png)

## Try it in ten seconds

```sh
uvx ctf-flightdeck mock
```

That opens the console on scripted data: no install, no key, no network, nothing spent. (No `uvx`?
`pipx run ctf-flightdeck mock` does the same.)

## What it is

flightdeck is a terminal harness for capture-the-flag events. It pulls the board, runs your own
no-model solver scripts first, starts an AI agent on each challenge in parallel, and submits the
flags you approve. Each agent works in its own **lane**, and you watch them all on one screen.
When a lane loops, stalls, overspends or ignores the hint, the console tells you, and one key
sends a hint, redirects it, forks it, kills it, moves it to a stronger model or hands you its
shell.

- **Bring what you have.** An API key (Anthropic, OpenRouter, OpenAI), a free model on your own
  machine (Ollama, MLX), a coding-agent CLI (Claude Code, Codex), a folder of solver scripts.
- **Built for CTFs.** It knows points, solves, categories, waves of 40 challenges, teammates,
  live instances, flag formats and counted tries. It plays CTFd events and plain folders.
- **Plays by the event's rules.** Every stage (pull, solvers, agents, submit, live instances) is
  `auto`, `confirm`, `manual` or `off`, checked before anything runs.
- **Safe by default.** Each lane runs in its own Docker container with no network, or, when
  its challenge has a live instance, a network that reaches that instance and nothing else. Challenge text is treated as hostile data, never as
  instructions. Lanes have token and dollar caps.
- **Learns from each run.** A report of where lanes stalled and which interventions helped,
  writeup drafts, and the list of challenges your solvers missed.

> **Status: v0.2.0 (alpha).** See the
> [changelog](https://github.com/MFisher14/ctf-flightdeck/blob/main/CHANGELOG.md) and the
> [roadmap](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/ROADMAP.md).

## Quickstart

Needs Python 3.12+ on macOS or Linux (Windows through WSL). Docker is recommended.

```sh
pipx install ctf-flightdeck   # or: uv tool install ctf-flightdeck
flightdeck init               # a few questions; writes your config and names the key it needs
flightdeck image build        # once, for Docker lanes (about 700 MB)
flightdeck doctor             # checks everything and says how to fix each problem
flightdeck practice           # 14 small practice challenges, on your model
```

Then play a real board:

```sh
flightdeck play ~/ctf/some-board                      # a folder of challenges
flightdeck play ~/ctf/event-board --event event.toml  # a CTFd event, by its rules
```

`practice` and `play` spend money on your model API unless the model runs on your machine. Each
lane stops and asks you at $2 or 400,000 tokens by default. Stuck? Run `flightdeck` on its own
and it says what to do next.

**Everything else is in the
[player's guide](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/GUIDE.md):** models
and keys, the console's keys, boards, your own solvers, events and teams, coding-agent lanes,
reports.

## The console

![An alert on a lane that ignores the description's hint, with numbered one-key answers under the lane list](https://raw.githubusercontent.com/MFisher14/ctf-flightdeck/main/docs/screenshots/alert-hint.png)

Lanes that need you sort first, and the line under the list says why and numbers the answers.
`h` hint, `r` redirect, `f` fork, `k` kill, `e` escalate to the next model, `t` take over the
lane's shell, `a` approve a flag, **Enter** for one lane full screen, `?` for every key. More
pictures in the
[screenshot gallery](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/SCREENSHOTS.md).

## Your data stays yours

flightdeck has **no telemetry, no analytics, no account, no update check and no server of its
own**. Nothing about you or your runs is sent to this project, ever.

It talks only to what you point it at:

- **The model API in your config.** A lane's challenge and its work go to the model you chose,
  as with any AI tool. Choose a model on your own machine (Ollama, MLX) and nothing leaves it.
- **The CTF platform in your event profile**, to pull the board and submit the flags you
  approve.

Your keys stay in your environment or a file only you can read, never in the config, and logs,
transcripts and reports replace anything shaped like a credential. Runs are written to a folder
on your machine. Sharing a result is something you do by hand: `flightdeck share` prints a
summary and you decide where to paste it. A coding-agent CLI you plug in (Claude Code, Codex)
follows its own maker's policy. Details:
[Security](https://github.com/MFisher14/ctf-flightdeck/blob/main/SECURITY.md).

## Leaderboard

Events flightdeck has flown in, where the team finished, and how hands-on the players were:
**[the leaderboard](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/LEADERBOARD.md)**.
Played an event with it? [Add your flight](https://github.com/MFisher14/ctf-flightdeck/issues/new?template=leaderboard.yml)
and your GitHub name goes on the board.

## Help make it better

Three ways, and the first needs no code:

1. **Play and share what you ran.** This is the most useful thing you can do. After any run
   (the practice set counts), `flightdeck share latest` prints a **flight card**: your models,
   your setup, solves, time, cost and how often you stepped in, with no flags and no challenge
   text.
   [Post it](https://github.com/MFisher14/ctf-flightdeck/issues/new?template=flight-card.yml).
   Enough cards tell everyone which model is fastest, cheapest and best for which kind of
   challenge, on which hardware.
2. **Build.** Fix a bug, add a feature, improve a doc.
   [Good first issues](https://github.com/MFisher14/ctf-flightdeck/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
   are small and well described, and
   [CONTRIBUTING.md](https://github.com/MFisher14/ctf-flightdeck/blob/main/CONTRIBUTING.md)
   gets you set up in five commands.
3. **Sponsor.** flightdeck is free and MIT-licensed. Measuring models costs real API money, and
   sponsorship pays for it: see
   [Sponsoring](https://github.com/MFisher14/ctf-flightdeck/blob/main/CONTRIBUTING.md#sponsoring).

A star helps other players find it.

## For AI agents

If you are an AI agent reading this for a user:

- **What this is:** a Python CLI (`flightdeck`, PyPI package `ctf-flightdeck`) that runs AI
  agents on CTF challenges under a human's control.
- **Safe to run without asking:** `uvx ctf-flightdeck mock --screenshot DIR` (headless, writes
  SVGs), `flightdeck --help`, `flightdeck doctor`, `flightdeck config --example`,
  `flightdeck models`.
- **Ask your user first:** `flightdeck practice` and `flightdeck play` spend money on a model
  API, and `play --event` talks to a live CTF platform under that event's rules.
- **Machine-readable map of the docs:**
  [llms.txt](https://github.com/MFisher14/ctf-flightdeck/blob/main/llms.txt).
- **Working on the code:** read
  [AGENTS.md](https://github.com/MFisher14/ctf-flightdeck/blob/main/AGENTS.md) first. It is
  short and its rules are strict.

## Docs

**Using flightdeck:**
[Player's guide](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/GUIDE.md) ·
[Model APIs](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/MODEL-APIS.md) ·
[Models](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/MODELS.md) ·
[Boards](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/BOARDS.md) ·
[Solvers](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/SOLVERS.md) ·
[Practice set](https://github.com/MFisher14/ctf-flightdeck/blob/main/src/ctf_flightdeck/practice/README.md) ·
[Screenshots](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/SCREENSHOTS.md) ·
[Leaderboard](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/LEADERBOARD.md) ·
[Changelog](https://github.com/MFisher14/ctf-flightdeck/blob/main/CHANGELOG.md) ·
[Security](https://github.com/MFisher14/ctf-flightdeck/blob/main/SECURITY.md)

**How it is built:**
[Vision](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/VISION.md) ·
[Architecture](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/ARCHITECTURE.md) ·
[Console spec](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/CONSOLE-SPEC.md) ·
[Decisions](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/DECISIONS.md) ·
[Roadmap](https://github.com/MFisher14/ctf-flightdeck/blob/main/docs/ROADMAP.md) ·
[Contributing](https://github.com/MFisher14/ctf-flightdeck/blob/main/CONTRIBUTING.md)

## License

MIT. See [LICENSE](https://github.com/MFisher14/ctf-flightdeck/blob/main/LICENSE).
