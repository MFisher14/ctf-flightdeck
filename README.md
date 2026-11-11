# ctf-flightdeck

A terminal harness for playing CTFs with AI agents, where **you** run the loop.

flightdeck pulls the board, runs your own no-model solvers first, starts agent lanes in parallel,
and submits flags, while you watch every lane on one console and step in when one goes the wrong
way: a hint, a redirect, a fork, a kill, or taking over its shell yourself.

Bring what you have: an API key (Anthropic, OpenRouter, OpenAI or a local model server), a
coding-agent CLI (Claude Code, Codex), a folder of solver scripts.

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
everything (Python, the config, the API key variable, a local model server and its models, Docker,
the lane image) and says how to fix each problem. Before the console opens, `play` and `practice`
ask the model API whether it takes your key and serves every model in your ladder, and stop with
what to fix if not. No setup at all: `flightdeck mock` opens the console on scripted data and
spends nothing.

## Keys and model APIs

Your config names the environment variable that holds each key, never the key. flightdeck reads
the variable from your environment, else from `~/.config/ctf-flightdeck/keys.env` (or the file
`$FLIGHTDECK_KEYS` names), which must be readable by you only:

```sh
mkdir -p ~/.config/ctf-flightdeck && touch ~/.config/ctf-flightdeck/keys.env && chmod 600 ~/.config/ctf-flightdeck/keys.env
# then add lines like:  ANTHROPIC_API_KEY=...   OPENROUTER_API_KEY=...
```

Lane processes never see these values.

With an Anthropic key, `flightdeck init --provider anthropic` writes the Anthropic API with the
ladder `claude-haiku-5-5`, `claude-sonnet-5-5`, `claude-opus-5-5` and their list prices, so the
dollar caps work from the start. If `OPENROUTER_API_KEY` is set too, init offers OpenRouter as the
fallback (`--fallback` away from a terminal): a lane whose calls to Anthropic keep failing (rate
limits, overload, an outage, after every retry) moves to OpenRouter's names for the same models for
the rest of its context, and its transcript says so; escalating it, or the long-context refresh,
tries Anthropic again. A refusal or a bad request never moves a lane. On Claude Sonnet and Opus
5.5, Anthropic retries a request its safety classifiers decline on its recommended fallback model,
inside the same call (Claude Haiku 5.5 has no such fallback); a request still declined ends the
lane with "the model declined (category)". Any config can have a `[fallback]` table
(`flightdeck config --example` shows it).

With the Anthropic API, `[api] fast = ["claude-opus-5-5"]` calls those ladder models in fast mode:
up to 2.5x the output speed at twice the price ($8 / $40 per million tokens on Claude Opus 5.5).
Only a model with fast mode is accepted (Claude Opus 5.5, Fable 5.2 and Mythos 5.2; Opus 5 and
Opus 4.8 as research previews, Opus 4.8 until 2026-11-30), and fast calls are priced at the fast
rate. Fast mode has its own rate limit: on a 429 the lane goes on at standard speed for the rest
of its session and says so (switching speed starts the prompt cache again).

## Light model

A few small jobs can use a small model. Today that is the hint judge: when a lane seems to ignore
what its description hints at, the alert shows at once, and the light model checks the lane's
steps; if it says the lane is using the technique after all, the alert comes down. By default
there is no light model, only the rules. Four choices, in `[light]`:

- `rules`: no model (the default).
- `openai`: any OpenAI-compatible server. **Recommended: an open-weight model on your own
  machine**, served by Ollama (`http://127.0.0.1:11434/v1`) or an MLX server
  (`http://127.0.0.1:8080/v1`), with `key_env = ""`. No provider's safety classifier stands
  between it and security work, and it costs nothing.
- `anthropic`: a Claude model (`claude-haiku-5-5`, say).
- `cactus`: Cactus Needle, on this machine (the `[cactus]` extra).

Measure one before you switch it on. Models worth measuring, as examples and not endorsements:
Qwen3.5 9B, Gemma 4 12B, gpt-oss-20b, Ministral 3 14B, Phi-4-mini. `eval-local` decides:

```sh
flightdeck eval-local --engine openai --base-url http://127.0.0.1:11434/v1 --model <model> \
    --compare anthropic:claude-haiku-5-5 --compare cactus
flightdeck init --light ollama --light-model <model>     # or edit [light]; `flightdeck doctor` checks it
```

eval-local runs each engine and the rules over the bundled cases (naming the hinted technique,
judging a lane, summarising one) and prints them side by side: accuracy, refusals and failures,
time and cost per job. A paid API is announced first with its number of calls: one per case,
never a retry.

The light model never holds anything up. When it refuses, fails, times out or answers outside the
options, the rules' answer stands, and the run says so once. A refused request is never sent on
to another model or provider: you see the refusal and decide.

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

Docker lanes get no network unless their challenge has a live instance (a web origin, or a TCP
service like `nc host port`: `tcp://host:port` in a challenge's `urls`). `--host` runs lane
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
cost no tokens at all. When lanes run in Docker, so do your solvers: each in a container of the
lane image, your pack mounted read-only, with no network unless the live-instance policy is `auto`
and the challenge has an instance. With `--host` they run on this machine, as you.

```sh
flightdeck l1 import ~/ctf/solvers        # manifests for a folder of plain scripts (the scripts are never changed)
flightdeck l1 route ~/ctf/solvers ~/ctf/some-board/crab-walk   # which engines a challenge reaches, and why (or why not)
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

- `ctf-flightdeck[cactus]`: Cactus Needle, a small on-device model, one of the light model's
  choices (`flightdeck eval-local --engine cactus` measures it against the rules first). Its
  telemetry is turned off. Nothing uses it unless you ask.
- `ctf-flightdeck[build]`: pytest, for `flightdeck build check`.

## Docs

[Vision](docs/VISION.md) · [Decisions](docs/DECISIONS.md) · [Roadmap](docs/ROADMAP.md) ·
[Console spec](docs/CONSOLE-SPEC.md) · [Architecture](docs/ARCHITECTURE.md) ·
[Changelog](CHANGELOG.md)

Development: `uv run pytest`. `ctfdeck` is an alias for `flightdeck`.

## License

MIT. See [LICENSE](LICENSE).
