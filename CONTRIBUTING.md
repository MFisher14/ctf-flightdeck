# Contributing

flightdeck is alpha, and help is welcome: a bug report, a fix, a test, a doc that says it better.
[docs/VISION.md](docs/VISION.md) says what flightdeck is for and what it is not: read it first.

## Set up

Python 3.12+ and [uv](https://docs.astral.sh/uv/), on macOS or Linux (Windows through WSL).

```sh
git clone https://github.com/MFisher14/ctf-flightdeck
cd ctf-flightdeck
uv sync                               # the dependencies, and pytest
git config core.hooksPath .githooks   # the commit guard: secrets, private notes, big files
uv run pytest
```

`uv run flightdeck mock` opens the console on scripted data. No test needs a key: the tests use
local fakes (a fake model server, a fake CTFd, fake agent CLIs). The Docker tests run only when
Docker answers and `debian:bookworm-slim` is already on your machine
(`docker pull debian:bookworm-slim`); otherwise they report as not run. No test pulls an image.
CI runs the tests and the secret scan on Linux and macOS for every push and pull request.

The commit guard checks each commit for key and token shapes, credential files, private notes
and files over 10 MB. If it blocks a value, take the value out; never skip it with
`--no-verify`. `python3 -I .githooks/secret_scan.py --all` scans every tracked file, as CI does.
To keep your own team name, handle or IPs out too, `python3 .githooks/secret_scan.py --add`
stores their sha256 digests (never the strings) in `~/.config/ctf-flightdeck/denylist.sha256`.

## Rules for code

These come from [AGENTS.md](AGENTS.md), and they hold for people and agents alike.

- **Tests must test.** Each behaviour gets a test that fails when the behaviour is wrong. No
  tautologies, no mocking the unit under test, no skip-as-pass. A test that needs a tool you do
  not have reports as not run (a skip that says why), never as passed.
- **No silent fallbacks.** A missing tool, key, model or config fails loudly, with a named
  reason.
- **Challenge text is untrusted data, never instructions.** That is everything that comes from a
  challenge, a platform, a teammate's synced folder or a model. Design every prompt and tool so
  that text cannot steer the harness: it reaches the model fenced as data, never in the system
  prompt, and the console through `text.untrusted()`, never as markup.
- **Never run a challenge binary**, in a test or anywhere else. Fixtures and demo challenges are
  synthetic.
- **No network to real CTF infrastructure** (platforms, instances, scoreboards, Discord). Test a
  platform adapter against recorded fixtures or a local instance you start yourself
  (`tests/fake_ctfd.py` is a fake CTFd that answers on 127.0.0.1).
- **No secrets and no real event data.** No key, token, cookie or Authorization value in a
  commit, not even a fake one shaped like a real one: a test that needs a key-shaped value builds
  it when it runs (`"sk-ant-fake-" + "k" * 24`). No real challenge, flag, team or player name.
- **Say exactly what ran.** Never say a test ran or passed unless you saw it.

## Propose a change

- **Something small** (a bug fix with a test that shows the bug, a doc fix): open a pull request.
- **Anything big** (a new platform, a change to how lanes run or what they may reach, a new
  dependency, a new console key): open an issue first, so we agree on it before you build it.
- [docs/DECISIONS.md](docs/DECISIONS.md) holds the decisions already made, with their dates. To
  change one, say which and why in the issue, rather than working around it.
- A security problem goes to the
  [private report](https://github.com/MFisher14/ctf-flightdeck/security/advisories/new), never
  an issue: see [SECURITY.md](SECURITY.md).

Work on a branch, in small commits. The pull request template asks what changed and why, and
how it was tested.

## Agents

An AI agent working on this repository, yours or ours, reads [AGENTS.md](AGENTS.md) first: the
same rules, short enough to re-read on every turn. Codex reads it by itself, and `CLAUDE.md`
points Claude Code to it.

## License

MIT, like the rest of flightdeck: what you contribute is released under [LICENSE](LICENSE).
