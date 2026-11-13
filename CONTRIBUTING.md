# Contributing

flightdeck is alpha, and help is welcome. There are three ways to help, and the first needs no
code:

1. [Play and share what you ran](#share-a-flight-card): the most useful of the three.
2. [Build](#set-up): a bug report, a fix, a test, a feature, a doc that says it better.
3. [Sponsor](#sponsoring) the model measurements.

[docs/VISION.md](docs/VISION.md) says what flightdeck is for and what it is not: read it first.

## Share a flight card

Nobody knows yet which model is best for which kind of challenge, on which machine, at what
cost. One player's runs cannot answer that. Many players' runs can.

```sh
flightdeck practice          # or play any board
flightdeck share latest      # prints the flight card of your newest run
```

A flight card says what you ran (flightdeck's version, the models, Docker or host, lanes at
once, a coding-agent CLI, a solver pack or none) and how it went (solves by category, time,
tokens, dollars, how often you stepped in, and the mode: hands-on, approve-only or hands-off).
It holds no flag, no challenge name and no challenge text, and `share` sends nothing anywhere:
it prints, and you paste it into
[a flight card issue](https://github.com/MFisher14/ctf-flightdeck/issues/new?template=flight-card.yml).

- The practice set is the best comparison, since everyone plays the same 14 challenges. Try a
  model nobody has posted yet, a local model on your hardware, or a different number of lanes.
- A real event counts too, once it has ended and if its rules allowed AI tools.
- Logs help when you can share them: `flightdeck report RUN_DIR` for a practice run. A report
  names challenges and quotes lane steps, so for a real event share it only if the event
  allows writeups.
- Played a whole event? [Put it on the leaderboard](docs/LEADERBOARD.md), with your GitHub
  name.
- A local model on unusual hardware:
  [the model results form](https://github.com/MFisher14/ctf-flightdeck/issues/new?template=hardware.yml)
  asks for a little more.

## Set up

Python 3.12+ and [uv](https://docs.astral.sh/uv/), on macOS or Linux (Windows through WSL).

```sh
git clone https://github.com/MFisher14/ctf-flightdeck
cd ctf-flightdeck
uv sync                               # the dependencies, and pytest
git config core.hooksPath .githooks   # the commit guard: secrets and big files stay out
uv run pytest
```

`uv run flightdeck mock` opens the console on scripted data. No test needs a key: the tests use
local fakes (a fake model server, a fake CTFd, fake agent CLIs). The Docker tests run only when
Docker answers and `debian:bookworm-slim` is already on your machine
(`docker pull debian:bookworm-slim`); otherwise they report as not run. One more test runs a
Python L1 engine in the real lane image, and only when `flightdeck image build` has built it.
No test pulls or builds an image.

CI runs the tests and the secret scan on Linux and macOS for every push and pull request. Its
Linux job pulls `debian:bookworm-slim` first and sets `FLIGHTDECK_REQUIRE_DOCKER=1`: with that
variable at 1, a Docker test that cannot run fails instead of being skipped, so the job never
passes with those tests left out. A second job builds the lane image and runs its test with
`FLIGHTDECK_REQUIRE_LANE_IMAGE=1`, which does the same for that test. Set either on your own
machine to be sure nothing was skipped:

```sh
FLIGHTDECK_REQUIRE_DOCKER=1 FLIGHTDECK_REQUIRE_LANE_IMAGE=1 uv run pytest
```

The solver pack (`packs/solvers/`, D24) has an environment and a suite of its own:
`packs/solvers/setup.sh` builds the environment, the tests in `tests/test_solver_pack.py` then run
the pack's intake on synthetic challenges (without the environment they report as not run; CI's
`solver-pack` job sets `FLIGHTDECK_REQUIRE_PACK=1`, which makes that a failure), and
`packs/solvers/README.md` says how to run the pack's own suite. Only the maintainer's export
(`packs/solvers/maint/export.py`) changes the pack's exported files; a fix to an engine goes in a
pull request as usual and is carried back to the master by him.

A Docker test tells pytest it cannot run through `docker_not_run()` in `tests/l1_kit.py`, never
a plain `pytest.skip`: that is what the variables turn into a failure.

The commit guard checks each commit for key and token shapes, credential files and files over
10 MB. If it blocks a value, take the value out; never skip it with `--no-verify`.
`python3 -I .githooks/secret_scan.py --all` scans every tracked file, as CI does. To keep your
own team name, handle or IPs out too, `python3 -I .githooks/secret_scan.py --add` stores their
sha256 digests (never the strings) in `~/.config/ctf-flightdeck/denylist.sha256`.

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
- A change a player will notice adds a line under `## Unreleased` at the top of
  [CHANGELOG.md](CHANGELOG.md) (add that heading if the last release took it), and updates the
  README or the docs page that describes it.
- [docs/DECISIONS.md](docs/DECISIONS.md) holds the decisions already made, with their dates. To
  change one, say which and why in the issue, rather than working around it.
- A security problem goes to the
  [private report](https://github.com/MFisher14/ctf-flightdeck/security/advisories/new), never
  an issue: see [SECURITY.md](SECURITY.md).

Work on a branch, in small commits. The pull request template asks what changed and why, and
how it was tested.

### Releases

For the maintainer. `.github/workflows/release.yml` publishes a tag `vX.Y.Z` to PyPI (Trusted
Publishing: no token anywhere), then creates the GitHub release with a `.deb` for amd64 and
arm64, and writes the Homebrew formula to the tap. A rehearsal (Run workflow, target testpypi)
builds and tests the `.deb`s too, and publishes neither them nor the formula.

- **The `.deb`** brings its own Python. `packaging/deb/build-in-docker.sh WHEEL OUT_DIR` builds
  it in a debian:12 container, and `packaging/deb/test-in-docker.sh DEB VERSION` installs it in
  a clean one and runs `flightdeck --version` and `flightdeck doctor` there. Both run on your
  machine as they do in CI, with Docker and uv.
- **The formula** is `packaging/homebrew/ctf-flightdeck.rb.in` with the release's sdist and one
  resource for each locked dependency, rendered by `packaging/homebrew/render_formula.py`
  (standard library only). Before the first release with it, try a rendered formula by hand:
  `brew install --build-from-source ./ctf-flightdeck.rb`, then `brew test ctf-flightdeck`.
- **The tap** is the repository `MFisher14/homebrew-tap`, which the workflow does not create.
  It needs one commit (a README will do) and a token that can write to it and to nothing else:
  a fine-grained personal access token for that one repository with Contents read and write.
  Store it as the secret `HOMEBREW_TAP_TOKEN` of an environment named `homebrew-tap` in this
  repository, with yourself as required reviewer, as for `pypi`. Without the secret the
  `homebrew-tap` job says so and passes, and the tap is not touched. The token is never in this
  repository.

### Adding a practice challenge

The practice set is the board that `flightdeck practice` plays
([its README](src/ctf_flightdeck/practice/README.md)). To add a challenge to it:

1. Add a directory to `src/ctf_flightdeck/practice/` with `challenge.json` and the handout files,
   all listed in `files` ([docs/BOARDS.md](docs/BOARDS.md) has the format).
2. Put the SHA-256 of the flag in `answers.sha256.json`, never the flag itself.
3. Add a reference solver to `tests/test_practice.py` that recovers the flag from the handout with
   the standard library, without running handout code.
4. Keep it synthetic and small: no compiled binaries, no executable files, under 1 MB per handout.

## Sponsoring

flightdeck is free and MIT-licensed, and stays that way. What costs money is measuring: every
figure in [docs/MODELS.md](docs/MODELS.md) for an API model was paid for per token, and each new
model means running the sets again. Sponsorship pays for those runs, and the results are
published for everyone.

**[Sponsor flightdeck on GitHub](https://github.com/sponsors/MFisher14).** Any amount helps, once or
monthly. A flight card from a model you already pay for helps just as much.

## Agents

An AI agent working on this repository, yours or ours, reads [AGENTS.md](AGENTS.md) first: the
same rules, short enough to re-read on every turn. Codex reads it by itself, and `CLAUDE.md`
points Claude Code to it.

## License

MIT, like the rest of flightdeck: what you contribute is released under [LICENSE](LICENSE).
