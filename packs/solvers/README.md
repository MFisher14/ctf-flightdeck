# flightdeck's solver pack

No-model solvers for CTF challenges: the engines flightdeck's author played with, exported from
his master repository. flightdeck runs them on a challenge before any model is called
([docs/SOLVERS.md](../../docs/SOLVERS.md)).

```sh
flightdeck pack install        # fetch, set up, write into your config
```

## What is here

| Path | What |
|---|---|
| `pack.toml` | What flightdeck needs to know: the setup command, the image, where the flightdeck manifests are. |
| `flightdeck/` | The adapter. `intake_engine.py` runs the pack's whole intake on one challenge and reports one result; `intake.manifest.toml` routes every challenge to it; `Dockerfile` is the image for Docker lanes. |
| `ctf/` | The pack's own pipeline package: intake, sweep and recursive unpack, engine manifests and router, flag formats, decoders. Its command line is `.venv/bin/python -m ctf`. It also holds the platform client and orchestration its author used before flightdeck; flightdeck uses none of that. |
| `solvers/` | Some 830 engines in lanes (`common`, `toolkits`, `warmups`, `binary`, `web`, `script-analysis`, `metadata-forensics`, `mobile-android`), each with a manifest in the pack's own format (`docs/CONTRACTS.md`, section 6). |
| `tools/`, `docker/`, `openers/`, `templates/`, `speedrun/` | Operator tools, sandbox and toolchain images, and the rest the engines load. |
| `docs/` | `CAPABILITIES.md` (what the engines solve, by category), `playbooks/`, `toolkits/`, `CONTRACTS.md`. |
| `tests/` | The pack's own suite, on synthetic fixtures. |
| `maint/` | The maintainer's export script, its patches and the pin override. |

The pack names the past events its engines were first written for (in comments, test names and
the four profiles under `events/`, whose hosts are placeholders). It holds no flag, token or
player name from them.

## Use it without flightdeck's console

```sh
./setup.sh                                                  # the Python environment, in .venv
flightdeck l1 run . ~/ctf/some-board/some-challenge         # the intake on one challenge
.venv/bin/python -m ctf engines route --help                # the pack's own router
.venv/bin/python solvers/warmups/crib_decode.py FILE        # one engine by hand
```

## Tests

```sh
.venv/bin/python -m pytest -q -n 6          # the pack's suite (long); flightdeck's own is `uv run pytest` at the top
```

Tests that need a tool or a corpus this machine lacks report as not run.

## For the maintainer

`python3 packs/solvers/maint/export.py ~/ctf-tools` copies the public paths of the master's last
commit here and applies `maint/patches/`. `README.md`, `pack.toml`, `setup.sh`, `flightdeck/` and
`maint/` belong to this repository and are never overwritten. The master is never written to.
