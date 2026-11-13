# Your solvers (L1)

Most players have a folder of scripts that solve the easy, familiar challenges with no model at
all: a decoder for layered base64, a script that carves files, an RSA small-exponent attack.
flightdeck calls these **L1**. Each lane runs the ones that fit its challenge before its first
model call (a coding-agent lane: before its CLI is started), so a solve can cost no tokens, and
when they find nothing the lane's model starts with what they reported.

You can bring your own, use flightdeck's solver pack, or both in turn. This page is the contract
between a pack and flightdeck.

## flightdeck's solver pack

The repository holds a solver pack, `packs/solvers/`: the no-model solvers its author played and
won events with. It is not part of the PyPI package (it is large, and brings some 250 pinned
Python libraries of its own), so you install it with one command:

```sh
flightdeck pack install
```

That fetches the pack as it was released with your flightdeck (a git clone of only that folder,
into `~/.local/share/ctf-flightdeck/packs/`; a source checkout of flightdeck uses its own
`packs/solvers/`), shows the pack's setup command and asks before running it (it builds the
pack's Python environment with `uv`, inside the pack's folder), builds the pack's Docker image
when your lanes run in Docker, and writes `[l1] pack` and `image` into your config. `--yes`
answers the questions; `--no-setup` and `--no-image` skip the steps; `--ref main` fetches the
newest pack instead of your release's.

On every challenge the pack runs its whole intake as one engine, `solvers.intake`: it unpacks
the handout recursively (archives inside archives, encoded containers), searches every member
for the flag under layered encodings, runs each of its analysis engines whose routes or file
types match (some 800, for crypto, forensics, reversing, web, mobile, network captures and
more), and then its decoders. One flag it can show the source of is `solved`, and is the only
thing it hands flightdeck as a flag. Several values, or one it cannot confirm, are told to the
lane's model and to you as text (the result is `unsure`): under auto submit flightdeck sends
every flag of a result, and a decoy or a guess must not go out that way. Its notes also say
what the handout holds, which engines ran and which others fit, so the model starts from there.

The lanes' models can use the pack too. `pack install` sets `lane_tools = true` under `[l1]`:
every lane's brief then says where the pack is and how to call it (`solvers fit` lists the
engines that fit the challenge, `solvers doc` and `solvers run` explain and run one, `solvers
playbook` prints the approach notes for a category), so a model reaches for an engine or a
playbook instead of writing a parser again. With Docker lanes, lanes then run in the pack's
image with the pack mounted read-only (their network is fenced as before); a coding-agent lane
(`--agent`) needs its CLI in that image, and a run says so before it starts when it is not.
`flightdeck pack install --no-lane-tools` leaves it off.

Three things to know:

- It never submits and never talks to a platform or the network; its engines run under its own
  network guard as well as flightdeck's.
- Some engines call command-line tools (tshark, binwalk, exiftool, ghidra and others). The
  Docker image has the common ones; on the host runtime they are yours to install
  (`packs/solvers/Brewfile` lists them), and an engine whose tool is missing is skipped and named.
- `flightdeck pack info` says what the configured pack is and whether its image is built;
  `flightdeck pack image` builds the image later.

`flightdeck pack install SOURCE` installs any other pack the same way: SOURCE is a git address
or a folder on this machine. A pack is code you choose to run, as you: read what its setup
command is before you say yes. [A pack that needs setup](#a-pack-that-needs-setup) is the
format.

## The words

- An **engine** is one solver: a Python function or a command.
- A **manifest** is a small file beside an engine that says how to run it and which challenges it
  fits.
- A **route** is one rule in a manifest: a category, some keywords, some file patterns. A challenge
  **reaches** an engine when it matches one of the engine's routes.
- A **pack** is a folder of engines with their manifests, laid out however you like.

Give flightdeck your pack with `play --pack FOLDER`, or once in your config:

```toml
[l1]
pack = "~/ctf/solvers"
concurrency = 4          # engines run at once on one challenge
```

## Start from the scripts you have

```sh
flightdeck l1 import ~/ctf/solvers
```

`l1 import` writes a manifest for every script in the folder that has none, into
`~/ctf/solvers/.flightdeck/generated/`. It never changes a script, and running it again rewrites
only that folder. It takes two kinds of script:

- a `.py` file with an `if __name__ == "__main__":` block, which runs as `python3 <the file>`;
- any other file with a `#!` line and an executable bit, which runs as itself.

Each gets the challenge folder as its last argument, and whatever it prints is searched for flags
(output `text`, below). Its route comes from where it is and what it is called:

- the **category** from its folder's name, when that names one: `crypto/` gives `cry`,
  `forensics/` gives `for`, `reverse-engineering/` gives `rev`, and so on for every name a board
  can use for `web`, `rev`, `pwn`, `misc` and `osint` ([BOARDS.md](BOARDS.md) lists them);
- the **keywords** from its file name's words of three letters or more, split on `_`, `-`, `.` and
  spaces, leaving out `solve`, `solver`, `script`, `exploit` and `main`.

So `crypto/crab_shift.py` gets this manifest, at priority 20 and with the tag `imported`:

```toml
id = "imported.crypto.crab_shift.py"
entry = "cli:python3 ./crypto/crab_shift.py"
tags = ["imported"]
output = "text"

[[routes]]
category = ["cry"]
keywords = ["crab", "shift"]
priority = 20
```

It reaches a crypto challenge whose name or description holds "crab" or "shift". The import lists
every script it skipped, with the reason: a `.py` file with no main block, a `#!` script without
an executable bit, a script with neither a category nor a keyword, or a script that a manifest
already runs. To route a script another way, write a manifest of your own for it (next section);
the import then leaves that script alone.

## Writing a manifest

A manifest is a file named `<anything>.manifest.toml`, anywhere in the pack. Paths in it start
from the folder it is in.

```toml
id = "decode.base64_layers"          # required; unique in the pack
entry = "decode_layers.py:solve"     # required: "<file>.py:<function>" or "cli:<command ...>"
tags = ["crypto", "decode"]          # optional
needs_tools = ["zsteg"]              # optional: programs that must be on PATH
timeout_seconds = 60                 # optional, 1 to 600; 60 by default
output = "result"                    # optional: "result" (the default) or "text"

[[routes]]                           # one or more
category = ["cry"]
keywords = ["base64"]
files = ["ext:.txt", "magic:PK", "magic:0x1f8b", "name:*.pcap"]
priority = 60                        # 0 to 100; 50 by default
```

An `id` is lower-case letters, digits, `_`, `.` and `-`, starting with a letter or digit. An
unknown key is an error, so a typo fails loudly instead of quietly never matching.

### Routes

A route matches a challenge when **every** condition it states holds, and a condition holds when
**any one** of its items does:

- `category`: the challenge's category is one of these. Use the short codes: `web`, `cry`, `rev`,
  `pwn`, `for`, `misc`, `osint`, or any other category in lower case.
- `keywords`: one of these is in the challenge's name or description (lower-case, as a
  substring).
- `any = true`: the route matches every challenge. It states no other condition; use it for an
  engine that looks at whatever it is given (an unpacker, a decoder).
- `files`: one of these patterns matches a handout file:
  - `ext:.txt`: the file name ends so, in any case (`ext:.tar.gz` works);
  - `magic:PK`: the file starts with this text; `magic:0x1f8b` gives the bytes in hex;
  - `name:*.pcap`: a glob on the file name, case-sensitive.

When a challenge reaches several engines, they are ordered by the `priority` of the route that
matched, highest first.

### Entries

- **A Python function**, `entry = "decode_layers.py:solve"`: flightdeck calls
  `solve(challenge_dir)` with the path of the engine's copy of the challenge, and the function
  returns a `SolverResult` (below). The file can import its own helpers from its folder.
- **A command**, `entry = "cli:./carve.sh --deep"`: the command is split like a shell line, and the
  challenge folder is added as its last argument. It runs with the copy of the challenge as its
  working folder, so a word that names a file of your pack (`./carve.sh`, `tools/x.py`) is run as
  that file. Any language works.

### Outputs

- `output = "result"`: the engine reports a `SolverResult`. A Python function returns it. A command
  prints it as JSON on its last non-empty line, or writes it to the file that the environment
  variable `FLIGHTDECK_L1_RESULT` names.
- `output = "text"`: the engine prints whatever it likes, and every match of the event's flag
  format in what it printed becomes a candidate flag.

An engine that searches for flags itself reads the event's flag format, a regular expression,
from the environment variable `FLIGHTDECK_FLAG_FORMAT`.

## The result: `SolverResult`

```python
from pathlib import Path

from ctf_flightdeck.l1.result import Evidence, SolverResult


def solve(challenge_dir: Path) -> SolverResult:
    text = (challenge_dir / "message.txt").read_text()
    flag = decode(text)                      # your own code
    if flag is None:
        return SolverResult("none", notes="no base64 layers in message.txt")
    return SolverResult("solved", flags=[flag], evidence=[Evidence("decode", "base64, three times", "message.txt")])
```

A result has one of five statuses:

| Status | Meaning | Rule |
|---|---|---|
| `solved` | The engine found the flag and can show why. | At least one flag and one piece of evidence. |
| `candidate` | One or more flags that may be right. | At least one flag. |
| `none` | The engine ran and found nothing. | No flags. |
| `unsure` | The engine ran, but its answer cannot be trusted either way. flightdeck also reports this for an engine that crashed, timed out or printed something that is not a result. | |
| `blocked` | The engine could not run. | No flags, and `notes` names what is missing. |

`solved` still means only "found": the platform decides whether a flag is right.

An engine in another language prints the same thing as one JSON object:

```json
{"schema": 1, "status": "solved", "flags": ["example{...}"],
 "evidence": [{"kind": "decode", "detail": "base64, three times", "path": "message.txt", "offset": null}],
 "cost": {"seconds": 0.2, "usd": 0.0, "tokens": 0},
 "engine": null, "challenge_id": null, "notes": ""}
```

| Field | What it is |
|---|---|
| `schema` | Always `1`. Required. |
| `status` | One of the five above. Required. |
| `flags` | A list of flags. |
| `evidence` | A list of reasons a human can check. Each has a `kind` (a short tag: `decode`, `carve`, `match`), a `detail` (one line), and optionally a `path` inside the challenge folder and a byte `offset` in it. |
| `cost` | `seconds`, `usd` and `tokens`. flightdeck measures the seconds itself. |
| `engine`, `challenge_id` | flightdeck fills these in. |
| `notes` | Free text for you: what the engine tried, or what it lacks. |

Everything but `schema` and `status` may be left out. A field flightdeck does not know, another
schema or a wrong type makes the result `unsure`: flightdeck reads a result strictly, because it
comes from a process that read a challenge's files.

## Try a pack from the command line

```sh
flightdeck l1 list ~/ctf/solvers                               # every engine, with its routes
flightdeck l1 route ~/ctf/solvers ~/ctf/some-board/crab-walk   # which engines this challenge reaches, and why
flightdeck l1 run ~/ctf/solvers ~/ctf/some-board/crab-walk     # run them, and print each result
```

`l1 route` takes a challenge folder of a [board](BOARDS.md) and lists the engines it reaches, best
first, each with the reason. When it reaches none, it says what each engine's nearest route lacks.

`l1 run` runs every engine the challenge reaches, each in its own copy of the challenge, and
prints each result as one line of JSON. It runs them **on this machine, as you, with no
container**, whatever your config's runtime says. The engines get no API keys or tokens from
flightdeck's environment. `--keep` keeps the copies, `--workdir DIR` says where they go, and
`--flag-format RE` gives a flag format other than the board's.

## How a run uses your pack

A lane routes its challenge through the pack and runs every engine it reaches, before its first
model call. Then:

- A flag an engine found becomes the lane's flag, like one its model found.
- If no engine solved the challenge, the lane goes on to its model, which is told what the
  engines reported.
- The run log records every engine that ran and what it reported, and `flightdeck gaps` reads it
  back (below).

**Where engines run** follows your lanes:

- With lanes in Docker, each engine runs in a container of its own, made from the lane image, with
  its copy of the challenge at `/work` and your pack mounted read-only. It has no network, unless
  the challenge has a live instance and lanes may reach it without asking (no event profile, or
  the profile's instance policy is `auto`). That network reaches the instance's hosts and ports
  and nothing else, as a lane's does (the guide's [Docker or host](GUIDE.md#docker-or-host)): a
  host name works as the challenge wrote it, but an instance given by IP address or as
  `localhost` is reached as `instance-10-0-0-5` (for `10.0.0.5`) or `instance-localhost`, on the
  same port, so an engine that reads `urls` from `challenge.json` must make that change itself.
  The programs an engine needs, `python3` included, must be in the lane image.
- With `--host`, each engine runs on this machine, as you, in a copy of the challenge, with an
  environment that holds no keys.

An engine stops at its `timeout_seconds`, and one that prints without end fills neither memory nor
disk: flightdeck keeps a bounded part of its output.

**Flags.** A flag that an engine reports as its result (`solved` or `candidate`) waits for your
approval. Under auto submit it goes to the platform at once, with the same exceptions as a flag a
lane's model found: for one, a flag that the challenge's own description or handout files hold,
which is often a decoy, still waits (the guide's [Play a board](GUIDE.md#play-a-board) lists
them all). A flag that is only a match in what an engine printed (`output = "text"`, so every
imported script) always waits for you, under auto submit too.

**Coding-agent lanes** (`--agent`) run the pack too, before their CLI is started, by the same
rules: engines run where the lanes do, a flag waits or goes out as above, and no CLI runs while a
flag waits for you (none at all when it solves the challenge). The CLI's opening brief says what
the engines found, as data, so the agent does not redo it.

**When L1 does not run.** Under an event profile, an `l1` policy of `manual` or `off` turns it
off.

Keep challenges out of your pack. A folder inside the pack that holds a challenge's files (it has
a `challenge.json` or a `board.json`) is never searched for engines, so that a challenge can never
add a solver to your pack; `l1 route` and `l1 run` refuse a challenge that is inside the pack.

## A pack that needs setup

A pack whose engines need more than its files says so in a `pack.toml` at its top, and
`flightdeck pack install` acts on it:

```toml
name = "my-pack"                     # required: lower-case letters, digits, _ . -
version = "1.0.0"                    # optional
description = "What it solves."      # optional, one line
engines = "flightdeck"               # optional: the only folder searched for *.manifest.toml

[setup]                              # optional
command = "./setup.sh"               # a file of the pack and its arguments, run in the pack's folder

[image]                              # optional
tag = "my-pack:1"
dockerfile = "docker/Dockerfile"     # inside the pack
context = "."                        # inside the pack; default: the Dockerfile's folder

[lanes]                              # optional: the pack as a toolkit for the lanes' models
note = "docs/LANE.md"                # a text file inside the pack; {pack} in it is the pack's folder
```

- `[setup] command` runs on this machine, as you, only when you agree to it.
- `[image]` is the image the pack's engines run in when lanes run in Docker, instead of the lane
  image: `[l1] image` in your config names it, and a run refuses to start while it is not built.
  It needs `bash` and whatever the engines run. flightdeck still mounts the pack read-only and
  gives each engine a container of its own with no network.
- `[lanes] note` is what a lane's brief says about the pack when your config has
  `lane_tools = true` under `[l1]`: your words to the model, at most 3,000 characters, placed
  after the challenge's own text and outside its fence. Under Docker the lanes run in `[l1]
  image` and see the pack, read-only, at the path it has on this machine. Keep the note short:
  it is in every turn's context.
- An unknown key is an error.

## From a gap to a new engine

After a run, `flightdeck gaps RUN_DIR` (or `flightdeck gaps latest`, for the newest run in your
config's `[run] dir`) lists the challenges no engine solved, with the engines that
ran on each and why L1 did not solve it. An engine counts as having solved a challenge only when it
reported `solved`; a `candidate` does not count, even when its flag was right. With `--pack` (and
the board the run played: `--board`, else the one the run recorded) it also routes each gap against
your pack as it is now, and ends each gap in `gaps.md`, and its printed summary, with the build
mode command for it, its challenge folder and your pack filled in and quoted for the shell, ready
to paste. A gap whose challenge is not on the board has no folder, so no command. Build mode turns
a gap into an engine:

```sh
flightdeck build gap ~/ctf/some-board/half-and-half --pack ~/ctf/solvers
```

It writes four things into the pack, and never overwrites a file:

- `misc/misc_half_and_half.py`: the engine, a `solve()` stub for you to fill in;
- `misc/misc_half_and_half.manifest.toml`: its manifest, with one route that describes this
  challenge (its category, a few distinctive words of its description and its files' extensions).
  Widen the route so that challenges like this one reach the engine too;
- `tests/cases/misc_half_and_half/`: the challenge as it was handed out, and the sha256 of its flag
  when the board has an answers file (never the flag itself);
- `tests/test_misc_half_and_half.py`: a test that passes once the router sends the archived
  challenge to the engine and the engine reports `solved` with the right flag.

```sh
flightdeck build check ~/ctf/solvers
```

`build check` runs every such test in the pack and lists the engines passing and failing. It needs
pytest (`pipx install "ctf-flightdeck[build]"`), and the tests get no API keys or tokens from
flightdeck's environment. An engine is done when its test passes.
