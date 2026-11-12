# Boards and event profiles

A **board** is what flightdeck plays: a folder of challenge folders. `flightdeck play FOLDER` opens
one, `flightdeck ctfd pull` writes one from a CTFd site, and the practice set that ships with
flightdeck is one. An **event profile** (`event.toml`) says what an event's rules allow, and how
far flightdeck goes on its own at each stage. This page is the format of both.

## The board folder

```
some-board/
  board.json               optional: the event's name and flag format
  answers.sha256.json      optional: the sha256 of each flag, for checking flags offline
  crab-walk/
    challenge.json         what the challenge is
    postcard.txt           its handout
  welcome-mat/
    challenge.json
    index.html
    portal.js
```

Every folder directly inside the board that holds a `challenge.json` is a challenge, and the rest
of that folder is its handout: the files a lane gets. A lane never works in the handout itself. It
works in a copy, so the board stays as you made it.

A folder with no `challenge.json` is left out, and so is a symlink to a folder. A board with no
challenge folder at all is an error.

To play a challenge from a platform flightdeck does not talk to, make its folder by hand: save
the files, write a `challenge.json`, and submit the flags yourself (see
[Flags without an answers file](#flags-without-an-answers-file)).

## `challenge.json`

```json
{
  "name": "Crab Walk",
  "category": "crypto",
  "points": 50,
  "solves": 312,
  "description": "A postcard from the practice range. Every letter took the same few steps sideways; walk them back.",
  "files": ["postcard.txt"],
  "id": "crab-walk"
}
```

| Key | Required | What it is |
|---|---|---|
| `name` | yes | The challenge's name, as the console shows it. |
| `category` | yes | The category, as the platform names it. `web` (`web exploitation`, `web security`), `crypto` (`cryptography`), `rev` (`reverse`, `reversing`, `reverse engineering`), `pwn` (`pwnable`, `pwnables`, `binary`, `binary exploitation`, `binexp`, `exploitation`), `forensics` (`forensic`, `digital forensics`), `misc` (`miscellaneous`) and `osint` (`open source intelligence`) become the console's short codes `web`, `cry`, `rev`, `pwn`, `for`, `misc` and `osint`, whatever their case and whether the words are joined by spaces, `-` or `_`; any other name is kept, in lower case. |
| `points` | yes | A whole number, 0 or more. Lanes start on the lowest-point challenges first. |
| `solves` | no | How many teams have solved it: a whole number, 0 by default. Among challenges worth the same, the one with more solves starts first. |
| `description` | no | The challenge's text. A lane reads it as data, and the "ignores the hint" alert reads it for the technique it hints at. |
| `files` | no | The handout files, as paths inside the challenge folder. Left out, it is every regular file in the folder and its subfolders, except `challenge.json` itself. |
| `urls` | no | The challenge's live instance, if it has one: web origins such as `"http://127.0.0.1:8080"`, and TCP services such as `"tcp://127.0.0.1:1337"` (what `nc 127.0.0.1 1337` reaches). An origin is a scheme, a host and an optional port, with no path, query or user name; a TCP service needs its port. |
| `id` | no | The challenge's id: lower-case letters, digits, `_`, `.` and `-` (a letter or digit first), at most 64 characters. Left out, it is the folder's name, which must then follow the same rule. Two challenges cannot share an id. |
| `max_attempts` | no | How many tries the platform allows at the flag (0, the default: any number). A flag for a challenge with a limit waits for you, under auto submit too, unless your config says `submit_limited = "auto"` under `[lanes]`. |

A key that is not in this table is an error, so a typo fails loudly instead of being ignored.
So is a `files` entry that does not exist, that leaves the challenge folder (`..` or an absolute
path), or that is or passes through a symlink.

A challenge with `urls` is a **live** challenge. A Docker lane gets a network only when its
challenge is live (the README's [Docker or host](../README.md#docker-or-host) says which network,
and when a lane asks you first), and a lane's http tool reaches only the origins listed here.

## `board.json`

```json
{
  "event": "Practice Range",
  "flag_format": "practice\\{[a-z0-9_]+\\}"
}
```

Both keys are optional, and so is the file.

- `event`: the event's name, shown in the console's header. Without it, the board folder's name.
- `flag_format`: a regular expression (Python's syntax) that the event's flags match, on one line
  and at most 200 characters. flightdeck uses it to spot flags in what lanes and solvers print, and
  every lane reads it in its brief. Without it, flightdeck looks for the common shape
  `word{...}`. An event profile's `flag_format` overrides the board's.

## `answers.sha256.json`

A board can carry its answers, so that flightdeck can check a flag with no platform: the practice
set does, and so can an archive of a past event you want to play again.

```json
{
  "crab-walk": "72bd7c5340cae2cb756a12d8bb1328aef9778dff3c40db2581e8f10676685fc7"
}
```

Each key is a challenge id, and each value is the SHA-256 of that challenge's exact flag, as 64
lower-case hex characters. The file holds hashes, never flags. To make one:

```sh
printf '%s' 'example{the_exact_flag}' | shasum -a 256
```

The file sits in the board folder, beside the challenge folders and never inside one: a lane works
in a copy of its challenge folder and must not find the answers there. `play --answers FILE` names
an answers file kept somewhere else. An answer for a challenge the board does not have is an error
(a stale or mistyped id). A board with answers ends its run with a scorecard, and
`flightdeck score RUN_DIR` scores the run again later.

### Flags without an answers file

Without an answers file, and without a platform flightdeck submits to, flightdeck cannot check a
flag. When a lane finds one, the console shows it and asks you to submit it on the platform
yourself; then press `a` if the platform accepted it or `d` if it did not. The same holds for a
challenge the answers file does not list.

## A board is untrusted

Everything in a board folder comes from someone else: a platform, a challenge author, a teammate.
flightdeck treats all of it as data.

- Nothing in a board is ever run by flightdeck. A lane or one of your solvers may run a handout
  file, inside its own copy (and, in Docker, inside its own container).
- `challenge.json`, `board.json` and the answers file are checked field by field, and a file over
  1 MB is refused.
- Symlinks are never followed, and no path may leave its challenge folder.
- A challenge's text reaches a lane's model fenced as data, never as instructions, and reaches
  your terminal with escape sequences made harmless.

## A board from CTFd

```sh
export CTFD_TOKEN=...                                   # your CTFd API token
flightdeck ctfd pull https://ctf.example.org ~/ctf/example-board
```

`ctfd pull` writes this same format: a folder per challenge with its `challenge.json` and its
downloaded files, and a `board.json`. It also writes `ctfd.json`, flightdeck's own record of which
CTFd challenge each folder is; leave it where it is. `--token-env` names another variable for the
token (its name, never the token), and `--event` and `--flag-format` set `board.json`'s two keys.
Pulling again into the same folder keeps what is there and adds what is new. It exits with status
1 when some challenges could not be pulled (each is named, with the reason), and 2 when the pull
could not start or finish.

You rarely need it: `flightdeck play FOLDER --event event.toml` pulls the board itself.
A CTFd board has no answers file, since CTFd checks the flags.

## The event profile: `event.toml`

An event profile says what one event's rules allow. Write it from the rules, check it, and play
by it:

```sh
flightdeck preflight --example > event.toml     # a commented profile to edit
flightdeck preflight event.toml                  # what flightdeck will do at each stage, and any problem
flightdeck play ~/ctf/example-board --event event.toml
```

The profile holds no secret: it names the environment variable that holds your CTFd token, never
the token.

```toml
[event]
name = "Example CTF"
platform = "ctfd"                   # "ctfd": flightdeck uses CTFd's API; "manual": a folder board
url = "https://ctf.example.org"     # ctfd: the site's address
token_env = "CTFD_TOKEN"            # ctfd: the NAME of the variable that holds your API token
# board = "board"                   # manual: the folder of challenge folders (relative to this file, or ~/...)
flag_format = "example\\{[^}]+\\}"  # a regular expression for the event's flags
team = false                        # true: team mode (claims, teammates' solves, live-box holds)

[rules]
ai_allowed = true                   # may model-driven lanes work challenges
platform_automation = true          # may flightdeck pull and submit through the platform's API
live_targets = "confirm"            # "allowed", "confirm" or "off": may lanes touch challenge instances
# max_lanes = 8                     # if the rules limit how many agents run at once

[policies]                          # optional
# pull = "auto"
# l1 = "auto"
# agents = "auto"
# submit = "confirm"
# instance = "confirm"
```

`[event]` says where the board comes from. With `platform = "ctfd"`, flightdeck pulls the board
from `url` into the folder you give `play`. With `platform = "manual"`, `board` names a folder
board you made, and you submit the flags on the platform yourself.

`[rules]` is what the event allows. `[policies]` is how far flightdeck goes on its own at each of
five stages, and it can be stricter than the rules, never looser: `preflight` and `play` refuse a
profile that asks for more than its rules allow.

| Stage | What it is |
|---|---|
| `pull` | Getting the board, and later waves of challenges, from the platform. |
| `l1` | Running your own no-model solvers ([SOLVERS.md](SOLVERS.md)). |
| `agents` | Starting model-driven lanes. |
| `submit` | Submitting flags to the platform. |
| `instance` | Lanes reaching a challenge's live instance. |

Each stage has one of four policies, from loosest to strictest:

| Policy | What it means |
|---|---|
| `auto` | flightdeck does it. |
| `confirm` | flightdeck prepares it, and you say yes first. |
| `manual` | You do it; flightdeck says what to do. |
| `off` | Nobody does it through flightdeck. |

The rules set the loosest policy a stage may have:

- `ai_allowed = false` makes `agents` off. `play` is agent lanes, so it does not start with
  `agents` at `manual` or `off`.
- `platform_automation = false` makes `pull` and `submit` manual: you put the challenges in the
  board folder, and you submit each flag and tell flightdeck how it went. flightdeck then has no
  use for CTFd's API, so such a profile must say `platform = "manual"` and name its `board`; a
  `ctfd` profile that may not pull is refused.
- `live_targets` makes `instance` `auto` (for `"allowed"`), `confirm` or `off`.

A stage you leave out of `[policies]` gets the loosest policy its rules allow, except `submit`,
which gets `confirm`: a flag goes to the platform only after you approve it, unless you ask for
`auto`.

What the policies mean during a run:

- **pull**: under `auto`, flightdeck pulls the board before the console opens and adds new waves
  as they appear. Under `confirm` it pulls once, after you say yes.
- **l1** and **agents**: under `confirm`, starting `play` is your yes. With `l1` at `manual` or
  `off`, your solver pack does not run.
- **submit**: under `confirm`, every flag waits for your `a`. Under `auto`, a flag a lane submits
  goes at once, with the exceptions the README lists under
  [Play a board](../README.md#play-a-board).
- **instance**: under `confirm`, a lane whose challenge is live asks you before its first model
  call, and until you allow it a Docker lane has no network. Under `manual` or `off`, lanes never
  reach the instance.

`rules.max_lanes` caps how many lanes run at once, and `team = true` asks for a team folder
(`play --team-dir`).
