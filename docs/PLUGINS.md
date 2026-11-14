# Plugins

flightdeck talks to CTFd and to a Game Master. A **plugin** lets it play an event on any other
platform: a small program of your own that pulls the board, submits a flag and reads the solved
list, which flightdeck runs when it needs one of the three. You write it for the platform in
front of you, usually in an afternoon, and flightdeck does the rest as it does for CTFd: the
queue, the lanes, your approvals, the resend of a rate-limited flag, the solved list.

A plugin is not a solver pack and not a CTFd plugin:

- A **pack** ([SOLVERS.md](SOLVERS.md)) is your no-model solvers, which work a challenge. A
  plugin never sees a challenge's files being worked; it only talks to the platform.
- A **CTFd container plugin** is part of a CTFd site, which starts a challenge's instance
  ([BOARDS.md](BOARDS.md#instances-on-demand)). flightdeck starts instances only on CTFd, never
  through a plugin of yours.

## In short

```sh
flightdeck plugin new myctf                 # writes ./myctf/: plugin.toml, adapter.py, event.example.toml
$EDITOR myctf/adapter.py                    # put the platform's own routes in
flightdeck plugin add ./myctf               # shows what it runs and gets, asks, and allows it in your config
flightdeck plugin pull quals/event.toml     # pulls the board and reads the solved list; submits nothing
flightdeck play --event quals/event.toml    # plays it
```

`plugin add` shows this before it asks:

```
  plugin    myctf 0.1.0 (plugin API 1): myctf events
  folder    /home/you/ctf/myctf
  provides  platform "myctf"   (event.toml: platform = "myctf")
  runs      <flightdeck's python> adapter.py   in that folder: for each pull, each flag, and each minute for the solved list
  gets      the event's URL, its token (the variable event.token_env names), the flags it submits
  not given your model API keys or the rest of your environment
  flightdeck does not sandbox a plugin: it runs as you, and can read your files and use the network. Read its files first.
  Enable it? [y/N]:
```

A yes adds two lines to your config, and nothing else allows a plugin:

```toml
[plugins.myctf]
path = "/home/you/ctf/myctf"
```

`--yes` answers yes. With no terminal to ask at and no `--yes`, `add` stops and your config is
as it was. If the config does not load with the new table in it, it is put back. To stop
allowing a plugin, take its table out of the config.

`plugin new NAME [--dir DIR]` writes `DIR/NAME/` (default: this folder) and never writes over a
folder that is there. `flightdeck doctor` has a line for each plugin your config allows: the
platform it provides and what runs for it, or what is wrong with it.

## `plugin.toml`

```toml
name = "myctf"                          # the platform's name: event.toml says platform = "myctf"
api = 1                                 # the plugin API this adapter speaks
command = ["{python}", "adapter.py"]    # what flightdeck runs, once per call, in the plugin's folder
version = "0.1.0"                       # optional
description = "MyCTF events"            # optional
token = true                            # optional
```

| Key | Required | What it is |
|---|---|---|
| `name` | yes | The platform's name, which an event profile's `platform` selects: lower-case letters, digits, `-` and `_`, starting with a letter, at most 32 characters. Not `ctfd`, `manual` or `gamemaster`. It must be the name of its `[plugins.NAME]` table in your config. |
| `api` | yes | The plugin API it speaks, a whole number. This flightdeck speaks 1. |
| `command` | yes | A list of words, at most 32: the program and its arguments. The first word is `{python}` (flightdeck's own interpreter), a file inside the plugin's folder (it must be executable, and no link may lead out of the folder), or a program on your `PATH`. |
| `version` | no | One line of at most 32 characters, shown by `plugin add`. |
| `description` | no | At most 200 characters, shown by `plugin add`. |
| `token` | no | `true` (the default): an event on this platform must name `token_env`. `false`: the platform needs no token, and the program gets none. |

A key that is not in this table is an error, and so is a file over 64 KiB. The program is found
when the file is read, so a plugin that cannot run fails at `plugin add`, in `doctor` and before
a run starts, with the reason.

`{python}` promises the standard library and nothing more: the example below uses `urllib`. A
plugin that needs other packages names its own launcher in `command`.

## The event profile

An event on a plugin's platform has an ordinary `event.toml`
([BOARDS.md](BOARDS.md#the-event-profile-eventtoml)); `plugin new` writes an example to copy.

```toml
[event]
name = "Quals"
platform = "myctf"                  # the plugin you added
url = "https://ctf.example.org"     # the address the adapter talks to
token_env = "MYCTF_TOKEN"           # the NAME of the variable that holds your token, never the token
board = "board"                     # the folder the challenges are pulled into: inside this file's folder

[rules]
ai_allowed = true
platform_automation = true
live_targets = "confirm"
```

The profile only selects the plugin. A profile may be a teammate's, so it cannot allow one: a
`platform` that is not `ctfd`, `manual` or `gamemaster` and not a plugin in **your** config is
refused, by `flightdeck preflight` and by `play`. It is never played as a folder board in its
place, and nothing shows the profile's word for it until your config has made it a name.

The token is read from the variable `token_env` names, in your environment or your keys file,
as a CTFd token is. Its value is handed to the plugin, and the profile that names the variable
may be someone else's, so the only variable a profile can name is one named for the plugin:
its name starts with the plugin's name in capitals and a `_` (`MYCTF_TOKEN`, `MYCTF_TOKEN_QUALS`;
`-` in the name is `_`). Any other name is refused (`CTFD_TOKEN`, `NPM_TOKEN`, another event's
token), and so is a variable your config names for a secret of its own (a model key in `[api]`,
`[fallback]` or `[light]`, the `[notify]` webhook) and a well-known key of another service
(`OPENAI_API_KEY`), whatever its name.

The profile also names the address (`url`), as a CTFd profile does: the plugin is handed your
token together with that address. flightdeck does not know which site a token is for, so
read the first lines `flightdeck preflight EVENT.toml` and `play` print before you run a
profile you did not write: `acme (a plugin) at <address>` and `token $ACME_TOKEN (set), given
only to the acme plugin, for <address>`. An `http` address is warned of, by a run's pre-flight
and by `flightdeck plugin pull`: the token would cross the network unencrypted.

What each policy does on a plugin's platform:

| Stage | Policy | What happens |
|---|---|---|
| `pull` | `auto` | flightdeck pulls the board through the plugin before the console opens, and again every 5 minutes. |
| `pull` | `confirm` | It pulls once, after you say yes, and no more during the run. |
| `pull` | `manual`, `off` | The run pulls nothing: it plays the board `flightdeck plugin pull` wrote. |
| `submit` | `auto`, `confirm` | Flags go to the platform through the plugin (`confirm`: each after you approve it). |
| `submit` | `manual`, `off` | flightdeck shows each flag; you submit it on the site and say how it went. |

Whenever the run uses the plugin, for pulling or for submitting, it also reads the solved list
through it: once before the console opens, then every minute. A challenge the platform lists as
solved starts no lane, and one solved during the run stops its lanes. A profile whose policies
use the plugin for nothing (pull and submit both by hand) plays as a board you fill yourself,
and `preflight` says so. `rules.platform_automation = false` makes that the case, and
`flightdeck plugin pull` refuses such a profile.

`/new` and `/attach` are off on a board a plugin fills: its challenges come from the platform.
`flightdeck start` and the home screen's form do not know plugins yet; write the profile from
`event.example.toml`.

## The three calls (plugin API 1)

For every call flightdeck starts the program once, with the plugin's folder as its working
directory, writes one JSON object to its stdin, and reads its stdout:

- **It worked:** exactly one JSON object on stdout, and exit status 0. Nothing else may go to
  stdout: write what you want to see while debugging to stderr.
- **It failed:** a non-zero exit status, with the reason on stderr. flightdeck shows the last
  line of it.

The event's token is in the environment variable `FLIGHTDECK_PLUGIN_TOKEN`, never on the
command line and never in the request. The rest of the program's environment is these
variables of yours, when they are set, and nothing else: `PATH`, `HOME`, `LANG`, `LC_ALL`,
`LC_CTYPE`, `TMPDIR`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`
(and their lower-case forms), plus `FLIGHTDECK_PLUGIN_API`, which is `1`.

Every request has `"api": 1`, the `op`, the event's `name` from the profile as `event`, and its
`url`. Calls never overlap: a pull, a submit and a read of the solved list each wait their turn.

| Call | May take | Answer may be |
|---|---|---|
| `pull` | 300 seconds | 8 MB |
| `submit` | 30 seconds | 1 MB |
| `solved` | 30 seconds | 1 MB |

When the time is up, the program and everything it started are killed.

### `pull`

```json
{"api": 1, "op": "pull", "event": "Quals", "url": "https://ctf.example.org",
 "files": "/home/you/ctf/quals/.plugin-pull-x1/files", "known": ["17"]}
```

```json
{"challenges": [
   {"ref": "17", "name": "Warm Up", "category": "misc", "points": 50, "description": "...",
    "files": ["17/chal.zip"], "urls": ["https://warmup.ctf.example.org"], "solves": 3, "max_attempts": 0}
 ],
 "notes": ["2 challenges are locked"]}
```

List every challenge the platform shows you. For each:

| Key | Required | What it is |
|---|---|---|
| `ref` | yes | The platform's own id for the challenge, as a string of 1 to 128 printable characters. `submit` is sent it back, and `solved` lists these. |
| `name` | yes | The challenge's name. |
| `category`, `points`, `description`, `solves`, `urls`, `max_attempts` | no | As in a board's [`challenge.json`](BOARDS.md#challengejson), and checked by the same rules. Left out, the category is `misc` and the points are 0. |
| `files` | no | The handout files you downloaded into the folder `files` names, each as a path relative to that folder. |

Download each file into the `files` folder of the request and list where you put it. A file
must be a regular file inside that folder (no `..`, no absolute path, no link) of at most
1 GiB; it lands in the challenge's folder under its own name, so two files of one challenge
cannot share a name. The refs in `known` are on the board already: their files need no second
download. `notes` is optional: up to 20 lines for the player (flightdeck shows them once).

The plugin never writes the board. flightdeck makes each new challenge's folder itself, reads
it back with the checks every board gets ([BOARDS.md](BOARDS.md#a-board-is-untrusted)) and only
then moves it into the board. A challenge that does not pass (an unknown key, a bad `urls`
entry, a file that is not there) is left out and named, with the reason; the others land. A
challenge already on the board is never changed by a later pull: a pull only adds.

One pull lists at most 1,000 challenges, the ones already on the board included: an answer
with more is refused whole and nothing is added (`its answer lists 1,200 challenges, more than
the 1,000 flightdeck takes from one pull`), so a plugin for a larger platform lists the event's
own challenges. Of the challenges left out, the first 20 are named and the rest counted. In a
run the folders are written off the console's loop: lanes go on while a large board lands.

### `submit`

```json
{"api": 1, "op": "submit", "event": "Quals", "url": "https://ctf.example.org", "ref": "17", "flag": "flag{...}"}
```

```json
{"verdict": "incorrect", "detail": "Wrong flag", "tries_left": 2}
```

`verdict` is one of five words. `detail` (the platform's own words), `tries_left` (a whole
number) and `retry_after` (seconds) are optional.

| Verdict | Say it when | What flightdeck does |
|---|---|---|
| `correct` | The platform accepted the flag. | The challenge is solved. |
| `incorrect` | The platform judged the flag and rejected it. | The flag is recorded as wrong and is never sent again. |
| `already_solved` | The platform says the challenge is solved already. | The challenge is closed as solved on the platform. |
| `rate_limited` | The platform refused to judge it for now. | The same flag is sent again: after `retry_after` plus a second (at most 5 minutes), or 65 seconds when you give none, up to 3 more times. Never when the challenge counts its tries (`max_attempts`, or a `tries_left` in the answer). |
| `unjudged` | Anything else: a reply you do not recognise, a locked challenge, an expired session. | No verdict: the flag comes back to you to submit by hand, and is never recorded as wrong. |

Answer `unjudged` whenever the platform's reply is not clearly one of the others. A call that
fails, runs out of time, or answers anything the API does not know is treated the same way: the
flag is yours again, a warning says why, and autopilot hands the controls back. Once an answer
gives `tries_left`, the challenge's tries are counted: its flags wait for you, under auto submit
too, and at 0 the challenge is closed.

### `solved`

```json
{"api": 1, "op": "solved", "event": "Quals", "url": "https://ctf.example.org"}
```

```json
{"solved": ["17", "23"]}
```

The refs of the challenges the platform lists as solved for your account or team.

## The example adapter

What `plugin new` writes, with placeholder routes to replace by the platform's own:

```python
import json
import os
import sys
import urllib.request

req = json.load(sys.stdin)


def api(path, body=None):
    request = urllib.request.Request(
        req["url"] + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + os.environ["FLIGHTDECK_PLUGIN_TOKEN"], "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=20) as reply:
        return json.load(reply)


if req["op"] == "pull":
    out = {"challenges": [
        {"ref": str(task["id"]), "name": task["title"], "category": task["category"], "points": task["points"],
         "description": task["text"], "files": [], "urls": task.get("urls", [])}
        for task in api("/api/tasks")
    ]}
elif req["op"] == "submit":
    word = api(f"/api/tasks/{req['ref']}/flag", {"flag": req["flag"]})["status"]
    out = {"verdict": {"ok": "correct", "bad": "incorrect", "dup": "already_solved"}.get(word, "unjudged"), "detail": word}
elif req["op"] == "solved":
    out = {"solved": [str(task["id"]) for task in api("/api/tasks") if task.get("solved")]}
else:
    sys.exit("unknown op")
json.dump(out, sys.stdout)
```

An uncaught error is already a correct failure: Python exits with status 1 and its last line
goes to stderr.

## The board a plugin fills

The board is an ordinary board folder ([BOARDS.md](BOARDS.md)), one folder per challenge, named
from the challenge's name (from its ref when the name has no letter or digit). Beside them
flightdeck keeps `plugin.json`, its own record of which plugin pulled the board, from which
address, and each folder's ref; leave it where it is.

```json
{"format": 1, "plugin": "myctf", "url": "https://ctf.example.org", "refs": {"warm-up": "17"}}
```

`flightdeck plugin pull EVENT.toml [FOLDER]` pulls into `event.board` (or `FOLDER`), reads the
solved list, and says what it found:

```
pulled into quals/board: 14 challenges (web 4, cry 3, misc 7), 2 listed as solved; nothing was submitted
```

It exits with status 1 when some challenges were left out (each is named, with the reason) and
2 when the pull could not start or the plugin's call failed. Pulling again adds what is new. A
run that is playing the board picks up what a pull in another terminal added, within seconds.

A folder that holds something else is refused: one that is not empty and has no `plugin.json`,
and a board pulled by another plugin or from another address. Flags would go to the wrong
place; use a new folder.

`event.board` must be a folder inside the profile's own folder (links followed). A pull makes
the folder and writes the platform's files into it, under `pull = "auto"` without a question,
and a profile may be someone else's: it cannot point a pull at another folder of your machine.
For a board elsewhere, leave `board` out of the profile and name the folder yourself:
`flightdeck plugin pull EVENT.toml FOLDER`, `flightdeck play FOLDER --event EVENT.toml`.

## Trust

A plugin is code you choose to run, so the choice is made visible and is yours alone:

- **Only your config allows one.** `[plugins.NAME]` is written by `plugin add` after it showed
  you what the plugin runs. An event profile, a board and a challenge cannot add or change it.
- **flightdeck never fetches one.** It does not download, install or update a plugin. You put
  the folder there, and you can read every file in it.
- **It is not sandboxed.** The program runs on this machine, as you. flightdeck does not hand it
  your model API keys or anything else from your environment, but a program that runs as you
  can read your files and use the network. Read a plugin before you add it, as you would any
  script, and again when someone sends you a new version.
- **It gets what it needs and no more:** the event's URL, the event's token, the board's refs,
  and each flag flightdeck submits through it.
- **What it says is untrusted.** Every string from a plugin (its answers, its stderr, the keys
  of its JSON) has the token's value cut out and is made safe to show before it reaches the
  console or a log. What it lists as challenges is read back as any untrusted board.
- **Nothing of it is imported.** It is a separate process each time, so it cannot stall the
  console: a call that hangs is killed at its time limit.

flightdeck itself contacts only the model API and the platform you configure. A plugin that
contacts anything else breaks that promise for the events you play with it: that is one of the
things to look for when you read one.

## When something is wrong

Each of these names the plugin and says what to do.

- **The plugin cannot be used** (`plugin add`, `doctor`, `preflight`, the start of a run):
  `plugin myctf: /home/you/ctf/myctf/plugin.toml: no such file`; `... unknown key comand
  (known: name, api, command, version, description, token)`; `... says another name than
  [plugins.myctf] in your config: the two must match`; `plugin myctf speaks plugin API 2, and
  this flightdeck (0.4.0) speaks 1: update flightdeck, or use the plugin's release for API 1`;
  `plugin myctf: command names a file outside the plugin's folder`; `plugin myctf: command's
  program is not in the plugin's folder and not on PATH`.
- **The profile names no plugin of yours:** `event.platform is not "ctfd", "manual" or
  "gamemaster", and names no plugin in your config (your config has: myctf). ` followed by how
  to add one.
- **The profile is missing something:** `event.url is required for a plugin's platform: the
  address its adapter talks to`; `event.token_env is required for platform "myctf": the name of
  the environment variable that holds your token`.
- **A run cannot start:** `the myctf plugin could not pull the board: <why>; nothing was
  started`; `could not read the solved list from the myctf plugin: <why>; nothing was started`;
  `<board> was not pulled by the myctf plugin, so flightdeck has nowhere to send its flags:
  \`flightdeck plugin pull EVENT.toml\` first, or set policies.pull to auto or confirm`.
- **During a run** (warnings, each said once while it lasts): `the myctf plugin did not judge
  <flag> for <challenge>: <why>`; `could not read the solved list from the myctf plugin: <why>;
  flightdeck reads it again in 60 s`; `the myctf plugin could not pull new challenges: <why>;
  flightdeck pulls again in 300 s`; `myctf: not added: <challenge>: <why>`.

`<why>` is what the call did: `it exited with status 1: <the last line of its stderr>`, `it
gave no answer within 30 s`, `its answer is not one JSON object`, `its answer has an unknown key
...`, `verdict must be one of correct, incorrect, already_solved, rate_limited, unjudged`. After
a submit that ran out of time the warning adds that the flag may have reached the platform:
check the challenge there before you submit it again.

## Test yours

Build the adapter against a stand-in for the platform on your own machine, not against a live
event: a wrong `submit` there spends real tries. A call is easy to make by hand:

```sh
cd myctf
echo '{"api": 1, "op": "solved", "event": "Test", "url": "http://127.0.0.1:8000"}' \
  | FLIGHTDECK_PLUGIN_TOKEN=test python3 adapter.py
```

Then `flightdeck plugin add ./myctf`, `flightdeck preflight EVENT.toml` (which runs nothing of
the plugin) and `flightdeck plugin pull EVENT.toml`, which is the first time flightdeck runs it
and submits nothing. flightdeck's own tests run the skeleton `plugin new` writes against a
stand-in on 127.0.0.1; no plugin has been run against a real platform yet, so tell us how
yours went ([CONTRIBUTING.md](../CONTRIBUTING.md)).
