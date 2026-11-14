# Boards and event profiles

A **board** is what flightdeck plays: a folder of challenge folders. `flightdeck play FOLDER` opens
one, `flightdeck ctfd pull` writes one from a CTFd site (`gm pull` from a Game Master, `plugin
pull` through a plugin of yours), and the practice set that ships with flightdeck is one. An **event profile** (`event.toml`) says what an event's rules allow, and how
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
| `instance` | no | `"on-demand"`: the challenge has no fixed address; the platform starts its instance (a container for your team) when asked. No lane starts on it until the instance is up, and then its address is the challenge's `urls` for the run. flightdeck starts it only where an event profile says how ([Instances on demand](#instances-on-demand)). |
| `type` | no | The platform's own name for the challenge's type (CTFd's `type`, such as `dynamic` or a plugin's `container`): letters, digits, `_`, `.` and `-`. `ctfd pull` writes it when it is not `standard`; an event profile's `[instances] types` reads it. |
| `rotates` | no | How often the challenge's flag rotates, in whole seconds (0, the default: it does not; at most 86400). See [Rotating flags](#rotating-flags). |

A key that is not in this table is an error, so a typo fails loudly instead of being ignored.
So is a `files` entry that does not exist, that leaves the challenge folder (`..` or an absolute
path), or that is or passes through a symlink.

A challenge with `urls` is a **live** challenge. A Docker lane gets a network only when its
challenge is live (the guide's [Docker or host](GUIDE.md#docker-or-host) says which network,
and when a lane asks you first), and a lane's http tool reaches only the origins listed here.

### Rotating flags

Some challenges hand out a flag that changes every N seconds on clock boundaries (with
`"rotates": 300`: at :00, :05, :10 and so on): a flag fetched at 16:04:58 is dead at 16:05:02.
Say so in the challenge's `challenge.json`, and flightdeck plays it by that rule:

- the lane is told to fetch the flag immediately before submitting, to script the fetch, and
  never to reuse an earlier one;
- a flag is sent only in the window a lane found it in. One that waited into a later window (for
  your approval, or in line behind another flag) is not sent, and neither is one whose window
  ends within 8 seconds: the lane is told it rotated out and to fetch and submit a fresh one, a
  warning says so, and nothing is counted as wrong;
- a flag the platform does call wrong is remembered and never sent again, but the first 6 at such
  a challenge do not count toward the wrong-answer stop (`wrong_stop`): a miss there is usually a
  rotation, not a guess. From the seventh on they count like any other.

Under the submit policy `confirm` a rotating flag will usually rotate out while it waits for your
approval (a run that starts that way says so); `--submit auto` avoids it.

The windows are counted on this machine's clock. If the platform's clock differs from yours, its
boundaries fall that much earlier or later than flightdeck thinks: keep your clock synchronised.

A CTFd pull does not know which challenges rotate: add `"rotates"` to the pulled challenge's
`challenge.json` yourself. A later pull or wave keeps the folder as it is, your key included. A
run reads the key when it puts the challenge on its board: pull the board first
(`flightdeck ctfd pull`), add the key, then play. A challenge that a wave brings during a run is
played without the key in that run.

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
`flightdeck score RUN_DIR` scores the run again later (`flightdeck score latest`: the newest run in
your config's `[run] dir`).

### Flags without an answers file

Without an answers file, and without a platform flightdeck submits to, flightdeck cannot check a
flag. When a lane finds one, the console shows it and asks you to submit it on the platform
yourself; then press `a` if the platform accepted it or `d` if it did not. The same holds for a
challenge the answers file does not list.

## A series of challenges

A board often splits one lab into several challenges on the same target. flightdeck links them by
name alone: two challenges are siblings when their names have the same start, compared in lower
case with punctuation folded to spaces. The start is

- the part before the first separator: a colon followed by a space, a hyphen or a bar with a space
  on both sides, or an en or em dash ("Harbor Lab: Read the Certificate", "Harbor Lab - The Gate",
  "Ghost Ship | Logbook"), or
- with no separator, the part before a trailing part number ("Harbor Lab Part 3", "Harbor Lab
  Task 2", "Harbor Lab (2/3)").

A start that is only a category or a label ("Web: SQL Login", "Warmup: Hello"), only a part
number ("Task 2 - Read it"), or shorter than three letters and digits links nothing.

A lane on a challenge of a series is told of its siblings and may read the files a sibling's
ended lane left ([the guide](GUIDE.md#play-a-board)). A challenge whose description reads as a
continuation ("continuation of the same lab", "see the first task") while no other challenge
shares the start of its name is told so, and its lane's log says it: name the challenges of one
lab alike when you write a board by hand.

## A board is untrusted

Everything in a board folder comes from someone else: a platform, a challenge author, a teammate.
flightdeck treats all of it as data.

- Nothing in a board is ever run by flightdeck. A lane or one of your solvers may run a handout
  file, inside its own copy (and, in Docker, inside its own container).
- `challenge.json`, `board.json` and the answers file are checked field by field, and a file over
  1 MB is refused.
- Symlinks are never followed, and no path may leave its challenge folder.
- A challenge's text reaches a lane's model fenced as data, never as instructions, and reaches
  your terminal with escape sequences made harmless. What one lane hands another (what it tried,
  a sibling challenge's files) is challenge-derived, and is fenced and named as data the same way.

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

## A board from a Game Master

A Game Master is a platform that is one URL. A challenge there is an attempt: it must be started
before its files and questions can be read, it takes one or more answers, and an answer is often
a name, a hash or a number, not a flag.

```sh
export GM_TOKEN=...                                     # your Game Master token
flightdeck gm list https://gm.example.org               # every challenge: id, lane, mode, solved or open
flightdeck gm pull https://gm.example.org ~/ctf/gm-board
flightdeck gm pull https://gm.example.org ~/ctf/gm-board --start
```

`gm pull` writes the same folder format, from the attempts that are started:

- **It starts nothing unless you say so.** Without `--start`, every attempt that is not started is
  left out and named, with the reason. With `--start`, each one that runs no clock is started and
  pulled.
- **It never starts a clock.** An attempt whose id ends in `/time_trial` or `/mastery` (or whose
  listed mode is one of those) starts a clock when it starts. flightdeck never starts one: start
  it on the Game Master yourself, then pull again, and its deadline is in the challenge's
  description.
- **One board challenge per answer.** An attempt with one answer is one challenge. An attempt with
  several is one challenge per answer id, named `Name (answer id)`, each with a copy of the
  attempt's files and its own question.
- **Answers are submitted as `answer{...}`.** flightdeck checks every candidate against the
  board's flag format before it goes anywhere, so a Game Master board's flag format says what an
  answer looks like. A new board gets `answer\{(?P<answer>[^{}\r\n]{1,200})\}`: a lane submits
  `answer{Alice Example}`, and what the group named `answer` matched, `Alice Example`, is what
  the Game Master is sent. `--flag-format` sets another; a format with no `answer` group sends
  the whole match (`[0-9a-f]{32}` for an event whose answers are all hashes). Keep it narrow: a
  format that matches ordinary prose makes every sentence a candidate.

It also writes `gm.json`, flightdeck's own record of which Game Master challenge and answer id
each folder is; leave it where it is. `--token-env` names another variable for the token, and
`--event` sets the board's name. Pulling again keeps what is there and adds what is new. It
exits with status 1 when some challenges could not be pulled, and 2 when the pull could not start
or finish, or nothing is started.

`flightdeck play ~/ctf/gm-board` plays that board with you submitting each answer by hand. With an
event profile whose platform is `gamemaster` (below), flightdeck submits them.

## A board from a plugin

For a platform that is neither CTFd nor a Game Master, and that an `[http]` table cannot
describe ([the next section](#a-board-from-a-platform-with-a-json-api)), a plugin of your own
does the talking ([PLUGINS.md](PLUGINS.md)): flightdeck runs its program to list the challenges and download
their files, and writes the board itself.

```sh
export MYCTF_TOKEN=...                          # the variable event.toml names (never the token itself)
flightdeck plugin pull ~/ctf/quals/event.toml   # into the profile's board folder; submits nothing
```

`plugin pull` writes this same format: a folder per challenge with its `challenge.json` and its
files. The plugin never writes into the board: it downloads into a staging folder and says what
each challenge is, and flightdeck builds each folder, reads it back with every check on this
page ([A board is untrusted](#a-board-is-untrusted)) and only then moves it in. A challenge that
does not pass is left out and named, with the reason, and the others land.

It also writes `plugin.json`, flightdeck's own record of which plugin pulled the board, from
which address, and which challenge on the platform each folder is; leave it where it is. A
folder's name comes from the challenge's name (from the platform's id for it when the name has
no letter or digit). Pulling again keeps what is there and adds what is new; a challenge on the
board is never changed by a later pull. A folder that already holds something else (files and no
`plugin.json`, or a board pulled by another plugin or from another address) is refused: use a
new folder. It exits with status 1 when some challenges were left out, and 2 when the pull could
not start or the plugin's call failed.

You rarely need it before a run: with `pull = "auto"` or `"confirm"` in the profile, `flightdeck
play --event event.toml` pulls the board itself. A plugin's board has no answers file, since the
platform checks the flags.

## A board from a platform with a JSON API

Many platforms have no adapter in flightdeck, but their own web page talks JSON to the site.
For those, the event profile can say how that API is asked, and flightdeck does the talking
itself: `platform = "http"` and an `[http]` table. No program of yours runs and there is no
plugin to trust. rCTF ships as a preset.

```sh
flightdeck http example > ~/ctf/quals/event.toml   # a profile with the rctf preset (--routes: every route written out)
export RCTF_TOKEN='https://ctf.example.org/login?token=...'   # rCTF: your team's login link, whole (or the token alone)
flightdeck preflight ~/ctf/quals/event.toml         # every request a run would make, and where your token goes
flightdeck http check ~/ctf/quals/event.toml        # signs in, lists, reads the solved list; submits nothing
flightdeck play --event ~/ctf/quals/event.toml
```

```toml
[event]
name = "Example Quals"
platform = "http"
url = "https://ctf.example.org"     # the platform's address: every route is a path under it
token_env = "RCTF_TOKEN"            # the NAME of the variable that holds your token
board = "board"                     # the folder the challenges are pulled into, beside this file

[http]
preset = "rctf"                     # rCTF's routes; a key you write under [http] wins over the preset's
```

It plays as a plugin's platform does. Under `pull = "auto"` flightdeck pulls the board before
the console opens and again every 5 minutes; under `"confirm"`, once, after your yes; under
`manual` or `off` the run pulls nothing and plays what `flightdeck http pull EVENT.toml
[FOLDER]` wrote. Under `submit = "confirm"` or `"auto"` flags go to the platform, one at a
time, and a rate-limited flag is sent again after the wait the platform names. Whenever the
run uses the platform it reads the solved list each minute. The board is the same folder
format, with a `plugin.json` beside the challenges that says `"plugin": "http"`, the address
and each folder's id on the platform; `/new` and `/attach` are off on it.

`preset = "rctf"` covers rCTF as its own source has it (`/api/v1`, which its successor keeps):
a sign-in that turns the team token into a session token, the challenge list, files, submit
and the team's solves. Your token there is the one in your team's login link (the "Team
Invite" link on rCTF's profile page, `/login?token=...`). Put the whole link in the variable,
in quotes: the link writes the token percent-encoded (`%2B` for `+`, `%2F` for `/`, `%3D` for
`=`) and rCTF's sign-in takes it only decoded, so flightdeck takes the `token` out of the link
and decodes it. The token copied out of the link works too, encoded or not. A link to another
site than `event.url` is refused: its token is that site's. The preset was built against a
stand-in that answers in rCTF's shape; nobody has played a real rCTF event through it yet, so
run `http check` first. flightdeck counts no tries there: rCTF has none.

`preset = "rctf2"` is for rCTF v2 (OtterSec's rewrite of 2026). It is the same table, but it
lists the challenges from `/api/v2/challs`, which also says which challenges have an instance
the site starts for your team, and marks each of those on-demand on the board. With
`plugin = "rctf"` under `[instances]`, flightdeck then starts those instances itself
([Instances on demand](#instances-on-demand)). The token variable is named as for `rctf`
(`RCTF_TOKEN`). An event on the older rCTF has no `/api/v2`: keep `preset = "rctf"` there. Its
instances usually come from a separate site (klodd) whose start wants a CAPTCHA every time,
so start them on that site yourself.

### The `[http]` table

For another platform, write the routes yourself: its browser's network tab shows them.
`flightdeck http example --routes` prints rCTF's table to edit. A request is `[METHOD, PATH]`;
a path into an answer is `$` followed by `.name`, `['name']`, `[n]`, `[*]` or `.*`. A quoted name
may not hold a control or invisible character (the pre-flight shows the path as it is written).

```toml
[http]
# game = "12"                           # the value of {game} in a route, for a platform with an id per event
# files_auth = false                    # true: a file on the event's own address is asked for with the token

[http.auth]
kind = "exchange"                       # "bearer", "token", "header", "cookie" or "exchange"
request = ["POST", "/api/v1/auth/login"]
body = { teamToken = "{token}" }
token_path = "$.data.authToken"
scheme = "Bearer"
link_param = "token"                    # the token is handed out in a link, as this query parameter

[http.list]
request = ["GET", "/api/v1/challs"]
items = "$.data[*]"                     # one match per challenge
ref = "$.id"                            # from here on, relative to one challenge
name = "$.name"
category = "$.category"
points = "$.points"
description = "$.description"
file_urls = "$.files[*].url"
file_names = "$.files[*].name"

[http.submit]
request = ["POST", "/api/v1/challs/{ref}/submit"]
body = { flag = "{flag}" }
verdict_path = "$.kind"
detail_path = "$.message"
retry_after_path = "$.data.timeLeft"
retry_after_unit = "ms"

[http.submit.verdicts]                  # a value this table does not name is no verdict
goodFlag = "correct"
badFlag = "incorrect"
badAlreadySolvedChallenge = "already_solved"
badRateLimit = "rate_limited"

[http.solved]
request = ["GET", "/api/v1/users/me"]
refs = "$.data.solves[*].id"
```

| Key | What it is |
|---|---|
| `auth.kind` | `bearer`: `Authorization: Bearer TOKEN`. `token`: `Authorization: Token TOKEN`. `header`, with `header = "X-Api-Key"`: the token in that header. `cookie`, with `cookie = "session"`: the token as that cookie's value. `exchange`: one sign-in request (`request`, a `body` with `{token}` in it), whose answer holds a session token at `token_path`; that is then sent as `Authorization: SCHEME TOKEN` (`scheme`: `Bearer` or `Token`). |
| `auth.link_param` | Optional, for a platform that hands the token out in a link (rCTF's `/login?token=...`): the name of that query parameter. The token variable may then hold the whole link, whose host must be `event.url`'s, or the token as the link writes it: flightdeck takes the parameter's value and percent-decodes it (`%2B` is read as `+`; a `+` stays a `+`). Without the key the variable's value is the token as it stands. |
| `list.request`, `items`, `ref`, `name` | Required. `items` matches one value per challenge; `ref` is the platform's id for it (a string or a whole number), which a submit is sent with. |
| `list.category`, `points`, `solves`, `description`, `max_attempts` | Optional, as in [`challenge.json`](#challengejson). `max_attempts` makes the challenge one whose tries are counted. |
| `list.file_urls`, `file_names` | Each file's address, and optionally its name (else the last part of the address). Both must match the same number of values. |
| `list.instance` | Optional: a value that says the challenge has an instance the platform starts when asked (rCTF v2's `instancerLifetime`). Any value but `null`, `false`, `0` or `""` writes `"instance": "on-demand"` in its `challenge.json`. |
| `[http.detail]` | Optional: `request` with `{ref}` in it and any of the fields above, read from one more request for each new challenge. A field here wins over the list's; `file_urls` here without `file_names` names each file from its address. |
| `submit.request`, `body` | Required for flightdeck to submit. The body is JSON; `{flag}` must be in it, and `{ref}` in the path or the body (`"{ref:int}"` as a whole value sends the ref as a number). |
| `submit.verdict_path`, `[http.submit.verdicts]` | Where the answer holds the platform's word, and which verdict each word means: `correct`, `incorrect`, `already_solved`, `rate_limited` or `unjudged`. The answer is read whatever its HTTP status (rCTF answers a wrong flag with 400). `true` and `false` and numbers are matched as those words. |
| `[http.submit.status]` | An HTTP status to a verdict (`429 = "rate_limited"`), used when no word decided. |
| `submit.detail_path`, `tries_left_path` | The platform's own sentence, and the tries it says are left. |
| `submit.retry_after_path`, `retry_after_unit` | How long a rate limit asks to wait, in `"s"` or `"ms"`; without it, the `Retry-After` header. |
| `[http.submit.poll]` | For a platform that judges later: `id_path` (the submission's id in the submit's answer), `request` with `{submission}` in it, `pending` (the words that mean "not yet"), `every` (seconds, default 1) and `at_most` (looks, default 10), and optionally its own `verdict_path`. |
| `solved.request`, `refs` | Required. `refs` matches the refs of the challenges your account or team has solved. |

`flightdeck http check EVENT.toml` is how a table gets written: it makes the sign-in, the list
and the solved-list requests, and for the first challenges (`--show N`) prints each path and
what it matched. It submits nothing and downloads nothing. It exits with status 1 when a path
a pull needs matched nothing or the wrong kind of value, and 2 when a request failed.

### What a table can and cannot make flightdeck do

A profile may be a teammate's, and an `[http]` table is data, not code, so flightdeck takes it
from the profile. These limits are what make that safe, and `flightdeck preflight` prints every
request with where the token goes before anything runs:

- **One address.** A route is a path under `event.url`: no scheme, no host, no `..`. Your token
  and the session token go to that address and nowhere else, and a redirect is never followed
  with them.
- **A token variable named for the platform.** `token_env` must be `HTTP_TOKEN`, a name that
  starts with `HTTP_TOKEN_` (`HTTP_TOKEN_QUALS`) or, with a preset, a name that starts with the
  preset's (`RCTF_TOKEN`, `RCTF_TOKEN_QUALS`). `HTTP_` alone is not enough: other programs name
  their own settings that way, and `HTTP_PROXY` holds a proxy's address, often with its
  password. A profile cannot name your CTFd token, a model key, a proxy setting, a variable
  your config names for a secret, or anything else. The profile still names the address, so
  read `preflight`'s `token` line before you play a profile you did not write.
- **A token out of a link, for the link's own site.** `auth.link_param` only says which part of
  your variable's value is the token. When the variable holds a link, its host must be
  `event.url`'s, or nothing is sent: a link to another site holds that site's token.
- **Five placeholders and no more:** `{ref}`, `{flag}`, `{game}`, `{submission}` and, in the
  sign-in body only, `{token}`. A challenge's name, text or file names can never be put into a
  request. A placeholder in a path is percent-encoded whole; in a body it is a JSON string.
- **No headers of the table's choosing** except the one that carries the token.
- **Files.** A file on the event's own address is fetched without the token unless
  `files_auth = true`. A file on another host (a storage bucket) is fetched over https only,
  with no token, no cookie and nothing else of the platform's; so is a redirect that leaves
  the event's address. Each file is at most 1 GiB and must have a plain file name.
- **One send per flag.** A request that fails is never sent again. Only a flag the platform
  rate-limited is: after the wait it names plus a second (at most 5 minutes), or 65 seconds
  when it names none, up to 3 more times, and never where tries are counted.
- **No rule, no verdict.** An answer no rule of the table matches is `unjudged`: the flag comes
  back to you to submit by hand and is never recorded as wrong. `incorrect` is reached only
  through a rule you can read in the table.
- **A web page is a stop.** HTML where JSON is expected (a login page, a "checking your
  browser" page) is never read as an answer and never worked around.
- **The answer is untrusted**: a size limit on every answer and 30 seconds for the whole of it
  (10 minutes for a file), the tokens cut out of every string, everything shown made safe, and
  every challenge folder read back as any board ([A board is untrusted](#a-board-is-untrusted)).

Not built, and refused by name when a table asks for them: pages of a listing, a download
route per challenge, form-encoded bodies, a CSRF header, HTML scraping, passwords and
captchas, encrypted requests. A [plugin](PLUGINS.md) can do those. An `[instances]` table
reaches the platform the same way, with the same token and the same limits
([Instances on demand](#instances-on-demand)).

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
# start = "2026-11-14T09:00:00+00:00"  # when the event starts, with its zone: autopilot waits for it
# end = "2026-11-15T09:00:00+00:00"    # when it ends: autopilot stops the run then

[rules]
ai_allowed = true                   # may model-driven lanes work challenges
platform_automation = true          # may flightdeck pull and submit through the platform's API
live_targets = "confirm"            # "allowed", "confirm" or "off": may lanes touch challenge instances
# max_lanes = 8                     # if the rules limit how many agents run at once
# material_to_models = false        # if the rules forbid giving a challenge's text or files to a model: no lane then starts
# declared_label = "Human-Led AI"   # if the event has teams declare a label for their AI use: yours, in the event's words

[policies]                          # optional
# pull = "auto"
# l1 = "auto"
# agents = "auto"
# submit = "confirm"
# instance = "confirm"
```

A Game Master event says `platform = "gamemaster"`, with the Game Master's `url` and `token_env`,
and plays the folder `flightdeck gm pull` wrote: `flightdeck play ~/ctf/gm-board --event
event.toml`, or `board = "..."` in the profile. A run pulls nothing and starts no attempt, so the
pull policy does nothing there. Under `submit = "confirm"` or `"auto"` flightdeck sends answers
to the Game Master and reads its solved list; under `manual` or `off` it contacts the Game Master
not at all. Set `flag_format` in the profile only to override the board's.

An event on a platform with a JSON API says `platform = "http"`, with the platform's `url`, a
`token_env` named `HTTP_TOKEN` or `HTTP_TOKEN_...` (or, with a preset, `RCTF_...`), the `board` folder
and an `[http]` table: a preset, or the platform's routes
([A board from a platform with a JSON API](#a-board-from-a-platform-with-a-json-api)).

An event on any other platform says `platform = "NAME"`, the name of a plugin you added with
`flightdeck plugin add` ([PLUGINS.md](PLUGINS.md)), with the platform's `url`, the `token_env`
of your token there (unless the plugin takes none) and the `board` folder its challenges are
pulled into. `platform` is `ctfd`, `manual`, `gamemaster`, `http` or such a name: a name that is no
plugin in your own config is refused, never played as a folder board, and a profile cannot add
a plugin. Under `pull = "auto"` flightdeck pulls the board through the plugin before the
console opens and again every 5 minutes; under `"confirm"`, once, after your yes; under
`manual` or `off` the run pulls nothing and plays what `flightdeck plugin pull` wrote. Under
`submit = "confirm"` or `"auto"` flags go to the platform through the plugin, and whenever the
run uses the plugin it reads the platform's solved list through it each minute.

`[event]` says where the board comes from. With `platform = "ctfd"`, flightdeck pulls the board
from `url` into the folder you give `play`. With `platform = "manual"`, `board` names a folder
board you made, and you submit the flags on the platform yourself.

`start` and `end` are optional: the event's first and last moment, each an ISO 8601 date and time
with its zone (`"2026-11-14T09:00:00+01:00"`, or `Z` for UTC; a time with no zone is refused,
naming the key, and so is an `end` that is not after `start`). Only autopilot reads them
([GUIDE.md](GUIDE.md#autopilot)): with a `start` still to come it waits until then before it pulls
or releases anything, and at the `end` it stops the run as quitting does. A run without autopilot
ignores both.

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
- `material_to_models = false` makes `agents` off too, with a refusal of its own. It is for the
  event whose rules allow AI help (asking a model to explain a concept) and forbid giving a
  model the challenge's text or files, or anything made from them. Every lane gives its model
  both, so no lane can keep that rule: `preflight` and `play` refuse, and name
  `rules.material_to_models`. Leave the key out, or say `true`, when the rules allow it.
- `platform_automation = false` makes `pull` and `submit` manual: you put the challenges in the
  board folder, and you submit each flag and tell flightdeck how it went. flightdeck then has no
  use for CTFd's API, so such a profile must say `platform = "manual"` and name its `board`; a
  `ctfd` profile that may not pull is refused. A profile on a plugin's platform then plays as a
  board you fill yourself: its plugin is not run, and `preflight` says so.
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
  goes at once, with the exceptions the guide lists under
  [Play a board](GUIDE.md#play-a-board).
- **instance**: under `confirm`, a lane whose challenge is live asks you before its first model
  call, and until you allow it a Docker lane has no network. Under `manual` or `off`, lanes never
  reach the instance.

`rules.max_lanes` caps how many lanes run at once, and `team = true` asks for a team folder
(`play --team-dir`).

### What your team declared

Some events ask each team to declare a label for its AI use, and score or mark teams by it.
The words are each event's own. `rules.declared_label` holds yours as the event writes it: a
few words in letters, digits, spaces and hyphens, at most 40 characters.

```toml
[rules]
declared_label = "Human-Led AI"
```

flightdeck does not know what a label means, and checks nothing by it. It keeps the label in
front of you and on the record:

- `preflight` shows it, and `play` says it first, before the console opens;
- the run records it, and `flightdeck share` prints it on the flight card beside the run's
  mode (hands-on, approve-only or hands-off), which is worked out from what you did;
- `flightdeck records` puts it at the top of each solve record
  ([GUIDE.md](GUIDE.md#a-record-of-each-solve)).

What the label commits you to goes in the other keys: an event that asks a person to approve
every flag is `submit = "confirm"`; one that forbids agents is `ai_allowed = false`; one that
forbids giving a model the challenge is `material_to_models = false`.

## Instances on demand

Some challenges have no fixed address: the site starts a container for your team when you
press a button, lets only a few run at once, and stops each after a while. On CTFd a plugin
does this; rCTF v2 does it itself. With an `[instances]` table in the event profile,
flightdeck presses the button:

```toml
[instances]
plugin = "docker_per_team"      # the site's container plugin (rCTF v2: "rctf")
types = ["container"]           # CTFd challenge types that have such an instance
max_running = 3                 # the most kept running at once: the site's cap for a team, or less
```

- **Which challenges.** A challenge whose `type` (above) is one of `types`, or whose
  `challenge.json` says `"instance": "on-demand"`. To find the type name, pull the board and look
  at a container challenge's `challenge.json`. On rCTF v2 the `rctf2` preset writes
  `"instance"` itself, and `types` is not needed.
- **When.** flightdeck starts an instance before a lane works its challenge, in the queue's own
  order, and no lane starts on such a challenge before its instance is up; the challenges behind
  it in the queue start meanwhile. It renews an instance five minutes before its end while lanes
  work it, and stops it when the challenge is solved, or parked with no lane on it, and when the
  run ends. A slot freed by a solve goes to the next challenge that waits.
- **What a lane gets.** The instance's address as its live instance: in its brief, and, in
  Docker, as the one thing its network reaches. A web challenge's is `http://host:port`, any
  other `tcp://host:port`, unless the plugin itself gives a URL or says which. An instance with
  several addresses (a web front and a TCP service) gives the lane every one, in the site's
  order. One flightdeck cannot hand a lane yet (a TLS service, rCTF's `tcp-ssl`) is left out,
  and the line that says the instance started names it; if that leaves none, no lane starts
  on the challenge and the instance is treated as one at an address flightdeck will not use
  (below).
- **An instance on its way up.** Some sites answer a start with "starting" and give the
  address only later. flightdeck then asks the status every 10 seconds and sends no other
  start; the lanes wait, and the instance is the one flightdeck started when it comes up.
- **A start that wants a person.** A site that guards its start button with a CAPTCHA refuses
  flightdeck's start, and flightdeck never tries to pass it: it says so once and sends no start
  for that challenge again. Start the instance on the site yourself; flightdeck asks the status
  every 30 seconds, uses the instance once it is up, and leaves it running, as a teammate's.
- **Your team.** An instance that is already running when flightdeck asks (a teammate's, or an
  earlier run's) is used and never stopped by this run. When the site says its cap is reached,
  flightdeck says so once and asks again every 30 seconds: teammates' instances take slots it
  cannot see.
- **A start with no answer.** flightdeck waits 20 seconds for each answer, and some plugins
  start the container inside the request, which can take longer. A start that got no answer
  (or an answer that was not the plugin's) may have been done all the same, so flightdeck
  says so and remembers it for ten minutes: when the instance is up the next time it asks,
  it is taken as the one flightdeck started, used, and stopped when the challenge is done.
  If nobody works the challenge by then, flightdeck keeps asking for those ten minutes and
  stops the instance when it turns up, and it looks once more when the run ends. Before a
  start is sent again, the status is always asked. This is a guess in one case: a teammate
  who starts the same challenge's instance in those ten minutes has it taken for
  flightdeck's. After a start the site refused in words, or after the ten minutes, an
  instance that turns up is a teammate's, as above. While such a challenge is wanted, it
  keeps its place first in line, so on a plugin with one container no other challenge is
  given the slot its container may hold. A start the site answered with an address
  flightdeck will not use (a host name with an underscore, a port past 65535) was done:
  no lane gets that address, and flightdeck stops the instance once nobody works the
  challenge, and when the run ends. A start still out when the run ends is waited for, and
  its instance stopped too.
- **What it needs.** `platform = "ctfd"`, or `platform = "http"` with a run that uses the
  platform (`pull` or `submit` not by hand), `platform_automation = true`, and the `instance`
  policy at `auto` (so `live_targets = "allowed"`): starting an instance is reaching it. A named
  plugin must be one of the event's platform (`rctf` is for `http`, the others for `ctfd`).
  Otherwise flightdeck starts none, and `preflight` and the start of a run say why; start it on
  the site yourself, and the lane works from the files. On the http platform the instancer is
  asked with the same token, the same sign-in and the same one address as the `[http]` table's
  own requests, by the challenge's id there.
- **Limits.** If the platform ends an instance and starts it again at another address, lanes
  hear of it, but a Docker lane's network was fenced to the old address: kill such a lane and
  queue the challenge again. A flightdeck that is killed leaves its instances to the platform,
  which stops them at their expiry.

### Which plugin

`plugin` names the site's container plugin. A container challenge's `type` in its
`challenge.json` tells you which one the site runs:

| `plugin` | The site runs | Challenge `type` | How far it was taken |
|---|---|---|---|
| `docker_per_team` | [CTFd-Docker-Plugin](https://github.com/andyjsmith/CTFd-Docker-Plugin) or a fork of it | `container` | Seen working at an event |
| `ctfd_owl` | [ctfd-owl](https://github.com/D0g3-Lab/H1ve/tree/master/CTFd/plugins/ctfd-owl) | `dynamic_check_docker` | Built from the plugin's source; never run against a site |
| `chall_manager` | [ctfd-chall-manager](https://github.com/ctfer-io/ctfd-chall-manager) | `dynamic_iac` | Built from the plugin's source; never run against a site |
| `rctf` | [rCTF v2](https://github.com/otter-sec/rctf)'s own instancer, with `platform = "http"` and `preset = "rctf2"` | (none: the preset marks them) | Built from rCTF's API reference; never run against a site |

For the ones that were never run against a site, try a practice challenge before you rely on
one, and tell us what happened in an issue.

- **`docker_per_team`.** `POST /containers/api/request`, `stop`, `renew` and `view_info`, each
  with `{"chal_id": N}`.
- **`ctfd_owl`.** The plugin runs one container per account (your team's, in team mode), so
  `max_running` is 1 and need not be written; a larger one is refused. The on-demand
  challenges in your queue take turns. When a teammate runs a container of another challenge,
  the plugin refuses the start ("You have boot ... before"), and flightdeck treats that as the
  cap: it says so once and asks again every 30 seconds. The plugin's stop takes whatever
  container the account runs, so flightdeck asks which challenge it belongs to first and stops
  only its own. It leaves a second between two requests that change something, because the
  plugin refuses faster ones. The site allows a set number of renewals; past it, flightdeck
  says so and starts the instance again when it ends.
- **`chall_manager`.** The address is a line the organiser wrote. flightdeck takes the first
  URL in it, else the first `nc host port`, else the first `host:port`. A line with none of
  these (an `ssh` command, say) is shown to you as it is, and no lane starts on the challenge;
  the instance stays up on the site, for you to use or stop there. flightdeck does not guess:
  inside a sentence, a `host:port` counts only when the host is a dotted name or an IPv4
  address, so a time (`12:30`) or a name and password (`ctf:1234`) is never taken for one, and
  a URL that does not read is an error, not a reason to try the rest of the line. From
  `http://name:password@host:port/` the lane gets the host and the port; the name and the
  password are yours to pass on with a hint. A start the team's mana cannot pay for is
  treated as the cap. An instance with no end is never renewed.
- **`rctf`.** `GET`, `PUT`, `PATCH` and `DELETE` on `/api/v2/integrations/challs/ID/instance`
  (the status, the start, the extension and the stop), with the challenge's own id in the path.
  The answer says the instance's state and lists its addresses, each a kind (`tcp`, `http`,
  `https` or `tcp-ssl`), a host and a port; the end is in milliseconds. A deployment may guard
  the start and the extension with a CAPTCHA: then start the instance on the site (above), and
  renew it there too.
- **ctfd-whale has no name here yet.** From its source: a start first removes whatever
  container the account runs, of any challenge; asking about a challenge other than the
  running one is refused; and the address comes as an `nc` line, a link, a pwntools snippet
  or `[ssl] host port`, some of them TLS endpoints flightdeck cannot hand a lane yet. Until it
  is built ([ROADMAP.md](ROADMAP.md)), start a whale instance on the site yourself.
  `plugin = "ctfd_docker"`, a guess of 0.4.0 that matched no plugin, is refused: write
  `docker_per_team` for CTFd-Docker-Plugin.

For any other plugin, give the four routes yourself instead of `plugin`; look at what the
site's "start instance" button sends, and what comes back, in your browser's network tab:

```toml
[instances]
start = ["POST", "/plugins/example/container?challenge_id={id}"]   # {id} is the challenge's number
stop = ["DELETE", "/plugins/example/container?challenge_id={id}"]
renew = ["PATCH", "/plugins/example/container?challenge_id={id}"]
status = ["GET", "/plugins/example/container?challenge_id={id}"]
api = true                      # the paths are under /api/v1 (false: under the site's root)
# body_key = "chal_id"          # for a route with no {id}: the number goes in a JSON body under this key
# address_key = "connectionInfo"  # the answer's key that holds the address
# port_key = "port"             # ... the port, when the address has none
# expires_key = "until"         # ... the seconds left, or the moment it ends (a number or a timestamp)
# expires_unit = "ms"           # ... when a number of the end counts milliseconds
# endpoints_key = "endpoints"   # the answer's key that holds a list of {"kind", "host", "port"}, one per address
# state_key = "status"          # the answer's key that says what the instance is doing
# running_states = ["running"]  # ... its words for "up" (any other word: no instance)
# pending_states = ["starting"] # ... its words for "on its way up or down": wait, and send nothing
types = ["container"]
```

- **The number.** A route whose path has `{id}` carries the challenge's id there and sends no
  body; any other route sends `{"<body_key>": N}`. A plugin may mix the two. On the http
  platform the id is the challenge's own on the platform (a string, such as rCTF's), written
  into the path percent-encoded.
- **Several addresses.** With `endpoints_key`, each item of the list is an object with a
  `host`, a `port` and optionally a `kind` (`tcp`, `http`, `https`; any other kind is left out
  and named). At most 8 are taken.
- **States.** With `state_key`, an answer whose word is one of `pending_states` is an instance
  on its way (asked again in 10 seconds); with `running_states` given, only those words mean an
  instance is up.
- **The answer's keys.** Each is one key name or a list tried in order, looked for in the
  answer and then in its `data`. Left out, flightdeck tries `hostname`, `host`, `ip`,
  `connect`, `url`, `address` for the address, `port` for the port, and `remaining_time`,
  `remaining`, `expires`, `timeout` for the end. A named plugin's keys can be named too.
- **The address** must be a URL, `host:port`, `nc host port` or a bare host with a port beside
  it. Only a host and a port are ever taken from an answer; nothing in it is run or followed.
- **A start that answers without an address.** Some plugins say only that the start is done.
  flightdeck then asks the status, up to three times two seconds apart, and gives up with the
  plugin's own words if no address comes. The start itself is never sent twice.
- **A refusal** is shown in the plugin's words, whether it sends them as `error`, `errors`,
  `message` or `msg`, and the words under its `data` when they say more. Words that name a
  CAPTCHA make it a start that wants a person (above).

flightdeck asks the plugin only about challenges on your board, sends each request that
changes something once, and never calls a route that spends points.
