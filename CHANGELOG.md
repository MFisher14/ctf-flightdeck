# Changelog

What changed for players, newest first. Milestones are in [docs/ROADMAP.md](docs/ROADMAP.md).

## Unreleased

- `flightdeck init` and the home screen's setup write no dollar cap for a custom
  OpenAI-compatible server on this machine (`127.0.0.1`, `localhost` or `::1`), as they already
  did for Ollama and MLX: a lane no longer stops on its first turn to ask about a budget nothing
  can price. The token cap still holds. The setup notes say, in one line, that a local proxy to
  a paid API should set `dollar_cap` and `[prices]`.
- The welcome screen's key line is `enter  open the console` alone on a board with challenges
  and in the mock, where esc did the same thing under another name. On an empty board, where
  Enter adds your first challenge, `esc  just show me the console` is still named. esc and q
  still close the welcome screen everywhere.
- The config folder follows `$XDG_CONFIG_HOME`: with it set to an absolute path, `flightdeck
  init` writes the config there, and the config, the keys file and your themes are read from
  `$XDG_CONFIG_HOME/ctf-flightdeck`. A file you already have in `~/.config/ctf-flightdeck` is
  still read when the new folder has none, and each command says so once on stderr (`flightdeck
  doctor` in a `config folder` line), so nothing is ignored in silence.
- A lane's session no longer answers one call late. Output a program wrote before a send (a
  debugger still loading, say) comes with the send's read but no longer ends it, so the read
  waits for the reply, and `until` is looked for only in what came after the send. A secret of
  the run's that a session writes is now taken out even when a read showed its start (after a
  pause, or inside what `until` matched), and when the session's full buffer drops its oldest
  bytes.
- A claude lane escalated or stopped in the middle of a turn now counts all the output tokens
  of that turn's last call, not only what claude's events had shown of it, so a token cap or
  a token budget no longer counts less than was spent.
- A lane on a model server whose context is too small for it (Ollama's 4,096-token default)
  no longer refreshes its context on nearly every call, which hid each tool's output from its
  model. When a fresh context alone takes most of what the server keeps, the lane says once
  that the server's context is too small and what to set, and goes on in its context.
- On a machine without Docker the setup form now says so and offers host, instead of showing
  "Looking for Docker…" for good with no runtime chosen, so that `ctrl+s` would not save.
- Approving more budget says the new cap and what is used of it, `L01's cap is now 15k tokens
  (12k used)`, where `11k of 15k tokens` read as a cap of 11k. Approving a lane on a model with
  no price says `L01 carries on with no dollar cap; its token cap is 400k tokens (120 used)`, not
  `L01's cap is now 120 of 400k tokens`. When that lane had reached its token cap too, the
  answer reads `carry on with no dollar cap and 50% more tokens` and the reply says `its token
  cap is raised to ...`, since approving raises it.
- `/` alone in the command bar, sent after esc closed its list, says `/ alone is no command:
  type / and a command's name, the list shows them` instead of `Unknown command /: type / to
  see the list`, and a stray space after the `/` (`/ hint try the cookie`) says `No space
  after the /: /hint`.
- The practice score says once which lanes had turns with no price (`L01, L02 and L08 had
  turns with no price, …`), not the same line for every lane.
- A lane on a model with no price asks whether to `carry on with no dollar cap` (1) or `stop the
  lane` (0), as its question says; its answers said `more budget`, which is not what approving
  does there.
- `/settings` in a run names its `c` key `change this run's settings`, where it said `change
  this run's` and stopped.
- A command typed fast straight after the `/` in the lane list is no longer cut short or
  turned into keys: a letter that came before the bar had opened went to the list (`/layout`
  arrived as `/ayout`), and there it could act (the `a` of `/approve` approved the selected
  lane's flag, the `q` of `/queue` quit). Every key after the `/` now goes into the bar, and
  so does every key after `h` and `r`, which open the bar with `/hint` and `/redirect`.
- While the host governor holds new lanes back (the machine is busy) and challenges wait, the
  header says `lanes wait` and why, and the line that says the board loaded says it too
  (`· no new lane starts for now: load 4.0 per CPU …`): before, the governor's warning came
  just before that line, which hid it, and the queued lanes waited with no reason on the
  screen. That line also counts in words: `1 challenge`, `1 lane started`, not `1 lanes started`.
- `ctrl+g` brings back what your editor wrote again. Every editor, even one that exited
  cleanly, was taken as failed (`the editor ... exited with status ShellExit(status=0, ...): the
  box keeps what it had`), so the box never got the edited text. An editor a signal ends now
  says which signal.
- A take-over's shell opens under a line that says whose shell it is, where, and that `exit`
  (or `ctrl+d`) hands the lane back, instead of at a bare `bash-3.2$` prompt. On macOS it no
  longer opens with bash's note about changing to zsh.
- While the filter hides the selected lane, the line under the list says so (`L02 is hidden by
  the filter: esc clears it`) instead of offering that lane's answers, which every key refused.
- In `flightdeck mock`, the header's clock note quotes its keys (`▶ live · ',' freezes`, `⏸ frozen
  · ',' resumes '.' steps`): a bare comma read as punctuation (`▶ live: , freezes`).
- When an `[instances]` table does nothing because the instance policy is not `auto`,
  `preflight` now says what to change (`live_targets = "allowed"` under `[rules]`).
- On noCTF, GZCTF and a table whose token is sent as it is, a 401 or 403 from the platform
  now ends with `(is the token the right one for this event, and still valid?)`, as a refused
  rCTF sign-in already did, instead of the bare status. A 404 to a route with `{game}` in it
  (GZCTF's) asks whether `game` under `[http]` is the event's.
- "The token variable ... is not set" (from `http check`, `http pull`, `plugin pull` and
  `play --event`) now says where your keys file is: `put RCTF_TOKEN=<token> in your keys file
  (~/.config/ctf-flightdeck/keys.env) or export it`.
- `flightdeck plugin pull` and `flightdeck http pull` say `pulling the board through ...` (on
  stderr) before they start, so a plugin that takes its time (a pull may take five minutes)
  no longer looks like a frozen terminal.
- `flightdeck start`'s question of how the challenges arrive no longer leaves "by hand" as the
  only answer off CTFd: it says that on rCTF, noCTF or GZCTF `flightdeck http example --preset
  NAME > event.toml` sets up an event flightdeck pulls and submits for.
- An example profile left unedited no longer sends your token to its placeholder address:
  `http check`, `http pull`, `plugin pull` and `play --event` refuse an `event.url` that is
  still `ctf.example.org` and say to put the event's own address there, and so do
  `flightdeck preflight` and `flightdeck start`, which once called such a profile ready. The http and
  plugin examples in BOARDS.md and the guide now say to make the folder and edit the profile
  first.
- `flightdeck doctor` names a plugin that cannot be read once (`warn plugin myctf: ...`, not
  `plugin myctf: plugin myctf: ...`), and for one whose folder moved or is gone it says to put
  the folder back or change its path in the config, not to fix a `plugin.toml` that is not
  there.
- `flightdeck start FOLDER` on a folder already set up now says when the event's token
  variable is not set, before it offers to launch; it used to say nothing, and the run then
  refused.
- A lane waiting for your answer to a flag or to more budget now gives its slot to the next
  queued challenge once it has waited a minute, as a lane waiting for a live-box answer does at
  once; an answer you give within the minute keeps its slot. At most `max_waiting` lanes
  (`[lanes]`, 4 by default) are without a slot at once, each keeping its workspace; one more
  keeps its slot, and so does a lane with a session open, and its transcript says why.
  `max_waiting = 0` keeps every slot, the live-box wait's too.
- A take-over whose shell cannot open no longer leaves the console frozen. When `docker` (or
  `bash`) is not there to run, the shell ends at once with an error (the lane's container is
  gone), or a signal ends it, you are back in the console straight away, the lane is handed
  back as it was (a paused lane stays paused), and the status line says why: `the shell did
  not start: docker was not found (is it installed and on your PATH?)`, or `the shell exited at
  once with status 1`. A shell that never ran is not told to the lane, except that the
  take-over closed its sessions, when it had any.
- `flightdeck mock` no longer rings the terminal's bell unless your config says `bell = true`
  under `[console]`: its lanes are scripted and need no one. A run rings as before, and
  `bell = false` still silences both.
- `/copy ` with a space lists what it copies (`output`, `command`, `flag`, `all`), each with a
  few words, as `/sort` and `/autopilot` list theirs.
- In the simple layout, while the filter hides the selected lane, the key line shows the keys
  for no lane, as help and the command bar's `no lane` do, instead of keys that would be
  refused.
- Up and down in the command bar and a lane's chat box bring back what you sent this run,
  newest first, as a shell does; down past the newest gives back what you were typing. While
  the `/` menu is open they still move in the menu. `ctrl+g` opens what is in the box in your
  editor (`$VISUAL`, else `$EDITOR`); when you save and quit, the text is back in the box on one
  line and nothing is sent until you press Enter. With no editor set it says so and opens
  nothing ([the guide](docs/GUIDE.md#the-command-bar)).
- A lane that runs the same command again and again shows it at a glance. In a lane's calm
  view the last row of a run of tool calls starts with how many times in a row the lane made
  that call (`⎿ ×7 $ nc -z 127.0.0.1 9000 → exit 1`), and in the peek the repeats are one row
  with the count, so the rows above it still show what the lane did before. Calls fold only
  when their text is the same (blanks aside). `ctrl+o` still shows every call, and `/copy all`
  copies every one.
- A lane notices when its model server drops its oldest messages. Ollama does this past the
  context it gives a model, with no error, and a lane with no `context` under `[api]` then went
  on without its brief. Now, when the context grew but the server counted no more prompt
  tokens than the call before, the lane says so, tells you once to set `OLLAMA_CONTEXT_LENGTH`
  and `[api] context`, and goes on at once in a fresh context with a summary. For the rest of
  the run, lanes on that model are refreshed when they reach the count where the drop was seen
  ([details](docs/MODEL-APIS.md#context-on-a-server-on-your-machine)).
- noCTF, DownUnderCTF's platform, ships as a preset of the http platform: `preset = "noctf"`
  under `[http]`, the API's address as `event.url`, and the session token the site keeps once
  you sign in in a variable named `NOCTF_...`. `flightdeck http example --preset noctf` prints
  a profile for it. A flag noCTF queues for the organisers to judge comes back to you, never
  marked wrong. It was written from noCTF's source and tried against a stand-in only, not a
  real noCTF yet: run `flightdeck http check` first
  ([Boards](docs/BOARDS.md#a-board-from-a-platform-with-a-json-api)).
- GZCTF ships as a preset of the http platform: `preset = "gzctf"` and the game's number
  (`game = "3"`) under `[http]`, with the value of your `GZCTF_Token` cookie (from the browser,
  once you have signed in) in a variable named `GZCTF_...`. `flightdeck http example --preset
  gzctf` prints a profile. flightdeck pulls the game's board, files and counted tries, sends a
  flag and waits for GZCTF to judge it, and reads your team's solves. A site that encrypts its
  flags (GZCTF's `ApiEncryption`) gets none from flightdeck: each flag comes back to you with
  the reason, and `http check` and each pull say so. A table for another platform can say the
  same with `[http.refuse]`. The preset has met a stand-in only, not a real GZCTF yet
  ([BOARDS.md](docs/BOARDS.md#a-board-from-a-platform-with-a-json-api)).
- A solver pack can say which flightdeck it needs: `flightdeck = ">=0.6"` in its `pack.toml`
  (`>=`, `>`, `<=`, `<`, `==`, `!=`, joined by commas). A flightdeck that does not meet it
  refuses the pack and says both versions, as in `this pack needs flightdeck >=0.6, you have
  0.5.0: upgrade flightdeck`: `pack install` stops before it runs anything, and doctor,
  `pack info`, the `l1` commands and a run use none of its engines. `pack info` shows the
  requirement ([the solver guide](docs/SOLVERS.md#a-pack-that-needs-setup)).
- The `/new` form and help ("Files, in this terminal") say how to drop a file in the terminal
  you are in, and what to press when nothing lands: over SSH, inside tmux, VS Code's terminal,
  iTerm2 and WezTerm on X11 each have their own sentence, and every other terminal the general
  one ([the guide](docs/GUIDE.md#events-and-teams)).
- Coding-agent lanes (`--agent claude` or `--agent codex`) hold the queue when the model API
  keeps failing in a way that may pass (a rate limit, a 5xx, an overload), as flightdeck's own
  lanes do: two lanes in a row whose CLI gave up on it, with no answer in between, hold the
  queue, so the rest of the queue is not spent on an API that does not answer, and autopilot
  disengages. `/unhold` puts the challenges they parked back in front of the queue (#33).
- Under autopilot, a lane that ignores the hint or goes the wrong way again after autopilot
  redirected it is escalated one rung, and at the top rung killed and its challenge parked, as
  a stalled lane is. It used to wait for you (#33).
- "Settings and health" on the home screen: your main settings (the config file, the model API,
  whether its key is set, the models, where lanes run, and the layout, theme, bell, title and
  mouse), each with where it is set, and the checks of `flightdeck doctor` with the fix under
  each problem. A key shows as `set` or `not set`, never its value. The checks run while the
  screen stays yours: `esc` leaves at once and stops them, `r` runs them again
  ([the guide](docs/GUIDE.md#install-and-first-run)).
- `ctrl+o` in the lane list opens your system's file window to attach files to the selected
  lane's challenge, as `/attach` with no file does: for a terminal where dragging a file in
  does nothing. In a lane's own view `ctrl+o` still turns details on or off. `?` lists both.
- A `/new` with a screenshot that was answered with `reading 1 image...` and then could not be
  added removes the copies of the files you dropped for it, and the warning says so: drop them
  again with `/new`. They used to stay in the run's folder until the run ended.
- `flightdeck init --force` replaces your config in one step, keeping its permissions: a write
  cut off half way (a full disk) leaves the old config as it was, never half of each.
- Instances on demand work with ctfd-whale: `plugin = "ctfd_whale"` under `[instances]`.
  flightdeck never sends a start while your account runs a container, because whale's start
  removes it: your own challenge's container is used as it is, and another challenge's is
  treated as the cap and left alone. Each form the site writes the address in is read, and a
  TLS endpoint reaches the lane as `tls://host:port`, with a brief that says to speak TLS to
  it. Built from the plugin's public source and tested against a fake of it only
  ([BOARDS.md](docs/BOARDS.md#which-plugin)).
- Instances on rCTF v2. With `preset = "rctf2"` under `[http]` and `plugin = "rctf"` under
  `[instances]`, flightdeck starts a challenge's instance on rCTF v2 before a lane works it,
  as it does on CTFd: it signs in with your team token as the pull does, renews the instance
  while it is worked and stops it when the challenge is solved. A challenge with an instance
  is marked on the board when it is pulled. An instance that is still starting is asked about
  every 10 seconds and gets no second start. A start the site guards with a CAPTCHA is said
  once and never sent again; start that instance on the site, and flightdeck uses it. Built
  from rCTF v2's API reference; it has not met a real event yet. The older rCTF keeps
  `preset = "rctf"`, and its instancer (klodd) wants a CAPTCHA, so start those by hand.
  `flightdeck http example --preset rctf2` prints a profile for it, with its token in
  `RCTF_TOKEN` and the two `[instances]` lines to take the `#` off, and `--routes` writes
  rCTF v2's routes out.
- Containers on GZCTF. With `preset = "gzctf"` under `[http]` and `plugin = "gzctf"` under
  `[instances]`, flightdeck starts a container challenge's container before a lane works it,
  with your `GZCTF_Token` cookie, extends it near its end and stops it when the challenge is
  solved. A pull marks the challenges whose type is `StaticContainer` or `DynamicContainer`.
  flightdeck leaves 10 seconds between two container changes, as GZCTF refuses faster ones.
  A site that serves its containers through its own WebSocket proxy gives no address a lane
  can use, and flightdeck says so: open those from the site. Built from GZCTF's source and
  tested against a stand-in only; it has not met a real event yet.
- `instance_values` under `[http.list]` or `[http.detail]` names the values of `instance` that
  mark a challenge on-demand, for a platform whose field says something for every challenge.
- An instance with several addresses (a web front and a TCP service, say) gives its lanes all
  of them. rCTF's `tcp-ssl` address, a TLS service, reaches the lane as `tls://host:port`, as
  ctfd-whale's do. One flightdeck cannot hand a lane yet is named in the line that says the
  instance started.
- For an instancer flightdeck has no name for, `[instances]` reads more answers:
  `endpoints_key` (a list of addresses), `state_key` with `running_states` and
  `pending_states`, and `expires_unit = "ms"`. On the http platform the `[http]` list may mark
  a challenge with an instance by an `instance` path, and a plugin's pull may say
  `"instance": "on-demand"`.
- flightdeck's own lanes can keep a program running across their turns: a debugger, an
  interpreter, a connection to the challenge's instance. A lane starts one with
  `session_start`, writes to it and reads it back with `session_send`, and stops it with
  `session_close`; you see each as a step (`session s1 start: gdb -q ./chall`, `session s1 <
  break main`). At most three per lane, one unused for ten minutes is closed, and every session
  is closed when the lane ends or when you take it over; the lane hears which when you hand
  back. Its output is handled like a command's: held secrets taken out, long output cut and
  saved ([the guide](docs/GUIDE.md#what-a-lanes-shell-has)).
- A lane can start a session on a terminal, for a program that shows its prompt or menu only at
  one (`session s1 start (terminal): python3`). What it writes comes back as plain text: colours
  and other terminal escapes are taken out before the lane or the console sees them. What the
  lane sends it reaches the program as sent: the terminal edits nothing, and a send that holds
  ctrl+d, which a terminal takes as the end of the input, is refused. The
  lane's brief now tells it of sessions in one line; a coding-agent lane, which has none, is
  not told.
- A lane that asks for the live instance (instance `confirm`) gives its slot to the next queued
  challenge while it waits for your answer, so the queue does not stand still while you are
  away. Once you answer, the lane goes on if a slot is free; if none is, its state reads `queued`
  until one frees, and it takes that one before anything queued. A `queued` lane that is asked
  something more (a flag the platform gave no verdict on) waits for your answer first: it takes
  no slot until you give it. Its transcript says which lane
  took its slot, and the run log has a `slot` event for each move. Other approvals keep their
  slot.
- Claude lanes were checked against a real Claude Code (2.1.325), and what differed is fixed. A
  message you send mid-turn now ends claude's turn with an interrupt request instead of Ctrl-C,
  which made claude quit when the turn had just ended. A lane's tokens now count all that
  claude's model calls wrote (they were low), and a call cut short by your message is charged
  at your config price, since claude leaves it out of its cost. `claude started on ...` is noted
  once, not every turn; a subscription's usage limit, near or reached, is a note on the lane; and
  a turn that fails for want of a login says `api_error`, not `success`. The guide says what was
  checked, and that a lane needs `CLAUDE_CODE_OAUTH_TOKEN` for a subscription: it does not see
  the login `claude` uses on your machine.
- `flightdeck http check` also asks the instancer's status when the profile has an
  `[instances]` table: once, for the first challenge marked on-demand, with a `GET` only, and
  it prints where the instance runs, that none runs, or what the site said. It never starts,
  renews or stops one, and it exits with status 1 when the answer is nothing a run could use.
- An rCTF v2 instance the site says "errored" is no longer taken for no instance. flightdeck
  says it failed, sends no start for it while the site says so, and asks again later: stop it
  or start it again on the site, and the run goes on.

- `/settings` in a run now opens Settings and health, the same screen as on the home screen:
  this run's settings on top (lanes at once, what happens to a flag, the layout and the theme;
  `c` opens `/config` to change them), a line that counts the lanes that need you, your setup
  and `flightdeck doctor`'s checks (in a run with `--agent claude` or `codex`, the checks of
  `flightdeck doctor --agent`: that CLI and its login, and the API key a warning). The checks run beside the console at a lower priority, and
  opening the screen again shows what they found until `r` checks again. `/config` works as
  before; `/settings` is no longer another name for it, and `/settings lanes 8` says to type
  `/config lanes 8`.
- `flightdeck start` and the home screen's "Start a new CTF" set up an event on rCTF, rCTF v2,
  noCTF or GZCTF: choose `3  json api`, then the platform, and give the site's address (on
  GZCTF the game's page gives the game too) and your token, which the question says where to
  find. The event file is the one `flightdeck http example --preset NAME` prints, filled in;
  the token goes to your keys file as `RCTF_TOKEN_<NAME>`, `NOCTF_TOKEN_<NAME>` or
  `GZCTF_TOKEN_<NAME>`, never shown. Without a terminal: `--preset NAME`, `--url` and, for
  GZCTF, `--game NUMBER`. By hand is still `2`.

## 0.5.0 (2026-11-14)

A calm console: the simple layout, a lane view of one row per step, a peek at the selected lane,
and themes. Events on more platforms: plugins of the player's own, the http platform with an
rCTF preset, and ctfd-owl and chall-manager instances. Rules that match 2026 events, with a
record of each solve; gdb and radare2 in every Docker lane, now on Debian 13; and the first five
minutes in a setup form on the home screen.

- `space` peeks at the selected lane. A panel opens under the lane list with the lane's last
  six steps, each on one row (a command and the first line of its output, the model's words,
  your messages, an alert, the question it waits on), over the line that says why the lane is
  flagged. It follows the selection as you move, and a message typed in the bar still goes to
  that lane, so you can read what a lane did and answer it without opening it. `space` or `esc`
  closes it; it stays as you left it for the run. On a short terminal it shows fewer rows and
  the list keeps three; under 18 lines it says there is no room. The `/` menu and a status
  message of several rows take their rows from the peek's oldest, never from its newest or
  from the list's three: where they leave it none it is hidden until they go. It works in both
  layouts and on a phone, and the lanes panel's bottom border says `space peek`.
- In `flightdeck mock`, `,` freezes the clock, since `space` is the peek now; `.` still steps
  it.
- `/theme` and `/layout` alone open a list you try before you choose. The console behind the
  list is drawn in the row the cursor is on; Enter keeps it for this run, `esc` puts back what
  you had, and `s` keeps it and saves it in your config (`theme = "nord"` or `layout = "deck"`
  under `[console]`, every other line of the file as it was). A theme file that cannot be used
  is listed with its reason and cannot be chosen. `/config` has the layout and the theme too,
  with a choice to save them. A save that cannot be done says why, leaves the file as it was,
  and the run keeps the look. `/layout` alone no longer switches to the other layout by
  itself: `/layout deck` and `/layout simple` still do, at once. With no config file (the mock
  before `flightdeck init`) a choice lasts for the run, and the list says so
  ([the guide](docs/GUIDE.md#layouts)).
- A quieter simple layout. In its header only what asks you to look keeps a coloured block:
  flightdeck, `host`, `AUTOPILOT`, `▲ N need you` and `queue held`. The event's name, `team`,
  the queue and the dollars are plain text, and the mock's tag is dimmed. In its lane list a
  lane that has started and done nothing yet reads `starting`, dimmed, with no cost, in place
  of `run` and `$.00`, until its first step or its first spend. The deck and compact layouts
  are as they were.
- `?` opens help for where you are. In a lane, `?` on the empty chat box opens help, from any
  pane; with text in the box it is a question mark (type a space first, or paste, to start a
  message with one). The key line in a lane reads `esc lanes  / commands  ? help  ctrl+o
  details`. Help starts with the lane in front of you: `This lane, now: L03 · Gamma` and the
  keys that apply to it, each with what it does; then the keys of the view you are in, the
  other view's, and the ones both have. In the lane list's command bar `?` opens help too while
  the bar is empty.
- The command bar names the lane it talks to. Its border reads `to L04 · Ticket Desk` and
  follows the selected lane in the lane list; in a lane's view it names that lane. It reads
  `no lane` when there is none to take a message, `the run` while you type a command that is
  not about one lane (`/note`, `/config`), and the lane a command names while you type it
  (`/kill L07`). A lane that would refuse what you type is not named: the border reads
  `L04 has finished` for a lane that has ended (until you type something it still takes,
  such as `/open` or `/copy`), and `L04 takes no more turns` for one that gave up and is
  open only for its flag's answer. The empty bar is shorter, the same in both views:
  `a message, or / for commands`.
- The `/` menu forgives. It finds a command from the second word of its name (`/over` lists
  `/takeover`) and from an alias (`/q` and `/exit` for `/quit`, `/settings` for `/config`,
  `/lanes` for `/back`, each shown beside the name). After a command's name it lists what the
  command takes: the lanes with their challenge and state for `/open`, the parked and new
  challenges for `/queue`, your themes for `/theme`, and the words of `/layout`, `/sort` and
  `/autopilot`. When nothing matches it says `No commands match "/x"` instead of closing.
  What runs is as strict as before: only a whole name or alias, and `/approve 2` is still
  refused. Enter on a row you chose with the arrow keys now puts that row in the bar.
- The console tells you a lane needs you when you are looking at another window. The
  terminal's title carries the count (`▲ 2 need you · flightdeck`, `queue held · flightdeck`
  while the queue is held, `flightdeck` when nothing waits), and the terminal's bell rings once
  each time the count goes up. The title you had comes back when the console leaves, and while
  you are in a lane's shell. Inside tmux the bell marks the window with nothing set up; the
  title reaches the terminal outside only with `set -g set-titles on`. `title = false` or
  `bell = false` under `[console]` turns either off. Tested by reading what a pseudo-terminal
  is sent; not yet looked at in each terminal program or inside tmux
  ([the guide](docs/GUIDE.md#the-terminals-title-and-bell)).
- A platform with a JSON API, with no code of yours: `platform = "http"` and an `[http]` table
  in `event.toml` say how the platform's API is asked, and flightdeck pulls the board, submits
  the flags you approve and reads the solved list itself. rCTF ships as a preset (`preset =
  "rctf"`, with your team's login link, or the token in it, in a variable named `RCTF_...`). `flightdeck http example`
  prints a profile to edit, `flightdeck http check EVENT.toml` signs in, lists and reads the
  solved list and shows what each path of the table matched (it submits nothing), and
  `flightdeck http pull` writes the board outside a run. `flightdeck preflight` prints every
  request such a profile makes and where your token goes. The preset has met a stand-in only,
  not a real rCTF yet. A plugin can no longer be named `http`.
- Instances on demand work with two more CTFd container plugins: `plugin = "ctfd_owl"` and
  `plugin = "chall_manager"` under `[instances]` in the event profile. Both were built from the
  plugins' source and have not been run against a real site yet, so try one on a practice
  challenge first ([BOARDS.md](docs/BOARDS.md#which-plugin)).
- For a container plugin flightdeck has no name for, `[instances]` can now say which keys of
  the plugin's answer hold the address, the port and the end (`address_key`, `port_key`,
  `expires_key`); the end may be a timestamp. A start that answers "done" with no address is
  followed by a look at the status instead of an error, and a refusal the plugin words as
  `msg` shows its reason instead of "HTTP 200". A route with `{id}` in its path no longer also
  sends the number in a body.
- `plugin = "ctfd_docker"` under `[instances]` is refused: it was a guess that matched no
  plugin. Write `docker_per_team` for CTFd-Docker-Plugin and its forks.
- An instance whose start got no answer in time, and that is up when flightdeck asks again
  within ten minutes, is now taken as the one flightdeck started: it is used and stopped when
  the challenge is done. Before, it was taken for a teammate's and never stopped, which held
  one of the team's slots until the site ended it
  ([BOARDS.md](docs/BOARDS.md#instances-on-demand)).
- A debugger and a decompiler in every Docker lane: the lane image now has `gdb` (and
  `gdb-multiarch`, for a binary of another architecture) and radare2 with the Ghidra decompiler
  (`r2`, `pdg`), and a lane's brief says how to run them from a shell with no terminal. Run
  `flightdeck image build` again to get them: `flightdeck doctor` warns while your lane image is
  one an older flightdeck built. The image is now Debian 13 (its `python3` is 3.13, not 3.11)
  and about 830 MB, where it was about 700. The solver pack's image has the same two
  (`flightdeck pack image` rebuilds it), so the pack's decompile engine works from a lane and
  at intake.
- A lane can look at a picture: flightdeck's own lanes have a `view_image` tool that shows the
  model a PNG, JPEG, GIF or WebP file in the lane's workspace, as it is (at most 3.75 MiB, so
  it fits the API's 5 MB once encoded; never scaled down). When your model's API will not take a picture, or the `[fallback]` model a lane
  moved to will not, the lane is told why and goes on without it instead of ending.
- Dropping a file on the console: a terminal that types the dropped file's path (instead of
  pasting it) now attaches it too, and never types it into a field or runs its letters as keys.
  Every drop that lands says so (`attached NAME (SIZE)` in the `/new` form, `got NAME (SIZE):
  press Enter to attach` on the command bar), and one that is refused says why. If nothing at
  all happens when you drop a file, your terminal kept it: `ctrl+o` in the `/new` form, or
  `/attach` with no file on the command bar, opens the file window.
- A dropped file attaches in more cases. On a Mac with a 12-hour clock, a fresh screenshot
  dragged onto iTerm2 or Ghostty was pasted as text and not attached: its name has a narrow
  space before AM or PM that those terminals send as it is (a 24-hour clock's name has none).
  Only an ordinary space or a tab parts two dropped paths now. A name with a double quote in
  iTerm2's "wrap in double quotes" form, and one with both a space and a quote in WezTerm's
  default form (`John's notes.pdf`), are read too.
- A dropped file is copied into the run's folder the moment it lands, so one that is gone
  before you press `ctrl+s` or Enter (a temporary file) is still attached. The `/attach` on
  the command bar names that copy. On macOS, still drag the saved screenshot and not the
  floating thumbnail: its file may be gone before the terminal sends the path.
- When what arrives reads as a dropped file but no such file is on this machine, the console
  says why and what to do, then pastes it as text as before: over SSH the file is on your own
  machine, under WSL a `C:\` path needs Windows Terminal's `pathTranslationStyle`, VS Code's
  terminal leaves some characters out of the name, or it was a temporary file that is gone.
- In Windows Terminal and Alacritty, the terminal's own paste key with a screenshot on the
  clipboard now pastes it into the `/new` form, as `ctrl+v` does.
- `mouse = false` under `[console]` leaves the mouse to your terminal, so you select and copy
  text the terminal's own way. Clicks and the wheel then do nothing in the console; every key
  works as before. The default is unchanged.
- The console opens in a simpler layout: one list of lanes, a short header, and only the keys
  that apply to the selected lane now. Every key still acts, and `?` lists them. `/layout deck`
  brings the full dashboard back for the rest of a run; `layout = "deck"` under `[console]` in
  your config keeps it.
- In the simple layout a lane's own view shows the files pane once the lane has changed a file,
  and the strip of other lanes only while one needs you. On a board you fill yourself, the first
  lane your `/new` starts opens full screen.
- Themes: `theme = "nord"` under `[console]` (`flightdeck`, `light`, `nord`, `gruvbox`,
  `dracula`, or your own `themes/NAME.toml` beside the config: as little as a `base` and one
  colour). `/theme NAME` tries one in a running console, and `/theme` lists them. A theme you
  could not read the console in is refused, with the pair of colours named.
- Plugins: an event on a platform flightdeck does not know can be played with a small adapter
  of your own. `flightdeck plugin new NAME` writes one to fill in, `flightdeck plugin add
  FOLDER` shows what it runs and enables it on your yes, and `platform = "NAME"` in event.toml
  uses it: flightdeck pulls the board, submits the flags you approve and follows the solved
  list through it. `flightdeck plugin pull EVENT.toml` tries the pull and submits nothing. How
  to write one: [docs/PLUGINS.md](docs/PLUGINS.md).
- An empty board now says how to add a challenge and keeps saying it, and the `/` menu scrolls
  to every command and lists `/new` first when there is no lane yet.
- On a small terminal (80x24 and under) the `/new` form, the welcome screen and help keep
  their last rows on screen: the keys (`ctrl+s` adds the challenge) and the line a refusal is
  said on. The form's description box gives up rows first, then its fields scroll to the one
  you are in. Help lists what a command does under it when there is no room beside it.
- The simple layout's lane list shows what each lane has spent at every width: on an
  80-column terminal the challenge's name narrows to make room, and under 74 columns the last
  action is left out (`flightdeck doctor` says so), never the cost.
- A status line too long for the terminal goes on in a second row instead of being cut, so
  what `/layout` and `/theme` answer (the config line that keeps the choice, and its file) is
  read whole at 80 columns.
- A lane's view is calm in the simple layout: one row for each thing the lane did, a run of
  tool calls on two (`⏺ 12 tool calls`, and the last one), a long L1 note or command as its first
  line and ` …+14 lines`, an alert as its name and turn. `ctrl+o` (or `/details`) shows every
  line and every output, and hides them again. The deck layout shows every line as before, and
  `ctrl+o` gives the calm view there. The transcript wraps again when the terminal is resized.
  A long transcript draws its newest 300 entries, and never more than 600: a first or last row
  counts the rest, and `pgup` or `pgdn` there shows 300 more. Help (`?`, `/help`) lists
  `ctrl+o` and, new there, `pgup` and `pgdn`.
- The "needs you now" card in a lane's view is calm in the simple layout too: three rows where
  it could take twenty. What the lane asks (the approval it waits for, or its most urgent alert
  and why it fired), the numbered answers (`1 more budget   0 stop the lane`), and a row for
  whatever else is open (`also: looping · past its effort budget · stalled`). `ctrl+o` shows
  the full card, every alert with its whole reason and each answer as a command, as the deck
  layout does. Where the card is narrow (an 80-column terminal, beside the files pane) it takes
  a row or two more: the flag that `1` submits is whole, no numbered answer is cut, and the
  last row counts what it cannot name and still says `ctrl+o shows all`. On the full card the approval and its `1` and `0` now come first, and a card
  taller than its half of the pane scrolls: before, a lane with four alerts lost the approval
  under the edge. An approval's text on the card shows a credential's name but not its value,
  as the transcript does (before, the card showed the value).
- A lane that restarts takes its view with it: `/attach` or `/kill` typed in a lane's own view
  moves the view to the fresh lane, with what you were typing (before, the view stayed on the
  dead lane). While no lane can start (the queue is held, every lane is busy) the view moves
  when one does, and it never moves you from where you went meanwhile. `/attach` names the
  fresh lane (`L01 restarted as L02`, or `L01 ended, a fresh lane starts when one is free`), and
  the ended lane reads `killed: to restart with extra.txt`. The chat box's border names its
  lane (the command bar's title, above).
- Text in the console selects and copies: drag over a lane's transcript, its needs-you box,
  the header or the status line and it is copied when you let go (`copied 212 characters`); a
  double-click copies a whole entry, a triple-click the transcript. `ctrl+c` copies the
  selection again, `esc` takes it down. `/copy` copies with no mouse: a lane's last output,
  `/copy command`, `/copy flag`, `/copy all`. It uses `pbcopy`, `wl-copy`, `xclip` or `xsel`
  and the terminal's clipboard (OSC 52, which works over SSH), and says so when it cannot tell
  that the copy arrived.
- The mock opens in your config's layout and theme, and the home screen in its theme.
  `flightdeck doctor` measures your terminal in the layout your config names, and reports each
  plugin you added.
- First-time setup happens in the home screen. With no config, "Get started" opens a form
  there: your model API, its key (typed out of sight and kept in your keys file), the models
  and Docker or host, which is offered by whether Docker runs here. `ctrl+s` saves it, and
  the home screen then offers the practice set first and starting an event one below, with
  building the lane image before both when Docker lanes need it. "Start a new CTF" with no
  config asks the same setup first. While the form still looks for Docker it saves no
  runtime (wait, or choose one yourself: your choice stands), and leaving it never waits for
  a Docker that does not answer. After a save for Docker lanes the terminal says that it is
  asking Docker before it waits, and waits once at most.
- `flightdeck init` asks for your API key at a hidden prompt and keeps it in your keys file,
  so there is no file to make by hand; Enter alone skips it. It asks only at a terminal, and
  only for a key that is not set yet.
- Every model API has models to offer in `init` and in the setup form: for OpenRouter its
  names for Claude Haiku, Sonnet and Opus 5.5, for OpenAI `gpt-5.4-mini` then `gpt-5.4`
  (flightdeck has not measured these two). Enter takes them, or give your own.
- When a run you started from the home screen ends, flightdeck comes back to the home screen
  with the event you just played first in the list; its spend, run folder and next commands
  are in the terminal under it. The practice set and the demo come back too. `q` there
  leaves, and a run that stops with an error leaves with its reason showing.
- The first five minutes read the way they run. `flightdeck --help` opens with the "New here?"
  line (run `flightdeck`: its home screen sets you up and offers the practice set), and
  `eval-local` has a panel of its own, below the commands a new player needs. `flightdeck
  doctor` ends with the line to act on: how many things there are to fix before a run (it used
  to end without one when a check failed), or `Ready` and the next command, with the warnings
  counted as what a run does not wait for. Help says "API key", "access token" and "model
  tokens" where "key" and "token" stood alone. The README's quickstart is three commands (look
  at the mock, install with uv, `flightdeck`) with `pipx` and the `.deb` as other ways to
  install, and the guide's glossary now comes second, with wave, live instance, brief, command
  bar and park added.
- The README opens on a one-minute recording of the demo (`uvx ctf-flightdeck mock`): a flag
  submitted with one key, a lane that ignores its hint redirected, a lane going the wrong way
  killed and started fresh, a wave of 43 challenges. It is the mock itself, played key by key
  by a script in the repository (`scripts/demo.py`), so it shows the console as it is.
- Event rules on AI use, three additions. `material_to_models = false` under `[rules]` in
  event.toml is for an event that allows AI help and forbids giving a model the challenge's
  text or files: `preflight` and `play` refuse, naming that rule, since every lane gives its
  model both. `declared_label = "Human-Led AI"` holds the label your team declared to the
  event, in the event's words: `play` says it before the console opens and `flightdeck share`
  prints it on the flight card under the mode; flightdeck checks nothing by it. `flightdeck
  start` and the home screen's form ask for the label (optional; `--label`), and their rules
  question now says what a lane does: an AI agent works the challenge and is given its text
  and files.
- `flightdeck records RUN_DIR` writes a record of each solve for an event's organisers, in
  `RUN_DIR/records/`: who solved it, whether you approved the flag, it went out on its own
  under submit `auto`, or you submitted it by hand; every flag sent; each of your
  interventions with its words; and every lane's whole transcript. It is the run's log and
  nothing else, and no model is called. It holds challenge text and the flag, so it is not
  for posting. How: [docs/GUIDE.md](docs/GUIDE.md#a-record-of-each-solve).

## 0.4.0 (2026-11-13)

The solver pack (M6), and a first run that needs no reading: `flightdeck` alone opens a home
screen, `flightdeck start` sets an event up, and `/new` hands a challenge to a lane.

- `ctrl+o` in `/new`, and `/attach` with no file, open your system's file window to choose
  files. Files dropped on the console are taken wherever the focus is.

- `flightdeck` on its own opens a home screen in the console's own style: resume an event you
  played, start a new CTF from a form, practice, a demo, or install the solver pack. With no
  config it offers to get you started.
- Your first console, and the mock, open on a welcome screen that says what you are looking at
  and what to press; on an empty board, Enter goes straight to adding a challenge.

- `/config` alone opens a settings dialog: lanes at once and what happens to a flag.
- In `/new`, `ctrl+v` pastes a screenshot from the clipboard, and the lanes' model reads the
  text of a challenge's images into its description. The form says what is attached. `/attach`
  adds files to a challenge afterwards and restarts its lane.
- A challenge's description is kept exactly as you give it, in `/new` and in `flightdeck add
  --text`: a path in it is text and never attaches a file. Files are attached only by handing
  them over (`--file`, `ctrl+o`, `ctrl+v`, `/attach`, or a drop), and each one is shown
  (`flightdeck add` prints it with its size). A device, your home folder itself and flightdeck's
  own config folder or keys file are refused, with the reason.
- `/new` stays open, with everything you typed, when the challenge cannot be added, and says
  why. Big files are copied in the background while the console goes on, and a path pasted on
  the command bar never replaces what you had typed there.
- A challenge with no file and no target says so when added, and its lane is told to say what
  is missing and stop instead of spending its budget waiting.
- `flightdeck vpn add|up|status|down` keeps an event's WireGuard or OpenVPN file and connects
  it; `flightdeck start` asks for the file and `flightdeck play` offers to connect it. A missing
  `wg-quick` or `openvpn` is installed with your package manager, on your yes.
- flightdeck connects only a VPN file you added (`vpn add`, or the VPN answer of `start`): one
  merely found in a folder you play, or changed since, is said to be unverified and is left
  alone. Lines of the file that run a program as root (`PostUp`, `up`, `plugin` and the like)
  are shown and asked about first, with no as the default; `--yes` does not answer for them.
  `vpn down` stops only the OpenVPN flightdeck started; a stale `vpn.pid` is removed, not killed.

- A board you fill yourself can start empty, and `/new` in the console hands a challenge to a
  lane: its name, then one box for its description, its files and screenshots (dragged in) and
  its instance's address. `flightdeck add` does the same from another terminal, and a run picks
  up any challenge folder added to its board while it plays.
- `flightdeck pack install` in a copy installed from a clone (`uv tool install .`) uses that
  clone's pack, and such an install is rebuilt when the source changes.

- `flightdeck start` sets up an event and plays it: it asks for the event's name, site, flag
  format and CTFd access token, makes the event's folder (`event.toml` and `board/`), keeps the
  token in your keys file, says whether the solver pack is installed (and offers it), and
  launches. `flightdeck play FOLDER` then plays that folder with no `--event`.
- An event's CTFd token is tied to its site. A token already in your keys file is used again
  only for an event at the same address as one you set up before; an event of the same name at
  another address gets a variable of its own and is asked for its token.
- `flightdeck start --token-env NAME` and `--token-stdin` hand the token over in a script, from
  an environment variable or a pipe; no option takes the token itself. Options are checked
  before anything is written, and for a folder already set up start says they were not used.
- An example flag given as the flag format (`CTF{s0me_t3xt}`) is read as `CTF{...}`, and start
  and the home screen's form say what they understood. The form also says, while it is open,
  why an event cannot be set up (a folder that cannot be made, a token that cannot be kept).
- A key or token with a line break or a hidden character in it is refused before it reaches
  your keys file, and the keys file is replaced in one step, so a save that fails loses no key.
- `flightdeck init` asks for the model API from a numbered list, and takes several answers at
  once ("anthropic, openrouter" writes OpenRouter as the fallback).
- `flightdeck` on its own and `flightdeck doctor` say whether no-model solvers (L1) are
  installed; `play` on a missing or empty folder points at `flightdeck start`.

### The solver pack

- flightdeck now has a solver pack: the no-model solvers its author won events with, in the
  repository's `packs/solvers/`. `flightdeck pack install` fetches it, builds its Python
  environment (after asking) and its Docker image, and writes it into your config. On every
  challenge it unpacks the handout recursively, searches it for the flag under layered
  encodings, runs its matching analysis engines (some 800) and its decoders, and tells the
  lane's model what it found. It is not in the PyPI package.
- `flightdeck pack install SOURCE` installs any pack from a git address or a folder;
  `flightdeck pack info` and `flightdeck pack image` show a pack and build its image. A pack
  says what it needs in a `pack.toml` (docs/SOLVERS.md).
- `[l1] lane_tools = true` (which `pack install` sets): every lane's brief says where the pack
  is and how to call it, so a lane's model can list the engines that fit, read a category's
  playbook and run an engine itself. Docker lanes then run in the pack's image.
- `[l1] image`: the Docker image your pack's engines run in, when it is not the lane image.
- A route can say `any = true` (every challenge), and an engine is given the event's flag
  format in `FLIGHTDECK_FLAG_FORMAT`.

### Instances on demand

- flightdeck starts a challenge's own container on CTFd when the site has a container plugin:
  an `[instances]` table in the event profile names the plugin (or its routes), the challenge
  types that have an instance, and how many may run at once. An instance is started before a
  lane works its challenge, renewed before it ends, and stopped on the solve; a teammate's
  running instance is used and left alone. `docs/BOARDS.md` has the details.
- `challenge.json` takes `"instance": "on-demand"` and `type`; `ctfd pull` records CTFd's type.

### What lanes share

- A lane that starts on a challenge other lanes worked or still work (a fork, a fresh lane after
  a kill, the next model up the ladder) reads what each of them tried and how it ended: its
  plan, the programs it ran, its last steps, what became of its flags, the alerts on it.
  flightdeck writes that record itself, hands it over as data, and keeps it under 3,000
  characters. The run folder keeps it as `shared.json`.
- Series: challenges whose names share a start ("Harbor Lab: Read…", "Harbor Lab:
  Fingerprint…") are linked. A lane on one is told which siblings are solved and what their
  lanes found, and can read the files a sibling's ended lane left: the folder on the host
  runtime, `/series/<challenge id>` (read-only) in Docker. A sibling's flag is never in the
  brief, and under submit auto a flag that already solved another challenge waits for you when
  a lane gives it again.

### The Game Master platform

- flightdeck now plays events on a Game Master (a one-URL platform whose challenges are attempts
  you start, answered by name, hash or number rather than a flag). `flightdeck gm list URL`
  shows its challenges; `flightdeck gm pull URL FOLDER` writes the started attempts as a board,
  one challenge per answer, and names every attempt it left unstarted. `--start` starts the ones
  that run no clock; flightdeck never starts a time trial or a mastery attempt.
- `platform = "gamemaster"` in an event profile: `flightdeck play FOLDER --event event.toml`
  submits answers to the Game Master under your submit policy and closes what it lists as
  solved. A lane submits `answer{...}` and what is inside is sent (`--flag-format` and
  `event.flag_format` set another form). An answer the Game Master did not judge (attempt not
  started or expired, a refused request, a rate limit that outlasts three more sends, a reply
  flightdeck does not know) comes back to you and is never counted as wrong.
- It was built against a fake Game Master only, from the solver pack's adapter: nothing here
  has met the real service yet.

### Flags

- `[lanes] variant_tries` (0 to 12, off by default): when the platform calls a flag wrong,
  flightdeck proposes its other spellings on the same lane, best first and one at a time: the
  letter case a cipher lost, a doubled wrapper, leet, accents, spaces and underscores, and the
  prefix as the flag format spells it. Each is a flag like any other: it waits for you wherever
  a lane's own flag would, and the approval says which flag it is a variant of and what changed.
- Rotating flags: add `"rotates": 300` to a challenge's `challenge.json` when its flag changes
  every 300 seconds. The lane is told to fetch the flag right before submitting, and flightdeck
  sends a flag only in the window it was found in: one that waited into a later window is not
  sent, the lane fetches a fresh one, and nothing is counted as wrong. The first 6 wrong flags
  at such a challenge do not count toward `wrong_stop`. Under submit confirm such flags usually
  rotate out while they wait; a run says so at its start.

### Autopilot

- A second opinion on a timer: `second_after` under `[autopilot]` (seconds) forks a challenge's
  only lane onto another model of your ladder once it has run that long unsolved, or at once
  when a flag of it is judged wrong; `third_after` adds a third lane on a third model. Off by
  default, once per challenge each.

### Your machine

- The host governor: while this machine's load per CPU, available RAM or free disk at the run
  folder is past its limit, no new lane starts; running lanes carry on, and starts resume by
  themselves. Limits are in the new `[governor]` config table (`max_load_per_cpu`,
  `min_free_ram_mb`, `min_free_disk_mb`; `enabled = false` turns it off). A warning says when
  starts are held and why, and another when they resume.
- `flightdeck doctor` has a `host` line: the load, RAM and disk readings, and any `[governor]`
  limit that binds now.
- A pack's `pack.toml` can list the programs its engines call (`tools = [...]`). `flightdeck
  doctor` (`pack tools`) and `flightdeck pack info` name the ones missing on this machine or in
  the image the engines run in.

### The console

- `/config` in the console: alone it shows the run's settings; `/config lanes 8` (or
  `unlimited`) changes how many lanes run at once, and `/config submit auto` turns auto approve
  on (`confirm` turns it off), each for the rest of the run and never past the event's rules.
  `/config file` names your config file. `max_lanes = "unlimited"` in the config lifts the
  lane limit from the start.
- `/note <text>` tells every lane at once (an organizer's ruling, a replaced handout): running
  lanes read it on their next turn, and lanes started later read it at their start.

### CTFd

- Under submit auto, once the platform has called three flags wrong at one challenge, that
  challenge's next flags wait for your approval (`[lanes] wrong_stop`, 0 to turn it off), so a
  lane that guesses cannot spray the platform.
- A flag CTFd rate-limited without checking it is sent again by itself: flightdeck waits what
  CTFd asks (or 65 seconds) and resends, up to three more times, and says so on the lane.
  Before, the flag went back to you at once and autopilot disengaged. A challenge whose tries
  CTFd counts is never resent to: those tries stay yours.

## 0.3.0 (2026-11-12)

Autopilot (M5): flightdeck runs an event by rule while you are away, inside a run budget,
never looser than the event's rules. With it: headless runs with a status file and a webhook,
a Docker lane's network fenced to its challenge's instance, flight cards and a leaderboard,
and the open issues of 0.1.x and 0.2.0.

### Sharing what you ran

- `flightdeck share RUN_DIR` prints a run's flight card: your setup and models, solves by
  category, time, spend by model, how often you stepped in, and whether the run was hands-on,
  approve-only or hands-off. It holds no flag and no challenge name or text, and sends nothing:
  you paste it where you choose. A run now records its setup in `setup.json` in its folder.
- A leaderboard of the events flightdeck was used in, `docs/LEADERBOARD.md`, with an issue form
  to add yours, and an issue form for flight cards.

### Autopilot

- `flightdeck play --autopilot` (and `practice`), or `[autopilot] engage = true`: flightdeck
  runs the event by rule while you are away, never looser than the event's rules and your
  config. It escalates a stalled lane, kills a looping one, redirects a lane that ignores the
  hint, gives a lane more budget when it asks (within the run budget) and sends unsolved
  challenges round again on the next model up. It answers no flag and submits nothing itself.
  Before lanes start, `play` says what it will and will not do under this run's policies (#13).
- Autopilot needs a run budget (`--budget-dollars`, `--budget-tokens`, or `budget_dollars` and
  `budget_tokens` under `[autopilot]`) and the Docker runtime; without them `play` does not
  start and says which is missing. At the budget it holds the queue, pauses the lanes and
  disengages (#13).
- Under autopilot a flag that would spend a challenge's last counted try waits for you, with
  `submit_limited = "auto"` too, and a request a model declined is never sent on to another
  model: Anthropic's server-side refusal fallback is off while autopilot has the run (#13).
- Autopilot disengages, holding the queue and saying why, when the model API fails for every
  lane, when CTFd keeps failing, does not judge a flag or answers with a web page for a person
  (a login page, a CAPTCHA), and at the event's end. `/autopilot off` takes the controls back,
  `/autopilot on` engages it again, and the header says `AUTOPILOT` while it is engaged (#13).
- Event profiles: `[event] start` and `end` (ISO 8601 times with a zone). Autopilot waits for
  the start before it pulls anything and stops the run at the end (#13).
- The post-flight report has an Autopilot section (its interventions by rule, each disengage
  and why), and the report, the scorecard and the flight card count only your own
  interventions; the card says `autopilot: engaged, N interventions by rule` (#13).
- `flightdeck mock --scenario autopilot` shows autopilot on fake data: rules firing, then a
  disengage at the run budget (#13).

### Headless runs and notifications

- `flightdeck play --headless` (and `practice --headless`) plays a board with no console, by
  the same rules: an approval waits and nothing is approved, since nobody is watching. It stops
  on SIGTERM, Ctrl-C or a hang-up as quitting does (exit status 128 plus the signal), ends on
  its own once nothing is left to do, and names each flag left waiting as it exits (#24).
- Every run, with the console too, keeps `status.json` in its run folder: the lanes, what
  needs you, the queue, spend and solves, replaced whole at each write, so a script, tmux or a
  phone over SSH never reads half a file. The guide lists its fields (#24).
- An opt-in notification webhook: `[notify] webhook_env` names the variable that holds its URL
  (never the URL itself: it is a secret, kept out of logs, errors and the run folder), and
  flightdeck POSTs a small JSON message when a flag is accepted, a lane needs you, or no more
  lanes start. A flag's value is never sent; the guide lists every field (#24).

### Solvers (L1)

- Categories: the long names boards use (Reverse Engineering, Binary Exploitation, Web
  Exploitation, Miscellaneous, Digital Forensics and the like, in any case, joined by spaces,
  `-` or `_`) now become the short codes `rev`, `pwn`, `web`, `misc` and `for`, so L1 routes
  reach those challenges, the board sorts them by code and build mode routes a new engine by
  category (#4).
- `flightdeck gaps --pack PACK`: each gap on the board now ends with its
  `flightdeck build gap CHALLENGE_DIR --pack PACK` command, in `gaps.md`, in the printed
  summary and in `gaps.json`, the paths filled in and shell-quoted, ready to paste (#19).

- Docker on Linux: a Python L1 engine's result can be read again. The engine wrote it as the
  container's root for its owner alone, so flightdeck, running as you, could not read it and
  the engine counted as unsure. CI found it on its first run of the lane image (#7).
- Coding-agent lanes (`--agent`) run your L1 pack too, before their CLI is started and in
  Docker when lanes run there. A flag an engine finds waits for you or goes out by the same
  rules as in flightdeck's own lanes, no CLI runs while it waits (none at all when it solves
  the challenge), and the CLI's opening brief says what the engines found, as data (#26).

### The console and lanes

- `A` in the fleet (or `/approve all`) approves every flag that waits for a plain yes in one
  action: a prompt lists each flag by lane and challenge, and `y` approves them, each as `a`
  would. The flags of one challenge still go to the platform one at a time, a flag known wrong
  is never sent, and a challenge whose tries the platform counts, a hand submit, more budget
  and the live box are left for their own answer, each named (#30).
- `x` in the fleet (or `/dismiss`) takes down a lane's alert about its course without touching
  the lane. The alert stays quiet for the lane's next 3 turns, as an answered one does, and the
  run log has it as your action; `flightdeck report` counts it as dismissed, not answered (#30).
- The fleet's key line has `A approve all` and `x dismiss`, so it shows every key from 173
  columns (182 in team mode); narrower, it leaves out focus and sort first, as before (#30).
- At 64 columns or fewer the console has a compact layout, for a phone over SSH: the header
  keeps what needs you and the run's dollars, each lane's row has its alert, state and cost,
  the line under the list wraps the reason and puts one answer on a row, and a lane opens with
  what it needs above its transcript (no files pane). `flightdeck doctor` says when your
  terminal gets it, and `flightdeck mock --screenshot` saves it at 56x40 (#28).
- A model API that keeps failing with a rate limit, a 5xx or an overload now holds the queue
  once two lanes in a row end on it, instead of parking challenge after challenge; `/unhold`
  puts the challenges the outage parked back in front of the queue (#2).
- If the console itself fails, `play` and `practice` now stop the run the way quitting does
  (lanes stopped, workspaces closed, your live-box holds freed in the team folder), print the
  usual exit lines and exit with status 1 (#9).
- `play` on a board without answers (a CTFd event, say) ends with one line that says what the
  run spent: its tokens and dollars, "at least" when some spend had no price (#16).
- The help screen (`?`) explains the `sending` chip, `queue held` in the header, and the `+`
  and `…` after a lane's dollars, and its board legend says which `…` is which (#17).
- Codex lanes: a take-over that lands during a file edit or a tool step opens its shell only
  once that step is on the lane, so your first edit is never credited to the agent (#21).

- A lane's transcript keeps every tool call of a turn, each with up to 40 lines of its output,
  where it kept the first call and 3 lines; a writeup draft shows them all, 20 lines of output
  each, and finds the flag in any of them. The console's steps and the alerts that count them
  are as before (#15).

### Safety

- A Docker lane that may reach its challenge's instance now reaches that instance and nothing
  else: each host and port in the challenge's `urls`, through an internal Docker network and a
  small proxy per host, never Docker's bridge network. A coding-agent lane (`--agent`) reaches
  its CLI's API (`api.anthropic.com` or `api.openai.com`) the same way, and L1 solvers that
  run online get the same fence (#14).
- In such a lane an instance given by IP address or as `localhost` is reached as
  `instance-10-0-0-5` or `instance-localhost`, on the same ports; the lane's brief says so.
  UDP, ping and ports that `urls` does not list go nowhere: the guide's "Docker or host" lists
  what the fence does not do (#14).
- A lane whose fence cannot be built (no `python3` in the lane image, a Docker Engine that
  cannot make an internal network without a gateway, no room for another network) does not
  start, or stays without a network, and says why. It is never put on the bridge network (#14).
- `flightdeck doctor` lists the networks and proxy containers a killed run left, and
  `doctor --clean` and the next `play` remove them (#14).
- A lane of flightdeck's own loop no longer sends its model the keys flightdeck holds: every
  value in your keys file, the `[api]` and `[fallback]` keys and the CTFd token become `[NAME]`
  in what a lane's tool calls return, before the model, the console, the transcript or the run
  log has them, as coding-agent lanes already did. On `--host` this is still cleanup, not a
  fence, and a keys file that cannot be read now stops such a run before it starts (#8).

### Models

- `[api] effort` sets the Anthropic effort of each ladder model
  (`effort = { "claude-opus-5-5" = "high" }`): lanes send it, a model with no entry runs at
  Anthropic's default, a model or level the API would refuse is a config error that names the
  key, and it is not sent to the `[fallback]` API (the lane says so when it moves) (#27).

- `flightdeck eval-local --repeat N` runs each engine N times over the same cases and shows
  each run's score, the mean and the range for every job, so the spread between runs is there
  to see. A paid engine is announced as its calls x N (#11).
- `flightdeck eval-local --cases FILE` checks a case file of your own before anything is
  scored or sent (hosts under `.test` only, no key material) and names the file and the line
  of a bad case. The scorecard's second line says which case set its figures come from and
  how many runs, and `docs/MODELS.md` says the same of each per-job figure (#22).
- `flightdeck models` finds AMD and Intel GPUs on Linux and names them. It has no measured
  results for them yet, so it says so, sizes its advice as for a machine with no GPU, and
  points at `--gpu-memory` and the model results form (#25).

### Commands and docs

- `flightdeck report latest` (and `writeups`, `gaps`, `score`, `share`): `latest` means the
  newest run in your config's `[run] dir`, by when the run started; the command names the
  folder it took, and a folder really named `latest` still wins (#20).
- Install with apt, from this release on (the Homebrew formula is built but its tap is not set
  up yet, so `brew install` does not work): the `.deb` for amd64 or arm64 on the GitHub
  release (`sudo apt install ./ctf-flightdeck_X.Y.Z_amd64.deb`). The `.deb` brings its own
  Python 3.12 under `/opt/ctf-flightdeck`, since Debian 12 has 3.11. There is no apt
  repository yet, so `apt upgrade` does not find a new release (#29).
- For contributors: CI now runs the Docker tests on Linux and fails if one was skipped
  (`FLIGHTDECK_REQUIRE_DOCKER=1`), and a second job builds the lane image and runs a Python L1
  engine in it (`FLIGHTDECK_REQUIRE_LANE_IMAGE=1`) (#7).
- The README is a short front page. What it held is the player's guide, `docs/GUIDE.md`.
  `llms.txt` maps the docs for AI agents.

## 0.2.0 (2026-11-12)

A model per small job, plus fixes from a rehearsal against a real CTFd, a security review and
the first pricing issue.

### A model per small job

- `[light] jobs` lists the jobs a run gives the light model. The default is `["judge"]`, the
  hint judge alone, as in 0.1.0. A job can have an engine of its own in a `[light.<job>]` table
  (a whole engine spec that inherits nothing from `[light]`, so one API's key never goes to
  another's server): Claude Haiku for the flag check and an open-weight model on your machine
  for the rest, say.
- `flagcheck`: under auto submit, the light model looks at a flag before it goes out without
  you. It can only hold a flag for you, never submit one, and no check outlives the run.
- `route`: at a lane's start, the challenge's category where the board names none (the board's
  own category always comes first), and the specialist family it suits.
- `recon`: a first look at the handout, added to the lane's opening brief as data in a fence of
  its own, never as instructions.
- A lane says when a challenge's description names a service (`nc host port`, say) that the
  board does not list as its instance.
- `flightdeck eval-local` scores each job the way a run uses it, with cases for route, recon
  and flagcheck. Which model did best at which job is in `docs/MODELS.md`.

### Models and your machine

- `flightdeck models` knows five more small models (Qwen3.5 0.8B, 2B and 4B, Gemma 4 E2B and
  E4B) and offers each light model only for the jobs it did no worse at than no model.
- `flightdeck models --memory GB [--apple | --gpu-memory GB]` gives the advice for a machine
  you describe instead of this one. `docs/MODELS.md` is now a guide by memory, 4 to 36 GB.
- `[api] context` (and `[fallback] context`) says how many tokens your model server gives a
  lane, so the lane's context is refreshed before it outgrows it. Ollama gives 4,096 tokens by
  default on most machines, too few for a lane: `doctor` and `models` say what context Ollama
  gives your lanes' model and how to raise it, and `init` for Ollama writes the note.
- `init` no longer suggests Phi-4-mini as a light model to measure.

### Safety

- Under auto submit, before a flag a lane gives goes out without you, flightdeck looks for it
  in the challenge's whole description and handout (a coding agent's claim, the model's
  `submit_flag` and an L1 engine's result alike). A flag found there, or one flightdeck could
  not search all of the handout for, waits for you. In 0.1.0 that search stopped at size
  limits, so a stand-in flag deep in a large handout could go out.
- Coding-agent lanes in Docker keep the CLI's own configuration in the container, outside the
  workspace: nothing a lane writes or unpacks in its workspace configures the CLI at its next
  start.

### Events

- CTFd 3.8.9 answers a flag for a challenge with no tries left as a rate limit ("You have 0
  tries remaining"). flightdeck now reads that as out of tries: the flag is never recorded as
  wrong, the challenge's lanes stop, and nothing more is sent for it. It checks the
  challenge's details first, since CTFd says the same for a burst of tries within a minute,
  which passes.
- A run knows the tries you or a teammate already used: each pull reads them from CTFd, a
  challenge with none left starts out of tries, and a later pull that finds tries again (an
  admin's change, or CTFd's timeout behaviour) opens it for you to queue.
- Under the instance policy `off`, a lane's opening brief no longer offers the live instance,
  and says the event's rules keep the lane off it.
- `flightdeck preflight`'s submit auto line says that every flag of a challenge whose tries
  the platform counts waits for you.
- `[lanes] submit_limited = "auto"` lets auto submit spend a challenge's counted tries without
  you, the last one included. It is off by default: a wrong flag can use up the tries for your
  whole team. `flightdeck preflight` and the start of a run say when it is on.
- `flightdeck score` counts a run's solves the way `flightdeck report` does, against the board
  the run played. A solve from before the run (on the platform, or in the team folder) is not
  a solve during it.

### Prices

- A `[prices."<model>"]` table takes `cache_write`, the rate for prompt tokens written to the
  cache; `init --provider anthropic` writes it. A cache rate left out is the input rate.
- On the Anthropic API, every attempt of a call counts on the lane's meter at the price of the
  model that ran it, including the attempts the refusal fallback ran and calls every model
  declined. `[prices]` may price the models the fallback answers with, and `play` says before
  lanes start what your config prices low or not at all.
- A reply cut short by a kill, a solve or quitting still counts what its call cost.
- Fast mode: tokens read from or written to the cache are priced with the cache multipliers on
  the fast rate. 0.1.0 priced them at the full fast input rate, which showed a fast lane at
  about twice its cost.

### Commands and docs

- `flightdeck preflight` describes each policy as `play` follows it, and refuses an event
  profile whose agents policy is `manual` or `off`, as `play` does. "preflight: ok" means
  `play` will start. Its token line reads your keys file as well as the environment.
- `flightdeck init` says what the host runtime means where it asks for the runtime, and
  `flightdeck doctor` warns when your config runs lanes on the host: lanes run as you, and can
  read your files and keys.
- `flightdeck writeups`, `score` and `build gap` answer a path that starts with `~` for a user
  that does not exist with one line, not a traceback (#18; thanks to bfs2021 for the fix).
- `flightdeck models ID` prints `timeout = 600` with a local model's `[api]` lines, as `init`
  writes it.
- `flightdeck --help` groups the commands as Set up, Play, Before and during an event, After a
  run, and Solvers (L1); arguments are named in upper case (`RUN_DIR`, `BOARD`, `PACK`).
- The practice set's README says that a coding-agent lane (`--agent`) is always on the network,
  so it can download the reference solutions: practice with `--agent` is not honest practice.
- The README is reordered, with sections for Docker or host, the words flightdeck uses,
  coding-agent lanes, and configuration and files; its links work on PyPI. Two new guides:
  `docs/BOARDS.md` (the board folder, `challenge.json`, the event profile) and
  `docs/SOLVERS.md` (L1 packs, manifests, `l1 import`, build mode).

## 0.1.0 (2026-11-11)

The first public release. flightdeck pulls a board, runs your own no-model solvers first, starts
an agent lane per challenge on a model API or a model server on your machine, and shows every
lane in one terminal console, where you approve flags and step in when a lane goes wrong. It
plays CTFd events and team play by the event's rules, and after a run it writes a report, writeup
drafts and the list of challenges your solvers missed.

### What's in it

- **The console.** A fleet view of every lane, sorted by what needs you, and a focus view of one
  lane with its transcript, the files it changed and a chat box. One key pauses, hints,
  redirects, forks, kills, escalates or takes over a lane. `flightdeck mock` shows it on
  scripted data, with no setup.
- **Lanes.** `flightdeck play BOARD` plays a folder of challenges, each lane in its own Docker
  container or on the host, with token and dollar caps per lane. `flightdeck practice` plays 14
  small challenges that ship with flightdeck.
- **Models.** OpenRouter or any OpenAI-compatible API, the Anthropic API (with a fallback API
  and fast mode), or Ollama or an MLX server on your machine. `flightdeck models` says which
  local models fit your machine.
- **Your solvers first (L1).** A pack of your own no-model solvers runs on each challenge before
  the lane's first model call, so a solve can cost no tokens.
- **Events and teams.** `play --event event.toml` follows an event's rules stage by stage, pulls
  and submits through CTFd, and shares claims and solves with teammates through a synced folder.
- **Coding-agent lanes.** `--agent claude` or `--agent codex` runs each lane as that CLI, behind
  the same controls.
- **Alerts and the light model.** Alerts for effort out of proportion, an ignored hint, a wrong
  direction on web, loops and stalls. An optional light model can take an "ignores the hint"
  alert down.
- **After a run.** `flightdeck report`, `writeups`, `score`, `gaps` and `build`.
- **Setup.** `flightdeck init` writes a config from a few questions, `flightdeck doctor` checks
  the setup and says how to fix each problem, and `flightdeck image build` builds the lane image.

### Safety

- A Docker lane has no network unless its challenge has a live instance. Under the instance
  policy `confirm` a lane asks before it may reach the instance, and until you say yes its
  container has no network.
- When lanes run in Docker, your L1 solvers do too: each engine in a container of the lane
  image, your pack mounted read-only, with no network unless the event lets lanes reach the
  challenge's instance at once. Under `confirm`, `manual` and `off` no engine can reach the
  instance. On the host runtime engines run as you.
- A flag reaches the platform only after you approve it, or under auto submit when a lane claims
  it. Under auto submit these still wait for you: a flag found in what a text-output engine
  printed; a flag written in the challenge's own text (its description or a handout file, often a
  decoy), whether the model submits it or an L1 engine returns it, and the lane says why; and
  every flag of a challenge whose tries CTFd counts. flightdeck never spends a challenge's last
  try on its own.
- The flag format, which comes from the board or the event profile, reaches a lane as data in
  the challenge brief, never in the system prompt; coding-agent lanes read it the same way. It
  is checked wherever flightdeck loads one (a board's `board.json`, an event profile,
  `--flag-format`) and again when a run starts: one line, no control, invisible or bidirectional
  character, at most 200 characters, and a regular expression that compiles. An error names
  where the format came from and the rule it breaks.
- The take-over shell reads no startup file (in Docker too), and on the host its HOME is a new
  folder only you can read, outside the workspace, removed when you hand back. So a `.bashrc`,
  `.bash_profile` or `.inputrc` that a lane, or an archive it unpacked, planted in its workspace
  never runs as you.
- What flightdeck keeps and shows of a run has the value of anything shaped like a credential
  taken out: the run log (`events.jsonl`), lane transcripts, `flightdeck report`, writeup drafts
  (with or without `--redact`) and what the console shows of a lane. That covers an upper-case
  `NAME=value` or `NAME: value` whose name holds KEY, TOKEN, SECRET, PASSWORD, PASSWD, COOKIE or
  AUTH (a Makefile's `:=`, `::=`, `?=` and `+=` too), Authorization and Cookie header values,
  and keys with a well-known prefix (`sk-ant-`, `ghp_`, `AKIA` and the like). The name stays
  and the value becomes `[redacted]`. Flags stay whole, since hiding them is `--redact`'s job.
- Coding-agent lanes hide every secret the run holds, not only the agent's own key: each value
  in your keys file, the `[api]` and `[fallback]` keys and the CTFd token show as `[NAME]` in
  the run's events and transcripts.
- The CTFd token comes from the environment variable the event profile names and goes only to
  that CTFd.
- If flightdeck itself is killed (kill -9, a power loss), what its lanes started can keep
  running: lane containers, L1 engines, coding-agent CLIs, servers a lane left in the
  background. The next `play` or `practice` removes it before it starts, wherever the run's
  folder is (`--run-dir` included), and says what it removed; `flightdeck doctor` names it, and
  `flightdeck doctor --clean` removes it. Only what a run marked is touched (its labelled
  containers, the process groups it recorded), never another setup's.

### Known limitations

- A run cannot be resumed: quitting stops every lane and closes its workspace.
- Coding-agent lanes do not run your L1 pack, and codex reports no cost (price its models under
  `[prices]` to see dollars).
- A lane that may reach its instance gets the open bridge network: there is no allowlist per
  host.
- macOS and Linux only; Windows through WSL.

<details>
<summary>Everything in 0.1.0, by area</summary>

**The console**

- `flightdeck mock`: the console on scripted data (fleet view and focus view, alerts, every
  intervention), with `--screenshot` for headless SVGs.
- Flags wait for you: `a` or `1` submits, `d` or `0` declines. On a board that cannot check
  flags you submit by hand and say whether it was accepted.
- `t` hands you the lane's real shell (its container in Docker); exit it to hand the lane back,
  and the lane hears what you changed. Other lanes keep working meanwhile.
- `q` while lanes are open asks first and says what quitting stops, naming each flag on its way
  to CTFd (quitting leaves its answer unknown); `y` quits, `n` or `esc` stays. Quitting stops
  every lane's work at once and raises no budget alert, approval or queued start while the run
  closes. What a coding-agent CLI spent in the turn that quitting cut still counts in the
  totals, the transcripts and the scorecard.
- Closing the terminal, an SSH drop or a SIGTERM stops every lane and closes every workspace, as
  quitting does; `play` exits with 128 plus the signal's number.
- `play` and `practice` end with the run folder and the commands that read it, ready to paste
  (`flightdeck report`, `writeups` and `gaps`, plus `score` when the run's board has answers),
  and name any flag that was still waiting for your approval. A run that ends with the queue
  held says so, with why and how many challenges never started.
- When the queue is held (a model API failure every lane would hit), the header says "queue
  held" and why, never "all clear", and the status line says how to lift it: once you have fixed
  the cause, `/unhold` starts the queued lanes in the free slots. Help and the `/` menu list it,
  and the menu offers it first while the queue is held. A key or model id changed in your config
  needs a new run.
- The key line always shows `? help` and `q quit`, and keeps approve, decline and the commands
  on a narrow terminal.
- A challenge solved with the flag an L1 engine found shows as `L1·<engine>` on the board (the
  owner column, the why line, the challenge card), as every report credits it, whichever lane
  submitted the flag.
- Help and the `/` menu say what take-over and decline do in a run.

**Lanes**

- `flightdeck play BOARD`: agent lanes play a folder of challenges against an OpenAI-compatible
  API (OpenRouter by default), each lane in its own Docker container or on the host. Lanes start
  cheapest-first; `max_lanes` run at once and the rest queue.
- `flightdeck practice`: 14 small synthetic challenges that ship with flightdeck, checked by
  hash.
- A lane's brief names a TCP service with the command that reaches it: `tcp://host:port (nc
  host port)`.
- A lane whose history passes 50k prompt tokens continues in a fresh context with a compact
  summary of the lane (its plan, newest steps, files, flags and what became of them, alerts and
  your messages), so a long lane does not get more expensive with every turn. Escalation hands
  the stronger model the same summary. Both keep what your L1 solvers found, in a message that
  is capped.
- A model that answers three times in a row without calling a tool gives up, quoting what it
  last said; a flag it writes in such a reply waits for you.
- A model API failure every lane would hit (no answer, a refused key, no credits, an unknown
  model) holds the queue and says what to check; the rest of the board stays queued.
- A lane that gave up while its flag waits (for you, or for CTFd's answer) takes no more turns,
  so a hint, a new plan or an escalation is refused, saying why: fork it onto another model
  (`f`), or answer or wait for its flag.
- A flag the platform rejected, or that you declined, is never asked about or submitted again
  on that challenge, by any lane, and an escalated model hears about it.
- The search for a flag in the challenge's own text says what it left out of the handout: the
  rest of a file past 1 MB, files past 16 MB in all, a file it could not read, files past the
  first 5000.
- Every run writes an append-only `events.jsonl` and each lane's full transcript.

**Alerts**

- Effort against a challenge's points and solves, ignoring the description's hint, the wrong
  direction on web, loops and stalls. An alert you just answered stays quiet for a few turns.
- The effort alert counts cached prompt tokens at a tenth, about what they cost, so a
  coding-agent CLI that resends a large cached prefix every turn does not raise it after a few
  cheap turns.

**Cost and budgets**

- Per-lane token and dollar caps (an alert at 80%, an approval at 100%), cost from the API or
  your config's prices, cached tokens counted.
- A coding-agent CLI reports what a turn cost only when the turn ends. Until then its lane's
  cost, and the header's dollar total, end in `…` and never show a settled $0.00. A cost
  reported after the lane ended (solved or killed mid-turn) still counts for the lane, the run
  and the reports.
- A turn whose cost never came (the CLI was stopped in it, or exited) is priced from your config
  when it has a price for its tokens. Otherwise the lane's dollars become an "at least" figure
  (`$0.42+`), a dollar cap holds on what is known, and only spend with no price asks you to drop
  the cap.
- `[prices."<model>"]` may name a model of an `[agents]` ladder, so codex lanes, which report
  tokens but no cost, get dollars. `play` names the codex models with no price, and `flightdeck
  config` lists the priced ones among its prices. claude keeps its own figure.
- A budget alert for spend with no price names the model that spent it ("No price for ..."): an
  escalated lane's earlier model, or a CLI's model.
- The fleet's cost column always has room for `+` (some spend had no price) and `…` (a CLI
  turn's cost still to come). A spend under half a cent shows as $0.0007 (or <.01 in a narrow
  column), never $0.00.
- `flightdeck config` says "no dollar cap" for lanes without one.

**Your solvers first (L1)**

- L1 solver packs: your no-model solvers, each with a small manifest saying which challenges it
  fits. `flightdeck l1 import` writes the manifests for a folder of scripts without changing the
  scripts, and shows the route each script got and how to change it.
- With `[l1] pack` in the config (or `--pack`), a lane runs the engines routed to its challenge
  before its first model call. A flag one finds waits for your approval (under auto submit, an
  engine's result goes at once), so a solve can cost no tokens at all.
- `flightdeck l1 route` says why a challenge reaches no engine.
- A cancelled engine run (a lane killed, a quit) removes its copy of the challenge.

**Model APIs**

- OpenRouter, OpenAI or any OpenAI-compatible API, and the Anthropic API for flightdeck's own
  lanes: `flightdeck init --provider anthropic` writes Claude Haiku, Sonnet and Opus 5.5 with
  their prices.
- A fallback API: any config can name a `[fallback]`, and with an Anthropic key `init` offers
  OpenRouter as one when `OPENROUTER_API_KEY` is set. A lane whose calls keep failing moves
  there for the rest of its context and says so. `flightdeck doctor` checks its key.
- Before lanes start, `play` and `practice` check that each model API takes your key and serves
  every model in your ladder (the Anthropic API through its Models API). If not, they stop and
  name the closest ids the API does serve, or the key's variable, or say to start your local
  model server.
- Fast mode on the Anthropic API: `[api] fast = ["claude-opus-5-5"]` calls those ladder models
  at up to 2.5x the output speed, priced at the fast rate. A model without fast mode is refused
  with the reason. On fast mode's own rate limit a lane goes on at standard speed and says so.
- `[api]` and `[fallback]` take `timeout`, the seconds one try of a lane's call may take (180
  by default, 600 with the Anthropic API), and `max_tokens`, the most tokens a lane's reply may
  hold. Unless you set it, a server on this machine is sent 8192 (mlx_lm.server's own default is
  512, too few for a model that reasons first), the Anthropic API 16000, and any other
  OpenAI-compatible API none.

**Local models**

- `flightdeck models`: what this machine has for local models (chip, memory, NVIDIA GPUs, the
  model servers on 127.0.0.1), then, for lanes and for the light model, the models that fit and
  why, and those not offered for a role, with the reason: open-weight models on this machine
  first where they run well (Apple Silicon, an NVIDIA GPU), then the model APIs. It recommends
  and never changes a config.
- `flightdeck models ID` prints how to get a model, with the server arguments it was measured
  with, and the config lines that use it (`--json` for scripts).
- Its catalog: Qwen3.5 9B, gpt-oss 20B, Gemma 4 12B (light role only) and Phi-4-mini (measured;
  offered for no role), on Ollama and MLX, the Anthropic API and OpenRouter. It shows what a
  benchmark measured for each model on each runtime (practice challenges solved, tool calls, the
  light-role score), and a build that measured badly is not offered for that role (see
  [docs/MODELS.md](docs/MODELS.md)).
- `flightdeck init` suggests the local models that did best in that benchmark: `gpt-oss:20b`
  for lanes on Ollama, Qwen3.5 9B for lanes on MLX and as the light model (`--light ollama|mlx`).
  At a terminal the suggestion is the default answer; away from one, the message names it.
- For a server on this machine `init` writes `timeout = 600` and `max_tokens = 8192` under
  `[api]` (a local model can take minutes for one reply), and for MLX it prints the
  `mlx_lm.server` command to start, with thinking off and replies of up to 8192 tokens.
  `flightdeck doctor` says what lane calls to a server on this machine send and how long each
  try may take (`lane calls`), and compares your ladder with what the server lists.

**Light model**

- `[light]` picks the light model for small jobs, on one of five engines: `rules` (the default:
  no model), `openai` (any OpenAI-compatible server; recommended: an open-weight model on your
  own machine through Ollama or an MLX server), `anthropic`, `cactus` (Cactus Needle, a small
  on-device model, in the optional extra `pip install "ctf-flightdeck[cactus]"`, with its
  telemetry turned off; nothing uses it unless you choose it) or `decider` (a Strands Decider
  server on your machine, a decision model that picks one of the options with a calibrated
  confidence). `flightdeck init --light ollama --light-model M` writes one, and `flightdeck
  doctor` checks it.
- Its job in a run is the hint judge: an "ignores the hint" alert shows at once, and comes down
  if the light model says the lane follows the hint after all. The light model never holds up a
  lane or an alert: when it refuses, fails, times out or answers outside the options, the rules'
  answer stands and the run says so once. Its spend is counted on the lane.
- A decider's answer below `[light] threshold` (0.9 by default) is unsure, and the rules' answer
  stands. `flightdeck init --light decider` writes it and says how to start its server, and
  `flightdeck doctor` checks the server.
- A light model on a server on this machine is asked, with each request, to answer without
  thinking first (`[light] thinking`: false by default there, and written by `init --light
  ollama|mlx`): a model that reasons first spends a job's few hundred tokens reasoning and
  answers nothing. `thinking = true` sends nothing extra, and an API elsewhere gets nothing
  extra unless you set `thinking = false`. The run says when thinking is off, and `flightdeck
  doctor` says whether it is.
- `flightdeck eval-local` scores any engine against the rules on hint, judge and summary cases
  before you trust it, and `--compare` scores several side by side: accuracy, refusals and
  failures, time and cost per job. A paid API is announced first, with its number of calls (one
  per case). `--engine decider --base-url URL` (or `--compare decider@URL`) scores a decider:
  its unsure answers in a row of their own, neither right nor wrong (its accuracy is over the
  answers it was sure of), and summaries as n/a. `--thinking on|off` measures either way (by
  default as your `[light] thinking` says for that server).

**Events and teams**

- `flightdeck preflight event.toml`: what an event's rules allow, and how far flightdeck goes on
  its own at each stage (pull, L1, agents, submit, live instance). It says when nothing runs at
  the l1 stage (no `[l1]` pack) and how to set one, and that under submit `auto` only a flag a
  lane claims goes to the platform at once (a model's submit, a coding agent's `FLAG:` line, an
  L1 engine's result); any other match waits for you.
- `flightdeck play FOLDER --event event.toml`: play an event by its rules. A CTFd board is
  pulled into the folder, new waves are added as they appear, the flags you approve are
  submitted through CTFd, and your team's solves stop your lanes on those challenges.
- A TCP service is a live instance: `tcp://host:port` in a challenge's `urls`, and what a CTFd
  pull reads from connection info like `nc host port`. A docker lane on it gets the network
  (asking first under `confirm`) and its brief names it.
- A challenge CTFd lists as solved closes in solo mode too, credited as CTFd says: you, your
  team, or "you or your team" when CTFd does not say.
- Flags go to CTFd from a worker off the console, so a slow CTFd neither freezes the console nor
  holds a lane up. A lane carries on while its flag is on its way (the fleet shows `sending`),
  one flag goes at a time per challenge, and CTFd's answer counts when it comes, also after the
  lane was killed or gave up (if the challenge was solved meanwhile, the answer is only
  recorded). A flag still on its way when you quit is named on the way out, as not known to
  have been submitted.
- A pull writes CTFd's `max_attempts` into a challenge's `challenge.json`, and a wrong flag's
  "You have N tries remaining" switches the challenge to asking you (said once, as a warning).
  Each approval says how many tries are left.
- A flag on its way to CTFd that comes back to you (no verdict, or the tries are counted) waits
  on every lane that sent it and is still at work. One you declined meanwhile is not asked
  again; one you approved goes on its turn without asking twice, unless that turn would spend
  the last try. A lane that gives up while its flag is on its way calls the model no more (a
  coding-agent lane's CLI stays frozen), and the answer ends it.
- `play` says which flag format the run checks flags against, and where it came from.
- Team mode: `flightdeck team init DIR`, then `--team-dir DIR`: teammates share claims,
  live-box holds and solves through a synced folder.

**Coding-agent lanes**

- `--agent claude` or `--agent codex`: lanes are that coding-agent CLI, with its own models
  (`[agents]` in the config) and its own key or token (claude: `ANTHROPIC_API_KEY` or
  `CLAUDE_CODE_OAUTH_TOKEN`; codex: `CODEX_API_KEY`, or a saved login on the host runtime),
  behind the same controls; `flightdeck doctor --agent claude` checks it first.
- Handing a lane back after a take-over interrupts the agent before it runs again, so a step it
  chose before you took over never runs, and the take-over shell opens only once the agent's
  last command is on the lane.
- `flightdeck doctor --agent`: the `[api]` key is only a warning (agent lanes never use it), the
  lane image is probed for the CLI as `play --agent` does, and the closing line says
  `flightdeck practice --agent ...`.

**Setup**

- `flightdeck` on its own says what it is and the next step on your machine; a missing config
  points at `flightdeck init`; a path under a `~user` that does not exist is a message, not a
  traceback.
- `flightdeck init` writes a config by asking a few questions. It checks each answer as you give
  it and asks again, says first if a config is already there, names a key that is already set
  (in your environment or the keys file), takes `ollama` as the local provider and `--runtime
  docker|host`, and away from a terminal names every option it still needs in one message. Its
  errors name your config file.
- `flightdeck doctor` checks the setup and says how to fix each problem. It names the machine in
  one line and points at `flightdeck models`, and its Docker advice fits your runtime. Its
  terminal check says what your terminal's size leaves out of the console on a busy run, and
  from which size nothing is left out (147x18 for four lanes in Docker; team mode's key line
  needs 156 columns).
- `flightdeck image build` builds the lane image once.

**After a run**

- `flightdeck report RUN_DIR`: the post-flight report (where lanes stalled, which of your
  interventions helped, cost per solve), written to `report.md` in the run folder.
- `flightdeck writeups RUN_DIR`: a writeup draft per solved challenge from its lane's transcript
  (`--redact` hides the flags). `--polish MODEL` has that model tidy the prose through the API
  in your config: it spends tokens, and the model never sees the run's flags, commands or
  outputs.
- `flightdeck score RUN_DIR`: scores a past run against the board's answers, and a run on a
  board with answers ends with that scorecard.
- `flightdeck gaps RUN_DIR`: the challenges no L1 solver solved, and why; with `--pack`, which of
  your engines would reach them.
- Build mode: `flightdeck build gap CHALLENGE_DIR --pack PACK` writes a new engine stub, its
  manifest and a test that passes only when a raw handout reaches the engine and it finds the
  flag (kept as a hash); `flightdeck build check PACK` runs those tests (`[build]` extra).
- The report and the scorecard count each spend for the model that spent it (an escalated
  lane's earlier model too), and show a coding-agent CLI's own cost of its turns apart from
  spend outside a turn. A CLI turn whose cost never came leaves that model's dollars, and the
  lane's in its writeup, unknown, with the part that is known; the scorecard notes such a turn.

</details>
