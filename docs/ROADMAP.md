# Roadmap

What is released, what comes next, what is still open, and how the first release was built.
[CHANGELOG.md](../CHANGELOG.md) says what each release changed for players.

## Built, not released: proposals after 0.6.0 (2026-11-16)

Proposals built and waiting for a release, in the order of their numbers in
[DECISIONS.md](DECISIONS.md); the lines for players are under Unreleased in
[CHANGELOG.md](../CHANGELOG.md).

- **Timeline replay in `play`** (P99; until now in "Still open from M0 to M4"). `play --waves`
  releases a folder board wave by wave from its `timeline.json`, `--timeline FILE` from another
  file, and `--speed` plays it faster or slower. Each wave's release line names the next. Until
  now `play` put the whole board out at the start, and `practice_mode.Release` was used by no
  command.
- **ACP agents as lanes** (P100; until now in "Still open from M0 to M4"). `--agent acp` runs
  the agent `[agents.acp]` names over the Agent Client Protocol, version 1. Met a fake only.
- **Both coding-agent CLIs played the whole practice set for real** (2026-11-16,
  [#3](https://github.com/MFisher14/ctf-flightdeck/issues/3)): claude 2.1.325 in docker lanes
  behind the fenced network, with tool calls (12 of 14), and codex 0.167.0 on the host with a
  saved ChatGPT login (13 of 14). It found that `doctor --agent` checked `[lanes] image` while
  `play` under `lane_tools` runs lanes in `[l1] image`; both now ask about the same image.
- **What the practice set costs** ([#43](https://github.com/MFisher14/ctf-flightdeck/issues/43)):
  $0.02 on Haiku 5.5, through OpenRouter or as claude lanes ([MODELS.md](MODELS.md#what-the-practice-set-costs)),
  and `flightdeck practice` says so before it starts. Measuring it found that Claude models on
  OpenRouter used no prompt cache; each request now carries OpenRouter's cache breakpoint (0% to
  72% of the prompt read from the cache).

## Released: 0.6.0, lane sessions and more platforms (2026-11-16)

Thirty proposals, in the order of their numbers in [DECISIONS.md](DECISIONS.md) (P69 to P98),
and the review fixes made before the release; the lines for players are under 0.6.0 in
[CHANGELOG.md](../CHANGELOG.md).

- **A take-over whose shell fails gives the console back** (P69). No `docker` to run, a
  container that is gone, a cancel: the console comes back at once, the lane is handed back as
  it was, and the status line says why. Until now Textual's suspend was never left when the
  shell's start raised, and the console drew nothing.
- **Three small gaps in the console** (P70). The mock rings the bell only with `bell = true`
  (a run rings as P61 has it), `/copy ` lists what it copies, and the simple key line shows the
  keys for no lane while the filter hides the selected lane.
- **Up and down recall what was sent; `ctrl+g` opens the bar in your editor** (P71). One
  history for the run, shared by the lane list's bar and a lane's chat box, in memory only;
  the `/` menu keeps the arrows while it is open. `ctrl+g` hands the terminal to `$VISUAL` or
  `$EDITOR` and puts the text back in the bar on one line, sending nothing; with neither set it
  says so. Not built: `ctrl+r` search, a history kept across runs, a bar of several lines.
- **The same call in a row is one row with a count** (P72). A lane's calm view and the peek
  fold the same tool call made several times in a row into one row, `×7` first, so a lane
  that loops shows it at a glance; details and `/copy` still have every call.
- **A lane notices a server that drops its oldest messages** (P73,
  [#10](https://github.com/MFisher14/ctf-flightdeck/issues/10)). A run on Ollama 0.34.2 showed
  that past its window it leaves out a chat's oldest messages with no error and holds the
  prompt count under the window, so a lane with no `[api] context` never refreshed. The
  driver now sees a context that grew while the count did not, says so on the lane, refreshes
  it at once, and refreshes later contexts on that model at the count where the drop was seen.
- **A noCTF preset for the http platform** (P74). `preset = "noctf"` plays an event on noCTF,
  DownUnderCTF's platform, with the session token the site keeps, and `flightdeck http example
  --preset noctf` prints a profile for it
  ([BOARDS.md](BOARDS.md#a-board-from-a-platform-with-a-json-api)). No change to the engine
  was needed: every route fits the `[http]` table as it was. Like the rctf preset, it has met a
  fake on 127.0.0.1 only, never a real noCTF.
- **GZCTF as a preset** (P75). `preset = "gzctf"` with the game's number and the player's
  `GZCTF_Token` cookie: the board, attachments and counted tries, a flag judged after it is
  taken, the team's solves, and `[http.refuse]`, which keeps every flag back from a site that
  wants it encrypted; `flightdeck http example --preset gzctf`. Written from GZCTF's public
  source and tested against a fake on 127.0.0.1 only, never a real GZCTF; a site that encrypts
  its flags gets none from flightdeck, and the player submits them on the site.
- **A pack names the flightdeck it needs** (P76). `flightdeck = ">=0.6"` in a `pack.toml`; a
  flightdeck that does not meet it refuses the pack, at install and wherever its engines are
  found, with both versions and what to do.
- **How a drop works in your terminal** (P77). The `/new` form and help say it in one
  sentence chosen from `SSH_CONNECTION`/`SSH_TTY`, `TMUX` and `TERM_PROGRAM`: over SSH,
  inside tmux, VS Code's terminal, iTerm2 and WezTerm on X11 have their own; every other
  terminal gets the general one. Each sentence is from that terminal's own source or
  documentation; none was tried in the terminal itself.
- **Coding-agent lanes hold the queue on an outage; a redirect that did not take escalates**
  (P78, [#33](https://github.com/MFisher14/ctf-flightdeck/issues/33)). The `claude` and `codex`
  lanes hold the queue on a model API outage as flightdeck's own lanes do, so autopilot
  disengages with `--agent` too; and a hint or wrong-way alert that comes back after
  autopilot's redirect escalates the lane one rung (at the top it is killed and parked), where
  it used to wait for you. This was the first item left of M5.
- **Settings and health on the home screen** (P79). The config's main settings, each with
  where it is set, and doctor's checks with their fixes, run in a child process that leaving
  the screen stops. A key is `set` or `not set`. Not built: changing a setting there, and the
  checks shown one by one.
- **ctfd-whale instances** (P80). `plugin = "ctfd_whale"` in `[instances]`: a start is never
  sent while the account runs a container, since whale's start removes it; another
  challenge's container reads as the cap; each of the router's five address forms is read,
  and a TLS endpoint reaches a lane as `tls://host:port` ([BOARDS.md](BOARDS.md#which-plugin)).
  Tested against a fake of the plugin's source only.
- **Instances beyond CTFd, rCTF v2's first** (P81). `[instances] plugin = "rctf"` with
  `preset = "rctf2"`: the instancer is asked by the challenge's string id with the `[http]`
  table's own sign-in; an instance may have several addresses, and one still starting is
  waited for; a start behind a CAPTCHA is left to the player
  ([BOARDS.md](BOARDS.md#instances-on-demand)). Built from rCTF v2's API reference and tested
  against a fake of it only. A `tcp-ssl` address reaches a lane as `tls://host:port`, the form
  P80 made for ctfd-whale. Not built: klodd's instances (it wants a CAPTCHA for every start);
  GZCTF's came with P88.
- **Sessions** (P82). flightdeck's own lanes keep a program running across turns (gdb, an
  interpreter, `nc` to the instance) with `session_start`, `session_send` and `session_close`:
  at most three per lane, closed after ten minutes unused, and all closed at a take-over and at
  the lane's end ([ARCHITECTURE.md](ARCHITECTURE.md#sessions)).
- **A lane waiting for a live-box answer gives its slot up** (P83, from issue #33): the next
  queued challenge starts in it, and once answered the lane takes the next free slot before
  anything queued. It was the last item left of M5 that was not about coding-agent lanes or a
  real event.
- **Tests wait for what must happen, also on a busy machine** (P84). A console test's
  `pilot.pause()` waits until the screen has settled, not until the process looks idle, and
  the tests that waited for a time now wait for the condition they meant. No change to
  flightdeck itself; CONTRIBUTING says what a pause waits for.
- **Three leftovers from the review** (P85). `flightdeck init --force` replaces a config whole
  (`config_edit.replace_file`), never writes over it in place; a `/new` with images that fails
  after it was answered removes the copies of its drop and says so; `ctrl+o` in the lane list
  opens the file window for the selected lane's challenge, as a bare `/attach` does.
- **Claude lanes checked against a real Claude Code** (P86,
  [#3](https://github.com/MFisher14/ctf-flightdeck/issues/3), in part). A run of Claude Code
  2.1.325 with no tools: a claude lane now ends a turn with an interrupt request, not SIGINT
  (which ended a claude waiting for a message), counts the output tokens its events miss, and
  charges a call an interrupt cut short. Still open: claude's tool calls, a whole `practice
  --agent claude` run, and all of codex.
- **Sessions in the brief, and on a terminal** (P87, after P82). flightdeck's own lanes are
  told of their session tools in one line of the brief (coding-agent lanes, which lack them,
  are not), and `session_start` takes `terminal: true`: the command runs on a pty under a small
  relay, with no controlling terminal, `TERM=dumb` and no echo, and its escapes are stripped
  before the model or the console see them ([ARCHITECTURE.md](ARCHITECTURE.md#sessions)).
- **GZCTF's containers** (P88). `[instances] plugin = "gzctf"` with `preset = "gzctf"`: the
  container of a challenge whose type is a container one is started, extended and stopped
  with the `[http]` table's cookie and game, its address read from the challenge's own detail;
  10 seconds between two changes, as GZCTF wants; a container behind GZCTF's own WebSocket
  proxy is said to be one no lane can reach ([BOARDS.md](BOARDS.md#which-plugin)). Built from
  GZCTF's public source and tested against a fake of it only, never a real GZCTF. Not built: a
  guard against a site that removes the team's oldest container at its limit (the setting is
  not shown to players).
- **`http check` asks the instancer, and "errored" is a failed instance** (P89). With
  `[instances]`, `flightdeck http check` sends one status `GET` for the first on-demand
  challenge (never a start) and prints what the site said; rCTF v2's `errored` is its own
  state (`failed_states`, `InstanceFailed`): no start is sent while the site says it, and the
  status is asked again later. Not confirmed: what rCTF does with a start of an errored one.
- **`/settings` in a run is Settings and health** (P90). The home screen's screen opens over
  the console, with the run's own settings on top (`c` opens `/config`'s dialog) and a line
  that counts the lanes that need you. Its checks run in the child at a lower priority, and
  what they found is kept for the run until `r`. `/config` is unchanged; `/settings` is no
  longer its alias.
- **The other waits for the player give their slot up too** (P91, after P83). A lane waiting
  for a flag answer or more budget gives its slot to the queue once it has waited a minute; at
  most `max_waiting` lanes (`[lanes]`, 4) are without a slot at once, and a lane whose sessions
  run on keeps its own.
- **No dollar cap for a custom server on this machine** (P92). Setup treats a custom
  OpenAI-compatible server at `127.0.0.1`, `localhost` or `::1` as it treats Ollama and MLX:
  no dollar cap, the token cap kept, and one line in the setup notes for a local proxy to a
  paid API.
- **The welcome screen names one key where there is one way on** (P93). On a loaded board
  and in the mock, Enter and esc both opened the console under two names; the key line now
  says `enter  open the console` alone, and esc and q still close it. An empty board keeps
  both, since there Enter opens `/new`.
- **The config folder follows `$XDG_CONFIG_HOME`** (P94). The config, the keys file
  and the themes are in `$XDG_CONFIG_HOME/ctf-flightdeck` when that is set, as notes and packs
  already follow their XDG variables; `~/.config/ctf-flightdeck` stays the default. A file left
  at the old place is still found, and every command says once where (doctor in its own line).
- **`flightdeck start` sets up an event on rCTF, rCTF v2, noCTF or GZCTF** (P95). The platform
  menu's third answer asks which of the four, the address (a page's path is cut where the
  routes are under the site's root; a GZCTF game's page gives the game) and the token, kept
  under a site-bound `RCTF_TOKEN_<NAME>`-style variable. The event file carries the `[http]`
  table `flightdeck http example --preset NAME` prints. The home screen's form asks the same.
  Not built: a table of your own routes from start, and asking the site which platform it runs.
- **The lane list's selection follows what you see** (P96). A filter that hides the
  selected lane selects the row the cursor is on, so the keys act on the highlighted row; a
  lane you approve, decline or kill from the list that folds into `N finished` hands the
  selection to the next lane that needs you, else to the row under it.
- **Settings and health in two columns; the narrow note goes when the terminal widens** (P97).
  A long path, a where line or a check's detail wraps under its own column at 80 columns. The
  layout list's "this terminal is narrow" note, and that part of the status line, go once the
  terminal is made wide.
- **One vocabulary for an answer** (P98). A lane that waits for you shows `1 0 answer` on the
  simple layout's key line, in the list and in its view, matching the numbers and words of the
  why line and the card (`1 more budget  0 stop the lane`); `a` and `d` still act. A budget
  wait about a model with no price says so when the lane gives its slot up.

Not verified yet: noCTF, GZCTF, rCTF v2, ctfd-whale and GZCTF's containers have met fakes only,
never a real site; gdb and radare2 have not been run in a session; the console was driven in a
pseudo-terminal with a terminal emulator, not looked at in each terminal program or in tmux; and the claude lane's whole `practice --agent claude`
run is not done.

## Released: 0.5.0, the calm console, themes, plugins and the http platform (2026-11-14)

Eighteen proposals, in the order of their numbers in [DECISIONS.md](DECISIONS.md) (P51 to P68),
and the review fixes made before the release; the lines for players are under 0.5.0 in
[CHANGELOG.md](../CHANGELOG.md). P54 to P62 and P64 to P68 were built from the list of what comes next (the
[milestones](https://github.com/MFisher14/ctf-flightdeck/milestones) have the rest).

- **The simple layout** (P51). The console opens on one list of lanes, a short header and the
  keys that apply to the selected lane now; `/layout deck`, or `layout = "deck"` under
  `[console]`, is the dashboard as it was. An empty board says what to do and keeps saying it,
  and the `/` menu scrolls to every command.
- **Themes** (P52). Every colour comes from one palette: five built in (`flightdeck`, `light`,
  `nord`, `gruvbox`, `dracula`) and a player's own `themes/NAME.toml`, refused when its colours
  could not be read. `/theme` switches in a running console.
- **Plugins** (P53). An event on a platform flightdeck does not know, through an adapter of the
  player's own that flightdeck runs out of process: `flightdeck plugin new`, `add` and `pull`,
  and `platform = "NAME"` in the event profile ([PLUGINS.md](PLUGINS.md)).
- **The first five minutes in words** (P54,
  [#36](https://github.com/MFisher14/ctf-flightdeck/issues/36)). The README's quickstart is
  three commands and follows the first run (the mock, `uv tool install`, `flightdeck` and its
  setup form, practice); `--help` opens with where a new player starts; `flightdeck doctor` ends
  with what is left to fix or the next command; an API key, an access token and model tokens
  are each called by name; and the guide's glossary comes second. The README and the guide
  describe the tree, so this quickstart is true of a release from 0.5.0 on: 0.4.0 has no
  setup form on its home screen, and both pages say so beside the form, with the commands that
  do the same on 0.4.0.
- **A dropped file always attaches** (P55,
  [#37](https://github.com/MFisher14/ctf-flightdeck/issues/37)). A dropped path is read as
  each terminal writes it, with only an ordinary space or a tab between two paths (a macOS
  screenshot's name on a 12-hour clock was not read from iTerm2 or Ghostty); a drop is copied
  into the run's folder as it lands; a paste that reads as a dropped file that is not on this
  machine says why; and an empty paste in the `/new` form pastes the clipboard's image. None
  of it was tried in a real terminal: each format is from that terminal's own source or
  documentation, and Terminal.app's and tmux's are not known.
- **The http platform** (P56). An event on a platform with a JSON API, played from a table of
  routes in the event profile with no code of the player's: `platform = "http"`, an `[http]`
  table, rCTF as its first preset, and `flightdeck http example`, `check` and `pull`
  ([BOARDS.md](BOARDS.md#a-board-from-a-platform-with-a-json-api)).
- **Two more CTFd container plugins** (P57). `plugin = "ctfd_owl"` and `plugin = "chall_manager"`
  in `[instances]`, the keys of a plugin's answer by name (`address_key`, `port_key`,
  `expires_key`), a start that answers without an address followed by a look at the status,
  and a refusal's reason read from `msg` ([BOARDS.md](BOARDS.md#which-plugin)). The guessed
  `ctfd_docker` shape is gone.
- **Rules that match 2026 events** (P58). An event profile can say that no challenge material
  may go to a model (`material_to_models = false`: `play` refuses, naming the rule) and hold the
  label the team declared to the event (`declared_label`: said before a run, on the flight
  card). `flightdeck records` writes a record of each solve for an event's organisers: the
  lanes' transcripts, the player's interventions, who let each flag go.
- **A debugger and a decompiler in every Docker lane** (P59). The lane image and the solver
  pack's image have `gdb` and radare2 with the Ghidra decompiler, and a lane's brief says how to
  run them without a terminal ([the guide](GUIDE.md#what-a-lanes-shell-has)).
- **A one-minute demo at the top of the README** (P60,
  [#43](https://github.com/MFisher14/ctf-flightdeck/issues/43)). `scripts/demo.py` plays the
  mock key by key with no terminal and writes `docs/screenshots/demo.gif`; the tests play it on
  every push, so a change to the console that breaks a step fails with that step's name. It is
  the console's own screenshots joined into a GIF, not a recording of a terminal. Still open
  from the same issue: what the 14-challenge practice set costs. Nothing prints a figure until
  one full run has been measured.
- **The need-you count in the terminal's title, and a bell** (P61,
  [#38](https://github.com/MFisher14/ctf-flightdeck/issues/38)). The terminal's title says how
  many lanes need the player and whether the queue is held, in a count and fixed words; the
  bell rings once each time the count goes up; the title the terminal had comes back when the
  console leaves. Both are on, each with a switch under `[console]`. Inside tmux the bell
  marks the window with nothing set up, so it is what reaches a phone over SSH. Tested on a
  pseudo-terminal; not yet looked at in each terminal program or in tmux.
- **A `/` that forgives** (P62, [#40](https://github.com/MFisher14/ctf-flightdeck/issues/40)).
  The command menu finds a command from the second word of its name or from an alias (`/q`,
  `/exit`, `/settings`, `/lanes`), lists what a command takes after its name (lanes, challenges,
  themes, layouts, sort modes, `on` and `off`), and says `No commands match "/x"` when nothing
  does. What Enter runs is as strict as it was. Not built: a lane offered after every lane
  command, `park` after `/kill`, and a search of the commands' descriptions.
- **A calm lane view** (P63). In the simple layout a lane's view is one row for each thing
  the lane did, a run of tool calls on two, and a needs-you card of three rows at most;
  `ctrl+o` or `/details` shows every line and the full card, which is what the deck layout
  opens with. Text selects with the mouse and is copied when the button comes up, and `/copy`
  copies a lane's last output, its command, its flag or its whole transcript with no mouse. A
  lane restarted by `/attach` or `/kill` from its own view takes the view to the fresh lane.
  Not built: selecting in the full card, the diff and the tables (the terminal's own selection
  reaches them), and a calm card in the compact layout.
- **The command bar names the lane it talks to** (P64,
  [#39](https://github.com/MFisher14/ctf-flightdeck/issues/39)). The bar's border reads
  `to L04 · Ticket Desk` and follows the selection in the lane list and the lane in a lane's
  view; `no lane` when there is none, `the run` while a command that takes no lane is typed,
  the lane a command names while it is typed, and `L04 has finished` or `L04 takes no more
  turns` for a lane that would refuse what is typed. The empty bar reads `a message, or / for
  commands` in both views. Not built: a border colour of its own for each of the three.
- **`?` opens help for where you are** (P65,
  [#41](https://github.com/MFisher14/ctf-flightdeck/issues/41)). In a lane, `?` on the empty
  chat box opens help; with text in the box it is a question mark, and the simple key line
  there reads `esc lanes  / commands  ? help  ctrl+o details`. Help opens on the lane in front
  of the player: the keys its key line has, each with its sentence, then the keys of the view
  it was opened from, the other view's and the ones both have. Not built: `? help` on the
  deck's and the compact layout's key lines in a lane.
- **A quiet header and quiet rows in the simple layout** (P66,
  [#42](https://github.com/MFisher14/ctf-flightdeck/issues/42)). Only what says "look here"
  keeps a block in the simple header: flightdeck, `host`, `AUTOPILOT`, `▲ N need you` and
  `queue held`; the event's name, `team`, the queue and the dollars are text, the mock tag
  muted. A lane that has done nothing yet reads `starting`, muted, with a blank cost. Not
  built: a header whose pieces the player chooses, and `starting` in the deck and compact
  layouts.
- **`/theme` and `/layout` as lists that are tried and can be saved** (P67,
  [#44](https://github.com/MFisher14/ctf-flightdeck/issues/44)). Alone, each opens a list; the
  console behind it is drawn in the row the cursor is on; Enter keeps it for the run, `esc`
  puts back what was there, and `s` saves it under `[console]` in the config. `/config` has
  both, with a choice to save them. The config is changed in one place (`config_edit.py`),
  which `pack install` and `plugin add` now use too.
- **`space` peeks at the selected lane** (P68,
  [#46](https://github.com/MFisher14/ctf-flightdeck/issues/46)). A panel between the lane list
  and the why line shows the lane's last six steps, one row each, and follows the selection;
  the command bar still talks to that lane. `space` or `esc` closes it. On a short terminal,
  and beside the `/` menu or a status line of several rows, it gives up its oldest rows first.
  In the mock, `,` freezes the clock.

Not verified yet: rCTF, ctfd-owl and chall-manager have met fakes only, never a real site; the
need-you count in the terminal's title and the bell, and copying with the mouse, were tested on
a pseudo-terminal and headless, not looked at in each terminal program or in tmux.

Known limits, each said where it applies:

- The rctf preset has met a stand-in only: it was written from rCTF's public source and tested
  against a fake that answers in that shape on 127.0.0.1, never a real rCTF.
- The http platform does not page a listing, download through a route per challenge, send a
  form-encoded body or a CSRF header, or start an instance; `flightdeck start` and the home
  screen's form do not offer it.
- `ctfd_owl` and `chall_manager` were built from the two plugins' public source, against fakes
  of that source. Neither has met a real site, a fork or an older release of its plugin.
- gdb runs only binaries of the lane image's own architecture (no emulator in the image), its
  tracing was run on arm64 only, and no run has yet measured what gdb and radare2 change in
  solves.
- No plugin has met a real platform: the plugin path was built against synthetic plugins and a
  stand-in on 127.0.0.1.
- A plugin is not sandboxed: it runs as the player, and `plugin add` says so before it asks.
- A plugin provides a platform and nothing else: no console commands, detectors, notification
  sinks or instances from one, no settings for it in the profile, no pinning of its files, and
  `flightdeck start` and the home screen's form do not offer a plugin's platform.
- Saving a theme or a layout edits the config line by line: a `[console]` written as dotted
  keys or as an inline table is refused and left as it was, with the line to write by hand.
  There is no key for the layout switch. The lists were driven by headless tests and once on a
  pseudo-terminal, not looked at in a terminal program.
- The five built-in palettes were checked for contrast, not judged by eye on many terminals.
- The gallery has no picture of the compact layout or of autopilot yet
  ([SCREENSHOTS.md](SCREENSHOTS.md)).

## Released: 0.4.0, M6 the solver pack and the first run (2026-11-13)

The author's own solvers and the pipeline he won events with come into flightdeck (D24; P29 to
P44 in [DECISIONS.md](DECISIONS.md); [SOLVERS.md](SOLVERS.md) says how to use the pack).

Built:

- **The solver pack, as an optional install.** `packs/solvers/` in this repository, never in the
  PyPI package: `flightdeck pack install` fetches it, builds its Python environment and its
  Docker image, and writes it into the config. Its whole no-model intake runs on every
  challenge as one engine: recursive unpack, flag search under layered encodings, some 800
  analysis engines routed by category and file type, decoders. Only a flag it can show the
  source of is handed over as a flag.
- **The pack as the lanes' toolkit** (`[l1] lane_tools`): every lane's brief says how to call
  the engines and read the category playbooks, and Docker lanes run in the pack's image.
- **From the pack's pipeline, into flightdeck's own** (each a proposal in DECISIONS, P33 to P44):
  - a flag CTFd rate-limited without checking it is waited out and sent again (P33);
  - the wrong-answer stop (P34); `/note`, a note for every lane (P35);
  - instances on demand: a challenge's own container started through a CTFd container plugin
    before a lane works it, renewed, and stopped on the solve (P36);
  - flag variants within a budget, off by default (P37);
  - a second and a third opinion on a timer under autopilot, off by default (P38);
  - rotating flags (P39);
  - the host governor: no new lane while the machine is over a limit (P40);
  - doctor names the pack's missing tools (P41);
  - the Game Master platform: pull, answers, the solved list (P42);
  - what the lanes of one challenge share, and series chaining (P43, P44).
- **From playing it** (the mock, then a real event from the README): `/config` in the console
  for the lane limit and auto approve (P45); `flightdeck start`, one command that sets an event
  up and plays it, and `flightdeck play FOLDER` with no `--event` (P46); an empty board
  you fill from the console with `/new`, or with `flightdeck add` (P47); pasted screenshots and
  `/attach` (P48); an event's VPN file kept and connected (P49); the opening menu
  and the welcome screen (P50).
- **The pack's own suite** runs in its folder (`packs/solvers/README.md`); the tests of the
  master repository's layout that the export leaves behind are listed and deselected, never
  counted as passed.

Known limits of what was ported, each said where it applies:

- The Game Master adapter and the `ctfd_docker` plugin shape were built against fakes and have
  not met a real service; `docker_per_team` is the plugin shape seen working at an event.
  (`ctfd_docker` matched no plugin and was dropped after this release: P57.)
- Instances are started in the queue's order, not highest value first, and a Docker lane whose
  instance came back at another address must be killed and queued again.
- Rotating-flag windows are counted on this machine's clock, not the platform's.
- The governor reads load, memory and disk; the pack's battery, thermal and cross-harness leases
  are not taken. Its Linux memory reading was tested through a fake host only.
- Flag variants never restore case from the challenge's own text (that would let challenge text
  choose what is sent).
- The pack's series engine (it computes a follow-up's answer from a sibling's saved certificate
  or favicon) stays an engine of the pack; flightdeck links the siblings and shares their files.

Not ported, because flightdeck has its own: the dispatcher, the board watcher, budgets and the
ledger, the leftovers reaper, writeups. Not portable: what drives the Claude Code and Codex
harnesses (launchers, permission profiles, worktrees, build lanes).

## Released: 0.3.0, M5 Autopilot (2026-11-12)

Engage autopilot and flightdeck runs the event end to end while you are away; take the controls
back at any time (D20; the details are P19 to P28 in [DECISIONS.md](DECISIONS.md), and the guide's
[Autopilot](GUIDE.md#autopilot) says how to use it). What was sketched, and is built:

- **Every stage as automatic as the event's rules allow, never looser.** Autopilot changes no
  policy: pull, L1, agents, submit and live instances go as far as the profile and your config set
  them. Under submit auto, flags a lane claims are submitted; everything else waits.
- **Scheduled.** Start at the event's start time, pull new waves on a timer, stop at the end. When
  the queue runs dry, unsolved challenges go round again on the next model up, within the budget.
- **Interventions by rule.** A stalled lane escalates one rung, a lane that gave up has its
  challenge queued again on the next model up, a looping lane is killed, a lane that ignores the
  hint is redirected to it, and a lane's own budget request is approved within the run budget. Code decides (D15); the
  light hint judge has its say in the Watch, as before.
- **Guardrails.** A run budget (dollars, tokens or both) is required to engage; at the budget no new
  lane starts and the lanes are paused. Docker only. No guessed flags, no last try spent, no refused request rerouted, nothing reached but a
  challenge's own instance.
- **Disengage.** Budget reached, the platform locking out or failing, the model API failing for every
  lane, a human check (a CAPTCHA), the event's end: autopilot holds the queue, says why in the
  console and logs it for the post-flight report. A challenge down to its last try does not
  disengage: that flag waits for you and the run goes on.
- **Headless, and a way to reach you.** Built ahead of the rest of M5: `play --headless` runs
  without the console by the same rules (an approval waits, nothing is approved) and stops on
  SIGTERM as quitting does; every run writes `status.json`; an opt-in webhook is told when a flag
  is accepted, a lane needs you, or the queue is held or autopilot disengages, and never gets a
  flag ([the guide](GUIDE.md#headless-runs-and-notifications)). Still open: a phone push, and
  approving from the phone (Later: phone control).

Left of M5:

- **A refusal inside a coding-agent CLI.** flightdeck reroutes no refused request, and switches
  Anthropic's server-side refusal fallback off for its own lanes; what a CLI does with a refusal
  on its own API is not flightdeck's to see.
- **A real event.** Autopilot is tested against the fake CTFd and the fake model, not yet flown.

## Released: 0.2.0, a model per small job (2026-11-12)

Each job was measured before it was built ([MODELS.md](MODELS.md)). The light model does small
jobs for a run, and the rules come first in every one:

- **judge**: the hint judge of 0.1.0. When the rules raise an "ignores the hint" alert, the light
  model may take it down.
- **route**: at a lane's start, a guess at the challenge's category where the board names none,
  and the specialist family it suits, which is the kind of specialist the challenge calls for (ten
  kinds, such as audio signals, image steganography, modern cryptography or web requests).
  Whether a challenge needs a live instance stays a rule.
- **recon**: a first look at the handout, added to a lane's opening brief as a fenced data
  section.
- **flagcheck**: a check on a flag before it is submitted without you. It can only hold an
  auto-submit, never cause one.

`[light] jobs` lists the jobs a run gives the light model, and a `[light.<job>]` table gives a
job an engine of its own. `flightdeck eval-local` scores each job the way a run uses it.

With it: model advice for a machine you describe and a guide by memory, and the fixes that a
rehearsal against a real CTFd, a security review and the first pricing issue asked for.

## Released: 0.1.0, the first public release (2026-11-11)

M0 to M4 built (below), docs and a quickstart, the MIT license, the secret scan
(`.githooks/secret_scan.py --all`) clean in CI, and a screenshot gallery
([SCREENSHOTS.md](SCREENSHOTS.md)).

**Easy to run: people won't use it if it's hard.** A new player gets from nothing to a running
console in a few minutes, without reading the architecture:

- One-line install or no install: `pip install ctf-flightdeck` (in a virtual environment),
  `pipx install ctf-flightdeck` or `uv tool install ctf-flightdeck`, or `uvx ctf-flightdeck mock` to
  try it; each tested from the built wheel in a clean environment; on PyPI since 2026-11-11.
  Python 3.12+; macOS and Linux (Windows through WSL).
- `flightdeck` with no setup offers the next step instead of an error; `flightdeck init` asks a few
  questions (provider, models, Docker or host) and writes the config; `flightdeck doctor` checks
  Python, Docker, the lane image, the key variable and the config, and says how to fix each problem.
- The mock and the practice set ship inside the package: `flightdeck mock` and `flightdeck practice`
  work right after installing, with no clone.
- A lane image that works out of the box, built only by a command the player runs.
- A quickstart at the top of the README, tested on a clean machine.

## Still open from M0 to M4

Planned in a milestone and not built:

- **ACP agents, against a real agent.** `--agent acp` runs the agent `[agents.acp]` names over the
  Agent Client Protocol, version 1 (P100). It has met a fake agent built from the protocol's
  schema only: no real agent or adapter has been run with it yet.
- **A real capture of the `claude` and `codex` streams.** The driver is tested against a fake CLI
  built from their docs, and so is a coding-agent lane's fenced network (below). Claude Code's
  stream was compared with a real run on 2026-11-14 (P86: 2.1.325, a prompt with no tools), and
  the differences fixed. On 2026-11-16 both played the whole practice set for real: claude in
  docker lanes behind the fenced network (12 of 14, $0.02 on Haiku), codex on the host with a
  saved ChatGPT login (13 of 14). Still open: codex in docker (it needs `CODEX_API_KEY`) and a
  raw capture of each stream's fields.

Built since (2026-11-12, issue #14): **the per-origin egress allowlist.** A Docker lane that may
reach its instance reaches only the hosts and ports its challenge's `urls` name, and a
coding-agent lane its CLI's API, through an internal Docker network and a proxy per host; it is
never on the bridge network (P9; the guide's [Docker or host](GUIDE.md#docker-or-host)). That is
the guardrail Autopilot needs: nothing reached but a challenge's own instance.

## Later (not scheduled)

- **ctfd-whale against a real CTFd.** Built against a fake of its source (P80); a run
  against a local CTFd with the plugin (Redis, a Docker socket and an frp or trp router
  beside it) is still to do before anyone relies on it.
- **Phone control.** Today: run flightdeck in tmux and attach over SSH (the console has a compact
  layout from 64 columns down). Option: serve the same console in a browser (textual-serve);
  touches D4 and must be locked down. Best: push a notification when a lane needs you, with approve and decline from the
  phone; needs its own sign-in and permission design.
- **Nerd Font look.** Opt-in powerline glyphs for truly slanted header segments and rounded chip ends
  in terminals that draw them; plain Unicode stays the default. Still later: a theme (P52)
  changes colours only, never a glyph.
- **Installs beyond PyPI.** Built, and first used by the release after 0.2.0: the release
  workflow builds a `.deb` for amd64 and arm64 that brings its own Python (Debian 12 has 3.11),
  installs each in a clean Debian 12 container and attaches them to the GitHub release, and it
  writes the Homebrew formula (`brew install mfisher14/tap/ctf-flightdeck`) to the tap
  (`packaging/`, and Releases in [CONTRIBUTING.md](../CONTRIBUTING.md)). The tap repository and
  its token are the maintainer's to create, and no `brew install` of the formula has been run
  yet. Left: a signed apt repository, so `apt upgrade` finds a new release. Homebrew's own
  repository and Debian's archives once the project is notable enough for them.
- **A host sandbox without Docker.** Strands Box (Apache-2.0: OS isolation with deny-by-default
  policies, an egress gateway and credentials injected outside the agent) could make `--host` lanes
  safe. Watch it: in November 2026 it was a preview for Apple silicon and Linux ARM64 only, with no
  Linux x86-64.

## Done: M0 to M4

The milestones behind 0.1.0, as they were planned and what each left open. What they built, as a
player sees it, is under 0.1.0 in [CHANGELOG.md](../CHANGELOG.md).

### M0: clickable mock

A Textual console with **fake, scripted data**: no models, no network, no real challenges.

- `uv run flightdeck mock` opens the console with the scenarios in `CONSOLE-SPEC.md`.
- Fake lanes tick over time (turns, tokens, dollars, actions) so it feels live.
- Every intervention key does something visible to the fake lane.
- Every alert type from the spec fires at least once.
- 43-challenge wave with `max_lanes` 16 is usable (scrolling, attention sort, queue).
- `flightdeck mock --screenshot DIR` saves SVG screenshots of key states for review.
- Tests: Textual pilot tests that keys change lane state and that attention sort orders alerts first.

**Exit (met):** layout and controls agreed on the mock and recorded in DECISIONS.md (D16).

### M1: thin working slice

Phase 1 agent model (D5a): flightdeck's own loop against an OpenAI-compatible endpoint (OpenRouter).

- Manual adapter: point at a folder of challenge dirs (handout files + `challenge.json`).
- Lean agent loop per lane: fresh context per challenge, small prefix (target under 6K tokens),
  few tools (shell, read file, http, python, submit-candidate), tool output truncated with overflow
  written to a file, per-call budget meter.
- Lanes run in Docker or on the host per `[lanes] runtime` (D9); `max_lanes` with a queue (D8).
- Console from M0 wired to real lanes: pause, hint, redirect, fork, kill, take over.
- Quick answers (deferred from M0): the needs-you card and the fleet's why line number their
  options (an approval: `1` approve, `0` decline; otherwise the alert's suggestions, numbered from
  `1`) and one key answers, no Enter (in the focus view only while the chat box is empty). A
  decline for candidate flags, live-box and budget requests, so "no" does not mean killing the
  lane.
- Per-lane tokens and turns, dollars with API pricing; per-lane caps that stop the lane.
- Append-only event log (JSONL) per run.
- OpenRouter: send a stable `session_id` per lane for sticky prompt caching; do not set
  `provider.order` (it disables sticky routing). Record cache hits reported by the API.
- Practice set: 10 to 20 synthetic or freely licensed challenges to run the slice on.

**Exit (met):** the practice set plays end to end through the console.

### M2: bring what you have

- External agent drivers: `claude` and `codex` CLIs as subprocess lanes; evaluate ACP for others.
- L1 plugin contract (`SolverResult`) and runner; script importer that wraps a folder of scripts with a
  generated manifest (no rewriting of user code); every engine run sandboxed.
- CTFd adapter (fixtures and a local CTFd only during development).
- Pre-flight: event profile + rules → stage policies (auto/confirm/manual/off); egress allowlist.
- Team mode: claims, teammate-solved stop, live-box courtesy.

Not done in M2: evaluating ACP, the per-origin egress allowlist and a real capture of the CLI
streams (under "Still open" above; the egress allowlist was built later, issue #14; ACP lanes
were built after 0.6.0, P100).

### M3: detectors and practice

- Real detectors for every alert in the spec (rules first; an optional cheap-model judge for
  "ignores the hint").
- Escalation with a compact state summary.
- Optional local model role (D15): evaluate Cactus and an OpenAI-compatible local server (Ollama,
  llama.cpp or MLX) on triage hints, the "ignores the hint" detector and lane summaries. Measure
  accuracy against rules-only before enabling by default.
- Cactus Needle (Apache-2.0/MIT; a 14-30 MB tool-calling model that runs on the CPU in
  milliseconds): an adapter in this repo plus an optional extra, `pip install
  ctf-flightdeck[cactus]` (pinned versions; their package fetches its engine and weights on first
  use; nothing of theirs bundled here); its anonymous telemetry switched off by default
  (NEEDLE_TELEMETRY=0, DO_NOT_TRACK=1, CACTUS_TELEMETRY=0). Jobs: which technique or L1 engine fits
  a challenge, whether a lane follows the hint, a typed or spoken command to an intervention.
  Needle does not run on MLX (a custom architecture) and does not need to at its size.
- MLX for lanes: `flightdeck init --provider mlx` for a local MLX server that speaks the OpenAI API
  with tool calling (`mlx_lm.server` passes tool calls for Qwen3.5 9B and Gemma 4 12B, not for
  gpt-oss 20B or Phi-4-mini: [MODELS.md](MODELS.md)), and a doctor check that the server answers.
- Practice mode: replay an archived board offline, scored against an answers file kept outside the
  handout.

How M3 came out: the light model (`[light]`, P15) runs the hint judge once one is set, on any of
four model engines (`openai`, `anthropic`, `cactus` for Cactus Needle, `decider`); with `rules`,
the default, there is no judge. In a first trial Needle did no better than keyword rules, so
nothing uses it unless you choose it. MLX lanes have run on a real MLX server, in the benchmark
behind the local models `init` suggests. Of practice mode, scoring is built; the replay is under
"Still open" above.

### M4: post-flight and build

- Post-flight timeline: where lanes stalled, where an intervention helped, cost per solve.
- Gap report: which challenges no L1 solver reached and why.
- Writeup drafts.
- Build mode: turn gaps into solvers; a solver is done only when a test shows a raw handout reaches it
  through the router.
