# Console spec

The console is the product: a fleet view to watch every lane and a focus view to work one (D16),
with one-key interventions in the fleet and a chat box with slash commands in both.
`flightdeck mock` shows it on scripted data; `play` and `practice` drive it with real lanes.

It draws in one of two layouts (P51). **deck** is the whole dashboard, and what the two sections
below describe. **simple**, the default, shows the same two views with less in them:
[Layouts](#layouts) says what it leaves out. Its colours come from a theme (P52,
[Themes](#themes)).

## Fleet view (the default screen)

```
 flightdeck ╱ event ╱ team ╱ docker ╱ lanes 16/16 · queue 27 ╱ ▲ 5 need you ╱ tok 4.1M ╱ $3.18 ╱ T+01:44
╭ board 51 · ✓ 2 · team ✓ 1 ───────╮ ╭ fleet 16/16 · sort attention ─────────────────────────────────╮
│ cat  name         pts solv   own │ │   !          lane chall        model state turns cost idle last │
│ web  Ticket Desk  100   41 ▶ L04 │ │ ▌ [flag]     L04  Ticket Desk  sonnet wait     7  .16  11m …    │
│ for  Static Hiss   50   88 ▶ L01 │ │   [offhint]  L01  Static Hiss  glm    run     21  .13  20s …    │
│ ...                              │ │   ...                                                          │
│                                  │ │ ▌L04 ▲ Flag found: Candidate mock{…} matches the flag format.   │
│                                  │ │    1  submit mock{…}   0  do not submit   enter open            │
╰──────────────────────────────────╯ ╰────────────────────────────────────────────────────────────────╯
 ● wren solved Night Shift · stopped L05                                    (status: latest outcome or event)
╭─ to L04 · Ticket Desk ─────────────────────────────────────────────────────────────────────────────╮
│ a message, or / for commands                                                                       │
╰────────────────────────────────────────────────────────────────────────────────────────────────────╯
 o open  ? help  p pause  h hint  r redirect  f fork  k kill  e escalate  t take over  a approve  d decline  A approve all  x dismiss  ...
```

`[flag]` stands for a chip: a solid colored label (no half-block caps, so no color shows past a
corner in any font). The header's segments are solid blocks with a `╱` between them on the page
(in the simple layout only what says "look here" is a block: [Layouts](#layouts)).

- **Header**: event, solo/team, docker/host, lanes used/limit, queue length, **how many lanes need
  you** ("all clear" when none), tokens, dollars (ending in `…` while a coding-agent CLI's turn is
  under way, whose cost comes when the turn ends; `+` when some spend has no price), event clock. While the queue is held (a model
  API failure every lane would hit, or a model API that keeps failing: two lanes in a row ended on
  a rate limit, a 5xx or an overload within a few minutes, with no reply in between), "queue held" stands where "all clear" would be (or beside
  "▲ N need you"), followed by why: never "all clear", since nothing starts until the player
  lifts the hold with `/unhold`.
- **Board**: every challenge with category, points, solve count, status (new ·, queued …, running ▶,
  solved by us ✓, solved by a teammate ✓ in cyan, blocked ✗, parked ‖) and owner (lane, me,
  teammate, or `L1·<engine>` when the flag that engine found solved it, whichever lane submitted
  it: every report credits the solve the same way). Enter on a row opens its lane; with no lane or
  several, a card to queue or claim it and to open any of its lanes (`1`-`9`). A parked challenge
  can be queued again, from its card or with `/queue`.
- **Fleet**: one compact row per lane, scrolling, **sorted by attention** (below). Finished lanes
  collapse into one row. 40+ rows stay usable. The list keeps its scroll position. The
  attention cell (`!`) shows what the lane most urgently needs from you (an alert or an approval);
  with nothing to answer, `sending` while a flag of the lane is on its way to the platform (its
  answer comes back on its own), else an informational alert, if any. The cost column has room
  for its markers: `$0.42+` when some spend had no price (what is known, as "at least"), and `…`
  while a coding-agent CLI's turn is under way (it reports the turn's cost when the turn ends),
  never a settled `$0.00` then.
- **Why line**: under the list, why the selected lane is flagged and the keys that answer it
  (for an alert about its course, also `x dismiss`).
- **Peek** (`space`, P68): a panel between the lane list and the why line with the last rows of
  the selected lane's log, so a hint or a redirect can be chosen without leaving the list.
  - Closed until `space` opens it; `space` or `esc` closes it (`esc` first leaves the command
    bar, then closes the peek, then clears the filter). It stays open or closed for the run:
    through a lane's view, `/layout` and a resize.
  - Its first row is a rule that names the lane and its challenge: the lane the keys and the
    command bar act on, so with the board in focus it is the challenge's only lane, and `no
    lane` when no lane or several work it, or when the filter hides the selected lane. It
    follows the selection.
  - Under the rule, six rows at most, oldest first, each cut at the edge and never wrapped.
    They are the calm transcript's rows (Focus view, below) with a run of tool calls opened:
    every call is a row (`⏺ the call → the first line of its output`, each with ` …+N lines`
    when it has more), and the model's words, a message or an intervention, a note, an alert
    (`▲ Loop alert · turn 3`) and an approval (`◆ asked you · turn 12: …`) are a row each. A
    lane with no step yet says so. The panel is the same height for every lane, so the list
    does not move with the cursor.
  - Its rows come from the lane list, which scrolls and keeps the selected lane in view. The
    list keeps three lane rows: on a terminal shorter than 23 lines (25 in the compact layout)
    the peek has fewer than six rows, and under 18 (20) it has none: `space` then opens
    nothing and the status line says how tall the terminal must be. An open peek that a
    resize leaves no room for is hidden until there is room again.
  - Those heights are with a status line of one row and the `/` menu closed. Both take their
    rows from the lanes panel, and the peek is sized for what the panel has left: it gives up
    one row for each of theirs, the oldest first (its last row is always the lane's last
    step), and is hidden when not one is left; only then does the list go under three lane
    rows, and it keeps the selected lane in view. The whole `/` menu is ten rows: the peek
    stays beside it from 28 lines (30 in the compact layout) and keeps all six rows from 33
    (35). On 24 lines the whole menu hides the peek, and it is back as the command is typed
    (the menu lists fewer) or the menu closes. On a terminal tall enough, `space` under a
    status line of several rows that has the room opens the peek hidden: what the status line
    says stays, and the peek shows once there is room.
  - The lanes panel's bottom border carries the hint: `space peek`, `space closes the peek`
    while it is open, `no room for the peek` while it is open and hidden (a short terminal,
    the `/` menu, a status line of several rows). No key line names
    it; `?` does.
  - The peek draws the same in every layout and changes nothing while it is closed.
    `flightdeck doctor` measures the lane list with the peek closed.
- **Command bar**: acts on the same lane the keys do (the board challenge's only lane when the board
  has focus; refused when the filter hides the selected lane). Its suggestions follow the selection.
  The title on its border says who what is typed goes to, and follows the selection (P64):
  `to L04 · Ticket Desk` for that lane; `no lane` when there is none (no lane yet, the board
  on a challenge with no lane or several, a filter that hides the selected lane); the lane a
  command names while it is typed (`/kill L07` reads `to L07 · …`, and `no lane L07` when
  there is no such lane); `the run` while a command that takes no lane is typed (`/note`,
  `/config`, `/queue`, `/approve all`). It is read from what is typed the way Enter reads
  it, so a name not yet whole, or a command Enter would refuse, leaves the title on the
  lane. A lane that would refuse what is typed is not named: `L04 has finished` for a lane
  that has ended (solved, killed, stopped, gave up), which still takes what reads it
  (`/open`, `/diff`, `/copy`) and, unless it solved its challenge, `/fork` with an approach;
  `L04 takes no more turns` for a lane that gave up and is open only for its flag's answer,
  for a message, `/hint`, `/redirect` and `/escalate`. With nothing typed the title is the
  one a message would get. The challenge's name is challenge text: made safe, never markup,
  cut with `…` at the bar's width. The empty bar reads `a message, or / for commands`.
  Enter on an empty bar opens the selected lane, and `?` in it opens help (Help, below); with
  anything in the bar, `?` is a question mark. A command that takes no argument refuses a stray
  word (`/approve 2` does not approve the selected lane; name it: `/approve L02`). `/approve all`
  names no lane: it is the fleet's `A` (Interventions, below), in either view.
- **Status line**: the latest intervention outcome or deck event (no toasts over the lanes); it
  clears after 12 seconds. One row; a line longer than the terminal is wide goes on in a second
  and a third, taken from the lane list while it shows, so its end is never cut. When the queue is held it says so and how to lift it: "queue held until
  you /unhold it: <why>". Lifting a hold that an API outage caused says how many of the challenges
  it parked were queued again.
- **An empty board**: while the board has no challenge, the page says so where the tables would
  be, and stays until there is one (a status line would expire). On a board the player fills:
  `No challenges yet. Type /new to hand one over (its text, files, a screenshot).`, and the
  command bar reads `/new to add a challenge · / for commands`. On a board that fills by itself:
  `Waiting for the board: challenges appear here when the event releases them.`, and the bar
  reads `/ for commands`. The bar's title is `no lane` on both. A board with
  challenges and no lane has `No lanes yet.` on the why line.
- **The `/` menu**: every command that matches what is typed, eight rows at a time; the arrow
  keys scroll to the rest. A lane's suggested answers come first; with no lane to act on,
  `/new`, `/help`, `/config` and `/queue` come first, then the rest in their usual order.
  The list is loose and what runs is not (P62):
  - A command is listed when what is typed starts its name, one of its aliases, or the second
    word of its name: `/over` lists `/takeover`, `/hold` `/unhold`, `/pilot` `/autopilot`,
    `/direct` `/redirect`. A name that starts with what is typed comes before a command found
    another way; a name or an alias typed whole comes first (`/q` lists `/quit`, then `/queue`).
  - The aliases are `/q` and `/exit` for `/quit`, `/settings` for `/config` and `/lanes` for
    `/back`; the menu and the help show them beside the name, as `/quit (/q, /exit)`. No other
    command has one: `/approve` is typed whole.
  - After a command's name and a space, the menu lists the words that command takes that
    start with what follows: every lane with its challenge and state for `/open` (found by
    the lane's id, `l1` for L01, or by a word of its challenge's name), the parked and new
    challenges for `/queue` (by id or by a word of the name), the themes for `/theme` (built
    in, then yours, the one in use marked), `simple` and `deck` for `/layout` (the one in use
    marked), the sort modes for `/sort`, `on` and `off` for `/autopilot`. A word typed whole is
    not listed. While the menu is open it follows the deck: a lane that changes state, a
    challenge that is parked. Other commands list nothing after their name.
  - When what is typed names no command and nothing is listed, the menu stays open with one
    muted row: `No commands match "/x"`.
  - The menu only fills the bar. Tab takes the highlighted row, or the first when none is.
    Enter takes the highlighted row while the name is not yet a command, and once the arrow
    keys moved to a row; anything else it sends as typed. The first row is highlighted only
    while the name is being typed: the rows after a name are not, since Enter there sends
    what is typed (`/open` and Enter still opens the selected lane).
  - What is sent runs only as a whole name or a whole alias with words the command knows:
    `/over` sent as typed is `Unknown command /over`, and `/approve 2` is refused, never read
    as L02.

## Focus view (enter on a lane)

```
 flightdeck ╱ ...header...
 4 other lanes need you: [L04 flag] [L07 loop] [L02 effort] [L03 wrongway]   ctrl+n next
╭ L01 · Static Hiss  for 50 · glm · run · turn 24 ─────────╮ ╭ files changed 3 ──────────────────╮
│ ⏺ python3 diff_channels.py --window 512 left.wav right…  │ │ ocr.py  +6 −0  new · turn 24      │
│   ⎿  no window rises above the noise floor               │ │ diff_channels.py  +9 −1  turn 21  │
│ › you  try sstv please                                   │ │ --- a/diff_channels.py            │
│ ⏺ python3 -m sstv -d static_hiss.wav -o decoded.png      │ │ +++ b/diff_channels.py            │
│ ╭ needs you now ──────────────────────────────────────╮  │ │ +parser.add_argument("--window")  │
│ │ ◆ waiting for you: submit mock{…}   /approve         │  │ │ ...                               │
│ ╰──────────────────────────────────────────────────────╯  │ │                                   │
╰ plan  Decode the audio as slow-scan TV ──────────────────╯ ╰───────────────────────────────────╯
╭─ to L01 · Static Hiss ─────────────────────────────────────────────────────────────────────────────╮
│ a message, or / for commands                                                                       │
╰────────────────────────────────────────────────────────────────────────────────────────────────────╯
 esc fleet  enter send  / commands  1-9 0 answer  ctrl+n next lane needing you  tab files  pgup pgdn scroll
```

- **Transcript**: the lane's steps (⏺ command, ⎿ output), your messages (› you), flightdeck notes,
  alerts and approvals, in order. It follows the lane; scroll back (`pgup`) and it stays where you
  are reading until you scroll to the end again. What a lane did shows a credential's name but
  not its value, as its transcript file keeps it. A key flightdeck holds shows as `[NAME]`, and
  the lane's model had it so too; anything else shaped like a credential shows as `[redacted]`,
  and the lane's model had that text as it was. It wraps to the pane, and wraps again when the
  terminal's width changes. The newest 300 entries are drawn; with more, the first row says how
  many earlier ones there are, and `pgup` at the top shows 300 more. No more than 600 are drawn
  at once, so a long lane redraws as fast as a short one: read back while the lane goes on, or
  far back, and the last row says how many later entries there are, and `pgdn` there shows 300
  more.
- **Details** (`ctrl+o`, or `/details`): the view's one switch, for the transcript and the
  needs-you card together. On, the transcript is as above: every line the lane's log keeps.
  Off, it is calm: one row for each entry, cut at the edge of the pane with `…` and never
  wrapped. The card with details off is under Needs you now, below.

  | Entry | Drawn as, with details off |
  |---|---|
  | one tool call | `⏺ $ unzip -l rev.zip → Archive:  rev.zip`: the first line of the call and of its output, each followed by ` …+6 lines` when it has more |
  | a run of tool calls | two rows: `⏺ 12 tool calls`, then `  ⎿ ` and the last call as above, which is what the lane is doing now |
  | the model's words | `⏺ ` and the words, wrapped: the one entry that is never cut |
  | a note from flightdeck (L1 too) | `· L1 intake: unsure (handout: 3 file(s) … …+14 lines`: its first line |
  | an alert | `▲ Loop alert · turn 3`; its reason is on the needs-you card |
  | an approval | `◆ asked you · turn 12: raise the cap by 50% (now 424k of 400k tokens)` |
  | your message | `› you  text` |
  | an intervention, yours or autopilot's | its line, then ` …+2 lines` in place of its output |

  A tool call is a step that is not the model's own words; a turn of three calls counts three.
  Anything else ends a run, and a run of one call is one row. A failed call shows as its output
  starts: with its status, in flightdeck's own loop. The status line says which way the switch
  went (`details on: every line and every alert (ctrl+o hides them)`, `details off (ctrl+o
  shows every line)`). The switch starts on in the `deck` and compact layouts and off in
  `simple` (Layouts, below), follows the layout on a `/layout`, and stays as you set it once you
  have set it by hand in that view; reading back, the entry you were on stays in view when it
  turns.
- **Needs you now**: with details on, the full card. First the approval the lane waits for,
  with `1 /approve` and `0 /decline` (and `then:` for each approval after it); then the lane's
  open alerts, the most urgent first, with their reasons and the suggested answers as commands
  (`/dismiss` under the alert it would take down); then the messages it has not read yet.
  It takes at most half the pane, so the transcript keeps its rows on a small terminal. A card
  taller than that scrolls in its half (the mouse wheel), from its first rows: the approval and
  its two answers are the ones in view.

  With details off the card is calm: three rows where the card is wide enough for them, and
  never a list of commands. Not in the compact layout, whose card keeps its own form.

  | Row | Drawn as, with details off |
  |---|---|
  | 1, the question | the approval the lane waits for: `◆ waiting for you: raise the cap by 50% (now 424k of 400k tokens)`. With none, its most urgent alert that wants an answer, and the reason: `▲ Loop: The same command ran 6 times in the last 6 turns: …` |
  | 2, its answers | `  1 more budget   0 stop the lane` for an approval (a flag: `  1 submit it   0 do not submit`). For an alert, `  1 hint "You are repeating python3 solve.py: it gives the…"   2 kill and re-queue fresh   /dismiss not a problem`: the numbers a digit answers, each with its label; an answer that sends its text at once (a hint, a new plan, a fork's approach) quotes the first 48 characters of it; three answers, then `+2 more`; `/dismiss not a problem` for an alert about the lane's course |
  | 3, only when something else is open | `  also: looping · past its effort budget · stalled   ctrl+o shows all`: each other alert in a word or two (`looping`, `past its effort budget`, `ignores the hint`, `wrong direction`, `stalled`, `near its cap`, `a flag to check`, `teammate`), then `1 more approval after this one` and `2 messages it has not read yet`. The alert an approval is about (its budget, its flag) is not named beside it |

  A narrow card (beside the files pane on an 80-column terminal its rows have 38 cells) takes
  more rows before the edge cuts what a digit answers:

  - An approval's question folds onto further rows, four at most, so the flag that `1` submits
    is whole on the card. An alert's reason is cut at the edge with `…`: the full card has it.
  - The quotes of row 2 shorten together until the row fits, down to 12 characters, and then
    there are none. Answers that still do not fit take further rows, each starting with its
    number, and `/dismiss not a problem` a row of its own if it must.
  - Row 3 keeps the names that fit and counts the rest: `  also: looping · +2 more   ctrl+o
    shows all`, then `  also: +3 more   ctrl+o shows all`. Where even that does not fit,
    `ctrl+o shows all` is on the next row.

  With no question (no approval, no alert that wants an answer) the card is the message
  the lane has not read yet (`› sent, not read yet: TEXT`), or how many (`› 2 messages sent,
  not read yet   ctrl+o shows all`, the key on the next row in a narrow card), under the row of
  an alert that needs no answer. The
  border and its title are as on the full card: the colour of the most urgent alert that wants
  an answer, else the approval's. A suggestion with no key (advice only) is on the full card.

  On both cards what the lane wrote (an approval's text, an alert's reason, a quoted answer, a
  message) shows a credential's name but not its value, as the transcript does. The flag an
  approval asks about is shown whole.
- **Files changed**: the files the lane wrote or edited, with the diff of the selected one.
- **Chat box**: plain text is a message the lane reads on its next turn; `/` runs a command. Typing
  reaches it from any pane. An unsent message stays with its lane when you switch lanes.
  Its border carries the same title as the fleet's command bar, in every layout: `to L01 ·
  Static Hiss` for the open lane, the lane a command names while it is typed, `the run` while
  a command that takes no lane is typed, and `L01 has finished` or `L01 takes no more turns`
  when the lane would refuse what is typed. Empty, it reads `a message, or / for commands`.
  `?` on the empty box opens help for this lane (Help, below), from any pane and in every
  layout; with text in the box it is a question mark. A message cannot start with a lone `?`
  typed on the empty box: type a space first (what is sent has no blanks at its ends), or paste
  it.
- **Selecting and copying**: text selects with the mouse. Drag over the transcript, the calm
  card, the header or the status line, and what you dragged over is copied when you let go; the
  status line says `copied 212 characters`. A double-click takes the whole entry, also what the
  edge cuts with `…`; a triple-click the whole transcript that is drawn. A row of the detailed
  transcript that wraps over three rows is copied as the one line it is. `ctrl+c` copies the
  selection again, in the lane list too; with nothing selected it is Textual's hint of the key
  that quits, as before.
  `esc` takes a selection down and the view stays (the next `esc` goes back), and so does typing.
  The chat box keeps the focus through a drag. The highlight is the theme's colour for a selected
  row (`selected_focus`), and the text on it keeps its own colour.

  A copy goes two ways, both every time: to the terminal's clipboard (OSC 52), and to the
  operating system's by its tool, which is `pbcopy` on macOS and on Linux `wl-copy`, else
  `xclip -selection clipboard`, else `xsel --clipboard --input`. Over SSH (`SSH_CONNECTION` or
  `SSH_TTY` is set) no tool is run: it would fill the clipboard of the machine flightdeck runs
  on, and OSC 52 carries the text to yours. A terminal never says whether it took OSC 52, so
  when no tool took the text the status line warns instead of claiming a copy: `sent to the
  terminal's clipboard (OSC 52). If paste is empty, this terminal does not take it: install
  xclip or wl-copy, or hold fn (Terminal.app), Option (iTerm2) or Shift while you drag`.
  Installing a tool is named only on a Linux machine you sit at, and a tool that failed is
  named first (`xclip failed (exit 1); sent to …`).

  `/copy` copies from the lane with no mouse, in either view. Alone (or `/copy output`): the
  output of the lane's last tool call that printed something, as its transcript keeps it (of a
  call of flightdeck's own loop, up to 40 lines), with real newlines. `/copy command`: that
  call's command, its lines real again and without the `$ ` of a shell call, so it pastes into a
  shell. `/copy flag`: the flag that waits for your approval, else the newest flag the run knows
  for the lane's challenge, which is the one a lane proposed, you submitted or an L1 engine
  reported last (also when the run had met it before); with none, `L01 has no flag yet`.
  `/copy all`: every line of the transcript in detail. The status line says what was copied
  (`copied L01's last output: 38 lines`), and names the flag (`copied L01's flag: flag{…}`): the
  newest may be one you declined. What is copied is what the console would show: a credential's name without its
  value, and control characters made visible.

  Not selectable: the full needs-you card (a panel), the diff, the lane list and the board
  (tables). `/copy` covers what a lane did; for the rest, the terminal's own selection: hold fn
  (Terminal.app), Option (iTerm2) or Shift while you drag.
- **A lane that restarts takes the view with it.** `/attach` typed here, and a kill that
  re-queues made here (`/kill`, the Kill prompt's re-queue, the numbered "kill and re-queue fresh"
  answer), end the lane and start a fresh one on its challenge: the view goes to the fresh lane,
  and an unsent message goes with it. While the fresh lane has not started (the queue is held, no
  lane is free) the view stays, and moves when it starts. It never goes to a lane that has itself
  ended (one that started during the copy and was ended with the files): it goes to the lane that
  runs. A player who went back to the fleet or opened another lane meanwhile is not moved, and
  nothing follows once the challenge is parked or solved. `/kill park` starts no lane, so the view
  stays. The same when the lane in view had already ended and `/attach` starts a lane on its
  challenge.
- **ctrl+n** goes through the lanes that need you in attention order, then round to the first.

## Layouts

`[console] layout` in the config is `simple` (the default) or `deck`; `/layout simple` and
`/layout deck` switch for the rest of the run, keeping the selection, the filter, the sort and
anything typed, and `/layout` alone opens the list that tries and saves one (Choosing a look,
below). `deck` is the console as the two sections above describe it. At 64
columns or fewer the compact layout (below) is drawn, whichever is chosen. `mock --screenshot`
takes its pictures in `deck`, and saves the simple layout as `simple-open`, `simple-alert` and
`simple-focus`.

`simple` shows what needs the player and little else:

```
 flightdeck ╱ event ╱ team ╱ queue 33 ╱ ▲ 3 need you ╱ $2.76
╭ lanes 16/16 · 33 waiting · ✓ 1 solved ─────────────────────────────────────────────────────────────╮
│   !          lane chall         state    cost  last action                                         │
│   [flag]     L04  Ticket Desk   wait     $.16  candidate flag mock{…}                              │
│ ▌ [offhint]  L01  Static Hiss   run      $.10  python3 diff_channels.py --window 512 left.wav …    │
│              L09  Night Shift   starting                                                           │
│   ...                                                                                              │
│ ▌L01 ▲ Ignores the hint: The description hints at slow-scan TV …                                   │
│    1  redirect with the hinted technique   2  hint   x  dismiss   enter open                       │
╰────────────────────────────────────────────────────────────────────────────────────────────────────╯
 ● Wave 2: 43 challenges · 10 lanes started · 33 queued
╭─ to L01 · Static Hiss ─────────────────────────────────────────────────────────────────────────────╮
│ a message, or / for commands                                                                       │
╰────────────────────────────────────────────────────────────────────────────────────────────────────╯
 1-9 answer  x dismiss  enter open  / commands  ? help  q quit
```

- **Header.** Only what is not the usual: flightdeck, the event's name, the mock tag, `team` in
  team mode, `host` when lanes run on this machine, `queue N` when the queue is not empty,
  `AUTOPILOT` while it is engaged, `▲ N need you` when any do, `queue held` and why, and the
  run's dollars. No solo, docker, lane count, "all clear", tokens or clock. Only "look here" is
  a block: flightdeck, `host`, `AUTOPILOT`, `▲ N need you` and `queue held`. The event's name,
  the queue and the dollars are text on the page, `team` is in the `info` colour on the page,
  and the mock tag is muted text; a `╱` still stands between every two pieces. Each colour a
  quiet piece takes on the page is one of the pairs a theme is checked for. On a narrow terminal
  the event's name goes first, then the mock tag, the queue, `host` and `team`; flightdeck,
  `AUTOPILOT`, the need-you count, a held queue and the dollars never drop.
- **Lane list.** One panel, no board. Columns: the attention cell (`!`), lane, challenge, state,
  cost, last action. Under 86 columns the challenge's name narrows (to 8 cells at least); under
  74 the last action is left out and the name is whole again; the cost is never left out, and
  `flightdeck doctor` says when the last action is. A running lane that has done nothing yet (no
  turn, no step of its own, nothing spent, no coding-agent CLI turn whose cost is on its way)
  reads `starting` in muted text in the state column, and its cost is blank; the filter finds it
  by `starting` and not by `run`, as its row says (in `deck` and the compact layout, whose rows
  say `run`, so does the filter). The model, turns and idle time are in the
  focus view's title. The panel's
  title is `lanes n/m`, then ` · N waiting` when the queue is not empty, ` · ✓ N solved` when
  any are, ` · sort X` only when the sort is not by attention, and the filter as in `deck`.
- **Why line.** Why the selected lane is flagged and its answers, as in `deck`, for a lane with
  an alert or an approval waiting; blank for any other lane (its row says what it is doing).
- **Peek.** `space`, as in `deck` (Fleet view, above): under the list, over the why line.
- **Key line.** Only the keys that apply to the selected lane now. Every other key still acts,
  and `?` lists them all:

  | The selected lane | Key line |
  |---|---|
  | none, on a board the player fills | `/new add a challenge  ? help  q quit` |
  | none, on a platform's board | `? help  q quit` |
  | needs nothing, or has finished | `enter open  / commands  ? help  q quit` |
  | waits for an approval | `a approve  d decline  enter open  / commands  ? help  q quit` |
  | has an alert with numbered answers | `1-9 answer`, and `x dismiss` when the alert is about its course, then `enter open  / commands  ? help  q quit` |

- **Focus view.** A part shows only when it has something in it: the files pane once the lane
  has changed a file, the strip of other lanes while one of them needs the player, the
  needs-you card while this lane does. The title is the same as in `deck` (the lane, its
  challenge, model, state, turns, tokens, cost and idle time). The transcript and the
  needs-you card are calm: details start off (Focus view, above), and `ctrl+o` shows every line
  and the full card. Key line: `esc lanes  / commands  ? help  ctrl+o details`, with `1-9
  answer` first while the lane has numbered answers (59 columns with the answers, so it is
  whole at every width the layout has; `?` works on the empty chat box). The chat box names
  the lane a message goes to on its border, as in every layout (Chat box, above), and a lane
  that has ended says `esc goes back to the lanes`.

  A lane that waits for more budget with its Loop, Effort and Stall alerts open, after an L1
  intake note of 15 lines and 15 tool calls, most of several lines: 13 rows of transcript and a
  card of three. With details on (`ctrl+o`) the same lane is 40 lines, the long ones wrapped,
  and a card of 15 rows or more.

  ```
   flightdeck ╱ practice ╱ ▲ 1 need you ╱ $0.00
  ╭─ L01 · Baby RSA  cry 0 · glm · wait · turn 15 · 424k tok · $0.00 · idle 0s ──────────────────────╮
  │ · L1 intake: unsure (handout: 3 file(s), 41 unpacked member(s) (17 ELF, 9 text, 6 zip, 5 png,…   │
  │ ⏺ $ unzip -o handout.zip -d work \ …+1 line → Archive:  handout.zip …+2 lines                    │
  │ ▲ Effort vs value alert · turn 1                                                                 │
  │ ⏺ 9 tool calls                                                                                   │
  │   ⎿ $ cd /work && python3 - <<'PY' …+5 lines → exit 1 …+3 lines                                  │
  │ ▲ Stall alert · turn 10                                                                          │
  │ ⏺ $ cd /work && python3 - <<'PY' …+5 lines → exit 1 …+3 lines                                    │
  │ ▲ Loop alert · turn 11                                                                           │
  │ ⏺ $ cd /work && python3 - <<'PY' …+5 lines → exit 1 …+3 lines                                    │
  │ ▲ Budget alert · turn 12                                                                         │
  │ ⏺ 3 tool calls                                                                                   │
  │   ⎿ $ cd /work && python3 - <<'PY' …+5 lines → exit 1 …+3 lines                                  │
  │ ◆ asked you · turn 15: raise the cap by 50% (now 424k of 400k tokens)                            │
  │ ╭─ needs you now ──────────────────────────────────────────────────────────────────────────────╮ │
  │ │ ◆ waiting for you: raise the cap by 50% (now 424k of 400k tokens)                            │ │
  │ │   1 more budget   0 stop the lane                                                            │ │
  │ │   also: looping · past its effort budget · stalled   ctrl+o shows all                        │ │
  │ ╰──────────────────────────────────────────────────────────────────────────────────────────────╯ │
  ╰───────────────────────────────────────────────────────────────────────────────────────── plan - ─╯
  ╭─ to L01 · Baby RSA ──────────────────────────────────────────────────────────────────────────────╮
   1-9 answer  esc lanes  / commands  ? help  ctrl+o details
  ```
- **The first lane.** On a board the player fills, the first lane of the run that a `/new`
  starts opens in the focus view, once it exists: only while the player is still in the lane
  list with nothing typed in the command bar, and only while it is the one lane. Later lanes
  start in the list. Never in `deck`, and never on a platform's board.
- **The welcome screen** names the lanes as the middle of the screen, and no board.

`flightdeck doctor` measures the terminal in the layout the config names: the simple layout has
no board to leave out, and nothing is left out of it from the first width that is not compact
and fits its header and its longest key line.

## Themes

`[console] theme` in the config names the palette the console draws every colour from (P52):
`flightdeck` (the default), `light`, `nord`, `gruvbox`, `dracula`, or the player's own
`themes/NAME.toml` beside the config ([GUIDE.md](GUIDE.md#themes) has the file's keys).
`/theme NAME` repaints what is on screen, a transcript's lines included, for the rest of the
run, and `/theme` alone opens the list that tries and saves one (Choosing a look, below).
`mock --screenshot` takes its pictures in the default theme, and saves the fleet in the light
one as `theme-light`.

A theme is colours only. The chips stay solid labels, the header's segments solid blocks (in
the simple layout, those that say "look here"), the
marks and glyphs the same plain Unicode, and what never drops from the header never drops in
any theme. A palette has 17 colours by role (the page, text, a muted text, an accent, the
states `ok`, `error`, `warn`, `info` and `pending`, the ink on their chips, and the surfaces),
whether it is dark, and the style of the diff view. Because the roles carry meaning (`error` is
"needs you", `warn` is a held queue), a theme whose pairs the player could not read is refused:
19 pairs, each at a WCAG contrast of 3.0 or more. A theme that cannot be used is an error when
the config loads and a warning from `/theme`; the default is never drawn in its place.

## Choosing a look

`/theme` and `/layout` alone open a list (P67): the built-in themes and the player's own, or the
two layouts, each with a few words (`built in`, `yours`, what the layout shows) and `in use` on
the one the console is drawn in, where the cursor starts.

- **The list is tried, not read.** The console behind it is drawn in the row the cursor is on,
  at once: both views, a transcript's lines, the dialog's own rows and keys. The dialog is 54
  columns at the right edge and the console behind it is not dimmed, so the header, the lane
  list and the key line show what the choice looks like.
- **enter** keeps the row for this run and writes nothing. **s** keeps it and saves it:
  `theme = "NAME"` or `layout = "NAME"` under `[console]` in the config. **esc** closes the
  list and puts back what was there, to the last cell. A click on a row is Enter on it.
- **What is said.** After Enter, `theme nord for this run. To keep it: /theme, then s`; after
  `s`, `theme nord, saved in your config file: PATH`; when the save could not be done, a
  warning, `theme nord for this run; it was not saved: REASON`. The run keeps the look either
  way. `/theme NAME` and `/layout NAME` answer as Enter does.
- **A theme file that cannot be used** is listed with `cannot be used:` and its reason under
  its name (the file by its name; the folder is said once, under the list), and takes neither
  the cursor nor a click. The list reads every theme file in the folder when it opens, so it
  shows a file as it is now.
- **With no config file** (the mock before `flightdeck init`) the list has no `s` row and says
  `This console has no config file, so a theme lasts for this run.`; `s` there says so in the
  list and does nothing else.
- **On a short terminal** the title and the keys stay on screen and the list between them
  scrolls to the cursor; under 24 rows the dialog gives up its blank rows and the note under
  the list.

`/config` has the same two in its dialog, under the run's settings, with a third list: `for
this run`, or `for this run, and saved in your config file`. Its theme list is the names only
(no file is opened for it), so a theme that cannot be used is refused when the dialog is
applied, with its reason, and then nothing in the dialog was changed. Saved from there, the
layout and the theme are both written, as the dialog shows them.

**The save** (`config_edit.save_console`) changes one line of the file, or adds one: over the
line that sets the key, else under a commented example of it, else at the end of the
`[console]` table, else in a `[console]` table added at the end of the file. Every other line
stays, comments and line endings included, and a config that is a link stays a link. Before
the write the new text must parse to the old text's settings with that key changed and
nothing else; after it the `[console]` table is loaded as a console loads it. A file that
fails either check, or cannot be written, is left as it was, and the reason is said.

## Attention order

1. Lanes that need the player: an approval waiting, or an alert that wants an answer. Most urgent
   first: a flag, then any other approval, then budget, loop, effort, ignores the hint, wrong way,
   stall; oldest first within the same urgency. A lane's approvals queue, a flag first, and none
   is dropped: the needs-you card lists those still to come (`then:`).
2. Lanes with only an informational alert (flightdeck already acted, e.g. a teammate holds the box).
3. Running lanes by idle time, in whole minutes, so rows do not reshuffle every tick.
4. Paused and taken-over lanes. 5. Finished lanes (collapsed).

## Alerts (from the author's real cues)

| Alert | Fires when (in the mock: scripted; in a run: a detector) | Suggested action |
|---|---|---|
| Effort vs value | Turns or tokens are high for a low-point challenge, especially one with many solves. "Complex work on a 50-pointer." | Hint "it's simpler than this", or kill and re-queue fresh |
| Ignores the hint | The description hints at something (e.g. SSTV, slow scan, radio) but the lane does something else (e.g. comparing stereo channels of the wav). | Redirect with the hinted technique |
| Wrong direction (web) | A web lane fuzzes or brute-forces when source is given, or keeps attacking one endpoint with no new signal. | Redirect, or fork with a different approach |
| Loop | The same command or near-same action repeats. | Hint or kill |
| Stall | No new artifact or hypothesis for N turns. | Escalate to a stronger model with a summary |
| Teammate solved / box in use | Team mode: the challenge is solved, or a teammate holds the live instance. | Solved: stop the lane (automatic). Box in use: keep the lane off the box until it is free (automatic) |
| Budget | Lane near its token or dollar cap (80%), or at it (100%: it waits). | Approve more (also at 80%), escalate (at 80%), or kill |
| Flag found | A candidate flag matches the format. | Approve submit (if submit = confirm) |

A lane whose live box a teammate holds is not stopped: it keeps working on the handout, off the
box, and then asks for live-box access (a `box` approval). At a budget's 80% warning `a` approves
more, as it does at 100%; escalate is offered at 80% only.

## Interventions

| Key (fleet) | Command (both views) | Action |
|---|---|---|
| `p` | `/pause` | Pause or resume the lane |
| `h` | `/hint <text>`, or plain text | A message the lane reads on its next turn |
| `r` | `/redirect <plan>` | Replace the lane's plan with a new direction |
| `f` | `/fork [approach]` | Start a sibling lane on the same challenge with a different approach or model |
| `k` | `/kill [park]` | Kill the lane; the challenge goes back to the queue (fresh) or is parked. A re-queue made in the lane's focus view takes the view to the fresh lane |
| `e` | `/escalate` | Hand a compact state summary to a stronger model |
| `t` | `/takeover` | Drop to a shell in the lane's workspace (its container in Docker); exit the shell to hand back. The lane hears what you changed. Taking over closes the lane's sessions (a gdb or a connection it kept running: P82), and the hand-back tells it which. Other lanes keep running meanwhile. |
| `a`, `1` | `/approve` | Approve the pending action (submit, more budget, live-box access); on a board that cannot check flags, "accepted" |
| `A` | `/approve all` | Approve every flag that waits for a plain yes, in one action (Approving several flags at once, below) |
| `x` | `/dismiss` | Dismiss the lane's most urgent alert about its course (effort, off-hint, wrong way, loop, stall) without intervening: you judge it wrong. It goes, and stays quiet as an answered alert does (Dismissing an alert, below) |
| `d`, `0` | `/decline` | Say no: the flag is not submitted (or, after a hand submit, was rejected), or the live box stays off, and the lane carries on; refusing more budget stops the lane |
| `1`-`9` | | Quick answers: the numbers in the why line and the needs-you card; one key, no enter (focus view: only while the chat box is empty) |
| `c` | `/claim [challenge]` | Team mode: claim or release a challenge |
| enter, `o` | `/open <lane>` | Open the lane in the focus view (`esc` or `/back`, also typed `/lanes`, returns) |
| `ctrl+o` (focus) | `/details` | In a lane's focus view: details on or off. On: every line of the transcript, and the full needs-you card; off: one row for each entry, a run of tool calls on two, and the card in three rows (more only where it is too narrow for them). Typed in the fleet, `/details` says it is that view's |
|  | `/diff [file]` | Show the files the lane changed |
| `ctrl+c` | `/copy [output\|command\|flag\|all]` | `ctrl+c` copies the text selected with the mouse (a drag copies it as you let go; `esc` takes the selection down). `/copy` copies from the lane with no mouse: its last output (alone), that call's command, its flag, or all of its transcript (Focus view, Selecting and copying) |
|  | `/config [lanes N\|unlimited]`, `/config submit auto\|confirm`, `/config file` (also `/settings`) | Alone: a dialog with this run's settings (lanes at once, what happens to a flag) and the console's layout and theme, which it can save (Choosing a look); Enter in the lanes field or `ctrl+s` applies, esc cancels. `lanes`: how many lanes run at once, from now on (raising it starts queued lanes; lowering it stops none). `submit auto` turns auto approve on: a flag a lane submits goes at once, with auto submit's exceptions; `submit confirm` turns it off. Flags already waiting stay yours. Neither goes past the event's rules. `file` names your config file. Each change lasts for this run; only the layout and the theme can be saved, and only when the dialog is told to. |
|  | `/layout [simple\|deck]` | The console's layout for the rest of this run: `simple` (one list of lanes, what needs you, the keys that apply now) or `deck` (the board and every column). Alone: the list that tries both and can save one (Choosing a look). The status line says how to keep it (`/layout, then s`), and that the compact layout shows when the terminal is narrow. Any other word is refused: `/layout takes simple or deck`. |
|  | `/theme [name]` | Alone: the list that tries the themes and can save one (Choosing a look). With a name: the console's colours for the rest of this run, and the status line says how to keep it (`/theme, then s`). A name that is no theme, or a theme file that cannot be used, is a warning with the reason, and the theme in use stays. |
|  | `/note <text>` | A note for every lane (an organizer's ruling, a replaced handout): each running lane reads it on its next turn, and every lane started later in this run reads it at its start. At most 12 stand at once. |
|  | `/new [name]` | Hand a challenge over, on a board you fill yourself: a form with the challenge's name and a box for its description and its instance's address; its files and screenshots are attached by a drop on the terminal, `ctrl+o` or `ctrl+v`, and listed on the form (a path written in the description is only text; the address is `https://...` or `nc host port`, on a line of its own); category and points are optional. A line under the box says what is attached. A dropped file is copied into the run's folder as it lands, so one that is gone before `ctrl+s` is still added. `ctrl+v` pastes a screenshot from the clipboard (so does an empty paste, which is what a terminal's own paste key sends in Windows Terminal and Alacritty), and the lanes' model reads an image's text into the description. `ctrl+s` adds it and a lane starts on it; `esc` cancels. Refused on a board that comes from a platform, and in the mock. |
|  | `/attach [challenge] <files>` | Add files to a challenge on a board you fill yourself: drag them onto the command bar, or give no file and choose them in the file window. A drop that lands is said with each file's name and size, and the `/attach` names the run's own copy of each file (`dropped/` in the run's folder), made as it landed. A paste that reads as a dropped file that is not on this machine is said with the likely reason, and is pasted as text. Its lanes start afresh with them, and the status line names the fresh ones (`attached extra.txt to doll; L01 restarted as L02`; `L01 ended, a fresh lane starts when one is free` while none has started; `L01, L02 restarted as L03, and 1 more starts when a lane is free` when only some have; `no fresh lane started: …` and the reason when none can). An ended lane's result reads `killed: to restart with extra.txt; re-queued fresh`. Typed in the lane's focus view, the view goes to the fresh lane. Without a challenge: the open lane's. |
|  | `/queue <challenge>` | Queue a parked or new challenge (also from its board card) |
|  | `/autopilot [on\|off]` | `on` engages autopilot, `off` takes the controls back, alone it says which it is. `on` is refused, with the reason, without a run budget, off the Docker runtime, while the queue is held, and once the budget is spent |
|  | `/unhold` | Lift the hold on the queue once its cause is fixed: the challenges an API outage parked are queued again, and queued lanes start in the free slots (a key or model id changed in your config needs a new run). Refused when the queue is not held; while it is, the `/` menu offers it first, whatever lane is selected |
| `/`, `s`, `tab` | `/filter`, `/sort` | Command bar, change sort, move focus between panes |
| `?` | `/help` | Help for where you are: the keys for the lane now, then every key and command, each alert chip, `sending`, `queue held`, the `+` and `…` after dollars, and the board's marks (Help, below). In the command bar and in a lane's chat box, only while it is empty |
| `q`, `ctrl+q` | `/quit` (also `/q`, `/exit`) | Quit; it asks first while lanes are open or a flag is on its way (Quitting and signals, below) |

`h`, `r` and `e` are refused on a lane that gave up and stays open only for its flag's answer (it
takes no more turns): fork it (`f`), or answer its flag or wait for the platform's answer.

### Help

`?` (or `/help`) opens help for where you are (P65): in the lane list, and in a lane's view
while its chat box is empty. It is one dialog with every row from either view; only its order
follows the view it was opened from.

1. **Now.** The keys the simple layout's key line has for the lane the keys act on, each with
   its sentence, under `This lane, now: L03 · Gamma` (in a lane) or `The selected lane, now:
   L02 · Beta` (in the list: the selected lane, or on the board its challenge's only lane).
   With no lane (also while the filter hides the selected lane, which every key refuses) it
   reads `Now, with no lane selected` and has the keys that act without one (`/new`, `?`, `q`). These are the same rows in every layout, since they are about the
   lane's state and not about the key line on screen. The challenge's name is challenge text:
   made safe, on one row, never markup.
2. **Keys in a lane** or **Keys in the lane list**: the view it was opened from first, then the
   other one.
3. **Keys in both**: selecting and copying, and `ctrl+q`.
4. The commands, the alerts, the header and cost marks, and the board's marks, as before.

`?`, `esc` or `q` closes it, and the focus is back where it was, with the chat box's draft as it
was. A `?` that opened help sends nothing to a lane.

### Approving several flags at once

When a wave lands, several lanes can wait with a flag each. `A` in the fleet (`/approve all` in
either view) answers them together:

- It takes the flag each lane is asking about now (a submit approval, the one `a` would approve),
  for every lane that needs you, whatever the filter shows. A lane's flags still to come (`then:`)
  are not in it: each comes up after the one before it is answered.
- It leaves out, and says why: a flag of a challenge whose tries the platform counts (it asks on
  its own: approve it with `a` on its lane); a hand submit waiting for you to say how it went; an
  approval that is not a flag (more budget, the live box); a lane you have taken over.
- Before anything is sent it asks: a prompt lists each flag by lane and challenge, then what it
  leaves out. `y` approves; `n`, `esc` or enter on Cancel changes nothing.
- On `y` each flag is approved as `a` would approve it, one logged approval per lane, so the
  deck's rules hold: the flags of one challenge go to the platform one at a time, and a flag the
  run already knows is wrong is never sent (the first rejection takes the same flag off every
  other lane). Only the flags the prompt listed are approved: a lane whose flag was answered or
  changed while the prompt was open is left.
- The status line then says how many were approved, on which lanes, and which were left and why.
  With no flag to approve it says so, and why each waiting approval was left, and asks nothing.

### Dismissing an alert

`x` in the fleet (`/dismiss` in either view) takes down the selected lane's most urgent alert when
that alert is about its course (effort vs value, ignores the hint, wrong direction, loop, stall).
The lane is not touched: no message, no new plan.

- It is logged as your action (an intervention with its outcome, and a line in the lane's
  transcript), as a hint or a redirect is.
- The alert stays quiet for that lane exactly as an answered alert does: the detector does not
  raise it again for the next 3 turns of the lane (`quiet_turns`), and raises it after that only
  if it still holds. There is no permanent mute.
- It is refused, with the reason, when the lane's most urgent alert is not about its course: a
  flag (approve or decline it), a budget alert (approve more, escalate or kill), a teammate alert
  (flightdeck already acted), another approval waiting, or no alert at all.
- The post-flight report counts it as dismissed: not as an answer to the alert, and not among
  the interventions judged to have helped.

In the focus view the chat box has the keyboard: interventions are slash commands there, `esc` goes
back to the fleet, `ctrl+n` goes on to the next lane that needs you, and `?` on the empty box opens
help (Help, above).

## Quitting and signals

While lanes are open, or a flag is on its way to the platform, `q` (or `ctrl+q`, or `/quit`) asks
first and says what is at stake:

- each flag on its way, by name: quitting leaves its answer unknown;
- the open lanes by state, and what each lane waiting for you waits for (five at most, then a
  count);
- the challenges queued and not started;
- that nothing waiting for you is submitted or approved;
- where the run's log and transcripts stay.

`y` stops every lane and closes its workspace (a run cannot be resumed). `n`, `esc` or enter on
Stay stays; `q` is not an answer, so a double tap never quits. While the run is closing, every
intervention is refused.

During a run, closing the terminal (or an SSH drop) and a SIGTERM stop the run the way quitting
does, without asking: every lane stops and every workspace closes, and `play` exits with 128 plus
the signal's number. On the way out `play` prints the scorecard (when the board has answers; otherwise
one line with the tokens and dollars the run spent, "at least" when some spend had no price), the
run folder and the commands that read it, and names any flag still waiting for your approval
(never submitted) and any flag still on its way to the platform (not known to have been
submitted).

If the console itself fails (an error in it that nothing handles), the run is stopped the same
way before `play` exits: every lane stops, every workspace closes and your live-box holds leave the
team folder. `play` prints the same lines on the way out, says that the console failed, and exits
with status 1.

## Terminal title and bell

What the console says outside its own window, for a player who is looking at another one
(`console/terminal.py`, `Beacon`; P61).

- **Title.** The terminal's icon and window title (OSC 0), from the header's own count and
  words:

  | Lanes that need you | Queue | Title |
  |---|---|---|
  | none | running | `flightdeck` |
  | 2 | running | `▲ 2 need you · flightdeck` |
  | none | held | `queue held · flightdeck` |
  | 2 | held | `▲ 2 need you · queue held · flightdeck` |

  It is written when the console opens and after that only when its text changes. It holds a
  count and fixed words and nothing else: no challenge name, no reason for a hold, no lane text
  (rule 5).
- **Bell.** One BEL each time the count of lanes that need you is higher than it was at the
  last redraw. None for the count the console opens on (the player is at the console), for a
  count that stays or falls, or for a hold.
- **Putting the title back.** Before its first title the console has the terminal save the one
  it shows (xterm's window operation 22, the title stack), and when it leaves it empties the
  title and has the terminal take the saved one back (operation 23). A terminal with a title
  stack shows what it showed before; one without is left with an empty title, which is its
  default one, never a count. This happens on every way out that still has a terminal (`q`,
  a run's SIGTERM, the event's end, a console that failed), and while a lane's shell has the
  terminal (`t` take over): the title goes back first, nothing is written while the shell has
  the terminal, and on the way back the title is saved and written again, with no bell.
  After a hang-up there is no terminal to write to. A SIGKILL leaves the title as it was, and
  so does a flightdeck stopped from outside (SIGTSTP, SIGSTOP) for as long as it is stopped.
- **Switches.** `title = false` and `bell = false` under `[console]`, each by itself. With
  `title` off nothing about the title is written, the save and the take-back included.
- **tmux.** With tmux's defaults a bell marks the window in the status line and is passed on to
  the terminal outside (`monitor-bell` on, `bell-action any`); a title sets the pane's title and
  reaches the terminal outside only with `set-titles on` (off by default). So over SSH on a
  phone the bell is the signal that arrives with nothing set up.

Both are written through the console's terminal driver, behind what is being drawn, and are
dropped once the terminal has hung up. Textual's `App.bell()` is not used: it writes nothing on
a headless driver, and the tests read what the driver is handed.

## Autopilot

While autopilot is engaged the header has an `AUTOPILOT` chip (`AP` in the compact layout) after
the lanes and before the need-you count. It never drops: who has the controls is not a detail.
An intervention autopilot makes by rule reads `› autopilot` in the lane's transcript, where yours
reads `› you`, and its texts say autopilot ("by autopilot; parked").

When autopilot disengages the chip goes, the status line shows the warning with its reason, and
the header says `queue held: autopilot disengaged: <reason>`. Its guardrails hold until you touch
the controls: your first intervention, `/unhold` or `/autopilot off` turns it off. `/unhold` lifts
the hold as always, and autopilot stays off until `/autopilot on`.

## Narrow terminals

What gives way when the terminal is narrow, least needed first (in the `deck` layout; the simple
layout's header and key line are under [Layouts](#layouts)):

- **Header.** The dollars go first, then tokens, the event clock, the event name, the mock tag and
  docker/host; flightdeck, solo/team, lanes, the need-you count and a held queue stay. A held
  queue's reason gets its room the same way (dollars, tokens, the clock, then the event name give
  way to it) and is cut to the room left; with fewer than 12 cells left, the header names no
  reason.
- **Board.** Under 100 columns the board hides (the lane list says so, down to 65 columns).
- **Fleet.** Low-value columns drop first, and the challenge name narrows before a column is cut.
- **Key line.** The fleet's key line always shows `? help` and `q quit`; the keys needed least are
  left out whole rather than cut: focus and sort first, then take over, escalate and fork, then
  claim, dismiss, redirect, hint and pause, then approve all, kill and open, and last the
  commands, decline and approve.

`flightdeck doctor` measures a terminal with the console's own layout code, so what it says a size
leaves out is what the console leaves out.

### Compact layout (64 columns or fewer)

For a phone over SSH (flightdeck in tmux, 50 to 60 columns). At 64 columns or fewer both views
switch to a layout made for that width, whether the console is in `simple` or `deck`; from 65
columns the rules above apply. It keeps what
matters there: what needs you and why, the one-key answers, and each lane's state and cost.

```
 solo ╱ 4/4 · q3 ╱ ▲ 2 need you ╱ $3.18
╭ fleet 4/4 · sort attention ────────────────────────╮
│    !      lane  state      cost  chall             │
│ ▌  flag   L04   wait       $.16  Ticket Desk       │
│    hint   L01   run        $.13  Static Hiss       │
│           L02   run        $.02  Bent Coin         │
│▌L04 ▲ Flag found: Candidate mock{…} matches the    │
│flag format.                                        │
│   1  submit mock{…}                                │
│   0  do not submit                                 │
│  enter open                                        │
│                                                    │
╰────────────────────────────────────────────────────╯
 ● wren solved Night Shift · stopped L05
╭─ to L04 · Ticket Desk ─────────────────────────────╮
│ a message, or / for commands                       │
╰────────────────────────────────────────────────────╯
 a yes  d no  1-9 answer  / cmd  ? help  q quit
```

- **Header.** What needs you ("▲ N need you", "all clear", "queue held" and why as room allows)
  and the run's dollars always stay, with lanes used/limit and the queue's length in short
  ("4/4 · q3"). The flightdeck name gives way first, then solo/team. Tokens, the event clock, the
  event's name, the mock tag and docker/host are not shown.
- **Fleet.** No board (as under 100 columns). Each lane row has the attention chip in four
  letters at most (`flag`, `budg`, `loop`, `efrt`, `hint`, `wway`, `stal`, `mate`; an approval
  alone: `sub`, `conf`, `budg`, `box`; `send` while a flag is on its way), the lane, the state in
  five letters at most (`run`, `wait`, `pause`, `take`; ended: `done`, `kill`, `stop`, `gave`),
  the lane's cost with its markers (`$.42+`, `…`), and last the challenge, which takes the room
  left: the edge of the terminal cuts its name, never the state or the cost. Model, turns, idle
  time and the last action are in the focus view.
- **Why line.** Six rows under the list: why the selected lane is flagged (wrapped onto two
  rows), then its numbered answers, one a row (three at most; with more, the last row says how
  many more: the lane's needs-you card has them all), then a row with `x dismiss` for an alert
  about its course and `enter open`.
- **Peek.** `space`, as on a wide terminal, directly over the why line; it needs 20 lines for
  one row and 25 for all six.
- **Key lines.** Fleet: `a yes  d no  1-9 answer  / cmd  ? help  q quit`. Focus: `esc fleet
  1-9 0 answer  / cmd  ctrl+n next`. Every other key still works (`?` lists them): only the line
  is shorter.
- **Focus view.** One pane: the needs-you card on top (six tenths of the pane at most; a taller
  card scrolls there), the transcript under it; the title has the lane, its state and its cost
  first, then the challenge.
  On the card the approval and its two answers come first, the reasons wrap, and each answer is
  one row, its number first and its command cut at the edge. The files pane is hidden, and `/diff` says so (widen the terminal to read a diff). The strip of other
  lanes needing you is `N more need you (ctrl+n):` and their chips. Details start on, in
  `simple` too; `ctrl+o` gives the calm transcript, and the card keeps this form.
- Panels lose their side margin and padding, and the gaps under the header and over the why
  line go, so the lane list has the rows and columns.

`flightdeck doctor` says when a terminal gets the compact layout, and what that layout leaves
out. `flightdeck mock --screenshot DIR` saves it as `compact-56x40` (the fleet) and
`compact-focus-56x40` (a lane).

## Mock scenarios

The mock ships fake data that exercises every alert and at least these scenarios:

1. **Wave drop**: 43 challenges arrive at once, `max_lanes` = 16, the rest queue. Scrolling and
   attention sorting must be usable.
2. **SSTV**: a 50-point forensics challenge whose description hints at slow-scan TV; the lane is
   comparing stereo channels. "Ignores the hint" fires; the player redirects.
3. **Overthinking**: a 50-point challenge with 300 solves at 40 turns. "Effort vs value" fires.
4. **Web wrong way**: a web lane brute-forcing directories while the source is in the handout.
5. **Team**: a teammate solves a challenge a lane is working on; the lane stops by itself.
6. **Flag found**: approve submit; the board updates.
7. **Autopilot**: engaged from the start with a run budget; it kills the looping lane, gives a
   lane more budget, escalates the stalled lane, then reaches its budget and disengages: the
   queue is held and the lanes are paused.
