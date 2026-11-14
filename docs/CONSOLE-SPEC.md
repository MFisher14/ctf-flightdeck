# Console spec

The console is the product: a fleet view to watch every lane and a focus view to work one (D16),
with one-key interventions in the fleet and a chat box with slash commands in both.
`flightdeck mock` shows it on scripted data; `play` and `practice` drive it with real lanes.

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
╭ / for commands · enter opens the selected lane · or type a message to it ──────────────────────────╮
╰────────────────────────────────────────────────────────────────────────────────────────────────────╯
 o open  ? help  p pause  h hint  r redirect  f fork  k kill  e escalate  t take over  a approve  d decline  A approve all  x dismiss  ...
```

`[flag]` stands for a chip: a solid colored label (no half-block caps, so no color shows past a
corner in any font). The header's segments are solid blocks with a `╱` between them on the page.

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
- **Command bar**: acts on the same lane the keys do (the board challenge's only lane when the board
  has focus; refused when the filter hides the selected lane). Its suggestions follow the selection.
  Enter on an empty bar opens the selected lane. A command that takes no argument refuses a stray
  word (`/approve 2` does not approve the selected lane; name it: `/approve L02`). `/approve all`
  names no lane: it is the fleet's `A` (Interventions, below), in either view.
- **Status line**: the latest intervention outcome or deck event (no toasts over the lanes); it
  clears after 12 seconds. When the queue is held it says so and how to lift it: "queue held until
  you /unhold it: <why>". Lifting a hold that an API outage caused says how many of the challenges
  it parked were queued again.

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
╭ message this lane (it reads it on its next turn) · / for commands ─────────────────────────────────╮
 esc fleet  enter send  / commands  1-9 0 answer  ctrl+n next lane needing you  tab files  pgup pgdn scroll
```

- **Transcript**: the lane's steps (⏺ command, ⎿ output), your messages (› you), flightdeck notes,
  alerts and approvals, in order. It follows the lane; scroll back (`pgup`) and it stays where you
  are reading until you scroll to the end again. What a lane did shows a credential's name but
  not its value, as its transcript file keeps it. A key flightdeck holds shows as `[NAME]`, and
  the lane's model had it so too; anything else shaped like a credential shows as `[redacted]`,
  and the lane's model had that text as it was.
- **Needs you now**: the lane's open alerts with their reasons and the suggested answers as commands
  (`/dismiss` under the alert it would take down).
  It takes at most half the pane, so the transcript keeps its rows on a small terminal.
- **Files changed**: the files the lane wrote or edited, with the diff of the selected one.
- **Chat box**: plain text is a message the lane reads on its next turn; `/` runs a command. Typing
  reaches it from any pane. An unsent message stays with its lane when you switch lanes.
- **ctrl+n** goes through the lanes that need you in attention order, then round to the first.

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
| `k` | `/kill [park]` | Kill the lane; the challenge goes back to the queue (fresh) or is parked |
| `e` | `/escalate` | Hand a compact state summary to a stronger model |
| `t` | `/takeover` | Drop to a shell in the lane's workspace (its container in Docker); exit the shell to hand back. The lane hears what you changed. Other lanes keep running meanwhile. |
| `a`, `1` | `/approve` | Approve the pending action (submit, more budget, live-box access); on a board that cannot check flags, "accepted" |
| `A` | `/approve all` | Approve every flag that waits for a plain yes, in one action (Approving several flags at once, below) |
| `x` | `/dismiss` | Dismiss the lane's most urgent alert about its course (effort, off-hint, wrong way, loop, stall) without intervening: you judge it wrong. It goes, and stays quiet as an answered alert does (Dismissing an alert, below) |
| `d`, `0` | `/decline` | Say no: the flag is not submitted (or, after a hand submit, was rejected), or the live box stays off, and the lane carries on; refusing more budget stops the lane |
| `1`-`9` | | Quick answers: the numbers in the why line and the needs-you card; one key, no enter (focus view: only while the chat box is empty) |
| `c` | `/claim [challenge]` | Team mode: claim or release a challenge |
| enter, `o` | `/open <lane>` | Open the lane in the focus view (`esc` or `/back` returns) |
|  | `/diff [file]` | Show the files the lane changed |
|  | `/config [lanes N\|unlimited]`, `/config submit auto\|confirm`, `/config file` | Alone: a dialog with this run's settings (lanes at once, what happens to a flag); Enter applies, esc cancels. `lanes`: how many lanes run at once, from now on (raising it starts queued lanes; lowering it stops none). `submit auto` turns auto approve on: a flag a lane submits goes at once, with auto submit's exceptions; `submit confirm` turns it off. Flags already waiting stay yours. Neither goes past the event's rules. `file` names your config file. Each change lasts for this run. |
|  | `/note <text>` | A note for every lane (an organizer's ruling, a replaced handout): each running lane reads it on its next turn, and every lane started later in this run reads it at its start. At most 12 stand at once. |
|  | `/new [name]` | Hand a challenge over, on a board you fill yourself: a form with the challenge's name and a box for its description and its instance's address; its files and screenshots are attached by a drop on the terminal, `ctrl+o` or `ctrl+v`, and listed on the form (a path written in the description is only text; the address is `https://...` or `nc host port`, on a line of its own); category and points are optional. A line under the box says what is attached. `ctrl+v` pastes a screenshot from the clipboard, and the lanes' model reads an image's text into the description. `ctrl+s` adds it and a lane starts on it; `esc` cancels. Refused on a board that comes from a platform, and in the mock. |
|  | `/attach [challenge] <files>` | Add files to a challenge on a board you fill yourself: drag them onto the command bar. Its lanes start afresh with them. Without a challenge: the open lane's. |
|  | `/queue <challenge>` | Queue a parked or new challenge (also from its board card) |
|  | `/autopilot [on\|off]` | `on` engages autopilot, `off` takes the controls back, alone it says which it is. `on` is refused, with the reason, without a run budget, off the Docker runtime, while the queue is held, and once the budget is spent |
|  | `/unhold` | Lift the hold on the queue once its cause is fixed: the challenges an API outage parked are queued again, and queued lanes start in the free slots (a key or model id changed in your config needs a new run). Refused when the queue is not held; while it is, the `/` menu offers it first, whatever lane is selected |
| `/`, `s`, `tab` | `/filter`, `/sort` | Command bar, change sort, move focus between panes |
| `?` | `/help` | Help: every key and command, each alert chip, `sending`, `queue held`, the `+` and `…` after dollars, and the board's marks |
| `q`, `ctrl+q` | `/quit` | Quit; it asks first while lanes are open or a flag is on its way (Quitting and signals, below) |

`h`, `r` and `e` are refused on a lane that gave up and stays open only for its flag's answer (it
takes no more turns): fork it (`f`), or answer its flag or wait for the platform's answer.

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
back to the fleet and `ctrl+n` goes on to the next lane that needs you.

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

What gives way when the terminal is narrow, least needed first:

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
switch to a layout made for that width; from 65 columns the rules above apply. It keeps what
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
╭ / for commands · enter opens the selected lane · … ╮
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
- **Key lines.** Fleet: `a yes  d no  1-9 answer  / cmd  ? help  q quit`. Focus: `esc fleet
  1-9 0 answer  / cmd  ctrl+n next`. Every other key still works (`?` lists them): only the line
  is shorter.
- **Focus view.** One pane: the needs-you card on top (six tenths of the pane at most), the
  transcript under it; the title has the lane, its state and its cost first, then the challenge.
  On the card the reasons wrap and each answer is one row, its number first and its command cut
  at the edge. The files pane is hidden, and `/diff` says so (widen the terminal to read a diff). The strip of other
  lanes needing you is `N more need you (ctrl+n):` and their chips.
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
