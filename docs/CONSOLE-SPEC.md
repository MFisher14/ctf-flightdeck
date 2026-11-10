# Console spec (M0)

The console is the product. M0 builds it as a clickable mock with fake data; M1 wires it to real lanes.
At the M0 review the player chose **route C**: a fleet view to watch every lane and a focus view to
work one lane, with one-key interventions in the fleet and a chat box with slash commands in both
(D16).

## Fleet view (the default screen)

```
 flightdeck ╱ event ╱ team ╱ docker ╱ lanes 16/16 · queue 27 ╱ ▲ 5 need you ╱ tok 4.1M ╱ $3.18 ╱ T+01:44
╭ board 51 · ✓ 2 · team ✓ 1 ───────╮ ╭ fleet 16/16 · sort attention ─────────────────────────────────╮
│ cat  name         pts solv   own │ │   !          lane chall        model state turns cost idle last │
│ web  Ticket Desk  100   41 ▶ L04 │ │ ▌ ▐flag▌     L04  Ticket Desk  sonnet wait     7  .16  11m …    │
│ for  Static Hiss   50   88 ▶ L01 │ │   ▐offhint▌  L01  Static Hiss  glm    run     21  .13  20s …    │
│ ...                              │ │   ...                                                          │
│                                  │ │ ▌L04 ▲ Flag found: candidate mock{…} matches the flag format    │
│                                  │ │    a submit mock{…}   enter open                                │
╰──────────────────────────────────╯ ╰────────────────────────────────────────────────────────────────╯
 ● wren solved Night Shift · stopped L05                                    (status: latest outcome or event)
╭ / for commands · enter opens the selected lane · or type a message to it ──────────────────────────╮
╰────────────────────────────────────────────────────────────────────────────────────────────────────╯
 o open  ? help  p pause  h hint  r redirect  f fork  k kill  e escalate  t take over  a approve  ...
```

- **Header**: event, solo/team, docker/host, lanes used/limit, queue length, **how many lanes need
  you**, tokens, dollars, event clock. Low-priority pieces drop out on narrow terminals.
- **Board**: every challenge with category, points, solve count, status (new ·, queued …, running ▶,
  solved by us ✓, solved by a teammate ✓ in cyan, blocked ✗, parked ‖) and owner (lane, me,
  teammate). Enter on a row opens its lane, or a card to queue or claim it.
- **Fleet**: one compact row per lane, scrolling, **sorted by attention** (below). Finished lanes
  collapse into one row. 40+ rows stay usable; low-value columns drop first on narrow terminals.
- **Why line**: under the list, why the selected lane is flagged and the keys that answer it.
- **Status line**: the latest intervention outcome or deck event (no toasts over the lanes).

## Focus view (enter on a lane)

```
 flightdeck ╱ ...header...
 4 other lanes need you: ▐L04 flag▌ ▐L07 loop▌ ▐L02 effort▌ ▐L03 wrongway▌   ctrl+n next
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
 esc fleet  enter send  / commands  ctrl+n next lane needing you  tab files  pgup pgdn scroll
```

- **Transcript**: the lane's steps (⏺ command, ⎿ output), your messages (› you), flightdeck notes,
  alerts and approvals, in order.
- **Needs you now**: the lane's open alerts with their reasons and the suggested answers as commands.
- **Files changed**: the files the lane wrote or edited, with the diff of the selected one.
- **Chat box**: plain text is a message the lane reads on its next turn; `/` runs a command.

## Attention order

1. Lanes that need the player: an approval waiting, or an alert that wants an answer. Most urgent
   first: a flag, then any other approval, then budget, loop, effort, ignores the hint, wrong way,
   stall; oldest first within the same urgency.
2. Lanes with only an informational alert (flightdeck already acted, e.g. a teammate holds the box).
3. Running lanes by idle time, in whole minutes, so rows do not reshuffle every tick.
4. Paused and taken-over lanes. 5. Finished lanes (collapsed).

## Alerts (from the author's real cues)

| Alert | Fires when (mock: scripted; M3: real detector) | Suggested action |
|---|---|---|
| Effort vs value | Turns or tokens are high for a low-point challenge, especially one with many solves. "Complex work on a 50-pointer." | Hint "it's simpler than this", or kill and re-queue fresh |
| Ignores the hint | The description hints at something (e.g. SSTV, slow scan, radio) but the lane does something else (e.g. comparing stereo channels of the wav). | Redirect with the hinted technique |
| Wrong direction (web) | A web lane fuzzes or brute-forces when source is given, or keeps attacking one endpoint with no new signal. | Redirect, or fork with a different approach |
| Loop | The same command or near-same action repeats. | Hint or kill |
| Stall | No new artifact or hypothesis for N turns. | Escalate to a stronger model with a summary |
| Teammate solved / box in use | Team mode: the challenge is solved, or a teammate holds the live instance. | Solved: stop the lane (automatic). Box in use: keep the lane off the box until it is free (automatic) |
| Budget | Lane near its token or dollar cap (80%), or at it (100%: it waits). | Approve more (also at 80%), escalate (at 80%), or kill |
| Flag found | A candidate flag matches the format. | Approve submit (if submit = confirm) |

## Interventions

| Key (fleet) | Command (both views) | Action |
|---|---|---|
| `p` | `/pause` | Pause or resume the lane |
| `h` | `/hint <text>`, or plain text | A message the lane reads on its next turn |
| `r` | `/redirect <plan>` | Replace the lane's plan with a new direction |
| `f` | `/fork [approach]` | Start a sibling lane on the same challenge with a different approach or model |
| `k` | `/kill [park]` | Kill the lane; the challenge goes back to the queue (fresh) or is parked |
| `e` | `/escalate` | Hand a compact state summary to a stronger model |
| `t` | `/takeover` | Drop to a shell in the lane's workspace; hand back when done (placeholder in M0) |
| `a` | `/approve` | Approve the pending action (submit, more budget, live-box access) |
| `c` | `/claim [challenge]` | Team mode: claim or release a challenge |
| enter, `o` | `/open <lane>` | Open the lane in the focus view (`esc` or `/back` returns) |
|  | `/diff [file]` | Show the files the lane changed |
|  | `/queue <challenge>` | Queue a parked or new challenge (also from its board card) |
| `/`, `s`, `tab` | `/filter`, `/sort` | Command bar, change sort, move focus between panes |
| `?` | `/help` | Help |

In the focus view the chat box has the keyboard: interventions are slash commands there, `esc` goes
back to the fleet and `ctrl+n` jumps to the next lane that needs you.

## Proposed at the M0 review (built in the mock, not yet signed off)

These go beyond route C itself; keep or change them when you sign off the mock.

- **Box in use** keeps the lane working on the handout, off the live box, instead of stopping it,
  and then asks for live-box access (a `box` approval).
- **Approvals** queue per lane and a flag goes first; nothing is dropped.
- **Budget**: `a` also works at the 80% warning; escalate is not offered at 100%.
- **Parked** is a board status; a parked challenge can be queued again (`/queue`, or its card).
- **Attention order** puts any approval with the flags and informational alerts after them (above).

## Mock scenarios (M0)

The mock ships fake data that exercises every alert and at least these scenarios:

1. **Wave drop**: 43 challenges arrive at once, `max_lanes` = 16, the rest queue. Scrolling and
   attention sorting must be usable.
2. **SSTV**: a 50-point forensics challenge whose description hints at slow-scan TV; the lane is
   comparing stereo channels. "Ignores the hint" fires; the player redirects.
3. **Overthinking**: a 50-point challenge with 300 solves at 40 turns. "Effort vs value" fires.
4. **Web wrong way**: a web lane brute-forcing directories while the source is in the handout.
5. **Team**: a teammate solves a challenge a lane is working on; the lane stops by itself.
6. **Flag found**: approve submit; the board updates.
