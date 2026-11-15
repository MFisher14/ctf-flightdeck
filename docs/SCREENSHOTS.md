# Screenshots

The console, from `flightdeck mock` (scripted data: every challenge, teammate and flag is invented).
Make your own with `flightdeck mock --screenshot DIR`, which writes SVGs of these moments for each
scenario (`--scenario default`, `wave`, `sstv`, `overthinking`, `web`, `team`, `flag`). The PNGs
here are those SVGs, drawn by a browser and saved with a 128-colour palette.

The console opens in the **simple** layout. Most pictures here show the **deck** layout, the whole
dashboard, which `/layout deck` switches to
([Layouts](GUIDE.md#layouts)). `mock --screenshot` takes its
pictures in the deck layout and the default theme whatever your config says; the `simple-` moments
and `theme-light` are switched to for their own shot.

## The demo, in a minute

![A one-minute recording of flightdeck mock in the simple layout: a flag is submitted with one key, a lane that ignores its hint is opened and redirected and finds the flag, a lane going the wrong way is killed and started fresh, a wave of 43 challenges drops, and the help screen lists every key](screenshots/demo.gif)

This one is not a set of stills. [`scripts/demo.py`](../scripts/demo.py) opens `flightdeck mock`
(the default scenario, the simple layout, 120 by 36) with no terminal, presses the keys a player
would (Enter, `1`, Page Up, Esc, `k`, `r`, `?`, `q`) and moves the mock's clock itself, so the
same frames come out every time. The line in the window's title bar is the script's caption:
the key just pressed and what it did. The first and the last frames are drawn, not played: a
shell prompt and the command typed at it.
[CONTRIBUTING.md](../CONTRIBUTING.md#the-readmes-demo) says how to build it again.

## The simple layout

![The simple layout: a short header with the event, the team tag, three lanes that need you and the run's dollars, where only flightdeck and the need-you count have a coloured block; one list of six lanes with their alert chip, challenge, state, cost and last action; under the list, the found flag with 1 to submit it and 0 not to; a key line of approve, decline, open, commands, help and quit](screenshots/simple.png)

What the console opens in: one list of lanes, sorted by what needs you. The header says only what
is not the usual, and only what asks you to look has a coloured block in it; the line under the
list says why the selected lane is flagged, and the key line has only the keys that apply to that
lane now. Every other key still acts, and `?` lists them.

![The simple layout during a wave: the header also says queue 33, the list's title says 16 of 16 lanes, 33 waiting and 1 solved, ten lanes that have not begun say starting and have no cost, and the selected lane ignores its description's hint, with 1 to redirect it, 2 to send a hint and x to dismiss the alert](screenshots/simple-alert.png)

A wave has landed: the header has the queue because it is not empty, and the list's title counts
the challenges that wait and the ones solved. The lanes the wave started say `starting`, with no
cost, until they take their first step. The selected lane's alert has numbered answers, so
the key line leads with `1-9 answer` and `x dismiss`.

![A lane full screen in the simple layout: the strip of two other lanes that need you; the calm transcript, 6 tool calls and the last of them, the alert's name and turn, 12 tool calls and the last of them; the needs-you card in two rows, the alert with its reason and its two numbered answers; the files the lane changed with a diff; and a key line of answer, esc lanes, commands, help and ctrl+o details](screenshots/simple-lane.png)

`enter` opens a lane. In the simple layout the view shows a part only when it has something in
it: the strip on top while another lane needs you, the card while this one does, the files pane
once the lane has changed a file. Its transcript is calm, a row for each thing the lane did and
two for a run of tool calls, and so is its card: what the lane asks, and the numbered answers.
`ctrl+o` shows every line and the full card, as the deck layout's lane does below.

![A lane in the simple layout that runs the same command again and again: its transcript says 6 tool calls, and the last row starts with ×4, python3 angr_solve.py ratchet_run and its timeout; the loop alert, and the needs-you card with 1 to send a hint and 2 to kill it and queue it again fresh](screenshots/folded-step.png)

A lane going round in circles shows it at a glance: the last row of a run of tool calls starts
with how many times in a row the lane made that call (`×4`). Calls fold only when their text is
the same; `ctrl+o` still shows every one. (From the `wave` scenario.)

## The fleet (the deck layout)

![The fleet view: the board of challenges on the left, every lane on the right sorted by what needs you, with alert chips and a flag waiting for approval](screenshots/fleet.png)

`/layout deck`: the board on the left, every lane on the right with its model, turns and idle
time, sorted by what needs you. The chips say why a lane needs you: a flag to approve, a live box
to allow, a budget, an alert.

![A second wave of challenges arrives during the run](screenshots/wave.png)

A new wave lands mid-run: lanes start up to the limit, the rest queue, lowest points first.

## Alerts

![An alert: the lane ignores what the description hints at, with quick answers to redirect it or send a hint](screenshots/alert-hint.png)

A lane ignores what the description hints at. `1` redirects it to the hinted technique, `2` sends a
hint, or write your own message.

![An alert: a lane repeating the same steps](screenshots/alert-loop.png)

A lane going round in circles.

![An alert: a lane spending heavily on a low-value challenge](screenshots/alert-effort.png)

A lane spending big on a challenge worth little.

![An alert: a lane heading the wrong way on a web challenge](screenshots/alert-web.png)

A lane heading the wrong way on a web challenge.

## A lane up close

![A lane full screen: its transcript, the files it changed with a diff, and a card for what needs you](screenshots/lane.png)

`enter` opens a lane: every step it took, the files it changed, and what it needs from you.
The deck layout shows a lane in detail: every line of each command and its output, and the
full card, each alert with its reason and its answers as commands. `ctrl+o` switches to the
calm view the simple layout opens in (above), and back; `/details` does the same.

![Chatting with a lane from its full-screen view](screenshots/chat.png)

Plain text in the chat box is a message the lane reads on its next turn.

![The files a lane changed, with a diff](screenshots/diff.png)

What the lane changed, as diffs.

![The command bar with slash commands](screenshots/command-bar.png)

`/` opens the command bar: hint, redirect, fork, kill, approve, decline, escalate, pause, take over.

## Flags

![A flag found by a lane, waiting for your approval](screenshots/flag-waiting.png)

A flag a lane found waits for you: `a` or `1` submits it, `d` or `0` declines.

![The flag approved and submitted](screenshots/flag-submitted.png)

Submitted and checked.

## Interventions

![Forking a lane onto another approach or model](screenshots/fork.png)

Fork a lane: a sibling on the same challenge, with another approach or model.

![Taking over a lane's shell](screenshots/take-over.png)

`t` takes over a lane's shell (in a real run, a shell in its workspace; exit it to hand the lane
back). The mock shows a placeholder.

## Autopilot

`flightdeck mock --scenario autopilot --screenshot DIR` saves two moments of its own, after
`01-open.svg` and `02-simple-open.svg`: `03-autopilot-rule.svg` (the `AUTOPILOT` chip in the
header, and a lane autopilot just killed by rule: its row says "by autopilot; parked") and
`04-autopilot-disengaged.svg` (the run budget reached: the chip is gone, the header says `queue
held: autopilot disengaged: the run budget is reached`, and the lanes are paused). No picture of
them here yet: make your own with that command.

## Team play

![Team mode: a teammate solved a challenge, so the lane working it stops](screenshots/team-solve.png)

A teammate solved Night Shift, so the lane on it stops.

![A challenge's card with its files and lanes, and the claim key](screenshots/challenge-card.png)

A challenge's card: what it is, its files and lanes; `c` claims it for you in team mode.

## Smaller terminals, and help

![The console on a 120 by 36 terminal](screenshots/narrow.png)

On a 120x36 terminal: less goes in the header, and the key line keeps what you need most.

At 64 columns or fewer (a phone over SSH) the console has a compact layout, whichever layout your
config names. `flightdeck mock --screenshot DIR` saves it at 56x40, numbered like the rest (18 and
19 in the default scenario): `18-compact-56x40.svg` (the fleet: each lane's row has what needs
you, its state and its cost; the line under the list has the reason and one answer a row) and
`19-compact-focus-56x40.svg` (a lane: what it needs above its transcript, no files pane). No
picture of it here yet: make your own with that command.

![Help opened from the lane list: first what the keys do now (here with no lane selected), then the lane list's keys, peek and esc among them; further down a lane's keys, the keys both views have, the commands, the alerts and the marks](screenshots/help.png)

`?` opens help for where you are, in a lane too while its chat box is empty. It starts with the
keys that apply now to the lane in front of you, then the keys of the view you are in, the
other view's (`ctrl+o` for a lane's details, `pgup` and `pgdn`), and the ones both have (the
mouse drag that copies, `ctrl+c`); then every command.

## Themes

![The fleet view in the light theme: dark text on a pale page, the same chips, columns and marks in the light theme's colours](screenshots/theme-light.png)

`theme = "light"` under `[console]` in your config, or `/theme light` in a running console. A
theme changes colours only: the chips, marks and layout are the same. Built in: `flightdeck` (the
default, every other picture here), `light`, `nord`, `gruvbox` and `dracula`; your own is a small
file ([Themes](GUIDE.md#themes)).
