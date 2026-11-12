# Screenshots

The console, from `flightdeck mock` (scripted data: every challenge, teammate and flag is invented).
Make your own with `flightdeck mock --screenshot DIR`, which writes SVGs of these moments (the PNGs
here were made from them) for each scenario (`--scenario default`, `wave`, `sstv`, `overthinking`,
`web`, `team`, `flag`).

## The fleet

![The fleet view: the board of challenges on the left, every lane on the right sorted by what needs you, with alert chips and a flag waiting for approval](screenshots/fleet.png)

The board on the left, every lane on the right, sorted by what needs you. The chips say why a lane
needs you: a flag to approve, a live box to allow, a budget, an alert.

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
`01-open.svg`: `02-autopilot-rule.svg` (the `AUTOPILOT` chip in the header, and a lane autopilot
just killed by rule: its row says "by autopilot; parked") and `03-autopilot-disengaged.svg` (the
run budget reached: the chip is gone, the header says `queue held: autopilot disengaged: the run
budget is reached`, and the lanes are paused). No picture of them here yet: make your own with
that command.

## Team play

![Team mode: a teammate solved a challenge, so the lane working it stops](screenshots/team-solve.png)

A teammate solved Night Shift, so the lane on it stops.

![A challenge's card with its files and lanes, and the claim key](screenshots/challenge-card.png)

A challenge's card: what it is, its files and lanes; `c` claims it for you in team mode.

## Smaller terminals, and help

![The console on a 120 by 36 terminal](screenshots/narrow.png)

On a 120x36 terminal: less goes in the header, and the key line keeps what you need most.

At 64 columns or fewer (a phone over SSH) the console has a compact layout. `flightdeck mock
--screenshot DIR` saves it at 56x40, numbered like the rest (14 and 15 in the default scenario):
`14-compact-56x40.svg` (the fleet: each lane's row has what needs you, its state and its cost;
the line under the list has the reason and one answer a row) and `15-compact-focus-56x40.svg` (a
lane: what it needs above its transcript, no files pane). No picture of it here yet: make your
own with that command.

![The help screen listing every key and command](screenshots/help.png)

`?` shows every key and command.
