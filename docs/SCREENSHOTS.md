# Screenshots

The console, from `flightdeck mock` (scripted data: every challenge, teammate and flag is invented).
Make your own with `flightdeck mock --screenshot DIR`, which writes SVGs of these moments for each
scenario (`--scenario default`, `wave`, `sstv`, `overthinking`, `web`, `team`, `flag`).

## The fleet

![The fleet view: the board of challenges on the left, every lane on the right sorted by what needs you, with alert chips and a flag waiting for approval](screenshots/fleet.png)

The board on the left, every lane on the right, sorted by what needs you. The chips say why a lane
needs you: a flag to approve, a live box to allow, a budget, an alert.

![A second wave of challenges arrives during the run](screenshots/wave.png)

A new wave lands mid-run: lanes start up to the limit, the rest queue cheapest first.

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

![A flag found by a lane, waiting for the player's approval](screenshots/flag-waiting.png)

A flag a lane found waits for you: `a` or `1` submits it, `d` or `0` declines.

![The flag approved and submitted](screenshots/flag-submitted.png)

Submitted and checked.

## Interventions

![Forking a lane onto another approach or model](screenshots/fork.png)

Fork a lane: a sibling on the same challenge, with another approach or model.

![Taking over a lane's shell](screenshots/take-over.png)

`t` takes over a lane's shell (in a real run, a shell in its workspace; exit it to hand the lane
back). The mock shows a placeholder.

## Team play

![Team mode: a teammate solved a challenge, so the lane working it stops](screenshots/team-solve.png)

A teammate solved Night Shift, so the lane on it stops.

![A challenge's card with its files and lanes, and the claim key](screenshots/challenge-card.png)

A challenge's card: what it is, its files and lanes; `c` claims it for you in team mode.

## Smaller terminals, and help

![The console on a 120 by 36 terminal](screenshots/narrow.png)

On a 120x36 terminal: less goes in the header, and the key line keeps what you need most.

![The help screen listing every key and command](screenshots/help.png)

`?` shows every key and command.
