# Leaderboard

Events flightdeck has flown in: where the team finished, what they ran, and how hands-on they
were. Every row was sent in by the players themselves, after their event ended.

**[Add your flight](https://github.com/MFisher14/ctf-flightdeck/issues/new?template=leaderboard.yml)**:
a short form, and your GitHub name goes on the board.

## Flights

Newest first.

| Event | Date | Team | Finish | Pilots | Mode | Setup | Card |
|---|---|---|---|---|---|---|---|
| *No flights yet. Yours could be the first.* | | | | | | | |

- **Finish**: the place on the final scoreboard, and out of how many teams (`12 / 840`), with a
  link to the public scoreboard or the CTFtime page where there is one.
- **Pilots**: the GitHub names of the players who flew, each linked to their profile.
- **Setup**: the models, where lanes ran (Docker or host), and any coding-agent CLI.
- **Card**: the issue with the run's flight card (`flightdeck share`), for the numbers.

## Mode: how hands-on the players were

The same three words everywhere, so rows can be compared. `flightdeck share` works out which
one a run was, from the run's own log.

| Mode | What it means |
|---|---|
| **Hands-on** | The players steered: hints, redirects, forks, escalations, kills or take-overs during the run. |
| **Approve-only** | The players only said yes or no: flags, budgets and live-instance requests. No steering. |
| **Hands-off** | Nobody touched a lane. Flags went out under auto submit. |

A team's event is often several runs. Give the mode of most of the event, and say so in the
notes if it varied.

## The rules

- **Only after the event has ended**, and only where the event's rules allowed AI tools. If the
  rules forbade them, the flight does not belong here (or anywhere).
- **No flags, no challenge text, no writeups** in the entry or its card. A flight card holds
  none of them by design.
- **You may enter only yourself and teammates who agreed** to be named. Ask for a row's removal
  at any time and it goes.
- Entries are taken on trust and checked against the public scoreboard where there is one. A
  row that cannot be checked says so.

## Why it exists

Credit for the players, and evidence for everyone else: which models, on which setups, with
how much human steering, finish where. The numbers behind each row are in its flight card, and
the cards together feed [the model guide](MODELS.md).
