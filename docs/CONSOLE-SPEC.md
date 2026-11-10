# Console spec (draft for M0)

The console is the product. M0 builds it as a clickable mock with fake data; M1 wires it to real lanes.

## Layout

```
┌ header ─────────────────────────────────────────────────────────────────────────────┐
│ event · mode solo|team · runtime docker|host · lanes 12/16 (queue 27) · tok 4.1M · $3.18 │
├ board (left) ──────────────┬ lanes (centre, scrolls) ───────────────────────────────┤
│ cat  name        pts solves│ ! lane chall        model   state  turns tok   $    idle │
│ web  Ticket Desk 100  41 ✓ │ ▲ L07  Static Hiss  glm     run    31    210k  .21  6m  │
│ for  Static Hiss  50  88   │   L03  Ticket Desk  sonnet  solved 12    90k   .44  -   │
│ ...                        │   ...                                                   │
├ detail (selected lane) ────┴──────────────────────────────────────────────────────────┤
│ plan · last actions · artifacts · alerts with reasons · suggested intervention        │
├ keys ─────────────────────────────────────────────────────────────────────────────────┤
│ p pause  h hint  r redirect  f fork  k kill  e escalate  t take over  a approve  ...  │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

- **Board**: every challenge with category, points, solve count, status (new, queued, running,
  solved by us, solved by teammate, blocked), owner (lane, me, teammate).
- **Lanes**: one compact row per lane, scrolling, **sorted by attention** (alerts first, then
  pending approvals, then running by idle time). Finished lanes collapse. 40+ rows must stay usable.
- **Detail**: the selected lane's current plan, recent actions (commands, short outputs), artifacts
  found, alerts with the reason they fired, and a suggested intervention.
- **Header**: event, solo/team, docker/host, lanes used/limit, queue length, totals for tokens and
  dollars.

## Alerts (from the author's real cues)

| Alert | Fires when (mock: scripted; M3: real detector) | Suggested action |
|---|---|---|
| Effort vs value | Turns or tokens are high for a low-point challenge, especially one with many solves. "Complex work on a 50-pointer." | Hint "it's simpler than this", or kill and re-queue fresh |
| Ignores the hint | The description hints at something (e.g. SSTV, slow scan, radio) but the lane does something else (e.g. comparing stereo channels of the wav). | Redirect with the hinted technique |
| Wrong direction (web) | A web lane fuzzes or brute-forces when source is given, or keeps attacking one endpoint with no new signal. | Redirect, or fork with a different approach |
| Loop | The same command or near-same action repeats. | Hint or kill |
| Stall | No new artifact or hypothesis for N turns. | Escalate to a stronger model with a summary |
| Teammate solved / box in use | Team mode: the challenge is solved, or a teammate holds the live instance. | Stop the lane (automatic in team mode) |
| Budget | Lane near its token or dollar cap. | Approve more, escalate, or kill |
| Flag found | A candidate flag matches the format. | Approve submit (if submit = confirm) |

## Interventions

| Key | Action |
|---|---|
| `p` | Pause or resume the lane |
| `h` | Inject a hint (free text) into the lane's next turn |
| `r` | Redirect: replace the lane's plan with a new direction |
| `f` | Fork: start a sibling lane on the same challenge with a different approach or model |
| `k` | Kill the lane; challenge goes back to the queue or is parked |
| `e` | Escalate: hand a compact state summary to a stronger model |
| `t` | Take over: drop to a shell in the lane's workspace; hand back when done |
| `a` | Approve the pending action (submit, more budget, live-box access) |
| `c` | Team mode: claim or release a challenge |
| `/`, `s`, `tab` | Filter, change sort, move focus between panes |
| `?` | Help |

## Mock scenarios (M0)

The mock must ship fake data that exercises every alert and at least these scenarios:

1. **Wave drop**: 43 challenges arrive at once, `max_lanes` = 16, the rest queue. Scrolling and
   attention sorting must be usable.
2. **SSTV**: a 50-point forensics challenge whose description hints at slow-scan TV; the lane is
   comparing stereo channels. "Ignores the hint" fires; the player redirects.
3. **Overthinking**: a 50-point challenge with 300 solves at 40 turns. "Effort vs value" fires.
4. **Web wrong way**: a web lane brute-forcing directories while the source is in the handout.
5. **Team**: a teammate solves a challenge a lane is working on; the lane stops by itself.
6. **Flag found**: approve submit; the board updates.
