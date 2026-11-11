# Changelog

What changed for players, newest first. Milestones are in [docs/ROADMAP.md](docs/ROADMAP.md).

## Unreleased

### M1: a working slice

- `flightdeck play BOARD`: agent lanes play a folder of challenges against an OpenAI-compatible API
  (OpenRouter by default), each lane in its own Docker container or on the host, from the M0
  console. Lanes start cheapest-first; `max_lanes` run at once and the rest queue.
- `flightdeck practice`: 14 small synthetic challenges that ship with flightdeck, checked by hash.
- `flightdeck init` writes a config by asking a few questions; `flightdeck doctor` checks the setup
  and says how to fix each problem; `flightdeck image build` builds the lane image once.
- Flags wait for you: `a`/`1` submits, `d`/`0` declines. On a board that cannot check flags you
  submit by hand and say whether it was accepted.
- `t` hands you the lane's real shell (its container in Docker); exit it to hand the lane back,
  and the lane hears what you changed. Other lanes keep working meanwhile.
- Per-lane token and dollar caps (an alert at 80%, an approval at 100%), cost from the API or
  your config's prices, cached tokens counted.
- Every run writes an append-only `events.jsonl` and each lane's full transcript.
- Docker lanes get no network unless their challenge has a live instance.

### M0: the console mock

- `flightdeck mock`: the console on scripted data (fleet view and focus view, alerts, every
  intervention), with `--screenshot` for headless SVGs.
