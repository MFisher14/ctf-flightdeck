# Porting from ctf-tools

`~/ctf-tools` is the author's **private** solver repo. It is read-only from here. Generic pipeline code
may be copied and generalised into flightdeck; nothing event- or solver-specific may.

## May be ported (when the milestone needs it)

| Source in ~/ctf-tools | What it gives | Milestone |
|---|---|---|
| `ctf/result.py`, `docs/CONTRACTS.md` §7 | `SolverResult` contract | M2 |
| `docs/CONTRACTS.md` §6, `ctf/engines/router.py`, `ctf/engines/runner.py` | Manifest format, routing, single-engine runner | M2 |
| `ctf/triage.py` | Keyword triage ideas | M2 |
| `docs/CONTRACTS.md` §1, §4, §5, §10 | Event profile, flag format, platform adapter + submit gate, budget/ledger shapes | M1 to M2 |
| Build items B-005 (platform adapters), B-189 (event profile), B-219 (filesystem fence), B-013 (recursive unpack), B-004 (dispatcher), B-033 (budget gates) | Check `~/ctf-tools/BUILD-PLAN.md` and `git log` for whether each has merged before porting | M2 to M3 |
| `.githooks/` | Secret guard (already adapted here) | done |

## Never ported

- `solvers/` (the private L1 pack), `events/`, `analysis/`, `writeups/`, `dashboard/`, `speedrun/`
- `tools/run.py` and other event-specific runners
- Anything with tokens, IPs, team or player names, organizer evidence, or real flags

## How to port

1. Copy the file, then generalise it: remove `ctf-tools` paths, event names, `CTF_*` env assumptions.
2. Rename into `ctf_flightdeck`. Never create a top-level `ctf` package.
3. Write or adapt tests so they test behaviour here (synthetic fixtures only).
4. Name the source file in the commit message.
5. Run `python3 -I .githooks/secret_scan.py --all` before committing.
