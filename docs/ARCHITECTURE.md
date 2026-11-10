# Architecture (draft)

## Pipeline

```
pull → triage → unpack → L1 → assign → agents → verify → submit → record
```

Every stage has a **policy**: `auto` (harness does it), `confirm` (harness prepares it, player presses a
key), `manual` (harness tells the player what to do), `off`. Pre-flight sets policies from the event
profile and rules and refuses configs that would break a rule (no platform API → pull/submit manual; no
AI → agents off; no automation against live targets → instance access confirm or off).

## Components

| Component | Job |
|---|---|
| Platform adapter | Board, challenge download, submit. `manual` (folder) first, then `ctfd`. |
| Triage | Category, points, solves, hints in the description; decides order and lane settings. Rules, not a model. |
| Unpack | Recursive archive extraction into a scratch copy, with depth/size limits and zip-slip protection. |
| L1 runner | Routes a challenge to the player's no-model solvers, runs them sandboxed in parallel, collects `SolverResult`s. Results seed the agent lane's starting state. |
| Lane manager | Starts, queues (`max_lanes`), pauses, forks, kills lanes; Docker or host per `containerized`. |
| Agent drivers | One interface. Phase 1: internal lean loop over an OpenAI-compatible API. Later: `claude`/`codex` CLI subprocesses, ACP agents. |
| Interventions | Hint, redirect, fork, escalate, take over, approve; all recorded in the event log. |
| Detectors | Produce alerts from lane activity (see CONSOLE-SPEC). |
| Budget meter | Tokens, turns, dollars per lane and in total; enforces caps. |
| Event log | Append-only JSONL of everything; feeds post-flight. |
| Console | Textual UI over all of the above. |

## The console seam (built in M0)

The console never talks to lanes directly. It reads a `Deck` and sends it interventions:

| Piece | Where | Job |
|---|---|---|
| Data model | `core/model.py` | `Challenge`, `Lane` (state, counters, plan, actions, artifacts, alerts, pending approval), `Alert` with `Suggestion`s, `Event`, `DeckConfig`. |
| `Deck` | `core/deck.py` | Board, queue and lanes. Enforces `max_lanes` (paused and taken-over lanes keep their slot), the flag format and submit policy, 80%/100% caps, team-mode stops. Applies interventions; logs every change as an `Event`. |
| Interventions | `core/interventions.py` | `Pause`, `Resume`, `Hint`, `Redirect`, `Fork`, `Kill`, `Escalate`, `TakeOver`, `HandBack`, `Approve`, `Claim`, `Release`, applied with `Deck.apply()` → `Outcome`. |
| `LaneDriver` | `core/driver.py` | What does a lane's work. The deck calls `start/pause/resume/hint/redirect/escalate/approved/rejected/stop`; the driver answers each step with `Deck.report(lane_id, TurnReport)`. |
| Attention sort | `core/attention.py` | Alerts, then approvals, then running by idle minute, then paused; finished last. |

M0 plugs in `mock.script.ScriptedDriver` and a manual clock (`mock.world.FakeWorld`); M1 replaces them
with an agent loop per lane behind the same `LaneDriver` protocol.

## Agent loop principles (from measured experience)

These come from analysing about 300k agent responses across four 2026 CTFs:

- **Context size drives cost, not the model.** Most tokens are the same context re-read every turn.
  Keep each lane fresh per challenge, keep the fixed prefix small (target under 6K tokens), and
  truncate tool output (large outputs go to a file the agent can read on purpose).
- **Long-lived orchestrator threads are the expensive tail.** The console is the orchestrator; it is
  code, not a model holding hundreds of thousands of tokens of context.
- **Caps and stop signals pay for themselves.** One stuck lane on one low-value challenge can cost more
  than the rest of an event. Per-lane caps, stall detection and teammate-solved stops are core.
- **Prompt caching must survive routing.** With OpenRouter, use a stable `session_id` per lane; setting
  `provider.order` disables sticky routing.

## Solver contract (M2, to be ported and generalised)

`SolverResult`: status `solved | candidate | none | unsure | blocked`, flags, evidence, cost, notes;
`blocked` names what is missing. Engines take a normalised challenge (read-only handout dir plus
`challenge.json`) and declare their inputs in a manifest. In-process Python or subprocess-with-JSON.
See `PORTING.md` for the source.
