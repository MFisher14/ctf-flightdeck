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
| Data model | `core/model.py` | `Challenge`, `Lane` (state, counters, plan, a log of actions that is its transcript, artifacts, changed files, alerts, approvals), `Alert` with `Suggestion`s, `EscalationSummary`, `Event`, `DeckConfig`. |
| `Deck` | `core/deck.py` | Board, queue and lanes. Enforces `max_lanes` (paused and taken-over lanes keep their slot), the flag format and submit policy, a per-lane queue of approvals, 80%/100% caps, team-mode rules. Applies interventions and logs every change as an `Event` with a structured payload (the M1 JSONL log is the event stream). Must be called from one thread. |
| Interventions | `core/interventions.py` | `Pause`, `Resume`, `Hint`, `Redirect`, `Fork`, `Kill`, `Escalate`, `TakeOver`, `HandBack`, `Approve`, `Claim`, `Release`, `Queue`, applied with `Deck.apply()` → `Outcome`. |
| `LaneDriver` | `core/driver.py` | What does a lane's work. The deck calls `start/pause/resume/hint/redirect/escalate/approved/rejected/stop`; the driver answers each step with `Deck.report(lane_id, TurnReport)`. It starts a turn only while the lane is RUNNING. |
| Attention sort | `core/attention.py` | Needs you (most urgent first), informational, running by idle minute, paused; finished last. |
| Untrusted text | `text.py` | Everything from a challenge, lane, tool or model is drawn through `untrusted()` and never parsed as markup. |
| Console | `console/` | Route C (D16): `FleetScreen`, `FocusScreen`, the command bar and slash commands. Redraws on its own timer and on deck events, with or without a mock clock. |

M0 plugs in `mock.script.ScriptedDriver` and a manual clock (`mock.world.FakeWorld`); M1 replaces them
with an agent loop per lane behind the same `LaneDriver` protocol.

## The working slice (built in M1)

| Piece | Where | Job |
|---|---|---|
| Folder board | `platform/manual.py` | A folder of challenge folders (format below); `answers.sha256.json` checks flags by hash; without it the player submits by hand and confirms (the deck's `CONFIRM` approval). |
| Config | `config.py` | `~/.config/ctf-flightdeck/config.toml`: API base URL, the name of the key's environment variable (never the key), the model ladder, prices, lane defaults, the run folder. Unknown keys fail loudly. |
| Model client | `agent/client.py` | OpenAI-compatible chat completions over httpx; a stable `session_id` per lane for OpenRouter's sticky prompt caching; never `provider.order`; retries with backoff; usage incl. cached tokens and the reported cost. |
| Workspaces | `agent/workspace.py` | A copy of the handout per lane: on the host (an allowlisted environment, no keys) or in a container per lane (`--pull never`); snapshots and diffs of the files a lane changes; the take-over shell. |
| Tools | `agent/tools.py` | `shell`, `read_file`, `python`, `http` (only the challenge's own origins), `submit_flag`, `set_plan`; long output cut, the rest saved to a file in the workspace. |
| Agent driver | `agent/driver.py`, `agent/prompts.py` | One asyncio task per lane on the console's loop (the deck's single thread). A turn is one model call; tool results go back into the context; the deck gets a `TurnReport` per turn. A small fixed prefix, then the challenge brief (challenge text fenced as data). Escalation starts a fresh context with the deck's summary. |
| Run | `run.py` | Checks config, board, key, Docker and the image before anything starts; wires the deck, driver, event log and console; releases the board on the console's loop. |
| Event log | `eventlog.py` | Append-only `events.jsonl` per run: every deck event, flushed per line. |

Board format: a folder; each subfolder with a `challenge.json` is a challenge:
`{"name", "category", "points", "solves"?, "description"?, "files"?, "urls"?, "id"?}` (unknown keys
are an error). Optional `board.json`: `{"event", "flag_format"}`. Optional `answers.sha256.json`:
`{"<challenge id>": "<sha256 of the flag>"}`, outside the challenge folders.

What keeps challenge text from steering the harness is the harness, not the prompt: tools are fenced
to the workspace and the challenge's own URLs, lane processes never see the API key, a flag reaches
the platform only through the deck's approval (or the `auto` policy), and nothing a model writes
changes a setting.

## Agent loop principles (from measured experience)

These come from analysing about 300k agent responses across four 2026 CTFs:

- **Context size drives cost, not the model.** Most tokens are the same context re-read every turn.
  Keep each lane fresh per challenge, keep the fixed prefix small (target under 6K tokens), and
  truncate tool output (large outputs go to a file the agent can read on purpose).
- **A lane's own history grows too.** Past 50k prompt tokens (configurable) a lane continues in a
  fresh context: the same prefix and brief, so the provider's cache still hits, plus a summary of
  its work instead of every old tool output.
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
