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
| Config | `config.py` | `~/.config/ctf-flightdeck/config.toml`: the API (`provider` openai or anthropic, base URL, the name of the key's environment variable, never the key) and an optional `[fallback]` API with its own ladder, the model ladder, prices, lane defaults, the run folder. Unknown keys fail loudly. Keys are read from the environment, else `~/.config/ctf-flightdeck/keys.env` (`keys.py`, chmod 600). |
| Model client | `agent/client.py` | OpenAI-compatible chat completions over httpx; a stable `session_id` per lane for OpenRouter's sticky prompt caching; never `provider.order`; retries with backoff; usage incl. cached tokens and the reported cost. A message key starting with `_` is flightdeck's own and never sent. |
| Anthropic client | `agent/anthropic_client.py` | `[api] provider = "anthropic"`: the Messages API through the official `anthropic` SDK, with the model client's interface. The driver's OpenAI-style history is translated each call: the system prompt is `system` with a cache breakpoint (tools and system are the fixed prefix), the tail is cached automatically, a reply's raw content blocks (thinking included) ride on its history message and go back unchanged, tool results become one user turn. No `thinking`, `temperature` or `tool_choice` is sent; Sonnet and Opus 5.5 carry the server-side refusal fallback, and a final refusal ends the lane as "the model declined (category)". The SDK's own retries are off, so the driver's retry gate holds; the key and base URL are passed explicitly, never read from the environment by the SDK; no SDK exception is chained onto an error. |
| Fallback | `agent/fallback.py` | Optional `[fallback]`: when the primary API fails for good with a retryable error (rate limit, 5xx, overload, no answer), the lane's call goes to the fallback API with the model at the same ladder position, and the lane stays there for the rest of its context (the APIs never mix in one context); the lane's transcript says so. Escalation and the context refresh try the primary again. A 400, 401 or refusal never moves a lane. |
| Workspaces | `agent/workspace.py` | A copy of the handout per lane: on the host (an allowlisted environment, no keys) or in a container per lane (`--pull never`); snapshots and diffs of the files a lane changes; the take-over shell. |
| Tools | `agent/tools.py` | `shell`, `read_file`, `python`, `http` (only the challenge's own origins), `submit_flag`, `set_plan`; long output cut, the rest saved to a file in the workspace. |
| Agent driver | `agent/driver.py`, `agent/prompts.py` | One asyncio task per lane on the console's loop (the deck's single thread). A turn is one model call; tool results go back into the context; the deck gets a `TurnReport` per turn. A small fixed prefix, then the challenge brief (challenge text fenced as data). Escalation starts a fresh context with the deck's summary. |
| Run | `run.py`, `apicheck.py` | Checks config, board, key, Docker and the image before anything starts, then asks each model API once whether it takes the key and serves the ladder (a refused key, a model it does not serve or no server up stops the run); wires the deck, driver, event log and console; releases the board on the console's loop. |
| Event log | `eventlog.py` | Append-only `events.jsonl` per run: every deck event, flushed per line. |

Board format: a folder; each subfolder with a `challenge.json` is a challenge:
`{"name", "category", "points", "solves"?, "description"?, "files"?, "urls"?, "id"?}` (unknown keys
are an error; `urls` are the live instances: http(s) origins, the http tool's, and `tcp://host:port`
services, which the shell reaches with nc; a CTFd pull reads both from the connection info).
Optional `board.json`: `{"event", "flag_format"}`. Optional `answers.sha256.json`:
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
  `provider.order` disables sticky routing. With the Anthropic API, caching is by content: keep the
  system prompt and tools byte-identical and the history append-only within a context (that also keeps
  replayed thinking blocks valid).

## M2 to M4 in a run

| Piece | Where | Job |
|---|---|---|
| L1 packs | `l1/` | `SolverResult` (status `solved | candidate | none | unsure | blocked`, flags, evidence, cost, notes; JSON with a schema number), engine manifests (`<name>.manifest.toml`: id, entry, tools it needs, timeout, routes by category, keywords and files), the router (which engines a challenge reaches, and why), the runner (each engine in its own copy of the handout, an allowlisted environment, its own process group, a timeout), the importer (manifests for a folder of plain scripts, never touching them). `flightdeck l1 list | route | run | import`. |
| L1 stage | `agent/l1stage.py` | With `[l1] pack` (or `--pack`), a lane runs the engines routed to its challenge before its first model call. Each result is an `l1` event; a flag one finds waits for the player like any candidate; the model's context says what they found, fenced as data. Engines run on this machine whatever the lanes' runtime: they are the player's code. |
| Detectors | `detect/` | Rules first: effort against points and solves, ignoring the description's hint (a technique lexicon, `hints.toml`), wrong direction on web, loops, stalls; an optional cheap-model judge may confirm a hint signal. `detect.Watch` runs them after every turn and raises or clears alerts through the deck; an alert the player just answered stays quiet for a few turns. Every real run has one. |
| Lane summary | `core/summary.py` | What a lane did, in at most 3000 characters (plan, the newest steps, files, flags and what became of them, alerts, the player's messages). Escalation and the context refresh hand it to the model, fenced as data. |
| Live instance policy | `agent/driver.py`, `run.py` | `auto`: lanes may reach their challenge's instance. `confirm`: a lane asks first (a live-box approval); until the player allows it, its http tool is off and its container has no network, then the container joins the bridge network. `off`: never. Pre-flight sets it from the event profile. |
| Known-wrong flags | `core/deck.py` | A flag the platform rejected, or the player declined, is remembered per challenge: proposed again it raises no approval and is never submitted again, and an escalation's summary lists it. |
| Pre-flight | `preflight.py` | The event profile (`event.toml`): what the rules allow, and a policy per stage (`pull`, `l1`, `agents`, `submit`, `instance`), never looser than the rules. `flightdeck preflight` checks it. |
| CTFd | `platform/ctfd.py` | Pulls a CTFd board into a folder board (waves add new challenges), submits approved flags (`CTFdVerifier`, never retried), reads the team's solves. The token comes from the variable the profile names and goes only to that CTFd. |
| Team channel | `team.py` | Claims, live-box holds and solves shared through a synced folder (no server); everything in it is untrusted. |
| Local models | `localmodel.py`, `needle.py` | `flightdeck eval-local` scores a local OpenAI-compatible server against the rules on hint and summary jobs. `needle.py` adapts Cactus Needle (`pip install "ctf-flightdeck[cactus]"`), a small on-device model, for picking among a few named options; off unless asked for, its telemetry turned off. |
| Event runs | `run.py` | `play --event`: the profile's policies set each stage; a CTFd board is pulled before the start, new waves are released as they appear, approved flags go through `CTFdVerifier`, the team's solves stop our lanes; the team folder is mirrored and watched. Background tasks run on the console's loop and stop at shutdown. |
| Coding-agent lanes | `agent/external.py` | `play --agent claude|codex`: the same LaneDriver protocol over the CLI's own event stream (Claude Code's stream-json, Codex's exec --json); messages, pause (SIGSTOP), take-over, escalation (a fresh session on the next model) and the CLI's own cost. Files the CLI would read as its configuration are moved out of the workspace first. |
| Practice mode | `practice_mode.py` | Scores a past run against the board's answers (`flightdeck score`); replays an archived board's release timeline. |
| Post-flight | `postflight.py`, `writeup.py` | `flightdeck report RUN_DIR` (where lanes stalled, which interventions helped, cost per solve) and `flightdeck writeups RUN_DIR` (a draft per solved challenge, from its transcript). |
