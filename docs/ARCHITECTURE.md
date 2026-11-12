# Architecture

How flightdeck is built, by subsystem. Each section has a table of its pieces, where each lives
under `src/ctf_flightdeck/` and what it does; a piece that needs more than a line has a subsection
below its table. What the console shows is in [CONSOLE-SPEC.md](CONSOLE-SPEC.md), and the decisions
the text cites (D9, P13 and the like) are in [DECISIONS.md](DECISIONS.md).

1. [Overview](#1-overview)
2. [What keeps challenge text from steering the harness](#2-what-keeps-challenge-text-from-steering-the-harness)
3. [Core](#3-core)
4. [Lanes](#4-lanes)
5. [L1](#5-l1)
6. [Platforms and events](#6-platforms-and-events)
7. [Detection and the light model](#7-detection-and-the-light-model)
8. [A run's lifecycle](#8-a-runs-lifecycle)
9. [After a run](#9-after-a-run)
10. [Cross-cutting](#10-cross-cutting)
11. [Model advice](#11-model-advice)
12. [Agent loop principles](#12-agent-loop-principles)
13. [Not built yet](#13-not-built-yet)

## 1. Overview

```
pull → order → L1 → lanes → approve and submit → record
```

Five stages have a **policy**: `pull`, `l1`, `agents`, `submit` and `instance` (whether lanes may
reach a challenge's live instance). An event profile (`event.toml`, with `play --event`) sets
them, never looser than the event's rules:

- `auto`: flightdeck does it.
- `confirm`: you say yes first. For pull, before the board is pulled (later waves are then not
  pulled); for submit, each flag; for instance, each lane, before it reaches its instance. For
  agents and l1, starting `play` is that yes.
- `manual`: you do it. Under submit `manual` flightdeck shows each flag, you submit it on the
  platform and say how it went. With agents `manual` or `off`, `play` does not start.
- `off`: nobody does it through flightdeck.

The rules set the loosest policy a stage may have: no platform automation makes pull and submit
`manual`, no AI makes agents `off`, and the rule on live targets (`allowed`, `confirm` or `off`)
sets instance. `flightdeck preflight` checks a profile against its rules and says what a run with
it will do. A run without an event profile takes submit from `[lanes] submit` (or `--submit`) and
runs the L1 pack and the lanes on its own.

The components, in one line each:

| Component | Job |
|---|---|
| Platform adapter | Board, challenge download, submit: `manual` (a folder board) and `ctfd`. |
| Order | Fewest points first, then most solves, then by name: rules, not a model. With the light model's `route` job, a lane's opening brief also carries a guess at the challenge's category, where the board names none, and the specialist family it suits; neither changes the order. |
| L1 runner | Routes a challenge to the player's no-model solvers and collects their `SolverResult`s. Each engine runs in its own copy of the handout, with an allowlisted environment, its own process group and a timeout: in a container when lanes run in Docker, as you on the host. The results go into the lane's opening context. |
| Lane manager | Starts, queues (`max_lanes`), pauses, forks, kills lanes; Docker or host per `[lanes] runtime`. |
| Agent drivers | One interface (`LaneDriver`): flightdeck's own lean loop over a model API, and the `claude` and `codex` CLIs as subprocesses. ACP agents: not built. |
| Interventions | Hint, redirect, fork, escalate, take over, approve; all recorded in the event log. |
| Detectors | Produce alerts from lane activity (see CONSOLE-SPEC). |
| Budget meter | Tokens, turns and dollars per lane and in total; token and dollar caps per lane (no cap on the run). |
| Event log | Append-only JSONL of everything; feeds post-flight. |
| Console | Textual UI over all of the above. |

## 2. What keeps challenge text from steering the harness

It is the harness, not the prompt: tools are fenced
to the workspace and the challenge's own URLs, the processes of flightdeck's own lanes are never
handed a key (a coding-agent CLI holds its own credential, which the commands it runs can read), a
flag reaches the platform only through the deck's approval (or the `auto` policy), a flag format is
checked as untrusted data wherever it is loaded (`flagformat.py`), and nothing a model writes
changes a setting.

## 3. Core

The console never talks to lanes directly. It reads a `Deck` and sends it interventions.
`flightdeck mock` plugs in `mock.script.ScriptedDriver` and a manual clock
(`mock.world.FakeWorld`); a run puts an agent loop per lane behind the same `LaneDriver` protocol.

| Piece | Where | Job |
|---|---|---|
| Data model | `core/model.py` | `Challenge` (with the tries its platform allows: `max_attempts`, `tries_left`, `limited`), `Lane` (state, counters, plan, a log of actions that is its transcript, artifacts, changed files, alerts, approvals; known and unknown dollars, a CLI turn's cost still to come), `Alert` with `Suggestion`s, `EscalationSummary`, `Event`, `DeckConfig`. |
| `Deck` | `core/deck.py` | Board, queue and lanes: it enforces the limits and the policies, applies interventions and logs every change as an event. [More](#deck). |
| Interventions | `core/interventions.py` | `Pause`, `Resume`, `Hint`, `Redirect`, `Fork`, `Kill`, `Escalate`, `TakeOver`, `HandBack`, `Approve`, `Claim`, `Release`, `Queue`, applied with `Deck.apply()` → `Outcome`. |
| `LaneDriver` | `core/driver.py` | What does a lane's work. The deck calls `start/pause/resume/hint/redirect/escalate/approved/rejected/stop`; the driver answers each step with `Deck.report(lane_id, TurnReport)`. It starts a turn only while the lane is RUNNING. `TurnReport.dollars_later` marks a coding-agent CLI's step, whose cost comes with the CLI's report at the turn's end (`turn_end`; with `unreported` and no dollars when it never came). A `Submitter` hands a flag to a platform over the network and returns at once. |
| Attention sort | `core/attention.py` | Needs you (most urgent first), informational, running by idle minute, paused; finished last. |
| Untrusted text | `text.py` | Everything from a challenge, lane, tool or model is drawn through `untrusted()` and never parsed as markup. |
| Console | `console/` | The two views of D16: `FleetScreen`, `FocusScreen`, the command bar and slash commands. Redraws on its own timer and on deck events, with or without a mock clock. Credits solves with `runrecord.Credit` over the deck's events, reading each once as the deck grows: the rule every report uses (an L1 engine's flag is `L1·<engine>`). `console/room.py` measures a terminal for `flightdeck doctor` with the console's own layout code (`fit_header`, `fleet.fit_keys`, `FLEET_ROWS`, `focus.key_room`). |
| Known-wrong flags | `core/deck.py` | A flag the platform rejected, or the player declined, is remembered per challenge: proposed again it raises no approval and is never submitted again, and an escalation's summary lists it. |

### Deck

Where: `core/deck.py`.

Board, queue and lanes. Enforces `max_lanes` (paused and taken-over lanes keep their slot), the flag
format and submit policy, a per-lane queue of approvals, 80%/100% caps, team-mode rules. Applies
interventions and logs every change as an `Event` with a structured payload (the M1 JSONL log is the
event stream). Must be called from one thread.

A failure every lane would hit holds the queue (`hold_queue()`, a warning event with `held` true)
until the player lifts it (`release_hold()`, the console's `/unhold`: refused when the queue is not
held, logged as a warning with `held` false before the lanes it lets start; reports list both among
the run's warnings).

With a submitter (a platform over the network) a flag goes out without waiting for its answer, one
at a time per challenge, and `platform_verdict()` applies the answer later, also after the lane
ended or the challenge was solved meanwhile; `sending()` names a lane's flags on their way. A flag
on its way that goes back to the player (no verdict, or the platform counts the tries) waits as an
approval on each lane that sent it and is still at work; a lane that gave up on it ends, unless no
lane at work sent it.

A challenge whose tries the platform counts (`Challenge.limited`) never gets a flag without the
player, and a flag the player approved keeps its turn after a count of tries unless it would spend
the last one. The player can opt out of that hold: with `[lanes] submit_limited = "auto"`, under
submit auto, such a challenge's claimed flags go out like any other's, the last try included
(`DeckConfig.holds`), and the run's opening notes say so.

`Deck.report` applies a spend-only report (`spend_only`: tokens, cached tokens or dollars, and
nothing else) to a lane that has ended: it counts for the lane and the run, is logged as a spend
event with the model that spent it and why, and the lane's transcript is written again; no cap is
asked about, and anything else in a late report is dropped.

## 4. Lanes

| Piece | Where | Job |
|---|---|---|
| Agent driver | `agent/driver.py`, `agent/prompts.py` | flightdeck's own loop: one asyncio task per lane, one model call per turn. [More](#agent-driver). |
| Tools | `agent/tools.py` | `shell`, `read_file`, `python`, `http` (only the challenge's own origins), `submit_flag`, `set_plan`; long output cut, the rest saved to a file in the workspace. |
| Workspaces | `agent/workspace.py` | A copy of the handout per lane, on the host or in a container, and the take-over shell. [More](#workspaces). |
| Lane summary | `core/summary.py` | What a lane did, in at most 3000 characters (plan, the newest steps, files, flags and what became of them, alerts, the player's messages). Escalation and the context refresh hand it to the model, fenced as data, after the L1 results. |
| Own text | `agent/owntext.py` | Before a flag goes out without the player, it is looked for in the challenge's own text. [More](#own-text). |
| Model client | `agent/client.py` | OpenAI-compatible chat completions over httpx. [More](#model-client). |
| Anthropic client | `agent/anthropic_client.py` | The Anthropic Messages API through the official SDK, and fast mode. [More](#anthropic-client). |
| Fallback | `agent/fallback.py` | An optional second API that a lane moves to when the first keeps failing. [More](#fallback). |
| Coding-agent lanes | `agent/external.py` | `play --agent claude\|codex`: the `LaneDriver` protocol over the CLI's own event stream. [More](#coding-agent-lanes). |

### Agent driver

Where: `agent/driver.py`, `agent/prompts.py`.

One asyncio task per lane on the console's loop (the deck's single thread). A turn is one model
call; tool results go back into the context; the deck gets a `TurnReport` per turn. A small fixed
prefix (the same text for every lane: nothing from the board), then the challenge brief (challenge
text, the flag format among it, fenced as data).

Escalation starts a fresh context with the deck's summary. Three replies in a row with no tool call
end the lane (a flag written in one waits for the player); a model API failure every lane would hit
(no answer, a refused key, an unknown model) holds the queue, saying why, before the lane ends.

A flag the model submits that the challenge's description or handout, as it came, holds is not
claimed: it waits for the player under auto too, and the model hears why; the lane says what that
search of the handout left out (past 1 MB of a file, 16 MB in all, 5000 files, or 5 seconds). A lane
that gives up while a flag of it still waits (for the player, or for the platform's answer) calls
the model no more.

### Workspaces

Where: `agent/workspace.py`.

A copy of the handout per lane: on the host (an allowlisted environment, no keys) or in a container
per lane (`--pull never`, with the run's labels); snapshots and diffs of the files a lane changes;
the take-over shell, which reads no startup file (bash `--noprofile --norc`, in Docker too) and on
the host gets a new owner-only HOME outside the workspace, removed at the hand-back or with the
workspace (readline reads `~/.inputrc` whatever bash's flags say, and the player's own HOME would
show a script the lane wrote the player's credentials). A host workspace notes the process groups it
starts in the run's process record (`leftovers.py`).

### Own text

Where: `agent/owntext.py`.

Under submit auto, before one flag a lane gives goes out without the player (a coding agent's claim,
`submit_flag`, an L1 engine's result), it is looked for in the challenge's description and in every
regular file of the handout folder the lane's copy was made from, each file read to its end and
searched as bytes (UTF-8, JSON's escapes, Latin-1, UTF-16; never base64, hex or another form a
challenge asks a solver to undo). The flag waits for the player when it is there, when the search
could not cover the whole handout, or when the flag has no bytes to look for (a lone surrogate).

`search()` never raises: a failure holds the flag and names the error. The search at a lane's start
(`planted`) stays bounded (1 MB of a file, 16 MB in all, 5000 files, 5 seconds): what it finds is
never claimed, and what it misses this search catches before anything goes out.

### Model client

Where: `agent/client.py`.

OpenAI-compatible chat completions over httpx; a stable `session_id` per lane for OpenRouter's
sticky prompt caching; never `provider.order`; retries with backoff, each try bounded by the
client's timeout (a lane's: `[api] timeout`, else 180 s); usage incl. cached tokens and the reported
cost. A message key starting with `_` is flightdeck's own and never sent. Per client, `max_tokens`
goes with every call that gives none (a lane's: `[api] max_tokens`, or 8192 to a server on this
machine, nothing to another API), and `extra_body` adds a server's own fields to every request (the
light role's thinking off); it may not set a field the client sets or never sends.

### Anthropic client

Where: `agent/anthropic_client.py`.

`[api] provider = "anthropic"`: the Messages API through the official `anthropic` SDK, with the
model client's interface. The driver's OpenAI-style history is translated each call: the system
prompt is `system` with a cache breakpoint (tools and system are the fixed prefix), the tail is
cached automatically, a reply's raw content blocks (thinking included) ride on its history message
and go back unchanged, tool results become one user turn. No `thinking`, `temperature` or
`tool_choice` is sent; Sonnet and Opus 5.5 carry the server-side refusal fallback, and a final
refusal ends the lane as "the model declined (category)".

Fast mode (`agent/fastmode.py`, facts from Anthropic's API documentation): a model in `[api] fast`
is called with `speed: "fast"` (plus the fast-mode beta for a research preview) and priced at the
fast rate unless `usage.speed` says standard; a 429 on a fast request is tried again at once at
standard speed, and that lane session stays at standard speed (switching speed invalidates the
prompt cache), with a notice on the lane.

The SDK's own retries are off, so the driver's retry gate holds; the key and base URL are passed
explicitly, never read from the environment by the SDK; no SDK exception is chained onto an error.
Each try is bounded by `[api] timeout` (else 600 s), and a call that gives no `max_tokens` sends
`[api] max_tokens` (else 16000).

### Fallback

Where: `agent/fallback.py`.

Optional `[fallback]`: when the primary API fails for good with a retryable error (rate limit, 5xx,
overload, no answer), the lane's call goes to the fallback API with the model at the same ladder
position, and the lane stays there for the rest of its context (the APIs never mix in one context);
the lane's transcript says so. Escalation and the context refresh try the primary again. A 400, 401
or refusal never moves a lane. Each API's client takes the timeout and max_tokens of its own table
(`build_client()`).

### Coding-agent lanes

Where: `agent/external.py`.

`play --agent claude|codex`: the same LaneDriver protocol over the CLI's own event stream (Claude
Code's stream-json, Codex's exec --json); messages, pause (SIGSTOP), take-over (the shell opens once
the step of the command it waited for is recorded; a hand-back's SIGINT reaches the frozen CLI
before its SIGCONT), escalation (a fresh session on the next model) and the CLI's own cost. Files
the CLI would read as its configuration are moved out of the workspace first.

The CLI gets the allowlist a lane's commands get, its own credential (from the environment or the
keys file) and nothing else of the player's; the commands the agent runs can read that credential,
in Docker too (codex is asked to keep it out of its commands' environment, but they can still reach
the codex process), and `find_agent()`'s warnings say so before lanes start.

The flag format is the board's data, in the opening brief's fence, never in claude's appended system
prompt or in the rules that open codex's first prompt. Every secret the run holds becomes `[NAME]`
in what the CLI writes, before anything is shown, logged or kept.

A CLI reports a turn's cost when the turn ends: its steps carry `dollars_later`, and its report is a
spend-only `turn_end` report, which still counts after the lane ended. claude's turn end is two
reports, the turn's cost and then what claude said, so the cost counts even when its last words
solved the lane; a step the lane's end cut off goes unreported and its tokens go with that cost. A
turn whose cost never came (`_Run.settle`: an escalation or a kill stopped the CLI in it, or it
exited) is priced at the config's price for its tokens when there is one (claude), else
`unreported`: the lane's dollars are not fully known (`Lane.unreported`), nothing is asked, and a
dollar cap holds on `known_dollars` while every unknown part is such a turn; only spend with no
price asks to drop the cap (P7).

A lane that gave up while a flag of it still waits is frozen like a waiting lane: no messages and no
new CLI until the deck ends it.

A docker lane's CLI keeps its own configuration (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`) in its
container, outside the bind-mounted `/work`: the exec wrapper makes that folder owner-only before
every start, removes a link or a file at its name without following it, refuses a folder another
user owns, and keeps it for the lane's later starts (codex resumes from it). A host lane keeps it
next to the workspace.

## 5. L1

| Piece | Where | Job |
|---|---|---|
| L1 packs | `l1/` | `SolverResult`, engine manifests, the router, the runner and the importer. [More](#l1-packs). |
| L1 stage | `agent/l1stage.py` | A lane runs the engines routed to its challenge before its first model call. [More](#l1-stage). |

### L1 packs

Where: `l1/`.

`SolverResult` (status `solved | candidate | none | unsure | blocked`, flags, evidence, cost, notes;
JSON with a schema number), engine manifests (`<name>.manifest.toml`: id, entry, tools it needs,
timeout, routes by category, keywords and files), the router (which engines a challenge reaches, and
why), the runner (each engine in its own copy of the handout, an allowlisted environment, its own
process group, a timeout), the importer (manifests for a folder of plain scripts, never touching
them). `flightdeck l1 list | route | run | import`. [SOLVERS.md](SOLVERS.md) is the guide to writing
a pack.

### L1 stage

Where: `agent/l1stage.py`.

With `[l1] pack` (or `--pack`), a lane runs the engines routed to its challenge before its first
model call. Each result is an `l1` event; a flag an engine returns as its result is claimed
(`TurnReport.claimed`), so it waits for the player under `confirm` and goes to the platform at once
under `auto` (unless the challenge's tries are counted), while a flag found in what a text engine
printed (`output = "text"`, `EngineRun.scraped`) is never claimed and waits for the player even
under auto submit, and so does an engine's own result that the challenge's own text holds (the
description, or the handout as it came, searched before the engines run; the lane names the engine);
the model's context says what they found, fenced as data, and keeps saying so after an escalation or
a refresh.

Engines run where lanes do (D17): on the host runtime on this machine, as the player; with Docker
each in a container of the lane image (`l1/container.py`), the pack and the boot script mounted
read-only, with no network unless the instance policy is auto and the challenge has an instance.

## 6. Platforms and events

| Piece | Where | Job |
|---|---|---|
| Folder board | `platform/manual.py` | A folder of challenge folders ([BOARDS.md](BOARDS.md)); `answers.sha256.json` checks flags by hash; without it the player submits by hand and confirms (the deck's `CONFIRM` approval). |
| CTFd | `platform/ctfd.py` | Pulls a CTFd board into a folder board, submits approved flags, and reads the team's solves and the tries left. [More](#ctfd). |
| Pre-flight | `preflight.py` | The event profile (`event.toml`): what the rules allow, and a policy per stage (`pull`, `l1`, `agents`, `submit`, `instance`), never looser than the rules. `flightdeck preflight` checks it. |
| Live instance policy | `agent/driver.py`, `run.py` | `auto`: lanes may reach their challenge's instance. `confirm`: a lane asks first (a live-box approval); until the player allows it, its http tool is off and its container has no network, then the container joins the bridge network. `off`: never. Pre-flight sets it from the event profile. |
| Event runs | `run.py` | `play --event`: the profile's policies, CTFd pulls and waves, submits off the console's loop, the team folder. [More](#event-runs). |
| Team channel | `team.py` | Claims, live-box holds and solves shared through a synced folder (no server); everything in it is untrusted. |

### CTFd

Where: `platform/ctfd.py`.

Pulls a CTFd board into a folder board (waves add new challenges; a challenge's limit on tries goes
into its challenge.json as `max_attempts`), submits approved flags (`CTFdVerifier.submit()`, which
returns a `Verdict` and sets nothing, so a worker thread calls it; never retried; a wrong flag's
answer carries the tries left, `Attempt.tries_left`), reads the team's solves.

The token comes from the variable the profile names and goes only to that CTFd.

Any answer that says no tries remain is `locked_out`, after one look at the challenge's details
(CTFd 3.8.9 says the same for a burst of tries within a minute: details that count fewer tries used
than the limit make it a rate limit). The tries left are read from every answer that gives them
(`Attempt.tries_left`), and each pull and wave reads the attempts used from every limited
challenge's details (`Pull.tries`; only where the challenge takes no partial answers); the deck
closes a challenge with none left and opens it again, parked, when a later pull finds tries
(`Deck.platform_tries`).

### Event runs

Where: `run.py`.

`play --event`: the profile's policies set each stage; a CTFd board is pulled before the start, new
waves are released as they appear, flags go to CTFd from one worker task off the console's loop
(`_Submits`, the deck's submitter: `CTFdVerifier.submit()` in a thread, its answer applied on the
loop through `Deck.platform_verdict`), the team's solves stop our lanes; the team folder is mirrored
and watched. Background tasks run on the console's loop and stop at shutdown; a flag still on its
way then is named on the way out, as not known to have been submitted.

Every run, with or without `--event`, ends through one path. `play` awaits the console on an event
loop of its own (`_fly()` in `cli.py`, which takes what runs between the board's release and the
shutdown) and awaits `Run.shutdown()` on that loop however the console ended: a quit, a signal, or
an exception in the console that nothing handled (`play` then exits 1). `Run.shutdown()` runs once:
the console's quit starts it, and a later call only waits for it. Then `play` closes the run and
prints its exit lines.

Board format: a folder in which each subfolder with a `challenge.json` is a challenge, with an
optional `board.json` (the event's name and flag format) and an optional `answers.sha256.json`
(each flag's sha256, outside the challenge folders). [BOARDS.md](BOARDS.md) has every key.

## 7. Detection and the light model

| Piece | Where | Job |
|---|---|---|
| Detectors | `detect/` | Rules first: effort against points and solves (cached prompt tokens weigh a tenth), ignoring the description's hint (a technique lexicon, `hints.toml`), wrong direction on web, loops, stalls; with a light model, the hint judge may take a hint alert down (below). `detect.Watch` runs them after every turn and raises or clears alerts through the deck; an alert the player just answered stays quiet for a few turns. Every real run has one. |
| Light role | `light.py`, `localmodel.py`, `localmodel_cli.py`, `needle.py` | The light model for small jobs: one interface, six jobs, five engines, and `flightdeck eval-local`. [More](#light-role). |
| Hint judge | `detect/judge.py`, `detect/watch.py`, `run.py` | With a light model, an "ignores the hint" alert comes down when the lane follows the hint after all. [More](#hint-judge). |
| First look | `agent/facts.py` | The `route` and `recon` jobs, at a lane's start. [More](#first-look). |
| Flag check | `agent/flaggate.py` | The `flagcheck` job: the light model's hold before an auto-submit. [More](#flag-check). |

### Light role

Where: `light.py`, `localmodel.py`, `localmodel_cli.py`, `needle.py`.

The light model for small jobs, `[light]`: one interface (`Light`) for six jobs on five engines. A
run gives it the jobs `[light] jobs` lists: `judge` (the hint judge, the default), `route` and
`recon` at a lane's start and `flagcheck` before an auto-submit (Hint judge, First look and Flag
check, below); `hint` (name a technique) and `summary` (summarise a lane) are measured by
eval-local and never used in a run. A
job may have an engine of its own in a `[light.<job>]` table, a whole engine spec that inherits
nothing from `[light]`, so one API's key never goes to another's server; the config refuses a job on
an engine that cannot do it (`config.JOB_ENGINES`: only `openai` and `anthropic` write a brief or
check a flag).

The engines: `rules` (the default, and every job's fallback), `openai` (an OpenAI-compatible server;
recommended: an open-weight model on this machine, which costs $0; with `[light] thinking` false,
the default for a server on this machine, each request asks for no thinking through the client's
`extra_body`: `light.THINKING_OFF`, `reasoning_effort` "none", which Ollama reads, and
`chat_template_kwargs` `enable_thinking` false, which mlx_lm.server reads), `anthropic` (effort low,
room for thinking, no server-side refusal fallback), `cactus` (Cactus Needle, `needle.py`, in a
thread of its own; `pip install "ctf-flightdeck[cactus]"`, telemetry off) and `decider` (a Strands
Decider server, `DeciderLight`: each job one `choice` question in JSON with sorted keys, sent as
application/json; untrusted text only in the state, which is sized in bytes to the 4,096-token
window with the oldest steps left out first; the answer must name an option sent, with numbers in
[0, 1] that agree; below the `[light]` threshold it is unsure and the rules' answer stands; one
request at a time; $0 on this machine).

One try per job within the `[light]` timeout; a model's answer counts only when it is exactly one of
the allowed options; a refusal, error, timeout, cut-off or empty reply, or an answer outside the
options is a named failure, and the caller uses the rules' answer.

`flightdeck eval-local` scores engines side by side on the bundled cases, one kind per job, each job
also as a run uses it (accuracy, refusals, failures, a decider's unsure answers (counted apart, and
left out of its accuracy), time and cost per job; a paid API announced first, one call per case,
three for a route case).

Its `--thinking on|off` sets an openai column's thinking; by default a column on `[light]`'s own
server takes `[light] thinking` as the config sets it, and any other column its server's default
(off on this machine, on elsewhere), and each openai column's label says which.

### Hint judge

Where: `detect/judge.py`, `detect/watch.py`, `run.py`.

With a light model in `[light]`, a run's Watch raises a rules HINT signal at once and asks the light
model in the background whether the lane follows the hinted technique; a "yes" takes the alert down
(the lane is told why) for `judge_every_turns` turns, nothing waits for it, and a failed job, or a
decider's unsure answer, leaves the rules' answer with a warning once per kind. Its spend is a SPEND
event naming the light model. The run's note on the light model says when its thinking is off. A
light model that cannot be made (a key not set, Cactus not installed) leaves the judge off with a
note; the run goes on.

### First look

Where: `agent/facts.py`.

The `route` and `recon` jobs. Once a lane's workspace is ready, flightdeck gathers facts about the
handout: each file's name, size, what `file -b` says of it (run in the lane's workspace, so in its
container under Docker; no handout file is ever run) and an excerpt of its printable strings.

`route` asks the light model which specialist family the challenge suits and, only where the board
names no category flightdeck knows, its category; the board's own category is never changed, and a
guess is shown as one (`osint?`). Whether a challenge needs a live instance stays a rule (the
board's URLs and the description), and route opens nothing. `recon` writes a first-pass brief from
the same facts.

Nothing waits: at the lane's first model call it takes what is back, as triage lines and a brief in
a fenced block of its own in the opening brief, with every match of the flag format in the brief
replaced; what is not back then is left out of the lane for good. One first look per challenge,
shared by forks. A failure, a refusal, a timeout or an answer outside the options leaves no family,
no guess and no brief, said once per kind.

### Flag check

Where: `agent/flaggate.py`.

The `flagcheck` job. Under submit auto, a flag that would go out without the player (a lane claimed
it, the challenge's own text does not hold it, the platform does not count the tries) is first shown
to the light model, which says whether it is the real flag or a stand-in. On "stand-in" the flag is
not claimed, so it waits for the player, and a note on the lane names the light model. It can only
hold: it submits nothing and releases nothing held for another reason, and under submit confirm it
checks nothing. A failure, a refusal, a timeout or an unsure answer holds nothing, said once per
kind. The lane goes on while its flag is checked.

## 8. A run's lifecycle

| Piece | Where | Job |
|---|---|---|
| Run | `run.py`, `apicheck.py` | Checks the setup before anything starts, wires the deck, driver, event log and console, and releases the board. [More](#run). |
| Event log | `eventlog.py` | Append-only `events.jsonl` per run, with credential values taken out. [More](#event-log). |
| Leftovers | `leftovers.py` | The backstop for what outlives a killed flightdeck. [More](#leftovers). |

### Run

Where: `run.py`, `apicheck.py`.

Checks config, board, key, Docker and the image before anything starts, then asks each model API
once whether it takes the key and serves the ladder (a refused key, a model it does not serve or no
server up stops the run); removes what runs whose flightdeck was killed left running
(`leftovers.sweep`), records this run's (labels on its containers, `processes.json` in its folder),
and notes the flag format it checks and where that came from; wires the deck, driver, event log and
console; releases the board on the console's loop. A coding-agent run hands the driver every secret
it holds to hide (`_held_secrets`: each keys-file value, the `[api]` and `[fallback]` keys, the CTFd
token).

### Event log

Where: `eventlog.py`.

Append-only `events.jsonl` per run: every deck event, flushed per line, with the value of anything
shaped like a credential taken out (`credentials.py`); the flags the run has named, and the fields
that name challenges, stay. Format 2 adds spend outside a turn as `spend` events; a coding-agent
CLI's step is a turn event with dollars null and `dollars_later` true, and the CLI's report of the
turn's cost a `spend` event with `turn_end` true (`unreported` true, dollars null, when it never
came). Reports credit each spend event to its `data.model`.

### Leftovers

Where: `leftovers.py`.

The backstop for what outlives a killed flightdeck. `labels()` go on every container a run starts:
the run, and the flightdeck that started it (a hash of the machine's id, the uid, the pid, its start
time, and its state folder as a hash: `$XDG_STATE_HOME/ctf-flightdeck`, else
`~/.local/state/ctf-flightdeck`).

`ProcessRecord` keeps the run folder's `processes.json`: that flightdeck, whether the run used
Docker, and its process groups on this machine with the processes seen in them and their start
times, written atomically as they change; a note in the state folder's `open-runs/` names the run
folder until the run ends cleanly, so the run is found wherever `--run-dir` put it.

`sweep()` runs before each play or practice (and removes what it finds) and in doctor (which
reports, and removes with `--clean`): it removes only containers with all of flightdeck's labels, of
this machine, user and state folder, and a recorded group only while a recorded process with the
same start time is in it and works under the run's folder. Its result says what it removed, what a
clean sweep would remove, and what it leaves alone, with why. Start times and working folders come
from /proc on Linux and the kernel (sysctl, proc_pidinfo) on macOS; elsewhere nothing is removed,
and the sweep says why.

## 9. After a run

| Piece | Where | Job |
|---|---|---|
| Post-flight | `postflight.py`, `writeup.py` | `flightdeck report` and `flightdeck writeups`. [More](#post-flight). |
| Practice mode | `practice_mode.py` | Scores a past run against the board's answers (`flightdeck score`). [More](#practice-mode). |
| Gap report | `gaps.py`, `gaps_cli.py` | `flightdeck gaps RUN_DIR`: the challenges no L1 engine solved, and why, written to `gaps.md` and `gaps.json` in the run folder; `--pack` routes each gap again offline and says which engines would reach it (nothing is run). |
| Build mode | `build.py`, `build_cli.py` | `flightdeck build gap CHALLENGE_DIR --pack PACK`: an engine stub, its manifest and a case test on a copy of the challenge; nothing is overwritten. `flightdeck build check PACK` runs the pack's case tests with pytest (the `[build]` extra) and no keys from flightdeck's environment. |

### Post-flight

Where: `postflight.py`, `writeup.py`.

`flightdeck report RUN_DIR` (where lanes stalled, which interventions helped, cost per solve; each
spend in the row of the model that spent it, a CLI's own turn costs apart from spend outside a turn)
and `flightdeck writeups RUN_DIR` (a draft per solved challenge, from its transcript, with
credentials taken out of every value it shows: `credentials.py`; both read an older run folder's log
and transcripts cleaned the same way; it writes only in `RUN_DIR/writeups/`, so the run's own log
and transcripts stay as they were written).

### Practice mode

Where: `practice_mode.py`.

Scores a past run against the board's answers (`flightdeck score`). `Release`, which puts a board on
the deck wave by wave from its `timeline.json`, is built and tested, but no command uses it: `play`
releases the whole board at the start, and `score` reads a timeline only to tell the challenges a
run had not reached from those added to the folder since. It counts a run's solves by the report's
rule (`runrecord.Credit`, `runrecord.solvers`), against the board the run played
(`practice_mode.played`); a solve marked `before_run` (the platform's, or the team folder's at the
start) is no solve during the run.

## 10. Cross-cutting

| Piece | Where | Job |
|---|---|---|
| Config | `config.py` | The config file, the keys file, and what `flightdeck init` writes. [More](#config). |
| Credentials | `credentials.py`, `transcript.py` | The second redaction layer: the value of anything shaped like a credential is taken out of what flightdeck keeps and shows. [More](#credentials). |
| Flag formats | `flagformat.py` | The one check for a flag format, at every loader (a board's `board.json`, an event profile, `--flag-format`) and again in `DeckConfig`: one line, no control, invisible or bidirectional character, at most 200 characters, a Python regular expression that compiles. An error names where the format came from and the rule, and shows the format escaped and cut short. |

### Config

Where: `config.py`.

`~/.config/ctf-flightdeck/config.toml`: the API (`provider` openai or anthropic, base URL, the name
of the key's environment variable, never the key; with anthropic, `fast`: the ladder models called
in fast mode; `timeout`: seconds per try of a lane's call; `max_tokens`: a lane's reply cap, which
`lane_max_tokens()` makes 8192 (`LOCAL_MAX_TOKENS`) for an OpenAI-compatible server on this machine
when unset, and leaves unset for any other) and an optional `[fallback]` API with its own ladder,
timeout and max_tokens (no `fast`), the model ladder, prices (for a ladder model, or for a model of
an `[agents]` ladder under the CLI's own name: codex reports no cost), lane defaults, the run
folder, and an optional `[light]` light model (engine, model, base URL, key variable, timeout,
price; the decider's confidence threshold; the openai engine's `thinking`, which `light_thinking()`
makes false for a server on this machine when unset and true for any other).

Unknown keys fail loudly. Keys are read from the environment, else
`~/.config/ctf-flightdeck/keys.env` (`keys.py`, chmod 600).

`flightdeck init` (`setup.py`) writes `timeout = 600` and `max_tokens = 8192` for a server on this
machine, suggests a ladder for Ollama and MLX and a light model for `--light ollama|mlx` (from
flightdeck's benchmark, docs/MODELS.md; never written unless the player takes it), and writes `thinking = false`
for a light model on this machine; `flightdeck doctor` names what lane calls to a server on this
machine send and wait (`lane calls`).

### Credentials

Where: `credentials.py`, `transcript.py`.

The second redaction layer, after the first (the allowlisted environment, and a coding-agent lane's
`[NAME]` for every secret the run holds). What flightdeck keeps of a run and what it shows lose the
value of anything shaped like a credential: the run log (`eventlog.py`), a lane's transcript (when
it is written), the steps a post-flight report quotes, every value a writeup draft shows, and what
the console shows of a lane.

Three shapes. An upper-case `NAME=value` or `NAME: value` whose name holds KEY, TOKEN, SECRET,
PASSWORD, PASSWD, COOKIE or AUTH, and a Makefile's `:=`, `::=`, `?=` and `+=` too. The value of an
Authorization, Proxy-Authorization or Cookie header, in any letter case; an Authorization scheme
(Bearer, Basic) stays in front, and a response's Set-Cookie stays. A key with a well-known prefix,
wherever it is: `sk-ant-`, `sk-or-`, `sk-proj-`, `ghp_`, `github_pat_`, `xoxb-` and `xoxp-` followed
by 8 or more characters, `ctfd_` and 16 or more hex digits (a CTFd token), and `AKIA` and 16
upper-case letters or digits (an AWS access key id).

The name stays and the value becomes `[redacted]`; a prefixed key keeps its prefix. The flags the
run knows stay: hiding them is `writeups --redact`'s job. Upper-case names only, since a lower-case
key or password is everyday CTF content. This cleans what is kept and shown: the lane's model had
the text as it was.

Every pattern takes a run of blanks whole (possessive quantifiers), so it runs in time linear in the
text: a transcript is written inside the deck's handling of the approval that ends its lane.

## 11. Model advice

Where: `hardware.py`, `model_catalog.py`, `models.toml`, `models_cli.py`, `ollama_context.py`.

`flightdeck models`. `hardware.py` reads the machine through an injectable `Host`: OS and
architecture, the Mac's chip, total memory, NVIDIA GPUs (nvidia-smi, found only in PATH's absolute
folders), the runtimes (Ollama's model list with sizes and the models it has loaded with the context
it gives each, an MLX server's and LM Studio's, llama-server on PATH); each probe is short, needs no
root and contacts only 127.0.0.1, and one that fails is unknown, with its reason.

`model_catalog.py` loads `models.toml` (package data), refusing unknown keys, missing fields and
duplicate ids: a local model has one build per runtime, each with its own `server_args` (MLX),
`thinking` (the `[light] thinking` its light results were measured with, when not the default),
`not_for` (the roles it is never offered for, and why), `measured` results (from `docs/MODELS.md`)
and, measured job by job, a `jobs` table on the case set `[eval]` names: such a build is offered for
each run job it did no worse at than a run with no light model (the judge and flagcheck right in a
run as often; route and recon right as often as wrong), its light line is written from the figures,
and its `[light]` lines set `jobs` to match; the Anthropic entry imports init's ladder and prices.

What fits is an estimate: the weights plus 6 GiB of context for a lane or 2 GiB for the light role,
against two thirds of unified memory on Apple Silicon, the largest NVIDIA GPU's memory, or else half
the memory on the CPU; a missing size is "cannot tell". `--memory GB` (with `--apple` or
`--gpu-memory GB`) gives the same advice for a machine described instead of this one, which is not
probed.

When the config's lanes use Ollama on this machine, it and `flightdeck doctor` (`lane context`, a
warning) say what context Ollama gives the ladder's model (its `/api/ps` for a loaded one, else an
estimate from `OLLAMA_CONTEXT_LENGTH` or the GPU memory: 4,096 under 23 GiB, 32,768 from 23, 262,144
from 47) against what a lane needs, and the fix; `[api] context` makes a lane's refresh point follow
the server's context (`config.lane_refresh_at`).

It recommends and never writes a config. `flightdeck doctor` shows the machine in one line that is
never essential.

## 12. Agent loop principles

These come from analysing about 300k agent responses across four 2026 CTFs:

- **Context size drives cost, not the model.** Most tokens are the same context re-read every turn.
  Keep each lane fresh per challenge, keep the fixed prefix small (target under 6K tokens), and
  truncate tool output (large outputs go to a file the agent can read on purpose).
- **A lane's own history grows too.** Past 50k prompt tokens (`COMPACT_AT` in agent/driver.py; sooner when
  `[api] context` says the model server gives a lane less) a lane continues in a fresh context: the
  same prefix and brief, so the provider's cache still hits, plus a summary of its work instead of
  every old tool output.
- **Long-lived orchestrator threads are the expensive tail.** The console is the orchestrator; it is
  code, not a model holding hundreds of thousands of tokens of context.
- **Caps and stop signals pay for themselves.** One stuck lane on one low-value challenge can cost more
  than the rest of an event. Per-lane caps, stall detection and teammate-solved stops are core.
- **Prompt caching must survive routing.** With OpenRouter, use a stable `session_id` per lane; setting
  `provider.order` disables sticky routing. With the Anthropic API, caching is by content: keep the
  system prompt and tools byte-identical and the history append-only within a context (that also keeps
  replayed thinking blocks valid).

## 13. Not built yet

- **An unpack stage.** Lanes and L1 engines get the handout as it came; a lane unpacks an archive
  itself, in its workspace.
- **ACP agents.** The coding-agent CLIs are `claude` and `codex` only.
- **A per-origin egress allowlist.** A Docker lane has no network, or the open bridge network once
  it may reach its instance (a coding-agent lane always has it, for its CLI's API).
- **Timeline replay in `play`.** `Release` exists (Practice mode, under After a run); `play` does not use it.
