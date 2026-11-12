# Decisions

Each entry is settled unless a later entry replaces it. Propose changes in a report; don't silently
deviate.

## 2026-11-10: founding decisions

| # | Topic | Decision |
|---|---|---|
| D1 | Repo | Separate public repo `ctf-flightdeck`. Private solver packs and event data never go in it; a private pack may depend on flightdeck, never the reverse. |
| D2 | Names | Distribution `ctf-flightdeck`, import `ctf_flightdeck`, command `flightdeck`. Never a plain `ctf` package (too generic: it collides with other CTF tooling). Avoid `ctfdeck` as the project name (reads as a CTFd plugin); fine as a command alias. `ctfpilot` is taken. |
| D3 | Language | Python 3.12+ with uv. CTF tooling and players' scripts are Python; L1 plugins load in-process. Plugins may also be subprocesses speaking JSON, so any language works. |
| D4 | Interface | Terminal UI (Textual). No web UI. |
| D5 | Agent model | Both: (a) flightdeck's own agent loop against model APIs, and (b) orchestrating external agents (claude/codex CLIs, ACP-capable agents). **Phase 1 is (a)**, via an OpenAI-compatible endpoint, tested on OpenRouter. (b) is roadmap. |
| D6 | Prototype order | M0 = clickable terminal mock with fake data, to agree on look and controls. M1 = thin working slice with real agents. |
| D7 | Solo/team | Both, chosen in config. Team mode means: never work a challenge a teammate solved, don't step on teammates' live boxes, claim challenges. |
| D8 | Lanes | Number of concurrent lanes is a config setting (`max_lanes`). Boards can drop 40+ challenges at once, so the lane list must scroll, stay compact and sort by what needs attention; overflow waits in a queue. |
| D9 | Execution | Config setting `containerized`: true runs every lane in Docker; false runs on the host (many players use a disposable VM). The choice is shown in the console header and checked in pre-flight. |
| D10 | Cost display | Per lane: tokens and turns always; dollars when using an API key with known prices. Per-lane caps. |
| D11 | Alerts | Built from the author's real intervention cues (see CONSOLE-SPEC): effort out of proportion to points, activity that ignores what the description hints at, web lanes heading the wrong way, loops, stalls, teammate solved. |
| D12 | License | MIT. Anyone may use, fork or rebuild it. |
| D13 | Release | Private until the demo works; go public at v0.1.0. |
| D14 | Timeline | ASAP. Work on private solver packs goes on in parallel and never blocks flightdeck, or the reverse. |
| D15 | Local models | The orchestrator is code, not a model. An optional **local model role** (no API key) may serve small jobs: triage hints from descriptions, the "ignores the hint" detector, lane summaries for escalation, and media helpers (audio transcription, image description). Rules come first; the local model is never required. Candidates to evaluate in M3: Cactus (`pip install cactus-compute`, Apache-2.0, small tool-calling, transcription and vision models; no OpenAI-compatible server per its README, so it needs its own adapter; set `CACTUS_TELEMETRY=0`), and Ollama / llama.cpp / MLX (OpenAI-compatible local servers). Not in M0 or M1. |
| D16 | Console layout (2026-11-10, M0 review) | Route C: a **fleet view** (board + every lane, attention-sorted) and a **focus view** for one lane (transcript, files and diffs, chat box). One-key interventions in the fleet; a chat box and slash commands in both. Rounded panels, slanted header, alert chips, plain Unicode only. Details in CONSOLE-SPEC; the behaviours listed there under "Proposed at the M0 review" are not yet signed off. |

## Proposed in M1 (built; confirmed by the player on 2026-11-11)

| # | Topic | Proposal |
|---|---|---|
| P1 | Boards that cannot check flags | A folder board without an answers file cannot tell whether a flag is right. Approving a flag then becomes "submit it yourself, then confirm": `a` = accepted (solved), `d` = rejected. |
| P2 | Decline | `d` / `0` / `/decline` says no without killing the lane: a flag is not submitted, the live box stays off limits; declining more budget stops the lane and parks the challenge. |
| P3 | Quick answers | One key answers what a lane needs: `1` approves an approval, `0` declines it; otherwise the most urgent alert's suggestions are numbered. In the focus view only while the chat box is empty. Kill and a bare fork still open their prompts. |
| P4 | Lane network | A Docker lane gets no network unless its challenge lists a live instance (`urls`), so it cannot fetch solutions or reach anything else. Finer egress rules are M2. |
| P5 | Lane image | flightdeck ships a Dockerfile (python3 and common CTF tools) and builds it only when the player runs `flightdeck image build`; it never pulls or builds an image by itself. |
| P6 | Host runtime | Host lanes run as the player: they can read the player's files and same-user processes' environments, including flightdeck's API key. flightdeck says so before every host run and recommends Docker, a VM or a separate low-limit key; it does not pretend to fence it. |
| P7 | Unpriced models | Cost comes from the API (OpenRouter reports it), else the config's price, else it is unknown. A dollar-capped lane whose cost becomes unknown asks once before carrying on without the dollar cap. **Refinement (built; accepted by the player on 2026-11-11):** only spend with no price asks. A coding-agent CLI reports a turn's cost when the turn ends, so until then the lane's dollars show as still to come, never as $0.00. A turn whose cost the CLI never reported (an escalation or a kill stopped it in the turn, or it exited) and that no config price covers leaves the lane's total not fully known, but the cap stays and holds on what is known, and the lane says so once. `[prices]` may price a model of an `[agents]` ladder (codex reports no cost), and a CLI's own figure (claude) wins over a config price. |


## Proposed in M2 to M4 (built; confirmed by the player on 2026-11-11, P8 changed: see D17)

| # | Topic | Proposal |
|---|---|---|
| P8 | L1 before lanes | With an L1 pack, a lane runs the engines routed to its challenge before its first model call; a flag one finds waits for the player like any candidate, and the model hears what they found (fenced as data). Engines run on the host, as the player, whatever the lanes' runtime: they are the player's own code. |
| P9 | Live instance policy | `auto`: lanes may reach their challenge's instance. `confirm`: a lane asks before its first model call; until the player allows it, its http tool is off and a docker lane has no network, then the container joins the bridge network (open egress, not only the instance). `off`/`manual`: never. On the host runtime only the http tool can be held back (pre-flight warns). |
| P10 | Known-wrong flags | A flag the platform rejected, or the player declined, is remembered per challenge: proposed again by any lane it raises no approval and is never submitted again, a sibling's waiting approval for it is dropped, and an escalated model hears of it. The platform's rejection outranks a decline. |
| P11 | Coding-agent CLIs | `play --agent claude|codex` runs lanes as that CLI, with its own login or key and its own model ladder (`[agents]`; claude defaults to sonnet then opus). A docker agent lane needs the CLI in its image and a network for the CLI's API, so an event whose instance policy is not `auto` refuses agent lanes. Files a CLI would read as its own configuration (CLAUDE.md, AGENTS.md, .mcp.json, .claude/, .codex/) are moved out of the workspace first: they are challenge data. A lane waiting for the player is frozen (SIGSTOP) so it spends nothing. |
| P12 | Cactus Needle | An adapter and an optional extra (`ctf-flightdeck[cactus]`), off unless asked for, its telemetry turned off. In the spike it beat keyword rules only when given the same keywords as triggers (70% against 67% on invented blurbs), so nothing uses it by default. |
| P13 | CTFd answers | CTFd's "already solved" and "locked out" are not a correct flag: the deck asks the player (and in team mode "already solved" closes the challenge at once). A flag attempt is never retried. |
| P14 | Extras | `[cactus]` (Cactus Needle) and `[build]` (pytest, for `flightdeck build check`) are optional extras, so the default install stays small. |

## 2026-11-11: decided with the player

| # | Topic | Decision |
|---|---|---|
| D17 | L1 isolation (changes P8) | When lanes run in Docker, the player's L1 solvers run in Docker too (a container per engine run, the pack mounted read-only), so a hostile handout cannot reach the player's machine through a solver's parser. On the host runtime they run as the player, as before. |
| D18 | Keys | Keys live in the environment or in `~/.config/ctf-flightdeck/keys.env` (owner-only, outside the repository); the config names each key's variable and never holds a key. A variable set in the environment wins over the file. |
| D19 | Model APIs | flightdeck's own lanes may use the Anthropic Messages API directly (the player's Anthropic key first), with an OpenAI-compatible API (OpenRouter) as the automatic fallback when the first keeps failing; a lane that falls back stays there for the rest of its current context. |
| D20 | Autopilot | **Autopilot** is the name of the mode where flightdeck runs an event end to end: scheduled pulls, L1, lanes, interventions and submits, with the player away. It comes after v0.1.0, as M5 (see ROADMAP). Fixed now: the event's rules stay the ceiling (autopilot is never looser than the profile); it never guesses a flag or spends a challenge's last try; engaging it needs a run budget; it disengages, holding the queue and raising an alert, when something needs a human; the player can always take the controls (take over, pause, kill, or switch autopilot off). The rest of its design is decided in M5. |

## Proposed with the light role (built; accepted by the player on 2026-11-11)

| # | Topic | Proposal |
|---|---|---|
| P15 | Light role (extends D15) | D15's local model role becomes the light role, `[light]`: `rules` (the default: no model), `openai` (any OpenAI-compatible server; recommended and said so in the docs, `init` and `doctor`: an open-weight model on the player's machine, which no provider classifier can stop and which costs $0), `anthropic` (an API model, which D15 did not allow), `cactus` or `decider` (a Strands Decider server on the player's machine: a decision model that writes no text and picks one of the options with a calibrated confidence). Every engine is measured with `flightdeck eval-local` against the rules before use. Its first job in a run is the hint judge. Nothing waits for it: an "ignores the hint" alert is raised at once by the rules, and a light model's "the lane follows the hint" takes it down (before, the alert was held until the judge confirmed it). A refusal, an error, a timeout, a malformed answer or one outside the options leaves the rules' answer, and the run says so once per kind; a refused request is never rerouted to another model or provider. The decider's answer below `[light] threshold` (0.9 by default) is unsure: neither an answer nor a failure, so the rules' answer stands, and eval-local counts unsure answers apart, neither right nor wrong (its accuracy is over the answers it was sure of). The judge's yes or no goes to it as a choice between two options, read against that confidence (its yes/no question type returns no confidence, and its choices are the type it is calibrated for). It gets one request at a time, as its documentation advises, and the challenge's text only in its state, never in its question. A light model that cannot be made (no key, Cactus missing) leaves the judge off with a note and never stops the run. |
| P16 | Fast mode | `[api] fast` lists the ladder models a lane calls in fast mode, on the Anthropic API only, and only models Anthropic documents fast mode for (Opus 5.5, Fable 5.2, Mythos 5.2; Opus 5 and Opus 4.8 as research previews, Opus 4.8 until 2026-11-30). A fast call is priced at the fast rate. On fast mode's own 429 the lane goes on at standard speed at once and stays there for its session (each switch invalidates the prompt cache), saying so on its transcript. |

## Proposed with the cleanup after a killed run (built; accepted by the player on 2026-11-11)

| # | Topic | Proposal |
|---|---|---|
| P17 | Leftovers of a killed flightdeck | When flightdeck itself is killed (SIGKILL, a power loss), what its lanes started can outlive it: lane containers, L1 engines, coding-agent CLIs, servers a lane left in the background. So a run marks what it starts. Its containers carry flightdeck's labels: the run, and the flightdeck that started it (a hash of the machine's id, the user id, the pid, its start time, and its state folder as a hash). Its process groups on this machine are listed in the run folder's `processes.json`, which a note in flightdeck's state folder (`~/.local/state/ctf-flightdeck/open-runs/`, under `$XDG_STATE_HOME` when that is set) names, so the run is found wherever `--run-dir` put its folder; record and note go when the run ends cleanly. `play` and `practice` remove what a run whose flightdeck is gone left running before they start, and say what they removed. `doctor` only reports it, and removes it with `--clean`: doctor is run to look at a setup, often just after something went wrong, and a leftover container may be what the player wants to look into. A recorded group is killed only while a recorded process with the same start time is still in it and works under the run's folder, so a pid the system has given out again is never signalled. Nothing unlabelled, unrecorded or labelled by another state folder is ever signalled or removed. |

## Proposed after the CTFd rehearsal (built in 0.2.0; awaiting the player)

| # | Topic | Proposal |
|---|---|---|
| P18 | Out of tries (changes P13) | P13 has the deck ask the player on CTFd's "locked out". A rehearsal against CTFd 3.8.9 showed why that is wrong: CTFd checks no more flags for the challenge, so the question "did CTFd accept it?" has no true answer, and a truthful "rejected" recorded a right flag as wrong. Proposed: an answer that says no tries remain closes the challenge as out of tries and asks nobody; the flag is recorded as unchecked, never as wrong. flightdeck asks the challenge's details first, because CTFd 3.8.9 says the same for a burst of tries within a minute, which passes (that case stays a rate limit). A later pull that finds tries again opens the challenge, parked, for the player to queue. "Already solved" stays as P13 has it. |
