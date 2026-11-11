# Decisions

Each entry is settled unless a later entry replaces it. Propose changes in a report; don't silently
deviate.

## 2026-11-10: founding decisions

| # | Topic | Decision |
|---|---|---|
| D1 | Repo | Separate public repo `ctf-flightdeck`. The private `~/ctf-tools` (solver pack, event data) stays private and will later depend on flightdeck. |
| D2 | Names | Distribution `ctf-flightdeck`, import `ctf_flightdeck`, command `flightdeck`. Never a plain `ctf` package (it collides with `ctf-tools`). Avoid `ctfdeck` as the project name (reads as a CTFd plugin); fine as a command alias. `ctfpilot` is taken. |
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
| D14 | Timeline | ASAP. `ctf-tools` work continues in parallel and must not block on flightdeck, or vice versa. |
| D15 | Local models | The orchestrator is code, not a model. An optional **local model role** (no API key) may serve small jobs: triage hints from descriptions, the "ignores the hint" detector, lane summaries for escalation, and media helpers (audio transcription, image description). Rules come first; the local model is never required. Candidates to evaluate in M3: Cactus (`pip install cactus-compute`, Apache-2.0, small tool-calling, transcription and vision models; no OpenAI-compatible server per its README, so it needs its own adapter; set `CACTUS_TELEMETRY=0`), and Ollama / llama.cpp / MLX (OpenAI-compatible local servers). Not in M0 or M1. |
| D16 | Console layout (2026-11-10, M0 review) | Route C: a **fleet view** (board + every lane, attention-sorted) and a **focus view** for one lane (transcript, files and diffs, chat box). One-key interventions in the fleet; a chat box and slash commands in both. Rounded panels, slanted header, alert chips, plain Unicode only. Details in CONSOLE-SPEC; the behaviours listed there under "Proposed at the M0 review" are not yet signed off. |

## Proposed in M1 (built; confirm or change them)

| # | Topic | Proposal |
|---|---|---|
| P1 | Boards that cannot check flags | A folder board without an answers file cannot tell whether a flag is right. Approving a flag then becomes "submit it yourself, then confirm": `a` = accepted (solved), `d` = rejected. |
| P2 | Decline | `d` / `0` / `/decline` says no without killing the lane: a flag is not submitted, the live box stays off limits; declining more budget stops the lane and parks the challenge. |
| P3 | Quick answers | One key answers what a lane needs: `1` approves an approval, `0` declines it; otherwise the most urgent alert's suggestions are numbered. In the focus view only while the chat box is empty. Kill and a bare fork still open their prompts. |
| P4 | Lane network | A Docker lane gets no network unless its challenge lists a live instance (`urls`), so it cannot fetch solutions or reach anything else. Finer egress rules are M2. |
| P5 | Lane image | flightdeck ships a Dockerfile (python3 and common CTF tools) and builds it only when the player runs `flightdeck image build`; it never pulls or builds an image by itself. |
| P6 | Host runtime | Host lanes run as the player: they can read the player's files and same-user processes' environments, including flightdeck's API key. flightdeck says so before every host run and recommends Docker, a VM or a separate low-limit key; it does not pretend to fence it. |
| P7 | Unpriced models | Cost comes from the API (OpenRouter reports it), else the config's price, else it is unknown. A dollar-capped lane whose cost becomes unknown asks once before carrying on without the dollar cap. |


## Proposed in M2 to M4 (built; confirm or change them)

| # | Topic | Proposal |
|---|---|---|
| P8 | L1 before lanes | With an L1 pack, a lane runs the engines routed to its challenge before its first model call; a flag one finds waits for the player like any candidate, and the model hears what they found (fenced as data). Engines run on the host, as the player, whatever the lanes' runtime: they are the player's own code. |
| P9 | Live instance policy | `auto`: lanes may reach their challenge's instance. `confirm`: a lane asks before its first model call; until the player allows it, its http tool is off and a docker lane has no network, then the container joins the bridge network (open egress, not only the instance). `off`/`manual`: never. On the host runtime only the http tool can be held back (pre-flight warns). |
| P10 | Known-wrong flags | A flag the platform rejected, or the player declined, is remembered per challenge: proposed again by any lane it raises no approval and is never submitted again, a sibling's waiting approval for it is dropped, and an escalated model hears of it. The platform's rejection outranks a decline. |
| P11 | Coding-agent CLIs | `play --agent claude|codex` runs lanes as that CLI, with its own login or key and its own model ladder (`[agents]`; claude defaults to sonnet then opus). A docker agent lane needs the CLI in its image and a network for the CLI's API, so an event whose instance policy is not `auto` refuses agent lanes. Files a CLI would read as its own configuration (CLAUDE.md, AGENTS.md, .mcp.json, .claude/, .codex/) are moved out of the workspace first: they are challenge data. A lane waiting for the player is frozen (SIGSTOP) so it spends nothing. |
| P12 | Cactus Needle | An adapter and an optional extra (`ctf-flightdeck[cactus]`), off unless asked for, its telemetry turned off. In the spike it beat keyword rules only when given the same keywords as triggers (70% against 67% on invented blurbs), so nothing uses it by default. |
| P13 | CTFd answers | CTFd's "already solved" and "locked out" are not a correct flag: the deck asks the player (and in team mode "already solved" closes the challenge at once). A flag attempt is never retried. |
| P14 | Extras | `[cactus]` (Cactus Needle) and `[build]` (pytest, for `flightdeck build check`) are optional extras, so the default install stays small. |
