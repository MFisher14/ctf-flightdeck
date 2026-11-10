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
