# Changelog

What changed for players, newest first. Milestones are in [docs/ROADMAP.md](docs/ROADMAP.md).

## 0.2.0 (2026-11-12)

A model per small job, plus fixes from a rehearsal against a real CTFd, a security review and
the first pricing issue.

### A model per small job

- `[light] jobs` lists the jobs a run gives the light model. The default is `["judge"]`, the
  hint judge alone, as in 0.1.0. A job can have an engine of its own in a `[light.<job>]` table
  (a whole engine spec that inherits nothing from `[light]`, so one API's key never goes to
  another's server): Claude Haiku for the flag check and an open-weight model on your machine
  for the rest, say.
- `flagcheck`: under auto submit, the light model looks at a flag before it goes out without
  you. It can only hold a flag for you, never submit one, and no check outlives the run.
- `route`: at a lane's start, the challenge's category where the board names none (the board's
  own category always comes first), and the specialist family it suits.
- `recon`: a first look at the handout, added to the lane's opening brief as data in a fence of
  its own, never as instructions.
- A lane says when a challenge's description names a service (`nc host port`, say) that the
  board does not list as its instance.
- `flightdeck eval-local` scores each job the way a run uses it, with cases for route, recon
  and flagcheck. Which model did best at which job is in `docs/MODELS.md`.

### Models and your machine

- `flightdeck models` knows five more small models (Qwen3.5 0.8B, 2B and 4B, Gemma 4 E2B and
  E4B) and offers each light model only for the jobs it did no worse at than no model.
- `flightdeck models --memory GB [--apple | --gpu-memory GB]` gives the advice for a machine
  you describe instead of this one. `docs/MODELS.md` is now a guide by memory, 4 to 36 GB.
- `[api] context` (and `[fallback] context`) says how many tokens your model server gives a
  lane, so the lane's context is refreshed before it outgrows it. Ollama gives 4,096 tokens by
  default on most machines, too few for a lane: `doctor` and `models` say what context Ollama
  gives your lanes' model and how to raise it, and `init` for Ollama writes the note.
- `init` no longer suggests Phi-4-mini as a light model to measure.

### Safety

- Under auto submit, before a flag a lane gives goes out without you, flightdeck looks for it
  in the challenge's whole description and handout (a coding agent's claim, the model's
  `submit_flag` and an L1 engine's result alike). A flag found there, or one flightdeck could
  not search all of the handout for, waits for you. In 0.1.0 that search stopped at size
  limits, so a stand-in flag deep in a large handout could go out.
- Coding-agent lanes in Docker keep the CLI's own configuration in the container, outside the
  workspace: nothing a lane writes or unpacks in its workspace configures the CLI at its next
  start.

### Events

- CTFd 3.8.9 answers a flag for a challenge with no tries left as a rate limit ("You have 0
  tries remaining"). flightdeck now reads that as out of tries: the flag is never recorded as
  wrong, the challenge's lanes stop, and nothing more is sent for it. It checks the
  challenge's details first, since CTFd says the same for a burst of tries within a minute,
  which passes.
- A run knows the tries you or a teammate already used: each pull reads them from CTFd, a
  challenge with none left starts out of tries, and a later pull that finds tries again (an
  admin's change, or CTFd's timeout behaviour) opens it for you to queue.
- Under the instance policy `off`, a lane's opening brief no longer offers the live instance,
  and says the event's rules keep the lane off it.
- `flightdeck preflight`'s submit auto line says that every flag of a challenge whose tries
  the platform counts waits for you.
- `flightdeck score` counts a run's solves the way `flightdeck report` does, against the board
  the run played. A solve from before the run (on the platform, or in the team folder) is not
  a solve during it.

### Prices

- A `[prices."<model>"]` table takes `cache_write`, the rate for prompt tokens written to the
  cache; `init --provider anthropic` writes it. A cache rate left out is the input rate.
- On the Anthropic API, every attempt of a call counts on the lane's meter at the price of the
  model that ran it, including the attempts the refusal fallback ran and calls every model
  declined. `[prices]` may price the models the fallback answers with, and `play` says before
  lanes start what your config prices low or not at all.
- A reply cut short by a kill, a solve or quitting still counts what its call cost.
- Fast mode: tokens read from or written to the cache are priced with the cache multipliers on
  the fast rate. 0.1.0 priced them at the full fast input rate, which showed a fast lane at
  about twice its cost.

## 0.1.0 (2026-11-11)

The first public release: the console, agent lanes on any model API or a local model server,
coding-agent lanes (Claude Code, Codex), your own no-model solvers first, CTFd events and team
play, alerts, practice scoring, post-flight reports, writeup drafts and build mode. Everything
from M0 to M4 is below.

### Lanes and L1

- When lanes run in Docker, your L1 solvers do too: each engine in a container of the lane image,
  your pack mounted read-only, with no network unless the event lets lanes reach the challenge's
  instance at once. Under `confirm`, `manual` and `off` no engine can reach the instance. On the
  host runtime they run as before.
- A flag found in what a text-output engine printed waits for you even under auto submit.
- Escalation and the long-context refresh keep what your L1 solvers found; that message is capped.
- A model that answers three times in a row without calling a tool gives up, quoting what it last
  said; a flag it writes in such a reply waits for you.
- A model API failure every lane would hit (no answer, a refused key, no credits, an unknown
  model) holds the queue and says what to check, instead of parking the whole board.
- The flag format, which comes from the board or the event profile, is shown in the challenge
  brief as data, never in the system prompt. Coding-agent lanes (claude, codex) now read it the
  same way: it is no longer in claude's appended system prompt or in the rules that open codex's
  first prompt.
- A flag the model submits that is written in the challenge's own text (its description or a
  handout file, often a decoy) waits for you under auto submit too, and the lane is told why, as
  coding-agent lanes already did. The lane says what that search of the handout left out (the
  rest of a file past 1 MB, files past 16 MB in all, a file it could not read, files past the
  first 5000).
- An L1 engine's result that the challenge's own text holds (a stand-in flag.txt, say) waits for
  you under auto submit too; the lane says why and names the engine.
- A lane that gave up while its flag waits (for you, or for CTFd's answer) takes no more turns,
  so a hint, a new plan or an escalation is refused, saying why: fork it onto another model
  (`f`), or answer or wait for its flag.
- Coding-agent lanes: handing a lane back after a take-over interrupts the agent before it runs
  again, so a step it chose before you took over never runs, and the take-over shell opens only
  once the agent's last command is on the lane.
- A lane's brief names a TCP service with the command that reaches it: `tcp://host:port (nc host
  port)`.
- Coding-agent lanes hide every secret the run holds, not only the agent's own key: each value in
  your keys file, the `[api]` and `[fallback]` keys and the CTFd token show as `[NAME]` in the
  run's events and transcripts.
- A coding-agent CLI reports what a turn cost only when the turn ends, so its lane's cost ends in
  `…` meanwhile instead of showing a settled $0.00, and a cost reported after the lane ended
  (solved or killed mid-turn) still counts for the lane, the run and the reports. A turn whose
  cost never came (the CLI was stopped in it, or exited) is priced from your config when it has
  a price for its tokens; otherwise the lane's dollars become an "at least" figure (`$0.42+`), a
  dollar cap holds on what is known, and only spend with no price asks you to drop the cap.
- `[prices."<model>"]` may name a model of an `[agents]` ladder, so codex lanes, which report
  tokens but no cost, get dollars; `play` names the codex models with no price, and
  `flightdeck config` lists the priced ones among its prices. claude keeps its own figure.
- A budget alert for spend with no price names the model that spent it ("No price for ..."): an
  escalated lane's earlier model, or a CLI's model, rather than the lane's model at the time.
- A cancelled engine run (a lane killed, a quit) removes its copy of the challenge.
- `flightdeck l1 import` shows the route each script got and how to change it; `flightdeck l1
  route` says why a challenge reaches no engine.

### Model APIs

- The Anthropic API for flightdeck's own lanes: `flightdeck init --provider anthropic` (Claude
  Haiku, Sonnet and Opus 5.5 with their prices), with OpenRouter offered as a fallback when
  `OPENROUTER_API_KEY` is set: a lane whose calls keep failing moves there for the rest of its
  context and says so. Any config can name a `[fallback]` API; `flightdeck doctor` checks its key.
- Before anything starts, `play` and `practice` ask each model API the lanes will use whether it
  takes the key and serves the ladder's models (the Anthropic API through its Models API), and
  stop with the closest ids it does serve, or the key's variable, or "start your local model
  server". A typo in a model id no longer ends every lane at its first call.
- Fast mode on the Anthropic API: `[api] fast = ["claude-opus-5-5"]` calls those ladder models at
  up to 2.5x the output speed, priced at the fast rate. A model without fast mode is refused with
  the reason. On fast mode's own rate limit a lane goes on at standard speed and says so.
- `[api]` and `[fallback]` take `timeout`, the seconds one try of a lane's call may take (180 by
  default, 600 with the Anthropic API), and `max_tokens`, the most tokens a lane's reply may
  hold. A server on this machine gets 8192 unless you set it, instead of its own default
  (mlx_lm.server's is 512, too few for a model that reasons first); no other OpenAI-compatible
  API is sent one, and the Anthropic API gets 16000.

### Setup

- `flightdeck init` checks each answer as you give it and asks again, says first if a config is
  already there, takes `ollama` as the local provider and `--runtime docker|host`, and away from
  a terminal names every option it still needs in one message. Its errors name your config file.
- `flightdeck doctor` compares your ladder with what a local model server lists. With `--agent`,
  the `[api]` key is only a warning (agent lanes never use it), the lane image is probed for the
  CLI as `play --agent` does, and the closing line says `flightdeck practice --agent ...`. Its
  Docker advice fits your runtime.
- `flightdeck models`: what this machine has for local models (chip, memory, NVIDIA GPUs, the
  model servers on 127.0.0.1), then, for lanes and for the light model, the models that fit and
  why, and those not offered for a role, with the reason: open-weight models on this machine
  first where they run well (Apple Silicon, an NVIDIA GPU), then the model APIs.
  `flightdeck models ID` prints how to get a model, with the server arguments it was measured
  with, and the config lines that use it (`--json` for scripts). It recommends and never changes
  a config. Its catalog: Qwen3.5 9B, gpt-oss 20B, Gemma 4 12B and Phi-4-mini (light role only)
  on Ollama and MLX, the Anthropic API and OpenRouter. It shows what a benchmark measured for each
  model on each runtime (practice challenges solved, tool calls, the light-role score), and a
  build that measured badly is not offered for that role (see [docs/MODELS.md](docs/MODELS.md)).
- `flightdeck doctor` names the machine in one line and points at `flightdeck models`. Its
  terminal check says what your terminal's size leaves out of the console on a busy run, and
  from which size nothing is (147x18 for four lanes in Docker; team mode's key line needs 156
  columns); it no longer calls 100x30 fine.
- If flightdeck itself is killed (kill -9, a power loss), what its lanes started can keep
  running (lane containers, L1 engines, coding-agent CLIs, servers a lane left in the
  background). The next `play` or `practice` removes it before it starts, wherever the run's
  folder is (`--run-dir` included), and says what it removed; `flightdeck doctor` names it, and
  `flightdeck doctor --clean` removes it. Only what a run marked is touched (its labelled
  containers, the process groups it recorded), never another setup's.
- `flightdeck init` names a key that is already set (in your environment or the keys file)
  instead of asking you to add it.
- `flightdeck init` suggests the local models that did best in a benchmark on one machine:
  `gpt-oss:20b` for lanes on Ollama, Qwen3.5 9B for lanes on MLX and as the light model
  (`--light ollama|mlx`). At a terminal the suggestion is the default answer; away from one, the
  message names it. For a server on this machine it writes `timeout = 600` and
  `max_tokens = 8192` under `[api]` (a local model can take minutes for one reply), and for MLX
  it prints the `mlx_lm.server` command to start, with thinking off and replies of up to 8192
  tokens. `flightdeck doctor` says what lane calls to a server on this machine send and how long
  each try may take (`lane calls`).
- `flightdeck preflight` says when nothing runs at the l1 stage (no `[l1]` pack) and how to set
  one, and that under submit `auto` only a flag a lane claims goes to the platform at once (a
  model's submit, a coding agent's `FLAG:` line, an L1 engine's result); any other match waits
  for you.

### Events

- A TCP service is a live instance: `tcp://host:port` in a challenge's `urls`, and what a CTFd
  pull reads from connection info like `nc host port`. A docker lane on it gets the network
  (asking first under `confirm`) and its brief names it.
- A challenge CTFd lists as solved closes in solo mode too, credited as CTFd says: you, your
  team, or "you or your team" when CTFd does not say.
- Flags go to CTFd from a worker off the console, so a slow CTFd no longer freezes the console or
  holds a lane up. A lane carries on while its flag is on its way (the fleet shows `sending`),
  one flag goes at a time per challenge, and CTFd's answer counts when it comes, also after the
  lane was killed or gave up (if the challenge was solved meanwhile, the answer is only
  recorded). A flag still on its way when you quit is named on the way out, as not known to
  have been submitted.
- A challenge whose tries CTFd counts never gets a flag without you, under auto submit too. A
  pull writes CTFd's `max_attempts` into its `challenge.json`, and a wrong flag's "You have N
  tries remaining" switches the challenge to asking you (said once, as a warning). Each approval
  says how many tries are left, and flightdeck never spends the last one on its own.
- A flag on its way to CTFd that comes back to you (no verdict, or the tries are counted) waits
  on every lane that sent it and is still at work. One you declined meanwhile is not asked
  again; one you approved goes on its turn without asking twice, unless that turn would spend
  the last try. A lane that gives up while its flag is on its way calls the model no more (a
  coding-agent lane's CLI stays frozen), and the answer ends it.
- Flag formats are checked wherever flightdeck loads one (a board's `board.json`, an event
  profile, `--flag-format`) and again when a run starts: one line, no control, invisible or
  bidirectional character, at most 200 characters, and a regular expression that compiles. An
  error names where the format came from and the rule it breaks. `play` says which format the
  run checks flags against, and where it came from.

### The console

- Closing the terminal, an SSH drop or a SIGTERM during a run now stops every lane and closes
  every workspace, as quitting does (before, lane commands, containers and paused agent CLIs
  kept running); `play` exits with 128 plus the signal's number.
- `q` while lanes are open asks first and says what quitting stops; `y` quits, `n` or `esc` stays.
  On the way out, `play` names any flag that was still waiting for your approval.
- The key line always shows `? help` and `q quit`, and keeps approve, decline and the commands on
  a narrow terminal.
- Quitting stops every lane's work at once and raises no budget alert, approval or queued start
  while the run closes; what a coding-agent CLI spent in the turn quitting cut still counts in
  the totals, the transcripts and the scorecard.
- The header's dollar total ends in `…` while a coding-agent CLI's turn is under way: that turn's
  cost comes when it ends.
- The quit prompt names each flag on its way to CTFd and says quitting leaves its answer unknown.
- The run log (`events.jsonl`), `flightdeck report` and what the console shows of a lane show a
  credential's name but not its value, as transcripts and writeup drafts do; the flags the run
  knows stay whole. A report on an older run folder is cleaned the same way.
- Help and the `/` menu say what take-over and decline do in a run; `flightdeck config` says "no
  dollar cap" instead of "$no cap".
- When the queue is held (a model API failure every lane would hit), the header says "queue held"
  and why, never "all clear", and the status line says how to lift it: once you have fixed the
  cause, `/unhold` starts the queued lanes in the free slots. Help and the `/` menu list it, and
  the menu offers it first while the queue is held. A key or model id changed in your config
  needs a new run.
- A challenge solved with the flag an L1 engine found shows as `L1·<engine>` on the board (the
  owner column, the why line, the challenge card), as every report credits it, whichever lane
  submitted the flag.
- The fleet's cost column always has room for its `+` (some spend had no price) and `…` (a CLI
  turn's cost still to come); before, a cost of $10 or more lost them. A spend under half a cent
  shows as $0.0007 (or <.01 in a narrow column), never $0.00.
- Taking over a lane is safer. The shell reads no startup file (in Docker too), and on the host
  its HOME is a new folder only you can read, outside the workspace, removed when you hand back.
  A `.bashrc`, `.bash_profile` or `.inputrc` that a lane, or an archive it unpacked, planted in
  its workspace no longer runs as you.
- `play` and `practice` end with the run folder and the commands that read it, ready to paste
  (`flightdeck report`, `writeups` and `gaps`, plus `score` when the run's board has answers). A
  run that ends with the queue held says so, with why and how many challenges never started.
- The effort alert counts cached prompt tokens at a tenth, about what they cost: a coding-agent
  CLI that resends a large cached prefix every turn no longer raises it after a few cheap turns.

### Light model

- `[light]` picks the light model for small jobs: `rules` (the default: none), `openai` (any
  OpenAI-compatible server; recommended: an open-weight model on your own machine through Ollama
  or an MLX server), `anthropic` or `cactus`. `flightdeck init --light ollama --light-model M`
  writes one; `flightdeck doctor` checks it.
- Its first job in a run is the hint judge: an "ignores the hint" alert shows at once, and comes
  down if the light model says the lane follows the hint after all. The light model never holds
  up a lane or an alert: when it refuses, fails, times out or answers outside the options, the
  rules' answer stands and the run says so once. Its spend is counted on the lane.
- `flightdeck eval-local` scores any engine against the rules, and `--compare` several side by
  side: accuracy, refusals and failures, time and cost per job, on hint, judge and summary
  cases. A paid API is announced first, with its number of calls (one per case).
- A fifth light engine, `decider`: a Strands Decider server on your machine, a decision model
  that picks one of the options with a calibrated confidence. Below `[light] threshold` (0.9 by
  default) its answer is unsure and the rules' answer stands. `flightdeck init --light decider`
  writes it and says how to start its server, `flightdeck doctor` checks the server, and
  `flightdeck eval-local --engine decider --base-url URL` (or `--compare decider@URL`) scores
  it: its unsure answers in a row of their own, neither right nor wrong (its accuracy is over
  the answers it was sure of), and summaries as n/a.
- A light model on a server on this machine is asked, with each request, to answer without
  thinking first (`[light] thinking`: false by default there, and written by
  `init --light ollama|mlx`): a model that reasons first spent a job's few hundred tokens
  reasoning and answered nothing. `thinking = true` sends nothing extra, and an API elsewhere
  gets nothing extra unless you set `thinking = false`. The run says when thinking is off,
  `flightdeck doctor` says whether it is, and `flightdeck eval-local --thinking on|off` measures
  either way (by default as your `[light] thinking` says for that server).

### M4: after a run

- `flightdeck report RUN_DIR`: the post-flight report (where lanes stalled, which of your
  interventions helped, cost per solve), written to `report.md` in the run folder.
- `flightdeck writeups RUN_DIR`: a writeup draft per solved challenge from its lane's transcript
  (`--redact` hides the flags).
- `flightdeck gaps RUN_DIR`: the challenges no L1 solver solved, and why; with `--pack`, which of
  your engines would reach them now.
- Build mode: `flightdeck build gap CHALLENGE_DIR --pack PACK` writes a new engine stub, its
  manifest and a test that passes only when a raw handout reaches the engine and it finds the
  flag (kept as a hash); `flightdeck build check PACK` runs those tests (`[build]` extra).
- Writeup drafts and lane transcripts take out anything shaped like a credential, with or
  without `--redact`: an upper-case `NAME=value` or `NAME: value` whose name holds KEY, TOKEN,
  SECRET, PASSWORD, PASSWD, COOKIE or AUTH (a Makefile's `:=`, `::=`, `?=` and `+=` too),
  Authorization and Cookie header values, and keys with a well-known prefix (`sk-ant-`, `ghp_`,
  `AKIA` and the like). The name stays and the value becomes `[redacted]`; flags stay, since
  hiding them is `--redact`'s job. Drafts made from older run folders are cleaned too (the run
  folders themselves are not changed).
- Post-flight and the scorecard count each spend for the model that spent it (an escalated
  lane's earlier model too), and a coding-agent CLI's own cost of its turns is no longer called
  spend outside a turn. A CLI turn whose cost never came leaves that model's dollars, and the
  lane's in its writeup, unknown, with the part that is known; the scorecard notes such a turn
  without the advice to add a price, which could not have given it.

### M3: detectors and practice

- The course alerts are real now: effort against a challenge's points and solves, ignoring the
  description's hint, the wrong direction on web, loops and stalls. An alert you just answered
  stays quiet for a few turns.
- Escalation and the long-context refresh hand the model a compact summary of the lane: its
  plan, newest steps, files, flags and what became of them, alerts and your messages.
- A flag the platform rejected, or that you declined, is never asked about or submitted again on
  that challenge, by any lane, and an escalated model hears about it.
- Practice mode: `flightdeck score RUN_DIR` scores a past run against the board's answers, and a
  run on a board with answers ends with that scorecard.
- `flightdeck eval-local`: measure a local model (Ollama, an MLX server) against the rules on
  small jobs before trusting it. Cactus Needle, a small on-device model, is an optional extra
  (`pip install "ctf-flightdeck[cactus]"`) with its telemetry turned off; nothing uses it unless
  you ask.

### M2: bring what you have

- L1 solver packs: your no-model solvers, each with a small manifest saying which challenges it
  fits (`flightdeck l1 import` writes them for a folder of scripts, without changing the scripts).
  With `[l1] pack` in the config (or `--pack`), a lane runs the engines routed to its challenge
  before its first model call; a flag one finds waits for your approval (under auto submit, an
  engine's result goes at once), so a solve can cost no tokens at all.
- `flightdeck preflight event.toml`: what an event's rules allow, and how far flightdeck goes on
  its own at each stage (pull, L1, agents, submit, live instance).
- The live instance policy: under `confirm` a lane asks before it may reach its challenge's
  instance, and until you say yes its container has no network.
- `flightdeck play FOLDER --event event.toml`: play an event by its rules. A CTFd board is pulled
  into the folder, new waves are added as they appear, the flags you approve are submitted
  through CTFd, and your team's solves stop your lanes on those challenges. The token comes from
  the environment variable the profile names and goes only to that CTFd.
- Team mode: `flightdeck team init DIR`, then `--team-dir DIR`: teammates share claims,
  live-box holds and solves through a synced folder.
- `--agent claude` or `--agent codex`: lanes are that coding-agent CLI, with its own login and
  models (`[agents]` in the config), behind the same controls; `flightdeck doctor --agent claude`
  checks it first.

### Easier to start

- `flightdeck` on its own says what it is and the next step on your machine; a missing config
  points at `flightdeck init`; a path under a `~user` that does not exist is a message, not a
  traceback.

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
- A lane whose history passes 50k prompt tokens continues in a fresh context with a summary, so a
  long lane does not get more expensive with every turn.
- Every run writes an append-only `events.jsonl` and each lane's full transcript.
- Docker lanes get no network unless their challenge has a live instance.

### M0: the console mock

- `flightdeck mock`: the console on scripted data (fleet view and focus view, alerts, every
  intervention), with `--screenshot` for headless SVGs.
