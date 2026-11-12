# Changelog

What changed for players, newest first. Milestones are in [docs/ROADMAP.md](docs/ROADMAP.md).

## Unreleased

### Sharing what you ran

- `flightdeck share RUN_DIR` prints a run's flight card: your setup and models, solves by
  category, time, spend by model, how often you stepped in, and whether the run was hands-on,
  approve-only or hands-off. It holds no flag and no challenge name or text, and sends nothing:
  you paste it where you choose. A run now records its setup in `setup.json` in its folder.
- A leaderboard of the events flightdeck was used in, `docs/LEADERBOARD.md`, with an issue form
  to add yours, and an issue form for flight cards.

### Autopilot

- `flightdeck play --autopilot` (and `practice`), or `[autopilot] engage = true`: flightdeck
  runs the event by rule while you are away, never looser than the event's rules and your
  config. It escalates a stalled lane, kills a looping one, redirects a lane that ignores the
  hint, declines a lane's own budget request and sends unsolved challenges round again on the
  next model up. It approves nothing and submits nothing itself. Before lanes start, `play`
  says what it will and will not do under this run's policies (#13).
- Autopilot needs a run budget (`--budget-dollars`, `--budget-tokens`, or `budget_dollars` and
  `budget_tokens` under `[autopilot]`) and the Docker runtime; without them `play` does not
  start and says which is missing. At the budget it holds the queue, pauses the lanes and
  disengages (#13).
- Under autopilot a flag that would spend a challenge's last counted try waits for you, with
  `submit_limited = "auto"` too, and a request a model declined is never sent on to another
  model: Anthropic's server-side refusal fallback is off while autopilot has the run (#13).
- Autopilot disengages, holding the queue and saying why, when the model API fails for every
  lane, when CTFd keeps failing, does not judge a flag or answers with a web page for a person
  (a login page, a CAPTCHA), and at the event's end. `/autopilot off` takes the controls back,
  `/autopilot on` engages it again, and the header says `AUTOPILOT` while it is engaged (#13).
- Event profiles: `[event] start` and `end` (ISO 8601 times with a zone). Autopilot waits for
  the start before it pulls anything and stops the run at the end (#13).
- The post-flight report has an Autopilot section (its interventions by rule, each disengage
  and why), and the report, the scorecard and the flight card count only your own
  interventions; the card says `autopilot: engaged, N interventions by rule` (#13).
- `flightdeck mock --scenario autopilot` shows autopilot on fake data: rules firing, then a
  disengage at the run budget (#13).

### Headless runs and notifications

- `flightdeck play --headless` (and `practice --headless`) plays a board with no console, by
  the same rules: an approval waits and nothing is approved, since nobody is watching. It stops
  on SIGTERM, Ctrl-C or a hang-up as quitting does (exit status 128 plus the signal), ends on
  its own once nothing is left to do, and names each flag left waiting as it exits (#24).
- Every run, with the console too, keeps `status.json` in its run folder: the lanes, what
  needs you, the queue, spend and solves, replaced whole at each write, so a script, tmux or a
  phone over SSH never reads half a file. The guide lists its fields (#24).
- An opt-in notification webhook: `[notify] webhook_env` names the variable that holds its URL
  (never the URL itself: it is a secret, kept out of logs, errors and the run folder), and
  flightdeck POSTs a small JSON message when a flag is accepted, a lane needs you, or no more
  lanes start. A flag's value is never sent; the guide lists every field (#24).

### Solvers (L1)

- Categories: the long names boards use (Reverse Engineering, Binary Exploitation, Web
  Exploitation, Miscellaneous, Digital Forensics and the like, in any case, joined by spaces,
  `-` or `_`) now become the short codes `rev`, `pwn`, `web`, `misc` and `for`, so L1 routes
  reach those challenges, the board sorts them by code and build mode routes a new engine by
  category (#4).
- `flightdeck gaps --pack PACK`: each gap on the board now ends with its
  `flightdeck build gap CHALLENGE_DIR --pack PACK` command, in `gaps.md`, in the printed
  summary and in `gaps.json`, the paths filled in and shell-quoted, ready to paste (#19).

- Coding-agent lanes (`--agent`) run your L1 pack too, before their CLI is started and in
  Docker when lanes run there. A flag an engine finds waits for you or goes out by the same
  rules as in flightdeck's own lanes, no CLI runs while it waits (none at all when it solves
  the challenge), and the CLI's opening brief says what the engines found, as data (#26).

### The console and lanes

- `A` in the fleet (or `/approve all`) approves every flag that waits for a plain yes in one
  action: a prompt lists each flag by lane and challenge, and `y` approves them, each as `a`
  would. The flags of one challenge still go to the platform one at a time, a flag known wrong
  is never sent, and a challenge whose tries the platform counts, a hand submit, more budget
  and the live box are left for their own answer, each named (#30).
- `x` in the fleet (or `/dismiss`) takes down a lane's alert about its course without touching
  the lane. The alert stays quiet for the lane's next 3 turns, as an answered one does, and the
  run log has it as your action; `flightdeck report` counts it as dismissed, not answered (#30).
- The fleet's key line has `A approve all` and `x dismiss`, so it shows every key from 173
  columns (182 in team mode); narrower, it leaves out focus and sort first, as before (#30).
- At 64 columns or fewer the console has a compact layout, for a phone over SSH: the header
  keeps what needs you and the run's dollars, each lane's row has its alert, state and cost,
  the line under the list wraps the reason and puts one answer on a row, and a lane opens with
  what it needs above its transcript (no files pane). `flightdeck doctor` says when your
  terminal gets it, and `flightdeck mock --screenshot` saves it at 56x40 (#28).
- A model API that keeps failing with a rate limit, a 5xx or an overload now holds the queue
  once two lanes in a row end on it, instead of parking challenge after challenge; `/unhold`
  puts the challenges the outage parked back in front of the queue (#2).
- If the console itself fails, `play` and `practice` now stop the run the way quitting does
  (lanes stopped, workspaces closed, your live-box holds freed in the team folder), print the
  usual exit lines and exit with status 1 (#9).
- `play` on a board without answers (a CTFd event, say) ends with one line that says what the
  run spent: its tokens and dollars, "at least" when some spend had no price (#16).
- The help screen (`?`) explains the `sending` chip, `queue held` in the header, and the `+`
  and `…` after a lane's dollars, and its board legend says which `…` is which (#17).
- Codex lanes: a take-over that lands during a file edit or a tool step opens its shell only
  once that step is on the lane, so your first edit is never credited to the agent (#21).

- A lane's transcript keeps every tool call of a turn, each with up to 40 lines of its output,
  where it kept the first call and 3 lines; a writeup draft shows them all, 20 lines of output
  each, and finds the flag in any of them. The console's steps and the alerts that count them
  are as before (#15).

### Safety

- A Docker lane that may reach its challenge's instance now reaches that instance and nothing
  else: each host and port in the challenge's `urls`, through an internal Docker network and a
  small proxy per host, never Docker's bridge network. A coding-agent lane (`--agent`) reaches
  its CLI's API (`api.anthropic.com` or `api.openai.com`) the same way, and L1 solvers that
  run online get the same fence (#14).
- In such a lane an instance given by IP address or as `localhost` is reached as
  `instance-10-0-0-5` or `instance-localhost`, on the same ports; the lane's brief says so.
  UDP, ping and ports that `urls` does not list go nowhere: the guide's "Docker or host" lists
  what the fence does not do (#14).
- A lane whose fence cannot be built (no `python3` in the lane image, a Docker Engine that
  cannot make an internal network without a gateway, no room for another network) does not
  start, or stays without a network, and says why. It is never put on the bridge network (#14).
- `flightdeck doctor` lists the networks and proxy containers a killed run left, and
  `doctor --clean` and the next `play` remove them (#14).
- A lane of flightdeck's own loop no longer sends its model the keys flightdeck holds: every
  value in your keys file, the `[api]` and `[fallback]` keys and the CTFd token become `[NAME]`
  in what a lane's tool calls return, before the model, the console, the transcript or the run
  log has them, as coding-agent lanes already did. On `--host` this is still cleanup, not a
  fence, and a keys file that cannot be read now stops such a run before it starts (#8).

### Models

- `[api] effort` sets the Anthropic effort of each ladder model
  (`effort = { "claude-opus-5-5" = "high" }`): lanes send it, a model with no entry runs at
  Anthropic's default, a model or level the API would refuse is a config error that names the
  key, and it is not sent to the `[fallback]` API (the lane says so when it moves) (#27).

- `flightdeck eval-local --repeat N` runs each engine N times over the same cases and shows
  each run's score, the mean and the range for every job, so the spread between runs is there
  to see. A paid engine is announced as its calls x N (#11).
- `flightdeck eval-local --cases FILE` checks a case file of your own before anything is
  scored or sent (hosts under `.test` only, no key material) and names the file and the line
  of a bad case. The scorecard's second line says which case set its figures come from and
  how many runs, and `docs/MODELS.md` says the same of each per-job figure (#22).
- `flightdeck models` finds AMD and Intel GPUs on Linux and names them. It has no measured
  results for them yet, so it says so, sizes its advice as for a machine with no GPU, and
  points at `--gpu-memory` and the model results form (#25).

### Commands and docs

- `flightdeck report latest` (and `writeups`, `gaps`, `score`, `share`): `latest` means the
  newest run in your config's `[run] dir`, by when the run started; the command names the
  folder it took, and a folder really named `latest` still wins (#20).
- Install with Homebrew or apt, from this release on:
  `brew install mfisher14/tap/ctf-flightdeck`, or the `.deb` for amd64 or arm64 on the GitHub
  release (`sudo apt install ./ctf-flightdeck_X.Y.Z_amd64.deb`). The `.deb` brings its own
  Python 3.12 under `/opt/ctf-flightdeck`, since Debian 12 has 3.11. There is no apt
  repository yet, so `apt upgrade` does not find a new release (#29).
- For contributors: CI now runs the Docker tests on Linux and fails if one was skipped
  (`FLIGHTDECK_REQUIRE_DOCKER=1`), and a second job builds the lane image and runs a Python L1
  engine in it (`FLIGHTDECK_REQUIRE_LANE_IMAGE=1`) (#7).
- The README is a short front page. What it held is the player's guide, `docs/GUIDE.md`.
  `llms.txt` maps the docs for AI agents.

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
- `[lanes] submit_limited = "auto"` lets auto submit spend a challenge's counted tries without
  you, the last one included. It is off by default: a wrong flag can use up the tries for your
  whole team. `flightdeck preflight` and the start of a run say when it is on.
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

### Commands and docs

- `flightdeck preflight` describes each policy as `play` follows it, and refuses an event
  profile whose agents policy is `manual` or `off`, as `play` does. "preflight: ok" means
  `play` will start. Its token line reads your keys file as well as the environment.
- `flightdeck init` says what the host runtime means where it asks for the runtime, and
  `flightdeck doctor` warns when your config runs lanes on the host: lanes run as you, and can
  read your files and keys.
- `flightdeck writeups`, `score` and `build gap` answer a path that starts with `~` for a user
  that does not exist with one line, not a traceback (#18; thanks to bfs2021 for the fix).
- `flightdeck models ID` prints `timeout = 600` with a local model's `[api]` lines, as `init`
  writes it.
- `flightdeck --help` groups the commands as Set up, Play, Before and during an event, After a
  run, and Solvers (L1); arguments are named in upper case (`RUN_DIR`, `BOARD`, `PACK`).
- The practice set's README says that a coding-agent lane (`--agent`) is always on the network,
  so it can download the reference solutions: practice with `--agent` is not honest practice.
- The README is reordered, with sections for Docker or host, the words flightdeck uses,
  coding-agent lanes, and configuration and files; its links work on PyPI. Two new guides:
  `docs/BOARDS.md` (the board folder, `challenge.json`, the event profile) and
  `docs/SOLVERS.md` (L1 packs, manifests, `l1 import`, build mode).

## 0.1.0 (2026-11-11)

The first public release. flightdeck pulls a board, runs your own no-model solvers first, starts
an agent lane per challenge on a model API or a model server on your machine, and shows every
lane in one terminal console, where you approve flags and step in when a lane goes wrong. It
plays CTFd events and team play by the event's rules, and after a run it writes a report, writeup
drafts and the list of challenges your solvers missed.

### What's in it

- **The console.** A fleet view of every lane, sorted by what needs you, and a focus view of one
  lane with its transcript, the files it changed and a chat box. One key pauses, hints,
  redirects, forks, kills, escalates or takes over a lane. `flightdeck mock` shows it on
  scripted data, with no setup.
- **Lanes.** `flightdeck play BOARD` plays a folder of challenges, each lane in its own Docker
  container or on the host, with token and dollar caps per lane. `flightdeck practice` plays 14
  small challenges that ship with flightdeck.
- **Models.** OpenRouter or any OpenAI-compatible API, the Anthropic API (with a fallback API
  and fast mode), or Ollama or an MLX server on your machine. `flightdeck models` says which
  local models fit your machine.
- **Your solvers first (L1).** A pack of your own no-model solvers runs on each challenge before
  the lane's first model call, so a solve can cost no tokens.
- **Events and teams.** `play --event event.toml` follows an event's rules stage by stage, pulls
  and submits through CTFd, and shares claims and solves with teammates through a synced folder.
- **Coding-agent lanes.** `--agent claude` or `--agent codex` runs each lane as that CLI, behind
  the same controls.
- **Alerts and the light model.** Alerts for effort out of proportion, an ignored hint, a wrong
  direction on web, loops and stalls. An optional light model can take an "ignores the hint"
  alert down.
- **After a run.** `flightdeck report`, `writeups`, `score`, `gaps` and `build`.
- **Setup.** `flightdeck init` writes a config from a few questions, `flightdeck doctor` checks
  the setup and says how to fix each problem, and `flightdeck image build` builds the lane image.

### Safety

- A Docker lane has no network unless its challenge has a live instance. Under the instance
  policy `confirm` a lane asks before it may reach the instance, and until you say yes its
  container has no network.
- When lanes run in Docker, your L1 solvers do too: each engine in a container of the lane
  image, your pack mounted read-only, with no network unless the event lets lanes reach the
  challenge's instance at once. Under `confirm`, `manual` and `off` no engine can reach the
  instance. On the host runtime engines run as you.
- A flag reaches the platform only after you approve it, or under auto submit when a lane claims
  it. Under auto submit these still wait for you: a flag found in what a text-output engine
  printed; a flag written in the challenge's own text (its description or a handout file, often a
  decoy), whether the model submits it or an L1 engine returns it, and the lane says why; and
  every flag of a challenge whose tries CTFd counts. flightdeck never spends a challenge's last
  try on its own.
- The flag format, which comes from the board or the event profile, reaches a lane as data in
  the challenge brief, never in the system prompt; coding-agent lanes read it the same way. It
  is checked wherever flightdeck loads one (a board's `board.json`, an event profile,
  `--flag-format`) and again when a run starts: one line, no control, invisible or bidirectional
  character, at most 200 characters, and a regular expression that compiles. An error names
  where the format came from and the rule it breaks.
- The take-over shell reads no startup file (in Docker too), and on the host its HOME is a new
  folder only you can read, outside the workspace, removed when you hand back. So a `.bashrc`,
  `.bash_profile` or `.inputrc` that a lane, or an archive it unpacked, planted in its workspace
  never runs as you.
- What flightdeck keeps and shows of a run has the value of anything shaped like a credential
  taken out: the run log (`events.jsonl`), lane transcripts, `flightdeck report`, writeup drafts
  (with or without `--redact`) and what the console shows of a lane. That covers an upper-case
  `NAME=value` or `NAME: value` whose name holds KEY, TOKEN, SECRET, PASSWORD, PASSWD, COOKIE or
  AUTH (a Makefile's `:=`, `::=`, `?=` and `+=` too), Authorization and Cookie header values,
  and keys with a well-known prefix (`sk-ant-`, `ghp_`, `AKIA` and the like). The name stays
  and the value becomes `[redacted]`. Flags stay whole, since hiding them is `--redact`'s job.
- Coding-agent lanes hide every secret the run holds, not only the agent's own key: each value
  in your keys file, the `[api]` and `[fallback]` keys and the CTFd token show as `[NAME]` in
  the run's events and transcripts.
- The CTFd token comes from the environment variable the event profile names and goes only to
  that CTFd.
- If flightdeck itself is killed (kill -9, a power loss), what its lanes started can keep
  running: lane containers, L1 engines, coding-agent CLIs, servers a lane left in the
  background. The next `play` or `practice` removes it before it starts, wherever the run's
  folder is (`--run-dir` included), and says what it removed; `flightdeck doctor` names it, and
  `flightdeck doctor --clean` removes it. Only what a run marked is touched (its labelled
  containers, the process groups it recorded), never another setup's.

### Known limitations

- A run cannot be resumed: quitting stops every lane and closes its workspace.
- Coding-agent lanes do not run your L1 pack, and codex reports no cost (price its models under
  `[prices]` to see dollars).
- A lane that may reach its instance gets the open bridge network: there is no allowlist per
  host.
- macOS and Linux only; Windows through WSL.

<details>
<summary>Everything in 0.1.0, by area</summary>

**The console**

- `flightdeck mock`: the console on scripted data (fleet view and focus view, alerts, every
  intervention), with `--screenshot` for headless SVGs.
- Flags wait for you: `a` or `1` submits, `d` or `0` declines. On a board that cannot check
  flags you submit by hand and say whether it was accepted.
- `t` hands you the lane's real shell (its container in Docker); exit it to hand the lane back,
  and the lane hears what you changed. Other lanes keep working meanwhile.
- `q` while lanes are open asks first and says what quitting stops, naming each flag on its way
  to CTFd (quitting leaves its answer unknown); `y` quits, `n` or `esc` stays. Quitting stops
  every lane's work at once and raises no budget alert, approval or queued start while the run
  closes. What a coding-agent CLI spent in the turn that quitting cut still counts in the
  totals, the transcripts and the scorecard.
- Closing the terminal, an SSH drop or a SIGTERM stops every lane and closes every workspace, as
  quitting does; `play` exits with 128 plus the signal's number.
- `play` and `practice` end with the run folder and the commands that read it, ready to paste
  (`flightdeck report`, `writeups` and `gaps`, plus `score` when the run's board has answers),
  and name any flag that was still waiting for your approval. A run that ends with the queue
  held says so, with why and how many challenges never started.
- When the queue is held (a model API failure every lane would hit), the header says "queue
  held" and why, never "all clear", and the status line says how to lift it: once you have fixed
  the cause, `/unhold` starts the queued lanes in the free slots. Help and the `/` menu list it,
  and the menu offers it first while the queue is held. A key or model id changed in your config
  needs a new run.
- The key line always shows `? help` and `q quit`, and keeps approve, decline and the commands
  on a narrow terminal.
- A challenge solved with the flag an L1 engine found shows as `L1·<engine>` on the board (the
  owner column, the why line, the challenge card), as every report credits it, whichever lane
  submitted the flag.
- Help and the `/` menu say what take-over and decline do in a run.

**Lanes**

- `flightdeck play BOARD`: agent lanes play a folder of challenges against an OpenAI-compatible
  API (OpenRouter by default), each lane in its own Docker container or on the host. Lanes start
  cheapest-first; `max_lanes` run at once and the rest queue.
- `flightdeck practice`: 14 small synthetic challenges that ship with flightdeck, checked by
  hash.
- A lane's brief names a TCP service with the command that reaches it: `tcp://host:port (nc
  host port)`.
- A lane whose history passes 50k prompt tokens continues in a fresh context with a compact
  summary of the lane (its plan, newest steps, files, flags and what became of them, alerts and
  your messages), so a long lane does not get more expensive with every turn. Escalation hands
  the stronger model the same summary. Both keep what your L1 solvers found, in a message that
  is capped.
- A model that answers three times in a row without calling a tool gives up, quoting what it
  last said; a flag it writes in such a reply waits for you.
- A model API failure every lane would hit (no answer, a refused key, no credits, an unknown
  model) holds the queue and says what to check; the rest of the board stays queued.
- A lane that gave up while its flag waits (for you, or for CTFd's answer) takes no more turns,
  so a hint, a new plan or an escalation is refused, saying why: fork it onto another model
  (`f`), or answer or wait for its flag.
- A flag the platform rejected, or that you declined, is never asked about or submitted again
  on that challenge, by any lane, and an escalated model hears about it.
- The search for a flag in the challenge's own text says what it left out of the handout: the
  rest of a file past 1 MB, files past 16 MB in all, a file it could not read, files past the
  first 5000.
- Every run writes an append-only `events.jsonl` and each lane's full transcript.

**Alerts**

- Effort against a challenge's points and solves, ignoring the description's hint, the wrong
  direction on web, loops and stalls. An alert you just answered stays quiet for a few turns.
- The effort alert counts cached prompt tokens at a tenth, about what they cost, so a
  coding-agent CLI that resends a large cached prefix every turn does not raise it after a few
  cheap turns.

**Cost and budgets**

- Per-lane token and dollar caps (an alert at 80%, an approval at 100%), cost from the API or
  your config's prices, cached tokens counted.
- A coding-agent CLI reports what a turn cost only when the turn ends. Until then its lane's
  cost, and the header's dollar total, end in `…` and never show a settled $0.00. A cost
  reported after the lane ended (solved or killed mid-turn) still counts for the lane, the run
  and the reports.
- A turn whose cost never came (the CLI was stopped in it, or exited) is priced from your config
  when it has a price for its tokens. Otherwise the lane's dollars become an "at least" figure
  (`$0.42+`), a dollar cap holds on what is known, and only spend with no price asks you to drop
  the cap.
- `[prices."<model>"]` may name a model of an `[agents]` ladder, so codex lanes, which report
  tokens but no cost, get dollars. `play` names the codex models with no price, and `flightdeck
  config` lists the priced ones among its prices. claude keeps its own figure.
- A budget alert for spend with no price names the model that spent it ("No price for ..."): an
  escalated lane's earlier model, or a CLI's model.
- The fleet's cost column always has room for `+` (some spend had no price) and `…` (a CLI
  turn's cost still to come). A spend under half a cent shows as $0.0007 (or <.01 in a narrow
  column), never $0.00.
- `flightdeck config` says "no dollar cap" for lanes without one.

**Your solvers first (L1)**

- L1 solver packs: your no-model solvers, each with a small manifest saying which challenges it
  fits. `flightdeck l1 import` writes the manifests for a folder of scripts without changing the
  scripts, and shows the route each script got and how to change it.
- With `[l1] pack` in the config (or `--pack`), a lane runs the engines routed to its challenge
  before its first model call. A flag one finds waits for your approval (under auto submit, an
  engine's result goes at once), so a solve can cost no tokens at all.
- `flightdeck l1 route` says why a challenge reaches no engine.
- A cancelled engine run (a lane killed, a quit) removes its copy of the challenge.

**Model APIs**

- OpenRouter, OpenAI or any OpenAI-compatible API, and the Anthropic API for flightdeck's own
  lanes: `flightdeck init --provider anthropic` writes Claude Haiku, Sonnet and Opus 5.5 with
  their prices.
- A fallback API: any config can name a `[fallback]`, and with an Anthropic key `init` offers
  OpenRouter as one when `OPENROUTER_API_KEY` is set. A lane whose calls keep failing moves
  there for the rest of its context and says so. `flightdeck doctor` checks its key.
- Before lanes start, `play` and `practice` check that each model API takes your key and serves
  every model in your ladder (the Anthropic API through its Models API). If not, they stop and
  name the closest ids the API does serve, or the key's variable, or say to start your local
  model server.
- Fast mode on the Anthropic API: `[api] fast = ["claude-opus-5-5"]` calls those ladder models
  at up to 2.5x the output speed, priced at the fast rate. A model without fast mode is refused
  with the reason. On fast mode's own rate limit a lane goes on at standard speed and says so.
- `[api]` and `[fallback]` take `timeout`, the seconds one try of a lane's call may take (180
  by default, 600 with the Anthropic API), and `max_tokens`, the most tokens a lane's reply may
  hold. Unless you set it, a server on this machine is sent 8192 (mlx_lm.server's own default is
  512, too few for a model that reasons first), the Anthropic API 16000, and any other
  OpenAI-compatible API none.

**Local models**

- `flightdeck models`: what this machine has for local models (chip, memory, NVIDIA GPUs, the
  model servers on 127.0.0.1), then, for lanes and for the light model, the models that fit and
  why, and those not offered for a role, with the reason: open-weight models on this machine
  first where they run well (Apple Silicon, an NVIDIA GPU), then the model APIs. It recommends
  and never changes a config.
- `flightdeck models ID` prints how to get a model, with the server arguments it was measured
  with, and the config lines that use it (`--json` for scripts).
- Its catalog: Qwen3.5 9B, gpt-oss 20B, Gemma 4 12B (light role only) and Phi-4-mini (measured;
  offered for no role), on Ollama and MLX, the Anthropic API and OpenRouter. It shows what a
  benchmark measured for each model on each runtime (practice challenges solved, tool calls, the
  light-role score), and a build that measured badly is not offered for that role (see
  [docs/MODELS.md](docs/MODELS.md)).
- `flightdeck init` suggests the local models that did best in that benchmark: `gpt-oss:20b`
  for lanes on Ollama, Qwen3.5 9B for lanes on MLX and as the light model (`--light ollama|mlx`).
  At a terminal the suggestion is the default answer; away from one, the message names it.
- For a server on this machine `init` writes `timeout = 600` and `max_tokens = 8192` under
  `[api]` (a local model can take minutes for one reply), and for MLX it prints the
  `mlx_lm.server` command to start, with thinking off and replies of up to 8192 tokens.
  `flightdeck doctor` says what lane calls to a server on this machine send and how long each
  try may take (`lane calls`), and compares your ladder with what the server lists.

**Light model**

- `[light]` picks the light model for small jobs, on one of five engines: `rules` (the default:
  no model), `openai` (any OpenAI-compatible server; recommended: an open-weight model on your
  own machine through Ollama or an MLX server), `anthropic`, `cactus` (Cactus Needle, a small
  on-device model, in the optional extra `pip install "ctf-flightdeck[cactus]"`, with its
  telemetry turned off; nothing uses it unless you choose it) or `decider` (a Strands Decider
  server on your machine, a decision model that picks one of the options with a calibrated
  confidence). `flightdeck init --light ollama --light-model M` writes one, and `flightdeck
  doctor` checks it.
- Its job in a run is the hint judge: an "ignores the hint" alert shows at once, and comes down
  if the light model says the lane follows the hint after all. The light model never holds up a
  lane or an alert: when it refuses, fails, times out or answers outside the options, the rules'
  answer stands and the run says so once. Its spend is counted on the lane.
- A decider's answer below `[light] threshold` (0.9 by default) is unsure, and the rules' answer
  stands. `flightdeck init --light decider` writes it and says how to start its server, and
  `flightdeck doctor` checks the server.
- A light model on a server on this machine is asked, with each request, to answer without
  thinking first (`[light] thinking`: false by default there, and written by `init --light
  ollama|mlx`): a model that reasons first spends a job's few hundred tokens reasoning and
  answers nothing. `thinking = true` sends nothing extra, and an API elsewhere gets nothing
  extra unless you set `thinking = false`. The run says when thinking is off, and `flightdeck
  doctor` says whether it is.
- `flightdeck eval-local` scores any engine against the rules on hint, judge and summary cases
  before you trust it, and `--compare` scores several side by side: accuracy, refusals and
  failures, time and cost per job. A paid API is announced first, with its number of calls (one
  per case). `--engine decider --base-url URL` (or `--compare decider@URL`) scores a decider:
  its unsure answers in a row of their own, neither right nor wrong (its accuracy is over the
  answers it was sure of), and summaries as n/a. `--thinking on|off` measures either way (by
  default as your `[light] thinking` says for that server).

**Events and teams**

- `flightdeck preflight event.toml`: what an event's rules allow, and how far flightdeck goes on
  its own at each stage (pull, L1, agents, submit, live instance). It says when nothing runs at
  the l1 stage (no `[l1]` pack) and how to set one, and that under submit `auto` only a flag a
  lane claims goes to the platform at once (a model's submit, a coding agent's `FLAG:` line, an
  L1 engine's result); any other match waits for you.
- `flightdeck play FOLDER --event event.toml`: play an event by its rules. A CTFd board is
  pulled into the folder, new waves are added as they appear, the flags you approve are
  submitted through CTFd, and your team's solves stop your lanes on those challenges.
- A TCP service is a live instance: `tcp://host:port` in a challenge's `urls`, and what a CTFd
  pull reads from connection info like `nc host port`. A docker lane on it gets the network
  (asking first under `confirm`) and its brief names it.
- A challenge CTFd lists as solved closes in solo mode too, credited as CTFd says: you, your
  team, or "you or your team" when CTFd does not say.
- Flags go to CTFd from a worker off the console, so a slow CTFd neither freezes the console nor
  holds a lane up. A lane carries on while its flag is on its way (the fleet shows `sending`),
  one flag goes at a time per challenge, and CTFd's answer counts when it comes, also after the
  lane was killed or gave up (if the challenge was solved meanwhile, the answer is only
  recorded). A flag still on its way when you quit is named on the way out, as not known to
  have been submitted.
- A pull writes CTFd's `max_attempts` into a challenge's `challenge.json`, and a wrong flag's
  "You have N tries remaining" switches the challenge to asking you (said once, as a warning).
  Each approval says how many tries are left.
- A flag on its way to CTFd that comes back to you (no verdict, or the tries are counted) waits
  on every lane that sent it and is still at work. One you declined meanwhile is not asked
  again; one you approved goes on its turn without asking twice, unless that turn would spend
  the last try. A lane that gives up while its flag is on its way calls the model no more (a
  coding-agent lane's CLI stays frozen), and the answer ends it.
- `play` says which flag format the run checks flags against, and where it came from.
- Team mode: `flightdeck team init DIR`, then `--team-dir DIR`: teammates share claims,
  live-box holds and solves through a synced folder.

**Coding-agent lanes**

- `--agent claude` or `--agent codex`: lanes are that coding-agent CLI, with its own models
  (`[agents]` in the config) and its own key or token (claude: `ANTHROPIC_API_KEY` or
  `CLAUDE_CODE_OAUTH_TOKEN`; codex: `CODEX_API_KEY`, or a saved login on the host runtime),
  behind the same controls; `flightdeck doctor --agent claude` checks it first.
- Handing a lane back after a take-over interrupts the agent before it runs again, so a step it
  chose before you took over never runs, and the take-over shell opens only once the agent's
  last command is on the lane.
- `flightdeck doctor --agent`: the `[api]` key is only a warning (agent lanes never use it), the
  lane image is probed for the CLI as `play --agent` does, and the closing line says
  `flightdeck practice --agent ...`.

**Setup**

- `flightdeck` on its own says what it is and the next step on your machine; a missing config
  points at `flightdeck init`; a path under a `~user` that does not exist is a message, not a
  traceback.
- `flightdeck init` writes a config by asking a few questions. It checks each answer as you give
  it and asks again, says first if a config is already there, names a key that is already set
  (in your environment or the keys file), takes `ollama` as the local provider and `--runtime
  docker|host`, and away from a terminal names every option it still needs in one message. Its
  errors name your config file.
- `flightdeck doctor` checks the setup and says how to fix each problem. It names the machine in
  one line and points at `flightdeck models`, and its Docker advice fits your runtime. Its
  terminal check says what your terminal's size leaves out of the console on a busy run, and
  from which size nothing is left out (147x18 for four lanes in Docker; team mode's key line
  needs 156 columns).
- `flightdeck image build` builds the lane image once.

**After a run**

- `flightdeck report RUN_DIR`: the post-flight report (where lanes stalled, which of your
  interventions helped, cost per solve), written to `report.md` in the run folder.
- `flightdeck writeups RUN_DIR`: a writeup draft per solved challenge from its lane's transcript
  (`--redact` hides the flags). `--polish MODEL` has that model tidy the prose through the API
  in your config: it spends tokens, and the model never sees the run's flags, commands or
  outputs.
- `flightdeck score RUN_DIR`: scores a past run against the board's answers, and a run on a
  board with answers ends with that scorecard.
- `flightdeck gaps RUN_DIR`: the challenges no L1 solver solved, and why; with `--pack`, which of
  your engines would reach them.
- Build mode: `flightdeck build gap CHALLENGE_DIR --pack PACK` writes a new engine stub, its
  manifest and a test that passes only when a raw handout reaches the engine and it finds the
  flag (kept as a hash); `flightdeck build check PACK` runs those tests (`[build]` extra).
- The report and the scorecard count each spend for the model that spent it (an escalated
  lane's earlier model too), and show a coding-agent CLI's own cost of its turns apart from
  spend outside a turn. A CLI turn whose cost never came leaves that model's dollars, and the
  lane's in its writeup, unknown, with the part that is known; the scorecard notes such a turn.

</details>
