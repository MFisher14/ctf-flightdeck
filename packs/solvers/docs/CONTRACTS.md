# Contracts

The interfaces every builder codes against. Written for B-001 (consumed by B-005, B-008, B-033, B-038,
B-186, B-187, B-189, B-219 and every Phase 1-3 unit). If a contract is wrong for your item, say so in
your report; do not fork it.

Status key: **impl** = implemented and tested in this repo; **interface** = the shape is fixed here,
the named unit implements it; **schema** = a file format, the named unit builds the tooling.

**This file is checked against the code** (`tests/test_contracts_doc.py`), both ways. Code to doc:
every public name of the modules below must appear in code (backticks or a code block) in its
section, and the CLI commands, manifest keys, profile fields, `CTF_*` variables and ledger record
fields the code uses must appear too. Doc to code: every `module.name(` call and `module.Name` the
code here writes must exist in that module, every `name=` keyword such a call passes must be a
parameter of the function, and each ledger record the core writes must have exactly
the fields its section 10 row lists. If you add, rename or remove a public function, a command or a
field, change it here in the same commit.

| # | Contract | Lives in | Status | Implemented further by |
|---|---|---|---|---|
| 1 | Event profile | `events/<slug>/event.toml`, `ctf/event.py` | impl | B-189 (scaffold, section 15), B-173 (policy fields), B-242 (`rules.sandboxed_execution`) |
| 2 | Paths | `ctf/paths.py` | impl | B-001a migrates callers |
| 3 | Environment | `ctf/env.py` | impl | B-001a migrates callers |
| 4 | Flag format | `ctf/flagfmt.py` | impl | B-001a removes every other flag regex |
| 5 | Platform adapter + submit gate | `ctf/platform/` | impl (gate, rules, adapters; B-044 batch fast path, Hall of Fame) | B-006/B-173 (checks) |
| 6 | Engine manifest, router, runner | `<module>.manifest.toml`, `ctf/engines/` | impl (B-186, B-187) | every engine |
| 7 | Solver result | `ctf/result.py` | impl | B-172 (agent vocabulary, section 46) |
| 8 | CLI | `ctf/cli/` | impl | every unit that adds a command |
| 9 | Test markers, NOT RUN report, strict mode, failure-sink guard | `ctf/testing/pytest_plugin.py`, `tests/known_failures.toml`, `tests/real/conftest.py` | impl (B-001d) | every unit that adds a test |
| 10 | Budget + ledger | `ctf/budget.py`, `ctf/ledger.py`, `ctf/quota.py` | impl (B-033 meter; ledger; B-193 usage ledger; B-171 quota meter) | B-101 (replay), B-202 (spend governors), B-214 (multi-event scheduler) |
| 11 | Layout: where new code goes | this file | — | — |
| 12 | Packs (modules loaded by path) | `ctf/packs.py` | impl (B-001b) | — |
| 13 | Live-service scope guard | `ctf/scope.py` | impl (B-001c, R-13) | every network client |
| 14 | Solver filesystem fence | `ctf/fence.py`, `ctf/fence_launch.py`, `ctf/fence_report.py`, `ctf/fence_selftest.py` | impl (B-219) | — |
| 15 | Event scaffold and agent rules | `ctf/eventscaffold.py`, `ctf/eventrules.py`, `templates/event/` | impl (B-189) | — |
| 16 | Build plan gate and pre-event hooks | `ctf/buildplan.py`, `ctf/preevent.py`, `ctf/doctor.py`, `ctf/rehearsal.py`, `ctf/fakectfd.py`, `ctf/toolbox.py`, `tools/toolbox.toml`, `ctf/rulesim.py`, `ctf/sandboxinfo.py` | impl (B-008; hooks B-039; toolbox B-142; assets/images checks B-188; B-190 blocking split, token, brief rules, usage, power, sandbox self-test) | B-003 (instances in the profile) |
| 17 | Carried CTFd path | `ctf/config.py`, `ctf/client.py`, `ctf/submit.py`, `ctf/workspace.py`, `ctf/triage.py`, `ctf/dynamic.py`, `ctf/fastlane.py`, `ctf/instances.py` | impl (carried from CSCTF) | B-006 (callers behind the submit gate), B-003 (instances) |
| 18 | Promotion record + fold-audit gate | `events/<slug>/promotion.json`, `ctf/promote.py`, `ctf/foldaudit.py` | impl (B-038) | B-197 (dated tags), B-040 (seeds) |
| 19 | Intake: parallel no-model intake per challenge | `ctf/intake/`, the `[intake]` manifest table (section 6) | impl (B-002) | B-004 (dispatcher), B-012 (auto-submit), B-017 (watcher) |
| 20 | Board watch stream | `ctf/watch.py` (docstring is the contract) | impl (B-017) | B-004, B-002, B-015 consume it |
| 21 | Question-id resolver (fail closed) | `ctf/idresolve.py`, lane `id_conventions.toml` | impl (B-010) | B-036, B-162, B-218 |
| 22 | No-model dispatcher | `ctf/dispatch.py`, `ctf/cli/dispatch.py` | impl (B-004) | B-015 claim store (section 26), B-016 (timers/reroutes, section 27) |
| 23 | Regression gate (impact selection, warm reuse, inventory) | `ctf/gate/`, `ctf/cli/gate.py`, `tests/gate.toml`, `tests/gate_baseline.toml`, `ctf/pyinterp.py`, `ctf/testing/loopback.py` | impl (B-195; B-137 ENV/fail log; B-153 lane budgets, baseline ledger, pre-arm gate, worktree venv, loopback harness) | B-196, B-197, B-253 |
| 24 | Armed Layer-1 openers | `openers/layer1.toml`, `ctf/openers/` (docstring is the contract), `ctf/cli/arm.py` | impl (B-014) | B-036 (day-one arming at pull, web opener) |
| 25 | Event solve policy | `ctf/eventpolicy.py`, `ctf/cli/policy.py` | impl (B-173) | B-154, B-205 consume it |
| 26 | Claim store solved view + solved watcher | `ctf/solved.py`, `ctf/cli/solved.py` | impl (B-015) | B-016, B-181 |
| 27 | Escalation timers and reroutes | `ctf/escalation.py`, `ctf/cli/escalate.py` | impl (B-016) | B-095 (effort ramp), B-143 (5-agent gate, section 39), B-172 (solver contract) |
| 28 | Host resource governor | `ctf/governor.py`, `ctf/diskguard.py`, `ctf/cli/governor.py` | impl (B-176) | B-214 (multi-event scheduler, section 44), wave launchers |
| 29 | Per-lane adaptation loop (lane gate, timed chaining, set pool) | `ctf/adapt/`, `ctf/cli/adapt.py` | impl (B-036) | B-174, B-195/B-253 (warm-gate cost), B-139, B-231 |
| 30 | Compaction thresholds | `ctf/compaction.py`, `ctf/cli/compaction.py` | impl (B-032) | B-200 (orchestrator restart route) |
| 31 | Ranked format catalog, corpus and property coverage matrix | `ctf/formats/` (docstrings are the contract), `ctf/formats/catalog.toml`, `ctf/cli/formats.py`, `docs/coverage/FORMATS.md` | impl (B-162; `disk` format B-221) | B-218 (accepted-format catalog), B-220..B-224 (metadata readers) |
| 32 | Warm standby agent pool | `ctf/standby.py`, `ctf/cli/standby.py` | impl (B-037; `helpers` pool and lane filter B-212) | B-212 (helper launch on STOP, section 62) |
| 33 | Per-challenge hypothesis ledger | `ctf/hypothesis.py`, `ctf/cli/hypothesis.py` | impl (B-181) | B-040 (mined mechanisms), B-182, B-203 |
| 34 | Tool-output hygiene + shared read map; repo primer, symbol index, research cache, binary-first read | `ctf/hygiene.py`, `ctf/readmap.py`, `ctf/cli/read.py`; `ctf/primer.py`, `ctf/symindex.py`, `ctf/research.py`, `ctf/binsummary.py`, `ctf/cli/{primer,symbols,research}.py` | impl (B-034, B-199) | B-035 (context trim) |
| 35 | Look-ahead completeness gate (matrix, computed tier, scale, forecast score); the daily look-ahead workflow (B-256) | `ctf/lookahead/`, `ctf/cli/lookahead.py`, `ctf/cli/lookahead_daily.py`, `workflows/day-lookahead.*` | impl (B-174, B-256) | lane readers adopt `computed.wrap`; B-227, B-216, B-225 (lane readers the gaps name) |
| 36 | Campaign state, relaunch list, resume file, scratch passes | `ctf/campaign.py`, `ctf/scratch.py` | impl (B-178) | B-177 (watchdog), B-018/B-037 (agent pools) |
| 37 | Pinned toolchain: images, assets, lane env-check, version notes, wheelhouse | `ctf/toolchain/`, `ctf/cli/toolchain.py`, `tools/images.toml`, `tools/assets.toml`, `tools/lanes.toml`, `docker/toolkit/`, `docker/sage/` | impl (B-188) | B-165 (static-RE workbench image) |
| 38 | Ask every reader before STOP on a MISSING id | `ctf/askreaders.py` (docstring is the contract), `openers/readers.toml`, `templates/ask-readers/one_field.py`, `ctf/cli/ask_readers.py` | impl (B-139) | B-216, B-225, B-224 (more readers), B-252/B-003 (the opener that calls it) |
| 39 | Brief-not-fork spawning and the per-challenge agent gate | `ctf/spawn.py`, `ctf/cli/spawn.py`, `tools/launch_gate.py` | impl (B-143) | — |
| 40 | Flag plausibility check and ranked variant set | `ctf/flagcheck.py`, `ctf/cli/flag.py` | impl (B-154) | every submitting lane |
| 41 | Shared codec graph | `ctf/codec/`, `ctf/cli/codec.py`, `solvers/common/codec_graph.py` | impl (B-163) | lane readers (unwrap, Binary, web proof decode) to adopt it |
| 42 | Arm and release-morning safety (dated tags, freeze, rollback, process fence, unwired) | `ctf/arm.py`, `ctf/cli/release.py` | impl (B-197) | B-014 openers, B-195 gate (`--mark-green`) |
| 43 | Thin orchestrator (status lines, debounced notifier, challenge-file guard, session brief) | `ctf/orch.py`, `ctf/cli/orch.py` | impl (B-200) | B-032 (restart at a context threshold) |
| 44 | Multi-event priority scheduler | `ctf/slate.py`, `ctf/cli/slate.py` | impl (B-214) | wave launchers and the dispatcher (call `Scheduler.acquire` or wrap in `ctf slate run`) |
| 45 | Handoff board | `ctf/handoff.py`, `ctf/handoff.toml`, `ctf/cli/handoff.py` | impl (B-180) | B-181 (hypothesis ledger), B-209 |
| 46 | Solver contract | `ctf/solver_contract.py`, `ctf/cli/contract.py` | impl (B-172) | B-181 (hypothesis ledger, section 33: its verified entries should feed fresh eyes), B-168 |
| 47 | Live status surface and progress files | `ctf/live.py`, `ctf/progress.py`, `ctf/cli/live.py` | impl (B-198) | every long run writes a progress file |
| 48 | Answer-format renderer | `ctf/answerfmt/` (docstrings are the contract), `ctf/cli/answer_format.py` | impl (B-232) | lane runners and readers (adoption), B-154 (flag variants) |
| 49 | Harness failover for release mornings | `ctf/failover.py`, `ctf/cli/failover.py`, `docs/runbooks/harness-failover.md` | impl (B-170; live rehearsal is a human step) | B-004/B-016 (read the active harness), B-200, B-202 |
| 50 | Shipped workflow scripts | `workflows/`, `ctf/workflows.py`, `ctf/cli/workflow.py`, `tests/wf_harness.py` | impl (B-194) | B-004 (board lanes), the Workflow tool |
| 51 | Stuck-id protocol (no-derivation detection, live re-read, agent/probe caps) | `ctf/stuck.py`, `ctf/cli/stuck.py` | impl (B-203) | B-254; consumed by submitting lanes and the dispatcher |
| 52 | Constructed-marker fallback and convention knowledge base | `solvers/common/marker_convention.py`, `solvers/common/render_candidates.py` (composition axis), `solvers/toolkits/seeds/marker/conventions.json`, `ctf/cli/marker.py` | impl (B-119, hard tail: candidates only) | the protocol engines (decoded values as fields), B-082 (raw-bytes witness grammars) |
| 53 | Set-to-delivery pairing (each set reads its own delivery) | `ctf/deliveries.py`, `ctf/openers/sets.py`, `ctf/cli/deliveries.py`; `tools/run.py` `split_sets` | impl (B-042) | the clock runner (B-252/B-003) through `split_sets`; `ctf arm` and the lane gate through `openers.run_input` |
| 54 | Runtime semantic adapters in pinned containers | `solvers/binary/runtime_trace.py`, `solvers/binary/_runtime_plans.py`, `tools/sandbox.py` (`runtime_run`), `docker/runtime/`, `tools/images.toml` | impl (B-242; the images are a human build, so no run in a real container was exercised) | IL2CPP and Flutter adapters, an intake hook (follow-ups in docs/build-log/B-242.md) |
| 55 | Disk-image boot harness and shipped-client User-Agent replay | `ctf/diskboot.py`, `ctf/clientreplay.py`, `ctf/cli/disk_boot.py`, `ctf/cli/client_replay.py`, `docker/qemu-boot/`, `docs/runbooks/disk-boot.md` | impl (B-131; the image build and every real boot are human steps) | a vision reader for the screens; B-221 (partition tables) |
| 56 | TI-Nspire documents | `solvers/toolkits/tns_nspire.py`, `tools/archive_expand.py` (the walk), `ctf/intake` (disputed flags) | impl (B-132) | engines that find flags where decoys sit (evidence kind `decoy`, section 7) |
| 57 | Discord recon | `ctf/discordrecon.py`, `ctf/discordapi.py`, `ctf/cli/discord.py`, `solvers/toolkits/osint_discord.py` | impl (B-112; the API client is tested only against a loopback fake; joining and clearance are human steps) | B-002 (intake runs the engine), B-169 (the task card) |
| 58 | Lattice and polynomial-ideal service | `solvers/common/algebra_service.py` (docstring is the contract), `solvers/common/_algebra_sage_worker.py`, `solvers/common/lattice_templates.py` | impl (B-157; a run under real Sage is a human step) | B-244 (fpylll behind `lattice_backends.reduce_lattice`), crypto engines that need BKZ or an ideal |
| 59 | Scoreboard ingestion and first-blood benchmark | `ctf/scoreboard.py`, `ctf/cli/scoreboard.py`, `ctf/platform/base.py` (`challenge_solves`) | impl (B-099, partial: no consumer reads the store yet) | lane targets and the live ledger (consumers) |
| 60 | Named jobs, launcher sessions and the end-of-event reaper (exact pid + start time) | `ctf/procid.py`, `ctf/jobs.py`, `ctf/sessions.py`, `ctf/reaper.py`, `ctf/cli/{job,session,reap}.py`, `tools/launch_gate.py` | impl (B-175; confirming a reap is the player's) | B-144 (jobs), B-191 (sanctioned helpers), R-09 launchers |
| 61 | Test and docs integrity (mutation check, fake-branch audit, collection, doc lint, known solves, new-engine audit) | `ctf/integrity/`, `ctf/cli/integrity.py`, `ctf/gate/notrun.py`, `tests/known_solves.toml`, `tests/fake_branches.toml`, `tests/collection_known.toml`, `tests/doclint_known.toml` | impl (B-196) | B-195 (the gate's selection and runner), B-036 (`regress.gate` for event cases) |
| 62 | No-model helper launch on a lane STOP (warm standby only where predicted) | `ctf/helpers.py` (docstring is the contract), `ctf/cli/helpers.py` | impl (B-212; per-lane warm/cold from measured latency is a human step) | B-036 chain (its STOPs), B-174 forecast (warm lanes), B-178 campaign (cold launch) |
| 63 | Completion-driven agent coordination (completion waits, capped lane relay, lane board) | `ctf/coord.py`, `ctf/cli/coord.py` | impl (B-239) | B-143 briefs (end with `coord done`), B-144, B-200, B-037, B-178 |
| 64 | Main-thread claims ledger (evidence check before a cause or a steer) | `ctf/findings.py`, `ctf/cli/findings.py` | impl (B-259) | B-200 (status, digest, brief), B-098 (retro) |
| 65 | Accepted-format catalog and pre-event vocabulary harvest (metadata lane) | `solvers/metadata-forensics/accepted_formats.py` + `.json`, `format_candidates.py` (`ranked`, `pick`), `ctf/cli/accepted_formats.py` | impl (B-218) | `format_candidates.pick` / `properties_strict.fc_candidates` (probe order, live); B-036 pre-clock check (adoption); B-224 |
| 66 | Resumable key-search harness (candidate banks, exact verifier, chunk ledger) | `solvers/common/keysearch.py`, `ctf/cli/keysearch.py` | impl (B-215) | B-074 lane (harvest, archive-password store, hashcrack wordlist feed its banks; a zip hit feeds the store) |
| 67 | Per-role and per-difficulty model router | `ctf/router.py` (docstring is the contract), `ctf/event.py` `[routing]`, `tools/route_launch.py`, `ctf/cli/model_route.py` | impl (B-201; the A/B-backed assignment is a human step) | the dispatcher / warm standby (pass `--difficulty`), B-096 trial result |
| 68 | Build-time work registry, file claims, fold owners, idle-machine lock | `ctf/workreg.py`, `ctf/cli/work.py`, `ctf/cli/_idle.py` | impl (B-213) | the build workflow outside the repo (register before spawn via `ctf work start` or `ctf worktree create --harness`; wrap the merge queue's full suite in `ctf work idle-run`) |
| 69 | Repo build sandbox profile for Codex (loopback, worktree git, host allowlist, Docker opt-in, push dry run) | `ctf/build_sandbox.py`, `ctf/cli/build_sandbox.py`, `tools/build_hosts.toml`, `ctf/testing/capabilities.py` (section 9 markers), `docs/build-sandbox.md` | impl (B-192) | Codex build lanes; the merge queue runs the `needs_jit` tests Codex cannot |
| 70 | Prompt-cache TTL choices (main 5m, standby 1h) and the TTL report | `ctf/cache_ttl.py` (docstring is the contract), `tools/claude_launch --standby`, `tools/ledger/usage.py` (`ttl_report`), `python -m ctf usage ttl` | impl (B-118) | B-017 (no-idle watcher), B-037 (standby launches) |
| 71 | Irreducible adaptation residual (no-oracle classes held unsure/none, playbooks, per-event frequency) | `ctf/residual.py`, `ctf/cli/residual.py`, `docs/playbooks/residual.md` (generated) | impl (B-254, hard tail: not a solver) | engines and agents that hit a no-oracle shape; the release/review loop that reads the per-event report |
| 72 | Scratch scaffolds, the expectation generator and the test-pin codemod | `ctf/scaffold.py`, `ctf/scaffold_templates/`, `ctf/expectations.py`, `ctf/testpin.py`, `ctf/cli/scaffold.py`, `ctf/cli/testpin.py`, `solvers/binary/racer_template.py` | impl (B-258) | B-196 (expectations from the saved corpus), lane promotion (racer candidates) |

---

## 1. Event profile

One TOML file per event, `events/<slug>/event.toml`, loaded by `ctf.event`:

```python
from ctf import event
prof = event.load("csctf")    # EventProfile (frozen dataclass), validated
prof = event.current()        # $CTF_EVENT, else the only profile under events/, else EventError
event.available()             # ["csctf", "huntress", "pink", "spooky"]
event.load_path(path, expect_slug=None)          # one file anywhere (the scaffold re-reads with it)
event.parse(data, src="<profile>", expect_slug=None)   # a decoded TOML mapping -> EventProfile
# EventProfile(slug, name, start, end, platform, flag, rules, proof, writeups, budget, submit,
#              sweep, models, allowance, instances, wire, routing, categories, sectors, path); its parts are frozen dataclasses too:
# Platform, FlagSpec, ProofSpec, Rules, Writeups, Budget, SubmitPace (the [submit] table),
# SweepPolicy (the [sweep] table; .authorized is mode == "player-authorized"),
# Models (the [models] table, B-100), Allowance (the [allowance] table, B-171),
# InstancesCfg (the [instances] table, B-003), WirePace (the [wire] table, B-140),
# Discord (the [discord] table, B-112: prof.discord.capture, .api_base, .token_env, .guild_id):
# Routing(rules, default_difficulty, verify_candidate, top_categories) and its RouteRule(role,
#   difficulty, harness, model, effort, tier, budget_usd, index) entries (the [routing] table, B-201;
#   None when the table is absent; event.ROUTE_DIFFICULTIES, ROUTE_HARNESSES, ROUTE_ANY, DEFAULT_TIER):
prof.wire.lane_budget(lane)      # the release-window budget of a lane; 0 for an unnamed one
```

Every per-event fact lives here: no module hard-codes an event name, URL, flag regex or rule.

```toml
slug = "csctf"                          # required; equals the folder name; [a-z0-9-]
name = "CSCTF 2026"                     # required
categories = ["Web", "Pwn"]            # default []
sectors = ["energy"]                    # default []
dates = { start = 2026-11-06T13:00:00Z, end = 2026-11-08T13:00:00Z }   # required; TOML date or datetime

[platform]                              # required
kind = "ctfd"                           # ctfd | gamemaster | manual
base_url = "https://x.example"          # required unless kind = manual; http(s)
team = "our-team"                       # optional
hosts = ["platform-proxy.example"]      # optional, default []: other names of the platform (a proxy);
                                        # bare host names. Platform.all_hosts() = base_url host + hosts:
                                        # never a target or an SSRF destination

[flag]                                  # required
prefixes = ["CSCTF", "CTF"]             # required; [] = format not known yet (any word prefix)
body = "[^}\\n]{1,256}"                 # default "[^{}\\s]{1,256}"; ASCII regex that cannot match "}"
case = "prefix-insensitive"             # exact (default) | prefix-insensitive | insensitive

[proof]                                 # optional: a non-flag proof token (Huntress web)
pattern = "proof_[0-9a-f]{32}"
case = "exact"

[rules]                                 # required
submit_mode = "auto"                    # required: auto | confirm | manual
wrong_answer_stop = 3                   # default 3: wrong answers on one challenge before stop-and-ask
guess_budget = 0                        # default 0: unreasoned variant submissions allowed per challenge
hints_allowed = false                   # default false
flag_sharing = "forbidden"              # required: allowed | forbidden
ai_on_platform = "allowed"              # required: allowed | forbidden (forbidden = no automation touches the platform)
live_service_scope = ["*.x.example", "10.13.37.0/24"]   # default []: host globs or CIDR networks (section 13)
public_fetch_allow = ["msdl.microsoft.com"]  # default []: public third-party hosts a tool may fetch from (section 13)
web_state_changing = false              # default false: BUILD-PLAN O-2 is the player's call. This field is
                                        # the single O-2 switch for the web lane: the B-149 contract executor
                                        # (solvers/web/contract_executor.py) reads it through ctf.event.current
                                        # and narrows any caller-supplied MutationPolicy back to GET-only
                                        # unless it is true, so no state-changing (POST/PUT/PATCH/DELETE)
                                        # web action runs unattended while this is false, whatever a caller asks.
                                        # web.flow_recorder and web.oidc_driver (B-183) enforce it too: there
                                        # every HTTP method other than GET (HEAD included) is state-changing
                                        # and refused (StateChangeRefused) unless this is true.
                                        # web.deser_fire (B-121) treats every gadget fire as state-changing
                                        # (it is RCE, whatever the verb): fire() raises FireRefused unless
                                        # this is true, failing closed when no profile loads. Its operator
                                        # kill-switch CTF_WEB_DESER_FIRE=off refuses even when it is true.
wrong_penalty = 0                       # optional (B-173): points lost per wrong answer, int >= 0;
                                        # absent = not known (the agent rules: treat every miss as costly)
approved_extras = true                  # default true (B-173): may the player approve sends past
                                        # wrong_answer_stop? false = the stop is final (section 5)
hint_suggestions = false                # default false (B-173): may agents suggest a hint to the player?
pointed_services = "forbidden"          # default forbidden (B-173): allowed = a challenge service the player
                                        # points at (`ctf policy point`) is also a target (section 13)
chain_rpc = "forbidden"                 # default forbidden (B-243): allowed = solvers/toolkits/evm_rpc.py may send
                                        # read-only EVM JSON-RPC (an allowlist of eth_* reads) to a node whose
                                        # URL live_service_scope admits (section 13); never a write or signing method
sandboxed_execution = "forbidden"       # default forbidden (B-242): allowed = the runtime adapters
                                        # (`binary.runtime_trace`, section 54) may run a delivered managed
                                        # or bytecode artifact for a bounded trace, only in a pinned
                                        # container with no network and no host mount. It gates that
                                        # engine alone (`eventpolicy.execution_refusal`); the agent rule
                                        # "detonate only in Docker" (section 15) is unchanged

[writeups]                              # optional (B-098: ctf/writeup/, `python -m ctf writeup`)
redact_flags = true                     # default true; must be true when rules.flag_sharing = "forbidden"
public_repo = ""                        # default none; the publish plan names it (publishing needs it)
publish_hold = true                     # default true: nothing is published until the player sets false

[budget]                                # optional (B-033)
per_point = 0.5                         # default 0.5 USD per point
floor = 25.0                            # default 25
ceiling = 250.0                         # default 250
per_challenge_day = 50.0                # optional flat rate (Huntress); replaces per_point when set
overthink_usd = 15.0                    # optional (B-130): the three overthink_* keys are set together
overthink_max_points = 50.0             #   or all unset. A challenge at or below overthink_max_points
overthink_min_solves = 25               #   that overthink_min_solves+ teams have solved is clamped to
                                        #   overthink_usd (an easy, well-solved row is not worth a deep
                                        #   spend). cap_usd(budget, points, days_open, solves); the clamp
                                        #   only fires when the solve count is known, and only lowers.

[human]                                 # optional (B-169, ctf/humanops.py, `ctf human`)
confirm_system = "CourseStack"          # default none: an off-platform points system the player confirms
                                        # by hand; enables `ctf human confirm-list` / `reconcile`
checklist = ["Charge the backup phone"] # default []: event-specific items for `ctf human checklist`

[discord]                               # optional (B-112, section 57, `ctf discord`)
capture = "forbidden"                   # forbidden | bot. Default forbidden: no API client, only what the
                                        # player pastes or exports is analysed. "bot" is the player's
                                        # recorded clearance (event rules and Discord's terms checked, the
                                        # bot admitted by an organizer)
api_base = "https://discord.com/api/v10"   # default; http(s), no credentials, query or fragment. Its host
                                        # must also be in rules.public_fetch_allow before a request is made
token_env = "CTF_DISCORD_TOKEN"         # default: the NAME of the CTF_* variable that holds the bot token,
                                        # never the token; CTF_TOKEN and CTF_COOKIE are refused
guild_id = "123456789012345678"         # default none: the server's numeric id, as a string

[submit]                                # optional (B-006): the team's cross-process submit queue
per_minute = 10                         # default 10: sends in any 60 s window, every process together
interval_s = 1.0                        # default 1.0: seconds between any two sends (also the CTFd adapter's floor)
per_challenge_interval_s = 3.0          # default 3.0: seconds between two sends on one challenge
max_hold_s = 600.0                      # default 600: one submit call retries an unjudged answer this long,
                                        # then leaves it queued for `ctf submit-queue drain`
rotating_miss_budget = 6                # default 6: rotating-flag misses (ctf.dynamic) per challenge that are
                                        # not wrong answers; each miss past it counts toward wrong_answer_stop

[sweep]                                 # optional (B-173): player-authorized sweeps (section 25)
mode = "forbidden"                      # default forbidden | player-authorized
max_count = 50                          # default 50: most sends one authorization may grant
interval_s = 5.0                        # default 5.0: the sweep pacer, seconds between two sweep sends
ttl_s = 3600.0                          # default 3600: an authorization expires this long after it is granted

[models]                                # optional (B-100): the classifier fallback and BUILD-PLAN O-3
primary = "claude-opus-5-5"             # default: the model sanctioned work should run on
fallback = ["claude-opus-4-8"]          # default: models a safety classifier may move a session onto
cyber_verified = "unknown"              # unknown (default) | requested | granted | denied; only granted
                                        # means the fallback is not expected (`python -m ctf access`)
docs = "claude-sonnet-5-5"              # default (B-097): the model writeup/retro drafts run on
docs_on_primary = ["pwn"]               # default: challenge categories (any case) whose writeups are
                                        # drafted on `primary` instead (exploit-heavy work)
effort = "medium"                       # default (B-095): the reasoning tier a solver's first agent is
                                        # launched at. minimal|low|medium|high|max. The escalation ladder
                                        # (section 27) ramps it a tier per fresh agent (never mid-session,
                                        # which rewrites the prompt cache). tools/{codex,claude}_launch
                                        # pin it via --effort (claude: a real launch fails unless the
                                        # installed CLI documents the flag; section 14)

[allowance]                             # optional (B-171): harness quota reserve and scheduling (section 10)
margin_pct = 10.0                       # default 10: added to every quota reading (the meter is not
                                        # trusted to the percent)
reserve_pct = 20.0                      # default 20: held back from solve and build work in a window
                                        # that outlives the next release
build_ceiling_pct = 70.0                # default 70: build work stops at this much of a window
recheck_minutes = 30.0                  # default 30: a limit hit is re-probed after this long, whatever
                                        # reset it named
releases = [2026-11-07T17:00:00Z]       # default []: wave / release times (a naive one is in tz)
daily_release = "12:00"                 # default "" (none): "HH:MM" in tz, every day of the event
tz = "America/New_York"                 # default "UTC": IANA zone for daily_release, naive releases, days
daily_usd = 0.0                         # default 0 (none): per-day spend allowance (`ctf quota daily`)
[instances]                             # optional (B-003): the per-team container-instance plugin
cap = 3                                 # the local slot cap the scheduler honours; omit for no local cap
[instances.endpoints]                   # the plugin wiring (ctf.instances.endpoints_from_config)
plugin = "docker_per_team"              # a named shape (docker_per_team | ctfd_docker); any extra key
                                        # overrides that shape, or give all of spawn/stop/renew/status
[wire]                                  # optional (B-140): the platform request journal and budget (section 5)
per_minute = 0                          # default 0 (no cap): requests in any 60 s window, every process together
release_budget = 0                      # default 0 (none): requests from a release anchor to its window's end
reserve = 0                             # default 0: of each cap, kept for submits and attempt starts
release_window_s = 60.0                 # default 60: the release window after each anchor
release_poll_free_s = 10.0              # default 10: list polls are not spread this long after the anchor
release_poll_gap_s = 0.0                # default 0 (off): then list polls (every lane) this far apart
release_lane_budget = 0                 # default 0 (none): requests per named lane (CTF_WIRE_LANE) in the
                                        # window; past it the lane's reads are held (polls, submits never)
release_lanes = { watch = 6 }           # default {}: per-lane overrides of release_lane_budget
pause_s = 20.0                          # default 20: a 429 without Retry-After pauses every process this long,
pause_max_s = 120.0                     # default 120: doubling on a repeat within 120 s, up to this
max_wait_s = 30.0                       # default 30: a request the release, poll-gap or lane budget held
                                        # this long goes anyway (forced); never past a pause or per_minute

[routing]                               # optional (B-201, section 67): the per-role, per-difficulty model
                                        # router. Absent: nothing is routed (launchers, ctf escalate as before)
default_difficulty = "medium"           # default medium: warmup | easy | medium | hard, when none is given
verify_candidate = "claude-sonnet-5-5"  # default "" (none): verify moves here only after an approving
                                        # ab_verify ledger record (B-096); else it stays on models.primary
top_categories = ["pwn", "crypto", "osint"]   # default [] (no limit): only these categories route a
                                        # solve at "hard"; another known category is routed as "medium"
[[routing.route]]                       # default none; the most specific matching rule names each field
role = "solve"                          # default "*": a ctf.stages.SPEND_CATEGORIES role
difficulty = "warmup"                   # default "*"
harness = "codex"                       # default "*": claude | codex; a harness rule matches only that launcher
model = "gpt-6.1-terra"                 # optional: a model id priced in tools/ledger/pricing.json
effort = "low"                          # optional: minimal | low | medium | high | max (a rule names model,
                                        # effort or both)
tier = "default"                        # default "default"; any other tier (ultrafast, fast, priority) must be
                                        # priced for the model and needs budget_usd
budget_usd = 40.0                       # only with a speed tier: > 0 and <= the [budget] ceiling (B-033)
```

`EventProfile.human` is a `Human(confirm_system: str | None, checklist: tuple[str, ...])`; a blank
`confirm_system` reads as none. Human-only work (task cards, the OSINT final-pin queue, the confirm
list and its reconciliation) lives in the ledger as `human.card`, `human.card_answer`,
`human.card_drop`, `human.confirm`, `human.confirm_done` and `human.reconcile` records, each with
`event_slug`; the confirm list also reads the gate's accepted `platform.submit` records.

`EventProfile.discord` is a `Discord(capture, api_base, token_env, guild_id: str | None)`; `capture` is
one of `event.DISCORD_CAPTURE`, and the defaults are `event.DISCORD_API_BASE` and
`event.DISCORD_TOKEN_ENV`. A new profile is scaffolded with `capture = "forbidden"` (section 57).

Validation (all raise `ctf.event.EventError` naming the file and the dotted key):

- unknown keys anywhere are an error; a missing required key names itself; enums are checked; a
  boolean is never accepted where a number is asked;
- `platform.kind = "manual"` requires `rules.submit_mode = "manual"`;
- `rules.ai_on_platform = "forbidden"` requires `rules.submit_mode = "manual"`;
- `rules.submit_mode = "auto"` requires known `flag.prefixes` (an unknown format makes auto-submit
  unsafe; use `confirm` until the first accepted flag confirms it, then edit the profile);
- `budget.floor <= budget.ceiling`; the three `budget.overthink_*` keys are all set or all unset,
  with `overthink_usd`/`overthink_max_points >= 0` and `overthink_min_solves` a whole number `>= 1`
  (B-130); `dates.end >= dates.start`;
- `submit.per_minute >= 1`; `submit.interval_s`, `submit.per_challenge_interval_s`, `submit.max_hold_s >= 0`;
  `submit.rotating_miss_budget` is an integer `>= 0`;
- `models.primary` is not in `models.fallback`; every model id (primary, fallback, docs) matches
  `^[a-z0-9][a-z0-9._-]{1,63}$`; `models.docs_on_primary` is a list of non-empty strings;
- `wire` caps are integers and times numbers, all `>= 0`; `wire.release_window_s > 0`;
  `wire.reserve` is below `wire.per_minute` and `wire.release_budget` when they are set;
  `wire.release_poll_free_s <= wire.release_window_s`; `wire.pause_s <= wire.pause_max_s`; each
  `wire.release_lanes` key is a lane name (`ctf.event.LANE_RE`) and each value an integer `>= 0`;
- `rules.flag_sharing = "forbidden"` requires `writeups.redact_flags = true` (B-098). The writeup
  pipeline also redacts whenever sharing is forbidden, so the two can never disagree at publish time;
- `rules.wrong_penalty >= 0`; `sweep.max_count >= 1`, `sweep.interval_s >= 0`, `sweep.ttl_s > 0`;
  `sweep.mode = "player-authorized"` requires `rules.submit_mode` other than `manual`;
- `allowance.margin_pct`, `reserve_pct`, `build_ceiling_pct` are within 0..100 and `margin_pct +
  reserve_pct < 100`; `allowance.recheck_minutes > 0`; `allowance.daily_usd >= 0`;
  `allowance.daily_release` is `"HH:MM"` (24-hour) or `""`; `allowance.tz` is an IANA zone;
  `allowance.releases` are datetimes.
- `[instances]` (B-003): `cap` is a positive integer or omitted (no local cap); `[instances.endpoints]`
  is required and validated by `ctf.instances.endpoints_from_config` at load (an unknown plugin or a
  malformed route fails loudly). The parsed value is `profile.instances` (`InstancesCfg`, or `None`
  when there is no section); `profile.instances.as_config()` is the `{"cap", "endpoints"}` mapping
  `ctfd.make_adapter` / `ctf.instances.Instances.from_config` take (a fresh plain-dict copy per call).
  `InstancesCfg.endpoints` is a read-only deep copy (`MappingProxyType`, arrays as tuples): it never
  aliases the parsed TOML.

`rules.live_service_scope` is read by the scope guard (section 13), not by `ctf.event`: an entry is
a host glob or a CIDR network; an empty list means no live service may be contacted; the platform's
own host and port are never in scope, whatever an entry matches; an entry made only of wildcards
(`*`, `*.*`) is refused as too broad.

`EventProfile.manual` is true when the platform kind or the submit mode is manual.

**Shipped profiles.** `events/huntress`, `events/csctf`, `events/pink`, `events/spooky` describe the four
past events (facts from each source repo, cited in the file header). They are fixtures: every host is
a `.example` placeholder. A live event gets its own folder (section 11, "Adding an event"); never point
a past-event profile at a real host. With four profiles present, `event.current()` needs `CTF_EVENT`.

Adding a field: add it to the dataclass and `parse()` in `ctf/event.py` with a default, document it
here (the TOML block above), give it a `new-event` option or a template line if a player sets it
(section 15), and add a test in `tests/test_contracts_event.py`. Never read an undeclared key.

**Player-declared permissions (B-191).** An optional sibling file `events/<slug>/permissions.toml`
records the known-good actions the *player* pre-authorises for an event (it is theirs to write; no
agent edits it, and it grants nothing by itself — it points each action at a sanctioned helper).
Loaded by `ctf.permissions` (`load(slug)` / `load_optional(slug)` -> `None` when absent;
`parse(data)`; `PermissionError` on a malformed file). Schema: an optional top-level `slug` and
`example` (bool), and zero or more `[[allow]]` tables with `id` (unique, `[a-z0-9-]`), `action`,
`reason` (all required) and optional `scope`, `helper`, `note`; unknown keys and an unknown `helper`
are errors. `SANCTIONED_HELPERS` names the purpose-built `ctf` commands (`abandon`,
`worktree-commit`, `permissions`, `discipline` (B-043), and since B-175 `job` and `reap`); each is a real `ctf/cli/<name>.py`. The repo ships no event's
declaration, only the template `docs/examples/permissions.example.toml` (`ctf.permissions.EXAMPLE_PATH`),
which carries `example = true`. A file that still says `example = true` is an unconfirmed example:
`ctf permissions` labels it so (never as the player's declaration) and `--check` exits 1 until the
player deletes that line. The file is not part of the generated agent-rules check (§1 is about
`event.toml`).

## 2. Paths

```python
from ctf import paths
paths.repo_root()          # this checkout (a worktree resolves to itself)
paths.events_root()        # <repo>/events
paths.event_dir(slug)      # <repo>/events/<slug>
paths.workdir(slug=None)   # $CTF_WORKDIR verbatim, else ~/ctf-work/<slug or current event>
paths.ensure_workdir()     # the same, created
paths.realdata_root()      # $CTF_REALDATA, else paths.DEFAULT_REALDATA (the Huntress corpus; read-only)
paths.require_realdata()   # the same, or FileNotFoundError naming CTF_REALDATA
paths.lanes_root()         # $CTF_LANES_DIR, else ~/ctf-work/_lanes: Codex build-lane state (B-179, docs/lanes.md)
paths.saved_challenges_root()  # $CTF_REAL_CHALLENGES (saved past-event attempts, day-NN/<lane>-.../),
                           # else None; set but not a directory: FileNotFoundError naming it
paths.rehearsal_corpus_root()  # $CTF_REHEARSAL_CORPUS (blind rehearsal corpus, B-155), else None;
                           # set but not a directory: FileNotFoundError naming it
paths.require_rehearsal_corpus()  # the same, or FileNotFoundError when CTF_REHEARSAL_CORPUS is unset
paths.geo_dataset_root()   # $CTF_GEO_DATASET (frozen OSINT geolocation dataset, B-113), else None;
                           # set but not a directory: FileNotFoundError naming it
paths.require_geo_dataset()  # the same, or FileNotFoundError when CTF_GEO_DATASET is unset
paths.factor_table_path()  # $CTF_FACTOR_TABLE (offline factor table, B-244), else
                           # <realdata_root()>/factor-table/factors.sqlite when that file exists, else None;
                           # set but not a file: FileNotFoundError naming it
paths.codex_home(environ=None)  # $CODEX_HOME, else ~/.codex (Codex config folder; read-only, B-039)
paths.toolbox_dir(environ=None) # $CTF_TOOLBOX_DIR, else paths.DEFAULT_TOOLBOX_DIR (~/tools): toolbox clones (B-142)
paths.claude_home(environ=None) # $CLAUDE_CONFIG_DIR, else ~/.claude (Claude Code config folder; read-only, B-193)
paths.gate_state(root=None) # $CTF_GATE_STATE, else <git common dir>/ctf-gate (B-195; shared by worktrees)
paths.status_state(root=None) # $CTF_STATUS_STATE, else <git common dir>/ctf-status (B-198 jobs, last push)
paths.workreg_state(root=None) # $CTF_WORKREG_STATE, else <git common dir>/ctf-workreg (B-213 work registry, idle lock; section 68)
paths.governor_state()     # $CTF_GOVERNOR_STATE, else ~/ctf-work/_governor (B-176; one per host, not created)
paths.wheelhouse_dir()     # $CTF_WHEELHOUSE, else ~/ctf-work/_wheelhouse (B-188: pre-downloaded wheels; not created)
paths.slate_state()        # $CTF_SLATE_STATE, else ~/ctf-work/_slate (B-214 multi-event scheduler; one per host, not created)
```

- `workdir()` is the only workdir resolver. It never creates anything; with no `CTF_WORKDIR` and no
  resolvable event it raises `EventError`. Runtime state (challenge folders, ledger, submit state)
  goes under it, never in the repo.
- No module derives a path from its own `__file__` walk or its own env lookup; use this file.
- Shell scripts ask for it: `python -m ctf workdir` (`ctf/cli/workdir.py`, `--create` to make it);
  no script spells a `${CTF_WORKDIR:-...}` default.
- Tests run with `CTF_WORKDIR` pointed at a temp dir and `CTF_EVENT` defaulting to `csctf` (root
  `conftest.py`); a test that needs another event sets `CTF_EVENT` with `monkeypatch`; a whole module
  pins one with `import event_pin; event_pin.pin(globals(), "<slug>")` (`tests/event_pin.py`: an autouse
  fixture under pytest, the process env plus the suite's loopback scope profile when run as a script).
- Enforced by `tests/test_single_sources.py`: nothing outside `ctf/paths.py` reads `$CTF_WORKDIR` (or a
  legacy spelling) or builds `<checkout>/challenges` / `<checkout>/workspace` from its own location.
- The saved past-event attempts are a corpus apart from the real-data one: `saved_challenges_root()`
  has no default and is never derived from `realdata_root()`. When it is None a pytest module's saved
  test calls `pytest.skip("not run: CTF_REAL_CHALLENGES is not set ...")` (NOT RUN report), and an
  uncollected check script prints `SKIP <section>: not run: CTF_REAL_CHALLENGES is not set`; never a
  pass. Set to a missing folder, the FileNotFoundError fails that test. Nothing reads
  `CTF_REAL_CHALLENGES` from `os.environ` directly. `tests/test_saved_sections.py` runs each module's
  saved test in a child pytest (unset, missing, empty) and each uncollected script with a saved section,
  listing the script's sections in the NOT RUN report.
- No hardcoded home or source-repo paths (R-05): no file holds `/Users/<name>` (whatever follows the
  name) or a home-relative 2026 source-repo path (tilde, `$HOME`, or the Python `Path.home()` / `HOME`
  joined with a `2026-ctf-` name), outside `docs/migration/` and the allowances in
  `ctf/testing/home_paths.py` (`ctf/paths.py`'s `DEFAULT_REALDATA` and the contract test that pins
  it, and the root `CLAUDE.md` / `AGENTS.md` rule naming the read-only source repos). `/Users/Shared` and `C:/Users/Public` are system folders and allowed.
  Enforced by `tests/test_no_home_paths.py`; `python -m ctf.testing.home_paths` lists findings.
  Playbooks run from the checkout root with `.venv/bin/python` and `python -m ctf ...`, with
  `CTF_EVENT` set; they never pin `CTF_WORKDIR` to a fixed folder.

## 3. Environment

```python
from ctf import env
env.get("CTF_WORKDIR")        # str | None; empty counts as unset
env.get_bool("CTF_TESTING")   # 1/0 true/false yes/no on/off; anything else -> EnvError
env.get_int("CTF_X")
env.require("CTF_EVENT")      # or EnvError naming it and its legacy spellings
env.legacy_names("CTF_TOKEN") # ("CSCTF_TOKEN", "HUNTRESS_GM_TOKEN", "HUNTRESS_TOKEN"): lookup order
```

- `CTF_*` names are canonical. Lookups must use the canonical name (`env.get("HUNTRESS_X")` is a
  `ValueError`).
- Compatibility: a canonical lookup also reads legacy spellings and emits a `DeprecationWarning`
  ("X is deprecated; set Y instead") when one is used. Order: explicit renames in `env.RENAMES`
  (`CTF_PLATFORM_URL` <- `CSCTF_URL`, `HUNTRESS_GM_URL`; `CTF_TOKEN` <- `CSCTF_TOKEN`,
  `HUNTRESS_GM_TOKEN`; `CTF_COOKIE` <- `CSCTF_COOKIE`; `CTF_TEAM_ID` <- `CSCTF_TEAM_ID`), then
  `HUNTRESS_<suffix>`, then `CSCTF_<suffix>`. The canonical name wins when both are set.
- Canonical names in use: `CTF_EVENT`, `CTF_EVENTS_DIR` (a folder of `<slug>/event.toml` profiles used instead of `<repo>/events`: the flightdeck adapter writes the profile of the board being played there), `CTF_WORKDIR`, `CTF_REALDATA`, `CTF_REAL_CHALLENGES`, `CTF_REHEARSAL_CORPUS`, `CTF_GEO_DATASET` (the frozen OSINT geolocation dataset, section 2), `CTF_FACTOR_TABLE` (the offline factor table, section 2, B-244), `CTF_RUN_LIVE`,
  `CTF_TESTING`, `CTF_STRICT_TESTS`, `CTF_PLATFORM_URL`, `CTF_TOKEN`, `CTF_COOKIE`, `CTF_TEAM_ID`,
  `CTF_HANDOFF_AS` (the handoff board's actor, section 45), `CTF_LANES_DIR` (Codex build-lane state, B-179), `CTF_GATE_STATE` (the regression gate's state folder, section 23),
  `CTF_STATUS_STATE` (the live status state folder, section 47), `CTF_WORKREG_STATE` (the build-time
  work registry's state folder, section 68), `CTF_IDLE_LOCK` (a boolean: `ctf gate run` and `ctf adapt
  gate|prewarm|chain` take the idle-machine lock when no `--idle-lock`/`--no-idle-lock` is given,
  section 68; read through `ctf.cli._idle.ENV_IDLE_LOCK`), `CTF_STATUS_PUSH_URL` (the phone push
  target, section 47; a secret like a token: never printed),
  `CTF_WIRE_LANE` (the lane a process's platform requests are journaled and budgeted under, section 5),
  `CTF_ENGINE_LEDGER` (`0` turns off `engine.run` records, section 6), `CTF_WEB_DESER_FIRE` (`off`
  forbids web.deser_fire gadget firing, B-121), `CTF_TOOLBOX_DIR` (where the
  binary toolbox's pinned clones live, section 16; default `~/tools`),
  `CTF_TOKEN_EXPIRES` (the platform token's expiry, ISO-8601 with offset, for the doctor's `token`
  check, B-190, section 16),
  `CTF_CAPACITY_AGENT_RAM_MB`, `CTF_CAPACITY_RESERVE_MB`, `CTF_CAPACITY_AGENTS_PER_CPU`,
  `CTF_CAPACITY_SUBAGENT_CAP`, `CTF_CAPACITY_MAX_WORKERS`, `CTF_CAPACITY_RAM_BASIS` (host sizing
  policy for `ctf capacity`, B-018; `ctf/capacity.py`), `CTF_SPAWN_ID` (the admitted spawn a gated
  launcher run starts, section 39),
  `CTF_GOVERNOR_STATE`, `CTF_GOVERNOR_HEAVY_CAP`, `CTF_GOVERNOR_HEAVY_RAM_MB`, `CTF_GOVERNOR_LOAD_SOFT`,
  `CTF_GOVERNOR_LOAD_HARD`, `CTF_GOVERNOR_BATTERY_LOW`, `CTF_GOVERNOR_DISK_MIN_GB`,
  `CTF_GOVERNOR_RSS_ALERT_MB`, `CTF_GOVERNOR_AGENT_NAMES`, `CTF_GOVERNOR_STRICT`,
  `CTF_GOVERNOR_EVICT_MIN_MB` (the host resource governor, B-176, section 28), `CTF_COMPACT_CLAUDE` and
  `CTF_COMPACT_CODEX` (compaction thresholds, section 30), `CTF_CACHE_TTL_CLAUDE`, `CTF_CACHE_TTL_STANDBY`
  (prompt-cache TTL overrides) and, set for a launched Claude agent, `CTF_CACHE_TTL_LAUNCHED` (section 70), `CTF_AGENT` (who is reading, for the shared
  read map, section 34; `agent` when unset), `CTF_CAMPAIGN_LAUNCHERS`
  (read), and, set for a launched agent (B-178, section 36), `CTF_CAMPAIGN_AGENT`, `CTF_CAMPAIGN_GOAL`,
  `CTF_CAMPAIGN_RESUME`, `CTF_SCRATCH_DIR`, `CTF_CHALLENGE` (the R-09 launchers' gate), `CTF_WHEELHOUSE`
  (the wheelhouse folder, section 37), `CTF_ASSET_ROCKYOU`, `CTF_ASSET_JOHN_SHARE`, `CTF_ASSET_SECLISTS`,
  `CTF_ASSET_GHIDRA`, `CTF_ASSET_WHISPER_GGML`, `CTF_ASSET_WHISPER_CT2`, `CTF_ASSET_SCHEMAS` (asset overrides and exports named in `tools/assets.toml`, read by name from the
  manifest, section 37), `CTF_SLATE_STATE` (the multi-event scheduler's state
  folder, B-214, section 44), `CTF_JOBS_DIR` (B-144; set
  for a job's command and hook: `CTF_JOB_ID`, `CTF_JOB_DIR`, and for the hook `CTF_JOB_RC`,
  `CTF_JOB_LOG`, `CTF_JOB_SUMMARY`), `CTF_JOB_OWNER` and `CTF_JOB_OWNER_PID` (a job's default owner
  and the pid whose exact identity owns it; set by the launchers for their agent, B-175, section 60),
  `CTF_SESSION` (the launchers' session name) and `CTF_SESSIONS_DIR` (session records; B-175), `CTF_BROWSER_HARNESS` (the command that drives the pinned
  browser worker, a path or a PATH name; no default, an unset one is a named failure),
  `CTF_BROWSER_HARNESS_ARGS` (its extra arguments, split on whitespace), `CTF_BROWSER_SANDBOX`
  (`seatbelt`, the default, `docker` or `none`), `CTF_BROWSER_IMAGE` (the local image for the docker
  mode; never pulled), `CTF_BROWSER_BUDGET_MS` and `CTF_BROWSER_MAX_EVENTS` (the default per-visit
  time budget and event cap; B-150, `ctf/web_browser.py`), `CTF_INTEGRATION_BRANCH` (the branch the
  integrator merge queue owns, B-147; `ctf/worktree.py`), `CTF_INTEGRATION_ALLOW` (true only on the
  integrator's own git commands, so `ctf integrate guard` admits them; never set it by hand) and
  `CTF_PYTHON` (the interpreter for the integrator's regenerate and gate steps,
  `ctf.worktree.resolve_python`; these three are read through named constants, not literals), and
  the scan-index lookups (B-114, `ctf/scan_index.py`; read through named constants):
  `CTF_SCAN_INDEX_SHODAN_KEY`, `CTF_SCAN_INDEX_CENSYS_TOKEN`, `CTF_SCAN_INDEX_FOFA_KEY`,
  `CTF_SCAN_INDEX_NETLAS_KEY` (the provider keys: secret values, the only place a key is read, never
  printed, cached or written to the ledger), `CTF_SCAN_INDEX_CENSYS_ORG` (optional organization id of
  a paid Censys plan), `CTF_SCAN_INDEX_BUDGET` and `CTF_SCAN_INDEX_BUDGET_<PROVIDER>` (requests a
  provider may be sent per workdir; default 25, 0 turns it off). Read
  outside `ctf.env`: `CTF_PYTHON` again (the interpreter `tools/ctfpy` uses; a shell script; and, through
  `ctf.env`, the first source of `ctf.pyinterp.resolve`, the gate's and `tools/suite.py`'s test
  interpreter, B-153) and
  `CTF_SUBMIT_STATE_DIR` (the
  carried CTFd client's shared pacing state). `CTF_DISCORD_TOKEN` (the Discord bot token for `ctf discord
  capture`, section 57; read through `ctf.env` by the name the profile's `[discord] token_env` gives, so
  another `CTF_*` name may hold it; a secret: never printed, logged or written to the ledger). Add new ones as `CTF_<AREA>_<NAME>`, read through
  `ctf.env`, and list them here (the doc test checks every `env.get*("CTF_...")` literal in `ctf/`).
- Secret values (`CTF_TOKEN`, `CTF_COOKIE`, the Discord bot token) are never printed, logged or written to the ledger.
- `CTF_FLAG_FORMAT` / `CSCTF_FLAG_FORMAT` overrides are retired: the flag format is the profile's.
  `ctf.config.load()` raises `ConfigError` when one is set, or when `.ctf/config.json` still holds a
  `flag_format` or `workdir` key (both retired; never silently ignored).
- Enforced by `tests/test_single_sources.py`: no `HUNTRESS_*`/`CSCTF_*` name is read, set or cleared
  anywhere except `ctf/env.py` and the contract tests that prove the legacy mapping (directly, through
  `monkeypatch`, an `env={...}` handed to a call, or one step through a helper of the same module).
  Code that reads a migrated name goes through `ctf.env` so a legacy spelling still works, with a warning.

## 4. Flag format

```python
from ctf import flagfmt
ff = flagfmt.for_profile(prof)        # cached FlagFormat
ff.find_flags(text_or_bytes)          # distinct matches, first-seen order
ff.is_flag(s)                         # the whole (stripped) string is one flag
ff.normalize(s)                       # canonical spelling for dedupe; ValueError for a non-flag
ff.find_proofs(data); ff.is_proof(s)  # [proof] tokens; LookupError if the profile has none
ff.known                              # False while prefixes = []
flagfmt.find_flags(data)              # module-level forms (find_flags, is_flag, normalize) use event.current()
flagfmt.current()                     # the active event's FlagFormat, cached per CTF_EVENT value
flagfmt.clear_current_cache()         # drop that cache (tests that rewrite a profile in place)
flagfmt.flag_pattern(spec)            # the text regex source for a FlagSpec; proof_pattern(spec) for a ProofSpec
flagfmt.TEXT / flagfmt.BYTES          # compiled-pattern stand-ins that follow the active event on every use
flagfmt.PROOF_TEXT / PROOF_BYTES      # the same for [proof]; match nothing when the profile has none
flagfmt.PROOF_ANYCASE                 # the [proof] pattern, any case: a broad "seen" scan, never a return gate
flagfmt.shape(); SHAPE_TEXT / SHAPE_BYTES   # any word prefix + the event's body: broad "seen" scans only
flagfmt.has_proof()                   # whether the active profile defines a [proof]
flagfmt.Filtered(base, keep, name)    # matches of a stand-in that pass keep(str): a refinement, no new regex
flagfmt.PROOF_SHAPE                   # the proof's literal lead + any token body, any case (proof_AAAA): seen only
flagfmt.literal_lead(pattern)         # 'proof_' for 'proof_[0-9a-f]{32}'; '' when no fixed literal start
flagfmt.BRACE_TEXT                    # any event's flag shape, word{...}: seen only (a compiled re.Pattern)
flagfmt.payoff_kind()                 # 'proof' when the profile defines [proof], else 'flag'
flagfmt.PAYOFF_TEXT / PAYOFF_ANYCASE / PAYOFF_SHAPE / PAYOFF_OTHER / PAYOFF_UUID4   # the payoff token model
flagfmt.by_payoff(proof_form, flag_form, name)   # a stand-in that picks by payoff_kind() on every use
flagfmt.uuid4_token(token)            # the token's 32 hex form a v4 UUID (a validator, never a gate)
flagfmt.PACKED_TEXT                   # TEXT without the left boundary: text decoded from fixed-width/binary records (R-16)
flagfmt.find_flags_packed(data)       # find_flags with no left boundary for str and bytes; ff.packed_regex
flagfmt.LEAD_TEXT / LEAD_BYTES        # the flag lead `PREFIX{` (event case rule, no boundary); ff.lead_regex / lead_bregex
flagfmt.cribs(); ff.cribs()           # ('CSCTF{', 'chronos{', ...) in profile order; LookupError with no known prefix
flagfmt.css_like(token)               # the token reads as a CSS rule (btn{color:red}): every declaration's property
                                      # is in flagfmt.CSS_PROPERTIES, a --custom or a -webkit-/-moz-/-ms-/-o- name
flagfmt.shape_reportable(token)       # a shape match may be reported AS A FLAG: event flag/proof format, or not css_like
```

- Text pattern: `(?<![A-Za-z0-9_])(PREFIXES)\{(?:BODY)\}`. Prefixes are literal, longest first. Bytes
  input drops the left boundary (binary data has no word boundaries); proofs also keep a right
  boundary in both forms.
- `case`: `exact`; `prefix-insensitive` (prefix any case, body exact; `normalize` rewrites the prefix
  to the profile's spelling); `insensitive` (whole match; `normalize` lower-cases).
- After B-001a, **no other module defines a flag or proof regex** (enforced by
  `tests/test_single_sources.py`; only `ctf/flagfmt.py` and its contract test are exempt). Engines that
  scan output call `flagfmt`; they do not take the event's regex from the caller. A caller-supplied
  pattern survives only as an optional filter for a **challenge-stated** answer shape (`--pattern` in
  `qr_decode`, `access_db`, `xor_strings`, `classical`), defaulting to the event format.
- Callers that need match objects (spans, `finditer`, `sub`) use `flagfmt.TEXT` / `BYTES`, which are not
  `re.Pattern` instances: call their methods, never pass them to `re.*`. They resolve the event on each
  use, so importing an engine never needs an event; using one without a resolvable event raises
  `EventError`.
- Two strengths, on purpose. `TEXT`/`BYTES` are the event format: anything returned, submitted or
  reported as "the flag". `SHAPE_*` (and `PROOF_ANYCASE`) are broad and exist for the web lane's
  never-wrong rule: a flag-shaped token with a foreign prefix in a baseline, or an uppercase proof,
  must still be *seen* so it makes an auto-return ambiguous or marks a decoy; it is never returned.
- **Payoff tokens (R-06).** What a live target hands out when beaten: an event whose profile defines
  `[proof]` (Huntress: `proof_<32 hex>`, exchanged on the platform) pays off in proofs, every other
  event in flags. The web readers run their never-wrong rule on the payoff stand-ins, so one reader
  serves both models: `PAYOFF_TEXT` (the proof, else the flag format) is the only value returned;
  `PAYOFF_ANYCASE` and `PAYOFF_SHAPE` are seen-only scans for decoys, baselines and near misses
  (surfaced as candidates); `PAYOFF_OTHER` is the other family (`BRACE_TEXT` under a proof event,
  `SHAPE_TEXT` under a flag event), which only makes a payoff ambiguous. A proof is never reported as a
  flag candidate, and a flag in a proof event's payoff is never the answer. Target-visible canaries
  (XXE absent-file names, CORS origins, deserialization keys) carry the active event's slug.
- **Cribs, packed records and CSS (R-16).** A crib or signature that means "the flag starts here" comes
  from `cribs()` / `LEAD_*`, never a literal event prefix (`tests/test_r16_flagfmt_audit.py` scans code
  literals for event-named leads). A reader that decodes fixed-width or binary records to text scans that
  text with `PACKED_TEXT` (or scans the bytes with `BYTES`): a flag may follow a digit or letter of the
  previous field. Text from prose, markup or delimited fields keeps `TEXT`. Under a broad body the shape
  scans (`SHAPE_*`, `BRACE_TEXT`, `PAYOFF_OTHER`) also match CSS; they may keep it in seen, decoy and
  ambiguity sets, but anything that reports a shape match as a flag (a player-flag line, a `flags` list,
  a flag answer form) filters it with `shape_reportable`. So does a module's own hand-rolled `name{...}`
  regex (windows, network). The same test file lists every consumer of a shape scan, and every module
  whose string literals hold such a hand-rolled brace regex, and fails on an unaudited new one.
- In tests, a stated answer format in a question fixture (a `pattern=`/`regex=` keyword, or a
  `"pattern"`/`"regex"` dict value) is challenge data and is not scanned as a flag regex.
- Bytes matches are returned as `str` decoded latin-1. Other encodings (UTF-16, base64 layers) are
  the intake units' job: `ctf/sweep.py` (B-013, `python -m ctf sweep`, run by `ctf pull`) unpacks a
  challenge's files into a scratch copy (`tools/archive_expand.py` with `opts=Walk()`) and matches
  `bregex`/`regex`/`find_flags` on raw, UTF-16, embedded-token and URL-decoded bytes, and
  `ctf/fragjoin.py` joins split image-metadata fragments. Its `SolverResult` (engine `intake.sweep`) is
  `solved` for one distinct flag, `candidate` for several or for joins; it never submits. B-132: the
  walk marks members whose text is where decoys sit (`Walk.doubt`, `{chain: (why, engine id)}`: a
  TI-Nspire document page); a flag the sweep finds only in such members and in the containers around
  them is in `Report.disputed` (`{flag: {"why", "engine"}}`, also in `.sweep.json`), and one disputed
  flag is a `candidate`, not `solved`. It matches
  with the profile it is given only (`embedded_decode.find_blobs(..., flag_re=ff.bregex)`), never the
  live `flagfmt.BYTES`, so `ctf sweep --event` works with `CTF_EVENT` unset. Its credential fence is
  public for engines that walk a challenge folder themselves: `sweep.SECRET_DIRS` (`.ctf`, `.git`) and
  `sweep.is_secret_file(name)` (`.env`, `.env.*`), used by `common.gcm_nonce_intake` (B-060).
- B-029 (`ctf/recover/`) adds members the archive walk does not open: a disk container (QCOW2, VHD,
  VHDX, sparse VMDK, EWF1) unwrapped to `<name>.raw`; an NTFS volume (bare, MBR or GPT) as
  `ntfs-listing.txt` plus `deleted/<path>` and `allocated/<path>` files (opened by the walk in turn);
  a .docx as `tracked-changes/accepted.txt`, `original.txt`, `deletions.txt`, `insertions.txt` (or
  `text.txt`). A decoded hex or base64 run is also tried under single-byte XOR (method
  `decode:<enc>>xor:0x<key>`), gated by the profile's format, off while its prefixes are unknown. A
  flag with XML markup inside whose tag-free text was also found is excluded; flags seen only through a
  tracked change rank first. No new flag regex: all matching is the profile's `bregex`.
- B-076 adds a `socat -v -x` serial log to `ctf/recover`'s members (`solvers/toolkits/serial_capture.py`,
  `members(data)`): each XMODEM transfer (ACKed blocks only, checksum or CRC-16, 128 or 1K blocks, the
  last block's 0x1A padding trimmed) as `socat/xmodem-<n>.<ext>`, or with no transfer each direction's
  bytes as `socat/stream-gt.bin` / `socat/stream-lt.bin`; all opened by the walk in turn. `ctf/fragjoin.py`
  gains an HTTP header source beside `fields()`: `header_fields([(name, value)])` -> `[Field]` (container
  `http:header`, name `<header>` or `<header>:<key>`) of every value or `key=value` item that is strict
  base64 of printable text (`b64_text`, `header_values`), put in part-number order (`part_number`,
  `part_order`: `part1`, `fragment_2`, `3of5`); `join()` is unchanged and takes them as they are. The
  sweep does not call it (a capture is read by `toolkits.http_triage`, whose pcap `[intake]` table runs it).
- B-135 (`ctf/recover/extfs.py`) adds an ext2/3/4 volume (bare, MBR or GPT) as `ext-listing.json`
  (every file with inode and UTC mtime, orphan inodes, the free-block carves), each file as
  `ext/<path>` (an orphan whose blocks still read as `ext/orphan/inode-<n>`), and every validated ELF
  carved from the blocks the block bitmap marks free as `ext-unallocated/blk<N>.elf`. B-011's
  decompile intake reads `unpacked/**/ext-unallocated/` (and only that part of the scratch copy);
  `toolkits.ransom_keystream` reads the listing's mtimes as seed-time candidates.
- B-070 adds two more sources of members, both under the walk's budgets (`Walk.take`). `ctf/polycarve.py`:
  an archive `solvers/toolkits/carving.py` validates inside or behind an image (PNG, JPEG, GIF, BMP, WebP
  by magic) becomes `<image> -> carved@0x<offset>.<zip|7z|gz|bz2|xz>`, other bytes after the image's end
  `<image> -> overlay@0x<offset>.bin`, and both are opened by the same walk; recovery and carving repeat
  on what they add, `sweep.DEEPEN` rounds at most. `ctf/handoutgit.py`: a git repository (a git directory,
  a bare repository, a lone packfile, a bundle) among the unpacked members, or a `.git` folder inside a
  pulled challenge's `files/`, is read as bytes with `solvers/toolkits/repo_supply_chain.py`. No git
  program is ever run on a handout. It gives `<git dir> -> git-report.txt` and, each opened and carved in
  turn, `deleted/<commit7>/<path>`, `unreachable/<commit7>/<path>`, `reflog-only/<commit7>/<path>`,
  `dangling/blob-<id12>`, `unreachable/blob-<id12>`, `index-only/<path>`, `tagged-blob/<id12>`,
  `history/<commit7>/<path>` and `nonstandard/<path>` (on disk `<git dir>.unpacked/`, which `ctf read`
  allows). What one pass adds is searched for repositories again (a repository in a deleted zip),
  `handoutgit.MAX_DEPTH` passes in all, with `MAX_REPOS` counting every pass; a repository left past the
  last pass is a note. An overlay the walk opens itself is not carved from the inside, but an archive
  inside the image before its end (a zip in a private chunk) still is. `sweep.SECRET_DIRS` is unchanged for the flag sweep: a `.git/` folder's raw files are never
  swept or copied, a target in one is refused, and a `.git` outside a pulled `files/` (a drop folder, a
  bare folder, at or above the challenge folder) is never read. `.sweep.json` gains `git`: one object per
  repository (`label`, `chain`, `head`, `refs`, `pseudo_heads`, `commits`, `commits_no_ref_reaches`,
  `not_reached_by_a_ref`, `deleted_files`, `nonstandard_files`, `hidden_dotfiles`, `decoded`, `fragments`,
  `candidates`, `would_run`, `exported`, `report`, `complete`, `problems`). `ctf/numfrag.py` joins
  numbered fragments (`text (2)`, `part 2: text`) found in a repository's files, messages and decoded
  strings; such a join is in the result's joins (`candidate`, never `solved`) and is never written into
  `git-report.txt`. `GitRepo.nonstandard()` lists the files in a git directory that git did not write;
  `find_git` sets `container` and `root` on each `GitRepo`.

## 5. Platform adapter and the submit gate

Interface in `ctf/platform/base.py`; one module per platform kind, `ctf/platform/<kind>.py`
(`ctfd.py`, `gamemaster.py`, `manual.py`), each exposing `make_adapter(profile) -> PlatformAdapter`.
B-005 wrote them. Adding a kind = adding a file (and the kind to `event.PLATFORM_KINDS`).

```python
from ctf.platform import ctfd, gamemaster, manual, policy, rules
ctf.platform.get_adapter(profile)    # policy.SubmitGate over the kind's adapter, rules installed (below)
ctf.platform.adapter_kind(profile)   # the kind get_adapter uses
policy.base_checks(profile, req)     # gate checks 1-4 (below)
rules.install(gate, workdir=None); rules.challenge_key(challenge_id)   # event rules (below)
ctfd.make_adapter(profile, instances=None, session=None, environ=None)   # ctfd.CTFdAdapter, or
                                                     # ctfd.CTFdInstanceAdapter when instances= is given
gamemaster.make_adapter(profile, session=None, environ=None)   # gamemaster.GameMasterAdapter
gamemaster.is_timed(challenge_id)    # a Time Trial / Mastery id: its start runs a clock
gamemaster.is_unsure(value)          # a "??..." answer: never sent
gamemaster.GameMasterAdapter.submit_answers(challenge_id, answers)   # raw batch POST; only the gate calls it
manual.make_adapter(profile, drop_dir=None)   # manual.ManualAdapter: the drop folder, no network
```

```python
class PlatformAdapter(Protocol):
    kind: str
    def list_challenges(self) -> list[Challenge]: ...
    def get_challenge(self, challenge_id: str) -> Challenge: ...
    def download_files(self, challenge_id: str, dest: Path) -> list[Path]: ...
    def submit(self, challenge_id: str, flag: str) -> SubmitResult: ...
    def team_solves(self) -> list[TeamSolve]: ...
    def scoreboard(self) -> list[ScoreRow]: ...

class InstanceCapability(Protocol):           # optional; check supports_instances(adapter)
    def start_instance(self, challenge_id: str) -> InstanceInfo: ...
    def stop_instance(self, challenge_id: str) -> InstanceInfo: ...
    def instance_status(self, challenge_id: str) -> InstanceInfo: ...

class SolvesCapability(Protocol):             # optional (B-099); call base.challenge_solves(adapter, id)
    def challenge_solves(self, challenge_id: str) -> list[ChallengeSolve]: ...
```

```python
from ctf.platform import base
base.ChallengeSolve(challenge_id, account, at=None, account_id=None)   # one team's solve; earliest = first blood
base.challenge_solves(adapter, challenge_id)   # every team's solves, earliest first; NotSupported naming the
                                               # adapter when it has no such call (never an empty list)
```

- Per-challenge solves (B-099): CTFd answers `GET /challenges/<id>/solves` (HTTP 403, scores hidden,
  is `NotSupported` naming it; a solve with no account name is a `PlatformError`, never guessed);
  the Game Master's `challenge_solves` raises `NotSupported` (it publishes no other team's solves) and
  the manual adapter's `NotAllowed`, with no request. The wire journals the read as op `solves` with
  the challenge id. `SolvesCapability` is not part of `PlatformAdapter`, so test doubles without it
  still pass `get_adapter`'s check; the ingester is section 59.

- Challenge ids are `str` at this layer. `Challenge`, `FileRef`, `TeamSolve`, `ScoreRow`,
  `ChallengeSolve`, `InstanceInfo` are frozen dataclasses in `base.py`.
- `SubmitResult(status, message, retry_after, sent, reply)`; `reply` is the platform's reply body
  when the adapter keeps it (Game Master: the dict minus `flag`, for the Hall of Fame pool fields;
  in memory only, never recorded whole; `None` otherwise). `status` is a `SubmitStatus`: `correct`,
  `incorrect`, `already_solved`, `rate_limited`, `paused`, `not_allowed`. `.judged` is false for
  `rate_limited`, `paused`, `not_allowed` (such an attempt must not count as a wrong answer and must
  not block a re-send). `.accepted` = correct or already_solved. `retry_after` is seconds.
- Errors: `PlatformError` (call failed; message names the call), `NotSupported` (operation not offered),
  `NotAllowed(NotSupported)` (the event's rules forbid it). An instance method on an adapter without
  instances raises `InstancesUnavailable` / `InstancesNotAllowed`, which are also `AttributeError`s, so
  `supports_instances()` stays False while a direct call names the reason. `supports_instances(gate)`
  on the `SubmitGate` that `get_adapter` returns judges the adapter the gate wraps (the gate forwards
  instance calls through `__getattr__`, which a `runtime_checkable` isinstance never consults).
- Adapters never raise for a wrong flag; they return `incorrect`.
- A multi-answer platform (Game Master) addresses one answer as `"<challenge id>#<answer id>"`; a
  single-answer challenge takes the bare id. Rules count both against `<challenge id>`.

**Submit policy gate** (`ctf/platform/policy.py`). `ctf.platform.get_adapter(profile)` imports the
kind's module and returns `SubmitGate(adapter, profile)`. A kind with no module raises
`PlatformError` ("no adapter for platform kind ..."). The gate passes read calls through and owns
`submit(challenge_id, flag, *, provenance, confirmed=False, allow_nonstandard=False, guess=False,
rotating=False, sweep=None)`. It refuses with `SubmitResult(NOT_ALLOWED, reason, sent=False)` without calling the
adapter when:

1. the event is manual (code-enforced manual mode: nothing is ever sent);
2. `provenance` is empty;
3. the value is not a flag in the event format, unless `allow_nonstandard=True` (brief-defined answers);
4. `submit_mode = "confirm"` and `confirmed` is false;
5. any check added with `gate.add_check(fn)` returns a reason. A check is
   `fn(profile, SubmitRequest) -> str | None`. The event rules and the queue's dedupe (below), B-173,
   B-044 and B-254 (`residual.install`: no plain value on an id marked residual without
   `confirmed=True`, section 71; it reads the ledger per send, so a corrupt ledger line raises a
   named `ResidualError`) register checks; they do not edit adapters. `gate.refusal(req)` runs them all;
   `gate.send(req)` is one raw send plus the observers.

Checks 1-4 are `policy.base_checks(profile, req)`; for a batch the format check applies to every value. `submit` also takes `guess=False` (an unreasoned
variant of an earlier value) and `rotating=False` (a rotating flag: an incorrect answer is a timing
miss that does not count toward `wrong_answer_stop` for the first `submit.rotating_miss_budget`
misses on a challenge, and counts like a static wrong answer past that, so a sweep sends at most
budget + stop wrong values before the stop holds; only `ctf.dynamic` may pass it, any other caller
gets `ValueError`). After the adapter answers, observers registered with
`gate.add_observer(fn(profile, req, result))` run; one that fails raises `RecordError` carrying
`.result`. `get_adapter` calls `ctf.platform.rules.install(gate, workdir=None)` on every gate (B-005),
which registers an `EventRules` check and recorder: `wrong_answer_stop` (below), `guess_budget`
(judged `guess=True` sends per challenge), and `flag_sharing` (`forbidden`: the record keeps only the
flag's SHA-256). The memory is the ledger, one `platform.submit` record per answered send (section
10; `post_stop`, and `rotating` when set); unjudged answers count toward no limit. A send that raised
is an unjudged `status: "error"` record with an `error` field (written by the queue).
`rules.challenge_key(id)` is the `<challenge id>` part of a multi-answer id.

`wrong_answer_stop` (B-006 decision): after N judged-incorrect answers on a challenge, a send is refused
unless it has `confirmed=True` **and** an unused player approval for that challenge. `confirmed=True`
alone no longer passes (PINK+ OS sent 8 wrong answers on a bare yes). An approval is a
`platform.approval` ledger record `{event_slug, challenge_id, count, reason}` written by
`EventRules.grant(challenge_id, reason, count)` (`ctf submit-queue approve <id> --reason ...`); a
judged send past the stop spends one, an unjudged one does not. With `rules.approved_extras = false`
(B-173) the stop is final: `grant` raises `ValueError` and every send past the stop is refused, an
authorized sweep's included.

**Authorized sweeps** (B-173, section 25). `sweep="<auth id>"` marks one send of a player-authorized
sweep run; only modules in `policy.SWEEP_CALLERS` (`ctf.eventpolicy`, the paced runner) may pass it,
any other caller gets `ValueError`. `EventRules(profile, workdir=None, clock=time.time)`:

```python
r = rules.EventRules(profile, workdir=None, clock=time.time)
r.authorize_sweep(challenge_id, count, reason, ttl_s=None)   # a platform.sweep_auth record (the player's)
r.sweep_auth(auth_id) -> dict | None; r.sweep_used(auth_id) -> int    # judged sends under it
r.sweep_refusal(challenge_id, auth_id) -> str | None                  # why a sweep send may not go now
r.sweep_unclaimed(auth_id, flag) -> str | None        # no run claimed it, or the run never offered flag
rules.sweep_claim_path(workdir, auth_id) -> Path      # the one run's claim file
```

The gate's check refuses a sweep send when either `sweep_refusal` or `sweep_unclaimed` gives a
reason. The claim file `<workdir>/sweeps/<id>.run` is JSON with `pid`, `started`, `challenge_id` and
`offered` (the SHA-256 of each value the run listed before offering it to the gate, never the value).
A send under an authorization no run has claimed, or of a value its run never offered (a hand-written
spool record, before or after the run), never goes; an unreadable claim file refuses by name.

`authorize_sweep` raises `ValueError` when `sweep.mode` is `forbidden`, `count` is outside
`1..sweep.max_count`, `ttl_s` is not in `(0, sweep.ttl_s]`, or the reason is empty. A send with
`sweep` set skips `wrong_answer_stop` and `guess_budget` while its authorization exists for this
event and challenge, is unexpired and has judged sends left; otherwise it is refused with a reason
starting `sweep:`. Its record carries `sweep` and `post_stop: false`; sweep sends count toward
neither the stop nor the budget afterwards and spend no approval. The queue spools `sweep` with the
request, so `drain` resends it under the same authorization (and re-checks it).

**Submit queue** (`ctf/platform/queue.py`, B-006). `get_adapter` also calls `queue.install(gate)`:
`gate.queue` is a `SubmitQueue` and every `gate.submit` goes through `queue.submit(gate, req)`:

1. the stateless checks (manual, provenance, format, confirm) refuse before any disk state;
2. under a cross-process per-challenge lock (`<workdir>/submitq/locks/`; a caller waits for it only
   until its own `max_hold_s` deadline, then the request is left spooled for drain), every check runs
   (`gate.refusal`), so a count-then-send is atomic across processes; the queue's own check refuses a
   value already judged on that challenge id (`duplicate: ...`) and any send on an id the team already
   got accepted (`solved: ...`);
3. the request is spooled (`<workdir>/submitq/pending/<id>.json`, flock-held while its call runs;
   never for `rotating`);
4. it takes the team's turn in `<workdir>/submitq/pace.json` or, when the turn is not free, drops the
   challenge lock, sleeps, and goes back to step 2 (so the checks run again right before the send):
   `submit.per_minute` sends per 60 s,
   `submit.interval_s` between any two, `submit.per_challenge_interval_s` per challenge, and the shared
   pause after a `rate_limited` answer (Retry-After, else 20 s doubling to 120 s) or `paused` (30 s);
5. it sends (`gate.send`) and retries `rate_limited` / `paused` answers until judged or
   `submit.max_hold_s` has passed. Then the result is `RATE_LIMITED` (`sent` says whether anything
   went out, `retry_after` is the next turn) and the spool stays for `ctf submit-queue drain`;
6. a finished call appends a `submit.done` ledger record (`attempts`, `held_s`, `queued`);
7. a send that raises (network error, timeout) is recorded as an unjudged `error` attempt, its spool is
   kept for `drain`, and the exception is re-raised with a note naming drain. It is not resent in-call:
   a timed-out POST may have been judged. A `RecordError` (answered, record failed) keeps no spool.

**Timed fast path and Hall of Fame** (B-044, `ctf/platform/halloffame.py`; its docstring is the
long form). `gate.submit_answers(challenge_id, answers, *, provenance, attempt=None, confirmed=False,
allow_nonstandard=False)` sends every answer of one attempt in ONE request (the Game Master grades a
batch as one) through the same checks, queue, records and observers. A manual event, or a gate whose
adapter is manual, is refused (`NOT_ALLOWED`, `sent=False`) before anything else; an adapter without
`submit_answers` raises `NotSupported`. Its `SubmitRequest` carries `answers` (sorted `(answer id,
value)` pairs) and `attempt` (an `AttemptRef`); `flag` is `policy.batch_flag(answers)`, the canonical
text, so dedupe and the records work unchanged. A batch is one `platform.submit` record (`answers`
count; `partial` when banked with answers still open, which does not make the challenge solved;
`attempt_id` and `ranked_retry` from the `AttemptRef`), and a wrong batch is one wrong answer.

```python
from ctf.platform import AttemptRef, halloffame
AttemptRef(attempt_id=None, deadline=None, ranked_retry=False, eligible=None, origin="unknown", pool=())
policy.batch_flag(answers) -> str              # sorted JSON of {answer id: value}
halloffame.eligibility(challenge_id, *bodies, timed=None) -> Eligibility    # later bodies win
halloffame.pool_of(body); halloffame.counts_of(body)     # run_for_time / hall_of_fame_eligible / variant_fresh; the counts
halloffame.classify_start(body, date=..., elapsed_s=0.0, own_attempt_ids=(), resumed_after_s=1.0,
                          skew_tolerance_s=1.0) -> StartOrigin      # fresh | own | foreign | unknown
halloffame.classify_response(resp) -> (body, StartOrigin)          # a requests.Response: Date, elapsed
halloffame.TimedAttempt.from_reply(gate, challenge_id, body, date=..., elapsed_s=0.0, ranked_retry=False,
                                   record=True, workdir=None)       # classify, check, write hof.start
att.submit(answers, provenance=..., confirmed=False, allow_nonstandard=True) -> TimedResult
att.ref() -> AttemptRef; att.answer_ids; att.deadline; att.attempt_id
halloffame.record_start(profile, challenge_id, body, origin, workdir=None)   # hof.start
halloffame.record_result(profile, req, result, el, workdir=None)             # hof.result
halloffame.own_attempt_ids(profile, challenge_id, workdir=None) -> set[str]   # our recorded starts
halloffame.known_ranked_left(profile, challenge_id, workdir=None, exclude_attempt=None) -> int | None
halloffame.report(profile, workdir=None) -> list[dict]       # hof records, each with a `warn` line or None
halloffame.check(profile, req, workdir=None); halloffame.observe(profile, req, result, workdir=None)
halloffame.install(gate, workdir=None)        # get_adapter does this, after rules.install
```

- `Eligibility(challenge_id, timed, eligible, regular, pool, counts, unranked_by)`: `eligible` is
  False on any explicit false of `run_for_time`, `hall_of_fame_eligible`, `variant_fresh`, True when
  `hall_of_fame_eligible` is true and nothing says false, None when nothing was said (a legacy route or
  an untimed id). `regular` (run_for_time or hall_of_fame_eligible false on a timed id): it scores but
  posts nothing to the fastest-times board; `.note` is the `REGULAR_NOTE` line, `.verdict()` one line,
  `.ranked_left` the last `ranked_attempts_remaining`.
- `StartOrigin(kind, attempt_id, late_s, elapsed_s, reason)`, `.teammate` = `foreign`. An attempt id
  in `own_attempt_ids` is `own`; an unreadable `started_at` or `Date` is `unknown` (never a
  teammate's); otherwise `foreign` only when `Date - started_at` exceeds `elapsed_s +
  RESUMED_AFTER_S + SKEW_TOLERANCE_S` (1.0 + 1.0 s), else `fresh`.
- `TimedResult(result, eligibility)`, `.note`. Who starts a clock is not decided here: the opener
  passes the start (or retry) reply it got.
- `install` registers `check` (an `AttemptRef` with origin `foreign` needs `confirmed=True`, refusal
  word `TEAMMATE`; a `ranked_retry` the server called not eligible, by the `AttemptRef`'s `eligible` or
  by its `pool`, is refused, `NOT_ELIGIBLE`; a `ranked_retry` is refused, `NO_RANKED_LEFT`, when an
  earlier attempt's hof records say `ranked_attempts_remaining` 0 and its own pool does not say
  `hall_of_fame_eligible` true) and the observer (every timed result, a timed id or an attempt with a
  deadline, gets a `hof.result` record from the start pool merged with the result reply, the reply
  winning; a regular attempt prints `NOTE <REGULAR_NOTE>...` on stderr).
- The queue, for a timed `AttemptRef` (one with a `deadline`, a `ranked_retry`, or any `AttemptRef` on
  a timed id, deadline or not): no per-challenge spacing (team budget, spacing and pause still hold),
  never spooled, `submit.done` `queued` false. With a `deadline` it is refused unsent
  (`queue.EXPIRED`) once `deadline - queue.DEADLINE_MARGIN_S` (0.3 s) has passed on this machine's
  clock (no skew allowance beyond the margin) and held at most until then; without one, at most
  `max_hold_s`, then dropped. A
  `ranked_retry` is deduped against its own `attempt_id`'s records only, and needs an attempt id.
  An untimed batch is spooled with its answers and attempt, and `drain` resends it whole.

`queue.pending()` lists spooled sends (`in_flight` or `orphaned`), `queue.drain(gate)` re-submits the
orphaned ones through the gate, `queue.status()` reports the shared budget and pause. A bare
`SubmitGate(adapter, profile)` without a queue runs the checks and calls the adapter once.

**Confident-batch bisect** (B-141, `ctf/bisect.py`; the master re-homing of the Huntress `grade.bank`
splitter onto `gate.submit_answers`). When a confident batch is rejected whole, the bisect sends
proper subsets through the same gate and reads each verdict to bank the right ids and name the wrong
one(s), inside the attempt. It is never-wrong: it banks only values the solver already computed, every
banked id was in an accepted sub-batch, every bad id was rejected *alone*, the whole batch is never
resent and no identical set goes on the wire twice.

```python
res = bisect.bisect(gate, challenge_id, answers, *, provenance,
                    split=None, suspects=(), stop=None,
                    allow_nonstandard=False, confirmed=False) -> bisect.BankResult
# BankResult(banked, bad, unchecked, requests, solved, stopped, last)
```

`suspects` (the ids a live `day_patch` answered) are isolated first: the non-suspects go out as one
batch, and when they are accepted the split is confined to the suspects (a wrong answer outside the
suspects falls back to the classic order, one extra request). `split(answer_id) -> family_key`
optionally cuts on a family boundary before halving. `stop()` is checked before every send; when it is
true the run ends and the unreached ids are `unchecked` (a non-verdict reply ends it the same way).

**Live per-lane lock** (B-141, `ctf/lanelock.py`; distinct from `ctf/promote.py`, which is post-event
promotion). Under `<workdir>/lanes/`: `lanelock.lane_lock(workdir, lane, blocking=True)` is the
exclusive `flock` a lane holds while it runs its submission; `set_promote_wanted` / `promote_wanted` /
`clear_promote_wanted` raise, read and lower the `<lane>.promote-wanted` flag; `promote_waiting(...)`
raises the flag, blocks on the lock, and clears the flag once the lock is held.
`lanelock.yield_stop(workdir, lane, *, deadline)` is the `stop` for `bisect.bisect`: on a **no-deadline**
attempt it yields the lane once the flag is up (a waiting promote), and on a **deadline** attempt it
returns `None`, so a timed bisect never reads the flag.

**Probe tier** (B-221, `ctf/probetier.py`; Huntress Day 28's fixup priority). A probe job
`ProbeJob(challenge_id, answer_ids, open_ids=(), options={}, deadline=None, bad=False, split=False,
source="")` is classified `fixup` (options built for every id, it covers every open id of the base, the base
has no rejected or held answer, not a split, no deadline), `low` (a split, or a base with a rejected or held
answer) or `normal` (anything else): `probetier.classify(job) -> (tier, why)`, `probetier.order(jobs)` best
tier first and stable within a tier. `probetier.turn(job, *, lane, workdir=None, blocking=True,
on_wait=None)` is the job's turn on the lane lock: a fixup job raises the promote-wanted flag before it
tries the lock and keeps it up while it waits, as `lanelock.promote_waiting` does (so a held no-deadline
split yields to it), and any other job waits on `lanelock.lane_lock` alone. `on_wait()` is called once,
just before the turn waits on a held lane (never on a free lane, never with `blocking=False`, which raises
BlockingIOError). `probetier.stop_for(job, *, lane, workdir=None)` is
the `stop` of a job's own send loop: `None` for a fixup or a deadline job, else `lanelock.yield_stop`.
`probetier.job_from_report(report, challenge_id, *, deadline=None, bad=False, source="ask-readers")` is the
job of an ask-readers report (its offers settle, every MISSING id is open; `ProbeTierError` with no offer).
Nothing is sent by the module; at the wire every submission is already the `priority` class. Its caller is
`ctf ask-readers probe`: the job's `turn` around `askreaders.probe(..., stop=stop_for(job))`, the tier in
the JSON report as `probe_tier: [tier, why]` (null when nothing was offered). On a held lane it prints
`lane <lane> is held; waiting for it at the <tier> tier` to stderr before it waits; `--no-wait` exits 2
instead, with nothing sent.

Selection: `ctf.platform.adapter_kind(profile)` is the kind `get_adapter` uses: `manual` whenever
`rules.ai_on_platform = "forbidden"`, whatever `platform.kind` says, else `platform.kind`. Manual
mode (`manual.py`) has no network code: `submit`, `scoreboard` and instance calls raise `NotAllowed`;
reads come from the drop folder `<workdir>/drop/<challenge id>/` (optional `challenge.toml` with
name, category, points, description, connection_info, tags; an optional `SOLVED` marker whose first
line names the solver; every other file is a challenge file).

Manual-mode cockpit (B-209, `ctf/cockpit/`, `python -m ctf cockpit`): the player's side of that
drop folder. It files drops from `<workdir>/inbox/` into `<workdir>/drop/<id>/files/` (so the
adapter's file names read `files/<name>`), keeps needs and a submission queue in
`<workdir>/cockpit/state.json`, and refuses any event whose `adapter_kind` is not manual. A player's
verdict on a hand-submitted value is written as a `platform.submit` record (through
`rules.EventRules.record`), so `wrong_answer_stop` and `guess_budget` count manual submissions too;
an accepted verdict is the only thing that writes `SOLVED`. Like the gate, the cockpit checks
`EventRules.check` again before each send: `next` never serves, and a verdict refuses, a queued item
the rules now refuse ("held"); `confirm` is the player's `confirmed=True` for one item.

Credentials: `CTF_TOKEN` (CTFd `Token`, Game Master `Bearer`), else for CTFd `CTF_COOKIE`; never
printed. `CTF_PLATFORM_URL`, if set, must equal the profile's `base_url` (the profile is the source).
A loopback Game Master URL (`http://127.0.0.1:<port>`, a rehearsal fake) gets no credentials.

Instances (B-003): `ctfd.make_adapter(profile, instances={"endpoints": {...}, "cap": N})` returns a
CTFd adapter with `InstanceCapability` through `ctf.instances` (plugin shapes `docker_per_team`,
`ctfd_docker`) plus `renew_instance` (extend the clock; not in the `InstanceCapability` Protocol —
callers duck-type it). With no explicit `instances=`, `make_adapter` reads the profile's `[instances]`
section (`profile.instances.as_config()`), so `get_adapter(profile)` yields the instance adapter for
an event that configures a plugin; an event with no `[instances]` section still gets the plain adapter,
whose instance calls raise `InstancesUnavailable`. Game Master `start_instance` is the attempt start;
it refuses Time Trial / Mastery ids (they start a clock). The value-ordered slot scheduler is
`ctf.instsched` (`plan`, `apply_plan`, `select_needs`, `due_for_renewal`, `SlotLedger`,
`permission_allowlist`), driven by the `ctf instance` CLI (section below): it starts the highest-value
open challenges up to the cap, frees a slot the moment a challenge is solved, and with
`--renew-within S` renews running unsolved instances expiring within S seconds. The engine's own cap
(`ctf.instances.Instances`) is per process; the CLI's cap binds across processes through the
`SlotLedger` (every instance started through the CLI, re-read live before each `start`/`schedule`).

Rule: nothing outside `ctf/platform/` calls `make_adapter` or a raw adapter's `submit`. `ctf submit`,
`python -m ctf.submit send|approve` and `ctf.dynamic.solve_dynamic(gate, challenge_id, retrieve, ...)`
go through `get_adapter` (B-006). The carried library function `ctf.submit.guarded_submit` keeps its
own tried.json guards and has no caller in the repo. `CTFdAdapter.server_time()` (one HEAD, the
`Date` header) gives `ctf.dynamic` the platform clock; the CTFd adapter's machine-wide pacing floor
(`ctf.client.SubmitPacer`) uses the profile's `submit.interval_s`.

Manual mode on the carried path (R-02, `ctf/platform/legacy.py`): until then every carried platform
call asks `legacy.require(call, submit=..., profile=None)` first (the profile passed, else
`event.current()`), and it raises before any session, socket or name lookup:
`NotAllowed` when the event is manual (`platform.kind = "manual"` or `ai_on_platform = "forbidden"`,
reads included) or, for a send, `submit_mode = "manual"`; `NoProfile(NotAllowed)` when no profile
loads (fail closed); `NotSupported` when the platform is not CTFd. Callers: the `ctf.client.CTFd`
constructor (`CTFd(cfg, profile=...)`, kept as `.profile`) and `CTFd.submit`, `guarded_submit` (the
client's `.profile`, else the current event), and `ctf.fastlane`'s rules-page GET. The gate-based
`ctf submit`, `python -m ctf.submit send`, `ctf submit-queue drain` and `solve_dynamic` ask the same
rule (`legacy.resolve` / `legacy.refusal`, raising only its `NotAllowed`) before any adapter, lock or
file exists. The `ctf` CLI and `python -m ctf.submit` print
`refused: <reason>` and exit 4 on a refusal.

```python
from ctf.platform import legacy
legacy.require(call, submit=False, profile=None)   # resolve, then check; returns the profile
legacy.resolve(call, profile=None)     # the profile passed, else event.current(); legacy.NoProfile when none loads
legacy.check(profile, call, submit=False)          # raises the refusal, if any
legacy.refusal(profile, call, submit=False)        # the NotAllowed / NotSupported to raise, or None
```

**The wire: per-request journal and release-minute budget (B-140, `ctf/platform/wire.py`; its
docstring is the full contract).** `get_adapter` ends with `wire.install(gate, adapter)`: the
adapter's HTTP session (`_s`) is wrapped in a `WireSession`, so every request of the CTFd and Game
Master adapters, reads included, is journaled and budgeted. An adapter with no session (manual, a test
double) gets none. The carried CTFd client (`ctf.client`, section 17) is not wrapped.

```python
from ctf.platform import wire
wire.of(gate)                          # the gate's Wire, or None; .lane = "watch" names this process's lane
wire.install(gate, adapter)            # done by get_adapter; idempotent
w = wire.Wire(profile, kind=None, workdir=None, pace=None, lane=None)   # lane default: $CTF_WIRE_LANE
w.send(request, method, url, **kw)     # budget, send, journal; w.status() the shared counts now
wire.op_of(kind, method, url, base_url=None, params=None, json_body=None)  # (op, challenge id)
wire.op_class(op)                      # "priority" (submit, start) | "poll" (list) | "read"
wire.decide(pace, rows, now, lane=lane, cls=cls, anchors=(), pause_until=0.0)   # (wait s, reason)
wire.active_anchors(anchors, now, pace)                 # anchors whose release window holds now
wire.next_pause(pace, now, retry_after, last_429, last_pause)
wire.limit_headers(resp)               # Retry-After, X-RateLimit-*, RateLimit-* only
wire.wire_dir(workdir); wire.journal_path(workdir)
wire.mark_releases(workdir, anchors, now=None); wire.clear_releases(workdir)
wire.profile_anchors(profile)          # dates.start when it is a datetime with a zone
wire.read_journal(workdir, since=None) # (rows, unreadable line count)
wire.ratelimit_report(rows)            # per 429: n60, nmin, second, mix by op / lane / class
```

Journal `<workdir>/wire/journal.jsonl` (0600, one line per request): `ts`, `asked`, `held_s`,
`held_by` (`pause` | `team` | `release` | `poll_gap` | `poll_inflight` | `lane` | null), `forced`, `dur_s`, `op`,
`method`, `cls`, `lane`, `pid`, `challenge`, `status`, `error`, `n60`, `nmin`, `rel_s`, `kind`, and on
a 429 `retry_after`, `pause_s`, `limit_headers`. Never a URL, body, flag, credential or any header
but the rate-limit ones. Budget rules in order, from the profile's `[wire]` table (section 1): a 429
pause holds everything (Retry-After, else `pause_s` doubling); `per_minute` and `release_budget` hold
reads and polls at the cap less `reserve` and priority requests at the cap; inside a release window
list polls are `release_poll_gap_s` apart from `+release_poll_free_s`, and a named lane's reads stop
at its `lane_budget`. **Poll inflight (B-252):** at most `Wire(poll_inflight=, default
wire.POLL_INFLIGHT=2)` list polls run at once, every process together — a poll is held (`held_by`
`"poll_inflight"`) until a slot frees; a slot is taken when a poll is admitted and freed when its
request returns or raises, and one older than `wire.POLL_INFLIGHT_TTL_S` is reaped (a crashed
process). It caps concurrency (`state.json` `poll_inflight`: `[pid, token, started_ts]`), so it is
never forceable and never lifted by the sole-lane rule; `poll_inflight=0` turns it off.
`wire.live_inflight(entries, now, ttl=)` is the slots still live. A request held `max_wait_s` is let go by the release, poll-gap and lane budgets
(`wire.FORCEABLE`; `forced`, one stderr line) but never by a pause or the `per_minute` cap, which
stands for the platform's own limit (a team-cap hold past `max_wait_s` prints one line and waits on).
`wire.decide(..., lift=FORCEABLE)` is the rule without those budgets; `Wire.admission(lane, cls)` is
`admit` as a generator of waits (for simulations). Release anchors: `dates.start` and
`wire.mark_releases` (`ctf watch run` records its `--wave` / `--daily` anchors, `ctf wait
--not-before` its start; `ctf wire mark-release`). A wire dir that cannot be
written raises `wire.WireError` (a `PlatformError`) before anything is sent.

The wire's journal row also carries `exempt` (`"sole_lane"` or null) and `bytes` (the response's
Content-Length, or null; `dur_s` is the time to the response headers, so a streamed artifact body
is read after it). **Sole-lane exemption (B-185):** a named lane that is the only one still working
in a release window is exempt from the release, poll-gap and lane budgets, never from a pause or
the `per_minute` cap: at least one other lane is known in the window (a read or priority request
in it, a `release_lanes` name, or a done mark since the anchor) and every one is marked done since
the anchor. The watcher's lane (`wire.PASSIVE_LANES`) never counts; an unnamed non-poll request
always does and is never done.

```python
wire.sole_lane(rows, lane, anchors, now, pace, done)    # done: {lane: when marked done}
wire.mark_lane_done(workdir, lane, done=True, now=None) # {lane: when}; done=False: working again
wire.content_length(resp)                               # int or None
```

**The release latency path (B-185, `ctf/platform/latency.py`; its docstring is the full
contract).** Pre-warmed connections, parallel list and start, phase timing from the first request,
status-only recovery of a non-idempotent start, and the wire-floor table per mode. Files, all
under `<workdir>/wire/` (0600): `phases.jsonl` (one row per timed step: `run`, `challenge`,
`mode`, `phase`, `t0`, `t1`, `dur_s`, `rel_s` since the release anchor, `ok`, `error`, `pid`, plus
step fields such as `bytes`, `state`, `polls`), `starts.json` (the persisted start record per
challenge: `state` posting | preparing | ready | unknown | absent, `posts`, `open_posts`,
`first_post`, `last_post`, `polls`, `alerted`) and `floors.json` (`ctf latency floors --write`).

```python
from ctf.platform import latency
latency.warm(gate, 2, phases=None)      # open idle keep-alive connections in the session pool, no request
latency.parallel(calls, phases=None, clock=time.time)   # {name: Outcome(value, error, t0, t1)}; errors kept
res = latency.open_release(gate, cid, anchor=None, lead_s=2.0, connections=2, start=True, dest=None,
                           timeout_s=600.0, alert_after_s=45.0, workdir=None)   # ReleaseOpen
g = latency.StartGuard(gate, workdir=None, alert_after_s=45.0, max_posts=2, post_grace_s=40.0,
                       phases=None, alert=None)   # g.start / recover / await_ready / ensure_ready -> StartOutcome
g.start(cid, post=None)   # post(cid) -> InstanceInfo replaces start_instance; only with it is a timed id taken (B-231)
latency.pending_starts(workdir); latency.clear_start(workdir, cid)
log = latency.PhaseLog(workdir, challenge=None, run=None, anchor=None, mode=None, kind=None)  # .span(), .mark()
latency.read_phases(workdir, since=None)                # (rows, unreadable line count)
latency.run_report(phase_rows, journal_rows, challenge=None)   # per run: first request, phases, missing
latency.floor_table(phase_rows, journal_rows, kind=None, records=None, bank_counts=None)  # +bank per timed mode
latency.parse_records(items); latency.write_floors(workdir, table)
latency.mode_of(kind, challenge); latency.poll_interval(elapsed_s); latency.workdir_of(gate)
latency.is_timed(kind, challenge); latency.phases_path(workdir)
# --- the timed opener and the pipeline floor (B-252) ---
latency.open_timed(gate, cid, starter=None, anchor=None, lead_s=2.0, connections=2, dest=None,
                   timeout_s=600.0, action="start", list_poll=True, workdir=None)   # TimedOpen
latency.ladder_on_green(gate, base, lane, starter=None, workdir=None, root=None, planner=None,
                        require_green=True, ...)   # start the next mode off a gate-green event
latency.gate_green(workdir, lane); latency.latest_gate(workdir, lane)   # the lane's newest adapt.gate
latency.submit_rtt(journal_rows, kind=None, lane=None)                  # per-submit round-trip stats
latency.bank_submit_floor(journal_rows, count=, kind=None, lane=None)   # cumulative bank-submit floor
from ctf.platform import gmtiming
gmtiming.bank_counts(slug, modes)   # {timed mode: cumulative base-bank size} from the event's profile
# --- no-model timed-start routing (B-231) ---
from ctf.platform import timedstart
st = timedstart.TimedStarter(gate, workdir=None, guard=None, err=None)   # also timedstart.router(gate, workdir=None, err=None)
info = st(cid)                       # -> InstanceInfo; st.results[cid] is a StartRoute
st.read_openapi()                    # GET op=openapi through the wired session (journal op "openapi")
timedstart.start_body_from_openapi(doc, cid)   # {"challenge": cid, "run_for_time": True, required consts...}
timedstart.start_schemas(doc)        # the POST JSON schemas naming `challenge` that are not a submit
timedstart.remembered_body(workdir); timedstart.remember_body(workdir, body, learned_from=, refused=, now=None)
timedstart.forget_body(workdir); timedstart.body_path(workdir)   # <workdir>/wire/start_body.json
# errors: timedstart.TimedStartError (PlatformError); timedstart.TimedStartRefused (NotAllowed: word, status)
```

**No-model timed-start routing (B-231, `ctf/platform/timedstart.py`).** The default `starter` of
`open_timed` / `ladder_on_green`. The start body (the event's remembered body, else the default
`{"challenge": id}`) is POSTed through `StartGuard.start(cid, post=...)`, so the `starts.json`
record keeps every process from a second clock start while one is pending. A refusal another body
can cure (an HTTP 4xx with a word outside `NOT_BODY_WORDS`: rate_limited, already_solved,
base_not_solved, ...) reads op=openapi once and retries once with `start_body_from_openapi`'s body
(`run_for_time: true` when a start schema lists it; every other required property from its const,
one-value enum or default, never guessed). No start schema, an unnamed required value, a derived
body equal to the refused one, a failed openapi read or a second refusal is a `TimedStartError`
(no third POST); `open_timed` reports it as `errors["start"]`. A reply with an attempt goes through
`halloffame.TimedAttempt.from_reply` (the `hof.start` record and the pool fields); a regular
attempt on a timed id prints the halloffame NOTE. A derived body that got an attempt is remembered
in `<workdir>/wire/start_body.json` (no challenge id) and goes first for every other lane; a file
that does not parse raises `TimedStartError` and sends nothing. A POST of unknown outcome (it
raised, or answered 5xx or any other non-4xx error, word or not) is resolved by status only (`TimedStartError` when still unknown), never re-sent with another body.

**The release pipeline floor (B-252).** `open_timed` is the warm opener for a timed mode: warm at
`anchor - lead_s`, then at the anchor the clock start (through `starter(cid) -> InstanceInfo`) in
parallel with a list poll (poll-to-detect), a read-only provisioning wait if still starting, the
download, and the `ready` mark — every step a PhaseLog row for the timed mode, so `floor_table`
gets its opening floor. A timed start runs a clock and is never recovered by a re-POST of the same
body; `starter` defaults to **B-231's** no-model route (`timedstart.router`, below), which sends at
most one retry, with the op=openapi body, after a definite refusal. An untimed id is refused (`NotAllowed`: use `open_release`). `open_timed` sends no submit —
no submit barrier is moved. `ladder_on_green` fires `open_timed` when the lane's newest `adapt.gate`
record is green and `chain.plan` (the `planner` seam) says `start`/`retry`, else reports the chain's
reason without starting. `bank_submit_floor` is the cumulative bank-submit critical path (`count x`
the measured per-submit round trip): the flat-seconds gate the timed ladder waits behind; the
event-specific bank sizes live in `ctf/platform/gmtiming.py` (Huntress 1300-1516), out of the shared
path. `floor_table(..., bank_counts=)` adds a `bank` field per named timed mode; it is reported,
never folded into `floor_s` (the bank is a base-lane barrier, not the mode's own opening).

Rules: a start POST is sent once per attempt; while the start record is posting, preparing or
unknown, `start()` sends one status read instead. A POST that raised leaves the outcome unknown,
resolved by status. A POST is re-sent only when status says no attempt exists and the last POST is
older than `post_grace_s`, at most `max_posts` unanswered POSTs (then `latency.StartRefused`, a
`LatencyError`, which is a `PlatformError`). The provisioning alert fires once per attempt across
processes, `alert_after_s` after the first POST (stderr line, a `provision_alert` phase row, the
`alert` callback). A Game Master Time Trial or Mastery id is refused (`NotAllowed`) before any
request (unless `start(cid, post=...)` is given: the opener's clock start, B-231). A start record
that does not parse raises `LatencyError` and sends nothing.

## 6. Engine manifest, router and runner (B-186, B-187)

One sidecar per engine, `<module>.manifest.toml`, beside the module (e.g.
`solvers/common/rsa_lattice.manifest.toml`). File-per-engine, so parallel builders never edit a shared
registry. Sidecars are found under `solvers/` and `tools/` (`manifest.ENGINE_ROOTS`); one elsewhere is
not an engine. Every top-level `solvers/<lane>/<name>.py` with a public def/class or a `__main__`
block is an engine module and needs one (`_`/`test_` files and sub-folders are helpers; a racer
candidate `dNN_<role>_dev.py`, `layout.RACER_CANDIDATE_RE`, is gitignored work in progress, section 72). Generated
artefacts (`docs/coverage/ENGINES.md`, later the triage and capabilities pages) are built from the
sidecars, never hand-edited. Working procedure: `docs/BUILDING.md`.

```toml
id = "metadata_forensics.exif_dump"   # required; unique; <lane>.<name>, lower_snake; a dashed lane folder becomes _
lane = "metadata-forensics"           # required; the solvers/<lane>/ folder name as written (dashes allowed)
entry = "solvers.metadata-forensics.exif_dump:solve"   # required; see "Entry" below
capabilities = ["executes", "exif"]   # tags [a-z0-9][a-z0-9_.+-]*: one class tag, then flags and topics
inputs = ["ext:.jpg", "magic:ÿØ"]   # free strings, informational: routing never reads them
needs_tools = ["exiftool", "py:PIL"]  # binaries or "py:<module>"; same names as the needs_tool marker
cost_class = "cheap"                  # cheap | medium (default) | heavy
status = "active"                     # active (default) | experimental | plan-only | retired

[[routes]]                            # zero or more; an engine with none is a lint error unless retired
category = ["forensics"]              # lower-case canonical categories (triage.canonical_category)
keywords = ["exif", " gps"]           # lower-case substrings of the lower-cased description
files = ["magic:ÿØÿ", "ext:.jpg", "name:IMG_*"]   # matchers, below
priority = 60                         # integer 0-100; higher runs first; set it (default 50)

[intake]                              # optional (B-002): the input adapter; without it intake never runs the engine
select = "files"                      # route (default): when the router routes the challenge here | files: on a `match`
run = "per-file"                      # required: per-file | all-files | folder | challenge (module:function entries)
match = ["magic:ÿØÿ", "ext:.jpg"]     # file matchers (route syntax); required for per-file, all-files, select = "files"
args = ["--json", "{file}"]           # argv after a cli entry; default ["{file}"] / ["{files}"] / ["{folder}"]
max_files = 8                         # 1-64 (default 8): per-file runs, or all-files files, at most
timeout = 30                          # 1-600 seconds (default 30) for one run
spawns = false                        # true: it starts other programs, so it runs only under the OS sandbox
originals = false                     # true (per-file only): also given the handout files the sweep left out for size
```

**Intake input adapter** (`[intake]`, B-002, section 19). `args` placeholders: `{file}` (per-file only),
`{files}` (all-files only; a whole item, it expands to one argument per file), `{folder}` (the sweep's
scratch copy, originals plus unpacked members), `{challenge}` (the challenge folder), `{out}` (the
engine's own folder `recon/engines/<id>/`, also its working directory). The input must reach the
engine: a per-file run names `{file}`, all-files `{files}`, folder `{folder}` or `{challenge}`. A
module:function entry takes `run = "challenge"` and no `args` (it is called as
`fn(challenge_dir, profile)`); a cli entry never does; a `library` engine cannot have the table. Every
violation is a `ManifestError` at discovery. `inputs` stays informational: intake reads `match`, never
`inputs`.

`originals = true` (B-136; `run = "per-file"` only, anything else is a `ManifestError`): the sweep copies
no original over `ctf.sweep.MAX_SOURCE` (256 MiB; `MAX_SOURCE_TOTAL`, 512 MiB, in all) into its scratch
folder, so an engine matched against the scratch copy never sees a memory or disk image of a real size.
An engine that says `originals = true` is also matched against the handout files the sweep did not read
(`engines.left_out`) and is given each as `{file}` by its own path under `files/`. It must read its
input by offset or mmap, never whole; `{folder}` is still the scratch copy. Engines without the key are
given nothing more than before (`toolkits.vol_triage` is the first to set it).

Validation (`ctf.engines.manifest`, all `ManifestError` naming the file and dotted key): unknown keys
are an error at the top and in a route; `id`, `lane`, `entry` are required; enums are checked; a
boolean is never a number or string; list entries must be distinct; keywords and categories must be
lower-case; `priority` is an integer 0-100.

**Entry.** Two forms:

- `"module:function"`: `module` is a dotted **repo path** (each part `[A-Za-z0-9_][A-Za-z0-9_-]*`),
  resolved to a file by splitting on dots (`<root>/solvers/metadata-forensics/exif_dump.py`, or a
  package `__init__.py`), so a dashed lane folder works although it is not an importable package
  name. The function is `fn(challenge_dir: Path, profile: EventProfile, **opts) -> SolverResult`.
- `"cli:<argv0 ...>"`: shell-split. `cli:python <script>` runs a repo-relative script (no absolute
  path, no `..`) as `__main__` with the engine `sys.path`; any other argv0 is an external command,
  arguments appended. A CLI engine prints one `SolverResult` JSON object as its last non-empty
  stdout line and exits 0 for any result (non-zero only for a crash), unless tagged `legacy-output`.

**Dotted engine imports** (R-17, `ctf/solverpkg.py`). Separate from the entry resolution above (which
is by file and keeps the dash): an engine module is also importable as `solvers.<lane>.<module>`. The
identifier-named lanes resolve through the `solvers` namespace package; the dash-named lanes resolve
under their underscore spelling (`solvers.script_analysis`, `solvers.metadata_forensics`,
`solvers.mobile_android`) through `solverpkg.DashedLaneFinder`, a `sys.meta_path` finder that
`import ctf` installs (idempotent; `solverpkg.install()` / `uninstall()`). Preconditions and
invariants: the underscore names resolve only after `import ctf`; the finder answers only those three
names, against the parent search path it is given (`solvers.__path__`), in order (the first portion
holding the dashed folder wins); `solvers/` has no
`__init__.py` and must not get one (it stays a namespace package, SH-06); the dashed folders are not
renamed. The dotted and flat imports of one file are two module objects, so module-level state is not
shared between them.

**Capability tags.** The first tag is the class (`generate.CLASS_TAGS`): `executes` (runs end to end
and scans its output for flags), `analysis` (reports facts), `plan` (prints candidates, never runs
them; pair with `status = "plan-only"`), `library` (import-only carried module: its entry names its
main public function, and `ctf run` refuses it with a message instead of guessing). Flags with
meaning to the runner: `legacy-output` (a carried `cli:python` script that prints free text; the
runner does not parse a `SolverResult` from it), `cli`, `documented` (a `docs/toolkits/<name>.md`
exists). Topic words follow (`rsa`, `pcap`, ...).

**Routes** (`ctf.engines.router`). A route matches when every condition it states holds: the
canonical category is one of `category` (none = any), the description contains one of `keywords`
(substring, so `" hci"` keeps its leading space), and a downloaded file (searched recursively)
matches one of `files`. File matchers: `magic:<text>` (the first 4096 bytes start with the text,
encoded latin-1; use TOML `\u00XX` escapes for high bytes), `ext:.x` (case-insensitive suffix of
the file name, so `ext:.tar.gz` works), `name:<glob>` (fnmatch on the file name). A route with no
condition never matches (and is a lint error). An engine's score is its best matching route's
priority, default 50 when unset; when several of its matching routes share that priority, the first
one listed gives the hit's reason; engines of equal priority sort by id; `retired` engines are never
routed. `ctf engines lint` treats an unset priority on a conflicting route as ambiguous (rules in
`docs/BUILDING.md`).

```python
from ctf.engines import manifest, router, runner
manifest.discover(root=None)        # [Manifest] sorted by id; ManifestError naming every bad file / duplicate id
manifest.scan(root=None)            # ([Manifest], [Problem]) collecting instead of raising (lint)
manifest.load(path); manifest.parse(data, path); manifest.parse_entry(path, raw) -> Entry
manifest.parse_intake(path, raw, entry, capabilities=()) -> IntakeSpec   # the [intake] table, checked against the entry
# IntakeSpec(run, select, match, args, max_files, timeout, spawns, originals); manifest.INTAKE_RUN, INTAKE_SELECT, INTAKE_PLACEHOLDERS
manifest.manifest_files(root=None); manifest.sidecar_for(module_path)
# Manifest(id, lane, entry_raw, entry, path, capabilities, inputs, needs_tools, cost_class, status, routes, intake)
#   .module_path .name .basename .rel_module(root) .has(tag); Route(...).effective_priority; Entry.target_file(root)
router.route(category, description="", files_dir=None) -> [Hit]      # Hit(manifest, priority, reason), best first
router.route_heads(manifests, category, description, heads) -> [Hit] # the same ranking over [(file, first bytes)]
router.route_matches(route, cat, text, heads); router.canonical_category(cat)
router.rank(entries, category, description="", files_dir=None, *, heads=None)   # [(key, priority, reason)] best first; entries = [(key, routes)]; heads replaces the files_dir walk
router.magic_bytes(val) -> bytes      # what a `magic:` matcher names: `0x<hex>` is bytes, anything else the text
router.engine_paths(category, description="", files_dir=None)       # repo-relative module paths
runner.resolve(name) -> Manifest     # id, name after the lane, basename or path; EngineError if missing/ambiguous
runner.run(name, args, record=True, challenge_id=None) -> int
runner.command(engine_id, args, ...); runner.boot_script(); runner.child_env()
runner.recording_enabled(no_ledger=False); runner.record_run(engine_id, exit_code=, seconds=, via=, status=None, challenge_id=None)
```

**Running.** `python -m ctf run <engine> [args...]` and `tools/ctfpy <engine> [args...]` both start
`<python> -I ctf/engines/_boot.py`, which puts `tools/`, every `solvers/<lane>/` and the repo root on
`sys.path` in the test suite's precedence (`layout.sys_path()`), exports `CTF_WORKDIR` from
`paths.workdir()` when it resolves, and runs the entry. A function engine is called as
`ctf run <id> <challenge_dir> [--opt key=value]... [--event slug]` (`--opt` values are JSON when they
parse, else strings) and its `SolverResult` JSON is printed.

**`engine.run` ledger record.** Every run appends one record to `<workdir>/ledger.jsonl`:
`{"ts", "event": "engine.run", "engine": <id>, "via": "ctf-run" | "ctfpy" | "intake", "exit_code": int,
"seconds": float, "status"?: <SolverResult status, when one was parsed>, "challenge_id"?: str}`.
With no resolvable workdir the engine still runs and stderr says it was not recorded and why;
`--no-ledger` or `CTF_ENGINE_LEDGER=0` turns recording off on purpose. `python -m ctf engines usage`
(`ctf.engines.usage`) turns the records into real-use counts.

**Engine tooling** behind `ctf engines lint | generate | coverage | usage` (procedure and lint rules
in `docs/BUILDING.md`):

```python
from ctf.engines import layout, lint, generate, coverage, usage
layout.lanes(root=None); layout.engine_modules(root=None)   # solvers/<lane>/ names; every module that needs a manifest
layout.is_engine_module(p); layout.flat_owner(basename, root=None)   # first file a flat `import <basename>` hits
layout.sys_path(root=None)                    # engine import path: tools/, the lanes, the repo root
lint.lint(root=None, baseline=None, known_categories=None) -> [Finding]   # Finding(code, severity, subject, message).line()
lint.claims_overlap(cat_a, kw_a, files_a, cat_b, kw_b, files_b)        # claim keys two routes share (empty = none)
lint.baseline_path(root=None); lint.load_baseline(root=None); lint.write_baseline(lines, root=None)
lint.stale_baseline(findings, baseline)       # baseline lines that no longer fire
lint.load_duplicate_docs(root=None)           # {basename: DuplicateDoc(basename, files, flat_import, reason)}; ValueError if malformed
planned, skipped = generate.plan(root=None, triage_path=None)   # [Planned(module, sidecar, text)], skip reasons
generate.write(planned) -> int                # sidecars written
generate.analyze(path) -> Facts               # static facts: parses the module, never imports or runs it
generate.classify(facts); generate.cost_class(needs, facts); generate.needs_tools(facts, repo_names)
generate.topic_tags(facts, doc_text, limit=10); generate.engine_id(module, root); generate.lane_of(module, root)
generate.assign_priorities(routes)            # carried triage order -> route priorities
generate.render_manifest(mid=, lane=, entry=, capabilities=, inputs=, needs=, cost=, status=, routes=, notes=)
coverage.matrix_path(root=None); coverage.render(root=None); coverage.write(root=None); coverage.is_stale(root=None)
coverage.tests_referencing(root=None)         # module path -> test files that import it or name its path
uses = usage.collect(workdirs)                # {engine id: Use(engine, runs, failures, last_ts, statuses)}
usage.report(uses, manifests) -> str
```

Routing (R-10). The manifests are the only routing source. `python -m ctf engines generate` renders
from them `ctf/engines/route_table.jsonl` (one JSON line per route of every engine not retired:
`id, path, class, priority, category, keywords, files`), `docs/CAPABILITIES.md` and
`docs/coverage/ENGINES.md`; each has a currency test, and `generate --check` exits 1 when one is stale.
`ctf.triage.suggest()` reads the table (a missing or malformed one raises `RouteTableError`) and lists
every engine with a matching route once, at its best matching route's effective priority (omitted =
50), best first, ties by id; `ctf engines route` ranks the live manifests the same way
(`router.rank`). `suggest()` returns `category, playbook, engines, routes, files`; `routes[i]` is
`{engine, id, class, priority, reason}`. `triage.CATEGORIES` lists the canonical categories;
`triage.CATEGORY_ENGINES` and `triage.IMPORT_ONLY` are read-only views of the table. A route matches
when every condition it states holds (category AND a keyword substring AND a file); a `magic:0x<hex>`
matcher is bytes, any other `magic:` value is text. Priority bands of the carried routes: category
lists 49 down, keyword nudges 60 and up (category-guarded ones above the rest), file routes inferred
from the formats the code tests for (`generate --file-routes`) 30 and down.

Shared basenames: two engine modules may share a basename only when
`docs/coverage/duplicate-basenames.toml` documents the pair (files, the one a flat import resolves to
on the engine sys.path, why). A flat `import <name>` of a shared name from any folder other than the
winner's is lint error `ambiguous-import`; load the exact file with `solvers/common/_shadowed.py`
(`common_module(name)`, `module_at(path, alias)`).

## 7. Solver result

```python
from ctf.result import SolverResult, Evidence, Cost, ResultError
SolverResult(status, flags=(), evidence=(), cost=Cost(), engine=None, challenge_id=None, notes="")
r.to_json(); SolverResult.from_json(s)       # exact round trip; {"schema": 1, ...}
```

| status | meaning | invariant |
|---|---|---|
| `solved` | a value in the event flag format, backed by evidence from the artifact ("flag found") | >= 1 flag and >= 1 evidence |
| `candidate` | plausible, not proven | >= 1 flag |
| `none` | ran to completion, found nothing | no flags |
| `unsure` | ran, cannot tell; needs a human/model read | — |
| `blocked` | could not run (missing tool, pack, corpus, permission) | no flags; `notes` names what is missing |

`solved` is never "accepted": acceptance exists only as a platform `SubmitResult`. `Evidence(kind,
detail, path=None, offset=None)`; `Cost(seconds, usd, tokens)`. A broken invariant, an unknown
field or another schema version raises `ResultError` (a `ValueError`).

`kind` is a free short tag, with one reserved value: an evidence item of kind `decoy` whose `detail`
holds a value in the event flag format says the engine found that value where decoys sit (text typed
onto a document page beside a drawing, B-132). The engine may still list the value in `flags` (as a
`candidate`); intake reads the item as a dispute of that flag (section 19, step 5).

## 8. CLI

`python -m ctf <command>`. `ctf/cli/__init__.py` holds the carried CSCTF commands and the discovery;
every other command is its own module `ctf/cli/<name>.py` (`_` becomes `-` on the command line):

```python
HELP = "one line shown in --help"
def add_arguments(parser: argparse.ArgumentParser) -> None: ...
def run(args: argparse.Namespace) -> int: ...      # the exit code
```

- Modules starting with `_` are helpers, not commands.
- A module that fails to import, or lacks one of the three names, is listed as `BROKEN: <error>` and
  exits 2 when run; other commands keep working.
- A name that collides with a built-in command raises `CLIError`. `cli.discover()` lists
  `(name, module | None, error | None)`.

Commands (the doc test fails when a command or a sub-command is missing here):

| command | module | what it does |
|---|---|---|
| `me`, `list`, `pull`, `triage`, `submit`, `status`, `check`, `doctor`, `wait` | built-in (`ctf/cli/__init__.py`, carried CSCTF CTFd CLI) | token check, challenge list, download + triage, submit on sight through the gate and queue (below), scoreboard line, solved check, environment doctor, wait for a wave |
| `hof` | `ctf/cli/hof.py` | `report [--json] [--strict]` (every timed start and result in the ledger, WARN lines), `check FILE... --id CID` and `classify FILE --date D [--elapsed S] [--id CID] [--own ID]` (offline, saved bodies): Hall of Fame eligibility and start origin (B-044, section 5) |
| `submit-queue` | `ctf/cli/submit_queue.py` | `status`, `pending`, `drain`, `approve <id> --reason R [--count N]`: the team's submit queue (B-006, section 5); `approve` is the player's, never an agent's |
| `policy` | `ctf/cli/policy.py` | `show [--json] [--event SLUG]`, `authorize-sweep <id> --count N --reason R [--ttl S]` (the player's), `sweep <id> --auth A --candidates FILE --note N`, `point <id> <host[:port]> --reason R`, `unpoint <host[:port]> --reason R`, `guesses [<id>]`: the event's solve policy (B-173, section 25) |
| `flag` | `ctf/cli/flag.py` | `check <value>` (exit 0 ok, 1 warnings, 4 blocked), `variants <value> [--max N] [--id ID] [--out FILE]` and `try <id> <value> --note N [--max N] [--confirm]` (exit 0 accepted, 1 not, 2 error, 4 refused), each with `--source S --other V --passed CHECK --case-lossy --case-ref FILE --nonstandard`: the plausibility check and the ranked variant set (B-154, section 40) |
| `model-route` | `ctf/cli/model_route.py` | `check` (the `[routing]` table, or the defaults, against tools/ledger/pricing.json; exit 2 naming each problem), `show [--harness H] [--json]` (every role x difficulty), `resolve ROLE [--difficulty D] [--harness H] [--category C] [--json]`: the per-role, per-difficulty model router (B-201, section 67); writes nothing |
| `marker` | `ctf/cli/marker.py` | `fields <challenge_dir>` (named values and their evidence), `candidates <challenge_dir> [--field NAME[:KIND]=VALUE]... [--family F] [--witness HEX[@WHERE]]... [--digest FORM]... [--budget N] [--top N] [--max-fields N] [--min-fields N] [--max-deviations N] [--keep-order] [--all-fields] [--nonstandard] [--id ID] [--out FILE] [--save FILE]` (exit 0 a ranked list and its guess-budget plan, 1 nothing to offer, 2 error; it sends nothing), `learn --verdict V (--from REPORT --flag VALUE or --family F --convention NAME [--kind ROLE=KIND]...) [--id ID]`, `kb [--family F]`: the constructed-marker fallback and its convention knowledge base (B-119, section 52) |
| `keysearch` | `ctf/cli/keysearch.py` | `[--root DIR]` then `new ID --spec FILE [--replace] [--allow-weak]` (freeze a spec into a job), `run ID [--workers N] [--max-chunks N] [--cpu-seconds S] [--all]` (search the chunks the ledger has not done: exit 0 a hit, 1 exhausted, 3 stopped early and resumable, 2 error), `status ID [--json]`, `show ID [--hit N | --index I] [--reveal]`, `list`: the resumable key search (B-215, section 66) |
| `event` | `ctf/cli/event.py` | `list`, `show [slug]`, `check [slug ...]`: event profiles |
| `new-event` | `ctf/cli/new_event.py` | scaffold `events/<slug>/` (section 15); `--regen` re-renders the agent files |
| `check-event` | `ctf/cli/check_event.py` | fail when an event's `CLAUDE.md`/`AGENTS.md` is missing, stale or edited (section 15) |
| `workdir` | `ctf/cli/workdir.py` | print the event working folder; `--create` |
| `engines` | `ctf/cli/engines.py` | `list`, `show`, `route`, `lint`, `generate`, `coverage`, `usage` (section 6) |
| `run` | `ctf/cli/run.py` | run one engine; `--no-ledger`, `--challenge-id` (section 6) |
| `budget` | `ctf/cli/budget.py` | `status`, `extend`, `stop`, `resume`, `set` (section 10); `extend` and `resume` are interactive |
| `ledger` | `ctf/cli/ledger.py` | `replay`, `waves`, `summary`, `mark`, `spend`: the wave replay and live spend summary from the event ledger, stage marks, categorised spend (B-101, section 10) |
| `build-plan` | `ctf/cli/build_plan.py` | `rank`, `check`, `pre-event`: rank pre-event builds, gate a build on an approved ranking |
| `fence` | `ctf/cli/fence.py` | `show`, `claude-settings`, `codex-args`, `check`, `report`, `selftest` (section 14) |
| `build-sandbox` | `ctf/cli/build_sandbox.py` | `show [--json]`, `codex-args [--name N]`, `config-toml [--name N]` (a `~/.codex/config.toml` fragment; installing it is a human step), `hosts`, `launch [--interactive] [--model M] [--approval A] [--dry-run] [PROMPT | -] [-- CODEX ARGS]`, all with `[--checkout DIR] [--docker] [--protect BRANCH]... [--integration-branch B]` (main, master and the integration branch are always protected); `selftest --scratch DIR [--codex-bin B]` (live, under `codex sandbox`, no model call; exit 1 a check failed); `push [--checkout DIR] [--remote R] [--branch B]` (DRY RUN: prints the command, never pushes): the Codex sandbox profile for repo build work, not for solvers (B-192, section 69). Exit 2 a named error |
| `sweep` | `ctf/cli/sweep.py` | unpack a challenge's files (or a bare file or folder) into a scratch copy and sweep every member for the flag; run by `pull` (B-013, section 4) |
| `intake` | `ctf/cli/intake.py` | `IDS...` or `--all`: one worker process per challenge, in parallel: download, sweep, input-adapted engines with the network denied, the fastlane decoders, `recon/index.md` and `triage.md`; submits nothing unless `--submit` (then, in the parent after every worker, the capped auto-submit through the SubmitGate, `--submit-cap N` judged sends per challenge, default 1; B-012) (B-002, section 19) |
| `arm` | `ctf/cli/arm.py` | the day-1 regression gate (B-014, section 24): build each lane's synthetic first-days fixtures, run its armed Layer-1 opener under the intake network guard with no model, check every frozen key and that no key holds on a neutral control; `--lane`, `--event`, `--strict`, `--json`, `--guard`, `--timeout`, `--root`. Exit 1 on a failed opener (or a not-run one under `--strict`), 2 on a usage, declaration or guard error or when nothing is selected. Declaration `openers/layer1.toml`, loaded by `ctf/openers/` |
| `dexvm` | `ctf/cli/dexvm.py` | `show APK... [--json]`, `replay [DIR] [--record] [--json]`, both `[--guard auto|os|hook] [--timeout S]` (B-229): every delivery is parsed in an engine process run by `openers.run_engine` (intake network guard, own process group, scrubbed engine env, run folders in a temporary folder of the event workdir), never in the ctf process. `show` runs `mobile_android.dex_chain_replay` (the VM's verdict, each ANS entry method's outcome and the decline's reason, beside the armed reader's answer). `replay` runs `mobile_android.codec_search` on every build under DIR (default `$CTF_REAL_CHALLENGES`; symlinks not followed; past `ctf.dexvm.MAX_BUILD_BYTES` reported, never read): a build recorded as a mobile-android B-036 event case (same input sha256) must print that case's expect lines, any other build must answer plain; `--record` records each plain build not yet recorded as event case `dexvm-<sha256[:12]>` (`regress.record_case`), so `adapt prewarm`/`gate` replay it. Exit 1 when a delivery is not answered plain (show) or a build fails (replay), 2 on a missing file or folder, no build, no event workdir, a guard that cannot hold or an engine that does not resolve. Library `ctf/dexvm.py` |
| `deliveries` | `ctf/cli/deliveries.py` | `ATTEMPT [--json]` (B-042, section 53): which delivery serves which set of a saved attempt (`attempt.json` beside `artifact/`), with the rule that proves it. Nothing is solved or sent. Exit 0 every set paired, 1 a set is unmapped (it would reach a solver with no files), 2 the attempt or a delivery cannot be read |
| `read` | `ctf/cli/read.py` | read a file with output capped and a whole-file window refused; records the read in the challenge's shared map (B-034, section 34). `--symbol NAME` reads one Python def/class; a binary gets the binary-first summary; `--strings [MIN]` (B-199) |
| `symbols` | `ctf/cli/symbols.py` | `TARGET` (a repo .py path or dotted module, or a .py outside the repo) prints the outline: imports, importers, every def/class/constant with its line range; `--find NAME` lists every definition; `--no-users`, `--max-tokens`, `--no-cap`, `--root`, `--state` (B-199, section 34) |
| `primer` | `ctf/cli/primer.py` | print `docs/PRIMER.md` (`--index`: `docs/FILE-INDEX.md`), `--check` (exit 1 stale), `--write` (B-199, section 34) |
| `research` | `ctf/cli/research.py` | the shared research cache (B-199, section 34): `get TEXT [--claim]`, `put TEXT --answer A|--answer-file F [--source URL]... [--replace]`, `claim`, `release`, `list`, `key`; `--dir`, `--agent`. Exit 0 hit/stored, 1 miss (with `--claim`: you hold it), 2 error, 3 another agent holds a fresh claim |
| `state` | `ctf/cli/state.py` | read the harness's lane-state files with compact fixed output so agents stop writing inline JSON readers (B-257, `ctf.lanestate`). Per challenge (`<id> --root DIR`/`$CTF_REAL_CHALLENGES`, or `--dir DIR`): `attempt`, `result`, `start`, `key`, `answers`, `verdicts`, `ladder`, `proofs [--file F]` (layout = `tools/run.py` VARIANT_FILES). Per lane: `conventions --lane L [--answers F] [--ids F]` (`solvers/<lane>/conventions.json` and `id_conventions.toml` via `ctf.idresolve`), `routes [--lane L] [--category C] [--id E]` (`route_table.jsonl`). `qdiff BASE TIMED` (`ctf.adapt.qdiff`). `status [--cid ID]` folds `ctf wire status` + `ctf ledger summary` (+ `ctf hypothesis list`) and `journal` wraps `ctf wire journal` (wrappers, never a second parser). `lint PATHS...` flags briefs that still hand-parse these files (exit 1 on findings). No network, no model; a missing file exits 2. B-210's `ctf show` reuses `ctf.lanestate` |
| `show` | `ctf/cli/show.py` | the operator read kit (B-210), one command with `state`: every `state` subcommand above works unchanged (`state.add_arguments(p, skip=...)` returns its subparsers action; `show` replaces `verdicts`), plus `question [CID] [--root R|--dir D|--file BODY] [--day N] [--id QID]...` (one line per question: kind, syntax, literal `none` by `ctf.idresolve.permits_literal_none`, accepted values), `keys` (`key.json` beside the submitted answers: `=` same, `!` differs, `-` one side), `verdicts [CID] [--status S] [--kind EV]... [--since T] [--limit N] [--json]` (the verdict ledger: `platform.submit`, `submit.done`, `hof.result`; `9` matches `9#a`; a flag only as `sha:<12 hex>`; with `--dir`/`--root`/`--day` also the folder's `verdicts.jsonl`), `timeline [CID] [--lane L] [--kind EV]...` (every ledger record of a challenge or lane, relative times), `hcfg SAMPLE... [--plain-only] [--json]` (every HCFG container via `solvers/binary/hcfg.py`: carrier, PE/ELF section, offset, encoding layer, key, CRC, member names), `members DELIVERY [--prefix dNN] [--json]` (archive order, size, sha256, day; `--prefix` by `members.day_members`; no password printed), `replay --tree A [--tree B ...] (--lane L | --engine ID --input F...) [--repeat K] [--case C]... [--lines RE] [--cprofile [--profile-dir D]] [--out FILE] [--cap S] [--guard M]` (`ctf.treereplay`: one fresh guarded process per attempt from each tree's own boot, per-attempt wall and CPU, answer diff `same`/`differs`/`unstable`/`missing`; exit 1 on a difference) and `lane-profile --lane L [--tree T] [--top N]` (CPU per case and top functions under cProfile, `ctf/_profboot.py`). Ledger subcommands take `--event`/`--workdir`. No network, no model; exit 2 on a missing or unreadable input. Libraries `ctf.opkit`, `ctf.treereplay` |
| `promote` | `ctf/cli/promote.py` | `start`, `inventory`, `show`, `decide`, `accept`: the post-event promotion record (section 18) |
| `fold-audit` | `ctf/cli/fold_audit.py` | `SLUG` or `--all`: fail when a recorded live fix has not reached the target master commit (section 18) |
| `seed-fold` | `ctf/cli/seed_fold.py` | `[LANE ...] [--dry-run] [--workdir DIR] [--json]`: fold event-learned label verdicts from the runtime ledger into the tracked per-lane seeds (`ctf.seedfold`, `labels.promote`, B-040, section 18). Exit 0 folded, 2 an error |
| `notes` | `ctf/cli/notes.py` | `add`, `retract`, `list`, `show`, `pending`, `sync`, `where`, `claude-hooks`: the player-notes feed (B-168, section 10) |
| `human` | `ctf/cli/human.py` | `checklist`, `add-card`, `add-pin`, `cards`, `pins`, `answer`, `drop`, `confirm`, `confirm-list`, `confirmed`, `reconcile`: human-only work (B-169, `ctf/humanops.py`; profile `[human]`, section 1) |
| `watch` | `ctf/cli/watch.py` | `run`, `tail`, `diff`: the one no-model board poller, its event stream, the offline brief verifier (section 20) |
| `preflight` | `ctf/cli/preflight.py` | the doctor checks for one event (B-039, B-142, B-190; section 16): `--event SLUG`, `--no-codex`, `--codex-mode fast\|deep\|cyber`, `--instance-plugin NAME --instance-challenge ID`, `--no-toolbox`, `--no-token`, `--brief FILE\|DIR` (repeatable), `--all-briefs` (only `<workdir>/*/codex_brief*.md`), `--settings FILE`, `--permission-mode default\|acceptEdits\|plan\|dontAsk\|auto` (default `auto`, the launchers' mode), `--interactive`, `--harness claude\|codex\|both`, `--strict` (warn, skip, advisory and sandbox-only fail too), `--json` (adds `blocking`, `advisory`, `not_run`, `sandbox_only` name lists). The report is split BLOCKING / ADVISORY / NOT RUN / OK. Exit 0 nothing blocking failed, 1 a blocking check failed, 2 the profile or a `--settings` file does not load. Without `--no-codex` it makes ONE real Codex call; without `--no-token` one `/users/me` and one `/tokens` request to the platform |
| `rehearse` | `ctf/cli/rehearse.py` | replay one wave offline against a fake CTFd on 127.0.0.1, or the manual drop folder (section 16): `--event SLUG`, `--submit-interval S`, `--keep DIR`, `--json`. Exit 0 passed, 1 a step failed, 2 cannot rehearse this event (e.g. Game Master) |
| `corpus` | `ctf/cli/corpus.py` | the blind rehearsal corpus of past challenges (B-155, `ctf.corpus` + `ctf.livereplay`): `index`, `stage ID --dest DIR`, `score ID --flag F`, `serve ID [--probe]`, `rehearse [--id ID] [--event SLUG] [--keep DIR] [--no-engines] [--engine-budget S] [--json]`, `import SRC --id ID --category CAT [--key-file F] [--service F] [--strip GLOB] [--engine E] [--corpus DIR] [--index FILE]`. Stages past challenges blind from `$CTF_REHEARSAL_CORPUS` (key and service spec stripped; links out of the challenge or onto an answer, and verbatim key copies, refused), routes them, starts any DNS/socat/web replay on 127.0.0.1 (its probe is a reachability check, not a solve), serves them on the B-039 fake CTFd (`FakeChallenge.connection_info` = the replay endpoint) and runs the no-model intake through the CTFd adapter, then scores the sweep's and each engine run's flags against the key. An empty or all-skipped run fails. `import` copies a public challenge folder into the corpus (answer files stripped, corpus root must be outside the repo) and prints or appends its flag-free index stanza. Exit 0 ok/passed, 1 failed, 2 a named error (no corpus, unknown id, bad replay spec). Never submits, never runs a challenge binary |
| `access` | `ctf/cli/access.py` | model-access status for an event (B-100, section 1): is the Opus 4.8 classifier fallback expected? `--event SLUG`, `--json`, `--plan-usd N`, `--check` (exit 3 unless `cyber_verified` granted). Reports only; never changes a model, a harness setting or the profile |
| `resolve-ids` | `ctf/cli/resolve_ids.py` | map renamed question ids onto the ids a lane's readers are proven on, fail closed (B-010, section 21): `QUESTIONS --conventions\|--known-ids\|--attempt ... [--member N]`. Exit 0 all resolve, 1 any unmatched or ambiguous, 2 unusable input |
| `toolbox` | `ctf/cli/toolbox.py` | the binary toolbox (B-142, section 16): `[--manifest TOML]` then `verify [--only NAME...] [--json]` (exit 1 when a core tool is not ok), `install [--only NAME...] [--apply [--system]] [--json]` (a DRY RUN unless `--apply`; `--apply` runs the brew/git steps, the system ones such as macFUSE/VeraCrypt only with `--system`, then verifies again; exit 1 something left, 2 brew/git absent for a step (the other steps still ran), a refused run, or `--system` without `--apply`), `brewfile [--write\|--check]` (the generated `./Brewfile`). Exit 2 on a bad manifest or unknown tool |
| `compaction` | `ctf/cli/compaction.py` | compaction thresholds (B-032, section 30): `show [--json]`; `check LOG [--harness H] [--limit N]` (exit 0 under, 3 at or over the threshold, 2 unusable input); `audit LOG... [--harness H] [--limit N] [--tolerance F] [--json]` (exit 0 every log held, 1 one exceeded or the threshold is off, 2 unusable input) |
| `writeup` | `ctf/cli/writeup.py` | the writeup/retro pipeline (B-098; `docs/writeup-pipeline.md`): `draft`, `retro`, `check`, `publish` (publish is a DRY RUN, never pushes); `assist` and `review` (B-097, `ctf/cli/_writeup_assist.py`, `ctf/writeup/assist.py`): the TODO prose drafted on `models.docs` and the one review pass on `models.primary`, routed by task type only (no `--model`), `--dry-run` calls no model; drafted text carries `<!-- drafted by= task= pass= -->` markers (`ctf/writeup/passes.py`) and `check`/`publish` block any block not cleared by `pass=person`, `models.primary` or a `models.fallback` id (`unreviewed-draft`, fail-closed; `passes.pass_findings(text, path, *, publish, models)`). `--event SLUG`, `--workdir DIR`, `--staging DIR`. Exit 0 clean/ready, 1 blocking findings or a closed gate (assist/review: a job declined, failed or answered out of format), 2 a named configuration error |
| `re-workbench` | `ctf/cli/re_workbench.py` | the static-RE workbench (B-165): `check` (capstone/unicorn/lief via `tools/static_re_check.py`, plus pefile; `--json`), `scaffold <dir>` (materialize a swarm workspace -- the `templates/static-re` brief, an empty owner-only shared `findings.jsonl`, a worked VMSpec, a captured readiness line; `--challenge`, `--agents N`, `--force`; pin the board's acceptance gate with one of `--gate-digest ALGO:HEX`, `--gate-regex P`, `--gate-flagfmt` into `findings.gate.json` plus a `gate_pin` anchor row in the log -- one is required, `--gate-later` opts out explicitly), `findings <board>` (read a `tools/shared_findings.py` board; `--accepted` re-verifies every accepted row against the pinned gate and flags the rest; `--json`). Offline; never runs a binary. Exit 0 ok, 1 readiness failed or an accepted row flagged, 2 a named error |
| `dispatch` | `ctf/cli/dispatch.py` | `run`, `once`, `show`: the no-model dispatcher — a claim and a machine-written handout per new challenge from the watch stream, then intake for the batch; never a model, never a submit (B-004, section 22) |
| `solved` | `ctf/cli/solved.py` | `run`, `once`, `list`: the solved watcher — on any team solve stop every agent on the challenge (B-033 hook) and mark its claim solved; the shared solved view the dispatcher gates on (B-015, section 26) |
| `hypothesis` | `ctf/cli/hypothesis.py` | `check`, `record`, `false`, `list`, `fp`, `mine`: the shared per-challenge hypothesis ledger (B-181, section 33) — `check CID --method M` exits 0 run / 1 skip so a runner gates a probe on it; `record` appends one attempt (positive runs a positive-control validation); `false` files a brute false positive; `fp` the false-positive rate per brute family; `mine` the verified true mechanism(s), `--file` written back to `_mechanisms.jsonl` |
| `render-sweep` | `ctf/cli/render_sweep.py` | `checklist DIR [--record]`, `rejected DIR --flag FLAG`: the fixed checklist of the render-and-read stego sweep (B-126, engine `toolkits.render_ocr_sweep`: spectrogram OCR to Nyquist, exact 5x7 glyphs, bit planes 0-2, keyless decode, cross-file keys) — one line per file and probe, `ruled out` / `open` / `incomplete` / `not run` / `REJECTED`; `rejected` (and `checklist --record`) writes it to the hypothesis ledger (section 33) under `--cid` or the id in `DIR/challenge.json`: a `negative` per ruled-out probe, an unread probe as `error` or `inconclusive` (never negative), the rejected reading as a `positive` followed by its `false_positive`. Method strings are `toolkits.render_ocr_sweep <probe> [<file>]`. The saved `DIR/recon/render_ocr_sweep/report.json` is reused only when it answers this run: the files are unchanged, it records the same options (`run_options`: flag format, `--key`s, OCR off or not, `top_hz`, ledger), its OCR could start, and it did not run out of time on a smaller budget than this run has; otherwise, and with `--fresh`, the sweep runs again, and the first line printed (`source` in `--json`) says `saved report` or `fresh sweep[: why]`; `--ocr auto\|on\|off`, `--key K`, `--seconds S`, `--agent A`, `--json`. Exit 0 ok, 2 on a named error |
| `stego-exhaust` | `ctf/cli/stego_exhaust.py` | `DIR [--rejected FLAG]... [--seconds S] [--ocr auto\|on\|off] [--no-sandbox] [--cid ID] [--no-ledger] [--no-record] [--agent A] [--json]`: the stego exhaustion harness (B-182, engine `toolkits.stego_exhaust`): a fixed catalog of steps per carrier (PNG, BMP, GIF, WebP, JPEG, TIFF, WAV: `trailing`, `carve`, `chunk-crc`, `metadata-concat`, `lsb-planes` (bits 0-7, every channel set, rows and columns, both bit orders), `lsb-deep`, `plane-grep`, `steganalysis`, `wav-lsb`, `wav-named-tools` (B-130), `stegseek-seed`, `exiftool`), carriers found inside swept two levels deep, then B-126's render sweep (`render:<probe>`) and `text-decode` over every recovered text. One deterministic verdict: `flag`, `open` (an item the catalog cannot read further, saying what it needs) or `nothing further`, `complete` only when no step is `not-run`; a step that could not run (tool missing, sandbox down, clock, unknown flag prefix) is `not-run`, never negative; `n/a` is no gap. Each step is recorded in the hypothesis ledger (section 33) under method `toolkits.stego_exhaust <step> <file>@<sha256[:12]>` (text decode: `... text-decode <delivery sha256[:12]>`): a flag as `positive`, a rejected reading as `positive` then `false_positive`, a negative step as `negative`, an open one `inconclusive`, a not-run one `error`; a step `should_skip` settles keeps its recorded result, is not recorded again and is not run again: what it recovered when it ran (its texts, the carriers it found, its human steps) is kept in `<workdir>/stego_exhaust/<id>/` (`stego_exhaust.store_dir`) and handed back; only a settled step that store does not hold is re-run, unrecorded, while the text decode or a step under that file is not settled, and only after every unsettled step, so a run the clock cut is completed by the next on the same budget; a text the decode read with no flag is not decoded again; ledger false positives count as rejected. stegseek and exiftool run only in a stego sandbox container already up (`stego_tools.no_start`): never started, built or pulled. Writes `DIR/recon/stego_exhaust/verdict.{json,txt}`. Exit 0 ok, 2 on a named error |
| `residual` | `ctf/cli/residual.py` | the irreducible residual (B-254, section 71): `classes`, `playbook [CLASS] [--write\|--check]` (docs/playbooks/residual.md), `template CLASS --id ID` (a blank B-151-shaped finding), `mark FINDING` (validate, record the id residual), `check RESULT [--class C]` (exit 1 when a residual result is solved/candidate), `hold RESULT --class C --why W` (print it held unsure), `check-answers ANSWERS [--allow-unmatched]` (exit 1 when a residual id carries a plain answer; names the residual ids no answer key matched; 2 on a namespace mismatch, or when none matched without --allow-unmatched), `stuck ID --question Q` (B-203 for a residual id; exit 0 stuck, 1 not), `report [--event S...] [--workdir D...] [--all-events] [--max-novel-share X]` (per-event frequency; exit 1 over the share). No model, no submit; 2 on a named error |
| `stuck` | `ctf/cli/stuck.py` | `assess`, `check`, `mark`, `list`, `reread`, `reconsider`, `clear`: the stuck-id protocol (B-203, section 51) — `assess ID --question Q [--file P...]` reports ok/try_format_candidates/stuck/probe_capped; `check` gates a probe (exit 0 send / 1 refused, like `hypothesis check`); `mark` records the id stuck (idempotent) and, with an event, opens a player card (exit 1 when not stuck); `list` the stuck ids, `reread` those due a 10-min live re-read, `reconsider` clears any whose brief changed since, `clear` cancels one. No model, no submit; 2 on a named error |
| `instance` | `ctf/cli/instance.py` | `start`, `status`, `renew`, `stop`, `stop-all`, `list`, `schedule`, `permissions`: drive per-team container instances through `get_adapter` (the profile's `[instances]` plugin, scope lock); `start`/`schedule` enforce the profile's cap across processes via the slot ledger (`<workdir>/instances/slots.json`; exit 1 at the cap); `schedule` is the value-ordered slot scheduler (`ctf.instsched`; `--challenge`, `--cap`, `--renew-within S`, `--dry-run`); `permissions` prints the solver allow/deny lists (per-verb `start status renew stop list`; `--profile`/`--event`, `stop-all`, `schedule` stay with the operator). `--profile` must be under `events/`. No model, no submit; refuses loudly (exit 4) with no plugin or in manual mode (B-003) |
| `escalate` | `ctf/cli/escalate.py` | `run`, `once`, `show`, `stop`: the dispatcher's live escalation ladder — a second/third agent on a different model on the 3-/8-minute timers (or a rejected flag), and a reroute within one poll when an agent stops on a refusal or a provider error; writes `escalation` records, launches nothing (B-016, section 27) |
| `spawn` | `ctf/cli/spawn.py` | `request`, `brief`, `result`, `results`, `end`, `allow`, `board`, `escalations`: brief-not-fork spawning and the per-challenge agent gate (B-143, section 39). `request` exits 0 admitted (prints the spawn id, the brief, the first-input size), 3 held at the agent limit, 4 refused (named reason); `allow` is the player's, interactive only; 2 a named error. Launches nothing |
| `contract` | `ctf/cli/contract.py` | `show`, `check`, `report`, `may-stop`, `solves`, `fact`, `fresh-eyes`: the solver contract every brief carries — lint a status report (exit 1 on a violation), record a `solver_status` only when it passes (SOLVED before acceptance is refused), the stop-loss verdict (exit 0 may stop, 1 keep working), recorded solve counts and verified facts, the fresh-eyes brief; no model, no network (B-172, section 46) |
| `gate` | `ctf/cli/gate.py` | `plan`, `run`, `inventory`: the impact-selected regression gate (section 23); `run --full --mark-green SLUG` tags a green clean HEAD after a full run (section 42); `run` is strict about tests that did not run: `--allow-not-run KIND` (section 23, B-196). B-153: `budget` (each lane's cost estimate against its five-minute budget; `--lane`, `--jobs`, `--import-junit XML`, `--json`; exit 3 when one is over), `baseline` (`check`, `list`, `keys`, `add ID --kind K --reason R [--owner O]`: the tracked baseline ledger), `prearm` (the pre-arm full gate: preflight checks, then a full index-free run; `--jobs`, `--out`, `--mark-green`, and `--idle-lock` / `--no-idle-lock` / `--idle-timeout S` as `run`; exit 0 green, 1 red or any ENV file, 2 usage, 4 preflight refused); common `--python PATH` (the pytest children's interpreter, `ctf.pyinterp`). A `run`/`plan` with `--lane` (not full) exits 3 over its budget (`--budget S` overrides) |
| `integrity` | `ctf/cli/integrity.py` | `mutate FILE [--function] [--lines A-B] [--op] [--max N] [--tests T ...] [--min-score S] [--list]`, `fakes [--source DIR]`, `collected`, `doclint [DOC ...]`, `preserve [--run] [--lane L] [--recorded] [--allow-not-run KIND]`, `engines --base REF`, `all [--base REF]`, each with `--json` where it reports; exit 0 clean, 1 findings or a red run, 2 usage or config error (section 61, B-196) |
| `live` | `ctf/cli/live.py` | `show` (the default), `page`, `push`, `loop`, `smoke`, `job`, `arm`, `forget`: the no-model status surface, its page, phone push and deployed-page smoke test, recorded jobs, the armed commit (B-198, section 47). Exit 0 ok, 1 a failed push/smoke check or a job's own code, 2 a named configuration error |
| `release` | `ctf/cli/release.py` | `SLUG`/`arm`, `status`, `check`, `green`, `freeze`, `thaw`, `rollback`, `unwired`: dated armed tags, the armed-lags-HEAD check, code freeze and rollback, the process-fence regression run before every arm, the unwired-module report (B-197, section 42) |
| `clock` | `ctf/cli/clock.py` | `[--event SLUG] [--now WHEN] [--hook [--hook-event UserPromptSubmit\|SessionStart]]`: the current time in Eastern time (weekday, EST/EDT) and UTC, the event's next release (`ctf.quota.next_release`) with a countdown, and whether the event has started, is running or is over (B-211, `ctf/clockline.py`). `--now` takes epoch seconds or ISO-8601 (no zone = Eastern) so tests inject the clock. With no event named and none to pick it still prints and names why there is no countdown. `--hook` prints Claude Code hook JSON (`additionalContext`) and never fails (errors become named lines); `tools/clock_hook` wraps it for a `UserPromptSubmit`/`SessionStart` hook (installing the hook is a human step). Exit 0 printed, 2 a bad `--now` or an event named by `--event`/`$CTF_EVENT` that does not load |
| `capacity` | `ctf/cli/capacity.py` | `show`, `plan --board N`: size concurrent agent capacity to the host (RAM/CPU) and lay a board onto worker lanes past a single harness's subagent cap; no model, no network, launches nothing (B-018, `ctf/capacity.py`) |
| `governor` | `ctf/cli/governor.py` | `status`, `check [--strict] [--measure S]`, `run -- CMD`, `watch [--once]`, `measure`, `disk --need SIZE`, `copy SRC DST`, `evict [--apply]`, `spotlight DIR [--apply]`: the host resource governor (B-176, section 28). Exit 0 ok, 1 a check failed / alert fired / disk refused / folder indexed, 2 a named error, 3 `run` not admitted within `--timeout`; `run` otherwise exits with CMD's code |
| `quota` | `ctf/cli/quota.py` | `scan`, `status`, `set`, `plan`, `gate`, `wait`, `daily`, `check`: the harness quota meter (B-171, section 10): quota readings from the session logs (`scan`) or the player (`set`), the state of each harness and window, quota-aware scheduling of a job file (`plan`; writeups first, held jobs batched by the time their limit resets), one job's go/no-go (`gate`), a no-model `wait` that releases the next batch, the per-day spend ledger, the doctor's allowance check. `--event`, `--workdir`, `--now`. Exit 0 ok, 1 the check failed / over the daily allowance / nothing held has a known release time, 2 a named error, 3 held |
| `slate` | `ctf/cli/slate.py` | `set`, `pause`, `resume`, `remove` (each `--by WHO --reason WHY`, logged), `show`, `history`, `check`, `status [--cap N]`, `plan --jobs FILE [--cap N \| --no-agents] [--now WHEN]`, `env SLUG`, `fence SLUG [--write]`, `run --event SLUG [--label L] [--timeout S] [--poll S] -- CMD`: the multi-event priority scheduler (B-214, section 44): the events in play and the player's priority, weight, `--max-agents`, `--min-agents`, `--quota-cap`, `--workdir` per event; agents shared out of the host governor's cap by priority; jobs placed on the account's shared quota windows by priority; each event's workdir isolated and fenced from the others. `--state DIR`, `--events-root DIR`. Exit 0 ok, 1 `check` found problems, 2 a named error, 3 held (`plan`) or not admitted within `--timeout` (`run`); `run` otherwise exits with CMD's code |
| `spend` | `ctf/cli/spend.py` | `status`, `cap`, `decide`, `gate`, `tier`, `review-plan`, `next`, `record` (`--findings SEV=N` or `--findings-file` reviewer JSON), `diff`, `investigate`: build and review spend governors (B-202, section 10): phase caps and mode (speed-run) budgets decided by the player before spending (`cap`/`decide` are interactive), the go/no-go `gate`, risk tiers, the review dispatcher's dry run, the stopping rule, review rounds and the standing diff audit, time-boxed investigations. `--event`, `--workdir`, `--now`. Exit 0 ok, 1 diff found changes, 2 a named error or refusal, 3 held / a person decides / an investigation hit its box |
| `failover` | `ctf/cli/failover.py` | `check`, `status`, `switch`, `rehearse`, `prune`: harness failover for release mornings (B-170, section 49): the quota meter's trigger (`check`: exit 0 stay, 3 switch, 1 stranded, with the runbook steps), the active harness and last rehearsals (`status`), the switch record (`switch --to H --by WHO --reason R`), and a rehearsal of one synthetic lane per lane through the fenced launcher (`rehearse --to H --by WHO [--live]`: exit 0 held, 1 not), and removal of old rehearsal lane folders (`prune [--keep N] [--dry-run]`, newest N runs per harness kept, ledger untouched). `--event`, `--workdir`, `--now`; 2 a named error |
| `usage` | `ctf/cli/usage.py` | `ingest`, `report`, `agents`, `assign`, `assign-role`, `reconcile`: the shipped usage ledger (B-193, section 10): per-response usage of the event's Claude Code and Codex sessions, priced by model, tier and cache TTL, the model served per agent, one attribution rule; `assign-role AGENT ROLE --by WHO [--note TEXT]` records an agent's work role (one of `ctf.stages.SPEND_CATEGORIES`) as a `usage.role` event for the by-role split (B-096); `reconcile --charge` tops the event ledger's spend up to it; `ttl [--window S] [--top N] [--json]` (B-118, section 70) the 1h cache writes priced at the 5m rate: gross (reused within S seconds), the late re-write cost and net, per thread and kind (exit 4 also when a row has no timestamp). Exit 0 ok, 2 a named error, 4 usage that could not be priced or read |
| `osint` | `ctf/cli/osint.py` | `status ID [--json]`, `handoff ID [--reason R] [--source S ...] [--note T]`, `guess-budget --wrong-count N [--guess-budget M] [--approvals-left K] [--json]`: the time-boxed live-OSINT playbook (B-115, `ctf/osint_playbook.py`; the OSINT box of section 10) — the box status of a challenge, the human-handoff file plus a recorded stop, and whether the threat-intel kit may run another candidate-feeding lookup. `status` and `handoff` take `--token-cap N` and `--time-box S`; `--event SLUG`. It never searches a platform or starts a model. Exit 0 ok (`guess-budget`: allowed), 2 a named error, 3 `guess-budget` blocked |
| `social` | `ctf/cli/social.py` | offline: `parse URL...` (platform, post id, canonical URL, post time decoded from the id), `plan URL` (the public endpoint a fetch would use, or why the platform is human-only), `scan FILE [--base-url URL]` (the social posts a saved news article links or embeds), `hosts` (the closed endpoint hosts and whether `rules.public_fetch_allow` lists each); online, opt-in with `--online` and inside the challenge's OSINT box: `fetch URL --challenge ID` (one oEmbed or public embed request) and `article URL --challenge ID` (one news-article fetch scanned for post IDs); all take `--json` where they print, the online two `--event SLUG --token-cap N --time-box S`. The social-media post helper (B-206, `solvers/toolkits/osint_social.py`): every host passes `scope.check_public_fetch`; a block, login wall or platform with no public endpoint is never worked around: it writes the B-115 handoff (reason `social_human_only`) and records a stop. Exit 0 ok, 2 a named refusal or error, 4 human-only (handoff written; `plan`: the platform is human-only) |
| `adapt` | `ctf/cli/adapt.py` | the per-lane adaptation loop (B-036, section 29): `gate LANE...` and `prewarm [LANE...] [--watch S [--duration S]]` (the warm lane regression gate; `--watch` re-gates a lane whenever its key changes; `--no-warm`, `--no-regate`, `--cap`, `--recut`, `--max-scale`, `--json`), `record LANE NAME --engine E --input F --expect LINE` (an accepted run as an event case; `--mode`, `--within`, `--scope`, `--note`, `--force`), `chain BASE_ID --lane L` (the next timed step; `--max-retries`, `--artifact-sha256` for a same-artifact retry), `mark CID --by teammate\|hand`, `attempt CID --outcome O [--lane-key K] [--artifact-sha256 S] [--missing N] [--learned KEY]`, `qdiff BASE.json TIMED.json`; B-253: gate/prewarm/chain take `--jobs N\|auto` (default auto, the deadline-aware quiet check) and `--no-day-scope`; `replay ATTEMPT_DIR --solver FILE [--serial] [--stability\|--profile] [--budget S]` (a saved attempt through the set pool; two concurrent interpreters compared; a profiled serial solve against a pooled one), `rows LANE --rows DIR --solver FILE [--no-warm]` (the lane's saved rows behind the per-prefix replay cache), `quiet` (running clocks and the replay policy). Common: `--workdir`, `--root`, `--event`, `--guard`. Exit: gate/prewarm 0 yes, 1 no, 3 not run; chain 0 start/retry/done, 1 stop, 3 wait/hold; qdiff 1 when a change needs attention; replay 1 unstable or pooled differs; rows 1 a row red; 2 an error |
| `latency` | `ctf/cli/latency.py` | `open CID` (warm, then list \|\| start at `--at`, provisioning wait, download), `start CID` (one guarded start, status reads until ready, the provisioning alert), `pending [--clear CID]`, `phases`, `floors [--record MODE=S] [--bank MODE=N] [--write]` (the per-mode wire-floor table, with each Game Master timed mode's bank-submit floor; B-252), `lane-done LANE [--undo]`: the release latency path (B-185/B-252, section 5); `open`/`start` contact the platform through `get_adapter`, the rest read `<workdir>/wire/`. Exit 0 ok, 1 not ready or a failed step, 2 a named error, 4 refused before a request |
| `mavlink` | `ctf/cli/mavlink.py` | `dissect CAPTURE`, `extract-key CAPTURE`, `verify CAPTURE --key`, `forge --msgid --payload --key`, `resign --prov-key --new-key`, `send HOST PORT`: the MAVLink 2 engine (B-031) — parse a `.pcap`/`.tlog`/raw stream (frames, msgids, signed frames, link ids, any `SETUP_SIGNING` key leaked in-band), count frames that verify under a key, build one signed frame, build a `SETUP_SIGNING` re-sign frame signed with the provisioning key, or drive a live link (scope-guarded through `get_adapter`; a non-loopback host must be in `rules.live_service_scope`). Reads only the capture path given; no platform contact except the explicit `send` target. Exit 0 ok, 1 nothing matched/verified, 2 a usage/parse error, 4 refused by the event's scope rules |
| `lookahead` | `ctf/cli/lookahead.py` | the look-ahead completeness gate (B-174, section 35): `gate MATRIX` (run every lane's reader over the forecast matrix; fail on a wrong answer, an unanswered or unsure deterministic id, a skipped/crashed/cut specimen, an uncovered newest-base id, an uncrossed size threshold, an unexercised real encoding, a bad encoding; `--lane`, `--timeout`, `--guard`, `--json`, `--report-out FILE`, `--no-record`), `thresholds PATH... [--matrix M]` (size constants and len() comparisons in code; undeclared ones), `scale SPECIMEN OUT --bytes N` (a multi-set specimen past a size), `score FORECAST --lane L --previous P --actual A [--report R]` (a forecast against the day), `plan MATRIX --report R` (which lanes get an agent). Common: `--workdir`, `--root`. Exit: gate 0 green, 1 a gap; thresholds 1 an undeclared one; plan 1 some lane needs an agent; 2 an error |
| `lookahead-daily` | `ctf/cli/lookahead_daily.py` | the daily look-ahead of a rolling-release event (B-256, section 35): `prepare --matrix M --out DIR --day D [--event SLUG \| --profile F] [--report R] [--tagged LANE --tag TAG [--families] [--containers] [--question-id]]... [--computed LANE]... [--seed] [--repo] [--agent-cap N] [--json]` (refuse a non-rolling event; stage tagged-copy and computed-field specimens into the matrix, no model; plan the profile's lanes with `forecast.plan`; write `DIR/D/plan.json` and, when a lane needs an agent, `DIR/D/workflow-args.json`, checked by the `day-lookahead` pre-launch gate), `finish --plan DIR/D/plan.json [--result R.json] [--previous-forecast F.toml] [--json]` (README naming every lane, `<lane>: NOT staged` with its last forecast; `forecast.toml` for `lookahead score`). Exit: prepare 0 args written, 1 no lane needs an agent; finish 0 every agent lane staged, 1 a lane NOT staged; 2 an error |
| `wire` | `ctf/cli/wire.py` | `status`, `journal`, `ratelimits`, `mark-release`: the platform request journal and release-minute budget (B-140, section 5); `ratelimits` gives each 429's request mix by op and lane; never contacts the platform |
| `scoreboard` | `ctf/cli/scoreboard.py` | `ingest`, `watch`, `record`, `show`, `bench`, `floors` (all take `--event SLUG`, `--workdir DIR`): low-priority reads of the public board and every team's per-challenge solves into `<workdir>/scoreboard/` (only `ingest` and `watch` contact the platform, through the wire as lane `board`; Game Master `NotSupported`, manual `NotAllowed`, exit 2), `record CID TEAM WHEN [--category C] [--name N]` / `record CID TEAM --delete` (a solve entered by hand, no request: a Game Master event's first bloods), the stored standings and first bloods, the per-lane first-blood benchmark from the store and the ledger (`--team`, `--margin`, `--t0`, `--lane`, `--strict`), and `latency.floor_table` with the fastest rival first blood as each mode's record (B-099, section 59) |
| `formats` | `ctf/cli/formats.py` | `list`, `identify`, `fingerprint`, `known`, `build`, `matrix`: the ranked format catalog, structural identification of a member (best first; an extension alone is never sure), the unknown-format `fingerprint FILE... [--online] [--event SLUG] [--json]` step (B-207, section 31: magic strings, header fields, record geometry and the offline lookups, the magic table then the known-format DB of B-087; `--online` opens public code search only where `rules.public_fetch_allow` lists the host), `known [--json]` (the known-format DB: what each entry matches on and the public reference it names; exit 2 on a bad table), the synthetic corpus written to `--out DIR` (never overwrites), and the metadata readers' property coverage matrix (`--json`, `--write` docs/coverage/FORMATS.md, `--check`) (B-162, section 31). Exit 1 on a matrix problem, a stale file under `--check` or an identify with no sure match, 2 on a bad catalog, magic table or known-format table, an unknown sample or event, an existing build file a missing lane pack, a file over identify's limit (FormatLimit) or a detector that failed (DetectorError) |
| `accepted-formats` | `ctf/cli/accepted_formats.py` | `harvest [--corpus DIR ...] [--lane L] [--out F \| --write \| --check \| --json]`, `check BODY [--catalog F] [--json]`, `show [PROPERTY ...] [--catalog F]`: the metadata lane's accepted-format catalog (B-218, section 65). `harvest` reads judged attempts from `--corpus`, else `$CTF_REAL_CHALLENGES` (no default; never inside the checkout); `--write` updates the tracked catalog, `--check` exits 1 when it is stale. `check` is the pre-clock brief of a status body / attempt.json. Exit 1 when `check` finds a question with status `unshaped` or a syntax phrase never seen, 2 on no corpus, no judged attempt, a broken catalog, an unreadable body or an unknown property |
| `toolchain` | `ctf/cli/toolchain.py` | the pinned toolchain (B-188, section 37): `[--root DIR]` then `lint [--only] [--json]` (static image/Dockerfile checks; exit 1 a pinned image has a finding), `status` (`docker image inspect`, a read; exit 1 a core image not ok), `build [--only] [--force] [--apply]` (a DRY RUN unless `--apply`; fresh images skipped, unlocked downloads and pinned images that fail lint refused; exit 1 left/failed/refused, 2 docker absent), `smoke NAME...` (in-image env-checks, networkless), `assets` (exit 1 a core asset not ok), `env [--write]` (`export` lines: CTF_PYTHON, PYTHONPATH, assets, venv bin on PATH), `envcheck LANE [--python PY] [--no-pins]` (exit 1 a required item missing, 2 unknown lane), `versions DIR` (version notes and the image to use; exit 1 missing/conflict, 2 not a folder), `wheels [--dir D] [--plan]` (exit 1 a pin missing, 2 no folder). Under CTF_TESTING a non-stub docker is exit 2 |
| `standby` | `ctf/cli/standby.py` | `take`, `renew`, `release`, `status`, `plan`: the warm standby agent pool — a warm agent blocks on `take` and is handed one claim + handout; `take` exits 4 on timeout; `--owner-pid` / `--ttl` + `renew` set lease liveness; `take --pool helpers [--lane L]` waits for lane-helper claims (B-037/B-212, section 32) |
| `helpers` | `ctf/cli/helpers.py` | `watch [--once] [--duration S] [--poll S] [--from-start] [--json]`, `arm (--lane-plan F \| --matrix M --report R) [--json] [--no-record]`, `deliver ID [--outcome delivered\|failed] [--note]`, `status [--json]`, `check`; common `--workdir`, `--config` (default `<workdir>/helpers.toml`): the no-model helper watcher (B-212, section 62). Exit 0 ok, 1 `watch --once` recorded an error or `arm`/`check` found a lane with no warm brief, 2 a named error |
| `codec` | `ctf/cli/codec.py` | `FILE... [--event SLUG] [--crib TEXT] [--slug] [--slug-pattern RE] [--records] [--consensus] [--group index\|all] [--min-n N] [--pack NAME] [--depth N] [--nodes N] [--budget S] [--json]`: the shared codec graph on a blob, numbered records at the true cut, N-record consensus over sibling sets (B-163, section 41). Exit 0 one answer per file, 1 none or several, 2 could not run |
| `web-lane` | `ctf/cli/web_lane.py` | `list`, `run [--dry-run] [--only ID ...] [--include-solved]`: the Huntress web lane (B-007; `ctf/web_lane.py`) — forces each released, unsolved web row open, reads it GET-only and submits only a value the event's `[proof]` format accepts, through `ctf.platform.get_adapter` (Game Master only; any other platform kind is refused before any start). Each row also lists named notes for any target it did not read (B-237, `ctf/web_ws.py`: why the server-first WebSocket class declined, or that it is switched off, plus the hunt's class hint; JSON key `notes`). `--event`/`--profile`, `--json`. Exit 0 ok, 2 a named error (including an undriven platform kind), 4 the event forbids automated submission or instances |
| `web-traps` | `ctf/cli/web_traps.py` | `PATH... [--description-file F] [--json]`: B-104, detect and flag only. Reads a challenge folder (challenge.json's brief + `files/` + `unpacked/`), a folder or a file as data with `solvers/toolkits/web_traps.py` (engine `toolkits.web_traps`, also run at intake on a routed brief or web source) and prints the verdict `trap` / `suspect` / `clean` with its rules (exfiltration to a third-party collector, an ask for the solver's own prompt, an ask to read the CTF platform) and every regex validation gate that leaves its input open (marker and an offline-checked candidate input; nothing is sent). `web_evidence.read_source` carries the same reads as `regex_gates` and `traps` (and `trap_cuts`: files those readers saw only in part), `web.triage` as `traps`. Every cut or skipped file is named (`cut` / `skipped` in the JSON, `NOT FULLY READ` in the engine notes). Exit 0 clean or suspect, 1 a trap (refuse it, hand it to the human), 2 a named error |
| `web-contracts` | `ctf/cli/web_contracts.py` | `matrix`, `fingerprint EVIDENCE`, `route EVIDENCE`, `route-trust URL --base B [--advertised R ...] [--clue T]`, `forge-grid --fields JSON [--max N]`, `minimize REQUEST`, `replay PLAN --capture CAP [--budget N]`: the B-184 web contract library (`solvers/web/contract_library.py`) offline — the fingerprint-first router over the cold/agent/none class matrix, the route-trust rule for clue-advertised URLs, the simplest-first forge grid with label-to-wire mutation, the request-minimization plan (auth noise dropped first), and the timed-mode replay runner driven against a recorded capture (never a live service; a target-described contract is delegated to B-149 `web.contract_executor`). Reads evidence/request/plan JSON and prints JSON. Exit 0 ok, 1 `route-trust` untrusted or `replay` found no proof, 2 a named error |
| `invariant` | `ctf/cli/invariant.py` | `[--json]` then `check --spec S --before B --after A [--accepted N]`, `plan --spec S --url URL`, `run --spec S --url URL [--event SLUG | --profile P] [--deadline-s S]`: the B-124 business-logic state-invariant harness (`solvers/web/invariant_harness.py`). The spec STATES the invariant (`stated_by` names who; the harness never finds the flaw). `check` evaluates it over two hand-captured snapshots (offline); `plan` validates the spec against the target origin and prints the rung ladder with each rung's reserved request count (sends nothing); `run` drives the smallest-transition ladder live (baseline + idle noise control, sequential 1..N, optional B-048 burst), reversing each accepted transition and confirming restore. `run` refuses (exit 4) unless the event's `rules.web_state_changing` is true and the URL is inside its live-service scope. Never submits. Exit 0 held, 1 violated, 2 a named error or unevaluable check, 3 a live run stopped inconclusive, 4 refused |
| `text-tricks` | `ctf/cli/text_tricks.py` | `[FILE... \| -] [--text TEXT ...] [--event SLUG] [--json]`: read a rules page, brief or pasted post for a flag hidden in the text itself -- bullet/line initials (acrostics), line finals, word initials, capitals, mid-word capitals, trailing whitespace and the gaps between words, zero-width characters -- against the event flag format (`ctf.texttricks`, B-208). Prints flags, candidates (verify by hand) and clues; the text is untrusted data, nothing is followed or submitted. Exit 0 one flag per input, 1 none or several, 2 could not run (no input, unreadable or over 1 MiB, no event format) |
| `favicon` | `ctf/cli/favicon.py` | `TARGET [--timeout S] [--json]`: fetch a service's declared favicon (an icon URL, a page URL, or a local icon file) and record its Shodan/Censys hashes for the first pass (`ctf.favicon`, `solvers/toolkits/favicon_hash.py`, B-089) |
| `tor-fetch` | `ctf/cli/tor_fetch.py` | `URL [--socks-port PORT] [--socks-host HOST] [--timeout S] [--out DIR] [--no-favicon] [--json]`: fetch a `.onion` hidden service over a local Tor SOCKS5h proxy and read its leaf certificate (serial as uppercase hex, SHA-1/256 fingerprints), headers, body and favicon (`ctf.tor`, B-091). `scope.check_host` on the onion host first; a running Tor SocksPort required (auto-detects 9050/9150). Exit 0 ok, 2 fetch/parse error, 3 no Tor proxy (start tor, B-175), 4 out of scope |
| `scan-index` | `ctf/cli/scan_index.py` | `cert (--sha256 H [--sha1 H] [--serial HEX] \| --cert-file PATH)`, `favicon (--icon-hash N [--md5 H] [--sha256 H] \| --file PATH)`, `title TEXT`, `host IP [--public-port N ...]`, each with `[--provider NAME ...] [--budget N] [--size N] [--refresh] [--challenge ID] [--json]`, and `quota [--budget N] [--json]`; `--event SLUG` before the action: keyed official-API lookups on Shodan, Censys (Platform), FOFA and Netlas, unioned to host:port rows (`ctf.scan_index`, B-114). `cert`/`favicon`/`title` find the origin behind Tor or a CDN (a CDN edge is labelled, never dropped); `host` unions one address's indexed ports (InternetDB joins), marks the non-public ones, names the scanners that have the host without the port, and lifts UUIDs and labelled values from archived bodies as leads. The provider hosts are a closed list and each request runs `scope.check_public_fetch` (`rules.public_fetch_allow`); keys come only from the `CTF_SCAN_INDEX_*` variables (section 3) and are never printed; no redirect is followed and no anonymous or browser route is tried. Every request with an HTTP answer is a `scan_index.query` ledger row (`provider`, `op`, `pivot`, `value`, `status`, `rows`, `event_slug`, `http_status`?, `reason`?, `challenge`?); a provider gets at most its budget of requests per workdir, and answers are cached under `<workdir>/scan-index/`. A provider that was not asked (`skipped`, `no_key`, `budget`, `refused`) or failed (`auth`, `quota`, `error`) is listed with its reason. Exit 0 at least one provider answered, 2 bad argument, 3 none answered, 4 every askable provider refused by the event's scope |
| `reap` | `ctf/cli/reap.py` | `[--workdir D \| --jobs-dir D --sessions-dir D] [--no-processes] [--repo DIR [--base REF] [--protect B]...] [--json] [--confirm ID]... [--log FILE]`: the end-of-event reaper (B-175, section 60). Without `--confirm` a dry run lists running and lost jobs (`job:<id>`), live and stale launcher sessions (`session:<name>@<launcher pid>-<start ms>`), clean merged unlocked worktrees (`worktree:<path>`) and merged unprotected branches not checked out (`branch:<name>`), and what is kept and why; with `--confirm` it acts on exactly those ids, re-checked first, in the order sessions, jobs, worktrees, branches, and appends each to `<workdir>/reaper.jsonl` (or `--log`). Exit 0 ok, 1 a confirmed id failed or was skipped, 2 usage or an id not in the plan (nothing done) |
| `session` | `ctf/cli/session.py` | `list [--sessions-dir D] [--json]`: the named launcher sessions, live or stale by pid and start time (B-175, section 60); exit 2 no sessions folder resolves |
| `discipline` | `ctf/cli/discipline.py` | `[--plain]`, `check -- "<command>"`: print the brief command discipline every brief carries (absolute paths, one command per call, the program named literally, plain git; markdown or `--plain`), or lint one command against it (exit 1 with each rule broken and its fix, 0 clean, 2 usage); one source `ctf/briefdiscipline.py`, carried by the dispatch handout, the orch brief and RULES, the standby plan, the codex handoff prompt and the event agent-rules template; the orch guard appends `fix_hint()` and `ctf.orch.ROLE_DENIAL_STANDS` (the rewrite alone does not lift a role denial) to a Bash denial; the block spells the helpers `/abs/repo/tools/ctfpy -m ctf ...` so they run from any folder (B-043) |
| `permissions` | `ctf/cli/permissions.py` | `[--event SLUG] [--check] [--helpers-only]`: show the player's declared permission rules (section 1) and the sanctioned helpers; an `example = true` file is labelled unconfirmed and fails `--check` (B-191) |
| `abandon` | `ctf/cli/abandon.py` | `<id> --reason "..."`: record a gated give-up (required, specific reason) to `<workdir>/abandoned.jsonl`; nothing is killed (B-191) |
| `worktree-commit` | `ctf/cli/worktree_commit.py` | `-m "..." [--all] [--trailer K=V] [--protect B]`: commit the current worktree (tracked changes only unless `--all`), refusing a detached HEAD and a protected branch; `main` and `master` are always protected and no flag removes one; exit 0 committed, 1 git failed (`GitFailed`), 2 refused or usage (`WorktreeRefused`) (B-191) |
| `worktree-venv` | `ctf/cli/worktree_venv.py` | `[--worktree DIR] [--venv DIR] [--force]`: link the worktree's `.venv` to a venv (`ctf.worktreevenv`); `--worktree` defaults to the top level of the git checkout holding the current directory (`git rev-parse --show-toplevel`), else the current directory: `--venv` if given, else `$CTF_VENV` if set, else the master checkout's `.venv` via `git --git-common-dir`; only the first source given is used and it must hold an executable `bin/python`; makes git ignore the `.venv` symlink first, also when the link already exists or `--force` relinks it (root ignore pattern `.venv`, else `info/exclude`); never touches a real `.venv` directory, `--force` only replaces a link aimed elsewhere; in the master checkout itself (its `.venv` is the venv to link) it reports that and changes nothing (`link()` action `is-master`); exit 0 linked, already linked or is-master, 2 refused (`WorktreeVenvError`) (R-17) |
| `worktree` | `ctf/cli/worktree.py` | `create <branch> <path> [--base REF]`, `list [--json]`, each with `[--repo DIR]` before or after the sub-command (`ctf.worktree`): per-agent build worktrees — one named branch per agent, created before spawn; a bare id becomes `item/<id>` (`agent_branch`: no leading `-`, and `git check-ref-format` must accept the name); refuses an existing branch or a non-empty path so two agents never share a tree. `create ... --harness H [--row ID]... [--file PATTERN]... [--fold F]...` first registers the agent in the section 68 work registry under the branch name, with the worktree and the claims, all or nothing (the folder is made empty first, so the record is live; a claim clash creates nothing and exits 1 naming each clash; a failed `git worktree add` unregisters it again); claims without `--harness` are refused. Exit 0 ok, 1 a claim conflict, 2 refused/usage, a bad claim or an unreadable registry (B-147, B-213) |
| `integrate` | `ctf/cli/integrate.py` | `plan`, `run`, `guard`, each with `[--repo DIR]` before or after the sub-command (`ctf.worktree`): the integrator merge queue. The integration branch is `--integration-branch`, else `$CTF_INTEGRATION_BRANCH`, else the repo's `git config ctftools.integrationBranch`; there is no built-in name and `run`/`guard` exit 2 without one. `run --items FILE [--branches ID=BRANCH ...] [--prefix item] [--no-regen] [--no-gate] [--keep-going]` must be on that branch with a clean tree and takes the queued `item/<id>` branches in BUILD-PLAN dependency order (`dependency_order` over `ctf.buildplan.load_items(--items)`; an item follows every dependency that is also queued, ties by id). One step per item, `MergeStep.status`: `merged` (`git merge --no-ff` made a merge commit of the previous HEAD and the branch tip, the generated files were regenerated into that same commit, the only one ever amended, and the gate was green), `already-merged` (the tip is already in the branch: nothing merged, regenerated, gated or amended), `conflict`, `merge-failed`, `missing-branch`, `regen-failed`, `gate-failed` (red gate, a gate that raised, or a gate that changed the checkout: a file left behind or a commit of its own), `skipped`. An item with a dependency that is not queued but has a local `<prefix>/<dep>` branch whose tip is not in the integration branch is `skipped` naming it (queue it or merge it first); a dependency with no local branch does not hold its dependent, and an item that lists itself as a dependency is not a cycle. Every failed step leaves the integration branch at the commit it had before the step (a red merge is rolled back; `gate-failed` keeps its sha in `MergeStep.commit`). The first failure halts the queue; `--keep-going` goes on, skipping every item with a failed or skipped dependency in the queue (the detail names it). Untracked files a failed step left behind are named, never deleted and never committed, and halt the queue in either mode. The clean-tree checks use `git status --untracked-files=all`, so they do not depend on `status.showUntrackedFiles`. An interrupt between the merge and the end of the gate (Ctrl-C, `SystemExit`, an unexpected exception) rolls the step back and is re-raised; while a step is in progress `<git dir>/ctf-integrate-step.json` names it, and a run that finds that file with the branch off the recorded base (the previous run was killed mid-step, so HEAD never passed the gate) exits 2 naming the commit to reset to; with the branch at the base the stale file is dropped. An empty queue is exit 2 for `plan` and `run`. The regenerate step (`default_regenerate`: `tools/requirements_gen.py`, `engines generate`, `engines coverage --write`, `new-event <slug> --regen` per event profile) and the gate (`default_gate`: `ctf gate run --base <pre-merge HEAD>`) run with `$CTF_PYTHON`, else the interpreter running the command (`resolve_python`; an unusable one is a failed step, not a traceback). `guard` is the hook refusal of a direct commit on the integration branch: allowed on any other branch, on the branch's first commit, and for the integrator's own commits (`$CTF_INTEGRATION_ALLOW` true; `0`/`false` or a non-boolean does not admit). A merge in progress (`MERGE_HEAD`) is not an exemption: a hand merge is a direct commit. It is opt-in: a checkout is protected once its `pre-commit` hook (every `git commit`, concluding a merge included) and its `pre-merge-commit` hook (a merge commit `git merge` makes itself) call it, and this repo's `.githooks` do not. git runs no hook for a fast-forward merge, `git reset`, `git branch -f` or `git update-ref`, so the guard cannot refuse those. After the queue, `run` makes every agent registered on a `merged` or `already-merged` branch leave the section 68 work registry (`Registry.leave_branch`, one `left` line each; no registry: nothing created; an unreadable one: exit 2, the merges stand). Nothing is pushed. Exit 0 ok/allowed, 1 some item did not merge, 2 refused/usage (B-147, B-213) |
| `work` | `ctf/cli/work.py` | the build-time work registry (B-213, section 68): `start AGENT --harness H [--branch B] [--worktree D] [--pid P] [--ttl S] [--row ID]... [--file PATTERN]... [--fold SLUG:SOURCE:PATH]... [--note N]` (register before spawn, all or nothing; `--branch` defaults to the agent name), `check [--agent A] [--branch B] [--worktree D] [claims]` (read-only), `claim AGENT [claims]`, `release AGENT [claims]`, `heartbeat AGENT`, `leave AGENT`, `list [--live]`, `reap`, `idle-status`, `idle-run [--shared] [--label L] [--agent A] [--timeout S] [--poll S] [--max-load X] -- CMD`; every sub-command takes `--state DIR`, `--backlog FILE`, `--master DIR`, `--json`. Exit 0 ok (idle-run: CMD's code), 1 a conflict (each named on stderr), 2 a named error, 3 idle-run timed out waiting |
| `campaign` | `ctf/cli/campaign.py` | `status`, `goal` (add, checkpoint, set, list), `launch`, `register`, `heartbeat`, `agent-done`, `resume [--relaunch]`, `relaunch`, `end`, `check [--hook]`, `brief`, `recover`: goals, agents, RESUME.md and briefs (section 36) |
| `scratch` | `ctf/cli/scratch.py` | `new [--shell]`, `close`, `list`, `prune`: per-challenge scratch passes with a manifest (section 36) |
| `series` | `ctf/cli/series.py` | `<id\|folder> [--json] [--no-ledger] [--no-write]`, `--index`, `[--workdir DIR] [--event SLUG]`: link a follow-up task to its series siblings in the workdir and compute the field its wording asks for (certificate serial / fingerprint / SPKI, favicon mmh3 / MD5 / SHA) from the evidence they saved (`ctf.series`); writes `recon/series.json` and `series.md`, records the reuse in the hypothesis ledger; candidates only, never submitted. Exit 0 candidates, 1 none (with the reason), 2 a bad target or workdir (B-090) |
| `lanes` | `ctf/cli/lanes.py` | `check`, `prompts`, `setup`, `run`, `status`, `integrate`: Codex build lanes from a backlog file: self-contained prompts, one checkout per lane, fenced `codex exec` with its own concurrency cap, result checks, collision-checked merge and CAPABILITIES entries (B-179, `docs/lanes.md`) |
| `backlog` | `ctf/cli/backlog.py` | `list [--status S] [--lane L] [--open] [--json]`, `open [--json]` (the open rows and the open count, computed), `set-status <id> <status>` (a done status moves the row to the Done section; with `--event` the change is also written to that event's ledger as `backlog.status`), `rank [--event SLUG] [--effort-budget U] [--board B] [--top N] [--json]` (the build-plan value model over the open rows that carry a lane and an effort: modeled estimates, not measured savings), `render [--out FILE] [--title T]` (Markdown), `sync [--write] [--no-git] [--check]` (rows and status rebuilt from `BUILD-PLAN.md`, the build-log Status lines and the Merge commits, operator-written fields kept; a dry run without `--write`; `--check` exits 1 when the file differs from a fresh sync and is an operator check, not a merge gate): the improvements backlog as rows with a closed status vocabulary (B-138, `ctf/backlog.py`). The file is `docs/backlog.jsonl`, or `--file F`; `list`, `open`, `set-status` and `render` also take `--event SLUG` for `<workdir>/backlog.jsonl` (same schema), while `rank --event` names the profile to rank for. Exit 2 = a named error (unknown status or id, missing or malformed file) |
| `ask-readers` | `ctf/cli/ask_readers.py` | ask every registered reader for the ids a lane's bank-only pass left MISSING (B-139, section 38): `list [--lane L]` (the registry in the order a lane asks it), `triage --lane L --questions Q --files DIR [--answers A] [--id QID]... [--json]` (what every reader said per MISSING id, OFFER or STOP and why; exit 1 when any id still stops), `template --lane L --id QID [--questions Q --files DIR] [--out P] [--force]` (the one-field reader, with what every reader said, into `<workdir>/ask-readers/<lane>/`), `probe --lane L --challenge CID ... [--event SLUG] [--max-per-id N] [--no-learn]` (each offer one option per request through the SubmitGate; exit 1 unless every MISSING id was accepted). Common: `--workdir`, `--root`, `--budget`. Exit 2 on unusable input |
| `orch` | `ctf/cli/orch.py` | `report`, `status`, `wait`, `brief`, `guard`, `claude-settings`: the thin orchestrator (B-200, section 43) — a solver's one status line, the one-line-per-challenge board, one debounced digest per batch of updates, the fresh-session brief, and the PreToolUse hook (with its settings file) that keeps the orchestrator session out of challenge files |
| `coord` | `ctf/cli/coord.py` | `done`, `wait`, `send`, `inbox`, `relay`, `cap`, `lanes`, `stats`: completion-driven agent coordination (B-239, section 63) — a child's completion file, one blocking wait on children / campaign agents / jobs / warm agents / claims / lane messages (exit 0 ok, 1 a target failed, 2 error, 124 timeout; a timeout under 60 s refused without `--allow-short`), a per-lane relay that delivers only a new finding or decision under a cap (`send` exit 3 when dropped), and the lane board that replaces `list_agents` |
| `findings` | `ctf/cli/findings.py` | `add`, `confirm`, `refute`, `retract`, `list`, `show`, `recheck`: the main thread's claims ledger (B-259, section 64) — `add {cause,steer} TEXT --artifact REF...` records a claim, always `suspected`, and is refused (exit 1, nothing written) with no artifact or one that does not resolve (`ledger:N`, `file:PATH[#LN]`, `git:ARGS` run read-only); `confirm ID` is a person's call (interactive terminal, id typed back); `refute ID --artifact REF` (did not hold), `retract ID --reason` (withdrawn); `list [--all]`, `show`, `recheck` (exit 1 when an artifact changed). Exit 2 on a named error |
| `handoff` | `ctf/cli/handoff.py` | `post`, `batch`, `launch`, `list`, `show`, `inbox`, `claim`, `note`, `done`, `cancel`, `reap`, `check-brief`, `modes`: the shared Claude/Codex handoff board (section 45) |
| `answer-format` | `ctf/cli/answer_format.py` | `contract FORMAT [--question T]` (what an answer_format states), `render FORMAT VALUE [--question T] [--ordered]` (one value; exit 0 plain, 3 options, 1 withheld), `batch QUESTIONS ANSWERS` (a whole delivery; exit 0 all plain, 3 some unsure, 1 any held), `synth QUESTION FILES_DIR` (a multi-file synthesis answer routed by answer-id suffix; exit 0 plain, 3 options, 1 withheld). Inputs are JSON text or `@path`; `--json`; exit 2 on unusable input. Never sends anything (B-232, section 48) |
| `machine` | `ctf/cli/machine.py` | the spec-driven register machine (B-057; engine `solvers/toolkits/spec_machine.py`, reference `docs/toolkits/spec_machine.md`): `init [PATH]` (write a starter `*.machine.toml`; never overwrites), `check SPEC [--json]` (run every worked example of the spec), `run SPEC PROGRAM [--input WORDS] [--trace]` (one program; `-` reads stdin), `play SPEC HOST PORT [--timeout S] [--max-rounds N] [--log FILE]` (the conformance gate, then answer the service round by round through `tools/netplay.py`; the target passes `ctf.scope` first; the flag is printed, never submitted); `check`, `run` and `play` take `--fuel N`. Exit 0 ok, 1 an example fails / the program trapped / no flag, 2 an error (spec, file, scope, a round that could not be answered), 4 `play` refused because not every worked example reproduces (or there is none): no connection is opened |
| `workflow` | `ctf/cli/workflow.py` | the shipped workflow registry and its pre-launch gate (B-194, section 50): `list [--json]` (the `workflows/*.js` scripts, their hard agent caps and required args), `lanes [--from board\|profile] [--event SLUG] [--workdir D] [--json]` (the lanes to fan out over — distinct lanes in the dispatch claims, or the event categories — so no workflow hard-codes a lane list), `check NAME --args-file F.json [--json]` (the required-argument schema check and the agent-cap dry-run against F; exit 1 REFUSED and names the missing arg or the over-cap count, before any agent would be spawned). Exit 0 ok, 1 refused / nothing found, 2 bad input. Never runs a model or the script |
| `geo-reconcile` | `ctf/cli/geo_reconcile.py` | the geo-sensor reconciliation harness (B-111, engine `toolkits.geo_reconcile`): `run --challenge ID [--start] \| --url URL --out DIR [--method FILE] [--event SLUG] [--json]` (GET `/schema` and the evidence through B-081's GET-only mirror under the scope guard, write the evidence pack, reconcile, write `report.json` + `reconciliation.json`; a dry run unless `--send --player-approved`, which POSTs the report once and only when `rules.web_state_changing` is true, the report is complete and schema-valid, and the POST ledger allows it: paced, capped, never a report already judged, and a send that may have reached the judge with no answer back counts and is resent only with `--resend-unknown`; the ledger is `<workdir>/geo-reconcile/posts/<challenge or host_port>.jsonl` under an exclusive lock, never per `--out`; `--challenge` reads our running instance and starts one only with `--start`, through the slot ledger), `offline PACK_DIR` (recompute from a mirrored pack, no network), `method` (print the default method JSON). A flag the judge returns is printed as a candidate, never submitted. Exit 0 report ready / accepted, 1 not ready or sent and not accepted, 2 error, 4 refused (scope, state-changing rule, approval, pacing/budget) |
| `discord` | `ctf/cli/discord.py` | Discord recon for announcement and recognition flags (B-112, section 57): `checklist [--challenge ID] [--card] [--json]` (the places a person reads in the server and what the snapshot already covers; `--card` opens one `discord` task card per challenge), `ingest FILE... [--as auto\|snapshot\|export\|text] [--where PLACE] [--kind KIND]` (a text paste, `-` for stdin, a chat exporter's channel JSON or another snapshot into `<workdir>/discord/snapshot.json`; a path inside the local Discord app's data folder is refused), `capture [--guild ID] [--first N] [--recent N] [--bots N] [--max-requests N] [--timeout S] [--min-interval S]` (the server through the bot API, GET only; needs `[discord] capture = "bot"`, the API host in `rules.public_fetch_allow` and the token variable), `analyze [--challenge ID] [--cue TEXT]... [--top N] [--json] [--no-decode]` (candidates best first; the report at `<challenge>/recon/discord.md`, else `<workdir>/discord/candidates.md`), `status [--json]`. `--event SLUG`, `--workdir DIR`. Never submits, never joins, never prints the token. Exit 0 ok (`analyze`: a candidate exists), 1 `analyze` found nothing, 2 a named error, 4 `capture` refused before any request |
| `scaffold` | `ctf/cli/scaffold.py` | write a tested scratch scaffold (B-258, section 72): `list`, `repro DIR [--target FILE.py:FUNC]` (PASS/FAIL/ERROR/OUT per case, `--expect`/`--save` an expectations file, `--pdb`), `probe DIR` (size, sha256, format, entropy, `--find`, `--at/--len` hexdump, `--strings`), `adv DIR [--target ...]` (seeded variants; a changed confident answer or a raise fails), `bench DIR [--target ...]` (CPU time, `--cpu-budget`, `--profile`), each `[--name N] [--force]`; `racer --day N [--role cx] [--lane-dir DIR] [--force]` (the complex-racer candidate `dNN_<role>_dev.py` from `solvers/binary/racer_template.py`, never the final `dNN.py`). Exit 0 written, 2 refused |
| `testpin` | `ctf/cli/testpin.py` | `--outputs FILE [--case ID] [--set KEY=JSON]... [--names RE] [--write] [--check] [--strict] TESTFILE...`: rewrite the literals test files pin from fixture outputs (an expectations document or a plain JSON object); a unified diff and no write unless `--write` (B-258, section 72); cases that disagree on a key without `--case` leave the bare key out (named on stderr, its pins skipped). Exit 0 done, 1 `--check` with a pending change or `--strict` with a skipped pin, 2 error |

`ctf submit <id> <flag> [--note N] [--confirm] [--nonstandard] [--guess] [--source S] [--passed CHECK]...`
(`--source`/`--passed`: how the value was found and the local checks it passed, as `ctf flag check`
takes them, B-154; `--guess`: an unreasoned
variant, counted against `rules.guess_budget` and logged with its note, B-173) submits on sight through the gate
and queue: exit 0 accepted, 1 not accepted (incorrect, or unjudged and left queued), 2 a named error
(no credentials, failed POST, unusable workdir; a send that raised stays queued for `submit-queue
drain`), 4 refused before anything was sent. Before the gate it runs the plausibility check (section
40): warnings go to stderr and the send goes on; a value with control characters or an empty body
is refused (exit 4).

`ctf doctor` takes `--start-docker` and `--no-codex` (skip the Codex model check and smoke call); it
ends with the `ctf preflight` checks, and a failed blocking one fails the doctor (exit 1); advisory
and sandbox-only results print as `--` with an `[advisory]` / `[sandbox-only]` tag. Inside a sandbox
(`ctf.sandboxinfo`) an unreachable Docker daemon is a `--` `[sandbox-only]` line, not an `XX`.

`permissions`, `abandon`, `worktree-commit` and `discipline` (B-043) are the sanctioned helpers (B-191, `ctf.permissions.SANCTIONED_HELPERS`): purpose-built so an interrupt-prone action is not needed. B-175 adds `job` (targeted stops of owned jobs instead of pkill/killall) and `reap` (the end-of-event reaper instead of bulk kills and deletes).
| `cockpit` | `ctf/cli/cockpit.py` | manual events only (B-209, section 5): `watch`, `sweep`, `add`, `describe`, `focus`, `file` (the drop zone); `needs`, `need`, `done` (the checklist); `enqueue`, `queue`, `next`, `accepted`, `rejected`, `confirm`, `withdraw` (the submission queue); `status`. Exit 4 = refused |
| `disk-boot` | `ctf/cli/disk_boot.py` | a networkless boot of a challenge's disk images (B-131, section 55): `plan <challenge_dir> [--out DIR] [--firmware auto\|uefi\|bios] [--memory-mb N] [--cpus N] [--machine q35\|pc] [--drive-if ide\|virtio\|scsi] [--script FILE] [--json]` (identifies the images, writes `recon/boot/plan.json`, runs nothing), `start <challenge_dir> --reason R` (the operator's: boots the plan in the `ctf-qemu-boot` container after a person at a terminal, shown the exact `docker run` command, types the folder name; exit 3 when nobody confirmed, 2 when plan.json is not what `plan` writes for the folder), `observe <challenge_dir> [--script FILE] [--qmp unix:PATH\|tcp:127.0.0.1:PORT] [--guest-out DIR] [--json]` (keys, mouse and screenshots over QMP; writes PNGs, crops and `vision-handoff.json`), `quit <challenge_dir>` (asks QEMU to exit over QMP, retires the session). Exit 0, 2 a named error, 3 refused |
| `client-replay` | `ctf/cli/client_replay.py` | a shipped client's User-Agent and URLs (B-131, section 55): `harvest <file\|dir>... [--json] [--max-bytes N] [--all]` (offline; exit 0 a custom User-Agent found, 1 none, 2 unusable input), `run <challenge_dir> [--url U]... [--ua A]... [--hops N] [--max-requests N] [--head FRAGMENT] [--include-stock] [--challenge-id ID] [--event SLUG] [--no-ledger]` (runs the engine `web.client_replay` with replay on through the runner: each in-scope URL and its first-level links once normally and once per shipped User-Agent; every URL passes `scope.check_url` first; prints the `SolverResult`) |
| `cache-keymap` | `ctf/cli/cache_keymap.py` | `--request REQ --response RESP [--source SRC] [--marker M] [--path RAW]... [--seed BASE]... [--front COMP]... [--backend COMP]... [--exfil-read PATH] [--json]` (B-105): which request inputs the front cache keys and which the backend reads, over saved request/response/source bytes, with the cache-key anomalies (unkeyed inputs, `%2e%2e` normalisation collisions) and an inert authenticated-bot exfil plan. Offline: it never sends traffic; the chain through a live bot is a human step. Exit 0, 2 an empty or unreadable input |

B-001a moves the built-in commands into their own modules; until then do not add to
`ctf/cli/__init__.py`.

**Long commands: `ctf job`** (B-144, `ctf/jobs.py`). Agents never poll their own long commands from
model turns. `ctf job start [--name N] [--cwd D] [--on-exit CMD] -- CMD...` runs CMD under a detached
supervisor (own session; CMD leads its own process group) and returns the job id; `ctf job wait ID...
[--timeout S] [--any]` blocks with no model turn and prints the wake message (status, output path, a
tail of at most 20 lines / 2000 chars, control codes stripped); `ctf job run` is start + wait; also
`status`, `tail`, `kill` (TERM then KILL of the whole group), `prune --older-than AGE [--dry-run]`
(removes the folders of jobs whose exit.json `ended_at` is at least AGE old and whose hook, if any,
has finished; never a running or lost job). The command gets SIG_DFL for SIGINT and SIGHUP even
though the supervisor shields itself from both. Wait exit codes: 0 all exited 0, 1 one
failed or was killed, 2 error (unknown job, lost supervisor, failed start), 124 timeout with the job
still running. Records: `<jobs root>/<id>/{job.json, output.log, lock, exit.json, summary.txt}`; jobs
root = `--jobs-dir`, else `$CTF_JOBS_DIR`, else `<workdir>/jobs`. State comes from files only (exit.json,
else the supervisor's flock held = running, else lost), never from a pid. `--on-exit` runs once after
exit with the wake message on stdin (how an orchestrator resumes an agent that ended its turn). The
event rules template carries the rule (section "Long-running commands").
B-175 makes these named jobs with owners (section 60): `start`/`run` take `--owner O` (default
`$CTF_JOB_OWNER`) and `--exclusive` (refuse a second live job of the same `--name`); `list [--owner O]
[--live] [--json]` is the registry (name, owner, pid, pgid, pidfile, state); `stop ID|NAME` is `kill`
by id or by the name of the one live job (a lost job is stopped by its exact identity); `reap --owner O
[--dry-run]` stops every live job of one owner (exit 1 when one could not be stopped). job.json gains
`owner`, `owner_pid`, `owner_start`, `pgid`, `pid_start`, `supervisor_start`, and the folder a `pid`
pidfile. `kill` also refuses a supervisor pid whose start time differs from `supervisor_start`.

## 9. Test markers

Registered by `ctf/testing/pytest_plugin.py`, loaded from the root `conftest.py`:

| marker | effect |
|---|---|
| `@pytest.mark.needs_tool("radare2", "py:cv2")` | not run unless every binary is on PATH / in the venv bin and every `py:` module is importable |
| `@pytest.mark.needs_realdata` / `needs_realdata("sub")` | not run unless `paths.realdata_root()` (or that subfolder) exists; several marks: every subfolder must exist; an empty root counts as absent |
| `@pytest.mark.needs_loopback` | not run unless this process can bind and connect on 127.0.0.1 (`capabilities.loopback()`); B-192 |
| `@pytest.mark.needs_jit` | not run unless a child process can run JIT code and, when installed, Unicorn (`capabilities.jit()`); B-192: Unicorn dies with SIGILL under Codex's seatbelt |
| `@pytest.mark.live` | never runs unless `--run-live` or `CTF_RUN_LIVE=1` |
| `@pytest.mark.slow` | tag only: runs by default; `-m "not slow"` deselects |

Every run ends with a `NOT RUN: N test(s) did not run (needs_realdata a, needs_tool b, needs_loopback
g, needs_jit h, live c, known-fail d, xfail e, skip f)` section listing each test that did not run (marker skips,
hand-written skips, xfails, known failures, and parts a test reported with
`pytest_plugin.record_not_run(item, label, reason)`) grouped by reason; it works under xdist.
**Strict mode:** `CTF_STRICT_TESTS=1` (or `--strict-not-run`) makes a run with anything in that list
exit 1 even when everything that ran passed; use it for CI and the pre-event gate. Rules: a missing
dependency is a skip with a named reason, never a pass; do not `importorskip` inside a test body when
a marker fits; never write `if not available: return`.

**Sandbox capabilities** (B-192, `ctf/testing/capabilities.py`). Codex's workspace-write sandbox
denies loopback bind and kills Unicorn (its seatbelt denies the sysctl `hw.cachelinesize`; QEMU then
reads a trapping register). Each probe runs once per process; the JIT probe runs in a child, since a
failing JIT engine kills its process. **Auto not-run:** when the loopback probe failed, a test (marked
or not) that fails in setup or call with a socket denial (an `OSError` with errno EPERM/EACCES and no
file name, also when explicitly wrapped: `__cause__` (`raise ... from`), a `reason` attribute
(`URLError`, urllib3), or an exception among a non-`AssertionError`'s `args` (requests)) is reported as
skipped `needs_loopback: <probe error> (auto: ...)`. `__context__` is not followed: an assert that
fails while an EPERM is being handled is a real failure. With loopback working such a failure stays
a failure, and a denied file operation (it carries the file name) always does.

```python
from ctf.testing import capabilities
capabilities.loopback(); capabilities.jit()      # Capability(ok, reason), cached per process
capabilities.probe_loopback(); capabilities.probe_jit(argv=None, timeout=JIT_PROBE_TIMEOUT_S)  # uncached
capabilities.classify_jit(returncode, stdout, stderr)   # only "JIT-OK 42" with exit 0 is ok; -N or 128+N = signal N
capabilities.is_socket_denial(exc)               # the auto not-run test
capabilities.reset()                             # forget cached results
capabilities.JIT_PROBE_SRC                       # the child's source (MAP_JIT page, then Unicorn when installed)
```

**Failure-sink guard** (B-001d). Carried script-style tests check with a helper that prints `FAIL`
and appends to a module-level `FAILED` / `FAILS` / `FAILURES` list, bumps a `FAIL` counter or appends
`False` to a `RESULTS` list, and never raises; pytest used to report them passed. The plugin snapshots
those module globals around each test call and fails the test when one grew, naming the checks. New
tests use plain `assert`.

**Known failures** (`tests/known_failures.toml`): failures the guard exposed that another unit owns.
One table per test node id: `reason` (required: what fails and who owns it), `checks` (optional list
of check labels; numbers are compared as `#`), `strict` (optional, default true). A listed test whose
failing checks are all listed is reported xfail as `known-fail: <reason>`; an unlisted failing check
fails it; when every check passes it fails with "remove the entry" (unless `strict = false`, for an
order-dependent one). Fixing one = fix the engine, delete the entry.

**Real-data tests** (`tests/real/`): carried Huntress scripts, collected by `tests/real/conftest.py`
as `<script>::realdata` (needs_realdata per corpus folder; any FAIL or SKIP fails it),
`<script>::synthetic` (the corpus-free checks, run against an empty corpus) and `<script>::live`.
Every script there must be listed in that file's `SCRIPTS`, with its corpus folders. A FAIL line
matching a script's `known_fail` pattern is reported as `known-fail: <reason>` instead of failing. A
script that needs an external tool for every item declares `tools=("py:scapy", ...)`; each becomes a
`needs_tool` marker on every item it yields, so a missing tool reports as not run. The OT oracle
(`tests/real/test_real_ot.py`, B-204) uses `needs_realdata("ot")` for the per-protocol corpus at
`$CTF_REALDATA/ot/<proto>/`, fetched by `tests/real/fetch_ot.py` (an operator step gated by
`rules.public_fetch_allow`; it refuses to write under `paths.DEFAULT_REALDATA`). The IQ demodulators
(`tests/test_iq_demod_real.py`, B-158) use `needs_realdata("rf-iq")` for operator-supplied off-air
captures: `$CTF_REALDATA/rf-iq/**/<capture>` beside `<capture>.expect.json` (`protocol`, and
optionally `rate`, `format`, `min_frames`, `contains`); nothing fetches them. The same file uses
`needs_realdata("rf")` for the rtl_433 captures of the carried `rf` kit as a negative control.

**PLC reference pairs** (B-160, `solvers/toolkits/ot_plc_code_pairs.json`, schema `plc-pairs-1`; it
sits beside the opcode table, not under `tests/real/`, because the engine reads it at run time): a
pair is a compiled sample plus its known source listing, pinned by both sha256, kept at
`$CTF_REALDATA/plc/<pair id>/<sample>` and `<listing>` (placed by the operator; there is no fetcher).
A pair is the only oracle for an entry of the opcode table `solvers/toolkits/ot_plc_code_tables.json`
(schema `plc-opcodes-1`): the loader refuses an entry with no `oracle {pair, sample_sha256,
listing_sha256}`, and `ot_plc_code.load_table` holds every citation to the manifest at run time: the
shipped table is refused when an entry cites a pair the manifest does not pin, and another table
(`--table`) loads with `table.citations = "unpinned"` in every report (`empty` | `pinned` | `unpinned`
| `unchecked`; none of them means proven). `tests/test_ot_plc_pairs.py` refuses a citation the
manifest does not pin (always on) and proves every entry on its pair under `needs_realdata("plc")`
(`ot_plc_code.verify_table`). A pair that an entry cites must decode completely and exactly. A pair
may be pinned before any entry reads it: it is then `unused` (`verify_table` lists it under
`unused_pairs`), its digests and its use as a pair are still checked, and it fails only when
something decoded of it differs from its listing. The oracle reports not run, never a pass, with no
pinned pair and with pairs pinned while the table is empty ("pinned, unused"). **A shipped table with entries
must be proven wherever the suite runs**: `test_a_shipped_table_with_entries_fails_without_its_proof`
is always on and fails, never skips, when the table has entries and `$CTF_REALDATA/plc/` is absent or
does not prove them (`ot_plc_code.unproven_reasons`), so an entry cannot merge on a pin row alone;
while the table is empty it needs no corpus. An unpinned idea goes under `candidates`, never `pairs`.
The engine entry is `solve` (a `SolverResult`: `blocked` while compiled logic is there and none of it
can be read, `unsure` when some was decoded or, with nothing opaque, a likely artifact failed to
parse, `none` otherwise; a file counts as an MC7 block by its header, the `pp` signature plus a load
size equal to the file size, not by the signature alone);
`--listing`, `--table-status` and `--verify-pairs` are the same file run as a script.

Plugin helpers a test or a conftest may call (the `pytest_*` functions are pytest hooks):

```python
from ctf.testing import pytest_plugin
pytest_plugin.tool_available("radare2")   # what needs_tool checks: a binary on PATH / venv bin, "py:<module>" importable
pytest_plugin.record_not_run(item, label, reason)   # list one part of a test in the NOT RUN report
pytest_plugin.strict(config)              # CTF_STRICT_TESTS=1 or --strict-not-run
pytest_plugin.known_failures(config)      # {nodeid: (reason, labels | None, strict)} from tests/known_failures.toml
pytest_plugin.norm_label(label)           # a check label with numbers as "#"
pytest_plugin.kind_of(reason)             # the NOT RUN group of a skip reason
```

**Loopback fixture** (B-153, `ctf/testing/loopback.py`, registered by the plugin): a test that starts a
fake service takes `loopback` and calls `loopback.http(handler)`, `loopback.tcp(handler)` or
`loopback.socket("tcp"|"udp")` -- 127.0.0.1, port 0, closed at teardown. A sandbox-denied bind fails the
test with a `GATE-ENV:` message (the gate reports ENV, section 23), never a skip and never a pass.

**Audit:** `python tools/test_audit.py [paths]` lists tests that do not test (empty body, only
`main()`, no assertion, a check() that never raises, constant or tuple asserts, a mock of the unit
under test, `if ...: return` instead of a skip, swallowed assertions, files pytest never collects,
checks run at import). Exit 1 on findings. Open findings: `docs/migration/HOLLOW-TESTS.md`.

## 10. Budget and ledger

`ctf/budget.py` (B-033):

```python
class Meter(Protocol):
    def add_spend(self, challenge_id: str, usd: float, tokens: int) -> None: ...
    def spent(self, challenge_id: str) -> Spend: ...      # Spend(usd, tokens)
    def cap(self, challenge_id: str) -> float: ...
budget.cap_usd(profile.budget, points, days_open=None, solves=None) -> float   # the one cap rule
budget.overthink_cap(profile.budget, points, solves) -> float | None   # the B-130 clamp, None when it does not apply
budget.high_value_points(profile.budget)                          # points where the value cap stops biting
budget.BudgetExceeded(challenge_id, spent_usd, cap_usd)            # raised at the cap
budget.ChallengeStopped(challenge_id, reason, detail="")          # raised by check() on a stopped challenge
m = budget.LedgerMeter(profile, workdir=None, points=None, ...)   # the Meter; all state in the ledger
m.add_spend(cid, usd, tokens, source=None); m.register(cid, points=, solves=, opened_at=, tail=, name=)
m.extend(cid, usd, by=, reason=); m.stop(cid, reason, by=, note=); m.resume(cid, by=); m.mark_progress(cid)
m.status(cid) -> ChallengeStatus; m.check(cid) -> ChallengeStatus   # check() raises at the cap / on a stop;
                                                                  # add_spend records, then raises BudgetExceeded at the cap
budget.extend_hint(status)                                        # the "how to extend" line for the player
budget.on_team_solve(challenge_id, solver=None, workdir=None)     # the solved watcher's stop hook
budget.is_stopped(challenge_id, workdir=None) -> str | None       # the active stop reason
```

Cap rule: `clamp(per_point * points, floor, ceiling)`; unknown points -> floor; with
`per_challenge_day` set, `min(ceiling, per_challenge_day * days_open)`. Overthink clamp (B-130): when the
profile sets all three `budget.overthink_*` keys and the solve count is known (a `budget_challenge`
record's `solves`, else the `solves=` adapter given to `LedgerMeter`), a challenge with
`points <= overthink_max_points` and `solves >= overthink_min_solves` is capped at
`min(cap, overthink_usd)`; it only lowers the cap and never fires on an unknown count. At the cap: checkpoint and ask
the player; an extension is a human decision (`python -m ctf budget extend`), recorded as a
`budget_extend` ledger event. High-value tails stop after 20 minutes with no progress-type event.

Opt-in OSINT box (B-115): `LedgerMeter(..., token_cap=None, time_box_seconds=None)` adds a per-challenge
live-OSINT token cap and wall-clock time box (both default `None`; a meter that sets neither is
byte-for-byte unchanged and never raises the box). When either is reached (token cap first, then the
time box), `check()` raises `budget.OsintBoxExceeded(challenge_id, reason, ...)` with reason
`OSINT_TOKEN_CAP` / `OSINT_TIME_BOX` -- a signal, not a stop; the B-115 handoff rig catches it. `status()`
then carries `token_cap`, `tokens_left`, `box_seconds_left` and `box_state` (`ok` / `over_tokens` /
`over_time`); all four are `None`/`ok` when no box is set.

`ctf/ledger.py` (B-101 builds the replay on it):

```python
ledger.append(event_type, *, workdir=None, **fields) -> dict   # one JSON line, flock + O_APPEND
ledger.read(workdir=None) -> Iterator[dict]                   # raises on a corrupt line
ledger.path(workdir=None) -> Path                             # <workdir>/ledger.jsonl
```

File: `<workdir>/ledger.jsonl` (mode 0600). Record: `{"ts": epoch, "event": type, ...fields}`.
Event types are `lower_snake`, dots for namespaces; new types need no registration. Stage
vocabulary: `detect`, `claim`, `first_tool`, `candidate`, `submit`, `accepted`, `rejected`, `spend`,
`budget_extend`, `stop`. Fields whose key names a secret (any key containing token, cookie,
authorization, password, passwd, secret, api_key/apikey, any case) and the reserved keys `ts`/`event`
are refused with a `ValueError`.

**Count keys: a token count is spelled `tok`.** The secret-key rule refuses every key containing
"token", including counts (`tokens`, `input_tokens`); there is no allow-list, so one record never
has two spellings. Write `tok` (or `<kind>_tok`, e.g. `in_tok`, `out_tok`, `cache_tok`); the refusal
message says so. `Cost.tokens` and `Spend.tokens` keep the word in Python, where it is not a ledger
key.

Records written today. The doc test writes each one, with every optional argument and again with
none, and checks it both ways: every field a record has is listed in its row, every field without
`?` (optional) is in every record, and every `?` field is left out of at least one.

| event | writer | fields |
|---|---|---|
| `engine.run` | `ctf.engines.runner.record_run` | `engine`, `via`, `exit_code`, `seconds`, `status`?, `challenge_id`? (section 6) |
| `platform.submit` | `ctf.platform.rules.EventRules.record`, `ctf.platform.queue.SubmitQueue._record_error` | `event_slug`, `challenge_id`, `status`, `judged`, `guess`, `confirmed`, `provenance`, `post_stop`, `rotating`? (a ctf.dynamic send), `sweep`? (the authorization id of a sweep send, B-173), `error`? (a send that raised; status error), `answers`? (a batch's answer count, B-044), `partial`? (banked, answers still open), `remaining`? (answers still open after a correct send, from a Game Master reply: `accepted` -> its count, `CORRECT` -> 0; B-016), `attempt_id`? (a send naming its timed attempt), `ranked_retry`?, and exactly one of `flag`? (flag_sharing allowed) or `flag_sha256`? (forbidden) |
| `platform.approval` | `ctf.platform.rules.EventRules.grant` | `event_slug`, `challenge_id`, `count`, `reason` (the player's approval past wrong_answer_stop, B-006) |
| `platform.sweep_auth` | `ctf.platform.rules.EventRules.authorize_sweep` | `event_slug`, `challenge_id`, `auth_id`, `count`, `reason`, `expires_at` (epoch; the player's one-run sweep authorization, B-173) |
| `scope.pointed` | `ctf.eventpolicy.point` | `event_slug`, `challenge_id`, `host`, `port`? (absent = any port), `reason` (a challenge service the player pointed at, B-173) |
| `scope.unpointed` | `ctf.eventpolicy.unpoint` | `event_slug`, `host`, `port`?, `reason` (withdraws the point with the same host and port) |
| `hof.start` | `ctf.platform.halloffame.record_start` | `event_slug`, `challenge_id`, `attempt_id`, `origin` (`fresh`/`own`/`foreign`/`unknown`), `late_s`, `elapsed_s`, `deadline`, `eligible`, `regular`, `pool`, `counts`, `reason` (a classified timed start or retry reply, B-044; null where the reply said nothing) |
| `hof.result` | `ctf.platform.halloffame.record_result` | `event_slug`, `challenge_id`, `attempt_id`, `status`, `eligible`, `regular`, `pool`, `counts`, `note` (every timed result, B-044) |
| `submit.done` | `ctf.platform.queue.SubmitQueue._done` | `event_slug`, `challenge_id`, `status`, `attempts`, `held_s`, `queued` (one per finished queued call, B-006) |
| `spend` | `LedgerMeter.add_spend` | `challenge_id`, `usd`, `tok`, `source`? |
| `budget_challenge` | `LedgerMeter.register` | `challenge_id`, `points`?, `solves`? (the solve count, B-130), `opened_at`?, `tail`?, `name`? |
| `budget_extend` | `LedgerMeter.extend` | `challenge_id`, `usd`, `by`, `reason`, `cap_usd` |
| `budget_checkpoint` | `LedgerMeter.add_spend`, `LedgerMeter.check` (at the cap, once per cap) | `challenge_id`, `spent_usd`, `cap_usd`, `path` |
| `stop` | `LedgerMeter.stop`, `on_team_solve` | `challenge_id`, `reason` (`team_solve` / `no_progress` / `manual`), `by`?, `note`? |
| `budget_resume` | `LedgerMeter.resume` | `challenge_id`, `by` |
| `progress` | `LedgerMeter.mark_progress` | `challenge_id`, `note`? |
| `build_plan.rank` | `ctf.buildplan.record` | `slug`, `approved`, `effort_budget`, `board_visible`, `items_sha256`, `estimate` (section 16) |
| `build_plan.check` | `ctf.buildplan.check_build` | `item`, `slug`, `phase`, `allowed`, `reason` (section 16) |
| `intake` | `ctf.intake.record`, called by `ctf.intake.intake_one` | `challenge_id`, `status` (a `SolverResult` status), `seconds`, `stages` (`download`/`sweep`/`engines`/`fastlane` seconds), `files`, `members`, `engines`, `flags` (counts) (section 19) |
| `quota.reading` | `ctf.quota.record` | `harness`, `window`, `exhausted`, `by`, `used_pct`?, `resets_at`? (epoch), `note`? (a quota reading the player took off the harness's usage screen, B-171) |
| `intake.autosubmit` | `ctf.intake.autosubmit.auto_submit` (one per attempt handed to the gate) | `challenge_id`, `sent`, `status` (a `SubmitStatus` value, or `error` when the gate raised: outcome unknown, recorded `sent`), `accepted`, `cap`, `error`? (B-012, section 19) |
| `spend.cap` | `ctf.spendgov.set_cap` | `phase` (a spend category), `usd`, `period` (`day` / `event`), `by`, `reason` (the player's phase cap, B-202; the latest per phase wins) |
| `spend.mode` | `ctf.spendgov.decide_mode` | `mode`, `usd`, `by`, `reason`, `challenges`? (globs; custom modes only), `value`? (what the player decided a place is worth), `minutes`? (time box from the mode's first spend, B-202) |
| `review.round` | `ctf.spendgov.record_round` | `scope`, `tree` (sha256 over the reviewed files), `tier`, `files` (count), `findings` (severity to count), `by`? (B-202) |
| `investigation.open` | `ctf.spendgov.open_investigation` | `inv_id`, `question`, `metric`, `threshold`, `minutes`, `usd`, `by` (B-202) |
| `investigation.close` | `ctf.spendgov.close_investigation` | `inv_id`, `answer`, `by`, `note`? (B-202) |
| `adapt.gate` | `ctf.adapt.regress.record_gate`, called by `ctf.adapt.regress.gate` | `lane`, `verdict` (`yes`/`no`/`not-run`), `lane_key`, `cases`, `ran`, `warm`, `recut`, `regated`, `not_run` (counts), `seconds`, `scale`, `reason`, `jobs`, `nice` (cases replayed at once and their niceness, B-253) (B-036, section 29) |
| `adapt.chain` | `ctf.adapt.chain.plan` | `challenge_id`, `lane`, `action` (`wait`/`start`/`retry`/`stop`/`hold`/`done`), `reason` (B-036, section 29) |
| `adapt.closed` | `ctf.adapt.chain.mark_closed` | `challenge_id`, `by` (`teammate`/`hand`), `note` (B-036, section 29) |
| `adapt.attempt` | `ctf.adapt.chain.record_attempt` | `challenge_id`, `outcome` (`correct`/`incorrect`/`not_submitted`/`expired`), `lane_key`?, `note`?, `artifact_sha256`?, `missing`?, `learned`? (the same-artifact retry rule, B-253) (B-036, section 29) |
| `lookahead.gate` | `ctf.lookahead.gate.record`, called by `ctf.lookahead.gate.gate` | `lane`, `verdict` (`green`/`red`), `specimens`, `ran`, `questions`, `deterministic`, `answered`, `wrong`, `unsure`, `unanswered`, `skipped`, `gaps` (counts), `seconds` (B-174, section 35) |
| `lookahead.score` | `ctf.lookahead.forecast.score` | `lane`, `day`, `new`, `hit`, `missed`, `unused` (counts), `recall` (null when nothing was new), `gap_ids`?, `gap_missed`? (with a day report) (B-174, section 35) |

Launcher gate (R-09, `tools/launch_gate.py`): `tools/codex_launch` and `tools/claude_launch` take
`--challenge ID` (or `$CTF_CHALLENGE`). Gated, they call `LedgerMeter.check()` before starting and every
`--gate-poll` seconds while the agent runs; a capped or stopped challenge is refused, or the running
agent stopped, with exit code 3 and a message naming the reason and the lifting command (`ctf budget
extend` / `ctf budget resume`; a team-solve stop is final). Spend read from the agent's own output
(`codex exec --json` turn usage, `claude -p --output-format stream-json`) is charged as `spend` with
`source="launcher:<harness>"`. Ledger events: `agent_launch` (`model`? since B-016; `role`? since B-096;
`job_owner` since B-175; `difficulty`?, `effort`?, `tier`?, `route`?, `category`?, `tier_budget_usd`? on a
routed launch since B-201, section 67), `agent_refused`, `agent_exit` (`reason` `route_budget` when a
speed-tier run spent its route's `budget_usd`), `agent_stop` (section 27), and, after
`agent_exit` when the agent left live jobs, `jobs_reaped` {`owner`, `stopped` (job ids), `failed` (job
ids), `error`?} (B-175: the supervised agent's jobs are stopped when it exits). `--session NAME` (or
`$CTF_SESSION`) claims a session first and refuses with exit 3 while a previous holder is alive by pid
and start time (section 60). `--role` (or `$CTF_ROLE`) names the agent's
work role for cost accounting; it must be one of `ctf.stages.SPEND_CATEGORIES` (solve, build, verify,
doc, orchestrate, guardian, other) and an unknown role is refused with exit 2 before the agent starts.
After the budget check the launchers run the per-challenge
agent gate (section 39): the 6th agent on a challenge is held for the player and refused with exit 3;
records for an admitted run carry `spawn_id`. Without a
challenge the launchers say on stderr that the gate is off and exec the agent as before.

Player notes (B-168, `ctf/notes.py`, `python -m ctf notes`): the per-event feed of what only the player
sees (organizer rulings, Discord fixes, solve counts), kept in `<workdir>/notes/` (`feed.jsonl`,
rendered `NOTES.md`, drop folder `inbox/`, hand-edited `player-notes.md`, per-agent `cursors/`).
`Feed.pending(agent, challenge=)` returns the notes and retractions that agent has not seen and moves
its cursor; a note with a challenge reaches agents on that challenge and agents with none.
`tools/claude_launch` adds a `hooks` block to the session settings (unless `--no-notes`) that runs
`python -m ctf.notes --dir <notes> hook [--challenge ID]` on SessionStart, UserPromptSubmit and
PostToolUse and answers with `hookSpecificOutput.additionalContext`, and makes the notes folder
unwritable to that session (`Edit(/<notes>/**)` in `permissions.deny`, the folder in
`sandbox.filesystem.denyWrite`; the hooks run outside the sandbox). Other harnesses pull with
`python -m ctf notes pending --agent NAME`, as the generated event rules say. Ledger events (ids,
never the text): `notes.add` {`note_id`, `kind`, `challenge_id`, `source`, `attachments` (a count)},
`notes.retract` {`note_id`, `target`, `challenge_id`}, `notes.delivered` {`agent`, `challenge_id`, `ids`}.

B-100 adds `model_fallback` (`tools/ledger/fallback.py`): one per session a safety classifier moved off
`models.primary`, fields `log, log_key, from_model, to_models, first_fallback_ts, minutes_to_fallback,
responses, stuck, fallback_only, premium_usd, cyber_verified[, challenge_id]`; an alert and a replay
record, not spend (the feed charges spend at the fallback's real rates).

Usage ledger (B-193, `tools/ledger/usage.py`, `tools/ledger/sources.py`, `python -m ctf usage`):

```python
from tools.ledger import sources, usage
usage.ingest(workdir, roots, *, harnesses=("claude", "codex"), refs=None, claude_home=None, codex_home=None)
    -> IngestResult(logs, new, superseded, outside, no_cwd, legacy_rollouts, served, notes)
usage.load(workdir) -> {key: row}            # <workdir>/usage/responses.jsonl, de-duplicated
usage.Attributor(workdir).of(row) -> (challenge_id | None, "assign" | "assign:parent" | "cwd" | None, why)
usage.summarize(rows, prices, attributor, *, roles=None) -> Report   # by_model (harness, model, tier),
                                             # by_challenge, unattributed (by agent, with why),
                                             # agents (model served), ttl_assumed, unpriced; and when
                                             # `roles` (agent id -> role) is given, by_role {role, responses,
                                             # tok, usd} and by_role_model {role, harness, model, tier, ...}
                                             # (a response whose agent has no role -> DEFAULT_ROLE "unknown";
                                             # without `roles` both stay []) -- B-096
usage.reconcile(report, ledger_records) -> [Reconciled(challenge_id, usage_usd, usage_tok, ledger_usd, ledger_tok)]
usage.charge(meter, reconciled) -> [(Reconciled, "charged" | "at_cap")]   # spend source usage:reconcile
usage.assign(workdir, agent, challenge_id, *, by, note=None)
usage.assign_role(workdir, agent, role, *, by, note=None)   # role in ctf.stages.SPEND_CATEGORIES -- B-096
usage.roles_from_ledger(records) -> {agent: role}           # from usage.role events, latest wins
usage.ttl_report(rows, prices, *, window_s=300) -> TtlReport  # B-118: per Claude thread (agent), 1h
                                             # writes whose next response came within window_s (hit_5m,
                                             # saving = GROSS, priced at the 5m rate), after it (late_1h,
                                             # saving_late), none (last_1h, saving_last); the counter-cost:
                                             # responses > window_s and <= 1h after the previous one in a
                                             # thread that wrote 1h, cache_read priced as 5m writes minus the
                                             # read (reread_late, tok_reread_late, cost_late); net = saving +
                                             # saving_late + saving_last - cost_late; 5m writes followed
                                             # after window_s (late_5m); by_kind, total, no_ts, unpriced
sources.claude_logs(roots, home=None); sources.codex_logs(roots, home=None) -> ([LogRef], notes)
sources.thread_db(home=None) -> ({id: Thread}, path | None)   # newest state_<n>.sqlite, opened immutable
                                             # (uncheckpointed -wal pages unseen; codex_logs notes a non-empty -wal)
```

One row per model response: Claude keyed by `message.id` (the line with the most output wins), Codex
by `response_id` (the record whose payload `thread_id` is the rollout's own thread wins: a fork's replay
of its parent is charged to the parent once). Rows hold token counts, `model` (the model served),
`speed` (Claude `fast`/`standard`; Codex the service tier at that response, Astra `ultrafast` is 6x),
the cache-write TTL split, `ttl_assumed` (an undivided cache write, priced at the 5m rate and counted in
every report), `agent`/`parent`/`kind`, `cwd`. Prices are applied at report time from
`tools/ledger/pricing.json`; an unknown model is listed unpriced (exit 4), never guessed. Sessions are
found by working folder (Claude project names; the Codex thread DB `cwd`, else a rollout's
`session_meta`); a response whose cwd is outside the workdir and every `--root` is never stored. Both
homes are read, never written. Attribution, one rule for both harnesses: a `usage.assign` for the agent,
else for its parent chain, else the challenge folder of the cwd (`<workdir>/<folder>/challenge.json` id);
anything else is reported unattributed by agent. Ledger events (not in the table above; tools/ writers):
`usage.served {harness, agent, model, kind, first_ts, parent?, challenge_id?}` once per (harness, agent,
model); `usage.assign {agent, challenge_id, by, note?}`; `usage.role {agent, role, by, note?}` (B-096, the
agent's work role for the `summarize(roles=)` split). `reconcile --charge` writes ordinary `spend`
events with `source="usage:reconcile"` for the amount the usage ledger exceeds the ledger's spend for a
challenge (every source counted), so re-running charges nothing more.

Verify A/B harness (B-096, `tools/ledger/ab_verify.py`): the harness and role plumbing for moving half of
verify work to Sonnet (EFFICIENCY-PLAN 3.8), not the live trial.
`run_ab(diffs, configs) -> ABResult(diffs, bugs_total, configs=[ConfigResult(name, model, diffs, bugs_total,
found, missed, recall, usd, tokens)], scores=[DiffScore(diff_id, config, found, missed, usd, tokens)])`
feeds each `SeededDiff(id, diff, bugs=[SeededBug(id, marker, regex=False)])` to each
`ReviewerConfig(name, model, review)` reviewer (a callable `diff -> Review(text, usd, tokens) | str`) and
counts which seeded bugs' markers appear in the review text. `load_corpus(obj)` parses the JSON corpus;
`record_result(workdir, result, *, by, approved=False, approved_model=None, note=None)` writes an
`ab_verify {by, approved, diffs, bugs_total, configs, approved_model?, note?}` ledger event (the real
Opus-vs-Sonnet run is a human step whose result is this record). `chosen_verify_model(records, *, primary,
candidate) -> model` returns `candidate` only once an approving `ab_verify` record names it, else
`primary`, so verify stays on the primary model until the A/B has approved the move.

Quota meter, allowance reserve and scheduling (B-171, `ctf/quota.py`, the session-log scanner
`tools/ledger/quota.py`, `python -m ctf quota`, the profile's `[allowance]` table, section 1):

```python
from ctf import quota
quota.Reading(harness, window, ts, source, used_pct=None, resets_at=None, exhausted=False,
              window_minutes=None, note="")        # .full; Reading.from_dict(d); r.to_dict()
quota.merge(latest, readings) -> int             # newest per (harness, window)
quota.window_name(minutes)                       # 300 session, 10080 weekly, else "<n>min"
quota.record(workdir, harness, window, used_pct=None, resets_at=None, exhausted=False, by="max", note=None)
quota.readings(workdir, records=None) -> ({(harness, window): Reading}, {harness: last served epoch})
quota.load_state(workdir); quota.save_state(workdir, st); quota.state_path(workdir)   # <workdir>/usage/quota-state.json
quota.next_release(profile, now) -> epoch | None # dates.start, allowance.releases, allowance.daily_release
quota.event_span(profile) -> (start, end)       # epoch, end exclusive; naive/date-only in allowance.tz,
                                                 # a date-only end is the whole day (next_release, clockline)
quota.limit_pct(kind, reserved, allowance)       # writeup/retro/release 100; solve 100 - reserve when
                                                 # reserved; build min(build_ceiling_pct, that)
quota.window_state(reading, last_ok, allowance, now, release) -> WindowState(harness, window, status,
    used_pct, effective_pct, resets_at, open_at, reserved, reading_ts, source, note)
    # status ok | unmetered | exhausted | probe
quota.DISPROOF_GRACE_S                           # 300: a served response clears a limit hit only this long after it
snap = quota.snapshot(profile, workdir=None, now=None)    # Snapshot(now, next_release, allowance, harnesses)
snap = quota.build_snapshot(profile, latest, last_ok, now)
# HarnessState(harness, status, windows, last_ok): .metered; Snapshot.read (any reading at all)
quota.Job(id, kind, harnesses=quota.HARNESSES, prefer=None, est_pct=None)   # .est; Job.from_dict(d)
quota.load_jobs(data) -> [Job]                   # a JSON list, or {"jobs": [...]}
plan = quota.schedule(snap, jobs)                # Plan(now, next_release, assigned, held, batches, warnings)
# Assignment(job, kind, harness, mode fit | unmetered | probe, est_pct, headroom_pct)
# Held(job, kind, release_at, reasons {harness: why}); batches [(release_at | None, (job ids))]
quota.next_wait(plan) -> epoch | None            # the first held batch with a known time
quota.check(profile, workdir=None, now=None)     # -> doctor.Check: the doctor's "allowance" check
quota.funded_at(harness_state, at) -> bool       # can take release work at `at` (a named reset is believed;
                                                 # no window = unmetered = funded); used by check and ctf.failover
days, undated = quota.daily(rows, records, price=pricing_fn, tz="UTC", allowance_usd=0.0)
# Day(date, usage_usd, usage_total, spend_usd, spend_total, total, allowance_usd, over, unpriced)
quota.fmt_time(epoch)
quota.QuotaError                                 # a ValueError naming the bad reading, job or state
from tools.ledger import quota as qscan
qscan.scan(workdir, roots, harnesses=("claude", "codex"), refs=None, claude_home=None, codex_home=None, tz=None)
    -> ScanResult(logs, lines, readings, hits, served, untimed, notes)
qscan.parse_reset(text, ts, tz=None); qscan.limit_reading(harness, text, ts, tz=None)
qscan.claude_line(line, roots=None, tz=None); qscan.codex_line(line, fallback_ts=0.0, tz=None)
qscan.rate_limit_readings(rate_limits, ts); qscan.window_of(text)
```

Readings: Codex `rate_limits` snapshots (`used_percent`, `window_minutes`, `resets_at` or
`resets_in_seconds`) and both harnesses' limit-hit messages (on API-error lines only; subagent/thread
caps, context limits and transient rate limits are not quota), plus the last served response per
harness, read by `scan` from the same session logs the usage ledger finds (by working folder, homes
read-only) into `<workdir>/usage/quota-state.json`; and `quota.reading` ledger events from `quota set`.
The newest reading per (harness, window) wins. A reading counts `margin_pct` higher. A limit hit is
`exhausted` until its named reset or `recheck_minutes` after it, whichever is first, then `probe` (one
job may find out); a response served more than `quota.DISPROOF_GRACE_S` (300 s) after the hit makes
it `unmetered` (the reading was wrong); one logged sooner may have been in flight when the limit hit
and disproves nothing. A window whose reset passed counts as reset. Scheduling: kind order writeup/retro, release, solve, build;
the preferred harness when it fits, else the most headroom, then unmetered, then probe; jobs add their
`est_pct` to the windows of the harness they go to; the rest are held with a reason per harness and
the latest time all of a harness's blocking windows open (the earliest such time among its
harnesses), batched by that time. The doctor's check fails only when every harness is known to be
blocked through the next release (a named reset is believed there). It warns with no reading at all,
a harness exhausted / in probe / unmetered, an eaten reserve, a reading over 6 h old, and while the
event runs with no release configured (`allowance.releases` and `daily_release` both empty, as the
scaffold writes them: the reserve would never apply). `ctf preflight --strict` therefore fails until a
quota reading is recorded (`ctf quota scan` or `ctf quota set`) and, during the event, a release is
configured (section 16).

Build and review spend governors (B-202, `ctf/spendgov.py`, `python -m ctf spend`):

```python
from ctf import spendgov as sg
sg.set_cap(phase, usd, *, period="day"|"event", by, reason, workdir=None)    # spend.cap
sg.decide_mode(mode, usd, *, by, reason, challenges=(), value=None, minutes=None, workdir=None)   # spend.mode
sg.gate(*, phase=None, mode=None, challenge_id=None, workdir=None, now=None, tz="UTC", records=None)
    -> Verdict(allowed, reasons, checked)          # held: no cap / budget decided yet, or it is spent
sg.phase_status(phase, records, *, now, tz) -> PhaseStatus(phase, cap, spent, since, state ok|over|uncapped, undated)
sg.mode_status(mode, records, *, now=None) -> ModeStatus(mode, budget, spent, state ok|over|over_time|undecided, started, elapsed_min)
sg.spend_phase(rec); sg.solved_at(records); sg.modes_of(cid, at, solved, budgets)
sg.tier_of(path, *, root=None); sg.scope_tier(paths, *, root=None)   # absolute paths resolved and made root-relative, relative ones normpath'd; either outside the root -> SpendGovError; TIER_RULES (first match), TIER_LIMITS {tier: (rounds, agents, continue_at)}
sg.next_step(rounds, tier, tree) -> Step(action review|stop|fix|escalate, reason, round)   # the stopping rule
sg.resolve_scope(root, patterns); sg.file_hashes(root, files); sg.tree_hash(hashes)
sg.record_round(scope, root, files, findings, *, by=None, workdir=None)   # review.round + snapshot
sg.count_findings(report) -> {severity: n}   # reviewer JSON (list, or {"findings": [...]}); a finding without a known severity is an error
sg.diff_since_review(scope, root, files=None, *, workdir=None) -> Diff(added, changed, removed, unchanged, ...)
sg.load_tasks(json_list) -> [ReviewTask(name, patterns)]
sg.plan_reviews(tasks, root, *, records=(), max_agents=4) -> ReviewPlan(entries, agents, max_agents)
    # PlanEntry action spawn|duplicate|stop|fix|escalate|over_cap; .needs_person; agents = the dry-run count
sg.open_investigation(id, question, *, metric, threshold, minutes, usd, by, workdir=None)
sg.close_investigation(id, answer, *, by, note=None, workdir=None)
sg.investigations(records, *, now) / sg.investigation(id, records, *, now)
    -> InvestigationStatus(..., state open|over_time|over_budget|closed, answer, crossed)
sg.status(*, workdir=None, now=None, tz="UTC", records=None) -> Status(phases, modes, investigations, uncategorized_usd)
sg.SpendGovError                                   # a ValueError naming the bad input or state
```

Phases are the spend categories: a `spend` record's `category`, challenge spend without one is
`solve`, other spend without one counts toward no cap. A `day` cap counts midnight to midnight in the
profile's `allowance.tz`; an `event` cap counts the whole ledger. A phase or mode with nothing decided
is held: the cap or budget is the player's decision (`ctf spend cap` / `decide` refuse without a
terminal). Mode `speedrun` is built in: work or spend on a timed id (`gamemaster.is_timed`) at or
after the team's first solve of it (`stop` reason `team_solve`, `accepted`, or a correct /
already_solved `platform.submit`). A custom mode counts spend on its glob-matched challenges from its
first decision. A mode decision with `minutes` is held (`over_time`) once that many minutes have passed
since the mode's first counted spend. Review tiers: agent-steering files (`CLAUDE.md`, `AGENTS.md`,
`SKILL.md`, `.claude/`) and `requirements*` `standard`, other docs `none`, tests `light`, solve-path and armed code (`solvers/`,
`openers/`, `ctf/platform/`, `ctf/intake/`, submit, scope, fence, budget, ledger, flagfmt,
`.githooks/`, launchers) `full`, anything else `standard`; the scope's tier is its riskiest file's.
Stopping rule: stop once the last round found nothing at or above the tier's `continue_at`; a round
on the same tree is never repeated (`fix` first); `escalate` to a person when the tier's rounds are
spent and the last still found something serious. Snapshots: `<workdir>/spend/reviewed/<scope>.json`.
Investigation spend is `spend` with `source="investigation:<id>"`.

Stages and replay (B-101, `ctf/stages.py`, `ctf/replay.py`, `python -m ctf ledger`):

```python
stages.STAGES  # wave_open detect claim intake_start intake_done first_tool candidate submit accepted rejected
stages.mark(stage, challenge_id=None, *, workdir=None, **fields) -> dict  # StageError: unknown stage,
                                    # no challenge id (all but wave_open), wave_open without wave=
stages.try_mark(...) -> dict | None   # live paths: an unresolvable workdir / OSError -> stderr, None
stages.record_wave(ids, *, label=None, announced=None, workdir=None)   # wave_open + new detects
stages.record_spend(usd, tok, category, *, source=None, note=None)    # spend of no challenge
stages.AgentStreamTap(usage, gate.record, harness=, flags=)           # first_tool + candidate
replay.wave_replay(records, wave=None, *, t0=None) -> Replay         # pipeline + per-challenge rows
replay.summarize(records, *, tail_of, wave=None) -> Summary
```

Writers: `ctf wait` (`wave_open {wave, count, announced?}` and `detect {wave}` for each challenge not
detected before; `--wave LABEL`, default `W<n>`; a label already in the ledger exits 2 before any
poll), `ctf pull` (`intake_start`, `intake_done {ok}`; `ok: false` is a failed pull, not a done intake), the
metered launchers (`first_tool {by, tool}` once; `candidate {by, flag_sha256}` per distinct
flag-format value in the agent's output, placeholders such as `CSCTF{...}` skipped, never the value,
off when the flag format is unknown). `claim` and the rest come from `ctf ledger mark`. The replay
also reads `agent_launch`, `engine.run` (first_tool at `ts - seconds`; status solved/candidate is a
candidate) and `platform.submit` (submit; accepted for correct/already_solved; rejected for incorrect).
`spend` may carry `category` (`solve build verify doc orchestrate guardian other`); challenge spend
without one counts as solve, other spend without one as uncategorized. An `accepted` mark may carry
`layer` (`layer1 | agent | human`); otherwise the closer is derived (agent activity before the accept,
else an engine run, else other).

---

## 11. Layout: where new code goes

| path | holds | naming |
|---|---|---|
| `ctf/` | core: event, paths, env, flagfmt, result, budget, ledger, packs, scope, fence, platform, engines, cli, testing, the carried CTFd client/submit/workspace/triage | one module per concern; no event names in code |
| `ctf/platform/<kind>.py` | one platform adapter per kind | kind = profile `platform.kind` |
| `ctf/cli/<name>.py` | one CLI command per module | `_` -> `-` on the command line |
| `ctf/engines/` | manifests, router, lint, generation, coverage, runner | |
| `solvers/<lane>/` | engines, grouped by lane (`common`, `toolkits`, `binary`, `web`, `metadata-forensics`, ...) | `<engine>.py` + `<engine>.manifest.toml` |
| `openers/layer1.toml` | the armed Layer-1 opener of each lane, its cases, keys and controls (section 24); fixture builders in `ctf/openers/fixtures.py` | one `[[opener]]` per lane |
| `ctf/formats/` | the ranked format catalog (`catalog.toml`), structural identification, the synthetic format corpus (`corpus.py`) and the property coverage matrix (`matrix.py`) (section 27) | one `[[format]]` per format; one builder per sample |
| `tools/` | operator scripts and offline tools that are not engines (`ctfpy`, `claude_launch`, `codex_launch`) | verb or noun, lower_snake |
| `templates/event/` | the one agent-rules template (section 15) | |
| `workflows/` | the shipped workflow scripts (B-194): one `<name>.js` (Workflow-tool script) + `<name>.wf.toml` pre-launch manifest per workflow; outside `.claude/` | `ctf/workflows.py`, `ctf workflow` |
| `events/<slug>/` | `event.toml`, generated `CLAUDE.md`/`AGENTS.md`, optional `fence.toml`, legacy agent config | slug = folder name |
| `docs/` | contracts, building guide, playbooks, build log, migration records | |
| `tests/` | the suite; `test_<area>_<topic>.py`; fixtures built synthetically in the test | contract tests: `test_contracts_*.py` |

**Layer direction:** `tools/` may import `ctf/`; `ctf/` does not import `tools/` at module level. The
exceptions are `ctf/cli/access.py` (B-100), `ctf/cli/usage.py` (B-193), `ctf/cli/quota.py` (B-171,
for `scan` and `daily`) and `ctf/router.py` (B-201: the price table and the B-096 A/B gate), which import
`tools.ledger` (the price table, rate ratios and session-log readers) lazily inside the command and
turn an `ImportError` into a named exit-2 error (`RouterError` for the router). It works because `python -m ctf` runs from the repo root.
Moving the price table and readers under `ctf/` would remove the exceptions.

**Adding an engine:** write `solvers/<lane>/<engine>.py` with the entry function returning a
`SolverResult`, its `<engine>.manifest.toml`, and `tests/test_<lane>_<engine>.py`. Use `flagfmt`
for flag matching, `paths` for locations, the `needs_tool` marker for external tools. Do not edit
`ctf/triage.py` to route it: the manifest routes it. Steps and checks: `docs/BUILDING.md`.

**Adding a CLI command:** add `ctf/cli/<name>.py` with `HELP`, `add_arguments`, `run`, a test, and a
row in the section 8 table. Do not edit `ctf/cli/__init__.py`.

**Adding an event:** `python -m ctf new-event <slug> --name ... --start ... --end ... --base-url ...
--flag-prefix ...` (or `--manual`) writes `events/<slug>/event.toml` and renders
`events/<slug>/CLAUDE.md` and `AGENTS.md` from the template (section 15). Edit `event.toml` by hand
for anything the options do not cover, then `python -m ctf new-event <slug> --regen` (add
`--workdir DIR` to install the agent files where sessions run). `python -m ctf event check <slug>`
validates the profile; `python -m ctf check-event <slug>` fails while the agent files are missing,
stale or hand-edited. Optional: `events/<slug>/fence.toml` (section 14). Set `CTF_EVENT=<slug>`.

**Rule: adding a new file beats editing a shared one.** Registries are directories (CLI commands,
platform kinds, engine manifests, policy checks registered at runtime), so parallel builders never
contend on one file. When a shared file must change, change it minimally and list it in your report.

## 12. Packs (modules loaded by path)

A *pack* is a module that routing or a lane loads by file path rather than by import: a category
toolkit named in `solvers/toolkits/registry.py`, the registry itself, a metadata reader pack beside
`solvers/metadata-forensics/properties_strict.py`, `solvers/common/triage.py` for file identity.

```python
from ctf import packs
packs.load_module(module_name, path, pack=None, cache=True)   # the module, or:
#   PackMissing      the file is not there
#   PackLoadError    the file is there and raised while importing (the cause is chained)
packs.toolkit_registry(root=None)   # solvers/toolkits/registry.py, loaded once as packs.REGISTRY_MODULE
#   RegistryLoadError                 missing or broken: no bundle routing, no toolkit map
# all three subclass PackError(pack, path, reason), a RuntimeError; .pack .path .reason
```

- A missing or broken pack is never skipped: the error names the pack and the path. A caller may
  catch it to degrade, but only by naming what is missing (a `blocked` `SolverResult`, a stderr line).
- `cache=True` keeps the module in `sys.modules` under `module_name` (a second call returns it);
  `cache=False` gives a fresh module each call, never registered. `SystemExit` raised while importing
  is a load error; `KeyboardInterrupt` and other non-`Exception` stops pass through.
- An optional external tool (a PyPI package or a binary) is not a pack: use the `needs_tools` manifest
  field and the `needs_tool` marker.

## 13. Live-service scope guard

The one check every network client runs before it opens a connection (B-001c). The web client
(`WebClient`, `RawSocketScope`), the chat client (`ChatTarget`) and the pwn client (`PwnTarget`) call
it from their constructors, before any socket and any name lookup.

```python
from ctf import scope
scope.check_host("web-1.x.example", 443, what="WebClient(...)")   # the normalised host, or OutOfScope
scope.check_url("http://10.1.2.3:8080/chat")                       # check_host on the URL's host and port
scope.check_platform_url(url)        # -> (host, port): a platform client's only target (R-13)
scope.check_public_fetch(url_or_host, purpose=...)   # a public mirror / symbol server / tunnel service (R-13)
scope.policy()                       # ScopePolicy(event, scope, platform, pointed): the scope in force
scope.pointed(profile=None)          # ((host, port | None), ...): player-pointed services in force (B-173)
scope.split_url(url)                 # (host, port); port defaults by scheme (http/ws 80, https/wss 443)
scope.pin(profile); scope.unpin(); scope.pinned()   # fix the profile for this process / back to event.current()
```

Every function takes `profile=None` (else the pinned profile, else `event.current()`) and
`error=OutOfScope`: a client passes its own subclass, so `except ctf.scope.OutOfScope` catches every
client's refusal. `OutOfScope` is a `ValueError`. Rules, in order:

1. No profile, or one that does not load: refused, naming the `EventError`. There is no default scope.
2. `rules.live_service_scope` empty: refused (no live service may be contacted).
3. The event platform is never a target: the host and port of `platform.base_url` and of
   `CTF_PLATFORM_URL` (and its legacy spellings) are refused even when an entry matches them. The
   port matters: a challenge instance on another port of the same host is allowed if the scope allows
   the host.
4. Otherwise the host must match an entry: a **host glob** (fnmatch, case-insensitive, `*` also spans
   dots: `*.x.example`, `web-?.x.example`, `10.13.37.*`, `localhost`) or an **IP network in CIDR
   form** (`10.0.0.0/8`, `fd00::/8`) matched against an IP-literal host. Names are never resolved. An
   entry made only of wildcards and dots (`*`, `*.*`) is refused as too broad; an entry with `/` that
   is not a network is refused.
5. **Player-pointed services** (B-173). With `rules.pointed_services = "allowed"`, a `scope.pointed`
   ledger record in the event workdir (`ctf policy point <id> <host[:port]>`, section 25) admits that
   exact host, and that exact port when the record has one; the latest `scope.pointed` /
   `scope.unpointed` record for a host and port wins. Rule 2 then refuses only when the scope and the
   points are both empty, and rule 3 still refuses the platform. With `forbidden` (the default) the
   records are not read. A ledger that cannot be read refuses (`OutOfScope`, fail closed).

`pin()` takes an `EventProfile` (else `TypeError`). The test suite pins a test-only loopback profile
(`tests/conftest.py`); a tool run with an explicit event may pin that one.

The rules above are `check_host` / `check_url`. Two more checks (R-13), same `profile=` and `error=`:

| check | allows | always refuses |
|---|---|---|
| `check_platform_url` | the host and port of `platform.base_url` or `$CTF_PLATFORM_URL` | no profile; no platform URL; any other host or port (challenge hosts included) |
| `check_public_fetch` | a host matching `rules.public_fetch_allow` (same entry syntax and too-broad rule) | no profile; an empty list (the refusal names the host, the purpose and the key to add); the event platform, with or without a port |

The two lists never open each other: a public mirror is not a target, and a target is not a mirror.

Who calls what: web, chat and pwn clients, `tools/netplay.py` and `tools/vpn.py` probes, and the
Web speed runtime (`speedrun/web_target.py` `target_identity`, so every `TargetClient`; refusal
`TargetOutOfScope`, B-152) use `check_host`; `speedrun/wire.py` (fast CTFd) uses `check_platform_url`; `solvers/toolkits/memory.py`
(Volatility symbol pack, `--online` PDB download), `tools/oob.py` (`up --public`, the public
probe) and `solvers/toolkits/osint_geolocate.py` (the live Overpass query of `osm --online` and
`sweep --online`: the endpoint, and again every redirect target of its default transport, B-113) use
`check_public_fetch`. The map-pin checker client (`solvers/toolkits/_osint_geo_checker.py`
`GeoChecker`, B-113) runs `check_url` on the challenge page in its constructor, posts only to that
page's own origin, and sends through `WebClient`. The live padding-oracle client
(`solvers/common/padding_oracle_live.py` `LiveOracle`, refusal `OutOfScope`, B-244) runs `check_host` on
its target in its constructor, and every query first takes one from a per-challenge budget kept in
`<workdir>/oracle/<challenge>.json` (ledger `oracle.budget`, `oracle.open`, `oracle.close`).
`tools/oob.py selftest` connects only to an address of this Mac.
The EVM JSON-RPC reader (`solvers/toolkits/evm_rpc.py` `RpcReader`, B-243) refuses (`RpcRefused`, an
`OutOfScope`) unless `rules.chain_rpc = "allowed"`, then runs `check_url` on the node URL in its
constructor; it sends only allowlisted read methods (`READ_METHODS`), never follows a redirect, and caps
the response size.
A new network client calls one of these before its first socket, and its test replaces the socket
boundary with a recorder (see `tests/test_scope_guard.py`, `tests/test_scope_remaining_clients.py`).

## 14. Solver filesystem fence

What a **solver** may read during an event (B-219), rendered as Claude Code settings, a Codex
permission profile and a denied-access report. Full description: `docs/fence.md`. It never edits
`~/.claude`, `~/.codex` or this repo's `.claude/settings.json`.

```python
from ctf import fence, fence_launch, fence_report, fence_selftest
f = fence.build(repo=None, workspace=None, home=None, drop=None, extra_read=(), extra_deny=(),
                strict_home=False, user_dir=True, toolchain=None, slug=None)    # Fence, or FenceError
f = fence.from_config(fence.load_config(slug), **overrides)   # events/<slug>/fence.toml under overrides
f = fence.read_fence(cfg, repo=None, workspace=None, home=None, user_dir=True)  # a reader's fence (B-034 `ctf read`):
    # build()'s deny rules (one source, fence._deny_rules), names, drop, allow_read, strict_home; no root-placement
    # checks; workspace defaults to the repo
f.read_roots; f.write_roots; f.classify(path, cwd=None) -> Verdict | None
f.claude_settings(); f.codex_profile(); f.codex_config_args(); f.describe(); f.command_category(segment)
fence.write_claude_settings(f, dest=None)   # <workspace>/.fence/claude-settings.json, mode 0600
fence.canon(p, home=None, cwd=None); fence.darwin_user_dir(); fence.toolchain_roots(); fence.toml_inline(v)
# Verdict(kind, path, root, category): kind allowed | system | denied | outside-home | outside; .reportable
# DenyRule(category, path, is_file, reason); FenceConfig(drop_folder, allow_read, deny_read, strict_home, source)
# DenyName(category, name, reason): a directory name denied at any depth (fence.DENY_NAMES); .globs, .match(p)
fence_launch.codex_argv(f, codex_bin="codex", headless=True, model=None, effort=None, approval="never", extra=(), prompt=None)
fence_launch.claude_argv(settings_path, claude_bin="claude", extra=(), effort=None)   # pure: never runs the CLI
fence_launch.claude_effort_flag(claude_bin="claude", help_text=None, timeout=60.0)   # "--effort", or LaunchError
fence_launch.check_codex_extra(extra); fence_launch.check_claude_extra(extra)   # LaunchError for a fence-defeating arg
rep = fence_report.scan_files(paths, f) -> Report        # Report(files, lines, commands, accesses, unparsed).clean
fence_report.render_text(rep); fence_report.extract_paths(command)
fence_report.classify_command(f, command, cwd=, source=, tool=, outcome=); fence_report.classify_path(...)  # [Access]
fence_selftest.codex_selftest(f, codex_bin="codex") -> [Check]   # live: needs the codex CLI
```

- Roots: read and write = the workspace (default `paths.workdir(slug)`) and the repo; read only = the
  drop folder (the one readable folder under `~/Downloads`) and `allow_read`; denied = the categories
  in `fence.DENY_HOME` / `DENY_ABS` plus `deny_read` (category `operator`). `strict_home` denies all of
  `$HOME` except the allowed roots and the Python toolchain.
- Inside the repo its gitignored sensitive trees are denied (`fence.DENY_REPO`: `analysis/`,
  `docs/writeups/`, `writeups/`, `.claude/`, `.ctf/`), and a `.ctf/` directory is denied at any depth
  under any root (`fence.DENY_NAMES`) (R-03).
- `build` raises `FenceError` naming the reason when a root would defeat the fence (workspace is
  `$HOME` or inside a denied root, drop folder is `~/Downloads` itself, a read root is a deny root).
- `events/<slug>/fence.toml` is optional; its keys are `drop_folder`, `allow_read`, `deny_read`,
  `strict_home`, and an unknown key or wrong type is a `FenceError`.
- Launchers: `tools/codex_launch` and `tools/claude_launch` build their argv with `fence_launch`;
  an argument that would undo the fence (sandbox bypass, other permission profile, fast tier) raises
  `LaunchError`, never silently dropped.
- `codex_argv` also carries the Codex compaction threshold (`-c model_auto_compact_token_limit=N`,
  section 30); a passthrough `-c model_auto_compact_token_limit=...` is refused and an unusable
  `CTF_COMPACT_CODEX` is a `LaunchError`. `tools/claude_launch` starts Claude with
  `CLAUDE_CODE_AUTO_COMPACT_WINDOW` (its dry run prints it between the `cd` and `claude`), then (B-118,
  section 70) `CLAUDE_CODE_PROMPT_CACHE_TTL=5m` and `CTF_CACHE_TTL_LAUNCHED=5m` (`--standby`: 1h;
  `CTF_CACHE_TTL_CLAUDE` / `CTF_CACHE_TTL_STANDBY` override, `off` sets nothing and removes a TTL a parent
  launch marked). A conflicting inherited TTL, or FORCE_PROMPT_CACHING_5M under 1h, or a CLI build without
  the variable (read, never run; a dry run does not probe) is exit 2.
- Effort (B-095): both launchers take `--effort`, defaulting to the event profile's `[models].effort`
  (none when no event resolves). Codex gets `-c model_reasoning_effort="E"`. `claude_argv(effort=E)`
  adds `--effort E` before the passthrough args and never runs the CLI. `claude_effort_flag` runs
  `<claude_bin> --help` once (stdin `/dev/null`, no session, nothing cached) and returns the flag, or
  raises `LaunchError` naming the flag and the binary when the help documents none, when the CLI
  cannot be started, or when the help does not return within `timeout` seconds. `tools/claude_launch`
  calls it on a real launch with an effort, after the gate admits the run (a refused launch starts no
  CLI); a failure is exit 2 and an admitted seat is given back. A dry run does not run the CLI and
  needs no binary: it prints the command with `--effort E` and says on stderr the flag was not checked.
- Model routing (B-201, section 67): both launchers take `--difficulty`, `--category` and `--no-route`
  (tools/route_launch.py). On an event with a `[routing]` table a launch with a role is routed: the
  route fills `--model` / `--effort` the caller left unset. `codex_argv(service_tier=T)` sets
  `-c service_tier="T"` and leaves only that tier's feature switch on (`CODEX_SPEED_TIERS`); the launcher
  passes it only for a speed-tier route with its own `budget_usd` on a budget-gated `codex exec` run,
  and refuses it otherwise. A passthrough `service_tier` is still refused. `claude_launch` refuses a
  Claude speed tier.
- The report records program name and path only, never the whole command.

## 15. Event scaffold and agent rules

`python -m ctf new-event` and `python -m ctf check-event` (B-189), built on:

```python
from ctf import eventscaffold as sc, eventrules
data = sc.profile_data(slug, name=, start=, end=, kind=, base_url=None, ..., submit_mode=, ai_on_platform=)
prof = sc.validate(data, slug)               # ctf.event.parse: the one validator
sc.write_profile(data, path, header=())      # TOML written, re-read and compared; returns the EventProfile
sc.to_toml(data, header=()); sc.parse_when("2027-03-01T09:00:00Z", "--start")   # ScaffoldError on a bad value
sc.fetch_categories(prof) -> (categories, n)  # through the platform adapter; ScaffoldError on a refusal or failure
sc.fetch_refusal(prof) -> str | None; sc.token_configured() -> bool; sc.merge_categories(*groups)
eventrules.render(prof, template=None) -> {"CLAUDE.md": text, "AGENTS.md": text}
eventrules.write(prof, dest, template=None) -> [Path]
eventrules.check(prof, dest, template=None) -> [problem]   # empty = current
eventrules.template_path(); eventrules.render_text(template, ctx); eventrules.context(prof, agent_file, template_digest)
eventrules.profile_digest(prof); eventrules.split_header(text)   # TemplateError on a bad template
```

- **One template**, `templates/event/agent-rules.md.tmpl`, renders both `CLAUDE.md` and `AGENTS.md`;
  below the end-of-header marker the two must be byte-identical (`render` refuses otherwise), so both
  harnesses load the same rules. Template syntax: `{{name}}`, `{{#if name}}..{{else}}..{{/if}}`,
  `{{#unless name}}..{{/unless}}`, `{{!-- comment --}}`; anything else is a `TemplateError`.
- Each generated file carries a metadata line with the profile and template digests; `check` (and
  `ctf check-event`) reports a file that is missing, stale (profile or template changed), edited by
  hand, or disagrees with its sibling. A folder with agent files and no `event.toml` also fails.
- `new-event` defaults are the cautious ones: `flag_sharing = "forbidden"`, `submit_mode = "confirm"`
  (or `manual`), flag format unknown until `--flag-prefix`. `--manual` = platform kind manual, no
  submit, `ai_on_platform = "forbidden"` unless `--ai-on-platform allowed`. It refuses to overwrite an
  existing `event.toml` without `--force`.
- Categories come from the platform adapter's `list_challenges()` only when the profile allows
  automation on the platform, a base URL is set and `CTF_TOKEN` is configured; a failed fetch stops
  the scaffold (`--no-fetch` skips it on purpose). The token is never printed.
- B-173 policy options: `--wrong-penalty N`, `--no-approved-extras`, `--hint-suggestions`,
  `--pointed-services allowed|forbidden`, `--sweep forbidden|player-authorized`
  (`sc.profile_data(..., wrong_penalty=None, approved_extras=True, hint_suggestions=False,
  pointed_services="forbidden", sweep_mode="forbidden")`; a new profile always writes `[sweep]`).
  Each policy field has a line in the template, so changing it makes the agent files stale.
- The template's `{{solver_contract}}` is `ctf.solver_contract.rules_md()` (B-172, section 46). It is
  part of the profile digest, so a contract change marks every event's agent files stale until
  `new-event <slug> --regen`.
- The template's `## Operating rules` block (B-211: preferences into rules or memory, count by unit,
  evidence over transcript memory, time from the clock, no GUI or browser control unless asked, patch
  from a fresh read) has no template tags and is kept byte-identical in the root `CLAUDE.md` and
  `AGENTS.md`; `tests/test_operating_rules.py` fails when any copy drifts or a generated event file
  lacks it.

## 16. Build plan gate and pre-event hooks

"Pay for the build once" (B-008): pre-event work defaults to the doctor and a rehearsal; any other
pre-event or in-event build runs only when a recorded ranking approved it. `python -m ctf build-plan
rank | check | pre-event` (section 8) is the CLI. The numbers are modeled estimates, never measured
savings.

```python
from ctf import buildplan, preevent
items = buildplan.load_items(path)            # [Item] from a to_build-style JSON list; BuildPlanError names a bad file or record
buildplan.parse_item(rec, where="item"); buildplan.parse_payoff_usd(payoff); buildplan.value_of(item)
buildplan.canon_categories(category)          # frozenset of canonical category tokens
board = buildplan.load_board(path)            # Board(categories, text) from a board dump
r = buildplan.rank(items, profile, effort_budget=0.0, board=None, items_source=None, board_source=None, now=None)
# Ranking(event, ..., entries=(Ranked(rank, id, decision, reason, score, ...), ...)); r.approved()
buildplan.record(r, workdir=None)             # <workdir>/build-plan/ranking.json + a build_plan.rank record
buildplan.load_ranking(workdir=None); buildplan.ranking_path(workdir=None)
buildplan.phase_of(profile, now=None)         # pre-event | in-event | post-event
buildplan.check_build(item_id, profile, workdir=None, now=None, log=True)   # GateDecision(allowed, item_id, phase, reason, entry)
buildplan.require_build(item_id, profile)     # the GateDecision, or buildplan.BuildRefused (.decision)
preevent.plan(profile, ranking)               # [Step(kind hook | build, name, detail)]: doctor, rehearsal, approved builds
preevent.run_hooks(profile)                   # [HookResult(name, status ok | fail | stub, detail)]; .passed only for ok
preevent.doctor_hook(profile)                 # ctf.doctor.run_checks: fail if any check failed (B-039)
preevent.rehearsal_hook(profile)              # ctf.rehearsal.rehearse in a temp folder (B-039)
from ctf import doctor, rehearsal
checks = doctor.run_checks(profile, codex=True, codex_mode="fast", instances_cfg=None, instance_challenge=None,
                           toolbox=True, client=None, token=True, briefs=None, fence=None, claude_settings=None,
                           harnesses=("claude", "codex"), permission_mode=None, background=True,
                           brief_workdir=None, usage=True, usage_workdir=None, power=True, sandbox=None)
# permission_mode None = rulesim.LAUNCH_PERMISSION_MODE ("auto"); brief_workdir: add launcher_briefs(it)
# [Check(name, status ok | warn | fail | skip, detail, fix, level, needs, sandbox_only)]: profile,
# categories, router, compaction, codex-model, codex-smoke, submit-dry-run, instances, toolbox, assets,
# images, allowance
# (doctor.check_allowance -> quota.check, B-171), failover (doctor.check_failover -> failover.check,
# B-170), token, brief-rules, usage, power, capabilities
# (B-190 added the last five, and the sandbox-only relabelling pass)
doctor.check_toolbox(environ=None, root=None, run=subprocess.run) # the binary toolbox (below): warn on a core problem
doctor.check_assets(environ=None, root=None, run=subprocess.run)  # B-188 asset manifest (section 37): warn on a core problem
doctor.check_images(environ=None, root=None, run=subprocess.run)  # B-188 images: lint fail, core image missing/stale warn
doctor.failed(checks, strict=False)           # blocking-level fails that are not sandbox-only; strict: every non-ok
doctor.split(checks)                          # Split(blocking, advisory, not_run, ok); .sandbox_only
doctor.render(checks, strict=False)           # report lines: BLOCKING / ADVISORY / NOT RUN / OK, then the verdict
doctor.LEVELS                                 # check name -> blocking | advisory (unlisted: blocking)
doctor.check_token(profile, client=None, environ=None, now=None)
doctor.check_brief_rules(profile, briefs, fence=None, claude_settings=None, harnesses=..., mode=None,
                         background=True, brief_workdir=None)
doctor.check_usage(profile, workdir=None); doctor.check_power(run=None, system=None)
doctor.check_capabilities(info); doctor.label_sandbox_only(checks, info)
from ctf import sandboxinfo, rulesim
info = sandboxinfo.detect(environ=None)       # SandboxInfo(sandboxed, evidence, verified, failed); .unverified(needs)
acts = rulesim.extract(text)                  # [Action(kind command | write | read, text, line, via, cwd)]
rulesim.ClaudeRules.from_settings(settings, cwd=, home=, mode=); rulesim.CodexRules.from_fence(fence)
# mode: rulesim.CLAUDE_MODES = default | acceptEdits | plan | dontAsk | auto; LAUNCH_PERMISSION_MODE = "auto"
rulesim.simulate(acts, [rules, ...])          # [Decision(harness, action, verdict allow | deny | prompt | classifier, reason)]
rulesim.blocking(decisions, background=True)  # denies, and prompts when nobody can answer them (never classifier)
rulesim.find_briefs(path)                     # a file, or *brief*.md under a folder the operator named
rulesim.launcher_briefs(workdir)              # <workdir>/*/codex_brief*.md only, no symlinks (--all-briefs)
rulesim.read_brief(path)                      # size-checked before reading; RulesError over MAX_BRIEF_BYTES
rep = rehearsal.rehearse(profile, workdir=path, submit_interval=rehearsal.DEFAULT_SUBMIT_INTERVAL)
# Rehearsal(steps, timings): .passed, .failures(); RehearsalError when this event cannot be rehearsed
```

- Decisions: `approved` (eligible and inside the effort budget), `candidate` (over budget),
  `after-board` (waits for the visible board), `skip`. Only `approved` passes the gate. The default
  effort budget is 0, so nothing is approved by default.
- `check_build` logs every decision as a `build_plan.check` ledger record (section 10). In-event, the
  ranking must have been made against the visible board. Post-event, a build is refused until the
  event's fold audit passes (section 18).
- A hook that raises or returns something other than a `HookResult` is a `fail`; a `stub` is never a
  pass, and `build-plan pre-event --run` exits non-zero while one is left.
- `codex-smoke` makes ONE real Codex call through `tools/codex_handoff.sh --preflight`. Under
  `CTF_TESTING` it refuses unless `CODEX_BIN` names a stub: set, not the `codex` on PATH, and carrying
  `doctor.CODEX_STUB_MARKER` (`ctf-codex-stub`) in its first 4 KiB. A `CODEX_BIN` that resolves to
  nothing is let through (the script fails "not found"). Test stubs carry the line `# ctf-codex-stub`.
- `categories` warns (never fails) on an announced category with no engine route, naming it.
- `compaction` is `compaction.preflight(environ, codex=codex)` (section 30).
- `allowance` (B-171) reads `<workdir>/usage/quota-state.json` and the ledger of `paths.workdir(slug)`.
  It warns while no quota reading is recorded, and during the event while the profile names no
  release, so `preflight --strict` fails until `ctf quota scan` / `ctf quota set` has recorded a
  reading. That is deliberate: an unmetered event is not known to be funded. The pre-event doctor hook
  (`preevent.doctor_hook`) is not strict: it reports the warning and passes.
- Blocking versus advisory (B-190): `doctor.LEVELS` names each check's level. A blocking check's
  fail stops the wave (and the pre-event `doctor_hook`); an advisory check (`categories`, `usage`,
  `power`, `capabilities`) never does. A check name not in the table is blocking (so the governor's
  `host-*` rows keep failing `ctf governor host`).
- `token` (blocking): one live `/users/me` per run, never a cached answer; expiry from
  `CTF_TOKEN_EXPIRES`, else the account's `/tokens` list (`CTFd.tokens()`; CTFd's naive timestamps
  are UTC). Warns when the token expires within `TOKEN_WARN_HOURS` (12, inclusive) or before the
  event ends. With several unexpired tokens and no `CTF_TOKEN_EXPIRES`, it warns when the earliest
  one does (it may be ours: CTFd does not say which). Skipped for manual and non-CTFd events,
  and under test (`CTF_TESTING` or a running pytest) unless a `client` is injected.
- `brief-rules` (blocking): `rulesim` simulates each named brief's commands and writes, nothing run,
  against the fence the launcher builds now (or `claude_settings`), for Claude Code in the launch
  permission mode (default `auto`, what the launchers pass) and for Codex. A deny, or a prompt in a
  background agent, fails; a prompt in an interactive session warns. In `auto` mode a would-be prompt
  is a `classifier` verdict: approximate, it warns and never blocks. `--all-briefs` reads only
  `launcher_briefs()` (never a recursive search of the workdir, which holds challenge downloads), and
  every brief is size-checked before it is read. A stale `<workspace>/.fence/claude-settings.json` is reported, never used.
  User and managed Claude settings are not read (said in the detail).
- `usage` (advisory): the ledger's spend and the challenges at their budget cap; the plan allowance
  is the `allowance` check. `power` (advisory): `pmset -g batt` via `governor.parse_pmset_batt`.
- `capabilities` and sandbox-only results: a check sets `needs` (`network`, `docker`, `loopback`,
  `tmp-write`) on a fail an environment limit can cause (a Codex call that ran and failed, an
  unreachable platform or instance route), never on a refusal or a config mismatch. When
  `sandboxinfo.detect()` finds a sandbox (Codex markers, macOS `sandbox_check`, a failed probe), such
  a fail becomes `skip` with `sandbox_only=True`: not a blocker, still counted by `--strict`.
- `failover` (B-170) reads the `failover.rehearsal` records in the ledger of `paths.workdir(slug)`. It
  warns until each direction (onto Claude, onto Codex) has a live rehearsal that held, and names the
  lanes of the last one that did not; so `preflight --strict` fails until both live rehearsals are
  recorded. Fail only when the ledger cannot be read (section 49).
- `toolbox` (B-142) warns, naming each tool and its state, when a core toolbox tool is not ok (a
  missing tool blocks one archetype, not the wave; `--strict` fails on it); an unreadable manifest
  fails; `ctf preflight --no-toolbox` (or `toolbox=False`) reports it as `skip`.
- `assets` and `images` (B-188, section 37) run with `toolbox` and are skipped with it. `assets` warns on
  a core asset that is not ok (naming its fix) and fails on an unreadable manifest. `images` fails when a
  pinned image has a lint finding or the manifest is unreadable, warns on a core image that is missing,
  stale or unlabelled and when docker is absent, and is `skip` under `CTF_TESTING` with a non-stub docker.

### Binary toolbox (B-142)

`tools/toolbox.toml` lists the host tools no engine ships that past editions needed (sops, age,
rclone, git-crypt, ccrypt, websocat, keepassxc-cli, veracrypt + macFUSE, firefox_decrypt + NSS;
optional sage). The key list is the manifest's header; `ctf/toolbox.py` refuses an unknown key.

```python
from ctf import toolbox
tools = toolbox.load(path=None)               # [Tool]; toolbox.parse(data, src) for a decoded mapping
toolbox.manifest_path(root=None)              # root joined with toolbox.MANIFEST_REL (the manifest above)
report = toolbox.verify(tools, environ=None, run=subprocess.run, python=None, only=None)
# [Status(name, role core | optional, state, path, version, detail, fix)], needs before dependants;
# state: ok | missing | broken | old | drift | needs (toolbox.STATES)
toolbox.problems(report, core_only=False)     # the statuses that are not ok
toolbox.version_ok(found, minimum)            # dotted-number comparison
steps = toolbox.plan_install(tools, report, environ=None)   # [Step(tool, argv | None, note, after, system)]
results = toolbox.apply(steps, environ=None, run=subprocess.run, allow_system=False)
# [StepResult(step, returncode, output, skipped, reason)]; reason "" (it ran) or one of toolbox.SKIP_REASONS:
# manual | absent (brew/git not on PATH) | system (allow_system False) | blocked (its tool or a need did not complete)
toolbox.render_brewfile(tools); toolbox.brewfile_path(root=None)   # ./Brewfile, generated
toolbox.capabilities_section(tools, missing_reason="")              # the CAPABILITIES.md section
# toolbox.ToolboxError: a bad or missing manifest, an unknown tool name, a refused apply
```

- Kinds: `binary` (first of `bins` on PATH, else an absolute `app_paths` executable; `extra_bins`
  must exist too), `clone` (`<paths.toolbox_dir()>/<dest>/<entry>`, run as `python -I entry
  version_args` from its folder; HEAD read from `.git` without running git and compared with the
  40-hex `rev`), `file` (one of `candidates` exists; `env_dir`'s folder is tried first).
- A probe runs once with no stdin and `toolbox.PROBE_TIMEOUT`; a non-zero exit, a timeout or no
  version in the output is `broken`, never ok.
- `plan_install` writes nothing; `apply` runs brew/git only (a manual step is printed, never run).
  A step whose program is not on PATH is skipped and named (`absent`); the others still run. A
  `system = true` tool (macFUSE, VeraCrypt: admin password, system extension, reboot) runs only with
  `allow_system=True` (`ctf toolbox install --apply --system`). A step that failed or did not run
  skips the rest of its tool's steps and every step whose `after` names it (`blocked`). Under
  `CTF_TESTING` it refuses any program on PATH without `toolbox.STUB_MARKER` (`ctf-toolbox-stub`) in
  its first `toolbox.STUB_MARKER_WINDOW` bytes, before anything runs, so no test installs anything.
- `doctor.run_checks(run=...)` passes `run` to the toolbox probes too.
- Generated: `./Brewfile` (`ctf toolbox brewfile --write`, checked by `tests/test_toolbox.py`) and the
  "Binary toolbox" section of `docs/CAPABILITIES.md` (`ctf engines generate`).

## 17. Carried CTFd path

The CSCTF-era modules that the built-in `ctf me | list | pull | triage | submit | status | check |
wait` commands (section 8) run on. They speak CTFd only. Manual mode reaches them through
`ctf.platform.legacy` (section 5), and B-006 moves their callers behind the submit gate. Settings come
through `ctf.env` (`CTF_PLATFORM_URL`, `CTF_TEAM_ID`, `CTF_SUBMIT_STATE_DIR`, the token and cookie,
never printed); a retired setting raises `ConfigError` naming where its replacement lives.

```python
from ctf import config, client, submit, workspace, triage, dynamic, fastlane, instances, texttricks
cfg = config.load()                           # Config(base_url, token, team_id, workdir, cookie, flags, submit_interval_min_s, ...)
ctfd = client.connect(cfg=None, profile=None) # client.CTFd(cfg, profile=...): me, tokens (B-190), team, challenges, challenge,
                                              #   team_solved_ids, scoreboard, download_files, submit -> Submission(status, message);
                                              #   errors: client.CTFdError
pacer = client.SubmitPacer(base_url, interval_s, state_dir=None)   # `with pacer.slot():` one queue per event host; .record(status)
client.submit_state_dir()                     # $CTF_SUBMIT_STATE_DIR, else the user cache dir
ch = workspace.for_challenge(detail, cfg=None)   # Challenge(cid, name, category, dir): <workdir>/<cid>-<slug>/ with files/, notes, tried.json
workspace.root(cfg=None); workspace.slug(name); workspace.dir_name(cid, name)   # "<cid>-<slug>", pull and intake
r = submit.guarded_submit(ctfd, ch, flag, provenance="", team_solved=None, allow=True, allow_nonstandard=False,
                          count_wrong=True, human_authorized_after_maxwrong=False)   # Result(status, message, submitted)
submit.main(argv=None)                        # python -m ctf.submit send | approve
s = triage.suggest(category, description="", files_dir=None)   # {category, playbook, engines, files}; engines include router hits
triage.render(s); triage.canonical_category(cat)
triage.identify_files(files_dir)              # via the solvers/common/triage.py pack (PackMissing / PackLoadError)
dynamic.solve_dynamic(gate, challenge_id, retrieve, attempts=6, offset=None, provenance="dynamic-flag (fresh fetch)")
                                              # rotating flag through the gate (B-006, section 5) -> SubmitResult
dynamic.server_offset(gate); dynamic.seconds_left_in_window(now=None, window_s=300, offset=0.0)
fastlane.try_solve(detail, files_dir, cfg=None, fetch=None, online=True, race=None, race_client_factory=None)  # simple classes; never submits/guesses
fastlane.try_sanity(detail, cfg, fetch, online); fastlane.try_encoding(detail, files_dir)
fastlane.try_osint(detail, cfg, fetch, online, *, profile=None, brief_fetch=None); fastlane.report(ws, online=True); fastlane.main(argv)
# B-088 brief-URL branch (last in try_osint; ctf/brieffield.py): a brief naming an http(s) URL AND asking for a named field
brieffield.try_brief_url(detail, *, profile=None, fetch=None, online=True)  # None off-class; flag always None; candidate + instruction,
                                              # field, candidates [{value,label,score,seen,url}], fetched, refused [{url,reason}], wrapped;
                                              # how/instruction name at most MAX_LISTED (10) values plus "and N more" (all stay in candidates)
brieffield.scoped_get(url, *, profile=None, timeout=FETCH_TIMEOUT_S, max_bytes=MAX_FETCH_BYTES)  # scope.check_url first (and on every
                                              # redirect, <= MAX_REDIRECTS, http(s) only); no proxy, no retry; OutOfScope / BriefFetchError
brieffield.field_question(text) -> Field|None; brieffield.brief_urls(text); brieffield.page_lines(body); brieffield.label_values(lines, field); brieffield.rank(hits)
fastlane.try_race(detail, cfg, *, client_factory=None, plan=None, online=True, clock=None, sleep=None)  # B-048 race/TOCTOU burst; fires only with an explicit plan + scope-locked factory
fastlane.try_shipped_client(detail, files_dir)  # B-131 (section 55): a flagless hand-off when a handout file states a custom User-Agent; offline, tried last
# B-048 race / TOCTOU burst engine (solvers/web/double_spend; operator-supplied approve route, never guessed):
double_spend.run_race_plan(client_factory, plan, *, clock=None, sleep=None)  # -> {report, won, state, stopped, payoff_text, payoff_field, error}; report never echoes request headers
double_spend.race(*, transport, width, success, readback=None, state_of=race_state, retry_after_of=race_retry_after_ms, retries=0, clock=None, sleep=None, deadline=None, max_requests=None, stop=None, mode="separate")  # -> (report, winner)
double_spend.burst_separate(clients, method, route, *, body=None, headers=None, barrier_timeout=..., on_event=None, release_factory=threading.Barrier)  # N independent connections, released together by a release_factory(width + 1) gate (injectable so a test can assert the engine's own all-together release)
double_spend.burst_single_packet(client, method, route, *, width, body=None, headers=None, withhold=1, ...)  # HTTP/1.1 last-byte sync; TLS raises RaceUnsupported (no silent downgrade)
double_spend.race_width(v, default=8); double_spend.race_state(resp); double_spend.race_retry_after_ms(resp); double_spend.RaceUnsupported
# B-124 business-logic state-invariant harness (solvers/web/invariant_harness; the invariant is STATED by the caller, never found):
invariant_harness.check(invariants, before, after, *, accepted=0)  # pure -> {verdict holds|violated|unevaluable, violations, unevaluable, accepted, checks}
invariant_harness.compile_spec(raw, base_url); invariant_harness.compile_invariants(raw)  # raise InvariantSpecError naming the problem
invariant_harness.ladder(compiled)  # [{rung, kind, count, reserve}]: baseline, sequential-1..N, optional burst-W (B-048 race)
invariant_harness.run_harness(spec, client_factory, *, base_url, clock=None, sleep=None, deadline=None, stop=None)  # -> report {verdict holds|violated|inconclusive, violation, baseline, rungs, requests, mutations, state_restored, stopped, error}; refuses unless rules.web_state_changing; reserve-before-mutate; never echoes headers/bodies
invariant_harness.state_change_refusal(); invariant_harness.unstable_paths(invariants, first, second); invariant_harness.action_words(route); invariant_harness.InvariantSpecError
fastlane.welcome_class(detail)  # "platform-profile"|"sanity"|"welcome"|None, from NAME+category only (B-041 auto-trigger)
fastlane.try_welcome(detail, files_dir=None, base_url=None)  # offline: inline brief flag, else a hidden-channel brief flag (B-208), else a flagless human step; None off-class; result carries zero_file
fastlane.try_text_tricks(detail, *, texts=None, force=False)  # B-208: hidden text channels of the brief (or [(source, text)]) -> "text-trick" result: flag only when exactly one complete flag is spelled; else candidate + instruction; None when nothing worth showing; result["text_tricks"] per source
# B-208 text-trick pass (ctf/texttricks.py); the text is untrusted data, read for the flag format only:
texttricks.scan(text, *, profile=None)        # -> Scan(readings, flags {flag: [channel]}, candidates, clues); .flag (one distinct or None), .ambiguous, .to_dict(); EventError without a format
texttricks.readings(text)                     # [Reading(channel, text, how, units, strong)] over CHANNELS: bullet/line initials, line finals, word initials, capitals, mid-word capitals, trailing whitespace/counts, separator bits, zero-width bits; strong = mid-word capitals from non-camel-case words
texttricks.notable(scan)                      # flag, candidate, zero-width chars, or >= 3 mid-word capitals outside camel-case words (GitHub, picoCTF do not count)
texttricks.is_placeholder(flag); texttricks.html_to_text(body); texttricks.looks_html(text)   # html_to_text is linear in the page; an unclosed script/style runs to the end
inst = instances.Instances(ctfd, endpoints=None, max_running=3, transport=None)   # spawn, status, renew, stop, stop_all
instances.endpoints_from_config(spec)         # PluginEndpoints(spawn, stop, renew, status, body_key=None, site_root=False)
instances.InstanceError
# B-003 slot scheduler (value-ordered, release-on-solve); pure plan + apply, no I/O of its own:
need = instsched.InstanceNeed(challenge_id, value=0, solved=False, running=False, remaining_s=None)
instsched.select_needs(challenges, solved_ids=(), running_ids=(), only=None)   # board -> [InstanceNeed]
p = instsched.plan(needs, cap=N_or_None)      # SlotPlan(to_stop, to_start, keep, blocked, cap)
instsched.apply_plan(controller, p, errors=PlatformError)   # [Action(op, challenge_id, ok, info, error)]
instsched.due_for_renewal(needs, within_s=120)   # running+unsolved with remaining_s <= within_s
instsched.remaining_from(info, now)           # InstanceInfo.expires_at (epoch) -> remaining_s, or None
instsched.apply_renewals(controller, ids, errors=PlatformError)   # [Action("renew", ...)]
# cross-process cap: a flock-guarded {"running": [ids]} file under <workdir>/instances/slots.json
with instsched.SlotLedger(instsched.slot_ledger_path(paths.workdir(slug))) as led:
    instsched.start_capped(controller, led, cid, cap=N_or_None)   # reconcile, then CapReached or start
    instsched.stop_tracked(controller, led, cid)                 # stop, then free the ledger slot
    instsched.reconcile(controller, led)      # {id: InstanceInfo|None}; drops ids no longer live
instsched.permission_allowlist(python="python")   # per-verb solver allow (start status renew stop list)
instsched.permission_denylist(python="python")    # --profile/--event, stop-all, schedule
instsched.ScheduleError; instsched.CapReached(ScheduleError)
```

`guarded_submit` checks, in order: manual mode (`NotAllowed`, before anything else); `count_wrong=False`
from any caller but `ctf.dynamic` (`ValueError`); the flag format (`allow_nonstandard` only for a
freeform answer the brief defines); skip solved; one try per value; stop after `submit_wrong_limit`
wrong answers on one challenge (`human_authorized_after_maxwrong=True` spends one player approval
recorded with `python -m ctf.submit approve`); `allow=False` is a dry run. The client paces sends.

## 18. Promotion record and the fold-audit gate (B-038)

Anchor: the annotated git tag `event/<slug>/start` on the master commit an event starts from
(`python -m ctf promote start <slug>`, which refuses while `fold-audit --all` fails against that
commit). Record: `events/<slug>/promotion.json` in the master, schema 1 (`ctf.promote.Record`):
`event`, `base` (start commit), `base_ref`, `fork_head`, `inventoried`, `entries[]` with `source`
(`fork` | `workspace`), `path`, `change` (`added` | `modified` | `deleted`), `state` (`committed` |
`uncommitted` | `untracked` | `workspace`), `blob` (git blob id; null when deleted), `size`,
`proposal`, `decision`, `stale`. A decision is `{"action": "engine", module, manifest, test,
commit?}`, `{"action": "fold", dest[], commit?}` or `{"action": "drop", reason}`. Unknown keys are
an error.

```python
from ctf import promote, foldaudit
rec = promote.inventory(slug, fork=..., workspace=...); promote.save_record(rec)
foldaudit.audit(slug, target="HEAD").passed      # PromoteError when it cannot run
foldaudit.audit_all(target=sha, exclude={next_slug})
```

The audit passes an entry when it is dropped with a reason, when its content is identical at a
`dest` in the target, when its folding `commit` is in the target's history, is not an ancestor of
`base`, changes at least one `dest` (against its first parent) and every `dest` exists there, or
(engine) when the module, its sidecar manifest (valid, entry runs the module) and a test naming the
module all exist at the target, the module's content differs from its content at `base`, and a
recorded `commit` passes the same commit checks against the module, manifest and test.
`promote.decide` refuses a `commit` at or before `base` or one that changes none of the decision's
paths. The audit also fails (`record:events/<slug>/promotion.json`) unless the record it read is
the one committed at the target. `buildplan.check_build` refuses post-event builds until
`foldaudit.audit(profile.slug)` passes. Operator steps: `docs/OPERATIONS.md`.

**Label seeds (B-040).** The per-lane label seed (`solvers/<lane>/conventions.json`, toolkit seeds;
`solvers/common/labels.py`) is fed by folding the runtime ledger, the same operation `labels.py promote`
runs, over every lane at once: `python -m ctf seed-fold` (`ctf.seedfold.fold_all`), run after an accepted
solve, not only at the end of an event. It also fires **automatically**: a `correct` outcome recorded
through `ctf.adapt.chain.record_attempt` (B-036) folds the event's learned verdicts into the seeds under
the attempt's own workdir (`fold_all(workdir=...)`), best effort -- the attempt record is written first and
a fold that cannot run (a judge-free event, an unreadable seed) prints one stderr line and is dropped,
never costing the record. The **order-degenerate guard**: a `learn(..., degenerate=True)`
row -- an acceptance the input could not distinguish (`labels.degenerate_accept`: the accepted spelling's
value equalled another offered option's, e.g. already-sorted bytes where `sorted` and `as_is` coincide) --
is written with a `"degenerate": true` field; `labels._fold` keeps its evidence but never promotes the
name, so `pick` stays unsure until a run on a distinguishing input accepts it. Generic readers consult the
seed store instead of a day table: `solvers/binary/d29.py` reads the build-word -> member-suffix map from
`solvers/binary/build_conventions.json` (question text first, then the seed, then the built-in O3/O0
default), so a renamed role tag on a later variant is followed with no new code. A first-seen label still
needs judge probing on the untimed base and is not learned here.

## 19. Intake: parallel no-model intake per challenge (B-002)

`python -m ctf intake IDS... | --all` (section 8) starts one worker process per challenge, all at once
up to `--jobs` (default: one per challenge, at most 2 x CPUs and 64). A worker is
`<python> -I -c <bootstrap> <root> --event SLUG --id ID [options]` (`intake.worker_command`), so a crash
in one challenge never stops the others, and it builds its own platform adapter from the profile.
`--all` takes the board's challenges that are not team-solved and have no finished intake
(`intake.finished(dir)`: a `recon/intake.json` whose status is not `blocked`), so a challenge whose
download failed is taken again by the next `--all` (`--include-solved`, `--force`). Typical wave use: `python -m ctf wait && python -m ctf intake --all`.
Exit 0 when every worker ran (and, with `--submit`, no auto-submit failed), 1 when one was blocked or
crashed or an auto-submit failed, 2 when intake could not start (a negative `--submit-cap` included).

One intake (`intake.intake_one`), with no model:

1. Download through `ctf.platform.get_adapter(profile)` (CTFd, Game Master, or the manual drop folder)
   into `<workdir>/<id>-<slug>/files/` (`intake.challenge_dir` through `workspace.dir_name`, the folder
   `ctf pull` uses; a numeric id is read as a number like pull's, any other id has the characters
   outside `[A-Za-z0-9._-]` replaced), with
   `challenge.json` and `notes.md`. A platform failure is a `blocked` result naming the call.
2. The sweep (section 4, `ctf.sweep.sweep`): recursive unpack into `unpacked/`, sha256 manifest,
   identify, flag search. No handout file is a note, not a failure.
3. Engines: `engines.plan` picks the engines whose `[intake]` table (section 6) selects this challenge,
   over the sweep's scratch copy (its own `.sweep.json`, `.sweep-owner`, `.lock` excluded; an engine whose
   table says `originals = true` is also matched against the handout files the sweep left out for size,
   `engines.left_out`, and is given each by its path under `files/`), and lists
   every skip with its reason: status not `active`, `cost_class` over `--max-cost` (default `cheap`), a
   missing `needs_tools` entry, no matching file, a spawning or external-command engine without the OS
   sandbox, the per-challenge `--engine-budget` (default 60 s) spent (no engine starts with less than
   `intake.MIN_ENGINE_SLICE`, 0.5 s, left). Routing is `router.route_heads` over the description with the
   challenge's tags appended, one per line (B-112: a challenge tagged `discord` often says nothing else; this holds
   for every engine, so a tag word can route one: of the common tag words, `pwn`, `heap`, `rop`, `rsa`, `aes`,
   `pcap`, `audio`, `pyjail`, `scada` and `discord` hit a keyword route as of B-112). Routed engines without the table
   are listed for the agent (`python -m ctf run <id> ...`), never guessed at. `engines.run_job` runs one
   through `runner.command(..., via="intake")` (so an `engine.run` record is written) under the network
   guard, in `recon/engines/<id>/` with stdout and stderr in `out[.n].txt` / `err[.n].txt` (cut at
   1 MiB each, the cut named in the run's note), killed at its `timeout` (its `engine.run` record then has `exit_code` -9). The environment
   drops every variable whose name holds TOKEN, COOKIE, AUTHORIZATION, PASSWORD, PASSWD, SECRET, API_KEY
   or CREDENTIAL, and sets `CTF_EVENT` and `CTF_WORKDIR`. Flags: the `SolverResult` an engine prints
   (unless `legacy-output`); only when it names none, the event format in its stdout.
4. Fastlane decoders (B-012, `ctf/intake/decode.py`, `decode.decode_hits`): the offline, deterministic
   `crib_decode` encoding-chain decode of every handout file and every encoded blob in the brief (all
   of them, not the first hit, so competing values make a `candidate`), stage `fastlane`. Each blob is
   decoded and the decoder's `LAST` read under the decoder's solve lock (threaded intakes never read
   each other's). The brief and files are untrusted data (decoded, never run); a missing `crib_decode`
   decoder or a decoder fault is a loud note, never a silent skip. Each hit is judged
   (`decode.judge`): `noise` (a control or non-printable character in the flag body: excluded, with a
   note), `unconfirmed` (every chain step is a loose transform -- xor, rot13, caesar, swapcase,
   reverse, ... -- with no crib support: the decoded reading is not clean text, or the flag is under
   half of it and the rest is not prose), else `flag`. Loose steps read flag shapes out of a few KB of
   base64 noise by chance, so an `unconfirmed` flag that no other source found makes the intake a
   `candidate`, never `solved` (`Report.unconfirmed`; `recon/intake.json` lists every hit under
   `fastlane`). A blob the crib decoder reads no flag from goes to the shared codec graph (B-163,
   section 41) with the event flag format as its oracle: every distinct flag it reaches is a hit
   (`decoder` `codec_graph`, `how` ends `(codec graph)`), judged the same way with the graph's
   representation steps counted as strict; `decode.GRAPH_BLOB_BUDGET` (1 s) bounds a blob and
   `decode.GRAPH_BUDGET` (4 s) the intake.
   Welcome auto-trigger (B-041, `ctf.fastlane.try_welcome`, same `fastlane` stage): on a welcome /
   zero-file / platform-profile challenge (`fastlane.welcome_class`: the `sanity` category or
   rules/welcome/intro/profile wording in the challenge NAME -- never loose description prose, so a
   normal challenge that merely quotes the format or "the rules" in its body is not classed welcome and
   its brief flag is not force-promoted), intake recovers one unambiguous flag printed in the brief
   itself -- offline, no network -- and records it (`Report.welcome`, `recon/intake.json` `welcome`,
   with a `zero_file` flag noting whether the challenge shipped any handout file).
   Because this is a welcome class, that brief flag is kept rather than dropped as template text (the
   merge forces it in as confirmed), so a welcome freebie is `solved`. When there is no inline flag,
   `welcome` is a flagless human step (read the rules page, fill a CTFd profile, finish a lesson),
   noted and never scripted. The encoding-chain decode of brief blobs and files is the decode step
   above; try_welcome only adds the plain inline-brief flag, or, when none is printed, the one flag
   the brief's hidden text channels spell (B-208, `ctf.texttricks`: an acrostic of bullets or lines,
   word initials, whitespace or zero-width bits), forced in the same way. It never submits.
   Text channels in the decode step (B-208): `fastlane._encoded_blobs_from_desc` also yields every
   printable whitespace / zero-width decode of the brief and any acrostic reading that carries braces,
   so they go through the same decoders and verdicts as any brief blob, on every challenge.
   Brief-URL field read (B-088, `ctf.brieffield.try_brief_url`, same `fastlane` stage, run in the
   intake worker itself because engines are network-denied): when the brief names an http(s) URL and
   asks for a named field ("Find the company registration number ..."), each brief URL is checked with
   `scope.check_url` against the intake's profile (`rules.live_service_scope`, or a `policy point`
   record; the platform is always refused) and at most `MAX_URLS` (3) in-scope URLs get one bounded GET
   each (`MAX_FETCH_BYTES`, `FETCH_TIMEOUT_S`, no proxy, redirects scope-checked). The page's
   label/value pairs are matched to the task noun ("Reg. No." for "registration number"; a label naming
   another field -- "Licence", "Registration date" -- is refused). The result is `Report.brief_url`
   (`recon/intake.json` `brief_url`) and a note: a `candidate` value with an instruction (verify, submit
   as displayed; `wrapped` shows the brief's `PREFIX{<answer>}` form), never a flag, so it changes
   neither the intake status nor what auto-submit sees. An out-of-scope URL is not fetched and is named.
   `Options.brief_fetch` (`ctf intake --no-brief-fetch`) turns the GET off (the instruction stays);
   corpus rehearsal runs with it off.
5. Flags from the sweep, engines and the fastlane decoders are merged (brief-quoted and placeholder
   values excluded, as in the sweep; a welcome auto-trigger's inline brief flag is the one exception,
   forced in as confirmed). One distinct flag is `solved` (found, never submitted inside
   intake) unless only an unconfirmed decode found it, only engines that returned `candidate` found it
   (B-090: such a flag is `Report.unconfirmed` until the sweep, an engine with another status or a
   confirmed decode also finds it), or an engine disputes it, several or only
   metadata joins `candidate`, else `none`; the result's engine is `intake`. A disputed flag (B-132)
   is one that an engine's own result names in an evidence item of kind `decoy` (section 7):
   `EngineRun.disputed`, merged into `Report.disputed` (flag -> why, in `recon/intake.json`). It
   stays a found flag, but whoever else found it (the sweep reads the same bytes) the intake is a
   `candidate`, so the capped auto-submit stands down and the player picks. The sweep's own disputes
   (`sweep.Report.disputed`, section 4) are merged too, so intake stands down when no engine ran
   (`--no-engines`, a timeout, a crash, a missing module); only a run of the engine the dispute names
   whose result is `solved` with that flag lifts it (it proved the value elsewhere in the document).
   Written: `recon/index.md`, `triage.md`, `recon/flags.txt` (flag TAB where), `recon/intake.json`
   (schema 1, stage timings, every run, skip and unadapted engine), a `## intake` block in `notes.md`,
   and the `intake` ledger record (section 10).

Capped auto-submit (B-012, `ctf.intake.autosubmit`, invoked by `ctf intake --submit`, never inside a
worker): the one place a `solved` intake becomes a submission, always through `ctf.platform.get_adapter`
(the SubmitGate, so a manual-mode event is refused). `autosubmit.eligible` sends only an unambiguous,
non-placeholder single flag in the event format with a printable body (a `candidate`, or a `solved`
status with several distinct flags, is never auto-submitted); `auto_submit` makes at most
`--submit-cap` (default 1, must be >= 0) judged sends per challenge across runs, counting the
`intake.autosubmit` ledger records (section 10) that were sent and either judged (correct, incorrect,
already solved) or of unknown outcome (`error`: the gate raised a PlatformError or OSError, so it may
have reached the platform). A gate refusal and an unjudged answer (rate limited, paused, not allowed)
do not consume the cap. A RecordError (answered, but the gate's observer failed) is still recorded
with its answer. The CLI pass runs after the intake summary, and one challenge's failure is printed
and counted, never stopping the rest.

```python
from ctf.intake import autosubmit, decode
flag, why = autosubmit.eligible(status, flags, profile)          # (flag | None, reason)
a = autosubmit.auto_submit(cid, status, flags, gate, profile=p, provenance="...", cap=1, workdir=None,
                           record=True)  # AutoSubmit(challenge_id, flag, submitted, accepted, status, reason,
                                         #            cap, prior, error); a.line()
autosubmit.prior_sends(cid, workdir); autosubmit.counts_against_cap(rec); autosubmit.LEDGER_EVENT
hits = decode.decode_hits(detail, files_dir, graph=True)  # [decode.Hit(flag, chain, source, reading, verdict, why,
                                              #             decoder)]; .how; graph=False: crib decoder only
decode.judge(flag, chain, reading, strict_steps) -> (decode.FLAG | UNCONFIRMED | NOISE, why)
decode.body_is_printable(flag); decode.crib_support(flag, reading) -> None | why
```

**Network guard** (`ctf/intake/guard.py`). Every engine runs under `ctf/intake/_guardboot.py`, a Python
audit hook installed before the engine boot: no socket but AF_UNIX, no name lookup, and in mode `hook`
no child process. Mode `os` also wraps the process in the OS sandbox (macOS `sandbox-exec` with a
deny-network profile, Linux `unshare --net --map-root-user`), which children inherit, so children are
allowed there. `--net-guard auto` (default) is `os` when a probe (`true` under the sandbox) passes, else
`hook`, and the reason is in every report; `os` where the probe fails is a `GuardError` (exit 2).
Mode `hook` also refuses everything that would run without the hook: `_posixsubprocess.fork_exec` is
replaced by a refusing function before the hook goes in (the call `multiprocessing` spawn and
forkserver use without `subprocess`; its child would be a fully unguarded interpreter, network
included), and the imports of `_posixsubprocess` (a fresh copy), `_ctypes` (all of ctypes) and the
sub-interpreter modules (`_xxsubinterpreters`, `_interpreters`, `_testinternalcapi`, `_testcapi`) are
refused with ImportError. Not covered by mode `hook`: a compiled extension module that opens a socket
in C without an audit event. Mode `hook` is a Python-level fence; mode `os` is the boundary.

```python
from ctf import intake
from ctf.intake import engines, guard, report
opts = intake.Options(engines=True, max_cost="cheap", engine_budget=60.0, net_guard="auto", record=True,
                      root=None, python=None)        # IntakeError on a bad value; opts.argv() for a worker
rep = intake.intake_one("9076", profile, adapter=None, workdir=None, options=opts, manifests=None)
# intake.Report(challenge_id, dir, result, seconds, stages, challenge, sweep, plan, runs, flags, excluded,
#               fastlane, welcome, unconfirmed, disputed, notes, guard, error, started); rep.status, rep.counts(), rep.to_dict(), rep.summary()
outs = intake.intake_many(ids, profile, jobs=None, options=opts, workdir=None, spawn=True, adapter=None,
                          on_done=None, poll=0.02)   # [intake.Outcome(challenge_id, exit_code, started, seconds,
                                                     #   summary, log, report)] in ids order; .ok
ids, skipped = intake.board(profile, adapter=None, workdir=None, include_solved=False, force=False)
intake.challenge_dir(workdir, challenge); intake.finished(dir) -> status | None; intake.default_jobs(n)
intake.write_outputs(rep); intake.MIN_ENGINE_SLICE
intake.worker_command("9076", "csctf", opts, python=None, root=None); intake.worker_main(argv)
intake.record(rep, workdir=None, options=None)     # the intake ledger record
intake.IntakeError
p = engines.plan(manifests, category, description, folder, guard=g, max_cost="cheap", heads=None, originals=())
engines.left_out(originals_dir, read)      # [(file, head)]: handout files the sweep did not read (`read`: the ones it did)
# engines.Plan(jobs, skipped, unadapted, routed, claims); engines.Job(manifest, files, reason, priority, index)
# engines.Skip(engine, reason); engines.EngineRun(engine, inputs, status, exit_code, seconds, output, errors,
#                                                  result_status, flags, note, disputed).to_dict()
engines.input_files(folder); engines.route_hits(manifests, category, description, heads)
engines.files_matching(matchers, heads); engines.claims(manifests, heads, folder); engines.tool_missing(needs)
engines.expand_args(spec, files, folder=f, challenge=c, out=o); engines.engine_env(profile, workdir=None)
run = engines.run_job(job, ctx, timeout=None)       # ctx = engines.Context(challenge_dir, folder, out_root,
                                                    #   profile, guard, root, python, challenge_id, record, workdir)
g = guard.resolve("auto")                           # guard.Guard(mode, prefix, reason).allows_spawn; guard.GuardError
guard.os_sandbox(refresh=False); guard.boot_path(root); guard.wrap(g, cmd, root)
report.index_md(rep); report.triage_md(rep); report.cell(text); report.code(text)
```

## 20. Board watch stream (B-017)

One no-model poller per event (`python -m ctf watch run`) reads the board through the platform
adapter and writes every detection to `<workdir>/watch/events.jsonl`. Nothing else polls the board:
the dispatcher (B-004), intake (B-002) and the claim store (B-015) read the stream. The full contract
(event types and their fields, brief versions, alerts) is the module docstring of `ctf/watch.py`. It
is the source of truth; change it there and here together.

```python
watch.follow(workdir=None, since=0) -> Iterator[dict]   # tail the stream; a partial last line is never read
watch.read_events(workdir=None, since=0) -> list[dict]  # every complete line with seq > since
watch.board_ids(workdir=None) -> list[str] | None       # ids listed now; None before board_open
watch.poller_pid(workdir=None) -> str | None            # pid of the running watcher, or None
watch.verify(workdir, challenge_id, frm=None, to=None)  # offline brief check (`ctf watch diff`)
```

Record: `{"seq": int (strictly increasing), "ts": epoch, "event": type, ...fields}`, mode 0600, one
writer (the lock holder). Types: `watch_start`, `board_open`, `poll_error`, `poll_ok`,
`challenge_new` (also ledger `detect`), `wave`, `challenge_gone`, `brief_changed` (also ledger
`watch.brief_changed`), `points_changed`, `team_solved`, `detail_error`, `watch_stop`. `challenge_new`
carries `solved` (the listing already says our team solved it); a challenge already solved the first time
it is listed also gets a `team_solved {first_sight: true}` right after its `challenge_new`, and one that
comes back onto the board already solved gets a `team_solved {first_sight: false, returning: true}`
there (its earlier row was dropped when it went, so no flip is seen). A consumer
keeps the last `seq` it handled and resumes with `follow(since=seq)`. Challenge text in the stream,
the briefs and the alerts is untrusted data. `ctf wait` reads this stream instead of the platform
while a watcher runs.

## 24. Armed Layer-1 openers (B-014)

Each day-1 lane ships a no-model *opener*: the engine that opens the lane's first release, synthetic
first-days fixtures (cases) with the frozen key the engine must print on each, and neutral controls on
which no key may hold. The declaration is `openers/layer1.toml` (one `[[opener]]` per lane, further
cases as `[[opener.case]]`); the fixture builders are `ctf/openers/fixtures.py` (`BUILDERS`; the mobile
computed-code shapes come from `ctf/openers/mobile_fixtures.py`, which builds real dex code with the
small Dalvik assembler `ctf/openers/dexasm.py`, and the Day 26 split bundle from
`ctf/openers/mobile_splits_synth.py`, B-229; the LiME images and kernel symbol tables of the
`memory-forensics` opener come from `ctf/openers/memory_fixtures.py`, B-136; the HCFG samples of the
`binary-hcfg` opener, which runs `binary.crc_transforms`, from `ctf/openers/binary_fixtures.py`, B-246). The gate
is `python -m ctf arm` (section 8). The module docstring of `ctf/openers/__init__.py` is the source of
truth; change it there and here together.

An opener's `lane` is its key in the declaration (unique; `--lane`, the lane gate and `for_lane` use it)
and is not required to be a `solvers/` folder: a lane folder can hold several openers under different
keys (`memory-forensics` runs `toolkits.vol_triage`; another forensics opener adds its own block). A
fixture builder may write files beside the input it returns (a delivery: the image and the table that
shipped with it); the engine is still run on the returned path only.

```python
openers.load(root=None) -> list[Opener]          # OpenerError: malformed block, duplicate lane, unknown key or
                                                 #   builder, an offline opener without fixture/expect/controls,
                                                 #   an engine that does not resolve or is not a cli entry
openers.for_lane(lane, openers=None, root=None) -> Opener     # OpenerError for a lane with no opener
openers.select(openers, lanes=None, profile=None) -> list[Opener]   # profile category = opener category or
                                                 #   lane name (no case/punctuation); unknown lane: OpenerError
openers.arm(opener, root=None, workdir=None, timeout=60.0, guard="auto", profile=None) -> ArmResult
openers.engine_env(work, profile=None) -> dict   # the run's environment (see below)
openers.run_engine(engine, input_path, root=, g=, run_dir=, work=, timeout=, profile=None, via="arm",
                   nice=0)
                                                 #   -> EngineRun(code, out, err, seconds).cut: one guarded run
                                                 #   as arming does it
openers.run_input(engine, input_path, ...same...) -> EngineRun   # run_engine; an input named attempt.json (a
                                                 #   saved multi-set attempt) runs the engine once per set, on
                                                 #   the set's own delivery (B-042). arm and the lane gate
                                                 #   (section 29) run every case and control through it
openers.os_sandbox_need(item, manifest) -> str   # why it needs the OS sandbox, or ""; item has needs_os_sandbox
openers.excerpt(stdout, stderr, limit=2000) -> str
Opener(lane, category, engine, label, fixture, expect, needs_tools, offline, reason, cases, controls,
       needs_os_sandbox).all_cases               # (Case(fixture, expect), *cases)
Case(fixture, expect, mode="base", within=None)  # mode: the row mode it stands for; within: a timed window (s)
ArmResult(lane, engine, status, reason, found, missing, seconds, exit_code, output, cases).ok
CaseResult(fixture, mode, status, reason, found, missing, seconds, exit_code, output)   # mode "control" for a control
openers.ARMED | openers.FAILED | openers.NOT_RUN
```

**Arming.** Each case and control runs as `runner.command(engine, [<fixture file>], via="arm",
record=False)` wrapped by `ctf.intake.guard.wrap` (section 19), in its own cwd under a temporary folder,
in a new session (the whole process group is killed at the timeout), with `engine_env`: the caller's
environment without `ctf.intake.engines.SECRET_ENV` names, `CTF_ENGINE_LEDGER=0`, `CTF_WORKDIR` a fresh
empty folder, and `CTF_EVENT` the profile's slug when one is given (dropped otherwise). A case is armed
when the run exits 0, every `expect` string is in its stdout and, with `within`, it took no longer. A
control fails when every `expect` string of some case is in its stdout: that key does not discriminate.
**Not run, never green:** the opener is `offline = false` (its `reason`); a tool in the manifest's
`needs_tools` or the opener's own is missing; or the engine needs the OS network sandbox
(`needs_os_sandbox = true`, a manifest `[intake] spawns = true`, or a non-Python cli entry) and the
guard is the audit hook only. Asking for `guard="os"` where it is unavailable raises `GuardError`.

**Keys** are anchored on the answer as the engine prints it (`<path>: <slug>   [<chain>]`, a full
`key = value` line), never on text the engine echoes from its input, and hold the signal rather than
a default the engine prints on anything; the control is the proof.

**Multi-delivery Mastery cases (B-042).** A case or control whose builder returns a saved attempt
(`ctf/openers/set_fixtures.py`: `attempt.json` beside `artifact/`, section 53) is run by
`openers.run_input` as a Mastery is played (`ctf/openers/sets.py`): `ctf.deliveries` pairs each set with
its own delivery, and the engine runs once per set on that delivery's bytes, each run in its own cwd with
the whole timeout. The combined stdout is one `set<N> <- <delivery> [<rule>]` line per set followed by
the engine's lines under `set<N>> `, with the path of the file it was given replaced by the delivery
(`delivery 2: blob.txt`, `delivery 1: bundle.zip -> blob-02.txt`). A key therefore names the set, the
delivery and the answer in one string. The lane's `*_crossed` control is the same attempt with the files
of sets 1 and 2 exchanged: every answer still comes out there, under the wrong set. Exit code: None when
a set's run was cut (later sets are not run), else the first non-zero engine exit, else 3 when a set has
no proven delivery (`set<N> <- UNMAPPED: <reason>`, the engine is not run for it), else 0; an attempt
that cannot be read is exit 2 with the reason on stderr. `seconds` is the sum. These cases carry no
`within`. Shipped: warmups (three same-named deliveries; one bundle of numbered blobs), script-analysis
(two `evidence.zip` in set order), metadata-forensics (one bundle of numbered evidence zips),
mobile-android (one APK per set), binary (one ELF per set: its engine reads one ELF, not the evidence
zip of the real Mastery).

---

## 21. Question-id resolver (B-010)

`ctf/idresolve.py` maps a renamed question id onto an id a reader is proven on, and refuses when that is
not certain. Rules and the convention-file schema are in the module docstring.

```python
cat = idresolve.Catalog(known_ids, strip=..., ids={...}, scopes=[...])   # or load_conventions(toml, known=...)
cat = idresolve.Catalog.from_attempt(saved_attempt_json)                 # the base attempt's ids
r = idresolve.resolve(qid, cat, members=names)    # Resolution(status, target, rule, selector, set, candidates, reason)
rep = idresolve.resolve_all(questions, cat, members)   # Report: .ok, .problems(), .to_json()
idresolve.covers(questions, cat, members=()) -> list[str]   # a lane's covers() hook: empty = every id resolves
answers, rep = idresolve.answer_through(solve_set, questions, files, ctx, catalog=cat,
                                        set_members=idresolve.SET_MEMBERS)   # optional: setN reads set N's delivery
solver = idresolve.ResolvingSolver(cat, inner_solve_set, set_members=None)   # solve_set + covers, for a lane solver file
solver.covers(questions, members=())   # without member names every stem-rule id is a problem (fail closed)
```

`answer_through` calls the inner solver once per (set, sample). Without `set_members` it expects one
set per call (as the runner calls); mapped ids of two or more sets in one call stay None. The inner
solver gets a copy of ctx without `partial`, so its known-id answers never land in the caller's partial
answers; the outer `ResolvingSolver.solve_set` writes the asked ids there. A scope's members are
counted by delivered name: two different bodies that would be handed on under one name are refused.

status is `exact` | `mapped` (resolved) or `unmatched` | `ambiguous` (fail closed: the id stays None and
is a problem line). Matching is by whole field name, never by a partial suffix. A mapped literal `none`
survives only when the asked question's format allows it (`permits_literal_none`). A lane's conventions
live beside its engines as `solvers/<lane>/id_conventions.toml` (data; no manifest). CLI:
`python -m ctf resolve-ids QUESTIONS --conventions|--known-ids|--attempt ... [--member N]` exits 0 when
every id resolves, 1 when any does not, 2 on unusable input.

---

## 22. No-model dispatcher (B-004)

The board-to-agent path with no LLM in it (dev/SPEED-STUDY.md rank 1). `ctf dispatch` reads the B-017
watch stream (section 20; no platform call of its own) and, for each `challenge_new`, writes with no
model a **claim** and a machine-written **handout**, then starts intake for the batch. The full
contract is the module docstring of `ctf/dispatch.py`; change it there and here together.

```python
dispatch.Detected.from_event(ev) -> Detected          # a challenge_new stream event (.solved from its `solved`); no id -> DispatchError
dispatch.dispatch_one(detected, profile, workdir=None, clock=time.time, record=True, intake="off") -> Claim
dispatch.handout_md(detected, profile, workdir=, brief=None) -> str   # the machine-written handout
dispatch.brief_for(workdir, detected) -> dict         # latest stored watch brief, else listing fields
dispatch.flag_grep_ere(profile) -> str                # grep -E regex for the flag; grep_command(profile)
dispatch.submit_command(profile, challenge_id) -> str # a non-plain id is shlex.quote'd (untrusted)
dispatch.playbook_path(lane) -> Path | None           # docs/playbooks/<lane>.md when it exists
dispatch.claim_path(workdir, challenge_id); dispatch.claimed_ids(workdir) -> set[str]  # corrupt -> DispatchError
dispatch.read_claims(workdir) -> ({id: record}, [(path, reason)]); dispatch.update_claim(workdir, id, **fields)
dispatch.pid_alive(pid) -> bool                       # live process (EPERM counts as live); None/bad/<=0 -> False
d = dispatch.Dispatcher(profile, workdir=None, intake_runner=None, clock=time.time, record=True,
                        intake_batches=4, max_intake_attempts=3, retry_after=10.0,
                        on_claim=None, on_intake=None, on_problem=None)
d.dispatch_new(detecteds) -> list[Claim]              # returns at once; intake runs in the background
d.once(since=0, wait=True); d.run(since=0, stop=None, poll=0.2, until=None, wait=True)
d.wait(timeout=None) -> list[IntakeResult]; d.close(); d.failed() -> list[IntakeResult]
```

A **claim** is `<workdir>/dispatch/claims/<id>.json` (`challenge_id`, `name`, `category`, `lane` =
canonical category, `points`, `seq`, `dispatched_at`, `handout`, `recon_dir`, `brief_source`,
`status`, `dispatcher_pid`, `intake` = off | pending | started | done | failed, `intake_attempts`,
`intake_error`), written at once — before intake starts. The **handout** is `<challenge dir>/handout.md`
(the `ctf.intake.challenge_dir` folder, beside the recon intake writes): the triage path, the brief
(quoted as data), the exact flag regex (the submit gate's) plus a looser grep-first command, the
category playbook (or a named "no playbook for lane X" note when `docs/playbooks/<lane>.md` does not
exist), the routed engines, a submit-on-sight command, an advisory escalation schedule
(B-016 drives the live timers and reroutes) and the solver contract with the lane's simplest-first
ladder (`solver_contract.handout_section`, B-172, section 46). Each dispatch also appends a `claim` ledger record
(`challenge_id`, `lane`, `seq`, `source`; the B-101 stage vocabulary, not a section 10 table row).

`intake_runner`, when given, is called once per dispatched batch with the new ids, on a background
thread pool (`intake_batches` at once), so the poll loop keeps claiming while a batch is intaken; the
CLI passes `ctf.intake.intake_many`, which downloads, sweeps and runs the input-adapted engines under
the network guard, recording one `engine.run` per engine (section 6). A runner that raises, or an
outcome with a non-zero exit, marks that challenge's claim `failed` with a named reason (`on_intake`,
and the CLI prints it and exits 1). Each poll retries intake for `pending`/`started` claims whose
dispatcher process is gone and for `failed` ones after `retry_after` s, up to `max_intake_attempts`.
An unreadable claim file is reported once (`on_problem`) and blocks a re-dispatch of that id. `ctf
dispatch show ID` exits 2 for an id neither the stream nor the stored briefs know. The dispatcher
never runs a model and never submits; the owner agent submits on sight through the queue (section 5).
`dispatch_new` skips any challenge in `ctf.solved.solved_ids`, recording a `dispatch_skip` ledger event,
so it never dispatches onto an already-solved challenge (B-015, section 26). Revoking a live claim on a
solve is B-015 (`ctf.solved`). The handout's escalation schedule is an advisory default; the live
timers and reroutes are B-016 (section 27).

---

## 23. Regression gate (B-195)

`python -m ctf gate plan | run | inventory` (`ctf/cli/gate.py`, code in `ctf/gate/`). The map is
`tests/gate.toml` (schema in `ctf/gate/config.py`; unknown keys are errors).

- **Selection.** `--base REF` (files changed since REF, untracked included) and/or `--changed F ...`
  select the test files whose static closure holds a changed file (imports, `pkg.mod` strings, path
  strings; a bare file name counts by content but is not followed), plus `[[scan]]` tests whose
  `inputs` globs match. A deleted file selects the tests whose closure names it and no longer
  resolves. A changed `global` input or an unmapped non-`inert` file makes the run **full**, naming
  the file. `--lane L` (alone: every file of the lane; with a selection: a filter) matches the lane
  globs against a test's direct dependencies; a lane glob starting with `!` excludes the files it
  matches (B-153: `config.lane_matches`), so a hub nearly every test imports puts no test in the lane.
- **Full once per batch.** `--batch ID`: the first run of a batch is full and is recorded in
  `<state>/batches/ID.json` with its red files (FAIL/ERROR/TIMEOUT); later runs of that batch are
  impact runs and need `--base`/`--changed` (or `--lane`). Every later run of the batch also reruns
  the batch's red files, after any lane filter, and updates the list: a file leaves it only when it
  runs green, a file that goes red joins it, a deleted one is dropped with a reason. So a red the full
  run found keeps the batch red whatever later changes touch. A record without a `red` list is an
  error (rerun with `--batch ID --full`). `--full` forces a full run. A full run reuses nothing.
- **Warm reuse.** A test file's key = sha256 over its inputs (closure, scan inputs, globals, data
  files under folders it names) by content, `sys.version`/`sys.executable`, the config `env` knobs and
  extra pytest args. Only a green, complete result (exit 0, no plain skip; xfail allowed) is stored;
  impact and lane runs reuse it on an exact key match (`--no-warm` turns reuse off). `no_warm` globs
  (the real-data scripts) always run, and so does a file carried as red in the batch
  (`run_gate(no_reuse=)`); a red run deletes the green result stored under its key
  (`WarmStore.drop`). Only a file that really ran (not a warm row) can leave a batch's red list.
- **Run.** One pytest child per file, `--jobs N` at a time (default 2), each in its own process group
  under a wall of `base_seconds * clamp(load1/cpus, 1, max_scale)`; TIMEOUT is red. One line per file
  (`PASS|FAIL|ERROR|TIMEOUT|EMPTY|ENV  secs  file  counts  [warm key] | detail`), then
  `GATE result=pass|fail mode=... files= ran= warm= ... empty= env= ... load= wall= scale=`. Exit 0
  green, 1 red, 2 usage or config error, 130 interrupted.
- **Environment vs. failure (B-137).** A red whose every failing/erroring message blames the
  environment is reported `ENV`, not FAIL: it does not turn the gate red (ENV is not in `ctf.gate.runner.BAD`),
  is never stored warm, and is listed apart. The verdict is judged from the pytest child's junit and
  log only (`ctf.gate.envfail`) -- the gate never probes Docker, the network or a tool. Signatures: a
  Docker daemon that will not answer, a sandbox-denied bind/listen/connect, and an explicit
  `GATE-ENV: <reason>` line a test emits to declare its own missing tool. A real failure beside an
  environment one keeps the whole file red, so a broken test cannot masquerade as ENV.
- **Stable fail log (B-137).** Every `ctf gate run` overwrites `<state>/last-fail.log` (human) and
  `<state>/last-run.json` (machine) with the run's result and one line per non-green file -- its
  status, name, detail and per-file log path (`ctf.gate.faillog`). A fixed path, written whatever the
  result, so a red is never lost when stdout is piped to `tail`; the `GATE` summary stays the final
  stdout line. A green run writes an "all N files green" line so a stale red log is never mistaken for
  the current state.
- **Full runs ignore the index (B-137).** A `--full` run (the arm/release path) lists the tree by
  walking the filesystem and dropping only gitignored paths (`impact.list_files(use_index=False)` →
  `list_files_fs`), never reading the git index -- so a staged deletion, a staged add or a
  `git rm --cached` cannot change which files it runs. Impact runs keep the fast `git ls-files`
  listing, since they are about the working tree's changes.
- **Progress.** `ctf gate run` writes a `ctf.progress` file (section 47) under `<state>/progress/`:
  kind `gate`, label = the mode, total = selected files, one step per finished file (warm rows count
  as done, not ran; red files are listed), then `pass`, `fail`, `interrupted` (Ctrl-C) or `error` (any
  other exception, which still propagates). `run_gate(on_row=)`
  is the hook. `ctf live` reads it for the gate's state and ETA.
- **Inventory.** `ctf.gate.inventory.ContentHashes` (sha256 re-read only when size/mtime/ctime/inode
  move) and `Inventory(path, version).refresh({key: content hash}, compute)` (recompute only changed
  keys, drop removed ones; an unreadable or other-version file is rebuilt and says so; `.discard(key)`
  forgets one key so the next refresh recomputes it, B-253). The gate keys
  its parse results by file; any per-item corpus index (a speed-run mode list, B-253's replay cache)
  uses the same class rather than rebuilding everything.
- **State.** `ctf.paths.gate_state()`: `$CTF_GATE_STATE`, else `<git common dir>/ctf-gate`. Tests
  point it at a temp folder; build agents set `CTF_GATE_STATE` so nothing is written in a shared `.git`.
- **Idle-machine lock (B-213).** `ctf gate run --idle-lock` (or `$CTF_IDLE_LOCK` true; `--no-idle-lock`
  wins over it; `--idle-timeout S` gives up with exit 2 naming the holder) holds the section 68 lock
  exclusive from the first file that runs to the last; a run whose every file is reused warm does not
  take it. In code: `run_gate(idle=)` takes a factory such as `workreg.idle_lock_for(root, label)`.
- **Release-path guards (B-137).** `ctf/gate/guards.py` names each guard that stands between the
  solver and an irreversible act (the submit gate's `base_checks` and `SubmitGate.refusal`, the Hall of
  Fame `check`, the budget meter's cap in `LedgerMeter.check`) with its call spellings and a fires-test.
  `tools/guard_audit.py` flags a bare/broad `except` that wraps a guard call and neither re-raises nor
  exits -- the Oct 9 shape where a suppressed NameError left a guard "armed but dead". Add a guard to
  the registry when you add a check to the release path; `tests/test_release_guards_fire.py` drives each
  one to fire and runs the lint over `ctf/platform`, `ctf/budget.py`, `ctf/arm.py`.
- **Strict not-run (B-196).** `ctf gate run` fails a file whose tests all passed but where a test, or a
  part a test recorded with `pytest_plugin.record_not_run`, did not run: its row is `NOTRUN` (in
  `ctf.gate.runner.BAD`, so it is red, drops its warm result and joins a batch's red list) and the
  `GATE` line ends `notrun=N`. `ctf.gate.notrun` reads the facts from the child's junit (`<skipped>`
  messages, xfail types and the `ctf_not_run` property) and gives each the plugin's kind
  (`needs_realdata`, `needs_tool`, `live`, `known-fail`, `xfail`, `skip`). Accepted kinds are
  `tests/gate.toml` `not_run_ok` (this repo: `live`, `xfail`, `known-fail`) plus
  `--allow-not-run KIND` (`any`: not strict for that run; `--mark-green` is then refused). A missing
  tool, corpus or package is never accepted by default. In the API, `run_file(allow_not_run=)` and
  `run_gate(allow_not_run=)` default to `None` (not strict); a stored warm result that had xfails is
  reused by a strict run only when both xfail kinds are accepted; a file with any other not-run item
  (a skip, or a part recorded through the `ctf_not_run` property) is never stored, whatever the run
  allowed. A NOTRUN row is never reclassified ENV.

- **Children's interpreter (B-153).** `ctf.pyinterp.resolve(root) -> Interpreter(path, source)`:
  `$CTF_PYTHON` (when set it must be executable, else `PythonError`, never a fall-through), then
  `<checkout>/.venv/bin/python`, then the main checkout's `.venv` (the working tree that owns the git
  common dir, read from the `.git` file; a linked worktree has no `.venv` of its own), then the running
  interpreter -- with a source string saying why, printed as `gate: python=<path> (<source>)`. The
  gate's pytest children and `tools/suite.py` both use it (`--python PATH` overrides either); `tools/ctfpy`
  is its shell twin. A child interpreter other than the running one enters the warm key.
- **Lane budget (B-153, `ctf.gate.budget`).** `[budget] lane_seconds` (default 300, at most 300: a
  longer gate is the pre-arm gate), `[budget.lanes] L = S` (at most 300, a known lane) and
  `[budget] full_only = [test globs]`: files no lane gate runs (a run with `--lane` that is not full drops
  them and its reason line names each as `NOT run here, left to the full and pre-arm gates`; a lane of
  only full-only files is an error, while an impact run (`--base`/`--changed`) with `--lane` whose impacted
  lane files are all full-only is an empty run, exit 0, with that reason line; `ctf gate budget` leaves them
  out of the estimate and lists them, JSON `full_only`). Test files in no lane (`no_lane_tests`) are named
  by `ctf gate budget` (`gate: N test file(s) are in no lane ...`), counted by `plan --lane` and listed in
  its JSON `no_lane`. A file's cost
  is `max(C, W - C * (r - 1))` with C the child's CPU seconds (from `os.wait4`), W its wall seconds and
  r = `max(1, load1/cpus at its start)`: CPU time does not inflate with host load, and the waiting part of
  the wall (W minus the load-stretched CPU) is counted whole, never divided by the load; a lane's cost is the longest-first makespan on `--jobs`
  workers; a warm row costs nothing. `<state>/timings.json` (`Timings`, flock-guarded, shared by worktrees)
  keeps each file's last real run (`run_gate(record_timings=True)`); `ctf gate budget --import-junit`
  seeds files with no gate record from a full-suite junit. A `run`/`plan` with `--lane` that is not a full
  run is refused before it starts (exit 3, nothing runs) when the recorded cost of the files it would run
  already exceeds the budget, naming the costliest files and the `--jobs` that would fit; after a run the
  measured cost goes on the GATE line as `budget=ok|over:<cost>/<limit>s`, and over is exit 3 even when
  every test passed (red stays exit 1). `--budget S` is the explicit override. `ctf gate budget` lists
  every lane (`BUDGET lane= limit= estimate= jobs= known= unknown= verdict=`), exit 3 when one is over.
- **Baseline ledger (B-153, `ctf.gate.baseline`).** `baseline = "tests/gate_baseline.toml"` in
  tests/gate.toml names a tracked TOML ledger: `version = 1`, `[[red]]` tables of `id` (a pytest node id),
  `kind` (`flaky | env | stale | broken`), `reason` (at least 10 characters), `since` (a TOML date, not in
  the future), optional `owner`; anything else is an error. With a ledger, `run_gate(baseline=ledger)`
  splits each red file's failing junit cases into new and baseline reds (`Row.red_new`, `red_baseline`;
  the detail names each with the ledger's kind, date and reason) and the GATE line ends `red_new=N
  red_baseline=M`; a red stays red and the exit code is unchanged. `last-run.json` items carry both
  counts. `tools/junit_diff.py --baseline FILE` lists ledger hits apart as `baseline_failed`, never newly
  bad. `ctf gate baseline check` exits 1 on an entry whose test file is gone.
- **Pre-arm full gate (B-153, `ctf.gate.prearm`).** `ctf gate prearm` runs every preflight check and
  reports each (`PREFLIGHT ok|FAIL <name>: <detail>`): `python` (the children's interpreter imports
  pytest), `clean` (`git status --porcelain` empty, untracked included), `baseline` (the ledger loads, no
  stale entry), `loopback` (this process can bind 127.0.0.1:0), then each `[[prearm]]` command of
  tests/gate.toml (`name`, `argv`, run as `<python> <argv...>` in the checkout; the repo wires the four
  generated-file checks and `tools/guard_audit.py`). Any failure refuses the full gate (exit 4, nothing
  runs). Otherwise it is `run --full` (index-free, nothing reused, the baseline ledger attributing), in
  which an ENV file fails the pre-arm gate (exit 1). `--mark-green SLUG` as for `run --full`. The last
  line is `PREARM result=pass|fail|refused preflight=ok|fail:<names> [gate= files= fail= error= timeout=
  env= red_new= red_baseline=]`; `<state>/last-prearm.json` records it.
- **Loopback harness (B-153, `ctf/testing/loopback.py`).** The `loopback` fixture (registered by the
  test plugin) and `bind(kind)`, `serve_http(handler)`, `serve_tcp(handler)`: 127.0.0.1 only, port 0
  only, every socket and server closed at teardown. A bind refused with EPERM/EACCES raises
  `LoopbackDenied` whose message carries `GATE-ENV:`, so the gate reports ENV, not FAIL; any other bind
  error propagates unchanged. New tests that start a fake service use it.
- Static selection misses dependencies computed at run time; the per-batch full run is the safety net.
  When `plan` says "no test maps to X", add a test, an `inert` glob or a `[[scan]]` rule. Docs are
  `inert` to the import graph, so the doc lint has its own `[[scan]]` rule (section 61).

---

## 25. Event solve policy (B-173)

One per-event policy every harness reads: the answers live in `events/<slug>/event.toml` (section 1),
the one agent-rules template renders them into `CLAUDE.md` and `AGENTS.md` (section 15), the code
enforces them (the submit gate, section 5; the scope guard, section 13), and `ctf policy show` prints
them (`--json` for scripts).

| question | profile field(s) | enforced by |
|---|---|---|
| penalty | `rules.wrong_penalty` (absent = not known) | template; `authorize-sweep` prints the worst case |
| throttle | `[submit]` `per_minute`, `interval_s`, `per_challenge_interval_s` | the submit queue |
| who submits | `rules.submit_mode` (auto: each solver on sight; confirm: after the player's yes; manual: the player) | the gate |
| wrong quota | `rules.wrong_answer_stop`, `rules.approved_extras` | `EventRules.check`, `grant` |
| guesses | `rules.guess_budget`; each `guess=True` send (`ctf submit --guess`) is logged with its note | `EventRules.check`; `ctf policy guesses` |
| sweeps | `[sweep]` `mode`, `max_count`, `interval_s`, `ttl_s` | `EventRules.authorize_sweep` / `sweep_refusal`, `run_sweep` |
| hints | `rules.hints_allowed`, `rules.hint_suggestions` | template (the CTFd adapter refuses every hint unlock) |
| live services | `rules.live_service_scope`, `rules.pointed_services` | `scope.check_host` |
| execution | `rules.sandboxed_execution` (default `forbidden`, B-242) | `eventpolicy.execution_refusal`, called by `binary.runtime_trace` before anything is run (section 54) |

```python
from ctf import eventpolicy
pol = eventpolicy.summary(profile)            # eventpolicy.Policy (frozen); pol.to_dict()
eventpolicy.lines(pol)                         # the `ctf policy show` lines
eventpolicy.execution_refusal(profile)         # None when rules.sandboxed_execution = "allowed", else
                                               # the reason, naming the key and the event (B-242)
eventpolicy.penalty_text(wrong_penalty)        # the penalty in words
eventpolicy.guess_log(profile, challenge_id=None, workdir=None)   # guess and sweep platform.submit records
eventpolicy.parse_address("host:port")         # (host, port | None); PolicyError on a URL, glob or bad port
eventpolicy.point(profile, challenge_id, address, reason, workdir=None)    # a scope.pointed record
eventpolicy.unpoint(profile, address, reason, workdir=None)                 # a scope.unpointed record
rep = eventpolicy.run_sweep(gate, challenge_id, candidates, auth_id=..., note=..., workdir=None,
                            clock=time.time, sleep=time.sleep)              # eventpolicy.SweepReport
# SweepReport(challenge_id, auth_id, outcome, reason, sent, skipped, results, accepted)
# outcome: accepted | exhausted | stopped. Errors: PolicyError (a ValueError), SweepError(PolicyError)
```

- **One run per authorization.** The player runs `ctf policy authorize-sweep <id> --count N --reason
  ...`, which prints an auth id. `run_sweep` (or `ctf policy sweep`) first checks it
  (`sweep_refusal`) and claims it with an exclusive file `<workdir>/sweeps/<auth id>.run`; a second
  run with the same id raises `SweepError` before any send. It then sends each distinct candidate
  through the gate and its queue with `guess=True, confirmed=True, sweep=<auth id>` and the
  provenance `<note> [sweep <auth id> #<n>]`, waiting `sweep.interval_s` after each actual send.
  It stops at the first accepted value, at any refusal other than `duplicate` (a value already judged
  is skipped, not sent), and at an unjudged answer the queue gave up on.
- **The guard stays on.** Outside an authorized run nothing changes: sweep sends count toward neither
  the stop nor the guess budget, so after the run the challenge's guard is where it was.
- **Pointed services.** `point` refuses (`PolicyError`) when `rules.pointed_services` is `forbidden`,
  when the address is the event platform (by host, or host and port), and for a URL, a glob, a network
  or a bad port. A point without a port admits every port of that host. A point is recorded with
  the challenge it is for (the provenance), but it is admitted event-wide: `scope.check_host` takes no
  challenge id, so a service pointed for one challenge is reachable from every solver of the event.
  This is intended: the scope guard answers "may this event's agents reach this host", and one
  challenge's service is often shared by its parts (`5#1`, `5#2`) or by a follow-up challenge.
  `unpoint` withdraws it for the whole event.
- **Drain and sweeps.** `submit-queue drain` resends a spooled sweep send (one whose send raised)
  only while its authorization is valid (`sweep_refusal`) and claimed by a run
  (`EventRules.sweep_unclaimed`: the claim file exists and lists the value's SHA-256), so only the
  run's own spooled sends are resent and a hand-written spool record cannot stand in for the run. Drain paces it: it waits until `sweep.interval_s` after the last send on that
  challenge (the queue's `by_challenge` stamp) before handing it to the queue.
- `ctf policy` exit codes: 0 ok (sweep: a value was accepted), 1 a sweep ended with nothing accepted,
  2 an error (unreadable candidate file, corrupt ledger, a failed send), 4 refused by the policy
  (manual event, no or used authorization, pointed services forbidden).

---

## 26. Claim store solved view + solved watcher (B-015)

A team solve — ours or a teammate's — must stop every agent on the challenge and block any new dispatch
onto it (11 W2 agents ran on already-solved challenges; $364.73 was spent after a teammate solve). The
B-017 watch stream (section 20) already emits `team_solved` and `challenge_gone`; `ctf.solved` turns them
into the shared stop signal and keeps the B-004 claim store (section 22) in step. No model, no platform
call of its own.

```python
solved.solved_ids(workdir=None) -> set[str]        # ids with a team-solve stop in the ledger (incl. teammates)
solved.is_solved(challenge_id, workdir=None) -> bool
solved.record_solve(challenge_id, solver=None, workdir=None) -> bool  # True = newly recorded; idempotent
w = solved.SolvedWatcher(workdir=None, on_solve=None, on_gone=None, on_problem=None, on_return=None,
                         clock=time.time)
w.handle(ev) -> str | None      # act on one stream event; returns the id when it recorded a solve
w.once(since=0) -> list[str]     # act on the solves/gones the stream already holds
w.run(since=0, stop=None, poll=0.2, sleep=time.sleep, until=None) -> list[str]   # follow the stream
```

`record_solve` calls `budget.on_team_solve` (section 10), writing one final `stop {reason: team_solve}`
to the event ledger, so every gated launcher (R-09) and agent loop tears its agents down within one gate
poll; it also marks the challenge's dispatch claim `status: "solved"` (`solved_at`, `solved_by`), even
when the stop already existed (returns False then). The watcher marks a vanished challenge's claim
`status: "gone"` (a `challenge_gone` is not a team solve, so it is not a final stop; a `solved` claim
stays `solved`), and on a `challenge_new` with `returning: true` restores a `gone` claim to `dispatched`
(`returned_at`; `on_return(cid, restored)`). A challenge already solved the first time it is listed
arrives as `team_solved {first_sight: true}` (section 20), one that returns already solved as
`team_solved {returning: true}`, and each is recorded like any solve. A claim already at the target
status is left alone, so a `--since 0` replay keeps the first `solved_at`/`gone_at` and reports
`revoked`/`restored` False. `solved_ids` is
the shared view the dispatcher gates on: `dispatch.dispatch_new` skips any id it holds, and any
`Detected` whose `challenge_new` already said `solved` (first sight, before the solved watcher wrote its
stop), and records a `dispatch_skip {challenge_id, reason: "solved"}` ledger event, so no agent is ever
dispatched onto a solved challenge — including a teammate's solve, which never produced a claim of ours.
It reads the ledger only when a batch holds a challenge not yet claimed. A stream event with no
challenge id is reported through `on_problem` and skipped, never silently dropped. Challenge names from
the stream are untrusted data.

---

## 27. Escalation timers and reroutes (B-016)

The live escalation ladder the B-004 handout only describes (dev/SPEED-STUDY.md rank 7,
dev/mechanisms.md M6). `ctf escalate` reads the event ledger (section 10) and the B-004 claims
(section 22) and, with no model, writes one `escalation` record per decision as it comes due. The full
contract is the module docstring of `ctf/escalation.py`; change it there and here together.

```python
escalation.record_agent_stop(reason, challenge_id, harness=, workdir=None, detail=None, model=None) -> dict
escalation.detect_stop(line) -> (reason, detail) | None   # one metered-agent JSON line, terminal signals only
escalation.read_states(workdir, claims=None) -> {challenge_key: ChallengeState}
esc = escalation.Escalator(profile, workdir=None, roster=None, second_s=180.0, third_s=480.0,
                           clock=time.time, record=True, read_claims=None,
                           on_decision=None, on_problem=None, router=None)
esc.roster_for(state) -> list[str]; esc.base_effort(state) -> str   # B-201: per-challenge with a router
esc.once() -> list[Decision]; esc.run(stop=None, poll=5.0, until=None) -> list[Decision]
esc.decisions_for(state, pending=None) -> list[Decision]; esc.owner_model(state) -> str
esc.show(challenge_id) -> dict; esc.unrouted -> list[Decision]   # no_model decisions still unmet
# Decision(challenge_id, action, trigger, to_model, from_model, elapsed_s, status, detail, for_stop_ts)
# escalation.SECOND_S, THIRD_S, POLL_S, REROUTE_BUDGET_S, ACTIONS, STOP_REASONS, STATUS_NO_MODEL
```

The ladder, per owned challenge (a claim, an `agent_launch` or an `agent_stop`: tools/codex_handoff.sh
writes only the stop; a bare `detect` owns nothing), stopping once it is solved or stopped (section 10
`accepted` of the bare id / `platform.submit` correct of the bare id that is not `partial` and not
`remaining > 0` / a correct part with `remaining = 0` / any `stop` / a dispatch claim section 26
marked `solved` or `gone`; a returned challenge's claim is `dispatched` again and escalates):

- a **second** agent on a different model at `second_s` (default 180 s) after the challenge's t0 (the
  earliest `agent_launch`, `claim` or claim `dispatched_at`; else the earliest `agent_stop`; a
  `detect` only when none exists), or at
  once on the first **rejected flag** (a `platform.submit` `incorrect` / a `rejected` stage);
- a **third** on a third model at `third_s` (default 480 s);
- a **reroute** on the next poll (default 5 s, under the 30 s budget) when an agent run stops on a
  **refusal** or a **provider error**, so a dead handoff never counts as coverage. One reroute per
  agent run: the stops of one run (the latest `agent_launch` of that harness, and model when both name
  one, at or before the stop) are answered once; a stop with no matching launch is its own run.
  `elapsed_s` is measured from the stop.

Ids are keyed with `ctf.platform.rules.challenge_key`: a multi-answer part `9#a` counts toward `9`. A
rejected part triggers the parent's early second; a correct part (a `platform.submit` or an `accepted`
stage) is listed in `show`'s `solved_parts` and does not by itself resolve the parent (the Game
Master's SubmitStatus is CORRECT for a banked part with others open); it resolves the parent only when
its `platform.submit` record carries `remaining = 0` (section 10 row; the Game Master's `CORRECT`
reply). Without a `remaining` (any other platform) the parent waits for a bare-id solve or a `stop`.

Models. The owner's model is the model on the first `agent_launch` (the metered launchers record it),
else roster[0]. A reroute moves off the stopped run's model (`agent_stop.model`, else its launch's,
else the owner's). The roster is `[models.primary, *models.fallback]`, extended with `ctf escalate
--model ID`; every model already launched, stopped or escalated onto is skipped, so each agent is a
*different* model. When no unused model is left, the decision is still written, loudly, with `status =
"no_model"` and a named shortage (never a silent reuse), and `ctf escalate` exits 1. A `no_model` is
not final: it is not written again while the roster is still exhausted (but is reported as unrouted on
every pass, exit 1), and a later pass with a free model writes the `dispatched` decision.

Ledger events written for this section (not section 10 table rows):

- `agent_launch` gains `model`? (tools/launch_gate.py: the codex usage reader's model, else the
  agent's `--model` / `-m`).
- `agent_stop` (`record_agent_stop`; the metered launchers via `ctf.stages.AgentStreamTap`, at most one
  per launched agent; `ctf escalate stop`; tools/codex_handoff.sh when its preflight fails or its codex
  run exits non-zero): `challenge_id`, `harness`, `reason` (`refusal` | `provider_error`), `detail`?,
  `model`?. Only terminal signals count: Claude `stop_reason: refusal`, a Claude `result` with
  `is_error` / an `error*` subtype other than a self-imposed `error_max_*` limit, a Codex `turn.failed`.
  A bare Codex `error` line (a reconnect notice) is not a stop.
- `escalation` (`Escalator._emit`): `challenge_id`, `action` (`second` | `third` | `reroute`),
  `trigger` (`timer` | `rejected_flag` | `refusal` | `provider_error`), `to_model`, `from_model`,
  `elapsed_s`, `status` (`dispatched` | `no_model`), `detail`?, `for_stop_ts`? (a reroute's answered
  stop). A dispatched second/third/reroute is never repeated, so re-running `ctf escalate` is
  idempotent.

Router (B-201, section 67). With `router=` (`ctf escalate` passes one when the profile has a
`[routing]` table) each challenge's roster is the router's `roster("solve", difficulty, category=...)` then the
`--model` extension, and the ramp's base effort is the `effort` the first `agent_launch` records (the
effort a routed launch ran at, an explicit `--effort` included), else that route's effort on the first
launch's `harness` (an explicit `effort=` wins over both). The difficulty and category are the first
`agent_launch`'s (a routed launch records them), else `routing.default_difficulty`. `show` adds
`difficulty` and `category`.

`ctf escalate` launches nothing: an orchestrator or a warm-standby agent reads the `escalation`
records and starts the agents (as the dispatcher writes a claim and something else runs intake). CLI:
`run` follows the ledger, `once` does one pass, `show ID [--model M ...]` prints a challenge's view with
the same roster and timers as `run` (writes nothing), `stop` records an `agent_stop` by hand
(`--model` names the stopped model). Agent output is data: `detect_stop` reads only the harness
protocol's stop/error fields, never challenge text.

---

## 28. Host resource governor (B-176)

`ctf/governor.py` (readings, policy, decision, host-wide slots, RSS watchdog, measured budget, doctor
checks) and `ctf/diskguard.py` (disk preflight, symlink-rejecting copier, post-acceptance eviction,
Spotlight exclusion). Builds on section 2's `paths.governor_state()` and B-018's `ctf.capacity`
(`HostState.resources()` is a `capacity.HostResources`; the RAM reserve is `CTF_CAPACITY_RESERVE_MB`).

```python
from ctf import governor, diskguard
s = governor.probe_host(disk_path)          # HostState: load, RAM, pressure, Battery, Thermal, disk; .unknown
policy = governor.GovernorPolicy.from_env() # heavy_cap 6, heavy_ram_mb 2048, load_soft 1.5 / load_hard 3.0
                                            # per CPU, battery_low 25, disk_min_gb 10, rss_alert_mb 8192, strict
d = governor.decide(s, policy, running=n)   # Decision(cap, running, heavy_cap, limits, unknown); Limit(resource, ceiling, reason)
d.slots; d.binding; d.reason; d.admit(ids)  # Admission(granted, queued, reason)
g = governor.Governor(paths.governor_state(), policy, probe=None)   # host-wide leases + FIFO queue
lease = g.acquire(label, timeout=None, poll=5.0); g.release(lease)  # Lease; GovernorTimeout names the limit
g.enqueue(label); g.try_acquire(ticket); g.leases(); g.queue(); g.decision()
procs, unreadable = governor.snapshot_processes()   # [Proc(pid, ppid, name, rss_bytes, cpu_seconds, exe)]
governor.is_agent(proc, names); governor.agent_trees(procs, names)   # [AgentTree(root, name, pids, rss_bytes, cpu_seconds)]
governor.rss_alerts(trees, policy, total_ram_bytes); governor.record_alerts(state_dir, alerts)
governor.measure(before, after, interval)   # Measurement: per_agent_ram_mb, agents_per_cpu for CTF_CAPACITY_*
governor.host_checks(s, d, policy, trees, measurement)   # [doctor.Check]
governor.parse_pmset_batt(text); governor.parse_pmset_therm(text); governor.parse_pressure_level(text)
# errors: GovernorError, GovernorTimeout(GovernorError)
diskguard.disk_preflight(path, need_bytes, min_free_bytes)   # DiskVerdict(ok, path, free_bytes, ..., reason)
diskguard.parse_size("2G"); diskguard.scan_tree(src)         # bytes; (files, bytes)
diskguard.safe_copytree(src, dst, min_free_bytes=0)          # SymlinkRejected | DiskBudgetError before writing
diskguard.eviction_plan(workdir, min_bytes=50 * MiB, solved=None)   # EvictionPlan(files=[Evictable], kept, challenges)
diskguard.apply_eviction(plan, workdir)     # deletes; evicted.json per challenge; governor.evict ledger records
diskguard.spotlight_status(path); diskguard.exclude_from_spotlight(path)   # SpotlightStatus(excluded, how, detail)
# errors: DiskGuardError, SymlinkRejected(DiskGuardError), DiskBudgetError(DiskGuardError)
```

- **Decision.** Every ceiling is a total of concurrent heavy agents; the cap is the lowest. Policy:
  `heavy_cap`. Load (1-minute, per logical CPU): at or over `load_soft` halves the cap, at or over
  `load_hard` admits none. RAM: `running` + (available - reserve) // `heavy_ram_mb`. macOS memory
  pressure: warn halves, critical admits none. Battery: on battery halves (under `battery_low` none);
  plugged in but discharging (the charger cannot keep up) halves (under `battery_low` none); no battery
  is no limit. Thermal (`pmset -g therm`): warning or performance level 1, or a CPU speed limit under
  100%, halves; level 2+ or a limit under 60% admits none. Disk: under `disk_min_gb` free admits none.
  "Halves" is `max(1, heavy_cap // 2)`. A reading not taken is in `HostState.unknown` with the reason
  and in `Decision.unknown`; with `strict` (`CTF_GOVERNOR_STRICT=1`) each one is a ceiling of 0.
- **Slots.** One governor per host (`CTF_GOVERNOR_STATE`): `leases/<id>.json` and `queue/<id>.json`
  (id, pid, label), under an flock on `lock`: every listing (`leases()`, `queue()`, admission) holds
  it, and files are written atomically (hidden temp file, then rename). A waiter is admitted when its queue position is below
  `slots`; a lease or ticket whose pid is gone, or whose file does not parse, is removed and named in
  `Governor.reaped`. `ctf governor run -- CMD` is the consumer: it holds one slot while CMD runs.
- **Watchdog.** An agent is a process named exactly one of `agent_names` (default `claude`, `codex`;
  case-sensitive, so the `Claude` desktop app is not one) or a versioned install of one
  (`.../claude/versions/<v>`). Its tree is it and every descendant; nested agents count once. Alerts:
  a tree at or over `rss_alert_mb`, or all trees together at or over half of RAM. It alerts (stderr,
  `alerts.jsonl` in the state folder, `--notify` macOS notification); it never signals a process.
  Command lines are never read.
- **Measure.** RAM: 90th-percentile tree RSS x 1.25. CPU: 100 / mean tree CPU % agents per CPU, clamped
  to `MAX_AGENTS_PER_CPU` (8). No agent running is a `GovernorError`, never a zero budget.
- **Doctor checks** (`ctf.doctor.Check`): `host-load`, `host-ram`, `host-battery`, `host-thermal`,
  `host-disk`, `governor`, `agent-rss`, `agent-budget`. A reading not taken is `skip` (with `strict`,
  `fail`). They are run by `ctf governor check`, not by `doctor.run_checks`.
- **Disk.** `safe_copytree` scans first and writes nothing when the source holds a symlink, FIFO,
  socket or device, when the copy would leave less than `min_free_bytes`, when `dst` exists or lies
  inside `src`. Eviction covers only `<id>-<slug>` folders whose flag was accepted (`flag.txt`) or whose
  id has a team-solve stop (`solved.solved_ids`); writeups, scripts, notes and records
  (`KEEP_NAMES`, `KEEP_SUFFIXES`, `KEEP_PREFIXES`, `KEEP_DIRS`) are kept whatever their size; nothing
  is followed through a symlink; each file is re-checked (inode, size, mtime, regular, inside its
  folder) before it is deleted, and a changed one is skipped. `ctf governor evict` is a dry run unless
  `--apply`. Spotlight: a folder ending `.noindex` is excluded; the `.metadata_never_index` marker is
  reported with the caveat that recent macOS honours it reliably only at volume roots.

---

## 29. Per-lane adaptation loop (B-036)

The loop that turns a new lane component into a no-model close by the next clock. The module
docstrings of `ctf/adapt/regress.py`, `ctf/adapt/chain.py`, `ctf/adapt/qdiff.py`,
`ctf/adapt/setpool.py`, `ctf/adapt/clocks.py` and `ctf/adapt/replay.py` (the last two B-253) are the source of truth; change them and this section together. Nothing in
`ctf.adapt` starts a clock or talks to a platform.

```python
from ctf.adapt import AdaptError, regress, chain, qdiff, setpool, clocks, replay
regress.regression_set(lane, root=None, workdir=None) -> list[RegCase]   # opener cases + controls + event cases
regress.record_case(lane, name, engine=, input_file=, expect=, workdir=, root=None, mode="base", within=None,
                    scope=(), note="", force=False) -> RegCase            # "yesterday", copied into the workdir
regress.gate(lane, root=None, workdir=None, cap=60.0, warm=True, regate=True, recut=2.0, guard="auto",
             profile=None, load=None, cpus=None, max_scale=4.0, keyer=None, record=True,
             jobs=1, nice=None,                         # jobs N | "auto" (clocks.replay_policy), B-253
             idle=None) -> LaneGate                   # idle: an idle-lock factory, taken before the first replay (section 68)
regress.prewarm(lanes, root=None, workdir=None, **gate_kw) -> list[LaneGate]
regress.watch(lanes, interval=5.0, duration=None, root=None, workdir=None, on_gate=None, **gate_kw)
                                                   # prewarm on change: a live fix is gated within one interval
regress.lanes_for(profile, root=None, workdir=None) -> list[str]          # opener lanes of the profile + recorded lanes
regress.current_lane_key(lane, root=None, workdir=None, keyer=None) -> str
regress.Keyer(root=None, state=None, day_scoped=True)                     # per-case keys over ctf.gate.impact
keyer.days(case, whole=False) ; keyer.folder_files(folder, days) ; keyer.day_refs(rel)   # lane minus other days' dNN (B-253)
keyer.case_key(case, m, whole=False) ; keyer.lane_part_key(case, m, key=None)   # warm-cache key ; lane-key part (not day-scoped)
regress.day_of(rel) ; regress.days_in_text(*texts) ; regress.days_in_file(path)
LaneGate(lane, verdict, reason, lane_key, cases, seconds, cap, scale, notes, jobs, nice).ok   # verdict yes | no | not-run
CaseOutcome(case, mode, status, reason, key, seconds, exit_code, runs, cap, recut, regated, output)
                                                   # status pass | warm | fail | cut | not-run
chain.plan(base_id, lane, workdir=None, root=None, max_retries=1, gate_kw=None, keyer=None, record=True,
           artifact_sha256=None) -> ChainStep
ChainStep(base, challenge_id, mode, action, reason, closed, gate, lane_key)   # action wait|start|retry|stop|hold|done
chain.closures(workdir=None) -> dict[str, Closure]       # Closure(challenge_id, by, source, ts, note)
chain.mark_closed(challenge_id, by=, note="", workdir=None)         # by teammate | hand
chain.record_attempt(challenge_id, outcome, lane_key=None, note=None, workdir=None,
                     artifact_sha256=None, missing=None, learned=())   # correct also folds label seeds (B-040)
with chain.AttemptGuard(challenge_id, lane_key=None, workdir=None, deadline=None, artifact_sha256=None) as att:
    ...; att.done(outcome, note=None, missing=None, learned=())     # holds a running clock (clocks) meanwhile
clocks.start(cid, deadline=, workdir=) -> Path ; clocks.stop(path) ; clocks.hold(cid, deadline=, workdir=)
clocks.running(workdir) -> [Clock(challenge_id, pid, deadline, started, path)]
clocks.deadline_busy(workdir) ; clocks.busy_source(workdir) ; clocks.replay_policy(workdir, cpus=None) -> ReplayPolicy(jobs, nice, busy, reason)
replay.replay(solver, make_sets, budget=None, pooled=True, workers=None) -> ReplayRun(answers, pooled, serial, timed_out, seconds, cpu, errors, notes, workers)
replay.SavedAttempt.load(dir) ; replay.replay_attempt(dir, solver_file, budget=None, pooled=True)
replay.stability(dir, solver_file, workdir=, budget=None, pooled=True) -> Stability(status stable|unstable|cut|failed, reason, runs, diffs)
replay.rows_in(folder) ; replay.row_key(keyer, solver_file, attempt) ; replay.gate_rows(rows, solver_file, workdir=, lane=) -> RowsGate
replay.profile_attempt(dir, solver_file, budget=None) -> Profile(sets, deliveries, workers, serial_seconds, per_set, pooled, top, equal)
qdiff.qdiff(before, after) -> QDiff        # .changes (QChange what/qid/before/after/attention), .attention, .lines()
setpool.solve(solver, sets, budget, errors) -> (raw, timed_out, said)            # the serial path, a share per set
setpool.SetPool.maybe(solver, nsets, notes) -> SetPool | None; pool.solve_sets(sets, budget, errors, notes) -> PoolRun
setpool.solve_budget(sets, deliveries=1) ; setpool.pool_wait(budget, deadline=True) ; setpool.workers_for(sets)
```

- **The set.** The lane's B-014 opener cases and controls (section 24) plus event cases under
  `<workdir>/adapt/cases/<lane>/<name>/` (`case.toml`: `engine`, `expect`, `mode`, `input`,
  `input_sha256`, optional `within`, `scope`, `note`; `input/<file>`). Event cases are challenge data:
  they stay in the workdir, never in the repo. A control must not match any case key of its engine,
  event cases included. A non-offline opener (web) is one not-run case with its reason. Unknown keys,
  a changed input, a missing `case.toml` and an empty set are AdaptError.
- **Keys** are per case: the engine manifest, the static closure of its entry file (`ctf.gate.impact`,
  sharing the regression gate's inventory under `ctf.paths.gate_state()`), the engine's folder (lanes
  load day modules by name at run time) or, when the case declares `scope`, the files its globs match
  instead (prefix-scoped: a new `d30.py` leaves a `d07*`-scoped case warm), the runner boot files, the
  fixture builder code (every `ctf/openers/*fixtures.py`: `fixtures.py` and the builder modules its
  `BUILDERS` come from, `regress.FIXTURE_GLOB`) or the input bytes (for a multi-delivery Mastery case, a
  `set_fixtures` builder, also `regress.SET_CODE`: the set fixtures, `ctf/openers/sets.py`,
  `ctf/deliveries.py`, `ctf/idresolve.py` and `tools/archive_expand.py`), the expect strings, mode,
  window, interpreter, and a control's forbidden keys. A scope that matches no file is AdaptError. The
  lane key is sha256 over every (case name, the case's key with day scoping off: `Keyer.lane_part_key`),
  so it changes with any file of the lane folder even where the warm cache is day-scoped (B-253).
- **Runs.** Each case runs through `openers.run_input` (section 24; one `run_engine` call, or one per set
  for a saved multi-set attempt; B-253's `nice` applies to every run): the intake network guard, no
  secret-named variable, no ledger, its own cwd and a workdir made new for that replay (a re-replay and a
  re-gate get their own; one that already exists is an error), a process group killed at its cap. The
  run folders are a temporary folder inside the event workdir, removed after the gate.
- **Verdicts.** Caps are `cap * clamp(load1/cpus, 1, max_scale)`, and a case's `within` scales by the same
  factor. A cap-cut case is re-replayed once at `recut` (>= 2) times the cap; cut twice is NO. A failing
  case is re-run once at the recut cap before the lane stops (`regate`); a pass there is not cached. Lane
  verdict: NO if any case is fail or cut, else not-run if any is, else YES. Only first-time and recut
  passes are cached, in `<workdir>/adapt/gate/<lane>.json`; a red result drops its key. One `adapt.gate`
  record per gate (section 10).
- **Idle-machine lock (B-213).** `ctf adapt gate|prewarm|chain --idle-lock` (or `$CTF_IDLE_LOCK` true;
  `--no-idle-lock` wins; `--idle-timeout S`) holds the section 68 lock exclusive around each lane's
  replays, so no other timing suite shares the host with its caps and `within` windows. It is taken
  just before the first case that actually replays and held to the end of the lane; a lane where every
  case is warm or not run never takes it (as `run_gate`). A timeout is exit 2 naming the holder; no case
  runs without the lock.
- **Chaining.** Closed = our accepted `platform.submit` (not `partial`; `#<aid>` stripped), an
  `adapt.attempt` correct, an `adapt.closed` mark, a team-solve `stop` (B-015's solved view, section 26),
  or a watch-stream `team_solved` (section 20); the earliest wins. The first mode not closed decides: base -> `wait`; a timed mode -> the lane gate:
  `start` (yes), `stop` (no), `hold` (not run). Failed attempts (`incorrect`, `not_submitted`,
  `expired`): up to `max_retries` automatic `retry` steps behind the gate; a wrong answer is retried only
  when the lane key changed since the attempt recorded it (no key recorded: no retry). `AttemptGuard`
  records `not_submitted` for anything that ends an attempt without `done()`, SIGTERM included. A closing
  ledger or watch record (one of the five above) whose `ts` is not a number is AdaptError naming its
  event and challenge id, never quoting the row; a malformed `ts` on any other row is not read (a missing
  `ts` reads as 0).
- **qdiff** compares a timed start's questions with the base's by `id` (else `qid`): `added`, `removed`,
  `kind`, `none` (by `idresolve.permits_literal_none`, section 21), `syntax`, `accepted` need attention;
  `text` is information.
- **Lane minus dNN (B-253).** An event case without `scope` whose days are known (`dNN--`/`dNN_` in its
  input name, bytes, zip/tar member names or expect lines) keys the engine folder minus other days'
  modules (`dNN*`, `fields_dNN*`), keeping any day a kept file names (string or import, to a fixpoint)
  and the static closure of every kept Python file (out-of-folder imports included, as for the whole
  folder); no day found: the whole folder. `day_scoped=False` (CLI `--no-day-scope`) turns it off. A day
  only inside a nested compressed archive is not seen. Day scoping keys the warm cache only: the lane key
  that `chain` compares and `watch` re-gates on is not day-scoped, so a fold into a day module no case
  covers still opens a refused retry.
- **Pooled gate and the quiet check (B-253).** `gate(jobs=N)` replays stale cases N at a time;
  `jobs="auto"` (the CLI default) is `clocks.replay_policy`: 10 at nice 0 unless a clock with a deadline
  runs (another process's `AttemptGuard`), then 3 at nice 10. A deadline-null clock is idle. Clock files
  are `<workdir>/adapt/clocks/*.clock.json`; a dead pid's is removed, a malformed one is AdaptError.
  `tools/yield_clocks.clock_busy(workdir)` is the same test as `run_held`'s busy source.
- **Same-artifact retry (B-253).** `plan(artifact_sha256=S)`: a failed `not_submitted`/`expired` attempt
  that recorded artifact S, the current lane key, `missing` > 0 and no `learned` key is `stop` without
  running the gate; otherwise the retry is gated as before.
- **Replays of saved attempts (B-253).** `replay.stability` runs two `python -I` children at once, each
  through the set pool, and compares their answers (a failed or cut child is not a stability verdict);
  `gate_rows` keys each saved row (solver closure, solver folder minus other days, `tools/run.py`, the
  row's bytes) in a `ctf.gate.inventory.Inventory` at `<workdir>/adapt/replay/<lane>.json`, reuses
  greens, never caches a red (`Inventory.discard`), and a row with `expect.json` must give every answer.
- **Set pool.** Forked workers with at most one set in flight each; a set not answered cleanly within
  `pool_wait` is solved serially with what is left. `maybe` refuses to fork beside another thread.
  Each set's watchdog keeps back half a fair share for every later set; partial answers of a cut,
  raising or exiting set are kept; blank answers are dropped. A no-deadline budget is
  `solve_budget(sets, deliveries)` = `LADDER_CAP` (2 s) per set or delivery, whichever is more. A set
  whose ctx has an empty `delivery` is not solved and is named in `errors`: with the reason when the
  split proved no delivery for it (`ctx["delivery_unmapped"]`, section 53), else as not downloaded.

---

## 30. Compaction thresholds (B-032)

Compact Claude agents at 200K tokens of context and Codex agents at 150K (analysis
`tokens/EFFICIENCY-PLAN.md` section 3.5). `ctf/compaction.py`'s docstring is the full description.

```python
from ctf import compaction
compaction.threshold(harness, environ=None)      # int tokens | None (off); harness in compaction.HARNESSES
compaction.parse_tokens(text, name="value")      # "200000" | "200k" | "1m" -> int; "off" -> None
compaction.claude_env(environ=None)              # {"CLAUDE_CODE_AUTO_COMPACT_WINDOW": "200000"} | {}
compaction.claude_conflicts(environ=None)        # [reason]: settings that disable or move the threshold
compaction.claude_settings(environ=None)         # {"autoCompactWindow": 200000} | {}
compaction.codex_config_args(environ=None)       # ["-c", "model_auto_compact_token_limit=150000"] | []
s = compaction.read_session(path, harness=None)  # Session(path, harness, contexts, compactions)
compaction.detect_harness(path, lines=50)        # "claude" | "codex" from the record types
a = compaction.audit(path, harness=None, limit=None, environ=None, tolerance=compaction.OVERSHOOT_TOLERANCE)
# Audit(path, harness, threshold, responses, peak, mean, over, excess_tokens, compactions, tolerance)
# .held, .fired_at, .to_dict(), .line(); Compaction(index, trigger, pre_tokens, ts)
r = compaction.check(path, harness=None, limit=None, environ=None)   # Reading(path, harness, context, threshold); .over, .line()
compaction.preflight(environ=None, codex=True)   # (status, detail, fix) for the doctor's `compaction` check
compaction.knob_in_build(path, marker, chunk=1 << 22)   # True | False | None (a #! launcher shim)
compaction.codex_config_limit(environ=None)      # (value | None, config path): one key of the Codex config
compaction.main(argv=None)                       # python -m ctf.compaction claude-env|claude-settings|codex-config
# compaction.CompactionError (a ValueError): unusable value, conflicting setting, unreadable log
# constants: DEFAULTS, ENV_VARS, BOUNDS, CLAUDE_WINDOW_VAR, CLAUDE_SETTING, CODEX_CONFIG_KEY,
# CLAUDE_DISABLING_VARS, CLAUDE_PCT_VAR, KNOB_MARKERS, BIN_VARS, SCRIPT_PROBE_LIMIT, CHECK_EXIT_OVER
```

- Thresholds: `DEFAULTS` (claude 200000, codex 150000); `CTF_COMPACT_CLAUDE` / `CTF_COMPACT_CODEX`
  override with a token count or `off` (harness default, nothing passed). Out of `BOUNDS` (claude
  100000..1000000, Claude Code's own range; codex 50000..1000000) or unparseable raises
  `CompactionError`; never a silent default.
- Where it is applied: `fence_launch.codex_argv` and `tools/codex_handoff.sh` pass
  `-c model_auto_compact_token_limit=N` (a `-c` beats the Codex config); `tools/claude_launch` sets
  `CLAUDE_CODE_AUTO_COMPACT_WINDOW=N` in the agent's environment (it beats every settings file;
  subagents inherit it); `tools/pink_launch.sh` sets the variable and passes `--settings
  '{"autoCompactWindow":N}'`. Shell scripts read the values with `python -m ctf.compaction ...`
  (imports nothing beyond `ctf.env`; exit 2 with the reason on a bad value).
- Claude Code compacts at the window minus its summary buffer, so a little under N. Launchers refuse
  (`CompactionError`, exit 2) when the environment would defeat the threshold: `DISABLE_AUTO_COMPACT`
  or `DISABLE_COMPACT` truthy, `CLAUDE_AUTOCOMPACT_PCT_OVERRIDE` set, or a different
  `CLAUDE_CODE_AUTO_COMPACT_WINDOW`. With the threshold off nothing is refused.
- Measuring: context per response is Claude input + cache writes + cache reads (one response per
  `message.id`; sidechain and `<synthetic>` lines skipped), Codex `input_tokens` (cached included;
  `token_usage_record` by `response_id`, else de-duplicated `token_count`). Compactions: Claude
  `compact_boundary` records (`compactMetadata.preTokens`, else the last response's context); Codex
  `compacted` records, else `context_compacted` events. A response counts as `over` above
  `threshold * (1 + tolerance)`; `held` needs a threshold and no response over. A log with no usage
  records raises `CompactionError`.
- `check` is the restart route: an orchestrator reads the latest context and, at the threshold, stops
  the agent and restarts it from a briefing (B-200). It raises when the log compacted after its last
  response (the new context is not known yet) or the threshold is off.
- Doctor `compaction`: fail on an unusable threshold, a conflicting setting, or an installed build
  (`CLAUDE_BIN` / `CODEX_BIN`, else on PATH; read, never run) without the knob string; warn when the
  CLI is missing or a launcher shim, when hand-started Claude sessions lack the variable in this shell,
  or when the Codex config's `model_auto_compact_token_limit` is unset, not an integer or above the
  threshold. The Codex config is read (that key only) only when Codex checks run.

---

## 31. Ranked format catalog, corpus and property coverage matrix (B-162)

A member format the metadata lane has never met must be read by Layer 1, not by a live reader. The
catalog `ctf/formats/catalog.toml` ranks the formats a forensics lane is most likely to be handed (one
`[[format]]` each: `id`, `rank` 1..N without gaps, `label`, `basis`, `extensions`, optional `refines`,
the lane `namespaces` that read it, the corpus `samples`, `[[format.nearest]]` spellings no reader
registers that must be read by a named reader, `[[format.gaps]]` spellings nothing reads yet). The
corpus `ctf/formats/corpus.py` builds every sample from invented values with the checks that hold by
construction. The matrix asks the lane (`solvers/metadata-forensics/properties_strict.py`) every check
and every nearest spelling as a question. The module docstrings are the source of truth.

```python
formats.load(path=None) -> tuple[Format]         # by rank; CatalogError names the file, format and key
                                                 #   (unknown key, rank gap, unknown builder or detector,
                                                 #   a nearest/gap sample not of the format, bad refines)
formats.identify(name, data, catalog=None) -> list[Match]   # structural matches in rank order (sure), a
                                                 #   refined format dropped for its finer one (msi, not ole),
                                                 #   then extension-only matches (never sure). `data` is
                                                 #   any buffer (bytes or an mmap); a detector's parse error
                                                 #   (PARSE_ERRORS) is no match, any other exception is a
                                                 #   DetectorError naming it; a zip whose end record states a
                                                 #   central directory over MAX_ZIP_DIRECTORY_BYTES (16 MiB)
                                                 #   is a FormatLimit
formats.identify_path(path, catalog=None) -> list[Match]    # the file mapped read-only, never read whole
                                                 #   (`ctf formats identify` exits 2 on FormatLimit/DetectorError)
Format(id, rank, label, basis, extensions, namespaces, samples, nearest, gaps, refines)
Nearest(asked, reader, sample) | Gap(asked, sample, note) | Match(format, rank, sure, why)
formats.DETECTORS                                # format id -> bounded structural test of the bytes
corpus.build(sample_id) -> Sample(id, name, data, checks)   # CorpusError for an unknown id
corpus.Check(prop, expected, artifact=None, needs_tools=())  # needs_tools: "7zz|bsdtar" = any one of them
corpus.cfb_write(streams, clsid) | corpus.property_set(props) | corpus.msi_stream_name(name, table)
corpus.cab_write(files, method, window_bits, set_id, stamp, blocks) | corpus.lzx_uncompressed(data)
corpus.clr_image(**fields) -> bytes              # B-222: a managed PE32 built byte by byte (CLR header, metadata
                                                 #   root, #~ tables, heaps, debug entries; clr=False: native)
corpus.clr_codeview(guid, age, path) | corpus.clr_repro(digest=b"")   # the data of a CodeView / Repro debug entry
matrix.compute(catalog=None, lane=None) -> Matrix   # with $CTF_JUDGE_LEDGER=off for the run, restored after
matrix.Matrix.problems() -> list[str]            # check unmatched, nearest not unsure or by another reader,
                                                 #   sample misidentified, no facts type, namespace with no
                                                 #   reader, a reader that raised on the corpus
matrix.Matrix.not_run() -> list[str]             # checks whose tool is missing: never matched, never green
matrix.render_markdown(m) -> str                 # docs/coverage/FORMATS.md
matrix.matches(answer, expected, labels) -> (status, matched, first)   # the `absent` option never matches
matrix.lane_module()                             # properties_strict by path (PackMissing / PackLoadError)
```

**Nearest reader, always unsure.** A nearest spelling's answer must be unsure (never plain, never
`none`) and its options must name the catalog's reader (`raw~msi.product_code_guid`), unless the
spelling has since been registered as a reader of its own. A check matches when the value the builder
wrote is the plain answer or one of the unsure options (any of the standard renderings of a list or a
time); the matrix records whether it is the first. `docs/coverage/FORMATS.md` is a snapshot written by
`ctf formats matrix --write`; `--check` reports drift. It is not suite-enforced, because every reader
change in the metadata lane would move it.

**RIFF container pack.** `solvers/metadata-forensics/readers_riff.py` (in `properties_strict.MORE_FILES`)
registers the `riff` namespace: the container's own facts for any form, and `riff.<field>` of a WAVE,
AVI or WebP file read by that form's reader (unsure).

**Media containers (B-223).** The catalog's ninth format, `media` (`DETECTORS["media"]`: an ISO base media
file that is not a still image (no image major brand, and no image compatible brand unless a movie brand
stands beside it), Matroska/WebM, FLAC, Ogg, AIFF/AIFF-C; a RIFF file stays `riff`), has the samples `media_mp4` (H.264 + AAC-LC) and `media_mkv` (WebM: VP9 + Opus), checked in
ffprobe's vocabulary through `readers_media.py`. In the lane, `properties_strict.CONTAINER_HEADS`
(head namespace -> fn(data) -> the file's container namespaces, best first; `readers_media.py` fills
`media`, `audio`, `video`) adds two steps to `resolve_name(key, q, name, data)`: 4a, before guess, reads the
name by the reader registered exactly as `<container>.<rest>` (so `media.chunk_count` of a WAV is
`wav.chunk_count`, not guess's `media.stream_count`); 4b, after guess, reads it by that namespace's
families, synonym and guess. Both are unsure under the asked name's key with the reader in every option. It needs the file's bytes; without them, or with no reader there, the name stays unresolved.

**CLR/.NET pack (B-222).** `solvers/metadata-forensics/readers_dotnet.py` (in `MORE_FILES`) registers the
`dotnet` namespace (clr, cli, net, managed, dot_net read as it; the same readers under `pe.dotnet_*`).
Every name is unconfirmed; `dotnet.mvid_guid` is plain only through the judge's verdict in the seed or
ledger (key `metadata.format/dotnet_mvid_guid`, form `raw`). An executable with no CLR header of its own
that carries a .NET single-file bundle is read through the bundle's application assembly (the one its
deps.json / runtimeconfig.json names, else its one application assembly; B-054's `decompile_intake`
takes it out); an unsettled pick is Unknown, and a missing B-054 file raises ModuleNotFoundError, never
an Unknown. `readers_dotnet.read_mvid(data) -> str | None` is the Mvid read for callers outside the
question path (`speedrun/solvers/metadata_d12.py`). The catalog's tenth format, `dotnet`, is detected from the
CLR directory and the BSJB root it points at.

**Long-tail formats (B-251).** Seven more formats are catalogued after the ten above (ranks 11 to 17): `tnef`, `jxl`,
`parquet`, `avro`, `tflite`, `coreml`, `thrift`. Their structural tests live in
`ctf/formats/detect_longtail.py` (`DETECTORS`, merged into `formats.DETECTORS`; bounded to the first
8 KiB and the last four bytes, and they answer False on hostile bytes instead of raising), their samples
and the writers that build them in `ctf/formats/corpus_longtail.py` (`SAMPLES`, merged into
`corpus.BUILDERS`; the writers share no code with the readers). The lane reads them through
`solvers/metadata-forensics/readers_longtail.py` (in `properties_strict.MORE_FILES`), which registers one
namespace per format and asks the toolkit reader of that format, loaded by path on first use; every
answer is unsure, a file the reader refuses is the lane's `Unknown` with the reader's reason, and a fact
whose value is empty (`""`, `[]`) is None, never an empty answer.

A detector's True is a sure match, so a format with a short or no magic is held to more than its first
bytes, and the toolkit readers use these same tests (one source: the catalog and a reader cannot
disagree about what a file is):

- `jxl`: the 12-byte container signature, or `FF 0A` followed by an image header that
  `detect_longtail.jxl_header(codestream) -> dict` reads to its end (ValueError otherwise: an enumeration
  value, bit depth, half float or size the format does not allow, or padding bits that are not zero). A
  necessary test, not a proof: the header has no checksum (about one random continuation of `FF 0A` in
  twenty passes; `tests/test_toolkits_lt_jxl.py` holds the rate).
- `coreml`: a protobuf `Model` whose description holds only ModelDescription fields (1, 10, 11, 12, 13,
  20, 21, 50, 100, all length-delimited) and shows one sign of a model: a feature that is a
  FeatureDescription (`coreml_feature`: a name and a FeatureType), directly or inside a function
  (`coreml_function`), or a model-type field (200 and up) after the description.
- `thrift`: the strict binary protocol's message envelope (`80 01 00 <type>`, an identifier as the method
  name, a sequence id, a first field header of a binary-protocol type).

**Not catalogued, by decision:** FlatBuffers and Cap'n Proto. Neither has a magic, and a buffer of
either is told only by a heuristic on its root table or segment table (`lt_flat_capnp.detect`), which is
enough to try a reader on a file the description routes to it and not enough for a sure match that makes
the fingerprint step skip a member. `lt_flat_capnp` is therefore route-selected only (`[intake] select =
"route"`) and has no catalog row; a FlatBuffers file with a known identifier gets its own row when a
reader with its schema exists (`tflite` is one).

The toolkit readers are contract engines (`solvers/toolkits/lt_avro.py`, `lt_thrift_parquet.py`,
`lt_flat_capnp.py`, `lt_model_meta.py`, `lt_tnef.py`, `lt_jxl.py`), each with an `[intake]` table. They
share one shape (`solvers/toolkits/_lt_common.py`, an underscore helper, not an engine):

```python
detect(head: bytes, name="") -> bool            # structure of the first 8 KiB, never the name alone
inspect(data, name="", opts=None) -> (facts, blobs)   # facts: JSON-able dict; blobs: [(label, bytes)]
solve(challenge_dir, profile=None, **opts) -> SolverResult
#   solved     one distinct flag of the event format in the decoded facts or payloads
#   candidate  several
#   unsure     files of the format were read (or are malformed): evidence lists what was read
#   blocked    files of the format are there and none was read whole: notes name the tool or key
#   none       no file of the format
# FormatError (malformed; the message says where) | NotThisFormat (a format with no magic: the head
# passed, the whole file is not this format; a folder walk passes over it) | NeedsTool(tool, why)
# (tool is a needs_tool name) | NeedsKey (only a key or passphrase that was not given opens it)
# These are the only exceptions a reader is meant to raise on any bytes: a file field of the wrong type,
# a count below zero or past its bytes is a FormatError. Each of the six readers has a mutation test
# (seeded mutations and bit flips of its samples, tests/lt_mutations.py) that allows no other; that
# holds it for the mutated samples, not for every possible input.
bounded_decompress(codec, body, limit, what, why="") -> bytes
#   deflate | zlib | gzip | bzip2 | xz | brotli | zstd | snappy | lz4; never produces more than `limit`
#   bytes: a part that holds more is a FormatError (nothing past the limit is inflated), a missing
#   decoder a NeedsTool. Every reader decompresses through it.
```

Two rules hold for every reader. **A missing decoder is never silent:** a reader that can read the rest
of a file without it (a JPEG XL `brob` box without brotli, a TNEF RTF body without compressed_rtf) lists
the part under the facts key `needs_tool` (`["py:brotli: the brob box at offset 32 is ..."]`); `solve`
puts every such line in the notes, and a file that gave no flag and has one counts as blocked, not read
(the CLI exits 1 with the line as `error`). The undecoded bytes are not handed to the flag scan. **A
count is held to its bytes or to a named limit, and repeated references to a per-file budget:** a count
a file states is held to the bytes that could hold it or to a module constant `MAX_*`, and what a file
can make a reader do many times over (references that name one target, items that take no bytes,
column chunks that share pages) is charged to a budget of the file, not of the part: Avro
`MAX_DECODED_VALUES` values decoded (a record and each field count) and `MAX_KEPT_VALUES` kept; Parquet
`MAX_FILE_READ` bytes of pages read (stored and decompressed alike), `MAX_FILE_PAGES` pages and
`MAX_KEPT_BYTES` of kept values (a dictionary entry each time it is kept); JPEG XL `MAX_BROB_TOTAL` bytes
out of all `brob` boxes; TFLite four times the file and 1 MiB of tables, strings, vectors, copied
buffers and tensor text read through offsets (`lt_flat_capnp.Reach`, which `Table` charges when given
one; past it the file is a FormatError naming the amplification); the schema-less FlatBuffers walk and
Cap'n Proto their own traversal budgets. Tests inject the limits through
`read_container(..., max_walk=, max_unpacked=, max_values=, max_kept_values=)` and
`read_parquet(..., max_read=, max_pages=, max_kept_bytes=)`. Where a limit ends the reading early the
facts say so (`walk_stopped`, `keep_stopped`, `cut`, `brob_stopped`) and keep the count the file states.
These bounds are held by tests for the amplifications they build, which is not a proof that no other
input costs more than its size.

`python solvers/toolkits/<engine>.py FILE... [--out DIR] [--opt KEY=VALUE]` prints one JSON object per
file (exit 1 when a file was not read, with its `error`) and with `--out` writes every decoded payload.

**Partitioned disk images (B-221).** Catalog format `disk` (rank 17, after the long-tail formats; namespaces `disk`, `gpt`, `mbr`; samples
`disk_gpt`, `disk_mbr`; detector: a GPT header at LBA 1 for 512- or 4096-byte sectors, or an MBR whose
entries are well formed and which is not a FAT/NTFS/exFAT boot sector). `corpus.gpt_image(parts, *, sector,
sectors, disk_guid, entries)` and `corpus.mbr_image(parts, *, sectors, signature)` build them.
`solvers/metadata-forensics/readers_disk.py` (in `MORE_FILES`, after `readers_more.py`) registers the rest
of the `disk.*` family, all unsure: table type, partition count, protective MBR, disk GUID, sector size,
total sectors, the GPT header LBAs and entry layout, the NT disk signature, and per-partition sequences in
table order (type GUIDs, unique GUIDs, names, MBR type codes, end LBAs, sector counts, byte sizes). They
read `readers_more._gpt_table_at` (the CRC-checked table the judged `disk.partition_start_lba_sequence`
reads); an MBR extended partition, a sector size an MBR does not state, and a GPT valid at both sector sizes
are Unknown with the reason.

**Unknown-format fingerprint + public code search (B-207).** The `format_fingerprint` step runs on a
member `identify` could not name `sure`: it measures what it can without a reader, looks the member up
offline before any remote search, and only then (when the event policy opens it) searches public code
for the short magic strings. Every result is an unsure 'likely tool/format' lead, never a flag. The
B-013 sweep (`ctf.sweep.fingerprint_unnamed`) auto-runs the step offline on every distinct unnamed
member and writes the leads under `fingerprint` in `.sweep.json` plus a note; the online search stays an
explicit operator opt-in via `ctf formats fingerprint --online` (which needs `--event SLUG` or `CTF_EVENT`).

```python
fingerprint.load_magic(path=None) -> tuple[Magic]   # the local magic table (ctf/formats/magic.toml),
                                                 #   longest signature first; MagicError names file/entry/key
fingerprint.fingerprint(name, data) -> Fingerprint  # magic strings, header fields, record stride (self-
                                                 #   correlation) + entropy profile, a bounded string table;
                                                 #   at most FP_BYTES read, nothing executed
fingerprint.magic_candidates(fp) -> tuple[str]   # the short magic strings worth a code search (bounded)
fingerprint.analyze(name, data, catalog=None, magic_table=None, client=None, profile=None, known=None) -> FingerprintResult
                                                 #   the step: identify (a sure match short-circuits), then
                                                 #   the offline magic lookup and the known-format DB (B-087;
                                                 #   known=None loads the shipped table, () turns it off),
                                                 #   then (only with a client) the online search; candidates
                                                 #   ranked best-first
FingerprintResult.to_result(engine=..., challenge_id=None) -> SolverResult   # status unsure; evidence are
                                                 #   the ranked leads (never a flag)
Magic(id, label, sig, at, tool, ext, note) | Candidate(source, label, why, score, tool, ref)
                                                 #   source: identify | magic | known | codesearch
codesearch.PublicCodeSearchClient(enabled=False, transport=None, clock=..., sleep=..., min_interval=2.0, request_cap=6)
codesearch.PublicCodeSearchClient.search(magics, profile=None) -> list[Lead]   # OFF unless enabled=True;
                                                 #   each request gated by scope.check_public_fetch against
                                                 #   rules.public_fetch_allow; only a short magic string is
                                                 #   ever sent (never file content); a per-string INPUT
                                                 #   refusal skips just that magic (recorded in .skipped),
                                                 #   a request-time error still propagates; Lead(source,
                                                 #   label, why, score, tool, ref); CodeSearchDisabled/CodeSearchError
```

The three gates on the online search: a client is off unless `enabled=True`; every request is validated
by `ctf.scope.check_public_fetch` against the profile's `rules.public_fetch_allow` (an event that does
not list `api.github.com` is refused); and only a short, single-line, printable, non-secret magic string
is sent. The transport, clock and sleep are injectable, so the suite never touches the network.

**Known-format DB (B-087).** `ctf/formats/known.toml`, read by `ctf/formats/known.py`, is the second
offline lookup of the step, for formats one fixed signature does not name. A `[[format]]` entry combines
signals measured on the B-207 `Fingerprint` and names the format plus the public reference that
documents its layout: `magic` (`[{ at, hex }]`, every one required, `at < 0` counted from the end),
`ascii` (a token in a printable run of the header window), `names` (fnmatch on the base name, any
case), `geometry` (`{ header, record, trailer, min_records }`: size == header + N x record + trailer)
and `entropy_min`. `require` lists the signals that must all hold, `support` the optional ones (each
that holds raises the score), `min_support` how many of those must hold; together they list every
declared signal exactly once (both omitted: all required). Loader rules (each a `KnownError` naming the
file, entry and key; an unknown key and a missing file too): `require` holds a content signal (`magic`,
`ascii` or `geometry`; a name or an entropy floor never names a format alone), and an entry whose only
required content signal is a geometry needs `min_support >= 1` (a geometry is a 1-in-record
coincidence). An entry is identification only: the table has no key, key-derivation or decryption
field, and a lead is unsure evidence like every other fingerprint lead.

```python
from ctf.formats import known
known.load(path=None) -> tuple[Known]            # file order; KnownError on any fault (never an empty table)
known.match(entry, fp, data) -> tuple[str] | None   # the reason per signal that held, or None
known.lookup(fp, data, table) -> list[Candidate]    # source "known", tool = the reference, ref = the entry id;
                                                 #   score BASE_SCORE + SIGNAL_SCORE per signal held (above a
                                                 #   bare magic hit), best first, ties by id
Known(id, label, reference, basis, require, support, min_support, family, note, magic, ascii, names,
      geometry, entropy_min); .signals | Sig(at, sig) | Geometry(header, record, trailer, min_records)
known.SIGNALS; known.CONTENT_SIGNALS; known.KNOWN_TABLE
```

`ctf.sweep.fingerprint_unnamed` loads the table once per sweep (a bad table is the note
`format_fingerprint not run: KnownError: ...`, never a crash), so a known-format lead reaches
`.sweep.json` and the sweep notes with no model; `ctf formats known` lists the table.

---

## 32. Warm standby agent pool (B-037)

A cold agent launch costs 11.5-24.6 s to the first tool; a warm agent already up and blocked on a queue
command wakes in a few seconds (dev/SPEED-STUDY.md 2.2, item 6). Warm agents are launched ahead of a
wave and block on `ctf standby take`; when the no-model dispatcher (section 22) writes claims, each
waiting agent is handed exactly one claim and its machine-written handout. No model, no platform call, no
network: it only reads the dispatch claims under the workdir and writes small lease / presence files
beside them. The full contract is the module docstring of `ctf/standby.py`; change it there and here
together.

```python
standby.take(workdir, agent, timeout=540.0, poll=0.2, stale_after=120.0,
             clock=time.monotonic, wall=time.time, sleep=time.sleep, record=True,
             owner_pid=standby.OWN_PROCESS, ttl=None) -> Assignment
                                                   # blocks; StandbyTimeout if no claim; Assignment has
                                                   # challenge_id, lane, claim, handout, handout_path, lease, waited,
                                                   # skipped ((id, reason) bad-handout claims passed over)
                                                   # never sleeps past timeout (sleeps min(poll, time left))
standby.try_lease(workdir, challenge_id, agent, clock=, stale_after=, owner_pid=, ttl=) -> dict | None
                                                   # atomic exclusive create / locked reclaim; None if a live lease holds it
standby.renew(workdir, agent, challenge_id, clock=time.time) -> dict | None   # heartbeat; None = agent no longer holds it
standby.lease_is_stale(lease, clock=time.time, stale_after=120.0) -> bool   # advisory read; try_lease re-checks under the lock
standby.unlease(workdir, challenge_id, owner) -> dict | None   # remove under the lock (owner only, any if None); no presence/ledger change
standby.release(workdir, agent, challenge_id, record=True, force=False) -> bool   # holder only, or any holder with force
standby.register(workdir, agent, status="waiting", challenge_id=None, pid=standby.OWN_PROCESS) -> dict   # presence
standby.read_leases(workdir) -> {id: lease}; standby.read_presence(workdir) -> {agent: record}
standby.pool_status(workdir, clock=time.time, stale_after=120.0) -> dict   # claims/available/leased/held_until_release/bad_handouts/agents
standby.plan(size, prefix="standby", argv_prefix=None, timeout=540.0, ttl=None) -> [{agent, argv, launch}]  # build work launches no agents
                                             # launch = standby.LAUNCH_ARGV: tools/claude_launch --standby (1h cache, B-118)
```

Under `<workdir>/dispatch/`: `leases/<id>.json` (`challenge_id`, `agent`, `pid`, `ttl`, `leased_at`,
`renewed_at`), its lock file `leases/<id>.json.lock`, and `standby/<agent>.json` (`agent`, `status` =
waiting | assigned | left, `challenge_id`, `pid`, `updated_at`). A claim is *available* when it has a
claim file (section 22) whose `status` is `dispatched` (`standby.DISPATCHED`) and no **live** lease; `take`
reads the handout of the lowest-seq available claim, then leases it with an atomic exclusive create
(`os.link` of a fully written temp file), so two agents never win the same claim. A claim with a bad
handout (missing, unreadable, no path) is skipped without a lease, recorded once per take as a
`standby.bad_handout` ledger row and named in `Assignment.skipped` and `pool_status()["bad_handouts"]`;
the next claim is handed out. If the wait ends with nothing handed out and bad claims were seen, `take`
raises `StandbyError` naming them (CLI exit 2), not `StandbyTimeout`. A corrupt claim file or a claim with
no integer `seq` raises `StandbyError` for every take, leasing nothing. Lease liveness is explicit, because the
`ctf standby take` process exits once it prints the handout: `pid` (in-process callers own it with
`OWN_PROCESS`; the CLI only with `--owner-pid`) is stale once that pid is gone and the lease is older
than `stale_after`; `ttl` (CLI `--ttl`) is stale `ttl` seconds after the last `renew`; a lease with
neither (the CLI default) is held until `release` (`release --force` is the operator's recovery).
Reclaim, renew and release run under an exclusive `flock` on the lease lock file, so concurrent
reclaimers of one stale lease serialise and exactly one wins. `take` records a `standby.take` ledger row
(`release` a `standby.release` with `holder` and `forced`). `python -m ctf standby take | renew | release
| status | plan`: `take` exits 0 on a claim, 4 on timeout, 2 on error; `renew` and `release` exit 1 when
the agent holds no such lease; an agent name must match `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`. Launching the
warm agents (~T-7 min) is an orchestrator/human step; build work runs no model and starts no agent.

Pools (B-212). `take(..., pool="dispatch"|"helpers", lane=None)` (CLI `--pool`, `--lane`): the default
`dispatch` pool is the challenge claims above; `helpers` is the lane-helper claims the helper watcher
writes (`<workdir>/helpers/claims/<id>.json`, section 62). `lane` keeps only that lane's claims. A
presence record gains `pool` / `lane` when they are not the defaults; `standby.read_pool_claims(workdir,
pool)` reads either pool; `standby.POOLS`, `DISPATCH_POOL`, `HELPERS_POOL`. A dispatch-pool agent is
never handed a helper claim. `pool_status` still reports the dispatch pool (helper leases, which share
`leases/`, show among its leases).

---

## 33. Per-challenge hypothesis ledger (B-181)

```python
from ctf import hypothesis
hypothesis.RESULTS                 # {negative, positive, inconclusive, error, false_positive}
hypothesis.path(challenge_id, workdir=None)        # <workdir>/hypotheses/<safe id>.jsonl
hypothesis.normalize_method(method)                # the dedupe key (lower, whitespace collapsed)
hypothesis.record(challenge_id, hypothesis=, method=, result=, payload=None, family=None,
                  agent=None, evidence="", control=None, workdir=None, profile=None)   # one attempt
hypothesis.validate_positive(payload, control, profile=None, family=None)   # Control(verified, reason, by)
hypothesis.body_implausible(flag)                  # None | why the flag body is not plausible
hypothesis.flag_body(flag)                         # text between the first { and the closing }
hypothesis.mark_false_positive(challenge_id, method, agent=None, evidence="", workdir=None)
hypothesis.read(challenge_id, workdir=None)        # every attempt, in write order (raises on corrupt)
hypothesis.entries(challenge_id, workdir=None)
hypothesis.seen(challenge_id, method, workdir=None)          # latest record for that method, or None
hypothesis.should_skip(challenge_id, method, workdir=None)   # Skip(skip, reason, prior)
hypothesis.methods_tried(challenge_id, workdir=None)         # {method_key: latest result}
hypothesis.latest_by_method(challenge_id, workdir=None)
hypothesis.false_positive_rate(family, workdir=None)         # FPRate(family, positives, false_positives, rate)
hypothesis.families(workdir=None)                            # every family, worst rate first
hypothesis.mine(challenge_id, workdir=None)        # Mechanism | None (the verified true mechanism)
hypothesis.mine_all(workdir=None)
hypothesis.file_mechanism(mech, workdir=None)      # append to <workdir>/hypotheses/_mechanisms.jsonl
hypothesis.mechanisms(workdir=None)
```

One append-only ledger **per challenge**, so an agent reads only its challenge's attempts (a few KB),
never the whole event ledger. Lines are written with `flock` + `O_APPEND` like `ctf.ledger`, so
concurrent agents and harnesses never interleave. A record is
`{ts, challenge_id, hypothesis, method, method_key, result, payload, family, agent, evidence, control,
verified}`; a `positive` also carries `verified_by` (`"control"`, `"flag-format"` or null) and
`verify_reason`.

- **Query before executing.** `should_skip(cid, method)` returns a `Skip`: a `negative`, a
  `false_positive` (re-running reproduces the same wrong hit; a stricter variant is a new method) or a
  *verified* `positive` settles the method (skip), while an unverified positive, `inconclusive`, `error`
  or a never-tried method does not. A runner gates a probe on it, or on the CLI `ctf hypothesis check`
  (exit 0 run / 1 skip). Every event's generated agent rules (`templates/event/agent-rules.md.tmpl`,
  "Attempts ledger") tell agents to `check` before a probe and `record` after it.
- **Positive-control validation.** `record(..., result="positive")` runs `validate_positive`. Trusted
  (`verified: true`) only (a) with an explicit `control`, an **attestation** by the recording agent of
  the known-good check it ran and saw pass (the ledger records it; it cannot re-run it;
  `verified_by: "control"`), or (b) for a method with no brute `family`, a `payload` that is a
  well-formed flag for the event, printable ASCII **and** with a plausible body (`body_implausible` is
  None: at least `MIN_BODY_WORD_CHARS` (3) characters of `[A-Za-z0-9_]`, making up at least
  `MIN_BODY_WORD_RATIO` (half) of the body) (`verified_by: "flag-format"`). A flag-shaped payload
  holding control or non-ASCII characters (`PINK{` + garbage + `}`) or printable junk (`PINK{#%!@(*&^}`,
  `PINK{ }`) is not verified, and a
  brute-family hit is never verified by its shape alone: it needs the control. Otherwise it is written
  as `verified: false` with a named `verify_reason`, never rejected and never treated as settled. With
  no resolvable event the reason says the flag format was unavailable; nothing is silently trusted.
  The CLI loads an explicit `--event` before touching anything: an unknown slug exits 2.
- **False-positive rate per brute family.** `mark_false_positive(cid, method)` files a correction
  carrying the hypothesis and family of the latest `positive` it corrects (it raises when no positive
  on that method exists). `false_positive_rate(family)` counts, across every
  challenge in the workdir, the positives in that family later corrected; a family with no positives
  reports `rate=None` (no data), never `0.0`.
- **The miner.** `mine(cid)` returns the latest verified, uncorrected `positive` as a `Mechanism`
  (`challenge_id, hypothesis, method, payload, family, agent, verified_by`), `None` when none is proven.
  A `false_positive` corrects only the positives on its method recorded before it, so a verified
  positive on the same method recorded after the correction (a re-run with a real control) is mined;
  `file_mechanism` writes it to `_mechanisms.jsonl`, the durable record a seed/promote step (B-040)
  learns from.
- **An engine that files its own checklist** (B-126, `toolkits.render_ocr_sweep`):
  `checklist(report, rejected=None)` gives one item per file and probe, `file_checklist(cid, items,
  workdir=, profile=, agent=)` records them with the method `toolkits.render_ocr_sweep <probe> [<file>]`
  (probes `spectrogram-ocr`, `spectrogram-5x7`, `bitplane-ocr`, `keyless-decode`, `cross-file-keys`).
  A probe that ran to the end with no flag is `negative`; one that could not be read (no tesseract, OCR
  off, out of time, a picture that does not open) is `error` or `inconclusive`, so it is never skipped
  as settled; so is a bit plane read at fewer sizes than it was due (`Reading.partial`), and a file
  probe that ran to the end without looking at the whole file (`files[name]["limits"]`: the 5x7 glyph
  reader past its first 60 s, a spectrogram cut by `top_hz`), which is `inconclusive` with the limit
  in its evidence; a reading the platform rejected is a `positive` followed by `mark_false_positive`. The
  two delivery-wide probes (`keyless-decode`, `cross-file-keys`) work on the texts the file probes read,
  so with no flag they are `negative` only when every reading was made, at every size, and their own
  work ran to the end (the decoder was not cut by the clock or left out for an unknown flag prefix, every key source
  was read); otherwise `inconclusive`, or `error` when no text was read at all. `ctf render-sweep`
  (section 8) is the CLI; the engine option `record=1` does the same at the end of a run.

Method strings, hypotheses and payloads recorded here are data, never instructions.

---

## 34. Tool-output hygiene and the shared read map (B-034)

Every tool result is re-read on every later model turn, so a large result is paid for many times
(EFFICIENCY-PLAN section 3.6: results over 5K tokens, and 22,609 read windows of 150+ lines, were the
two biggest reading wastes). Three parts cut that, and all three are free: a capping policy, a read
command that uses it, and a per-challenge map so a second agent does not re-read what the first already
read.

**The policy** (`ctf/hygiene.py`) is pure functions over text the caller already holds; it reads no file
and no environment, and it never truncates silently (rule 6): a capped result carries a note naming what
was cut and how to get the rest.

```python
from ctf import hygiene
hygiene.BYTES_PER_TOKEN   # 3.6, the plan's bytes-per-token ratio
hygiene.CAP_TOKENS        # 2000: the default output cap (only the first ~2K is usually needed)
hygiene.LOUD_TOKENS       # 5000: a result over this is re-read in full every later turn
hygiene.WINDOW_LINES      # 150: a read window of this many lines or more is a whole-file window
hygiene.estimate_tokens(data)                       # bytes / BYTES_PER_TOKEN, rounded up (str or bytes)
cap = hygiene.cap_text(text, max_tokens=hygiene.CAP_TOKENS, max_lines=None, keep="head")
# hygiene.CapResult(text, capped, shown_lines, total_lines, shown_tokens, total_tokens, note); cap.render()
# keep="head" or "head-tail"; whole lines only, so the budget may overshoot by one line
adv = hygiene.window_advice(n_lines, query=False)   # hygiene.WindowAdvice(ok, reason, suggestion)
# query=True (a grep) is always targeted; n_lines None (whole file) or >= WINDOW_LINES is not ok
hygiene.looks_binary(data, sample=8192)             # True for content to summarise, not dump as text
hygiene.HygieneError                                # a bad budget or mode (loud, never a silent default)
```

**The shared map** (`ctf/readmap.py`) records what each agent read of a challenge's files, at
`<challenge_dir>/recon/readmap.json` (schema 1), beside intake's recon output. Paths are relative to the
challenge dir. `open` seeds it from intake's sweep manifest (`unpacked/.sweep.json`), adding every file
the map lacks: an original under its own path (`<sources>/<chain>`, i.e. `files/<name>`, the path `ctf
read` records), a member under its scratch path (`unpacked/<archive>.unpacked/<member>`). A sweep that is
present but unreadable is a `ReadMapError`, never silently "nothing read". Every entry and every read
carries the content's sha256: `prior_reads(..., sha256=)` also finds reads of other entries holding the
same bytes (a scratch copy, an unpacked member), and drops a read whose recorded hash differs (the file
changed since). Selectors match by `readmap.overlaps`: the same selector, `full` against any line range,
two line ranges sharing a line, or two `bytes:` previews; a grep only matches the same grep. `save` holds
an exclusive `fcntl.flock` on `recon/readmap.json.lock` across the re-read, the union of entries and
reads, and the atomic replace, so agents saving at the same moment never drop each other's records.

```python
from ctf import readmap
readmap.SCHEMA; readmap.MAP_PATH; readmap.SWEEP_PATH   # 1, "recon/readmap.json", "unpacked/.sweep.json"
readmap.LOCK_SUFFIX                                    # ".lock": recon/readmap.json.lock, held while saving
readmap.agent_id(environ=None)                         # $CTF_AGENT, else "agent"
m = readmap.ReadMap.open(challenge_dir, seed=True)     # load recon/readmap.json, then seed from the sweep
m = readmap.ReadMap.load(challenge_dir)                # load without seeding (ReadMapError on bad schema)
m.seed_from_sweep(challenge_dir); m.lookup(path)       # -> number added; readmap.FileEntry | None
m.prior_reads(path, selector, exclude_agent=None, sha256=None)   # [readmap.FileRead], oldest first
m.record(path, sha256, size, kind, selector, *, tokens, agent, at=None)   # tokens, agent required
m.save(); m.to_dict(); readmap.overlaps(earlier_selector, now_selector)   # -> bool
# readmap.FileEntry(path, sha256, size, kind, reads); readmap.FileRead(agent, at, selector, tokens, sha256)
# selector is "full" | "lines:A-B" | "grep:PATTERN" | "bytes:N" | "summary" | "strings:MIN" (the last two
# B-199; they overlap only the same selector); readmap.ReadMapError on a corrupt map/sweep
```

**The command** `python -m ctf read PATH` (section 8) caps output, refuses a whole-file or large
window unless `--full`, and records the read in the shared map. `--lines A-B` is a bounded range (A-,
-B and a single A also parse; the end is clamped to the file, a start past the last line is an error);
`--grep PATTERN [--around N]` is a targeted content query; `--full` allows a whole-file window;
`--no-cap` prints all of it; `--bytes N` is a hex preview of the first N bytes, capped like text.
`--lines`, `--grep` and `--bytes` are mutually exclusive (exit 2).
`--map DIR` (an existing directory holding PATH, else exit 2) / `--no-map` / `--agent NAME` control the
shared map; without
`--map` the challenge dir is the nearest folder above PATH holding `challenge.json` or `recon/`, and
when there is none the read is not recorded and stderr says so. A line count ignores the empty piece a
final newline leaves. A read of content already read prints a note first: by another agent (naming it,
and the other path when the same bytes were read elsewhere), or by this agent (`you (NAME) already
read ...`). Refused with exit 4 before the file is opened: a symbolic link (never followed); a path that
is or resolves into `sweep.SECRET_DIRS` (`.ctf/`, `.git/`); a `.env` / `.env.*` file (`sweep._secret_file`)
outside a pulled challenge's `files/` (the platform's download there is challenge data, as in the sweep);
and any path the read fence denies (`fence.read_fence`: the same rules as `fence.build`, including the
notification-database rule and `$CTF_EVENT`'s `fence.toml` `deny_read` and `strict_home`, with its drop
folder, `allow_read` and the event workspace winning where more specific). Names and paths are compared
case-folded (the default macOS volume is case-insensitive: `.CTF/`, `~/.CODEX/` are refused). Exit codes: 0 ok; 1 refused a whole-file/large window, or a line/symbol read of a binary (re-run with
`--full`/`--grep`/`--strings`/`--bytes`; B-199); 2 error (no such file, unreadable, a bad `--lines`/`--grep`/`--bytes`/
`--map`, a range starting past the end, a map that cannot be read or written: nothing is printed to
stdout, re-run with `--no-map`; a bad fence config); 4 refused a secret-bearing or fence-denied path.

### B-199: repo primer, symbol index, research cache and binary-first read

The module docstrings of `ctf/primer.py`, `ctf/symindex.py`, `ctf/research.py` and `ctf/binsummary.py`
are the source of truth; change them and this section together. Nothing here fetches, imports or runs
what it reads.

**Primer.** `docs/PRIMER.md` (the brief: start here, the reading rules, layout, ctf packages, solver
lanes, the largest files) and `docs/FILE-INDEX.md` (every command with its HELP, every ctf and tools
module with its docstring's first sentence, the lanes, every module of 2000+ lines) are generated from
the tree. They are in `ctf.engines.derived.DERIVED`, so `python -m ctf engines generate` (which the
merge queue runs) regenerates them and `--check` fails when either is stale; `tests/test_primer.py`
checks the committed files (a `tests/gate.toml` scan rule selects it for any `ctf/`, `tools/` or
`solvers/` change). Never hand-edit or hand-merge them: regenerate. `primer.rules_md()` is the one
source of the reading rules: the event template inserts it as `{{repo_reading_rules}}`
(`ctf.eventrules`), so a change to it makes every event's CLAUDE.md / AGENTS.md stale until
`new-event --regen`.

```python
from ctf import primer
primer.PRIMER_REL; primer.INDEX_REL; primer.LARGE_LINES; primer.HUGE_LINES   # paths; 2000; 4000
primer.render_primer(root=None) -> str; primer.render_index(root=None) -> str
primer.write(root=None) -> [Path]; primer.stale_files(root=None) -> [rel]; primer.is_stale(root=None)
primer.write_primer / write_index / primer_stale / index_stale (root=None)   # the DERIVED entries
primer.repo_files(root=None) -> frozenset[rel]       # in a checkout: impact.list_files (GateError if git fails)
primer.commands(root, *, files=None) -> (builtins, [(command, HELP)])
primer.modules(root, top="ctf", *, files=None) -> [(rel, summary)]
primer.large_files(root, *, min_lines=LARGE_LINES, files=None) -> [(rel, "~Nk")]; primer.rules_md() -> str
```

In a git checkout (`root/.git` exists) the tree is the gate's file list (tracked plus
untracked-not-ignored), so a gitignored scratch module does not change the generated files; git failing
there raises `GateError` (`ctf primer --write` exits 2). A tree with no `.git` (an exported copy, a
synthetic test tree) has no ignore rules, so every file counts.

**Research keys** keep word order (stop words dropped): "convert hex to base64" and "convert base64 to
hex" are different keys. A `get` hit prints the stored `asked:` text under its header line.

**Symbol index** (`ctf.symindex`). Built on the gate's graph (`ctf.gate.impact.Graph`: the same `ast`
parse, import resolution and file list) and cached per file by content hash in
`<state>/symbols.json` (`ctf.gate.inventory.Inventory`, version `symbols-1`), beside the gate's
`deps.json`/`hashes.json` in `paths.gate_state()`. A symbol is a top-level def/async def/class, a
method or nested class of a class (never the inside of a function) or a module-level UPPER_CASE
constant; its range starts at its first decorator.

```python
from ctf import symindex
symindex.parse_symbols(text) -> {"symbols": [[kind, name, start, end, signature, doc]], "error": str}
symindex.symbols_of(text) -> [symindex.Symbol]        # SymbolError when it does not parse
symindex.lookup(symbols, name) -> [Symbol]            # exact qualname, else dotted suffix / last part
symindex.format_symbol(sym, indent=True) -> str
idx = symindex.SymbolIndex(root, state_dir, cfg=None, files=None)   # cfg: tests/gate.toml; files: git
idx.resolve(target, cwd=None) -> rel                  # path or dotted module; SymbolError if none/ambiguous
idx.symbols(rel); idx.imports(rel); idx.importers(rel); idx.find(name) -> [(rel, Symbol)]
idx.outline(rel, users=True, max_list=12) -> str; idx.stats   # Stats(total, computed, reused, ...)
```

**`ctf read` additions.** `--symbol NAME` reads exactly one definition (`symindex.lookup`; ambiguous
or unknown is exit 2 naming the candidates); it is a targeted read (never refused as a large window,
still capped) and is recorded in the shared map as `lines:A-B`. A binary read with no selection prints
the `binsummary` summary (exit 0, selector `summary`); `--lines`/`--symbol` on a binary is exit 1.
`--strings [MIN]` (default 4) lists every string with its offset (selector `strings:MIN`).

```python
from ctf import binsummary
s = binsummary.summarize(name, data)   # BinarySummary(name, size, sha256, entropy, labels, problems,
                                       #   head, strings, strings_total, scanned); s.render()
binsummary.identify(name, data) -> (labels, problems)   # ctf.formats.identify sure matches + magic table
binsummary.strings(data, min_len=4, limit=None) -> [(offset, "ascii"|"utf16le", text)]
binsummary.hexdump(data, n); binsummary.entropy(data)   # bits/byte over ENTROPY_BYTES
binsummary.SCAN_BYTES; binsummary.SUMMARY_STRINGS; binsummary.MIN_STRING; binsummary.HEAD_BYTES
```

**Research cache** (`ctf.research`). `<workdir>/research/<sha256(key)[:32]>.json` (schema 1) per
answer, `.claim` beside it while an agent looks it up (every claim change is made under an exclusive
`fcntl.flock` on `.lock` beside it, so exactly one agent wins a fresh claim or the take-over of a stale
one; stale after `CLAIM_TTL` 900 s). Keys: `url:host/path?sorted-query` (http/https and `www.` folded,
default port, fragment and tracking parameters dropped) or `q:<words in order, stop words dropped>`. A
URL with credentials or a secret-looking parameter is a `ResearchError`, as is an empty answer, one
over `MAX_ANSWER_BYTES` (64 KiB), a second `put` without `replace`, or an unreadable entry.

```python
from ctf import research
research.normalize(text) -> key; research.normalize_url(url); research.normalize_query(q)
c = research.Cache(root, clock=time.time); research.default_root()   # <workdir>/research
c.get(text) -> Entry | None; c.put(text, answer, sources=(), agent=..., replace=False) -> Entry
c.claim(text, agent=...) -> Claim     # research.ClaimHeld(claim) when another agent holds a fresh one
c.release(text, agent=...) -> bool; c.holder(text) -> Claim | None; c.entries() -> [Entry], newest first
c.lookup(text, agent=..., claim=False) -> Lookup(status="hit"|"claimed"|"held"|"miss", key, entry, claim)
```

---

## 35. Look-ahead completeness gate (B-174)

The pre-release look-ahead as a release gate: green only when the forecast's stated deterministic work
is covered. The module docstrings of `ctf/lookahead/matrix.py`, `ctf/lookahead/gate.py`,
`ctf/lookahead/computed.py`, `ctf/lookahead/scale.py` and `ctf/lookahead/forecast.py` are the source
of truth; change them and this section together. Nothing in `ctf.lookahead` talks to a platform or
starts a model. It builds on B-036 (`adapt.qdiff`, section 29) and B-010 (`idresolve`, section 21).

```python
from ctf.lookahead import LookaheadError, matrix, gate, computed, scale, forecast
m = matrix.load(matrix_dir)                      # Matrix(path, lanes, specimens, skipped, waivers)
matrix.load_specimen(lane, specimen_dir) -> Specimen
matrix.determinism(question, judged=()) -> "deterministic" | "judged"
matrix.decode_chain(chain, data) -> bytes        # EncodingMismatch names the layer that does not hold
matrix.bad_encodings(specimen) -> [(member, why)]
matrix.read_questions(path); matrix.questions_in(body, where); matrix.qid_of(q); matrix.bare_id(qid)
matrix.check_chain(chain, where)
reports = gate.gate(matrix_dir, lanes=None, root=None, workdir=None, guard="auto", timeout=None,
                    record_to_ledger=True)       # [LaneReport], one lookahead.gate record each
runs = gate.run_lane(m, lane, root=None, guard="auto", timeout=None, workdir=None)  # {name: SpecimenRun}
rep = gate.evaluate(m, lane, runs, seconds=0.0)  # LaneReport(lane, gaps, rows, runs, seconds)
rep.ok; rep.verdict; rep.counts(); rep.headline(); rep.lines(); rep.to_json()
gate.classify(question, answer, key) -> (status, why)
gate.record(rep, workdir=None); gate.child_command(root, g, job, out)
computed.answer(question, files); computed.fill(questions, files, answers) -> (answers, filled_ids)
computed.wrap(solve_set)                         # a lane's solve_set with the tier behind it
scale.scan(paths, root=None) -> [Found]; scale.undeclared(found, m) -> [Found]
scale.replicate(specimen_dir, out_dir, min_total_bytes) -> Path
fc = forecast.load(path)                         # Forecast(day, lanes: {lane: LaneForecast(new, gaps, note)})
forecast.score(fc, lane, previous, actual, report=None, workdir=None, record=True) -> Score
forecast.new_shape(previous, actual) -> ids
forecast.plan(reports, shapes) -> [LanePlan]     # shapes: {lane: (previous, base) bodies, or None}
```

- **Matrix.** `<matrix>/matrix.toml` (`[lane.<lane>]`: `reader` (required; a module with
  `solve_set(questions, files, ctx)`), `judged`, `base`, `previous`, `timeout`, `real_encodings`,
  `allow_unsure` (bool, default false), `[[lane.<lane>.threshold]]` `name`/`bytes`/`measure` (`total` | `member`); `[[skipped]]`
  `lane`/`name`/`reason`/`ids`; `[[waived_threshold]]` `bytes`/`reason`/`where`) and one folder per
  specimen under `<lane>/`: `specimen.toml` (`encoding`, `[encodings]`, `skip`, `note`, `[ctx]`),
  `questions.json`, optional `key.json`, `files/`. Unknown keys, a key id no question asks, an id asked
  twice, a specimen with no member, a symlinked member and an undeclared lane folder are LookaheadError.
  Matrices are challenge-shaped data: they stay out of the repo unless synthetic.
- **Determinism.** Every question is deterministic unless it says `"determinism": "judged"` or its id
  (a leading `setN.` dropped) matches a lane `judged` glob. No kind-based guess.
- **Encodings.** Each member's chain (`CODECS`: `raw`, `base64`, `base64url`, `base32`, `hex`, `zlib`,
  `gzip`, `bz2`, `xz`, `utf-16le`, `reverse`; outermost first) is decoded strictly (only line breaks
  are dropped from text layers; a stream must end with nothing after it); a layer that does not hold
  is a `bad_encoding` gap.
- **Running.** One child per lane (`python -I ctf/intake/_guardboot.py --mode M -- ctf/engines/_boot.py
  ... -m ctf.lookahead._child`): the intake network guard (section 19), `openers.engine_env` (no
  secret-named variable, `CTF_ENGINE_LEDGER=0`, a fresh workdir), run folders in a temporary folder
  inside the workdir; each specimen under the lane's cap (SIGALRM), the child under cap x specimens +
  `CHILD_SLACK`. A reader that does not load is LookaheadError. A specimen without a result is
  `crashed` (the first) or `skipped` (not reached).
- **Gate.** Statuses `correct`, `answered`, `wrong`, `unsure`, `unanswered`, `skipped`. Gap kinds
  (`GAP_KINDS`): `wrong`, `unanswered` (deterministic only), `unsure` (a deterministic id answered
  unsure: never sent, so not answered at release; not a gap for a judged id or under the lane's
  `allow_unsure = true`), `skipped`, `crashed`, `cut`,
  `bad_encoding`, `uncovered` (a newest-base id no specimen that ran asks), `threshold` (no specimen
  that ran on one side), `unexercised_encoding`, `empty`. Any gap: `red`; none: `green`. The literal
  `none` is wrong unless `idresolve.permits_literal_none` allows it or the key is none; an unsure
  answer (`??` + JSON: the labels encoding `{"k": key, "o": [[name, value], ...]}`, or the long field
  names `key`/`options`, B-249) is wrong when none of its options is the key.
- **Mobile specimens (B-249).** `ctf.lookahead.mobile_specimens.write(dest, controls=False,
  allow_unsure=True, only=None) -> Path` writes a synthetic mobile-android matrix (reader
  `solvers/mobile-android/codec_search.py`; specimens `thumb_jni`, a Thumb armeabi-v7a JNI `analysis`
  chain, and `hermes_bundle`, a Hermes string table; `controls` adds `thumb_gate_fail`, which must come
  back unanswered) plus a `forecast.toml`. The Thumb specimens need the native emulator, which the
  audit-hook guard refuses (ctypes): under that guard alone their id is an `unanswered` gap.
- **Computed tier.** Templates `count`, `size`, `digest`, `digests` (`TEMPLATES`), matched on the
  whole question text, with kind checks; ambiguous member names and upper-case or `0x` spellings are
  not answered. `fill` fills only empty ids (None, missing, or blank text, as `classify` counts
  unanswered) and never overrides. The gate shows the tier's value on an unanswered deterministic id
  but keeps the gap until the lane's own reader answers (`computed.wrap`).
- **Scale.** `scan` reports module-level size constants (MAX/LIMIT/CAP/THRESHOLD/CUTOFF/BYTES/SIZE,
  >= `MIN_BYTES`) and `len()` comparisons; a file that does not parse is LookaheadError. `replicate`
  makes `set<n>/` members and `set<n>.` ids, at least two sets, past the size.
- **Forecast.** `score`: new shape = the attention changes of `adapt.qdiff` (removed ids not
  counted); `hit`/`missed`/`unused`/`recall`; with a report, `gap_missed` = its wrong, unanswered,
  unsure and uncovered ids no `gaps` glob names. `plan`: an agent for a lane with a gap, a new shape, an unknown
  shape or no report; none for a green lane with an unchanged shape.

### The daily look-ahead workflow (B-256)

For a rolling-release event (`allowance.daily_release` set, or two or more `allowance.releases`; any
other event is refused). The module docstrings of `ctf/lookahead/daily.py`, `ctf/lookahead/tagged.py`
and `ctf/lookahead/fixtures.py`, and `workflows/day-lookahead.js`, are the source of truth.

```python
from ctf.lookahead import daily, tagged, fixtures
daily.profile_lanes(profile) -> tuple[str]       # slugs of the event's categories ("Script Analysis" ->
                                                 # script-analysis; NOT the canonical dispatch category)
daily.require_rolling(profile)                   # LookaheadError unless the event releases more than once
daily.plan_day(profile, matrix_dir, reports)     # [LanePlan] over exactly the profile lanes (forecast.plan);
                                                 # a matrix or report lane outside the profile is an error
daily.plan_doc(profile, plans, day=, matrix_dir=, staged=) -> dict   # plan.json
daily.workflow_args(profile, doc, repo=, out=, agent_cap=None) -> dict   # agent lanes only; none: error
daily.finish(doc, result, out_dir, previous_forecast=None) -> FinishReport   # README.md + forecast.toml
tagged.render(family, container, tag, seed) -> Rendered    # FAMILIES x CONTAINERS (NOT_APPLICABLE)
tagged.stage(matrix_dir, lane, tag, seed=, families=, containers=, question_id="tagged_copy") -> [name]
fixtures.encode_chain(chain, plain) -> bytes     # matrix.decode_chain(chain, result) == plain
fixtures.stage_computed(matrix_dir, lane, seed=, chains=None) -> [name]   # default: the lane's real_encodings
```

- **Workflow.** `workflows/day-lookahead.js` (+ `.wf.toml`, section 50): required `event`, `repo`,
  `out`, `day`, `matrix`, `lanes` (`[{key, reasons, staged}]`, the plan's agent lanes); one schema-forced
  predictor per lane; a predictor that throws, returns null or answers for another lane is re-run once
  with a reworded brief; a lane that fails twice is in `notStaged` and logged `<lane>: NOT staged`.
  Hard cap 16, `stages_per_lane = 2` (the re-run counted), no extra agents. Returns `{day, staged,
  notStaged, planned, cap}`.
- **Staging (no model).** Specimens `tagged-<family>-<container>` and `computed-<chain>` under the
  matrix lane; a folder of that name the step did not stage is refused, its own are rewritten. The tag
  is the event's (no default).
- **finish.** Every agent lane the result does not carry as staged is NOT staged, whatever the
  workflow's own list says; a result lane the plan gave no agent, or staged twice, is an error. The
  README counts lanes and never says "all"; blank globs are dropped and named; `forecast.toml` is
  re-read by `forecast.load`; with no lane staged it is not written (a stale one is removed).

---

## 36. Campaign state and scratch (B-178)

```python
from ctf.campaign import Campaign
c = Campaign()                                   # <workdir>/campaign/, event label optional
c.add_goal(gid, title, challenge=, lane=, next_step=)
c.checkpoint(gid, note, next_step=)              # open -> active; done/dropped refuse
c.set_goal_status(gid, status, blocker=)         # open | active | blocked (needs blocker) | done | dropped
c.launch(aid, argv, harness=, challenge=, goal=, prompt_file=)   # detached supervisor, fenced launchers only
c.register(aid, harness); c.heartbeat(aid); c.finish(aid, "done" | "failed")
c.reconcile() -> [newly lost ids]; c.relaunch_list(); c.relaunch(aid)
c.alive(agent_record) -> (bool, why_not)         # the liveness rule reconcile uses; read-only
c.end_session(summary, profile=)                 # refuses while a live goal has no next step
c.check() -> [problems]                          # stale RESUME.md, missing next steps, lost agents;
                                                 # [] for a workdir with no state.json yet (and it
                                                 # creates nothing there, not even campaign/)
c.refresh_resume() -> Path                       # rebuild RESUME.md from state.json, under the state flock
from ctf import scratch
scratch.open_pass(chal_dir, purpose) -> Path; scratch.close_pass(p, status); scratch.passes(chal_dir)
```

- `<workdir>/campaign/state.json` (`{"schema": 1, "rev", "goals", "agents", "sessions"}`) is replaced
  atomically under an flock; `state.json.prev` is the last good copy. A corrupt or missing state
  beside a `.prev` raises `CampaignError` naming `ctf campaign recover`; nothing is guessed.
- `<workdir>/RESUME.md` is regenerated from state on every change and carries
  `<!-- ctf-campaign-resume rev=N -->`; never hand-written. Briefs go to `<workdir>/briefs/`.
  A writer replaces `state.json` and then `RESUME.md` under the state flock, `ctf campaign resume`
  included (`refresh_resume()`); `check()` reads the pair under the same flock, so it never reports a
  resume that a writer is about to bring current and never compares the two from either side of a
  write. `write_resume(st)` itself takes no lock: call it only inside the flock that read `st`. Do not
  call `check()` or `refresh_resume()` while holding the state lock (a second flock on the same file
  would wait on itself).
- A launch waits `campaign.SUPERVISOR_START_WAIT` seconds (60) for its supervisor to detach, then
  records the agent failed ("supervisor did not start").
- A supervised agent is alive while `campaign/agents/<id>.lock` is flock-held. Relaunch skips closed
  goals, registered agents, the launch cap and challenges with an active budget stop (`budget.is_stopped`)
  or at their cap (`LedgerMeter.status`, needs the event profile; no profile is itself the reason).
  `launch` with a challenge refuses the same way, and every launch with a challenge sets
  `CTF_CHALLENGE` for the agent, so `tools/claude_launch` / `tools/codex_launch` gate and meter it
  (R-09); their own `--challenge` must match the campaign's.
- Ledger events: `campaign.lost {agents}`, `campaign.relaunch {agent, launch, challenge_id}`,
  `campaign.end {rev}`.
- Scratch lives in `<challenge folder>/.scratch/NNN-<purpose>/` with `MANIFEST.json`; nothing deletes
  outside `.scratch`, an open pass, or a folder without a manifest. Details: `docs/campaign.md`.

---

## 37. Pinned toolchain: images, assets, lane env-check, version notes, wheelhouse (B-188)

One package, `ctf/toolchain/`, five modules; the CLI is `python -m ctf toolchain` (section 8); the doctor
runs `assets` and `images` (section 16). Docker is only ever started through an injected `run`, and under
`CTF_TESTING` (in the environ handed in or in the process) only a docker carrying `images.STUB_MARKER`
(`ctf-docker-stub`) in its first `images.STUB_MARKER_WINDOW` bytes runs; anything else is `ImagesError`
before a call is made. Build work never builds, pulls or runs a real image.

```python
from ctf.toolchain import images, assets, lanes, versions, wheels
imgs = images.load(path=None)                 # [Image] from tools/images.toml; images.parse(data, src) for a decoded mapping
images.manifest_path(root=None); images.select(imgs, only)
findings = images.lint(imgs, root=None)       # [Finding(image, path, line, rule, text)]; rules: images.RULES
images.lint_dockerfile(image, text, context=None, staged=())   # one Dockerfile's text
images.parse_dockerfile(text)                 # [Instruction(line, op, text)]: continuations joined, heredocs appended
images.errors(findings, imgs)                 # the fatal ones: findings of `pinned = true` images
images.requirement_pins(root=None); images.normalise(name)
images.staged_files(image, root=None)         # {toolchain-requirements.txt, toolchain-constraints.txt: text} from requirements.in
images.content_hash(image, root=None)         # sha256 of context_files, staged pins, build args, platform, tag
images.context_files(image, root=None)        # the files Docker is sent: the context minus its .dockerignore (sorted)
images.dockerignore_rules(ctx); images.dockerignored(rel, rules)   # Docker's .dockerignore reading (last match wins, `!` re-includes)
images.docker_path(environ=None)              # the docker on PATH or None (stub-only under CTF_TESTING)
report = images.status(imgs, root=None, environ=None, run=subprocess.run)
# [ImageStatus(name, tag, role, state, detail, fix, want, have)]; state: ok | missing | stale | unlabelled | unknown
images.problems(report, core_only=False)
steps = images.plan_build(imgs, report=None, root=None, force=False)   # [BuildStep(image, tag, action build|skip|refused, reason, argv)]
images.apply_build(steps, imgs, root=None, environ=None, run=subprocess.run)   # [BuildResult(step, returncode, output, reason)]
images.stage(image, dest, root=None)          # copy of context_files + staged pin files (the checkout is never written)
images.smoke(image, environ=None, run=subprocess.run, timeout=images.SMOKE_TIMEOUT)   # [SmokeResult(image, argv, returncode, output)]
images.run_argv(image, cmd, workdir=None)     # docker run --rm --network none --pull=never --cap-drop ALL ...
# images.Image(name, tag, dockerfile, context, role, platform, args, py, downloads, smoke, versions, default_for,
#              managed, built_by, pinned, unpinned_reason, provides); images.Download(name, url, sha256, arg)

items = assets.load(path=None)                # [Asset] from tools/assets.toml; assets.parse(data, src); assets.manifest_path(root=None)
rep = assets.resolve(items, environ=None, run=subprocess.run, only=None)
# [AssetStatus(name, role, state ok | missing | broken, path, source env:VAR | candidate, detail, fix)]
assets.select(items, only); assets.expand(candidate, environ=None); assets.problems(rep, core_only=False)
assets.exports(items, rep)                    # {VAR: path} for every ok asset, under each export name
assets.render_env(values, path_prepend=())    # POSIX `export` lines

r = lanes.check(lane, root=None, python=None, environ=None, run=subprocess.run, specs=None, pins=True, asset_items=None)
# EnvReport(lane, python, items, image): .passed, .problems(), .to_dict(); Item(kind module|bin|asset|pins|source, name, required, ok, detail, fix)
lanes.scan_imports(files, root=None)          # ({module: ImportUse(module, required_by, optional_by)}, [unparseable files])
lanes.find_modules(names, python, environ=None, run=subprocess.run)   # {name: bool} via `<python> -I` find_spec
lanes.engine_files(lane, root=None); lanes.lane_engines(lane, root=None); lanes.known_lanes(root=None)
lanes.load_specs(path=None); lanes.parse_specs(data, src); lanes.specs_path(root=None)   # tools/lanes.toml -> {lane: LaneSpec}
values, prepend = lanes.exports(root=None, python=None, environ=None, run=subprocess.run, asset_items=None)

sc = versions.scan(folder, max_files=versions.MAX_FILES)   # Scan(notes, files, skipped, truncated)
versions.scan_text(text, path); versions.scan_binary(data, path)   # [VersionNote(tool, version, path, line, text)]
picks = versions.pick(notes, imgs)            # [Pick(tool, status ok|default|missing|conflict, image, tag, wanted, reason)]
versions.py_mismatches(notes, version_of=versions.installed_version); versions.installed_version(name)

w = wheels.check(directory=None, requirements=None)   # WheelReport(directory, requirements, pins, present, missing, other_version)
wheels.plan(directory=None, requirements=None, python=None)   # [fill argv (network: human), offline install argv]
wheels.dist_of(filename); wheels.parse_pins(text); wheels.normalise(name); wheels.requirements_path(root=None)
# errors: images.ImagesError, assets.AssetsError, lanes.LaneError, wheels.WheelsError (all ValueError)
```

- **Images** (`tools/images.toml`, keys in its header; an unknown key is an error). `managed = false`
  images (the csctf sandbox, pwn and analysis images) are built by another tool (`built_by`) and only
  checked for presence; `pinned = false` images (the carried pwn/analysis ones) report lint findings
  without failing. A pinned image fails `lint` on any rule. An image's `py` names take their versions from
  requirements.in at build time (one source of versions); a `[[image.download]]` with an empty `sha256` is
  *unlocked*: `plan_build` refuses it and prints the hash command (a human records it). `plan_build`
  also runs `lint` and refuses a pinned image with any finding, so `build --apply` never builds and
  labels an image that `lint` fails. `apply_build`
  stamps `images.LABEL` (`org.ctf-tools.toolchain.hash`) with `content_hash`, and `status` compares it,
  so an image built from the current files is never rebuilt. The hash and the staged copy cover the
  same files, `context_files` (the context minus what its `.dockerignore` lists; `docker/toolkit` and
  `docker/sage` ignore OS and editor files, so a stray `.DS_Store` never marks an image stale). Sage comes as one image per tag
  (`ctf-sage:10.5`, `ctf-sage:10.7`), each `versions = { sage = ... }`, one `default_for = ["sage"]`.
- **Assets** (`tools/assets.toml`): an override variable that is set but names nothing usable is
  `broken`; it never falls through to a candidate. `{toolbox}` is `paths.toolbox_dir()`. `rockyou`
  exports `ROCKYOU` (what `hashcrack.find_rockyou` reads first); `john-share` probes
  `perl -MCompress::Raw::Lzma` (7z2john.pl's module); `ghidra` exports `GHIDRA_INSTALL_DIR`.
  `schema-bundle` (optional, B-159) is the folder of licensed protocol schemas
  (`$CTF_ASSET_SCHEMAS`, else `{toolbox}/schemas`), one sub-folder per family; only
  `solvers/toolkits/schema_bundle.py` reads it (`schema_bundle.bundle_root()`, `BundleMissing` when it
  does not resolve, `SchemaMissing` naming the family, the file and its source when a family is
  absent). No schema is committed to the repo: `docs/toolkits/schema_bundle.md` records, per family,
  where it comes from and whether it may be redistributed.
  `whisper-ggml` (a whisper.cpp model file) and `whisper-ct2` (a CTranslate2 Whisper model folder) are
  the optional local speech-to-text models of `solvers/toolkits/audio_speech.py` (B-087), which resolves
  them at run time: a human places them under `{toolbox}/whisper/`, nothing in the repo downloads one,
  and the engine refuses a model path inside the checkout.
- **Lanes**: the master has one venv (R-14); a lane's env-check reads its engines' imports (top of module,
  reached only through top-of-module imports = required) plus `tools/lanes.toml` (`modules`, `bins`,
  `assets` required; `image` informational) and runs `tools/venv_pins.py` with the lane's interpreter.
- **Versions**: files are only read (no symlink followed, only regular files opened: a FIFO, socket or
  device is skipped and listed, never read; text up to `versions.MAX_TEXT_BYTES`, binaries
  up to `versions.MAX_BINARY_BYTES` for `versions.BINARY_PATTERNS` only, at most `versions.MAX_FILES`).
  Archives are not opened: sweep first. `pick` groups the noted versions by the image that serves
  them (10.5 and 10.5.1 both run in the 10.5 image: `ok`); `conflict` only when no one image serves
  them all. A note of 10.50 never picks the 10.5 image.
- **Wheels**: the pins of `requirements.txt` against `<name>-<version>` wheels/sdists in
  `paths.wheelhouse_dir()`; a missing folder is `WheelsError`, never an empty pass.

---

## 38. Ask every reader before STOP on a MISSING id (B-139)

The pass between a lane's bank-only pass and its STOP: for each id the bank left MISSING (None or
absent; an unsure `??` answer is not MISSING), ask every registered reader and field catalog for that
one field, and offer what they say as an unsure answer when it is exactly one fact. The module docstring
of `ctf/askreaders.py` is the source of truth; change it and this section together. Nothing in it sends
an answer except `probe`, and only through the `submit` it is given.

```python
from ctf import askreaders
regs = askreaders.load_registry(path=None, root=None) -> list[Reader]  # openers/readers.toml; AskError names a bad entry
askreaders.readers_for(lane, readers=None, root=None, workdir=None, live=True) -> list[Reader]
                                       # the lane's own readers, then lanes = ["*"], then <workdir>/ask-readers/<lane>/*.py
askreaders.live_readers(lane, workdir=None) -> list[Reader]            # kind "live", call solve_set, loaded fresh
askreaders.missing_ids(questions, answers) -> list[str]
askreaders.field_of(qid) -> str                                        # no setN., idresolve.canon
a = askreaders.ask_one(question, files, readers, lane, ctx=None, budget=None) -> Asked
rep = askreaders.ask_missing(questions, answers, files, lane, readers=None, ctx=None, root=None, workdir=None,
                             budget=None) -> AskReport                 # rep.answers: the bank plus each offer
solver = askreaders.AskingSolver(lane_solve_set, lane, readers=None, root=None, workdir=None, budget=None)
solver.solve_set(questions, files, ctx)    # ctx["ask_readers"] = rep.to_json(); offers go into ctx["partial"]
probes = askreaders.probe(rep, submit, max_per_id=askreaders.MAX_OPTIONS, on_verdict=None, stop=None) -> list[Probe]
                                           # stop() read before each send; once true the rest is not_probed, "yielded the lane"
submit = askreaders.gate_submit(gate, challenge_id, provenance)        # gate.submit("<cid>#<answer id>", v, allow_nonstandard=True)
askreaders.template_text(lane, qid, asked=None, root=None) -> str
askreaders.write_template(lane, qid, asked=None, workdir=None, out=None, root=None, force=False) -> Path
askreaders.labels_module()                 # solvers/common/labels.py, as the lanes import it
Reader(name, lanes, module, call, function, kind, needs_tools, note, path).asks(lane)
ReaderAnswer(reader, status, member, key, options, candidates, why, said, seconds).values() / .line() / .to_dict()
Fact(values, answers).to_dict()
Asked(qid, answer_id, field, outcome, answers, facts, offer, key, reason).line() / .to_dict()
AskReport(lane, asked, answers, readers).offers() / .stops() / .ok / .lines() / .to_json()
Probe(qid, answer_id, key, name, value, status, message).line() / .to_dict()   # accepted | rejected | held | not_probed
askreaders.OFFER | NO_READER | CONFLICT | REJECTED; askreaders.CALLS; askreaders.KINDS; askreaders.AskError
askreaders.REGISTRY; askreaders.LIVE_DIR; askreaders.TEMPLATE; askreaders.SAID_MAX; askreaders.TEMPLATE_SAID_LINES
```

- **Registry** (`openers/readers.toml`, schema in its header; unknown keys, a duplicate name, an unknown
  `call` or `kind`, a module file that is not there are AskError). `call` is `solve_set`
  (`fn(questions, files, ctx)`), `fields` (`fn(member name, bytes, questions)`, once per delivered bytes
  member) or `apk` (`fn(questions, package members, package bytes)`, once per delivered zip holding
  `classes.dex` or `AndroidManifest.xml`, at most `APK_MAX_BYTES` uncompressed). Registered now:
  `binary.field_catalog`, `metadata.properties_strict`, `mobile.apk_facts`.
- **Asking.** Each reader gets the one question alone, a ctx copy without `partial`, in process, stdout
  and stderr captured (`said`, head and tail, `SAID_MAX`). The capture swaps the process-wide
  sys.stdout/stderr, so readers run one at a time under one module lock: concurrent asks from several
  threads are serialised, and output another thread prints while a reader runs lands in that reader's
  `said`. A running reader is never killed (`budget` skips only readers not yet started); a hung reader
  holds its lane. Status `answered`, `none`, `error` (raised,
  or not a dict), `unavailable` (missing `needs_tools`, a module that does not load, no such
  function) or `skipped` (the `budget` was spent): every one is named in the report, never dropped.
- **One fact.** An answer's values are its options (an unsure answer: spellings of one fact) or its one
  plain value; a labels candidates answer gives one fact per option. Answers whose value sets meet are
  one fact. Outcomes: `offer` (one fact: `labels.unsure` under the first keyed answer's key, else
  `<lane>.ask/<field>`, one option per value in reader order, plain values named after their reader,
  at most `MAX_OPTIONS`, names already rejected for the key dropped; never plain), `no_reader`,
  `conflict` (two or more facts; nothing is guessed), `rejected` (every option already rejected). A
  literal `none` counts only where `idresolve.permits_literal_none` allows it.
- **Probing.** One option per request in offer order; accepted closes the id, incorrect tries the next,
  an unjudged result (`SubmitStatus.judged` false) holds every probe left. `on_verdict(key, name,
  "accepted"|"rejected")` per judged option (the CLI passes `labels.learn`, `src="ask-readers"`).
- **Agent case.** `write_template` renders `templates/ask-readers/one_field.py` (placeholders
  `"__FIELD_ID__"`, `"__LANE__"`, `# __CANDIDATES__`; inert as shipped) with every reader's answer and
  the first `TEMPLATE_SAID_LINES` lines of its own output as comments, each one physical line (line
  breaks, other control characters and lone surrogates escaped: the values come from challenge files and
  the next ask runs the file), into `<workdir>/ask-readers/<lane>/field_<id>.py`
  (an existing file is AskError unless `force`). The agent fills `read()`; the next ask finds the file as
  a live reader and its answer is offered like any other.

---

## 39. Brief-not-fork spawning and the per-challenge agent gate (B-143)

Codex forks inherit the parent's whole context (the prefix above a 20K brief cost about $2,617 at base
rates; 457 of 468 CSCTF parent spawns used `fork_turns: "all"`; 57 spawns failed when forked children
tried to spawn too), and agents past the 5th on one challenge cost at least $1,174 (tokens/waste.md
section 3.7, tokens/EFFICIENCY-PLAN.md section 3.13). `ctf.spawn` is the gate every new agent on a
challenge goes through. The full contract is the module docstring of `ctf/spawn.py`; change it there
and here together.

```python
sp = spawn.Spawner(workdir=None, profile=None, meter=None, cap=AGENT_CAP, brief_max_tok=BRIEF_MAX_TOK,
                   fork_max_tok=FORK_MAX_TOK, on_hold=None, clock=time.time)
sp.request(cid, role="auto", mode="brief", reason=None, parent_tok=None, fork_turns=None, lane=None,
           task=None, evidence=(), harness=None, model=None, stop_minutes=STOP_MINUTES, replaces=None,
           escalation_ts=None, check_budget=True) -> Decision      # admitted | held | refused
sp.peek(cid, role="auto", mode="brief", reason=None, parent_tok=None, fork_turns=None, replaces=None)
sp.preview(cid, lane=None, task=None, evidence=(), stop_minutes=STOP_MINUTES) -> str   # writes nothing
sp.lookup(spawn_id, cid) -> Decision; sp.bind(spawn_id, cid, harness=) -> Decision   # $CTF_SPAWN_ID
sp.allow(cid, agents, by=, reason=) -> int; sp.end(spawn_id, reason=None) -> dict
sp.release(spawn_id, cid, bound=, reason=) -> dict   # a launch that never started: spawn_void / spawn_unbound
sp.view(cid) -> ChallengeView; sp.board(ids=None) -> list[ChallengeView]; sp.from_escalations(harness=None)
spawn.build_brief(cid, spawn_id=, role=, lane=None, task=None, claim=None, evidence=(), tried=(),
                  stop_minutes=STOP_MINUTES, spawn_tool=False, max_tok=BRIEF_MAX_TOK) -> str
spawn.tried_so_far(records, cid, exclude_spawn=None) -> list[str]; spawn.evidence_paths(workdir, cid, extra=())
spawn.read_views(records, cap=AGENT_CAP) -> {challenge_key: ChallengeView}
spawn.record_result(cid, lane, status, summary, spawn_id=None, paths=(), workdir=None) -> dict
spawn.results(cid, workdir=None) -> list[dict]
spawn.estimate_tok(text) -> int; spawn.one_line(text, limit=300) -> str; spawn.spawn_id_from_env()
spawn.no_spawn_args(harness) -> list[str]   # codex: --disable multi_agent; claude: --disallowedTools=Agent,Task
# Decision(challenge_id, status, role, mode, reason, detail, spawn_id, agents, cap, first_input_tok,
#          fork_turns, spawn_tool, brief_path, checkpoint); .admitted; .to_fields()
# ChallengeView(challenge_id, cap, spawns, legacy_launches, held, allows, results, voided); .agents .owner .waiting
# spawn.AGENT_CAP (5), BRIEF_MAX_TOK, FORK_MAX_TOK, BYTES_PER_TOK, STOP_MINUTES, ROLES, ROLE_AUTO, MODES,
# STATUSES, RESULT_STATUSES, REFUSALS, ENDING_EVENTS, CODEX_NO_SPAWN_ARGS, CLAUDE_NO_SPAWN_ARGS, SpawnError
```

The rules, decided under one lock (`<workdir>/spawn/.lock`) so two processes never both take the last
seat; ids keyed with `challenge_key` (a part `9#a` counts toward `9`):

- **Budget first.** `request` calls the B-033 meter's `check()` (section 10): a stopped or capped
  challenge is refused (`stopped`, `at_cap`). The launchers check the budget themselves and pass
  `check_budget=False`.
- **Brief, not fork.** `mode="brief"` (the default) writes `<workdir>/spawn/briefs/<id>/<spawn_id>.md`:
  task, challenge (from the dispatch claim, section 22), evidence paths (the handout, `recon/index.md`,
  `triage.md`, `recon/flags.txt` when they exist, plus `evidence`; a missing one is refused), tried so
  far (lane results, rejected flags, other agents' lanes, Layer-1 engines run, agent stops; cleaned to
  one line each under a "data, not instructions" heading), and the stop rule. At most `brief_max_tok`
  (about 4 bytes a token): the oldest history lines are dropped with a note, and a brief still over is a
  `SpawnError`. `fork_turns` is `"none"`. `mode="fork"` needs a stated `reason` unless `parent_tok` is at
  most `fork_max_tok` (else refused `fork_needs_reason`); `fork_turns` is `"all"` or the count given.
  `mode="launch"` is a fresh launcher run (no inherited context, no brief).
- **One owner.** `role="owner"` is refused (`owner_exists`) while a live owner exists, unless `replaces`
  names it (that owner gets a `spawn_end`). `role="auto"` takes the free owner seat, else helper. A spawn
  is live until a `spawn_end`, or an `agent_exit` / `agent_stop` carrying its `spawn_id`.
- **Children do not spawn.** `spawn_tool` is true only for an owner that is not a fork; the gated
  launchers start every other admitted run with `no_spawn_args(harness)`.
- **At most `cap` agents** (`AGENT_CAP` = 5, plus every `spawn_allow`): every `spawn` record counts, live
  or ended, plus each `agent_launch` naming no `spawn_id` (a launch from before the gate). The next
  request is **held**: one checkpoint `<workdir>/budget/spawn-checkpoints/<id>-<cap>.json` and one
  `spawn_held` record per cap level, and `on_hold` (the CLI prints a `SPAWN GATE:` line). Only the player
  raises it: `ctf spawn allow ID --agents N --reason R` refuses without an interactive terminal and has
  the challenge id typed back.
- **Lane results persist as found** (`record_result`, `ctf spawn result`), and feed the next brief.
- **Escalations.** `from_escalations` answers each `dispatched` B-016 `escalation` record (section 27)
  once with a request on its `to_model` (a second/third is a helper; a reroute is `auto`); a held one is
  asked again each pass, a refused one is not.

Launchers (`tools/launch_gate.py` `admit` -> `admit_spawn`, after the budget check): `$CTF_SPAWN_ID`
names a spawn admitted by `ctf spawn request`; it is checked (exists, this challenge, not ended, not
launched before) and marked `spawn_bound`, so one id starts one agent; without it the run is its own
`request(mode="launch")`. Held or refused: exit 3 and an `agent_refused {reason: spawn_<reason>}`
(`spawn` for a bad `$CTF_SPAWN_ID`). A dry run decides the same and writes nothing. The gate's records
for an admitted run (`agent_launch`, `agent_exit`, `first_tool`, `candidate`, `agent_stop`) carry
`spawn_id`. The harness binary is checked before admission (a missing one takes no seat). An admitted
run whose agent never starts (a settings or argv error, the exec failing, an interrupt before the exec)
gives its seat back on every return path (`launch_gate.release_unstarted` -> `Spawner.release`): the
run's own spawn gets `spawn_void` (no longer counted nor live; its id is not handed out again), a bound
`$CTF_SPAWN_ID` gets `spawn_unbound` (still counted for its requester, launchable again). Once an
`agent_launch` names the spawn it cannot be released, only ended.

Ledger events written for this section (not section 10 table rows):

- `spawn`: `challenge_id`, `spawn_id`, `role`, `mode`, `spawn_tool`, `n` (this agent's number), `cap`,
  `first_input_tok`? (the brief's size; a fork's `parent_tok` plus the brief; none for a launch),
  `fork_turns`?, `parent_tok`?, `lane`?, `task`?, `harness`?, `model`?, `reason`?, `brief`?,
  `escalation_ts`?, `replaces`?.
- `spawn_held`: `challenge_id`, `agents`, `cap`, `path`, `role`, `mode`, `lane`?, `model`?,
  `escalation_ts`?.
- `spawn_refused`: `challenge_id`, `reason` (one of `REFUSALS`), `mode`, `detail`, `escalation_ts`?.
- `spawn_allow`: `challenge_id`, `agents`, `by`, `reason`, `cap` (the new limit).
- `spawn_end`: `challenge_id`, `spawn_id`, `reason`?. `spawn_bound`: `challenge_id`, `spawn_id`,
  `harness`.
- `spawn_void` / `spawn_unbound`: `challenge_id`, `spawn_id`, `reason` (the launcher's error).
- `lane_result`: `challenge_id`, `lane`, `status` (`found` | `ruled_out` | `partial` | `blocked`),
  `summary`, `spawn_id`?, `paths`?.

What it cannot enforce: a Codex or Claude agent's in-session spawn tool is the harness's; the event
rules (section 15 template, "Spawning agents") tell every agent to `ctf spawn request` first and to
pass the brief with `fork_turns: "none"`, and the ledger shows any agent that skipped it only through
the usage ledger (section 10), not here.

---

## 40. Flag plausibility check and ranked variant set (B-154)

One pre-submit check every lane can call, and one ranked list of format variants that replaces
re-guessing. `ctf/flagcheck.py` (its docstring lists every finding and axis); `ctf flag` is the CLI
(section 8). It reads the event's flag format (section 4) and guess budget (section 25) and sends
only through the submit gate (section 5).

```python
from ctf import flagcheck
chk = flagcheck.check(value, profile, source="strings", others=(), local_checks=("pkcs7", "hmac"),
                      case_lossy=False, case_ref=None, allow_nonstandard=False)    # flagcheck.Check
# Check(value, primary, verdict, findings, in_format, source); .codes() .level_of(code) .refuses .to_dict()
# Finding(code, level, message); level info | warn | block; verdict ok | warn | block (the worst level)
vs = flagcheck.variants(value, profile, source="enigma", case_ref=text, max_variants=12)  # VariantSet
# VariantSet(check, ranked); .primary .sendable(allow_nonstandard) .plan(guesses_left) -> (send, held)
# Variant(rank, value, score, changes, in_format); rank 0 is the primary (score 1, no changes)
flagcheck.guesses_left(profile, challenge_id, workdir=None)    # rules.guess_budget - judged guesses used
rep = flagcheck.try_variants(gate, challenge_id, value, note="...", source=None, confirmed=False,
                             allow_nonstandard=False, max_variants=12, workdir=None)   # TryReport
# TryReport(challenge_id, outcome, reason, sent, guesses, results, skipped, held, accepted, check)
# outcome: accepted | exhausted | capped | stopped | refused. Errors: FlagCheckError (a ValueError)
flagcheck.split(value)          # (prefix | None, body)
flagcheck.restore_case(body, ref)   # body in ref's letter case (whole body, else per word), or None
flagcheck.has_leet(body); flagcheck.deleet(body); flagcheck.leetify(body); flagcheck.ascii_fold(s)
```

- **Sources.** `source` is a name from `flagcheck.SOURCES`, or None: `STATIC_SOURCES` (strings,
  grep, plaintext, metadata, comment, constant, git-history, intake, sweep, fastlane) draw the
  `static_source` decoy warning, which names any `local_checks` passed; `CASE_LOSSY_SOURCES`
  (enigma, morse, baconian...) draw `case_lost`; `DERIVED_SOURCES` draw nothing. An unknown name
  raises `FlagCheckError`.
- **The primary** is the value with the safe fixes applied, each named by a finding: whitespace,
  a double wrap, a missing or foreign wrapper (rewrapped with the event's first prefix), prefix
  spelling under `case = "exact"`, and, when the case was lost and `case_ref` spells the value,
  that case. Nothing else changes the value; every other difference is a variant.
- **Block.** `empty`, `empty_body` and `control_chars` (`Check.refuses`, `flagcheck.REFUSE_CODES`)
  can never be a flag: `variants` raises and `ctf submit` refuses them (exit 4) before the gate.
  `not_in_format` blocks too, but the gate stays the format's enforcer; under `allow_nonstandard`
  it is the info finding `nonstandard`.
- **Ranking.** Axes in `flagcheck.AXES` order (case, diacritics, spaces, leet, wrap); each
  alternative has a prior in `flagcheck.WEIGHTS`; a variant's score is the product over the
  alternatives it combines (at most `flagcheck.MAX_AXES`). Sorted by score, then fewer changes,
  then axis order. Case alternatives appear only when the case was lost or `case_ref` is given.
  `max_variants` counts sendable variants (in the format, or all under `allow_nonstandard`).
- **Budget.** `try_variants` sends rank 0 with `guess=False`, then sendable variants with
  `guess=True`, at most `guesses_left` of them, each with the provenance `<note> [variant <rank>:
  <changes>]`. It skips a `duplicate` refusal, stops at the first accepted value, any other refusal
  or an unjudged answer, and returns what it could not send in rank order as `held` (for
  `ctf policy sweep --candidates`, written by `ctf flag variants --out FILE`).
- **Callers.** `ctf submit` (`submit_one`, with `--source`/`--passed`), `ctf flag` and intake's
  capped auto-submit (`ctf/intake/autosubmit.py`, source `intake`: a `decoy_marker` body is not
  sent and is handed to the player) run the check before the gate.
- **Decoy phrases** (`flagcheck.DECOY_PHRASES`) match whole words of the body after undoing leet;
  a phrase's own words may run together (`nicetry`), but a phrase inside a longer word does not count.
- **Case reference.** Matching ignores case and leet, one character per character (a letter whose
  lower case is longer, such as `İ`, is compared as itself), whole words only.
- **Heuristic.** A warn verdict is not "wrong" and ok is not "solved": only the platform's accepted
  answer marks a challenge solved. A decoy that passes every local check cannot be told apart here.

---

## 41. Shared codec graph (B-163)

One recursive codec graph for every lane (`ctf/codec/`): intake's fastlane decode, `ctf codec`
(section 8), the `common.codec_graph` engine, and any lane that hands it a recognizer of its own final
object. Nodes are byte strings, edges are codecs, the goal is an oracle that validates the final state.

```python
from ctf.codec import Graph, FlagOracle, CribOracle, SlugOracle, Recognizer, AnyOf, Oracle
from ctf.codec import Codec, CodecError, apply_chain, by_name, core, Hit, SearchResult, search
g = Graph(codecs=None, max_depth=8, max_nodes=40000, max_bytes=64 << 20, max_loose=3, max_state=1 << 20,
          xor=True, keyed=None)                      # codecs: core() + any pack's; bad bounds -> ValueError
r = g.search(data, oracle, deadline=None, all_depths=False)   # SearchResult; deadline is time.monotonic()
r.hits; r.answers; r.unique; r.truncated; r.nodes; r.depth; r.errors; r.skipped_large; r.to_json()
# Hit(answer, chain, data, oracle, confirmed); h.how ("rot47+b64+b64")
states, res = g.explore(data, deadline=None)          # every state reached, [(bytes, chain)], no goal
search(data, oracle, codecs=None, deadline=None)      # one-shot Graph(codecs).search
apply_chain(data, chain, codecs=None)                 # re-apply a chain (names); None when a step refuses
by_name(name, codecs=None)                            # Codec, incl. caesar<n>, xor0x<kk>, rail<n>; CodecError
core()                                                # the core codecs (ctf/codec/codecs.py CORE)
Codec(name, kind, decode, doc="", text_only=False)    # kind: strict | symbol | loose | keyed | pack

FlagOracle(profile=None)       # the event format (flagfmt; None = the active event), printable body
CribOracle(crib)               # strong: a literal known plaintext
SlugOracle(crib=None, pattern=oracle.SLUG)   # strong: one slug after the crib, or alone on the last line
Recognizer(fn, name="recognizer")            # strong: fn(state) -> answer | True | falsy (a CRC check, ...)
AnyOf(*oracles)                # union; strong for a state only when a strong member accepts it
oracle.is_strong(oracle, data=None)

from ctf.codec import records, pack
records.parse(blob)            # [Record(index, payload)] from NN<TAB>payload lines; RecordsError
records.readings(payload, graph=None, deadline=None)   # [Reading(text, chains, proved, consensus)]
records.chain_proves(chain, codecs=None)              # >= 1 step, every step a representation change
records.assemble(recs, oracle, crib=b"", graph=None, pin=4, reads=None, deadline=None)   # SetResult
records.consensus(sets, oracle, crib=b"", min_n=3, group="index", graph=None, pin=4, deadline=None)
records.solve_blob(blob, oracle, crib=b"", graph=None, budget=None, group_all=False, min_n=3)
# SetResult(answer, assemblies, unvouched, reason, consensus, placed); Assembly(text, answers, picks, vouched)
pack.names(); pack.load(name, root=None)   # breadth pack codecs ("warmups": crib_decode's STRICT list)
```

- **Codec kinds.** `strict` (base64/url/32/85/58, ascii85, hex, binary/octal/decimal lists, url,
  html, utf-16, run-length `<n>:<c>,`, gzip/zlib/bz2/xz bounded at `codecs.MAX_OUT`) and `symbol`
  (Morse, Bacon 26/24, tap, Polybius, and each *over hex*: Bacon/tap/Polybius groups or Morse that
  spell hex digits, read on by `hex`) are representation steps. `loose` (rot13, rot47, caesar1-25,
  atbash, reverse, swapcase, `xor0x<kk>` only for keys that make every byte printable) and `keyed`
  (rail fence 2-12) are not. `pack` codecs (`<pack>.<name>`) count as representation steps.
- **Search.** Breadth first, shortest chain first, two stages: representation steps only, then (only
  when that finds nothing) loose and keyed steps too, at most `max_loose` per chain and never two in a
  row. A loose output is followed only when it *reads on* (a strict codec turns it into text, a
  container magic, a state with a printable xor key, or an oracle answer; a partial url/html decode
  counts only when the escapes are most of it). Keyed steps run only under a strong oracle (or
  `keyed=True`): a transposition can assemble a flag shape out of any text.
- **Answers.** Every hit at the goal depth is kept; `unique` is the one distinct answer or None.
  `confirmed` = a representation step in the chain, or a strong oracle. A bound that cut the search is
  named in `truncated` (`nodes`, `bytes`, `deadline`); a codec that raised is named in `errors` and
  its attempt counts against `max_nodes` like any other. Pack codecs are asked only on states up to
  `graph.PACK_MAX_STATE` (8 KiB).
- **Records** (`records`): readings at the true cut of crib + answer. A reading is vouched by the crib
  (inside it, or `pin` crib characters); past the crib only a proving chain (representation steps only)
  or a consensus chain is admissible, so a keyless reading never decides a slug. `consensus` takes the
  chain the crib vouched for a record position in `min_n` places with no equal rival, and reads the
  unvouched records of a set without one answer by it, round by round.
- **Packs** load through `ctf.packs.load_module`: an unknown name is `PackError`, a missing or broken
  module `PackMissing` / `PackLoadError`, a module with no decoder list `PackLoadError`. A module
  already in `sys.modules` (fastlane imports `crib_decode`) is reused only when it was loaded from the
  same path; `root=` names another tree, loaded fresh and kept out of `sys.modules`.
- Inputs are untrusted data: decoded, never executed (the pack's esolang readers interpret programs
  with step limits; nothing starts a process). No network.

---

## 42. Arm and release-morning safety (B-197)

`python -m ctf release SLUG` (= `ctf release arm SLUG`), `python -m ctf release
[status|check|green|freeze|thaw|rollback] SLUG` and `python -m ctf release unwired`
(`ctf/cli/release.py`, code in `ctf/arm.py`, built on B-038's git helpers; `ctf arm` is B-014's opener
gate, section 24). Exit 0 ok; 1 the release ref lags (check) or a refusal (`arm.ArmError`: frozen, nothing to thaw or roll back, the fence
regression failed); 2 an error (`arm.ArmInputError`: a ref that is not a commit, no such package, no
psutil; also an unknown action or a missing slug). All anchors are *dated, annotated* git tags that
are never force-moved (the fault that made a human re-arm every night because `git tag -f` was
blocked):

- `event/<slug>/armed/<YYYY-MM-DD>` and `.<n>` (n>=2) for a re-arm the same day. `arm.arm()` is a
  no-op returning the tag only when the day's *latest* armed tag already points at the commit;
  re-arming an earlier commit (after a rollback) writes the next suffix. Suffixes sort numerically.
- `event/<slug>/green/<ts>` (rollback targets, `mark_green`), `event/<slug>/freeze/<ts>` and
  `event/<slug>/thaw/<ts>`; a second stamp in the same second gets `.<n>`, freeze and thaw sharing
  one sequence. `mark_green` on the commit the latest green tag already names is a no-op.

`arm.lag(slug, head="HEAD")` -> `Lag(state, is_lagging, behind, files, ...)`: `armed` when the latest
armed tag is the release ref, else `lagging` / `ahead` / `diverged` / `not-armed`, all `is_lagging`.
`ctf release check` exits 1 whenever it lags. A hard freeze (`arm.freeze`) makes `arm.arm` refuse
any commit but the frozen one until `arm.thaw` (or `--allow-past-freeze`); `arm.rollback_target`
returns the last green tag and refuses loudly when none was marked. `ctf gate run --full --mark-green
SLUG` (B-195) calls `arm.mark_green(slug, require_clean=True)` after a green run that gated at least
one file; a dirty tree or an empty run is refused (exit 2). Only a *full* run may mark green
(`ctf.cli.gate.green_refusal`): an impact or lane run, a `--full` run filtered by `--lane`, or a run
with a pytest selection option (`-k`, `-m`, `--deselect`, `--lf`, `--sw`, `--ignore`, ...) is refused
with exit 2 before it runs, since it proves only part of the suite. The tag message records the run
(`gate full run, N file(s)`; `ctf release green` writes `marked by hand`).

Process-identity fence: `arm.classify(pids, registry=None) -> FenceVerdict(own_pid, own_pgid, ours,
foreign, missing, why)`. A pid is ours when it is this process, an ancestor, a descendant at any depth
(detached or not: tools/process_group.spawn makes every helper a new session leader), in our process
group, or (with an `arm.OwnedRegistry(dir)` that the spawner fills with `register(proc)`) a
registered process (pid + create time), a descendant of one, or in a registered group (even after
its leader exited, while the group has a member: `arm.group_alive(pgid)`). A record whose process
and whole group are gone is expired (deleted) by `classify`, so a later unrelated group reusing the
id is never ours. Shared session is not ownership. Gone or zombie pids are `missing`. A "wait for
the other work" loop blocks only on `safe_to_wait()` (foreign), so the opener never blocks on its own
helpers (the Day-29 594 s self-block). `arm.fence_selftest()` is the real-process regression
`arm.arm` runs before writing any tag (`fence_check=False` skips it); a failure refuses the arm.
Needs psutil (pinned in requirements.in), `sh` and `sleep`.

`arm.unwired(root, package="ctf")` lists modules nothing imports, resolving imports with `ast`
(absolute and relative, every `from . / .. / ..pkg import x` form; a non-docstring string naming the
module also counts, except in the module itself; a file that does not parse is searched textually;
hidden folders are skipped). Test files (`arm.is_test_file`: under `tests/` or `test/`, `conftest.py`,
`test_*.py`, `*_test.py`) are not callers unless `include_tests=True` (`ctf release unwired
--include-tests`): a module only its test imports is reported. A conftest's `pytest_plugins` entries
count as wired. Entry points (`__init__`, `__main__`, `_`-prefixed, `test_*`, `cli.*` command modules)
are excluded. Ledger:
`arm.write`, `arm.noop`, `arm.green`, `arm.green.noop`, `arm.freeze`, `arm.thaw`.

---

## 43. Thin orchestrator (B-200)

The orchestrating main thread reads status lines, wakes once per batch, and stays out of challenge
files. The full contract is the module docstring of `ctf/orch.py`; change it there and here together.

```python
orch.report(challenge_id, state, note="", by="agent", workdir=None) -> dict   # one status line; OrchError on a bad state/id
orch.read_status(workdir=None) -> {id: latest record}       # <workdir>/orch/status.jsonl
orch.board(workdir=None) -> list[Row]                       # stream + claims + ledger + status, active first
orch.status_line(row, width=120) -> str; orch.render_board(rows, width=120, include_finished=False, max_lines=40)
orch.classify(source, rec, prev_state=None) -> Note         # source ledger|stream|status; level urgent|wake|quiet
n = orch.Notifier(workdir=None, quiet_s=15.0, max_batch_s=120.0, urgent_s=2.0, min_gap_s=60.0, poll_s=1.0)
d = n.wait(max_wait_s=None) -> Digest; d.render(max_lines=12); n.commit(d); n.close()
orch.reset(workdir=None) -> offsets; orch.load_cursor(workdir); orch.save_cursor(workdir, offsets, states, last_digest)
orch.tail_lines(path, offset=0) -> (records, new_offset)    # truncated file / corrupt line -> OrchError
orch.guard_decision(hook_input, workdir=, allow_subagents=True) -> (allowed, reason)
orch.guard_main(stdin_text, workdir=) -> (exit, stdout, stderr)   # PreToolUse deny JSON; unreadable input or any guard error -> 2
orch.path_allowed(path, workdir) -> bool; orch.claude_settings(workdir) -> dict; orch.write_settings(workdir) -> Path
orch.brief_md(workdir=None) -> str; orch.write_brief(workdir=None) -> Path   # <workdir>/orch/brief.md
orch.one_line(text, limit=160) -> str                       # platform/agent text flattened to one line
orch.claims_lines(workdir=None, width=120, max_lines=40, include_final=False) -> list[str]   # B-259
```

- **Status line** record: `ts`, `challenge_id`, `state` (one of `orch.STATES`: `needs_player`,
  `blocked`, `stuck`, `candidate`, `working`, `solved`, `done`), `note` (one line, at most
  `orch.NOTE_MAX` characters), `by`. Append-only, mode 0600, flock + O_APPEND. Not a ledger record.
- **Board.** A `Row` per challenge from the watch stream (section 20), the dispatcher claims (section
  22), the ledger (`agent_launch`/`agent_exit`, `candidate`, `platform.submit`, `stop`/`budget_resume`,
  `spend`, `intake`) and the status log, plus whether `<challenge dir>/summary.md` exists. A corrupt
  source raises `OrchError`; nothing is skipped.
- **Notifier.** Byte offsets per source in `<workdir>/orch/cursor.json` (schema 1, with each
  challenge's last state). Levels: URGENT (`budget_checkpoint`, a `paused` submit, `board_open`,
  `brief_changed`, `watch_stop`, a `needs_player` state), QUIET (spend, progress, engine runs,
  launches, claims, detects, records the stream already reports, `working` heartbeats, a repeated
  state), WAKE for everything else, unknown types included. `wait` returns `urgent_s` after the first
  URGENT, or `quiet_s` after the last WAKE, or `max_batch_s` after the first WAKE (a non-urgent digest
  waits `min_gap_s` after the last one); with `max_wait_s` and nothing to report, `woke=False`. One
  `wait` per workdir (`orch/wait.lock`). `commit` saves the offsets; a truncated source raises until
  `reset`, which finds the ends without parsing (`orch.end_offset`). A corrupt line raises naming the
  file and must be repaired by hand: the board reads every line, so `reset` does not recover from it.
- **Guard.** For the orchestrator session only (`claude --settings <workdir>/orch/claude-settings.json`):
  `Read`/`Write`/`Edit`/`MultiEdit`/`NotebookEdit`/`Glob`/`Grep`/`Bash` may not touch the workdir except
  `orch/` and `<challenge dir>/summary.md`; a search or a recursive shell walk rooted at the workdir or
  above is denied; `python -m ctf SUB ...` or `<repo>/tools/ctfpy -m ctf SUB ...` (the spelling the
  denials and briefs give, `briefdiscipline.ctf_command`, B-043) with SUB in `orch.CTF_SHORTCUT` (orch,
  status, budget, submit) and no shell operator or wildcard passes unchecked, every other ctf command gets the full
  check. A call whose hook input names `agent_id` passes when `allow_subagents` (subagents do the
  delegated reading). The Bash check is best-effort (paths spelled out, resolved tokens, braces and
  wildcards expanded with every match checked, `~+` taken as the cwd, `~-` and directory-stack tildes
  denied, `$CTF_WORKDIR`), not a sandbox: the solver fence
  (section 14) is the hard boundary for solvers. Every guard failure exits 2 (the only exit Claude Code
  blocks on); the hook command from `claude_settings` maps any other exit to 2.
- **Brief.** The rules (`orch.RULES`), what waits on the player, the whole board, resume commands,
  then every cause and steer claim with its status (section 53); no model writes it. B-032 restarts a
  session from it at a context threshold.
- **Claims (B-259).** The notifier's fourth source is `<workdir>/orch/findings.jsonl` (section 64;
  `orch.SOURCES` gains `claims`, an older cursor reads it from byte 0). A new claim is QUIET, a
  person's confirmation and a retraction WAKE, a refutation URGENT. `orch.claims_lines(workdir=None,
  width=120, max_lines=40, include_final=False)` is the heading plus one line per claim with its
  status; `ctf orch status` prints it under the board, a woken `Digest` carries it (`Digest.claims`,
  at most `orch.CLAIM_LINES` claims) and the brief lists every claim. `findings` is in
  `orch.CTF_SHORTCUT`: it hashes a challenge file to link it, never prints it.

---

## 44. Multi-event priority scheduler (B-214)

`ctf/slate.py` (the module docstring is the full contract) and `ctf/cli/slate.py`. Builds on section 28's
`governor.Governor` (the host cap and slot leases), section 10's `ctf.quota` (readings, snapshots,
`quota.schedule`), section 14's fence and section 2's `paths.slate_state()`.

```python
from ctf import slate
store = slate.Store(state_dir=None, events_root=None)   # paths.slate_state(): slate.json, history.jsonl, queue/, lock
store.set(slug, by=..., reason=..., priority=2, weight=1.0, max_agents=3, min_agents=0,
          quota_cap_pct=None, paused=False, workdir=None)   # add or change; EventError without a profile
store.pause(slug, by=..., reason=...); store.resume(...); store.remove(...); store.history(); store.load()
sl = store.load()                            # Slate(entries={slug: Entry}); sl.get(slug); sl.ordered(); sl.active()
slate.Entry(slug, priority, weight, max_agents, min_agents, quota_cap_pct, paused, workdir, set_by, reason, set_at)
slate.order_key(entry)                       # (-priority, -weight, slug)
slate.workdir_of(entry)                      # the entry's workdir, else paths.workdir(slug)
slate.workspaces(sl)                         # {slug: Path}; SlateError: shared, nested or in-repo workdir
slate.child_env(sl, slug, base=None)         # env with CTF_EVENT and CTF_WORKDIR pinned to the event
slate.fence_for(sl, slug, events_root=None)  # fence.Fence with every other event's workdir denied ("operator")
a = slate.allocate(sl, cap, demand, running=None)   # Allocation(cap, shares={slug: Share(slug, agents, running, demand, reason, room)}); Share.free
slate.lease_label(slug, label); slate.label_event(label)   # "slate:<slug>: <label>" <-> slug
sched = slate.Scheduler(store, governor_obj) # census(), allocation(), enqueue(slug, label), try_admit(ticket)
lease = sched.acquire(slug, label, timeout=None, poll=5.0); sched.release(lease)   # GovernorTimeout past timeout
latest, last_ok = slate.account_readings(workdirs)   # quota readings merged across every event workdir
jobs = slate.load_jobs({"pink": [{"id": "p1", "kind": "solve"}]})   # {slug: [quota.Job]}
p = slate.plan(sl, jobs, now=None, allocation=a, events_root=None)
# SlatePlan(now, next_release, allocation, assigned=[Placed(slug, assignment)], held=[HeldJob(slug, job, kind,
#   release_at, reasons)], batches, warnings); p.for_event(slug)
slate.check(sl, events_root=None)            # [problem line]; [] = the slate works
# errors: SlateError (plus event.EventError, quota.QuotaError, governor.GovernorTimeout)
```

- **The slate** is runtime state, one per host, never in an event profile: the player's call changes by
  the hour (PINK+ capped at 3 agents and lifted it 31 minutes later). Every change names `by` and
  `reason` and is appended to `history.jsonl` with the entry before and after. An event needs a profile
  that loads (`event.load`). `slate.json` is written atomically under the flock on `lock`.
- **Isolation.** Each event's workdir is its entry's `workdir` (absolute or `~/`), else
  `paths.workdir(slug)`. Two events in one folder, one inside another, or one inside the repo is a
  `SlateError` (a set `CTF_WORKDIR` pins every event to one folder and is named). `set` refuses a change
  that would break it, and writes nothing. `child_env` and `ctf slate run` pin `CTF_EVENT` and
  `CTF_WORKDIR` for the agent; `fence_for` / `ctf slate fence` add every other event's workdir to the
  fence's denied roots.
- **Agents.** `allocate`: floors (`min_agents`) first in `order_key` order; then each priority tier,
  highest first, served in full before the next; inside a tier one agent at a time to the event with the
  fewest agents per unit of `weight` (ties: higher weight, then slug). Never past `max_agents` or the
  event's demand; paused events get none; unused share flows down. `Share.free` is the share less the
  running agents, capped by `Share.room`: its part of the seats the cap has open after every running
  agent (an event over its share still holds its seats). Open seats go tier by tier, highest priority
  first; inside a tier one seat at a time to the event with the fewest agents (running plus seats already
  opened to it) per unit of `weight` (ties: higher weight, then slug). `Scheduler` (and `ctf slate
  run`): the cap is the governor's `Decision.cap` minus heavy-agent leases not labelled `slate:` or
  labelled for an event no longer on the slate; demand is an event's running leases plus its live
  tickets under `queue/`; a ticket is admitted when its place among its event's tickets (oldest first)
  is below `Share.free` and `Governor.try_acquire` seats it. A ticket inside its share keeps its
  governor ticket (its place in the host queue) between tries; any try withdraws the governor tickets
  of every ticket outside its share, and `dequeue`, timeout and reaping withdraw it too. Dead or
  unreadable tickets are reaped
  (`Scheduler.reaped`). Running agents are never stopped or signalled: an event over its share
  after a priority change just gets no new agents.
- **Budget.** Quota windows are the account's: `account_readings` merges every event workdir's readings
  (newest per harness and window; latest served response per harness). `plan` takes tiers in priority
  order and events in a tier by weight (as `allocate`), each event's jobs in `quota.KIND_RANK` order
  (writeups first), and places each job with `quota.schedule` on that event's snapshot with the usage
  placed so far added to every metered window. The reserve holds for the earliest `next_release` of any
  active event. `quota_cap_pct` caps what one plan adds for one event per window (held reason names it);
  one probe job per harness across all events; with an `allocation`, jobs past an event's `Share.free`
  are held under `"agents"`; a paused event's jobs are held under `"event"`. Held jobs are batched by
  the time they open, like `quota.Plan.batches`. Warnings: an event outside its dates, an unmetered
  harness that took jobs.

---

## 45. Handoff board (B-180)

Claude, Codex and the player hand work to each other through files under the workdir; the runbook
is `docs/handoff.md`.

```python
from ctf import handoff
board = handoff.Board()                       # <workdir>/handoff/
h = handoff.post(board, challenge="42", mode="fast", guidance=text, by="claude")   # -> Handoff
handoff.launch(board, h.id, by="claude")      # detached tools/<harness>_launch --challenge: fenced + budget-gated
board.claim(id, by=); board.note(text, by=, hid=None, to="any"); board.done(id, by=, status=)
board.inbox(who, peek=False) -> (tasks, notes); board.state() -> {id: Handoff}; board.reap(by="reaper")
handoff.check_brief(path) -> id               # HandoffError if the end marker or digest is wrong
handoff.load_modes(slug) -> {name: Mode}      # ctf/handoff.toml + events/<slug>/handoff.toml
```

- `handoff/board.jsonl`: one JSON object per line, `{"seq", "ts", "op", "id", "by", ...}`; ops
  `post`, `claim`, `launch`, `launch_failed`, `note`, `done`, `cancel`. Appended under an exclusive
  flock; a transition not allowed from the current state is refused under the same lock.
- `handoff/<id>/brief.md` ends with `=== END OF BRIEF <id> sha256:<digest of the text above> ===`;
  a launched agent's prompt is a pointer to it, never the brief. `board.claim` refuses a brief that
  fails `check_brief`. An id whose directory already exists is skipped, never reused.
- Modes: `harness`, `model`, `tier` (`standard` only, B-009), `launch` (`detached` | `queue`);
  codex adds `effort`, `daybreak` (required, explicit), optional `cyber_access_program`; claude adds
  optional `permission_mode`. Unknown or missing keys raise `HandoffConfigError`.
- `--as` / `CTF_HANDOFF_AS` names the actor; every board method, `reap` included, refuses a bad name
  with `HandoffError`. Ledger events: `handoff.post`, `handoff.launch`,
  `handoff.launch_failed`, `handoff.done`.

---

## 46. Solver contract (B-172)

One set of solver rules in every brief, and the no-model checks that back them. A brief can state
rules but cannot make a model follow them (the spec's blocker), so the rules are one source rendered
everywhere, and the parts that can be checked against the ledger are checked. The full contract is the
module docstring of `ctf/solver_contract.py`; change it there and here together.

```python
from ctf import solver_contract
solver_contract.rules_md(heading_level=2) -> str        # the rules, status words, report shape
solver_contract.handout_section(lane, challenge_id=None) -> str   # ladder + rules (dispatch handouts)
solver_contract.ladder_for(lane) -> tuple[str, ...]     # LADDERS[canonical lane], else DEFAULT_LADDER
solver_contract.agent_status_for(result) -> str         # SolverResult: solved -> FLAG_FOUND, blocked -> BLOCKED, else WORKING
solver_contract.acceptance(challenge_id, workdir=None) -> str | None   # how the ledger shows it accepted
solver_contract.may_stop(profile, challenge_id, workdir=None, clock=None) -> StopVerdict
solver_contract.parse_report(text) -> Report
solver_contract.check(report, profile=None, workdir=None, challenge_id=None) -> list[Violation]
solver_contract.check_report(text, profile=None, workdir=None, challenge_id=None) -> list[Violation]
solver_contract.record_status(report, profile=, challenge_id=, workdir=None, by=None) -> (record | None, [Violation])
solver_contract.record_solve_count(challenge_id, count, source=, workdir=None) -> dict
solver_contract.solve_count(challenge_id, workdir=None) -> SolveCount | None
solver_contract.record_fact(challenge_id, fact, evidence=, workdir=None, by=None) -> dict
solver_contract.facts(challenge_id, workdir=None) -> list[Fact]
solver_contract.fresh_eyes_md(challenge_id, workdir=None) -> str
solver_contract.write_fresh_eyes(challenge_id, workdir=None) -> Path   # <challenge folder>/fresh-eyes.md
# Rule(id, title, text); RULES, RULE_IDS, STATUSES, STATUS_MEANING, NEEDS_NEXT, LADDERS, DEFAULT_LADDER
# StopVerdict(challenge_id, allowed, reasons); Violation(rule, code, message); SolveCount(challenge_id, count, source, ts)
# Report(status, challenge, next, evidence, oracle, solves, stop_loss, text); Fact(challenge_id, fact, evidence, by, ts)
# CONTRACT_VERSION, STATUS_EVENT, FACT_EVENT, SOLVE_COUNT_EVENT, FRESH_EYES_NAME, ContractError (a ValueError)
```

The rules (`RULE_IDS`): `simplest-first` (a ladder per lane, cheapest rung first, each rung ruled in or
out with a recorded test), `evidence-before-claims` (wire/byte evidence for a crypto theory),
`flag-in-artifact`, `solves-before-broken`, `oracle-before-submit`, `persist` (no stop on a
score-open challenge until a stop-loss fires), `next-action`, `status-vocabulary`, `fresh-eyes`. They
reach every agent twice: `rules_md()` is the event template's `{{solver_contract}}` (section 15, both
CLAUDE.md and AGENTS.md), and `handout_section()` closes every dispatcher handout (section 22).

Status words (`STATUSES`): `WORKING`, `FLAG_FOUND`, `SOLVED`, `BLOCKED`, `STOPPED`. An engine's
`solved` (section 7) is `FLAG_FOUND` here; `SOLVED` means `acceptance()` finds an `accepted` stage, a
`platform.submit` `correct`/`already_solved` that is not `partial` and has no `remaining > 0` (a part's
own record for a part; for the bare id a part only with `remaining = 0`, as section 27), or a
team-solve `stop`. A `solver_status` record is never proof of acceptance.

A status report is `KEY: value` lines (`STATUS`, `CHALLENGE`, `NEXT`, `EVIDENCE`, `ORACLE`, `SOLVES`,
`STOP_LOSS`; rest is prose). `check()` codes: `no-status`, `unknown-status`, `no-next` (WORKING,
FLAG_FOUND, BLOCKED), `solved-before-acceptance`, `solved-unverifiable` (no id), `flag-no-evidence`,
`flag-no-oracle` (`ORACLE: pass <how>` or `none <why>`), `broken-without-solves`, `broken-but-solved`
(a cited or recorded count > 0, or our own acceptance), `flag-elsewhere-no-evidence`,
`stop-no-stop-loss`, `stop-before-stop-loss` (STOPPED, or stand-down prose, while `may_stop` says no),
`stop-unverifiable` (no id or profile), and `challenge-mismatch` (`record_status` only). The first
line for each key wins. The prose checks are phrase matches: they catch the stock wording, not every
paraphrase. "Broken" counts only with the challenge as its subject (challenge, service, server,
instance, remote, checker, endpoint, it, this), never "MD5, which is broken" or a negated "is not
broken". A stand-down counts only when it is not negated ("not giving up") and its clause's object is not
a theory, idea, rung or hypothesis unless the clause also names the challenge. A flag-elsewhere claim
names an outside place (elsewhere, outside the challenge/files, Discord, social media) or a flat "not in
the files" that ends the clause.

`may_stop` fires on: acceptance; a dispatch claim (section 26) marked `solved` or `gone`; a B-033
budget stop (any reason), the cap reached, or the no-progress timer due on a high-value tail (read,
not recorded); the B-006 wrong-answer stop with no player approval left (`rules.approved_extras`
false: none ever). Otherwise `allowed` is false and the reason says the challenge still scores.

Fresh eyes: the brief (`dispatch.brief_for`), the challenge folder's `files/` listing, which of
`recon/index.md`, `triage.md`, `recon/flags.txt` exist, the verified facts (each with evidence; a
`fact` record without evidence is left out), and the lane's ladder plus the rules. Never `notes.md`,
hypotheses or transcripts. Fact and challenge text are fenced as data.

Ledger events written for this section (not section 10 table rows):

- `solver_status` (`record_status`, `ctf contract report`; only a passing report): `challenge_id`,
  `status`, `next`?, `evidence`?, `oracle`?, `solves`?, `stop_loss`?, `by`?.
- `fact` (`record_fact`, `ctf contract fact`): `challenge_id`, `fact`, `evidence`, `by`?.
- `solve_count` (`record_solve_count`, `ctf contract solves --record`): `challenge_id`, `count`,
  `source`. The latest record wins; nothing fetches the board's count yet (read it by hand).

CLI: `show [--lane L]`, `check [FILE|-] [--challenge ID]` (exit 1 on a violation), `report ID --status
S [--next --evidence --oracle --solves --stop-loss --note --by]` (exit 1, nothing recorded, on a
violation), `may-stop ID [--json]` (exit 0 may stop, 1 keep working), `solves ID [--record N --source
S]` (exit 1 when none is on record), `fact ID TEXT --evidence E [--by]`, `fresh-eyes ID [--write]`;
exit 2 on a named error.

---

## 47. Live status surface and progress files (B-198)

```python
from ctf import live, progress
snap = live.collect(live.default_sources(event_slug=None, no_event=False))   # dict, JSON-safe
live.render_text(snap)                    # the `ctf live` text; live.text_lines(snap) -> [(label, text)]
live.write_page(snap, out, title=live.page_title(snap), refresh=30)
live.push(snap, live.push_url(None), state_dir=paths.status_state(), title="...")  # "sent" | "unchanged" | "too soon"
live.smoke(url, max_age=600, expect_digest=snap["digest"])                  # [Check(name, ok, detail)]
live.run_job("suite", argv, folder=paths.status_state() / progress.PROGRESS_DIR, repo=paths.repo_root())
live.arm(workdir, live.make_git(repo), note="")   # <workdir>/status/armed.json: HEAD as the armed commit

p = progress.Progress(folder, "gate", total=120, jobs=2, label="impact", head=progress.head_of(root))
p.step(seconds=3.2); p.step(warm=True); p.step(seconds=9.0, bad="tests/test_x.py"); p.finish("fail")
progress.read(folder)                     # newest first, each with state and eta
```

- **No model, no platform.** Every field comes from a file or process state: git, BUILD-PLAN.md and
  `docs/build-log/`, progress files, the event workdir (watch stream, ledger, dispatch claims, armed
  commit) and `ps` process names. The module docstring of `ctf/live.py` lists each source. A source
  that cannot be read is shown with its reason (a note or an `error` field), never as zero.
- **Progress files** (`ctf/progress.py` docstring is the record): one JSON per run, written by the
  process doing the work. State is computed on read: `running` (owner pid or child pid alive),
  `finished`, `died` (not finished and both pids gone: never reported as running), `unreadable`.
  ETA = remaining x seconds per item / jobs, from this run (`observed`), else the median of the last
  10 finished runs of the same kind and label (`usual`), else unknown with the reason. Folders:
  `<gate state>/progress/` (the gate) and `<status state>/progress/` (`ctf live job`). Each folder
  keeps its newest 20 finished run files and the newest 500 lines of `history.jsonl`.
- **Plan.** Percent through `BUILD-PLAN.md` by items and by effort (S 1, M 2, L 4, XL 8): an item is
  done when `docs/build-log/<id>.md` exists, or any `<id><letter>.md` part does (the plan does not list
  a unit's parts, so one logged part counts the unit; parts whose `Status:` words differ count as
  `partial`); its `Status:` word is counted. Rate: effort logged in the last 6 h by the git add time of each log (two logs at least),
  else since the first log. ETA: remaining effort / rate.
- **Alerts.** A run that died; the newest gate of a label not `pass`; the newest job of a name not
  `ok`; a running run on a commit other than HEAD; the armed commit behind or diverged from HEAD; an
  in-event, non-manual board with no watcher; failing board polls; agents launched with no exit whose
  pid is gone; unreadable claims, stream or ledger.
- **What leaves the machine.** The snapshot, page and push carry no path, command line, flag or
  challenge text. `collect` passes every string of the snapshot through `live.scrub`: the checkout,
  workdir and state folders become `<repo>`, `<workdir>`, `<gate state>` and `<status state>`, and any
  other absolute path keeps only its last part (`<path>/event.toml`), so error notes (a
  missing profile, a corrupt ledger line, no .git) name the file without the path. Dict keys are
  scrubbed too. A path after `:`, `-` or `->` counts; a URL's `scheme://` does not, and scrubbing is
  idempotent (`<repo>/x` stays). The page has `<meta name="ctf-live-digest">` (sha256 of the headline: no times, ages
  or ETAs) and `<meta name="ctf-live-generated">` (epoch). The push is an ntfy-style POST (`Title`,
  `Priority` 4 with alerts else 3, `Tags`) to `$CTF_STATUS_PUSH_URL` or `--url`, never printed, sent
  when `live.push_key` (states, results, solves, alerts; not progress counts) changed, not sooner than
  `--min-interval` unless the alerts changed; a failed send exits 1 and leaves the push state as it was.
  `live.check_endpoint` refuses a push or smoke URL that is not http(s), is the event platform
  (`platform` hosts or `$CTF_PLATFORM_URL`) or is in `rules.live_service_scope`, before any connection.
  With no event resolved (`--no-event`, or none selected) it checks every profile under `events/`
  (`live.endpoint_profiles`); a profile that does not load is an error naming it.
- **Smoke.** `ctf live smoke URL [--local PAGE]` fetches the deployed page and checks HTTP 200, an HTML
  content type, the two meta tags, freshness (`--max-age`, default 600 s) and, given a local page or
  digest, that the deployed page is the one built here. Exit 0 all ok, 1 a check failed.
- **Jobs and arming.** `ctf live job --name N -- CMD` runs CMD with a progress record (result `ok`,
  `rc=N`, `interrupted`, `not started`), so "is it running?" is answered by the record and the pid.
  `ctf live arm` records HEAD for the event (the commit its long-running processes run; not
  `ctf arm`, the B-014 opener gate of section 24, which records nothing); `ctf live forget --died`
  removes died records.

## 48. Answer-format renderer (B-232)

A judged platform states each answer's form in the question's `answer_format` (`kind`, `syntax`,
`accepted_values`, `normalization`). At Huntress, answers that were read right were still sent wrong:
step lists comma-joined although the syntax said `joined by >` (Day 6), relationship targets and zip
member names in file order when the judge took ascending (Days 15 and 23), and a timed-only
`synthesis-sha256-order` question no reader routed (Day 15). `ctf/answerfmt/` is the one lane-blind path
that formats an answer from its contract. No network, no model; the module docstrings are the contract.

```python
from ctf.answerfmt import contract, rendering, synth, wire, shellword

contract.read(answer_format, question_text=None) -> Contract   # None reads as no contract (present False)
    # Contract: kind, syntax, accepted, accepted_partial, case_insensitive, separator, tight, container
    # (json_array | json_object | json), order (ascending | descending | file | any | keyed), conflicts, none_ok
rendering.render(value, answer_format=None, question_text=None, ordered=False, contract=None) -> Rendering
    # Rendering: status plain | options | withheld, value, options ((name, text), ...), axes, reason
rendering.render_answers(questions, answers, answer_ids=None) -> Batch   # plain / unsure / held / passed by id
synth.route(answer_id) -> (Handler, match) | None
synth.answer(answer_id, question_text, answer_format, files) -> Rendering
synth.covered(answer_id, question_text, answer_format) -> None | why     # before the files are delivered
synth.register(name, suffix, handler, covered=None) -> Handler           # suffix must end in $
synth.handlers(); synth.files_from_dir(folder) -> {relative path: bytes}
wire.wire(question, value, lane, field=None, labels=None, ordered=False) -> str | None
wire.to_wire(rendering, key, labels=None); wire.key_for(lane, field, rendering, kind=""); wire.load_labels()
shellword.word(text, i=0) -> (value | None, end); shellword.words(text); shellword.assignment(text)
```

Rules:

- **Only what is stated is applied.** The separator (`joined by >`, `joined by " > "`, `comma-separated`,
  `separated by a comma followed by a space`, `one per line`), `no (surrounding) spaces`, a JSON
  array or object, and the element order (`ascending`, `in alphabetical order`, `in sorted order`, `descending`,
  `in file order`, `in the order they appear`, `not sorted`, `in any order`) are read from the syntax;
  the order also from the question text. Two different separators or orders are a conflict (`conflicts`),
  read as unstated. An order keyed on something else (`sorted by size`, `digest order`, `in (ascending)
  order of modification time`, `chronologically`, `oldest first`, `from oldest to newest`) is `keyed`
  (`order of appearance` / `first occurrence` is file order; `in the order of the input` and `in order
  of file name` are no key); a
  direction stated with it (`largest first`, `ascending`) is the key's own, and `keyed` wins over any
  other stated order (still named in `conflicts`), so such a list is withheld, never offered in file order.
- **A list answer has two axes.** Order: `given` (kind `ordered_tokens`, or `ordered=True`), the stated
  order, else file order AND ascending (numeric for ints; a digit-string list also gets
  `ascending_numeric` unless integers are stated). Join: JSON array, the stated separator (tight and
  spaced unless `no spaces` is stated or the separator holds its blanks), else comma / comma-space /
  JSON / space. Options are named `<order>+<join>`, best first, at most 12, each text distinct. One
  option is `plain`; more are `options` and are never sent plain. A `keyed` order without
  `ordered=True`, a list under a JSON-object contract, a set and an empty list (unless the literal none
  is allowed) are `withheld`.
- **A token string is a list.** Under kind `ordered_tokens`, or a stated separator on a text kind, a
  string answer is split and rejoined as the contract states (a stated newline, `one per line`, is
  stated though it is a blank). When the stated separator is in it, it
  splits on that one alone (`cut -d, -f1>sort` under `>` is two tokens). When it is not and exactly one
  common separator (`->`, `=>`, `>`, `,`, `|`, `;`, newline) is, the split opens a `split` axis: the
  split reading's options (`split_comma+given+stated`) then the whole string (`whole`), never plain.
  Several common separators and not the stated one, or an empty token (`a,,b`), are withheld.
- **Scalars.** Kind integer must be base-10 (or the allowed literal none); a closed enum takes its
  listed spelling on a case-insensitive match and is withheld on none; kind json must parse; anything
  else is sent as given. An already-unsure `??` string is never rendered (`render_answers` passes it
  through untouched). An answer id with no question is held. An unreadable answer_format raises
  `AnswerFormatError` naming the id.
- **Synthesis by id suffix.** The shipped handler `digest_order` answers ids ending in
  `[synthesis-]<algo>-[digest-]order` (`synth.DIGESTS`): the `Files: [...]` list's names in ascending or
  descending full-file digest order, rendered by the question's own contract with `ordered=True`. It is
  withheld when the text names another algorithm, narrows the bytes digested, states no direction or
  both, asks the digests instead of the names, or when a named file is missing, two files share a
  name or a digest.
- **The wire.** `wire.to_wire` returns the plain text, None for withheld, and for options
  `labels.candidates` (the order or split axis open: different lists are different candidate facts) or
  `labels.pick` (spellings only) under `<lane>.<field>/answer_format.<kind>.<axes>`. labels is
  `solvers/common/labels.py`, loaded through `ctf.packs` (PackMissing / PackLoadError on a miss). Once
  the judge accepts a hypothesis for the key, the next variant's own list is answered plain under it.
- **Shell words.** `shellword` reads POSIX word concatenation (`'ab'"cd"ef$'\x67'` is `abcdefg`) as data;
  a word that needs an expansion (`$x`, `$(..)`, a backtick) has value None; an unterminated quote
  raises `ShellWordError`.

## 49. Harness failover for release mornings (B-170)

What to do when the harness holding the lanes cannot hold the next release (Claude Code out of quota
and Codex takes over, or the reverse). The procedure is `docs/runbooks/harness-failover.md`; the full
contract is the module docstring of `ctf/failover.py`. The trigger is the B-171 quota meter (section 10).

```python
from ctf import failover
r = failover.readiness(snap, harness, lanes=1, est_pct=None)      # Readiness(harness, now, at_release, status, why); .ready
d = failover.decide(snap, primary="claude", active=None, lanes=1, est_pct=None, records=None)
# Decision(action, primary, active, target, trigger, now, next_release, ready, warnings); .switch
failover.steps(d, profile, workdir=None)          # [str]: the runbook steps for d.action, commands filled in
failover.other(harness)                           # the other harness
failover.active(workdir, primary="claude", records=None)     # last failover.switch harness, else primary
failover.last_switch(workdir, records=None)       # the newest failover.switch record or None
failover.switch(workdir, to, by=, reason=, primary="claude", records=None)   # failover.switch record
failover.profile_lanes(profile)                   # the event's categories as lanes, else DEFAULT_LANES
failover.encode(flag, encoding); failover.task_text(lane, flag, encoding); failover.prompt_text(profile, lane)
failover.guard_bin(harness, raw, live=, env=)     # the resolved harness binary, or FailoverError
failover.lane_command(profile, harness, lane_dir, prompt, bin=, model=None, python=sys.executable, repo=None)
rep = failover.rehearse(profile, harness, by=, workdir=None, lanes=None, live=False, bin=None, model=None,
                        parallel=None, deadline_s=300.0, timeout_s=None, environ=None, record=True,
                        python=sys.executable, repo=None)
# RehearsalReport(harness, live, bin, lanes=[LaneResult(lane, status, seconds, exit_code, detail)], wall_s,
#                 deadline_s, parallel, root); .held, .failed
failover.rehearsals(records, harness=None, live=None)      # failover.rehearsal records, oldest first
failover.rehearsal_warnings(records, harness)     # [] when the last live rehearsal onto harness held
failover.check(profile, workdir=None)             # the doctor's "failover" Check
failover.rehearsal_runs(workdir)                  # run folders under <workdir>/failover-rehearsal/, oldest first
failover.prune_rehearsals(workdir, keep=1, dry_run=False)   # remove all but the newest `keep` runs per
                                                  # harness; -> [removed Path]; symlinks and other names untouched
# failover.FailoverError; failover.HARNESSES, ACTIONS, SWITCH_EVENT, REHEARSAL_EVENT, STUB_MARKER,
# LAUNCHERS, BIN_ENV, DEFAULT_LANES, DEFAULT_DEADLINE_S, ENCODINGS, LANE_STATUSES, RUNBOOK
```

- **Decision.** `readiness` schedules `lanes` release jobs (`quota.schedule`) pinned to one harness
  (`now`: none held, none a probe) and asks quota whether it is funded at the next release
  (`at_release`). A harness with no reading is ready (unmetered) and `why` says so. `decide`: the
  primary while it is ready; else the other harness when it is ready now; else `stranded`. The action
  compares that with the active harness: `stay`, `failover` (off the primary), `failback` (back onto
  it), `stranded`. A target other than the primary carries the rehearsal warnings of that harness.
- **Ledger records** (`ctf.ledger`; not section 10 core records):
  `failover.switch` from `failover.switch`: `harness`, `from_harness`, `action` (`failover` /
  `failback`), `primary`, `by`, `reason`. A switch onto the active harness is refused.
  `failover.rehearsal` from `failover.rehearse`: `harness`, `live`, `held`, `lanes` (each `lane`,
  `status` one of `pass` / `wrong` / `no-result` / `timeout` / `launch-error`, `seconds`, `exit_code`,
  `detail`), `wall_s`, `deadline_s`, `parallel`, `by`. No flag value is written.
- **Rehearsal.** One lane folder per lane under `<workdir>/failover-rehearsal/<stamp>-<harness>-<hex>/`
  with `task.txt` (a fresh flag in the event format, `doctor.synth_flag`, encoded one of `ENCODINGS`),
  run through `tools/codex_launch` / `tools/claude_launch` (the fence; `CTF_CHALLENGE` is dropped so
  the budget gate stays off), all lanes at once unless `parallel`. A lane passes when the first line
  of its `result.txt` is its flag; it holds when it also took at most `deadline_s`. A lane still
  running at `timeout_s` (default twice the deadline) has its process group killed.
- **Guards.** Without `live`, the binary (`bin`, else `$CODEX_BIN` / `$CLAUDE_BIN`, else the CLI
  name) must carry `STUB_MARKER` (`ctf-harness-stub`) in its first 4 KiB and must not be the CLI on
  PATH. With `live`, it must not be a stub, and a live rehearsal is refused under `CTF_TESTING`. A
  binary that resolves to nothing is a `FailoverError` naming the variable.
- **Lane folders** are kept until `prune_rehearsals` (only real folders named `<stamp>-<harness>-<hex>`;
  a symlinked `failover-rehearsal/` is refused). Pruning never touches the ledger records.
- Nothing starts agents or reroutes work by itself: `check` prints the steps and exits 3; the
  dispatcher (section 22), the escalation roster (section 27) and the launchers do not read
  `failover.active()` yet. Wiring them needs a model-to-harness map, which no profile carries yet
  (follow-up `B-170-F1` in BUILD-PLAN.md; design in docs/build-log/B-170.md).

---

## 50. Shipped workflow scripts (B-194)

The repo's workflow scripts live in `workflows/*.js` (outside `.claude/`) and run under the Workflow
tool (`agent()` / `pipeline()` / `parallel()` / `phase()` / `log()` / `args`). They replace the 2026
pattern of generating a workflow as a string at run time, which failed on parse errors and
`StructuredOutput` mismatches, hard-coded its lanes (so the web lane was skipped), let a human question
reach the running agents, and fanned out without a bound until the weekly allowance was gone.

Each `<name>.js` is paired with a `<name>.wf.toml` manifest read by `ctf.workflows` (`python -m ctf
workflow`). The manifest is the pre-launch copy of the script's contract; the JS enforces the same at
run time (defence in depth) and `tests/test_workflows_registry_b194.py` asserts the two agree.

```python
from ctf import workflows as wf
wf.load_all() -> [Workflow(name, script, description, required, lane_arg, stages_per_lane,
                           extra_agents, max_agents, path)]   # one per workflows/<name>.wf.toml; script must exist
wf.get(name) -> Workflow                                       # WorkflowError names the unknown workflow
wf.validate(wf, args)         # WorkflowError names the first missing required arg; lane_arg must be a non-empty list
wf.plan_agents(wf, args) -> int                                # len(args[lane_arg]) * stages_per_lane + extra_agents
wf.effective_cap(wf, args) -> int                              # max_agents, lowered (never raised) by args["agentCap"]
wf.check_cap(wf, args) -> int                                  # WorkflowError when plan_agents > effective_cap
wf.preflight(wf, args) -> int                                  # validate then check_cap; the full pre-launch gate
wf.lanes_from_board(workdir=None) -> [lane]                    # distinct lanes across the dispatch claims (ctf.dispatch)
wf.lanes_from_profile(profile) -> [lane]                       # the event categories, canonicalised (ctf.triage)
wf.WorkflowError                                               # names the workflow and the field/count at fault
```

Every shipped workflow enforces four guards **before the first `agent()` call**, so a failed guard
spawns zero agents: (1) a required-argument schema check that names the first missing field; (2) the
lane/target list is a required argument from the board, never a built-in list, and an empty one fails
loudly; (3) each agent's brief carries only its one lane/target plus the standing safety rules (free-form
`args` fields are not interpolated, so a human question never reaches an agent); (4) a hard per-workflow
agent cap whose dry-run count (from the arguments) is compared to the cap before launch, with an optional
`agentCap` argument that may only lower the cap. `workflows/README.md` is the authoring guide.

## 51. Stuck-id protocol (B-203)

The brake on unbounded probing of an answer that cannot be derived. An id with no derivation once drew
329 rejected probes and an agent swarm; a spelling not derivable from the files had the organizer
rewrite the question. The protocol composes the rejection ledger (section 33, and the `platform.submit`
records of section 5), the budget caps (section 10), the per-challenge agent gate (section 39, `ctf.spawn`), the
live re-read (section 20, `ctf.watch`) and the ranked format candidates (sections 31/48 and
`solvers/common/render_candidates.py`), and adds only the no-derivation detector and the per-id caps.
Full contract: the module docstring of `ctf/stuck.py`. No model, no submit, no platform call.

```python
from ctf import stuck
stuck.Thresholds(stuck_after=8, probe_cap=20, agent_cap=2, reread_interval_s=600.0)   # stuck.DEFAULT
stuck.vocabulary(question, extra=())        # distinctive anchor tokens of the asked id (setN. removed,
                                            # generic field/shape words and <4-char tokens dropped)
stuck.material_tokens(brief_text=None, files=None)   # tokens of the brief + each file's name and body
stuck.reject_count(workdir, id, event_slug=None)     # judged-wrong platform.submit records for the id
stuck.format_candidates(read_value, answer_format=None, field=None, rejected=())   # untried re-spellings
a = stuck.assess(id, question=, brief_text=None, files=None, workdir=None, rejections=None,
                 read_value=None, answer_format=None, rejected_values=(), extra_vocab=(),
                 format_candidates_on=True, thresholds=stuck.DEFAULT, event_slug=None)
# Assessment(challenge_id, status, rejections, vocabulary, vocabulary_found, derivable,
#            untried_format_candidates, thresholds, reason); .is_stuck
stuck.mark_stuck(a, workdir=None, profile=None, route=True, agent=None)   # one `stuck` record + player card
stuck.marked_stuck(workdir, id); stuck.stuck_ids(workdir)
stuck.clear_stuck(id, workdir=None, reason="", by=None)
stuck.probe_allowed(id, question=, brief_text=None, files=None, workdir=None, **assess_kw)  # Decision
stuck.agent_allowed(id, question=, ..., thresholds=stuck.DEFAULT, **assess_kw)   # Decision(.agents)
stuck.agents_on(workdir, id)                 # the per-challenge agent count from ctf.spawn (section 39)
stuck.last_read_ts(workdir, id); stuck.reread_due(workdir, clock=time.time, thresholds=DEFAULT)
stuck.brief_changed_since_stuck(workdir, id); stuck.reconsider(workdir, profile=None, by="watch")
# stuck.StuckError; STUCK_EVENT "stuck", CLEARED_EVENT "stuck_cleared"; statuses OK,
# TRY_FORMAT_CANDIDATES, STUCK, PROBE_CAPPED
```

- **The detector.** An id is **stuck** when it has **no vocabulary** (no distinctive token of the asked
  id appears in the brief or any delivered file -- the spelling is not derivable from what was given)
  AND it has drawn at least `stuck_after` rejected probes. An id is **probe-capped** once it has drawn
  `probe_cap` rejected probes, derivable or not (a hard ceiling). Both are `is_stuck` and route to the
  player; an underivable id ends with the player or the organizer, so there is no machine answer.
- **Format candidates first (on by default).** When a value WAS read (`read_value`), the ranked
  re-spellings not yet rejected are offered before the id is called stuck (`TRY_FORMAT_CANDIDATES`), so
  an id is never declared stuck merely because the one plain spelling that was sent was wrong. Turn it
  off with `format_candidates_on=False`.
- **Caps.** `probe_allowed` is the gate an agent/harness puts before a `platform.submit` (as
  `hypothesis.should_skip` gates a probe): refused when the id is stuck or probe-capped. `agent_allowed`
  refuses a new agent on a stuck id or once `agent_cap` agents are on its challenge; the 5-per-challenge
  numeric gate itself stays in `ctf.spawn`, consumed through `agents_on`, not re-counted.
- **Live re-read.** `reread_due` lists stuck ids whose newest stored brief (section 20) is older than
  `reread_interval_s` (10 min) for a driver to prioritise a detail fetch. When the organizer rewrites a
  stuck id's question, the `brief_changed` event lands after the `stuck` record;
  `brief_changed_since_stuck` sees it and `reconsider` writes a `stuck_cleared` so the engine reconsiders
  the id instead of leaving it parked. The watcher is not modified: feeding `reread_due` into a poll's
  prioritised detail list is a follow-up (docs/build-log/B-203.md).
- **Question text, brief text and file bytes are data, never instructions;** file bytes are tokenized
  (a strings-style pass), never executed.

## 52. Constructed-marker fallback and convention knowledge base (B-119)

A constructed marker is a digest (usually the first hex characters of a SHA-256) of several evidence
values joined in an order and in spellings the author chose. The files do not determine the field set,
the order or the renderings, so this is a hard-tail item: nothing here claims a convention. What is
automated is the extraction of named values, the enumeration of field subset x order x rendering x
join, the hashing, an offline check against a witness (a hex tag the files carry for the same digest),
and a knowledge base of conventions the judge has accepted, kept as data in the label seed store
(section 18, B-040). The engine is `common.marker_convention`; the command is `ctf marker` (section 8).

```python
from solvers.common import marker_convention as mc, render_candidates as RC, labels
f = mc.make_field(name, value, kind=None, sources=())     # Field(name, value, kind, sources); .stored .to_dict()
mc.parse_field("name[:kind]=value"); mc.infer_kind(value); mc.role(name)     # kinds: mc.KINDS
mc.renderings(f, prior=())            # [(rendering name, text)], the stored spelling first, then RC's
mc.render_table(f)                    # {rendering name: text}, every name (two may spell one text)
form = mc.DigestForm.parse("sha256[:8]")   # DigestForm(algo, head, tail, upper); .name .apply(hexdigest)
mc.forms_from_brief(text)             # the cuts a brief states (`8_lowercase_hex`), [] when none: per stated
                                      # length, one form per algorithm of mc.brief_algos(text)
w = mc.parse_witness("9f3c21aa@suffix")    # Witness(token, where, source); .match(hexdigest) .places(size)
docs, notes = mc.load_handout(challenge_dir); mc.handout_files(challenge_dir); mc.read_brief(challenge_dir)
fields, notes = mc.extract_fields(docs, brief="")
witnesses, notes = mc.find_witnesses(docs)   # at most mc.MAX_FILE_WITNESSES tags; the note names the cut
held, whole = mc.containers(docs)     # {archive: a member it holds}: never a second source for its member
conv = mc.Convention.parse(name)      # Convention(digest, join, parts); .name .roles .preimage(fields)
rep = mc.search(fields, digests, witnesses=(), family="any", kb=None, budget=mc.DEFAULT_BUDGET,
                top=mc.DEFAULT_TOP, min_fields=None, max_deviations=None, permute=True, wrap=None)
# Report(family, fields, digests, witnesses, candidates, space, enumerated, witness_hits, kb_available,
#        notes); .exhausted .supported .kinds() .to_dict()
# Candidate(rank, flag, marker, convention, preimage, basis, detail)
#   basis: witness | witness-weak | kb | kb-recut | prior   (only witness and kb make a report `supported`)
flags, unsure = mc.pick(rep)          # <= labels.MAX_OPTIONS flags through labels.candidates
plan = mc.send_plan(rep, profile, guesses_left, allow_nonstandard=False)   # Plan(send, held, reasoned, guesses_left)
kb = mc.KB()                          # .available .reason .accepted(family) .rejected(family) .joins()
                                      # .digests() .renders(kind) .families()
mc.learn(family, convention, verdict, kinds=None, challenge_id=None)       # [(key, name)] rows written
mc.convention_key(family); mc.family_name(family); mc.wrapper(profile, nonstandard=False)
report, unused, notes = mc.run(challenge_dir, profile, **opts)
mc.solve(challenge_dir, profile, **opts)                                    # the engine entry: a SolverResult
# mc.MarkerError (a ValueError); mc.ENGINE_ID, KB_LANE, DEFAULT_FORMS, CHANCE_LIMIT, MAX_FILE_WITNESSES, WHERE,
# WITNESS_LABELS
RC.compose_axis(fields, joins=None, min_fields=1, max_fields=None, max_deviations=None, permute=True, limit=None)
RC.compose_size(fields, joins=None, min_fields=1, max_fields=None, max_deviations=None, permute=True)
RC.render_named(value, kind)          # every (name, text) of a kind, not de-duplicated, not capped
RC.render(value, "decimal")           # dp_1 .. dp_8, dp_0, shortest, as_stored; RC.JOINS, RC.COMPOSE_MAX_FIELDS
labels.keys(prefix)                   # keys with state under a prefix, candidate keys included
```

- **Spelling lives in `render_candidates`.** A field's renderings are the stored spelling
  (`as_stored`) followed by `render_candidates`' spellings for its kind (`tag`: the hex of its bytes,
  `0x` and bare, both cases; `hexid`; `integer`; `timestamp`: ISO 8601 forms and epoch; `decimal`:
  fixed decimal places). `compose_axis` yields `Composed(fields, renders, join, text)` best first:
  fewest fields off their first rendering, larger subsets before smaller, the given order before other
  orders, joins in `JOINS` order (colon first; one field alone is not joined). It is for offline
  comparison only and is never capped at `labels.MAX_OPTIONS`; `compose_size` is the size of the same
  space. The `decimal` kind, `render_named` and the composition axis are not reached by `classify`, so
  no existing candidate list changed.
- **Ranking** (`search`). Witness hits first, strong before weak: a hit is strong when the number of
  chance matches expected is under `CHANCE_LIMIT`. The number is `texts x algorithms x` the sum, over
  every witness compared whose tag is at least as long as the one that hit, of `positions /
  16^len(token)`: a hit among many tags of its length is weak, and a longer tag is not weakened by
  shorter ones. `find_witnesses` takes at most `MAX_FILE_WITNESSES` (32) tags from the files and
  names the rest in a note (a log of hashes is not that many checks); a caller's witnesses are never
  cut. Then the conventions the judge accepted for the family, where every role is among the fields.
  When `digests` is given (the brief or the caller states the cut) and an accepted convention was
  cut another way, the stated cut wins: its fields, order and renderings are listed under each stated
  form with basis `kb-recut` and a note, ahead of the prior. That is a guess (not `supported`, so
  `unsure` and never the reasoned value of a plan); with no stated digest an accepted convention
  keeps its own. Then the prior: the compositions that deviate least from "every field, given
  order, first rendering, first join" (one point per re-rendered field, one for another order, two per
  field left out, up to three for a later join), for each digest form in turn; the first forms of
  different algorithms alternate, so an algorithm read from the brief's prose never hides SHA-256. A
  convention the judge rejected for the family is left out, unless a strong witness in this challenge
  confirms it: the rejection was the judge's answer for other values, the witness is this challenge's
  own check, and the candidate and a note say so. One flag is listed once; `budget` caps the texts
  hashed and the report states how much of the space that covered.
- **The brief's digest** (`forms_from_brief`). A length is read by shape (`N hex`). One inside the
  braces of a flag format (`{8_lowercase_hex}`) or after `first` or `last` ("the first 16 hex"; `last`
  cuts the tail, `sha256[-8:]`) is about the answer; one that stands anywhere else ("addresses are 4
  hex digits wide") is used only when the brief states none of the first sort. Every distinct length
  left gets its forms, in the order stated, and `run` notes it when there is more than one. An
  algorithm's name must start a word (`cmd5` and `Geisha-1` name none). SHA-256 alone when the brief
  names it; when it names only other
  algorithms (`md5`, `sha1`, `sha512`) each gets a form, in the order named, and SHA-256 follows: a
  name in prose may be about a download's checksum. `run` notes it when more than one is hashed.
- **Never a claim, never a send.** `solve` returns `candidate` only when the first value is backed by
  a strong witness or a family-accepted convention, `unsure` when the list is ranked by priors alone,
  `none` with no field or candidate, `blocked` for a bad option; never `solved`.
- **Not run at intake.** The manifest has no `[intake]` table and must not get one. Intake (section
  19) took an engine's flags whatever its result status and called one distinct flag `solved`, which
  `ctf intake --submit` may send; this engine's one flag can be a convention learned on another
  challenge. (Since B-090 a flag only `candidate`-status engines found stays an intake `candidate`;
  the rule stands anyway.) The router lists the engine (`engines_without_adapter` in the intake report) and the
  agent runs `ctf marker candidates`. Its route holds marker phrases only ("resulting marker",
  "recover its marker", "build/construct/submit the marker", "consensus marker"): a hex answer shape
  ("32 lowercase hex characters") is any flag format and does not route here.
  `tests/test_common_marker_intake.py` drives the real `intake_one` and fails if the table comes
  back; the router cases in `tests/test_common_marker_extract.py` fail if a shape keyword does.
- **The pick and the plan.** `pick` hands on at most `labels.MAX_OPTIONS` flags
  through `labels.candidates` on the family's convention key (an accepted convention answers alone;
  a strong witness outranks it and keeps the ranked list). `send_plan` cuts the ranked list with
  `flagcheck.VariantSet.plan` (section 40): a backed first candidate is the reasoned value and the
  rest are guesses; an unbacked first candidate is itself a guess. Everything past
  `rules.guess_budget` is held for the player's sweep (section 25). No code path here submits, and
  none bypasses the wrong-answer count.
- **Knowledge base.** Labels lane `marker` (`labels.TOOLKIT_PREFIXES`), seed
  `solvers/toolkits/seeds/marker/conventions.json`, runtime ledger `<workdir>/_ledger/marker.jsonl`,
  folded by `ctf seed-fold marker`. Keys: `marker.convention/<family>#candidates` (names are
  `Convention.name`: `<digest>;<join>;<role>=<rendering>,...`, `-` for the join of one field),
  `marker.join/<family>`, `marker.digest/<family>`, `marker.render/<kind>.<family>`. `learn` writes
  the convention row for either verdict and, for `accepted`, the join, the digest form and each
  rendering that differs from the stored spelling under its value's kind; a rendering equal to the
  stored spelling is not recorded. The join, digest and rendering rows of every family reorder the
  axes for all families. Without a judge ledger (`CTF_JUDGE_LEDGER=off`) the base is not read, the
  report says so, and `learn` raises `MarkerError`.
- **Extraction** (`extract_fields`) reads JSON leaves (a real number keeps the file's spelling:
  `12.5000` is stored as `12.5000`), XML attributes and leaf elements (a document declaring a DTD or
  an entity is not parsed), `key: value` lines and a binary's four-character ASCII magic; a value is
  corroborated when two sources hold it (another file names it, or a spelling of it at least three
  characters long stands as a whole token in another file or the brief). A run of more than 12 digits
  is an identifier (`text`), from a JSON number as from a string. A value shaped like a kind it
  cannot be rendered in (`2031-02-30T04:05:06Z`) is kept as `text`, and one that cannot be a field
  (a name with no letter or digit) is left out; a note names both. Two timestamps are one value only
  when they agree to the last sub-second digit. A file that holds another evidence
  file is no source (`containers`): an archive intake unpacked (`<archive>.unpacked/`), or a binary
  that holds another file's bytes whole (a tar, a stored zip, an image). A text file is never taken
  for a container. With no `fields` option only corroborated values are used, `DEFAULT_MAX_FIELDS`
  at most. Captures and binaries are not decoded here: values a protocol engine read are passed as
  `fields`. Every cut (file size, file count, repeated names, the scan limits, a container, a JSON
  file nested too deeply to parse) is a note in the result. A value labelled `tag`, `witness`,
  `checksum`... with 8 or more hex characters is a witness, never a field. A directory or file whose
  name starts with a dot is never read (`.ctf/` holds credentials), nor is a symlink; the workspace's
  own files (`challenge.json`, `notes.md`, `tried.json`, `flag.txt`) are skipped at the top of a bare
  folder only.

## 53. Set-to-delivery pairing (B-042)

A Mastery asks the same questions of several sets (`set1.<id>`, `set2.<id>`, ...) and ships each set its
own file: one delivery per set, often all with one file name (`blob.txt`, `evidence.zip`) and the same
member names, or one bundle holding a numbered member per set. `ctf/deliveries.py` is the one rule for
which delivery is a set's own, and it fails closed: a set whose delivery is not proven gets none, with the
reason, never the nearest one. Its module docstring is the source of truth; change it and this section
together.

```python
from ctf import deliveries
deliveries.set_of(question) -> int                 # N of a leading setN. in the id, else an int `set` field, else 0
deliveries.named_delivery(question) -> int | None  # K when the artifact text starts `delivery K:`
deliveries.chain(question) -> list[str]            # the container chain it names, without that head
deliveries.choose(n, questions, sets, count, members=None) -> Choice     # one set
deliveries.plan(attempt, members=None, count=None) -> list[Choice]       # every set, in set order
Choice(set, rule, index, member, reason).mapped / .label(names) / .to_dict()   # index: 0-based delivery
deliveries.ALL | NAMED | POSITION | MEMBER | UNMAPPED
deliveries.read_attempt(folder_or_attempt_json) -> Saved(attempt, names, blobs, folder)   # DeliveryError
deliveries.is_attempt(path) -> bool                # a regular file named attempt.json
deliveries.bundle_members(name, data, attempt=None) -> {member: bytes}   # top level, the runner's expander
deliveries.set_inputs(saved) -> [SetInput(choice, label, name, data)]    # each set's own bytes
deliveries.unsolved_line(n, ctx) -> str            # the error line of a set a solver never read
deliveries.is_unsolved_line(line) -> bool          # True for such a line (NOT_DOWNLOADED | UNPROVEN)
```

**Rules**, in the order they are tried:

| rule | holds when | the set reads |
|---|---|---|
| `all` | the attempt has one set (also with no delivery at all) | every delivery. One numbered set whose questions all name the same one of several deliveries reads that one (`named`) |
| `named` | every question of the set that names a delivery (`delivery 2: evidence.zip -> x.ps1`, at the start of its `artifact` text) names the same one, and the attempt has it | that delivery, whatever the set order says |
| `position` | no question of the set names a delivery, there are several deliveries, and the set numbers are exactly 1..<deliveries> | delivery N for set N |
| `member` | one delivery for several sets, with one top-level member numbered N just before its extension (`idresolve.SET_MEMBERS`); with several such members, the one the set's questions name first in their chain | that member, as the set's delivery |
| `unmapped` | nothing above | nothing. `reason` names it: questions naming two deliveries, a delivery number the attempt does not have, set numbers that do not pair with the deliveries, a bundle with no member or no single member for the set, a multi-set attempt with no delivery |

A bundle with no numbered member is read whole by a set only when every question of the set says
`delivery 1:` (rule `named`). `choose` raises `DeliveryError` when one delivery serves several sets and
the caller passed no member names.

**The runner.** `tools/run.py` `split_sets(attempt, blobs, locked=None, notes=None)` takes every set's
delivery from `choose` (a bundle's member names from its own expansion), so each runner, replay, gate
and lane self-test that splits an attempt gets this pairing. A mapped set's ctx is unchanged (`set`,
`delivery_name`, `delivery`, `attempt`, and for a multi-set attempt `siblings`, `delivery_id`,
`delivery_state`, `siblings_total_bytes`, `siblings_limit_bytes`). An unmapped set gets no files,
`delivery_name` None, `delivery` b"", `ctx["delivery_unmapped"]` = the reason, no entry in `siblings`,
and one line `set N: no delivery is proven to be its own (<reason>); ...` in `notes` (on stderr as
`NOTE ...` when no list is passed). `run.solve_all`, `setpool.solve` and the Huntress timed runner's
serial `solve` do not call the solver for it and put `unsolved_line(n, ctx)` in `errors`: the reason,
or `its delivery was not downloaded` for a mapped set whose bytes never arrived. When a second pass
finishes every set a cut first pass left (row 256), `run.fold_cut_lines` keeps those lines as errors
(`is_unsolved_line`) and turns the other cut lines into `first pass:` NOTEs. The binary speed path
(`speedrun/solvers/binary_par.py` `pairing`) takes the same `choose` and hands the attempt back to the
serial path when a set is unmapped, one set reads several deliveries, or one bundle serves several
sets. Before B-042 such a set read the last delivery or the whole bundle.

**Where a bundle is expanded.** `bundle_members` (and so `set_inputs` on a one-bundle attempt with
several sets) expands the bundle in the calling process with the runner's expander
(`tools/archive_expand.py`, which runs 7-Zip for a 7z member when it is installed), one level deep and
under that expander's own member-size and depth limits: in `python -m ctf deliveries` and in the
`ctf arm` / lane-gate parent (`ctf.openers.sets`), not inside the guarded engine process. Only each
set's engine run is guarded. The inputs are the case's own synthetic fixtures or a saved attempt the
operator names; a bundle that should not be opened outside the guard is not given to these commands.

**A saved attempt** is `attempt.json` beside `artifact/<file>` (one delivery) or
`artifact/delivery-NN/<file>` (several), the layout the runners save and the Game Master adapter's
`download_files(cid, <folder>/artifact)` writes. `read_attempt` checks each delivery against the
attempt's `sha256` when it states one. `DeliveryError`: no `attempt.json`, not an attempt, a delivery
that is missing, a symlink, changed, or named with a path, an unnamed delivery whose folder does not hold
exactly one file.

**Command.** `python -m ctf deliveries ATTEMPT [--json]` prints the pairing (section 8). Exit 0 every
set paired, 1 a set is unmapped, 2 unreadable.

---

## 54. Runtime semantic adapters in pinned containers (B-242)

`binary.runtime_trace` runs a delivered managed or bytecode artifact for a short, bounded trace and
reports what it did: the entry points, what each returns on a few probe inputs, what it printed, and
the strings it built at run time. It is the only engine of the master that executes a delivered
file, so the path is fixed end to end:

| step | where | rule |
|---|---|---|
| may it run at all | `eventpolicy.execution_refusal(profile)` (section 25) | `rules.sandboxed_execution` must be `"allowed"`; otherwise the result is `blocked` naming the key, and no container is asked for |
| what runs it | `solvers/binary/_runtime_plans.py` | an inert `RuntimePlan`: image name, runner argv, fuel, time, limits |
| where it runs | `tools/sandbox.py` `runtime_run` | one fresh `docker run --rm` container per call: `--network none`, no mount of any kind, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, uid 10001, CPU / memory / pids limits, a tmpfs `/tmp` and `/work`. Nothing is ever run on the host |
| which image | `tools/images.toml` (`runtime-*`, section 37), `docker/runtime/` | the image must carry the label `org.ctf-tools.toolchain.hash` equal to `images.content_hash(image)` and is run by its image id; a missing, unlabelled or stale image is `SandboxDown` naming the build command. Every base image is an exact tag and its digest |
| in and out | `docker/runtime/entry.sh` | the request is an uncompressed tar on stdin (`artifact.bin`, `dep/NNN.bin`: names fixed by `runtime_run`, never taken from a delivered file); the runner prints one line `@@CTF-RUNTIME-TRACE@@ <json>` on stdout |

Runtimes and their fuel:

| runtime | reads | image(s) | fuel |
|---|---|---|---|
| `wasm` | a core WebAssembly module (version 1) | `runtime-wasm` | wasmtime fuel (instructions) |
| `python` | a `.pyc`, by its magic number; `.py` when named | `runtime-python-3.8` ... `runtime-python-3.14` | bytecode instructions |
| `lua` | Lua source or bytecode 5.1 to 5.4, LuaJIT bytecode | `runtime-lua` (five interpreters) | VM instructions |
| `jvm` | a Java `.class` or a jar | `runtime-jvm` | wall time |
| `dotnet` | a PE with a CLR header (a CIL assembly) | `runtime-dotnet` | wall time |
| `node` | V8 cached data (`.jsc`), tried on each Node line; JavaScript when named or unpacked | `runtime-node-24`, `-22`, `-20` | wall time |

```python
# solvers/binary/_runtime_plans.py (a helper, loaded by path; pure functions, nothing is opened or run)
target = plans.classify(data, name="", source=False)   # Target(runtime, variants, kind, note) | None
plan = plans.build_plan(runtime, variant="", fuel=None, seconds=30, probes=(), max_events=512)
# RuntimePlan(runtime, variant, image, argv, fuel, fuel_kind, seconds, container_seconds, probes,
#             network="none", mounts=(), read_only_root=True, drop_capabilities=("ALL",),
#             user="10001:10001", memory="768m", cpus="1", pids=96); plan.to_dict()
members = plans.request_members(artifact, deps=())      # [("artifact.bin", bytes), ("dep/000.bin", bytes), ...]
trace = plans.parse_trace(stdout, runtime)              # Trace; TraceError when it is not one valid trace
# Trace(runtime, runtime_version, status ok|partial|error, fuel_kind, fuel_limit, fuel_used,
#       fuel_exhausted, entries ((name, signature), ...), events ({"kind": ..., field: text}, ...),
#       strings, notes, truncated); trace.texts(); trace.errors(); trace.to_dict()
# errors: plans.PlanError (a bound or variant out of range), plans.TraceError (both ValueError)

# tools/sandbox.py (the only place a runtime container is started)
image_id = sandbox.runtime_image(tag, want_hash, build_hint="")   # "sha256:..."; SandboxDown when not built / unlabelled / stale
argv = sandbox.runtime_argv(image_id, name, seconds, argv, memory="768m", cpus="1", pids=96)   # the docker run arguments
blob = sandbox.runtime_request(members)                           # the request tar; ValueError for any other member name
res = sandbox.runtime_run(tag, want_hash, argv, members, seconds, memory="768m", cpus="1", pids=96, build_hint="")
# Result(code, stdout, stderr, files={}, out_dir=None, seconds); code 124 = stopped at the time limit

# solvers/binary/runtime_trace.py
result = runtime_trace.solve(challenge_dir, profile, **opts)    # opts: only, probe, fuel, seconds; any other -> blocked
# python -m ctf run binary.runtime_trace <challenge_dir> --event <slug> [--opt only=files/x.jar]
#                                        [--opt probe=TEXT] [--opt seconds=N] [--opt fuel=N]
result = runtime_trace.trace_challenge(challenge_dir, profile, only=None, probe=None, fuel=None, seconds=None,
                                       budget=600.0, clock=time.monotonic)   # the whole call's budget: not an --opt
```

- **What is traced.** The handout (`files/` and the folder root), `recon/unpack/` (B-054: bundle
  assemblies, a Node SEA main script) and `recon/recover/` (B-167: the `.pyc` files of a PyInstaller
  archive); nothing is extracted again. Bytecode and binary kinds are told by magic number. Source
  text in the handout is traced only with `only=<path>` (a path inside the challenge folder; a
  symlink or a path outside it is refused). Symlinks are never followed; identical bytes are taken
  once; at most `runtime_trace.MAX_ARTIFACTS` artifacts per call, kept by `runtime_trace.rank`: a
  .NET entry assembly (a sibling `<name>.runtimeconfig.json` / `<name>.deps.json`, or the name of its
  `recon/unpack/<host>/` folder) first, framework assemblies (`System.*`, `Microsoft.*`, `mscorlib`,
  `netstandard`, ...) last, the rest in walk order; the ones left out are named. For a JVM or .NET
  artifact the other regular files (never a symlink) of its own folder that the same runtime reads go
  along as dependencies.
- **Options.** `only`, `probe`, `fuel`, `seconds` and nothing else: an unknown option (a typo such as
  `onyl`) is `blocked` before anything is looked at, so it never widens a run. The policy gate holds
  whatever the options and wherever an artifact came from.
- **Routing.** `reverse` at 36 and `misc` / `pwn` at 28 for a format it runs (Wasm, class, jar,
  `.pyc`, Lua bytecode, `.jsc`); `reverse` at 22 for any `.dll` / `.exe` (a file matcher cannot read
  the CLR header; the scan gives `none` for a native PE).
- **Statuses.** `blocked`: the event forbids it, an option is out of bounds, or no container could
  run (the notes name the image and `python -m ctf toolchain build --apply --only <image>`).
  `candidate`: a trace holds a string in the event flag format (never `solved`: the trace is produced
  beside the artifact). `none`: nothing to trace, or every artifact traced to completion with no
  flag. `unsure`: a partial trace (fuel or time ran out, a call failed), an artifact its runtime did
  not load, a run that gave no trace, or a file left out, each named in the notes. A recognised file
  no image reads (an unknown `.pyc` magic, a WebAssembly component) and IL2CPP metadata or a Dart /
  Flutter snapshot (no adapter) are named in the notes and are never a clean `none`.
- **The trace** is written to `recon/runtime/<file>-<hash>/trace.json` with the artifact's path,
  SHA-256, the plan and the image tag. It is untrusted data: every field is a bounded string, lists
  are capped (`_runtime_plans.MAX_TRACE_*`), and nothing in it is executed or followed.
- **Runner contract** (`docker/runtime/<runtime>/`): `<runner> --artifact FILE --deps DIR --fuel N
  --seconds S --max-events N [--probe-hex HEX]...`; exit status 0 with a trace line for any artifact,
  including one that does not load (`status: "error"`). Each Dockerfile runs the runner on a fixture
  of `docker/runtime/selftest/` at build time and fails the build unless the trace holds the string
  the fixture computes; the image's `smoke` command repeats that check the way `runtime_run` does: the
  fixture as the request tar, through the entry script, under `build_plan`'s exact argv for every
  variant the image serves. The entry script stops the runner with TERM at the limit and KILL two
  seconds later.
- **Where instruction fuel does not reach.** Instruction fuel counts interpreted instructions only.
  Lua: one long C call (`string.rep`, a pathological `string.find` pattern, a huge `table.concat`)
  runs no VM instruction and is ended only by the container's time and memory limits (no trace comes
  back, exit 124); a `__gc` finalizer would run with the hook off, so the runner never arms one (the
  field is hidden while `setmetatable` runs, the chunk still sees its own metatable, a `refused`
  event named `__gc` is recorded) and exits without `lua_close`. Python: the same holds for one long
  C call (see B-242's build log).
- **Not at intake.** The engine has no `[intake]` table: it executes a delivered file, so it is run
  on purpose, for an event whose profile allows it.
- **Under `CTF_TESTING`** `runtime_run` refuses any docker that is not a test stub (the marker of
  section 37), so no test starts a real container.

---

## 55. Disk-image boot harness and shipped-client User-Agent replay (B-131)

Two modules, each with a CLI command (section 8) and a thin engine. The module docstrings are the full
contract; the operator's procedure is `docs/runbooks/disk-boot.md`.

**Boot harness** (`ctf/diskboot.py`, engine `metadata_forensics.disk_boot`, image `ctf-qemu-boot:1` in
`tools/images.toml`, section 37). Booting a challenge disk image runs challenge code, so:

```python
from ctf import diskboot
infos = diskboot.find_images(challenge_dir)        # [ImageInfo(path, format, table, firmware, role, size, why)], boot first
diskboot.identify(path, rel=None)                  # one file -> ImageInfo | None (structure only: never mounted, never run)
plan = diskboot.plan(challenge_dir, infos=None, out_dir=None, firmware="auto", memory_mb=2048, cpus=2,
                     machine="q35", drive_if="ide", script=None, root=None)
# BootPlan(challenge_dir, out_dir, image, image_tag, container, firmware, images, qemu_argv, start_argv,
#          qmp_argv, guest_out, script, notes, options); .to_dict(); BootPlan.from_dict(d). Runs and writes nothing.
#          options = plan()'s own arguments {firmware, memory_mb, cpus, machine, drive_if}, so it can be re-made.
diskboot.check_plan(plan, root)                    # None, or BootError: not what plan() writes for its folder now
approval = diskboot.approve_interactive(plan, reason, stdin=None, stdout=None, prompt=input)
# Approval(challenge_dir, by, reason, argv): sealed by approve_interactive; built by hand or replace()d it is refused
session = diskboot.start(plan, approval, profile=None, environ=None, run=subprocess.run, clock=time.time, root=None)
diskboot.load_session(out_dir, challenge_dir=None); diskboot.connect_session(session, environ=None, timeout=diskboot.QMP_TIMEOUT)
diskboot.end_session(out_dir, environ=None, timeout=diskboot.QMP_TIMEOUT, challenge_dir=None)
qmp = diskboot.QMP.connect(spec, timeout=diskboot.QMP_TIMEOUT, environ=None)   # "unix:PATH" | "tcp:127.0.0.1:PORT" | argv list
qmp.execute(command, **arguments); qmp.status(); qmp.screendump(guest_path); qmp.send_key(chord, hold_ms=None)
qmp.type_text(text); qmp.mouse_rel(dx, dy); qmp.click(button="left"); qmp.quit(); qmp.close(); qmp.events
obs = diskboot.observe(qmp, script, out_dir, guest_out=None, sleep=time.sleep, flag_prefixes=())
# Observation(out_dir, shots=[Shot(file, name, step, width, height, sha256)], duplicates_dropped,
#             animated=[{step, name, box, cropped}], crops, handoff, events); .to_dict()
diskboot.validate_script(script); diskboot.parse_chord(chord); diskboot.text_chords(text)
diskboot.read_ppm(data); diskboot.write_png(frame); diskboot.changed_box(a, b); diskboot.crop(frame, box)
diskboot.container_name(challenge_dir)
# errors: diskboot.BootError (a RuntimeError), diskboot.QMPError (a BootError, with .cls)
```

- **Nothing boots by itself.** `plan` only writes command lines. `start` needs an `Approval`, which
  `approve_interactive(plan, ...)` issues only when stdin and stdout are terminals and the person, shown
  the plan's exact `docker run` command, types the challenge folder's name (`PermissionError`
  otherwise; no flag stands in for it). The approval is sealed (an HMAC over its fields with a
  per-process key) and names the command it showed (`argv`): `start` refuses an `Approval` built by
  hand or changed with `dataclasses.replace`, and one whose `argv` is not the plan's `start_argv`.
  This keeps callers honest; the Python API is not a security boundary against code in the same
  process, the person at the terminal is. `start` refuses a plan whose command is not this harness's
  networkless `docker run` of the manifest image, and (`check_plan`) any plan that is not exactly what
  `plan()` writes for its folder and recorded options now: an edited `plan.json` (an added mount,
  privilege or network, a dropped `-snapshot`), a plan with no `options`, or a folder whose images
  changed is refused, and docker is never run. `ctf disk-boot start` runs `check_plan` before it asks
  the person, and refuses a `plan.json` made for another folder or out folder. `start` refuses a
  second start while a session is recorded, and refuses with the build command when the image is not
  `ok` (`images.status`): it never builds or pulls. Docker is found through `images.docker_path`, so
  under `CTF_TESTING` only a stub docker runs. With a profile, `start` appends the ledger record
  `diskboot.start` after the `docker run` returns: `event_slug`, `challenge_dir` (the folder's name),
  `container`, `image`, `approved_by`, `reason`, `outcome` (`started` | `failed` | `unknown` when
  docker did not return and the container may exist) and, unless started, `detail`. The session is
  `<out_dir>/session.json` (`container`, `image`, `started`, `approved_by`, `reason`, `qmp_argv`,
  `guest_out`). `load_session`, `connect_session` and `end_session` run its `qmp_argv` only when it
  is exactly `docker exec -i ctf-boot-<12 hex> socat - UNIX-CONNECT:/run/boot/qmp.sock` for the
  record's container (and, given `challenge_dir`, for that folder's `container_name`); any other
  command is refused, never run.
- **Networkless, read-only.** The container runs `--network none --pull=never --cap-drop ALL
  --security-opt no-new-privileges --read-only` (the flags of `images.run_argv`), QEMU runs
  `-nic none -snapshot`, the challenge folder is mounted read-only at `/img`, and no port is published:
  QMP is a Unix socket in a tmpfs, reached with `docker exec -i <container> socat - UNIX-CONNECT:...`
  (`plan.qmp_argv`). A shipped client's requests are replayed from outside (below), never by giving the
  guest a network.
- **Ending.** `end_session` sends QMP `quit` (the container was started `--rm`) and renames the
  session record to `session-ended.json`. The harness never runs `docker stop`, `kill` or `rm`: a VM
  that no longer answers is the operator's to remove, by the container name the error prints.
- **QMP.** Negotiates `qmp_capabilities` first; a command's error reply is `QMPError` with QEMU's
  class and description; events that arrive between replies are kept in `.events`; a reply that does
  not arrive within `timeout` seconds is `QMPError` (real elapsed time by nature). TCP is loopback
  only. `type_text` maps a US layout onto qcodes and names the first character it cannot type.
- **Observe script**: a JSON list of one-action steps, validated whole before the first is sent:
  `wait` (seconds), `shot` (a name), `burst` (`name`, `count`, `interval`), `key` (qcodes joined by `-`),
  `type`, `mouse` (`[x, y]`: park top-left, then a relative move), `mouse_rel`, `click` (`left`,
  `middle`, `right`). Screens are converted from QEMU's PPM to PNG (`shots/NNNN-<name>.png`); in a
  burst a frame equal to the last kept one is dropped; a region that changes inside a burst and covers
  at most `diskboot.CROP_MAX_SHARE` of the screen is cropped out of each distinct frame (`crops/`).
- **Vision is handed off.** `observe` writes `<out_dir>/vision-handoff.json` (`needs`, `ask`,
  `flag_prefixes`, `shots`, `duplicates_dropped`, `animated`, `crops`) and stops: what is drawn is read
  by a person or a vision model, and a partial flag is reported as drawn, never completed.
- **Engine** `metadata_forensics.disk_boot` (`solve(challenge_dir, profile, **opts)`, intake adapter on
  disk-image files): identifies the images, writes `recon/boot/plan.json`, and returns `unsure` with
  the operator's next commands (`none` with no image, `blocked` with the reason when no plan can be
  made). It never calls docker.

**Shipped-client replay** (`ctf/clientreplay.py`, engine `web.client_replay`):

```python
from ctf import clientreplay
h = clientreplay.harvest(paths, max_bytes=clientreplay.DEFAULT_MAX_BYTES)   # files or folders, read as data
h = clientreplay.harvest_blobs(files)              # {name: bytes} already in memory
# Harvest(user_agents, urls, files, scanned_bytes, truncated, skipped): .custom_user_agents(), .client_urls(), .to_dict()
# Constant(kind, value, path, offset, encoding, how, stock, near_ua, count)
clientreplay.scan_bytes(data, name="", base=0); clientreplay.is_stock_user_agent(value)
rep = clientreplay.replay(urls, user_agents, profile=None, hops=1, max_requests=clientreplay.DEFAULT_MAX_REQUESTS,
                          max_links=clientreplay.DEFAULT_MAX_LINKS, timeout=clientreplay.DEFAULT_TIMEOUT,
                          max_bytes=clientreplay.MAX_BODY, baseline_ua=clientreplay.DEFAULT_BASELINE_UA,
                          interval=clientreplay.DEFAULT_INTERVAL, sleep=time.sleep, connect=None)
# ReplayReport(user_agents, baseline_ua, hops, requests, responses, diffs, refused, flags, fragments, capped,
#              not_fetched, skipped_assets): .gated(), .operator_steps(), .to_dict()
# Response(url, ua, status, final_url, content_type, length, sha256, body, error, truncated)
# Diff(url, ua, hop, parent, what, unstable, excerpt); Refusal(url, reason, hop, parent, via)
# FlagHit(value, url, ua, ua_only); Fragment(kind, value, url, ua)
clientreplay.get(url, ua, profile=None, timeout=clientreplay.DEFAULT_TIMEOUT, max_bytes=clientreplay.MAX_BODY, connect=None)
clientreplay.links_of(body, base_url, content_type=""); clientreplay.is_asset(url); clientreplay.compare(base, other)
clientreplay.find_fragments(base_body, ua_body, profile); clientreplay.join_fragments(head, tail, profile)
gs = clientreplay.guess_stop(profile, challenge_id, workdir=None)
# GuessStop(challenge_id, wrong, wrong_answer_stop, approved_extras, guesses_used, guess_budget): .stopped, .guesses_left, .line()
# error: clientreplay.ReplayError (a ValueError)
```

- **Harvest** is offline. Files are read as bytes in windows (never executed or imported): a raw disk
  image as it lies, zip members through the zip, ASCII and UTF-16LE. A path with a `.ctf` or `.git`
  part and this item's own output (`recon/client`, `recon/boot`) are never opened; symbolic links are
  not followed. A User-Agent is taken from a quoted value, a header line or an assignment shaped like
  `product/1.0` after the name; `how = "nearby"` marks a quoted `product/1.0` string near a name whose
  value is a variable; templates are dropped; a library or browser value is `stock`. A URL is
  `near_ua` within `clientreplay.NEAR` bytes of a custom User-Agent in the same file. The byte budget
  is explicit and a file cut short by it is listed in `truncated`.
- **Replay** sends GET only, with no cookies. Every seed URL, redirect target and link passes
  `scope.check_url` under the event profile before a connection (section 13), in `replay` and again in
  `get`; a refused URL becomes a `Refusal` (`via`: `seed`, `link`, `redirect`) and one line of
  `operator_steps()`. Per allowed URL: one normal request (`baseline_ua`) and one per shipped
  User-Agent, compared on status, final URL, content type and body; a body-only difference is
  re-checked with a second normal request and marked `unstable` when the page changes by itself. Links
  (href, src, action, bare URLs) are followed to depth `hops`; static assets are skipped and counted;
  `max_requests` and `max_links` are caps whose leftovers are named in `not_fetched`.
- **Flags and fragments.** A `FlagHit` is `ua_only` when only a shipped User-Agent received the value
  on a stable page. A `Fragment` is a `tail` (closed by `}` with no `{`) or a `head` (a flag prefix and
  `{`, never closed) on a line the normal reply lacks. `join_fragments` returns `head + tail` only when
  that is exactly one flag in the event's format; it inserts, trims and re-cases nothing.
- **Guess stop.** `guess_stop` reads the submit gate's own counters (`EventRules.wrong_count`,
  `EventRules.guesses_used`, section 5) against `rules.wrong_answer_stop` and `rules.guess_budget` as
  `eventpolicy.summary` resolves them (section 25). It refuses nothing itself: the gate does.
- **Engine** `web.client_replay` (`solve(challenge_dir, profile, **opts)`): offline by default (what
  intake runs): the custom User-Agents, the client URLs and whether the scope allows each, written to
  `recon/client/constants.json`. With `replay=true` it runs the replay (`recon/client/replay.json`).
  `solved` only for a `ua_only` flag; `candidate` for a flag the normal request received too, or for
  the option `head` joined to a received tail; `unsure` for a User-Agent-only reply, a fragment or
  refused client URLs; `none`; `blocked` with the reason. Options: `replay`, `head`, `url`,
  `user_agent`, `hops`, `max_requests`, `include_stock`, `max_bytes`, `challenge_id`, `interval`.
- **Hooks.** `fastlane.try_shipped_client(detail, files_dir)` (the last fast-lane class: an offline
  harvest within `fastlane.CLIENT_SCAN_BYTES`, returning a flagless instruction, never a fetch; only a
  `direct` custom User-Agent triggers it, a `nearby` one is left to the engine; a handout it cannot
  read returns None after a WARNING on the `ctf.fastlane` logger naming the error) and
  `web_evidence.client_constants(files)` (the harvest over a `{name: bytes}` delivery).
- **Replay service for tests** (`ctf/livereplay.py`): a `web` route may carry `variants` (`when`: request
  headers that must match exactly), and the service keeps every request in `.requests`.

---

## 56. TI-Nspire documents (B-132)

`solvers/toolkits/tns_nspire.py` (engine `toolkits.tns_nspire`) reads the `*TIMLP` zip variant. Its top
level imports the standard library only, so `tools/archive_expand.py` loads it by path.

```python
import tns_nspire as T
box = T.read_container(data, max_member=T.MAX_MEMBER)   # Container(version, members, notes); TnsError when
                                                        #   the bytes do not start as a document
# Member(name, method, csize, usize, crc, offset, data, encoding, crc_ok, problem, note, missing):
#   data is the content (method 0 stored, 8 raw deflate, 13 decrypted then inflated; a TIXC stream is the
#   XML it decodes to, checked against the header's size and CRC-32); data None -> problem says why
box = T.headers(data); T.read_member(m, data, max_member)   # the lazy form: one member decoded at a time,
                                                        #   so a caller with a total budget checks it first
T.is_document(m) -> bool                                # a page or settings XML: where a decoy sits
T.method13_decrypt(raw) -> bytes                        # the deflate stream; ToolMissing without pycryptodomex
T.expand_key(packed21) -> bytes; T.tixc_decode(stream, cap=T.MAX_MEMBER) -> bytes
page = T.parse_page(xml, name)                          # Page(points, segments, texts, other, notes) | None
png = T.render_page(page, width=T.RENDER_WIDTH)         # y up; hidden objects red; free text objects blue
T.index_decodes({name: text}, ff) -> [(flag, how, source)]
T.examine(files, ff, out_dir=None, ocr="auto", read=None, deadline=None, prefixes=()) -> Report
T.solve(challenge_dir, profile, out=..., ocr="auto|on|off", seconds=30, challenge_id=..., read=...)
```

- **Status.** One flag read from a member as it stands or decoded from an index list is `solved`; a
  flag read by OCR, flag-shaped text in a document page, or several values are `candidate`; a
  rendered page with no flag is `unsure`; `blocked` names the missing module (`py:Cryptodome`,
  `py:PIL`) or tesseract under `ocr=on`; else `none`. Page text is evidence kind `decoy` only while
  no script or index list proves the same value (OCR does not: the rendering draws the typed text);
  a proven value's page sighting is a `match` item (`"<flag>: also ..."`), so the engine and intake
  agree.
- **Limits.** `MAX_MEMBER` per member, `MAX_TOTAL` decoded bytes per handout (examine reads members
  one at a time against it and names the first it leaves unread), `MAX_MEMBERS`, `MAX_DOCS`.
- **Output.** `<challenge>/recon/tns_nspire/`: every member as its content, a PNG per drawn page,
  `report.json` (schema 1). Member names are made safe, and two handouts whose paths make one folder
  name get `-2`, `-3` (compared without case); nothing in a document is executed.
- **Intake.** `[intake] select = "files"`, `run = "challenge"`, `match = ["magic:*TIMLP"]`, `spawns =
  false`, `needs_tools = ["py:Cryptodome"]`: Pillow and tesseract are optional (the result names what
  it lacked), and under the audit-hook guard the tesseract call is refused and noted.
- **The sweep's walk.** `tools/archive_expand.py` opens a `*TIMLP` document under `opts=Walk()` only
  (the legacy walk leaves it opaque): each member is decoded one at a time into the room the walk's
  budgets leave, recorded as its content under `"<doc> -> <member>"`; a member not read is a note
  naming why. A document page member is put in `Walk.doubt`, so the sweep disputes a flag found only
  there (section 4) and intake stands down without this engine (section 19, step 5).
- **Fingerprint.** `ctf/formats/magic.toml` has the `ti_nspire_tns` row, so an unnamed `*TIMLP` member
  is named offline with this engine's id.

---

## 57. Discord recon (B-112)

Some challenges keep their flag in the event's Discord server: a recognition word in a hidden channel's
description, a flag spelled by the first character of each rules bullet, an author's profile, the
server's expressions. The server is captured once into a snapshot and analysed with no model.

Three ways in, all ending as items in `<workdir>/discord/snapshot.json` (owner-only):

1. a text paste the player saves (`ctf discord ingest FILE --where PLACE --kind KIND`, `-` for stdin);
2. a chat exporter's one-channel JSON (`guild`, `channel`, `messages`);
3. `ctf discord capture`, the bot API client, only when the profile's `[discord] capture = "bot"`.

Joining the server, the onboarding clicks, and checking that the event's rules and Discord's terms
allow a capture are human steps (`ctf discord checklist`, a `discord` task card of section 1's
`[human]` work). Nothing reads the local Discord app's data: `refuse_app_data` rejects a path inside a
Discord client folder, which the solver fence (section 14) denies as well.

```python
from ctf import discordrecon as dr
snap = dr.load(dr.snapshot_path(workdir))        # DiscordReconError naming the human step when absent;
                                                 # a path inside a Discord client folder is refused
snap = dr.load_or_new(path); dr.save(snap, path)
snap.add(items, source="paste", notes=(), now=None)   # merge, deduplicated by (kind, where, text); how many were new
snap.counts(); snap.notes(); snap.to_dict(); dr.Snapshot.from_dict(d)   # strict: unknown keys are refused
dr.Item(kind, where, text, author="", seq=0, source="paste")   # kind in dr.KINDS (dr.NAME_KINDS + dr.TEXT_KINDS)
dr.ingest_text(text, where="#rules", kind="rules", source="paste", author="")   # one item, lines kept
dr.ingest_export(obj, source="export")           # (guild, items) from a chat exporter's channel JSON
dr.ingest_file(path, as_="auto", where=None, kind=None)   # (guild, items, "snapshot" | "export" | "text")
dr.message_text(msg)                             # content, embeds, attachment and sticker names, a poll
dr.refuse_app_data(path)                         # the resolved path, or DiscordReconError
rep = dr.analyze(snap, profile, cues=(), brief="", decode=True)   # dr.Report
rep.candidates; rep.readings; rep.notes; rep.flags(decoys=False); rep.to_dict()
# dr.Candidate(value, kind, where, item_kind, how, score, in_format, wrapped); dr.Reading(text, where, how, prefixed)
dr.cue_words(name, description)                  # the challenge's content words, for `cues`
dr.read_challenge(challenge_dir)                 # {"id", "name", "description", "discord_only", "bare"} from
                                                 # challenge.json; bare: no files, no target (None: no json)
dr.analyze_challenge(snap, profile, challenge_dir, extra_cues=(), decode=True, write=True, top=50)
                                                 # (Report, <challenge>/recon/discord.md | None)
dr.report_title(ch); dr.render_report(rep, title="Discord recon candidates", top=None)
dr.checklist(snap)                               # [dr.Place(key, ask, kinds, by_bot, have)]; .done
dr.render_checklist(places, capture="forbidden", challenge=None)
dr.request_card(profile, challenge_id, name="", workdir=None, source=dr.CARD_SOURCE)   # (Card, created): one open card per challenge
dr.DiscordReconError; dr.SCHEMA; dr.SCORES; dr.PLACES
```

Candidate kinds, strongest first (`dr.SCORES`; a challenge cue word found in the item adds up to
`dr.CUE_BONUS_MAX`): `acrostic-flag` (the first or last characters of an item's lines or bullets, of
the messages of one channel in posting order, or of a list of names spell a flag), `flag` (a
literal), `decoded-flag` (reached by the shared codec graph of section 41 from the item or one of its
tokens; a loose-only chain scores `dr.LOOSE_DECODE_SCORE`), `hidden-flag` (invisible Unicode tag
characters), `recognition` (the value after a cue such as "recognition word:", "password is",
"Kennwort:"), `spoiler`, `braceless` (an expression, role, channel or thread name that starts with a
flag prefix), `decoy-flag` (a literal flag that reads as a format example, has a placeholder body, or
is quoted in the challenge brief: listed last). An acrostic that is not a flag is a `Reading`, never a
candidate. Matching is `ctf.flagfmt` for the profile given; the module defines no flag regex.

**A Discord flag is never attributed to a challenge by a machine.** One server holds the flags of
several challenges and a rules page shows format examples, so every result is a candidate. The engine
`toolkits.osint_discord` (routed by the word `discord` in a challenge's description or tags, run at
intake) therefore returns `unsure` with **no flags** and writes the ranked candidates to
`<challenge>/recon/discord.md`; intake merges an engine's flags and would call a lone one `solved`. It
returns `blocked` when there is no snapshot, and then opens one task card for a challenge that lives in
the server (`discord_only`: tagged `discord`, or no handout and no target and either named for Discord
or with a sentence that names Discord beside a recon cue (flag, channel, pins, recognition, join, an
invite link ...) and no help word (ticket, help, questions, stuck, updates ..., or "ask" without a bot);
admins and organizers are not help words), `none` when the snapshot
holds no candidate, and `candidate` with the event-format flags (decoys last) only on `--opt flags=true`.
Other opts: `snapshot=PATH` (refused, before it is looked up, inside a Discord client folder),
`card=false`, `decode=false`.

```python
from ctf import discordapi
bot = discordapi.from_profile(profile, environ=None)      # DiscordRefused before any connection
bot = discordapi.Client(api_base, token, timeout=20.0, max_requests=400, min_interval=0.25,
                        max_retries=3, max_wait=30.0)      # also sleep=, clock= (injectable)
bot.get(path, query=None)                        # decoded JSON; HttpError(.status), BudgetSpent, DiscordError
res = discordapi.capture(bot, guild_id, first=50, recent=0, bots=25, max_channels=200)
res.guild; res.items; res.notes; res.requests; res.partial   # discordapi.CaptureResult
discordapi.DiscordError; discordapi.DiscordRefused; discordapi.HttpError; discordapi.BudgetSpent
```

Client rules, each with a test:

- `from_profile` refuses, in this order and before any request: `[discord] capture` other than `"bot"`;
  an API host that `scope.check_public_fetch` does not allow (`rules.public_fetch_allow`; the event
  platform is always refused); an unset token variable (`[discord] token_env`, read through `ctf.env`).
- The token is sent only as `Authorization: Bot ...` to the configured API base. It is in no error
  message (an echoed one is scrubbed; a token holding anything outside printable ASCII, such as a pasted
  line break, is refused at construction without being repeated, and a request http.client cannot send
  never passes its error text on), no repr, no snapshot and no ledger record. A redirect is refused;
  plain http is refused except to loopback; no proxy is taken from the environment.
- Bot applications only: a token whose `/users/@me` is not a bot is refused (automating a user account
  is against Discord's terms). GET only: it joins nothing and posts nothing.
- Ids taken from API answers reach a request path only when they are digits.
- At least `min_interval` between requests; a 429 waits out `Retry-After` up to `max_wait`, at most
  `max_retries` times; `max_requests` ends a capture with a note and `partial`. A place the bot may not
  read (403, 404) is a note in the snapshot. The identity, server and channel-list reads must succeed.
- `capture` reads: the server's name, description, roles, emoji, stickers, welcome screen; every
  channel's name, topic and forum tags (the channel list is not filtered by what the bot can open, so a
  hidden channel's description is included); active threads; scheduled events; soundboard; onboarding;
  the server's bots and their public descriptions (people are not listed); per readable text channel
  its pins, its first `first` messages and its newest `recent` (the rules channel's as kind `rules`).
  Member profiles (About Me, status, banner) are not readable by a bot and stay on the checklist.

Ledger records (counts only, never a value; each carries `event_slug`): `discord.ingest` (`source`,
`items`, `added`), `discord.capture` (`guild_id`, `items`, `added`, `requests`, `partial`, `notes`),
`discord.analyze` (`items`, `candidates`, `flags`, `challenge_id` when one was given). The engine's runs
are `engine.run` records like any other.

---

## 58. Lattice and polynomial-ideal service (B-157)

One JSON job, a named backend, a checked result. The full contract is the module docstring of
`solvers/common/algebra_service.py`; the operator page is `docs/toolkits/algebra_service.md`. Both are
engines of the `common` lane (`common.algebra_service`, `common.lattice_templates`), imported flat like
their neighbours.

```python
import algebra_service as alg                 # solvers/common, flat import
res = alg.execute(job, backend="auto", sage_version=None, timeout=alg.DEFAULT_TIMEOUT, environ=None, root=None)
# ServiceResult(op, status, backend, detail, proof, checks, result, seconds, reason, needs_tool, fix)
#   .ok  .require() -> result | BackendUnavailable | ServiceError   .to_dict()
alg.reduce_basis(basis, method="lll", block_size=20, tours=None, backend="auto")   # verified rows, or it raises
alg.parse_job(job)                            # Job(op, wire, ring, names, polys, basis); JobError when malformed
alg.plan_backend(parsed, backend, sage_version=None, environ=None, root=None)      # the one backend, or BackendUnavailable
alg.backend_status(environ=None, root=None); alg.selftest(backend="auto"); alg.sage_images(root=None)
alg.same_lattice(before, after, u, v); alg.solve_left(m, t)                      # the lattice certificate and its maker
alg.parse_polynomial(text, names, ring); alg.poly_text(ring, f, names); alg.parse_ring(value); alg.parse_int(value)
# alg.OPS, LATTICE_OPS, IDEAL_OPS, BACKENDS, ORDERS, STATUSES, SENTINEL, SCHEMA; JobError, ServiceError, BackendUnavailable

import lattice_templates as lt
t = lt.build(name, args)                      # or lt.hidden_number(...), lt.bounded_linear(...), ... : lt.TEMPLATES
# Template(name, basis, extract, notes); .dimension
lt.solve(t, method="lll", block_size=20, backend="auto")          # checked solutions; raises like require()
lt.solve_detailed(t, method="bkz")            # (solutions, ServiceResult): ([], blocked) when BKZ has no backend
```

- **Job** (`schema` 1). `op` is one of `lll`, `bkz` (`basis`, `block_size`, `tours`); `groebner`, `variety`,
  `eliminate`, `resultant`, `roots` (`ring`, `vars`, `polys`, `order`, `eliminate`, `var`); `small_roots`
  (`modulus`, `poly`, `bound`, `beta`, `epsilon`). An unknown key is a `JobError`. `ring` is `QQ`, `GF(p)` or
  `Zmod(n)`. A polynomial is a string for the module's own parser or a term list
  `[[coeff, [exponents]], ...]`; nothing is evaluated. The string parser runs in the caller, so it is
  bounded by work: parentheses nest at most `MAX_NESTING` deep and one job's expansion costs at most
  `MAX_PARSE_WORK` meter units (`parse_polynomial(..., meter=)`); past either it is a `JobError`.
- **Wire form** (what a worker receives, `Job.wire`): integers, exponent lists and a `timeout`, no
  names and no strings to parse. A worker prints one line, `SENTINEL` + JSON:
  `{"status": "ok", "engine", "data"}` (Sage also `sage_version`), or `error` / `timeout` / `blocked`
  with `error` (and `needs_tool`). `data`: `{"basis", "u", "v"}` for a reduction (U·B = R, V·R = B),
  `{"basis"}`, `{"points"}`, `{"poly"}`, `{"roots"}`. A coefficient is an int, or `[num, den]` over QQ.
- **Backends**: `python` (the child `algebra_service.py __worker__ job.json`: `lattice_backends.reduce_lattice`
  for LLL and fpylll BKZ, SymPy over QQ and GF(p), `rsa_lattice.coppersmith_roots`), `sage-local`
  (`sage -python worker.py job.json`), `sage-image` (the `ctf-sage:<version>` image of section 37 through
  `images.run_argv`: no network, never pulled, `timeout -k 10 <s> sage -python /work/worker.py /work/job.json`;
  the image must be `ok` in `images.status`), `sage` (local when present and no release was named, else
  the image; a named release always means its image), `auto` (python inside the `AUTO_*` limits, else
  sage). One backend is chosen per job and named in the result; a job never falls through to another
  after it ran.
- **Statuses**: `ok`; `blocked` (no backend can run it as asked: `needs_tool` uses the marker names
  `py:fpylll`, `sage`, `image:<tag>`, and `fix` is the step that provides it; also a Sage of another
  release than asked for); `error` (it ran and failed, or its answer failed a check); `timeout`. Nothing is
  installed, pulled or built, and BKZ is never answered with LLL.
- **Proof**: `exact` (reductions: both transforms multiplied out here; `variety`, `roots`, `small_roots`:
  every value substituted here), `partial` (`eliminate`, `resultant`: the eliminated variables are
  absent), `none` (`groebner`). A value that fails its check makes the whole result `error`.
- **Local reduction seam**: the python backend reduces only through `lattice_backends.reduce_lattice`.
  A faster local backend (B-244's fpylll LLL) goes behind that function; it must not add another.
- **Templates** return only values that pass the template's own exact check; an empty list means the
  reduction exposed nothing, not that no solution exists.

---

## 59. Scoreboard ingestion and first-blood benchmark (B-099)

Reads the public board through the platform adapter instead of a pasted dump, and measures first
bloods won and lost per lane against the event ledger's accepted times (the Huntress
`benchmark_vs_firstblood` yardstick, ported off hand-copied board times). Full contract: the module
docstring of `ctf/scoreboard.py`. Per-challenge solves are `base.challenge_solves` (section 5).

```python
from ctf import scoreboard
r = scoreboard.ingest(gate, workdir=None, team=None, max_solves=20, force=False, lane="board",
                      keep_rows=50, now=time.time)     # IngestResult(deferred, board_rows, challenges,
                                                       # fetched, pending, first_bloods, errors); .ok
scoreboard.watch(gate, cycles=None, interval_s=60.0, sleep=time.sleep, on_result=None, on_error=None,
                 **ingest_kw)                          # repeated ingest; NotSupported/NotAllowed stop it
scoreboard.record_solve(workdir, cid, account, at, category=None, name=None, team=None, delete=False)
                                                       # a solve entered by hand (no request, any kind)
scoreboard.busy(wire)                                  # why a board read must wait now, or None
st = scoreboard.load(workdir)                          # <workdir>/scoreboard/state.json (schema 1)
scoreboard.read_events(workdir)                        # events.jsonl: board snapshots, first_blood lines
scoreboard.first_blood(st["challenges"][cid])          # the earliest timed solve, or None
b = scoreboard.bench(st, records, team="us", margin=0.3, t0=None, lane=None)
# Bench(team, margin, rows: [BenchRow], lanes: [LaneBench], notes); BenchRow.status won | lost |
# unsolved | uncontested, .gap_s (ours - rival), .place, .verdict PASS | FAIL | NOTARGET
scoreboard.floor_records(b, kind="ctfd")               # {mode: s} -> latency.floor_table(records=...)
scoreboard.render_bench(b)
# scoreboard.ScoreboardError; LANE "board"; DEFAULT_MARGIN 0.3; MAX_SOLVES 20
```

- **Low priority.** `ingest` sends nothing (`deferred` says why) while the wire is paused after a 429,
  while a release window is open, or once the last 60 s hold half the team's `wire.per_minute` less its
  `reserve`; it re-checks before each per-challenge read and leaves the rest `pending`. `force=True`
  skips only this check, never the wire's own holds. Every request is journaled as lane `board`
  (ops `scoreboard`, `list`, `solves`). The cycle sets the gate's `Wire.lane` for its length, so
  `ingest` needs its own gate (the CLI runs it as its own process): a gate shared with another
  lane's thread would journal that thread's requests as `board`.
- **Economy.** Per-challenge solves are read only for challenges whose solve count (the CTFd list's
  `solves`) changed, never-read ones first, at most `max_solves` a cycle; a count of 0 needs no read.
  The stored count is the list's (not the number of rows a capped solves read returned).
- **Hand entry.** `record_solve` (`ctf scoreboard record`) writes one team's solve into the same
  store as a row with `hand: true`, with no request on any kind: a Game Master event publishes no
  other team's solves, so its first-blood times are typed in. An ingest keeps hand rows of teams its
  read does not list; a team the board records is refused (the board's time wins). A changed first
  blood is an `events.jsonl` `first_blood` line with `source: "hand"`; the bench's `ours_source` is
  `hand` for our own hand row.
- **Kinds.** CTFd only. A Game Master event raises `NotSupported` and a manual one (or
  `ai_on_platform = "forbidden"`) `NotAllowed`, both from the adapter, named, before any request.
- **Store.** `<workdir>/scoreboard/state.json` and `events.jsonl`, 0600, one writer by flock. Team
  names are public board data; no URL, header, token or flag is written. The core ledger is read,
  never written: first bloods are lines of `events.jsonl`, not ledger records.
- **Bench.** Offline. Our time is the board's record of our team's solve (the rivals' clock) when
  present, else the ledger's first `accepted` stage; the release is the T0 of the challenge's ledger
  wave (`replay.waves`, `replay.assign`), else (a challenge the ledger never staged) the last wave
  opened at or before its first board solve, else `t0`. `target_s = rival_elapsed_s * (1 - margin)`;
  unsolved with a rival is FAIL. `team` is required (`platform.team` or `--team`): without it a rival
  cannot be told from us, so it is a `ScoreboardError`, never a guess.

---

## 60. Named jobs, launcher sessions and the end-of-event reaper (B-175)

Nothing is signalled or deleted from a record unless the record still names the same thing. A process
is identified by **pid AND start time** (`ctf/procid.py`), never a pid alone; a git branch by its sha
(compare-and-delete); a worktree by its HEAD and a clean status.

```python
from ctf import procid, jobs, sessions, reaper
procid.start_time(pid); procid.identity(pid)        # float | None; {"pid", "start"} or ProcIdError
procid.status(pid, start)                           # "alive" | "gone" | "reused" | "zombie"
procid.matches(pid, start); procid.pgid_of(pid)
procid.terminate(pid, start, pgid=None, grace=1.0, timeout=8.0)   # "stopped" | "not_running"
procid.terminate_report(pid, start, ...)            # (outcome, "SIGTERM" | "SIGKILL" | None): what ended it
jobs.start(argv, root=..., name=..., owner=None, owner_pid=None, exclusive=False)   # section 8
jobs.live_jobs(root, owner=None); jobs.job_dir(root, "ID or live NAME"); jobs.holds_name(st)
jobs.command_status(st); jobs.owner_status(st)      # procid status, or "unknown" / "none"
jobs.kill_lost(d, grace=..., timeout=..., by="reap"); jobs.reap(root, owner=..., dry_run=False)  # [Reaped]
sessions.sessions_root(override=None)               # $CTF_SESSIONS_DIR, else <workdir>/sessions
sessions.claim(root, name, harness=..., challenge=None, owner=None, pid=None)   # Claim, or SessionLive
sessions.set_agent(claim, pid, own_group=True, owner=None); sessions.release(claim)
sessions.peek(root, name); sessions.session_state(root, name); sessions.list_sessions(root)
sessions.stop(root, name, agent_grace=5.0, launcher_grace=30.0, timeout=10.0, expect=None)   # Stopped
sessions.reap_id(name, record)                      # "session:<name>@<launcher pid>-<launcher start ms>"
sessions.same_claim(rec_a, rec_b)                   # same launcher pid AND start time
sessions.same_stale_record(rec_a, rec_b)            # same_claim, or same pid and neither has a start (stale removal only)
reaper.plan(jobs_root=None, sessions_root=None, repo=None, base="HEAD", protect=(), here=None)  # Plan
reaper.render(plan); reaper.to_json(plan); reaper.protected_branches(repo, base, extra=())
reaper.execute(plan, ids, log=path_or_None, agent_grace=..., launcher_grace=...)  # [Result]
```

- **Jobs.** `job.json` records the owner (`--owner`, else `$CTF_JOB_OWNER`) and, with
  `$CTF_JOB_OWNER_PID`, the owner's pid and start time (an owner pid that is not live is refused);
  the supervisor records the command's `pgid` and `pid_start` and its own `supervisor_start`, and
  writes the `pid` pidfile. `kill_lost` stops a lost job (supervisor dead) only while its command is
  still the recorded (pid, start) leading the recorded group; a command already gone gets its record
  closed (`exit.json` with `lost: true`, `rc: null`); a lost record with no start time is refused.
  `exit.json`'s `signal` is the one that ended the command (`SIGKILL` when the TERM grace ran out).
  A lost job holds its name (`--exclusive`, lookup by name) only while its command is alive, reused or
  unprovable (`holds_name`); one whose command is gone is found by name only when it is the sole
  record under that name.
  `reap(owner=)` stops only that owner's live jobs and reports each as `stopped`, `closed`, `ended`
  or `failed` (with the reason).
- **Launchers** (`tools/launch_gate.py`): a supervised agent runs with `CTF_JOB_OWNER` (a fresh
  `<harness>-<challenge>-<launcher pid>-<random>`), `CTF_JOB_OWNER_PID` (the launcher) and
  `CTF_JOBS_DIR` (`$CTF_JOBS_DIR`, else `<ledger workdir>/jobs`); after `agent_exit` the launcher
  reaps that owner's jobs and records `jobs_reaped`. An exec'd (ungated) agent gets the owner pair with
  its own pid (`exec_owner_env`). `claim_session(args, harness, dry_run=)` returns `(claim, None)`,
  `(None, None)` with no session named, or `(None, 3)` over a live one; `release_session(claim)`.
- **Sessions.** `<root>/<name>.json`: name, harness, challenge, owner, claimed_at, launcher_pid,
  launcher_start, agent_pid, agent_start, agent_pgid (when the agent leads its own group). A record is
  live while its launcher or its agent matches by pid and start time; a dead or reused pid leaves it
  stale, and a new claim replaces it. Claims and releases hold `<root>/.<name>.lock`. The reaper's id
  for a session is `reap_id`: the name plus the launcher's pid and start time, so a name re-claimed
  after the dry run is a different id. `stop(expect=record)` refuses (nothing signalled) when the
  record now names another launcher.
- **Reaper.** `plan` changes nothing. Candidates: running jobs, lost jobs (stoppable by identity, or
  whose command is gone), live and stale sessions, linked worktrees that are clean
  (`status --porcelain --untracked-files=all` empty), unlocked, present and whose HEAD is an ancestor
  of the base, and local branches merged into the base that are not protected (`main`, `master`, the
  base, the current branch, the configured integration branch, `--protect`) and not checked out
  (a branch checked out in a candidate worktree is offered `after` it). Never: the main worktree, the
  worktree holding the current directory, remotes. `execute` refuses the whole run when an id is not
  in the plan, then acts in the order sessions, jobs, worktrees, branches, re-checking each:
  `git worktree remove` (never `--force`), `git update-ref -d refs/heads/<name> <planned sha>` after
  re-checking protection with the plan's `--protect` extras (`Plan.protect`); a stale-session
  candidate only removes the record, and only while it is still that same stale claim
  (`same_stale_record`: a record with no launcher start, which can never be live, matches only
  another no-start record of the same pid; a real claim always records a start). A
  branch whose worktree was not removed in the same run is `skipped`. Each result is appended to the
  log as `{ts, id, outcome, detail}`. The player runs `--confirm`; an agent shows the dry run.

---

## 61. Test and docs integrity (B-196)

`python -m ctf integrity mutate | fakes | collected | doclint | preserve | engines | all`
(`ctf/cli/integrity.py`, code in `ctf/integrity/`). Each check is static unless it says it runs tests;
a missing config, registry or tests folder is an `IntegrityError` (exit 2), never an empty pass.

```python
from ctf.integrity import mutate, fakes, collected, doclint, preserve, newengines
ms, counts = mutate.generate(root, rel, ops=mutate.OPS, functions=(), lines=None)   # Mutant list
rep = mutate.run(root, rel, tests=None, ops=mutate.OPS, functions=(), lines=None, max_mutants=None,
                 state=None, config=None)          # MutationReport: .mutants (Outcome), .killed, .survived, .score
res = fakes.audit(root, source_dirs=fakes.SOURCE_DIRS)      # FakeAudit: .branches (Branch), .findings, .ok
res = collected.audit(root)                                  # CollectAudit: .new, .known, .stale, .ok
res = doclint.audit(root, only=None)                         # DocAudit: .new, .known, .stale, .ok
res = preserve.check(root)                                   # PreserveResult: .solves, .findings, .ok
preserve.run(root, res, out_dir=out, allow_not_run=())       # strict run of the registry tests
preserve.run_lanes(lanes, res, workdir=wd)                   # ctf.adapt.regress.gate per lane: YES required
audits = newengines.audit(root, base, state=None)            # EngineAudit per manifest added since base
```

- **Mutation (`mutate`).** Operators `cmp`, `boundary`, `bool`, `not`, `if`, `const`, `return`,
  `arith`, `raise`, `call`, inside function bodies only (module-level tables, docstrings, annotations,
  defaults, decorators and f-string internals are never mutated; a line with `# pragma: no mutate` is
  skipped; a mutant that does not compile or repeats another's text is dropped). The tests are the
  gate's impact selection for the file (section 23), or `--tests`. The checkout's files (as the gate
  lists them) are copied to a temporary folder; the unmutated copy must be green first (else
  `IntegrityError`); each mutant is written there with a fresh mtime and its bytecode removed, its
  test files run fastest first through `ctf.gate.runner.run_file` (`-x`), stopping at the first that
  fails. KILLED = some file not PASS (a hang is cut at `max(MIN_WALL, WALL_FACTOR * baseline)` seconds,
  load-scaled: a TIMEOUT kill); SURVIVED = every file passed. The checkout is never written. Exit 0 when
  `killed / mutants >= --min-score` (default 1.0).
- **Fake branches (`fakes`).** An `if`/ternary/`while` in `ctf/`, `solvers/`, `tools/` (not test or
  self-test files, not `ctf/testing/`) whose condition reads a fake flag (`fakes.FLAGS`: `CTF_TESTING`,
  `PYTEST_CURRENT_TEST`, `CTF_OFFLINE_AUDIT`; `audit(flags=...)` takes another non-empty list) (directly,
  through a local assigned from a read, or through a module predicate that returns one) needs
  a test that imports the module, names the function (or a same-module caller) through that import, and
  turns every flag it reads off: in its body, a requested fixture or an autouse fixture. A read of the
  process environment needs the process flag off (`monkeypatch.delenv`, `setenv(FLAG, "0")`, ...); a read
  of an injected `environ=` mapping is also off for a dict literal without the flag. A flag may be spelled
  as a module-level string constant (`FLAG = "CTF_TESTING"`, bare, imported or `mod.FLAG`) in source or
  test: constants are collected (`fakes.module_constants`) from every source and collected test file that
  names a flag literally and matched by name, and a file naming such a constant is audited.
  `tests/fake_branches.toml` holds waivers (`reason`) or evidence the audit cannot see (`tests`); a
  waiver for no branch, or naming a missing test, is a finding.
- **Collection (`collected`).** Findings: `misnamed` (defines tests, does not match `pytest.ini`
  `python_files`, imported by no test), `ignored` (conftest `collect_ignore`), `not-gated` (outside
  `tests/gate.toml` `tests`), `no-tests` (collected, no test function or class), `stray` (a `test_*.py` or
  `selftest*.py` outside `tests/`, which `testpaths = tests` never collects, that no `tests/` source runs
  or imports: names its repo path, or its folder as a quoted segment with its file name or an
  `import <stem>` line; a root-level file needs only the name or import). `collect_ignore` entries are
  matched relative to their conftest's folder, as pytest does (`testfiles.ignored_by`). `tests/collection_known.toml`
  lists the findings known when the check shipped (`[[known]]` rule, path, reason); a new finding or a
  stale entry fails.
- **Doc lint (`doclint`).** Over `README.md`, `CLAUDE.md`, `AGENTS.md`, `BUILD-PLAN.md` and the
  maintained docs (`docs/*.md`, `docs/playbooks`, `docs/toolkits`, `docs/runbooks`, `docs/coverage`,
  `docs/examples`; never build logs, migration notes, retros or writeups): a backticked repo path under a
  top-level folder must exist, a relative Markdown link must resolve, `python -m ctf <cmd>` must name a
  command. `<!-- doclint: skip -->` opts a line out. `tests/doclint_known.toml` (`[[known]]` doc, rule,
  ref, reason; no line numbers) holds the known stale references. `tests/test_integrity_tree_docs.py`
  runs it, and `tests/gate.toml` maps every doc to it with a `[[scan]]` rule, so a doc edit is gated.
- **Known solve paths (`preserve`).** `tests/known_solves.toml` `[[solve]]` id, what, tests (node
  ids), optional engines (ids that must keep a manifest). The static check wants each test defined in
  a collected file and not hollow (`tools/test_audit.py`). `--run` runs them through the gate runner,
  one child per file, strict not-run (a skipped known-solve test is not preserved). Event solve paths
  recorded with `ctf adapt record` (`regress.record_case`, kept in the workdir) are replayed with
  `--lane L` / `--recorded` (`regress.gate`, YES required). Run it before verifying a fix lane.
- **New engines (`engines --base REF`).** Every `*.manifest.toml` added since REF (committed or
  untracked): the manifest loads, its entry file exists, at least one test file reaches it by import
  (a `[[scan]]` test does not count), none of those tests is hollow, and its fake branches have
  non-fake tests. Each line ends with the mutation command for the entry file.
- **Tree tests.** `tests/test_integrity_tree.py` (fakes, collection, known solves) and
  `tests/test_integrity_tree_docs.py` (doc lint) hold the tree to these checks on every gate run that
  touches their `[[scan]]` inputs.

---

## 62. No-model helper launch on a lane STOP (B-212)

The full contract is the module docstring of `ctf/helpers.py`; change it there and here together.

```python
from ctf import helpers
cfg = helpers.load_config(path)        # <workdir>/helpers.toml by default (helpers.config_path); strict keys
helpers.parse_config(raw, src)         # Config(launcher, harness, event, handoff_wait, max_per_lane,
                                       #        warm_timeout, lease_ttl, default_mode, cwd,
                                       #        lanes={lane: LaneConfig})
cfg.lane(name) -> LaneConfig(mode=auto|warm|cold, warm_agents, brief, launcher)
cfg.brief_path(lane, workdir)          # [lane.X] brief, else <workdir>/briefs/<lane>-gap.md (campaign gap brief)
w = helpers.Watcher(workdir, cfg, clock=time.time, resume=None, plan_kw=None, start="end"|"beginning",
                    campaign=None)
w.tick() -> TickReport                 # launched, taken, returned, fallbacks, delivered, resumed, absorbed,
                                       # capped, errors
w.run(stop=None, poll=1.0, duration=None)
helpers.deliver(workdir, helper_id, outcome="delivered"|"failed", note=None)   # one helpers.deliver record
helpers.arm(lane_plans, cfg, workdir=None, argv_prefix=None, record=True) -> ArmPlan
                                       # lanes (WarmLane: lane, warm, reason, agents [{agent, lane, argv}],
                                       # brief, brief_ok), missing_briefs, warm_agents
helpers.read_claims(workdir)           # the `helpers` standby pool (section 32)
helpers.tail(workdir, offset) -> (records, new_offset)   # complete ledger lines only
helpers.stop_of(rec) / helpers.healthy_lane(rec)
helpers.status(workdir) -> {offset, helpers, lanes, open}
ctf.cli.lookahead.plans_from_matrix(matrix, report)   # forecast.plan from a matrix + gate report
                                       # (shared by `lookahead plan` and `helpers arm --matrix`)
```

A STOP is an `adapt.chain` record with `action = "stop"` or an `adapt.gate` record with verdict `no`
(section 29); a lane is healthy again on a gate `yes` or a chain `start | retry` (gated steps; a chain
`done` runs no lane gate and resets nothing). One helper is
open per lane; later STOPs on it are absorbed (their base joins its `bases`). At most `max_per_lane`
helpers between healthy signals (`helpers.capped` once past it). A launch needs the lane's warm brief
(none: `helpers.error`, nothing launched). Warm: a live waiting `standby take --pool helpers` agent for
the lane (or any lane, counted for one lane at a time) and a lane not configured `cold` -> a helper
claim (status `dispatched`); not leased within `handoff_wait` s -> the watcher leases it itself,
marks it `withdrawn` and launches cold (`helpers.fallback`). Warm agents from `arm` take with `--ttl
lease_ttl` (default 900 s) and the handout tells the helper to `standby renew`; a taken helper whose lease
lapses (ttl unrenewed, or a dead owner pid past the standby stale age) is reclaimed by the watcher through
`standby.try_lease` (a renewal that lands first wins), recorded `helpers.returned` (agent, reason) and
offered again; a held lease (no pid, no ttl) is never reclaimed. Cold: `Campaign.launch(helper_id, launcher,
harness, challenge=<first base>, prompt_file=<handout>, scratch=False)`, the campaign's fenced-launcher
allow-list and budget gate applying; the `helpers.launch` record's `metered` names that challenge, and
is null for a helper a lane gate NO started with no chain base waiting: such a launch is not metered by the
campaign budget gate (only `max_per_lane` bounds it). Delivery (`helpers.deliver`, or the campaign agent ending done;
failed/lost is a failure) closes the helper (`helpers.delivered`; a warm claim goes to `delivered` or
`failed`, its lease dropped) and, when delivered, re-runs `chain.plan(base, lane)` for each base
(`helpers.resume` with the action). Helper ids `helper-<lane>-<nnn>` (one counter: unique), warm agents
`hw-<lane>-<nn>`; both valid standby agent names and campaign ids. State: `<workdir>/helpers/state.json`
(flock `state.lock`; the ledger byte cursor, the counter, helpers, per-lane counts), handouts
`<workdir>/helpers/<id>/handout.md`. Ledger events: `helpers.launch` (mode warm|cold), `helpers.taken`,
`helpers.fallback`, `helpers.returned`, `helpers.absorbed`, `helpers.capped`, `helpers.deliver`,
`helpers.delivered`, `helpers.resume`, `helpers.error`, `helpers.arm`. `arm` gives a lane warm agents only
when its mode is `warm`, or `auto` and the look-ahead plan (section 35, `forecast.plan`) gives it an
agent. Per-lane warm vs cold stays config until cold-spawn latency is measured live (human step). No
model, no platform call, no network.

---

## 63. Completion-driven agent coordination (B-239)

At CSCTF 2,169 coordination-only subagent responses (`send_message`, `wait_agent`, `list_agents`,
`followup_task`, `wait`) cost $166.70, and 280 of 409 `wait_agent` calls timed out at a 24 s mean
timeout. `ctf.coord` makes a parent block on a completion file, gates lane messages, and puts lane state
behind one command. The full contract is the module docstring of `ctf/coord.py`; change it there and
here together.

```python
coord.complete(child, status, summary, paths=(), challenge_id=None, lane=None, by=None, replace=False,
               workdir=None, clock=time.time) -> dict          # coord/done/<child>.json, exclusive
coord.read_completions(workdir=None) -> {child: record}
coord.parse_target("child:ID" | "ID" | "campaign:AID" | "job:ID" | "standby:AGENT[=waiting,assigned,left]"
                   | "claim:CID" | "msg:LANE") -> Target
coord.wait(targets, workdir=None, timeout=DEFAULT_TIMEOUT, any_=False, interval=0.5, as_agent=None,
           allow_short=False, jobs_root=None, clock=time.monotonic, sleep=time.sleep, wall=time.time,
           log=True) -> WaitResult(code, probes, waited_s, timed_out, checks); .render(); .to_dict()
coord.combined_code(probes, any_=False) -> 0 | 1 | 124
coord.send(lane, kind, text, sender=, workdir=None) -> Verdict(lane, kind, delivered, reason, seq, detail)
coord.inbox(lane, agent, workdir=None, peek=False) -> [message]   # unseen, own excluded, cursor moves
coord.messages(workdir, lane); coord.dropped(workdir, lane); coord.last_seq(workdir, lane)
coord.lane_cap(workdir, lane); coord.set_cap(workdir, lane, cap, by=, reason=)
coord.relay(workdir=None) -> ([Verdict], [problem])   # new lane_result ledger records -> the gate
coord.board(workdir=None) -> Board(rows, lanes, idle, loose_agents, loose_completions, problems)
coord.render_board(board, width=120); coord.stats(workdir=None) -> dict
# coord.STATUSES ("done", "failed", "blocked"), TARGET_KINDS, RELAYED_KINDS ("finding", "decision"),
# LANE_MSG_CAP (20), DEFAULT_TIMEOUT (540), MIN_TIMEOUT (60), EXIT_* (0, 1, 2, 3 dropped, 124), CoordError
```

- **Completion, not polling.** A target is complete when its own record says so: a child's completion
  file (`done` is success; `failed` and `blocked` end the wait as a failure), a campaign agent's
  `done`/`failed`/`lost` (a `running` agent whose supervisor lock is free or whose heartbeat is stale
  reads as lost through the public `Campaign.alive`; nothing is written), a B-144 job's `exit.json` or
  lost lock, a standby presence (default present; `left` or a pid `dispatch.pid_alive` finds dead,
  when not wanted, is a failure), a claim's
  intake `done`/`off` (`failed` is a failure), or a new delivered lane message (after the `--as`
  agent's cursor, else after the lane's last seq at the start; own messages never wake; the cursor
  then moves to the last seq the wait read, never further or backwards). The wait checks files once
  per `interval` in one process and returns once. An unknown campaign agent or job, an unreadable
  claim or completion file is a `CoordError` (exit 2). Job records: `jobs_root` (CLI `--jobs-dir`),
  else `$CTF_JOBS_DIR`, else `<workdir>/jobs`.
- **The child id.** A B-143 `spawn request` brief ends with `python -m ctf coord done <spawn id> ...
  --challenge <id>`, so the parent waits on the spawn id.
- **No timed polls.** A timeout under `MIN_TIMEOUT` is refused unless `allow_short`; a timeout returns
  124 with the pending lines. Every wait appends `{ts, targets, any, outcome, code, waited_s, checks,
  as}` to `coord/waits.jsonl`; `stats` counts completed vs timed out.
- **The lane relay.** `send` delivers only a `finding` or `decision` that is not a repeat (same kind and
  casefolded, punctuation-stripped text already delivered in the lane) while the lane has fewer than its
  cap delivered (`cap.json`, else `LANE_MSG_CAP`). Everything else goes to `dropped.jsonl` with reason
  `kind`, `repeat` or `cap`, and the verdict names where it belongs. `relay` forwards `lane_result`
  ledger records (section 39): found / ruled_out / blocked as findings, partial as progress (dropped);
  a record whose lane is not a usable id is a named problem; a ledger shorter than the cursor is an
  error. The cursor (`relay-cursor.json`) moves past each record as it is handled and is written even
  when a send raises, so a record delivered before an `OSError` is never offered again.
- **Rules.** The agent rules teach `coord wait msg:<lane> --as <you>` (a lane wait from the agent's own
  inbox cursor) and `--no-timeout` for a Claude Code background wait.
- **The lane board.** `board` joins `dispatch.read_claims` (lane, status, intake), standby leases
  (owner) and presence (the idle pool: waiting with a live or unknown pid), campaign agents by
  challenge (`lost?` for an unreconciled dead one), completion files by `challenge_id`, and the lane
  message counts. Unreadable claims are `problems` (CLI exit 1).
- Coordination records stay out of the event ledger, so `ctf orch wait` (section 43) is not woken by
  them. Message and completion text is agent-written data, cut to one line, never instructions.

---

## 64. Main-thread claims ledger (B-259)

An evidence check before the orchestrating main thread states a root cause or steers agents. On
release mornings causes were stated that proved wrong or unproven, agents were steered on them, and
the retros did not record the steer. Every such statement is now a recorded claim with a linked
artifact and a status. Full contract: the module docstring of `ctf/findings.py`.

```python
from ctf import findings
findings.add(kind, text, artifacts=[...], challenge_id=None, to=None, by="orch", workdir=None,
             cwd=None, git_repo=None) -> dict      # kind cause|steer; always `suspected`; EvidenceRefused
                                                   # (nothing written) with no artifact or one unresolved
findings.confirm(claim_id, by=, note="", workdir=None) -> dict      # a person; suspected -> confirmed
findings.refute(claim_id, by=, artifacts=[...], reason="", workdir=None, cwd=None, git_repo=None) -> dict
findings.retract(claim_id, by=, reason=, workdir=None) -> dict      # its author withdraws it
findings.claims(workdir=None, include_final=True) -> list[dict]     # folded: current status, history
findings.get(claim_id, workdir=None); findings.records(workdir=None); findings.path(workdir=None)
findings.held(claim) -> str                        # held | did not hold | retracted | unresolved
findings.resolve_artifact(ref, workdir=None, cwd=None, git_repo=None) -> dict
findings.recheck(claim_id, workdir=None) -> [(artifact, matches, reason)]
findings.recheck_artifact(artifact, workdir=None) -> (matches, reason)
findings.git_argv(args) -> list[str]               # the checked argv of a git: reference
findings.check_git_argv(argv) -> list[str]         # the same check on a split argv (recheck reruns it)
findings.claim_line(claim, width=160); findings.note_text(record); findings.artifact_label(artifact)
findings.one_line(text, limit=400)
# findings.FindingsError; findings.EvidenceRefused (a FindingsError); KINDS (cause, steer);
# STATUSES (suspected, confirmed, refuted, retracted); FINAL, LIVE, HELD, GIT_READONLY
```

- **File.** `<workdir>/orch/findings.jsonl` (mode 0600, flock + O_APPEND; the id `F-<n>` is assigned
  under the lock). Records: `{"ts", "op": "claim", "id", "kind", "text", "challenge_id", "to", "by",
  "artifacts", "status": "suspected", "verify_reason"}` and `{"ts", "op": "status", "id", "status",
  "by", "reason", "artifacts", "verify_reason"}`. Not ledger records. A corrupt line raises
  `FindingsError` naming the file and line.
- **Artifacts.** `ledger:N` (line N of the event ledger: its sha256, `event`, `challenge_id`, `ts`),
  `file:PATH[#LN]` (a regular file: path, size, sha256, and that line's sha256; hashed, never copied)
  and `git:ARGS` (a subcommand in `GIT_READONLY`, run in `git_repo`, default the repo root, with no
  pager, external diff, textconv, fsmonitor, hooks, signature check, global or system config or
  caller `GIT_*` variable, and `GIT_OPTIONAL_LOCKS=0`; kept: repo, HEAD, argv, output sha256 and line
  count). Refused: an option before `--` that writes a file or runs a program (`--output`,
  `--ext-diff`, `--textconv`, `--filters`, `--open-files-in-pager`, `--show-signature`,
  `--submodule`, `--recurse-submodules`, `--ignore-submodules`, any abbreviation of one, since git
  takes unique prefixes, `--text` outside diff, log, show and grep, where it is not exact (`cat-file
  --text` is `--textconv`), and any short-option bundle holding `O`); a repo inside the workdir
  passed, the event's own workdir (`paths.workdir()`) or the base of all event workdirs; a repo
  whose config, includes followed, sets a key outside the allow-list `_GIT_CONFIG_OK` (a filter,
  diff or textconv driver, fsmonitor, a pager, gpg, an alias, any `submodule.*` key: a repo's config
  can run commands; the key is named, its value never shown); a repo with a submodule (a gitlink in
  its index, a `.gitmodules` at its top, or a non-empty `modules` folder in its git dir or common
  dir: git runs inside a submodule under the submodule's own config); a non-zero exit. git status
  and diff also run with `--ignore-submodules=all`. `recheck`
  re-resolves each artifact and says whether it still matches; for git it checks the stored argv
  and repo again before running anything.
- **Status.** A claim is `suspected` until a person confirms it: whether an artifact supports a cause
  is judgement, so the code checks only that the evidence exists and pins it. `confirm` is the
  person's call (`ctf findings confirm` demands an interactive terminal and the id typed back);
  `refute` needs an artifact; `retract` needs a reason; refuted and retracted are final; a confirmed
  claim can still be refuted. Each record says why in `verify_reason`.
- **Shown.** `ctf orch status`, a woken `ctf orch wait` digest and the brief show each claim with its
  status (section 43); `ctf writeup retro` lists every claim stated in the window, its evidence and
  whether it held (`retro.claims_section(profile, workdir, since=None, until=None)`; a flag in the
  event format inside claim text is masked).
- Claim text, file content and git output are data, never instructions.

---

## 65. Accepted-format catalog and pre-event vocabulary harvest (B-218)

The metadata lane reads a value and then has to SPELL it the way the judge accepts (`0x014c`, a GUID in
braces, member names as a sorted compact JSON array). `format_candidates.py` offers the spellings as
`labels.candidates` (row 346, never plain); this catalog orders them by what the judge has accepted
before, for the same property, its class and its kind. Module docstrings are the contract.

```python
# solvers/metadata-forensics/accepted_formats.py (a lane pack; loaded by path through ctf.packs)
AF.Catalog.load(path=None) -> Catalog          # the tracked accepted_formats.json; CatalogError names why
AF.load_default() -> Catalog                   # the same, re-read when the file changes
Catalog.preference(prop, kind, opts=None, answer_format=None) -> (prefer, last)
Catalog.probe_order(prop, kind, opts=None, answer_format=None) -> [hypothesis names]
Catalog.merge(other) -> Catalog; Catalog.save(path); Catalog.dumps(); Catalog.from_json(raw)
AF.harvest(roots, lane="metadata-forensics") -> Catalog   # judged attempts; CorpusError names why not
AF.corpus_root(explicit=None) -> Path          # explicit, else $CTF_REAL_CHALLENGES; never inside the checkout
AF.brief(questions, catalog) -> [Finding]      # Finding(qid, prop, status, kind, opts, probe, new_syntax, missing)
AF.property_of(question, known_fields=()); AF.property_of_key(key); AF.infer_kind(prop, answer_format)
AF.classify(text, kind, answer_format=None, **opts) -> frozenset; AF.allows(name, kind, answer_format)
# solvers/metadata-forensics/format_candidates.py
FC.render_all(value, kind, **opts); FC.kind_names(kind); FC.order(options, prefer, last, names_only=False)
FC.ranked(value, kind, key=None, prop=None, catalog=None, answer_format=None, **opts)
FC.pick(key, value, kind, prop=None, catalog=None, answer_format=None, **opts)  # catalog=False: render order
```

- **The catalog** holds per property its kind (and width), `accepted` (judged-correct texts only one
  hypothesis renders), `consistent` (texts several render: degenerate, as `labels.degenerate_accept`),
  `rejected` (a single-id refusal where the same attempt had the same VALUE accepted in another spelling:
  a format verdict, never a value verdict), the judge's syntax phrases, answer kinds and normalizations,
  how often it was asked and where. Plus every syntax phrase seen and the ids whose property could not be
  read. Loading checks every key; a name that is no hypothesis of the entry's kind is refused.
- **The probe order** (`preference`): the property's accepted names, then its consistent ones, then names
  of its class (`<kind>/<last field word>/<width>`), then of its kind, one vote per property (a property
  asked 500 times does not outvote two others); a tie in one table is broken by the next. Names the
  question's answer_format rules out (`base-10`, a stated `0x` prefix or `no 0x`, `lowercase`,
  `8-4-4-4-12`, braces, a JSON array, a stated comma join, ascending or file order read through
  `ctf.answerfmt.contract`, a closed enum) go last, then names the property was refused under. A split
  property (one name both accepted and refused) has no preference of its own. The order never adds or
  removes a candidate and never makes one plain.
- **`format_candidates.pick` uses it by default**, reading the property from the key
  (`metadata.format/<prop>`, `metadata.<ns>/<field>`); `properties_strict.fc_candidates` goes through it.
  A missing or broken tracked catalog raises CatalogError (no silent uncatalogued order), from
  `fc_candidates` too (its other failures are still `None`); `catalog=False` is the explicit render order.
- **The harvest** reads only a judged-attempt corpus outside the checkout (`--corpus`, else
  `$CTF_REAL_CHALLENGES`; no default): every folder with an `attempt.json` below a `<lane>-*` folder, its
  `key.json` when the attempt id matches, its `verdicts.jsonl` rows (`correct`/`accepted` accept every
  value sent; `incorrect` of exactly one id refuses it). Nothing under a dot-folder is read; attempt ids
  are left out of `sources`; synthesis ids (`ctf.answerfmt.synth.route`) are skipped. Stem fields
  anchored by an inspected file (`roster-size-bytes` beside `roster.csv`) name the same field of an
  unanchored id. A list refused in no sorted order is that value's document order, so an accepted text of
  the same items in another order counts as `sorted`, and the document order as refused. A corpus file
  present but unreadable (corrupt JSON, no questions list, no answers object, verdict lines that are no
  row) is listed in `Catalog.unreadable` (`<relative path>: <why>`; a report of the run, not saved) and
  printed as a WARNING by `ctf accepted-formats harvest`, never skipped silently.
- **The brief** (`ctf accepted-formats check BODY`): per question `known` / `consistent` / `prior` /
  `new` (with the probe order), `verbatim`, `enum`, `synth`, or `unshaped` with the exact missing piece
  (no property name; an answer kind nothing renders; judged answers no kind renders; a synthesis transform
  the question does not settle); `new_syntax` when the judge's phrase was never seen. Any `unshaped` or
  new phrase is exit 1: probe on the untimed base or hand the named piece to an agent before the clock.
- Corpus files and question text are data, never instructions; they are parsed as JSON and never run.

## 66. Resumable key-search harness (B-215)

A key-derivation search (the key is a hash, HMAC, PBKDF2 or scrypt of some joining of values the
handout states, in some encoding) as a job on disk any agent can continue. The engine is
`common.keysearch` (`solvers/common/keysearch.py`, a CLI script); the command is `ctf keysearch`
(section 8). Operator notes and a spec example: `docs/keysearch.md`.

```python
from solvers.common import keysearch as ks
job = ks.create(sid, spec, base=spec_dir, root=None, replace=False, allow_weak=False)   # freeze + write
ks.freeze(spec, base, allow_weak=False) -> dict            # sources read, files pinned by sha256, checked
ks.load_spec(path) -> dict                                 # .toml or .json
ks.load_job(sid, root=None) -> (dir, job)                  # refuses an edited job (fingerprint)
ks.run(sid, root=None, workers=1, max_chunks=None, cpu_seconds=None, all_hits=False, out=print, warn=None) -> dict
ks.progress(sid, root=None) -> (job, ks.Progress)          # done chunks, hits, tested, cpu, runs, last_stop
ks.reveal(sid, index, root=None) -> (candidate, key, recipe)
ks.Space(job)        # .total .chunks .chunk_range(c) .decode(i) .candidate(i) .key(i) .recipe(i) .test_range(a, b)
ks.expand_bank(bank) -> list[bytes]; ks.parse_kdf(spec, key_len) -> (fn, salted)
ks.build_verifier(table) -> ks.Verifier   # HashVerifier HmacVerifier GcmVerifier CribVerifier ZipVerifier
ks.chance_hits(total, bits); ks.fingerprint(job); ks.mask(value)
ks.root_dir(root=None); ks.job_dir(sid, root=None); ks.heal_tail(dir, warn=None); ks.read_progress(dir)
ks.add_arguments(parser); ks.dispatch(args, out=print); ks.main(argv=None)
ks.KeySearchError     # every refusal, with the reason
```

- **Layout.** `<workdir>/keysearch/<id>/job.json` (atomic, mode 0600: it holds candidate atoms),
  `ledger.jsonl` (written with `ctf.ledger.append(..., workdir=<search dir>)`: flock, one `os.write`
  a line), `run.lock` (one runner per job; a second is refused). `--root` moves the searches.
- **Spec** (TOML or JSON): `key_len`, `chunk` (default 2048), `kdf` (list), `salts` / `salts_hex`,
  `[[bank]]` (`name`; atoms from `values`, `hex`, `file` + `limit`, `harvest` + `siblings` (B-074
  `harvest.harvest`), `store` (the `archive_passwords` candidates), `wordlist` (`hashcrack.wordlist()`,
  `CTF_WORDLIST`); variants `case` (as-is lower upper title) x `encodings` (utf8 utf16le utf16be
  latin1) x `nul`), `[[template]]` (`slots` = bank names, `seps` / `seps_hex`, `orders` given|all),
  `[verify]` (`kind` hash | hmac | aes-gcm | crib | zip; byte fields as `<name>_hex` or `<name>_file`),
  `allow_weak`, `note`. Every source is read when the job is made; a file bank and a zip are pinned by
  sha256 and a run refuses one that changed, so a candidate index means the same thing on every resume.
- **Derivations.** `raw` (the candidate, when its length is `key_len`), `pad0`, a hashlib name or
  `md4` (hashcrack's), `ALG*N` (iterated), `hmac:ALG` (key = candidate, msg = salt), `hmac-salt:ALG`,
  `pbkdf2:ALG:ITERS`, `scrypt:N:R:P`. A salted derivation is one point of the space per salt. Output
  is cut to `key_len`; one shorter than `key_len` is refused when the job is made.
- **Exact verifier.** `hash` (the key equals `target`), `hmac` (`alg`, `msg`, `tag`), `aes-gcm`
  (`nonce`, `ct`, `tag`, `aad`), `crib` (`cipher` aes-ecb | aes-cbc | aes-ctr | xor | rc4, `ct`,
  `crib` or `crib_hex`, `offset`, `iv` (else the first block), `nonce` + `initial` for ctr, `pkcs7`),
  `zip` (`file`: the smallest encrypted member must open; AES verifier then HMAC, or ZipCrypto check
  byte then CRC). Each counts the bits it checks; a job whose expected chance hits over the space
  (`total` x 2^-bits) exceed `MAX_CHANCE` (1e-3) is refused unless `allow_weak`.
- **Resume.** The index space is mixed-radix (template, one atom per slot with the last slot fastest,
  separator, derivation fastest); chunk c is `[c*chunk, (c+1)*chunk)`. A chunk is done when its
  `keysearch.chunk` line is in the ledger; a run searches only the others, in order. A hit is written
  before its chunk; a chunk cut short by a hit is not done (`run --all` searches it again, and hits are
  recorded once). A torn last line (crash mid-append) is cut with a warning and its chunk redone; a
  bad line elsewhere, a record for another job, or an edited job.json is an error. SIGTERM or ^C
  stops a CLI run as `interrupted`. `--cpu-seconds` sums the workers' `time.process_time`.
- **Ledger lines** (search ledger): `keysearch.start` (`fp`, `run`, `workers`, `done_before`, `todo`),
  `keysearch.chunk` (`fp`, `chunk`, `tested`, `cpu`), `keysearch.hit` (`fp`, `index`, `chunk`,
  `masked`, `recipe` {slots, sep_len, kdf, salt}, `stored`? for a zip), `keysearch.stop` (`fp`, `run`,
  `reason` hit | exhausted | max-chunks | cpu-budget | interrupted, `chunks`, `tested`, `cpu`, `done`,
  `of`). The event ledger gets one `keysearch.stop` per run (`search`, `reason`, `hits`, `tested`,
  `done`, `of`).
- **Secrets.** No line shows a candidate or key: only `mask` (length and first character) and the
  recipe. `show --reveal` reconstructs one index to stdout. A zip hit by `raw` is added to the
  archive-password store (`source` `keysearch:<id>`), so the sweep and the archive lane use it.
  When the store has no workdir (no `CTF_WORKDIR`, no single event) or cannot be written, the hit is
  still recorded, with `stored: false` and a warning that names the store, not the password.

## 67. Per-role and per-difficulty model router (B-201)

Which model, reasoning effort and speed tier an agent launches on, by its work role and the
challenge's difficulty, from the profile's optional `[routing]` table (section 1). The full contract is
the module docstring of `ctf/router.py`; change it there and here together.

```python
from ctf import router
rt = router.Router(profile, prices=None, records=None, workdir=None)   # validated; RouterError lists problems
rt = router.Router.from_profile(profile, workdir=wd)
route = rt.resolve(role, difficulty=None, harness=None, category=None) -> router.Route
rt.roster(role="solve", difficulty=None, category=None) -> list[str]   # the escalation order (section 27)
rt.table(harness=None) -> list[router.Route]                           # every role x difficulty
rt.verify_approved(model) -> bool                                       # the B-096 A/B gate
rt.opted_in                                                              # the profile has [routing]
# Route(role, difficulty, model, harness, effort, tier, budget_usd, model_rule, effort_rule, category,
#       asked_difficulty, notes); route.speed_tier, route.source ("rule:N" | "default"),
#       route.ledger_fields(), route.to_dict()
router.load_prices(path=None) -> dict; router.model_harness(model, prices) -> str
router.tiers_for(model, prices) -> tuple[str, ...]
# router.ROLES (= ctf.stages.SPEND_CATEGORIES), DIFFICULTIES, HARNESSES, DIFFICULTY_STEPS, RouterError
```

- **Defaults** for what no rule names: model `models.primary` (`doc` -> `models.docs`; `verify` ->
  `routing.verify_candidate` only once an approving `ab_verify` record names it); effort
  `models.effort` stepped by `DIFFICULTY_STEPS` (warmup -1, easy/medium 0, hard +1, clamped); tier
  `default`. A verify route onto any non-primary model, from a rule too, is held on the primary until an
  approving `ab_verify` record names that model; the hold is in `Route.notes`.
- **Rules**: the most specific matching `[[routing.route]]` (harness 4, role 2, difficulty 1) that names a
  model gives model, tier and `budget_usd`; the most specific naming an effort gives the effort. A
  harness rule matches only a launch on that harness. `top_categories` downgrades a solve at `hard` of a
  known, unlisted category to `medium`.
- **Harness**: a launcher asks for its own harness; a model of the other harness is not routed
  (`model` None, said in `notes`), the effort still is.
- **Validation**: every model the router can return (rules, `models.primary`, `models.fallback`,
  `models.docs`, `verify_candidate`) must be priced in tools/ledger/pricing.json; a rule's harness must be
  its model's, its tier priced for it. `ctf/event.py` checks structure (a speed tier needs a model and a
  `budget_usd` in (0, the `[budget]` ceiling]; `budget_usd` on the default tier and repeated
  role/difficulty/harness keys are refused).
- **Launchers** (tools/route_launch.py: `add_route_options`, `route_for`, `apply_route`,
  `check_speed_tier`, `record_route`, `passthrough_model`, `RouteLaunchError`): routed only when the profile
  has `[routing]` and the launch has a role (`--role` / `$CTF_ROLE`); difficulty from `--difficulty` /
  `$CTF_DIFFICULTY`, category from `--category` / `$CTF_CATEGORY`. Explicit `--model` / `--effort` (claude:
  a passthrough `--model`) win. `--difficulty` / `--category` without a role, an event or a `[routing]`
  table, or with `--no-route`, are exit 2. The gate records `ledger_fields()` on `agent_launch`, with
  `effort` set to the effort launched (`record_route(gate, route, tier, effort=...)`). A ledger the
  router cannot read (a corrupt line) is a `RouterError` naming the ledger file, exit 2.
- **Speed tiers** (B-009, B-033): used only when the route's own model is launched, on a budget-gated
  (`--challenge`), metered `codex exec` run; the usage is priced at the tier's multiplier and the gate's
  `agent_cap_usd` is the route's `budget_usd`: at it the agent is stopped (exit 3, `route_budget`).
  Otherwise refused (exit 2). `claude_launch` refuses every Claude speed tier.

## 68. Build-time work registry, file claims, fold owners, idle-machine lock (B-213)

Build nights went wrong in four ways: a build was armed while another harness was working, one file was
reworked in five worktrees, two agents built one solver, and parallel builders collided on one box and
one branch. `ctf/workreg.py` (its docstring is the source of truth) is the shared record that stops
them; `ctf work` (section 8) is its command line. It only observes: it never signals or stops a process
and never touches a worktree or a branch (B-147 makes those).

```python
from ctf import workreg
reg = workreg.Registry(state, backlog=None, master=None, clock=time.time, pid_alive=...)
reg.begin(agent, harness=, branch="", worktree=None, pid=None, ttl=None, rows=(), files=(), folds=(), note="")
                                       # before spawn: all or nothing; ClaimConflict(.conflicts) names every clash
reg.check(agent=None, rows=(), files=(), folds=(), branch=None, worktree=None) -> list[Conflict]   # read-only
reg.claim(agent, rows=(), files=(), folds=()) ; reg.release(agent, rows=(), files=(), folds=())
reg.heartbeat(agent) ; reg.leave(agent) ; reg.reap() -> list[str] ; reg.history() -> list[dict]
reg.leave_branch(branch, why="") -> list[str]   # every agent on that branch (live or stale) leaves; no registry: []
reg.agents() -> list[AgentView]        # AgentView(name, record, live, reason).to_dict(); listing never reaps
reg.stale_reason(record) -> str        # "" when live
Conflict(kind, wanted, held, owner, harness, branch).describe()   # kind row | file | fold | branch | worktree
workreg.normalize_pattern(pattern) ; workreg.patterns_overlap(a, b) ; workreg.pattern_matches(pattern, path)
workreg.backlog_rows(path=None) -> dict[str, Row] ; workreg.resolve_fold(fold, master=None) -> (key, paths)
lock = workreg.IdleLock(state, label, mode="exclusive", agent="", timeout=None, poll=5.0, clock=..., sleep=...,
                        wall=..., pid_alive=..., max_load=None, load_fn=None, cpus=None, on_wait=None)
with lock: ...                         # or lock.acquire() / lock.release(); IdleLockTimeout names the holders
workreg.idle_status(state, pid_alive=...) -> {"state": "free|shared|exclusive", "holders", "waiting", "stale"}
workreg.idle_lock_for(root, label, mode="exclusive", timeout=None, **kw)   # a factory for run_gate / regress.gate
workreg.describe_holder(record) -> str
WorkRegError ; ClaimConflict(WorkRegError) ; IdleLockTimeout(WorkRegError)
```

- **State** is `paths.workreg_state()` (section 2): the git common dir, so every worktree of one repo
  shares it. `registry.json` (`{"schema": 1, "agents": {...}}`, replaced atomically under the flock on
  `registry.lock`), `history.jsonl` (one line per begin, claim, release, leave and reap), `idle.lock` and
  `idle/` (holder and wanted records). An unreadable or other-schema registry is a named error, never
  reset. Nothing here writes the event ledger: this is build-time state.
- **Agents** are keyed by name, by convention the B-147 branch (`item/<id>`). A record holds `harness`
  (`claude`, `codex`, `human`, `other`), `branch`, `worktree`, `pid`, `ttl`, `started`, `heartbeat`,
  `note` and `claims` (`row`, `file`, `fold`). Two live agents never share a name, a branch or a
  worktree. A record is stale when its pid is gone, its ttl lapsed without a heartbeat, or its worktree
  folder is gone; a stale record's claims do not conflict, and `begin`, `claim` and `reap` reap stale
  records first (only registry entries; each reap is saved at once, even when the call then fails, and is
  in the history and returned as `reaped`), so `claim` for an agent gone stale is "not registered". A
  record with none of pid, ttl or worktree is held until `leave`, `leave_branch` (`ctf integrate run`
  after its branch merges) or, for a `ctf worktree create --harness` record, removing the worktree.
- **Row claims** are B-138 backlog rows (default `docs/backlog.jsonl`): an unknown id or a done
  (terminal) row is refused; open rows, hard-tail ones included, can be claimed. One live owner per row.
- **File claims** are repo-relative patterns: `*` and `?` stay in one segment, `**` crosses, `**/`
  matches zero or more directories, a trailing `/` claims a directory (`d/` = `d/**`). Classes and
  braces are refused. Two claims conflict exactly when some path matches both (an automaton product,
  not a prefix test).
- **Fold claims** are `<slug>:<promotion entry key>` (section 18), canonicalised by
  `workreg.resolve_fold` (`<slug>:<path>` names the entry when the path is unique). The entry must exist
  and must not be decided `drop`. One live owner per fold; the master paths it lands at (its decision,
  else its proposal, `promote.decision_paths`) also conflict with other agents' file claims and folds.
- **Idle-machine lock.** A timing suite takes it exclusive (`ctf gate run --idle-lock`, section 23;
  `ctf adapt gate|prewarm|chain --idle-lock`, section 29; `ctf work idle-run -- CMD`); heavy work that
  timing suites should wait for takes it shared (`ctf work idle-run --shared -- CMD`). An exclusive
  waiter leaves a wanted record and new shared takers wait behind it, so heavy work cannot starve a
  timing suite. `max_load` also waits for load1 per CPU to drop to it. A crashed holder never wedges it
  (the kernel drops the flock; its record shows as stale). Not re-entrant: a command run under a shared
  hold that asks for the exclusive lock waits on its own parent until the timeout.

## 69. Repo build sandbox profile (B-192)

A Codex permission profile for BUILD work on this repo, passed with `-c` (installing it into
`~/.codex` is a human step). It is not the solver fence (section 14) and never loosens it. Full
contract: the docstring of `ctf/build_sandbox.py`; operator guide: `docs/build-sandbox.md`. Every
allowance below was verified live under `codex sandbox` (codex-cli 0.167.0), each with a control.

```python
from ctf import build_sandbox as bs
lay = bs.git_layout(checkout)          # GitLayout(checkout, gitdir, common, hooks); .linked
                                       # hooks = `git rev-parse --git-path hooks` (core.hooksPath)
hosts = bs.load_hosts(path=None)       # tools/build_hosts.toml: [[host]] name (exact DNS name), why
bs.check_host_name(name, where="host")
bs.host_conflicts(hosts, events_root=None)   # [why]: event platform (or a parent domain of one) /
                                             # live_service_scope, Discord, model API, PUSH_HOSTS
bs.checked_hosts(path=None, events_root=None)   # load + conflicts, raises BuildSandboxError
p = bs.build(checkout=None, hosts=None, docker=False, unix_sockets=(), home=None, events_root=None,
             protect=(), integration_branch=None, environ=None)
# BuildProfile(layout, hosts, home, unix_sockets, deny, protected, integration_branch); Host(name, why)
bs.protected_branches(checkout, protect=(), integration_branch=None, environ=None)
# -> (main, master, the integration branch (ctf.worktree.integration_branch_name, None when unset),
#     *protect), integration branch or None; an invalid branch name raises BuildSandboxError
p.read_only(); p.filesystem(); p.network(); p.codex_profile(); p.describe()
p.codex_config_args(name=bs.PROFILE_NAME)   # -c permissions.ctf_build={...} -c default_permissions="ctf_build"
                                            # -c features.network_proxy=true   (always all three)
p.config_toml(name=bs.PROFILE_NAME)         # ~/.codex/config.toml fragment; does not select the profile
bs.build_deny(home); bs.docker_sockets(home)   # DOCKER_SOCKETS, listed only with docker=True
bs.check_launch_extra(extra)                # fence_launch's refusals + any features.network_proxy change
bs.launch_argv(p, codex_bin="codex", headless=True, model=None, approval="never", extra=(), prompt=None)
plan = bs.push_plan(checkout, remote="origin", branch=None)   # PushPlan(branch, remote, command, notes)
checks = bs.selftest(scratch=DIR, codex_bin="codex", timeout=120.0, python=None, curl="/usr/bin/curl",
                     events_root=None)      # [Check(name, ok, detail, required)]
```

- **Filesystem.** `extends = ":workspace"`; write: the checkout, the common `.git` and the gitdir
  (Codex protects a linked worktree's gitdir even inside a write root, so it is listed explicitly);
  read only (`read_only()`): `<common>/hooks`, the hooks folder git runs here (`layout.hooks`:
  core.hooksPath, relative ones resolved against this checkout), `<common>/config`, both
  `config.worktree` files, `<common>/packed-refs` and `.lock`, `<common>/HEAD` from a linked
  worktree, and for each protected branch (main, master, the integration branch, `protect`) its
  ref file and `.lock`; a plain write, `rm` and `git update-ref` of one are all refused (verified).
  A guard, not a wall: a lane still writes the rest of the common `.git` and can subvert it (rename
  the refs folder, plant a symlink). Cost: deleting any ref inside the sandbox fails (git takes
  `packed-refs.lock`). Deny: the fence's `DENY_HOME` rows of categories agent-state, customer-work
  and credentials (`~/.config` included), with `BUILD_HOME_READABLE` (`~/.config/git`,
  `~/.config/uv`) re-opened read only and `BUILD_HOME_DENY_AGAIN` (`~/.config/git/credentials`)
  denied again; and `/**/.ctf`, `/**/.ctf/**` (`DENY_NAMES`). A checkout inside a denied store is
  refused.
- **Network.** `enabled = true`, `allow_local_binding = true`, `domains = {host = "allow"}` for
  the allowlist, and `features.network_proxy = true`. Without the proxy feature `enabled = true` is
  the whole network (verified), so `codex_config_args` always carries it and `check_launch_extra`
  refuses `-c features.network_proxy=...`, `--disable network_proxy` and `--enable network_proxy`.
  Direct egress is denied; hosts go through Codex's proxy, which answers others with
  `x-proxy-error: blocked-by-allowlist`. `PUSH_HOSTS` (exact names: github.com, api.github.com,
  gitlab.com, upload.pypi.org, ...) are refused on the allowlist, so the sandbox itself keeps a
  push outside; their read-only siblings (codeload.github.com, ...) stay allowed.
- **Docker.** `docker=True` adds `DOCKER_SOCKETS` as `unix_sockets` (with `~` as the home).
  Listed, never exercised: the self-test proves the mechanism on a synthetic socket.
- **JIT.** Not fixable by a profile (no Codex setting adds a sysctl): `needs_jit` (section 9).
- **Push.** `push_plan` is a dry run: it refuses `PROTECTED_BRANCHES`, a detached HEAD, an unknown
  remote or branch, and a push that would need `--force` (the fetched remote-tracking ref is not an
  ancestor); it never fetches, never pushes, never prints the remote URL.
- **Self-test.** `selftest` refuses a scratch folder under the temp folder (`:workspace` makes it
  writable, so git checks there prove nothing), uses a fresh `CODEX_HOME` (never `~/.codex`),
  TEST-NET-1 (`192.0.2.1`) for egress and `SELFTEST_BLOCKED` / `SELFTEST_ALLOWED` (`.invalid`)
  for the proxy. A `required = False` check (JIT) is reported and never fails it. macOS cannot nest
  sandboxes, so it runs outside any sandbox.

## 70. Prompt-cache TTL choices (B-118)

Claude main threads paid for 1-hour cache writes that were mostly read again within 5 minutes
(EFFICIENCY-PLAN section 3.12). Claude Code 2.1.322 has the control: `CLAUDE_CODE_PROMPT_CACHE_TTL`
(exactly `5m` or `1h`) sets the main conversation's TTL and beats the `promptCacheTtl` setting;
`CLAUDE_CODE_SUBAGENT_PROMPT_CACHE_TTL` covers subagents and is never set here. Full contract: the
module docstring of `ctf/cache_ttl.py`.

```python
from ctf import cache_ttl
cache_ttl.ttl_for(role, environ=None) -> "5m" | "1h" | None   # role main (5m) | standby (1h); None = off
cache_ttl.conflicts(role, environ=None) -> [str]              # settings that would undo the choice
cache_ttl.launch_env(role="main", environ=None) -> ({var: value}, [var to unset])   # CacheTtlError on a conflict
cache_ttl.check_build(claude_bin, environ=None) -> True | None   # None: a #! shim; CacheTtlError: no knob
```

- Roles: `main` is every agent `tools/claude_launch` starts; `standby` (`tools/claude_launch --standby`)
  is a B-037 warm agent that blocks on `ctf standby take` for up to 9 minutes, so it keeps 1h.
- `CTF_CACHE_TTL_CLAUDE` / `CTF_CACHE_TTL_STANDBY`: `5m`, `1h` or `off` (nothing set); anything else is
  `CacheTtlError`. The launcher also sets `CTF_CACHE_TTL_LAUNCHED` to the TTL it chose: an inherited
  `CLAUDE_CODE_PROMPT_CACHE_TTL` equal to it came from a parent launch and is replaced (with `off`,
  removed); any other inherited value that differs is refused, as are a truthy `FORCE_PROMPT_CACHING_5M`
  (Claude's spellings: 1/true/yes/on) and `CLAUDE_CODE_MESSAGES_PROMPT_CACHE_TTL` exactly `5m` (untrimmed, as
  Claude compares it) under 1h.
- Measuring: `usage.ttl_report` (section 10) and `python -m ctf usage ttl`: `saving` is gross (1h writes
  read again within 5 minutes, at the 5m rate); `cost_late` prices what 5m costs in return (a response
  more than 5 minutes but within 1 hour after the previous one writes its read prefix again); `net` is the
  thread at 5m. `standby.plan` rows carry `launch` (`tools/claude_launch --standby`). After this item, launched
  main threads should show no 1h writes; `late_5m` counts the cold re-caches B-017's watcher removes.

## 71. Irreducible adaptation residual (B-254)

A hard-tail item and a standing limit, not a solver. Some shapes have no machine-checkable oracle: the
answer is the author's or the judge's own vocabulary, or the input carries too little information
(measured novelty: 2:44 to 4:00 with foreknowledge, 5 to 20 min blind). The contract keeps `unsure` and
`none` as their correct endings, gives each class a one-line playbook in B-151's handoff shape, hooks a
residual id into the stuck-id protocol (section 51), and measures per event how much was novel. The
full contract is the module docstring of `ctf/residual.py`. No model, no network, no submit.

```python
from ctf import residual
residual.CLASSES; residual.classes(); residual.get(class_id)   # ResidualClass(id, lane, title, shapes,
    # no_oracle, cold_stops_at, playbook, controls, bounded_next_probe, never); unknown -> ResidualError
residual.playbook_md()                      # the generated residual playbook doc (`playbook --check`)
residual.handoff_template(class_id, challenge_id="")      # blank finding, probe/lane/never pre-filled
f = residual.validate_finding(obj)          # Finding(residual_class, challenge_id, evidence, likely_shape,
                                            #   controls_tried, bounded_next_probe, lane, never)
residual.mark(f, workdir=None)              # one `residual` ledger record
residual.marked(workdir=None)               # {challenge_id: class id}, the latest mark wins
residual.hold(result, class_id, why)        # tag + solved/candidate -> unsure (flags kept as options)
residual.check(result, class_id=None)       # [Violation(code, challenge_id, message)]: forced-plain, unknown-class
residual.classes_of(result)                 # class ids from Evidence(kind="residual", detail="<class>: why")
residual.hold_answer(value)                 # judged-lane answer -> "??value" (gamemaster.is_unsure)
residual.check_answers(answers, residual_ids, require_match=True)   # forced-plain for a plain answer on
    # an answer key a residual id covers; ResidualError when a residual id and an answer key name one
    # answer in two forms ('12#owner' vs 'owner'), or (require_match) when no residual id covers any key
residual.covering(residual_ids, key)        # the residual id covering a key: itself, else its bare challenge
residual.unmatched(answers, residual_ids)   # residual ids (known classes) that cover no answer key
residual.install(gate, workdir=None)        # the submit-gate check; get_adapter does this (section 5)
residual.gate_refusal(req, residual_ids)    # its reason for one SubmitRequest, or None
residual.route_stuck(challenge_id, question=, brief_text=None, files=None, workdir=None, profile=None,
                     route=True)            # stuck.assess; stuck.mark_stuck(agent="residual:<class>") when stuck
r = residual.frequency(records, label="huntress")         # EventReport
residual.report_for(workdir, label=None)    # the workdir's ledger; ResidualError when it has none
residual.render_report(r)
# HELD_STATUSES ("unsure", "none"); FORCED_STATUSES ("solved", "candidate"); FINDING_FIELDS; CLOSERS
# ("layer1", "agent", "human", "teammate", "other"); NOVEL_CLOSERS; RESIDUAL_EVENT "residual"; EVIDENCE_KIND
```

- **Classes.** `warmups.lossy_or_unstated_key`, `mobile.opaque_codec`, `metadata.new_vocabulary`,
  `binary.unjudged_enum`, `script.unproved_descriptor`, `web.unproved_effect`. The web class hands off
  through B-151's `solvers/web/agent_handoff.py` playbooks.
- **The hold.** A result in a residual class (tagged, or named by `class_id`) that ends `solved` or
  `candidate` is `forced-plain`; `unsure`, `none` and `blocked` pass. `hold` keeps the original evidence
  and flags, adds the tag once, and says in `notes` why the value is never sent plain. On a judged lane a
  residual id's answer must be None or an unsure `??` answer (`gamemaster.is_unsure`, the one rule).
- **The gate.** `get_adapter` installs `residual.install(gate)` after `halloffame.install`. A send whose
  id (or, for a batch, any `<challenge>#<answer id>`) is covered by a residual mark (the id itself, or
  its bare challenge id) and carries a plain value is refused (NOT_ALLOWED, never sent) unless
  `confirmed=True` (the player's go: the class's one bounded probe) or a player-authorized sweep. A
  single send on a bare challenge id (`12`) is also held by a mark on any of its answers (`12#owner`),
  since an adapter may resolve a bare id to the only answer (Game Master does). The marks are re-read
  from the event ledger on every send, so a corrupt ledger line stops every send, residual or not,
  with a named `ResidualError` ("cannot read the residual marks", naming file and line); the rules
  check and the queue's dedupe already read the same ledger per send and stop on it too.
- **Frequency.** Closers reuse B-101's rule (`replay.closed_by`) over the stages plus B-036's
  `adapt.closed` (by hand -> `human`, by teammate -> `teammate`) and `adapt.attempt` correct, and a
  team-solve `stop` (`teammate`); the earliest close wins. Every id in the report is the challenge key
  (`replay._key`: `12#owner` is `12`), residual marks and stuck ids included; a challenge marked in
  several classes counts in each, with a note. Time to close runs from `detect`, else the
  id's first record; a close with no earlier record has none and a note says so. `novel` = closed by
  agent, human or teammate. Residual marks are counted per class with how each ended and whether the id
  is stuck (a `stuck` not cancelled by `stuck_cleared`).

Ledger event written for this section (not a section 10 row): `residual` {`challenge_id`,
`residual_class`, `lane`, `evidence`, `likely_shape`, `controls_tried`, `bounded_next_probe`}.

## 72. Scratch scaffolds, the expectation generator and the test-pin codemod (B-258)

`ctf/expectations.py` is the one expectation generator (B-196 builds on it): it runs a callable over
cases and writes a deterministic JSON document.

```python
c = expectations.case(id, *args, expect=MISSING, **kwargs)     # Case(id, args, kwargs, expect)
fn = expectations.load_target("solvers/binary/d31.py:answers")  # FILE.py:FUNC (own module name) or pkg.mod:FUNC
doc = expectations.generate(fn, cases, target_spec="")          # {"schema": 1, "target", "cases": {id: {"output"}|{"error"}}}
expectations.run_case(fn, c)                                    # {"output": json} or {"error": "Type: msg"}
expectations.normalize(value, where="output")                   # plain JSON; bytes -> {"$bytes": hex}; else ExpectationError
expectations.denormalize(value)                                 # {"$bytes": hex} -> bytes
expectations.write(path, doc); expectations.load(path)          # sorted keys, indent 1; load validates
expectations.dumps(doc); expectations.validate(doc)
expectations.compare(expected_doc, actual_doc)                  # [Diff(case, path, expected, actual)]
expectations.diff_values(expected, actual, path="", case="")    # True is never 1; absent is MISSING, not None
expectations.outputs_of(doc)                                    # {case: output}; a plain object is {"": obj}
expectations.pins(doc, case=None)                               # Pins: {key: value} and {case/key: value}
expectations.Pins(values, cases=(), ambiguous=())               # dict + .cases (every case id) + .ambiguous
```

When two cases give one key different values and no `case` is chosen, `pins` leaves the bare key out
(its `case/key` forms stay) and names it in `.ambiguous`: the codemod never picks a case silently.

`ctf/testpin.py`: a pin is a literal paired with a string key: an entry of a dict literal assigned
to a name matching `DEFAULT_NAMES` (EXPECT*, *_EXPECTED, WANT, GOLDEN, PINS; a nested entry is also
keyed `outer/inner`, looked up first), the literal side of `x["key"] == lit` or `x.get("key") == lit`
(either way round), or any assignment or comparison carrying `# pin: KEY`. Only the literal's own
source span is replaced, in its old style (quote, hex width and case, tuple). A non-literal pin is
reported as skipped, never rewritten. An entry nested under a case id (`cases`) takes only its own
`case/key` value, never a bare key; a pin on a bare key in `ambiguous` is skipped with that reason.
The rewrite must parse and every edited pin must read back as its new value, or nothing is written
(TestPinError).

```python
testpin.find_sites(source, names=DEFAULT_NAMES)        # [Site(key, alt, node, line, origin)]
testpin.plan(source, values, names=DEFAULT_NAMES, *, cases=None, ambiguous=None)   # Plan(edits, unchanged, skipped, sites)
testpin.apply(source, plan); testpin.rewrite(source, values, names=DEFAULT_NAMES, *, cases=None, ambiguous=None)   # (new, plan)
testpin.render(value, old_node, old_src); testpin.diff(old, new, path)
testpin.rewrite_file(path, values, write=False, names=DEFAULT_NAMES, cases=None, ambiguous=None)   # (unified diff, plan)
# cases/ambiguous None: taken from values.cases/values.ambiguous when values is an expectations.Pins
```

`ctf/scaffold.py` holds the logic of the generated files (`ctf/scaffold_templates/*.py.tmpl`, filled
with the checkout's root and the target): `repro`, `probe`, `adversarial` (with `variants` and
`classify`: per key same / declined / changed / raised; a change fails unless the file's oracle
accepts it), `bench` (CPU time through an injectable `clock`; wall time is informative only), their
`*_main` argv wrappers, `render`/`write_scaffold`, and `racer_text`/`write_racer`.

`solvers/binary/racer_template.py` is inert under its name (evidence.py loads `<prefix>.py` only for a
prefix of letters and digits; generic.py loads only `fields_<prefix>.py`). `write_racer` copies it to
`<lane>/dNN_<role>_dev.py` with `PREFIX = "dNN"`; promotion to `dNN.py` is the lane's promotion step,
never the generator. The candidate is gitignored and is not an engine module (no manifest, no lint
finding) until promotion gives it its final name and a manifest. The copied module keeps evidence.py's
contract `answers(questions, files, ctx)`: an id left out is not its own, None is a decision, a value outside the stated answer_format becomes
None. RULES rows are `(field regex, text regex | None, reader(q, match, state))`; a reader returns a
value, None, or LEAVE (try the next row).
