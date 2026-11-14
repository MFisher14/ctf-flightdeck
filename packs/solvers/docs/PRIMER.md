<!-- GENERATED FILE, do not edit. Rendered by ctf/primer.py; regenerate with `python -m ctf engines generate` (B-199). -->

# Repo primer

Read this once at the start of a session instead of opening files to orient. It is generated
from the tree; `docs/FILE-INDEX.md` has one line for every command and module.

## Start here

- `CLAUDE.md`: the rules for working on the master itself
- `BUILD-PLAN.md`: the build plan and order (B-ids)
- `docs/CONTRACTS.md`: the interfaces every builder codes against (the code wins where they differ)
- `docs/BUILDING.md`: how to add an engine: manifest, router, runner
- `docs/CAPABILITIES.md`: every engine, what it does and when triage suggests it (generated)
- `docs/OPERATIONS.md`: running an event
- `docs/FILE-INDEX.md`: every command and module in one line each (generated; grep it)

## Reading this repo cheaply

Every tool result is re-read on every later turn, so read once and narrowly.

- **Orient from the primer.** At the start of a session run `python -m ctf primer` (it prints
  `docs/PRIMER.md`, generated: where to start, the layout, the large files) instead of opening
  files to find your way.
  `docs/FILE-INDEX.md` lists every command and module in one line each: query it with
  `python -m ctf read docs/FILE-INDEX.md --grep <word>`, do not read it whole.
- **Read by query, not by window.** `python -m ctf read PATH --grep PATTERN`, `--lines A-B` (under
  150 lines) or `--symbol NAME` (exactly one function or class). It caps the output and tells you
  when another agent already read the same thing. No `cat`, `sed -n` windows or whole-file reads.
- **Large modules by symbol.** `python -m ctf symbols PATH` lists a module's functions and classes
  with line ranges, its imports and its importers; `python -m ctf symbols --find NAME` finds where a
  name is defined. Then `python -m ctf read PATH --symbol NAME`. Never page through a large file.
- **Binaries: `ctf read` first.** `python -m ctf read FILE` on a binary prints its type, size,
  hash, entropy, a hex head and its strings with offsets; `--strings` lists every string and
  `--bytes N` is a longer hex view. Do not open a binary with a text reader, `cat` or `xxd`.
- **Research once per event.** Before a web or standards look-up run
  `python -m ctf research get "<query or URL>" --claim`. Exit 0 prints the answer another agent
  stored. Exit 1 means it was a miss and you now hold the claim: look it up, then store what you
  found with `python -m ctf research put "<query or URL>" --answer "<summary>" --source <url>`
  (or `python -m ctf research release "<query or URL>"` if you give up). Exit 3 means another
  agent is looking it up now: do other work and ask again; do not fetch it in parallel. Store a
  summary with its sources, never a secret.

## Layout

| folder | what |
|---|---|
| `ctf/` | the platform client, CLI (`python -m ctf`), orchestration, policy, gate and every shared service |
| `solvers/` | the solving engines, one folder per lane; each engine has a `*.manifest.toml` beside it |
| `tools/` | operator tools and launchers (`tools/ctfpy` runs engine code with the right interpreter) |
| `tests/` | the suite (`.venv/bin/python -m pytest`); `tests/gate.toml` maps files to tests |
| `docs/` | contracts, build logs, capabilities, coverage, runbooks and playbooks |
| `events/` | one folder per event: `event.toml` and the generated CLAUDE.md / AGENTS.md |
| `templates/` | templates rendered by commands (event agent rules, write-ups, hand-offs) |
| `workflows/` | shipped Workflow-tool scripts (B-194) |
| `openers/` | armed Layer-1 opener and reader tables (B-014, B-139) |
| `speedrun/` | the speed-run harness and its solvers |
| `corpus/` | the rehearsal corpus index |
| `docker/` | the sandbox images: untrusted artifacts run only in these |

## ctf packages

| package | what |
|---|---|
| `ctf/adapt/` | The per-lane adaptation loop (B-036): a new lane component becomes a no-model close by the next clock. |
| `ctf/answerfmt/` | The answer-format renderer: every answer formatted from its question's answer_format (B-232). |
| `ctf/cli/` | Command line for the CSCTF solver backbone. |
| `ctf/cockpit/` | Manual-mode cockpit (B-209): drop-zone watcher, needs checklist, submission queue. |
| `ctf/codec/` | The shared recursive codec graph (B-163), used by every lane. |
| `ctf/engines/` | Engines: manifests, routing, lint, coverage matrix, the runner (B-186, B-187). |
| `ctf/formats/` | Ranked format catalog, structural identification and the synthetic corpus (B-162). |
| `ctf/gate/` | The regression gate (B-195): impact-selected test files, exact-hash warm reuse, load-scaled walls. |
| `ctf/intake/` | Parallel no-model intake per challenge (B-002). |
| `ctf/integrity/` | Test and docs integrity tooling (B-196): checks that a green suite means a tested tree. |
| `ctf/lanes/` | Programmatic Codex build lanes (B-179). |
| `ctf/lookahead/` | The look-ahead completeness gate (B-174): a forecast is green only when tomorrow's stated deterministic work is covered, not when known rea… |
| `ctf/openers/` | Armed Layer-1 openers per lane (B-014). |
| `ctf/platform/` | Platform adapters, selected by the event profile's platform.kind. |
| `ctf/recover/` | Recovery the archive walk does not do (B-029): files of a disk image, deleted ones included, and both sides of a tracked-change Word docume… |
| `ctf/testing/` | Test infrastructure shared by the suite (the pytest marker plugin). |
| `ctf/toolchain/` | The pinned toolchain (B-188): images, assets, the per-lane environment, version notes, wheels. |
| `ctf/writeup/` | Writeup and retro pipeline, and the (dry-run) public-repo publish path (B-098). |

## Solver lanes

Engines, their routes and needs: `docs/CAPABILITIES.md`.

| lane | what |
|---|---|
| `solvers/binary/` | reverse engineering and binary analysis engines |
| `solvers/common/` | shared engine libraries (codecs, crypto, evidence, proposers) imported by the other lanes |
| `solvers/metadata-forensics/` | file-format readers and metadata / forensics engines |
| `solvers/mobile-android/` | APK / DEX / Android engines |
| `solvers/script-analysis/` | script, deobfuscation and codec-plan engines |
| `solvers/toolkits/` | per-topic toolkits (network, windows, web, crypto, cloud, stego, ...) |
| `solvers/warmups/` | warm-up and classical decoding engines |
| `solvers/web/` | Web-exploitation lane solvers (live targets). |

## Large files

Read a module of 2000+ lines by symbol, never in slices: `python -m ctf symbols PATH`, then
`python -m ctf read PATH --symbol NAME`. `docs/FILE-INDEX.md` lists every one; the largest:

- ~7k lines: `solvers/metadata-forensics/properties_strict.py`, `solvers/mobile-android/codec_search.py`, `solvers/web/proof_hunt.py`
- ~6k lines: `solvers/warmups/crib_decode.py`
- ~5k lines: `solvers/binary/generic.py`, `solvers/mobile-android/dex_chain_codec.py`, `solvers/mobile-android/dex_float.py`, `solvers/toolkits/web.py`, `solvers/toolkits/web_evidence.py`
- ~4k lines: `solvers/binary/field_catalog.py`, `solvers/common/modern_crypto.py`, `solvers/toolkits/modern_crypto.py`, `solvers/toolkits/network.py`, `solvers/toolkits/windows.py`
