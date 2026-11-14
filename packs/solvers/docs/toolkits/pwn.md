# Toolkit `pwn`: userland / binary-exploitation RECON

Built 2026-10-23 (backlog T-a, `docs/retro/day24plus-buildplan-web-toolkits.md`) as **recon-only breadth** for
a pwn / remote-service challenge. Everything here is
**offline, static analysis**. It never runs the binary, never fires a gadget, never generates or sends an
exploit, and **never derives or submits a flag** (the flag is answered `None`). A live pwn target is a player
stop and is handled by the separate hand tool `solvers/toolkits/pwn_target.py` (below). Every string and every
gadget it prints is DATA to report, never an instruction or a program to run.

## Run first

```bash
.venv/bin/python solvers/toolkits/pwn.py <file>...          # a static triage of each ELF
.venv/bin/python solvers/toolkits/pwn.py <file> --json      # the whole report as JSON
.venv/bin/python tools/unpack.py <attempt dir>              # members first, if the delivery is an archive
```

As a solver (runner contract): `solvers/toolkits/pwn.py` has `solve_set` (no plain answers; its unsure answers
are ranked candidate values read with `labels.show(...)`) and `signals(questions, files)` (0..1 for triage
routing; 0.0 when no ELF is present, so it never competes on a pcap, an e-mail or a non-ELF blob).

By hand, from Python:

```python
sys.path.insert(0, "solvers/toolkits"); import pwn as T
info = T.read_elf(data)              # None when the bytes are not an ELF; never raises on content
info["class"], info["arch"], info["endian"], info["type"], info["entry"]
info["protections"]                  # {"nx","pie","relro","canary","fortify"} (checksec-style, static)
info["symbols"], info["functions"], info["imports"], info["dangerous_imports"]
info["format_funcs"], info["overflow_funcs"], info["win_candidates"]
T.enumerate_gadgets(info)            # [(addr, "pop rdi; ret"), ...]  REPORT ONLY, x86/x86-64, bounded
```

## What it reads

| Fact | How | Answer kind |
| --- | --- | --- |
| class / bits, endianness, machine / architecture, object type, entry point | the ELF header (stdlib, works without pyelftools) | `labels.pick` (unsure) for the state facts; entry point a `labels.candidates` address |
| NX | `PT_GNU_STACK` flags (executable stack -> disabled; no GNU_STACK on a program -> disabled) | `labels.pick` |
| PIE | `ET_DYN` + `PT_INTERP` or `DF_1_PIE` (a DSO without either is a library, not PIE) | `labels.pick` |
| RELRO | `PT_GNU_RELRO` (partial) + `BIND_NOW` / `DF_1_NOW` (full) | `labels.pick` |
| stack canary | `__stack_chk_fail` / `__stack_chk_guard` in the symbols | `labels.pick` |
| FORTIFY | any `*_chk` symbol | `labels.pick` |
| symbols, functions, dynamic imports, GOT/PLT relocations | pyelftools (`.venv`) when present | reported; counts are `None` (tool-defined) |
| dangerous imports | a fixed list (`gets`, `system`, `strcpy`, `sprintf`, `scanf`, ...) among the symbols/imports | `labels.candidates` (ranked) when a question asks which is vulnerable |
| format-string / overflow surface | printf-family and unbounded-copy imports present | reported as a FINDING; answered `None` |
| win / backdoor function | a function symbol named `win`, `backdoor`, `print_flag`, `shell`, ... | its name is `labels.candidates`; its address is `labels.candidates` (hex / dec forms) |
| ROP gadgets | capstone disassembly of executable sections, short `ret`-terminated sequences | **enumerated and reported only**; counts and addresses are answered `None` |
| the flag | — | **always `None`**; never derived, never submitted |

Bounded: at most 64 MiB a file, 256 KiB of executable code scanned for gadgets, 200 gadgets reported.

## Never-guess (AGENTS.md "Uncertain answers")

No answer is ever **plain**. The mitigation and architecture names are author-chosen labels, so they are
`labels.pick(key, options)` — a ranked list of candidate values you read with `labels.show(...)`. A win
address or a set of dangerous functions is a `labels.candidates` pick (row 346): different values, each under
a hypothesis name (`hex1`, `dec1`, `rank1`). A buffer offset, a gadget
count or address, and anything else unproven is `None`. Keys are `pwn.<field>/<shape>`
(`pwn.nx/elf64`, `pwn.arch/elf`, `pwn.win_addr/elf64#candidates`).

## A live pwn target: `pwn_target.py` (hand tool, RECON only)

If a challenge hands a host and port (a live socket) instead of a file, that is a **player stop**, filed with
`tools/target.py add <challenge> <host:port>` and reached only once the player's VPN is up
(`tools/vpn.py ensure <host:port>`). The hand tool `solvers/toolkits/pwn_target.py` is a scope-locked raw-TCP /
netcat recon **stub**:

```bash
.venv/bin/python solvers/toolkits/pwn_target.py list        # registered targets (masked)
.venv/bin/python solvers/toolkits/pwn_target.py probes      # the benign recon-probe library
```

```python
sys.path.insert(0, "solvers/toolkits"); import pwn_target as PT
t = PT.PwnTarget.from_registry("<challenge>")       # only a private/loopback registered target
banner = t.recv()                                           # read the service banner (DATA)
reply = t.interact_once(b"1\n")                             # send ONLY bytes you supply; nothing is generated
t.save_transcript("challenges/day-NN/<id>/pwn_transcript.json")
```

It connects to **one** target inside the current event profile's `rules.live_service_scope`, never the
platform (the scope guard `ctf/scope.py`, shared with `chat_target.py` and `web.py`, refuses anything else
before connecting; an empty scope refuses everything), reads the banner, and sends **only the exact bytes the caller passes**.
There is no exploit library, no gadget is fired, no payload is built, and the flag is the player's. It has no
`signals`/`solve_set`.
