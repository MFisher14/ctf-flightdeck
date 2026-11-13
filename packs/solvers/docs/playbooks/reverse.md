# Playbook: reverse engineering

Recover logic from a compiled artifact. The engines are **static/offline** readers; they
never execute the sample. When you must *run* or *emulate* untrusted code, do it in Docker
(`csctf-pwn:1` for x86-64, `csctf-sandbox:2` otherwise) — never on the Mac.

Set this once per shell:

```bash
cd <ctf-tools checkout>                   # every command on this page runs from the checkout root
export CTF_EVENT=<event slug>             # the event profile, events/<slug>/event.toml
.venv/bin/python -m ctf workdir --create  # the workdir (ctf.paths): $CTF_WORKDIR, else ~/ctf-work/<event>
```

`workspace/` on this page means that workdir (`.venv/bin/python -m ctf workdir`). Files land in `workspace/<id>-<slug>/files/` (UNTRUSTED). `./csctf pull all` fetches + triages.

---

## 1. First moves (identify before you dig)

```bash
F=workspace/<id>-<slug>/files/<sample>
.venv/bin/python solvers/binary/binfmt.py "$F"   # container + arch (ELF/PE/Mach-O/wasm/DEX)
.venv/bin/python solvers/binary/facts.py "$F"    # LANGUAGE / toolchain — picks your whole approach
.venv/bin/python solvers/toolkits/pwn.py "$F"    # (ELF) stripped? symbols? imports?
python3 tools/sandbox.py run --in "$F" strings -n 8 {in} | grep -iE 'csctf|chronos|flag\{'
```

`facts.py` is the fork in the road: Go/Rust/.NET/PyInstaller/Java/Kotlin/Nim/Zig/Unity each
have their own route below. Then decompile (§3) and read the check.

---

## 2. Engine CLIs (verified in this repo)

### Container & header facts — `solvers/binary/binfmt.py`
```bash
.venv/bin/python solvers/binary/binfmt.py "$F"
```
ELF / PE / Mach-O(+fat) / WebAssembly / DEX / Neko headers: bits, machine, entry, sections,
segments, dynamic `NEEDED`, build id. None → "the container proves it is not that format".

### Language / toolchain marks — `solvers/binary/facts.py`
```bash
.venv/bin/python solvers/binary/facts.py "$F"
```
Prints what the file says about itself: `go_version` / `rustc_version` / `compiler`;
`dotnet_metadata_version`; `pyinstaller_*`; Java `class_*` / jar `jar_main_class`;
`kotlin_metadata_*`; `dex_version`; `wasm_version`; Mach-O `macho_*`; **UPX** packer; and
Nim/Zig/Crystal/D/GHC/Swift markers.

### Strict managed/VM formats and protector evidence — `solvers/toolkits/reverse_formats.py`

```bash
.venv/bin/python solvers/toolkits/reverse_formats.py scan "$F"
.venv/bin/python solvers/toolkits/reverse_formats.py wasm "$F"
.venv/bin/python solvers/toolkits/reverse_formats.py dotnet "$F"
.venv/bin/python solvers/toolkits/reverse_formats.py ebpf raw-insns.bin
.venv/bin/python solvers/toolkits/reverse_formats.py vmlift opcode-spec.json
.venv/bin/python solvers/toolkits/reverse_formats.py symbolic-plan angr-spec.json
```

`scan` requires structural format evidence for JVM/WASM/.NET/eBPF and labels Go/Rust/Swift strings
as leads only. It parses CLR `BSJB` stream headers (declining overlapping or multiple valid roots),
WASM section order/import/export/code framing, and raw eBPF registers/`LD_DW_IMM` pairs/jump targets/
helper calls. The deeper existing .NET metadata-table reader remains
`solvers/metadata-forensics/readers_dotnet.py`; Java/Kotlin constant pools and metadata remain in
`facts.py`; Go/Rust string/symbol leads remain in `reverse_depth.py`. Swift support is evidence and
metadata routing, not a complete reflection/demangling implementation.

Packer output is deliberately not an unpacked-value claim. UPX needs two independent signatures;
VMProtect and Themida/WinLicense need multiple PE markers. One marker is reported only as `*-like`
and receives no unpack plan. Any actual `upx -d`, trace, or debugger step stays inside the networkless
sacrificial Docker container, followed by independent container/architecture revalidation.

`vmlift` mechanically maps bytecode through a reviewed opcode table and checks immediate and branch
boundaries; a program containing branches must explicitly set `branch_mode` to `relative` or
`absolute`. Its IR always says `verified: false` because a mislabeled handler creates a perfectly
well-framed but wrong lift; verify handler semantics in native disassembly. `symbolic-plan` wraps the
existing source-only angr generator with a hash, Docker-only instruction, and an explicit requirement
to replay a unique model through the original checker before accepting it.

### ELF symbol/stripping recon — `solvers/toolkits/pwn.py`
```bash
.venv/bin/python solvers/toolkits/pwn.py "$F"
```
Checksec + `symbols/functions/imports` counts + dangerous imports. Tells you fast whether an
ELF is stripped and what it links.

### Field catalog (reference) — `solvers/binary/field_catalog.py`
```bash
.venv/bin/python solvers/binary/field_catalog.py --list   # every field rule + its key
```
Use `--list` to see every per-sample fact the catalog *can* name (language marks, ELF/PE/
Mach-O/wasm/DEX header fields, packers). **Note:** the per-field query mode
(`field_catalog.py SAMPLE FIELD`) depends on day-template modules that were stripped from this
repo and raises `ModuleNotFoundError` — read the actual per-sample facts with `binfmt.py` /
`facts.py` / `pwn.py` instead.

### Crackme input recovery — `solvers/toolkits/symbolic.py` (z3)
```bash
.venv/bin/python solvers/toolkits/symbolic.py --selftest    # prove the engine works
.venv/bin/python solvers/toolkits/symbolic.py "$F"          # READ cmp immediates (recon)
```
Reads comparison constants from the disassembly; the solve is a Python API that returns the
input **only when z3 proves it unique** (never-wrong). Ideal for "what string makes `check()`
return 0". (No angr here — z3 via this module is the symbolic path.)

### Unity IL2CPP — `solvers/toolkits/il2cpp.py`
```bash
.venv/bin/python solvers/toolkits/il2cpp.py <global-metadata.dat> [--json]
```
For Unity games/apps whose C# was AOT-compiled. Recovers **string literals** (byte-exact,
plain-eligible) and **type/method/field names** (author labels → unsure candidates), plus the
metadata version and counts. Behaviour (what a method *does*) stays `None` — read that from the
paired `libil2cpp.so` / `GameAssembly.dll`.

### Library modules (no CLI — import / called from the lane)
- `solvers/binary/static_re.py` — bounded static-RE fallback: picks one executable, disassembles
  exact symbol-backed ELF functions, may hand a stripped pure decoder to the whole-image
  emulator, and lifts a crackme to z3 when the input length + success convention are stated.
  API: `eligible(questions, files, ctx)`, `answers(questions, files, ctx)`.
- `solvers/binary/native_behavior.py` — bounded whole-image **x86-64 emulator** for a *described*
  lone/static ELF integer decoder. API: `asks(q)`, `contract(q)`, `answer(q, data)`. Returns the
  value the decoder computes; nothing runs on the host. Since B-166 the decoder need not be called
  from the entry point (targets come from `decoder_discovery.unary_rows`).
- `solvers/binary/decoder_discovery.py` — **automatic decoder discovery** (an engine:
  `python -m ctf run binary.decoder_discovery <challenge_dir>`). Maps the functions of an x86-64 /
  AArch64 ELF (stripped or not), binds each call's arguments from the call site (constants, image
  pointers, stack buffers) and from B-011's pseudocode in `recon/decompile/`, ranks decoder
  candidates (B-026's mixer and check readers are leads) and emulates the bound calls in the loaded
  image, capturing what a decoder prints (puts / putchar / printf / write). One flag-format output
  is a `candidate`; two different ones are `unsure` (decoy or real: read the evidence). A candidate
  it could not bind is listed with the reason.
- `solvers/toolkits/pe_emu.py` — offline PE mapper + **fail-closed x86-64 Unicorn**; an **API-hash
  resolver** (`resolve_api_hash`, `build_api_hash_index`, `hash_ror13/djb2/fnv1a/crc32`) and a
  compare-site finder. For shellcode / packed PE / API-hashing malware.
- `solvers/binary/pe_resources.py` — `walk(data)` a PE resource directory (icons, `RT_RCDATA`,
  manifests, embedded blobs) to pull an embedded payload or flag resource.

---

## 3. Docker / host decompilation

**Rule:** static disassembly/decompilation is analysis; *running or emulating* the sample is
Docker-only.

Decompile & disassemble in `csctf-sandbox:2` (radare2 + r2ghidra, offline, read-only root):
```bash
python3 tools/sandbox.py run --in "$F" rabin2 -I {in}                 # bininfo / checksec
python3 tools/sandbox.py run --in "$F" rabin2 -z {in}                 # strings in data sections
python3 tools/sandbox.py run --in "$F" rabin2 -s {in}                 # symbols
python3 tools/sandbox.py run --in "$F" r2 -q -c 'aaa; afl' {in}       # list functions
python3 tools/sandbox.py run --in "$F" r2 -q -c 'aaa; pdg @ sym.main' {in}   # r2ghidra decompile
python3 tools/sandbox.py run --in "$F" objdump -d {in}
python3 tools/sandbox.py run --in "$F" readelf -a {in}
python3 tools/sandbox.py run --in "$F" upx -d -o {out}/unpacked {in}  # if facts.py flagged UPX
```
`python3 tools/sandbox.py tools` lists every tool by image. Host **radare2** (`r2 -A <file>`,
`rabin2 -I`) is also fine for quick static triage — it parses, it does not execute the target.
(Ghidra is **not** installed on this Mac; use the sandbox's r2ghidra `pdg` for decompilation.)

**Running / emulating** untrusted code: x86-64 in `csctf-pwn:1` (qemu-user, `gdb-multiarch`,
`ltrace`/`strace`); other formats via the sandbox tools above. Never execute on the host.
```bash
docker run --rm -it --platform linux/amd64 --network none \
  -v "$PWD/workspace/<id>-<slug>/files":/chal:ro csctf-pwn:1
```

---

## 4. Techniques → engines (by what `facts.py` found)

| Sample | Route |
| --- | --- |
| Stripped C/C++ ELF crackme | r2ghidra `pdg` to read `check()`; `symbolic.py` + z3 (or `native_behavior`/`static_re`) for the exact input |
| UPX-packed | `facts.py` flags it → `upx -d` **in the sandbox** → re-triage the unpacked file |
| Go / Rust | `facts.py` gives the version; symbols usually survive → r2/`objdump`; look for the embedded flag check |
| .NET / managed | `facts.py` `dotnet_metadata_version` → `ilspycmd <asm.dll>` (dotnet global tool, installed by setup.sh) for C#; or `monodis`/`strings` for a quick read |
| PyInstaller | `facts.py` `pyinstaller_*` → `.venv/bin/python solvers/binary/pyinstaller_extract.py <exe> --json`; the bounded pure-Python CArchive reader validates cookie/TOC/zlib entries and reports string/flag leads without unmarshalling. Add `--extract-dir OUT --pyc-magic-hex <8 hex>` only when the cookie's Python version matches a known magic. `docker_disassembly_plan()` emits a literal `--pull=never --network none` Python `dis` plan; marshal/decompile only there. The 2024 Ransom/Chrono-key pattern often exposes the hardcoded pw/hash before full decompilation. |
| Windows API-hashing / shellcode | `pe_emu.resolve_api_hash` to name the hashed APIs; `find_compare_sites` for key checks |
| Unity (IL2CPP) | `il2cpp.py` on `global-metadata.dat` for literals + symbol names |
| Java / Android (dex/apk/jar) | `facts.py` IDs it → host `jadx` / `apktool` (see the mobile playbook) |

---

## 5. Get the flag out & submit

RE flags are recovered **statically** — a decoded constant, a z3-recovered input, a decrypted
string, an IL2CPP literal. Reason to the one `csctf{...}` / `chronos{...}` value, then submit once:

```bash
./csctf submit <id> 'csctf{...}' --note 'z3-recovered key from check()'
```
or from a solver: `ctf.submit.guarded_submit(ctfd, ch, flag, provenance="...")`. The guard does
the flag-format check (the event profile's `[flag]` (`events/<slug>/event.toml`, read through `ctf.flagfmt`)), dedupe, pacing, skip-solved, and **stop-and-ask
after 3 wrong**. **Never brute-force or loop candidate flags** — one reasoned flag, one submit.
Check `./csctf check <id>` first and skip anything a teammate already solved.

> Pure RE has no live target, so no scope/rate concerns — *unless* it's a keygen-me that phones
> a service. Then treat the network step like pwn: assigned target only, no flooding (see
> `pwn.md` §5 and AGENTS.md fair play).

## Symbolic and obfuscation depth

`solvers/toolkits/reverse_depth.py` has four static modes. `angr` turns a bounded JSON check
description into a source-only angr harness (find/avoid addresses, stdin/argv width, byte constraints)
for the player to run in Docker; the generator never imports angr or executes the binary. `cfg` ranks
opaque predicates and control-flow-flattening dispatcher evidence, `vm` clusters bytecode handlers
and inferred stack/register effects, and `symbols` recovers Go buildinfo/string-shaped symbol leads
and Rust v0/legacy name/type leads. It does **not** claim a complete `.gopclntab` reconstruction.
Treat all deobfuscation output as navigation hints and verify recovered input against the original
check in the sandbox.
