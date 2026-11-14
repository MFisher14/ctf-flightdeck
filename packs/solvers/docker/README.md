# Docker images

Untrusted challenge artifacts are executed/detonated **only** inside these images, never on the Mac.

## `csctf-sandbox:1` / `csctf-sandbox:2` — analysis sandbox

Warm, isolated containers (`--network none`, read-only root, all capabilities dropped,
no-new-privileges, unprivileged user, cpu/mem/pid limits, a read-only `/drop` and a writable `/out`).
Driven by `tools/sandbox.py`.

- **`:1`** (`docker/sandbox/Dockerfile`) — upx, tshark, Volatility 3, oletools, binwalk, 7-Zip, YARA, file.
- **`:2`** (`docker/sandbox/Dockerfile.2`) — all of `:1` plus steghide/stegseek/zsteg/outguess/stegsnow,
  tesseract, exiftool/exiv2/pngcheck, foremost/scalpel/bulk_extractor/sleuthkit, poppler/qpdf/mutool,
  ffmpeg/sox, zbar/qrencode, multimon-ng/minimodem/rtl_433, radare2 + r2ghidra, python readers
  (scapy/evtx/regipy/lnkparse3/extract-msg/fickling), and the bytecode decompilers of B-167:
  pycdc/pycdas and decompyle3 (Python `.pyc`), CFR and Vineflower on a headless JRE (Java
  `.class`/`.jar`). Every download is pinned by SHA-256 in the Dockerfile; the build takes no
  `--build-arg`. An image built before B-167 lacks the decompilers until it is rebuilt
  (`tools/sandbox.py build`): `binary.sandbox_recover` then reports `blocked`, naming the tool.

```bash
docker build -t csctf-sandbox:1 -f docker/sandbox/Dockerfile   docker/sandbox
docker build -t csctf-sandbox:2 -f docker/sandbox/Dockerfile.2 docker/sandbox
```

## `csctf-pwn:1` — x86-64 pwn / RE

A `linux/amd64` userland (runs under emulation on Apple Silicon) with gdb-multiarch + qemu-user,
pwntools, ROPgadget/ropper, one_gadget, patchelf, angr, and pwndbg. For running and debugging x86-64
challenge binaries.

```bash
docker build --platform linux/amd64 -t csctf-pwn:1 docker/pwn
docker run --rm -it --platform linux/amd64 --network none \
  -v "$PWD/workspace/<id>/files":/chal:ro csctf-pwn:1
# heap/debug work may need:  --cap-add=SYS_PTRACE --security-opt seccomp=unconfined
```

## `csctf-pwn-multiarch:1` — non-x86 pwn / RE

For ARM, AArch64, MIPS, and RISC-V challenge binaries (qemu-user + gdb-multiarch + pwntools).

```bash
docker build -t csctf-pwn-multiarch:1 docker/pwn-multiarch
```

## `csctf-analysis:1` — reversing / symbolic execution

The runtime for the angr/Triton/Qiling harnesses the reversing lane generates
(`solvers/binary/symbolic_harness.py` + the concolic/firmware-emulation planners emit a plan +
harness source with `image_build_required=True`; a human runs the generated harness inside this
image). Contains angr, qiling, pwntools, capstone, unicorn. Run networkless/read-only like the
sandbox images.

```bash
docker build -t csctf-analysis:1 docker/analysis
```

## Pinned toolchain images (B-188): `ctf-toolkit:1`, `ctf-sage:<version>`

`tools/images.toml` lists every image here, pinned, with its env-check (`smoke`). The ones it builds
itself (`managed`) are:

- **`ctf-toolkit:1`** (`docker/toolkit/`): tshark, zsteg, john jumbo with a working `7z2john.pl` (its Perl
  module Compress::Raw::Lzma), 7-Zip, and the Python RE/crypto stack (capstone, lief, pefile, unicorn,
  pyelftools, pycryptodome, z3, sympy, gmpy2, scapy, pwntools) at the versions requirements.in pins.
  `ctf-envcheck` inside it checks all of that.
- **`ctf-sage:10.5`, `ctf-sage:10.7`** (`docker/sage/`): one SageMath image per tagged release, never
  `latest`. A past challenge needed 10.5: a later release's `E.gens()` gave a self-consistent but wrong
  answer. Pick the tag from the challenge's own notes:

```bash
.venv/bin/python -m ctf toolchain versions workspace/<id>/files   # notes + the image + its docker run line
docker run --rm --platform linux/amd64 --network none --pull=never -v "$PWD":/work -w /work \
  ctf-sage:10.5 sage your_script.sage
```

```bash
.venv/bin/python -m ctf toolchain lint             # static checks of every Dockerfile (no docker)
.venv/bin/python -m ctf toolchain status           # present? built from the current files? (a read)
.venv/bin/python -m ctf toolchain build            # the plan (a dry run); --apply builds what is missing/stale
.venv/bin/python -m ctf toolchain smoke toolkit    # the image's env-check, networkless
```

Each built image carries the label `org.ctf-tools.toolchain.hash` (the hash of its context, staged pins
and build args), so an unchanged image is never rebuilt. The hash and the build both leave out what the
context's `.dockerignore` lists (OS and editor files), so a stray `.DS_Store` does not trigger a rebuild.
`build` runs `lint` first and refuses a pinned image with a finding. The toolkit's john download is
refused until its sha256 is recorded in `tools/images.toml`. The csctf images above are listed too (`managed = false`:
`tools/sandbox.py` or this file builds them); pwn, pwn-multiarch and analysis are `pinned = false`, with
their lint findings reported until they are rebuilt pinned.

## Runtime images (B-242): `ctf-runtime-*`

One pinned image per runtime (`docker/runtime/<runtime>/Dockerfile`, all sharing the context
`docker/runtime`), for the runtime semantic adapters (`binary.runtime_trace`): the engine that runs a
delivered managed or bytecode artifact for a short, bounded trace. Each image bakes that runtime's
runner and the shared entry script; every base image is an exact tag and its digest.

| image | runs | fuel |
|---|---|---|
| `ctf-runtime-wasm:1` | a WebAssembly module on wasmtime (the master's pin) | instructions |
| `ctf-runtime-python:3.8` ... `:3.14` | a `.pyc` on the CPython that wrote it | bytecode instructions |
| `ctf-runtime-lua:1` | Lua source or bytecode on Lua 5.1, 5.2, 5.3, 5.4 or LuaJIT | VM instructions |
| `ctf-runtime-jvm:25` | a Java class or jar on JDK 25 | wall time |
| `ctf-runtime-dotnet:10` | a CIL assembly on .NET 10 | wall time |
| `ctf-runtime-node:20`, `:22`, `:24` | JavaScript, or V8 cached data on the Node line that made it | wall time |

```bash
.venv/bin/python -m ctf toolchain build --only runtime-wasm            # the plan (a dry run)
.venv/bin/python -m ctf toolchain build --apply --only runtime-wasm    # build it (needs the network)
.venv/bin/python -m ctf toolchain smoke runtime-wasm                   # re-run its self-test, networkless
```

- **Self-testing builds.** Each Dockerfile runs its runner on a fixture of `docker/runtime/selftest/`
  (our own source, compiled in the build) and fails the build unless the trace holds the string the
  fixture computes at run time. `smoke` repeats it the way `runtime_run` runs a trace: the fixture
  as the request tar on stdin, through the entry script, under the plan's exact argv.
- **Pinned packages.** The Lua image installs its interpreters from the Debian snapshot of its base
  image's date (snapshot.debian.org), not the moving archive.
- **Run only by `tools/sandbox.py` `runtime_run`**: a fresh `docker run --rm` per call with
  `--network none`, no mount at all, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, uid 10001,
  CPU / memory / pids limits and a time limit. The request goes in on stdin (a tar holding
  `artifact.bin` and `dep/`), the trace comes back on stdout. `runtime_run` refuses an image whose
  `org.ctf-tools.toolchain.hash` label is not the hash of the current files, and runs it by image id,
  so build these with `ctf toolchain build`, never with a bare `docker build`.
- **Off unless the event allows it.** The engine runs nothing while the event profile has
  `rules.sandboxed_execution = "forbidden"` (the default); see docs/CONTRACTS.md section 54.
- The shared context means a change to any file under `docker/runtime/` marks all of these images
  stale: rebuild the ones you use.

## `ctf-qemu-boot:1` — networkless boot of a challenge's disk images (B-131)

QEMU (x86-64 system emulation, TCG) with OVMF and socat (`docker/qemu-boot/`, listed in
`tools/images.toml`). For a challenge that is a bootable disk set: the harness boots it and looks at
the screen over QMP (`ctf/diskboot.py`; procedure in `docs/runbooks/disk-boot.md`).

```bash
.venv/bin/python -m ctf toolchain build --apply --only qemu-boot    # a human step; never done by an agent
.venv/bin/python -m ctf toolchain smoke qemu-boot                    # its env-check, networkless
.venv/bin/python -m ctf disk-boot plan workspace/<id>                # what would run; runs nothing
.venv/bin/python -m ctf disk-boot start workspace/<id> --reason ...  # the operator, at a terminal
.venv/bin/python -m ctf disk-boot observe workspace/<id>             # screenshots -> recon/boot/
.venv/bin/python -m ctf disk-boot quit workspace/<id>
```

Booting an image runs challenge code, so `start` asks the person at the terminal to type the
challenge folder's name and no flag stands in for that. The container runs with `--network none`,
`--read-only`, every capability dropped and no published port (QMP is a Unix socket inside it, reached
with `docker exec ... socat`); QEMU gets `-nic none -snapshot` and the handout is mounted read-only.

## Opt-in deserialization runtime verification

`tests/test_round4_payload_verification.py` exercises generated deserialization candidates only in
already-local sacrificial images.  Its runner always uses `--pull never --network none`, a read-only
root, dropped capabilities, `no-new-privileges`, and memory/PID/time limits:

```bash
CTF_DOCKER_VERIFY=1 .venv/bin/python -m pytest \
  tests/test_round4_payload_verification.py -q
```

The local `csctf-sandbox:2` image verifies PyYAML's unsafe-loader candidate and the Ruby
Marshal/ERB build-plan values.  The local .NET SDK verifies Json.NET type resolution, but Linux has
no `PresentationFramework`, so the ObjectDataProvider candidate remains correctly labelled a static
Windows-runtime plan.  `jsonpickle` is now installed in the local `csctf-sandbox:2` image (added to
`docker/sandbox/Dockerfile.2`), so that candidate executes in the sacrificial container too.

### Round-5 fixed-image verification matrix

`tests/test_round5_runtime_verification.py` adds an independently bounded probe of the exact
already-local images.  It never installs a package and never builds or pulls an image.  Every
container uses `--pull=never --network none --read-only --cap-drop ALL`,
`--security-opt no-new-privileges`, and PID/memory/time limits.

| Candidate/runtime | Fixed local image(s) | Result and boundary |
| --- | --- | --- |
| PyYAML `UnsafeLoader` | `csctf-sandbox:2` | Round 4 executes the exact emitted value and observes its marker; `SafeLoader` rejects it. |
| jsonpickle `py/reduce` | `csctf-sandbox:2` (jsonpickle installed) | Round 5 executes the exact emitted value in the networkless container and observes its marker. |
| Ruby Marshal/ERB plan | `csctf-sandbox:2` | Round 5 serializes a source-supported review wrapper, invokes its callback through real `Marshal.load`, evaluates the exact emitted ERB plan, and observes the marker. This proves the plan contract, not a universal stdlib gadget. |
| Json.NET ObjectDataProvider | `mcr.microsoft.com/dotnet/sdk:8.0` | `Newtonsoft.Json.dll` is present, but `PresentationFramework.dll` is absent. The emitted Windows/WPF candidate therefore remains static and unexecuted. |
| PHP magic-method value | `phpmyadmin:latest` | Round 3 uses real `unserialize` in the networkless container and observes the marker. |
| Jinja2/Twig, SQL, upload polyglots, ORW shellcode | Existing Round-3 images | Round 3 parses/executes these with the applicable local runtime and asserts their markers or parser effects. |

Run the focused checks with:

```bash
CTF_DOCKER_VERIFY=1 .venv/bin/python -m pytest -q \
  tests/test_round3_payload_verification.py \
  tests/test_round4_payload_verification.py \
  tests/test_round5_runtime_verification.py
```

The Ruby callback fixture is deliberately synthetic and source-supported. The candidate API remains
review-only (`candidate_only=true`, `executed=false`); the verifier does not promote a plan to an
executed payload or claim that arbitrary Ruby applications expose that callback. A WPF
ObjectDataProvider round trip remains unavailable with the permitted local images (no
`PresentationFramework` on Linux).
