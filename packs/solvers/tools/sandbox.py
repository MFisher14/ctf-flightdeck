#!/usr/bin/env python3
"""The sandbox for hostile-format tools (backlog rows 91 and 147): warm Linux containers, nothing native.

  python3 tools/sandbox.py build [1|2]           docker build of an image (default: the newest, csctf-sandbox:2;
                                                 needs the network)
  python3 tools/sandbox.py start [--launch-docker] [--wait S]
  python3 tools/sandbox.py stop [--all]
  python3 tools/sandbox.py status [--json]
  python3 tools/sandbox.py tools                 the tools, by image
  python3 tools/sandbox.py run [--timeout S] [--in FILE]... [--keep] TOOL [ARGS...]
  python3 tools/sandbox.py bench [-n N]          per-call overhead, warm (docker exec) against cold (docker run)

Two images, two containers (GENS).
  csctf-sandbox:1  (docker/sandbox/Dockerfile)   container csctf-sandbox, folders <SANDBOX_DIR>/drop, out
      upx, tshark, Volatility 3 (vol), oletools (olevba, oleid, mraptor, rtfobj, oleobj, msodde), binwalk,
      7-Zip (7z), YARA (yara, yarac), file.
  csctf-sandbox:2  (docker/sandbox/Dockerfile.2) container csctf-sandbox-2, folders <SANDBOX_DIR>/v2/drop, out
      everything of :1 at the same versions, and: steghide, stegseek, zsteg, outguess, stegsnow; tesseract;
      exiftool, exiv2, pngcheck; foremost, scalpel, bulk_extractor, sleuthkit (mmls, fsstat, fls, icat,
      tsk_recover); qpdf, pdftotext, pdfimages, pdfdetach, pdfinfo, pdftoppm, mutool; ffmpeg, ffprobe, sox;
      zbarimg, qrencode; multimon-ng, minimodem, rtl_433; sstv (decoder), pysstv (encoder); radare2 (r2, rabin2,
      rasm2, rafind2) with the r2ghidra decompiler (pdg); strings, objdump, readelf; python3 (-I is put first)
      with numpy, scipy, Pillow, pyzbar, pypdf, scapy, python-evtx, regipy, LnkParse3, extract-msg, fickling;
      pycdc and decompyle3 (Python .pyc -> source), pycdas (.pyc disassembly); cfr and vineflower (Java
      .class/.jar -> source).
:2 is used when it is built, else :1 (choose()). The two never share a name or a folder, so a
process that still knows only :1 keeps starting and using `csctf-sandbox` while this file uses
`csctf-sandbox-2`: neither replaces the other. CTF_SANDBOX_IMAGE=1 in the environment keeps this
file on :1 (the way back if :2 misbehaves).

A tool that is on neither list is refused. Nothing a caller asks for is ever run on this Mac: when no
container can run the tool, `run` (and run() for Python callers) stops with SandboxDown and its reason,
and a caller treats the file as not read (facts.unpack_upx: "not unpacked").

A container (start). Started with --network none, a read-only root, every capability dropped,
no-new-privileges, an unprivileged user (uid 10001), --init, CPU, memory and process limits (LIMITS), a
64 MB /tmp, and exactly two mounts: its drop folder read-only at /drop, and its out folder at /out, the
one writable folder (each call's output is capped at OUT_MAX and removed unless --keep). SANDBOX_DIR is
$CTF_SANDBOX_DIR, else ~/.csctf-sandbox: never the home folder itself, the repository, the token
file or ~/.docker. No environment variable is handed in (docker exec passes none), and the docker CLI
itself runs with CTF_TOKEN removed from its environment. A container that exists with any other
settings (its spec label differs) is removed and started again. `start` starts the container of the
chosen image only and leaves the other alone; `stop` removes that one, `stop --all` both. When the
chosen image is built but its container cannot be started, `start` (and a call that has to start
one) starts the older image's container instead and says so in a WARNING line: row 91's tools go on.

  --launch-docker  when the Docker daemon does not answer, open Docker Desktop (`open -g -a
                   Docker`) and wait for it up to --wait seconds (default 120).

run. One call is one `docker exec <container> timeout -k 1 S TOOL ARGS` with its own time limit S
(--timeout, default 30). Row 167: the container is checked fit (up, right spec, room under the pids
limit) before the tool is exec'd into it, an unfit one is skipped, and when the image has the baked
wrapper (WRAPPER) the tool is run through it so children it leaves behind are killed when the call
ends and do not fill the container's 128-process limit for the next caller; an image built before
row 167 runs the bare `timeout`. run(..., start=False) never starts a container (a budget/timed path
fails closed rather than spend its time starting one). Each --in FILE is copied to /drop/<call>/<name>; in ARGS, {in} stands for the
first, {in0} {in1} ... for each, and {out} for the call's writable folder /out/<call>. The tool's stdout
and stderr are passed through and the exit status is the tool's (124 when the time limit stopped it).
With --keep the call's output folder stays on the host and its path is printed on stderr.
A Python caller wraps an argument that must reach the tool as it is in Lit (a passphrase, a
password, a key: `flag{in}` is a passphrase, not a placeholder); nothing is replaced in a Lit.
Which container: the newest one that holds the tool and is up. When the :2 container is not up but its
image is built, a :1 tool runs in the :1 container if that is up; otherwise (and for every :2-only tool)
the :2 container is started first, once, under a lock (about a second), and the call goes on. A
container that `stop` removed is not started by a call: only `start` brings it back.

Runtime containers (B-242; no command line, Python callers only). runtime_run(tag, want_hash, argv,
members, seconds) runs one runtime adapter's runner over a delivered managed or bytecode artifact in a
fresh `docker run --rm` container of a ctf-runtime-* image (docker/runtime/): no network, no mount (the
request is a tar on stdin, the trace comes back on stdout), read-only root, every capability dropped,
an unprivileged user, CPU, memory, process and time limits. The image must carry the content hash the
caller expects (its org.ctf-tools.toolchain.hash label) and is run by its image id. Whether an event
allows such a run at all is the caller's question (rules.sandboxed_execution, ctf/eventpolicy.py).

For tests: $CTF_DOCKER is used as the docker CLI (a stand-in), and $CTF_SANDBOX_NAME names
the :1 container (the :2 container is that name with -2; tests start their own, beside the real ones).
Under CTF_TESTING a runtime container is only ever started through a stand-in that carries the test
stub marker.

Exit status: 0 done (status: up), 1 status: down, 2 usage, 3 the sandbox is down (start,
run, bench: the reason is one line on stderr), else the tool's own status. No network request and no
token: this file reads no token, the containers it runs have no network (--network none), and
nothing a caller asks for is ever run on the host.
"""
import fcntl
import hashlib
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
import uuid
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import env as ctf_env

HERE = Path(__file__).resolve().parent
NAME = ctf_env.get("CTF_SANDBOX_NAME") or "csctf-sandbox"   # the :1 container; a test container has its own name
IMAGE = "csctf-sandbox:1"                     # the row 91 image (kept under this name for its callers)
CONTEXT = HERE.parent / "docker" / "sandbox"     # the Dockerfiles (Dockerfile, Dockerfile.2)
TOOLS_1 = ("upx", "tshark", "vol", "olevba", "oleid", "mraptor", "rtfobj", "oleobj", "msodde", "binwalk", "7z",
           "yara", "yarac", "file")
TOOLS_2 = ("steghide", "stegseek", "zsteg", "outguess", "stegsnow", "tesseract", "exiftool", "exiv2", "pngcheck",
           "foremost", "scalpel", "bulk_extractor", "mmls", "fsstat", "fls", "icat", "tsk_recover",
           "qpdf", "pdftotext", "pdfimages", "pdfdetach", "pdfinfo", "pdftoppm", "mutool",
           "ffmpeg", "ffprobe", "sox", "zbarimg", "qrencode", "multimon-ng", "minimodem", "rtl_433",
           "sstv", "pysstv", "r2", "rabin2", "rasm2", "rafind2", "strings", "objdump", "readelf", "python3",
           "pycdc", "pycdas", "decompyle3", "cfr", "vineflower")   # B-167: Python / JVM bytecode decompilers
TOOLS = TOOLS_1 + TOOLS_2


class Gen:
    """One image and its container: number, image tag, container name, the folder under SANDBOX_DIR
    that holds its drop and out ('' for :1, as row 91 built it), its Dockerfile, its tools."""

    def __init__(self, n, sub, dockerfile, tools):
        self.n, self.sub, self.dockerfile, self.tools = n, sub, dockerfile, tools
        self.image = f"csctf-sandbox:{n}"
        self.name = NAME if n == 1 else f"{NAME}-{n}"

    def __repr__(self):
        return f"<Gen {self.image} in {self.name}>"


GENS = (Gen(2, "v2", "Dockerfile.2", TOOLS), Gen(1, "", "Dockerfile", TOOLS_1))   # newest first
GEN1 = GENS[-1]
FORCE = (ctf_env.get("CTF_SANDBOX_IMAGE") or "").strip().split(":")[-1]    # "1" or "2": use that image only
def _limit(env_name: str, default: str, pattern: str) -> str:
    """A resource limit from the environment, validated so a bad value can never reach `docker run`.

    The defaults (cpus 2 / memory 1g / pids 128) are the right safety cap for DETONATING an untrusted
    sample — observing behaviour, not heavy compute. A big passive-data job (a multi-GB memory dump or
    disk image analysed with Volatility/TSK, which parses structures and executes no untrusted code)
    legitimately needs more, so each is overridable, e.g. `CTF_SANDBOX_MEMORY=8g CTF_SANDBOX_CPUS=6`.
    The override flows into run_args() -> spec(): a container started with different limits hashes to a
    different identity, so a stale one is replaced rather than silently reused. A malformed value (e.g.
    memory "lots") is ignored and the safe default stands.
    """
    v = (ctf_env.get(env_name) or "").strip()
    return v if v and re.fullmatch(pattern, v) else default


LIMITS = {
    "cpus": _limit("CTF_SANDBOX_CPUS", "2", r"\d+(\.\d+)?"),     # docker --cpus: a positive number
    "memory": _limit("CTF_SANDBOX_MEMORY", "1g", r"\d+[bkmgBKMG]"),  # docker --memory: <int><b|k|m|g>
    "pids": int(_limit("CTF_SANDBOX_PIDS", "128", r"\d+")),
    "tmp": "64m",
}
WRAPPER = "/usr/local/bin/csctf-run"      # the wrapper baked into both images (docker/sandbox/) that runs a
                                          # tool in its own process group and kills the group on exit, so
                                          # children the tool leaves behind do not outlive the call and fill the
                                          # pids limit. Optional at run time: an image without the wrapper runs
                                          # the bare `timeout`, so a call still works against an un-rebuilt image.
PIDS_HEADROOM = 16          # row 167: a container with fewer than this many of LIMITS['pids'] free is unfit
UID = "10001:10001"
OUT_MAX = 256 << 20         # bytes one call may leave in its output folder; more is removed and reported
FSIZE = 256 << 20           # RLIMIT_FSIZE inside the container: no file grows past this
RUN_TIMEOUT = 30.0          # default per-call limit, seconds
SLACK = 5.0                 # what the docker CLI may add to a call before the host gives up on it
PROBE_TIMEOUT = 5.0         # one status read (docker inspect, docker exec true)
STALE = 3600.0              # a call's folder older than this, found when a container is started, is a dead call's
DOCKER_APP = "/Applications/Docker.app"
DOCKERS = ("/usr/local/bin/docker", "/opt/homebrew/bin/docker", "/Applications/Docker.app/Contents/Resources/bin/docker")
DOWN_WORDS = ("Error response from daemon", "Cannot connect to the Docker daemon", "No such container",
              "is not running", "error during connect", "docker: command not found",
              "OCI runtime exec failed")      # the container could not start the process (its process limit is full)


class SandboxDown(RuntimeError):
    """The sandbox cannot run a tool now. str() is the reason, one line."""


class NoContainer(SandboxDown):
    """This image's container is not there or not running (another image's may be)."""


class Lit(str):
    """An argument of run() that reaches the tool exactly as written: {in}, {in0} ... and {out} in
    it are NOT replaced. For values the caller did not write itself (a passphrase, a password, a
    key, a script): 'flag{in}' as a steghide passphrase must stay 'flag{in}'."""


class Result:
    """One call: code (the tool's exit status, 124 when its time limit stopped it), stdout and
    stderr (bytes), files ({name: bytes} the call left in its output folder, unless kept),
    out_dir (the host path of that folder when kept, else None), seconds (the whole call)."""

    def __init__(self, code, stdout, stderr, files, out_dir, seconds, note=""):
        self.code, self.stdout, self.stderr = code, stdout, stderr
        self.files, self.out_dir, self.seconds, self.note = files, out_dir, seconds, note
        self.image = ""             # the image whose container ran the call

    @property
    def timed_out(self) -> bool:
        return self.code == 124


# ---- where things are --------------------------------------------------------------------------

def sandbox_dir() -> Path:
    """$CTF_SANDBOX_DIR, else ~/.csctf-sandbox. Refused if it is the home folder, a parent
    of it, or a folder that holds the token file or the repository."""
    raw = ctf_env.get("CTF_SANDBOX_DIR") or str(Path.home() / ".csctf-sandbox")
    p = Path(raw).expanduser().resolve()
    home = Path.home().resolve()
    repo = HERE.parent.resolve()
    if p == home or p in home.parents or p == repo or p in repo.parents or (p / ".ctf" / "token").exists():
        raise SandboxDown(f"refused: {p} would mount the home folder, the repository or the token into the sandbox")
    return p


def gens(tool=None) -> tuple:
    """The images this process may use, newest first: all of GENS, or the one CTF_SANDBOX_IMAGE
    names; with a tool, only those that hold it."""
    got = tuple(g for g in GENS if not FORCE or str(g.n) == FORCE) or GENS
    return tuple(g for g in got if tool is None or tool in g.tools)


def _gen(gen=None) -> "Gen":
    return gen if gen is not None else choose()


def drop_dir(gen=None) -> Path:
    return sandbox_dir() / _gen(gen).sub / "drop"


def out_dir(gen=None) -> Path:
    return sandbox_dir() / _gen(gen).sub / "out"


def docker() -> str:
    """The docker CLI: $CTF_DOCKER (a stand-in for tests), else PATH, else the usual places."""
    override = ctf_env.get("CTF_DOCKER")
    if override:
        return override
    found = shutil.which("docker")
    if found:
        return found
    for path in DOCKERS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise SandboxDown("docker is not installed")


def _env() -> dict:
    env = {k: v for k, v in os.environ.items() if k not in ("CTF_TOKEN",)}
    path = env.get("PATH", "")
    for extra in ("/usr/local/bin", "/opt/homebrew/bin"):   # a minimal PATH may lack the docker helpers
        if extra not in path.split(":"):
            path = f"{path}:{extra}" if path else extra
    env["PATH"] = path
    return env


def _docker(args, timeout, input_bytes=None):
    """(returncode, stdout bytes, stderr bytes) of one docker CLI call. SandboxDown when the CLI is
    missing or does not answer within timeout."""
    try:
        p = subprocess.run([docker(), *args], capture_output=True, timeout=timeout, env=_env(),
                           stdin=subprocess.DEVNULL if input_bytes is None else None, input=input_bytes)
    except FileNotFoundError:
        raise SandboxDown("docker is not installed")
    except subprocess.TimeoutExpired:
        raise SandboxDown(f"docker {args[0]} did not answer within {timeout:g} s (is Docker Desktop hung?)")
    except OSError as e:
        raise SandboxDown(f"docker could not run ({type(e).__name__}: {e})")
    return p.returncode, p.stdout, p.stderr


def _first_line(b: bytes) -> str:
    text = b.decode("utf-8", "replace").strip().splitlines()
    return text[0][:200] if text else ""


_PRESENT = {}
_WRAPPER = {}       # row 167: gen.image -> whether that image's container has WRAPPER (one probe, cached)


def present(gen) -> bool:
    """True when the image is built here (one `docker image inspect`, remembered when True).
    SandboxDown when the daemon does not answer."""
    if _PRESENT.get(gen.image):
        return True
    code, out, err = _docker(["image", "inspect", "--format", "{{.Id}}", gen.image], PROBE_TIMEOUT)
    if code == 0:
        _PRESENT[gen.image] = _first_line(out) or True      # the image's id, to tell a rebuilt image
        return True
    line = _first_line(err)
    if "No such image" in line or "no such image" in line or "not found" in line:
        return False
    raise SandboxDown(f"the Docker daemon does not answer ({line or f'exit {code}'})")


def choose() -> "Gen":
    """The image to use: the newest that is built (:2 when present, else :1); the newest of all when
    none is built, so that `start` names the one to build. SandboxDown when the daemon does not answer."""
    usable = gens()
    for g in usable:
        if present(g):
            return g
    return usable[0]


def run_args(gen=None) -> list:
    """The `docker run` options of the container, mounts included (the spec its label hashes)."""
    gen = _gen(gen)
    return ["--network", "none", "--read-only", "--tmpfs", f"/tmp:rw,nosuid,nodev,size={LIMITS['tmp']}",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", UID, "--init",
            "--cpus", LIMITS["cpus"], "--memory", LIMITS["memory"], "--memory-swap", LIMITS["memory"],
            "--pids-limit", str(LIMITS["pids"]), "--ulimit", f"fsize={FSIZE}", "--ulimit", "nofile=1024:1024",
            "--restart", "no", "-v", f"{drop_dir(gen)}:/drop:ro", "-v", f"{out_dir(gen)}:/out:rw"]


def spec(gen=None) -> str:
    gen = _gen(gen)
    # This label is a compatibility contract with already-running containers,
    # not an attacker-controlled content cache. Keep the historical 64-bit label
    # so a newer checkout does not discard a fit container merely because its
    # display width changed.
    return hashlib.sha256(json.dumps([gen.image, run_args(gen)]).encode()).hexdigest()[:16]


# ---- status ------------------------------------------------------------------------------------

def inspect(gen=None):
    """The container's `docker inspect` record, or None when there is none. SandboxDown when the
    daemon does not answer."""
    gen = _gen(gen)
    code, out, err = _docker(["inspect", "--type", "container", gen.name], PROBE_TIMEOUT)
    if code != 0:
        line = _first_line(err)
        if "No such" in line or "no such" in line:
            return None
        raise SandboxDown(f"the Docker daemon does not answer ({line or f'exit {code}'})")
    try:
        return json.loads(out)[0]
    except (ValueError, IndexError):
        raise SandboxDown("docker inspect gave no record")


def problems(rec: dict, gen=None) -> list:
    """What makes a container record unfit to run hostile files in: [] when it is fit."""
    gen = _gen(gen)
    out = []
    state = rec.get("State") or {}
    host = rec.get("HostConfig") or {}
    labels = (rec.get("Config") or {}).get("Labels") or {}
    if not state.get("Running"):
        out.append(f"the container is {state.get('Status') or 'not running'}")
    if host.get("NetworkMode") != "none":
        out.append(f"its network is {host.get('NetworkMode')!r}, not none")
    if not host.get("ReadonlyRootfs"):
        out.append("its root is writable")
    if labels.get("csctf.sandbox.spec") != spec(gen):
        out.append("it was started with other settings (tools/sandbox.py start replaces it)")
    mounts = {m.get("Destination"): m for m in rec.get("Mounts") or []}
    if set(mounts) - {"/drop", "/out", "/tmp"}:
        out.append("it has other mounts: " + ", ".join(sorted(set(mounts) - {"/drop", "/out", "/tmp"})))
    if "/drop" in mounts and mounts["/drop"].get("RW"):
        out.append("/drop is writable")
    built, runs = _PRESENT.get(gen.image), rec.get("Image")
    if isinstance(built, str) and built.startswith("sha256:") and isinstance(runs, str) and runs.startswith("sha256:") and built != runs:
        out.append(f"it runs an older build of {gen.image} (tools/sandbox.py start replaces it)")
    return out


def health_of(gen) -> tuple:
    """(True, detail) when this image's container can run a tool now, else (False, reason). Two
    docker calls at most (inspect, and one `docker exec ... true`). Raises SandboxDown only when the
    daemon does not answer."""
    rec = inspect(gen)
    if rec is None:
        return False, f"no container {gen.name} (tools/sandbox.py start)"
    bad = problems(rec, gen)
    if bad:
        return False, "; ".join(bad)
    t0 = time.perf_counter()
    code, _, err = _docker(["exec", gen.name, "true"], PROBE_TIMEOUT)
    took = time.perf_counter() - t0
    if code != 0:
        return False, f"docker exec failed ({_first_line(err) or f'exit {code}'})"
    image = (rec.get("Config") or {}).get("Image", "?")
    return True, (f"{gen.name} up ({image}), network none, read-only root, cpus {LIMITS['cpus']}, "
                  f"memory {LIMITS['memory']}, pids {LIMITS['pids']}; exec {took:.2f} s")


def _pids_ok(gen) -> tuple:
    """(True, '') when this image's container has room below LIMITS['pids'], else (False, reason). One
    `docker exec` that counts the numeric entries of /proc. Fails closed: a count it cannot read is
    unfit, so a container clogged by a tool's leftover children is skipped, not exec'd into (row 167)."""
    code, out, err = _docker(["exec", gen.name, "sh", "-c", 'ls /proc | grep -c "^[0-9]"'], PROBE_TIMEOUT)
    if code != 0:
        return False, f"could not count its processes ({_first_line(err) or f'exit {code}'})"
    try:
        n = int(_first_line(out) or "")
    except ValueError:
        return False, "could not read its process count"
    if LIMITS["pids"] - n < PIDS_HEADROOM:
        return False, f"{n} of {LIMITS['pids']} processes in use (tools/sandbox.py stop, then start)"
    return True, ""


def fit(gen) -> tuple:
    """(True, detail) when run() may exec a tool into this image's container, else (False, reason).
    Row 167: a container that inspect shows up but mis-configured (wrong spec, network or writable
    root) or out of processes is skipped, so a tool is never exec'd into an unfit one. When inspect
    gives no record (the container is absent, or the daemon cannot say for this one) it returns True
    and lets _run_in decide: _run_in raises NoContainer for a missing container (run() then starts
    it) and SandboxDown for one whose exec fails because it is full. Raises SandboxDown only when the
    daemon does not answer (as inspect does)."""
    rec = inspect(gen)
    if rec is None:
        return True, f"no record for {gen.name}; the exec decides"
    bad = problems(rec, gen)
    if bad:
        return False, "; ".join(bad)
    ok, why = _pids_ok(gen)
    return (True, f"{gen.name} fit") if ok else (False, why)


def health(gen=None) -> tuple:
    """(True, detail) when a tool can be run now, else (False, reason). The chosen image's container
    is asked first (one image inspect, one container inspect, one `docker exec ... true`, each
    stopped after PROBE_TIMEOUT); when that one is not up, an older image's fit container still
    counts as up, and the detail says that the newer one starts on first use. Never raises."""
    try:
        if gen is not None:
            return health_of(gen)
        chosen = choose()
        ok, detail = health_of(chosen)
        if ok:
            return True, detail
        if present(chosen):
            for g in gens():
                if g is chosen:
                    continue
                ok2, detail2 = health_of(g)
                if ok2:
                    return True, f"{detail2}; {chosen.image} is built and its container {chosen.name} starts on first use"
        return False, detail
    except SandboxDown as e:
        return False, str(e)
    except Exception as e:      # a status read must never take its caller down
        return False, f"the sandbox could not be checked ({type(e).__name__}: {e})"


# ---- start, stop, build ------------------------------------------------------------------------

def daemon_up() -> bool:
    try:
        code, _, _ = _docker(["version", "--format", "{{.Server.Version}}"], PROBE_TIMEOUT)
    except SandboxDown:
        return False
    return code == 0


def stopped_mark(gen) -> Path:
    """The file `stop` leaves: while it is there, run() does not start this container by itself."""
    return sandbox_dir() / f".stopped-{gen.n}"


def start_gen(gen, say=print) -> None:
    """Make this image's container up and fit, under its lock (two callers never start it twice);
    SandboxDown with the reason when it cannot be. The daemon is taken as up."""
    if not present(gen):
        raise SandboxDown(f"the image {gen.image} is not built (tools/sandbox.py build)")
    root = sandbox_dir() / gen.sub
    root.mkdir(parents=True, exist_ok=True)
    with open(sandbox_dir() / f".start-{gen.n}.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        rec = inspect(gen)
        if rec is not None and not problems(rec, gen):
            stopped_mark(gen).unlink(missing_ok=True)
            say(f"{gen.name} is already up")
            return
        if rec is not None:
            _docker(["rm", "-f", gen.name], 30)
        # The folders are kept, not emptied: another process may have written a call's input a
        # moment ago and be waiting for this lock. Only what a dead call left (older than STALE)
        # is removed.
        for d in (drop_dir(gen), out_dir(gen)):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o755 if d == drop_dir(gen) else 0o777)
            for old in d.iterdir():
                try:
                    if time.time() - old.stat().st_mtime > STALE:
                        shutil.rmtree(old, ignore_errors=True) if old.is_dir() else old.unlink()
                except OSError:
                    pass
        code, _, err = _docker(["run", "-d", "--name", gen.name, "--label", f"csctf.sandbox.spec={spec(gen)}",
                                *run_args(gen), gen.image], 60)
        if code != 0:
            raise SandboxDown(f"docker run failed ({_first_line(err) or f'exit {code}'})")
        ok, detail = health_of(gen)
        if not ok:
            raise SandboxDown(f"started, but not fit: {detail}")
        stopped_mark(gen).unlink(missing_ok=True)
        say(detail)


def start(launch_docker=False, wait=120.0, say=print, gen=None) -> None:
    """Make the chosen image's container up and fit (:2 when it is built, else :1); SandboxDown with
    the reason when it cannot be. The other image's container is left as it is."""
    if not daemon_up():
        if not launch_docker:
            raise SandboxDown("the Docker daemon does not answer (start Docker Desktop, or start --launch-docker)")
        if not os.path.isdir(DOCKER_APP):
            raise SandboxDown(f"the Docker daemon does not answer and {DOCKER_APP} is not installed")
        say("the Docker daemon does not answer: opening Docker Desktop")
        subprocess.run(["/usr/bin/open", "-g", "-a", "Docker"], capture_output=True, timeout=30)
        deadline = time.monotonic() + wait
        while not daemon_up():
            if time.monotonic() > deadline:
                raise SandboxDown(f"Docker Desktop did not answer within {wait:g} s")
            time.sleep(2)
    if gen is not None:
        start_gen(gen, say)
        return
    chosen = choose()
    try:
        start_gen(chosen, say)
    except SandboxDown as e:
        # The newest image is built but its container cannot be started: an older image's
        # container is better than none on a release morning (row 91's tools go on; row 147's
        # say 'sandbox down'). With no image built at all the reason names the one to build.
        if not present(chosen):
            raise
        for g in gens():
            if g is not chosen and present(g):
                try:
                    start_gen(g, say)
                except SandboxDown:
                    continue
                say(f"WARNING {chosen.image} could not be started ({e}); {g.image} is up in {g.name} instead, "
                    f"and only its tools run")
                return
        raise


def stop(gen=None, every=False) -> bool:
    """Remove the chosen image's container (every=True: each image's). True when none of them is left."""
    try:
        todo = gens() if every else (_gen(gen),)
        for g in todo:
            try:                # a container somebody stopped is not started again by a call (run)
                sandbox_dir().mkdir(parents=True, exist_ok=True)
                stopped_mark(g).write_text(time.strftime("%Y-%m-%d %H:%M:%S\n"))
            except OSError:
                pass
            _docker(["rm", "-f", g.name], 30)
        return all(inspect(g) is None for g in todo)
    except SandboxDown:
        return False


def build(say=print, gen=None) -> int:
    gen = gen or gens()[0]
    t0 = time.perf_counter()
    p = subprocess.run([docker(), "build", "-t", gen.image, "-f", str(CONTEXT / gen.dockerfile), str(CONTEXT)], env=_env())
    say(f"build of {gen.image} exit {p.returncode} in {time.perf_counter() - t0:.0f} s")
    return p.returncode


# ---- run ---------------------------------------------------------------------------------------

def _size(folder: Path) -> int:
    total = 0
    for p in folder.rglob("*"):
        try:
            if p.is_file() and not p.is_symlink():
                total += p.stat().st_size
        except OSError:
            pass
    return total


def _has_wrapper(gen) -> bool:
    """True when this image's container has the leftover-killing wrapper (row 167), cached per image.
    One `docker exec ... test -x`; False (fall back to a bare `timeout`) when it is absent or cannot be
    checked, so a container from an image built before row 167 still runs its tools."""
    if gen.image in _WRAPPER:
        return _WRAPPER[gen.image]
    try:
        code, _, _ = _docker(["exec", gen.name, "test", "-x", WRAPPER], PROBE_TIMEOUT)
    except SandboxDown:
        return False        # not cached: a transient daemon hiccup must not stick as "no wrapper"
    _WRAPPER[gen.image] = code == 0
    return _WRAPPER[gen.image]


def _run_in(gen, tool, args, inputs, timeout, keep, executable) -> Result:
    """One call in this image's container. NoContainer when that container is not there."""
    call = uuid.uuid4().hex[:12]
    drop, out = drop_dir(gen) / call, out_dir(gen) / call
    names = []
    try:
        if not drop_dir(gen).is_dir() or not out_dir(gen).is_dir():
            raise NoContainer(f"the sandbox folders under {sandbox_dir() / gen.sub} are missing (tools/sandbox.py start)")
        drop.mkdir()
        out.mkdir()
        os.chmod(out, 0o777)
        for i, (name, data) in enumerate(inputs):
            name = "".join(c if c.isalnum() or c in "._-" else "_" for c in str(name))[:80]
            if not name.strip("."):     # '', '.', '..': not a file name (.. would be the drop folder itself)
                name = f"in{i}"
            if name in names:
                name = f"{i}-{name}"
            (drop / name).write_bytes(data)
            os.chmod(drop / name, 0o755 if executable else 0o644)
            names.append(name)
        subs = {"{out}": f"/out/{call}"}
        for i, name in enumerate(names):
            subs[f"{{in{i}}}"] = f"/drop/{call}/{name}"
        if names:
            subs["{in}"] = subs["{in0}"]
        argv = []
        for a in args:
            if isinstance(a, Lit):      # as written: a passphrase is not a template
                argv.append(str.__str__(a))
                continue
            a = str(a)
            for k, v in subs.items():
                a = a.replace(k, v)
            argv.append(a)
        if tool == "python3":       # isolated: no script folder, no user site, no PYTHON* variable
            argv = ["-I", *argv]
        limit = max(0.001, float(timeout))   # 0 would mean no limit to timeout(1)
        if _has_wrapper(gen):                 # row 167: run the tool in its own process group and reap its
            runner = [WRAPPER, f"{limit:.3f}"]    # children; the wrapper keeps the `timeout -k 1 S` budget
        else:                                 # an image built before row 167: the bare timeout, as before
            runner = ["timeout", "-k", "1", f"{limit:.3f}"]
        t0 = time.perf_counter()
        code, so, se = _docker(["exec", "-w", f"/out/{call}", gen.name, *runner, tool, *argv], limit + SLACK)
        took = time.perf_counter() - t0
        line = _first_line(se)
        if code != 0 and ("No such container" in line or "is not running" in line):
            raise NoContainer(f"docker exec could not run {tool} ({line})")
        if code != 0 and not line and b"OCI runtime exec failed" in so[:400]:    # docker prints this one on stdout
            line = _first_line(so)
        if code in (125, 126, 127) or (code != 0 and any(w in line for w in DOWN_WORDS)):
            raise SandboxDown(f"docker exec could not run {tool} in {gen.name} ({line or f'exit {code}'})")
        if code != 0 and not all((drop / n).is_file() for n in names):
            # the input went away under the tool (an older tools/sandbox.py emptied the folder
            # while starting the container): its failure is not a reading of the file
            raise SandboxDown(f"the input of {tool} was removed while it ran: run it again")
        if code != 0 and names:
            # A tool that failed must have failed on the file: one more exec asks the container
            # whether it sees this call's input at all. It does not when somebody started the
            # container with other folders (another CTF_SANDBOX_DIR) after this call began.
            seen, _, _ = _docker(["exec", gen.name, "test", "-r", f"/drop/{call}/{names[0]}"], PROBE_TIMEOUT)
            if seen == 1:
                raise SandboxDown(f"{gen.name} does not see this call's input (it runs with other folders): "
                                  f"tools/sandbox.py start, then run it again")
        files, note, kept = {}, "", None
        size = _size(out)
        if size > OUT_MAX:
            note = f"the call left {size} bytes, more than {OUT_MAX}: its output was removed"
        elif keep:
            kept = out
        else:
            for p in sorted(out.rglob("*")):
                if p.is_file() and not p.is_symlink():
                    files[p.relative_to(out).as_posix()] = p.read_bytes()
        r = Result(code, so, se, files, kept, took, note)
        r.image = gen.image
        return r
    finally:
        shutil.rmtree(drop, ignore_errors=True)
        if not (keep and out.is_dir() and _size(out) <= OUT_MAX):
            shutil.rmtree(out, ignore_errors=True)


def run(tool: str, args=(), inputs=(), timeout: float = RUN_TIMEOUT, keep: bool = False,
        executable: bool = False, start: bool = True) -> Result:
    """Run TOOL with ARGS inside a container. inputs: (name, bytes) pairs or host paths, copied
    to /drop/<call>/ (mode 0644, or 0755 with executable=True: `upx` packs only an executable
    file); {in}, {in0}, {in1} ... and {out} in args are replaced (see the module text), except in
    an argument wrapped in Lit, which reaches the tool as written.
    The newest container that holds the tool and is up and fit runs it (row 167: a container is
    checked fit before a tool is exec'd into it, so a clogged or mis-configured one is skipped); a
    newer image that is built but not started is started first when no older container can run the
    tool (see the module text).
    With start=False the call never starts a container: when none that holds the tool is already up
    and fit it raises SandboxDown('not started ...'), so a caller on a budget or timed path cannot
    spend its time starting one (row 167; the sandbox is off the timed path anyway).
    SandboxDown when no container can run it; nothing is ever run natively."""
    if tool not in TOOLS:
        raise ValueError(f"{tool} is not a sandbox tool ({', '.join(TOOLS)})")
    able = gens(tool)
    if not able:
        raise SandboxDown(f"{tool} is not in csctf-sandbox:{FORCE} (CTF_SANDBOX_IMAGE={FORCE})")
    args = list(args)           # read once per container tried: never a generator half used
    inputs = [tuple(item) if isinstance(item, (tuple, list)) else (Path(item).name, Path(item).read_bytes())
              for item in inputs]
    first = None
    for g in able:              # row 167: exec a tool only into a container that is up and fit
        ok, why = fit(g)
        if not ok:
            first = first or SandboxDown(f"{g.name}: {why}")
            continue
        try:
            return _run_in(g, tool, args, inputs, timeout, keep, executable)
        except NoContainer as e:    # raced: the container went away between the fit check and the exec
            first = first or e
    if not start:               # row 167: a budget/timed path never starts a container (fail closed)
        raise SandboxDown(f"not started; run tools/sandbox.py start first "
                          f"({first or ('no container holding ' + tool + ' is up')})")
    built = [g for g in able if present(g)]
    if not built and len(able) == 1 and len(gens()) > 1:
        raise SandboxDown(f"{tool} needs {able[0].image}, which is not built (tools/sandbox.py build)")
    failed = None
    for g in built:             # no container that holds the tool is up: start the newest that is built,
        if stopped_mark(g).exists():    # and an older one only when the newer cannot be started
            raise SandboxDown(f"{g.name} was stopped (tools/sandbox.py stop): tools/sandbox.py start")
        try:
            start_gen(g, say=lambda *_: None)
        except SandboxDown as e:
            failed = failed or e
            continue
        ok, why = fit(g)        # row 167: a just-started container is checked too, before the exec
        if not ok:
            failed = failed or SandboxDown(f"{g.name} started but not fit: {why}")
            continue
        return _run_in(g, tool, args, inputs, timeout, keep, executable)
    raise SandboxDown(str(failed or first))


def upx_unpack(data: bytes, timeout: float, start: bool = True):
    """(unpacked bytes or None, note) of `upx -d` on a copy of data, inside the sandbox. The notes
    are those of solvers/binary/facts.unpack_upx, with ' in the sandbox' added; a sandbox that is
    down gives (None, 'sandbox down: <reason>: the packed image is not read'). start is run()'s: with
    start=False a timed caller never starts a container (B-167)."""
    try:
        r = run("upx", ["-d", "-q", "-o", "{out}/unpacked", "{in}"], inputs=[("packed", data)], timeout=timeout,
                start=start)
    except SandboxDown as e:
        return None, f"sandbox down: {e}: the packed image is not read"
    got = r.files.get("unpacked")
    if r.timed_out:
        return None, f"upx -d took more than {timeout:g} s in the sandbox"
    if r.code != 0 or not got:
        why = (r.stderr or r.stdout).decode("utf-8", "replace").strip().splitlines()
        return None, f"upx -d failed in the sandbox ({why[-1][:160] if why else r.note or f'exit {r.code}'})"
    return got, f"unpacked by upx -d to {len(got)} bytes in the sandbox"


# ---- runtime containers (B-242) ----------------------------------------------------------------
# A runtime adapter (solvers/binary/runtime_trace.py) runs a delivered managed or bytecode artifact
# for a bounded trace. That is execution of a delivered file, so it has its own, stricter path than
# run(): one fresh container per call (`docker run --rm`), never a warm one; no mount at all (the
# request goes in on stdin as a tar, the trace comes back on stdout); and only an image that carries
# the content hash it is expected to have, run by its image id so what was checked is what runs.
# This function is the only place such a container is started.

RUNTIME_ENTRY = "/usr/local/bin/ctf-runtime-entry"       # docker/runtime/entry.sh, baked into every image
RUNTIME_LABEL = "org.ctf-tools.toolchain.hash"           # ctf.toolchain.images.LABEL
RUNTIME_STUB_MARKER = b"ctf-docker-stub"                 # ctf.toolchain.images.STUB_MARKER
RUNTIME_MAX_SECONDS = 305                                # the longest a runtime container may live
RUNTIME_MAX_INPUT = 96 << 20                             # bytes of one request
RUNTIME_START_SLACK = 60.0                               # what `docker run` may add: create, start, remove
RUNTIME_MEMBER = re.compile(r"artifact\.bin|dep/[0-9]{3}\.bin")
RUNTIME_LIMIT = {"memory": re.compile(r"[0-9]+[kmg]"), "cpus": re.compile(r"[0-9]+(\.[0-9]+)?")}
RUNTIME_ID = re.compile(r"sha256:[0-9a-f]{64}")
RUNTIME_HASH = re.compile(r"[0-9a-f]{64}")
RUNTIME_TAG = re.compile(r"[a-z0-9][a-z0-9_./-]*:[A-Za-z0-9_][A-Za-z0-9_.-]*")


def _runtime_docker() -> str:
    """docker(), except that under CTF_TESTING only a test stub is accepted (a file that carries
    RUNTIME_STUB_MARKER near its start): no test starts a real container through this path."""
    path = docker()
    if ctf_env.get_bool("CTF_TESTING"):
        try:
            with open(path, "rb") as fh:
                stub = RUNTIME_STUB_MARKER in fh.read(4096)
        except OSError:
            stub = False
        if not stub:
            raise SandboxDown(f"refused under CTF_TESTING: {path} is not a test stub; no test starts a runtime container")
    return path


def runtime_image(tag: str, want_hash: str, build_hint: str = "") -> str:
    """The image id (sha256:...) of ``tag``, after checking that the image carries the toolchain
    label ``want_hash`` (the hash of the files it must be built from). SandboxDown, naming what to
    do, when the image is not built, carries no label, or was built from other files."""
    if not RUNTIME_TAG.fullmatch(tag) or tag.endswith(":latest"):
        raise ValueError(f"{tag!r} is not an exact image tag")
    if not RUNTIME_HASH.fullmatch(want_hash):
        raise ValueError("want_hash must be the 64 hex digits of the image's content hash")
    _runtime_docker()
    hint = f" ({build_hint})" if build_hint else ""
    code, out, err = _docker(["image", "inspect", "--format",
                              '{{.Id}} {{index .Config.Labels "' + RUNTIME_LABEL + '"}}', tag], PROBE_TIMEOUT)
    if code != 0:
        line = _first_line(err)
        if "no such image" in line.lower() or "not found" in line.lower():
            raise SandboxDown(f"the image {tag} is not built{hint}")
        raise SandboxDown(f"the Docker daemon does not answer ({line or f'exit {code}'})")
    parts = _first_line(out).split()
    image_id = parts[0] if parts else ""
    have = parts[1] if len(parts) > 1 else ""
    if not RUNTIME_ID.fullmatch(image_id):
        raise SandboxDown(f"docker image inspect gave no image id for {tag}")
    if not RUNTIME_HASH.fullmatch(have):
        raise SandboxDown(f"the image {tag} carries no {RUNTIME_LABEL} label: it was not built by "
                          f"`ctf toolchain build`, so its content is not known{hint}")
    if have != want_hash:
        raise SandboxDown(f"the image {tag} was built from other files (label {have[:12]}, the files now "
                          f"hash to {want_hash[:12]}){hint}")
    return image_id


def runtime_argv(image_id: str, name: str, seconds: int, argv, memory: str = "768m", cpus: str = "1",
                 pids: int = 96) -> list:
    """The `docker run` arguments of one runtime container: no network, no mount, never a pull, a
    read-only root, every capability dropped, no-new-privileges, an unprivileged user, CPU, memory
    and process limits, a tmpfs /tmp and a tmpfs /work for the request, stdin kept open for it, and
    the entry script as the command. ValueError for anything that is not exactly that shape."""
    if not RUNTIME_ID.fullmatch(image_id):
        raise ValueError("a runtime container runs an image id (sha256:...), never a tag")
    if not re.fullmatch(r"ctf-runtime-[0-9a-f]{12}", name):
        raise ValueError("a runtime container is named ctf-runtime-<12 hex>")
    if not isinstance(seconds, int) or isinstance(seconds, bool) or not 1 <= seconds <= RUNTIME_MAX_SECONDS:
        raise ValueError(f"seconds must be 1..{RUNTIME_MAX_SECONDS}")
    if not RUNTIME_LIMIT["memory"].fullmatch(memory) or not RUNTIME_LIMIT["cpus"].fullmatch(cpus):
        raise ValueError("memory is <int><k|m|g> and cpus a positive number")
    if not isinstance(pids, int) or isinstance(pids, bool) or not 8 <= pids <= 1024:
        raise ValueError("pids must be 8..1024")
    argv = [str(a) for a in argv]
    if not argv or any("\x00" in a for a in argv):
        raise ValueError("the runner argv must be non-empty strings")
    return ["run", "--rm", "-i", "--name", name, "--network", "none", "--pull=never", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", UID, "--init",
            "--cpus", cpus, "--memory", memory, "--memory-swap", memory, "--pids-limit", str(pids),
            "--ulimit", f"fsize={FSIZE}", "--ulimit", "nofile=1024:1024", "--restart", "no",
            "--tmpfs", f"/tmp:rw,nosuid,nodev,size={LIMITS['tmp']}",
            "--tmpfs", "/work:rw,nosuid,nodev,noexec,size=256m,mode=1777",
            "--workdir", "/work", "--entrypoint", RUNTIME_ENTRY, image_id, str(seconds), *argv]


def runtime_request(members) -> bytes:
    """The request tar of (name, bytes) members: `artifact.bin` and `dep/NNN.bin` only (the names
    docker/runtime/entry.sh unpacks), plus the `dep/` folder itself. ValueError for any other name,
    for a missing artifact, or when the request is over RUNTIME_MAX_INPUT."""
    import io
    import tarfile
    members = [(str(n), bytes(b)) for n, b in members]
    names = [n for n, _ in members]
    if names.count("artifact.bin") != 1 or len(set(names)) != len(names):
        raise ValueError("a runtime request holds exactly one artifact.bin and no name twice")
    bad = [n for n in names if not RUNTIME_MEMBER.fullmatch(n)]
    if bad:
        raise ValueError(f"not a runtime request member name: {bad[0]!r}")
    if sum(len(b) for _, b in members) > RUNTIME_MAX_INPUT:
        raise ValueError(f"the request is over {RUNTIME_MAX_INPUT} bytes")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        folder = tarfile.TarInfo("dep")
        folder.type, folder.mode = tarfile.DIRTYPE, 0o755
        tar.addfile(folder)
        for name, body in sorted(members):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(body), 0o644
            tar.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def runtime_run(tag: str, want_hash: str, argv, members, seconds: int, *, memory: str = "768m",
                cpus: str = "1", pids: int = 96, build_hint: str = "") -> Result:
    """Run one runtime runner over one request in a fresh container of the image ``tag``, and give
    its Result (code: the runner's exit status, 124 when the container's time limit stopped it;
    stdout: the trace line; stderr: the runner's diagnostics; no files).

    The image must carry the content hash ``want_hash`` (runtime_image) and is run by its image id.
    The container (runtime_argv) has no network and no mount: ``members`` go in on stdin
    (runtime_request) and nothing comes back but the two streams. It is stopped from the inside
    after ``seconds``; when the docker CLI still has not returned RUNTIME_START_SLACK seconds after
    that, the container is killed by its own name and the call is SandboxDown. Nothing is ever run
    on the host."""
    image_id = runtime_image(tag, want_hash, build_hint)
    name = f"ctf-runtime-{uuid.uuid4().hex[:12]}"
    args = runtime_argv(image_id, name, seconds, argv, memory, cpus, pids)
    request = runtime_request(members)
    t0 = time.perf_counter()
    try:
        code, so, se = _docker(args, seconds + RUNTIME_START_SLACK, input_bytes=request)
    except SandboxDown:
        try:
            _docker(["kill", name], 30)          # our own container, by the unique name we gave it
        except SandboxDown:
            pass
        raise
    took = time.perf_counter() - t0
    line = _first_line(se)
    # 125 / 126 / 127 with the CLI's own `docker:` line: the container never ran the entry script.
    # (A runner may exit with any status and print anything; only the CLI writes that prefix first.)
    if code in (125, 126, 127) and line.startswith("docker:"):
        raise SandboxDown(f"docker run could not start {tag} ({line})")
    r = Result(code, so, se, {}, None, took)
    r.image = tag
    return r


# ---- bench -------------------------------------------------------------------------------------

def bench(n: int = 10) -> dict:
    """Median seconds of one trivial call (`true`), warm (docker exec into the running container)
    and cold (docker run --rm with the same settings), and of a warm `upx --version`."""
    def timed(args):
        t0 = time.perf_counter()
        code, _, err = _docker(args, 60)
        if code != 0:
            raise SandboxDown(f"docker {args[0]} failed ({_first_line(err) or f'exit {code}'})")
        return time.perf_counter() - t0
    gen = choose()
    ok, detail = health_of(gen)
    if not ok:
        raise SandboxDown(detail)
    warm = [timed(["exec", gen.name, "true"]) for _ in range(n)]
    upx = [timed(["exec", gen.name, "upx", "--version"]) for _ in range(n)]
    cold = [timed(["run", "--rm", *run_args(gen), gen.image, "true"]) for _ in range(max(3, n // 2))]
    return {"warm_exec": statistics.median(warm), "warm_upx_version": statistics.median(upx),
            "cold_run": statistics.median(cold), "n": n}


# ---- command line ------------------------------------------------------------------------------

def main(argv) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0 if argv else 2
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "build" and (not rest or rest in (["1"], ["2"])):
            return build(gen=next(g for g in GENS if str(g.n) == rest[0]) if rest else None)
        if cmd == "tools" and not rest:
            for g in reversed(GENS):
                own = [t for t in g.tools if g.n == 1 or t not in TOOLS_1]
                print(f"{g.image} ({g.name}{'' if g.n == 1 else ', and everything of :1'}): {' '.join(own)}")
            return 0
        if cmd == "start":
            launch, wait = False, 120.0
            while rest:
                if rest[0] == "--launch-docker":
                    launch, rest = True, rest[1:]
                elif rest[0] == "--wait" and len(rest) > 1:
                    wait, rest = float(rest[1]), rest[2:]
                else:
                    return usage()
            print(time.strftime("%Y-%m-%d %H:%M:%S"), "sandbox start")
            start(launch, wait)
            print("SANDBOX up")
            return 0
        if cmd == "stop" and rest in ([], ["--all"]):
            gone = stop(every=bool(rest))
            print("SANDBOX stopped" if gone else "SANDBOX stop: the container could not be removed (is Docker up?)")
            return 0 if gone else 3
        if cmd == "status":
            ok, detail = health()
            if rest == ["--json"]:
                print(json.dumps({"up": ok, "detail": detail, "dir": str(sandbox_dir())}))
            elif rest:
                return usage()
            else:
                print(f"SANDBOX {'up' if ok else 'down'}: {detail}")
            return 0 if ok else 1
        if cmd == "bench":
            n = int(rest[1]) if rest[:1] == ["-n"] and len(rest) == 2 else (10 if not rest else -1)
            if n < 1:
                return usage()
            got = bench(n)
            print(f"SANDBOX bench n={got['n']}: warm exec {got['warm_exec'] * 1000:.0f} ms, warm upx --version "
                  f"{got['warm_upx_version'] * 1000:.0f} ms, cold run {got['cold_run'] * 1000:.0f} ms (medians)")
            return 0
        if cmd == "run":
            timeout, inputs, keep = RUN_TIMEOUT, [], False
            while rest and rest[0].startswith("--"):
                if rest[0] == "--timeout" and len(rest) > 1:
                    timeout, rest = float(rest[1]), rest[2:]
                elif rest[0] == "--in" and len(rest) > 1:
                    inputs.append(rest[1])
                    rest = rest[2:]
                elif rest[0] == "--keep":
                    keep, rest = True, rest[1:]
                else:
                    return usage()
            if not rest:
                return usage()
            if rest[0] not in TOOLS:
                print(f"sandbox: {rest[0]} is not a sandbox tool ({', '.join(TOOLS)})", file=sys.stderr)
                return 2
            r = run(rest[0], rest[1:], inputs, timeout, keep)
            sys.stdout.buffer.write(r.stdout)
            sys.stderr.buffer.write(r.stderr)
            if r.note:
                print(f"sandbox: {r.note}", file=sys.stderr)
            if r.out_dir:
                print(f"sandbox: output kept at {r.out_dir}", file=sys.stderr)
            if r.timed_out:
                print(f"sandbox: {rest[0]} was stopped after {timeout:g} s", file=sys.stderr)
            return r.code
    except SandboxDown as e:
        print(f"SANDBOX DOWN: {e}", file=sys.stderr)
        return 3
    except (OSError, ValueError) as e:
        print(f"sandbox: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    return usage()


def usage() -> int:
    print("usage: sandbox.py build [1|2] | start [--launch-docker] [--wait S] | stop [--all] | status [--json] | tools | "
          "run [--timeout S] [--in FILE]... [--keep] TOOL [ARGS...] | bench [-n N]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
