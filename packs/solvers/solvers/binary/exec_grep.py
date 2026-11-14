#!/usr/bin/env python3
"""Sandbox exec-and-grep at intake (B-024).

Some keygen / check binaries simply *print the flag* when run (sometimes only when given the right
argument -- the code a mixer-inversion recovers).  The mounted handout is often not even executable.
This engine copies each ELF into a locked-down container (``csctf-pwn:1`` by default), makes it
executable, runs it read-only / no-network / resource-capped with a hard timeout, and greps the
combined stdout+stderr for the event flag format.  Candidate inputs are read from
``recon/mixer/recovered.txt`` (written by ``binary.mixer_invert``) so the two compose: invert the
mixer, then confirm by running ``./fcunlock <code>`` in the sandbox.

Isolation is **not optional**: the binary is untrusted.  The run path requires Docker and the sandbox
image and fails loudly (``blocked``) when either is missing -- there is no native fallback, and this
engine never runs a challenge binary on the host.  The actual exec is delegated to a pluggable
:class:`SandboxExec` backend so the grep/aggregation logic is testable without Docker.

Entry: ``solve(challenge_dir, profile) -> SolverResult`` (an intake ``run = "challenge"`` adapter,
``spawns = true`` so intake runs it only under the OS network sandbox).
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_IMAGE = "csctf-pwn:1"
DEFAULT_TIMEOUT = 10                 # seconds per run inside the container
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_BINARIES = 8
MAX_INPUTS = 16                      # candidate argv inputs tried per binary
MAX_OUTPUT = 1 << 20                 # bytes of combined output scanned per run
# Native executables the backend can run. Production is Linux ELF in the csctf-pwn image; Mach-O is
# accepted too so a native-backend run works on a dev host. The grep logic is format-agnostic.
_ELF = b"\x7fELF"
_MACHO = frozenset({b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                    b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"})


def _is_native_exe(head: bytes) -> bool:
    return head[:4] == _ELF or head[:4] in _MACHO

# Container resource caps (one call is one `docker run`).
MEM_LIMIT = "64m"
PIDS_LIMIT = 64
CPU_LIMIT = "1.0"
TMPFS_SIZE = "16m"
CONTAINER_PATH = "/work/target"      # where the binary is mounted (read-only)


class SandboxUnavailable(RuntimeError):
    """The isolation backend (Docker + image) is not available; the run cannot proceed safely."""


@dataclass(frozen=True)
class RunResult:
    stdout: bytes = b""
    stderr: bytes = b""
    exit_code: int = 0
    timed_out: bool = False

    @property
    def output(self) -> bytes:
        return (self.stdout + b"\n" + self.stderr)[:MAX_OUTPUT]


def image_for(profile) -> str:
    """The sandbox image: ``CTF_PWN_IMAGE`` env, else the profile's, else ``csctf-pwn:1``."""
    env = os.environ.get("CTF_PWN_IMAGE")
    if env:
        return env
    img = getattr(profile, "pwn_image", None) if profile is not None else None
    return img or DEFAULT_IMAGE


def docker_run_argv(image: str, host_path: str, argv, *, timeout: int = DEFAULT_TIMEOUT,
                    mem: str = MEM_LIMIT, pids: int = PIDS_LIMIT, cpus: str = CPU_LIMIT) -> list[str]:
    """The ``docker run`` command for one locked-down execution (pure; built even in tests).

    ``--network none`` (no network), ``--read-only`` root with the binary mounted read-only, all
    capabilities dropped, no-new-privileges, memory / pids / cpu caps, a small writable tmpfs, and a
    container-side ``timeout`` so a hung process is killed even if the host wrapper is bypassed.
    """
    return [
        "docker", "run", "--rm",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", mem,
        "--pids-limit", str(pids),
        "--cpus", cpus,
        "--tmpfs", f"/tmp:size={TMPFS_SIZE},exec",
        "--workdir", "/tmp",
        "-v", f"{host_path}:{CONTAINER_PATH}:ro",
        "--entrypoint", "timeout",
        image,
        "-k", "1", str(timeout),
        # copy to writable tmpfs, chmod +x, run (the mount is read-only / often non-exec).
        "sh", "-c", f'cp {CONTAINER_PATH} /tmp/t && chmod +x /tmp/t && /tmp/t "$@"', "t",
        *[str(a) for a in argv],
    ]


@dataclass
class DockerExec:
    """Production backend: one ``docker run --rm --network none`` per execution.

    ``run_fn`` and ``which_fn`` are injectable so the command building and the unavailable-path can be
    exercised without a Docker daemon; the default path shells out to real ``docker``.
    """
    image: str = DEFAULT_IMAGE
    run_fn: object = field(default=subprocess.run, repr=False)
    which_fn: object = field(default=shutil.which, repr=False)
    _image_ok: "bool | None" = field(default=None, repr=False, compare=False)

    def available(self) -> tuple[bool, str]:
        if self.which_fn("docker") is None:
            return False, "docker not found on PATH"
        # The sandbox image is a required resource: a missing image must fail loudly (blocked),
        # not surface later as a swallowed non-zero docker exit reported as "no flag" (rule 6/10).
        if self._image_ok is None:
            self._image_ok = self._probe_image()
        if not self._image_ok:
            return False, f"image {self.image} not present"
        return True, ""

    def _probe_image(self) -> bool:
        """``docker image inspect <image>`` returns 0 iff the local image exists (read-only query)."""
        try:
            cp = self.run_fn(["docker", "image", "inspect", self.image],
                             capture_output=True, timeout=30, check=False)
        except subprocess.TimeoutExpired:
            return False
        except FileNotFoundError:                      # docker vanished between the PATH check and here
            return False
        return getattr(cp, "returncode", 1) == 0

    def run(self, host_path: Path, argv=(), *, timeout: int = DEFAULT_TIMEOUT) -> RunResult:
        ok, why = self.available()
        if not ok:
            raise SandboxUnavailable(
                f"{why}; sandbox exec-and-grep needs Docker and the {self.image} image")
        cmd = docker_run_argv(self.image, str(host_path), argv, timeout=timeout)
        env = {k: v for k, v in os.environ.items()
               if k not in ("CTF_TOKEN",) and "TOKEN" not in k and "COOKIE" not in k}
        try:
            cp = self.run_fn(cmd, capture_output=True, timeout=timeout + 5, env=env, check=False)
        except subprocess.TimeoutExpired as e:
            return RunResult(stdout=e.stdout or b"", stderr=e.stderr or b"", exit_code=124,
                             timed_out=True)
        except FileNotFoundError as e:                 # docker vanished between check and run
            raise SandboxUnavailable(str(e)) from e
        return RunResult(stdout=cp.stdout or b"", stderr=cp.stderr or b"",
                         exit_code=cp.returncode, timed_out=cp.returncode == 124)


# --------------------------------------------------------------------------- engine
def _native_exe_files(challenge_dir: Path) -> list[Path]:
    out = []
    for p in sorted(challenge_dir.rglob("*")):
        if "recon" in p.parts or not p.is_file() or p.is_symlink():
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            with p.open("rb") as fh:
                if not _is_native_exe(fh.read(4)):
                    continue
        except OSError:
            continue
        out.append(p)
        if len(out) >= MAX_BINARIES:
            break
    return out


def candidate_inputs(challenge_dir: Path) -> list[list[str]]:
    """Argv candidates to try: no-arg, then each recovered code from ``recon/mixer/recovered.txt``."""
    inputs: list[list[str]] = [[]]
    rec = challenge_dir / "recon" / "mixer" / "recovered.txt"
    try:
        for line in rec.read_text(encoding="utf-8", errors="replace").splitlines():
            code = line.strip()
            if code and [code] not in inputs:
                inputs.append([code])
    except OSError:
        pass
    return inputs[:MAX_INPUTS]


def solve(challenge_dir, profile, *, exec_backend=None, timeout: int = DEFAULT_TIMEOUT, **_opts):
    """Run every handout ELF in the sandbox and grep its output for the event flag.

    ``solved`` when a run prints a flag; ``none`` when nothing does; ``blocked`` when the isolation
    backend (Docker + image) is unavailable (the binary is never run on the host).
    """
    from ctf.result import SolverResult, Evidence
    from ctf import flagfmt

    challenge_dir = Path(challenge_dir)
    ff = flagfmt.for_profile(profile)
    files = _native_exe_files(challenge_dir)
    if not files:
        return SolverResult(status="none", engine="binary.exec_grep",
                            notes="no native executable (ELF/Mach-O) in the handout")

    backend = exec_backend if exec_backend is not None else DockerExec(image_for(profile))
    avail = getattr(backend, "available", lambda: (True, ""))()
    ok, why = avail if isinstance(avail, tuple) else (bool(avail), "")
    if not ok:
        image = getattr(backend, "image", image_for(profile))
        return SolverResult(status="blocked", engine="binary.exec_grep",
                            notes=(f"sandbox unavailable: {why}. exec-and-grep needs Docker and the "
                                   f"{image} image; the binary is never run on the host."))

    inputs = candidate_inputs(challenge_dir)
    flags: list[str] = []
    evidence: list[Evidence] = []
    ran = 0
    errs: list[str] = []
    for f in files:
        rel = str(f.relative_to(challenge_dir))
        for argv in inputs:
            try:
                res = backend.run(f, argv, timeout=timeout)
            except SandboxUnavailable as e:
                return SolverResult(status="blocked", engine="binary.exec_grep",
                                    notes=f"sandbox unavailable mid-run: {e}")
            except Exception as e:                      # a backend error on one input is not fatal
                errs.append(f"{rel} {argv!r}: {type(e).__name__}: {e}")
                continue
            ran += 1
            for fl in ff.find_flags(res.output):
                if fl not in flags:
                    flags.append(fl)
                    how = "no args" if not argv else f"argv {argv!r}"
                    evidence.append(Evidence(
                        kind="oracle", path=rel,
                        detail=f"ran {rel} in sandbox ({how}); output contained {fl}"))

    if flags:
        return SolverResult(status="solved", flags=tuple(flags), evidence=tuple(evidence),
                            engine="binary.exec_grep",
                            notes=(f"flag printed by running the binary in the sandbox "
                                   f"({ran} run(s))" + (f"; errors: {'; '.join(errs)}" if errs else "")))
    note = f"ran {ran} sandbox execution(s), no flag in output"
    if errs:
        note += "; errors: " + "; ".join(errs)
    return SolverResult(status="none", engine="binary.exec_grep", notes=note)


if __name__ == "__main__":            # manual: python exec_grep.py <image> <binary> [args...]
    import json
    import sys
    img, binp, *rest = sys.argv[1:]
    r = DockerExec(img).run(Path(binp), rest)
    print(json.dumps({"exit": r.exit_code, "timed_out": r.timed_out,
                      "output": r.output.decode("latin-1")}, indent=2))
