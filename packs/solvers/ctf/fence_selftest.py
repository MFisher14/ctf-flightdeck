"""Live check of the Codex half of the fence (B-219): run real commands under `codex sandbox` with
the fence's permission profile and confirm denied roots cannot be read and the workspace can.
A .ctf/ canary nested in the workspace must be refused too (R-03), and the repo's private trees
(analysis/, writeups, .claude/, .ctf/) are probed first among the denied roots.

Nothing is read from a denied root even when the fence fails: every probe is `stat -f %z`
(prints a size, never contents) or `cat` of a canary file this check wrote itself.
"""
from __future__ import annotations

import dataclasses
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .fence import DenyRule, Fence

_NOT_PERMITTED = ("Operation not permitted", "Permission denied")


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _sandbox(codex_bin: str, fence: Fence, argv: list[str], timeout: int) -> subprocess.CompletedProcess:
    cmd = [codex_bin, "sandbox", *fence.codex_config_args(), "--", *argv]
    return subprocess.run(cmd, cwd=fence.workspace, capture_output=True, text=True, timeout=timeout)


def codex_selftest(fence: Fence, *, codex_bin: str = "codex", max_roots: int | None = None,
                   timeout: int = 60) -> list[Check]:
    if shutil.which(codex_bin) is None:
        raise FileNotFoundError(f"codex CLI not found ({codex_bin!r}); install it or pass --codex-bin")
    checks: list[Check] = []
    fence.workspace.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fence-canary-") as canary_dir, \
            tempfile.NamedTemporaryFile("w", dir=fence.workspace, prefix=".fence-probe-",
                                        suffix=".txt", delete=False) as probe:
        probe.write("WORKSPACE-OK\n")
        probe.close()
        canary = Path(canary_dir).resolve() / "canary.txt"
        canary.write_text("CANARY-SHOULD-NOT-BE-READ\n")
        f2 = dataclasses.replace(fence, deny=fence.deny + (
            DenyRule("selftest", canary.parent, False, "self-test canary"),))
        try:
            r = _sandbox(codex_bin, f2, ["/bin/cat", probe.name], timeout)
            checks.append(Check("workspace readable", r.returncode == 0 and "WORKSPACE-OK" in r.stdout,
                                (r.stderr or r.stdout).strip()[:200]))
            r = _sandbox(codex_bin, f2, ["/bin/cat", str(canary)], timeout)
            blocked = r.returncode != 0 and "CANARY" not in r.stdout and any(
                s in r.stderr for s in _NOT_PERMITTED)
            checks.append(Check("canary in a denied root blocked", blocked,
                                (r.stderr or r.stdout).strip()[:200]))
            # Control: the same probe under Codex's plain workspace-write sandbox (no fence) must
            # read the canary, or the check above proves nothing about the fence.
            r = subprocess.run([codex_bin, "sandbox", "-c", 'sandbox_mode="workspace-write"', "--",
                                "/bin/cat", str(canary)], cwd=fence.workspace, capture_output=True,
                               text=True, timeout=timeout)
            checks.append(Check("control: canary readable without the fence",
                                r.returncode == 0 and "CANARY" in r.stdout,
                                (r.stderr or r.stdout).strip()[:200]))
            # R-03: a .ctf/ directory nested inside the (writable) workspace is still unreadable.
            # The canary lives under the workspace probe dir, so the workspace read above is its
            # control.
            for n in fence.deny_names:
                cdir = Path(tempfile.mkdtemp(prefix=".fence-probe-", dir=fence.workspace))
                try:
                    secret = cdir / "sub" / n.name / "canary.txt"
                    secret.parent.mkdir(parents=True)
                    secret.write_text("CANARY-SHOULD-NOT-BE-READ\n")
                    r = _sandbox(codex_bin, fence, ["/bin/cat", str(secret)], timeout)
                    blocked = r.returncode != 0 and "CANARY" not in r.stdout and any(
                        s in r.stderr for s in _NOT_PERMITTED)
                    checks.append(Check(f"{n.category}: a {n.name}/ inside the workspace blocked",
                                        blocked, (r.stderr or r.stdout).strip()[:200]))
                finally:
                    shutil.rmtree(cdir, ignore_errors=True)
        finally:
            Path(probe.name).unlink(missing_ok=True)
    # Repo carve-outs (R-03) first, so a max_roots cap still probes them.
    roots = sorted((d for d in fence.deny if d.category != "home" and d.path.exists()),
                   key=lambda d: d.carved_from is None)
    if max_roots is not None:
        roots = roots[:max_roots]
    for d in roots:
        r = _sandbox(codex_bin, fence, ["/usr/bin/stat", "-f", "%z", str(d.path)], timeout)
        blocked = r.returncode != 0 and any(s in r.stderr for s in _NOT_PERMITTED)
        checks.append(Check(f"{d.category}: {d.path}", blocked,
                            "blocked" if blocked else f"READABLE (exit {r.returncode})"))
    return checks
