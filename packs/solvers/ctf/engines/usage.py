"""Real-use metric: how often each engine ran in play, from the `engine.run` ledger records.

    python -m ctf engines usage [--workdir DIR]...

A workdir is one event's runtime folder (`paths.workdir()`); several can be combined. Active engines
that never ran are counted, which is the number B-008 asked for: built engines that never fire.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .. import ledger
from . import manifest as _manifest
from .runner import LEDGER_EVENT


@dataclass
class Use:
    engine: str
    runs: int = 0
    failures: int = 0          # non-zero exit codes
    last_ts: float = 0.0
    statuses: dict | None = None


def collect(workdirs: list[Path]) -> dict[str, Use]:
    out: dict[str, Use] = {}
    for wd in workdirs:
        for rec in ledger.read(Path(wd)):
            if rec.get("event") != LEDGER_EVENT or "engine" not in rec:
                continue
            u = out.setdefault(rec["engine"], Use(rec["engine"], statuses=defaultdict(int)))
            u.runs += 1
            u.failures += 1 if rec.get("exit_code", 0) != 0 else 0
            u.last_ts = max(u.last_ts, float(rec.get("ts", 0)))
            if rec.get("status"):
                u.statuses[rec["status"]] += 1
    return out


def report(uses: dict[str, Use], manifests: list[_manifest.Manifest]) -> str:
    import time
    active = [m.id for m in manifests if m.status != "retired"]
    lines = [f"{'engine':40} {'runs':>5} {'fail':>5}  last run (UTC)       statuses"]
    for u in sorted(uses.values(), key=lambda u: (-u.runs, u.engine)):
        last = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(u.last_ts)) if u.last_ts else "-"
        st = ", ".join(f"{k}={v}" for k, v in sorted((u.statuses or {}).items()))
        lines.append(f"{u.engine:40} {u.runs:>5} {u.failures:>5}  {last:20} {st}")
    unknown = sorted(set(uses) - {m.id for m in manifests})
    never = [i for i in active if i not in uses]
    lines.append("")
    lines.append(f"{len(uses)} engine(s) used; {len(never)} of {len(active)} active engines never ran")
    if unknown:
        lines.append("ran but no longer manifested: " + ", ".join(unknown))
    return "\n".join(lines)
