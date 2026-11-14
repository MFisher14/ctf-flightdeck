"""The fold-audit gate (B-038): every live fix recorded for an event has reached the master commit the
next event will start from.

    res = foldaudit.audit("csctf", target="HEAD")          # AuditResult; res.passed
    foldaudit.audit_all(target=sha, exclude={"next-event"})  # every event with a record or start tag

The record is `<master>/events/<slug>/promotion.json` (ctf/promote.py). Per entry:

- undecided                      -> fail (decide it: engine, fold or drop)
- drop (with a reason)           -> pass
- fold, content identical at a dest path in the target   -> pass
- fold, deleted in the event and absent at the target    -> pass
- fold with `commit`: that commit is in the target's history, came after the event's start commit
  (`base`), changes at least one dest, and every dest exists at the target -> pass
- engine: module, manifest and test all exist at the target, the module differs from its content at
  the start commit, the manifest is valid and is the module's sidecar, the test names the module, and
  a recorded `commit` passes the same checks as a fold's (changing the module, manifest or test)
- anything else                  -> fail, naming what is missing

The record itself must be committed at the target (`record:events/<slug>/promotion.json`): an
uncommitted or locally edited record fails, because the next event's checkout would not carry it.

With the event fork (or workspace) given, the audit inventories it again from the recorded start
commit: a change that is not in the record, or whose content changed after it was recorded, fails.
That is the "a live fix stayed uncommitted in the fork" case.

Exit codes for the CLI: 0 pass, 1 fail, 2 error (no record, no tag, not a git checkout).
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import ledger, paths
from . import promote as _p
from .promote import PromoteError


class FoldAuditFailed(PromoteError):
    """Raised by callers that refuse to proceed past a failing audit; carries the results."""

    def __init__(self, results: list["AuditResult"]):
        self.results = results
        names = ", ".join(f"{r.event} ({len(r.failures())} unfolded)" for r in results)
        super().__init__(f"fold-audit fails for {names}")


@dataclass(frozen=True)
class Finding:
    key: str
    verdict: str            # pass | fail
    reason: str


@dataclass
class AuditResult:
    event: str
    target: str             # the ref as asked
    target_commit: str
    findings: list[Finding] = field(default_factory=list)
    note: str = ""

    @property
    def passed(self) -> bool:
        return not self.failures()

    def failures(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict == "fail"]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["passed"] = self.passed
        return d


def _file_at(master: Path, target: str, path: str) -> str | None:
    return _p.blob_at(master, target, path)


def _no_base(rec_base: str) -> str:
    return (f"the record's start commit {rec_base[:12]} is not in the master: cannot tell what changed "
            f"after the event started (fetch it, or re-inventory with --base)")


def _commit_ok(master: Path, d: dict, target: str, base: str | None, rec_base: str,
               touches: list[str]) -> str | None:
    """None when the decision's commit (if any) could have folded the event's change into the
    target: it is in the target's history, it came after the event's start commit, and it changes
    at least one of `touches`. Else the reason."""
    c = d.get("commit")
    if not c:
        return None
    if _p.commit_of(master, c) is None:
        return f"recorded commit {c[:12]} is not in the master"
    if not _p.is_ancestor(master, c, target):
        return f"recorded commit {c[:12]} is not in the history of the target"
    if base is None:
        return _no_base(rec_base)
    if _p.is_ancestor(master, c, base):
        return (f"recorded commit {c[:12]} is at or before the event's start commit {base[:12]}: it "
                f"cannot have folded a change made during the event")
    if not _p.changed_paths(master, c) & set(touches):
        return f"recorded commit {c[:12]} does not change {', '.join(touches)}"
    return None


def _check_fold(master: Path, target: str, e: _p.Entry, d: dict, base: str | None, rec_base: str) -> Finding:
    dest = d["dest"]
    if e.change == "deleted":
        present = [x for x in dest if _file_at(master, target, x) is not None]
        if present:
            return Finding(e.key, "fail", f"deleted in the event but still in the target: {', '.join(present)}")
        return Finding(e.key, "pass", "deletion reached the target")
    blobs = {x: _file_at(master, target, x) for x in dest}
    same = [x for x, b in blobs.items() if b == e.blob]
    if same:
        return Finding(e.key, "pass", f"identical at {same[0]}")
    missing = [x for x, b in blobs.items() if b is None]
    if d.get("commit"):
        bad = _commit_ok(master, d, target, base, rec_base, dest)
        if bad:
            return Finding(e.key, "fail", bad)
        if missing:
            return Finding(e.key, "fail", f"folded by {d['commit'][:12]} but missing at the target: "
                                          f"{', '.join(missing)}")
        return Finding(e.key, "pass", f"folded by {d['commit'][:12]}")
    if missing:
        return Finding(e.key, "fail", f"not in the target: {', '.join(missing)} absent")
    return Finding(e.key, "fail", f"the event's content is not at {', '.join(dest)} in the target (it "
                                  f"differs); fold it, or record the folding commit with --commit")


def _check_engine(master: Path, target: str, e: _p.Entry, d: dict, base: str | None, rec_base: str) -> Finding:
    from .engines import manifest as _m
    missing = [d[k] for k in ("module", "manifest", "test") if _file_at(master, target, d[k]) is None]
    if missing:
        return Finding(e.key, "fail", f"engine not in the target: {', '.join(missing)} absent")
    bad = _commit_ok(master, d, target, base, rec_base, [d["module"], d["manifest"], d["test"]])
    if bad:
        return Finding(e.key, "fail", bad)
    if base is None:
        return Finding(e.key, "fail", _no_base(rec_base))
    if _file_at(master, base, d["module"]) == _file_at(master, target, d["module"]):
        return Finding(e.key, "fail", f"engine module {d['module']} is unchanged since the event's start "
                                      f"commit {base[:12]}: the event's script never reached it")
    raw = _p.read_blob(master, _file_at(master, target, d["manifest"]))
    try:
        man = _m.parse(tomllib.loads(raw.decode("utf-8")), master / d["manifest"])
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, _m.ManifestError) as exc:
        return Finding(e.key, "fail", f"manifest {d['manifest']} is invalid: {exc}")
    if man.module_path.relative_to(master).as_posix() != d["module"]:
        return Finding(e.key, "fail", f"manifest {d['manifest']} is not the sidecar of {d['module']}")
    runs = None
    if man.entry.kind == "function":
        runs = man.entry.module.replace(".", "/")
        expect = str(Path(d["module"]).with_suffix(""))
    elif man.entry.is_python_cli:
        runs, expect = man.entry.argv[1], d["module"]
    if runs is not None and runs != expect:
        return Finding(e.key, "fail", f"manifest {d['manifest']} entry runs {runs}, not {d['module']}")
    test_text = _p.read_blob(master, _file_at(master, target, d["test"])).decode("utf-8", "replace")
    stem = Path(d["module"]).stem
    if not re.search(rf"(?<![A-Za-z0-9_]){re.escape(stem)}(?![A-Za-z0-9_])", test_text):
        return Finding(e.key, "fail", f"test {d['test']} never names the engine module '{stem}'")
    return Finding(e.key, "pass", f"engine {man.id}: module, manifest and test in the target")


def check_entry(master: Path, target: str, e: _p.Entry, *, base: str | None, rec_base: str) -> Finding:
    """One entry's verdict. `base` is the event's start commit resolved in the master (None when
    the master lacks it), `rec_base` the id the record names."""
    d = e.decision
    if d is None:
        prop = e.proposal.get("action", "?") if e.proposal else "none"
        return Finding(e.key, "fail", f"undecided ({e.state}; proposal: {prop}); run "
                                      f"`python -m ctf promote decide|accept`")
    if d["action"] == "drop":
        return Finding(e.key, "pass", f"dropped: {d['reason']}")
    if d["action"] == "fold":
        return _check_fold(master, target, e, d, base, rec_base)
    return _check_engine(master, target, e, d, base, rec_base)


def _drift(rec: _p.Record, fresh: list[_p.Entry], source: str) -> list[Finding]:
    known = {e.key: e for e in rec.entries if e.source == source}
    out = []
    for e in fresh:
        old = known.get(e.key)
        if old is None:
            out.append(Finding(e.key, "fail", f"live fix not in the record ({e.change}, {e.state}): "
                                              f"re-run `python -m ctf promote inventory`"))
        elif old.blob != e.blob or old.change != e.change:
            out.append(Finding(e.key, "fail", "changed after it was recorded: re-run "
                                              "`python -m ctf promote inventory` and decide it again"))
    return out


def _check_record_at_target(master: Path, target: str, slug: str, rec_file: Path) -> Finding | None:
    """The decisions travel with the master: the record audited must be the one committed at the
    target, or the next event's checkout (and a later audit of that commit) would not have it."""
    rel = f"events/{slug}/{_p.RECORD_NAME}"
    at = _file_at(master, target, rel)
    key = f"record:{rel}"
    if at is None:
        return Finding(key, "fail", f"the promotion record is not committed at the target: commit {rel}")
    if at != _p.blob_id(rec_file):
        return Finding(key, "fail", f"the record audited ({rec_file}) differs from {rel} at the target: "
                                    f"commit it")
    return None


def audit(slug: str, *, master: Path | None = None, target: str = "HEAD", record: Path | None = None,
          fork: Path | None = None, workspace: Path | None = None, log: bool = True) -> AuditResult:
    """Audit one event's record against `target` in the master. Raises PromoteError when it cannot
    run (no record, unreadable record, no git checkout, unknown target)."""
    master_root = paths.repo_root() if master is None else Path(master)
    rec_file = Path(record) if record else _p.record_path(slug, master_root)
    rec = _p.load_record(slug, master_root, record)
    master_root = _p.require_repo(master_root, "master")
    sha = _p.commit_of(master_root, target)
    if sha is None:
        raise PromoteError(f"target {target} is not a commit in {master_root}")
    base = _p.commit_of(master_root, rec.base)
    res = AuditResult(event=slug, target=target, target_commit=sha)
    res.findings = [check_entry(master_root, sha, e, base=base, rec_base=rec.base) for e in rec.entries]
    rec_finding = _check_record_at_target(master_root, sha, slug, rec_file)
    if rec_finding is not None:
        res.findings.append(rec_finding)
    if fork is not None:
        res.findings += _drift(rec, _p.inventory_fork(fork, rec.base), "fork")
    if workspace is not None:
        res.findings += _drift(rec, _p.inventory_workspace(workspace), "workspace")
    if not rec.entries:
        res.note = "the record lists no changes"
    if log:
        ledger.append("fold_audit.check", workdir=paths.workdir(slug), slug=slug, target=sha,
                      passed=res.passed, entries=len(rec.entries), failures=len(res.failures()))
    return res


def events_to_audit(master: Path) -> list[str]:
    """Every event with a promotion record or a start tag in the master."""
    slugs = set()
    ev = Path(master) / "events"
    if ev.is_dir():
        slugs |= {d.name for d in ev.iterdir() if (d / _p.RECORD_NAME).is_file()}
    tags = _p.git(master, "tag", "--list", f"{_p.TAG_PREFIX}*/start")
    for t in tags.splitlines():
        m = re.match(rf"^{re.escape(_p.TAG_PREFIX)}([a-z0-9][a-z0-9-]*)/start$", t.strip())
        if m:
            slugs.add(m.group(1))
    return sorted(slugs)


def _still_running(master: Path, slug: str, now: _dt.datetime | None) -> bool:
    """True when the event's profile says it has not ended (it is audited after it ends)."""
    from . import buildplan, event
    if not (Path(master) / "events" / slug / event.PROFILE_NAME).is_file():
        return False
    prof = event.load(slug, Path(master) / "events")
    return buildplan.phase_of(prof, now) != "post-event"


def audit_all(*, master: Path | None = None, target: str = "HEAD", exclude: set[str] | frozenset = frozenset(),
              now: _dt.datetime | None = None, log: bool = True) -> list[AuditResult]:
    """Audit every event that has a record or a start tag. A started event without a record fails
    (its live fixes were never inventoried) unless its profile says it is still running."""
    master = _p.require_repo(paths.repo_root() if master is None else Path(master), "master")
    sha = _p.commit_of(master, target)
    if sha is None:
        raise PromoteError(f"target {target} is not a commit in {master}")
    out = []
    for slug in events_to_audit(master):
        if slug in exclude:
            continue
        if not _p.record_path(slug, master).is_file():
            if _still_running(master, slug, now):
                out.append(AuditResult(slug, target, sha, note="still running: audited after it ends"))
                continue
            out.append(AuditResult(slug, target, sha, [Finding(
                f"event:{slug}", "fail",
                f"started (tag {_p.start_tag(slug)}) but no promotion record: run "
                f"`python -m ctf promote inventory {slug} --fork <event checkout>`")]))
            continue
        out.append(audit(slug, master=master, target=sha, log=log))
    return out


def render(res: AuditResult) -> str:
    lines = [f"fold-audit {res.event} -> {res.target} ({res.target_commit[:12]}): "
             f"{'PASS' if res.passed else 'FAIL'}"
             + (f"  [{res.note}]" if res.note else "")]
    for f in res.findings:
        lines.append(f"  {f.verdict.upper():<4}  {f.key}  {f.reason}")
    return "\n".join(lines)


def to_json(results: list[AuditResult]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=1)
