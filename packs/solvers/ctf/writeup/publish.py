"""Build the public writeup tree from staging, and the publish plan. DRY RUN ONLY.

    plan = publish.build(profile, staging, out, known=..., now=...)
    plan.ready         # every gate passed: the tree COULD be pushed on the player's go
    plan.to_dict()     # what is written to the plan file

Only an allowlist leaves staging: text files with a known suffix, at most MAX_BYTES, outside private
names and folders. Each file has its private blocks stripped, is redacted when the event redacts, and
is scanned; the scan's blocking findings, the event's hold, its end time and its public repo are the
gates (ctf.writeup.policy). Excluded files are listed with the reason, so a screenshot or binary
someone wants public is a visible human decision, never a silent copy.

Nothing here runs git or gh, creates a repository or pushes: the plan lists the commands a person
would run after the go (`would_run`). B-098 ships the dry run only; executing the plan is a follow-up
that needs the player's decision.
"""
from __future__ import annotations

import datetime as _dt
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .. import event as _event
from . import common, passes as _passes, policy as _policy, scan as _scan

MARKER = ".ctf-public-tree"
ALLOW_NAME = "publish-allow.txt"
MAX_BYTES = 512 * 1024
TEXT_SUFFIXES = frozenset({
    ".md", ".txt", ".py", ".sage", ".sh", ".c", ".h", ".cpp", ".hpp", ".rs", ".go", ".js", ".ts", ".rb",
    ".pl", ".php", ".java", ".kt", ".cs", ".ps1", ".lua", ".gdb", ".r2", ".asm", ".s", ".sol", ".html",
    ".css", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".sql", ".nim", ".zig", ".hs", ".ml",
})
# Staging records that never leave staging (the 2026 staging README's "do not publish" list, plus the
# workspace bookkeeping names in case a workspace file was copied into staging).
PRIVATE_NAMES = frozenset({
    "STATUS.md", "SOURCE.md", "NEEDS-PLAYER-INPUT.md", "event.json", "solves.json", common.STATE_NAME,
    ALLOW_NAME, "notes.md", "tried.json", "flag.txt", "challenge.json", "ledger.jsonl",
})
PRIVATE_DIRS = frozenset({"files", "retro", "attachments", "screenshots"})


@dataclass
class Plan:
    event: str
    staging: Path
    out: Path
    public_repo: str | None
    redacted: bool
    known_values: int
    known_source: str
    gates: list[_policy.Gate] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)
    excluded: list[dict] = field(default_factory=list)
    findings: list[_scan.Finding] = field(default_factory=list)
    short_known: int = 0
    known_hashes: int = 0

    @property
    def blocking(self) -> list[_scan.Finding]:
        return [f for f in self.findings if f.blocking]

    @property
    def ready(self) -> bool:
        return bool(self.gates) and all(g.ok for g in self.gates)

    def would_run(self) -> list[str]:
        repo = self.public_repo or "<public_repo not set>"
        name = repo.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        return [
            f"cd {self.out}",
            "git init -b main  # only if the tree is not a git repo yet",
            "git add -A",
            f"git commit -m 'Writeups: {self.event}'",
            f"gh repo create {name} --public --source . --remote origin  # only if the repo does not exist",
            f"git push -u origin main  # to {repo}",
        ]

    def to_dict(self) -> dict:
        return {
            "mode": "dry-run",
            "status": "ready" if self.ready else "blocked",
            "event": self.event,
            "public_repo": self.public_repo,
            "staging": str(self.staging),
            "out": str(self.out),
            "redacted": self.redacted,
            "known_values": self.known_values,
            "known_source": self.known_source,
            "short_known_values_not_redacted": self.short_known,
            "known_flag_hashes": self.known_hashes,
            "gates": [g.to_dict() for g in self.gates],
            "files": self.files,
            "excluded": self.excluded,
            "findings": [f.to_dict() for f in self.findings],
            "would_run": self.would_run(),
            "note": "Dry run: nothing was pushed, no repository was created. A person runs would_run "
                    "after the player's go.",
        }


def _exclusion(rel: Path, size: int) -> str | None:
    parts = rel.parts
    if any(p.startswith((".", "_")) for p in parts):
        return "hidden or underscore path (private)"
    if rel.name in PRIVATE_NAMES:
        return "private staging record"
    if any(p in PRIVATE_DIRS for p in parts[:-1]):
        return f"private folder {next(p for p in parts[:-1] if p in PRIVATE_DIRS)}/"
    if rel.suffix.lower() not in TEXT_SUFFIXES:
        return "not a reviewable text file: publish it by hand after review"
    if size > MAX_BYTES:
        return f"larger than {MAX_BYTES} bytes"
    return None


def read_allow(staging: Path) -> list[str]:
    p = staging / ALLOW_NAME
    if not p.is_file():
        return []
    return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]


def _prepare_out(out: Path, staging: Path) -> None:
    if out == staging or staging in out.parents or out in staging.parents:
        raise common.WriteupError(f"public tree {out} and staging {staging} must not contain each other")
    if out.exists():
        if not out.is_dir():
            raise common.WriteupError(f"public tree path {out} exists and is not a folder")
        children = [c for c in out.iterdir() if c.name != ".git"]
        if children and not (out / MARKER).is_file():
            raise common.WriteupError(f"refusing to clear {out}: it is not empty and has no {MARKER} marker "
                                      "(it was not built by this pipeline)")
        for c in children:
            shutil.rmtree(c) if c.is_dir() and not c.is_symlink() else c.unlink()
    out.mkdir(parents=True, exist_ok=True)
    (out / MARKER).write_text("built by python -m ctf writeup publish (B-098); contents are regenerated\n",
                              encoding="utf-8")


def _index(profile: _event.EventProfile, files: list[dict]) -> str:
    lines = [f"# {profile.name}: writeups", ""]
    for f in files:
        if f["path"].endswith("README.md") and "/" in f["path"]:
            lines.append(f"- [{f['title'] or f['path'].rsplit('/', 2)[0]}]({f['path']})")
    return "\n".join(lines) + "\n"


def _title(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return common.cell(line[2:].strip())
    return ""


def build(profile: _event.EventProfile, staging: Path, out: Path, *, known: set[str] | None,
          known_source: str, now: _dt.datetime | None = None, known_hashes: set[str] = frozenset()) -> Plan:
    """Build the public tree at `out` and return the plan. `known` is the set of flag values on record
    (None is refused: say known_source="pattern-only" with an empty set to accept pattern redaction);
    `known_hashes` the ledger's flag_sha256 values (ctf.writeup.evidence.known_hashes)."""
    if known is None:
        raise common.WriteupError("publish needs the known flag values (from the workdir) or an explicit "
                                  "pattern-only choice")
    pol = _policy.for_profile(profile)
    staging = common.guard_dir(staging, "staging folder")
    out = common.guard_dir(out, "public tree")
    if not staging.is_dir():
        raise common.WriteupError(f"staging folder {staging} does not exist (run `ctf writeup draft` first)")
    now = now or _dt.datetime.now(_dt.timezone.utc)
    scanner = _scan.Scanner(profile, known=known, allow=read_allow(staging), known_hashes=known_hashes)
    plan = Plan(event=profile.slug, staging=staging, out=out, public_repo=pol.public_repo, redacted=pol.redact,
                known_values=len(scanner.known), known_source=known_source,
                known_hashes=len(scanner.known_hashes))

    sources = []
    for src in sorted(p for p in staging.rglob("*") if p.is_file() or p.is_symlink()):
        rel = src.relative_to(staging)
        if src.is_symlink():
            plan.excluded.append({"path": rel.as_posix(), "reason": "symlink"})
            continue
        why = _exclusion(rel, src.stat().st_size)
        if why:
            plan.excluded.append({"path": rel.as_posix(), "reason": why})
            continue
        try:
            text = src.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            plan.excluded.append({"path": rel.as_posix(), "reason": "not UTF-8 text"})
            continue
        sources.append((rel, text))

    # Harvest every Flag section and every hashed value first, so a value written (or resolved) in one
    # file is redacted in all of them, even where it is embedded in a longer token.
    if pol.redact:
        for _, text in sources:
            scanner.add_known(scanner.harvest_flag_sections(text))
            scanner.resolve_hashes(text)
    plan.known_values = len(scanner.known)
    plan.short_known = len(scanner.short_known)

    _prepare_out(out, staging)
    for rel, text in sources:
        body, unclosed = _scan.strip_private(text)
        n = 0
        if pol.redact:
            body, n = scanner.redact(body)
        found = scanner.scan(body, rel.as_posix())
        found += _passes.pass_findings(body, rel.as_posix(), publish=True, models=profile.models)   # B-097
        if unclosed:
            found.insert(0, _scan.Finding("unclosed-private", 0, "<!-- private --> without <!-- /private -->",
                                          True, rel.as_posix()))
        plan.findings.extend(found)
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(body, encoding="utf-8")
        plan.files.append({"path": rel.as_posix(), "bytes": len(body.encode("utf-8")),
                           "sha256": common.sha256_text(body), "redactions": n, "title": _title(body)})

    if not (staging / "README.md").is_file() and plan.files:
        idx = _index(profile, plan.files)
        plan.findings.extend(scanner.scan(idx, "README.md"))
        (out / "README.md").write_text(idx, encoding="utf-8")
        plan.files.append({"path": "README.md", "bytes": len(idx.encode("utf-8")),
                           "sha256": common.sha256_text(idx), "redactions": 0, "title": _title(idx)})

    plan.gates = pol.publish_gates(now=now, files=len(plan.files), blocking=len(plan.blocking))
    return plan


def check(profile: _event.EventProfile, targets: list[Path], *, known: set[str],
          known_hashes: set[str] = frozenset()) -> tuple[list[_scan.Finding], list[dict]]:
    """Scan files as publish would emit them (private blocks stripped, redacted when the event
    redacts) without writing anything. A folder is walked with the publish allowlist; a file named
    directly is always scanned. Returns (findings, excluded)."""
    pol = _policy.for_profile(profile)
    allow: list[str] = []
    picked: list[tuple[str, Path]] = []
    excluded: list[dict] = []
    for t in targets:
        t = Path(t)
        if t.is_dir():
            allow += read_allow(t)
            for src in sorted(p for p in t.rglob("*") if p.is_file()):
                rel = src.relative_to(t)
                why = "symlink" if src.is_symlink() else _exclusion(rel, src.stat().st_size)
                if why:
                    excluded.append({"path": str(src), "reason": why})
                else:
                    picked.append((str(src), src))
        elif t.is_file():
            picked.append((str(t), t))
        else:
            raise common.WriteupError(f"nothing to check at {t}")
    scanner = _scan.Scanner(profile, known=known, allow=allow, known_hashes=known_hashes)
    texts = []
    for name, src in picked:
        try:
            texts.append((name, src.read_bytes().decode("utf-8")))
        except UnicodeDecodeError:
            excluded.append({"path": name, "reason": "not UTF-8 text"})
    if pol.redact:
        for _, text in texts:
            scanner.add_known(scanner.harvest_flag_sections(text))
    findings: list[_scan.Finding] = []
    for name, text in texts:
        body, unclosed = _scan.strip_private(text)
        if pol.redact:
            body, _ = scanner.redact(body)
        if unclosed:
            findings.append(_scan.Finding("unclosed-private", 0, "<!-- private --> without <!-- /private -->",
                                          True, name))
        findings.extend(scanner.scan(body, name))
        findings.extend(_passes.pass_findings(body, name, publish=False, models=profile.models))   # B-097
    return findings, excluded


def write_plan(plan: Plan, path: Path) -> Path:
    """Write the plan JSON. Like the trees, it lives outside the checkout (or under writeups/) and
    never inside the public tree."""
    path = common.guard_dir(path, "plan file")
    if path == plan.out or plan.out in path.parents:
        raise common.WriteupError(f"the plan file {path} must not be inside the public tree")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan.to_dict(), indent=1) + "\n", encoding="utf-8")
    return path


def default_plan_path(out: Path) -> Path:
    return out.parent / f"{out.name}.publish-plan.json"
