#!/usr/bin/env python3
"""B-001 step 1: import the master tree from the merge plan.

Reads the per-file merge decisions (analysis/out/reports/diffs/*.merge.json, read-only) and the
source repos (2026-ctf-csctf, -huntress, -pink, -spooky under --sources-dir, default the home folder;
read-only), then copies the planned files into this repo and writes the migration reports under
docs/migration/.

Deterministic and re-runnable: the plan depends only on the inputs; every output is sorted; a run
removes files a previous run imported (docs/migration/import-manifest.json) that the new plan no
longer contains, and rewrites a file only when its bytes differ.

    python tools/migrate/import_master.py --dry-run     # print the plan summary, write nothing
    python tools/migrate/import_master.py               # import and write the reports

Policy (BUILD-PLAN.md, B-001; the task brief for step 1):
  * identical files and CSCTF-only files with no decision: CSCTF copy
  * take_csctf / take_huntress: that side; keep_both: per its reason (table KEEP_BOTH); drop: skipped;
    archive: not imported, listed in ARCHIVED.md; hand_merge: start side named by its reason
    (CSCTF when unclear), imported, queued
  * Huntress-only files with no decision: code under solvers/, tools/, ctf/ is imported and flagged;
    everything else is listed in NOT-IMPORTED.md
  * Pink differences only where the live-deltas file or the reports say so (table PINK_START)
  * live deltas: must-merge queued; event-specific and discard listed
  * never imported: see NEVER_* below; agent config goes to events/<event>/legacy-agent-config/
    under names Claude Code and Codex do not auto-load (dot-claude/, CLAUDE.legacy.md, ...)

Fails loudly (exit 2) when an input is missing or a decision names a file no source has.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

HOME = Path.home()
REPO = Path(__file__).resolve().parents[2]
DIFFS = REPO / "analysis/out/reports/diffs"
MANIFEST = REPO / "analysis/out/workplan/diff_manifest.json"
# The four source repos (read-only), by folder name under one parent folder: --sources-dir, default the
# home folder (where the 2026 events kept them). main() rebinds SOURCES in place from the flag.
SOURCE_NAMES = {"csctf": "2026-ctf-csctf", "huntress": "2026-ctf-huntress", "pink": "2026-ctf-pink",
                "spooky": "2026-ctf-spooky"}


def source_roots(parent: Path) -> dict[str, Path]:
    return {event: Path(parent).expanduser() / name for event, name in SOURCE_NAMES.items()}


SOURCES = source_roots(HOME)
MIG = "docs/migration"
STATE = f"{MIG}/import-manifest.json"
MAX_BYTES = 10 * 1024 * 1024

# Paths in this repo the import never writes or deletes.
PROTECTED = (".git/", ".githooks/", ".gitignore", "BUILD-PLAN.md", "analysis/", ".venv/", "writeups/",
             "CLAUDE.md", "AGENTS.md", "docs/CONTRACTS.md", f"{MIG}/BASELINE.md", "tools/migrate/",
             "tests/test_import_master.py")

# --- never import -------------------------------------------------------------------------------
NEVER_DIRS = {".venv", "__pycache__", ".ctf", "challenges", "workspace", "logs", "chronos-logs",
              "scratchpad", "Claude outputs", ".pytest_cache", ".git", ".wrangler", "_realdata"}
NEVER_DIR_PREFIX = ("writeups",)            # writeups/, writeups-public/, ...
NEVER_PATH_PREFIX = ("docs/writeups/",)
# Real challenge deliveries the source trees used as test fixtures; the master builds them synthetically (R-04).
NEVER_REAL_CHALLENGE_PREFIX = ("tests/fixtures/day27_mobile_splits/",)
SECRET_NAMES = {"token", "cookie", "cookies", "cookie.txt", "cookies.txt", "auth.json", ".env", ".netrc",
                ".huntress_gm", ".huntress_gm_token", ".huntress_gm.curl", "settings.local.json"}
SECRET_SUFFIX = (".token", ".env", ".ovpn", ".cookie", ".cookies")
JUNK_NAMES = {".DS_Store"}
JUNK_SUFFIX = (".pyc",)
# Event-specific root files: reported, not imported.
EVENT_ROOT_FILES = {"blackout.py", "builder9.py", "builder9b.py", "ask-the-organizer.md", "mast.err",
                    "SPOOKY.md"}
EVENT_ROOT_GLOBS = ("builder9*.py", "codex_result*")

# --- agent config -------------------------------------------------------------------------------
AGENT_EVENTS = ("csctf", "huntress")


def agent_target(event: str, rel: str) -> str | None:
    """Master path for an event's agent-config file, or None if rel is not agent config."""
    base = f"events/{event}/legacy-agent-config/"
    if rel.startswith(".claude/"):
        return base + "dot-claude/" + rel[len(".claude/"):]
    if rel.startswith(".codex/"):
        return base + "dot-codex/" + rel[len(".codex/"):]
    if rel in ("CLAUDE.md", "AGENTS.md"):
        return base + rel[:-3] + ".legacy.md"
    return None


def is_agent_config(rel: str) -> bool:
    return rel.startswith((".claude/", ".codex/")) or rel in ("CLAUDE.md", "AGENTS.md")


# --- per-file decisions the generic rules cannot express -----------------------------------------
# keep_both: (side, master path) pairs to import; the other side is archived.
KEEP_BOTH = {
    "tests/test_contract.py": [("csctf", "tests/test_payload_contract.py")],
    "tests/test_verify.py": [("csctf", "tests/test_pwn_verify.py")],
    ".claude/rules/tools.md": [("csctf", None)],      # None: the agent-config target
    "solvers/web/__init__.py": [("huntress", "solvers/web/__init__.py")],
    "solvers/web/research_wp_cookie_diff.py": [("csctf", "solvers/web/research_wp_cookie_diff.py")],
}
# Pink: where the live-deltas file or the reports pick Pink as the start side.
PINK_START = {"ctf/submit.py"}
# Pink-only files and where they go (both are hand_merge in infra-tools-ctf-claude.merge.json).
PINK_ONLY_TARGET = {
    "tools/pink_launch.sh": "tools/pink_launch.sh",
    # live-deltas calls the prompt event-specific; the infra plan hand-merges it into a per-event
    # template. It goes to the Pink legacy agent config, not tools/, for B-189 to template from.
    "tools/pink_wave_prompt.md": "events/pink/legacy-agent-config/pink_wave_prompt.md",
}
# hand_merge start side when the reason names one; checked in order.
START_RULES = [
    (re.compile(r"take pink'?s version", re.I), "pink"),
    (re.compile(r"base on huntress|keep huntress'?s file", re.I), "huntress"),
]


# Event-specific top-level directories: reported, not imported (CSCTF's scoreboard dashboard carries
# the platform host and a teammates list; Huntress's is a separate nested repo).
EVENT_TOP_DIRS = {"dashboard"}

# --- commit-guard pass (.githooks/secret_scan.py) ------------------------------------------------
# Denylisted values found in imported text are replaced everywhere, keyed by the 8-char sha256 prefix
# the guard prints. The plaintext is discovered at run time from the denylist; this file never holds it.
# An unknown denylisted value fails the import loudly.
DENY_REPLACE = {
    "d41ff86f": {"what": "CSCTF config key name (submit pacing)", "to": "submit_interval_min_s"},
    "722c4cb6": {"what": "CSCTF config key name (wrong-answer cap)", "to": "submit_wrong_limit"},
    "d2774d18": {"what": "CSCTF platform domain label", "to": "ctf-platform", "tld": ("ro", "example")},
}
# Values of a pragma-able token shape (guard CONTENT_RULES with pragma allowed) count as known-fake
# when they carry one of these markers; the line then gets the guard's own pragma. Any other value
# keeps its file out of the import.
FAKE_MARKERS = ("EXAMPLE", "ABCD", "TEST", "FAKE", "DUMMY", "SAMPLE")
# Lines where the value sits inside a string literal: the comment syntax of the embedded language.
PRAGMA_STYLE_OVERRIDE = {
    "tests/test_container_iac.py": "#",              # HCL inside a bytes literal
    "tests/test_wave3_web_recon.py": "//",           # JavaScript inside a str literal
    "tests/test_web_endpoint_inventory.py": "//",    # JavaScript inside a bytes literal
    "tests/fixtures/tk_cloud_container/terraform.tfstate": "json-key",
}


def load_guard():
    spec_path = REPO / ".githooks/secret_scan.py"
    if not spec_path.is_file():
        die(f"commit guard missing at {spec_path}")
    import importlib.util
    spec = importlib.util.spec_from_file_location("secret_scan", spec_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_denylist() -> set[str]:
    env = os.environ.get("CTF_DENYLIST")
    path = Path(env).expanduser() if env and env != "none" else HOME / ".config/ctf-tools/denylist.sha256"
    if env == "none" or not path.is_file():
        die(f"denylist not found at {path} (CTF_DENYLIST={env!r}); the import refuses to run without "
            "it because its output must pass the commit guard")
    return {ln.strip() for ln in path.read_text().splitlines() if ln.strip() and not ln.startswith("#")}


class Redactor:
    """Replace denylisted values (discovered by hash) consistently across bytes and report text."""

    def __init__(self, guard, deny: set[str]):
        self.guard, self.deny = guard, deny
        self.values: dict[str, bytes] = {}           # prefix -> plaintext (in memory only)
        self.hits: defaultdict[str, set[str]] = defaultdict(set)   # prefix -> master paths

    def discover(self, master: str, data: bytes) -> None:
        for rx in self.guard.CANDIDATE_PATTERNS:
            for m in rx.finditer(data):
                h = hashlib.sha256(m.group(0)).hexdigest()
                if h not in self.deny:
                    continue
                pfx = h[:8]
                if pfx not in DENY_REPLACE:
                    raise ImportError_(f"denylisted value [sha256:{pfx}] in {master} has no replacement rule")
                if b"\0" in data:
                    raise ImportError_(f"denylisted value [sha256:{pfx}] in binary file {master}")
                self.values[pfx] = m.group(0)

    def apply(self, master: str, data: bytes) -> bytes:
        if b"\0" in data:
            return data
        out = data
        for pfx in sorted(self.values, key=lambda p: -len(self.values[p])):
            v, rule = self.values[pfx], DENY_REPLACE[pfx]
            if v not in out:
                continue
            self.hits[pfx].add(master)
            if "tld" in rule:
                old, new = (t.encode() for t in rule["tld"])
                sep = rb"(\.|\xe3\x80\x82|%2[Ee]|%252[Ee])"
                out = re.sub(re.escape(v) + sep + re.escape(old) + rb"\b",
                             lambda m: rule["to"].encode() + m.group(1) + new, out)
            out = out.replace(v, rule["to"].encode())
        return out

    def text(self, s: str) -> str:
        return self.apply("<report>", s.encode()).decode()


def _line_end_in_string(src: bytes, line_no: int) -> bool:
    """True when the end of physical line line_no (1-based) lies inside a Python string token."""
    import io
    import tokenize
    fstart = getattr(tokenize, "FSTRING_START", -1)
    fend = getattr(tokenize, "FSTRING_END", -1)
    open_f: list[int] = []
    try:
        for tok in tokenize.tokenize(io.BytesIO(src).readline):
            if tok.type == tokenize.STRING and tok.start[0] <= line_no < tok.end[0]:
                return True
            if tok.type == fstart:
                open_f.append(tok.start[0])
            elif tok.type == fend and open_f:
                if open_f.pop() <= line_no < tok.end[0]:
                    return True
    except (tokenize.TokenError, SyntaxError) as e:
        raise ImportError_(f"cannot tokenize for pragma placement: {e}")
    return False


def add_pragmas(master: str, data: bytes, guard) -> tuple[bytes | None, list[str]]:
    """Mark known-fake token-shaped values with the guard pragma. Returns (new data or None to drop
    the file, notes)."""
    pragma_rules = [(rx, rule) for rx, rule, ok in guard.CONTENT_RULES if ok]
    lines = data.split(b"\n")
    todo: dict[int, str] = {}
    for rx, rule in pragma_rules:
        for m in rx.finditer(data):
            ln = data.count(b"\n", 0, m.start())
            if guard.PRAGMA in lines[ln]:
                continue
            body = m.group(0).decode("ascii", "replace")
            if not any(k in body[4:] for k in FAKE_MARKERS):
                return None, [f"{rule}: value without a known-fake marker"]
            todo[ln] = rule
    if not todo:
        return data, []
    style = PRAGMA_STYLE_OVERRIDE.get(master)
    notes = []
    for ln in sorted(todo):
        if master.endswith(".py"):
            # Python code takes '#'; a line ending inside a string literal takes the embedded
            # language's comment, which must be named in PRAGMA_STYLE_OVERRIDE.
            if _line_end_in_string(data, ln + 1):
                if style is None:
                    raise ImportError_(f"{master}:{ln + 1} value inside a multi-line string; add a style override")
                st = style
            else:
                st = "#"
        elif style is None:
            raise ImportError_(f"{master}:{ln + 1} needs a pragma but has no comment style")
        else:
            st = style
        if st == "json-key":
            line = lines[ln].rstrip()
            if not line.endswith(b","):
                raise ImportError_(f"{master}:{ln + 1} json-key pragma needs a trailing comma")
            lines[ln] = line + b' "_secret_scan": "secret-scan: allow",'
        else:
            lines[ln] = lines[ln].rstrip() + b"  " + st.encode() + b" " + guard.PRAGMA
        notes.append(f"line {ln + 1}: {todo[ln]} (known-fake) marked with `{st}` pragma")
    return b"\n".join(lines), notes


class ImportError_(Exception):
    pass


def die(msg: str) -> None:
    print(f"import_master: ERROR: {msg}", file=sys.stderr)
    sys.exit(2)


# --- source enumeration --------------------------------------------------------------------------
def git_list(repo: Path, *args: str) -> list[str]:
    out = subprocess.run(["git", "--no-optional-locks", "-C", str(repo), "ls-files", "-z", *args],
                         capture_output=True, check=True).stdout
    return sorted(p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p)


def enumerate_repo(name: str) -> dict[str, Path]:
    """Tracked plus untracked-not-ignored files of a source repo, read from the working tree."""
    repo = SOURCES[name]
    if not (repo / ".git").exists():
        die(f"source repo {repo} is not a git checkout")
    rels = set(git_list(repo)) | set(git_list(repo, "-o", "--exclude-standard"))
    return {r: repo / r for r in sorted(rels) if (repo / r).is_file() or (repo / r).is_symlink()}


def file_bytes(p: Path) -> bytes:
    return p.read_bytes()


def same(a: Path, b: Path) -> bool:
    if a.stat().st_size != b.stat().st_size:
        return False
    return a.read_bytes() == b.read_bytes()


# --- decisions -----------------------------------------------------------------------------------
class Decision:
    def __init__(self, group: str, path: str, action: str, reason: str, note: str | None):
        self.group, self.path, self.action, self.reason, self.note = group, path, action, reason, note
        self.patterns = expand_pattern(path)
        self.exact = self.patterns is None

    def text(self) -> str:
        return self.reason + (f" Verifier note: {self.note}" if self.note else "")

    def matches(self, rel: str) -> bool:
        if self.exact:
            return rel == self.path
        return any((rel.startswith(p) if p.endswith("/") else fnmatch.fnmatchcase(rel, p))
                   for p in self.patterns)

    def specificity(self) -> int:
        return max(len(re.split(r"[*?{]", p)[0]) for p in (self.patterns or [self.path]))


def expand_pattern(path: str) -> list[str] | None:
    """None for an exact file path, else the list of prefix ('dir/') or fnmatch patterns."""
    p = re.sub(r"\s*\(.*\)\s*$", "", path).strip()       # drop '(49 Huntress day one-offs)'
    if p.endswith("/"):
        return [p]
    m = re.match(r"^(.*/)\{(.*)\}$", p)                   # dir/{a,b*,c}
    if m:
        head, alts = m.group(1), [a.strip() for a in m.group(2).split(",")]
    elif "," in p:                                       # dir/a*,b*,c*
        head = p[: p.rfind("/", 0, p.find(",")) + 1]
        alts = [a.strip() for a in p[len(head):].split(",")]
    else:
        head, alts = None, None
    if alts is not None:
        # an alternative names a module stem or a glob; match it bare and with .py
        return sorted({head + a for a in alts} | {head + a + ".py" for a in alts if not a.endswith(".py")})
    if any(c in p for c in "*?["):
        return [p]
    return None


def load_decisions() -> tuple[list[Decision], list[dict]]:
    if not DIFFS.is_dir():
        die(f"merge decisions not found at {DIFFS}")
    decisions, live = [], []
    for f in sorted(DIFFS.glob("*.merge.json")):
        data = json.loads(f.read_text())
        group = f.name[: -len(".merge.json")]
        if group == "live-deltas":
            for e in data:
                repo_dir, _, rest = e["path"].partition("/")
                event = repo_dir.replace("2026-ctf-", "")
                if event not in SOURCES:
                    die(f"live delta names unknown repo folder {repo_dir!r}")
                live.append({"event": event, "path": rest, "action": e["action"], "reason": e["reason"]})
            continue
        for e in data:
            decisions.append(Decision(group, e["path"], e["action"], e["reason"], e.get("verifier_note")))
    return decisions, live


# --- planning ------------------------------------------------------------------------------------
class Plan:
    def __init__(self):
        self.files: dict[str, tuple[str, str, Path]] = {}   # master -> (side, src rel, src abs)
        self.why: dict[str, str] = {}                      # master -> rule label
        self.archived: list[tuple[str, str, str, str, str]] = []  # (side, rel, group, reason, decision path)
        self.dropped: list[tuple[str, str, str, str, str]] = []
        self.excluded: defaultdict[str, list[tuple[str, str]]] = defaultdict(list)  # rule -> (side, rel)
        self.not_imported: list[tuple[str, str, str]] = []  # (side, rel, why)
        self.flag_h_only: list[str] = []
        self.flag_modified_nodecision: list[str] = []
        self.queue: dict[str, dict] = {}
        self.live_skipped: list[dict] = []
        self.notes: list[str] = []
        self.unmatched_decisions: list[Decision] = []
        self.content: dict[str, bytes] = {}                 # master -> bytes when the guard pass changed them
        self.guard_notes: list[str] = []
        self.redact = lambda s: s
        self.guard_scan = lambda path, text: []

    def add(self, master: str, side: str, rel: str, src: Path, why: str):
        if any(master == p.rstrip("/") or master.startswith(p) for p in PROTECTED if p.endswith("/")) \
                or master in PROTECTED:
            raise ImportError_(f"plan targets protected path {master}")
        if master in self.files and self.files[master][2] != src:
            prev = self.files[master]
            if not same(prev[2], src):
                raise ImportError_(f"two sources for {master}: {prev[0]}:{prev[1]} and {side}:{rel}")
        self.files[master] = (side, rel, src)
        self.why[master] = why

    def enqueue(self, master: str, *, side: str | None, rel: str | None, reason: str, origin: str,
                imported: bool, sources: dict[str, str] | None = None, live: bool = False, note: str = ""):
        q = self.queue.setdefault(master, {"master_path": master, "start_side": side, "imported": imported,
                                           "sources": {}, "reasons": [], "live_delta": False, "notes": []})
        if side and not q["start_side"]:
            q["start_side"] = side
        q["imported"] = q["imported"] or imported
        for k, v in (sources or {}).items():
            q["sources"].setdefault(k, v)
        if side and rel:
            q["sources"].setdefault(side, f"~/{SOURCES[side].name}/{rel}")
        q["reasons"].append(f"[{origin}] {reason}")
        q["live_delta"] = q["live_delta"] or live
        if note:
            q["notes"].append(note)


def never_rule(rel: str, src: Path | None) -> str | None:
    parts = rel.split("/")
    if rel.startswith(NEVER_PATH_PREFIX):
        return "never-import docs/writeups/"
    if rel.startswith(NEVER_REAL_CHALLENGE_PREFIX):
        return "never-import real challenge files (synthetic in the master, R-04)"
    for d in parts[:-1]:
        if d in NEVER_DIRS:
            return f"never-import dir {d}/"
        if d.startswith(NEVER_DIR_PREFIX):
            return "never-import writeups*/"
    name = parts[-1]
    if rel == ".gitignore":
        return "source root .gitignore (master keeps its own)"
    if name in JUNK_NAMES or name.endswith(JUNK_SUFFIX):
        return "junk (.DS_Store/.pyc)"
    if name in SECRET_NAMES or name.endswith(SECRET_SUFFIX) or name.startswith(".env"):
        return "credential-shaped file name"
    if len(parts) > 1 and parts[0] in EVENT_TOP_DIRS:
        return f"event-specific {parts[0]}/"
    if len(parts) == 1 and (name in EVENT_ROOT_FILES or any(fnmatch.fnmatch(name, g) for g in EVENT_ROOT_GLOBS)):
        return "event-specific root file"
    if src is not None and src.is_symlink():
        return "symlink"
    if src is not None and src.stat().st_size > MAX_BYTES:
        return "file over 10 MB"
    return None


def start_side(reason: str, have: dict[str, Path]) -> str:
    sides = [s for s in ("csctf", "huntress", "pink") if s in have]
    if len(sides) == 1:
        return sides[0]
    for rx, side in START_RULES:
        if rx.search(reason) and side in have:
            return side
    return "csctf" if "csctf" in have else sides[0]


def build_plan() -> tuple[Plan, dict]:
    for name, path in SOURCES.items():
        if not path.is_dir():
            die(f"source {name} missing at {path}")
    if not MANIFEST.is_file():
        die(f"diff manifest missing at {MANIFEST}")
    decisions, live = load_decisions()
    exact = {d.path: d for d in decisions if d.exact}
    patterns = sorted((d for d in decisions if not d.exact), key=lambda d: -d.specificity())
    C, H, P = (enumerate_repo(s) for s in ("csctf", "huntress", "pink"))
    plan = Plan()
    used: set[int] = set()
    stats = Counter()

    def decision_for(rel: str, in_c: bool, in_h: bool, modified: bool) -> Decision | None:
        d = exact.get(rel)
        if d:
            used.add(id(d))
            return d
        if in_c and in_h and not modified:
            return None                      # identical files take CSCTF; patterns name one side's set
        for d in patterns:
            if not d.matches(rel):
                continue
            a = d.action
            if a in ("take_csctf", "keep_both") and not in_c:
                continue
            if a == "take_huntress" and not (in_h and (not in_c or modified)):
                continue
            if a in ("archive", "drop", "hand_merge") and in_c and in_h:
                continue
            used.add(id(d))
            return d
        return None

    # ---- agent config (csctf, huntress): legacy copies, decisions still honoured
    for side, files in (("csctf", C), ("huntress", H)):
        for rel, src in files.items():
            if not is_agent_config(rel):
                continue
            rule = never_rule(rel, src)
            if rule:
                plan.excluded[rule].append((side, rel))
                continue
            in_c, in_h = rel in C, rel in H
            modified = in_c and in_h and not same(C[rel], H[rel])
            d = decision_for(rel, in_c, in_h, modified)
            target = agent_target(side, rel)
            if d and d.action == "keep_both":
                keep_sides = [s for s, _ in KEEP_BOTH.get(rel, [])]
                if side not in keep_sides:
                    plan.archived.append((side, rel, d.group, d.text(), d.path))
                    continue
            elif d and d.action in ("archive", "drop") and (side == "huntress" or not in_h):
                (plan.archived if d.action == "archive" else plan.dropped).append((side, rel, d.group, d.text(), d.path))
                continue
            elif d and d.action == "take_huntress" and side == "csctf":
                pass                                 # each event keeps its own legacy copy
            plan.add(target, side, rel, src, "agent-config (legacy, not auto-loaded)")
            stats[f"agent-config:{side}"] += 1
            present = {s: f[rel] for s, f in (("csctf", C), ("huntress", H)) if rel in f}
            if d and d.action == "hand_merge" and side == start_side(d.text(), present):
                plan.enqueue(target, side=side, rel=rel, reason=d.text(), origin=d.group, imported=True,
                             note="agent config: lands in events/<event>/legacy-agent-config for B-189 to template")

    # ---- everything else, by master path
    all_rels = sorted((set(C) | set(H) | set(P)) - {r for r in set(C) | set(H) | set(P) if is_agent_config(r)})
    for rel in all_rels:
        in_c, in_h, in_p = rel in C, rel in H, rel in P
        have = {s: f[rel] for s, f in (("csctf", C), ("huntress", H), ("pink", P)) if rel in f}
        rule = None
        for s, src in have.items():
            rule = never_rule(rel, src)
            if rule:
                break
        if rule:
            for s in have:
                plan.excluded[rule].append((s, rel))
            continue
        modified = in_c and in_h and not same(C[rel], H[rel])
        pink_diff = in_c and in_p and not same(C[rel], P[rel])
        d = decision_for(rel, in_c, in_h, modified)

        # Pink-only files
        if in_p and not in_c and not in_h:
            if rel in PINK_ONLY_TARGET:
                if d is None:
                    raise ImportError_(f"pink-only {rel} has no decision")
                tgt = PINK_ONLY_TARGET[rel]
                plan.add(tgt, "pink", rel, P[rel], f"{d.action} (pink only)")
                if d.action == "hand_merge":
                    plan.enqueue(tgt, side="pink", rel=rel, reason=d.text(), origin=d.group, imported=True)
                stats["pink-only"] += 1
            else:
                plan.not_imported.append(("pink", rel, "pink-only with no import decision"))
            continue

        if d is None:
            if in_c:
                why = "identical in CSCTF and Huntress" if in_h and not modified else (
                    "CSCTF-only, no decision" if not in_h else "differs from Huntress, no decision: CSCTF")
                if modified:
                    plan.flag_modified_nodecision.append(rel)
                plan.add(rel, "csctf", rel, C[rel], why)
                stats["csctf:" + ("identical" if in_h and not modified else "only" if not in_h else "modified")] += 1
            elif in_h:
                if rel.split("/")[0] in ("solvers", "tools", "ctf"):
                    plan.add(rel, "huntress", rel, H[rel], "Huntress-only code, no decision (flagged)")
                    plan.flag_h_only.append(rel)
                    stats["huntress:only-code-nodecision"] += 1
                else:
                    plan.not_imported.append(("huntress", rel, "Huntress-only, not code under solvers/tools/ctf"))
            if pink_diff and rel not in PINK_START:
                plan.notes.append(f"Pink differs on {rel}; CSCTF kept (reports name CSCTF newer)")
            continue

        a = d.action
        if a == "take_csctf":
            if not in_c:
                raise ImportError_(f"take_csctf {rel}: CSCTF has no such file")
            plan.add(rel, "csctf", rel, C[rel], "take_csctf")
            stats["take_csctf"] += 1
        elif a == "take_huntress":
            if not in_h:
                raise ImportError_(f"take_huntress {rel}: Huntress has no such file")
            plan.add(rel, "huntress", rel, H[rel], "take_huntress")
            stats["take_huntress"] += 1
        elif a == "keep_both":
            if rel in KEEP_BOTH:
                for side, tgt in KEEP_BOTH[rel]:
                    src = have.get(side)
                    if src is None:
                        raise ImportError_(f"keep_both {rel}: {side} has no such file")
                    plan.add(tgt, side, rel, src, f"keep_both ({side} copy)")
                for side in have:
                    if side not in [s for s, _ in KEEP_BOTH[rel]] and side != "pink":
                        plan.archived.append((side, rel, d.group, d.text(), d.path))
            elif len([s for s in have if s != "pink"]) == 1 or (in_c and not modified):
                side = "csctf" if in_c else "huntress"
                plan.add(rel, side, rel, have[side], f"keep_both ({side} copy)")
            else:
                raise ImportError_(f"keep_both {rel}: two differing sides and no KEEP_BOTH rule")
            stats["keep_both"] += 1
        elif a == "drop":
            for side in [s for s in have if s != "pink"]:
                plan.dropped.append((side, rel, d.group, d.text(), d.path))
            stats["drop"] += 1
        elif a == "archive":
            for side in [s for s in have if s != "pink"]:
                plan.archived.append((side, rel, d.group, d.text(), d.path))
            stats["archive"] += 1
        elif a == "hand_merge":
            side = "pink" if (rel in PINK_START and in_p) else start_side(d.text(), {s: v for s, v in have.items() if s != "pink" or rel in PINK_START})
            plan.add(rel, side, rel, have[side], f"hand_merge (start: {side})")
            srcs = {s: f"~/{SOURCES[s].name}/{rel}" for s in have if s != "pink" or pink_diff}
            plan.enqueue(rel, side=side, rel=rel, reason=d.text(), origin=d.group, imported=True, sources=srcs)
            stats["hand_merge"] += 1
        else:
            raise ImportError_(f"unknown action {a!r} for {rel}")
        if pink_diff and rel not in PINK_START and a != "hand_merge":
            plan.notes.append(f"Pink differs on {rel}; {a} keeps the {'CSCTF' if a != 'take_huntress' else 'Huntress'} copy")

    # ---- decisions that matched no enumerated file (gitignored, untracked-excluded, or dirs)
    for d in decisions:
        if id(d) in used:
            continue
        ondisk = {s: SOURCES[s] / d.path for s in ("csctf", "huntress") if (SOURCES[s] / d.path).exists()}
        if d.action in ("archive", "drop"):
            side = next(iter(ondisk), "huntress")
            (plan.archived if d.action == "archive" else plan.dropped).append((side, d.path, d.group, d.text(), d.path))
        elif d.action == "hand_merge" and d.path.startswith(NEVER_PATH_PREFIX):
            plan.enqueue(d.path, side="csctf", rel=d.path, reason=d.text(), origin=d.group, imported=False,
                         note="source sits under docs/writeups/ (never-import path): port the generic part "
                              "into the master writeup pipeline (B-098); do not copy the folder")
        elif d.path.startswith(NEVER_PATH_PREFIX):
            plan.excluded["never-import docs/writeups/ (decision " + d.action + ")"].append(("csctf", d.path))
        else:
            plan.unmatched_decisions.append(d)

    # ---- live deltas
    for e in live:
        if e["action"] == "must-merge":
            rel, ev = e["path"], e["event"]
            master = rel
            if is_agent_config(rel):
                # Pink's agent config is CSCTF's fork: its deltas land on the CSCTF legacy copy
                master = agent_target("csctf" if ev == "pink" else ev, rel)
            elif ev == "pink" and rel in PINK_ONLY_TARGET:
                master = PINK_ONLY_TARGET[rel]
            imported = master in plan.files
            note = ""
            if ev == "spooky":
                note = "Spooky agent config is not imported (its own folder, symlinked engines); read it from the source"
            if rel == ".gitignore":
                master = ".gitignore"
                imported = False
                note = ("master .gitignore already ignores logs/ at any depth; check and close, "
                        "the import does not rewrite .gitignore")
            plan.enqueue(master, side=None, rel=None, reason=e["reason"], origin=f"live-deltas:{ev}",
                         imported=imported, sources={ev: f"~/{SOURCES[ev].name}/{rel}"}, live=True, note=note)
        else:
            plan.live_skipped.append(e)

    for m, q in plan.queue.items():
        if not q["start_side"]:
            q["start_side"] = plan.files[m][0] if m in plan.files else next(iter(q["sources"]), None)

    guard_pass(plan)

    return plan, {"stats": stats, "C": len(C), "H": len(H), "P": len(P), "decisions": len(decisions),
                  "live": len(live)}


def guard_pass(plan: "Plan") -> None:
    """Make the planned tree pass the commit guard: redact denylisted values, mark known-fake
    token-shaped fixture values with the guard pragma, drop files holding real-looking ones, then
    re-scan every planned file with the guard itself and fail on any remaining block."""
    guard = load_guard()
    deny = load_denylist()
    red = Redactor(guard, deny)
    raw = {m: src.read_bytes() for m, (_, _, src) in plan.files.items()}
    for m in sorted(raw):
        red.discover(m, raw[m])
    for m in sorted(raw):
        data = red.apply(m, raw[m])
        if b"\0" not in data:
            new, notes = add_pragmas(m, data, guard)
            if new is None:
                side, rel, _ = plan.files.pop(m)
                plan.why.pop(m, None)
                plan.excluded["credential-shaped value without a known-fake marker"].append((side, rel))
                plan.guard_notes.append(f"`{m}`: left out ({notes[0]})")
                if m in plan.queue:
                    plan.queue[m]["imported"] = False
                    plan.queue[m]["notes"].append("left out of the tree by the commit-guard pass")
                continue
            for n in notes:
                plan.guard_notes.append(f"`{m}` {n}")
            data = new
        if data != raw[m]:
            plan.content[m] = data
    for pfx in sorted(red.hits):
        rule = DENY_REPLACE[pfx]
        for m in sorted(red.hits[pfx]):
            if m in plan.queue:
                plan.queue[m]["notes"].append(
                    f"guard pass replaced a denylisted value here ({rule['what']} -> `{rule['to']}`); the "
                    "source still has the old one, so diff with that in mind"
                    + ("" if "tld" in rule else ". An old event config using the old key name is now ignored "
                       "silently: make config loading reject unknown keys"))
        plan.guard_notes.append(f"denylisted value [sha256:{pfx}] ({rule['what']}) replaced by "
                                f"`{rule['to']}`" + (f" (TLD .{rule['tld'][0]} -> .{rule['tld'][1]})"
                                                     if 'tld' in rule else "")
                                + f" in {len(red.hits[pfx])} files: " + ", ".join(f"`{h}`" for h in sorted(red.hits[pfx])))
    for m in sorted(plan.files):
        data = plan.content.get(m, raw[m])
        blocks, _ = guard.scan(m, data, deny)
        if blocks:
            raise ImportError_(f"guard still blocks {m}: {sorted(set(blocks))}")
    plan.redact = red.text
    plan.guard_scan = lambda path, text: guard.scan(path, text.encode(), deny)[0]


# --- batching ------------------------------------------------------------------------------------
TEST_SUBSYSTEMS = [
    ("tests-web", ("web", "xxe", "ssrf", "proof", "graphql", "werkzeug")),
    ("tests-script", ("script", "stego_review", "carriers")),
    ("tests-mobile", ("mobile",)),
    ("tests-metadata", ("metadata", "real_cab", "review_a", "ese_reader", "fs_walk")),
    ("tests-binary-pwn-crypto", ("binary", "pwn", "crypto", "serial", "c_review", "flask_tools")),
    ("tests-huntress-adapt", ("adapt", "propose", "proposer", "ladder", "contract_job", "acceptance",
                              "next_components")),
    ("tests-platform-ctfd", ("submit", "instances")),
]


# Files that one agent should merge together (shared contract or one edit across them).
AFFINITY = {
    # live deltas
    "ctf/submit.py": "live-submit-guard", "tests/test_submit_guard.py": "live-submit-guard",
    "ctf/client.py": "live-submit-guard", "ctf/workspace.py": "live-submit-guard",
    "ctf/instances.py": "live-instances-wave", "tests/test_instances.py": "live-instances-wave",
    "ctf/cli.py": "live-instances-wave",
    "tools/codex_handoff.sh": "live-launch", "tools/pink_launch.sh": "live-launch", ".gitignore": "live-launch",
    # code
    "solvers/common/labels.py": "solvers-labels-selftests",
    "solvers/metadata-forensics/selftest.py": "solvers-labels-selftests",
    "solvers/mobile-android/selftest.py": "solvers-labels-selftests",
    "solvers/binary/binfmt.py": "solvers-lane-fixes", "solvers/script-analysis/lang_sh.py": "solvers-lane-fixes",
    "solvers/common/cloud_container.py": "solvers-lane-fixes",
    "tools/oob.py": "tools", "tools/target.py": "tools", "tools/vpn.py": "tools", "tools/run.py": "tools",
    "solvers/toolkits/web.py": "toolkits-web-core", "docs/toolkits/web.md": "toolkits-web-core",
    "solvers/toolkits/web_exploit.py": "toolkits-web-flagspec",
    "solvers/toolkits/web_xxe_ssrf.py": "toolkits-web-flagspec", "docs/toolkits/web_xxe_ssrf.md": "toolkits-web-flagspec",
    "speedrun/wire.py": "speedrun-client", "speedrun/common.py": "speedrun-client", "speedrun/corpus.py": "speedrun-client",
    "speedrun/solvers/binary_par.py": "speedrun-pools", "speedrun/solvers/script_pool.py": "speedrun-pools",
    "speedrun/solvers/script_worker.py": "speedrun-pools",
    "speedrun/solvers/binary_facts.py": "speedrun-parsers-b", "speedrun/solvers/mobile_jit.py": "speedrun-parsers-b",
    "speedrun/solvers/metadata_zip.py": "speedrun-parsers-b", "speedrun/solvers/metadata_d30.py": "speedrun-parsers-b",
    # tests the name heuristic would misfile
    "tests/test_day21r4_383.py": "tests-web",                     # depends on proof_hunt
    "tests/test_wave50_fields_d25_ordinal.py": "tests-binary-pwn-crypto",   # depends on fields_d25
}


def subsystem(path: str) -> str:
    if path in AFFINITY:
        return AFFINITY[path]
    name = path.rsplit("/", 1)[-1].lower()
    if path.startswith("speedrun/solvers/metadata_"):
        return "speedrun-parsers-a"
    if path.startswith("tests/"):
        for sub, keys in TEST_SUBSYSTEMS:
            if any(k in name for k in keys):
                return sub
        return "tests-misc"
    if path.startswith("ctf/") or path.startswith("tests/test_instances") or path == ".gitignore":
        return "ctf-platform"
    if path.startswith("events/"):
        return "agent-config"
    if path.startswith("tools/"):
        return "tools-net" if name in ("oob.py", "target.py", "vpn.py") else "tools-runner"
    if path.startswith(("solvers/toolkits/", "docs/toolkits/")):
        stem = name.rsplit(".", 1)[0]
        return "toolkits-targets" if stem in ("chat_target", "pwn_target", "readme") else "toolkits-web"
    if path.startswith("solvers/web/"):
        return "solvers-web"
    if path.startswith("speedrun/solvers/metadata"):
        return "speedrun-readers"
    if path.startswith("speedrun/"):
        return "speedrun-runtime"
    if path.startswith("docs/writeups/"):
        return "writeup-pipeline"
    if path.startswith("solvers/"):
        return "solvers-" + path.split("/")[1]
    return "misc"


def make_batches(queue: dict[str, dict]) -> list[dict]:
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for m, q in sorted(queue.items()):
        kind = "live-delta" if q["live_delta"] else ("test" if m.startswith("tests/") else "code")
        q["kind"], q["subsystem"] = kind, subsystem(m)
        sub = q["subsystem"]
        if kind == "live-delta" and not sub.startswith("live-"):
            sub = "live-agent-config" if m.startswith("events/") else "live-platform"
        q["subsystem"] = sub
        groups[(kind, sub)].append(m)
    cap = {"test": 10, "code": 4, "live-delta": 5}
    order = {"live-delta": 0, "code": 1, "test": 2}
    batches, n = [], 0
    for (kind, sub) in sorted(groups, key=lambda k: (order[k[0]], k[1])):
        paths = groups[(kind, sub)]
        for i in range(0, len(paths), cap[kind]):
            n += 1
            batches.append({"id": f"hm-{n:02d}", "kind": kind, "subsystem": sub, "files": paths[i:i + cap[kind]]})
    for b in batches:
        for m in b["files"]:
            queue[m]["batch"] = b["id"]
    return batches


# --- outputs -------------------------------------------------------------------------------------
def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


_TEXT_FILTER = {"redact": lambda s: s, "scan": lambda path, text: []}


def write_text(path: Path, text: str, dry: bool) -> None:
    """Write generated text after the guard redaction; refuse text the guard would still block."""
    text = _TEXT_FILTER["redact"](text)
    blocks = _TEXT_FILTER["scan"](str(path.relative_to(REPO)), text)
    if blocks:
        die(f"generated {path.relative_to(REPO)} would be blocked by the guard: {sorted(set(blocks))}")
    if dry:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.read_text() != text:
        path.write_text(text)


def apply(plan: Plan, dry: bool) -> dict:
    state_path = REPO / STATE
    prev = json.loads(state_path.read_text())["files"] if state_path.exists() else {}
    removed = sorted(set(prev) - set(plan.files))
    written = 0
    if not dry:
        for m in removed:
            p = REPO / m
            if p.is_file():
                p.unlink()
        for m, (side, rel, src) in sorted(plan.files.items()):
            dst = REPO / m
            data = plan.content.get(m) or src.read_bytes()
            if not dst.exists() or dst.read_bytes() != data:
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(data)
                written += 1
            mode = 0o755 if os.stat(src).st_mode & stat.S_IXUSR else 0o644
            os.chmod(dst, mode)
        state = {"files": {m: {"source": f"{side}:{rel}",
                               "sha256": hashlib.sha256(plan.content.get(m) or src.read_bytes()).hexdigest(),
                               **({"changed_by": "guard pass"} if m in plan.content else {})}
                           for m, (side, rel, src) in sorted(plan.files.items())}}
        write_text(state_path, json.dumps(state, indent=1, sort_keys=True) + "\n", dry)
    return {"removed": removed, "written": written}


def requirements_in(dry: bool) -> list[str]:
    src = (SOURCES["csctf"] / "requirements.txt").read_text().splitlines()
    seen, out = set(), ["# Master solver dependencies. Generated by tools/migrate/import_master.py from",
                        "# the CSCTF source repo's requirements.txt (pins kept, duplicate pins listed once), plus the",
                        "# test runner and the Unicorn pin B-240 asks for. Lock: requirements.lock.txt (CSCTF).",
                        "# Install: uv pip install --python .venv/bin/python -r requirements.in", ""]
    dups = []
    for line in src:
        s = line.strip()
        if s and not s.startswith("#"):
            key = re.split(r"[=<>!~ ]", s, 1)[0].lower().replace("_", "-").replace(".", "-")
            if key in seen:
                dups.append(s)
                continue
            seen.add(key)
        if s.startswith("# CSCTF 2026 solver dependencies") or s.startswith("#   uv venv"):
            continue
        out.append(line)
    out += ["", "# --- added by the master import (B-001 / B-240) ---",
            "unicorn==2.1.4", "pytest==9.1.1", "pytest-xdist==3.8.0", "pytest-timeout==2.4.0", ""]
    if (REPO / "requirements.in").exists():
        # Since R-14 the master owns requirements.in (pins added after the import, the generator header);
        # a re-run must not put the CSCTF-era file back. tools/requirements_gen.py --check then names any
        # requirements.txt / setup.sh this re-run reverted.
        print("requirements.in exists and is owned by the master (R-14): left unchanged", file=sys.stderr)
        return dups
    write_text(REPO / "requirements.in", "\n".join(out), dry)
    return dups


def md_table(rows: list[list[str]], head: list[str]) -> str:
    esc = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    lines += ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def short(s: str, n: int = 160) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def reports(plan: Plan, meta: dict, batches: list[dict], applied: dict, dups: list[str], dry: bool) -> None:
    mig = REPO / MIG
    by_side = Counter(v[0] for v in plan.files.values())
    by_why = Counter(plan.why.values())
    tree_bytes = sum(v[2].stat().st_size for v in plan.files.values())

    # ARCHIVED.md: one row per decision entry (a directory or glob entry counts once)
    agg: dict[tuple[str, str, str], list] = {}
    for s, r, g, t, dp in plan.archived:
        row = agg.setdefault((g, s, dp), [set(), t])
        row[0].add(r)
    arch = ["# Archived: not imported into the master tree", "",
            "Merge decision `archive` (and the losing side of `keep_both`). The source stays where it is, "
            "read-only; mine it from the path below when an item needs it (B-240 and the per-lane items list "
            "what to extract). Generated by `tools/migrate/import_master.py`. `files` counts enumerated source "
            "files (tracked plus untracked-not-ignored); a gitignored entry shows 1.", "",
            f"{len(agg)} decision entries covering {len({(s, r) for s, r, *_ in plan.archived})} files.", "",
            md_table([[g, f"~/{SOURCES[s].name}/{dp}", len(fs), short(t, 220)]
                      for (g, s, dp), (fs, t) in sorted(agg.items())],
                     ["group", "source path", "files", "reason"]), ""]
    write_text(mig / "ARCHIVED.md", "\n".join(arch), dry)

    # NOT-IMPORTED.md
    def dir_of(rel: str, depth: int = 2) -> str:
        parts = rel.split("/")
        return "/".join(parts[:min(depth, len(parts) - 1)]) + "/" if len(parts) > 1 else "(root)"
    ni = Counter((s, dir_of(r), w) for s, r, w in plan.not_imported)
    ex = Counter((rule, s, dir_of(r, 1)) for rule, items in plan.excluded.items() for s, r in items)
    dagg: dict[tuple[str, str, str], list] = {}
    for s, r, g, t, dp in plan.dropped:
        dagg.setdefault((g, s, dp), [set(), short(t, 140)])[0].add(r)
    arch_dirs = Counter((s, dir_of(r)) for s, r in {(s, r) for s, r, *_ in plan.archived} if s == "huntress")
    big = sorted(plan.excluded.get("file over 10 MB", []))
    txt = ["# Not imported", "", "Generated by `tools/migrate/import_master.py`. Counts are files.", "",
           "## Huntress-only (and Pink-only) files with no decision, outside solvers/ tools/ ctf/", "",
           "Prototypes, dashboards, observation scripts and the like. Source repos keep them.", "",
           md_table([[f"~/{SOURCES[s].name}/{d}", w, n] for (s, d, w), n in sorted(ni.items())],
                    ["directory", "why", "files"]), "",
           "## Huntress docs, records, speedrun and test data archived by decision", "",
           "By directory; the decision rows with reasons are in ARCHIVED.md.", "",
           md_table([[f"~/{SOURCES[s].name}/{d}", n] for (s, d), n in sorted(arch_dirs.items())],
                    ["directory", "files"]), "",
           "## Excluded by a never-import rule", "",
           md_table([[rule, s, d, n] for (rule, s, d), n in sorted(ex.items())], ["rule", "repo", "top dir", "files"]),
           "", "## Files over 10 MB", "",
           ("\n".join(f"- ~/{SOURCES[s].name}/{r}" for s, r in big) or "None among the enumerated files "
            "(tracked plus untracked-not-ignored; gitignored corpora such as speedrun/variants/ were not enumerated)."),
           "", "## Dropped by decision", "",
           md_table([[g, f"~/{SOURCES[s].name}/{dp}", len(fs), t] for (g, s, dp), (fs, t) in sorted(dagg.items())],
                    ["group", "source", "files", "reason"]), ""]
    write_text(mig / "NOT-IMPORTED.md", "\n".join(txt), dry)

    # queue + batches
    queue = [plan.queue[k] for k in sorted(plan.queue)]
    write_text(mig / "hand-merge-queue.json", json.dumps({"batches": batches, "queue": queue}, indent=1) + "\n", dry)
    bt = ["# Hand-merge batches", "",
          "The hand_merge queue plus every must-merge live delta, grouped by subsystem for parallel agents "
          "(tests up to 10 per batch, code up to 4, live deltas up to 5). Full reasons and source paths per file: "
          "`hand-merge-queue.json`. A file marked *not imported* has no copy in the tree yet: the agent works from "
          "the source path.", ""]
    for b in batches:
        bt += [f"## {b['id']} — {b['kind']} — {b['subsystem']} ({len(b['files'])})", ""]
        for m in b["files"]:
            q = plan.queue[m]
            srcs = ", ".join(f"{k}: `{v}`" for k, v in sorted(q["sources"].items()))
            flag = "" if q["imported"] else " — *not imported*"
            bt.append(f"- `{m}` (start: {q['start_side']}{flag}) — {srcs}")
            for r in q["reasons"]:
                bt.append(f"  - {short(r, 300)}")
            for n in q["notes"]:
                bt.append(f"  - note: {n}")
        bt.append("")
    write_text(mig / "HAND-MERGE-BATCHES.md", "\n".join(bt), dry)

    # IMPORT-REPORT.md
    st = meta["stats"]
    rep = ["# Master import report (B-001 step 1)", "",
           "Generated by `tools/migrate/import_master.py` (deterministic; re-run to refresh). Inputs: "
           "`analysis/out/reports/diffs/*.merge.json`, `analysis/out/workplan/diff_manifest.json`, and the working "
           "trees of the four source repos (tracked plus untracked-not-ignored files; uncommitted edits included, "
           "as the merge reports require).", "",
           "## Counts", "",
           f"- Source files enumerated: CSCTF {meta['C']}, Huntress {meta['H']}, Pink {meta['P']} "
           f"(Spooky is not a git repo; its engines are symlinks into Pink; used only for live deltas).",
           f"- Merge decisions read: {meta['decisions']} file/pattern entries, {meta['live']} live deltas.",
           f"- **Files imported: {len(plan.files)}** ({tree_bytes / 1e6:.1f} MB) — by source: "
           + ", ".join(f"{k} {v}" for k, v in sorted(by_side.items())) + ".",
           "- By rule: " + ", ".join(f"{k} {v}" for k, v in sorted(by_why.items(), key=lambda kv: -kv[1])) + ".",
           f"- Archived (not imported, see ARCHIVED.md): {len({(s, r) for s, r, *_ in plan.archived})} entries.",
           f"- Dropped by decision: {len({(s, r) for s, r, *_ in plan.dropped})} entries.",
           f"- Not imported, no decision (NOT-IMPORTED.md): {len(plan.not_imported)} files.",
           f"- Excluded by never-import rules: {sum(len(v) for v in plan.excluded.values())} files "
           f"({', '.join(f'{k}: {len(v)}' for k, v in sorted(plan.excluded.items()))}).",
           f"- Hand-merge queue: {len(plan.queue)} master paths "
           f"({sum(1 for q in plan.queue.values() if q['live_delta'])} with a must-merge live delta) in {len(batches)} batches "
           f"(HAND-MERGE-BATCHES.md).", ""]
    rep += ["## Huntress-only code imported with no decision (flagged)", "",
            f"{len(plan.flag_h_only)} files under solvers/, tools/, ctf/ that no merge entry names. Review each "
            "with its lane owner (B-240 carry checklist).", ""]
    rep += [f"- `{p}`" for p in plan.flag_h_only] + [""]
    rep += ["## Files that differ between CSCTF and Huntress with no decision", "",
            "CSCTF copy imported." if plan.flag_modified_nodecision else "None.", ""]
    rep += [f"- `{p}`" for p in plan.flag_modified_nodecision] + [""]
    rep += ["## Pink", "",
            "Pink differs from CSCTF in 7 tracked files plus 2 untracked tools (`diff -rq`, and the manifest's "
            "modified_cp / only_p). Applied: `ctf/submit.py` starts from Pink (hand_merge, 'take pink's version'); "
            "`tools/pink_launch.sh` imported from Pink and queued; `tools/pink_wave_prompt.md` goes to "
            "`events/pink/legacy-agent-config/` (live deltas call it event-specific, the infra plan hand-merges it "
            "into a template). Everything else keeps the CSCTF copy, which the reports name newer.", ""]
    rep += [f"- {n}" for n in sorted(set(plan.notes))] + [""]
    rep += ["## Live deltas", "", "must-merge entries are in the hand-merge queue. Skipped:", "",
            md_table([[e["action"], f"{e['event']}: {e['path']}", short(e["reason"], 140)] for e in plan.live_skipped],
                     ["action", "path", "reason"]), ""]
    rep += ["## Agent config", "",
            "No `.claude/`, `.codex/`, event `CLAUDE.md` or `AGENTS.md` at the repo root. The CSCTF and Huntress "
            "copies are under `events/<event>/legacy-agent-config/`, renamed so neither harness auto-loads them "
            "(`dot-claude/`, `CLAUDE.legacy.md`, `AGENTS.legacy.md`); archive/drop decisions still apply "
            "(Huntress lane rules, play-day skill, `settings.local.json` and so on are not copied). The root "
            "`CLAUDE.md` / `AGENTS.md` are hand-written, neutral, and not touched by this script.", ""]
    rep += ["## Event-specific root files (reported, not imported)", ""]
    rep += [f"- ~/{SOURCES[s].name}/{r}" for s, r in sorted(plan.excluded.get("event-specific root file", []))] + [""]
    rep += ["## Decisions that matched no file", "",
            "Entries in a merge.json whose path is neither an enumerated file nor a pattern over one."
            if plan.unmatched_decisions else "None.", ""]
    rep += [f"- {d.group}: `{d.path}` ({d.action})" for d in plan.unmatched_decisions] + [""]
    rep += ["## Commit-guard pass", "",
            "The tree must pass `.githooks/secret_scan.py`. The import reads the same denylist, finds "
            "denylisted values by hash (never by plaintext), replaces them consistently in every imported "
            "text file and in these reports, marks known-fake token-shaped fixture values with the guard's "
            "own `secret-scan: allow` pragma, leaves out files holding real-looking ones, then re-scans every "
            "planned file with the guard and fails on any block. Changed files carry `changed_by: guard pass` "
            "in `import-manifest.json`. The two renamed keys were CSCTF `.ctf/config.json` keys: an old event "
            "config that still uses them is now ignored by `ctf/config.py` (noted on the live-submit-guard "
            "batch).", ""]
    rep += [f"- {n}" for n in plan.guard_notes] + [""]
    rep += ["## requirements.in", "",
            "From CSCTF `requirements.txt` with pins kept, plus `unicorn==2.1.4`, `pytest==9.1.1`, "
            "`pytest-xdist==3.8.0`, `pytest-timeout==2.4.0` (versions installed in `.venv`). pytest itself is "
            "added because CSCTF's requirements did not name it. `requirements.lock.txt` is CSCTF's, unchanged."
            + (f" Duplicate pins dropped: {', '.join(dups)}." if dups else ""), ""]
    write_text(mig / "IMPORT-REPORT.md", "\n".join(rep), dry)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="plan and print counts; write nothing")
    ap.add_argument("--sources-dir", type=Path, default=HOME,
                    help="the folder holding the four 2026-ctf-* source repos (default: your home folder)")
    args = ap.parse_args(argv)
    SOURCES.clear()
    SOURCES.update(source_roots(args.sources_dir))
    try:
        plan, meta = build_plan()
    except ImportError_ as e:
        die(str(e))
    _TEXT_FILTER["redact"], _TEXT_FILTER["scan"] = plan.redact, plan.guard_scan
    batches = make_batches(plan.queue)
    applied = apply(plan, args.dry_run)
    dups = requirements_in(args.dry_run)
    reports(plan, meta, batches, applied, dups, args.dry_run)
    by_side = Counter(v[0] for v in plan.files.values())
    print(f"{'DRY RUN: ' if args.dry_run else ''}files {len(plan.files)} ({dict(sorted(by_side.items()))}); "
          f"archived {len({(s, r) for s, r, *_ in plan.archived})}; dropped {len(plan.dropped)}; "
          f"not-imported {len(plan.not_imported)}; excluded {sum(len(v) for v in plan.excluded.values())}; "
          f"queue {len(plan.queue)} in {len(batches)} batches; flagged H-only code {len(plan.flag_h_only)}; "
          f"unmatched decisions {len(plan.unmatched_decisions)}; written {applied['written']}, "
          f"removed {len(applied['removed'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
