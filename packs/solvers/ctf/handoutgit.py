"""The handout-git step (B-070): what a git repository in a challenge's files gives up, read as bytes.

A git directory stores every file deflated, so the flag sweep (ctf/sweep.py) sees nothing of a
repository's history: not a file a later commit deleted, not a commit `git reset` cut loose, not a commit
message. This step reads the repository with solvers/toolkits/repo_supply_chain.py (pure Python: loose
objects, packs, bundles, refs, reflog, index) and hands the sweep plain members to search, hash and list:

    step = Step(ff, embedded_decode, loose(target, notes))
    members = step.run(rows, walk, notes)     # [(chain, bytes, open it?)]; then step.repos, step.joins

NO git program is ever run on a handout, here or anywhere: a repository's config, hooks, filters and
aliases are code a real git would execute. They are listed in the report as bytes ("WOULD RUN").

Which repositories. Only ones that are challenge data:
- a git directory, a bare repository, a lone packfile or a bundle among the members of an unpacked archive
  (`rows`, whatever the nesting), and
- a `.git` folder inside a pulled challenge's `files/` (`loose`), which the flag sweep itself never reads
  (`sweep.SECRET_DIRS`): its files reach this step only, and only what the step derives is written.
A `.git` at or above the challenge folder is never looked for, a drop folder's or a bare folder's `.git`
is never read (it may be the operator's own; archive it or pull it), links are never followed, and `.ctf/`
is never entered.

What one repository gives, as members under `<git directory> -> ...` (on disk `<git directory>.unpacked/`,
beside the repository, a path `ctf read` allows where `.git/` itself is refused):

  git-report.txt            refs, HEAD, ORIG_HEAD and the other pseudo-heads, every commit (reachable or
                            not) with its epoch, full message and changed paths, reflog, stashes, tags,
                            the objects no ref reaches (git fsck --unreachable) and the dangling ones,
                            deleted files, the files in the git directory git did not write, hidden
                            dotfiles, decoded strings, numbered fragments, what a real git would run
  deleted/<commit>/<path>   a file a commit deleted, as it was in that commit's parent
  unreachable/<commit>/..   files a commit no ref and no reflog reaches added or changed
  reflog-only/<commit>/..   the same for a commit only the reflog or ORIG_HEAD still names
  dangling/blob-<id>, unreachable/blob-<id>, index-only/<path>, tagged-blob/<id>
                            blobs no commit holds: dangling, staged and never committed, tagged directly
  history/<commit>/<path>   every other version of a file that is not in the work tree (newest first)
  nonstandard/<path>        the files in the git directory that git did not write

Each member is opened by the archive walk and the polyglot carver in turn (a zip deleted from history, an
image with an archive behind it in a cut commit) and counts against the walk's budgets. A blob the work
tree already holds is not exported twice.

Decoded strings: every hex / base64 / base32 token (solvers/toolkits/embedded_decode.py) in the work tree's
text files, the exported blobs, the non-standard files and the messages that decodes to printable text, with
where it sits. Numbered fragments (ctf/numfrag.py) are read from all of those and from what decoded; an
assembled value is a `join` in the sweep's result (a candidate, never `solved`) and is deliberately not
written into git-report.txt, so the flag sweep cannot find it there as if it were plain text.

Bounded: bytes and files read from a loose `.git`, bytes of git objects in one container, repositories per
sweep, exported blobs per repository, texts decoded. Every cut is a note. A reader that fails on hostile
bytes is a note and the sweep goes on.
"""
from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

from . import numfrag as _numfrag
from . import paths as _paths
from .packs import load_module as _load_module

__all__ = ["Step", "loose", "GIT_DIR", "REPORT"]

GIT_DIR = ".git"
REPORT = "git-report.txt"
ARROW = " -> "
MAX_GIT_FILE = 64 << 20          # bytes of one file read from a loose .git
MAX_GIT_BYTES = 256 << 20        # bytes of git objects and packs in one container; more is not read
MAX_GIT_FILES = 40000            # files read from loose .git folders
MAX_REPOS = 8                    # repositories read in one sweep
MAX_DEPTH = 3                    # passes of the step: a repository inside what a pass exported is read, this deep
MAX_OBJECTS = 50000              # a repository with more objects is left to the engine run by hand
MAX_EXPORTS = 1500               # blobs exported from one repository
MAX_NONSTANDARD = 200
MAX_COMMITS_SHOWN = 500
MAX_TEXTS = 3000                 # texts searched for encoded tokens and numbered fragments
TEXT_CAP = 256 << 10             # bytes of one text searched
MAX_DECODED = 200                # decoded strings kept
_SECRET = ".ctf"


def _rsc():
    rel = "solvers/toolkits/repo_supply_chain.py"
    return _load_module("ctf_handoutgit_repo_supply_chain", _paths.repo_root() / rel, pack=rel)


def loose(target, notes: list) -> list[tuple[str, bytes]]:
    """[(path relative to files/, bytes)] of every file in a `.git` folder inside a pulled challenge's
    `files/`. [] for any other target: a drop folder's or a bare folder's `.git` may be the operator's own
    and is never read. Links are never followed, `.ctf/` is never entered, and the bytes read are bounded
    (MAX_GIT_FILE each, MAX_GIT_BYTES and MAX_GIT_FILES in all; a note for each cut)."""
    if getattr(target, "kind", "") != "pulled" or not Path(target.sources).is_dir():
        return []
    sources = Path(target.sources)
    out, total, full = [], 0, False
    for folder, dirs, names in os.walk(sources):
        here = Path(folder)
        rel_here = here.relative_to(sources)
        inside = GIT_DIR in rel_here.parts
        for d in list(dirs):
            if (here / d).is_symlink() or d == _SECRET:
                dirs.remove(d)                       # sweep.read_sources already notes links and .ctf outside .git
                if inside:
                    notes.append(f"git handout: ignored {(rel_here / d).as_posix()!r} "
                                 f"({'a symbolic link' if (here / d).is_symlink() else 'a credentials folder'})")
        dirs.sort()
        if not inside or full:
            continue
        for n in sorted(names):
            f = here / n
            rel = (rel_here / n).as_posix()
            if f.is_symlink() or not f.is_file():
                continue
            size = f.lstat().st_size
            if size > MAX_GIT_FILE:
                notes.append(f"git handout: not read {rel!r}: {size} bytes is over the limit of {MAX_GIT_FILE}")
                continue
            if len(out) >= MAX_GIT_FILES or total + size > MAX_GIT_BYTES:
                notes.append(f"git handout: stopped at {rel!r}: the budget for loose .git folders "
                             f"({MAX_GIT_FILES} files, {MAX_GIT_BYTES} bytes) is spent; the repository is read "
                             f"incomplete")
                full = True
                break
            with open(f, "rb") as fh:
                data = fh.read(MAX_GIT_FILE + 1)
            if len(data) > MAX_GIT_FILE:
                notes.append(f"git handout: not read {rel!r}: it grew past the limit while being read")
                continue
            total += len(data)
            out.append((rel, data))
    return out


def _marker(path: str, data: bytes) -> bool:
    return path == "HEAD" or path.endswith("/HEAD") or data[:4] == b"PACK" or data[:6] in (b"# v2 g", b"# v3 g")


def _groups(rows) -> dict:
    """{container chain: [(path, bytes)]} of the containers among `rows` ([(chain, bytes)]) that hold a
    repository marker (a HEAD, a pack, a bundle)."""
    groups = {}
    for chain, data in rows:
        chain = tuple(chain)
        groups.setdefault(chain[:-1], []).append((str(chain[-1]).replace("\\", "/"), data))
    return {c: files for c, files in groups.items() if any(_marker(p, d) for p, d in files)}


def holding(rows) -> list[str]:
    """The containers among `rows` that look like they hold a repository, as labels: what a pass the
    sweep did not run would have read."""
    return [ARROW.join(c) or "the handout's files" for c in sorted(_groups(rows))]


def _git_internal(path: str, data: bytes) -> bool:
    return "objects/" in path or data[:4] == b"PACK"


def _hidden(path: str) -> bool:
    return any(part.startswith(".") and part not in (".", "..") for part in path.split("/"))


def _texty(data: bytes) -> bool:
    return b"\x00" not in data[:4096]


def _printable(data: bytes) -> bool:
    """Every byte is printable ASCII or white space: a decode with one stray byte is not listed as text."""
    return bool(data) and all(32 <= c < 127 or c in (9, 10, 13) for c in data)


def _when(t, tz) -> str:
    if t is None:
        return "-"
    try:
        return f"{t} ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(t)))} UTC, zone {tz or '?'})"
    except (ValueError, OverflowError, OSError):
        return str(t)


class Step:
    """One sweep's handout-git step. `ff` is the event's ctf.flagfmt.FlagFormat (never the active event's),
    `embedded` solvers/toolkits/embedded_decode.py, `loose_rows` what `loose()` read.

    After run(): `repos` is one JSON-ready summary per repository (the `git` list of .sweep.json) and
    `joins` is [(fragjoin.Join, sha256 of that repository's git-report.txt)]."""

    def __init__(self, ff, embedded, loose_rows=()):
        self.ff, self.ed, self.loose = ff, embedded, list(loose_rows)
        self.repos, self.joins = [], []

    def run(self, rows, walk, notes: list) -> list[tuple[tuple, bytes, bool]]:
        """[(chain, bytes, open_it)] for every repository among `rows` ([(chain, bytes)]: the originals and
        the members unpacked so far) and the loose `.git` folders this step was given."""
        self.repos, self.joins = [], []
        return self._scan(list(rows) + [((rel,), data) for rel, data in self.loose], walk, notes)

    def more(self, rows, walk, notes: list) -> list[tuple[tuple, bytes, bool]]:
        """run() again over `rows` the sweep added after it: what the step exported and what was opened,
        recovered and carved from that (a repository in a deleted zip). The loose `.git` is not read twice;
        `repos` and `joins` grow, and MAX_REPOS counts every pass."""
        return self._scan(list(rows), walk, notes)

    def _scan(self, rows: list, walk, notes: list) -> list[tuple[tuple, bytes, bool]]:
        groups = _groups(rows)
        out = []
        for container in sorted(groups):
            files = groups[container]
            where = ARROW.join(container) or "the handout's files"
            heavy = sum(len(d) for p, d in files if _git_internal(p, d))
            if heavy > MAX_GIT_BYTES:
                notes.append(f"git handout in {where}: {heavy} bytes of git objects is over the limit of "
                             f"{MAX_GIT_BYTES}; not read (run solvers/toolkits/repo_supply_chain.py on it by hand)")
                continue
            try:
                rsc = _rsc()
                repos = rsc.find_git([(ARROW.join(container), p, d) for p, d in files])
            except Exception as e:       # hostile bytes: a repository that breaks the reader never stops the sweep
                notes.append(f"git handout in {where}: the repository does not read ({type(e).__name__}: {e})")
                continue
            for repo in repos:
                if len(self.repos) >= MAX_REPOS:
                    notes.append(f"git handout {repo.label}: not read, {MAX_REPOS} repositories were read already")
                    continue
                try:
                    out += self._read(rsc, repo, container, walk, notes)
                except Exception as e:
                    notes.append(f"git handout {repo.label}: reading it failed, nothing exported "
                                 f"({type(e).__name__}: {e})")
        return out

    # ---------------------------------------------------------------- one repository

    def _read(self, rsc, repo, container: tuple, walk, notes: list) -> list:
        if not repo.objects and not repo.nonstandard():
            notes.append(f"git handout {repo.label}: a git directory with no readable object; nothing exported")
            return []
        root = repo.root
        base = container + (((root.rstrip("/") if root else "") or "git-dir"),)
        label = repo.label
        if len(repo.objects) > MAX_OBJECTS:
            notes.append(f"git handout {label}: {len(repo.objects)} objects is over the pull-time limit of "
                         f"{MAX_OBJECTS}; not read here (run solvers/toolkits/repo_supply_chain.py on it by hand)")
            return []
        members, texts, problems = [], [], list(repo.problems)

        def take(sub: str, body: bytes, opens: bool = True) -> bool:
            if walk is not None and not walk.take(f"{label}{ARROW}{sub}", len(body)):
                return False
            members.append((base + (sub,), body, opens))
            return True

        def blob_id(data: bytes) -> str:
            return hashlib.new(repo.hashname, b"blob %d\x00" % len(data) + data).hexdigest()

        reach = repo.reach()
        taken = {blob_id(d) for d in repo.worktree.values()}
        exports, deleted = [], []

        def want(sub: str, oid) -> bool:
            if not oid or oid in taken or repo.blob(oid) is None:
                return False
            taken.add(oid)
            exports.append((sub, oid))
            return True

        try:
            for c, p in repo.deleted():
                parents = repo.parents(c)
                oid = repo.snapshot(parents[0]).get(p) if parents else None
                sub = f"deleted/{c[:7]}/{p}"
                deleted.append({"commit": c, "path": p, "member": sub if want(sub, oid) else None})
        except rsc.Incomplete as e:
            problems.append(f"deleted files not listed in full: {e}")
        commits = repo.ids()
        changes = {}
        for c in commits:
            try:
                changes[c] = repo.changes(c)
            except rsc.Incomplete as e:
                changes[c] = None
                problems.append(f"commit {c[:12]}: its files do not read ({e})")
        for c in commits:
            how = repo.where(c)
            if how == "refs" or changes[c] is None:
                continue
            folder = "reflog-only" if how == "reflog" else "unreachable"
            for p, (_old, new) in changes[c].items():
                want(f"{folder}/{c[:7]}/{p}", new)
        held = repo.blob_paths()
        staged = {e["id"]: e["path"] for e in repo.index()}
        for oid in sorted(o for o, (typ, _) in repo.objects.items() if typ == "blob" and o not in held):
            how = repo.where(oid)
            if how == "index":
                sub = f"index-only/{staged.get(oid, 'blob-' + oid[:12])}"
            elif how == "refs":
                sub = f"tagged-blob/{oid[:12]}"
            else:
                sub = f"{'dangling' if oid in reach['dangling'] or oid in reach['dangling_no_reflog'] else 'unreachable'}/blob-{oid[:12]}"
            want(sub, oid)
        for c in reversed(commits):
            if repo.where(c) != "refs" or changes[c] is None:
                continue
            for p, (_old, new) in changes[c].items():
                want(f"history/{c[:7]}/{p}", new)
        if len(exports) > MAX_EXPORTS:
            notes.append(f"git handout {label}: {len(exports) - MAX_EXPORTS} older file version(s) not exported "
                         f"(limit {MAX_EXPORTS} per repository); repo_supply_chain.py --grep reads them all")
            exports = exports[:MAX_EXPORTS]
        exported = 0
        for sub, oid in exports:
            body = repo.blob(oid)
            if take(sub, body):
                exported += 1
                texts.append((sub, body))
            elif walk is not None and walk.full:
                break
        odd = repo.nonstandard()
        for row in odd[:MAX_NONSTANDARD]:
            body = repo.t[row["path"]]
            row["member"] = f"nonstandard/{row['path']}" if take(f"nonstandard/{row['path']}", body) else None
            texts.append((f"git directory file {row['path']}", body))
        if len(odd) > MAX_NONSTANDARD:
            notes.append(f"git handout {label}: {len(odd) - MAX_NONSTANDARD} more file(s) git did not write are "
                         f"listed in {REPORT} but not exported")

        dotfiles = [{"path": p, "where": "work tree", "size": len(repo.worktree[p])}
                    for p in sorted(repo.worktree) if _hidden(p)]
        seen_dot = {r["path"] for r in dotfiles}
        for oid, places in held.items():
            for c, p in places:
                if _hidden(p) and p not in seen_dot:
                    seen_dot.add(p)
                    dotfiles.append({"path": p, "where": f"commit {c[:7]}", "size": len(repo.blob(oid) or b"")})
        dotfiles.sort(key=lambda r: (r["where"] != "work tree", r["path"]))

        messages = []
        for c in commits:
            m = (repo.commit(c) or {}).get("message") or ""
            messages.append((f"commit {c[:7]} message", m.encode("utf-8", "replace")))
        tags = [repo.tag(o) for o, (typ, _) in sorted(repo.objects.items()) if typ == "tag"]
        for t in tags:
            messages.append((f"tag {t.get('tag')} message", (t.get("message") or "").encode("utf-8", "replace")))
        reflog = repo.reflog()
        if reflog:
            messages.append(("reflog", "\n".join(e["message"] for e in reflog).encode("utf-8", "replace")))
        searched = [(p, d) for p, d in sorted(repo.worktree.items())] + texts + messages
        searched = [(o, bytes(d[:TEXT_CAP])) for o, d in searched if d and _texty(d)]
        if len(searched) > MAX_TEXTS:
            notes.append(f"git handout {label}: {len(searched) - MAX_TEXTS} text(s) not searched for encoded "
                         f"strings or numbered fragments (limit {MAX_TEXTS})")
            searched = searched[:MAX_TEXTS]
        decoded = self._decode(searched)
        frag_texts = [(o, d.decode("utf-8", "replace")) for o, d in searched]
        frag_texts += [(f"{row['where']} ({row['encoding']}-decoded)", row["text"]) for row in decoded]
        fragments = _numfrag.find(frag_texts, self.ff)
        joins = _numfrag.assemble(fragments, self.ff)

        config = rsc.git_config_facts(repo)
        would_run = [f"config {k} = {v}" for k, v in config["runs"]] + [f"hooks/{n}" for n in config["hooks"]]
        not_reached = [{"id": o, "type": repo.objects[o][0], "reached_from": repo.where(o),
                        "dangling": o in reach["dangling"]} for o in sorted(reach["no_ref"])]
        cut = [c for c in commits if repo.where(c) != "refs"]
        summary = {
            "label": label, "chain": ARROW.join(base), "object_format": repo.hashname, "objects": len(repo.objects),
            "complete": repo.complete, "problems": problems, "head": repo.head(), "refs": repo.refs(),
            "pseudo_heads": repo.pseudo_heads(), "commits": len(commits),
            "commits_no_ref_reaches": [{"id": c, "reached_from": repo.where(c),
                                        "time": (repo.commit(c) or {}).get("committer_time"),
                                        "subject": ((repo.commit(c) or {}).get("message") or "").strip().split("\n")[0][:200]}
                                       for c in cut],
            "not_reached_by_a_ref": not_reached[:400], "deleted_files": deleted,
            "nonstandard_files": odd, "hidden_dotfiles": dotfiles[:400], "decoded": decoded,
            "fragments": [{"index": f.index, "total": f.total, "text": f.body, "origin": f.origin}
                          for f in sorted(fragments, key=lambda f: f.index)],
            "candidates": [j.flag for j in joins], "would_run": would_run,
            "exported": exported, "report": ARROW.join(base + (REPORT,)),
        }
        text = self._report(repo, summary, changes, reflog, tags, config, len(joins)).encode("utf-8", "replace")
        if take(REPORT, text, opens=False):
            digest = hashlib.sha256(text).hexdigest()
            self.joins += [(j, digest) for j in joins]
        else:
            summary["report"] = None
            self.joins += [(j, "") for j in joins]
        self.repos.append(summary)
        dangling = sum(1 for o in not_reached if o["dangling"])
        notes.append(f"git handout {label}: {len(commits)} commit(s), {len(cut)} that no ref reaches, "
                     f"{len(not_reached)} object(s) no ref reaches ({dangling} dangling), {len(deleted)} deleted "
                     f"file(s), {len(odd)} file(s) in the git directory git did not write, {len(decoded)} decoded "
                     f"string(s), {len(joins)} assembled candidate(s); {exported} blob(s) exported; read "
                     f"{summary['report'] or 'the git list of the sweep report'} (no git program was run)")
        if would_run:
            notes.append(f"git handout {label}: a real git would run {len(would_run)} thing(s) here "
                         f"({'; '.join(would_run)[:200]}): never run git in the scratch copy")
        return members

    def _decode(self, searched: list) -> list:
        """[{where, encoding, offset, token, text}] of the encoded tokens that decode to printable text."""
        out, seen = [], set()
        for origin, data in searched:
            try:
                blobs = self.ed.find_blobs(data, min_printable=0.95, max_results=50, flag_re=self.ff.bregex)
            except Exception:            # one text the decoder trips on is one text without decoded strings
                continue
            for b in blobs:
                dec = bytes(b["decoded"])
                key = (origin, b["offset"], dec)
                if key in seen or not _printable(dec):
                    continue
                seen.add(key)
                out.append({"where": origin, "encoding": str(b["encoding"]).replace("base64url", "base64"),
                            "offset": int(b["offset"]), "token": str(b["match"])[:120],
                            "text": dec.decode("ascii")})
                if len(out) >= MAX_DECODED:
                    return out
        return out

    def _report(self, repo, s: dict, changes: dict, reflog: list, tags: list, config: dict, candidates: int) -> str:
        head = s["head"]
        lines = [f"git handout: {s['label']}",
                 "Read as bytes (ctf/handoutgit.py over solvers/toolkits/repo_supply_chain.py). No git program was",
                 "run, and none may be run on this repository or on its scratch copy: see WOULD RUN below.",
                 "",
                 f"objects: {s['objects']} ({s['object_format']})   complete: {'yes' if s['complete'] else 'NO'}",
                 f"HEAD: {head.get('ref') or 'detached'} {head.get('id') or '-'}"]
        for name, oid in sorted(s["refs"].items()):
            lines.append(f"ref {name} {oid}")
        for name, ids in sorted(s["pseudo_heads"].items()):
            lines.append(f"{name}: {' '.join(ids)}")
        for name, url in sorted(config["remotes"].items()):
            lines.append(f"remote {name}: {url}")
        if config["user"]:
            lines.append("config user: " + ", ".join(f"{k}={v}" for k, v in sorted(config["user"].items())))
        for w in s["would_run"]:
            lines.append(f"WOULD RUN under a real git: {w}")
        for p in s["problems"]:
            lines.append(f"PROBLEM: {p}")
        commits = repo.ids()
        lines += ["", f"commits ({len(commits)}), oldest first (every commit object, reachable or not):"]
        for c in commits[:MAX_COMMITS_SHOWN]:
            cm = repo.commit(c) or {}
            how = repo.where(c)
            tag = "" if how == "refs" else ("   [ONLY THE REFLOG OR A PSEUDO-HEAD REACHES IT]" if how == "reflog"
                                            else "   [NO REF REACHES IT]")
            lines.append(f"commit {c}{tag}")
            lines.append(f"  author    {cm.get('author') or '-'} <{cm.get('email') or '-'}>  {_when(cm.get('time'), cm.get('tz'))}")
            lines.append(f"  committer {cm.get('committer') or '-'} <{cm.get('committer_email') or '-'}>  "
                         f"{_when(cm.get('committer_time'), cm.get('committer_tz'))}")
            for parent in cm.get("parents") or []:
                lines.append(f"  parent    {parent}")
            for ln in (cm.get("message") or "").rstrip("\n").split("\n")[:40]:
                lines.append(f"      {ln}")
            ch = changes.get(c)
            if ch is None:
                lines.append("  files: not readable")
                continue
            for p, (old, new) in list(ch.items())[:40]:
                lines.append(f"  {'added' if old is None else 'deleted' if new is None else 'modified':8} {p}")
            if len(ch) > 40:
                lines.append(f"  ... {len(ch) - 40} more path(s)")
        if len(commits) > MAX_COMMITS_SHOWN:
            lines.append(f"... {len(commits) - MAX_COMMITS_SHOWN} more commit(s) not shown")
        if reflog:
            lines += ["", "reflog:"]
            for e in reflog[-200:]:
                lines.append(f"  {e['ref']}: {e['old'][:12]} -> {e['new'][:12]}  {e['message']}")
        stashes = repo.stashes()
        if stashes:
            lines += ["", "stashes:"]
            for st in stashes:
                lines.append(f"  stash@{{{st['index']}}} {st['id']}  {(st['message'] or '').strip()}")
        if tags:
            lines += ["", "annotated tags:"]
            for t in tags:
                lines.append(f"  tag {t.get('tag')} -> {t.get('type')} {t.get('object')}")
                for ln in (t.get("message") or "").rstrip("\n").split("\n")[:20]:
                    lines.append(f"      {ln}")
        if s["not_reached_by_a_ref"]:
            lines += ["", "objects no ref reaches (git fsck --unreachable --no-reflogs would list them):"]
            for o in s["not_reached_by_a_ref"]:
                lines.append(f"  {o['type']:6} {o['id']}  reached from: {o['reached_from']}"
                             + ("  (dangling)" if o["dangling"] else ""))
        if s["deleted_files"]:
            lines += ["", "deleted files (the content is the member named):"]
            for d in s["deleted_files"]:
                lines.append(f"  {d['path']}  deleted by commit {d['commit'][:12]}  -> "
                             + (d["member"] or "same content as a file already unpacked"))
        if s["nonstandard_files"]:
            lines += ["", "files in the git directory that git did not write:"]
            for row in s["nonstandard_files"]:
                lines.append(f"  {row['path']} ({row['size']} bytes): {row['why']}"
                             + (f"  -> {row['member']}" if row.get("member") else ""))
        if s["hidden_dotfiles"]:
            lines += ["", "hidden dotfiles:"]
            for row in s["hidden_dotfiles"]:
                lines.append(f"  {row['path']} ({row['size']} bytes, {row['where']})")
        if s["decoded"]:
            lines += ["", "decoded strings (hex / base64 / base32 tokens that read as text):"]
            for row in s["decoded"]:
                lines.append(f"  {row['where']} @{row['offset']} {row['encoding']}:")
                for ln in row["text"].split("\n")[:6]:
                    lines.append(f"      {ln}")
        if s["fragments"]:
            lines += ["", "numbered fragments (a line that carries a position):"]
            for f in s["fragments"]:
                lines.append(f"  ({f['index']}) in {f['origin']}:")
                lines.append(f"      {f['text']}")
            lines.append(f"  {candidates} assembled candidate(s): listed as joins in the sweep's result and under "
                         f"`git` in .sweep.json, not here")
        lines += ["", f"exported: {s['exported']} blob(s) beside this report (deleted/, unreachable/, reflog-only/, "
                      f"dangling/, index-only/, history/, nonstandard/)"]
        return "\n".join(lines) + "\n"
