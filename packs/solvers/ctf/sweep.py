"""The pull-time corpus sweep (B-013): what a challenge's files give up with no model and no tool run.

    rep = sweep(target, profile)          # target: a pulled challenge folder, a drop folder, any folder or file
    rep.result                            # ctf.result.SolverResult (solved / candidate / none)
    rep.manifest                          # one entry per original file and per unpacked member

Steps, in order, all offline:

1. Recursive unpack into a scratch copy, never in place. A pulled challenge (`challenge.json` +
   `files/`) unpacks into `<challenge>/unpacked/`; anything else (a manual drop folder, a bare file or
   folder) into `<workdir>/sweep/<name>-<hash>/`, or `out=`. The originals are copied there and every
   archive's members land beside it in `<archive>.unpacked/`, as tools/archive_expand.py's wide walk
   (`Walk`) reads them: zip/APK/JAR, 7z and RAR (7-Zip), tar, whole-file gzip/bz2/xz, base64/hex/...
   envelopes around a container, nested to `max_depth`. Member names are made safe by tools/unpack.py
   (`Tree`: no '..', no absolute path, no harness file name, no write outside the folder, no symlink
   created or followed, files 0644). Budgets: bytes per member, bytes and members in all, depth; every
   member not read or not written is a line in `notes`. Nothing unpacked is ever executed. Originals
   are read up to MAX_SOURCE each and MAX_SOURCE_TOTAL in all; .ctf/ and .git/ folders under the target
   are never read (a note each), nor .env* files except in a pulled challenge's files/ (there they are
   the platform's download, and a web handout's .env often holds the flag). A target that is or lies in
   a .ctf/ or .git/ folder, or is a .env file, is refused.
   B-074: when a member stays locked (no known archive password opens it), candidate passwords are
   harvested from the corpus bytes -- a container's appended overlay, readable ASCII/UTF-16 strings and
   sibling text files -- added to the password store, and the unpack is run once more so a harvested
   password opens the archive and the flag inside is swept. Nothing is generated; only strings that
   literally appear in the handout are tried.
   B-029 (ctf/recover): a disk container is unwrapped to `<name>.raw`; an NTFS volume (bare, MBR or GPT)
   gives `ntfs-listing.txt` and its files, deleted ones included, as `deleted/<path>` / `allocated/<path>`
   members that the walk opens in turn; a .docx gives `tracked-changes/accepted.txt`, `original.txt`,
   `deletions.txt` and `insertions.txt` (text joined across runs). All count against the walk's budgets.
   B-135 (ctf/recover/extfs.py): an ext volume gives `ext-listing.json` (paths, inodes, mtimes), its
   files as `ext/<path>` and the ELF programs carved from its free blocks as `ext-unallocated/blk<N>.elf`.
   B-070 (ctf/polycarve): an archive inside or behind an image (a zip after a PNG's IEND) is carved, with
   its structure validated, as `carved@0x<offset>.<ext>`, other trailing bytes as `overlay@0x<offset>.bin`,
   and both go back through the same walk; recovery and carving repeat on what they add, DEEPEN rounds at
   most. B-070 (ctf/handoutgit): a git repository among the members, or a `.git` folder inside a pulled
   challenge's files/ (the one .git the sweep opens: it is the platform's download; its raw files still
   never enter the flag sweep or the scratch copy), is read as bytes, never with a git program, and gives
   `<git dir> -> git-report.txt` plus the files only its history holds (`deleted/`, `unreachable/`,
   `reflog-only/`, `dangling/`, `index-only/`, `history/`) and the files in the git directory git did not
   write (`nonstandard/`), each opened and carved in turn; a repository inside those is read in a further
   pass (handoutgit.MAX_DEPTH passes). `.sweep.json` lists each repository under `git`.
2. A sha256 manifest of every original and member: chain ("handout.zip -> logs/a.swp"), scratch path,
   size, sha256 and what solvers/common/triage.py's identify() calls it. Written to `.sweep.json` in the
   scratch folder together with the findings.
3. Triage on the scratch copy (ctf.triage.suggest over the unpacked files), so a bare dropped file or
   folder gets the same engine list a pulled challenge does.
4. A flag sweep over every distinct content (originals and members): the event's flag format (ctf.flagfmt)
   in the raw bytes and in UTF-16; every embedded base64 / base64url / base32 / hex token
   (solvers/toolkits/embedded_decode.py with its opt-in pass over the three other base64 alignments,
   given the profile's pattern, never the active event's) and, one level further,
   tokens inside what those decode to; the same after URL-decoding (a base64 query parameter in a web
   log). A decoded hex or base64 run with no flag is also tried under every single-byte XOR key, gated
   by the flag format and printability (ctf/recover/xorcrib.py; off while the event's prefixes are not
   known). A flag with XML markup inside whose tag-free text was also found is excluded.
   Flags seen only through a tracked change rank first; the brief's wording picks the redline's side.
5. Split-metadata fragments (ctf/fragjoin.py): image metadata fields joined in file order when one opens
   a flag and a later one closes it. B-070: numbered fragments of a git handout (ctf/numfrag.py: a deleted
   file's `... (1)`, a hidden file's hex that decodes to `... (2)`, a note in .git/ ending `...} (3)`)
   joined by their positions; these are joins too, so candidates.

Findings that appear verbatim in the challenge's brief, or whose body is a placeholder (`...`, `xxx`,
`example`), are excluded and listed as such. Status: one distinct flag from steps 4 -> `solved`
(flag found, not accepted); several -> `candidate` (decoys possible); only joins -> `candidate`; nothing
-> `none`. Nothing is submitted here: intake (B-002) and the submit gate decide that.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import tomllib
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from . import flagfmt as _flagfmt
from . import fragjoin as _fragjoin
from . import handoutgit as _handoutgit
from . import paths as _paths
from . import polycarve as _polycarve
from . import recover as _recover
from .packs import load_module as _load_module
from .result import Cost, Evidence, SolverResult

SCHEMA = 1
ENGINE = "intake.sweep"
REPORT = ".sweep.json"          # written last: the findings and the manifest
OWNER = ".sweep-owner"          # written first: this folder is a sweep's scratch copy
SUFFIX = ".unpacked"            # an archive's members go in <archive>.unpacked/
MAX_SOURCE = 256 << 20          # an original larger than this is not read (a note says so)
MAX_SOURCE_TOTAL = 512 << 20    # bytes of all originals read; the rest is not read (a note each)
SECRET_DIRS = (".ctf", ".git")  # never read in or under a target (tokens, cookies, git credentials)
SCAN_CAP = 64 << 20             # bytes of one content scanned for flags
WINDOW = 4 << 20                # embedded_decode reads at most this much at once
OVERLAP = 64 << 10
UTF16_CAP = 16 << 20
NESTED_TOKENS = 200             # decoded tokens of one content searched again for tokens
DEEPEN = 6                      # rounds of recover + carve over what the round before added (B-070)
JUNK = (".DS_Store",)
DROP_META = ("challenge.toml", "SOLVED")       # a manual drop folder's own files, not challenge files
PLACEHOLDER_WORDS = {"", "example", "flag", "flag_here", "your_flag", "your_flag_here", "insert_flag_here",
                     "redacted", "placeholder", "sample", "xxx", "fake", "test"}
_PLACEHOLDER_CHARS = re.compile(r"[.\-_xX*?#\s]*")


class SweepError(RuntimeError):
    """The sweep cannot run: a bad target, an out folder it may not use, a missing pack."""


class NothingToSweep(SweepError):
    """The target holds no file at all (no file was skipped either): a pulled challenge with no handout,
    such as most web or instance challenges. `ctf pull` says so plainly; `ctf sweep` still exits 2."""


# ---------------------------------------------------------------- the packs it borrows

def _tool(name: str, rel: str):
    return _load_module(name, _paths.repo_root() / rel, pack=rel)


def archive_expand():
    """tools/archive_expand.py, under the name tools/run.py imports it by (one module, one password store)."""
    return _tool("archive_expand", "tools/archive_expand.py")


def _unpack_tools():
    return _tool("ctf_tools_unpack", "tools/unpack.py")


def _embedded():
    return _tool("ctf_embedded_decode", "solvers/toolkits/embedded_decode.py")


def _identify():
    return _tool("ctf_common_triage", "solvers/common/triage.py").identify


def _harvest():
    return _tool("ctf_common_harvest", "solvers/common/harvest.py")


def _passwords():
    return _tool("ctf_common_archive_passwords", "solvers/common/archive_passwords.py")


def _ledger():
    return _tool("ctf_common_evidence_ledger", "solvers/common/evidence_ledger.py")


# B-207: the offline format_fingerprint step on every member ctf.formats.identify cannot name `sure`.
def fingerprint_unnamed(blobs: dict, manifest: list, notes: list) -> list:
    """Run the offline format_fingerprint step (ctf.formats.fingerprint.analyze) on every distinct member
    `ctf.formats.identify` cannot name `sure`, and return the ranked 'likely tool/format' leads -- unsure,
    for a human, never a flag. Offline only: the public code search stays an explicit operator opt-in
    (`ctf formats fingerprint --online`), so the sweep never reaches the network. A missing catalog or
    magic table fails loudly as a named note and nothing is fingerprinted -- never a silent fallback."""
    from . import formats as _formats
    from .formats import fingerprint as _fp
    from .formats import known as _known
    try:
        catalog = _formats.load(None)
        table = _fp.load_magic()
        known = _known.load()               # B-087: the known-format DB, loaded once for every member
    except (_formats.CatalogError, _formats.corpus.CorpusError, _fp.MagicError, _known.KnownError) as e:
        notes.append(f"format_fingerprint not run: {type(e).__name__}: {e}")
        return []
    member_of: dict = {}
    for entry in manifest:
        member_of.setdefault(entry.sha256, entry.chain[-1])
    leads = []
    for digest, data in blobs.items():
        name = member_of.get(digest, "member")
        res = _fp.analyze(name, data, catalog=catalog, magic_table=table, known=known)   # offline: client=None
        if res.named or not res.candidates:
            continue
        fp = res.fp
        leads.append({
            "sha256": digest, "member": name,
            "entropy": None if fp is None else fp.entropy,
            "stride": None if fp is None else fp.stride,
            "candidates": [{"source": c.source, "label": c.label, "tool": c.tool, "why": c.why,
                            "score": c.score, "ref": c.ref} for c in res.candidates],
        })
        top = res.candidates[0]
        notes.append(f"format_fingerprint: {name!r} unnamed by identify; likely {top.label}"
                     + (f" (tool: {top.tool})" if top.tool else "")
                     + f" -- {top.why} <unsure lead>")
    leads.sort(key=lambda row: row["member"] or "")
    return leads


# B-074: an encrypted archive whose password is in the handout. expand() leaves a note when no known
# password opens a member; we then harvest candidates from the corpus bytes (appended overlay, readable
# strings, sibling files -- all of which are in blobs/sources), add the new ones to the password store,
# and re-unpack once so the now-known password opens the archive and the flag inside is swept.
_LOCKED_NOTE = "no known archive password opens"


def _harvest_into_store(blobs: dict, sources: list, notes: list) -> list:
    hv, pw = _harvest(), _passwords()
    cands, seen = [], set()
    for data in list(blobs.values()) + [d for _rel, d in sources]:
        for c in hv.from_bytes(data):
            if c not in seen:
                seen.add(c)
                cands.append(c)
    # B-068: a cross-file join (a GUID / key / password in a LNK, hive, pcap, pax xattr, shell history
    # or a static PowerShell recipe) is another candidate source for the same locked member. It is
    # best-effort and fully guarded: a reader fault never stops the string harvest above.
    files = dict(blobs)
    files.update({rel: d for rel, d in sources})
    try:
        for c in _ledger().harvest_candidates(files):
            if c not in seen:
                seen.add(c)
                cands.append(c)
    except Exception as e:                       # noqa: BLE001
        notes.append(f"evidence-ledger join skipped ({type(e).__name__})")
    new = pw.add_many(cands, source="harvest-sweep")
    if new:
        notes.append(f"harvested {len(new)} new candidate password(s) from the corpus "
                     f"(appended bytes / strings / sibling files / cross-file join); re-swept")
    return new


# ---------------------------------------------------------------- what is swept, and where it goes

@dataclass
class Target:
    root: Path                       # the folder results are reported against (paths are relative to it)
    sources: Path                    # the folder (or file) holding the originals
    out: Path                        # the scratch copy
    brief: str = ""
    category: str = ""
    challenge_id: str | None = None
    kind: str = "folder"             # pulled | drop | folder | file


def _slug(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-.")
    return s[:48] or "target"


def _inside(a: Path, b: Path) -> bool:
    """a is b or lies under b."""
    try:
        a.relative_to(b)
        return True
    except ValueError:
        return False


def resolve_target(path: str | Path, out: str | Path | None = None, brief: str | None = None) -> Target:
    """What to sweep and where its scratch copy goes. Raises SweepError for a target that is not there
    or an out folder that overlaps the originals."""
    p = Path(path).expanduser()
    if p.is_symlink() or not p.exists():
        raise SweepError(f"sweep target {p} is not there (or is a symbolic link)")
    p = p.resolve()
    if any(d in p.parts for d in SECRET_DIRS) or (p.is_file() and _secret_file(p.name)):
        raise SweepError(f"sweep target {p} is or lies in a credentials store (.ctf/, .git/, .env): never "
                         f"read (for a git-forensics handout, sweep its archive or a copy of the objects)")
    if p.is_dir() and (p / "files").is_dir() and (p / "challenge.json").is_file():
        try:
            detail = json.loads((p / "challenge.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise SweepError(f"{p / 'challenge.json'} does not read as JSON ({type(e).__name__})") from e
        t = Target(root=p, sources=p / "files", out=p / "unpacked", kind="pulled",
                   brief=str(detail.get("description") or ""), category=str(detail.get("category") or ""),
                   challenge_id=str(detail["id"]) if detail.get("id") is not None else None)
    elif p.is_dir():
        t = Target(root=p, sources=p, out=Path(), kind="folder")
        meta = p / "challenge.toml"
        if meta.is_file() and not meta.is_symlink():
            try:
                info = tomllib.loads(meta.read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                raise SweepError(f"{meta} does not read as TOML ({type(e).__name__}: {e})") from e
            t.kind, t.challenge_id = "drop", p.name
            t.brief, t.category = str(info.get("description") or ""), str(info.get("category") or "")
    else:
        t = Target(root=p.parent, sources=p, out=Path(), kind="file")
    if out is not None:
        t.out = Path(out).expanduser().resolve()
    elif t.kind != "pulled":
        tag = hashlib.sha256(str(p).encode()).hexdigest()[:8]
        t.out = _paths.workdir() / "sweep" / f"{_slug(p.name)}-{tag}"
    # A folder's scratch copy may not lie in it, and no original may lie in the scratch folder (the next
    # sweep clears it). A bare file's scratch folder may sit beside it, never around it.
    if (t.sources.is_dir() and _inside(t.out, t.sources)) or _inside(t.sources, t.out):
        raise SweepError(f"the scratch folder {t.out} overlaps the originals in {t.sources}: "
                         f"the sweep never unpacks in place")
    if brief is not None:
        t.brief = brief
    return t


def _secret_file(name: str) -> bool:
    return name == ".env" or name.startswith(".env.")


def is_secret_file(name: str) -> bool:
    """True for a file name the sweep never reads (`.env`, `.env.*`): the public form of its name fence,
    for an engine that walks a challenge folder itself (B-060)."""
    return _secret_file(name)


def read_sources(t: Target, notes: list) -> list[tuple[str, bytes]]:
    """[(path relative to the sources, bytes)] of every regular file, sorted. Links are never followed;
    secret-bearing folders (SECRET_DIRS) are never read, nor .env files outside a pulled challenge's
    files/ (the platform's download there, so challenge data); at most MAX_SOURCE bytes of one
    file and MAX_SOURCE_TOTAL in all are read, and each file left out is a line in `notes`."""
    if t.sources.is_file():
        files = [(t.sources.name, t.sources)]
    else:
        files = []
        for folder, dirs, names in os.walk(t.sources):
            here = Path(folder)
            for d in list(dirs):
                rel = (here / d).relative_to(t.sources).as_posix()
                if (here / d).is_symlink():
                    dirs.remove(d)
                    notes.append(f"ignored {rel!r}: a symbolic link")
                elif d in SECRET_DIRS:
                    dirs.remove(d)
                    if d == _handoutgit.GIT_DIR and t.kind == "pulled":
                        # B-070: the platform's download, so challenge data. Its raw files stay out of the
                        # flag sweep and the scratch copy; the handout-git step reads the repository.
                        notes.append(f"left out of the flag sweep {rel!r}: a git directory (deflated objects); "
                                     f"the handout-git step reads the repository")
                    else:
                        notes.append(f"not read {rel!r}: a folder that may hold credentials"
                                     + (" (a git handout is read from its archive, or from a pulled challenge's "
                                        "files/)" if d == _handoutgit.GIT_DIR else ""))
            for n in names:
                f = here / n
                rel = f.relative_to(t.sources).as_posix()
                if n in JUNK or n.startswith("._") or (t.kind == "drop" and rel in DROP_META):
                    continue
                if f.is_symlink():
                    notes.append(f"ignored {rel!r}: a symbolic link")
                    continue
                if _secret_file(n) and t.kind != "pulled":
                    notes.append(f"not read {rel!r}: a file that may hold credentials")
                    continue
                if f.is_file():
                    files.append((rel, f))
        files.sort()
    out, total = [], 0
    for rel, f in files:
        size = f.lstat().st_size
        if size > MAX_SOURCE:
            notes.append(f"not read {rel!r}: {size} bytes is over the source limit of {MAX_SOURCE}")
            continue
        if total + size > MAX_SOURCE_TOTAL:
            notes.append(f"not read {rel!r}: {size} more bytes would pass the sources' total budget of "
                         f"{MAX_SOURCE_TOTAL} ({total} read)")
            continue
        with open(f, "rb") as fh:
            data = fh.read(MAX_SOURCE + 1)        # a file that grew since lstat is still capped
        if len(data) > MAX_SOURCE or total + len(data) > MAX_SOURCE_TOTAL:
            notes.append(f"not read {rel!r}: it grew past the source budget while being read")
            continue
        total += len(data)
        out.append((rel, data))
    return out


# ---------------------------------------------------------------- the scratch copy

def _prepare_out(out: Path, ut) -> None:
    """Make `out` an empty scratch folder. A folder that holds anything and is not a sweep's own (no
    OWNER file) is refused: the sweep never deletes files it did not write."""
    if out.is_symlink():
        raise SweepError(f"the scratch folder {out} is a symbolic link")
    if out.exists():
        if not out.is_dir():
            raise SweepError(f"the scratch folder {out} is a file")
        left = [e.name for e in os.scandir(out) if e.name != ut.LOCK]
        if left and not (out / OWNER).is_file():
            raise SweepError(f"{out} holds files and is not a sweep's scratch folder (no {OWNER}); "
                             f"remove it or pass another out folder")
        ut.clear(out)
    else:
        out.mkdir(parents=True, mode=0o755)
    ut.write_file(out / OWNER, b"ctf sweep scratch copy: everything here is rewritten by the next sweep\n")


def _disk_name(chain: tuple) -> str:
    """The scratch path of a member: every archive on its chain becomes '<name>.unpacked/'."""
    return "/".join([c + SUFFIX for c in chain[:-1]] + [chain[-1]])


@dataclass
class Entry:
    chain: tuple
    sha256: str
    size: int
    path: str | None                 # in the scratch copy, relative to the target root; None = not written
    kind: str = ""
    original: bool = False

    def to_dict(self) -> dict:
        return {"chain": " -> ".join(self.chain), "sha256": self.sha256, "size": self.size, "path": self.path,
                "kind": self.kind, "original": self.original}


def _rel(p: Path, root: Path) -> str:
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return str(p)


def unpack(t: Target, sources: list, walk, notes: list, git=None) -> tuple[list[Entry], dict]:
    """Write the scratch copy. ([Entry], {sha256: bytes}) of every original and member. `git` (a
    ctf.handoutgit.Step, B-070) is run over everything unpacked; what it exports is unpacked in turn and
    searched for repositories again, handoutgit.MAX_DEPTH passes in all."""
    ae, ut = archive_expand(), _unpack_tools()
    _prepare_out(t.out, ut)
    tree = ut.Tree(t.out, t.out, reserved=(OWNER, REPORT, ut.LOCK))
    entries, blobs, written = [], {}, []

    def put(chain: tuple, data: bytes, original: bool):
        digest = hashlib.sha256(data).hexdigest()
        blobs.setdefault(digest, data)
        where = None
        try:
            path, _n = tree.path_for(_disk_name(chain))
            ut.write_file(path, data)
            where = _rel(path, t.root)
        except ut.Skip as e:
            notes.append(f"not written {' -> '.join(chain)!r}: {e}")
        entries.append(Entry(chain, digest, len(data), where, original=original))
        written.append((chain, data))

    def deepen(rows: list):
        """What the archive walk does not open, until a round adds nothing. B-029: files of a disk image
        (deleted ones too) and both views of a tracked-change document. B-070: archives carved out of
        images, back through the walk. A carved row is recovered and carved in the next round, once."""
        pending = rows
        for _round in range(DEEPEN):
            if not pending:
                return
            more = list(_recover.cascade(pending, walk, notes, ae))
            carved = _polycarve.cascade(pending + more, walk, notes, ae)
            for chain, body in more + carved:
                put(chain, body, False)
            pending = carved
        if pending:
            notes.append(f"{' -> '.join(pending[0][0])!r} and {len(pending) - 1} more carved member(s) were not "
                         f"searched for further images or archives (limit of {DEEPEN} rounds)")

    def opened(name: str, data: bytes, chain: tuple) -> list:
        """The walk's rows for one content, under `chain` (the content's own row first)."""
        ae.expand(name, data, {}, opts=walk)
        rows = [(chain + tuple(c)[1:], bytes(body)) for c, _key, body in (walk.rows or [])]
        walk.rows = None
        return rows or [(chain, data)]

    for rel, data in sources:
        put((rel,), data, True)
        rows = opened(rel, data, (rel,))
        for chain, body in rows[1:]:
            put(chain, body, False)
        deepen(rows)
    if git is not None:
        # B-070: repositories among the members (and a pulled files/.git). Only what the step derives is
        # written; a blob it exports is opened by the walk, recovered and carved like any other member.
        # What one pass adds is searched for repositories again (a repository in a deleted zip, or in an
        # archive carved from an image in history), MAX_DEPTH passes in all.
        found = git.run(list(written), walk, notes)
        for depth in range(1, _handoutgit.MAX_DEPTH + 1):
            start = len(written)
            for chain, body, opens in found:
                put(chain, body, False)
                if not opens:
                    continue
                rows = opened(chain[-1], body, chain)
                for sub, inner in rows[1:]:
                    put(sub, inner, False)
                deepen(rows)
            added = written[start:]
            if not added:
                break
            if depth == _handoutgit.MAX_DEPTH:
                left = _handoutgit.holding(added)
                if left:
                    notes.append(f"git handout: {left[0]!r} and {len(left) - 1} more place(s) inside what the "
                                 f"step exported may hold a repository; not read (limit of "
                                 f"{_handoutgit.MAX_DEPTH} passes)")
                break
            found = git.more(added, walk, notes)
    notes.extend(walk.notes)
    walk.notes.clear()
    return entries, blobs


# ---------------------------------------------------------------- the flag sweep

@dataclass
class Hit:
    flag: str
    method: str                      # plain | utf-16le | utf-16be | decode:<enc> | url+decode:<enc> | ...
    sha256: str
    offset: int | None = None


def _windows(data: bytes):
    if len(data) <= WINDOW:
        yield 0, data
        return
    step = WINDOW - OVERLAP
    for at in range(0, len(data), step):
        yield at, data[at:at + WINDOW]
        if at + WINDOW >= len(data):
            break


def _decoded_tokens(data: bytes, ed, ff) -> list[tuple[str, int, bytes]]:
    """[(encoding, offset, decoded bytes)] of every embedded token in data (all four base64 alignments,
    embedded_decode's opt-in pass). The event's pattern is passed in: the sweep never reads the active
    event, so `--event` holds with CTF_EVENT unset."""
    out, seen = [], set()
    for at, chunk in _windows(data):
        for b in ed.find_blobs(chunk, min_printable=0.0, max_results=1 << 20, flag_re=ff.bregex,
                               alignments=True):
            key = (at + b["offset"], bytes(b["decoded"]))
            if key not in seen:
                seen.add(key)
                out.append((b["encoding"], at + b["offset"], bytes(b["decoded"])))
    return out


def scan(data: bytes, digest: str, ff, ed) -> list[Hit]:
    """Every flag in the event format that one content holds, plainly or under one or two encodings."""
    hits = []
    data = data[:SCAN_CAP]
    for m in ff.bregex.finditer(data):
        hits.append(Hit(m.group(0).decode("latin-1"), "plain", digest, m.start()))
    if b"\x00" in data[:UTF16_CAP]:
        for enc in ("utf-16-le", "utf-16-be"):
            for start in (0, 1):
                text = data[start:UTF16_CAP].decode(enc, "replace")
                for m in ff.regex.finditer(text):
                    hits.append(Hit(m.group(0), enc.replace("-", ""), digest, start + 2 * m.start()))
    layers = [("", data)]
    if b"%" in data:
        unq = urllib.parse.unquote_to_bytes(data)
        if unq != data:
            layers.append(("url+", unq))
            for m in ff.bregex.finditer(unq):
                hits.append(Hit(m.group(0).decode("latin-1"), "url", digest, None))
    # TODO(B-163): the URL layer and the one nested level below are local to the sweep; the shared codec
    # graph should own layered decodes so every caller of embedded_decode gets them.
    for tag, layer in layers:
        tokens = _decoded_tokens(layer, ed, ff)
        for enc, off, dec in tokens:
            found = ff.find_flags(dec)
            for f in found:
                hits.append(Hit(f, f"{tag}decode:{enc}", digest, off if not tag else None))
            if not found and enc in _recover.xorcrib.ENCODINGS:     # B-029: a hex/base64 run under a one-byte key
                for key, _at, f in _recover.xorcrib.single_byte(dec, ff):
                    hits.append(Hit(f, f"{tag}decode:{enc}>xor:0x{key:02x}", digest, off if not tag else None))
        nested = [t for t in tokens if not ff.find_flags(t[2]) and len(t[2]) >= 16][:NESTED_TOKENS]
        for enc, off, dec in nested:
            for enc2, _off2, dec2 in _decoded_tokens(dec, ed, ff):
                for f in ff.find_flags(dec2):
                    hits.append(Hit(f, f"{tag}decode:{enc}>{enc2}", digest, off if not tag else None))
    return hits


def _placeholder(flag: str) -> bool:
    body = flag[flag.index("{") + 1:-1]
    return body.lower() in PLACEHOLDER_WORDS or _PLACEHOLDER_CHARS.fullmatch(body) is not None


# ---------------------------------------------------------------- the report

@dataclass
class Report:
    target: Target
    manifest: list[Entry]
    flags: dict                      # normalized flag -> [Hit]
    joins: list                      # [fragjoin.Join, sha256]
    excluded: dict                   # normalized flag -> reason
    triage: dict
    notes: list
    result: SolverResult
    seconds: float = 0.0
    extra: dict = field(default_factory=dict)
    disputed: dict = field(default_factory=dict)     # normalized flag -> {"why", "engine"} (B-132, _disputes)

    def to_dict(self) -> dict:
        locs = self._locations()
        return {
            "schema": SCHEMA, "engine": ENGINE, "target": str(self.target.root), "kind": self.target.kind,
            "sources": _rel(self.target.sources, self.target.root) or ".", "out": str(self.target.out),
            "challenge_id": self.target.challenge_id, "seconds": round(self.seconds, 3),
            "manifest": [e.to_dict() for e in self.manifest],
            "flags": {f: [{"method": h.method, "offset": h.offset, "sha256": h.sha256,
                           "where": locs.get(h.sha256, [])} for h in hits] for f, hits in self.flags.items()},
            "joins": [{"flag": j.flag, "sha256": d, "where": locs.get(d, []),
                       "parts": [{"container": p.container, "name": p.name, "text": p.text} for p in j.parts]}
                      for j, d in self.joins],
            "excluded": self.excluded,
            "disputed": self.disputed,
            "triage": {"category": self.triage.get("category"), "engines": self.triage.get("engines", []),
                       "files": [list(x) for x in self.triage.get("files", [])]},
            "fingerprint": self.extra.get("fingerprint", []),       # B-207: unsure format leads for unnamed members
            "git": self.extra.get("git", []),                       # B-070: one summary per handout repository
            "notes": self.notes,
            "result": json.loads(self.result.to_json()),
        }

    def _locations(self) -> dict:
        locs = {}
        for e in self.manifest:
            locs.setdefault(e.sha256, []).append(" -> ".join(e.chain))
        return locs

    def render(self) -> str:
        r = self.result
        lines = [f"sweep: {r.status}  members={sum(not e.original for e in self.manifest)} "
                 f"originals={sum(e.original for e in self.manifest)} scratch={self.target.out}"]
        locs = self._locations()
        for f, hits in self.flags.items():
            h = hits[0]
            lines.append(f"  flag {f}  via {h.method} in {(locs.get(h.sha256) or ['?'])[0]}"
                         + (f" @0x{h.offset:x}" if h.offset is not None else "")
                         + (f"  (+{len(hits) - 1} more)" if len(hits) > 1 else ""))
        for j, d in self.joins:
            lines.append(f"  joined {j.flag}  from {' + '.join(p.container + ':' + p.name for p in j.parts)}"
                         f" in {(locs.get(d) or ['?'])[0]}")
        for f, why in self.excluded.items():
            lines.append(f"  excluded {f}: {why}")
        for n in self.notes[:20]:
            lines.append(f"  note: {n}")
        if len(self.notes) > 20:
            lines.append(f"  note: ... {len(self.notes) - 20} more in {self.target.out / REPORT}")
        return "\n".join(lines)


def _disputes(flags: dict, manifest: list, doubt: dict) -> dict:
    """B-132. {flag: {"why", "engine"}} for every flag found only in members the walk marks as where
    decoys sit (Walk.doubt: a TI-Nspire document page) and in the containers around such a member
    that holds it too (a stored page shows its bytes in its container). A flag also found anywhere
    else (a script, another file) is not disputed."""
    if not doubt:
        return {}
    chains = {}
    for e in manifest:
        chains.setdefault(e.sha256, []).append(tuple(e.chain))
    out = {}
    for f, hits in flags.items():
        seen = {c for h in hits for c in chains.get(h.sha256, [])}
        doubtful = [c for c in seen if c in doubt]
        if not doubtful:
            continue
        if all(c in doubt or any(len(d) > len(c) and d[:len(c)] == c for d in doubtful) for c in seen):
            why, engine = doubt[sorted(doubtful)[0]]
            out[f] = {"why": f"only in {why}: {' -> '.join(sorted(doubtful)[0])}", "engine": engine}
    return out


def _result(t: Target, flags: dict, joins: list, manifest: list, seconds: float, disputed=None) -> SolverResult:
    locs = {}
    for e in manifest:
        locs.setdefault(e.sha256, e)
    evidence = []
    for f, hits in flags.items():
        h, e = hits[0], locs.get(hits[0].sha256)
        evidence.append(Evidence(h.method if h.method == "plain" else "decode",
                                 f"{f} via {h.method} in {' -> '.join(e.chain) if e else h.sha256}",
                                 path=e.path if e else None, offset=h.offset))
    for j, d in joins:
        e = locs.get(d)
        evidence.append(Evidence("join", f"{j.flag} joined from "
                                 + " + ".join(f"{p.container}:{p.name}" for p in j.parts)
                                 + (f" in {' -> '.join(e.chain)}" if e else ""), path=e.path if e else None))
    found = list(flags)
    joined = [j.flag for j, _ in joins if j.flag not in flags]
    common = dict(engine=ENGINE, challenge_id=t.challenge_id, cost=Cost(seconds=round(seconds, 3)),
                  evidence=evidence)
    if len(found) == 1 and disputed and found[0] in disputed:
        return SolverResult("candidate", flags=found + joined,
                            notes=f"one distinct flag in the corpus, found {disputed[found[0]]['why']}: a possible "
                                  f"decoy, not proven ({disputed[found[0]]['engine']} can settle it)", **common)
    if len(found) == 1:
        more = f"; {len(joined)} other value(s) joined from metadata fragments" if joined else ""
        return SolverResult("solved", flags=found, notes="one distinct flag in the corpus" + more, **common)
    if found:
        return SolverResult("candidate", flags=found + joined,
                            notes=f"{len(found)} distinct flags in the corpus: decoys are possible", **common)
    if joined:
        return SolverResult("candidate", flags=joined, notes="joined from split metadata fragments", **common)
    return SolverResult("none", engine=ENGINE, challenge_id=t.challenge_id, cost=Cost(seconds=round(seconds, 3)),
                        notes="no flag in the event format in any original or member")


def sweep(target: str | Path, profile, *, out: str | Path | None = None, brief: str | None = None,
          walk=None) -> Report:
    """Run the whole sweep on `target` for the event `profile` and write `<out>/.sweep.json`."""
    started = time.monotonic()
    t = resolve_target(target, out=out, brief=brief)
    ff = _flagfmt.for_profile(profile)
    ed, ident = _embedded(), _identify()
    ae = archive_expand()
    walk = walk or ae.Walk()
    notes = []
    sources = read_sources(t, notes)
    loose_git = _handoutgit.loose(t, notes)      # B-070: a .git inside a pulled challenge's files/, else []
    if not sources and not loose_git:
        if notes:
            raise SweepError(f"no file to sweep under {t.sources}: every file was left out ("
                             + "; ".join(notes[:5]) + (f"; {len(notes) - 5} more" if len(notes) > 5 else "") + ")")
        raise NothingToSweep(f"no file to sweep under {t.sources}")
    ut = _unpack_tools()
    if t.out.is_symlink() or (t.out.exists() and not t.out.is_dir()):
        raise SweepError(f"the scratch folder {t.out} is a symbolic link or a file")
    t.out.mkdir(parents=True, exist_ok=True, mode=0o755)
    with ut.Locked(t.out):
        git = _handoutgit.Step(ff, ed, loose_git)
        manifest, blobs = unpack(t, sources, walk, notes, git)
        used = walk
        if any(_LOCKED_NOTE in n for n in notes) and _harvest_into_store(blobs, sources, notes):
            walk2 = ae.Walk(max_member=walk.max_member, max_total=walk.max_total,
                            max_members=walk.max_members, max_depth=walk.max_depth)
            manifest, blobs = unpack(t, sources, walk2, notes, git)
            used = walk2
        for e in manifest:
            try:
                e.kind = str(ident(blobs[e.sha256], e.chain[-1]))[:120]
            except Exception as exc:     # one content the reader cannot name: said, never blank
                e.kind = f"identify() raised {type(exc).__name__}"
        from . import triage as _triage
        tri = _triage.suggest(t.category, t.brief, t.out)
        tri["files"] = [x for x in tri.get("files", []) if not x[0].startswith((OWNER, REPORT, ut.LOCK))]
        in_brief = {_norm(ff, f) for f in ff.find_flags(t.brief)} if t.brief else set()
        flags, excluded, joins = {}, {}, []
        for digest, data in blobs.items():
            for h in scan(data, digest, ff, ed):
                key = _norm(ff, h.flag)
                if key is None:
                    continue
                why = _excluded(key, in_brief)
                if why:
                    excluded.setdefault(key, why)
                    continue
                flags.setdefault(key, []).append(h)
            for j in _fragjoin.join(_fragjoin.fields(data), ff):
                key = _norm(ff, j.flag)
                if key is None:
                    continue
                why = _excluded(key, in_brief)
                if why:
                    excluded.setdefault(key, why)
                elif all(key != _norm(ff, x.flag) for x, _ in joins):
                    joins.append((j, digest))
        for j, digest in git.joins:              # B-070: numbered fragments of a git handout, by position
            key = _norm(ff, j.flag)
            if key is None:
                continue
            why = _excluded(key, in_brief)
            if why:
                excluded.setdefault(key, why)
            elif all(key != _norm(ff, x.flag) for x, _ in joins):
                joins.append((j, digest))
        # The best witness first: a plain match before a decode, and the innermost member holding it
        # before the archive around it (a stored zip shows its members' bytes too).
        depth = {}
        for e in manifest:
            depth[e.sha256] = max(depth.get(e.sha256, 0), len(e.chain))
        for hits in flags.values():
            hits.sort(key=lambda h: (h.method != "plain", -depth.get(h.sha256, 0), h.method))
        flags = _rank_revisions(flags, manifest, t.brief, notes, excluded)
        if not ff.known:
            notes.append("no single-byte XOR crib: the event's flag prefixes are not known yet")
        fingerprints = fingerprint_unnamed(blobs, manifest, notes)
        seconds = time.monotonic() - started
        disputed = _disputes(flags, manifest, getattr(used, "doubt", None) or {})
        result = _result(t, flags, joins, manifest, seconds, disputed)
        rep = Report(t, manifest, flags, joins, excluded, tri, notes, result, seconds,
                     extra={"fingerprint": fingerprints, "git": git.repos}, disputed=disputed)
        ut.write_file(t.out / REPORT, (json.dumps(rep.to_dict(), indent=1) + "\n").encode())
    return rep


def _rank_revisions(flags: dict, manifest: list, brief: str, notes: list, excluded: dict) -> dict:
    """B-029: a flag with XML markup inside whose tag-free text is another found flag is excluded (a grep
    across `<w:r>` runs); then flags seen only through a tracked change first, and the brief's side of a
    redline before the other (ctf.recover.ooxml.rank); otherwise the order found."""
    for f, clean in _recover.ooxml.markup_twins(list(flags)).items():
        excluded.setdefault(f, f"XML markup inside it: {clean} reads whole from the document's text")
        del flags[f]
    chains = {}
    for e in manifest:
        chains.setdefault(e.sha256, []).append(" -> ".join(e.chain))
    seen = {f: {v for h in hits for c in chains.get(h.sha256, []) if (v := _recover.ooxml.view_of(c))}
            for f, hits in flags.items()}
    order, note = _recover.ooxml.rank(seen, brief)
    if note and order != list(flags):
        notes.append(note)
    return {f: flags[f] for f in order}


def _norm(ff, flag: str):
    try:
        return ff.normalize(flag)
    except ValueError:
        return None


def _excluded(flag: str, in_brief: set) -> str | None:
    if flag in in_brief:
        return "appears verbatim in the challenge brief (template text)"
    if _placeholder(flag):
        return "its body is a placeholder"
    return None
