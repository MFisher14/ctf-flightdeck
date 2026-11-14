#!/usr/bin/env python3
"""Write a saved delivery's members to disk, so an agent can read them. Offline: no Game Master
request, no token.

Usage:
  python3 tools/unpack.py <file>          recursively unpack one archive/envelope into <file>.unpacked/
  python3 tools/unpack.py <attempt dir>   unpack a saved attempt's deliveries into its members/ folder
  python3 tools/unpack.py --lane LANE --day N [--mode base|time_trial|mastery]

A saved attempt holds only what was delivered: artifact/evidence.zip, artifact/blob.txt, or
artifact/delivery-NN/<file> when there are several deliveries. An agent reads specimens with
the Read tool, which cannot look inside an archive, and a background agent cannot be asked to
approve an ad-hoc `unzip`. This tool writes the members next to the artifact, so reading them
is one allowed command.

  <attempt dir>   Any folder that has an artifact/ folder: a saved attempt, or one of its
                  earlier variants under history/<attempt id>/.
  --lane, --day   Find the folder through the opener's handoff file
                  <CHALLENGES>/day-NN/_open/<lane>.json: its ids[<mode>] (for the base also
                  base_id) names the folder <CHALLENGES>/day-NN/<id>/.
  --mode          base (the default), time_trial or mastery. Without --mode the base is unpacked
                  also when the lane stopped at its Time Trial (state STOP, the base CORRECT,
                  the Time Trial not, a Time Trial variant on disk); one line on stderr then
                  says that the variant to read is the Time Trial's and how to unpack it.

What is written. Every delivery goes through run.expand(<file name>, <bytes>, out), the reader
tools/run.py builds a solver's `files` with, so what lands on disk is what the solver is
handed: every member of the archive, of archives inside it, of an APK or a JAR, and of an
encrypted zip that `infected` or a password in <challenges>/_passwords.json opens (tools/password.py). Each member is written once, under its own name. The
delivery file itself is written only when it held no members (a blob.txt).

Same name twice. `files` holds a member under "<archive> -> <member>" and, for the first
member of that name, under the name alone. A Mastery bundle of evidence-01.zip, evidence-02.zip,
... repeats every specimen name, so the later ones exist only under the arrow keys. They are
written too, by the rule for two members on one path: resource-sample.ps1 is the one from
evidence-01.zip, resource-sample~2.ps1 the one from evidence-02.zip. One line on stderr per
archive says so.

Where. <attempt dir>/members/ when the delivery is a file directly under artifact/, and
<attempt dir>/members/delivery-NN/ for artifact/delivery-NN/<file>.

Member names are untrusted. An output path is built from the name's '/'-separated components:
empty ones, '.' and '..' are dropped, every character outside [A-Za-z0-9._+@=-] becomes '_',
and a component is cut to 120 characters. A component named CLAUDE.md, CLAUDE.local.md,
AGENTS.md, .claude or .mcp.json (any case) gets a leading '_', so the agent harness never
loads a member as project instructions or settings: such a file is specimen text, read like
any other member. A member whose path is already taken (also when the
two differ only in case: this Mac's file system ignores it) gets ~2, ~3, ... before its
extension. No symbolic link is created or followed: an archive entry stored as a link becomes
a plain file holding the link's text. A member over 64 MB is skipped; writing stops at 2,000
members or 512 MB. That budget is spent breadth first (backlog row 117): the delivery's own
members, then the entries of an archive inside it, then the next level, so a fat jar never keeps
the day's new sample off the disk; of an archive inside an archive at most 600 members are
written, and one line per such archive says how many were not. Files are written through a temporary file and os.replace, with mode 0644.
Nothing from an archive is run or handed to another program by this tool. (run.expand itself
falls back to 7-Zip for an archive the Python libraries cannot read, exactly as on a live run.)

Running it again. members/.source.json records {delivery path under artifact/: sha256} for
what was unpacked, and members/.members.json {member path: sha256} for what was written. While
the first equals what is under artifact/ now and every member of the second is still on disk
with those bytes, nothing is written and the listing is printed from disk, so several agents
may run this at the same moment (they take turns on members/.lock). When the delivery differs
(a retry replaced the variant), a member was removed or edited since, or the last unpack met an
archive no known password opened (a password may have been added since), everything under
members/ is removed and the delivery is unpacked again. Nobody else should write under
members/: a file put there is listed while the members are intact and removed with them.

Output, on stdout:

  <the members folder, absolute>
  <path under members/>  <bytes>  <first 16 hex digits of the sha256>      one per member, sorted
  UNPACK dir=<members folder> members=<n> bytes=<n> deliveries=<n> fresh=<true|false>

`fresh` is true when this run wrote the files. A member that was skipped, a stop at a limit,
an archive whose members were renamed with ~N, and a delivery that looks like an archive but
gave no member (another password, or damaged), is one line on stderr starting `unpack: `;
those lines are kept in members/.notes.txt and printed again by every later run.

It reads artifact/ and the handoff file and writes only under members/. artifact/ is never
touched.

Exit status: 0 the members are on disk; 2 no handoff file, no such id, no artifact/ folder or
no delivery in it; 64 a usage error; 1 anything else (a file could not be written, tools/run.py
did not load). Every failure is one line on stderr. Where nothing is on disk because the
attempt was not started, the line says so: a timed attempt is saved when its clock starts,
and an untimed base when it is started; for a base the opener did not start (a lane with no
registered solver) that is `tools/verify.py <base id> <solver> --start`, which needs a solver
file (a stub whose solve_set returns {} will do). That command is named only for the folder
the opener leaves for such a lane (it holds status.json). Any other base folder of a day
that holds no attempt yet is a registered lane's, made by the tool that is starting the base
at that moment: the line says to run this again, and names no command (the opener or the
lane's owner starts that base; a second start by whoever reads the line is not wanted). A
folder that is no attempt's at all (the day's folder, a wrong path) gets the plain line.
"""
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import time
import zipfile
from pathlib import Path

USAGE = "usage: unpack.py <file-or-attempt-dir> | unpack.py --lane LANE --day N [--mode base|time_trial|mastery]"
MODES = ("base", "time_trial", "mastery")
EX_USAGE, EX_MISSING, EX_FAILED = 64, 2, 1

MAX_MEMBER = 64 * 1024 * 1024     # a member larger than this is skipped
MAX_NESTED = 600                  # of an archive INSIDE an archive (a jar in evidence.zip), at most this many members
MAX_MEMBERS = 2000                # writing stops at this many members ...
MAX_TOTAL = 512 * 1024 * 1024     # ... or at this many bytes, over all deliveries of the attempt
MAX_COMPONENT = 120               # characters kept of one path component
MAX_PATH = 1000                   # a longer output path is skipped (the file system allows 1024)
LOCK_WAIT = 120.0                 # longest wait for another unpack of the same attempt
LOCK_POLL = 0.05

SOURCE, LOCK, NOTES, WRITTEN = ".source.json", ".lock", ".notes.txt", ".members.json"
PASSWORD_NOTE = "no known archive password opens it"   # in .notes.txt: the next run unpacks again
RESERVED = (SOURCE, LOCK, NOTES, WRITTEN)  # this tool's own files, directly under members/
ARCHIVE_MAGIC = (b"PK\x03\x04", b"7z\xbc\xaf\x27\x1c")   # what run.expand opens as an archive
UNSAFE = re.compile(r"[^A-Za-z0-9._+@=-]")
# Names an agent harness loads by itself, as instructions or settings, when a file beside them is
# read. A member is never left on disk under one of them (compared without regard to case).
HARNESS = ("claude.md", "claude.local.md", "agents.md", ".claude", ".mcp.json")
TIMED = ("time_trial", "mastery")         # the folder of a timed attempt, under its base's folder
DAY_FOLDER = re.compile(r"day-\d+")       # <CHALLENGES>/day-NN: a base attempt's folder is directly under it
DELIVERY = re.compile(r"delivery-(\d+)")
LANE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
ID_PART = re.compile(r"[A-Za-z0-9._-]+")
ARROW = " -> "                            # run.expand's "<archive> -> <member>" keys


class Stop(Exception):
    """End the command with one line on stderr and this exit status."""

    def __init__(self, message: str, code: int):
        super().__init__(message)
        self.message, self.code = message, code


class Skip(Exception):
    """This member cannot be written; the reason is printed and the next member is tried."""


def one_line(text) -> str:
    return " ".join(str(text).split())


def shown(name) -> str:
    """An untrusted name, safe to print: quoted, ASCII only, no control characters, not too long."""
    text = json.dumps(str(name))
    return text if len(text) <= 160 else text[:157] + '..."'


# ---------------------------------------------------------------- the command line

def parse(argv: list) -> dict:
    """{'dir': path} or {'lane': ..., 'day': n, 'mode': ..., 'mode_given': bool}. Anything else is
    a usage error."""
    given, positional, i = {}, [], 0
    while i < len(argv):
        arg = argv[i]
        i += 1
        if not isinstance(arg, str):
            raise Stop(f"argument {shown(arg)} is not a string. {USAGE}", EX_USAGE)
        if arg in ("-h", "--help"):
            return {"help": True}
        if arg.startswith("--"):
            name, eq, value = arg[2:].partition("=")
            if name not in ("lane", "day", "mode"):
                raise Stop(f"unknown option {shown(arg)}. {USAGE}", EX_USAGE)
            if not eq:
                if i >= len(argv):
                    raise Stop(f"--{name} needs a value. {USAGE}", EX_USAGE)
                value = argv[i]
                i += 1
            if name in given:
                raise Stop(f"--{name} is given twice. {USAGE}", EX_USAGE)
            given[name] = value
        elif arg.startswith("-") and arg != "-":
            raise Stop(f"unknown option {shown(arg)}. {USAGE}", EX_USAGE)
        else:
            positional.append(arg)
    if positional and given:
        raise Stop(f"give an attempt folder or --lane and --day, not both. {USAGE}", EX_USAGE)
    if positional:
        if len(positional) > 1 or not positional[0]:
            raise Stop(USAGE, EX_USAGE)
        return {"dir": positional[0]}
    if "lane" not in given or "day" not in given:
        raise Stop(USAGE, EX_USAGE)
    if not LANE.fullmatch(given["lane"]):
        raise Stop(f"--lane must be a lane name such as script-analysis, not {shown(given['lane'])}. {USAGE}", EX_USAGE)
    if not re.fullmatch(r"\d{1,2}", given["day"]) or int(given["day"]) < 1:
        raise Stop(f"--day must be a day number, not {shown(given['day'])}. {USAGE}", EX_USAGE)
    mode = given.get("mode", "base")
    if mode not in MODES:
        raise Stop(f"--mode must be one of {', '.join(MODES)}, not {shown(mode)}. {USAGE}", EX_USAGE)
    return {"lane": given["lane"], "day": int(given["day"]), "mode": mode, "mode_given": "mode" in given}


# ---------------------------------------------------------------- the two modules this tool borrows
# Both are imported only when they are needed and never for a usage error: importing gm reads
# the environment (it makes no request and does not read the token), and run imports gm.

def _tools_on_path():
    sys.dont_write_bytecode = True      # importing run and gm must not leave a .pyc in tools/
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)


def _challenges() -> Path:
    """gm.CHALLENGES: where the saved attempts are (also from a linked worktree)."""
    _tools_on_path()
    try:
        import gm
    except Exception as e:      # also a SyntaxError left by a half-made live fix: one line, no traceback
        raise Stop(f"tools/gm.py did not load ({type(e).__name__}: {one_line(e)})", EX_FAILED)
    return Path(gm.CHALLENGES)


def _runner():
    """tools/run.py, for its expand(). Imported, never copied: the solver's `files` and the
    members on disk must come from one reader."""
    _tools_on_path()
    try:
        import run
    except Exception as e:
        raise Stop(f"tools/run.py did not load ({type(e).__name__}: {one_line(e)})", EX_FAILED)
    if not callable(getattr(run, "expand", None)):
        raise Stop("tools/run.py has no expand(name, data, out)", EX_FAILED)
    return run


def _id_folder(day_dir: Path, cid):
    """The folder of a challenge id under the day's folder, or None for a value that is no id.
    The id came from a Game Master response, so it is data: it may name a folder of this day
    (a timed id is '<base id>/time_trial') and nothing else."""
    if not isinstance(cid, str) or not cid:
        return None
    parts = cid.split("/")
    if any(p in (".", "..") or not ID_PART.fullmatch(p) for p in parts):
        return None
    return day_dir.joinpath(*parts)


def stopped_later(h: dict, day_dir: Path):
    """One line for a caller that unpacked the base without asking for it by name, when the
    handoff says the lane is stopped with the base CORRECT and the Time Trial not, and a Time
    Trial variant is on disk: the files to study are that variant's, and the base's are the
    ones the solver already answers. None otherwise (also while the lane is still being
    played: its Time Trial may be running). The Mastery is left out on purpose: a Mastery that
    ended short is reported to the player, not fixed."""
    results, ids = h.get("results"), h.get("ids")
    if h.get("state") != "STOP" or not isinstance(results, dict) or not isinstance(ids, dict):
        return None
    if results.get("base") != "CORRECT" or results.get("time_trial") == "CORRECT":
        return None
    folder = _id_folder(day_dir, ids.get("time_trial"))
    if folder is None or not (folder / "artifact").is_dir():
        return None
    try:
        earlier = sum(1 for p in (folder / "history").iterdir() if (p / "artifact").is_dir())
    except OSError:
        earlier = 0
    more = f"; {earlier} earlier variant(s) are under {folder / 'history'}, each unpacked by its folder" if earlier else ""
    return (f"this is the base, which is CORRECT; the lane stopped with its Time Trial short of CORRECT, and that "
            f"variant is the one to read: add --mode time_trial ({folder}){more}")


def from_handoff(lane: str, day: int, mode: str, mode_given: bool = True) -> tuple:
    """(the attempt folder the opener's handoff file names for this lane and mode, a line to
    print after the listing or None)."""
    day_dir = _challenges() / f"day-{day:02d}"
    handoff = day_dir / "_open" / f"{lane}.json"
    try:
        h = json.loads(handoff.read_bytes())
    except FileNotFoundError:
        # Name the lanes that are open, so that `--lane binary` is corrected in one step.
        try:
            lanes = sorted(p.stem for p in handoff.parent.glob("*.json")
                           if p.stem not in ("day", "state", "journal", "routes_seen") and LANE.fullmatch(p.stem))
        except OSError:
            lanes = []
        there = f"; handoffs there: {', '.join(lanes[:12])}" if lanes else ""
        raise Stop(f"no handoff file {handoff} (the opener has not opened {lane} on day {day}{there})", EX_MISSING)
    except (OSError, ValueError) as e:
        raise Stop(f"handoff file {handoff} cannot be read ({type(e).__name__})", EX_MISSING)
    ids = h.get("ids") if isinstance(h, dict) else None
    cid = ids.get(mode) if isinstance(ids, dict) else None
    if not cid and mode == "base" and isinstance(h, dict):
        cid = h.get("base_id")
    if not isinstance(cid, str) or not cid:
        raise Stop(f"handoff file {handoff} has no {mode} id", EX_MISSING)
    folder = _id_folder(day_dir, cid)
    if folder is None:
        raise Stop(f"handoff file {handoff}: {shown(cid)} is not a challenge id", EX_MISSING)
    if not folder.is_dir():
        # Say what the missing folder means: an agent that reads only "does not exist" looks for
        # a wrong path, when there is simply nothing to read yet.
        why = ("a base is saved when it is started: this one was not" if mode == "base" else
               f"a timed attempt is saved when its clock starts: this {mode} was not started")
        raise Stop(f"no saved attempt for {cid}: {folder} does not exist ({why})", EX_MISSING)
    return folder, (stopped_later(h, day_dir) if mode == "base" and not mode_given else None)


# ---------------------------------------------------------------- what was delivered

def _junk(name: str) -> bool:
    """Files the Finder leaves behind; never a delivery."""
    return name == ".DS_Store" or name.startswith("._")


def _plain_files(folder: Path, notes: list, artifact: Path) -> list:
    """Names of the regular files directly in folder, sorted. A symbolic link is never read."""
    names = []
    with os.scandir(folder) as entries:
        for e in entries:
            if _junk(e.name):
                continue
            if e.is_symlink():
                notes.append(f"ignored {shown((folder / e.name).relative_to(artifact).as_posix())} under artifact/: a symbolic link")
            elif e.is_file(follow_symlinks=False):
                names.append(e.name)
    return sorted(names)


def find_deliveries(artifact: Path, notes: list) -> list:
    """[(group, path under artifact/, file name)], in order. group is '' for a file directly
    under artifact/ (the only delivery) and 'delivery-NN' for artifact/delivery-NN/<file>.
    Other folders under artifact/ (somebody's own unzip) are not deliveries."""
    found = [("", name, name) for name in _plain_files(artifact, notes, artifact)]
    folders = []
    with os.scandir(artifact) as entries:
        for e in entries:
            if DELIVERY.fullmatch(e.name) and e.is_dir(follow_symlinks=False):
                folders.append(e.name)
    for folder in sorted(folders, key=lambda n: (int(DELIVERY.fullmatch(n).group(1)), n)):
        for name in _plain_files(artifact / folder, notes, artifact):
            found.append((folder, f"{folder}/{name}", name))
    if any(g for g, _, _ in found) and any(not g for g, _, _ in found):
        notes.append("artifact/ holds files beside its delivery-NN folders: their members are in members/ itself")
    return found


# ---------------------------------------------------------------- writing under members/

def make_dir(path: Path):
    """Create one folder, or accept one that is already a plain folder. Never a link."""
    try:
        os.mkdir(path, 0o755)
        os.chmod(path, 0o755)
    except FileExistsError:
        pass
    if not stat.S_ISDIR(os.lstat(path).st_mode):
        raise Skip(f"{path.name} on its path is not a plain folder")


def write_file(target: Path, data: bytes):
    """Write data to target through a temporary file in the same folder; mode 0644."""
    n = 0
    while True:
        n += 1
        tmp = target.parent / f".tmp-{os.getpid()}-{n}"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            break
        except FileExistsError:      # a member with that very name is already there: take the next
            if n >= 1000:
                raise
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            os.fchmod(f.fileno(), 0o644)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def components(name) -> list:
    """The path components an untrusted member name is allowed to become."""
    parts = []
    for raw in str(name).split("/"):
        if raw in ("", ".", ".."):
            continue
        part = UNSAFE.sub("_", raw)[:MAX_COMPONENT]
        if part.lower() in HARNESS:     # never on disk under a name the harness reads as instructions
            part = "_" + part
        parts.append(part)
    return parts


class Tree:
    """Where one delivery's members go: hands out a path for each name and never the same twice."""

    def __init__(self, members: Path, root: Path, reserved=()):
        self.members = os.path.realpath(members)
        self.root = root
        self.files = {r.lower() for r in reserved}    # paths taken by a file, lower case
        self.dirs = {}                                # folders this run made: lower case -> the name made

    def _free(self, above: list, part: str, as_dir: bool) -> tuple:
        """(name, n): part, or part with ~n before its extension, so that it does not land on
        a file (for a folder) or on anything at all (for a file)."""
        stem, ext = os.path.splitext(part)
        n, name = 1, part
        while True:
            key = "/".join(above + [name]).lower()
            if key not in self.files and (as_dir or key not in self.dirs):
                return name, n
            n += 1
            name = f"{stem}~{n}{ext}"

    def path_for(self, name) -> tuple:
        """(path, n) for a member name; n is 1, or the ~n its file name was given."""
        parts = components(name)
        if not parts:
            raise Skip("no usable name is left of it")
        if len(str(self.root)) + sum(len(p) + 1 for p in parts) + 8 > MAX_PATH:
            raise Skip("its path is too long")
        above = []
        for part in parts[:-1]:
            name = self._free(above, part, as_dir=True)[0]
            key = "/".join(above + [name]).lower()
            if key in self.dirs:
                # 'dir/b' after 'Dir/a': one folder, under the spelling it was made with, also
                # on a file system that tells the two apart (where 'dir' would not exist).
                name = self.dirs[key]
            else:
                make_dir(self.root.joinpath(*above, name))
                self.dirs[key] = name
            above.append(name)
        folder = self.root.joinpath(*above)
        real = os.path.realpath(folder)
        if real != self.members and os.path.commonpath([real, self.members]) != self.members:
            raise Skip("its path resolves outside the members folder")
        leaf, n = self._free(above, parts[-1], as_dir=False)
        self.files.add("/".join(above + [leaf]).lower())
        return folder / leaf, n


def clear(members: Path):
    """Remove everything under members/ except the lock. Links are removed, never followed.
    The two records go first: a run that dies half way must not leave them saying that the
    members are there."""
    for name in (SOURCE, WRITTEN):
        try:
            os.unlink(members / name)
        except FileNotFoundError:
            pass
        except (IsADirectoryError, PermissionError):
            pass    # a folder of that name: the walk below removes it
    for folder, dirs, files in os.walk(members, topdown=False):
        for name in files:
            if folder == str(members) and name == LOCK:
                continue
            os.unlink(os.path.join(folder, name))
        for name in dirs:
            path = os.path.join(folder, name)
            if os.path.islink(path):
                os.unlink(path)
            else:
                os.rmdir(path)


def split_key(key: str, out: dict) -> tuple:
    """(archive, member name) for one of run.expand's keys; archive is None for a member's own
    name. expand files an archive under its own name before any "<archive> -> <member>" key,
    so the archive is the part before an arrow that is itself a key. The LONGEST such prefix wins:
    a full-path key "outer -> inner -> x" (backlog row 303, where both "outer" and "outer -> inner"
    are keys) is a member of "outer -> inner", not of "outer". A member whose NAME holds ' -> '
    (names are untrusted) is still not taken for a member of something else, because its prefix is
    not a key."""
    at = key.rfind(ARROW)
    while at >= 0:
        if key[:at] in out:
            return key[:at], key[at + len(ARROW):]
        at = key.rfind(ARROW, 0, at)
    return None, key


def nesting(out: dict) -> dict:
    """{id(bytes): (depth, archive key)} for every member run.expand filed under an arrow key:
    how many archives deep the member lies (1 for a member of the delivery, 2 for an entry of an
    archive inside it, ...) and the archive it came from, the shallowest when there are several.

    expand files an inner archive's entries under "<inner archive> -> <entry>", with the inner
    archive named as its own member, so the depth is not the number of arrows in a key: it is one
    more than the depth of the archive's own bytes. A member's own-name key holds the very same
    bytes object as its arrow key, which is how a key without an arrow gets its depth here."""
    holders = {}        # id(member bytes) -> the archive keys it was filed under
    for key, data in out.items():
        if not isinstance(data, (bytes, bytearray)):
            continue
        archive, _ = split_key(key, out)
        if archive is not None and isinstance(out.get(archive), (bytes, bytearray)):
            holders.setdefault(id(data), []).append(archive)
    memo = {}

    def depth(ident, seen) -> tuple:
        if ident not in holders:
            return 0, None
        if ident in memo:
            return memo[ident]
        best = None
        for archive in holders[ident]:
            parent = id(out[archive])
            if parent in seen or len(seen) > 16:
                continue        # an archive that names itself: no deeper than where it was first seen
            d = 1 + depth(parent, seen | {ident})[0]
            if best is None or d < best[0]:
                best = (d, archive)
        memo[ident] = best or (1, holders[ident][0])
        return memo[ident]

    return {ident: depth(ident, frozenset()) for ident in holders}


@contextlib.contextmanager
def _bounded_member_reads(limit: int):
    """While expanding, never fully inflate a ZIP member whose DECLARED uncompressed size is over
    `limit`: such a member is skipped by the write cap anyway, so reading only `limit`+1 bytes of it
    stops a decompression bomb before it allocates. Members within the cap are read unchanged, so no
    member that is actually written is affected."""
    original = zipfile.ZipFile.read

    def bounded(self, member, *args, **kwargs):
        try:
            info = member if isinstance(member, zipfile.ZipInfo) else self.getinfo(member)
            size = info.file_size
        except Exception:
            size = None
        if size is not None and size > limit:
            pwd = args[0] if args else kwargs.get("pwd")
            with self.open(member, pwd=pwd) as handle:
                return handle.read(limit + 1)
        return original(self, member, *args, **kwargs)

    zipfile.ZipFile.read = bounded
    try:
        yield
    finally:
        zipfile.ZipFile.read = original


def write_members(run, members: Path, blobs: list, notes: list):
    """Expand every delivery as the runner does and write its members. blobs is
    [(group, path under artifact/, file name, bytes)]."""
    groups = list(dict.fromkeys(g for g, _, _, _ in blobs))
    folders = [g for g in groups if g]
    count = total = 0
    for group in groups:
        out, names, stopped = {}, [], False
        for g, rel, name, data in blobs:
            if g != group:
                continue
            names.append(name)
            keys = run.Keys() if hasattr(run, "Keys") else None
            try:
                with _bounded_member_reads(MAX_MEMBER):
                    if keys is None:
                        run.expand(name, data, out)
                    else:
                        run.expand(name, data, out, keys=keys)
                        for locked in keys.locked:
                            notes.append(f"{shown(locked)} in {shown(rel)} under artifact/: {PASSWORD_NOTE}; "
                                         f"add the password with tools/password.py add '<value>' and run this again")
            except Exception as e:      # a reader that fails on hostile bytes loses that archive, not the run
                notes.append(f"{shown(rel)} under artifact/ could not be expanded ({type(e).__name__}); what was read of it is written")
                out.setdefault(name, data)
        # A delivery that is an archive with members is not written again as a file.
        archives = {n for n in names if any(k.startswith(n + ARROW) for k in out)}
        for g, rel, name, data in blobs:
            # Say so when an archive gave nothing: otherwise the agent finds evidence.zip among
            # the members with no word on why (a password no candidate is, or damaged).
            if g == group and name not in archives and data.startswith(ARCHIVE_MAGIC) and out.get(name) is data:
                notes.append(f"{shown(rel)} under artifact/ looks like an archive but no member could be read from it "
                             f"(another password, or damaged): the file itself is written")
        if group:
            try:
                make_dir(members / group)
            except Skip as e:
                raise Stop(f"{members / group}: {e}", EX_FAILED)
            tree = Tree(members, members / group)
        else:
            tree = Tree(members, members, reserved=RESERVED + tuple(folders))
        where = f"artifact/{group}" if group else "artifact"
        again = {}      # archive -> the ~n of each member of it whose name an earlier member holds
        # Breadth first (backlog row 117): the delivery's own members before the entries of an
        # archive inside it, those before the next level. On Day 8 the 2,000 members went to the
        # classes of a fat jar and the day's new sample, a top-level member, was never written.
        entries, home = [], nesting(out)
        for at, (key, data) in enumerate(out.items()):
            if not isinstance(data, (bytes, bytearray)):
                continue
            archive, name = split_key(key, out)
            if archive is None:
                if key in archives:
                    continue
            elif out.get(name) is data:
                continue    # expand filed this very member under its own name: written at that key
            depth, inside = home.get(id(data), (0, None))
            if archive is not None and inside is None:
                depth, inside = 1, archive
            entries.append((depth, at, key, data, archive, name, inside))
        entries.sort(key=lambda e: (e[0], e[1]))
        nested_all, nested_done, capped = {}, {}, {}
        for depth, _, _, _, _, _, inside in entries:
            if depth >= 2:
                nested_all[inside] = nested_all.get(inside, 0) + 1
        for i, (depth, _, key, data, archive, name, inside) in enumerate(entries):
            if depth >= 2 and nested_done.get(inside, 0) >= MAX_NESTED:
                capped[inside] = capped.get(inside, 0) + 1      # one fat archive does not use up the budget
                continue
            if count >= MAX_MEMBERS:
                left = {}       # what the stop leaves out, per archive: one line, as before, with the counts
                for d, _, _, _, _, _, ins in entries[i:]:
                    label = shown(ins) if d >= 1 and ins is not None else "the delivery"
                    left[label] = left.get(label, 0) + 1
                per = ", ".join(f"{n} of {label}" for label, n in list(left.items())[:8])
                notes.append(f"stopped at {MAX_MEMBERS} members: {shown(key)} of {where} and what follows it are not written"
                             + (f" ({per}{', ...' if len(left) > 8 else ''})" if per else ""))
                stopped = True
                break
            if len(data) > MAX_MEMBER:
                notes.append(f"skipped {shown(key)} of {where}: {len(data)} bytes is over the limit of {MAX_MEMBER}")
                continue
            if total + len(data) > MAX_TOTAL:
                notes.append(f"stopped at {MAX_TOTAL} bytes: {shown(key)} of {where} and what follows it are not written")
                stopped = True
                break
            try:
                path, n = tree.path_for(name)
                write_file(path, data)
            except Skip as e:
                notes.append(f"skipped {shown(key)} of {where}: {e}")
                continue
            count += 1
            total += len(data)
            if depth >= 2:
                nested_done[inside] = nested_done.get(inside, 0) + 1
            if archive is not None and n > 1:
                again.setdefault(archive, []).append(n)
        for inside, n in capped.items():
            notes.append(f"{shown(inside)} in {where} is an archive inside an archive with {nested_all.get(inside, 0)} members: "
                         f"the first {MAX_NESTED} are written, {n} are not (the cap per nested archive; read the rest "
                         f"with a reader of your own, from artifact/)")
        for archive, ns in again.items():
            tilde = f"~{ns[0]}" if len(set(ns)) == 1 else "~N"
            notes.append(f"{len(ns)} member(s) of {shown(archive)} in {where} have a name an earlier member holds: "
                         f"each is written with {tilde} before its extension")
        if stopped:
            return


def recorded(members: Path, name: str = SOURCE):
    """What members/.source.json says was unpacked (or members/.members.json says was
    written), or None when it says nothing usable."""
    path = members / name
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None
        data = json.loads(path.read_bytes())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def listing(members: Path) -> list:
    """[(path under members/, bytes, sha256)] of every member on disk, sorted."""
    rows = []
    for folder, _dirs, files in os.walk(members):
        for name in files:
            if folder == str(members) and name in RESERVED:
                continue
            path = os.path.join(folder, name)
            if not stat.S_ISREG(os.lstat(path).st_mode):
                continue
            with open(path, "rb") as f:
                data = f.read()
            rows.append((Path(path).relative_to(members).as_posix(), len(data), hashlib.sha256(data).hexdigest()))
    return sorted(rows)


class Locked:
    """Hold members/.lock, so that two runs on one attempt take turns."""

    def __init__(self, members: Path):
        self.path, self.fd = members / LOCK, None

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o644)
        os.fchmod(self.fd, 0o644)       # whatever the umask: the next agent must be able to open it
        end = time.monotonic() + LOCK_WAIT
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= end:
                    os.close(self.fd)
                    raise Stop(f"another unpack has held {self.path} for {LOCK_WAIT:.0f} s", EX_FAILED)
                time.sleep(LOCK_POLL)

    def __exit__(self, *exc):
        os.close(self.fd)       # closing gives the lock up
        return False


def not_started(attempt: Path) -> str:
    """What to add to "no artifact/ folder" for an attempt's folder that exists and holds no
    attempt. Three kinds, told apart by what is on disk:
      - a timed attempt's folder: not started, and no command is offered for a clock;
      - the folder the opener leaves for a lane with no registered solver (it holds status.json,
        the question contract): nothing of that lane is downloaded until its base is started,
        and tools/verify.py --start is the command that does it;
      - any other folder directly under a day's folder: a registered lane's base. Its folder is
        made by tools/verify.py just before it starts the base, so the reader has arrived in
        the seconds before the delivery is saved, or after a start that failed. No command is
        named here: the opener or the lane's owner starts that base, and a line that told
        every reader to start it would have two of them banking one base at once.
    A folder that is none of these (the day's folder, _open/, a wrong path) is no attempt's: ''."""
    if not attempt.is_dir() or (attempt / "attempt.json").exists():
        return ""
    if attempt.name in TIMED or "history" in attempt.parts[-3:]:
        return " (and no attempt.json: the attempt was not started, so nothing was downloaded)"
    if (attempt / "status.json").is_file():
        return (" (and no attempt.json: the attempt was not started, so nothing was downloaded; an untimed base is "
                "started, and its delivery saved, by tools/verify.py <base id> <solver> --start)")
    if DAY_FOLDER.fullmatch(attempt.parent.name) and not attempt.name.startswith(("_", ".")):
        return (" (and no attempt.json: the base was not started, or is being started right now, so nothing is "
                "downloaded yet; if it is being started the delivery is here in a few seconds: run this again)")
    return ""


def unpack_file(file: Path) -> int:
    """Recursively unpack one archive/envelope file into a sibling <name>.unpacked/ folder and print
    the listing, through the same run.expand() the attempt reader uses. The file itself is never
    changed; only the output folder is written."""
    file = file.resolve()
    try:
        data = file.read_bytes()
    except OSError as e:
        raise Stop(f"{file} cannot be read ({type(e).__name__}: {one_line(e.strerror or e)})", EX_MISSING)
    members = file.parent / (file.name + ".unpacked")
    try:
        os.mkdir(members, 0o755)
        os.chmod(members, 0o755)
    except FileExistsError:
        pass
    if not stat.S_ISDIR(os.lstat(members).st_mode):
        raise Stop(f"{members} is not a plain folder", EX_FAILED)
    notes = []
    with Locked(members):
        run = _runner()                 # before anything is removed
        clear(members)
        write_members(run, members, [("", file.name, file.name, data)], notes)
        if notes:
            write_file(members / NOTES, ("\n".join(notes) + "\n").encode())
        rows = listing(members)
    for note in notes:
        print(f"unpack: {one_line(note)}", file=sys.stderr)
    lines = [str(members)]
    lines += [f"{rel}  {size}  {digest[:16]}" for rel, size, digest in rows]
    lines.append(f"UNPACK dir={members} members={len(rows)} bytes={sum(r[1] for r in rows)} "
                 f"deliveries=1 fresh=true")
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


def unpack(attempt: Path, after=None) -> int:
    """Unpack one attempt folder and print the listing. `after` is one more line for stderr."""
    attempt = attempt.resolve()
    artifact, members = attempt / "artifact", attempt / "members"
    if not artifact.is_dir():
        hint = (" (give the attempt folder, the one that holds artifact/)" if attempt.name in ("artifact", "members")
                else not_started(attempt))
        raise Stop(f"no artifact/ folder under {attempt}{hint}", EX_MISSING)
    notes = []
    found = find_deliveries(artifact, notes)
    if not found:
        raise Stop(f"no delivery under {artifact}", EX_MISSING)
    try:
        os.mkdir(members, 0o755)
        os.chmod(members, 0o755)
    except FileExistsError:
        pass
    if not stat.S_ISDIR(os.lstat(members).st_mode):
        raise Stop(f"{members} is not a plain folder", EX_FAILED)
    once = []       # said by this run only, not kept in .notes.txt
    with Locked(members):
        blobs = [(group, rel, name, (artifact / rel).read_bytes()) for group, rel, name in found]
        source = {rel: hashlib.sha256(data).hexdigest() for _, rel, _, data in blobs}
        fresh = recorded(members) != source
        rows = None
        if not fresh:
            # The same delivery. The listing is only printed from disk while every member this
            # tool wrote is still there with its bytes: after `rm members/*` (which leaves the
            # dot files) or an edit of a specimen, "nothing to do" would be a lie for good.
            rows = listing(members)
            written, have = recorded(members, WRITTEN), {rel: digest for rel, _, digest in rows}
            try:
                was_locked = PASSWORD_NOTE in (members / NOTES).read_text(errors="replace")
            except OSError:
                was_locked = False
            if written is None:
                fresh = True
                once.append("members/ has no usable record of what was written: unpacked again")
            elif was_locked:
                fresh = True        # a password may have been added since (tools/password.py)
                once.append("the last unpack met an archive no known password opened: unpacked again")
            else:
                lost = sorted(rel for rel, digest in written.items() if have.get(rel) != digest)
                if lost:
                    fresh = True
                    once.append(f"{len(lost)} member(s) under members/ were removed or changed since they were "
                                f"unpacked (first {shown(lost[0])}): unpacked again")
        if fresh:
            run = _runner()                 # before anything is removed
            clear(members)
            write_members(run, members, blobs, notes)
            if notes:
                write_file(members / NOTES, ("\n".join(notes) + "\n").encode())
            rows = listing(members)
            write_file(members / WRITTEN, (json.dumps({rel: digest for rel, _, digest in rows}, indent=1,
                                                      sort_keys=True) + "\n").encode())
            # Last: a run that died half way leaves no record, so the next one starts over.
            write_file(members / SOURCE, (json.dumps(source, indent=1, sort_keys=True) + "\n").encode())
        else:
            try:
                notes = (members / NOTES).read_bytes().decode("ascii", "backslashreplace").splitlines()
            except OSError:
                notes = []
    for note in once + notes + ([after] if after else []):
        print(f"unpack: {one_line(note)}", file=sys.stderr)
    lines = [str(members)]
    lines += [f"{rel}  {size}  {digest[:16]}" for rel, size, digest in rows]
    lines.append(f"UNPACK dir={members} members={len(rows)} bytes={sum(r[1] for r in rows)} "
                 f"deliveries={len(source)} fresh={'true' if fresh else 'false'}")
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


def main(argv=None) -> int:
    try:
        a = parse(sys.argv[1:] if argv is None else list(argv))
        if a.get("help"):
            print(__doc__.strip())
            return 0
        if "dir" in a:
            p = Path(a["dir"])
            return unpack_file(p) if p.is_file() else unpack(p)
        attempt, after = from_handoff(a["lane"], a["day"], a["mode"], a["mode_given"])
        return unpack(attempt, after)
    except Stop as e:
        print(f"unpack: {one_line(e.message)}", file=sys.stderr)
        return e.code
    except OSError as e:
        where = f" ({e.filename})" if e.filename else ""
        print(f"unpack: {type(e).__name__}: {one_line(e.strerror or e)}{where}", file=sys.stderr)
        return EX_FAILED


if __name__ == "__main__":
    sys.exit(main())
