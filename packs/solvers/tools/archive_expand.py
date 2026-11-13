#!/usr/bin/env python3
"""The delivery expander: how a solver's `files` are built from a delivery's bytes.

expand(name, data, out) records `data` under `name`, then every member if it is an archive (zip, APK
and JAR included; 7z through 7-Zip when it is installed), nested archives too ("outer -> inner"), and
the decoded endpoint of a thin reversible envelope (base64/gzip/... around a container) through
solvers/common/unwrap.py. Encrypted members are tried with `infected` and the passwords in
solvers/common/archive_passwords.py; Keys records the archives none of them opens.

This is the library half of tools/run.py (B-001 hand merge hm-17): it has no platform client in
it and imports without tools/gm.py or tools/lanes.py, so tools/unpack.py, the lane solvers and
the speedrun workers can build `files` the way the attempt runner does. tools/run.py re-exports
every name here (run.expand, run.Keys, run.pw, run.unwrap, run.SEVENZ_MAGIC, ...), so
`import run; run.expand(...)` callers are unchanged.

Nothing here makes a request or runs anything from an archive; 7-Zip only extracts.

The wide walk (B-013, opt-in). expand(..., opts=Walk()) is the intake sweep's walk: on top of the
above it opens tar (ustar/gnu/pax; regular files, a link entry becomes a file holding its target
text), a whole-file gzip / bz2 / xz stream ("log.txt.gz -> log.txt"), RAR through 7-Zip, and a
TI-Nspire document (*TIMLP, B-132: solvers/toolkits/tns_nspire.py reads its members, the encrypted
XML pages as the XML they hold); it
enforces Walk's budgets (bytes of one member, bytes and members in all, nesting depth, 7-Zip's listed
size before it extracts) and keeps a line in Walk.notes for every member or archive it did not open
and why (a missing 7-Zip included), and Walk.rows holds (chain, key, bytes) for every member with the
whole chain it came through. Without opts nothing of this runs: a delivery expands exactly as before
(tests/test_harden_compress_unpack.py keeps a tar opaque there).
"""
import bz2
import contextlib
import importlib.util
import io
import lzma
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path

class _OnlyInfected:
    """What run.py uses when solvers/common/archive_passwords.py is not beside this tools/ (a copy
    of tools/ alone, as tests/test_gm.py makes): `infected` and nothing else, the behaviour before
    backlog row 75. Same names as the module's, as far as run.py uses them."""
    DEFAULT = b"infected"

    @staticmethod
    def candidates():
        return [b"infected"]

    @staticmethod
    def learn(obj, source="gm"):
        return []

    class Opener:
        def __init__(self, data, zf=None, cands=None):
            self.data, self.zf, self.locked, self.used, self._aes = data, zf or zipfile.ZipFile(io.BytesIO(data)), [], None, None

        def read(self, info):
            for pwd in (None, b"infected"):
                with contextlib.suppress(Exception):
                    return self.zf.read(info, pwd=pwd)
            with contextlib.suppress(Exception):
                import pyzipper as _aes
                self._aes = self._aes or _aes.AESZipFile(io.BytesIO(self.data))
                return self._aes.read(info.filename, pwd=b"infected")
            return None

        def password_for(self):
            return None


def _load_passwords():
    """solvers/common/archive_passwords.py of this copy, under its own name (backlog row 75); the
    `infected`-only stand-in above when this tools/ has no solvers/ beside it."""
    name = "archive_passwords"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parent.parent / "solvers" / "common" / "archive_passwords.py"
    if not path.is_file():
        return _OnlyInfected
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


pw = _load_passwords()


def _load_unwrap():
    """solvers/common/unwrap.py (the reversible-envelope peeler), loaded by path like the passwords
    module so a tools/-only copy (tests/test_gm.py) simply has it as None and expand peels nothing new."""
    name = "unwrap"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parent.parent / "solvers" / "common" / "unwrap.py"
    if not path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


unwrap = _load_unwrap()


try:
    import pyzipper  # AES-encrypted zip members, in process
except ImportError:  # the system python3 has no pyzipper; 7-Zip does the same job
    pyzipper = None

SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"
RAR_MAGIC = b"Rar!\x1a\x07"
TNS_MAGIC = b"*TIMLP"          # a TI-Nspire document: a zip variant only the wide walk opens (B-132)


def _load_tns():
    """solvers/toolkits/tns_nspire.py (the TI-Nspire reader, B-132), loaded by path on first use like
    the passwords module; None when this tools/ has no solvers/ beside it (the walk then says so)."""
    name = "tns_nspire"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parent.parent / "solvers" / "toolkits" / "tns_nspire.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return mod


class Walk:
    """Options and state of one wide walk (B-013). Pass the same object to one top-level expand().

    max_member   bytes of one member: a larger one is not read (its declared size decides for zip and
                 tar; a stream that inflates past it is dropped)
    max_total    bytes of all members read in this walk; at it the walk stops reading
    max_members  members read in this walk; at it the walk stops reading
    max_depth    archives inside archives followed (0 = the delivery's own members only)
    notes        one line per thing not opened or not read, and why (never silent)
    rows         [(chain tuple, key, bytes)]: the delivery, then every member with its whole chain
    doubt        {chain tuple: (why, engine id)}: members whose text is where decoys sit (a TI-Nspire
                 document page, B-132). The sweep never calls a flag found only there (and in the
                 containers around it) solved; `engine` is the reader that can settle it.
    """

    def __init__(self, max_member: int = 64 << 20, max_total: int = 512 << 20, max_members: int = 4000,
                 max_depth: int = 6):
        self.max_member, self.max_total = int(max_member), int(max_total)
        self.max_members, self.max_depth = int(max_members), int(max_depth)
        self.notes, self.rows, self.doubt = [], None, {}
        self.total = self.count = 0
        self.full = False

    def take(self, key: str, size: int) -> bool:
        """Count one member of `size` bytes about to be kept; False (and one note) when a budget says no."""
        if self.full:
            return False
        if size > self.max_member:
            self.notes.append(f"skipped {key!r}: {size} bytes is over the member limit of {self.max_member}")
            return False
        if self.count + 1 > self.max_members or self.total + size > self.max_total:
            self.full = True
            self.notes.append(f"stopped at {key!r}: the walk's budget ({self.max_members} members, "
                              f"{self.max_total} bytes) is spent; it and what follows are not read")
            return False
        self.count += 1
        self.total += size
        return True


_STREAM_SUFFIX = {".gz": "", ".tgz": ".tar", ".gzip": "", ".bz2": "", ".tbz2": ".tar", ".tbz": ".tar",
                  ".xz": "", ".txz": ".tar"}


def _stream_kind(data: bytes):
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if data[:3] == b"BZh" and data[3:4].isdigit():
        return "bz2"
    if data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    return None


def _inflate_bounded(data: bytes, kind: str, cap: int):
    """The whole-file gzip/bz2/xz stream (concatenated members too), or None when it inflates past
    `cap` bytes. Driven piece by piece, so a bomb is dropped holding at most cap + one piece."""
    pieces, size, rest = [], 0, data
    while rest:
        if kind == "gzip":
            d = zlib.decompressobj(47)
        elif kind == "bz2":
            d = bz2.BZ2Decompressor()
        else:
            d = lzma.LZMADecompressor()
        buf = rest
        while True:
            if kind == "gzip":
                chunk = d.decompress(buf, 1 << 20)
                buf = d.unconsumed_tail
            else:
                chunk = d.decompress(buf, max_length=1 << 20)
                buf = b""
            size += len(chunk)
            if size > cap:
                return None
            pieces.append(chunk)
            if d.eof:
                break
            if kind == "gzip" and not chunk and not buf:
                break                              # no input left and nothing more comes out: truncated
            if kind != "gzip" and d.needs_input:
                break
        if not d.eof:
            break                                  # truncated: what inflated so far is kept
        rest = d.unused_data
        if _stream_kind(rest) != kind:
            break                                  # trailing bytes that start no further member
    return b"".join(pieces)


def _stream_member_name(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    low = base.lower()
    for suffix, repl in _STREAM_SUFFIX.items():
        if low.endswith(suffix) and len(base) > len(suffix):
            return base[: -len(suffix)] + repl
    return base + ".out"


def _is_tar(data: bytes) -> bool:
    return len(data) >= 512 and data[257:262] == b"ustar"


# pax extended records the normal walk never surfaces: a tar member's extended header carries
# keyword/value pairs (SCHILY.xattr.<name> for an extended attribute, and any custom keyword an author
# writes), and a secret is sometimes parked in one. _expand_tar reads a member's *bytes* but not these
# headers, so B-068's evidence ledger reads them here. The standard keywords that only duplicate a tar
# field (times, ids, names, path, size) are dropped: a custom keyword or an xattr is what a join wants.
_PAX_STANDARD = frozenset((
    "atime", "ctime", "mtime", "size", "uid", "gid", "uname", "gname",
    "path", "linkpath", "hdrcharset", "charset", "comment",
))


def pax_records(data: bytes) -> list:
    """Every non-standard pax extended-header record of a tar, as [(member, keyword, value)]. [] when
    the bytes are not a readable tar or carry no such record. Reads headers only; no member is written
    out and nothing is executed. A keyword that merely restates a tar field (mtime, path, uid, ...) is
    dropped; SCHILY.xattr.<name> and any author-written keyword are kept, value as text."""
    out = []
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except (tarfile.TarError, EOFError, OSError, ValueError):
        return out
    with tf:
        while True:
            try:
                m = tf.next()
            except (tarfile.TarError, EOFError, OSError, ValueError):
                break
            if m is None:
                break
            for keyword, value in (getattr(m, "pax_headers", None) or {}).items():
                if keyword in _PAX_STANDARD or not isinstance(value, str) or not value:
                    continue
                out.append((m.name, keyword, value))
    return out


def _expand_tar(name, data, out, depth, keys, opts, _rows, _chain):
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except (tarfile.TarError, EOFError, OSError) as e:
        opts.notes.append(f"{name!r} looks like a tar but did not open ({type(e).__name__})")
        return
    with tf:
        while True:
            try:
                m = tf.next()
            except (tarfile.TarError, EOFError, OSError) as e:
                opts.notes.append(f"{name!r}: the tar is damaged after {opts.count} member(s) ({type(e).__name__}); "
                                  f"what was read is kept")
                return
            if m is None:
                return
            key = f"{name} -> {m.name}"
            if m.issym() or m.islnk():
                body = os.fsencode(m.linkname)     # a link is its target's text, never followed
            elif m.isreg():
                if m.size > opts.max_member:
                    opts.notes.append(f"skipped {key!r}: {m.size} bytes is over the member limit of {opts.max_member}")
                    continue
                f = tf.extractfile(m)
                body = f.read(opts.max_member + 1) if f is not None else b""
            else:
                continue                           # folders, devices, fifos: nothing to read
            if not opts.take(key, len(body)):
                if opts.full:
                    return
                continue
            out[key] = body
            _rows.append((_chain + (m.name,), key, body))
            expand(m.name, body, out, depth + 1, keys, _rows=_rows, _chain=_chain + (m.name,), opts=opts)


def _expand_tns(name, data, out, depth, keys, opts, _rows, _chain):
    """The members of a TI-Nspire document (B-132), each as its content: a deflated script inflated, an
    encrypted (method 13) XML page decrypted, inflated and decoded from its TIXC token stream. A member
    that is not read (no pycryptodomex, a damaged stream, over the member limit) is a note naming why."""
    tns = _load_tns()
    if tns is None:
        opts.notes.append(f"{name!r} is a TI-Nspire document but solvers/toolkits/tns_nspire.py is not beside "
                          f"this tools/: not opened")
        return
    try:
        box = tns.headers(data)
    except tns.TnsError as e:
        opts.notes.append(f"{name!r} starts like a TI-Nspire document but did not open ({e})")
        return
    opts.notes.extend(f"{name!r}: {n}" for n in box.notes)
    for m in box.members:
        if opts.full:
            return
        key = f"{name} -> {m.name}"
        # One member is decoded at a time, and only into the room the walk's budgets leave: what is
        # decoded and held stays within max_total plus one member, whatever the document states.
        room = opts.max_total - opts.total
        if m.problem is None and m.usize <= opts.max_member and m.usize > room:
            opts.take(key, m.usize)                   # over the walk's total: it stops, with its note
            return
        tns.read_member(m, data, min(opts.max_member, max(room, 0)))
        if m.data is None:
            opts.notes.append(f"skipped {key!r}: {m.problem}")
            continue
        if m.note:
            opts.notes.append(f"{key!r}: {m.note}")
        body, m.data = m.data, None
        if not opts.take(key, len(body)):
            if opts.full:
                return
            continue
        out[key] = body
        chain = _chain + (m.name,)
        if tns.is_document(m):
            opts.doubt[chain] = (tns.DOCUMENT_DOUBT, tns.ENGINE)
        _rows.append((chain, key, body))
        expand(m.name, body, out, depth + 1, keys, _rows=_rows, _chain=chain, opts=opts)


def _expand_stream(name, data, out, depth, keys, opts, _rows, _chain, kind):
    body = _inflate_bounded(data, kind, opts.max_member)
    if body is None:
        opts.notes.append(f"{name!r}: the {kind} stream inflates past the member limit of {opts.max_member}; not read")
        return
    inner = _stream_member_name(name)
    key = f"{name} -> {inner}"
    if not opts.take(key, len(body)):
        return
    out[key] = body
    _rows.append((_chain + (inner,), key, body))
    expand(inner, body, out, depth + 1, keys, _rows=_rows, _chain=_chain + (inner,), opts=opts)


_SEVENZ_SIZE = re.compile(rb"^Size = (\d+)\s*$", re.M)


def _sevenzip_listed_size(exe: str, src: Path):
    """The sum of the member sizes 7-Zip lists for an archive, or None when it cannot list it."""
    try:
        done = subprocess.run([exe, "l", "-slt", "-p-", str(src)], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    _, sep, entries = done.stdout.partition(b"\n----------")
    if not sep:
        return None
    return sum(int(m) for m in _SEVENZ_SIZE.findall(entries))


class Keys:
    """What one split_sets call knows about archive passwords: the attempt, whose text may state
    one, and the archives no candidate opened (`locked`, file names in the order met). `found`
    holds, per locked archive, how deep it sat (0 is a delivery), the members no candidate opened
    and whether any other member of it was read: split_sets stops a run only on a locked delivery
    or a locked member a question names, and notes the rest."""

    def __init__(self, attempt=None, locked=None):
        self.attempt, self.locked, self.asked = attempt, (locked if locked is not None else []), False
        self.found = {}

    def more(self) -> bool:
        """Read the attempt for a password the Game Master states, once: True when that added one
        to the store, so the archive is worth trying again."""
        if self.asked or not isinstance(self.attempt, dict):
            return False
        self.asked = True
        try:
            return bool(pw.learn(self.attempt, source=str(self.attempt.get("attempt_id") or "gm")))
        except Exception:
            return False

    def lock(self, name: str, depth: int = 0, members=(), read_any: bool = False):
        # Keyed by the archive's own (bare) name on purpose: the password a STOP asks the player for
        # is per archive name, not per path. Two same-named locked inner archives still merge here
        # (the collision-only full-path keys of backlog row 303 are for members that WERE read).
        if name not in self.locked:
            self.locked.append(name)
        old = self.found.get(name)
        if old is None or depth < old["depth"]:
            self.found[name] = {"depth": depth, "members": list(members), "read_any": bool(read_any)}


def _collision_keys(out: dict, rows: list):
    """Backlog row 303. A nested member is keyed by its immediate container's OWN name
    ("<container> -> <member>"), so two inner archives of ONE name write the same legacy key and the
    later body wins (the earlier one is addressable only as the first-come bare name). After a depth-0
    expand this gives each lost body a full-path key naming the whole chain it came through
    ("evidence.zip -> a.zip -> stage.zip -> x.js"). The trigger is an actual OVERWRITE: a legacy key
    written with two or more DIFFERENT bodies. Two inner archives of DIFFERENT names
    (evidence-01.zip, evidence-02.zip) write different legacy keys, so nothing is lost and nothing is
    added -- a delivery with no overwrite is byte-for-byte unchanged (keys, order and values). Where
    one chain string still covers two bodies (a zip listing a name twice, two same-named outer
    entries) the bodies go under "<chain> #1", "<chain> #2", ..., the "#N" marking that the chain
    alone cannot say which is which.

    `rows` is [(chain tuple, legacy key, body)] for the top delivery node and every arrow write of
    this top call, in walk order. Cost is O(members): string joins only, no re-expansion."""
    by_legacy = {}
    for chain, legacy, body in rows:
        by_legacy.setdefault(legacy, []).append((chain, body))
    for items in by_legacy.values():
        if len({bytes(b) for _, b in items}) < 2:
            continue                                  # one distinct body under this key: nothing overwritten
        by_full = {}
        for chain, body in items:
            by_full.setdefault(" -> ".join(chain), []).append(body)
        for full, bodies in by_full.items():
            distinct = []
            for b in bodies:
                if all(bytes(b) != bytes(x) for x in distinct):
                    distinct.append(b)
            if len(distinct) == 1:
                b = distinct[0]
                if full not in out or out[full] == b:
                    out[full] = b                     # never overwrite a differing legacy key
            else:
                for i, b in enumerate(distinct, 1):
                    out[f"{full} #{i}"] = b            # ambiguous: the chain alone names two bodies


def expand_7z(name: str, data: bytes, out: dict, depth: int, keys=None, first=None, _rows=None, _chain=None,
              _skip=None, opts=None):
    """Members of an archive the Python libraries could not read, with 7-Zip: `first` (a
    candidate that passed a member's check), else each candidate in turn until one extracts.
    An entry 7-Zip writes as a symbolic link is read as its target's text, never followed.
    With opts (the wide walk): a missing 7-Zip is a note, and an archive whose listed size is over
    the walk's remaining budget is not extracted."""
    exe = shutil.which("7zz") or shutil.which("7z")
    if not exe:
        if opts is not None:
            opts.notes.append(f"{name!r} was not opened: it needs 7-Zip (7zz or 7z), which is not installed")
        return
    if _chain is None:
        _chain = (name,)
    tries = [first] if first else (pw.candidates() or [pw.DEFAULT])
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "archive.bin"
        src.write_bytes(data)
        if opts is not None:
            listed = _sevenzip_listed_size(exe, src)
            room = opts.max_total - opts.total
            if listed is not None and listed > room:
                opts.notes.append(f"{name!r} was not extracted: 7-Zip lists {listed} bytes, over the "
                                  f"{room} bytes left in the walk's budget")
                return
        wrong = 0
        for n, pwd in enumerate(tries):
            dst = Path(td) / f"x{n}"
            done = subprocess.run([exe, "x", "-y", "-p" + pwd.decode("utf-8", "replace"), f"-o{dst}", str(src)],
                                  capture_output=True, timeout=30)
            said = (done.stdout + done.stderr).lower()
            bad = b"wrong password" in said or b"can not open encrypted" in said
            # What a wrong password extracts is garbage: only a clean run, or a partial one that
            # says nothing about the password (a damaged member), is taken.
            if done.returncode == 0 or (not bad and any(p.is_file() for p in dst.rglob("*"))):
                for p in sorted(dst.rglob("*")):
                    if p.is_symlink():
                        body = os.fsencode(os.readlink(p))     # the link's text; the target is never read
                    elif p.is_file():
                        body = p.read_bytes()
                    else:
                        continue
                    rel = p.relative_to(dst).as_posix()
                    if opts is not None and not opts.take(f"{name} -> {rel}", len(body)):
                        if opts.full:
                            return
                        continue
                    out[f"{name} -> {rel}"] = body
                    if _rows is not None:
                        _rows.append((_chain + (rel,), f"{name} -> {rel}", body))
                    if _skip is not None and _skip(rel):
                        continue                  # row 225: the caller expands this member itself
                    expand(rel, body, out, depth + 1, keys, _rows=_rows, _chain=_chain + (rel,), opts=opts)
                return
            wrong += bad
        if wrong and wrong == len(tries) and keys is not None and data[:6] == SEVENZ_MAGIC:
            keys.lock(name, depth)
        if opts is not None:
            opts.notes.append(f"{name!r}: 7-Zip read no member of it (" +
                              ("no known password opens it" if wrong else "damaged, or not an archive") + ")")


def _peel_envelopes(name: str, data: bytes, out: dict, depth: int, keys, _rows, _chain, opts=None):
    """Peel a thin reversible envelope off a non-archive member/delivery (base64/base32/base85/hex/
    url/PEM/data-URI/gzip/zlib/raw-deflate/bz2/xz/byteswap/reversed, and one 2-level nest) when the
    decoded bytes start with a known container/executable magic, then recurse expand into the revealed
    container so the lane sees its members. MAGIC-GATED: a decode of garbage is discarded, so a
    delivery with no envelope is byte-for-byte unchanged and no saved answer can move. Any failure here
    is swallowed: envelope peeling only ever ADDS recognized inner streams, it never blocks expand."""
    if unwrap is None or depth > 4:
        return
    # A delivery/member that ALREADY starts with a known container/format magic is the real artifact,
    # not a thin reversible envelope of one (an envelope re-encodes the bytes as base64/gzip/..., which
    # never begins with a raw container magic; the gzip/zlib/bz2/xz magics are deliberately NOT in this
    # set, so a compressed envelope is still peeled). Skipping it here costs ~0 and moves no answer: the
    # magic-gated peel would discard every speculative decode of these bytes anyway. This keeps a
    # recognized delivery (ELF, PE, PNG, PDF, OLE, SQLite, the Binary HCFG, ...) from paying the full
    # decoder battery per member -- the Day-18 metadata and Day-20 binary deliveries are such members.
    try:
        if unwrap.looks_like_container(data):
            return
        peeled = unwrap.peel(data, hints=unwrap.hints_for_name(name))
    except Exception:
        return
    for i, (body, chain) in enumerate(peeled):
        if not isinstance(body, (bytes, bytearray)) or bytes(body) == bytes(data):
            continue
        tag = "+".join(chain)
        key = f"{name} [unwrap:{tag}]"
        if i:                                     # the rare case of two recognized peels of one member
            key = f"{key} #{i + 1}"
        if key in out:
            continue
        if opts is not None:
            if not opts.take(key, len(body)):
                return
            _rows.append((_chain + (key,), key, bytes(body)))
        out[key] = bytes(body)
        expand(key, bytes(body), out, depth + 1, keys, _rows=_rows, _chain=_chain + (key,), opts=opts)


def expand(name: str, data: bytes, out: dict, depth: int = 0, keys=None, _rows=None, _chain=None, _skip=None,
           opts=None):
    """Record data under name, then every member if it is an archive (APK and JAR included).
    An encrypted member is opened with the known passwords (solvers/common/archive_passwords.py);
    an archive with a member none of them opens is noted in keys.locked.

    `_rows` and `_chain` are internal (backlog row 303): the depth-0 top call creates the row list
    and, after the whole walk, adds the collision-only full-path keys (`_collision_keys`). A delivery
    where no container key is overwritten (two inner archives of one name) is byte-for-byte unchanged.

    `_skip` (backlog row 225, split_sets only): a test on a member name of THIS archive; a member it
    passes is recorded under "<name> -> <member>" but not walked into (the caller expands it itself,
    once). It applies to this archive's own members only, never deeper.

    `opts` (a Walk, B-013): the wide walk described at the top of this file. None keeps the walk
    above exactly as it was."""
    if _chain is None:
        _chain = (name,)
    owner = _rows is None and depth == 0
    if owner:
        _rows = []
        if opts is not None:
            opts.rows = _rows
    try:
        out.setdefault(name, data)
        if owner:
            _rows.append((_chain, name, data))        # the top delivery node has no arrow write
        if opts is not None and opts.full:
            return
        if depth > (4 if opts is None else opts.max_depth):
            if opts is not None and (data[:4] == b"PK\x03\x04" or data[:6] == SEVENZ_MAGIC or
                                     data[:6] == RAR_MAGIC or data[:6] == TNS_MAGIC or _is_tar(data) or
                                     _stream_kind(data)):
                opts.notes.append(f"{name!r} was not opened: it lies {depth} archives deep, past the "
                                  f"depth limit of {opts.max_depth}")
            return
        if data[:6] == SEVENZ_MAGIC or (opts is not None and data[:6] == RAR_MAGIC):
            return expand_7z(name, data, out, depth, keys, _rows=_rows, _chain=_chain, _skip=_skip, opts=opts)
        if opts is not None and data[:4] != b"PK\x03\x04":
            kind = _stream_kind(data)
            if kind:
                return _expand_stream(name, data, out, depth, keys, opts, _rows, _chain, kind)
            if _is_tar(data):
                return _expand_tar(name, data, out, depth, keys, opts, _rows, _chain)
            if data[:6] == TNS_MAGIC:
                return _expand_tns(name, data, out, depth, keys, opts, _rows, _chain)
        if data[:4] != b"PK\x03\x04":
            _peel_envelopes(name, data, out, depth, keys, _rows, _chain, opts=opts)
            return
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            if opts is not None:
                opts.notes.append(f"{name!r} starts like a zip but its directory does not read; not opened")
            return
        op, unreadable, read_any = None, False, False
        for info in zf.infolist():
            if info.is_dir():
                continue
            if opts is not None and info.file_size > opts.max_member:
                opts.notes.append(f"skipped {name + ' -> ' + info.filename!r}: {info.file_size} bytes is over "
                                  f"the member limit of {opts.max_member}")
                continue
            op = op or pw.Opener(data, zf)
            body = op.read(info)
            if body is None and info.filename in op.locked and keys is not None and keys.more():
                op = pw.Opener(data, zf)          # the attempt stated a password: the candidates again
                body = op.read(info)
            if body is None:
                unreadable = True
                continue
            if opts is not None and not opts.take(f"{name} -> {info.filename}", len(body)):
                if opts.full:
                    return
                continue
            read_any = True
            out[f"{name} -> {info.filename}"] = body
            if _rows is not None:
                _rows.append((_chain + (info.filename,), f"{name} -> {info.filename}", body))
            if _skip is not None and _skip(info.filename):
                continue                              # row 225: the caller expands this member itself
            expand(info.filename, body, out, depth + 1, keys, _rows=_rows, _chain=_chain + (info.filename,),
                   opts=opts)
        if not unreadable:
            return
        if op.locked:
            # No candidate passes the check of an encrypted member: 7-Zip has the same candidates, and
            # what it would extract under a wrong one is garbage. The members that were read stay.
            if keys is not None:
                keys.lock(name, depth, op.locked, read_any)
            if opts is not None:
                opts.notes.append(f"{name!r}: no known archive password opens {len(op.locked)} member(s) "
                                  f"(first {op.locked[0]!r}); add one with tools/password.py")
            return
        expand_7z(name, data, out, depth, keys, op.password_for(), _rows=_rows, _chain=_chain,
                  _skip=_skip, opts=opts)   # last resort for members neither library could read
    finally:
        if owner:
            try:
                _collision_keys(out, _rows)
            except Exception:
                pass                                  # a post-pass that fails never changes the walk's output
