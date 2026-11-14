#!/usr/bin/env python3
"""Reader for the `huntress.binary.dynamic_trace.v1` template the lane's samples carry.

  .venv/bin/python solvers/binary/trace_template.py <sample> [...]     the templates found, per file

Backlog row 116. Every sample since Day 2 prints one JSON record when it runs, and the text it is
built from stands in the file (seen in the Day 8 delivery):

  d05 (Rust)    {"schema":"huntress.binary.dynamic_trace.v1","branch":"","event_count":,"campaign":"",
                "family":"system_information_discovery","effects":"synthetic_environment_only","network":"none"}
  d06 (Java)    ... "branch":"%s","event_count":%d,"campaign":"%s","family":"modeled_command_dispatch",
                "effects":"synthetic_dispatch_only","network":"none"}       (a String constant of the class)
  d07 (Kotlin)  ... "family":"loopback_stage_transfer","effects":"synthetic_stage_only","network":"none"}
  d08 (Swift)   ... "family":"loopback_request_plan","effects":"synthetic_request_plan_only","network":"none"}
                (the interpolation's pieces, padded apart)
  d02 (C++)     ... "campaign":"BR02-000","family":"%s","rtti":"%s"}        (the family is filled in at run time)
  d03 (.NET)    a UTF-16 format string with positional arguments; d04 (Go) only the schema string

No question has asked about it yet. When one does, this module offers the member of the template
the field names, and only a member whose value is written out in the template: `family`, `effects`,
`network`, `schema` and any other literal member. `branch` and `event_count` are what the program
computes when it runs and stay None; so does `campaign` (the config's, asked as a config field), a
member the template fills in (`%s`, `{0}`, an interpolation hole), and a field two templates of the
sample state differently. Nothing is run.

Backlog row 291 (Day 13): the Crystal build has no brace template. It keeps the record's type as
`NamedTuple(schema: String, branch: String, event_count: Int32, campaign: String, family: String,
effects: String, label_count: Int32, network: String)` and its written-out values as separate
String literals (type id 1, bytesize, size, text, NUL) that follow one another: the schema, then
the family, then the effects. _crystal() reads that one shape and nothing wider: the schema literal
stands exactly once in the file, the sample has no brace template, one tuple type names the
members, and exactly two label literals stand directly behind the schema literal. They are offered
as `family` and `effects`; `network`, `label_count`, `branch`, `event_count` and `campaign` stay
None there, and any other count of literals leaves the schema alone.

Every answer is labels.pick('binary.trace_<member>/template', [('literal', value)]): unsure until
the judge accepts the reading, and inert until a question's field asks for a trace member
(asks()). field_catalog.py calls options().
"""
import io
import re
import struct
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
import labels  # noqa: E402

SCHEMA = b"huntress.binary.dynamic_trace.v"
WINDOW = 1024               # bytes of a template read from its opening brace
HITS = 16                   # places of the schema string looked at in one blob
ZIP_BYTES = 64 << 20        # bytes of an archive's entries read to look for the schema string
RUNTIME = ("branch", "event_count", "events", "campaign")      # computed when the sample runs, or the config's
PAIR = re.compile(r'"([A-Za-z_][A-Za-z0-9_]{0,31})"\s*:\s*"([^"\\\x00-\x1f\x7f-￿]{0,160})"')
HOLE = re.compile(r"%[-0-9.]*[a-zA-Z@]|\{\d*\}|\$\{?\w*|\\\(|^$")
FIELD = re.compile(r"(?:dynamic_trace|trace|behaviou?r|behaviou?ral|dynamic|emulation|sandbox)_([a-z][a-z0-9_]*)")
BARE = ("family", "effects", "network", "schema", "behavior_family", "behaviour_family", "trace_schema")


def member_of(bare: str):
    """The template member a field (without prefix and `analysis_`) names, or None."""
    bare = str(bare)
    if bare in ("family", "effects", "network", "schema"):
        return bare
    m = FIELD.fullmatch(bare)
    if m:
        return m.group(1)
    return None


def asks(bare: str) -> bool:
    """Whether a field asks for a member of the trace template."""
    return member_of(bare) is not None


def _templates_in(text: str) -> list:
    """The members of every template in a piece of text: {member: literal value, or None for a hole}."""
    out = []
    at = text.find(SCHEMA.decode())
    for _ in range(HITS):
        if at < 0:
            break
        start = text.rfind("{", max(0, at - 48), at)
        if start >= 0 and re.fullmatch(r'\{\s*"schema"\s*:\s*"', text[start:at]):
            window = text[start:start + WINDOW]
            end = window.find('"}')
            # The record ends at the first `"}`; without one (a member list that ends in a number,
            # a cut window, or a record whose closing members stand elsewhere, backlog row 187) the
            # whole window is read for the members that are present (the schema head and any literal
            # before the hole), and _complete() fills the closing members from the one tail literal.
            if end < 0:
                end = window.find("}", len(SCHEMA) + 16)
            body = window[:end + 2] if end >= 0 else window
            members = {}
            for name, value in PAIR.findall(body):
                if name not in members:
                    members[name] = None if HOLE.search(value) else value
            if (members.get("schema") or "").startswith(SCHEMA.decode()):    # (None: the schema has a hole)
                out.append(members)
        at = text.find(SCHEMA.decode(), at + 1)
    return out


CLOSING = ("family", "effects", "network")
# The record's closing members as one literal, `"family":"..","effects":"..","network":".."}`. Backlog
# row 187: the Nim build writes this tail at a LOWER offset than the schema head, so the forward window
# never reaches it; a bounded scan of the whole member finds it in either direction.
TAIL = re.compile(rb'"family":"([^"\\\x00-\x1f]{0,160})","effects":"([^"\\\x00-\x1f]{0,160})"'
                  rb',"network":"([^"\\\x00-\x1f]{0,160})"\}')


def _has_closing(members: dict) -> bool:
    """Whether a template already states any of family/effects/network as a literal (not a hole)."""
    return any(members.get(k) for k in CLOSING)


def _tails(piece: bytes) -> list:
    """Every distinct closing-member literal in the member's bytes (both directions). A member filled in
    at run time (`%s`, an interpolation hole) is not a literal and is skipped."""
    out = []
    for m in TAIL.finditer(piece):
        rec = {name: value.decode("latin-1") for name, value in zip(CLOSING, m.groups())}
        if any(HOLE.search(v) for v in rec.values()):
            continue
        if rec not in out:
            out.append(rec)
    return out


def _complete(found: list, piece: bytes) -> list:
    """Fill a schema head whose closing members did not fall in its forward window from the ONE tail
    literal that stands anywhere in the member (row 187). Two distinct tails, or none, leave the head as
    it was, so a disagreement (or nothing) still reads None through options()."""
    if not any(m.get("schema") and not _has_closing(m) for m in found):
        return found
    tails = _tails(piece)
    if len(tails) != 1:
        return found
    tail = tails[0]
    done = []
    for m in found:
        if m.get("schema") and not _has_closing(m):
            m = dict(m)
            for name, value in tail.items():
                m.setdefault(name, value)
        done.append(m)
    return done


# ---- backlog row 291: the Crystal form (a NamedTuple type string and separate String literals)
CRYSTAL_TUPLE = re.compile(rb"NamedTuple\((schema: String(?:, [a-z_][a-z0-9_]{0,31}: [A-Z][A-Za-z0-9:]{0,31}){1,15})\)")
CRYSTAL_LABEL = re.compile(rb"[a-z][a-z0-9_]{0,159}")
CRYSTAL_GAP = 16            # a literal is adjacent when fewer than this many NUL bytes of padding precede it


def _crystal_literal(piece: bytes, at: int):
    """(text, the offset behind its NUL) of the Crystal String literal whose header begins at `at`, or
    None: type id 1, bytesize equal to size (ASCII), printable text of that length, a NUL."""
    if at < 0 or piece[at:at + 4] != b"\x01\0\0\0" or at + 13 > len(piece):
        return None
    n, size = struct.unpack_from("<II", piece, at + 4)
    if n != size or not 0 < n <= 160:
        return None
    text = piece[at + 12:at + 12 + n]
    if len(text) != n or piece[at + 12 + n:at + 13 + n] != b"\0" or any(not 0x20 <= b < 0x7F for b in text):
        return None
    return text, at + 13 + n


def _crystal(piece: bytes) -> list:
    """The one trace record of a Crystal build, as [{member: literal}] or []. Only this shape: the
    schema string stands exactly once and is a String literal of its own; every NamedTuple type string
    that begins with `schema: String` names the same members, with `family` before `effects`, both
    String; the literals directly behind the schema literal (padding only between them) that are labels
    are exactly two, and differ. Then they are the family and the effects, in the tuple's order. Any
    other count states the schema alone: which member a literal belongs to is then not established."""
    if piece.count(SCHEMA) != 1:
        return []
    head = _crystal_literal(piece, piece.find(SCHEMA) - 12)
    if not head or not re.fullmatch(re.escape(SCHEMA) + rb"\d{1,3}", head[0]):
        return []
    tuples = {m.group(1) for m in CRYSTAL_TUPLE.finditer(piece)}
    if len(tuples) != 1:
        return []
    typed = [tuple(part.split(b": ", 1)) for part in tuples.pop().split(b", ")]
    strings = [name.decode() for name, kind in typed if kind == b"String"]
    if len({name for name, _ in typed}) != len(typed) or "family" not in strings or "effects" not in strings \
            or strings.index("family") > strings.index("effects"):
        return []
    follow, end = [], head[1]
    while len(follow) < 4:
        gap = 0
        while gap < CRYSTAL_GAP and piece[end + gap:end + gap + 1] == b"\0":
            gap += 1
        literal = _crystal_literal(piece, end + gap) if gap < CRYSTAL_GAP else None
        if not literal or not CRYSTAL_LABEL.fullmatch(literal[0]):
            break           # not adjacent, or no label (d13: the YAML builder's error text comes next)
        follow.append(literal[0].decode())
        end = literal[1]
    members = {"schema": head[0].decode()}
    if len(follow) == 2 and follow[0] != follow[1]:
        members["family"], members["effects"] = follow
    return [members]


def _blobs(blob: bytes):
    """The blob, and for an archive each entry that holds the schema string (classes of a jar)."""
    yield blob
    if blob[:4] == b"PK\x03\x04" or (blob[:2] == b"#!" and b"PK\x03\x04" in blob[:1 << 16]):
        read = 0
        try:
            zf = zipfile.ZipFile(io.BytesIO(blob))
            for info in zf.infolist():
                if info.is_dir() or info.file_size > 8 << 20 or read > ZIP_BYTES:
                    continue
                got = zf.read(info)
                read += len(got)
                if SCHEMA in got or SCHEMA.decode().encode("utf-16-le") in got:
                    yield got
        except Exception:
            return


def templates(blob: bytes) -> list:
    """Every trace template in one file: the ASCII (or modified UTF-8) text and the UTF-16LE text."""
    out = []
    for piece in _blobs(blob):
        here = []
        if SCHEMA in piece:
            # Bytes that are no text become U+FFFF, which no member value may hold: a value never
            # runs across padding or code.
            here += _templates_in("".join(chr(b) if 0x20 <= b < 0x7F else "￿" for b in _near(piece, SCHEMA)))
        wide = SCHEMA.decode().encode("utf-16-le")
        if wide in piece:
            near = _near(piece, wide, 2)
            here += _templates_in(near.decode("utf-16-le", "replace"))
        here = _complete(here, piece)      # row 187: a head whose closing members stand elsewhere
        if not here and SCHEMA in piece and wide not in piece:
            here = _crystal(piece)         # row 291: no brace template at all; the Crystal literals
        out += here
    return out


def _near(piece: bytes, mark: bytes, unit: int = 1) -> bytes:
    """The bytes around the first HITS places of `mark`, joined (a 67 MB file is not decoded whole)."""
    parts, at = [], piece.find(mark)
    for _ in range(HITS):
        if at < 0:
            break
        start = max(0, at - 64 * unit)
        start -= (at - start) % unit
        parts.append(piece[start:at + WINDOW * unit])
        at = piece.find(mark, at + WINDOW * unit)
    return (b"\0" * unit * 2).join(parts)


def collect(blobs: list) -> list:
    """Every trace template of a sample's files (templates() of each)."""
    out = []
    for blob in blobs:
        if isinstance(blob, (bytes, bytearray)):
            out += templates(bytes(blob))
    return out


def options(bare: str, blobs=None, found=None):
    """(key, [(method, value)]) for a trace field over a sample's files (or the templates collect()
    read from them), or None: the field asks no trace member, no template states it as a literal, or
    two templates state it differently."""
    member = member_of(bare)
    if member is None or member in RUNTIME:
        return None
    seen = []
    for members in (collect(blobs or []) if found is None else found):
        value = members.get(member)
        if member in members and value is None:
            return None            # a template fills it in at run time: not a literal of the sample
        if value is not None and value not in seen:
            seen.append(value)
    if len(seen) != 1:
        return None
    return f"binary.trace_{member}/template", [("literal", seen[0])]


def answer(bare: str, blobs: list):
    got = options(bare, blobs)
    return labels.pick(got[0], got[1]) if got else None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for path in sys.argv[1:]:
        found = templates(Path(path).read_bytes())
        print(f"{path}: {len(found)} template(s)")
        for members in found:
            for name, value in members.items():
                print(f"  {name} = {'(filled in at run time)' if value is None else value}")
