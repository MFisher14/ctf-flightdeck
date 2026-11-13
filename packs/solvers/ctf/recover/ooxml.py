"""Tracked-change views of a Word document (B-029): both sides of a redline, as plain text.

    v = views(docx_bytes)          # raises OoxmlError when it is not a readable .docx
    v.accepted                     # every change accepted: insertions kept, deletions dropped
    v.original                     # every change rejected: deletions (w:delText) kept, insertions dropped
    v.changes                      # [Change]: each w:ins / w:del / w:moveFrom / w:moveTo with its text
    v.files()                      # [(name, bytes)]: the text members the sweep scans

Text is joined per paragraph across runs, so a flag split over several `<w:r>` (or over two deletions,
w:id 107 and 108) reads whole, with no markup between its pieces. `deletions.txt` and `insertions.txt`
also join every change of one paragraph, and of the whole document, in order: a flag cut in two by a
live run between two deletions is whole there. Parts read: the body, headers, footers, footnotes,
endnotes, comments and the glossary. Text inserted and then deleted is in neither view.

XML is parsed only after refusing any DOCTYPE or ENTITY declaration (no entity expansion, no external
fetch); each part is read up to MAX_PART bytes.

`rank(flag_views, brief)` orders found flags for the sweep: a flag that exists only through a tracked
change ranks before one in text both views share (the live-text decoy), and a brief that asks for the
original ("deleted", "removed", "redline", "approved" ...) or the final text ("final", "accepted",
"inserted" ...) picks which side first.
"""
from __future__ import annotations

import io
import lzma
import re
import xml.etree.ElementTree as ET
import zipfile
import zlib
from dataclasses import dataclass, field

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
MAX_PART = 32 << 20
FOLDER = "tracked-changes"
PARTS = re.compile(r"word/(?:document|header\d*|footer\d*|footnotes|endnotes|comments|glossary/document)\.xml")
_DECL = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)", re.I)
REMOVE = ("del", "moveFrom")         # text gone from the accepted view
ADD = ("ins", "moveTo")              # text absent from the original view
KINDS = REMOVE + ADD
# What a damaged zip raises from zipfile (Python 3.12, in memory): a bad directory or header, a member that
# overlaps the next or fails its CRC (BadZipFile, ValueError "negative seek"), a member whose data runs
# past the end (EOFError), a corrupt deflate / bzip2 / LZMA stream (zlib.error, OSError, lzma.LZMAError),
# an encrypted member (RuntimeError) or a version or method it does not support (NotImplementedError, a
# RuntimeError). Anything else is cascade()'s named note.
ZIP_ERRORS = (zipfile.BadZipFile, ValueError, OSError, EOFError, RuntimeError, zlib.error, lzma.LZMAError)

ORIGINAL_HINTS = ("delet", "removed", "remove ", "struck", "strike", "redline", "redact", "original",
                  "before the edit", "before edit", "earlier draft", "first draft", "scrub", "erase",
                  "approved", "rejected", "took out", "taken out", "crossed out")
ACCEPTED_HINTS = ("final version", "final text", "final draft", "current version", "as published",
                  "as sent", "accepted", "live text", "insert", "added", "addition")


class OoxmlError(ValueError):
    """Not a .docx this reader can open, or a part it refuses to parse; the message says why."""


@dataclass
class Change:
    kind: str                        # ins | del | moveFrom | moveTo
    part: str
    paragraph: int                   # 1-based, within the part
    id: str
    author: str
    date: str
    text: str

    @property
    def removes(self) -> bool:
        return self.kind in REMOVE


@dataclass
class Views:
    accepted: str
    original: str
    changes: list = field(default_factory=list)
    parts: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def tracked(self) -> bool:
        return bool(self.changes)

    def files(self) -> list[tuple[str, bytes]]:
        """The text members: `text.txt` for a document without tracked changes; else `accepted.txt`,
        `original.txt` and `insertions.txt` / `deletions.txt` for the side(s) that changed."""
        if not self.tracked:
            return [(f"{FOLDER}/text.txt", self.accepted.encode())] if self.accepted.strip() else []
        out = [(f"{FOLDER}/accepted.txt", self.accepted.encode()), (f"{FOLDER}/original.txt", self.original.encode())]
        for name, removes in (("deletions.txt", True), ("insertions.txt", False)):
            mine = [c for c in self.changes if c.removes == removes]
            if mine:
                out.append((f"{FOLDER}/{name}", _change_text(mine).encode()))
        return out


def _change_text(changes: list) -> str:
    lines = []
    for c in changes:
        lines.append(f"[w:{c.kind} id={c.id} author={c.author!r} date={c.date} {c.part} paragraph {c.paragraph}]")
        lines.append(c.text)
    lines.append("[joined per paragraph]")
    per = {}
    for c in changes:
        per.setdefault((c.part, c.paragraph), []).append(c.text)
    lines.extend("".join(texts) for texts in per.values())
    lines.append("[joined in document order]")
    lines.append("".join(c.text for c in changes))
    return "\n".join(lines) + "\n"


def is_docx(data: bytes) -> bool:
    if data[:4] != b"PK\x03\x04" or b"word/" not in data:
        return False
    try:
        return "word/document.xml" in zipfile.ZipFile(io.BytesIO(data)).namelist()
    except ZIP_ERRORS:
        return False


def _read(zf: zipfile.ZipFile, name: str) -> bytes:
    info = zf.getinfo(name)
    if info.file_size > MAX_PART:
        raise OoxmlError(f"{name} is {info.file_size} bytes, over the part limit of {MAX_PART}")
    with zf.open(info) as fh:                 # zipfile stops at the declared size (then checks the CRC)
        return fh.read(MAX_PART)


def _walk(part: str, xml: bytes, acc: list, org: list, changes: list) -> None:
    """Append the part's paragraphs to the two views, and its changes to `changes`."""
    if _DECL.search(xml):
        raise OoxmlError(f"{part} declares a DOCTYPE or ENTITY: not parsed")
    stack, para, runs = [], 0, 0
    a_buf, o_buf = [], []

    def flush():
        acc.append("".join(a_buf))
        org.append("".join(o_buf))
        a_buf.clear()
        o_buf.clear()

    def text(s: str, deleted: bool):
        added = any(c[0] in ADD for c in stack)
        removed = deleted or any(c[0] in REMOVE for c in stack)
        if not removed:
            a_buf.append(s)
        if not added:
            o_buf.append(s)
        if stack:
            stack[-1][2].append(s)

    try:
        for ev, el in ET.iterparse(io.BytesIO(xml), events=("start", "end")):
            tag = el.tag
            if not isinstance(tag, str) or not tag.startswith(W):
                continue
            local = tag[len(W):]
            if ev == "start":
                if local in KINDS:
                    stack.append((local, el, []))
                elif local == "p":
                    para += 1
                elif local == "r":
                    runs += 1
                continue
            if local == "t":
                text(el.text or "", False)
            elif local == "delText":
                text(el.text or "", True)
            elif local == "r":
                runs -= 1
            elif local == "tab" and runs:            # w:pPr/w:tabs/w:tab is a tab stop, not text
                text("\t", False)
            elif local in ("br", "cr") and runs:
                text("\n", False)
            elif local == "p":
                flush()
            elif local in KINDS:                     # well-formed XML: it closes the top of the stack
                kind, _el, buf = stack.pop()
                body = "".join(buf)
                if stack:                            # a change inside a change: its text counts for both
                    stack[-1][2].append(body)
                if body:
                    changes.append(Change(kind, part, max(para, 1), el.get(W + "id", ""),
                                          el.get(W + "author", ""), el.get(W + "date", ""), body))
            if local not in KINDS and local != "p":
                el.clear()
    except ET.ParseError as e:
        raise OoxmlError(f"{part} is not well-formed XML: {e}") from e
    if a_buf or o_buf:
        flush()


def views(data: bytes) -> Views:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except ZIP_ERRORS as e:
        raise OoxmlError(f"not a zip ({type(e).__name__})") from e
    names = zf.namelist()
    if "word/document.xml" not in names:
        raise OoxmlError("no word/document.xml: not a Word document")
    order = sorted((n for n in names if PARTS.fullmatch(n)), key=lambda n: (n != "word/document.xml", n))
    acc, org, changes, notes, read = [], [], [], [], []
    for part in order:
        try:
            xml = _read(zf, part)
            pa, po = [], []
            _walk(part, xml, pa, po, changes)
        except ZIP_ERRORS as e:                 # OoxmlError is a ValueError
            why = str(e) if isinstance(e, OoxmlError) else f"{type(e).__name__}: {e}"
            if part == "word/document.xml":
                raise OoxmlError(f"{part}: {why}") from e
            notes.append(f"{part} not read: {why}")
            continue
        read.append(part)
        header = [] if part == "word/document.xml" else [f"[{part}]"]
        acc.extend(header + pa)
        org.extend(header + po)
    return Views("\n".join(acc) + "\n", "\n".join(org) + "\n", changes, read, notes)


# ---------------------------------------------------------------- ranking found flags

def view_of(chain_name: str) -> str | None:
    """'accepted' | 'original' | 'ins' | 'del' | 'text' for a member named by `files()`, else None."""
    m = re.search(FOLDER + r"/(accepted|original|insertions|deletions|text)\.txt$", chain_name)
    if not m:
        return None
    return {"insertions": "ins", "deletions": "del"}.get(m.group(1), m.group(1))


_TAG = re.compile(r"<[^<>]*>")


def markup_twins(flags) -> dict:
    """{flag: its twin} for each flag with XML tags inside (a raw grep across `<w:r>` runs) whose text
    with the tags taken out is itself one of `flags`: the same flag, read whole from the views."""
    have = set(flags)
    out = {}
    for f in flags:
        if "<" in f and ">" in f:
            clean = _TAG.sub("", f)
            if clean != f and clean in have:
                out[f] = clean
    return out


def brief_side(brief: str) -> str | None:
    """'original' or 'accepted' when the brief's wording points at one side of a redline, else None."""
    low = (brief or "").lower()
    o = sum(h in low for h in ORIGINAL_HINTS)
    a = sum(h in low for h in ACCEPTED_HINTS)
    if o > a:
        return "original"
    if a > o:
        return "accepted"
    return None


def rank(flag_views: dict, brief: str = "") -> tuple[list, str]:
    """(flags in order, a note) from {flag: set of views it was seen in}, in the given order otherwise.
    The brief's side of the redline first (when it names one); then a flag whole inside the changed text
    (deletions.txt / insertions.txt), then one seen in a single view (it may span live and changed text),
    then text both views share (the live-text decoy) and flags from anywhere else."""
    side = brief_side(brief)

    def tracked(v: set) -> bool:
        return bool(v & {"ins", "del"}) or (("accepted" in v) != ("original" in v))

    def strength(v: set) -> int:
        # 0: whole inside the changed text; 1: in one view only (it may span live and changed text,
        # "CSCTF{red" + live run + "line}"); 2: text both views share, or no view at all
        return 0 if v & {"ins", "del"} else 1 if tracked(v) else 2

    def on_side(v: set) -> bool:
        if side == "original":
            return "del" in v or ("original" in v and "accepted" not in v)
        if side == "accepted":
            return "ins" in v or ("accepted" in v and "original" not in v)
        return False

    order = sorted(flag_views, key=lambda f: (not on_side(flag_views[f]), strength(flag_views[f])))
    if not any(tracked(v) for v in flag_views.values()):
        return order, ""
    note = "flags seen only through a tracked change rank before text both views share"
    if side:
        note += f"; the brief points at the {side} text, so that side ranks first"
    return order, note
