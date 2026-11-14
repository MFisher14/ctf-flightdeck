#!/usr/bin/env python3
"""Metadata Forensics: a file embedded in mail (backlog row 345; Day 18 look-ahead, build item 2).

Loaded by properties_strict.py by name (MAIL_FILE), after the reader packs, with their contract
(register(M) adds unconfirmed readers). It does two things.

1. member(q, files, ctx): the file a question is about when its artifact chain names a member AFTER a
   mail file ('metadata-day-18-evidence.zip -> message-002.eml -> voice-note-001.wav'). tools/run.py
   expands zip and 7z only, so such a member is not in `files`, and before this the only-leaf rule
   answered about the .eml itself: the look-ahead staged 5 WRONG plain answers (the attachment's
   sha256, md5, size and filename were the message's, and an attached message's Message-ID was the
   outer one). Here the member is the MIME part whose filename is exactly the chain's name, decoded
   from its transfer encoding (base64 strictly, quoted-printable, 7bit/8bit/binary as they stand); an
   attached message/rfc822 part is a message of its own, so the chain may go on through it, at most
   MAIL_DEPTH mail files deep. An mbox is its messages' parts together; an Outlook .msg is its
   attachment storages (PR_ATTACH_DATA_BIN under the long, else the short, file name).
   It returns
     None            when the chain names no member after a mail file. Every question saved through
                     Day 17 is 'delivery -> file', so for them nothing here changes anything, and the
                     Day 3 rule (the id and the artifact name file A, the delivery holds file B: B's own
                     value) never runs through a message;
     (label, bytes)  the part, labelled '<mail> -> <name>' so its base name is the part's filename;
     (None, None)    with one NOTE line when the chain names such a member and it cannot be read: no part
                     of that name, two of them, a part that does not decode, the last part of a multipart
                     that is not closed, a chain that goes on past a part that is no mail, a file with a
                     mail extension that is no mail. Never the outer message.
   A mail file the chain names that is not delivered is the one delivered top-level mail file (the Day 3
   rule, applied to the container only); none or two is (None, None).

2. register(M): the attachments of one message as readers of the eml namespace (email.* reads as it),
   every one unconfirmed, so unsure until the judge accepts a name: attachment_filename and _name, the
   content types, the SHA-256, MD5 and SHA-1 of the decoded parts, their sizes (each one, and the list).

properties_strict.py answers an identity fact of such a part (filename, size, md5/sha1/sha256, magic
prefix) unsure under '<the property's key>+mail_part' until the judge accepts it there: the judge has
never judged an attachment's decoded bytes. Every other property of the part is read by its normal
reader, as a member of a tar is (row 54).
"""
import binascii
import functools
import io
import re
import tarfile
import zipfile

M = None
NEW = []          # names this pack registered
MAIL_EXT = (".eml", ".msg", ".mbox", ".mbx")
MAIL_DEPTH = 3    # mail files a chain may run through (a message attached to a message attached to one)
CONTAINER_DEPTH = 6   # total typed mail/archive edges in one explicitly named chain
MAIL_LIMIT = 1 << 26   # bytes of a mail file, and of a decoded part, that are read
ARCHIVE_MEMBERS = 4000
PART_LIMIT = 2000      # MIME parts walked in one mail file
NEST_LIMIT = 16        # multipart levels
HEAD_END = re.compile(rb"\r?\n\r?\n")
HEAD_START = re.compile(rb"[A-Za-z][A-Za-z0-9-]*:[ \t]|From ")   # readers_docs._eml's own first test
MBOX_FROM = re.compile(rb"(?:\A|(?<=\n))From \S")
CFB_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
MSG_MARK = "__substg1.0_".encode("utf-16-le")
UTF8_BOM = b"\xef\xbb\xbf"


def U(msg):
    raise M.Unknown(msg)


def _say(line):
    M._say(line)


def _bare(name) -> str:
    """A name without its folders (either slash)."""
    return str(name).replace("\\", "/").rsplit("/", 1)[-1].strip()


# ------------------------------------------------------------------ what a mail file is

def mail_kind(d):
    """'rfc822', 'mbox' or 'msg' for a mail file, else None."""
    if not isinstance(d, (bytes, bytearray)) or not d or len(d) > MAIL_LIMIT:
        return None
    d = bytes(d)
    if d[:8] == CFB_MAGIC:
        return "msg" if MSG_MARK in d else None
    body = d[3:] if d[:3] == UTF8_BOM else d
    if not HEAD_START.match(body[:80]):
        # Not even a first header line: readers_docs._eml (an lru_cache of 4) is not asked, so the
        # delivery zip a chain starts with does not push the messages the eml readers read out of it.
        return None
    docs = (M.MORE_MODULES or {}).get("readers_docs.py") if M is not None else None
    if docs is None or docs._eml(d) is None:
        return None
    return "mbox" if body[:5] == b"From " else "rfc822"


def mail_named(name) -> bool:
    return isinstance(name, str) and _bare(name).lower().endswith(MAIL_EXT)


# ------------------------------------------------------------------ the parts of an RFC 5322 message

class Part:
    """One MIME leaf (or attached message): its filename, content type, transfer encoding, the body as it
    stands in the message, and whether the body is whole (not the last part of an unclosed multipart)."""
    __slots__ = ("filename", "ctype", "cte", "body", "whole", "decoded")

    def __init__(self, filename, ctype, cte, body, whole, decoded=None):
        self.filename, self.ctype, self.cte, self.body, self.whole, self.decoded = filename, ctype, cte, body, whole, decoded

    def data(self) -> bytes:
        """The decoded bytes, or Unknown."""
        if self.decoded is not None:
            return self.decoded
        if not self.whole:
            U("it is the last part of a multipart that is not closed, so it may be cut")
        if self.body is None:
            U("its bytes are not stored as data (an embedded message of an Outlook file)")
        cte = (self.cte or "").strip().lower()
        if cte in ("", "7bit", "8bit", "binary"):
            # Review of 3b194be: only text and messages travel as they stand. A JPEG sent as 8bit by Python's
            # SMTP policy has every LF of its bytes written CRLF, and its SOF then read 2560x13 for 10x13.
            main = (self.ctype or "text/plain").split("/", 1)[0].strip().lower()
            if main not in ("text", "message"):
                U(f"a {str(self.ctype)[:60]} part sent as {cte or 'no transfer encoding'}: line ends in its bytes may "
                  f"have been rewritten on the way, so its bytes are not read")
            out = self.body
        elif cte == "base64":
            # strict_mode: a character outside the alphabet, padding out of place or data after it raises; in C, where
            # a 20 MB part took 0.39 s through a regular expression and base64.b64decode(validate=True)
            s = self.body.translate(None, b" \t\r\n")
            try:
                if len(s) % 4:
                    raise binascii.Error("a length that is no multiple of 4")
                out = binascii.a2b_base64(s, strict_mode=True)
            except (binascii.Error, ValueError):
                U("its base64 is not whole (a character outside the alphabet, padding out of place, or a length that "
                  "is no multiple of 4)")
        elif cte == "quoted-printable":
            out = binascii.a2b_qp(self.body)
        else:
            U(f"its transfer encoding {cte[:40]!r} is not read")
        if len(out) > MAIL_LIMIT:
            U("it is larger than is read")
        self.decoded = out
        return out


def _head_body(d: bytes):
    if d[:2] == b"\r\n":
        return b"", d[2:]
    if d[:1] == b"\n":
        return b"", d[1:]
    m = HEAD_END.search(d)
    return (d[:m.start()], d[m.end():]) if m else (d, b"")


def _headers(head: bytes):
    import email.parser
    import email.policy
    return email.parser.BytesHeaderParser(policy=email.policy.compat32).parsebytes(head + b"\r\n\r\n")


def _filename(h):
    try:
        fn = h.get_filename()
    except Exception:
        U("a part's file name does not read")
    if not fn:
        return None
    fn = str(fn)
    if "=?" in fn:   # an RFC 2047 encoded word, which mailers write in a filename too; one that does not decode stays as written
        docs = M.MORE_MODULES.get("readers_docs.py")
        try:
            fn = docs._mail_value(fn) if docs is not None else fn
        except M.Unknown:
            pass
    return fn


def _marks(body: bytes, boundary: bytes):
    r"""[(start, end, closing)] of the delimiter lines of `boundary`: what the expression
    (?:\A|\r?\n)--<boundary>(--)?[ \t]*(?=\r?\n|\Z) matches, found with bytes.find (a regular expression tried
    at every byte of a 20 MB body took 0.26 s). `start` takes in the line break before the delimiter, `end` is
    where the delimiter line's own line break begins."""
    delim, size, out = b"--" + boundary, len(body), []
    i = body.find(delim)
    while i >= 0:
        if i == 0 or body[i - 1] == 0x0A:
            j = i + len(delim)
            closing = body[j:j + 2] == b"--"
            k = j + 2 if closing else j
            while k < size and body[k] in (0x20, 0x09):
                k += 1
            if k == size or body[k] == 0x0A or body[k:k + 2] == b"\r\n":
                start = 0 if i == 0 else i - 2 if i >= 2 and body[i - 2:i] == b"\r\n" else i - 1
                out.append((start, k, closing))
        i = body.find(delim, i + 1)
    return out


def _split(body: bytes, boundary: bytes):
    """([segment], closed): the body parts between the delimiter lines of `boundary` (RFC 2046 5.1.1:
    the line break before a delimiter belongs to it), and whether the close delimiter was there."""
    marks = _marks(body, boundary)
    segs, closed = [], False
    for k, (_, end, closing) in enumerate(marks):
        if closing:
            closed = True
            break
        start = end
        start += 2 if body[start:start + 2] == b"\r\n" else 1 if body[start:start + 1] == b"\n" else 0
        stop = marks[k + 1][0] if k + 1 < len(marks) else len(body)
        segs.append(body[start:max(start, stop)])
    return segs, closed


def parts(d: bytes, out=None, depth=0, whole=True):
    """[Part] of one message: every leaf of its multipart tree and every attached message, in order; an
    attached message is a leaf here (its own parts are its own). The message itself is a Part when it
    is not multipart."""
    out = [] if out is None else out
    if depth > NEST_LIMIT:
        U("multiparts nested deeper than are read")
    head, body = _head_body(d)
    h = _headers(head)
    if h.get_content_maintype() == "multipart":
        boundary = h.get_boundary()
        if not boundary:
            U("a multipart with no boundary")
        try:
            b = boundary.encode("latin-1")
        except UnicodeEncodeError:
            U("a boundary that is not 8-bit text")
        segs, closed = _split(body, b)
        if not segs:
            U("a multipart with no part")
        for k, seg in enumerate(segs):
            parts(seg, out, depth + 1, whole and (closed or k < len(segs) - 1))
            if len(out) > PART_LIMIT:
                U("more MIME parts than are walked")
        return out
    out.append(Part(_filename(h), h.get_content_type(), h.get("Content-Transfer-Encoding"), body, whole))
    return out


def mbox_messages(d: bytes) -> list:
    """The messages of an mbox, each without its 'From ' line."""
    if d[:3] == UTF8_BOM:
        d = d[3:]
    starts = [m.start() for m in MBOX_FROM.finditer(d)]
    out = []
    for k, s in enumerate(starts):
        chunk = d[s:starts[k + 1] if k + 1 < len(starts) else len(d)]
        nl = chunk.find(b"\n")
        out.append(chunk[nl + 1:] if nl >= 0 else b"")
    return out


def msg_parts(d: bytes) -> list:
    """[Part] of an Outlook .msg: one per attachment storage, its PR_ATTACH_DATA_BIN as the decoded bytes."""
    import olefile
    try:
        ole = olefile.OleFileIO(io.BytesIO(d))
    except Exception:
        U("the Outlook file does not read as a compound file")
    try:
        storages = sorted({e[0] for e in ole.listdir(streams=True, storages=True)
                           if e and e[0].lower().startswith("__attach_version1.0_#")})
        out = []
        for st in storages[:PART_LIMIT]:
            def get(tag, st=st):
                path = f"{st}/__substg1.0_{tag}"
                return ole.openstream(path).read() if ole.exists(path) else None
            fn = None
            for tag, codec in (("3707001F", "utf-16-le"), ("3707001E", "latin-1"),
                               ("3704001F", "utf-16-le"), ("3704001E", "latin-1")):
                raw = get(tag)
                if raw:
                    fn = raw.decode(codec, "replace").rstrip("\x00") or None
                    if fn:
                        break
            mime = get("370E001F")
            data = get("37010102")
            out.append(Part(fn, mime.decode("utf-16-le", "replace").rstrip("\x00") if mime else None, "binary",
                            data, True, data))
        return out
    finally:
        ole.close()


def all_parts(d: bytes, kind: str) -> list:
    """The parts of a mail file of this kind, split once: every question of a solve that names a part of the
    same mail (and the attachment readers) shares one split and each part's one decode (review of 3b194be:
    a 20 MB message asked 10 questions took 4.3 s split again for each, 1.0 s on the armed tree). A mail
    that does not split is remembered as such too."""
    ok, got = _split_mail(bytes(d), kind)
    if not ok:
        U(got)
    return got


@functools.lru_cache(maxsize=4)
def _split_mail(d: bytes, kind: str):
    try:
        if kind == "msg":
            return True, msg_parts(d)
        if kind == "mbox":
            out = []
            for one in mbox_messages(d):
                parts(one, out)
            return True, out
        return True, parts(d[3:] if d[:3] == UTF8_BOM else d)
    except M.Unknown as e:
        return False, str(e)


def named_part_entry(d: bytes, kind: str, want: str):
    """(stored name, decoded bytes) of one uniquely named part, or Unknown."""
    hits = [p for p in all_parts(d, kind) if p.filename and _bare(p.filename) == _bare(want)]
    if not hits:
        U(f"no MIME part of it is named {want[:80]!r}")
    if len(hits) > 1:
        U(f"{len(hits)} MIME parts of it are named {want[:80]!r}")
    return hits[0].filename, hits[0].data()


def named_part(d: bytes, kind: str, want: str):
    """The decoded bytes of the one part of this mail file whose filename is `want`, or Unknown."""
    return named_part_entry(d, kind, want)[1]


# ------------------------------------------------------------------ typed archive edges inside mail chains

def _archive_name(name) -> str:
    return str(name or "").replace("\\", "/").removeprefix("./")


def archive_kind(d: bytes):
    """'zip' or 'tar' only after the container itself parses; None for a magic prefix alone."""
    if not isinstance(d, (bytes, bytearray)) or not d or len(d) > MAIL_LIMIT:
        return None
    data = bytes(d)
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                if len(zf.infolist()) <= ARCHIVE_MEMBERS:
                    return "zip"
        except Exception:
            return None
    # Keep the tar branch exact and cheap.  Compressed tarballs are already compression containers in
    # run.expand; an attachment with a real POSIX/GNU tar header can be traversed here without extraction.
    if len(data) >= 512 and data[257:263] in (b"ustar\0", b"ustar "):
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
                if len(tf.getmembers()) <= ARCHIVE_MEMBERS:
                    return "tar"
        except Exception:
            return None
    return None


def _one_archive_name(names, want):
    """The one exact path, else the one unique basename; duplicate stored names remain ambiguous."""
    asked = _archive_name(want)
    exact = [n for n in names if _archive_name(n) == asked]
    hits = exact if exact else [n for n in names if _bare(n) == _bare(asked)]
    if not hits:
        U(f"no archive member of it is named {want[:80]!r}")
    if len(hits) > 1:
        U(f"{len(hits)} archive members of it are named {want[:80]!r}")
    return hits[0]


def named_archive_member(d: bytes, kind: str, want: str):
    """(stored full path, bytes) of one named regular member, using the shared password candidates."""
    if kind == "zip":
        zf = None
        try:
            zf = zipfile.ZipFile(io.BytesIO(d))
            infos = [i for i in zf.infolist() if not i.is_dir()]
            chosen = _one_archive_name([i.filename for i in infos], want)
            matches = [i for i in infos if i.filename == chosen]
            if len(matches) != 1:
                U(f"{len(matches)} archive members have the stored path {chosen[:80]!r}")
            info = matches[0]
            if info.file_size > MAIL_LIMIT:
                U("the named archive member is larger than is read")
            import archive_passwords
            opener = archive_passwords.Opener(bytes(d), zf)
            body = opener.read(info)
            if body is None:
                if info.filename in opener.locked:
                    U("the named archive member is encrypted and none of the configured passwords opens it")
                U("the named archive member is damaged or uses an unsupported compression method")
            if len(body) > MAIL_LIMIT:
                U("the named archive member is larger than is read")
            return info.filename, body
        except M.Unknown:
            raise
        except Exception as e:
            U(f"the zip archive does not read ({type(e).__name__})")
        finally:
            if zf is not None:
                zf.close()
    if kind == "tar":
        try:
            with tarfile.open(fileobj=io.BytesIO(d), mode="r:") as tf:
                members = [m for m in tf.getmembers() if m.isfile()]
                chosen = _one_archive_name([m.name for m in members], want)
                matches = [m for m in members if m.name == chosen]
                if len(matches) != 1:
                    U(f"{len(matches)} archive members have the stored path {chosen[:80]!r}")
                info = matches[0]
                if info.size > MAIL_LIMIT:
                    U("the named archive member is larger than is read")
                fh = tf.extractfile(info)
                body = fh.read(MAIL_LIMIT + 1) if fh is not None else None
                if body is None or len(body) != info.size or len(body) > MAIL_LIMIT:
                    U("the named tar member is cut or larger than is read")
                return info.name, body
        except M.Unknown:
            raise
        except Exception as e:
            U(f"the tar archive does not read ({type(e).__name__})")
    U("it is no supported archive")


# ------------------------------------------------------------------ the member a question's chain names

def _chain(q):
    art = q.get("artifact") if isinstance(q, dict) else None
    if not isinstance(art, str) or "->" not in art:
        return None
    # Review of 3b194be: an empty element (a doubled or a trailing arrow) is dropped, so a malformed chain
    # still names the part after the mail file (before, it was no chain and the message itself was answered).
    chain = [c for c in (s.strip() for s in art.split("->")) if c]
    return chain if len(chain) >= 2 else None


def names_mail_member(q) -> bool:
    """Whether the question's chain names a member after a file with a mail extension (covers(): no files)."""
    chain = _chain(q)
    return bool(chain) and any(mail_named(c) for c in chain[:-1])


def _element(chain, i, files, ctx):
    """(key, bytes) of the chain's i-th file as run.py recorded it, or (None, None)."""
    keys = [f"{chain[i - 1]} -> {chain[i]}"] if i else []
    keys.append(chain[i])
    for k in keys:
        d = files.get(k)
        if isinstance(d, (bytes, bytearray)):
            return k, bytes(d)
    dname, delivery = ctx.get("delivery_name"), ctx.get("delivery")
    if i == 0 and isinstance(dname, str) and _bare(dname) == _bare(chain[0]) and isinstance(delivery, bytes):
        return dname, delivery
    return None, None


def _one_delivered_mail(files, ctx):
    """(key, bytes, kind) of the one top-level mail file of the delivery, or None for none or two."""
    dname = ctx.get("delivery_name")
    pre = f"{dname} -> " if isinstance(dname, str) else None
    seen = {}
    delivery = ctx.get("delivery")
    if isinstance(dname, str) and isinstance(delivery, bytes) and mail_kind(delivery):   # the delivery is the mail file
        seen[delivery] = (dname, delivery, mail_kind(delivery))
    for n, d in files.items():
        if not isinstance(d, (bytes, bytearray)):
            continue
        top = n[len(pre):] if pre and n.startswith(pre) else None
        if top is None or " -> " in top:
            continue
        kind = mail_kind(d)
        if kind:
            seen.setdefault(bytes(d), (n, bytes(d), kind))
    return next(iter(seen.values())) if len(seen) == 1 else None


def member(q, files, ctx):
    """See the module's docstring: None, (label, bytes) or (None, None)."""
    art = q.get("artifact") if isinstance(q, dict) else None
    if not isinstance(art, str) or "->" not in art:
        return None
    if art.count("->") == 1 and isinstance(files, dict):
        # The shape of every saved question, 'delivery.zip -> file': asked about every question of a set,
        # so the common case is answered first and cheaply. A zip is no mail file.
        head = art[:art.index("->")].strip()
        d = files.get(head)
        if isinstance(d, (bytes, bytearray)) and d[:4] == b"PK\x03\x04" and not head.lower().endswith(MAIL_EXT):
            return None
    chain = _chain(q)
    if chain is None or not isinstance(files, dict):
        return None
    ctx = ctx if isinstance(ctx, dict) else {}
    aid = q.get("answer_id") or q.get("qid")
    start = None
    for i in range(len(chain) - 1):
        key, d = _element(chain, i, files, ctx)
        kind = mail_kind(d) if d is not None else None
        if kind:
            start = (i, key, d, kind)
            break
        if mail_named(chain[i]):
            if d is not None:
                _say(f"NOTE {aid}: the artifact names {_bare(chain[-1])[:80]!r} inside {_bare(chain[i])[:80]!r}, "
                     f"which is no mail file; no file is chosen (row 345: never the file that holds it)")
                return None, None
            one = _one_delivered_mail(files, ctx)
            if one is None:
                _say(f"NOTE {aid}: the artifact names {_bare(chain[-1])[:80]!r} inside {_bare(chain[i])[:80]!r}, "
                     f"which is not delivered, and the delivery holds no one mail file in its place; no file is chosen")
                return None, None
            _say(f"NOTE {aid}: {_bare(chain[i])[:80]!r} is not delivered; {_bare(one[0])[:80]!r} is the one mail file "
                 f"of the delivery, read in its place")
            start = (i, one[0], one[1], one[2])
            break
    if start is None:
        return None
    i, label, d, kind = start
    rest = chain[i + 1:]
    try:
        if len(rest) > CONTAINER_DEPTH:
            U(f"the chain runs through more than {CONTAINER_DEPTH} container members")
        mail_edges = 0
        for k, want in enumerate(rest):
            container = kind or archive_kind(d)
            if container in ("rfc822", "mbox", "msg"):
                mail_edges += 1
                if mail_edges > MAIL_DEPTH:
                    U(f"the chain runs through more than {MAIL_DEPTH} mail files")
                stored, d = named_part_entry(d, container, want)
            elif container in ("zip", "tar"):
                stored, d = named_archive_member(d, container, want)
            else:
                U(f"{_bare(label)[:80]!r} is neither a mail file nor a supported archive")
            label = f"{label} -> {stored}"
            kind = mail_kind(d) if k + 1 < len(rest) else None
    except Exception as e:
        why = str(e) if isinstance(e, M.Unknown) else f"{type(e).__name__}: {M._clean(e, 120)}"
        _say(f"NOTE {aid}: the artifact names {' -> '.join(rest)[:120]!r} inside the container chain "
              f"from {_bare(start[1])[:80]!r}; {M._clean(why, 200)}; no file is chosen "
              f"(row 345: never an outer container in its place)")
        return None, None
    return label, d


# ------------------------------------------------------------------ the attachments of a message, as readers

def attachments(d: bytes):
    """[Part] with a filename of one RFC 5322 message (an mbox of one message too), or None for a file
    that is no message. Unknown for an mbox of several messages. None while properties_strict.facts()
    lists a file's facts (the UNKNOWN PROPERTY page): eleven readers walking the MIME tree there cost
    every unregistered question about a message 0.7 ms (Day 16's base), and the page still lists
    eml.attachment_names."""
    if M.FACTS_PAGE[0]:
        return None
    return _attachments(bytes(d))


@functools.lru_cache(maxsize=4)
def _attachments(d: bytes):
    kind = mail_kind(d)
    if kind not in ("rfc822", "mbox"):
        return None
    docs = M.MORE_MODULES.get("readers_docs.py")
    docs._eml1(d)   # Unknown for an mbox of several messages
    return [p for p in all_parts(d, kind) if p.filename]


def _one(n, d, get):
    atts = attachments(d)
    if atts is None or not atts:
        return None
    if len(atts) > 1:
        U(f"the message has {len(atts)} attachments")
    return get(atts[0])


def _each(n, d, get):
    atts = attachments(d)
    if atts is None or not atts:
        return None
    return [get(p) for p in atts]


def _ctype(p):
    if not p.ctype:
        U("an attachment states no content type")
    return p.ctype


def _digest(algo):
    import hashlib
    return lambda p: hashlib.new(algo, p.data()).hexdigest()


def _name(p):
    return p.filename


def register(module):
    global M
    M = module
    before = dict(M.REG)
    families = len(M.FAMILIES)

    def reg(names, fmt, fn):
        M.prop(*[f"eml.{x}" for x in names], fmt=fmt)(fn)

    reg(("attachment_filename", "attachment_name", "attachment_file_name"), "text", lambda n, d: _one(n, d, _name))
    reg(("attachment_content_type", "attachment_mime_type", "attachment_media_type"), "text",
        lambda n, d: _one(n, d, _ctype))
    reg(("attachment_content_types", "attachment_mime_types", "attachment_media_types"), "list",
        lambda n, d: _each(n, d, _ctype))
    for algo in ("sha256", "md5", "sha1"):
        reg((f"attachment_{algo}",), "hex", lambda n, d, a=algo: _one(n, d, _digest(a)))
        reg((f"attachment_{algo}s", f"attachment_{algo}_list"), "list", lambda n, d, a=algo: _each(n, d, _digest(a)))
    reg(("attachment_size_bytes", "attachment_size"), "integer", lambda n, d: _one(n, d, lambda p: len(p.data())))
    reg(("attachment_sizes_bytes", "attachment_sizes", "attachment_size_bytes_list"), "intlist",
        lambda n, d: _each(n, d, lambda p: len(p.data())))
    for k, old in before.items():   # a name registered before keeps its reader: nothing judged is replaced
        if M.REG[k] is not old:
            M.MORE_CLASHES.append(M.REG[k].name)
            M.REG[k] = old
    NEW[:] = [k for k in M.REG if k not in before]
    M.TIE_FREE.update(M.REG[k].fn for k in NEW)
    return len(M.REG) - len(before), len(M.FAMILIES) - families
