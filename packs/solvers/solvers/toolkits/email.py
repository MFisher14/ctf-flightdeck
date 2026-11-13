#!/usr/bin/env python3
"""Phishing and e-mail toolkit (backlog row 84), toolkit key "email": .eml, .msg and mbox.

  .venv/bin/python solvers/toolkits/email.py <file>... [--json] [--no-qr]

Offline: no Game Master request, no token, no network. The clock path is the standard library only
(the stdlib e-mail parser and a small compound-file reader for .msg); Pillow and pyzbar are imported
only when a QR code is asked for (or by the command), compressed_rtf only for a .msg RTF body.

What it reads (every reader takes bytes and can be called by hand):
  load(data, name)         [Mail, ...]: one for an .eml or a .msg, one per message of an mbox
  received_chain(mail)     the Received headers, newest first: from, helo, rdns, ips, by, with, id, for, date
  originating(mail)        the IP candidates: X-Originating-IP and the like, the earliest Received hop
  auth_results(mail)       spf, dkim, dmarc (and arc, compauth) results, their properties, DKIM-Signature tags
  addresses(mail)          From, Sender, Reply-To, Return-Path, To, Cc as (display name, address) pairs
  mismatches(mail)         reply-to and return-path against From, an address inside the display name
  urls(mail)               every URL: where it stands, the link text shown, refanged and defanged forms
  homoglyphs(mail)         domains with non-ASCII or xn-- labels: unicode, punycode and ASCII skeleton
  qr_codes(mail)           QR payloads of the images (attachments, inline parts, data: URIs in HTML)
  smuggling(mail)          HTML smuggling: the indicators, the download name, the decoded payloads
  triage(mail)             all of it as one dict; report(mail) the same for a reader

signals(questions, files) -> 0..1: how strongly a delivery and its questions look like e-mail.
solve_set(questions, files, ctx) is the runner contract. It never guesses (AGENTS.md, "Uncertain
answers"). Nothing of this lane is judged yet, so a PLAIN answer is given only for
  - a hash (SHA-256, SHA-1, MD5, SHA-512) or the size in bytes of a whole attachment (never of
    something inside it, never of one whose encoding is damaged or cut), or the hash of the mail
    file itself,
  - a count the bytes fix: attachments, Received headers, messages of an mbox; never 0, never from
    a mail the parser had doubts about (Mail.doubt), never URLs or recipients,
  - an SPF, DKIM or DMARC result when the question is an enum that names one check and the one
    result every header states is one of its accepted values.
The hash and size of an HTML-smuggling payload are unsure: one decoded base64 layer is not proof
of what the script saves.
Every other fact it establishes (an address, a domain, an IP, a header value, a date, a URL, a file
type, a yes or no) comes back as labels.pick('email.<field>/<shape>', [(method, value), ...]), best
spelling first, which tools/verify.py probes on the untimed base. Where two readings of a question
would give different facts (X-Originating-IP against the earliest Received hop, two URLs, two
attachments and no name in the question) the answer is None, and the command prints every
candidate for the lane's agent. A question whose artifact names another member of the delivery (a
file that is no mail and holds none: `evidence.zip -> access.log` beside the mail) is None too.

This file is named after its toolkit key, which is also the name of the standard library's e-mail
package. tools/run.py puts a solver's folder first on sys.path, so `import email` could find this
file. When that happens the lines below hand the importer the standard library's package instead.
"""
import sys as _sys

if __name__ == "email":     # imported by the bare name: the importer wanted the standard library
    import importlib as _importlib
    import os as _os
    _here = _os.path.dirname(_os.path.abspath(__file__))
    _saved = list(_sys.path)
    _sys.path[:] = [p for p in _saved if _os.path.abspath(p or _os.getcwd()) != _here]
    _mine = _sys.modules.pop("email", None)
    try:
        _std = _importlib.import_module("email")
    finally:
        _sys.path[:] = _saved
    _sys.modules["email"] = _std        # the import system returns what sys.modules holds
    globals().update({k: v for k, v in vars(_std).items() if k not in ("__builtins__",)})
else:
    import base64
    import binascii
    import codecs
    import hashlib
    import html as _html
    import ipaddress
    import json
    import re
    import struct
    import sys
    import time
    import unicodedata
    from datetime import timezone
    from html.parser import HTMLParser
    from pathlib import Path

    import email as _stdmail            # the standard library (see the module text)
    import email.header as _mailheader
    import email.utils as _mailutils

    HERE = Path(__file__).resolve().parent
    COMMON = HERE.parent / "common"
    if str(COMMON) not in sys.path:
        sys.path.append(str(COMMON))
    import labels       # noqa: E402
    import triage as _triage    # noqa: E402  (identify, unique_files: the same eyes as the triage map)

    KEY = "email"
    ARROW = " -> "
    MAX_MAIL = 64 * 1024 * 1024         # a mail file larger than this is not parsed
    MAX_IMAGE = 8 * 1024 * 1024         # an image larger than this is not searched for a QR code
    MAX_PIXELS = 36_000_000
    MAX_MBOX = 2000                     # messages read from one mbox
    QR = True                           # False: never import Pillow/pyzbar (the command's --no-qr)
    QR_BUDGET = 0.5                     # seconds one mail's images may take; what is left over is noted, not read

    OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    _SUBSTG_W = "__substg1.0_".encode("utf-16-le")
    KNOWN_HEADERS = {"received", "from", "to", "cc", "subject", "date", "message-id", "mime-version", "return-path",
                     "delivered-to", "reply-to", "content-type", "authentication-results", "received-spf",
                     "dkim-signature", "x-originating-ip", "x-mailer", "sender", "x-received", "arc-seal",
                     "content-transfer-encoding", "in-reply-to", "references", "thread-topic", "x-ms-exchange-organization-authas"}
    STRONG_HEADERS = {"received", "message-id", "mime-version", "return-path", "delivered-to", "authentication-results",
                      "received-spf", "dkim-signature"}

    # ---- the mail --------------------------------------------------------------------------------

    class Mail:
        """One message. headers: [(name, value)] unfolded and decoded, in file order (newest Received
        first). bodies: [{type, text, cte, charset, inner}]. attachments: [{filename, declared_type,
        disposition, content_id, cte, data, exact, size, md5, sha1, sha256, true_type}]. nested: [Mail]
        for an attached message. notes: what the reader could not do."""

        def __init__(self, name="", kind="eml", raw=b""):
            self.name, self.kind, self.raw = name, kind, raw
            self.headers, self.raw_headers, self.bodies, self.attachments, self.nested, self.notes = [], [], [], [], [], []
            self._cache = {}
            # doubt: why a count or a hash read from this mail is not proven (a cut file, a header
            # block the parser and a plain line count read differently, an mbox split that is not
            # certain, a .msg with no transport headers). Non-empty: no plain count from it.
            self.doubt = []

        def get_all(self, name) -> list:
            n = name.lower()
            return [v for k, v in self.headers if k.lower() == n]

        def get(self, name, default=None):
            got = self.get_all(name)
            return got[0] if got else default

        def raw_all(self, name) -> list:
            n = name.lower()
            return [v for k, v in self.raw_headers if k.lower() == n]

    def _unfold(value) -> str:
        return re.sub(r"\r?\n[ \t]*", " ", _raw8(str(value))).strip()

    def _raw8(text: str) -> str:
        """A header value with raw 8-bit bytes in it (the parser hands them over as lone surrogates):
        read as UTF-8, else as cp1252. Real mail does this in To: and in file names."""
        if not any(0xDC80 <= ord(c) <= 0xDCFF for c in text):
            return text
        raw = text.encode("utf-8", "surrogateescape")
        for cs in ("utf-8", "cp1252", "latin-1"):
            try:
                return raw.decode(cs)
            except UnicodeDecodeError:
                continue
        return text

    def _decode_words(value: str) -> str:
        if "=?" not in value:
            return value
        try:
            return str(_mailheader.make_header(_mailheader.decode_header(value)))
        except Exception:
            return value

    def _text(data: bytes, charset=None) -> str:
        for cs in (charset, "utf-8", "latin-1"):
            if not cs:
                continue
            try:
                return data.decode(cs)
            except (UnicodeDecodeError, LookupError):
                continue
        return data.decode("latin-1", "replace")

    def _attachment(filename, data: bytes, declared=None, disposition=None, cid=None, cte=None, exact=True) -> dict:
        members = ()
        if data[:4] == b"PK\x03\x04":
            try:
                import io
                import zipfile
                members = tuple(zipfile.ZipFile(io.BytesIO(data)).namelist())
            except Exception:
                members = ()
        return {"filename": filename, "declared_type": declared, "disposition": disposition, "content_id": cid,
                "cte": cte, "data": data, "exact": exact, "size": len(data),
                "md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(), "members": list(members),
                "true_type": _triage.identify(data, filename or "", members)}

    def _b64_text(text: str):
        """The bytes of a body that is wholly base64 text (a second layer), else None."""
        compact = re.sub(r"\s+", "", text)
        if len(compact) < 24 or len(compact) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
            return None
        try:
            return base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError):
            return None

    def parse_eml(data: bytes, name: str = "", depth: int = 0) -> Mail:
        """An RFC 5322 message from its bytes (the standard library's parser, the lenient policy)."""
        mail = Mail(name, "eml", data)
        body_bytes = data[:MAX_MAIL]
        if len(data) > MAX_MAIL:
            mail.doubt.append("the file is larger than is read")
        # A byte-order mark or blank lines before the first header: sniff() looks past them, and so
        # must the parser, or it reads the whole header block as body (and counts no header at all).
        if body_bytes.startswith(b"\xef\xbb\xbf"):
            body_bytes = body_bytes[3:]
        body_bytes = body_bytes.lstrip(b"\r\n")
        msg = _stdmail.message_from_bytes(body_bytes)
        for k, v in msg.raw_items():
            raw = _unfold(v)
            mail.raw_headers.append((k, raw))
            mail.headers.append((k, _decode_words(raw)))
        if msg.defects:
            mail.notes.append("parser defects: " + ", ".join(type(d).__name__ for d in msg.defects[:5]))
        # The parser's header count against a plain count of the header block's lines: when they
        # differ the block was not read as written, and no count of headers is proven.
        block = re.split(rb"\r?\n[ \t]*\r?\n", body_bytes, maxsplit=1)[0]
        lines = len(re.findall(rb"(?m)^[!-9;-~]+[ \t]*:", block))
        if lines != len(mail.headers):
            mail.doubt.append(f"header block: {lines} header lines, {len(mail.headers)} parsed")

        def _cut(part) -> bool:
            return any(type(d).__name__ in ("CloseBoundaryNotFoundDefect", "StartBoundaryNotFoundDefect",
                                            "MultipartInvariantViolationDefect") for d in part.defects)

        def visit(part, cut=False):
            ctype = part.get_content_type()
            if ctype == "message/rfc822" and part.is_multipart():
                for inner in part.get_payload():
                    body = inner.as_bytes()
                    fn = _filename(part)
                    # Re-serialised by the parser: not the sender's exact bytes, so never hashed.
                    mail.attachments.append(_attachment(fn, body, ctype, part.get_content_disposition(), None,
                                                        part.get("Content-Transfer-Encoding"), exact=False))
                    if depth < 4:
                        mail.nested.append(parse_eml(body, fn or "attached message", depth + 1))
                return
            if ctype.startswith("message/") and part.is_multipart() and (_filename(part) or part.get_content_disposition() == "attachment"):
                # message/delivery-status and its kin with a file name: an attachment. Its bytes are the
                # parser's re-serialisation of the blocks inside, so it is never hashed or sized.
                body = b"\n".join(sub.as_bytes() for sub in part.get_payload() if hasattr(sub, "as_bytes"))
                mail.attachments.append(_attachment(_filename(part), body, ctype, part.get_content_disposition(), None,
                                                    part.get("Content-Transfer-Encoding"), exact=False))
                return
            if part.is_multipart():
                subs = [sub for sub in part.get_payload() if hasattr(sub, "get_content_type")]
                open_end = cut or _cut(part)        # no closing boundary: the last part may be cut short
                for sub in subs:
                    visit(sub, cut=open_end and sub is subs[-1])
                return
            before = len(part.defects)
            whole = not cut and not _cut(part) and len(data) <= MAX_MAIL
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
                whole = False
                mail.notes.append(f"a {ctype} part could not be decoded")
            if len(part.defects) > before or any("Base64" in type(d).__name__ for d in part.defects):
                whole = False                       # damaged base64: what was decoded is not the file
            if cut:
                mail.notes.append(f"a {ctype} part has no closing boundary: it may be cut short (not hashed)")
            fn = _filename(part)
            disp = part.get_content_disposition()
            cte = str(part.get("Content-Transfer-Encoding") or "").strip().lower() or None
            cid = str(part.get("Content-ID") or "").strip().strip("<>") or None
            if fn or disp == "attachment" or ctype not in ("text/plain", "text/html"):
                whole = whole and bool(payload)     # nothing decoded: no file to hash
                att = _attachment(fn, payload, ctype, disp, cid, cte, exact=whole)
                if not whole:
                    mail.notes.append(f"attachment {fn or ctype}: damaged or cut encoding (not hashed, not sized)")
                mail.attachments.append(att)
                if depth < 4 and (str(fn or "").lower().endswith(".eml") or sniff(payload, fn or "") == "eml"):
                    mail.nested.append(parse_eml(payload, fn or "attached message", depth + 1))
                return
            charset = part.get_content_charset()
            text = _text(payload, charset)
            body = {"type": ctype, "text": text, "cte": cte, "charset": charset, "inner": None}
            inner = _b64_text(text) if ctype == "text/plain" else None
            if inner is not None and _triage.identify(inner).startswith(("text", "html", "json", "xml")):
                body["inner"] = _text(inner)
            mail.bodies.append(body)

        visit(msg)
        # Any defect the parser met (a boundary never closed, a multipart with no parts, damaged
        # base64), or no blank line after the headers: the mail may be cut, so no count is proven.
        defects = [type(d).__name__ for part in msg.walk() for d in part.defects]
        if defects:
            mail.doubt.append("parser defects: " + ", ".join(sorted(set(defects))[:5]))
        if not re.search(rb"\r?\n[ \t]*\r?\n", body_bytes):
            mail.doubt.append("no blank line after the headers: the file may be cut")
        if not msg.is_multipart() and re.search(rb"(?m)^--[^\r\n]{1,80}\r?\n(?:Content-|MIME-)", body_bytes):
            mail.doubt.append("a body with MIME boundaries the headers do not declare")
        return mail

    def _filename(part):
        try:
            fn = part.get_filename()
        except Exception:
            fn = None
        if fn is not None and ("\ufffd" in fn or any(0xDC80 <= ord(c) <= 0xDCFF for c in fn)):
            # raw 8-bit bytes in the parameter (not RFC 2231, not an encoded word): the parser gives
            # U+FFFD for each. Read the name from the header as written.
            for header in ("Content-Disposition", "Content-Type"):
                for k, v in part.raw_items():
                    m = re.search(r'(?i)\b(?:file)?name\s*=\s*"([^"]+)"', _unfold(v)) if k.lower() == header.lower() else None
                    if m:
                        return _decode_words(m.group(1)) or None
        if fn is None:
            return None
        return _decode_words(_unfold(fn)) or None

    def parse_mbox(data: bytes, name: str = "") -> list:
        """The messages of an mbox: split at the 'From ' separator lines."""
        doubt = []
        starts = []
        for m in re.finditer(rb"(?m)^From [^\r\n]*\r?\n", data[:MAX_MAIL]):
            # A separator is followed by a header block. A body line that begins "From " and was
            # not quoted is not one; either way the split is then a reading, not a fact.
            real = bool(set(_header_block(data[m.end():m.end() + 16384])) & KNOWN_HEADERS)
            blank_before = m.start() == 0 or data[max(0, m.start() - 4):m.start()].endswith((b"\n\n", b"\n\r\n"))
            if not real:
                doubt.append("a line beginning 'From ' with no header block after it was left in a body")
                continue
            if not blank_before:
                doubt.append("a 'From ' separator with no blank line before it")
            starts.append(m.start())
        if len(re.findall(rb"(?m)^From ", data[:MAX_MAIL])) != len(starts) and not doubt:
            doubt.append("a 'From ' line that is cut short")
        if len(starts) > MAX_MBOX:
            doubt.append(f"more than {MAX_MBOX} messages: the rest was not read")
        if len(data) > MAX_MAIL:
            doubt.append("the file is larger than is read")
        out = []
        for i, a in enumerate(starts[:MAX_MBOX]):
            b = starts[i + 1] if i + 1 < len(starts) else len(data)
            chunk = data[a:b]
            chunk = chunk[chunk.index(b"\n") + 1:]
            chunk = re.sub(rb"(?m)^>(>*From )", rb"\1", chunk)          # mboxrd/mboxo quoting
            m = parse_eml(chunk.rstrip(b"\r\n") + b"\n", f"{name}#{i + 1}")
            m.kind, m.raw = "mbox", b""        # a message of an mbox has no file of its own to hash
            m.mbox_doubt = list(dict.fromkeys(doubt))
            out.append(m)
        return out

    # ---- .msg: a small compound-file reader -------------------------------------------------------

    class _Streams(dict):
        """{path: bytes} plus .short: the paths whose bytes are fewer than their directory entry states."""

        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.short = set()
            self.damaged = False        # a file that is not whole: nothing read from it is hashed or counted plain

    def cfb_streams(data: bytes) -> dict:
        """{path: bytes} of every stream of a Compound File Binary (OLE2) file, path parts joined
        with '/'. ValueError when the bytes are not one. Bounded: every chain is walked once."""
        if data[:8] != OLE_MAGIC or len(data) < 512:
            raise ValueError("not a compound file")
        shift, mshift = struct.unpack_from("<HH", data, 30)
        if shift not in (9, 12) or mshift > shift:
            raise ValueError("bad sector size")
        ssz, msz = 1 << shift, 1 << mshift
        nfat, dir_start, _, cutoff, mfat_start, nmfat, difat_start, ndifat = struct.unpack_from("<IIIIIIII", data, 44)
        nsect = len(data) // ssz + 1

        def sector(n):
            off = (n + 1) * ssz
            return data[off:off + ssz]

        difat = list(struct.unpack_from("<109I", data, 76))
        nxt, seen = difat_start, set()
        while nxt < 0xFFFFFFFA and nxt not in seen and len(seen) <= nsect:
            seen.add(nxt)
            s = sector(nxt)
            if len(s) < ssz:
                break
            vals = struct.unpack_from(f"<{ssz // 4}I", s)
            difat += vals[:-1]
            nxt = vals[-1]
        fat = []
        for n in difat:
            if n >= 0xFFFFFFFA or n > nsect or len(fat) > 4 * nsect + ssz:
                continue
            s = sector(n)
            fat += struct.unpack_from(f"<{len(s) // 4}I", s)

        def chain(start, table, limit):
            out, seen_ = [], set()
            while start < 0xFFFFFFFA and start < len(table) and start not in seen_ and len(out) < limit:
                seen_.add(start)
                out.append(start)
                start = table[start]
            return out

        def read(start, size=None):
            body = b"".join(sector(n) for n in chain(start, fat, nsect + 1))
            return body if size is None else body[:size]

        directory = read(dir_start)
        entries = []
        for off in range(0, len(directory) - 127, 128):
            e = directory[off:off + 128]
            nlen = struct.unpack_from("<H", e, 64)[0]
            ename = e[:max(0, min(nlen, 64) - 2)].decode("utf-16-le", "replace")
            etype = e[66]
            left, right, child = struct.unpack_from("<III", e, 68)
            start, size = struct.unpack_from("<IQ", e, 116)
            if shift == 9:
                size &= 0xFFFFFFFF
            entries.append((ename, etype, left, right, child, start, size))
        if not entries or entries[0][1] != 5:
            raise ValueError("no root entry")
        mini = read(entries[0][5], entries[0][6])
        mfat = []
        for n in chain(mfat_start, fat, nsect + 1):
            s = sector(n)
            mfat += struct.unpack_from(f"<{len(s) // 4}I", s)

        def stream(e):
            _, _, _, _, _, start, size = e
            if size > len(data):
                return b""
            if size < cutoff:
                return b"".join(mini[n * msz:(n + 1) * msz] for n in chain(start, mfat, len(mfat) + 1))[:size]
            return read(start, size)

        out, visited = _Streams(), set()
        if len(data) % ssz:
            out.damaged = True          # not a whole number of sectors: cut, or bytes added or lost
        stack = [(entries[0][4], "")]
        while stack:
            idx, prefix = stack.pop()
            if idx >= len(entries) or idx in visited:
                continue
            visited.add(idx)
            e = entries[idx]
            path = prefix + e[0]
            stack.append((e[2], prefix))
            stack.append((e[3], prefix))
            if e[1] == 1:
                stack.append((e[4], path + "/"))
            elif e[1] == 2:
                out[path] = stream(e)
                if len(out[path]) != e[6]:
                    out.short.add(path)     # a damaged or cut file: fewer bytes than the entry states
                    out.damaged = True
        return out

    _PT = {"001F": "utf-16-le", "001E": "cp1252"}

    def _msg_props(streams: dict, prefix: str) -> dict:
        """{property id 'XXXX': value} of one storage: strings decoded, binaries as bytes."""
        out = {}
        for path, body in streams.items():
            if not path.startswith(prefix) or "/" in path[len(prefix):]:
                continue
            m = re.fullmatch(r"__substg1\.0_([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})", path[len(prefix):])
            if not m:
                continue
            pid, ptype = m.group(1).upper(), m.group(2).upper()
            if ptype in _PT:
                out.setdefault(pid, body.decode(_PT[ptype], "replace").rstrip("\x00"))
            elif ptype == "0102":
                out.setdefault(pid, body)
        return out

    def _msg_fixed(streams: dict, prefix: str, header: int) -> dict:
        """{property id: 8 value bytes} of the fixed-size properties (__properties_version1.0)."""
        body = streams.get(prefix + "__properties_version1.0", b"")
        out = {}
        for off in range(header, len(body) - 15, 16):
            ptype, pid = struct.unpack_from("<HH", body, off)
            out[f"{pid:04X}"] = (ptype, body[off + 8:off + 16])
        return out

    def _filetime(raw: bytes):
        ticks = struct.unpack("<Q", raw)[0]
        if not ticks:
            return None
        from datetime import datetime, timedelta
        try:
            return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
        except OverflowError:
            return None

    def parse_msg(data: bytes, name: str = "", _streams=None, _prefix: str = "", depth: int = 0) -> Mail:
        """An Outlook .msg from its bytes. The transport headers (PR_TRANSPORT_MESSAGE_HEADERS), when the
        message has them, are read exactly as an .eml's; else From, To, Subject and Date are made from
        the MAPI properties and marked '(from MAPI properties)' in notes."""
        streams = _streams if _streams is not None else cfb_streams(data[:MAX_MAIL])
        mail = Mail(name, "msg", data if _streams is None else b"")
        damaged = bool(getattr(streams, "damaged", False)) or len(data) > MAX_MAIL
        if damaged:
            mail.doubt.append("the compound file is damaged or cut")
        p = _msg_props(streams, _prefix)
        fixed = _msg_fixed(streams, _prefix, 32 if _prefix == "" else 24)
        transport = p.get("007D")
        if isinstance(transport, str) and transport.strip():
            head = parse_eml(transport.strip().encode("utf-8", "replace") + b"\r\n\r\n")
            mail.headers, mail.raw_headers = head.headers, head.raw_headers
        else:
            mail.notes.append("no transport headers: From, To, Subject and Date are from MAPI properties")
            mail.doubt.append("a .msg with no transport headers")
            sender = p.get("5D01") or p.get("0C1F") or p.get("0065") or ""
            sname = p.get("0C1A") or p.get("0042") or ""
            if sender or sname:
                mail.headers.append(("From", f"{sname} <{sender}>" if sname and sender else sname or sender))
            for pid, hname in (("0E04", "To"), ("0E03", "Cc"), ("0037", "Subject"), ("1035", "Message-ID")):
                if isinstance(p.get(pid), str) and p[pid]:
                    mail.headers.append((hname, p[pid]))
            when = fixed.get("0039") or fixed.get("0E06")
            if when and when[0] == 0x40 and _filetime(when[1]):
                mail.headers.append(("Date", _mailutils.format_datetime(_filetime(when[1]))))
            mail.raw_headers = list(mail.headers)
        if isinstance(p.get("1000"), str) and p["1000"]:
            mail.bodies.append({"type": "text/plain", "text": p["1000"], "cte": None, "charset": None, "inner": None})
        html_body = p.get("1013")
        if isinstance(html_body, bytes) and html_body:
            mail.bodies.append({"type": "text/html", "text": _text(html_body), "cte": None, "charset": None, "inner": None})
        elif isinstance(html_body, str) and html_body:
            mail.bodies.append({"type": "text/html", "text": html_body, "cte": None, "charset": None, "inner": None})
        rtf = p.get("1009")
        if isinstance(rtf, bytes) and rtf and not mail.bodies:
            try:
                import compressed_rtf
                mail.bodies.append({"type": "text/rtf", "text": _text(compressed_rtf.decompress(rtf)), "cte": None,
                                    "charset": None, "inner": None})
            except Exception:
                mail.notes.append("the RTF body was not decompressed")
        stores = sorted({path[len(_prefix):].split("/", 1)[0] for path in streams
                         if path.startswith(_prefix + "__attach_version1.0_#")})
        for store in stores:
            ap = _msg_props(streams, _prefix + store + "/")
            fn = ap.get("3707") or ap.get("3704") or ap.get("3001")
            inner_prefix = _prefix + store + "/__substg1.0_3701000D/"
            if any(path.startswith(inner_prefix) for path in streams):
                if depth < 4:
                    inner = parse_msg(b"", fn or "attached message", streams, inner_prefix, depth + 1)
                    mail.nested.append(inner)
                mail.notes.append(f"attachment {fn or store} is an embedded message (not hashed: it has no bytes of its own)")
                continue
            body = ap.get("3701")
            data_path = _prefix + store + "/__substg1.0_37010102"
            whole = isinstance(body, bytes) and bool(body) and not damaged and data_path in streams \
                and data_path not in getattr(streams, "short", ())
            if not isinstance(body, bytes):
                body = b""
            if not whole:
                mail.notes.append(f"attachment {fn or store}: its data stream is missing or cut (not hashed, not sized)")
            mail.attachments.append(_attachment(fn if isinstance(fn, str) else None, body,
                                                ap.get("370E") if isinstance(ap.get("370E"), str) else None,
                                                "attachment", ap.get("3712") if isinstance(ap.get("3712"), str) else None,
                                                exact=whole))
        return mail

    # ---- what a file is, and loading ---------------------------------------------------------------

    def _header_block(data: bytes) -> list:
        """The header names of the leading 'Name: value' block of a text, lowercase; [] when the text
        does not begin with one."""
        head = data[:16384]
        if head.startswith(b"\xef\xbb\xbf"):
            head = head[3:]
        names = []
        for line in re.split(rb"\r?\n", head.lstrip(b"\r\n")):
            if not line.strip():
                break
            if line[:1] in b" \t":
                if not names:
                    return []
                continue
            m = re.match(rb"([!-9;-~]{1,60}):(?:\s|$)", line)
            if not m:
                return [] if len(names) < 2 else names
            names.append(m.group(1).decode("ascii").lower())
        return names

    def sniff(data: bytes, name: str = "") -> str:
        """'eml', 'mbox', 'msg' or '' from the bytes; a name only lowers the bar for an .eml."""
        if not data:
            return ""
        if data[:8] == OLE_MAGIC:
            return "msg" if _SUBSTG_W in data else ""
        if data[:5] == b"From " and re.match(rb"From \S+ +\S[^\r\n]*\r?\n", data[:400]):
            rest = data[data.index(b"\n") + 1:]
            if len(set(_header_block(rest)) & KNOWN_HEADERS) >= 2:
                return "mbox"
        names = set(_header_block(data))
        known = names & KNOWN_HEADERS
        if len(known) >= 3 and (names & STRONG_HEADERS or {"from", "to", "subject"} <= names):
            return "eml"
        if str(name).lower().endswith(".eml") and len(known) >= 2:
            return "eml"
        return ""

    def load(data: bytes, name: str = "") -> list:
        """[Mail, ...] of one file: [] when it is not mail."""
        kind = sniff(data, name)
        try:
            if kind == "eml":
                return [parse_eml(data, name)]
            if kind == "mbox":
                return parse_mbox(data, name)
            if kind == "msg":
                return [parse_msg(data, name)]
        except (ValueError, struct.error, IndexError):
            return []
        return []

    # ---- Received, the originating IP --------------------------------------------------------------

    _IP4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])")
    _IP6 = r"(?:IPv6:)?((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})"

    def _ips(text: str) -> list:
        out = []
        for m in _IP4.finditer(text):
            out.append(m.group())
        for m in re.finditer(r"[\[(]\s*" + _IP6 + r"\s*[\])]", text, re.I):
            try:
                out.append(str(ipaddress.ip_address(m.group(1))))
            except ValueError:
                pass
        return list(dict.fromkeys(out))

    def _public(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        # The documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) are
        # what a synthetic challenge uses for "the internet": they count as public here.
        doc = any(a in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")) \
            if a.version == 4 else a in ipaddress.ip_network("2001:db8::/32")
        return doc or not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast
                           or a.is_unspecified)

    def received_chain(mail: Mail) -> list:
        """The Received headers as they stand in the file (the newest hop first, the sender's last)."""
        out = []
        for value in mail.get_all("Received"):
            main, _, date = value.rpartition(";")
            if not main:
                main, date = value, ""
            m_by = re.search(r"(?:^|\s)by\s+(\S+)", main)
            frm = main[:m_by.start()] if m_by else main
            m_from = re.match(r"\s*from\s+(\S+)", frm)
            rdns = re.search(r"\(\s*([A-Za-z0-9._-]+\.[A-Za-z]{2,})\s*[\[(]", frm)
            hop = {"from": m_from.group(1) if m_from else None, "helo": m_from.group(1) if m_from else None,
                   "rdns": rdns.group(1) if rdns else None, "ips": _ips(frm),
                   "by": m_by.group(1).rstrip(";") if m_by else None, "with": None, "id": None, "for": None,
                   "date": date.strip() or None, "raw": value}
            rest = main[m_by.end():] if m_by else ""
            for key, rx in (("with", r"\bwith\s+(\S+)"), ("id", r"\bid\s+(\S+)"), ("for", r"\bfor\s+<?([^>\s;]+)>?")):
                m = re.search(rx, rest)
                if m:
                    hop[key] = m.group(1).rstrip(";")
            helo = re.search(r"\b(?:helo|ehlo)[=\s]+\[?([^\s)\]]+)", frm, re.I)
            if helo:
                hop["helo"] = helo.group(1)
            out.append(hop)
        return out

    ORIGIN_HEADERS = ("X-Originating-IP", "X-Sender-IP", "X-Source-IP", "X-Client-IP", "X-Originating-Client-IP",
                      "X-MS-Exchange-Organization-OriginalClientIPAddress", "X-Remote-IP", "X-Real-IP")

    def originating(mail: Mail) -> dict:
        """{headers: {name: ip}, earliest: ip of the earliest Received hop that has one, earliest_public:
        the earliest public one, spf_client: client-ip of Received-SPF, candidates: the distinct ones,
        ip: the one IP when every candidate agrees, else None}."""
        heads = {}
        for h in ORIGIN_HEADERS:
            v = mail.get(h)
            got = _ips("[" + v.strip().strip("[]") + "]") if v else []
            if got:
                heads[h] = got[0]
        chain = received_chain(mail)
        earliest = earliest_public = None
        for hop in reversed(chain):
            if hop["ips"] and earliest is None:
                earliest = hop["ips"][0]
            pub = [ip for ip in hop["ips"] if _public(ip)]
            if pub and earliest_public is None:
                earliest_public = pub[0]
        spf = None
        for v in mail.get_all("Received-SPF"):
            m = re.search(r"client-ip=([^;\s]+)", v)
            if m and _ips("[" + m.group(1) + "]"):
                spf = _ips("[" + m.group(1) + "]")[0]
                break
        cands = list(dict.fromkeys([*heads.values(), *([earliest_public or earliest] if (earliest_public or earliest) else [])]))
        return {"headers": heads, "earliest": earliest, "earliest_public": earliest_public, "spf_client": spf,
                "candidates": cands, "ip": cands[0] if len(cands) == 1 else None}

    # ---- SPF, DKIM, DMARC -----------------------------------------------------------------------------

    _AUTH_METHODS = ("spf", "dkim", "dmarc", "arc", "compauth", "dara", "bimi", "iprev", "auth", "sender-id")

    def _tags(value: str) -> dict:
        out = {}
        for item in value.split(";"):
            k, sep, v = item.partition("=")
            if sep and k.strip():
                out.setdefault(k.strip().lower(), re.sub(r"\s+", "", v) if k.strip().lower() in ("b", "bh", "h") else v.strip())
        return out

    def _split_outside_parens(value: str) -> list:
        """The clauses of a header value, split at the semicolons that stand outside a comment."""
        out, depth, cur = [], 0, []
        for ch in value:
            if ch == "(":
                depth += 1
            elif ch == ")" and depth:
                depth -= 1
            if ch == ";" and not depth:
                out.append("".join(cur))
                cur = []
            else:
                cur.append(ch)
        out.append("".join(cur))
        return out

    def auth_results(mail: Mail) -> dict:
        """{method: {results: [every result stated, in file order], result: the one result when all
        agree, props: {name: value}}} from Authentication-Results and Received-SPF, plus
        'dkim_signature': the tags of the first DKIM-Signature (d, s, a, bh, h ...). ARC-* headers are
        another server's copy and are not read."""
        out = {}

        def slot(method):
            return out.setdefault(method, {"results": [], "result": None, "props": {}})

        for value in mail.get_all("Authentication-Results"):
            for clause in _split_outside_parens(value):
                m = re.match(r"\s*([a-z][a-z-]*)\s*=\s*([a-z]+)", clause, re.I)
                if not m or m.group(1).lower() not in _AUTH_METHODS:
                    continue
                s = slot(m.group(1).lower())
                s["results"].append(m.group(2).lower())
                bare = re.sub(r"\([^()]*\)", " ", clause)
                for pm in re.finditer(r"\b((?:smtp|header|policy|body)\.[a-z0-9_-]+)\s*=\s*([^\s;]+)", bare, re.I):
                    s["props"].setdefault(pm.group(1).lower(), pm.group(2).strip("<>\"'"))
                for pm in re.finditer(r"\b(p|sp|dis|pct|reason)=([A-Za-z0-9_.-]+)", " ".join(re.findall(r"\(([^()]*)\)", clause))):
                    s["props"].setdefault(pm.group(1).lower(), pm.group(2))
                for pm in re.finditer(r"\b(action|reason)=([A-Za-z0-9_.-]+)", bare):
                    s["props"].setdefault(pm.group(1).lower(), pm.group(2))
        for value in mail.get_all("Received-SPF"):
            m = re.match(r"\s*([A-Za-z]+)", value)
            if m:
                s = slot("spf")
                s["results"].append(m.group(1).lower())
                s.setdefault("as_written", m.group(1))
                for pm in re.finditer(r"\b(client-ip|envelope-from|helo|receiver|identity)=\"?([^;\s\"]+)", value):
                    s["props"].setdefault(pm.group(1).lower(), pm.group(2).strip("<>"))
        for s in out.values():
            if len(set(s["results"])) == 1:
                s["result"] = s["results"][0]
        sig = mail.get("DKIM-Signature")
        if sig:
            out["dkim_signature"] = _tags(sig)
            if len(mail.get_all("DKIM-Signature")) > 1:
                out["dkim_signature"]["_count"] = len(mail.get_all("DKIM-Signature"))
        return out

    # ---- addresses and what does not match ---------------------------------------------------------------

    def _decode_tight(value: str) -> str:
        """Encoded words decoded where they stand, nothing added between them and their neighbours (an
        address with one non-ASCII letter is written a@micr=?utf-8?b?0L4=?=soft.example)."""
        if "=?" not in value:
            return value

        def one(m):
            try:
                raw, cs = _mailheader.decode_header(m.group())[0]
                return raw.decode(cs or "ascii", "replace") if isinstance(raw, bytes) else str(raw)
            except Exception:
                return m.group()
        return re.sub(r"=\?[^?\s]+\?[bBqQ]\?[^?\s]*\?=", one, value)

    _ADDR_SPEC = re.compile(r"[^\s<>()\[\],;:\"@]+@[^\s<>()\[\],;:\"@]+")

    def _split_mailboxes(value: str) -> list:
        """A header value cut at the commas (and semicolons) that stand outside quotes, angle brackets
        and comments."""
        out, cur, quote, angle, paren, esc = [], [], False, 0, 0, False
        for ch in value:
            if esc:
                cur.append(ch)
                esc = False
                continue
            if ch == "\\" and (quote or paren):
                cur.append(ch)
                esc = True
                continue
            if ch == '"' and not paren:
                quote = not quote
            elif not quote:
                if ch == "(":
                    paren += 1
                elif ch == ")" and paren:
                    paren -= 1
                elif ch == "<" and not paren:
                    angle += 1
                elif ch == ">" and angle and not paren:
                    angle -= 1
                elif ch in ",;" and not angle and not paren:
                    out.append("".join(cur))
                    cur = []
                    continue
            cur.append(ch)
        out.append("".join(cur))
        return [x.strip() for x in out if x.strip()]

    def _addrs(values) -> list:
        """[(display name, address)] of raw (not yet decoded) header values. The mailboxes are split
        first and the encoded words decoded after, so a comma inside an encoded display name stays in
        the name; `name@a.example <real@b.example>` is the address in the brackets with the other as
        its display name (the standard library's strict reader gives nothing for it); an address
        written wholly as an encoded word is decoded."""
        out = []
        for value in values:
            if not value:
                continue
            for box in _split_mailboxes(_unfold(value)):
                box = re.sub(r"^[^:<>@\"]*:\s*(?=\S)", "", box) if re.match(r"^[^:<>@\"]*:\s*\S", box) and "@" in box else box   # group name:
                m = re.search(r"<([^<>]*)>\s*(?:\([^()]*\)\s*)?$", box)
                if m:
                    addr = m.group(1).strip()
                    name = box[:m.start()].strip()
                else:
                    c = re.match(r"^(\S+@\S+)\s*\((.*)\)$", box)
                    if c:
                        addr, name = c.group(1), c.group(2)
                    else:
                        plain = _decode_tight(box).strip().strip('"') if re.fullmatch(r"\S+", box) else _decode_words(box).strip().strip('"')
                        if _ADDR_SPEC.fullmatch(plain):
                            addr, name = plain, ""
                        elif "@" in plain and _ADDR_SPEC.search(plain) and " " not in plain:
                            addr, name = _ADDR_SPEC.search(plain).group(), ""
                        else:
                            addr, name = "", plain
                name = _decode_words(name).strip()
                if len(name) >= 2 and name[0] == name[-1] == '"':
                    name = name[1:-1].replace('\\"', '"').replace("\\\\", "\\")
                addr = re.sub(r"\s+", "", _decode_tight(addr)).strip("<>")
                if addr or name:
                    out.append((name, addr))
        return out

    def addresses(mail: Mail) -> dict:
        out = {}
        for key, header in (("from", "From"), ("sender", "Sender"), ("reply_to", "Reply-To"),
                            ("return_path", "Return-Path"), ("to", "To"), ("cc", "Cc"), ("bcc", "Bcc"),
                            ("delivered_to", "Delivered-To"), ("envelope_to", "X-Original-To")):
            out[key] = _addrs(mail.raw_all(header))
        return out

    def domain_of(address: str):
        if not address or "@" not in address:
            return None
        return address.rsplit("@", 1)[1].strip().strip(">.").lower() or None

    def _related(a: str, b: str) -> bool:
        return a == b or a.endswith("." + b) or b.endswith("." + a)

    def _differs(a, b):
        """True: two unrelated domains. False: the very same address. None: anything between (the same
        domain with another mailbox, a subdomain of the other), which the bytes do not settle."""
        if not a or not b:
            return None
        if a.lower() == b.lower():
            return False
        da, db = domain_of(a), domain_of(b)
        if not da or not db or _related(da, db):
            return None
        return True

    def mismatches(mail: Mail) -> dict:
        """{reply_to_mismatch, return_path_mismatch, display_name_spoof: True, False or None (not
        settled by the bytes), display_name_address: the address or domain written inside From's
        display name}."""
        ad = addresses(mail)
        frm = ad["from"][0] if len(ad["from"]) == 1 else None
        out = {"reply_to_mismatch": None, "return_path_mismatch": None, "display_name_spoof": None,
               "display_name_address": None}
        if frm and frm[1]:
            if len(ad["reply_to"]) == 1:
                out["reply_to_mismatch"] = _differs(ad["reply_to"][0][1], frm[1])
            if len(ad["return_path"]) == 1:
                out["return_path_mismatch"] = _differs(ad["return_path"][0][1], frm[1])
            inside = re.search(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)", frm[0] or "")
            if inside:
                out["display_name_address"] = inside.group()
                d = _differs(inside.group(), frm[1])
                out["display_name_spoof"] = d
        return out

    # ---- URLs ----------------------------------------------------------------------------------------------

    _URL = re.compile(r"(?i)\b(?:h(?:tt|xx|\*\*)ps?|ftp)(?:\[://\]|(?:\[:\]|:)(?://|\[//\]))[^\s\"'<>`]{3,2000}")
    _DEFANG = ((r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}", "."), (r"\[:\]", ":"), (r"\[://\]", "://"),
               (r"\[/\]", "/"), (r"\[at\]|\(at\)|\[@\]", "@"))

    def refang(url: str) -> str:
        out = url
        for rx, to in _DEFANG:
            out = re.sub(rx, to, out, flags=re.I)
        out = re.sub(r"^h(?:xx|\*\*)p", "http", out)
        out = re.sub(r"^H(?:XX|\*\*)P", "HTTP", out)
        out = re.sub(r"(?i)^(https?|ftp):\[//\]", r"\1://", out)
        return out

    def is_defanged(url: str) -> bool:
        return refang(url) != url

    def url_host(url: str):
        m = re.match(r"(?i)[a-z][a-z0-9+.-]*://(?:[^/@?#\s]*@)?(\[[0-9a-f:.]+\]|[^/:?#\s]+)", refang(url))
        return m.group(1).lower().rstrip(".") if m else None

    def defang(url: str, scheme: bool = True) -> str:
        """hxxps://evil[.]example/path: the dots of the host bracketed, http written hxxp."""
        url = refang(url)
        m = re.match(r"(?i)([a-z][a-z0-9+.-]*)(://)((?:[^/@?#\s]*@)?)([^/?#\s]+)(.*)$", url, re.S)
        if not m:
            return url.replace(".", "[.]")
        sch, sep, user, host, rest = m.groups()
        if scheme:
            sch = re.sub(r"(?i)^h(tt)p", lambda x: "h" + ("xx" if x.group(1) == "tt" else "XX") + "p", sch)
        return sch + sep + user + host.replace(".", "[.]") + rest

    def _trim_url(u: str) -> str:
        u = u.rstrip(".,;:!?")
        while u and u[-1] in ")]}" and u.count({")": "(", "]": "[", "}": "{"}[u[-1]]) < u.count(u[-1]):
            u = u[:-1].rstrip(".,;:!?")
        return u

    class _Links(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.found, self.text, self._a, self.scripts, self._script = [], [], None, [], None
            self.downloads = []

        def handle_starttag(self, tag, attrs):
            a = {k.lower(): (v or "") for k, v in attrs}
            if tag == "a":
                self._a = {"url": a.get("href", "").strip(), "where": "html:href", "display": "",
                           "download": a.get("download")}
                if "download" in a:
                    self.downloads.append(a.get("download") or "")
            elif tag in ("form",) and a.get("action"):
                self.found.append({"url": a["action"].strip(), "where": "html:form-action", "display": None})
            elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
                m = re.search(r"(?i)url\s*=\s*['\"]?([^'\";>\s]+)", a.get("content", ""))
                if m:
                    self.found.append({"url": m.group(1), "where": "html:meta-refresh", "display": None})
            elif tag in ("img", "script", "iframe", "embed", "source", "link", "object", "area", "base") :
                key = "href" if tag in ("link", "area", "base") else ("data" if tag == "object" else "src")
                if a.get(key):
                    where = "html:href" if tag == "area" else f"html:{tag}-{key}"
                    self.found.append({"url": a[key].strip(), "where": where, "display": None})
            if tag == "script":
                self._script = []

        def handle_endtag(self, tag):
            if tag == "a" and self._a is not None:
                self._a["display"] = " ".join(self._a["display"].split())
                self.found.append(self._a)
                self._a = None
            if tag == "script" and self._script is not None:
                self.scripts.append("".join(self._script))
                self._script = None

        def handle_data(self, data):
            if self._script is not None:
                self._script.append(data)
                return
            if self._a is not None:
                self._a["display"] += data
            self.text.append(data)

    def _parse_html(text: str) -> _Links:
        p = _Links()
        try:
            p.feed(text)
            p.close()
        except Exception:
            pass
        return p

    def _url_entry(url, where, display=None) -> dict:
        url = url.strip()
        clean = refang(url)
        return {"url": url, "where": where, "display": display, "refanged": clean, "defanged": defang(clean),
                "host": url_host(clean), "was_defanged": clean != url}

    def _html_sources(mail: Mail) -> list:
        """[(where, html text)]: the HTML bodies and the HTML (or SVG) attachments."""
        out = [("body", b["text"]) for b in mail.bodies if b["type"] == "text/html"]
        for a in mail.attachments:
            fn = (a["filename"] or "").lower()
            if a["true_type"].startswith(("html", "xml")) or fn.endswith((".html", ".htm", ".shtml", ".xhtml", ".svg", ".hta")):
                if a["size"] <= MAX_IMAGE:
                    out.append((f"attachment:{a['filename'] or '?'}", _text(a["data"])))
        return out

    def urls(mail: Mail, qr: bool = False) -> list:
        """Every URL of the mail, in reading order: [{url, where, display, refanged, defanged, host,
        was_defanged}]. where: 'body:text', 'body:html:href', 'body:html:img-src' ...,
        'attachment:<name>:html:href', and 'qr:<image>' when qr is asked for. mailto:, cid:, data:,
        javascript: and tel: targets and bare fragments are not URLs here."""
        key = ("urls", qr)
        if key in mail._cache:
            return mail._cache[key]
        out = []
        for b in mail.bodies:
            if b["type"] != "text/html":
                for text in (b["text"], b.get("inner") or ""):
                    for m in _URL.finditer(text):
                        out.append(_url_entry(_trim_url(m.group()), "body:text"))
        for where, text in _html_sources(mail):
            p = _parse_html(text)
            for f in p.found:
                u = f["url"]
                if not u or re.match(r"(?i)(mailto|cid|data|javascript|tel|about|blob|file):|#", u):
                    continue
                if not re.match(r"(?i)[a-z][a-z0-9+.-]*(\[:\]|:)", u) and not u.startswith("//"):
                    continue        # a relative path names no host
                out.append(_url_entry(u, f"{where}:{f['where']}", f.get("display")))
            seen = {e["refanged"] for e in out}
            for chunk in ("".join(p.text), *p.scripts):
                for m in _URL.finditer(chunk):
                    e = _url_entry(_trim_url(m.group()), f"{where}:html:text")
                    if e["refanged"] not in seen:
                        seen.add(e["refanged"])
                        out.append(e)
        if qr:
            for code in qr_codes(mail):
                for m in _URL.finditer(code["text"]):
                    out.append(_url_entry(_trim_url(m.group()), f"qr:{code['image']}"))
        mail._cache[key] = out
        return out

    def link_mismatches(mail: Mail) -> list:
        """Anchors whose visible text is itself a URL or a host that differs from the target's host."""
        out = []
        for e in urls(mail):
            shown = (e.get("display") or "").strip()
            if not shown or not e["where"].endswith("html:href"):
                continue
            m = _URL.search(shown) or re.search(r"\b(?:[a-z0-9-]+(?:\[\.\]|\.))+[a-z]{2,24}\b", shown, re.I)
            if not m:
                continue
            host = url_host(m.group()) or refang(m.group()).lower()
            if host and e["host"] and host != e["host"]:
                out.append({"shown": m.group(), "shown_host": host, "target": e["url"], "target_host": e["host"]})
        return out

    # ---- homoglyph and IDN domains -------------------------------------------------------------------------

    CONFUSABLE = {
        # Cyrillic
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
        "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "в": "b", "к": "k", "м": "m", "н": "h", "т": "t",
        "ґ": "r", "г": "r", "ь": "b", "ё": "e", "ї": "i", "ә": "e", "ѵ": "v", "ց": "g", "ո": "n", "ս": "u",
        # Greek
        "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "ε": "e", "υ": "u", "χ": "x",
        "η": "n", "β": "b", "ϲ": "c", "ϳ": "j", "ω": "w", "μ": "u", "γ": "y",
        # Latin look-alikes
        "ı": "i", "ɩ": "i", "ɡ": "g", "ɑ": "a", "ƅ": "b", "ʏ": "y", "ᴠ": "v", "ᴡ": "w", "ɴ": "n", "ꜱ": "s",
        "ℓ": "l", "ǀ": "l", "ł": "l", "đ": "d", "ø": "o", "ß": "b", "æ": "ae", "œ": "oe", "ð": "d", "þ": "p",
        "ħ": "h", "ŧ": "t", "ɗ": "d", "ƙ": "k", "ɓ": "b", "ƴ": "y", "ȷ": "j",
    }

    def skeleton(label: str) -> str:
        """The ASCII letters a Unicode domain shows: the confusable table, then accents dropped."""
        out = []
        for ch in label:
            if ch in CONFUSABLE:
                out.append(CONFUSABLE[ch])
                continue
            norm = unicodedata.normalize("NFKD", ch)
            base = "".join(c for c in norm if not unicodedata.combining(c))
            out.append("".join(CONFUSABLE.get(c, c) for c in base))
        return "".join(out).lower()

    def idn_forms(domain: str):
        """{unicode, punycode, skeleton, scripts} of a domain with a non-ASCII or an xn-- label; None
        for a plain ASCII one or one that does not decode."""
        domain = domain.strip().strip(".")
        labels_u, labels_a, idn = [], [], False
        for lab in domain.split("."):
            if lab.lower().startswith("xn--"):
                try:
                    u = codecs.decode(lab[4:].encode("ascii"), "punycode")
                except (UnicodeError, ValueError):
                    return None
                labels_u.append(u)
                labels_a.append(lab.lower())
                idn = True
            elif any(ord(c) > 127 for c in lab):
                u = unicodedata.normalize("NFC", lab).lower()
                try:
                    labels_a.append("xn--" + codecs.encode(u, "punycode").decode("ascii"))
                except (UnicodeError, ValueError):
                    return None
                labels_u.append(u)
                idn = True
            else:
                labels_u.append(lab.lower())
                labels_a.append(lab.lower())
        if not idn:
            return None
        uni = ".".join(labels_u)
        scripts = sorted({unicodedata.name(c, "?").split(" ")[0].lower() for c in uni if ord(c) > 127})
        skel = ".".join(skeleton(lab) for lab in labels_u)
        return {"unicode": uni, "punycode": ".".join(labels_a), "skeleton": skel if skel.isascii() else None,
                "scripts": scripts}

    def domains(mail: Mail) -> list:
        """[(domain as written, where)] of the address headers and the URLs, each once."""
        out, seen = [], set()

        def add(d, where):
            if d and (d.lower(), where) not in seen:
                seen.add((d.lower(), where))
                out.append((d, where))

        for key, pairs in addresses(mail).items():
            for _, a in pairs:
                add(domain_of(a), key)
        for e in urls(mail):
            add(e["host"], "url")
        return out

    _COMMON_LABELS = {"www", "mail", "com", "net", "org", "app", "netlify", "google", "microsoft", "outlook", "office", "gmail",
                      "yahoo", "hotmail", "protonmail", "proton", "github", "amazonaws", "cloudfront", "azurewebsites", "web",
                      "sites", "blogspot", "wordpress", "herokuapp", "vercel", "pages", "firebaseapp", "onmicrosoft", "sharepoint"}

    def _edit_distance(a: str, b: str, cap: int = 3) -> int:
        """Levenshtein distance with a swap of two neighbours counted once; cap + 1 when over the cap."""
        if abs(len(a) - len(b)) > cap:
            return cap + 1
        prev2, prev = None, list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            cur = [i]
            for j, cb in enumerate(b, 1):
                v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
                if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                    v = min(v, prev2[j - 2] + 1)
                cur.append(v)
            prev2, prev = prev, cur
        return prev[-1]

    _LOOK = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("l", "i"), ("5", "s"), ("cl", "d"))

    def _look_key(label: str) -> str:
        """A label with the classic visual swaps folded (rn/m, vv/w, 0/o, 1 and l and i, 5/s, cl/d)."""
        t = label.lower()
        for a, b in _LOOK:
            t = t.replace(a, b)
        return t

    LOOKALIKE_ALL_PAIRS = 150       # labels up to which every pair of a mail's domain labels is compared

    def lookalikes(mail: Mail) -> list:
        """[{domain, where, resembles, resembles_where, label, other_label, distance}]: pairs of
        domains of the mail (address headers, URLs) with a label of six or more characters that
        differs from a label of the other by one edit, one swap, or only by look-alike characters
        (ASCII: the homoglyphs() reader does IDN). The pair is ordered when one side is where the
        mail's own parties are (From, To, Cc) and the other only in a link or a reply path: the second
        is then `domain`, the look-alike; otherwise the order is the reading order. A reader's hint."""
        seen, labels = set(), []
        for d, where in domains(mail):
            for lab in d.lower().split("."):
                if len(lab) >= 6 and lab not in _COMMON_LABELS and not lab.startswith("xn--") and (lab, d.lower()) not in seen:
                    seen.add((lab, d.lower()))
                    labels.append((lab, d.lower(), where))
        places = {}
        for d, where in domains(mail):
            places.setdefault(d.lower(), []).append(where)
        out, done = [], set()
        # Every pair is compared while the mail names few domains. A mail with hundreds (a newsletter,
        # a list of links) is compared only against the domains of its own parties: all pairs of 800
        # labels took 5 s, and a look-alike is a look-alike of one of the parties.
        party = {lab for lab, d, _ in labels if any(w in ("from", "sender", "to", "cc", "reply_to", "return_path") for w in places.get(d, ()))}
        wide = len(labels) <= LOOKALIKE_ALL_PAIRS
        for i, (la, da, _) in enumerate(labels):
            if not wide and la not in party and not party:
                break
            for lb, db, _ in labels[i + 1:]:
                if la == lb or da == db or abs(len(la) - len(lb)) > 2 or (not wide and la not in party and lb not in party):
                    continue
                if (la, lb) in done or (lb, la) in done:
                    continue
                dist = _edit_distance(la, lb, 2)
                if dist == 1 or (dist <= 2 and _look_key(la) == _look_key(lb)):
                    done.add((la, lb))
                    own = lambda d: any(w in ("from", "sender", "to", "cc") for w in places.get(d, ()))     # noqa: E731
                    first, second = (da, la), (db, lb)
                    if own(db) and not own(da):
                        first, second = second, first
                    out.append({"domain": second[0], "where": sorted(set(places.get(second[0], ()))), "label": second[1],
                                "resembles": first[0], "resembles_where": sorted(set(places.get(first[0], ()))), "other_label": first[1],
                                "distance": dist, "ordered": own(first[0]) != own(second[0])})
        return out

    def homoglyphs(mail: Mail) -> list:
        """[{domain, where, unicode, punycode, skeleton, scripts}] for every IDN domain of the mail."""
        out, seen = [], set()
        for d, where in domains(mail):
            forms = idn_forms(d)
            if forms and forms["punycode"] not in seen:
                seen.add(forms["punycode"])
                out.append({"domain": d, "where": where, **forms})
        return out

    # ---- QR codes -----------------------------------------------------------------------------------------------

    _IMAGE_TYPES = ("png", "jpeg", "gif", "webp")

    def images(mail: Mail) -> list:
        """[(name, bytes)] of the image parts and of data: image URIs in the HTML."""
        out = []
        for i, a in enumerate(mail.attachments):
            if a["true_type"] in _IMAGE_TYPES or a["data"][:2] == b"BM":
                out.append((a["filename"] or a["content_id"] or f"part-{i + 1}", a["data"]))
        n = 0
        for where, text in _html_sources(mail):
            for m in re.finditer(r"data:image/[a-z0-9.+-]+;base64,([A-Za-z0-9+/=\s]{40,})", text, re.I):
                try:
                    body = base64.b64decode(re.sub(r"\s+", "", m.group(1)), validate=True)
                except (binascii.Error, ValueError):
                    continue
                n += 1
                out.append((f"{where}:data-uri-{n}", body))
        return out

    def qr_codes(mail: Mail) -> list:
        """[{image, text, type}] of every QR (or other) code pyzbar reads in the mail's images. [] when
        Pillow or pyzbar is missing or QR is off; mail.notes says so."""
        if "qr" in mail._cache:
            return mail._cache["qr"]
        out = []
        pics = images(mail)
        if pics and QR:
            try:
                import io
                from PIL import Image
                from pyzbar import pyzbar
            except Exception as e:       # ImportError, or OSError when libzbar is not found
                mail.notes.append(f"QR codes were not read ({type(e).__name__}: Pillow or pyzbar/libzbar is missing)")
                pics = []
            t0 = time.monotonic()
            for name, body in pics:
                if time.monotonic() - t0 > QR_BUDGET:
                    mail.notes.append(f"{name}: not searched for a QR code (the {QR_BUDGET:g} s budget was spent)")
                    continue
                if len(body) > MAX_IMAGE:
                    mail.notes.append(f"{name}: too large to search for a QR code")
                    continue
                try:
                    im = Image.open(io.BytesIO(body))
                    if im.width * im.height > MAX_PIXELS:
                        continue
                    frames = [im.convert("RGBA")]
                    # A code drawn light on dark, or on a transparent ground, reads only once flattened.
                    flat = Image.new("RGBA", im.size, "white")
                    flat.alpha_composite(frames[0])
                    grey = flat.convert("L")
                    tries = [grey, grey.point(lambda v: 255 - v)]
                    if max(im.size) < 400:
                        tries.append(grey.resize((im.width * 3, im.height * 3)))
                    got = []
                    for t in tries:
                        got = pyzbar.decode(t)
                        if got or time.monotonic() - t0 > QR_BUDGET:
                            break
                    for g in got:
                        out.append({"image": name, "text": _text(g.data), "type": g.type})
                except Exception:
                    mail.notes.append(f"{name}: the image could not be read")
        elif pics:
            mail.notes.append("QR codes were not read (off)")
        mail._cache["qr"] = out
        return out

    # ---- HTML smuggling ---------------------------------------------------------------------------------------------

    SMUGGLE_MARKS = (
        ("atob", r"\batob\s*\("), ("blob", r"\bnew\s+Blob\s*\("), ("create_object_url", r"\bcreateObjectURL\s*\("),
        ("ms_save_blob", r"\bmsSave(?:OrOpen)?Blob\s*\("), ("download_attribute", r"\.download\s*=|setAttribute\(\s*['\"]download['\"]|<a[^>]+\bdownload\b"),
        ("click", r"\.click\s*\(\s*\)"), ("from_char_code", r"\bfromCharCode\b"), ("uint8array", r"\bUint8Array\b"),
        ("data_uri", r"\bdata:[a-z0-9.+/-]+;base64,"), ("char_code_at", r"\bcharCodeAt\b"),
        ("eval", r"\beval\s*\("), ("unescape", r"\bunescape\s*\("), ("document_write", r"\bdocument\.write\s*\("),
        ("file_saver", r"\bsaveAs\s*\("), ("clipboard_write", r"\bclipboard\.writeText\s*\("),
    )

    def smuggling(mail: Mail) -> list:
        """One entry per HTML source that carries a payload it builds in the browser: [{where,
        indicators: [name, ...], download_names: [...], payloads: [{size, sha256, md5, sha1, true_type,
        data}]}]. A payload is a base64 literal of 200 characters or more (or the argument of atob, or
        a data: URI that is not an image) that decodes strictly."""
        if "smuggling" in mail._cache:
            return mail._cache["smuggling"]
        out = []
        for where, text in _html_sources(mail):
            marks = [name for name, rx in SMUGGLE_MARKS if re.search(rx, text, re.I)]
            names = []
            for rx in (r"\.download\s*=\s*['\"]([^'\"]{1,200})['\"]", r"setAttribute\(\s*['\"]download['\"]\s*,\s*['\"]([^'\"]{1,200})['\"]",
                       r"<a[^>]+\bdownload\s*=\s*['\"]([^'\"]{1,200})['\"]", r"\bsaveAs\s*\([^,()]+,\s*['\"]([^'\"]{1,200})['\"]",
                       r"\bmsSave(?:OrOpen)?Blob\s*\([^,()]+,\s*['\"]([^'\"]{1,200})['\"]"):
                for m in re.finditer(rx, text, re.I):
                    if m.group(1) not in names:
                        names.append(m.group(1))
            literals = []
            for m in re.finditer(r"atob\s*\(\s*['\"`]([A-Za-z0-9+/=\s]{16,})['\"`]\s*\)", text):
                literals.append(m.group(1))
            for m in re.finditer(r"data:(?!image/)[a-z0-9.+/-]*;base64,([A-Za-z0-9+/=]{24,})", text, re.I):
                literals.append(m.group(1))
            for m in re.finditer(r"['\"`]([A-Za-z0-9+/]{200,}={0,2})['\"`]", text):
                literals.append(m.group(1))
            payloads, seen = [], set()
            for lit in literals:
                compact = re.sub(r"\s+", "", lit)
                if compact in seen or len(compact) % 4:
                    continue
                seen.add(compact)
                try:
                    body = base64.b64decode(compact, validate=True)
                except (binascii.Error, ValueError):
                    continue
                if body:
                    payloads.append({**{k: v for k, v in _attachment(None, body).items()
                                        if k in ("size", "sha256", "md5", "sha1", "true_type", "data")}})
            if payloads or len({"blob", "create_object_url", "ms_save_blob", "download_attribute", "file_saver"} & set(marks)) >= 2:
                out.append({"where": where, "indicators": marks, "download_names": names, "payloads": payloads})
        mail._cache["smuggling"] = out
        return out

    # ---- everything, for a reader ---------------------------------------------------------------------------------------

    def date_forms(value: str) -> list:
        """[(method, value)] of a Date header: as written, ISO 8601 in UTC and with its own offset, the
        date alone, the Unix time."""
        out = [("as_written", value)]
        try:
            dt = _mailutils.parsedate_to_datetime(value)
            if dt is None:
                return out
            if dt.tzinfo is None:
                out.append(("iso_naive", dt.strftime("%Y-%m-%dT%H:%M:%S")))
                return out
            utc = dt.astimezone(timezone.utc)
            out += [("iso_utc_z", utc.strftime("%Y-%m-%dT%H:%M:%SZ")), ("iso_offset", dt.isoformat()),
                    ("iso_utc_offset", utc.strftime("%Y-%m-%dT%H:%M:%S+00:00")),
                    ("utc_space", utc.strftime("%Y-%m-%d %H:%M:%S")), ("date_utc", utc.strftime("%Y-%m-%d")),
                    ("epoch", str(int(utc.timestamp())))]
        except (TypeError, ValueError, IndexError, OverflowError):
            return out
        return out

    def ext_mismatch(att: dict):
        """True when the bytes are of another family than the name's extension says, False when they
        agree, None when the extension or the type is not in the table."""
        ext = Path(att["filename"] or "").suffix.lower()
        fam = TYPE_FAMILY.get(att["true_type"].split(" ")[0].rstrip(","))
        if att["true_type"].startswith("zip ("):
            fam = "zip"
        want = EXT_FAMILY.get(ext)
        if not ext or want is None or fam is None:
            return None
        return fam not in want

    TYPE_FAMILY = {"zip": "zip", "pdf": "pdf", "png": "png", "jpeg": "jpeg", "gif": "gif", "pe": "pe", "pe+cli": "pe",
                   "mz": "pe", "elf": "elf", "html": "html", "ole": "ole", "rtf": "rtf", "7z": "7z", "rar": "rar",
                   "gzip": "gzip", "lnk": "lnk", "iso-bmff": "mp4", "cab": "cab", "xml": "xml", "json": "json",
                   "text": "text", "webp": "webp", "chm": "chm"}
    EXT_FAMILY = {".zip": {"zip"}, ".pdf": {"pdf"}, ".png": {"png"}, ".jpg": {"jpeg"}, ".jpeg": {"jpeg"}, ".gif": {"gif"},
                  ".exe": {"pe"}, ".dll": {"pe"}, ".scr": {"pe"}, ".html": {"html", "text", "xml"}, ".htm": {"html", "text", "xml"},
                  ".doc": {"ole", "rtf"}, ".xls": {"ole"}, ".ppt": {"ole"}, ".msg": {"ole"}, ".docx": {"zip"},
                  ".xlsx": {"zip"}, ".pptx": {"zip"}, ".docm": {"zip"}, ".xlsm": {"zip"}, ".jar": {"zip"}, ".apk": {"zip"},
                  ".rtf": {"rtf"}, ".7z": {"7z"}, ".rar": {"rar"}, ".gz": {"gzip"}, ".lnk": {"lnk"}, ".txt": {"text"},
                  ".csv": {"text"}, ".json": {"json", "text"}, ".xml": {"xml", "text"}, ".svg": {"xml", "text", "html"},
                  ".cab": {"cab"}, ".chm": {"chm"}, ".webp": {"webp"}, ".iso": set(), ".img": set()}
    # Spellings a judge might use for a file type, snake_case first (never answered plain).
    TYPE_LABELS = {
        "zip": ["zip", "zip_archive", "application/zip"], "pdf": ["pdf", "pdf_document", "application/pdf"],
        "png": ["png", "png_image", "image/png"], "jpeg": ["jpeg", "jpg", "jpeg_image", "image/jpeg"],
        "gif": ["gif", "gif_image", "image/gif"], "pe": ["pe", "pe32", "exe", "windows_executable", "pe_executable"],
        "elf": ["elf", "elf_executable"], "html": ["html", "html_document", "text/html"],
        "ole": ["ole", "ole2", "ole_compound_file", "compound_file", "cfb"], "rtf": ["rtf", "rich_text", "application/rtf"],
        "7z": ["7z", "7zip", "7z_archive"], "rar": ["rar", "rar_archive"], "gzip": ["gzip", "gz", "gzip_archive"],
        "lnk": ["lnk", "windows_shortcut", "shortcut", "shell_link"], "cab": ["cab", "cabinet"],
        "xml": ["xml", "xml_document"], "json": ["json"], "text": ["text", "plain_text", "text/plain"],
        "mp4": ["mp4", "iso_bmff"], "webp": ["webp"], "chm": ["chm", "compiled_html_help"],
    }

    def triage(mail: Mail, qr: bool = True) -> dict:
        """Everything the readers find in one mail, without the attachment bytes."""
        ad = addresses(mail)
        atts = [{k: v for k, v in a.items() if k != "data"} | {"ext_mismatch": ext_mismatch(a)} for a in mail.attachments]
        smug = [{**s, "payloads": [{k: v for k, v in p.items() if k != "data"} for p in s["payloads"]]} for s in smuggling(mail)]
        return {"name": mail.name, "kind": mail.kind, "size": len(mail.raw), "sha256": hashlib.sha256(mail.raw).hexdigest() if mail.raw else None,
                "subject": mail.get("Subject"), "date": mail.get("Date"), "date_forms": date_forms(mail.get("Date")) if mail.get("Date") else [],
                "message_id": mail.get("Message-ID"), "mailer": mail.get("X-Mailer") or mail.get("User-Agent"),
                "addresses": ad, "mismatches": mismatches(mail), "received": received_chain(mail),
                "originating": originating(mail), "auth": auth_results(mail),
                "bodies": [{"type": b["type"], "cte": b["cte"], "charset": b["charset"], "chars": len(b["text"]),
                            "base64_inside": b.get("inner") is not None} for b in mail.bodies],
                "attachments": atts, "urls": urls(mail, qr=qr), "link_mismatches": link_mismatches(mail),
                "homoglyphs": homoglyphs(mail), "lookalikes": lookalikes(mail), "qr": qr_codes(mail) if qr else [], "smuggling": smug,
                "indicators": indicators(mail, qr),
                "nested": [triage(n, qr) for n in mail.nested], "notes": list(mail.notes)}

    def report(mail: Mail, qr: bool = True) -> str:
        t = triage(mail, qr)
        L = [f"== {t['name'] or '(mail)'}  [{t['kind']}, {t['size']} bytes" + (f", sha256 {t['sha256']}" if t["sha256"] else "") + "]"]

        def row(k, v):
            if v not in (None, "", [], {}):
                L.append(f"{k:<18} {v}")

        row("Subject", t["subject"])
        row("Date", t["date"])
        for method, v in t["date_forms"][1:]:
            row(f"  {method}", v)
        row("Message-ID", t["message_id"])
        row("Mailer", t["mailer"])
        for key in ("from", "sender", "reply_to", "return_path", "to", "cc", "bcc", "delivered_to"):
            for name, addr in t["addresses"][key]:
                row(key, f"{addr}" + (f"   (display name: {name!r})" if name else ""))
        mm = t["mismatches"]
        row("reply-to mismatch", mm["reply_to_mismatch"])
        row("return-path mism.", mm["return_path_mismatch"])
        row("display-name spoof", f"{mm['display_name_spoof']} (name holds {mm['display_name_address']})" if mm["display_name_address"] else None)
        L.append(f"Received hops      {len(t['received'])} (newest first)")
        for i, h in enumerate(t["received"], 1):
            L.append(f"  {i}. from {h['from']} helo {h['helo']} ips {','.join(h['ips']) or '-'} by {h['by']} with {h['with']} date {h['date']}")
        o = t["originating"]
        row("originating IP", o["ip"] or ("candidates disagree: " + ", ".join(o["candidates"]) if o["candidates"] else None))
        for h, ip in o["headers"].items():
            row(f"  {h}", ip)
        row("  earliest hop", o["earliest"])
        row("  earliest public", o["earliest_public"])
        row("  spf client-ip", o["spf_client"])
        for method, s in t["auth"].items():
            if method == "dkim_signature":
                row("DKIM-Signature", " ".join(f"{k}={v}" for k, v in s.items() if k in ("d", "s", "a", "c", "_count")))
            else:
                row(method, f"{s['result'] or 'DISAGREE ' + '/'.join(s['results'])}  " + " ".join(f"{k}={v}" for k, v in s["props"].items()))
        for b in t["bodies"]:
            L.append(f"body               {b['type']} cte={b['cte']} charset={b['charset']} chars={b['chars']}"
                     + ("  (base64 text inside, decoded)" if b["base64_inside"] else ""))
        L.append(f"attachments        {len(t['attachments'])}")
        for a in t["attachments"]:
            L.append(f"  - {a['filename']!r} declared={a['declared_type']} true={a['true_type']} size={a['size']}"
                     f" ext_mismatch={a['ext_mismatch']}" + ("" if a["exact"] else "  (re-serialised: do not hash)"))
            L.append(f"    sha256={a['sha256']} md5={a['md5']} sha1={a['sha1']}")
            if a["members"]:
                L.append(f"    members: {', '.join(a['members'][:12])}")
        L.append(f"urls               {len(t['urls'])}")
        for u in t["urls"]:
            L.append(f"  - [{u['where']}] {u['url']}" + (f"   shown as {u['display']!r}" if u["display"] else "")
                     + (f"   refanged {u['refanged']}" if u["was_defanged"] else f"   defanged {u['defanged']}"))
        for m in t["link_mismatches"]:
            L.append(f"  ! link text shows {m['shown_host']} but points to {m['target_host']}")
        for h in t["homoglyphs"]:
            L.append(f"homoglyph domain   {h['unicode']} ({h['where']}) punycode={h['punycode']} skeleton={h['skeleton']} scripts={','.join(h['scripts'])}")
        for k in t["lookalikes"]:
            L.append(f"look-alike domain  {k['domain']} ({','.join(k['where'])}) resembles {k['resembles']} ({','.join(k['resembles_where'])}): "
                     f"{k['label']} / {k['other_label']}, {k['distance']} edit" + ("" if k["ordered"] else "  (which one is the copy is not settled)"))
        for q in t["qr"]:
            L.append(f"QR code            [{q['image']}] {q['type']}: {q['text']}")
        for s in t["smuggling"]:
            L.append(f"HTML smuggling     [{s['where']}] indicators={','.join(s['indicators'])} download={s['download_names']}")
            for p in s["payloads"]:
                L.append(f"  payload size={p['size']} true={p['true_type']} sha256={p['sha256']}")
        row("indicators", ", ".join(t["indicators"]))
        for n in t["notes"]:
            L.append(f"NOTE {n}")
        out = "\n".join(L)
        for n in mail.nested:
            out += "\n\n-- attached message --\n" + report(n, qr)
        return out

    # ---- the lane signal ---------------------------------------------------------------------------------------------------

    _MAIL_WORDS = re.compile(r"\b(?:e-?mail|phish\w*|spf|dkim|dmarc|reply-?to|return-?path|message-?id|x-originating-ip|"
                             r"received header|mail ?server|sender|recipient|attachment|eml|mbox|outlook|quishing|"
                             r"display name|envelope|smuggl\w+|homoglyph|punycode|mailer|subject line|inbox)\b", re.I)

    def mail_files(files: dict) -> list:
        """[(name, bytes, kind)] of the mail files among the files a solver is handed."""
        out = []
        for name, data in _triage.unique_files(files):
            kind = sniff(data, name.split(ARROW)[-1])
            if kind:
                out.append((name, data, kind))
        return out

    def signals(questions, files) -> float:
        """0..1: how strongly this delivery and its questions look like the e-mail category. A mail
        file among the files is 0.7; the share of questions that speak of mail adds up to 0.3 (and is
        all there is, at most 0.3, without a mail file)."""
        try:
            has = bool(mail_files(files or {}))
            qs = list(questions or [])
            hits = sum(1 for q in qs if _MAIL_WORDS.search(_words(q)))
            share = hits / len(qs) if qs else 0.0
            return round((0.7 if has else 0.0) + 0.3 * min(1.0, 2 * share), 3)
        except Exception:
            return 0.0

    # ---- the runner contract ---------------------------------------------------------------------------------------------------

    def _fmt(q) -> dict:
        f = q.get("answer_format")
        return f if isinstance(f, dict) else {}

    def _enum(q) -> list:
        f = _fmt(q)
        for key in ("accepted_values", "options", "choices", "values", "enum"):
            if isinstance(f.get(key), list):
                return [str(v) for v in f[key]]
        return []

    _COMPOUND = ((r"reply[-_]to", "reply-to"), (r"return[-_]path", "return-path"), (r"message[-_]id", "message-id"),
                 (r"x[-_]originating[-_]ip", "x-originating-ip"), (r"x[-_]mailer", "x-mailer"), (r"user[-_]agent", "user-agent"),
                 (r"display[-_]name", "display name"), (r"content[-_]type", "content-type"), (r"file[-_]?name", "filename"),
                 (r"file[-_]type", "file type"), (r"first[-_]hop", "first hop"), (r"last[-_]hop", "last hop"))

    def _words(q) -> str:
        """The question's text and its answer id as lowercase words (the id's separators as spaces)."""
        aid = re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("qid") or q.get("id") or ""))
        aid = aid.lower()
        for i, (rx, _) in enumerate(_COMPOUND):
            aid = re.sub(rx, f"\x00{i}\x00", aid)
        aid = re.sub(r"[-_.]+", " ", aid)
        for i, (_, word) in enumerate(_COMPOUND):
            aid = aid.replace(f"\x00{i}\x00", word)
        return (" ".join(str(q.get("question") or "").split()) + " | " + aid).lower()

    def pick(field: str, options):
        """labels.pick under 'email.<field>'. Until solvers/common/labels.py knows the lane 'email' (its
        LANE_DIRS), the same unsure string is written here: tools/verify.py then lists the answer as
        open and never sends it."""
        opts = [(str(n), v) for n, v in options if v is not None and str(v).strip()]
        seen, uniq = set(), []
        for n, v in opts:
            if v not in seen:
                seen.add(v)
                uniq.append((n, v))
        if not uniq:
            return None
        key = f"{KEY}.{field}".lower()
        try:
            return labels.pick(key, uniq[:labels.MAX_OPTIONS])
        except ValueError:
            return labels.SENTINEL + json.dumps({"k": key, "o": [[n, v] for n, v in uniq[:labels.MAX_OPTIONS]]},
                                                separators=(",", ":"))

    # A question that negates or excludes ("the file that is NOT the attachment", "the size without the
    # attachment", "other than", "except") asks for something this file's reading of it does not prove:
    # never plain. A format instruction ("do not include the 0x prefix", "without quotes") is not one.
    _FORMAT_NEG = re.compile(r"(?i)\b(?:do not|don't|not|without|no|excluding)\s+(?:\w+\s+){0,3}?(?:0x|prefix(?:es)?|quotes?|quotation marks?|units?|spaces?|"
                             r"extensions?|braces|brackets|dashes|hyphens|colons|separators?|padding|zeros?|punctuation|whitespace|newlines?|"
                             r"trailing \w+|leading \w+|scheme|defang\w*)\b")
    _NEGATION = re.compile(r"(?i)\bnot\b|n't\b|\bwithout\b|\bexcluding\b|\bexcept\b|\bother than\b|\bnever\b|\bneither\b|\bminus\b|\bapart from\b")


    def _negates(text) -> bool:
        return _NEGATION.search(_FORMAT_NEG.sub(" ", str(text or ""))) is not None


    def _shape(q, options, plain=False, field="value"):
        """Fit options [(method, value)] to the question's format: an enum keeps only its accepted
        values (in its spelling), a pattern only what matches. plain=True returns the value itself
        when exactly one is left."""
        f = _fmt(q)
        opts = [(n, str(v)) for n, v in options if v is not None and str(v).strip()]
        plain = plain and not _negates(q.get("question"))
        words = (str(f.get("syntax") or "") + " " + str(q.get("question") or "")).lower()
        if re.search(r"\bupper-?case\b", words) and not re.search(r"\blower-?case\b", words):
            opts = [(n, v.upper()) for n, v in opts] if plain else opts + [(n + "_upper", v.upper()) for n, v in opts]
        accepted = _enum(q)
        if accepted or str(f.get("kind")) == "enum":
            by = {a.strip().lower(): a for a in accepted}
            opts = [(n, by[v.strip().lower()]) for n, v in opts if v.strip().lower() in by]
        rx = f.get("pattern") or f.get("regex")
        if isinstance(rx, str) and rx.strip():
            try:
                opts = [(n, v) for n, v in opts if re.fullmatch(rx, v)]
            except re.error:
                return None
        if str(f.get("kind")) == "integer":
            opts = [(n, v) for n, v in opts if re.fullmatch(r"-?\d+", v)]
        if not opts:
            return None
        if plain:
            return opts[0][1] if len({v for _, v in opts}) == 1 else pick(field, opts)
        return pick(field, opts)

    def _bool(q, value: bool, field: str):
        accepted = [a.strip().lower() for a in _enum(q)]
        forms = [("true_false", "true" if value else "false"), ("yes_no", "yes" if value else "no")]
        if accepted:
            return _shape(q, forms, field=field)
        if str(_fmt(q).get("kind")) not in ("", "None", "exact_text", "boolean", "bool"):
            return None
        return pick(field, forms)

    def _addr_forms(pairs, raw=None) -> list:
        """[(method, value)] for one address: bare, lowercase, and the header as written."""
        if len(pairs) != 1 or not pairs[0][1]:
            return []
        a = pairs[0][1]
        return [("address", a), ("address_lower", a.lower()), ("as_written", raw)]

    def _domain_forms(d) -> list:
        if not d:
            return []
        out = [("domain", d.lower())]
        forms = idn_forms(d)
        if forms:
            out += [("punycode", forms["punycode"]), ("unicode", forms["unicode"])]
        return out

    def _url_forms(e, words: str) -> list:
        forms = [("as_written", e["url"]), ("refanged", e["refanged"]), ("defanged", e["defanged"]),
                 ("defanged_dots_only", defang(e["refanged"], scheme=False))]
        if re.search(r"\bdefang", words) and not re.search(r"\b(?:refang|undefang|re-fang|un-defang)", words):
            forms = [forms[2], forms[3], forms[0], forms[1]]
        elif re.search(r"\b(?:refang|undefang|re-fang|un-defang|live|clickable|original)", words):
            forms = [forms[1], forms[0], forms[2], forms[3]]
        return forms

    def _distinct_urls(entries) -> list:
        """One entry per URL (compared refanged), in reading order; a URL written both live and
        defanged is shown by its live writing."""
        order, best = [], {}
        for e in entries:
            k = e["refanged"]
            if k not in best:
                order.append(k)
                best[k] = e
            elif best[k]["was_defanged"] and not e["was_defanged"]:
                best[k] = e
        return [best[k] for k in order]

    _LINK_WHERE = ("body:text", "html:href", "html:form-action", "html:meta-refresh", "html:text")

    def _link_entries(mail: Mail, words: str) -> list:
        """The URLs a question about 'the link' can mean: the QR codes' when it says QR, the
        attachments' when it says attachment, else the body's links (or, when the body has none,
        every source together)."""
        if re.search(r"\bqr\b|quishing|barcode", words):
            return _distinct_urls([e for e in urls(mail, qr=True) if e["where"].startswith("qr:")])
        allu = [e for e in urls(mail) if e["where"].endswith(_LINK_WHERE) or e["where"] == "body:text"]
        if re.search(r"\battach", words):
            return _distinct_urls([e for e in allu if e["where"].startswith("attachment:")])
        body = [e for e in allu if e["where"].startswith("body")]
        return _distinct_urls(body or allu)

    # what an inner-file question may NOT be about: a count, a hash, a size, a type (those are other facts of the member)
    _COUNTISH_INNER = re.compile(r"\bhow many\b|\bnumber of\b|\bcount\b|\bsha-?\d+\b|\bmd5\b|\bhash\b|\bsize\b|\btype\b|\bformat\b|\bextension\b|\bbytes\b")

    def _archive_names(data: bytes):
        """The member names of a zip attachment (directories left out), read from its directory only;
        None for anything that is not a zip this reads."""
        if data[:2] != b"PK":
            return None
        try:
            import io as _io
            import zipfile as _zf
            with _zf.ZipFile(_io.BytesIO(data)) as z:
                return [i.filename for i in z.infolist() if not i.is_dir()][:64]
        except Exception:
            return None

    def _target_attachment(q, mail: Mail, words: str):
        """The one attachment a question is about: named in the question or as its member, the n-th
        when it says so, or the only one."""
        atts = [a for a in mail.attachments if a["filename"] or a["disposition"] == "attachment"] or list(mail.attachments)
        text = str(q.get("question") or "")
        member = Path(str(q.get("member") or "")).name
        named = [a for a in atts if a["filename"] and (a["filename"] == member or
                 re.search(r"(?<![\w.-])" + re.escape(a["filename"]) + r"(?![\w-])", text))]
        # a name that is part of a longer named one (a.pdf in data.pdf) is the longer one's
        named = [a for a in named if not any(b is not a and a["filename"] != b["filename"]
                                             and a["filename"] in b["filename"] for b in named)]
        if len(named) == 1:
            return named[0]
        if named:
            return None
        ordinal = re.search(r"\b(first|second|third|fourth|fifth|last|1st|2nd|3rd|4th|5th)\s+attach", words)
        if ordinal:
            i = {"first": 0, "1st": 0, "second": 1, "2nd": 1, "third": 2, "3rd": 2, "fourth": 3, "4th": 3,
                 "fifth": 4, "5th": 4, "last": -1}[ordinal.group(1)]
            try:
                return atts[i]
            except IndexError:
                return None
        return atts[0] if len(atts) == 1 else None

    def _hash(q, data: bytes, algo: str):
        value = hashlib.new(algo, data).hexdigest()
        return _shape(q, [("hex", value)], plain=True, field=f"hash/{algo}")

    _COUNT_FILLER = set("""how many what is are was were the a an number count total of there in on to this that it its does do did
        have has had contain contains include includes carry carries e-mail email mail message sample phishing
        file eml msg mbox mailbox archive given provided delivered present exist exists exactly pass passes
        passed through traverse traversed list lists listed show shows shown and or by for""".split())
    _NOUNS = {"attachments": "attachments attachment attached files", "received": "received hops hop relays relay headers header lines",
              "urls": "urls url links link hyperlinks", "recipients": "recipients recipient",
              "messages": "messages emails e-mails mails"}

    def _bare_count(text: str, noun: str) -> bool:
        """True when a count question has no qualifier: every word of it is a filler or the counted
        noun itself ("How many attachments does the email have?", not "... are executables")."""
        ok = _COUNT_FILLER | set(_NOUNS[noun].split())
        return all(wd in ok for wd in re.findall(r"[a-z][a-z-]*", text.lower()))

    _OTHER_OBJECT = re.compile(r"\battach|\bpayload\b|\bbody\b|\bheader|\bimage\b|\bpicture\b|\bqr\b|\burl\b|\blink\b|\bscript\b|"
                               r"\bpdf\b|\bdocument\b|\bmacro\b|\bembedded\b|\binside\b|\bwithin\b|\bcontained\b|\bzip\b|\barchive\b")

    def _about_mail_file(q, mail: Mail, text: str) -> bool:
        """True when a hash question is about the mail file itself: "the SHA-256 of the email", the
        file's own name, or "its ..." with the mail file as the question's member; and it names
        nothing else (an attachment, a body, an image, a document)."""
        if _OTHER_OBJECT.search(text) or _INDIRECT.search(text) or re.search(r"\bdecoded\b|\btext\b|\bnormali[sz]ed\b", text):
            return False
        base = Path(str(mail.name)).name.lower()
        if base and re.search(r"(?:of|for)\s+(?:the\s+)?(?:file\s+)?[`'\"]?" + re.escape(base) + r"[`'\"]?(?![\w-])", text):
            return True
        if re.search(r"(?:of|for)\s+(?:the|this)\s+(?:phishing\s+|suspicious\s+|delivered\s+|malicious\s+)?"
                     r"(?:e-?mail|message|mail|eml|msg)(?:\s+(?:file|message))?\s*(?:[?.,(]|$|\bas\b|\bin (?:hex|lower|upper))", text):
            return True
        member = Path(str(q.get("member") or "")).name.lower()
        return bool(member and member == base and re.search(r"\bits\b|\bthis file\b|\bthe file\b", text))

    # A hash or size "of the file inside the attached zip", "of the e-mail that carries the attachment",
    # "of the decoded macro": another object than the attachment (or payload, or mail file) itself.
    _INDIRECT = re.compile(r"\binside\b|\bwithin\b|\bcontain\w*|\bextract\w*|\bunzip\w*|\bdecompress\w*|\bunpack\w*|"
                           r"\bmembers?\b|\bmacros?\b|\bdecrypt\w*|\bdeobfuscat\w*|\bstage\b|\bfinal\b|\bbase64\b|\bencoded\b|"
                           r"\b(?:e-?mail|message|mail)\s+(?:that|which|with|carrying|having|holding)\b|"
                           r"\bfile\s+(?:in|from)\s+the\b")

    _ALGOS = (("sha256", r"sha-?256"), ("sha512", r"sha-?512"), ("sha1", r"sha-?1"), ("md5", r"md5"))
    _BOOLISH = re.compile(r"^(?:does|do|did|is|are|was|were|has|have|can|should)\b|\bmismatch|\bdiffer|\bmatch(?:es)?\b|"
                          r"\bsame as\b|\bspoof(?:ed|ing)?\b|\btrue or false\b|\byes or no\b")

    def answer(q, mail: Mail):
        """One question's answer about one mail: plain, an unsure pick, or None (see the module text)."""
        f = _fmt(q)
        kind = str(f.get("kind") or "")
        w = _words(q)
        text = w.split(" | ")[0]
        if kind in ("json", "ordered_tokens"):
            return None

        if kind == "mitre_attack_id" or re.search(r"\bmitre\b|att&ck|\btechnique id\b", w):
            has_att = any(a["filename"] or a["disposition"] == "attachment" for a in mail.attachments)
            has_url = bool(_link_entries(mail, ""))
            if has_att and not has_url:
                return _shape(q, [("spearphishing_attachment", "T1566.001")], field="attack/attachment")
            if has_url and not has_att:
                return _shape(q, [("spearphishing_link", "T1566.002")], field="attack/link")
            return None

        # -- an enum that names what the mail does (html_smuggling, qr_code, reply_to_mismatch ...) ---
        if _indicator_enum(q):
            return _by_indicator(q, mail)

        # -- hashes ------------------------------------------------------------------------------
        algos =[name for name, rx in _ALGOS if re.search(r"\b" + rx + r"\b", w)]
        if algos or re.search(r"\b(?:hash|digest|checksum)\b", w):
            if len(algos) != 1:
                return None
            algo = algos[0]
            if re.search(r"\bpayload|smuggl|dropped|decoded file|embedded file|blob\b", w):
                # Never plain: the base64 literal is one layer. Whether the script XORs, reverses or
                # joins it before it saves the file cannot be proven without running it.
                loads = [p for s in smuggling(mail) for p in s["payloads"]]
                if len(loads) != 1 or _INDIRECT.search(text):
                    return None
                return _shape(q, [("base64_literal_decoded", hashlib.new(algo, loads[0]["data"]).hexdigest())],
                              field=f"payload_hash/{algo}")
            if re.search(r"\bbody\b|\bheader", w):
                return None
            if _INDIRECT.search(text):
                return None
            att = _target_attachment(q, mail, w)
            if re.search(r"\battach", w) or (att is not None and att["filename"] and att["filename"].lower() in text):
                return _hash(q, att["data"], algo) if att is not None and att["exact"] else None
            if q.get("member") and att is not None and att["filename"] == Path(str(q["member"])).name:
                return _hash(q, att["data"], algo) if att["exact"] else None
            if mail.raw and _about_mail_file(q, mail, text):
                return _hash(q, mail.raw, algo)
            return None

        # -- counts ------------------------------------------------------------------------------
        if re.search(r"\bhow many\b|\bnumber of\b|\bcount\b|\btotal\b", w):
            # Plain only for the bare question ("How many attachments does the email have?"). A
            # qualifier ("... are executables", "distinct", "external") makes it another count: unsure.
            if re.search(r"\battach", w):
                named = [a for a in mail.attachments if a["filename"]]
                disp = [a for a in mail.attachments if a["disposition"] == "attachment"]
                either = [a for a in mail.attachments if a["filename"] or a["disposition"] == "attachment"]
                no_cid = [a for a in either if not a["content_id"]]      # an inline picture is not everyone's attachment
                return _shape(q, [("named_or_attachment", len(either)), ("named", len(named)),
                                  ("attachment_disposition", len(disp)), ("non_body_parts", len(mail.attachments)),
                                  ("without_content_id", len(no_cid))],
                              plain=_bare_count(text, "attachments") and not mail.doubt and bool(either),
                              field="count/attachments")       # a plain count is never 0: none found is not none there
            if re.search(r"\breceived\b|\bhops?\b|\brelay", w):
                # "Received headers" is the count the bytes fix; "hops" and "relays" are a reading of it.
                return _shape(q, [("received_headers", len(mail.get_all("Received")))],
                              plain=_bare_count(text, "received") and "received" in text and not mail.doubt
                              and bool(mail.get_all("Received")),
                              field="count/received")
            if re.search(r"\bservers?\b|\bmtas?\b", w):
                return _shape(q, [("received_headers", len(mail.get_all("Received")))], field="count/servers")
            if re.search(r"\burls?\b|\blinks?\b|hyperlink", w):
                ent = [e for e in urls(mail) if e["where"].endswith(_LINK_WHERE)]
                return _shape(q, [("distinct", len(_distinct_urls(ent))), ("all", len(ent)),
                                  ("distinct_with_sources", len(_distinct_urls(urls(mail))))], field="count/urls")   # never plain: what is a URL is a reading
            if re.search(r"\brecipient", w):
                to = {a.lower() for _, a in addresses(mail)["to"] if a}
                tocc = to | {a.lower() for _, a in addresses(mail)["cc"] if a}
                return _shape(q, [("to", len(to)), ("to_and_cc", len(tocc))], field="count/recipients") if to else None
            if re.search(r"\bqr\b", w):
                return _shape(q, [("codes", len(qr_codes(mail)))], field="count/qr") if qr_codes(mail) else None
            return None

        # -- size --------------------------------------------------------------------------------
        if re.search(r"\bsize\b|\bbytes\b", w) and re.search(r"\battach", w):
            att = _target_attachment(q, mail, w)
            if att is None or not att["exact"] or not re.search(r"\bbytes?\b", w + " " + str(f.get("syntax") or "").lower()):
                return None
            if _INDIRECT.search(text) or re.search(r"\bdecoded\b", text):
                return None
            return _shape(q, [("bytes", att["size"])], plain=True, field="size/attachment")

        # -- SPF, DKIM, DMARC --------------------------------------------------------------------
        # Two checks named ("the DMARC result given that SPF failed"): which one is asked is not
        # this reader's to say.
        methods = [m for m in ("spf", "dkim", "dmarc") if re.search(rf"\b{m}\b", w)]
        if len(methods) > 1:
            return None
        auth = methods[0] if methods else None
        if auth:
            res = auth_results(mail)
            s = res.get(auth) or {"results": [], "result": None, "props": {}}
            sig = res.get("dkim_signature") or {}
            if auth == "dkim" and re.search(r"\bselector\b", w):
                vals = {v for v in (sig.get("s"), s["props"].get("header.s")) if v}
                return _shape(q, [("selector", vals.pop())], field="dkim/selector") if len(vals) == 1 and sig.get("_count", 1) == 1 else None
            if auth == "dkim" and re.search(r"\balgorithm\b", w):
                return _shape(q, [("as_written", sig.get("a"))], field="dkim/algorithm") if sig.get("a") and sig.get("_count", 1) == 1 else None
            if auth == "dkim" and re.search(r"\bdomain\b|\bd=|\bsign(?:ed|ing|er)\b", w):
                vals = {v.lower() for v in (sig.get("d"), s["props"].get("header.d")) if v}
                return _shape(q, _domain_forms(vals.pop()), field="dkim/domain") if len(vals) == 1 and sig.get("_count", 1) == 1 else None
            if auth == "dmarc" and re.search(r"\bpolicy\b", w):
                return _shape(q, [("as_written", s["props"].get("p"))], field="dmarc/policy") if s["props"].get("p") else None
            if auth == "spf" and re.search(r"\bip\b|\baddress\b", w) and not re.search(r"\bdomain\b", w):
                vals = {v for v in (s["props"].get("client-ip"), s["props"].get("smtp.client-ip")) if v}
                return _shape(q, [("ip", vals.pop())], field="spf/client_ip") if len(vals) == 1 else None
            if re.search(r"\bdomain\b|\bmailfrom\b|envelope", w):
                prop = {"spf": "smtp.mailfrom", "dmarc": "header.from", "dkim": "header.d"}.get(auth)
                v = s["props"].get(prop) or (s["props"].get("envelope-from") if auth == "spf" else None)
                if not v:
                    return None
                return _shape(q, _domain_forms(domain_of(v) or v) + [("as_written", v)], field=f"{auth}/domain")
            if s["result"] is None:
                return None
            if re.search(r"\b(?:pass(?:ed|es)?|fail(?:ed|s)?|valid|aligned)\b", text) and _BOOLISH.search(text) \
                    and not re.search(r"\bresult\b|\bstatus\b|\bverdict\b|\boutcome\b", text):
                if s["result"] not in ("pass", "fail"):
                    return None
                truth = (s["result"] == "pass") != bool(re.search(r"\bfail", text))
                return _bool(q, truth, f"bool/{auth}_passed")
            forms = [("lower", s["result"])]
            if s.get("as_written") and len(s["results"]) == 1:
                forms.append(("as_written", s["as_written"]))
            # The one result every header states, in an enum that lists it: the format is the enum's.
            return _shape(q, forms, plain=bool(_enum(q)), field=f"{auth}/result")

        ad = addresses(mail)
        mm = mismatches(mail)

        # -- yes/no about the addresses ----------------------------------------------------------
        boolish = bool(_BOOLISH.search(text)) or set(a.lower() for a in _enum(q)) in ({"true", "false"}, {"yes", "no"})
        if re.search(r"\breply-to\b", w) and boolish:
            return _bool(q, mm["reply_to_mismatch"] != bool(re.search(r"\bmatch(?:es)?\b|\bsame\b", text) and not re.search(r"mismatch|not match|n't match", text)),
                         "bool/reply_to_mismatch") if mm["reply_to_mismatch"] is not None else None
        if re.search(r"\breturn-path\b|envelope (?:from|sender)", w) and boolish:
            return _bool(q, mm["return_path_mismatch"] != bool(re.search(r"\bmatch(?:es)?\b|\bsame\b", text) and not re.search(r"mismatch|not match|n't match", text)),
                         "bool/return_path_mismatch") if mm["return_path_mismatch"] is not None else None
        if re.search(r"\bdisplay name\b", w) and boolish:
            return _bool(q, mm["display_name_spoof"], "bool/display_name_spoof") if mm["display_name_spoof"] is not None else None

        # -- the originating IP and the hops -----------------------------------------------------
        named_origin = next((h for h in ORIGIN_HEADERS if h.lower() in w), None)
        if named_origin:
            ip = originating(mail)["headers"].get(named_origin)
            return _shape(q, [("ip", ip), ("as_written", mail.get(named_origin))], field="ip/" + named_origin.lower()) if ip else None
        if re.search(r"\bip\b|\bipv4\b|\bipv6\b|\bip address\b", w):
            if re.search(r"originat|\bsource\b|\bsender\b|\bsending\b|\bsent\b|\bcame from\b|\battacker\b|\bfirst hop\b|\bclient\b", w):
                o = originating(mail)
                return _shape(q, [("ip", o["ip"])], field="ip/originating") if o["ip"] else None
            return None
        chain = received_chain(mail)
        if re.search(r"\bhelo\b|\behlo\b", w):
            hop = chain[-1] if chain else None
            return _shape(q, [("as_written", hop["helo"]), ("lower", hop["helo"].lower())], field="received/helo") if hop and hop["helo"] else None
        if re.search(r"\b(?:first|originating|sending|earliest)\s+(?:hop|server|host|mta|relay|mail server)\b", w):
            hop = chain[-1] if chain else None
            return _shape(q, [("from_host", hop["from"]), ("lower", hop["from"].lower())], field="received/first_host") if hop and hop["from"] else None
        if re.search(r"\b(?:last|final|receiving|latest)\s+(?:hop|server|host|mta|relay|mail server)\b", w):
            hop = chain[0] if chain else None
            return _shape(q, [("by_host", hop["by"]), ("lower", hop["by"].lower())], field="received/last_host") if hop and hop["by"] else None

        # -- QR codes ----------------------------------------------------------------------------
        if re.search(r"\bqr\b|quishing|barcode", w):
            codes = qr_codes(mail)
            texts = list(dict.fromkeys(c["text"] for c in codes))
            if len(texts) != 1:
                return None
            ent = _link_entries(mail, w)
            if re.search(r"\bdomain\b|\bhost(?:name)?\b", w):
                return _shape(q, _domain_forms(ent[0]["host"]), field="qr/domain") if len(ent) == 1 and ent[0]["host"] else None
            if len(ent) == 1 and ent[0]["url"] == texts[0].strip():
                return _shape(q, _url_forms(ent[0], w), field="qr/url")
            return _shape(q, [("as_written", texts[0]), ("stripped", texts[0].strip())], field="qr/text")

        # -- HTML smuggling ----------------------------------------------------------------------
        if re.search(r"smuggl|\bdropped\b|\bpayload\b|\bblob\b", w):
            sm = smuggling(mail)
            if len(sm) != 1:
                return None
            if re.search(r"file ?name|\bnamed?\b", w):
                names = sm[0]["download_names"]
                return _shape(q, [("download_name", names[0])], field="smuggling/filename") if len(names) == 1 else None
            if re.search(r"\btype\b|\bformat\b|\bkind of file\b", w) and len(sm[0]["payloads"]) == 1:
                fam = TYPE_FAMILY.get(sm[0]["payloads"][0]["true_type"].split(" ")[0])
                return _shape(q, [(x, x) for x in TYPE_LABELS.get(fam, [])], field=f"filetype/{fam}") if fam else None
            if re.search(r"\bsize\b|\bbytes\b", w) and len(sm[0]["payloads"]) == 1:
                if _INDIRECT.search(text):
                    return None
                return _shape(q, [("base64_literal_decoded", sm[0]["payloads"][0]["size"])], field="payload_size/bytes")
            return None

        # -- homoglyph and IDN domains -----------------------------------------------------------
        if re.search(r"homoglyph|look-?alike|punycode|\bidn\b|\bxn--|unicode domain|confusable|internationali[sz]ed|typo-?squat|"
                     r"misspel\w+ domain|spoofed domain|fake domain|imperson\w+ domain", w):
            hg = homoglyphs(mail)
            if not hg and not re.search(r"punycode|\bidn\b|\bxn--|unicode|character|code ?point", w):
                la = lookalikes(mail)
                if len(la) != 1 or not la[0]["ordered"]:
                    return None             # none, two pairs, or a pair whose copy is not settled
                if re.search(r"\bnot\b|n't\b|\bhow many\b|\bregistrar\b|\bregistered\b|\bwhen\b|\bwho\b|\bwhere\b|\bip\b|\baddress(?:es)?\b|"
                             r"\bage\b|\bcreated\b|\btld\b|\bcharacters?\b|\bletters?\b|\bdiffer|\bsecond\b|\bother\b", w):
                    return None             # a question about the look-alike (who registered it, which letter differs), not for it
                k = la[0]
                if re.search(r"legitimate|imperson|\breal\b|mimic|pretend|\bbrand\b|imitat|\bspoofing\b|resembl", w) and \
                        not re.search(r"look-?alike|typo-?squat|fake|misspel", w):
                    return _shape(q, [("domain", k["resembles"]), ("label", k["other_label"])], field="lookalike/resembles")
                return _shape(q, [("domain", k["domain"]), ("label", k["label"])], field="lookalike/domain")
            if len(hg) != 1:
                return None
            h = hg[0]
            if re.search(r"legitimate|imperson|\breal\b|mimic|pretend|\bbrand\b|imitat|\bspoofing\b", w):
                return _shape(q, [("ascii_skeleton", h["skeleton"])], field="homoglyph/skeleton") if h["skeleton"] else None
            if re.search(r"which (?:character|letter)|\bcharacter\b|\bcode ?point\b", w):
                odd = [c for c in h["unicode"] if ord(c) > 127]
                if len(set(odd)) != 1:
                    return None
                c = odd[0]
                return _shape(q, [("character", c), ("u_plus", f"U+{ord(c):04X}"), ("name", unicodedata.name(c, "")),
                                  ("name_snake", unicodedata.name(c, "").lower().replace(" ", "_"))], field="homoglyph/character")
            first = "punycode" if re.search(r"punycode|\bxn--|\bascii\b", w) else ("unicode" if re.search(r"unicode|decoded", w) else None)
            forms = [("as_written", h["domain"]), ("punycode", h["punycode"]), ("unicode", h["unicode"])]
            forms.sort(key=lambda nv: nv[0] != first)
            return _shape(q, forms, field="homoglyph/domain")

        # -- attachments -------------------------------------------------------------------------
        if re.search(r"\battach", w):
            att = _target_attachment(q, mail, w)
            if att is None:
                return None
            if re.search(r"\b(?:true|real|actual)\b.*\b(?:type|format|extension)\b|\bmagic\b|\bfile type\b|\bfile format\b|"
                         r"\bkind of file\b|\bactually\b", w):
                if boolish and re.search(r"\bextension\b|\bmatch", w):
                    mis = ext_mismatch(att)
                    return _bool(q, mis, "bool/extension_mismatch") if mis is not None else None
                fam = TYPE_FAMILY.get(att["true_type"].split(" ")[0])
                if att["true_type"].startswith("zip ("):
                    fam = "zip"
                return _shape(q, [(x, x) for x in TYPE_LABELS.get(fam, [])], field=f"filetype/{fam}") if fam else None
            if re.search(r"content-?type|mime", w):
                return _shape(q, [("declared", att["declared_type"])], field="attachment/content_type") if att["declared_type"] else None
            if re.search(r"\bextension\b", w):
                ext = Path(att["filename"] or "").suffix
                return _shape(q, [("dotless", ext.lstrip(".").lower()), ("dotted", ext.lower())], field="attachment/extension") if ext else None
            if re.search(r"\b(?:holds?|held|contain\w*|inside|within)\b", w):
                # Day 14 look-ahead (new-lane findings F4, F5): a question about what the attached archive
                # holds is not the attachment's own name. It was answered with that name, under the key of
                # the attachment-name question, so one accepted name would have answered both. The archive
                # is read (its directory, never run): one member is that member's name, under a key of its
                # own; none, several, or an archive that is not read is None.
                if not re.search(r"\bfile ?name\b|\bname\b|\bfile\b|\bmember\b|\bwhat\b|\bwhich\b", w) or _COUNTISH_INNER.search(w):
                    return None
                names = _archive_names(att["data"])
                if not names or len(names) != 1:
                    return None
                return _shape(q, [("as_written", names[0])], field="attachment/inner_name")
            if re.search(r"file ?name|\bname\b|\bwhat (?:file|attachment)\b|\bwhich (?:file|attachment)\b|\bcalled\b", w):
                return _shape(q, [("as_written", att["filename"])], field="attachment/filename") if att["filename"] else None
            if re.search(r"\burls?\b|\blinks?\b", w):
                pass                    # falls to the URL rules below
            else:
                return None

        # -- URLs --------------------------------------------------------------------------------
        if re.search(r"\burls?\b|\blinks?\b|hyperlink|\bhref\b|\bwebsite\b|web address|landing page|phishing (?:page|site)|"
                     r"credential[- ]harvest|\bredirect", w):
            lm = link_mismatches(mail)
            if re.search(r"\b(?:display(?:ed|s)?|shown|shows|visible|appears?|claims?|pretends?|link text|anchor text)\b", w) and len(lm) == 1:
                if re.search(r"\b(?:actual(?:ly)?|real(?:ly)?|points?|leads?|destination|target|goes)\b", w):
                    e = _url_entry(lm[0]["target"], "html:href")
                    if re.search(r"\bdomain\b|\bhost(?:name)?\b", w):
                        return _shape(q, _domain_forms(e["host"]), field="url/target_domain")
                    return _shape(q, _url_forms(e, w), field="url/target")
                return _shape(q, [("as_written", lm[0]["shown"]), ("host", lm[0]["shown_host"])], field="url/shown")
            quoted = [x for x in re.findall(r"[\"\u201c\u2018']([^\"\u201d\u2019']{3,120})[\"\u201d\u2019']", str(q.get("question") or ""))]
            by_text = [e for e in urls(mail) if e["where"].endswith("html:href") and e.get("display")
                       and any(x.strip().lower() == e["display"].strip().lower() for x in quoted)]
            if by_text:
                # a link the question names by the text it shows: its target, when every such link has the one
                targets = _distinct_urls(by_text)
                if len(targets) != 1:
                    return None
                if re.search(r"\bdomain\b|\bhost(?:name)?\b", w):
                    return _shape(q, _domain_forms(targets[0]["host"]), field="url/target_domain_by_text")
                return _shape(q, _url_forms(targets[0], w), field="url/target_by_text")
            ent = _link_entries(mail, w)
            if re.search(r"\bdomain\b|\bhost(?:name)?\b", w):
                hosts = list(dict.fromkeys(e["host"] for e in ent if e["host"]))
                return _shape(q, _domain_forms(hosts[0]), field="url/domain") if len(hosts) == 1 else None
            if len(ent) != 1:
                return None
            if re.search(r"\bpath\b", w):
                m = re.match(r"(?i)[a-z][a-z0-9+.-]*://[^/?#]+(/[^?#]*)", ent[0]["refanged"])
                return _shape(q, [("path", m.group(1))], field="url/path") if m else None
            return _shape(q, _url_forms(ent[0], w), field="url/single")

        # -- Reply-To, Return-Path ---------------------------------------------------------------
        for words_rx, key, header in ((r"\breply-to\b|\brepl(?:y|ies)\b.*\b(?:address|domain|go|goes|sent|receive[sd]?|directed)\b|"
                                       r"\breceives? (?:the )?replies\b", "reply_to", "Reply-To"),
                                      (r"\breturn-path\b|envelope (?:from|sender)|\bbounce", "return_path", "Return-Path")):
            if re.search(words_rx, w):
                pairs = ad[key]
                if len(pairs) != 1 or not pairs[0][1]:
                    return None
                if re.search(r"\bdomain\b", w):
                    return _shape(q, _domain_forms(domain_of(pairs[0][1])), field=f"{key}/domain")
                return _shape(q, _addr_forms(pairs, mail.get(header)), field=f"{key}/address")

        # -- single headers ----------------------------------------------------------------------
        if re.search(r"\bmessage-id\b", w):
            v = mail.get("Message-ID")
            return _shape(q, [("as_written", v), ("bare", v.strip().strip("<>"))], field="header/message_id") \
                if v and len(mail.get_all("Message-ID")) == 1 else None
        if re.search(r"\bsubject\b", w):
            v = mail.get("Subject")
            raw = (mail.raw_all("Subject") or [None])[0]
            return _shape(q, [("decoded", v), ("as_written", raw)], field="header/subject") \
                if v is not None and len(mail.get_all("Subject")) == 1 else None
        if re.search(r"x-mailer|user-agent|\bmailer\b|(?:mail|e-?mail) client|\bsoftware\b", w):
            vals = [v for v in (mail.get("X-Mailer"), mail.get("User-Agent")) if v]
            return _shape(q, [("as_written", vals[0])], field="header/mailer") if len(vals) == 1 else None
        named = _named_header(q, mail)
        if named:
            vals = mail.get_all(named)
            if len(vals) != 1:
                return None
            raw = mail.raw_all(named)[0]
            if named.lower() == "date":
                return _date(q, vals[0])
            return _shape(q, [("decoded", vals[0]), ("as_written", raw)], field="header/" + re.sub(r"[^a-z0-9]+", "_", named.lower()))
        if re.search(r"\bdate\b|\bwhen\b|\btimestamp\b|\btime\b.*\bsent\b|\bsent\b.*\btime\b", w) and not re.search(r"\breceived\b|\bhop\b|\bdeliver", w):
            v = mail.get("Date")
            return _date(q, v) if v and len(mail.get_all("Date")) == 1 else None

        # -- who it is from, who it is to --------------------------------------------------------
        if re.search(r"\bdisplay name\b|\bsender'?s? name\b|\bname of the sender\b", w):
            pairs = ad["from"]
            return _shape(q, [("decoded", pairs[0][0])], field="from/display_name") if len(pairs) == 1 and pairs[0][0] else None
        if re.search(r"\bsender\b|\bwho sent\b|\bsent (?:this|the|it)\b|\bsent from\b|\bfrom (?:header|address|field|domain|line)\b|"
                     r"\bsending (?:address|domain|account|mailbox)\b|\boriginating (?:address|domain)\b", w) and \
                not re.search(r"\brecipient|\bsent to\b|\baddressed to\b", w):
            pairs = ad["from"]
            if len(pairs) != 1 or not pairs[0][1]:
                return None
            if re.search(r"\bdomain\b", w):
                return _shape(q, _domain_forms(domain_of(pairs[0][1])), field="from/domain")
            return _shape(q, _addr_forms(pairs, mail.get("From")), field="from/address")
        for words_rx, key, header in ((r"\bbcc\b", "bcc", "Bcc"), (r"\bcc\b|carbon cop", "cc", "Cc"),
                                      (r"\brecipient\b|\bvictim\b|\bsent to\b|\baddressed to\b|\bto header\b|\bto address\b|\btargeted (?:user|employee)\b", "to", "To")):
            if re.search(words_rx, w):
                pairs = ad[key]
                if len(pairs) != 1 or not pairs[0][1]:
                    return None
                if re.search(r"\bdomain\b", w):
                    return _shape(q, _domain_forms(domain_of(pairs[0][1])), field=f"{key}/domain")
                if re.search(r"\bname\b", w) and not re.search(r"\baddress\b", w):
                    return _shape(q, [("decoded", pairs[0][0])], field=f"{key}/display_name") if pairs[0][0] else None
                return _shape(q, _addr_forms(pairs, mail.get(header)), field=f"{key}/address")

        # -- the body's wrapping -----------------------------------------------------------------
        if re.search(r"content-transfer-encoding|\btransfer encoding\b|\bbody\b.*\bencod|\bencod\w*\b.*\bbody\b", w):
            ctes = list(dict.fromkeys(b["cte"] for b in mail.bodies if b["cte"]))
            return _shape(q, [("lower", ctes[0])], field="body/transfer_encoding") if len(ctes) == 1 else None
        if re.search(r"\bcharset\b|character set", w):
            cs = list(dict.fromkeys(b["charset"] for b in mail.bodies if b["charset"]))
            return _shape(q, [("lower", cs[0].lower()), ("as_written", cs[0])], field="body/charset") if len(cs) == 1 else None

        # -- a value the question's own pattern picks out ----------------------------------------
        return _by_pattern(q, mail)

    # What a mail was seen to do, and the names an enum might give it (never answered plain).
    INDICATOR_NAMES = {
        "html_smuggling": "html_smuggling smuggling html_smuggle html_smuggled_payload",
        "qr_code": "qr_code qr qr_phishing quishing qr_code_phishing qrcode",
        "homoglyph_domain": "homoglyph homoglyph_domain lookalike_domain look_alike_domain idn_homograph homograph "
                            "homograph_domain punycode punycode_domain idn_spoofing",
        "reply_to_mismatch": "reply_to_mismatch reply_to_spoofing mismatched_reply_to reply_to_redirect reply_to_hijack",
        "return_path_mismatch": "return_path_mismatch envelope_mismatch mismatched_return_path envelope_sender_mismatch",
        "display_name_spoof": "display_name_spoofing display_name_spoof display_name_impersonation display_name_deception",
        "link_mismatch": "link_mismatch mismatched_link deceptive_link url_mismatch masked_link link_text_mismatch "
                         "href_mismatch hidden_link",
        "extension_mismatch": "extension_mismatch file_extension_mismatch masquerading masqueraded_attachment "
                              "mismatched_extension fake_extension",
        "double_extension": "double_extension double_file_extension",
    }

    def indicators(mail: Mail, qr: bool = True) -> list:
        """The names of INDICATOR_NAMES this mail was seen to carry, in that order."""
        mm = mismatches(mail)
        named = [a for a in mail.attachments if a["filename"]]
        seen = {
            "html_smuggling": bool(smuggling(mail)), "qr_code": bool(qr and qr_codes(mail)),
            "homoglyph_domain": bool(homoglyphs(mail)), "reply_to_mismatch": mm["reply_to_mismatch"] is True,
            "return_path_mismatch": mm["return_path_mismatch"] is True, "display_name_spoof": mm["display_name_spoof"] is True,
            "link_mismatch": bool(link_mismatches(mail)), "extension_mismatch": any(ext_mismatch(a) for a in named),
            "double_extension": any(re.search(r"\.[A-Za-z0-9]{2,5}\.(?:exe|scr|com|bat|cmd|js|jse|vbs|vbe|wsf|hta|lnk|ps1|iso|img|html?)$",
                                              a["filename"], re.I) for a in named),
        }
        return [k for k in INDICATOR_NAMES if seen[k]]

    def _indicator_enum(q) -> dict:
        """{normalised value: accepted value} of an enum that lists at least one indicator name, else {}."""
        norm = {re.sub(r"[^a-z0-9]+", "_", a.strip().lower()).strip("_"): a for a in _enum(q)}
        known = {n for names in INDICATOR_NAMES.values() for n in names.split()}
        return norm if any(n in known for n in norm) else {}

    def _by_indicator(q, mail: Mail):
        """An enum question whose accepted values name things a mail can do (html_smuggling,
        qr_code, reply_to_mismatch ...): the one accepted value that names something this mail was
        seen to do. Two values that fit, or none: None. Unsure, always: which of a mail's traits a
        question means is the author's."""
        norm = _indicator_enum(q)
        if not norm:
            return None             # no enum, or one about something else
        hits = [(ind, norm[n]) for ind in indicators(mail) for n in INDICATOR_NAMES[ind].split() if n in norm]
        values = {v for _, v in hits}
        if len(values) != 1:
            return None
        return pick(f"indicator/{hits[0][0]}", [(hits[0][1], hits[0][1])])

    def _date(q, value: str):
        forms = date_forms(value)
        words = (str(_fmt(q).get("syntax") or "") + " " + str(q.get("question") or "")).lower()
        if re.search(r"iso|8601|3339|yyyy|\butc\b|\bzulu\b", words):
            forms = forms[1:] + forms[:1]
        if re.search(r"epoch|unix", words):
            forms = [f for f in forms if f[0] == "epoch"] + [f for f in forms if f[0] != "epoch"]
        return _shape(q, forms, field="header/date")

    _HEADER_NAME = r"[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*"

    _OWN_RULE = {"from", "to", "cc", "bcc", "reply-to", "return-path", "subject", "message-id", "received",
                 "authentication-results", "received-spf", "dkim-signature", "x-mailer", "user-agent"}

    def _named_header(q, mail: Mail):
        """The header a question names in so many words ('the X-Campaign header', 'header `X-Foo`'),
        when the mail has it; else None."""
        text = str(q.get("question") or "")
        names = {k.lower(): k for k, _ in mail.headers}
        hits = []
        for m in re.finditer(rf"[`'\"]?({_HEADER_NAME})[`'\"]?:?\s+header\b|\bheader\s+(?:named\s+|called\s+|field\s+)?[`'\"]?({_HEADER_NAME})[`'\"]?", text):
            cand = (m.group(1) or m.group(2)).lower()
            if cand in _OWN_RULE:
                continue
            if cand in names and names[cand] not in hits:
                hits.append(names[cand])
        return hits[0] if len(hits) == 1 else None

    def _by_pattern(q, mail: Mail):
        """A flag-like value: the question gives a real regular expression (answer_format.pattern or
        .regex, with a literal run of three or more characters in it) and exactly one string in the
        decoded mail matches it. Unsure, always: a decoy would match as well."""
        f = _fmt(q)
        rx = f.get("pattern") or f.get("regex")
        if not isinstance(rx, str) or not re.search(r"[A-Za-z]{3,}", re.sub(r"\\.|\[[^\]]*\]", "", rx)):
            return None
        try:
            crx = re.compile(rx.lstrip("^").rstrip("$"))
        except re.error:
            return None
        texts = [v for _, v in mail.headers] + [b["text"] for b in mail.bodies] + [b["inner"] for b in mail.bodies if b.get("inner")]
        for a in mail.attachments:
            if a["size"] <= MAX_IMAGE and a["true_type"].startswith(("text", "html", "json", "xml", "base64", "hex")):
                texts.append(_text(a["data"]))
        for s in smuggling(mail):
            texts += [_text(p["data"]) for p in s["payloads"] if p["true_type"].startswith(("text", "html", "json", "xml"))]
        found = []
        for t in texts:
            for m in crx.finditer(t):
                if m.group() and m.group() not in found:
                    found.append(m.group())
        return _shape(q, [("only_match", found[0])], field="pattern/only_match") if len(found) == 1 else None

    def _mail_for(q, loaded: list):
        """(mail, messages of its file, whole) a question is about: the mail file its member or its
        text names, else the only mail file; the message of an mbox whose subject or Message-ID the
        question quotes; an attached message when the question says so. whole=True: the file has
        several messages and the question picks none (only their count can be asked)."""
        if not loaded:
            return None, None, False
        text = str(q.get("question") or "")
        member = Path(str(q.get("member") or "")).name
        hits = [(name, ms) for name, ms in loaded
                if Path(name.split(ARROW)[-1]).name == member
                or re.search(r"(?<![\w.-])" + re.escape(Path(name.split(ARROW)[-1]).name) + r"(?![\w-])", text)]
        if len(hits) != 1:
            if hits or len(loaded) != 1:
                return None, None, False
            hits = loaded
        name, ms = hits[0]
        if not ms:
            return None, None, False
        mail = ms[0]
        if len(ms) > 1:
            quoted = re.findall(r"[\"\u201c']([^\"\u201d']{4,200})[\"\u201d']", text)
            sel = [m for m in ms if any(s.strip().lower() in ((m.get("Subject") or "").strip().lower(),
                                                              (m.get("Message-ID") or "").strip("<> ").lower()) for s in quoted)]
            if len(sel) != 1:
                return mail, ms, True
            mail = sel[0]
        if re.search(r"\b(?:attached|original|forwarded|inner|embedded|nested)\s+(?:e-?mail|message)\b", text.lower()):
            return (mail.nested[0], ms, False) if len(mail.nested) == 1 else (None, None, False)
        return mail, ms, False

    def _whole(q, ms: list):
        """A question about an mbox as a whole: only the bare count of its messages."""
        text = _words(q).split(" | ")[0]
        if re.search(r"\bhow many\b|\bnumber of\b|\bcount of\b", text) and re.search(r"\b(?:messages|e-?mails|mails)\b", text) \
                and _bare_count(text, "messages") and str(_fmt(q).get("kind") or "") not in ("json", "ordered_tokens", "enum", "mitre_attack_id"):
            sure = not any(getattr(m, "mbox_doubt", None) for m in ms)
            return _shape(q, [("messages", len(ms))], plain=sure, field="count/messages")
        return None

    def _other_members(files: dict, loaded: list) -> set:
        """The bare names (lowercase) of the files handed over that are no mail file read here and
        hold none: an access log or a capture beside the mail. A question whose artifact names one
        of them is that member's question whatever its words, and this toolkit's fact under its key
        would be another fact (Day 12 look-ahead, N1). An archive that holds a mail file, at any
        depth, is not among them; neither is a name the delivery does not have, which proves nothing
        (a timed variant has named a file of another variant) and stays with _mail_for."""
        paths = [[Path(part).name.lower() for part in str(key).split(ARROW)] for key in files]
        ours = {Path(name.split(ARROW)[-1]).name.lower() for name, _ in loaded}
        grew = True
        while grew:
            grew = False
            for path in paths:
                for holder, held in zip(path, path[1:]):
                    if held in ours and holder not in ours:
                        ours.add(holder)
                        grew = True
        return {path[-1] for path in paths} - ours - {""}

    def _names_other(q, others: set, loaded: list) -> bool:
        """True when the question's artifact names one of `others` (_other_members) and no mail file
        before it. `message.eml -> invoice.pdf` is the mail's attachment, as before, also when a
        file of that name lies beside the mail in the delivery."""
        if Path(str(q.get("member") or "")).name.lower() not in others:
            return False
        mails = {Path(name.split(ARROW)[-1]).name.lower() for name, _ in loaded}
        holders = [re.sub(r"^\s*delivery \d+\s*:\s*", "", part, flags=re.I).strip()
                   for part in str(q.get("artifact") or "").split("->")[:-1]]
        return not any(Path(h).name.lower() in mails for h in holders)

    def solve_set(questions, files, ctx) -> dict:
        out = {(q.get("qid") or q.get("id")): None for q in questions}
        try:
            found = mail_files(files or {})
        except Exception:
            return out
        if not found:
            return out              # not this toolkit's delivery: nothing is answered
        loaded = []
        for name, data, _ in found:
            try:
                ms = load(data, name.split(ARROW)[-1])
            except Exception:
                ms = []
            if ms:
                loaded.append((name, ms))
        partial = ctx.get("partial") if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict) else None
        try:
            others = _other_members(files or {}, loaded)
        except Exception:
            return out
        for q in questions:
            qid = q.get("qid") or q.get("id")
            try:
                if _names_other(q, others, loaded):
                    continue            # another member's question: not answered from the mail beside it
                mail, ms, whole = _mail_for(q, loaded)
                out[qid] = None if mail is None else (_whole(q, ms) if whole else answer(q, mail))
            except Exception:       # a fact that cannot be read is no answer
                out[qid] = None
            if partial is not None and out[qid] is not None:
                partial[qid] = out[qid]
        return out

    # ---- the command ---------------------------------------------------------------------------------------------------------------

    def _from_path(path: Path) -> list:
        """[(name, bytes)] of a file; of its members too when it is a plain zip."""
        data = path.read_bytes()
        out = [(path.name, data)]
        if data[:4] == b"PK\x03\x04":
            try:
                import io
                import zipfile
                zf = zipfile.ZipFile(io.BytesIO(data))
                for info in zf.infolist()[:500]:
                    if not info.is_dir() and not info.flag_bits & 1 and info.file_size <= MAX_MAIL:
                        out.append((f"{path.name}{ARROW}{info.filename}", zf.read(info)))
            except Exception:
                pass
        return out

    def main(argv) -> int:
        global QR
        args = [a for a in argv if not a.startswith("--")]
        if not args:
            print("usage: email.py <file>... [--json] [--no-qr]", file=sys.stderr)
            return 2
        if "--no-qr" in argv:
            QR = False
        seen_any, rc, dumps = False, 0, []
        for arg in args:
            p = Path(arg)
            if not p.is_file():
                print(f"email.py: {arg} is not a file", file=sys.stderr)
                rc = 2
                continue
            for name, data in _from_path(p):
                ms = load(data, name.split(ARROW)[-1])
                for m in ms:
                    seen_any = True
                    if "--json" in argv:
                        dumps.append(triage(m, qr=QR))
                    else:
                        print(report(m, qr=QR))
                        print()
                if not ms and name == p.name and data[:4] != b"PK\x03\x04":
                    print(f"{name}: not an .eml, .msg or mbox by its bytes ({_triage.identify(data, name)})")
        if "--json" in argv:
            print(json.dumps(dumps, indent=1, ensure_ascii=False, default=str))
        return rc if seen_any or rc else 1

    if __name__ == "__main__":
        sys.exit(main(sys.argv[1:]))
