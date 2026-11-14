"""The proposer families build: general widenings of the deterministic enumerator (proposer_enum.py).

Every id the enumerator missed on the adapt bench, or ranked below 3, was classified by WHY it missed. Each family
gets one general widening here, never a rule per case. The enumerator calls them from `propose_one`, around its own
experts, and the 12-candidate cap and the ranking stay its own:

  judged    names the judge already ACCEPTED for the same field (the labels ledger, cut to `ctx["ledger_before"]`
            when the caller replays a morning), ranked first among the new candidates;
  (a) spell same fact, another spelling: braces on a GUID, letter case, separators of a byte string, zero padding
            and the 0x prefix of hex, a list's items as low bytes / without prefix / upper case, the list sorted,
            reversed, without its empty or first/last item. Added after the value they respell, a little lower;
  (b) anchor a position measured from another anchor: the file offset of a self-checking record found raw or
            inside an encoded carrier (base64, hex, UTF-16 text: the carrier's own first character), its payload
            and end, the offset inside its section, its virtual address and RVA, the decoy magic's offsets last;
  (c) derive absent or derived fields: a url's host / domain / registrable domain / tld / path / port / scheme,
            a domain's labels, counts and lengths of a stated value, digests (md5/sha1/sha256/crc32) of a record's
            payload, of a stated value or of a member; `none` / `[]` / `null` for an absent field;
  (d) vocab author vocabulary labels: an enum token chosen by its own clause in the question text (anchors such as
            `.hcfg`, `Base64`, `WebAssembly`, read against where the record really is; `other than` negates),
            and, with no enum, snake_case labels composed from the facts (`raw_hcfg_section`, `base64`, ...);
  (e) other  a self-checking record no question names (4-byte tag, version, one-byte XOR key, u16 length, CRC-32 of
            the payload; the record layout proposer_enum.DEFAULT_RECORD already assumes) found by its own CRC,
            whose JSON pairs answer the asked noun; and three classical codecs the battery lacked (ITA2/Baudot,
            Vigenere over the hex alphabet for `ANS-` codes, slug words checked against the dictionary).

Round 2 (section "round 2" below) covers what round 1 left open: GUIDs kept as in-memory bytes, alias keys,
fingerprints by the named digest; the PE overlay and wasm custom sections; Day 12-style Script enums and ATT&CK ids (a
stated codec decoded, the reconstruction statement, the lane's judged label families); a base64/hex layer inside a
record, Mobile codes in res/raw and assets, nested zip comments, keyboard shifts with no crib word.

Nothing here is ever plain: the enumerator's output reaches the judge only as `labels.candidates` (row 346).
Every reading is bounded by counts and the enumerator's deadline. No network, no execution of a delivery.
"""
import base64
import binascii
import hashlib
import io
import json
import os
import re
import struct
import time
import zipfile
import zlib
from pathlib import Path

E = None   # the proposer_enum module, set by its loader (so a bench-loaded copy shares its caches)

class _Rx:
    """A module pattern compiled on its first use: the module is loaded once per worker process (and with no
    bytecode cache), and most questions use few of these, so loading it compiles none of them."""
    __slots__ = ("_args", "_rx")

    def __init__(self, *args):
        self._args, self._rx = args, None

    def __getattr__(self, name):
        rx = self._rx
        if rx is None:
            rx = self._rx = re.compile(*self._args)
        return getattr(rx, name)


def _xor_tables():
    """The 256 XOR-k byte tables, as one big-int XOR each (the same bytes as `bytes(c ^ k for c in range(256))`, in
    a tenth of a millisecond instead of two)."""
    ident = int.from_bytes(bytes(range(256)), "big")
    ones = int.from_bytes(b"\x01" * 256, "big")
    return [(ident ^ (ones * k)).to_bytes(256, "big") for k in range(256)]


XOR_TABLES = _xor_tables()
REC_TAG = _Rx(rb"(?=[A-Z0-9]{0,3}[A-Z])[A-Z0-9]{4}")
REC_HEAD = _Rx(rb"(?=((?=[A-Z0-9]{0,3}[A-Z])[A-Z0-9]{4})[\x00-\x20])")   # a tag, then a small version byte
B64_CARRIER = _Rx(rb"[A-Za-z0-9+/]{20,}={0,2}")
B64U_CARRIER = _Rx(rb"[A-Za-z0-9_-]{20,}={0,2}")
HEX_CARRIER = _Rx(rb"(?:[0-9a-f]{2}){16,}|(?:[0-9A-F]{2}){16,}")
U16_B64_CARRIER = _Rx(rb"(?:[A-Za-z0-9+/]\x00){20,}(?:=\x00){0,2}")
SCAN_MAX = 8 << 20
TAG_HITS_MAX = 250000
CARRIER_MAX = 3000

POSITION_WORDS = {"offset", "address", "addr", "position", "pos", "location", "start", "begin", "begins", "rva",
                  "va", "vaddr", "index", "where", "located"}
OBJECT_WORDS = {"config", "configuration", "cfg", "record", "container", "payload", "blob", "resource", "data",
                "settings", "header", "carrier", "embedded", "stored"}
URL_PARTS = ("host", "hostname", "domain", "tld", "path", "port", "scheme", "protocol", "query", "registrable",
             "suffix", "label", "labels", "apex", "root", "sld", "subdomain", "fragment")
DIGESTS = ("sha256", "sha1", "md5", "crc32", "sha512")


# ------------------------------------------------------------------------------------------------- records

def _parse_default(b, o):
    """A record at o in the default layout (tag, version u8, xor key u8, length u16le, CRC-32 u32le, payload at
    +12): the decoded payload when its CRC-32 checks (decoded, or as stored), else None."""
    if o + 12 > len(b):
        return None
    for n in dict.fromkeys((b[o + 6] | (b[o + 7] << 8), (b[o + 6] << 8) | b[o + 7])):
        r = _parse_n(b, o, n)
        if r:
            if n != (b[o + 6] | (b[o + 7] << 8)):
                r["length_be"] = True
            return r
    return None


def _parse_n(b, o, n):
    if n < 4 or o + 12 + n > len(b):
        return None
    key = b[o + 5]
    head = b[o + 12:o + 20].translate(XOR_TABLES[key])
    head_raw = b[o + 12:o + 20]
    pr = E.printable_ratio
    if pr(head) < 0.75 and pr(head_raw) < 0.75:
        return None
    body = b[o + 12:o + 12 + n]
    want = int.from_bytes(b[o + 8:o + 12], "little")
    dec = body.translate(XOR_TABLES[key])
    if (zlib.crc32(dec) & 0xffffffff) == want:
        return {"payload": dec, "key": key, "version": b[o + 4], "length": n, "crc": want, "xor": True}
    if (zlib.crc32(body) & 0xffffffff) == want:
        return {"payload": body, "key": key, "version": b[o + 4], "length": n, "crc": want, "xor": False}
    return None


def _b64dec(t: bytes):
    t = t.strip()
    for alt in (None, b"-_"):
        try:
            s = t if alt is None else t.replace(b"-", b"+").replace(b"_", b"/")
            return base64.b64decode(s + b"=" * (-len(s) % 4))
        except (binascii.Error, ValueError):
            continue
    return None


_SCANNED = {}


def inner_record(out, kind, m, t):
    """A record that begins inside a carrier's decoded bytes (not at its first byte)."""
    try:
        full = binascii.unhexlify(t[:len(t) // 2 * 2]) if kind == "hex" else _b64dec(t[:len(t) // 4 * 4])
    except (binascii.Error, ValueError):
        return
    if not full:
        return
    for mm in REC_HEAD.finditer(full[:65536]):
        r = _parse_default(full, mm.start())
        if r:
            r.update({"magic": full[mm.start():mm.start() + 4].decode("latin-1"), "offset": m.start(), "carrier": kind,
                      "inner": mm.start(), "size": 12 + r["length"], "carrier_len": len(m.group())})
            out.append(r)
            return


def records_in(env, name, deadline):
    """Every self-checking record in one member, found raw by its CRC, or at the head of an encoded carrier:
    [{"magic", "offset" (where its first byte / its carrier's first character is), "carrier", "inner", "payload",
    "size", ...}]. Cached per member."""
    ck = ("fam_records", name)
    if ck in env._facts:
        return env._facts[ck]
    b = (env.member_bytes(name) or b"")[:SCAN_MAX]
    # the same member recurs in every set of a cumulative Mastery: one scan a process, by its content
    # This process cache may outlive one attempt.  A sampled digest plus CRC-32
    # is a useful change detector, not a content identity: two members can
    # deliberately share both and hold different records in an unsampled
    # region.  Key the reusable fact by every byte instead.
    gk = (len(b), hashlib.sha256(b).digest())
    if gk in _SCANNED:
        env._facts[ck] = _SCANNED[gk]
        return _SCANNED[gk]
    out = []
    hits = 0
    for m in REC_HEAD.finditer(b):
        hits += 1
        if hits > TAG_HITS_MAX or (hits & 4095) == 0 and time.time() > deadline:
            break
        o = m.start()
        if o + 12 > len(b):
            break
        if b[o + 4] > 32:      # a version byte, small
            continue
        r = _parse_default(b, o)
        if r:
            r.update({"magic": b[o:o + 4].decode("latin-1"), "offset": o, "carrier": "raw", "inner": 0,
                      "size": 12 + r["length"]})
            out.append(r)
    # encoded carriers: a text whose decoding begins with a record
    for kind, rx in (("base64", B64_CARRIER), ("base64url", B64U_CARRIER), ("hex", HEX_CARRIER), ("utf16_base64", U16_B64_CARRIER)):
        n = 0
        for m in rx.finditer(b):
            n += 1
            if n > CARRIER_MAX or time.time() > deadline:
                break
            t0 = m.group()
            if kind == "base64url" and not re.search(rb"[-_]", t0):
                continue
            t0 = t0[::2] if kind == "utf16_base64" else t0
            found = False
            for sh in range(0, min(8, max(1, len(t0) - 23))):
                t = t0[sh:]
                try:
                    head = binascii.unhexlify(t[:24]) if kind == "hex" else _b64dec(t[:24])
                except (binascii.Error, ValueError):
                    head = None
                if not head or len(head) < 4 or not REC_TAG.fullmatch(head[:4]):
                    continue
                try:
                    full = binascii.unhexlify(t[:len(t) // 2 * 2]) if kind == "hex" else \
                        _b64dec(t[:len(t) // 4 * 4] if not t.endswith(b"=") else t)
                except (binascii.Error, ValueError):
                    full = None
                r = _parse_default(full, 0) if full else None
                if r:
                    step = 2 if kind == "utf16_base64" else 1
                    r.update({"magic": full[:4].decode("latin-1"), "offset": m.start() + step * sh, "carrier": kind,
                              "inner": 0, "size": 12 + r["length"], "carrier_len": len(m.group()) - step * sh})
                    out.append(r)
                    found = True
                    break
            if not found and len(t0) >= 40:
                inner_record(out, kind, m, t0)
    env._facts[ck] = out
    if time.time() <= deadline:      # a scan cut by the deadline is not kept for the next set
        if len(_SCANNED) > 256:
            _SCANNED.clear()
        _SCANNED[gk] = out
    return out


def raw_magic_offsets(b, magic, cap=16):
    out, i = [], b.find(magic.encode())
    while i >= 0 and len(out) < cap:
        out.append(i)
        i = b.find(magic.encode(), i + 1)
    return out


# ------------------------------------------------------------------------------------------------- sections

def sections_of(b):
    """[(name, file offset, size, virtual address)] of an ELF or PE, plus ELF PT_LOAD segments as ('<load>', ...).
    Bounded, struct only; anything that does not read is []."""
    out = []
    try:
        if b[:4] == b"\x7fELF":
            is64, le = b[4] == 2, b[5] == 1
            en = "<" if le else ">"
            if is64:
                phoff, shoff = struct.unpack_from(en + "QQ", b, 0x20)
                phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(en + "HHHHH", b, 0x36)
            else:
                phoff, shoff = struct.unpack_from(en + "II", b, 0x1c)
                phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(en + "HHHHH", b, 0x2a)
            shdrs = []
            for i in range(min(shnum, 512)):
                p = shoff + i * shentsize
                if is64:
                    nm, typ, flags, addr, off, size = struct.unpack_from(en + "IIQQQQ", b, p)
                else:
                    nm, typ, flags, addr, off, size = struct.unpack_from(en + "IIIIII", b, p)
                shdrs.append((nm, typ, addr, off, size))
            strtab = shdrs[shstrndx] if shstrndx < len(shdrs) else None
            for nm, typ, addr, off, size in shdrs:
                name = ""
                if strtab:
                    s = strtab[3] + nm
                    e = b.find(b"\x00", s)
                    name = b[s:e].decode("latin-1") if e >= 0 else ""
                if typ != 8:   # NOBITS has no file bytes
                    out.append((name, off, size, addr))
            for i in range(min(phnum, 256)):
                p = phoff + i * phentsize
                if is64:
                    typ, flags, off, vaddr, paddr, filesz = struct.unpack_from(en + "IIQQQQ", b, p)
                else:
                    typ, off, vaddr, paddr, filesz = struct.unpack_from(en + "IIIII", b, p)
                if typ == 1:
                    out.append(("<load>", off, filesz, vaddr))
        elif b[:2] == b"MZ":
            pe = struct.unpack_from("<I", b, 0x3c)[0]
            if b[pe:pe + 4] != b"PE\x00\x00":
                return out
            nsec, = struct.unpack_from("<H", b, pe + 6)
            optsz, = struct.unpack_from("<H", b, pe + 20)
            opt = pe + 24
            magic, = struct.unpack_from("<H", b, opt)
            base = struct.unpack_from("<Q", b, opt + 24)[0] if magic == 0x20b else struct.unpack_from("<I", b, opt + 28)[0]
            st = opt + optsz
            for i in range(min(nsec, 96)):
                p = st + 40 * i
                name = b[p:p + 8].rstrip(b"\x00").decode("latin-1")
                vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", b, p + 8)
                out.append((name, rawptr, rawsize, base + va))
                out.append(("<rva>" + name, rawptr, rawsize, va))
    except (struct.error, IndexError):
        return out
    return out


def table_end(b):
    """Where an ELF's or PE's own header tables end: the section header table, the program headers."""
    try:
        if b[:4] == b"\x7fELF":
            en = "<" if b[5] == 1 else ">"
            if b[4] == 2:
                phoff, shoff = struct.unpack_from(en + "QQ", b, 0x20)
                phentsize, phnum, shentsize, shnum = struct.unpack_from(en + "HHHH", b, 0x36)
            else:
                phoff, shoff = struct.unpack_from(en + "II", b, 0x1c)
                phentsize, phnum, shentsize, shnum = struct.unpack_from(en + "HHHH", b, 0x2a)
            return max(shoff + shentsize * shnum, phoff + phentsize * phnum)
    except (struct.error, IndexError):
        pass
    return 0


def place_of(secs, off):
    """(section name, offset in section, virtual address, rva) of a file offset; Nones when unmapped."""
    name = rel = va = rva = None
    for nm, so, sz, addr in secs:
        if not (so <= off < so + sz) or sz <= 0:
            continue
        if nm == "<load>":
            va = va if va is not None else addr + (off - so)
        elif nm.startswith("<rva>"):
            rva = addr + (off - so)
        elif name is None and nm:
            name, rel = nm, off - so
            if addr and va is None:
                va = addr + (off - so)
    return name, rel, va, rva


# ------------------------------------------------------------------------------------------------- the judged

_LEDGER = {}


def _ledger_rows(prefix):
    import labels                       # the event workdir (ctf.paths.workdir()); no fallback folder
    root = labels.challenges_root()
    p = Path(root) / "_ledger" / f"{prefix}.jsonl"
    try:
        st = p.stat()
    except OSError:
        return []
    ck = (str(p), st.st_mtime, st.st_size)
    if ck not in _LEDGER:
        rows = []
        for line in p.read_text(errors="replace").splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if isinstance(r, dict) and r.get("key") and r.get("name") is not None:
                rows.append(r)
        _LEDGER.clear()
        _LEDGER[ck] = rows
    return _LEDGER[ck]


LANE_PREFIX = {"script-analysis": "script", "binary-reverse-engineering": "binary", "warmups": "warmups",
               "mobile-android": "mobile", "metadata-forensics": "metadata"}


def judged(spec, pool, ctx):
    """Names the judge accepted for this field before (`<lane>.<field>/...` keys), as candidates first. A name is
    offered only where it fits the asked form (labels; a method name never fits an integer or a digest)."""
    prefix = LANE_PREFIX.get(spec.lane, spec.lane.split("-")[0] if spec.lane else "")
    if not prefix or spec.form in ("int", "int_or_none", "hex0x", "sha256", "ans", "slug", "guid"):
        return
    field = re.sub(r"[^a-z0-9_]+", "_", spec.field.lower()).strip("_")
    if not field:
        return
    before = ctx.get("ledger_before")
    acc, rej = {}, set()
    for r in _ledger_rows(prefix):
        if before and str(r.get("t", "")) >= before:
            continue
        k = str(r["key"])
        f = k.split("/", 1)[0].split(".", 1)[-1]
        if f != field or "#candidates" in k:
            continue
        nm = str(r["name"])
        if r.get("verdict") == "accepted":
            acc[nm] = acc.get(nm, 0) + 1
        elif r.get("verdict") == "rejected" and r.get("scope") == "key":
            rej.add(nm)
    for i, (nm, n) in enumerate(sorted(acc.items(), key=lambda x: -x[1])):
        if not re.fullmatch(r"[a-z][a-z0-9_.+-]{0,60}", nm) or nm in rej:
            continue
        pool.add(f"judged:{field}", nm, 27.5 - 0.5 * i + 0.2 * min(n, 5))


# ------------------------------------------------------------------------------------------------- (a) spelling

GUID_RX = _Rx(r"\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?")
HEXPAIRS_RX = _Rx(r"(?:[0-9a-fA-F]{2}[:\- ]){3,}[0-9a-fA-F]{2}")


def _item_forms(x):
    """Other spellings of one list item: a hex code as its low byte, with or without 0x, in either case."""
    out = []
    if isinstance(x, str):
        m = re.fullmatch(r"(0x)?([0-9a-fA-F]+)", x)
        if m and (m.group(1) or (len(x) >= 2 and re.search(r"[a-fA-F]", x) and len(x) % 2 == 0)):
            h = m.group(2)
            if len(h) == 4 and h[:2].lower() == "ff":
                out.append(("low_byte", "0x" + h[2:].lower()))
            out.append(("prefix_lower", "0x" + h.lower()))
            out.append(("no_prefix", h.lower()))
            out.append(("upper", "0x" + h.upper()))
            out.append(("bare_upper", h.upper()))
    return out


DT_RX = _Rx(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d)(?::(\d\d))?(?:\.\d+)?(Z|[+-]\d\d:?\d\d)?")
DT_LAYOUTS = (("yyyy-mm-dd hh:mm:ss", "{Y}-{m}-{d} {H}:{M}:{S}"), ("yyyy-mm-ddthh:mm:ssz", "{Y}-{m}-{d}T{H}:{M}:{S}Z"),
              ("yyyy-mm-ddthh:mm:ss", "{Y}-{m}-{d}T{H}:{M}:{S}"), ("yyyy-mm-dd", "{Y}-{m}-{d}"),
              ("yyyymmdd", "{Y}{m}{d}"), ("dd/mm/yyyy", "{d}/{m}/{Y}"), ("mm/dd/yyyy", "{m}/{d}/{Y}"))


def stated_forms(spec):
    """The forms the question's own syntax and text ask for: case, prefix, separators, order, layout."""
    got = getattr(spec, "_stated_forms", None)
    if got is None:
        got = _stated_forms(spec)
        try:
            spec._stated_forms = got
        except AttributeError:
            pass
    return got


def _stated_forms(spec):
    t = (spec.syntax + " " + (spec.asked if len(spec.text) > 240 else spec.text)).lower()
    f = set()
    if re.search(r"\blower[- ]?case\b|\blowercase\b|in lowercase", t) and not re.search(r"(?:not|no|never) lower", t):
        f.add("lower")
    if re.search(r"\bupper[- ]?case\b|\buppercase\b|\bcapital", t) and not re.search(r"(?:not|no|never) upper", t):
        f.add("upper")
    if re.search(r"0x[- ]prefix|0x followed|with (?:a |an )?0x|0x-prefixed|prefixed (?:with|by) 0x", t):
        f.add("prefix0x")
        if re.search(r"hexadecimal|\bhex\b", t):
            f.add("hexint")      # a number asked as 0x-prefixed hexadecimal (round 2)
    if re.search(r"without (?:a |the |any )?(?:0x )?prefix|no (?:0x )?prefix|no leading 0x", t):
        f.add("noprefix")
    if re.search(r"separated by colons|colon[- ]separated|colons? between", t):
        f.add("colon")
    if re.search(r"separated by (?:hyphens|dashes)|(?:hyphen|dash)[- ]separated", t) and "guid" not in t:
        f.add("dash")
    if re.search(r"\bsorted\b|ascending|alphabetical", t) and not re.search(r"not sorted|unsorted", t):
        f.add("sorted_desc" if "descending" in t else "sorted")
    elif "descending" in t:
        f.add("sorted_desc")
    if re.search(r"reverse(?:d)? order", t):
        f.add("reversed")
    if re.search(r"comma[- ]separated|separated by commas|joined (?:by|with) commas", t):
        f.add("comma_nospace" if re.search(r"no spaces?|without spaces?", t) else "comma")
    if re.search(r"no leading v|without (?:the |a )?(?:leading )?v\b|digits only|numeric only", t):
        f.add("no_v")
    if re.search(r"without (?:the |any )?quotes|no quotes|unquoted", t):
        f.add("unquote")
    for pat, fmt in DT_LAYOUTS:
        if pat in t:
            f.add("dt:" + fmt)
            break
    return f


def apply_stated(value, forms):
    """value rewritten to every stated form that applies to it; the value itself when none does."""
    v = value
    if not isinstance(v, str) or not forms:
        return v
    if v.startswith("["):
        try:
            items = json.loads(v)
        except ValueError:
            items = None
        if isinstance(items, list):
            items = [apply_stated(x, forms - {"sorted", "sorted_desc", "reversed"}) if isinstance(x, str) else x for x in items]
            try:
                if "sorted" in forms:
                    items = sorted(items)
                elif "sorted_desc" in forms:
                    items = sorted(items, reverse=True)
            except TypeError:
                pass
            if "reversed" in forms:
                items = items[::-1]
            if "comma" in forms or "comma_nospace" in forms:
                return ("," if "comma_nospace" in forms else ", ").join(str(x) for x in items)
            return E.jdump(items)
    if "unquote" in forms and len(v) > 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    if "no_v" in forms and re.fullmatch(r"[vV]\d+(?:\.\d+)*", v):
        v = v[1:]
    m = DT_RX.fullmatch(v)
    dt = next((x[3:] for x in forms if x.startswith("dt:")), None)
    if m and dt:
        v = dt.format(Y=m.group(1), m=m.group(2), d=m.group(3), H=m.group(4), M=m.group(5), S=m.group(6) or "00")
    if ("colon" in forms or "dash" in forms) and re.fullmatch(r"(?:[0-9a-fA-F]{2}[:\- ]?){3,}", v):
        pairs = re.findall(r"[0-9a-fA-F]{2}", v)
        if "".join(pairs) == re.sub(r"[:\- ]", "", v):
            v = (":" if "colon" in forms else "-").join(pairs)
    if "hexint" in forms and re.fullmatch(r"\d{1,19}", v):
        v = "0x%x" % int(v)
    if re.fullmatch(r"(0x)?[0-9a-fA-F]+", v) and (re.search(r"[a-fA-F]", v) or v.startswith("0x")):
        if "prefix0x" in forms and not v.startswith("0x"):
            v = "0x" + v
        if "noprefix" in forms and v.startswith("0x"):
            v = v[2:]
    if "lower" in forms and v != v.lower():
        v = v.lower()
    elif "upper" in forms:
        v = ("0x" + v[2:].upper()) if v.startswith("0x") else v.upper()
    return v


UNIT = {"b": 1, "byte": 1, "bytes": 1, "kb": 1024, "kib": 1024, "k": 1024, "mb": 1 << 20, "mib": 1 << 20, "gb": 1 << 30,
        "gib": 1 << 30, "ms": 0.001, "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1, "min": 60, "mins": 60,
        "minute": 60, "minutes": 60, "h": 3600, "hr": 3600, "hour": 3600, "hours": 3600}
TRUE_WORDS = {"yes", "y", "on", "1", "true", "enabled", "enable"}
FALSE_WORDS = {"no", "n", "off", "0", "false", "disabled", "disable"}


def respell(spec, value):
    """[(how, spelling)] of a fact that does not fit the asked form as it stands: its number without the unit (and
    converted to the unit the question names), a boolean word as the enum's true/false, a version without its v,
    a list split from its separators, the stated forms."""
    out = []
    if not isinstance(value, str) or len(value) > 400:
        return out
    v = value.strip().strip("\"'")
    words = set(spec.field_toks) | set(spec.noun_toks)
    if spec.form in ("int", "int_or_none", "text"):
        m = re.fullmatch(r"(-?\d+(?:\.\d+)?)\s*([A-Za-z]+)?", v)
        if m:
            num_, unit = float(m.group(1)), (m.group(2) or "").lower()
            if m.group(1).lstrip("-").isdigit() and unit:
                out.append(("no_unit", m.group(1)))
            if unit in UNIT or (not unit and words & {"ms", "milliseconds", "millisecond"}):
                base = num_ * UNIT.get(unit or "s", 1)
                targets = []
                if words & {"bytes", "byte"} or "in bytes" in spec.low:
                    targets.append(("bytes", 1))
                if words & {"ms", "milliseconds", "millisecond"}:
                    targets.append(("ms", 0.001))
                if words & {"seconds", "second", "secs", "sec"}:
                    targets.append(("seconds", 1))
                if words & {"minutes", "minute"}:
                    targets.append(("minutes", 60))
                if words & {"kb", "kib", "kilobytes"}:
                    targets.append(("kib", 1024))
                if not targets and UNIT.get(unit) in (1024, 1 << 20, 1 << 30):
                    targets.append(("bytes", 1))
                for nm, scale in targets:
                    x = base / scale
                    if abs(x - round(x)) < 1e-9:
                        out.append((f"to_{nm}", str(int(round(x)))))
                if UNIT.get(unit) in (1024, 1 << 20, 1 << 30):
                    x = num_ * {1024: 1000, 1 << 20: 10 ** 6, 1 << 30: 10 ** 9}[UNIT[unit]]
                    if abs(x - round(x)) < 1e-9:
                        out.append(("to_bytes_decimal", str(int(round(x)))))
    if spec.form == "enum" and {a.lower() for a in spec.accepted} >= {"true", "false"}:
        if v.lower() in TRUE_WORDS:
            out.append(("bool_word", "true"))
        elif v.lower() in FALSE_WORDS:
            out.append(("bool_word", "false"))
    if re.fullmatch(r"[vV]\d+(?:\.\d+)+", v):
        out.append(("no_v", v[1:]))
    m = re.fullmatch(r"[vV]?(\d+(?:\.\d+){1,3})[-+~._]?(?:rc|alpha|beta|pre|dev|build|b|a)[.\-_]?\w*", v)
    if m:
        out.append(("no_prerelease", m.group(1)))
    if spec.form in ("int", "int_or_none") and re.fullmatch(r"0+\d+", v):
        out.append(("no_zero_pad", str(int(v))))
    lowsyn = (spec.syntax + " " + spec.asked).lower()
    if re.fullmatch(r"\d{9,19}", v) and re.search(r"iso.?8601|date|time|utc|yyyy", lowsyn):
        import datetime as _dt
        n = int(v)
        for how, secs in (("epoch_s", n), ("epoch_ms", n / 1000), ("filetime", n / 1e7 - 11644473600)):
            if 0 < secs < 4102444800:
                t = _dt.datetime.fromtimestamp(int(secs), _dt.timezone.utc)
                forms = stated_forms(spec)
                dt = next((x[3:] for x in forms if x.startswith("dt:")), None)
                lay = [dt] if dt else []
                lay += ["{Y}-{m}-{d}T{H}:{M}:{S}Z", "{Y}-{m}-{d} {H}:{M}:{S}"]
                for j, L in enumerate(dict.fromkeys(lay)):
                    out.append((f"{how}_{j}", L.format(Y=f"{t.year:04d}", m=f"{t.month:02d}", d=f"{t.day:02d}",
                                                          H=f"{t.hour:02d}", M=f"{t.minute:02d}", S=f"{t.second:02d}")))
    if re.fullmatch(r"[A-Za-z0-9+/]{8,}={0,2}", v) and len(v) % 4 == 0 and re.search(r"\bhex", lowsyn):
        try:
            out.append(("base64_to_hex", base64.b64decode(v).hex()))
        except (binascii.Error, ValueError):
            pass
    if spec.form in ("json", "tokens") and not v.startswith("[") and re.search(r"[,;|]", v):
        out.append(("split", [x.strip() for x in re.split(r"[,;|]", v) if x.strip()]))
    if spec.form == "hex0x" and re.fullmatch(r"[0-9a-fA-F]+", v):
        out.append(("prefix", "0x" + v.lower()))
    st = apply_stated(v, stated_forms(spec))
    if st != v:
        out.append(("stated", st))
    return out


def spellings(spec, value):
    """[(how, spelling)] of one value: the family (a) alternatives, best first."""
    out = []
    if not isinstance(value, str):
        return out
    v = value
    norm_ci = spec.normalization == "case_insensitive"
    m = GUID_RX.fullmatch(v.strip())
    if m:
        g = m.group(1)
        braced = v.strip().startswith("{")
        forms = [("braces", "{" + g + "}")] if not braced else [("no_braces", g)]
        if not norm_ci:
            forms += [("braces_upper", "{" + g.upper() + "}"), ("braces_lower", "{" + g.lower() + "}"),
                      ("upper", g.upper()), ("lower", g.lower())]
        return [(h, s) for h, s in forms if s != v]
    if v.startswith("[") and spec.form in ("json", "text", "tokens"):
        try:
            items = json.loads(v)
        except ValueError:
            items = None
        if isinstance(items, list) and items:
            dump = E.jdump
            if all(isinstance(x, str) for x in items):
                alts = {}
                for x in items:
                    for how, y in _item_forms(x):
                        alts.setdefault(how, []).append(y)
                for how, ys in alts.items():
                    if len(ys) == len(items) and ys != items:
                        out.append((f"items_{how}", dump(ys)))
                        if how == "low_byte":
                            out.append(("items_low_byte_drop_first", dump(ys[1:])))
            if items and items[0] == "":
                out.append(("drop_empty", dump(items[1:])))
            if len(items) > 1:
                try:
                    out.append(("sorted", dump(sorted(items))))
                except TypeError:
                    pass
                out.append(("drop_first", dump(items[1:])))
                out.append(("drop_last", dump(items[:-1])))
                out.append(("reversed", dump(items[::-1])))
            if spec.form == "text":
                out.append(("comma", ",".join(str(x) for x in items)))
                out.append(("comma_space", ", ".join(str(x) for x in items)))
        return [(h, s) for h, s in out if s != v]
    if HEXPAIRS_RX.fullmatch(v) or (re.fullmatch(r"(?:[0-9a-fA-F]{2}){4,16}", v) and re.search(r"[a-fA-F]", v)):
        pairs = re.findall(r"[0-9a-fA-F]{2}", v)
        for sep, nm in ((":", "colon"), ("-", "dash"), ("", "joined"), (" ", "space")):
            for case in ((str.lower, "lower"), (str.upper, "upper")) if not norm_ci else ((str.lower, "lower"),):
                s = case[0](sep.join(pairs))
                if s != v:
                    out.append((f"{nm}_{case[1]}", s))
        return out
    m = re.fullmatch(r"(0x)?([0-9a-fA-F]+)", v)
    if m and (m.group(1) or re.search(r"[a-fA-F]", v)) and spec.form in ("hex0x", "text"):
        h = m.group(2)
        if m.group(1):
            for w in sorted({len(h) + len(h) % 2, 4, 8}):
                if w > len(h):
                    out.append((f"pad{w}", "0x" + h.lower().zfill(w)))
            stripped = h.lstrip("0") or "0"
            if stripped != h:
                out.append(("unpadded", "0x" + stripped.lower()))
        if spec.form == "text":
            if not norm_ci and h != h.lower():
                out.append(("lower", ("0x" if m.group(1) else "") + h.lower()))
            out.append(("toggle_prefix", h.lower() if m.group(1) else "0x" + h.lower()))
            if not norm_ci and h != h.upper():
                out.append(("upper", ("0x" if m.group(1) else "") + h.upper()))
        return [(h2, s) for h2, s in out if s != v]
    if spec.form == "text" and len(v) <= 200:
        # the bytes' own surroundings: a value quoted or bracketed, and plain case alternatives
        if v[:1] in "{[(\"'" and v[-1:] in "}])\"'" and len(v) > 2:
            out.append(("unwrapped", v[1:-1]))
        if not norm_ci and re.search(r"[A-Z]", v) and v != v.lower():
            out.append(("lower", v.lower()))   # a label is lower snake_case; an upper-case respelling is noise
        if "\\\\" in v:
            out.append(("unescaped", v.replace("\\\\", "\\")))
        elif "\\" in v:
            out.append(("escaped", v.replace("\\", "\\\\")))
        m = DT_RX.fullmatch(v)
        if m:
            for _, fmt in DT_LAYOUTS[:4]:
                out.append(("datetime", fmt.format(Y=m.group(1), m=m.group(2), d=m.group(3), H=m.group(4), M=m.group(5),
                                                   S=m.group(6) or "00")))
        for how, x in respell(spec, v):
            if isinstance(x, str):
                out.append((how, x))
    return [(h, s) for h, s in out if s != v]


def widen_spellings(spec, pool, top=6):
    """(a): the leading candidates' other spellings, each a little under the value it respells."""
    forms = stated_forms(spec)
    rows = sorted(pool.items.values(), key=lambda r: (-r[0], r[3]))[:top]
    for rank, (sc, nm, v, *_) in enumerate(rows):
        st = apply_stated(v, forms)
        if st != v:   # the question's stated form: just above the value as the bytes spell it
            pool.add(f"{nm.split('~')[0]}~stated", st, sc + 0.5)
        for j, (how, s) in enumerate(spellings(spec, v)[:10]):
            pool.add(f"{nm.split('~')[0]}~spell:{how}", s, sc - 2.0 - 0.4 * j - 0.2 * rank)


def bytes_context_spellings(spec, env, pool, members):
    """(a): a GUID found bare in the text is offered as the bytes hold it, braces included."""
    if spec.form not in ("guid", "text"):
        return
    for name in members[:3]:
        dec = env.decoded(name)
        for depth, how, text in dec.texts[:40]:
            for m in re.finditer(r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}", text[:2000000]):
                inner = m.group()[1:-1]
                cur = pool.items.get(pool._key(inner))
                if cur:
                    pool.add(f"{cur[1].split('~')[0]}~spell:bytes_braces", m.group(), cur[0] - 0.02)   # the bytes' own spelling of the same fact


# ------------------------------------------------------------------------------------------------- (b) anchors

def _object_words(spec):
    words = set(spec.field_toks) | set(spec.noun_toks)
    return words - POSITION_WORDS - E.STOP


def asks_position(spec):
    if spec.form not in ("int", "int_or_none", "hex0x"):
        return False
    words = set(spec.field_toks) | set(spec.noun_toks)
    return bool(words & POSITION_WORDS)


def relevant_records(spec, env, members):
    """The records a question is about: in its members, those whose magic it names first, CRC-valid only."""
    words = _object_words(spec)
    out = []
    for mi, name in enumerate(members[:8]):
        if env.time_left() <= 0:
            break
        for r in records_in(env, name, env.deadline - E.MARGIN):
            named = r["magic"].lower() in words or r["magic"].lower() in spec.low.split()
            out.append((mi, name, r, named))
    return out


def expert_anchors(spec, env, pool, members):
    """(b): where a record is, from every anchor a question may mean."""
    if not asks_position(spec):
        return
    words = set(spec.field_toks) | set(spec.noun_toks)
    recs = relevant_records(spec, env, members)
    if not recs:
        return
    objw = _object_words(spec)
    if not any(named for _, _, _, named in recs) and not (objw & OBJECT_WORDS):
        return
    want_rva = "rva" in words or "relative virtual" in spec.low
    want_va = bool(words & {"va", "vaddr", "virtual", "address", "addr", "memory", "mapped"}) and "file" not in words and not want_rva
    want_rel = bool(words & {"relative", "within", "inside"}) or ("section" in words and "start" in words)
    want_payload = "payload" in words or (bool(words & {"data", "body", "json"}) and "record" not in words)
    from_end = ("end" in words and bool(words & {"before", "from", "until"})) or bool(words & {"eof", "tail"})
    want_end = bool(words & {"end", "ends", "after", "past", "exclusive"}) and not from_end
    want_overlay = "overlay" in words and bool(words & {"relative", "within", "start", "inside"})
    fieldish = "field" in words or "fields" in words
    for mi, name, r, named in recs:
        b = env.member_bytes(name) or b""
        secs = sections_of(b[:SCAN_MAX])
        sec, rel, va, rva = place_of(secs, r["offset"])
        mapped_end = max([so + sz for nm, so, sz, _ in secs if not nm.startswith("<rva>")] + [table_end(b)])
        seg = next(((so, addr) for nm, so, sz, addr in secs if nm == "<load>" and so <= r["offset"] < so + sz), None)
        base = 32 + (6 if named else 0) - 1.5 * mi   # a position asked of a record outranks its header fields
        tag = f"anchor:{r['magic']}:{r['carrier']}"
        off = r["offset"]
        opts = [("file_offset", off, 0.0)]
        if r["carrier"] != "raw":
            opts.append(("carrier_end", off + r.get("carrier_len", 0), 6 if want_end else -6))
        else:
            opts.append(("payload_offset", off + 12, 7 if want_payload else -3))
            opts.append(("end_offset", off + r["size"], 6 if want_end else -5))
            if fieldish:
                for fw, d in (("length", 6), ("len", 6), ("size", 6), ("crc", 8), ("crc32", 8), ("checksum", 8),
                              ("key", 5), ("version", 4)):
                    if fw in words:
                        opts.append((f"field_{fw}", off + d, 8))
                        break
        if rel is not None:
            opts.append((f"section_relative:{sec}", rel, 7 if want_rel else -2.5))
        if va is not None:
            opts.append(("virtual_address", va, 7 if want_va else -3))
        if rva is not None:
            opts.append(("rva", rva, 8 if want_rva else -3.5))
        if seg is not None:
            opts.append(("segment_relative", off - seg[0], 8 if "segment" in words else -4))
        if r.get("inner"):
            opts.append(("carrier_inner", r["inner"], 8 if words & {"decoded", "within", "inside", "inner"} else -3))
        if "block" in words or "blocks" in words:
            for bs in (16, 512, 4096, 64):
                opts.append((f"block{bs}", off // bs, 6 if f"{bs}" in spec.text else 2))
        if secs and off >= mapped_end:
            opts.append(("overlay_relative", off - mapped_end, 8 if want_overlay else -4))
        opts.append(("from_file_end", len(b) - off, 8 if from_end else -7))
        for i, (how, val, adj) in enumerate(opts):
            pool.add(f"{tag}:{how}", val, base + adj - 0.2 * i)
        # the bare magic's other places (a decoy, the word a decoder compares with) are the last resort
        for j, o in enumerate(raw_magic_offsets(b[:SCAN_MAX], r["magic"])):
            if o != r["offset"]:
                pool.add(f"anchor:{r['magic']}:bare_magic", o, base - 9 - 0.3 * j)


# ------------------------------------------------------------------------------------------------- (c) derived

def url_parts(u):
    m = re.match(r"(?i)([a-z][a-z0-9+.-]*)://([^/:?#]+)(?::(\d+))?([^?#]*)(\?[^#]*)?", u)
    if not m:
        return {}
    host = m.group(2)
    labels = host.split(".")
    out = {"scheme": m.group(1), "protocol": m.group(1), "host": host, "hostname": host, "domain": host,
           "port": m.group(3) or {"http": "80", "https": "443", "ftp": "21"}.get(m.group(1).lower()),
           "path": m.group(4) or "/", "query": (m.group(5) or "")[1:] or None}
    out.update(domain_parts(host))
    out["domain"] = host
    return out


def domain_parts(host):
    labels = [x for x in host.split(".") if x]
    if len(labels) < 2:
        return {}
    return {"tld": labels[-1], "suffix": labels[-1], "registrable": ".".join(labels[-2:]), "apex": ".".join(labels[-2:]),
            "root": ".".join(labels[-2:]), "sld": labels[-2], "subdomain": ".".join(labels[:-2]) or None,
            "label": labels[0], "labels": labels, "label_count": len(labels), "first_label": labels[0]}


DERIVE_WORDS = set(URL_PARTS) | {"count", "number", "many", "total", "length", "len", "chars", "characters", "first",
                                  "last", "ms", "milliseconds", "seconds", "minutes", "keys", "fields", "properties",
                                  "entries", "items", "converted"} | set(DIGESTS)


SAME_NOUN = {"host": {"host", "hostname", "domain", "fqdn"}, "hostname": {"host", "hostname", "domain", "fqdn"},
             "domain": {"domain", "host", "hostname", "fqdn"}, "url": {"url", "uri", "endpoint", "link"},
             "peer": {"peer", "node", "server"}, "key": {"key"}}


def stem(w):
    return w[:-1] if len(w) > 3 and w.endswith("s") and not w.endswith("ss") else w


def base_noun(spec):
    """The noun a derived question builds on: the id's field words without its trailing derivation words
    (`config_domain_tld` -> domain, `config_host_first_label` -> host, `config_url_port` -> url)."""
    ft = [t for t in spec.field_toks if t not in ("config", "analysis", "cfg")]
    while len(ft) > 1 and ft[-1] in DERIVE_WORDS:
        ft.pop()
    out = [stem(t) for t in ft if (t not in DERIVE_WORDS or t in SAME_NOUN) and t.isalpha() and len(t) >= 3]
    if not out and set(spec.field_toks) & set(URL_PARTS):
        out = ["url", "domain", "host"]       # `registrable_domain`, `tld`: a part of the url or domain
    return out


def base_facts(spec, env, members, recs):
    """[(score, name, key, value)]: the stated values a derived question builds on, matched to its noun with the
    derivation words taken out (`config_url_port` -> the url), from the records and the decoded texts."""
    ft = base_noun(spec)
    if not ft:
        return []
    out = []
    want = set()
    for t in ft:
        want |= SAME_NOUN.get(t, {t})

    def score(k):
        kt = {stem(x) for x in E.toks(k.split(".")[-1])}
        s = 6.0 * len(kt & want)
        if kt and kt <= want:
            s += 6
        return s - 0.5 * len(kt - want)

    for mi, name in enumerate(members[:4]):
        for r in (recs or {}).get(name, []):
            obj = None
            for lh, txt in payload_texts(r)[::-1]:
                try:
                    obj = json.loads(txt)
                    break
                except ValueError:
                    obj = None
            if isinstance(obj, dict):
                out.append((-1.0 - mi, f"record:{r['magic']}:object", "__object__", obj))
                for k, v in obj.items():
                    sc = score(k)
                    if sc > 0:
                        out.append((sc + 20 - mi, f"record:{r['magic']}:kv:{k}", k, v))
        if env.time_left() <= 0:
            break
        dec = env.decoded(name)
        for depth, how, text in dec.texts[:60]:
            for k, v in E.kv_pairs(text) + line_kv(text):
                sc = score(k)
                if sc > 0:
                    out.append((sc + 14 - mi, f"kv:{k}", k, v))
    out.sort(key=lambda x: -x[0])
    seen, uniq = set(), []
    for row in out:
        key = (row[2], json.dumps(row[3], sort_keys=True, default=str))
        if key not in seen:
            seen.add(key)
            uniq.append(row)
    return uniq[:12]


def line_kv(text):
    """key = value / key: value read per LINE, so a value holding ; , | survives (INI, YAML, env files)."""
    out = []
    for ln in text[:200000].splitlines()[:4000]:
        m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_.\-]{0,40})\s*[=:]\s*(.+?)\s*$", ln)
        if m and len(m.group(2)) <= 400:
            out.append((m.group(1), m.group(2).strip().strip("'\"")))
    return out


EXTRA_SHAPES = {
    "macaddr": (r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])|(?<![0-9A-Za-z])[0-9A-Fa-f]{12}(?![0-9A-Za-z])",
                {"mac", "hwaddr", "bssid", "ether", "hardware"}),
    "fingerprint": (r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){15,63}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])", {"fingerprint", "thumbprint"}),
    "datetime": (r"\b\d{4}-\d\d-\d\d[T ]\d\d:\d\d(?::\d\d)?(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?\b",
                 {"timestamp", "time", "date", "datetime", "built", "created", "modified", "compiled"}),
    "version": (r"(?<![\w.])[vV]?\d+\.\d+(?:\.\d+){0,2}(?![\w.])", {"version", "ver", "release"}),
}


def expert_extra_shapes(spec, env, pool, members):
    """(a): values of a shape the enumerator has no reader for, when the asked noun names it."""
    words = {stem(w) for w in set(spec.field_toks) | set(spec.noun_toks)}
    for nm, (rx, kws) in EXTRA_SHAPES.items():
        if not words & {stem(k) for k in kws}:
            continue
        r = re.compile(rx)
        for mi, name in enumerate(members[:3]):
            dec = env.decoded(name)
            seen = []
            for depth, how, text in dec.texts[:30]:
                for m in r.finditer(text[:2000000]):
                    if m.group() not in seen:
                        seen.append(m.group())
            for i, h in enumerate(seen[:8]):
                pool.add(f"shape:{nm}", h, 16 - mi - 0.3 * i)


def expert_line_kv(spec, env, pool, members):
    """(a)/(c): key=value lines whose value the enumerator's pair reader cut at a ; , or |."""
    for mi, name in enumerate(members[:3]):
        dec = env.decoded(name)
        for depth, how, text in dec.texts[:20]:
            for k, v in line_kv(text):
                ks = E.key_score(k, spec)
                if ks > 0 and re.search(r"[;,|]", v):
                    pool.add(f"line_kv:{k}", v, 19 + ks - mi)


def expert_derived(spec, env, pool, members, recs=None):
    """(c): parts, counts, lengths, conversions and digests of a value the question builds on."""
    words = set(spec.field_toks) | set(spec.noun_toks)
    fwords = set(spec.field_toks)
    final = set(E.toks(re.split(r"(?<=[.;])\s+", spec.text.strip())[-1])) if spec.text.strip() else set()
    dwords = fwords | final          # what is derived is said by the id's words and the asked sentence
    asked = [w for w in DERIVE_WORDS if w in dwords]
    if not asked and not (recs and re.search(r"\bnone\b", spec.low)):
        return
    facts = base_facts(spec, env, members, recs)
    base = set(base_noun(spec))
    part_words = [w for w in URL_PARTS if w in dwords and stem(w) not in base]
    algo = next((a for a in DIGESTS if a in dwords), None)
    words = dwords
    objs = [v for _, _, k, v in facts if k == "__object__"]
    if objs and base and fwords & {"config", "cfg", "settings", "configuration"} and re.search(r"\bnone\b", spec.low) \
            and not any(k != "__object__" for _, _, k, _ in facts):
        pool.add("absent:record_has_no_such_field", "none", 26)
    for sc0, nm, k, v in facts:
        sc = 24 + 0.4 * sc0
        if k == "__object__":
            if words & {"keys", "fields", "properties"} and words & {"count", "number", "many"}:
                pool.add(f"derived:{nm}:key_count", len(v), 28)
            continue
        if isinstance(v, str) and part_words:
            parts = url_parts(v) if re.match(r"(?i)[a-z][a-z0-9+.-]*://", v) else domain_parts(v) \
                if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z0-9-]{2,}", v, re.I) else \
                domain_parts(v.split("@")[-1].strip("<> ")) if "@" in v else {}
            q_ = parts.get("query") or ""
            for pk, pv in re.findall(r"(?:^|&)([^=&]+)=([^&]*)", q_):
                if pk.lower() in fwords:
                    pool.add(f"derived:{nm}:query_param:{pk}", pv, sc + 6)
            m_ = re.fullmatch(r"[^@\s]+@([^@\s>]+)", v.strip("<> "))
            if m_ and "domain" in dwords:
                pool.add(f"derived:{nm}:email_domain", m_.group(1), sc + 6)
            for i, w in enumerate(part_words):
                key = "label_count" if w in ("labels", "label") and words & {"count", "number", "many"} else w
                val = parts.get(key)
                if val is None:
                    continue
                if isinstance(val, list):
                    val = E.jdump(val) if spec.form == "json" else ".".join(val)
                pool.add(f"derived:{nm}:{key}", val, sc + (6 if w in fwords else 2) - 0.3 * i)
        items = v if isinstance(v, list) else None
        if isinstance(v, str) and re.search(r"[;,|]", v) and len(v) < 2000 and not re.match(r"(?i)[a-z]+://", v):
            items = [x.strip() for x in re.split(r"[;,|]", v) if x.strip()]
        if items is not None:
            if words & {"count", "number", "many", "total", "entries", "items"}:
                pool.add(f"derived:{nm}:count", len(items), sc + 5)
            if "first" in words and items:
                pool.add(f"derived:{nm}:first", items[0], sc + 5)
            if "last" in words and items:
                pool.add(f"derived:{nm}:last", items[-1], sc + 5)
        if isinstance(v, str) and words & {"length", "len", "chars", "characters"} and not (words & POSITION_WORDS):
            pool.add(f"derived:{nm}:length", len(v), sc + 5)
            if len(v.encode()) != len(v):
                pool.add(f"derived:{nm}:utf8_length", len(v.encode()), sc + 3)
        num_ = v if isinstance(v, (int, float)) and not isinstance(v, bool) else \
            (float(v) if isinstance(v, str) and re.fullmatch(r"-?\d+(?:\.\d+)?", v) else None)
        if num_ is not None:
            for wset, mult, how in (({"ms", "milliseconds"}, 1000, "s_to_ms"), ({"minutes"}, 1 / 60, "s_to_min"),
                                    ({"seconds"}, 1 / 1000, "ms_to_s"), ({"kb", "kib", "kilobytes"}, 1 / 1024, "b_to_kib")):
                if words & wset:
                    x = num_ * mult
                    if abs(x - round(x)) < 1e-9:
                        pool.add(f"derived:{nm}:{how}", int(round(x)), sc + 4)
        if algo and isinstance(v, (str, int)) and not (words & {"member", "file", "artifact", "sample"}):
            emit_digest(pool, algo, f"derived:{nm}:value_{algo}", str(v).encode(), sc - 4)
    # digests of a record's payload
    if algo and spec.form in ("text", "sha256", "hex0x", "int"):
        objw = _object_words(spec)
        for name in members[:3]:
            for r in (recs or {}).get(name, []):
                strong = bool(objw & {"payload", "decoded", "config", "configuration", "record", "json"})
                emit_digest(pool, algo, f"derived:{r['magic']}:payload_{algo}", r["payload"], 28 if strong else 15)
                if algo == "crc32":
                    pool.add(f"derived:{r['magic']}:stored_crc", "0x%08x" % r["crc"], 27 if strong else 15)
    if spec.form == "json" and re.search(r"\b(?:absent|missing|none|empty|no such)\b", spec.low):
        pool.add("absent:empty_list", "[]", 6)
    # an email address the pool holds, asked for its domain
    if "domain" in fwords:
        for sc, nm, v, *_ in sorted(pool.items.values(), key=lambda r: (-r[0], r[3]))[:12]:
            m_ = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", v)
            if m_:
                pool.add(f"derived:{nm.split('~')[0]}:email_domain", m_.group(1), sc + 1)
    # a count of the distinct values of a shape the noun names (urls, domains, ips, ...)
    if words & {"count", "number", "many"} and spec.form in ("int", "int_or_none"):
        for sh in ("url", "domain", "ip", "email", "mutex", "registry", "filename"):
            if sh in base or (sh + "s") in fwords:
                hits = []
                for name in members[:3]:
                    for depth, how, text in env.decoded(name).texts[:40]:
                        hits += E.shape_hits(text, sh)
                if hits:
                    pool.add(f"derived:shape:{sh}:distinct_count", len(set(hits)), 25 + (2 if "distinct" in dwords or "unique" in dwords else 0))
                    pool.add(f"derived:shape:{sh}:count", len(hits), 23 + (2 if not ("distinct" in dwords or "unique" in dwords) else 0))


def emit_digest(pool, algo, how, data, sc):
    if algo == "crc32":
        c = zlib.crc32(data) & 0xffffffff
        pool.add(how, "0x%08x" % c, sc)
        pool.add(how + ":dec", c, sc - 0.5)
        pool.add(how + ":bare", "%08x" % c, sc - 0.8)
    else:
        pool.add(how, hashlib.new(algo, data).hexdigest(), sc)


# ------------------------------------------------------------------------------------------------- (d) vocabulary

ANCHOR_WORDS = {"base64": ("carrier", "base64"), "base 64": ("carrier", "base64"), "hex": ("carrier", "hex"),
                "hexadecimal": ("carrier", "hex"), "utf-16": ("carrier", "utf16_base64"),
                "webassembly": ("container", "wasm"), "wasm": ("container", "wasm"), "mach-o": ("container", "macho"),
                "overlay": ("place", "overlay"), "resource": ("place", "resource"), "literal": ("carrier", "raw"),
                "zlib": ("carrier", "zlib"), "compressed": ("carrier", "zlib")}
NEG = _Rx(r"(?:other than|not|except|outside|without|rather than|instead of|no)\s+(?:\w+\s+){0,3}$", re.I)


def located_facts(env, recs):
    """What the bytes say about where the record is: carrier, section, container, overlay."""
    facts = []
    for name, rs in recs.items():
        b = env.member_bytes(name) or b""
        cont = "elf" if b[:4] == b"\x7fELF" else "pe" if b[:2] == b"MZ" else "wasm" if b[:4] == b"\x00asm" else \
            "macho" if b[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") else "data"
        secs = sections_of(b[:SCAN_MAX]) if cont in ("elf", "pe") else []
        mapped_end = max([so + sz for nm, so, sz, _ in secs if not nm.startswith("<")] + [0])
        for r in rs:
            sec, rel, va, rva = place_of(secs, r["offset"])
            facts.append({"carrier": r["carrier"], "section": sec, "container": cont, "magic": r["magic"],
                          "overlay": bool(secs) and r["offset"] >= mapped_end, "mapped": va is not None})
    return facts


def clause_of(text, token, tokens):
    """The words of the question that define one enum token: from the token to the next token named."""
    low = text.lower()
    best = None
    for m in re.finditer(r"(?<![\w.])" + re.escape(token.lower()) + r"(?![\w])", low):
        s = m.end()
        nxt = [low.find(t.lower(), s) for t in tokens if t != token]
        nxt = [x for x in nxt if x >= 0]
        e = min(nxt + [len(low), (low.find(";", s) + 1 or len(low) + 1) - 1 if low.find(";", s) >= 0 else len(low)])
        cl = low[s:e]
        if len(cl.strip()) >= 8 and (best is None or len(cl) > len(best)):
            best = cl
    return best or ""


def clause_score(clause, facts):
    """How well the located facts satisfy a clause: its section names, its carrier and container words."""
    if not clause or not facts:
        return 0.0
    sc = 0.0
    f = facts[0]
    for m in re.finditer(r"(?<![\w])(\.[a-z_][\w.$]{1,20})", clause):
        neg = bool(NEG.search(clause[:m.start()][-40:]))
        hit = any((x.get("section") or "") == m.group(1) for x in facts)
        sc += (-6.0 if hit else 4.0) if neg else (8.0 if hit else -5.0)
    for w, (kind, val) in ANCHOR_WORDS.items():
        for m in re.finditer(r"(?<![\w-])" + re.escape(w) + r"(?![\w-])", clause):
            neg = bool(NEG.search(clause[:m.start()][-40:]))
            if kind == "carrier":
                hit = any(x["carrier"].startswith(val) for x in facts)
            elif kind == "container":
                hit = any(x["container"] == val for x in facts)
            else:
                hit = any(x.get(val) for x in facts)
            sc += (-4.0 if hit else 1.0) if neg else (5.0 if hit else -3.0)
            break
    if re.search(r"\bmapped\b|\bsection\b", clause) and not any(x["mapped"] for x in facts):
        sc -= 1.5
    if re.match(r"\W*(?:otherwise|else|fallback|default)", clause) or re.search(r"\botherwise\b", clause[:20]):
        sc += 0.5
    return sc


def expert_vocab(spec, env, pool, members, recs):
    """(d): an enum token whose own clause the located facts satisfy; composed labels without an enum."""
    facts = located_facts(env, recs) if recs else []
    named = set(spec.field_toks) | set(E.toks(spec.text))
    facts.sort(key=lambda f: f["magic"].lower() not in named)
    if spec.accepted and len(spec.accepted) > 2 and facts:
        scores = {a: clause_score(clause_of(spec.text, a, spec.accepted), facts) for a in spec.accepted}
        low = spec.text.lower()
        fb = None
        for a in spec.accepted:
            al = re.escape(a.lower())
            if re.search(r"\botherwise,?\s+(?:(?:submit|use|answer|choose|it is|report)\s+)?" + al + r"\b", low) or \
                    re.search(r"\b" + al + r"\s+otherwise\b", low):
                fb = a
        if fb and not any(v > 2 for k, v in scores.items() if k != fb):
            scores[fb] = scores.get(fb, 0) + 6.0
        for a, cs in scores.items():
            if cs:
                pool.add(f"vocab:clause:{a}", a, 14 + cs)
        return
    if spec.accepted or spec.form not in ("text",) or not facts:
        return
    words = set(spec.field_toks)
    if not words & {"storage", "stored", "location", "placement", "carrier", "encoding", "form", "layout", "packing",
                    "embedding", "store", "kind", "method"}:
        return
    f = facts[0]
    carrier = {"base64url": "base64", "utf16_base64": "base64"}.get(f["carrier"], f["carrier"])
    sec = (f.get("section") or "").lstrip(".").replace(".", "_").replace("$", "_").lower()
    labels = [carrier]
    if sec:
        labels += [f"{carrier}_{sec}_section", f"{carrier}_{sec}", f"{carrier}_in_{sec}", f"{sec}_section"]
        if f["mapped"] and f["container"] in ("elf", "pe", "macho"):
            labels.append(f"{carrier}_const_array")   # a record compiled into a native image is a C array
        if sec in ("rodata", "rdata", "const", "data_rel_ro"):
            labels += [f"{carrier}_const_array", f"{carrier}_const_data", f"{carrier}_rodata_array"]
        if sec in ("data",):
            labels += [f"{carrier}_data_array", f"{carrier}_global_array"]
        if sec in ("text",):
            labels += [f"{carrier}_code", f"{carrier}_stack_string"]
    if f.get("overlay"):
        labels += [f"{carrier}_overlay", "overlay"]
    if f["container"] == "wasm":
        labels += ["wasm_data_segment", f"{carrier}_wasm_data"]
    for i, lab in enumerate(dict.fromkeys(labels)):
        pool.add(f"vocab:composed:{lab}", lab, 15 - 0.6 * i)


# ------------------------------------------------------------------------------------------------- (e) other

def expert_unnamed_records(spec, env, pool, members, recs):
    """(e): a record no question names, found by its CRC-32: its JSON pairs and shapes answer the asked noun."""
    if spec.form in ("int", "int_or_none", "hex0x") and asks_position(spec):
        return
    mags = {m.lower() for m in E.magic_words(spec)}
    shapes = E.wanted_shapes(spec)
    for mi, name in enumerate(members[:6]):
        for r in recs.get(name, []):
            layers = payload_texts(r)
            if mags:
                # a question that names its container has the enumerator's own record expert; only a base64 or hex
                # layer inside that record's payload is new here (round 2)
                if r["magic"].lower() not in mags or len(layers) < 2:
                    continue
                layers = layers[1:]
            for lh, txt in layers[::-1]:
                expert_record_pairs(spec, pool, r, lh, txt, 30 - 1.0 * mi + (0 if lh == "payload" else 0.5), shapes)


def expert_record_pairs(spec, pool, r, lh, txt, sc0, shapes):
    """The pairs and shapes of one record payload text (as stored, or a layer inside it) that answer the noun."""
    tag = f"record:{r['magic']}" + ("" if lh == "payload" else f":{lh}")
    for k, v in E.kv_pairs(txt):
        ks = E.key_score(k, spec)
        if ks <= 0:
            continue
        if isinstance(v, (list, tuple)):
            pool.add(f"{tag}:kv:{k}", list(v), sc0 + ks)
        elif isinstance(v, (str, int)) and not isinstance(v, bool):
            pool.add(f"{tag}:kv:{k}", v, sc0 + ks)
        elif v is None:
            pool.add(f"{tag}:kv:{k}:null", "none", sc0 + ks - 4)
    for si, sh in enumerate(shapes[:3]):
        for h in E.shape_hits(txt, sh)[:3]:
            pool.add(f"record:{r['magic']}:{sh}", h, sc0 - 8 - 2 * si)


ITA2_LTRS = "\x00E\nA SIU\rDRJNFCKTZLWHYPQOBG\x0fMXV\x0e"
ITA2_FIGS = "\x003\n- \x0787\r$4',!:(5\")2#6019?&\x0f./;\x0e"


def ita2_decode(codes, start_figs=False):
    out, figs = [], start_figs
    for c in codes:
        if c == 31:
            figs = False
            continue
        if c == 27:
            figs = True
            continue
        ch = (ITA2_FIGS if figs else ITA2_LTRS)[c]
        if ch not in "\x00\x0e\x0f\x07":
            out.append(ch)
    return "".join(out).lower()


def classical_extra(raw: bytes, deadline=None):
    """[(how, text)]: codecs the enumerator's battery lacked, each a standard decoding, chained up to three deep:
    ITA2/Baudot 5-bit groups (either bit order), a big integer in base 10/16/36/58/62, affine ciphers (every key),
    keyboard row shifts, repeated percent-decoding, base85/Ascii85/Z85, =XX quoted-printable, octal and \\x escapes."""
    t0 = raw.decode("latin-1", "replace").strip()
    out = []
    seen = {t0}
    frontier = [("raw", t0)]
    for depth in range(3):
        nxt = []
        for how, t in frontier:
            for nm, x in _decode_steps(t, deep=depth > 0):
                if not x or x in seen or len(x) > 20000:
                    continue
                seen.add(x)
                h = f"{how}>{nm}" if how != "raw" else nm
                out.append((h, x))
                nxt.append((h, x))
                if len(out) > 600 or (deadline and time.time() > deadline):
                    return out
        frontier = nxt
    return out


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
NATO = {w: w[0] for w in ("alfa alpha bravo charlie delta echo foxtrot golf hotel india juliett juliet kilo lima mike "
                          "november oscar papa quebec romeo sierra tango uniform victor whiskey xray x-ray yankee zulu").split()}
NATO.update({"zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6", "seven": "7",
             "eight": "8", "nine": "9", "niner": "9", "dash": "-", "hyphen": "-", "space": " ", "stop": "."})
BRAILLE = {0x01: "a", 0x03: "b", 0x09: "c", 0x19: "d", 0x11: "e", 0x0b: "f", 0x1b: "g", 0x13: "h", 0x0a: "i", 0x1a: "j",
           0x05: "k", 0x07: "l", 0x0d: "m", 0x1d: "n", 0x15: "o", 0x0f: "p", 0x1f: "q", 0x17: "r", 0x0e: "s", 0x1e: "t",
           0x25: "u", 0x27: "v", 0x3a: "w", 0x2d: "x", 0x3d: "y", 0x35: "z", 0x24: "-", 0x00: " ", 0x3c: "#"}
B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
QWERTY_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]


def _int_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""


def _printable_text(b):
    return b.decode("latin-1") if b and E.printable_ratio(b) > 0.9 else None


def _decode_steps(t, deep=False):
    out = []
    s = t.strip()
    if len(s) > 8000:
        return out
    # ITA2 / Baudot
    groups = re.findall(r"(?<![01])[01]{5}(?![01])", s)
    if len(groups) >= 8 and len(groups) * 5 >= 0.6 * len(re.sub(r"\s", "", s)):
        for order in ("msb", "lsb"):
            out.append((f"ita2_{order}", ita2_decode([int(g if order == "msb" else g[::-1], 2) for g in groups])))
    # a big integer in a base
    if re.fullmatch(r"[0-9A-Za-z]{16,400}", s):
        for nm, alpha in (("base36", "0123456789abcdefghijklmnopqrstuvwxyz"), ("base58", B58), ("base62", B62)):
            src = s.lower() if nm == "base36" else s
            if all(c in alpha for c in src):
                n = 0
                for c in src:
                    n = n * len(alpha) + alpha.index(c)
                x = _printable_text(_int_bytes(n))
                if x:
                    out.append((nm + "_int", x))
        if s.isdigit():
            x = _printable_text(_int_bytes(int(s)))
            if x:
                out.append(("decimal_int", x))
    # affine ciphers over the letters, every key; kept only when a word of the crib shows
    if not deep and re.search(r"[A-Za-z]{4}", s) and len(s) <= 4000:   # letter ciphers on the first layer only
        for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
            ai = pow(a, -1, 26)
            for b_ in range(26):
                x = "".join(chr((ai * (ord(c) - 97 - b_)) % 26 + 97) if "a" <= c <= "z" else
                            chr((ai * (ord(c) - 65 - b_)) % 26 + 65) if "A" <= c <= "Z" else c for c in s)
                if re.search(r"(?i)submit|answer|slug|nice|work", x):
                    out.append((f"affine_{a}_{b_}", x))
        for d, nm in ((1, "kb_left"), (-1, "kb_right")):
            m = {}
            for r in QWERTY_ROWS:
                for i, c in enumerate(r):
                    m[c] = r[(i + d) % len(r)]
                    m[c.upper()] = r[(i + d) % len(r)].upper()
            x = "".join(m.get(c, c) for c in s)
            if re.search(r"(?i)submit|answer|nice|work", x):
                out.append((nm, x))
    if " " in s and len(s) <= 4000:
        out.append(("words_reversed", " ".join(w[::-1] for w in s.split(" "))))
    words_ = re.findall(r"[A-Za-z]+", s)
    if len(words_) >= 6 and sum(1 for w in words_ if w.lower() in NATO) >= 0.7 * len(words_):
        out.append(("nato", "".join(NATO.get(w.lower(), " " if w.lower() in ("space", "stop") else "") for w in
                                    re.findall(r"[A-Za-z]+|[^A-Za-z\s]", s))))
    if sum(1 for c in s if 0x2800 <= ord(c) <= 0x28ff) >= 6:
        out.append(("braille", "".join(BRAILLE.get(ord(c) - 0x2800, c if not 0x2800 <= ord(c) <= 0x28ff else "?") for c in s)))
    if re.fullmatch(r"[1-5]{2}(?:[\s,/-]*[1-5]{2}){5,}[\s\S]*", s) and len(re.findall(r"[1-5]{2}", s)) >= 6:
        grid = "abcdefghiklmnopqrstuvwxyz"
        for nm, f in (("polybius_rc", lambda a, b: grid[(a - 1) * 5 + b - 1]), ("polybius_cr", lambda a, b: grid[(b - 1) * 5 + a - 1])):
            out.append((nm, re.sub(r"([1-5])([1-5])", lambda mm: f(int(mm.group(1)), int(mm.group(2))), s)))
    if "%" in s:
        from urllib.parse import unquote
        x = unquote(s)
        if x != s:
            out.append(("percent", x))
    if re.fullmatch(r"(?:=[0-9A-Fa-f]{2}|[^=\s])+", s) and s.count("=") >= 4:
        try:
            out.append(("quoted_printable", bytes.fromhex("".join(re.findall(r"=([0-9A-Fa-f]{2})", s))).decode("latin-1")))
        except ValueError:
            pass
    if re.fullmatch(r"(?:\\[0-7]{3})+", s):
        out.append(("octal_escapes", bytes(int(x, 8) for x in re.findall(r"\\([0-7]{3})", s)).decode("latin-1")))
    if re.fullmatch(r"(?:\\x[0-9a-fA-F]{2})+", s):
        out.append(("hex_escapes", bytes.fromhex(s.replace("\\x", "")).decode("latin-1")))
    if len(s) >= 10 and not re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        for nm, fn in (("base85", base64.b85decode), ("ascii85", lambda z: base64.a85decode(z, adobe=z.startswith(b"<~")))):
            try:
                x = _printable_text(fn(s.encode()))
                if x:
                    out.append((nm, x))
            except (ValueError, binascii.Error):
                pass
        z85 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
        if len(s) % 5 == 0 and all(c in z85 for c in s):
            b = bytearray()
            for i in range(0, len(s), 5):
                n = 0
                for c in s[i:i + 5]:
                    n = n * 85 + z85.index(c)
                if n >= 1 << 32:
                    b = None
                    break
                b += n.to_bytes(4, "big")
            x = _printable_text(bytes(b)) if b else None
            if x:
                out.append(("z85", x))
    return out


NUMW = {"zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
        "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16,
        "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20, "thirty": 30, "forty": 40, "fifty": 50,
        "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90}


def slugs_in_words(text):
    """A slug written out: `Jaunty Raven Glade 73`, `dapper summit brook twenty-nine`."""
    out = []
    t = text[:20000]
    for m in re.finditer(r"(?i)\b([a-z]{2,12})[\s_-]+([a-z]{2,12})[\s_-]+([a-z]{2,12})[\s_-]+(\d{2}\b|[a-z]+(?:[\s-][a-z]+)?)", t):
        w = [x.lower() for x in m.groups()]
        tail = w[3]
        if tail.isdigit():
            n = int(tail)
        else:
            parts = re.split(r"[\s-]", tail)
            if not all(p in NUMW for p in parts):
                continue
            n = sum(NUMW[p] for p in parts)
        if 0 <= n <= 99 and all(E.is_word(x) for x in w[:3]):
            out.append(f"{w[0]}-{w[1]}-{w[2]}-{n:02d}")
    return out


def slug_word_bonus(slug):
    """Dictionary words in a slug's three words (each 0..3)."""
    parts = slug.split("-")[:3]
    return 3.0 * sum(1 for w in parts if E.is_word(w))


def expert_slug_extra(spec, env, pool):
    """(e): slugs from the extra codecs, and every slug candidate re-ranked by its words being words."""
    if spec.form != "slug":
        return
    raw = env.ctx.get("delivery") or next(iter(env.files.values()), b"")
    # the extra codecs only when no candidate yet reads as three dictionary words (they cost a Mastery's 98 sets)
    known = any(slug_word_bonus(r[2]) >= 9 for r in pool.items.values())
    texts = [] if known else classical_extra(raw, env.deadline - E.MARGIN)
    if not known:
        texts += [("as_is", raw.decode("latin-1", "replace"))] + [(f"norm_{h}", t) for h, t in list(texts)[:200]]
        # keyboard row shifts with no crib word to gate them: a slug of dictionary words is the evidence (round 2)
        texts += [(h, t) for h, t in kb_decodes(raw[:20000].decode("latin-1", "replace")) if E.SLUG_RE.search(t)]
    for how, txt in texts:
        for h in slugs_in_words(txt):
            pool.add(f"classical:{how}:words", h, 19 + slug_word_bonus(h))
    for how, txt in texts:
        for h in E.SLUG_RE.findall(txt):
            slug = "-".join(h)
            pool.add(f"classical:{how}", slug, 20 + slug_word_bonus(slug))
    for r in pool.items.values():
        bonus = slug_word_bonus(r[2])
        r[0] += 4.0 * bonus - 18.0   # three dictionary words lift a slug; none sinks it below one that has them


HEXA = "0123456789ABCDEF"


def vig_hex(code, key, sign):
    out = []
    for i, c in enumerate(code):
        k = HEXA.index(key[i % len(key)]) if key[i % len(key)] in HEXA else 0
        out.append(HEXA[(HEXA.index(c) + sign * k) % 16])
    return "".join(out)


def expert_ans_extra(spec, env, pool):
    """(e): an `ANS-` code under a Vigenere over the hex alphabet whose key is a hex text the puzzle states."""
    if spec.form != "ans":
        return
    texts = []
    for name, b in list(env.files.items())[:400]:
        if name.endswith(".json") or b"huntress_puzzle" in name.encode() or b[:1] == b"{":
            texts.append(b[:200000].decode("utf-8", "replace"))
    for t in texts:
        try:
            obj = json.loads(t)
        except ValueError:
            continue
        flat = list(E.flatten_json(obj))
        codes = [v for k, v in flat if isinstance(v, str) and re.fullmatch(r"(?:ANS-)?[0-9A-Fa-f]{16}", v)]
        keys = [v for k, v in flat if isinstance(v, str) and re.fullmatch(r"[0-9A-Fa-f]{1,32}", v)
                and re.search(r"key|secret|shift|mask|iv|nonce|salt|pad", k, re.I)]
        for c in codes:
            body = c[-16:].upper()
            for key in keys:
                for sign in (-1, 1):
                    pool.add(f"ans_extra:vig_hex{'_dec' if sign < 0 else '_enc'}", "ANS-" + vig_hex(body, key.upper(), sign), 24 - (0 if sign < 0 else 1))


# ================================================================================================= round 2
# The families build, round 2: the miss families round 1 left uncovered (synth_families2.py measures them).

def _words(spec):
    return {stem(w) for w in set(spec.field_toks) | set(spec.noun_toks)}


def _texts(env, members, n=3, cap=40):
    for mi, name in enumerate(members[:n]):
        for depth, how, text in env.decoded(name).texts[:cap]:
            yield mi, name, depth, how, text


def payload_texts(r):
    """[(how, text)] of a record's payload: as stored, and a base64 or hex layer inside it (decoded when it reads)."""
    got = r.get("_layers")
    if got is not None:
        return got
    p = r["payload"]
    out = [("payload", p.decode("utf-8", "replace"))]
    t = p.strip()
    inner = None
    if len(t) >= 16 and re.fullmatch(rb"(?:[0-9a-fA-F]{2})+", t):
        try:
            inner = ("hex", binascii.unhexlify(t))
        except (binascii.Error, ValueError):
            inner = None
    elif len(t) >= 16 and re.fullmatch(rb"[A-Za-z0-9+/_-]+={0,2}", t):
        b = _b64dec(t)
        if b:
            inner = ("base64", b)
    if inner and E.printable_ratio(inner[1][:512]) > 0.9:
        out.append((inner[0], inner[1].decode("utf-8", "replace")))
        z = None
        try:
            z = zlib.decompress(inner[1])
        except zlib.error:
            pass
        if z and E.printable_ratio(z[:512]) > 0.9:
            out.append((inner[0] + ">zlib", z.decode("utf-8", "replace")))
    r["_layers"] = out
    return out


# ------------------------------------------------------------------------------------------------- (a) GUID bytes

HEX32_RX = _Rx(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")
HEXSEP16_RX = _Rx(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[ :,-]){15}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
GUID_WORDS = {"guid", "uuid", "clsid", "iid", "appid", "libid", "mvid", "guids", "uuids", "clsids", "typelib"}


def guid_renderings(spec, raw16, base_how):
    """[(how, text)] of 16 GUID bytes: as Windows keeps them in memory (the first three fields little-endian) and
    as a straight big-endian reading, each in the question's stated rendering first, then braces/case."""
    import uuid
    syn = spec.syntax.lower()
    braces = bool(re.search(r"\bbraces?\b|\bbraced\b|registry form|curly", syn)) and not re.search(
        r"\bno braces|without (?:the |any )?braces|unbraced", syn)
    upper = bool(re.search(r"\bupper", syn)) and not re.search(r"\blower", syn)
    out = []
    for interp, g in (("mixed_endian", uuid.UUID(bytes_le=bytes(raw16))), ("big_endian", uuid.UUID(bytes=bytes(raw16)))):
        s = str(g)
        alts = [(braces, upper)] + [(b_, u_) for b_ in (False, True) for u_ in (False, True) if (b_, u_) != (braces, upper)]
        for j, (b_, u_) in enumerate(alts):
            t = ("{%s}" % s) if b_ else s
            out.append((f"{base_how}:{interp}" + ("" if j == 0 else f":{'braces' if b_ else 'bare'}_{'upper' if u_ else 'lower'}"),
                        t.upper() if u_ else t, j))
    return out


def gpt_guids(b):
    """[(name, 16 raw bytes)]: a GPT header's disk GUID and its first partition entries' type and unique GUIDs."""
    out = []
    for sec in (512, 4096):
        h = sec
        if b[h:h + 8] != b"EFI PART" or len(b) < h + 92:
            continue
        out.append(("gpt_disk_guid", b[h + 56:h + 72]))
        try:
            lba, n, size = struct.unpack_from("<QII", b, h + 72)
        except struct.error:
            break
        base = lba * sec
        for i in range(min(n, 4)):
            e = base + i * size
            if len(b) < e + 32 or b[e:e + 16] == bytes(16):
                break
            out.append((f"gpt_partition{i}_type_guid", b[e:e + 16]))
            out.append((f"gpt_partition{i}_unique_guid", b[e + 16:e + 32]))
        break
    return out


def expert_guid_bytes(spec, env, pool, members, recs):
    """(a): a GUID stored as its 16 in-memory bytes (32 hex digits, a GPT header's raw bytes) asked as a GUID, and a
    GUID asked as its in-memory bytes."""
    words = _words(spec)
    syn = spec.syntax.lower()
    if spec.form == "guid" or (spec.form == "text" and words & GUID_WORDS and "guid" in syn):
        seen = set()

        def offer(raw, how, sc):
            if raw in seen or len(raw) != 16:
                return
            seen.add(raw)
            for h2, t, j in guid_renderings(spec, raw, how):
                pool.add(h2, t, sc - (1.0 if "big_endian" in h2 else 0) - 2.0 * min(j, 1) - 0.3 * j)

        cands = []
        for mi, name, depth, how, text in _texts(env, members, 3, 40):
            for k, v in E.kv_pairs(text) + line_kv(text):
                if isinstance(v, str) and (HEX32_RX.fullmatch(v.strip()) or HEXSEP16_RX.fullmatch(v.strip())):
                    ks = E.key_score(k, spec) + (3 if set(E.toks(k)) & (GUID_WORDS | {"bytes", "raw"}) else 0)
                    cands.append((26 + min(ks, 8) - mi, f"guid_bytes:kv:{k}", v))
            for m in HEX32_RX.finditer(text[:400000]):
                cands.append((17 - mi, "guid_bytes:hex32", m.group()))
        for name, rs in (recs or {}).items():
            for r in rs:
                for lh, txt in payload_texts(r):
                    for k, v in E.kv_pairs(txt):
                        if isinstance(v, str) and HEX32_RX.fullmatch(v.strip()):
                            cands.append((27 + min(E.key_score(k, spec), 8), f"guid_bytes:record:{r['magic']}:{k}", v))
        for sc, how, v in sorted(cands, key=lambda x: -x[0])[:6]:
            offer(bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", v)), how, sc)
        for mi, name in enumerate(members[:3]):
            for gname, raw in gpt_guids(env.member_bytes(name) or b""):
                gw = set(E.toks(gname))
                offer(raw, f"guid_bytes:{gname}", 28 + 2.0 * len(gw & words) - mi - (2 if "partition" in gname else 0))
        return
    # the reverse: a GUID asked as the 16 bytes kept in memory, as hex
    if spec.form in ("text", "sha256") and words & GUID_WORDS and (
            words & {"byte", "bytes", "memory", "raw", "le"} or re.search(r"\b32\b.*hex|hex.*\b32\b", syn)):
        import uuid
        for mi, name, depth, how, text in _texts(env, members, 3, 30):
            for i, m in enumerate(GUID_RX.finditer(text[:400000])):
                if i >= 6:
                    break
                g = uuid.UUID(m.group(1))
                up = "upper" in syn and "lower" not in syn
                for j, (h2, raw) in enumerate((("guid_as_bytes:mixed_endian", g.bytes_le), ("guid_as_bytes:big_endian", g.bytes))):
                    hx = raw.hex()
                    pool.add(h2, hx.upper() if up else hx, 24 - 1.0 * j - mi - 0.3 * i)
                    pool.add(h2 + ":case", hx.lower() if up else hx.upper(), 20 - 1.0 * j - mi - 0.3 * i)


# ------------------------------------------------------------------------------------------------- (a) aliases

ALIAS_GROUPS = [
    {"mac", "macaddr", "hwaddr", "hw", "ether", "ethernet", "lladdr", "phys", "physical", "bssid", "hardware"},
    {"host", "hostname", "server", "srv", "node", "fqdn", "peer", "endpoint", "c2", "cnc", "remote", "gateway", "relay"},
    {"user", "username", "account", "acct", "login", "principal", "owner", "runas", "uid", "logon", "operator"},
    {"password", "pass", "pwd", "passwd", "secret", "credential", "credentials"},
    {"ip", "ipv4", "ipaddr", "addr"},
    {"agent", "useragent", "ua"},
    {"email", "mail", "sender", "recipient", "from"},
    {"version", "ver", "release", "build"},
    {"interval", "sleep", "delay", "period", "beacon"},
]


GENERIC_HEADS = {"address", "addr", "name", "value", "id", "string", "text"}


def alias_set(spec):
    """The alias words of the asked field's head noun (its last word, and the word before a generic one such as
    `address`: mac_address -> mac; build_timestamp has no alias), minus the field's own words."""
    ft = [stem(w) for w in spec.field_toks]
    if not ft:
        return set()
    head = {ft[-1]} | ({ft[-2]} if len(ft) > 1 and ft[-1] in GENERIC_HEADS else set())
    out = set()
    for g in ALIAS_GROUPS:
        if head & g:
            out |= g
    return out - set(ft)


def expert_alias_kv(spec, env, pool, members, recs):
    """(a): a value stored under a key that shares no word with the asked field but is a known alias of it
    (`hw` for a MAC, `server` for a hostname, `account` for a username); ranked below a key that names the field."""
    if spec.form not in ("text", "int", "guid", "json"):
        return
    al = alias_set(spec)
    if not al:
        return
    ft = {stem(w) for w in spec.field_toks}

    def hit(k):
        kt = {stem(x) for x in E.toks(k.split(".")[-1])}
        return bool(kt & al) and not (kt & ft)

    for mi, name, depth, how, text in _texts(env, members, 3, 40):
        for k, v in E.kv_pairs(text) + line_kv(text):
            if (isinstance(v, str) and 0 < len(v) <= 300 or isinstance(v, int) and not isinstance(v, bool)) and hit(k):
                leaf_ns = E.key_score(k, spec) if "." in k else 0.0
                pool.add(f"alias:{k}", v, max(21.5, 23.0 + leaf_ns) - mi + 0.2 * depth)
    for name, rs in (recs or {}).items():
        for r in rs:
            for lh, txt in payload_texts(r):
                for k, v in E.kv_pairs(txt):
                    if (isinstance(v, str) and 0 < len(v) <= 300 or isinstance(v, int) and not isinstance(v, bool)) and hit(k):
                        pool.add(f"alias:record:{r['magic']}:{k}", v, 24)


# ------------------------------------------------------------------------------------------------- (a) fingerprints

FP_WORDS = {"fingerprint", "thumbprint", "fp", "fingerprints", "thumbprints"}
PEM_RX = _Rx(r"-----BEGIN ([A-Z0-9 ]+)-----\s*([A-Za-z0-9+/=\s]+?)-----END \1-----")
SSH_RX = _Rx(r"\b(ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com)\s+(AAAA[A-Za-z0-9+/]+={0,2})")


def key_blobs(b):
    """[(kind, der-or-blob bytes)] a member holds: PEM blocks (certificate, public key), OpenSSH public keys, and the
    member itself when it is DER (a SEQUENCE with a long length)."""
    out = []
    if b[:2] == b"\x30\x82" and 4 + int.from_bytes(b[2:4], "big") <= len(b) + 2:
        out.append(("der", b[:4 + int.from_bytes(b[2:4], "big")]))
    t = b[:2000000].decode("latin-1")
    for m in PEM_RX.finditer(t):
        try:
            out.append(("pem_" + m.group(1).lower().replace(" ", "_"), base64.b64decode(re.sub(r"\s+", "", m.group(2)))))
        except (binascii.Error, ValueError):
            continue
    for m in SSH_RX.finditer(t):
        try:
            out.append(("ssh", base64.b64decode(m.group(2))))
        except (binascii.Error, ValueError):
            continue
    return out[:8]


def expert_fingerprints(spec, env, pool, members):
    """(a): a certificate's or key's fingerprint, the digest the question NAMES first (sha1 / sha256 / md5; a bare
    `thumbprint` sha1 then sha256), in the stated rendering; a stated fingerprint of another algorithm sinks."""
    words = set(spec.field_toks) | set(spec.noun_toks)
    low = spec.low
    algos = [a for a in ("sha256", "sha1", "md5", "sha512", "sha384") if a in words or a in low.replace("-", "")]
    if not (words & FP_WORDS) and not (algos and words & {"certificate", "cert", "key", "pubkey", "public", "x509", "ssh"}):
        return
    order = algos or ["sha1", "sha256", "md5"]
    syn = spec.syntax.lower()
    forms = stated_forms(spec)
    lens = {"md5": 32, "sha1": 40, "sha256": 64, "sha384": 96, "sha512": 128}
    for mi, name in enumerate(members[:3]):
        for bi, (kind, blob) in enumerate(key_blobs(env.member_bytes(name) or b"")):
            for ai, algo in enumerate(order[:3]):
                d = hashlib.new(algo, blob)
                hx = d.hexdigest()
                sc = 30 - 3.0 * ai - 1.0 * mi - 0.5 * bi
                if kind == "ssh":
                    b64 = base64.b64encode(d.digest()).decode().rstrip("=")
                    first = [(f"ssh_{algo}_openssh", f"{algo.upper()}:{b64}" if algo != "md5" else "MD5:" + ":".join(hx[i:i + 2] for i in range(0, len(hx), 2)))]
                    first.append((f"ssh_{algo}_b64", b64))
                    for j, (h2, v) in enumerate(first):
                        pool.add(f"fingerprint:{h2}", v, sc - 1.0 * j)
                pairs = [hx[i:i + 2] for i in range(0, len(hx), 2)]
                rend = [("bare", hx), ("colon_upper", ":".join(pairs).upper()), ("colon_lower", ":".join(pairs)),
                        ("bare_upper", hx.upper())]
                st = apply_stated(hx if not ({"colon", "dash"} & forms) else ":".join(pairs), forms)
                if "colon" in syn and "upper" in syn:
                    st = ":".join(pairs).upper()
                rend = [("stated", st)] + [r for r in rend if r[1] != st]
                for j, (h2, v) in enumerate(rend):
                    pool.add(f"fingerprint:{kind}:{algo}:{h2}", v, sc - (0 if j == 0 else 1.5 + 0.3 * j) - (1 if kind == "ssh" else 0))
    if algos:
        want = {lens[a] for a in algos if a in lens}
        for r in pool.items.values():
            if r[1].startswith("fingerprint:"):
                continue
            n = len(re.sub(r"[^0-9A-Fa-f]", "", r[2]))
            if re.fullmatch(r"[0-9A-Fa-f:\s-]{32,200}", r[2]) and n in lens.values() and n not in want:
                r[0] -= 8.0      # a digest of another algorithm (the stated SHA-1 when SHA-256 is asked)


# ------------------------------------------------------------------------------------------------- (b) extents

def pe_overlay(b):
    """(start, size) of a PE's overlay: the end of the last section's raw data to the end of the file."""
    try:
        if b[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", b, 0x3c)[0]
        if b[pe:pe + 4] != b"PE\x00\x00":
            return None
        nsec, = struct.unpack_from("<H", b, pe + 6)
        optsz, = struct.unpack_from("<H", b, pe + 20)
        st = pe + 24 + optsz
        end = 0
        for i in range(min(nsec, 96)):
            rawsize, rawptr = struct.unpack_from("<II", b, st + 40 * i + 16)
            if rawsize:
                end = max(end, rawptr + rawsize)
        if end == 0 or end > len(b):
            return None
        return end, len(b) - end
    except (struct.error, IndexError):
        return None


def wasm_customs(b):
    """[{name, offset (its id byte), content (after the size), name_at, payload_at, payload_size, size}] of a wasm."""
    if b[:4] != b"\x00asm":
        return []

    def uleb(p):
        r, s = 0, 0
        while True:
            c = b[p]
            p += 1
            r |= (c & 0x7f) << s
            s += 7
            if c < 0x80:
                return r, p
    out, pos = [], 8
    try:
        while pos < len(b) and len(out) < 64:
            sid = b[pos]
            ln, p = uleb(pos + 1)
            if sid == 0:
                nl, q = uleb(p)
                out.append({"name": b[q:q + nl].decode("utf-8", "replace"), "offset": pos, "content": p, "name_at": q,
                            "payload_at": q + nl, "payload_size": ln - (q + nl - p), "size": ln})
            pos = p + ln
    except IndexError:
        pass
    return out


def expert_extents(spec, env, pool, members):
    """(b): the PE overlay's start and size, and a wasm custom section's offsets and sizes, as facts."""
    words = set(spec.field_toks) | set(spec.noun_toks)
    low = spec.low
    if spec.form not in ("int", "int_or_none", "hex0x", "text"):
        return
    want_pos = bool(words & (POSITION_WORDS | {"begin", "begins", "starts"}))
    want_size = bool(words & {"size", "length", "len", "bytes"}) and not (want_pos and "size" not in words and "length" not in words)
    ft = set(spec.field_toks)
    if not (want_pos or want_size) or (ft & {"count", "number", "name", "names"} and not ft & (POSITION_WORDS | {"size", "length", "bytes"})):
        return            # a count or a name is not an extent
    for mi, name in enumerate(members[:4]):
        b = env.member_bytes(name) or b""
        if words & {"overlay", "appended", "trailing", "tail"} or re.search(r"after the (?:last )?(?:pe )?sections?|appended data|overlay", low):
            ov = pe_overlay(b[:SCAN_MAX * 4])
            if ov and ov[1] > 0:
                start, size = ov
                pool.add("extent:pe_overlay_start", start, 30 - mi + (4 if want_pos and not want_size else -2 if want_size else 0))
                pool.add("extent:pe_overlay_size", size, 30 - mi + (4 if want_size and not want_pos else -2 if want_pos else 0))
        if b[:4] == b"\x00asm" and ("custom" in words or "custom" in low):
            secs = wasm_customs(b)
            if not secs:
                continue
            named = [s for s in secs if re.search(r"(?<![\w.-])" + re.escape(s["name"]) + r"(?![\w-])", spec.text)]
            for si, s in enumerate(named or secs[-1:]):
                base = 30 - mi - si
                if want_pos:
                    idb = bool(re.search(r"\bid byte|section id|header|begin|starts?\b", low))
                    for j, (how, v, adj) in enumerate((("offset", s["offset"], 2 if idb else 0),
                                                      ("payload_offset", s["payload_at"], 3 if "payload" in words or "data" in words else -1),
                                                      ("content_offset", s["content"], -1.5), ("name_offset", s["name_at"], -2))):
                        pool.add(f"extent:wasm_custom:{how}", v, base + adj - 0.2 * j)
                if want_size:
                    after_name = bool(re.search(r"after (?:its|the) name|payload|data", low))
                    for j, (how, v, adj) in enumerate((("payload_size", s["payload_size"], 2 if after_name else -0.5),
                                                      ("section_size", s["size"], 0 if after_name else 1.5),
                                                      ("total_size", s["size"] + (s["content"] - s["offset"]), -2))):
                        pool.add(f"extent:wasm_custom:{how}", v, base + adj - 0.2 * j)


# ------------------------------------------------------------------------------------------------- (e) zip comments

def zip_comments(b, path=(), depth=0, out=None):
    """[(chain of archive names, member or None, comment)] of a zip and, recursively, every zip it holds."""
    import zipfile
    import io as _io
    out = [] if out is None else out
    if depth > 3 or b[:2] != b"PK" or len(out) > 200:
        return out
    try:
        z = zipfile.ZipFile(_io.BytesIO(b))
    except Exception:
        return out
    if z.comment:
        out.append((path, None, z.comment.decode("utf-8", "replace")))
    for zi in z.infolist()[:200]:
        if zi.comment:
            out.append((path, zi.filename, zi.comment.decode("utf-8", "replace")))
        if zi.filename.lower().endswith((".zip", ".jar", ".apk", ".docx", ".xlsx")) and zi.file_size < (16 << 20):
            try:
                inner = z.read(zi.filename)
            except Exception:
                continue
            zip_comments(inner, path + (zi.filename,), depth + 1, out)
    return out


def expert_zip_comments(spec, env, pool, members):
    """(e): an archive's comment, a member's comment, and both inside nested archives, ranked by the names and
    the words (inner, nested, member) the question uses."""
    words = set(spec.field_toks) | set(spec.noun_toks)
    if not ({"comment", "comments"} & words or "comment" in spec.low):
        return
    low = spec.text.lower()
    nested_asked = bool(words & {"inner", "nested", "embedded", "inside", "child"}) or bool(re.search(r"\binner|nested|inside\b", low))
    member_asked = bool(words & {"member", "entry", "file"}) and "member" in " ".join(spec.field_toks + [low])
    for mi, name in enumerate(members[:3]):
        b = env.member_bytes(name) or b""
        for ci, (chain, member, comment) in enumerate(zip_comments(b)[:60]):
            sc = 26 - mi - 0.1 * ci
            named = [n for n in chain + ((member,) if member else ()) if n and Path(n).name.lower() in low]
            sc += 4.0 * len(named)
            if chain and chain[-1] and Path(chain[-1]).name.lower() in low and not member:
                sc += 2.0          # the archive the question names, its own comment
            if member and Path(member).name.lower() in low:
                sc += 2.0
            sc += (3.0 if chain else -3.0) if nested_asked else (-2.0 * len(chain))
            sc += (2.5 if member else -2.5) if member_asked else (-1.5 if member else 1.0)
            pool.add(f"zip_comment:{'/'.join(chain) or 'archive'}:{member or 'archive'}"[:70], comment, sc)


# ----------------------------------------------------------------------------------------- relation groups

RELATION_GROUP_RX = _Rx(r"(?:relation[._-])?(?:identical[._-])?(sha256|sha1|md5|crc32)[._-]groups?")
RELATION_MAX_MEMBERS = 4096
RELATION_MAX_MEMBER = 32 << 20
RELATION_MAX_TOTAL = 64 << 20


def _relation_group_digest(spec):
    """The digest explicitly named by a ``relation.*_groups`` property, or None.

    This is deliberately question-driven.  A generic mention of SHA-256 elsewhere in the prompt must not turn an
    ordinary metadata question into a cross-member partition guess.
    """
    joined = (spec.field + " " + spec.text).lower()
    m = RELATION_GROUP_RX.search(joined)
    if not m or "group" not in joined or "relation" not in joined:
        return None
    return m.group(1)


def _relation_target(spec, env, members):
    """Return the one zip member the relation question names; ambiguity is no evidence."""
    named = {Path(x).name.lower() for x in re.findall(r"[A-Za-z0-9_.+@-]+\.zip\b", spec.text, re.I)}
    choices = []
    for name in members:
        b = env.member_bytes(name)
        if b is None or not str(name).lower().endswith(".zip"):
            continue
        if named and Path(name).name.lower() not in named:
            continue
        choices.append((name, b))
    if len(choices) == 1:
        return choices[0]
    return None


def _relation_partition(blob, digest):
    """Read one flat zip and return its duplicate-content groups.

    The reader is intentionally stricter than a general archive walker: duplicate names, encryption, an excessive
    member/byte budget, a bad CRC/local body, or an unsupported digest refuses the entire reading.  The proposer can
    then fall back to its other evidence without manufacturing a partition.
    """
    if not blob.startswith(b"PK") or len(blob) > RELATION_MAX_TOTAL:
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            infos = [zi for zi in z.infolist() if not zi.is_dir()]
            names = [zi.filename for zi in infos]
            if (not infos or len(infos) > RELATION_MAX_MEMBERS or len(names) != len(set(names))
                    or any(zi.flag_bits & 1 or zi.file_size > RELATION_MAX_MEMBER for zi in infos)
                    or sum(zi.file_size for zi in infos) > RELATION_MAX_TOTAL):
                return None
            groups = {}
            for pos, zi in enumerate(infos):
                body = z.read(zi)             # ZipFile checks the member CRC while reading
                if digest == "crc32":
                    key = f"{zlib.crc32(body) & 0xffffffff:08x}"
                elif digest in ("md5", "sha1", "sha256"):
                    key = hashlib.new(digest, body).hexdigest()
                else:
                    return None
                groups.setdefault(key, []).append((pos, zi.filename))
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, zlib.error):
        return None
    return [(key, rows) for key, rows in groups.items() if len(rows) >= 2]


def expert_relation_groups(spec, env, pool, members):
    """Candidate-only renderings of a byte-proven cross-member digest partition.

    The production proposer wraps every value from this module in ``labels.candidates``.  Even the first rendering is
    therefore probed alone on a no-deadline attempt; no author-chosen JSON vocabulary becomes a plain answer here.
    """
    if not spec.lane.startswith("metadata") or spec.form != "json":
        return
    digest = _relation_group_digest(spec)
    target = _relation_target(spec, env, members) if digest else None
    if target is None:
        return
    name, blob = target
    partition = _relation_partition(blob, digest)
    if not partition:
        return

    # Archive order and digest values are byte facts.  Stems/basenames/paths and their ordering are author vocabulary,
    # so all are separate candidates.  Avoid a stem rendering when it would erase a distinction.
    rows_first = [[path for _, path in rows] for _, rows in partition]
    all_paths = [p for group in rows_first for p in group]
    stems = [Path(p).stem for p in all_paths]
    stem_unique = len(stems) == len(set(stems))

    if stem_unique:
        stem_sorted = [sorted(Path(p).stem for p in group) for group in rows_first]
        stem_sorted.sort(key=lambda group: tuple(group))
        pool.add(f"relation:{digest}:stems_sorted_groups_by_first", json.dumps(stem_sorted, separators=(",", ":")),
                 46, prov=f"member {name} > zip central directory > {digest} partition > stems recursively sorted")
        stem_first = [[Path(p).stem for p in group] for group in rows_first]
        pool.add(f"relation:{digest}:stems_first_seen", json.dumps(stem_first, separators=(",", ":")), 44,
                 prov=f"member {name} > zip central directory > {digest} partition > stems in archive order")

    base_sorted = [sorted(Path(p).name for p in group) for group in rows_first]
    base_sorted.sort(key=lambda group: tuple(group))
    path_sorted = [sorted(group) for group in rows_first]
    path_sorted.sort(key=lambda group: tuple(group))
    pool.add(f"relation:{digest}:basenames_sorted", json.dumps(base_sorted, separators=(",", ":")), 42,
             prov=f"member {name} > zip central directory > {digest} partition > basenames sorted")
    pool.add(f"relation:{digest}:paths_sorted", json.dumps(path_sorted, separators=(",", ":")), 41,
             prov=f"member {name} > zip central directory > {digest} partition > paths sorted")

    objects = [{"digest": key, "members": sorted(path for _, path in rows)} for key, rows in partition]
    objects.sort(key=lambda row: tuple(row["members"]))
    pool.add(f"relation:{digest}:objects_members", json.dumps(objects, separators=(",", ":")), 38,
             prov=f"member {name} > zip central directory > {digest} partition > digest/member objects")


def prune_relation_group_noise(spec, pool):
    """A ``*_groups`` answer is a partition, never an enumerator's bare list of digest literals."""
    digest = _relation_group_digest(spec)
    if not digest:
        return
    lengths = {"md5": 32, "sha1": 40, "sha256": 64, "crc32": 8}
    rx = re.compile(rf"[0-9a-fA-F]{{{lengths[digest]}}}")
    for key, row in list(pool.items.items()):
        try:
            value = json.loads(row[2])
        except (TypeError, ValueError):
            continue
        if isinstance(value, list) and value and all(isinstance(v, str) and rx.fullmatch(v) for v in value):
            del pool.items[key]


# ------------------------------------------------------------------------------------------------- (e) mobile

ANS_KEY_WORDS = {"answer", "code", "result", "backend", "response", "ans", "token", "contract"}
ANS_MEMBERS_MAX = 26   # the score of a code read inside a record, the most expert_ans_members gives


def expert_ans_members(spec, env, pool, members):
    """(e): an `ANS-` code inside any member under res/raw or assets, read by the decoders and the record scan."""
    if spec.form != "ans":
        return
    # only when the earlier candidates come up short: 26 is the most this scan gives (a record's code), and a tie
    # keeps the earlier candidate first, so above it the scan could not move rank 1 (and it costs every Mobile set)
    if max((r[0] for r in pool.items.values()), default=0) >= ANS_MEMBERS_MAX:
        return
    names = [k for k in env.plain_members() if re.search(r"(?:^|/)(?:res/raw|assets)/", k)][:60]
    for name in names:
        if env.time_left() <= 0:
            return
        b = env.member_bytes(name) or b""
        if len(b) > 4 << 20:
            continue
        texty = E.printable_ratio(b[:1024]) > 0.85
        for depth, how, text in (env.decoded(name).texts[:80] if texty else []):
            for m in E.ANS_RE.finditer(text):
                # a code stated as it is stored is often the encoded one (the enumerator scores it 20); one a decoder
                # reached is the stronger reading
                pool.add(f"ans_member:{how}"[:60], m.group().upper(), (23 + 0.3 * min(depth, 3)) if depth else 19)
            for k, v in E.kv_pairs(text):
                if isinstance(v, str) and re.fullmatch(r"[0-9A-Fa-f]{16}", v.strip()) and set(E.toks(k)) & ANS_KEY_WORDS:
                    pool.add(f"ans_member:kv:{k}", "ANS-" + v.strip().upper(), 21)
        for r in ([] if texty else records_in(env, name, env.deadline - E.MARGIN)):
            for lh, txt in payload_texts(r):
                for m in E.ANS_RE.finditer(txt):
                    pool.add(f"ans_member:record:{r['magic']}:{lh}", m.group().upper(), ANS_MEMBERS_MAX)


# ------------------------------------------------------------------------------------------------- (e) keyboard

KB_MODELS = {"letters_digits": ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"],
             "full_rows": ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"],
             "letters": ["qwertyuiop", "asdfghjkl", "zxcvbnm"]}


def kb_decodes(text):
    """[(how, text)]: the text shifted back along keyboard rows (every model, one or two keys, wrapping or not)."""
    out = []
    for nm, rows in KB_MODELS.items():
        for d in (1, -1, 2, -2):
            for wrap in (True, False):
                m = {}
                for row in rows:
                    n = len(row)
                    for i, c in enumerate(row):
                        j = i - d
                        if not wrap and not 0 <= j < n:
                            continue
                        m[c] = row[j % n]
                        if c.isalpha():
                            m[c.upper()] = row[j % n].upper()
                out.append((f"kb_{nm}_{'right' if d > 0 else 'left'}{abs(d)}{'' if wrap else '_nowrap'}",
                            "".join(m.get(c, c) for c in text)))
    return out


# ------------------------------------------------------------------------------------------------- (d) script

CODEC_LABEL_RX = _Rx(r"(?i)(?:codec\w*[\"']?\s*[:=]\s*[\"']?|HUNTRESS-CODEC:)([a-z][a-z0-9_]*(?:\|[a-z0-9_]*){0,3})")
MATERIAL_RX = _Rx(r"(?i)(?:\bmaterial\w*[\"']?\s*[:=]+\s*|HUNTRESS-MATERIAL:)")
TRANSFORMS = ("identity", "single_byte_xor", "repeating_key_xor", "add_modulo_256", "subtract_modulo_256", "reverse_bytes",
              "rolling_xor", "reverse_then_xor", "rotate_left", "rotate_right")


def _material_spans(text):
    """The text a stated material holds: the value after `Material... =` / `MATERIAL:` up to the next statement."""
    out = []
    for m in MATERIAL_RX.finditer(text[:400000]):
        s = m.end()
        rest = text[s:s + 60000]
        line = rest.split("\n", 1)[0]
        out.append(line)                     # a one-line statement
        stop = re.search(r"\n(?=[^\s\"'+&.)\],\\])", rest)
        more = rest[:stop.start()] if stop else rest
        if more.strip() != line.strip() and len(more) < 20000:
            out.append(more)                 # continued over lines (Python's parenthesised chunks, `& _`)
        if len(out) >= 6:
            break
    return out


def _material_bytes(span):
    """[(representation, bytes)] read from a material span every generic way: base64 of its joined literals, hex
    pairs, decimal numbers (each order), the text itself and reversed."""
    lits = [a or b or c for a, b, c in E.LIT_RE.findall(span)]
    joined = "".join(lits) if lits else span.strip().strip(";").strip()
    out = []
    j2 = re.sub(r"\s+", "", joined)
    if len(j2) >= 8 and re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", j2):
        b = _b64dec(j2.encode())
        if b:
            out.append(("base64", b))
    body = span if not lits or all(re.fullmatch(r"[0-9A-Fa-f]{2}", x) for x in lits) else joined
    hx = re.sub(r"\\x|\\u00|0x|%|\\\\", " ", body)
    if re.fullmatch(r"[\s0-9A-Fa-f:,;\-\[\]\"'()|.\\_]+", hx) and re.search(r"[A-Fa-f]", hx + "a"):
        pairs = re.findall(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{2})(?![0-9A-Fa-f])", hx)
        if len(pairs) < 8:
            run = re.sub(r"[^0-9A-Fa-f]", "", hx)
            pairs = [run[i:i + 2] for i in range(0, len(run) // 2 * 2, 2)]
        if len(pairs) >= 8:
            out.append(("hex", bytes(int(p, 16) for p in pairs)))
    nums = re.findall(r"(?<![\w.])\d{1,3}(?![\w.])", body)
    if len(nums) >= 8 and all(int(n) < 256 for n in nums) and len("".join(nums)) >= 0.5 * len(re.sub(r"[\s,;:\-\[\]()\"'|]", "", body) or "x"):
        bs = bytes(int(n) for n in nums)
        out.append(("decimal", bs))
        out.append(("decimal_reversed", bs[::-1]))
    if joined and E.printable_ratio(joined.encode("latin-1", "replace")) > 0.95:
        out.append(("text", joined.encode("latin-1", "replace")))
        out.append(("text_reversed", joined[::-1].encode("latin-1", "replace")))
    return out[:8]


_ADD_TABLES = []


def add_table(k):
    """The add-k byte table (built on first use: only a stated add/subtract codec needs them)."""
    if not _ADD_TABLES:
        _ADD_TABLES.extend(bytes(range(k_, 256)) + bytes(range(0, k_)) for k_ in range(256))
    return _ADD_TABLES[k & 0xff]


ROT_TABLES = {f"rotl{r}": bytes(((c << r) | (c >> (8 - r))) & 0xff for c in range(256)) for r in range(1, 8)}
_NONPRINT_B = bytes(c for c in range(256) if not (32 <= c < 127 or c in (9, 10, 13)))


def _head_ok(x):
    h = x[:48]
    return len(h.translate(None, _NONPRINT_B)) >= len(h) - 1


def _table_variants(b, tables):
    """(how, bytes) of the single-byte tables that keep the first 48 bytes printable (a C-speed screen first)."""
    h = b[:48]
    for how, tb in tables:
        if len(h.translate(tb).translate(None, _NONPRINT_B)) >= len(h) - 1:
            yield how, b.translate(tb)


def _transform_variants(b, transform, keyb):
    """(how, bytes) of one stated transform (every reading of its direction); an unnamed or unknown transform gets
    the identity, the reversal and the enumerator's own single-byte screen."""
    t = (transform or "").lower()
    ks = list(keyb) or []
    m = re.search(r"(\d+)$", t)
    if m and not ks:
        ks = [int(m.group(1)) & 0xff]
    known = any(t.startswith(x.split("_")[0]) for x in TRANSFORMS) or re.match(r"(?:add|sub|xor|rot|rev|rol)", t)
    if not known or t in ("", "identity", "none", "plain"):
        yield "identity", b
        yield "reverse", b[::-1]
        if not known:
            for src, bb in (("", b), ("rev>", b[::-1])):
                for how, x in E._single_xor(bb):
                    yield src + how, x
        return
    if t.startswith("reverse") and "xor" not in t:
        yield "reverse", b[::-1]
    if "xor" in t and "rolling" not in t and "repeating" not in t:
        tables = [(f"xor{k:02x}", XOR_TABLES[k]) for k in (ks[:1] or range(1, 256))]
        if t.startswith("reverse"):
            yield from ((h + "_reversed", x[::-1]) for h, x in _table_variants(b, tables))
            yield from ((h + "_after_reverse", x) for h, x in _table_variants(b[::-1], tables))
        else:
            yield from _table_variants(b, tables)
    if "repeating" in t and ks:
        yield "repeating_xor", bytes(c ^ ks[i % len(ks)] for i, c in enumerate(b))
    if t.startswith(("add", "sub")):
        tables = []
        for k in (ks[:1] or range(1, 256)):
            tables += [(f"minus{k:02x}", add_table(256 - k)), (f"plus{k:02x}", add_table(k))]
        yield from _table_variants(b, tables)
    if "rolling" in t:
        for k in ks[:1] or [0]:
            yield "rolling_index", bytes(c ^ ((k + i) & 0xff) for i, c in enumerate(b))
            yield "rolling_index_k", bytes(c ^ k ^ (i & 0xff) for i, c in enumerate(b))
            prev, x = k, bytearray()
            for c in b:
                x.append(c ^ prev)
                prev = c
            yield "rolling_cipher_feedback", bytes(x)
            prev, x = k, bytearray()
            for c in b:
                prev = c ^ prev
                x.append(prev)
            yield "rolling_plain_feedback", bytes(x)
    if t.startswith("rot"):
        yield from _table_variants(b, list(ROT_TABLES.items()))


def stated_codec_texts(text):
    """[(how, text)]: a stated material decoded by its stated codec label (`repr|transform|key`), each reading of the
    label tried; kept only when it reads as a key=value record."""
    labels = [m.group(1) for m in CODEC_LABEL_RX.finditer(text[:400000])][:4]
    spans = _material_spans(text)
    if not spans:
        return []
    out, seen = [], set()
    for lab in labels or ["|"]:
        parts = lab.split("|")
        transform = parts[1] if len(parts) > 1 else ""
        keyb = b""
        for p in parts[2:]:
            h = re.sub(r"[^0-9a-fA-F]", "", p)
            if h and len(h) % 2 == 0:
                keyb += bytes.fromhex(h)
        for span in spans:
            for rep, b in _material_bytes(span):
                for how, x in _transform_variants(b, transform, keyb):
                    if len(out) > 40:
                        return out
                    if len(x) < 8 or not _head_ok(x) or x in seen:
                        continue
                    seen.add(x)
                    if E.printable_ratio(x[:2048]) < 0.97:
                        continue
                    s = x.decode("latin-1")
                    if len(E.KEYISH_RE.findall(s[:4000])) >= 2 or ("=" in s and "|" in s):
                        out.append((f"stated_codec:{parts[0]}|{transform}:{rep}>{how}", s))
    return out


NUM_ARRAY_RX = _Rx(r"(?<![\w.])(?:\d{1,3}[ \t]+){7,}\d{1,3}(?![\w.])")
QHEX_ARRAY_RX = _Rx(r"(?:\\?[\"']([0-9a-fA-F]{2})\\?[\"']\s*,\s*){7,}\\?[\"'][0-9a-fA-F]{2}\\?[\"']")


def augment_script_texts(env, members):
    """(d): texts the enumerator's decoders did not reach, added to the member's decoded pool before its experts
    run: a material under its stated codec label, a space-separated decimal array and a quoted hex-byte array."""
    for name in members[:2]:
        ck = ("fam_aug", name)
        if ck in env._facts:
            continue
        env._facts[ck] = True
        b = env.member_bytes(name) or b""
        if not b or len(b) > 2 << 20 or E.printable_ratio(b[:4096]) < 0.9:
            continue
        dec = env.decoded(name)
        text = dec.texts[0][2] if dec.texts else ""
        got = stated_codec_texts(text)
        for how, s in got:
            h = hash(s)
            if h not in dec.seen and len(dec.texts) < E.MAX_DECODES:
                dec.seen.add(h)
                dec.texts.append((1, how, s))     # a key=value record already: nothing under it to walk
        if got:
            continue
        for m in list(NUM_ARRAY_RX.finditer(text[:400000]))[:20]:
            vals = [int(x) for x in m.group().split()]
            if all(v < 256 for v in vals):
                dec._try_bytes(0, "fam_decimal_space", bytes(vals))
        for m in list(QHEX_ARRAY_RX.finditer(text[:400000]))[:20]:
            dec._try_bytes(0, "fam_quoted_hex", bytes(int(x, 16) for x in re.findall(r"[\"']([0-9a-fA-F]{2})\\?[\"']", m.group())))


SEED_DIRS = {"script": "script-analysis", "binary": "binary", "metadata": "metadata-forensics", "mobile": "mobile-android",
             "warmups": "warmups"}
_SEEDS = {}
SOLVERS_DIR = Path(__file__).resolve().parents[1]


def judged_keys(prefix, ctx):
    """{key: (accepted names, rejected names)} of a lane: the tracked seed and the ledger, cut to the morning when the
    caller replays one (a seed name the ledger first judged after the cut is left out)."""
    before_t = ctx.get("ledger_before")
    hit = _SEEDS.get((prefix, before_t))
    if hit is not None and time.time() - hit[0] < 30:
        return hit[1]          # read again at most every 30 s (the ledger grows during a morning)
    p = SOLVERS_DIR / SEED_DIRS.get(prefix, prefix) / "conventions.json"
    out = {}
    try:
        seed = json.loads(p.read_text())
    except (OSError, ValueError):
        seed = {}
    rows = _ledger_rows(prefix)
    late = set()
    if before_t:
        early = {(str(r["key"]), str(r["name"])) for r in rows if str(r.get("t", "")) < before_t}
        late = {(str(r["key"]), str(r["name"])) for r in rows if str(r.get("t", "")) >= before_t} - early
    for k, st in (seed.items() if isinstance(seed, dict) else []):
        if not isinstance(st, dict) or k.endswith("#candidates"):
            continue
        acc = [st["accepted"]] if isinstance(st.get("accepted"), str) and (k, st["accepted"]) not in late else []
        out[k] = (acc, [x for x in st.get("rejected") or [] if isinstance(x, str) and (k, x) not in late])
    for r in rows:
        if before_t and str(r.get("t", "")) >= before_t:
            continue
        k = str(r["key"])
        if k.endswith("#candidates"):
            continue
        acc, rej = out.setdefault(k, ([], []))
        if r.get("verdict") == "accepted" and r["name"] not in acc:
            acc.append(str(r["name"]))
        elif r.get("verdict") == "rejected" and r.get("scope") == "key" and r["name"] not in rej:
            rej.append(str(r["name"]))
    if len(_SEEDS) > 16:
        _SEEDS.clear()
    _SEEDS[(prefix, before_t)] = (time.time(), out)
    return out


_FIELD_KEYS = {}


def judged_field(prefix, field, ctx, with_rejected=False):
    """[(mid, shape or None, accepted names[, rejected names])] of a lane's judged keys `<prefix>.<field>/<mid>[.<shape>]`
    with an accepted name, parsed once per morning cut."""
    keys = judged_keys(prefix, ctx)
    ck = (prefix, field, ctx.get("ledger_before"), with_rejected)
    hit = _FIELD_KEYS.get(ck)
    if hit is None or hit[0] is not keys:
        rx = re.compile(re.escape(prefix) + r"\." + re.escape(field) + r"/([a-z0-9]+)(?:\.(.+))?")
        out = []
        for k, (acc, rej) in keys.items():
            m = rx.fullmatch(k)
            if m and acc:
                out.append((m.group(1), m.group(2), acc, rej) if with_rejected else (m.group(1), m.group(2), acc))
        if len(_FIELD_KEYS) > 64:
            _FIELD_KEYS.clear()
        hit = _FIELD_KEYS[ck] = (keys, out)
    return hit[1]


LANG_GROUPS = [{"js", "mjs", "jse", "cjs", "ts"}, {"bat", "cmd", "batch"}, {"vbs", "vbe", "vbscript"}, {"py", "pyc", "python"},
               {"sh", "bash", "zsh"}, {"ps1", "psm1", "powershell"}]


def _same_lang(mid, ext):
    if mid == ext:
        return True
    return any(mid in g and ext in g for g in LANG_GROUPS)


IGNORE_GENERIC = {"labels", "label", "lines", "line", "commands", "command", "ordinary", "outside", "wrapper", "statement",
                  "statements", "that", "which", "may", "use", "different", "form", "expansion", "control", "flow",
                  "output", "echo", "the", "and", "only", "inert"}


_IGNORE = {}


def ignore_words(text):
    """The words of the question's own `Ignore ...` sentences (separator, noise, envelope, ...): what they name is
    noise, whatever the bytes call it."""
    if text in _IGNORE:
        return _IGNORE[text]
    if len(_IGNORE) > 512:
        _IGNORE.clear()
    out = _IGNORE[text] = set()
    for m in re.finditer(r"(?i)\bignore\b([^.]{0,300})", text):
        out |= {w for w in E.toks(m.group(1)) if len(w) >= 4 and w not in IGNORE_GENERIC}
    return out


def statement_focus(text, noise=frozenset()):
    """The statement that puts the most earlier-assigned values together (counting an indirect reference such as
    `FrAg%%G` to the assigned FrAg0..FrAg3 as all of them), its head keyword, and the control line that wraps it
    (a jump to its label whose name the question does not call noise, a guard, a loop; a plain assignment is none)."""
    lines = text.replace("\r", "").split("\n")
    assigned = []
    best, bi = 0, None
    for i, ln in enumerate(lines):
        refs = {(a or b).lower() for a, b in re.findall(r"[%!]+([A-Za-z_]\w*)(?=[%!:])|\$\{?([A-Za-z_]\w*)", ln)}
        aset = set(assigned)
        names = refs & aset
        for r in refs - aset:
            grp = [a for a in aset if a.startswith(r) and re.fullmatch(r"_?\d{1,2}", a[len(r):])]
            if len(grp) >= 2:
                names |= set(grp)
        if len(names) >= 2 and len(names) > best:
            best, bi = len(names), i
        for m in E.ASSIGN_RE.finditer(ln):
            assigned.append(m.group(1).lower())
    if bi is None:
        return None
    stmt = lines[bi].strip()
    target = None
    mt = re.search(r"(?i)\bset\s+\"?([A-Za-z_]\w*)=", stmt)
    if mt:
        target = mt.group(1).lower()
    head = (re.match(r"(?i)\s*([a-z]+)", stmt) or [None, ""])[1].lower()
    wrap = []

    def noisy(name):
        return bool(set(E.toks(name)) & noise)

    for j in range(bi - 1, max(-1, bi - 6), -1):
        ln = lines[j].strip()
        if not ln or re.match(r"(?i)(rem\b|::|ver\b|echo\b|set\s+\"?neutral)", ln) or ln in ("(", ")"):
            continue
        if target and re.fullmatch(r"(?i)set\s+\"?" + re.escape(target) + r"=\"?", ln):
            continue      # the statement's own initialisation of its target
        if ln.startswith(":"):
            label = ln[1:].split()[0] if ln[1:].split() else ""
            if not label or noisy(label):
                continue
            for k, other in enumerate(lines):
                if k != j and not re.search(r"--inspect|--plan", other) and re.search(r"(?i)\b(goto|call)\s+:?" + re.escape(label) + r"\b", other):
                    wrap.append(other.strip())
            if wrap:
                break
            continue
        if re.match(r"(?i)goto\b", ln):
            continue
        if re.match(r"(?i)(?:set\s|\$?[A-Za-z_]\w*\s*=)", ln) and not re.match(r"(?i)(?:if|for|call|goto|while|do)\b", ln):
            break         # a plain assignment: nothing wraps the statement
        wrap.append(ln)
        break
    return {"stmt": stmt, "head": head, "wrap": wrap, "line": bi}


VAR_REF_RX = _Rx(r"%%~?[A-Za-z_]\w*%%|%[A-Za-z_]\w*%|![A-Za-z_]\w*!")
REF_KIND = {"percent": lambda t: t.startswith("%") and not t.startswith("%%"), "double": lambda t: t.startswith("%%"),
            "delayed": lambda t: t.startswith("!")}


def _has(p, rx, line):
    """A part's surface form on a line. A variable reference is read token by token, left to right, so adjacent
    references (`%a%%b%`) are two percent references, not a `%%b%%` double one."""
    if p in REF_KIND:
        return any(REF_KIND[p](t) for t in VAR_REF_RX.findall(line))
    return bool(re.search(rx, line))


def _part_score(p, focus, wrap, lines):
    rxs = E.VALUE_ALIASES.get(p, [r"(?i)\b" + re.escape(p) + r"\b"])
    if not rxs:
        return None       # a word with no surface form (`guard`, `direct`): it neither helps nor counts against
    best = 0.0
    for rx in rxs[:1] if p in REF_KIND else rxs:
        spec_w = 1.0 + 2.0 / (1 + sum(1 for ln in lines if _has(p, rx, ln)))
        if _has(p, rx, focus):
            best = max(best, 3.0 * spec_w)
        if wrap and _has(p, rx, wrap):
            best = max(best, 2.0 * spec_w)
    return best


def expert_statement_enum(spec, env, pool, members, ctx):
    """(d): an enum about one statement (its control-flow wrapper, its expansion form), ranked from the question's
    own clause tokens read against that statement (indirect references counted, its head keyword weighed, the lines
    the question's `Ignore` sentence names left out) and from the lane's judged label families
    (`<lane>.<field>/<mid>.<feature>` -> name, the feature's words read in the wrapper)."""
    if not spec.accepted or len(spec.accepted) < 3 or not re.search(r"\bstatement\b", spec.text) or not members:
        return
    texts = env.decoded(members[0]).texts
    text = texts[0][2] if texts else ""
    noise = frozenset(ignore_words(spec.text))
    ck = ("fam_focus", members[0], noise)
    if ck not in env._facts:
        env._facts[ck] = (statement_focus(text, noise), E.focus_context(text) is not None)
    f, e_has = env._facts[ck]
    if not f:
        return
    # the enumerator added 3 x its own focus reading; ours replaces it (it reads the question's Ignore sentence, an
    # indirect reference and the statement's own initialisation)
    ek = ("fam_efocus", members[0], tuple(spec.accepted))
    if ek not in env._facts:
        env._facts[ek] = E.focus_scores(spec, text) if e_has else {}
    e_focus = env._facts[ek]
    focus, wrap = f["stmt"], " \n ".join(f["wrap"])
    lines = text.splitlines()
    adj = {}
    for a in spec.accepted:
        parts = E.toks(a)
        got = [x for x in (_part_score(p, focus, wrap, lines) for p in parts) if x is not None]
        if got:
            sc = sum(got) / len(got) * (1.0 if all(got) else 0.4)
            if all(got) and parts[0] == f["head"] and f["head"] != "set":
                sc += 2.0     # the statement's outermost construct names its form (`for ... call set`: the FOR form)
        else:
            sc = 2.5 if not f["wrap"] else 0.0     # `direct`: nothing wraps the statement
        adj[a] = 3.0 * sc - 3.0 * e_focus.get(a, 0.0)
    # judged label families: a feature of the wrapper whose words show there, its accepted name
    prefix = LANE_PREFIX.get(spec.lane, "")
    field = spec.field_toks[-1] if spec.field_toks else ""
    ext = Path(spec.member or members[0]).suffix.lower().lstrip(".")
    if prefix and field:
        wtoks = set(E.toks(wrap))
        best = None
        for mid, st, acc, rej in judged_field(prefix, field, ctx, with_rejected=True):
            if not st or not re.fullmatch(r"[a-z0-9_]+", st) or not _same_lang(mid, ext):
                continue
            feat = st.split("_")
            ok = (not f["wrap"]) if feat == ["none"] else all(t in wtoks for t in feat)
            if ok and (best is None or len(feat) > best[0]):
                best = (len(feat), acc, rej)
        if best:
            for nm in best[1]:
                adj[nm] = adj.get(nm, 0) + 6.0
            for nm in best[2]:
                adj[nm] = adj.get(nm, 0) - 1.0
    for a, d in adj.items():
        r = pool.items.get(pool._key(a))
        if r is not None and d:
            r[0] += d


TERMINAL_RX = _Rx(r"\bending (?:in|with)\b|\bends? (?:in|with)\b|\bterminal\b|\bfinal\b|\blast\b")


def graph_steps_cached(spec, env, members):
    """The enumerator's decoded behavior graph of a question's members, read once per member set."""
    ck = ("fam_steps", tuple(members[:2]))
    if ck not in env._facts:
        env._facts[ck] = E.graph_steps(spec, env, members)
    return env._facts[ck]


def expert_graph_clause_enum(spec, env, pool, members):
    """(d): an enum whose tokens the question defines by step words (`uploader for a graph ending in
    transmit_remote`), each token's own clause read against the decoded behavior graph: the share of its steps
    present, all of them, its terminal step, and its `then` / `followed by` order."""
    if not spec.accepted or len(spec.accepted) < 3 or not re.search(r"\b[a-z]+_[a-z_]+\b", spec.text) \
            or not re.search(r"\bgraph\b|\bsteps?\b|behaviou?r", spec.low):
        return            # only a question about a behavior graph defines its tokens by step words
    steps = graph_steps_cached(spec, env, members)
    if not steps:
        return
    toks_acc = {a.lower() for a in spec.accepted}
    for a in spec.accepted:
        cl = clause_of(spec.text, a, spec.accepted)
        trig = [t for t in re.findall(r"\b[a-z]+_[a-z_]+\b", cl) if t not in toks_acc]
        if not trig:
            continue
        hit = [t for t in trig if t in steps]
        sc = 6.0 * len(hit) / len(trig) + (3.0 if len(hit) == len(trig) else 0.0)
        if TERMINAL_RX.search(cl):
            sc += 4.0 if steps[-1] in trig else -2.0
        m = re.search(r"\b([a-z]+_[a-z_]+)\s+(?:then|followed by)\s+(?:\w+\s+){0,2}?([a-z]+_[a-z_]+)", cl)
        if m and m.group(1) in steps and m.group(2) in steps:
            sc += 2.0 if steps.index(m.group(1)) < steps.index(m.group(2)) else -2.0
        r = pool.items.get(pool._key(a))
        if r is not None and sc:
            r[0] += sc


def expert_attack_judged(spec, env, pool, members, ctx):
    """(d): the lane's judged ATT&CK names for the decoded behavior graph (`script.attack/<ext>.<steps>`), above the
    rubric's own reading, and the language's judged default a little lower."""
    if spec.form != "attack":
        return
    prefix = LANE_PREFIX.get(spec.lane, "")
    if not prefix:
        return
    steps = graph_steps_cached(spec, env, members)
    ext = Path(spec.member or (members[0] if members else "")).suffix.lower().lstrip(".")
    top = max((r[0] for r in pool.items.values()), default=0)
    key_steps = "+".join(steps)
    for mid, st, names in judged_field(prefix, "attack", ctx):
        for nm in names:
            if not re.fullmatch(r"T\d{4}(?:\.\d{3})?|none", nm):
                continue
            if st and steps and st == key_steps:
                pool.add(f"judged_family:attack:{mid}.steps", nm, max(top, 30) + (1.0 if _same_lang(mid, ext) else 0.5))
            elif not st and _same_lang(mid, ext):
                pool.add(f"judged_family:attack:{mid}", nm, 8.5)


# ------------------------------------------------------------------------------------------------- entry

def records_by_member(env, members):
    out = {}
    for name in members[:6]:
        if env.time_left() <= 0:
            break
        rs = records_in(env, name, env.deadline - E.MARGIN)
        if rs:
            out[name] = rs
    return out


def before(spec, env, pool, members, ctx):
    """Called before the enumerator's experts."""
    judged(spec, pool, ctx)
    if spec.lane.startswith("script") or spec.form == "attack" or (spec.accepted and re.search(r"\bstatement\b", spec.text)):
        try:
            augment_script_texts(env, members)
        except Exception as e:   # the augment's failure costs only its texts
            import sys
            print(f"proposer_families: augment on {spec.qid}: {type(e).__name__}: {e}", file=sys.stderr)


def none_floor(spec, pool):
    """(c): an absent field: the literal `none` the syntax names, when no candidate has strong evidence."""
    if re.search(r"literal none|\bnone\b (?:when|if) .{0,40}absent", (spec.syntax + " " + spec.text).lower()):
        top = max((r[0] for r in pool.items.values() if r[2] != "none"), default=0)
        if top < 18:
            pool.add("absent:none_no_evidence", "none", top - 0.5 if top else 10)   # right under the best weak reading


def needs_records(spec, pool):
    """Whether any widening here reads the records: a scan of every member is the costly part, so only then."""
    words = set(spec.field_toks) | set(spec.noun_toks)
    if asks_position(spec):
        return True
    if spec.accepted and len(spec.accepted) > 2 and re.search(r"(?<![\w])\.[a-z_][\w.]{1,20}|base64|webassembly|overlay|literal", spec.low):
        return True
    if not spec.accepted and spec.form == "text" and words & {"storage", "stored", "location", "placement", "carrier",
                                                               "encoding", "layout", "packing", "embedding", "store"}:
        return True
    if any(a in words for a in DIGESTS) and _object_words(spec) & OBJECT_WORDS:
        return True
    if words & {"url", "uri", "link", "endpoint"} and any(w in words for w in URL_PARTS if w != "path") \
            or words & {"tld", "registrable", "apex", "sld", "subdomain"}:
        return True
    if set(spec.field_toks) & (DERIVE_WORDS | {"absent", "missing", "present"}):
        return True
    if spec.form == "guid" or (set(spec.field_toks) & GUID_WORDS and spec.form == "text"):
        return True       # a GUID kept as its in-memory bytes inside a record (round 2)
    if alias_set(spec) and max((r[0] for r in pool.items.values()), default=0) < 30:
        return True       # a value under an alias of the asked field, inside a record (round 2)
    if E.magic_words(spec) and spec.form in ("text", "int", "json") and max((r[0] for r in pool.items.values()), default=0) < 30:
        return True       # the named record's payload holds a base64 or hex layer (round 2)
    if set(spec.field_toks) & {"config", "cfg", "settings"} and re.search(r"\bnone\b", spec.syntax.lower()):
        top = max((r[0] for r in pool.items.values() if r[2] != "none"), default=0)
        if top < 22:     # no pair of the config names the field: it may be absent from the record
            return True
    if not E.magic_words(spec) and spec.form in ("text", "int", "int_or_none", "json"):
        top = max((r[0] for r in pool.items.values()), default=0)
        return top < 30      # nothing strong yet: a record no question names may hold it
    return False


def after(spec, env, pool, members, ctx):
    """Called after the enumerator's experts, before ranking."""
    recs = {}
    binaryish = any((env.member_bytes(m) or b"")[:4] in (b"\x7fELF", b"\x00asm") or (env.member_bytes(m) or b"")[:2] == b"MZ"
                    or (env.member_bytes(m) or b"")[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")
                    for m in members[:6])
    if (binaryish or spec.lane.startswith("binary")) and needs_records(spec, pool):
        recs = records_by_member(env, members)
    steps = [
        ("line_kv", lambda: expert_line_kv(spec, env, pool, members)),
        ("extra_shapes", lambda: expert_extra_shapes(spec, env, pool, members)),
        ("anchors", lambda: expert_anchors(spec, env, pool, members) if recs else None),
        ("unnamed_records", lambda: expert_unnamed_records(spec, env, pool, members, recs) if recs else None),
        ("vocab", lambda: expert_vocab(spec, env, pool, members, recs)),
        ("derived", lambda: expert_derived(spec, env, pool, members, recs)),
        ("slug_extra", lambda: expert_slug_extra(spec, env, pool)),
        ("ans_extra", lambda: expert_ans_extra(spec, env, pool)),
        ("guid_bytes", lambda: expert_guid_bytes(spec, env, pool, members, recs)),
        ("alias_kv", lambda: expert_alias_kv(spec, env, pool, members, recs)),
        ("fingerprints", lambda: expert_fingerprints(spec, env, pool, members)),
        ("extents", lambda: expert_extents(spec, env, pool, members)),
        ("zip_comments", lambda: expert_zip_comments(spec, env, pool, members)),
        ("relation_groups", lambda: expert_relation_groups(spec, env, pool, members)),
        ("ans_members", lambda: expert_ans_members(spec, env, pool, members)),
        ("statement_enum", lambda: expert_statement_enum(spec, env, pool, members, ctx)),
        ("attack_judged", lambda: expert_attack_judged(spec, env, pool, members, ctx)),
        ("graph_clause_enum", lambda: expert_graph_clause_enum(spec, env, pool, members)),
        ("none_floor", lambda: none_floor(spec, pool)),
        ("bytes_spellings", lambda: bytes_context_spellings(spec, env, pool, members)),
        ("spellings", lambda: widen_spellings(spec, pool)),
        ("relation_group_prune", lambda: prune_relation_group_noise(spec, pool)),
    ]
    for nm, fn in steps:
        if env.time_left() <= 0 and nm not in ("spellings",):
            continue
        try:
            fn()
        except Exception as e:   # one widening's failure costs only its candidates
            import sys
            print(f"proposer_families: {nm} on {spec.qid}: {type(e).__name__}: {e}", file=sys.stderr)
