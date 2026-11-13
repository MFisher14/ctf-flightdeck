#!/usr/bin/env python3
"""Mobile, Day 21 look-ahead (docs/retro/day-21-predictions-mobile.md): the payload a puzzle document's `data`
names by path, when it is NOT a dex member of the package itself.

Day 20 ("loaded later") was codec `dynamic` with `data` = `assets/payload.dex`, a secondary DEX of the APK whose
string table holds the code in clear. Reading that member by its path is the member-by-path fold's (a separate
build); this module reads what that fold does not, and only that:

  nested     the path names an archive (a JAR, an APK, a zip) whose dex members hold the code, or is written
             `<archive>!/<member>`
  native     the path names a native library: its printable runs
  resource   the path names resources.arsc: its value pool
  packed     the path names a gzip of a payload
  encrypted  the path names a member that is a payload (dex, zip, ELF, gzip) under XOR, RC4 or AES with a key
             the document states or the app's own dex carries. A key is taken only when the decrypted bytes
             start with one of those magics (RC4: the whole magic, `dex\n0` for a dex): the magic is the proof,
             nothing is guessed
  no-ext     the path names a dex member without the `.dex` extension (res/raw/module)
  list       `data` is a list of paths: one code in all of them, or a code cut in two over them (head `ANS-...`
             in the first, the rest of its hex in the next)
  hermes     (Day 21 final prep) the path names Hermes bytecode (magic c6 1f bc 03 c1 03 19 1f): its string table
             (header string count, 32-bit small-string entries: is_utf16, 23-bit offset, 8-bit length, overflow
             entries for long strings; app_bundles.hermes_strings) cut into separate strings, the exact-code rule
             applied per string. The storage holds the strings back to back, so a code glued to its neighbours
             is read only through the table; a file whose table does not add up is read as raw bytes with the
             ANS boundary regex, as before (never a looser regex)
  pieces     (Day 21 final prep) one path, no exact code: a code cut in two inside a Hermes string table, a
             .NET #US heap or an AXML string pool (exactly one string `ANS-` plus 1 to 15 hex digits, exactly
             one string of the hex digits that complete it), or in a JavaScript bundle written as quoted literals
             joined by `+` in one expression (exactly one such expression whose literals join to a code).
             Route `apk-pieces:named-strings:<hermes|dotnet|axml|js-concat>`; two heads, two tails or two
             expressions with two codes are nothing

Only exact codes (`ANS-` and 16 uppercase hex digits) are read; no transform, no search. Exactly one code in what
the path names, else nothing (the caller's search goes on as before). The answer is NEVER plain by itself: every
route here has a name of its own (`apk-string:<kind>:named-<how>`), so it is a one-option `labels.pick` until the
judge accepts that name on a base, and the caller's second-code look still demotes it when the package holds
another code. Bounded by bytes and counts, never by a clock: the same package gets the same answer on the base, in
the gate's replay and on a clock.

  basename   (Day 21 final prep) `data` is no member path but the basename or stem of exactly one member, case
             folded (`index.android.bundle` -> assets/index.android.bundle, `Huntress.Arena` ->
             assemblies/Huntress.Arena.dll): that member, the route ending `named-by-basename`

  named_paths(doc, members) -> [path]           the paths `data` names, [] when it names none
  by_basename(text, members) -> path | None     the one member `text` names by basename or stem
  read(doc, members) -> (code, route) | None    this module's reading
"""
import base64
import binascii
import gzip
import io
import re
import struct
import zipfile
import zlib

ANS = re.compile(rb"(?<![0-9A-Za-z])ANS-[0-9A-F]{16}(?![0-9A-Za-z])")
HEAD = re.compile(r"^ANS-[0-9A-F]{1,15}$")
HEX = re.compile(r"^[0-9A-F]{1,15}$")
HERMES = b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f"
MAGICS = {b"dex\n": "dex", b"PK\x03\x04": "zip", b"\x7fELF": "elf", b"\x1f\x8b\x08": "gzip", HERMES: "hermes"}
MAX_PIECE_STRINGS = 60000   # strings of one table the pieces rule reads
MAX_JS = 4 << 20            # bytes of a JavaScript bundle the `+` rule reads
_JS_CONCAT = re.compile(r"""(?<![\w$.\]\)'"])(?:"[A-Za-z0-9-]{1,20}"|'[A-Za-z0-9-]{1,20}')"""
                        r"""(?:\s*\+\s*(?:"[A-Za-z0-9-]{1,20}"|'[A-Za-z0-9-]{1,20}')){1,15}""")
_CODE = re.compile(r"ANS-[0-9A-F]{16}")
MAX_BODY = 8 << 20        # bytes of one payload that is read
MAX_INNER = 64            # members of an archive the path names that are read
MAX_PATHS = 8             # paths of a `data` list
MAX_KEYS = 256            # key candidates tried on an encrypted payload
MAX_RC4 = 1 << 20         # bytes of a payload decrypted under RC4 by the Python fallback (no `cryptography` ARC4)
RC4_MAGICS = (b"dex\n0", b"PK\x03\x04", b"\x7fELF", b"\x1f\x8b\x08")   # RC4 has no block to align: the whole magic
MAX_STRINGS = 20000       # dex strings read from one dex
SEP = ("!/", "!")         # <archive>!/<member>, as a JarURLConnection writes it
_KEY_FIELD = re.compile(r"(^|_)(key|secret|pass|password|passphrase|seed)(_hex|_b64|_base64)?$", re.I)
_IV_FIELD = re.compile(r"^(iv|nonce|aes_iv|iv_hex)$", re.I)
_PATHLIKE = re.compile(r"^[\w.\-]+(/[\w.\-]+)*(!/?[\w.\-/]+)?$")


# ---------------------------------------------------------------------------- readers of one body

def dex_strings(b):
    """The strings of a dex's string table (string_ids at header 0x38), [] for anything else."""
    if not b.startswith(b"dex\n") or len(b) < 0x70:
        return []
    try:
        n, off = struct.unpack_from("<II", b, 0x38)
        out = []
        for i in range(min(n, MAX_STRINGS)):
            j = struct.unpack_from("<I", b, off + 4 * i)[0]
            while b[j] & 0x80:      # the ULEB128 length in UTF-16 units
                j += 1
            j += 1
            e = b.index(b"\0", j)
            out.append(b[j:e].decode("utf-8", "replace"))
        return out
    except Exception:
        return []


def elf_strings(b):
    return [m.group(0).decode() for m in re.finditer(rb"[\x20-\x7e]{4,256}", b[:MAX_BODY])] if b[:4] == b"\x7fELF" else []


def arsc_strings(b):
    try:
        import apk_resources
        return apk_resources.arsc_strings(b)
    except Exception:
        return []


_HERMES_MEMO = [None, None]   # the last Hermes body read (the same bytes object, never a copy) and its strings


def hermes_strings(b):
    """The strings of a Hermes bytecode file's string table, or None when the table does not add up. The last body
    read is remembered, so the exact-code rule and the pieces rule parse a bundle once."""
    if _HERMES_MEMO[0] is b:
        return _HERMES_MEMO[1]
    try:
        import app_bundles
        got = app_bundles.hermes_strings(b)
    except Exception:
        got = None
    out = None if got is None else [t for t, _ in got]
    _HERMES_MEMO[:] = [b, out]
    return out


def structured(b):
    """The kind of a body the pieces rule reads by its structure ('hermes', 'dotnet', 'axml', 'js'), or ''."""
    if b.startswith(HERMES):
        return "hermes"
    if b[:2] == b"MZ" and b"BSJB" in b[:MAX_BODY]:
        return "dotnet"
    if len(b) >= 8 and struct.unpack_from("<HH", b, 0) == (0x0003, 8):
        return "axml"
    try:
        import app_bundles
        if app_bundles.is_js(b):
            return "js"
    except Exception:
        pass
    return ""


def table_strings(b, kind):
    """The separate strings of a structured body: a Hermes string table, the .NET #US heap, the AXML pool."""
    try:
        if kind == "hermes":
            return hermes_strings(b) or []
        if kind == "dotnet":
            import app_bundles
            return app_bundles.dotnet_strings(b)[:MAX_PIECE_STRINGS]
        if kind == "axml":
            import apk_resources
            return apk_resources.pool_strings(b, 8)[:MAX_PIECE_STRINGS]
    except Exception:
        return []
    return []


def js_concat_codes(b):
    """The codes a JavaScript bundle writes as quoted literals joined by `+` in ONE expression ("ANS-" + "1A2B..."):
    an expression whose literals join to exactly `ANS-` and 16 hex digits, standing alone (no `+` before or after it,
    so no variable or call is part of it)."""
    try:
        text = b[:MAX_JS].decode("utf-8", "replace")
    except Exception:
        return set()
    out = set()
    for m in _JS_CONCAT.finditer(text):
        before = text[max(0, m.start() - 40):m.start()].rstrip()
        after = text[m.end():m.end() + 40].lstrip()
        if before.endswith("+") or after.startswith("+"):
            continue
        joined = "".join(re.findall(r"""["']([A-Za-z0-9-]*)["']""", m.group(0)))
        if _CODE.fullmatch(joined):
            out.add(joined)
    return out


def pieces(kind, b):
    """(code, tag) for a code cut in pieces inside one structured body; (None, why) otherwise.

    hermes, dotnet, axml: exactly one string that is `ANS-` and 1 to 15 hex digits, and exactly one string of the
    hex digits that complete it. js: exactly one code over the bundle's `+` expressions of quoted literals."""
    if kind == "js":
        codes = js_concat_codes(b)
        if len(codes) == 1:
            return codes.pop(), "js-concat"
        return None, ("%d codes joined by + in the bundle" % len(codes)) if codes else "no code joined by +"
    if kind not in ("hermes", "dotnet", "axml"):
        return None, "not a table"
    strings = list(dict.fromkeys(table_strings(b, kind)))
    heads = [s for s in strings if HEAD.match(s)]
    if len(heads) != 1:
        return None, "%d strings start a code" % len(heads)
    need = 20 - len(heads[0])
    tails = [s for s in strings if len(s) == need and HEX.match(s)]
    if len(tails) != 1:
        return None, "%d strings complete %s" % (len(tails), heads[0])
    code = heads[0] + tails[0]
    return (code, kind) if _CODE.fullmatch(code) else (None, "not a code")


def kind_of(b) -> str:
    for magic, kind in MAGICS.items():
        if b.startswith(magic):
            return kind
    if len(b) >= 12 and struct.unpack_from("<HH", b, 0) == (0x0002, 12):
        return "resources"
    return ""


def strings_of(b, kind):
    if kind == "hermes":
        return hermes_strings(b) or []
    if kind == "dex":
        return dex_strings(b)
    if kind == "elf":
        return elf_strings(b)
    if kind == "resources":
        return arsc_strings(b)
    return []


def _unzip(b):
    """[(name, body)] of an archive's members, dex members first, at most MAX_INNER."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(b))
        infos = [i for i in zf.infolist() if not i.is_dir() and i.file_size <= MAX_BODY and not i.flag_bits & 1]
    except Exception:
        return []
    infos.sort(key=lambda i: (not i.filename.endswith(".dex"), i.filename))
    out = []
    for i in infos[:MAX_INNER]:
        try:
            out.append((i.filename, zf.read(i)))
        except Exception:
            continue
    return out


def _gunzip(b):
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(b, MAX_BODY)
        return out if not d.unconsumed_tail else None
    except Exception:
        return None


# ---------------------------------------------------------------------------- keys and ciphers

def _key_forms(text):
    """The byte forms of one key text: as it stands, hex, base64; each 1 to 64 bytes."""
    out = []
    if not isinstance(text, str) or not 1 <= len(text) <= 128:
        return out
    out.append(text.encode())
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,64}", text):
        out.append(binascii.unhexlify(text))
    if re.fullmatch(r"[A-Za-z0-9+/]{4,88}={0,2}", text) and len(text) % 4 == 0:
        try:
            out.append(base64.b64decode(text, validate=True))
        except Exception:
            pass
    return [k for k in dict.fromkeys(out) if 1 <= len(k) <= 64]


def doc_keys(doc):
    """Key texts the document states: fields named like a key (key, key_hex, aes_key, xor_key, secret, ...)."""
    out = []
    for k, v in doc.items():
        if isinstance(k, str) and _KEY_FIELD.search(k) and isinstance(v, str):
            out.append(v)
    return out


def doc_ivs(doc):
    out = []
    for k, v in doc.items():
        if isinstance(k, str) and _IV_FIELD.match(k) and isinstance(v, str):
            out += [f for f in _key_forms(v) if len(f) == 16]
    return out


def app_key_texts(members, skip):
    """Key texts the app's own code carries: each string of the package's dex members (not the payload), 4 to 64
    characters, and the value of a `NAME=VALUE` or `NAME: VALUE` string."""
    out = []
    for n, b in members.items():
        if n in skip or not n.endswith(".dex"):
            continue
        for s in dex_strings(b):
            if 4 <= len(s) <= 64 and " " not in s and not s.startswith(("L", "[")):
                out.append(s)
            m = re.match(r"^[A-Za-z_][\w.]{0,40}\s*[=:]\s*(\S{4,64})$", s)
            if m:
                out.append(m.group(1))
    return list(dict.fromkeys(out))


def _xor(data, key):
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


def _aes(key, data, mode, iv=None):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    m = modes.ECB() if mode == "ecb" else modes.CBC(iv)
    dec = Cipher(algorithms.AES(key), m).decryptor()
    return dec.update(data) + dec.finalize()


def _rc4_py(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out, i, j = bytearray(len(data)), 0, 0
    for n, c in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = c ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def _rc4(key, data):
    """RC4 (no drop) of `data`: `cryptography`'s ARC4 when it is there, else the Python one up to MAX_RC4 bytes
    (None past that: a payload that cannot be read whole is not read)."""
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
        from cryptography.hazmat.primitives.ciphers import Cipher
        if 5 <= len(key) <= 256:
            dec = Cipher(ARC4(key), mode=None).decryptor()
            return dec.update(data) + dec.finalize()
    except Exception:
        pass
    return _rc4_py(key, data) if len(data) <= MAX_RC4 else None


def _unpad(b):
    p = b[-1] if b else 0
    return b[:-p] if 1 <= p <= 16 and b.endswith(bytes([p]) * p) else b


def decrypt(body, keys):
    """(plain, how) for the first key under which `body` decrypts to a known payload magic, else (None, None).
    keys: [(source, key bytes)]. XOR with the key repeated; RC4 (row 408); AES-ECB, AES-CBC with the IV in front of
    the data or a zero IV, for a key of 16, 24 or 32 bytes. Only the first block is decrypted to test a key."""
    for source, key in keys[:MAX_KEYS]:
        if kind_of(_xor(body[:8], key)):
            return _xor(body, key), "xor-key-" + source
    # Day 21 build round 2 (row 408): RC4 with the same keys, the first eight bytes to test a key (the Python
    # key schedule, 256 steps), the whole body only for a key whose output starts with a whole payload magic
    for source, key in keys[:MAX_KEYS]:
        head = _rc4_py(key, body[:8])
        if head.startswith(RC4_MAGICS):
            plain = _rc4(key, body)
            if plain is not None and plain[:8] == head:
                return plain, "rc4-key-" + source
    if len(body) < 32 or len(body) % 16:
        return None, None
    try:
        import cryptography  # noqa: F401
    except Exception:
        return None, None
    for source, key in keys[:MAX_KEYS]:
        if len(key) not in (16, 24, 32):
            continue
        try:
            if kind_of(_aes(key, body[:16], "ecb")):
                return _unpad(_aes(key, body, "ecb")), "aes-ecb-key-" + source
            if kind_of(_aes(key, body[16:32], "cbc", body[:16])):
                return _unpad(_aes(key, body[16:], "cbc", body[:16])), "aes-cbc-ivfront-key-" + source
            if kind_of(_aes(key, body[:16], "cbc", bytes(16))):
                return _unpad(_aes(key, body, "cbc", bytes(16))), "aes-cbc-zeroiv-key-" + source
        except Exception:
            continue
    return None, None


# ---------------------------------------------------------------------------- the path and what it names

_NOT_NAMED = re.compile(r"^(META-INF/|assets/huntress_puzzle\.json$|AndroidManifest\.xml$|classes\d*\.dex$)", re.I)
_EXT = re.compile(r"\.[A-Za-z0-9]{1,9}$")   # .so, .dll, .bundle, .jsbundle
_BASENAME = re.compile(r"^[\w.\-]{3,128}$")


def by_basename(text, members):
    """The ONE member whose basename, or basename less one or two extensions (`Huntress.Arena.dll.so`), equals
    `text` case-folded; a `.so` also without a `lib`/`lib_` in front. None for a text with a `/`, a text that is
    a member itself, no match or two matches. The package's own document, signing files, manifest and classes*.dex
    are never named this way."""
    if not isinstance(text, str) or "/" in text or not _BASENAME.match(text.strip()) or text in members:
        return None
    want = text.strip().casefold()
    hits = []
    for n in members:
        if _NOT_NAMED.match(n):
            continue
        base = n.rsplit("/", 1)[-1]
        names = {base}
        if base.lower().endswith(".so"):
            for pre in ("lib_", "lib"):
                if base.startswith(pre):
                    names.add(base[len(pre):])
                    break
        for x in list(names):
            one = _EXT.sub("", x)
            names.update((one, _EXT.sub("", one)))
        if want in {x.casefold() for x in names if x}:
            hits.append(n)
            if len(hits) > 1:
                return None
    return hits[0] if hits else None


def resolve(doc, members):
    """(paths, how): named_paths, or the one member `data` names by basename or stem (how 'by-basename')."""
    paths = named_paths(doc, members)
    if paths:
        return paths, ""
    data = doc.get("data") if isinstance(doc, dict) else None
    n = by_basename(data, members)
    return ([n], "by-basename") if n else ([], "")


def named_paths(doc, members):
    """The member paths `data` names: a string, or a list of strings, each a member of the package or
    `<archive>!/<member>` with the archive a member. [] when `data` names none (every judged codec's data)."""
    data = doc.get("data") if isinstance(doc, dict) else None
    items = data if isinstance(data, list) else [data]
    if not items or len(items) > MAX_PATHS or not all(isinstance(x, str) and _PATHLIKE.match(x) for x in items):
        return []
    out = []
    for x in items:
        arch = next((x.split(s, 1)[0] for s in SEP if s in x), None)
        if x in members or (arch and arch in members):
            out.append(x)
        else:
            return []
    return out


def _bodies(path, members):
    """[(how, body)]: what one path names, opened. how: '' for the member as it stands, else the steps taken."""
    for s in SEP:
        if s in path:
            arch, inner = path.split(s, 1)
            got = [(n, b) for n, b in _unzip(members.get(arch, b"")) if n == inner.lstrip("/")]
            return [("jar-path", b) for _, b in got]
    return [("", members[path])]


def _open(body, how, members, doc, skip, depth=0):
    """[(kind, how, body)]: a payload body opened down to readable kinds (dex, elf, resources, or raw bytes)."""
    k = kind_of(body)
    if k == "zip" and depth < 2:
        out = []
        for n, b in _unzip(body):
            sub = _open(b, (how + "+" if how else "") + "in-zip", members, doc, skip, depth + 1)
            out += [s for s in sub if s[0] in ("dex", "elf", "resources", "hermes")]
        return out
    if k == "gzip" and depth < 2:
        plain = _gunzip(body)
        return _open(plain, (how + "+" if how else "") + "gzip", members, doc, skip, depth + 1) if plain else []
    if k:
        return [(k, how, body)]
    if depth == 0 and not structured(body):   # a .NET assembly, an AXML file, a JS bundle: no cipher to undo
        keys = [("doc", f) for t in doc_keys(doc) for f in _key_forms(t)]
        keys += [("apk", f) for t in app_key_texts(members, skip) for f in _key_forms(t)]
        plain, cipher = decrypt(body, list(dict.fromkeys(keys)))
        if plain is not None:
            return _open(plain, (how + "+" if how else "") + cipher, members, doc, skip, depth + 1)
    return [("raw", how, body)]


def _codes(kind, body):
    """Exact codes of one opened body: in its strings for a dex, ELF or resource table, in its bytes otherwise.
    A Hermes file: in each string of its table (the storage is glued), in its bytes when the table does not add up."""
    if kind == "hermes" and hermes_strings(body) is None:
        return {m.group(0).decode() for m in ANS.finditer(body[:MAX_BODY])}, []
    if kind in ("dex", "elf", "resources", "hermes"):
        found = set()
        for s in strings_of(body, kind):
            found.update(m.group(0).decode() for m in ANS.finditer(s.encode("utf-8", "replace")))
        return found, [s for s in strings_of(body, kind)]
    return {m.group(0).decode() for m in ANS.finditer(body[:MAX_BODY])}, []


KINDS = {"dex": "dex", "elf": "lib", "resources": "resources", "raw": "asset", "hermes": "hermes"}


def deferred(paths, members):
    """True for the Day 20 shape, which the member-by-path fold reads: one path, a dex member of the package
    itself (named `.dex`, dex magic)."""
    return len(paths) == 1 and paths[0] in members and paths[0].endswith(".dex") and members[paths[0]].startswith(b"dex\n")


def read(doc, members):
    """(code, route) when what `data` names holds exactly one exact code (or one code cut over a list of paths),
    else None. The route names the member kind and how it was reached: apk-string:<kind>:named[-<how>]."""
    paths, named_how = resolve(doc, members)
    if not paths or deferred(paths, members):
        return None
    skip = set(p.split("!")[0] for p in paths)
    per_path = []
    for p in paths:
        opened = []
        for how, body in _bodies(p, members):
            if len(body) <= MAX_BODY:
                opened += _open(body, how, members, doc, skip)
        per_path.append(opened)
    found = {}
    for opened in per_path:
        for kind, how, body in opened:
            codes, _ = _codes(kind, body)
            for c in codes:
                found.setdefault(c, (kind, how))
    cut = {}
    if len(paths) == 1 and len(found) <= 1:
        # Day 21 final prep: a code cut in pieces inside the one body the path names (a Hermes string table, the
        # .NET #US heap, the AXML pool, a JS bundle's `+` expression of quoted literals)
        for kind, how, body in per_path[0]:
            k = kind if kind == "hermes" else structured(body)
            if k:
                code, tag = pieces(k, body)
                if code:
                    cut.setdefault(code, (tag, how))
    if len(found) == 1:
        code, (kind, how) = next(iter(found.items()))
        if any(c != code for c in cut):
            return None     # a whole code and another code in pieces: nothing proves which
        tags = [t for t in ("list" if len(paths) > 1 else "", named_how, how) if t]
        return code, "apk-string:%s:named%s" % (KINDS[kind], "-" + "-".join(tags) if tags else "")
    if found:
        return None
    if len(cut) == 1:
        code, (tag, how) = next(iter(cut.items()))
        tags = [t for t in (named_how, how) if t]
        return code, "apk-pieces:named-strings:%s%s" % (tag, "-" + "-".join(tags) if tags else "")
    if len(paths) < 2:
        return None
    # a code cut over the list: the head (ANS- and 1 to 15 hex digits) in the first path, the rest in the next ones
    parts = []
    for opened in per_path:
        strings = [s for kind, _, body in opened for s in _codes(kind, body)[1]]
        parts.append(strings)
    heads = {s for s in parts[0] if HEAD.match(s)}
    if len(heads) != 1:
        return None
    code = heads.pop()
    for strings in parts[1:]:
        need = 20 - len(code)
        tails = {s for s in strings if HEX.match(s) and len(s) <= need}
        if len(tails) != 1:
            return None
        code += tails.pop()
    return (code, "apk-pieces:named-list") if re.fullmatch(r"ANS-[0-9A-F]{16}", code) else None
