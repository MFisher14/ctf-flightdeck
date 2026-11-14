"""Day 21 Mobile look-ahead readers (new file, loaded by name by codec_search.py).

These cover shapes the lane's look-aheads flagged but left to None: the ones in
`docs/retro/day-21-predictions-mobile.md` ("Not built, and why") and the Low rows of
`docs/backlog-status.md` under "Mobile Android". Every reader here answers ONLY an EXACT
code (`ANS-` and 16 uppercase hex digits), exactly one, and the answer is always unsure
(`labels.pick` / `labels.candidates`, route of its own under `mobile.codec/lookahead:...`),
never plain before the judge accepts the route's name. A reading that is not exactly one
code gives nothing and the usual search stands.

Where it runs. `codec_search.lookahead_revise` calls `read(members, dups)` in `_solve`
AFTER the usual reading (`dynamic_member_hit` / `solve_members` / `stated_revise`), and ONLY
when that reading gave NO code. So nothing here can change an answer the shipped solver
already makes, and, because every saved attempt of Days 1 to 21 is answered by the shipped
solver with a code, this module is never reached on the regression set and adds no time to
a saved solve (`tools/preflight.py --regress mobile-android`, `tools/solvetimes.py`). It is
reached only on a document the rest of the solver could not read.

The exactness proof. A structural reader (char list, linked list, collapsed keys, an XML
`<pin>`) is accepted only when the bytes reconstruct EXACTLY one code; a keyed cipher
(XTEA, a rolling XOR, an LCG keystream) is accepted only when the stated key decrypts `data`
to EXACTLY one code. The chance that a wrong structure or a wrong key yields exactly
`ANS-[0-9A-F]{16}` is negligible (same principle `dynamic_members.py` uses with a payload
magic), so a reader that fires has read the code, not guessed it; one that does not fire
returns nothing rather than a maybe.

Bounded by sizes and counts, never by a clock, so the base, the gate's replay and a clock
agree. B-249 adds `decoy_places` (Day 18 item 6: places a `decoys`/`noise`/`junk`/... field
lists are removed, `keep`/`select`/`pick` places are read, `every`/`skip` drops every k-th,
then the document's `order`; every reading must give the same one code). Not built here
(documented, left to None, no guess): AES-GCM / ChaCha20 / an RC4 or PBKDF2 key with a
nonce the document does not state / a key from a signing certificate (no cheap magic-proved
test for a stream cipher with an unknown nonce, and none seen in the lane); a Kotlin
`kotlin.random.Random` XorWow keystream (no Kotlin runtime to verify a port against). The
stated forms (AES-GCM, ChaCha20, XTEA, a keyed columnar transposition, a substitution or
lookup table, a hash- or PBKDF2-derived key, a permutation by a stated order) are read in
words by `stated_spec.py` (B-249); `database_name` / `table_name` are question facts,
answered by `apk_facts.py` (B-249), not a code path; OAT/VDEX/ODEX/`.dm` payloads
named by `data` (a clear code in such a member is already found by `dynamic_members.py`,
which scans the opened bytes; only an encrypted-zip member named by `data` is new, and it is
read here through the package's own archive passwords).
"""

import base64
import binascii
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE.parent / "common", HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import puzzle_asset_codec as base          # noqa: E402  ANS regex and the decode transforms

try:                                        # the same key-form and archive helpers the member fold uses
    import dynamic_members                   # noqa: E402
except Exception:                            # without it the keyed-cipher and encrypted-zip readers stand down
    dynamic_members = None

try:                                        # the resources.arsc value-pool reader (arsc_strings), Day 23 carriers
    import apk_resources                     # noqa: E402
except Exception:                            # without it the resources.arsc carrier stands down
    apk_resources = None

PUZZLE = base.PUZZLE
CODE = base.ANSWER                           # ANS- and 16 uppercase hex digits
CODE_LOOSE = re.compile(rb"(?<![0-9A-Za-z])ANS-[0-9A-Fa-f]{16}(?![0-9A-Za-z])")

# Fields a puzzle document uses for its own machinery: a structural reader never treats one
# of these as the code's carrier (the 152 saved documents use only these, docs/retro/day-21).
RESERVED = {
    "schema", "day", "codec", "algorithm", "algo", "cipher", "mode", "encoding",
    "key", "key_hex", "key_b64", "key_base64", "aes_key", "xor_key", "secret",
    "password", "passphrase", "seed", "salt", "iv", "nonce", "aes_iv", "iv_hex",
    "order", "parts", "step", "stride", "offset", "start", "rounds", "count",
    "a", "b", "c", "m", "k", "mult", "multiplier", "increment", "inc", "mod",
    "case", "hint", "note", "notes", "description", "transform", "steps", "use",
}

MAX_NODES = 64                               # a linked list / collapsed map is read up to this many entries
MAX_BYTES = 1 << 20                          # bytes of a member a keyed cipher may decrypt
MAX_CODE_LEN = 20                            # len("ANS-") + 16


def _exact(text):
    """The code when `text` is EXACTLY one code (ascii, surrounding white space allowed), else None."""
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("latin-1")
        except Exception:
            return None
    if not isinstance(text, str):
        return None
    t = text.strip()
    return t if CODE.fullmatch(t) else None


def _one_in(b):
    """The one code in bytes `b` (case-folded to upper), or None for none or two different ones."""
    found = {m.group(0).upper().decode() for m in CODE_LOOSE.finditer(bytes(b)[:MAX_BYTES])}
    return found.pop() if len(found) == 1 else None


# ---------------------------------------------------------------------------- structural readers


def char_list(doc):
    """`data` (or a non-reserved list field) is a list of the code's characters, in order: 20 one-character
    strings, or 20 integer char codes. Join and keep it only when the join is EXACTLY one code."""
    out = []
    items = _list_fields(doc)
    for where, lst in items:
        if not 4 <= len(lst) <= 256:
            continue
        s = None
        if all(isinstance(x, str) and len(x) == 1 for x in lst):
            s = "".join(lst)
        elif all(isinstance(x, int) and 0 <= x <= 0x10FFFF for x in lst):
            try:
                s = "".join(chr(x) for x in lst)
            except Exception:
                s = None
        code = _exact(s) if s is not None else None
        if code:
            out.append(("char-list" + _at(where), code))
    return out


def linked_list(doc):
    """`data` (or a non-reserved map field) is a map of nodes, each {char, next}: a character under one of
    `c`/`char`/`ch`/`value`/`v`/`letter` and the id of the next node under `next`/`link`/`n`. Start at the
    head (a `head`/`start` field, or the one node no `next` points to) and walk, each node once, up to
    MAX_NODES. Keep it only when the walked characters are EXACTLY one code."""
    out = []
    for where, obj in _map_fields(doc):
        nodes = {str(k): v for k, v in obj.items() if isinstance(v, dict)}
        if not 4 <= len(nodes) <= MAX_NODES or len(nodes) != len(obj):
            continue
        targets = {_node_next(v) for v in nodes.values()}
        heads = [k for k in nodes if k not in targets]
        head = None
        for name in ("head", "start", "first"):
            if isinstance(doc.get(name), (str, int)) and str(doc[name]) in nodes:
                head = str(doc[name])
        if head is None:
            head = heads[0] if len(heads) == 1 else None
        if head is None:
            continue
        chars, cur, seen = [], head, set()
        while cur is not None and cur in nodes and cur not in seen and len(chars) <= MAX_CODE_LEN:
            seen.add(cur)
            ch = _node_char(nodes[cur])
            if ch is None:
                chars = None
                break
            chars.append(ch)
            cur = _node_next(nodes[cur])
        code = _exact("".join(chars)) if chars else None
        if code:
            out.append(("linked-list" + _at(where), code))
    return out


def collapsed_keys(doc):
    """The code's characters collapsed into map keys: a map (top level, or a non-reserved field) that is
    {char: position} (a one-character key, an integer value) for every entry, or {position: char} (an
    integer-or-digit-string key, a one-character value). Order by position, join, keep it only when the
    join is EXACTLY one code. The top-level reserved fields are left out of a top-level reading."""
    out = []
    maps = list(_map_fields(doc))
    top = {k: v for k, v in doc.items() if k not in RESERVED}
    if top:
        maps.append((None, top))
    for where, obj in maps:
        if not 4 <= len(obj) <= 256:
            continue
        code = _collapsed(obj)
        if code:
            out.append(("collapsed-keys" + _at(where), code))
    return out


def _collapsed(obj):
    char_key = all(isinstance(k, str) and len(k) == 1 and isinstance(v, int) for k, v in obj.items())
    pos_key = all(_is_pos(k) and isinstance(v, str) and len(v) == 1 for k, v in obj.items())
    pairs = None
    if char_key:
        pairs = [(v, k) for k, v in obj.items()]
    elif pos_key:
        pairs = [(int(k), v) for k, v in obj.items()]
    if pairs is None:
        return None
    positions = [p for p, _ in pairs]
    if sorted(positions) != list(range(min(positions), min(positions) + len(positions))):
        return None   # the positions must be a dense run, else the join is not proven
    return _exact("".join(ch for _, ch in sorted(pairs)))


# ---------------------------------------------------------------------------- decoy places (B-249)
# Day 18 look-ahead, item 6 (docs/retro/day-18 predictions, shapes C18/C20/C21): `data` carries the code's characters
# with decoy characters inserted at places a field lists. `decoys`/`noise`/`junk`/`padding`/`drop` lists the places to
# remove, `keep`/`select`/`pick` the places to read (in the listed order), `every`/`skip` a k whose every k-th place
# is a decoy. The document's `order` then applies as it would to a clean `data`. Each list is read 0-based and
# 1-based, every k-th from both ends of the count, and the order in both directions: every reading that gives an EXACT
# code must give the same one, else nothing (never a guess between two readings).

_DECOY_DROP = ("decoys", "decoy", "noise", "junk", "padding", "drop", "filler", "remove")
_DECOY_KEEP = ("keep", "select", "pick")
_DECOY_EVERY = ("every", "skip")
MAX_DECOY_TEXT = 256


def _int_list(v):
    if isinstance(v, list) and v and all(isinstance(x, int) and not isinstance(x, bool) for x in v):
        return v
    return None


def _decoy_text(doc):
    d = doc.get("data")
    if isinstance(d, str) and 20 < len(d) <= MAX_DECOY_TEXT:
        return d
    if isinstance(d, list) and 20 < len(d) <= MAX_DECOY_TEXT and all(isinstance(x, str) and len(x) == 1 for x in d):
        return "".join(d)
    return None


def _cleaned(doc, text):
    """[(how, cleaned text)] every stated decoy field gives, each reading of it once."""
    out = []
    n = len(text)
    for f in _DECOY_DROP:
        lst = _int_list(doc.get(f))
        if lst is None:
            continue
        for base in (0, 1):
            pos = [x - base for x in lst]
            if len(set(pos)) != len(pos) or any(not 0 <= x < n for x in pos):
                continue
            drop = set(pos)
            out.append(("drop@%s" % f, "".join(c for i, c in enumerate(text) if i not in drop)))
    for f in _DECOY_KEEP:
        lst = _int_list(doc.get(f))
        if lst is None:
            continue
        for base in (0, 1):
            pos = [x - base for x in lst]
            if len(set(pos)) != len(pos) or any(not 0 <= x < n for x in pos):
                continue
            out.append(("keep@%s" % f, "".join(text[i] for i in pos)))
    for f in _DECOY_EVERY:
        k = doc.get(f)
        if isinstance(k, bool) or not isinstance(k, int) or not 2 <= k <= n:
            continue
        out.append(("every@%s" % f, "".join(c for i, c in enumerate(text) if (i + 1) % k)))
        out.append(("every0@%s" % f, "".join(c for i, c in enumerate(text) if i % k)))
    return out


def _ordered(doc, text):
    """[(how, text)]: `text` as it stands when the document states no order, else every reading of the order."""
    order = _int_list(doc.get("order"))
    if order is None:
        return [("", text)]
    n = len(text)
    out = []
    for base in (0, 1):
        o = [x - base for x in order]
        if sorted(o) != list(range(n)):
            continue
        out.append(("+order", "".join(text[i] for i in o)))
        inv = [""] * n
        for i, src in enumerate(o):
            inv[src] = text[i]
        out.append(("+order-inverse", "".join(inv)))
    return out


def decoy_places(doc):
    """B-249: the code read after removing the decoy places the document lists (see the block comment above), then
    applying its order. Exactly one distinct exact code across every reading, else nothing."""
    if not isinstance(doc, dict):
        return []
    text = _decoy_text(doc)
    if text is None:
        return []
    codes = {}
    for how, clean in _cleaned(doc, text):
        for ohow, t in _ordered(doc, clean):
            c = _exact(t)
            if c:
                codes.setdefault(c, how + ohow)
    if len(codes) != 1:
        return []
    code, how = next(iter(codes.items()))
    return [("decoy-places:" + how, code)]


# ---------------------------------------------------------------------------- an XML <pin>


def nsc_pin(members):
    """A code as a `<pin ...>CODE</pin>` value in a text network_security_config.xml (Day 20 D12; the dex
    label record starves the no-document budget before the package look reaches the member). Exactly one
    distinct pin value that is an exact code, read from any text XML member that holds a `<pin`."""
    codes = set()
    for name, body in members.items():
        if name == PUZZLE or not name.lower().endswith(".xml"):
            continue
        if b"<pin" not in body[:MAX_BYTES]:
            continue
        try:
            text = bytes(body[:MAX_BYTES]).decode("utf-8", "replace")
        except Exception:
            continue
        for value in re.findall(r"<pin\b[^>]*>\s*([^<]+?)\s*</pin>", text, re.I):
            c = _exact(value)
            if c:
                codes.add(c)
    if len(codes) == 1:
        return [("nsc-pin", codes.pop())]
    return []


# ---------------------------------------------------------------------------- resource / manifest / prefs carriers
# Day 23 look-ahead (docs/retro/day-23-predictions-mobile-android.md, recommended gap 1): the resource carriers
# that the global package string look reads only when the budget is not starved first. `nsc_pin` above is the one
# such carrier the wave2 build read directly (budget-independent); these cover the rest the same way, so a
# Day-20-style long-string classes.dex that eats the no-document budget no longer hides a code in a strings.xml,
# the resources.arsc value pool, a manifest `<meta-data android:value>` or a SharedPreferences `<map><string>`.
# Read here directly, never clocked; each answers only an EXACT code and only when there is exactly one, so it
# is always an unsure one-option pick and can never make a wrong plain answer.

_ELEM_TEXT = re.compile(r"<(?:string|item)\b[^>]*>\s*([^<]+?)\s*</(?:string|item)>", re.I)
_ATTR_VALUE = re.compile(r"""=\s*(?:"([^"]*)"|'([^']*)')""")


def resource_strings(members):
    """A code in the resources.arsc value pool (apk_resources.arsc_strings): exactly one distinct exact code across
    every resources.arsc member. Budget-independent, so a classes.dex that starves the no-document search's budget
    does not hide it (the Day 20 D12 failure mode, in a carrier wave2's nsc_pin did not cover)."""
    if apk_resources is None:
        return []
    codes = set()
    for name, body in members.items():
        if name == PUZZLE or len(body) > MAX_BYTES:
            continue
        try:
            b = bytes(body)
            if not apk_resources.is_arsc(b):
                continue
            for s in apk_resources.arsc_strings(b):
                c = _exact(s)
                if c:
                    codes.add(c)
        except Exception:
            continue
    if len(codes) == 1:
        return [("arsc-value", codes.pop())]
    return []


def resource_xml(members):
    """A code in a text XML member: a `<string>`/`<item>` body (res/values/strings.xml, a SharedPreferences
    `<map><string>`) or any attribute value (a manifest `<meta-data android:value>`). Exactly one distinct exact
    code across every text XML member, read directly here (budget-independent), never the puzzle document and never
    a `<pin>` value (nsc_pin reads that)."""
    codes = set()
    for name, body in members.items():
        if name == PUZZLE or not name.lower().endswith(".xml"):
            continue
        head = bytes(body[:MAX_BYTES])
        if b"<" not in head:
            continue
        try:
            text = head.decode("utf-8", "replace")
        except Exception:
            continue
        values = [m.group(1) for m in _ELEM_TEXT.finditer(text)]
        values += [a or b for a, b in _ATTR_VALUE.findall(text)]
        for v in values:
            c = _exact(v)
            if c:
                codes.add(c)
    if len(codes) == 1:
        return [("resource-xml", codes.pop())]
    return []


# ---------------------------------------------------------------------------- keyed ciphers (stated key)


def keyed_cipher(doc, members):
    """A cipher whose name and key the document states, over `data` as bytes/hex/base64: XTEA (ECB), a
    rolling XOR (`key[i] xor position`), and an LCG keystream with stated parameters. Accept ONLY when the
    plaintext is EXACTLY one code (the exactness is the proof, as a payload magic is for dynamic_members).
    A wrong key or wrong cipher yields no code and nothing is offered."""
    if dynamic_members is None or not isinstance(doc, dict):
        return []
    codec = str(doc.get("codec") or doc.get("algorithm") or doc.get("algo") or "").strip().lower()
    data = doc.get("data")
    blob = _data_bytes(data)
    if blob is None or not blob or len(blob) > MAX_BYTES:
        return []
    keys = [k for t in dynamic_members.doc_keys(doc) for k in dynamic_members._key_forms(t)]
    keys = list(dict.fromkeys(keys))
    out = []
    if codec in ("xtea", "xxtea_xtea", "tea_x") or "xtea" in codec:
        for key in keys:
            if len(key) == 16 and len(blob) % 8 == 0:
                code = _exact(_xtea_decrypt(blob, key))
                if code:
                    out.append(("xtea", code))
                    break
    if not out and ("rolling" in codec or codec in ("rolling_xor", "rolling-xor", "progressive_xor")):
        for key in keys:
            code = _rolling_xor(blob, key)
            if code:
                out.append(("rolling-xor", code))
                break
    if not out and (codec in ("lcg", "lcg_keystream", "lcg-keystream") or "lcg" in codec):
        code = _lcg_keystream(blob, doc)
        if code:
            out.append(("lcg", code))
    return out


# ---------------------------------------------------------------------------- an encrypted zip member named by data


def encrypted_zip_member(doc, members):
    """`data` names, by path, a member that is a zip whose own entries are password-encrypted (the package's
    own archive passwords open it, the member fold's `_unzip` skips an encrypted entry). Open it with the
    package passwords and read exactly one code in the one entry's bytes."""
    if dynamic_members is None or not isinstance(doc, dict):
        return []
    data = doc.get("data")
    if not isinstance(data, str) or data not in members:
        return []
    body = members[data]
    if body[:4] != b"PK\x03\x04":
        return []
    try:
        from archive_passwords import candidates as pw_candidates   # noqa: E402
    except Exception:
        return []
    import io
    codes = set()
    try:
        import pyzipper
    except Exception:
        pyzipper = None
    for pw in pw_candidates():
        opened_any = False
        for mod, enc in ((pyzipper, True), (__import__("zipfile"), False)):
            if mod is None:
                continue
            try:
                zf = mod.AESZipFile(io.BytesIO(body)) if enc else mod.ZipFile(io.BytesIO(body))
            except Exception:
                continue
            try:
                for info in zf.infolist():
                    if info.is_dir() or info.file_size > MAX_BYTES:
                        continue
                    try:
                        inner = zf.read(info.filename, pwd=pw.encode() if isinstance(pw, str) else pw)
                    except Exception:
                        continue
                    opened_any = True
                    c = _one_in(inner)
                    if c:
                        codes.add(c)
            finally:
                try:
                    zf.close()
                except Exception:
                    pass
        if opened_any and codes:
            break
    if len(codes) == 1:
        return [("encrypted-zip-member", codes.pop())]
    return []


# ---------------------------------------------------------------------------- two entries with the document's name


def twin_entries(dups):
    """MO1: two zip entries of `assets/huntress_puzzle.json` in the delivery; the solver reads the LAST, and
    when that read gives no code an earlier entry may hold it. Read each earlier body's structure (and its
    clear bytes); one distinct code is a single unsure pick, two are candidates (the earlier entries, newest
    first), so the judge says which it wants."""
    codes = []
    for body in list(dups)[:4]:
        c = _doc_code(body)
        if c and c not in codes:
            codes.append(c)
    if len(codes) == 1:
        return {"kind": "single", "route": "lookahead:twin-entry", "code": codes[0]}
    if len(codes) >= 2:
        opts = [("twin_%d" % i, c) for i, c in enumerate(codes[:12])]
        return {"kind": "candidates", "key": "lookahead:twin-entry", "options": opts}
    return None


def _doc_code(body):
    """The one exact code an earlier puzzle-document body yields by its structure or in clear, else None."""
    import json
    c = _one_in(body)
    if c:
        return c
    try:
        doc = json.loads(bytes(body).decode("utf-8-sig"))
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    hits = char_list(doc) + linked_list(doc) + collapsed_keys(doc)
    seen = {code for _, code in hits}
    return seen.pop() if len(seen) == 1 else None


# ---------------------------------------------------------------------------- the entry point


def read(members, dups=()):
    """What to offer when the usual reading gave no code, or None. A dict:
      {"kind": "single", "route": <str>, "code": <code>}            one-option unsure pick
      {"kind": "candidates", "key": <suffix>, "options": [...] }    a candidate pick (row 346)
    plus a list of NOTE strings. Exactly one distinct code across every reader is a single pick; two or more
    DIFFERENT codes from the single-pick readers mean nothing is proven and None is returned (never a guess).
    The twin-entry case is decided on its own, because it is itself a two-code ambiguity."""
    notes = []
    if not members or PUZZLE not in members:
        tw = twin_entries(dups)
        if tw:
            notes.append("lookahead twin-entry: %s" % _describe(tw))
        return tw, notes

    import json
    try:
        doc = json.loads(bytes(members[PUZZLE]).decode("utf-8-sig"))
    except Exception:
        doc = None

    hits = []
    hits += nsc_pin(members)
    hits += resource_strings(members)
    hits += resource_xml(members)
    if isinstance(doc, dict):
        try:
            hits += char_list(doc) + linked_list(doc) + collapsed_keys(doc)
            hits += decoy_places(doc)
            hits += keyed_cipher(doc, members)
            hits += encrypted_zip_member(doc, members)
        except Exception as e:
            notes.append("lookahead: a reader raised %s: %s; the usual search stands" % (type(e).__name__, str(e)[:120]))

    distinct = {}
    for route, code in hits:
        distinct.setdefault(code, route)
    if len(distinct) == 1:
        code, route = next(iter(distinct.items()))
        got = {"kind": "single", "route": "lookahead:" + route, "code": code}
        notes.append("lookahead %s gives %s where the usual reading has none (one-option pick, unsure until judged)"
                     % (route, code))
        return got, notes
    if len(distinct) > 1:
        notes.append("lookahead: %d readers gave %d different codes (%s); nothing proves which, None"
                     % (len(hits), len(distinct), ", ".join("%s=%s" % (r, c) for c, r in distinct.items())[:200]))
        return None, notes

    tw = twin_entries(dups)
    if tw:
        notes.append("lookahead twin-entry: %s" % _describe(tw))
    return tw, notes


# ---------------------------------------------------------------------------- small helpers


def _describe(got):
    if got.get("kind") == "single":
        return "%s gives %s (one-option pick)" % (got["route"], got["code"])
    return "candidates %s" % ", ".join("%s=%s" % (n, v) for n, v in got["options"])


def _at(where):
    return "" if where is None else "@" + re.sub(r"[^a-z0-9_]+", "_", str(where).lower())[:24]


def _list_fields(doc):
    out = []
    if not isinstance(doc, dict):
        return out
    if isinstance(doc.get("data"), list):
        out.append(("data", doc["data"]))
    for k, v in doc.items():
        if k not in RESERVED and k != "data" and isinstance(v, list):
            out.append((k, v))
    return out


def _map_fields(doc):
    out = []
    if not isinstance(doc, dict):
        return out
    if isinstance(doc.get("data"), dict):
        out.append(("data", doc["data"]))
    for k, v in doc.items():
        if k not in RESERVED and k != "data" and isinstance(v, dict):
            out.append((k, v))
    return out


def _is_pos(k):
    if isinstance(k, int):
        return k >= 0
    return isinstance(k, str) and k.isdigit()


_CHAR_FIELDS = ("c", "char", "ch", "value", "v", "letter", "l")
_NEXT_FIELDS = ("next", "link", "n", "ptr", "to")


def _node_char(node):
    for f in _CHAR_FIELDS:
        v = node.get(f)
        if isinstance(v, str) and len(v) == 1:
            return v
        if isinstance(v, int) and 0 <= v <= 0x10FFFF and f in ("value", "v"):
            try:
                return chr(v)
            except Exception:
                return None
    return None


def _node_next(node):
    for f in _NEXT_FIELDS:
        if f in node:
            v = node[f]
            return str(v) if v is not None else None
    return None


def _data_bytes(data):
    """`data` as bytes: a hex string, a base64 string, or a list of byte ints; None otherwise."""
    if isinstance(data, list) and all(isinstance(x, int) and 0 <= x <= 255 for x in data):
        return bytes(data)
    if not isinstance(data, str):
        return None
    s = data.strip()
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s):
        try:
            return binascii.unhexlify(s)
        except Exception:
            pass
    try:
        dec = base.t_base64(s.encode(), {})
        if dec:
            return dec
    except Exception:
        pass
    return None


def _xtea_decrypt(blob, key, rounds=32, delta=0x9E3779B9):
    k = struct.unpack(">4I", key)
    out = bytearray()
    mask = 0xFFFFFFFF
    for off in range(0, len(blob), 8):
        v0, v1 = struct.unpack(">2I", blob[off:off + 8])
        s = (delta * rounds) & mask
        for _ in range(rounds):
            v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (s + k[(s >> 11) & 3]))) & mask
            s = (s - delta) & mask
            v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (s + k[s & 3]))) & mask
        out += struct.pack(">2I", v0, v1)
    return out.rstrip(b"\x00").decode("latin-1")


def _rolling_xor(blob, key):
    """Two well-defined position-dependent XOR schemes; accept only an exact code."""
    if not key:
        return None
    for scheme in ("add", "xor"):
        out = bytearray()
        for i, c in enumerate(blob):
            k = key[i % len(key)]
            out.append(c ^ ((k + i) & 0xFF) if scheme == "add" else c ^ k ^ (i & 0xFF))
        code = _exact(bytes(out).decode("latin-1"))
        if code:
            return code
    return None


def _lcg_keystream(blob, doc):
    """A byte keystream from an LCG whose parameters the document states (a, c, m, seed). state' = (a*state+c)
    mod m; the low byte of each state xors the next ciphertext byte. Accept only an exact code."""
    def num(*names):
        for n in names:
            v = doc.get(n)
            if isinstance(v, int):
                return v
        return None
    a = num("a", "mult", "multiplier")
    c = num("c", "inc", "increment")
    m = num("m", "mod", "modulus")
    seed = num("seed", "start", "x0")
    if a is None or seed is None:
        return None
    if c is None:
        c = 0
    if m is None:
        m = 1 << 32
    if m <= 1:
        return None
    state = seed % m
    out = bytearray()
    for byte in blob:
        state = (a * state + c) % m
        out.append(byte ^ (state & 0xFF))
    return _exact(bytes(out).decode("latin-1"))
