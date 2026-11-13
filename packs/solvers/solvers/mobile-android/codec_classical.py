#!/usr/bin/env python3
"""Classical ciphers for codec_search.py, applied only when the puzzle document names them (backlog row 88).

codec_search.py imports this module beside codec_more.py and calls register(), which adds steps bound to
solvers/common/classical.py (the toolkit Warmups already uses):

  autokey     the primer from the document's or the APK's keys; with none that works, a primer of ONE
              letter recovered from the code's first letter (tag primer-searched: the other two letters
              of ANS and every hex letter then check it)
  gronsfeld   a key of digits (a field key, digits, shifts, code or pin); both directions
  variant     the variant Beaufort (key plus letter), keys as for vigenere
  keyboard    QWERTY neighbours: every key one to the right or left (digits and marks move too), and
              letters moved inside their row with wrap-around, one or two keys either way
  polybius    a 6 x 6 square (letters then digits, an optional key first) with the labels 1-6, 0-5 or
              A-F; the square has no '-', so the reading is tagged hyphen-restored
  spelling    ICAO spelling words and figures (alfa november sierra dash zero ...)
  blockrev    blocks of a size the document gives reversed; with no size, the sizes 2 to 10
  swap        neighbouring characters swapped
              (both only where codec_search's own position moves, which read a 20-character code moved in
              chunks of 2, 4, 5 or 10 and offer every move that fits, read nothing: their routes stay)
  enigma      Enigma I / M3 with the document's rotors, reflector, rings, start and plugboard

None is a search move: a document that names no such codec is read exactly as before, and nothing here
can change what a judged codec answers. Under codec_search's fail-closed rule a reading counts only when
it is exactly ANS- plus 16 upper-case hex characters, and it is offered unsure (labels.pick under
mobile.codec/<the document's name>) until the judge accepts its route. A parameter that is searched
(the one-letter primer, a block size, the keyboard move) is kept only when the code's form proves it;
if two searched values ever proved different codes, each would be offered under its own tag.

Not here, because the cipher cannot carry the code: Bacon, the tap code, a 5 x 5 Polybius square, A1Z26
(no digits beside letters), Playfair and bifid (letter pairs only).

Plain Python on the timed path; every loop is bounded by the caller's clock or by a small constant.
"""
import re

try:
    from _shadowed import common_module
    K = common_module("classical")   # solvers/toolkits/classical.py wins a flat import
except Exception:   # a copy of the lane without solvers/common/classical.py: no step is registered
    K = None

MAX_OUT = 4096
SIZES = ("size", "block", "blocksize", "block_size", "n", "k", "width", "key", "length", "group")
DIGIT_KEYS = ("key", "digits", "shifts", "code", "pin", "number", "numeric_key")
SEARCH_SIZES = range(2, 11)
_FORM = re.compile(r"ANS[0-9A-F]{16}")


def _texts(C, d) -> list:
    """The state and what lies under one text encoding of it, as ASCII text (each once)."""
    out = []
    for x in C._layers(d):
        try:
            t = bytes(x).decode("ascii")
        except UnicodeDecodeError:
            continue
        if t and len(t) <= MAX_OUT and t not in out:
            out.append(t)
    return out


def _keys(C, p) -> list:
    """[(text, tag)]: the document's key candidates, then the APK's, that are ASCII text."""
    out = []
    for k, tag in C.key_candidates(p) + [(k, "key-apk") for k in C.APK_KEYS.get("keys", ())]:
        try:
            t = bytes(k).decode("ascii")
        except UnicodeDecodeError:
            continue
        if t.strip() and (t, tag) not in out:
            out.append((t, tag))
    return out


def _tag(*parts) -> str:
    return ":".join(t for t in parts if t)


def _proven(C, found):
    """found [(output, tag)] of a searched parameter: the outputs that are an answer code; one of them
    when they all prove the same code."""
    found = [(o, t) for o, t in found if o and C._proves(o)]
    return C._one(found) or found


def autokey(C, d, p, clock):
    outs = []
    for key, tag in clock.each([(k, t) for k, t in _keys(C, p) if any(c.isalpha() for c in k)][:16]):
        for t in _texts(C, d):
            try:
                outs.append((K.autokey_decrypt(t, key).encode(), tag))
            except ValueError:
                continue
    found = []
    for t in _texts(C, d):
        first = next((c for c in t if c.isalpha()), None)
        if first is None:
            continue
        primer = chr((ord(first.upper()) - 65) % 26 + 97)       # the letter that turns the first letter into A
        found.append((K.autokey_decrypt(t, primer).encode(), "primer-searched"))
    return outs + _proven(C, found)


def gronsfeld(C, d, p, clock):
    outs = []
    for v, tag in clock.each(C.params(p, DIGIT_KEYS)[:8]):
        digits = "".join(str(x) for x in v) if isinstance(v, list) else str(v)
        if isinstance(v, bool) or not re.fullmatch(r"[0-9]{1,64}", digits.replace(" ", "").replace(",", "")):
            continue
        digits = re.sub(r"[ ,]", "", digits)
        key = "".join(chr(97 + int(x)) for x in digits)
        for t in _texts(C, d):
            outs.append((K.gronsfeld_decrypt(t, digits).encode(), tag))
            outs.append((K.vigenere_encrypt(t, key).encode(), _tag("inverse", tag)))
    return outs


def variant(C, d, p, clock):
    outs = []
    for key, tag in clock.each([(k, t) for k, t in _keys(C, p) if any(c.isalpha() for c in k)][:16]):
        k = "".join(c for c in key if c.isalpha())
        for t in _texts(C, d):
            outs.append((K.vigenere_decrypt(t, k, "variant").encode(), tag))
    return outs


def keyboard(C, d, p, clock):
    found = []
    for t in _texts(C, d):
        moves = [("", K.keyboard_shift(t, False)), ("left", K.keyboard_shift(t, True)), ("wrap", K.keyboard_wrap(t, -1)),
                 ("wrap-left", K.keyboard_wrap(t, 1)), ("wrap2", K.keyboard_wrap(t, -2)), ("wrap2-left", K.keyboard_wrap(t, 2))]
        found += [(o.encode(), tag) for tag, o in moves if o]
    return _proven(C, found)


def polybius(C, d, p, clock):
    keys = [("", "")] + [(k, _tag("square", t)) for k, t in _keys(C, p) if k.isalnum()][:8]
    found = []
    for t in _texts(C, d):
        for key, tag in clock.each(keys):
            for labels, ltag in (("123456", ""), ("012345", "labels-0"), ("ABCDEF", "labels-a")):
                try:
                    o = K.polybius_decode(t, key, 6, labels)
                except (ValueError, IndexError):
                    o = None
                o = re.sub(r"\s", "", o).upper() if o else ""
                if _FORM.fullmatch(o):
                    found.append((("ANS-" + o[3:]).encode(), _tag("hyphen-restored", ltag, tag)))
    return _proven(C, found)


def spelling(C, d, p, clock):
    outs = []
    for t in _texts(C, d):
        o = K.spelling_decode(t)
        if o:
            outs.append((o.encode(), ""))
    return outs


def _positional(C, p) -> bool:
    """Whether codec_search's position moves (its step 5: the 20 characters, or those under one text
    layer) already turn the document's data into a code."""
    d = p.get("data") if isinstance(p, dict) else None
    if not isinstance(d, str):
        return False
    if C.positional(p, ""):
        return True
    if 20 < len(d) <= 64:
        for dec in (C.base.t_base64, C.base.t_hex, C.base.t_base32):
            under = dec(d, {})
            if under and len(under) == 20 and under.isascii() and C.positional({"data": under.decode("ascii")}, ""):
                return True
    return False


def blockrev(C, d, p, clock):
    if _positional(C, p):   # codec_search's own position moves read it, and offer every move that fits
        return []
    sizes = []
    for v, tag in C.params(p, SIZES):
        sizes += [(n, tag) for n in C._ints(v) if 2 <= n <= 64]
    texts = _texts(C, d)
    outs = [(K.block_reverse(t, n).encode(), tag) for n, tag in clock.each(sizes[:8]) for t in texts]
    if outs:
        return outs
    return _proven(C, [(K.block_reverse(t, n).encode(), "size-searched:%d" % n) for t in texts
                       for n in clock.each(SEARCH_SIZES)])


def swap(C, d, p, clock):
    if _positional(C, p):
        return []
    return [(K.swap_pairs(t).encode(), "") for t in _texts(C, d)]


ROTOR_FIELDS = ("rotors", "rotor", "wheels", "walzen", "rotor_order")
RING_FIELDS = ("rings", "ring", "ring_settings", "ringstellung", "ring_setting")
START_FIELDS = ("start", "position", "positions", "grundstellung", "key", "message_key", "initial", "window")
PLUG_FIELDS = ("plugboard", "plugs", "stecker", "steckerbrett", "pairs")
REFLECTOR_FIELDS = ("reflector", "ukw", "umkehrwalze")


def _field(C, p, names, default):
    for v, _ in C.params(p, names):
        if isinstance(v, (str, list)) and v:
            return v
    return default


def enigma(C, d, p, clock):
    rotors = _field(C, p, ROTOR_FIELDS, ["I", "II", "III"])
    if isinstance(rotors, str):
        rotors = [x for x in re.split(r"[\s,\-/]+", rotors.upper()) if x]
    rotors = [str(x).upper() for x in rotors]
    reflector = str(_field(C, p, REFLECTOR_FIELDS, "B")).upper().replace("UKW-", "").replace("UKW", "").strip() or "B"
    rings = _field(C, p, RING_FIELDS, "AAA")
    start = _field(C, p, START_FIELDS, "AAA")
    plugs = _field(C, p, PLUG_FIELDS, "")
    if isinstance(plugs, list):
        plugs = " ".join(str(x) for x in plugs)
    if len(rotors) != 3 or any(r not in K.ROTORS for r in rotors) or reflector not in K.REFLECTORS:
        return []

    def three(v):
        if isinstance(v, list):
            return " ".join(str(x) for x in v) if len(v) == 3 else None
        v = str(v).strip()
        return v if len(v) == 3 and v.isalpha() else v if len(v.split()) == 3 else None
    rings, start = three(rings), three(start)
    if rings is None or start is None:
        return []
    outs = []
    for t in _texts(C, d):
        try:
            outs.append((K.enigma(t, rotors, reflector, rings, start, plugs).encode(), ""))
        except (ValueError, IndexError, KeyError):
            continue
    return outs


def steps(C) -> dict:
    """The steps of this module, bound to one instance of codec_search."""
    from functools import partial
    if K is None:
        return {}
    return {"autokey": partial(autokey, C), "gronsfeld": partial(gronsfeld, C), "variant": partial(variant, C),
            "keyboard": partial(keyboard, C), "polybius": partial(polybius, C), "spelling": partial(spelling, C),
            "blockrev": partial(blockrev, C), "swap": partial(swap, C), "enigma": partial(enigma, C)}


NAMES = {
    "auto-key": "autokey", "auto_key": "autokey", "autokey-vigenere": "autokey", "autokey_vigenere": "autokey",
    "autoclave": "autokey",
    "gronsfeld-cipher": "gronsfeld", "gronsfeld_cipher": "gronsfeld",
    "variant-beaufort": "variant", "variant_beaufort": "variant", "variantbeaufort": "variant",
    "qwerty": "keyboard", "keyboard-shift": "keyboard", "keyboard_shift": "keyboard", "kbd": "keyboard",
    "keyshift": "keyboard", "key-shift": "keyboard", "key_shift": "keyboard", "qwerty-shift": "keyboard",
    "qwerty_shift": "keyboard", "keyboard-cipher": "keyboard", "keyboard_cipher": "keyboard",
    "polybius-square": "polybius", "polybius_square": "polybius", "polybius6": "polybius",
    "nato": "spelling", "icao": "spelling", "phonetic": "spelling", "nato-phonetic": "spelling",
    "nato_phonetic": "spelling", "phonetic-alphabet": "spelling", "phonetic_alphabet": "spelling",
    "spelling-alphabet": "spelling", "spelling_alphabet": "spelling",
    "block-reverse": "blockrev", "block_reverse": "blockrev", "reverse-blocks": "blockrev",
    "reverse_blocks": "blockrev", "blockreverse": "blockrev", "chunk-reverse": "blockrev", "chunk_reverse": "blockrev",
    "swap-pairs": "swap", "swap_pairs": "swap", "swappairs": "swap", "pair-swap": "swap", "pair_swap": "swap",
    "pairswap": "swap",
    "enigma-m3": "enigma", "enigma_m3": "enigma", "enigma-i": "enigma", "enigma_i": "enigma", "enigma1": "enigma",
}


def register(C) -> None:
    """Add this module's steps to one codec_search instance's tables: only names nothing there has yet."""
    for name, fn in steps(C).items():
        if name not in C.KEYED and name not in C.STEP and name not in C.base.NAMED and name not in C.ALIASES:
            C.KEYED[name] = fn
    for alias, name in NAMES.items():
        if (name in C.KEYED and alias not in C.ALIASES and alias not in C.KEYED and alias not in C.STEP
                and alias not in C.base.NAMED and alias not in C.JOIN and alias not in C.WEAVE and alias not in C.SHIFTS):
            C.ALIASES[alias] = name
