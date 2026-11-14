"""Single-byte XOR under a flag crib (B-029): a hex or base64 run that decodes to bytes XORed with one key.

    hits = single_byte(decoded, ff)        # [(key, offset, flag)] for keys 1..255

Gated three ways, because 255 keys over every decoded token of a corpus is a lot of chances for noise:

- the event's flag format: the XORed bytes hold a whole flag (prefix, braces, body), never a prefix
  alone; an event whose prefixes are not known yet (`ff.known` False) is not cribbed at all, since any
  word then passes as a prefix;
- the flag is printable ASCII throughout;
- and either the whole XORed token reads as text (PLAINTEXT_RATIO of it printable: the hex run *is* the
  encrypted message) or the flag's body is at least LONG_BODY characters. A short prefix like `CTF`,
  prefix-insensitive, otherwise turns up in random bytes under some key.

A key is tried only when both brace bytes occur under it (worked out from the distinct bytes, so a short
token costs a few set operations). Input past MAX_INPUT is not read.
"""
from __future__ import annotations

MAX_INPUT = 1 << 20
ENCODINGS = ("hex", "base64")    # the sweep cribs these runs (embedded_decode names), not base32 or misaligned
                                 # base64: those triple the tokens of a text corpus for a rare case
PLAINTEXT_RATIO = 0.85
LONG_BODY = 12
_TABLES = [bytes(b ^ k for b in range(256)) for k in range(256)]
_TEXT = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def _printable(b: bytes) -> float:
    return sum(c in _TEXT for c in b) / len(b) if b else 0.0


def single_byte(data: bytes, ff) -> list[tuple[int, int, str]]:
    if not ff.known or not data or len(data) > MAX_INPUT:
        return []
    out = []
    present = set(data)
    # the keys under which both braces occur: one pass over the distinct bytes, not 255 over the data
    keys = ({b ^ 0x7B for b in present} & {b ^ 0x7D for b in present}) - {0}
    for k in sorted(keys):
        plain = data.translate(_TABLES[k])
        texty = None
        for m in ff.bregex.finditer(plain):
            flag = m.group(0)
            if not all(0x20 <= c < 0x7F for c in flag):
                continue
            body = len(flag) - flag.index(b"{") - 2
            if body < LONG_BODY:
                if texty is None:
                    texty = _printable(plain) >= PLAINTEXT_RATIO
                if not texty:
                    continue
            out.append((k, m.start(), flag.decode("ascii")))
    return out
