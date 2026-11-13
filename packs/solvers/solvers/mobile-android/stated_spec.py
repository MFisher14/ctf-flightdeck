#!/usr/bin/env python3
"""Mobile, the Day 21 build, round 3 (item 3): a decoding the package or the question STATES in words.

Binary's stated_layout.py reads a wrapper the way the day's own question text spells it out. The Mobile lane's
spec is the puzzle document (`codec`, `data`, `key`, `parts`, `order`: codec_search reads every field of it), and
through Day 20 neither the document nor the question ever said more in prose: the 20 documents of Days 1 to 20 hold
no text field beside `schema`, `day`, `codec`, `data` and the codec's parameters, and the 20 question texts are one
sentence of narrative and `Submit only the exact backend answer code returned for this case.` (the build's mining
of the saved attempts). A document may still bring a recipe in words (`"hint": "Base64-decode the data field, XOR
every byte with 0x2a, then reverse it."`) beside a codec name no reader applies, or the question may say where the
code is (`the code stored in assets/payload.bin`). This module reads such a sentence into a pipeline and carries it
out on the bytes, never inventing a fact: the result must be an exact answer code.

Where the text is read:

  the document  each text value of a prose field of assets/huntress_puzzle.json (`hint`, `note`, `notes`,
                `description`, `instructions`, `instruction`, `how`, `howto`, `how_to`, `recipe`, `spec`,
                `contract`, `readme`, `comment`, `procedure`, `method`, `decode`, `decoding`, `transform`, `steps`,
                `recovery`; a list of strings is one step each), at most PROSE_CHARS characters a field
  the question  the question's text and the attempt's prompt: only a sentence that names a member path or a step

The grammar (a text is split into segments at `;`, `.`, `,`, `then`, `->`, `>`, `first`/`next`/`finally`, numbered
steps; each segment is read on its own):

  steps     base64 (`base64-decode`, `decode the base64`, `from base64`, url-safe), base32, hex (`hex-decode`,
            `from hex`, `unhex`), reverse, rot13, rot47, atbash, a letter shift with a stated direction (`shift
            each letter back by 3`), a byte add or subtract (`subtract 7 from each byte`), XOR with a stated key (a
            literal `0x2a` or `42`, a quoted text, `the key`, `the <name> field`), zlib/gzip/raw inflate
            (`decompress`, `inflate`, `gunzip`), URL decoding, and a slice (`take the first N bytes`, `skip the first
            N bytes`, `N bytes at offset M`). A segment that is just a codec name (`base64 > xor > reverse`) is that
            step, with the document's own `key` for xor. Keyed: RC4, Vigenere, AES-ECB/CBC, a permutation by a
            stated order; B-249 adds AES-GCM (ciphertext then a verified 16-byte tag; key and nonce stated),
            ChaCha20 (key and nonce stated), XTEA (ECB, 16-byte key), a keyed columnar transposition (`columnar
            transposition with keyword 'ZEBRA'`, a keyword field, `N columns`), a block reverse (`reverse each block
            of 4 bytes`), a substitution table (`translate 'QWE..' to 'ABC..'`, or a {char: char} field), and a
            lookup of integer indices into a stated table (`look up each index in the alphabet field`)
  keys      a quoted text, hex, `the key`, a named field, a PBKDF2 derivation with stated password, salt and count,
            and (B-249) a hash of a stated text (`the key is the SHA-256 of 'pw'`, `the first 16 bytes of the MD5
            of the passphrase field`); the route names the key's origin, never its value
  source    `the <name> field` (default: `data`), a member path (`read assets/blob.bin`, `stored in res/raw/x`),
            `the member the data field names`; a `data` that is a member's path is that member's bytes
  rule      every other word of a segment that holds a step or a source must be filler (`the`, `each`, `byte`,
            `result`, `answer`, `code`, ...); a segment with no step whose words name an action no step here reads
            (`decode me`, `decrypt`, `unscramble`, `permute`) makes the whole text no spec; a segment with neither
            is narrative and is passed over. An xor or a shift whose key or amount is not stated gives no spec.

What it gives (`read(doc, members, texts)`): (code, route, steps) when every text that states a pipeline gives the
same exact code (the whole result is `ANS-` and 16 uppercase hex digits; from a member's bytes, exactly one code in
the result), else None (`conflict` beside it when two texts give two codes). codec_search.stated_revise turns that
into the answer: a code where the usual reading has none is a one-option pick under `mobile.codec/stated+<steps>`
(route `stated:<steps>`, the steps by name and the key's origin, never a value: the same route on every variant);
a code that differs from the usual reading makes the answer unsure under `<the codec's key>:stated`, the stated
code first and the usual reading after it (a decoy `data` beside a recipe that reads elsewhere is never sent plain);
a code equal to the usual reading changes nothing. Every hit prints one stderr line `NOTE mobile stated: ...`
(the day-review marker `mobile-stated-spec`). Bounded by sizes (PROSE_CHARS, MAX_STEPS, MAX_BYTES), never by a
clock: the same package gives the same answer on the base, in the gate's replay and on a clock.
"""
import base64
import binascii
import bz2
import codecs
import gzip
import hashlib
import json
import lzma
import re
import struct
import urllib.parse
import zlib

ANS_WHOLE = re.compile(r"ANS-[0-9A-F]{16}")
ANS_ANY = re.compile(rb"(?<![0-9A-Za-z])ANS-[0-9A-F]{16}(?![0-9A-Za-z])")
PUZZLE = "assets/huntress_puzzle.json"
PROSE_FIELDS = ("hint", "hints", "note", "notes", "description", "instructions", "instruction", "how", "howto",
                "how_to", "recipe", "spec", "specification", "contract", "readme", "comment", "comments", "procedure",
                "method", "decode", "decoding", "transform", "steps", "recovery", "recover")
PROSE_CHARS = 1000        # characters of one text that are read
MAX_TEXTS = 8             # texts read in all (document fields, list items, question, prompt)
MAX_STEPS = 8             # steps of one pipeline
MAX_BYTES = 1 << 20       # bytes of a state (a member, an inflated body)
MAX_DEX = 4               # dex members whose string table is searched for a stated recipe (gap c)
MAX_DEX_TEXTS = 8         # recipe strings taken from the dex tables in all
MAX_DEX_SCAN = 1 << 20    # bytes of a dex scanned for the cheap has_dex_recipe() pre-check

NUM = r"(0x[0-9a-f]{1,8}|\d{1,6})"
QUOTED = r"[`\"']([^`\"']{1,64})[`\"']"
FIELD = r"(?:the\s+)?(?:value\s+(?:of|in)\s+(?:the\s+)?)?[`\"']?([a-z_][a-z0-9_]{0,31})[`\"']?\s+(?:field|key|property|entry|value)\b"
PATH = r"[`\"']?((?:assets|res|lib|raw|meta-inf|root|files|data)/[a-z0-9_./!-]+|[a-z0-9_-]+\.(?:bin|dat|dex|txt|json|so|enc|blob|raw|jar|apk|zip|gz|db))[`\"']?"

FILLER = set("""
the a an it its this that these those each every all whole entire one byte bytes character characters char chars letter
letters value values string strings text data field fields result results output it's then and to get obtain recover
recovers recovered reveal reveals gives give given yields yield is are be will of from with using use by in into on
apply applying take taking read reading start starting answer answers code codes ans back step steps now you your
should must can which as at for contents content payload member file final original plaintext them they once again
after before has have been was were stored below above following order process note simply just
document states stated named names shown here there what result's backend case submit returned exact
first second third next finally lastly afterwards
""".split())
ACTION = re.compile(r"\b(?:decod\w*|decrypt\w*|deciph\w*|unscrambl\w*|unshuffl\w*|permut\w*|rotat\w*|shift\w*|swap\w*|"
                    r"transpos\w*|substitut\w*|translat\w*|convert\w*|transform\w*|xor\w*|invert\w*|undo\w*|unpack\w*|"
                    r"decompress\w*|interleav\w*|deinterleav\w*|sort\w*|map\w*|lookup|index\w*|rearrang\w*|reorder\w*|"
                    r"join\w*|concatenat\w*|split\w*|cipher\w*|encod\w*|skip\w*|drop\w*|remov\w*|strip\w*|trim\w*|"
                    r"cut\w*|keep\w*|take|discard\w*|ignor\w*|prepend\w*|append\w*|pad\w*|add|subtract\w*|repeat\w*|caesar\w*|"
                    r"vigen\w*|beaufort|affine|rail\w*|base\d+|ascii85|a85|z85|bzip2?|bz2|xz|lzma|brotli|zstd|complement\w*|"
                    r"nibble\w*|hex\w*|rot\d*|atbash|zlib|gzip|deflat\w*)\b", re.I)

# Segments end at ; . : , `then` -> => an arrow > `and` before a step word, and a numbered step (`1.`, `step 2:`).
# A sequence word (first, next, finally) is never a boundary: `skip the first 7 bytes` is one step, and the word
# is filler where it stands at the start of a segment.
SPLIT = re.compile(r";|\n|:\s|\.(?=\s|$)|,\s*|\s+then\s+|\s*(?:->|=>|\u2192|>)\s*|\s+and\s+(?=(?:then\s+)?(?:base|hex|un|"
                   r"rev|rot|xor|sub|add|shift|inflat|decom|gunz|url|take|skip|keep|drop|atbash|decod|read)\w*)|"
                   r"(?:^|\s)\(?\d[.)]\s+|\bstep\s+\d+\s*:", re.I)

# (name, compiled pattern, builder(match, doc) -> step tuple | None (an unread parameter: no spec))
B64 = r"base[- ]?64"
STEPS = []


def _step(name, pattern):
    def deco(fn):
        STEPS.append((name, re.compile(pattern, re.I), fn))
        return fn
    return deco


@_step("base64url", r"\b(?:url[- ]?safe\s+" + B64 + r"|" + B64 + r"[- ]?url)(?:[- ]?decod\w*)?\b")
def _b64url(m, doc):
    return ("base64url",)


@_step("base64", r"\b" + B64 + r"[- ]?decod\w*\b|\bdecod\w*\s+(?:the\s+|it\s+|them\s+)?(?:from\s+|as\s+|with\s+)?" + B64 +
       r"\b|\bfrom\s+" + B64 + r"\b|\bun-?base[- ]?64\w*\b|\b" + B64 + r"\b(?=\s+(?:text|string|data|value)?\s*$)")
def _b64(m, doc):
    return ("base64",)


@_step("base32", r"\bbase[- ]?32[- ]?decod\w*\b|\bdecod\w*\s+(?:the\s+|it\s+)?(?:from\s+|as\s+)?base[- ]?32\b|\bfrom\s+"
       r"base[- ]?32\b")
def _b32(m, doc):
    return ("base32",)


@_step("hex", r"\bhex(?:adecimal)?[- ]?decod\w*\b|\bdecod\w*\s+(?:the\s+|it\s+)?(?:from\s+|as\s+)?hex(?:adecimal)?\b|"
       r"\bfrom\s+hex(?:adecimal)?\b|\bunhex\w*\b")
def _hex(m, doc):
    return ("hex",)


@_step("reverse", r"\brevers(?:e|ed|es|ing)\b|\bread\s+(?:it\s+)?backwards?\b|\bin\s+reverse(?:\s+order)?\b")
def _rev(m, doc):
    return ("reverse",)


@_step("rot13", r"\brot[- ]?13\b")
def _rot13(m, doc):
    return ("rot13",)


@_step("rot47", r"\brot[- ]?47\b")
def _rot47(m, doc):
    return ("rot47",)


@_step("atbash", r"\batbash\b")
def _atbash(m, doc):
    return ("atbash",)


@_step("letters", r"\bshift\s+(?:each\s+|every\s+|all\s+)?(?:the\s+)?letters?\s+(back(?:wards?)?|forwards?|left|right|down|up)"
       r"\s+by\s+" + NUM + r"\b")
def _letters(m, doc):
    n = _int(m.group(2))
    return ("letters", -n if m.group(1).startswith(("back", "left", "down")) else n)


@_step("bytes", r"\b(?:subtract|minus)\s+" + NUM + r"\s+from\s+(?:each|every|all)\s+(?:the\s+)?(?:bytes?|characters?|chars?)\b|"
       r"\badd\s+" + NUM + r"\s+to\s+(?:each|every|all)\s+(?:the\s+)?(?:bytes?|characters?|chars?)\b|"
       r"\bshift\s+(?:each|every|all)\s+(?:the\s+)?(?:bytes?|characters?|chars?)\s+(back(?:wards?)?|forwards?|left|right|down|up)"
       r"\s+by\s+" + NUM + r"\b")
def _bytes(m, doc):
    if m.group(1):
        return ("add", -_int(m.group(1)))
    if m.group(2):
        return ("add", _int(m.group(2)))
    n = _int(m.group(4))
    return ("add", -n if m.group(3).startswith(("back", "left", "down")) else n)


@_step("xor", r"\bxor(?:ed|ing)?\b(?:\s+(?:each|every|all)\s+(?:the\s+)?(?:bytes?|characters?|chars?))?(?:\s+(?:it|them|"
       r"the\s+(?:bytes?|data|result|text)))?(?:\s+(?:with|using|against|by)\s+(?:the\s+)?(?:(?:one-?byte|single-?byte|"
       r"repeating|byte)\s+)?(?:key\s+)?(?:" + QUOTED + r"|" + NUM + r"\b|" + FIELD + r"|(?P<thekey>key)\b))?")
def _xor(m, doc):
    if m.group(1):
        return ("xor", m.group(1).encode("utf-8"), "text")
    if m.group(2):
        n = _int(m.group(2))
        return ("xor", bytes([n]), "literal") if n < 256 else None
    name = m.group(3) or (m.group("thekey") and "key")
    if not name:
        # a bare `xor` (`base64 -> xor`) is keyed by the document's own `key` field, as the codec `xor` is; an xor
        # with any other word and no key stated gives no spec
        return _key_field(doc, "key") if m.group(0).strip() == "xor" else None
    return _key_field(doc, name)


# Registered BEFORE inflate so a stated bzip2/xz/lzma stage claims its whole span first: the generic `decompress`
# branch of inflate (zlib/gzip) would otherwise shadow it. These algos never fall through to inflate.
@_step("decompress2", r"\b(?P<a1>bzip2?|bz2|xz|lzma)[- ]?(?:decompress\w*|decod\w*|inflat\w*)\b|"
       r"\b(?:de)?compress(?:ed|ion)?\s+(?:it\s+|them\s+|the\s+\w+\s+)?(?:with|as|using|via|from)\s+(?:the\s+)?"
       r"(?P<a2>bzip2?|bz2|xz|lzma)\b|\bbun?zip2?\w*\b|\bun(?P<a3>xz|lzma)\w*\b")
def _decompress2(m, doc):
    algo = (m.group("a1") or m.group("a2") or m.group("a3") or "bz2").lower()
    if m.group(0).lower().startswith(("bunzip", "bzip")) or algo.startswith("bz"):
        algo = "bz2"
    return ("decompress2", algo)


@_step("inflate", r"\b(?:as|in)\s+(?:zlib|gzip|deflate)(?:[- ]?(?:compressed|data|stream))?\b|\b(?:zlib|gzip)[- ]compressed\b|"
       r"\b(?:zlib[- ]?(?:decompress\w*|inflat\w*)|inflat(?:e|ed|es|ing)|(?<![-\w])decompress(?:ed|es|ing)?(?:\s+with\s+"
       r"(?:zlib|gzip|deflate))?|gunzip\w*|gzip[- ]decompress\w*|un-?gzip\w*)\b")
def _inflate(m, doc):
    return ("inflate",)


@_step("url", r"\b(?:url|percent)[- ]?decod\w*\b|\bdecod\w*\s+(?:the\s+)?(?:url|percent)[- ]?(?:encoding|escapes)\b")
def _url(m, doc):
    return ("url",)


@_step("slice", r"\b(?:take|keep|use)\s+(?:only\s+)?the\s+(first|last)\s+" + NUM + r"\s+(?:bytes|characters|chars)\b|"
       r"\b(?:skip|drop|remove|strip)\s+the\s+(first|last)\s+" + NUM + r"\s+(?:bytes|characters|chars)\b|"
       r"\b" + NUM + r"\s+bytes\s+(?:starting\s+)?at\s+(?:offset\s+)?" + NUM + r"\b")
def _slice(m, doc):
    if m.group(1):
        n = _int(m.group(2))
        return ("slice", 0, n) if m.group(1) == "first" else ("slice", -n, None)
    if m.group(3):
        n = _int(m.group(4))
        return ("slice", n, None) if m.group(3) == "first" else ("slice", 0, -n if n else None)
    return ("slice", _int(m.group(6)), _int(m.group(5)), "at")


# --- keyed ciphers, a key derivation and a permutation, all stated in words (Day 21 round 3 gaps) ------------
# Each matches its cipher name and takes the REST of the segment as a clause; the builder reads the key (and, for
# AES, the IV and mode) the clause states, and gives None (so the text is no spec) when a required parameter is not
# stated. The key's VALUE never reaches the route: route_of() names only its origin, so every variant shares a key.

@_step("rc4", r"\b(?:rc4|arc4|arcfour)(?:[- ](?:decrypt|decode|cipher|decipher))?\b(?P<clause>.*)$")
def _rc4(m, doc):
    k = _cipher_key(m.group("clause"), doc)
    return ("rc4", k[0], k[1]) if k else None


@_step("vigenere", "\\b(?:vigenere|vigen\u00e8re)(?:[- ](?:decrypt|decode|cipher|decipher))?\\b(?P<clause>.*)$")
def _vigenere(m, doc):
    k = _cipher_key(m.group("clause"), doc)
    if not k:
        return None
    letters = bytes(c for c in k[0] if 65 <= c <= 90 or 97 <= c <= 122)
    return ("vigenere", letters, k[1]) if letters else None


@_step("aes", r"\baes(?:[- ]?(?:128|192|256))?(?:[- ]?(?:ecb|cbc))?(?:[- ](?:decrypt|decode|cipher|decipher))?\b"
       r"(?P<clause>.*)$")
def _aes(m, doc):
    low = m.group(0).lower()
    bits = re.search(r"\baes[- ]?(128|192|256)\b", low)
    want = {"128": 16, "192": 24, "256": 32}[bits.group(1)] if bits else None
    k = _cipher_key(m.group("clause"), doc, want)
    if not k or len(k[0]) not in (16, 24, 32) or (want and len(k[0]) != want):
        return None
    iv = _aes_iv(m.group("clause"))
    if iv is not None and len(iv) != 16:
        return None
    mode = "cbc" if re.search(r"\bcbc\b", low) else "ecb" if re.search(r"\becb\b", low) else ("cbc" if iv else "ecb")
    if mode == "cbc" and iv is None:
        return None
    return ("aes", k[0], iv, mode, k[1])


@_step("permute", r"\b(?:permute|permutation|reorder|re-order|rearrange|unscramble|deinterleave|transpose)"
       r"(?:[- ](?:the\s+)?(?:bytes|characters|chars))?\b(?P<clause>.*)$")
def _permute(m, doc):
    o = _order(m.group("clause"), doc)
    if not o or len(o[0]) > 256 or sorted(o[0]) != list(range(len(o[0]))):
        return None
    return ("permute", o[0], o[1])


# --- more stated decode/transform verbs (wave70): text encodings, a wider decompression family, byte rotation and
# a bit complement / nibble swap. Every one is a deterministic byte transform, so a wrong reading gives no exact
# code and the text yields no spec (fail closed); the result must still be the whole ANS code or one in a member.

@_step("base85", r"\bbase[- ]?85[- ]?decod\w*\b|\bdecod\w*\s+(?:the\s+|it\s+)?(?:from\s+|as\s+)?base[- ]?85\b|"
       r"\bfrom\s+base[- ]?85\b")
def _base85(m, doc):
    return ("base85",)


@_step("ascii85", r"\bascii[- ]?85[- ]?decod\w*\b|\ba85[- ]?decod\w*\b|\bdecod\w*\s+(?:the\s+|it\s+)?(?:from\s+|as\s+)?"
       r"ascii[- ]?85\b|\bfrom\s+ascii[- ]?85\b")
def _ascii85(m, doc):
    return ("ascii85",)


@_step("z85", r"\bz85[- ]?decod\w*\b|\bdecod\w*\s+(?:the\s+|it\s+)?(?:from\s+|as\s+)?z85\b|\bfrom\s+z85\b")
def _z85step(m, doc):
    return ("z85",)


@_step("rotate", r"\brotate\s+(?:each|every|all)?\s*(?:the\s+)?(?:bytes?|characters?|chars?)\s+(?P<dir>left|right)"
       r"\s+by\s+" + NUM + r"\b")
def _rotate(m, doc):
    n = _int(m.group(m.lastindex)) % 8
    return ("rol" if m.group("dir").lower() == "left" else "ror", n)


@_step("complement", r"\b(?:invert|complement|flip)\s+(?:all\s+|each\s+|every\s+|the\s+)?(?:bits\s+(?:of\s+)?)?"
       r"(?:the\s+)?(?:bytes?|characters?|chars?|data|result)?\b|\bone'?s[- ]?complement\b|\bbitwise[- ]?not\b|"
       r"\bbit-?wise\s+complement\b")
def _complement(m, doc):
    return ("complement",)


@_step("nibble", r"\bswap\s+(?:the\s+)?nibbles?\b(?:\s+(?:of|in)\s+(?:each|every|all)?\s*(?:the\s+)?"
       r"(?:bytes?|characters?|chars?))?|\bnibble[- ]?swap\w*\b")
def _nibble(m, doc):
    return ("nibble",)


# --- B-249: the stated recipes the look-ahead readers deferred to this module ("a stated permutation/table/keyed-block
# cipher in words", lookahead_readers.py; AES-GCM / ChaCha20 / a key derived by a hash). Each is a deterministic byte
# transform with every parameter stated; a wrong reading gives no exact code, so the text gives no code (fail closed).
# A step that must claim its span before a broader one (AES-GCM before AES, a block reverse before reverse, a keyed
# columnar transposition before permute) is registered in front of it.

def _step_before(anchor, name, pattern):
    def deco(fn):
        at = next(i for i, (n, _rx, _b) in enumerate(STEPS) if n == anchor)
        STEPS.insert(at, (name, re.compile(pattern, re.I), fn))
        return fn
    return deco


@_step_before("aes", "aes-gcm", r"\baes(?:[- ]?(?:128|192|256))?[- ]?gcm\b(?:[- ](?:decrypt|decode|decipher))?"
              r"(?P<clause>.*)$")
def _aes_gcm(m, doc):
    """AES-GCM with a stated key and nonce; `data` is the ciphertext followed by its 16-byte tag (verified)."""
    low = m.group(0).lower()
    bits = re.search(r"\baes[- ]?(128|192|256)\b", low)
    want = {"128": 16, "192": 24, "256": 32}[bits.group(1)] if bits else None
    k = _cipher_key(m.group("clause"), doc, want)
    if not k or len(k[0]) not in (16, 24, 32) or (want and len(k[0]) != want):
        return None
    nonce = _nonce(m.group("clause"), doc)
    if nonce is None or not 8 <= len(nonce) <= 16:
        return None
    return ("aes-gcm", k[0], nonce, k[1])


@_step("chacha20", r"\bchacha[- ]?20\b(?:[- ](?:decrypt|decode|decipher))?(?P<clause>.*)$")
def _chacha20(m, doc):
    """ChaCha20 (counter 0) with a stated 32-byte key and an 8- or 12-byte nonce."""
    k = _cipher_key(m.group("clause"), doc, 32)
    if not k or len(k[0]) != 32:
        return None
    nonce = _nonce(m.group("clause"), doc)
    if nonce is None or len(nonce) not in (8, 12):
        return None
    return ("chacha20", k[0], nonce, k[1])


@_step("xtea", r"\bxtea\b(?:[- ](?:ecb|decrypt|decode|decipher))*(?P<clause>.*)$")
def _xtea(m, doc):
    """XTEA (64 rounds of the 32-cycle schedule, big-endian words, ECB) with a stated 16-byte key."""
    k = _cipher_key(m.group("clause"), doc, 16)
    if not k or len(k[0]) != 16:
        return None
    return ("xtea", k[0], k[1])


@_step_before("permute", "columnar", r"\b(?:keyed\s+)?columnar(?:\s+transposition)?\b(?:[- ](?:decrypt|decode))?"
              r"(?P<clause>.*)$")
def _columnar(m, doc):
    """A columnar transposition DECODE under a stated keyword (quoted, or a field) or a stated column count."""
    clause = m.group("clause")
    kw = re.search(r"\b(?:key\s*word|keyword|key)\s+(?:is\s+|=\s*|of\s+|:\s*)?" + QUOTED, clause, re.I)
    if kw:
        word, origin = kw.group(kw.lastindex), "text"
    else:
        f = re.search(r"\b(?:key\s*word|keyword|key)\s+(?:is\s+|=\s*|:\s*)?(?:the\s+)?" + FIELD, clause, re.I)
        n = re.search(r"\b" + NUM + r"\s+columns\b", clause, re.I)
        if f:
            v = _doc_value(doc, f.group(f.lastindex))
            word, origin = (v, "field:" + f.group(f.lastindex).lower()) if isinstance(v, str) else (None, None)
        elif n:
            word, origin = int(_int(n.group(1))), "columns"
        else:
            return None
    perm = _col_perm(word)
    return ("columnar", tuple(perm), origin) if perm else None


@_step_before("reverse", "block-reverse", r"\brevers(?:e|ing)\s+(?:each|every)\s+(?:block\s+of\s+)?" + NUM +
              r"[- ]?(?:bytes?|characters?|chars?)(?:[- ]blocks?)?\b|\brevers(?:e|ing)\s+(?:each|every)\s+" + NUM +
              r"[- ](?:byte|character|char)[- ]blocks?\b")
def _block_reverse(m, doc):
    n = _int(m.group(1) or m.group(2))
    return ("block-reverse", n) if 2 <= n <= 64 else None


@_step("translate", r"\b(?:translat\w*|substitut\w*|map(?:ping)?)\b(?P<clause>.*)$")
def _translate(m, doc):
    """A stated substitution table: `translate 'QWE...' to 'ABC...'` (two quoted alphabets of one length, no
    character twice in either) or `substitute ... the <name> field` whose value is a {char: char} map."""
    clause = m.group("clause")
    pair = re.search(QUOTED + r"\s+(?:to|into|->|=>|onto)\s+" + QUOTED, clause, re.I)
    if pair:
        src, dst = pair.group(1), pair.group(2)
        if len(src) != len(dst) or len(set(src)) != len(src) or len(set(dst)) != len(dst):
            return None
        return ("translate", tuple(zip(src, dst)), "text")
    f = re.search(FIELD, clause, re.I)
    if f:
        v = _doc_value(doc, f.group(1))
        if (isinstance(v, dict) and 0 < len(v) <= 256 and all(isinstance(a, str) and len(a) == 1 and isinstance(b, str)
                                                                and len(b) == 1 for a, b in v.items())
                and len(set(v.values())) == len(v)):
            return ("translate", tuple(sorted(v.items())), "field:" + f.group(1).lower())
    return None


@_step("lookup", r"\b(?:look\s*(?:it\s+|them\s+|each\s+\w+\s+)?up|indices\s+into|indexes\s+into|index\s+into)\b"
       r"(?P<clause>.*)$")
def _lookup(m, doc):
    """The state is integer indices (digits separated by any non-digit) into a stated table: a quoted text, or a
    document field that is a text or a list of one-character texts. 0-based unless the clause says 1-based."""
    clause = m.group("clause")
    q = re.search(QUOTED, clause)
    table, origin = None, None
    if q:
        table, origin = q.group(1), "text"
    else:
        f = re.search(r"(?:the\s+)?[`\"']?([a-z_][a-z0-9_]{0,31})[`\"']?\s+(?:field|table|alphabet|list|array)\b",
                      clause, re.I)
        if f:
            v = _doc_value(doc, f.group(1))
            if isinstance(v, list) and v and all(isinstance(x, str) and len(x) == 1 for x in v):
                v = "".join(v)
            if isinstance(v, str) and v:
                table, origin = v, "field:" + f.group(1).lower()
    if not table:
        return None
    base = 1 if re.search(r"\b(?:1|one)[- ]based\b", clause, re.I) else 0
    return ("lookup", table, base, origin)


def _doc_value(doc, name):
    if not isinstance(doc, dict) or not isinstance(name, str):
        return None
    hit = [k for k in doc if isinstance(k, str) and k.lower() == name.lower()]
    return doc[hit[0]] if len(hit) == 1 else None


def _nonce(clause, doc):
    """The nonce (or IV) a clause states: hex (`nonce hex 00..`, `nonce 0x..`), a quoted text, or a document field."""
    m = re.search(r"\b(?:nonce|iv)\s+(?:in\s+)?hex\s+(?:is\s+|=\s*|:\s*)?[`\"']?([0-9a-fA-F]{16,32})[`\"']?", clause, re.I)
    if m and len(m.group(1)) % 2 == 0:
        return bytes.fromhex(m.group(1))
    m = re.search(r"\b(?:nonce|iv)\s+(?:is\s+|=\s*|:\s*)?0x([0-9a-fA-F]{16,32})\b", clause, re.I)
    if m and len(m.group(1)) % 2 == 0:
        return bytes.fromhex(m.group(1))
    m = re.search(r"\b(?:nonce|iv)\s+(?:is\s+|=\s*|of\s+|:\s*)?" + QUOTED, clause, re.I)
    if m:
        return m.group(m.lastindex).encode("utf-8")
    m = re.search(r"\b(?:nonce|iv)\s+(?:is\s+|=\s*|:\s*)?(?:the\s+)?" + FIELD, clause, re.I)
    if m:
        v = _doc_value(doc, m.group(m.lastindex))
        if isinstance(v, str) and re.fullmatch(r"(?:[0-9a-fA-F]{2}){8,16}", v):
            return bytes.fromhex(v)
        if isinstance(v, str) and 8 <= len(v) <= 16:
            return v.encode("utf-8")
    return None


def _col_perm(word):
    """The column ranks a keyword gives (its letters ranked, ties left to right; codec_more._col_perm's rule) or a
    column count (the columns in order); None for anything else."""
    if isinstance(word, int) and not isinstance(word, bool):
        return list(range(word)) if 2 <= word <= 64 else None
    if isinstance(word, str) and 2 <= len(word) <= 64 and word.isalnum() and not word.isdigit():
        order = sorted(range(len(word)), key=lambda i: (word[i].upper(), i))
        perm = [0] * len(word)
        for rank, i in enumerate(order):
            perm[i] = rank
        return perm
    return None


BARE = {"base64": ("base64",), "b64": ("base64",), "base64url": ("base64url",), "base32": ("base32",), "hex": ("hex",),
        "unhex": ("hex",), "reverse": ("reverse",), "reversed": ("reverse",), "rot13": ("rot13",), "rot47": ("rot47",),
        "atbash": ("atbash",), "zlib": ("inflate",), "gzip": ("inflate",), "inflate": ("inflate",),
        "deflate": ("inflate",), "urldecode": ("url",), "xor": "xor",
        "base85": ("base85",), "b85": ("base85",), "ascii85": ("ascii85",), "a85": ("ascii85",), "z85": ("z85",),
        "bzip2": ("decompress2", "bz2"), "bz2": ("decompress2", "bz2"), "bunzip2": ("decompress2", "bz2"),
        "xz": ("decompress2", "xz"), "lzma": ("decompress2", "lzma"), "complement": ("complement",),
        "nibbleswap": ("nibble",)}
SOURCE_MEMBER = re.compile(r"\b(?:read|take|load|open|start\s+(?:with|from)|from|in|inside|use|stored\s+(?:in|at|under)|"
                           r"kept\s+in|held\s+in|found\s+in|located\s+(?:in|at)|lives\s+in|of)\s+(?:the\s+)?(?:bytes\s+of\s+"
                           r"(?:the\s+)?)?(?:member|file|asset|resource|entry)?\s*" + PATH, re.I)
SOURCE_NAMED = re.compile(r"\b(?:the\s+)?(?:member|file|asset|path)\s+(?:that\s+)?(?:the\s+)?[`\"']?data[`\"']?\s+"
                          r"(?:field\s+)?names\b|\b(?:the\s+)?(?:member|file|asset)\s+named\s+(?:in|by)\s+(?:the\s+)?"
                          r"[`\"']?data[`\"']?(?:\s+field)?\b", re.I)
SOURCE_FIELD = re.compile(r"\b(?:read|take|use|start\s+(?:with|from)|from|decod\w*|base[- ]?64[- ]?decod\w*|hex[- ]?decod\w*|"
                          r"of)\s+" + FIELD, re.I)


QUESTION_TRIGGER = re.compile(r"(?:assets|res|lib|raw|meta-inf|root|files|data)/|\.(?:bin|dat|dex|txt|json|so|enc|blob|raw|"
                              r"jar|apk|zip|gz|db)\b|base[- ]?(?:64|32|85)|ascii[- ]?85|\bz85\b|hex|revers|\brot[- ]?(?:13|47)|"
                              r"atbash|xor|inflat|decompress|gunzip|bun?zip|\bbz2\b|\bxz\b|\blzma\b|rotate|complement|nibble|"
                              r"url[- ]?decod|percent|\bshift\b|subtract|\badd\s|\bskip\b|\btake\s+the\b|"
                              r"\bbytes\s+(?:starting\s+)?at\b", re.I)


PROSE_KEYS = re.compile(rb'"(?:' + "|".join(PROSE_FIELDS).encode() + rb')"\s*:', re.I)


# `hex-decode the blob field`: a field named beside a step is its source
SOURCE_BARE = re.compile(r"\b(?:the\s+)?[`\"']?([a-z_][a-z0-9_]{0,31})[`\"']?\s+field\b", re.I)


def _int(text):
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def _key_field(doc, name):
    """An xor step keyed by a document field: an integer of 0 to 255 is one byte, a text is its UTF-8 bytes."""
    if not isinstance(doc, dict):
        return None
    hit = [k for k in doc if isinstance(k, str) and k.lower() == name.lower()]
    if len(hit) != 1:
        return None
    v = doc[hit[0]]
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return ("xor", bytes([v]), "field:" + hit[0].lower()) if 0 <= v < 256 else None
    if isinstance(v, str) and 0 < len(v) <= 64:
        return ("xor", v.encode("utf-8"), "field:" + hit[0].lower())
    return None


def _field_bytes(doc, name):
    """A document field's bytes for a cipher key, salt or password (a string's UTF-8, a 0..255 int's one byte)."""
    kf = _key_field(doc, name)
    return kf[1] if kf else None


def _labelled_bytes(clause, label, doc):
    """The bytes a `<label>` names in the clause: a quoted literal (its UTF-8), or a document field; else None."""
    m = re.search(label + r"\s+(?:is\s+|=\s*|of\s+|:\s*)?" + QUOTED, clause, re.I)
    if m:
        return m.group(m.lastindex).encode("utf-8")
    m = re.search(label + r"\s+(?:is\s+|=\s*|:\s*)?(?:the\s+)?" + FIELD, clause, re.I)
    if m:
        return _field_bytes(doc, m.group(m.lastindex))
    return None


def _dklen(low):
    """The derived key length a clause states (`32-byte key`, `AES-256`), or None."""
    m = re.search(r"\b(16|24|32)[- ]?byte\b", low)
    if m:
        return int(m.group(1))
    m = re.search(r"\baes[- ]?(128|192|256)\b", low)
    return {"128": 16, "192": 24, "256": 32}[m.group(1)] if m else None


def _kdf_key(clause, doc, want_len=None):
    """A key PBKDF2 derives from a STATED password, salt and iteration count (a stated KDF). None when any part is
    not stated. The result is a value (bytes); its origin is `kdf:pbkdf2-<hash>`, so the route never carries it."""
    low = clause.lower()
    if "pbkdf2" not in low and not re.search(r"\bderiv(?:e|ed|ing)\b", low):
        return None
    pw = _labelled_bytes(clause, r"(?:password|passphrase|pass|secret)", doc)
    salt = _labelled_bytes(clause, r"salt", doc)
    if pw is None or salt is None:
        return None
    mi = re.search(r"(\d{1,7})\s*(?:iterations|rounds|times)\b|"
                   r"\b(?:iterations|rounds|count)\s*(?:of|=|:)?\s*(\d{1,7})", low)
    if not mi:
        return None
    iters = int(mi.group(1) or mi.group(2))
    if not 1 <= iters <= 10_000_000:
        return None
    hm = re.search(r"\b(md5)\b|\bsha-?(1|224|256|384|512)\b", low)
    h = "md5" if (hm and hm.group(1)) else ("sha" + hm.group(2) if hm else "sha256")
    dklen = want_len or _dklen(low) or 32
    try:
        return hashlib.pbkdf2_hmac(h, pw, salt, iters, dklen), "kdf:pbkdf2-" + h
    except (ValueError, TypeError):
        return None


_HASH_KEY = re.compile(r"\bkey\s+(?:is\s+|=\s*|:\s*)?(?:the\s+)?(?:first\s+(?P<n>16|24|32)\s+bytes\s+of\s+(?:the\s+)?)?"
                       r"(?P<h>md5|sha-?1|sha-?256|sha-?512)\s+(?:digest\s+|hash\s+)?of\s+(?:" + QUOTED +
                       r"|(?:the\s+)?" + FIELD + r")", re.I)


def _hash_key(clause, doc, want_len=None):
    """B-249: a key a hash derives from a stated text (`the key is the SHA-256 of 'pw'`, `the key is the first 16
    bytes of the MD5 of the passphrase field`). The digest, cut to the stated length (or the cipher's), else None.
    Its origin is `kdf:<hash>`: the route names the derivation, never the text or the key."""
    m = _HASH_KEY.search(clause)
    if not m:
        return None
    h = m.group("h").lower().replace("-", "")
    quoted = m.group(3)
    src = quoted.encode("utf-8") if quoted is not None else _field_bytes(doc, m.group(4))
    if src is None:
        return None
    digest = hashlib.new(h, src).digest()
    n = int(m.group("n")) if m.group("n") else want_len
    if n is not None:
        if n > len(digest):
            return None
        digest = digest[:n]
    return digest, "kdf:" + h


def _cipher_key(clause, doc, want_len=None):
    """(key bytes, origin) a cipher clause STATES: a PBKDF2 derivation, a quoted literal, a hex literal, `the key` or a
    named field. None when no key is stated. `origin` names where the key came from, never its value."""
    kdf = _kdf_key(clause, doc, want_len)
    if kdf:
        return kdf
    hk = _hash_key(clause, doc, want_len)
    if hk:
        return hk
    m = re.search(r"\bkey\s+(?:is\s+|=\s*|of\s+|:\s*)?" + QUOTED, clause, re.I)
    if m:
        return m.group(m.lastindex).encode("utf-8"), "text"
    m = re.search(r"\b(?:hex\s+key|key\s+(?:in\s+)?hex)\s+(?:is\s+|=\s*|:\s*)?[`\"']?([0-9a-fA-F]{2,128})[`\"']?",
                  clause, re.I)
    if m and len(m.group(1)) % 2 == 0:
        return bytes.fromhex(m.group(1)), "hex"
    m = re.search(r"\bkeyed\s+(?:with|by)\s+(?:the\s+)?" + FIELD + r"|\bkey\s+(?:is\s+|=\s*|:\s*)?(?:the\s+)?" + FIELD,
                  clause, re.I)
    if m:
        name = next((g for g in m.groups() if g), None)
        kb = _field_bytes(doc, name) if name else None
        if kb:
            return kb, "field:" + name.lower()
    if re.search(r"\bthe\s+key\b", clause, re.I):
        kb = _field_bytes(doc, "key")
        if kb:
            return kb, "field:key"
    return None


def _aes_iv(clause):
    """The 16-byte IV an AES clause states (a quoted literal or 32 hex characters), or None."""
    m = re.search(r"\biv\s+(?:in\s+)?hex\s+(?:is\s+|=\s*|:\s*)?[`\"']?([0-9a-fA-F]{32})[`\"']?", clause, re.I)
    if m:
        return bytes.fromhex(m.group(1))
    m = re.search(r"\biv\s+(?:is\s+|=\s*|of\s+|:\s*)?" + QUOTED, clause, re.I)
    return m.group(m.lastindex).encode("utf-8") if m else None


def _order(clause, doc):
    """(order tuple, origin) a permutation clause states: a literal index list (`order 3,1,0,2`) or a document field
    that is a list of ints. None when no order is stated."""
    m = re.search(r"\border\s+(?:is\s+|=\s*|:\s*)?\[?\s*(\d+(?:\s*[, ]\s*\d+)+)\s*\]?", clause, re.I)
    if m:
        return tuple(int(x) for x in re.findall(r"\d+", m.group(1))), "literal"
    for fm in re.finditer(r"(?:the\s+)?([a-z_][a-z0-9_]{0,31})\s+(?:field|array|list)\b", clause, re.I):
        if isinstance(doc, dict):
            hit = [k for k in doc if isinstance(k, str) and k.lower() == fm.group(1).lower()]
            if len(hit) == 1 and isinstance(doc[hit[0]], list) and doc[hit[0]] \
                    and all(isinstance(x, int) and not isinstance(x, bool) for x in doc[hit[0]]):
                return tuple(doc[hit[0]]), "field:" + hit[0].lower()
    return None


# ---------------------------------------------------------------------------- reading a text

class NoSpec(Exception):
    """The text states something this grammar does not read whole."""


def _segments(text):
    return [s.strip(" \t:-") for s in SPLIT.split(text) if s and s.strip(" \t:-")]


def _filler_only(text):
    words = re.findall(r"[a-z0-9_]+", text.lower())
    return all(w in FILLER for w in words)


def parse(text, doc):
    """(steps, source) the text states, or None when it states no pipeline; raises NoSpec when it states one this
    grammar does not read whole. source is ('field', name) or ('member', path) or ('named', None)."""
    text = text[:PROSE_CHARS]     # matched without case: a quoted key keeps its letters
    steps, sources, said = [], [], False
    for seg in _segments(text):
        found = []
        for name, rx, build in STEPS:
            for m in rx.finditer(seg):
                if any(m.start() < e and s < m.end() for s, e, _ in found):
                    continue
                step = build(m, doc)
                if step is None:
                    raise NoSpec(f"{name} with a parameter not stated: {seg[:60]!r}")
                found.append((m.start(), m.end(), step))
        rest = seg
        for s, e, _ in sorted(found, reverse=True):
            rest = rest[:s] + " " + rest[e:]
        src = None
        for rx, kind in ((SOURCE_NAMED, "named"), (SOURCE_MEMBER, "member"), (SOURCE_FIELD, "field"),
                         (SOURCE_BARE if found else None, "field")):
            if rx is None:
                continue
            m = rx.search(rest)
            if m:
                src = (kind, m.group(1) if kind != "named" else None)
                rest = rest[:m.start()] + " " + rest[m.end():]
                break
        if not found and not src:
            word = re.fullmatch(r"\s*([a-z0-9]+)\s*", seg, re.I)
            bare = BARE.get(word.group(1).lower()) if word else None
            if bare == "xor":
                bare = _key_field(doc, "key")
                if bare is None:
                    raise NoSpec("a bare xor with no key field")
            if bare:
                steps.append(bare)
                said = True
                continue
            if ACTION.search(seg):
                raise NoSpec(f"a step this grammar does not read: {seg[:60]!r}")
            continue       # narrative
        if not _filler_only(rest):
            raise NoSpec(f"words beside the step that are no filler: {rest.strip()[:60]!r}")
        if src:
            sources.append(src)
        steps += [st for _, _, st in sorted(found)]
        said = True
    if not said:
        return None
    if len(set(sources)) > 1 or len(steps) > MAX_STEPS:
        raise NoSpec("two sources, or more steps than are read")
    return steps, (sources[0] if sources else ("field", "data"))


# ---------------------------------------------------------------------------- carrying it out

def _b64dec(s, alt=False):
    t = re.sub(rb"\s+", b"", s)
    t += b"=" * (-len(t) % 4)
    if alt:
        if not re.fullmatch(rb"[A-Za-z0-9_-]*={0,2}", t):
            return None
        return base64.urlsafe_b64decode(t)
    return base64.b64decode(t, validate=True)


def _inflate(b):
    if b[:2] == b"\x1f\x8b":
        out = gzip.decompress(b)
    else:
        try:
            out = zlib.decompressobj().decompress(b, MAX_BYTES + 1)
        except zlib.error:
            out = zlib.decompressobj(-15).decompress(b, MAX_BYTES + 1)
    return out if len(out) <= MAX_BYTES else None


def _letters(b, n):
    out = bytearray(b)
    for i, c in enumerate(out):
        if 65 <= c <= 90:
            out[i] = (c - 65 + n) % 26 + 65
        elif 97 <= c <= 122:
            out[i] = (c - 97 + n) % 26 + 97
    return bytes(out)


def _rc4_apply(key, data):
    """RC4 keystream over the bytes (encrypt and decrypt are the same operation)."""
    if not key:
        return None
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 255
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for n, c in enumerate(data):
        i = (i + 1) & 255
        j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        out[n] = c ^ s[(s[i] + s[j]) & 255]
    return bytes(out)


def _vigenere_apply(key, data):
    """Vigenere DECODE over ASCII letters; the key index advances only on a letter, other bytes pass through."""
    if not key:
        return None
    out = bytearray(data)
    ki = 0
    for n, c in enumerate(out):
        if 65 <= c <= 90:
            out[n] = (c - 65 - ((key[ki % len(key)] | 0x20) - 97)) % 26 + 65
            ki += 1
        elif 97 <= c <= 122:
            out[n] = (c - 97 - ((key[ki % len(key)] | 0x20) - 97)) % 26 + 97
            ki += 1
    return bytes(out)


def _aes_apply(key, iv, mode, data):
    """AES-ECB (key) or AES-CBC (key, IV) decrypt, PKCS#7 padding stripped when valid. None when pycryptodome is
    absent, the input is not a block multiple, or the cipher raises."""
    if not data or len(data) % 16:
        return None
    try:
        from Crypto.Cipher import AES          # lazy: its absence must not disable the whole module
    except Exception:
        return None
    try:
        pt = (AES.new(key, AES.MODE_CBC, iv) if mode == "cbc" else AES.new(key, AES.MODE_ECB)).decrypt(data)
    except (ValueError, TypeError):
        return None
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        pt = pt[:-pad]
    return pt


_Z85_ALPHABET = (b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#")
_Z85_INV = {c: i for i, c in enumerate(_Z85_ALPHABET)}


def _z85_apply(text):
    """ZeroMQ Z85 decode (RFC 32): five characters a four-byte big-endian group; another length or symbol is None."""
    text = re.sub(rb"\s+", b"", text)
    if len(text) % 5:
        return None
    out = bytearray()
    for k in range(0, len(text), 5):
        v = 0
        for c in text[k:k + 5]:
            if c not in _Z85_INV:
                return None
            v = v * 85 + _Z85_INV[c]
        if v > 0xFFFFFFFF:
            return None
        out += struct.pack(">I", v)
    return bytes(out)


def _decompress2_apply(algo, b):
    """bzip2/xz/lzma decompression, bounded to MAX_BYTES; None when the stream does not end whole in bounds."""
    if algo == "bz2":
        d = bz2.BZ2Decompressor()
    else:
        d = lzma.LZMADecompressor(lzma.FORMAT_XZ if algo == "xz" else lzma.FORMAT_AUTO)
    out = d.decompress(b, max_length=MAX_BYTES + 1)
    if not d.eof or len(out) > MAX_BYTES:
        return None
    return out


def _permute_apply(order, data):
    """Reorder each block of len(order) bytes by the stated index order: out[i] = block[order[i]]. None when the data
    is not a whole number of blocks."""
    n = len(order)
    if not n or len(data) % n or sorted(order) != list(range(n)):
        return None
    out = bytearray(len(data))
    for base in range(0, len(data), n):
        block = data[base:base + n]
        for i, src in enumerate(order):
            out[base + i] = block[src]
    return bytes(out)


def _aes_gcm_apply(key, nonce, data):
    """AES-GCM decrypt of ciphertext||tag (a 16-byte tag at the end), the tag verified: a wrong key, nonce or layout
    fails authentication and gives None. None too when pycryptodome is absent."""
    if len(data) < 17:
        return None
    try:
        from Crypto.Cipher import AES          # lazy, as _aes_apply
    except Exception:
        return None
    try:
        return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(data[:-16], data[-16:])
    except (ValueError, TypeError, KeyError):
        return None


def _chacha20_apply(key, nonce, data):
    try:
        from Crypto.Cipher import ChaCha20
    except Exception:
        return None
    try:
        return ChaCha20.new(key=key, nonce=nonce).decrypt(data)
    except (ValueError, TypeError):
        return None


def _xtea_apply(key, data, rounds=32, delta=0x9E3779B9):
    """XTEA ECB decrypt (big-endian words, 32 cycles); PKCS#7 padding stripped when valid, else trailing NULs."""
    if not data or len(data) % 8:
        return None
    k = struct.unpack(">4I", key)
    mask = 0xFFFFFFFF
    out = bytearray()
    for off in range(0, len(data), 8):
        v0, v1 = struct.unpack(">2I", data[off:off + 8])
        s = (delta * rounds) & mask
        for _ in range(rounds):
            v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & mask
            s = (s - delta) & mask
            v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & mask
        out += struct.pack(">2I", v0, v1)
    pad = out[-1]
    if 1 <= pad <= 8 and out[-pad:] == bytes([pad]) * pad:
        return bytes(out[:-pad])
    return bytes(out).rstrip(b"\x00")


def _columnar_apply(perm, data):
    """Columnar transposition decode: the text was written out column by column, in the keyword's rank order, each
    column top to bottom (codec_more.col_decode's layout)."""
    n = len(perm)
    if not 2 <= n < len(data):
        return None
    by_rank = sorted(range(n), key=lambda c: perm[c])
    positions = [i for c in by_rank for i in range(c, len(data), n)]
    out = bytearray(len(data))
    for k, pos in enumerate(positions):
        out[pos] = data[k]
    return bytes(out)


def _lookup_apply(table, base, data):
    """The table's entries at the integer indices the bytes hold (digits separated by anything else)."""
    nums = re.findall(rb"\d{1,6}", data)
    if not nums or len(nums) > MAX_BYTES:
        return None
    out = []
    for t in nums:
        i = int(t) - base
        if not 0 <= i < len(table):
            return None
        out.append(table[i])
    return "".join(out).encode("utf-8")


def apply(step, b):
    """One step on bytes: the bytes after it, or None when the step does not apply (bad base64, a slice past the end)."""
    kind = step[0]
    try:
        if kind == "base64":
            return _b64dec(b)
        if kind == "base64url":
            return _b64dec(b, alt=True)
        if kind == "base32":
            t = re.sub(rb"\s+", b"", b).upper()
            return base64.b32decode(t + b"=" * (-len(t) % 8))
        if kind == "base85":
            return base64.b85decode(re.sub(rb"\s+", b"", b))
        if kind == "ascii85":
            t = re.sub(rb"\s+", b"", b)
            return base64.a85decode(t, adobe=t.startswith(b"<~") and t.endswith(b"~>"))
        if kind == "z85":
            return _z85_apply(b)
        if kind == "decompress2":
            return _decompress2_apply(step[1], b)
        if kind == "rol":
            n = step[1] % 8
            return bytes(((c << n) | (c >> (8 - n))) & 255 if n else c for c in b)
        if kind == "ror":
            n = step[1] % 8
            return bytes(((c >> n) | (c << (8 - n))) & 255 if n else c for c in b)
        if kind == "complement":
            return bytes(c ^ 0xFF for c in b)
        if kind == "nibble":
            return bytes(((c << 4) | (c >> 4)) & 255 for c in b)
        if kind == "hex":
            return bytes.fromhex(re.sub(r"\s+", "", b.decode("ascii")))
        if kind == "reverse":
            return b[::-1]
        if kind == "rot13":
            return codecs.encode(b.decode("latin-1"), "rot13").encode("latin-1")
        if kind == "rot47":
            return bytes(33 + (c - 33 + 47) % 94 if 33 <= c <= 126 else c for c in b)
        if kind == "atbash":
            return bytes(155 - c if 65 <= c <= 90 else 219 - c if 97 <= c <= 122 else c for c in b)
        if kind == "letters":
            return _letters(b, step[1])
        if kind == "add":
            return bytes((c + step[1]) & 255 for c in b)
        if kind == "xor":
            k = step[1]
            return bytes(c ^ k[i % len(k)] for i, c in enumerate(b))
        if kind == "rc4":
            return _rc4_apply(step[1], b)
        if kind == "vigenere":
            return _vigenere_apply(step[1], b)
        if kind == "aes":
            return _aes_apply(step[1], step[2], step[3], b)
        if kind == "permute":
            return _permute_apply(step[1], b)
        if kind == "aes-gcm":
            return _aes_gcm_apply(step[1], step[2], b)
        if kind == "chacha20":
            return _chacha20_apply(step[1], step[2], b)
        if kind == "xtea":
            return _xtea_apply(step[1], b)
        if kind == "columnar":
            return _columnar_apply(step[1], b)
        if kind == "block-reverse":
            n = step[1]
            if len(b) % n:
                return None
            return b"".join(b[i:i + n][::-1] for i in range(0, len(b), n))
        if kind == "translate":
            table = dict(step[1])
            return "".join(table.get(c, c) for c in b.decode("utf-8")).encode("utf-8")
        if kind == "lookup":
            return _lookup_apply(step[1], step[2], b)
        if kind == "inflate":
            return _inflate(b)
        if kind == "url":
            return urllib.parse.unquote_to_bytes(b.decode("latin-1"))
        if kind == "slice":
            if len(step) == 4:     # N bytes at offset M
                start, n = step[1], step[2]
                return b[start:start + n] if start + n <= len(b) else None
            start, end = step[1], step[2]
            if abs(start) > len(b) or (end is not None and abs(end) > len(b)):
                return None
            return b[start:end]
    except (ValueError, binascii.Error, UnicodeError, zlib.error, lzma.LZMAError, EOFError, OSError, IndexError):
        return None
    return None


def route_of(steps, source) -> str:
    """The route's name: the steps by name, the key's origin (never its value), the source's kind."""
    words = []
    for st in steps:
        if st[0] == "xor":
            words.append("xor=" + st[2])
        elif st[0] == "rc4":
            words.append("rc4=" + st[2])
        elif st[0] == "vigenere":
            words.append("vigenere=" + st[2])
        elif st[0] == "aes":
            words.append("aes-" + st[3] + "=" + st[4])
        elif st[0] == "permute":
            words.append("permute=" + st[2])
        elif st[0] in ("aes-gcm", "chacha20"):
            words.append(st[0] + "=" + st[3])
        elif st[0] in ("xtea", "columnar", "translate"):
            words.append(st[0] + "=" + st[2])
        elif st[0] == "lookup":
            words.append("lookup=" + st[3] + ("@1" if st[2] else ""))
        elif st[0] == "block-reverse":
            words.append("block-reverse" + str(st[1]))
        elif st[0] in ("rol", "ror"):
            words.append(st[0] + str(st[1]))
        elif st[0] == "decompress2":
            words.append(st[1])
        elif st[0] in ("add", "letters"):
            words.append(st[0])
        else:
            words.append(st[0])
    where = "" if source == ("field", "data") else "@" + (source[0] if source[0] != "field" else "field:" + source[1])
    return "stated:" + ">".join(words) + where


def _source_bytes(source, doc, members):
    """(bytes, from a member?) of the stated source, or (None, False)."""
    kind, name = source
    if kind == "named" or (kind == "field" and name == "data" and isinstance(doc, dict)
                           and isinstance(doc.get("data"), str) and _member(doc["data"], members) is not None):
        path = doc.get("data") if isinstance(doc, dict) else None
        body = _member(path, members) if isinstance(path, str) else None
        return (body, True) if body is not None else (None, False)
    if kind == "member":
        body = _member(name, members)
        return (body, True) if body is not None else (None, False)
    if not isinstance(doc, dict):
        return None, False
    hit = [k for k in doc if isinstance(k, str) and k.lower() == name.lower()]
    if len(hit) != 1 or not isinstance(doc[hit[0]], str):
        return None, False
    return doc[hit[0]].encode("utf-8"), False


def _member(path, members):
    if not isinstance(path, str):
        return None
    p = path.strip().lstrip("./").lstrip("/")
    for k, v in members.items():
        if isinstance(k, str) and k.lower() == p.lower() and isinstance(v, (bytes, bytearray)) and k != PUZZLE:
            return bytes(v[:MAX_BYTES])
    return None


def carry_out(steps, source, doc, members):
    """The one code the pipeline gives, or None."""
    b, from_member = _source_bytes(source, doc, members)
    if b is None:
        return None
    for st in steps:
        b = apply(st, b)
        if not b or len(b) > MAX_BYTES:
            return None
    t = b.strip().decode("latin-1")
    if ANS_WHOLE.fullmatch(t):
        return t
    if from_member:
        codes = {m.group(0).decode() for m in ANS_ANY.finditer(b)}
        if len(codes) == 1:
            return codes.pop()
    return None


def texts_of(doc, extra=()):
    """[(where, text)]: the document's prose fields, then the question's and the prompt's texts."""
    out = []
    if isinstance(doc, dict):
        for k, v in doc.items():
            if not (isinstance(k, str) and k.lower() in PROSE_FIELDS):
                continue
            if isinstance(v, str) and v.strip():
                out.append(("@" + k.lower(), v))
            elif isinstance(v, list) and v and all(isinstance(x, str) and x.strip() for x in v) and len(v) <= MAX_STEPS:
                out.append(("@" + k.lower(), " ; ".join(v)))
    for i, t in enumerate(extra):
        if isinstance(t, str) and t.strip():
            out.append(("question" if i == 0 else "prompt", t))
    return out[:MAX_TEXTS]


def _plain_steps_field(doc, where, text):
    """A `steps` field that is only codec names joined (`base64>xor`) is codec_search's own chain: not read here."""
    return where == "@steps" and re.fullmatch(r"\s*[a-z0-9_+\-]+(?:\s*(?:>|->|\+|\||,|;|then)\s*[a-z0-9_+\-]+)*\s*",
                                              text.lower())


# ------- a decoding stated in a secondary dex's strings or its CONTRACT, not in the document or the question (gap c).
# A dex string is read as a recipe only when it has the SHAPE of one (an arrow, `then`, a `CONTRACT`/`RECIPE` label,
# or an action beside a step word). A class or method name has none of those, so a normal package is untouched; and a
# dex recipe is still carried through the same grammar and must give an exact code, so it is a one-option pick, never
# plain. The cheap has_dex_recipe() keeps read_package()'s fast early-return for a package with no such string.
DEX_RECIPE = re.compile(
    r"\b(?:contract|recipe)\b\s*[:=]|->|=>|→|\bthen\b|\bfollowed\s+by\b|"
    r"\bxor\b[^.;\n]{0,40}\b(?:with|key)\b|"
    r"\b(?:decode|decrypt|decipher)\b[^.;\n]{0,40}\b(?:then|with|using|base|hex|xor|rot|aes|rc4)\b", re.I)
DEX_LABEL = re.compile(r"^\s*(?:contract|recipe|decode|decoding|steps?|how\s*to\s*decode)\s*[:=\-]\s*", re.I)


def _dex_members(members):
    """[(name, bytes)] of the package's dex members (classes.dex and any secondary .dex), bounded by MAX_DEX."""
    out = []
    for k, v in members.items():
        if not isinstance(v, (bytes, bytearray)):
            continue
        if (isinstance(k, str) and k.lower().endswith(".dex")) or (len(v) >= 8 and bytes(v[:4]) == b"dex\n"):
            out.append((k, bytes(v)))
            if len(out) >= MAX_DEX:
                break
    return out


def _dex_strings(d):
    """The dex string pool as text (the same layout apk_facts._dex_strings reads), each at most PROSE_CHARS long."""
    try:
        n, off = struct.unpack_from("<II", d, 0x38)
    except struct.error:
        return []
    out = []
    for i in range(min(n, 20000)):
        try:
            o = struct.unpack_from("<I", d, off + 4 * i)[0]
            while d[o] & 0x80:
                o += 1
            o += 1
            end = d.index(b"\0", o)
        except (struct.error, ValueError, IndexError):
            continue
        s = d[o:end].decode("utf-8", "replace")
        if 0 < len(s) <= PROSE_CHARS:
            out.append(s)
    return out


def has_dex_recipe(members):
    """True when a dex member's bytes hold a recipe-shaped string (a cheap scan; no string pool is parsed)."""
    for _, body in _dex_members(members):
        try:
            if DEX_RECIPE.search(body[:MAX_DEX_SCAN].decode("latin-1")):
                return True
        except Exception:
            continue
    return False


def dex_recipe_texts(members):
    """The recipe-shaped strings of the dex members, a leading `CONTRACT:`/`RECIPE:` label stripped, bounded."""
    texts = []
    for _, body in _dex_members(members):
        for s in _dex_strings(body):
            if DEX_RECIPE.search(s):
                texts.append(DEX_LABEL.sub("", s, count=1))
                if len(texts) >= MAX_DEX_TEXTS:
                    return texts
    return texts


def read(doc, members, extra=(), dex_texts=()):
    """(code, route, steps) or None, and the notes of what was read (see the module text)."""
    got, notes = {}, []
    for where, text in texts_of(doc, extra):
        if _plain_steps_field(doc, where, text):
            continue
        if where in ("question", "prompt") and not QUESTION_TRIGGER.search(text[:PROSE_CHARS]):
            continue           # one search: a question that names no member path and no step
        try:
            spec = parse(text, doc)
        except NoSpec as e:
            notes.append(f"{where}: no spec ({e})")
            continue
        if spec is None:
            continue
        steps, source = spec
        if not steps and source == ("field", "data"):
            continue
        code = carry_out(steps, source, doc, members)
        route = route_of(steps, source)
        notes.append(f"{where}: {route} gives {code or 'no code'}")
        if code:
            got.setdefault(code, (route, steps, where))
    for text in dex_texts:     # a dex-stated recipe speaks only through a code: a miss adds no note (a random
        if not QUESTION_TRIGGER.search(text[:PROSE_CHARS]):   # class name is never read as a failed pipeline)
            continue
        try:
            spec = parse(text, doc)
        except NoSpec:
            continue
        if not spec:
            continue
        steps, source = spec
        if not steps and source == ("field", "data"):
            continue
        code = carry_out(steps, source, doc, members)
        if code:
            got.setdefault(code, (route_of(steps, source), steps, "@dex"))
            notes.append(f"@dex: {route_of(steps, source)} gives {code}")
    if len(got) != 1:
        if len(got) > 1:
            notes.append("two codes from two stated pipelines: " + ", ".join(sorted(got)))
        return None, notes
    code, (route, steps, where) = next(iter(got.items()))
    return (code, route, steps), notes


def read_package(members, extra=()):
    """read() on the package's own puzzle document (None when it is no JSON object), the question texts beside it, and
    a recipe a secondary dex's strings state (gap c)."""
    doc = None
    raw = members.get(PUZZLE)
    asked = [t for t in extra if isinstance(t, str) and QUESTION_TRIGGER.search(t[:PROSE_CHARS])]
    has_prose = isinstance(raw, (bytes, bytearray)) and PROSE_KEYS.search(raw)
    dex_texts = dex_recipe_texts(members) if has_dex_recipe(members) else ()
    if not asked and not has_prose and not dex_texts:
        return None, []        # no prose field, no question that names a member or a step, no dex recipe
    if isinstance(raw, (bytes, bytearray)) and len(raw) <= 1 << 20:
        try:
            doc = json.loads(bytes(raw).decode("utf-8-sig"))
        except (ValueError, UnicodeError):
            doc = None
    if not isinstance(doc, dict):
        doc = None
    if doc is None and not dex_texts and not any(isinstance(t, str) and t.strip() for t in extra):
        return None, []
    return read(doc or {}, members, extra, dex_texts)


# A named keyed cipher or permutation whose SHAPE this grammar recognises but which it will not carry out (the
# key/IV/order is not stated in a form it reads, or the cipher library is absent). codec_search demotes a plain
# `data` reading over such a text, so a decoy `data` that base64-decodes to an ANS code is never banked plain while
# the real decode is a keyed AES/RC4/Vigenere or a permutation stated only in words -- the decode shapes this module
# fails closed on (S01/S02 of the Day 28 look-ahead).
CIPHER_SHAPE_STEPS = frozenset({"rc4", "vigenere", "aes", "permute", "aes-gcm", "chacha20", "xtea", "columnar"})


def _segment_steps(seg, doc):
    """(steps, source) the readable decode steps of ONE segment, ignoring the narrative words around them, or None
    when the segment holds no readable step (or one whose parameter is not stated, e.g. an AES clause with no key).
    Unlike parse() this does NOT enforce filler-only or raise: a human hint carries extra words ('For this puzzle
    simply base64 decode the data field'), and the caller (_yields_code_alone) verifies the pipeline by carrying it
    out to a whole ANS code, so a spurious reading yields no code and spares nothing."""
    found = []
    for name, rx, build in STEPS:
        for m in rx.finditer(seg):
            if any(m.start() < e and s < m.end() for s, e, _ in found):
                continue
            step = build(m, doc)
            if step is None:
                return None     # a step whose required parameter is not stated: this segment is not executable
            found.append((m.start(), m.end(), step))
    if not found:
        word = re.fullmatch(r"\s*([a-z0-9]+)\s*", seg, re.I)
        bare = BARE.get(word.group(1).lower()) if word else None
        if not bare or bare == "xor":
            return None
        return [bare], ("field", "data")
    rest = seg
    for s, e, _ in sorted(found, reverse=True):
        rest = rest[:s] + " " + rest[e:]
    source = ("field", "data")
    for rx, kind in ((SOURCE_NAMED, "named"), (SOURCE_MEMBER, "member"), (SOURCE_FIELD, "field"), (SOURCE_BARE, "field")):
        m = rx.search(rest)
        if m:
            source = (kind, m.group(1) if kind != "named" else None)
            break
    return [st for _, _, st in sorted(found)], source


def _yields_code_alone(text, doc, members):
    """True when some single stated SEGMENT of the text, carried out on its own stated source, yields a valid ANS
    code -- a WORKING decode clause that sits in the SAME field as the unexecutable cipher sentence.

    Day 28 review: states_unexecutable_cipher parsed the WHOLE field as one pipeline, so an unexecutable AES/RC4/
    Vigenere clause poisoned a correct base64/reverse clause beside it and demoted a legitimate plain (`...encrypted
    with AES-256-CBC... simply base64 decode the data field`; `First rc4 decrypt with the session key, then base64
    decode it`; `Apply vigenere with the stored key then reverse the result`). A field with a working clause is not
    `unexecutable`: its plain reading stays. Only a field whose stated transform has NO working clause that yields a
    code is demoted (S01 `from base64, then AES-128-CBC ...` and S02 `transpose it, then base64 decode` over a decoy
    whose single clauses yield no code still demote). Restrict-only: this can only SPARE a plain, never demote one,
    and only when a clause actually carries out to a whole ANS code (the never-guess check)."""
    for seg in _segments(text[:PROSE_CHARS]):
        spec = _segment_steps(seg, doc)
        if spec is None:
            continue
        steps, source = spec
        if not steps and source == ("field", "data"):
            continue
        if carry_out(steps, source, doc, members):
            return True
    return False


def states_unexecutable_cipher(members, extra=()):
    """A reason string when the package's puzzle document (or a stated-source question/prompt) names a keyed cipher
    (AES, RC4, Vigenere) or a permutation in words that this grammar recognises but cannot carry out to a code, and
    no stated text of the package produced a code; '' otherwise.

    Restrict-only, never-guess: a legit puzzle carries no prose field, and a text whose stated cipher DID yield a
    code is turned into the answer by stated_revise (it never reaches here), so no correct plain is weakened --
    this only demotes a decoy `data` the shipped readers would otherwise bank plain. Bounded exactly as read()."""
    if not members:
        return ""
    raw = members.get(PUZZLE)
    extra = tuple(t for t in extra if isinstance(t, str))
    has_prose = isinstance(raw, (bytes, bytearray)) and PROSE_KEYS.search(raw)
    asked = any(QUESTION_TRIGGER.search(t[:PROSE_CHARS]) for t in extra)
    if not has_prose and not asked:
        return ""
    doc = None
    if isinstance(raw, (bytes, bytearray)) and len(raw) <= 1 << 20:
        try:
            doc = json.loads(bytes(raw).decode("utf-8-sig"))
        except (ValueError, UnicodeError):
            doc = None
    if not isinstance(doc, dict):
        doc = {}
    for where, text in texts_of(doc, extra):
        if _plain_steps_field(doc, where, text):
            continue
        t = text[:PROSE_CHARS]
        if where in ("question", "prompt") and not QUESTION_TRIGGER.search(t):
            continue
        named = next((name for name, rx, _b in STEPS
                      if name in CIPHER_SHAPE_STEPS and rx.search(t)), None)
        if not named:
            continue
        # Demote only for a CONCRETE stated pipeline -- the cipher/permutation beside at least one OTHER recognised
        # step (a base/encoding/transform, an xor, or a bare codec name). A lone vague verb with no readable step
        # ("unscramble the data with the moon table") is treated as noise and changes nothing, exactly as a recipe
        # the grammar cannot read always has (the stated-spec invariant): the usual reading, which may well be the
        # truth, keeps its plain answer. S01 ("base64 then AES-128-CBC ...") and S02 ("transpose it, then base64
        # decode") both carry such a second step; the moon-table case does not.
        other_step = any(rx.search(t) for name, rx, _b in STEPS if name not in CIPHER_SHAPE_STEPS)
        bare = any(w.lower() in BARE for w in re.findall(r"[A-Za-z0-9]+", t))
        if not (other_step or bare):
            continue
        # The shape is present in a concrete pipeline; demote unless the field carries out to a code. Two ways it
        # can, and either leaves the plain alone (Day 28 review: do not let an unexecutable cipher clause poison a
        # working one in the same field):
        #   - stated_spec's own executable path: THIS whole text parses and carries out to a code (then
        #     stated_revise owns it and no demote is needed here);
        #   - any single stated SEGMENT of the field carries out on its own source to a code (a base64/reverse
        #     clause beside the unexecutable cipher sentence).
        try:
            spec = parse(text, doc)
        except NoSpec:
            spec = None
        code = None
        if spec:
            steps, source = spec
            if steps or source != ("field", "data"):
                code = carry_out(steps, source, doc, members)
        if code is None and not _yields_code_alone(text, doc, members):
            return "%s names a %s decode in a stated pipeline this reader does not carry out, and the field holds " \
                   "no working clause that yields a code" % (where, named)
    return ""
