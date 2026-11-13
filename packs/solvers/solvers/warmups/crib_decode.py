#!/usr/bin/env python3
"""Warmups auto-decoder: layered (CyberChef-style) decoding that reads toward a flag.

Usage:
  .venv/bin/python solvers/warmups/crib_decode.py <blob-file> [...]

A warmup / sanity / misc blob is readable text run through one or more reversible encodings
(the base families, hex and byte lists, URL / HTML / MIME escapes, unicode look-alikes, morse
and braille, esolang programs such as Brainfuck, Ook!, Chef or Shakespeare, and the keyless
classical ciphers rot13 / caesar / atbash / rot47 / single-byte xor). This module undoes them
and surfaces the flag inside.

What is tried on a payload: a breadth-first search of the strict (information-preserving)
decoders to a depth of six, one loose step (a rotation, atbash, rot47, a reversal, words
reversed, single-byte xor) on the payload and on the first strict results, the payload reversed
then one strict step, and byte values written in any base from 3 to 36. Every decoder, esolang
interpreter and cipher stays wired in; each reading is a (text, chain) pair, and a text reached
two ways keeps its simpler chain.

The target is a flag. Every reading is scanned for the flag format
(?:csctf|flag|chronos|ctf){...}; when a decode contains one, that string is the answer and is
surfaced first, with the chain that produced it. This is the jeopardy decode discipline: a
payload is not over-decoded into something that merely looks like English -- the search is read
toward the layer where a flag appears, not toward any fixed sentence.

Discipline (kept generic): every decoder is tried on every payload; a reading is trusted only
for what its decoders can actually recover (a keyless letter step passes letters and digits
through, so it proves nothing on its own); the search is bounded by a per-blob time budget and a
state cap; and when no flag is reached the CLI prints the best decode(s) it did reach, so a human
can take it from there. A blob over 1 MiB is not read, and above 8 KiB the big-number decoders
and the heaviest search are skipped.

Keyed classical ciphers (vigenere, beaufort, autokey, columnar, ...) need a key or crib to break
and are not auto-searched here -- point the crypto toolkits at those. A legacy known-plaintext
search (fit a reading to a fixed sentence) is retained so none of the decoders are lost, but it
is no longer the primary path.
"""
import base64
import binascii
import datetime
import functools
import hashlib
import html
import importlib.util
import json
import re
import sys
import threading
import time
import unicodedata
import urllib.parse
import zlib
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
for _p in (HERE.parent / "common", HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
import labels  # noqa: E402
import layered_decode as L  # noqa: E402
try:   # the classical toolkit (row 88): keyed ciphers read off the sentence, Brainfuck. Without it they are not read.
    from _shadowed import common_module  # noqa: E402
    # A DIFFERENT module also named "classical" lives under solvers/toolkits/ and wins a flat import on the
    # engine sys.path; load the intended common/classical.py by file.
    K = common_module("classical")
except Exception:   # a copy of this folder without solvers/common/classical.py still runs
    K = None
try:   # Day 9 round 2: more strict forms, programs, late readers and the lossy codes. Without it they are not read.
    import formats_more as M  # noqa: E402
except Exception:   # a copy of this folder without formats_more.py (or its tables) runs as before
    M = None
try:   # row 162: run a COW program natively, so a copy without formats_more.py reads it too (d_cow below).
    import esolangs as _ESO  # noqa: E402
except Exception:   # a copy of this folder without esolangs.py: COW is read only through M, or not at all
    _ESO = None
try:   # Day 20 coverage build: lossy codes read off the sentence. Without it they are not read.
    import lossy_codes as LC  # noqa: E402
except Exception:   # a copy of this folder without lossy_codes.py runs as before
    LC = None
try:   # Day 20 coverage build, second round: keyed classical ciphers broken with the sentence
    import lossy_ciphers as LCI  # noqa: E402
except Exception:   # a copy of this folder without lossy_ciphers.py runs as before
    LCI = None
try:   # post-Day-29 breadth: artifact-scoped known-plaintext Fractionated Morse, always unsure
    import fractionated_morse as FM  # noqa: E402
except Exception:   # a copy of this folder without fractionated_morse.py runs as before
    FM = None
try:   # Day 21 look-ahead build: byte-order twists of Days 19 and 20 (mixed-endian UTF-32, a lying or trailing
    # byte order mark, nibble-swapped hex of UTF-16, od/hexdump listings). Without it they are not read.
    import byte_order as BO  # noqa: E402
except Exception:   # a copy of this folder without byte_order.py runs as before
    BO = None
try:   # Day 24 look-ahead build: base58check and Gray code, CRC- or crib-gated (same interface as byte_order.py)
    import base_extra as BE  # noqa: E402
except Exception:   # a copy of this folder without base_extra.py runs as before
    BE = None
try:   # Round 5: explicit CRC-bearing Hamming/RS envelopes; never auto-guess a bare noisy codeword
    import ecc_steps as ECS  # noqa: E402
except Exception:   # a copy without the optional ECC toolkit retains every older reader
    ECS = None
try:   # Day 21 look-ahead build: a random substitution with letters the sentence lacks, filled from the word lists
    import subst_fill as SF  # noqa: E402
except Exception:   # a copy of this folder without subst_fill.py runs as before
    SF = None
try:   # wave 2 breadth build (2026-10-23): triple columnar transposition, crib-provable plain. Without it it is not read.
    import transposition as TR  # noqa: E402
except Exception:   # a copy of this folder without transposition.py runs as before
    TR = None
try:   # wave 4 breadth build (2026-10-23): brainfuck-dialect esolangs (alphuck, pikalang, blub, spoon), crib-provable plain
    import esolang as ESL  # noqa: E402
except Exception:   # a copy of this folder without esolang.py runs as before
    ESL = None
try:   # wave 15 breadth build (2026-10-24): arbitrary-payload esolangs (Chef, Shakespeare), crib-provable plain
    import esolang2 as ESL2  # noqa: E402
except Exception:   # a copy of this folder without esolang2.py runs as before
    ESL2 = None
try:   # wave 122 breadth build (2026-10-24): 2D/stack esolangs (><> Fish, LOLCODE), crib-provable plain
    import esolang3 as ESL3  # noqa: E402
except Exception:   # a copy of this folder without esolang3.py runs as before
    ESL3 = None
try:   # Day 28 look-ahead build (2026-10-27): boolfuck (bit-level BF) and a crib-learned BF token-dialect
    import esolang4 as ESL4  # noqa: E402
except Exception:   # a copy of this folder without esolang4.py runs as before
    ESL4 = None
try:   # row 547 (2026-10-27): esolang_more.py's Rockstar and Befunge-98 readers (its Chef and Shakespeare stay
    # esolang2's: the same step names, asked there first). Behind a cheap signature of each language; crib-gated.
    import esolang_more as ESLM  # noqa: E402
except Exception:   # a copy of this folder without esolang_more.py runs as before
    ESLM = None
try:   # wave123 adaptation hardening (2026-10-24): independent radix/base/RLE decoders and the structural-decode
    # backstop; asked last, like _enigma, and only for a whole blob every reader left None. Never plain.
    import redundant as RD  # noqa: E402
except Exception:   # a copy of this folder without redundant.py runs as before
    RD = None
try:   # envelope-peel build (2026-10-25): an XOR layer (single-byte, or a repeating key recovered from the crib)
    # re-fed through the reversible-codec battery. Without it an XOR envelope is read as before (never).
    import unwrap as UW  # noqa: E402
except Exception:   # a copy of this folder without solvers/common/unwrap.py runs as before
    UW = None

try:   # Day 26 build: 5-column outer triple columnar when time allows (exotic.py); multitap/piglatin ride lossy_codes
    import exotic as EXO  # noqa: E402
except Exception:   # a copy of this folder without exotic.py runs as before
    EXO = None
try:   # B-094: numeric/symbolic decoder pack (atomic numbers, numeric-ASCII, math-constant keystreams,
    import numsym as NS  # noqa: E402    leetrot, smooth-integer). Each reader self-gates on a flag-shaped decode.
except Exception:   # a copy of this folder without numsym.py runs as before
    NS = None
try:   # B-230: the strict character/manual-code family pack (polybius, tap, bacon, DTMF multitap, and the
    # QR/odd bases base45/crockford32/zbase32/base32hex/base122). Folded into the one pass below; a copy of
    # this folder without codec_decoders.py runs as before (the pack is just not offered).
    import codec_decoders as CD  # noqa: E402
except Exception:
    CD = None

CRIB = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "
CRIB_L = CRIB.lower()
LEN = len(CRIB)          # 87
_LETTERS = [0]           # _LETTERS[i] is the number of letters in CRIB[:i]
for _c in CRIB:
    _LETTERS.append(_LETTERS[-1] + _c.isalpha())
BUDGET = L.BUDGET        # seconds one blob may spend when the attempt has no clock
MIN_BUDGET = 0.03        # a blob is never given less, however short the window
CRIB_SHARE = 0.6         # part of a blob's budget the crib search may use; the rest is the fallback's
FALLBACK_SLACK = 0.15    # layered_decode's assemble() may run this long past the budget it is given
PIN = 6                  # sentence letters a record must reproduce for its transform to count as checked
MAX_WORD = 14            # letters in the longest slug word the fallback accepts
DEPTH = 6                # strict decoders applied one after another (layered_decode's own search goes to 5)
CAP = 400                # distinct byte strings the strict search of one payload may reach
JOIN = 12                # lines of a decoded text that are also read as one line
LOOSE_SOURCES = 10       # strict results (the payload first) that each get one loose step
NODES = 20000            # steps of the search that fits readings to the sentence
BIG = 8192               # bytes: above this the big-number decoders, the other forms and the generic search are not asked
MAX_BLOB = 1 << 20       # bytes of a blob that is read at all
DEEP_WRAPPER_MIN = 7     # the established strict graph already covers chains through six layers
DEEP_WRAPPER_MAX = 10    # bounded finale look-ahead: alternating canonical base64 / hexadecimal only
DEEP_WRAPPER_PROBE = 11  # recognise one extra layer so it fails closed before the wide search
DEEP_WRAPPER_MIN_BYTES = 2049  # skip the established <=6-layer specimens without adding even a decode
DEEP_WRAPPER_MAX_BYTES = 1 << 15  # the ten-layer specimens are <16 KiB; keep this path cheap on junk
KEY = "warmups.digits/"  # the label key of a digit convention: warmups.digits/<chain>
ENCODING = "warmups.encoding/day-%02d"   # the seed's record of a day's judged encoding
EVENT_DAY_ONE = datetime.date(2026, 10, 1)  # Day N is played on calendar day N of the event
EVENT_UTC_OFFSET = datetime.timedelta(hours=-4)   # the event's days are US Eastern days (EDT through October)


def _event_day(when):
    """The event day of an instant (a datetime with a zone), or None outside Days 1 to 31. The day is the
    Eastern one: an attempt started at 20:10 Eastern is 00:10 UTC of the next date and still that day's
    (third round of the Day 14 build; the date was taken in UTC, and an evening Time Trial was dated a
    day late, which made its judged digits unsure)."""
    try:
        n = ((when.astimezone(datetime.timezone.utc) + EVENT_UTC_OFFSET).date() - EVENT_DAY_ONE).days + 1
    except (AttributeError, ValueError, OverflowError):
        return None
    return n if 1 <= n <= 31 else None
PATCH = HERE / "day_patch.py"
PRIVATE = "warmups_crib_private"   # the module name a day patch loads its own copy of this file under

SLUG_FULL = re.compile(r"[a-z]+-[a-z]+-[a-z]+-[0-9]{2}")
# The jeopardy target: a flag-format string anywhere in a decoded reading is the answer.
# The prefix case is ignored; the body is anything but a brace or a line break.
FLAG_RE = flagfmt.TEXT
# The characters of the sentence and of a slug: a reading with any other cannot fit.
FITTING = re.compile(r"[A-Za-z0-9 !,:\-]+")
# Fitting characters with one line break among them: the break may be the sentence's last space (_search).
ONE_BREAK = re.compile(r"([A-Za-z0-9 !,:\-]*)\r?\n([A-Za-z0-9 !,:\-]*)")
# Steps that map letters to letters and pass every digit through: what the encoder did to
# the digits, if anything, cannot be read from them.
LETTERS_ONLY = re.compile(r"rot13|caesar[0-9]+|atbash")
# Steps that only move characters: every digit is where the reversal puts it.
REVERSALS = ("reverse", "revwords", "wordorder")
# Codecs that escape only some characters and leave a slug's own characters as they are.
PARTIAL = ("url", "urlplus", "qp", "qp2", "html", "htmlfold", "uescp", "cssesc", "xescp", "utf7")
# Steps of a day's chain that can leave a whole record as it stands: the codecs above, and the word order,
# which moves nothing in a piece without a space (Day 13 build; see _left_alone).
SPARING = PARTIAL + ("wordorder", "nospace", "spacemark")
# Day 14 build (row 294): the steps that change only the case of letters. swapcase undoes itself exactly;
# the other two lower a text whose case holds nothing of the original's (all capitals, capitals in turn):
# what they give has lost the sentence's own capitals, so a slug read through one is never plain (_answer).
CASE_STEPS = ("upper", "altcase", "title", "swapcase")
CASE_LOSSY = {"upper": "upper", "altcase": "alternating", "title": "title"}   # step -> the <form> of warmups.case/<form>
if BO is not None:   # Day 21 final prep: ITA2 has one case, so a slug read through it is unsure under warmups.case/ita2
    CASE_LOSSY.update(getattr(BO, "CASE_LOSSY", {}))
CASE = "warmups.case/"   # the label key of a slug read through a lossy case step
FORM = "warmups.form/"   # the label key of a slug read from a sentence that lost characters (nospace)
# Day 19 build (W4): a slug followed on its line by one filler character repeated (a grid padded to whole rows
# before a transposition: 'slug-42xx'). The pad is read off only behind the slug's two digits, and the slug is
# offered unsure under warmups.form/pad_<char>: the sentence checks nothing of what stood behind the slug.
# The four named here keep the names the ledger and seeds hold; any other single repeated filler is read by
# _pad_off / _pad_step_name under warmups.form/pad_<char> (row 377).
PAD_FILLERS = {"x": "pad_x", "X": "pad_upper_x", "_": "pad_underscore", "=": "pad_equals"}
PAD_STEPS = tuple(PAD_FILLERS.values())    # the four original names; any pad_<char> is a pad step (_is_pad_step)
PAD_MAX = 24             # filler characters behind the slug at most (a grid of 25 columns pads 24)
_PAD_INV = {name: ch for ch, name in PAD_FILLERS.items()}   # pad_x -> 'x', pad_upper_x -> 'X', ...
# Row 377 (Day 20 build): the pad reader reads ANY single repeated non-slug filler behind the slug's two digits,
# not only x/X/_/=. A filler that is no letter or digit gets a readable tag so that pad_<tag> round-trips to the
# filler for a replay (_pad_char); alphanumeric fillers are the character itself, control/non-printable are u<hex>.
_PAD_TAGS = {" ": "space", "-": "dash", ".": "dot", ",": "comma", ";": "semicolon", ":": "colon",
             "!": "bang", "?": "question", "'": "apos", '"': "quote", "`": "backtick", "~": "tilde",
             "@": "at", "#": "hash", "$": "dollar", "%": "percent", "^": "caret", "&": "amp",
             "*": "star", "+": "plus", "/": "slash", "\\": "backslash", "|": "bar",
             "(": "lparen", ")": "rparen", "[": "lbrack", "]": "rbrack", "{": "lbrace", "}": "rbrace",
             "<": "lt", ">": "gt"}
_PAD_TAG_INV = {tag: ch for ch, tag in _PAD_TAGS.items()}
# Day 20 build (warmups item 5): a transposition over a grid padded with blanks to whole rows leaves the pad
# behind the slug's two digits in the day's own record of a Mastery, the last one (a whole blob loses it with its
# line's white space). Blanks are no character of a slug, so they are read off there, by the walk by the days
# and by the delivery's reading of its last records alike; only where the day's chain moves characters (a keyed
# transposition: a grid), so a text that itself ends in a blank behind its digits is still no answer (Day 12's
# layout rule, tests/test_day12_warmups_layout.py).
_BLANK_PADDED = re.compile(r"(.*[0-9]{2})[ \t]{1,%d}" % PAD_MAX)


def _moves_chars(chain) -> bool:
    """True when `chain` holds a keyed step that moves characters (a transposition: a grid). A filler pad behind
    the slug only exists because a grid was padded to whole rows before such a step, so the pad is read off
    only here: a text that itself ends in that filler behind its digits, under a byte or letter encoding, is no
    pad (Day 12's layout rule, tests/test_day12_warmups_layout.py)."""
    return any(":" in step and _kind(step) in KEYED_MOVING for step in chain or ())


def _blank_pad(text, chain=()):
    """The text without blanks behind its last two digits (a grid's pad) when `chain` holds a keyed step that
    moves characters; any other text as it stands."""
    if not _moves_chars(chain):
        return text
    m = _BLANK_PADDED.fullmatch(text) if text else None
    return m.group(1) if m else text


def _pad_fn(filler: bytes):
    """The step that reads a filler pad off the end of a text: everything behind the last two digits when
    it is that filler repeated; a text that does not end so is given back as it stands."""
    pattern = re.compile(rb"([0-9]{2})(" + re.escape(filler) + rb"{1,%d})[ \t\r\n]*\Z" % PAD_MAX)

    def d(b):
        m = pattern.search(b)
        return b[:m.end(1)] if m else b
    return d


_PAD_FNS = {step: _pad_fn(ch.encode()) for ch, step in PAD_FILLERS.items()}


def _pad_tag(ch: str) -> str:
    """A readable, reversible token for a filler character (the part after `pad_` in a pad step's name)."""
    if ch in _PAD_TAGS:
        return _PAD_TAGS[ch]
    if len(ch) == 1 and ch.isalnum():
        return ch
    return "u%x" % ord(ch)


def _pad_step_name(ch: str) -> str:
    """The step name that reads a pad of filler `ch` off a slug. The four of PAD_FILLERS keep their names."""
    return PAD_FILLERS.get(ch) or ("pad_" + _pad_tag(ch))


def _pad_char(step: str):
    """The filler character a pad step reads off, or None when `step` is no pad step (row 377). The inverse
    of _pad_step_name: pad_x -> 'x', pad_tilde -> '~', pad_9 -> '9', pad_u<hex> -> that character."""
    if step in _PAD_INV:
        return _PAD_INV[step]
    if not step.startswith("pad_"):
        return None
    tag = step[4:]
    if tag in _PAD_TAG_INV:
        return _PAD_TAG_INV[tag]
    if len(tag) == 1 and tag.isalnum():
        return tag
    if tag.startswith("u") and len(tag) > 1:
        try:
            return chr(int(tag[1:], 16))
        except ValueError:
            return None
    return None


def _is_pad_step(step: str) -> bool:
    """True when `step` reads a filler pad off a slug (one of the four, or any pad_<char>; row 377)."""
    return step in _PAD_FNS or _pad_char(step) is not None


def _pad_off(s: str):
    """A whole-blob last line that ends in a run of ONE repeated filler behind a complete slug (a grid
    padded to whole rows before a transposition). Returns (core, filler) with `core` the line without the
    pad -- ending in the slug's two digits -- or None (row 377).

    The slug is word-word-word-DD with exactly two digits after its last hyphen, so the pad is read off
    safely even when the filler is a digit: whatever follows those two digits, when it is one character
    repeated 1..PAD_MAX times, is the pad; anything else (mixed trailing characters, no slug, a filler that
    ate into the slug's own two digits) is None, so no wrong permutation is ever read. The slug is offered
    UNSURE under warmups.form/pad_<filler> either way: the sentence checks nothing of what stood behind it."""
    if not s:
        return None
    matches = list(SLUG_FULL.finditer(s))
    if not matches:
        return None
    end = matches[-1].end()
    core, tail = s[:end], s[end:]
    if not tail or len(tail) > PAD_MAX or tail != tail[0] * len(tail):
        return None
    if not FITTING.fullmatch(core):
        return None
    return core, tail[0]


RULED = "cut"            # the third member of a delivery's pin for one set's record: it holds only for a blob
                         # that is cut where the rule of twelve days cuts it (_cut_as_ruled, _consensus_records)
RECORDS_TIME = 1.2       # seconds the delivery-wide reading of the records before the last may take (0.6 until the
                         # second round of the Day 14 build: Day 13's real 63 sets take 0.19 s, and a machine three
                         # times slower for a moment cut the read and left the delivery without its pins)
# Decoders that are another form of an older one and give its characters wherever both read a
# text: a day's blobs read by one and a record read by the other are one encoding (_canon).
# (morsekeep, formats_more.py, reads only what morse refuses: the same table, a mark left as it stands.)
ALIAS = {"htmlfold": "html", "morsex": "morse", "morsekeep": "morse"}
# Decoders that turn the whole text into one number: their cost grows with the square of the length.
BIG_NUMBER = ("b58", "b62", "b36", "bigdec", "bigoct")
# Decoders whose output can be a thousand times their input, in one call no deadline can interrupt.
INFLATING = ("compress", "inflate")
READ = 4                 # letters of a word a record must itself give for the word to speak for its transform
# Keyed steps (backlog row 88): a cipher whose key was read off the sentence. Its step in a chain is
# "<cipher>:<key>". These map letters to letters and pass digits through, like a rotation:
KEYED_LETTERS = (("affine", "vigenere", "beaufort", "autokey", "subst", "kbdw", "porta", "kwfill")
                 + (M.LETTER_KINDS if M else ()))
# and these only move characters, like a reversal: every digit is where the key puts it.
KEYED_MOVING = ("rail", "columnar", "blockrev", "split", "scytale", "faro", "redef", "route", "agree",
                "mysz", "decim", "dcol", "tricol")   # Day 20 build: Myszkowski, decimation, double columnar
#                                                      (classical.py); wave 2: triple columnar (transposition.py)
KEYED_SOURCES = 6        # readings of a payload (the payload first) that the keyed ciphers are tried on
KEYED_MAX = 400          # characters of such a reading: the sentence and a slug are about 110, and the rail
                         # fence and columnar searches grow with the square of the length
CONSENSUS_MIN = 5        # sets of a delivery whose last record must give a strong word under its day's chain
CONSENSUS_TIME = 0.6     # seconds the delivery-wide reading may take, once per delivery and process (0.25 until the
                         # second round of the Day 14 build: Day 13's real 63 sets take 0.08 s; see RECORDS_TIME)
PROGRAM_HEAD = 0.25      # seconds a program in a blob may run before the first blob's own limit is set (solve_set)
BOM = b"\xef\xbb\xbf"    # a UTF-8 byte order mark in front of a blob is part of no encoding

B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
B91 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
_B91 = {c: i for i, c in enumerate(B91)}
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769"
Z85 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
_Z85 = {c: i for i, c in enumerate(Z85)}
# What may stand between the numbers of a list: white space, or one of , ; | . / : _ -
LIST_SEP = r"[\s,;|./:_\-]+"
NATO = {w: w[0] for w in ("alfa alpha bravo charlie delta echo foxtrot golf hotel india juliett juliet kilo lima mike "
                          "november oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee zulu").split()}
NATO.update({"x-ray": "x", "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6",
             "seven": "7", "eight": "8", "nine": "9", "niner": "9", "dash": "-", "hyphen": "-", "minus": "-",
             "space": " ", "/": " ", "stop": "."})

# What the last call of solve_blob did, for the NOTE line, the command line and the self-test.
LAST = {}


# ---------------------------------------------------------------------------- more decoders
# Strict like the ones in layered_decode: each refuses any input that is not in its own form.

def _int_bytes(n: int):
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else None


def d_b62(b):
    t = L._compact(b)
    if not t or len(t) < 6 or not t.isascii() or not t.isalnum():
        return None
    n = 0
    for c in t:
        n = n * 62 + B62.index(c)
    return _int_bytes(n)


def d_b36(b):
    t = L._compact(b)
    if not t or len(t) < 6 or not re.fullmatch(r"[0-9a-z]+|[0-9A-Z]+", t):
        return None
    return _int_bytes(int(t, 36))


def d_bigdec(b):
    """One decimal integer whose bytes are the text."""
    t = L._compact(b)
    if not t or len(t) < 6 or len(t) > 4000 or not t.isascii() or not t.isdigit():
        return None
    return _int_bytes(int(t))


def d_b91(b):
    t = L._compact(b)
    if not t or len(t) < 5 or any(c not in _B91 for c in t):
        return None
    value, queue, bits, out = -1, 0, 0, bytearray()
    for c in t:
        x = _B91[c]
        if value < 0:
            value = x
            continue
        value += x * 91
        queue |= value << bits
        bits += 13 if (value & 8191) > 88 else 14
        while bits > 7:
            out.append(queue & 255)
            queue >>= 8
            bits -= 8
        value = -1
    if value >= 0:
        out.append((queue | value << bits) & 255)
    return bytes(out)


def d_uu(b):
    lines = [ln for ln in b.splitlines() if ln.strip() and not ln.startswith((b"begin ", b"end"))]
    if not lines:
        return None
    try:
        return b"".join(binascii.a2b_uu(ln) for ln in lines)
    except Exception:
        return None


def _packed(base, pattern):
    """Three digits per byte with nothing between them (decimal 078105..., octal 116151...)."""
    def f(b):
        t = L._compact(b)
        if not t or len(t) < 6 or len(t) % 3 or not re.fullmatch(pattern, t):
            return None
        values = [int(t[i:i + 3], base) for i in range(0, len(t), 3)]
        return bytes(values) if all(v < 256 for v in values) else None
    return f


d_dec3 = _packed(10, r"[0-9]+")
d_oct3 = _packed(8, r"[0-7]+")


def d_octesc(b):
    t = L._text(b)
    if t is None or not re.fullmatch(r"(?:\\[0-7]{1,3}\s*)+", t.strip()):
        return None
    return bytes(int(x, 8) & 255 for x in re.findall(r"\\([0-7]{1,3})", t))


def d_uesc(b):
    t = L._text(b)
    if t is None or not re.fullmatch(r"(?:(?:\\u|%u|U\+)[0-9a-fA-F]{4}\s*)+", t.strip()):
        return None
    return "".join(chr(int(x, 16)) for x in re.findall(r"(?:\\u|%u|U\+)([0-9a-fA-F]{4})", t)).encode()


def d_runlength(b):
    """Run-length groups `<decimal count>:<char>,` (Day 24): each group is a decimal count, a colon, one
    literal character and a terminating comma (optional on the last), and the character is repeated `count`
    times. Day 24's base has count 1 everywhere (`1:N,1:i,1:c,...`); a variant that compresses a repeated
    character still reads, because the decoder expands by the count. Folded from the Day 24 live fix
    (day_patch.py NAME='runlength'), now a strict step of this module.

    Strict: anything that is not that exact form is refused (plain text does not start with digits + colon),
    so no normal blob is ever mis-read as run-length. The literal character is always the single character
    right after the colon and the following comma terminates the group, so a character that is itself `:`,
    `,`, a space, a digit, `-` or `!` never confuses the parse. The digits of the slug ride as literal
    characters in the stream, so the slug (digits and all) is read plain, as for every strict decoder."""
    if not isinstance(b, (bytes, bytearray, memoryview)):
        return None
    try:
        s = bytes(b).decode("latin-1")   # one byte, one character: the parse is over single characters
    except Exception:
        return None
    s = s.strip("\r\n")
    if not s:
        return None
    out = []
    i, n, groups = 0, len(s), 0
    digits = "0123456789"
    while i < n:
        j = i
        while j < n and s[j] in digits:
            j += 1
        if j == i or j >= n or s[j] != ":":
            return None                      # not a `<count>:` group
        count = int(s[i:j])
        if count < 1 or count > 100000:
            return None
        k = j + 1                            # the literal character, exactly one, taken as-is
        if k >= n:
            return None
        out.append(s[k] * count)
        groups += 1
        i = k + 1
        if i < n:                            # a comma terminates each group (optional on the last)
            if s[i] != ",":
                return None
            i += 1
    if groups < 2:
        return None
    return "".join(out).encode("utf-8")


def d_revhex(b):
    """Hexadecimal text whose complete nibble stream was reversed (Day 28).

    This is deliberately one strict, lossless step rather than a day-specific answer: after ASCII whitespace is
    removed, every character must be hexadecimal and the stream must contain complete bytes. Reversing the stream
    and decoding its byte pairs is therefore reproducible for every variant; ordinary text, odd input and malformed
    hex are refused. It folds the Day 28 live patch's ``revhex`` decoder into the shipped search vocabulary.
    """
    if not isinstance(b, (bytes, bytearray, memoryview)):
        return None
    try:
        text = bytes(b).decode("ascii")
    except (UnicodeDecodeError, ValueError):
        return None
    compact = "".join(text.split())
    if not compact or len(compact) % 2 or re.fullmatch(r"[0-9a-fA-F]+", compact) is None:
        return None
    try:
        return bytes.fromhex(compact[::-1])
    except ValueError:
        return None


def d_morse2(b):
    """Morse written with other marks for dot and dash (_ for dash, a bullet for dot)."""
    t = L._text(b)
    if t is None:
        return None
    u = t
    for mark, sign in (("_", "-"), ("−", "-"), ("–", "-"), ("—", "-"),
                       ("·", "."), ("•", "."), ("*", ".")):
        u = u.replace(mark, sign)
    return L.d_morse(u.encode()) if u != t else None


# The marks of the ITU morse table that layered_decode's lacks: what morse needs to carry base64,
# base32 padding or a URL ('=' '+' '/').
MORSE_MARKS = {"-...-": "=", ".-.-.": "+", "-..-.": "/", ".--.-.": "@", "-.--.": "(", "-.--.-": ")", ".-...": "&",
               ".----.": "'", ".-..-.": '"', "-.-.-.": ";", "..--.-": "_", "...-..-": "$"}
_MORSE_ALL = {**L.MORSE, **MORSE_MARKS}


def d_morsex(b):
    """Morse with any of MORSE_MARKS in it (without one it is layered_decode's morse). Letters,
    words and marks are split as there: one space between letters, ' / ' or three spaces between
    words."""
    t = L._text(b)
    if t is None or not re.fullmatch(r"[.\-/|\s]+", t) or ("." not in t and "-" not in t):
        return None
    words = re.split(r"\s*[/|]\s*|\s{3,}", t.strip())
    codes = [w.split() for w in words]
    if not any(c in MORSE_MARKS for w in codes for c in w):
        return None
    try:
        return " ".join("".join(_MORSE_ALL[c] for c in w) for w in codes).encode()
    except KeyError:
        return None


def d_nato(b):
    t = L._text(b)
    if t is None:
        return None
    tokens = t.split()
    if len(tokens) < 3:
        return None
    out, hits = [], 0
    for token in tokens:
        value = NATO.get(token.lower())
        if value is not None:
            out.append(value)
            hits += 1
        elif len(token) == 1:
            out.append(token)
        else:
            return None
    return "".join(out).encode() if hits >= 3 else None


def d_urlplus(b):
    """URL quoting that writes a space as '+'."""
    t = L._text(b)
    if t is None or "+" not in t or " " in t.strip():
        return None
    return urllib.parse.unquote_plus(t).encode()


def d_revwords(b):
    """Every word written backwards, the words in their own order."""
    t = L._text(b)
    if t is None or not t.isascii() or not re.search(r"[A-Za-z]{2}", t):
        return None
    return " ".join(w[::-1] for w in t.split(" ")).encode()


def d_wordorder(b):
    """The words in the opposite order, each written as it was (Day 13 build): the text is split at its
    single spaces and the pieces are put back last first, which undoes itself. A text without a space is
    refused: there the step changes nothing, and a Mastery record that holds only the slug's end is then
    a record its day left alone (_left_alone)."""
    t = L._text(b)
    if t is None or not t.isascii():
        return None
    t = t.strip("\r\n")
    if " " not in t or "\n" in t or not re.search(r"[A-Za-z]{2}", t):
        return None
    return " ".join(t.split(" ")[::-1]).encode()


_UPPER, _LOWER = re.compile(rb"[A-Z]"), re.compile(rb"[a-z]")


def d_swapcase(b):
    """Every letter in the other case (Day 14 build, row 294): the step undoes itself, so what it gives is
    exactly what was written. The search takes a reading through it only where the sentence comes out in
    its own case, capital for capital (_cased): a text in capitals throughout is d_upper's, and lossy."""
    if not b.isascii() or not (_UPPER.search(b) or _LOWER.search(b)):
        return None
    return b.swapcase()


def d_upper(b):
    """A text whose letters are all capitals, lowered. Lossy: the sentence's own capitals are gone, and
    nothing says the slug had none. A slug read through it is labels.pick under warmups.case/upper."""
    if not b.isascii() or _LOWER.search(b) or not _UPPER.search(b):
        return None
    return b.lower()


def _alternating(b: bytes) -> bool:
    """True when the case of the letters alternates: no capital at the even places and no small letter at
    the odd ones, or the other way round."""
    even, odd = b[0::2], b[1::2]
    return (not (_UPPER.search(even) or _LOWER.search(odd))) or (not (_LOWER.search(even) or _UPPER.search(odd)))


def d_altcase(b):
    """A text whose letters are capital and small in turn, lowered: counted by character (every other
    character of the text) or by letter (every other letter, whatever stands between). Lossy like d_upper:
    warmups.case/alternating. A text without a capital is refused."""
    if not b.isascii() or not _UPPER.search(b):
        return None
    if not (_alternating(b) or _alternating(re.sub(rb"[^A-Za-z]", b"", b))):
        return None
    return b.lower()


_NOT_TITLE = re.compile(rb"[A-Za-z][A-Z]| [a-z]")


def d_title(b):
    """A text in which every word begins with a capital, lowered (second round of the Day 14 build): no
    capital stands behind a letter, and no small letter begins a word behind a space (the first word of a
    payload may be the end of one). Lossy like d_upper: warmups.case/title. The sentence as it is written
    is refused (`work` begins small); a piece of it whose words all begin with capitals (`Game Master: `)
    is read, to the same letters as it stands. A text without a capital is refused, except one without a
    space: a Mastery record that holds only the slug's end is then read as it is, by its day's own step."""
    if not b.isascii() or _NOT_TITLE.search(b):
        return None
    if not _UPPER.search(b) and (b" " in b or not _LOWER.search(b)):
        return None
    return b.lower()


CRIB_TIGHT = "Niceworkdecodingthiswarmup!Tosolve,submitthisexactanswertotheGameMaster:"


def d_nospace(b):
    """The sentence written without its spaces, with them put back (Day 14 build, row 296): a text that
    begins with the 72 other characters of the sentence, in their own case, and has no space at all. What
    follows them is given as it stands. The sentence was not read whole (its 15 spaces are not in the
    bytes), so a slug read through this step is never plain: labels.pick under warmups.form/nospace. A
    record that does not begin so is refused, and a Mastery record that holds only the slug's end is a
    record its day left alone (_left_alone)."""
    t = L._text(b)
    if t is None:
        return None
    t = t.strip("\r\n")
    if not t.startswith(CRIB_TIGHT) or " " in t or "\n" in t:
        return None
    return (CRIB + t[len(CRIB_TIGHT):]).encode()


# Other forms of the encodings above (Day 5 retro: a sweep of 157 encodings found these refused).

def _listed(base, pattern):
    """A list of byte values with any of LIST_SEP between them and brackets, braces or quotes
    around it ([78, 105], {0x4e, 0x69}, 78-105-99); the pattern's one group is the number."""
    def f(b):
        t = L._text(b)
        if t is None:
            return None
        tokens = [x for x in re.split(LIST_SEP, t.strip().strip("[](){}<>\"'").strip()) if x]
        hits = [re.fullmatch(pattern, x) for x in tokens]
        if len(tokens) < 2 or not all(hits):
            return None
        values = [int(m.group(1), base) for m in hits]
        return bytes(values) if all(v < 256 for v in values) else None
    return f


d_dec2 = _listed(10, r"(\d{1,3})")
d_oct2 = _listed(8, r"(?:0[oO])?([0-7]{1,4})")           # 0o116, and C's 0116
d_hex2 = _listed(16, r"(?:0[xX]|\\x|%)?([0-9a-fA-F]{2})")
d_bin2 = _listed(2, r"(?:0[bB])?([01]{1,8})")


def d_bin7(b):
    """Seven bits per character with nothing between them."""
    t = L._compact(b)
    if not t or len(t) < 14 or len(t) % 7 or not re.fullmatch(r"[01]+", t):
        return None
    return bytes(int(t[i:i + 7], 2) for i in range(0, len(t), 7))


def d_binlsb(b):
    """Eight bits per byte, the lowest bit written first."""
    t = L._text(b)
    if t is None or not re.fullmatch(r"[01\s]+", t):
        return None
    groups = t.split()
    if len(groups) == 1 and len(groups[0]) >= 16 and len(groups[0]) % 8 == 0:
        groups = [groups[0][i:i + 8] for i in range(0, len(groups[0]), 8)]
    if len(groups) < 2 or not all(len(g) == 8 for g in groups):
        return None
    return bytes(int(g[::-1], 2) for g in groups)


def d_bigbin(b):
    """One binary integer whose bytes are the text: its leading zero bits are not written."""
    t = L._compact(b)
    if not t or not re.fullmatch(r"(?:0[bB])?[01]+", t):
        return None
    prefixed = t[:2].lower() == "0b"
    t = t[2:] if prefixed else t
    if len(t) < 9 or (len(t) % 8 == 0 and not prefixed):
        return None   # whole bytes with no prefix are layered_decode's binary
    t = t.zfill(-(-len(t) // 8) * 8)
    return bytes(int(t[i:i + 8], 2) for i in range(0, len(t), 8))


def d_bigoct(b):
    """One octal integer whose bytes are the text."""
    t = L._compact(b)
    if not t or len(t) < 9 or len(t) > 6000 or not re.fullmatch(r"(?:0[oO])?[0-7]+", t):
        return None
    return _int_bytes(int(t[2:] if t[:2].lower() == "0o" else t, 8))


def d_html2(b):
    """Numeric HTML entities written without their semicolons."""
    t = L._text(b)
    if t is None or not re.fullmatch(r"(?:&#(?:\d{1,7}|[xX][0-9a-fA-F]{1,6});?\s*)+", t.strip()):
        return None
    values = [int(x[1:], 16) if x[0] in "xX" else int(x) for x in re.findall(r"&#([xX][0-9a-fA-F]+|\d+)", t)]
    if any(v > 0x10FFFF for v in values):
        return None
    return "".join(map(chr, values)).encode("utf-8", "replace")


def d_qp2(b):
    """Quoted-printable that escaped nothing and only broke its long lines with '='."""
    if not re.search(rb"=\r?\n", b) or re.search(rb"=[0-9A-F]{2}", b):
        return None
    return binascii.a2b_qp(b)


def d_dump(b):
    """A hex dump: xxd (`00000000: 4e69 6365 2077  Nice w`) or hexdump -C
    (`00000000  4e 69 63 65  |Nice|`). The offsets and the text column are dropped."""
    t = L._text(b)
    if t is None:
        return None
    out, rows = bytearray(), 0
    for line in t.splitlines():
        if not line.strip() or re.fullmatch(r"[0-9a-fA-F]{7,8}\s*", line):   # hexdump ends with a bare offset
            continue
        # Split by hand: a pattern that looks for the text column goes back and forth over a long line.
        m = re.match(r"[0-9a-fA-F]{7,8}(: |  )", line)
        rest = line[m.end():] if m else ""
        if m and m.group(1) == ": ":
            cell = rest.split("  ", 1)[0]                 # xxd: two spaces, then the text
        else:
            rest = rest.rstrip()                          # hexdump -C: the text between two bars
            cell = rest.split("|", 1)[0] if rest.endswith("|") and rest.count("|") > 1 else ""
        cell = re.sub(r"\s+", "", cell)
        if not cell or len(cell) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", cell):
            return None
        out += bytes.fromhex(cell)
        rows += 1
    return bytes(out) if rows else None


def d_utf16be(b):
    """UTF-16 with the high byte first and no byte order mark (layered_decode reads the other order)."""
    if len(b) <= 8 or len(b) % 2 or b[0::2].count(0) <= len(b) // 4:
        return None
    try:
        return b.decode("utf-16-be").encode()
    except UnicodeError:
        return None


def _b32_as(alphabet, fold):
    """Base32 written with another alphabet (Crockford's, z-base-32), with or without padding."""
    table = str.maketrans(alphabet, B32)

    def f(b):
        t = L._compact(b)
        if not t or len(t) < 8:
            return None
        t = fold(t.rstrip("="))
        if any(c not in alphabet for c in t):
            return None
        try:
            return base64.b32decode(t.translate(table) + "=" * (-len(t) % 8))
        except Exception:
            return None
    return f


d_crock32 = _b32_as(CROCKFORD, lambda t: t.upper().replace("O", "0").replace("I", "1").replace("L", "1"))
d_zb32 = _b32_as(ZBASE32, str.lower)


def d_z85(b):
    """ZeroMQ's base85; a last group that is short is filled up as ascii85 does it."""
    t = L._compact(b)
    if not t or len(t) < 5 or len(t) % 5 == 1 or any(c not in _Z85 for c in t):
        return None
    pad = -len(t) % 5
    out = bytearray()
    for i in range(0, len(t) + pad, 5):
        value = 0
        for c in (t + "#" * pad)[i:i + 5]:
            value = value * 85 + _Z85[c]
        if value > 0xFFFFFFFF:
            return None
        out += value.to_bytes(4, "big")
    return bytes(out[:len(out) - pad])


# Row 73 (Day 8 build): braille, more spellings of unicode escapes, and HTML entities that name a
# character the sentence writes otherwise.

# North American Braille ASCII: the character of each six-dot cell, by the cell's dot bits (dot 1 is
# bit 0, dot 6 bit 5; U+2800 plus the bits is the Unicode cell). CyberChef's 'To Braille' writes it.
BRAILLE_ASCII = " A1B'K2L@CIF/MSP\"E3H9O6R^DJG>NTQ,*5<-U8V.%[$+X!&;:4\\0Z7(_?W]#Y)="
# English grade-1 braille: the letters are Braille ASCII's; a digit is a letter a to j after the
# number sign, until a space, another mark or the letter sign; the capital sign makes the next
# letter upper case (twice, the rest of the word).
_G1 = {i: c.lower() for i, c in enumerate(BRAILLE_ASCII) if c.isalpha()}
_G1.update({0x00: " ", 0x02: ",", 0x06: ";", 0x12: ":", 0x32: ".", 0x16: "!", 0x26: "?", 0x24: "-", 0x04: "'"})
_G1_DIGIT = {i: str("abcdefghij".index(c) + 1)[-1] for i, c in _G1.items() if c in "abcdefghij"}
BRAILLE_NUMBER, BRAILLE_CAPITAL, BRAILLE_LETTER = 0x3C, 0x20, 0x30


def _braille_cells(b, top):
    """The cells (U+2800 to U+2800 + top) of a braille text as numbers, white space as its
    character, or None when anything else is in it or there are fewer than four cells."""
    if b"\xe2" not in b:   # every braille cell is E2 A0..A3 xx in UTF-8: refuse other text at once
        return None
    t = L._text(b)
    if t is None:
        return None
    out = []
    for c in t.strip():
        n = ord(c) - 0x2800
        if 0 <= n <= top:
            out.append(n)
        elif c.isspace():
            out.append(c)
        else:
            return None
    return out if sum(isinstance(x, int) for x in out) >= 4 else None


def d_brascii(b):
    """Six-dot braille read as Braille ASCII, letters in lower case (the cells have no case)."""
    cells = _braille_cells(b, 0x3F)
    if cells is None:
        return None
    return "".join(BRAILLE_ASCII[x].lower() if isinstance(x, int) else x for x in cells).encode()


def d_braille(b):
    """Six-dot braille read as English grade 1: letters, the number sign, the capital sign and
    the usual marks. A cell outside those is a refusal."""
    cells = _braille_cells(b, 0x3F)
    if cells is None:
        return None
    out, number, caps, word_caps = [], False, False, False
    for x in cells:
        if not isinstance(x, int) or x == 0:
            out.append(" " if x == 0 else x)
            number = caps = word_caps = False
            continue
        if x == BRAILLE_NUMBER:
            number = True
            continue
        if x == BRAILLE_LETTER:
            number = False
            continue
        if x == BRAILLE_CAPITAL:
            word_caps, caps = caps, True
            continue
        if number and x in _G1_DIGIT:
            out.append(_G1_DIGIT[x])
            continue
        number = False
        c = _G1.get(x)
        if c is None:
            return None
        out.append(c.upper() if caps or word_caps else c)
        caps = False
    return "".join(out).encode()


def d_braille8(b):
    """Eight-dot braille as bytes: each cell U+2800 + n is the byte n. White space between cells is dropped."""
    cells = _braille_cells(b, 0xFF)
    if cells is None:
        return None
    return bytes(x for x in cells if isinstance(x, int))


_UESC = r"\\u\{([0-9a-fA-F]{1,6})\}|\\U([0-9a-fA-F]{8})|\\u([0-9a-fA-F]{4})|[Uu]\+([0-9a-fA-F]{4,6})"


def _uesc_value(m):
    v = int(next(g for g in m.groups() if g), 16)
    return chr(v) if v <= 0x10FFFF else None


def d_uesc2(b):
    """Unicode escapes in the spellings uesc does not read: \\u{4e} (JavaScript), \\U0000004e
    (Python), and U+004E with commas or semicolons between them. Nothing else may be in the text."""
    t = L._text(b)
    if t is None or not re.fullmatch(r"(?:(?:%s)[\s,;]*)+" % _UESC, t.strip()):
        return None
    values = [_uesc_value(m) for m in re.finditer(_UESC, t)]
    return None if None in values else "".join(values).encode()


def d_uescp(b):
    """Text in which only some characters are unicode escapes (any spelling of _UESC), the rest
    written as they are: the escapes are read, the rest is kept."""
    t = L._text(b)
    if t is None or not re.search(_UESC, t):
        return None
    out = re.sub(_UESC, lambda m: _uesc_value(m) or m.group(0), t)
    return out.encode() if out != t else None


# The entities that name a character the sentence writes another way: a no-break space, the hyphens
# and the minus sign. html.unescape gives U+00A0, U+2010 and U+2212, which no reading can fit.
_HTML_FOLD = re.compile(r"&(?:nbsp|NonBreakingSpace|hyphen|dash|minus);")
_FOLD = str.maketrans({"\u00a0": " ", "\u2010": "-", "\u2011": "-", "\u2212": "-"})


def d_htmlfold(b):
    """HTML entities with &nbsp;, &hyphen;, &dash; or &minus; among them, read as a space and a hyphen."""
    t = L._text(b)
    if t is None or not _HTML_FOLD.search(t):
        return None
    return html.unescape(t).translate(_FOLD).encode()


def d_inflate(b):
    """A raw deflate stream, with no zlib or gzip header around it. Text is never one, and no
    more than MAX_BLOB bytes are taken out of it. The 8-byte floor keeps a strict reader off tiny
    inputs on a whole blob, but inside the walk by the days (_WALKING, the path that also drops
    formats_more's floors) a numbered record is a short slug fragment whose raw deflate is 4 to 7
    bytes, so the floor is lifted there; the header-byte and ASCII guards (a deflate stream is binary)
    still fail closed, and the record's reading is checked against the day's chain and the slug."""
    if (len(b) < 8 and not _WALKING[0]) or b[:1] in (b"\x78", b"\x1f") or b.isascii():
        return None
    try:
        stream = zlib.decompressobj(-15)
        out = stream.decompress(b, MAX_BLOB + 1)
    except zlib.error:
        return None
    return out if stream.eof and not stream.unused_data else None


FORMS = [d_dec2, d_oct2, d_hex2, d_bin2, d_bin7, d_binlsb, d_bigbin, d_bigoct, d_html2, d_qp2, d_dump, d_utf16be,
         d_crock32, d_zb32, d_z85, d_inflate, d_uesc2, d_uescp, d_htmlfold]


# ---------------------------------------------------------------------------- the Day 9 pack
# Backlog row 110 (CSS escapes, character-code calls) and the forms a ninth day may bring. Strict like
# the rest: each refuses what is not in its own form, and the sentence still has to come out.

_CSS = re.compile(r"\\([0-9a-fA-F]{1,6})[ \t\n]?|\\([^0-9a-fA-F\r\nA-Za-z])")


def d_cssesc(b):
    r"""CSS escapes: a backslash and 1 to 6 hex digits, with one optional white space after them
    (`\4e \69 ce`), and a backslash before a mark or a space (`\!`, as CSS.escape writes them). Text
    between escapes is kept. A backslash that starts neither (`\x4e`, a unicode escape) is a
    refusal: that is another language's escape."""
    t = L._text(b)
    if t is None or "\\" not in t:
        return None
    out, at, hits = [], 0, 0
    for m in _CSS.finditer(t):
        if "\\" in t[at:m.start()]:
            return None
        out.append(t[at:m.start()])
        if m.group(1):
            v = int(m.group(1), 16)
            if not 0 < v <= 0x10FFFF or 0xD800 <= v <= 0xDFFF:
                return None
            out.append(chr(v))
        else:
            out.append(m.group(2))
        hits += 1
        at = m.end()
    if "\\" in t[at:] or not hits:
        return None
    out.append(t[at:])
    return "".join(out).encode()


_CODE_CALL = re.compile(r"(?i)fromCharCode|fromCodePoint|\b(?:uni)?chrw?\b|\bchar\b|\[char(?:\[\])?\]|\bbytes\b"
                        r"|\bbytearray\b|\bBuffer\.from\b|\bUint8Array\b")
_CODE_REST = re.compile(r"(?i)0x[0-9a-f]+|\d+|string\.|fromCharCode|fromCodePoint|(?:uni)?chrw?|char|bytes|bytearray"
                        r"|buffer|from|new|uint8array|join|map|concat|[\s()\[\]{},+.&|;:'\"$=\-]")
_CODE_NUMBER = re.compile(r"0[xX][0-9a-fA-F]+|\d+")


def d_charcodes(b):
    """Character codes inside the call that turns them into text: String.fromCharCode(78,105),
    chr(78).chr(105), chr(78)+chr(105), CHAR(78,105), CHR(78)||CHR(105), [char]78+[char]105,
    "".join(map(chr,[78,105])), bytes([78,105]), Buffer.from([78,105]), new Uint8Array([78,105]).
    The call's own words, brackets and joining marks
    are dropped and the numbers (decimal or 0x hex) are the characters; anything else in the text
    is a refusal. A bare list of numbers is not this form (the list readers have it)."""
    if b"(" not in b and b"]" not in b:   # every such call has a bracket: most payloads leave here
        return None
    t = L._text(b)
    if t is None or len(t) > BIG or not _CODE_CALL.search(t) or _CODE_REST.sub("", t):
        return None
    values = [int(x, 16) if x[:2].lower() == "0x" else int(x) for x in _CODE_NUMBER.findall(t)]
    if len(values) < 2 or any(not 0 < v <= 0x10FFFF or 0xD800 <= v <= 0xDFFF for v in values):
        return None
    return "".join(map(chr, values)).encode()


_XESC = re.compile(r"\\x([0-9a-fA-F]{2})|\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})"
                   r"|\\([0-7]{1,3})|\\([nrtabfv\\'\"/ ])")
_XESC_SIMPLE = {"n": b"\n", "r": b"\r", "t": b"\t", "a": b"\a", "b": b"\b", "f": b"\f", "v": b"\v"}


def d_xescp(b):
    r"""Text in which some characters are C, JavaScript or Python escapes (\x4e, \116, \n, and the unicode escapes)
    and the rest is written as it is. At least one \xNN or octal escape must be there (text with
    only \u escapes is uescp's), and every backslash must start an escape."""
    t = L._text(b)
    if t is None or not re.search(r"\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}", t):
        return None
    out, at = bytearray(), 0
    for m in _XESC.finditer(t):
        if "\\" in t[at:m.start()]:
            return None
        out += t[at:m.start()].encode()
        x, ub, u4, u8, octal, simple = m.groups()
        if x:
            out.append(int(x, 16))
        elif ub or u4 or u8:
            v = int(ub or u4 or u8, 16)
            if v > 0x10FFFF or 0xD800 <= v <= 0xDFFF:
                return None
            out += chr(v).encode()
        elif octal:
            out.append(int(octal, 8) & 255)
        else:
            out += _XESC_SIMPLE.get(simple, simple.encode())
        at = m.end()
    if "\\" in t[at:]:
        return None
    return bytes(out + t[at:].encode())


XX = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_XX = {c: i for i, c in enumerate(XX)}


def d_xx(b):
    """xxencode: each line is a length character and groups of four characters of XX for three
    bytes. A line whose length character does not fit its body is a refusal."""
    t = L._text(b)
    if t is None:
        return None
    out, lines = bytearray(), 0
    for ln in t.splitlines():
        ln = ln.rstrip("\r")
        if not ln.strip() or ln.startswith("begin ") or ln == "end":
            continue
        n = _XX.get(ln[0], -1)
        body = ln[1:]
        if n == 0 and not body:
            continue
        if not 0 < n <= 45 or len(body) != -(-n // 3) * 4 or any(c not in _XX for c in body):
            return None
        chunk = bytearray()
        for i in range(0, len(body), 4):
            v = (_XX[body[i]] << 18) | (_XX[body[i + 1]] << 12) | (_XX[body[i + 2]] << 6) | _XX[body[i + 3]]
            chunk += v.to_bytes(3, "big")
        out += chunk[:n]
        lines += 1
    return bytes(out) if lines and len(out) >= 4 else None


def d_yenc(b):
    """yEnc with its =ybegin line: every byte is 42 higher, and '=' escapes the next one (64 more)."""
    if not b.lstrip().startswith(b"=ybegin "):
        return None
    out = bytearray()
    for ln in b.splitlines():
        if ln.startswith((b"=ybegin", b"=ypart", b"=yend")):
            continue
        i = 0
        while i < len(ln):
            c = ln[i]
            if c == 0x3D:
                i += 1
                if i >= len(ln):
                    return None
                c = (ln[i] - 64) & 255
            out.append((c - 42) & 255)
            i += 1
    return bytes(out) if out else None


def _b92(c):
    n = ord(c)
    if c == "!":
        return 0
    if 35 <= n <= 95:
        return n - 34
    if 97 <= n <= 125:
        return n - 35
    return -1


def d_b92(b):
    """base92: pairs of characters are 13 bits, a last single character 6."""
    if b" " in b or b'"' in b or len(b) < 6:   # neither is in its alphabet: most payloads leave here
        return None
    t = L._text(b)
    if t is None:
        return None
    t = t.strip("\r\n")
    if len(t) < 6 or len(t) > BIG:
        return None
    vals = [_b92(c) for c in t]
    if min(vals) < 0:
        return None
    bits = []
    for i in range(0, len(vals) - 1, 2):
        x = vals[i] * 91 + vals[i + 1]
        if x > 8191:
            return None
        bits.append(format(x, "013b"))
    if len(vals) % 2:
        if vals[-1] > 63:
            return None
        bits.append(format(vals[-1], "06b"))
    bits = "".join(bits)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))


def d_utf7(b):
    """UTF-7: the characters written as +<base64 of UTF-16>- (a '!' is +ACE-), the rest as it is."""
    if not b.isascii() or not re.search(rb"\+[A-Za-z0-9/]{3,}-?", b):
        return None
    try:
        out = b.decode("utf-7").encode()
    except (UnicodeError, ValueError):
        return None
    return out if out != b else None


def d_utf32(b):
    """UTF-32 in either byte order, with or without a byte order mark."""
    if len(b) < 16 or len(b) % 4:
        return None
    try:
        if b[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
            return b.decode("utf-32").encode()
        if b[3::4].count(0) == b[2::4].count(0) == len(b) // 4:
            return b.decode("utf-32-le").encode()
        if b[0::4].count(0) == b[1::4].count(0) == len(b) // 4:
            return b.decode("utf-32-be").encode()
    except UnicodeError:
        pass
    return None


def d_datauri(b):
    """A data: URI: what follows ';base64,' decoded, or what follows ',' unquoted."""
    m = re.match(rb"\s*data:[A-Za-z0-9/+.\-;=_]*?(;base64)?,(.+?)\s*$", b, re.S)
    if not m:
        return None
    if m.group(1):
        return L.d_b64(m.group(2))
    return urllib.parse.unquote_to_bytes(m.group(2))


_WALKING = [False]   # True while _day_walk reads a record by its day's proved chain (Day 16 retro)


def _walking(on: bool):
    """Set the day walk's flag here and in formats_more.py, whose readers keep floors of their own outside
    the walk (d_emojiaz; Day 18 look-ahead, B3). A copy of formats_more without the flag is left alone."""
    _WALKING[0] = on
    flag = getattr(M, "WALKING", None) if M is not None else None
    if isinstance(flag, list) and flag:
        flag[0] = on
    flag = getattr(BO, "WALKING", None) if BO is not None else None
    if isinstance(flag, list) and flag:
        flag[0] = on


def d_unquote(b):
    """A text inside one pair of quotes ("...", '...', `...`, b'...'): what is between them, when
    the quote does not occur inside. At least 10 characters in the search; inside the day walk
    (_WALKING), any non-empty text: there the chain is the one both saved blobs of the record's day
    prove, and the crib or the slug state checks where the record goes on. Day 16: sixteen records
    cut the sentence into pieces of about seven characters, Day 9's record `"\\u0078..."` read as
    `"xact a"` (8) was refused, and the walk ended at record 9 in all 78 sets."""
    t = L._text(b)
    if t is None:
        return None
    t = t.strip()
    if t[:2] in ("b'", 'b"'):
        t = t[1:]
    if len(t) < (3 if _WALKING[0] else 10) or t[0] not in "\"'`" or t[-1] != t[0] or t[0] in t[1:-1]:
        return None
    return t[1:-1].encode()


def d_mime(b):
    """Row 211: a MIME encoded-word, =?charset?B?<base64>?= or =?charset?Q?<quoted-printable>?=, as an
    email header writes non-ASCII. Only when an encoded word is actually present; the crib then decides."""
    if b"=?" not in b or b"?=" not in b or not b.isascii():
        return None
    try:
        import email.header
        parts = email.header.decode_header(b.decode("ascii"))
    except Exception:  # noqa: BLE001 - not a well-formed encoded word
        return None
    out, encoded = b"", False
    for payload, charset in parts:
        if isinstance(payload, bytes):
            encoded = encoded or charset is not None
            out += payload
        else:
            out += payload.encode("utf-8", "replace")
    return out if encoded and out != b else None


_PRINTABLE = bytes(range(32, 127)) + b"\t\n\r"


def _ebcdic(b, codec):
    """b read under one EBCDIC code page, or None: non-ASCII bytes, 8 or more, that read as printable text
    (at least 90 percent of the output's bytes; counted by translate, the same count as a loop over the bytes).
    Inside the walk by the days (_WALKING; Day 21 build, round 2) a record of any length, ASCII bytes included,
    is read: there the chain is the one both saved blobs of the record's day prove, and a Mastery of 21 records
    cuts the text into pieces of about five characters (cp037's floor of 8 left every set None)."""
    if not b or (not _WALKING[0] and (b.isascii() or len(b) < 8)):
        return None
    try:
        out = b.decode(codec).encode("utf-8", "replace")
    except (UnicodeError, ValueError):
        return None
    printable = len(out) - len(out.translate(None, _PRINTABLE))
    return out if out != b and printable >= 0.9 * len(out) else None


def d_ebcdic(b):
    """Row 211: EBCDIC (cp037), the mainframe code page. Its bytes are high (a-i are 0x81-0x89), so a blob
    of mostly non-ASCII bytes that reads as printable text under cp037 is a candidate; the crib decides.
    Code page 500 writes '!' as another byte, so its sentence does not fit here: d_ebcdic500 reads it."""
    return _ebcdic(b, "cp037")


def d_ebcdic500(b):
    """Day 21 build, round 2 (row 411): EBCDIC code page 500 (international), asked after cp037. Of the
    sentence's and a slug's characters only '!' differs from cp037 (0x4f here, 0x5a there), so a cp037 blob
    reads 'warmup]' here and a cp500 blob 'warmup|' under d_ebcdic: one of the two continues the sentence,
    never both, and the full-sentence crib alone makes the reading plain, as for every strict decoder."""
    return _ebcdic(b, "cp500")


def d_ebcdic273(b):
    """Day 21 build, round 2 (row 411): EBCDIC code page 273 (German), asked after cp500. It writes '!' as
    cp500 does (0x4f) and differs from cp500 only in 17 bytes the sentence and a slug never hold (umlauts,
    brackets, braces), so a cp273 blob of the event's text is read by d_ebcdic500 with the same characters
    and keeps that chain name. The search asks this one only for a payload that holds one of those bytes
    (_EBCDIC_DIFF), so it adds no second state with the same text; as a step of a chain it reads any payload."""
    return _ebcdic(b, "cp273")


def _byte_class(a, b):
    """A pattern that finds a byte decoded differently by code pages a and b."""
    diff = [x for x in range(256) if bytes([x]).decode(a) != bytes([x]).decode(b)]
    return re.compile(b"[" + b"".join(re.escape(bytes([x])) for x in diff) + b"]")


# Row 411: the bytes code page 500 reads otherwise than cp037 ('!', '[', ']', '|', '^', the cent sign, ...), and the
# bytes cp273 reads otherwise than cp500. A payload with none of them gives the very text the reader before gave,
# which the search holds already: _strict_steps does not ask the later reader then.
_EBCDIC_DIFF = {"ebcdic500": _byte_class("cp037", "cp500"), "ebcdic273": _byte_class("cp500", "cp273")}


_CALL_ARG = re.compile(r"\s*[A-Za-z_$][\w.$]{0,40}\(\s*(?:b|r)?([\"'`])(.{8,})\1\s*\)\s*;?\s*", re.S)


def d_callarg(b):
    """One call around one quoted text (atob("..."), base64.b64decode('...'), bytes.fromhex('...'),
    unescape('...')): the text between the quotes, when the quote does not occur inside. What the
    call would do is not assumed: the other decoders read what is left."""
    t = L._text(b)
    m = _CALL_ARG.fullmatch(t) if t is not None and len(t) <= BIG else None
    if not m or m.group(1) in m.group(2):
        return None
    return m.group(2).encode()


def _varpack(base):
    """Printable characters as numbers with nothing between them and no padding: a code that
    starts with 1 has three digits (100 to 126, octal 100 to 176), any other has two."""
    digits = r"[0-9]+" if base == 10 else r"[0-7]+"

    def f(b):
        t = L._text(b)
        t = t.strip() if t is not None else None   # nothing between the digits: a spaced list is another form
        if not t or len(t) < 8 or not re.fullmatch(digits, t):
            return None
        out, i = bytearray(), 0
        while i < len(t):
            w = 3 if t[i] == "1" else 2
            if i + w > len(t):
                return None
            v = int(t[i:i + w], base)
            if not 32 <= v <= 126:
                return None
            out.append(v)
            i += w
        return bytes(out)
    return f


d_decpack = _varpack(10)
d_octpack = _varpack(8)


def d_nfkc(b):
    """Look-alike characters as the ASCII they stand for: full-width forms, mathematical letters,
    circled and superscript characters, and text with combining marks or zero-width characters in
    it. Only when everything left is ASCII."""
    if b.isascii():
        return None
    t = L._text(b)
    if t is None or len(t) > BIG:
        return None
    n = "".join(c for c in unicodedata.normalize("NFKD", t) if unicodedata.category(c) not in ("Mn", "Me", "Cf"))
    return n.encode() if n.isascii() and n.strip() and n != t else None


def d_base100(b):
    """base100: each byte as one emoji, the four bytes F0 9F (143 + (x + 55) // 64) (128 + (x + 55) % 64)."""
    b = b.strip()
    if len(b) < 16 or len(b) % 4:
        return None
    out = bytearray()
    for i in range(0, len(b), 4):
        if b[i] != 0xF0 or b[i + 1] != 0x9F:
            return None
        v = (b[i + 2] - 143) * 64 + (b[i + 3] - 128) - 55
        if not 0 <= v <= 255:
            return None
        out.append(v)
    return bytes(out)


_ASCII_TEXT = re.compile(rb"[\x20-\x7e\t\r\n]+")


def d_twosym(b):
    """Eight bits per character written with any two symbols instead of 0 and 1 (spaces and tabs,
    two zero-width characters, two letters). Line ends are dropped, and spaces too when they are a
    third symbol. Of the two ways to call the symbols 0 and 1, the one that gives printable ASCII
    is taken; none or both is a refusal."""
    t = L._text(b)
    if t is None or len(t) < 16 or len(t) > BIG:
        return None
    t = t.replace("\r", "").replace("\n", "")
    kinds = set(t)
    if len(kinds) == 3 and " " in kinds:
        t = t.replace(" ", "")
        kinds.discard(" ")
    if len(kinds) != 2 or kinds == {"0", "1"} or len(t) < 16 or len(t) % 8:
        return None
    one, two = sorted(kinds)
    good = []
    for zero in (one, two):
        bits = "".join("0" if c == zero else "1" for c in t)
        o = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
        if _ASCII_TEXT.fullmatch(o):
            good.append(o)
    return good[0] if len(good) == 1 else None


# Row 331 (Day 17, 'Bacon Bits'): the text written as hex, each hex digit (0 to 15) as one group of five
# a/b symbols read as a binary number (a = 0, b = 1), two groups a byte. Classic Bacon of LETTERS stays None
# (rows 88, 136, 160: it cannot carry the slug's two digits); this is a code of the 16 hex digits, which
# carries any byte. The pairs of symbols, each with the one that stands for 0 when the reading is not
# inverted: a and b, the same in capitals, a dot and a dash, 0 and 1.
_BACON_ZERO = {frozenset(b"ab"): ord("a"), frozenset(b"AB"): ord("A"), frozenset(b".-"): ord("."),
               frozenset(b"01"): ord("0")}
_BACON_LEAD = frozenset(b"abAB.-01")
_BACON_SPACE = frozenset(b" \t\r\n\f\v")
BACONHEX_FLOOR = 16   # bytes a five-symbol reading must give outside the day walk (row 331)


def _baconhex(b, inverted: bool):
    """The text whose hex digits are written as groups of two symbols, two groups a byte, or None.

    Strict, all or nothing: exactly one pair of _BACON_ZERO's symbols and white space, nothing else; groups
    of five split on any white space, or one run with no separator (a run wrapped over lines is joined) cut
    in fives; at width five the zero symbol leads every group (every value 15 or less, which pins which
    symbol is 0: `baconhex` reads the pair's first symbol as 0, `baconhex_inv` the other one, so a day's
    chain carries its polarity into a record too short to show it); groups of four only for 0 and 1, split
    by white space and not inverted (four symbols in one run are eight-bit binary, read elsewhere; four-bit
    a/b is d_twosym's); an even count; every byte printable ASCII or white space. Outside the day walk
    (_WALKING) the text must be at least BACONHEX_FLOOR bytes: a short text in two symbols (a piece of
    classic Bacon in the letters a to p, five Morse digits) is not read as hex by the search."""
    if len(b) > BIG or len(b) < 9:
        return None
    t = b.strip()
    if not t or t[0] not in _BACON_LEAD:
        return None
    kinds = frozenset(t) - _BACON_SPACE
    zero = _BACON_ZERO.get(kinds)
    if zero is None:
        return None
    one = next(iter(kinds - {zero}))
    tokens = t.split()
    width = len(tokens[0])
    if width in (4, 5) and all(len(g) == width for g in tokens):
        groups = tokens
    elif not any(c in t for c in b" \t\f\v"):   # one run, perhaps wrapped over lines: cut in fives
        run, width = b"".join(tokens), 5
        if len(run) % 5:
            return None
        groups = [run[i:i + 5] for i in range(0, len(run), 5)]
    else:
        return None
    if width == 4 and (inverted or zero != ord("0") or len(tokens) < 2):
        return None
    if len(groups) % 2 or len(groups) < 2:
        return None
    if not _WALKING[0] and len(groups) // 2 < BACONHEX_FLOOR:
        return None
    if inverted:
        zero, one = one, zero
    if width == 5 and any(g[0] != zero for g in groups):
        return None
    table = bytes.maketrans(bytes((zero, one)), b"01")
    values = [int(g.translate(table), 2) for g in groups]
    out = bytes(16 * values[i] + values[i + 1] for i in range(0, len(values), 2))
    return out if _ASCII_TEXT.fullmatch(out) else None


def d_baconhex(b):
    """Hex digits as groups of five a/b symbols, a = 0 (row 331; _baconhex)."""
    return _baconhex(b, False)


def d_baconhex_inv(b):
    """The same with the pair's second symbol as 0 (b = 0, a = 1; _baconhex)."""
    return _baconhex(b, True)


def d_bf(b):
    """A Brainfuck program (or Ook!) run with a step limit: what it prints. Asked above 8 KB too:
    an Ook! program is ten times its Brainfuck (the sentence is 35 KB of it)."""
    if K is None or len(b) < 16 or len(b) > BF_MAX:
        return None
    t = L._text(b)
    if t is None:
        return None
    if _OOK_ANY.search(t):
        # row 546: ook / OOK tokens are folded to Ook before the pair map (`book.` is not a token: \b)
        t = K.ook_to_brainfuck(_OOK_FOLD.sub("Ook", t))
        if t is None:
            return None
    elif not _SHORT_OOK_REST.sub("", t):
        # row 546: Short Ook (only . ? ! and white space) goes to ook_to_brainfuck's short form, which
        # still asks an even count, the Ook pair map; the program then runs under the step cap, crib-gated
        t = K.ook_to_brainfuck(t)
        if t is None:
            return None
    elif re.sub(r"[+\-<>\[\].,\s]", "", t) or "+" not in t or "." not in t:
        return None
    return K.brainfuck(t, steps=200_000)


BF_MAX = 96 * 1024   # bytes of a program d_bf runs
_OOK_ANY = re.compile(r"(?i)\book[.?!]")          # an Ook! token in any letter case (row 546)
_OOK_FOLD = re.compile(r"(?i)\book(?=[.?!])")     # the word part of such a token, folded to `Ook`
_SHORT_OOK_REST = re.compile(r"[.?!\s]")          # what Short Ook is made of (row 546)

# row 547: esolang_more.py's Rockstar and Befunge-98 readers. Only these two of its four: its Chef and
# Shakespeare share esolang2's step names, and esolang2 reads them. Each is asked only behind a signature
# cheaper and stricter than the module's own _which (which still runs inside the module's step_fn), so the
# states of a 133-set Mastery pay a regular expression, not a parse. Each reader keeps the module's own
# wall-clock backstop (esolang_more.READER_TIME, a perf_counter deadline), its step cap and its output cap,
# and what it prints answers only where it continues the crib, as every strict step.
ESLM_NAMES = frozenset({"rockstar", "befunge98"} & set(ESLM.NAMES)) if ESLM is not None else frozenset()
# Rockstar: a line that starts with an output word and a line that starts with an assignment or cast word.
_ESLM_ROCK_SAY = re.compile(rb"(?im)^[ \t]*(?:say|shout|whisper|scream|print)\b")
_ESLM_ROCK_SET = re.compile(rb"(?im)^[ \t]*(?:put|let|cast|burn)\b")
# Befunge-98: with its data taken out (a ' fetch, a string), every character left must be an instruction, so
# a base85 or prose text that holds an @ has letters outside that set and is refused before the VM runs.
_ESLM_B98_DATA = re.compile(rb"'[\s\S]|\"[^\"]*\"")
_ESLM_B98_REST = re.compile(rb"[0-9a-f+\-*/%!`><^v?_|:\\$.,#gp&~@;jkqrxsnuwz\[\]{}()=it\s]")
_ESLM_B98_ONLY = re.compile(rb"[a-f;jkqrxsnuwz\[\]{}()=it]")   # instructions Befunge-98 has and -93 does not


def _eslm_sig(name: str, b) -> bool:
    """The cheap signature of a Rockstar or Befunge-98 program (row 547)."""
    if not isinstance(b, (bytes, bytearray)) or not (16 <= len(b) <= 256 * 1024) or not bytes(b).isascii():
        return False
    b = bytes(b)
    if name == "rockstar":
        return bool(_ESLM_ROCK_SAY.search(b) and _ESLM_ROCK_SET.search(b))
    if b"@" not in b:
        return False
    code = _ESLM_B98_DATA.sub(b"", b)
    # every character an instruction, and at least one that Befunge-93 lacks: a Befunge-93 program stays
    # formats_more's late `befunge:93` reading, under the name it has always had
    return not _ESLM_B98_REST.sub(b"", code) and (b"'" in b or bool(_ESLM_B98_ONLY.search(code)))


ESLM_TIME = 0.12        # seconds the two readers may spend in one _settle (a crib search of one layout)
_ESLM_SPENT = [0.0]     # reset by _settle and at each blob's start (_solve_once); a real program reads in
                        # about 5 ms, a non-halting junk one takes the module's 0.10 s backstop, and a junk
                        # blob's states can pass the signature 20 times
_ESLM_CUT = [False]     # set when ESLM_TIME refused a payload the signature takes: readings() keeps no such result


def _eslm_run(name: str, b):
    """One esolang_more reader on one payload, behind its signature (row 547); bytes or None."""
    if _ESLM_SPENT[0] > ESLM_TIME:
        if _eslm_sig(name, b):
            _ESLM_CUT[0] = True       # a reading left out for time: what it was part of is cut, not whole
        return None
    if not _eslm_sig(name, b):
        return None
    t0 = time.perf_counter()
    try:
        return ESLM.step_fn(name)(bytes(b)) or None
    except Exception:
        return None
    finally:
        _ESLM_SPENT[0] += time.perf_counter() - t0


def _eslm_steps(cur):
    for name in ("rockstar", "befunge98"):
        if name in ESLM_NAMES:
            out = _eslm_run(name, cur)
            if out:
                yield name, out


def _eslm_step_fn(name: str):
    def f(b):
        return _eslm_run(name, b)
    f.__name__ = "d_" + name
    return f

# row 162: COW (Huntress 2024's "Cattle"). esolangs.py runs it; read here in crib_decode's own pack so a
# copy of this folder without formats_more.py still reads it. A payload that is not COW costs only the look
# _NOT_COW takes at its raw bytes, and a COW program's run cannot outlast COW_TIME whatever the search's
# own budget (esolangs.cow counts a loop's scanning against a deadline, not against its step cap).
COW_MAX = BF_MAX     # bytes of a program d_cow runs (a COW program is ~120 bytes per character it prints)
COW_TIME = 0.05      # seconds one COW program may run
_NOT_COW = re.compile(rb"[^mMoO \t\r\n]")


def d_cow(b):
    """A COW program run with a step and time limit: what it prints, or None. Deterministic, so the slug
    it decodes to is a plain answer, exactly like d_bf's Brainfuck."""
    if _ESO is None or not (24 <= len(b) <= COW_MAX) or _NOT_COW.search(b):
        return None
    t = L._text(b)
    if t is None:
        return None
    return _ESO.cow(t, steps=200_000, deadline=time.perf_counter() + COW_TIME)


def _whitespace_bits(data: bytes) -> bool:
    """True for a blob of spaces and tabs only (and line ends): empty to the eye, bits to d_twosym."""
    return len(data) >= 16 and not data.strip(b" \t\r\n") and b" " in data and b"\t" in data


PACK9 = [d_cssesc, d_charcodes, d_xescp, d_xx, d_yenc, d_b92, d_utf7, d_utf32, d_datauri, d_unquote, d_callarg,
         d_decpack, d_octpack, d_nfkc, d_base100, d_twosym, d_mime, d_ebcdic, d_bf, d_cow, d_baconhex,
         d_baconhex_inv]
# Day 21 build, round 2 (row 411): the cp500 and cp273 readers are not in PACK9. Two more strict decoders asked on
# every state of the search cost the saved bases 3 to 5 percent (each state pays the call and the search's own
# checks); _strict_steps asks these two only for a payload that is not ASCII (EBCDIC never is), right after STRICT,
# so behind d_ebcdic (cp037): a text cp037 already gave keeps its chain name, and an ASCII state pays one isascii().
EBCDIC_LATE = [d_ebcdic500, d_ebcdic273]


# Byte values written in another base (Day 7 build, backlog row 21). Days 3 to 6 wrote each byte
# in base 16, 2, 10 and 8; the same list in base 3 to 36 is read here. One call per state of the
# search answers for every base at once (radix_all), so 31 more bases cost one tokenizing.

RADIX_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"
# Bases with a decoder and a judged name of their own: binary, octal, decimal, hex.
RADIX_SKIP = (2, 8, 10, 16)
RADIX_BASES = tuple(n for n in range(3, 37) if n not in RADIX_SKIP)


def _radix_width(n: int) -> int:
    """Digits of 255 in base n: the width of a zero-padded byte."""
    w = 1
    while n ** w < 256:
        w += 1
    return w


RADIX_WIDTH = {n: _radix_width(n) for n in RADIX_BASES}
_RADIX_TEXT = re.compile(rb"[\x20-\x7e\t\r\n]+")
_RADIX_LIST = re.compile(r"[0-9A-Za-z]+(?:[\s,;|]+[0-9A-Za-z]+)*")


@functools.lru_cache(maxsize=256)
def _digit_runs(b: bytes):
    """(tokens, highest digit, longest token, packed) of a list of digit runs in one case, or
    None. Runs are separated by white space, ',' ';' or '|'; one run with nothing between the
    bytes is `packed` and is cut by each base's width."""
    if len(b) > BIG or not b.isascii():
        return None
    t = b.decode("ascii").strip().strip("[](){}").strip()
    if len(t) < 4 or not _RADIX_LIST.fullmatch(t):
        return None
    tokens = [x for x in re.split(r"[\s,;|]+", t) if x]
    lower = t.lower()
    if t != lower and t != t.upper():   # one case throughout: base64 text is no digit list
        return None
    top = max(RADIX_DIGITS.index(c) for c in set(lower) if c in RADIX_DIGITS)
    packed = len(tokens) == 1
    if not packed and len(tokens) < 2:
        return None
    return tuple(x.lower() for x in tokens), top, max(map(len, tokens)), packed


def radix_all(b: bytes) -> list:
    """[(name, bytes)]: the payload read as byte values in every base of RADIX_BASES its digits
    and run lengths allow, named radix<n>. Strict: the runs must all fit the base (no digit at or
    above it, none longer than a padded byte, every value under 256), and the bytes must be text
    (printable ASCII and white space). A packed run is read only in a base whose padded byte has
    three digits or more, in whole bytes."""
    got = _digit_runs(b)
    if got is None:
        return []
    tokens, top, longest, packed = got
    out = []
    for n in RADIX_BASES:
        if n <= top:
            continue
        w = RADIX_WIDTH[n]
        if packed:
            run = tokens[0]
            if w < 3 or len(run) % w or len(run) < 2 * w:
                continue
            values = [int(run[i:i + w], n) for i in range(0, len(run), w)]
        else:
            if longest > w:
                continue
            values = [int(x, n) for x in tokens]
        if max(values) > 255:
            continue
        o = bytes(values)
        if _RADIX_TEXT.fullmatch(o):
            out.append(("radix%d" % n, o))
    return out


RADIX_NAMES = {"radix%d" % n for n in RADIX_BASES}

for _name, _fn in list(globals().items()):
    if _name.startswith("d_") and callable(_fn):
        _fn.__name__ = _name  # closures would otherwise all report themselves as "f"

_LETTER = re.compile(rb"[A-Za-z]")


def _fast(dec):
    """One of layered_decode's loose steps as a single bytes.translate, under the same name
    and with the same output. They map byte for byte (single-byte xor, the caesar shifts,
    atbash, rot47) and are written there as a Python loop per character; 280 of them run on
    every payload, which was four fifths of a blob's time."""
    name = dec.__name__[2:]
    if name.startswith("xor"):
        table = dec(bytes(range(256)))

        def f(b):
            return b.translate(table)
    else:
        table = dec(bytes(range(128))) + bytes(range(128, 256))
        letters = name != "rot47"   # the caesar shifts and atbash refuse text without a letter

        def f(b):
            if not b.isascii() or (letters and not _LETTER.search(b)):
                return None
            return b.translate(table)
    f.__name__ = dec.__name__
    return f


# The other forms come last: a payload that an earlier decoder reads keeps the chain it had.
STRICT = L.STRICT + [d_urlplus, d_b62, d_b36, d_bigdec, d_b91, d_uu, d_dec3, d_oct3, d_octesc, d_uesc, d_morse2,
                     d_morsex, d_nato, d_brascii, d_braille, d_braille8] + FORMS + PACK9 + [d_runlength, d_revhex]
_FORM_NAMES = {d.__name__[2:] for d in FORMS + PACK9 + EBCDIC_LATE}
# Decoders that are not asked on a payload over BIG (see _safe); d_bf and d_cow have a limit of their own
# (a COW program is tens of KB for a one-line slug, so it is almost always over BIG and must stay asked).
_NOT_BIG = (_FORM_NAMES | set(BIG_NUMBER + INFLATING)) - {"bf", "cow"}
LOOSE = [d if d.__name__ == "d_reverse" else _fast(d) for d in L.LOOSE] + [d_revwords, d_wordorder]
# Day 14 build: the case steps (d_upper before d_swapcase: a text in capitals throughout reads alike under
# both, and a text keeps the first of two equally simple chains; it is the lossy one's) and d_nospace.
LOOSE += [d_upper, d_altcase, d_title, d_swapcase, d_nospace]
# What is worth trying on ASCII text: xor with a key of 0x80 and above turns every byte of it
# into a non-ASCII one, and no character of the sentence or of a slug is left.
LOOSE_ASCII = [d for d in LOOSE if not (d.__name__.startswith("d_xor") and int(d.__name__[5:], 16) >= 0x80)]
_STRICT_NAMES = {d.__name__[2:] for d in STRICT + EBCDIC_LATE} | RADIX_NAMES | (set(M.NAMES) if M else set())
if M is not None:
    _FORM_NAMES |= set(M.NAMES)   # what they give waits behind the older readings for its loose step
if BO is not None:               # Day 21 look-ahead build: strict, and behind every older reading
    _STRICT_NAMES |= set(BO.NAMES)
    _FORM_NAMES |= set(BO.NAMES)
if BE is not None:               # Day 24 look-ahead build: strict, and behind every older reading
    _STRICT_NAMES |= set(BE.NAMES)
    _FORM_NAMES |= set(BE.NAMES)
if ECS is not None:              # self-validating ECC envelopes: syndrome + re-encode + CRC
    _STRICT_NAMES |= set(ECS.NAMES)
    _FORM_NAMES |= set(ECS.NAMES)
if ESL is not None:              # wave 4 breadth build: brainfuck-dialect esolangs, strict (info-complete transforms)
    _STRICT_NAMES |= set(ESL.NAMES)
    _FORM_NAMES |= set(ESL.NAMES)
if ESL2 is not None:             # wave 15 breadth build: Chef and Shakespeare, strict (deterministic info-complete)
    _STRICT_NAMES |= set(ESL2.NAMES)
    _FORM_NAMES |= set(ESL2.NAMES)
if ESL3 is not None:             # wave 122 breadth build: ><> Fish and LOLCODE, strict (deterministic info-complete)
    _STRICT_NAMES |= set(ESL3.NAMES)
    _FORM_NAMES |= set(ESL3.NAMES)
if ESL4 is not None:             # Day 28 look-ahead build: boolfuck and a crib-learned BF token-dialect, strict
    _STRICT_NAMES |= set(ESL4.NAMES)
    _FORM_NAMES |= set(ESL4.NAMES)
if ESLM_NAMES:                   # row 547: Rockstar and Befunge-98, strict (deterministic, input-free, crib-gated)
    _STRICT_NAMES |= ESLM_NAMES
    _FORM_NAMES |= ESLM_NAMES
if NS is not None:               # B-094: the one non-parametric name (atomic); the rest carry their params
    _STRICT_NAMES |= set(NS.NAMES)
    _FORM_NAMES |= set(NS.NAMES)

# --- B-230: the cumulative decoder pack -------------------------------------------------------------
# Every optional decoder family registered here is tried against a warmup blob in ONE pass of the strict
# search (_strict_steps / _step_fn), behind the built-in readers, so a reading the built-ins already reach
# keeps its simpler chain. A family is (label, names, steps, step_fn): steps(b) yields (name, bytes|None)
# like a built-in reader; step_fn(name) returns a bytes->bytes|None decoder to replay one of its readings
# (or None when it cannot, e.g. an ambiguous reading that declines rather than guessing). A family is only
# ever called on a state the capped, budgeted search reached, so it inherits the per-blob time budget, the
# CAP state cap and the 1 MiB skip (solve_blob refuses an over-MAX_BLOB blob before any family runs).
# B-250 (warmups residuals: keyed digit options, ITA1, DTMF/QR re-entry, Enigma M4, esolang subsets) hooks
# its families in through register_family, with no edit to the hot search code.
_BUILTIN_STRICT_NAMES = frozenset(_STRICT_NAMES)   # snapshot before any family is folded in
_BUILTIN_FORM_NAMES = frozenset(_FORM_NAMES)


class _Family:
    __slots__ = ("label", "names", "steps", "step_fn")

    def __init__(self, label, names, steps, step_fn):
        self.label, self.names, self.steps, self.step_fn = label, frozenset(names), steps, step_fn


_FAMILIES = []


def _refresh_family_names():
    """Rebuild the strict/form name sets in place from the built-in snapshot plus every folded family, so
    _rank and the chain readers (which read these globals at call time) see the current pack."""
    extra = frozenset().union(*(f.names for f in _FAMILIES)) if _FAMILIES else frozenset()
    _STRICT_NAMES.clear()
    _STRICT_NAMES.update(_BUILTIN_STRICT_NAMES | extra)
    _FORM_NAMES.clear()
    _FORM_NAMES.update(_BUILTIN_FORM_NAMES | extra)
    try:
        _rank.cache_clear()   # a folded name changes _rank for a cached chain that contains it
    except NameError:
        pass                  # _rank is defined below; nothing is cached yet at import time
    try:
        _READ_MEMO.clear()    # a folded family reaches readings the memo was built without
    except NameError:
        pass                  # _READ_MEMO is defined below; empty at import-time registration


def register_family(label, names, steps, step_fn):
    """Fold a decoder family into the one-pass strict search and return it (pass it to unregister_family to
    remove it). `names` is the family's strict step names, `steps(b)` yields its (name, bytes|None) readings,
    and `step_fn(name)` returns a bytes->bytes|None decoder to replay one of them (or None). This is the
    B-250 extension point. A family claiming a name a built-in reader or an earlier family already owns is
    rejected here with a ValueError naming the clash: the earlier reader resolves first in _step_fn, so a
    colliding family would be searched (yielding its reading) yet never replayed -- a silent miss B-250's
    residual families must not be able to introduce."""
    names = frozenset(names)
    clash = names & _STRICT_NAMES
    if clash:
        raise ValueError(
            "register_family(%r): step name(s) %s already claimed by a built-in reader or an earlier "
            "family; the reader asked first resolves in _step_fn, so this family would be searched but "
            "never replayed. Rename the step(s)." % (label, ", ".join(sorted(clash))))
    fam = _Family(label, names, steps, step_fn)
    _FAMILIES.append(fam)
    _refresh_family_names()
    return fam


def unregister_family(fam):
    """Remove a family added by register_family; its names leave the strict-name set unless another folded
    family still claims them or they are built-in."""
    _FAMILIES.remove(fam)
    _refresh_family_names()


def families() -> list:
    """The labels of the decoder families folded into the one pass, built-ins first, in fold order."""
    return ["built-in"] + [f.label for f in _FAMILIES]


if CD is not None:
    # The families codec_decoders adds that the built-in battery lacks: the manual codes -- a 5x5 Polybius
    # square, standard Bacon over an A/B alphabet, and DTMF/multitap keypad runs. Everything else it carries
    # is already read under a built-in name -- the bases base16/32/64, base32hex, ascii85, base85, z85,
    # base91/92, base45, crockford32, zbase32, base58* and base62*, base122, morse and ita2 (tap is the same
    # 5x5 square as polybius) -- so those are left out: a second reader for bytes a built-in already reaches
    # would only cost every state of the search its call without reaching anything new.
    _CD_ADDS = tuple(n for n in ("polybius", "bacon", "dtmf-text") if n in CD.NAMES)
    _CD_ADD_SET = frozenset(_CD_ADDS)

    def _cd_steps(b, _allow=_CD_ADD_SET):
        # The manual codes are a warmup shape, never a stack of tens of KiB: above BIG they are not asked,
        # like the other forms (a decompression bomb would otherwise pay their per-state regex on every
        # large state -- tests/test_day23_warmups_edges.py's CPU budget).
        if len(b) > BIG:
            return
        for _name, _out in CD.steps(b):
            if _name in _allow:
                yield _name, _out

    def _cd_step_fn(name, _allow=_CD_ADD_SET):
        return CD.step_fn(name) if name in _allow else None

    _CD_FAMILY = register_family("codec_decoders", _CD_ADD_SET, _cd_steps, _cd_step_fn)

# B-250: the Warmups lane residuals (warmup_residuals.py): ITA1 Baudot, headerless yEnc, DTMF re-entry from
# a WAV, QR re-entry from an image, and Chicken programs on B-055's VM. Each is a strict step whose output
# re-enters the search; the crib or a flag-format string is still the only oracle. ITA1 has one case, so a
# slug read through it is case-lossy (warmups.case/ita1): a candidate, never plain on this module's word.
# Each reader decides its own size and signature policy (a WAV or an image is far above BIG).
import warmup_residuals as RES  # noqa: E402

CASE_LOSSY.update(RES.CASE_LOSSY)
_RES_FAMILY = register_family("warmup_residuals", RES.NAMES, RES.steps, RES.step_fn)

# The letter ciphers that may have been written over an encoding, and the encodings looked for
# under them: the payload's letters are mapped back by each, then one of these reads it.
_UNDER = {"d_atbash", "d_rot47", "d_swapcase"} | {"d_caesar%d" % n for n in range(1, 26) if n != 13}
UNDER_CIPHER = [L.d_hex, L.d_b64, L.d_b32, L.d_b64url, L.d_binary, L.d_octal, L.d_decimal, L.d_b85, L.d_a85,
                L.d_b58, L.d_rot13, L.d_morse, d_b36, d_b62]
# Under a caesar shift or atbash, which pass digits and marks through: the encodings whose
# alphabet has letters (rot13 after a shift is only another shift, but not after atbash).
UNDER_LETTERS = [L.d_hex, L.d_b64, L.d_b32, L.d_b64url, L.d_b85, L.d_a85, L.d_b58, L.d_rot13, d_b36, d_b62]
_LETTER_STEPS = set()    # loose steps a day patch added (add_loose): letter ciphers, their digits open like a rotation's


def _safe(decoder, b):
    """The decoder's output, or None when it refuses, fails or would take too long: no blob
    so far is over 1 KB, and a big-number decoder on a long text can use up a whole window
    in one call that no deadline check can interrupt. So can decompression (64 KB of gzip
    hold 50 MB), and every later step would then work on what it gave: above 8 KB it is
    not asked, and an output of more than 1 MB is dropped, whichever decoder it came from.
    The other forms are not asked above 8 KB either: sixteen more decoders on every state of
    a 60 KB stack of digits cost a whole blob the budget it had been read in before."""
    if len(b) > BIG and decoder.__name__[2:] in _NOT_BIG:
        return None
    try:
        out = decoder(b) or None
    except Exception:
        return None
    return None if out is not None and len(out) > MAX_BLOB else out


# Base85 whose encoder filled the last group of four bytes with NULs (Python's pad=True; Z85's own rule
# that the input is a multiple of four): the decoders give the fill back with the text.
ZERO_FILLED = ("a85", "b85", "z85")


def _unfilled(out: bytes):
    """What a base85 decoder gave without its 1 to 3 NUL bytes of fill, or None when there is none to take
    off: the bytes are whole groups of four (so was the text, in groups of five), they end in a NUL but
    not in four (a whole group of NULs is data), and no NUL is among the rest."""
    if len(out) % 4 or not out.endswith(b"\0") or out.endswith(b"\0\0\0\0"):
        return None
    less = out.rstrip(b"\0")
    return less if less and b"\0" not in less else None


def _strict_steps(cur: bytes):
    """(step name, output or None) of every strict decoder on one state of the search, then the
    readings of radix_all: STRICT is asked as it stands at the call (a day patch may add to it).
    A base85 output that ends in an encoder's fill is given a second time without it, under the same
    name: the day's base, its Time Trial and its Mastery record are then one chain, filled or not. A NUL
    is no character of the sentence or of a slug, so at most one of the two can fit."""
    for dec in STRICT:
        out = _safe(dec, cur)
        yield dec.__name__[2:], out
        if out and out[-1] == 0 and dec.__name__[2:] in ZERO_FILLED:
            less = _unfilled(out)
            if less:
                yield dec.__name__[2:], less
    if cur.isascii():
        yield from radix_all(cur)
    else:                      # row 411: EBCDIC code pages 500 and 273, behind cp037 (EBCDIC_LATE)
        for dec in EBCDIC_LATE:
            name = dec.__name__[2:]
            if _EBCDIC_DIFF[name].search(cur):
                yield name, _safe(dec, cur)
    if M is not None:          # formats_more.py's strict readers, behind everything that was here before
        yield from M.steps(cur)
    if BO is not None:         # Day 21 look-ahead build: byte_order.py's readers, behind all of the above
        yield from BO.steps(cur)
    if BE is not None:         # Day 24 look-ahead build: base_extra.py's readers
        yield from BE.steps(cur)
    if ECS is not None:        # Round 5: only explicit, CRC-protected ECC envelopes
        yield from ECS.steps(cur)
    if ESL is not None:        # wave 4 breadth build: brainfuck-dialect programs, last (each gates on its own alphabet)
        yield from ESL.steps(cur)
    if ESL2 is not None:       # wave 15 breadth build: Chef and Shakespeare, last (each gates on its own structure)
        yield from ESL2.steps(cur)
    if ESL3 is not None:       # wave 122 breadth build: ><> Fish and LOLCODE, last (each gates on its own structure)
        yield from ESL3.steps(cur)
    if ESL4 is not None:       # Day 28 look-ahead build: boolfuck and a crib-learned BF token-dialect, last
        yield from ESL4.steps(cur)
    if ESLM_NAMES:             # row 547: Rockstar and Befunge-98, last of all (each behind its own signature)
        yield from _eslm_steps(cur)
    if NS is not None:         # B-094: numeric/symbolic readers, each self-gated on a flag-shaped decode
        yield from NS.steps(cur)
    for fam in _FAMILIES:      # B-230: the folded decoder-pack families, behind every built-in reading
        yield from fam.steps(cur)


@functools.lru_cache(maxsize=None)
def _rank(chain) -> tuple:
    """Lower is the simpler way to have read a payload: fewer loose steps, then fewer steps."""
    return (sum(1 for step in chain if step not in _STRICT_NAMES), len(chain))


def _kind(step: str) -> str:
    """The cipher of a keyed step ('vigenere' of 'vigenere:lemon'); any other step is its own kind."""
    return step.split(":", 1)[0]


@functools.lru_cache(maxsize=256)
def _keyed_fn(name: str):
    """The decoder (bytes -> bytes or None) of a keyed step, from its name, or None for a name that
    is not one. The key is in the name, so a key read off one blob (a day's saved base) reads
    another (a Mastery record)."""
    kind, _, key = name.partition(":")
    try:
        if kind == "xorkey":
            k = bytes.fromhex(key)
            return (lambda b: bytes(x ^ k[i % len(k)] for i, x in enumerate(b))) if k else None
        if kind == "add":
            table = bytes((x - int(key)) % 256 for x in range(256))
            return lambda b: b.translate(table)
        if kind == "rot94":
            n = int(key)
            table = bytes(33 + (x - 33 - n) % 94 if 33 <= x <= 126 else x for x in range(256))
            return lambda b: b.translate(table) if b.isascii() else None
    except ValueError:
        return None
    if kind == "tricol" and TR is not None:        # wave 2: triple columnar, its three orders in the name
        fn = TR.decode_named(name)
    elif M is not None and kind in M.LATE_KINDS:
        fn = M.keyed_fn(name)
    else:
        fn = K.decode_named(name) if K is not None and key else None
    if fn is None:
        return None

    def f(b):
        t = L._text(b)
        out = fn(t.strip("\r\n")) if t is not None else None
        return out.encode() if out else None
    return f


def _step_fn(name: str):
    """The decoder (bytes -> bytes or None) of one step of a chain, by the step's name."""
    if NS is not None and NS.owns(name):   # B-094: our names carry params in a ':' suffix, so resolve before _keyed_fn
        return NS.step_fn(name)
    if ":" in name:
        return _keyed_fn(name)
    if name in _PAD_FNS:
        return _PAD_FNS[name]
    if name.startswith("pad_"):              # row 377: a pad_<char> step built for a filler outside the four
        ch = _pad_char(name)
        if ch is not None:
            return _pad_fn(ch.encode())
    if name in RADIX_NAMES:
        return lambda b: next((o for n, o in radix_all(b) if n == name), None)
    if M is not None and name in M.NAMES:
        return M.step_fn(name)
    if BO is not None and name in BO.NAMES:
        return BO.step_fn(name)
    if BE is not None and name in BE.NAMES:
        return BE.step_fn(name)
    if ECS is not None and name in ECS.NAMES:
        return ECS.step_fn(name)
    if ESL is not None and name in ESL.NAMES:
        return ESL.step_fn(name)
    if ESL2 is not None and name in ESL2.NAMES:
        return ESL2.step_fn(name)
    if ESL3 is not None and name in ESL3.NAMES:
        return ESL3.step_fn(name)
    if ESL4 is not None and name in ESL4.NAMES:
        return ESL4.step_fn(name)
    if name in ESLM_NAMES:
        return _eslm_step_fn(name)
    for fam in _FAMILIES:      # B-230: a folded decoder-pack family's step, for chain replay
        if name in fam.names:
            return fam.step_fn(name)
    for d in STRICT + LOOSE + EBCDIC_LATE:
        if d.__name__[2:] == name:
            return d
    return None


def _reads(name: str, b: bytes) -> bool:
    """True when the strict step `name` gives anything for these bytes."""
    fn = _step_fn(name)
    return fn is not None and bool(_safe(fn, b))


def _apply_bytes(chain, payload: bytes):
    """The payload read by exactly this chain, as bytes, or None when a step refuses it.

    A base85 step that ends the chain gives its text without an encoder's NUL fill, as _strict_steps
    gives it a second time (Day 18 look-ahead, B3): a day whose base and Time Trial are read so (Z85, whose
    encoder fills every text to whole groups of four) has its Mastery records read the same way in the day
    walk, where the fill was kept and no record fitted (0 of 88 sets). A NUL is no character of the
    sentence or of a slug, so a reading that kept it could fit nothing; a step inside the chain is left
    as it was."""
    cur = payload
    for i, name in enumerate(chain):
        fn = _step_fn(name)
        cur = _safe(fn, cur.strip(b"\r\n") if name == "reverse" else cur) if fn is not None else None
        if not cur:
            return None
        if i == len(chain) - 1 and cur[-1] == 0 and name in ZERO_FILLED:
            cur = _unfilled(cur) or cur
    return cur


def _apply_chain(chain, payload: bytes):
    """The payload read by exactly this chain, as text, or None when a step refuses it."""
    cur = _apply_bytes(chain, payload)
    return L._text(cur) if cur is not None else None


# Keyed steps that put one character for one character, digits and marks included (the sentence shows the
# marks moved; it has no digit), and the one that reverses blocks. Each has a second way to have written
# the slug's two digits that the sentence cannot tell from the first: see _keyed_rival.
KEYED_EACH = ("rot94", "add", "xorkey", "kbd", "vigascii")
UNTOLD = object()   # _keyed_rival: the digits could not be checked


def _keyed_rival(chain, payload: bytes, slug: str):
    """The other way the last keyed step of `chain` may have written the slug's two digits, as
    (name of the reading taken, name of the other, the other's digits); None when there is no
    other; UNTOLD when that could not be checked (the answer is then None).

    The key was read off the sentence, which holds no digit, so it proves nothing about them:
      - a step that puts one character for one (rot94, add, xorkey, kbd) may have left digits as
        they were. That reading is open only when the cipher text holds digits where the slug's
        digits are: anything else there and the step has plainly moved them.
      - reversed blocks: the last block may be short, and a writer may reverse it or leave it.
        When it is exactly the two digits both give a slug, with the digits swapped.
    `payload` is the one that held the digits (the blob, or a Mastery record)."""
    if not chain or ":" not in chain[-1]:
        return None
    kind = _kind(chain[-1])
    if kind not in KEYED_EACH and kind != "blockrev":
        return None
    before = _apply_bytes(chain[:-1], payload) if len(chain) > 1 else payload
    fn = _keyed_fn(chain[-1])
    if before is None or fn is None:
        return UNTOLD
    before = before.strip(b"\r\n")
    after = _safe(fn, before)
    if not after or len(after) != len(before):
        return UNTOLD
    end = len(after.rstrip())
    if end < 2 or after[end - 2:end] != slug[-2:].encode():
        return UNTOLD
    if kind == "blockrev":
        try:
            size = int(chain[-1].partition(":")[2])
        except ValueError:
            return UNTOLD
        if size > 0 and len(before) % size == 2 and slug[-1] != slug[-2]:
            return "reversed", "kept", slug[-1] + slug[-2]
        return None
    there = before[end - 2:end]
    if there.isdigit() and there != after[end - 2:end]:
        return "moved", "kept", there.decode()
    return None


# Day 20 build (warmups item 3): the encodings a transposition may stand over, each with the alphabet its
# text is written in and the part of the sentence's own encoding that does not depend on the slug (base64
# takes 3 bytes a group and base32 5: the sentence's 87 bytes give 116 and 136 fixed characters; hex all 174).
# The transposition moves an encoder's '=' fill too, so the alphabet takes it anywhere; the strict step that
# decodes the moved text back still refuses a fill out of place.
MOVED_OVER = (("b64", re.compile(r"[A-Za-z0-9+/=]+"), lambda b: base64.b64encode(b[:len(b) // 3 * 3]).decode()),
              ("hex", re.compile(r"[0-9a-f]+"), lambda b: b.hex()),
              ("hex", re.compile(r"[0-9A-F]+"), lambda b: b.hex().upper()),
              ("b32", re.compile(r"[A-Z2-7=]+"), lambda b: base64.b32encode(b[:len(b) // 5 * 5]).decode()))


def _moved_encoding(payload: bytes, deadline: float) -> list:
    """[(chain, text)] for a payload that is a transposition of an encoded text: the transposition is read
    off the sentence's own encoding (its fixed part, MOVED_OVER) by the readers crib_keys uses (rail fence,
    columnar, reversed blocks, and the Day 19 and 20 transpositions), each one reading or nothing, and the
    moved text is then decoded by the encoding's strict step. Only for a payload that is one line in the
    encoding's alphabet and holds every character of that fixed part (a transposition changes none), so any
    other payload pays a regular expression. The chain is (<transposition>, <encoding>)."""
    out = []
    t = L._text(payload)
    if t is None:
        return out
    t = t.strip("\r\n")
    if not LEN + 8 <= len(t) <= 2 * KEYED_MAX:
        return out
    for step, alphabet, encode in MOVED_OVER:
        if not alphabet.fullmatch(t) or time.perf_counter() > deadline:
            continue
        known = encode(CRIB.encode())
        if not K.holds_crib(t, known):
            continue
        moved = []
        rail = K.crib_railfence(t, known)
        if rail:
            moved.append(("rail:%d.%d" % rail, K.railfence_decrypt(t, *rail)))
        order = K.crib_columnar(t, known)
        if order:
            moved.append(("columnar:" + ".".join(map(str, order)), K.columnar_decrypt(t, K._ranks(order))))
        size = K.crib_block_reverse(t, known)
        if size:
            moved.append(("blockrev:%d" % size, K.block_reverse(t, size)))
        if not moved and hasattr(K, "crib_transpositions"):
            moved = K.crib_transpositions(t, known)
        fn = _step_fn(step)
        for name, text in moved:
            plain = L._text(_safe(fn, text.encode()) or b"") if fn is not None else None
            if plain and plain.startswith(CRIB) and all(plain != p for _, p in out):
                out.append(((name, step), plain))
    return out


def keyed(payload: bytes, read: dict, deadline: float) -> dict:
    """{text: chain} for a cipher with a key, the key read off the sentence (known plaintext):
    on the payload and its first strict readings, as they are and reversed, the keyed ciphers of
    solvers/common/classical.py (affine, vigenere, beaufort, autokey, a keyboard shift, a
    substitution for the letters the sentence holds, rail fence, columnar, reversed blocks), a
    rotation of the printable characters by another number than 47 (rot94:<n>), every byte moved
    by one number (add:<n>), and xor with a repeating key of two bytes or more (xorkey:<hex>).
    Each reading starts with the sentence; the search still has to fit all of it and a slug.
    Asked only when the keyless readings of a layout decide nothing (see _settle)."""
    out = {}
    if len(payload) > BIG:
        return out

    def add(text, chain):
        if text is not None and text[:12].lower() == CRIB_L[:12] and text not in read and text not in out:
            out[text] = chain

    texts = sorted(((t, c) for t, c in read.items() if LEN + 8 <= len(t) <= KEYED_MAX and "\n" not in t.strip("\r\n")
                    and all(step in _STRICT_NAMES for step in c)), key=lambda kv: _rank(kv[1]))[:KEYED_SOURCES]
    late = []    # Day 19 build: the readers crib_keys leaves to crib_late, asked below only when nothing read a text
    for text, chain in texts:
        if time.perf_counter() > deadline:
            return out
        t = text.strip("\r\n")
        if K is not None:
            for pre, variant in (((), t), (("reverse",), t[::-1])):
                for name, plain in K.crib_keys(variant, CRIB, late=False):
                    add(plain, chain + pre + (name,))
                late.append((chain + pre, variant))
        if t.isascii() and 33 <= ord(t[0]) <= 126:
            n = (ord(t[0]) - ord(CRIB[0])) % 94
            if n not in (0, 47):
                add(L._text(_keyed_fn("rot94:%d" % n)(t.encode())), chain + ("rot94:%d" % n,))
    raws = [(payload.strip(b"\r\n"), ())]
    for name, o in _strict_steps(payload):   # bytes under a key are often text too (xor with letters)
        if o and LEN + 8 <= len(o) <= KEYED_MAX and len(raws) < KEYED_SOURCES and all(o != r for r, _ in raws):
            raws.append((o, (name,)))
    crib = CRIB.encode()
    for raw, chain in raws:
        if not LEN + 8 <= len(raw) <= KEYED_MAX or time.perf_counter() > deadline:
            continue
        n = (raw[0] - crib[0]) % 256
        if n:
            add(L._text(raw.translate(bytes((x - n) % 256 for x in range(256)))), chain + ("add:%d" % n,))
        key = K.crib_xor(raw, crib) if K is not None else None
        if key and len(key) > 1:
            add(L._text(_keyed_fn("xorkey:" + key.hex())(raw)), chain + ("xorkey:" + key.hex(),))
    if not out and hasattr(K, "crib_late"):
        # Day 19 build (W1, W2): the transpositions and the Vigenere over printable ASCII, only for a payload no
        # reader above read, so a blob an earlier reader reads (Day 18's rail fence, a byte shift, a repeating
        # xor) pays nothing for them.
        for pre, variant in late:
            if time.perf_counter() > deadline:
                return out
            for name, plain in K.crib_late(variant, CRIB):
                add(plain, pre + (name,))
    if not out and K is not None and time.perf_counter() < deadline:
        # Day 20 build (warmups item 3): a transposition over an encoded text (columnar over base64, a rail
        # fence over hex). The sentence's own encoding is known, so it is the crib of the transposition.
        for chain, plain in _moved_encoding(payload, deadline):
            add(plain, chain)
    if M is not None and not out and time.perf_counter() < deadline:
        # Round 2: another keyboard layout, a table of symbols read off the sentence, a shift of code points,
        # bases in a cycle, a Befunge program. On the payload itself; each still has to fit the sentence.
        t = L._text(payload)
        if t is not None:
            for name, plain in M.late(t.strip("\r\n"), CRIB, deadline):
                add(plain, (name,))
    if TR is not None and not out and time.perf_counter() < deadline:
        # wave 2 breadth build: triple columnar transposition. Asked last, only for a whole blob nothing else
        # read: a transposition is information-preserving, so a reading that reproduces the ENTIRE sentence is
        # the unique correct permutation (crib-provable plain); >1 surviving triple, or a bounded search cut by
        # its cap/deadline, gives None (never a guessed permutation). Bounded (~0.1 s worst case; outer order
        # <=4). On the payload itself and reversed.
        t = L._text(payload)
        if t is not None:
            tt = t.strip("\r\n")
            for variant, pre in ((tt, ()), (tt[::-1], ("reverse",))):
                if out or time.perf_counter() > deadline:
                    break
                for name, plain in TR.crib_readings(variant, CRIB, deadline):
                    add(plain, pre + (name,))
                if not out and EXO is not None:
                    for name, plain in EXO.wide_readings(variant, CRIB, deadline):
                        add(plain, pre + (name,))
    return out


def _keyed_extra(parts, whole: bool, read, deadline: float) -> list:
    """Per payload, the keyed readings to add to a search: for a blob that is one payload, keyed();
    for numbered records, each record read by its day's chain when that chain has a keyed step
    (the key that read the day's saved base blob; _day_checked still asks the Time Trial blob)."""
    if whole and len(parts) == 1:
        return [keyed(parts[0][1], read[0], deadline)]
    out = []
    for (slot, payload), got in zip(parts, read):
        chain = _day_chain(slot) if isinstance(slot, int) and not whole else None
        text = _apply_chain(chain, payload) if chain and any(":" in step for step in chain) else None
        if chain and _kind(chain[-1]) == "xorkey" and not _in_sentence(text) and time.perf_counter() < deadline:
            # B-250: a repeating-key xor record whose variant has its own key (the day's key reads the day's
            # blobs, not this record): the record's own key, read off the sentence at the one place it fits.
            mine = _variant_xor(chain, payload)
            if mine is not None:
                chain, text = mine
        out.append({text: chain} if text is not None and text not in got else {})
    return out


def _in_sentence(text) -> bool:
    """True when a record's reading starts with PIN or more characters that stand in the sentence."""
    t = (text or "").strip("\r\n")
    return len(t) >= PIN and t[:PIN] in CRIB


def _variant_xor(chain, payload: bytes):
    """B-250: (chain, text) for a record under a day chain that ends in xorkey:<key>, read with the record's
    own repeating key: the bytes before that step, xored with the sentence at each place, give a key
    (classical.crib_xor, two periods or more of it checked) at exactly one place, or None. The key restarts
    with the record, as each variant's encoder starts it."""
    if K is None:
        return None
    before = _apply_bytes(chain[:-1], payload) if len(chain) > 1 else payload
    if not before:
        return None
    before = before.rstrip(b"\r\n")
    crib = CRIB.encode()
    found = {}
    for off in range(0, LEN - PIN + 1):
        seg = crib[off:off + len(before)]
        if len(seg) < 2 * PIN:
            break
        key = K.crib_xor(before[:len(seg)], seg)
        if key and len(key) > 1:
            found.setdefault(key, off)
        if len(found) > 1:
            return None
    if len(found) != 1:
        return None
    key = next(iter(found))
    step = "xorkey:" + key.hex()
    text = L._text(_keyed_fn(step)(before))
    return (tuple(chain[:-1]) + (step,), text) if text is not None else None


_READ_MEMO: dict = {}
READ_MEMO_MAX = 2048


def readings(payload: bytes, deadline: float) -> dict:
    """_readings, memoized by payload within the process (backlog row 183): a Mastery repeats most
    records byte for byte across its sets. A result is kept only when the call ended before its
    deadline, so a cut search is never reused, and each caller gets its own copy. Nor is one that the
    Rockstar / Befunge-98 readers' time cap (ESLM_TIME) cut short: their spent time is shared state, and
    a reading made after it ran out lacks theirs, so keeping it would answer None for that payload for the
    rest of the process (SH-08)."""
    got = _READ_MEMO.get(payload)
    if got is None:
        held, _ESLM_CUT[0] = _ESLM_CUT[0], False
        try:
            got = _readings(payload, deadline)
            cut = _ESLM_CUT[0]
        finally:
            _ESLM_CUT[0] = held or _ESLM_CUT[0]
        if not cut and time.perf_counter() <= deadline:
            if len(_READ_MEMO) >= READ_MEMO_MAX:
                _READ_MEMO.clear()
            _READ_MEMO[payload] = got
    return dict(got)


def _readings(payload: bytes, deadline: float) -> dict:
    """{text: chain} for everything within reach of one payload: strict chains to depth 6,
    the payload reversed and then one strict step, and one loose step (reverse, atbash,
    rot47, the caesar shifts, single-byte xor, words reversed) on the payload and on the
    first strict results. A text reached twice keeps its simpler chain."""
    out = {}

    def add(b, chain):
        t = L._text(b)
        if t is not None and (t not in out or _rank(chain) < _rank(out[t])):
            out[t] = chain

    add(payload, ())
    seen, frontier, sources, later = {payload}, [(payload, ())], [(payload, ())], []
    plus = {}   # what urlplus gave -> what it was given
    for _ in range(DEPTH):
        nxt = []
        for cur, chain in frontier:
            before = plus.get(cur) if chain and chain[-1] == "urlplus" else None
            for name, o in _strict_steps(cur):
                if len(seen) > CAP or time.perf_counter() > deadline:
                    break
                if not o or o in seen:
                    continue
                # urlplus takes any text with a '+' and no space. A decoder that reads the text as it stood
                # needs no urlplus in front of it: behind one it reads a text that lost a symbol (Ascii85
                # skips the space a '+' became, and the last digit comes out as another).
                # Not rot13, which reads any letters: that it reads the text as it stood says nothing, and with
                # urlplus+rot13 dropped a form-encoded rot13 text was left to url+rot13+urlplus, a chain that
                # ends in a codec and so gave the digits as settled (rot18 text: 8 wrong slugs of 8; review of W3).
                if before is not None and not _any_text((name,)) and _reads(name, before):
                    continue
                if name == "urlplus":
                    plus[o] = cur
                seen.add(o)
                step = chain + (name,)
                add(o, step)
                # What one of the other forms gave waits behind the rest for its loose step.
                (later if _FORM_NAMES.intersection(step) else sources).append((o, step))
                nxt.append((o, step))
        frontier = nxt
        if not frontier:
            break
    sources += later
    rev = payload.strip(b"\r\n")[::-1]
    for name, o in _strict_steps(rev):
        if time.perf_counter() > deadline:
            break
        if o:
            add(o, ("reverse", name))
    for src, chain in sources[:LOOSE_SOURCES]:
        if time.perf_counter() > deadline:
            break
        for dec in (LOOSE_ASCII if src.isascii() else LOOSE):
            if time.perf_counter() > deadline:
                break
            o = _safe(dec, src)
            if o:
                add(o, chain + (dec.__name__[2:],))
    return out


REVERSE_SOURCES = 24    # strict-prefix states tested for a reversal bridge on a whole-blob miss
REVERSE_TIME = 0.050    # seconds of a blob's miss budget this forecast bridge may spend
REVERSE_TAIL_RESERVE = 0.025  # preserve the established keyed/late-reader tail on tight historical budgets
REVERSE_COMPOSE_MIN_REMAINING = REVERSE_TIME + REVERSE_TAIL_RESERVE
LOOSE_COMPOSE_SOURCES = 32    # strict-prefix states offered one information-preserving loose edge
LOOSE_COMPOSE_STATES = 800    # accepted strict outputs after that edge (not raw transform attempts)
LOOSE_COMPOSE_TIME = 0.100    # bounded miss-only graph; ordinary solved blobs never enter it
# Do not start the new breadth graph unless it can receive its full bound while preserving the historical
# keyed/late-reader tail.  In particular Day 18's 20 ms base retry has only 60 ms total: partially exploring
# this graph produced enough intermediate readings to consume the tail and hid its established rail answer.
LOOSE_COMPOSE_MIN_REMAINING = LOOSE_COMPOSE_TIME + REVERSE_TAIL_RESERVE


def _bridge_steps(cur: bytes):
    """The form-gated shipped readers used by the miss-only reversal bridge.

    ``STRICT`` and the radix readers are the composable byte/text codecs.  The late keyed, lossy and VM packs
    remain on their specialised paths: putting all of those behind every reversed prefix made deliberate-None
    corpora several times slower, while adding no evidence-derived composition.  A future late-pack composition
    therefore still fails closed and is a live reader task, rather than silently taxing every known miss.
    """
    for decoder in STRICT:
        if decoder.__name__ == "d_rot13":
            continue   # maps every letter-text to another: not a form gate, and its digits are ambiguous anyway
        value = _safe(decoder, cur)
        name = decoder.__name__[2:]
        yield name, value
        if value and value[-1] == 0 and name in ZERO_FILLED:
            less = _unfilled(value)
            if less:
                yield name, less
    if cur.isascii():
        yield from radix_all(cur)


def reverse_composed(payload: bytes, deadline: float) -> dict:
    """Text readings whose bounded path contains reversal between strict decoders.

    Asked only by ``_settle``'s existing second pass, after the ordinary readings found no candidate.  Reversal
    is a byte-exact involution: there is no key to guess and every digit is merely moved, so it is the one loose
    edge safe to put back into the strict graph.  It deliberately stays outside ``_STRICT_NAMES``; ranking,
    short-record vouches and day-chain evidence therefore remain exactly as before.

    A cheap first phase walks at most REVERSE_SOURCES strict-prefix states.  Only a prefix whose reversal is itself
    accepted by a shipped strict reader opens the second graph; deliberate garbage and true-ambiguity misses pay
    bounded form checks, not another full search.  DEPTH, CAP, a byte-string ``seen`` set and the caller's deadline
    bound the opened graph.  The inverse edge immediately returns to a seen state.  Before this bridge the fast path
    handled reverse alone and reverse+one-strict, but deterministic stacks with a reversal in the middle, after two
    strict layers, or twice around another codec stopped at an encoded intermediate value.
    """
    if not isinstance(payload, bytes) or time.perf_counter() > deadline:
        return {}
    deadline = min(deadline, time.perf_counter() + REVERSE_TIME)
    out = {}

    def add(value, chain):
        if "reverse" not in chain:
            return
        text = L._text(value)
        if text is not None and (text not in out or _rank(chain) < _rank(out[text])):
            out[text] = chain

    # Prefixes reachable without a reversal.  Breadth is deliberately the same order the ordinary strict graph
    # uses; twenty-four covers the release matrix's depth-six pair-position paths while bounding a miss independent
    # of decoder count.
    prefix_seen, frontier, sources = {payload}, [(payload, ())], [(payload, ())]
    for _ in range(max(0, DEPTH - 2)):
        nxt = []
        for cur, chain in frontier:
            for name, value in _bridge_steps(cur):
                if len(sources) >= REVERSE_SOURCES or time.perf_counter() > deadline:
                    break
                if not value or value in prefix_seen:
                    continue
                prefix_seen.add(value)
                step = chain + (name,)
                sources.append((value, step))
                nxt.append((value, step))
            if len(sources) >= REVERSE_SOURCES or time.perf_counter() > deadline:
                break
        frontier = nxt
        if not frontier or len(sources) >= REVERSE_SOURCES or time.perf_counter() > deadline:
            break

    # Open the graph only where reversing one of those prefixes produces a value a strict reader accepts.
    seen = set(prefix_seen)
    frontier = []
    for cur, chain in sources:
        if len(chain) + 1 > DEPTH or time.perf_counter() > deadline:
            continue
        reversed_ = cur[::-1]
        if reversed_ == cur:
            continue
        # The ordinary fast path gives reversal to its first LOOSE_SOURCES strict states.  The miss-only prefix
        # walk may expose the same exact terminal reversal just beyond that cut; retain it before asking whether
        # another strict layer follows.  The full crib still has to accept the resulting text.
        add(reversed_, chain + ("reverse",))
        if len(chain) + 2 > DEPTH:
            continue
        for name, value in _bridge_steps(reversed_):
            if time.perf_counter() > deadline:
                break
            if not value or value in seen:
                continue
            seen.add(value)
            step = chain + ("reverse", name)
            add(value, step)
            frontier.append((value, step))

    while frontier and time.perf_counter() <= deadline:
        nxt = []
        for cur, chain in frontier:
            if len(chain) >= DEPTH:
                continue
            for name, value in _bridge_steps(cur):
                if len(seen) > CAP or time.perf_counter() > deadline:
                    break
                if not value or value in seen:
                    continue
                seen.add(value)
                step = chain + (name,)
                add(value, step)
                nxt.append((value, step))
            value = cur[::-1]
            if len(seen) <= CAP and value and value not in seen:
                seen.add(value)
                step = chain + ("reverse",)
                add(value, step)
                nxt.append((value, step))
        frontier = nxt
    return out


def loose_composed(payload: bytes, deadline: float) -> dict:
    """Read one form-preserving loose transform before, between, or after strict codecs.

    ROT47, Atbash and Caesar are cheap bijections but are intentionally not ordinary
    graph edges: multiplying every strict state by every key would make deliberate misses expensive.
    This miss-only bridge first keeps a small breadth-first set of *strict* prefixes.  It offers each
    prefix one loose edge, but opens a suffix graph only when a shipped strict decoder accepts the
    transformed bytes.  Thus a key/rotation is continued because the next layer has real syntax, not
    because its output happens to be printable.  The final answer remains gated by the complete warmup
    sentence in ``_search``.

    Reversal retains its older specialised bridge (and its historical ranking behavior); lossy case,
    spacing and word-order transforms are not promoted here because their output cannot prove the bytes
    they discarded. Single-byte/repeating XOR composition stays on ``envelope_answer``'s crib-gated
    shared peeler, retaining its established provenance.
    """
    if not isinstance(payload, bytes) or time.perf_counter() > deadline:
        return {}
    # The bridge covers one loose edge in a bounded three-layer composition.  A canonical Base64
    # stream that is still Base64 after four complete decodes is a deeper strict-only nest, not one
    # of those shapes.  Decline it before the miss-only graph: otherwise exhausting the crib slice
    # marks the deliberate miss out-of-time and triggers the untimed 3x retry (the historical
    # seven-deep resource fixture rose from <0.45 s to >0.52 s).
    probe = payload
    for _ in range(4):
        probe = _safe(L.d_b64, probe)
        if not probe:
            break
    else:
        return {}
    deadline = min(deadline, time.perf_counter() + LOOSE_COMPOSE_TIME)
    out = {}

    def add(value, chain):
        text = L._text(value)
        if text is not None and (text not in out or _rank(chain) < _rank(out[text])):
            out[text] = chain

    # These are exactly layered_decode's information-preserving loose transforms, through crib_decode's
    # fast translation-table wrappers.  High-bit XOR keys cannot turn ASCII encoded text into another
    # ASCII codec layer and are already excluded by LOOSE_ASCII.
    loose = [dec for dec in LOOSE_ASCII
             if dec.__name__ in {"d_atbash", "d_rot47"} or dec.__name__.startswith("d_caesar")]
    # XOR composition is handled by the crib-gated shared envelope peeler.  Keeping it on that route
    # preserves the established ``envelope`` provenance and avoids duplicating 127 keys in this graph.

    # Strict prefixes: enough for a loose edge after two or three outer codecs, bounded independently of
    # the number of decoder families.  A prefix is retained only when a strict decoder actually parsed it.
    prefix_seen, frontier, sources = {payload}, [(payload, ())], [(payload, ())]
    for _ in range(max(0, DEPTH - 2)):
        nxt = []
        for cur, chain in frontier:
            for name, value in _bridge_steps(cur):
                if len(sources) >= LOOSE_COMPOSE_SOURCES or time.perf_counter() > deadline:
                    break
                if not value or value in prefix_seen:
                    continue
                prefix_seen.add(value)
                step = chain + (name,)
                sources.append((value, step))
                nxt.append((value, step))
            if len(sources) >= LOOSE_COMPOSE_SOURCES or time.perf_counter() > deadline:
                break
        frontier = nxt
        if not frontier:
            break

    suffix_seen = set(prefix_seen)
    accepted = 0

    def strict_suffix(first, first_chain):
        """Continue one syntax-accepted loose result immediately, before trying another key."""
        nonlocal accepted
        frontier = [(first, first_chain)]
        while frontier and time.perf_counter() <= deadline and accepted < LOOSE_COMPOSE_STATES:
            nxt = []
            for state, state_chain in frontier:
                if len(state_chain) >= DEPTH:
                    continue
                for strict_name, strict_value in _bridge_steps(state):
                    if time.perf_counter() > deadline or accepted >= LOOSE_COMPOSE_STATES:
                        break
                    if not strict_value:
                        continue
                    accepted += 1
                    strict_chain = state_chain + (strict_name,)
                    add(strict_value, strict_chain)
                    if strict_value not in suffix_seen and len(strict_chain) < DEPTH:
                        suffix_seen.add(strict_value)
                        nxt.append((strict_value, strict_chain))
            frontier = nxt

    for cur, chain in sources:
        if time.perf_counter() > deadline or len(chain) >= DEPTH:
            break
        decoders = loose if cur.isascii() else [d for d in loose if d.__name__.startswith("d_xor")]
        for dec in decoders:
            if time.perf_counter() > deadline:
                break
            value = _safe(dec, cur)
            if not value or value == cur:
                continue
            loose_chain = chain + (dec.__name__[2:],)
            add(value, loose_chain)          # the loose transform may itself be terminal
            if len(loose_chain) >= DEPTH:
                continue
            for name, parsed in _bridge_steps(value):
                if time.perf_counter() > deadline or accepted >= LOOSE_COMPOSE_STATES:
                    break
                if not parsed:
                    continue
                accepted += 1
                step = loose_chain + (name,)
                add(parsed, step)
                if parsed not in suffix_seen and len(step) < DEPTH:
                    suffix_seen.add(parsed)
                    strict_suffix(parsed, step)
            if accepted >= LOOSE_COMPOSE_STATES:
                break
        if accepted >= LOOSE_COMPOSE_STATES:
            break

    return out


def under_cipher(payload: bytes, deadline: float) -> dict:
    """{text: chain} for a letter cipher written over one of the encodings (rot47 over base64, a
    caesar shift over hex, atbash over base32): the payload's letters mapped back by each of
    _UNDER, then one strict step of UNDER_CIPHER or radix_all. A caesar shift and atbash leave
    digits alone, so under them only the encodings with letters in their alphabet are looked
    for. Asked only when the first readings of a layout decide nothing (see _settle): it costs
    a known encoding nothing.

    Day 14 build (row 294). The case of the letters is one more thing that may have been changed over a
    letter cipher or under an encoding, and it is looked for here, so a blob the first readings answer
    never pays for it: swapcase and then one encoding with letters in its alphabet (base64 with its
    case swapped); a caesar shift or atbash and then one case step (the first readings hold a case step
    alone, and behind rot13 or any other strict step); the text reversed and then one case step."""
    out = {}
    if len(payload) > BIG or not payload.isascii():
        return out
    letters = bool(_LETTER.search(payload))   # rot47 moves every mark; the others need a letter to move
    if letters:   # Day 14 build (row 294): the case changed in a text that was reversed
        rev = payload.strip(b"\r\n")[::-1]
        for dec2 in (d_upper, d_altcase, d_swapcase):
            t = L._text(_safe(dec2, rev) or b"\xff")
            if t is not None and t not in out:
                out[t] = ("reverse", dec2.__name__[2:])
    for dec in LOOSE_ASCII:
        if dec.__name__ not in _UNDER or time.perf_counter() > deadline:
            continue
        if not letters and dec.__name__ != "d_rot47":
            continue
        o = _safe(dec, payload)
        if not o or o == payload:
            continue
        step = (dec.__name__[2:],)
        digits_too = dec.__name__ == "d_rot47"
        for dec2 in (UNDER_CIPHER if digits_too else UNDER_LETTERS):
            if time.perf_counter() > deadline:
                break
            o2 = _safe(dec2, o)
            t = L._text(o2) if o2 and o2 != o else None
            if t is not None and t not in out:
                out[t] = step + (dec2.__name__[2:],)
        # Day 14 build (row 294): the case changed over a caesar shift or atbash (rot13 is a strict step, and
        # the first readings hold its case forms already). Both steps map letter for letter, in either order.
        for dec2 in (d_upper, d_altcase, d_swapcase) if not digits_too and dec is not d_swapcase else ():
            o2 = _safe(dec2, o)
            t = L._text(o2) if o2 and o2 != o else None
            if t is not None and t not in out:
                out[t] = step + (dec2.__name__[2:],)
        for name2, o2 in radix_all(o) if digits_too else ():
            t = L._text(o2)
            if t is not None and t not in out:
                out[t] = step + (name2,)
    return out


def _joined(text: str) -> list:
    """A decoded text of 2 to JOIN lines with its last lines read as one, for a sentence that
    runs over several lines (a break after 'warmup!', the slug alone on the final line, text
    wrapped at a column): from each line on, the lines joined by a space and by nothing, kept
    when the result starts like the sentence. The search then asks for all of the sentence."""
    if "\n" not in text.strip("\r\n"):
        return []
    raw = [ln for ln in text.splitlines() if ln.strip()]
    if not 2 <= len(raw) <= JOIN:
        return []
    lines = [ln.strip() for ln in raw]
    out = []
    for i in range(len(lines) - 1):
        # By nothing twice: a hard wrap keeps the space at the edge of a line, an indent is not one.
        for joined in (" ".join(lines[i:]), "".join(lines[i:]), "".join(raw[i:]).strip()):
            if joined[:12].lower() == CRIB_L[:12] and joined not in out:
                out.append(joined)
    return out


# ---------------------------------------------------------------------------- known words

_WORDS = None
_SAVED = set()   # the saved slugs' own words, a part of _WORDS
STRONG = 5       # letters from which a dictionary word is unlikely to be met by chance


def _saved_words() -> set:
    """The words of every judged slug saved under the challenges folder: answers the judge
    accepted (key.json) and the snapshots of solved attempts (golden.json). They are the
    judge's own vocabulary, and a few of its words are not in the system dictionary.
    answers.json is not read: a run writes it before the judge has spoken (a dry run, a
    rejected submission, a day patch), and a wrong slug's words would count as known, and
    as strong, in every later run. Reading can fail in any way without costing more than
    the words."""
    words = set()
    try:
        root = labels.challenges_root()
        files = [p for d in sorted(root.glob("day-*/warmups-day-*"))
                 for p in sorted(d.rglob("*.json")) if p.name in ("key.json", "golden.json")]
        for path in files[:400]:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict) and isinstance(data.get("answers"), dict):
                data = data["answers"]
            for value in (data.values() if isinstance(data, dict) else ()):
                if isinstance(value, str) and SLUG_FULL.fullmatch(value):
                    words.update(value.split("-")[:3])
    except Exception:
        pass
    return words


def vocabulary() -> set:
    """Known words: the system dictionary (three letters and more: it lists every single
    letter and many two-letter fragments as words) and the saved slugs' words."""
    global _WORDS
    if _WORDS is None:
        _SAVED.update(_saved_words())
        _WORDS = {w for w in L._dictionary() if len(w) >= 3} | _SAVED
    return _WORDS


def known_words(slug: str) -> int:
    """How many different known words a slug's three words hold. With no word list at all
    the answer is 0, so nothing is accepted on its words. A word that occurs twice counts
    once: a wrong key that turns one word into a known word does the same to its twin
    (vigenere on 'coral-coral' read by a caesar shift gave 'sonny-sonny')."""
    return len(set(slug.split("-")[:3]) & vocabulary())


def _strong(word: str) -> bool:
    """A word known beyond chance: a word of a saved slug, or a dictionary word of five
    letters or more. The system dictionary holds one in a hundred of all four-letter strings
    (girr, ulla, boof), so two short words can come out of a wrong caesar shift; one in a
    thousand five-letter strings is a word."""
    return word in _SAVED or (len(word) >= STRONG and word in vocabulary())


def strong_words(slug: str) -> int:
    """How many different strong words (see _strong) a slug's three words hold."""
    return sum(_strong(w) for w in set(slug.split("-")[:3]))


def read_here(slug: str, shares) -> tuple:
    """(known, strong): the slug's different known words, and the strong ones among them,
    that speak for a transform nobody checked.

    `shares` is one (slug characters, unchecked) pair per payload, in order: how many of the
    slug's characters the payload gave, and whether it was read without any check (no
    sentence letters in it, and a chain that turns any text into text). A word speaks for
    such a payload only if the payload itself gave at least READ of its letters (all of
    them for a shorter word). 'nimble-ba' from a record in binary says nothing about the
    cipher of the next record, and a wrong key that leaves some letters alone completes
    'br' to 'brine' from three letters more easily than it writes a word."""
    flags = []
    for count, unchecked in shares:
        flags += [bool(unchecked)] * count
    known, strong, at = set(), set(), 0
    vocab = vocabulary()
    for word in slug.split("-")[:3]:
        here = sum(flags[at:at + len(word)])
        at += len(word) + 1
        if word in vocab and here >= min(READ, len(word)):
            known.add(word)
            if _strong(word):
                strong.add(word)
    return known, strong


vocabulary()  # at import, so a timed run pays for the dictionary before its clock starts


# ---------------------------------------------------------------------------- the crib search

def numbered(data: bytes):
    """[(record number, payload)] of a numbered-record blob in record order, or None."""
    lines = [ln for ln in data.splitlines() if ln.strip()]
    hits = [L.RECORD.match(ln) for ln in lines]
    if not lines or not all(hits):
        return None
    return [(int(m.group(1)), m.group(2).rstrip(b"\r")) for m in sorted(hits, key=lambda m: int(m.group(1)))]


def _last_line(text: str) -> str:
    """The final non-empty line of a decoded blob, without the white space around it: the
    line the question asks about."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def _untrailed(text: str) -> str:
    """The text without what may stand behind the slug in the last record of a blob: line breaks and
    white-space-only lines, from the first line break of the white space the text ends in. A text that
    ends in no line break (a space, a tab, a lone carriage return) comes back as it is.
    One pass from the end, whatever the text: a pattern looked for from every line break of a reading
    that is line breaks by the thousand took minutes, in one call no deadline can cut (review of W3)."""
    body = text.rstrip(" \t\r\n")
    tail = text[len(body):]
    at = tail.find("\n")
    if at < 0:
        return text
    return body + tail[:at - 1 if tail[at - 1:at] == "\r" else at]


START = (0, False, 0)   # of a slug read so far: (hyphens passed, inside a word, digits)
DONE = (3, False, 2)


@functools.lru_cache(maxsize=None)
def _grow(state, text):
    """The state of a slug after `text` is added to one in `state`, or None when the result
    is not the beginning of any slug (three lowercase words, each followed by a hyphen, then
    two digits). The search asks this for every reading at every step, so it is remembered."""
    words, inside, digits = state
    for c in text:
        if "a" <= c <= "z":
            if words == 3:
                return None
            inside = True
        elif c == "-":
            if not inside:
                return None
            words, inside = words + 1, False
        elif "0" <= c <= "9":
            if words != 3 or digits == 2:
                return None
            digits += 1
        else:
            return None
    return (words, inside, digits)


def _cased(text: str, chain, at: int, k: int) -> bool:
    """False only for a reading through d_swapcase whose first k characters are not the sentence's at
    offset `at` capital for capital (Day 14 build). The fit compares without regard to case, as it always
    has; swapcase is believed as an exact inverse, so it must give the sentence as it is written. A text
    in capitals throughout, swapped, is the sentence in small letters: that one is d_upper's."""
    return "swapcase" not in chain or text[:k] == CRIB[at:at + k]


def _search(parts, whole: bool, deadline: float, under=None, extra=None):
    """Fit one reading per payload to the sentence, left to right.

    parts is [(slot, payload)]. Returns (found, cut, where, read):
      found  [(slug, steps)] for every way the payloads read as the sentence followed by a
             slug; steps is one (chain, sentence letters, slug characters, slot) per payload
      cut    the time or the step limit ended the search early
      where  (payload index, sentence offset) of the furthest point any reading reached
      read   the readings of each payload, for the triage line

    A decoder that strips white space (morse) loses a space at the edge of a record. Where
    the sentence has a space at the current offset and a decoded reading does not start
    with one, the reading is also tried one character further on.

    A line break in the decoded text (Day 12 build), numbered records only. The last record's
    reading may end in line breaks and white-space-only lines: they are dropped before the fit.
    And a record's one line break is taken for a space where it stands at the sentence's last
    space, offset 86 (the slug on a line of its own). Both only for the reading by the chain
    that reads both saved blobs of the record's day (_day_proved): all 87 characters of the
    sentence proved that chain twice, and nothing else says such a record holds a line break.
    Nothing else is relaxed: any other character behind the two digits or a line break
    anywhere else leaves the reading out, and a record before the last one is not trimmed.
    A whole blob is read by its last line, as before.

    `under` (from _settle) is the list of readings a first call returned: each payload's
    readings are then those plus under_cipher's, a text reached both ways keeping the simpler
    chain, and nothing is decoded again. With `extra` (one {text: chain} per payload, the keyed
    readings) those are added instead of under_cipher's."""
    read, fits, breaks = [], [], []
    for n, (number, payload) in enumerate(parts):
        # Out of time while the payloads are still being prepared: the search below is cut either way, so
        # the payloads left are not prepared for it (4000 records took three times a blob's budget here).
        # The first payload is always read: the triage line of a cut search is written from it.
        if n and time.perf_counter() > deadline:
            read.extend({} for _ in parts[n:])
            break
        if under is None:
            got = readings(payload, deadline)
        else:
            got = dict(under[n])
            additions = under_cipher(payload, deadline) if extra is None else extra[n]
            bridge_deadline = deadline - REVERSE_TAIL_RESERVE
            if extra is None and whole and time.perf_counter() < bridge_deadline:
                # A form-preserving loose transform may stand before/between/after strict codecs.  These are
                # miss-only bridges: payloads the
                # ordinary graph already answered never pay for it, preserving their release path and budget.
                # A numbered Mastery learns the chain on its whole-blob base/Time Trial and replays that chain;
                # its deliberate-None record combinations therefore do not pay for rediscovery per set. Keep a
                # fixed tail for established keyed/late readers: a forecast bridge must not consume a 20--50 ms
                # historical budget before Day 18's rail/columnar stage gets its turn.
                additions = dict(additions)
                remaining = deadline - time.perf_counter()
                bridges = (reverse_composed,) if remaining >= REVERSE_COMPOSE_MIN_REMAINING else ()
                if remaining >= LOOSE_COMPOSE_MIN_REMAINING:
                    bridges = (loose_composed, reverse_composed)
                for bridge in bridges:
                    if time.perf_counter() >= bridge_deadline:
                        break
                    for text, chain in bridge(payload, bridge_deadline).items():
                        if text not in additions or _rank(chain) < _rank(additions[text]):
                            additions[text] = chain
            for text, chain in additions.items():
                if text not in got or _rank(chain) < _rank(got[text]):
                    got[text] = chain
        read.append(got)
        final = not whole and n == len(parts) - 1
        options, broken = {}, {}
        day = False   # the chain of this record's day (_day_proved), asked by the first reading that needs it
        for text, chain in got.items():
            s = _last_line(text) if whole else text
            if s and FITTING.fullmatch(s) and (s not in options or _rank(chain) < _rank(options[s])):
                options[s] = chain
            if whole and s and _moves_chars(chain):
                # Day 19 build (W4), generalised by row 377: the last line with a run of one filler behind the
                # slug's two digits (a padded grid before a transposition), read without the pad. Any single
                # repeated filler, not only x/X/_/=; the slug keeps its two digits, so the pad is read off safely
                # even when the filler is a digit, and a filler that ate into the slug is None (_pad_off). Read
                # only where the chain moves characters (a transposition: a grid), so an ordinary full stop or
                # other punctuation behind the slug under a byte or letter encoding is no pad (Day 12's rule).
                off = _pad_off(s)
                if off is not None:
                    core, filler = off
                    padded = chain + (_pad_step_name(filler),)
                    if core not in options or _rank(padded) < _rank(options[core]):
                        options[core] = padded
        # A text of several lines also with its last lines joined (see _joined). Only for the fit: `read`
        # keeps what was decoded, so a joined line does not make a changed template look like the usual one.
        for text, chain in got.items():
            if "\n" not in text:
                continue
            for s in _joined(text):
                if FITTING.fullmatch(s) and (s not in options or _rank(chain) < _rank(options[s])):
                    options[s] = chain
            if whole:
                continue
            # Numbered records (see above). The last record: the line breaks behind the slug are no part of
            # it. Any record: its one line break may stand for the sentence's last space (the slug on a line
            # of its own, as _joined reads it in a whole blob).
            s = _untrailed(text) if final and text[-1:].isspace() else text
            trimmed = s != text and s[-2:].isdigit() and FITTING.fullmatch(s) is not None
            m = ONE_BREAK.fullmatch(s) if "\n" in s else None
            if m is not None and (not CRIB_L[:LEN - 1].endswith(m.group(1).lower())
                                  or _grow(START, m.group(2)) is None):
                m = None   # not the sentence's end, a line break, and the beginning of a slug
            if not trimmed and m is None:
                continue
            # Only the reading by the chain of the record's own day. The day's saved blobs are read when a
            # reading gets here, which the readings of a blob without such a line break do not.
            if day is False:
                day = _day_proved(number)
            if not day or _canon(chain) != day:
                continue
            if trimmed and (s not in options or _rank(chain) < _rank(options[s])):
                options[s] = chain
            if m is not None:   # kept apart with the break's place: fitted only where that is the space before the slug
                key = (m.group(1) + " " + m.group(2), len(m.group(1)))
                if key not in broken or _rank(chain) < _rank(broken[key]):
                    broken[key] = chain
        if not whole and options:
            # Day 13 build. Two steps can read a record alike (a piece without a space reversed whole, or word
            # by word), and a text keeps the first of two equally simple chains. Where the chain that reads
            # both saved blobs of the record's day gives one of the texts and is no less simple than the chain
            # the text has, the text is the day's: the same characters, under the name its day proved.
            proved = _day_proved(number)
            s = _apply_chain(proved, payload) if proved else None
            if s in options and _canon(options[s]) != proved and _rank(proved) <= _rank(options[s]):
                options[s] = proved
        ranked = sorted(options.items(), key=lambda kv: _rank(kv[1]), reverse=True)
        fits.append([(text, text.lower(), chain) for text, chain in ranked])
        breaks.append([(text, text.lower(), chain, gap) for (text, gap), chain in broken.items()
                       if text not in options])
    found, nodes, cut, where = [], 0, time.perf_counter() > deadline, (0, 0)
    stack = [(0, 0, "", START, ())]
    while stack and not cut:
        i, off, tail, state, steps = stack.pop()
        if (i, off) > where:
            where = (i, off)
        if i == len(parts):
            if off == LEN and state == DONE:
                found.append((tail, steps))
            continue
        nodes += 1
        if nodes > NODES or time.perf_counter() > deadline:
            cut = True
            break
        slot = parts[i][0]
        if off == LEN:   # past the sentence: every reading is slug characters or nothing
            for text, _, chain in fits[i]:
                grown = _grow(state, text)
                if grown is not None:
                    stack.append((i + 1, off, tail + text, grown, steps + ((chain, 0, len(text), slot),)))
            continue
        for text, lower, chain, gap in breaks[i]:   # a line break only for the space before the slug
            k = LEN - off
            if off + gap == LEN - 1 and lower[:k] == CRIB_L[off:] and _cased(text, chain, off, k):
                grown = _grow(state, text[k:])
                if grown is not None:
                    letters = _LETTERS[LEN] - _LETTERS[off]
                    stack.append((i + 1, LEN, tail + text[k:], grown, steps + ((chain, letters, len(text) - k, slot),)))
        for text, lower, chain in fits[i]:
            for skip in (0, 1):
                if skip and not (chain and CRIB[off] == " " and text[0] != " "):
                    continue
                at = off + skip
                k = min(len(text), LEN - at)
                if lower[:k] != CRIB_L[at:at + k] or not _cased(text, chain, at, k):
                    continue
                grown = _grow(state, text[k:])
                if grown is None:
                    continue
                letters = _LETTERS[at + k] - _LETTERS[at]
                stack.append((i + 1, at + k, tail + text[k:], grown, steps + ((chain, letters, len(text) - k, slot),)))
    return found, cut, where, read


def _candidates(found, parts=()) -> list:
    """One entry per distinct slug among the fitting readings: its best path (pinned first,
    then the simpler chains), whether that path is pinned, and its known words.

    A path is pinned when every payload that gave slug characters also reproduced at least
    PIN letters of the sentence: the transform that read the slug was checked against the
    crib in the same payload. Letters, because one letter does not tell a caesar shift from
    atbash ('e' and 'r', which end the sentence, are 13 apart: both map them alike), and a
    cipher with a key can leave a few letters in a row as they are.

    A payload without those letters (the last record of a Mastery blob holds the slug's end
    and nothing else) is pinned by its day instead, see _day_checked: its chain is the one
    that reads that day's saved base blob and its saved Time Trial blob, where all 87
    characters of the sentence checked it. Each payload pinned that way must give at least
    one strong word itself: a record written under another key than its day's two blobs
    is letters under the day's chain too, and a word that an earlier record gave would
    vouch for it (4 wrong slugs of 40 in the Day 5 retro's test of that looser rule). And
    when the chain is one that reads any letters, two of the slug's three words must be
    known: the day makes up for one word that no list knows, not for two ('pytcj' three
    back is 'ravel', and with the other two words unknown that one chance word had
    carried a record written five on).
    Such an entry has 'by_day' set, and _decide takes the pin back when it does not stand
    alone (see _day_alone).

    Row 109 (Day 9 build). A payload read by strict steps alone, the same that read both blobs of
    its day, is pinned by the day without a word of its own: a strict decoder refuses what is not
    in its form, so there is no other key the record could be under. And a payload whose
    (record number, chain) the whole delivery vouches for (_PINS, set by solve_set from
    consensus()) is pinned without words too, and that pin is not taken back by _day_alone:
    the rival readings were counted over every set of the delivery."""
    checked = {}   # (chain, slot, payload index of a raw record) -> _day_checked, asked once per search

    def by_day(chain, slot, i):
        record = parts[i][1] if not chain and i < len(parts) else None
        k = (chain, slot, i if record is not None else None)
        if k not in checked:
            checked[k] = _day_checked(chain, slot, record)
        return checked[k]

    def unpinned(slug, steps):
        """0 pinned by the crib; 1 by the day's strict chain or by the delivery (row 109); 2 by the day and a
        word of its own (a loose chain); 3 not pinned."""
        open_ = [i for i, (_, letters, n, _) in enumerate(steps) if n and letters < PIN]
        if not open_:
            return 0
        # Asked only for the payloads the crib left open: a blob of short records has thousands of paths.
        if not all(by_day(steps[i][0], steps[i][3], i) for i in open_):
            return 3
        # Row 109. A record read by strict steps alone, the ones that read both blobs of its day, was put
        # there in that form: it has no other key and owes no word. A record the whole delivery vouches
        # for (_PINS, see consensus) owes none either. Only the others are asked for words of their own.
        loose = [i for i in open_ if _any_text(steps[i][0])]
        asked = [i for i in loose if (steps[i][3], _canon(steps[i][0])) not in _PINS]
        # Day 13 build: a record before the last that the delivery vouches for in this very set (its payload
        # is in the pin), and only in a blob cut where the rule of twelve days cuts it.
        ruled = [i for i in asked if i < len(parts)
                 and (steps[i][3], _canon(steps[i][0]), RULED, parts[i][1]) in _PINS]
        if ruled and _cut_as_ruled(steps, slug):
            asked = [i for i in asked if i not in ruled]
        # A record number its delivery reads a second way (_consensus_records, the last rule) is believed on
        # its day and a word in no set: the word may be the second account's ('repaid' and 'diaper').
        if any(i < len(steps) - 1 and steps[i][3] in _TWICE for i in asked):
            return 3
        # A record before the last is believed on its day and one word only in a blob cut as ruled: a record
        # that lost characters is as slug-shaped as a whole one ('e-stor' for 'ble-stor' kept the word and
        # wrote 'nime-storm'), and the pieces around it close over the gap. (The last record that loses its
        # end loses a digit, and no slug is left.) No saved blob has such a record before Day 13.
        if any(i < len(steps) - 1 for i in asked) and not _cut_as_ruled(steps, slug):
            return 3
        if asked and known_words(slug) < 2:
            return 3
        for i in asked:   # each for itself: the words of one record say nothing about the next one's key
            if not read_here(slug, [(n, j == i) for j, (_, _, n, _) in enumerate(steps)])[1]:
                return 3
        # Pinned by the day only where a loose record was believed on a word of its own: that pin _day_alone
        # may take back for a rival key. A strict record, or one the delivery vouches for, has no rival key.
        return 2 if asked else 1

    best = {}
    for slug, steps in found:
        order = (unpinned(slug, steps), tuple(sum(x) for x in zip(*[_rank(chain) for chain, _, _, _ in steps])))
        if slug not in best or order < best[slug][0]:   # the same slug by another path
            best[slug] = (order, steps)
    return [{"slug": slug, "steps": steps, "pinned": order[0] < 3, "by_day": order[0] == 2,
             "known": known_words(slug)} for slug, (order, steps) in best.items()]


def _shares(steps) -> list:
    """read_here's `shares` for one path of the crib search: per payload, the slug characters
    it gave, and whether nothing checked it (fewer than PIN letters of the sentence in it,
    and a chain that turns any text into text)."""
    return [(n, letters < PIN and _any_text(chain)) for chain, letters, n, _ in steps]


def _any_text(chain) -> bool:
    """True when the chain would have turned any letters into letters: no decoder ran, or one
    of its steps is a loose one or rot13. A strict decoder refuses what is not in its own
    form, so a slug that comes out of strict steps alone was put in. So does a keyed step of
    STRICT_KEYED (hexsym, row 333): its table, learned from all 174 hex digits of the sentence,
    refuses any token it does not hold."""
    return not chain or any((step not in _STRICT_NAMES and not (":" in step and _kind(step) in STRICT_KEYED))
                            or step == "rot13" for step in chain)


STRICT_KEYED = tuple(getattr(M, "STRICT_KINDS", ())) if M is not None else ()


# Steps that are exact bijections over the whole printable range (rot47): every character moves,
# digits and marks included, and the step is its own inverse. A record read by one and giving a valid
# slug was written by it -- rot47 of anything but the rot47 image of a slug is not slug-shaped -- so,
# like a strict decoder (row 109), it is pinned by its own shape, needs no strong word and no delivery
# vouch, and its digits are plain (_open_digits is False for it). A letter cipher is NOT such a step: it
# leaves digits and marks where they stand and maps letters to letters, so every key reads a slug as a
# slug; its digit guard (the NO_DIGITS case) stays. Row 308.
EXACT = frozenset({"rot47"})


def _self_pinning(chain) -> bool:
    """True when a record read by `chain` is pinned by its own shape: a non-empty chain whose every step is
    a strict decoder or an exact full-range bijection (rot47). Such a record needs no word of its own and no
    delivery vouch, exactly as a strict record does (row 109); row 308 adds rot47. rot13 is in _STRICT_NAMES
    but is a letter cipher (it maps letters to letters and leaves digits and marks fixed, like a rotation, so
    a record under another key reads as a slug through it): it is NOT self-pinning and keeps its vouch, as
    _any_text already singles it out."""
    return bool(chain) and all((step in _STRICT_NAMES and step != "rot13") or step in EXACT
                               or (":" in step and _kind(step) in STRICT_KEYED) for step in chain)


def _counts(c) -> bool:
    """Whether a candidate may be believed at all.

    It is pinned; or its slug came out of strict decoders only (a strict decoder does not
    write a slug by accident) and holds two different known words; or the payloads nobody
    checked speak for themselves: they gave two different strong words, or all three words
    are known and they gave two of them. Words that other payloads gave do not count for
    them: with 'nimble-ba' in a binary record, one known word in the next record was enough
    for a cipher that leaves half the alphabet alone to be read as rot47, digits and all.
    Each such payload is asked for itself: with two words read through atbash in one record,
    the next record was believed as it stood ('exwwhu' for 'butter' three on), and the
    reading that undid its shift was then dropped as the first one decoded further.

    A slug read by strict decoders alone is not believed either when a payload that gave
    slug characters unchecked (fewer than PIN letters of the sentence) was read by another
    chain than the one both saved blobs of its day are read by (Day 8 build, backlog row 63).
    With rot13 inside the day's chain (base64 of rot13 text), base64 alone reads the last
    record as rot13 text, and 'onyx' comes out as 'balk', a known word: with the first word
    from the record before it, 6 wrong slugs of 261 ('groovy-fnvybe-balk-88').

    c holds 'pinned', 'known', 'slug' and either 'steps' (a path of the crib search) or
    'shares' (see read_here). The shares are worked out only for a candidate with two known
    words: a blob of many short records has tens of thousands of slug-shaped readings."""
    if c["pinned"]:
        return True
    if c["known"] < 2:
        return False
    for chain, letters, n, slot in c.get("steps", ()):
        if n and letters < PIN and isinstance(slot, int) and not _any_text(chain):
            day = _day_chain(slot)
            if day and day == _day_chain(slot, "time_trial") and _canon(chain) != day:
                return False
    shares = c["shares"] if "shares" in c else _shares(c["steps"])
    for i, (count, unchecked) in enumerate(shares):
        if not (count and unchecked):
            continue
        known_here, strong_here = read_here(c["slug"], [(n, j == i) for j, (n, _) in enumerate(shares)])
        if not (len(strong_here) >= 2 or (c["known"] == 3 and len(known_here) >= 2)):
            return False
    return True


def _within(a, b) -> bool:
    """True when chain a is chain b with some steps left out."""
    rest = iter(b)
    return all(step in rest for step in a)


def _decoded_further(c, others) -> bool:
    """True when candidate c is another candidate decoded further: payload by payload its
    chains hold the other's chains, plus steps the other did not need (quoted-printable
    finding '=49' inside rot47 text, a caesar shift applied to what base85 gave)."""
    mine = [chain for chain, _, _, _ in c["steps"]]
    for o in others:
        if o is c:
            continue
        theirs = [chain for chain, _, _, _ in o["steps"]]
        if len(theirs) == len(mine) and theirs != mine and all(_within(a, b) for a, b in zip(theirs, mine)):
            return True
    return False


def _day_alone(cands) -> list:
    """The candidates, with a pin by the day taken back where it does not stand alone.

    A candidate pinned by its day has one strong word of the unchecked payloads behind it.
    When another slug among the candidates has such a word too, the payloads read as words
    under two keys ('river' under one caesar shift is 'arena' under another), and the day's
    chain is then only one of two accounts: the candidate is judged like any other, on the
    words alone. Measured over every pair of letter ciphers with the last record written
    under another key than its day's blobs: 3 wrong slugs in 13,440 without this.
    The rival must bring a strong word of its own, one the pinned candidate's payloads do not
    give (Day 8 build, backlog row 46). A rival that reads an earlier record another way
    (the %xx record through rot13 and url, 'bright-vayley-blossom-84') and the last one by
    the same atbash has the pinned slug's own word 'blossom', and a shared word is no second
    account: with atbash as the day, 25 of 261 Mastery slugs had no answer. Another key that
    writes its own word ('river' and 'arena') is still caught."""
    if not any(c["by_day"] for c in cands):
        return cands
    words = {c["slug"]: read_here(c["slug"], [(n, letters < PIN) for _, letters, n, _ in c["steps"]])[1]
             if c["known"] else set() for c in cands}

    def rival(c):
        return any(words[o["slug"]] - words[c["slug"]] for o in cands if o["slug"] != c["slug"])
    return [{**c, "pinned": False, "by_day": False} if c["by_day"] and rival(c) else c for c in cands]


def _decide(cands):
    """(the candidate to believe, None) or (None, why not).

    Of the candidates that count (see _counts), one that is only another one decoded further
    is dropped: a strict decoder that finds its own form inside a correct reading, or a
    loose step on top of one, gives a second slug-shaped text. One candidate left is the
    answer. Several are a tie, unless exactly one has all three words known."""
    cands = _day_alone(cands)
    good = [c for c in cands if _counts(c)]
    if not good:
        if not cands:
            return None, "no reading fits the sentence"
        top = max(cands, key=lambda c: c["known"])
        return None, (f"{len(cands)} slug-shaped reading(s), none with enough known words"
                      f" (best {top['slug']!r} has {top['known']})")
    if len(good) > 1:
        good = [c for c in good if not _decoded_further(c, good)]
    if len(good) == 1:
        return good[0], None
    full = [c for c in good if c["known"] == 3]
    if len(full) == 1:
        return full[0], None
    names = ", ".join(repr(c["slug"]) for c in sorted(good, key=lambda c: -c["known"])[:3])
    return None, f"{len(good)} readings compete for the slug ({names})"


# ---------------------------------------------------------------------------- the delivery (row 109)

_PINS = frozenset()   # (record number, chain) pairs the delivery of the set being solved vouches for
_CONSENSUS = {}       # (challenges root, the delivery's blobs) -> its pins
_TWICE = frozenset()  # record numbers that delivery reads a second way (_consensus_records, the last rule)
_SECOND = {}          # (challenges root, the delivery's blobs) -> those record numbers
_TAIL = re.compile(r"-?(?:[a-z]+-)*[0-9]{1,2}")


def _tail_words(text: str) -> bool:
    """True when the end of a slug (`asket-maple-31`) holds a strong word between its hyphens."""
    return any(_strong(w) for w in text.split("-")[:-1] if w)


def consensus(siblings) -> frozenset:
    """The (record number, chain) pairs a whole delivery vouches for; empty when it vouches for none.

    `siblings` is {set number: blob} for every set of the attempt (ctx['siblings'] from
    tools/run.py's split_sets). In a Mastery the last record holds only the slug's end, and under
    a letter cipher one set cannot tell the day's key from a key that happens to write a word:
    a slug with a word no list knows is left None (Day 8 sweep: atbash 11, caesar +3 7 of 38
    sets). All the sets of one delivery are written the same way, so they are asked together.
    The pair (N, chain) is vouched for when

      - every blob is numbered records, the same count, the last one numbered N;
      - chain is the one that reads Day N's saved base blob and its saved Time Trial blob
        (both checked by all 87 characters of the sentence), and it reads any letters (a strict
        chain needs no vouching); or both blobs are read by codecs that escape only some
        characters and no record has anything for them (the chain is then empty);
      - read by it, the last record of every set is the end of a slug, and in at least
        max(5, half) of the sets it holds a strong word;
      - no other chain within the search's reach reads a slug's end with a word of a saved slug
        (the judge's own vocabulary) in more than one set, or with any strong word in more than
        max(2, a sixth of the sets the day's chain gives one in). A second key in the delivery
        writes the judge's words in the sets that are under it; a wrong key writes a dictionary
        word now and then (caesar +9 over atbash: 'hopper', 'pacer', 'tetter' in 3 of 38 sets),
        which is why the dictionary alone is given that much room. A reading that is the day
        chain's own text without its leading hyphen is not another chain's word (Day 12 build: a
        reversed '-petal-89' ends in '-', which punycode drops; it emptied 60 of 60 reverse
        deliveries).

    Read once per delivery and process, inside CONSENSUS_TIME; cut short, it vouches for nothing."""
    if not isinstance(siblings, dict) or len(siblings) < CONSENSUS_MIN:
        return frozenset()
    try:
        key = (str(labels.challenges_root()), frozenset(siblings.items()))
        if key in _CONSENSUS:
            return _CONSENSUS[key]
    except Exception:
        return frozenset()
    if len(_CONSENSUS) > 8:
        _CONSENSUS.clear()
        _SECOND.clear()
    twice = set()
    _CONSENSUS[key] = pins = _consensus(list(siblings.values()), twice)
    _SECOND[key] = frozenset(twice)
    return pins


def _second_way(siblings) -> frozenset:
    """The record numbers the delivery consensus() last read for `siblings` reads a second way
    (_consensus_records, the last rule); empty for a delivery it has not read."""
    try:
        return _SECOND.get((str(labels.challenges_root()), frozenset(siblings.items())), frozenset())
    except Exception:
        return frozenset()


def _consensus(blobs, twice=None) -> frozenset:
    """consensus() without its memory: the pin of the last record (_consensus_last, row 109) and the pins
    of the records before it (_consensus_records, Day 13 build), each read inside its own time. `twice`,
    when it is a set, is given the record numbers the delivery reads a second way."""
    none = frozenset()
    if any(not isinstance(b, (bytes, bytearray)) or len(b) > RETRY_MAX_BYTES for b in blobs):
        return none
    recs = [numbered(bytes(b[3:] if bytes(b[:3]) == BOM else b)) for b in blobs]
    if any(not r for r in recs) or len({(len(r), r[-1][0]) for r in recs}) != 1 or len(recs[0]) < 2:
        return none
    pins = _consensus_last(recs)
    try:   # the records one by one: the last record too, where row 109's own rule gave it no pin
        pins = pins | _consensus_records(recs, last=not pins, twice=twice)
    except Exception:   # the older pin never pays for the newer rule
        pass
    return pins


def _cut_as_ruled(steps, slug: str) -> bool:
    """True when a blob's records are cut where the rule of the first twelve days cuts them: record k of N
    ends at floor(k * L / N) of the L characters of the sentence and the slug (all 363 saved Mastery blobs
    of Days 2 to 12). `steps` is one (chain, sentence letters, slug characters, slot) per record, as the
    search gives them: a record's place in the sentence is told by its letters, so a space that a decoder
    lost at a record's edge (morse) does not count against it. A record that lost characters, or holds
    some that are not its own, moves a cut of the blob: its pin by the delivery does not hold then.
    A generator that cuts by another rule fails this in every blob: see the module text for what that
    costs (every set None where a letters-to-letters record before the last holds only slug characters)."""
    total, count = LEN + len(slug), len(steps)
    letters = chars = 0
    for i, (_, got, n, _) in enumerate(steps):
        letters, chars = letters + got, chars + n
        end = (i + 1) * total // count
        if letters != _LETTERS[min(end, LEN)] or chars != max(0, end - LEN):
            return False
    return True


def _fits_at(text: str, chain, off: int, state):
    """Where a record's reading stands when the records before it reached offset `off` of the sentence
    with a slug in `state`: (offset it begins at, sentence characters it gives), or None when it does not
    go on from there. As in _search: a decoded reading may have lost the space its record began with."""
    if not text:
        return None
    at = off
    if off < LEN and chain and CRIB[at] == " " and text[0] != " ":
        at += 1
    k = min(len(text), LEN - at)
    if text[:k].lower() != CRIB_L[at:at + k] or not _cased(text, chain, at, k) or _grow(state, text[k:]) is None:
        return None
    return at, k


def _by_crib(payload: bytes, off: int, state, deadline: float):
    """(text, chain, (offset, sentence characters)) of the one way a record goes on from offset `off` with
    at least PIN letters of the sentence in it, by any reading within the search's reach: the crib checks
    such a record itself, whatever chain read it. (None, (), None) when no reading does, when two
    readings go on differently (other slug characters, another offset reached), for a record of more
    than RETRY_MAX_BYTES, or out of time."""
    found = {}
    if len(payload) > RETRY_MAX_BYTES or time.perf_counter() > deadline:
        return None, (), None
    got = readings(payload, deadline)
    if time.perf_counter() > deadline:
        return None, (), None
    for text, chain in got.items():
        fit = _fits_at(text, chain, off, state) if FITTING.fullmatch(text) else None
        if fit is None or _LETTERS[fit[0] + fit[1]] - _LETTERS[fit[0]] < PIN:
            continue
        key = (fit[0] + fit[1], text[fit[1]:])
        if key not in found or _rank(chain) < _rank(found[key][1]):
            found[key] = (text, chain, fit)
    # A reading that is another found reading decoded further (its chain is one of the others plus extra
    # steps) is no second way the record goes on: a loose step on top of the simpler reading only moves its
    # own end (Day 9's quoted escapes ' answer' and, with wordorder behind it, 'answer '; row 308). Drop it,
    # as _decide drops a candidate decoded further. The simpler reading is the record's, and the day's.
    if len(found) > 1:
        chains = [c for _, c, _ in found.values()]
        kept = [v for v in found.values() if not any(oc != v[1] and _within(oc, v[1]) for oc in chains)]
    else:
        kept = list(found.values())
    return kept[0] if len(kept) == 1 else (None, (), None)


def _day_walk(parts, deadline: float):
    """Numbered records read one way only, each by the chain that reads both saved blobs of its own day
    (_day_proved), from the first record on for as long as they go on from one another as the sentence
    and then a slug: (steps, marks, offset reached, slug state, slug so far). steps is one (chain, sentence
    letters, slug characters, slot) per record read, as _search gives them; marks is one (offset before the
    record, slug state before it, slug characters before it) each. A record its day's chain leaves as it
    stands (_left_alone) is read as it is, under the empty chain. A record its day's chain does not read
    is taken from the search's readings when the crib itself settles it (_by_crib). The walk ends at the
    first record whose day is not proved, or that does not go on either way."""
    steps, marks, off, state, tail = [], [], 0, START, ""
    last_slot = parts[-1][0] if parts else None
    for slot, payload in parts:
        chain = _day_proved(slot)
        if not chain:
            # Row 297: the record of a day that needs no decoding is read as it stands, under the empty chain.
            text = L._text(payload) if _plain_day(slot) else None
            fit = _fits_at(text, (), off, state) if text is not None and FITTING.fullmatch(text) else None
            if fit is None:
                break
            at, k = fit
            marks.append((off, state, len(tail)))
            steps.append(((), _LETTERS[at + k] - _LETTERS[at], len(text) - k, slot))
            off, state, tail = at + k, _grow(state, text[k:]), tail + text[k:]
            continue
        _walking(True)
        try:
            text = _apply_chain(chain, payload)
        finally:
            _walking(False)
        if all(step in SPARING for step in chain) and (text is None or text.encode("utf-8") == payload):
            text, chain = (L._text(payload) if _left_alone(payload, slot) else None), ()
        if text is None and "spacemark" in chain and any(step != "spacemark" for step in chain):
            # Second round of the Day 14 build: a day that writes a mark for every space (`N i c e / w o r k`).
            # A record with no space in it has no mark for that step to read: it is read by the day's other
            # steps, when what they give holds neither a space nor a mark.
            rest = tuple(step for step in chain if step != "spacemark")
            less = _apply_chain(rest, payload)
            if less is not None and not re.search(r"[ _/]", less):
                text, chain = less, rest
        if text is not None and chain and slot == last_slot:
            # Day 20 build (warmups item 5): the blank pad of a grid behind the slug (_blank_pad).
            text = _blank_pad(text, chain)
        fit = None
        if text is not None and (chain or FITTING.fullmatch(text)):
            fit = _fits_at(text, chain, off, state)
        if fit is None:
            # Not as its day's blobs are read (a seven-character piece of Day 9's quoted escapes is too
            # short for the day's own order of steps). The crib settles such a record whatever read it.
            text, chain, fit = _by_crib(payload, off, state, deadline)
            if fit is None:
                break
        at, k = fit
        marks.append((off, state, len(tail)))
        steps.append((chain, _LETTERS[at + k] - _LETTERS[at], len(text) - k, slot))
        off, state, tail = at + k, _grow(state, text[k:]), tail + text[k:]
    return steps, marks, off, state, tail


def _words_at(tail: str, start: int, end: int) -> set:
    """The strong words of a slug read so far (`tail`) that speak for the characters tail[start:end]: whole
    words (a hyphen stands behind each), with at least READ of their letters (all, for a shorter word) among
    those characters. The measure of read_here, for one record of a walk."""
    out, at = set(), 0
    for word in tail.split("-")[:-1][:3]:
        here = min(at + len(word), end) - max(at, start)
        if word and here >= min(READ, len(word)) and _strong(word):
            out.add(word)
        at += len(word) + 1
    return out


def _consensus_records(recs, last: bool = True, twice=None) -> frozenset:
    """The pins of a delivery for single records (Day 13 build): (record number, chain, RULED, the record's
    payload) for each set's record that the delivery vouches for. With `last` false the last record is
    left out (row 109's own pin stands for it).

    From Day 13 on, the record of a letters-to-letters day (Day 12: the text reversed) is no longer the
    last one. It holds eight or nine characters of the slug and nothing of the sentence, the case row 109
    settled for the last record: one set cannot tell the day's chain from a key that happens to write a
    word. Alone, a set was left None when its record gave no strong word, and also when it gave one and
    another key wrote a dictionary word in the same record ('-revir-y' is 'river' reversed, and '-naren-'
    nine letters on), or a rotation on top of the next record's strict reading did ('stor' and 'k'):
    3 to 9 of 63 sets, whatever the thirteenth encoding. The sets of a delivery are asked together, record
    by record. Each set is first read one way only, every record by the chain of its own day (_day_walk).
    For a record number whose day's two saved blobs are read by one chain that reads any letters (or that
    leaves the record as it stands):

      - the sets that count are those whose walk reaches the record, and in which it gives slug characters
        and fewer than PIN letters of the sentence (the crib checks any other). The walk may end at the
        record itself (it does not go on under its day's chain) in one set, which then has no pin; in two,
        the delivery is written a second way and vouches for no set (reverse and caesar +3 in turn);
      - in at least max(5, two thirds) of them the record speaks for its chain: a strong word of the walk's
        slug is whole and has READ of its letters in the record (_words_at), or the record gives READ
        letters of the sentence at its place. (Over the 342 judged Mastery slugs cut in 13 a twelfth
        record speaks in every one; the judge's 142 words have not grown since Day 8.)
      - no other chain within the search's reach does the same for itself, set into the same place of the
        same walk, with a word of a saved slug in more than one set, or with any strong word, in sets
        where the day's reading gives none, in more than max(2, a sixth of the day chain's sets). A second
        key in the delivery writes words where the day's chain writes letters. A chain that writes a
        dictionary word where the day's chain writes one too is a property of the two ciphers, not a key
        (caesar +9 over atbash turns 'copper', 'pepper' and 'butter' into 'gutter', 'tetter' and 'hopper':
        22 of 63 sets), and the record is under one key. The exception is a word that is the day's word
        read backwards ('reward' for 'drawer'): that one counts in every set, because a record that is
        not reversed at all reads so under the day's reversal. A word the day's reading gives too is no second
        account, nor is the day's own text without its leading hyphen (punycode's twin);
      - and a set is vouched for only when its record gives such a word itself, or when no other chain
        writes one there and the walk reads the whole blob as the sentence and a slug with two known
        words (the delivery makes up for one word no list knows, as the day does in _candidates).

    The last rule (review of 2026-10-12, evening): a record number before the last is read a second way
    when, in more than max(2, a sixth) of its sets, another account of the record's own characters gives
    the walk's slug more known words than the day's reading does. Two accounts are asked. Under the
    reversal, the record's words in the opposite order: each word reversed where it stands ('rotro-minim'
    for 'rotor-minim'; a palindrome spoke for the reversal in 48 of 63 such sets, all wrong). And the
    record's last character where the next record begins with the same one, as the next record's own
    (the text reversed, cut, and the pieces put back in order moves record 12 on by one: 'cooter-bbutter'
    for 'scooter-butter'). Such a record number gets no pin, and `twice`, when it is a set, is given the
    number: _candidates then believes that record on its day and one word in no set, where the word may
    be the other account's ('diaper' for 'repaid'). A day's own reading does this in a few sets of a
    delivery whose words read both ways (1 to 6 of 63 with one such word a slug), which is the room it
    is given; with the judge's words, in none.

    The reversal of a slug's piece is slug-shaped read forward too, and so is every rotation of it: what
    decides is the day's chain and the count over the delivery, never how one reading looks. A pin holds
    only in a blob cut as ruled (_cut_as_ruled), which the users of the pin ask. Cut short by its time,
    the reading of a record number vouches for nothing."""
    deadline = time.perf_counter() + RECORDS_TIME
    count = len(recs[0])
    walks = None
    pins = set()
    for j in range(count if last else count - 1):
        slot = recs[0][j][0]
        day = _day_proved(slot)
        # Row 297 (Day 14 build): a day that needs no decoding, its digits judged on a base, is a
        # letters-to-letters day whose chain is the empty one, and is vouched for by the same counts.
        if not (day or _plain_day(slot)) or any(r[j][0] != slot for r in recs):
            continue
        if day and not _any_text(day) and not all(step in SPARING for step in day):
            continue   # a strict day: its record has no other key and needs no vouching
        if walks is None:
            walks = [_day_walk(r, deadline) for r in recs]
        if sum(1 for steps, *_ in walks if len(steps) == j) > 1:
            continue   # in more than one set the record does not go on under its day's chain: a second way
        sets = speaking = second = backed = 0
        strong, saved, granted = {}, {}, []
        for r, (steps, marks, reached, state, tail) in zip(recs, walks):
            if len(steps) <= j:
                continue
            chain, letters, n, _ = steps[j]
            if not n or letters >= PIN or not _any_text(chain):
                continue
            if time.perf_counter() > deadline:
                return frozenset(pins)
            sets += 1
            off, before_state, before = marks[j]
            payload = r[j][1]
            piece = tail[before:before + n]
            mine = _words_at(tail, before, before + n)
            speaking += bool(mine) or letters >= READ
            # The last rule: another account of the same characters that knows more of the slug's words.
            rest = tail[before + n:]
            accounts = ["-".join(w[::-1] for w in piece.split("-"))] if chain == ("reverse",) else []
            if rest[:1] == piece[-1:]:
                accounts.append(piece[:-1])
            second += any(known_words(tail[:before] + a + rest) > known_words(tail) for a in accounts)
            twin = piece[1:] if piece[:1] == "-" else None
            seen = set()
            for text, other in readings(payload, deadline).items():
                other = _canon(other)
                if other == chain or other in seen or not FITTING.fullmatch(text):
                    continue
                fit = _fits_at(text, other, off, before_state)
                if fit is None:
                    continue
                theirs = text[fit[1]:]
                if theirs == piece or theirs == twin:
                    continue
                words = _words_at(tail[:before] + theirs + tail[before + n:], before, before + len(theirs)) - mine
                if not words:
                    continue
                seen.add(other)
                # Also where the day's reading gives a word, when the other chain's word is that word read
                # backwards: 'drawer' and 'reward' are one record under reverse or under nothing, and a
                # delivery of such words says nothing for either (review: 63 of 63 wrong without this).
                if not mine or any(w[::-1] in mine for w in words):
                    strong[other] = strong.get(other, 0) + 1
                if words & _SAVED:
                    saved[other] = saved.get(other, 0) + 1
            whole = len(steps) == len(r) and reached == LEN and state == DONE
            backed += bool(mine) or letters >= READ or (whole and known_words(tail) >= 3)
            if mine or (not seen and whole and known_words(tail) >= 2):
                granted.append((slot, chain, RULED, payload))
        if time.perf_counter() > deadline:
            break
        if j < count - 1 and second > max(2, sets // 6):
            if twice is not None:
                twice.add(slot)
            continue
        if any(v > 1 for v in saved.values()) or any(v > max(2, speaking // 6) for v in strong.values()):
            continue
        # Day 16 retro: sixteen records cut the slug into pieces of six or seven characters, and a whole word
        # with READ of its letters stood in record 13 in only 24 of its 42 sets (two thirds is 28): 42 sets
        # None. Where NO other chain writes a strong word in ANY set of the delivery, a set also backs the
        # day's chain when the walk reads it whole and all three of its slug's words are known: a wrong key in
        # the record breaks the word that runs through it. Two thirds of the sets must back it, as before. A
        # second key writes words where the day's chain writes letters, so it never leaves `strong` empty.
        backing = backed if not strong and not saved else speaking
        if backing < max(CONSENSUS_MIN, (2 * sets + 2) // 3):
            continue
        pins.update(granted)
    return frozenset(pins)


def _consensus_last(recs) -> frozenset:
    none = frozenset()
    deadline = time.perf_counter() + CONSENSUS_TIME
    slot = recs[0][-1][0]
    chain = _day_chain(slot)
    if chain is None or chain != _day_chain(slot, "time_trial"):
        return none
    last = [r[-1][1] for r in recs]
    if chain and all(step in SPARING for step in chain):
        if not all(_left_alone(p, slot) for p in last):
            return none
        chain = ()
    elif not chain:
        if not _plain_day(slot):   # row 297: a day that needs no decoding, its digits judged on a base
            return none
    elif not _any_text(chain):
        return none
    texts = [L._text(p) if not chain else _blank_pad(_apply_chain(chain, p), chain) for p in last]
    if any(t is None or not _TAIL.fullmatch(t) for t in texts):
        return none
    mine_hits = sum(map(_tail_words, texts))
    if mine_hits < max(CONSENSUS_MIN, (len(texts) + 1) // 2):
        return none
    strong, saved = {}, {}   # rival chain -> sets in which it writes a strong word / a saved slug's word
    for payload, mine in zip(last, texts):
        if time.perf_counter() > deadline:
            return none
        seen = set()
        # The day's own text without its leading hyphen is no rival: a piece that begins with '-' ends in '-'
        # when its day reverses it, and punycode reads that without the hyphen. The same words and the same
        # digits name no other key and no other slug. That text and nothing wider.
        twin = mine[1:] if mine[:1] == "-" else None
        for text, other in readings(payload, deadline).items():
            other = _canon(other)
            if text == mine or other == chain or other in seen or not _TAIL.fullmatch(text) or not _tail_words(text):
                continue
            if text == twin:
                continue
            seen.add(other)
            strong[other] = strong.get(other, 0) + 1
            if any(w in _SAVED for w in text.split("-")[:-1]):
                saved[other] = saved.get(other, 0) + 1
    if time.perf_counter() > deadline:
        return none
    if any(n > 1 for n in saved.values()) or any(n > max(2, mine_hits // 6) for n in strong.values()):
        return none
    return frozenset({(slot, chain)})


# ---------------------------------------------------------------------------- digits

def rot5(text: str) -> str:
    """The text with every digit rotated by five (0 and 5, 1 and 6, ...); letters stay."""
    return "".join(chr((ord(c) - 48 + 5) % 10 + 48) if "0" <= c <= "9" else c for c in text)


def complement(text: str) -> str:
    """The text with every digit d written as 9 - d (0 and 9, 1 and 8, ...): what atbash
    does to letters, done to digits. Letters stay."""
    return "".join(chr(105 - ord(c)) if "0" <= c <= "9" else c for c in text)


def _open_digits(chain) -> bool:
    """True when the chain that read the slug's digits says nothing about them: its last
    step, reversals aside, maps letters only (a rotation, atbash), or no decoder ran at
    all. Such a step passes digits through, and the cipher that was really used may have
    had a rule for them too (rot18 is rot13 with rot5; an atbash that mirrors 0-9); text
    that needed no decoding is the same case with a rotation of zero. Every other step
    fixes the digits it gives back: a byte codec encodes them, rot47 moves them with
    everything else, a reversal only reorders them. A case step and d_nospace touch no digit
    (Day 14 build): the step before them decides, and alone they leave the digits settled."""
    core = list(chain)
    # Row 246 (Day 19 build): a codec that escapes only some characters (PARTIAL: urlplus, url, qp, ...) at the
    # end of the chain passes the slug's digits as they stand, so the step before it decides them, as for a
    # reversal: rot13+urlplus (a letter cipher with '+' for its spaces) leaves the digits open, where the last
    # step alone took them as settled and answered a rot18 text plain and wrong. A filler pad (PAD_STEPS)
    # touches no digit either.
    while core and (core[-1] in REVERSALS or core[-1] in CASE_STEPS or core[-1] == "nospace"
                    or _is_pad_step(core[-1]) or core[-1] in PARTIAL or _kind(core[-1]) in KEYED_MOVING):
        core.pop()
    if not core:
        return not chain
    return (bool(LETTERS_ONLY.fullmatch(core[-1])) or core[-1] in _LETTER_STEPS
            or (":" in core[-1] and _kind(core[-1]) in KEYED_LETTERS) or core[-1] in OPEN_DIGIT_STEPS)


# Strict steps whose digits the sentence cannot check (Day 18 build, B5): upside-down text. Its letters are fixed by
# one table the sentence checks, but the tables in use differ on digits (6 and 9 turned or left), and the
# sentence holds no digit. Digits read through it are unsure: `as_is` (turned), then `unflipped` (6 and 9 as written).
OPEN_DIGIT_STEPS = tuple(getattr(M, "OPEN_DIGITS", ())) if M is not None else ()
_SWAP69 = str.maketrans("69", "96")


def _turned_digits(chain) -> bool:
    """True when the digits were read through a step of OPEN_DIGIT_STEPS. Its two readings differ only on a
    6 or a 9, so a slug without either has its digits settled by both (_answer): plain, no probe."""
    core = [step for step in chain if step not in CASE_STEPS and step not in REVERSALS and step != "nospace"
            and not _is_pad_step(step)]
    return bool(core) and core[-1] in OPEN_DIGIT_STEPS


def _judged(chain, slot) -> bool:
    """True when the judge has accepted this chain with the digits as they are: the chain is
    the one encoding the seed records for day `slot`. The seed has base64, rot13, hex and
    binary for Days 1 to 4, and each was CORRECT as the day's single blob, its Time Trial
    and the Mastery record of the same number. Of those only rot13 leaves the digits open."""
    if not isinstance(slot, int) or len(chain) != 1:
        return False
    try:
        return labels.state(ENCODING % slot).get("accepted") == chain[0]
    except Exception:
        return False


_DAY_CHAINS = {}   # (challenges root, day, mode) -> the chain that reads that day's saved blob, or settled None
_DAY_CUT = object()    # an interrupted, unproved read: returned to _day_chain but NEVER stored in _DAY_CHAINS
DAY_READ = 0.1         # seconds the first read of an ordinary saved blob may take
DAY_READ_PROGRAM = 0.5 # first read of a BF/Ook program: Day 27's 35 KiB blobs need ~0.1 s cold before load
DAY_READ_AGAIN = 0.5   # seconds of a second read, for a blob whose first read the clock cut
DAY_READ_SPARE = 1.0   # seconds all second reads of a process may take together
_DAY_SPARE = [DAY_READ_SPARE]
DAY_CHAINS_FILE = HERE / "day_chains.json"
_DAY_CHAIN_SEED = None  # loaded lazily: exact artifact SHA-256 -> tuple of decoder step names
# Day 21 build, round 2 (row 412): warm() fills _DAY_CHAINS on a thread while a Mastery start is in flight. A day
# read runs the whole search, which uses this module's globals (LAST, _PINS, _WALKING, M.DEADLINE), so it never runs
# beside a solve: a solve holds _SOLVE_LOCK from its first line to its last (_holding), and a fill of _DAY_CHAINS
# takes it too. _SOLVES counts the solves begun in this process; warm() stops at the first slot after a solve began
# (the solve proves the days it needs itself, exactly as cold), so a solve waits for one day's read at most.
_SOLVE_LOCK = threading.RLock()
_SOLVES = [0]


def _lock_after_fork():
    """A forked child (run.py's `warmups=pool` workers) has no warm() thread: a lock that thread held at the fork
    would never be released there, so the child takes a fresh one. A slot it was reading is simply not filled."""
    global _SOLVE_LOCK
    _SOLVE_LOCK = threading.RLock()


try:
    import os as _os
    _os.register_at_fork(after_in_child=_lock_after_fork)
except Exception:   # a platform without fork: nothing to reset
    pass


@functools.lru_cache(maxsize=256)
def _reconciled_kind(chain) -> bool:
    """True when the chain holds a RECONCILED step (asked on every record of a Mastery: kept per chain)."""
    return any(step.split(":", 1)[0] in RECONCILED for step in chain)


def _day_read(day, mode=""):
    """The chain the saved blob of the day and mode is read by, as _DAY_CHAINS holds it (before
    _day_reconciled names its transposition step)."""
    return _day_chain(day, mode, raw=True)


def _day_chain(day, mode="", raw=False):
    """The chain that reads the saved base blob of Warmups day `day` (the single file under
    <challenges>/day-NN/warmups-day-NN/artifact/), when the sentence pins it; else None.
    With mode 'time_trial', the same for the day's saved Time Trial blob
    (.../warmups-day-NN/time_trial/artifact/). Read once per process, day and mode. The
    blob is the day's own encoding with all 87 characters of the crib in it, so its chain
    names the encoding of record `day` in a Mastery blob. No answer file is read."""
    if not isinstance(day, int) or not 1 <= day <= 99:
        return None
    try:
        root = labels.challenges_root()
    except Exception:
        return None
    slot = (str(root), day, mode)
    if slot not in _DAY_CHAINS:
        with _SOLVE_LOCK:   # row 412: one read per slot, never beside a solve or warm()'s own read
            if slot not in _DAY_CHAINS:
                filled = _day_fill(root, day, mode, slot)
                # Row 592: an unpinned search whose own clock expired is not evidence that the saved blob has
                # no day chain. Keeping None here poisoned every later Mastery in this process. Leave the slot
                # absent so a later call, after release load has passed, can prove it.
                if filled is not _DAY_CUT:
                    _DAY_CHAINS[slot] = filled
    chain = _DAY_CHAINS.get(slot)
    # Day 19 build: with its transposition step named alike in the day's two blobs where one name reads both
    # (_day_reconciled; `raw` asks for the chain as read).
    if raw or not chain or not _reconciled_kind(chain) or mode not in ("", "time_trial"):
        return chain
    return _day_reconciled(day, mode, chain)


def _day_seed_rows():
    """The tracked exact-artifact accelerator, or an empty dict.

    The file is data, never authority: malformed rows are dropped, and _day_seed_chain independently applies
    every hit to the artifact and checks the full pinned crib and slug before the chain can be used. A stale
    file, a copied variant or a changed decoder therefore takes the ordinary bounded search.
    """
    global _DAY_CHAIN_SEED
    if _DAY_CHAIN_SEED is not None:
        return _DAY_CHAIN_SEED
    rows = {}
    try:
        raw = json.loads(DAY_CHAINS_FILE.read_text())
        if isinstance(raw, dict):
            for digest, chain in raw.items():
                if (isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
                        and isinstance(chain, list) and len(chain) <= DEEP_WRAPPER_MAX
                        and all(isinstance(step, str) and 0 < len(step) <= 160 for step in chain)):
                    rows[digest] = tuple(chain)
    except (OSError, ValueError, TypeError):
        pass
    _DAY_CHAIN_SEED = rows
    return rows


def _day_endpoint(text) -> bool:
    """True only for the exact pinned sentence followed by exactly one production-shaped slug."""
    if not isinstance(text, str):
        return False
    text = text.rstrip("\r\n")
    return text.startswith(CRIB) and SLUG_FULL.fullmatch(text[LEN:]) is not None


def _day_seed_chain(data: bytes, rows=None):
    """A seed chain for these exact bytes, after applying and re-verifying it; otherwise None."""
    try:
        chain = (rows if rows is not None else _day_seed_rows()).get(hashlib.sha256(data).hexdigest())
        if chain is None:
            return None
        return chain if _day_endpoint(_apply_chain(chain, data)) else None
    except Exception:
        return None


def _day_program(data: bytes) -> bool:
    """Cheap exact-language signature for the BF/Ook blobs whose first proof needs the larger bound."""
    if not (16 <= len(data) <= BF_MAX):
        return False
    text = L._text(data)
    if text is None:
        return False
    return (bool(_OOK_ANY.search(text)) or not _SHORT_OOK_REST.sub("", text)
            or (not re.sub(r"[+\-<>\[\].,\s]", "", text) and "+" in text and "." in text))


def _prove_day_blob(data: bytes, deadline: float):
    """Search one saved blob until `deadline`: (verified chain or None, whether the search was cut)."""
    held = M.DEADLINE[0] if M is not None else None
    if M is not None:
        M.DEADLINE[0] = deadline
    try:
        _, cut, _, _, cand, _ = _settle([(None, data)], True, deadline)
    finally:
        if M is not None:
            M.DEADLINE[0] = held
    cut = bool(cut or time.perf_counter() > deadline)
    chain = _canon(cand["steps"][0][0]) if cand is not None and cand["pinned"] else None
    # _settle's pinned bit retains the existing day-chain semantics, including lossy case/form days whose
    # sentence is established without reproducing its original case. The seed builder applies the returned path
    # and requires _day_endpoint separately, so only exact reversible chains can enter day_chains.json.
    # Spaced characters with `/` for a space are also accepted by d_nato. Keep the historic canonical name.
    spaced = ("spaced", "spacemark")
    if chain == ("nato",) and M is not None and _apply_chain(spaced, data) == _apply_chain(chain, data):
        chain = spaced
    return chain, cut


def _day_fill(root, day, mode, slot):
    """Read one saved slot: a verified chain, settled None, or _DAY_CUT.

    Row 412 still writes a completed result once under _SOLVE_LOCK. Row 592 distinguishes a settled search that
    found no pinned chain (cacheable None) from a clock-cut search (retryable, never cached). Row 593's exact-hash
    seed is only a fast route to the same byte-level proof.
    """
    try:
        where = "day-%02d/warmups-day-%02d*/" % (day, day) + (mode + "/" if mode else "") + "artifact"
        folders = [d for d in sorted(root.glob(where)) if d.is_dir()]
        blobs = [p for d in folders for p in sorted(d.iterdir()) if p.is_file()]
        if len(blobs) == 1 and blobs[0].stat().st_size <= MAX_BLOB:
            data = blobs[0].read_bytes()
            chain = _day_seed_chain(data)
            if chain is not None:
                if chain and _reconciled_kind(chain):
                    _DAY_DATA[slot] = data
                return chain
            # The first read remains 0.1 s for ordinary blobs. BF/Ook is recognized before search and gets the
            # same bounded 0.5 s that a retry had: Day 27's 35 KiB programs sit on the 0.1 s cliff under load.
            first = DAY_READ_PROGRAM if _day_program(data) else DAY_READ
            was_cut = False
            for attempt, limit in enumerate((first, DAY_READ_AGAIN)):
                if attempt:
                    if _DAY_SPARE[0] <= 0:
                        break
                    limit = min(limit, _DAY_SPARE[0])
                began = time.perf_counter()
                chain, cut = _prove_day_blob(data, began + limit)
                if attempt:
                    _DAY_SPARE[0] = max(0.0, _DAY_SPARE[0] - (time.perf_counter() - began))
                if chain is not None:
                    if chain and _reconciled_kind(chain):
                        _DAY_DATA[slot] = data
                    return chain
                was_cut = was_cut or cut
                if not cut:
                    return None
            return _DAY_CUT if was_cut else None
        return None
    except Exception:
        return None


WARM_MODES = ("", "time_trial")


def _saved_days(root) -> list:
    """The days with a saved Warmups folder under the challenges root, in order."""
    days = set()
    for d in root.glob("day-[0-9][0-9]/warmups-day-[0-9][0-9]*"):
        try:
            if d.is_dir():
                days.add(int(d.parent.name[4:]))
        except ValueError:
            continue
    return sorted(n for n in days if 1 <= n <= 99)


def _warm_slots(days, today=None, mode="time_trial"):
    """Slots in release priority: today's/newest day first, and an explicitly requested mode first."""
    normalized = []
    for day in days:
        if isinstance(day, int) and 1 <= day <= 99 and day not in normalized:
            normalized.append(day)
    if today is None:
        today = _event_day(datetime.datetime.now(datetime.timezone.utc))
    normalized.sort(key=lambda day: (day != today, -day))
    modes = list(WARM_MODES)
    if mode in WARM_MODES:
        modes.remove(mode)
        modes.insert(0, mode)
    return [(day, saved_mode) for day in normalized for saved_mode in modes]


def warm(days=None, today=None, mode="time_trial") -> dict:
    """Day 21 build, round 2 (row 412): prove the day chains a Mastery's walk by the days reads (_day_chain of
    each day, the base and the Time Trial, and a reconciled step's name), ahead of the solve. The chains depend
    on the saved blobs only, never on the delivery, yet a fresh run.py proved them inside the window (Day 20:
    0.234 s of the Mastery's 0.44 s solve). Called on a thread while the Mastery start is in flight, or at start.

    `days`: None for every day with a saved Warmups folder; an int N for days 1 to N; or an iterable of days.
    Idempotent and offline (local files only); a slot already filled costs a dict look. Thread-safe with a solve:
    each slot is read under _SOLVE_LOCK, which a solve holds throughout, and warm() stops for good at the first
    slot after a solve has begun, so a solve waits at most for the one read in hand and then proves what is left
    itself, as cold. `today` and `mode` are optional test/runner hints; by default the current Eastern event day,
    saved days newest first and each day's Time Trial are preferred. Never raises. Returns the legacy fields plus
    separate counts for byte-proved chains, settled-unpinned blobs and retryable clock cuts."""
    began = time.perf_counter()
    seen = _SOLVES[0]
    filled = slots = proved = unpinned = cut = 0
    stopped = None
    try:
        root = labels.challenges_root()
        if days is None:
            days = _saved_days(root)
        elif isinstance(days, int):
            days = range(1, days + 1)
        for day, saved_mode in _warm_slots(days, today=today, mode=mode):
            slots += 1
            slot = (str(root), day, saved_mode)
            if slot in _DAY_CHAINS:
                continue
            if _SOLVES[0] != seen:
                stopped = "a solve began"
                break
            with _SOLVE_LOCK:
                if _SOLVES[0] != seen:
                    stopped = "a solve began"
                    break
                _day_chain(day, saved_mode)   # and the reconciled name, as the walk asks for it
                if slot not in _DAY_CHAINS:
                    cut += 1
                else:
                    filled += 1
                    if _DAY_CHAINS[slot] is None:
                        unpinned += 1
                    else:
                        proved += 1
    except Exception as e:  # noqa: BLE001 - a warm-up never costs anything but its own work
        stopped = f"{type(e).__name__}: {str(e)[:120]}"
    got = {"filled": filled, "proved": proved, "unpinned": unpinned, "cut": cut, "slots": slots,
           "seconds": round(time.perf_counter() - began, 4), "stopped": stopped}
    if filled or cut or stopped:   # a warm-up that found everything proved already says nothing
        try:
            print(f"NOTE warmups warm(): proved={proved} unpinned={unpinned} cut={cut} of {slots} day chain(s)"
                  f" ahead in {got['seconds']:.3f} s"
                  f"{'; stopped: ' + stopped if stopped else ''} (row 412)", file=sys.stderr)
        except Exception:
            pass
    return got


def _holding(fn):
    """A solve entry point (solve_set, solve_blob), counted in _SOLVES and run under _SOLVE_LOCK (row 412)."""
    @functools.wraps(fn)
    def held(*args, **kwargs):
        _SOLVES[0] += 1          # before the lock: a warm() between two slots sees it and stops
        with _SOLVE_LOCK:
            return fn(*args, **kwargs)
    return held


def readings_within(payload: bytes, seconds: float) -> dict:
    """{text: chain} of every keyless reading of one payload (readings: the strict chains and one loose step),
    searched for at most `seconds`. The entry point for a caller outside this module that wants the readings and
    not a solve (B-126, render_ocr_sweep): it takes _SOLVE_LOCK, so the read never runs beside a solve or a
    warm() day read, and gives the program readers the same deadline (M.DEADLINE), put back when it returns or
    raises. It is not counted in _SOLVES: it is not a solve, and warm() need not stop for it. ValueError when
    `seconds` is not a positive number: a read with no time is the caller's to skip, by name."""
    try:
        seconds = float(seconds)
    except (TypeError, ValueError) as e:
        raise ValueError(f"readings_within: seconds must be a positive number, not {seconds!r}") from e
    if not 0.0 < seconds < float("inf"):
        raise ValueError(f"readings_within: seconds must be a positive number, not {seconds!r}")
    with _SOLVE_LOCK:
        deadline = time.perf_counter() + seconds
        held = M.DEADLINE[0] if M is not None else None
        if M is not None:
            M.DEADLINE[0] = deadline
        try:
            return readings(bytes(payload), deadline)
        finally:
            if M is not None:
                M.DEADLINE[0] = held


# Day 19 build (W1, conflict C9). A scytale counted by its rows has ceil(L/rows) columns, so the column count
# follows each text's length: crib_columnar names the base blob's reading columnar:0.1...18 and the Time Trial's
# columnar:0.1...19, the two blobs of the day disagree, and no Mastery record is read by the day. And a name
# that reads both blobs may still read a record of another length otherwise (a 7-character record of a 6-row
# scytale has 2 columns; read with 19 identity columns it is the record as it stands, wrongly). So where a
# day's chain holds such a step, every name that reads the step's text in BOTH saved blobs the way each blob's
# own chain read it is kept (columnar by its identity order, the scytale by each row count, and the names an
# agree step already holds), and the day's step is that one name, or agree:<a>|<b>, which reads a record only
# where all of them give the same characters. No name reads both: the chains stay as they are (unproved).
RECONCILED = ("columnar", "scytale", "agree")
_DAY_DATA = {}         # (root, day, mode) -> the saved blob whose chain holds a RECONCILED step
_RECONCILED = {}       # (root, day, base chain, Time Trial chain) -> the chain both are named by, or None


def _identity_columns(step: str):
    """The column count of a columnar step whose order is the identity (a scytale by columns), else None."""
    kind, _, key = step.partition(":")
    if kind != "columnar":
        return None
    try:
        order = [int(x) for x in key.split(".")]
    except ValueError:
        return None
    return len(order) if order == list(range(len(order))) else None


def _step_names(step: str, length: int) -> list:
    """The names that may stand for a transposition step on a text of `length` characters: the step,
    the names an agree step holds, and for a scytale (by columns or by rows) the other count that gives
    the same columns on this length."""
    names = step.partition(":")[2].split("|") if _kind(step) == "agree" else [step]
    out = list(names)
    # Day 20 build (warmups item 1): a decimation of k (every k-th character, k moved on to the next number
    # coprime with the length) is, on one text, a columnar transposition of k columns whose order follows the
    # length mod k: the base and the Time Trial are named by two orders. decim:<k> is offered for a columnar
    # step of k columns (and k - 1 to k - 3, which the move on may have turned into k); _reconcile keeps it only
    # where it reads both blobs as their own chains did.
    for name in names:
        if _kind(name) == "columnar" and hasattr(K, "decimation_decrypt"):
            columns = len(name.partition(":")[2].split("."))
            out += ["decim:%d" % k for k in getattr(K, "DECIM_STEPS", ()) if columns - 3 <= k <= columns]
    for name in names:
        columns = _identity_columns(name)
        if columns is None and _kind(name) == "scytale":
            try:
                columns = -(-length // int(name.partition(":")[2]))
            except (ValueError, ZeroDivisionError):
                columns = None
        if columns is None or columns < 2:
            continue
        # Each family within its own range: a scytale by columns as far as crib_columnar searches (21), by rows
        # 2 to 12. A 4-row scytale of 113 characters has 29 columns, which no columnar reading names: rows only.
        if columns <= getattr(K, "COLUMNAR_MAX", 21):
            out.append("columnar:" + ".".join(map(str, range(columns))))
        out += ["scytale:%d" % rows for rows in getattr(K, "SCYTALE_ROWS", ()) if -(-length // rows) == columns]
    return list(dict.fromkeys(out))


def _day_reconciled(day, mode, chain):
    """See RECONCILED: the day's chain with its transposition step named so that one name reads both saved
    blobs, or `chain` as it is when no name does (the two blobs then stay unproved, as before)."""
    try:
        root = str(labels.challenges_root())
    except Exception:
        return chain
    base, trial = _day_read(day), _day_read(day, "time_trial")
    memo = (root, day, base, trial)
    if memo not in _RECONCILED:
        _RECONCILED[memo] = None
        try:
            _RECONCILED[memo] = _reconcile(base, trial, _DAY_DATA.get((root, day, "")),
                                           _DAY_DATA.get((root, day, "time_trial")))
        except Exception:
            pass
    got = _RECONCILED[memo]
    return got if got is not None else chain


def _reconcile(base, trial, base_data, trial_data):
    """The chain both saved blobs of a day are read by once their one transposition step is named alike
    (RECONCILED), or None. The chains must be equal apart from that step."""
    if not base or not trial or base_data is None or trial_data is None or len(base) != len(trial):
        return None
    at = [i for i, (a, b) in enumerate(zip(base, trial)) if _kind(a) in RECONCILED or _kind(b) in RECONCILED]
    if len(at) != 1 or any(a != b for i, (a, b) in enumerate(zip(base, trial)) if i != at[0]):
        return None
    i = at[0]
    if not (_kind(base[i]) in RECONCILED and _kind(trial[i]) in RECONCILED):
        return None
    texts = []
    for chain, data in ((base, base_data), (trial, trial_data)):
        before = _apply_bytes(chain[:i], data) if i else data
        text = L._text(before) if before is not None else None
        if text is None:
            return None
        text = text.strip("\r\n")
        texts.append((text, K.decode_named(chain[i])(text)))
    kept = []
    for name in _step_names(base[i], len(texts[0][0])) + _step_names(trial[i], len(texts[1][0])):
        fn = K.decode_named(name)
        if name not in kept and fn is not None and all(after is not None and fn(text) == after
                                                       for text, after in texts):
            kept.append(name)
    if not kept:
        return None
    step = kept[0] if len(kept) == 1 else "agree:" + "|".join(kept)
    if K.decode_named(step) is None:
        return None
    return base[:i] + (step,) + base[i + 1:]


def _canon(chain) -> tuple:
    """The chain with each step under the name of the decoder it is a form of (ALIAS): where both
    read a text they give the same characters, so they are one way of reading a day's encoding."""
    return tuple(ALIAS.get(step, step) for step in chain)


def _day_proved(slot):
    """The chain that reads both saved blobs of day `slot`, the base and the Time Trial, or None when
    they are not both read, or not by one chain. Never the empty chain: None for a day that needs no
    decoding."""
    chain = _day_chain(slot)
    return chain if chain and chain == _day_chain(slot, "time_trial") else None


def _plain_day(slot) -> bool:
    """True for a day whose two saved blobs, the base and the Time Trial, both need no decoding at all
    (the empty chain, pinned by all 87 characters of the sentence in each), once the judge has accepted
    a way to read the digits of such a text on a base (warmups.digits/plain has an accepted name).
    Day 14 build, row 297: a day that changes no letter (the text as it is; only the digits moved). Its
    Mastery record is then a record of a letters-to-letters day whose chain is the empty one: _day_walk
    reads it as it stands and the delivery vouches for it as for any letter cipher (_consensus_last),
    by the same counts. No saved day of Days 1 to 13 is such a day."""
    if not isinstance(slot, int) or _day_chain(slot) != () or _day_chain(slot, "time_trial") != ():
        return False
    try:   # the name judged for this day's own slot (_day_key): another day's name does not open the walk
        return bool(labels.state(_day_key(KEY + "plain", slot)[0]).get("accepted"))
    except Exception:
        return False


def _day_checked(chain, slot, record=None) -> bool:
    """True when record `slot` of a Mastery blob, read by `chain`, is read the way its day's
    own blobs are: the saved base blob of day `slot` and the saved Time Trial blob of that
    day are both read by exactly this chain. Each of them is a second variant of the day's
    encoding in which the sentence checked the chain, key and all; a day whose two blobs
    disagree (a key per variant), or with either blob missing, checks nothing. A record that
    needed no decoding (`record` is its payload) is checked only when both blobs of its day
    agree and are read by codecs that escape only some characters, none of which finds anything
    in the record (_left_alone): such an encoder passes a slug's characters as they are (row 73:
    with standard quoted-printable as the day, 2 of 10 slug-only records had no answer)."""
    if not isinstance(slot, int):
        return False
    if not chain:
        return (record is not None and _day_chain(slot) is not None
                and _day_chain(slot) == _day_chain(slot, "time_trial") and _left_alone(record, slot))
    chain = _canon(chain)
    return _day_chain(slot) == chain and _day_chain(slot, "time_trial") == chain


def _left_alone(record, slot) -> bool:
    """True when a record that needed no decoding is explained by its day's encoding: the
    saved base blob of day `slot` is read by codecs that escape only some characters (URL
    quoting, quoted-printable, HTML entities), and none of them finds anything to decode in
    this record. Such an encoder passes a slug through as it is, digits included."""
    chain = _day_chain(slot) if record is not None else None
    if not chain or any(step not in SPARING for step in chain):
        return False
    # Day 13 build: the word order is such a step too. It moves nothing in a piece without a space, and
    # d_wordorder refuses one, as a codec refuses a text with nothing of its own in it.
    by_name = {d.__name__[2:]: d for d in STRICT + [d_wordorder, d_nospace]}
    if M is not None:
        by_name["spacemark"] = M.step_fn("spacemark")
    if ("nospace" in chain or "spacemark" in chain) and b" " in record:   # Day 14 build: such a day left no space in
        return False
    return all(_safe(by_name[step], record) in (None, record) for step in chain)


def _digits_key(chain) -> str:
    """warmups.digits/<chain>, the caesar shifts under one name: whether a rotation's digits
    are rotated too does not depend on the shift, and a variant with another shift must not
    have to learn it again."""
    names = [re.sub(r"^caesar[0-9]+$", "caesar", _kind(step)) for step in chain]   # a keyed step without its key
    return KEY + ("+".join(names) if names else "plain")


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_ACCEPTED = re.compile(r"(\d{4}-\d\d-\d\dT\S*)\s+accepted\s+(\S+)(?:.*?\battempt=(\S+))?")
_ATTEMPT_ID = re.compile(rb'"attempt_id"\s*:\s*"([^"]+)"')
_ATTEMPT_DAYS = {}   # challenges root -> {attempt id: the day of the Warmups folder that holds it, or None}


def _attempt_day(attempt: str, hint=None):
    """The day of the Warmups folder that holds a saved attempt, or None when no folder does. An attempt
    is a day's base, its Time Trial or its Mastery (tools/run.py learns names inside a timed window too,
    under the timed attempt's own id), or an earlier variant of one, which lies under history/<attempt
    id>/ beside it. Looked for by its id, the folder of day `hint` first (the day the row's date says),
    then the newest days first; remembered per process and root, hit or miss, so a Mastery pays for one
    lookup and not for one per set."""
    try:
        root = labels.challenges_root()
    except Exception:
        return None
    known = _ATTEMPT_DAYS.setdefault(str(root), {})
    if attempt in known:
        return known[attempt]
    day = None
    try:
        folders = []
        for d in root.glob("day-*/warmups-day-*"):
            m = re.search(r"day-(\d{1,2})$", d.parent.name)
            if m and d.is_dir():
                folders.append((int(m.group(1)), d))
        folders.sort(key=lambda f: (f[0] != hint, -f[0]))
        want = attempt.encode("ascii", "replace")
        for number, d in folders:
            for sub in (d, d / "time_trial", d / "mastery"):
                if (sub / "history" / attempt).is_dir():
                    day = number
                    break
                try:
                    with (sub / "attempt.json").open("rb") as f:
                        found = _ATTEMPT_ID.search(f.read(MAX_BLOB))
                except OSError:
                    continue
                if found and found.group(1) == want:
                    day = number
                    break
            if day is not None:
                break
    except Exception:
        day = None
    known[attempt] = day
    return day


_JUDGED = {}   # (challenges root, key, the key's evidence) -> _judged_days' answer


def _judged_days(key: str):
    """(accepted name, days) for a label key: the event days on which the judge accepted the key's name.
    Each accepting row of the ledger (and of the seed's evidence, which promote copies from it) names the
    attempt it was judged on (the base's from tools/verify.py, a Time Trial's or a Mastery's from
    tools/run.py's probing inside a window); the day is that of the Warmups folder that holds the attempt
    (_attempt_day), or, when the attempt is not on disk, the row's own date. `days` is None for a name that cannot be dated at all: no
    accepting row, or one that names no Game Master attempt (a row written by hand or by a test). Such a
    name is believed on every day, as every name was before this rule. (None, None) with no accepted name."""
    try:
        st = labels.state(key)
    except Exception:
        return None, None
    name = st.get("accepted")
    if not name:
        return None, None
    try:
        memo = (str(labels.challenges_root()), key, name, tuple(st.get("evidence") or ()))
    except Exception:
        memo = None
    if memo in _JUDGED:
        return _JUDGED[memo]
    days, everywhere = set(), False
    for line in st.get("evidence") or ():
        m = _ACCEPTED.match(str(line))
        if not m or m.group(2) != name:
            continue
        attempt = m.group(3)
        if attempt and not _UUID.fullmatch(attempt):
            everywhere = True
            break
        dated = _event_day(_when(m.group(1)))   # the Eastern day of the row's own time, as day_of dates an attempt
        day = _attempt_day(attempt, dated) if attempt else None
        if day is None:
            day = dated
        if day is not None:
            days.add(day)
    got = (name, None if everywhere else (days or None))
    if memo is not None:
        if len(_JUDGED) > 256:
            _JUDGED.clear()
        _JUDGED[memo] = got
    return got


def _day_key(key: str, slot) -> tuple:
    """(the key to ask labels.pick under, the names to offer first) for a slug whose payload stands in
    `slot`: a record's number, or the attempt's day for a blob that is one payload.

    Second round of the Day 14 build. A name the judge accepted for warmups.digits/<cipher> was judged on
    ONE day's encoder, and a later day that uses the same cipher may treat the digits another way (atbash
    again, the digits mirrored: the Day 13 row answered it plain and wrong, base, Time Trial and all 68
    sets). So the name is plain only where it was judged: in the slot of its day, which is that day's base
    and Time Trial and that day's record in every later Mastery. In any other slot the key is the day's
    own, `<key>@dNN` (`<key>@undated` when nothing says the day), with the name accepted elsewhere as its
    first option: one probe on that day's base settles it, and the answer it learns is plain in that slot
    from then on. rot13 has had this rule since Day 5 by another road (_judged). A name that cannot be
    dated is believed everywhere (_judged_days)."""
    name, days = _judged_days(key)
    if name is None or days is None or (isinstance(slot, int) and slot in days):
        return key, []
    return key + ("@d%02d" % slot if isinstance(slot, int) and 0 < slot < 100 else "@undated"), [name]


def _merged(options) -> list:
    """The options with those of one value under one name, `a+b`, in their order. Two readings of the
    digits can give the same slug (27 mirrored is 72, and so is 27 rotated by five: four slugs in a
    hundred). A probe on such a slug cannot tell them apart, so the judge's yes must not be learned
    under either name alone: the next variant would be answered plain by a rule nobody judged."""
    out = []
    for name, value in options:
        for i, (n, v) in enumerate(out):
            if v == value:
                out[i] = (n + "+" + name, v)
                break
        else:
            out.append((name, value))
    return out


def _pick(key: str, options, slot):
    """labels.pick under the key of the slot's day (_day_key): (answer, key). Where the key has an
    accepted name among the readings, that reading is the answer. Otherwise readings that give one and
    the same slug are offered as one option under a joined name (_merged)."""
    key, first = _day_key(key, slot)
    values = [value for _, value in options]
    if len(set(values)) != len(values):   # two readings of one value: asked only then (labels.state stats two files)
        try:
            st = labels.state(key)
            judged = [] if st.get("split") else list(st.get("accepted_names") or ())
        except Exception:
            judged = []
        if not any(name in dict(options) for name in judged):
            options = _merged(options)
    if first:
        def place(option):
            return min([first.index(part) for part in option[0].split("+") if part in first] or [len(first)])
        options = sorted(options, key=place)
    return labels.pick(key, options), key


def _lossy_forms(steps, parts=None) -> list:
    """The lossy forms the slug's characters came through, as the part of a label key behind `warmups.`
    (Day 14 build): `case/upper` or `case/alternating` for a payload that gave slug characters through
    d_upper or d_altcase, `form/nospace` for one read through d_nospace, or left as it stands by a day
    whose own blobs are read through it. A payload that gave only letters of the sentence says nothing
    about the slug. `steps` is a path of the search; `parts` the numbered records, or None."""
    out = []
    for i, (chain, _, count, slot) in enumerate(steps):
        if not count:
            continue
        found = ["case/" + CASE_LOSSY[step] for step in chain if step in CASE_LOSSY]
        # Day 19 build: a filler pad read off after the slug (W4) and a keyword alphabet completed beyond the
        # sentence's letters (W3) are readings no check of the sentence covers: never plain on this word.
        found += ["form/" + step for step in chain if _is_pad_step(step)]
        found += ["subst_fill/keyword" for step in chain if _kind(step) == "kwfill"][:1]
        if "nospace" in chain:
            found.append("form/nospace")
        elif not chain and parts is not None and isinstance(slot, int) and "nospace" in (_day_chain(slot) or ()):
            found.append("form/nospace")
        out += [f for f in found if f not in out]
    return out


def _answer(slug: str, chain, slot, record=None, rival=None, lossy=()):
    """(answer, key): the plain slug, or the unsure answer for its digits and the key it is
    filed under. The answer is None when the judge has rejected every way to read them.
    `record` is the payload that held the digits when the blob is numbered records. `rival`
    is _keyed_rival's word on a keyed step: a second way to read the digits makes the answer
    unsure between the two (warmups.digits/<cipher>), and digits that could not be checked make
    it None.

    `lossy` (Day 14 build, rows 294 and 296) is _lossy_forms' word on the path: a slug whose characters
    came through a form that cannot carry the whole sentence is never plain on this module's word. One
    form: labels.pick under `warmups.<form>` with the one reading as its option (`lower` for a case form,
    `as_read` for the sentence without its spaces); where the digits are open too, the key also names
    the steps that left them open and each way to read them is an option (`lower`, `lower_rot5`, ...). The
    slug in capitals is never an option: the answer format asks for lowercase words. Once the judge has
    accepted the name on a base, labels.pick gives the plain value. Two forms at once, or a keyed step's
    rival beside one, is None."""
    if rival is UNTOLD:
        return None, _digits_key(chain)
    settled = (not _open_digits(chain) or _judged(chain, slot) or (not chain and _left_alone(record, slot))
               or (_turned_digits(chain) and len({value for _, value in _digit_options(slug, chain)}) == 1))
    if lossy:
        core = [step for step in chain if step not in CASE_STEPS and step != "nospace" and not _is_pad_step(step)]
        key = "warmups." + lossy[0] + ("" if settled else _digits_key(core)[len(KEY) - 1:].replace("/", "+", 1))
        if len(lossy) > 1 or rival is not None:
            return None, key
        word = "lower" if lossy[0].startswith("case/") else "as_read"
        options = [("as_is", slug)] if settled else _digit_options(slug, chain)
        return _pick(key, [(word if name == "as_is" else f"{word}_{name}", value) for name, value in options], slot)
    if rival is not None:
        mine, other, digits = rival
        return _pick(_digits_key(chain), [(mine, slug), (other, slug[:-2] + digits)], slot)
    if settled:
        return slug, None
    return _pick(_digits_key(chain), _digit_options(slug, chain), slot)


_CAESAR = re.compile(r"caesar([0-9]+)")


def _digit_options(slug: str, chain) -> list:
    """The ways to read open digits, best first, as (name, value) pairs: as they are, then
    rotated by five. With atbash in the chain, mirrored (9 - d) comes between the two: it
    is what atbash would do to digits.

    Day 14 build (row 295). When the digits were read through one caesar shift, a third way comes last:
    `shift`, each digit moved back by the number the letters were moved on by, modulo ten (a writer who
    moves the whole alphabet by N may move 0-9 by N too). The step caesarK reads by moving K on, so the
    writer moved 26 - K on. Left out for a shift of 0 or 5 among the ten digits, which is one of the two
    readings above for every slug. Last, so it costs a probe only when both of the others are rejected.
    Two readings that give the same slug for THIS slug are both listed here; _pick offers them as one.

    Day 18 build: digits read through upside-down text (OPEN_DIGIT_STEPS) have two readings, as turned
    (`as_is`) and with 6 and 9 as they were written (`unflipped`, a table that turns no digit)."""
    core = [step for step in chain if step not in CASE_STEPS and step not in REVERSALS and step != "nospace"
            and not _is_pad_step(step)]
    if core and core[-1] in OPEN_DIGIT_STEPS:
        return [("as_is", slug), ("unflipped", slug[:-2] + slug[-2:].translate(_SWAP69))]
    options = [("as_is", slug), ("rot5", rot5(slug))]
    if "atbash" in chain:
        options.insert(1, ("complement", complement(slug)))
    shifts = [int(m.group(1)) for m in map(_CAESAR.fullmatch, chain) if m]
    by = None
    if len(shifts) == 1 and "atbash" not in chain and not any(":" in step for step in chain):
        by = (26 - shifts[0]) % 26 % 10
    elif core and core[-1] == "rot13" and "atbash" not in chain and not shifts:
        by = 3   # second round: rot13 is a shift of 13, and 13 is 3 among ten digits
    if by is not None and by % 5:   # a shift of 0 or 5 is `as_is` or `rot5` for every slug: no reading of its own
        options.append(("shift", slug[:-2] + "".join(chr((ord(c) - 48 - by) % 10 + 48) for c in slug[-2:])))
    # Second round: the mirrored digits are a later option for rot13 and for a text that needed no decoding
    # too. Last, so it costs a probe only when every reading before it is rejected.
    if "atbash" not in chain and (not core or core[-1] == "rot13") and not shifts:
        options.append(("complement", complement(slug)))
    # B-250 (B6): a keyboard wrap or a Vigenere-family key whose writer moved the digits too (the keyboard's
    # digit row by the same n; each digit by its key letter modulo ten). Last: a probe only after the others.
    # keyed_digit_option itself declines every step but kbdw:<n> and a Vigenere-family key, so no gate here.
    third = RES.keyed_digit_option(slug, core[-1:], CRIB)   # the step that read the digits, only
    if third is not None:
        options.append(third)
    return options


# ---------------------------------------------------------------------------- one blob

_CLASSES = (("upper", rb"[A-Z]"), ("lower", rb"[a-z]"), ("digit", rb"[0-9]"), ("space", rb"[ \t\r\n]"),
            ("punct", rb"[!-/:-@\[-`{-~]"), ("other", rb"[^ -~\t\r\n]"))


def _classes(b: bytes) -> str:
    """The character classes of a payload, for the triage line."""
    counts = [(name, len(re.findall(pattern, b))) for name, pattern in _CLASSES]
    marks = []
    for m in re.finditer(_CLASSES[4][1], b[:4096]):
        if m.group() not in marks:
            marks.append(m.group())
    text = " ".join(f"{name}={n}" for name, n in counts if n)
    return text + (f" ({b''.join(marks[:12]).decode('ascii')})" if marks else "")


def _triage(why: str, payload: bytes, which: str, read: dict) -> str:
    """The one line a None leaves behind: the reason, the payload's length and character
    classes, and its three most English readings with the chain that gave each."""
    # A miss must stay cheap: the simplest 300 chains, scored on their first 120 characters.
    simplest = sorted(read.items(), key=lambda kv: _rank(kv[1]))[:300]
    ranked = sorted(simplest, key=lambda kv: -L.english(kv[0][:120].encode("utf-8", "replace")))
    LAST["readings"] = [(text, chain) for text, chain in ranked[:8]]   # the CLI's best-decodes block
    shown = " | ".join(f"{text.strip()[:44]!r} via {'+'.join(chain) or 'plain'}" for text, chain in ranked[:3])
    return (f"no answer: {why}; {which} is {len(payload)} bytes, {_classes(payload)}; "
            f"best readings: {shown or 'none is text'}")


def _flag_hunt(data: bytes, recs, deadline: float):
    """Every flag-format string a layered reading of the blob, or of a numbered record, reaches.

    Returns [(flag, chain, text)] ranked simplest-chain first, deduped by flag value (the simplest
    chain kept), or []. The readings are the same strict+loose graph the retained anchored search
    fits to text (readings()); here each is read toward FLAG_RE -- "a flag appears" -- which is what
    a jeopardy decode is after. readings() is memoized, so a search that follows reuses it and a
    blob with no flag pays nothing extra."""
    found = {}   # flag -> (chain, text)
    payloads = [data] + [p for _, p in (recs or ())]
    for payload in payloads:
        if time.perf_counter() > deadline:
            break
        if not isinstance(payload, (bytes, bytearray)):
            continue
        for text, chain in readings(bytes(payload), deadline).items():
            if "{" not in text:
                continue
            for m in FLAG_RE.finditer(text):
                flag = m.group(0)
                if flag not in found or _rank(chain) < _rank(found[flag][0]):
                    found[flag] = (chain, text)
    ranked = sorted(found.items(), key=lambda kv: (_rank(kv[1][0]), kv[0]))
    return [(flag, chain, text) for flag, (chain, text) in ranked]


def _canonical_b64(payload: bytes):
    """One canonical standard-base64 wrapper, padded or unpadded, with no ignored whitespace."""
    if not isinstance(payload, bytes) or len(payload) < 4 or not payload.isascii():
        return None
    if not re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", payload):
        return None
    bare = payload.rstrip(b"=")
    if len(bare) % 4 == 1:
        return None
    try:
        decoded = base64.b64decode(bare + b"=" * (-len(bare) % 4), validate=True)
    except (ValueError, binascii.Error):
        return None
    canonical = base64.b64encode(decoded)
    return decoded if payload in (canonical, canonical.rstrip(b"=")) else None


def _canonical_hex(payload: bytes):
    """One canonical case-insensitive hexadecimal wrapper, without separators or prefixes."""
    if (not isinstance(payload, bytes) or len(payload) < 2 or len(payload) % 2
            or not re.fullmatch(rb"[0-9A-Fa-f]+", payload)):
        return None
    try:
        decoded = bytes.fromhex(payload.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return None
    return decoded if payload.lower() == decoded.hex().encode("ascii") else None


def _exact_warmup(payload: bytes):
    """The slug only when the complete bytes are the exact shipped crib and one complete slug line."""
    prefix = CRIB.encode("ascii")
    if not payload.startswith(prefix):
        return None
    tail = payload[len(prefix):]
    if tail.endswith(b"\r\n"):
        tail = tail[:-2]
    elif tail.endswith(b"\n"):
        tail = tail[:-1]
    try:
        slug = tail.decode("ascii")
    except UnicodeDecodeError:
        return None
    return slug if SLUG_FULL.fullmatch(slug) else None


_DEEP_WRAPPER_REFUSED = object()


def _deep_b64_hex(payload: bytes):
    """A narrow finale fast path for seven to ten alternating base64 / hex wrappers.

    Both possible outer codecs are walked independently. Every layer must be a canonical, byte-exact wrapper
    and the endpoint must be the complete Warmups crib plus one slug, so an encoded prefix, concatenation or
    printable intermediate is not evidence. Competing paths and the explicitly recognised eleventh layer fail
    closed. Depths through six are deliberately left to the established graph and keep their existing plain
    answer and route.
    """
    if (not isinstance(payload, bytes)
            or not (DEEP_WRAPPER_MIN_BYTES <= len(payload) <= DEEP_WRAPPER_MAX_BYTES)):
        return None
    decoders = {"b64": _canonical_b64, "hex": _canonical_hex}
    hits = []
    over = []
    for first in ("b64", "hex"):
        current, name, chain = payload, first, []
        for depth in range(1, DEEP_WRAPPER_PROBE + 1):
            current = decoders[name](current)
            if current is None:
                break
            chain.append(name)
            slug = _exact_warmup(current)
            if slug is not None:
                row = (slug, tuple(chain))
                if depth > DEEP_WRAPPER_MAX:
                    over.append(row)
                elif depth >= DEEP_WRAPPER_MIN:
                    hits.append(row)
                break
            name = "hex" if name == "b64" else "b64"
    if over:
        LAST["note"] = (f"no answer: an exact alternating base64/hex wrapper reaches the crib after "
                        f"{len(over[0][1])} layers, beyond the bounded {DEEP_WRAPPER_MAX}-layer finale reader")
        return _DEEP_WRAPPER_REFUSED
    if len(hits) != 1:
        if hits:
            LAST["note"] = "no answer: competing alternating base64/hex wrapper paths reach an exact crib"
            return _DEEP_WRAPPER_REFUSED
        return None
    slug, chain = hits[0]
    key = "warmups.wrapper/" + "+".join(chain)
    answer = labels.pick(key, [("exact_crib", slug)])
    LAST.update(answer=answer, route="deep_wrapper", key=key, chains=[list(chain)], slug=slug)
    if answer is None:
        LAST["note"] = f"no answer: the judge has rejected the exact crib reading under {key}"
        return _DEEP_WRAPPER_REFUSED
    if labels.is_unsure(answer):
        LAST["note"] = (f"unsure: {len(chain)} canonical alternating base64/hex wrappers reach the exact crib and"
                        f" slug {slug!r}; key {key} must be judged for this exact wrapper shape")
    return answer, [list(chain)], CRIB + slug


def _settle(parts, whole: bool, deadline: float):
    """_search, then _decide: (found, cut, where, read, candidate or None, why not). When the
    first readings decide nothing and time is left, the search is made once more with
    under_cipher's readings added. A blob the first readings answer is answered exactly as
    before, and only a blob they leave without an answer pays for the second search."""
    _ESLM_SPENT[0] = 0.0      # row 547: the Rockstar / Befunge-98 readers' time is counted per settle
    found, cut, where, read = _search(parts, whole, deadline)
    cand, why = (None, None) if cut else _decide(_candidates(found, parts))
    if cand is None and not cut and time.perf_counter() < deadline:
        found2, cut2, where2, read2 = _search(parts, whole, deadline, under=read)
        cut = cut2
        if not cut2:
            cand2, why2 = _decide(_candidates(found2, parts))
            if cand2 is not None or len(found2) > len(found):
                found, where, read, cand, why = found2, max(where, where2), read2, cand2, why2
    if cand is None and not cut and time.perf_counter() < deadline:
        # Row 88: a cipher with a key. The key is read off the sentence (a blob that is one payload) or is
        # the one that read the record's day (numbered records). Only a blob nothing else answers pays.
        extra = _keyed_extra(parts, whole, read, deadline)
        if any(extra):
            found3, cut3, where3, read3 = _search(parts, whole, deadline, under=read, extra=extra)
            if not cut3:
                cand3, why3 = _decide(_candidates(found3, parts))
                if cand3 is not None or len(found3) > len(found):
                    found, where, read, cand, why = found3, max(where, where3), read3, cand3, why3
            else:
                cut = True
    if cand is None and not cut and time.perf_counter() > deadline:
        # Row 356 (Day 18): the deadline passed with no candidate, so a stage above was skipped (the second
        # search, the keyed stage) or stopped early (keyed() and M.late() return on the deadline with what
        # they have). That is a cut like one inside _search: it says OUT_OF_TIME, and row 76's second read
        # answers. Day 18's gate replay of the rail-fence base was cut so under release load and said only
        # 'no reading continues the sentence', so nothing read it again.
        cut = True
    return found, cut, where, read, cand, why


def _crib(parts, whole: bool, deadline: float):
    """The crib search over one layout: (hit, why, payload index for the triage, readings).
    hit is (slug, steps, text)."""
    found, cut, where, read, cand, why = _settle(parts, whole, deadline)
    at = min(where[0], len(parts) - 1)
    if cut:
        return None, "the time budget ran out before the search finished", at, read
    if cand is None:
        if not found and where[0] < len(parts):
            why = f"no reading continues the sentence at offset {where[1]}"
        return None, why, at, read
    return (cand["slug"], cand["steps"], CRIB + cand["slug"]), None, at, read


def _by_days(parts, deadline: float):
    """The hit (slug, steps, text) of numbered records read one way only, each by the chain of its own
    day, or None when that leaves anything open (the search is then asked, as before). Day 13 build.

    Twelve days running, record k of a Mastery blob was written in Day k's encoding, and both saved blobs
    of every day prove its chain by all 87 characters of the sentence. A blob is answered here when
      - its records are numbered 1 to N, and every one is read by its own day's proved chain, or holds
        PIN letters of the sentence under the one reading that goes on (_day_walk);
      - together they are the sentence and one slug, cut as ruled (_cut_as_ruled);
      - and every record that gives slug characters is settled the way the search settles it: by at least
        PIN letters of the sentence in it, or by a chain of strict decoders alone (row 109), or by the
        delivery's pin (consensus: the last record's, or this set's own for a record before the last).
    Nothing is believed here that the search would not believe from the same path; what is left out is
    the search for other paths, which cost a 13-record set 20 to 50 ms and the 63 sets of a Day 13
    Mastery its 1.5 s (docs/retro/day-13-predictions-simple.md, Part 4, rows 3 and 4). A record under a chain that reads any
    letters with no pin, a record its day does not read: the search decides. A blob cut another way goes to
    the search too, which then believes no slug-only loose record before the last (None; the module text)."""
    if len(parts) < 2 or [number for number, _ in parts] != list(range(1, len(parts) + 1)):
        return None
    steps, _, off, state, tail = _day_walk(parts, deadline)
    if len(steps) != len(parts) or off != LEN or state != DONE or not _cut_as_ruled(steps, tail):
        return None
    # The whole set read by the days (row 308). Every record that holds sentence letters is checked by
    # the crib (its PIN letters reproduce the sentence at its place); a record that holds only the slug's
    # end was still read by exactly the chain two of its day's own blobs prove (the row-269 proof), the
    # walk having reached it that way. When every slug-only record is one the shape itself pins (a strict
    # decoder, or the exact bijection rot47: _self_pinning) or one the delivery vouches for (_PINS), the
    # set stands whole, no per-record strong word asked. rot47 vouches its record incl its digits; a
    # letter cipher keeps its digit guard in _answer. A letter-cipher slug-only record that the delivery
    # does not vouch still ends the set None, as before: the shape of an atbash or caesar reading does not
    # prove its key.
    for (chain, letters, n, slot), (_, payload) in zip(steps, parts):
        if (n and letters < PIN and _any_text(chain) and not _self_pinning(chain)
                and (slot, chain) not in _PINS and (slot, chain, RULED, payload) not in _PINS
                and not _rotation_checked(chain, letters, slot)):
            return None
    return tail, tuple(steps), CRIB + tail


# Day 18 look-ahead (B1; docs/retro/day-18-predictions-warmups.md, F1): the one-step letter rotations whose
# key, if any, a record's own sentence letters check, and how many of them a thin record must give.
# Day 24 fold of the Day 23 live fix: a rail fence (`rail:<rails>.<offset>`) is a fixed permutation of a record's
# characters, so, like a rotation, a record it was read by (the day's proved chain) with at least ROTATION_LETTERS
# sentence letters at their place is checked by those letters. Day 23: a long third slug word pushed a slug
# character into Day 18's rail record (2 sentence letters, below PIN) and three sets of 113 stayed None.
_ROTATION = re.compile(r"caesar[0-9]+|atbash|rot13|rail:[0-9]+\.[0-9]+")
ROTATION_LETTERS = 2


def _rotation_checked(chain, letters: int, slot) -> bool:
    """True when a record that gives slug characters with fewer than PIN letters of the sentence is settled
    by the letters it does give: it was read by its day's own proved chain, that chain is ONE rotation
    (caesarN, atbash or rot13), and the record reproduces at least ROTATION_LETTERS letters of the sentence
    at its place in a walk cut as ruled. A caesar shift with any other key moves every one of those letters,
    and atbash and rot13 have no key, so the letters check the very rotation the record's slug characters
    went through. The digits keep their own guard (_answer).

    Why (Day 18 look-ahead, F1). An 18-record cut puts the sentence's end in record 14 (Day 14's caesar),
    and for a slug of 27 characters or more that record holds three letters of the sentence and one or two
    of the slug. Under PIN it needed the delivery's pin, and only 0 to 2 sets of a delivery have slug
    characters there, under CONSENSUS_MIN: such a set was None whatever Day 18's code (9% to 19% of a
    morning's Masteries hold one). The delivery's vouch is asked first and is unchanged."""
    return (letters >= ROTATION_LETTERS and len(chain) == 1 and bool(_ROTATION.fullmatch(chain[0]))
            and _day_proved(slot) == _canon(chain))


def _is_transposition(chain) -> bool:
    """True for a non-empty chain that is a FIXED permutation of a record's characters, perhaps over a strict
    decoding: every step is a keyed transposition (KEYED_MOVING: rail, columnar, scytale, route, redef, ...; its
    key written into the step's name), a strict decoder or an exact full-range bijection (as _self_pinning allows),
    and at least one is a transposition. The key of every step is fixed by the chain's own name, so a day-proved
    such chain applied to a Mastery record is a decode, not a key guess, and a wrong setting is refused by the
    strict step's form or rearranges the characters out of a slug. A letter cipher (caesar, atbash, rot13, a keyed
    letter cipher) is excluded: it maps letters to letters, so another key reads a slug as a slug, and a record's
    few sentence letters -- not its shape -- are what check such a key (_rotation_checked's job, ROTATION_LETTERS)."""
    moving = False
    for step in chain or ():
        if ":" in step and _kind(step) in KEYED_MOVING:
            moving = True
        elif (step in _STRICT_NAMES and step != "rot13") or step in EXACT or (":" in step and _kind(step) in STRICT_KEYED):
            continue
        else:
            return False
    return moving


def _walk_slug(parts, deadline: float):
    """Row 490: the whole set reconstructed when the walk by the days reaches the slug's end in a blob cut as
    ruled, each record read by exactly the chain its own two saved blobs prove -- the broader companion of
    _by_days for a day-proved TRANSPOSITION record that _rotation_checked's one-rotation, ROTATION_LETTERS-letter
    rule leaves open (Day 23: a long third slug word 'waterfall' pushed a slug character into Day 18's rail:3.0
    record, and a set with fewer than two sentence letters there, or a transposition laid over an encoding -- more
    than one step -- stayed None). It is asked ONLY after _by_days returned None, so it can turn a None into an
    answer and can move none; _by_days' own hits are untouched, and this function uses the same _day_walk, so the
    slug it returns is the walk's, never a second reading.

    Never-wrong, the way _by_days is. The hit stands only when the walk reaches off == LEN with the slug DONE in a
    blob _cut_as_ruled -- the whole 87-character sentence and one slug reproduced at the ruled cuts -- and every
    record _by_days left open (slug characters, fewer than PIN sentence letters, a loose chain, no strict or
    self-pinning shape, no delivery vouch, not _rotation_checked) was read by EXACTLY its day's proved chain and
    that chain is a fixed permutation (_is_transposition): a transposition's key is in the chain's name, so applying
    it to the record is a decode, not a guess, as _day_walk already applied it. A single-blob base or Time Trial
    (fewer than two numbered records), a walk that did not complete or reach DONE or cut as ruled, or an open record
    whose chain is a letter cipher, an unproved day's or not its day's: None, and the generic search decides, as
    before. 'walked' makes sure at least one open record was rescued this way, so the function claims only a set it
    genuinely reconstructed by the new path and never duplicates a hit _by_days could have returned."""
    if len(parts) < 2 or [number for number, _ in parts] != list(range(1, len(parts) + 1)):
        return None
    steps, _, off, state, tail = _day_walk(parts, deadline)
    if len(steps) != len(parts) or off != LEN or state != DONE or not _cut_as_ruled(steps, tail):
        return None
    walked = False
    for (chain, letters, n, slot), (_, payload) in zip(steps, parts):
        if not (n and letters < PIN and _any_text(chain) and not _self_pinning(chain)
                and (slot, chain) not in _PINS and (slot, chain, RULED, payload) not in _PINS
                and not _rotation_checked(chain, letters, slot)):
            continue   # the crib, a strict or self-pinning shape, the delivery's vouch or _rotation_checked settles it, as in _by_days
        if not (_is_transposition(chain) and _day_proved(slot) == _canon(chain)):
            return None   # a letter cipher, an unproved day or a chain that is not its day's: never a guessed reading
        walked = True
    return (tail, tuple(steps), CRIB + tail) if walked else None


def _usual(read: dict) -> bool:
    """True when some reading of the first payload starts like the usual sentence. The crib's
    verdict is then final: the generic search may only answer for a changed template."""
    return any(len(t) >= 6 and t[:12].lower() == CRIB_L[:len(t[:12])] for t in read)


_L_STEPS = {d.__name__[2:]: d for d in L.STRICT + L.LOOSE}   # layered_decode's own steps, by the names its chains use


def _fallback_shares(data: bytes, slug: str, chains, text: str):
    """read_here's `shares` for a slug the generic search put together from several
    payloads: per payload, how many of the slug's characters it gave and whether a step
    that turns any text into text read it. None when that cannot be told: the payloads are
    decoded again with the chains layered_decode reports, and joined they must give its
    text. Nothing here checked any payload against a sentence, so none is pinned; the one
    chain taken on trust is a record read by the encoding the seed has for its day (rot13
    in record 2), which the judge has seen in that record of every Mastery."""
    lines = [ln for ln in data.splitlines() if ln.strip()]
    numbers = [number for number, _ in numbered(data) or ()]
    for payloads, slots in ((L.records(data), numbers), (lines, ())):
        if not payloads or len(payloads) != len(chains):
            continue
        slots = slots if len(slots) == len(chains) else [None] * len(chains)
        pieces = []
        for payload, chain in zip(payloads, chains):
            for step in chain:
                try:
                    payload = _L_STEPS[step](payload) if payload else None
                except Exception:
                    payload = None
            piece = L._text(payload) if payload is not None else None
            if piece is None:
                break
            pieces.append(piece)
        if len(pieces) != len(chains):
            continue
        for joiner in ("", "\n"):
            if joiner.join(pieces) != text:
                continue
            start = text.rfind(slug)
            shares, at = [], 0
            for piece, chain, slot in zip(pieces, chains, slots):
                inside = max(0, min(at + len(piece), start + len(slug)) - max(at, start))
                shares.append((inside, _any_text(tuple(chain)) and not _judged(tuple(chain), slot)))
                at += len(piece) + len(joiner)
            return shares if start >= 0 and sum(n for n, _ in shares) == len(slug) else None
    return None


def _fallback(data: bytes, parts, day, budget: float):
    """layered_decode's own search, for a blob whose sentence is not the usual one, then the
    gate: (hit, why) with hit = (slug, chains, text, chain of the last payload, its slot)."""
    hit = L.solve_blob(data, max(0.02, budget - FALLBACK_SLACK))
    if not hit:
        return None, "the sentence is not the usual one and the generic search found no slug"
    slug, chains, text = hit
    before = text.rsplit(slug, 1)[0]
    words = [w.lower() for w in re.findall(r"[A-Za-z]+", before)]
    known = vocabulary()
    last = tuple(chains[-1]) if chains else ()
    # Several payloads: one may hold the slug's end alone, and nothing checked its transform.
    shares = _fallback_shares(data, slug, chains, text) if len(chains) > 1 and SLUG_FULL.fullmatch(slug) else None
    if not SLUG_FULL.fullmatch(slug):
        why = f"the generic search found {slug!r}, which is not three words and two digits"
    elif known_words(slug) < 2:
        why = f"the generic search found {slug!r}, with {known_words(slug)} known word(s)"
    elif len(chains) > 1 and shares is None:
        why = f"the generic search found {slug!r}, and which payload gave which of its words cannot be told"
    elif len(chains) > 1 and not _counts({"slug": slug, "pinned": False, "known": known_words(slug),
                                          "shares": shares}):
        why = (f"the generic search found {slug!r} through {'+'.join(last) or 'no decoder'}, and the payloads that"
               f" nothing checked gave too few of its known words themselves")
    elif max(map(len, slug.split("-")[:3])) > MAX_WORD:
        why = f"the generic search found {slug!r}, with a word longer than {MAX_WORD} letters"
    elif not before.rstrip().endswith(":"):
        why = f"the generic search found {slug!r}, but the text before it does not end with ':'"
    elif words and sum(w in known or w in L.COMMON for w in words) < 0.8 * len(words):
        why = f"the generic search found {slug!r} after text that is not English"
    else:
        slot = parts[-1][0] if parts and len(chains) == len(parts) else day
        return (slug, [list(c) for c in chains], text, last, slot), None
    return None, why


LOSSY = "warmups.lossy/"   # the label key of a reading in a code that cannot carry the whole sentence


def _lossy(data: bytes, read: dict, deadline: float):
    """solve_blob's result for a blob in a lossy code (formats_more.lossy), or None: an UNSURE answer with
    one option, the slug that the code's reading gives in exactly one way, under warmups.lossy/<code>.
    Asked only when the crib search and the fallback found nothing in a blob that is one payload. The
    reading gave the sentence's 68 letters in order, but not its marks. It stays unsure even after the
    judge accepted the method on a base (backlog row 171): the slug's words come from the system
    dictionary, not from the bytes, so the next variant's word may not be the one the code means. The
    base is closed by one probe; the gates then hold the clocks for the lane's agent, and run.py never
    sends it."""
    text = L._text(data)
    if text is None or time.perf_counter() > deadline:
        return None
    strict = sorted(((t, c) for t, c in read.items() if c and all(step in _STRICT_NAMES for step in c)),
                    key=lambda kv: _rank(kv[1]))[:KEYED_SOURCES]
    try:
        got = M.lossy([(text.strip("\r\n"), ())] + strict, CRIB, vocabulary(), deadline)
    except Exception:
        return None
    if got is None:
        return None
    code, method, slug, reading = got
    if not SLUG_FULL.fullmatch(slug):
        return None
    key = LOSSY + code
    if labels.pick(key, [(method, slug)]) is None:
        LAST["note"] = f"no answer: the judge has rejected the reading {method} of {slug!r} under {key}"
        return None
    answer = labels.unsure(key, [(method, slug)])     # never plain, accepted or not (row 171)
    chains = [code.split("+")]
    LAST.update(answer=answer, route="lossy", key=key, chains=chains, slug=slug)
    if labels.is_unsure(answer):
        LAST["note"] = (f"unsure: {code} cannot carry the sentence's marks; its reading gives the 68 letters of the"
                        f" sentence and then {slug!r} ({method}); key {key}")
    return answer, chains, CRIB + slug


AUTOKEY_CT = "warmups.digits/autokey_ct"   # the digits of a ciphertext-autokey reading (lossy_codes.autokey_ct)


def _lattice(data: bytes, slot, deadline=None):
    """Day 20 coverage build: solve_blob's result for a whole blob in a lossy code that
    lossy_codes.read takes off the sentence (Polybius, tap code, A1Z26 tokens, Bacon of the letters,
    Braille without the number sign, leetspeak), or in a ciphertext autokey, or (second round) in a keyed
    classical cipher lossy_ciphers.read breaks with the sentence (running key, Hill, bifid, ADFGX/ADFGVX,
    Nihilist), or None. Asked only after every other reader (and _lossy) left the blob None, for a blob that
    is one payload.

    Never plain on its own word. A reading through a fixed standard table that gives the slug in one way
    (`as_read`) is labels.pick under warmups.lossy/<code> in the slot of its day (_pick, the day rule): plain
    only where the judge accepted `as_read` there, on that day. A slug chosen among several readings by its
    known words (`vocabulary`), and anything read through leetspeak's table, which the sentence teaches only
    in part, stays unsure accepted or not (row 171's rule). The ciphertext autokey proves the slug's letters
    and leaves its digits open: warmups.digits/autokey_ct, `as_is` then `rot5`, by the day rule. A keyed
    cipher's reading is picked under the day rule only when every slug character came through a cell or key
    the sentence proved (`exact`); a running key's digits are open (warmups.digits/runkey). lossy_codes is
    bounded by counts (ITEMS, PARSES, STEPS); lossy_ciphers by counts and by `deadline`: a read the deadline
    stopped sets LAST['lattice_cut'], and _solve_once says so in its note (row 356's second read)."""
    if LC is None:
        return None
    text = L._text(data)
    if text is None or not (LEN <= len(text) <= BIG):
        return None
    text = text.strip("\r\n")
    try:
        got = LC.read(text, CRIB, vocabulary(), _SAVED)
    except Exception:
        got = None
    chain = None
    if got is None:
        try:
            auto = LC.autokey_ct(text, CRIB)
        except Exception:
            auto = None
        if auto is not None:
            return _autokey_answer(auto, slot)
        ciph = None
        if FM is not None:
            try:
                fractionated = FM.read(text, CRIB, deadline)
            except Exception:
                fractionated = None
            if fractionated is FM.CUT:
                LAST["lattice_cut"] = True
                return None
            if fractionated:
                # The full slug is unique, but the keyed table is inferred from this artifact's crib and
                # one legal trigram is not exercised by the sentence.  Keep it unsure under the artifact
                # hash forever: a name accepted for one alphabet cannot make another artifact plain.
                ciph = {
                    "code": "fractionated_morse@blob-" + fractionated["fingerprint"],
                    "method": "crib_map",
                    "slugs": [fractionated["slug"]],
                    "exact": False,
                    "digits_open": False,
                    "chain": fractionated["chain"],
                }
        if ciph is None:
            if LCI is None:
                return None
            try:
                ciph = LCI.read(text, CRIB, vocabulary(), _SAVED, deadline)
            except Exception:
                ciph = None
        if LCI is not None and ciph is LCI.CUT:
            LAST["lattice_cut"] = True
            return None
        if not ciph:
            # Day 21 look-ahead build: a random substitution whose slug holds letters the sentence lacks
            # (subst_fill.py), its unknown letters filled from the word lists; never plain.
            try:
                got = SF.read(text, CRIB, vocabulary(), _SAVED) if SF is not None else None
            except Exception:
                got = None
            if got is None:
                return None
        else:
            if ciph["digits_open"]:
                return _runkey_answer(ciph, slot)
            got = (ciph["code"], ciph["method"], ciph["slugs"], ciph["exact"])
            chain = ciph["chain"]
    code, method, slugs, fixed = got
    if not slugs or not all(SLUG_FULL.fullmatch(s) for s in slugs):
        return None
    slug = slugs[0]
    key = LOSSY + code
    if method == "readings":
        # several slugs with known words and nothing to tell them apart: DIFFERENT values, so a
        # candidate pick (row 346) under a key of this blob's own readings, so that a name accepted
        # or rejected here says nothing of another variant; never plain, accepted or not.
        tag = hashlib.sha256("|".join(slugs).encode()).hexdigest()
        options = [("reading%d" % (i + 1), s) for i, s in enumerate(slugs)]
        answer = labels.candidates(f"{key}+readings.{tag}", options)
        key = labels.candidate_key(f"{key}+readings.{tag}")
        if answer is not None and not labels.is_unsure(answer):
            answer = labels.unsure(key, [(n, v) for n, v in options if v == answer])
    elif fixed and method == "as_read":
        answer, key = _pick(key, [(method, slug)], slot)
    else:
        answer = labels.unsure(key, [(method, slug)]) if labels.pick(key, [(method, slug)]) is not None else None
    chains = [[chain or code]]
    if answer is None:
        LAST["note"] = f"no answer: the judge has rejected the reading {method} of {slug!r} under {key}"
        return None
    LAST.update(answer=answer, route="lattice", key=key, chains=chains, slug=slug)
    if labels.is_unsure(answer):
        LAST["note"] = (f"unsure: {chain or code} cannot carry the whole sentence; its reading gives the sentence's"
                        f" letters and then {slug!r} ({method}); key {key}")
    return answer, chains, CRIB + slug


def _autokey_answer(auto, slot):
    primer, tail = auto
    slug = tail.strip().lower()
    if not SLUG_FULL.fullmatch(slug) or known_words(slug) < 2:
        return None
    answer, key = _pick(AUTOKEY_CT, [("as_is", slug), ("rot5", rot5(slug))], slot)
    if answer is None:
        LAST["note"] = f"no answer: the judge has rejected every way to read the digits of {slug!r} under {key}"
        return None
    chains = [["autokey_ct:%d" % primer]]
    LAST.update(answer=answer, route="lattice", key=key, chains=chains, slug=slug)
    if labels.is_unsure(answer):
        LAST["note"] = (f"unsure: a ciphertext autokey with a primer of {primer} letter(s) reads the sentence and"
                        f" {slug!r}; the sentence has no digit, so the digits are open; key {key}")
    return answer, chains, CRIB + slug


RUNKEY = "warmups.digits/runkey"   # the digits of a running-key reading (lossy_ciphers, second round)


def _runkey_answer(ciph, slot):
    """A running key's reading: the letters proven by the key stream the sentence gave, the digits open
    (as_is, rot5) by the day rule, as every Vigenere-family reading's."""
    slugs = ciph["slugs"]
    if len(slugs) != 1 or ciph["method"] != "as_read":
        return None
    slug = slugs[0]
    if not SLUG_FULL.fullmatch(slug) or known_words(slug) < max(2, ciph.get("words") or 0):
        return None
    answer, key = _pick(RUNKEY, [("as_is", slug), ("rot5", rot5(slug))], slot)
    if answer is None:
        LAST["note"] = f"no answer: the judge has rejected every way to read the digits of {slug!r} under {key}"
        return None
    chains = [[ciph["chain"]]]
    LAST.update(answer=answer, route="lattice", key=key, chains=chains, slug=slug)
    if labels.is_unsure(answer):
        LAST["note"] = (f"unsure: a running key ({ciph['chain']}) reads the sentence and {slug!r}; the sentence has"
                        f" no digit, so the digits are open; key {key}")
    return answer, chains, CRIB + slug


ENIGMA = "warmups.classical/enigma"   # the label key of a reading through an Enigma machine


def _enigma(data: bytes, deadline: float):
    """row 162: solve_blob's result for a blob whose own text states Enigma settings
    (classical.enigma_settings) and whose cipher text, run back through the machine from those settings,
    gives the sentence: an UNSURE answer under warmups.classical/enigma, the slug the reading ends on, or
    None. Asked last, like _lossy, and only for a blob that is one payload.

    Never plain, accepted or not (like row 171): the settings are read from stated text, not derived from
    the crib the way crib_keys derives a Vigenere key, so the next variant's stated settings (or the way
    this reader reads them) are not proven. The base is closed by one probe; the gates then hold the lane's
    clocks for its agent, and run.py never sends it inside a window (gm.session drops every "??")."""
    if K is None or time.perf_counter() > deadline:
        return None
    text = L._text(data)
    if text is None or not (LEN <= len(text) <= BIG):
        return None
    settings = K.enigma_settings(text)
    if settings is None:
        return None
    kwargs = {k: settings[k] for k in ("rotors", "reflector", "rings", "start", "plugboard")}
    # Enigma steps its rotors on every letter, so the cipher text must be run on its own, from the start
    # position: the stated settings lines would step the machine first. Try the whole text and each line;
    # the one that is the cipher text decodes to the sentence, with the slug's digits and hyphens (every
    # non-letter) passing through unchanged.
    slug = None
    for cand in [text] + [ln for ln in text.splitlines() if len(ln.strip()) >= LEN]:
        if time.perf_counter() > deadline:
            return None
        try:
            plain = K.enigma(cand, **kwargs)
        except Exception:
            continue
        low = plain.lower()
        if CRIB_L[:48] not in low:
            continue
        for m in SLUG_FULL.finditer(low):
            slug = m.group(0)
        if slug is not None:
            break
    if slug is None:
        return None
    option = [("enigma", slug)]
    if labels.pick(ENIGMA, option) is None:
        LAST["note"] = f"no answer: the judge has rejected the enigma reading of {slug!r} under {ENIGMA}"
        return None
    answer = labels.unsure(ENIGMA, option)     # never plain, accepted or not (like row 171)
    chains = [["enigma"]]
    LAST.update(answer=answer, route="enigma", key=ENIGMA, chains=chains, slug=slug)
    LAST["note"] = (f"unsure: the blob states Enigma settings and its cipher text decodes to the sentence and"
                    f" {slug!r}; the settings were read from the text, not derived from the crib, so the reading"
                    f" stays unsure; key {ENIGMA}")
    return answer, chains, CRIB + slug


REDUNDANT = "warmups.redundant/"   # wave123: the structural-decode backstop's key, fingerprinted per blob


def _redundant(data: bytes, day, deadline: float):
    """wave123 adaptation hardening: solve_blob's result for a whole blob every other reader (the crib search,
    the fallback, _lossy, _lattice and _enigma) left None, or None. Asked last, like _enigma, and only for a
    blob that is one payload.

    The independent radix/base/RLE decoders in redundant.py (a SECOND decoder for base64, base32, URL percent,
    Ascii85/base85 and run-length, the way layered_decode's decimal/octal/HTML already have d_dec2/d_oct2/
    d_html2) read the blob and an independent hex surface with hand-written code that imports neither `base64`
    nor `urllib`, so a bug in a shipped reader cannot blank them too, and they read a few presentations the
    strict readers refuse (lowercase base32, '+'-for-space URL, char/count run-length). So a single-reader bug
    no longer blanks a whole day: the day degrades to a probeable candidate instead of a total blank.

    Scoped so it never offers a candidate where a shipped reader correctly declined. It is anchored on the
    FULL crib sentence (crib=CRIB below), and redundant.candidates offers a reading ONLY when it is the lane's
    own unambiguous shape: the whole crib intact, exactly one slug token, that slug the final content. So a
    blob a shipped crib-anchored reader would itself have seen and declined -- a footer or trailing text after
    the slug, two slugs, the sentence twice -- stays None here (it decodes to a crib-bearing text that is not
    that shape), and a stream nothing truly decoded (e.g. an lz4 block with no length header) stays None too
    (its control bytes break the crib). The backstop only turns a genuine blank -- a blob no shipped reader
    could read -- into a probeable candidate; it never second-guesses a shipped reader's deliberate None.

    Never plain. Each qualifying reading is offered as a labels.candidates set (row 346) under a key
    fingerprinted by THIS blob's own bytes and readings, so a name the judge accepts here can never answer a
    different value on a different blob or variant (the next variant has other bytes, hence another key, and
    stays unsure). It is never plain before the judge accepts a name (and then only on this very blob, whose
    base verify.py probed), never sent inside a deadline (the runners probe a candidate pick only on an attempt
    with no deadline), and stripped from every timed submit by gm.session() (every "??" value). A free-text slug
    no reader nailed degrades to a probeable candidate instead of None. Pure: no request, no clock, no state."""
    if RD is None or time.perf_counter() > deadline:
        return None
    if not isinstance(data, (bytes, bytearray)) or not (LEN <= len(data) <= BIG):
        return None
    try:
        cands = RD.candidates(bytes(data), crib=CRIB, slug_re=SLUG_FULL)
    except Exception:
        return None
    cands = [(n, v) for n, v in (cands or []) if isinstance(v, str) and SLUG_FULL.fullmatch(v)]
    if not cands:
        return None
    tag = hashlib.sha256(bytes(data) + b"\x00" + "|".join(f"{n}={v}" for n, v in cands).encode()).hexdigest()
    key = labels.candidate_key(f"{REDUNDANT}{tag}")
    answer = labels.candidates(key, cands)
    if answer is None:
        LAST["note"] = f"no answer: the judge has rejected every independent-decoder reading under {key}"
        return None
    slug = cands[0][1] if labels.is_unsure(answer) else answer
    chains = [["redundant"]]
    LAST.update(answer=answer, route="redundant", key=key, chains=chains, slug=slug)
    if labels.is_unsure(answer):
        tried = ", ".join(n for n, _ in cands)
        LAST["note"] = (f"unsure: no shipped reader read the blob, but independent decoders ({tried}) each read a"
                        f" slug; the readings are different values, so a candidate pick of this blob's own key"
                        f" {key}, never plain until the judge accepts one")
    return answer, chains, CRIB + slug


ENVELOPE = "warmups.envelope/"   # envelope-peel build: the XOR-envelope backstop's key, fingerprinted per blob


def _envelope(data: bytes, day, deadline: float):
    """Envelope-peel build (2026-10-25): a whole blob wrapped in an XOR layer (single-byte, or a
    repeating key recovered from the crib by known-plaintext) that is then re-fed through the reversible
    codec battery -- the `single / repeating / xor-then-base64` class, which the shipped chain missed
    because XOR was only ever a TERMINAL step, never re-entered into the decoder. Asked last, after
    `_redundant`, and only for a whole single-payload blob every other reader left None.

    CRIB-ANCHORED, never a false match. `solvers/common/unwrap.py` peels XOR + codecs and keeps only a
    stream in which the ENTIRE 87-character crib survives; a single-byte or repeating XOR key is pinned
    uniquely by the full crib, and every codec in the battery is byte-exact, so a wrong key or a
    speculative decode cannot reproduce the sentence. The slug's digits are therefore byte-exact too.

    One surviving slug is crib-provable and plain (the same standard as the triple-columnar reader: a
    reading that reproduces the entire sentence is the unique correct one). Two to four distinct slugs
    are a candidate pick (row 346) of THIS blob's own key, never plain until the judge accepts one; more
    is None. Pure: no request, no clock, no state; bounded by unwrap's node/byte caps and this deadline."""
    if UW is None or time.perf_counter() > deadline:
        return None
    if not isinstance(data, (bytes, bytearray)) or not (LEN <= len(data) <= BIG):
        return None
    crib_b = CRIB.encode()
    try:
        peeled = UW.peel(bytes(data), crib=crib_b, try_xor=True, deadline=deadline, max_nodes=8000)
    except Exception:
        return None
    slugs = {}   # slug -> chain (first/shortest wins; peel returns shortest chains first)
    for body, chain in peeled:
        if crib_b not in body or not any(step.startswith("xor") for step in chain):
            continue   # only the XOR class is this reader's; a pure-codec envelope is run.expand's / the main search's
        text = L._text(body)
        if text is None or CRIB not in text:
            continue
        after = text.split(CRIB, 1)[1].strip()
        if not SLUG_FULL.fullmatch(after):   # the lane's exact shape: the crib, the slug, nothing else
            continue
        slugs.setdefault(after, list(chain))
    if not slugs:
        return None
    if len(slugs) == 1:
        slug, chain = next(iter(slugs.items()))
        LAST.update(answer=slug, route="envelope", key=None, chains=[chain], slug=slug)
        LAST["note"] = (f"the blob is an XOR envelope ({'+'.join(chain)}); the entire sentence survives the"
                        f" peel, which pins the key, so the slug {slug!r} is crib-provable and plain")
        return slug, [chain], CRIB + slug
    if len(slugs) > 4:
        LAST["note"] = f"no answer: the XOR-envelope peel left {len(slugs)} different slugs; too ambiguous"
        return None
    cands = [(f"reading{i + 1}", s) for i, s in enumerate(slugs)]
    tag = hashlib.sha256(bytes(data) + b"\x00" + "|".join(s for s in slugs).encode()).hexdigest()
    key = labels.candidate_key(f"{ENVELOPE}{tag}")
    answer = labels.candidates(key, cands)
    if answer is None:
        LAST["note"] = f"no answer: the judge has rejected every XOR-envelope reading under {key}"
        return None
    slug = cands[0][1] if labels.is_unsure(answer) else answer
    chain = slugs[slug] if slug in slugs else list(next(iter(slugs.values())))
    LAST.update(answer=answer, route="envelope", key=key, chains=[chain], slug=slug)
    LAST["note"] = (f"unsure: the blob peels (XOR envelope) to {len(slugs)} different slugs, so a candidate pick"
                    f" of this blob's own key {key}, never plain until the judge accepts one")
    return answer, [chain], CRIB + slug


RETRY_FACTOR = 3.0   # row 76: an untimed blob whose search ran out of budget is read once more, this much longer
OUT_OF_TIME = "the time budget ran out"
RETRY_MAX_BYTES = 4096   # the second read is only for blobs of the event's shape: a few hundred bytes, 1 to 40
RETRY_MAX_RECORDS = 40   # numbered records (Day 7's Mastery blob: 8). Junk and bombs keep the one budget.


CHEAP_ONLY = "the records' own days leave it open, and the search was not made"


@_holding
def solve_blob(data: bytes, budget: float = BUDGET, day=None, retry=None, wide: bool = True):
    """(answer, [decoder chain per payload], decoded text) or None.

    answer is a flag-format string when a layered decode reached one (LAST['route'] == 'flag',
    LAST['flags'] holding every flag found, simplest chain first); otherwise the retained
    known-plaintext search may still return a candidate. LAST says what happened: LAST['note']
    is the triage line of a None and LAST['readings'] its best decodes.

    A blob whose search was cut by the budget is read once more with `retry` seconds, by
    default RETRY_FACTOR times the budget (0 for none)."""
    got = _solve_once(data, budget, day, wide)
    if not wide:   # only the walk by the days was asked (see _solve_questions): nothing to read a second time
        return got
    retry = budget * RETRY_FACTOR if retry is None else retry
    shaped = (isinstance(data, (bytes, bytearray)) and len(data) <= RETRY_MAX_BYTES
              and len(numbered(bytes(data)) or ()) <= RETRY_MAX_RECORDS)
    if _CAP_END[0] is not None:
        # Day 20 build (row 227): on a clock the second read also ends where tools/run.py's solve cap leaves
        # the sets still to come their share (solve_set sets _CAP_END), counted at the moment it begins.
        retry = min(retry, _CAP_END[0] - time.perf_counter())
    if got is None and retry > budget and shaped and OUT_OF_TIME in (LAST.get("note") or ""):
        got = _solve_once(data, retry, day)
        if LAST.get("note"):
            LAST["note"] = f"{LAST['note']} (read a second time with {retry:.2f} s)"
    return got


def _solve_once(data: bytes, budget: float, day=None, wide: bool = True):
    t0 = time.perf_counter()
    # The flag hunt reads before the first _settle resets it: without this it ran on what the previous
    # blob's last settle left of ESLM_TIME, and a blob after one that spent it read no Rockstar (SH-08).
    _ESLM_SPENT[0] = 0.0
    LAST.clear()
    LAST.update(answer=None, route=None, key=None, note=None, chains=None)
    if isinstance(data, (bytes, bytearray)) and bytes(data[:3]) == BOM:
        data = bytes(data[3:])
    if not isinstance(data, (bytes, bytearray)) or not (data.strip() or _whitespace_bits(bytes(data))):
        LAST["note"] = "no answer: the blob is empty"
        return None
    data = bytes(data)
    if len(data) > MAX_BLOB:
        LAST["note"] = f"no answer: the blob is {len(data)} bytes, more than is read ({MAX_BLOB})"
        return None
    deep = _deep_b64_hex(data)
    if deep is _DEEP_WRAPPER_REFUSED:
        return None
    if deep is not None:
        return deep
    crib_deadline = t0 + budget * CRIB_SHARE
    if M is not None:
        M.DEADLINE[0] = t0 + budget      # a program a reader runs must not outlast the blob's budget
    recs = numbered(data)
    if wide:
        # Primary jeopardy target: a flag-format string anywhere in a layered reading of the blob
        # (or of a numbered record). The readings are the anchored search's own; here they are read
        # toward "a flag appears". A blob with no flag falls through to the retained search below.
        flags = _flag_hunt(data, recs, min(crib_deadline, t0 + max(MIN_BUDGET, 0.5 * budget)))
        LAST["flags"] = flags
        if flags:
            flag, chain, text = flags[0]
            LAST.update(answer=flag, route="flag", key=None, chains=[list(chain)], slug=flag, note=None)
            return flag, [list(chain)], text
    layouts = ([(recs, False)] if recs else []) + [([(day, data)], True)]
    hit = why = record = None
    blame = None   # (reason, payload, its name, its readings) of the first layout, for the triage
    usual = False
    by_days = None
    if recs and len(recs) <= RETRY_MAX_RECORDS:
        # Day 13 build: numbered records that their own days read, with nothing left open, need no search.
        # The saved blobs of the records' days are read first, once a process (about 0.1 s for thirteen
        # days, each read inside its own 0.1 s): that is not this blob's time, whose budget is counted
        # from here.
        try:
            for number, _ in recs:
                _day_proved(number)
            waited = time.perf_counter() - t0
            t0, crib_deadline = t0 + waited, crib_deadline + waited
            if M is not None:
                M.DEADLINE[0] = t0 + budget
            by_days = _by_days(recs, crib_deadline)
            if by_days is None:   # row 490: the whole-set reconstruction for a day-proved transposition record _by_days left open
                by_days = _walk_slug(recs, crib_deadline)
        except Exception:
            by_days = None
    if by_days is not None:
        hit, parts, whole, layouts = by_days, recs, False, []
    elif not wide and recs:
        # Third round of the Day 14 build: the caller asked for the cheap reading only (numbered records read
        # by their own days). It left the blob open; the search is the caller's to ask for, or not.
        LAST["note"] = f"no answer: {CHEAP_ONLY}"
        return None
    for parts, whole in layouts:
        hit, reason, at, read = _crib(parts, whole, crib_deadline)
        usual = usual or _usual(read[0])
        if blame is None:
            name = "the blob" if whole else f"record {parts[at][0]} of {len(parts)}"
            blame = (reason, parts[at][1], name, read[at])
        if hit or time.perf_counter() > crib_deadline:
            break
    if hit:
        slug, steps, text = hit
        last = max(i for i, step in enumerate(steps) if step[2])   # the payload that held the digits
        digit_chain, slot = steps[last][0], steps[last][3]
        record = None if whole else parts[last][1]
        chains = [list(chain) for chain, _, _, _ in steps]
        route = "crib"
    else:
        why = blame[0]
        if usual:
            pass   # the sentence is the usual one: the crib's verdict stands
        elif len(data) > BIG:
            why = f"{why}; the generic search is not asked for a blob over {BIG} bytes"
        elif time.perf_counter() < crib_deadline:
            got, why_not = _fallback(data, recs or [(day, data)], day, budget - (time.perf_counter() - t0))
            if got:
                slug, chains, text, digit_chain, slot = got
                hit, route = got, "fallback"
            else:
                why = f"{why}; {why_not}"
    if not hit:
        got = _lossy(data, blame[3], t0 + budget) if recs is None and M is not None else None
        if got is None and recs is None:   # Day 20 coverage build: lossy codes and the ciphertext autokey
            got = _lattice(data, day, t0 + budget)
        if got is None and recs is None:   # row 162: a blob whose text states Enigma settings, unsure only
            got = _enigma(data, t0 + budget)
        if got is None and recs is None:   # wave123: independent decoders' candidate pick, unsure only
            got = _redundant(data, day, t0 + budget)
        if got is None and recs is None:   # envelope-peel build: an XOR envelope re-fed through the codecs
            got = _envelope(data, day, t0 + budget)
        if got is not None:
            return got
        cut = LAST.pop("lattice_cut", None)
        LAST["note"] = _triage(why, blame[1], blame[2], blame[3])
        if cut and OUT_OF_TIME not in (LAST["note"] or ""):
            LAST["note"] = f"{LAST['note']}; {OUT_OF_TIME} before the keyed cipher search finished"
        return None
    rival = _keyed_rival(tuple(digit_chain), parts[last][1], slug) if route == "crib" else None
    lossy = _lossy_forms(steps, None if whole else parts) if route == "crib" else []
    answer, key = _answer(slug, digit_chain, slot, record, rival, lossy)
    LAST.update(answer=answer, route=route, key=key, chains=chains, slug=slug)
    if lossy:
        if answer is None:
            LAST["note"] = (f"no answer: the slug is {slug!r}, read through {' and '.join(lossy)}, and the judge has"
                            f" rejected every reading under {key} (or two such forms met)")
            return None
        if labels.is_unsure(answer):
            LAST["note"] = (f"unsure: the slug is {slug!r}, read through {'+'.join(digit_chain) or 'no decoder'}: a"
                            f" form that cannot carry the whole sentence ({', '.join(lossy)}), so the slug is not"
                            f" plain until the judge accepts it once; key {key}")
        return answer, chains, text
    if rival is UNTOLD:
        LAST["note"] = (f"no answer: the slug is {slug!r}, but the digits a keyed step ({digit_chain[-1]}) gave"
                        f" could not be checked against the cipher text")
        return None
    if rival is not None and labels.is_unsure(answer):
        LAST["note"] = (f"unsure: the slug is {slug!r} and its digits were read through {digit_chain[-1]}, whose key"
                        f" the sentence gave; the sentence has no digit, so they may also be {rival[2]!r}"
                        f" ({rival[0]}, {rival[1]}); key {key}")
        return answer, chains, text
    if answer is None:
        LAST["note"] = (f"no answer: the judge has rejected every way to read the digits of {slug!r}"
                        f" under {key}; the blob is {len(data)} bytes, {_classes(data)}")
        return None
    if key and labels.is_unsure(answer):
        names = ", ".join(name for name, _ in labels.parse(answer).options)
        LAST["note"] = (f"unsure: the slug is {slug!r} and its digits were read through "
                        f"{'+'.join(digit_chain) or 'no decoder'}, which leaves them open ({names}); "
                        f"key {key}")
    return answer, chains, text


# ---------------------------------------------------------------------------- the attempt

def _when(text):
    try:
        t = datetime.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


def budget_for(ctx) -> float:
    """Seconds one blob may spend: min(0.35, (window - 1.5) / number of questions), the
    window being deadline minus start of ctx['attempt']. 0.35 for an attempt with no clock."""
    attempt = ctx.get("attempt") if isinstance(ctx, dict) else None
    if not isinstance(attempt, dict):
        return BUDGET
    started, deadline = _when(attempt.get("started_at")), _when(attempt.get("deadline"))
    if started is None or deadline is None:
        return BUDGET
    window = (deadline - started).total_seconds()
    count = len(attempt.get("questions") or ()) or 1
    return max(MIN_BUDGET, min(BUDGET, (window - 1.5) / count))


# Day 20 build (row 227). A Mastery's first set is the cold one: it pays for the delivery-wide reading (the
# pins, the saved days' chains) and its own search, and spare_for held a full blob budget back for every set
# still to come, so it got no second read (Day 11: 0 s for sets 1 to 5). Measured on the saved Day 11 and 15
# to 18 Masteries (53 to 88 sets, in order in one process, as tools/run.py solves them): every set after the
# first took 0.3 to 0.7 ms on average, at most 20.5 ms (Day 11), and the first 0.14 to 0.88 s. So the sets
# still to come are held back at SET_COST each (or the blob budget, when that is less), and on a clock the
# second read must also end where run.py's cap leaves them that much: SOLVE_CAP (the lane's solve_cap in
# tools/lanes.py) less CAP_MARGIN, from the moment the pass's first set began (_CAP_END, read by solve_blob
# when the second read would begin). Before, nothing kept a second read inside the cap: a base cut at 0.35 s
# was read again for up to 1.05 s more on a window of any length.
SET_COST = 0.005         # seconds held back for each set still to come (measured: at most 0.0007 on average)
SOLVE_CAP = 1.5          # tools/lanes.py: solve_cap of the warmups lane (run.py stops the solver there)
CAP_MARGIN = 0.25        # seconds of that cap never given to a second read
_PASS = {}               # attempt id -> (perf_counter when this pass began its first set, last set number)
_CAP_END = [None]        # perf_counter by which a second read of the set being solved must end (None: no clock)


def spare_for(ctx, budget: float):
    """Seconds a blob cut by its budget may get for a second read (row 76): what the window has
    left after 1.5 s of margin and the share of every set still to come (row 227: SET_COST each, or
    `budget` when that is less), at most RETRY_FACTOR times the budget. None (the default retry) for an
    attempt with no clock; 0 when nothing is left. Also sets _CAP_END for solve_blob (the solve cap)."""
    _CAP_END[0] = None
    attempt = ctx.get("attempt") if isinstance(ctx, dict) else None
    deadline = _when(attempt.get("deadline")) if isinstance(attempt, dict) else None
    if deadline is None:
        return None
    count = len(attempt.get("questions") or ()) or 1
    try:
        done = max(0, int(ctx.get("set") or 1))
    except (TypeError, ValueError):
        done = 1
    share = min(budget, SET_COST) * max(0, count - done)
    aid = str(attempt.get("attempt_id") or id(attempt))
    began, last = _PASS.get(aid, (None, None))
    if began is None or last is None or done <= last:      # a new pass over the attempt (run.py solves in order)
        if len(_PASS) > 16:
            _PASS.clear()
        began = time.perf_counter()
    _PASS[aid] = (began, done)
    _CAP_END[0] = began + SOLVE_CAP - CAP_MARGIN - share
    left = (deadline - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    spare = left - 1.5 - share
    return max(0.0, min(budget * RETRY_FACTOR, spare))


def day_of(ctx):
    """The event day of the attempt, or None when nothing says. A saved attempt does not
    carry its challenge id, so the day is read from a '-day-NN' in a file name (a Mastery
    bundle has one) and otherwise from the date the attempt was started: Day N's challenges
    are played on day N of the event. Only _judged() uses it, to tell the day whose rot13
    the judge accepted from a later day whose blob merely reads the same way; a day that
    cannot be told, or is told wrongly, makes that answer unsure and never wrong."""
    if not isinstance(ctx, dict):
        return None
    attempt = ctx.get("attempt") if isinstance(ctx.get("attempt"), dict) else {}
    names = [ctx.get("challenge"), attempt.get("challenge"), attempt.get("challenge_id"), ctx.get("delivery_name")]
    names += [a.get("filename") for a in attempt.get("artifacts") or () if isinstance(a, dict)]
    for name in names:
        m = re.search(r"-day-(\d{1,2})(?!\d)", name) if isinstance(name, str) else None
        if m:
            return int(m.group(1))
    started = _when(attempt.get("started_at"))
    if started is None:
        return None
    return _event_day(started)


# ---------------------------------------------------------------------------- day patch

def _load_patch():
    """day_patch.py from this folder, if someone wrote one today. A broken one is reported and ignored."""
    if not PATCH.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("warmups_day_patch", PATCH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except (Exception, SystemExit) as e:
        print("NOTE warmups day_patch.py could not be loaded: %s: %s" % (type(e).__name__, str(e)[:200]),
              file=sys.stderr)
        return None
    if not callable(getattr(mod, "answer", None)) and not callable(getattr(mod, "override", None)):
        print("NOTE warmups day_patch.py defines no answer(q, files, ctx); ignored", file=sys.stderr)
        return None
    return mod


# At import, so a timed run pays for it before its clock starts. A patch's own copy of this
# module (loaded under the name PRIVATE) loads no patch: it would be the patch itself.
_patch = None if __name__ == PRIVATE else _load_patch()


def add_strict(decoder, name: str):
    """Put one more decoder at the end of STRICT, under `name` as its step in a chain. For a
    day patch, on its own copy of this module (day_patch_template.py): the search then reads
    the new encoding alone and as a record among the old ones. Nothing here calls it.
    Only for a decoder that refuses what is not in its form: what it gives is trusted like
    the strict ones here, digits and all."""
    decoder.__name__ = "d_" + name
    STRICT.append(decoder)
    _STRICT_NAMES.add(name)
    _rank.cache_clear()


def add_loose(decoder, name: str):
    """The same for a cipher that maps letters to letters: one more loose step. It reads any
    text and says nothing about digits, so it is judged like a rotation: tried once, on a
    payload and on what the first strict chains gave; a record it read that holds only the
    slug's end must speak for itself or be pinned by its day; and digits read through it
    come back unsure under warmups.digits/<name>."""
    decoder.__name__ = "d_" + name
    LOOSE.append(decoder)
    LOOSE_ASCII.append(decoder)
    _LETTER_STEPS.add(name)
    _rank.cache_clear()


PATCH_WITHDRAW = "<<withdraw>>"  # what day_patch.override returns to take an answer back: the answer becomes None


def _overridden(q, value, files, ctx):
    """day_patch.override(q, answer, files, ctx): the opt-in way for a live fix to replace or withdraw
    ANY answer of this module, a plain one included. Asked for every question when the patch defines
    it, after answer(); `value` is what would be returned without it. A text it returns replaces the
    answer, PATCH_WITHDRAW makes it None, anything else leaves it. A raise costs nothing: the answer
    stands. One NOTE line per replacement."""
    if _patch is None or not callable(getattr(_patch, "override", None)):
        return value
    aid = q.get("answer_id") or q.get("qid") or q.get("id")
    try:
        new = _patch.override(q, value, files, ctx)
    except (Exception, SystemExit) as e:
        print("NOTE %s: day_patch.override raised %s: %s; the answer stands" % (aid, type(e).__name__, str(e)[:200]),
              file=sys.stderr)
        return value
    if not isinstance(new, str) or not new or new == value:
        return value
    if new == PATCH_WITHDRAW:
        if value is None:
            return value
        new = None
    print("NOTE %s: %s replaced by day_patch.py (%s)" % (aid, str(value)[:100], str(new)[:100]), file=sys.stderr)
    return new


def _patched(q, files, ctx):
    if _patch is None or not callable(getattr(_patch, "answer", None)):
        return None
    try:
        return _patch.answer(q, files, ctx)
    except (Exception, SystemExit) as e:
        print("NOTE warmups day_patch.answer raised %s: %s" % (type(e).__name__, str(e)[:200]), file=sys.stderr)
        return None


# ---------------------------------------------------------------------------- runner contract

# A question that asks for the slug under another id than `message`: its text asks which answer slug to
# submit (the wording of all 529 questions of Days 1 to 11), or its answer format describes a slug.
# Not a question about a part of the slug ('the first word of the answer slug', 'the answer slug's ...').
_ASKS_SLUG = re.compile(r"(?i)\b(?:what|which)(?: is the)?(?: exact)? answer slug\b(?!['’])[^?.]*\bsubmit\b")
_SLUG_SYNTAX = re.compile(r"(?is)\bthree lowercase words\b.*\bhyphen.*\btwo-digit number\b")


def _asks_slug(q, qid) -> bool:
    """True when the question is known to ask for the blob's slug: its id is `message`, or its text asks
    for the answer slug, or its answer format is the slug's (three lowercase words and a two-digit
    number). Any other question (the encoding's name, a count, one word of the slug) is not answered."""
    if qid == "message":
        return True
    form = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    return bool(_ASKS_SLUG.search(str(q.get("question") or ""))
                or _SLUG_SYNTAX.search(str(form.get("syntax") or "")))


@_holding
def solve_set(questions, files, ctx):
    """One set: the slug of the blob each question names, under the question's id.

    Every set so far has had one question, `message`. If a set ever holds more, only the
    one named `message` is given the slug: what the others ask is not known here. A lone
    question under another id is given the slug only when it asks for it (_asks_slug)."""
    ctx = ctx if isinstance(ctx, dict) else {}
    files = files if isinstance(files, dict) else {}
    budget, day = budget_for(ctx), day_of(ctx)
    retry = spare_for(ctx, budget)
    out = {}
    global _PINS, _TWICE
    if M is not None:
        M.DEADLINE[0] = time.perf_counter() + PROGRAM_HEAD   # for a program read before the first blob's own limit
    try:   # row 109: what the whole delivery says about its last record, read once and remembered
        _PINS = consensus(ctx.get("siblings"))
        _TWICE = _second_way(ctx.get("siblings"))
    except Exception:
        _PINS = _TWICE = frozenset()
    try:
        _solve_questions(questions, files, ctx, budget, day, retry, out)
    finally:
        _PINS = _TWICE = frozenset()
        _CAP_END[0] = None
    if isinstance(ctx.get("partial"), dict):
        ctx["partial"].update({k: v for k, v in out.items() if v is not None})
    return out


WIDE_BLIND = 3     # sets of a delivery in which the search must find nothing, with none answered, before it is given up
WIDE_PATIENT = 12  # sets it must leave None for any reason, with none answered, before it is given up all the same
_DELIVERIES = {}   # (challenges root, the delivery's blobs) -> [sets the search found nothing in, sets it answered,
                   #                                            sets it left None for any reason]
_KNOWN_NONE = re.compile(r"slug-shaped reading\(s\), none with enough known words \(best '[^']*' has ([1-9])\)"
                         r"|readings compete for the slug")


def _delivery(ctx, data):
    """The search's record for the delivery of the set being solved: [left None, answered], shared by all
    its sets; None for a set with no delivery around it (a base, a Time Trial) or a blob that is not
    numbered records. Third round of the Day 14 build."""
    if not isinstance(ctx, dict) or not isinstance(data, (bytes, bytearray)):
        return None
    try:
        if len(data) > RETRY_MAX_BYTES or not numbered(bytes(data[3:] if bytes(data[:3]) == BOM else data)):
            return None
    except Exception:
        return None
    # tools/run.py gives every set of one delivery this same mutable object. It is the cheap identity/cache path,
    # and remains present when a very large delivery intentionally omits the sibling byte map used by consensus().
    shared = ctx.get("delivery_state")
    if isinstance(shared, dict):
        return shared.setdefault("warmups.search", [0, 0, 0])
    siblings = ctx.get("siblings")
    if not isinstance(siblings, dict) or len(siblings) < CONSENSUS_MIN:
        return None
    try:
        key = (str(labels.challenges_root()), frozenset(siblings.items()))
    except Exception:
        return None
    if key not in _DELIVERIES:
        if len(_DELIVERIES) > 8:
            _DELIVERIES.clear()
        _DELIVERIES[key] = [0, 0, 0]
    return _DELIVERIES[key]


def _solve_delivery_set(q, data, files, ctx, budget, day, retry, seen):
    """One set of a Mastery delivery: (hit, note, whether the patch was already asked, its answer).

    Third round of the Day 14 build. Every set of a delivery is written the same way. A delivery this
    module cannot read used to pay the whole search for every set (0.07 to 0.14 s each, 4.5 to 9 s for 68
    sets), so inside the lane's cap a third of the sets ever reached a live day_patch.py. Now:

      - the cheap reading comes first, for every set: numbered records read by their own days (_by_days,
        a few milliseconds). What it answers is the answer, exactly as before.
      - a set it leaves open goes to the search, as before, and the delivery remembers how that ended;
      - (a) once the search has left one set of the delivery None and has answered none, a day patch that
        defines answer() or override() is asked BEFORE the search, and the search is made only for a set
        the patch leaves None too;
      - (b) once the search has found NOTHING in WIDE_BLIND sets (no reading that continues the sentence,
        or slug-shaped readings without one known word) and has answered none, it is not made for the
        rest of the delivery: they are None at the cost of the cheap reading, and the patch is asked.
        A set it left None with known words in a slug-shaped reading (a record its day does not vouch
        for, two readings that compete) does not count there: the search reads some such deliveries in
        part, on the sets whose own words speak (a third of the sets in tests/test_warmups_day9.py's pair
        measure). For those it is given up only after WIDE_PATIENT sets left None and none answered.
    A search the clock cut says nothing about the delivery and is not counted. With no delivery around the
    set nothing here applies. What changes: with a patch, a set the cheap reading leaves open in a delivery
    whose first such set the search could not answer is the patch's before it is the search's."""
    hit = solve_blob(data, budget, day, retry, wide=False)
    note = LAST.get("note")
    if hit is not None or CHEAP_ONLY not in (note or ""):
        return hit, note, False, None
    blind = not seen[1] and (seen[0] >= WIDE_BLIND or seen[2] >= WIDE_PATIENT)
    early = None
    asked = False
    if not blind and seen[2] and not seen[1] and _patch is not None:
        asked = True
        early = _patched(q, files, ctx)
        if early is None:
            early = _overridden(q, None, files, ctx)
        if early is not None:
            return None, f"no answer: {CHEAP_ONLY}: day_patch.py was asked first (row (a))", True, early
    if blind:
        return None, (f"no answer: {CHEAP_ONLY}: the search left the first {seen[2]} such sets of this delivery None"
                      f" and answered none, so it is not made for the rest"), False, None
    hit = solve_blob(data, budget, day, retry)
    note = LAST.get("note")
    if hit is not None:
        seen[1] += 1
    elif OUT_OF_TIME not in (note or ""):
        seen[2] += 1
        seen[0] += not _KNOWN_NONE.search(note or "")
    return hit, note, asked, None


def _solve_questions(questions, files, ctx, budget, day, retry, out):
    for q in questions:
        qid = q.get("qid") or q.get("id")
        where = f"set {ctx.get('set')} {qid}"
        asked, early = False, None
        if len(questions) > 1 and qid != "message":
            out[qid] = None
            note = "no answer: only the question named `message` is known to ask for the slug"
        elif not _asks_slug(q, qid):
            out[qid] = None
            note = (f"no answer: the question `{qid}` is not named `message` and neither its text nor its"
                    f" answer format asks for the slug")
        else:
            data = files.get(q.get("member") or "") or files.get(q.get("artifact") or "") or ctx.get("delivery") or b""
            try:
                seen = _delivery(ctx, data)
                if seen is None:
                    hit = solve_blob(data, budget, day, retry)
                    note = LAST.get("note")
                else:
                    hit, note, asked, early = _solve_delivery_set(q, data, files, ctx, budget, day, retry, seen)
            except Exception as e:  # a blob must never cost the other sets their answers
                hit, note = None, f"no answer: the solver raised {type(e).__name__}: {str(e)[:160]}"
            out[qid] = hit[0] if hit else None
            if hit and BO is not None and not _BO_SAID:
                _say_byte_order(where, hit)
            if hit and BO is not None and not _FINAL_SAID:
                _say_final(where, hit)
            if hit and BO is not None and not _WAVE2_SAID:
                _say_wave2(where, hit)
            if hit and not _EBCDIC_SAID:
                _say_ebcdic(where, hit)
        if early is not None:   # the patch answered a set the cheap reading left open (see _solve_delivery_set)
            out[qid] = early
            note = f"answered by day_patch.py ({note})"
        elif (out[qid] is None or labels.is_unsure(out[qid])) and not asked:   # a plain answer is never the patch's to change
            fixed = _patched(q, files, ctx)
            if fixed is not None and fixed != out[qid]:   # the same unsure answer back is this module's own
                out[qid] = fixed
                note = f"answered by day_patch.py ({note})"
        # The one way a live fix reaches a plain answer: the patch's own override(), when it has one.
        after = out[qid] if asked and early is None and out[qid] is None else _overridden(q, out[qid], files, ctx)
        if after != out[qid]:
            out[qid] = after
            note = f"replaced by day_patch.override ({note})"
        if note:
            print(f"NOTE warmups {where}: {note}"[:900], file=sys.stderr)


_BO_SAID = []   # one line per process, so a Mastery of 98 sets says it once
_EBCDIC_SAID = []
EBCDIC_MORE = frozenset({"ebcdic500", "ebcdic273"})


def _say_ebcdic(where, hit):
    """Day 21 build, round 2 (row 411): one stderr line per process the first time a chain through the cp500 or
    cp273 reader answers, the review's marker (a plain answer prints nothing else). Never raises."""
    try:
        steps = sorted({s for chain in (hit[1] or []) for s in chain} & EBCDIC_MORE)
        if steps:
            _EBCDIC_SAID.append(1)
            print(f"NOTE warmups {where}: read through {', '.join(steps)} (EBCDIC code page 500/273; Day 21 build,"
                  f" round 2, row 411)", file=sys.stderr)
    except Exception:
        pass


def _say_byte_order(where, hit):
    """Day 21 look-ahead build: one stderr line the first time a chain through a byte_order.py reader answers,
    for tools/day_review.py's marker table (a plain answer prints nothing else). Never raises."""
    try:
        steps = sorted({s for chain in (hit[1] or []) for s in chain} & getattr(BO, "LOOKAHEAD_NAMES", BO.NAMES))
        if steps:
            _BO_SAID.append(1)
            print(f"NOTE warmups {where}: read through byte_order ({', '.join(steps)}; Day 21 look-ahead build)",
                  file=sys.stderr)
    except Exception:
        pass


_WAVE2_SAID = []


def _say_wave2(where, hit):
    """Wave 2 (2026-10-21): one stderr line per process the first time a chain through a byte_order.py Wave 2
    reader answers (hexinv, or an ITA2 unshift-on-space form), the review's marker `warmups-wave2`. Never raises."""
    try:
        steps = sorted({s for chain in (hit[1] or []) for s in chain} & getattr(BO, "WAVE2_NAMES", frozenset()))
        if steps:
            _WAVE2_SAID.append(1)
            print(f"NOTE warmups {where}: read through {', '.join(steps)} (inverted wide-text hex / ITA2"
                  f" unshift-on-space; Wave 2 build)", file=sys.stderr)
    except Exception:
        pass


_FINAL_SAID = []


def _say_final(where, hit):
    """Day 21 final prep: one stderr line per process the first time a chain through byte_order.py's mojibake or
    ITA2 readers answers, the review's marker. Never raises."""
    try:
        steps = sorted({s for chain in (hit[1] or []) for s in chain} & getattr(BO, "FINAL_NAMES", frozenset()))
        if steps:
            _FINAL_SAID.append(1)
            print(f"NOTE warmups {where}: read through {', '.join(steps)} (UTF-16 mojibake / ITA2 Baudot;"
                  f" Day 21 final prep)", file=sys.stderr)
    except Exception:
        pass


def _settle_collector():
    """Day 21 look-ahead build (Metadata's Day 14 rule, properties_strict._settle_collector). This module and the
    readers it loads build tens of thousands of objects that live for the whole process, and where the
    collector's counters stood after the import decided whether a full collection, about 7 ms here, fell inside
    the first solve of a process (a gate's replay, a runner's first set): with byte_order.py and subst_fill.py
    loaded it fell inside the Day 15, 19 and 20 base and Time Trial replays (0.014 s where 0.007 s is the work),
    on the tree before them it did not. gc.freeze() moves what the import built to the permanent generation, so
    no later collection walks it; no collection is made first (it would cost the import as much as it saves).
    Never raises: a collector that cannot be settled leaves the solver as it was."""
    try:
        import gc
        gc.freeze()
    except Exception:
        pass


_settle_collector()


def main(argv) -> int:
    if not argv or any(a.startswith("-") for a in argv):
        print("usage: crib_decode.py <blob-file> [...]", file=sys.stderr)
        return 2
    status = 0
    for path in argv:
        try:
            blob = Path(path).read_bytes()
        except OSError as e:
            print("crib_decode.py: %s: %s" % (path, e.strerror or e), file=sys.stderr)
            status = 2
            continue
        t0 = time.perf_counter()
        hit = solve_blob(blob)
        ms = (time.perf_counter() - t0) * 1000
        flags = LAST.get("flags") or []
        if hit and LAST.get("route") == "flag":
            flag, chain, text = flags[0] if flags else (hit[0], tuple(hit[1][0]), hit[2])
            print(f"{path}: FLAG  {flag}   [via {'+'.join(chain) or 'plain'}]   {ms:.0f} ms")
            print(f"    decoded: {text.strip()[:200]!r}")
            for other, ochain, _ in flags[1:6]:
                print(f"    also FLAG  {other}   [via {'+'.join(ochain) or 'plain'}]")
            continue
        if hit:
            layers = " | ".join("+".join(c) or "plain" for c in hit[1])
            shown = hit[0]
            parsed = labels.parse(hit[0])
            if parsed is not None:
                shown = "candidates: " + " or ".join(f"{value} ({name})" for name, value in parsed.options) + f" [{parsed.key}]"
            print(f"{path}: {shown}   [{layers}]   {ms:.0f} ms\n    {hit[2].strip()!r}")
            continue
        # No flag and no exact anchor: print the best decode(s) found -- the primary readable
        # result for a human -- and flag any that still matches the flag format (a time-cut hunt).
        reads = LAST.get("readings") or []
        hot = [(t, c) for t, c in reads if FLAG_RE.search(t)]
        print(f"{path}: no flag found   {ms:.0f} ms")
        for text, chain in (hot or reads)[:5]:
            tag = "FLAG? " if (text, chain) in hot else ""
            print(f"    {tag}{text.strip()[:120]!r}   [via {'+'.join(chain) or 'plain'}]")
        if not reads:
            print(f"    {LAST.get('note')}")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
