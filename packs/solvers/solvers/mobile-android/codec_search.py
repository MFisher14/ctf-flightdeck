#!/usr/bin/env python3
"""Mobile wrapper: a wider codec search around puzzle_asset_codec.py that fails closed.

Usage:
  .venv/bin/python solvers/mobile-android/codec_search.py <file.apk> [...]

A Huntress mobile fixture carries its answer code in assets/huntress_puzzle.json:

  {"schema": "huntress.mobile.puzzle.v1", "day": N, "codec": "<name>", "data": "<text>", ...params}

The codec has changed every day (plain, reverse, base64, xor, split), so the next one is
expected to be new. puzzle_asset_codec.py, the Day 4 solver, is not edited: this module
asks it first and then looks further (pieces listed beside an order, more named codecs,
renamed, split or nested data fields, keys from the dex and manifest, a key or a bit move
proven by the known "ANS-" prefix, a code's characters moved inside `data`, documents in
other members, a bounded search over reversible transforms).

Looking further finds more, and more of what it finds can be wrong, so every result says
how it was reached, and that decides what is returned (docs/ops/contracts.md):

  plain   the Day 4 solver applied the codec the document names to its `data` field, in the
          usual asset, and the judge has accepted that codec name (plain, reverse, base64,
          xor in the seed; a chain of them counts). Or the document is Day 5's in the shape
          the judge saw: codec split, `parts` put in the order `order` gives them, which
          the seed holds as split:by-order (see "arrangements").
  unsure  any other route at confidence high or medium: a codec new to the judge applied by
          name, an arrangement that differs from the judged shape, a search hit through at
          least one transform, a position move, a key recovered from the ANS- prefix or
          taken from the dex. Returned as
          labels.pick('mobile.codec/<codec name or route>', [(route, value), ...]), so the
          runners probe it on the untimed base, one option per request, and never send it
          on a clock. Once the judge accepts a route, the same route is answered plain on
          the next variant.
  None    confidence low or none: an answer-shaped string under a codec name that was not
          applied (the transform may work inside the answer's own alphabet: rot5, a
          reversed body), pieces beside an order that no reading turns into a code, or
          beside any other number of the document's own (the fields joined as listed ignore
          it and are not offered instead), a string in the dex, a document that is not
          JSON. A candidate is printed in the NOTE for the lane's agent and is never
          returned.

rot5 and rot18 are applied only when the document names them: they turn one well-formed
answer into another, so a search could never tell that it had used them wrongly.

The likely next codecs are applied by name (backlog row 20): base32 in the RFC alphabet, the
base32hex alphabet and Crockford's; ROT-N and Caesar spelled rot7, rot-7, rot_7, caesar_3, or
rot/caesar/shift with the amount in a field; rot47; atbash; zlib, gzip, raw deflate, bzip2 and
xz/lzma, under base64, hex or base32 (PACKED: as Day 4's xor bytes sat under base64); ascii85,
base85, Z85; URL-safe base64 under its usual spellings; and chains of any of them, as a list or
joined with + | , > -> then / &. Each is unsure under mobile.codec/<the document's name> until
the judge accepts it. base32hex, Crockford and Z85 read most upper-case text, so they are never
search moves (NAME_ONLY): a search that tried them would crowd out everything else.

Keyed shifts with a key of several characters (backlog row 47): vigenere (also vig, polyalphabetic)
is read over letters (the key index on letters, or on every character), over bytes mod 256 and
over the 95 printable characters, and as a repeating add of 2 to 4 bytes proven by the ANS-
prefix; beaufort over letters and bytes; caesar and shift take a key list as each byte's own
shift. Every such reading has a tag of its own in the route, so it is unsure until the judge
accepts that route, and only an exact ANS-[0-9A-F]{16} counts.

Codecs that read their parameters from named fields (backlog row 72), in the document's style
(a lowercase codec name, parameters beside it as Day 4's and Day 7's `key` was): railfence
(rail_fence, zigzag; the count from `rails`, another of RAILS or any integer field, else the
counts 2 to 8 proved by the ANS- prefix), affine (`a` and `b` or their other names, or a key of
two integers; over letters mod 26 and bytes mod 256; with no pair, a over its valid values and b
proved by the prefix), substitution (an `alphabet`, a keyword, a map or a plain/cipher pair of
fields). A parameter may be a reference to another field ({"rails": "seed"}, {"key_field":
"salt"}, {"a": "$mult"}). `codec: chain` (or pipeline, ...) with the steps in `steps`, step1 and
step2, or outer and inner is a chain like 'a+b'; a chain is read in the order the document lists
it first, and a different code from the reversed order follows it as `order-reversed`. Every
such reading is unsure under its own route until the judge accepts it.

Day 9 hardening (2026-10-08; Days 1 to 8 followed a published rotation, Day 9 on does not). All of
it is unsure at best, and none of it changes what a judged document answers:

  classical     codec_classical.py (backlog row 88): autokey, gronsfeld, variant Beaufort, keyboard neighbours,
                a 6 x 6 Polybius square, ICAO spelling words, reversed blocks, swapped pairs, Enigma; by name only
  more codecs   codec_more.py: base36/62/45/91, quoted-printable, HTML entities, backslash escapes,
                Morse, zstd, lz4, brotli, snappy, columnar and scytale, delta and running xor,
                per-character offsets, chacha20, des3, fernet, jwt, and a base-N step in an
                alphabet the document gives. Applied by name only, never as search moves. A
                position move (rotate, chunks reversed) is also read under one text layer.
                Since Day 12 also, by the document's own name and in no table here (codec_more.OWN):
                unicode, json, json_string, quoted, pem, armor, hexdump, xxd, lower, lowercase,
                lower_hex, upper, swapcase, xor_prev, add_index, sub_index.
  shapes        a document that states a schema other than huntress.mobile.puzzle.v1 is not the
                judged shape of its codec: its route carries `schema-v2` and is unsure until the
                judge accepts it (one probe on the base, plain on every variant after). A codec or
                steps written as objects ({"codec": {"name": "xor", "key": 29}}, {"pipeline":
                [{"op": "base64"}, ...]}) are reshaped (reshape) and marked. Pieces that are
                documents of their own are joined (fragments).
  documents     asset_docs.py: the puzzle's fields in a plist, compiled XML (also the manifest's
                <meta-data>), resources.arsc, text XML, SQLite, properties, YAML, TOML,
                MessagePack, CBOR or protobuf; and inside an Android backup, a tar or a gzip among
                the members. The route names the format (`doc-plist`).
  keys          apk_resources.py: key material is also read from resources.arsc, other compiled XML
                (res/xml/network_security_config.xml), native libraries and small text members;
                a resource or meta-data named key, secret, salt or iv is tried first.
  the package   when no document gives anything, the one answer code the whole package holds (a dex
                string, a resource, a library, META-INF, the signing block; as it stands or under
                the search's transforms) is offered under `apk-string:<where>[:<how>]`, and one
                code cut in two pieces or over files in name order under `apk-pieces:...`. Two
                different codes, or three loose pieces, are None: nothing says which is meant.
  code          app_bundles.py (2026-10-08, round 2): the puzzle inside the app's code. Hermes bytecode
                (string table with true lengths, object literals where the buffers say which
                values belong to which keys), a JavaScript bundle as text, a dex beyond its string
                pool (static fields with their values as one object per class, the strings one
                method loads in order, an array's elements), .NET assemblies of a Xamarin or MAUI
                app (user strings; XALZ members and stores inflated), native libraries and Dart
                snapshots over their whole length (a code bundle is read up to 8 MiB), and a code
                under one byte of XOR or of addition in a native library, dex or assembly. A
                document is `doc-<format>`, a lone code `apk-string:<kind>`, pieces
                `apk-pieces:dex-method` or `:dex-array`, a one-byte key `apk-string:<kind>:xor-byte`.
                All unsure; the documents come after every member document, the rest after
                every other package string.
  questions     a question that does not ask for the code is handed to apk_facts.py (package,
                components, deep link, permissions, certificate, hashes): unsure picks under
                mobile.<fact>/apk, plain only for a hash or a size of the delivered package.
  budget        a Mastery of more than three deliveries shares MASTERY_SOLVE seconds between its
                sets (set_budget): a miss is cut short, a judged answer takes a millisecond.

Never plain by position (2026-10-11, Day 12 look-ahead). The whole of assets/huntress_puzzle.json is
the document by its name and is answered at once, as before. Every other hit (an entry nested in a
member, a document in another member or in the app's code, one item of a list of fields) is held
while the candidates behind it are read by name: one that gives another code, or was not read in
the time, makes the answer None, also when the judge has accepted the route's name, with the
candidates in the NOTE. Candidates that agree are one answer. When the document comes from a
package inside the delivery, the document of a second package there (two APKs in one zip) is a
candidate of every hit, and it has the same claim to the name: unless it gives the same code by
name the answer is None. Every other candidate is read by name only: one that only a search or a
key from the package would decode does not count against a hit. Two entries named
assets/huntress_puzzle.json in one archive are not candidates of each other: the last is read,
as before.

Day 14 look-ahead (2026-10-13; docs/retro/day-14-predictions-mobile.md, tests/test_day14_mobile.py). None
of it changes the answer of a saved APK of Days 1 to 13; everything new is unsure (labels.pick):

  second code   the player's decision of 2026-10-13, which reverses row 270's note-only and MO1's "plain
                whatever stands beside it": when the package holds an answer code beside the one this
                module reads, the answer offers both under `<key>:second-code`, its own reading first
                (second_codes: another field of the document that its codec decodes, an earlier zip entry
                of the document's name, a puzzle-shaped document in another member, a code in clear or
                under base64 or hex in a member's bytes or a SQLite cell, a keystore secret). The name
                the judge accepts there answers the next variant plain. A document inside a package
                inside the delivery is not read for this. The look is bounded by what it reads
                (SECOND_MEMBERS, SECOND_BYTES, SECOND_DOCS, SECOND_KDF) and by no clock, so the same
                package gets the same answer on every run; a package past those bounds keeps this
                module's own reading plain, with what was seen in the NOTE. This module's reading is in
                ctx["partial"] before the look begins.
  shape         a text field that holds no code (`case`, `hint`, `transform`) beside a judged codec's
                `data` changes nothing. (A split document with any further field is `:extra-fields`,
                as on the armed tree.) A key recovered from the ANS- start of a text that starts with
                ANS- already is no reading (a shift inside the hex alphabet: step 4, a candidate).
  questions     the id `answer` under a stated format that is not the code's, with no word of the code
                and no fact read, is offered under `<the codec's key>:unasked` (a question with no
                format at all keeps the code). A format that names ANS- and asks lower case gets the
                lower-case spelling as a further option under `<the codec's key>:lower-asked`. One key
                each, made from the codec's, so the one name the judge accepts answers the replay
                (_as_asked). A question under another id is the code's by its format only when it is
                the one such question of its set.
  ciphers       des and des-cbc by name (codec_more); AES-GCM with the tag in a field of its own; keys the
                document derives or wraps (derived_keys: PBKDF2 from password, salt and a stated count;
                a wrapped_key under a wrapping_key by XOR, AES-ECB or RFC 3394); an IV from the package
                beside a key from the package; a padded base64 text of key length as key material.
  split         every piece under one text encoding (`pieces-base64`); more pieces than the order names
                (`subset`).
  documents     JSON5 and UTF-16 with a byte order mark when strict JSON was not read (`doc-encoded`); a
                document that names its codec `algorithm`.
  keystores     keystores.py: PKCS12, JCEKS and BKS secret entries under a password the package states
                or a usual one (never searched): a secret that is a code is `keystore:<format>`, every
                secret is key material (`key-apk`), and a document whose codec is `keystore` is not
                searched itself. A store's work is counted in iterations of key derivation and paid
                before it is done (keystores.STORE_WORK, APK_WORK; SECOND_KDF beside a document that
                answered): what does not fit is not read, once, and the APK's deadline is looked at
                inside every derivation.
  seconds       the dex of every fixture holds a record of labels (CODEC, CONTROL, DAY) that app_bundles
                reads as a document: its 16-character label was searched for 0.2 s before the package's
                strings were looked at. A text of a code document under CODE_DOC_SEARCH characters is
                not searched. The look for a second code runs no pattern over a member that does not
                hold the code's first four bytes.

Day 18 look-ahead (2026-10-17; docs/retro/day-18-predictions-mobile.md, tests/test_day18_mobile.py). None of it
changes the answer of a saved APK of Days 1 to 17; everything new is unsure (labels.pick), never plain until the
judge accepts its route:

  decoys        beside a PLAIN answer each other top-level text field of the usual document (16 to 256
                characters, not a header, key or selector field; FIELD_FIELDS of them and FIELD_CHARS
                characters in all) gets a short search with the document's keys (field_codes: FIELD_NODES
                states, FIELD_DEPTH moves, no block cipher, no clock, so the base, the gate's replay and a
                clock agree); another code makes the answer unsure under `<key>:second-code` with
                `field:@<field>:search:<path>`, also when the package look is past its bounds. A field a
                selector names ({"use": "b"}; SELECTORS) is searched and offered first, before this module's
                own reading, also when the judged codec decodes it (`field:@<field>`); otherwise the judged
                reading goes first. The key then carries the selector's fields, `<key>:second-code@<field>`:
                a name accepted where `use` named `b` never answers plain where it names `data`.
  formulas      an order stated as a formula over the characters of `data` (formulas: step, stride,
                multiplier, a, k ... and offset, start, increment, b, shift; digits as text too), route
                `<codec>:by-formula-<fields>`; only for a codec name this module does not apply (by_shape).
  pairs, maps   [[place, piece]], [[piece, place]] and {"place": piece} in any top-level field, after every
                order listed (_paired, rows 342 and 343): `<codec>:by-pos:@<field>:pairs`,
                `:pairs-char-first`, `by-key:...:map`.
                An order written as a list of digit strings is read when its numbers are 0..n-1 or 1..n
                (tag `order-strings`).
  lookups       `data` indices into a stated table, alphabet or pool (lookups): `<codec>:lookup@<field>`.
  grids, seeds  grid reads the codec names (spiral, snake, boustrophedon, transpose with stated rows or
                cols; faro; deinterleave), `<codec>:by-grid-<pattern>`; seeded shuffles (Python's
                random.Random(seed).shuffle, Collections.shuffle with java.util.Random(seed)),
                `<codec>:by-seeded-<generator>`. Not Kotlin's Random(seed): no runtime here checked a port.
  uu, search    row 342: a uuencoded line shorter than its length character allows decodes to nothing (a
                0 to 2 character field made ANS-6666666666666666); and a search path holds at most one xor
                with a top-level key (they share the move name `xor`), one with each key read more widely
                (`xor:key=day`), and one one-byte shift of any key (add, sub, caesar), so moves that nearly
                undo each other no longer turn a near-identity into a made-up code.

Day 19 look-ahead (2026-10-18; docs/retro/day-19-predictions-mobile.md items 1 to 6, row 318; docs/build-day19/mobile.md,
tests/test_day19_mobile.py). Every saved APK of Days 1 to 18 answers as before; everything new is unsure:

  nested        beside any answer, each object of the usual document that holds a `data` text (two levels
                down, objects in lists too, SUB_DOCS in all; not a piece with an index) is read by name with
                its own codec and keys, else the parent's (`field:@<path>.data:sub`); beside a plain answer one
                that gives nothing by name gets the field look's short search. A selector may name a dotted
                path ({"use": "release.data"}): that field goes first.
  side ciphers  a side text beside `<cipher>_key` (aes, rc4, des, chacha20, xor), or `<field>_key` with
                `<field>_codec`, is read by name under that cipher and key (`field:@<field>:<key field>`).
  packaging     a whole member under zlib or a one-byte XOR keyed by its first byte ^ '{' (`doc-zlib`,
                `doc-xor`), and a document as JSON text in a dex or .bin (`doc-in-<member>`), each only with
                the huntress.mobile.puzzle schema; two different documents (a dex too) give none, and a native
                document the libraries answer is read first, without these readers.
  spellings     `data` empty and ONE list of values under chars, bytes, ints or values (`@chars`); xor with a stated
                key step (`key-step=<field>`); `indexed` as one step of a chain (`indexed+xor:by-order:at-1`).
  native        row 318: the libraries' one clear code beside a decoy in `data` leads as native:so-disagree.

Day 20 build (the Day 19 look-ahead's remaining WRONG and None shapes; docs/build-day20/mobile.md,
tests/test_day20_mobile.py). Every saved APK of Days 1 to 18 answers as before; everything new is unsure:

  blowfish      by the codec's name (codec_more.py): ECB, CBC with a stated IV or the IV in front.
  branches      a list of objects that each state WHEN they apply ({when: release, data}) and decode to
                different codes: a candidate pick (row 346), `<codec>:<field>=<condition>`, only when every
                condition is release-like or hostile, one of each, and nothing else in the document chooses a
                branch (a top-level field, a selector, an item's flag, a hint naming a condition) (when_branches);
                it was None. Day 20 gaps build: the key carries the document's fingerprint
                (`<codec>+branches_<field>@doc-<sha256>#candidates`), so it is plain only for the document it was
                judged on; scalar headers beside the list are allowed (they only move the order).
  beside plain  a header text (hint, note, description) of 20 characters or more, searched with NO key (Day 18's
                G09: a header is never a key, and a short one is not read); a code cut over numbered side fields
                (`field:@p1+p2:joined`); a window of len(data) in a field over MAX_PIECE characters
                (`field:@<field>:window`); a byte list (`field:@<field>:ints:search:...`); a string of the app's
                dex read by the document's own codec (`apk-string:dex:own-codec`; read only when the package look
                is complete, DEX_SCAN characters in all the dex members). Each only demotes the plain
                answer to `<key>:second-code`, bounded by counts, never by a clock; the reads by the
                document's own codec share one budget in base_cost units (OWN_UNITS).

One APK may spend BUDGET seconds, reading the archive included, enforced by checking a
deadline in every loop over keys, states and members (the runner owns the alarm timer).
The Day 4 solver checks no deadline, so it is asked only for a document whose named chain
is small (base_cost); a larger one is taken by the bounded code here and is unsure at
best. `cryptography` is imported only when a cipher is tried. Each set prints one
NOTE line on stderr: answer, confidence, route, and what the puzzle document contained.

A live fix is a new file: if day_patch.py exists beside this module, day_patch.answer(q,
files, ctx) is called for each question this module answered None or unsure, and a result
that is not None is used in its place. When the patch declines (None), this module's
unsure answer stays, so the base can still be probed. A plain answer is never offered to
the patch: it is asked last, not first, and cannot change what the judge has accepted.
day_patch_template.py is the skeleton to copy; nothing here loads the template itself.
A plain answer is reached one way only, and only when the patch asks for it: if day_patch.py
defines override(q, answer, files, ctx), it is asked about EVERY question after the above,
with the answer this module would return. A text it returns replaces that answer (plain, or
a labels.pick value), the text `<<withdraw>>` (PATCH_WITHDRAW) makes it None, anything else
leaves it; each replacement is one stderr line, `NOTE <id>: <old> replaced by day_patch.py
(<new>)`, and a raise costs nothing. Without that function nothing here changes.
"""
import base64
import contextlib
import binascii
import bz2
import hashlib
import importlib.util
import io
import itertools
import json
import lzma
import math
import re
import struct
import sys
import time
import urllib.parse
import zipfile
import zlib
from collections import deque, namedtuple
from pathlib import Path

# tools/run.py may solve one set while later delivery bytes are still downloading.  This solver reads only the
# current set's files/context (never ctx['siblings'] or another delivery), so that path is answer-equivalent.
INDEPENDENT_DELIVERIES = True

HERE = Path(__file__).resolve().parent
for _p in (HERE.parent / "common", HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
import labels  # noqa: E402
import puzzle_asset_codec as base  # noqa: E402
import apk_facts  # noqa: E402
import apk_resources  # noqa: E402
import asset_docs  # noqa: E402
import codec_more  # noqa: E402
try:  # wave3: render_candidates + override_guard wiring (a new file; loaded by path under a unique
    _rsp_spec = importlib.util.spec_from_file_location("mobile_respell", HERE / "respell.py")
    _respell = importlib.util.module_from_spec(_rsp_spec)   # name, so another lane's respell.py never shadows it
    _rsp_spec.loader.exec_module(_respell)
except Exception:
    _respell = None
try:                      # the code containers (Hermes, dex fields, .NET, native): a file of its own
    import app_bundles    # noqa: E402
except Exception:         # without it the solver answers everything it answered before
    app_bundles = None
try:                      # Day 21 look-ahead: the payload a document's `data` names, beyond a dex of the package
    import dynamic_members  # noqa: E402
except Exception:         # without it the solver answers everything it answered before
    dynamic_members = None
try:                      # Day 21 build, round 3 (item 3): a decoding the document or the question states in words
    import stated_spec    # noqa: E402
except Exception:         # without it the solver answers everything it answered before
    stated_spec = None
try:                      # Day 21 look-ahead: readers for shapes the usual reading leaves None (lookahead_readers.py)
    import lookahead_readers  # noqa: E402
except Exception:         # without it the solver answers everything it answered before
    lookahead_readers = None
try:                      # Day 24 fold-in of Day 23's live fix: the `analysis` dex-chain codec (dex_chain_codec.py)
    import dex_chain_codec  # noqa: E402
except Exception:         # without it the solver answers everything it answered before
    dex_chain_codec = None
try:                      # a code hidden at the container level: a non-standard signing-block ID-value, a
    import apk_container   # noqa: E402  ZIP entry the central directory hides (apk_container.py)
except Exception:         # without it the solver answers everything it answered before
    apk_container = None
try:                      # Day 26 fold: a split APK bundle (.apks, .xapk, a zip of *.apk splits, an .aab layout)
    import split_bundle    # noqa: E402
except Exception:         # without it the solver answers everything it answered before
    split_bundle = None
STATED_TEXTS = []         # the set's question and prompt texts, for stated_spec (solve_set fills it before _solve)

PUZZLE = base.PUZZLE
BUDGET = 0.40            # seconds one APK may spend; a Mastery has three APKs in a 6 s window
KEY = "mobile.codec/"    # the label key of a route: mobile.codec/<codec name or route>
PATCH = HERE / "day_patch.py"
IMPORT_RESERVE = 0.10    # seconds that must be left before `cryptography` is first imported
MAX_STATE = 4096         # bytes of one search state
MAX_MEMBER = 1 << 20     # bytes of one archive member that is read
MAX_PUZZLE = 4 << 20     # bytes of the puzzle document itself: it is read whatever else the APK holds
MAX_CODE = 8 << 20       # bytes of a member that is the app's code (a JS bundle, libapp.so, an assembly store)
_CODE_NAME = re.compile(r"(\.bundle|\.jsbundle|\.hbc|\.dll|\.blob|\.blob\.so|/libapp\.so|/libmonodroid\.so|\.dex)$|"
                        r"^Payload/([^/]+)\.app/\2$")
XOR_RESERVE = 0.05       # seconds that must be left before a one-byte key is looked for
MAX_MEMBERS = 2000       # archive members that are read, the puzzle document and the other assets first
MAX_WRAPPED = 1 << 16    # bytes of a member that is tried as JSON under base64 or hex
FANOUT = 400             # states carried from one named step to the next
BASE_COST = 300_000      # byte operations puzzle_asset_codec.by_codec may be asked for (it checks no deadline)
LAYERED_WRAPPER_MIN = 6  # shallower layered documents keep their existing, judged/search routes
LAYERED_WRAPPER_MAX = 8  # the finale fast path is deliberately finite; a ninth wrapper is refused
LAYERED_WRAPPER_BYTES = 1 << 16  # enough for eight wrappers around one answer, still cheap to peel
ANS_LOOSE = re.compile(rb"(?<![0-9A-Za-z])ANS-[0-9A-Fa-f]{16}(?![0-9A-Za-z])")
ANS_BODY = re.compile(rb"[0-9A-F]{16}")
NOT_APPLIED = "which was not applied"   # the route of solve_doc's step-4 candidate (row 309): an
# answer-shaped string under a codec the module did not apply. The one LOW own-document hit that
# solve_members holds instead of returning, so a code in a native library or another member can
# still be found; every other LOW hit (a contested list, pieces that do not read) is returned as before.

# What one solve found. value: the answer-shaped text. confidence: high, medium or low.
# route: how it was reached, in words that stay the same on the next variant (never a key's
# bytes). codec: the name the label key is built from. steps: the codec names the Day 4
# solver applied on the usual document, or () for every other route. options: further
# (route, value) pairs offered with the first, best first: the other readings of one
# arrangement, the other position moves that fit.
Hit = namedtuple("Hit", "value confidence route codec steps options", defaults=((),))

LAST = {}  # the last solve, for the NOTE line and the command line
LAST_SET = {}  # B-229: the last solve_set's note (its dex-chain / split / day_patch outcome), for solve_delivery


class Clock:
    """A deadline that is checked, never signalled."""

    def __init__(self, seconds=BUDGET):
        self.start = time.perf_counter()
        self.total = seconds
        self.stop = self.start + seconds

    def up(self) -> bool:
        return time.perf_counter() >= self.stop

    def left(self) -> float:
        return self.stop - time.perf_counter()

    def each(self, items):
        """The items, until the deadline: a loop over keys or states stops by itself."""
        for item in items:
            if self.up():
                return
            yield item


class Ambiguous(Exception):
    """One text holds two different answer-shaped strings: nothing can say which is meant."""


# ---------------------------------------------------------------------------- answer shapes

def strict(b):
    """The answer code if b is exactly one (surrounding white space allowed)."""
    t = bytes(b).strip()
    return t.decode() if base.ANSWER.fullmatch(t.decode("latin-1")) else None


def answers_in(b) -> set:
    """Every different answer-shaped string in b, upper-cased."""
    return {m.group(0).upper().decode() for m in ANS_LOOSE.finditer(bytes(b))}


def loose(b):
    """The one answer inside a wrapper (answer=..., {"answer": ...}) or written with lower-case hex."""
    hits = answers_in(b)
    return hits.pop() if len(hits) == 1 else None


def body_only(b):
    """The answer whose 16 hex characters b is, when the ANS- prefix was left off."""
    t = bytes(b).strip()
    return "ANS-" + t.decode() if ANS_BODY.fullmatch(t) else None


def _slug(text, limit=64) -> str:
    """Document text made safe for a label key or a route: lowercase, a small alphabet, bounded."""
    return re.sub(r"[^a-z0-9_+.>@:=/-]+", "_", str(text).strip().lower()).strip("_")[:limit]


def _strict_text_wrappers(value):
    """Canonical Base64/hex decodings of one bounded ASCII wrapper.

    This is intentionally much smaller than the general transform search.  A spelling is
    accepted only when encoding the decoded bytes reproduces the input (apart from Base64
    padding and hex case), so permissive decoder behavior cannot manufacture a route.
    """
    raw = bytes(value).strip()
    if not raw or len(raw) > LAYERED_WRAPPER_BYTES:
        return []
    out = []
    if len(raw) % 2 == 0 and re.fullmatch(rb"[0-9A-Fa-f]+", raw):
        try:
            decoded = binascii.unhexlify(raw)
        except (binascii.Error, ValueError):
            decoded = b""
        if decoded and decoded.hex().encode() == raw.lower():
            out.append(("hex", decoded))
    if re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", raw) and b"=" not in raw[:-2]:
        padded = raw + b"=" * (-len(raw) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if decoded and base64.b64encode(decoded).rstrip(b"=") == raw.rstrip(b"="):
            out.append(("base64", decoded))
    return out


def _layered_wrapper_hit(p, suffix=""):
    """Fast, unsure-only route for six to eight explicit text wrappers.

    Day 30 established the ``layered`` family, but the general breadth-first search
    spends a 15-set finale's 0.12-second share before reaching a sixth wrapper.  Only
    the exact stated codec is eligible here.  The wrapper sequence gets its own option
    name under ``mobile.codec/layered``; an older accepted layered route therefore
    cannot make this one plain.  Multiple values, multiple data items and a ninth
    wrapper are explicit low-confidence refusals.
    """
    if not isinstance(p, dict) or not isinstance(p.get("codec"), str) \
            or p["codec"].strip().lower() != "layered":
        return None
    data = p.get("data")
    values = [data] if isinstance(data, str) else data if (
        isinstance(data, list) and data and len(data) <= 8 and all(isinstance(x, str) for x in data)
    ) else []
    if not values:
        return None

    found = []
    shallow = False
    overdeep = False
    for text in values:
        try:
            raw = text.encode("ascii")
        except (UnicodeEncodeError, AttributeError):
            continue
        if not 0 < len(raw) <= LAYERED_WRAPPER_BYTES:
            continue
        states = [(raw, ())]
        for depth in range(1, LAYERED_WRAPPER_MAX + 1):
            next_states, seen = [], set()
            for state, path in states:
                for name, decoded in _strict_text_wrappers(state):
                    route = path + (name,)
                    answer = strict(decoded)
                    if answer is not None:
                        if depth < LAYERED_WRAPPER_MIN:
                            shallow = True
                        else:
                            found.append((answer, route))
                        continue
                    marker = (decoded, route)
                    if (8 <= len(decoded) <= LAYERED_WRAPPER_BYTES and marker not in seen
                            and len(next_states) < 1 << depth):
                        seen.add(marker)
                        next_states.append(marker)
            states = next_states
            if not states:
                break
        # A canonical wrapper remains after eight peels.  Do not let the generic
        # search reinterpret that explicitly over-depth contract through a shorter path.
        overdeep = overdeep or any(_strict_text_wrappers(state) for state, _path in states)

    if shallow:
        return None                         # preserve every pre-existing <=5-layer route
    distinct = {answer for answer, _path in found}
    if overdeep:
        return Hit("", "low", "codec 'layered' has more than eight canonical text wrappers" + suffix,
                   "layered", ())
    if len(distinct) != 1 or len(values) != 1:
        return (Hit("", "low", "codec 'layered' has conflicting wrapped values" + suffix, "layered", ())
                if found else None)
    answer = next(iter(distinct))
    options, used = [], set()
    for value, path in found:
        name = "layered:wrappers:" + ">".join(path) + suffix
        if value == answer and name not in used:
            used.add(name)
            options.append((name, value))
    if not options:
        return None
    return Hit(answer, "medium", options[0][0], "layered", (), tuple(options[1:12]))


# ---------------------------------------------------------------------------- transforms

def _try(fn):
    def step(d):
        try:
            return fn(d) or None
        except Exception:
            return None
    return step


def _b58(d, alphabet=b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"):
    n = 0
    for c in d.strip():
        n = n * 58 + alphabet.index(c)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _nums(radix, token):
    """A list of numbers written in text ('65 78 83', '01000001 ...') as the bytes they name."""
    pat = re.compile(token)

    def f(d):
        text = d.decode("ascii")
        toks = pat.findall(text)
        if len(toks) < 4 or re.sub(r"[\s,;:\[\]]|0b|0o", "", pat.sub("", text)):
            return None
        return bytes(int(t, radix) for t in toks)  # a value over 255 raises: not a byte list
    return f


def _inflate(d):
    for wbits in (15, 31, -15):
        try:
            out = zlib.decompressobj(wbits).decompress(d, MAX_STATE)  # bounded: no bomb
        except zlib.error:
            continue
        if out:
            return out
    return None


def _bunzip(d):
    """bzip2, bounded like _inflate. Only bytes that start with the bzip2 magic are tried."""
    if not d.startswith(b"BZh"):
        return None
    return bz2.BZ2Decompressor().decompress(d, MAX_STATE) or None


def _unlzma(d):
    """xz or legacy .lzma, bounded like _inflate. Only bytes with one of their headers are tried."""
    if not (d.startswith(b"\xfd7zXZ\x00") or d[:1] == b"\x5d"):
        return None
    return lzma.LZMADecompressor().decompress(d, MAX_STATE) or None


_B32 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_B32HEX = b"0123456789ABCDEFGHIJKLMNOPQRSTUV"
_CROCKFORD = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _b32alpha(alphabet, crockford=False):
    """Base32 written in another alphabet (RFC 4648 base32hex, Crockford's), as bytes."""
    table = bytes.maketrans(alphabet, _B32)

    def f(d):
        t = re.sub(rb"\s+", b"", d).upper().rstrip(b"=")
        if crockford:
            t = t.replace(b"-", b"").translate(bytes.maketrans(b"OIL", b"011"))
        if not t or len(t) % 8 in (1, 3, 6) or t.translate(None, alphabet):
            return None
        return base64.b32decode(t.translate(table) + b"=" * (-len(t) % 8))
    return f


_Z85 = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
_B85 = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"


def _z85(d):
    """ZeroMQ's Z85: base85 with its own alphabet, the same digit values, whole 5-character groups."""
    t = d.strip()
    if not t or len(t) % 5 or t.translate(None, _Z85):
        return None
    return base64.b85decode(t.translate(bytes.maketrans(_Z85, _B85)))


def _utf16(d):
    if len(d) % 2 or len(d) < 8:
        return None
    for enc, zeros in (("utf-16le", d[1::2]), ("utf-16be", d[0::2])):
        if zeros.count(0) == len(d) // 2:
            return d.decode(enc).encode()
    return None


def _rot47(d):
    return bytes(33 + (c - 33 + 47) % 94 if 33 <= c <= 126 else c for c in d)


def _rot5(d):
    return bytes((c - 48 + 5) % 10 + 48 if 48 <= c <= 57 else c for c in d)


def _atbash(d):
    return bytes(155 - c if 65 <= c <= 90 else 219 - c if 97 <= c <= 122 else c for c in d)


def _url(d):
    return urllib.parse.unquote_to_bytes(d) if b"%" in d else None


def _uu(d):
    """One uuencoded line, refused when it is shorter than its own length character allows (row 342).

    binascii.a2b_uu pads a short line with NUL bytes (a2b_uu(b'1') is 17 of them), and a search
    that reached a field of 0 to 2 characters turned that padding into a made-up code
    (ANS-6666666666666666 under xor:key=day). b2a_uu writes zero groups as spaces, which strip()
    takes off: a slack of 5 refused none of 40,000 genuine texts, a slack of 2 about 4 %."""
    t = d.strip()
    n = (t[0] - 32) & 63 if t else 0
    if not n or len(t) - 1 < 4 * -(-n // 3) - 5:
        return None
    return binascii.a2b_uu(t)


def _rc4(key, data):
    s, j, out = list(range(256)), 0, bytearray()
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    for c in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


def _vigenere(d, key, every=False, beaufort=False):
    """Upper-case letters shifted back by the key's letters (A=0). The key index advances on
    each letter, or on `every` character; Beaufort reads key minus letter (its own inverse)."""
    ks = [c % 32 - 1 for c in key if chr(c).isalpha()]
    if not ks:
        return None
    out, i = bytearray(), 0
    for c in d:
        if 65 <= c <= 90:
            k = ks[i % len(ks)]
            out.append((k - (c - 65) if beaufort else c - 65 - k) % 26 + 65)
            i += 1
        else:
            out.append(c)
            i += every
    return bytes(out)


def _sub256(d, key):
    """Every byte minus the key's byte at its place: a repeating multi-byte add, undone."""
    return bytes((c - key[i % len(key)]) % 256 for i, c in enumerate(d))


def _sub95(d, key, offset):
    """Printable ASCII shifted back inside its 95 characters by the key (a key byte less `offset`)."""
    if any(not 32 <= c <= 126 for c in d):
        return None
    return bytes((c - 32 - (key[i % len(key)] - offset)) % 95 + 32 for i, c in enumerate(d))


def polyalphabetic(d, keys, clock, beaufort=False):
    """[(output, tag)] for the keyed polyalphabetic readings of one state, under every key.

    Each reading carries a tag of its own, so none of them can take the route name of the
    plain letter reading (the first, untagged one), and the judge names the one it accepts:
    letters-every (the key index advances on every character, not only on letters), bytes
    (every byte minus the key byte, mod 256), printable and printable-raw (inside the 95
    printable characters, the key byte less 32 or as it stands). Beaufort has its letter
    readings and bytes. Key by key, the document's own key first, each over every text layer."""
    outs, layers = [], _layers(d)
    for k, tag in clock.each(keys):
        for x in layers:
            if beaufort:
                cands = (("", _vigenere(x, k, beaufort=True)), ("letters-every", _vigenere(x, k, True, True)),
                         ("bytes", bytes((k[i % len(k)] - c) % 256 for i, c in enumerate(x))))
            else:
                cands = (("letters-every", _vigenere(x, k, True)), ("bytes", _sub256(x, k)),
                         ("printable", _sub95(x, k, 32)), ("printable-raw", _sub95(x, k, 0)))
            outs += [(o, ":".join(t for t in (name, tag) if t)) for name, o in cands if o]
    return outs


# ---------------------------------------------------------------------------- parameters by name
#
# Rail fence, affine and keyed substitution take their parameters from fields the document
# names (rails, a and b, alphabet), the way Day 4's xor and Day 7's caesar took `key`. A field
# may also name another field that holds the value: {"rails": "day"}, {"key_field": "salt"},
# {"rails_from": "seed"}, {"key": "$seed"}. The route says where a value came from whenever it
# was not the parameter's own first name, so a reading never takes the name of another.

def _ref(p, v):
    """The field another field names, when v is a reference to one: (field, value), else None."""
    if not isinstance(v, str) or not 1 <= len(v) <= 40:
        return None
    name = v[1:] if v[:1] in "$@" else v
    if name in p and name not in ("schema", "codec", "data"):
        return name, p[name]
    return None


def params(p, names):
    """[(value, tag)] for the parameter whose names are `names` (its own name first), references followed.

    The tag is empty for the parameter's own name, `<own>=<field>` for another of its names
    or a referenced field. A field `<name>_field`, `<name>_from`, `<name>_ref` or `<name>_source`
    that names another field gives that field's value."""
    if not isinstance(p, dict):
        return []
    own, out = names[0], []
    for n in names:
        for field in (n, n + "_field", n + "_from", n + "_ref", n + "_source"):
            if field not in p:
                continue
            v, tag = p[field], ("" if field == own else own + "=" + _slug(field, 24))
            got = _ref(p, v) if field != n or not _usable(v) else None
            if got:
                out.append((got[1], own + "=" + _slug(got[0], 24)))
            if field == n and not (isinstance(v, str) and v[:1] in "$@" and got):
                out.append((v, tag))  # the value as it stands, after the field it may name
    seen, uniq = set(), []
    for v, tag in out:  # one field reached under two of the names counts once
        mark = (json.dumps(v, sort_keys=True, default=str), tag)
        if mark not in seen:
            seen.add(mark)
            uniq.append((v, tag))
    return uniq


def _usable(v) -> bool:
    """Can v stand for a parameter by itself? An integer, a list of integers or a string of digits can."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    if isinstance(v, list):
        return bool(v) and all(isinstance(x, int) and not isinstance(x, bool) for x in v)
    return isinstance(v, str) and bool(re.fullmatch(r"\s*-?\d{1,4}(\s*[,;\s]\s*-?\d{1,4})*\s*", v))


def _ints(v) -> list:
    """The integers v stands for: an integer, a list of them, or digits written as text."""
    if isinstance(v, bool):
        return []
    if isinstance(v, int):
        return [v]
    if isinstance(v, list):
        return [x for x in v if isinstance(x, int) and not isinstance(x, bool)][:8]
    if isinstance(v, str) and _usable(v):
        return [int(t) for t in re.findall(r"-?\d{1,4}", v)][:8]
    return []


def _proves(o) -> bool:
    """Is o an answer code, as it stands or under one text encoding? A searched parameter needs this."""
    return bool(strict(o) or any(strict(y) for y in base._text_layers(o)[1:]))


def _one(found):
    """found [(output, tag)] reduced to nothing when its outputs prove different answers: a search
    that fits two values cannot say which is meant, so it offers neither."""
    values = {strict(o) or next((strict(y) for y in base._text_layers(o)[1:] if strict(y)), None) for o, _ in found}
    return found[:1] if len(values) == 1 else []


RAILS = ("rails", "rail", "key", "depth", "rows", "levels", "lines", "height", "fence", "n", "k")
MAX_RAILS = 64
SEARCH_RAILS = range(2, 9)


def _rail_order(n, length):
    """The positions of a text in the order a rail fence of n rails writes them out."""
    rows, r, step = [], 0, 1
    for i in range(length):
        rows.append(r)
        if r == 0:
            step = 1
        elif r == n - 1:
            step = -1
        r += step
    return sorted(range(length), key=lambda i: (rows[i], i))


def _rail_decode(d, n):
    if not 2 <= n < len(d):
        return None
    out = bytearray(len(d))
    for k, pos in enumerate(_rail_order(n, len(d))):
        out[pos] = d[k]
    return bytes(out)


def _rail_encode(d, n):
    if not 2 <= n < len(d):
        return None
    return bytes(d[i] for i in _rail_order(n, len(d)))


def railfence(d, p, clock):
    """[(output, tag)] for a rail fence on d and its text layers.

    The rail count comes from a field first (RAILS, then any other integer field, each named
    in the tag when it is not `rails`), read both ways: written out by rails (the decode, no
    tag) and `inverse`. With no field that gives a count, the counts 2 to 8 are tried and a
    count is kept only when the ANS- prefix proves it (`rails-searched`). When counts that
    prove different answers remain (on 20 characters 7 and 8 rails move the first four
    alike), each is offered under its own count (`rails-searched:<n>`), smallest first: the
    judge names the count, which a document that never states it keeps from variant to
    variant."""
    counts = [(n, tag) for v, tag in params(p, RAILS) for n in _ints(v)[:1] if 2 <= n <= MAX_RAILS]
    named = {f for f in RAILS} | {"day", "version", "v", "schema", "codec", "data"}
    counts += [(v, "rails=" + _slug(k, 24)) for k, v in (p.items() if isinstance(p, dict) else ())
               if k not in named and isinstance(v, int) and not isinstance(v, bool) and 2 <= v <= MAX_RAILS]
    outs, layers = [], _layers(d)
    for n, tag in clock.each(list(dict.fromkeys(counts))[:16]):
        for x in layers:
            outs += [(o, ":".join(t for t in (way, tag) if t)) for way, o in
                     (("", _rail_decode(x, n)), ("inverse", _rail_encode(x, n))) if o]
    if outs:
        return outs
    found = [(o, way + "rails-searched", n) for x in layers for n in clock.each(SEARCH_RAILS)
             for way, o in (("", _rail_decode(x, n)), ("inverse:", _rail_encode(x, n))) if o and _proves(o)]
    if _one([(o, t) for o, t, _ in found]):
        return [(found[0][0], found[0][1])]
    return [(o, "%s:%d" % (t, n)) for o, t, n in found]


AFFINE_A = ("a", "alpha", "mult", "multiplier", "m", "slope", "k1", "key_a", "a_key")
AFFINE_B = ("b", "beta", "shift", "offset", "add", "increment", "intercept", "k2", "key_b", "b_key")


def _affine_letters(d, a, b):
    """Letters decoded from y = a*x + b (mod 26), both cases; None when a has no inverse."""
    try:
        inv = pow(a % 26, -1, 26)
    except ValueError:
        return None
    return bytes((inv * (c - 65 - b)) % 26 + 65 if 65 <= c <= 90 else (inv * (c - 97 - b)) % 26 + 97 if 97 <= c <= 122
                 else c for c in d)


def _affine_bytes(d, a, b):
    """Bytes decoded from y = a*x + b (mod 256); None when a is even."""
    if a % 2 == 0:
        return None
    inv = pow(a % 256, -1, 256)
    return bytes((inv * (c - b)) % 256 for c in d)


def affine(d, p, clock):
    """[(output, tag)] for an affine cipher on d and its text layers.

    a and b come from fields (AFFINE_A, AFFINE_B), or a and b from a key of two integers.
    Read over letters (mod 26, no tag) and over bytes (mod 256, `bytes`). When the document
    gives no pair, a is searched over its valid values (a given a is kept) and b is recovered
    from the ANS- prefix (`prefix-ab`, `prefix-b`): kept only when the first four characters
    come out as ANS-, and nothing when two values of a prove different answers."""
    pairs = []
    a_s = [(n, tag) for v, tag in params(p, AFFINE_A) for n in _ints(v)[:1]]
    b_s = [(n, tag) for v, tag in params(p, AFFINE_B) for n in _ints(v)[:1]]
    pairs += [(a, b, ":".join(t for t in (ta, tb) if t)) for a, ta in a_s[:2] for b, tb in b_s[:2]]
    for v, tag in params(p, ("key", "keys", "ab", "params")):
        ns = _ints(v)
        if len(ns) == 2:
            pairs.append((ns[0], ns[1], "ab=" + (tag.split("=", 1)[1] if tag else "key")))
    outs, layers = [], _layers(d)
    for a, b, tag in clock.each(pairs[:8]):
        for x in layers:
            outs += [(o, ":".join(t for t in (way, tag) if t)) for way, o in
                     (("", _affine_letters(x, a, b)), ("bytes", _affine_bytes(x, a, b))) if o]
    if outs:
        return outs
    fixed = a_s[0] if a_s else None
    found = []
    for x in layers:
        if clock.up():
            break
        if len(x) >= 4 and 65 <= x[0] <= 90:   # letters: b is where A went, a is proven by S
            for a in ([fixed[0]] if fixed else (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)):
                o = _affine_letters(x, a, x[0] - 65)
                if o and o[:4] == b"ANS-" and _proves(o):
                    found.append((o, "prefix-b" if fixed else "prefix-ab"))
        if len(x) >= 4:                         # bytes: 13a is the step from A to N, b follows
            for a in ([fixed[0]] if fixed else [((x[1] - x[0]) * pow(13, -1, 256)) % 256]):
                o = _affine_bytes(x, a, (x[0] - 65 * a) % 256)
                if o and o[:4] == b"ANS-" and _proves(o):
                    found.append((o, "bytes:prefix-b" if fixed else "bytes:prefix-ab"))
    return _one(found)


SUBST = ("alphabet", "cipher_alphabet", "cipheralphabet", "alpha", "table", "mapping", "map", "substitution",
         "cipher", "key", "keyword", "secret")
_LETTERS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_PAIRS = (("plain", "cipher"), ("from", "to"), ("source", "target"), ("plain_alphabet", "cipher_alphabet"),
          ("in", "out"))


def _tables(v, tag):
    """[(cipher alphabet, plain alphabet, tag)] that the value v of a field could mean."""
    if isinstance(v, dict) and 2 <= len(v) <= 95 and all(isinstance(k, str) and isinstance(x, str) and len(k) == 1
                                                         and len(x) == 1 for k, x in v.items()):
        ks, xs = "".join(v).encode("latin-1", "replace"), "".join(v.values()).encode("latin-1", "replace")
        if len(set(xs)) == len(xs):
            return [(ks, xs, ":".join(t for t in ("map", tag) if t)), (xs, ks, ":".join(t for t in ("map-inverse", tag) if t))]
        return []
    if not isinstance(v, str) or not v.isascii() or not 1 <= len(v) <= 95:
        return []
    t = v.encode()
    out = []
    if len(t) >= 10 and len(set(t)) == len(t):  # an alphabet in its cipher order
        out.append((t, bytes(sorted(t)), tag))
        if set(t) == set(b"0123456789" + _LETTERS):
            out.append((t, _LETTERS + b"0123456789", ":".join(x for x in ("letters-first", tag) if x)))
    letters = bytes(dict.fromkeys(c for c in t.upper() if 65 <= c <= 90))
    if letters and len(letters) < 26 and t.isalpha():  # a keyword: its letters, then the rest of A to Z
        out.append((letters + bytes(c for c in _LETTERS if c not in letters), _LETTERS,
                    ":".join(x for x in ("keyword", tag) if x)))
    return out


def substitution(d, p, clock):
    """[(output, tag)] for a keyed substitution on d and its text layers.

    The cipher alphabet comes from a field (SUBST): a permutation of its own characters
    (read against them sorted, and an alphanumeric one also against A to Z then 0 to 9:
    `letters-first`), a keyword that starts the alphabet (`keyword`), or a map of single
    characters (`map`, `map-inverse`); or from a pair of fields such as plain and cipher
    (`pair`). Each table is read both ways: cipher to plain (no tag) and `inverse`. A letter
    table also maps the lower-case letters. With no table in the document there is nothing
    to read: a substitution is not searched."""
    tables = []
    if isinstance(p, dict):  # a pair of fields says both alphabets: it comes before either read alone
        for a, b in _PAIRS:
            pa, pb = p.get(a), p.get(b)
            if isinstance(pa, str) and isinstance(pb, str) and pa.isascii() and pb.isascii() and len(pa) == len(pb) \
                    and 2 <= len(pa) <= 95 and len(set(pa)) == len(pa) == len(set(pb)):
                tables.append((pb.encode(), pa.encode(), "pair=" + _slug(a, 12)))
    tables += [x for v, tag in params(p, SUBST) for x in _tables(v, tag)]
    outs, layers = [], _layers(d)
    for cipher, plain, tag in clock.each(tables[:12]):
        for way, (src, dst) in (("", (cipher, plain)), ("inverse", (plain, cipher))):
            if set(src) <= set(_LETTERS) and set(dst) <= set(_LETTERS):
                src, dst = src + src.lower(), dst + dst.lower()
            table = bytes.maketrans(src, dst)
            outs += [(x.translate(table), ":".join(t for t in (way, tag) if t)) for x in layers]
    return outs


KEYED = {"railfence": railfence, "affine": affine, "substitution": substitution}


# Codecs this module can apply by name, beyond the ones puzzle_asset_codec.NAMED has.
STEP = {
    "base85": _try(lambda d: base64.b85decode(d.strip())),
    "ascii85": _try(lambda d: base64.a85decode(d.strip(), adobe=d.strip().startswith(b"<~"))),
    "base58": _try(_b58),
    "binary": _try(_nums(2, r"[01]{8}")),
    "decimal": _try(_nums(10, r"\d{1,3}")),
    "octal": _try(_nums(8, r"[0-7]{1,3}")),
    "url": _try(_url),
    "utf16": _try(_utf16),
    "zlib": _try(_inflate),
    "rot47": _try(_rot47),
    "rot5": _try(_rot5),
    "rot18": _try(lambda d: _rot5(base.t_rot13(d, {}) or b"")),
    "atbash": _try(_atbash),
    "uu": _try(_uu),
    "bz2": _try(_bunzip),
    "lzma": _try(_unlzma),
    "base32hex": _try(_b32alpha(_B32HEX)),
    "crockford": _try(_b32alpha(_CROCKFORD, crockford=True)),
    "z85": _try(_z85),
}
# Compressed bytes are written into the document under a text encoding, as Day 4's xor bytes
# were under base64: a step of these names is applied to the data and to every text layer of it.
PACKED = ("zlib", "bz2", "lzma")
# Alphabets that read most upper-case text as valid: applied when the document names them, never
# as a search move, where they would turn every state into one more and crowd the search out.
NAME_ONLY = ("base32hex", "crockford", "z85")
# A Caesar shift whose amount is a key of the document (or recovered from the ANS- prefix).
SHIFTS = ("caesar", "add", "sub", "shift", "rot", "rotn", "rot-n", "rot_n", "caesar-n", "caesar_n")
_ROTN = re.compile(r"(rot|caesar|shift)[-_ ]?(\d+)")
ALIASES = {
    "b85": "base85", "base-85": "base85", "a85": "ascii85", "b58": "base58", "bin": "binary", "bits": "binary",
    "dec": "decimal", "ascii": "decimal", "oct": "octal", "percent": "url", "urlencode": "url",
    "url-encoded": "url", "utf-16": "utf16", "utf16le": "utf16", "utf-16le": "utf16", "gzip": "zlib",
    "gz": "zlib", "deflate": "zlib", "inflate": "zlib", "uuencode": "uu",
    "raw": "plain", "text": "plain", "clear": "plain", "cleartext": "plain", "plaintext": "plain",
    "utf8": "plain", "utf-8": "plain", "noop": "plain",
    # base64 with the URL-safe alphabet (puzzle_asset_codec.t_base64 reads both alphabets)
    "base64-url": "base64url", "base64_url": "base64url", "b64url": "base64url", "b64-url": "base64url",
    "b64_url": "base64url", "urlsafe": "base64url", "urlsafe-base64": "base64url", "urlsafe_base64": "base64url",
    "urlsafebase64": "base64url", "url-safe-base64": "base64url", "url_safe_base64": "base64url",
    "urlsafe-b64": "base64url", "urlsafe_b64": "base64url", "base64-urlsafe": "base64url",
    "base64_urlsafe": "base64url", "base64urlsafe": "base64url", "websafe-base64": "base64url",
    "websafe_base64": "base64url", "base-64": "base64", "base_64": "base64", "base-32": "base32",
    "base_32": "base32", "base-16": "hex", "base_16": "hex",
    "base32-hex": "base32hex", "base32_hex": "base32hex", "b32hex": "base32hex", "b32-hex": "base32hex",
    "base32hexdecode": "base32hex", "crockford32": "crockford", "crockford-base32": "crockford",
    "crockford_base32": "crockford", "base32-crockford": "crockford", "base32_crockford": "crockford",
    "base32crockford": "crockford", "zeromq": "z85", "z85-base85": "z85", "base85-z85": "z85",
    "bzip2": "bz2", "bzip": "bz2", "bz": "bz2", "xz": "lzma", "lzma2": "lzma", "lzma-alone": "lzma",
    "lzma_alone": "lzma", "zlib-deflate": "zlib", "gunzip": "zlib", "rot-47": "rot47", "rot_47": "rot47",
    "rot 47": "rot47", "rot_13": "rot13", "rot 13": "rot13",
    "vig": "vigenere", "vigenère": "vigenere", "polyalphabetic": "vigenere",
    # row 72: rail fence, affine and keyed substitution, each read with parameters from named fields
    "rail_fence": "railfence", "rail-fence": "railfence", "rail fence": "railfence", "rails": "railfence",
    "rail": "railfence", "zigzag": "railfence", "zig-zag": "railfence", "zig_zag": "railfence",
    "railfence_cipher": "railfence", "rail_fence_cipher": "railfence", "rail-fence-cipher": "railfence",
    "affine_cipher": "affine", "affine-cipher": "affine",
    "subst": "substitution", "substitute": "substitution", "sub_alphabet": "substitution",
    "monoalphabetic": "substitution", "mono": "substitution", "simple_substitution": "substitution",
    "simple-substitution": "substitution", "keyword": "substitution", "keyed": "substitution",
    "keyed_alphabet": "substitution", "keyed-alphabet": "substitution", "cipher_alphabet": "substitution",
    "alphabet": "substitution", "mixed_alphabet": "substitution", "keyword_cipher": "substitution",
    "substitution_cipher": "substitution", "substitution-cipher": "substitution",
}
# A codec name that says only that the steps are listed elsewhere: the steps are read from
# one of CHAIN_FIELDS (a list, or a string joined as `codec` is), or from numbered fields.
CHAIN = ("chain", "chained", "pipeline", "multi", "multistep", "multi-step", "multi_step", "layered", "layers",
         "compose", "composed", "composite", "stack", "stacked", "combo", "combined", "nested", "sequence")
CHAIN_FIELDS = ("steps", "chain", "pipeline", "layers", "codecs", "ops", "operations", "transforms", "sequence",
                "stages")
_NUMBERED = (("step%d", 1), ("codec%d", 1), ("stage%d", 1), ("layer%d", 1), ("step_%d", 1), ("codec_%d", 1))
_ORDINAL = (("first", "second", "third", "fourth"), ("outer", "inner"))
IDENTITY = ("plain", "none", "identity")
# Names that say how the data is laid out over several fields. They apply only to the
# matching layout, so an answer-shaped single field under one of them is not "applied".
JOIN = ("split", "concat", "join", "joined", "parts", "chunks", "segments", "pieces", "fragments")
WEAVE = ("interleave", "interleaved", "weave", "zip", "alternate")
# Pieces listed beside an order (see "arrangements" below). ARRANGED is the layout of pieces
# put in order, which a JOIN name applies to as it does to a join.
ARRANGED = "arranged"
SUBSET = "subset"        # the cut of an order that names fewer pieces than the document lists
PIECES = "parts"         # the pieces field of the judged Day 5 document; any other is named in the route
PAIRED = ("pairs", "pairs-char-first", "map")   # the cuts of pieces that carry their own places (_paired)
LISTED = ("", "objects") + PAIRED  # the cuts whose pieces the document lists one by one
MAX_PIECES = 64          # pieces of one arrangement: an answer code has 20 characters
MAX_PIECE = 256          # characters of a piece that is decoded by itself
MAX_SOURCES = 16         # arrangements read from one document
QUICK = 0.03             # seconds, and QUICK_NODES states, of the short search under a layout name (step 6)
QUICK_NODES = 300
_INT_SEP = re.compile(r"\s*[,;]\s*|\s+")  # one separator between two numbers of an order written as text
# rot5 and rot18 keep a well-formed answer well formed, so they are never search moves.
BLIND = ("rot5", "rot18")
_OTHER = re.compile(r"aes.*|rc4|arc4|cipher|encrypted|vigenere|beaufort|xor.*")
# Readings of a keyed shift with a key of several bytes, beyond the one-byte Caesar shift: at
# most this many are added to one state, so they cannot crowd the one-byte readings (and their
# text layers) out of by_name's FANOUT.
MAX_KEYED = 48
UNKNOWN = object()       # by_name: a step name apply() does not know
MAX_OTHERS = 4           # further exact answers with another value that by_name offers beside the first
_WEAKER = frozenset(("prefix-added", "unwrapped"))   # by_name's tags of a reading that is not an exact code


def _known(name) -> bool:
    return (name in base.NAMED or name in STEP or name in ALIASES or name in JOIN or name in WEAVE
            or name in SHIFTS or name in KEYED or bool(_ROTN.fullmatch(name) or _OTHER.fullmatch(name)))


# More steps that are applied only by name (base36/62/45/91, escapes, Morse, zstd, lz4, brotli,
# snappy, columnar, delta, offsets, chacha20, des3, fernet, jwt): codec_more.py adds them to KEYED
# and ALIASES. None is a search move, so an opaque codec name is searched as before.
APK_KEYS = {}            # {"keys": [bytes]} while a document is read again with the APK's key material


class _Self:
    """This module's globals by attribute, for codec_more: the solver is loaded by path, more than
    once in a process and under names that are not in sys.modules, so it hands itself over."""

    def __getattr__(self, name):
        try:
            return globals()[name]
        except KeyError:
            raise AttributeError(name) from None


SELF = _Self()
codec_more.register(SELF)
try:   # Day 14 look-ahead: keystore files (PKCS12, JKS, JCEKS, BKS) with a stated or usual password
    import keystores  # noqa: E402
except Exception:   # an armed export without the file: the lane runs as before
    keystores = None
try:   # backlog row 88: classical ciphers by name (codec_classical.py over solvers/common/classical.py)
    import codec_classical  # noqa: E402
    codec_classical.register(SELF)
except Exception:   # an armed export without the file, or without classical.py: the lane runs as before
    codec_classical = None

_BITREV = bytes(int("{:08b}".format(c)[::-1], 2) for c in range(256))


def _rol(c, r):
    """One byte rotated left by r bits."""
    return ((c << r) | (c >> (8 - r))) & 255


def _layers(d):
    """d, plus what it is underneath a text encoding (base64, hex, base32, a number list)."""
    outs = base._text_layers(d)
    for name in ("decimal", "binary", "octal"):
        o = STEP[name](d)
        if o:
            outs.append(o)
    return outs


def keyless(d):
    """Decodings whose key is recovered from the plaintext's known start, "ANS-": [(tag, bytes)].

    The bit moves need no key at all, and the known start proves them the same way: every
    byte rotated by 1 to 7 bits (4 is the nibble swap), or its bit order reversed, is
    offered only when the first four bytes come out as "ANS-".

    A tag names the method and never its amount (Day 12 look-ahead): a key's length and a
    rotation's bit count are read from each variant's own bytes, so prefix-key and prefix-rol
    are the names the judge accepts once and the next variant answers under, whatever its
    amount. A key of 1 to 4 bytes is every period the four known bytes allow, as before; when
    two periods give different answer codes neither is offered: one name holds one value."""
    if len(d) != 20:
        d = d.strip()
        if len(d) != 20:
            return []
    if d[:4] == b"ANS-":
        # Day 14 look-ahead: the text starts as an answer code already, so every key the start
        # "proves" is the key that changes nothing, and the reading would be the data as it
        # stands under a codec that was not applied (a shift inside the hex alphabet came out
        # as one option, a wrong code). That case is solve_doc's step 4: a candidate, no answer.
        return []
    out = []
    k4 = bytes(a ^ b for a, b in zip(d[:4], b"ANS-"))
    keyed = list(dict.fromkeys(base._xor(d, k4[:n]) for n in (1, 2, 3, 4) if (k4[:n] * 4)[:4] == k4))
    if len({strict(o) for o in keyed} - {None}) <= 1:
        out += [("prefix-key", o) for o in keyed]
    out.append(("prefix-add", bytes((c - (d[0] - 65)) % 256 for c in d)))
    # a repeating add of 2 to 4 bytes, its period the shortest the four known bytes allow
    a4 = bytes((a - b) % 256 for a, b in zip(d[:4], b"ANS-"))
    if a4[1:] != a4[:3]:
        n = next(n for n in (2, 3, 4) if (a4[:n] * 4)[:4] == a4)
        out.append(("prefix-add%d" % n, _sub256(d, a4[:n])))
    out.append(("prefix-roll-add", bytes(c ^ (((d[0] ^ 65) + i) & 255) for i, c in enumerate(d))))
    out.append(("prefix-roll-xor", bytes(c ^ (d[0] ^ 65) ^ i for i, c in enumerate(d))))
    if 65 <= d[0] <= 90:
        out.append(("prefix-caesar", base._caesar(d, (65 - d[0]) % 26)))
    for r in range(1, 8):   # at most one fits: no two rotations of a byte give "A"
        if _rol(d[0], r) == 65 and bytes(_rol(c, r) for c in d[:4]) == b"ANS-":
            out.append(("prefix-rol", bytes(_rol(c, r) for c in d)))
    if d[:4].translate(_BITREV) == b"ANS-":
        out.append(("prefix-bitrev", d.translate(_BITREV)))
    return out


def block_ciphers(d, keys, ivs, clock, algs=("rc4", "aes")):
    """(label, plaintext) for RC4 and AES (ECB, CBC, CTR, GCM) under every key candidate.

    A generator, so the caller stops at the first answer and the deadline is checked
    between keys. `cryptography` is imported here, only when a cipher is really tried."""
    if "rc4" in algs:
        for k, tag in clock.each(keys):
            yield "rc4" + (":" + tag if tag else ""), _rc4(k, d)
    if "aes" not in algs or len(d) < 16 or clock.up():
        return
    if "cryptography" not in sys.modules and clock.left() < IMPORT_RESERVE:
        return  # the import would run past the deadline, and nothing can interrupt it
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return
    seen = set()
    for k, tag in keys:
        cands = [("", k)] if len(k) in (16, 24, 32) else []
        cands += [("md5", hashlib.md5(k).digest()), ("sha256", hashlib.sha256(k).digest()),
                  ("sha256.16", hashlib.sha256(k).digest()[:16]), ("pad16", k.ljust(16, b"\0")[:16])]
        for kdf, kk in cands:
            if clock.up():
                return
            if kk in seen:
                continue
            seen.add(kk)
            tries = []
            if len(d) % 16 == 0:
                tries.append(("ecb", modes.ECB(), d))
                tries += [("cbc", modes.CBC(iv), d) for iv in ivs if len(iv) == 16]
                tries.append(("cbc-zero-iv", modes.CBC(b"\0" * 16), d))
                if len(d) >= 32:
                    tries.append(("cbc-iv-first", modes.CBC(d[:16]), d[16:]))
            tries += [("ctr", modes.CTR(iv), d) for iv in ivs if len(iv) == 16]
            suffix = (":" + kdf if kdf else "") + (":" + tag if tag else "")
            for mode_name, mode, body in tries:
                try:
                    dec = Cipher(algorithms.AES(kk), mode).decryptor()
                    pt = dec.update(body) + dec.finalize()
                except Exception:
                    continue
                if pt and 1 <= pt[-1] <= 16:
                    yield "aes-" + mode_name + suffix, pt[:-pt[-1]]
                yield "aes-" + mode_name + suffix, pt
            for iv, body, mode_name in [(i, d, "gcm") for i in ivs if len(i) == 12] + (
                    [(d[:12], d[12:], "gcm-iv-first")] if len(d) > 28 else []):
                try:
                    yield "aes-" + mode_name + suffix, AESGCM(kk).decrypt(iv, body, None)
                except Exception:
                    continue


# ---------------------------------------------------------------------------- the document

META = ("schema", "day", "codec", "version", "v", "alg", "algorithm", "encoding", "steps", "chain", "hint",
        "note", "description")
_KEYISH = re.compile(r"(^|\.)(key|iv|nonce|salt|secret|pass|password|seed)\w*$", re.I)


def flat(p, prefix=""):
    """Every leaf of the document as (dotted name, value). A list of integers is one leaf."""
    if isinstance(p, dict):
        for k, v in p.items():
            if k == TYPED_STEPS:
                continue
            yield from flat(v, f"{prefix}{k}.")
    elif isinstance(p, list) and not (p and all(isinstance(x, int) for x in p)):
        for i, v in enumerate(p):
            yield from flat(v, f"{prefix}{i}.")
    else:
        yield prefix[:-1], p


INT_DATA = ("chars", "bytes", "ints", "values", "codes", "char_codes", "charcodes")
KEY_STEP = ("key_step", "keystep", "step", "key_increment", "increment", "key_delta", "delta")


def data_candidates(p):
    """What the encoded text could be, as [(layout, bytes)], the usual one first.

    'data' is the `data` string itself. 'ints' is a `data` list of byte values, written out
    as decimal text. 'join', 'join.sorted', 'join.reversed' and 'interleave' put several
    text fields together. 'field:<name>' is one renamed or nested text field. (Pieces that
    come with an order are laid out by arranged(), not here; solve_doc then drops the
    joins, which ignore the order, as it does beside any other number: see numbers_in.)"""
    out = []
    d = p.get("data")
    if isinstance(d, str):
        out.append(("data", d.encode("utf-8", "surrogatepass")))
    elif isinstance(d, list) and d and all(isinstance(x, int) for x in d):
        out.append(("ints", " ".join(str(x & 255) for x in d[:MAX_STATE]).encode()))
    if d is None or d == "":
        # Day 19 look-ahead (item 5): `data` empty and the values under another name (a Java char[] or
        # byte[] written out), as the `ints` layout, named in the route (`@chars`). Only when the document
        # holds ONE such list (or several with the same values): two different lists are two facts, and
        # reading the first would be a guess by position (review of the Day 19 build), so neither is read.
        lists = [(f, " ".join(str(x & 255) for x in v).encode()) for f in INT_DATA for v in [p.get(f)]
                 if isinstance(v, list) and 2 <= len(v) <= MAX_STATE
                 and all(isinstance(x, int) and not isinstance(x, bool) for x in v)]
        if lists and len({body for _, body in lists}) == 1:
            out.append(("ints:" + lists[0][0], lists[0][1]))
    parts = [(n, v) for n, v in flat(p)
             if isinstance(v, str) and v and n.split(".")[0].lower() not in META and not _KEYISH.search(n)][:16]

    def natural(name):
        return [(0, int(t), "") if t.isdigit() else (1, 0, t) for t in re.split(r"(\d+)", name)]

    if len(parts) > 1:
        out.append(("join", "".join(v for _, v in parts).encode("utf-8", "surrogatepass")))
        out.append(("join.sorted", "".join(v for _, v in sorted(parts, key=lambda nv: natural(nv[0])))
                    .encode("utf-8", "surrogatepass")))
        out.append(("join.reversed", "".join(v for _, v in parts[::-1]).encode("utf-8", "surrogatepass")))
        if len(parts) == 2 and 0 <= len(parts[0][1]) - len(parts[1][1]) <= 1:
            a, b = parts[0][1], parts[1][1]
            woven = "".join(x + y for x, y in zip(a, b)) + a[len(b):]
            out.append(("interleave", woven.encode("utf-8", "surrogatepass")))
    out += [("field:" + n, v.encode("utf-8", "surrogatepass")) for n, v in parts if n != "data"]
    seen, uniq = set(), []
    for label, body in out:
        if body and body not in seen and len(body) <= MAX_STATE:
            seen.add(body)
            uniq.append((label, body))
    return uniq


def key_candidates(p):
    """Every byte string the document could mean as a key: [(bytes, tag)].

    The keys the Day 4 solver reads carry no tag. A key read more widely (a nested field,
    the `day` number, a little-endian integer) is tagged with where it came from, so the
    route says so and is not mistaken for the judged one."""
    out = []
    try:
        out += [(k, "") for k in base._keys(p)]
    except Exception:
        pass
    for n, v in flat(p):
        if n.split(".")[0] in ("schema", "codec", "data"):
            continue
        tag = "key=" + _slug(n, 24)
        try:
            out += [(k, tag) for k in base._keys({"k": v})]
        except Exception:
            continue
        if isinstance(v, int) and not isinstance(v, bool) and v >= 256:
            out.append((v.to_bytes((v.bit_length() + 7) // 8, "little"), tag + ".le"))
    seen, uniq = set(), []
    for k, tag in out:
        if k and k not in seen:
            seen.add(k)
            uniq.append((k, tag))
    return uniq


_WRAPPED = re.compile(r"^(wrapped|encrypted|enc|sealed|protected)[_\-]?(data[_\-]?)?(key|dek|cek)$|^(edek|wrapped|wrapped_dek)$", re.I)
_WRAPPING = re.compile(r"^(wrapping|wrap|unwrap|master|kek|key[_\-]?encryption)[_\-]?(key)?$", re.I)
_PASSWORD = re.compile(r"^(password|passphrase|pass|pin|store[_\-]?pass(word)?|key[_\-]?pass(word)?)$", re.I)
_SALT = re.compile(r"^(salt|kdf[_\-]?salt)$", re.I)
_ITERATIONS = re.compile(r"^(iterations?|iteration[_\-]?count|iter|rounds|kdf[_\-]?iterations?|c)$", re.I)
MAX_ITERATIONS = 200_000    # a stated PBKDF2 count over this is not derived (it would be most of the APK's time)


def derived_keys(p, clock) -> list:
    """[(key, tag)] for keys the document does not hold but says how to get (Day 14 look-ahead), read
    from its own top-level fields by their names and never searched for:

      unwrap-xor, unwrap-aes, unwrap-rfc3394   a `wrapped_key` under a `wrapping_key` (or `kek`):
          the two XORed, the wrapped key decrypted with AES-ECB, or unwrapped as RFC 3394 says
      pbkdf2-sha1.16, pbkdf2-sha256.32, ...    PBKDF2 over a `password` and a `salt` with the
          `iterations` the document states (none stated: nothing is derived)

    Every tag goes into the route, so such an answer is unsure until the judge accepts it."""
    if not isinstance(p, dict):
        return []
    def vals(rx):
        out = []
        for k, v in p.items():
            if isinstance(k, str) and rx.match(k) and isinstance(v, (str, list)) and v:
                try:
                    out += base._keys({"k": v})
                except Exception:
                    pass
        return out

    out = []
    wrapped, wrapping = vals(_WRAPPED), vals(_WRAPPING)
    if wrapped and wrapping and not clock.up():
        ciphers = None
        if "cryptography" in sys.modules or clock.left() >= IMPORT_RESERVE:
            try:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
                ciphers = (Cipher, algorithms, modes, aes_key_unwrap)
            except ImportError:
                ciphers = None
        for w in wrapped[:6]:
            for k in wrapping[:6]:
                if len(w) == len(k) and len(w) in (16, 24, 32):
                    out.append((bytes(a ^ b for a, b in zip(w, k)), "unwrap-xor"))
                if ciphers and len(k) in (16, 24, 32):
                    Cipher, algorithms, modes, aes_key_unwrap = ciphers
                    if len(w) % 16 == 0 and len(w) >= 16:
                        try:
                            dec = Cipher(algorithms.AES(k), modes.ECB()).decryptor()
                            pt = dec.update(w) + dec.finalize()
                            out += [(x, "unwrap-aes") for x in (pt, pt[:16], pt[:-pt[-1]] if 1 <= pt[-1] <= 16 else b"")
                                    if len(x) in (16, 24, 32)]
                        except Exception:
                            pass
                    if len(w) % 8 == 0 and len(w) >= 24:
                        try:
                            out.append((aes_key_unwrap(k, w), "unwrap-rfc3394"))
                        except Exception:
                            pass
    passwords = [v.encode() for k, v in p.items() if isinstance(k, str) and _PASSWORD.match(k) and isinstance(v, str) and v]
    salts = vals(_SALT)
    counts = [v for k, v in p.items() if isinstance(k, str) and _ITERATIONS.match(k) and isinstance(v, int)
              and not isinstance(v, bool) and 1 <= v <= MAX_ITERATIONS]
    if passwords and salts and counts:
        spent = 0
        for pw in passwords[:2]:
            for salt in salts[:3]:
                for alg, size in (("sha1", 16), ("sha256", 32), ("sha256", 16), ("sha1", 32)):
                    spent += counts[0]
                    if clock.up() or spent > 4 * MAX_ITERATIONS or (counts[0] > 20_000 and clock.left() < 0.2):
                        break
                    out.append((hashlib.pbkdf2_hmac(alg, pw, salt, counts[0], size), "pbkdf2-%s.%d" % (alg, size)))
    seen, uniq = set(), []
    for k, tag in out:
        if k and k not in seen:
            seen.add(k)
            uniq.append((k, tag))
    return uniq


_TAG_FIELD = re.compile(r"^(tag|auth[_\-]?tag|gcm[_\-]?tag|mac)$", re.I)


def gcm_tags(p) -> list:
    """The authentication tags a document states in a field of their own (12 to 16 bytes)."""
    out = []
    for k, v in (p.items() if isinstance(p, dict) else ()):
        if isinstance(k, str) and _TAG_FIELD.match(k) and isinstance(v, str) and v:
            try:
                out += [t for t in base._keys({"k": v}) if 12 <= len(t) <= 16 and t != v.encode()]
            except Exception:
                pass
    return list(dict.fromkeys(out))


def base_steps(p):
    """The codec names as puzzle_asset_codec.by_codec reads them."""
    codec = p.get("codec")
    raw = codec if isinstance(codec, list) else re.split(r"\s*(?:\+|\||,|>|->|then)\s*", str(codec or ""))
    return [str(c).strip().lower() for c in raw if c]


def base_cost(p, steps) -> int:
    """An upper bound on the byte operations puzzle_asset_codec.by_codec spends on a document.

    by_codec keeps every output of every step, and each state's text decodings: an xor
    step turns one state into up to 16 per key (4 text layers in, 4 out), any other step
    into up to 4. xor works byte by byte in Python; the other steps are counted at a
    sixteenth of that plus a fixed charge per state. A Day 4 document costs a few hundred;
    four xor steps over forty keys would not finish in a day."""
    try:
        keys = max(len(base._keys(p)), 1)
        size = len(base._b(p.get("data", "")))
    except Exception:
        return BASE_COST + 1
    states, cost = 1, 0
    for name in steps:
        if base.NAMED.get(name) is base.t_xor:
            cost += states * 4 * keys * size
            states *= 16 * keys
        else:
            cost += states * (size // 16 + 40)
            states *= 4
        if cost > BASE_COST:
            break
    return 2 * cost  # the chain is tried in the order given and reversed


def chain_steps(p):
    """(field, steps) when `codec` says only that the steps are listed elsewhere ('chain',
    'pipeline'): the steps from a CHAIN_FIELDS list or string, or from numbered or ordinal
    fields (step1, step2; first, second; outer, inner) in their own order. Else None.

    The steps are taken in the order the document lists them; by_name reads them in that
    order first and the reversed order after, as for any chain."""
    codec = p.get("codec")
    if not (isinstance(codec, str) and codec.strip().lower() in CHAIN):
        return None
    for field in CHAIN_FIELDS:
        v = p.get(field)
        if isinstance(v, list) and 1 < len(v) <= 8 and all(isinstance(x, str) and x for x in v):
            return field, [x.strip().lower()[:40] for x in v]
        if isinstance(v, str) and v.strip():
            toks = [t for t in re.split(r"\s*(?:\+|\||,|>|->|then|/|&)\s*", v.strip().lower()) if t]
            if 1 < len(toks) <= 8:
                return field, [t[:40] for t in toks]
    for pattern, first in _NUMBERED:
        vals = []
        while len(vals) < 8 and isinstance(p.get(pattern % (first + len(vals))), str):
            vals.append(p[pattern % (first + len(vals))].strip().lower()[:40])
        if len(vals) > 1:
            return pattern.replace("%d", "n"), vals
    for names in _ORDINAL:
        vals = [p[n].strip().lower()[:40] for n in names if isinstance(p.get(n), str)]
        if len(vals) > 1:
            return names[0], vals
    return None


STEP_NAME = ("op", "codec", "name", "type", "step", "kind", "alg", "algorithm", "transform", "encoding", "method",
             "fn", "function", "id")
STEP_LISTS = CHAIN_FIELDS + ("codec", "encoding", "alg", "algorithm")
TYPED_STEPS = "__huntress_typed_steps__"
TYPED_STAGE = "__huntress_typed_stage__"


def _step_name(x):
    """The name of one step: the text itself, or the name field of a step written as an object."""
    if isinstance(x, str):
        return x.strip().lower()[:40] or None
    if isinstance(x, dict):
        for f in STEP_NAME:
            if isinstance(x.get(f), str) and x[f].strip():
                return x[f].strip().lower()[:40]
    return None


def reshape(p):
    """(document, marks): normalize object-shaped codec steps without losing their ownership.

    {"codec": {"name": "xor", "key": 29}} becomes the legacy single codec "xor" beside key 29
    (mark `codec-object`), because one stage has no ownership ambiguity;
    {"pipeline": [{"op": "base64"}, {"op": "xor", "key": 29}]} becomes codec ["base64", "xor"]
    while retaining one ordered parameter record per stage (mark `steps-objects`). The legacy flat
    fields remain for readers that predate typed stages, but by_name() uses only the local record,
    explicitly global fields and explicit references while executing a typed chain. Any other document
    is returned as it is, with no mark. The marks go into the route, so a reshaped document is never the
    judged shape of its codec."""
    if not isinstance(p, dict):
        return p, ()
    if TYPED_STEPS in p:                 # reshape is intentionally idempotent across nested-document paths
        return p, ()
    marks, out = [], p
    codec = out.get("codec")
    if isinstance(codec, dict) and _step_name(codec):
        out = {k: v for k, v in out.items() if k != "codec"}
        named = next(f for f in STEP_NAME if isinstance(codec.get(f), str) and codec[f].strip())
        for k, v in codec.items():
            if k != named:
                out.setdefault(k, v)
        out["codec"] = _step_name(codec)
        # A lone codec object has no cross-stage ownership ambiguity.  Preserve its established
        # flattened route and judged label; ordered typed records are for multi-step object lists.
        marks.append("codec-object")
    if not out.get("codec") and not out.get("steps"):
        # the steps as a list of names under another field, and no codec field at all
        for field in CHAIN_FIELDS:
            v = out.get(field)
            if field not in ("steps", "chain") and isinstance(v, list) and 1 <= len(v) <= 8 and all(isinstance(x, str) and x.strip()
                                                                                  for x in v):
                out = {**{k: x for k, x in out.items() if k != field}, "steps": v}
                marks.append("steps=" + _slug(field, 24))
                break
    for field in STEP_LISTS:
        v = out.get(field)
        if not (isinstance(v, list) and 1 <= len(v) <= 8 and any(isinstance(x, dict) for x in v)):
            continue
        names = [_step_name(x) for x in v]
        if not all(names):
            continue
        records = [{"name": name,
                    "params": ({k: x for k, x in step.items()
                                if k != next(f for f in STEP_NAME
                                             if isinstance(step.get(f), str) and step[f].strip())}
                               if isinstance(step, dict) else {})}
                   for name, step in zip(names, v)]
        new = {k: x for k, x in out.items() if k != field}
        for i, step in enumerate(v):
            if not isinstance(step, dict):
                continue
            named = next(f for f in STEP_NAME if isinstance(step.get(f), str) and step[f].strip())
            for k, x in step.items():
                if k == named:
                    continue
                slot = k if k not in new else "%s_%d" % (k, i + 1)
                new.setdefault(slot, x)
        own = new.get("codec")
        if field == "codec" or not own or (isinstance(own, str) and own.strip().lower() in CHAIN):
            new["codec"] = names
            new[TYPED_STEPS] = records
            out = new
            marks.append("steps-objects")
        break
    return out, tuple(marks)


def typed_steps(p):
    """The ordered typed step records retained by reshape(), or ()."""
    rows = p.get(TYPED_STEPS) if isinstance(p, dict) else None
    if not (isinstance(rows, list) and 1 <= len(rows) <= 8):
        return ()
    out = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str) or not isinstance(row.get("params"), dict):
            return ()
        out.append(row)
    return tuple(out)


def chain_field(p):
    """The field a chain's steps were listed in, or None (see chain_steps)."""
    got = chain_steps(p) if isinstance(p, dict) else None
    return got[0] if got else None


def steps_of(p):
    """(steps, name): the codec as a list of step names, and the name the document gave it.

    The name may sit in `codec` or in a field a later schema could use instead. A name that
    is not known as a whole is split on the usual separators when every piece is known;
    otherwise it stays one unrecognised step."""
    codec = None
    listed = chain_steps(p)
    if listed:
        return listed[1], "+".join(listed[1])
    for field in ("codec", "steps", "chain", "encoding", "alg", "algorithm"):
        if p.get(field):
            codec = p[field]
            break
    if isinstance(codec, list):
        steps = [str(c).strip().lower()[:40] for c in codec[:8]]
        return steps, "+".join(steps)
    if not isinstance(codec, str):
        return [], ""
    name = codec.strip().lower()[:80]
    if not name:
        return [], ""
    # a chain joined with + | , > first: 'xor+railfence' is two steps, though 'xor.*' would read it as one
    toks = [t for t in re.split(r"\s*(?:\+|\||,|>|->|then)\s*", name) if t]
    if 1 < len(toks) <= 8 and all(_known(t) for t in toks) and any(ALIASES.get(t, t) in KEYED for t in toks):
        return toks, name
    if _known(name):
        return [name], name
    for sep in (r"\s*(?:\+|\||,|>|->|then|/|&)\s*", r"[-_\s.:]+"):
        toks = [t for t in re.split(sep, name) if t]
        if 1 < len(toks) <= 8 and all(_known(t) for t in toks):
            return toks, name
    return [name], name


def apply(name, d, layout, keys, ivs, clock, p=None):
    """_apply, and after its outputs the same step read in an alphabet the document gives (a field
    `alphabet` beside base64, base32, base58, base85): tagged, so it never takes the step's own name.
    Last, a step codec_more applies by the name the document wrote and no other (codec_more.OWN:
    json, pem, hexdump, lowercase, ...): for a name nothing above knows it is the whole reading."""
    outs = _apply(name, d, layout, keys, ivs, clock, p)
    if outs is not None and isinstance(p, dict) and ALIASES.get(name, name) in codec_more._STANDARD:
        outs = list(outs) + codec_more.also(SELF, ALIASES.get(name, name), d, p)
    mine = codec_more.own(SELF, name, d, p, clock)
    if mine is not None:
        outs = list(outs or ()) + mine
    return outs


def _apply(name, d, layout, keys, ivs, clock, p=None):
    """One named step on one state: [(output, tag)], or None for a name this module does not know.

    The tag is empty when the step was applied as named with what the document gives, and
    says what else was needed otherwise (a key from the prefix, a key from the APK). `p` is
    the document, for the steps that read their parameters from fields by name (KEYED)."""
    name = ALIASES.get(name, name)
    if name in KEYED:
        return KEYED[name](d, p if isinstance(p, dict) else {}, clock)
    if name in JOIN:
        return [(d, "")] if layout.startswith(("join", ARRANGED)) else []
    if name in WEAVE:
        return [(d, "")] if layout == "interleave" else []
    if name in PACKED:
        return [(o, "") for x in _layers(d) for o in [STEP[name](x)] if o]
    if name in STEP:
        o = STEP[name](d)
        return [(o, "")] if o else []
    if name in base.NAMED and name != "xor":
        try:
            o = base.NAMED[name](d, {})
        except Exception:
            o = None
        return [(o, "")] if o else []
    m = _ROTN.fullmatch(name)
    if m:
        # rot-47, rot-5 and rot-18 may mean the named rotations of their own alphabets: those
        # come first, then the letters shifted both ways. Only an exact answer code is kept.
        n, outs = int(m.group(2)), []
        if m.group(1) == "rot" and n in (5, 18, 47):
            o = STEP["rot%d" % n](d)
            outs += [(o, "")] if o else []
        return outs + [(base._caesar(d, -(n % 26)), ""), (base._caesar(d, n % 26), "")]
    # The keyed steps cost one pass over the state per key, in Python: each loop over the
    # keys ends at the deadline, so a document with many keys cannot run past the budget.
    layers = _layers(d)
    if name.startswith("xor"):
        return ([(base._xor(x, k), tag) for x in layers for k, tag in clock.each(keys)]
                + _rolling(layers, keys, p)
                + ([] if isinstance(p, dict) and p.get(TYPED_STAGE) else
                   [(o, tag) for x in layers for tag, o in keyless(x)]))
    if name in SHIFTS:
        outs = [(f(x, s * k[0]), tag) for x in layers for k, tag in clock.each(keys) if len(k) == 1
                for s in (1, -1) for f in (base._caesar, base._shift)]
        # a key of several bytes (a list of shifts) is each byte's own shift, tagged `bytes`
        # so it never takes the one-byte route's name; after it, the keyless readings
        multi = [(_sub256(x, k), ":".join(t for t in ("bytes", tag) if t))
                 for k, tag in clock.each(keys) if len(k) > 1 for x in layers]
        return outs + multi[:MAX_KEYED] + [(o, tag) for x in layers for tag, o in keyless(x)]
    if name == "vigenere":
        # the letter reading first, as before; then the other readings, and a repeating add
        # of 2 to 4 bytes proven by the ANS- prefix, for a key the document does not hold
        outs = [(o, tag) for k, tag in clock.each(keys) for o in [_vigenere(d, k)] if o]
        return (outs + polyalphabetic(d, keys, clock)
                + [(o, tag) for x in layers for tag, o in keyless(x) if re.fullmatch(r"prefix-add\d", tag)])
    if name == "beaufort":
        return polyalphabetic(d, keys, clock, beaufort=True)
    if name.startswith("aes") or name in ("rc4", "arc4", "cipher", "encrypted"):
        stated_alg = next((str(p.get(f)).lower() for f in ("algorithm", "alg", "cipher")
                           if isinstance(p, dict) and isinstance(p.get(f), str)), "")
        algs = (("aes",) if name.startswith("aes") or "aes" in stated_alg else
                ("rc4",) if name in ("rc4", "arc4") or stated_alg in ("rc4", "arc4") else ("rc4", "aes"))
        stated_mode = next((str(p.get(f)).lower().replace("aes-", "").replace("_", "-")
                            for f in ("mode", "cipher_mode", "block_mode")
                            if isinstance(p, dict) and isinstance(p.get(f), str)), "")
        if not stated_mode and name.startswith("aes-"):
            stated_mode = name[4:].lower().replace("_", "-")
        outs = []
        tagged = [x + t for t in gcm_tags(p) for x in (layers[1:] or layers)] if "aes" in algs else []
        for x in (layers[1:] or layers) + tagged:
            for label, o in block_ciphers(x, keys, ivs, clock, algs):
                if len(algs) == 1:  # the step's name already says the cipher: keep the mode and the key's origin
                    label = label[4:]
                if stated_mode and not (label == stated_mode or label.startswith(stated_mode + ":")
                                        or label.startswith(stated_mode + "-")):
                    continue
                # A typed stage that owns an IV/nonce cannot silently switch to an inferred zero or
                # ciphertext-prefixed IV merely because that alternate also produces answer-shaped bytes.
                if p.get(TYPED_STAGE) and ivs and ((stated_mode == "cbc" and label.startswith(("cbc-zero-iv", "cbc-iv-first")))
                                                   or (stated_mode == "gcm" and label.startswith("gcm-iv-first"))):
                    continue
                outs.append((o, label))
                if len(outs) >= 4000:
                    return outs
        return outs
    return None


def _rolling(layers, keys, p) -> list:
    """Day 19 look-ahead (item 5): xor with a key that moves by a stated step per byte, byte i XOR
    (key + step*i) & 255. Only when the document states the step (KEY_STEP, a non-zero integer of
    -255..255) and only for its one-byte keys (at most FIELD_KEYS); tagged `key-step=<field>`, so
    the route is never the judged xor's."""
    if not isinstance(p, dict):
        return []
    field = next((f for f in KEY_STEP if isinstance(p.get(f), int) and not isinstance(p.get(f), bool)
                  and p[f] and -255 <= p[f] <= 255), None)
    if field is None:
        return []
    step = p[field]
    one = [(k[0], tag) for k, tag in keys if len(k) == 1][:FIELD_KEYS]
    return [(bytes(c ^ ((k + step * i) & 255) for i, c in enumerate(x)),
             ":".join(t for t in ("key-step=" + _slug(field, 24), tag) if t))
            for x in layers for k, tag in one]


_EXPLICIT_GLOBALS = ("globals", "global", "global_params", "global_parameters", "shared_params",
                     "shared_parameters", "pipeline_globals")
_REF_FIELD = re.compile(r"(?:_field|_from|_ref|_source)$", re.I)


def _stage_context(p, record):
    """A typed step's parameters plus only explicitly global values and explicit references.

    A top-level ``key`` beside an object pipeline is not silently shared by every stage.  A value under
    ``globals``/``global_params`` is shared because the artifact said so.  A local ``key_ref: k2`` (or
    ``key: '$k2'``) also owns that reference, so the named top-level value is copied into this stage only.
    """
    shared = {}
    for field in _EXPLICIT_GLOBALS:
        value = p.get(field) if isinstance(p, dict) else None
        if isinstance(value, dict):
            shared.update(value)
    parameters = p.get("parameters") if isinstance(p, dict) else None
    if isinstance(parameters, dict) and str(parameters.get("scope", "")).lower() == "global":
        shared.update({k: v for k, v in parameters.items() if k != "scope"})
    local = dict(record.get("params") or {})
    nested = local.pop("params", None)
    if isinstance(nested, dict):
        local = {**nested, **local}
    stage = {**shared, **local, "codec": record["name"], TYPED_STAGE: True}
    if isinstance(p, dict):
        for field, value in list(local.items()):
            target = None
            if isinstance(value, str) and value[:1] in "$@":
                target = value[1:]
            elif _REF_FIELD.search(str(field)) and isinstance(value, str):
                target = value
            if target in p and target not in ("data", "codec", TYPED_STEPS):
                stage.setdefault(target, p[target])
                stem = _REF_FIELD.sub("", str(field))
                if stem in ("key", "iv", "nonce", "salt", "password", "passphrase"):
                    stage[stem] = p[target]
    return stage


def _typed_bytes(value):
    """Byte interpretations of one explicitly owned parameter, decoded forms before display text."""
    out = []
    if isinstance(value, str):
        text = value.strip()
        if len(text) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", text):
            try:
                out.append(bytes.fromhex(text))
            except ValueError:
                pass
    try:
        out += list(base._keys({"key": value}))
    except Exception:
        pass
    return list(dict.fromkeys(x for x in out if x))


_TYPED_KEY = re.compile(r"^(?:key\d*|keys|secret|password|passphrase|pass|seed|k)$", re.I)


def _stage_keys(p, clock):
    out = []
    for name, value in (p.items() if isinstance(p, dict) else ()):
        if _TYPED_KEY.match(str(name)):
            tag = "" if str(name).lower() in ("key", "keys") else "key=" + _slug(name, 24)
            out += [(x, tag) for x in _typed_bytes(value)]
    # KDF/wrapped-key inputs are also stage-owned; derive only from this stage context.
    if isinstance(p, dict) and any(_WRAPPED.match(str(k)) or _PASSWORD.match(str(k)) for k in p):
        out += derived_keys(p, clock)
    seen, uniq = set(), []
    for value, tag in out:
        if value not in seen:
            seen.add(value)
            uniq.append((value, tag))
    return uniq


def _ivs_of(p):
    out = []
    for name, value in flat(p):
        if re.search(r"(?:^|\.)(?:iv|nonce)\w*$", name, re.I):
            out += _typed_bytes(value)
    return list(dict.fromkeys(out))[:16]


def _typed_order(steps, p):
    rows = typed_steps(p)
    return rows if len(rows) == len(steps) and [r["name"] for r in rows] == list(steps) else ()


def by_name(steps, starts, keys, ivs, clock, p=None):
    """Apply the named steps, in the order given and reversed, to each layout of the data.

    Returns (value, tags, layout, others) for the first exact answer. `others` are up to
    MAX_OTHERS further (value, tags) pairs: exact answers with another value that other
    readings of the same step gave from the same states, best first (a keyed shift read
    over letters and over every character can both give a code), and, when the steps read
    in the order given give a code, the code the reversed order gives if it differs, tagged
    `order-reversed` (which order the document lists is not certain). A body without its prefix,
    and an answer inside wrapper text under a codec that only says "plain", are weaker
    readings: they are taken only when no layout gives an exact answer.

    That needs every layout to have been tried, so when the deadline passes first the
    result is None: a weaker reading must not stand in for an exact one that was not
    reached. The deadline is checked for every state, and apply() checks it for every key."""
    weak = None
    identity = all(ALIASES.get(s, s) in IDENTITY for s in steps)
    typed = _typed_order(steps, p)
    directions = [str(r["params"].get("direction", r["params"].get("operation", ""))).lower()
                  for r in typed]
    listed_only = bool(directions) and all(d in ("decode", "decrypt", "decryption", "unpack", "unwrap")
                                           for d in directions)
    reversed_only = bool(directions) and all(d in ("encode", "encrypt", "encryption", "pack", "wrap")
                                             for d in directions)
    choices = [(list(steps), typed)]
    reverse_choice = (list(reversed(steps)), tuple(reversed(typed)) if typed else ())
    if reversed_only:
        choices = [reverse_choice]
    elif not listed_only and reverse_choice != choices[0]:
        choices.append(reverse_choice)

    def run(order, records, start, layout):
        """The states after the steps in this order; UNKNOWN for a name this module does not
        know, None at the deadline. The deadline is checked for every state."""
        states = [(start, ())]
        for index, name in enumerate(order):
            if records:
                stage_p = _stage_context(p, records[index])
                stage_keys, stage_ivs = _stage_keys(stage_p, clock), _ivs_of(stage_p)
            else:
                stage_p, stage_keys, stage_ivs = p, keys, ivs
            nxt, seen = [], set()
            for st, tags in states:
                if clock.up():
                    return None
                outs = apply(name, st, layout, stage_keys, stage_ivs, clock, stage_p)
                if outs is None:
                    return UNKNOWN
                for o, tag in outs:
                    if o and o not in seen and len(o) <= MAX_STATE:
                        seen.add(o)
                        nxt.append((o, tags + ((tag,) if tag else ())))
                if len(nxt) >= FANOUT:
                    break  # only the first FANOUT are carried on: the rest need not be computed
            # as in the Day 4 solver, a step's output may still sit under a text encoding
            for o, tags in list(nxt):
                if len(nxt) >= FANOUT or clock.up():
                    break
                for y in base._text_layers(o)[1:]:
                    if y not in seen:
                        seen.add(y)
                        nxt.append((y, tags))
            states = nxt[:FANOUT]
        return states

    for layout, start in starts:
        for choice_index, (order, records) in enumerate(choices):
            states = run(order, records, start, layout)
            if states is None:
                return None
            if states is UNKNOWN:
                return weak  # an unrecognised name: nothing here was applied by name
            exact = [(a, tags) for st, tags in states for a in [strict(st)] if a]
            if exact:
                others, values = [], {exact[0][0]}
                for a, tags in exact[1:]:
                    if a not in values and len(others) < MAX_OTHERS:
                        values.add(a)
                        others.append((a, tags))
                if choice_index == 0 and len(choices) == 2 and len(others) < MAX_OTHERS and not clock.up():
                    # the steps also read in the other order: a different code is offered after the first
                    back = run(choices[1][0], choices[1][1], start, layout)
                    back = back if isinstance(back, list) else []
                    for a, tags in [(a, tags) for st, tags in back for a in [strict(st)] if a][:1]:
                        if a not in values:
                            others.append((a, tags + ("order-reversed",)))
                return exact[0][0], exact[0][1], layout, tuple(others)
            if clock.up():
                return None
            if weak is None:
                for st, tags in states:
                    a = body_only(st)
                    if a:
                        weak = (a, tags + ("prefix-added",), layout, ())
                        break
                    a = loose(st) if identity else None
                    if a:
                        weak = (a, tags + ("unwrapped",), layout, ())
                        break
    return None if clock.up() else weak


# ---------------------------------------------------------------------------- arrangements
#
# A document that lists pieces beside an order is an arrangement, whatever its codec and
# its fields are called. Day 5's judged document is one:
#
#   {"codec": "split", "data": "", "parts": ["<piece>", "<piece>", "<piece>"], "order": [2, 0, 1]}
#
# An order can be read two ways, and both are tried:
#
#   by    piece number order[i] is pieces[i]: the pieces sorted by their order number
#         (the reading the judge accepted on Day 5 as split:by-order)
#   take  piece number i is pieces[order[i]]
#
# A reading counts only when it gives exactly one answer code. Route names, under
# mobile.codec/<codec>: <codec>:by-<order field>, <codec>:take-<order field>, and
# <codec>:either-<order field> first when both give the same code (an order that is its
# own inverse says nothing about which reading the author meant), followed by one tag per
# difference from the judged shape, so only that shape carries the judged name.

def _order(v):
    """An order: 2 to MAX_PIECES different integers, as a list or written as text ('2,0,1'). Else None.

    The text is cut into tokens and never matched as a whole: a pattern over the whole
    text can be made to backtrack without end, and no deadline check interrupts a regex.
    A list of digit strings (['3', '10', ...], Day 18 look-ahead) is an order only when its
    numbers are 0 to n-1 or 1 to n: pieces of a code can be digits too."""
    if isinstance(v, str) and len(v) <= 400 and v.strip()[:1].isdigit():
        toks = _INT_SEP.split(v.strip())
        if 2 <= len(toks) <= MAX_PIECES and all(len(t) <= 4 and t.isascii() and t.isdigit() for t in toks):
            v = [int(t) for t in toks]
    elif (isinstance(v, list) and 2 <= len(v) <= MAX_PIECES
          and all(isinstance(x, str) and 1 <= len(x) <= 3 and x.isascii() and x.isdigit() for x in v)):
        ns = [int(x) for x in v]
        v = ns if sorted(ns) in (list(range(len(ns))), list(range(1, len(ns) + 1))) else None
    if (isinstance(v, list) and 2 <= len(v) <= MAX_PIECES
            and all(isinstance(x, int) and not isinstance(x, bool) for x in v) and len(set(v)) == len(v)):
        return v
    return None


def _numbered(v):
    """A list of {integer, string} objects as (order, pieces, name of the integer field), or None.

    None too when each integer is the length of its string: that is a length, not a place."""
    if not (isinstance(v, list) and 2 <= len(v) <= MAX_PIECES and all(isinstance(x, dict) for x in v)):
        return None
    order, pieces, names = [], [], set()
    for obj in v:
        nums = [(k, x) for k, x in obj.items() if isinstance(x, int) and not isinstance(x, bool)]
        texts = [x for x in obj.values() if isinstance(x, str) and x]
        if len(nums) != 1 or len(texts) != 1:
            return None
        names.add(nums[0][0])
        order.append(nums[0][1])
        pieces.append(texts[0])
    if len(names) != 1 or len(set(order)) != len(order) or order == [len(x) for x in pieces]:
        return None
    return order, pieces, names.pop()


def _int(v):
    """An integer, not a boolean."""
    return isinstance(v, int) and not isinstance(v, bool)


def _paired(v):
    """Pieces that carry their own places (rows 342 and 343): (order, pieces, place name, cut), or None.

    [[place, piece], ...] (cut 'pairs'), [[piece, place], ...] ('pairs-char-first') and
    {"place": piece, ...} ('map'), with _numbered's guards: 2 to MAX_PIECES items, every place
    a different integer, every piece a text that is not empty, the places not the pieces' lengths."""
    if isinstance(v, dict) and 2 <= len(v) <= MAX_PIECES and all(
            isinstance(k, str) and 1 <= len(k) <= 3 and k.isascii() and k.isdigit() and isinstance(x, str) and x
            for k, x in v.items()):
        order, pieces, name, cut = [int(k) for k in v], list(v.values()), "key", "map"
    elif isinstance(v, list) and 2 <= len(v) <= MAX_PIECES and all(isinstance(x, list) and len(x) == 2 for x in v):
        if all(_int(x[0]) and isinstance(x[1], str) and x[1] for x in v):
            order, pieces, name, cut = [x[0] for x in v], [x[1] for x in v], "pos", "pairs"
        elif all(isinstance(x[0], str) and x[0] and _int(x[1]) for x in v):
            order, pieces, name, cut = [x[1] for x in v], [x[0] for x in v], "pos", "pairs-char-first"
        else:
            return None
    else:
        return None
    if len(set(order)) != len(order) or order == [len(x) for x in pieces]:
        return None
    return order, pieces, name, cut


# An order the document states as a formula (Day 18 look-ahead; Day 17's own order was (3 + 7i)
# mod 20): position i of `data` goes to (start + step * i) mod n, read by and take as any order.
FORMULA_STEP = ("step", "stride", "multiplier", "mult", "a", "k", "skip", "jump")
FORMULA_START = ("offset", "start", "increment", "b", "shift")
FORMULA = "formula-"     # the start of such an order's name in the route: formula-<step field>[+<start field>]


def _small_int(v):
    """An integer of at most three digits, as a number or written as text ('7', '-3'); else None."""
    if _int(v) and -999 <= v <= 999:
        return v
    if isinstance(v, str) and 1 <= len(v) <= 6 and re.fullmatch(r"\s*-?\d{1,3}\s*", v):
        return int(v)
    return None


def by_shape(p) -> bool:
    """Does no step of the document's codec name one this module applies by name? Then its fields
    may state an order as a formula, or a table its `data` indexes (Day 18 look-ahead). Under a name
    that is applied (affine's a and b, caesar's k) those fields are that codec's parameters."""
    return not any(_known(ALIASES.get(s, s)) for s in steps_of(p)[0])


def formulas(p) -> list:
    """[(order name, order)] for each order the document states as a formula over the characters of `data`.

    A step from FORMULA_STEP (an integer, or digits written as text) that is prime to n, the
    length of `data`, and a start from FORMULA_START (0 when there is none): at most two of each.
    Only for a codec name this module does not apply (by_shape)."""
    d = p.get("data")
    if not (isinstance(d, str) and 2 <= len(d) <= MAX_PIECES) or not by_shape(p):
        return []
    n = len(d)
    steps = [(f, s) for f in FORMULA_STEP for s in [_small_int(p.get(f))] if s is not None and math.gcd(s % n, n) == 1]
    starts = [(f, o) for f in FORMULA_START for o in [_small_int(p.get(f))] if o is not None] or [("", 0)]
    return [(FORMULA + sf + ("+" + of if of else ""), [(o + s * i) % n for i in range(n)])
            for sf, s in steps[:2] for of, o in starts[:2]]


# A grid read the codec names (Day 18 look-ahead): `data` is the code written row by row into a grid
# and read out another way. Each pattern gives the place in the code of each character of `data`.
def _spiral(rows, cols, clockwise=True):
    grid = [[r * cols + c for c in range(cols)] for r in range(rows)]
    out, top, bot, left, right = [], 0, rows - 1, 0, cols - 1
    while top <= bot and left <= right:
        if clockwise:
            out += [grid[top][c] for c in range(left, right + 1)] + [grid[r][right] for r in range(top + 1, bot + 1)]
            out += [grid[bot][c] for c in range(right - 1, left - 1, -1)] if top < bot else []
            out += [grid[r][left] for r in range(bot - 1, top, -1)] if left < right else []
        else:
            out += [grid[r][left] for r in range(top, bot + 1)] + [grid[bot][c] for c in range(left + 1, right + 1)]
            out += [grid[r][right] for r in range(bot - 1, top - 1, -1)] if left < right else []
            out += [grid[top][c] for c in range(right - 1, left, -1)] if top < bot else []
        top, bot, left, right = top + 1, bot - 1, left + 1, right - 1
    return out


GRID_PATTERNS = {
    "spiral-cw": lambda r, c: _spiral(r, c),
    "spiral-ccw": lambda r, c: _spiral(r, c, clockwise=False),
    "snake-cols": lambda r, c: [i * c + j for j in range(c) for i in (range(r) if j % 2 == 0 else range(r - 1, -1, -1))],
    "snake-rows": lambda r, c: [i * c + j for i in range(r) for j in (range(c) if i % 2 == 0 else range(c - 1, -1, -1))],
    "transpose": lambda r, c: [i * c + j for j in range(c) for i in range(r)],
}
# By the codec's name only: a grid read is never searched for (a short list keeps two moves from
# giving two different exact codes, as positional() does).
GRID_NAMES = {"spiral": ("spiral-cw", "spiral-ccw"), "snake": ("snake-cols", "snake-rows"),
              "boustrophedon": ("snake-rows", "snake-cols"), "transpose": ("transpose",),
              "faro": ("faro-out",), "riffle": ("faro-out",), "deinterleave": ("deinterleave",)}
GRID_ROWS = ("rows", "height")
GRID_COLS = ("cols", "columns", "width")
GRID_STREAMS = ("streams", "ways", "k")
GRID = "grid-"           # the start of a grid read's name in the route: grid-<pattern>[-<k> when searched]


def grids(p) -> list:
    """[(order name, order)] for the grid reads the document's codec names, over the characters of `data`.

    The grid is rows x cols from GRID_ROWS and GRID_COLS (either one is enough). A grid the
    document does not state is not searched: a spiral or a row snake keeps the code's ANS- in
    front on every grid of four or more columns, and each grid would offer another code. faro is
    one perfect out-shuffle; deinterleave takes every k-th character first, k from GRID_STREAMS
    or 2 to 5 (named in the route). The order is the place of each character of `data` in the
    code, so `by` decodes."""
    d, steps = p.get("data"), steps_of(p)[0]
    names = GRID_NAMES.get(ALIASES.get(steps[0], steps[0])) if len(steps) == 1 else None
    if not (names and isinstance(d, str) and 4 <= len(d) <= MAX_PIECES):
        return []
    n, out = len(d), []
    rows = [v for f in GRID_ROWS for v in [_small_int(p.get(f))] if v and 1 < v < n and n % v == 0]
    cols = [v for f in GRID_COLS for v in [_small_int(p.get(f))] if v and 1 < v < n and n % v == 0]
    shapes = list(dict.fromkeys([(r, n // r) for r in rows] + [(n // c, c) for c in cols]))[:2]
    for name in names:
        if name in GRID_PATTERNS:
            out += [(GRID + name, GRID_PATTERNS[name](r, c)) for r, c in shapes]
        elif name == "faro-out" and n % 2 == 0:
            out.append((GRID + name, [j for i in range(n // 2) for j in (i, n // 2 + i)]))
        elif name == "deinterleave":
            ks = [v for f in GRID_STREAMS for v in [_small_int(p.get(f))] if v and 1 < v < n]
            out += [(GRID + name + ("" if ks else "-%d" % k), [i for r in range(k) for i in range(r, n, k)])
                    for k in (ks[:1] or range(2, 6))]
    return out


# A seeded shuffle (Day 18 look-ahead): the places of `data` come from a pseudo-random generator under a
# seed the document states. Python's random.Random(seed).shuffle and java.util.Collections.shuffle with
# new java.util.Random(seed) (the port below was checked against the JDK's own output); not Kotlin's
# Random(seed), whose port no runtime here could check.
SEED_FIELDS = ("seed", "rng_seed", "random_seed", "shuffle_seed")
RNG_FIELDS = ("rng", "prng", "generator", "random")
SEEDED = "seeded-"       # the start of such an order's name in the route: seeded-<generator>[-<seed field>]


def _java_shuffle(n, seed):
    """Collections.shuffle(list of 0..n-1, new java.util.Random(seed)): its 48-bit LCG and nextInt(bound)."""
    state, lst = (seed ^ 0x5DEECE66D) & ((1 << 48) - 1), list(range(n))

    def next31():
        nonlocal state
        state = (state * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        return state >> 17

    for i in range(n, 1, -1):
        if i & -i == i:
            j = (i * next31()) >> 31
        else:
            while True:
                bits = next31()
                j = bits % i
                if bits - j + (i - 1) < (1 << 31):   # Java's int overflow test: retry
                    break
        lst[i - 1], lst[j] = lst[j], lst[i - 1]
    return lst


def seeded(p) -> list:
    """[(order name, order)] for the seeded shuffles of the characters of `data` (SEED_FIELDS, an integer).
    Only for a codec name this module does not apply (by_shape)."""
    d = p.get("data")
    seeds = [(f, v if _int(v) else int(v)) for f in SEED_FIELDS for v in [p.get(f)]
             if _int(v) or (isinstance(v, str) and re.fullmatch(r"-?\d{1,19}", v))]
    seeds = [(f, s) for f, s in seeds if abs(s) < 1 << 63]
    if not (seeds and isinstance(d, str) and 2 <= len(d) <= MAX_PIECES) or not by_shape(p):
        return []
    import random   # here, so the module's import does not pay for it
    n, out = len(d), []
    for f, seed in seeds:
        tail = "" if f == "seed" else "-" + f
        py = list(range(n))
        random.Random(seed).shuffle(py)
        out += [(SEEDED + "python" + tail, py), (SEEDED + "java" + tail, _java_shuffle(n, seed))]
    return out[:4]


def _derived_fields(p, oname) -> set:
    """The fields of the document an order it states another way (a formula, a grid, a seed) was read from."""
    if oname.startswith(FORMULA):
        return set(oname[len(FORMULA):].split("+"))
    if oname.startswith(GRID):
        return {f for f in GRID_ROWS + GRID_COLS + GRID_STREAMS + ("direction",) if f in p}
    if oname.startswith(SEEDED):
        return {f for f in SEED_FIELDS + RNG_FIELDS if f in p}
    return set()


def _order_name(oname) -> str:
    """An order's name as the route carries it: a field's name at most 24 characters, a stated one's at most 48."""
    return _slug(oname, 48 if oname.startswith((FORMULA, GRID, SEEDED)) else 24)


def arrangements(p, clock):
    """Every way the document lists pieces beside an order: [(order field, order, pieces field, pieces, cut)].

    The pieces are a list of strings as long as the order (cut ''), a list of {integer,
    string} objects, which is its own order ('objects'), or one string as long as the
    order ('chars') or a multiple of it ('chunks', cut evenly). An order is any top-level
    field but `data` that _order() reads. Integers that are the lengths of the pieces they
    stand beside are their lengths, and no order. Only the top level of the document is
    read, up to MAX_SOURCES arrangements and until the deadline.

    Day 18 look-ahead, after every order listed: pieces that carry their places, as pairs or a map
    (_paired, in any top-level field, `data` too), then an order the document states another way
    over the characters of `data`: a formula (formulas, named formula-<fields>), a grid read its
    codec names (grids, grid-<pattern>) or a seeded shuffle (seeded, seeded-<generator>)."""
    out = [(got[2], got[0], k, got[1], "objects") for k, v in clock.each(p.items()) for got in [_numbered(v)] if got]
    orders = [(k, o) for k, v in clock.each(p.items()) if k not in ("schema", "codec", "data")
              for o in [_order(v)] if o]
    for oname, order in orders[:4]:
        n = len(order)
        for k, v in clock.each(p.items()):
            if len(out) >= MAX_SOURCES:
                return out[:MAX_SOURCES]
            if k == oname or k.lower() in META:
                continue
            if isinstance(v, list) and len(v) == n and all(isinstance(x, str) for x in v) and any(v):
                if order != [len(x) for x in v]:
                    out.append((oname, order, k, v, ""))
            elif (isinstance(v, list) and n < len(v) <= MAX_PIECES and all(isinstance(x, str) and x for x in v)
                  and all(0 <= x < len(v) for x in order)):
                # more pieces than the order names (Day 14 look-ahead): the order picks its pieces
                out.append((oname, order, k, v, SUBSET))
            elif isinstance(v, str) and v and len(v) % n == 0 and len(v) <= MAX_STATE:
                size = len(v) // n
                out.append((oname, order, k, [v[i:i + size] for i in range(0, len(v), size)],
                            "chars" if size == 1 else "chunks"))
    # after every order listed, so a pairs or map field beside a judged shape (a decoy) comes behind its reading
    out += [(got[2], got[0], k, got[1], got[3]) for k, v in clock.each(p.items()) for got in [_paired(v)] if got]
    out += [(oname, order, "data", list(p["data"]), "chars") for oname, order in formulas(p) + grids(p) + seeded(p)]
    return out[:MAX_SOURCES]


def _shape(p, oname, pname, pieces, order, cut):
    """How one arrangement differs from the judged Day 5 document, as route tags: none for that shape."""
    tags = []
    if pname != PIECES:
        tags.append("@" + _slug(pname, 24))
    if cut:
        tags.append(cut)
    if not all(pieces):
        tags.append("empty-piece")
    if pname != "data" and p.get("data") not in (None, ""):
        tags.append("data-present")
    if sorted(order) != list(range(len(order))):
        tags.append("order-keys")
    # the fields the order was read from: none of its own for pieces that carry their places
    derived = _derived_fields(p, oname)
    used = derived or (set() if cut in PAIRED else {oname})
    if (any(isinstance(p.get(f), str) and re.fullmatch(r"\s*-?\d{1,19}\s*", p[f]) for f in derived) if derived
            else isinstance(p.get(oname), str)):
        tags.append("order-text")
    elif isinstance(p.get(oname), list) and p[oname] and all(isinstance(x, str) for x in p[oname]):
        tags.append("order-strings")       # a list of digit strings (Day 18 look-ahead)
    if _order_name(oname) != oname:
        tags.append("order-renamed")
    if set(p) - {"schema", "day", "codec", "data", pname} - used:
        tags.append("extra-fields")
    return tuple(tags)


def numbers_in(p) -> bool:
    """Does the document carry a number of its own, at any depth?

    Not the header's (`day`, `version`), not a key's, not a `data` list of byte values. Such
    a number may say how the pieces are ordered in a way arrangements() does not read (an
    order one level down, two numbers in each piece's object, a list of one-number lists),
    and the string fields joined as listed ignore it."""
    for n, v in flat(p):
        if n.split(".")[0].lower() in META or _KEYISH.search(n) or (n == "data" and isinstance(v, list)):
            continue
        if isinstance(v, (int, float, list)) and not isinstance(v, bool):
            return True
    return False


def _stands(source) -> bool:
    """Is this one string cut and put back as it was? Under an ascending order both readings are the string."""
    _, order, _, _, cut = source
    return cut not in LISTED and order == sorted(order)


def _lay(items, perm, reading):
    """The pieces in answer order: 'by' puts items[i] at place perm[i], 'take' reads items[perm[i]] at place i."""
    if reading == "take":
        return "".join(items[j] for j in perm)
    out = [""] * len(items)
    for place, item in zip(perm, items):
        out[place] = item
    return "".join(out)


def _each_decoded(pieces, names, keys, ivs, clock, p=None):
    """Every piece decoded by the named steps by itself: the texts, or None unless each piece gives exactly one."""
    if any(len(piece) > MAX_PIECE for piece in pieces):
        return None
    texts = []
    for piece in pieces:
        states = [piece.encode("utf-8", "surrogatepass")]
        for name in names:
            if clock.up():
                return None
            states = [o for st in states for o, _ in (apply(name, st, "data", keys, ivs, clock, p) or []) if o][:4]
        found = {st.decode("ascii") for st in states if st.isascii()}
        if len(found) != 1:
            return None
        texts.append(found.pop())
    return texts


def arranged(p, sources, steps, keys, ivs, clock):
    """The readings of a document's arrangements that give an answer code: [(reading, order field, tags, value)].

    A reading is the code as it stands, or, under a chain that names further steps
    (split+base64, split+xor), the arranged text put through by_name ('then'), or each
    piece decoded by those steps before it is placed ('pieces-decoded'). Only exact answer
    codes are kept: a body without its prefix or an answer inside other text is no reading."""
    found = []
    rest = [s for s in steps if ALIASES.get(s, s) not in JOIN]
    for oname, order, pname, pieces, cut in sources:
        rank = {x: i for i, x in enumerate(sorted(order))}   # ranked: 1-based or sparse keys are the same order
        perm = [rank[x] for x in order]
        # one string cut and put back as it was is the string: by_name reads that as it stands
        same = cut not in LISTED and perm == sorted(perm)
        shape = _shape(p, oname, pname, pieces, order, cut)
        for reading in ("by", "take"):
            if clock.up():
                return found
            if cut == SUBSET:
                # `take`: the pieces the order names, in its order. `by`: the first pieces, placed.
                text = "".join(pieces[j] for j in order) if reading == "take" else _lay(pieces[:len(order)], perm, "by")
            else:
                text = _lay(pieces, perm, reading)
            value, tags = (text, ()) if base.ANSWER.fullmatch(text) else (None, ())
            if not value and steps and not same and len(text) <= MAX_STATE:
                got = by_name(steps, [(ARRANGED, text.encode("utf-8", "surrogatepass"))], keys, ivs, clock, p)
                if got and not any(t in ("prefix-added", "unwrapped") for t in got[1]):
                    value, tags = got[0], ("then",) + tuple(dict.fromkeys(got[1]))
            if not value and rest and cut in LISTED:
                for names in ([rest] if rest == rest[::-1] else [rest[::-1], rest]):
                    texts = _each_decoded(pieces, names, keys, ivs, clock, p)
                    text = _lay(texts, perm, reading) if texts else ""
                    if base.ANSWER.fullmatch(text):
                        value, tags = text, ("pieces-decoded",)
                        break
            if not value and not rest and cut in LISTED:
                # every piece under the same text encoding, though the document names none (Day 14 look-ahead)
                for layer in ("base64", "hex", "base32"):
                    texts = _each_decoded(pieces, [layer], keys, ivs, clock, p)
                    text = _lay(texts, perm, reading) if texts else ""
                    if base.ANSWER.fullmatch(text):
                        value, tags = text, ("pieces-" + layer,)
                        break
            if value:
                found.append((reading, oname, shape + tags, value))
    return found


# Day 19 look-ahead (item 6): Day 17's `indexed` named as one step of a chain (`indexed+xor`, `xor>indexed`).
# The order is applied where a state is as long as it, after the other steps that come before it, in either
# order of the listed steps, both readings (by, take). Only an exact code counts, and two different codes give none.
ARRANGE_STEPS = ("indexed", "index", "scatter", "scattered", "permute", "permuted", "permutation", "shuffle",
                 "shuffled", "reorder", "reordered", "arrange", "arranged")


def _states(names, start, keys, ivs, clock, p):
    """The states after the named steps, as by_name computes them (FANOUT at most, text layers too)."""
    states = [(start, ())]
    for name in names:
        nxt, seen = [], set()
        for st, tags in states:
            if clock.up():
                return []
            outs = apply(name, st, "data", keys, ivs, clock, p)
            if outs is None:
                return []
            for o, tag in outs:
                if o and o not in seen and len(o) <= MAX_STATE:
                    seen.add(o)
                    nxt.append((o, tags + ((tag,) if tag else ())))
            if len(nxt) >= FANOUT:
                break
        for o, tags in list(nxt):
            if len(nxt) >= FANOUT:
                break
            for y in base._text_layers(o)[1:]:
                if y not in seen:
                    seen.add(y)
                    nxt.append((y, tags))
        states = nxt[:FANOUT]
    return states


def indexed_chain(p, keys, ivs, clock):
    """(codec, [(name, value)]) for a document whose codec chains one ARRANGE_STEPS step with known steps,
    or None. Each reading that gives an exact code is an option (`<codec>:<by|take|either>-<order>:at-<k>`,
    the order applied after k of the other steps); two different codes give None, as for any arrangement
    whose readings disagree."""
    codec = p.get("codec")
    if not isinstance(codec, str) or len(codec) > 80:
        return None
    toks = [t for t in re.split(r"\s*(?:\+|\||,|>|->|then)\s*", codec.strip().lower()) if t]
    at = [i for i, t in enumerate(toks) if t in ARRANGE_STEPS]
    if not 2 <= len(toks) <= 6 or len(at) != 1:
        return None
    rest = [t for i, t in enumerate(toks) if i != at[0]]
    if not all(_known(ALIASES.get(t, t)) or _known(t) for t in rest):
        return None
    data = p.get("data")
    if not isinstance(data, str) or not data or len(data) > MAX_STATE:
        return None
    orders = [(k, o) for k, v in p.items() if k not in ("schema", "codec", "data") for o in [_order(v)] if o][:2]
    found = {}
    start = data.encode("utf-8", "surrogatepass")
    for oname, order in orders:
        n = len(order)
        rank = {x: i for i, x in enumerate(sorted(order))}
        perm = [rank[x] for x in order]
        for names in ([rest] if rest == rest[::-1] else [rest, rest[::-1]]):
            for k in range(len(names) + 1):
                pre, post = names[:k], names[k:]
                for st, _ in (_states(pre, start, keys, ivs, clock, p) if pre else [(start, ())]):
                    if len(st) != n or clock.up():
                        continue
                    items = list(st.decode("latin-1"))
                    for reading in ("by", "take"):
                        text = _lay(items, perm, reading).encode("latin-1")
                        if post:
                            got = by_name(post, [(ARRANGED, text)], keys, ivs, clock, p)
                            value = got[0] if got and not _WEAKER.intersection(got[1]) else None
                        else:
                            value = strict(text)
                        if value and base.ANSWER.fullmatch(value):
                            found.setdefault((_order_name(oname), k), {}).setdefault(reading, value)
    if not found or len({v for got in found.values() for v in got.values()}) != 1:
        return None
    name = _slug(codec) or "unnamed"
    options = []
    for (oname, k), got in found.items():
        if len(got) == 2:
            options.append(("%s:either-%s:at-%d" % (name, oname, k), got["by"]))
        else:
            options += [("%s:%s-%s:at-%d" % (name, r, oname, k), v) for r, v in got.items()]
    return name, options


# A lookup (Day 18 look-ahead): `data` holds indices into a table the document states, a string
# or a list of strings, and the code is the table's items at those indices, in data's order.
LOOKUP_TABLES = ("table", "alphabet", "charset", "pool", "symbols", "dictionary", "strings", "lut")
MAX_TABLE = 256          # characters, or items, of a table that is read


def lookups(p) -> list:
    """[(table field, tags, value)] for each table of LOOKUP_TABLES that `data`'s indices turn into an answer code.

    `data` is a list of 2 to MAX_PIECES integers, or the same written as text ('17,16,3':
    tag `indices-text`); an index may repeat (a code repeats its digits) and must fall inside
    the table. Indices start at 0. Only for a codec name this module does not apply (by_shape),
    and only an exact answer code counts."""
    d = p.get("data")
    tags = ()
    if isinstance(d, str) and len(d) <= 400 and d.strip()[:1].isdigit():
        toks = _INT_SEP.split(d.strip())
        if not (2 <= len(toks) <= MAX_PIECES and all(len(t) <= 3 and t.isascii() and t.isdigit() for t in toks)):
            return []
        d, tags = [int(t) for t in toks], ("indices-text",)
    if not (isinstance(d, list) and 2 <= len(d) <= MAX_PIECES and all(_int(x) and x >= 0 for x in d)) or not by_shape(p):
        return []
    out = []
    for f in LOOKUP_TABLES:
        t = p.get(f)
        if isinstance(t, list) and not all(isinstance(x, str) for x in t):
            continue
        if not (isinstance(t, (str, list)) and 2 <= len(t) <= MAX_TABLE) or max(d) >= len(t):
            continue
        value = "".join(t[i] for i in d)
        if base.ANSWER.fullmatch(value):
            out.append((f, tags, value))
    return out


# Day 20 build (the Day 19 look-ahead's B05): a list of branches, each with a condition and its own `data`.
# Only fields that name WHEN a branch applies (review of build20/mobile: `variant`, `case`, `state`, `profile` and
# `mode` also hold labels that only mark a place, '1' and '2', 'a' and 'b', and a name the judge accepted for such
# a label would answer a variant whose real code moved plain and wrong).
WHEN_FIELDS = ("when", "if", "condition", "cond", "env", "environment", "build", "build_type")
# Read as whole words of the condition (review of build20/mobile-fix1: substrings read `token` as ok, `realm` as real
# and `!debug`, `not_rooted`, `nondebug` as hostile). A first word is matched whole; a last word as the start of a
# word (rooted, debuggable, emulator, tampered). A negation anywhere ranks the condition 1 (nothing is read from it).
WHEN_FIRST = frozenset(("release", "prod", "production", "clean", "normal", "default", "genuine", "signed",
                        "untampered", "real", "store", "valid", "ok", "true", "safe", "trusted", "verified", "play"))
WHEN_LAST = ("debug", "root", "emulat", "tamper", "test", "devel", "hook", "frida", "xposed", "magisk", "decoy", "fake",
             "honeypot", "false", "invalid", "unsigned", "resign", "sideload", "jailbr", "instrument")
WHEN_LAST_WORDS = frozenset(("dev",))
WHEN_NOT = frozenset(("not", "no", "non", "never", "without", "dont", "isnt"))
MAX_BRANCHES = 8


def _when_words(text) -> list:
    """The lower-case words of a condition: split on anything not a letter and between camelCase humps."""
    return [w.lower() for w in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", text)]


def _when_word(w) -> int:
    """0 for a normal-state word, 2 for a hostile one, None for neither."""
    if w in WHEN_FIRST:
        return 0
    if w in WHEN_LAST_WORDS or w.startswith(WHEN_LAST):
        return 2
    return None


def _when_rank(text) -> int:
    """0 for a condition a person reads as the app's normal state (release, clean), 2 for a hostile one (debug,
    rooted, emulator, tampered), 1 for anything else, a condition that says both, or one with a negation in it
    (`!debug`, `not_rooted`, `nondebug`, `unrooted`; `unsigned` and `untampered` are words of their own)."""
    words = _when_words(text)
    if "!" in text or not words:
        return 1
    ranks = set()
    for w in words:
        r = _when_word(w)
        if r is None and (w in WHEN_NOT or any(w.startswith(n) and _when_word(w[len(n):]) is not None
                                               for n in ("non", "not", "un", "no"))):
            return 1
        if r is not None:
            ranks.add(r)
    return 0 if ranks == {0} else 2 if ranks == {2} else 1


WHEN_TEXT_HEADERS = frozenset(("schema", "codec", "alg", "algorithm", "encoding"))
WHEN_NUMBER_HEADERS = frozenset(("day", "version", "v"))
WHEN_STEP_HEADERS = frozenset(("steps", "chain"))
_WHEN_KEY_NAME = re.compile(r"(?:[a-z0-9]+_)?(?:key|iv|nonce|salt|secret|pass|password|passphrase|seed)", re.I)


def when_header_ok(k, v) -> bool:
    """fix3: True only for a top-level field beside a branch list that the codec itself needs and that cannot
    choose a branch: a text header of the codec, a day or version, the step list, an empty `data`, a key field
    under a plain key name (`key`, `iv`, `aes_key`; never `key_index`) with a text value. Every hint, note and
    description, and every other field of any type, is False."""
    low = k.lower()
    if low in WHEN_TEXT_HEADERS:
        return isinstance(v, str)
    if low in WHEN_NUMBER_HEADERS:
        return isinstance(v, (str, int)) and not isinstance(v, bool)
    if low in WHEN_STEP_HEADERS:
        return isinstance(v, str) or (isinstance(v, list) and all(isinstance(x, str) for x in v))
    if low == "data":
        return v == ""
    return bool(_WHEN_KEY_NAME.fullmatch(k)) and isinstance(v, str)


WHEN_BRANCHES = True   # Day 20 gaps build: back on, under a key that carries the document's own fingerprint
WHEN_FP = 64             # full SHA-256 of the document in every artifact-scoped candidate key


def when_fingerprint(p) -> str:
    """Day 20 gaps build (item 6 back on): WHEN_FP hex digits of the SHA-256 of the whole puzzle document as
    canonical JSON (sorted keys, no blanks). The branch list's candidate key carries it, so a name the judge
    accepts answers PLAIN only this very document, whose branches and every header it was judged with are
    the same bytes; any other document (a variant whose header, flag, key or data differs in any way, the
    four reviews' position-choosing headers among them) has another key and stays unsure. The cost: every
    variant's branch list is probed on its own (one or two probes on an untimed base or a regular attempt;
    inside a deadline a candidate pick is not probed, row 346)."""
    try:
        text = json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    except (TypeError, ValueError):
        text = repr(p)
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:WHEN_FP]


def when_side_ok(k, v) -> bool:
    """Day 20 gaps build: a top-level field beside a branch list that the per-document key makes harmless (it
    can only change the ORDER of the candidates, never make one plain on another document): every field
    when_header_ok takes, and any other scalar (text, number, boolean, null) that is no selector and no
    condition field (a `use` or a top-level `env` beside the list is still None: what it chooses is read by
    no reader here). A top-level `data` must still be empty, and a list or object beside the branch list is
    None (two lists: which is the branch list?)."""
    if when_header_ok(k, v):
        return True
    low = k.lower()
    if low == "data" or low in SELECTORS or low in WHEN_FIELDS or isinstance(v, (list, dict)):
        return False
    return v is None or isinstance(v, (str, int, float, bool))


def when_branches(p, steps, keys, ivs, clock, suffix=""):
    """A Hit offering every branch's code as a candidate pick (row 346), or None.

    One top-level list of 2 to MAX_BRANCHES objects, each with a `data` text of at most MAX_PIECE
    characters and ONE condition field, the same field in every item (WHEN_FIELDS), whose text is
    different in every item, and nothing else in the item; every other top-level field one the codec
    itself needs (when_header_ok: no hint, note or description at all, an empty `data`, a key field
    under a plain key name; fix3), and no other top-level text holding a word of a condition or the
    list's name (a field, flag, selector, position or hint that chooses a branch makes the name depend
    on more than the condition); each item's `data` gives exactly one exact answer code by the document's
    named steps (by_name, its keys), and the codes are not all the same. Every condition must be one
    _when_rank reads as the app's normal state or as a hostile one (rank 0 or 2), with at least one of
    each: a label that only marks a place ('1', '2', 'a', 'b', 'beta') says nothing about which branch
    is meant, and contested()'s rule (the position never decides) stands for it. The options are
    named `<codec>:<field>=<condition>`, the hypothesis, never the value, under a key that carries the
    field and the document's fingerprint (`<codec>+branches_<field>@doc-<fp>#candidates`, when_fingerprint;
    Day 20 gaps build), so the name the judge accepts answers plain only the very document it was judged on,
    and every other variant stays a candidate pick (four reviews found headers that choose a branch by
    position; with the fingerprint none of them can turn an accepted name into a wrong plain answer, so the
    fields beside the list are when_side_ok's, any scalar but a selector or a condition field, and a header
    that names a condition only moves the order); the release-like conditions first, the hostile ones last,
    the document's order between. Anything else is None, and the caller's low Hit
    stands. Bounded by MAX_BRANCHES reads of a short text; the caller asks only while its clock is
    not up (a cut gives the low Hit, never another answer)."""
    lists = [(k, v) for k, v in p.items() if isinstance(v, list) and k.lower() not in META
             and 2 <= len(v) <= MAX_BRANCHES and all(isinstance(x, dict) for x in v)]
    if len(lists) != 1:
        return None
    lname, items = lists[0]
    # Nothing else in the document may say which branch is active (review of build20/mobile-fix1: a top-level
    # `env`, `build_type`, `current` or `use: branches.1.data`, or an item's `active: true`, chooses one, and a
    # name accepted for one condition would then answer a variant whose document chooses the other plain and
    # wrong). So every other top-level field is a header (META), `data` or a key field, and each item holds its
    # condition and `data` and nothing else.
    # fix3 (review of build20/mobile-fix2): a header may choose a branch by its POSITION ('the first entry is live',
    # 'use item 2', hint: 2, hint: {"use": "branches.1.data"}, key_index: 1), and no word list catches every way
    # of saying so. So the document holds the list and the fields the codec itself needs and NOTHING else: no
    # hint, note or description of any type, a top-level `data` only when it is empty, a key field only under a
    # plain key name with a text value, the codec's own headers only as text (day and version as a number too).
    for k, v in p.items():
        if k == lname:
            continue
        if not isinstance(k, str) or not when_side_ok(k, v):
            return None
    rows, cfield = [], None
    for item in items:
        conds = [f for f in WHEN_FIELDS if isinstance(item.get(f), str) and 0 < len(item[f].strip()) <= 40]
        d = item.get("data")
        if len(conds) != 1 or (cfield is not None and conds[0] != cfield) or set(item) != {conds[0], "data"}:
            return None
        cfield = conds[0]
        if not isinstance(d, str) or not 0 < len(d) <= MAX_PIECE:
            return None
        if _when_rank(item[cfield]) == 1:
            return None
        try:
            got = by_name(steps, [("data", d.encode("utf-8", "surrogatepass"))], keys, ivs, clock, p)
        except Ambiguous:
            return None
        if not got or _WEAKER.intersection(got[1]) or not base.ANSWER.fullmatch(got[0]):
            return None
        if any(v != got[0] and not _WEAKER.intersection(t) for v, t in got[3]):
            return None     # one branch read two ways: nothing says which
        rows.append((item[cfield].strip(), got[0]))
    if len({_slug(c, 64) for c, _ in rows}) != len(rows) or len({v for _, v in rows}) < 2:
        return None
    if {_when_rank(c) for c, _ in rows} != {0, 2}:
        return None
    # ... and no header text or other top-level text names a condition or the list (a hint `use the debug branch`,
    # `configs[1]`): a word of a condition, or the list's name, in any other top-level text is a choice.
    # Day 20 gaps build: a header that names a condition no longer gives None. The key carries the document's
    # fingerprint (when_fingerprint), so such a header can only move the order of the options on this document.
    codec, renamed = _codec(steps)
    ranked = sorted(range(len(rows)), key=lambda i: (_when_rank(rows[i][0]), i))
    options = [("%s:%s=%s%s%s" % (codec, cfield, _slug(rows[i][0], 64), renamed, suffix), rows[i][1]) for i in ranked]
    # The key carries the full canonical-document SHA-256.  Ledger keys are
    # local metadata, not wire answers, so shortening this identity only
    # creates a cross-artifact promotion risk without buying wire space.
    key = "%s+branches_%s@doc-%s" % (_slug(codec, 24), cfield, when_fingerprint(p))
    return Hit(options[0][1], "high", options[0][0], key + labels.CANDIDATE_MARK, (), tuple(options[1:]))


def _codec(steps):
    """(name, mark): the steps' label-key name, and ':renamed' when that is not the document's own text."""
    joined = "+".join(steps)
    codec = _slug(joined) or "unnamed"
    return codec, ":renamed" if steps and codec != joined else ""


def arranged_hit(found, steps, suffix):
    """One Hit for the readings arranged() found: the first is its route, the others its further options."""
    codec, renamed = _codec(steps)
    groups = {}
    for reading, oname, tags, value in found:
        groups.setdefault((oname, tags), {}).setdefault(reading, value)
    options = []
    for (oname, tags), got in groups.items():
        tail = _order_name(oname) + "".join(":" + t for t in tags) + renamed + suffix
        if len(got) == 2 and got["by"] == got["take"]:
            options.append(("%s:either-%s" % (codec, tail), got["by"]))
        options += [("%s:%s-%s" % (codec, reading, tail), got[reading]) for reading in ("by", "take") if reading in got]
    weak = any("key-apk" in t or t.startswith("prefix-") for t in found[0][2])
    return Hit(options[0][1], "medium" if weak else "high", options[0][0], codec, (), tuple(options[1:]))


# Position moves: `data` is the 20 characters of an answer code in another order, and no
# order list says which. Validated by the exact answer shape, like everything else.
_MOVED = re.compile(r"[0-9A-FNS-]{20}")


def positional(p, name):
    """[(move, value)] for the position moves that turn a 20-character `data` into an answer code.

    A rotation (N, S and - occur once in a code, so at most one fits), chunks of 2, 4, 5 or
    10 reversed inside or in their order, two halves woven. Several can fit with different
    values (blocks reversed, and the rotation that brings ANS- to the front), so each is an
    option, the moves the codec's name speaks of first; none is ever a plain answer until
    the judge has accepted its name."""
    d = p.get("data")
    if not (isinstance(d, str) and _MOVED.fullmatch(d)) or base.ANSWER.fullmatch(d):
        return []
    if any(d.count(c) != 1 for c in "NS-") or "A" not in d:
        return []
    cands = [("rotate", d[r:] + d[:r]) for r in range(1, 20)]
    for size in (2, 4, 5, 10):
        chunks = [d[i:i + size] for i in range(0, 20, size)]
        cands.append(("chunks%d-reversed" % size, "".join(c[::-1] for c in chunks)))
        cands.append(("blocks%d-reversed" % size, "".join(chunks[::-1])))
    cands.append(("weave", "".join(x + y for x, y in zip(d[:10], d[10:]))))
    cands.append(("weave-odd-first", "".join(y + x for x, y in zip(d[:10], d[10:]))))
    seen, out = set(), []
    for move, value in cands:
        if base.ANSWER.fullmatch(value) and value not in seen:
            seen.add(value)
            out.append((move, value))
    words = [w[:5] for w in re.split(r"[^a-z]+", name) if len(w) >= 5]
    return sorted(out, key=lambda mv: -sum(w in mv[0] for w in words))


SHIFT_MOVES = ("add", "sub", "caesar")   # the search's one-byte shift moves: at most one of them in a path


def search(start, keys, ivs, clock, far=(), max_depth=6, max_nodes=8000, block=True):
    """Breadth-first search over the reversible transforms, for a codec that was not applied by name.

    `keys` (from the document) are moves. `far` keys (from the dex and manifest) are only
    tried as the last step on a node. Returns (hit, body, done): hit is (value, path) for
    the first exact answer; body is the first state that was an answer without its prefix,
    which the caller may use only when nothing exact exists; done says the search ran dry
    rather than out of time. Raises Ambiguous when a state holds two different
    answer-shaped strings: some later move would always single one of them out. `block`
    False leaves RC4 and AES out (field_codes: a search bounded by states, never by a clock)."""
    moves = [(n, lambda d, f=f: f(d, {})) for n, f in (
        ("base64", base.t_base64), ("hex", base.t_hex), ("base32", base.t_base32), ("rot13", base.t_rot13),
        ("reverse", base.t_reverse))]
    moves += [(n, f) for n, f in STEP.items() if n not in BLIND + NAME_ONLY]
    moves += [("xor" + (":" + tag if tag else ""), lambda d, k=k: base._xor(d, k)) for k, tag in keys[:24]]
    for k, tag in keys:
        if len(k) == 1:
            moves += [("add", lambda d, k=k: base._shift(d, -k[0])), ("sub", lambda d, k=k: base._shift(d, k[0])),
                      ("caesar", lambda d, k=k: base._caesar(d, -k[0])),
                      ("caesar", lambda d, k=k: base._caesar(d, k[0]))]
    seen, queue, nodes, ciphers, body = {start}, deque([(start, ())]), 0, 0, None
    while queue and nodes < max_nodes:
        if clock.up():
            return None, body, False
        cur, path = queue.popleft()
        nodes += 1
        a = strict(cur)
        if a:
            return (a, path), body, True
        for tag, out in keyless(cur):
            a = strict(out)
            if a:
                return (a, path + (tag,)), body, True
        binary = not cur.isascii()
        if far and binary and len(cur) == 20:
            for k, tag in far:
                a = strict(base._xor(cur, k))
                if a:
                    return (a, path + ("xor:" + tag,)), body, True
        found = answers_in(cur)
        if len(found) > 1:
            raise Ambiguous(">".join(path) or "no transform")
        if found:
            return (found.pop(), path + ("unwrapped",)), body, True
        if body is None:
            a = body_only(cur)
            if a:
                body = (a, path + ("prefix-added",))
        if block and (keys or far) and ciphers < 4 and binary and 16 <= len(cur) <= 96 and len(set(cur)) > 12:
            ciphers += 1
            for label, out in block_ciphers(cur, list(keys) + list(far), ivs, clock):
                a = strict(out) or loose(out)
                if a:
                    return (a, path + (label,)), body, True
        if len(path) >= max_depth:
            continue
        # A keyed move is made once in a path: one one-byte shift of any key (add, sub and caesar together)
        # and each xor move name once (`xor` for every top-level key, `xor:<tag>` for a key read more widely).
        # Two of them nearly undo each other around the moves between (xor:key=day>sub>xor:key=day),
        # and the prefix-proven readings then turn the near-identity into a made-up code (Day 18
        # look-ahead, with row 342's strict uu: the search reaches that deep once uu stops crowding it).
        shifted = any(t in SHIFT_MOVES for t in path)
        for label, mv in moves:
            if clock.up():  # one node has a move per key: the deadline cannot wait for the next node
                return None, body, False
            if (shifted and label in SHIFT_MOVES) or (label.startswith("xor") and label in path):
                continue
            try:
                out = mv(cur)
            except Exception:
                out = None
            if out and out not in seen and len(out) <= MAX_STATE:
                seen.add(out)
                queue.append((out, path + (label,)))
    return None, body, not queue


def docs_in(obj, nested=False):
    """Every object in the JSON that looks like a puzzle document: (document, is it nested)."""
    if isinstance(obj, dict):
        if any(k in obj for k in ("codec", "data", "steps", "encoding", "algorithm", "alg")):
            yield obj, nested
        for v in obj.values():
            yield from docs_in(v, True)
    elif isinstance(obj, list):
        for v in obj:
            yield from docs_in(v, True)


KEYSTORE_NAMES = ("keystore", "key_store", "key-store", "androidkeystore", "android_keystore", "jks", "jceks", "bks",
                  "pkcs12", "p12", "pfx")
# Day 15 (row 309): a codec that says the answer is the one code stored in the APK's native libraries
# (lib/*/*.so), not in the document's own `data`. solve_doc returns None for such a document and
# native_hit reads the libraries (apk_resources.native_secret). Every spelling answers under the one
# key mobile.codec/native (route native:so-secret), so the promoted seed carries to every variant.
NATIVE_NAMES = ("native", "native_library", "native-library", "nativelibrary", "jni", "ndk",
                "native_secret", "native-secret",
                # Day 16 look-ahead (row 312): native-library synonyms an author may reach for when
                # the theme deepens. Each only routes into native_hit, which fails closed (no code,
                # or two that differ: None), so widening the name never forces an answer.
                "so", "so_secret", "so-secret", "shared_object", "shared-object", "sharedobject",
                "native_obfuscated", "native-obfuscated", "libsecret")
CODE_DOC_SEARCH = 20     # characters a text of a document found in the app's code must have to be searched


def _nonlinear_table_hit(p, where, suffix):
    """B-249 (Day 30 audit M3): a quadratic (stated or crib-recovered) or stated piecewise offset table, read by
    codec_more.quadratic_offset_shape / piecewise_offset_shape behind the exact ANS fullmatch of all 20 bytes. Offered
    as a candidate under a document-fingerprint key of its own (decide() calls labels.candidates: always unsure until
    that exact key is judged), never under the judged `table` or `linear-offset` names. Two shapes that read two
    different codes prove nothing: None."""
    got = []
    for shape in (codec_more.quadratic_offset_shape, codec_more.piecewise_offset_shape):
        try:
            r = shape(p)
        except Exception:
            r = None
        if r is not None:
            got.append(r)
    if not got or len({value for value, _route in got}) != 1:
        return None
    value, route = got[0]
    family = route.split(":", 1)[0]
    fingerprint = when_fingerprint({"document": p, "where": where})
    return Hit(value, "medium", route + suffix, family + "@doc-" + fingerprint + labels.CANDIDATE_MARK, (), ())


def solve_doc(p, where, apk_keys, clock, named_only=False, min_search=0):
    """One puzzle document: a Hit, or None when nothing in it decodes to an answer.

    `where` is empty for the usual document (the whole of assets/huntress_puzzle.json) and
    names the difference otherwise. `apk_keys` is a function that returns the key material
    of the dex and manifest; it is only called when the document's own keys did not do.
    `named_only` ends after what the document names was applied (steps 1 to 3): that is how
    the candidates behind a hit that is held are read (solve_members)."""
    suffix = ":" + where if where else ""
    # 1. The Day 4 solver's named path. On the usual document this is the judged route.
    #    It is asked only for a document that names a codec (with none, by_codec returns
    #    answer-shaped data as it stands, which is case 4 below: a candidate, not an
    #    answer) and only when the work is small: by_codec checks no deadline, and a chain
    #    of keyed steps over many keys multiplies its states without bound.
    steps = base_steps(p)
    keyed_schedule = None
    if (p.get("schema") == "huntress.mobile.puzzle.v1" and len(steps) == 1 and not _known(steps[0])
            and steps[0] not in ("packet", "table")):
        keyed_schedule = codec_more.keyed_schedule_shape(p)
    if steps == ["packet"]:
        # Day 28 ("Protocol Reconstruction"): this is a named, length-delimited frame, not a
        # license to search arbitrary hex for an embedded answer. Keep the route spelling the
        # judge accepted when the generic search first discovered the format; the key remains
        # mobile.codec/packet. A malformed frame is a LOW hit so the own document fails closed
        # instead of falling through to that generic search under an already accepted name.
        value = codec_more.packet_frame(p)
        if value is not None:
            return Hit(value, "high", "search:hex>unwrapped" + suffix, "packet", ())
        return Hit("", "low", "codec 'packet' is not one complete HA/length/payload/trailer frame" + suffix,
                   "packet", ())
    if steps == ["table"]:
        # Day 29 ("White-Box Key Recovery"): data[i] = code[i] + key + step*i (mod 256), the step
        # recovered from the ANS- prefix. Judged on Day 29's base as `table:sub-key-step` under
        # mobile.codec/table (the morning's live fix). A document that does not read exactly is a
        # LOW hit, so it fails closed rather than searching under the accepted name.
        value = codec_more.table_offsets(p)
        if value is not None:
            return Hit(value, "high", "table:sub-key-step" + suffix, "table", ())
        # B-249: the escalations of the same table (a quadratic schedule, a stated piecewise one) under the judged
        # name: offered unsure under a document-fingerprint candidate key, never the judged `table` key.
        shaped = _nonlinear_table_hit(p, where, suffix)
        if shaped is not None:
            return shaped
        return Hit("", "low", "codec 'table' is not key plus a per-position step over the ANS- prefix" + suffix,
                   "table", ())
    if steps == ["layered"]:
        # Day 30 ("Layered Protections"): raw = base64(data); code = reverse(raw[j] XOR (key + j)), the roll seeded by
        # the document's integer key. The generic search found it as `search:base64>reverse>prefix-roll-xor` (k0 from
        # the ANS- prefix, k0 XOR i), which the judge accepted under mobile.codec/layered on the base; the two
        # readings coincide there. Applied by name, no search: the accepted spelling only when the judged route
        # reads the same code, otherwise a name of its own (unsure until judged). A document the reader does not
        # establish goes on to the usual path exactly as before (the name `layered` is also an opaque chain word).
        got = codec_more.layered_rolling(p)
        if got is not None:
            value, judged = got
            if judged:
                return Hit(value, "high", "search:base64>reverse>prefix-roll-xor" + suffix, "layered", ())
            return Hit(value, "medium", "layered:base64>reverse>xor-key-roll" + suffix, "layered", ())
    if steps and all(s_ in KEYSTORE_NAMES for s_ in steps):
        # Day 14 look-ahead: the document says the answer is in a keystore. Nothing in its own fields
        # is decoded or searched: solve_members reads the store (keystores.py) with the password the
        # document states, and that needs the APK's time.
        return None
    if steps and all(s_ in NATIVE_NAMES for s_ in steps):
        # Day 15 (row 309): the document says the answer is in a native library (lib/*/*.so). Nothing
        # in its own fields is decoded (its `data` only repeats the code in clear, which step 4 below
        # would read as an unproven candidate and stop the base): solve_members reads the library
        # (native_hit -> apk_resources.native_secret) and cross-checks the document's `data`.
        return None
    value = None
    # Object pipelines retain stage ownership below.  The legacy by_codec path receives one shared
    # key pool, so running it first would undo that proof and could let a coincidental key combination win.
    if steps and not typed_steps(p) and base_cost(p, steps) <= BASE_COST:
        try:
            value = base.by_codec(p)
        except Exception:
            value = None
    if value:
        name = "+".join(steps)
        if keyed_schedule is not None and keyed_schedule[0] != value:
            return Hit(keyed_schedule[0], "medium", keyed_schedule[1] + suffix, name, ())
        return Hit(value, "high", name + suffix, name, () if where else tuple(steps))

    steps, name = steps_of(p)
    field = chain_field(p)
    listed_in = ("steps=" + _slug(field, 24),) if field else ()  # the route says where the steps were listed
    starts = data_candidates(p)
    keys = key_candidates(p)
    if steps and any(_OTHER.fullmatch(ALIASES.get(s_, s_)) or ALIASES.get(s_, s_) in ("des3", "chacha20", "blowfish") for s_ in steps):
        keys = keys + [k for k in derived_keys(p, clock) if k[0] not in {x for x, _ in keys}]
    ivs = []
    for n, v in flat(p):
        if re.search(r"iv|nonce", n, re.I):
            try:
                ivs += base._keys({"k": v})
            except Exception:
                pass
    usual = "join" if any(s in JOIN for s in steps) else "interleave" if any(s in WEAVE for s in steps) else "data"

    def named(got, extra=()):
        value, tags, layout, others = got
        hit = route(value, tags, layout, extra)
        # another value from the same step is a further option, under its own route name;
        # pick() answers plain only the name the judge accepted, wherever it stands
        options, names = [], {hit.route}
        for v, t in others:
            r = route(v, t, layout, extra).route
            if r not in names:
                names.add(r)
                options.append((r, v))
        return hit._replace(options=tuple(options))

    def route(value, tags, layout, extra):
        tags = list(dict.fromkeys(tags)) + list(extra)
        if layout != usual:
            tags.insert(0, "@" + _slug(layout.split(":", 1)[-1], 24))
        if not tags and all(s in base.NAMED for s in steps):
            # The Day 4 solver knows every step and did not get here itself, so this is
            # not the route the judge has seen, whatever the name says.
            tags.append("wide")
        weak = any("key-apk" in t or t.startswith(("prefix-", "unwrapped")) for t in tags)
        codec = _slug("+".join(steps))  # a step such as 'xor-<anything>' still carries the document's text
        if codec != "+".join(steps):
            # 'xor!' is applied as xor and slugs to 'xor': without a mark its route would be
            # the judged codec's own name, and the seed would answer it plain.
            tags.append("renamed")
        return Hit(value, "medium" if weak else "high", codec + "".join(":" + t for t in tags) + suffix, codec, ())

    def contested(got, keys):
        """A low Hit when the code came from one item of a list and another item gives a
        different code by the same steps; else None.

        by_name stops at the first field that gives a code. A field with a name of its own
        is in the route by that name (`@payload`), so the judge accepts or rejects that
        field. Among `candidates.0.data` and `candidates.1.data` (or `candidates.1.value`)
        only the position says which is meant, and that must never decide an answer, also
        not once the judge has accepted the route's name on a look-alike. Every text of the
        other items is read, also those data_candidates left out as too many, and an item
        that was not read in the time counts as one that disagrees. A weaker reading (a body
        without its prefix, a code inside other text) disagrees only with a weaker one."""
        value, tags, layout, _ = got
        path = layout[6:].split(".") if layout.startswith("field:") else []
        if not any(part.isdigit() for part in path):
            return None
        weak = bool(_WEAKER.intersection(tags))

        def beside(field) -> bool:   # in another item of a list the hit is in: the paths part at a list index
            for a, b in zip(field.split("."), path):
                if a != b:
                    return a.isdigit() and b.isdigit()
            return False

        for field, text in flat(p):
            if not (isinstance(text, str) and text and len(text) <= MAX_STATE and beside(field)) or _KEYISH.search(field):
                continue
            more = None if clock.up() else by_name(steps, [("field:" + field, text.encode("utf-8", "surrogatepass"))],
                                                   keys, ivs, clock, p)
            if clock.up():
                return Hit(value, "low", "codec %r gives %s from %s, and the other items of its list were not all read"
                           % (name, value, layout), name, ())
            if more and more[0] != value and (weak or not _WEAKER.intersection(more[1])):
                return Hit(value, "low", "codec %r gives two different codes, and only their order says which is "
                           "meant: %s from %s, %s from %s" % (name, value, layout, more[0], more[2]), name, ())
        return None

    # 2. An arrangement: pieces listed beside an order, read both ways. When no reading
    #    gives a code the document was not understood, and its string fields joined as
    #    listed (which ignores the order) are not offered in its place; nor are they for
    #    any other document that carries a number of its own, which may be an order that
    #    was not read. One string that an ascending order leaves as it stands is no
    #    reading of a new codec (the codec the document names is tried first, in step 3):
    #    it counts only under a name the judge has accepted, for the variant of a judged
    #    chunk order whose order happens to be ascending.
    sources = arrangements(p, clock)
    listed = any(cut in LISTED for *_, cut in sources)
    laid = listed or any(layout.startswith(("join", "interleave")) for layout, _ in starts)
    if sources:
        found = arranged(p, [s for s in sources if not _stands(s)], steps, keys, ivs, clock)
        if found:
            return arranged_hit(found, steps, suffix)
        found = arranged(p, [s for s in sources if _stands(s)], steps, keys, ivs, clock)
        if found and _accepted(arranged_hit(found, steps, suffix)):
            return arranged_hit(found, steps, suffix)
        if clock.up():
            return None
    #    A lookup (Day 18 look-ahead): `data` holds indices into a table the document states. Each
    #    table that gives a code is an option of its own, `<codec>:lookup@<table field>`.
    looked = lookups(p)
    if looked:
        codec, renamed = _codec(steps)
        options = [("%s:lookup@%s%s%s%s" % (codec, _slug(f, 24), "".join(":" + t for t in tags), renamed, suffix), value)
                   for f, tags, value in looked]
        return Hit(options[0][1], "high", options[0][0], codec, (), tuple(options[1:]))
    #    Day 17's `indexed` as one step of a chain (Day 19 look-ahead, item 6): unsure under the chain's name.
    chained = indexed_chain(p, keys, ivs, clock)
    if chained:
        codec, options = chained
        options = [(n_ + suffix, v) for n_, v in options]
        return Hit(options[0][1], "high", options[0][0], codec, (), tuple(options[1:]))
    every = starts
    if listed or numbers_in(p):
        starts = [(layout, start) for layout, start in starts if not layout.startswith(("join", "interleave"))]

    # 3. The codec the document names, applied more widely.
    if steps:
        got = by_name(steps, starts, keys, ivs, clock, p)
        if got:
            held = contested(got, keys)
            if held is not None and not clock.up():
                # Day 20 build (the Day 19 look-ahead's B05): the list's items each say WHEN they apply
                # ({when: debuggable, data}, {when: release, data}). Nothing proves which branch the judge
                # wants, so this is a candidate pick (row 346), each branch named by its condition, never plain
                # before the judge has accepted one condition's name.
                # Withdrawn before arming (2026-10-19 night): four review rounds each found a header that
                # picks a branch by position and turns an accepted condition name into a wrong plain answer
                # on a later variant. Day 20 gaps build: back on, under a key that carries the document's own
                # fingerprint (when_fingerprint), so an accepted name is plain only for this very document.
                if WHEN_BRANCHES:
                    held = when_branches(p, steps, keys, ivs, clock, suffix) or held
            usual_hit = held or named(got, listed_in)
            if keyed_schedule is not None and keyed_schedule[0] != usual_hit.value:
                return Hit(keyed_schedule[0], "medium", keyed_schedule[1] + suffix,
                           _slug("+".join(steps)), ())
            return usual_hit
        if typed_steps(p):
            # The artifact supplied a complete typed sequence.  Falling through to the generic key/search
            # pools would discard its ownership and could make a top-level decoy key stand in for a missing
            # stage parameter.  Preserve the failure as low evidence; never invent a different pipeline.
            return Hit("", "low", "the typed stage sequence did not produce one exact answer" + suffix,
                       _slug("+".join(steps)), ())
    wrapped = _layered_wrapper_hit(p, suffix)
    if wrapped is not None:
        if keyed_schedule is not None and keyed_schedule[0] != wrapped.value:
            return Hit(keyed_schedule[0], "medium", keyed_schedule[1] + suffix,
                       _slug("+".join(steps)), ())
        return wrapped
    # Day 29 hardening (backlog row 568): a renamed white-box table is still recoverable from
    # artifact structure, but it must never borrow the judge-accepted `mobile.codec/table` name.
    # Ask only after the document's own named reader failed, and only for one genuinely unknown
    # codec name.  linear_offset_shape() insists on 20 exact hex bytes, a JSON integer key, one
    # unique constant step over every byte of the ANS- crib, and a complete upper-case answer.
    # The canonical-document fingerprint scopes the hypothesis to this artifact shape, while the
    # candidate mark makes decide() call labels.candidates: absent a verdict for this exact key the
    # result is always unsure, never a plain answer or a family-prior promotion.
    if len(steps) == 1 and not _known(steps[0]):
        value = codec_more.linear_offset_shape(p)
        if value is not None:
            if keyed_schedule is not None and keyed_schedule[0] != value:
                return Hit(keyed_schedule[0], "medium", keyed_schedule[1] + suffix,
                           _slug("+".join(steps)), ())
            fingerprint = when_fingerprint({"document": p, "where": where})
            candidate_key = "linear-offset@doc-" + fingerprint + labels.CANDIDATE_MARK
            return Hit(value, "medium", "linear-offset:sub-key-step" + suffix,
                       candidate_key, (), ())
        shaped = _nonlinear_table_hit(p, where, suffix)
        if shaped is not None:
            if keyed_schedule is not None and keyed_schedule[0] != shaped.value:
                return Hit(keyed_schedule[0], "medium", keyed_schedule[1] + suffix,
                           _slug("+".join(steps)), ())
            return shaped
    if named_only:
        return None

    # 4. Answer-shaped text under a codec that was not applied: the transform may work
    #    inside the answer's own alphabet, so this is a candidate for a person, not an answer.
    for layout, start in starts:
        found = answers_in(start)
        if found:
            return Hit(strict(start) or sorted(found)[0], "low",
                       "%d answer-shaped string(s) in %s under codec %r, %s"
                       % (len(found), layout, name, NOT_APPLIED), name, ())

    # 5. `data` is a code's 20 characters in another order, and a position move puts them
    #    back. A medium route, like a search hit: each move that fits is an option.
    moved = positional(p, name)
    if moved:
        codec, renamed = _codec(steps)
        options = [("%s:%s%s%s" % (codec, move, renamed, suffix), value) for move, value in moved]
        return Hit(options[0][1], "medium", options[0][0], codec, (), tuple(options[1:]))
    #    The same when the moved characters sit under one text encoding (base64, hex, base32):
    #    the layer is named in the route after the move.
    d = p.get("data")
    if isinstance(d, str) and 20 < len(d) <= 64:
        for layer, dec in (("base64", base.t_base64), ("hex", base.t_hex), ("base32", base.t_base32)):
            under = dec(d, {})
            if under and len(under) == 20 and under.isascii():
                moved = positional({"data": under.decode("ascii")}, name)
                if moved:
                    codec, renamed = _codec(steps)
                    options = [("%s:%s@%s%s%s" % (codec, move, layer, renamed, suffix), value) for move, value in moved]
                    return Hit(options[0][1], "medium", options[0][0], codec, (), tuple(options[1:]))

    def searched(clock, far=(), weak=True, **caps):
        """The search over every layout that is left: a Hit, or None. `weak` allows a body without its prefix."""
        body, dry = None, True
        for layout, start in starts:
            if len(start) < min_search and not ANS_BODY.fullmatch(start.strip().upper()):
                continue    # a label of a record in the app's code (CONTROL = "keystore_wrapper"), not a payload;
                            # sixteen hex digits are a code's body and are searched at any length (review, 2026-10-13)
            try:
                hit, b, done = search(start, keys, ivs, clock, far, **caps)
            except Ambiguous as e:
                return Hit("", "low", "two different answer-shaped strings in %s after %s" % (layout, e), name, ())
            tail = "" if layout == "data" else "@" + _slug(layout.split(":", 1)[-1], 24)
            if hit:
                route = "search:" + ">".join(hit[1]) + tail + suffix
                return Hit(hit[0], "medium", route, name or route, ())
            if b and body is None:
                body = (b, tail)
            dry = dry and done
            if clock.up():
                return None
        if weak and body and dry:  # only when every search ran dry: no exact answer exists to prefer
            route = "search:" + ">".join(body[0][1]) + body[1] + suffix
            return Hit(body[0][0], "medium", route, name or route, ())
        return None

    # 6. A codec that lays pieces out, with the pieces there, and no code by name: every
    #    move of the search decodes and none reorders, so the budget is not spent on it.
    #    Beside an order that is None at once. With no order the pieces as joined may still
    #    sit under one more transform, which a short search finds in a few milliseconds.
    layouts = [s for s in steps if ALIASES.get(s, s) in JOIN + WEAVE]
    if laid and layouts and (listed or len(layouts) == len(steps)):
        hit = None if listed else searched(Clock(min(QUICK, clock.left())), weak=False, max_depth=2,
                                           max_nodes=QUICK_NODES)
        return hit or Hit("", "low", "codec %r lays out pieces, and no reading of them is an answer code" % name,
                          name, ())
    # A join that step 2 set aside and that is answer-shaped as listed: a candidate, as in step 4.
    for layout, start in every:
        found = answers_in(start) if (layout, start) not in starts else None
        if found:
            return Hit(strict(start) or sorted(found)[0], "low",
                       "%d answer-shaped string(s) in %s under codec %r, beside a number that may order the pieces"
                       % (len(found), layout, name), name, ())

    # 7. The named codec again, with key material from the dex and manifest.
    far = [(k, "key-apk") for k in apk_keys()] if steps or starts else []
    known = {k for k, _ in keys}
    far = [(k, tag) for k, tag in far if k not in known]
    if steps and far:
        APK_KEYS["keys"] = [k for k, _ in far]   # for the steps of codec_more.py that read their own keys
        # an IV may stand in the package beside the key (Day 14 look-ahead): the first few of its length
        far_ivs = [k for k, _ in far if len(k) in (12, 16) and k not in ivs][:6]
        try:
            got = by_name(steps, starts, keys + far, ivs, clock, p)
            if not got and far_ivs and not clock.up():   # as before first; the package's IVs only when that gave nothing
                got = by_name(steps, starts, keys + far, ivs + far_ivs, clock, p)
            hit = (contested(got, keys + far) or named(got, listed_in)) if got else None
        finally:
            APK_KEYS.clear()
        if hit:
            return hit

    # 8. Search. An exact answer through at least one transform is a medium route. Its name
    #    starts with 'search:', so it can never be the name of a codec applied by name: a
    #    search that ends after the one move 'reverse', in a document that names no codec,
    #    is not the judged codec `reverse`, and the seed must not answer it plain.
    search_hit = searched(clock, far)
    if keyed_schedule is not None and (search_hit is None or keyed_schedule[0] != search_hit.value):
        return Hit(keyed_schedule[0], "medium", keyed_schedule[1] + suffix,
                   _slug("+".join(steps)), ())
    return search_hit


# ---------------------------------------------------------------------------- the APK

def dex_strings(d):
    try:
        n, off = struct.unpack_from("<II", d, 0x38)
        out = []
        for i in range(min(n, 20000)):
            o = struct.unpack_from("<I", d, off + 4 * i)[0]
            while d[o] & 0x80:
                o += 1
            o += 1
            out.append(d[o:d.index(b"\0", o)])
        return out
    except Exception:
        return []


def axml_strings(d):
    try:
        hs = struct.unpack_from("<H", d, 10)[0]
        cnt, _, flags, sstart = struct.unpack_from("<IIII", d, 16)
        out = []
        for i in range(min(cnt, 20000)):
            o = struct.unpack_from("<I", d, 8 + hs + 4 * i)[0] + 8 + sstart
            if flags & 0x100:
                o += 2 if d[o] & 0x80 else 1
                n = d[o]
                o += 1
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | d[o]
                    o += 1
                out.append(d[o:o + n])
            else:
                n = struct.unpack_from("<H", d, o)[0]
                out.append(d[o + 2:o + 2 + 2 * n].decode("utf-16le", "replace").encode())
        return out
    except Exception:
        return []


_FRAMEWORK = re.compile(rb"^(L[\w/$]+;|\[?[VZBSCIJFDL]+|<init>|<clinit>|[a-z][A-Za-z]+)$")


SMALL_TEXT = 4096        # bytes of a text member whose lines are read as strings
_KEYNAME = re.compile(r"key|secret|salt|nonce|seed|passw|token|(^|[_.\-])iv($|[_.\-])", re.I)
_SIGNING = re.compile(r"META-INF/[^/]+\.(RSA|DSA|EC|SF|MF)$", re.I)


def _is_text(body) -> bool:
    return bool(body) and len(body) <= SMALL_TEXT and b"\0" not in body and all(c >= 32 or c in b"\t\r\n" for c in body)


def package_strings(members, deadline=None) -> list:
    """[(kind, string)] for every string of the package a person would read, the dex and the manifest
    first (as app_strings always read them), then what an app can also carry them in:

      resources  resources.arsc's value pool (strings.xml compiled)
      res-xml    any other compiled XML (res/xml/network_security_config.xml)
      lib        printable runs of a native library (lib/<abi>/*.so)
      text       the lines of a small text member (assets, res/raw, META-INF other than the signature)

    Bounded by the readers; a member that is none of these gives nothing. The code containers'
    strings (app_bundles.py) are read until `deadline`: solve_members reads the list once per APK
    and hands it on, because reading 8 MiB members three times was most of a miss's time."""
    first, rest = [], []
    for n, body in members.items():
        if n.endswith(".dex"):
            first += [("dex", s) for s in dex_strings(body)]
        elif n == "AndroidManifest.xml":
            first += [("manifest", s) for s in axml_strings(body)]
        elif apk_resources.is_arsc(body):
            rest += [("resources", s.encode("utf-8", "replace")) for s in apk_resources.arsc_strings(body)]
        elif apk_resources.is_axml(body):
            rest += [("res-xml", s.encode("utf-8", "replace")) for s in apk_resources.pool_strings(body, 8)]
        elif apk_resources.is_elf(body):
            rest += [("lib", s) for s in apk_resources.elf_strings(body)]
        elif not _SIGNING.match(n) and _is_text(body) and body.lstrip()[:1] not in (b"{", b"["):
            rest += [("text", line.strip()) for line in body.splitlines() if line.strip()]
    return first + rest + code_strings(members, deadline)


def code_strings(members, deadline=None) -> list:
    """[(kind, string)] from the app's code containers (app_bundles.py): hermes, dotnet, and for a
    native library the runs behind the first megabyte elf_strings reads, and UTF-16 runs (kind
    `lib`, as before; a Mach-O or PE is `native`)."""
    out = []
    if app_bundles is None:
        return out
    for n, body in members.items():
        if n.endswith(".dex") or n == "AndroidManifest.xml" or apk_resources.is_arsc(body) or apk_resources.is_axml(body):
            continue
        if deadline is not None and time.perf_counter() >= deadline:
            break
        try:
            got = app_bundles.strings(n, body, deadline)
        except Exception:
            continue
        if apk_resources.is_elf(body):
            seen = set(apk_resources.elf_strings(body))
            got = [("lib", s) for _, s in got if s not in seen]
        out += got
    return out


def app_strings(members, pkg=None):
    """The strings of the package that the app's author wrote (no type names): the dex and the
    manifest first, then resources, other compiled XML, native libraries and small text members.
    `pkg` is package_strings(members) when the caller already has it."""
    strings = [s for _, s in (package_strings(members) if pkg is None else pkg)]
    return [s for s in dict.fromkeys(strings) if 2 <= len(s) <= 256 and not _FRAMEWORK.match(s)]


_STORE_PASS = re.compile(r"(store|keystore|key|ks)[_\-]?pass(word)?$|^(password|passphrase|pass|pin)$", re.I)


def keystore_passwords(members) -> list:
    """The passwords a keystore of this package may be opened with: the ones the package states under
    a password's name (a field of a JSON member, a manifest meta-data, a string resource), then the
    usual ones of keystores.USUAL. Stated or usual only: nothing is generated or searched."""
    stated = []
    for n, body in members.items():
        if len(body) > MAX_WRAPPED:
            continue
        if body.lstrip()[:1] in (b"{", b"["):
            obj, _ = _json(body, whole=n == PUZZLE)
            for field, v in (flat(obj) if obj is not None else ()):
                if isinstance(v, str) and v and _STORE_PASS.search(field.split(".")[-1]):
                    stated.append(v)
        elif apk_resources.is_arsc(body):
            stated += [v for (_, name), v in apk_resources.arsc_values(body).items() if isinstance(v, str) and _STORE_PASS.search(name)]
        elif apk_resources.is_axml(body):
            for el in apk_resources.axml_tree(body):
                name = el["attrs"].get("name")
                if isinstance(name, str) and _STORE_PASS.search(name) and isinstance(el["attrs"].get("value"), str):
                    stated.append(el["attrs"]["value"])
    return list(dict.fromkeys(stated[:8]))


def keystore_keys(members, clock) -> list:
    """The secret entries of the package's keystores as key material (keystores.py), first among the APK's keys."""
    return [secret for _, _, secret in keystore_secrets(members, clock) if 1 <= len(secret) <= 64]


SECOND_KDF = 40_000      # key-derivation iterations the look for a second code may spend on keystores (about 12 ms)


def keystore_secrets(members, clock, budget=None, state=None) -> list:
    """[(format, alias, secret bytes)] of the keystores among the members (keystores.py); [] at once for
    a package that ships none, which is every package of Days 1 to 13: nothing else is read for it.

    The work is counted, not timed (review of 2026-10-13): keystores.APK_WORK iterations of key
    derivation for the APK, or `budget` when the caller gives one, and inside it the APK's own
    deadline. A store that does not fit is "not read" and is not tried again (keystores caches that);
    `state`, when given, gets state["cut"] = True then."""
    if keystores is None or clock.up():
        return []
    try:
        if not any(keystores.kind(n, body) for n, body in members.items()):
            return []
        return keystores.secrets(members, keystore_passwords(members), clock.stop,
                                 keystores.APK_WORK if budget is None else budget, state)
    except Exception:
        if state is not None:
            state["cut"] = True
        return []


def named_keys(members) -> list:
    """Values the package stores under a name that says key, secret, salt, iv, seed or password: a
    string resource, a manifest <meta-data>, an attribute of a compiled XML file. They are tried
    before the keys read from the strings at large."""
    out = []
    for n, body in members.items():
        if apk_resources.is_arsc(body):
            out += [v for (_, name), v in apk_resources.arsc_values(body).items() if _KEYNAME.search(name)]
        elif apk_resources.is_axml(body):
            for el in apk_resources.axml_tree(body):
                name = el["attrs"].get("name")
                if isinstance(name, str) and _KEYNAME.search(name) and "value" in el["attrs"]:
                    out.append(el["attrs"]["value"])
                out += [v for k, v in el["attrs"].items() if _KEYNAME.search(k)]
    keys = []
    for v in out[:32]:
        try:
            keys += base._keys({"k": v})
        except Exception:
            continue
    return list(dict.fromkeys(k for k in keys if k))


def key_material(strings, limit=48):
    """Key candidates from the app's strings: tokens, whole short strings, and hex runs as bytes."""
    extra, exact = [], set()
    for s in strings:
        toks = [t for t in re.findall(rb"[A-Za-z0-9_.\-]{4,}", s) if not re.fullmatch(rb"[a-z]+", t)]
        for t in toks + ([s] if len(s) <= 64 else []):
            extra.append(t)
            for h in re.findall(rb"[0-9A-Fa-f]{8,}", t):
                extra.append(h)
                if len(h) % 2 == 0:
                    extra.append(bytes.fromhex(h.decode()))
        # a padded base64 text that is exactly a 16- or 32-byte key or IV (Day 14 look-ahead). Only with its
        # padding: an identifier of 16 or 32 letters is base64 too, and would crowd the real keys out.
        if len(s) in (24, 44) and s.endswith(b"=") and re.fullmatch(rb"[A-Za-z0-9+/_\-]+={1,2}", s):
            k = base.t_base64(s, {})
            if k and len(k) in (16, 32):
                extra.append(k)
                exact.add(k)

    def score(k):
        return (k not in exact, not re.search(rb"SECRET|KEY|TOKEN|[0-9A-F]{8}", k), not re.search(rb"\d", k), len(k) > 64)

    return sorted(dict.fromkeys(k for k in extra if k), key=score)[:limit]


def _opener(blob, zf):
    """solvers/common/archive_passwords.Opener for an encrypted archive: `infected`, then the
    passwords of <challenges>/_passwords.json. None when the module cannot be loaded."""
    try:
        import archive_passwords
        return archive_passwords.Opener(blob, zf)
    except Exception:
        return None


def read_members(blob, depth=0, clock=None, twins=None, dups=None):
    """({name: bytes}, names that came from an archive inside the archive) for a zip or APK.

    The puzzle document is read first and whatever else the archive holds, as the Day 4
    solver reads it by name: an APK with thousands of resources, or a document with a long
    field, must not turn a judged codec into a miss. Then the other assets, then the rest
    in archive order, up to MAX_MEMBERS members of at most 1 MiB each, and only while more
    than half of the clock's time is left (reading is part of the APK's budget). An
    archive inside is opened one level down, with the known archive passwords tried. Anything
    that is not a readable zip gives two empty results.

    A name holds one body here. `twins`, when the caller gives a list, takes the other bodies
    under the puzzle document's name when the one kept came from an archive inside (the
    documents of two packages in one delivery): which of them the result holds is a matter
    of position, and solve_members reads them as candidates. The delivery's own document
    has no twin, and two entries of that name in one archive are not twins either: the last
    is the one zipfile and the Day 4 solver read (selftest.py holds the solver to that)."""
    members, inner = {}, set()
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
        infos = [i for i in zf.infolist() if not i.is_dir()
                 and i.file_size <= (MAX_PUZZLE if i.filename == PUZZLE else
                                     MAX_CODE if app_bundles and _CODE_NAME.search(i.filename) else MAX_MEMBER)]
        # a stable sort: two entries with one name keep their order, so the last still wins
        infos.sort(key=lambda i: (i.filename != PUZZLE, not i.filename.startswith("assets/")))
        del infos[MAX_MEMBERS:]
    except Exception:
        return members, inner
    opener = None
    for info in infos:
        if clock is not None and info.filename != PUZZLE and clock.left() < clock.total / 2:
            break
        body = None
        if info.flag_bits & 1 or info.compress_type == 99:   # encrypted: the known passwords (row 75)
            if opener is None:
                opener = _opener(blob, zf)
            if opener is not None:
                with contextlib.suppress(Exception):
                    body = opener.read(info)
        else:
            with contextlib.suppress(Exception):
                body = zf.read(info)
        if body is None:
            continue
        if dups is not None and depth == 0 and info.filename == PUZZLE and members.get(PUZZLE, body) != body:
            dups.append(members[PUZZLE])   # an earlier entry of the document's name with another body (second_codes)
        members[info.filename] = body  # of two entries with one name the last wins, as in zipfile and the Day 4 solver
        inner.discard(info.filename)
        if depth == 0 and body[:4] == b"PK\x03\x04":
            sub, _ = read_members(body, depth + 1, clock)
            for n, b in sub.items():
                if n not in members:
                    members[n] = b
                    inner.add(n)
                elif twins is not None and n == PUZZLE and n in inner and members[n] != b:
                    twins.append(b)
    return members, inner


def _json(body, whole=False):
    """(parsed JSON, how it was wrapped) for a member that is JSON, plainly or under base64 or hex.

    A member over 64 KiB is not looked at, except the puzzle document itself (`whole`),
    which is parsed as plain JSON at any size the reader let through."""
    if len(body) > MAX_WRAPPED and not whole:
        return None, ""
    for wrap, dec in (("", lambda b: b), ("base64", lambda b: base.t_base64(b, {})),
                      ("hex", lambda b: base.t_hex(b, {}))):
        if wrap and len(body) > MAX_WRAPPED:
            break
        try:
            cand = dec(body)
            if cand:
                obj = json.loads(cand.decode("utf-8-sig"))
                if isinstance(obj, (dict, list)):
                    return obj, wrap
        except Exception:
            continue
    # Day 14 look-ahead: the same document in UTF-16 with a byte order mark, or written as JSON5
    # (comments, a comma before a closing bracket). Only when strict JSON was not read, small
    # members only, and under a wrap name, so the route says `doc-encoded` and is never plain.
    if len(body) <= MAX_WRAPPED and body.lstrip()[:1] in (b"{", b"[", b"/", b"\xff", b"\xfe", b"\xef"):
        for wrap, text in _lenient_texts(body):
            try:
                obj = json.loads(text)
            except Exception:
                continue
            if isinstance(obj, (dict, list)):
                return obj, wrap
    return None, ""


# Day 19 look-ahead (items 2 and 3): a puzzle document under a whole-document layer, or as a string inside
# the app's code. Each is kept only when it parses as a JSON object whose schema is huntress.mobile.puzzle:
# that literal is the proof, so nothing that merely decodes is read as a document.
SCHEMA_LITERAL = b"huntress.mobile.puzzle"
_DOC_LITERAL = re.compile(rb'\{\s*"schema"\s*:\s*"huntress\.mobile\.puzzle')
_ESCAPED_DOC = re.compile(rb'\{\s*\\"schema\\"\s*:\s*\\"huntress\.mobile\.puzzle')
MAX_EMBEDDED = 4        # documents read out of one member of the app's code
MAX_INFLATED = 1 << 18   # bytes a whole-document zlib or gzip layer may inflate to


def _puzzle_object(text):
    """The parsed JSON object when `text` is one with a huntress.mobile.puzzle schema, else None."""
    if SCHEMA_LITERAL not in text:
        return None
    try:
        obj = json.loads(text.decode("utf-8-sig"))
    except Exception:
        return None
    s = obj.get("schema") if isinstance(obj, dict) else None
    return obj if isinstance(s, str) and s.strip().startswith(SCHEMA_LITERAL.decode()) else None


def doc_layers(body):
    """(document, format) when the whole member is a puzzle document under one layer, else None.

    zlib (inflated to MAX_INFLATED at most, the stream complete), then a one-byte XOR whose key is the
    member's first byte XOR '{'. Format `zlib` or `xor`: the route says `doc-zlib` or
    `doc-xor`, so a document read this way is never the judged shape of its codec."""
    if not 16 <= len(body) <= MAX_WRAPPED:
        return None
    # (a gzip member is opened by apk_resources.expand before this is reached, and read as doc-inner)
    for fmt, wbits, magic in (("zlib", 15, b"\x78"),):
        if body.startswith(magic):
            try:
                d = zlib.decompressobj(wbits)
                text = d.decompress(body, MAX_INFLATED)
            except Exception:
                continue
            if d.eof and not d.unconsumed_tail:
                obj = _puzzle_object(text)
                if obj is not None:
                    return obj, fmt
    key = body[0] ^ 0x7B
    if key:
        obj = _puzzle_object(body.translate(bytes(c ^ key for c in range(256))))
        if obj is not None:
            return obj, "xor"
    return None


def _balanced(body, start):
    """The bytes of the JSON object that begins at `start` (strings and escapes respected), or None
    when it does not close within MAX_WRAPPED bytes."""
    depth, quoted, i, end = 0, False, start, min(len(body), start + MAX_WRAPPED)
    while i < end:
        c = body[i]
        if quoted:
            if c == 0x5C:
                i += 2
                continue
            if c == 0x22:
                quoted = False
        elif c == 0x22:
            quoted = True
        elif c == 0x7B:
            depth += 1
        elif c == 0x7D:
            depth -= 1
            if depth == 0:
                return body[start:i + 1]
        i += 1
    return None


def embedded_docs(n, body):
    """(document or list of documents, format) for the puzzle documents that stand as JSON text inside a
    member of the app's code (a dex, a .bin), else None. Format `in-<member's file name>`.

    A document is cut out of the bytes at the literal `{"schema":"huntress.mobile.puzzle` as one balanced
    object and must parse with that schema; at most MAX_EMBEDDED, each once. Two different documents
    are both returned (a list): solve_members reads them as candidates, and two codes give none."""
    if SCHEMA_LITERAL not in body:
        return None
    out = []
    for m in _DOC_LITERAL.finditer(body):
        text = _balanced(body, m.start())
        obj = _puzzle_object(text) if text else None
        if obj is not None and obj not in out:
            out.append(obj)
        if len(out) >= MAX_EMBEDDED:
            break
    if not out:
        return None
    return (out[0] if len(out) == 1 else out), "in-" + _slug(n.rsplit("/", 1)[-1], 32)


def _lenient_texts(body):
    """(wrap name, text) readings of a member that is nearly JSON: UTF-16 behind its byte order mark,
    and either reading with JSON5's comments and trailing commas taken out (a linear pass that
    knows what a string is; nothing is taken out of a string)."""
    texts = []
    if body[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            texts.append(("utf16", body.decode("utf-16")))
        except Exception:
            pass
    else:
        try:
            texts.append(("", body.decode("utf-8-sig")))
        except Exception:
            pass
    out = []
    for wrap, text in texts:
        if wrap:
            out.append((wrap, text))
        cleaned = _json5(text)
        if cleaned != text:
            out.append(("json5" if not wrap else wrap + "+json5", cleaned))
    return out


def _json5(text) -> str:
    """`text` without // and /* */ comments and without a comma that only white space parts from a
    closing bracket. Strings are copied as they stand."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif c == "/" and text[i + 1:i + 2] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c == "/" and text[i + 1:i + 2] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


SCHEMA_V1 = "huntress.mobile.puzzle.v1"
PIECE_DATA = ("data", "value", "text", "piece", "fragment", "chunk", "payload", "part", "content")
PIECE_ORDER = ("index", "order", "pos", "position", "seq", "sequence", "idx", "i", "n", "rank", "offset", "part")
PIECE_CODEC = ("codec", "encoding", "alg", "algorithm", "op", "steps")


def schema_mark(p) -> str:
    """'' for the schema the judge has seen (or none stated); else a mark for the route.

    A document that states another schema (huntress.mobile.puzzle.v2) may mean something else by
    the same field names, so nothing in it is the judged shape of its codec: its answer is unsure
    under <route>:schema-v2 until the judge accepts that, once, on the untimed base."""
    s = p.get("schema") if isinstance(p, dict) else None
    if s is None or (isinstance(s, str) and s.strip() in ("", SCHEMA_V1)):
        return ""
    if not isinstance(s, str):
        return "schema-other"
    m = re.fullmatch(r"huntress\.mobile\.puzzle\.(v\d{1,3})", s.strip())
    return "schema-" + (m.group(1) if m else _slug(s, 32) or "other")


def fragments(obj, where, apk_keys, clock):
    """A Hit for a document that lists its pieces as documents of their own, or None.

      {"fragments": [{"codec": "hex", "data": "..."}, {"codec": "base64", "data": "...", "index": 0}]}

    Every piece names its own codec (PIECE_CODEC) and holds one text (PIECE_DATA); each must decode,
    by its named steps, to exactly one text. The pieces are laid in the order an integer field they
    all carry gives (PIECE_ORDER, named in the route), else as listed. Only an exact answer code
    counts, and the route (`fragments:<codecs>:listed` or `:by-<field>`) is unsure until judged."""
    lists = []
    if isinstance(obj, list):
        lists.append(("", obj, {}))
    elif isinstance(obj, dict):
        lists += [(k, v, obj) for k, v in obj.items() if isinstance(v, list)]
    for field, items, parent in lists[:8]:
        if not (2 <= len(items) <= MAX_PIECES and all(isinstance(x, dict) for x in items)):
            continue
        if not all(any(x.get(f) for f in PIECE_CODEC) for x in items):
            continue
        texts, names = [], []
        for item in items:
            if clock.up():
                return None
            item, _ = reshape(item)
            p = {**{k: v for k, v in parent.items() if k != field and not isinstance(v, (list, dict))}, **item}
            steps, _name = steps_of(p)
            piece = next((item[f] for f in PIECE_DATA if isinstance(item.get(f), str) and item[f]), None)
            if not steps or piece is None:
                break
            keys = key_candidates(p)
            got = None
            for order in ([steps] if steps == steps[::-1] else [steps, steps[::-1]]):
                got = _each_decoded([piece], order, keys, [], clock, p)
                if got:
                    break
            if not got:
                break
            texts.append(got[0])
            names += [s for s in steps if s not in names]
        if len(texts) != len(items):
            continue
        how, order = "listed", list(range(len(items)))
        for f in PIECE_ORDER:
            nums = [x.get(f) for x in items]
            if all(isinstance(v, int) and not isinstance(v, bool) for v in nums) and len(set(nums)) == len(nums):
                how, order = "by-" + f, sorted(range(len(items)), key=lambda i: nums[i])
                break
        value = "".join(texts[i] for i in order)
        if base.ANSWER.fullmatch(value):
            tail = (":@" + _slug(field, 24) if field else "") + (":" + where if where else "")
            return Hit(value, "high", "fragments:%s:%s%s" % (_slug("+".join(names), 40), how, tail), "fragments", ())
    return None


_ANS_RAW = re.compile(rb"(?<![0-9A-Za-z])ANS-[0-9A-F]{16}(?![0-9A-Za-z])")
_ANS_WIDE = re.compile(rb"A\x00N\x00S\x00-\x00(?:[0-9A-F]\x00){16}")
_PIECE_HEAD = re.compile(rb"ANS-[0-9A-F]{0,15}")
_PIECE_TAIL = re.compile(rb"[0-9A-F]{3,16}")


def member_kind(n, body) -> str:
    """Where in the package a member sits, as one word for a route."""
    if n.endswith(".dex"):
        return "dex"
    if n == "AndroidManifest.xml":
        return "manifest"
    if apk_resources.is_arsc(body):
        return "resources"
    if apk_resources.is_axml(body):
        return "res-xml"
    if apk_resources.is_elf(body):
        return "lib"
    if n.startswith("META-INF/"):
        return "meta-inf"
    code = app_bundles.kind_of(n, body) if app_bundles else ""
    if code in ("hermes", "dotnet", "native"):
        return code
    return "asset" if n.startswith(("assets/", "res/raw/")) else "member"


def sqlite_codes(body):
    """({answer code: 'table.column'}, complete) for the codes that stand in clear in the TEXT and
    BLOB cells of a SQLite member, each cell read as a string of its own (row 270); ({}, True)
    for a member that is no SQLite file.

    The scan of the member's bytes misses most of them: a record's values follow one another
    with no separator, so the byte before the code is another column's last character or the
    code's own serial type, the digit `5`, and the look-behind of _ANS_RAW refuses both. A cell
    holds a code when the cell, or a part of it that no letter or digit touches, is one; a BLOB
    may hold it as UTF-16. `complete` is False when the database was not read to its end."""
    try:
        got = asset_docs.sqlite_cells(body)
    except Exception:
        got = ([], False) if body.startswith(b"SQLite format 3\x00") else None
    if got is None:
        return {}, True
    cells, complete = got
    out = {}
    for table, column, value in cells:
        for m in _ANS_RAW.finditer(value):
            out.setdefault(m.group(0).decode(), "%s.%s" % (table, column))
        for m in _ANS_WIDE.finditer(value):
            out.setdefault(m.group(0).decode("utf-16le"), "%s.%s" % (table, column))
    return out, complete


# base64 and hex of "ANS-" and sixteen more characters. Nothing is asked of the byte before it (in a
# string pool that is another value's end); the text must end there, or it is the start of a longer one.
_B64_CODE = re.compile(rb"QU5TL[A-Za-z0-9+/_\-]{22}(?![A-Za-z0-9+/_\-])")
_HEX_CODE = re.compile(rb"414[eE]532[dD](?:[0-9A-Fa-f]{2}){16}(?![0-9A-Fa-f])")
_B64_WIDE = re.compile(rb"Q\x00U\x005\x00T\x00L\x00(?:[A-Za-z0-9+/_\-]\x00){22}")


def encoded_codes(body) -> dict:
    """{answer code: 'base64' or 'hex'} for the codes a member's bytes hold under one of the two text
    encodings (Day 14 look-ahead). The text is found by what "ANS-" becomes in it and counts only
    when it decodes to exactly an answer code."""
    out = {}
    if b"QU5TL" in body:
        for m in _B64_CODE.finditer(body):
            try:
                value = strict(base64.b64decode(m.group(0).translate(bytes.maketrans(b"-_", b"+/")) + b"="))
            except Exception:
                value = None
            if value:
                out.setdefault(value, "base64")
    if b"Q\x00U\x005\x00T\x00L\x00" in body:
        for m in _B64_WIDE.finditer(body):
            try:
                value = strict(base64.b64decode(m.group(0)[::2].translate(bytes.maketrans(b"-_", b"+/")) + b"="))
            except Exception:
                value = None
            if value:
                out.setdefault(value, "utf16:base64")
    if b"414" in body:
        for m in _HEX_CODE.finditer(body):
            value = strict(bytes.fromhex(m.group(0).decode()))
            if value:
                out.setdefault(value, "hex")
    if body.startswith(b"SQLite format 3\x00") and len(body) <= NOTE_CHUNK and (b"QU5TL" in body or b"414" in body):
        # in a record the next column's bytes follow the text with nothing between: each cell by itself
        try:
            cells = asset_docs.sqlite_cells(body)[0]
        except Exception:
            cells = []
        for _, _, value in cells:
            v = bytes(value).strip()
            if len(v) in (27, 28) and v.startswith(b"QU5TL"):
                try:
                    code = strict(base64.b64decode(v[:27].translate(bytes.maketrans(b"-_", b"+/")) + b"="))
                except Exception:
                    code = None
                if code:
                    out.setdefault(code, "base64")
            elif len(v) == 40 and _HEX_CODE.fullmatch(v):
                out.setdefault(strict(bytes.fromhex(v.decode())), "hex")
    out.pop(None, None)
    return out


NOTE_BUDGET = 0.03       # seconds the look for a second code may take, and never more than the APK's clock has left
NOTE_CHUNK = 1 << 18     # bytes scanned between two looks at that clock


_SCAN_LITERAL = {_ANS_RAW: b"ANS-", _ANS_WIDE: b"A\x00N\x00S\x00-\x00"}


def _scan(rx, body, clock):
    """rx's matches in body, a chunk at a time (20 bytes of overlap: a code's length), until the clock is up."""
    lit = _SCAN_LITERAL.get(rx)
    if lit is not None and lit not in body:
        return      # the code's own start is not there: no pattern is run over the member (most members, every day)
    for at in range(0, len(body), NOTE_CHUNK):
        if clock.up():
            return
        yield from rx.finditer(body, max(0, at - 40), min(len(body), at + NOTE_CHUNK))


def other_codes(members, value, clock, blob=b""):
    """[(code, where)] for the answer codes that stand in clear in the package and are not `value`.

    For the NOTE only (row 270): when the puzzle document gives one code and a SQLite row, a DEX
    string or another member holds a different one, the document's answer stands (twelve days
    judged the document) and a lane agent must see the other at once. As it stands only: the
    members' bytes (ASCII and UTF-16), the cells of a small SQLite member, the archive's own bytes.
    Nothing is decoded, and the caller's clock (NOTE_BUDGET, 0.03 s) ends the look wherever it
    stands: on a package of large members the note may be short, the answer is never late."""
    out = {}
    for n, body in members.items():
        if clock.up() or len(out) >= MAX_NAMED:
            break
        if len(body) > MAX_MEMBER:
            continue
        for m in _scan(_ANS_RAW, body, clock):
            out.setdefault(m.group(0).decode(), n)
        for m in _scan(_ANS_WIDE, body, clock):
            out.setdefault(m.group(0).decode("utf-16le"), n + " (UTF-16)")
        if body.startswith(b"SQLite format 3\x00") and len(body) <= NOTE_CHUNK and not clock.up():
            for code, cell in sqlite_codes(body)[0].items():
                out.setdefault(code, "%s, cell %s" % (n, cell))
    for m in _scan(_ANS_RAW, blob[:8 << 20], clock):
        out.setdefault(m.group(0).decode(), "the archive's own bytes")
    return [(code, where) for code, where in out.items() if code != value][:MAX_NAMED]


_DOC_MEMBER = re.compile(r"\.(json|xml|db|sqlite3?|properties|ya?ml|toml|plist|txt|cfg|conf|ini|b64|hex|gz|ab|tar)$", re.I)
SECOND = ":second-code"  # the end of the label key of an answer that offers two codes


SECOND_MEMBERS = 64      # members the look reads
SECOND_BYTES = 2 << 20   # bytes it scans: the members it reads and the archive's own
SECOND_DOCS = 8          # members it reads as a second puzzle document
SECOND_DOC_BYTES = 4096  # ... each at most this long (a puzzle document is about a hundred bytes)
_FOREVER = Clock(1e9)    # for the scans below: they are bounded by bytes, and no clock cuts them

# Day 18 look-ahead (the decoy shape): a judged codec's `data` holds a decoy and the real code sits in
# another field of the same document under another transform. Beside a PLAIN answer each other
# top-level text field gets a short search with the document's keys, bounded by states and never by
# a clock, so the base, the gate's replay and a clock give the same answer.
SELECTORS = ("use", "active", "follow", "field", "select", "source", "target", "real", "primary")
# The only top-level keys the field look never searches for a competing code: a schema marker, the day number and the
# codec name. Every other META field (version, encoding, alg, algorithm, steps, chain, hint, note, description, v) can
# carry a decoy-competing code and is searched (wave12 adversarial review).
_FIELD_STRUCTURAL = ("schema", "day", "codec")
FIELD_FIELDS = 6         # top-level text fields the short search reads, the ones a selector names first
FIELD_NODES = 200        # states it visits in one field ...
FIELD_DEPTH = 3          # ... at most this many transforms deep
FIELD_KEYS = 6           # the document's own keys it tries, each of 1 to 16 bytes
FIELD_CHARS = 512        # characters of the document's fields it searches in all (six 256-character fields beside
                         # five one-byte keys took about 200 ms; a decoy field is a few dozen characters)


_MISSING = object()


def _resolve(p, path):
    """The value a dotted path names in the document ("release.data", "entries.1"), or _MISSING.

    A segment is a key of an object or the index of a list; at most SUB_DEPTH + 1 segments."""
    if not isinstance(path, str) or not path or len(path) > 64:
        return _MISSING
    cur = p
    parts = path.split(".")
    if len(parts) > SUB_DEPTH + 1:
        return _MISSING
    for part in parts:
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return _MISSING
    return cur


def selected(p) -> set:
    """The fields a selector of the document names ({"use": "b"}): the field it says to read.

    A top-level field by its name, and (Day 19 look-ahead) a nested one by its dotted path
    ({"use": "release.data"}) when that path names a text or an object in the document."""
    if not isinstance(p, dict):
        return set()
    out = set()
    for f in SELECTORS:
        v = p.get(f)
        if not isinstance(v, str) or v == f or v.split(".")[0] in ("schema", "day", "codec"):
            continue
        if v in p or ("." in v and isinstance(_resolve(p, v), (str, dict))):
            out.add(v)
    return out


def _field_target(name):
    """The field an offered name `field:@<field>[:...]` reads, without a trailing `.data`, or None."""
    if not name.startswith("field:@"):
        return None
    t = name[len("field:@"):].split(":")[0]
    return t[:-5] if t.endswith(".data") else t


def field_codes(p, value, budget=None, skip=None) -> list:
    """[(field, code, path)] for the other top-level text fields of the document that a short search turns
    into an answer code that is not `value`.

    A field of 16 to MAX_PIECE characters, not `data`, not a header, key or selector field, and not
    one that holds a code in clear (the scan of the document's member names that one). At most
    FIELD_FIELDS of them and FIELD_CHARS characters in all, the fields a selector names first, then
    in the document's order (a field that does not fit is passed over); each is searched FIELD_NODES
    states and FIELD_DEPTH transforms deep with FIELD_KEYS of the document's keys and no block
    cipher. A field whose states hold two codes gives none.

    A field named like a key (`license_key`, `stage_iv`) is searched like any other: only the fields
    cipher_codes takes as key or IV material are left out (review of the Day 19 build: leaving every
    `*_key` out let a decoy in `data` stand plain beside the real code in `license_key`). `skip` names
    them: document_codes passes only the fields cipher_codes actually used as material for a side text
    that decoded (second review: an `xor_key`, `aes_key` or `aes_iv` that holds the real code itself,
    beside no side text the cipher decodes, was left out of the look and the decoy stood plain); with
    no `skip`, every field cipher_material names. `budget`, a one-item list, is the FIELD_CHARS left,
    shared with nested_codes and written back."""
    chosen = selected(p)
    material = cipher_material(p) if skip is None else set(skip)
    # wave12 adversarial review: a competing code hidden in a META text field (version, encoding, alg, algorithm,
    # steps, chain, hint, note, description, v) was skipped here, so a decoy in `data` under a judged codec stood
    # PLAIN while the real code sat base64/keyed in such a field (meta-field:*, hint-xor-key: WRONG plain). Only the
    # three fields that are never a code -- schema, day, codec -- are structural; every other named field holding
    # 16..MAX_PIECE characters that the short search turns into a DIFFERENT valid ANS code is a competing code and
    # demotes the plain answer to <key>:second-code (never-guess: this can only demote, never introduce an answer,
    # and a legit short metadata string -- "1.0.0", "utf-8" -- is under 16 chars or never decodes to ANS-[0-9A-F]{16},
    # so no legit plain is weakened; saved docs carry no such field).
    texts = [(k, v) for k, v in p.items() if isinstance(v, str) and 16 <= len(v) <= MAX_PIECE and k != "data"
             and k.lower() not in _FIELD_STRUCTURAL and not _KEYISH.search(k) and k not in material
             and not (k in SELECTORS and _resolve(p, v) is not _MISSING)
             and not answers_in(v.encode("utf-8", "replace"))]
    room, kept = (budget[0] if budget else FIELD_CHARS), []
    # Selector-named fields first, then the shortest: long padding fields placed before the real code must not
    # use up FIELD_CHARS and leave the decoy plain (review of c6dfb2c).
    for k, v in sorted(texts, key=lambda kv: (kv[0] not in chosen, len(kv[1])))[:FIELD_FIELDS]:
        if len(v) <= room:
            room -= len(v)
            kept.append((k, v))
    if budget:
        budget[0] = room
    texts = kept
    if not texts:
        return []
    keys = [(k, tag) for k, tag in key_candidates(p) if len(k) <= 16][:FIELD_KEYS]
    out = []
    for k, text in texts:
        try:
            hit, _, _ = search(text.encode("utf-8", "surrogatepass"), keys, [], _FOREVER, max_depth=FIELD_DEPTH,
                               max_nodes=FIELD_NODES, block=False)
        except Ambiguous:
            continue
        if hit and hit[0] != value:
            out.append((k, hit[0], hit[1]))
    return out


# Day 19 look-ahead (items 1 and 4; docs/retro/day-19-predictions-mobile.md, docs/build-day19/mobile.md): the
# decoy family that row 350's field look did not reach. A nested object (or an object in a list) that brings its
# own key or codec beside a decoy in `data`, and a side field under a block or stream cipher whose key the
# document names (`secure` beside `aes_key`). Each is read by name, bounded by what it reads and never by a clock,
# and a code it gives only ever demotes a plain answer to `<key>:second-code`: nothing here is plain.
SUB_DEPTH = 2            # levels of nested objects read as sub-documents (release = 1, release.payload = 2)
SUB_DOCS = 8             # sub-documents read in all
_NAMED_KEY = re.compile(r"(^|[_\-.])(key|iv|nonce|salt)$", re.I)
_CIPHER_KEY = re.compile(r"^(aes(?:[_\-]?(?:128|192|256))?(?:[_\-]?(?:ecb|cbc|ctr|gcm))?|rc4|arc4|des3?|3des|"
                         r"triple[_\-]?des|chacha20|blowfish|xor)[_\-]?key$", re.I)
_CIPHER_IV = ("%s_iv", "%s_nonce", "iv", "nonce")
_SIDE_CIPHER = ("%s_codec", "%s_cipher", "%s_alg", "%s_algorithm")
_PIECE_MARKS = ("index", "order", "pos", "position", "seq", "sequence", "idx", "i", "n", "rank", "part")


def _simple_step(s) -> bool:
    """A step by_name applies with a bounded number of states and no clock: a text layer, a rotation, a shift."""
    s = ALIASES.get(s, s)
    return s in base.NAMED or s in SHIFTS or s in STEP or s in PACKED or bool(_ROTN.fullmatch(s))


def sub_documents(p) -> list:
    """[(dotted path, object)] for the nested objects of the document that hold a `data` text of their own.

    An object under a top-level field (level 1), an object in a top-level list (level 1), and the
    objects in those (level 2); at most SUB_DOCS, in the document's order. Not under a header field
    (`codec` written as an object is reshape()'s), and not an object that carries a piece's number
    (`index`, `order`, ...): those are an arrangement's pieces, which arranged() reads."""
    out = []

    def visit(obj, path, level):
        if len(out) >= SUB_DOCS or not isinstance(obj, dict):
            return
        d = obj.get("data")
        if (isinstance(d, str) and 0 < len(d) <= MAX_PIECE
                and not any(isinstance(obj.get(f), int) and not isinstance(obj.get(f), bool) for f in _PIECE_MARKS)):
            out.append((path, obj))
        if level < SUB_DEPTH:
            for k, v in obj.items():
                each(v, "%s.%s" % (path, k), level + 1)

    def each(v, path, level):
        if isinstance(v, dict):
            visit(v, path, level)
        elif isinstance(v, list):
            for i, x in enumerate(v[:SUB_DOCS]):
                visit(x, "%s.%d" % (path, i), level)

    if isinstance(p, dict):
        for k, v in p.items():
            if k.lower() not in META:
                each(v, k, 1)
    return out


def _merged(p, sub) -> dict:
    """A sub-document read as a puzzle document: its own fields, over the parent's header and keys.

    Its own codec when it names one, else the parent's. When it brings any parameter of its own
    (a key, a shift, an order), none of the parent's parameters is kept: only the header. The parent's
    other text fields (a decoy, a selector) are never keys of the sub-document."""
    own = {k: v for k, v in sub.items() if not isinstance(v, (dict, list))
           or (isinstance(v, list) and v and all(isinstance(x, int) and not isinstance(x, bool) for x in v))}
    params = [k for k in own if k != "data" and k.lower() not in META]
    keep = {}
    for k, v in p.items():
        if k == "data" or k in SELECTORS:
            continue
        if k.lower() in META:
            keep[k] = v
        elif params:
            continue
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            keep[k] = v
        elif isinstance(v, list) and v and all(isinstance(x, int) and not isinstance(x, bool) for x in v):
            keep[k] = v
        elif isinstance(v, str) and (_KEYISH.search(k) or _NAMED_KEY.search(k) or k.lower() in ("k", "shift", "rot")):
            keep[k] = v
    return {**keep, **own}


def _named_reading(q):
    """The code a (sub-)document gives by the codec it names, read as the Day 4 solver or by_name would, or None.

    Only for steps that are bounded without a clock (_simple_step); a chain the Day 4 solver would
    take too long over (base_cost) is not read."""
    steps = base_steps(q)
    if not steps:
        return None
    if all(s_ in base.NAMED for s_ in steps) and base_cost(q, steps) <= BASE_COST:
        try:
            v = base.by_codec(q)
        except Exception:
            v = None
        if v and strict(v.encode()):
            return v
    named, _ = steps_of(q)
    if not named or not all(_simple_step(s_) for s_ in named):
        return None
    data = q.get("data")
    if not isinstance(data, str) or not data:
        return None
    keys = [(k, tag) for k, tag in key_candidates(q) if len(k) <= 16][:FIELD_KEYS]
    try:
        got = by_name(named, [("data", data.encode("utf-8", "surrogatepass"))], keys, [], _FOREVER, q)
    except Exception:
        return None
    # a weaker reading (a body that had no ANS- prefix, a code inside other text) is no code of the sub-document
    return got[0] if got and not _WEAKER.intersection(got[1]) and strict(got[0].encode()) else None


def nested_codes(p, value, search=True, budget=None) -> list:
    """[(name, code, where)] for the sub-documents of the document (sub_documents) that give an answer
    code that is not `value`.

    Each is read by name first (its own codec, else the parent's; its own keys, else the parent's):
    `field:@<path>.data:sub`. With `search`, one that gives nothing by name gets the field look's short
    search (FIELD_NODES states, FIELD_DEPTH moves, its own keys first, no block cipher), FIELD_CHARS
    characters in all, shared with field_codes through `budget` (a one-item list, written back): the field
    look's bounds hold for both together: `field:@<path>.data:sub:search:<moves>`. A document that lays
    out pieces (split, interleave) has no sub-documents: its objects are pieces."""
    if not isinstance(p, dict) or any(ALIASES.get(s_, s_) in JOIN + WEAVE for s_ in steps_of(p)[0]):
        return []
    out, room = [], (budget[0] if budget else FIELD_CHARS)
    for path, sub in sub_documents(p):
        q = _merged(p, sub)
        name = "field:@" + _slug(path + ".data", 40)
        got, moves = _named_reading(q), None
        if not got and search and len(sub["data"]) <= room:
            room -= len(sub["data"])
            keys = [(k, tag) for k, tag in key_candidates(q) if len(k) <= 16][:FIELD_KEYS]
            try:
                hit, _, _ = search_text(sub["data"], keys)
            except Ambiguous:
                hit = None
            if hit:
                got, moves = hit[0], hit[1]
        if budget:
            budget[0] = room
        if got and got != value and base.ANSWER.fullmatch(got):
            label = name + ":sub" + (":search:" + ">".join(moves) if moves is not None else "")
            out.append((_slug(label, 96), got, "%s, object %s%s" % (PUZZLE, path, " after " + ">".join(moves)
                                                                     if moves else "")))
    return out


def search_text(text, keys):
    """The field look's short search over one text (field_codes' bounds)."""
    return search(text.encode("utf-8", "surrogatepass"), keys, [], _FOREVER, max_depth=FIELD_DEPTH,
                  max_nodes=FIELD_NODES, block=False)


def cipher_material(p) -> set:
    """The fields cipher_codes reads as key or IV material, not as text: `<cipher>_key` (aes_key, rc4_key, ...)
    with its `<cipher>_iv` and `<cipher>_nonce`, and `<field>_key` beside a text `<field>` whose cipher
    `<field>_codec` (or `_cipher`, `_alg`, `_algorithm`) names. Any other field named like a key is a text."""
    out = set()
    if not isinstance(p, dict):
        return out
    for kf in p:
        if not isinstance(kf, str):
            continue
        m = _CIPHER_KEY.match(kf)
        if m:
            out.add(kf)
            prefix = re.sub(r"[_]", "-", m.group(1).lower()).split("-")[0]
            out.update(f % prefix for f in _CIPHER_IV if "%" in f and (f % prefix) in p)
        elif kf.lower().endswith(("_key", "-key")) and isinstance(p.get(kf[:-4]), str):
            t = kf[:-4]
            if any(isinstance(p.get(f % t), str) for f in _SIDE_CIPHER):
                out.add(kf)
    return out


def _byte_list(v):
    """A cipher-sized Java byte[] (a list of 16 to MAX_PIECE signed or unsigned byte values) as bytes, or None.
    Not an order list (a permutation of 0..n-1 or 1..n: int_list_codes and arranged() read those)."""
    if (isinstance(v, list) and 16 <= len(v) <= MAX_PIECE
            and all(isinstance(x, int) and not isinstance(x, bool) and -128 <= x <= 255 for x in v)
            and sorted(v) not in (list(range(len(v))), list(range(1, len(v) + 1)))):
        return bytes(x & 255 for x in v)
    return None


def cipher_codes(p, value, used=None) -> list:
    """[(name, code, where)] for the side fields of the document that a cipher the document names by its key
    field decodes to an answer code that is not `value`.

    `<cipher>_key` (aes_key, rc4_key, des_key, chacha20_key, xor_key) beside a text field OR a cipher-sized
    byte[] side field (`secure` = AES-ECB(code); Day 20 look-ahead D04): each candidate ciphertext of the
    field look (field_codes' choice: not `data`, not a header, key or selector field; a text of 16 to
    MAX_PIECE characters, or a byte[] of 16 to MAX_PIECE values) is read under that cipher and key, by name,
    with an IV from `<cipher>_iv`, `iv` or `nonce`. `<field>_key` beside `<field>`: that field only, under the
    cipher `<field>_codec` (or `_cipher`, `_alg`, `_algorithm`) names; with none named, the field look's
    search already tries the key. And a cipher-sized byte[] whose cipher NO `<cipher>_key` field names (a
    generically named key, D04b): tried under RC4 and AES with the document's own key candidates, kept only
    when those keys give exactly one answer code (fails closed on two). Named `field:@<field>:<key field>` or
    `field:@<byte list>:<cipher reading>`. `used`, a set, gets the key and IV fields of every reading that
    decoded to an answer code (this one's or another): only those are material the field look need not read as
    text. Like every cipher reading, a code here only ever demotes a plain answer to `<key>:second-code`,
    never a plain answer of its own."""
    if not isinstance(p, dict):
        return []
    side = lambda k: (isinstance(k, str) and k != "data" and k.lower() not in META  # noqa: E731
                      and not _KEYISH.search(k) and not _NAMED_KEY.search(k) and k not in SELECTORS)
    ctexts = [(k, v) for k, v in p.items() if side(k) and isinstance(v, str) and 16 <= len(v) <= MAX_PIECE
              and not answers_in(v.encode("utf-8", "replace"))][:FIELD_FIELDS]
    blists = [(k, b) for k, v in p.items() if side(k) for b in [_byte_list(v)] if b is not None][:INT_FIELDS]
    cands = ctexts + blists
    names = {k for k, _ in cands}
    jobs = []
    for kf, kv in p.items():
        if not isinstance(kv, (str, int, list)) or isinstance(kv, bool):
            continue
        m = _CIPHER_KEY.match(kf)
        if m:
            cipher = re.sub(r"[_]", "-", m.group(1).lower())
            jobs += [(t, tv, cipher, kf, kv) for t, tv in cands]
        elif kf.lower().endswith(("_key", "-key")) and kf[:-4] in names:
            t = kf[:-4]
            named = next((p[f % t] for f in _SIDE_CIPHER if isinstance(p.get(f % t), str)), None)
            if named:
                jobs.append((t, dict(cands)[t], named.strip().lower()[:40], kf, kv))
    out, solved = [], set()
    for t, tv, cipher, kf, kv in jobs[:FIELD_FIELDS * 3]:
        if not _known(ALIASES.get(cipher, cipher)) and not _known(cipher):
            continue
        sub = {"codec": cipher, "data": tv, "key": kv}
        prefix = cipher.split("-")[0]
        ivf = None
        for f in _CIPHER_IV:
            f = f % prefix if "%" in f else f
            if isinstance(p.get(f), str):
                sub["iv"], ivf = p[f], f
                break
        try:
            hit = solve_doc(sub, "", lambda: [], _FOREVER, named_only=True)
        except Exception:
            hit = None
        if used is not None and hit and hit.value and base.ANSWER.fullmatch(hit.value):
            used.update(f for f in (kf, ivf) if f)
        if (hit and hit.value and hit.value != value and hit.confidence in ("high", "medium")
                and base.ANSWER.fullmatch(hit.value) and not any(w in hit.route for w in _WEAKER)):
            solved.add(t)
            out.append((_slug("field:@%s:%s" % (_slug(t, 24), _slug(kf, 24)), 96), hit.value,
                        "%s, field %s under %s %s" % (PUZZLE, t, cipher, kf)))
    # Row 376 (D04b): a cipher-sized byte[] whose cipher no `<cipher>_key` field names (a stream or block
    # cipher's ciphertext beside a generically named key, `key_hex`). Tried under RC4 and AES with the
    # document's own key candidates; kept only when those keys give exactly one answer code, so a wrong key
    # never contributes one. Never plain, as above.
    if blists:
        kc = [(k, tg) for k, tg in key_candidates(p) if 4 <= len(k) <= 64][:FIELD_KEYS]
        ivs = []
        for n_, v_ in flat(p):
            if re.search(r"iv|nonce", n_, re.I):
                try:
                    ivs += base._keys({"k": v_})
                except Exception:
                    pass
        for name, data in blists:
            if name in solved or not kc:
                continue
            found = {}
            for label, pt in block_ciphers(data, kc, ivs, _FOREVER, algs=("rc4", "aes")):
                got = strict(pt) or loose(pt)
                if got and got != value:
                    found.setdefault(got, label)
                    if len(found) > 1:
                        break
            if len(found) == 1:
                got, label = next(iter(found.items()))
                if used is not None:
                    used.add(name)
                out.append((_slug("field:@%s:%s" % (_slug(name, 24), _slug(label, 24)), 96), got,
                            "%s, byte list %s under %s" % (PUZZLE, name, label)))
    return out


# Day 20 build (the Day 19 look-ahead's remaining WRONG shapes V04, V05, V11, V12, V13; docs/build-day20/mobile.md):
# the real code where neither row 350's field look nor the Day 19 sub-documents reach. Each reading is by the
# document's own judged codec or by the field look's short search, bounded by counts and bytes and never by a
# clock, beside a PLAIN answer only; a different exact code only ever demotes that answer to `<key>:second-code`.
HEADER_TEXTS = ("hint", "note", "description")   # header fields (META) read for a code, never as a key or a step
HEADER_MIN = 20          # characters a header text must have: an answer code has 20 (Day 18's G09 hint 'b' is not read)
HEADER_FIELDS = 3        # header texts read, each with the field look's short search and NO key of the document
LONG_FIELD = 4096        # characters of a text field longer than MAX_PIECE whose windows are read
LONG_WINDOWS = 32        # windows of len(data) read under the document's own codec, in all the long fields
                         # (the run's end and start come first), and within OWN_UNITS
SUB_WINDOWS = 24         # wave17 (the never-wrong sweep's sub-256 side-field wrong-plain): windows of len(data)
                         # read under the document's own codec in the SUB-256 side fields (16..MAX_PIECE), after
                         # every long field so long-field behaviour is byte-identical, and within OWN_UNITS. A
                         # sub-256 all-hex/all-base64 side field can carry the real code embedded at an offset the
                         # whole-field transform search (field_codes) cannot isolate (the window scan only reached
                         # fields over MAX_PIECE). read() returns only an exact answer, so a window only ever demotes
                         # a plain answer to <key>:second-code; with nothing read, behaviour is exactly as before.
INT_FIELDS = 4           # side fields holding a list of byte values (a Java byte[]) the short search reads
JOIN_GROUPS = 4          # groups of numbered side fields (p1, p2) read as one code cut in pieces
JOIN_PIECES = 4          # ... each of 2 to this many pieces
_NUMBERED_FIELD = re.compile(r"^(.*?)[_\-]?(\d{1,2})$")
_PAIR_NAMES = (("head", "tail"), ("first", "second"), ("left", "right"), ("prefix", "suffix"), ("start", "end"),
               ("front", "back"))
DEX_WINDOWS = 256        # windows of len(data) read under the document's own codec in the strings of the app's dex
                         # (a run must look like encoded material, _encoded_run), and within OWN_UNITS
# What one read by the document's own codec costs grows with the document: the Day 4 solver takes every top-level
# field for a key, so an xor document with a hundred side fields costs about 200 times one with none (review of
# build20/mobile: 256 dex windows of such a document took 1.5 s). The looks that read by the document's codec
# (joined_codes, window_codes, dex_codes) therefore share one budget counted in base_cost units, never in seconds:
# every read is charged READ_FIXED + COST_WEIGHT * base_cost(doc), and a look stops when the next read would pass
# OWN_UNITS. Measured on this machine under a load of about 12: a read of a window that does not decode costs about
# 0.04 us a unit, one of a window that is itself valid base64 about 0.15 us a unit plus 0.35 ms (the weight and the
# fixed charge are set for the second), so the whole budget is at most about 30 ms on any document: a judged xor
# document with no side field keeps about 51 reads, one with eight side fields about 9, one with thirty 2.
READ_FIXED = 4_000
COST_WEIGHT = 4
OWN_UNITS = 250_000
DEX_SCAN = 1 << 20       # characters of dex strings scanned in all the dex members together (review of
                         # build20/mobile-fix1: six 5 MB dex files cost 550 ms, scanned per member only)
DEX_SLACK = 16           # characters a run of the class may have beside the encoded code
DEX_STRING = 512         # characters of a dex string that is read
ANCHORS = 16             # anchored windows (_anchors) read in all the long fields, after the strided ones and apart
                         # from LONG_WINDOWS (review of c9e3de4: inside it they crowded out a strided window)
DENSE_CAP = LONG_FIELD   # the most offsets of ONE class-run _long_dense will plan for an exhaustive (every-offset)
                         # scan; a run bigger than this is never fully covered, so it fails closed (long_field_unscanned)
FILL_RUN = 4             # characters one repeated character needs to be filler an anchor is taken from
DEX_SEARCHES = 24        # windows of dex strings given the field look's short search with no key (Day 20 look-ahead
                         # row 3: the real code under ANOTHER key or codec than the document's), each about 0.4 ms
_CODE_PIECE = re.compile(r"[0-9A-FNS-]{1,20}")
_CLASSES = ((re.compile(r"[0-9a-fA-F]+"), 2), (re.compile(r"[A-Za-z0-9+/=]+"), 4), (re.compile(r"[A-Za-z0-9_=-]+"), 4),
            (re.compile(r"[A-Za-z0-9-]+"), 1))   # (class, the stride of the windows read inside one of its runs)
_FILLER = re.compile(r"(.)\1{%d,}" % (FILL_RUN - 1), re.S)


def _offsets(n, L, stride, anchors=()):
    """The offsets of the windows of L characters read in a run of n: the run's end and start first (a code
    behind or before filler of its own class), then `anchors` (_anchors: where the code's own padding ends or
    a filler run meets other material, at any offset), then every `stride` characters from the start and from
    the end."""
    out = []
    for i in [n - L, 0] + list(anchors) + list(range(stride, n - L, stride)) + list(range(n - L - stride, 0, -stride)):
        if 0 <= i <= n - L and i not in out:
            out.append(i)
    return out


def _pad_of(data) -> int:
    """The `=` characters base64 padding ends `data` with (1 or 2, else 0): a code under the document's own
    codec has the length of `data`, and so the same padding."""
    if not isinstance(data, str):
        return 0
    pad = len(data) - len(data.rstrip("="))
    return pad if pad <= 2 else 0


def _anchors(run, L, stride, pad) -> list:
    """Day 20 look-ahead row 3 (D05): offsets of windows of L characters in `run` that a stride does not reach.
    A window that ends where a group of exactly `pad` `=` characters ends (the code's own padding, with no other
    `=` in the window), and a window that starts where a run of one repeated character (FILL_RUN or more) ends,
    or ends where one begins, give or take stride - 1 characters (a code whose first or last characters are the
    filler's). At most ANCHORS, in that order; read after the run's end and start, before the strided windows,
    inside LONG_WINDOWS."""
    out, n = [], len(run)
    if pad:
        for m in re.finditer(r"(?<!=)={%d}(?!=)" % pad, run):
            i = m.end() - L
            if i >= 0 and "=" not in run[i:m.start()]:
                out.append(i)
    for m in _FILLER.finditer(run):
        for k in range(max(1, stride)):
            if m.end() < n:
                out.append(m.end() - k)
            if m.start() > 0:
                out.append(m.start() + k - L)
    seen = []
    for i in out:
        if 0 <= i <= n - L and i not in seen:
            seen.append(i)
            if len(seen) >= ANCHORS:
                break
    return seen


def own_codec(doc):
    """(read, L, cls, spend, cost) for the document's own judged codec, or None: read(text) is the code the Day 4
    solver reads from `text` as the document's `data` (or None), L the length of the document's `data` (the
    length an answer code has under this codec in this document), cls the first of _CLASSES that holds all
    of `data` (hex, base64, a code's own letters), or None, and spend(n) takes n reads' charge from the
    looks' one budget (OWN_UNITS) and says whether there was room, and cost the per-document base_cost the
    budget is counted in (READ_FIXED + COST_WEIGHT * cost a read; _long_dense uses it). Only for a document whose
    every step the Day 4 solver applies (base.NAMED) within BASE_COST, with a `data` of 16 to 64 characters."""
    steps = base_steps(doc) if isinstance(doc, dict) else []
    d = doc.get("data") if isinstance(doc, dict) else None
    if not steps or not all(s_ in base.NAMED for s_ in steps):
        return None
    # Row 376: the window and dex looks read `data`-length windows of a long field or a dex string under the
    # document's OWN codec and key. base._keys takes EVERY top-level field for a key, so base_cost (and each
    # read itself) grew with the side-field count: a decoy document that carries ~10-15 key-like side fields (a
    # feature-flags / build-config blob) spent the shared OWN_UNITS budget before a single window was read, so
    # the real code in a long field or a dex string went unread and the decoy stood plain (WRONG; D01/D02 of the
    # Day 20 look-ahead). The budget and the reads are charged on the document's declared key material only (its
    # codec and `data`, and its key/iv/nonce/salt/seed/secret/pass fields) — a side field is a text the field
    # look reads, never a key of this read. It can only leave a decoy unread as it did before (never worse: the
    # window/dex looks only ever demote a plain answer to `<key>:second-code`, never make a wrong answer plain).
    kdoc = {k: v for k, v in doc.items()
            if k in ("schema", "day", "codec", "data") or (isinstance(k, str) and _KEYISH.search(k))}
    cost = base_cost(kdoc, steps)
    if cost > BASE_COST or not isinstance(d, str) or not 16 <= len(d) <= 64:
        return None
    cls = next((c for c in _CLASSES if c[0].fullmatch(d)), None)
    left = [OWN_UNITS]

    def spend(n=1) -> bool:
        if left[0] < n * (READ_FIXED + COST_WEIGHT * cost):
            left[0] = 0
            return False
        left[0] -= n * (READ_FIXED + COST_WEIGHT * cost)
        return True

    def read(text):
        try:
            v = base.by_codec({**kdoc, "data": text})
        except Exception:
            return None
        return v if v and base.ANSWER.fullmatch(v) else None

    return read, len(d), cls, spend, cost


def _codec_states(doc, text) -> list:
    """The texts the document's own codec makes of `text` (by_codec's states, both orders) that are pieces
    of an answer code (_CODE_PIECE): for a code cut over fields."""
    steps = base_steps(doc)
    out = []
    for order in (steps, steps[::-1]):
        states = [text.encode("utf-8", "surrogatepass")]
        for name in order:
            fn = base.NAMED.get(name)
            nxt = []
            for st in states[:16]:
                try:
                    o = fn(st, doc)
                except Exception:
                    o = None
                nxt.extend(o if isinstance(o, list) else [o] if o is not None else [])
            states = nxt + [y for st in nxt for y in base._text_layers(st)[1:]]
        for st in states:
            try:
                t = st.decode("ascii").strip()
            except (UnicodeDecodeError, AttributeError):
                continue
            if _CODE_PIECE.fullmatch(t) and t not in out:
                out.append(t)
    return out


def _side_texts(doc):
    """The document's top-level text fields that are no header, key or selector field and not `data`."""
    return [(k, v) for k, v in doc.items() if isinstance(k, str) and isinstance(v, str) and k != "data"
            and k.lower() not in META and not _KEYISH.search(k) and k not in SELECTORS]


def joined_codes(doc, value, own) -> list:
    """[(name, code, where)] for a code cut over numbered side fields (p1, p2; part_1, part_2) or a named pair
    (head and tail, first and second, ...): each piece read by the document's own codec to exactly one piece
    of an answer code and the pieces joined in their numbers' order, or else the texts joined in that order
    and read as one. Groups of 2 to JOIN_PIECES fields numbered from 0 or 1 without a gap; JOIN_GROUPS."""
    texts = dict((k, v) for k, v in _side_texts(doc) if 0 < len(v) <= MAX_PIECE)
    groups = {}
    for k in texts:
        m = _NUMBERED_FIELD.match(k)
        if m and m.group(1):
            groups.setdefault(m.group(1), []).append((int(m.group(2)), k))
    ordered = []
    for members in groups.values():
        members.sort()
        nums = [n for n, _ in members]
        if 2 <= len(nums) <= JOIN_PIECES and nums == list(range(nums[0], nums[0] + len(nums))) and nums[0] in (0, 1):
            ordered.append([k for _, k in members])
    for a, b in _PAIR_NAMES:
        for k in texts:
            if k.endswith(a):
                kb = k[:-len(a)] + b
                if kb in texts and [k, kb] not in ordered:
                    ordered.append([k, kb])
    # Day 23 look-ahead D05 + edge hardening: lettered GROUPS (part_a/part_b[/part_c/part_d], a/b/c) the named-pair
    # and numbered-suffix rules miss. A field ending in a single lowercase letter whose stem is empty (bare `a`) or
    # ends with a separator (`part_` + the letter): group the siblings by stem, order by letter, and keep a
    # consecutive run from `a` of 2 to JOIN_PIECES pieces (so part_a/part_b/part_c/part_d all join, not only the
    # pair). The separator/length guard keeps a word that merely ends in a letter (media) from pairing with an
    # unrelated sibling; a gap (a,c) or a run that does not start at `a` (b,c) is left alone (fail-closed).
    lettered = {}
    for k in texts:
        if k[-1:].isalpha() and k[-1:].islower() and (len(k) == 1 or k[-2] in "_-"):
            lettered.setdefault(k[:-1], []).append((k[-1], k))
    for members in lettered.values():
        members.sort()
        chars = [c for c, _ in members]
        if 2 <= len(chars) <= JOIN_PIECES and chars == [chr(ord("a") + i) for i in range(len(chars))]:
            grp = [k for _, k in members]
            if grp not in ordered:
                ordered.append(grp)
    out = []
    for names in ordered[:JOIN_GROUPS]:
        if not own[3](2 * len(names) + 1):
            break
        got = None
        pieces = [_codec_states(doc, texts[n]) for n in names]
        if all(len(x) == 1 for x in pieces):
            joined = "".join(x[0] for x in pieces)
            got = joined if base.ANSWER.fullmatch(joined) else None
        got = got or own[0]("".join(texts[n] for n in names))
        if not got:
            # Day 23 look-ahead D05: the halves stored as PLAIN code fragments (p1="ANS-1234", p2="5678...";
            # part_a/part_b), not encoded under the document's codec. Join them as they stand, keep only an exact
            # code. The judged codec's `data` is a decoy; this demotes it to <codec>:second-code (the decoy first).
            plain = "".join(texts[n] for n in names)
            got = plain if base.ANSWER.fullmatch(plain) else None
        if got and got != value:
            out.append((_slug("field:@%s:joined" % "+".join(_slug(n, 16) for n in names), 96), got,
                        "%s, fields %s joined" % (PUZZLE, "+".join(names))))
    return out


def _long_dense(doc, own):
    """Deterministic plan (run lengths and the document's own read-cost only; no decode) for the DENSE,
    every-offset scan of the long side fields the strided reading of window_codes cannot cover exhaustively.

    Returns (plan, partial): `plan` is [(k, run, [offsets])] for the runs that will be read at EVERY offset
    (0..n-L) under the document's own codec, within a fresh OWN_UNITS budget; `partial` is True when a varied
    class-run (at least L characters outside any repeated-character filler run) is left only partly scanned.

    window_codes reads `plan` (so a code in a short/medium run is FOUND and offered as a second code);
    long_field_unscanned returns `partial` (so a run the scan could not fully cover fails closed to an unsure
    pick, never the decoy plain). The two share this plan so they always agree on which runs are fully covered.

    Why this is needed: window_codes's strided reading steps by cls[1] (2 for hex, 4 for base64/url), so for a
    strided class it NEVER reads every offset of a run -- a code at a phase-shifted offset (any offset not a
    multiple of the stride from the run's start/end) was missed, and long_field_unscanned's old `n - L + 1 <=
    LONG_WINDOWS + ANCHORS` shortcut wrongly called such a run "fully scanned", so a decoy in `data` stood PLAIN
    while the real code sat at that offset in a >256-character side field (wave12 review: the multi-run / short-
    run hex & reverse decoy family, 59 WRONG-plain of the offset sweep)."""
    read, L, cls, spend, cost = own
    if cls is None:
        return [], False
    stride = cls[1]
    per_read = READ_FIXED + COST_WEIGHT * cost
    budget = OWN_UNITS
    plan, partial = [], False
    for k, v in doc.items():
        if (not isinstance(k, str) or not isinstance(v, str) or k == "data" or not MAX_PIECE < len(v) <= LONG_FIELD
                or _KEYISH.search(k) or k.lower() in _FIELD_STRUCTURAL):
            continue
        for run in cls[0].finditer(v):
            r = run.group(0)
            n = len(r)
            need = n - L + 1
            if need <= 0:
                continue
            if stride == 1 and need <= LONG_WINDOWS + ANCHORS:
                continue   # a stride-1 class: the strided reading already reads every offset of this run
            # Only VARIED content can hide a code at an offset the strided/anchor reading misses. A run that is
            # mostly repeated-character filler (varied < L) cannot hold a whole code away from a filler edge, and
            # a code next to filler is read by the filler-edge anchors; such a run stays safe (as the committed
            # long_field_unscanned had it), so it is neither scanned densely nor counted partial.
            varied = n - sum(m.end() - m.start() for m in _FILLER.finditer(r))
            if varied < L:
                continue
            if need <= DENSE_CAP and need * per_read <= budget:
                plan.append((k, run, list(range(0, need))))
                budget -= need * per_read
            else:
                partial = True   # too long for the budget/cap to cover every offset: fail closed
    return plan, partial


def window_codes(doc, value, own) -> list:
    """[(name, code, where)] for a text field longer than MAX_PIECE (up to LONG_FIELD characters; a header
    text too) with the encoded code inside it: windows of len(data) characters inside a run of the class
    `data` is written in (_offsets: the run's end and start, then every stride), each read by the
    document's own codec. LONG_WINDOWS windows in all, then every offset of the runs _long_dense can afford
    (so a phase-shifted code a strided class never aligns to is still FOUND)."""
    read, L, cls, spend, _cost = own
    if cls is None:
        return []
    out, left = [], LONG_WINDOWS
    pad = _pad_of(doc.get("data")) if cls[1] == 4 else 0
    later, done = [], set()   # (field, run, offset) of the anchored windows: read only after every strided
                              # window, apart from LONG_WINDOWS; `done` is the offsets the strided phase read

    def take(k, run, i):
        got = read(run.group(0)[i:i + L])
        if got and got != value and got not in {c for _, c, _ in out}:
            out.append((_slug("field:@%s:window" % _slug(k, 24), 96), got,
                        "%s, field %s at %d" % (PUZZLE, k, run.start() + i)))
    for k, v in doc.items():
        if (not isinstance(k, str) or not isinstance(v, str) or k == "data" or not MAX_PIECE < len(v) <= LONG_FIELD
                or _KEYISH.search(k) or k.lower() in _FIELD_STRUCTURAL):
            # wave12 adversarial review: a non-structural META long field (encoding, version, alg, ...) was skipped
            # here, so a decoy in `data` stood plain while the real code sat windowed in such a field; only the
            # three structural keys are skipped now, as in field_codes.
            continue
        for run in cls[0].finditer(v):
            n = len(run.group(0))
            # Every anchor is kept for the second phase, and the strided phase records the offsets it ACTUALLY read
            # (`done`). Before, an anchor was dropped merely for being a THEORETICAL strided offset (`i not in
            # strided`), but the strided loop reads only the first LONG_WINDOWS of them, so a code at a stride-
            # aligned offset past that cap -- almost any offset in a long run, forward- or backward-strided -- was
            # never read and the decoy stood plain (wave12 adversarial review, the D05 long-field family).
            later.extend((k, run, i) for i in _anchors(run.group(0), L, cls[1], pad))
            for i in _offsets(n, L, cls[1]):
                if left <= 0:
                    break
                if not spend():
                    return out
                left -= 1
                done.add((id(run), i))
                take(k, run, i)
    read_anchors = 0
    for k, run, i in later:
        if read_anchors >= ANCHORS:
            break
        if (id(run), i) in done:
            continue
        if not spend():
            break
        done.add((id(run), i))
        read_anchors += 1
        take(k, run, i)
    # The dense pass (wave12 review): read EVERY offset of the runs _long_dense can fully afford, so a code at a
    # phase-shifted offset a strided class never aligns to is FOUND here and offered as a second code. A run the
    # plan cannot cover is left to long_field_unscanned, which fails it closed to an unsure pick.
    plan, _ = _long_dense(doc, own)
    for k, run, offsets in plan:
        for i in offsets:
            take(k, run, i)
    # wave17: the sub-256 side fields, scanned exactly as a long field but only after every long field above, so
    # long-field behaviour is untouched. A code embedded at an offset the whole-field transform search (field_codes)
    # cannot isolate (a run of filler of its own class before the code, or the whole-field decode misaligned) is
    # reached here. take() only keeps a strict exact code (read() returns only an exact answer), so this can only
    # demote a plain answer, never make a wrong one plain; with nothing read it returns `out` unchanged.
    sub_left = min(left, SUB_WINDOWS)
    sub_later = []
    for k, v in doc.items():
        if sub_left <= 0:
            break
        if (not isinstance(k, str) or not isinstance(v, str) or k == "data" or not 16 <= len(v) <= MAX_PIECE
                or _KEYISH.search(k) or (k.lower() in META and k.lower() not in HEADER_TEXTS)):
            continue
        for run in cls[0].finditer(v):
            n = len(run.group(0))
            if n < L:
                continue
            strided = _offsets(n, L, cls[1])
            sub_later.extend((k, run, i) for i in _anchors(run.group(0), L, cls[1], pad) if i not in strided)
            for i in strided:
                if sub_left <= 0:
                    break
                if not spend():
                    return out
                sub_left -= 1
                take(k, run, i)
    for k, run, i in sub_later[:ANCHORS]:
        if sub_left <= 0 or not spend():
            break
        sub_left -= 1
        take(k, run, i)
    return out


def long_field_unscanned(doc, own) -> bool:
    """True when the document has a non-key, non-structural text field longer than MAX_PIECE whose class-run the
    window scan (_long_dense's plan) cannot cover at every offset -- a run too long for the budget, or (for a
    strided class, hex/base64/url) one the strided reading steps over phase-shifted offsets of and the dense
    plan could not afford.

    A code could then sit at an offset window_codes never reads, so a plain reading of `data` must NOT be banked
    over it (fail-closed, never-guess; wave12 adversarial review, the pad-less/filler-less and short-run strided
    decoy families). Only for a document the Day 4 solver reads by a judged codec (own_codec is not None); a legit
    puzzle carries no such long side field, so no correct plain answer is weakened, and a found competing code is
    still offered first. Shares _long_dense with window_codes, so a run the scan did read in full never fails
    closed and a run it could not is never called scanned (the old `n - L + 1 <= LONG_WINDOWS + ANCHORS` shortcut
    ignored the stride and wrongly called a short strided run fully scanned)."""
    if not own:
        return False
    if own[2] is None or not isinstance(doc, dict):
        return False
    _, partial = _long_dense(doc, own)
    return partial


# A whole clear answer code (ANS- + 16 hex) matched WITHOUT the boundary look-arounds of ANS_LOOSE/_ANS_RAW. Those
# guards are exactly what hides X02's code from the package scan -- a clear code pressed against alphanumeric filler
# -- so this loose form is the one signal that separates a hidden clear code from ordinary prose/URL/UUID/hex text.
_CLEAR_CODE = re.compile(r"ANS-[0-9A-Fa-f]{16}")


def long_clear_field_unscanned(doc) -> bool:
    """True when the document has a non-key, non-structural, non-selector text field longer than MAX_PIECE that
    holds a CODE-SHAPED run the boundary-guarded package scan and the codec-class window scan both miss: a whole
    clear ANS code (`ANS-` + 16 hex) glued into filler, where the look-arounds of ANS_LOOSE/_ANS_RAW never cut the
    code out of the glue. The `ANS-` literal is the lane code's invariant marker: a run matching the lane's ANS/code
    pattern is what tells a hidden clear code from ordinary text.

    NARROWED (Day 28 review): it fires ONLY on such a code-shaped run, not on any long varied stretch. Before, a
    maximal non-filler stretch of 20+ characters was enough, so natural English prose, a URL, a UUID, a hex blob, a
    base64 thumbnail or a changelog -- none of which repeat a character four times -- all tripped it and demoted a
    legitimate plain (confirmed: a 284-char natural `description` beside a correct base64 `data` stood plain and was
    wrongly demoted; costly on a tight Mastery where an unsure id cannot be probed). Now such a field, with no
    `ANS-`+16-hex run, does NOT demote. The X02 decoy (a clear ANS code glued into a >256-char side field) still
    demotes: the clear code is present, so this returns True and the lone `data` reading is held as an unsure
    candidate scoped to the delivery, never banked plain.

    Fail-closed, never-guess, restrict-only: a legit puzzle carries no such long side field (every saved puzzle
    document holds only schema/day/codec/data and the codec's short key/parts/order), so no correct plain answer is
    weakened; it can only demote the lone reading to an unsure pick scoped to this delivery, never offer or bank a
    wrong answer. Complements long_field_unscanned, which covers an ENCODED run of the data codec's own class."""
    if not isinstance(doc, dict):
        return False
    for k, v in doc.items():
        if (not isinstance(k, str) or not isinstance(v, str) or k == "data" or len(v) <= MAX_PIECE
                or _KEYISH.search(k) or k.lower() in _FIELD_STRUCTURAL
                or (k in SELECTORS and _resolve(doc, v) is not _MISSING)):
            continue
        if _CLEAR_CODE.search(v):
            return True
    return False


def header_codes(doc, value) -> list:
    """[(name, code, where)] for a header text (hint, note, description) of HEADER_MIN to MAX_PIECE characters
    that the field look's short search turns into an answer code with NO key of the document. Day 18's G09
    decision stands: a header field is never a key or a step of the document's own reading, and a short one
    (G09's hint 'b') is not read at all; a hint the author wrote for the reader gives no code, at a few
    hundred states."""
    out, names = [], {}
    for k in doc:
        if isinstance(k, str) and k.lower() in HEADER_TEXTS and isinstance(doc[k], str) and k.lower() not in names \
                and HEADER_MIN <= len(doc[k]) <= MAX_PIECE:
            names[k.lower()] = k   # one place a header name: Note, NOTE and note do not crowd out hint
    for k in list(names.values())[:HEADER_FIELDS]:
        v = doc[k]
        if not isinstance(v, str) or not HEADER_MIN <= len(v) <= MAX_PIECE or answers_in(v.encode("utf-8", "replace")):
            continue
        try:
            hit, _, _ = search_text(v, [])
        except Ambiguous:
            continue
        if hit and hit[0] != value:
            out.append((_slug("field:@%s:search:%s" % (_slug(k, 24), ">".join(hit[1])), 96), hit[0],
                        "%s, header field %s after %s" % (PUZZLE, k, ">".join(hit[1]))))
    return out


def int_list_codes(doc, value) -> list:
    """[(name, code, where)] for a side field holding a list of 16 to MAX_PIECE byte values (a Java byte[],
    signed or not) that the field look's short search, with the document's keys, turns into an answer code.
    Not `data` (data_candidates reads that), not a key or header field, and not an order (a permutation of
    0..n-1 or 1..n); at most INT_FIELDS."""
    lists = [(k, v) for k, v in doc.items() if isinstance(k, str) and k != "data" and isinstance(v, list)
             and 16 <= len(v) <= MAX_PIECE and not _KEYISH.search(k) and k.lower() not in META
             and all(isinstance(x, int) and not isinstance(x, bool) and -128 <= x <= 255 for x in v)
             and sorted(v) not in (list(range(len(v))), list(range(1, len(v) + 1)))]
    if not lists:
        return []
    keys = [(k, tag) for k, tag in key_candidates(doc) if len(k) <= 16][:FIELD_KEYS]
    out = []
    for k, v in lists[:INT_FIELDS]:
        try:
            hit, _, _ = search(bytes(x & 255 for x in v), keys, [], _FOREVER, max_depth=FIELD_DEPTH,
                               max_nodes=FIELD_NODES, block=False)
        except Ambiguous:
            continue
        if hit and hit[0] != value:
            moves = ":search:" + ">".join(hit[1]) if hit[1] else ""
            out.append((_slug("field:@%s:ints%s" % (_slug(k, 24), moves), 96), hit[0],
                        "%s, byte list %s after %s" % (PUZZLE, k, ">".join(hit[1]) or "nothing")))
    return out


def _encoded_run(text, cls) -> bool:
    """Does a run of the class look like encoded material, not a name? A digit or a base64 symbol in it, and
    for a base64 class both letter cases (a Java or Kotlin identifier has neither digit nor symbol; base64 of
    twenty bytes without one is under one in a hundred, and a miss only leaves the answer as it was)."""
    if not re.search(r"[0-9+/=_-]", text):
        return False
    return cls[1] != 4 or (re.search(r"[a-z]", text) is not None and re.search(r"[A-Z]", text) is not None)


def dex_codes(members, value, own, pad=0) -> list:
    """[(name, code, where)] for a string of the app's dex (at most DEX_STRING characters) that holds the code
    under the document's own codec: in each run of the class `data` is written in that is len(data) to
    len(data) + DEX_SLACK characters long, every window of len(data) characters, read by name. Type descriptors are left out (_FRAMEWORK); DEX_WINDOWS windows
    in all, in the members' order, and DEX_SCAN characters of strings scanned in all. Named
    `apk-string:dex:own-codec`: offered only when the package look was complete (second_codes' bounds), so
    the caller does not ask for it otherwise (document_codes' `dex`).

    Day 20 look-ahead row 3: a window the document's codec reads to nothing is then given the field look's
    short search with NO key (search_text: a code under another xor key is read by its `ANS-` start, as the
    package look reads a dex string), named `apk-string:dex:search:<path>`; DEX_SEARCHES windows in all, and
    only a window whose `=` padding is exactly `pad`'s (the `=` that end `data`; none when `pad` is 0)."""
    read, L, cls, spend, _cost = own
    if cls is None:
        return []
    out, left, scan, searches = [], DEX_WINDOWS, DEX_SCAN, [DEX_SEARCHES]

    def searched(win):
        if searches[0] <= 0 or "=" in (win[:-pad] if pad else win) or (pad and not win.endswith("=" * pad)):
            return None
        searches[0] -= 1
        try:
            hit, _, _ = search_text(win, [])
        except Ambiguous:
            return None
        return hit
    for n, body in members.items():
        if not n.endswith(".dex") or len(body) > MAX_CODE:
            continue
        for raw in dex_strings(body):
            if not L <= len(raw) <= DEX_STRING or _FRAMEWORK.match(raw):
                continue
            scan -= len(raw)
            if scan < 0:
                return out
            try:
                text = raw.decode("ascii")
            except UnicodeDecodeError:
                continue
            for run in cls[0].finditer(text):
                if not L <= len(run.group(0)) <= L + DEX_SLACK or not _encoded_run(run.group(0), cls):
                    continue
                for i in range(0, len(run.group(0)) - L + 1):
                    if left <= 0 or not spend():
                        return out
                    left -= 1
                    win = run.group(0)[i:i + L]
                    got, name, how = read(win), "apk-string:dex:own-codec", "a string read by the document's codec"
                    if not got:
                        hit = searched(win)
                        if hit:
                            path = ">".join(hit[1]) or "as-it-stands"
                            got, name, how = hit[0], _slug("apk-string:dex:search:" + path, 96), "a string after " + path
                    if got and got != value and got not in {c for _, c, _ in out}:
                        out.append((name, got, "%s, %s" % (n, how)))
    return out


def second_codes(members, hit, clock, blob=b"", dups=()) -> tuple:
    """([(name, code, where)], complete, clear_truncated) for the answer codes the package holds beside the one `hit`
    gives (Day 14 look-ahead; the player's decision of 2026-10-13 reverses row 270's: the answer then
    offers both, the hit's own first, and is never plain until the judge has said which).

      field:@<name>        another text field of the puzzle document that the document's own
                           (judged) codec decodes to another code
      twin-entry           an earlier zip entry of the document's name that gives another code by name
      <route>              a puzzle-shaped document in another member (`base64:doc-moved`), by name
      apk-string:<kind>[:base64|:hex]   a code in clear, or under base64 or hex, in a member's bytes,
                           in a cell of a small SQLite member, or in the archive's own bytes
      keystore:<format>    a secret entry of a keystore the package ships (keystores.py)

    Nothing is searched: every reading is by name or as it stands (document_codes, which _solve
    asks after this, searches the document's other fields beside a plain answer).

    The look is bounded by what it reads, never by time (review of 2026-10-13: under a 30 ms clock the
    same package was answered plain on one run and unsure on the next, so base, gate replay and clock
    could disagree). It reads at most SECOND_MEMBERS members and SECOND_BYTES bytes (the members and the
    archive together), SECOND_DOCS small members as documents, and SECOND_KDF iterations of keystore
    key derivation. `complete` is True only when the whole package fits those bounds, which is a fact
    of the package and the same on every run. The caller offers both codes only for a complete look.
    `clear_truncated` is True when the member or byte bound left a member's bytes UNSCANNED (more members
    than the look reads, or the SECOND_BYTES budget hit): a real answer code may lie in the unscanned bytes
    beyond the bound, so the caller demotes a plain reading to an unsure second code rather than bank a
    possible decoy (the D03 shape: a judged-codec decoy in `data`, the real code in a member past the bound).
    A past-bounds look that did NOT truncate the clear scan (only more documents or a keystore than the look
    opens) still keeps this module's own reading. `clock`
    is the APK's own: it only ends the reading of a second document that takes too long, and a look
    that ran into it is not complete."""
    out, seen = [], {hit.value}
    state = {}

    def add(name, value, where):
        if value and value not in seen and len(out) < MAX_NAMED:
            seen.add(value)
            out.append((name, value, where))

    rest = [(n, b) for n, b in members.items() if n != PUZZLE]
    complete = (len(rest) <= SECOND_MEMBERS
                and sum(len(b) for _, b in rest) + len(blob) + len(members.get(PUZZLE) or b"") <= SECOND_BYTES)
    # A clear-code scan truncated by the member or byte bound leaves members/bytes beyond it UNSCANNED, so it
    # cannot rule out a real answer code hiding there. The caller treats this as fail-closed (never-guess): the
    # document's own reading is demoted to unsure rather than banked plain, so a judged-codec decoy in `data`
    # with the real code past the bound is never submitted plain (the D03 shape). Set precisely where a member's
    # bytes go unscanned: more members than the look reads, or the byte budget hit in the loop below.
    clear_truncated = len(rest) > SECOND_MEMBERS
    body, doc = members.get(PUZZLE), None
    if body is not None and len(body) <= MAX_WRAPPED:
        doc, _ = _json(body, whole=True)
        steps = base_steps(doc) if isinstance(doc, dict) else []
        if steps and all(s_ in base.NAMED for s_ in steps) and base_cost(doc, steps) <= BASE_COST:
            fields = [(f, t) for f, t in flat(doc) if f != "data" and isinstance(t, str) and 16 <= len(t) <= MAX_PIECE
                      and f.split(".")[0].lower() not in META and not _KEYISH.search(f)]
            complete = complete and len(fields) <= 16
            for field, text in fields[:16]:
                try:
                    add("field:@" + _slug(field, 24), base.by_codec({**doc, "data": text}), "%s, field %s" % (PUZZLE, field))
                except Exception:
                    continue
    for earlier in list(dups)[:4]:
        obj, _ = _json(earlier, whole=True) if len(earlier) <= SECOND_DOC_BYTES else (None, "")
        for other in (named_hits(obj, ["doc-twin-entry"], lambda: [], clock) if obj is not None else ()):
            if other is None:
                complete = False
            elif other.confidence != "low":
                add("twin-entry", other.value, "an earlier zip entry named %s" % PUZZLE)
    complete = complete and len(dups) <= 4
    room, docs = SECOND_BYTES, 0
    for n, other_body in rest[:SECOND_MEMBERS]:
        if len(other_body) > room:
            clear_truncated = True
            break       # past the bytes this look reads (complete is False already)
        room -= len(other_body)
        kind = member_kind(n, other_body)
        if (kind in ("asset", "member") and _DOC_MEMBER.search(n) and len(other_body) <= SECOND_DOC_BYTES
                and not _SIGNING.match(n) and other_body[:1] not in (b"", b"\x7f")):
            docs += 1
            if docs > SECOND_DOCS:
                complete = False
            else:
                obj, wrap = _json(other_body)
                fmt = ""
                if obj is None and not other_body.startswith(b"SQLite format 3\x00"):
                    try:
                        got = asset_docs.parse(n, other_body, known=lambda name: _known(ALIASES.get(name, name)))
                    except Exception:
                        got = None
                    if got:
                        obj, fmt = got[0]
                if obj is not None and any(True for _ in docs_in(obj)):
                    where = ["doc-moved"] + (["doc-encoded"] if wrap else []) + (["doc-" + fmt] if fmt else [])
                    for other in named_hits(obj, where, lambda: [], clock):
                        if other is None:
                            complete = False
                        elif other.confidence != "low":
                            add(route_name(other), other.value, "a document in " + n)
        for m in _scan(_ANS_RAW, other_body, _FOREVER):
            add("apk-string:" + kind, m.group(0).decode(), n)
        for m in _scan(_ANS_WIDE, other_body, _FOREVER):
            add("apk-string:%s:utf16" % kind, m.group(0).decode("utf-16le"), n + " (UTF-16)")
        if other_body.startswith(b"SQLite format 3\x00") and len(other_body) <= NOTE_CHUNK:
            codes, read = sqlite_codes(other_body)
            complete = complete and read
            for code, cell in codes.items():
                add("apk-string:" + kind, code, "%s, cell %s" % (n, cell))
        for code, how in encoded_codes(other_body).items():
            add("apk-string:%s:%s" % (kind, how), code, "%s (%s)" % (n, how))
    own = None
    if body is not None and len(body) <= SECOND_BYTES:
        # The document's own member: a code in clear beside the one it decodes to. Not its `data`
        # when that is what the codec read (rot5 turns one code into another): only where the code
        # was laid out from other fields (split) is a code in `data` a second one.
        doc = doc if isinstance(doc, dict) else {}
        read_data = not any(ALIASES.get(s_, s_) in JOIN + WEAVE for s_ in steps_of(doc)[0]) if doc else True
        own = strict(doc["data"].encode("utf-8", "replace")) if read_data and isinstance(doc.get("data"), str) else None
        for m in _scan(_ANS_RAW, body, _FOREVER):
            if m.group(0).decode() != own:
                add("apk-string:asset", m.group(0).decode(), PUZZLE)
    for m in _scan(_ANS_RAW, blob[:max(0, room)], _FOREVER):
        if m.group(0).decode() != own:      # a stored (not deflated) document shows its `data` in the archive's bytes too
            add("apk-string:archive", m.group(0).decode(), "the archive's own bytes")
    for fmt, alias, secret in keystore_secrets(members, clock, SECOND_KDF, state):
        code = strict(secret) or (strict(secret.decode("utf-16-be", "ignore").encode()) if len(secret) == 40 else None)
        add("keystore:" + fmt, code, "keystore entry %r" % alias)
    return out, complete and not state.get("cut") and not clock.up(), clear_truncated


def document_codes(members, hit, others, search=True, dex=False) -> tuple:
    """([(name, code, where)], ahead, targets): what the usual document adds to second_codes' `others`
    (Day 18 look-ahead).

    With `search` (beside a plain answer: the decoy shape), the codes field_codes finds in the
    document's other top-level fields, named `field:@<field>:search:<path>`, at most MAX_NAMED, each
    with a value of its own and not the hit's. `ahead` names the codes, of `others` too, that stand in
    a field a selector of the document points at ({"use": "b"}): the answer offers those before this
    module's own reading. `targets` are the fields the selectors name, sorted: the answer's key carries
    them, so a name the judge accepted where the selector named one field never answers plain where
    it names another (review of 2026-10-17: a variant whose `use` flipped to `data` was answered plain
    with the decoy the accepted name pointed at)."""
    body = members.get(PUZZLE)
    doc = _json(body, whole=True)[0] if body is not None and len(body) <= MAX_WRAPPED else None
    if not isinstance(doc, dict):
        return [], set(), []
    more, seen = [], {hit.value}
    budget = [FIELD_CHARS]   # the field look's characters, for the top-level fields and the nested ones together
    used = set()             # the key and IV fields a side cipher read as material for a text that decoded
    side = cipher_codes(doc, hit.value, used)
    for field, code, path in (field_codes(doc, hit.value, budget, skip=used) if search else ()):
        if code not in seen and len(more) < MAX_NAMED:
            seen.add(code)
            more.append((_slug("field:@%s:search:%s" % (_slug(field, 24), ">".join(path)), 96), code,
                         "%s, field %s after %s" % (PUZZLE, field, ">".join(path) or "nothing")))
    # Day 19 look-ahead: nested objects with their own codec or key, and side fields under a cipher the
    # document names by its key field. By name beside any answer; the nested search only beside a plain one.
    for name, code, where in nested_codes(doc, hit.value, search, budget) + side:
        if code not in seen and len(more) < MAX_NAMED:
            seen.add(code)
            more.append((name, code, where))
    if search:
        # Day 20 build: a code cut over two fields, a field longer than MAX_PIECE, a header text, a byte list,
        # a string of the app's dex. Beside a plain answer only, each bounded by counts, never by a clock.
        own = own_codec(doc)
        extra = header_codes(doc, hit.value) + int_list_codes(doc, hit.value)
        if own:
            extra = joined_codes(doc, hit.value, own) + window_codes(doc, hit.value, own) + extra
        # the dex look only when its code could be offered: the package look was complete (`dex`)
        for name, code, where in extra + (dex_codes(members, hit.value, own, _pad_of(doc.get("data")) if own[2] and own[2][1] == 4 else 0)
                                     if own and dex else []):
            if code not in seen and code not in {c for _, c, _ in others} and len(more) < MAX_NAMED:
                seen.add(code)
                more.append((name, code, where))
    targets = sorted(selected(doc))
    chosen = {_field_target("field:@" + _slug(f, n)) for f in targets for n in (24, 40)}
    ahead = {name for name, _, _ in list(others) + more if _field_target(name) in chosen}
    return more, ahead, targets


def package_answer(members, opaque, far, clock, blob=b"", pkg=None):
    """({answer code: route}, complete) for the answer codes the package holds outside any puzzle document.

    As it stands: an exact code in any member's bytes (ASCII or UTF-16), or in the archive's own
    bytes outside its members (the signing block, the comment). Under transforms: a member that is
    no document, and every string of the dex, the manifest, the resource table, compiled XML,
    native libraries and small text members, each through the bounded search. `complete` is False
    when the clock ran out first: then nothing can be said about how many codes there are.
    Raises Ambiguous when one text holds two."""
    found = {}
    whole = True
    for n, body in members.items():
        if len(body) > MAX_MEMBER and clock.up():
            return found, False    # code members of 8 MiB each: the scan itself is part of the budget
        kind = member_kind(n, body)
        if body.startswith(b"SQLite format 3\x00"):
            # a database: every TEXT and BLOB cell as a string of its own, under the name the scan
            # of the bytes gives a code it does find (one fact, one name, whatever stands beside it)
            codes, read = sqlite_codes(body)
            whole = whole and read
            for value in codes:
                found.setdefault(value, "apk-string:" + kind)
        if kind == "hermes" and app_bundles.hermes_strings(body) is not None:
            continue    # its storage packs strings back to back: the string table says where one ends
        for m in _ANS_RAW.finditer(body):
            found.setdefault(m.group(0).decode(), "apk-string:" + kind)
        for m in _ANS_WIDE.finditer(body):
            found.setdefault(m.group(0).decode("utf-16le"), "apk-string:%s:utf16" % kind)
        if kind == "lib" and app_bundles is not None:      # a Dart string object, ended by its length field
            for value in app_bundles.dart_codes(body):
                found.setdefault(value, "apk-string:lib:dart-string")
        if len(body) <= MAX_MEMBER:
            for value, how in encoded_codes(body).items():     # a preferences value, a database cell, a string pool
                found.setdefault(value, "apk-string:%s:%s" % (kind, how))
    for m in _ANS_RAW.finditer(blob[:8 << 20]):
        found.setdefault(m.group(0).decode(), "apk-string:archive")
    # a secret entry of a keystore the package ships, opened with a stated or usual password (keystores.py)
    for fmt, _, secret in keystore_secrets(members, clock):
        if strict(secret):
            found.setdefault(strict(secret), "keystore:" + fmt)
    for n in opaque:
        body = members[n].strip()
        if not body or len(body) > MAX_STATE:
            continue
        if clock.up():
            return found, False
        hit, _, _ = search(body, [], [], clock, far, max_nodes=3000)
        if hit:
            found.setdefault(hit[0], "apk-string:%s:%s" % (member_kind(n, members[n]), ">".join(hit[1]) or "as-it-stands"))
    seen = set()
    for kind, s in (package_strings(members, clock.stop) if pkg is None else pkg):
        if not 20 <= len(s) <= 256 or s in seen or _FRAMEWORK.match(s):
            continue
        seen.add(s)
        if clock.up():
            return found, False
        hit, _, _ = search(s, [], [], clock, max_depth=4, max_nodes=300)
        if hit:
            found.setdefault(hit[0], "apk-string:%s:%s" % (kind, ">".join(hit[1]) or "as-it-stands"))
    return found, whole and not clock.up()


def package_pieces(members, opaque, pkg=None):
    """(answer code, route) when the package holds one code cut in pieces outside any document, else None.

    files    small members whose whole text is a piece (ANS- and some hex digits; hex digits): in
             the order of their names they must give exactly one code (`apk-pieces:files-by-name`)
    strings  among the strings of the dex, the manifest and the resources: exactly one that starts
             a code (ANS- and 3 to 15 digits) and exactly one of the length that completes it
             (`apk-pieces:strings`). Three or more loose pieces have no order to read, so they are
             nothing."""
    def natural(name):
        # by the file's own name (the pieces may sit in assets/, res/raw/ and META-INF/), then its folder
        return [[(0, int(t), "") if t.isdigit() else (1, 0, t) for t in re.split(r"(\d+)", part)]
                for part in (name.rsplit("/", 1)[-1], name)]

    files = [(n, members[n].strip()) for n in sorted(opaque, key=natural) if len(members[n]) <= 64]
    files = [(n, b) for n, b in files if _PIECE_HEAD.fullmatch(b) or _PIECE_TAIL.fullmatch(b)]
    if len(files) >= 2 and sum(b.startswith(b"ANS-") for _, b in files) == 1:
        value = b"".join(b for _, b in files).decode()
        if base.ANSWER.fullmatch(value):
            return value, "apk-pieces:files-by-name"
    pool = list(dict.fromkeys(s for kind, s in (package_strings(members) if pkg is None else pkg)
                              if kind in ("dex", "manifest", "resources")))
    heads = [s for s in pool if _PIECE_HEAD.fullmatch(s) and 7 <= len(s) <= 17]
    if len(heads) == 1:
        tails = [s for s in pool if len(s) == 20 - len(heads[0]) and _PIECE_TAIL.fullmatch(s)]
        if len(tails) == 1:
            return (heads[0] + tails[0]).decode(), "apk-pieces:strings"
    return None


SIBLING = 0.12           # seconds one further candidate gets, by name only, behind a hit that is held
MAX_NAMED = 4            # candidates that disagree, as the NOTE names them


def named_hits(obj, base_where, apk_keys, clock, first=None):
    """What the documents of one parsed member give by name alone, in the order solve_members
    reads them: a Hit each, or None for one that was not read to its end in its SIBLING seconds.

    Its pieces as documents of their own come first, then every document in it; with `first`
    only the documents from that number on (the caller has read what stands before). A
    document whose named codec gives no code gives nothing: no search and no key from the
    package is spent on a candidate that only has to say whether it disagrees. Once the APK's
    own time is up nothing more is read: every document left is one that was not read."""
    def read(fn):
        if clock.up():
            return [None]
        short = Clock(max(0.0, min(SIBLING, clock.left())))
        hit = fn(short)
        return [hit] if hit or short.up() else []

    if first is None:
        yield from read(lambda short: fragments(obj, ".".join(base_where), apk_keys, short))
    for i, (p, nested) in enumerate(docs_in(obj)):
        if i < (first or 0):
            continue
        p, marks = reshape(p)
        where = base_where + (["doc-nested"] if nested else []) + list(marks) + [m for m in [schema_mark(p)] if m]
        yield from read(lambda short: solve_doc(p, ".".join(where), apk_keys, short, named_only=True))


def native_libs(members) -> list:
    """The bodies of the APK's JNI libraries (lib/<abi>/*.so) among the members, outer package first."""
    return [b for n, b in members.items() if n.endswith(".so") and "lib/" in n.replace("!", "/")]


def native_hit(members, clock=None):
    """Day 15 (row 309): a Hit for a puzzle document whose codec is `native`, whose answer is the one
    answer code stored in the APK's native libraries (lib/*/*.so), or None for any other document.

    solve_doc returns None for a native document (NATIVE_NAMES), so the base would stop MISSING; the
    code is read here by apk_resources.native_secret and cross-checked against the document's own
    `data` (a `data` that holds a different code gives None). It is offered under mobile.codec/native,
    route native:so-secret, so the promoted seed answers Day 15 plain and the name carries to the
    cumulative Mastery. None when the libraries hold no code, or two that differ, or the document is
    not native: nothing is guessed."""
    body = members.get(PUZZLE)
    if body is None or len(body) > MAX_PUZZLE:
        return None
    doc, _ = _json(body, whole=True)
    steps = base_steps(doc) if isinstance(doc, dict) else []
    if not (steps and all(s_ in NATIVE_NAMES for s_ in steps)):
        return None
    data = doc.get("data") if isinstance(doc, dict) else None
    libs = native_libs(members)
    code = apk_resources.native_secret(libs, data if isinstance(data, str) else None)
    if code and base.ANSWER.fullmatch(code):
        return Hit(code, "medium", "native:so-secret", "native", ())
    # Day 16 look-ahead (row 312): the code did not stand in clear. The forecast is that the native
    # theme deepens to a code hidden behind one constant transform in the library (an XOR/ADD key byte,
    # or the code stored base64/hex/reversed). native_derive reads those, bounded, and each is offered
    # unsure under mobile.codec/native (the judged native:so-secret is not among them, so pick() stays
    # unsure): one base probe names the route and the cumulative Mastery is then plain. None when
    # nothing decodes, so the base is left MISSING rather than guessing.
    derived = apk_resources.native_derive(libs, data if isinstance(data, str) else None)
    derived = [(r, c) for r, c in derived if base.ANSWER.fullmatch(c)]
    if derived:
        # The further readings are OPTIONS (offered via labels.pick), not steps: the steps slot drives
        # the judged-chain plain path in decide() and _judged() expects codec-name strings, so a
        # (route, code) tuple there both hides the readings from offered() and raises in decide().
        return Hit(derived[0][1], "medium", derived[0][0], "native", (), tuple(derived[1:]))
    return None


def _bare_codec_pick(hit, p, members):
    """Row 367: the one LOW step-4 candidate solve_members holds (an answer-shaped `data` under a codec this
    module did not apply by name, with nothing else to confirm it) offered as a one-probe unsure pick
    `labels.pick('mobile.codec/<codec>', [('<codec>:plain', data)])` instead of None, so a bare-new-codec base
    (a new control name, `data` just holding the code in clear) closes in the opener's own pass via one base
    probe, as the Day 19 reflection fold-in (codec_more.OWN) would have, with no agent day_patch.

    Only when the reading is unambiguous: exactly one answer-shaped code in `data`; NO positional or
    within-alphabet move of the code (a rotation, a reversal, a chunk reversal, a weave, rot5 of its digits,
    rot18) reads a DIFFERENT valid code (so the unapplied codec cannot plausibly be one of those, which would
    make `data` a scrambled form rather than the answer — test_day14_mobile [12], the hostile cases of
    selftest); and no OTHER ANS- code stands in clear anywhere in the package (a decoy in `data` with the real
    code elsewhere in clear then keeps this None). Otherwise None (fails closed, exactly as before). It is still
    never plain: decide() offers it unsure under the codec's own key, so it reaches the judge only as a probe."""
    code = hit.value
    if not (isinstance(code, str) and base.ANSWER.fullmatch(code) and isinstance(p, dict)):
        return None
    # 0. the codec must be one NO reader of this module recognises — a genuinely novel control name (the
    # reflection shape, before `reflection` was folded into codec_more.OWN). A recognised transform (a text
    # layer, a shift, a cipher, an OWN name like json/lower/swapcase, a grid like spiral/snake) that was tried
    # and gave no code is handled by its own reader; here only a name nothing applies.
    steps = base_steps(p)

    def _applied(s):
        a = ALIASES.get(s, s)
        return (_known(a) or _simple_step(a) or a in codec_more.OWN or a in GRID_NAMES or a in CHAIN
                or a in NATIVE_NAMES or a in KEYSTORE_NAMES)
    if not steps or any(_applied(s_) for s_ in steps):
        return None
    # 1. exactly one answer-shaped reading in `data` (across every layout data_candidates reads)
    seen = set()
    for _layout, start in data_candidates(p):
        seen |= answers_in(start)
    if seen != {code}:
        return None
    # 2. no positional / within-alphabet move of the code reads a different valid code. For a code-shaped
    # `data` the solver's `positional` returns nothing (it skips a value that is already an answer), so the
    # moves are enumerated here against the code itself: every rotation, every reversal and chunk reversal, a
    # weave, and rot5 (its digits) and rot18. If any gives another valid code the reading is ambiguous — the
    # opaque codec could be that move — and the base is left MISSING rather than probe a guess.
    if _alphabet_variants(code):
        return None
    # 3. no different ANS- code in clear anywhere in the package
    for body in members.values():
        if any(other != code for other in answers_in(body)):
            return None
    codec = _slug(hit.codec) or "unnamed"
    return Hit(code, "medium", codec + ":plain", codec, ())


def _alphabet_variants(code) -> set:
    """Row 367: the DIFFERENT valid answer codes a positional or within-alphabet move reads `code` as — a
    rotation of the string, the string or its 16-character body reversed, chunks of 2/4/8 reversed or in
    reversed order, the two halves of the body woven, rot5 of the digits and rot18. A non-empty result means
    `data` is ambiguous (the unapplied codec could be one of these moves), so a bare-codec pick fails closed."""
    out, body = set(), code[4:]
    cand = [code[i:] + code[:i] for i in range(1, 20)]            # rotations of the whole string
    cand += ["ANS-" + body[::-1], code[::-1]]                     # body reversed, whole reversed
    for size in (2, 4, 8):
        chunks = [body[i:i + size] for i in range(0, 16, size)]
        cand.append("ANS-" + "".join(c[::-1] for c in chunks))   # each chunk reversed in place
        cand.append("ANS-" + "".join(chunks[::-1]))              # chunks in reversed order
    cand.append("ANS-" + "".join(x + y for x, y in zip(body[:8], body[8:])))  # halves woven
    for v in (_rot5(code.encode()), _rot5(base.t_rot13(code.encode(), {}) or b"")):  # rot5, rot18
        try:
            cand.append(v.decode("ascii"))
        except (UnicodeDecodeError, AttributeError):
            pass
    for v in cand:
        if v != code and isinstance(v, str) and base.ANSWER.fullmatch(v):
            out.add(v)
    return out


MAX_NAMED_MEMBERS = 4   # members of the package a puzzle document's fields name by path, read before the search


def _member_path(v, members):
    """The member a document's field names by its path ('assets/payload.dex', './assets/x', '/assets/x'), or None."""
    if not isinstance(v, str) or not 3 <= len(v) <= 256:
        return None
    n = v.strip()
    while n.startswith(("./", "/")):
        n = n[2:] if n.startswith("./") else n[1:]
    return n if n in members and n != PUZZLE and not _SIGNING.match(n) else None


NAMED_SEARCH_STRINGS = 8   # strings of the dex `data` names that the named search reads (20 to 128 bytes, no space)
NAMED_SEARCH_LEN = 128     # bytes of the longest string it reads (base64 of a code under two layers is 40 to 56)
NAMED_SEARCH_NODES = 64    # states of the bounded search for one of them (about 1 ms at worst; 300 took up to 20 ms)
NAMED_SEARCH_DEPTH = 2     # moves in one path, a keyless reading (prefix-key, prefix-rol) after them
NAMED_SEARCH_KEYS = 6      # the document's own keys (its key fields, as the Day 4 solver reads them) used as moves


def named_search(n, strings, doc, clock, saw):
    """A Hit for the one code the strings of the dex the document's `data` names give under a transform; or None.

    Day 21 build round 2 (docs/retro/day-21-predictions-mobile.md, prediction candidate 2: A12 base64, A17 two
    strings, A23 xor with the document's key). The package look reads these on the base's template in about 0.09 s,
    but on the Day 20 Time Trial's the search of the document's fields spends the whole budget first. Here the same
    readers run over that member's strings alone, before any document is searched:

      pieces   exactly one string that starts a code (ANS- and 3 to 13 digits) and exactly one of the length that
               completes it (package_pieces' rule), route `apk-pieces:named-strings`
      search   the first NAMED_SEARCH_STRINGS strings of 20 to 128 bytes with no space that are not framework names,
               each through the bounded search (NAMED_SEARCH_NODES states, NAMED_SEARCH_DEPTH moves, no block
               cipher) with the document's own keys as moves, route `apk-string:dex:named-search:<path>`; about
               8 ms at worst for the member (eight strings of random hex), well inside a Mastery set's 0.24 s

    Bounded by states and strings, so the base, the gate's replay and a clock agree, unless the APK's own clock runs
    out first (then nothing). Exactly one code from all of it, else nothing (a text that holds two raises
    Ambiguous: nothing). Every route is a name of its own: a one-option pick until the judge accepts it, and
    _solve's second-code look still runs behind it."""
    found = {}
    pool = list(dict.fromkeys(strings))
    heads = [s for s in pool if _PIECE_HEAD.fullmatch(s) and 7 <= len(s) <= 17]
    if len(heads) == 1:
        tails = [s for s in pool if len(s) == 20 - len(heads[0]) and _PIECE_TAIL.fullmatch(s)]
        if len(tails) == 1 and base.ANSWER.fullmatch((heads[0] + tails[0]).decode()):
            found[(heads[0] + tails[0]).decode()] = "apk-pieces:named-strings"
    try:
        keys = [(k, t) for k, t in key_candidates(doc) if not t][:NAMED_SEARCH_KEYS]
    except Exception:
        keys = []
    texts = [s for s in pool if 20 <= len(s) <= NAMED_SEARCH_LEN and b" " not in s
             and not _FRAMEWORK.match(s)][:NAMED_SEARCH_STRINGS]
    for s in texts:
        try:
            hit, _, _ = search(s, keys, [], clock, max_depth=NAMED_SEARCH_DEPTH, max_nodes=NAMED_SEARCH_NODES,
                               block=False)
        except Ambiguous as e:
            saw.append("%s: one string holds two answer-shaped texts after %s" % (n, e))
            return None
        if hit:
            found.setdefault(hit[0], "apk-string:dex:named-search:" + (">".join(hit[1]) or "as-it-stands"))
        elif clock.up():
            return None
    if len(found) != 1:
        if found:
            saw.append("%s: %d different codes under transforms: %s" % (n, len(found), ", ".join(sorted(found)[:4])))
        return None
    value, route = next(iter(found.items()))
    saw.append("%s: %s gives %s (the named member's strings alone)" % (n, route, value))
    return Hit(value, "medium", route, "", ())


def named_member_hit(members, apk_keys, clock, saw):
    """A Hit from a member the puzzle document names by its path, read BEFORE the bounded search; or None.

    Day 21 build (the fold of Day 20's live fix, "Loaded Later"): the document said codec `dynamic` and
    `data: "assets/payload.dex"`, a secondary DEX whose string table holds the answer code in clear. The
    package look found it (`apk-string:dex`) on the base in 0.09 s, but on the Time Trial variant and on one
    Mastery set the search of the document's own fields spent the whole 0.40 s first and answered None. Here,
    for each field of assets/huntress_puzzle.json whose value is the path of a member of the package (any
    codec, any field name, the first MAX_NAMED_MEMBERS), the member is read by what it is:

      a dex          its string table (dex_strings; its raw bytes when the table does not read): exactly
                     one answer code there is `apk-string:dex`, the route and key the package look gives
                     the same code (judged on Day 20's base), so its answer is what the look would give;
      a document     a puzzle document of its own (JSON or another format asset_docs reads): its own codec,
                     by name only (solve_doc steps 1 to 3), under `<route>:doc-named` (a new name: unsure);
      anything else  exactly one code as it stands (ASCII or UTF-16) is `apk-string:<kind>`, as the look names
                     it; else, a small member is read under the document's own codec with the member in place
                     of the field, by name only, under `<route>:doc-member` (a new name: unsure).

    Two different codes in one member, a low reading, or nothing: None, and the usual reading follows with
    the clock it had. Never a guess: a code is taken only when it is the one code of the member the document
    names, and _solve's second-code look still runs on every plain or unsure answer, so a decoy code elsewhere
    in the package demotes it to an unsure `:second-code` key exactly as it would the look's own hit."""
    obj, _ = _json(members.get(PUZZLE, b""), whole=True)
    if not isinstance(obj, dict):
        return None
    named = []
    for field, v in flat(obj):
        n, by_base = _member_path(v, members), False
        if n is None and field == "data" and dynamic_members is not None:
            # Day 21 final prep (X7/X8): `data` is no member path but the basename or stem of exactly one member
            n, by_base = dynamic_members.by_basename(v, members), True
        if n and n not in [m for _, m, _ in named]:
            named.append((field, n, by_base))
        if len(named) >= MAX_NAMED_MEMBERS:
            break
    # Day 21 final prep: `data` first. A member a side field names (legacy_module, hint, note) is a candidate
    # only beside the document's own reading (side_member below), never ahead of the member `data` names.
    named.sort(key=lambda fn: fn[0].split(".")[0] != "data")
    own = []

    def own_reading():
        if not own:
            own.append(own_doc_hit(obj, apk_keys, clock))
        return own[0]

    for field, n, by_base in named:
        if clock.up():
            return None
        hit = _named_one(obj, field, n, members, apk_keys, clock, saw)
        if hit is _STOP:
            return None
        if hit is None:
            continue
        if by_base:
            hit = hit._replace(route=hit.route + BY_BASENAME, steps=())
            saw.append("%s: named by its basename in the document's field data (%s)" % (n, json.dumps(obj.get("data"))[:80]))
            print("NOTE mobile named member: data %s names %s by its basename; %s gives %s (Day 21 final prep; a name of "
                  "its own, unsure until judged)" % (json.dumps(obj.get("data"))[:80], n, hit.route, hit.value), file=sys.stderr)
        if field.split(".")[0] != "data" or by_base:
            own_hit = own_reading()
            if own_hit is None and not by_base and _data_unread(obj, members):
                # Day 21 final prep, second review: the document's codec is a name no reader applies by name,
                # but `data` holds a value of its own that the budgeted search may decode to the real code.
                # The side member's code is no proof then: it is held (side_deferred) and the usual reading
                # follows; it is the answer only when that reading gives none, and then only unsure.
                deferred = hit._replace(codec=(hit.codec or hit.route) + SIDE_MEMBER, options=())
                LAST.setdefault("side_deferred", (deferred, field, n))
                saw.append("%s: named by the side field %s gives %s; the document's codec %s is read by no reader by "
                           "name and its data is no member path, so the usual reading goes first and this code is "
                           "held, unsure under its own key" % (n, field, hit.value, json.dumps(obj.get("codec"))[:40]))
                continue
            return side_member(hit, own_hit, field, n, saw)
        return hit
    return None


SIDE_MEMBER = ":side-member"   # the end of the key of a side field's member held behind the usual reading
LOADER_CODECS = ("dynamic", "loader")   # codecs whose document names its payload: a side member may stand for it


def _data_unread(obj, members) -> bool:
    """Day 21 final prep (second review): does the document's `data` hold a value of its own (non-empty, no member
    path) under a codec that is not a loader's (`dynamic`, `loader`)? Then a member a side field names is never
    plain: the budgeted search of `data` may give the document's own code."""
    codec = obj.get("codec")
    if isinstance(codec, dict):
        codec = codec.get("name") or codec.get("type") or codec.get("codec")
    name = codec.strip().lower() if isinstance(codec, str) else ""
    if name in LOADER_CODECS:
        return False
    data = obj.get("data")
    if data is None or data == "" or data == [] or data == {}:
        return False
    if isinstance(data, str) and _member_path(data, members):
        return False
    return True


BY_BASENAME = ":named-by-basename"   # the end of a route read from a member `data` names by basename (Day 21 final prep)


def own_doc_hit(obj, apk_keys, clock):
    """The document's own codec applied to its own fields, by name only (solve_doc steps 1 to 3): a Hit or None."""
    hit = None
    if isinstance(obj, dict) and obj.get("codec") is not None and not clock.up():
        try:
            p, marks = reshape(obj)
            hit = solve_doc(p, ":".join(marks), apk_keys, clock, named_only=True)
        except Exception:
            hit = None
    return hit if hit is not None and hit.confidence in ("high", "medium") and hit.value else None


_STOP = object()   # _named_one: the APK's clock ran out, nothing more is read by name


def side_member(hit, own, field, n, saw):
    """Day 21 final prep (the review of ac5c24e: a decoy dex a side field names was sent PLAIN under the judged
    `apk-string:dex`). A member a field other than `data` names is the answer only when the document's own codec
    gives no code from its own fields (`dynamic`, `loader`, a codec no reader applies). When it does:

      the same code       the document's own reading, as it would be without the member
      another code        unsure under `<the document's key>:second-code`, the document's code first and the
                          member's after it (as `<route>@<member>`), never plain before the judge accepts a name
                          there; one saw line and one NOTE say so (the day-review marker
                          `mobile-final-prep`)"""
    if own is None:
        saw.append("%s: named by the side field %s; the document's own codec gives no code from its fields, so the "
                   "member's reading stands" % (n, field))
        return hit
    if own.value == hit.value:
        saw.append("%s: named by the side field %s gives %s, the code of the document's own reading" % (n, field, hit.value))
        return own
    mark = labels.CANDIDATE_MARK if (own.codec or "").endswith(labels.CANDIDATE_MARK) else ""
    codec = _key(own)[len(KEY):]
    codec = (codec[:-len(mark)] if mark else codec) + SECOND + mark   # a candidate key keeps its mark last
    where = "%s@%s" % (route_name(hit), _slug(n, 32))
    saw.append("%s: named by the side field %s gives %s; the document's own reading gives %s (%s)"
               % (n, field, hit.value, own.value, route_name(own)))
    print("NOTE mobile side member: %s named by the side field %s gives %s; the document's own reading (%s) gives %s: "
          "unsure under %s, the document's code first (Day 21 final prep)"
          % (n, field, hit.value, route_name(own), own.value, KEY + codec), file=sys.stderr)
    # own.steps keep the judged route's own name ('xor', as the second-code look offers it); decide()'s judged-chain
    # rule never makes a `:second-code` pick plain
    return Hit(own.value, "medium", own.route, codec, own.steps, ((where, hit.value),))


def _named_one(obj, field, n, members, apk_keys, clock, saw):
    """named_member_hit's reading of ONE member a field of the document names: a Hit, None, or _STOP."""
    body = members[n]
    kind = member_kind(n, body)
    saw.append("%s: named by the document's field %s (%d bytes, %s)" % (n, field, len(body), kind))
    if body.startswith(b"dex\n"):
        strings = dex_strings(body)
        codes = ({m.decode() for s in strings for m in _ANS_RAW.findall(s)} if strings
                 else {m.decode() for m in _ANS_RAW.findall(body)})
        if len(codes) == 1:
            return Hit(codes.pop(), "medium", "apk-string:dex", "", ())
        if codes:
            saw.append("%s: %d different answer codes in its strings: %s" % (n, len(codes), ", ".join(sorted(codes)[:4])))
            return None
        if field == "data" and strings:
            # Day 21 build round 2 (prediction candidate 2): the code under a transform inside the dex
            # `data` names (base64, xor with the document's key, two strings), read before the search
            # of the document can spend the budget; bounded by steps, never by a share of the clock
            hit = named_search(n, strings, obj, clock, saw)
            if hit is not None:
                return hit
            if clock.up():
                return _STOP
        return None
    doc, wrap = _json(body)
    if doc is None:
        got = asset_docs.parse(n, body, known=lambda name: _known(ALIASES.get(name, name)))
        doc = got[0][0] if got else None
    if isinstance(doc, dict) and doc.get("codec") is not None:
        p, marks = reshape(doc)
        hit = solve_doc(p, ":".join(["doc-named"] + (["doc-encoded"] if wrap else []) + list(marks)), apk_keys,
                        clock, named_only=True)
        if hit and hit.confidence in ("high", "medium"):
            return hit
        return None
    codes = {m.decode() for m in _ANS_RAW.findall(body)}
    wide = {m.decode("utf-16le") for m in _ANS_WIDE.findall(body)}
    if len(codes | wide) == 1:
        value = (codes | wide).pop()
        if dynamic_members is not None:
            # Day 21 final prep: a whole code beside ANOTHER code in pieces in the same body (a Hermes string table,
            # .NET #US, AXML, a JS `+` expression): nothing proves which is meant
            try:
                k = dynamic_members.structured(body)
                cut = dynamic_members.pieces(k, body)[0] if k else None
            except Exception:
                cut = None
            if cut and cut != value:
                saw.append("%s: %s whole and %s in pieces: not taken" % (n, value, cut))
                return None
        return Hit(value, "medium", "apk-string:%s%s" % (kind, "" if value in codes else ":utf16"), "", ())
    if codes | wide:
        return None
    top = field.split(".")[0]
    if len(body) <= MAX_STATE and top == field and obj.get("codec") is not None:
        try:
            text = body.strip().decode("utf-8")
        except UnicodeDecodeError:
            return None
        p, marks = reshape(dict(obj, **{field: text}))
        hit = solve_doc(p, ":".join(["doc-member"] + list(marks)), apk_keys, clock, named_only=True)
        if hit and hit.confidence in ("high", "medium"):
            return hit
    return None


def solve_members(members, inner=(), clock=None, blob=b"", twins=()):
    """The members of one APK: a Hit or None. What was looked at is left in LAST['saw'].

    `blob` is the archive itself, when the caller has it: its bytes outside the members (the
    signing block, the comment) are looked at for a code that stands there as it is.
    `twins` are the other bodies under the puzzle document's name when that document is not
    the delivery's own: the documents of the other packages in the delivery (read_members).

    Never plain by position (2026-10-11). The whole of the member named assets/huntress_puzzle.json
    is the document by its name, and its hit is returned at once, as it always was. Any other
    hit is one candidate among those that stand behind it: the entries nested beside it in its
    member, and for a document in another member every document of the members after it. They
    are read by name (named_hits), and one that gives another code, or was not read in the time,
    makes the answer None with the candidates in the NOTE: the first of them is not more of an
    answer than the second, and once the judge has accepted the route's name on a look-alike it
    would be sent plain. Candidates that agree stay the one hit. A twin is a candidate of every
    hit, and it carries the document's own name: it must give the same code by name, and one
    that gives none makes the answer None as well."""
    clock = clock or Clock()
    saw, cache = [], {}
    members, inner = dict(members), set(inner)
    twins = [t for t in dict.fromkeys(twins) if t != members.get(PUZZLE)]

    def pkg():
        if "p" not in cache:       # once per APK, after the members are final, and never past the clock
            cache["p"] = package_strings(members, clock.stop)
        return cache["p"]

    def strings():
        if "s" not in cache:
            cache["s"] = app_strings(members, pkg())
        return cache["s"]

    def apk_keys():
        if "k" not in cache:
            cache["k"] = list(dict.fromkeys(keystore_keys(members, clock) + named_keys(members) + key_material(strings())))[:64]
        return cache["k"]

    def used():
        saw.append("time budget of %.2f s used up" % clock.total)

    def parsed(n, body):
        """(document, how it was wrapped, its format) for one member's body, as the loop below parses it."""
        obj, wrap = _json(body, whole=n == PUZZLE)
        fmt = ""
        if obj is None:
            got = asset_docs.parse(n, body, known=lambda name: _known(ALIASES.get(name, name)))
            if got:
                obj, fmt = got[0]
        if obj is None and layered:
            obj, fmt = (doc_layers(body) or (embedded_docs(n, body) if n.endswith((".bin", ".dex")) else None)
                        or (None, ""))
        return obj, wrap, fmt

    def later(after):
        """(parsed member, where it stands) for the members behind `after` that may hold a document."""
        for n in order[order.index(after) + 1:]:
            if _SIGNING.match(n) or clock.up():
                continue
            if n.endswith(".dex"):
                # a dex is a candidate only through a puzzle document that stands in it as JSON text (Day 19
                # look-ahead, item 3): two documents in two members are candidates of each other, a dex too
                if not (layered and SCHEMA_LITERAL in members[n]):
                    continue
                got = embedded_docs(n, members[n])
                if got is None:
                    continue
                obj, wrap, fmt = got[0], "", got[1]
            else:
                obj, wrap, fmt = parsed(n, members[n])
            if obj is not None:
                yield obj, [w for w, on in (("doc-moved", n != PUZZLE), ("doc-inner", n in inner),
                                            ("doc-encoded", bool(wrap)), ("doc-" + fmt, bool(fmt))) if on]

    def code_candidates():
        """(document, where it stands) for the puzzle documents app_bundles.docs finds in the code of every
        member (a JavaScript or Hermes bundle, a dex's fields or strings), in the members' order and wherever
        they stand. They are candidates of a document one of the Day 19 readers found (a dex or .bin holding
        JSON text, a whole member under a layer): later() covers only the members behind it, and the code is
        otherwise read only when no member is a document (second review of the Day 19 build: a decoy in
        classes.dex was offered alone, the real document in assets/index.android.bundle dropped). First
        the puzzle documents that stand as JSON text, as they are or with their quotes escaped, in ANY
        member (a .so, a dex's escaped string), then app_bundles.docs. Ends when the clock is up (alone()
        then says the candidates were not all read)."""
        for n in order:
            body = members[n]
            if _SIGNING.match(n) or n == PUZZLE or SCHEMA_LITERAL not in body:
                continue
            if clock.up():
                return
            texts = [body]
            if _ESCAPED_DOC.search(body):
                texts.append(re.sub(rb'\\(["\\/])', rb"\1", body))
            for text in texts:
                got = embedded_docs(n, text)
                if got is not None:
                    yield got[0], ["doc-moved"] + (["doc-inner"] if n in inner else []) + ["doc-" + got[1]]
        if app_bundles is None:
            return
        known = lambda name: _known(ALIASES.get(name, name))  # noqa: E731
        for n in order:
            if _SIGNING.match(n) or n == PUZZLE:
                continue
            if clock.up():
                return
            try:
                found_docs = app_bundles.docs(n, members[n], clock.stop, known)
            except Exception:
                found_docs = []
            for obj, fmt in found_docs:
                try:
                    obj = asset_docs.normalise(asset_docs._jsonable(obj))
                except Exception:
                    continue
                yield obj, ["doc-moved"] + (["doc-inner"] if n in inner else []) + ["doc-" + fmt]

    def alone(held, obj, base_where, at, rest=None):
        """`held`, or a low Hit when a candidate behind it gives another code or was not read.

        The twins are candidates of every hit, and one that gives no code by name counts as
        not read. `at`: the hit's number among the documents of `obj` when it is one of the
        nested ones (the entries behind it are candidates), else None. `rest`: the parsed
        members behind it, for a hit outside the member that has the document's name; beside
        that member no other member is a candidate.

        The reading ends as soon as the answer is None either way: at the first candidate
        that was not read, and at the last one the NOTE has room for (MAX_NAMED). Thirty
        thousand entries behind a hit must not be read past the APK's time (review,
        2026-10-11: they took 4 s of a 0.4 s budget, each one read after the time was up)."""
        if held.confidence == "low":
            return held
        said, unread = [], []

        def decided() -> bool:
            return bool(unread) or len(said) >= MAX_NAMED - 1

        def read(hits) -> int:
            count = 0
            for count, other in enumerate(hits, 1):
                if other is None:
                    unread.append(1)
                elif other.confidence == "low" or other.value != held.value:
                    said.append(other)
                if decided():
                    break
            return count

        for body in twins:
            if decided():
                break
            twin, _, _ = parsed(PUZZLE, body)
            if twin is None or not read(named_hits(twin, base_where + ["doc-twin"], apk_keys, clock)):
                unread.append(1)
        if at is not None and not decided():
            read(named_hits(obj, base_where, apk_keys, clock, at + 1))
        for more, where in rest or ():
            if said or unread:
                break
            read(named_hits(more, where, apk_keys, clock))
        if said:
            both = [held] + said[:MAX_NAMED - 1]
            return Hit(held.value, "low", "%d candidates give different codes by name, and only their order says which "
                       "is meant: %s" % (len(said) + 1, ", ".join("%s (%s)" % (h.value, route_name(h)[:60]) for h in both)),
                       "", ())
        if unread or (rest is not None and clock.up()):
            return Hit(held.value, "low", "%s gives %s, and the candidates beside it were not all read: one took too long, "
                       "or another body under the document's name gives no code by name" % (route_name(held), held.value), "", ())
        return held

    LAST["saw"] = saw
    # A container among the members (an Android backup, a tar, a gzip) is opened one level down.
    for n in list(members):
        body = members[n]
        if body[:2] == b"\x1f\x8b" or body[:15] == b"ANDROID BACKUP\n" or body[257:262] == b"ustar":
            for name, b in apk_resources.expand(n, body):
                if name not in members:
                    members[name] = b
                    inner.add(name)
    order = sorted(members, key=lambda n: (n != PUZZLE, not n.startswith("assets/"), n == "AndroidManifest.xml", n))
    # A document whose codec is `native` (Day 15, row 309) answers from the libraries, judged plain
    # (native:so-secret). It is read first: the Day 19 readers below (a document in a dex or a .bin, a whole
    # member under zlib or a one-byte XOR) must not put a document they find ahead of that judged answer
    # (review of the Day 19 build: a decoy in classes.dex led the answer, and a clock with a deadline lost
    # the mode). With a native answer in hand they are not read at all, as on the tree before them.
    nat_early = native_hit(members, clock)
    layered = nat_early is None
    if layered and not twins:
        # Day 21 build (Day 20's "Loaded Later"): a member the document names by path is read before
        # the search of the document's fields can spend the budget (named_member_hit)
        hit = named_member_hit(members, apk_keys, clock, saw)
        if hit is not None:
            return hit
    opaque = []
    low_own = None   # a LOW own-document candidate (solve_doc step 4): held, not returned (row 309)
    for n in order:
        if _SIGNING.match(n):
            continue
        if n.endswith(".dex"):
            # the app's code: only a puzzle document that stands in it as JSON text (Day 19 look-ahead,
            # item 3; dynamic loading). Everything else of a dex is read further down, as before.
            got = embedded_docs(n, members[n]) if n != PUZZLE and layered and not clock.up() else None
            if got is None:
                continue
            obj, wrap, fmt = got[0], "", got[1]
            day19 = True
        else:
            day19 = False
            if n != PUZZLE and clock.up():  # thousands of members: parsing them is part of the budget
                used()
                return None
            obj, wrap = _json(members[n], whole=n == PUZZLE)
            fmt = ""
            if obj is None:
                # not JSON: the same fields in another container (plist, compiled or text XML, the resource
                # table, SQLite, properties, YAML, TOML, MessagePack, CBOR, protobuf)
                got = asset_docs.parse(n, members[n], known=lambda name: _known(ALIASES.get(name, name)))
                if got:
                    obj, fmt = got[0]
            if obj is None and layered:
                # Day 19 look-ahead (items 2 and 3): the whole member under zlib, gzip or a one-byte XOR, or
                # a document as JSON text inside a .bin; each only with the huntress.mobile.puzzle schema
                got = doc_layers(members[n]) or (embedded_docs(n, members[n]) if n.endswith(".bin") else None)
                if got:
                    obj, fmt = got
                    day19 = True
        if obj is None:
            opaque.append(n)
            continue
        docs = list(docs_in(obj))
        if fmt and not docs and not isinstance(obj, list):
            if n != "AndroidManifest.xml" and not n.startswith("META-INF/"):
                opaque.append(n)    # another format, and no puzzle field in it: still searched as bytes
            continue
        small = len(members[n]) <= MAX_WRAPPED
        saw.append("%s: %s" % (n, json.dumps(obj, default=str)[:300] if small else
                               members[n][:300].decode("utf-8", "replace") + " ... (%d bytes)" % len(members[n])))
        base_where = [w for w, on in (("doc-moved", n != PUZZLE), ("doc-inner", n in inner),
                                      ("doc-encoded", bool(wrap)), ("doc-" + fmt, bool(fmt))) if on]
        own = n == PUZZLE   # the member with the document's name: no other member is a candidate beside it

        def behind(n=n, own=own, day19=day19):
            # the candidates behind a hit outside the member with the document's name; for a document a Day 19
            # reader found, the documents in the code of every member too
            if own:
                return None
            return itertools.chain(later(n), code_candidates()) if day19 else later(n)

        hit = fragments(obj, ".".join(base_where), apk_keys, clock)
        if hit:
            return hit if own and not twins else alone(hit, obj, base_where, None, behind())
        for at, (p, nested) in enumerate(docs):
            p, marks = reshape(p)
            where = base_where + (["doc-nested"] if nested else []) + list(marks) + [m for m in [schema_mark(p)] if m]
            hit = solve_doc(p, ".".join(where), apk_keys, clock)
            if hit:
                if own and not nested and not twins:
                    if not (hit.confidence == "low" and NOT_APPLIED in hit.route):
                        return hit   # the document itself, by its name: as it always was (a
                        #            contested list, pieces that do not read: still returned, -> None)
                    # Only solve_doc's step-4 candidate: an answer-shaped string under a codec this
                    # module did not apply. Do not stop the base here (row 309, Day 15): the real code
                    # may stand in a native library (native_hit) or another member. Hold the candidate
                    # (and its document, for row 367); if nothing confirms it, it is dealt with at the end.
                    low_own = low_own or (hit, p)
                else:
                    return alone(hit, obj, base_where, at if nested else None, behind())
            if clock.up():
                used()
                return None
    # A document whose codec is `native` (Day 15, row 309): solve_doc returned None for it, so no hit
    # above; the answer is the one code the native libraries hold, cross-checked against its `data`.
    nat = nat_early
    if nat is not None:
        return nat
    if low_own is not None:
        # The own document named a codec this module did not apply, and no native library confirmed its
        # answer-shaped `data`. Row 367: when the reading is unambiguous (one code in `data`, no move to a
        # different one, no other clear code in the package) offer it as a one-probe unsure pick, so a
        # bare-new-codec base closes in the opener's pass; otherwise it stays the LOW candidate (decide() ->
        # None, MISSING), as before, rather than guessing the document's data. The second-code look still runs
        # in _solve once this is an unsure answer, so a decoy with the real code in a side field is demoted.
        held, doc = low_own
        return _bare_codec_pick(held, doc, members) or held
    # Nothing in a member that is a document. The app's code may hold the same fields (app_bundles.py):
    # a Hermes object literal, a JavaScript bundle, a class's static fields, a JSON text in a string.
    if app_bundles is not None:
        # A Xamarin store, or one compressed assembly, is inflated only now: no member document
        # waits behind it (review, 2026-10-08: a store of forged headers took the whole budget
        # before the first document was read). Inflating is Python, so it gets a quarter of the
        # budget at most and 16 MiB for the whole package.
        room = app_bundles.MAX_EXPAND
        for n in list(order):
            body = members[n]
            if not (body[:4] in (b"XABA", b"XALZ") or (body[:4] == b"\x7fELF" and b"XABA" in body[:1 << 16])):
                continue
            until = min(clock.stop, time.perf_counter() + clock.total / 4)
            for name, b in app_bundles.expand(n, body, until, room):
                if name not in members:
                    members[name] = b
                    inner.add(name)
                    order.append(name)
                    room -= len(b)
                    if len(b) <= MAX_STATE:
                        opaque.append(name)    # as a member that is no document: searched as bytes
                    for k in ("p", "s", "k"):  # the package's strings and keys are read again with it
                        cache.pop(k, None)
        known = lambda name: _known(ALIASES.get(name, name))  # noqa: E731
        cut = []

        def code_docs():
            """(document, where it stands) for what the code of each member holds, until the clock is up."""
            for n in order:
                if clock.up():
                    cut.append(n)
                    return
                try:
                    found_docs = app_bundles.docs(n, members[n], clock.stop, known)
                except Exception:
                    found_docs = []
                for obj, fmt in found_docs:
                    try:
                        obj = asset_docs.normalise(asset_docs._jsonable(obj))
                    except Exception:
                        continue
                    saw.append("%s (%s): %s" % (n, fmt, json.dumps(obj, default=str)[:300]))
                    yield obj, ["doc-moved"] + (["doc-inner"] if n in inner else []) + ["doc-" + fmt]

        code = code_docs()
        for obj, base_where in code:
            for at, (p, nested) in enumerate(docs_in(obj)):
                p, marks = reshape(p)
                where = base_where + (["doc-nested"] if nested else []) + list(marks) + [m for m in [schema_mark(p)] if m]
                # Day 14 look-ahead: every fixture's dex holds a record of labels (CODEC, CONTROL, DAY) and
                # no payload. Searching its 16-character label cost 0.2 s of every APK whose answer is not
                # in a document, before the package's strings were looked at. Short texts are not searched.
                hit = solve_doc(p, ".".join(where), apk_keys, clock, min_search=CODE_DOC_SEARCH)
                if hit:
                    # one candidate among the documents the code holds behind it: they are read by name
                    return alone(hit, obj, base_where, at if nested else None, code)
                if clock.up():
                    used()
                    return None
        if cut:
            used()
            return None
    # Nothing in a document. An answer code that stands somewhere else in the package, as it is or
    # under transforms, is offered (unsure) only when it is the one code the whole package holds:
    # with two, nothing says which is meant, and the candidates only feed the NOTE.
    for n in opaque:
        saw.append("%s: %d bytes, no puzzle document" % (n, len(members[n])))
    far = [(k, "key-apk") for k in apk_keys()]
    try:
        found, complete = package_answer(members, opaque, far, clock, blob, pkg())
    except Ambiguous as e:
        return Hit("", "low", "two different answer-shaped strings in one text of the package after %s" % e, "", ())
    # what the dex puts together from pieces (one method's strings in order, one array's elements)
    built = {}
    if app_bundles is not None:
        for n in order:
            if n.endswith(".dex") and not clock.up():
                try:
                    for route, value in app_bundles.pieces(n, members[n], clock.stop):
                        built.setdefault(value, "apk-pieces:" + route)
                except Exception:
                    continue
    if len(found) == 1 and complete:
        value, route = next(iter(found.items()))
        if any(v != value for v in built):   # a whole code here, another built there: nothing says which
            return Hit(value, "low", "one answer-shaped string (%s) and another code the dex builds from pieces: %s" % (
                route, ", ".join(sorted(v for v in built if v != value)[:3])), "", ())
        return Hit(value, "medium", route, "", ())
    if found:
        first = sorted(found)[0]
        why = ("%d different answer-shaped strings in the package" % len(found) if len(found) > 1
               else "one answer-shaped string, and the package was not searched to its end")
        return Hit(first, "low", "%s: %s" % (why, ", ".join("%s (%s)" % (found[v], v) for v in sorted(found)[:4])), "", ())
    if not clock.up():
        pieces = package_pieces(members, opaque, pkg())
        if pieces:
            return Hit(pieces[0], "medium", pieces[1], "", ())
    if app_bundles is not None and not clock.up():
        # one method's strings in order, one array's elements, then a code under a one-byte key:
        # each only when it is the one code of its kind in the whole package
        if len(built) == 1 and not clock.up():
            value, route = next(iter(built.items()))
            return Hit(value, "medium", route, "", ())
        if built:
            return Hit(sorted(built)[0], "low", "%d different codes put together from pieces in the dex: %s" % (
                len(built), ", ".join(sorted(built)[:4])), "", ())
        keyed, complete = {}, True
        for n in order:
            body = members[n]
            if not (n.endswith(".dex") or app_bundles.kind_of(n, body) in ("native", "dotnet")):
                continue
            if clock.left() < XOR_RESERVE:
                complete = False
                break
            try:
                for value, (route, byte) in app_bundles.xor_codes(body, clock.stop - XOR_RESERVE / 2).items():
                    if value not in keyed:
                        keyed[value] = "apk-string:%s:%s" % (member_kind(n, body), route)
                        saw.append("%s: %s under the key byte 0x%02x" % (n, route, byte))
            except Exception:
                continue
        complete = complete and clock.left() >= XOR_RESERVE / 2
        if len(keyed) == 1 and complete:
            value, route = next(iter(keyed.items()))
            return Hit(value, "medium", route, "", ())
        if keyed:
            return Hit(sorted(keyed)[0], "low", "%s under a one-byte key: %s" % (
                "%d different codes" % len(keyed) if len(keyed) > 1 else "one code, and the package was not searched to its end",
                ", ".join("%s (%s)" % (keyed[v], v) for v in sorted(keyed)[:4])), "", ())
    short = [s.decode("utf-8", "replace") for s in strings() if len(s) < 24 and re.fullmatch(rb"[a-z0-9_+\-]+", s)]
    if short:
        saw.append("short dex/manifest strings: %s" % short[:20])
    if clock.up():
        used()
    return None


# ---------------------------------------------------------------------------- the answer

def _judged(step) -> bool:
    """Has the judge accepted this codec name, with nothing since to say otherwise?"""
    if not re.fullmatch(r"[a-z0-9_-]{1,32}", step):
        return False
    st = labels.state(KEY + step)
    return step in st["accepted_names"] and not st["split"]


def route_name(hit) -> str:
    """The name a Hit's route is offered and remembered under.

    A name spelled only with the Day 4 solver's codec names ('reverse', 'base64+xor') is
    the name of the judged route of its key, which the seed accepts. Only the Day 4
    solver's own result on the usual document (hit.steps) may carry it. solve_doc marks
    every other route already; this is the one place that enforces it, whatever built
    the Hit, so such a route stays unsure until the judge accepts it under its own name."""
    if not hit.steps and all(t in base.NAMED for t in hit.route.split("+")):
        return hit.route + ":not-by-name"
    return hit.route


def offered(hit) -> list:
    """Every (name, value) a Hit offers, best first: its own route, then its further options.

    A further option is never the Day 4 solver's own route, so it is held to the same
    rule as a Hit without steps: no judged codec's bare name."""
    rest = [(route_name(hit._replace(route=name, steps=())), value) for name, value in hit.options]
    return [(route_name(hit), hit.value)] + rest


def _unbranded(options, hit):
    """Rename the hit's OWN reading off the bare codec name for a fail-closed candidate pick (review
    2026-10-23, docs/retro/mobile-d05-revise-notes.md). A candidate hypothesis names the reading, never the
    value; the bare codec name (`base64`) must not name an option, because -- accepted once under a shared key
    -- it would answer another variant's `data` decode (a decoy) plain. The hit's reading(s) become
    `data-decode:<route>`; a code found elsewhere keeps its route name (`apk-string:...`, `field:@...`,
    `twin-entry`), which is a place, not a codec. Order and values are untouched, so the look's own
    first-option order stands."""
    own = {v for _, v in offered(hit)}
    out, seen_names = [], set()
    for name, value in options:
        nm = "data-decode:" + _slug(name, 24) if value in own else name
        if nm not in seen_names:
            seen_names.add(nm)
            out.append((nm, value))
    return out


def _key(hit) -> str:
    """The label key a Hit is offered under: mobile.codec/<codec name or route>. A Hit whose codec ends in
    labels.CANDIDATE_MARK (when_branches) keeps the mark and its complete artifact scope: its key is a
    candidate key (row 346). Ordinary reusable family keys keep the historical 64-character bound."""
    mark = labels.CANDIDATE_MARK if (hit.codec or "").endswith(labels.CANDIDATE_MARK) else ""
    codec = hit.codec[:-len(mark)] if mark else hit.codec
    limit = 256 if mark else 64
    return KEY + (_slug(codec, limit) or _slug(hit.route) or "unnamed") + mark


def _accepted(hit) -> bool:
    """Has the judge accepted one of the names this Hit offers, with nothing since to say otherwise?"""
    st = labels.state(_key(hit))
    return not st["split"] and any(name in st["accepted_names"] for name, _ in offered(hit))


def decide(hit):
    """(answer, key) for a Hit: a plain answer, an unsure answer, or None. Never a guess.

    Confidence low is None. Everything else goes through labels.pick under the key of its
    codec name, with the route as the option's name: plain if that route is accepted for
    the key (the judged codecs are, in the seed), unsure if it is new, None if the judge
    rejected it. A Hit that carries several readings offers them all, so a name the judge
    accepted answers plain whichever place it has, and a base probe tries them in order.
    A chain whose every step is a judged codec, applied by the Day 4 solver on the usual
    document, is plain as long as nothing is recorded against it."""
    if hit is None or hit.confidence not in ("high", "medium"):
        return None, None
    key = _key(hit)
    answer = labels.pick(key, offered(hit))
    if (labels.is_unsure(answer) and len(hit.steps) > 1 and all(_judged(s) for s in hit.steps)
            and SECOND not in (hit.codec or "")):
        st = labels.state(key)
        if not st["accepted_names"] and not st["rejected"] and not st["split"]:
            return hit.value, key
    return answer, key


def dynamic_member_hit(members):
    """Day 21 look-ahead (docs/retro/day-21-predictions-mobile.md; dynamic_members.py): a Hit when the puzzle
    document's `data` names, by path, a payload that is NOT a dex member of the package itself (a JAR, APK or zip
    holding a dex, a native library, resources.arsc, a gzip, a payload under XOR, RC4 or AES with a key the document or
    the app's dex carries, a dex without the extension, a list of paths) and exactly one exact code stands there.
    Its route is a name of its own (`apk-string:<kind>:named-<how>`), so the answer is a one-option pick until the
    judge accepts it, and _solve's second-code look still runs behind it. None otherwise, for the Day 20 shape
    (a `.dex` member of the package), which the member-by-path reading answers, and for a judged codec that reads a
    member itself (`native`, a keystore name)."""
    if dynamic_members is None or PUZZLE not in members or len(members[PUZZLE]) > MAX_WRAPPED:
        return None
    try:
        doc, _ = _json(members[PUZZLE], whole=True)
        codec = _slug(doc.get("codec", "")) if isinstance(doc, dict) else ""
        reads_member = codec in NATIVE_NAMES + KEYSTORE_NAMES
        if not isinstance(doc, dict) or (reads_member and labels.state(KEY + codec)["accepted_names"]):
            # a codec whose judged route reads a member itself (`native` with a library's path in `data`: native_hit)
            # keeps that route. Day 21 build round 2 (row 409's harness): any other judged codec (`reflection`, judged
            # on Day 19, reads `data` as it stands) reads nothing from a path, so it no longer stops this reading
            return None
        got = dynamic_members.read(doc, members)
    except Exception as e:
        print("NOTE mobile dynamic_members raised %s: %s; the usual search goes on" % (type(e).__name__, str(e)[:160]),
              file=sys.stderr)
        return None
    if not got:
        return None
    LAST["saw"] = ["%s: %s names a payload by path; read by dynamic_members" % (PUZZLE, json.dumps(doc.get("data"))[:200])]
    if "by-basename" in got[1]:
        # Day 21 final prep (X7/X8): a member `data` names only by its basename is a candidate beside the
        # document's own reading, as a member a side field names is (side_member)
        own = own_doc_hit(doc, lambda: [], Clock())
        if own is not None:
            hit = side_member(Hit(got[0], "medium", got[1], got[1], ()), own, "data", "(by basename)", LAST["saw"])
            return hit
    print("NOTE mobile dynamic_members: data names %s; %s gives %s (Day 21 look-ahead; a name of its own, unsure "
          "until judged)" % (json.dumps(doc.get("data"))[:160], got[1], got[0]), file=sys.stderr)
    return Hit(got[0], "medium", got[1], got[1], ())


def stated_revise(hit, members, texts=()):
    """Day 21 build, round 3 (item 3; stated_spec.py): the Hit as a decoding the document or the question STATES in
    words has it. No stated pipeline, or one that gives no exact code, or the same code as `hit`: `hit` unchanged.
    A code where `hit` has none (None, or a low reading): a Hit of its own, route `stated:<steps>`, key
    `mobile.codec/stated+<steps>` (a one-option pick until the judge accepts the route). A code that differs from
    `hit`'s: the stated code first and every reading of `hit` after it, under `<hit's key>:stated` (never plain
    before the judge has accepted the stated route there). One stderr line `NOTE mobile stated: ...` either way."""
    if stated_spec is None or not members:
        return hit
    try:
        got, notes = stated_spec.read_package(members, tuple(t for t in texts if isinstance(t, str)))
    except Exception as e:
        print("NOTE mobile stated: stated_spec.py raised %s: %s; the answer stands" % (type(e).__name__, str(e)[:160]),
              file=sys.stderr)
        return hit
    if got is None:
        if notes:
            print("NOTE mobile stated: %s" % "; ".join(notes)[:400], file=sys.stderr)
        return hit
    code, route, steps = got
    usual = hit is not None and hit.confidence in ("high", "medium") and hit.value
    if usual and hit.value == code:
        print("NOTE mobile stated: %s gives %s, the code the usual reading gives (%s); nothing changes"
              % (route, code, route_name(hit)), file=sys.stderr)
        return hit
    if not usual:
        print("NOTE mobile stated: %s gives %s where the usual reading has none (one-option pick, unsure until judged)"
              % (route, code), file=sys.stderr)
        return Hit(code, "medium", route, "stated+" + _slug(route[len("stated:"):], 48), ())
    mark = labels.CANDIDATE_MARK if (hit.codec or "").endswith(labels.CANDIDATE_MARK) else ""
    base_codec = _key(hit)[len(KEY):]
    base_codec = base_codec[:-len(mark)] if mark else base_codec
    print("NOTE mobile stated: %s gives %s, the usual reading gives %s (%s): unsure under %s, the stated code first"
          % (route, code, hit.value, route_name(hit), KEY + base_codec + ":stated" + mark), file=sys.stderr)
    return Hit(code, "medium", route, base_codec + ":stated" + mark, (), tuple(offered(hit)))


def lookahead_revise(hit, members, dups=()):
    """Day 21 look-ahead (lookahead_readers.py): the Hit as the look-ahead readers have it, but ONLY when the
    usual reading (dynamic_member_hit / solve_members / stated_revise) gave no code. A reading from those
    readers is always a one-option pick or a candidate pick (row 346), route `mobile.codec/lookahead:<how>`,
    unsure until the judge accepts it, and `_solve`'s second-code look still runs behind it.

    When `hit` already carries a code this returns `hit` unchanged before any work, so nothing the shipped
    solver answers is changed or slowed (every saved attempt has a code, so this is never reached on the
    regression set). Only a document no other reader could read reaches the readers here."""
    if lookahead_readers is None:
        return hit
    if hit is not None and hit.confidence in ("high", "medium") and hit.value:
        return hit
    try:
        got, notes = lookahead_readers.read(members, dups)
    except Exception as e:
        print("NOTE mobile lookahead: lookahead_readers.py raised %s: %s; the usual search stands"
              % (type(e).__name__, str(e)[:160]), file=sys.stderr)
        return hit
    for n in notes or ():
        print("NOTE mobile lookahead: %s" % n, file=sys.stderr)
    if not got:
        return hit
    LAST.setdefault("saw", []).append("lookahead: %s" % (got.get("route") or got.get("key")))
    if got["kind"] == "single":
        route = got["route"]
        return Hit(got["code"], "medium", route, _slug(route, 48), ())
    options = [tuple(o) for o in got["options"]]
    codec = _slug(got["key"], 48) + labels.CANDIDATE_MARK
    return Hit(options[0][1], "medium", options[0][0], codec, (), tuple(options[1:]))


def container_revise(hit, blob):
    """APK container reader (apk_container.py): the Hit as a code hidden at the container level has it, but
    ONLY when the usual reading (dynamic_member_hit / solve_members / stated_revise / the look-ahead readers)
    gave no code. A code inside a non-standard APK Signing Block ID-value or inside a ZIP local entry the
    central directory hides / misdescribes, each only when it decodes (base64/hex/zlib/gzip/deflate) to
    EXACTLY one code -- a plain run is already `apk-string:archive`. The reading is a one-option pick, route
    `apk-sigblock:<id>...` or `apk-zip-hidden:<name>...`, unsure until the judge accepts it, and `_solve`'s
    second-code look still runs behind it.

    When `hit` already carries a code this returns `hit` unchanged before any work, so nothing the shipped
    solver answers is changed or slowed (every saved attempt has a code, so this is never reached on the
    regression set). It is reached only on a package whose code no other reader could find."""
    if apk_container is None or not isinstance(blob, (bytes, bytearray)) or not blob:
        return hit
    if hit is not None and hit.confidence in ("high", "medium") and hit.value:
        return hit
    try:
        got, notes = apk_container.read(bytes(blob))
    except Exception as e:
        print("NOTE mobile container: apk_container.py raised %s: %s; the usual search stands"
              % (type(e).__name__, str(e)[:160]), file=sys.stderr)
        return hit
    for n in notes or ():
        print("NOTE mobile container: %s" % n, file=sys.stderr)
    if not got:
        return hit
    route = got["route"]
    LAST.setdefault("saw", []).append("container: %s" % route)
    return Hit(got["code"], "medium", route, _slug(route, 48), ())


def _side_fallback(hit, held):
    """Day 21 final prep (second review): a side field's member held by named_member_hit is the answer only when the
    usual reading gives no code, and then unsure under `<its route>:side-member` (a name of its own, never the judged
    `apk-string:dex`). Beside a code of the usual reading the second-code look offers the member's code after it.
    The package look's own reading of that same member (`apk-string:*`, `apk-pieces:*`: the one code of the whole
    package, judged on Day 20 for a `dynamic` document) is no reading of the document either: the same code from it
    is offered under the side key too, never plain while `data` holds a value no reader decoded."""
    if held is None:
        return hit
    side, field, n = held
    if hit is not None and hit.confidence in ("high", "medium") and hit.value:
        if not (hit.value == side.value and hit.route.startswith(("apk-string", "apk-pieces"))):
            return hit
        why = "the usual reading gives the same code only from the package look (%s)" % route_name(hit)
    else:
        why = "the usual reading gives no code"
    LAST.setdefault("saw", []).append("%s: %s; the side field %s's member is offered unsure under %s"
                                      % (n, why, field, _key(side)))
    print("NOTE mobile side member: %s named by the side field %s gives %s; %s: unsure under %s (Day 21 final prep)"
          % (n, field, side.value, why, _key(side)), file=sys.stderr)
    return side


BESIDE_ANALYSIS = ":beside-analysis"   # the end of the key of a package-look code beside an `analysis` document
PACKAGE_ROUTES = ("apk-string", "apk-pieces", "apk-sigblock", "apk-zip-", "keystore:")   # the package look's routes
PAYLOAD_FIELDS = ("data", "payload", "blob", "cipher", "ciphertext", "encoded")   # dex_chain_codec.has_data's fields


def _doc_payload(doc):
    """True when the puzzle document carries a payload a reading decodes: a non-empty field of PAYLOAD_FIELDS, the
    fields dex_chain_codec.has_data reads (Day 20's `dynamic` document names the dex that holds the code in `data`).
    An `analysis` document (schema, day, codec, build: 38 of the saved documents) carries none, nor does a split
    document whose `data` is empty (16, read through its parts, never by the package look). A member named in some
    other field is no payload here: the package look's code need not come from that member (a decoy string in
    classes.dex beside a document that names the native library), so such a document's package-look code is unsure
    too, one probe on the base."""
    return any(doc.get(k) not in (None, "", [], {}) for k in PAYLOAD_FIELDS)


def _beside(ans):
    """True for an unsure answer under a `:beside-analysis` key (_beside_analysis), whatever _as_asked added to it."""
    try:
        return bool(ans) and labels.is_unsure(ans) and BESIDE_ANALYSIS in (labels.parse(ans).key or "")
    except Exception:
        return False


def _beside_merge(beside_ans, chain_ans):
    """Day 27 so-ambig fix round 2 (the review of 38a1668, minor): dex_chain_codec.answer_any's pick stood in for a
    `:beside-analysis` answer whole, so the package look's code was no longer offered (if the judge wants it, the base
    probe failed and the lane went to None). Now the chain's code(s) come first and the package look's after them, each
    value once, under the `:beside-analysis` key (a candidate key when either side is one: row 346); plain only for a
    name the judge has accepted there. A plain or unreadable chain answer is returned as it is.

    B-229 fix round 2: beside a document dex_chain_codec.is_analysis reads as `analysis`, solve_set then withdraws a
    merged answer that offers any value the chain did not compute (_chain_stray: fail closed, never a decoy as a
    candidate). The merge stands as it was for a renamed codec with no payload (is_analysis False)."""
    try:
        b = labels.parse(beside_ans) if labels.is_unsure(beside_ans) else None
        c = labels.parse(chain_ans) if labels.is_unsure(chain_ans) else None
    except Exception:
        return chain_ans
    if b is None or c is None:
        return chain_ans
    opts, names, values = [], set(), set()
    for name, value in [tuple(o) for o in c.options] + [tuple(o) for o in b.options]:
        if name in names or value in values:
            continue
        names.add(name)
        values.add(value)
        opts.append((name, value))
    key = b.key or ""
    if key.endswith(labels.CANDIDATE_MARK) or (c.key or "").endswith(labels.CANDIDATE_MARK):
        base = key[:-len(labels.CANDIDATE_MARK)] if key.endswith(labels.CANDIDATE_MARK) else key
        got = labels.candidates(base, opts)
    else:
        got = labels.pick(key, opts)
    print("NOTE mobile beside analysis: the dex chain's %s first, then the package look's %s, under %s (so-ambig fix "
          "round 2)" % ([v for _, v in c.options], [v for _, v in b.options], key), file=sys.stderr)
    return got if got is not None else chain_ans


BESIDE_DOC_MEMBERS = 64   # members _reading_docs reads for a document when the puzzle member holds none


def _reading_docs(members):
    """Day 27 so-ambig fix round 2 (the review of 38a1668, F2): the puzzle documents the usual reading finds, for rule
    3. assets/huntress_puzzle.json as solve_members parses it (_json: plain, base64, hex, UTF-16, JSON5; asset_docs; a
    whole-member layer, doc_layers: zlib, one-byte XOR); when that member is absent or holds no document, the documents
    standing in the other members, in the reading's order (_json and asset_docs for a member of at most MAX_WRAPPED
    bytes, doc_layers, embedded_docs for a .bin or .dex member), at most BESIDE_DOC_MEMBERS members. Every puzzle-shaped
    object of each (docs_in). Rule 3 read the member as _json alone, so a document under a layer or inside a .bin, and
    its codec `analysis`, left the classes.dex decoy PLAIN under the judged apk-string:dex beside the library. An
    object of assets/huntress_puzzle.json itself is the document by its name whatever its fields (round 1 read any
    object there: one with no codec at all is a document with no payload), and an object anywhere that carries the
    huntress.mobile.puzzle schema is one too."""
    def objs(obj, own):
        out = [p for p, _ in docs_in(obj)] if obj is not None else []
        if isinstance(obj, dict) and obj not in out:
            s = obj.get("schema")
            if own or (isinstance(s, str) and s.strip().startswith(SCHEMA_LITERAL.decode())):
                out.insert(0, obj)
        return out

    def parse(n, body, whole):
        obj, _ = _json(body, whole=whole)
        if obj is None:
            got = asset_docs.parse(n, body, known=lambda name: _known(ALIASES.get(name, name)))
            obj = got[0][0] if got else None
        if obj is None:
            got = doc_layers(body) or (embedded_docs(n, body) if n.endswith((".bin", ".dex")) else None)
            obj = got[0] if got else None
        return objs(obj, whole)
    if not isinstance(members, dict):
        return []
    body = members.get(PUZZLE)
    if isinstance(body, (bytes, bytearray)):
        try:
            got = parse(PUZZLE, bytes(body), True)
        except Exception:
            got = []
        if got:
            return got
    pool = {n: bytes(b) for n, b in members.items() if isinstance(b, (bytes, bytearray))}
    for n, b in list(pool.items()):
        # a container among the members (an Android backup, a tar, a gzip) is opened one level down, as solve_members
        # opens it before it looks for a document
        if b[:2] == b"\x1f\x8b" or b[:15] == b"ANDROID BACKUP\n" or b[257:262] == b"ustar":
            try:
                for name, inner in apk_resources.expand(n, b):
                    pool.setdefault(name, inner)
            except Exception:
                pass
    out = []
    order = sorted((n for n in pool if n != PUZZLE and not _SIGNING.match(n)),
                   key=lambda n: (not n.startswith("assets/"), n == "AndroidManifest.xml", n))
    for n in order[:BESIDE_DOC_MEMBERS]:
        b = pool[n]
        try:
            if n.endswith(".dex"):
                # the app's code: only a puzzle document standing in it as JSON text, as solve_members reads a dex
                got = embedded_docs(n, b) if SCHEMA_LITERAL in b else None
                out += objs(got[0], False) if got else []
            else:
                out += parse(n, b, False)
        except Exception:
            continue
    return out


def _doc_codec(doc):
    """The document's codec name, lower-cased (a {name: ...} or [..] spelling read as the first name in it)."""
    c = doc.get("codec") if isinstance(doc, dict) else None
    if isinstance(c, dict):
        c = c.get("name") or c.get("type") or c.get("codec")
    if isinstance(c, list) and c:
        c = c[0]
    return c.strip().lower() if isinstance(c, str) else ""


def _payload_proves(doc, code, members):
    """Day 27 so-ambig fix round 2 (the review of 38a1668, OPEN RISK 6): does the document PROVE the package look's
    `code`? Only when its own codec decodes its fields to that very code (own_doc_hit), or when a member it names by
    path is read to it by the named-member readers, under named_member_hit's own rule of which field may name the
    payload: a payload field (`data`, `payload`, ...) always; another field (legacy_module, hint) only when the
    document's own codec reads nothing from its fields and `data` holds no value of its own (a loader codec such as
    `dynamic`, as side_member lets such a member stand); or dynamic_members' reading of `data` (a list of paths,
    `<archive>!/<member>`, a basename). A payload that decodes to nothing (`{"codec": "computed", "data": "Zm9vYmFy"}`,
    `payload: "x"`, a list of words, a member holding no code) proves nothing: the classes.dex decoy was sent PLAIN
    under the judged apk-string:dex there."""
    clock = Clock()
    own = own_doc_hit(doc, lambda: [], clock)
    if own is not None:
        return own.value == code
    side_ok = not _data_unread(doc, members)
    for field, v in flat(doc):
        n = _member_path(v, members)
        if not n or (field.split(".")[0] not in PAYLOAD_FIELDS and not side_ok):
            continue
        try:
            hit = _named_one(doc, field, n, members, lambda: [], clock, [])
        except Exception:
            hit = None
        if hit is not None and hit is not _STOP and hit.value == code:
            return True
    if dynamic_members is not None:
        try:
            got = dynamic_members.read(doc, members)
        except Exception:
            got = None
        if got and got[0] == code:
            return True
    return False


def _beside_analysis(hit, members):
    """Day 27 (so-ambig, round 2): a document whose codec is `analysis` says the app's own dex chain COMPUTES the
    code (dex_chain_codec.py; judged on Day 23 as `analysis:dex-chain`). When that chain declines (a library left
    out, an unmodelled call) the usual reading goes on, and its package look (`apk-string:*`, `apk-pieces:*`: the one
    code-shaped string of the whole package; a keystore secret, a code at the container level) is no reading of that
    computation: a decoy string in classes.dex was sent PLAIN under `mobile.codec/apk-string:dex`, the name the judge
    accepted on Day 20 for a `dynamic` document, whose `data` names the dex that holds the code. Such a Hit (its own
    route one of PACKAGE_ROUTES) goes under its own key, `<its key>:beside-analysis`
    (a candidate key keeps its mark), never plain before the judge accepts a name there. A name the judge REJECTED
    under the Hit's own key is not offered again under the new one (Day 23 rejected `apk-pieces:dex-method`, "ANS-"
    and the hex alphabet one method holds, on an analysis attempt): when every name is, the Hit is returned as it is
    and decide() gives None, as before. Every other Hit, and any Hit of a document with another codec (Day 20's
    `dynamic` stays plain), is returned as it is.

    Fix round 1 (the review of 6f0ed2a): the rule keyed on the codec string `analysis` alone, so the same document
    under any other codec spelling (`{"name": "analysis"}`, `["analysis"]`, `analysis-v2`, `computed`, none at all)
    still sent the dex decoy PLAIN, with or without the library. The rule now holds for every document that carries
    no payload (_doc_payload: no payload field), whose code only the app can compute: codec_search.solve_set then
    hears dex_chain_codec.answer_any in place of such an unsure answer (the dex chain's own reading, unsure under
    `mobile.codec/dex-chain`), as it hears answer() for an `analysis` document. A document with a payload (Day 20's
    `dynamic` one, every codec with `data`) is untouched.

    Fix round 2 (the review of 38a1668). F2: the rule read assets/huntress_puzzle.json as _json alone, so a document
    under a whole-document layer (zlib, one-byte XOR) or standing in a .bin or .dex member skipped it, and the decoy
    stayed plain beside the library; it now reads every document the usual reading finds (_reading_docs). OPEN RISK 6:
    a payload field that decodes to nothing kept the decoy plain; a payload now counts only when it PROVES the code
    (_payload_proves: a member it names that the named-member readers read to that very code, or the document's own
    codec decoding it). So the Hit is returned as it is only when no document the reading finds is an `analysis` one
    and one of them proves the code, or when no document is found at all (as before); otherwise its own key."""
    if hit is None or hit.confidence not in ("high", "medium") or not hit.value:
        return hit
    if not str(hit.route).startswith(PACKAGE_ROUTES):
        return hit
    if (hit.codec or "").split(labels.CANDIDATE_MARK)[0].endswith(SIDE_MEMBER):
        return hit                                    # _side_fallback's key of its own: never the judged name already
    try:
        docs = [d for d in _reading_docs(members) if isinstance(d, dict)]
    except Exception:
        docs = []
    if not docs:
        return hit                                    # no document at all: the package look is the reading, as before
    analysis = [d for d in docs if _doc_codec(d) == "analysis"]
    doc = (analysis or docs)[0]
    if analysis:
        why = "whose codec is analysis"
    else:
        try:
            if any(_doc_payload(d) and _payload_proves(d, hit.value, members) for d in docs):
                return hit
        except Exception:
            pass                                      # a document that does not read as one: no payload proven
        doc = next((d for d in docs if _doc_payload(d)), doc)
        why = ("whose payload does not prove it (codec %s)" if _doc_payload(doc) else
               "that carries no payload (codec %s)") % json.dumps(doc.get("codec"), default=str)[:60]
    mark = labels.CANDIDATE_MARK if (hit.codec or "").endswith(labels.CANDIDATE_MARK) else ""
    base_codec = _key(hit)[len(KEY):]
    base_codec = base_codec[:-len(mark)] if mark else base_codec
    if base_codec.endswith(BESIDE_ANALYSIS):
        return hit
    try:
        rejected = set(labels.state(_key(hit))["rejected"])
    except Exception:
        rejected = set()
    keep = [(name, value) for name, value in offered(hit) if name not in rejected]
    if not keep:
        return hit
    base_codec = base_codec[:64 - len(BESIDE_ANALYSIS)]   # _key cuts a codec at 64: the mark must survive the cut
    print("NOTE mobile beside analysis: %s gives %s beside a document %s (the app's dex chain computes the code, and "
          "this is no reading of it): unsure under %s (so-ambig r2)"
          % (route_name(hit), hit.value, why, KEY + base_codec + BESIDE_ANALYSIS + mark), file=sys.stderr)
    if len(keep) == len(offered(hit)):
        return hit._replace(codec=base_codec + BESIDE_ANALYSIS + mark)
    return Hit(keep[0][1], hit.confidence, keep[0][0], base_codec + BESIDE_ANALYSIS + mark, (), tuple(keep[1:]))


def _solve(members, inner=(), clock=None, blob=b"", twins=(), dups=(), early=None):
    """Solve one APK's members and record the outcome in LAST. Returns the answer to give.

    `clock` is the APK's budget when the caller started it before reading the archive,
    `twins` what read_members found beside the puzzle document under its own name, and `dups`
    the earlier bodies of two zip entries of that name in the delivery itself. `early`, when given,
    is called with (answer, key) as soon as this module's own reading is decided and before the rest
    of the package is looked at for a second code: the runner's partial answers hold it from then on,
    so nothing that look meets (a keystore, a large member) can withhold it."""
    LAST.clear()
    clock = clock or Clock()
    t0 = clock.start
    try:
        # Forecast matrix: a small set of *self-identifying* structural documents used to spend the whole
        # 0.12-second large-Mastery per-set budget in the generic graph before lookahead_readers got its turn.  The
        # structural reader is exact (it accepts only one complete ANS code), cheap, and already the fallback
        # for these shapes.  Give it first refusal only when the document itself proves that shape: list/map
        # data (character/linked/collapsed encodings), or one of the three explicitly stated keyed algorithms
        # implemented by lookahead_readers.  Ordinary strings, every judged codec and every saved Day 1--28
        # document take the unchanged path.  Conflicting lookahead readers still make read() return None, in
        # which case the generic search runs as before; the later second-code scan still guards a fast hit.
        fast = None
        keyed_failed = False
        keyed_look = False
        try:
            pbody = members.get(PUZZLE)
            pdoc = _json(pbody, whole=True)[0] if isinstance(pbody, (bytes, bytearray)) else None
            pname = str((pdoc or {}).get("codec") or (pdoc or {}).get("algorithm")
                        or (pdoc or {}).get("algo") or "").strip().lower()
            pdata = (pdoc or {}).get("data") if isinstance(pdoc, dict) else None
            keyed_look = ("xtea" in pname or "rolling" in pname
                          or pname in ("progressive_xor", "lcg", "lcg_keystream", "lcg-keystream"))
            if isinstance(pdoc, dict) and keyed_look and lookahead_readers is not None:
                # Ask only the reader the document states.  Calling the aggregate look-ahead here let an unrelated
                # XML/resource code stand in for a failed XTEA/rolling/LCG decrypt; once that resource route had a
                # ledger name it could become a wrong plain answer.  A stated keyed algorithm whose own key does not
                # produce exactly one code is a deterministic decline, even when the package carries decoy codes.
                hits = lookahead_readers.keyed_cipher(pdoc, members)
                distinct = {}
                for route, code in hits:
                    distinct.setdefault(code, route)
                if len(distinct) == 1:
                    code, route = next(iter(distinct.items()))
                    route = "lookahead:" + route
                    fast = Hit(code, "medium", route, _slug(route, 48), ())
                else:
                    keyed_failed = True
            elif (isinstance(pdoc, dict) and isinstance(pdata, (list, dict))
                  # Keep every established stated-layout reader in front of the forecast bridge.  In
                  # particular, Day 18's `indexed` map must keep the judged
                  # `indexed:by-key:@data:map` route; letting collapsed_keys take it first moves the
                  # same fact to mobile.codec/lookahead and loses the accepted per-codec name.  The
                  # bridge is for a genuinely novel/opaque structural control name (the forecast
                  # fixtures use `mystery`), not a faster spelling of an existing arrangement.
                  and pname not in set(ARRANGE_STEPS).union(GRID_NAMES, {
                      "pairs", "map", "stride", "affine_index", "lookup", "string_pool",
                      "seeded_shuffle",
                  })):
                fast = lookahead_revise(None, members, dups)
        except Exception:
            fast, keyed_failed = None, keyed_look
        # For those three explicitly stated algorithms, a failed exact decrypt is a deterministic decline.  Sending
        # the ciphertext through the generic transform graph after its stated key failed only burns the small
        # Mastery share and can promote an unrelated accidental code.  Other structural shapes still fall through.
        hit = fast if fast is not None else (None if keyed_look else
                                              (dynamic_member_hit(members)
                                               or solve_members(members, inner, clock, blob, twins)))
        hit = _side_fallback(hit, LAST.pop("side_deferred", None))
        hit = stated_revise(hit, members, STATED_TEXTS)
        if not keyed_failed:
            hit = lookahead_revise(hit, members, dups)  # a fast hit returns unchanged; every other shape falls back here
            hit = container_revise(hit, blob)
        hit = _beside_analysis(hit, members)   # Day 27 so-ambig r2: no judged package-look name beside `analysis`
        answer, key = decide(hit)
    except Exception as e:  # hostile bytes must cost this answer, not the run
        saw = LAST.get("saw", [])
        LAST.clear()
        LAST.update(answer=None, confidence="none", route="solver error %s: %s" % (type(e).__name__, str(e)[:120]),
                    saw=saw)
        return None
    saw = LAST.get("saw", [])
    LAST.clear()
    LAST.update(answer=answer if not labels.is_unsure(answer) else "unsure",
                confidence=hit.confidence if hit else "none",
                route=route_name(hit) if hit else "no document or string decodes to ANS-[0-9A-F]{16}")
    if hit and hit.options:
        LAST["options"] = [name for name, _ in offered(hit)]
    if hit and hit.value and (answer is None or labels.is_unsure(answer)):
        LAST["candidate"] = hit.value
        if answer is None and key:  # say "rejected" only when the ledger does
            try:
                rejected = all(name in labels.state(key)["rejected"] for name, _ in offered(hit))
            except Exception:
                rejected = False
            LAST["route"] += (" (rejected by the judge for this key)" if rejected
                              else " (no answer could be offered for this key)")
    if key:
        LAST["key"] = key
    if early is not None:
        try:
            early(answer, key)
        except Exception:
            pass
    if answer is not None and hit and hit.value:
        # A second code in the package (the player's decision of 2026-10-13, which reverses row
        # 270's): the answer offers both, this hit's own first, under a key of its own, so one or
        # two base probes say which the judge wants and that name answers the next variant. No
        # saved APK of Days 1 to 17 holds a second code; their answers are as they were. Beside a
        # plain answer the document's other fields are also searched (Day 18 look-ahead), and a
        # field the document's own selector names ({"use": "b"}) is offered before this hit.
        try:
            others, complete, clear_truncated = second_codes(members, hit, clock, blob if isinstance(blob, (bytes, bytearray)) else b"", dups)
        except Exception:
            others, complete, clear_truncated = [], False, False
        try:
            more, ahead, targets = document_codes(members, hit, others, search=not labels.is_unsure(answer),
                                                  dex=complete)
        except Exception:
            more, ahead, targets = [], set(), []
        # What is offered: every code the look saw when it was complete; when it was not (past its
        # bounds), the codes of the document's own fields still are (field:@...: read the same on every
        # run, whatever the package holds; review of 2026-10-17: a decoy document inside a 70-member APK
        # stayed plain and wrong). Each value once, the look's own names first.
        seen = list(others) + [m for m in more if m[1] not in {code for _, code, _ in others}]
        offer, values = [], {hit.value}
        cand = bool(key) and key.endswith(labels.CANDIDATE_MARK)
        again = SECOND in (hit.codec or "")   # side_member's pick (Day 21 final prep): already a second-code key
        if cand or again:
            # a candidate pick already offers every branch's code: a second look's copy of one is no new code
            values.update(v for _, v in offered(hit))
        # Fail-closed (never-guess), NARROWED (review 2026-10-23, docs/retro/mobile-d05-revise-notes.md): when the
        # clear-code scan was truncated by the member or byte bound a real code may sit in the unscanned members/
        # bytes beyond it. The document's own reading is demoted to an unsure pick ONLY under genuine decoy-vs-real
        # ambiguity -- a competing clear code actually exists, within the bound (`seen`) OR anywhere past it (the
        # cheap truncation-proof clear scan `other_codes`, deterministic with no clock). A merely-large LEGIT package
        # whose `data` is the sole code (no competing reading anywhere) is NOT demoted: it stays plain, so a legit
        # reading is never needlessly demoted and no accepted name reaches the second-code ledger from it (which,
        # under the old bare per-codec key, re-plained a later variant's decoy). Already-unsure answers, candidate
        # picks and side-member second-code picks are left as they are.
        # wave12 adversarial review: a code at an offset the bounded window scan never reaches, inside a long side
        # field with no `=` padding and no repeated-character filler (hex, reverse; a pad-less class), was a WRONG
        # plain answer. Fail-closed: a long non-key side field of the data's class the scan cannot cover
        # exhaustively (long_field_unscanned) demotes the lone reading too, whether or not a competing code was
        # found there. A legit puzzle has no such field, so no correct plain is weakened.
        # Day 28 look-ahead: two more fail-closed demotes beside long_field_unscanned, each restrict-only (a legit
        # puzzle carries neither a long side field nor a prose field, so no correct plain is weakened):
        #  - long_clear_field_unscanned: a CLEAR code glued into filler in a >256-char side field, which the
        #    boundary-guarded package scan and the codec-class window scan both miss (X02);
        #  - stated_spec.states_unexecutable_cipher: a keyed AES/RC4/Vigenere or a permutation stated only in words,
        #    whose shape this reader recognises but cannot carry out, beside a decoy `data` (S01/S02).
        try:
            _pb = members.get(PUZZLE)
            _pdoc = _json(_pb, whole=True)[0] if _pb is not None and len(_pb) <= MAX_WRAPPED else None
            long_unscanned = (not labels.is_unsure(answer) and not cand and not again and bool(hit.value)
                              and ((isinstance(_pdoc, dict)
                                    and (long_field_unscanned(_pdoc, own_codec(_pdoc))
                                         or long_clear_field_unscanned(_pdoc)))
                                   or bool(stated_spec and stated_spec.states_unexecutable_cipher(members, STATED_TEXTS))))
        except Exception:
            long_unscanned = False
        demote = (clear_truncated and not labels.is_unsure(answer) and not cand and not again and bool(hit.value)
                  and (bool(seen) or bool(other_codes(members, hit.value, _FOREVER,
                                                       blob if isinstance(blob, (bytes, bytearray)) else b"")))) \
            or long_unscanned
        for name, code, where in seen:
            if code not in values and (complete or demote or name.startswith("field:@")):
                values.add(code)
                offer.append((name, code, where))
        if seen:
            LAST["other_codes"] = ["%s in %s" % (code, where) for _, code, where in seen]
        if seen and not offer and not demote:
            # past the look's bounds (a fact of the package, the same on every run): this module's reading stands
            LAST["second_look"] = ("not complete: the package is past the %d members or %d bytes the look reads, or holds a "
                                   "keystore that was not opened" % (SECOND_MEMBERS, SECOND_BYTES))
        elif offer or demote:
            if demote and not offer:
                # the clear scan was truncated and nothing else was seen (the real code is past the bound and
                # unreachable): still demote the lone reading so the base probes it and never banks a decoy plain.
                LAST["demoted_truncated"] = ("the %d-member / %d-byte second-code scan was truncated without ruling "
                                             "out a real code beyond it" % (SECOND_MEMBERS, SECOND_BYTES))
            if len(offer) < len(seen):
                LAST["not_offered"] = ["%s in %s (the look was not complete)" % (code, where) for name, code, where in seen
                                       if (name, code, where) not in offer]
            options, names = [], set()
            first = [(name, code, where) for name, code, where in offer if name in ahead]
            for name, value, where in (first + [(n, v, None) for n, v in offered(hit)]
                                       + [(name, code, where) for name, code, where in offer if name not in ahead]):
                if name in names and where and value not in {v for _, v in options}:
                    # Day 21 build: a second code under the same route name as this hit's own (both
                    # `apk-string:dex`, the named secondary dex and classes.dex) was dropped here, and the
                    # pick offered one code only; it is now offered under the name with its place
                    name = "%s@%s" % (name, _slug(where, 32))
                if name not in names:
                    names.add(name)
                    options.append((name, value))
            key = (key or _key(hit))
            if cand:
                key = key[:-len(labels.CANDIDATE_MARK)]
            if not again:
                key += SECOND + ("@" + "+".join(_slug(t, 24) for t in targets) if targets else "")
            if demote and not offer and not cand and not again:
                # The LONE fail-closed past-bound demote (review 2026-10-23): nothing was offered within the bound,
                # so the only option is the hit's own reading -- and a BARE per-codec `<codec>:second-code` key
                # offering it under the codec name let a name accepted on ONE package (a legit large package, whose
                # `data` IS the real code, probed once) re-plain ANOTHER package's decoy under the same key. Scope
                # the key to THIS delivery (when_fingerprint, as the when-branches pick does) and make it a
                # CANDIDATE key (row 346): never plain until the judge accepts a name for THIS key, and an accepted
                # hypothesis answers only this very document -- any other variant has another key and stays unsure,
                # so a decoy is never re-plained. The hit's own reading is renamed off the bare codec name
                # (_unbranded). A demote that DID offer a competing code within the bound keeps the established
                # `:second-code` pick below: it offers that code under its own route name (a place, not a codec),
                # which is what gets accepted, so the codec-name re-plain hazard does not arise.
                pbody = members.get(PUZZLE)
                pdoc = _json(pbody, whole=True)[0] if pbody is not None and len(pbody) <= MAX_WRAPPED else None
                key += "@doc-" + when_fingerprint(pdoc if pdoc is not None else pbody) + labels.CANDIDATE_MARK
                options = _unbranded(options, hit)
                answer = labels.candidates(key, options)
            else:
                if cand:
                    key += labels.CANDIDATE_MARK   # still a candidate key (row 346): probed only where a candidate may be
                answer = labels.pick(key, options)
            LAST.update(answer=answer if not labels.is_unsure(answer) else "unsure", key=key,
                        options=[name for name, _ in options], candidate=hit.value)
            if first:
                LAST["ahead"] = [name for name, _, _ in first]
    LAST["seconds"] = round(time.perf_counter() - t0, 3)
    LAST["saw"] = saw
    return answer


def solve_apk(apk: bytes):
    """The answer for one APK: a plain answer, an unsure answer ('??...'), or None."""
    clock = Clock()  # reading the archive is part of the APK's budget
    twins, dups = [], []
    members, inner = read_members(apk, clock=clock, twins=twins, dups=dups)
    if not members:
        LAST.clear()
        LAST.update(answer=None, confidence="none", route="the delivery is not a readable zip archive", saw=[])
        return None
    return _solve(members, inner, clock, apk, twins, dups)


# B-229: the question the command line asks of a computed-code delivery (Huntress set questions had this one id)
CODE_QUESTION = {"id": "answer", "question": "What is the answer code?", "answer_format": "ANS-XXXXXXXXXXXXXXXX"}


FAIL_CLOSED_ROUTE = ("analysis dex chain (dex_chain_codec.py): no single code proven, fail closed "
                     "(python -m ctf dexvm show names the decline)")


def _chain_stray(answer, proven) -> list:
    """B-229 fail closed: the values an unsure `answer` offers that the dex chain did not compute (`proven`: the chain's
    codes for an `analysis` document). Such a document carries no data: its code is what the app's own dex chain
    computes, so a package-look code beside a declined chain (`...:beside-analysis`, `...:analysis-unread`: a
    placeholder in a method nothing calls, Day 23 Mastery's ANS-0123456789ABCDEF) is no reading of it, and offering it
    as a candidate spends a probe on a decoy. [] for None, a plain answer (only the chain answers an `analysis`
    document plain), an unsure answer whose every value the chain computed, and a "??" string that does not parse
    (labels.parse gives it no options: nothing to probe, never sent)."""
    if answer is None or not labels.is_unsure(answer):
        return []
    proven = set(proven or ())
    return [v for _n, v in getattr(labels.parse(answer), "options", ()) if v not in proven]


def _computed(apk: bytes) -> str:
    """B-229: the delivery shape solve_apk does not read but solve_set does: 'split' for a bundle of split APKs
    (split_bundle.candidate, Day 26), 'analysis' when the puzzle document says the app's own dex chain computes the
    code (dex_chain_codec.is_analysis, Days 23 and 31), else ''."""
    if split_bundle is not None:
        try:
            if split_bundle.candidate(apk):
                return "split"
        except Exception as e:
            print("NOTE mobile split_bundle.candidate raised %s: %s" % (type(e).__name__, str(e)[:200]),
                  file=sys.stderr)
    if dex_chain_codec is None:
        return ""
    members, _inner = read_members(apk, clock=Clock())
    try:
        return "analysis" if members and dex_chain_codec.is_analysis(members) else ""
    except Exception as e:
        print("NOTE mobile dex_chain_codec.is_analysis raised %s: %s" % (type(e).__name__, str(e)[:200]),
              file=sys.stderr)
        return ""


def solve_delivery(apk: bytes, name: str = "delivery.apk"):
    """B-229 (arming the `analysis` codec): the answer for one delivery as the timed runner reads a set of it. A split
    bundle (Day 26) or an APK whose document says codec `analysis` (Days 23 and 31) is read by solve_set with the one
    code question, so the dex-chain VM, its split-asset hook and its in-memory loader answer it exactly as they answer
    a set: plain only under a judged route, unsure or None otherwise (fail closed). Any other delivery is solve_apk's.
    LAST holds the note the command line prints.

    Fail closed (B-229): for an `analysis` delivery the code is what the app's dex chain computes, so an unsure answer
    that offers any value the chain did not compute is withdrawn: None, never a candidate. Since fix round 2 the rule
    is solve_set's own (_chain_stray), so the set path the timed runner drives (ctf.adapt.setpool) fails closed too.

    Live fix (day_patch.py): heard on EVERY delivery, the same way solve_set hears it (answer() where the reader has
    no plain answer, then override()), so `ctf run`, `ctf arm` and `adapt prewarm` see a live fix whatever the
    delivery's shape. A live fix's answer is never withdrawn by the rule above: the operator wrote it."""
    kind = _computed(apk)
    ctx = {"delivery": apk, "delivery_name": name}
    if not kind:
        return _delivery_patch(solve_apk(apk), ctx)
    LAST_SET.clear()
    out = solve_set([dict(CODE_QUESTION)], {}, ctx)
    answer = out.get(CODE_QUESTION["id"])
    LAST.clear()
    LAST.update(LAST_SET)
    LAST["computed"] = kind
    patched = bool(LAST_SET.get("day_patch") or LAST_SET.get("day_patch_override"))
    if patched:
        LAST.update(confidence="day_patch", route="day_patch.py live fix")
    if answer is None:
        LAST.update(answer=None, confidence="none")
        if kind == "analysis" and not patched:
            LAST["route"] = FAIL_CLOSED_ROUTE
    elif labels.is_unsure(answer):
        parsed = labels.parse(answer)
        if parsed is not None and parsed.options:
            LAST["candidate"] = ", ".join(str(v) for _n, v in parsed.options)
            LAST["key"] = parsed.key
    return answer


def _delivery_patch(answer, ctx):
    """solve_delivery's live fix for a delivery solve_apk read: day_patch.answer() when there is no plain answer, then
    day_patch.override(), exactly as solve_set applies them. LAST says so when the patch changed the answer."""
    q = dict(CODE_QUESTION)
    new = answer
    if new is None or labels.is_unsure(new):
        fixed = _patched(q, {}, ctx)
        if fixed is not None:
            new = fixed
    new = _overridden(q, new, {}, ctx)
    if new != answer:
        LAST.update(answer=new if not labels.is_unsure(new) else "unsure", confidence="day_patch",
                    route="day_patch.py live fix")
        if labels.is_unsure(new):
            parsed = labels.parse(new)
            if parsed is not None and parsed.options:
                LAST["candidate"] = ", ".join(str(v) for _n, v in parsed.options)
                LAST["key"] = parsed.key
    return new


def solve_puzzle(doc: bytes):
    """The answer for one puzzle document, read as if it were the APK's usual asset."""
    return _solve({PUZZLE: doc})


# ---------------------------------------------------------------------------- day patch

def _load_patch():
    """day_patch.py from this folder, if someone wrote one today. A broken one is reported and ignored."""
    if not PATCH.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("mobile_day_patch", PATCH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except (Exception, SystemExit) as e:
        print("NOTE mobile day_patch.py could not be loaded: %s: %s" % (type(e).__name__, str(e)[:200]),
              file=sys.stderr)
        return None
    if not callable(getattr(mod, "answer", None)) and not callable(getattr(mod, "override", None)):
        print("NOTE mobile day_patch.py defines no answer(q, files, ctx); ignored", file=sys.stderr)
        return None
    return mod


_patch = _load_patch()  # at import, so a timed run pays for it before its clock starts
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
    if _respell is None:
        if new == PATCH_WITHDRAW:
            if value is None:
                return value
            new = None
        print("NOTE %s: %s replaced by day_patch.py (%s)" % (aid, str(value)[:100], str(new)[:100]), file=sys.stderr)
        return new
    # wave3 (T4, override-guard): a day_patch override() may not replace or withdraw a judge-accepted
    # plain answer; a BAD/unjudged/None id is still fixed. (T2, render_candidates): a read-but-unjudged
    # unsure value gets its value's other plausible spellings offered too, never a plain value.
    try:
        guarded, blocked, gnote = _respell.guard_value(aid, value, new)
    except Exception:
        guarded, blocked, gnote = (None if new == PATCH_WITHDRAW else new), False, ""
    if blocked:
        print("NOTE %s: %s" % (aid, gnote), file=sys.stderr)
        return value
    if guarded == value:
        return value
    if labels.is_unsure(guarded):
        try:
            guarded = _respell.enrich(guarded, q)
        except Exception:
            pass
    print("NOTE %s: %s replaced by day_patch.py (%s)" % (aid, str(value)[:100], str(guarded)[:100]), file=sys.stderr)
    return guarded


def _patched(q, files, ctx):
    if _patch is None or not callable(getattr(_patch, "answer", None)):
        return None
    try:
        return _patch.answer(q, files, ctx)
    except (Exception, SystemExit) as e:
        print("NOTE mobile day_patch.answer raised %s: %s" % (type(e).__name__, str(e)[:200]), file=sys.stderr)
        return None


# ---------------------------------------------------------------------------- runner contract

MASTERY_SOLVE = 1.2      # seconds all the sets of one attempt may spend together (the lane's solve cap is 1.5)
MIN_BUDGET = 0.12        # seconds one APK always gets: a judged codec takes about a millisecond


def set_budget(ctx) -> float:
    """Seconds this set's APK may spend: BUDGET, or less when the attempt has so many deliveries that
    BUDGET for each would pass the lane's solve cap (Day 8's Mastery had five; eight are rehearsed).

    It only shortens a miss. An answer by a judged route is found long before either limit."""
    attempt = ctx.get("attempt") if isinstance(ctx, dict) else None
    n = 0
    if isinstance(attempt, dict):
        for field in ("artifacts", "downloads"):
            if isinstance(attempt.get(field), list):
                n = max(n, len(attempt[field]))
        sets = {q.get("set") for q in attempt.get("questions") or () if isinstance(q, dict) and q.get("set") is not None}
        n = max(n, len(sets))
    return BUDGET if n <= 3 else max(MIN_BUDGET, min(BUDGET, MASTERY_SOLVE / n))


_CODE_WORDS = re.compile(r"ANS\\?-|\banswer[ _-]code\b|\bevidence[ _-]code\b"
                         r"|\bbackend(?:'s)?\b(?!\s+(?:url|uri|host|hostname|endpoint|address|domain|server|api|path|port)\b)", re.I)
# Answer kinds that cannot hold `ANS-` and sixteen hex digits: a question of such a kind never gets the code.
NEVER_CODE = frozenset(("integer", "int", "number", "numeric", "float", "boolean", "bool", "enum", "json", "ordered_tokens",
                        "mitre_attack_id"))
_SAMPLE_CODE = "ANS-0123456789ABCDEF"
CODE, FACTS_THEN_CODE, FACTS, NOTHING = "code", "facts-then-code", "facts", "nothing"


def _format_takes_code(fmt) -> bool:
    """Does the answer format itself say the ANS- code: the literal `ANS-` anywhere in it (also with
    the hyphen escaped, as a regular expression writes it), or a short regular expression among
    its values that the shape of a code matches in full (`^[A-Z]{3}-[0-9A-F]{16}$`)."""
    text = fmt if isinstance(fmt, str) else json.dumps(fmt, default=str)
    if "ANS-" in text or "ANS\\-" in text or "ANS\\\\-" in text:
        return True
    for v in (fmt.values() if isinstance(fmt, dict) else ()):
        if isinstance(v, str) and 8 <= len(v) <= 80 and "{" in v and sum(v.count(c) for c in "+*") <= 1:
            try:
                if re.fullmatch(v, _SAMPLE_CODE):
                    return True
            except re.error:
                continue
    return False


def answer_route(q) -> str:
    """What the question under the lane's id `answer` is given (rows 270 and its review, 2026-10-12).

    The id asked for the code on every saved attempt of Days 1 to 12 (100 questions of 100), a
    wrong plain code costs one rejected single-answer request on the base, and a withheld right
    one costs an agent and, on a one-attempt route, the clock. So the id errs toward the code:

      CODE              the format names `ANS-` (or is a pattern the code's shape matches), or the
                        format or the sentence has a word of the code (`answer code`, `evidence
                        code`, the backend that returns it) and the kind can hold a code
      NOTHING           a word of the code under a kind that cannot hold one (an integer, an enum,
                        JSON, ...): the code is asked in a form it does not have
      FACTS             a kind that cannot hold a code and no word of it: apk_facts.py or None
      FACTS_THEN_CODE   anything else (a free-text or unknown kind, no word of the code):
                        apk_facts.py first, and the code when it reads no fact in the question.
                        That is row 270's case: an activity-name question under `exact_text`
                        stays an unsure activity pick and is not given the code."""
    fmt = q.get("answer_format")
    kind = str(fmt.get("kind") or "").strip().lower() if isinstance(fmt, dict) else ""
    if fmt and _format_takes_code(fmt):
        return CODE
    text = "%s %s %s" % (q.get("question") or "", q.get("prompt") or "",
                         (fmt if isinstance(fmt, str) else json.dumps(fmt, default=str)) if fmt else "")
    worded = bool(_CODE_WORDS.search(text))
    if kind in NEVER_CODE:
        return NOTHING if worded else FACTS
    return CODE if worded else FACTS_THEN_CODE


_LOWER = re.compile(r"\blower(?:[- ]?case)?\b", re.I)
_UPPER = re.compile(r"\bupper(?:[- ]?case)?\b", re.I)      # "upper or lowercase", "uppercase", "upper-case"


def _lower(value):
    return value[:4] + value[4:].lower() if isinstance(value, str) and value.startswith("ANS-") else None


def lower_asked(q) -> bool:
    """Does the question's format name the code (ANS-) and ask it in lower case, and not in upper case too?"""
    fmt = q.get("answer_format")
    text = fmt if isinstance(fmt, str) else json.dumps(fmt, default=str) if fmt else ""
    return bool(fmt) and bool(_LOWER.search(text)) and not _UPPER.search(text) and _format_takes_code(fmt)


def _as_asked(q, answer, key, unasked=False):
    """The answer with the doubts the QUESTION adds, under ONE key made from the codec's own (Day 14
    look-ahead; review of 2026-10-13):

      :unasked       the id `answer` under a stated format that is not the code's, with no word of the
                     code and no fact read: the code is the likeliest answer and not a proven one
      :lower-asked   the format names the code and asks lower case: the lower-case spelling follows
                     each upper-case one (`<name>:lower`)

    The options are this module's own (its route names when the codec is not judged yet, else `code`,
    or `upper` and `lower`), and the key is `<the codec's key><marks>`: `mobile.codec/base32:lower-asked`.
    One key, so the one name the judge accepts on the base answers the replay plain. A second key
    behind the codec's (as the first cut had it) left the replay unsure under a key nothing could
    probe once the base was closed, and the gate shut. Any other question changes nothing."""
    marks = (":unasked" if unasked else "") + (":lower-asked" if lower_asked(q) else "")
    if answer is None or not marks:
        return answer
    got = labels.parse(answer) if labels.is_unsure(answer) else None
    try:
        base_key, options = (got["k"], [(o[0], o[1]) for o in got["o"]]) if got is not None else \
            (key or KEY + "unnamed", [("code" if unasked else "upper", answer)])
    except Exception:
        return answer
    if ":lower-asked" in marks:
        wider = []
        for name, value in options:
            wider.append((name, value))
            low = _lower(value)
            if low and low != value:
                wider.append(("lower" if name == "upper" else name + ":lower", low))
        options = wider
    if base_key.endswith(labels.CANDIDATE_MARK):
        # a candidate key (when_branches, row 346) keeps its mark at the end: it is still probed only as one
        return labels.pick(base_key[:-len(labels.CANDIDATE_MARK)] + marks + labels.CANDIDATE_MARK, options[:12])
    return labels.pick(base_key + marks, options[:12])


ANALYSIS_UNREAD = ":analysis-unread"


def _analysis_unread(answer, key):
    """KB-2 fix round 1 (review of e281f95, issue 1a): (answer, key) of the generic search's reading of a document
    whose codec is `analysis` and whose own dex chain was not read to exactly one code. Such a document carries no
    data: the code is computed by the app's dex chain, so a code the generic search finds in clear (the one code of
    the package, `apk-string:dex`, judged on Day 20 for another kind of document) may be a decoy beside it. It is
    never plain under the route's own key: the reading stays, as an unsure pick under `<that key>:analysis-unread`
    (a plain answer as the option `code`, an unsure one with its own options; a candidate key keeps its mark at the
    end). No saved delivery answers through here (every saved `analysis` delivery is read by its dex chain)."""
    if answer is None:
        return None, key
    got = labels.parse(answer) if labels.is_unsure(answer) else None
    if got is not None:
        if not got.key or not got.options:
            return answer, key           # an unsure string that does not parse stays as it is (never sent)
        base, options = got.key, list(got.options)
    else:
        base, options = (key or KEY + "unnamed"), [("code", answer)]
    cand = base.endswith(labels.CANDIDATE_MARK)
    if cand:
        base = base[:-len(labels.CANDIDATE_MARK)]
    if BESIDE_ANALYSIS in base:
        # the KB-2 port onto so-ambig: so-ambig's _beside_analysis already gave this package-look reading a key of its
        # own beside an `analysis` document (the armed tree's name for exactly this shape), never plain until judged;
        # it keeps that one key, with no second suffix
        return answer, key
    if not base.endswith(ANALYSIS_UNREAD):
        base += ANALYSIS_UNREAD
    ukey = base + (labels.CANDIDATE_MARK if cand else "")
    return labels.pick(ukey, options[:12]), ukey


def asks_code(q) -> bool:
    """True when the question under the id `answer` is the code's at once (answer_route is CODE)."""
    return answer_route(q) == CODE


def split_look(members, value, blob=b""):
    """split_bundle's second-code look over one split's members (or the bundle's own): what second_codes finds
    beside a single APK's answer `value`, [(name, code, where)]. Bounded by its sizes, no clock (_FOREVER), so a
    base, its gate replay and a clock agree."""
    found, _complete, _truncated = second_codes(members, Hit(value, "high", "split-bundle", None, ()), _FOREVER,
                                                blob if isinstance(blob, (bytes, bytearray)) else b"")
    return found


def solve_set(questions, files, ctx):
    """One set: the APK's answer under the set's question id. See the module text for the three outcomes.

    Every set so far has had one question, `answer`, whose format is the ANS- code. The id
    `answer` is given the code unless its answer kind cannot hold one or apk_facts.py reads a
    fact of the package in a question that has no word of the code (answer_route). If a
    set ever holds more, only that question is given the code: what the
    others ask is not known here. A single question under another name is given the code
    unless it states an answer format that is not the ANS- code: the code would then be a
    guess at a question this module cannot read."""
    ctx = ctx or {}
    files = files if isinstance(files, dict) else {}
    blob = ctx.get("delivery") or b""
    clock = Clock(set_budget(ctx))  # reading the archive is part of the APK's budget
    twins, dups = [], []
    members, inner = read_members(blob, clock=clock, twins=twins, dups=dups) if blob else ({}, set())
    unpacked = not members
    if not members:  # not a zip: take what the runner unpacked
        members = {k: v for k, v in files.items() if " -> " not in k and isinstance(v, (bytes, bytearray))}
    elif PUZZLE not in members and isinstance(files.get(PUZZLE), (bytes, bytearray)):
        # The runner unpacks deeper than read_members (an APK over 1 MiB inside a zip, a 7z,
        # an AES zip) and the Day 4 solver reads the document from there. Use it rather than
        # miss it, marked as found inside another archive, which makes the answer unsure.
        members[PUZZLE] = bytes(files[PUZZLE])
        inner = set(inner) | {PUZZLE}
        unpacked = True
    if (PUZZLE in members and (unpacked or PUZZLE in inner)
            and "%s -> %s" % (ctx.get("delivery_name"), PUZZLE) not in files):
        # The document is not the delivery's own member: it comes from an archive inside, and the
        # runner, which unpacks deeper than read_members, kept the first body it unpacked under the
        # name. The other bodies under the name are that document's twins.
        twins += [bytes(v) for k, v in files.items() if k.endswith(" -> " + PUZZLE)
                  and isinstance(v, (bytes, bytearray)) and v != members[PUZZLE]]
    def qid(q):
        return q.get("qid") or q.get("id")

    def other_format(q):
        fmt = q.get("answer_format")
        return bool(fmt) and "ANS-" not in json.dumps(fmt, default=str)

    def names_fact(q):
        # an id that names a fact of the package (`package_name`, `cert_sha256`) does not ask for the
        # code, unless the question's own format says ANS-
        if q.get("answer_format") and "ANS-" in json.dumps(q["answer_format"], default=str):
            return False
        try:
            return apk_facts.match(qid(q) or "") is not None
        except Exception:
            return False

    def code_format(q):
        fmt = q.get("answer_format")
        return bool(fmt) and _format_takes_code(fmt)

    # Day 14 look-ahead (review of 2026-10-13): a question under another id whose format is the code's is
    # the code's only when it is the ONE such question of its set. Two questions that both want an ANS-
    # code want two different codes, and this module reads one: then only `answer` is given it, and the
    # others are None (they are not handed to apk_facts.py either: a case id is no answer code).
    coded = [q for q in questions if code_format(q)]
    routes = {id(q): answer_route(q) for q in questions if qid(q) == "answer"}
    mine = [q for q in questions if routes.get(id(q)) == CODE or (qid(q) != "answer" and len(coded) == 1 and q is coded[0])
            or (qid(q) != "answer" and len(questions) == 1 and not other_format(q) and not names_fact(q))]
    unread = [q for q in coded if q not in mine]

    def early(first, key):
        # this module's own reading, into the runner's partial answers before anything else is looked at
        if isinstance(ctx.get("partial"), dict):
            ctx["partial"].update({qid(q): v for q in mine for v in [_as_asked(q, first, key)] if v is not None})

    attempt = ctx.get("attempt") if isinstance(ctx.get("attempt"), dict) else {}
    STATED_TEXTS[:] = [mine[0].get("question") if mine else None,
                       attempt.get("prompt") or (mine[0].get("prompt") if mine else None)]
    split = None
    if (split_bundle is not None and isinstance(blob, (bytes, bytearray)) and blob
            and (PUZZLE in inner or PUZZLE not in members) and split_bundle.candidate(blob)):
        # Day 26 fold: the delivery's document is not its own member and its own names hold two or more
        # *.apk splits (or .aab module folders; split_bundle.candidate reads the central directory only, so an
        # inner APK past read_members' bound counts too). A split bundle's base and feature splits are read
        # as splits (split_bundle.py); None for anything else, which goes on as before.
        try:
            split = split_bundle.solve(blob, look=split_look)
        except Exception as e:
            split = None
            print("NOTE mobile split_bundle raised %s: %s" % (type(e).__name__, str(e)[:200]), file=sys.stderr)
    dex_fast = False
    chain_unread = None    # KB-2 fix round 1: (codes, declines) of an `analysis` document whose chain gave no one code
    chain_files = dict(files, **members)   # the one mapping the dex chain reads below (dex_chain_codec.answer)
    chain_run = None       # Day 30 fold: the gate's run of the chain, handed to answer() in place of a second run
    chain_codes = None     # B-229: the codes the chain computed (solve_delivery's fail-closed rule)
    if members and dex_chain_codec is not None and split is None:
        # Day 24: an `analysis` document has no data to decode, so the generic search below would only spend its
        # whole budget; when the dex chain runs to a code, that reading (below) is the answer and this skips it.
        try:
            analysis = dex_chain_codec.is_analysis(members, ctx)
        except Exception:
            analysis = False
        if analysis:
            try:
                # Day 30 fold (speed): the chain is run over the very mapping answer() reads, once; answer() takes this
                # run (dex_chain_codec.AnalysisRun) instead of running the chain a second time over the same bytes.
                chain_run = dex_chain_codec.AnalysisRun(chain_files)
                _c, _d = chain_run.codes, chain_run.declines
                dex_fast = bool(_c) and not _d   # a decline: keep the generic search too (the answer is then unsure)
            except Exception:
                chain_run = None
                _c, _d = [], 1
            chain_codes = list(_c)
            if not dex_fast:
                chain_unread = (len(_c), _d)
    if split is not None:
        # the bundle's own reading, or WITHHELD (answer None: a part or chain of the bundle did not hold, and the
        # base split alone is not read in its place)
        STATED_TEXTS[:] = []
        answer = split.answer
        LAST.clear()
        LAST.update(answer=answer if not labels.is_unsure(answer) else "unsure",
                    confidence="high" if answer is not None else "none", route=split.route, saw=[])
        if split.key:
            LAST["key"] = split.key
        LAST.update(split.note)
        if answer is not None:
            try:
                early(answer, split.key)   # into the runner's partial answers, as _solve's own reading is
            except Exception:
                pass
    elif members and not dex_fast:
        # KB-2 fix round 1 (review of e281f95): an `analysis` document whose own dex chain was not read to exactly one
        # code (a native the bridge declines, an opcode, a budget) is no document the generic search reads: the one
        # code in clear it finds may be a decoy beside the chain's real code, so its reading is never plain here (it
        # was plain under the judged apk-string:dex). The runner's partial answers get the same demoted reading.
        def unread_hook(first, key):
            # B-229 fix round 2: the demoted reading reaches the runner's partial answers only when the chain computed
            # every value it offers (a package-look decoy is withdrawn below, so it is never a timed-out set's answer)
            first, key = _analysis_unread(first, key)
            if not _chain_stray(first, chain_codes):
                early(first, key)

        hook = early if chain_unread is None else unread_hook
        try:
            answer = _solve(members, inner, clock, blob if isinstance(blob, (bytes, bytearray)) else b"", twins, dups,
                            hook)
        finally:
            STATED_TEXTS[:] = []
        if chain_unread is not None and answer is not None:
            answer, ukey = _analysis_unread(answer, LAST.get("key"))
            LAST["key"] = ukey
            LAST["answer"] = answer if not labels.is_unsure(answer) else "unsure"
            LAST["analysis_unread"] = "codes=%d declines=%d" % chain_unread
            print("NOTE mobile set %s: the document's codec is analysis and its dex chain gave %d code(s) with %d "
                  "decline(s): the generic search's reading is offered unsure under %s (KB-2 fix round 1)"
                  % (ctx.get("set"), chain_unread[0], chain_unread[1], ukey), file=sys.stderr)
    else:
        answer = None
        LAST.clear()
        LAST.update(answer=None, confidence="none",
                    route="analysis dex chain (dex_chain_codec.py)" if dex_fast else "the set has no delivery to read",
                    saw=[])
    out = {qid(q): (_as_asked(q, answer, LAST.get("key")) if q in mine else None) for q in questions}
    note = dict(LAST)
    if chain_codes is not None:
        note["chain_codes"] = chain_codes
    others = [q for q in questions if q not in mine and q not in unread and routes.get(id(q)) != NOTHING]
    if others and members:
        # A question that does not ask for the code asks something about the package itself (its
        # manifest, its strings, its signature). apk_facts.py reads those and answers only what the
        # question names, unsure unless it is a hash, a size or a count (never-guess).
        try:
            # The package is the delivery itself when its manifest (or Info.plist) is a direct member:
            # only then are the delivery's own hash and size the package's. A package found inside
            # another archive is still read, without them.
            direct = {k: v for k, v in members.items() if k not in inner}
            own = bool(apk_facts.read(direct)) and isinstance(blob, (bytes, bytearray))
            facts = apk_facts.solve_questions(others, direct if own else members, bytes(blob) if own else b"")
        except Exception as e:
            facts = {}
            note["facts_error"] = "%s: %s" % (type(e).__name__, str(e)[:120])
        for q in others:
            if facts.get(qid(q)) is not None:
                out[qid(q)] = facts[qid(q)]
        note["facts"] = sorted(k for k, v in facts.items() if v is not None)
    for q in questions:
        # The id `answer` whose question names no fact of the package is the code's, as it always was.
        if routes.get(id(q)) == FACTS_THEN_CODE and out[qid(q)] is None:
            # Day 14 look-ahead: nothing in the question says the code and nothing in it names a fact
            # this module reads. The code is the likeliest answer and not a proven one: offered, unsure.
            # A question that states no format at all (a hand-made one) is given the code as before.
            out[qid(q)] = _as_asked(q, answer, note.get("key"), unasked=True) if q.get("answer_format") else answer
            mine.append(q)
    if len(mine) != len(questions):
        note["unanswered"] = [qid(q) for q in questions if q not in mine and out.get(qid(q)) is None]
    for q in questions:
        # The live fix is heard where this module has no plain answer: a judged answer is
        # never offered to it, and when it declines, an unsure answer stays as it is.
        if (out[qid(q)] is None or labels.is_unsure(out[qid(q)])) and dex_chain_codec is not None and split is None:
            # Day 23 fold-in: codec `analysis` computes its ANS code in the app's own dex chain. The reader is
            # fail-closed (None unless the document says `analysis` and a dex method assembling "ANS-" runs to
            # a valid code); pick/candidates only, plain once the judge has accepted mobile.codec/analysis.
            try:
                dcc_ans = dex_chain_codec.answer(q, chain_files, ctx, run=chain_run if dex_fast else None)
                if dcc_ans is None and q in mine and (out[qid(q)] is None or _beside(out[qid(q)])):
                    # look-ahead: a renamed codec with no payload; unsure-only under mobile.codec/dex-chain. Day 27
                    # so-ambig fix round 1: also beside a package-look code under such a document (_beside_analysis),
                    # as answer() stands in for one beside an `analysis` document. Fix round 2 (the review's minor
                    # finding): beside it the chain is read whatever the payload fields hold (rule 3 found that they
                    # prove nothing), and the package look's code is still offered, after the chain's (_beside_merge)
                    beside = _beside(out[qid(q)])
                    dcc_ans = dex_chain_codec.answer_any(q, chain_files, ctx, beside=beside)
                    if beside and dcc_ans is not None:
                        dcc_ans = _beside_merge(out[qid(q)], dcc_ans)
            except Exception as e:
                dcc_ans = None
                print("NOTE mobile dex_chain_codec raised %s: %s" % (type(e).__name__, str(e)[:200]), file=sys.stderr)
            if dcc_ans is not None:
                out[qid(q)] = dcc_ans
                note.setdefault("dex_chain", []).append(qid(q))
                note["answer"] = "unsure" if labels.is_unsure(dcc_ans) else dcc_ans
                note["confidence"] = "medium" if labels.is_unsure(dcc_ans) else "high"
                note["route"] = "analysis dex chain (dex_chain_codec.py)"
                parsed_dcc = labels.parse(dcc_ans) if labels.is_unsure(dcc_ans) else None
                if parsed_dcc is not None:
                    note["key"] = parsed_dcc.key
        if chain_codes is not None and q in mine:
            # B-229 fail closed (fix round 2: here, so the set path the timed runner drives holds it too, not only
            # solve_delivery): an `analysis` document's code is what its dex chain computes. An unsure answer that
            # offers a value no chain method computed (the package look beside a declined chain, under
            # `:beside-analysis` / `:analysis-unread`) is withdrawn, never a candidate. Before the live fix below, so a
            # day_patch.py answer is heard and never withdrawn.
            stray = _chain_stray(out[qid(q)], chain_codes)
            if stray:
                print("NOTE mobile set %s: the dex chain computed %s; the unsure answer to %s also offered %s, which no "
                      "chain method computed: withdrawn (B-229 fail closed)"
                      % (ctx.get("set"), sorted(chain_codes) or "no code", qid(q), stray), file=sys.stderr)
                out[qid(q)] = None          # (the partial answers never held it: unread_hook above)
                note.setdefault("withdrawn", []).append(qid(q))
                note.update(answer=None, confidence="none", route=FAIL_CLOSED_ROUTE)
                note.pop("candidate", None)
                note.pop("key", None)
        if out[qid(q)] is None or labels.is_unsure(out[qid(q)]):
            fixed = _patched(q, files, ctx)
            if fixed is not None:
                out[qid(q)] = fixed
                note.setdefault("day_patch", []).append(qid(q))
        # The one way a live fix reaches a plain answer: the patch's own override(), when it has one.
        after = _overridden(q, out[qid(q)], files, ctx)
        if after != out[qid(q)]:
            out[qid(q)] = after
            note.setdefault("day_patch_override", []).append(qid(q))
    LAST_SET.clear()
    LAST_SET.update(note)
    print("NOTE mobile set %s: %s" % (ctx.get("set"), json.dumps(note, default=str)[:900]), file=sys.stderr)
    if note.get("other_codes") and note.get("second_look"):
        print("NOTE mobile set %s: SECOND CODE in the package. This solver reads %s (%s); the package also holds: %s. "
              "The look was %s, so the answer is this solver's own reading, as it would be without the look."
              % (ctx.get("set"), note.get("candidate") or note.get("answer"), str(note.get("route"))[:80],
                 "; ".join(note["other_codes"])[:400], note["second_look"]), file=sys.stderr)
    elif note.get("other_codes"):
        print("NOTE mobile set %s: SECOND CODE in the package. This solver reads %s (%s); the package also holds: %s. "
              "Nothing proves which is asked: the answer offers them in %s under %s (plain only for a "
              "name the judge has accepted there)."
              % (ctx.get("set"), note.get("candidate") or note.get("answer"), str(note.get("route"))[:80],
                 "; ".join(note["other_codes"])[:400],
                 "that order, %s first: the field the document's own selector names" % ", ".join(note["ahead"])
                 if note.get("ahead") else "that order", note.get("key")), file=sys.stderr)
    elif note.get("demoted_truncated"):
        print("NOTE mobile set %s: SECOND CODE scan TRUNCATED (%s). This solver reads %s (%s), but a real code could "
              "lie beyond the bound, so the reading is demoted to an unsure pick under %s and NOT banked plain "
              "(fail-closed, never-guess); it is probed on the base, and withdrawn/replaced by day_patch.py override() "
              "if the base is rejected."
              % (ctx.get("set"), note["demoted_truncated"], note.get("candidate") or note.get("answer"),
                 str(note.get("route"))[:80], note.get("key")), file=sys.stderr)
    if isinstance(ctx.get("partial"), dict):
        ctx["partial"].update({k: v for k, v in out.items() if v is not None})
    return out


def main(argv) -> int:
    if not argv or any(a.startswith("-") for a in argv):
        print("usage: codec_search.py <file.apk> [...]", file=sys.stderr)
        return 2
    status = 0
    for path in argv:
        try:
            blob = Path(path).read_bytes()
        except OSError as e:
            print("codec_search.py: %s: %s" % (path, e.strerror or e), file=sys.stderr)
            status = 2
            continue
        answer = solve_delivery(blob, Path(path).name)   # B-229: `analysis` and split deliveries too
        shown = answer
        if labels.is_unsure(answer):
            shown = "unsure %s (key %s)" % (LAST.get("candidate"), LAST.get("key"))
        print("%s: %s  [%s] %s" % (path, shown, LAST.get("confidence"), LAST.get("route")))
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
