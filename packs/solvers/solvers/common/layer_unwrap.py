"""Engine: layered-polyglot auto-unwrapper, an identify-then-dispatch loop over decoders that already exist (B-133).

    python -m ctf run common.layer_unwrap <challenge_dir> [--opt file=REL] [--opt out=REL] [--opt write=0]
        [--opt key=HEX[,HEX]] [--opt nonce=HEX] [--opt aad=TEXT] [--opt password=TEXT --opt salt=HEX
        --opt iterations=N] [--opt first=N] [--opt budget=SECONDS] [--opt steps=N] [--opt max_layers=N]
        [--opt max_files=N] [--event SLUG]

A "journey" challenge wraps its flag in layers: an encoding, a compressed stream, a length-prefixed
blob, an AES-GCM blob whose key the layer before printed, an esolang program that prints the next
layer, a program in a real language that decodes the next. This engine adds no decoder. For each
layer it asks a signature table what the bytes are, hands them to the decoder the tree already has,
and looks at the result again. The table, in the order it is asked:

    signature                              decoder it dispatches to
    flag in the event format               (the goal: stop, solved)
    AES-GCM nonce/ciphertext/tag layout    cryptography's AESGCM, with a key an earlier layer stated
                                           (or --opt key=...); only a verifying tag is a decode
    u32 / u64 length prefix                the prefix is dropped when it states exactly what follows
    zip / 7z / rar / tar with one member   tools/archive_expand.py (B-013); more members: handed on
    a known file format                    ctf.formats (identify, the magic table): handed to its lane;
                                           an image is first tried as a Piet program (B-055)
    a program in a real language           never run: the loop stops and returns unsure
    then, together, the best reading wins:
    gzip / zlib / bz2 / xz / zstd / ...    solvers/common/unwrap.py, solvers/warmups/encdepth_layered.py
    an esolang program                     the bounded interpreters in solvers/warmups/esolang*.py,
                                           solvers/common/classical.py and B-055's chicken
    an encoded text blob                   unwrap.py and encdepth_layered.py (the base families, ...)
    a blob inside a text                   solvers/toolkits/embedded_decode.py (B-013)

A layer is ACCEPTED only when something proves it: its own checksum (gzip CRC-32, a zlib / bz2 / xz
stream check, a zip member's stored CRC-32, recomputed here over the bytes the extractor gave: a 7z,
rar or tar member carries no proof of its own), a verifying AES-GCM tag, a digest or CRC an earlier layer stated,
a complete file structure read out of the result (solvers/common/verified_transform.py), or a flag
at the end of the chain. A proof at layer N also accepts every layer before it (wrong bytes do not
checksum). A decode nothing has proved yet is kept as an UNVERIFIED lead and the loop goes on; when
the loop stops without a flag it writes a stop record naming the layer it could not read
(`unknown-layer`), the program it must not run (`program-layer`) or the format another lane owns
(`known-format`), the layers accepted so far and the unverified ones, so a model starts at layer N
with the bytes of every layer in a file, and runs the engine again on what it decodes.

The stop record (<challenge_dir>/recon/layer_unwrap/<input>/unwrap.json, beside NN-<decoder>.bin,
the bytes each layer gave; the recon/<engine>/ convention of the other engines, which do not read
recon/ as handout) is one JSON object. <input> is the input's name when it is a plain name at the top
of the handout; any other path is its flattened form, '@' and 12 hex digits of its SHA-256, so two
inputs never share a folder. --opt out= must be a folder inside the challenge folder and not the
handout folder itself (nor one holding it). A layer folder that cannot be written (a file in its
place, no room) is said in the notes and the run goes on: a flag it reached is still returned.

    schema, engine, input, flags
    layers  [{n, kind, name, proof, verified, bytes_in, bytes_out, sha256, file}]
    stop    {reason, layer, bytes, file, accepted_through, unverified, refused, notes, next,
             identified?, candidates?, facts?, members?}

`stop.reason` is flag, program-layer, known-format, unknown-layer, budget, max-layers, cycle or
too-large. `stop.layer` is the layer the loop stopped at and `stop.file` the file holding its bytes;
`accepted_through` is the last proved layer and `unverified` the layers after it; `refused` lists
signatures that fired and whose decoder gave nothing; `next` says what to do. It holds sizes, names
and hashes, never a layer's content. A name taken from the challenge (a shebang's interpreter) is
named only when it is on a known list: anything else is `shebang`, so no challenge text reaches it.
An archive member's name is repeated (in `members`, a proof or a note) cut to NAME_SHOWN characters,
unprintable characters as '?', then its full length.

Which files are read: the handout (<challenge_dir>/files/, else the challenge folder), at most
--opt max_files= (default MAX_FILES) of them, each at most MAX_LAYER bytes. At the challenge root
recon/ and unpacked/ are engine output, not handout, and are not walked (nor is the out= folder);
hidden entries (.ctf, .git) and symbolic links are never read. Every file left out for the count,
its size, as a link or as hidden is named in the result's notes and evidence (`skipped`), and a run
that left a handout file unread for the count or its size never reports `none`.

Result: `solved` for one distinct flag at the end of a chain; `candidate` for several; `unsure`
when the loop stopped at a layer with a stop record, or a file was left unread; `none` when every
file was read and none has a layer this engine reads; `blocked` when the event has no flag format,
an option is bad or a needed package is missing. Nothing here executes a challenge file: esolang
programs are data walked by capped interpreters, real-language programs are only named. It never
submits and makes no network request.

Single-threaded only: while an interpreter runs, _reader_budget sets the time backstops of the
carried esolang modules (module globals) to this loop's budget. One process per engine (ctf run)
is safe; a threaded caller that runs another esolang engine in the same process at the same time
would see this loop's budget for the length of the call. Two threads of this engine take turns at
that patch (a lock), so neither restores the other's budget as the module's own.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import math
import os
import re
import sys
import threading
import time
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

ENGINE = "common.layer_unwrap"
SCHEMA = 1
MAX_LAYER = 256 << 20         # bytes of one layer; a larger one stops the loop (`too-large`). The first
                              # layer of a journey holds every later one: the PINK 5 handout was 75 MB
EL_MAX = 16 << 20             # the most encdepth_layered.peel takes (its own ceiling); unwrap.py has MAX_IN
MAX_ESOLANG = 8 << 20         # bytes above which no esolang signature is asked (the interpreters' own caps
                              # are 128 KiB to 512 KiB; only the Brainfuck family is read above those)
PROBE = 256 << 10             # a program's structure is looked for in this much of its head and of its tail
MAX_FILES = 16                # handout files one run reads (--opt max_files=); the rest are named, not read
MAX_LAYERS = 32               # layers followed in one file
HARVEST = 1 << 20             # characters of a text layer read for stated fields (key=, nonce=, sha256=, ...)
DEFAULT_BUDGET = 60.0         # seconds one file may take
DEFAULT_STEPS = 20_000_000    # interpreter steps one esolang program may take
BF_OUTPUT = 4 << 20           # bytes a Brainfuck layer may print (a printed next layer can be large)
MAX_AEAD_TRIES = 512          # key x layout x aad combinations tried on one layer
MAX_PBKDF2 = 2_000_000        # iterations a stated PBKDF2 derivation may ask for
MIN_ESOLANG = 8               # bytes below which no esolang signature is asked
ROOT_SKIP = {"recon", "unpacked"}     # engine and intake output at the challenge root (not handout); nowhere else
OUT_DIR = Path("recon") / "layer_unwrap"     # default out=: the recon/<engine>/ convention
RECORD = "unwrap.json"
HERE = Path(__file__).resolve().parent
# What a reader raises when it refuses hostile text ("not this one"). Anything else from a reader is
# a fault in the reader, and is said in the notes with its type.
_REFUSALS = (ValueError, LookupError, ArithmeticError, RecursionError, MemoryError, EOFError)


class UnwrapError(RuntimeError):
    """The unwrapper cannot run as asked: the message names the missing module, package or option."""


# ------------------------------------------------------------------ the decoders this loop dispatches to

def _engine_path() -> None:
    for d in (HERE, HERE.parent / "warmups", HERE.parent / "toolkits", HERE.parents[1] / "tools"):
        if d.is_dir() and str(d) not in sys.path:
            sys.path.append(str(d))
    root = str(HERE.parents[1])
    if root not in sys.path:
        sys.path.append(root)


class _Mods:
    """The carried modules, imported once and by name. A missing one is an UnwrapError that names it:
    the loop never runs with a decoder family quietly absent."""

    NAMES = {"UW": "unwrap", "VT": "verified_transform", "EL": "encdepth_layered", "ED": "embedded_decode",
             "ESL": "esolang", "ESO": "esolangs", "ESL2": "esolang2", "ESL3": "esolang3", "ESL4": "esolang4",
             "ESM": "esolang_more", "CH": "chicken", "PIET": "piet", "AE": "archive_expand"}

    def __init__(self):
        import importlib
        _engine_path()
        for attr, name in self.NAMES.items():
            try:
                setattr(self, attr, importlib.import_module(name))
            except ImportError as e:
                raise UnwrapError(f"decoder module {name!r} cannot be imported ({e})") from None
        try:
            from _shadowed import common_module
            self.K = common_module("classical")           # solvers/common/classical.py, not the toolkit face
            from ctf import formats as F
            from ctf.formats import fingerprint as FP
            self.F, self.FP = F, FP
        except ImportError as e:
            raise UnwrapError(f"decoder module cannot be imported ({e})") from None
        self.magic = FP.load_magic()                      # MagicError names a broken table: never quietly empty

    # Modules with the _which / steps interface. esolang_more before esolang2: both read Chef and
    # Shakespeare, and esolang_more's are the fuller readers (docs/build-log/B-055.md).
    PACKS = ("ESL", "ESM", "ESL2", "ESL3", "ESL4")


_MODS = None


def _mods() -> _Mods:
    global _MODS
    if _MODS is None:
        _MODS = _Mods()
    return _MODS


# ------------------------------------------------------------------ records

@dataclass(frozen=True)
class Sig:
    """One hit of the signature table on a layer's bytes."""
    kind: str        # flag | compressed | aead | frame | archive | format | program | esolang | encoding | text | binary
    name: str        # gzip, aes-gcm, u32be-length, zip, go, brainfuck, base64, ...
    why: str


@dataclass
class Step:
    """One decoder's reading of a layer."""
    kind: str
    name: str
    out: bytes
    proof: str | None = None
    rank: int = 0
    order: tuple = ()


@dataclass
class Layer:
    n: int                   # 1-based position in the chain (offset by `first` on a resumed run)
    kind: str
    name: str
    proof: str | None        # what proved this layer, or None
    verified: bool           # proved here, or by a later layer or the flag
    bytes_in: int
    bytes_out: int
    out: bytes = field(repr=False, default=b"")

    def to_dict(self) -> dict:
        return {"n": self.n, "kind": self.kind, "name": self.name, "proof": self.proof,
                "verified": self.verified, "bytes_in": self.bytes_in, "bytes_out": self.bytes_out,
                "sha256": hashlib.sha256(self.out).hexdigest()}


@dataclass
class Carry:
    """Key material and stated checks read from the text of earlier layers (or given as options)."""
    keys: list = field(default_factory=list)          # (bytes, where it came from)
    nonces: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    aads: list = field(default_factory=list)
    passwords: list = field(default_factory=list)
    salts: list = field(default_factory=list)
    iterations: list = field(default_factory=list)
    digests: list = field(default_factory=list)       # (hex digest, where)
    crcs: list = field(default_factory=list)          # (int, where)
    _derived: dict = field(default_factory=dict)

    def _add(self, bucket: list, value, where: str) -> None:
        if value not in (None, b"", "") and all(v != value for v, _ in bucket):
            bucket.append((value, where))

    def all_keys(self) -> list:
        """The stated keys, then the PBKDF2-HMAC-SHA256 keys of every stated password, salt and
        iteration count (all three must be stated; nothing is guessed)."""
        out = list(self.keys)
        for pw, w1 in self.passwords:
            for salt, _ in self.salts:
                for iters, _ in self.iterations:
                    for size in (32, 16):
                        k = (pw, salt, iters, size)
                        if k not in self._derived:
                            self._derived[k] = hashlib.pbkdf2_hmac("sha256", pw, salt, iters, size)
                        out.append((self._derived[k], f"PBKDF2-HMAC-SHA256 of the password from {w1}"))
        return out


@dataclass
class Unwrap:
    layers: list
    flags: tuple
    stop: dict
    final: bytes = field(repr=False, default=b"")

    @property
    def accepted_through(self) -> int:
        """How many layers, from the first, are verified."""
        k = 0
        for layer in self.layers:
            if not layer.verified:
                break
            k += 1
        return k

    def to_dict(self) -> dict:
        return {"schema": SCHEMA, "engine": ENGINE, "flags": list(self.flags),
                "layers": [x.to_dict() for x in self.layers], "stop": self.stop}


class _Ctx:
    def __init__(self, ff, carry, deadline, clock, steps, name):
        self.ff, self.carry, self.deadline, self.clock, self.steps, self.name = ff, carry, deadline, clock, steps, name
        self.m = _mods()
        self.refused: list = []       # Sig: a signature fired and its decoder gave nothing
        self.notes: list = []

    def left(self) -> float:
        return max(0.0, self.deadline - self.clock())

    def reader_deadline(self) -> float:
        """The loop's deadline as the time.perf_counter() value the interpreters compare against."""
        return time.perf_counter() + self.left()


# ------------------------------------------------------------------ the signature table

_TEXT_SAMPLE = 1 << 16


def _text(b: bytes):
    """The bytes as text when they are UTF-8 and read as text (95% printable; a long layer is judged
    on its first and last 64 KiB of characters), else None."""
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not t:
        return None
    sample = t if len(t) <= 2 * _TEXT_SAMPLE else t[:_TEXT_SAMPLE] + t[-_TEXT_SAMPLE:]
    good = sum(1 for c in sample if c.isprintable() or c in "\r\n\t")
    return t if good >= 0.95 * len(sample) else None


_COMPRESSED = (("gzip", b"\x1f\x8b\x08"), ("bz2", b"BZh"), ("xz", b"\xfd7zXZ\x00"),
               ("zstd", b"\x28\xb5\x2f\xfd"), ("lz4", b"\x04\x22\x4d\x18"))


def _sig_compressed(b: bytes) -> list:
    out = [Sig("compressed", name, f"starts with the {name} magic {magic.hex()}")
           for name, magic in _COMPRESSED if b.startswith(magic)]
    if len(b) >= 2 and b[0] & 15 == 8 and b[0] >> 4 <= 7 and int.from_bytes(b[:2], "big") % 31 == 0:
        out.append(Sig("compressed", "zlib", f"a zlib header ({b[:2].hex()}: deflate, check bits hold)"))
    return out


FRAMES = (("u32be-length", 4, "big"), ("u32le-length", 4, "little"),
          ("u64be-length", 8, "big"), ("u64le-length", 8, "little"))


def _sig_frame(b: bytes) -> list:
    return [Sig("frame", name, f"the first {size} bytes state {len(b) - size}, exactly the bytes that follow")
            for name, size, order in FRAMES
            if len(b) > size and int.from_bytes(b[:size], order) == len(b) - size]


_ARCHIVES = ((b"PK\x03\x04", "zip"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"))
_MAGIC_LABELS = {b"\x7fELF": "elf", b"\x89PNG\r\n\x1a\n": "png", b"%PDF-": "pdf", b"dex\n": "dex",
                 b"\xca\xfe\xba\xbe": "java-class", b"SQLite format 3\x00": "sqlite", b"HCFG": "hcfg",
                 b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "ole", b"PK\x05\x06": "zip", b"PK\x07\x08": "zip",
                 b"GIF87a": "gif", b"GIF89a": "gif", b"\xff\xd8\xff": "jpeg"}
_IMAGES = ("png", "gif", "bmp")


def _archive_kind(b: bytes):
    for magic, name in _ARCHIVES:
        if b.startswith(magic):
            return name
    return "tar" if b[257:262] == b"ustar" else None


def _sig_format(b: bytes, m) -> list:
    """A file format another lane owns: an archive, a catalog format (ctf.formats.identify), one of
    unwrap.py's strong container magics, or (binary layers only: several of its signatures are
    letters) an entry of the local magic table (ctf/formats/magic.toml)."""
    arch = _archive_kind(b)
    if arch:
        return [Sig("archive", arch, f"a {arch} archive by its magic")]
    try:
        sure = [x for x in m.F.identify("layer", b) if x.sure]       # by structure only: a layer has no name
    except (m.F.FormatLimit, m.F.DetectorError) as e:     # said, never a quiet "no match"
        return [Sig("format", "unreadable", f"ctf.formats could not read it: {type(e).__name__}: {e}")]
    if sure:
        return [Sig("format", sure[0].format, f"ctf.formats.identify: {sure[0].why}")]
    for magic in m.UW.STRONG_MAGICS + (b"GIF87a", b"GIF89a", b"\xff\xd8\xff"):
        if b.startswith(magic):
            return [Sig("format", _MAGIC_LABELS.get(magic, "magic-" + magic.hex()),
                        f"starts with the container magic {magic.hex()}")]
    if b[:2] == b"BM" and len(b) >= 14 and int.from_bytes(b[2:6], "little") == len(b):
        return [Sig("format", "bmp", "a BMP header whose size field is the file's size")]
    if b[:2] == b"MZ" and len(b) >= 0x40:
        at = int.from_bytes(b[0x3c:0x40], "little")
        if b[at:at + 4] == b"PE\x00\x00":
            return [Sig("format", "pe", "an MZ header that points at a PE signature")]
    if _text(b) is None:
        for x in m.magic:
            if len(x.sig) >= 3 and b[x.at:x.at + len(x.sig)] == x.sig and not any(
                    b.startswith(mg) for _, mg in _COMPRESSED):
                return [Sig("format", x.id, f"magic table: {x.label} ({x.sig.hex()} at offset {x.at})")]
    return []


# A program in a real language: every pattern of a row must match. These name the layer; nothing runs it.
_PROGRAMS = (
    ("go", (rb"(?m)^package\s+\w+", rb"\bfunc\s+\w+\s*\(")),
    ("rust", (rb"\bfn\s+main\s*\(\s*\)", rb"\blet\s+(?:mut\s+)?\w+|\bconst\s+\w+\s*:")),
    ("c", (rb"(?m)^\s*#\s*include\s*[<\"]", rb"\b(?:int|void)\s+main\s*\(")),
    ("java", (rb"\bclass\s+\w+", rb"\bstatic\s+void\s+main\s*\(")),
    ("haskell", (rb"(?m)^main\s*(?:::|=)", rb"(?m)^(?:import\s+(?:qualified\s+)?[A-Z][\w.]*|module\s+[A-Z])")),
    ("php", (rb"<\?php\b",)),
    ("ruby", (rb"(?m)^\s*(?:require\s+['\"]|puts\s|def\s+\w+)", rb"(?m)^\s*end\s*$|<<~?[A-Z_]+")),
    ("python", (rb"(?m)^(?:import\s+\w+|from\s+[\w.]+\s+import\s)", rb"(?m)^\s*(?:def\s+\w+\s*\(|print\s*\(|\w+\s*=\s)")),
    ("javascript", (rb"\b(?:const|let|var)\s+\w+\s*=", rb"\bfunction\b|=>|\bconsole\.log\s*\(|\brequire\s*\(")),
    ("perl", (rb"(?m)^use\s+strict\b|^my\s+\$\w+", rb"\bprint\b|\bsub\s+\w+")),
    ("powershell", (rb"(?i)\$\w+\s*=", rb"(?i)\b(?:Write-(?:Host|Output)|\[System\.|New-Object|param\s*\()")),
    ("emojicode", ("\U0001F3C1\\s*\U0001F347".encode(),)),            # chequered flag, grapes: the entry block
)
_SHEBANG = re.compile(rb"\A#!\s*(?:/usr/bin/env\s+)?(?:\S*/)?([A-Za-z][\w.+-]*)")
# The interpreter a shebang names is challenge text: it is repeated only when it is one of these
# (a trailing version is dropped: python3.11 is python). Any other name is `shebang`.
_INTERPRETERS = frozenset((
    "awk", "bash", "bun", "crystal", "dart", "dash", "deno", "elixir", "escript", "fish", "gawk", "groovy",
    "guile", "jshell", "julia", "ksh", "lua", "luajit", "mawk", "nim", "node", "nodejs", "ocaml", "osascript",
    "perl", "php", "powershell", "pwsh", "python", "pypy", "racket", "raku", "rscript", "ruby", "runghc",
    "runhaskell", "scala", "sbcl", "sed", "sh", "swift", "tclsh", "ts-node", "tsx", "wish", "zsh"))
# Program layers the tree already reads statically, without running them: named in stop.next.
_STATIC_READERS = {
    lang: "solvers/binary/deobfuscation.py (deobfuscate_source, peel_constant_layers) recovers its constant "
          "strings and literal encodings statically; "
    for lang in ("javascript", "php", "powershell", "node", "nodejs", "deno", "bun", "pwsh")}


def _interpreter(raw: bytes) -> str:
    base = re.sub(r"[\d.]+$", "", raw.decode("ascii", "replace")).lower()
    return base if base in _INTERPRETERS else "shebang"
_CRYPTO_WORDS = ("aes", "gcm", "cbc", "pbkdf2", "hmac", "sha256", "sha1", "md5", "zlib", "gzip", "base64",
                 "xor", "chacha", "rc4", "argon2", "scrypt")
_LITERAL = re.compile(r"[\"'][0-9A-Za-z+/=]{24,}[\"']")


def _sig_program(b: bytes) -> list:
    if _text(b) is None:
        return []
    sb = _SHEBANG.match(b)
    if sb:
        name = _interpreter(sb.group(1))
        return [Sig("program", name, "a shebang line names its interpreter" if name != "shebang" else
                    f"a shebang line names an interpreter not on the known list ({len(sb.group(1))} "
                    f"characters of challenge text, not repeated here)")]
    # The next layer sits in the middle of the source as one long literal; the structure is at the ends.
    probe = b if len(b) <= 2 * PROBE else b[:PROBE] + b"\n" + b[-PROBE:]
    for lang, patterns in _PROGRAMS:
        if all(re.search(p, probe) for p in patterns):
            return [Sig("program", lang, f"{lang} source by its structure ({len(patterns)} patterns)")]
    return []


def _program_facts(b: bytes) -> dict:
    """What a model needs to start on a program layer, read without running it: the transforms it
    names and the literals that hold the next layer. Counts and sizes only, never the content."""
    text = b.decode("utf-8", "replace")
    low = _LITERAL.sub('""', text).lower()        # the code without its blobs: hex spells "cbc" by chance
    hexes = re.findall(r"[\"']([0-9a-fA-F]{32,})[\"']", text)
    b64s = [s for s in re.findall(r"[\"']([A-Za-z0-9+/]{24,}={0,2})[\"']", text) if s not in hexes]
    return {"lines": text.count("\n") + (not text.endswith("\n")), "bytes": len(b),
            "names": sorted(w for w in _CRYPTO_WORDS if w in low),
            "hex_literals": {"count": len(hexes), "chars": sum(map(len, hexes))},
            "base64_literals": {"count": len(b64s), "chars": sum(map(len, b64s))},
            "file_names": sorted(set(re.findall(r"[\"']([\w-]{1,40}\.[A-Za-z][A-Za-z0-9]{1,11})[\"']", text)))[:8]}


_COW_WORD = r"(?:moo|mOo|moO|mOO|Moo|MOo|MoO|MOO|OOO|MMM|OOM|oom)"
_ESOLANG_SIGS = (                                   # name, the test on (bytes, text or None)
    ("brainfuck", lambda b, t: _bf_like(b)),
    ("ook", lambda b, t: t is not None and (len(re.findall(r"(?i)\book[.?!]", t)) >= 8
                                             or (len(t) >= 16 and not re.sub(r"[.?!\s]", "", t)))),
    ("cow", lambda b, t: t is not None and re.fullmatch(rf"(?:\s*{_COW_WORD})+\s*", t) is not None),
    ("whitespace", lambda b, t: len(b) >= 16 and not b.strip(b" \t\n") and b" " in b and b"\t" in b and b"\n" in b),
    ("jsfuck", lambda b, t: len(b) >= 12 and re.fullmatch(rb"[\[\]()!+\s]+", b) is not None and b"[" in b),
    ("deadfish", lambda b, t: re.fullmatch(rb"[idso\s]+", b) is not None and b"o" in b),
    ("chicken", lambda b, t: t is not None and len(t.split()) >= 8 and set(t.split()) == {"chicken"}),
)
_READERS = ("cow", "whitespace", "befunge", "malbolge", "jsfuck", "deadfish")   # esolangs.READERS, by signature
_OWN_STEPS = ("befunge", "jsfuck")      # readers kept on their own step cap: their signatures are the loosest
# Three gates of esolang_more.py pass English prose (the words "print" and "is"; "ingredients" and
# "method"; an @ among symbols). Here a signature also names the layer in the stop record, so each of
# those three must hold a line or a character set only a program has.
_B98_DATA = re.compile(rb"\"[^\"]*\"|'[\s\S]")
_B98_CODE = re.compile(rb"[0-9a-f+\-*/%!`><^v?_|:\\$.,#gp&~@;jkqrxsnuwz\[\]{}()=it\s]*")
_TIGHT = {
    "rockstar": lambda b: re.search(rb"(?im)^[ \t]*(?:say|shout|whisper|scream|print)\b", b) is not None,
    "chef": lambda b: re.search(rb"(?m)^[ \t]*Ingredients\.[ \t]*$", b) is not None
    and re.search(rb"(?m)^[ \t]*Method\.[ \t]*$", b) is not None,
    "befunge": lambda b: b.isascii() and _B98_CODE.fullmatch(_B98_DATA.sub(b"", b)) is not None,
}


def _bf_like(b: bytes) -> bool:
    body = len(b.translate(None, b" \t\r\n\v\f"))
    ops = len(b) - len(b.translate(None, b"+-<>[].,"))
    return ops >= 16 and ops >= 0.9 * body and b"." in b and (b"+" in b or b"-" in b)


def _sig_esolang(b: bytes, m) -> list:
    if not MIN_ESOLANG <= len(b) <= MAX_ESOLANG:
        return []
    t = _text(b)
    out = [Sig("esolang", name, f"the {name} signature of the table") for name, test in _ESOLANG_SIGS if test(b, t)]
    if t is not None and m.ESO.malbolge_valid(t):
        out.append(Sig("esolang", "malbolge", "passes the Malbolge loader's check of every character"))
    seen = {s.name for s in out}
    for attr in m.PACKS:
        mod = getattr(m, attr)
        for name in mod._which(b):
            name = "befunge" if name == "befunge98" else name
            if name == "bfdialect":           # esolang4 learns its token map from the Warmups sentence only
                continue
            if name not in seen and _TIGHT.get(name, lambda _b: True)(b):
                seen.add(name)
                out.append(Sig("esolang", name, f"the signature gate of {mod.__name__}.py"))
    return out


_ALPHABET = {"base16", "base64", "base64url", "base32", "base32hex", "base85", "ascii85", "z85", "base45",
             "base58", "base58:flickr", "base58:ripple", "base91", "base92", "base122"}
_SPECIFIC = ("base16", "base32", "base32hex", "base64", "base64url")     # narrowest alphabet first
_COMP_NAMES = {"gzip", "zlib", "bz2", "bzip2", "xz", "zstd", "lz4", "snappy-framed", "raw-deflate"}
_CHECKED = {"zlib": "zlib Adler-32", "bz2": "bzip2 block CRC", "bzip2": "bzip2 block CRC", "xz": "xz stream check"}
_LOOSE = {"raw-deflate", "reverse", "byteswap16"}    # no magic and no check of their own: need a strong result
_PARTIAL = {"url", "percent", "html-entities"}       # text to text, changing only the escapes: text out proves nothing


def _blobby(b: bytes) -> bool:
    """One encoded blob, not prose: no blank inside a line, or tokens of one width (`de ad be ef`)."""
    tokens = b.split()
    if len(tokens) <= 1 or not re.search(rb"[ \t]", b.strip()):
        return True
    return len(tokens) >= 4 and len({len(t) for t in tokens[:-1]}) == 1


def _sig_aead(b: bytes, carry: Carry) -> bool:
    return bool(carry.all_keys()) and len(b) >= 16 and _text(b) is None


def identify(data: bytes, *, flag_format=None, carry: Carry | None = None) -> list:
    """[Sig] for one layer, in the order the loop asks them: what the bytes are, before any decode.
    `flag_format` (a ctf.flagfmt.FlagFormat) adds the flag signature; `carry` the AES-GCM one."""
    m = _mods()
    b = bytes(data)
    out = []
    if flag_format is not None and flag_format.find_flags(b):
        out.append(Sig("flag", "flag", "holds a flag in the event format"))
    out += _sig_compressed(b)
    if carry is not None and _sig_aead(b, carry):
        out.append(Sig("aead", "aes-gcm", "binary, and an earlier layer stated a key: nonce / ciphertext / tag layouts apply"))
    out += _sig_frame(b)
    out += _sig_format(b, m)
    out += _sig_program(b)
    out += _sig_esolang(b, m)
    t = _text(b)
    if t is not None:
        out.append(Sig("text", "blob" if _blobby(b) else "prose", "printable text"))
    elif b:
        out.append(Sig("binary", "binary", f"{len(b)} bytes, {_entropy(b):.2f} bits/byte"))
    return out


def _entropy(b: bytes) -> float:
    sample = b[:1 << 16]
    if not sample:
        return 0.0
    counts = [0] * 256
    for x in sample:
        counts[x] += 1
    n = len(sample)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


# ------------------------------------------------------------------ key material stated by a layer

_FIELD = re.compile(
    r"(?i)(?<![A-Za-z0-9])(aes[_-]?key|secret[_-]?key|key|nonce|iv|auth[_-]?tag|tag|aad|associated[_-]?data|"
    r"password|passphrase|salt|iterations|iters|sha256|sha1|md5|crc32)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9+/=_-]{2,})")


def _as_bytes(value: str) -> list:
    """Every way a stated value can be bytes: hex, base64, its own characters. The tag decides."""
    import base64
    import binascii
    out = []
    if len(value) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", value):
        out.append(bytes.fromhex(value))
    bare = value.rstrip("=")
    for altchars in (None, b"-_"):
        try:
            got = base64.b64decode(bare + "=" * (-len(bare) % 4), altchars=altchars, validate=True)
        except (binascii.Error, ValueError):
            continue
        if got not in out:
            out.append(got)
    out.append(value.encode())
    return out


def harvest(text: str, where: str, carry: Carry) -> bool:
    """Read `name = value` / `"name": "value"` fields a layer states into the carry: keys (16/24/32
    bytes), nonces, tags, associated data, PBKDF2 parameters, digests and CRCs of what follows.
    Only the first HARVEST characters are read; the return is True when the text is longer (the
    caller says so). A crc32 of eight hex digits is hex, even when all eight are decimal digits
    (crc32=12345678 is 0x12345678: a CRC-32 is written as eight hex digits); 0x... is hex; any
    other run of digits is decimal."""
    for m in _FIELD.finditer(text[:HARVEST]):
        name, value = re.sub(r"[_-]", "", m.group(1).lower()), m.group(2)
        forms = _as_bytes(value)
        if name in ("aeskey", "secretkey", "key"):
            for f in forms:
                if len(f) in (16, 24, 32):
                    carry._add(carry.keys, f, where)
        elif name in ("nonce", "iv"):
            for f in forms[:-1]:
                if 8 <= len(f) <= 16:
                    carry._add(carry.nonces, f, where)
        elif name in ("authtag", "tag"):
            for f in forms[:-1]:
                if len(f) == 16:
                    carry._add(carry.tags, f, where)
        elif name in ("aad", "associateddata"):
            for f in forms:
                carry._add(carry.aads, f, where)
        elif name in ("password", "passphrase"):
            carry._add(carry.passwords, value.encode(), where)
        elif name == "salt":
            for f in forms:
                carry._add(carry.salts, f, where)
        elif name in ("iterations", "iters"):
            if value.isdigit() and 1 <= int(value) <= MAX_PBKDF2:
                carry._add(carry.iterations, int(value), where)
        elif name in ("sha256", "sha1", "md5"):
            want = {"sha256": 64, "sha1": 40, "md5": 32}[name]
            if len(value) == want and re.fullmatch(r"[0-9a-fA-F]+", value):
                carry._add(carry.digests, value.lower(), where)
        elif name == "crc32":
            hexed = value[2:] if value[:2].lower() == "0x" else value
            if re.fullmatch(r"[0-9a-fA-F]{8}", hexed) or (hexed != value and re.fullmatch(r"[0-9a-fA-F]{1,8}", hexed)):
                carry._add(carry.crcs, int(hexed, 16), where)
            elif value.isdigit() and int(value) < 1 << 32:
                carry._add(carry.crcs, int(value), where)
    return len(text) > HARVEST


# ------------------------------------------------------------------ dispatch: one reading of one layer per decoder

def _aead(b: bytes, ctx: _Ctx):
    """The plaintext of an AES-GCM layer under a carried key, or None. Layouts: nonce|ct|tag,
    nonce|tag|ct, ct|tag|nonce, and a carried nonce (and tag) with ct|tag, ct, tag|ct. Only a
    verifying tag returns anything, so a wrong key or layout cannot produce a layer."""
    keys = ctx.carry.all_keys()
    if not keys:
        return None
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:
        raise UnwrapError(f"an earlier layer stated an AES key, and checking this layer against it needs "
                          f"the cryptography package (py:cryptography): {e}") from None
    # A layer too short for a layout gives a short nonce or body, which AESGCM refuses below.
    layouts = [("nonce|ct|tag", b[:12], b[12:]), ("nonce|tag|ct", b[:12], b[28:] + b[12:28]),
               ("ct|tag|nonce", b[-12:], b[:-12])]
    for nonce, _ in ctx.carry.nonces:
        layouts += [("ct|tag, stated nonce", nonce, b), ("tag|ct, stated nonce", nonce, b[16:] + b[:16])]
        layouts += [("ct, stated nonce and tag", nonce, b + tag) for tag, _ in ctx.carry.tags]
    aads = [None] + [a for a, _ in ctx.carry.aads]
    tries = 0
    for key, where in keys:
        for layout, nonce, body in layouts:
            for aad in aads:
                tries += 1
                if tries > MAX_AEAD_TRIES:
                    ctx.notes.append(f"AES-GCM: stopped after {MAX_AEAD_TRIES} key/layout/aad combinations")
                    return None
                try:
                    plain = AESGCM(key).decrypt(nonce, body, aad)
                except (InvalidTag, ValueError):
                    continue
                return Step("aead", "aes-gcm", plain,
                            proof=f"AES-GCM tag verifies ({layout}; AES-{len(key) * 8} key from {where})")
    return None


@contextlib.contextmanager
def _reader_budget(mod, ctx: _Ctx):
    """Run a carried interpreter module on this loop's budget. Each stops itself on a wall-clock
    backstop of 20 to 100 ms sized for a Warmups blob search (READER_TIME; esolang3 also clamps to a
    blob deadline another engine may have left set; esolang4 binds it as the default argument of its
    _deadline). A layer of a journey is one program, not one of hundreds of search states, and that
    backstop refuses a real program whenever the machine is busy. The step and output caps of each
    interpreter are untouched, and every value is put back.

    These are module globals: single-threaded only (see the module docstring). The lock makes two
    threads of this engine take turns, so a thread never saves another's budget as the original."""
    with _BUDGET_LOCK:
        with _patched_budget(mod, ctx):
            yield


_BUDGET_LOCK = threading.RLock()


@contextlib.contextmanager
def _patched_budget(mod, ctx: _Ctx):
    saved = {k: getattr(mod, k) for k in ("READER_TIME", "TOTAL_CAP") if hasattr(mod, k)}
    held = mod.DEADLINE[0] if hasattr(mod, "DEADLINE") else None
    bound = mod._deadline.__defaults__
    try:
        for k in saved:
            setattr(mod, k, ctx.left())
        if hasattr(mod, "DEADLINE"):
            mod.DEADLINE[0] = ctx.reader_deadline()
        if bound:
            mod._deadline.__defaults__ = (ctx.left(),)
        yield
    finally:
        for k, v in saved.items():
            setattr(mod, k, v)
        if hasattr(mod, "DEADLINE"):
            mod.DEADLINE[0] = held
        mod._deadline.__defaults__ = bound


def _esolang(b: bytes, sigs: list, ctx: _Ctx) -> list:
    """[Step] of every esolang whose signature fired: the program is walked by its bounded
    interpreter. A signature whose interpreter gives nothing is recorded as refused."""
    m, out = ctx.m, []
    names = {s.name for s in sigs}
    t = _text(b)
    got = {}                                              # name -> bytes
    raised = {}                                           # name -> "ExcType: message" of a reader that raised

    def run(name, fn):
        if name in names and name not in got:
            try:
                o = fn()
            except Exception as e:                        # said either way: in the refusal, and a fault in the notes
                raised[name] = _raised(e, f"the {name} interpreter", ctx)
                o = None
            if o:
                got[name] = o.encode("latin-1", "replace") if isinstance(o, str) else bytes(o)

    def bf(src):
        ops = "".join(c for c in (src or "") if c in "+-<>[].,")
        return m.ESL.run_bf(ops, steps=ctx.steps, out_cap=BF_OUTPUT, deadline=ctx.reader_deadline())

    if t is not None:
        run("brainfuck", lambda: bf(t))
        run("ook", lambda: bf(m.K.ook_to_brainfuck(re.sub(r"(?i)\book(?=[.?!])", "Ook", t))))
        run("chicken", lambda: m.CH.run_source(t, steps=min(ctx.steps, m.CH.STEPS)))
        for name, fn in m.ESO.READERS:
            if name in _READERS:
                kw = {} if name in _OWN_STEPS else {"steps": ctx.steps}
                run(name, lambda fn=fn, kw=kw: fn(t, deadline=ctx.reader_deadline(), **kw))
    for attr in m.PACKS:
        mod = getattr(m, attr)
        with _reader_budget(mod, ctx):
            try:
                rows = mod.steps(b)
            except Exception as e:
                said = _raised(e, f"{mod.__name__}.steps", ctx)
                for name in mod._which(b):
                    raised.setdefault("befunge" if name == "befunge98" else name, said)
                rows = []
        for name, o in rows:
            name = "befunge" if name == "befunge98" else name
            if name not in got and o:
                got[name] = bytes(o)
    for s in sigs:
        if s.name in got:
            out.append(Step("esolang", s.name, got[s.name]))
        elif s.name in raised:
            ctx.refused.append(Sig("esolang", s.name, s.why + f"; its interpreter raised {raised[s.name]}"))
        else:
            ctx.refused.append(Sig("esolang", s.name, s.why + "; its interpreter gave nothing (input asked for, "
                                   "no halt within the caps, or not a clean program)"))
    return out


def _raised(e: Exception, who: str, ctx: _Ctx) -> str:
    """The type of what a reader raised. A refusal type is the reader saying "not this one"; any
    other type is a fault in the reader, which goes into the notes with its message (cut short: a
    message may quote the layer), so a broken decoder is never mistaken for a layer it cannot read."""
    if isinstance(e, _REFUSALS):
        return type(e).__name__
    said = f"{type(e).__name__}: {str(e)[:80]}"
    ctx.notes.append(f"{who} failed with {said} (a fault in the reader, not a refusal of the layer)")
    return said


NAME_SHOWN = 80                        # characters of a challenge-chosen name (an archive member's) a record repeats
NOTE_SHOWN = 240                       # characters of one archive_expand note, which quotes member names


def _shown(name: str) -> str:
    """A name the challenge chose (an archive member's), as a record repeats it: unprintable
    characters as '?', and at most NAME_SHOWN characters, then its full length."""
    clean = "".join(c if c.isprintable() else "?" for c in name)
    return clean if len(clean) <= NAME_SHOWN else f"{clean[:NAME_SHOWN]}... ({len(name)} characters)"


def _archive(b: bytes, sig: Sig, ctx: _Ctx):
    """(Step or None, members): the one member of a single-member archive, through archive_expand's
    bounded wide walk. An archive of several members is another lane's (ctf sweep): its member names
    are returned for the stop record."""
    m = ctx.m
    walk = m.AE.Walk(max_member=MAX_LAYER, max_total=4 * MAX_LAYER, max_members=64, max_depth=0)
    found: dict = {}
    top = ctx.name or "layer"
    try:
        m.AE.expand(top, b, found, opts=walk)
    except Exception as e:
        ctx.notes.append(f"{sig.name} archive not opened: {type(e).__name__}: {e}")
        return None, []
    # archive_expand's notes quote member names (challenge text): each is cut to NOTE_SHOWN characters
    ctx.notes.extend(n if len(n) <= NOTE_SHOWN else f"{n[:NOTE_SHOWN]}... ({len(n)} characters)" for n in walk.notes)
    members = [(k, v) for k, v in found.items() if k != top and " -> " in k and k.count(" -> ") == 1]
    if len(members) != 1:
        return None, [f"{_shown(k.split(' -> ', 1)[1])} ({len(v)} bytes)" for k, v in members[:16]]
    key, data = members[0]
    member = key.split(" -> ", 1)[1]
    return Step("archive", f"{sig.name}-member", data, proof=_member_crc(b, sig.name, member, data, ctx)), []


def _member_crc(b: bytes, kind: str, member: str, data: bytes, ctx: _Ctx):
    """The proof of an archive member, or None. archive_expand takes what 7-Zip extracts from a
    damaged member too (its last resort for a zip member the library could not read), so the stored
    CRC-32 is checked here against the bytes it gave. A zip's is read from its directory; 7z and rar
    are read only through 7-Zip, whose listing this loop does not parse, and tar stores no check:
    those members carry no proof of their own."""
    if kind != "zip":
        return None
    try:
        info = zipfile.ZipFile(io.BytesIO(b)).getinfo(member)
    except (zipfile.BadZipFile, KeyError, ValueError, OSError) as e:
        ctx.notes.append(f"the zip member's stored CRC-32 could not be read ({type(e).__name__}): taken unproved")
        return None
    if zlib.crc32(data) == info.CRC and len(data) == info.file_size:
        return f"zip member CRC-32 ({_shown(member)})"
    ctx.notes.append(f"zip member {_shown(member)!r}: the extracted bytes do not match its stored CRC-32 "
                     f"(a damaged member): taken unproved")
    return None


def _piet(b: bytes, ctx: _Ctx):
    m = ctx.m
    try:
        out = m.PIET.run_piet(b, steps=min(ctx.steps, 5_000_000), deadline=ctx.reader_deadline())
    except m.PIET.MissingPillowError as e:
        ctx.notes.append(f"the image was not tried as a Piet program: {e}")
        return None
    except Exception as e:
        said = _raised(e, "the Piet interpreter", ctx)
        ctx.refused.append(Sig("esolang", "piet", f"the image as a Piet program: its interpreter raised {said}"))
        return None
    return Step("esolang", "piet", out) if out else None


def _encodings(b: bytes, ctx: _Ctx) -> list:
    """[Step] of every whole-layer reading the two envelope batteries give: unwrap.py's (one level,
    every decode kept for this loop's own recognition) and encdepth_layered.py's. Readings are
    de-duplicated by their bytes; the first decoder to give a reading names it. Each battery keeps
    its own size cap: unwrap.py reads nothing over its MAX_IN (48 MiB), and encdepth_layered.py
    declines a layer over EL_MAX, which is noted."""
    m, out, seen = ctx.m, [], {b}
    if len(b) < m.UW.MIN_LEN:                 # nothing shorter is a wrapped layer (unwrap.py's own floor)
        return []
    rows = [(chain[0], data) for data, chain in m.UW.peel(b, recognize=lambda _b: True, max_depth=1)]
    try:
        rows += m.EL.peel(b, max_bytes=EL_MAX)
    except m.EL.DecodeError as e:
        ctx.notes.append(f"encdepth_layered declined the layer: {e}")
    blobby = _blobby(b)
    for name, data in rows:
        if not data or data in seen or len(data) > MAX_LAYER or (name in _ALPHABET and not blobby):
            continue
        seen.add(data)
        out.append(Step("compressed" if name in _COMP_NAMES else "encoding", name, data))
    return out


def _embedded(b: bytes, ctx: _Ctx) -> list:
    """[Step] of the longest encoded blobs inside a text layer (embedded_decode.find_blobs). A stated
    key or nonce is a blob too; it is never the one followed, because the payload beside it is the
    reading that is recognised (a key authenticates it, it holds a flag, a stream, a text)."""
    t = _text(b)
    if t is None:
        return []
    rows = ctx.m.ED.find_blobs(t, min_printable=0.0, flag_re=ctx.ff.bregex, max_results=100)   # [] over its own size cap
    rows.sort(key=lambda r: (-len(r["match"]), r["offset"], r["encoding"]))    # the payload is the long one
    return [Step("embedded", f"{r['encoding']}@{r['offset']}", r["decoded"]) for r in rows[:6]]


# ------------------------------------------------------------------ recognition and proof of a reading

def _strength(out: bytes, ctx: _Ctx) -> int:
    """How well a reading re-enters detection: 3 a flag, 2 a strong signature (a compressed stream's
    magic, an exact length prefix, an archive or known format, a real-language program, bytes a
    carried key authenticates), 1 printable text, 0 nothing."""
    if ctx.ff.find_flags(out):
        return 3
    if (any(s.name != "zlib" for s in _sig_compressed(out)) or _sig_frame(out) or _sig_format(out, ctx.m)
            or _sig_program(out)):
        return 2
    if _text(out) is None:
        return 2 if _aead(out, ctx) is not None else 0
    return 1


def _prove(step: Step, cur: bytes, ctx: _Ctx) -> None:
    """Set step.proof when the reading self-validates (verified_transform.py's rule: a stored check,
    a stated digest, or a complete file structure; never a bare length or a printable look)."""
    VT = ctx.m.VT
    if step.proof:
        return
    if step.name == "gzip" and VT.verify(cur, magic=b"\x1f\x8b", structure=True):
        step.proof = "gzip CRC-32 (the stream reads to its end)"
    elif step.name in _CHECKED:
        step.proof = _CHECKED[step.name]
    else:
        for digest, where in ctx.carry.digests:
            if VT.verify(step.out, digest=digest):
                step.proof = f"the digest stated in {where} matches"
                return
        for crc, where in ctx.carry.crcs:
            if VT.verify(step.out, crc=crc):
                step.proof = f"the CRC-32 stated in {where} matches"
                return
        if VT.verify(step.out, structure=True):
            step.proof = "the result is a complete file structure"


def _pick(steps: list, cur: bytes, ctx: _Ctx, deep: bool = True, lead: bool = True):
    """The reading to follow, or None: a proved one first, then the best-recognised one, ties to the
    narrowest alphabet and the table's order. A loose decoder needs a strong result. An escape reader
    (url, html entities) turns text into text, and base85 text holds a %hh by chance, so its text
    counts only when that text in turn has a reading to follow (one look ahead, no further)."""
    for i, s in enumerate(steps):
        _prove(s, cur, ctx)
        s.rank = 4 if s.proof else _strength(s.out, ctx)
        if deep and s.rank == 1 and s.name in _PARTIAL and _pick(
                _encodings(s.out, ctx) + _embedded(s.out, ctx), s.out, ctx, deep=False) is None:
            s.rank = 0
        s.order = (_SPECIFIC.index(s.name) if s.name in _SPECIFIC else len(_SPECIFIC), i)
    good = [s for s in steps if s.rank >= (2 if s.name in _LOOSE else 1)]
    if good:
        return min(good, key=lambda s: (-s.rank, s.order))
    if not lead:
        return None
    # Nothing recognised. A reading may still be followed as an unverified lead when there is no
    # choice to make: the narrowest of the hex / base32 / base64 alphabets that reads the layer, or
    # the one thing a program printed or a stream held. Wide alphabets and escape readers take almost
    # any text, so they are never followed on trust; and no lead is taken (`lead` False) from a layer
    # that is a program its interpreter refused (a COW program is also base64 letters).
    narrow = [s for s in steps if s.name in _SPECIFIC]
    if narrow:
        return min(narrow, key=lambda s: s.order)
    lone = [s for s in steps if s.kind in ("esolang", "compressed") and s.name not in _LOOSE]
    return lone[0] if len(lone) == 1 else None


# ------------------------------------------------------------------ the loop

def unwrap(data: bytes, flag_format, *, name: str = "", carry: Carry | None = None, max_layers: int = MAX_LAYERS,
           budget: float | None = None, steps: int = DEFAULT_STEPS, first: int = 1,
           clock=time.perf_counter) -> Unwrap:
    """Peel `data` layer by layer and return the chain, the flags reached and why the loop stopped.

    flag_format  a ctf.flagfmt.FlagFormat: the goal, and the gate on what counts as a flag
    carry        key material known before the first layer (the engine's key= / nonce= / ... options)
    budget       seconds for the whole chain (default DEFAULT_BUDGET), on `clock` (injectable so a test
                 drives time itself)
    steps        the step cap handed to each esolang interpreter
    first        the number of the first layer (a resumed run continues the earlier numbering)

    stop["reason"]: flag | program-layer | known-format | unknown-layer | budget | max-layers | cycle |
    too-large. Every stop but `flag` carries the layer number, what was identified, and the next step.
    """
    carry = carry if carry is not None else Carry()
    ctx = _Ctx(flag_format, carry, clock() + (DEFAULT_BUDGET if budget is None else budget), clock, steps, name)
    layers: list = []
    cur, seen = bytes(data), set()

    def stop(reason: str, **more) -> Unwrap:
        n = first + len(layers)
        flags = tuple(flag_format.find_flags(cur)) if reason == "flag" else ()      # distinct, in order
        if reason == "flag":
            for layer in layers:
                layer.verified = True
        u = Unwrap(layers, flags, {}, cur)
        k = u.accepted_through
        u.stop = {"reason": reason, "layer": n, "bytes": len(cur),
                  "accepted_through": first + k - 1, "unverified": [x.n for x in layers[k:]],
                  "refused": [vars(s) for s in ctx.refused], "notes": list(dict.fromkeys(ctx.notes)), **more}
        return u

    while True:
        ctx.refused.clear()
        if flag_format.find_flags(cur):
            return stop("flag")
        if len(layers) >= max_layers:
            return stop("max-layers", next=f"{max_layers} layers followed; raise --opt max_layers= to go on")
        if ctx.left() <= 0:
            return stop("budget", next="the time budget is spent; run again on the last layer's file with a larger --opt budget=")
        if len(cur) > MAX_LAYER:
            return stop("too-large", next=f"the layer is over {MAX_LAYER} bytes; this loop does not read it")
        digest = hashlib.sha256(cur).digest()
        if digest in seen:
            return stop("cycle", next="a decode gave an earlier layer back; the chain does not advance")
        seen.add(digest)
        n = first + len(layers)
        text = _text(cur)
        if text is not None and harvest(text, f"layer {n}", carry):
            ctx.notes.append(f"layer {n}: fields (key=, nonce=, sha256=, ...) were read from its first {HARVEST} "
                             f"characters only; one stated after them needs --opt key= / nonce= / ...")

        def take(step: Step) -> None:
            layers.append(Layer(n, step.kind, step.name, step.proof, bool(step.proof), len(cur), len(step.out), step.out))
            if step.proof:
                for layer in layers:
                    layer.verified = True

        # 1. a layer a stated key authenticates, or an exact length prefix
        step = _aead(cur, ctx)
        if step is None and _sig_aead(cur, carry):
            ctx.refused.append(Sig("aead", "aes-gcm", "no stated key authenticates this layer under the known layouts"))
        if step is None:
            frames = _sig_frame(cur)
            if frames:
                size = next(size for name_, size, _ in FRAMES if name_ == frames[0].name)
                step = Step("frame", frames[0].name, cur[size:])
                _prove(step, cur, ctx)
        if step is not None:
            take(step)
            cur = step.out
            continue

        # 2. a file format: an archive of one member is followed, an image is tried as Piet, the rest is handed on
        fmt = _sig_format(cur, ctx.m)
        if fmt:
            members = []
            if fmt[0].kind == "archive":
                step, members = _archive(cur, fmt[0], ctx)
            else:
                step = _piet(cur, ctx) if fmt[0].name in _IMAGES else None
            if step is not None:
                _prove(step, cur, ctx)
                take(step)
                cur = step.out
                continue
            return stop("known-format", identified=[vars(fmt[0])], members=members,
                        next=f"layer {n} is a {fmt[0].name} file: give its saved bytes to the lane that reads it "
                             f"(python -m ctf sweep <file>, python -m ctf triage)")

        # 3. a program in a real language is never run
        prog = _sig_program(cur)
        if prog:
            what = "a script whose shebang names an unknown interpreter" if prog[0].name == "shebang" else \
                f"{prog[0].name} source"
            return stop("program-layer", identified=[vars(prog[0])], facts=_program_facts(cur),
                        next=f"layer {n} is {what}: {_STATIC_READERS.get(prog[0].name, '')}read it and re-implement "
                             f"its transform statically (never run it), write the result to a file in the challenge "
                             f"folder, then run python -m ctf run {ENGINE} <challenge_dir> --opt file=<that file> "
                             f"--opt first={n + 1}")

        # 4. compressed streams, esolang programs, whole-layer encodings, a blob inside a text
        eso = _sig_esolang(cur, ctx.m)
        cands = (_esolang(cur, eso, ctx) if eso else []) + _encodings(cur, ctx) + _embedded(cur, ctx)
        step = _pick(cands, cur, ctx, lead=not any(r.kind == "esolang" for r in ctx.refused))
        if step is not None:
            take(step)
            cur = step.out
            continue
        ctx.refused += [Sig("compressed", g.name, g.why + "; it does not decompress to a checked end")
                        for g in _sig_compressed(cur)]
        sigs = identify(cur, carry=carry)
        fp = ctx.m.FP.fingerprint(name or "layer", cur)
        return stop("unknown-layer", identified=[vars(s) for s in sigs],
                    candidates=[{"name": s.name, "bytes": len(s.out)} for s in cands if s.name not in _LOOSE][:12],
                    facts={"size": fp.size, "entropy": round(fp.entropy, 3), "head_hex": fp.head_hex[:64],
                           "magic_ascii": list(fp.magic_ascii[:6]), "stride": fp.stride},
                    next=f"layer {n} is not one this loop reads: decode it statically, write the result to a file in "
                         f"the challenge folder, then run python -m ctf run {ENGINE} <challenge_dir> "
                         f"--opt file=<that file> --opt first={n + 1}")


# ------------------------------------------------------------------ the engine entry

def _files(base: Path, root: Path, out_dir: Path, max_files: int = MAX_FILES):
    """(files to read, [(path relative to base, why it is not read, unread)]). Walked in sorted order;
    at the challenge root (only there) recon/ and unpacked/ are engine output and are not walked, nor
    is the out= folder; hidden entries are never opened (a hidden folder is named, not listed); links
    are not followed; an empty file has nothing to read. Every file left out, for any reason but
    being engine output, is in the second list; `unread` is True for a handout file whose content
    was not looked at (over the file count or the size cap), so the run cannot say `none`."""
    root, out_dir = root.resolve(), out_dir.resolve()
    found, skipped = [], []
    for dirpath, dirnames, filenames in os.walk(base):
        here = Path(dirpath)
        keep = []
        for d in sorted(dirnames):
            p = here / d
            if (here.resolve() == root and d in ROOT_SKIP) or p.resolve() == out_dir:
                continue
            if d.startswith(".") or p.is_symlink():
                skipped.append((str(p.relative_to(base)) + "/", "hidden folder" if d.startswith(".") else "link"))
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            p = here / name
            rel = str(p.relative_to(base))
            if name.startswith("."):
                skipped.append((rel, "hidden file"))
            elif p.is_symlink() or not p.is_file():
                skipped.append((rel, "link, not followed" if p.is_symlink() else "not a regular file"))
            elif p.stat().st_size == 0:
                skipped.append((rel, "empty"))
            elif p.stat().st_size > MAX_LAYER:
                skipped.append((rel, f"{p.stat().st_size} bytes, over the {MAX_LAYER}-byte layer cap", True))
            else:
                found.append(p)
    found.sort()
    skipped += [(str(p.relative_to(base)), f"over the {max_files}-file cap (--opt max_files=)", True)
                for p in found[max_files:]]
    return found[:max_files], [s if len(s) == 3 else (*s, False) for s in skipped]


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".")[:80] or "layer"


def _opt_bytes(value: str, what: str) -> list:
    out = []
    for part in str(value).split(","):
        part = part.strip()
        if not part:
            continue
        if len(part) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", part):
            raise UnwrapError(f"--opt {what}= takes hex (comma-separated for several); got {len(part)} characters that are not")
        out.append(bytes.fromhex(part))
    return out


def _opt_int(opts: dict, key: str, default: int, low: int, high: int) -> int:
    raw = opts.get(key, default)
    try:
        v = int(raw)
    except (TypeError, ValueError):
        raise UnwrapError(f"--opt {key}= takes an integer; got {raw!r}") from None
    if not low <= v <= high:
        raise UnwrapError(f"--opt {key}= must be {low}..{high}; got {v}")
    return v


def _carry_from(opts: dict) -> Carry:
    c = Carry()
    for k in _opt_bytes(opts.get("key", ""), "key"):
        if len(k) not in (16, 24, 32):
            raise UnwrapError(f"--opt key= is an AES key of 16, 24 or 32 bytes; got {len(k)}")
        c._add(c.keys, k, "the key= option")
    for v in _opt_bytes(opts.get("nonce", ""), "nonce"):
        c._add(c.nonces, v, "the nonce= option")
    for v in _opt_bytes(opts.get("salt", ""), "salt"):
        c._add(c.salts, v, "the salt= option")
    if opts.get("aad"):
        c._add(c.aads, str(opts["aad"]).encode(), "the aad= option")
    if opts.get("password"):
        c._add(c.passwords, str(opts["password"]).encode(), "the password= option")
    if opts.get("iterations"):
        c._add(c.iterations, _opt_int(opts, "iterations", 0, 1, MAX_PBKDF2), "the iterations= option")
    return c


def _folder(rel: str) -> str:
    """The output folder of one input, unique per input path: a plain name (no folder, nothing _safe
    changes) is its own name; any other is its _safe form, '@' and 12 hex digits of the SHA-256 of
    the path. '@' is a character _safe never keeps, so the two kinds never meet: files/a/b
    (a__b@...) and files/a__b (a__b) are different folders."""
    flat = _safe(rel.replace("/", "__"))
    if flat == rel:
        return flat
    return f"{flat}@{hashlib.sha256(rel.encode('utf-8', 'surrogateescape')).hexdigest()[:12]}"


def _write(out_dir: Path, src: Path, rel: str, u: Unwrap) -> dict:
    """Save every layer's bytes and the stop record (unwrap.json) under out_dir/<_folder(rel)>/;
    return the record. stop.file is the file that holds the bytes the loop stopped at: the last
    layer's, or the input. An OSError is the caller's to report."""
    d = out_dir / _folder(rel)
    d.mkdir(parents=True, exist_ok=True)
    doc = u.to_dict()
    doc["input"] = rel
    for layer, row in zip(u.layers, doc["layers"]):
        f = d / f"{layer.n:02d}-{_safe(layer.name)}.bin"
        f.write_bytes(layer.out)
        f.chmod(0o644)
        row["file"] = str(f)
    doc["stop"]["file"] = doc["layers"][-1]["file"] if u.layers else str(src)
    (d / RECORD).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    doc["record"] = str(d / RECORD)
    return doc


def _line(rel: str, u: Unwrap) -> str:
    s = u.stop
    chain = " > ".join(f"{x.name}{'' if x.verified else '?'}" for x in u.layers) or "no layer peeled"
    what = {"flag": "flag reached", "program-layer": "program layer (not run)", "known-format": "known format",
            "unknown-layer": "unknown layer"}.get(s["reason"], s["reason"])
    named = ", ".join(i["name"] for i in s.get("identified", [])[:3])
    said = "".join(f"; note: {note}" for note in s["notes"][:2])       # what was not tried, and why: never silent
    return f"{rel}: {what} {s['layer']}{' (' + named + ')' if named else ''}; chain: {chain}{said}"


def solve(challenge_dir, profile, **opts):
    from ctf import flagfmt
    from ctf.result import Cost, Evidence, SolverResult

    t0 = time.monotonic()

    def result(status, **kw):
        return SolverResult(status, engine=ENGINE, cost=Cost(seconds=round(time.monotonic() - t0, 3)), **kw)

    challenge_dir = Path(challenge_dir)
    ff = flagfmt.for_profile(profile)
    if not ff.known:
        return result("blocked", notes="the event profile has no flag format, so this loop has no goal to stop at")
    try:
        try:
            budget = float(opts.get("budget", DEFAULT_BUDGET))
        except (TypeError, ValueError):
            raise UnwrapError(f"--opt budget= takes seconds; got {opts.get('budget')!r}") from None
        steps = _opt_int(opts, "steps", DEFAULT_STEPS, 1, 10 ** 9)
        max_layers = _opt_int(opts, "max_layers", MAX_LAYERS, 1, 256)
        max_files = _opt_int(opts, "max_files", MAX_FILES, 1, 256)
        first = _opt_int(opts, "first", 1, 1, 10 ** 6)
        _carry_from(opts)                              # a bad key= / nonce= / ... is refused before any file is read
        _mods()
    except UnwrapError as e:
        return result("blocked", notes=str(e))
    root = challenge_dir.resolve()
    # Layer files are written inside the challenge folder only, as file= reads only inside it.
    out_dir = (challenge_dir / str(opts["out"] if opts.get("out") else OUT_DIR)).resolve()
    if out_dir != root and root not in out_dir.parents:
        return result("blocked", notes=f"--opt out={opts['out']}: not a folder inside the challenge folder")
    if out_dir == root:
        return result("blocked", notes=f"--opt out={opts['out']}: the challenge folder itself; name a folder inside it")
    if not opts.get("file"):
        # nor the handout folder, or a folder holding it: the layer folders would land among the
        # handout files, where a file of the same name stops them
        hand = (challenge_dir / "files").resolve() if (challenge_dir / "files").is_dir() else root
        if out_dir == hand or out_dir in hand.parents:
            return result("blocked", notes=f"--opt out={opts['out']}: the handout folder itself or a folder "
                                         f"holding it; name a folder inside the handout or beside it")
    skipped = []
    if opts.get("file"):
        one = (challenge_dir / str(opts["file"])).resolve()
        if root not in one.parents or not one.is_file():
            return result("blocked", notes=f"--opt file={opts['file']}: not a file inside the challenge folder")
        if one.stat().st_size > MAX_LAYER:
            return result("blocked", notes=f"--opt file={opts['file']}: over {MAX_LAYER} bytes")
        files, base = [one], root
    else:
        base = challenge_dir / "files" if (challenge_dir / "files").is_dir() else challenge_dir
        files, skipped = _files(base, root, out_dir, max_files)
    write = str(opts.get("write", "1")).strip().lower() not in ("0", "false", "no", "off")

    flags, evidence, lines, stuck, written = [], [], [], 0, set()
    unread = [rel for rel, _, gone in skipped if gone]
    for rel, why, _ in skipped[:16]:
        evidence.append(Evidence("skipped", f"not read: {why}", path=rel))
    if skipped:
        shown = "; ".join(f"{rel} ({why})" for rel, why, _ in skipped[:8])
        lines.append(f"{len(skipped)} file(s) not read: {shown}" + (f"; and {len(skipped) - 8} more" if len(skipped) > 8 else ""))
    for f in files:
        rel = str(f.relative_to(base))
        try:
            u = unwrap(f.read_bytes(), ff, name=f.name, carry=_carry_from(opts), max_layers=max_layers, budget=budget,
                       steps=steps, first=first)
        except UnwrapError as e:
            return result("blocked", notes=f"{rel}: {e}")
        reason = u.stop["reason"]
        if not u.layers and reason in ("unknown-layer", "known-format"):
            continue                                   # nothing of this engine's in the file
        doc = u.to_dict()
        if write:
            name = _folder(rel)
            if name in written:                        # two inputs, one folder: never overwrite the first record
                lines.append(f"{rel}: layer files not written: its folder {name} is another input's")
            else:
                written.add(name)
                try:
                    doc = _write(out_dir, f, rel, u)
                except OSError as e:                   # a file where a folder must go, no room, no permission:
                    lines.append(f"{rel}: layer files not written "      # said, and the run goes on
                                 f"({type(e).__name__}: {str(e)[:160]})")
        for layer in u.layers:
            evidence.append(Evidence("decode", f"layer {layer.n}: {layer.name} ({layer.kind}), {layer.bytes_in} -> "
                                     f"{layer.bytes_out} bytes; " + (f"proved by {layer.proof}" if layer.proof else
                                                                      "accepted by a later proof" if layer.verified
                                                                      else "UNVERIFIED lead"), path=rel))
        lines.append(_line(rel, u) + (f"; record: {doc['record']}" if "record" in doc else ""))
        if reason == "flag":
            flags += [x for x in u.flags if x not in flags]
            evidence.append(Evidence("match", f"flag in the event format under {len(u.layers)} layer(s)"
                                     if u.layers else "flag in the event format in the file as it stands", path=rel))
        else:
            stuck += 1
            evidence.append(Evidence("stop", f"{reason} at layer {u.stop['layer']}: {u.stop.get('next', '')}"[:400],
                                     path=rel))
    notes = " | ".join(lines)[:1800]
    if len(flags) == 1:
        return result("solved", flags=flags, evidence=evidence, notes=notes)
    if flags:
        return result("candidate", flags=flags, evidence=evidence,
                      notes=f"{len(flags)} distinct flags reached; not chosen between. " + notes)
    if stuck:
        return result("unsure", evidence=evidence, notes=notes)
    if unread:
        return result("unsure", evidence=evidence,
                      notes=(f"no layer this loop reads in the {len(files)} file(s) read, but {len(unread)} handout "
                             f"file(s) were not read (run again with --opt file=<one> or a larger --opt max_files=) | "
                             + notes)[:1800])
    return result("none", evidence=evidence,
                  notes=(f"no layer this loop reads in {len(files)} file(s)" + (" | " + notes if notes else ""))[:1800])
