#!/usr/bin/env python3
"""B-167: Python / JVM bytecode recovery and a packer-unpack set, run in the sandbox at intake.

Managed and interpreted samples stop at metadata: a ``.pyc`` or a Java ``.class`` / ``.jar`` carries
the challenge logic, but the native-decompile intake (B-011 / B-054) does not read them, a PyInstaller
executable hides its scripts in an appended archive, and a UPX-packed executable hides its code until
it is unpacked.  This engine recovers that code at intake by running the right tool *inside the
networkless Docker sandbox* (``tools/sandbox.py``), never natively:

  * Python ``.pyc`` / ``.pyo``  -> source, by ``pycdc`` (primary) then ``decompyle3`` (fallback); when
                                  neither gives clean source, the partial source is kept and the
                                  ``pycdas`` disassembly is added (reported ``unsure``, never clean)
  * Java ``.class``             -> source, by ``cfr`` then ``vineflower``
  * Java ``.jar`` / ``.war``    -> a tree of ``.java``, by ``cfr`` then ``vineflower``
  * a PyInstaller executable    -> its script entries as ``.pyc`` (the CArchive is parsed in this
                                  process by ``pyinstaller_extract``, as data), each then recovered as
                                  a ``.pyc`` above
  * a UPX-packed ELF/PE/Mach-O  -> the unpacked image, by ``upx -d`` (``sandbox.upx_unpack``), which
                                  is then handed to the native decompiler of ``decompile_intake``
  * a native stub that carries  -> that inner image, decoded in memory by ``packer_unpack`` (a zlib /
    a compressed native image      gzip / bzip2 / xz stream or an ``AP32`` aPLib wrapper, each checked
    or an ``AP32`` payload         by its own checksum; a bounded decode of data, nothing is run), then
                                  handed to the native decompiler as well

The recovered text/bytes are written under ``recon/recover/<file>-<hash>/`` and scanned for the event
flag format; a hardcoded flag surfaces as a ``candidate``.  Nothing is decompiled or unpacked by a tool
run natively, and a challenge file is treated as data: this engine parses headers to pick the tool, but
never imports, unmarshals, or executes it.

No silent fallback: a down sandbox (not started, image not built, a tool missing from the image, or the
Docker socket denied by intake's network guard) is ``blocked`` with the named reason; a file that is
too large, unreadable, over the file cap or past the time budget is named in the notes and the result
is never a clean ``none``.  The decompilers are a human rebuild step (``docker/sandbox/Dockerfile.2`` +
``tools/sandbox.py build``); see ``docs/build-log/B-167.md``.

Entry: ``solve(challenge_dir, profile) -> SolverResult`` (an intake ``run = "challenge"`` adapter).
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import re
import struct
import sys
import time
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

# ----------------------------------------------------------------------------- limits
MAX_FILE_BYTES = 256 * 1024 * 1024    # a handout file larger than this is not recovered at intake
MAX_FILES = 24                        # files recovered in one challenge (the rest are counted)
MAX_OUTPUT_FILES = 2000               # .java members kept from one jar
MAX_MEMBER_BYTES = 8 * 1024 * 1024    # one .java read out of a decompiler's source archive
MAX_OUTPUT_BYTES = 64 * 1024 * 1024   # all .java read out of a decompiler's source archive
MAX_ZIP_ENTRIES = 100_000             # zip entry names read to tell a jar from a plain zip
MAX_PYI_SCRIPTS = 16                  # script entries recovered from one PyInstaller archive
SCAN_WINDOW = 4 * 1024 * 1024         # bytes at the head and tail searched for a packer / archive marker
HEAD_BYTES = 16                       # bytes read to decide whether a file's body is read at all
PY_TIMEOUT = 60.0                     # seconds for one .pyc decompile in the sandbox
DISASM_TIMEOUT = 30.0                 # seconds for one pycdas disassembly in the sandbox
JVM_TIMEOUT = 180.0                   # seconds for one .class / .jar decompile in the sandbox
UPX_TIMEOUT = 20.0                    # seconds for one `upx -d` in the sandbox
DECOMPILE_TIMEOUT = 90.0              # seconds for ONE pass of the native decompile of an unpacked image
DECOMPILE_PASSES = 2                  # decompile_file's r2 backend spends its timeout twice (aflj, then pdg)
DECOMPILE_PROBE = 30.0                # ... after a one-off `pdg?` plugin probe of up to this many seconds
CARVE_MAX_BYTES = 32 * 1024 * 1024    # a native file larger than this is not searched for an inner image
CARVE_MAX_OUTPUT = 32 * 1024 * 1024   # one inner image decoded in memory (aPLib is decoded in pure Python)
MAX_CARVE_TRIES = 32                  # full in-memory decodes tried on one file
CARVE_PROBE_BYTES = 256               # bytes a deflate stream's start is test-decoded on before a full decode
OVERALL_BUDGET = 240.0                # seconds for one whole solve(): under the manifest's intake timeout
MIN_TOOL_SECONDS = 2.0                # a tool is not started with less than this left of the budget

# ----------------------------------------------------------------------------- magic / sniff
_JAVA_CLASS = b"\xca\xfe\xba\xbe"     # also Mach-O FAT_MAGIC: told apart by the class major-version field
_ZIP = b"PK"
_PYC_TAIL = b"\r\n"                   # every CPython pyc magic is <2-byte int> + b"\r\n" at offset 2
_UPX = b"UPX!"
_ELF = b"\x7fELF"
_MACHO = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"}
_PYI_COOKIE = b"MEI\x0c\x0b\x0a\x0b\x0e"   # the PyInstaller CArchive cookie magic (pyinstaller_extract.MAGIC)
# a Java class major_version: 45 (JDK 1.1) .. well past current; a Mach-O fat header's u32 nfat_arch
# sits in the same two bytes and is a small count (1..~30), so this range separates the two cleanly.
_CLASS_MAJOR_MIN = 45
_CLASS_MAJOR_MAX = 255
# The 2-byte CPython magic word (little-endian).  3.x words run from 3000 (3.0a1) upward in steps and
# stay far below 4000; 2.x and 1.x used the listed values.  None of them is two printable ASCII
# characters, so a Windows text file ("hi\r\n...") never passes.
_PYC_MAGIC_3X = range(3000, 4000)
_PYC_MAGIC_OLD = frozenset({20121, 50428, 50823, 60202, 60717}) | frozenset(range(62011, 62212))
# The word each CPython release writes, for a PyInstaller archive that names only its Python version.
_PYC_MAGIC_BY_VERSION = {27: 62211, 35: 3351, 36: 3379, 37: 3394, 38: 3413, 39: 3425,
                         310: 3439, 311: 3495, 312: 3531, 313: 3571}


def pyc_magic_word(head: bytes) -> int | None:
    """The CPython magic word of ``head`` when its first four bytes are a known pyc magic, else None."""
    if len(head) < 4 or head[2:4] != _PYC_TAIL:
        return None
    word = int.from_bytes(head[:2], "little")
    return word if (word in _PYC_MAGIC_3X or word in _PYC_MAGIC_OLD) else None


def is_pyc(head: bytes) -> bool:
    """True when ``head`` looks like a CPython ``.pyc``: a known 2-byte magic word, ``\\r\\n``, and
    room for a header (16 bytes: the 3.7+ magic, bit field, mtime, source size).

    ``\\r\\n`` at offset 2 alone is not enough -- any CRLF text file with a two-character first line
    has it -- so the magic word is checked against the values CPython has used."""
    return len(head) >= 16 and pyc_magic_word(head) is not None


def is_java_class(head: bytes) -> bool:
    """True when ``head`` is a single Java ``.class`` (CA FE BA BE with a class ``major_version``).

    0xCAFEBABE is also a Mach-O fat binary; the two are told apart by the two bytes at offset 6, the
    class ``major_version`` for a class file and the low half of ``nfat_arch`` for a fat Mach-O."""
    if head[:4] != _JAVA_CLASS or len(head) < 8:
        return False
    major = int.from_bytes(head[6:8], "big")
    return _CLASS_MAJOR_MIN <= major <= _CLASS_MAJOR_MAX


def zip_names(data: bytes) -> list[str]:
    """The entry names of a ZIP, from its central directory (no member is inflated), bounded to
    MAX_ZIP_ENTRIES.  A zip whose central directory cannot be read falls back to the local file
    headers at its front; anything else gives an empty list."""
    if data[:2] != _ZIP:
        return []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return [info.filename for info in zf.infolist()[:MAX_ZIP_ENTRIES]]
    except (zipfile.BadZipFile, ValueError, OSError, EOFError, struct.error, NotImplementedError,
            OverflowError):
        pass
    names, pos = [], 0
    while len(names) < MAX_ZIP_ENTRIES and pos + 30 <= len(data) and data[pos:pos + 4] == b"PK\x03\x04":
        csize, _usize, nlen, xlen = struct.unpack_from("<IIHH", data, pos + 18)
        names.append(data[pos + 30:pos + 30 + nlen].decode("utf-8", "replace"))
        pos += 30 + nlen + xlen + csize
    return names


def is_jar(data: bytes) -> bool:
    """True when ``data`` is a ZIP with a ``.class`` member (a ``.jar`` / ``.war``).

    The test is on the archive's entry names, not on raw bytes: ``META-INF/`` alone is also in an
    EPUB, an ODT and an APK (whose code is ``classes.dex``, which a JVM decompiler does not read), so
    only an actual ``.class`` entry routes a zip to the JVM decompilers."""
    return any(name.endswith(".class") for name in zip_names(data))


def is_fat_macho(head: bytes) -> bool:
    """True when ``head`` is a universal (fat) Mach-O: CA FE BA BE, then a u32 ``nfat_arch`` that is a
    small count -- below every Java class ``major_version``, which sits in the same bytes."""
    return (head[:4] == _JAVA_CLASS and len(head) >= 8
            and 1 <= int.from_bytes(head[4:8], "big") < _CLASS_MAJOR_MIN)


def _is_native(head: bytes) -> bool:
    return head[:4] == _ELF or head[:4] in _MACHO or head[:2] == b"MZ" or is_fat_macho(head)


def is_upx_packed(data: bytes) -> bool:
    """True when ``data`` is a UPX-packed ELF / PE / Mach-O (the ``UPX!`` marker in a native image)."""
    if _UPX not in data[:SCAN_WINDOW] and _UPX not in data[-SCAN_WINDOW:]:
        return False
    return _is_native(data)


def is_pyinstaller(data: bytes) -> bool:
    """True when ``data`` is a native executable with a PyInstaller CArchive cookie near its end (the
    archive is validated when it is extracted)."""
    return _is_native(data) and _PYI_COOKIE in data[-(1 << 20):]


# The stream starts packer_unpack decodes, strongest magic first: the two-byte zlib headers also turn
# up by chance in any code section, so they are tried last and test-decoded before a full decode.
_STREAMS = (("ap32", b"AP32"), ("xz", b"\xfd7zXZ\x00"), ("gzip", b"\x1f\x8b\x08"), ("bzip2", b"BZh"),
            ("zlib", b"\x78\x01"), ("zlib", b"\x78\x5e"), ("zlib", b"\x78\x9c"), ("zlib", b"\x78\xda"))


def _starts_a_stream(fmt: str, data: bytes, pos: int) -> bool:
    """A cheap test of the bytes at ``pos``, so a full decode (which copies the rest of the file) is
    tried only where a stream can start: a deflate stream's first CARVE_PROBE_BYTES must inflate
    without an error, and a bzip2 header must be followed by its block magic."""
    if fmt in ("zlib", "gzip"):
        probe = zlib.decompressobj(zlib.MAX_WBITS if fmt == "zlib" else 16 + zlib.MAX_WBITS)
        try:
            probe.decompress(data[pos:pos + CARVE_PROBE_BYTES], 1 << 16)
        except zlib.error:
            return False
    elif fmt == "bzip2":
        return data[pos + 3:pos + 4] in b"123456789" and data[pos + 4:pos + 10] == b"1AY&SY"
    return True


def embedded_images(data: bytes) -> dict:
    """What a native stub carries compressed: ``{"inner-<offset>.<format>": bytes}`` for each zlib /
    gzip / bzip2 / xz stream inside native ``data`` that decodes to a native image, and each ``AP32``
    (aPLib) wrapper that decodes at all.  Every decode is ``packer_unpack``'s -- in memory, capped, and
    accepted only when the stream's own checksum holds -- and nothing is executed.

    Bounds: a file over CARVE_MAX_BYTES is not searched, and the search stops after MAX_CARVE_TRIES
    full decodes (what was found by then is returned).  The last file's answer is kept, so ``sniff``
    and then ``recover`` on the same bytes decode once."""
    if not _is_native(data) or len(data) > CARVE_MAX_BYTES:
        return {}
    key = hashlib.sha256(data).digest()
    if _CARVED[0] != key:
        _CARVED[:] = [key, _carve(data)]
    return dict(_CARVED[1])


_CARVED: list = [None, {}]            # [sha256 of the last file searched, what embedded_images found in it]


def _carve(data: bytes) -> dict:
    pu = load_packer()
    out: dict = {}
    tries = 0
    for fmt, magic in _STREAMS:
        pos = data.find(magic)
        while pos >= 0:
            if _starts_a_stream(fmt, data, pos):
                if tries >= MAX_CARVE_TRIES:
                    return out
                tries += 1
                try:
                    body = pu.decompress_carved(data, pu.CarvedStream(pos, fmt, 0, "stream magic"),
                                                max_output=CARVE_MAX_OUTPUT).data
                except pu.UnpackError:
                    body = None
                if body is not None and (fmt == "ap32" or _is_native(body)):
                    out[f"inner-{pos:#x}.{fmt}"] = body
            pos = data.find(magic, pos + 1)
    return out


def sniff(data: bytes) -> str | None:
    """The recovery kind of ``data`` -- ``"pyc"``, ``"jvm_class"``, ``"jvm_jar"``, ``"pyinstaller"``,
    ``"upx"``, ``"stub"`` -- or None when this engine does not recover the file.

    A PyInstaller executable is tested before UPX: its archive may hold UPX-compressed libraries, and
    the Python scripts are the payload.  ``"stub"`` (a native file with a compressed inner image, see
    ``embedded_images``) is tested last: it is the only kind found by decoding, not by a marker."""
    if is_pyc(data):
        return "pyc"
    if is_java_class(data):
        return "jvm_class"
    if is_jar(data):
        return "jvm_jar"
    if is_pyinstaller(data):
        return "pyinstaller"
    if is_upx_packed(data):
        return "upx"
    if embedded_images(data):
        return "stub"
    return None


def _plausible(head: bytes) -> bool:
    """A cheap first-bytes test: only a file that passes has its body read and sniffed."""
    return is_pyc(head) or head[:4] == _JAVA_CLASS or head[:2] == _ZIP or _is_native(head)


# ----------------------------------------------------------------------------- collaborators
# The sandbox client is loaded by path from the tools/ folder beside solvers/ (the same seam
# solvers/binary/facts.py uses), so the engine imports without a hard dependency on tools/ and a test
# can inject a fake by setting ``sandbox_recover._SANDBOX``.  The PyInstaller archive reader and the
# native decompiler are sibling engines, loaded by path the same way (``_PYI`` / ``_DECOMPILE``), as is
# the in-memory stream decoder ``packer_unpack`` (``_PACKER``).
SANDBOX_CLIENT = Path(__file__).resolve().parents[2] / "tools" / "sandbox.py"
PYI_EXTRACT = Path(__file__).resolve().with_name("pyinstaller_extract.py")
DECOMPILE_INTAKE = Path(__file__).resolve().with_name("decompile_intake.py")
PACKER_UNPACK = Path(__file__).resolve().with_name("packer_unpack.py")
_SANDBOX = None
_PYI = None
_DECOMPILE = None
_PACKER = None


class SandboxUnavailable(RuntimeError):
    """A collaborator module could not be loaded (distinct from the sandbox being down)."""


class NotRecoverable(ValueError):
    """The data is not a kind this engine recovers."""


def _load(path: Path, alias: str):
    """The module at ``path``, loaded under ``alias`` (registered in sys.modules while it runs: a
    module that defines dataclasses needs to find itself there)."""
    try:
        spec = importlib.util.spec_from_file_location(alias, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[alias] = module
        spec.loader.exec_module(module)
    except Exception as e:                                          # noqa: BLE001 - reported, never swallowed
        sys.modules.pop(alias, None)
        raise SandboxUnavailable(f"{path.name} could not be loaded ({type(e).__name__}: {e})") from e
    return module


def load_sandbox():
    """The ``tools/sandbox.py`` module object (loaded once, by path).  SandboxUnavailable on failure."""
    global _SANDBOX
    if _SANDBOX is None:
        _SANDBOX = _load(SANDBOX_CLIENT, "ctf_sandbox_recover_client")
    return _SANDBOX


def load_pyinstaller():
    """The sibling ``pyinstaller_extract`` module (a pure-Python, bounded CArchive reader)."""
    global _PYI
    if _PYI is None:
        _PYI = _load(PYI_EXTRACT, "ctf_sandbox_recover_pyi")
    return _PYI


def load_decompiler():
    """``decompile_intake.decompile_file`` (B-011): the native decompile of one executable."""
    global _DECOMPILE
    if _DECOMPILE is None:
        _DECOMPILE = _load(DECOMPILE_INTAKE, "ctf_sandbox_recover_decompile").decompile_file
    return _DECOMPILE


def load_packer():
    """The sibling ``packer_unpack`` module (bounded, pure-Python aPLib / zlib / gzip / bzip2 / xz)."""
    global _PACKER
    if _PACKER is None:
        _PACKER = _load(PACKER_UNPACK, "ctf_sandbox_recover_packer")
    return _PACKER


# ----------------------------------------------------------------------------- recovery result
@dataclass(frozen=True)
class Recovery:
    """One file's recovery.  ``outputs`` maps an output name (source file / unpacked image) to its
    bytes; ``tool`` is the sandbox tool that produced it; ``ok`` means code was recovered; ``partial``
    (with ``ok``) means it is incomplete -- a decompiler stopped part-way, or only a disassembly came
    out; ``blocked`` means the sandbox was down for every tool tried (a loud, named failure, never a
    silent empty).  A blocked PyInstaller recovery still carries the ``.pyc`` files it extracted."""
    kind: str
    tool: str = ""
    outputs: dict = field(default_factory=dict)
    ok: bool = False
    blocked: bool = False
    note: str = ""
    partial: bool = False

    @property
    def text(self) -> str:
        """All recovered outputs decoded for the flag scan (bytes that do not decode are replaced)."""
        return "\n".join(b.decode("utf-8", "replace") for b in self.outputs.values())


_COMMENT_STARTS = ("#", "//", "/*", "*")      # a block comment's body lines start with `*` (CFR's banner)


def _has_code(text: str) -> bool:
    """True when ``text`` has a line that is not blank and not a comment -- a decompiler produced
    real source, not only a ``# could not decompile`` or ``/* Decompiled with CFR */`` banner."""
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith(_COMMENT_STARTS):
            return True
    return False


# What a decompiler prints when it gave up part-way while still exiting 0 and printing some source.
_INCOMPLETE = (b"Decompyle incomplete", b"Unsupported opcode",                 # pycdc (stdout / stderr)
               b"Parse error at or near", b"Deparsing stopped",                # decompyle3
               b"This method has failed to decompile", b"Exception decompiling")   # CFR


def _java_members(files: dict) -> dict:
    """The ``.java`` members of a sandbox ``Result.files`` dict, bounded to MAX_OUTPUT_FILES.  When a
    decompiler wrote no loose ``.java`` but a source archive (Vineflower saves a jar's sources as a
    jar), the ``.java`` entries of that archive are read instead, each and all of them bounded."""
    out = {}
    for name in sorted(files):
        if name.endswith(".java"):
            out[name] = files[name]
            if len(out) >= MAX_OUTPUT_FILES:
                return out
    if out:
        return out
    total = 0
    for name in sorted(files):
        if not name.endswith((".jar", ".zip")):
            continue
        try:
            zf = zipfile.ZipFile(io.BytesIO(files[name]))
        except (zipfile.BadZipFile, ValueError, OSError, EOFError, struct.error, NotImplementedError):
            continue
        with zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.endswith(".java"):
                    continue
                try:
                    with zf.open(info) as fh:
                        body = fh.read(MAX_MEMBER_BYTES + 1)
                except (zipfile.BadZipFile, ValueError, OSError, EOFError, RuntimeError, NotImplementedError):
                    continue
                if len(body) > MAX_MEMBER_BYTES or total + len(body) > MAX_OUTPUT_BYTES:
                    continue
                total += len(body)
                out[info.filename] = body
                if len(out) >= MAX_OUTPUT_FILES:
                    return out
    return out


# ----------------------------------------------------------------------------- time budget
def _tool_time(timeout: float, left):
    """The seconds one tool run may take: ``timeout``, cut to what is left of the caller's budget
    (``left()``); None when less than MIN_TOOL_SECONDS is left, so the tool is not started."""
    if left is None:
        return timeout
    remaining = left()
    if remaining < MIN_TOOL_SECONDS:
        return None
    return min(timeout, remaining)


def _chain_time(left):
    """The seconds ONE pass of the native decompile of an unpacked image may take, or None when the
    budget cannot hold the chain.  ``decompile_file`` takes a per-pass timeout: its r2 backend runs
    DECOMPILE_PASSES processes with it, after a plugin probe of up to DECOMPILE_PROBE seconds, so the
    chain can take ``DECOMPILE_PASSES * t + DECOMPILE_PROBE`` and ``t`` is cut to fit what is left."""
    return _tool_time(DECOMPILE_TIMEOUT, lambda: (left() - DECOMPILE_PROBE) / DECOMPILE_PASSES)


_SPENT = "not run: the time budget is spent"

# ----------------------------------------------------------------------------- down notes
BUILD_HINT = "build docker/sandbox/Dockerfile.2 (tools/sandbox.py build) and tools/sandbox.py start"
GUARD_HINT = ("the Docker socket is denied to this process: on macOS intake's OS network guard "
              "(sandbox-exec, deny network*) keeps a guarded engine from Docker. Run this engine outside "
              "the guard: python -m ctf run binary.sandbox_recover <challenge_dir>")


def guard_denied(reason: str) -> bool:
    """True when a sandbox-down reason is the Docker socket being refused to this process (what the
    docker CLI prints under a deny-network sandbox), not a daemon or image that is missing."""
    low = reason.lower()
    return "docker" in low and ("permission denied" in low or "operation not permitted" in low)


def _down_note(downs) -> str:
    """One blocked note from the ``"<tool>: <reason>"`` lines of the tools that could not run: tools
    that share a reason are named together, and the hint says what to do about it."""
    by_reason: dict[str, list[str]] = {}
    for line in downs:
        tool, _, reason = line.partition(": ")
        by_reason.setdefault(reason, []).append(tool)
    joined = "; ".join(f"{', '.join(tools)}: {reason}" for reason, tools in by_reason.items())
    return f"sandbox down: {joined} ({GUARD_HINT if guard_denied(joined) else BUILD_HINT})"


# ----------------------------------------------------------------------------- per-tool runners
# Each runner returns (outputs, note, state) with state "ok" | "partial" | "failed"; it raises the
# sandbox's own SandboxDown when the sandbox cannot run the tool (not started / image not built / tool
# missing), which the adapter turns into a blocked Recovery.

def _why(r) -> str:
    lines = (r.stderr or r.stdout or b"").decode("utf-8", "replace").strip().splitlines()
    return lines[-1][:160] if lines else (getattr(r, "note", "") or f"exit {r.code}")


def _run_stdout_decompiler(sb, tool: str, inname: str, data: bytes, outname: str, timeout: float,
                           start: bool = True):
    """A decompiler that prints source to stdout (pycdc, decompyle3, cfr on a single class).

    Clean source needs exit 0 and no give-up marker; source with a non-zero exit or a marker
    (pycdc's ``# WARNING: Decompyle incomplete`` / ``Unsupported opcode``) is ``partial``."""
    r = sb.run(tool, ["{in}"], inputs=[(inname, data)], timeout=timeout, start=start)
    if r.timed_out:
        return {}, f"{tool} timed out after {timeout:g}s in the sandbox", "failed"
    src = r.stdout or b""
    if not _has_code(src.decode("utf-8", "replace")):
        return {}, f"{tool} produced no source in the sandbox ({_why(r)})", "failed"
    marks = [m.decode() for m in _INCOMPLETE if m in src or m in (r.stderr or b"")]
    if r.code == 0 and not marks:
        return {outname: src}, "", "ok"
    return {outname: src}, f"{tool} output is incomplete ({marks[0] if marks else f'exit {r.code}'})", "partial"


def _run_dir_decompiler(sb, tool: str, inname: str, data: bytes, args, timeout: float, start: bool = True):
    """A decompiler that writes ``.java`` files into the call's out folder (cfr --outputpath, vineflower)."""
    r = sb.run(tool, args, inputs=[(inname, data)], timeout=timeout, start=start)
    if r.timed_out:
        return {}, f"{tool} timed out after {timeout:g}s in the sandbox", "failed"
    members = _java_members(r.files)
    if members:
        return members, "", "ok"
    return {}, f"{tool} produced no .java in the sandbox ({_why(r)})", "failed"


# ----------------------------------------------------------------------------- adapters
def recover_python(data: bytes, *, name: str = "module", timeout: float = PY_TIMEOUT,
                   start: bool = True, left=None) -> Recovery:
    """Recover a ``.pyc`` / ``.pyo`` to source in the sandbox: ``pycdc`` first, ``decompyle3`` next.

    When neither gives clean source, the first partial source is kept and the ``pycdas`` disassembly
    is added as the last resort; the Recovery is then ``partial``."""
    sb = load_sandbox()
    outname = f"{name}.py"
    downs, fails, partial = [], [], None
    for tool in ("pycdc", "decompyle3"):
        t = _tool_time(timeout, left)
        if t is None:
            fails.append(f"{tool} {_SPENT}")
            continue
        try:
            outputs, note, state = _run_stdout_decompiler(sb, tool, "input.pyc", data, outname, t, start)
        except sb.SandboxDown as e:
            downs.append(f"{tool}: {e}")
            continue
        except ValueError as e:                       # the sandbox client refused the call (not its tool)
            fails.append(f"{tool} was refused by the sandbox client ({e})")
            continue
        if state == "ok":
            return Recovery("pyc", tool, outputs, ok=True)
        if state == "partial" and partial is None:
            partial = (tool, outputs)
        fails.append(note)

    kept, tools = {}, []
    if partial:
        tools.append(partial[0])
        kept.update(partial[1])
    t = _tool_time(min(timeout, DISASM_TIMEOUT), left)
    if t is None:
        fails.append(f"pycdas {_SPENT}")
    else:
        try:
            r = sb.run("pycdas", ["{in}"], inputs=[("input.pyc", data)], timeout=t, start=start)
        except sb.SandboxDown as e:
            downs.append(f"pycdas: {e}")
        except ValueError as e:
            fails.append(f"pycdas was refused by the sandbox client ({e})")
        else:
            if r.code == 0 and not r.timed_out and (r.stdout or b"").strip():
                kept[f"{name}.pycdas.txt"] = r.stdout
                tools.append("pycdas")
            else:
                fails.append(f"pycdas produced no disassembly in the sandbox ({_why(r)})")
    if kept:
        return Recovery("pyc", "+".join(tools), kept, ok=True, partial=True,
                        note="no clean source: " + "; ".join(fails + downs))
    if downs and not fails:
        return Recovery("pyc", blocked=True, note=_down_note(downs))
    return Recovery("pyc", note="; ".join(fails + downs) or "no Python decompiler ran")


def recover_jvm(data: bytes, *, name: str = "Main", timeout: float = JVM_TIMEOUT,
                start: bool = True, left=None, kind: str | None = None) -> Recovery:
    """Recover a Java ``.class`` (to one source) or a ``.jar`` / ``.war`` (to a ``.java`` tree) in the
    sandbox: ``cfr`` first, ``vineflower`` next.  A partial ``cfr`` source (a method it could not
    decompile) is kept only when ``vineflower`` gives nothing cleaner."""
    sb = load_sandbox()
    kind = kind or ("jvm_jar" if is_jar(data) else "jvm_class")
    inname = "input.jar" if kind == "jvm_jar" else f"{name}.class"
    downs, fails, partial = [], [], None
    for tool in ("cfr", "vineflower"):
        t = _tool_time(timeout, left)
        if t is None:
            fails.append(f"{tool} {_SPENT}")
            continue
        try:
            if kind == "jvm_jar":
                args = (["{in}", "--outputpath", "{out}"] if tool == "cfr" else ["{in}", "{out}"])
                outputs, note, state = _run_dir_decompiler(sb, tool, inname, data, args, t, start)
            elif tool == "cfr":
                outputs, note, state = _run_stdout_decompiler(sb, tool, inname, data, f"{name}.java", t, start)
            else:   # vineflower has no stdout mode; it writes <Class>.java into the out folder
                outputs, note, state = _run_dir_decompiler(sb, tool, inname, data, ["{in}", "{out}"], t, start)
        except sb.SandboxDown as e:
            downs.append(f"{tool}: {e}")
            continue
        except ValueError as e:
            fails.append(f"{tool} was refused by the sandbox client ({e})")
            continue
        if state == "ok":
            return Recovery(kind, tool, outputs, ok=True)
        if state == "partial" and partial is None:
            partial = (tool, outputs)
        fails.append(note)
    if partial:
        return Recovery(kind, partial[0], partial[1], ok=True, partial=True,
                        note="no clean source: " + "; ".join(fails + downs))
    if downs and not fails:
        return Recovery(kind, blocked=True, note=_down_note(downs))
    return Recovery(kind, note="; ".join(fails + downs) or "no JVM decompiler ran")


def unpack_upx(data: bytes, *, name: str = "unpacked", timeout: float = UPX_TIMEOUT,
               start: bool = True, left=None) -> Recovery:
    """Unpack a UPX-packed executable with ``upx -d`` in the sandbox (``tools/sandbox.upx_unpack``)."""
    sb = load_sandbox()
    t = _tool_time(timeout, left)
    if t is None:
        return Recovery("upx", note=f"upx {_SPENT}")
    out, note = sb.upx_unpack(data, t, start=start)
    if out is not None:
        return Recovery("upx", "upx", {name: out}, ok=True, note=note)
    if note.startswith("sandbox down"):
        return Recovery("upx", blocked=True,
                        note=f"{note} ({GUARD_HINT if guard_denied(note) else BUILD_HINT})")
    return Recovery("upx", note=note)


def unpack_embedded(data: bytes, *, name: str = "stub") -> Recovery:
    """Unpack the compressed inner image(s) of a native stub in memory (``embedded_images``).  No
    sandbox is involved: the decoders are bounded pure Python and nothing is run."""
    images = embedded_images(data)
    if images:
        return Recovery("stub", "packer_unpack", images, ok=True)
    return Recovery("stub", note=f"no compressed native image or AP32 payload decodes inside {name}")


# PyInstaller's own bootstrap / runtime-hook scripts: in every archive, never the challenge logic.
_PYI_RUNTIME = re.compile(r"^(pyiboot\d+_|pyi_rth_?)")


def _pyi_magic(cookie, entries) -> bytes | None:
    """The 4-byte pyc magic of a PyInstaller archive: the one its PYZ member records (``PYZ\\0`` +
    magic), else the word of the CPython release the cookie names; None when neither is known."""
    for e in entries:
        if e.typecode == "z" and e.data[:4] == b"PYZ\x00" and pyc_magic_word(e.data[4:8]) is not None:
            return e.data[4:8]
    word = _PYC_MAGIC_BY_VERSION.get(cookie.python_version)
    return None if word is None else word.to_bytes(2, "little") + _PYC_TAIL


def pyc_from_code(body: bytes, magic: bytes) -> bytes:
    """``body`` (a marshalled code object, as PyInstaller stores a script) as a ``.pyc``: unchanged
    when it already starts with a pyc header, else behind a zeroed header of the size the magic's
    CPython release reads (16 bytes from 3.7, 12 from 3.3, 8 before).  Nothing is unmarshalled."""
    if is_pyc(body):
        return body
    word = int.from_bytes(magic[:2], "little")
    pad = 12 if word in _PYC_MAGIC_3X and word >= 3390 else 8 if word in _PYC_MAGIC_3X and word >= 3230 else 4
    return magic + b"\x00" * pad + body


def recover_pyinstaller(data: bytes, *, name: str = "app", timeout: float = PY_TIMEOUT,
                        start: bool = True, left=None) -> Recovery:
    """Recover the scripts of a PyInstaller executable: read its CArchive in this process (as data,
    by ``pyinstaller_extract``), turn each script entry into a ``.pyc``, and decompile each in the
    sandbox as ``recover_python`` does.  The ``.pyc`` files are kept in the outputs either way, so a
    down sandbox still leaves them on disk (the Recovery is then ``blocked``).  Modules inside the
    archive's PYZ member are not read: its table of contents is a marshalled object."""
    pyi = load_pyinstaller()
    try:
        cookie, entries = pyi.extract_carchive(data)
    except pyi.PyInstallerError as e:
        return Recovery("pyinstaller", note=f"the PyInstaller archive of {name} could not be read ({e})")
    scripts = [e for e in entries if e.typecode == "s" and not _PYI_RUNTIME.match(e.name)]
    if not scripts:
        return Recovery("pyinstaller", note=f"the PyInstaller archive of {name} holds no script entry "
                                            f"({len(entries)} entries)")
    magic = _pyi_magic(cookie, entries)
    if magic is None:
        return Recovery("pyinstaller", note=f"the PyInstaller archive of {name} is for Python "
                                            f"{cookie.python_version} and has no PYZ member: its pyc magic "
                                            "is not known, so its scripts were not rebuilt")
    outputs, tools, notes = {}, [], []
    n_ok = n_blocked = n_partial = 0
    for e in scripts[:MAX_PYI_SCRIPTS]:
        stem = e.name.rsplit("/", 1)[-1] or "script"
        pyc = pyc_from_code(e.data, magic)
        outputs[f"{stem}.pyc"] = pyc
        rec = recover_python(pyc, name=stem, timeout=timeout, start=start, left=left)
        if rec.ok:
            n_ok += 1
            n_partial += rec.partial
            outputs.update(rec.outputs)
            for tool in rec.tool.split("+"):
                if tool not in tools:
                    tools.append(tool)
        elif rec.blocked:
            n_blocked += 1
        if rec.note:
            notes.append(f"{e.name}: {rec.note}")
    if len(scripts) > MAX_PYI_SCRIPTS:
        notes.append(f"{len(scripts) - MAX_PYI_SCRIPTS} more script entries not recovered "
                     f"(over MAX_PYI_SCRIPTS={MAX_PYI_SCRIPTS})")
    tool = "+".join(["pyinstaller_extract", *tools])
    note = "; ".join(notes)
    done = min(len(scripts), MAX_PYI_SCRIPTS)
    if n_ok:
        return Recovery("pyinstaller", tool, outputs, ok=True, note=note,
                        partial=bool(n_partial or n_ok < done or len(scripts) > MAX_PYI_SCRIPTS))
    if n_blocked == done:
        return Recovery("pyinstaller", tool, outputs, blocked=True, note=note)
    return Recovery("pyinstaller", tool, outputs, note=note)


def recover(data: bytes, *, name: str = "artifact", timeout: float | None = None, start: bool = True,
            left=None, kind: str | None = None) -> Recovery:
    """Route ``data`` to the fitting adapter by ``kind`` (sniffed when not given).  ``timeout`` is one
    tool run's limit (each kind has its own default).  NotRecoverable (a ValueError) when it is not a
    kind this engine handles."""
    kind = kind or sniff(data)
    if kind == "pyc":
        return recover_python(data, name=name, timeout=timeout or PY_TIMEOUT, start=start, left=left)
    if kind in ("jvm_class", "jvm_jar"):
        return recover_jvm(data, name=name, timeout=timeout or JVM_TIMEOUT, start=start, left=left, kind=kind)
    if kind == "pyinstaller":
        return recover_pyinstaller(data, name=name, timeout=timeout or PY_TIMEOUT, start=start, left=left)
    if kind == "upx":
        return unpack_upx(data, name=name, timeout=timeout or UPX_TIMEOUT, start=start, left=left)
    if kind == "stub":
        return unpack_embedded(data, name=name)
    raise NotRecoverable(f"{name} is not a .pyc, Java .class/.jar, PyInstaller or UPX-packed executable, "
                         "or a native stub with a compressed inner image")


# ----------------------------------------------------------------------------- intake engine
_SKIP_DIRS = {"recon", "unpacked"}     # intake's own output under the challenge folder (as decompile_intake)


def _safe(name: str) -> str:
    """One traversal-free path component."""
    clean = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:120]
    return clean if clean.strip(".") else "file"


def _folder(rel: str) -> str:
    """The output folder name of one handout file: its flattened relative path plus a short hash of
    the exact path, so ``a/b.pyc`` and ``a__b.pyc`` never share a folder."""
    flat = _safe(rel.replace("/", "__").replace("\\", "__"))
    return f"{flat}-{hashlib.sha256(rel.encode('utf-8', 'surrogateescape')).hexdigest()[:8]}"


def _member_path(oname: str) -> Path:
    """An output name (``a/A.java``) as a relative path with each component made safe; ``..``, ``.``
    and empty components are dropped, so it cannot leave the output folder."""
    parts = [_safe(p) for p in re.split(r"[\\/]+", oname) if p not in ("", ".", "..")]
    return Path(*parts[-16:]) if parts else Path("file")


@dataclass
class Scan:
    """What the handout walk left out, filled while ``_scan`` runs."""
    skipped: list = field(default_factory=list)       # "<rel>: <why>" -- over the size cap or unreadable
    overflow: int = 0                                 # plausible files not read (over MAX_FILES)
    duplicates: list = field(default_factory=list)    # rel paths whose bytes equal an earlier file's
    unreached: list = field(default_factory=list)     # plausible files not read: the time budget was spent
    unsearched: list = field(default_factory=list)    # native files over CARVE_MAX_BYTES: no inner-image search


def _scan(challenge_dir: Path, report: Scan, spent=lambda: False):
    """Yield ``(path, rel, data, kind)`` for each handout file this engine recovers, one body in memory
    at a time: ``files/`` and the folder root, without intake's own ``recon/`` and ``unpacked/`` output
    (the sweep's unpacked copy of a jar is the same classes again).  Only a file whose first bytes are
    plausible is read; a body identical to an earlier one is not yielded twice; at most MAX_FILES are
    yielded; once ``spent()`` is true no further body is read.  What is left out is recorded in
    ``report``."""
    seen_paths: set[Path] = set()
    seen_bodies: set[str] = set()
    yielded = 0
    for root in (challenge_dir / "files", challenge_dir):
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            dirnames[:] = sorted(d for d in dirnames
                                 if not (here == challenge_dir and d in _SKIP_DIRS)
                                 and not (here / d).is_symlink())
            for n in sorted(filenames):
                f = here / n
                if f.is_symlink() or not f.is_file():
                    continue
                rel = str(f.relative_to(challenge_dir))
                try:
                    real = f.resolve()
                    if real in seen_paths:
                        continue
                    seen_paths.add(real)
                    size = f.stat().st_size
                    with open(f, "rb") as fh:
                        head = fh.read(HEAD_BYTES)
                except OSError as e:
                    report.skipped.append(f"{rel}: could not be read ({type(e).__name__})")
                    continue
                if not _plausible(head):
                    continue
                if size > MAX_FILE_BYTES:
                    report.skipped.append(f"{rel}: {size} bytes is over the {MAX_FILE_BYTES} byte cap")
                    continue
                if yielded >= MAX_FILES:
                    report.overflow += 1
                    continue
                if spent():
                    report.unreached.append(rel)
                    continue
                try:
                    data = f.read_bytes()
                except OSError as e:
                    report.skipped.append(f"{rel}: could not be read ({type(e).__name__})")
                    continue
                kind = sniff(data)
                if kind is None:
                    if _is_native(data) and len(data) > CARVE_MAX_BYTES:
                        report.unsearched.append(rel)
                    continue
                digest = hashlib.sha256(data).hexdigest()
                if digest in seen_bodies:
                    report.duplicates.append(rel)
                    continue
                seen_bodies.add(digest)
                yielded += 1
                yield f, rel, data, kind


def solve(challenge_dir, profile, *, timeout: float | None = None, budget: float = OVERALL_BUDGET,
          clock=time.monotonic, **_opts):
    """Recover every ``.pyc`` / Java ``.class`` / ``.jar`` / PyInstaller executable and unpack every
    UPX-packed executable in the handout, in the sandbox, into ``recon/recover/`` -- then report.  A
    native stub's compressed inner image is unpacked in memory (``embedded_images``) the same way.

    ``candidate`` when a recovered source or unpacked image holds the event flag format; ``blocked``
    when there was work but the sandbox was down for all of it (notes name the step to take);
    ``none`` only when nothing needed recovering, or everything recovered cleanly with no flag;
    ``unsure`` otherwise -- a partial or failed recovery, or a file left out (too large, unreadable,
    over MAX_FILES, past the time budget), each named in the notes.

    The whole call holds to ``budget`` seconds (``clock`` is injectable): a tool is given at most what
    is left, and files reached after it is spent are named as not examined.  A container is never
    started from here (``start=False``): a sandbox that is not already up is ``blocked``."""
    from ctf.result import SolverResult, Evidence
    from ctf import flagfmt

    challenge_dir = Path(challenge_dir)
    ff = flagfmt.for_profile(profile)
    deadline = clock() + budget

    def left() -> float:
        return deadline - clock()

    base = challenge_dir / "recon" / "recover"
    report = Scan()
    evidence: list[Evidence] = []
    flags: list[str] = []
    recovered, partial, failed, blocked, undecompiled = [], [], [], [], []

    def scan_flags(text: str) -> None:
        for fl in ff.find_flags(text):
            if fl not in flags:
                flags.append(fl)

    for path, rel, data, kind in _scan(challenge_dir, report, spent=lambda: left() < MIN_TOOL_SECONDS):
        outdir = base / _folder(rel)
        try:
            rec = recover(data, name=path.stem or "artifact", timeout=timeout, start=False, left=left,
                          kind=kind)
        except SandboxUnavailable as e:
            blocked.append(f"{rel}: {e}")
            continue

        written = {}
        for oname, body in rec.outputs.items():
            dest = outdir / _member_path(oname)
            n = 1
            while dest in written.values():           # two output names that sanitize to one path
                dest = dest.with_name(f"{dest.stem}.{n}{dest.suffix}")
                n += 1
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(body)
            written[oname] = dest
            unpacked = rec.kind in ("upx", "stub") or oname.endswith(".pyc")
            evidence.append(Evidence(kind="unpack" if unpacked else "decompile",
                                     detail=f"{rec.tool} {'unpacked' if unpacked else 'recovered'} "
                                            f"{oname} of {rel}",
                                     path=str(dest.relative_to(challenge_dir))))
        scan_flags(rec.text)

        if rec.blocked:
            blocked.append(f"{rel}: {rec.note}")
            continue
        if not rec.ok:
            failed.append(f"{rel}: {rec.note}")
            continue
        desc = f"{rel} ({rec.kind} by {rec.tool})"
        if rec.partial:
            partial.append(f"{desc}: {rec.note}")
        else:
            recovered.append(desc)

        if rec.kind in ("upx", "stub"):
            # The unpacked image is the real program: hand it to the native decompiler (B-011), which
            # skips recon/ on its own walk and so would only ever see the packed stub.  An AP32 payload
            # that is not an executable (shellcode, data) is kept and flag-scanned, not decompiled.
            for oname, dest in written.items():
                if not _is_native(rec.outputs[oname]):
                    continue
                t = _chain_time(left)
                if t is None:
                    undecompiled.append(f"{rel}: the unpacked image was not decompiled (time budget spent)")
                    continue
                try:
                    d = load_decompiler()(dest, challenge_dir / "recon" / "decompile" / _folder(rel),
                                          timeout=t, challenge_dir=challenge_dir)
                except SandboxUnavailable as e:
                    undecompiled.append(f"{rel}: the unpacked image was not decompiled ({e})")
                    continue
                if not d.ok:
                    undecompiled.append(f"{rel}: the unpacked image was not decompiled ({d.note})")
                    continue
                for label, wrote in d.functions.items():
                    evidence.append(Evidence(kind="decompile",
                                             detail=f"{d.backend} decompiled {label} of the unpacked {rel}",
                                             path=wrote))
                scan_flags(d.pseudocode)

    notes = []
    if blocked:
        notes.append("sandbox down for: " + "; ".join(blocked))
    if failed:
        notes.append("could not recover: " + "; ".join(failed))
    if partial:
        notes.append("recovered in part: " + "; ".join(partial))
    if undecompiled:
        notes.append("; ".join(undecompiled))
    if report.skipped:
        notes.append("left out: " + "; ".join(report.skipped))
    if report.unreached:
        notes.append(f"not examined, the {budget:g} s time budget was spent: " + ", ".join(report.unreached))
    if report.overflow:
        notes.append(f"{report.overflow} more file(s) not examined (over MAX_FILES={MAX_FILES})")
    if report.duplicates:
        notes.append("same bytes as a file already recovered: " + ", ".join(report.duplicates))
    if report.unsearched:
        notes.append(f"not searched for a compressed inner image (over the {CARVE_MAX_BYTES} byte cap): "
                     + ", ".join(report.unsearched))
    note = ". ".join(notes)
    engine = "binary.sandbox_recover"
    incomplete = bool(blocked or failed or partial or undecompiled or report.skipped or report.unreached
                      or report.overflow)

    if flags:
        return SolverResult(status="candidate", flags=tuple(flags), evidence=tuple(evidence), engine=engine,
                            notes=("flag-format string(s) in recovered source / unpacked image "
                                   "(static, unverified). " + note).strip())
    if recovered and not incomplete:
        return SolverResult(status="none", evidence=tuple(evidence), engine=engine,
                            notes=("recovered " + ", ".join(recovered) + " to recon/recover/"
                                   + (". " + note if note else "")))
    if recovered or partial:
        return SolverResult(status="unsure", evidence=tuple(evidence), engine=engine,
                            notes=(("recovered " + ", ".join(recovered) + ". " if recovered else "") + note))
    if blocked and not failed:
        # recoverable input, but the sandbox was down for every file: a loud, named blocked.
        return SolverResult(status="blocked", evidence=tuple(evidence), engine=engine,
                            notes="no recovery ran; the sandbox is down. " + note)
    if incomplete:
        # a tool ran and recovered nothing, or a file was left out: not a clean "none".
        return SolverResult(status="unsure", evidence=tuple(evidence), engine=engine,
                            notes="recovered nothing. " + note)
    return SolverResult(status="none", evidence=tuple(evidence), engine=engine,
                        notes=("no .pyc / Java .class/.jar / PyInstaller or UPX-packed executable and no native "
                               "stub with a compressed inner image in the handout" + (". " + note if note else "")))
