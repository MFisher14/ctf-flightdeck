#!/usr/bin/env python3
"""Runtime facts of a binary sample, found by magic or regex over the whole file.

Usage:
  python3 solvers/binary/facts.py <sample> [...]

A new day's sample usually brings one question about its runtime (the Go version, the CLI
metadata version, ...). This module does not answer such a question. It prints what the
file says about itself, so the lane owner can see the fact and write fields_dNN.py for it:

  go_version, go_path, go_module, go_settings   the `\\xff Go buildinf:` blob (Go 1.18+)
  rustc_version, rustc_commit, rustc_date       `rustc version X (hash date)` and the
                                                `/rustc/<commit>/` prefix of panic paths
  compiler                                      the strings a toolchain leaves in .comment:
                                                `GCC: (...) X`, `clang version X`, `Linker: X`
  dotnet_metadata_version, dotnet_target        the BSJB metadata root and the target
                                                framework attribute
  pyinstaller_cookie, pyinstaller_python,       the CArchive cookie (`MEI\\014\\013\\012\\013\\016`)
  pyinstaller_pylib, pyinstaller_markers        and bootloader strings
  python_markers                                names of an embedded CPython (libpython3.11.so,
                                                python311.dll, Py_Initialize)
  packer                                        a UPX signature
  class_major, class_minor, java_release,       a Java class file (CAFEBABE, major 45 or more), or the
  class_name                                    main class of a jar (else its first class): the
                                                class-file version and the class's own name
  jar_main_class, jar_created_by, jar_build_jdk the jar's META-INF/MANIFEST.MF (Main-Class as written,
                                                dotted; continuation lines joined)
  kotlin_metadata_version, kotlin_kind,         the class's @kotlin.Metadata annotation (mv, k), and
  kotlin_modules                                the jar's META-INF/*.kotlin_module names
  dex_version                                   a DEX file's header version (`035`), also the
                                                classes.dex of an APK
  wasm_version                                  a WebAssembly module's version word
  macho_bits, macho_cputype, macho_cpusubtype,  a thin Mach-O's mach_header (the first architecture of
  macho_filetype, macho_ncmds,                  a fat file, whose CPU types are in macho_fat_cputypes)
  macho_sizeofcmds, macho_flags
  dotnet_bundle_version, dotnet_bundle_id,      a .NET single-file bundle's manifest (dotnet_bundle: the
  dotnet_bundle_files, dotnet_bundle_compressed, apphost's bundle signature and the header it points at)
  dotnet_bundle_assemblies
  asar_files                                    an Electron asar archive's top-level names (asar_header)
  ar_members                                    an ar archive's members: a static library, a Go c-archive
  toolchain_markers                             runtime strings of Nim, Zig, Crystal, D, GHC, Swift, a .NET
                                                apphost or a Go plugin (ELF, PE, Mach-O or ar files only)

The class-file reader (parse_class, jvm_arrays) is also what generic.py reads a class's byte[] and
int[] initialisers and its split String constants with (backlog row 61). solvers/binary/
fields_template.py turns these facts into unsure answers for a lane owner's fields_dNN.py.
  unpacked                                      what `upx -d` made of a copy of a UPX-packed executable
                                                (in the sandbox, tools/sandbox.py, off the timed path);
                                                the facts of the unpacked image are added where the
                                                packed one hides them (unpack_upx)

Nothing here reads a section table: a stripped, repacked or cross-built sample (ELF, PE or
Mach-O) still has the same bytes somewhere. A fact that is not found is left out of the
result; facts() never raises.
"""
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

GO_BUILDINFO = b"\xff Go buildinf:"
# The 16-byte sentinels that open and close the module info inside the build info blob.
GO_MOD_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
GO_MOD_END = bytes.fromhex("f932433186182072008242104116d8f2")
PYI_COOKIE = b"MEI\x0c\x0b\x0a\x0b\x0e"
TEXT = rb"[\x20-\x7e]"
MAX_LIST = 8   # distinct strings kept per list fact


def _uvarint(data: bytes, o: int):
    """(value, next offset) of the varint at data[o]. At most ten bytes, as Go's own reader allows:
    a long run of bytes with the top bit set is not a length, and reading it as one grows an
    integer by seven bits per byte (seconds on 300 KB, minutes on a megabyte)."""
    x = 0
    for shift in range(0, 70, 7):
        c = data[o]
        o += 1
        x |= (c & 0x7F) << shift
        if c < 0x80:
            return x, o
    raise ValueError("a varint longer than ten bytes")


def _distinct(matches) -> list:
    out = []
    for m in matches:
        text = m.decode("utf-8", "replace").strip()
        if text and text not in out:
            out.append(text)
            if len(out) >= MAX_LIST:
                break
    return out


def _go(data: bytes, out: dict):
    """Go 1.18+ stores the toolchain version and the module info inline, each behind a varint length."""
    i = data.find(GO_BUILDINFO)
    if i < 0 or i + 32 > len(data):
        return
    modinfo = b""
    if data[i + 15] & 2:
        try:
            n, o = _uvarint(data, i + 32)
            version = data[o:o + n]
            if re.fullmatch(rb"go\d[\x21-\x7e]{0,40}|devel [\x20-\x7e]{1,80}", version):
                out["go_version"] = version.decode()
            n, o = _uvarint(data, o + n)
            modinfo = data[o:o + n]
        except (IndexError, ValueError):
            modinfo = b""   # a cut or mangled blob: the sentinels and the regex below still apply
    if not modinfo:
        # Older layouts point at the strings; the module info is still plain text between its sentinels.
        a = data.find(GO_MOD_START)
        b = data.find(GO_MOD_END, a + 16) if a >= 0 else -1
        modinfo = data[a:b + 16] if b >= 0 else b""
    if "go_version" not in out:
        # Pointer layout: the version string lives elsewhere in the file. Only read it with a regex
        # because the build info magic already says this is a Go binary.
        m = re.search(rb"go1\.\d+(?:\.\d+|rc\d+|beta\d+)?", data)
        if m:
            out["go_version"] = m.group(0).decode()
    if modinfo.startswith(GO_MOD_START) and modinfo.endswith(GO_MOD_END):
        modinfo = modinfo[16:-16]
    settings = {}
    for line in modinfo.decode("utf-8", "replace").splitlines():
        kind, _, rest = line.partition("\t")
        if kind == "path" and rest:
            out["go_path"] = rest
        elif kind == "mod" and rest:
            out["go_module"] = rest.split("\t")[0]
        elif kind == "build":
            k, _, v = rest.partition("=")
            if k:
                settings[k] = v
    if settings:
        out["go_settings"] = settings


def _rust(data: bytes, out: dict):
    m = re.search(rb"rustc version (\d+\.\d+\.\d+[0-9A-Za-z.+-]*) \(([0-9a-f]{7,40}) (\d{4}-\d{2}-\d{2})\)", data)
    if m:
        out["rustc_version"], out["rustc_commit"], out["rustc_date"] = (g.decode() for g in m.groups())
    # Panic locations carry the full commit: /rustc/<40 hex>/library/core/src/...
    m = re.search(rb"/rustc/([0-9a-f]{40})[/\\]", data)
    if m:
        out["rustc_commit"] = m.group(1).decode()


def _compiler(data: bytes, out: dict):
    """What compilers and linkers write into .comment (ELF) or .rdata$zzz (MinGW), wherever it sits."""
    found = []
    for needle, pattern in ((b"GCC: (", rb"GCC: \([^)\x00]{0,80}\) " + TEXT + rb"{1,60}"),
                            (b"clang version ", rb"(?:[A-Za-z]+ )?clang version " + TEXT + rb"{1,120}"),
                            (b"Linker: ", rb"Linker: " + TEXT + rb"{1,60}")):
        if needle in data:
            found += [(m.start(), m.group(0)) for m in re.finditer(pattern, data)]
    names = _distinct(text for _, text in sorted(found))
    if names:
        out["compiler"] = names


def _dotnet(data: bytes, out: dict):
    """The CLI metadata root: "BSJB", major 1, minor 1, reserved 0, length, version string."""
    at = data.find(b"BSJB")
    while at >= 0:
        if at + 16 <= len(data):
            major, minor, reserved, length = struct.unpack_from("<HHII", data, at + 4)
            raw = data[at + 16:at + 16 + length]
            if (major, minor, reserved) == (1, 1, 0) and 0 < length <= 255 and len(raw) == length:
                version = raw.split(b"\0", 1)[0]
                if version and re.fullmatch(TEXT + rb"+", version):
                    out["dotnet_metadata_version"] = version.decode()
                    break
        at = data.find(b"BSJB", at + 1)
    m = re.search(rb"\.NET(?:CoreApp|Framework|Standard),Version=v[0-9.]+", data)
    if m:
        out["dotnet_target"] = m.group(0).decode()


def _python(data: bytes, out: dict):
    at = data.rfind(PYI_COOKIE)
    if at >= 0:
        out["pyinstaller_cookie"] = f"0x{at:x}"
        if at + 24 + 64 <= len(data):
            # PyInstaller 2.1+: package length, TOC offset, TOC length, Python version, library name.
            _, _, _, pyvers = struct.unpack_from("!iiii", data, at + 8)
            if 20 <= pyvers < 100:
                out["pyinstaller_python"] = f"{pyvers // 10}.{pyvers % 10}"
            elif 300 <= pyvers < 500:
                out["pyinstaller_python"] = f"{pyvers // 100}.{pyvers % 100}"
            lib = data[at + 24:at + 88].split(b"\0", 1)[0]
            if lib and re.fullmatch(TEXT + rb"+", lib):
                out["pyinstaller_pylib"] = lib.decode()
    markers = [m.decode() for m in (b"_MEIPASS2", b"pyi-runtime-tmpdir", b"Cannot open PyInstaller archive",
                                    b"PYINSTALLER_", b"_PYI_ARCHIVE_FILE", b"NUITKA_ONEFILE") if m in data]
    if markers:
        out["pyinstaller_markers"] = markers
    names = []
    if b"python" in data:
        names += re.findall(rb"(?:lib)?python[23](?:\.?\d{1,2})?(?:\.so[0-9.]*|\.dll|\.dylib|\.zip)", data)
    names += [m for m in (b"Py_Initialize", b"PyRun_SimpleString", b"PyMarshal_ReadObjectFromString") if m in data]
    names = _distinct(names)
    if names:
        out["python_markers"] = names


def _packer(data: bytes, out: dict):
    if b"UPX!" in data:
        m = re.search(rb"\$Id: UPX ([0-9.]+)", data)
        out["packer"] = "UPX " + m.group(1).decode() if m else "UPX"


# ---------------------------------------------------------------------------- UPX

UPX_TOOLS = ("/opt/homebrew/bin/upx", "/usr/local/bin/upx")   # looked for first, then PATH
UPX_TIMEOUT = 2.0         # seconds `upx -d` may take on one file
UPX_MAX = 64 << 20        # an unpacked image larger than this is not read
UPX_HEADS = (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce")
_UPX_DONE = {}            # sha256 of the packed bytes -> (unpacked or None, note): one run per file
SANDBOX_CLIENT = Path(__file__).resolve().parents[2] / "tools" / "sandbox.py"   # backlog row 91


def upx_tool():
    """The path of the upx program, or None."""
    for path in UPX_TOOLS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return shutil.which("upx")


def on_timed_path() -> bool:
    """True inside a timed window, where row 74 runs as it was built: this process holds
    judge.clock() (tools/run.py, timed_ladder.py), or it is the replay child of tools/preflight.py,
    whose gate must say what the timed run will do. The sandbox (row 91) is never on that path."""
    judge = sys.modules.get("judge")
    if judge is not None and getattr(judge, "_clock_depth", 0):
        return True
    return Path(sys.argv[0] if sys.argv else "").name == "preflight.py" and sys.argv[1:2] == ["--child"]


def upx_sandboxed(data: bytes, timeout: float):
    """(unpacked bytes or None, note) of `upx -d` in the sandbox (tools/sandbox.upx_unpack). The
    sandbox client is loaded from the tools/ folder beside solvers/ only when a packed file comes."""
    path = SANDBOX_CLIENT
    try:
        spec = importlib.util.spec_from_file_location("huntress_sandbox", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as e:
        return None, f"sandbox down: {path} could not be loaded ({type(e).__name__}): the packed image is not read"
    return module.upx_unpack(data, timeout)


def unpack_upx(data: bytes, timeout: float = UPX_TIMEOUT):
    """(unpacked bytes or None, note) for an executable (ELF, PE, Mach-O) that carries the UPX!
    signature. Off the timed path (on_timed_path) upx runs in the sandbox only (backlog row 91):
    `upx -d` on a copy in the container, and a sandbox that is down gives None and a note that
    starts 'sandbox down'. On the timed path (and the gate replay), as row 74 built it and row 211
    restored it: a copy is written to a fresh temporary folder outside the repository, `upx -d -o`
    writes the unpacked image next to it, and the folder is removed; nothing is run but upx itself,
    which only decompresses. At most `timeout` seconds, once per distinct file."""
    if b"UPX!" not in data or not (data[:4] in UPX_HEADS or data[:2] == b"MZ"):
        return None, "no UPX! signature in an ELF, PE or Mach-O image"
    digest = hashlib.sha256(data).digest()
    if digest in _UPX_DONE:
        return _UPX_DONE[digest]
    if not on_timed_path():
        # Backlog row 91: off the timed path upx runs only in the sandbox (tools/sandbox.py), never
        # here. A sandbox that is down reads as not unpacked, and is asked again next time.
        done = upx_sandboxed(data, timeout)
        if not done[1].startswith("sandbox down"):
            if len(_UPX_DONE) >= 8:
                _UPX_DONE.clear()
            _UPX_DONE[digest] = done
        return done
    # Row 211 (review S1): on the timed path upx IS run natively again, as row 74 built it. Row 164 had
    # returned None here, which left a UPX-packed sample's clocks (and the gate replay, which runs as
    # on_timed_path) with the config fields None -> GATE NO, no fix allowed, the whole timed pair lost.
    # The sandbox is barred from the clock (runbook section 10), so native upx is the only way to read a
    # packed build inside a window. Nothing is run but upx itself, which only decompresses, on a copy in a
    # fresh temporary folder outside the repository, at most `timeout` seconds, once per distinct file.
    tool = upx_tool()
    if tool is None:
        done = None, "upx is not installed (brew install upx): the packed image is not read on the clock"
    else:
        folder = tempfile.mkdtemp(prefix="huntress-upx-")
        try:
            src, dst = os.path.join(folder, "packed"), os.path.join(folder, "unpacked")
            with open(src, "wb") as fh:
                fh.write(data)
            p = subprocess.run([tool, "-d", "-q", "-o", dst, src], stdin=subprocess.DEVNULL, capture_output=True,
                               timeout=timeout)
            size = os.path.getsize(dst) if os.path.isfile(dst) else -1
            if p.returncode != 0 or size <= 0:
                why = (p.stderr or p.stdout).decode("utf-8", "replace").strip().splitlines()
                done = None, f"upx -d failed ({why[-1][:160] if why else f'exit {p.returncode}'})"
            elif size > UPX_MAX:
                done = None, f"upx -d made {size} bytes, more than the {UPX_MAX} read"
            else:
                with open(dst, "rb") as fh:
                    done = fh.read(), f"unpacked by upx -d to {size} bytes"
        except subprocess.TimeoutExpired:
            done = None, f"upx -d took more than {timeout:g} s"
        except OSError as e:
            done = None, f"upx -d could not run ({type(e).__name__}: {e})"
        finally:
            shutil.rmtree(folder, ignore_errors=True)
    if len(_UPX_DONE) >= 8:
        _UPX_DONE.clear()
    _UPX_DONE[digest] = done
    return done


# ---------------------------------------------------------------------------- JVM, DEX, WebAssembly, Mach-O
# Backlog row 52: facts a JVM, Android, WebAssembly or Apple sample states in its own headers. Like
# every fact here they are printed for the lane owner and never answered automatically.

CLASS_MAGIC = b"\xca\xfe\xba\xbe"
ZIP_MAGIC = b"PK\x03\x04"
STUB_MAX = 1 << 16          # how far behind a `#!` line a zip's first entry may start (generic.STUB_MAX)
CLASS_MAX = 8 << 20         # a jar entry larger than this is not read for its class facts
# Bytes of one constant-pool entry after its tag, for every tag but Utf8 (1).
_POOL_SIZE = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4,
              19: 2, 20: 2}


def is_class(blob: bytes) -> bool:
    """A Java class file: CAFEBABE and a class-file major version of 45 or more (a fat Mach-O has
    the count of its architectures in that word, a handful)."""
    return blob[:4] == CLASS_MAGIC and len(blob) >= 10 and struct.unpack_from(">H", blob, 6)[0] >= 45


def mutf8(raw: bytes) -> str:
    """Java's modified UTF-8 (NUL as C0 80, a supplementary character as two 3-byte surrogates)."""
    try:
        return raw.replace(b"\xc0\x80", b"\0").decode("utf-8", "surrogatepass").encode(
            "utf-16", "surrogatepass").decode("utf-16")
    except UnicodeError:
        return raw.decode("utf-8", "replace")


def parse_class(blob: bytes, texts: bool = True) -> dict:
    """The parts of a class file the readers use, from the bytes only (nothing is loaded or run):

      major, minor   the class-file version
      utf8           {pool index: text} of the Utf8 constants
      ints           {pool index: value} of the Integer constants
      strings        [(pool index, text)] of the String constants, in pool order
      this           the class's own name (internal form, a/b/C)
      codes          [code bytes] of every method's Code attribute, in method order
      annotations    the class's RuntimeVisibleAnnotations attribute body, or None

    With texts=False (generic.py's layer reader, about 3 times faster) `utf8` holds the raw bytes
    of each constant, and only the String constants are decoded.
    Raises struct.error, ValueError or IndexError on a class that is cut or malformed."""
    minor, major, count = struct.unpack_from(">HHH", blob, 4)
    utf8, ints, kinds, refs = {}, {}, {}, {}
    i, at = 1, 10
    while i < count:
        tag = blob[at]
        if tag == 1:
            n = struct.unpack_from(">H", blob, at + 1)[0]
            if at + 3 + n > len(blob):
                raise ValueError("a constant runs past the end of the class")
            utf8[i] = blob[at + 3:at + 3 + n]
            at += 3 + n
        elif tag == 3:
            ints[i] = struct.unpack_from(">i", blob, at + 1)[0]
            at += 5
        elif tag in _POOL_SIZE:
            if tag in (7, 8):
                refs[i] = struct.unpack_from(">H", blob, at + 1)[0]
            at += 1 + _POOL_SIZE[tag]
        else:
            raise ValueError(f"constant pool tag {tag} at {at}")
        kinds[i] = tag
        i += 2 if tag in (5, 6) else 1
    this = struct.unpack_from(">H", blob, at + 2)[0]
    at += 6
    at += 2 + 2 * struct.unpack_from(">H", blob, at)[0]          # interfaces
    codes, annotations = [], None
    for member in ("fields", "methods", "class"):
        n = 1 if member == "class" else struct.unpack_from(">H", blob, at)[0]
        at += 0 if member == "class" else 2
        for _ in range(n):
            at += 0 if member == "class" else 6
            attrs = struct.unpack_from(">H", blob, at)[0]
            at += 2
            for _ in range(attrs):
                name, size = struct.unpack_from(">HI", blob, at)
                if member == "methods" and utf8.get(name) == b"Code":
                    length = struct.unpack_from(">I", blob, at + 10)[0]
                    codes.append(blob[at + 14:at + 14 + length])
                elif member == "class" and utf8.get(name) == b"RuntimeVisibleAnnotations":
                    annotations = blob[at + 6:at + 6 + size]
                at += 6 + size
    if at > len(blob):
        raise ValueError("the class is cut")
    strings = [(k, mutf8(utf8[r])) for k, r in sorted(refs.items()) if kinds.get(k) == 8 and r in utf8]
    name = utf8.get(refs.get(this))
    if texts:
        utf8 = {k: mutf8(v) for k, v in utf8.items()}
    return {"major": major, "minor": minor, "utf8": utf8, "ints": ints, "strings": strings,
            "this": None if name is None else mutf8(name), "codes": codes, "annotations": annotations}


def _push(code: bytes, at: int):
    """(value, next offset) of an int constant pushed at `at` (iconst_m1..5, bipush, sipush), or None."""
    op = code[at] if 0 <= at < len(code) else -1
    if 0x02 <= op <= 0x08:
        return op - 0x03, at + 1
    if op == 0x10 and at + 1 < len(code):
        return struct.unpack_from(">b", code, at + 1)[0], at + 2
    if op == 0x11 and at + 2 < len(code):
        return struct.unpack_from(">h", code, at + 1)[0], at + 3
    return None


# newarray's type operand -> (the store opcode of its elements, the values an element may have)
_ARRAYS = {8: (0x54, range(-128, 256)),      # byte[]: bastore, javac's signed bytes (and 128..255 as ints)
           10: (0x4F, range(0, 256))}         # int[]: iastore, only values that are one byte


def jvm_arrays(code: bytes, least: int = 12) -> list:
    """The byte[] and int[] literals a method builds, as bytes: `<length> newarray byte|int`, then
    for every element `dup <index> <value> bastore|iastore` (javac's and kotlinc's form for an
    array initialiser). Kept only when the array has `least` elements or more, every element is
    set exactly this way and every value fits its range (an int[] element only 0..255)."""
    out = []
    at = code.find(b"\xbc")
    while 0 <= at < len(code) - 1:
        kind = _ARRAYS.get(code[at + 1])
        size = None
        if kind:
            for back in (3, 2, 1):   # the length was pushed right before
                got = _push(code, at - back) if at - back >= 0 else None
                if got and got[1] == at:
                    size = got[0]
                    break
        if kind and size and size >= least:
            store, allowed = kind
            arr, pos = {}, at + 2
            while pos < len(code) and code[pos] == 0x59 and len(arr) < size:
                idx = _push(code, pos + 1)
                val = _push(code, idx[1]) if idx else None
                if not val or val[1] >= len(code) or code[val[1]] != store or val[0] not in allowed:
                    break
                arr[idx[0]] = val[0] & 0xFF
                pos = val[1] + 1
            if len(arr) == size and set(arr) == set(range(size)):
                out.append(bytes(arr[k] for k in range(size)))
        at = code.find(b"\xbc", at + 1)
    return out


def _element(blob: bytes, at: int, cls: dict):
    """(value, next offset) of one annotation element_value: an int or a string constant, a list
    for an array, None for any other kind (an enum, a class, a nested annotation)."""
    tag = chr(blob[at])
    at += 1
    if tag in "BCIJSZDF":
        idx = struct.unpack_from(">H", blob, at)[0]
        return (cls["ints"].get(idx) if tag in "BCISZ" else None), at + 2
    if tag == "s":
        return cls["utf8"].get(struct.unpack_from(">H", blob, at)[0]), at + 2
    if tag == "e":
        return None, at + 4
    if tag == "c":
        return None, at + 2
    if tag == "@":
        return None, _annotation(blob, at, cls)[1]
    if tag == "[":
        n = struct.unpack_from(">H", blob, at)[0]
        at += 2
        items = []
        for _ in range(n):
            v, at = _element(blob, at, cls)
            items.append(v)
        return items, at
    raise ValueError(f"element tag {tag!r}")


def _annotation(blob: bytes, at: int, cls: dict):
    """((type descriptor, {element name: value}), next offset)."""
    kind, n = struct.unpack_from(">HH", blob, at)
    at += 4
    values = {}
    for _ in range(n):
        name = cls["utf8"].get(struct.unpack_from(">H", blob, at)[0])
        values[name], at = _element(blob, at + 2, cls)
    return (cls["utf8"].get(kind), values), at


def kotlin_metadata(cls: dict):
    """The element values of the class's @kotlin.Metadata annotation, or None."""
    blob = cls.get("annotations")
    if not blob:
        return None
    at, n = 2, struct.unpack_from(">H", blob, 0)[0]
    for _ in range(n):
        (kind, values), at = _annotation(blob, at, cls)
        if kind == "Lkotlin/Metadata;":
            return values
    return None


def _class_facts(blob: bytes, out: dict):
    cls = parse_class(blob)
    out["class_major"], out["class_minor"] = cls["major"], cls["minor"]
    out["java_release"] = str(cls["major"] - 44) if cls["major"] >= 49 else f"1.{cls['major'] - 44}"
    if cls["this"]:
        out["class_name"] = cls["this"]
    meta = kotlin_metadata(cls)
    if meta is not None:
        mv = meta.get("mv")
        if isinstance(mv, list) and mv and all(isinstance(x, int) for x in mv):
            out["kotlin_metadata_version"] = ".".join(map(str, mv))
        if isinstance(meta.get("k"), int):
            out["kotlin_kind"] = meta["k"]


def manifest(text: str) -> dict:
    """The main section of a MANIFEST.MF: {name: value}, continuation lines (a leading space) joined."""
    out, last = {}, None
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not line:
            if out:
                break            # the main section ends at the first blank line
            continue
        if line.startswith(" ") and last:
            out[last] += line[1:]
        elif ":" in line:
            last, _, value = line.partition(":")
            last = last.strip()
            out[last] = value.strip()
    return out


def _jvm(data: bytes, out: dict):
    """A class file, or a jar's manifest, its main class (else its first class) and its Kotlin modules."""
    if is_class(data):
        _class_facts(data, out)
        return
    if not (data[:4] == ZIP_MAGIC or (data[:2] == b"#!" and ZIP_MAGIC in data[:STUB_MAX])):
        return
    zf = zipfile.ZipFile(io.BytesIO(data))
    infos = {i.filename: i for i in zf.infolist() if not i.is_dir()}
    man = infos.get("META-INF/MANIFEST.MF")
    if man is not None and man.file_size <= 1 << 20:
        fields = manifest(zf.read(man).decode("utf-8", "replace"))
        for name, fact in (("Main-Class", "jar_main_class"), ("Created-By", "jar_created_by"),
                           ("Build-Jdk-Spec", "jar_build_jdk"), ("Build-Jdk", "jar_build_jdk")):
            if fields.get(name):
                out.setdefault(fact, fields[name])
    modules = [n[len("META-INF/"):-len(".kotlin_module")] for n in infos
               if n.startswith("META-INF/") and n.endswith(".kotlin_module")]
    if modules:
        out["kotlin_modules"] = modules[:MAX_LIST]
    main = out.get("jar_main_class")
    entry = infos.get(main.replace(".", "/") + ".class") if main else None
    if entry is None:
        entry = next((i for n, i in infos.items() if n.endswith(".class") and not n.endswith("module-info.class")),
                     None)
    if entry is not None and entry.file_size <= CLASS_MAX:
        blob = zf.read(entry)
        if is_class(blob):
            _class_facts(blob, out)
    dex = infos.get("classes.dex")
    if dex is not None and "dex_version" not in out:
        with zf.open(dex) as fh:
            _dex(fh.read(8), out)


def _dex(data: bytes, out: dict):
    """`dex\\n` + three version digits + NUL."""
    if data[:4] == b"dex\n" and data[7:8] == b"\0" and data[4:7].isdigit():
        out["dex_version"] = data[4:7].decode()


def _wasm(data: bytes, out: dict):
    if data[:4] == b"\0asm" and len(data) >= 8:
        out["wasm_version"] = struct.unpack_from("<I", data, 4)[0]


MACHO_MAGIC = {b"\xcf\xfa\xed\xfe": (64, "<"), b"\xce\xfa\xed\xfe": (32, "<"),
               b"\xfe\xed\xfa\xcf": (64, ">"), b"\xfe\xed\xfa\xce": (32, ">")}
MACHO_FILETYPE = {1: "MH_OBJECT", 2: "MH_EXECUTE", 3: "MH_FVMLIB", 4: "MH_CORE", 5: "MH_PRELOAD", 6: "MH_DYLIB",
                  7: "MH_DYLINKER", 8: "MH_BUNDLE", 9: "MH_DYLIB_STUB", 10: "MH_DSYM", 11: "MH_KEXT_BUNDLE",
                  12: "MH_FILESET"}


def _macho_header(data: bytes, at: int, out: dict):
    bits, end = MACHO_MAGIC[data[at:at + 4]]
    cpu, sub, ftype, ncmds, sizeofcmds, flags = struct.unpack_from(end + "iIIIII", data, at + 4)
    out.update(macho_bits=bits, macho_cputype=f"0x{cpu & 0xFFFFFFFF:08x}", macho_cpusubtype=sub & 0x00FFFFFF,
               macho_filetype=MACHO_FILETYPE.get(ftype, ftype), macho_ncmds=ncmds, macho_sizeofcmds=sizeofcmds,
               macho_flags=f"0x{flags:08x}")


def _macho(data: bytes, out: dict):
    """A thin Mach-O's mach_header; for a fat file (CAFEBABE or CAFEBABF with fewer than 45
    architectures) the CPU types of its architectures and the first architecture's header."""
    if data[:4] in MACHO_MAGIC and len(data) >= 28:
        _macho_header(data, 0, out)
        return
    if data[:4] in (CLASS_MAGIC, b"\xca\xfe\xba\xbf") and len(data) >= 8:
        n = struct.unpack_from(">I", data, 4)[0]
        if not 0 < n < 45:
            return
        wide = data[3] == 0xBF
        size = 32 if wide else 20
        cpus, first = [], None
        for k in range(n):
            cpu = struct.unpack_from(">i", data, 8 + size * k)[0]
            off = struct.unpack_from(">Q" if wide else ">I", data, 8 + size * k + 8)[0]
            cpus.append(f"0x{cpu & 0xFFFFFFFF:08x}")
            first = off if first is None else first
        out["macho_fat_cputypes"] = cpus
        if first is not None and data[first:first + 4] in MACHO_MAGIC and len(data) >= first + 28:
            _macho_header(data, first, out)


# ---------------------------------------------------------------------------- packagings of backlog row 80
# A .NET single-file bundle, an Electron asar archive, an ar archive (a Go c-archive, any static
# library), and the toolchain strings of Nim, Zig, Crystal, D, GHC and Swift. generic.py names the
# first three as containers (unsure) and reads a bundle's files as layers; the markers are triage only.

# The .NET host's bundle signature (SHA-256 of ".net core bundle"), right after the 8-byte offset of
# the bundle header: 0 in an apphost that carries no bundle, the header's file offset in one that does.
BUNDLE_SIG = bytes.fromhex("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae")
BUNDLE_TYPES = {0: "unknown", 1: "assembly", 2: "native", 3: "deps_json", 4: "runtimeconfig_json", 5: "symbols"}
BUNDLE_FILES_MAX = 1 << 16


def _bundle_string(data: bytes, o: int):
    """(text, next offset) of a BinaryWriter string: a 7-bit encoded length, then UTF-8."""
    n = shift = 0
    for _ in range(5):
        b = data[o]
        o += 1
        n |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            break
    else:
        raise ValueError("string length longer than 5 bytes")
    raw = data[o:o + n]
    if len(raw) != n:
        raise ValueError("string cut by the end of the file")
    return raw.decode("utf-8"), o + n


def _bundle_at(data: bytes, off: int):
    """The bundle manifest whose header starts at `off`, or None when it does not parse whole."""
    if not 0 < off < len(data):
        return None
    major, minor, count = struct.unpack_from("<IIi", data, off)
    if not (1 <= major <= 16 and 0 < count <= BUNDLE_FILES_MAX):
        return None
    bundle_id, o = _bundle_string(data, off + 12)
    if major >= 2:
        o += 40          # deps.json offset and size, runtimeconfig.json offset and size, flags
    files = []
    for _ in range(count):
        offset, size = struct.unpack_from("<qq", data, o)
        o += 16
        packed = 0
        if major >= 6:
            packed = struct.unpack_from("<q", data, o)[0]
            o += 8
        kind = data[o]
        path, o = _bundle_string(data, o + 1)
        stored = packed or size
        if offset < 0 or size < 0 or packed < 0 or kind not in BUNDLE_TYPES or offset + stored > len(data) or not path:
            return None
        files.append({"path": path, "type": BUNDLE_TYPES[kind], "offset": offset, "size": size, "compressed": packed})
    return {"version": f"{major}.{minor}", "id": bundle_id, "header": off, "files": files}


BUNDLE_HITS = 16        # signature places looked at in one file
BUNDLE_TRIES = 2        # distinct non-zero header offsets parsed in one file (a real bundle has one)
_BUNDLE_MEMO: dict = {}  # the last few files' answers: header() asks once per member, and more than once


def dotnet_bundle(data: bytes):
    """The manifest of a .NET single-file bundle (an apphost with files appended to it), or None:
    {version, id, header, files: [{path, type, offset, size, compressed}]}. `compressed` is the
    stored size of a file the bundler deflated (raw deflate, .NET 6+), 0 for a file stored as it is.
    Read from the bytes only, and only when every entry of the manifest parses and lies inside the
    file: an apphost without a bundle (offset 0) gives None.

    Bounded: at most BUNDLE_HITS places of the signature and BUNDLE_TRIES distinct header offsets
    per file (a real bundle has exactly one non-zero placeholder), each manifest parse is linear in
    the file, and the answer is kept for the last few files, so a file full of signatures that point
    at one long, broken manifest costs one parse, not one per signature and per call."""
    at = data.find(BUNDLE_SIG)
    if at < 0:
        return None                     # no signature: no hash of the file, nothing kept
    memo = isinstance(data, bytes)
    if memo and data in _BUNDLE_MEMO:
        return _BUNDLE_MEMO[data]
    got, tried, hits = None, set(), 0
    while at >= 0 and hits < BUNDLE_HITS and len(tried) < BUNDLE_TRIES:
        hits += 1
        if at >= 8:
            off = struct.unpack_from("<q", data, at - 8)[0]
            if off and off not in tried:
                tried.add(off)
                try:
                    got = _bundle_at(data, off)
                except (struct.error, ValueError, IndexError, UnicodeDecodeError, RecursionError):
                    got = None
                if got:
                    break
        at = data.find(BUNDLE_SIG, at + 1)
    if memo:
        if len(_BUNDLE_MEMO) >= 4:
            _BUNDLE_MEMO.pop(next(iter(_BUNDLE_MEMO)))
        _BUNDLE_MEMO[data] = got
    return got


ASAR_JSON_MAX = 16 << 20


def asar_header(data: bytes):
    """An Electron asar archive's header, or None: {files: top-level names, base: where the file
    bodies start}. The layout is two Chromium pickles: [4][header size], then [payload size]
    [JSON length][JSON], the JSON an object with a `files` object."""
    if data[:4] != b"\x04\0\0\0" or len(data) < 16:
        return None
    size, payload, length = struct.unpack_from("<III", data, 4)
    if not (0 < length <= ASAR_JSON_MAX and 16 + length <= 8 + size <= len(data) and length + 4 <= payload <= size):
        return None
    try:
        top = json.loads(data[16:16 + length].decode("utf-8"))
    except Exception:   # not UTF-8, not JSON, or nested past the parser's depth (RecursionError)
        return None
    if not isinstance(top, dict) or not isinstance(top.get("files"), dict):
        return None
    return {"files": list(top["files"])[:64], "base": 8 + size}


AR_MAGIC = b"!<arch>\n"
AR_MEMBERS_MAX = 4096


def ar_members(data: bytes):
    """[(name, bytes)] of an ar archive (a static library, a Go c-archive), GNU and BSD long names
    read; None for a file that is not one or whose first member header is malformed."""
    if data[:8] != AR_MAGIC:
        return None
    out, o, longnames = [], 8, b""
    while o + 60 <= len(data) and len(out) < AR_MEMBERS_MAX:
        head = data[o:o + 60]
        if head[58:60] != b"`\n":
            break
        try:
            size = int(head[48:58].strip())
        except ValueError:
            break
        body = data[o + 60:o + 60 + size]
        if size < 0 or len(body) != size:
            break
        name = head[:16].rstrip(b" ")
        if name == b"//":
            longnames = body
        elif name.startswith(b"/") and name[1:].isdigit():
            name = longnames[int(name[1:]):].split(b"\n", 1)[0]
        elif name.startswith(b"#1/") and name[3:].isdigit():
            n = int(name[3:])
            name, body = body[:n].rstrip(b"\0"), body[n:]
        if name not in (b"/", b"//"):
            out.append((name.rstrip(b"/").decode("latin-1"), body))
        o += 60 + size + (size & 1)
    return out or None


TOOLCHAINS = (("nim", (b"NimMain", b"NimMainModule", b"nimFrame", b"fatal.nim")),
              ("zig", (b"reached unreachable code", b"attempt to use null value", b"zig_probe_stack", b"start.zig")),
              ("crystal", (b"__crystal_main", b"CRYSTAL_", b"Crystal::")),
              ("d", (b"_Dmain", b"_d_run_main", b"__dmd_", b"druntime")),
              ("ghc", (b"GHC RTS", b"ghczmprim_GHC", b"base_GHCziBase", b"hs_main")),
              ("swift", (b"swift_retain", b"__swift5_", b"libswiftCore")),
              ("dotnet_apphost", (b"DOTNET_ROOT", b"hostfxr")),
              ("go_plugin", (b"go:plugin", b"plugin/unnamed", b"_cgo_export")))
EXEC_HEADS = (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce")


def _toolchain(data: bytes, out: dict):
    """The strings each toolchain's runtime leaves, for an ELF, PE, Mach-O or ar file only."""
    if not (data[:4] in EXEC_HEADS or data[:2] == b"MZ" or data[:8] == AR_MAGIC):
        return
    found = {lang: [m.decode() for m in marks if m in data] for lang, marks in TOOLCHAINS}
    found = {k: v for k, v in found.items() if v}
    if found:
        out["toolchain_markers"] = found


def _bundle(data: bytes, out: dict):
    if not (data[:4] in EXEC_HEADS or data[:2] == b"MZ") or BUNDLE_SIG not in data:
        return
    got = dotnet_bundle(data)
    if got:
        out.update(dotnet_bundle_version=got["version"], dotnet_bundle_id=got["id"],
                   dotnet_bundle_files=len(got["files"]),
                   dotnet_bundle_compressed=sum(1 for f in got["files"] if f["compressed"]),
                   dotnet_bundle_assemblies=[f["path"] for f in got["files"] if f["type"] == "assembly"][:MAX_LIST])


def _asar(data: bytes, out: dict):
    got = asar_header(data)
    if got:
        out["asar_files"] = got["files"][:MAX_LIST]


def _ar(data: bytes, out: dict):
    got = ar_members(data)
    if got:
        out["ar_members"] = [n for n, _ in got][:MAX_LIST]


READERS = (_go, _rust, _compiler, _dotnet, _python, _packer, _jvm, _dex, _wasm, _macho, _toolchain, _bundle, _asar,
           _ar)


def _read(data: bytes, out: dict):
    for reader in READERS:
        try:
            reader(data, out)
        except Exception as e:  # a truncated or hostile file must cost one fact, not the dump
            out.setdefault("errors", []).append(f"{reader.__name__[1:]}: {type(e).__name__}: {e}"[:120])


def facts(data: bytes) -> dict:
    """Every runtime fact found in the file, {name: value}. Missing facts are left out. A UPX-packed
    executable is unpacked (unpack_upx) and the facts of the image under it fill the ones the
    packed bytes do not show; `unpacked` says what became of it."""
    out = {}
    _read(data, out)
    if str(out.get("packer", "")).startswith("UPX"):
        try:
            inner, note = unpack_upx(data)
        except Exception as e:
            inner, note = None, f"unpacking raised {type(e).__name__}: {e}"
        out["unpacked"] = note
        if inner:
            under = {}
            _read(inner, under)
            for k, v in under.items():
                out.setdefault(k, v)
    return out


def render(found: dict) -> list:
    """One `name = value` line per fact, in the order found."""
    return [f"{k} = {v}" for k, v in found.items()]


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        sys.exit(__doc__)
    status = 0
    for path in sys.argv[1:]:
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError as e:
            print(f"facts.py: cannot read {path}: {e.strerror}", file=sys.stderr)
            status = 2
            continue
        print(path)
        for line in render(facts(blob)) or ["(no runtime fact found)"]:
            print(f"  {line}")
    sys.exit(status)
