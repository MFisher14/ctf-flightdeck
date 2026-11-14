#!/usr/bin/env python3
"""Builder of the B-241 machine-code fixtures (tests/b241_blobs.py) from their assembly listings.

The B-241 tests run hand-written code inside the bounded emulators: a PE32 ``.text`` (x86), JNI natives
(x86-64) and floating-point natives (AArch64).  The listings are ``tests/fixtures/native_image/B241_*.s``;
this file assembles each with clang's integrated assembler (no linker: a listing has no relocation) and
writes the bytes and the label offsets to ``tests/b241_blobs.py``, which the tests import.  It is TEST
INFRASTRUCTURE ONLY: never imported by a solver, and nothing it produces is run on the host.

    .venv/bin/python -I -B tests/b241_fixture_asm.py            rebuild tests/b241_blobs.py
    .venv/bin/python -I -B tests/b241_fixture_asm.py --check    exit 1 when the committed blobs are stale
    .venv/bin/python -I -B tests/b241_fixture_asm.py --macho    rebuild the Mach-O fixtures (macOS, cc)

The Mach-O fixtures (``tests/fixtures/native_image/b241_macho_*``: four dylibs and two PIE executables) are
compiled from ``B241_MACHO.c`` by the host cc and linked by the macOS linker, since no Mach-O linker is
carried.  Nothing built is run on the host.

An operand ``BASE + (label - start)`` (an absolute address of a label, for an image loaded at a fixed base)
is resolved in two passes, because LLVM's Intel-syntax parser takes no label difference in an operand: the
first pass assembles with a placeholder of the same width, the second with the label's address.
"""
from __future__ import annotations

import re
import shutil
import struct
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCES = HERE / "fixtures" / "native_image"
OUT = HERE / "b241_blobs.py"

# name -> (listing, clang target, the address `start` is loaded at when the listing uses BASE + (label - start))
LISTINGS = {
    "PE32": ("B241_PE32.s", "i386-pc-linux-gnu", 0x401000),
    "JNI64": ("B241_JNI_X86_64.s", "x86_64-linux-gnu", 0),
    "FPA64": ("B241_FP_ARM64.s", "aarch64-linux-gnu", 0),
}
_ABSOLUTE = re.compile(r"BASE \+ \((\w+) - start\)")


class AsmError(RuntimeError):
    """The listing could not be assembled into relocation-free bytes."""


def _text_and_labels(obj: bytes) -> tuple[bytes, dict[str, int]]:
    """The ``.text`` bytes and its symbols of an ELF relocatable object (ELF32 or ELF64, little-endian)."""
    if obj[:4] != b"\x7fELF" or obj[5] != 1:
        raise AsmError("the assembler did not write a little-endian ELF object")
    wide = obj[4] == 2
    if wide:
        shoff, = struct.unpack_from("<Q", obj, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", obj, 0x3A)
    else:
        shoff, = struct.unpack_from("<I", obj, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", obj, 0x2E)

    def header(index: int):
        at = shoff + index * shentsize
        if wide:
            name, kind, _flags, _addr, offset, size, link, _info, _align, entsize = \
                struct.unpack_from("<IIQQQQIIQQ", obj, at)
        else:
            name, kind, _flags, _addr, offset, size, link, _info, _align, entsize = \
                struct.unpack_from("<IIIIIIIIII", obj, at)
        return name, kind, offset, size, link, entsize

    names_at = header(shstrndx)[2]

    def cstring(table: int, at: int) -> str:
        end = obj.index(b"\0", table + at)
        return obj[table + at:end].decode()

    sections = [(cstring(names_at, h[0]),) + h[1:] for h in map(header, range(shnum))]
    text_index = next(i for i, s in enumerate(sections) if s[0] == ".text")
    for name, kind, _offset, size, _link, _entsize in sections:
        if kind in (4, 9) and size:                      # SHT_RELA / SHT_REL
            raise AsmError(f"the listing needs a relocation ({name}); a fixture must assemble without one")
    _name, _kind, offset, size, _link, _entsize = sections[text_index]
    text = obj[offset:offset + size]
    labels: dict[str, int] = {}
    for name, kind, offset, size, link, entsize in sections:
        if kind != 2:                                    # SHT_SYMTAB
            continue
        strings = sections[link][2]
        for at in range(offset, offset + size, entsize):
            if wide:
                st_name, _info, _other, shndx, value, _size = struct.unpack_from("<IBBHQQ", obj, at)
            else:
                st_name, value, _size, _info, _other, shndx = struct.unpack_from("<IIIBBH", obj, at)
            label = cstring(strings, st_name) if st_name else ""
            if label and shndx == text_index and not label.startswith("$"):
                labels[label] = value
    return text, labels


def assemble(name: str, clang: str, work: Path) -> tuple[bytes, dict[str, int]]:
    listing, target, base = LISTINGS[name]
    source = (SOURCES / listing).read_text(encoding="utf-8")
    absolute = sorted(set(_ABSOLUTE.findall(source)))
    body = _ABSOLUTE.sub(r"A_\1", source)
    if absolute and "    .text\n" not in body:
        raise AsmError(f"{listing}: no '.text' line to define the absolute labels after")

    def one_pass(addresses: dict[str, int]) -> tuple[bytes, dict[str, int]]:
        head = "".join("    .set A_%s, %#x\n" % (label, addresses.get(label, base)) for label in absolute)
        cooked = work / (name + ".s")
        cooked.write_text(body.replace("    .text\n", "    .text\n" + head, 1), encoding="utf-8")
        out = work / (name + ".o")
        done = subprocess.run([clang, "-target", target, "-c", "-x", "assembler", str(cooked), "-o", str(out)],
                              capture_output=True, text=True)
        if done.returncode != 0:
            raise AsmError(f"{listing}: clang exited {done.returncode}: {done.stderr.strip()[-800:]}")
        return _text_and_labels(out.read_bytes())

    text, labels = one_pass({})
    if absolute:
        text, second = one_pass({label: base + labels[label] for label in absolute})
        if second != labels:
            raise AsmError(f"{listing}: label offsets moved between the two passes")
    labels.pop("start", None)
    return text, labels


def render(clang: str) -> str:
    out = ['"""Machine code of the B-241 test fixtures.  GENERATED by tests/b241_fixture_asm.py from the listings',
           'tests/fixtures/native_image/B241_*.s: do not edit by hand (tests/test_b241_blobs.py checks it against',
           'the listings wherever clang is present).  Each blob is the listing\'s .text; each LABELS maps a label',
           'to its offset in it."""', ""]
    with tempfile.TemporaryDirectory(prefix="b241-asm-") as tmp:
        for name in LISTINGS:
            text, labels = assemble(name, clang, Path(tmp))
            out.append(f"{name}_HEX = (")
            out.extend('    "%s"' % line for line in textwrap.wrap(text.hex(), 100))
            out.append(")")
            out.append(f"{name} = bytes.fromhex({name}_HEX)")
            row = ", ".join('"%s": %#x' % item for item in sorted(labels.items(), key=lambda kv: (kv[1], kv[0])))
            out.append(f"{name}_LABELS = {{")
            out.append(textwrap.fill(row, 108, initial_indent="    ", subsequent_indent="    ") + ",")
            out.append("}")
            out.append("")
    return "\n".join(out)


MACHO_SOURCE = SOURCES / "B241_MACHO.c"
# (file name, cc arguments): both architectures, with chained fixups (the linker's default) and with the
# classic dyld-info opcodes. (A universal file is put together from two of them inside the test.)
MACHO_BUILDS = (
    ("b241_macho_x86_64_chained.dylib", ("-arch", "x86_64")),
    ("b241_macho_x86_64_classic.dylib", ("-arch", "x86_64", "-Wl,-no_fixup_chains")),
    ("b241_macho_arm64_chained.dylib", ("-arch", "arm64")),
    ("b241_macho_arm64_classic.dylib", ("-arch", "arm64", "-Wl,-no_fixup_chains")),
    # PIE executables: __PAGEZERO below a __TEXT that does not start at address zero
    ("b241_macho_x86_64_exec_chained", ("-arch", "x86_64", "-DB241_EXECUTABLE")),
    ("b241_macho_arm64_exec_classic", ("-arch", "arm64", "-DB241_EXECUTABLE", "-Wl,-no_fixup_chains")),
)


def build_macho(out: Path) -> list[Path]:
    """Compile B241_MACHO.c into the Mach-O fixtures in ``out`` (macOS with the command-line tools only)."""
    if sys.platform != "darwin":
        raise AsmError("the Mach-O fixtures are built with the macOS linker; this is not macOS")
    cc = shutil.which("cc")
    if not cc:
        raise AsmError("cc is needed to build the Mach-O fixtures")
    built = []
    for name, extra in MACHO_BUILDS:
        target = out / name
        kind = (["-dynamiclib", "-install_name", "@rpath/libb241.dylib"] if name.endswith(".dylib")
                else ["-Wl,-pie"])
        done = subprocess.run([cc, *extra, *kind, "-O1", "-fstack-protector-all", "-o", str(target),
                               str(MACHO_SOURCE)], capture_output=True, text=True)
        if done.returncode != 0:
            raise AsmError(f"{name}: cc exited {done.returncode}: {done.stderr.strip()[-800:]}")
        built.append(target)
    return built


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--macho" in argv:
        try:
            for path in build_macho(SOURCES):
                print(f"b241_fixture_asm: wrote {path.name} ({path.stat().st_size} bytes)")
        except AsmError as exc:
            print(f"b241_fixture_asm: {exc}", file=sys.stderr)
            return 2
        return 0
    clang = shutil.which("clang")
    if not clang:
        print("b241_fixture_asm: clang is not on PATH", file=sys.stderr)
        return 2
    try:
        text = render(clang)
    except AsmError as exc:
        print(f"b241_fixture_asm: {exc}", file=sys.stderr)
        return 2
    if "--check" in argv:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            print("b241_fixture_asm: tests/b241_blobs.py is stale; run tests/b241_fixture_asm.py", file=sys.stderr)
            return 1
        print("b241_fixture_asm: tests/b241_blobs.py is current")
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"b241_fixture_asm: wrote {OUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
