"""Novel/unrecognized CONTAINER recovery for the Binary lane (the classic morning-of gap).

`generic._header` names a file only when its magic is intact (`\\x7fELF` with a valid EI_CLASS/
EI_DATA, `MZ`+`PE\\0\\0`, a Mach-O magic, ...). When the magic is ABSENT or damaged it returns
`kind=None`, and `format_answer`/`machine_answer` then answer the `analysis_format` and
`analysis_machine` questions with None. This module recovers those two facts from the RESIDUAL
structure the header still carries, and emits them as `labels.candidates` (UNSURE, never plain):

  * an ELF section-header table / a readable e_machine field / valid EI_CLASS+EI_DATA bytes;
  * a PE `PE\\0\\0` signature remnant / a DOS stub / a bare COFF machine field;
  * a Mach-O thin header remnant (cputype + filetype + a valid first load command) or a fat
    header remnant (nfat_arch + an architecture whose cputype and sub-image check out).

Every answer is a candidate pick (row 346): the option NAMES the detection hypothesis
(`elf_section_table`, `pe_signature`, `macho_thin_header`, ...), never the value, so the name the
judge accepts answers the next variant with that variant's own detected value under the same
hypothesis. Nothing is ever plain, and the module is a LAST RESORT: generic.py asks it ONLY when NO
header was recognised at all (never over a format/machine a recognised header left None, which is a
deliberate never-guess decision), and the module itself skips any member generic.header recognises
and blanks a machine the members disagree on. So it can never change an answer another reader gives:
it only turns a None into an unsure, probeable answer with the truth among the options.
"""

import struct
import sys
from pathlib import Path

from _shadowed import module_at

# this lane's generic.py: solvers/script-analysis/generic.py wins a flat `import generic`
generic = module_at(Path(__file__).resolve().parent / "generic.py", "binary_generic")
import labels
from answer_kinds import kind_of

# ---------------------------------------------------------------------------- bounded helpers

PE_SCAN = 1 << 16          # how far into a member a `PE\0\0` remnant is searched
DOS_STUB = b"This program cannot be run in DOS mode"


def _u(data: bytes, off: int, size: int, end: str):
    """An unsigned int of `size` bytes at `off`, or None when it runs off the member."""
    if off < 0 or off + size > len(data):
        return None
    return int.from_bytes(data[off:off + size], "little" if end == "<" else "big")


# ---------------------------------------------------------------------------- one detection

class _Hit:
    """One recovered family: its format value and the hypothesis that found it, plus the CPU the
    same structure names (None when it names none, e.g. a fat Mach-O). `score` ranks the evidence."""

    __slots__ = ("fmt", "fmt_signal", "cpu", "cpu_signal", "score")

    def __init__(self, fmt, fmt_signal, cpu, cpu_signal, score):
        self.fmt = fmt
        self.fmt_signal = fmt_signal
        self.cpu = cpu
        self.cpu_signal = cpu_signal
        self.score = score


# ---------------------------------------------------------------------------- ELF

_ELF_SHDR = {32: 40, 64: 64}       # e_shentsize of a well-formed ELF, by class
_ELF_PHDR = {32: 32, 64: 56}       # e_phentsize
_ELF_EHSIZE = {32: 52, 64: 64}     # e_ehsize (the header's own size)
_ELF_ETYPE_OK = frozenset((0, 1, 2, 3, 4))


def _elf(data: bytes):
    """The strongest ELF detection of `data`, or None. The magic may be damaged or absent, but the
    header's declared identity bytes are respected: a valid EI_CLASS (data[4]) pins the class and a
    valid EI_DATA (data[5]) pins the byte order, so the e_machine is read under the header's OWN
    endianness only and never reinterpreted under the OPPOSITE one (which would read a byte-swapped
    field and name a nameless big-endian machine -- x86-64, say -- wrongly). Only an identity byte
    that is absent or invalid leaves its interpretation open to be scored, so a file whose EI_CLASS/
    EI_DATA bytes are gone is still recovered from the rest of the header."""
    if len(data) < 52:
        return None
    classes = (32,) if data[4] == 1 else (64,) if data[4] == 2 else (32, 64)
    ends = ("<",) if data[5] == 1 else (">",) if data[5] == 2 else ("<", ">")
    best = None
    for bits in classes:
        for end in ends:
            ehsize_at = 40 if bits == 32 else 52
            if ehsize_at + 12 > len(data):
                continue
            e_type = _u(data, 16, 2, end)
            e_machine = _u(data, 18, 2, end)
            e_version = _u(data, 20, 4, end)
            e_ehsize = _u(data, ehsize_at, 2, end)
            e_shentsize = _u(data, ehsize_at + 6, 2, end)
            e_shnum = _u(data, ehsize_at + 8, 2, end)
            e_shstrndx = _u(data, ehsize_at + 10, 2, end)
            e_shoff = _u(data, 32 if bits == 32 else 40, 8 if bits == 64 else 4, end)
            class_ok = data[4] == (1 if bits == 32 else 2)
            data_ok = data[5] == (1 if end == "<" else 2)
            ver_byte_ok = len(data) > 6 and data[6] == 1
            ehsize_ok = e_ehsize == _ELF_EHSIZE[bits]
            # The section-header table: offset, entry size, count and the string-table index all consistent
            # and inside the member. The strongest residual signal (what the HARDEN calls for first).
            shdr_ok = (ehsize_ok and e_shentsize == _ELF_SHDR[bits] and e_shnum and 0 < e_shnum <= 65535
                       and e_shoff and e_shstrndx is not None and e_shstrndx < e_shnum
                       and e_shoff + e_shnum * e_shentsize <= len(data))
            machine_known = e_machine in generic.ELF_CPU
            # A readable e_machine field, corroborated by the header's own size and version.
            emachine_ok = (machine_known and ehsize_ok and e_version == 1 and e_type in _ELF_ETYPE_OK)
            # Only the EI_CLASS/EI_DATA bytes (and the version fields): the weakest tier.
            classendian_ok = class_ok and data_ok and ver_byte_ok and e_version == 1 and ehsize_ok
            if shdr_ok:
                signal, score = "elf_section_table", 10
            elif emachine_ok:
                signal, score = "elf_e_machine", 7
            elif classendian_ok:
                signal, score = "elf_class_endian", 4
            else:
                continue
            if data[:4] == b"\x7fELF":
                score += 2                       # the magic itself survived: extra corroboration
            cpu = generic._elf_cpu(e_machine, bits, end == "<" and "little" or "big") if machine_known else None
            hit = _Hit("elf", signal, cpu, "elf_e_machine_field" if cpu else None, score)
            if best is None or hit.score > best.score:
                best = hit
    return best


# ---------------------------------------------------------------------------- PE / COFF

def _pe(data: bytes):
    """The strongest PE/COFF detection of `data`, or None. A `PE\\0\\0` remnant with a valid COFF
    header and PE32/PE32+ optional magic is taken first (MZ damaged); then a bare COFF header.

    A member whose PE magic is INTACT (MZ at +0 and e_lfanew pointing straight at a `PE\\0\\0`) is
    declined: generic.header reads that layout directly, so a None it returned on it is a corrupt or
    TRUNCATED PE, not a novel/damaged-magic container, and recovery never guesses a format for it."""
    n = len(data)
    e_lfanew = _u(data, 0x3C, 4, "<")
    if data[:2] == b"MZ" and e_lfanew is not None and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
        return None
    best = None
    # A `PE\0\0` signature anywhere in the head, each validated by the COFF header behind it.
    start = 0
    limit = min(n, PE_SCAN)
    while True:
        p = data.find(b"PE\x00\x00", start, limit)
        if p < 0:
            break
        start = p + 1
        machine = _u(data, p + 4, 2, "<")
        nsec = _u(data, p + 6, 2, "<")
        optsize = _u(data, p + 20, 2, "<")
        optmagic = _u(data, p + 24, 2, "<")
        if machine not in generic.PE_CPU or not nsec or not (1 <= nsec <= 96):
            continue
        if optmagic not in (0x10B, 0x20B) or optsize is None or p + 24 + optsize > n:
            continue
        e_lfanew = _u(data, 0x3C, 4, "<")
        if e_lfanew == p:
            signal, score = "pe_signature", 10
        elif DOS_STUB in data[:PE_SCAN]:
            signal, score = "pe_dos_stub", 9
        else:
            signal, score = "pe_signature", 8
        hit = _Hit("pe", signal, generic.PE_CPU[machine], "pe_coff_machine", score)
        if best is None or hit.score > best.score:
            best = hit
    if best is not None:
        return best
    # A bare COFF object (no MZ, no `PE\0\0`): machine + section-count + a section table that fits
    # and whose first entry has a printable name. Weaker, so required to be strict.
    machine = _u(data, 0, 2, "<")
    nsec = _u(data, 2, 2, "<")
    optsize = _u(data, 16, 2, "<")
    if machine in generic.PE_CPU and nsec and 1 <= nsec <= 96 and optsize is not None and optsize <= 0x400:
        sec0 = 20 + optsize
        if sec0 + nsec * 40 <= n:
            name = data[sec0:sec0 + 8]
            if name and all(c == 0 or 0x20 <= c < 0x7F for c in name) and name[0] != 0:
                return _Hit("pe", "pe_coff_header", generic.PE_CPU[machine], "pe_coff_machine", 6)
    return None


# ---------------------------------------------------------------------------- Mach-O

_MACHO_FILETYPE = frozenset(range(1, 13))       # MH_OBJECT .. MH_FILESET
_MACHO_LC = frozenset((
    0x1, 0x19, 0x2, 0xB, 0xC, 0xD, 0xE, 0x1B, 0x1C | 0x80000000, 0x1D, 0x21, 0x2C, 0x24, 0x25, 0x2F,
    0x30, 0x32, 0x28 | 0x80000000, 0x2A, 0x18 | 0x80000000, 0x1F | 0x80000000, 0x26, 0x29,
    0x22 | 0x80000000, 0x22, 0x33 | 0x80000000, 0x34 | 0x80000000))


def _macho_thin(data: bytes):
    """A thin Mach-O header remnant (magic damaged): cputype + filetype + a valid first load
    command, read under whichever endianness makes the cputype a known one."""
    if len(data) < 32:
        return None
    for end in ("<", ">"):
        cputype = _u(data, 4, 4, end)
        filetype = _u(data, 12, 4, end)
        ncmds = _u(data, 16, 4, end)
        sizeofcmds = _u(data, 20, 4, end)
        if cputype not in generic.MACHO_CPU or filetype not in _MACHO_FILETYPE:
            continue
        if not ncmds or not (1 <= ncmds <= 4096) or sizeofcmds is None or not (8 <= sizeofcmds <= len(data)):
            continue
        hs = 32 if cputype & 0x01000000 else 28
        cmd = _u(data, hs, 4, end)
        cmdsize = _u(data, hs + 4, 4, end)
        if cmd not in _MACHO_LC or cmdsize is None or not (8 <= cmdsize <= sizeofcmds) or cmdsize % 4:
            continue
        sub = _u(data, 8, 4, end) or 0
        cpu = generic.MACHO_SUBTYPE.get((cputype, sub & 0x00FFFFFF)) or generic.MACHO_CPU[cputype]
        return _Hit("macho", "macho_thin_header", cpu, "macho_cpu_type", 10)
    return None


def _macho_fat(data: bytes):
    """A fat Mach-O header remnant (magic damaged): nfat_arch + a first architecture whose cputype
    is known and whose sub-image lies inside the member and names the same cputype."""
    n = len(data)
    if n < 28:
        return None
    nfat = _u(data, 4, 4, ">")            # a fat header is always big-endian
    if not nfat or not (1 <= nfat <= 30):
        return None
    cputype = _u(data, 8, 4, ">")
    offset = _u(data, 16, 4, ">")
    size = _u(data, 20, 4, ">")
    if cputype not in generic.MACHO_CPU or offset is None or size is None:
        return None
    if offset < 8 + nfat * 20 or offset + size > n or size < 28:
        return None
    # The sub-image must be a thin Mach-O of the architecture the table claims: its own magic, or a
    # readable cputype matching the entry. This is what tells a fat header from 20 random bytes.
    sub = data[offset:offset + 32]
    if sub[:4] in generic.MACHO_MAGIC:
        return _Hit("macho+fat", "macho_fat_header", None, None, 9)
    for end in ("<", ">"):
        if _u(sub, 4, 4, end) == cputype and _u(sub, 12, 4, end) in _MACHO_FILETYPE:
            return _Hit("macho+fat", "macho_fat_header", None, None, 9)
    return None


# ---------------------------------------------------------------------------- the scan

def scan(data: bytes):
    """Every residual-structure detection of one member, strongest first; [] for none."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 20:
        return []
    data = bytes(data)
    hits = [h for h in (_elf(data), _pe(data), _macho_thin(data), _macho_fat(data)) if h is not None]
    hits.sort(key=lambda h: h.score, reverse=True)
    return hits


def _member_detections(members) -> list:
    """For each member whose header generic.header does NOT recognise, its residual-structure
    detections (strongest first). A member with a recognised header is the normal readers' to
    answer, and a format or machine they left None on it is a deliberate never-guess decision:
    recovery is a LAST RESORT for the novel/damaged containers only, so a recognised member is
    skipped here and can never be supplemented. This is also what holds the raise->clean-None error
    contract: when pick_sample raised and the sample is None but the real (recognised) members are
    still handed in, nothing is recovered from them."""
    out = []
    for _, data in members or ():
        if not isinstance(data, (bytes, bytearray)):
            continue
        blob = bytes(data)
        try:
            if generic.header(blob).get("kind"):
                continue
        except Exception:
            pass
        hits = scan(blob)
        if hits:
            out.append(hits)
    return out


def _best_member(members) -> list:
    """The detections of the unrecognised member with the single strongest residual signal, [] for
    none."""
    best, best_score = [], 0
    for hits in _member_detections(members):
        if hits[0].score > best_score:
            best, best_score = hits, hits[0].score
    return best


def recovered_format(members, fmt=None):
    """A candidate pick (unsure) for `analysis_format` recovered from residual structure, or None.
    Each option names the detection hypothesis and carries the detected format value; different
    families contribute different values, strongest evidence first, deduped by value."""
    if kind_of(fmt) == "integer":
        return None                     # a container format is never a number
    hits = _best_member(members)
    options, seen = [], set()
    for h in hits:
        if h.fmt in seen:
            continue
        seen.add(h.fmt)
        options.append((h.fmt_signal, h.fmt))
    if not options:
        return None
    return labels.candidates("binary.format/recovered", options)


def recovered_machine(members, fmt=None):
    """A candidate pick (unsure) for `analysis_machine`/`analysis_architecture` recovered from
    residual structure, or None. The hypothesis reads the machine field of the detected header, so
    the accepted name answers each later variant with that variant's own CPU.

    agreed_header blanks a machine the prefix's executables STATE DIFFERENTLY; recovery honours the
    same ambiguity. Each unrecognised member names at most one primary CPU (its strongest hit that
    carries one); when two members name DIFFERENT CPUs the fact is not established, so nothing is
    offered -- never one arbitrary member's CPU."""
    if kind_of(fmt) == "integer":
        return None                     # the integer machine id is left to the judged header path
    detections = _member_detections(members)
    primaries = set()
    for hits in detections:
        for h in hits:
            if h.cpu is not None:
                primaries.add(h.cpu)
                break
    if len(primaries) > 1:
        return None                     # the members disagree on the machine: ambiguous, like agreed_header
    best = max(detections, key=lambda hits: hits[0].score, default=None)
    if best is None:
        return None
    options, seen = [], set()
    for h in best:
        if h.cpu is None or h.cpu in seen:
            continue
        seen.add(h.cpu)
        options.append((h.cpu_signal, h.cpu))
    if not options:
        return None
    return labels.candidates("binary.machine/recovered", options)


def _main(argv) -> int:                     # pragma: no cover - a quick look at one file
    if argv and argv[0] in ("-h", "--help"):
        print("usage: structural_recover.py <sample> [...]")
        return 0
    if not argv:
        print("structural_recover.py: expected at least one sample", file=sys.stderr)
        return 2
    try:
        for path in argv:
            with open(path, "rb") as fh:
                blob = fh.read()
            print(path)
            for h in scan(blob):
                print(f"  {h.fmt_signal:<20} fmt={h.fmt:<10} cpu={h.cpu} score={h.score}")
    except Exception as exc:
        print(f"structural_recover.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
