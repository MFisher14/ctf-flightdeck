#!/usr/bin/env python3
"""Toolkit pwn: userland / binary-exploitation RECON (ELF analysis). Built 2026-10-23 (backlog T-a,
docs/retro/day24plus-buildplan-web-toolkits.md) as RECON-ONLY breadth for a possible Day 24-31
"pwn"/remote-service lane that tools/lanes.py does not know.

  .venv/bin/python solvers/toolkits/pwn.py <file>... [--json]      a static triage of the ELF(s)

What it reads, all OFFLINE and static (pyelftools when present, a stdlib header parse otherwise;
capstone, in .venv, only to ENUMERATE gadgets, never to run anything):
  - ELF class, endianness, machine/architecture, object type, entry point, interpreter;
  - exploit mitigations the way a checksec-style header read sees them: NX (PT_GNU_STACK),
    PIE (ET_DYN + PT_INTERP / DF_1_PIE), RELRO (PT_GNU_RELRO + BIND_NOW), stack canary
    (__stack_chk_fail), FORTIFY (*_chk);
  - the symbol table and dynamic symbols, the GOT/PLT relocations, and the imported libc
    functions that are classically dangerous (gets, strcpy, system, sprintf, scanf, ...);
  - symbol-address / GOT-entry (import address) / PLT-stub resolution (row 8, pyelftools): for the
    one symbol a question names, its defined st_value, its GOT slot address (a relocation r_offset),
    or its PLT stub address in the unambiguous classic layout; absent, or ambiguous, resolves to
    None (the address is never guessed), and a resolved address is a rendering candidate pick, never
    plain before the judge accepts a rendering;
  - ROP gadget ENUMERATION on x86/x86-64 executable sections (reported, never executed), and a
    report of format-string / overflow surface (printf-family and unbounded copies present).

HARD RULES (AGENTS.md "New categories", "Untrusted content"; the prompt of 2026-10-23):
  - RECON / ANALYSIS ONLY. Nothing here executes the binary, runs a gadget, fires an exploit, or
    uses a value read from it. ROP-gadget output is a listing to report, never a program to run.
  - A live pwn target (a host/port the Game Master or the player gives) is a player stop and a
    separate HAND tool, solvers/toolkits/pwn_target.py (recon only, scope-locked); this module
    makes no connection and has no live path.
  - NEVER-GUESS (AGENTS.md "Uncertain answers"): no plain answer is ever returned here. Every
    established fact is labels.pick(key, options) (its author-chosen name is not judged yet) or
    labels.candidates(key, options) for a win/entry address whose form the judge has not fixed;
    everything else, and the flag ALWAYS, is None. The flag is never derived and never submitted.
  - Bounded compute: at most MAX_FILE bytes a file, GADGET_SCAN bytes of executable code scanned,
    MAX_GADGETS gadgets reported.

Keys: `pwn.<field>/<shape>` (solvers/common/labels.py TOOLKIT_PREFIXES knows `pwn`; its unsure
answers are probed by tools/verify.py on the untimed base and remembered in
challenges/_ledger/pwn.jsonl).
"""
import io
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(1, str(COMMON))
import labels    # noqa: E402
import triage    # noqa: E402

KEY = "pwn"
ARROW = triage.ARROW
MAX_FILE = 64 * 1024 * 1024
GADGET_SCAN = 256 * 1024          # bytes of executable code scanned for gadgets
MAX_GADGETS = 200
GADGET_WINDOW = 10                # bytes before a `ret` a gadget may reach back

# e_machine -> (primary name, other spellings of the SAME architecture fact).
MACHINES = {
    0x03: ("i386", ["i386", "x86", "x86-32", "ia32", "intel_80386"]),
    0x3E: ("amd64", ["amd64", "x86_64", "x86-64", "x64", "em_x86_64"]),
    0x28: ("arm", ["arm", "armv7", "arm32", "em_arm"]),
    0xB7: ("aarch64", ["aarch64", "arm64", "armv8", "em_aarch64"]),
    0x08: ("mips", ["mips", "em_mips"]),
    0x0A: ("mips", ["mips", "mipsel", "em_mips_rs3_le"]),
    0x14: ("powerpc", ["powerpc", "ppc", "ppc32"]),
    0x15: ("ppc64", ["ppc64", "powerpc64"]),
    0x16: ("s390", ["s390", "systemz", "s390x"]),
    0xF3: ("riscv", ["riscv", "riscv64", "rv64"]),
    0x2B: ("sparc", ["sparc", "sparcv9"]),
}
ET = {0: "none", 1: "relocatable", 2: "executable", 3: "shared_object", 4: "core"}

# Classically dangerous libc imports, ranked most-dangerous first. Presence is a FINDING, never a
# claim that the binary is exploitable; the agent confirms by reading the code.
DANGEROUS = [
    "gets", "system", "execve", "execl", "execlp", "execvp", "popen", "strcpy", "strcat",
    "sprintf", "vsprintf", "scanf", "sscanf", "fscanf", "gets_s", "getwd", "realpath",
    "memcpy", "alloca", "mktemp", "tmpnam", "strncpy", "strncat", "snprintf", "read",
]
FORMAT_FUNCS = ("printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", "vsprintf",
                "vsnprintf", "dprintf", "syslog", "err", "warn", "setproctitle")
OVERFLOW_FUNCS = ("gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf", "fscanf",
                  "getwd", "realpath", "read", "fread", "memcpy", "alloca")
WIN_RX = re.compile(r"(?:^|_)(?:win|backdoor|flag|secret|shell|give|get[_]?flag|admin|magic|target|"
                    r"pwn|vuln|notcalled|print[_]?flag|cat[_]?flag|unlock|gift|debug)(?:$|_|\d)", re.I)


# ---------------------------------------------------------------------------- ELF reading

def _is_elf(data) -> bool:
    return isinstance(data, (bytes, bytearray)) and data[:4] == b"\x7fELF"


def _header(data: bytes) -> dict:
    """ELF identity from the header alone, stdlib only (works without pyelftools)."""
    cls = {1: 32, 2: 64}.get(data[4])
    endian = "<" if data[5] == 1 else ">"
    etype, machine = struct.unpack_from(endian + "HH", data, 16)
    if cls == 64:
        entry = struct.unpack_from(endian + "Q", data, 24)[0]
        phoff = struct.unpack_from(endian + "Q", data, 32)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", data, 54)
    else:
        entry = struct.unpack_from(endian + "I", data, 24)[0]
        phoff = struct.unpack_from(endian + "I", data, 28)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", data, 42)
    prim, spellings = MACHINES.get(machine, (f"em_{machine}", [f"em_{machine}"]))
    return {"class": cls, "endian": "little" if endian == "<" else "big", "endian_char": endian,
            "machine": machine, "arch": prim, "arch_spellings": spellings, "etype": etype,
            "type": ET.get(etype, f"et_{etype}"), "entry": entry,
            "phoff": phoff, "phentsize": phentsize, "phnum": phnum}


# Program-header p_type values we care about.
PT_INTERP, PT_GNU_STACK, PT_GNU_RELRO = 3, 0x6474E551, 0x6474E552
PF_X = 0x1
DT_FLAGS, DT_FLAGS_1, DT_BIND_NOW = 30, 0x6FFFFFFB, 24
DF_BIND_NOW, DF_1_NOW, DF_1_PIE = 0x08, 0x00000001, 0x08000000


def _segments(data: bytes, h: dict) -> list:
    """(p_type, p_flags) for each program header, stdlib only. [] on any malformed table."""
    out = []
    ec, cls = h["endian_char"], h["class"]
    off, ent, num = h["phoff"], h["phentsize"], h["phnum"]
    if not off or not cls or num in (0, 0xFFFF) or num > 4096:
        return out
    try:
        for i in range(num):
            base = off + i * ent
            if cls == 64:
                p_type, p_flags = struct.unpack_from(ec + "II", data, base)
            else:
                p_type = struct.unpack_from(ec + "I", data, base)[0]
                p_flags = struct.unpack_from(ec + "I", data, base + 24)
            out.append((p_type, p_flags))
    except struct.error:
        return out
    return out


def _with_pyelftools(data: bytes, h: dict):
    """Enrich `h` with symbols, dynamic symbols, relocations and sections when pyelftools is
    present. A failure leaves `h` as it was: the header facts still stand."""
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
        from elftools.elf.relocation import RelocationSection
        from elftools.elf.dynamic import DynamicSection
    except Exception:  # noqa: BLE001 - no pyelftools: header facts only
        return
    try:
        elf = ELFFile(io.BytesIO(data))
    except Exception:  # noqa: BLE001
        return
    syms, dyn_undef, funcs = [], [], []
    dyn_flags, dyn_flags_1, bind_now = 0, 0, False
    exec_sections, plt_relocs = [], []
    # Symbol-address / PLT / GOT resolution (row 8): deterministic recon facts, kept as name -> SET
    # of values so an ambiguous name (two defined symbols, two relocations) resolves to nothing.
    sym_values, got_offsets, plt_map = {}, {}, {}
    plt_order = []                       # (name, r_offset) in .rela.plt / .rel.plt order
    plt_geo = None                       # (sh_addr, sh_size, sh_entsize) of the one classic ".plt"
    has_plt_sec = False                  # ".plt.sec"/".plt.got" present -> PLT stub address is ambiguous
    try:
        for sec in elf.iter_sections():
            try:
                flags = sec["sh_flags"]
            except Exception:  # noqa: BLE001
                flags = 0
            nm = sec.name or ""
            if flags & 0x4 and sec["sh_type"] == "SHT_PROGBITS" and sec.data_size:  # SHF_EXECINSTR
                exec_sections.append((nm, sec["sh_addr"], sec.data()[:GADGET_SCAN]))
            if nm == ".plt":
                plt_geo = (sec["sh_addr"], sec["sh_size"], sec["sh_entsize"])
            elif nm in (".plt.sec", ".plt.got"):
                has_plt_sec = True
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    name = sym.name or ""
                    if not name:
                        continue
                    try:
                        stype = sym["st_info"]["type"]     # a pyelftools Container, not a plain dict
                    except Exception:  # noqa: BLE001
                        stype = ""
                    val = sym["st_value"]
                    shndx = sym["st_shndx"]
                    syms.append(name)
                    if stype == "STT_FUNC" and val and shndx != "SHN_UNDEF":
                        funcs.append((name, val))
                    # A defined function or data symbol with a real address: a resolvable fact.
                    if stype in ("STT_FUNC", "STT_OBJECT") and val and shndx != "SHN_UNDEF":
                        sym_values.setdefault(name, set()).add(val)
                    if shndx == "SHN_UNDEF" and stype in ("STT_FUNC", "STT_NOTYPE"):
                        dyn_undef.append(name)
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    t = tag.entry.d_tag
                    if t == "DT_FLAGS":
                        dyn_flags = tag.entry.d_val
                    elif t == "DT_FLAGS_1":
                        dyn_flags_1 = tag.entry.d_val
                    elif t == "DT_BIND_NOW":
                        bind_now = True
            if isinstance(sec, RelocationSection):
                if "plt" in nm or "got" in nm:
                    plt_relocs.append(nm)
                symtab = None
                try:
                    link = sec["sh_link"]
                    if link:
                        symtab = elf.get_section(link)
                except Exception:  # noqa: BLE001
                    symtab = None
                is_plt_reloc = nm in (".rela.plt", ".rel.plt")
                try:
                    for rel in sec.iter_relocations():
                        off = rel["r_offset"]
                        rname = ""
                        symidx = rel["r_info_sym"]
                        if symidx and isinstance(symtab, SymbolTableSection):
                            try:
                                rname = symtab.get_symbol(symidx).name or ""
                            except Exception:  # noqa: BLE001
                                rname = ""
                        if rname:
                            # r_offset is the address of the GOT slot patched for this symbol:
                            # the import address / GOT entry.
                            got_offsets.setdefault(rname, set()).add(off)
                        if is_plt_reloc:
                            plt_order.append((rname, off))
                except Exception:  # noqa: BLE001 - a truncated relocation table costs only its own facts
                    pass
    except Exception:  # noqa: BLE001 - a truncated table costs its own facts, not the header
        pass
    # PLT stub addresses, only for the unambiguous classic layout: a single ".plt" with a real
    # entry size, no ".plt.sec"/".plt.got", and a size of exactly one resolver header plus one
    # entry per relocation, in .rela.plt order. Anything else is left unresolved (never guessed).
    if plt_order and plt_geo and not has_plt_sec:
        p_addr, p_size, p_ent = plt_geo
        if p_ent and p_addr and p_size == p_ent * (len(plt_order) + 1):
            for i, (rname, _off) in enumerate(plt_order):
                if rname:
                    plt_map.setdefault(rname, set()).add(p_addr + (i + 1) * p_ent)
    h["symbols"] = sorted(set(syms))
    h["functions"] = funcs
    h["imports"] = sorted(set(dyn_undef))
    h["dyn_flags"], h["dyn_flags_1"], h["bind_now"] = dyn_flags, dyn_flags_1, bind_now
    h["exec_sections"] = exec_sections
    h["has_plt"] = bool(plt_relocs)
    h["sym_values"] = sym_values
    h["got_offsets"] = got_offsets
    h["plt_map"] = plt_map
    h["pyelftools"] = True


def read_elf(data: bytes) -> dict:
    """A static report of one ELF, or None when the bytes are not an ELF. Header-only without
    pyelftools; symbols/relocations/mitigations added when it is present. Never raises on content."""
    if not _is_elf(data) or len(data) < 20 or len(data) > MAX_FILE:
        return None
    try:
        h = _header(data)
    except (struct.error, IndexError):
        return None
    h.setdefault("symbols", [])
    h.setdefault("functions", [])
    h.setdefault("imports", [])
    h.setdefault("exec_sections", [])
    h.setdefault("has_plt", None)
    h.setdefault("sym_values", {})
    h.setdefault("got_offsets", {})
    h.setdefault("plt_map", {})
    h.setdefault("pyelftools", False)
    h["segments"] = _segments(data, h)
    _with_pyelftools(data, h)
    h["protections"] = _protections(h)
    names = set(h["imports"]) | set(h["symbols"])
    h["dangerous_imports"] = [f for f in DANGEROUS if f in names]
    h["format_funcs"] = sorted(n for n in names if any(n == f or n.endswith("_" + f) for f in FORMAT_FUNCS))
    h["overflow_funcs"] = sorted(n for n in names if n in OVERFLOW_FUNCS)
    h["win_candidates"] = [(n, v) for n, v in h["functions"] if WIN_RX.search(n)]
    return h


def _protections(h: dict) -> dict:
    """Checksec-style mitigations, each a tri-state string: 'enabled'/'disabled'/'unknown',
    RELRO 'full'/'partial'/'none'. Derived from the program headers, the dynamic flags and the
    symbol names only -- a static read, never a guarantee."""
    seg_types = {t for t, _ in h["segments"]}
    gnu_stack = [fl for t, fl in h["segments"] if t == PT_GNU_STACK]
    if gnu_stack:
        nx = "disabled" if (gnu_stack[0] & PF_X) else "enabled"
    elif h["segments"]:
        nx = "disabled"           # no GNU_STACK on a program with segments: stack is executable
    else:
        nx = "unknown"            # a relocatable/library with no program headers
    has_interp = PT_INTERP in seg_types
    flags1 = h.get("dyn_flags_1", 0)
    if h["etype"] == 3:           # ET_DYN
        if has_interp or (flags1 & DF_1_PIE):
            pie = "enabled"
        else:
            pie = "dso"           # a shared library, not a PIE executable
    elif h["etype"] == 2:
        pie = "disabled"          # ET_EXEC: fixed load address
    else:
        pie = "unknown"
    if PT_GNU_RELRO in seg_types:
        bind_now = h.get("bind_now") or (h.get("dyn_flags", 0) & DF_BIND_NOW) or (flags1 & DF_1_NOW)
        relro = "full" if bind_now else "partial"
    else:
        relro = "none"
    names = set(h["imports"]) | set(h["symbols"])
    canary = "enabled" if ("__stack_chk_fail" in names or "__stack_chk_guard" in names) else "disabled"
    fortify = "enabled" if any(n.endswith("_chk") for n in names) else "disabled"
    return {"nx": nx, "pie": pie, "relro": relro, "canary": canary, "fortify": fortify}


# ---------------------------------------------------------------------------- ROP gadgets (report only)

def enumerate_gadgets(h: dict, max_gadgets: int = MAX_GADGETS) -> list:
    """[(address, assembly)] of short ret-terminated gadgets in the executable sections, for a
    REPORT ONLY. x86/x86-64 only (capstone, in .venv); [] otherwise or when capstone is absent.
    Nothing is executed; this is a static disassembly listing."""
    if h["arch"] not in ("i386", "amd64"):
        return []
    try:
        import capstone
    except Exception:  # noqa: BLE001
        return []
    mode = capstone.CS_MODE_64 if h["class"] == 64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    out = []
    for _name, addr, code in h.get("exec_sections", []):
        if not code:
            continue
        for i, b in enumerate(code):
            if b != 0xC3:                      # `ret`
                continue
            start = max(0, i - GADGET_WINDOW)
            best = None
            for s in range(start, i + 1):
                try:
                    insns = list(md.disasm(bytes(code[s:i + 1]), addr + s))
                except Exception:  # noqa: BLE001
                    insns = []
                if insns and insns[-1].address == addr + i and insns[-1].mnemonic == "ret" and len(insns) <= 6:
                    best = "; ".join(f"{ins.mnemonic} {ins.op_str}".strip() for ins in insns)
                    break
            if best:
                out.append((addr + i, best))
                if len(out) >= max_gadgets:
                    return out
    return out


# ---------------------------------------------------------------------------- signals

_WORDS = re.compile(
    r"\brop\b|gadget|ret2|canary|stack[ _]?protect|\bnx\b|\bpie\b|relro|\bgot\b|\bplt\b|overflow|"
    r"format[ _]string|buffer|exploit|shellcode|one[_ ]?gadget|libc|pwntools|\bpwn\b|mitigation|"
    r"checksec|win function|backdoor|ret2win|ret2libc|\baslr\b|\belf\b|stack[ _]smash|gets\(", re.I)


def signals(questions, files) -> float:
    """0..1: how much the delivery and its questions look like a binary-exploitation (pwn) lane.
    An ELF (especially an executable or core) in the bytes, plus pwn vocabulary in the questions.
    0.0 when no ELF is present (so it never competes on a pcap, an e-mail or a 64-byte blob)."""
    elves, exe = 0, 0
    try:
        for _n, data in triage.unique_files(files or {}):
            if _is_elf(data):
                elves += 1
                try:
                    hh = _header(bytes(data))
                    if hh["etype"] in (2, 3, 4):
                        exe += 1
                except Exception:  # noqa: BLE001
                    pass
    except Exception:  # noqa: BLE001
        return 0.0
    if not elves:
        return 0.0
    score = 0.5 if exe else 0.4
    hits = set()
    for q in questions or []:
        f = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        text = " ".join(str(x or "") for x in (q.get("question"), q.get("answer_id") or q.get("id"),
                                               f.get("syntax")))
        hits |= {m.group().lower() for m in _WORDS.finditer(text)}
    score += min(0.4, 0.08 * len(hits))
    return round(min(1.0, score), 2)


# ---------------------------------------------------------------------------- answers (never-guess)

def _pick(field, shape, options):
    try:
        return labels.pick(f"{KEY}.{field}/{shape}", options)
    except ValueError:            # labels.py does not know the prefix
        return None


def _candidates(field, shape, options):
    try:
        return labels.candidates(f"{KEY}.{field}/{shape}", options)
    except ValueError:
        return None


def _elf_for(q, reps):
    """The ELF report a question is about: its named member, else the one ELF, else None when
    the question names a member no ELF matches or there is more than one ELF and no name."""
    member = q.get("member") or (str(q.get("artifact") or "").split(ARROW)[-1] if q.get("artifact") else "")
    base = Path(str(member)).name if member else ""
    if base:
        hit = [r for r in reps if Path(r[0]).name == base or r[0].split(ARROW)[-1] == member or r[0] == member]
        if len(hit) == 1:
            return hit[0][1]
        if hit:
            return None
    return reps[0][1] if len(reps) == 1 else None


def _spellings_for_value(primary, extra=()):
    """[(name, value)] spellings of ONE established fact, best first. Names are the spelling,
    values equal them: a state fact with several accepted wordings."""
    out, seen = [], set()
    for v in (primary, *extra):
        v = str(v)
        if v and v not in seen:
            seen.add(v)
            out.append((v, v))
    return out


_IDENT_RX = re.compile(r"[A-Za-z_][A-Za-z0-9_.@]*")
_QUOTED_RX = re.compile(r"[`'\"]([A-Za-z_][A-Za-z0-9_.@]*)")


def _symbol_named(text, aid_text, names):
    """The ONE symbol a question is about, chosen only from `names` (the symbols this binary
    actually carries for the field). A backtick/quote-delimited name wins; otherwise a bare token.
    None when the question names no present symbol, or names more than one: the symbol is never
    guessed, so an ambiguous question resolves to nothing (never-guess)."""
    if not names:
        return None
    present = set(names)
    quoted = present & set(_QUOTED_RX.findall(text or ""))
    if quoted:
        return next(iter(quoted)) if len(quoted) == 1 else None
    toks = set(_IDENT_RX.findall(text or "")) | set(_IDENT_RX.findall((aid_text or "").replace("-", " ")))
    hit = present & toks
    return next(iter(hit)) if len(hit) == 1 else None


def _unique(values):
    """The one value of a name -> set map entry, or None when absent or ambiguous (never guessed)."""
    if not values or len(values) != 1:
        return None
    return next(iter(values))


def _addr_candidates(field, shape, v, info):
    """An address as a candidate pick over its renderings (hex, decimal, zero-padded hex), exactly
    as `entry` is: the address is a byte-proven fact, but which rendering the judge accepts is not
    known, so it is never plain until the judge accepts a rendering name (row 346)."""
    return _candidates(field, shape, [("hex", hex(v)), ("dec", str(v)),
                                      ("hex_pad", f"0x{v:016x}" if info.get("class") == 64 else f"0x{v:08x}")])


def _route(text, aid_text):
    """The field a question asks about, from its words and answer-id tokens. One field or None."""
    t = (text + " " + aid_text).lower()

    def has(*words):
        return any(re.search(r"(?<![a-z])" + w + r"(?![a-z])", t) for w in words)

    if has("flag"):
        return "flag"
    if has("nx", "no.?execute", "dep", "executable stack", "non.?executable"):
        return "nx"
    if has("pie", "position.?independent", "aslr"):
        return "pie"
    if has("relro"):
        return "relro"
    if has("canary", "stack.?protector", "stack.?guard", "stack.?cookie", "ssp"):
        return "canary"
    if has("fortify", "_chk"):
        return "fortify"
    if has("mitigation", "protection", "checksec", "hardening"):
        return "mitigations"
    if has("endian", "endianness", "byte.?order"):
        return "endianness"
    if has("arch", "architecture", "machine", "isa", "processor", "cpu"):
        return "arch"
    if has("bit", "bits", "class", "word.?size", "32.?bit", "64.?bit"):
        return "bits"
    if has("gadget", "rop"):
        return "gadget"
    # GOT / import-address and PLT come BEFORE the entry-point check: "GOT entry" and "PLT entry"
    # carry the word "entry" but are not the program entry point. The word "got" counts only in a
    # GOT-table context (it is also an English verb); "plt" and the spelled-out tables are unambiguous.
    if (has("global.?offset.?table", "import.?address", "import.?table")
            or (has("got") and has("entry", "slot", "table", "address", "addr", "pointer", "ptr"))):
        return "got"
    if has("plt", "procedure.?linkage.?table"):
        return "plt"
    if has("entry.?point", "entrypoint") or (has("entry") and has("point", "program", "start")):
        return "entry"
    if has("win", "backdoor", "ret2win", "target function", "secret function"):
        return "win"
    if has("offset", "padding", "distance"):
        return "offset"
    if has("dangerous", "vulnerable", "unsafe", "insecure", "overflow", "format.?string",
           "banned", "risky"):
        return "vuln_func"
    if has("type", "object.?type", "elf.?type"):
        return "elf_type"
    # A generic "address of <symbol>" / "where is <symbol> located": last, so entry/win/got/plt
    # keep their own questions. It resolves to an answer only for a defined symbol the question
    # names; otherwise _answer_one returns None.
    if has("address", "addr", "vaddr", "located", "location"):
        return "sym_addr"
    return None


def _answer_one(q, info):
    """One question's answer: labels.pick / labels.candidates / None. Never plain, flag always None."""
    text = str(q.get("question") or "")
    aid_text = str(q.get("answer_id") or q.get("id") or q.get("qid") or "")
    field = _route(text, aid_text)
    if field is None or field == "flag":
        return None                                   # unknown field, or the flag: never derived
    prot = info["protections"]
    shape = f"elf{info['class'] or ''}"
    # Identity and mitigation facts VARY per binary (an NX-off recompile, an aarch64 build), so
    # the fact itself goes into the key shape: an accepted name under one value can never be
    # returned plain for a variant carrying another (new-code-audit-v2 H6; labels.pick returns
    # the key's accepted name even when it is not among the options offered).
    if field == "arch":
        return _pick("arch", f"elf+{info['machine']}",
                     _spellings_for_value(info["arch"], info["arch_spellings"]))
    if field == "bits":
        b = info["class"]
        if not b:
            return None
        return _pick("bits", f"elf+{b}", _spellings_for_value(str(b), [f"{b}-bit", f"{b}bit", f"x{b}"]))
    if field == "endianness":
        e = info["endian"]
        extra = ["le", "lsb", "little-endian"] if e == "little" else ["be", "msb", "big-endian"]
        return _pick("endianness", f"elf+{e}", _spellings_for_value(e, extra))
    if field == "elf_type":
        return _pick("elf_type", f"elf+{info['etype']}", _spellings_for_value(info["type"]))
    if field in ("nx", "pie", "relro", "canary", "fortify"):
        state = prot[field]
        if state == "unknown":
            return None
        if field == "relro":
            return _pick("relro", f"{shape}+{state}", _spellings_for_value(state))
        if state in ("enabled", "full", "partial"):
            extra = ["yes", "true", f"{field}_enabled", "present", "on"]
            return _pick(field, f"{shape}+enabled", _spellings_for_value("enabled", extra))
        if state in ("disabled", "dso", "none"):
            extra = ["no", "false", f"{field}_disabled", "absent", "off"]
            return _pick(field, f"{shape}+disabled", _spellings_for_value("disabled", extra))
        return None
    if field == "vuln_func":
        funcs = info.get("dangerous_imports") or []
        if not funcs:
            return None
        # A few DIFFERENT candidate functions: a candidate pick, ranked by danger (row 346).
        opts = [(f"rank{i + 1}", name) for i, name in enumerate(funcs[:labels.MAX_OPTIONS])]
        return _candidates("vuln_func", shape, opts)
    if field == "win":
        wins = info.get("win_candidates") or []
        if not wins:
            return None
        # The name is a judge label; the address is a candidate value under a few forms.
        if "name" in text.lower() and "address" not in text.lower() and "addr" not in aid_text.lower():
            opts = [(f"rank{i + 1}", name) for i, (name, _v) in enumerate(wins[:labels.MAX_OPTIONS])]
            return _candidates("win_name", shape, opts)
        opts = []
        for i, (_name, v) in enumerate(wins[:6]):
            opts.append((f"hex{i + 1}", hex(v)))
            opts.append((f"dec{i + 1}", str(v)))
        return _candidates("win_addr", shape, opts[:labels.MAX_OPTIONS])
    if field == "entry":
        v = info.get("entry")
        if not v:
            return None
        return _addr_candidates("entry", shape, v, info)
    if field in ("sym_addr", "got", "plt"):
        # row 8: a resolved symbol address, GOT/import-address slot, or PLT stub, derived from the
        # bytes (symbol table and relocations) for the ONE symbol the question names. Unknown
        # symbol, absent fact, or an ambiguous one (two symbols, two values) -> None: never guessed.
        table = {"sym_addr": info.get("sym_values", {}),
                 "got": info.get("got_offsets", {}),
                 "plt": info.get("plt_map", {})}[field]
        name = _symbol_named(text, aid_text, table)
        if name is None:
            return None
        v = _unique(table.get(name))
        if v is None:
            return None
        return _addr_candidates(field, shape, v, info)
    # gadget count/address, offset, mitigations count: tool-defined / unprovable -> None (never-guess).
    return None


def solve_set(questions, files, ctx) -> dict:
    """The runner contract (tools/verify.py, tools/run.py). Every answer is labels.pick,
    labels.candidates or None; nothing is ever plain, and the flag is always None."""
    reps = []
    try:
        for name, data in triage.unique_files(files or {}):
            r = read_elf(bytes(data))
            if r is not None:
                reps.append((name, r))
    except Exception:  # noqa: BLE001
        reps = []
    out = {}
    for q in questions or []:
        qid = q.get("qid") or q.get("id") or q.get("answer_id")
        if qid is None:
            continue
        info = _elf_for(q, reps)
        out[qid] = None if info is None else _answer_one(q, info)
    return out


# ---------------------------------------------------------------------------- CLI (offline triage)

def _report(name: str, info: dict) -> dict:
    gadgets = enumerate_gadgets(info)
    return {
        "file": name, "class": info["class"], "endian": info["endian"], "arch": info["arch"],
        "type": info["type"], "entry": hex(info["entry"]), "pyelftools": info["pyelftools"],
        "protections": info["protections"],
        "symbols": len(info["symbols"]), "functions": len(info["functions"]),
        "imports": len(info["imports"]), "has_plt": info.get("has_plt"),
        "resolvable_symbols": len(info.get("sym_values", {})),
        "got_entries": len(info.get("got_offsets", {})),
        "plt_entries": len(info.get("plt_map", {})),
        "dangerous_imports": info["dangerous_imports"],
        "format_funcs": info["format_funcs"], "overflow_funcs": info["overflow_funcs"],
        "win_candidates": [(n, hex(v)) for n, v in info["win_candidates"]],
        "gadgets_found": len(gadgets), "gadgets_sample": [(hex(a), g) for a, g in gadgets[:20]],
    }


def main(argv) -> int:
    as_json = "--json" in argv
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print("usage: pwn.py <file>... [--json]   (RECON ONLY: no binary is run, the flag is never derived)",
              file=sys.stderr)
        return 2
    reports = []
    for p in paths:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            print(f"pwn.py: {p}: {e}", file=sys.stderr)
            continue
        info = read_elf(data)
        if info is None:
            print(f"- {p}: not an ELF ({len(data)} bytes)")
            continue
        reports.append(_report(p, info))
    if as_json:
        print(json.dumps(reports, indent=1))
        return 0
    for r in reports:
        prot = r["protections"]
        print(f"# {r['file']}  ELF{r['class']} {r['endian']} {r['arch']} ({r['type']}) entry={r['entry']}")
        print(f"  mitigations: NX={prot['nx']} PIE={prot['pie']} RELRO={prot['relro']} "
              f"canary={prot['canary']} fortify={prot['fortify']}  (pyelftools={r['pyelftools']})")
        print(f"  symbols={r['symbols']} functions={r['functions']} imports={r['imports']} plt={r['has_plt']}")
        print(f"  resolvable: {r['resolvable_symbols']} symbol addr(s), {r['got_entries']} GOT entrie(s), "
              f"{r['plt_entries']} PLT stub(s)  (recon facts; an address is never guessed)")
        if r["dangerous_imports"]:
            print("  dangerous imports (FINDING, confirm in the code): " + ", ".join(r["dangerous_imports"]))
        if r["format_funcs"]:
            print("  format-string surface: " + ", ".join(r["format_funcs"]))
        if r["win_candidates"]:
            print("  win/backdoor candidates (RECON): " + ", ".join(f"{n}@{a}" for n, a in r["win_candidates"]))
        print(f"  ROP gadgets enumerated (report only, never executed): {r['gadgets_found']}")
        for a, g in r["gadgets_sample"]:
            print(f"    {a}: {g}")
        print("  the flag is never derived here and is answered None; a live target is a player stop "
              "(solvers/toolkits/pwn_target.py).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
