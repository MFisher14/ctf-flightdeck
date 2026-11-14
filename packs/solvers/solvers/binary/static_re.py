#!/usr/bin/env python3
"""Bounded static-RE fallback for a lone Binary Single Solve.

This reader exists for the reverse-engineering challenge shape that is not the
cumulative ``dNN_*`` HCFG exercise: one delivery, ordinary answer ids, and a
question about the bytes of a program.  It is deliberately narrower than an
interactive reverse engineer:

* it selects one executable by its bytes (or an explicitly named member), not
  by an answer-id prefix;
* it never invokes the delivery as a host program;
* it disassembles exact bounded symbol-backed ELF functions, and may hand one stripped entrypoint-
  referenced pure decoder to the whole-image emulator by virtual address;
* it asks the shipped straight-line symbolic lifter to recover a crackme input
  only when the question states the input length and success return convention;
* it identifies a packer only from executable structure/signatures; and
* every new rendering is ``labels.candidates`` until the judge accepts its
  hypothesis.  Unsupported, incomplete, or ambiguous evidence is ``None``.

The fallback is gated to a non-timed Single Solve on the final two release days,
so it cannot move a historical cumulative answer or synthetic future-prefix tests.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
TOOLKITS = HERE.parent / "toolkits"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))
import labels  # noqa: E402
import answer_kinds  # noqa: E402

MAX_FILE = 64 * 1024 * 1024
MAX_FUNCTION = 4096
MAX_INSNS = 512
MAX_INPUT = 128
SYMBOLIC_TIMEOUT_MS = 1800

DAY_ID = re.compile(r"^(?:set\d+\.)?d0*(\d+)(?:_|$)", re.I)
ROUTE_DAY = re.compile(r"(?:^|[^a-z0-9])day[-_ ]*0*(\d+)(?:[^0-9]|$)", re.I)
STATIC_WORDS = re.compile(
    r"\b(?:disassembl(?:e|y)|instructions?|mnemonics?|opcode|immediate|crackme|serial|pass(?:word|code)|"
    r"accepted input|valid input|check(?:er| function)|key check|packer|packed|packing|protector|obfuscat|"
    r"decoder|decode routine|return value|abi argument|entry point|architecture|machine|file format|sha-?256|"
    r"file size)\b", re.I)
CRACKME_WORDS = re.compile(
    r"\b(?:input|key|password|passcode|serial|license)\b", re.I)
CRACKME_ACTION = re.compile(
    r"\b(?:recover|derive|determine|find|solve|cause[sd]?|make[sd]?|accepted|accepts?|valid|satisf(?:y|ies))\b", re.I)
DISASM_WORDS = re.compile(r"\b(?:disassembl(?:e|y)|instructions?|mnemonics?|opcode|immediate|assembly)\b", re.I)
PACKER_WORDS = re.compile(r"\b(?:packer|packed with|packing|protector|compressor)\b", re.I)

_SYMBOLIC = []


def _qid(q) -> str:
    return str(q.get("qid") or q.get("id") or "") if isinstance(q, dict) else str(q or "")


def _text(q) -> str:
    if not isinstance(q, dict):
        return str(q or "")
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    return " ".join(str(x or "") for x in (_qid(q), q.get("question"), fmt.get("syntax")))


def covers_question(q) -> bool:
    """Whether this reader has a bounded rule for the question's *shape*.

    This shape predicate is shared by the runtime eligibility gate and the
    bounded answer rules; a malformed/ambiguous artifact still returns None.
    ``evidence.covers()`` deliberately has no attempt context and therefore
    does not use the static adapter to green-light any timed contract.
    """
    text = _text(q)
    return bool(STATIC_WORDS.search(text) or
                (CRACKME_WORDS.search(text) and re.search(r"\b(?:function|routine|symbol)\b", text, re.I)
                 and re.search(r"\breturns?\b", text, re.I)))


def eligible(questions, files=None, ctx=None) -> bool:
    """True only for the lone/static Single Solve contract.

    Historical d01--d29 sets are an absolute opt-out.  A timed route is also an
    opt-out even if a response happens to call it a single set.
    """
    qs = list(questions or [])
    if not qs or not any(covers_question(q) for q in qs):
        return False
    # covers(questions) has no route/attempt context.  It must not turn a timed
    # contract green from wording alone, so only the actual solve context can
    # enable this adapter.
    if not isinstance(ctx, dict) or not isinstance(ctx.get("attempt"), dict):
        return False
    attempt = ctx.get("attempt") if isinstance(ctx.get("attempt"), dict) else {}
    route = " ".join(str(attempt.get(k) or "")
                     for k in ("challenge", "challenge_id", "_challenge_id", "id", "mode")).lower()
    if "time_trial" in route or "time trial" in route or "mastery" in route:
        return False
    if attempt.get("deadline") is not None:
        return False
    route_days = [int(value) for value in ROUTE_DAY.findall(route)]
    if route_days and any(day not in (30, 31) for day in route_days):
        return False
    days = []
    for q in qs:
        m = DAY_ID.match(_qid(q))
        if m:
            days.append(int(m.group(1)))
    # d97/d99 are deliberately used by the Binary look-ahead tests as generic
    # unknown-prefix stand-ins.  The static adapter is for the two actual final
    # release days, not a replacement for every future dNN generic contract.
    if days and any(day not in (30, 31) for day in days):
        return False
    # When mode is present, accept only a standard/single spelling.  The live
    # response has used both underscore and display-name forms over the event.
    mode = str(attempt.get("mode") or "").strip().lower().replace("-", "_").replace(" ", "_")
    if mode and mode not in {"single", "single_solve", "standard", "standard_single_solve"}:
        return False
    if not days and not mode:
        return False
    return True


def _macho(data: bytes) -> bool:
    """Structurally validate a thin/fat Mach-O header.

    ``CA FE BA BE`` is also a Java class magic.  A magic-only check therefore
    routes ordinary class files as fat Mach-O; validate every architecture row
    and its bounded slice before calling it Mach-O.
    """
    magic = data[:4]
    thin = {
        b"\xfe\xed\xfa\xce": (">", 28), b"\xce\xfa\xed\xfe": ("<", 28),
        b"\xfe\xed\xfa\xcf": (">", 32), b"\xcf\xfa\xed\xfe": ("<", 32),
    }
    if magic in thin:
        end, head = thin[magic]
        if len(data) < head:
            return False
        try:
            cpu, filetype, ncmds, commands = struct.unpack_from(end + "I4xIII", data, 4)
            return cpu != 0 and 1 <= filetype <= 12 and ncmds <= 4096 and head + commands <= len(data)
        except struct.error:
            return False
    fat = {
        b"\xca\xfe\xba\xbe": (">", 20), b"\xbe\xba\xfe\xca": ("<", 20),
        b"\xca\xfe\xba\xbf": (">", 32), b"\xbf\xba\xfe\xca": ("<", 32),
    }
    if magic not in fat or len(data) < 8:
        return False
    end, width = fat[magic]
    try:
        count = struct.unpack_from(end + "I", data, 4)[0]
        if not 1 <= count <= 32 or 8 + count * width > len(data):
            return False
        spans = []
        for i in range(count):
            at = 8 + i * width
            if width == 20:
                cpu, _sub, off, size, align = struct.unpack_from(end + "IIIII", data, at)
            else:
                cpu, _sub, off, size, align, _reserved = struct.unpack_from(end + "IIQQII", data, at)
            if cpu == 0 or size == 0 or align > 31 or off < 8 + count * width or off + size > len(data):
                return False
            spans.append((off, off + size))
        spans.sort()
        return all(spans[i - 1][1] <= spans[i][0] for i in range(1, len(spans)))
    except (IndexError, struct.error):
        return False


def _kind(data: bytes) -> str | None:
    if len(data) >= 20 and data[:4] == b"\x7fELF" and data[4] in (1, 2) and data[5] in (1, 2):
        return "elf"
    if len(data) > 0x40 and data[:2] == b"MZ":
        try:
            nt = struct.unpack_from("<I", data, 0x3C)[0]
            if 0x40 <= nt <= len(data) - 24 and data[nt:nt + 4] == b"PE\0\0":
                return "pe"
        except (IndexError, struct.error):
            pass
    if _macho(data):
        return "macho"
    return None


def _bodies(files, ctx) -> list[tuple[str, bytes, str | None]]:
    """Distinct bounded bodies, retaining a useful name for member selection."""
    rows = []
    if isinstance(files, dict):
        rows.extend((str(n), bytes(b)) for n, b in files.items()
                    if isinstance(b, (bytes, bytearray)) and 0 < len(b) <= MAX_FILE)
    if isinstance(ctx, dict) and isinstance(ctx.get("delivery"), (bytes, bytearray)):
        b = bytes(ctx["delivery"])
        if 0 < len(b) <= MAX_FILE:
            rows.append((str(ctx.get("delivery_name") or "delivery"), b))
    unique = {}
    for name, body in rows:
        digest = hashlib.sha256(body).digest()
        # Prefer a member path over the archive-level alias for diagnostics and
        # an explicitly named question member.
        old = unique.get(digest)
        if old is None or (" -> " in name and " -> " not in old[0]):
            unique[digest] = (name, body, _kind(body))
    return list(unique.values())


def select_artifact(q, files, ctx):
    """One byte-selected executable, never a prefix/file-name guess."""
    rows = _bodies(files, ctx)
    member = str(q.get("member") or "").strip() if isinstance(q, dict) else ""
    if member:
        named = [r for r in rows if Path(r[0].split(" -> ")[-1]).name == Path(member).name]
        named = [r for r in named if r[2] is not None]
        if len(named) == 1:
            return named[0]
        if len(named) > 1:
            return None
    executables = [r for r in rows if r[2] is not None]
    if len(executables) == 1:
        return executables[0]
    # A raw-code task is allowed only when the question itself says raw machine
    # code/shellcode and there is literally one distinct body.
    if len(rows) == 1 and re.search(r"\b(?:raw machine code|raw x86|shellcode)\b", _text(q), re.I):
        return rows[0][0], rows[0][1], "raw"
    return None


def _symbolic():
    if _SYMBOLIC:
        return _SYMBOLIC[0]
    try:
        spec = importlib.util.spec_from_file_location("binary_static_symbolic", TOOLKITS / "symbolic.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception as exc:  # missing z3/capstone is a clean unsupported shape
        print(f"[static_re] symbolic lifter unavailable ({type(exc).__name__}: {exc})", file=sys.stderr)
        mod = None
    _SYMBOLIC.append(mod)
    return mod


def _elf_functions(data: bytes) -> tuple[str | None, int | None, list[dict]]:
    """(arch, bits, exact symbol-backed function regions), bounded and static."""
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
        elf = ELFFile(io.BytesIO(data))
        arch = {3: "i386", 62: "amd64"}.get(int(elf.header["e_machine"]) if isinstance(elf.header["e_machine"], int)
                                             else {"EM_386": 3, "EM_X86_64": 62}.get(elf.header["e_machine"], -1))
        bits = int(elf.elfclass)
        if arch is None or bits not in (32, 64):
            return None, bits, []
        out, seen = [], set()
        for tab in elf.iter_sections():
            if not isinstance(tab, SymbolTableSection):
                continue
            for sym in tab.iter_symbols():
                try:
                    if sym["st_info"]["type"] != "STT_FUNC" or not sym.name:
                        continue
                    ndx, size, addr = sym["st_shndx"], int(sym["st_size"]), int(sym["st_value"])
                    if not isinstance(ndx, int) or not 1 <= size <= MAX_FUNCTION:
                        continue
                    sec = elf.get_section(ndx)
                    off = addr - int(sec["sh_addr"])
                    body = sec.data()
                    if off < 0 or off + size > len(body) or not (int(sec["sh_flags"]) & 0x4):
                        continue
                    code = bytes(body[off:off + size])
                    key = (sym.name, addr, code)
                    if key not in seen:
                        seen.add(key)
                        out.append({"name": sym.name, "address": addr, "code": code})
                except (IndexError, KeyError, TypeError, ValueError):
                    continue
        return arch, bits, out
    except Exception:
        return None, None, []


def _named_function(text: str, functions: list[dict]):
    hits = []
    for fn in functions:
        name = fn["name"]
        # A sentence-ending period after an ordinary C symbol is punctuation,
        # not a continuation of the symbol.  Dots *inside* a symbol remain part
        # of re.escape(name) itself.
        if re.search(rf"(?<![A-Za-z0-9_$]){re.escape(name)}(?![A-Za-z0-9_$])", text):
            hits.append(fn)
    # Two symbol tables often repeat exactly the same function; _elf_functions
    # already deduplicates those.  Two mentioned functions are ambiguous.
    return hits[0] if len(hits) == 1 else None


def _disassemble(arch: str, bits: int, fn: dict):
    try:
        import capstone
        from capstone import x86
        mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
        md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        md.detail = True
        insns = list(md.disasm(fn["code"], fn["address"]))
        if not insns or len(insns) > MAX_INSNS:
            return None
        if insns[0].address != fn["address"] or sum(i.size for i in insns) != len(fn["code"]):
            return None
        return insns, x86
    except Exception:
        return None


def _scope_sha256(*parts) -> str:
    """Full SHA-256 of a length-delimited scope transcript.

    Static-RE keys have never been accepted by the judge, so there is no historical key to preserve.  Keep
    every candidate-only artifact/question/function scope collision-resistant rather than using CRC-32 or a
    truncated digest.  Length framing also prevents two different tuples from sharing a concatenation.
    """
    digest = hashlib.sha256()
    for part in parts:
        if isinstance(part, str):
            raw = part.encode("utf-8", "replace")
        elif isinstance(part, (bytes, bytearray)):
            raw = bytes(part)
        else:
            raw = str(part).encode("utf-8", "replace")
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def _question_scope(q) -> str:
    return _scope_sha256(" ".join(_text(q).lower().split()))


def _tag(q) -> str:
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    kind = str(fmt.get("kind") or "text").lower()
    syntax = " ".join(str(fmt.get("syntax") or "").lower().split())
    return f"{kind}+syntax_sha256_{_scope_sha256(syntax)}"


def _candidate(key: str, options):
    # Deduplicate equal values without trying to hash JSON containers.
    out, seen = [], set()
    for name, value in options:
        try:
            mark = json.dumps(value, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            continue
        if mark in seen:
            continue
        seen.add(mark)
        out.append((name, value))
    return labels.candidates(key, out)


def _input_length(text: str) -> int | None:
    pats = (
        r"\b(\d{1,3})\s*(?:-|\s)?(?:byte|character|char)s?\b",
        r"\b(?:input|key|password|passcode|serial)(?:'s)?\s+length\s+(?:is\s+|of\s+)?(\d{1,3})\b",
        r"\blength\s+(?:is\s+|of\s+)?(\d{1,3})\b",
    )
    vals = {int(m.group(1)) for p in pats for m in re.finditer(p, text, re.I)}
    vals = {n for n in vals if 1 <= n <= MAX_INPUT}
    return next(iter(vals)) if len(vals) == 1 else None


def _success_return(text: str):
    low = text.lower()
    if not re.search(r"\b(?:success|accepted|valid|correct)\b", low) or "return" not in low:
        return None
    good = r"(?:success|accepted|valid|correct)(?:\s+input|\s+key)?"

    def linked(value):
        ret = rf"(?:returns?|return\s+value|result)(?:\s+(?:of|is|=|the|integer))*\s*{value}"
        tie = rf"(?:on|for|when|means|indicates|exactly\s+for)\s+(?:a\s+)?{good}"
        return bool(re.search(rf"\b{ret}\b\s*(?:,|;|iff|if)?\s*{tie}\b", low)
                    or re.search(rf"\b{value}\b\s*{tie}\b", low)
                    or re.search(rf"\b{good}\b.{{0,32}}\b{ret}\b", low))

    nonzero = linked(r"(?:non[- ]?zero|true|1)")
    zero = linked(r"(?:(?<!non-)(?<!non )zero|false|0)")
    if nonzero == zero:
        return None
    return "nonzero" if nonzero else "zero"


def _charset(text: str):
    low = text.lower()
    if re.search(r"\bprintable(?:\s+ascii)?\b", low):
        return range(0x20, 0x7f), "printable"
    if re.search(r"\blowercase(?:\s+ascii)?(?:\s+letters?)?\b", low):
        return range(ord("a"), ord("z") + 1), "lower"
    if re.search(r"\buppercase(?:\s+ascii)?(?:\s+letters?)?\b", low):
        return range(ord("A"), ord("Z") + 1), "upper"
    if re.search(r"\balphanumeric\b", low):
        return (list(range(ord("0"), ord("9") + 1)) + list(range(ord("A"), ord("Z") + 1))
                + list(range(ord("a"), ord("z") + 1))), "alnum"
    return None, "bytes"


def _render_input(q, values: list[bytes], unique: bool, scope: str):
    text = _text(q).lower()
    opts = []
    # Z3 does not promise model-enumeration order.  A candidate name is the
    # ledger identity of its hypothesis, so ordinal names (model1/model2)
    # could silently bind an accepted name to a different value on replay.
    # Sort/deduplicate the bytes and name non-unique hypotheses by their own
    # digest; the same name can then never denote another candidate value.
    ordered = sorted(set(values))
    for raw in ordered:
        stem = ("unique" if unique
                else "model_sha256_" + hashlib.sha256(raw).hexdigest())
        printable = bool(raw) and all(0x20 <= b < 0x7f for b in raw)
        if printable:
            opts.append((stem + "_exact_text", raw.decode("ascii")))
        if re.search(r"\bhex(?:adecimal)?\b|\bhex\b", text) or not printable:
            opts.append((stem + "_lower_hex", raw.hex()))
            opts.append((stem + "_0x_lower_hex", "0x" + raw.hex()))
    # lift_linear models every out-of-symbol conditional edge as a rejected
    # path.  The question states the return convention, but an accepted cold
    # split can still differ between builds.  Scope acceptance to these exact
    # bytes so a probe can replay this Single Solve plain but can never bless a
    # different control-flow shape.
    question_tag = _question_scope(q)
    scope_tag = scope if re.fullmatch(r"[0-9a-f]{64}", str(scope)) else _scope_sha256(scope)
    shape = f"elf+x86+{_tag(q)}+qsha256_{question_tag}+scope_sha256_{scope_tag}"
    return _candidate(f"binary.static_input/{shape}", opts)


def _crackme(q, data: bytes):
    text = _text(q)
    if not (CRACKME_WORDS.search(text) and CRACKME_ACTION.search(text)):
        return None
    n = _input_length(text)
    success = _success_return(text)
    if n is None or success is None:
        return None
    arch, bits, funcs = _elf_functions(data)
    fn = _named_function(text, funcs)
    symbolic = _symbolic()
    if fn is None or symbolic is None or arch not in ("amd64", "i386"):
        return None
    charset, _charset_name = _charset(text)
    try:
        sol = symbolic.lift_linear(fn["code"], n, arch=arch, bits=bits, base=fn["address"],
                                   charset=charset, success_return=success,
                                   timeout_ms=SYMBOLIC_TIMEOUT_MS, max_candidates=labels.MAX_OPTIONS)
    except Exception:
        return None
    scope = _scope_sha256(hashlib.sha256(data).digest(), fn["name"],
                          fn["address"].to_bytes(8, "little"), fn["code"])
    if sol.status == symbolic.UNIQUE and isinstance(sol.plain(), bytes):
        return _render_input(q, [sol.plain()], True, scope)
    if sol.status == symbolic.MULTIPLE:
        vals = [v for v in sol.candidate_values() if isinstance(v, bytes)]
        return _render_input(q, vals, False, scope) if vals else None
    return None


def _disassembly_fact(q, data: bytes):
    text = _text(q)
    if not DISASM_WORDS.search(text):
        return None
    arch, bits, funcs = _elf_functions(data)
    fn = _named_function(text, funcs)
    decoded = _disassemble(arch, bits, fn) if fn is not None and arch else None
    if decoded is None:
        return None
    insns, x86 = decoded
    # Every candidate name below describes an answer *representation*, while
    # its value is specific to this artifact, question, and function.  Scope
    # the ledger key accordingly so an accepted ``full_json`` (or immediate,
    # count, or mnemonic) from one crackme can never become a confident value
    # for a later binary that happens to ask the same-shaped question.
    scope = _scope_sha256(hashlib.sha256(data).digest(), text, fn["name"],
                          fn["address"].to_bytes(8, "little"), fn["code"])
    key = f"binary.static_disassembly/elf+x86+{_tag(q)}+scope_sha256_{scope}"
    low = text.lower()
    if re.search(r"\b(?:instruction|opcode)s?\s+count\b|\bhow many\s+instructions?\b", low):
        return _candidate(key + "+count", [("exact_symbol_instruction_count", len(insns))])
    if "mnemonic" in low and re.search(r"\bfirst\b", low):
        return _candidate(key + "+first_mnemonic", [("capstone_mnemonic", insns[0].mnemonic)])
    if "mnemonic" in low and re.search(r"\blast\b", low):
        return _candidate(key + "+last_mnemonic", [("capstone_mnemonic", insns[-1].mnemonic)])
    if re.search(r"\b(?:immediate|constant)\b", low):
        vals = []
        for ins in insns:
            if ins.mnemonic not in ("cmp", "test"):
                continue
            for op in ins.operands:
                if op.type == x86.X86_OP_IMM:
                    vals.append(int(op.imm))
        vals = list(dict.fromkeys(vals))
        if len(vals) != 1:
            return None
        v = vals[0]
        return _candidate(key + "+compare_immediate", [("signed_decimal", str(v)),
                                                         ("lower_hex", hex(v & ((1 << 64) - 1)))])
    full = [f"{ins.mnemonic} {ins.op_str}".strip() for ins in insns]
    mnemonics = [ins.mnemonic for ins in insns]
    return _candidate(key + "+listing", [("full_json", full), ("mnemonic_json", mnemonics),
                                          ("semicolon_text", "; ".join(full)),
                                          ("newline_text", "\n".join(full))])


def _pe_sections(data: bytes) -> list[str]:
    try:
        nt = struct.unpack_from("<I", data, 0x3C)[0]
        nsec, opt = struct.unpack_from("<H12xH", data, nt + 6)
        if not 1 <= nsec <= 96:
            return []
        at, out = nt + 24 + opt, []
        for i in range(nsec):
            raw = data[at + i * 40:at + i * 40 + 8]
            if len(raw) != 8:
                return []
            out.append(raw.rstrip(b"\0").decode("ascii", "strict").lower())
        return out
    except (IndexError, UnicodeDecodeError, struct.error):
        return []


def _packer_name(kind: str, data: bytes) -> str | None:
    if kind == "pe":
        sec = set(_pe_sections(data))
        checks = (
            ("upx", ({"upx0", "upx1"} <= sec) or ("upx!" in sec and b"UPX!" in data)),
            ("aspack", {".aspack", ".adata"} <= sec),
            ("mpress", {".mpress1", ".mpress2"} <= sec),
            ("themida", ".themida" in sec),
            ("vmprotect", {".vmp0", ".vmp1"} <= sec),
        )
        hits = [name for name, yes in checks if yes]
        return hits[0] if len(hits) == 1 else None
    if kind == "elf" and b"UPX!" in data and (b"$Info:" in data or b"UPX0" in data or b"UPX1" in data):
        return "upx"
    return None


def _analysis_image(kind: str, data: bytes):
    """Bytes safe to disassemble, or None when a recognized packer stayed packed.

    UPX is decompressed through the Binary lane's existing bounded static
    unpacker (sandboxed off-clock); the delivered program is never executed.
    Other recognized protectors are identified for a packer question but their
    stubs are not mistaken for the protected function.
    """
    packer = _packer_name(kind, data)
    if packer is None:
        return data
    if packer != "upx":
        return None
    try:
        import facts
        inner, _note = facts.unpack_upx(data, timeout=2.0)
    except (Exception, SystemExit):
        return None
    if not isinstance(inner, bytes) or not 0 < len(inner) <= MAX_FILE or _kind(inner) != kind:
        return None
    return inner


def _meta(q, kind: str, data: bytes):
    text = _text(q).lower()
    # These are candidate *interpretations* (whole delivered executable,
    # structural packer signature, header rendering), not universal labels.
    # Scope the ledger key to both the normalized question and selected bytes
    # so an accepted hypothesis cannot become plain for a semantically
    # different question or a later look-alike executable.
    question_tag = _question_scope(q)
    artifact_tag = hashlib.sha256(data).hexdigest()
    key = (f"binary.static_fact/{kind}+{_tag(q)}+qsha256_{question_tag}"
           f"+scope_sha256_{artifact_tag}")
    if re.search(r"\bsha-?256\b", text):
        return _candidate(key + "+sha256", [("whole_artifact", hashlib.sha256(data).hexdigest())])
    if re.search(r"\bfile size\b|\bsize in bytes\b", text):
        return _candidate(key + "+size", [("whole_artifact_bytes", len(data))])
    if re.search(r"\b(?:packer|packed with|packing|protector|compressor)\b", text):
        name = _packer_name(kind, data)
        return _candidate(key + "+packer", [("structural_signature", name)]) if name else None
    if re.search(r"\bfile format\b|\bexecutable format\b", text):
        return _candidate(key + "+format", [("header", {"elf": "elf", "pe": "pe", "macho": "mach_o"}.get(kind))])
    if kind == "elf" and re.search(r"\b(?:architecture|machine)\b", text):
        arch, bits, _ = _elf_functions(data)
        value = {("amd64", 64): "x86-64", ("i386", 32): "x86"}.get((arch, bits))
        return _candidate(key + "+architecture", [("elf_header", value)]) if value else None
    if kind == "elf" and re.search(r"\bentry point\b", text):
        try:
            end = "<" if data[5] == 1 else ">"
            entry = struct.unpack_from(end + ("Q" if data[4] == 2 else "I"), data, 24)[0]
        except (IndexError, struct.error):
            return None
        return _candidate(key + "+entry", [("lower_0x", hex(entry)), ("decimal", str(entry))])
    return None


def _fit(q, value):
    if value is None:
        return None
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else None
    if not fmt:
        return value
    try:
        return answer_kinds.fit(value, fmt, _qid(q))[0]
    except Exception:
        return None


def answer(q, files, ctx):
    if not covers_question(q):
        return None
    selected = select_artifact(q, files, ctx)
    if selected is None:
        return None
    _name, data, kind = selected
    analysis = _analysis_image(kind, data)
    behavior_contract = False
    if kind == "elf" and analysis is not None:
        value = _crackme(q, analysis)
        if value is None:
            try:
                import native_behavior
                behavior_contract = native_behavior.asks(q)
                value = native_behavior.answer(q, analysis)
            except (Exception, SystemExit) as exc:
                print(f"[static_re] native behavior fallback stopped at {type(exc).__name__}: {str(exc)[:160]}",
                      file=sys.stderr)
                value = None
        if value is None:
            value = _disassembly_fact(q, analysis)
    else:
        value = None
    # A semantic decoder question that the behavior path cannot prove must remain None.  Its
    # incidental words (for example "entry point calls it") are not a request for the ELF entry
    # address and must not fall through to _meta's structural fact reader.
    if value is None and not behavior_contract:
        value = _meta(q, kind, data)
    return _fit(q, value)


def answers(questions, files, ctx) -> dict:
    """Answers for recognized open ids.  Ambiguity is intentionally retained as None."""
    out = {}
    if not eligible(questions, files, ctx):
        return out
    for q in questions or []:
        qid = _qid(q)
        if not qid:
            continue
        try:
            out[qid] = answer(q, files, ctx)
        except (Exception, SystemExit) as exc:
            print(f"[static_re] {qid}: static reader stopped at {type(exc).__name__}: {str(exc)[:160]}",
                  file=sys.stderr)
            out[qid] = None
    return out
