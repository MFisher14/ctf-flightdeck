"""Bounded structural lifters for common managed bytecode formats.

The lifters consume immutable byte strings already extracted by the caller.
They do not invoke Python/Lua/.NET/JVM/WebAssembly runtimes, load code objects,
or execute instructions.  Python ``.pyc`` support deliberately separates the
header from caller-supplied raw wordcode so no runtime object decoder is used.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
import struct
from typing import Mapping, Sequence


MAX_BYTECODE = 16 << 20
MAX_INSTRUCTIONS = 200_000
MAX_SWITCH_TARGETS = 4096
MAX_FUNCTIONS = 10_000


class LiftError(ValueError):
    """Malformed, truncated, unsupported, or cap-exceeding bytecode."""


@dataclass(frozen=True)
class IRInstruction:
    offset: int
    mnemonic: str
    operands: tuple[str, ...] = ()
    branch_targets: tuple[int, ...] = ()
    annotation: str = ""

    def render(self) -> str:
        operand_text = ", ".join(self.operands)
        targets = "" if not self.branch_targets else " -> " + ", ".join(
            f"0x{target:x}" for target in self.branch_targets
        )
        annotation = "" if not self.annotation else f" ; {self.annotation}"
        return f"{self.offset:06x}: {self.mnemonic}{(' ' + operand_text) if operand_text else ''}{targets}{annotation}"


@dataclass(frozen=True)
class LiftResult:
    dialect: str
    version: str
    instructions: tuple[IRInstruction, ...]
    warnings: tuple[str, ...] = ()

    def render(self) -> str:
        header = f"; {self.dialect} {self.version}".rstrip()
        lines = [header, *(instruction.render() for instruction in self.instructions)]
        lines.extend(f"; warning: {warning}" for warning in self.warnings)
        return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class PycHeader:
    magic_hex: str
    header_size: int
    hash_based: bool
    checked_hash: bool
    timestamp: int | None
    source_size: int | None
    source_hash_hex: str | None


@dataclass(frozen=True)
class LuaHeader:
    version: str
    format: int
    endian: str | None
    integer_size: int | None
    size_t_size: int | None
    instruction_size: int | None
    number_size: int | None


@dataclass(frozen=True)
class WasmModuleIR:
    version: int
    sections: tuple[tuple[int, int], ...]
    functions: tuple[LiftResult, ...]

    def to_dict(self) -> dict:
        return asdict(self)


def _bytes(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("bytecode must be immutable bytes")
    if len(data) > MAX_BYTECODE:
        raise LiftError("bytecode exceeds the 16 MiB cap")
    return data


class _Cursor:
    def __init__(self, data: bytes, endian: str = "little"):
        self.data = data
        self.offset = 0
        self.endian = endian

    def remaining(self) -> int:
        return len(self.data) - self.offset

    def take(self, size: int) -> bytes:
        if not isinstance(size, int) or size < 0 or self.offset + size > len(self.data):
            raise LiftError("truncated bytecode operand")
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def integer(self, size: int, *, signed: bool = False, endian: str | None = None) -> int:
        return int.from_bytes(self.take(size), endian or self.endian, signed=signed)

    def uleb(self, max_bytes: int = 5) -> int:
        value = 0
        for index in range(max_bytes):
            byte = self.u8()
            value |= (byte & 0x7F) << (index * 7)
            if not byte & 0x80:
                return value
        raise LiftError("unsigned LEB128 exceeds its cap")

    def sleb(self, max_bytes: int = 5) -> int:
        value = 0
        byte = 0
        shift = 0
        for _ in range(max_bytes):
            byte = self.u8()
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                if byte & 0x40:
                    value |= -(1 << shift)
                return value
        raise LiftError("signed LEB128 exceeds its cap")


# --------------------------------------------------------------------------- Python


def inspect_pyc_header(data: bytes, *, header_size: int = 16) -> PycHeader:
    """Parse only the fixed pyc header; the payload remains opaque bytes."""
    data = _bytes(data)
    if header_size not in {12, 16}:
        raise ValueError("pyc header_size must be 12 or 16")
    if len(data) < header_size or data[2:4] != b"\r\n" or data[:2] == b"\0\0":
        raise LiftError("invalid or truncated pyc header")
    magic = data[:4].hex()
    if header_size == 12:
        timestamp, source_size = struct.unpack_from("<II", data, 4)
        return PycHeader(magic, 12, False, False, timestamp, source_size, None)
    flags = struct.unpack_from("<I", data, 4)[0]
    if flags & ~0x03:
        raise LiftError("pyc flags contain reserved bits")
    if flags & 1:
        return PycHeader(magic, 16, True, bool(flags & 2), None, None, data[8:16].hex())
    timestamp, source_size = struct.unpack_from("<II", data, 8)
    return PycHeader(magic, 16, False, False, timestamp, source_size, None)


_PY311 = {
    0: "CACHE", 1: "POP_TOP", 2: "PUSH_NULL", 9: "NOP", 83: "RETURN_VALUE",
    90: "STORE_NAME", 91: "DELETE_NAME", 92: "UNPACK_SEQUENCE", 93: "FOR_ITER",
    95: "STORE_ATTR", 97: "STORE_GLOBAL", 100: "LOAD_CONST", 101: "LOAD_NAME",
    102: "BUILD_TUPLE", 103: "BUILD_LIST", 104: "BUILD_SET", 105: "BUILD_MAP",
    106: "LOAD_ATTR", 107: "COMPARE_OP", 108: "IMPORT_NAME", 109: "IMPORT_FROM",
    110: "JUMP_FORWARD", 111: "JUMP_IF_FALSE_OR_POP", 112: "JUMP_IF_TRUE_OR_POP",
    114: "POP_JUMP_FORWARD_IF_FALSE", 115: "POP_JUMP_FORWARD_IF_TRUE",
    116: "LOAD_GLOBAL", 120: "COPY", 122: "BINARY_OP", 123: "SEND",
    124: "LOAD_FAST", 125: "STORE_FAST", 126: "DELETE_FAST",
    128: "POP_JUMP_FORWARD_IF_NOT_NONE", 129: "POP_JUMP_FORWARD_IF_NONE",
    130: "RAISE_VARARGS", 132: "MAKE_FUNCTION", 133: "BUILD_SLICE",
    134: "JUMP_BACKWARD_NO_INTERRUPT", 135: "MAKE_CELL", 136: "LOAD_CLOSURE",
    137: "LOAD_DEREF", 138: "STORE_DEREF", 140: "JUMP_BACKWARD",
    142: "CALL_FUNCTION_EX", 144: "EXTENDED_ARG", 145: "LIST_APPEND",
    146: "SET_ADD", 147: "MAP_ADD", 149: "COPY_FREE_VARS", 151: "RESUME",
    155: "FORMAT_VALUE", 156: "BUILD_CONST_KEY_MAP", 157: "BUILD_STRING",
    160: "LOAD_METHOD", 162: "LIST_EXTEND", 163: "SET_UPDATE", 164: "DICT_MERGE",
    165: "DICT_UPDATE", 166: "PRECALL", 171: "CALL", 172: "KW_NAMES",
    173: "POP_JUMP_BACKWARD_IF_NOT_NONE", 174: "POP_JUMP_BACKWARD_IF_NONE",
    175: "POP_JUMP_BACKWARD_IF_FALSE", 176: "POP_JUMP_BACKWARD_IF_TRUE",
}


def _text_values(values: Sequence[str], field: str) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)) or len(values) > 65535:
        raise ValueError(f"{field} must be a bounded text sequence")
    if any(not isinstance(item, str) or len(item) > 4096 for item in values):
        raise ValueError(f"{field} contains invalid text")
    return tuple(values)


def lift_python_wordcode(
    code: bytes,
    *,
    version: str = "3.11",
    opcode_names: Mapping[int, str] | None = None,
    constants: Sequence[str] = (),
    names: Sequence[str] = (),
    locals_: Sequence[str] = (),
) -> LiftResult:
    """Lift 2-byte CPython wordcode already extracted by an offline tool."""
    code = _bytes(code)
    if len(code) % 2:
        raise LiftError("Python wordcode has a truncated opcode/argument pair")
    if version != "3.11" and opcode_names is None:
        raise ValueError("non-3.11 wordcode requires an explicit opcode_names mapping")
    table = dict(_PY311 if opcode_names is None else opcode_names)
    if any(not isinstance(key, int) or isinstance(key, bool) or not 0 <= key <= 255
           or not isinstance(value, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value)
           for key, value in table.items()):
        raise ValueError("opcode_names contains an invalid entry")
    constants = _text_values(constants, "constants")
    names = _text_values(names, "names")
    locals_ = _text_values(locals_, "locals")
    instructions = []
    warnings = []
    extended = 0
    pending_extended = False
    for offset in range(0, len(code), 2):
        if len(instructions) >= MAX_INSTRUCTIONS:
            raise LiftError("Python instruction cap exceeded")
        opcode, low_argument = code[offset], code[offset + 1]
        argument = (extended << 8) | low_argument
        mnemonic = table.get(opcode, f"OP_{opcode:02X}")
        operands = [str(argument)]
        annotation = ""
        targets: tuple[int, ...] = ()
        if mnemonic == "EXTENDED_ARG":
            extended = argument
            pending_extended = True
            annotation = "extends the next instruction argument"
        else:
            extended = 0
            pending_extended = False
            lookup = None
            if mnemonic == "LOAD_CONST" and argument < len(constants):
                lookup = constants[argument]
            elif mnemonic in {"LOAD_NAME", "STORE_NAME", "DELETE_NAME", "LOAD_ATTR", "STORE_ATTR",
                              "LOAD_GLOBAL", "STORE_GLOBAL", "IMPORT_NAME", "IMPORT_FROM", "LOAD_METHOD"}:
                index = argument >> 1 if mnemonic == "LOAD_GLOBAL" else argument
                if index < len(names):
                    lookup = names[index]
            elif mnemonic in {"LOAD_FAST", "STORE_FAST", "DELETE_FAST"} and argument < len(locals_):
                lookup = locals_[argument]
            if lookup is not None:
                annotation = lookup
            if "JUMP_FORWARD" in mnemonic or mnemonic in {
                "JUMP_IF_FALSE_OR_POP", "JUMP_IF_TRUE_OR_POP", "FOR_ITER", "SEND",
            }:
                targets = (offset + 2 + argument * 2,)
            elif "JUMP_BACKWARD" in mnemonic:
                targets = (offset + 2 - argument * 2,)
            if targets and not 0 <= targets[0] < len(code):
                warnings.append(f"branch at 0x{offset:x} targets outside supplied wordcode")
        if mnemonic.startswith("OP_"):
            warnings.append(f"unknown Python opcode 0x{opcode:02x} at 0x{offset:x}")
        instructions.append(IRInstruction(offset, mnemonic, tuple(operands), targets, annotation))
    if pending_extended:
        raise LiftError("Python wordcode ends with EXTENDED_ARG")
    return LiftResult("python-wordcode", version, tuple(instructions), tuple(warnings))


# --------------------------------------------------------------------------- Lua 5.1


_LUA51_OPS = (
    "MOVE", "LOADK", "LOADBOOL", "LOADNIL", "GETUPVAL", "GETGLOBAL", "GETTABLE",
    "SETGLOBAL", "SETUPVAL", "SETTABLE", "NEWTABLE", "SELF", "ADD", "SUB", "MUL",
    "DIV", "MOD", "POW", "UNM", "NOT", "LEN", "CONCAT", "JMP", "EQ", "LT", "LE",
    "TEST", "TESTSET", "CALL", "TAILCALL", "RETURN", "FORLOOP", "FORPREP", "TFORLOOP",
    "SETLIST", "CLOSE", "CLOSURE", "VARARG",
)


def inspect_lua_header(data: bytes) -> LuaHeader:
    data = _bytes(data)
    if len(data) < 12 or data[:4] != b"\x1bLua":
        raise LiftError("invalid or truncated Lua chunk header")
    version_byte, format_byte = data[4], data[5]
    version = {0x51: "5.1", 0x52: "5.2", 0x53: "5.3", 0x54: "5.4"}.get(version_byte)
    if version is None or format_byte != 0:
        raise LiftError("unsupported Lua chunk version or format")
    if version == "5.1":
        endian_flag, int_size, size_t, instruction_size, number_size = data[6:11]
        integral_flag = data[11]
        if (endian_flag not in {0, 1} or int_size not in {4, 8} or size_t not in {4, 8}
                or instruction_size != 4 or number_size not in {4, 8} or integral_flag not in {0, 1}):
            raise LiftError("invalid Lua 5.1 scalar-size header")
        return LuaHeader(version, format_byte, "little" if endian_flag else "big",
                         int_size, size_t, instruction_size, number_size)
    if data[6:12] != b"\x19\x93\r\n\x1a\n":
        raise LiftError("invalid Lua chunk check-data sequence")
    if version == "5.2":
        if len(data) < 17:
            raise LiftError("truncated Lua 5.2 scalar-size header")
        int_size, size_t, instruction_size, number_size, integral_flag = data[12:17]
        if (instruction_size != 4 or any(size not in {4, 8} for size in (int_size, size_t, number_size))
                or integral_flag not in {0, 1}):
            raise LiftError("invalid Lua 5.2 scalar-size header")
        return LuaHeader(version, format_byte, None, int_size, size_t, instruction_size, number_size)
    if version == "5.3":
        if len(data) < 17:
            raise LiftError("truncated Lua 5.3 scalar-size header")
        int_size, size_t, instruction_size, integer_size, number_size = data[12:17]
        scalar_end = 17
    else:  # Lua 5.4 removed C int/size_t widths from the chunk header.
        if len(data) < 15:
            raise LiftError("truncated Lua 5.4 scalar-size header")
        instruction_size, integer_size, number_size = data[12:15]
        int_size, size_t, scalar_end = None, None, 15
    if instruction_size != 4 or integer_size not in {4, 8} or number_size not in {4, 8}:
        raise LiftError("invalid Lua scalar-size header")
    if len(data) < scalar_end + integer_size + number_size:
        raise LiftError("truncated Lua check-value header")
    integer_bytes = data[scalar_end:scalar_end + integer_size]
    if int.from_bytes(integer_bytes, "little", signed=True) == 0x5678:
        endian = "little"
    elif int.from_bytes(integer_bytes, "big", signed=True) == 0x5678:
        endian = "big"
    else:
        raise LiftError("invalid Lua integer check value")
    number_bytes = data[scalar_end + integer_size:scalar_end + integer_size + number_size]
    number_format = ("<" if endian == "little" else ">") + ("f" if number_size == 4 else "d")
    if struct.unpack(number_format, number_bytes)[0] != 370.5:
        raise LiftError("invalid Lua number check value")
    return LuaHeader(version, format_byte, endian, int_size, size_t, instruction_size, number_size)


def lift_lua51_instructions(code: bytes, *, endian: str = "little") -> LiftResult:
    code = _bytes(code)
    if endian not in {"little", "big"}:
        raise ValueError("Lua endianness must be little or big")
    if len(code) % 4:
        raise LiftError("Lua 5.1 instruction stream is not 32-bit aligned")
    if len(code) // 4 > MAX_INSTRUCTIONS:
        raise LiftError("Lua instruction cap exceeded")
    instructions = []
    warnings = []
    abx = {"LOADK", "GETGLOBAL", "SETGLOBAL", "CLOSURE"}
    asbx = {"JMP", "FORLOOP", "FORPREP"}
    for pc in range(len(code) // 4):
        word = int.from_bytes(code[pc * 4:pc * 4 + 4], endian)
        opcode = word & 0x3F
        a = (word >> 6) & 0xFF
        c = (word >> 14) & 0x1FF
        b = (word >> 23) & 0x1FF
        bx = (word >> 14) & 0x3FFFF
        sbx = bx - 131071
        mnemonic = _LUA51_OPS[opcode] if opcode < len(_LUA51_OPS) else f"OP_{opcode:02X}"
        targets = ()
        if mnemonic in asbx:
            operands = (f"R{a}", str(sbx))
            targets = (pc + 1 + sbx,)
        elif mnemonic in abx:
            operands = (f"R{a}", str(bx))
        else:
            operands = (f"R{a}", str(b), str(c))
        if mnemonic.startswith("OP_"):
            warnings.append(f"unknown Lua opcode {opcode} at pc {pc}")
        instructions.append(IRInstruction(pc, mnemonic, operands, targets))
    return LiftResult("lua", "5.1", tuple(instructions), tuple(warnings))


# --------------------------------------------------------------------------- .NET IL


_IL: dict[int, tuple[str, str]] = {
    0x00: ("nop", ""), 0x01: ("break", ""), 0x02: ("ldarg.0", ""),
    0x03: ("ldarg.1", ""), 0x04: ("ldarg.2", ""), 0x05: ("ldarg.3", ""),
    0x06: ("ldloc.0", ""), 0x07: ("ldloc.1", ""), 0x08: ("ldloc.2", ""),
    0x09: ("ldloc.3", ""), 0x0A: ("stloc.0", ""), 0x0B: ("stloc.1", ""),
    0x0C: ("stloc.2", ""), 0x0D: ("stloc.3", ""), 0x0E: ("ldarg.s", "u1"),
    0x0F: ("ldarga.s", "u1"), 0x10: ("starg.s", "u1"), 0x11: ("ldloc.s", "u1"),
    0x12: ("ldloca.s", "u1"), 0x13: ("stloc.s", "u1"), 0x14: ("ldnull", ""),
    0x15: ("ldc.i4.m1", ""), 0x16: ("ldc.i4.0", ""), 0x17: ("ldc.i4.1", ""),
    0x18: ("ldc.i4.2", ""), 0x19: ("ldc.i4.3", ""), 0x1A: ("ldc.i4.4", ""),
    0x1B: ("ldc.i4.5", ""), 0x1C: ("ldc.i4.6", ""), 0x1D: ("ldc.i4.7", ""),
    0x1E: ("ldc.i4.8", ""), 0x1F: ("ldc.i4.s", "i1"), 0x20: ("ldc.i4", "i4"),
    0x21: ("ldc.i8", "i8"), 0x22: ("ldc.r4", "r4"), 0x23: ("ldc.r8", "r8"),
    0x25: ("dup", ""), 0x26: ("pop", ""), 0x27: ("jmp", "token"),
    0x28: ("call", "token"), 0x29: ("calli", "token"), 0x2A: ("ret", ""),
    0x2B: ("br.s", "branch1"), 0x2C: ("brfalse.s", "branch1"),
    0x2D: ("brtrue.s", "branch1"), 0x2E: ("beq.s", "branch1"),
    0x2F: ("bge.s", "branch1"), 0x30: ("bgt.s", "branch1"),
    0x31: ("ble.s", "branch1"), 0x32: ("blt.s", "branch1"),
    0x33: ("bne.un.s", "branch1"), 0x34: ("bge.un.s", "branch1"),
    0x35: ("bgt.un.s", "branch1"), 0x36: ("ble.un.s", "branch1"),
    0x37: ("blt.un.s", "branch1"),
    0x38: ("br", "branch4"), 0x39: ("brfalse", "branch4"), 0x3A: ("brtrue", "branch4"),
    0x3B: ("beq", "branch4"), 0x3C: ("bge", "branch4"), 0x3D: ("bgt", "branch4"),
    0x3E: ("ble", "branch4"), 0x3F: ("blt", "branch4"), 0x40: ("bne.un", "branch4"),
    0x41: ("bge.un", "branch4"), 0x42: ("bgt.un", "branch4"),
    0x43: ("ble.un", "branch4"), 0x44: ("blt.un", "branch4"),
    0x45: ("switch", "switch"), 0x58: ("add", ""),
    0x59: ("sub", ""), 0x5A: ("mul", ""), 0x5B: ("div", ""), 0x5D: ("rem", ""),
    0x5F: ("and", ""), 0x60: ("or", ""), 0x61: ("xor", ""), 0x62: ("shl", ""),
    0x65: ("neg", ""), 0x66: ("not", ""), 0x6F: ("callvirt", "token"),
    0x70: ("cpobj", "token"), 0x71: ("ldobj", "token"), 0x72: ("ldstr", "token"),
    0x73: ("newobj", "token"), 0x74: ("castclass", "token"), 0x75: ("isinst", "token"),
    0x79: ("unbox", "token"), 0x7A: ("throw", ""), 0x7B: ("ldfld", "token"),
    0x7C: ("ldflda", "token"), 0x7D: ("stfld", "token"), 0x7E: ("ldsfld", "token"),
    0x7F: ("ldsflda", "token"), 0x80: ("stsfld", "token"), 0x81: ("stobj", "token"),
    0x8C: ("box", "token"), 0x8D: ("newarr", "token"),
    0x8F: ("ldelema", "token"), 0xA3: ("ldelem", "token"), 0xA4: ("stelem", "token"),
    0x8E: ("ldlen", ""), 0xA5: ("unbox.any", "token"), 0xD0: ("ldtoken", "token"),
    0xDC: ("endfinally", ""), 0xDD: ("leave", "branch4"), 0xDE: ("leave.s", "branch1"),
    0xFE01: ("ceq", ""), 0xFE02: ("cgt", ""), 0xFE04: ("clt", ""),
    0xFE06: ("ldftn", "token"), 0xFE07: ("ldvirtftn", "token"),
    0xFE09: ("ldarg", "u2"), 0xFE0A: ("ldarga", "u2"), 0xFE0B: ("starg", "u2"),
    0xFE0C: ("ldloc", "u2"), 0xFE0D: ("ldloca", "u2"), 0xFE0E: ("stloc", "u2"),
    0xFE12: ("unaligned.", "u1"), 0xFE13: ("volatile.", ""), 0xFE14: ("tail.", ""),
    0xFE15: ("initobj", "token"), 0xFE16: ("constrained.", "token"),
    0xFE17: ("cpblk", ""), 0xFE18: ("initblk", ""), 0xFE1A: ("rethrow", ""),
    0xFE1C: ("sizeof", "token"), 0xFE1E: ("readonly.", ""),
}


def _numeric_operand(cursor: _Cursor, kind: str) -> tuple[str, int | None]:
    if kind == "u1":
        return str(cursor.integer(1)), None
    if kind == "u2":
        return str(cursor.integer(2)), None
    if kind == "i1":
        return str(cursor.integer(1, signed=True)), None
    if kind == "i4":
        return str(cursor.integer(4, signed=True)), None
    if kind == "i8":
        return str(cursor.integer(8, signed=True)), None
    if kind == "r4":
        return repr(struct.unpack("<f", cursor.take(4))[0]), None
    if kind == "r8":
        return repr(struct.unpack("<d", cursor.take(8))[0]), None
    if kind == "token":
        return f"token(0x{cursor.integer(4):08x})", None
    if kind == "branch1":
        delta = cursor.integer(1, signed=True)
        return str(delta), delta
    if kind == "branch4":
        delta = cursor.integer(4, signed=True)
        return str(delta), delta
    raise LiftError(f"unsupported operand kind {kind}")


def lift_dotnet_il(code: bytes) -> LiftResult:
    code = _bytes(code)
    cursor = _Cursor(code)
    instructions = []
    warnings = []
    while cursor.remaining():
        if len(instructions) >= MAX_INSTRUCTIONS:
            raise LiftError(".NET IL instruction cap exceeded")
        start = cursor.offset
        first = cursor.u8()
        opcode = 0xFE00 | cursor.u8() if first == 0xFE else first
        known = opcode in _IL
        mnemonic, kind = _IL.get(opcode, (f"op_{opcode:04x}", ""))
        operands: tuple[str, ...] = ()
        targets: tuple[int, ...] = ()
        if kind == "switch":
            count = cursor.integer(4)
            if count > MAX_SWITCH_TARGETS:
                raise LiftError(".NET switch target cap exceeded")
            deltas = [cursor.integer(4, signed=True) for _ in range(count)]
            base = cursor.offset
            operands = tuple(str(delta) for delta in deltas)
            targets = tuple(base + delta for delta in deltas)
        elif kind:
            operand, delta = _numeric_operand(cursor, kind)
            operands = (operand,)
            if delta is not None:
                targets = (cursor.offset + delta,)
        if mnemonic.startswith("op_"):
            warnings.append(f"unknown IL opcode 0x{opcode:04x} at 0x{start:x}; lifting stopped to avoid operand desynchronization")
        if targets and any(target < 0 or target >= len(code) for target in targets):
            warnings.append(f"IL branch at 0x{start:x} targets outside supplied code")
        instructions.append(IRInstruction(start, mnemonic, operands, targets))
        if not known:
            break
    return LiftResult("dotnet-il", "ECMA-335", tuple(instructions), tuple(warnings))


def lift_dotnet_method(body: bytes) -> LiftResult:
    """Parse a tiny/fat method header and lift exactly its declared IL bytes."""
    body = _bytes(body)
    if not body:
        raise LiftError("empty .NET method body")
    if body[0] & 0x03 == 0x02:
        header_size, code_size = 1, body[0] >> 2
    elif body[0] & 0x03 == 0x03:
        if len(body) < 12:
            raise LiftError("truncated .NET fat method header")
        flags_and_size = struct.unpack_from("<H", body, 0)[0]
        header_size = (flags_and_size >> 12) * 4
        code_size = struct.unpack_from("<I", body, 4)[0]
        if header_size < 12 or header_size > len(body):
            raise LiftError("invalid .NET fat method header size")
    else:
        raise LiftError("unknown .NET method header")
    if code_size > MAX_BYTECODE or header_size + code_size > len(body):
        raise LiftError("truncated or over-cap .NET method code")
    result = lift_dotnet_il(body[header_size:header_size + code_size])
    warnings = result.warnings
    if header_size + code_size < len(body):
        warnings += ("method has trailing sections/data not lifted",)
    return LiftResult(result.dialect, result.version, result.instructions, warnings)


# --------------------------------------------------------------------------- JVM


_JVM_NAMES = {
    0x00: "nop", 0x01: "aconst_null", 0x02: "iconst_m1", 0x03: "iconst_0",
    0x04: "iconst_1", 0x05: "iconst_2", 0x06: "iconst_3", 0x07: "iconst_4",
    0x08: "iconst_5", 0x10: "bipush", 0x11: "sipush", 0x12: "ldc",
    0x13: "ldc_w", 0x14: "ldc2_w", 0x15: "iload", 0x16: "lload",
    0x17: "fload", 0x18: "dload", 0x19: "aload", 0x1A: "iload_0",
    0x1B: "iload_1", 0x1C: "iload_2", 0x1D: "iload_3", 0x2A: "aload_0",
    0x2B: "aload_1", 0x2C: "aload_2", 0x2D: "aload_3", 0x36: "istore",
    0x37: "lstore", 0x38: "fstore", 0x39: "dstore", 0x3A: "astore",
    0x3B: "istore_0", 0x3C: "istore_1", 0x3D: "istore_2",
    0x3E: "istore_3", 0x57: "pop", 0x59: "dup", 0x60: "iadd", 0x64: "isub",
    0x68: "imul", 0x6C: "idiv", 0x70: "irem", 0x74: "ineg", 0x7E: "iand",
    0x80: "ior", 0x82: "ixor", 0x84: "iinc", 0x99: "ifeq", 0x9A: "ifne",
    0x9B: "iflt", 0x9C: "ifge", 0x9D: "ifgt", 0x9E: "ifle", 0x9F: "if_icmpeq",
    0xA0: "if_icmpne", 0xA1: "if_icmplt", 0xA2: "if_icmpge", 0xA3: "if_icmpgt",
    0xA4: "if_icmple", 0xA5: "if_acmpeq", 0xA6: "if_acmpne", 0xA7: "goto",
    0xA8: "jsr", 0xA9: "ret", 0xAA: "tableswitch", 0xAB: "lookupswitch",
    0xAC: "ireturn", 0xB0: "areturn", 0xB1: "return", 0xB2: "getstatic",
    0xB3: "putstatic", 0xB4: "getfield", 0xB5: "putfield", 0xB6: "invokevirtual",
    0xB7: "invokespecial", 0xB8: "invokestatic", 0xB9: "invokeinterface",
    0xBA: "invokedynamic", 0xBB: "new", 0xBC: "newarray", 0xBD: "anewarray",
    0xBE: "arraylength", 0xBF: "athrow", 0xC0: "checkcast", 0xC1: "instanceof",
    0xC4: "wide", 0xC5: "multianewarray", 0xC6: "ifnull", 0xC7: "ifnonnull",
    0xC8: "goto_w", 0xC9: "jsr_w",
}
_JVM_U1 = {0x12, *range(0x15, 0x1A), *range(0x36, 0x3B), 0xA9, 0xBC}
_JVM_U2 = {0x13, 0x14, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xBB, 0xBD, 0xC0, 0xC1}
_JVM_BRANCH2 = set(range(0x99, 0xA9)) | {0xC6, 0xC7}


def lift_jvm_code(code: bytes) -> LiftResult:
    code = _bytes(code)
    cursor = _Cursor(code, "big")
    instructions = []
    warnings = []
    while cursor.remaining():
        if len(instructions) >= MAX_INSTRUCTIONS:
            raise LiftError("JVM instruction cap exceeded")
        start = cursor.offset
        opcode = cursor.u8()
        mnemonic = _JVM_NAMES.get(opcode, f"op_{opcode:02x}")
        operands: tuple[str, ...] = ()
        targets: tuple[int, ...] = ()
        if opcode == 0x10:
            operands = (str(cursor.integer(1, signed=True)),)
        elif opcode == 0x11:
            operands = (str(cursor.integer(2, signed=True, endian="big")),)
        elif opcode in _JVM_U1:
            value = cursor.integer(1)
            if opcode == 0xBC and value not in range(4, 12):
                raise LiftError("invalid JVM newarray type code")
            operands = (str(value),)
        elif opcode in _JVM_U2:
            operands = (f"cp#{cursor.integer(2, endian='big')}",)
        elif opcode == 0x84:
            operands = (str(cursor.integer(1)), str(cursor.integer(1, signed=True)))
        elif opcode in _JVM_BRANCH2:
            delta = cursor.integer(2, signed=True, endian="big")
            operands, targets = (str(delta),), (start + delta,)
        elif opcode in {0xC8, 0xC9}:
            delta = cursor.integer(4, signed=True, endian="big")
            operands, targets = (str(delta),), (start + delta,)
        elif opcode in {0xB9, 0xBA}:
            index = cursor.integer(2, endian="big")
            extra = cursor.take(2)
            if (opcode == 0xB9 and (extra[0] == 0 or extra[1] != 0)) or (opcode == 0xBA and extra != b"\0\0"):
                raise LiftError("invalid JVM invoke reserved byte")
            operands = (f"cp#{index}", str(extra[0])) if opcode == 0xB9 else (f"cp#{index}",)
        elif opcode == 0xC5:
            operands = (f"cp#{cursor.integer(2, endian='big')}", str(cursor.integer(1)))
        elif opcode == 0xC4:
            nested = cursor.u8()
            nested_name = _JVM_NAMES.get(nested, f"op_{nested:02x}")
            index = cursor.integer(2, endian="big")
            if nested == 0x84:
                constant = cursor.integer(2, signed=True, endian="big")
                operands = (nested_name, str(index), str(constant))
            elif nested in {*range(0x15, 0x1A), *range(0x36, 0x3B), 0xA9}:
                operands = (nested_name, str(index))
            else:
                raise LiftError("invalid JVM wide opcode")
        elif opcode in {0xAA, 0xAB}:
            padding = (-cursor.offset) % 4
            if any(cursor.take(padding)):
                warnings.append(f"non-zero JVM switch padding at 0x{start:x}")
            default = cursor.integer(4, signed=True, endian="big")
            target_rows = [start + default]
            operand_rows = [f"default:{default}"]
            if opcode == 0xAA:
                low = cursor.integer(4, signed=True, endian="big")
                high = cursor.integer(4, signed=True, endian="big")
                count = high - low + 1
                if count < 0 or count > MAX_SWITCH_TARGETS:
                    raise LiftError("JVM tableswitch target cap exceeded")
                for key in range(low, high + 1):
                    delta = cursor.integer(4, signed=True, endian="big")
                    operand_rows.append(f"{key}:{delta}")
                    target_rows.append(start + delta)
            else:
                count = cursor.integer(4, signed=True, endian="big")
                if count < 0 or count > MAX_SWITCH_TARGETS:
                    raise LiftError("JVM lookupswitch target cap exceeded")
                last_key = None
                for _ in range(count):
                    key = cursor.integer(4, signed=True, endian="big")
                    delta = cursor.integer(4, signed=True, endian="big")
                    if last_key is not None and key <= last_key:
                        warnings.append(f"unsorted JVM lookupswitch keys at 0x{start:x}")
                    last_key = key
                    operand_rows.append(f"{key}:{delta}")
                    target_rows.append(start + delta)
            operands, targets = tuple(operand_rows), tuple(target_rows)
        if mnemonic.startswith("op_"):
            warnings.append(f"unknown JVM opcode 0x{opcode:02x} at 0x{start:x}")
        if targets and any(target < 0 or target >= len(code) for target in targets):
            warnings.append(f"JVM branch at 0x{start:x} targets outside supplied code")
        instructions.append(IRInstruction(start, mnemonic, operands, targets))
    return LiftResult("jvm", "class-code", tuple(instructions), tuple(warnings))


# --------------------------------------------------------------------------- WebAssembly


_WASM_NAMES = {
    0x00: "unreachable", 0x01: "nop", 0x02: "block", 0x03: "loop", 0x04: "if",
    0x05: "else", 0x0B: "end", 0x0C: "br", 0x0D: "br_if", 0x0E: "br_table",
    0x0F: "return", 0x10: "call", 0x11: "call_indirect", 0x1A: "drop", 0x1B: "select",
    0x1C: "select_t",
    0x20: "local.get", 0x21: "local.set", 0x22: "local.tee", 0x23: "global.get",
    0x24: "global.set", 0x28: "i32.load", 0x29: "i64.load", 0x2A: "f32.load",
    0x2B: "f64.load", 0x36: "i32.store", 0x37: "i64.store", 0x38: "f32.store",
    0x39: "f64.store", 0x3F: "memory.size", 0x40: "memory.grow", 0x41: "i32.const",
    0x42: "i64.const", 0x43: "f32.const", 0x44: "f64.const", 0x45: "i32.eqz",
    0x46: "i32.eq", 0x47: "i32.ne", 0x4A: "i32.gt_s", 0x4C: "i32.le_s",
    0x6A: "i32.add", 0x6B: "i32.sub", 0x6C: "i32.mul", 0x6D: "i32.div_s",
    0x71: "i32.and", 0x72: "i32.or", 0x73: "i32.xor", 0x7C: "i64.add",
    0x92: "f32.add", 0xA0: "f64.add", 0xD0: "ref.null", 0xD1: "ref.is_null",
    0xD2: "ref.func", 0xFC: "misc.prefix",
}


def lift_wasm_function(code: bytes) -> LiftResult:
    code = _bytes(code)
    cursor = _Cursor(code)
    instructions = []
    warnings = []
    while cursor.remaining():
        if len(instructions) >= MAX_INSTRUCTIONS:
            raise LiftError("WASM instruction cap exceeded")
        start = cursor.offset
        opcode = cursor.u8()
        mnemonic = _WASM_NAMES.get(opcode, f"op_{opcode:02x}")
        operands: tuple[str, ...] = ()
        targets: tuple[int, ...] = ()
        if opcode in {0x02, 0x03, 0x04}:
            operands = (str(cursor.sleb(5)),)
        elif opcode in {0x0C, 0x0D, 0x10, 0x20, 0x21, 0x22, 0x23, 0x24}:
            operands = (str(cursor.uleb()),)
        elif opcode == 0x0E:
            count = cursor.uleb()
            if count > MAX_SWITCH_TARGETS:
                raise LiftError("WASM br_table target cap exceeded")
            labels = [cursor.uleb() for _ in range(count)]
            default = cursor.uleb()
            operands = tuple([*(str(label) for label in labels), f"default:{default}"])
        elif opcode == 0x11:
            operands = (str(cursor.uleb()), str(cursor.uleb()))
        elif opcode == 0x1C:
            count = cursor.uleb()
            if count > 32:
                raise LiftError("WASM typed-select type cap exceeded")
            types = [cursor.u8() for _ in range(count)]
            if any(value not in {0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x70, 0x6F} for value in types):
                raise LiftError("invalid WASM typed-select value type")
            operands = tuple(f"0x{value:02x}" for value in types)
        elif 0x28 <= opcode <= 0x3E:
            operands = (f"align={cursor.uleb()}", f"offset={cursor.uleb()}")
        elif opcode in {0x3F, 0x40}:
            memory = cursor.uleb()
            operands = (str(memory),)
        elif opcode == 0x41:
            operands = (str(cursor.sleb(5)),)
        elif opcode == 0x42:
            operands = (str(cursor.sleb(10)),)
        elif opcode == 0x43:
            operands = (repr(struct.unpack("<f", cursor.take(4))[0]),)
        elif opcode == 0x44:
            operands = (repr(struct.unpack("<d", cursor.take(8))[0]),)
        elif opcode == 0xD0:
            operands = (str(cursor.sleb(5)),)
        elif opcode == 0xD2:
            operands = (str(cursor.uleb()),)
        elif opcode == 0xFC:
            subopcode = cursor.uleb()
            values = [subopcode]
            if subopcode in {8, 10, 12, 14}:
                values.extend((cursor.uleb(), cursor.uleb()))
            elif subopcode in {9, 11, 13, 15, 16, 17}:
                values.append(cursor.uleb())
            elif subopcode > 17:
                raise LiftError("unsupported WASM misc-prefix opcode")
            operands = tuple(str(value) for value in values)
        elif mnemonic.startswith("op_"):
            if 0x45 <= opcode <= 0xC4:
                mnemonic = f"numeric_{opcode:02x}"
            else:
                raise LiftError(f"unsupported WASM opcode 0x{opcode:02x}; immediate shape unknown")
        instructions.append(IRInstruction(start, mnemonic, operands, targets))
    if not instructions or instructions[-1].mnemonic != "end":
        warnings.append("WASM function body does not end with end opcode")
    return LiftResult("wasm", "core-v1", tuple(instructions), tuple(warnings))


def lift_wasm_module(data: bytes) -> WasmModuleIR:
    data = _bytes(data)
    if len(data) < 8 or data[:4] != b"\0asm" or data[4:8] != b"\x01\0\0\0":
        raise LiftError("invalid or unsupported WebAssembly module header")
    cursor = _Cursor(data[8:])
    sections = []
    functions = []
    section_order = {**{value: value for value in range(1, 10)}, 12: 10, 10: 11, 11: 12}
    last_noncustom = 0
    declared_functions: int | None = None
    code_seen = False
    while cursor.remaining():
        section_id = cursor.u8()
        size = cursor.uleb()
        if size > cursor.remaining():
            raise LiftError("truncated WebAssembly section")
        payload = cursor.take(size)
        if section_id > 12:
            raise LiftError("invalid WebAssembly section id")
        if section_id != 0:
            order = section_order[section_id]
            if order <= last_noncustom:
                raise LiftError("duplicate or out-of-order WebAssembly section")
            last_noncustom = order
        sections.append((section_id, size))
        if section_id == 3:
            function_section = _Cursor(payload)
            declared_functions = function_section.uleb()
            if declared_functions > MAX_FUNCTIONS:
                raise LiftError("WASM function cap exceeded")
            for _ in range(declared_functions):
                function_section.uleb()
            if function_section.remaining():
                raise LiftError("trailing bytes in WASM function section")
        if section_id != 10:
            continue
        code_seen = True
        code = _Cursor(payload)
        count = code.uleb()
        if count > MAX_FUNCTIONS:
            raise LiftError("WASM function cap exceeded")
        for function_index in range(count):
            body_size = code.uleb()
            body = _Cursor(code.take(body_size))
            local_groups = body.uleb()
            if local_groups > 65535:
                raise LiftError("WASM local-group cap exceeded")
            total_locals = 0
            for _ in range(local_groups):
                total_locals += body.uleb()
                value_type = body.u8()
                if value_type not in {0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x70, 0x6F}:
                    raise LiftError("invalid WASM local value type")
                if total_locals > 1_000_000:
                    raise LiftError("WASM local count cap exceeded")
            lifted = lift_wasm_function(body.take(body.remaining()))
            if not lifted.instructions or lifted.instructions[-1].mnemonic != "end":
                raise LiftError("WASM module function body lacks terminal end opcode")
            functions.append(LiftResult(
                lifted.dialect, f"core-v1/function-{function_index}", lifted.instructions,
                lifted.warnings + ((f"locals={total_locals}",) if total_locals else ()),
            ))
        if code.remaining():
            raise LiftError("trailing bytes in WASM code section")
        if declared_functions is None and count:
            raise LiftError("WASM code section has no matching function section")
        if declared_functions is not None and count != declared_functions:
            raise LiftError("WASM function/code count mismatch")
    if declared_functions and not code_seen:
        raise LiftError("WASM function section has no matching code section")
    return WasmModuleIR(1, tuple(sections), tuple(functions))


__all__ = [
    "LiftError", "IRInstruction", "LiftResult", "PycHeader", "LuaHeader", "WasmModuleIR",
    "inspect_pyc_header", "lift_python_wordcode", "inspect_lua_header",
    "lift_lua51_instructions", "lift_dotnet_il", "lift_dotnet_method",
    "lift_jvm_code", "lift_wasm_function", "lift_wasm_module",
]
