#!/usr/bin/env python3
"""Static Python 3.12/3.13 ``.pyc`` and marshal-v4 inspector.

The input is data, never code: this module does not import ``marshal``/``dis``
and never loads, imports, or executes a code object.  It implements the small
marshal-v4 subset used by CPython code objects, with explicit resource caps,
then inventories wordcode, inline caches, jumps, and exception-table entries.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import struct
import sys
from typing import Any


MAX_INPUT = 64 << 20
MAX_BLOB = 32 << 20
MAX_ITEMS = 250_000
MAX_REFS = 250_000
MAX_DEPTH = 160
MAX_CODE_UNITS = 2_000_000
MAX_EXCEPTION_ENTRIES = 200_000

FLAG_REF = 0x80
NULL = object()


class RedepthPycError(ValueError):
    """Malformed, unsupported, or resource-cap-exceeding pyc input."""


@dataclass(frozen=True)
class PycHeader:
    version: str
    magic_hex: str
    flags: int
    hash_based: bool
    checked_hash: bool
    timestamp: int | None
    source_size: int | None
    source_hash_hex: str | None


@dataclass(frozen=True)
class PhysicalInstruction:
    physical_offset: int
    logical_index: int | None
    opcode: int
    opname: str
    base_opname: str
    argument: int | None
    cache_entries: int
    is_cache: bool
    cache_owner_offset: int | None
    raw_hex: str
    annotation: str
    jump_target: int | None


@dataclass(frozen=True)
class ExceptionEntry:
    start: int
    end: int
    target: int
    depth: int
    lasti: bool


@dataclass(frozen=True)
class CodeInfo:
    name: str
    qualname: str
    filename: str
    argcount: int
    posonlyargcount: int
    kwonlyargcount: int
    stacksize: int
    flags: int
    firstlineno: int
    code_size: int
    constants: tuple[str, ...]
    names: tuple[str, ...]
    localsplus_names: tuple[str, ...]
    localsplus_kinds_hex: str
    linetable_size: int
    exceptiontable_size: int
    instructions: tuple[PhysicalInstruction, ...]
    exception_entries: tuple[ExceptionEntry, ...]
    children: tuple["CodeInfo", ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class PycReport:
    header: PycHeader
    root: CodeInfo
    marshal_objects: int
    marshal_references: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class _Ref:
    index: int


@dataclass(frozen=True)
class _Value:
    kind: str
    value: Any
    ref_index: int | None = None


@dataclass(frozen=True)
class _RawCode:
    argcount: int
    posonlyargcount: int
    kwonlyargcount: int
    stacksize: int
    flags: int
    code: _Value | _Ref
    consts: _Value | _Ref
    names: _Value | _Ref
    localsplusnames: _Value | _Ref
    localspluskinds: _Value | _Ref
    filename: _Value | _Ref
    name: _Value | _Ref
    qualname: _Value | _Ref
    firstlineno: int
    linetable: _Value | _Ref
    exceptiontable: _Value | _Ref


class _Cursor:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def remaining(self) -> int:
        return len(self.data) - self.offset

    def take(self, count: int) -> bytes:
        if not isinstance(count, int) or count < 0 or count > self.remaining():
            raise RedepthPycError("truncated marshal payload")
        result = self.data[self.offset:self.offset + count]
        self.offset += count
        return result

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "little")

    def i32(self) -> int:
        return int.from_bytes(self.take(4), "little", signed=True)

    def i64(self) -> int:
        return int.from_bytes(self.take(8), "little", signed=True)


def _pairs(text: str) -> dict[int, str]:
    result: dict[int, str] = {}
    for token in text.split():
        number, name = token.split(":", 1)
        result[int(number)] = name
    return result


# CPython-generated tables, pinned to the corresponding release branches.
_PY312_STANDARD = _pairs("""
0:CACHE 1:POP_TOP 2:PUSH_NULL 3:INTERPRETER_EXIT 4:END_FOR 5:END_SEND
9:NOP 11:UNARY_NEGATIVE 12:UNARY_NOT 15:UNARY_INVERT 17:RESERVED
25:BINARY_SUBSCR 26:BINARY_SLICE 27:STORE_SLICE 30:GET_LEN
31:MATCH_MAPPING 32:MATCH_SEQUENCE 33:MATCH_KEYS 35:PUSH_EXC_INFO
36:CHECK_EXC_MATCH 37:CHECK_EG_MATCH 49:WITH_EXCEPT_START 50:GET_AITER
51:GET_ANEXT 52:BEFORE_ASYNC_WITH 53:BEFORE_WITH 54:END_ASYNC_FOR
55:CLEANUP_THROW 60:STORE_SUBSCR 61:DELETE_SUBSCR 68:GET_ITER
69:GET_YIELD_FROM_ITER 71:LOAD_BUILD_CLASS 74:LOAD_ASSERTION_ERROR
75:RETURN_GENERATOR 83:RETURN_VALUE 85:SETUP_ANNOTATIONS 87:LOAD_LOCALS
89:POP_EXCEPT 90:STORE_NAME 91:DELETE_NAME 92:UNPACK_SEQUENCE 93:FOR_ITER
94:UNPACK_EX 95:STORE_ATTR 96:DELETE_ATTR 97:STORE_GLOBAL 98:DELETE_GLOBAL
99:SWAP 100:LOAD_CONST 101:LOAD_NAME 102:BUILD_TUPLE 103:BUILD_LIST
104:BUILD_SET 105:BUILD_MAP 106:LOAD_ATTR 107:COMPARE_OP 108:IMPORT_NAME
109:IMPORT_FROM 110:JUMP_FORWARD 114:POP_JUMP_IF_FALSE 115:POP_JUMP_IF_TRUE
116:LOAD_GLOBAL 117:IS_OP 118:CONTAINS_OP 119:RERAISE 120:COPY
121:RETURN_CONST 122:BINARY_OP 123:SEND 124:LOAD_FAST 125:STORE_FAST
126:DELETE_FAST 127:LOAD_FAST_CHECK 128:POP_JUMP_IF_NOT_NONE
129:POP_JUMP_IF_NONE 130:RAISE_VARARGS 131:GET_AWAITABLE 132:MAKE_FUNCTION
133:BUILD_SLICE 134:JUMP_BACKWARD_NO_INTERRUPT 135:MAKE_CELL 136:LOAD_CLOSURE
137:LOAD_DEREF 138:STORE_DEREF 139:DELETE_DEREF 140:JUMP_BACKWARD
141:LOAD_SUPER_ATTR 142:CALL_FUNCTION_EX 143:LOAD_FAST_AND_CLEAR
144:EXTENDED_ARG 145:LIST_APPEND 146:SET_ADD 147:MAP_ADD 149:COPY_FREE_VARS
150:YIELD_VALUE 151:RESUME 152:MATCH_CLASS 155:FORMAT_VALUE
156:BUILD_CONST_KEY_MAP 157:BUILD_STRING 162:LIST_EXTEND 163:SET_UPDATE
164:DICT_MERGE 165:DICT_UPDATE 171:CALL 172:KW_NAMES 173:CALL_INTRINSIC_1
174:CALL_INTRINSIC_2 175:LOAD_FROM_DICT_OR_GLOBALS 176:LOAD_FROM_DICT_OR_DEREF
237:INSTRUMENTED_LOAD_SUPER_ATTR 238:INSTRUMENTED_POP_JUMP_IF_NONE
239:INSTRUMENTED_POP_JUMP_IF_NOT_NONE 240:INSTRUMENTED_RESUME
241:INSTRUMENTED_CALL 242:INSTRUMENTED_RETURN_VALUE 243:INSTRUMENTED_YIELD_VALUE
244:INSTRUMENTED_CALL_FUNCTION_EX 245:INSTRUMENTED_JUMP_FORWARD
246:INSTRUMENTED_JUMP_BACKWARD 247:INSTRUMENTED_RETURN_CONST
248:INSTRUMENTED_FOR_ITER 249:INSTRUMENTED_POP_JUMP_IF_FALSE
250:INSTRUMENTED_POP_JUMP_IF_TRUE 251:INSTRUMENTED_END_FOR
252:INSTRUMENTED_END_SEND 253:INSTRUMENTED_INSTRUCTION 254:INSTRUMENTED_LINE
""")

_PY312_SPECIAL = _pairs("""
6:BINARY_OP_ADD_FLOAT 7:BINARY_OP_ADD_INT 8:BINARY_OP_ADD_UNICODE
10:BINARY_OP_INPLACE_ADD_UNICODE 13:BINARY_OP_MULTIPLY_FLOAT
14:BINARY_OP_MULTIPLY_INT 16:BINARY_OP_SUBTRACT_FLOAT 18:BINARY_OP_SUBTRACT_INT
19:BINARY_SUBSCR_DICT 20:BINARY_SUBSCR_GETITEM 21:BINARY_SUBSCR_LIST_INT
22:BINARY_SUBSCR_TUPLE_INT 23:CALL_PY_EXACT_ARGS 24:CALL_PY_WITH_DEFAULTS
28:CALL_BOUND_METHOD_EXACT_ARGS 29:CALL_BUILTIN_CLASS
34:CALL_BUILTIN_FAST_WITH_KEYWORDS 38:CALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS
39:CALL_NO_KW_BUILTIN_FAST 40:CALL_NO_KW_BUILTIN_O 41:CALL_NO_KW_ISINSTANCE
42:CALL_NO_KW_LEN 43:CALL_NO_KW_LIST_APPEND 44:CALL_NO_KW_METHOD_DESCRIPTOR_FAST
45:CALL_NO_KW_METHOD_DESCRIPTOR_NOARGS 46:CALL_NO_KW_METHOD_DESCRIPTOR_O
47:CALL_NO_KW_STR_1 48:CALL_NO_KW_TUPLE_1 56:CALL_NO_KW_TYPE_1
57:COMPARE_OP_FLOAT 58:COMPARE_OP_INT 59:COMPARE_OP_STR 62:FOR_ITER_LIST
63:FOR_ITER_TUPLE 64:FOR_ITER_RANGE 65:FOR_ITER_GEN 66:LOAD_SUPER_ATTR_ATTR
67:LOAD_SUPER_ATTR_METHOD 70:LOAD_ATTR_CLASS 72:LOAD_ATTR_GETATTRIBUTE_OVERRIDDEN
73:LOAD_ATTR_INSTANCE_VALUE 76:LOAD_ATTR_MODULE 77:LOAD_ATTR_PROPERTY
78:LOAD_ATTR_SLOT 79:LOAD_ATTR_WITH_HINT 80:LOAD_ATTR_METHOD_LAZY_DICT
81:LOAD_ATTR_METHOD_NO_DICT 82:LOAD_ATTR_METHOD_WITH_VALUES
84:LOAD_CONST__LOAD_FAST 86:LOAD_FAST__LOAD_CONST 88:LOAD_FAST__LOAD_FAST
111:LOAD_GLOBAL_BUILTIN 112:LOAD_GLOBAL_MODULE 113:STORE_ATTR_INSTANCE_VALUE
148:STORE_ATTR_SLOT 153:STORE_ATTR_WITH_HINT 154:STORE_FAST__LOAD_FAST
158:STORE_FAST__STORE_FAST 159:STORE_SUBSCR_DICT 160:STORE_SUBSCR_LIST_INT
161:UNPACK_SEQUENCE_LIST 166:UNPACK_SEQUENCE_TUPLE
167:UNPACK_SEQUENCE_TWO_TUPLE 168:SEND_GEN
""")

_PY313_STANDARD = _pairs("""
0:CACHE 17:RESERVED 149:RESUME 254:INSTRUMENTED_LINE 1:BEFORE_ASYNC_WITH
2:BEFORE_WITH 4:BINARY_SLICE 5:BINARY_SUBSCR 6:CHECK_EG_MATCH
7:CHECK_EXC_MATCH 8:CLEANUP_THROW 9:DELETE_SUBSCR 10:END_ASYNC_FOR
11:END_FOR 12:END_SEND 13:EXIT_INIT_CHECK 14:FORMAT_SIMPLE 15:FORMAT_WITH_SPEC
16:GET_AITER 18:GET_ANEXT 19:GET_ITER 20:GET_LEN 21:GET_YIELD_FROM_ITER
22:INTERPRETER_EXIT 23:LOAD_ASSERTION_ERROR 24:LOAD_BUILD_CLASS 25:LOAD_LOCALS
26:MAKE_FUNCTION 27:MATCH_KEYS 28:MATCH_MAPPING 29:MATCH_SEQUENCE 30:NOP
31:POP_EXCEPT 32:POP_TOP 33:PUSH_EXC_INFO 34:PUSH_NULL 35:RETURN_GENERATOR
36:RETURN_VALUE 37:SETUP_ANNOTATIONS 38:STORE_SLICE 39:STORE_SUBSCR 40:TO_BOOL
41:UNARY_INVERT 42:UNARY_NEGATIVE 43:UNARY_NOT 44:WITH_EXCEPT_START
45:BINARY_OP 46:BUILD_CONST_KEY_MAP 47:BUILD_LIST 48:BUILD_MAP 49:BUILD_SET
50:BUILD_SLICE 51:BUILD_STRING 52:BUILD_TUPLE 53:CALL 54:CALL_FUNCTION_EX
55:CALL_INTRINSIC_1 56:CALL_INTRINSIC_2 57:CALL_KW 58:COMPARE_OP
59:CONTAINS_OP 60:CONVERT_VALUE 61:COPY 62:COPY_FREE_VARS 63:DELETE_ATTR
64:DELETE_DEREF 65:DELETE_FAST 66:DELETE_GLOBAL 67:DELETE_NAME 68:DICT_MERGE
69:DICT_UPDATE 70:ENTER_EXECUTOR 71:EXTENDED_ARG 72:FOR_ITER 73:GET_AWAITABLE
74:IMPORT_FROM 75:IMPORT_NAME 76:IS_OP 77:JUMP_BACKWARD
78:JUMP_BACKWARD_NO_INTERRUPT 79:JUMP_FORWARD 80:LIST_APPEND 81:LIST_EXTEND
82:LOAD_ATTR 83:LOAD_CONST 84:LOAD_DEREF 85:LOAD_FAST 86:LOAD_FAST_AND_CLEAR
87:LOAD_FAST_CHECK 88:LOAD_FAST_LOAD_FAST 89:LOAD_FROM_DICT_OR_DEREF
90:LOAD_FROM_DICT_OR_GLOBALS 91:LOAD_GLOBAL 92:LOAD_NAME 93:LOAD_SUPER_ATTR
94:MAKE_CELL 95:MAP_ADD 96:MATCH_CLASS 97:POP_JUMP_IF_FALSE
98:POP_JUMP_IF_NONE 99:POP_JUMP_IF_NOT_NONE 100:POP_JUMP_IF_TRUE
101:RAISE_VARARGS 102:RERAISE 103:RETURN_CONST 104:SEND 105:SET_ADD
106:SET_FUNCTION_ATTRIBUTE 107:SET_UPDATE 108:STORE_ATTR 109:STORE_DEREF
110:STORE_FAST 111:STORE_FAST_LOAD_FAST 112:STORE_FAST_STORE_FAST
113:STORE_GLOBAL 114:STORE_NAME 115:SWAP 116:UNPACK_EX
117:UNPACK_SEQUENCE 118:YIELD_VALUE 236:INSTRUMENTED_RESUME
237:INSTRUMENTED_END_FOR 238:INSTRUMENTED_END_SEND
239:INSTRUMENTED_RETURN_VALUE 240:INSTRUMENTED_RETURN_CONST
241:INSTRUMENTED_YIELD_VALUE 242:INSTRUMENTED_LOAD_SUPER_ATTR
243:INSTRUMENTED_FOR_ITER 244:INSTRUMENTED_CALL 245:INSTRUMENTED_CALL_KW
246:INSTRUMENTED_CALL_FUNCTION_EX 247:INSTRUMENTED_INSTRUCTION
248:INSTRUMENTED_JUMP_FORWARD 249:INSTRUMENTED_JUMP_BACKWARD
250:INSTRUMENTED_POP_JUMP_IF_TRUE 251:INSTRUMENTED_POP_JUMP_IF_FALSE
252:INSTRUMENTED_POP_JUMP_IF_NONE 253:INSTRUMENTED_POP_JUMP_IF_NOT_NONE
""")

_PY313_SPECIAL = _pairs("""
3:BINARY_OP_INPLACE_ADD_UNICODE 150:BINARY_OP_ADD_FLOAT 151:BINARY_OP_ADD_INT
152:BINARY_OP_ADD_UNICODE 153:BINARY_OP_MULTIPLY_FLOAT 154:BINARY_OP_MULTIPLY_INT
155:BINARY_OP_SUBTRACT_FLOAT 156:BINARY_OP_SUBTRACT_INT 157:BINARY_SUBSCR_DICT
158:BINARY_SUBSCR_GETITEM 159:BINARY_SUBSCR_LIST_INT 160:BINARY_SUBSCR_STR_INT
161:BINARY_SUBSCR_TUPLE_INT 162:CALL_ALLOC_AND_ENTER_INIT
163:CALL_BOUND_METHOD_EXACT_ARGS 164:CALL_BOUND_METHOD_GENERAL
165:CALL_BUILTIN_CLASS 166:CALL_BUILTIN_FAST 167:CALL_BUILTIN_FAST_WITH_KEYWORDS
168:CALL_BUILTIN_O 169:CALL_ISINSTANCE 170:CALL_LEN 171:CALL_LIST_APPEND
172:CALL_METHOD_DESCRIPTOR_FAST 173:CALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS
174:CALL_METHOD_DESCRIPTOR_NOARGS 175:CALL_METHOD_DESCRIPTOR_O
176:CALL_NON_PY_GENERAL 177:CALL_PY_EXACT_ARGS 178:CALL_PY_GENERAL
179:CALL_STR_1 180:CALL_TUPLE_1 181:CALL_TYPE_1 182:COMPARE_OP_FLOAT
183:COMPARE_OP_INT 184:COMPARE_OP_STR 185:CONTAINS_OP_DICT 186:CONTAINS_OP_SET
187:FOR_ITER_GEN 188:FOR_ITER_LIST 189:FOR_ITER_RANGE 190:FOR_ITER_TUPLE
191:LOAD_ATTR_CLASS 192:LOAD_ATTR_GETATTRIBUTE_OVERRIDDEN
193:LOAD_ATTR_INSTANCE_VALUE 194:LOAD_ATTR_METHOD_LAZY_DICT
195:LOAD_ATTR_METHOD_NO_DICT 196:LOAD_ATTR_METHOD_WITH_VALUES
197:LOAD_ATTR_MODULE 198:LOAD_ATTR_NONDESCRIPTOR_NO_DICT
199:LOAD_ATTR_NONDESCRIPTOR_WITH_VALUES 200:LOAD_ATTR_PROPERTY 201:LOAD_ATTR_SLOT
202:LOAD_ATTR_WITH_HINT 203:LOAD_GLOBAL_BUILTIN 204:LOAD_GLOBAL_MODULE
205:LOAD_SUPER_ATTR_ATTR 206:LOAD_SUPER_ATTR_METHOD 207:RESUME_CHECK
208:SEND_GEN 209:STORE_ATTR_INSTANCE_VALUE 210:STORE_ATTR_SLOT
211:STORE_ATTR_WITH_HINT 212:STORE_SUBSCR_DICT 213:STORE_SUBSCR_LIST_INT
214:TO_BOOL_ALWAYS_TRUE 215:TO_BOOL_BOOL 216:TO_BOOL_INT 217:TO_BOOL_LIST
218:TO_BOOL_NONE 219:TO_BOOL_STR 220:UNPACK_SEQUENCE_LIST
221:UNPACK_SEQUENCE_TUPLE 222:UNPACK_SEQUENCE_TWO_TUPLE
""")

_CACHE_312 = {
    "BINARY_SUBSCR": 1, "STORE_SUBSCR": 1, "UNPACK_SEQUENCE": 1,
    "FOR_ITER": 1, "STORE_ATTR": 4, "LOAD_ATTR": 9, "COMPARE_OP": 1,
    "LOAD_GLOBAL": 4, "BINARY_OP": 1, "SEND": 1, "LOAD_SUPER_ATTR": 1,
    "CALL": 3,
}
_CACHE_313 = {
    "LOAD_GLOBAL": 4, "BINARY_OP": 1, "UNPACK_SEQUENCE": 1,
    "COMPARE_OP": 1, "CONTAINS_OP": 1, "BINARY_SUBSCR": 1, "FOR_ITER": 1,
    "LOAD_SUPER_ATTR": 1, "LOAD_ATTR": 9, "STORE_ATTR": 4, "CALL": 3,
    "STORE_SUBSCR": 1, "SEND": 1, "JUMP_BACKWARD": 1, "TO_BOOL": 3,
    "POP_JUMP_IF_TRUE": 1, "POP_JUMP_IF_FALSE": 1, "POP_JUMP_IF_NONE": 1,
    "POP_JUMP_IF_NOT_NONE": 1,
}

_HASARG_312 = frozenset("""
STORE_NAME DELETE_NAME UNPACK_SEQUENCE FOR_ITER UNPACK_EX STORE_ATTR DELETE_ATTR
STORE_GLOBAL DELETE_GLOBAL SWAP LOAD_CONST LOAD_NAME BUILD_TUPLE BUILD_LIST BUILD_SET
BUILD_MAP LOAD_ATTR COMPARE_OP IMPORT_NAME IMPORT_FROM JUMP_FORWARD POP_JUMP_IF_FALSE
POP_JUMP_IF_TRUE LOAD_GLOBAL IS_OP CONTAINS_OP RERAISE COPY RETURN_CONST BINARY_OP SEND
LOAD_FAST STORE_FAST DELETE_FAST LOAD_FAST_CHECK POP_JUMP_IF_NOT_NONE POP_JUMP_IF_NONE
RAISE_VARARGS GET_AWAITABLE MAKE_FUNCTION BUILD_SLICE JUMP_BACKWARD_NO_INTERRUPT
MAKE_CELL LOAD_CLOSURE LOAD_DEREF STORE_DEREF DELETE_DEREF JUMP_BACKWARD
LOAD_SUPER_ATTR CALL_FUNCTION_EX LOAD_FAST_AND_CLEAR EXTENDED_ARG LIST_APPEND SET_ADD
MAP_ADD COPY_FREE_VARS YIELD_VALUE RESUME MATCH_CLASS FORMAT_VALUE BUILD_CONST_KEY_MAP
BUILD_STRING LIST_EXTEND SET_UPDATE DICT_MERGE DICT_UPDATE CALL KW_NAMES
CALL_INTRINSIC_1 CALL_INTRINSIC_2 LOAD_FROM_DICT_OR_GLOBALS LOAD_FROM_DICT_OR_DEREF
INSTRUMENTED_LOAD_SUPER_ATTR INSTRUMENTED_POP_JUMP_IF_NONE
INSTRUMENTED_POP_JUMP_IF_NOT_NONE INSTRUMENTED_RESUME INSTRUMENTED_CALL
INSTRUMENTED_RETURN_VALUE INSTRUMENTED_YIELD_VALUE INSTRUMENTED_CALL_FUNCTION_EX
INSTRUMENTED_JUMP_FORWARD INSTRUMENTED_JUMP_BACKWARD INSTRUMENTED_RETURN_CONST
INSTRUMENTED_FOR_ITER INSTRUMENTED_POP_JUMP_IF_FALSE INSTRUMENTED_POP_JUMP_IF_TRUE
INSTRUMENTED_END_FOR INSTRUMENTED_END_SEND INSTRUMENTED_INSTRUCTION INSTRUMENTED_LINE
""".split())

_HASARG_313 = frozenset("""
BINARY_OP BUILD_CONST_KEY_MAP BUILD_LIST BUILD_MAP BUILD_SET BUILD_SLICE BUILD_STRING
BUILD_TUPLE CALL CALL_ALLOC_AND_ENTER_INIT CALL_BOUND_METHOD_EXACT_ARGS
CALL_BOUND_METHOD_GENERAL CALL_BUILTIN_CLASS CALL_BUILTIN_FAST
CALL_BUILTIN_FAST_WITH_KEYWORDS CALL_BUILTIN_O CALL_FUNCTION_EX CALL_INTRINSIC_1
CALL_INTRINSIC_2 CALL_ISINSTANCE CALL_KW CALL_LEN CALL_LIST_APPEND
CALL_METHOD_DESCRIPTOR_FAST CALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS
CALL_METHOD_DESCRIPTOR_NOARGS CALL_METHOD_DESCRIPTOR_O CALL_NON_PY_GENERAL
CALL_PY_EXACT_ARGS CALL_PY_GENERAL CALL_STR_1 CALL_TUPLE_1 CALL_TYPE_1 COMPARE_OP
COMPARE_OP_FLOAT COMPARE_OP_INT COMPARE_OP_STR CONTAINS_OP CONTAINS_OP_DICT
CONTAINS_OP_SET CONVERT_VALUE COPY COPY_FREE_VARS DELETE_ATTR DELETE_DEREF DELETE_FAST
DELETE_GLOBAL DELETE_NAME DICT_MERGE DICT_UPDATE ENTER_EXECUTOR EXTENDED_ARG FOR_ITER
FOR_ITER_GEN FOR_ITER_LIST FOR_ITER_RANGE FOR_ITER_TUPLE GET_AWAITABLE IMPORT_FROM
IMPORT_NAME INSTRUMENTED_CALL INSTRUMENTED_CALL_KW INSTRUMENTED_FOR_ITER
INSTRUMENTED_JUMP_BACKWARD INSTRUMENTED_JUMP_FORWARD INSTRUMENTED_LOAD_SUPER_ATTR
INSTRUMENTED_POP_JUMP_IF_FALSE INSTRUMENTED_POP_JUMP_IF_NONE
INSTRUMENTED_POP_JUMP_IF_NOT_NONE INSTRUMENTED_POP_JUMP_IF_TRUE INSTRUMENTED_RESUME
INSTRUMENTED_RETURN_CONST INSTRUMENTED_YIELD_VALUE IS_OP JUMP_BACKWARD
JUMP_BACKWARD_NO_INTERRUPT JUMP_FORWARD LIST_APPEND LIST_EXTEND LOAD_ATTR
LOAD_ATTR_CLASS LOAD_ATTR_GETATTRIBUTE_OVERRIDDEN LOAD_ATTR_INSTANCE_VALUE
LOAD_ATTR_METHOD_LAZY_DICT LOAD_ATTR_METHOD_NO_DICT LOAD_ATTR_METHOD_WITH_VALUES
LOAD_ATTR_MODULE LOAD_ATTR_NONDESCRIPTOR_NO_DICT LOAD_ATTR_NONDESCRIPTOR_WITH_VALUES
LOAD_ATTR_PROPERTY LOAD_ATTR_SLOT LOAD_ATTR_WITH_HINT LOAD_CONST LOAD_DEREF LOAD_FAST
LOAD_FAST_AND_CLEAR LOAD_FAST_CHECK LOAD_FAST_LOAD_FAST LOAD_FROM_DICT_OR_DEREF
LOAD_FROM_DICT_OR_GLOBALS LOAD_GLOBAL LOAD_GLOBAL_BUILTIN LOAD_GLOBAL_MODULE LOAD_NAME
LOAD_SUPER_ATTR LOAD_SUPER_ATTR_ATTR LOAD_SUPER_ATTR_METHOD MAKE_CELL MAP_ADD MATCH_CLASS
POP_JUMP_IF_FALSE POP_JUMP_IF_NONE POP_JUMP_IF_NOT_NONE POP_JUMP_IF_TRUE RAISE_VARARGS
RERAISE RESUME RETURN_CONST SEND SEND_GEN SET_ADD SET_FUNCTION_ATTRIBUTE SET_UPDATE
STORE_ATTR STORE_ATTR_WITH_HINT STORE_DEREF STORE_FAST STORE_FAST_LOAD_FAST
STORE_FAST_STORE_FAST STORE_GLOBAL STORE_NAME SWAP UNPACK_EX UNPACK_SEQUENCE
UNPACK_SEQUENCE_LIST UNPACK_SEQUENCE_TUPLE UNPACK_SEQUENCE_TWO_TUPLE YIELD_VALUE
""".split())


def _base_name(name: str) -> str:
    if name.startswith("INSTRUMENTED_"):
        candidate = name[len("INSTRUMENTED_"):]
        return candidate
    for family in (
        "UNPACK_SEQUENCE", "LOAD_SUPER_ATTR", "BINARY_SUBSCR", "STORE_SUBSCR",
        "BINARY_OP", "COMPARE_OP", "CONTAINS_OP", "FOR_ITER", "LOAD_GLOBAL",
        "LOAD_ATTR", "STORE_ATTR", "TO_BOOL", "CALL",
    ):
        if name == family or name.startswith(family + "_"):
            return family
    if name == "SEND_GEN":
        return "SEND"
    if name == "RESUME_CHECK":
        return "RESUME"
    if name.startswith("LOAD_CONST__"):
        return "LOAD_CONST"
    if name.startswith("LOAD_FAST__"):
        return "LOAD_FAST"
    if name.startswith("STORE_FAST__"):
        return "STORE_FAST"
    return name


@dataclass(frozen=True)
class _OpcodeMeta:
    names: dict[int, str]
    bases: dict[int, str]
    base_numbers: dict[str, int]
    caches: dict[str, int]
    has_arguments: frozenset[str]
    extended_arg: int


def _metadata(standard: dict[int, str], special: dict[int, str], caches: dict[str, int],
              has_arguments: frozenset[str]) -> _OpcodeMeta:
    names = {**standard, **special}
    bases = {number: _base_name(name) for number, name in names.items()}
    base_numbers = {name: number for number, name in standard.items()}
    return _OpcodeMeta(names, bases, base_numbers, caches, has_arguments,
                       base_numbers["EXTENDED_ARG"])


_OPCODES = {
    "3.12": _metadata(_PY312_STANDARD, _PY312_SPECIAL, _CACHE_312, _HASARG_312),
    "3.13": _metadata(_PY313_STANDARD, _PY313_SPECIAL, _CACHE_313, _HASARG_313),
}
_MAGICS = {bytes.fromhex("cb0d0d0a"): "3.12", bytes.fromhex("f30d0d0a"): "3.13"}


class _MarshalReader:
    def __init__(self, data: bytes):
        self.cursor = _Cursor(data)
        self.refs: list[_Value | None] = []
        self.object_count = 0

    def read_root(self) -> _Value:
        value = self._read(0, allow_null=False)
        if value is NULL or not isinstance(value, _Value):
            raise RedepthPycError("marshal root is not an object")
        if self.cursor.remaining():
            raise RedepthPycError("trailing bytes after marshal root")
        if any(item is None for item in self.refs):
            raise RedepthPycError("unresolved marshal reference reservation")
        return value

    def _bounded_count(self, count: int, label: str) -> int:
        if count < 0 or count > MAX_ITEMS:
            raise RedepthPycError(f"{label} count exceeds bounds")
        return count

    def _reserve(self) -> int:
        if len(self.refs) >= MAX_REFS:
            raise RedepthPycError("marshal reference cap exceeded")
        index = len(self.refs)
        self.refs.append(None)
        return index

    def _finish(self, kind: str, value: Any, ref_index: int | None) -> _Value:
        result = _Value(kind, value, ref_index)
        if ref_index is not None:
            self.refs[ref_index] = result
        return result

    def _blob(self, label: str) -> bytes:
        count = self.cursor.i32()
        if count < 0 or count > MAX_BLOB:
            raise RedepthPycError(f"{label} length exceeds bounds")
        return self.cursor.take(count)

    def _text(self, raw: bytes, *, ascii_only: bool = False) -> str:
        try:
            return raw.decode("ascii" if ascii_only else "utf-8", "strict" if ascii_only else "surrogatepass")
        except UnicodeError as exc:
            raise RedepthPycError("invalid marshalled string encoding") from exc

    def _read(self, depth: int, *, allow_null: bool) -> _Value | _Ref | object:
        if depth > MAX_DEPTH:
            raise RedepthPycError("marshal nesting cap exceeded")
        self.object_count += 1
        if self.object_count > MAX_ITEMS:
            raise RedepthPycError("marshal object cap exceeded")
        tag_byte = self.cursor.u8()
        flag_ref = bool(tag_byte & FLAG_REF)
        tag = chr(tag_byte & ~FLAG_REF)
        if tag == "0":
            if flag_ref or not allow_null:
                raise RedepthPycError("unexpected marshal NULL marker")
            return NULL
        if tag == "r":
            if flag_ref:
                raise RedepthPycError("reference object cannot reserve a reference")
            index = self.cursor.i32()
            if index < 0 or index >= len(self.refs):
                raise RedepthPycError("marshal back-reference is out of range")
            return _Ref(index)

        if tag in {"N", "F", "T", "S", "."} and flag_ref:
            # CPython never registers its singleton values in the marshal
            # reference table; accepting the flag would desynchronize indices.
            raise RedepthPycError("singleton marshal value cannot reserve a reference")

        ref_index = self._reserve() if flag_ref else None
        if tag == "N":
            return self._finish("none", None, ref_index)
        if tag == "F":
            return self._finish("bool", False, ref_index)
        if tag == "T":
            return self._finish("bool", True, ref_index)
        if tag == "S":
            return self._finish("stopiteration", "StopIteration", ref_index)
        if tag == ".":
            return self._finish("ellipsis", "Ellipsis", ref_index)
        if tag == "i":
            return self._finish("int", self.cursor.i32(), ref_index)
        if tag == "I":
            return self._finish("int", self.cursor.i64(), ref_index)
        if tag == "l":
            digits_signed = self.cursor.i32()
            digits = self._bounded_count(abs(digits_signed), "long digit")
            value = 0
            for index in range(digits):
                digit = self.cursor.u16()
                if digit > 0x7FFF:
                    raise RedepthPycError("invalid marshal long digit")
                value |= digit << (15 * index)
            if digits and not (value >> (15 * (digits - 1))):
                raise RedepthPycError("non-canonical marshal long")
            if digits_signed < 0:
                value = -value
            return self._finish("int", value, ref_index)
        if tag == "g":
            value = struct.unpack("<d", self.cursor.take(8))[0]
            return self._finish("float", repr(value), ref_index)
        if tag == "y":
            real, imag = struct.unpack("<dd", self.cursor.take(16))
            return self._finish("complex", (repr(real), repr(imag)), ref_index)
        if tag in {"f", "x"}:
            parts = 2 if tag == "x" else 1
            values = []
            for _ in range(parts):
                size = self.cursor.u8()
                raw = self.cursor.take(size)
                try:
                    number = float(raw.decode("ascii"))
                except (UnicodeError, ValueError, OverflowError) as exc:
                    raise RedepthPycError("invalid textual marshal float") from exc
                values.append(repr(number))
            return self._finish("complex" if parts == 2 else "float",
                                tuple(values) if parts == 2 else values[0], ref_index)
        if tag == "s":
            return self._finish("bytes", self._blob("bytes"), ref_index)
        if tag in {"u", "t", "a", "A"}:
            raw = self._blob("string")
            return self._finish("str", self._text(raw, ascii_only=tag in {"a", "A"}), ref_index)
        if tag in {"z", "Z"}:
            raw = self.cursor.take(self.cursor.u8())
            return self._finish("str", self._text(raw, ascii_only=True), ref_index)
        if tag in {"(", ")", "[", "<", ">"}:
            count = self.cursor.u8() if tag == ")" else self._bounded_count(self.cursor.i32(), "container")
            if tag == ")":
                self._bounded_count(count, "container")
            items = tuple(self._required(depth + 1) for _ in range(count))
            kind = {"(": "tuple", ")": "tuple", "[": "list", "<": "set", ">": "frozenset"}[tag]
            return self._finish(kind, items, ref_index)
        if tag == "{":
            pairs = []
            while True:
                key = self._read(depth + 1, allow_null=True)
                if key is NULL:
                    break
                value = self._read(depth + 1, allow_null=False)
                if value is NULL or not isinstance(value, (_Value, _Ref)):
                    raise RedepthPycError("invalid marshal dictionary value")
                pairs.append((key, value))
                if len(pairs) > MAX_ITEMS:
                    raise RedepthPycError("marshal dictionary item cap exceeded")
            return self._finish("dict", tuple(pairs), ref_index)
        if tag == "c":
            raw_code = self._read_code(depth)
            return self._finish("code", raw_code, ref_index)
        raise RedepthPycError(f"unsupported marshal type tag 0x{ord(tag):02x}")

    def _required(self, depth: int) -> _Value | _Ref:
        value = self._read(depth, allow_null=False)
        if value is NULL or not isinstance(value, (_Value, _Ref)):
            raise RedepthPycError("unexpected marshal NULL value")
        return value

    def _read_code(self, depth: int) -> _RawCode:
        integers = [self.cursor.i32() for _ in range(5)]
        if any(value < 0 for value in integers[:4]) or integers[3] > MAX_CODE_UNITS:
            raise RedepthPycError("invalid code-object scalar field")
        fields = [self._required(depth + 1) for _ in range(8)]
        firstlineno = self.cursor.i32()
        if firstlineno < 0:
            raise RedepthPycError("invalid code-object first line")
        linetable = self._required(depth + 1)
        exceptiontable = self._required(depth + 1)
        return _RawCode(
            integers[0], integers[1], integers[2], integers[3], integers[4],
            fields[0], fields[1], fields[2], fields[3], fields[4], fields[5],
            fields[6], fields[7], firstlineno, linetable, exceptiontable,
        )


def _resolve(value: _Value | _Ref, refs: list[_Value | None]) -> _Value:
    seen: set[int] = set()
    current = value
    while isinstance(current, _Ref):
        if current.index in seen or current.index < 0 or current.index >= len(refs):
            raise RedepthPycError("cyclic or invalid marshal reference in required field")
        seen.add(current.index)
        target = refs[current.index]
        if target is None:
            raise RedepthPycError("unresolved marshal reference")
        current = target
    return current


def _expect(value: _Value | _Ref, kind: str, refs: list[_Value | None], label: str) -> Any:
    resolved = _resolve(value, refs)
    if resolved.kind != kind:
        raise RedepthPycError(f"code-object {label} must be {kind}")
    return resolved.value


def _tuple_text(value: _Value | _Ref, refs: list[_Value | None], label: str) -> tuple[str, ...]:
    items = _expect(value, "tuple", refs, label)
    result = []
    for item in items:
        text = _expect(item, "str", refs, label)
        result.append(text)
    return tuple(result)


def _summary(value: _Value | _Ref, refs: list[_Value | None], depth: int = 0,
             seen_refs: frozenset[int] = frozenset()) -> str:
    if depth > 5:
        return "<depth-cap>"
    if isinstance(value, _Ref):
        if value.index in seen_refs:
            return f"<recursive-ref#{value.index}>"
        if value.index < 0 or value.index >= len(refs) or refs[value.index] is None:
            return f"<invalid-ref#{value.index}>"
        return _summary(refs[value.index], refs, depth + 1, seen_refs | {value.index})  # type: ignore[arg-type]
    if value.kind == "none":
        return "None"
    if value.kind in {"bool", "int", "float", "ellipsis", "stopiteration"}:
        return repr(value.value) if value.kind in {"bool", "int"} else str(value.value)
    if value.kind == "complex":
        return f"complex{value.value!r}"
    if value.kind == "str":
        text = value.value
        return repr(text if len(text) <= 160 else text[:157] + "...")
    if value.kind == "bytes":
        raw = value.value
        return f"bytes[{len(raw)}]:{raw[:32].hex()}{'...' if len(raw) > 32 else ''}"
    if value.kind == "code":
        try:
            name = _expect(value.value.name, "str", refs, "name")
        except RedepthPycError:
            name = "?"
        return f"<code {name}>"
    if value.kind in {"tuple", "list", "set", "frozenset"}:
        rows = [_summary(item, refs, depth + 1, seen_refs) for item in value.value[:12]]
        if len(value.value) > 12:
            rows.append("...")
        return f"{value.kind}[{', '.join(rows)}]"
    if value.kind == "dict":
        return f"dict[{len(value.value)}]"
    return f"<{value.kind}>"


_CONST_OPS = {"LOAD_CONST", "RETURN_CONST", "KW_NAMES"}
_NAME_OPS = {
    "STORE_NAME", "DELETE_NAME", "STORE_ATTR", "DELETE_ATTR", "STORE_GLOBAL",
    "DELETE_GLOBAL", "LOAD_NAME", "LOAD_ATTR", "IMPORT_NAME", "IMPORT_FROM",
    "LOAD_GLOBAL", "LOAD_SUPER_ATTR", "LOAD_FROM_DICT_OR_GLOBALS",
}
_LOCAL_OPS = {"LOAD_FAST", "STORE_FAST", "DELETE_FAST", "LOAD_FAST_CHECK", "LOAD_FAST_AND_CLEAR"}
_FREE_OPS = {"MAKE_CELL", "LOAD_CLOSURE", "LOAD_DEREF", "STORE_DEREF", "DELETE_DEREF", "LOAD_FROM_DICT_OR_DEREF"}
_FORWARD_JUMPS = {"FOR_ITER", "JUMP_FORWARD", "POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE", "SEND", "POP_JUMP_IF_NOT_NONE", "POP_JUMP_IF_NONE"}
_BACKWARD_JUMPS = {"JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT"}
_COMPARE = ("<", "<=", "==", "!=", ">", ">=")


def _annotation(base: str, argument: int | None, consts: tuple[_Value | _Ref, ...],
                names: tuple[str, ...], localsplus: tuple[str, ...], refs: list[_Value | None],
                version: str) -> str:
    if argument is None:
        return ""
    if base in _CONST_OPS and 0 <= argument < len(consts):
        return _summary(consts[argument], refs)
    if base in _NAME_OPS:
        shift = 1 if base in {"LOAD_GLOBAL", "LOAD_ATTR"} else 2 if base == "LOAD_SUPER_ATTR" else 0
        index = argument >> shift
        if 0 <= index < len(names):
            return names[index]
    if base in _LOCAL_OPS | _FREE_OPS and 0 <= argument < len(localsplus):
        return localsplus[argument]
    if version == "3.13" and base in {"LOAD_FAST_LOAD_FAST", "STORE_FAST_LOAD_FAST", "STORE_FAST_STORE_FAST"}:
        left, right = argument >> 4, argument & 0x0F
        if left < len(localsplus) and right < len(localsplus):
            return f"{localsplus[left]}, {localsplus[right]}"
    if base == "COMPARE_OP":
        index = argument >> 4 if version == "3.12" else argument >> 5
        if 0 <= index < len(_COMPARE):
            return _COMPARE[index]
    return ""


def _lift_wordcode(code: bytes, version: str, consts: tuple[_Value | _Ref, ...],
                   names: tuple[str, ...], localsplus: tuple[str, ...], refs: list[_Value | None]) -> tuple[tuple[PhysicalInstruction, ...], tuple[str, ...], set[int]]:
    if len(code) % 2 or len(code) // 2 > MAX_CODE_UNITS:
        raise RedepthPycError("wordcode is truncated or exceeds its cap")
    meta = _OPCODES[version]
    rows: list[PhysicalInstruction] = []
    warnings: list[str] = []
    main_offsets: set[int] = set()
    cursor = 0
    logical = 0
    extended = 0
    pending_extended = False
    while cursor < len(code):
        offset = cursor
        opcode = code[offset]
        opname = meta.names.get(opcode)
        if opname is None:
            raise RedepthPycError(f"unsupported Python {version} opcode 0x{opcode:02x} at 0x{offset:x}")
        if opname == "CACHE":
            raise RedepthPycError(f"orphan inline CACHE at 0x{offset:x}")
        base = meta.bases[opcode]
        has_argument = opname in meta.has_arguments or base in meta.has_arguments
        argument = (code[offset + 1] | extended) if has_argument else None
        if base == "EXTENDED_ARG":
            if argument is None:
                raise RedepthPycError("EXTENDED_ARG lacks an argument")
            extended = argument << 8
            if extended >= (1 << 31):
                extended -= 1 << 32
            pending_extended = True
        else:
            extended = 0
            pending_extended = False
        cache_count = meta.caches.get(base, 0)
        after = offset + 2 * (1 + cache_count)
        if after > len(code):
            raise RedepthPycError(f"truncated inline cache after 0x{offset:x}")
        jump_target = None
        if argument is not None and base in _FORWARD_JUMPS:
            jump_target = after + argument * 2
        elif argument is not None and base in _BACKWARD_JUMPS:
            jump_target = after - argument * 2
        annotation = _annotation(base, argument, consts, names, localsplus, refs, version)
        if opname != base:
            annotation = (annotation + "; " if annotation else "") + f"specialized from {base}"
            warnings.append(f"specialized opcode {opname} at 0x{offset:x}")
        if opname.startswith("INSTRUMENTED_"):
            warnings.append(f"instrumented opcode {opname} at 0x{offset:x}")
        if opname == "RESERVED":
            warnings.append(f"reserved opcode at 0x{offset:x}")
        rows.append(PhysicalInstruction(
            offset, logical, opcode, opname, base, argument, cache_count, False,
            None, code[offset:offset + 2].hex(), annotation, jump_target,
        ))
        main_offsets.add(offset)
        for cache_index in range(cache_count):
            cache_offset = offset + 2 + cache_index * 2
            raw = code[cache_offset:cache_offset + 2]
            rows.append(PhysicalInstruction(
                cache_offset, None, raw[0], "CACHE", "CACHE", int.from_bytes(raw, "little"),
                0, True, offset, raw.hex(), f"cache {cache_index + 1}/{cache_count} for {base}", None,
            ))
        logical += 1
        cursor = after
    if pending_extended:
        raise RedepthPycError("wordcode ends with EXTENDED_ARG")
    for row in rows:
        if row.jump_target is not None and row.jump_target not in main_offsets:
            warnings.append(f"jump at 0x{row.physical_offset:x} targets non-instruction 0x{row.jump_target:x}")
    return tuple(rows), tuple(dict.fromkeys(warnings)), main_offsets


def _exception_varint(data: bytes, offset: int, *, record_start: bool) -> tuple[int, int]:
    if offset >= len(data):
        raise RedepthPycError("truncated exception-table varint")
    first = True
    value = 0
    chunks = 0
    while True:
        if offset >= len(data) or chunks >= 10:
            raise RedepthPycError("truncated or overlong exception-table varint")
        byte = data[offset]
        offset += 1
        if first:
            if record_start != bool(byte & 0x80):
                raise RedepthPycError("invalid exception-table record marker")
            first = False
        elif byte & 0x80:
            raise RedepthPycError("unexpected exception-table record marker")
        value = (value << 6) | (byte & 0x3F)
        chunks += 1
        if not byte & 0x40:
            return value, offset


def _parse_exception_table(data: bytes, code_size: int, main_offsets: set[int]) -> tuple[ExceptionEntry, ...]:
    offset = 0
    rows = []
    while offset < len(data):
        if len(rows) >= MAX_EXCEPTION_ENTRIES:
            raise RedepthPycError("exception-table entry cap exceeded")
        start_units, offset = _exception_varint(data, offset, record_start=True)
        length_units, offset = _exception_varint(data, offset, record_start=False)
        target_units, offset = _exception_varint(data, offset, record_start=False)
        packed, offset = _exception_varint(data, offset, record_start=False)
        start, end, target = start_units * 2, (start_units + length_units) * 2, target_units * 2
        if length_units <= 0 or start not in main_offsets or target not in main_offsets:
            raise RedepthPycError("exception table targets a non-instruction")
        if end > code_size or (end != code_size and end not in main_offsets):
            raise RedepthPycError("exception table range is outside wordcode")
        rows.append(ExceptionEntry(start, end, target, packed >> 1, bool(packed & 1)))
    return tuple(rows)


def _nested_codes(value: _Value | _Ref, refs: list[_Value | None], seen: set[int],
                  output: list[_RawCode], depth: int = 0) -> None:
    if depth > 8 or len(output) > MAX_ITEMS:
        return
    if isinstance(value, _Ref):
        if value.index in seen or value.index < 0 or value.index >= len(refs) or refs[value.index] is None:
            return
        seen.add(value.index)
        _nested_codes(refs[value.index], refs, seen, output, depth + 1)  # type: ignore[arg-type]
        return
    if value.kind == "code":
        output.append(value.value)
        return
    if value.kind in {"tuple", "list", "set", "frozenset"}:
        for item in value.value:
            _nested_codes(item, refs, seen, output, depth + 1)
    elif value.kind == "dict":
        for key, item in value.value:
            _nested_codes(key, refs, seen, output, depth + 1)
            _nested_codes(item, refs, seen, output, depth + 1)


def _analyze_code(raw: _RawCode, version: str, refs: list[_Value | None],
                  active: set[int]) -> CodeInfo:
    identity = id(raw)
    if identity in active:
        raise RedepthPycError("recursive code-object graph")
    active.add(identity)
    try:
        code = _expect(raw.code, "bytes", refs, "code")
        consts = _expect(raw.consts, "tuple", refs, "consts")
        names = _tuple_text(raw.names, refs, "names")
        localsplus = _tuple_text(raw.localsplusnames, refs, "localsplusnames")
        localspluskinds = _expect(raw.localspluskinds, "bytes", refs, "localspluskinds")
        if len(localspluskinds) != len(localsplus):
            raise RedepthPycError("localsplus names/kinds length mismatch")
        filename = _expect(raw.filename, "str", refs, "filename")
        name = _expect(raw.name, "str", refs, "name")
        qualname = _expect(raw.qualname, "str", refs, "qualname")
        linetable = _expect(raw.linetable, "bytes", refs, "linetable")
        exceptiontable = _expect(raw.exceptiontable, "bytes", refs, "exceptiontable")
        instructions, warnings, main_offsets = _lift_wordcode(
            code, version, consts, names, localsplus, refs,
        )
        exceptions = _parse_exception_table(exceptiontable, len(code), main_offsets) if exceptiontable else ()
        nested_raw: list[_RawCode] = []
        seen_refs: set[int] = set()
        for constant in consts:
            _nested_codes(constant, refs, seen_refs, nested_raw)
        children = tuple(_analyze_code(child, version, refs, active) for child in nested_raw if id(child) not in active)
        return CodeInfo(
            name, qualname, filename, raw.argcount, raw.posonlyargcount,
            raw.kwonlyargcount, raw.stacksize, raw.flags, raw.firstlineno, len(code),
            tuple(_summary(item, refs) for item in consts), names, localsplus,
            localspluskinds.hex(), len(linetable), len(exceptiontable), instructions,
            tuple(exceptions), children, warnings,
        )
    finally:
        active.remove(identity)


def _parse_header(data: bytes) -> tuple[PycHeader, str]:
    if len(data) < 16:
        raise RedepthPycError("truncated pyc header")
    magic = data[:4]
    version = _MAGICS.get(magic)
    if version is None:
        raise RedepthPycError(f"unsupported pyc magic {magic.hex()}")
    flags = int.from_bytes(data[4:8], "little")
    if flags & ~0x03 or flags == 0x02:
        raise RedepthPycError("invalid PEP 552 pyc flags")
    if flags & 1:
        header = PycHeader(version, magic.hex(), flags, True, bool(flags & 2),
                           None, None, data[8:16].hex())
    else:
        header = PycHeader(version, magic.hex(), flags, False, False,
                           int.from_bytes(data[8:12], "little"),
                           int.from_bytes(data[12:16], "little"), None)
    return header, version


def analyze_pyc(data: bytes) -> PycReport:
    """Analyze one Python 3.12/3.13 pyc without loading its code object.

    All invalid input and resource failures are normalized to
    :class:`RedepthPycError`.
    """
    try:
        if not isinstance(data, bytes):
            raise RedepthPycError("input must be immutable bytes")
        if len(data) > MAX_INPUT:
            raise RedepthPycError("input exceeds the 64 MiB cap")
        header, version = _parse_header(data)
        reader = _MarshalReader(data[16:])
        root_value = reader.read_root()
        if root_value.kind != "code":
            raise RedepthPycError("pyc marshal root is not a code object")
        root = _analyze_code(root_value.value, version, reader.refs, set())
        return PycReport(header, root, reader.object_count, len(reader.refs))
    except RedepthPycError:
        raise
    except Exception as exc:
        raise RedepthPycError(f"pyc analysis failed safely: {type(exc).__name__}") from exc


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise RedepthPycError(message)


def _read_file(path: str) -> bytes:
    with Path(path).open("rb") as handle:
        data = handle.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise RedepthPycError("input exceeds the 64 MiB cap")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="redepth_pyc.py", description=__doc__)
    parser.add_argument("input", help="Python 3.12 or 3.13 .pyc file")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        report = analyze_pyc(_read_file(args.input))
        print(json.dumps(report.to_dict(), indent=2 if args.pretty else None,
                         sort_keys=True, ensure_ascii=True, allow_nan=False))
        return 0
    except (RedepthPycError, OSError) as exc:
        print(f"redepth_pyc: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "RedepthPycError", "PycHeader", "PhysicalInstruction", "ExceptionEntry",
    "CodeInfo", "PycReport", "analyze_pyc", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
