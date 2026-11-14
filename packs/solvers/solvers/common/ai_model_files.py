#!/usr/bin/env python3
"""Static readers for AI model files: pickle, PyTorch checkpoints, joblib, numpy, safetensors,
GGUF, ONNX and Keras. Offline, standard library only.

Nothing here is ever loaded: no pickle.load(s), no Unpickler, no marshal, no torch, numpy, onnx,
safetensors, joblib, h5py or keras import, no eval of anything from a file (a .npy header goes
through ast.literal_eval, which builds literals only). Every string read from a file is data: a
chat template, a doc string or a metadata value that reads like an instruction is reported as text
and changes nothing here.

  analyze(data, name="") -> report dict or None     what the bytes are and every fact read from them
  read_pickle(data)       a pickletools.genops walk with a small symbolic stack (protocols 0 to 5):
                          GLOBAL/STACK_GLOBAL/INST targets, REDUCE/OBJ/NEWOBJ/BUILD arguments, memo
                          use, several pickles in one stream, nested pickles, joblib array frames;
                          a truncated or broken stream is read up to the break
  read_torch_zip(data)    <name>/data.pkl of a PyTorch zip checkpoint, its tensors and storages
  read_npy / read_npz     header (descr, fortran_order, shape); an object array's pickle is walked
  read_safetensors(data)  8-byte length, JSON header: tensors, dtypes, shapes, __metadata__
  read_gguf(data)         magic, version, counts, typed key-value metadata, tensor infos
  read_onnx(data)         a minimal protobuf wire reader: nodes, op types, initializers, string
                          attributes, external-data locations, metadata_props
  read_keras_zip / read_hdf5   config.json (Lambda layers), HDF5 JSON attributes found by scan
  public(report)          the report without its internal symbolic values, JSON-serializable

The question side (signals, solve_set, the CLI) is solvers/toolkits/ai_model_files.py.
"""
import ast
import base64
import binascii
import bz2
import io
import json
import lzma
import pickletools      # the opcode table and genops only; nothing is unpickled
import re
import struct
import zipfile
import zlib

MAX_OPS = 3_000_000             # opcodes read from one stream
MAX_PICKLES = 64                # pickles read from one stream (a legacy torch file has four or more)
MAX_NESTED = 3                  # depth of pickles inside pickles
MAX_INFLATE = 32 * 1024 * 1024  # bytes taken out of one compressed stream or zip member
MAX_STRINGS = 20000
MAX_RENDER = 200                # items of one container shown in a rendered argument

PICKLE_EXT = (".pkl", ".pickle", ".p", ".pck", ".pk", ".joblib", ".pt", ".pth", ".ckpt", ".bin", ".sav", ".model", ".dat")


# ---- symbolic values of the pickle machine ----------------------------------------------------------

class Global:
    __slots__ = ("module", "name")

    def __init__(self, module, name):
        self.module, self.name = str(module), str(name)

    @property
    def dotted(self):
        return f"{self.module}.{self.name}"


class Call:
    __slots__ = ("func", "args", "kwargs", "kind", "pos", "items", "appends", "state")

    def __init__(self, func, args, kind, pos, kwargs=None):
        self.func, self.args, self.kind, self.pos, self.kwargs = func, args, kind, pos, kwargs
        self.items, self.appends, self.state = [], [], None


class Persistent:
    __slots__ = ("pid",)

    def __init__(self, pid):
        self.pid = pid


class Unknown:
    __slots__ = ("why",)

    def __init__(self, why):
        self.why = why


class SymDict:
    __slots__ = ("items",)

    def __init__(self, items=None):
        self.items = list(items or [])

    def get(self, key, default=None):
        for k, v in reversed(self.items):
            if isinstance(k, str) and k == key:
                return v
        return default


class SymSet:
    __slots__ = ("items", "frozen")

    def __init__(self, items=None, frozen=False):
        self.items, self.frozen = list(items or []), frozen


_MARK = object()
_PUSH = {"INT", "BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4", "FLOAT", "BINFLOAT", "STRING", "BINSTRING",
         "SHORT_BINSTRING", "BINBYTES", "SHORT_BINBYTES", "BINBYTES8", "BYTEARRAY8", "UNICODE", "BINUNICODE",
         "SHORT_BINUNICODE", "BINUNICODE8"}
_GETATTR = {"builtins.getattr", "__builtin__.getattr"}
_IMPORT = {"builtins.__import__", "__builtin__.__import__", "importlib.import_module", "importlib.__import__"}


def callable_name(func, depth=0):
    """'module.name' of what a call invokes: a global, or getattr(<global or imported module>, 'name')
    spelled out. None when the callable is something else (the result of another call)."""
    if isinstance(func, Global):
        return func.dotted
    if isinstance(func, Call) and depth < 4 and isinstance(func.args, tuple):
        inner = callable_name(func.func, depth + 1)
        if inner in _GETATTR and len(func.args) >= 2 and isinstance(func.args[1], str):
            base = callable_name(func.args[0], depth + 1)
            return f"{base}.{func.args[1]}" if base else None
        if inner in _IMPORT and func.args and isinstance(func.args[0], str):
            return func.args[0]
        # operator.attrgetter('system')(__import__('os')) is os.system; functools.partial(f, ...)() is f
        # (both are how real scanners' test pickles hide the callable: picklescan malicious12, malicious19)
        if isinstance(func.func, Call) and isinstance(func.func.args, tuple) and func.func.args:
            maker = callable_name(func.func.func, depth + 1)
            if maker == "operator.attrgetter" and len(func.func.args) == 1 and isinstance(func.func.args[0], str) \
                    and len(func.args) == 1:
                base = callable_name(func.args[0], depth + 1)
                return f"{base}.{func.func.args[0]}" if base else None
    if isinstance(func, Call) and depth < 4 and isinstance(func.args, tuple) and func.args \
            and callable_name(func.func, depth + 1) == "functools.partial":
        return callable_name(func.args[0], depth + 1)
    return None


def callable_module(func, depth=0):
    """The module the callable of callable_name() comes from, as the stream names it: 'bdb' for the
    global ('bdb', 'Bdb.run') and for getattr(bdb.Bdb, 'run'), 'os' for getattr(__import__('os'),
    'system'). The dotted name cannot say it: 'bdb.Bdb.run' splits as 'bdb.Bdb' + 'run'."""
    if isinstance(func, Global):
        return func.module
    if isinstance(func, Call) and depth < 4 and isinstance(func.args, tuple) and func.args:
        inner = callable_name(func.func, depth + 1)
        if inner in _GETATTR and len(func.args) >= 2:
            return callable_module(func.args[0], depth + 1)
        if inner in _IMPORT and isinstance(func.args[0], str):
            return func.args[0]
        if inner == "functools.partial":
            return callable_module(func.args[0], depth + 1)
        if isinstance(func.func, Call) and callable_name(func.func.func, depth + 1) == "operator.attrgetter" and len(func.args) == 1:
            return callable_module(func.args[0], depth + 1)
    return None


def _text(b):
    """bytes as text when they are printable ASCII, else None."""
    if isinstance(b, (bytes, bytearray)) and b and all(32 <= c < 127 or c in (9, 10, 13) for c in b):
        return bytes(b).decode("ascii")
    return None


def render(v, depth=0):
    """A symbolic value as plain JSON-serializable data."""
    if v is None or isinstance(v, (bool, int, float, str)):
        return v if not isinstance(v, int) or isinstance(v, bool) or abs(v) < 1 << 63 else {"int": str(v)}
    if isinstance(v, (bytes, bytearray)):
        t = _text(v)
        return {"bytes": t} if t is not None else {"bytes_hex": bytes(v[:256]).hex(), "length": len(v)}
    if depth > 6:
        return {"unknown": "nested too deep to show"}
    if isinstance(v, (tuple, list)):
        return [render(x, depth + 1) for x in v[:MAX_RENDER]]
    if isinstance(v, Global):
        return {"global": v.dotted}
    if isinstance(v, Call):
        out = {"call": callable_name(v.func), "kind": v.kind,
               "args": render(v.args, depth + 1) if isinstance(v.args, (tuple, list)) else [render(v.args, depth + 1)]}
        if out["call"] is None:
            out["callable"] = render(v.func, depth + 1)
        if v.items:
            out["items"] = [[render(k, depth + 1), render(x, depth + 1)] for k, x in v.items[:MAX_RENDER]]
        if v.state is not None:
            out["state"] = render(v.state, depth + 1)
        return out
    if isinstance(v, SymDict):
        return {"dict": [[render(k, depth + 1), render(x, depth + 1)] for k, x in v.items[:MAX_RENDER]]}
    if isinstance(v, SymSet):
        return {"set": [render(x, depth + 1) for x in v.items[:MAX_RENDER]]}
    if isinstance(v, Persistent):
        return {"persistent_id": render(v.pid, depth + 1)}
    if isinstance(v, Unknown):
        return {"unknown": v.why}
    return {"unknown": type(v).__name__}


# ---- the pickle walk -----------------------------------------------------------------------------------

def _dtype_itemsize(dt):
    """Bytes per element of a numpy dtype as it is pickled (numpy.dtype('f8', False, True)); 0 for an
    object dtype (its array is pickled inline), None when it cannot be read."""
    if isinstance(dt, Call) and isinstance(dt.args, tuple) and dt.args and isinstance(dt.args[0], str):
        m = re.fullmatch(r"[<>|=]?([A-Za-z])(\d+)", dt.args[0])
        if not m:
            return None
        if m.group(1) == "O":
            return 0
        n = int(m.group(2))
        if m.group(1) == "U":
            n *= 4
        if m.group(1) == "V" and isinstance(dt.state, tuple) and len(dt.state) > 5 and isinstance(dt.state[5], int) and dt.state[5] > 0:
            n = dt.state[5]
        return n
    return None


def _walk(buf, depth, acc):
    """Walk one pickle from buf's position. Appends globals, calls, strings and byte constants to
    acc as they are met, so a stream that breaks keeps everything before the break."""
    start = buf.tell()
    stack, memo = [], {}
    pk = {"start": start, "end": None, "protocol": None, "proto_stated": False, "max_opcode_protocol": 0, "ops": 0,
          "complete": False, "error": None, "value": None, "memo_puts": 0, "memo_gets": 0}

    def push(v):
        stack.append(v)

    def pop():
        if not stack or stack[-1] is _MARK:
            return Unknown("stack underflow")
        return stack.pop()

    def top():
        return stack[-1] if stack and stack[-1] is not _MARK else None

    def popmark():
        items = []
        while stack:
            v = stack.pop()
            if v is _MARK:
                break
            items.append(v)
        items.reverse()
        return items

    def call(func, args, kind, pos, kwargs=None):
        c = Call(func, args, kind, pos, kwargs)
        acc["calls"].append((c, depth))
        return c

    gen = pickletools.genops(buf)
    while True:
        try:
            op, arg, pos = next(gen)
        except StopIteration:
            break
        except Exception as e:                      # short read, unknown opcode, bad text: the break
            pk["error"] = f"{type(e).__name__}: {str(e)[:160]}"
            break
        pk["ops"] += 1
        if pk["ops"] > MAX_OPS:
            pk["error"] = f"more than {MAX_OPS} opcodes"
            break
        n = op.name
        pk["max_opcode_protocol"] = max(pk["max_opcode_protocol"], op.proto)
        if n == "PROTO":
            pk["protocol"], pk["proto_stated"] = arg, True
        elif n == "FRAME" or n == "READONLY_BUFFER":
            pass
        elif n == "STOP":
            pk["complete"] = True
            pk["value"] = stack[-1] if stack and stack[-1] is not _MARK else None
            break
        elif n in _PUSH:
            push(arg)
            if isinstance(arg, str):
                if len(acc["strings"]) < MAX_STRINGS:
                    acc["strings"].append(arg)
                if n in ("STRING", "BINSTRING", "SHORT_BINSTRING"):      # a protocol 0-2 str8 may hold bytes
                    acc["bytes"].append((arg.encode("latin-1", "replace"), depth))
            elif isinstance(arg, (bytes, bytearray)):
                acc["bytes"].append((bytes(arg), depth))
                t = _text(arg)
                if t is not None and len(acc["strings"]) < MAX_STRINGS:
                    acc["strings"].append(t)
        elif n == "NONE":
            push(None)
        elif n == "NEWTRUE":
            push(True)
        elif n == "NEWFALSE":
            push(False)
        elif n == "EMPTY_TUPLE":
            push(())
        elif n == "EMPTY_LIST":
            push([])
        elif n == "EMPTY_DICT":
            push(SymDict())
        elif n == "EMPTY_SET":
            push(SymSet())
        elif n == "MARK":
            stack.append(_MARK)
        elif n == "POP":
            if stack:
                stack.pop()
        elif n == "POP_MARK":
            popmark()
        elif n == "DUP":
            push(top())
        elif n == "TUPLE":
            push(tuple(popmark()))
        elif n in ("TUPLE1", "TUPLE2", "TUPLE3"):
            k = int(n[-1])
            items = [pop() for _ in range(k)]
            push(tuple(reversed(items)))
        elif n == "LIST":
            push(list(popmark()))
        elif n == "DICT":
            items = popmark()
            push(SymDict(zip(items[0::2], items[1::2])))
        elif n == "FROZENSET":
            push(SymSet(popmark(), frozen=True))
        elif n in ("APPEND", "APPENDS"):
            vs = [pop()] if n == "APPEND" else popmark()
            t = top()
            if isinstance(t, list):
                t.extend(vs)
            elif isinstance(t, Call):
                t.appends.extend(vs)
        elif n in ("SETITEM", "SETITEMS"):
            if n == "SETITEM":
                v = pop()
                pairs = [(pop(), v)]
            else:
                items = popmark()
                pairs = list(zip(items[0::2], items[1::2]))
            t = top()
            if isinstance(t, (SymDict, Call)):
                t.items.extend(pairs)
        elif n == "ADDITEMS":
            vs = popmark()
            t = top()
            if isinstance(t, SymSet):
                t.items.extend(vs)
        elif n == "GLOBAL":
            module, _, name = str(arg).partition(" ")
            g = Global(module, name)
            acc["globals"].append((g.dotted, depth))
            push(g)
        elif n == "STACK_GLOBAL":
            name, module = pop(), pop()
            if isinstance(name, str) and isinstance(module, str):
                g = Global(module, name)
                acc["globals"].append((g.dotted, depth))
                push(g)
            else:
                push(Unknown("STACK_GLOBAL of something that is not two strings"))
        elif n == "INST":
            module, _, name = str(arg).partition(" ")
            g = Global(module, name)
            acc["globals"].append((g.dotted, depth))
            push(call(g, tuple(popmark()), "inst", pos))
        elif n == "OBJ":
            items = popmark()
            push(call(items[0] if items else Unknown("OBJ with no class"), tuple(items[1:]), "obj", pos))
        elif n == "REDUCE":
            args = pop()
            push(call(pop(), args, "reduce", pos))
        elif n == "NEWOBJ":
            args = pop()
            push(call(pop(), args, "newobj", pos))
        elif n == "NEWOBJ_EX":
            kwargs, args = pop(), pop()
            push(call(pop(), args, "newobj_ex", pos, kwargs))
        elif n == "BUILD":
            state = pop()
            t = top()
            if isinstance(t, Call):
                t.state = state
                acc["builds"].append((t, state, depth))
                if callable_name(t.func) in ("joblib.numpy_pickle.NumpyArrayWrapper", "sklearn.externals.joblib.numpy_pickle.NumpyArrayWrapper") \
                        and isinstance(state, SymDict):
                    # joblib writes the array's raw bytes into the stream right after its wrapper.
                    shape, size = state.get("shape"), _dtype_itemsize(state.get("dtype"))
                    acc["arrays"].append({"shape": list(shape) if isinstance(shape, tuple) else None,
                                          "dtype": state.get("dtype").args[0] if size is not None else None,
                                          "order": state.get("order") if isinstance(state.get("order"), str) else None})
                    if size is None or not isinstance(shape, tuple) or not all(isinstance(d, int) and d >= 0 for d in shape):
                        pk["error"] = "a joblib array frame whose size cannot be read"
                        break
                    if size:
                        count = 1
                        for d in shape:
                            count *= d
                        if state.get("numpy_array_alignment_bytes") is not None:
                            pad = buf.read(1)
                            buf.seek(pad[0] if pad else 0, 1)
                        if buf.tell() + count * size > len(buf.getbuffer()):
                            pk["error"] = "a joblib array frame runs past the end of the file"
                            break
                        buf.seek(count * size, 1)
        elif n in ("PUT", "BINPUT", "LONG_BINPUT"):
            memo[arg] = top()
            pk["memo_puts"] += 1
        elif n == "MEMOIZE":
            memo[len(memo)] = top()
            pk["memo_puts"] += 1
        elif n in ("GET", "BINGET", "LONG_BINGET"):
            push(memo[arg] if arg in memo else Unknown(f"memo {arg} was never stored"))
            pk["memo_gets"] += 1
        elif n == "PERSID":
            push(Persistent(arg))
        elif n == "BINPERSID":
            push(Persistent(pop()))
        elif n in ("EXT1", "EXT2", "EXT4"):
            push(Unknown(f"extension registry code {arg}"))
        elif n == "NEXT_BUFFER":
            push(Unknown("an out-of-band buffer"))
        else:
            push(Unknown(n))
    pk["end"] = buf.tell()
    if pk["protocol"] is None:
        pk["protocol"] = pk["max_opcode_protocol"]      # not stated by the stream: what pickletools infers
    if not pk["complete"]:
        pk["stack_at_break"] = [render(v) for v in stack[-8:] if v is not _MARK]
        pk["value"] = None
        if pk["error"] is None:
            pk["error"] = "the stream ends before STOP"
    return pk


def _starts_pickle(data, at=0):
    return len(data) >= at + 2 and data[at] == 0x80 and data[at + 1] <= 5


def looks_pickle(data: bytes, name: str = "") -> bool:
    """A stream with a PROTO header (protocols 2 to 5), or one without (0 and 1) that walks cleanly
    to a STOP at its end, or breaks only after several opcodes under a pickle file name."""
    if _starts_pickle(data):
        return True
    if not data or len(data) < 2 or chr(data[0]) not in pickletools.code2op:
        return False
    acc = {"globals": [], "calls": [], "strings": [], "bytes": [], "builds": [], "arrays": []}
    buf = io.BytesIO(data)
    pk = _walk(buf, 0, acc)
    if pk["complete"] and pk["ops"] >= 3 and not data[pk["end"]:].strip():
        return True
    if not name.lower().endswith(PICKLE_EXT):
        return False
    if pk["ops"] >= 4 and bool(acc["globals"] or acc["strings"]):
        return True
    # a stream that breaks right after naming a global (picklescan's broken_model.pkl: GLOBAL
    # builtins.exec, MARK, then a string whose length runs past the end): read up to the break
    return pk["ops"] >= 1 and any(_DOTTED.match(str(g[0] if isinstance(g, tuple) else g)) for g in acc["globals"])


_DOTTED = re.compile(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+\Z")


_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")


def decode_embedded(text):
    """(encoding, bytes) when the whole string is strict base64 or hex of at least 16 characters."""
    if not isinstance(text, str):
        return None
    s = text.strip()
    if not 16 <= len(s) <= 4 * 1024 * 1024:
        return None
    if _HEX.fullmatch(s):
        return "hex", bytes.fromhex(s)
    if len(s) % 4 == 0 and _B64.fullmatch(s):
        try:
            alt = "-_" if ("-" in s or "_" in s) else None
            return "base64", base64.b64decode(s, altchars=alt, validate=True)
        except (binascii.Error, ValueError):
            return None
    return None


def inflate(data: bytes):
    """(method, bytes) of a zlib, gzip, bzip2, xz, lzma or joblib 'ZF' stream, capped; else None."""
    try:
        if data[:2] == b"\x1f\x8b":
            return "gzip", zlib.decompressobj(31).decompress(data, MAX_INFLATE)
        if data[:2] == b"ZF":                               # joblib before 0.10: 'ZF' + hex length + zlib
            at = data.find(b"x", 2, 24)
            return ("zlib", zlib.decompressobj().decompress(data[at:], MAX_INFLATE)) if at > 0 else None
        if len(data) > 2 and data[0] & 0x0F == 8 and (data[0] << 8 | data[1]) % 31 == 0:
            return "zlib", zlib.decompressobj().decompress(data, MAX_INFLATE)
        if data[:3] == b"BZh":
            return "bzip2", bz2.BZ2Decompressor().decompress(data, MAX_INFLATE)
        if data[:6] == b"\xfd7zXZ\x00":
            return "xz", lzma.LZMADecompressor().decompress(data, MAX_INFLATE)
        if data[:3] == b"\x5d\x00\x00":
            return "lzma", lzma.LZMADecompressor(lzma.FORMAT_ALONE).decompress(data, MAX_INFLATE)
    except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError):
        return None
    return None


def read_pickle(data: bytes, depth: int = 0) -> dict:
    """The static reading of a pickle stream (see the module text). Never unpickles."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    acc = {"globals": [], "calls": [], "strings": [], "bytes": [], "builds": [], "arrays": []}
    buf = io.BytesIO(data)
    pickles = []
    while buf.tell() < len(data) and len(pickles) < MAX_PICKLES:
        if pickles and not _starts_pickle(data, buf.tell()):
            break
        pk = _walk(buf, depth, acc)
        pickles.append(pk)
        if not pk["complete"]:
            break
    nested, decoded = [], []
    if depth < MAX_NESTED:
        seen = set()
        candidates = [(b, "bytes") for b, _ in acc["bytes"]]
        for s in list(acc["strings"]):
            got = decode_embedded(s)
            if got:
                enc, raw = got
                packed = inflate(raw)
                if packed:
                    enc, raw = f"{enc}+{packed[0]}", packed[1]
                t = _text(raw)
                if _starts_pickle(raw):
                    candidates.append((raw, enc))
                elif t is not None:
                    decoded.append({"encoding": enc, "text": t})
                    again = decode_embedded(t)              # one more level (base64 of base64, hex of base64)
                    t2 = _text(again[1]) if again else None
                    if t2 is not None:
                        decoded.append({"encoding": f"{enc}+{again[0]}", "text": t2})
        for raw, how in candidates:
            if raw in seen:
                continue
            seen.add(raw)
            packed = inflate(raw) if not _starts_pickle(raw) else None
            if packed:
                raw, how = packed[1], f"{how}+{packed[0]}"
            if len(raw) >= 4 and _starts_pickle(raw):
                sub = read_pickle(raw, depth + 1)
                if sub["ops"] >= 2:
                    sub["carried_as"] = how
                    nested.append(sub)
    complete = bool(pickles) and all(p["complete"] for p in pickles)
    end = pickles[-1]["end"] if pickles else 0
    stated = [p["protocol"] for p in pickles if p["proto_stated"]]
    globals_, calls = [], []
    for g, d in acc["globals"]:
        if g not in globals_:
            globals_.append(g)
    for c, d in acc["calls"]:
        calls.append({"kind": c.kind, "callable": callable_name(c.func), "module": callable_module(c.func), "pos": c.pos,
                      "args": render(c.args) if isinstance(c.args, (tuple, list)) else [render(c.args)],
                      **({"kwargs": render(c.kwargs)} if c.kwargs is not None else {}),
                      **({"callable_value": render(c.func)} if callable_name(c.func) is None else {})})
    strings = list(dict.fromkeys(acc["strings"] + [d["text"] for d in decoded]))
    rep = {"kind": "pickle", "size": len(data),
           # the protocol the stream states (its PROTO opcode), when every pickle in it states the same one
           "protocol": stated[0] if stated and len(set(stated)) == 1 and len(stated) == len(pickles) else None,
           "protocol_inferred": max((p["protocol"] for p in pickles), default=None),
           "protocols": [p["protocol"] for p in pickles], "pickles": len(pickles),
           "ops": sum(p["ops"] for p in pickles), "complete": complete, "truncated": not complete,
           "error": next((p["error"] for p in pickles if p["error"]), None),
           "stack_at_break": next((p["stack_at_break"] for p in pickles if not p["complete"]), None),
           "trailing_bytes": len(data) - end if complete else 0,
           "memo_puts": sum(p["memo_puts"] for p in pickles), "memo_gets": sum(p["memo_gets"] for p in pickles),
           "globals": globals_, "calls": calls,
           # GLOBAL, STACK_GLOBAL and INST opcodes of this stream (a global named twice counts twice)
           "global_ops": len(acc["globals"]),
           "builds": [{"callable": callable_name(o.func), "state": render(s)} for o, s, _ in acc["builds"][:MAX_RENDER]],
           "strings": strings, "decoded": decoded, "arrays": acc["arrays"], "nested": nested,
           "_values": [p["value"] for p in pickles]}
    for sub in nested:                                      # what a nested pickle holds is part of the file
        rep["globals"] += [g for g in sub["globals"] if g not in rep["globals"]]
        rep["calls"] += [{**c, "nested": c.get("nested", 0) + 1} for c in sub["calls"]]
        rep["strings"] = list(dict.fromkeys(rep["strings"] + sub["strings"]))
    if any(g.startswith(("joblib.", "sklearn.externals.joblib.")) for g in rep["globals"]):
        rep["kind"] = "joblib"
    v0 = pickles[0]["value"] if pickles else None
    if isinstance(v0, int) and v0 == 0x1950A86A20F9469CFC6C and len(pickles) > 1:
        rep["kind"] = "torch_legacy"
    if rep["kind"] in ("pickle", "torch_legacy"):
        flags = {}
        rep["tensors"] = torch_tensors(rep["_values"], flags)
        rep["tensors_capped"] = bool(flags.get("capped"))
    return rep


# ---- PyTorch ---------------------------------------------------------------------------------------------

TORCH_STORAGE = {"FloatStorage": "float32", "DoubleStorage": "float64", "HalfStorage": "float16", "BFloat16Storage": "bfloat16",
                 "LongStorage": "int64", "IntStorage": "int32", "ShortStorage": "int16", "CharStorage": "int8",
                 "ByteStorage": "uint8", "BoolStorage": "bool", "ComplexFloatStorage": "complex64",
                 "ComplexDoubleStorage": "complex128", "QInt8Storage": "qint8", "QUInt8Storage": "quint8",
                 "QInt32Storage": "qint32"}


def torch_tensors(values, flags=None) -> list:
    """Every torch._utils._rebuild_tensor* call reachable from the pickles' values, with the dict key
    it sits under: [{name, path, shape, stride, dtype, storage_type, storage_key, location, offset}].
    flags["capped"] is set when the walk stopped short (too deep, too many, a value it cannot see
    into), so the list may not be all of them."""
    out, seen = [], set()
    flags = flags if isinstance(flags, dict) else {}

    def tensor(c, path):
        args = c.args if isinstance(c.args, tuple) else ()
        name = callable_name(c.func) or ""
        if name.endswith("_rebuild_parameter") or name.endswith("_rebuild_parameter_with_state"):
            return tensor(args[0], path) if args and isinstance(args[0], Call) else None
        rec = {"name": next((p for p in reversed(path) if isinstance(p, str)), None),
               "path": ".".join(str(p) for p in path), "shape": None, "dtype": None, "storage_type": None,
               "storage_key": None, "location": None, "offset": None, "stride": None, "rebuild": name}
        if args and isinstance(args[0], Persistent) and isinstance(args[0].pid, tuple) and len(args[0].pid) >= 4:
            pid = args[0].pid
            st = pid[1].name if isinstance(pid[1], Global) else None
            rec.update(storage_type=st, dtype=TORCH_STORAGE.get(st), storage_key=pid[2] if isinstance(pid[2], str) else None,
                       location=pid[3] if isinstance(pid[3], str) else None)
        if len(args) > 2 and isinstance(args[2], tuple) and all(isinstance(d, int) for d in args[2]):
            rec["shape"] = list(args[2])
            rec["offset"] = args[1] if isinstance(args[1], int) else None
            if len(args) > 3 and isinstance(args[3], tuple) and all(isinstance(d, int) for d in args[3]):
                rec["stride"] = list(args[3])       # in elements, like offset (B-116: a transposed view is not contiguous)
        out.append(rec)

    def visit(v, path, depth):
        if isinstance(v, Unknown):
            flags["capped"] = True
            return
        if depth > 14 or len(out) > 50000:
            if isinstance(v, (Call, SymDict, list, tuple)):
                flags["capped"] = True
            return
        if id(v) in seen:
            return
        if isinstance(v, (Call, SymDict, list, tuple)):
            seen.add(id(v))
        if isinstance(v, Call):
            name = callable_name(v.func) or ""
            if name.startswith("torch.") and "_rebuild_" in name and ("tensor" in name or "parameter" in name):
                tensor(v, path)
                return
            for k, x in v.items:
                visit(x, path + [k if isinstance(k, (str, int)) else "?"], depth + 1)
            visit(v.args, path, depth + 1)
            visit(v.state, path, depth + 1)
        elif isinstance(v, SymDict):
            for k, x in v.items:
                visit(x, path + [k if isinstance(k, (str, int)) else "?"], depth + 1)
        elif isinstance(v, (list, tuple)):
            for i, x in enumerate(v):
                visit(x, path + [i], depth + 1)

    for v in values or []:
        visit(v, [], 0)
    return out


def _zip_members(data: bytes):
    """{name: bytes} of a zip, each member capped; None when it is not a readable zip."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, OSError):
        return None
    out = ZipMembers()
    for info in zf.infolist()[:5000]:
        if info.is_dir():
            continue
        try:
            with zf.open(info) as f:
                out[info.filename] = f.read(MAX_INFLATE)
        except Exception as e:          # an encrypted or damaged member is not read ...
            raw, why = _zip_raw_member(data, info, e)
            out[info.filename] = raw    # ... unless its bytes are there in the clear (see _zip_raw_member)
            if raw is not None:
                out.tricks.append({"member": info.filename, "trick": why})
    return out


class ZipMembers(dict):
    """{name: bytes or None} plus `tricks`: members the zip module refused and that were read all
    the same, each with the reason. A loader that does not check what the zip module checks
    (PyTorch's own reader) loads such a member, so a scanner that skips it is blind to it."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.tricks = []


def _zip_raw_member(data: bytes, info, error):
    """(bytes, reason) of a member zipfile refused, when the directory entry's CRC-32 proves the
    bytes at its offset are the member in the clear: the encryption flag set on plain data
    (picklescan's malicious1_0x1.zip) or a local header whose name differs from the directory's
    (malicious1_central_directory.zip). (None, None) for anything else: real encryption stays unread."""
    try:
        at = info.header_offset
        if data[at:at + 4] != b"PK\x03\x04" or info.compress_size > MAX_INFLATE:
            return None, None
        n, m = struct.unpack_from("<HH", data, at + 26)
        local_name = data[at + 30:at + 30 + n]
        body = data[at + 30 + n + m:at + 30 + n + m + info.compress_size]
        if info.compress_type == 0:
            raw = body
        elif info.compress_type == 8:
            raw = zlib.decompressobj(-15).decompress(body, MAX_INFLATE)
        else:
            return None, None
        if len(raw) != info.file_size or zlib.crc32(raw) & 0xFFFFFFFF != info.CRC:
            return None, None
        if info.flag_bits & 1:
            return raw, "encryption flag set on a member stored in the clear (its CRC-32 matches)"
        if local_name != info.filename.encode("utf-8", "replace"):
            return raw, f"local header names it {local_name.decode('latin-1')!r}, the directory {info.filename!r}"
        return raw, f"the zip module refused it ({type(error).__name__}) and its CRC-32 matches"
    except (struct.error, zlib.error, ValueError, OverflowError):
        return None, None


def read_torch_zip(data: bytes, members=None) -> dict:
    members = members if members is not None else _zip_members(data)
    if not members:
        return None
    pkls = [n for n in members if n.rsplit("/", 1)[-1] in ("data.pkl", "constants.pkl", "attributes.pkl") and members[n] is not None]
    main = next((n for n in pkls if n.endswith("data.pkl")), None)
    if not main:
        return None
    root = main[:-len("data.pkl")]
    rep = read_pickle(members[main])
    rep["kind"] = "torch_zip"
    rep["pickle_member"] = main
    rep["archive_name"] = root.rstrip("/") or None
    rep["members"] = sorted(members)
    rep["storages"] = [{"key": n[len(root) + 5:], "size": len(members[n] or b"")} for n in sorted(members) if n.startswith(root + "data/")]
    ver = members.get(root + "version")
    rep["format_version"] = _text(ver.strip()) if ver else None
    order = members.get(root + "byteorder")
    rep["byteorder"] = _text(order.strip()) if order else None
    rep["torchscript"] = any(n.startswith(root + "code/") for n in members)
    rep["code_members"] = sorted(n for n in members if n.startswith(root + "code/") and n.endswith(".py"))
    rep["zip_tricks"] = list(getattr(members, "tricks", []))
    rep["pickle_size"], rep["size"] = rep.get("size"), len(data)       # size is the file's, as for every other kind
    flags = {}
    rep["tensors"] = torch_tensors(rep["_values"], flags)
    rep["tensors_capped"] = bool(flags.get("capped"))
    for n in pkls:
        if n != main:
            sub = read_pickle(members[n])
            rep["globals"] += [g for g in sub["globals"] if g not in rep["globals"]]
            rep["calls"] += [{**c, "member": n} for c in sub["calls"]]
            rep["strings"] = list(dict.fromkeys(rep["strings"] + sub["strings"]))
    return rep


# ---- numpy -----------------------------------------------------------------------------------------------

def read_npy(data: bytes) -> dict:
    if not isinstance(data, (bytes, bytearray)):
        return None
    if data[:6] != b"\x93NUMPY" or len(data) < 10:
        return None
    major, minor = data[6], data[7]
    rep = {"kind": "npy", "size": len(data), "format_version": f"{major}.{minor}", "descr": None, "fortran_order": None,
           "shape": None, "object_array": False, "error": None, "strings": [], "globals": [], "calls": []}
    try:
        if major == 1:
            hlen, at = struct.unpack_from("<H", data, 8)[0], 10
        else:
            hlen, at = struct.unpack_from("<I", data, 8)[0], 12
        raw = data[at:at + hlen]
        if len(raw) < hlen:
            rep["error"] = "the header runs past the end of the file"
        header = ast.literal_eval(raw.decode("utf-8" if major >= 3 else "latin-1").strip())     # literals only
        if not isinstance(header, dict):
            raise ValueError("the header is not a dict")
        rep["header"] = {str(k): (list(v) if isinstance(v, tuple) else v) for k, v in header.items()
                         if isinstance(v, (str, int, bool, tuple, list))}
        descr = header.get("descr")
        rep["descr"] = descr if isinstance(descr, str) else json.dumps(render(descr))
        rep["fortran_order"] = header.get("fortran_order") if isinstance(header.get("fortran_order"), bool) else None
        shape = header.get("shape")
        rep["shape"] = list(shape) if isinstance(shape, tuple) and all(isinstance(d, int) for d in shape) else None
        rep["data_offset"] = at + hlen
        rep["object_array"] = isinstance(descr, str) and descr.lstrip("<>|=").startswith("O")
        if rep["object_array"] and len(data) > at + hlen:
            sub = read_pickle(data[at + hlen:])
            sub.pop("_values", None)
            rep.update(pickle=sub, globals=sub["globals"], calls=sub["calls"], strings=sub["strings"],
                       protocol=sub["protocol"], truncated=sub["truncated"])
    except (struct.error, ValueError, SyntaxError, UnicodeDecodeError, MemoryError, RecursionError) as e:
        rep["error"] = f"{type(e).__name__}: {str(e)[:120]}"
    rep["tensors"] = [{"name": None, "shape": rep["shape"], "dtype": rep["descr"]}] if rep["shape"] is not None else []
    return rep


def read_npz(data: bytes, members=None) -> dict:
    members = members if members is not None else _zip_members(data)
    if not members or not all(n.endswith(".npy") for n in members):
        return None
    rep = {"kind": "npz", "size": len(data), "members": sorted(members), "tensors": [], "arrays": [], "globals": [],
           "calls": [], "strings": [], "object_array": False}
    for n in members:                                       # the archive's own order
        sub = read_npy(members[n] or b"")
        if sub is None:
            return None
        name = n[:-4]
        rep["arrays"].append({"name": name, "shape": sub["shape"], "dtype": sub["descr"], "fortran_order": sub["fortran_order"],
                              "object_array": sub["object_array"]})
        rep["tensors"].append({"name": name, "shape": sub["shape"], "dtype": sub["descr"]})
        rep["object_array"] |= sub["object_array"]
        rep["globals"] += [g for g in sub["globals"] if g not in rep["globals"]]
        rep["calls"] += [{**c, "member": n} for c in sub["calls"]]
        rep["strings"] = list(dict.fromkeys(rep["strings"] + sub["strings"]))
    return rep


# ---- safetensors -----------------------------------------------------------------------------------------

SAFETENSORS_NUMPY = {"F64": "float64", "F32": "float32", "F16": "float16", "BF16": "bfloat16", "I64": "int64", "I32": "int32",
                     "I16": "int16", "I8": "int8", "U64": "uint64", "U32": "uint32", "U16": "uint16", "U8": "uint8", "BOOL": "bool"}


def read_safetensors(data: bytes) -> dict:
    """None unless the first 8 bytes are a length whose bytes are a JSON object of tensor entries."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    if len(data) < 10:
        return None
    n = struct.unpack_from("<Q", data, 0)[0]
    if n < 2 or n > len(data) - 8 or data[8:9] != b"{":
        return None
    dupes = []

    def pairs(items):
        keys = [k for k, _ in items]
        dupes.extend(k for k in set(keys) if keys.count(k) > 1)
        return dict(items)

    try:
        header = json.loads(data[8:8 + n].decode("utf-8"), object_pairs_hook=pairs)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(header, dict):
        return None
    meta = header.get("__metadata__")
    tensors = []
    for name, t in header.items():
        if name == "__metadata__":
            continue
        if not (isinstance(t, dict) and isinstance(t.get("dtype"), str) and isinstance(t.get("shape"), list)
                and isinstance(t.get("data_offsets"), list)):
            return None
        tensors.append({"name": name, "dtype": t["dtype"], "shape": t["shape"], "data_offsets": t["data_offsets"]})
    if not tensors and not isinstance(meta, dict):
        return None
    data_len = len(data) - 8 - n
    ends = [t["data_offsets"][1] for t in tensors if len(t["data_offsets"]) == 2 and all(isinstance(o, int) for o in t["data_offsets"])]
    meta = meta if isinstance(meta, dict) else {}
    strings = [v for v in meta.values() if isinstance(v, str)]
    decoded = []
    for s in strings:
        got = decode_embedded(s)
        t = _text(got[1]) if got else None
        if t is not None:
            decoded.append({"encoding": got[0], "text": t})
    return {"kind": "safetensors", "size": len(data), "header_length": n, "data_length": data_len,
            "tensors": tensors, "metadata": meta, "metadata_keys": list(meta), "duplicate_keys": sorted(set(dupes)),
            "unused_data_bytes": data_len - max(ends) if ends and max(ends) <= data_len else None,
            "offsets_past_end": bool(ends) and max(ends) > data_len,
            "strings": strings + [d["text"] for d in decoded], "decoded": decoded}


# ---- GGUF ------------------------------------------------------------------------------------------------

GGUF_TYPES = {0: "uint8", 1: "int8", 2: "uint16", 3: "int16", 4: "uint32", 5: "int32", 6: "float32", 7: "bool", 8: "string",
              9: "array", 10: "uint64", 11: "int64", 12: "float64"}
_GGUF_FMT = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "?", 10: "Q", 11: "q", 12: "d"}
GGML_TYPES = {0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 6: "Q5_0", 7: "Q5_1", 8: "Q8_0", 9: "Q8_1", 10: "Q2_K", 11: "Q3_K",
              12: "Q4_K", 13: "Q5_K", 14: "Q6_K", 15: "Q8_K", 16: "IQ2_XXS", 17: "IQ2_XS", 18: "IQ3_XXS", 19: "IQ1_S",
              20: "IQ4_NL", 21: "IQ3_S", 22: "IQ2_S", 23: "IQ4_XS", 24: "I8", 25: "I16", 26: "I32", 27: "I64", 28: "F64",
              29: "IQ1_M", 30: "BF16"}
GGUF_FILE_TYPES = {0: "ALL_F32", 1: "MOSTLY_F16", 2: "MOSTLY_Q4_0", 3: "MOSTLY_Q4_1", 7: "MOSTLY_Q8_0", 8: "MOSTLY_Q5_0",
                   9: "MOSTLY_Q5_1", 10: "MOSTLY_Q2_K", 11: "MOSTLY_Q3_K_S", 12: "MOSTLY_Q3_K_M", 13: "MOSTLY_Q3_K_L",
                   14: "MOSTLY_Q4_K_S", 15: "MOSTLY_Q4_K_M", 16: "MOSTLY_Q5_K_S", 17: "MOSTLY_Q5_K_M", 18: "MOSTLY_Q6_K",
                   19: "MOSTLY_IQ2_XXS", 20: "MOSTLY_IQ2_XS", 21: "MOSTLY_Q2_K_S", 22: "MOSTLY_IQ3_XS", 23: "MOSTLY_IQ3_XXS",
                   24: "MOSTLY_IQ1_S", 25: "MOSTLY_IQ4_NL", 26: "MOSTLY_IQ3_S", 27: "MOSTLY_IQ3_M", 28: "MOSTLY_IQ2_S",
                   29: "MOSTLY_IQ2_M", 30: "MOSTLY_IQ4_XS", 31: "MOSTLY_IQ1_M", 32: "MOSTLY_BF16"}
GGUF_ARRAY_HEAD = 64


class _Cut(Exception):
    pass


def read_gguf(data: bytes) -> dict:
    if data[:4] != b"GGUF":
        return None
    rep = {"kind": "gguf", "size": len(data), "version": None, "endian": "little", "tensor_count": None, "kv_count": None,
           "metadata": [], "tensors": [], "truncated": False, "error": None, "strings": [], "decoded": []}
    e = "<"
    pos = 4

    def take(fmt):
        nonlocal pos
        size = struct.calcsize(e + fmt)
        if pos + size > len(data):
            raise _Cut(f"the file ends at offset {len(data)} inside a field at {pos}")
        v = struct.unpack_from(e + fmt, data, pos)[0]
        pos += size
        return v

    def string():
        nonlocal pos
        n = take(length)
        if n > len(data) - pos:
            raise _Cut(f"a string of {n} bytes at offset {pos} runs past the end of the file")
        s = data[pos:pos + n].decode("utf-8", "replace")
        pos += n
        return s

    def value(t, depth=0):
        if t == 8:
            return string()
        if t == 9:
            if depth > 2:
                raise _Cut("arrays nested too deep")
            et, n = take("I"), take(length)
            if n > len(data) - pos:
                raise _Cut(f"an array of {n} items at offset {pos} runs past the end of the file")
            head = []
            for i in range(n):
                v = value(et, depth + 1)
                if i < GGUF_ARRAY_HEAD:
                    head.append(v)
            return {"array_of": GGUF_TYPES.get(et, f"type {et}"), "count": n, "head": head}
        if t not in _GGUF_FMT:
            raise _Cut(f"value type {t} at offset {pos} is not a GGUF type")
        return take(_GGUF_FMT[t])

    try:
        if len(data) >= 8 and struct.unpack_from("<I", data, 4)[0] > 0xFFFF:
            e, rep["endian"] = ">", "big"
        rep["version"] = take("I")
        length = "I" if rep["version"] == 1 else "Q"
        rep["tensor_count"] = take(length)
        rep["kv_count"] = take(length)
        for _ in range(rep["kv_count"]):
            key = string()
            t = take("I")
            rep["metadata"].append({"key": key, "type": GGUF_TYPES.get(t, f"type {t}"), "value": value(t)})
        for _ in range(rep["tensor_count"]):
            name = string()
            nd = take("I")
            if nd > 16:
                raise _Cut(f"a tensor with {nd} dimensions")
            dims = [take(length) for _ in range(nd)]
            t = take("I")
            rep["tensors"].append({"name": name, "shape": dims, "dtype": GGML_TYPES.get(t, f"type {t}"), "ggml_type": t,
                                   "offset": take("Q")})
        rep["header_end"] = pos
    except _Cut as cut:
        rep["truncated"], rep["error"] = True, str(cut)
    kv = {}
    for m in rep["metadata"]:
        kv.setdefault(m["key"], []).append(m["value"])
    rep["duplicate_keys"] = sorted(k for k, v in kv.items() if len(v) > 1)
    rep["metadata_keys"] = list(kv)

    def one(key):
        return kv[key][0] if len(kv.get(key, ())) == 1 else None

    rep["architecture"] = one("general.architecture") if isinstance(one("general.architecture"), str) else None
    rep["name"] = one("general.name") if isinstance(one("general.name"), str) else None
    ft = one("general.file_type")
    rep["file_type"] = ft if isinstance(ft, int) and not isinstance(ft, bool) else None
    rep["quantization"] = GGUF_FILE_TYPES.get(rep["file_type"])
    tpl = one("tokenizer.chat_template")
    rep["chat_template"] = tpl if isinstance(tpl, str) else None
    rep["chat_templates"] = {k: v[0] for k, v in kv.items() if k.startswith("tokenizer.chat_template") and len(v) == 1 and isinstance(v[0], str)}
    for m in rep["metadata"]:
        v = m["value"]
        if isinstance(v, str):
            rep["strings"].append(v)
        elif isinstance(v, dict) and v["count"] <= GGUF_ARRAY_HEAD:
            rep["strings"] += [x for x in v["head"] if isinstance(x, str)]
    for s in list(rep["strings"]):
        got = decode_embedded(s)
        t = _text(got[1]) if got else None
        if t is not None:
            rep["decoded"].append({"encoding": got[0], "text": t})
            rep["strings"].append(t)
    return rep


# ---- protobuf wire format and ONNX -------------------------------------------------------------------------

def _varint(buf, i, end):
    shift = v = 0
    while True:
        if i >= end or shift > 63:
            raise ValueError("a varint runs past the end")
        b = buf[i]
        i += 1
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v, i
        shift += 7


def pb_fields(buf: bytes, start: int = 0, end: int = None, lenient: bool = False):
    """[(field number, wire type, value)] of one protobuf message: varint -> int, 64-bit and 32-bit
    -> bytes, length-delimited -> bytes. ValueError on a malformed message; with lenient, what was
    read before the break and False instead: (fields, whole)."""
    end = len(buf) if end is None else end
    out, i = [], start
    try:
        while i < end:
            key, i = _varint(buf, i, end)
            num, wt = key >> 3, key & 7
            if num == 0:
                raise ValueError("field number 0")
            if wt == 0:
                v, i = _varint(buf, i, end)
            elif wt in (1, 5):
                n = 8 if wt == 1 else 4
                if i + n > end:
                    raise ValueError("a fixed field runs past the end")
                v, i = bytes(buf[i:i + n]), i + n
            elif wt == 2:
                n, i = _varint(buf, i, end)
                if i + n > end:
                    raise ValueError("a length-delimited field runs past the end")
                v, i = bytes(buf[i:i + n]), i + n
            else:
                raise ValueError(f"wire type {wt}")
            out.append((num, wt, v))
    except ValueError:
        if lenient:
            return out, False
        raise
    return (out, True) if lenient else out


def _s(v):
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else None


def _ints(fields, num):
    """A repeated int64 field, packed or not."""
    out = []
    for n, wt, v in fields:
        if n != num:
            continue
        if wt == 0:
            out.append(v)
        elif wt == 2:
            i = 0
            while i < len(v):
                x, i = _varint(v, i, len(v))
                out.append(x)
    return [x - (1 << 64) if x >= 1 << 63 else x for x in out]


ONNX_DTYPES = {1: "FLOAT", 2: "UINT8", 3: "INT8", 4: "UINT16", 5: "INT16", 6: "INT32", 7: "INT64", 8: "STRING", 9: "BOOL",
               10: "FLOAT16", 11: "DOUBLE", 12: "UINT32", 13: "UINT64", 14: "COMPLEX64", 15: "COMPLEX128", 16: "BFLOAT16"}
ONNX_NUMPY = {"FLOAT": "float32", "UINT8": "uint8", "INT8": "int8", "UINT16": "uint16", "INT16": "int16", "INT32": "int32",
              "INT64": "int64", "BOOL": "bool", "FLOAT16": "float16", "DOUBLE": "float64", "UINT32": "uint32",
              "UINT64": "uint64", "COMPLEX64": "complex64", "COMPLEX128": "complex128", "BFLOAT16": "bfloat16"}
_ONNX_MODEL_FIELDS = {1, 2, 3, 4, 5, 6, 7, 8, 14, 20, 25, 26}


def _onnx_tensor(raw):
    f = pb_fields(raw)
    ext = {}
    for n, wt, v in f:
        if n == 13 and wt == 2:
            kv = pb_fields(v)
            k = next((_s(x) for a, w, x in kv if a == 1 and w == 2), None)
            ext[k] = next((_s(x) for a, w, x in kv if a == 2 and w == 2), None)
    dt = next((v for n, wt, v in f if n == 2 and wt == 0), None)
    return {"name": next((_s(v) for n, wt, v in f if n == 8 and wt == 2), None), "shape": _ints(f, 1),
            "dtype": ONNX_DTYPES.get(dt, f"type {dt}" if dt is not None else None), "data_type": dt,
            "data_location": "external" if any(n == 14 and wt == 0 and v == 1 for n, wt, v in f) or ext else "default",
            "external_data": ext, "doc_string": next((_s(v) for n, wt, v in f if n == 12 and wt == 2), None)}


def _onnx_graph(raw, rep, depth=0):
    for n, wt, v in pb_fields(raw):
        if wt != 2:
            continue
        if n == 1:
            nf = pb_fields(v)
            node = {"name": next((_s(x) for a, w, x in nf if a == 3 and w == 2), None),
                    "op_type": next((_s(x) for a, w, x in nf if a == 4 and w == 2), None),
                    "domain": next((_s(x) for a, w, x in nf if a == 7 and w == 2), None),
                    "inputs": [_s(x) for a, w, x in nf if a == 1 and w == 2],
                    "outputs": [_s(x) for a, w, x in nf if a == 2 and w == 2], "attributes": [], "depth": depth}
            for a, w, x in nf:
                if a == 6 and w == 2 and _s(x):
                    rep["strings"].append(_s(x))
                if a != 5 or w != 2:
                    continue
                af = pb_fields(x)
                attr = {"name": next((_s(y) for b, c, y in af if b == 1 and c == 2), None)}
                strs = [_s(y) for b, c, y in af if b in (4, 9) and c == 2]
                if strs:
                    attr["strings"] = strs
                    rep["string_attributes"].append({"node": node["name"], "op_type": node["op_type"], "name": attr["name"],
                                                     "value": strs[0] if len(strs) == 1 else strs})
                    rep["strings"] += strs
                ints = _ints(af, 3) + _ints(af, 8)
                if ints:
                    attr["ints"] = ints
                for b, c, y in af:
                    if b == 5 and c == 2:
                        t = _onnx_tensor(y)
                        attr["tensor"] = t["name"]
                        if t["external_data"]:
                            rep["external"].append({"tensor": t["name"], **t["external_data"]})
                    if b == 6 and c == 2 and depth < 4:
                        _onnx_graph(y, rep, depth + 1)
                node["attributes"].append(attr)
            rep["nodes"].append(node)
        elif n == 2 and depth == 0:
            rep["graph_name"] = _s(v)
        elif n == 5:
            t = _onnx_tensor(v)
            rep["tensors"].append(t)
            if t["external_data"]:
                rep["external"].append({"tensor": t["name"], **t["external_data"]})
        elif n == 10 and _s(v):
            rep["strings"].append(_s(v))
        elif n in (11, 12) and depth == 0:
            name = next((_s(x) for a, w, x in pb_fields(v) if a == 1 and w == 2), None)
            rep["inputs" if n == 11 else "outputs"].append(name)


def read_onnx(data: bytes) -> dict:
    """None unless the bytes are a protobuf message with ModelProto's field numbers and a graph that
    holds a node with an op type, an initializer or an input."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    if len(data) < 8 or data[0] not in (0x08, 0x12, 0x3A, 0x42, 0x1A, 0x22, 0x32):
        return None
    try:
        top = pb_fields(data)
    except ValueError:
        return None
    if not top or any(n not in _ONNX_MODEL_FIELDS for n, _, _ in top):
        return None
    graphs = [v for n, wt, v in top if n == 7 and wt == 2]
    if len(graphs) != 1:
        return None
    rep = {"kind": "onnx", "size": len(data), "ir_version": next((v for n, wt, v in top if n == 1 and wt == 0), None),
           "producer_name": next((_s(v) for n, wt, v in top if n == 2 and wt == 2), None),
           "producer_version": next((_s(v) for n, wt, v in top if n == 3 and wt == 2), None),
           "domain": next((_s(v) for n, wt, v in top if n == 4 and wt == 2), None),
           "model_version": next((v for n, wt, v in top if n == 5 and wt == 0), None),
           "doc_string": next((_s(v) for n, wt, v in top if n == 6 and wt == 2), None),
           "opsets": [], "metadata": {}, "graph_name": None, "nodes": [], "tensors": [], "inputs": [], "outputs": [],
           "string_attributes": [], "external": [], "strings": [], "decoded": [], "duplicate_keys": []}
    try:
        _onnx_graph(graphs[0], rep)
        for n, wt, v in top:
            if n == 8 and wt == 2:
                f = pb_fields(v)
                rep["opsets"].append({"domain": next((_s(x) for a, w, x in f if a == 1 and w == 2), "") or "",
                                      "version": next((x for a, w, x in f if a == 2 and w == 0), None)})
            if n == 14 and wt == 2:
                f = pb_fields(v)
                k = next((_s(x) for a, w, x in f if a == 1 and w == 2), None)
                if k in rep["metadata"] and k not in rep["duplicate_keys"]:
                    rep["duplicate_keys"].append(k)
                rep["metadata"][k] = next((_s(x) for a, w, x in f if a == 2 and w == 2), None)
    except (ValueError, RecursionError):
        return None
    if not (any(nd["op_type"] for nd in rep["nodes"]) or rep["tensors"] or rep["inputs"]):
        return None
    rep["metadata_keys"] = list(rep["metadata"])
    rep["subgraph_nodes"] = sum(1 for nd in rep["nodes"] if nd["depth"])
    rep["op_types"] = [nd["op_type"] for nd in rep["nodes"]]
    rep["initializers"] = [t["name"] for t in rep["tensors"]]
    rep["external_locations"] = list(dict.fromkeys(x["location"] for x in rep["external"] if x.get("location")))
    rep["strings"] += [s for s in (rep["doc_string"], rep["producer_name"]) if s] + [v for v in rep["metadata"].values() if v] \
        + rep["external_locations"]
    for s in list(rep["strings"]):
        got = decode_embedded(s)
        t = _text(got[1]) if got else None
        if t is not None:
            rep["decoded"].append({"encoding": got[0], "text": t})
            rep["strings"].append(t)
    return rep


# ---- Keras -----------------------------------------------------------------------------------------------

_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
HDF5_TRIES = 4096               # '{"class_name"' markers tried in one HDF5 file


def marshal_strings(raw: bytes) -> list:
    """String constants of marshalled code, by scan (never unmarshalled): a short-ASCII record (type
    z or Z, one length byte) or a string record (s, u, t, a, A, four length bytes) whose bytes are
    printable. When no record is found, every printable run of four or more characters."""
    out, i = [], 0
    while i < len(raw) - 2:
        c = raw[i] & 0x7F
        n = at = None
        if c in b"zZ":
            n, at = raw[i + 1], i + 2
        elif c in b"sutaA" and i + 5 <= len(raw):
            n, at = struct.unpack_from("<I", raw, i + 1)[0], i + 5
        if n and n <= 65536 and at + n <= len(raw):
            t = _text(raw[at:at + n])
            if t is not None and (len(t) >= 2):
                out.append(t)
                i = at + n
                continue
        i += 1
    return list(dict.fromkeys(out)) or [m.group().decode("ascii") for m in _PRINTABLE.finditer(raw)]


def _json_strings(v, out, depth=0):
    if isinstance(v, str):
        out.append(v)
    elif isinstance(v, dict) and depth < 40:
        for x in v.values():
            _json_strings(x, out, depth + 1)
    elif isinstance(v, list) and depth < 40:
        for x in v:
            _json_strings(x, out, depth + 1)


def keras_config(config) -> dict:
    """Layers and Lambda layers of a Keras model config (a parsed JSON value). A Lambda's function is
    base64 of marshalled code: its printable strings are read by scan; it is never unmarshalled."""
    layers, lambdas, classes = [], [], []

    def visit(v, depth=0, listed=False, nested=False):
        if depth > 40:
            return
        if isinstance(v, dict):
            cfg = v.get("config")
            if isinstance(v.get("class_name"), str) and isinstance(cfg, dict) and not v["class_name"].startswith("__"):
                entry = {"class_name": v["class_name"], "name": cfg.get("name") if isinstance(cfg.get("name"), str) else None}
                classes.append(entry)
                # A layer is an entry of a model's `config.layers` list. Every other class_name of a
                # real config is not one: the model itself, a DTypePolicy, an initializer, a
                # regularizer, the optimizer and the loss of compile_config (a real 3-layer .keras
                # file has eleven such objects).
                if listed:
                    layers.append({**entry, "nested": nested})
                if v["class_name"] == "Lambda":
                    found = []
                    _json_strings(cfg.get("function"), found)
                    code = []
                    for s in found:
                        try:
                            raw = base64.b64decode(s.strip(), validate=True) if len(s.strip()) >= 16 else None
                        except (binascii.Error, ValueError):
                            raw = None
                        if raw:
                            code += marshal_strings(raw)
                    lambdas.append({"name": cfg.get("name") if isinstance(cfg.get("name"), str) else None,
                                    "function_type": cfg.get("function_type") if isinstance(cfg.get("function_type"), str) else None,
                                    "module": cfg.get("module") if isinstance(cfg.get("module"), str) else None,
                                    "code_strings": code})
            inside = listed or nested
            for k, x in v.items():
                if k == "layers" and isinstance(x, list) and x \
                        and all(isinstance(e, dict) and isinstance(e.get("class_name"), str) for e in x):
                    for e in x:
                        visit(e, depth + 1, listed=True, nested=inside)
                else:
                    visit(x, depth + 1, listed=False, nested=inside)
        elif isinstance(v, list):
            for x in v:
                visit(x, depth + 1, listed=False, nested=nested)

    visit(config)
    strings = []
    _json_strings(config, strings)
    return {"model_class": config.get("class_name") if isinstance(config, dict) and isinstance(config.get("class_name"), str) else None,
            "model_name": (config.get("config") or {}).get("name") if isinstance(config, dict) and isinstance(config.get("config"), dict)
            and isinstance((config.get("config") or {}).get("name"), str) else None,
            "layers": layers, "classes": classes, "lambda_layers": lambdas,
            "strings": [s for s in strings if len(s) < 4096] + [s for la in lambdas for s in la["code_strings"]]}


def read_hdf5(data: bytes) -> dict:
    """An HDF5 file read by scan: every JSON object that follows a '{"class_name"' or a model_config
    marker, and the keras_version and backend attribute strings near their names."""
    if data[:8] != b"\x89HDF\r\n\x1a\n":
        return None
    rep = {"kind": "hdf5", "size": len(data), "layers": [], "lambda_layers": [], "strings": [], "configs": 0,
           "keras_version": None, "backend": None, "read_by": "scan"}
    dec = json.JSONDecoder()
    at, seen, tries = 0, set(), 0
    # latin-1 maps a byte to a character, so the file is decoded once and an offset is the same in
    # both; the object found is then read again from its own bytes as UTF-8.
    whole = data[:8 * MAX_INFLATE].decode("latin-1")
    while len(seen) < 16 and tries < HDF5_TRIES:
        at = whole.find('{"class_name"', at)
        if at < 0:
            break
        tries += 1
        try:
            _, used = dec.raw_decode(whole, at)
            obj = json.loads(data[at:used].decode("utf-8", "replace"))
        except (ValueError, RecursionError):
            at += 1
            continue
        text = json.dumps(obj, sort_keys=True)
        if text not in seen:
            seen.add(text)
            got = keras_config(obj)
            rep["configs"] += 1
            if rep["configs"] == 1:
                rep.update(model_class=got["model_class"], model_name=got["model_name"])
            rep["layers"] += [la for la in got["layers"] if la not in rep["layers"]]
            rep["lambda_layers"] += [la for la in got["lambda_layers"] if la not in rep["lambda_layers"]]
            rep["strings"] = list(dict.fromkeys(rep["strings"] + got["strings"]))
        at += max(1, len(text) // 2)
    for key in ("keras_version", "backend"):
        i = data.find(key.encode())
        if i >= 0:
            m = re.search(rb"(\d+\.\d+\.\d+[\w.-]*)" if key == "keras_version" else rb"\b(tensorflow|theano|cntk|jax|torch)\b",
                          data[i + len(key):i + len(key) + 160])
            rep[key] = m.group(1).decode() if m else None
            if rep[key] is None:        # h5py and Keras 2 write a variable-length string: a heap reference
                v = _h5_vlen_attr(data, i + len(key))
                m = re.fullmatch(r"\d+\.\d+(?:\.\d+)?[\w.+-]*" if key == "keras_version" else r"[A-Za-z_][\w.-]{1,40}", v or "")
                rep[key] = m.group() if m else None
    return rep


def _h5_vlen_attr(data: bytes, at: int):
    """The text of a variable-length string attribute whose name ends at `at`: its value is
    (length u32, global heap address u64, object index u32) and the text is that object of the
    'GCOL' collection. None when no such reference follows the name within 96 bytes."""
    for o in range(at, min(at + 96, len(data) - 16)):
        try:
            n, addr, idx = struct.unpack_from("<IQI", data, o)
        except struct.error:
            return None
        if not (0 < n <= 4096 and 0 < idx < 65536 and 0 < addr <= len(data) - 16 and data[addr:addr + 4] == b"GCOL"):
            continue
        end = min(len(data), addr + struct.unpack_from("<Q", data, addr + 8)[0])
        p = addr + 16
        while p + 16 <= end:
            oid, _, _, size = struct.unpack_from("<HHIQ", data, p)
            if oid == 0:
                break
            if oid == idx:
                raw = data[p + 16:p + 16 + size]
                return raw[:n].decode("utf-8", "replace") if size >= n else None
            p += 16 + (size + 7) // 8 * 8
    return None


def read_keras_zip(data: bytes, members=None) -> dict:
    members = members if members is not None else _zip_members(data)
    if not members or not members.get("config.json") or not ("metadata.json" in members or "model.weights.h5" in members):
        return None
    try:
        config = json.loads(members["config.json"].decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    rep = {"kind": "keras_zip", "size": len(data), "members": sorted(members), "metadata": {}, **keras_config(config)}
    dupes = []

    def pairs(items):
        keys = [k for k, _ in items]
        dupes.extend(k for k in set(keys) if keys.count(k) > 1)
        return dict(items)

    rep["metadata_entries"] = None          # every entry of metadata.json, whatever its value
    try:
        meta = json.loads((members.get("metadata.json") or b"{}").decode("utf-8"), object_pairs_hook=pairs)
        rep["metadata"] = {k: v for k, v in meta.items() if isinstance(v, (str, int, float, bool))} if isinstance(meta, dict) else {}
        # counted only when the member was there and could be read (a damaged member is not "no entries")
        rep["metadata_entries"] = len(meta) if isinstance(meta, dict) and members.get("metadata.json") else None
    except (ValueError, UnicodeDecodeError, RecursionError):
        pass
    rep["duplicate_keys"] = sorted(set(dupes))
    rep["metadata_keys"] = list(rep["metadata"])
    rep["keras_version"] = rep["metadata"].get("keras_version") if isinstance(rep["metadata"].get("keras_version"), str) else None
    return rep


# ---- one entry point ---------------------------------------------------------------------------------------

def analyze(data: bytes, name: str = ""):
    """The report of one file, or None when the bytes are none of the formats above. `name` is used
    only to accept a pickle that has no PROTO header and does not walk to a clean STOP."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 4:
        return None
    data = bytes(data)
    rep = None
    if data[:4] == b"GGUF":
        rep = read_gguf(data)
    elif data[:6] == b"\x93NUMPY":
        rep = read_npy(data)
    elif data[:4] == b"PK\x03\x04":
        try:
            names = [n for n in zipfile.ZipFile(io.BytesIO(data)).namelist() if not n.endswith("/")]
        except (zipfile.BadZipFile, ValueError, OSError):
            names = []
        # Members are read only when the names say it is a model container (an APK or a bundle is not).
        if names and (any(n.rsplit("/", 1)[-1] == "data.pkl" for n in names) or "config.json" in names
                      or all(n.endswith(".npy") for n in names)):
            members = _zip_members(data)
            rep = read_torch_zip(data, members) or read_keras_zip(data, members) or read_npz(data, members)
    elif data[:8] == b"\x89HDF\r\n\x1a\n":
        rep = read_hdf5(data)
    else:
        rep = read_safetensors(data)
        if rep is None:
            packed = inflate(data)
            if packed and looks_pickle(packed[1], name):
                rep = read_pickle(packed[1])
                rep["compression"] = packed[0]
            elif looks_pickle(data, name):
                rep = read_pickle(data)
            else:
                rep = read_onnx(data)
    if rep is not None:
        rep["file"] = name
    return rep


def public(rep):
    """The report without its internal symbolic values: JSON-serializable."""
    if isinstance(rep, dict):
        return {k: public(v) for k, v in rep.items() if not str(k).startswith("_")}
    if isinstance(rep, (list, tuple)):
        return [public(v) for v in rep]
    return rep
