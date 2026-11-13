"""Tensor values out of saved model files, sliced by layout and never unpickled (B-116).

The static readers in solvers/common/ai_model_files.py say where each tensor sits (name, dtype, shape,
offsets, torch storage key, offset and stride). This helper turns that layout into numpy arrays:

    ts = load_file(path)                 # TensorSet(kind, source, tensors {name: ndarray}, skipped, metadata)
    ts = load_bytes(data, name)          # the same from bytes
    sf = SafetensorsFile.open(path)      # header only; a big file stays on disk
    sf = SafetensorsFile.open(zip_path, member="model/model.safetensors")   # read from inside a zip
    arrays = sf.read(names, astype="float32")

Formats: safetensors, npz, npy, the PyTorch zip (`torch.save` of a state dict: the pickle is walked
symbolically by the reader, the storages are raw members) and a JSON object of nested number lists.
Nothing is deserialized: an object array, a legacy (non-zip) torch pickle, Keras HDF5 and ONNX are
refused or skipped with the reason named, never guessed at. Every file is data.

A helper (the leading underscore keeps it out of the engine registry): the engines that use it are
model_trigger.py and model_prefix_probe.py.
"""
from __future__ import annotations

import json
import struct
import sys
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"

MAX_FILE = 256 * 1024 * 1024          # load_file/load_bytes: a small saved net, read whole
MAX_ELEMENTS = 64_000_000             # values taken from one small-net file
MAX_HEADER = 100 * 1024 * 1024        # a safetensors JSON header
MAX_JSON = 32 * 1024 * 1024
NUMERIC_KINDS = "biuf"                # numpy dtype kinds taken as numbers (bool, int, uint, float)


class TensorError(ValueError):
    """The file cannot be read as tensors; the message names the file, the tensor and the reason."""


class OverCap(TensorError):
    """The whole file is refused: its tensors together pass MAX_ELEMENTS (never a per-tensor skip)."""


def _admit(total: int, n: int, name: str, label: str) -> int:
    """The running value count of a file after one more tensor of `n` values; OverCap before that
    tensor is built when the count would pass MAX_ELEMENTS (many tensors each under the cap must not
    add up to gigabytes: a zero-stride view costs a few bytes in the file)."""
    if total + n > MAX_ELEMENTS:
        raise OverCap(f"{name}: {total + n} values is over the {MAX_ELEMENTS} value small-net cap "
                      f"(refused at tensor {label!r}, before it was built)")
    return total + n


def _np():
    try:
        import numpy
    except ImportError as exc:                                  # pragma: no cover - numpy is pinned
        raise TensorError("numpy is not installed (py:numpy): tensor values cannot be read") from exc
    return numpy


def reader():
    """solvers/common/ai_model_files.py (the static format reader), loaded by path: a toolkit module
    has the same basename."""
    if str(COMMON) not in sys.path:
        sys.path.append(str(COMMON))
    from _shadowed import common_module
    return common_module("ai_model_files")


@dataclass
class TensorSet:
    kind: str
    source: str
    tensors: dict = field(default_factory=dict)
    skipped: list = field(default_factory=list)       # [(name, why)]
    metadata: dict = field(default_factory=dict)


def _count(shape) -> int:
    n = 1
    for d in shape:
        n *= d
    return n


def _shape(shape, what: str) -> list:
    if not isinstance(shape, (list, tuple)) or not all(isinstance(d, int) and not isinstance(d, bool) and d >= 0
                                                       for d in shape):
        raise TensorError(f"{what}: shape {shape!r} is not a list of non-negative integers")
    return list(shape)


# ---- safetensors --------------------------------------------------------------------------------------

def _st_dtype(code: str, what: str):
    """(numpy dtype read from the bytes, is_bfloat16) for a safetensors dtype code."""
    np = _np()
    table = reader().SAFETENSORS_NUMPY
    if code not in table:
        raise TensorError(f"{what}: safetensors dtype {code!r} is not one this reader knows")
    if code == "BF16":
        return np.dtype("<u2"), True
    return np.dtype(table[code]).newbyteorder("<"), False


def _bf16(raw):
    """bfloat16 bit patterns (uint16) as float32: the 16 bits are the top half of a float32."""
    np = _np()
    return (raw.astype(np.uint32) << 16).view(np.float32)


class SafetensorsFile:
    """One safetensors file, on disk or as a member of a zip. Only the header is read by `open`.

    layout: {name: {"dtype": code, "shape": [...], "start": int, "end": int}} (offsets into the data
    section), in file order. metadata: the header's `__metadata__` strings.
    """

    def __init__(self, path: Path, member: str | None, layout: dict, metadata: dict, data_start: int, size: int,
                 data: bytes | None = None):
        self.path, self.member = Path(path), member
        self.layout, self.metadata = layout, metadata
        self.data_start, self.size = data_start, size
        self.data = data                                  # from_bytes: the whole file, already in memory

    @property
    def label(self) -> str:
        return f"{self.path.name}!{self.member}" if self.member else self.path.name

    @classmethod
    def open(cls, path, member: str | None = None) -> "SafetensorsFile":
        path = Path(path)
        label = f"{path.name}!{member}" if member else path.name
        try:
            if member is None:
                size = path.stat().st_size
                with open(path, "rb") as f:
                    head = f.read(8)
                    n = cls._header_len(head, size, label)
                    head += f.read(n)
            else:
                with zipfile.ZipFile(path) as zf:
                    size = zf.getinfo(member).file_size
                    with zf.open(member) as f:
                        head = f.read(8)
                        n = cls._header_len(head, size, label)
                        head += f.read(n)
        except (OSError, zipfile.BadZipFile, KeyError) as exc:
            raise TensorError(f"{label}: cannot be opened ({type(exc).__name__}: {exc})") from exc
        layout, metadata = cls._layout(head, n, size, label)
        return cls(path, member, layout, metadata, 8 + n, size)

    @classmethod
    def from_bytes(cls, data: bytes, name: str = "model.safetensors") -> "SafetensorsFile":
        n = cls._header_len(data[:8], len(data), name)
        layout, metadata = cls._layout(data[:8 + n], n, len(data), name)
        return cls(Path(name), None, layout, metadata, 8 + n, len(data), data=data)

    @staticmethod
    def _layout(head: bytes, n: int, size: int, label: str):
        if len(head) != 8 + n:
            raise TensorError(f"{label}: the safetensors header runs past the end of the file")
        rep = reader().read_safetensors(head)
        if rep is None:
            raise TensorError(f"{label}: not a safetensors header (no JSON object of tensor entries)")
        if rep["duplicate_keys"]:
            raise TensorError(f"{label}: duplicate tensor name(s) in the header: {', '.join(rep['duplicate_keys'][:5])}")
        data_len = size - 8 - n
        layout = {}
        for t in rep["tensors"]:
            what = f"{label}: tensor {t['name']!r}"
            dtype, _bf = _st_dtype(t["dtype"], what)
            shape = _shape(t["shape"], what)
            off = t["data_offsets"]
            if len(off) != 2 or not all(isinstance(o, int) and not isinstance(o, bool) for o in off):
                raise TensorError(f"{what}: data_offsets {off!r} is not a pair of integers")
            start, end = off
            if not 0 <= start <= end <= data_len:
                raise TensorError(f"{what}: bytes {start}..{end} lie outside the {data_len} byte data section")
            if end - start != _count(shape) * dtype.itemsize:
                raise TensorError(f"{what}: {end - start} bytes do not hold shape {shape} of {t['dtype']}")
            layout[t["name"]] = {"dtype": t["dtype"], "shape": shape, "start": start, "end": end}
        layout = dict(sorted(layout.items(), key=lambda item: item[1]["start"]))       # file order
        return layout, dict(rep["metadata"])

    @staticmethod
    def _header_len(head: bytes, size: int, label: str) -> int:
        if len(head) < 8:
            raise TensorError(f"{label}: shorter than a safetensors length prefix")
        n = struct.unpack("<Q", head)[0]
        if n < 2 or n > min(MAX_HEADER, size - 8):
            raise TensorError(f"{label}: safetensors header length {n} is not plausible for a {size} byte file")
        return n

    def nbytes(self, names=None, astype: str | None = None) -> int:
        """Bytes the named tensors (default all) take once read, as `astype` when given."""
        np = _np()
        total = 0
        for name in (self.layout if names is None else names):
            t = self._entry(name)
            item = np.dtype(astype).itemsize if astype else (4 if t["dtype"] == "BF16" else _st_dtype(t["dtype"], name)[0].itemsize)
            total += _count(t["shape"]) * item
        return total

    def _entry(self, name: str) -> dict:
        if name not in self.layout:
            raise TensorError(f"{self.label}: no tensor named {name!r}")
        return self.layout[name]

    def _decode(self, raw, t: dict, astype):
        np = _np()
        dtype, bf = _st_dtype(t["dtype"], self.label)
        arr = np.frombuffer(raw, dtype=dtype) if not isinstance(raw, np.ndarray) else raw
        if bf:
            arr = _bf16(arr)
        arr = arr.reshape(t["shape"])
        return arr.astype(astype) if astype else arr

    def read(self, names=None, astype: str | None = None) -> dict:
        """{name: ndarray} for `names` (default all), converted to `astype` when given.

        A file on disk is memory-mapped (only the asked tensors are read); a zip member is read as one
        forward stream in offset order, each tensor converted as it arrives, so the member is never
        held whole or written to disk."""
        np = _np()
        want = list(self.layout) if names is None else list(names)
        entries = sorted(((self._entry(n), n) for n in want), key=lambda e: e[0]["start"])
        out = {}
        try:
            if self.member is None:
                if self.data is not None:
                    mm = np.frombuffer(self.data, dtype=np.uint8)
                else:
                    mm = np.memmap(self.path, dtype=np.uint8, mode="r")
                for t, name in entries:
                    a, b = self.data_start + t["start"], self.data_start + t["end"]
                    dtype, _bf = _st_dtype(t["dtype"], self.label)
                    raw = mm[a:b].view(dtype) if b > a else np.zeros(0, dtype)
                    out[name] = self._decode(raw, t, astype)
            else:
                with zipfile.ZipFile(self.path) as zf, zf.open(self.member) as f:
                    pos = 0
                    for t, name in entries:
                        a, b = self.data_start + t["start"], self.data_start + t["end"]
                        if a < pos:                              # overlapping extents: not a forward stream
                            raise TensorError(f"{self.label}: tensor {name!r} overlaps an earlier one; extract the "
                                              "member to a file and open that")
                        self._skip(f, a - pos)
                        raw = f.read(b - a)
                        if len(raw) != b - a:
                            raise TensorError(f"{self.label}: tensor {name!r} is cut short in the zip member")
                        pos = b
                        out[name] = self._decode(raw, t, astype)
        except (OSError, zipfile.BadZipFile, zlib.error) as exc:
            raise TensorError(f"{self.label}: read failed ({type(exc).__name__}: {exc})") from exc
        return {n: out[n] for n in want}

    @staticmethod
    def _skip(f, n: int):
        while n > 0:
            got = f.read(min(n, 1 << 20))
            if not got:
                raise TensorError("the zip member ends before the tensor data")
            n -= len(got)


# ---- numpy --------------------------------------------------------------------------------------------

def _npy_array(raw: bytes, what: str):
    np = _np()
    rep = reader().read_npy(raw)
    if rep is None:
        raise TensorError(f"{what}: not an .npy array")
    if rep.get("error"):
        raise TensorError(f"{what}: unreadable .npy header ({rep['error']})")
    if rep["object_array"]:
        raise TensorError(f"{what}: an object array is a pickle; it is never loaded")
    shape = _shape(rep["shape"], what)
    try:
        dtype = np.dtype(rep["descr"])
    except (TypeError, ValueError) as exc:
        raise TensorError(f"{what}: dtype {rep['descr']!r} is not a plain numeric type") from exc
    if dtype.kind not in NUMERIC_KINDS or dtype.fields is not None:
        raise TensorError(f"{what}: dtype {rep['descr']!r} is not a plain numeric type")
    n, at = _count(shape), rep["data_offset"]
    if len(raw) - at < n * dtype.itemsize:
        raise TensorError(f"{what}: {len(raw) - at} data bytes do not hold shape {shape} of {dtype} "
                          "(cut short, or past the reader's member cap)")
    arr = np.frombuffer(raw, dtype=dtype, count=n, offset=at)
    return arr.reshape(shape, order="F" if rep["fortran_order"] else "C")


def _from_npz(data: bytes, name: str, members) -> TensorSet:
    ts = TensorSet("npz", name)
    total = 0
    for member in members:                                  # the archive's own order
        key = member[:-4]
        try:
            arr = _npy_array(members[member] or b"", f"{name}!{member}")     # a view: nothing allocated yet
        except TensorError as exc:
            ts.skipped.append((key, str(exc)))
            continue
        total = _admit(total, int(arr.size), name, key)
        ts.tensors[key] = arr
    return ts


# ---- torch zip ----------------------------------------------------------------------------------------

def _from_torch_zip(data: bytes, name: str, members, rep: dict) -> TensorSet:
    np = _np()
    ts = TensorSet("torch_zip", name, metadata={"byteorder": rep.get("byteorder"), "capped": rep.get("tensors_capped")})
    root = (rep.get("archive_name") + "/") if rep.get("archive_name") else ""
    order = ">" if rep.get("byteorder") == "big" else "<"
    total = 0
    for t in rep.get("tensors") or []:
        label = t.get("path") or t.get("name") or "?"
        key = label if label not in ts.tensors else f"{label}#{len(ts.tensors)}"
        what = f"{name}: tensor {label!r}"
        try:
            if not t.get("dtype") or t.get("storage_key") is None:
                raise TensorError(f"{what}: its storage type or key was not recovered from the pickle")
            try:
                dtype = np.dtype(t["dtype"]).newbyteorder(order)
            except TypeError as exc:
                raise TensorError(f"{what}: storage dtype {t['dtype']!r} has no numpy equivalent") from exc
            if dtype.kind not in NUMERIC_KINDS:
                raise TensorError(f"{what}: storage dtype {t['dtype']!r} is not a plain numeric type")
            shape = _shape(t.get("shape"), what)
            raw = members.get(f"{root}data/{t['storage_key']}")
            if raw is None:
                raise TensorError(f"{what}: storage member data/{t['storage_key']} is missing or unreadable")
            store = np.frombuffer(raw, dtype=dtype, count=len(raw) // dtype.itemsize)
            offset = t.get("offset")
            if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
                raise TensorError(f"{what}: storage offset {offset!r} was not recovered")
            stride = t.get("stride")
            contiguous = [_count(shape[i + 1:]) for i in range(len(shape))]
            if stride is None:
                raise TensorError(f"{what}: its stride was not recovered, so the element order is unknown")
            stride = _shape(stride, what)
            if len(stride) != len(shape):
                raise TensorError(f"{what}: stride {stride} does not match shape {shape}")
            n = _count(shape)
            if n > MAX_ELEMENTS:                            # a zero stride can claim any shape over one value
                raise TensorError(f"{what}: {n} values is over the {MAX_ELEMENTS} value small-net cap")
            last = offset + sum((d - 1) * s for d, s in zip(shape, stride)) if n else offset - 1
            if last >= store.size:
                raise TensorError(f"{what}: it reaches element {last} of a {store.size} element storage")
            total = _admit(total, n, name, label)
            if stride == contiguous or n == 0:
                arr = store[offset:offset + n].reshape(shape)
            else:                                           # a view (transposed, sliced): copied by stride
                # strides are non-negative and the last element was checked against the storage above,
                # so the strided view stays inside it; the copy is the only allocation (n values)
                arr = np.lib.stride_tricks.as_strided(store[offset:], shape=shape,
                                                      strides=[s * dtype.itemsize for s in stride]).copy()
            ts.tensors[key] = arr
        except OverCap:
            raise
        except TensorError as exc:
            ts.skipped.append((key, str(exc)))
    return ts


# ---- JSON ---------------------------------------------------------------------------------------------

def _from_json(data: bytes, name: str) -> TensorSet | None:
    np = _np()
    try:
        doc = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(doc, dict):
        return None
    ts = TensorSet("json", name)

    def visit(value, path, depth):
        if depth > 6:
            return
        if isinstance(value, dict):
            for k, v in value.items():
                visit(v, path + [str(k)], depth + 1)
        elif isinstance(value, list) and value:
            key = ".".join(path)
            try:
                arr = np.array(value, dtype=np.float64)
            except (ValueError, TypeError):
                ts.skipped.append((key, f"{name}: {key!r} is not a rectangular list of numbers"))
                return
            if arr.ndim >= 1 and np.all(np.isfinite(arr)):
                ts.tensors[key] = arr
            else:
                ts.skipped.append((key, f"{name}: {key!r} holds a non-finite number"))

    visit(doc, [], 0)
    return ts if ts.tensors else None


# ---- entry points -------------------------------------------------------------------------------------

def load_bytes(data: bytes, name: str = "") -> TensorSet:
    """The tensors of one small model file. TensorError when it is not a format this helper slices."""
    np = _np()
    if not isinstance(data, (bytes, bytearray)):
        raise TensorError(f"{name}: bytes expected")
    data = bytes(data)
    if len(data) > MAX_FILE:
        raise TensorError(f"{name}: {len(data)} bytes is over the {MAX_FILE} byte small-net cap "
                          "(open a large safetensors file with SafetensorsFile)")
    rd = reader()
    ts = None
    if data[:6] == b"\x93NUMPY":
        ts = TensorSet("npy", name)
        ts.tensors[Path(name).stem or "array"] = _npy_array(data, name)
    elif data[:4] == b"PK\x03\x04":
        members = rd._zip_members(data)
        if not members:
            raise TensorError(f"{name}: an unreadable zip")
        rep = rd.read_torch_zip(data, members)
        if rep is not None:
            ts = _from_torch_zip(data, name, members, rep)
        elif all(n.endswith(".npy") for n in members):
            ts = _from_npz(data, name, members)
        else:
            raise TensorError(f"{name}: a zip that is neither an .npz nor a PyTorch archive "
                              "(a Keras archive's HDF5 weights are not sliced here)")
    elif data[:8] == b"\x89HDF\r\n\x1a\n":
        raise TensorError(f"{name}: HDF5 (Keras) weights are not sliced here; export them to .npz")
    elif data[:1] in (b"{", b" ", b"\n", b"\r", b"\t") and len(data) <= MAX_JSON:
        ts = _from_json(data, name)
    if ts is None and len(data) >= 10:
        n = struct.unpack_from("<Q", data, 0)[0]
        if 2 <= n <= len(data) - 8 and data[8:9] == b"{":
            sf = SafetensorsFile.from_bytes(data, name)
            total = 0
            for key, t in sf.layout.items():                 # counted from the header, before any read
                total = _admit(total, _count(t["shape"]), name, key)
            ts = TensorSet("safetensors", name, tensors=sf.read(), metadata=sf.metadata)
    if ts is None:
        kind = (rd.analyze(data, name) or {}).get("kind")
        if kind in ("pickle", "joblib", "torch_legacy"):
            raise TensorError(f"{name}: a {kind} file is a pickle; it is never loaded. Re-save the weights as "
                              ".npz or safetensors in a sandbox, or read the layout with ai_model_files")
        raise TensorError(f"{name}: not a model file this helper slices"
                          + (f" (the static reader calls it {kind})" if kind else ""))
    total = sum(int(a.size) for a in ts.tensors.values())
    if total > MAX_ELEMENTS:
        raise TensorError(f"{name}: {total} values is over the {MAX_ELEMENTS} value small-net cap")
    if not ts.tensors and not ts.skipped:
        raise TensorError(f"{name}: it holds no tensor")
    for key, arr in ts.tensors.items():
        if arr.dtype.kind == "f" and not np.all(np.isfinite(arr)):
            ts.skipped.append((key, f"{name}: tensor {key!r} holds a non-finite value"))
    for key, _why in ts.skipped:
        ts.tensors.pop(key, None)
    return ts


def load_file(path) -> TensorSet:
    path = Path(path)
    try:
        size = path.stat().st_size
        if size > MAX_FILE:
            raise TensorError(f"{path.name}: {size} bytes is over the {MAX_FILE} byte small-net cap "
                              "(open a large safetensors file with SafetensorsFile)")
        data = path.read_bytes()
    except OSError as exc:
        raise TensorError(f"{path.name}: cannot be read ({type(exc).__name__})") from exc
    return load_bytes(data, path.name)


__all__ = ["TensorError", "OverCap", "TensorSet", "SafetensorsFile", "load_file", "load_bytes", "reader", "MAX_FILE", "MAX_ELEMENTS"]
