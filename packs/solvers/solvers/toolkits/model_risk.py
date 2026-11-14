#!/usr/bin/env python3
"""Security-risk overlay for reports from the existing static AI model readers.

This module intentionally does **not** implement another model parser.  ``review_report`` consumes
the JSON-safe reports produced by ``solvers/common/ai_model_files.py`` (or an equivalently shaped
report from another static reader).  ``analyze_bytes`` delegates parsing to that existing reader and
then applies this overlay.  It never unpickles, imports a framework, loads a model, invokes a custom
operator, evaluates Keras config/source, or accesses a network.

The overlay adds cross-field and security interpretation that round 5 did not provide: tensor-range
and overlap consistency, GGUF count/type/alignment checks, ONNX external/function/training risks,
Keras custom deserialization fields, TorchScript source/member review, and pickle opcode/dynamic-call
indicators.  Structural facts are marked verified; intent and exploitability remain review candidates.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import math
import re
import sys
import urllib.parse
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any


HERE = Path(__file__).resolve().parent
MAX_MODEL_BYTES = 256 << 20
MAX_FINDINGS = 2_000
MAX_ITEMS = 200_000
MAX_DEPTH = 40
MAX_SOURCE = 4 << 20
MAX_ELEMENTS = 1 << 80


FORMAT_RISK_MATRIX: Mapping[str, tuple[str, ...]] = {
    "pickle": ("callable invocation", "dynamic callable", "persistent ID", "extension opcode",
               "BUILD/setstate", "nested payload", "trailing bytes"),
    "torch_zip": ("embedded pickle", "TorchScript source", "archive path", "ambiguous ZIP metadata",
                  "storage/tensor mismatch"),
    "torch_legacy": ("multiple pickle streams", "callable invocation", "persistent storage IDs"),
    "joblib": ("pickle gadget", "compressed/nested payload", "raw array frame"),
    "npy": ("object-array pickle", "shape/data consistency"),
    "npz": ("object-array pickle", "archive path", "member inconsistency"),
    "safetensors": ("offset overlap", "offset out of bounds", "dtype/shape byte mismatch",
                    "duplicate key", "unreferenced trailing bytes"),
    "gguf": ("declared count mismatch", "unknown value/tensor type", "misaligned tensor",
             "duplicate metadata", "chat-template/metadata injection"),
    "onnx": ("external path/URI", "custom operator/domain", "local function", "training graph",
             "string/code attribute"),
    "keras_zip": ("Lambda layer", "custom class/module", "registered deserializer", "archive path"),
    "hdf5": ("Lambda layer", "custom class/module", "scan-only config visibility"),
}


def risk_matrix() -> dict[str, list[str]]:
    return {kind: list(risks) for kind, risks in FORMAT_RISK_MATRIX.items()}


def _finding(kind: str, score: int, reason: str, *, verified: bool = False,
             format_kind: str | None = None, **fields: Any) -> dict[str, Any]:
    row = {"kind": kind, "score": int(score), "reason": reason,
           "verified": bool(verified), "requires_human_review": not bool(verified)}
    if format_kind:
        row["format"] = format_kind
    row.update(fields)
    return row


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _shape_elements(shape: Any) -> int | None:
    if not isinstance(shape, Sequence) or isinstance(shape, (str, bytes, bytearray)) or len(shape) > 32:
        return None
    total = 1
    for dimension in shape:
        if not _is_int(dimension) or dimension < 0 or dimension > (1 << 60):
            return None
        total *= dimension
        if total > MAX_ELEMENTS:
            return None
    return total


def _unsafe_path(value: str) -> tuple[bool, str]:
    """Return path danger and a transparent reason; URL decoding is part of the static check."""
    if not isinstance(value, str) or not value:
        return False, ""
    decoded = urllib.parse.unquote(value.replace("\\", "/"))
    posix = PurePosixPath(decoded)
    windows = PureWindowsPath(decoded)
    if posix.is_absolute() or windows.is_absolute() or decoded.startswith("//"):
        return True, "absolute path"
    try:
        split = urllib.parse.urlsplit(decoded)
    except ValueError:
        return True, "malformed URI/path"
    if split.scheme:
        return True, f"external URI scheme {split.scheme.lower()}"
    if ".." in posix.parts or ".." in windows.parts:
        return True, "parent-directory traversal"
    if "\x00" in value:
        return True, "NUL in path"
    return False, ""


def _deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen, rows = set(), []
    for row in findings:
        key = json.dumps(row, sort_keys=True, ensure_ascii=False, default=str)
        if key not in seen:
            seen.add(key); rows.append(row)
    rows.sort(key=lambda item: (-int(item.get("score", 0)), item.get("kind", ""),
                                str(item.get("tensor", item.get("member", "")))))
    return rows[:MAX_FINDINGS]


def _bounded_preview(value: Any, depth: int = 0) -> Any:
    if depth > 6:
        return "<depth-capped>"
    if isinstance(value, str):
        return value[:2_048] + ("<truncated>" if len(value) > 2_048 else "")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, Mapping):
        return {str(key)[:128]: _bounded_preview(item, depth + 1)
                for key, item in itertools.islice(value.items(), 64)}
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        return [_bounded_preview(item, depth + 1) for item in value[:64]]
    if isinstance(value, (bytes, bytearray)):
        return {"length": len(value), "sha256": hashlib.sha256(bytes(value)).hexdigest()}
    return f"<{type(value).__name__}>"


DTYPE_BYTES: Mapping[str, float] = {
    "F64": 8, "F32": 4, "F16": 2, "BF16": 2,
    "I64": 8, "I32": 4, "I16": 2, "I8": 1,
    "U64": 8, "U32": 4, "U16": 2, "U8": 1, "BOOL": 1,
    "FLOAT": 4, "DOUBLE": 8, "FLOAT16": 2, "BFLOAT16": 2,
    "INT64": 8, "INT32": 4, "INT16": 2, "INT8": 1,
    "UINT64": 8, "UINT32": 4, "UINT16": 2, "UINT8": 1,
    "float64": 8, "float32": 4, "float16": 2, "bfloat16": 2,
    "int64": 8, "int32": 4, "int16": 2, "int8": 1,
    "uint64": 8, "uint32": 4, "uint16": 2, "uint8": 1, "bool": 1,
}


def review_safetensors(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    kind, findings = "safetensors", []
    data_length = report.get("data_length")
    data_length = data_length if _is_int(data_length) and data_length >= 0 else None
    intervals: list[tuple[int, int, str]] = []
    tensors = report.get("tensors") if isinstance(report.get("tensors"), list) else []
    if len(tensors) > MAX_ITEMS:
        return [_finding("item-cap", 70, "tensor list exceeds overlay cap", verified=True,
                         format_kind=kind, count=len(tensors))]
    names = Counter(str(tensor.get("name")) for tensor in tensors if isinstance(tensor, Mapping))
    for name, count in names.items():
        if count > 1:
            findings.append(_finding("duplicate-tensor-name", 90, "tensor name occurs more than once",
                                     verified=True, format_kind=kind, tensor=name, count=count))
    for tensor in tensors:
        if not isinstance(tensor, Mapping):
            findings.append(_finding("malformed-tensor-entry", 84, "tensor entry is not an object",
                                     verified=True, format_kind=kind))
            continue
        name = str(tensor.get("name"))[:512]
        offsets = tensor.get("data_offsets")
        if not (isinstance(offsets, list) and len(offsets) == 2 and all(_is_int(value) for value in offsets)):
            findings.append(_finding("malformed-offset", 94, "tensor offsets are not two integers",
                                     verified=True, format_kind=kind, tensor=name, offsets=offsets))
            continue
        start, end = offsets
        if start < 0 or end < start:
            findings.append(_finding("invalid-offset-range", 98, "tensor has a negative or reversed byte range",
                                     verified=True, format_kind=kind, tensor=name, offsets=offsets))
            continue
        # Half-open empty ranges are legitimate for zero-element tensors and overlap nothing.
        if end > start:
            intervals.append((start, end, name))
        if data_length is not None and end > data_length:
            findings.append(_finding("offset-past-end", 98, "tensor byte range exceeds the declared data area",
                                     verified=True, format_kind=kind, tensor=name, offsets=offsets,
                                     data_length=data_length))
        elements = _shape_elements(tensor.get("shape"))
        item_size = DTYPE_BYTES.get(str(tensor.get("dtype")))
        if elements is None:
            findings.append(_finding("invalid-shape", 88, "tensor shape is malformed or exceeds safe arithmetic bounds",
                                     verified=True, format_kind=kind, tensor=name, shape=tensor.get("shape")))
        elif item_size is None:
            findings.append(_finding("unknown-dtype", 62, "tensor dtype is not in the static size table",
                                     format_kind=kind, tensor=name, dtype=tensor.get("dtype")))
        elif end - start != elements * item_size:
            findings.append(_finding("tensor-byte-mismatch", 96,
                                     "offset length does not equal shape product times dtype size",
                                     verified=True, format_kind=kind, tensor=name,
                                     actual_bytes=end - start, expected_bytes=int(elements * item_size)))
    intervals.sort()
    widest: tuple[int, int, str] | None = None
    for current in intervals:
        if widest is not None and current[0] < widest[1]:
            findings.append(_finding("overlapping-tensor-data", 99, "two tensor byte ranges overlap",
                                     verified=True, format_kind=kind,
                                     tensors=[widest[2], current[2]], ranges=[list(widest[:2]), list(current[:2])]))
        if widest is None or current[1] > widest[1]:
            widest = current
    if report.get("offsets_past_end") is True and not any(row["kind"] == "offset-past-end" for row in findings):
        findings.append(_finding("offset-past-end", 98, "reader reports at least one offset past the data area",
                                 verified=True, format_kind=kind))
    unused = report.get("unused_data_bytes")
    if _is_int(unused) and unused > 0:
        findings.append(_finding("unreferenced-data", 72, "bytes after the final referenced tensor are unclaimed",
                                 verified=True, format_kind=kind, bytes=unused))
    return findings


def _gguf_metadata(report: Mapping[str, Any]) -> tuple[list[Mapping[str, Any]], dict[str, list[Any]]]:
    rows = [row for row in report.get("metadata", []) if isinstance(row, Mapping)] \
        if isinstance(report.get("metadata"), list) else []
    by_key: dict[str, list[Any]] = {}
    for row in rows[:MAX_ITEMS]:
        by_key.setdefault(str(row.get("key")), []).append(row.get("value"))
    return rows, by_key


def review_gguf(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    kind, findings = "gguf", []
    metadata, by_key = _gguf_metadata(report)
    tensors = report.get("tensors") if isinstance(report.get("tensors"), list) else []
    truncated = report.get("truncated") is True
    declared_tensors, declared_kv = report.get("tensor_count"), report.get("kv_count")
    if not truncated and _is_int(declared_tensors) and declared_tensors != len(tensors):
        findings.append(_finding("declared-count-mismatch", 96, "declared tensor count differs from parsed entries",
                                 verified=True, format_kind=kind, declared=declared_tensors, parsed=len(tensors), field="tensor_count"))
    if not truncated and _is_int(declared_kv) and declared_kv != len(metadata):
        findings.append(_finding("declared-count-mismatch", 96, "declared metadata count differs from parsed entries",
                                 verified=True, format_kind=kind, declared=declared_kv, parsed=len(metadata), field="kv_count"))
    if truncated:
        findings.append(_finding("truncated-container", 83, "GGUF header/data ended inside a parsed field",
                                 verified=True, format_kind=kind, error=report.get("error")))
    for key, values in by_key.items():
        if len(values) > 1:
            findings.append(_finding("duplicate-metadata-key", 82,
                                     "duplicate metadata may be interpreted differently by loaders",
                                     verified=True, format_kind=kind, key=key, count=len(values)))
    alignment = 32
    values = by_key.get("general.alignment", [])
    if len(values) == 1:
        requested = values[0]
        if _is_int(requested) and 1 <= requested <= (1 << 20) and requested & (requested - 1) == 0:
            alignment = requested
        else:
            findings.append(_finding("invalid-alignment", 84,
                                     "general.alignment is not a bounded positive power of two",
                                     verified=True, format_kind=kind, value=requested))
    architecture = report.get("architecture") if isinstance(report.get("architecture"), str) else None
    model_prefixes = {key.split(".", 1)[0] for key in by_key if "." in key} \
        - {"general", "tokenizer", "quantization", "adapter"}
    if architecture and model_prefixes and architecture not in model_prefixes and len(model_prefixes) == 1:
        findings.append(_finding("architecture-metadata-mismatch", 68,
                                 "architecture name differs from the only architecture-specific metadata prefix",
                                 format_kind=kind, architecture=architecture, prefixes=sorted(model_prefixes)))
    for tensor in tensors[:MAX_ITEMS]:
        if not isinstance(tensor, Mapping):
            continue
        name = str(tensor.get("name"))[:512]
        dtype = str(tensor.get("dtype"))
        if dtype.startswith("type "):
            findings.append(_finding("unknown-tensor-type", 80, "GGUF tensor uses an unknown numeric type",
                                     verified=True, format_kind=kind, tensor=name, dtype=dtype,
                                     ggml_type=tensor.get("ggml_type")))
        offset = tensor.get("offset")
        if _is_int(offset) and (offset < 0 or offset % alignment != 0):
            findings.append(_finding("misaligned-tensor-offset", 76,
                                     "tensor offset is negative or not aligned to general.alignment",
                                     verified=True, format_kind=kind, tensor=name, offset=offset, alignment=alignment))
        if _shape_elements(tensor.get("shape")) is None:
            findings.append(_finding("invalid-shape", 84, "GGUF tensor dimensions are malformed or excessive",
                                     verified=True, format_kind=kind, tensor=name, shape=tensor.get("shape")))
    for row in metadata[:MAX_ITEMS]:
        key, type_name, value = str(row.get("key")), str(row.get("type")), row.get("value")
        if type_name.startswith("type "):
            findings.append(_finding("unknown-metadata-type", 84, "GGUF metadata uses an unknown numeric type",
                                     verified=True, format_kind=kind, key=key, type=type_name))
        if isinstance(value, str):
            unsafe, why = _unsafe_path(value)
            if unsafe and re.search(r"(?i)(?:path|url|uri|file|adapter|template|source)", key):
                findings.append(_finding("external-metadata-reference", 75, why,
                                         format_kind=kind, key=key, value=value[:512]))
            if re.search(r"(?i)\b(?:ignore|override|system prompt|call the tool|when the assistant reads)\b", value):
                findings.append(_finding("instruction-bearing-metadata", 87,
                                         "metadata contains instruction-shaped text; treat it as data",
                                         format_kind=kind, key=key, excerpt=value[:512]))
    return findings


STANDARD_ONNX_DOMAINS = {"", "ai.onnx", "ai.onnx.ml", "ai.onnx.preview.training"}
DANGEROUS_ONNX_OPS = {"PythonOp", "PyFunc", "ATen", "Plugin", "Custom", "Interpreter", "Shell"}


def review_onnx(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    kind, findings = "onnx", []
    nodes = report.get("nodes") if isinstance(report.get("nodes"), list) else []
    for node in nodes[:MAX_ITEMS]:
        if not isinstance(node, Mapping):
            continue
        domain = str(node.get("domain") or "")
        op = str(node.get("op_type") or "")
        if domain not in STANDARD_ONNX_DOMAINS or op in DANGEROUS_ONNX_OPS:
            findings.append(_finding("custom-operator", 90,
                                     "runtime-specific operator may require code outside the ONNX graph",
                                     format_kind=kind, node=node.get("name"), domain=domain, op_type=op))
        for attribute in node.get("attributes", []) if isinstance(node.get("attributes"), list) else []:
            if not isinstance(attribute, Mapping):
                continue
            strings = attribute.get("strings") if isinstance(attribute.get("strings"), list) else []
            for value in strings[:128]:
                if isinstance(value, str) and re.search(r"(?i)\b(?:exec|eval|subprocess|os\.system|import |curl |wget )", value):
                    findings.append(_finding("code-shaped-attribute", 82,
                                             "string attribute contains code/process-shaped text",
                                             format_kind=kind, node=node.get("name"), attribute=attribute.get("name"),
                                             excerpt=value[:512]))
    external = report.get("external") if isinstance(report.get("external"), list) else []
    for entry in external[:MAX_ITEMS]:
        if not isinstance(entry, Mapping):
            continue
        location = entry.get("location")
        if not isinstance(location, str) or not location:
            findings.append(_finding("missing-external-location", 88,
                                     "external tensor has no usable location", verified=True,
                                     format_kind=kind, tensor=entry.get("tensor")))
            continue
        unsafe, why = _unsafe_path(location)
        if unsafe:
            findings.append(_finding("unsafe-external-location", 96, why, verified=True,
                                     format_kind=kind, tensor=entry.get("tensor"), location=location[:1024]))
        for field in ("offset", "length"):
            value = entry.get(field)
            if value is not None:
                try:
                    number = -1 if isinstance(value, bool) else int(value)
                except (TypeError, ValueError, OverflowError):
                    number = -1
                if number < 0:
                    findings.append(_finding("invalid-external-range", 92,
                                             f"external tensor {field} is not a non-negative integer",
                                             verified=True, format_kind=kind, tensor=entry.get("tensor"),
                                             field=field, value=value))
    functions = report.get("functions") if isinstance(report.get("functions"), list) else []
    for function in functions[:MAX_ITEMS]:
        if isinstance(function, Mapping):
            domain = str(function.get("domain") or "")
            findings.append(_finding("local-function", 66,
                                     "model defines a local function; inspect its nodes and runtime resolution",
                                     format_kind=kind, name=function.get("name"), domain=domain,
                                     custom_domain=domain not in STANDARD_ONNX_DOMAINS))
    training = report.get("training_info", report.get("training_graphs", []))
    if isinstance(training, list) and training:
        findings.append(_finding("training-graph", 72,
                                 "model carries training initialization/algorithm graphs often ignored by inference-only review",
                                 format_kind=kind, count=len(training)))
    duplicate_opsets = Counter(str(row.get("domain") or "") for row in report.get("opsets", [])
                               if isinstance(row, Mapping))
    for domain, count in duplicate_opsets.items():
        if count > 1:
            findings.append(_finding("duplicate-opset-domain", 70,
                                     "multiple opset imports name the same domain",
                                     verified=True, format_kind=kind, domain=domain, count=count))
    return findings


# Broad safe list: an unknown name is only a low-confidence review candidate, never a malicious verdict.
KERAS_BUILTINS = {
    "Functional", "Sequential", "Model", "InputLayer", "Dense", "Conv1D", "Conv2D", "Conv3D",
    "DepthwiseConv2D", "SeparableConv2D", "Embedding", "LSTM", "GRU", "RNN", "SimpleRNN",
    "BatchNormalization", "LayerNormalization", "Normalization", "Dropout", "Flatten", "Reshape",
    "Activation", "ReLU", "Softmax", "Add", "Average", "Concatenate", "Multiply", "Maximum",
    "MaxPooling1D", "MaxPooling2D", "AveragePooling1D", "AveragePooling2D", "GlobalAveragePooling2D",
    "ZeroPadding1D", "ZeroPadding2D", "Cropping1D", "Cropping2D", "DTypePolicy", "InputSpec",
    "Zeros", "Ones", "Constant", "RandomNormal", "RandomUniform", "GlorotNormal", "GlorotUniform",
    "HeNormal", "HeUniform", "L1", "L2", "L1L2", "Adam", "AdamW", "SGD", "RMSprop", "Adagrad",
    "BinaryCrossentropy", "CategoricalCrossentropy", "SparseCategoricalCrossentropy", "MeanSquaredError",
    "Accuracy", "AUC", "Precision", "Recall",
}


def _trusted_keras_module(module: str) -> bool:
    return any(module == root or module.startswith(root + ".")
               for root in ("keras", "tensorflow", "builtins"))


def _walk_config(value: Any, *, path: str = "$", depth: int = 0,
                 state: dict[str, int] | None = None):
    state = state if state is not None else {"items": 0}
    if depth > MAX_DEPTH or state["items"] >= MAX_ITEMS:
        return
    state["items"] += 1
    if isinstance(value, Mapping):
        yield path, value
        for key, item in itertools.islice(value.items(), MAX_ITEMS):
            yield from _walk_config(item, path=f"{path}.{str(key)[:128]}", depth=depth + 1, state=state)
    elif isinstance(value, list):
        for index, item in enumerate(value[:MAX_ITEMS]):
            yield from _walk_config(item, path=f"{path}[{index}]", depth=depth + 1, state=state)


def review_keras(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    kind, findings = str(report.get("kind")), []
    for layer in report.get("lambda_layers", []) if isinstance(report.get("lambda_layers"), list) else []:
        if isinstance(layer, Mapping):
            findings.append(_finding("keras-lambda", 96,
                                     "Lambda deserialization can materialize supplied Python behavior",
                                     format_kind=kind, layer=layer.get("name"), module=layer.get("module"),
                                     code_string_count=len(layer.get("code_strings", []))
                                     if isinstance(layer.get("code_strings"), list) else None))
    classes = report.get("classes") if isinstance(report.get("classes"), list) else []
    for entry in classes[:MAX_ITEMS]:
        if not isinstance(entry, Mapping):
            continue
        class_name = str(entry.get("class_name") or "")
        if class_name and class_name not in KERAS_BUILTINS and class_name != "Lambda":
            findings.append(_finding("custom-keras-class", 58,
                                     "class is outside the overlay's broad built-in allowlist",
                                     format_kind=kind, class_name=class_name, name=entry.get("name")))
    configs = []
    for key in ("config", "model_config", "compile_config", "raw_config"):
        if isinstance(report.get(key), (Mapping, list)):
            configs.append((key, report[key]))
    for root_name, config in configs:
        for path, obj in _walk_config(config, path=f"$.{root_name}"):
            class_name = obj.get("class_name")
            module = obj.get("module")
            registered = obj.get("registered_name")
            if isinstance(module, str) and module and not _trusted_keras_module(module):
                findings.append(_finding("external-keras-module", 84,
                                         "deserialization references a module outside Keras/TensorFlow built-ins",
                                         format_kind=kind, path=path, module=module, class_name=class_name))
            if isinstance(registered, str) and registered and registered not in {class_name, "None"}:
                findings.append(_finding("registered-deserializer", 78,
                                         "config requests a registered custom object during deserialization",
                                         format_kind=kind, path=path, registered_name=registered,
                                         class_name=class_name))
            if class_name in {"__lambda__", "Lambda", "PythonFunction", "PyFunc"}:
                findings.append(_finding("executable-keras-config", 94,
                                         "config contains a function-like deserialization class",
                                         format_kind=kind, path=path, class_name=class_name))
    if kind == "hdf5" and report.get("read_by") == "scan":
        findings.append(_finding("partial-format-visibility", 52,
                                 "HDF5 configuration was recovered by bounded scan, not a full HDF5 tree walk",
                                 verified=True, format_kind=kind))
    return findings


DANGEROUS_CALLS = {
    "os.system", "posix.system", "nt.system", "os.popen", "subprocess.Popen", "subprocess.call",
    "subprocess.run", "builtins.eval", "builtins.exec", "__builtin__.eval", "__builtin__.exec",
    "runpy._run_code", "runpy._run_module_code", "types.FunctionType", "marshal.loads",
    "socket.create_connection", "urllib.request.urlopen", "shutil.rmtree", "pathlib.Path.write_text",
    "pathlib.Path.write_bytes", "pip._internal.main",
}
DANGEROUS_MODULES = {"os", "posix", "nt", "subprocess", "socket", "urllib", "http", "ctypes",
                     "multiprocessing", "runpy", "marshal", "pip", "shutil"}
DYNAMIC_HELPERS = {"builtins.getattr", "__builtin__.getattr", "builtins.__import__", "__builtin__.__import__",
                   "operator.attrgetter", "functools.partial"}


def review_pickle(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    kind, findings = str(report.get("kind", "pickle")), []
    calls = report.get("calls") if isinstance(report.get("calls"), list) else []
    for call in calls[:MAX_ITEMS]:
        if not isinstance(call, Mapping):
            continue
        target = call.get("callable")
        if not isinstance(target, str) or not target:
            findings.append(_finding("dynamic-pickle-call", 94,
                                     "pickle invokes a callable the static symbolic VM cannot resolve",
                                     format_kind=kind, opcode=call.get("kind"), position=call.get("pos"),
                                     callable_value=call.get("callable_value"), nested=call.get("nested")))
            continue
        module = target.split(".", 1)[0]
        if target in DANGEROUS_CALLS or module in DANGEROUS_MODULES:
            findings.append(_finding("side-effect-pickle-call", 99,
                                     "deserialization invokes a side-effect-capable callable",
                                     format_kind=kind, callable=target, opcode=call.get("kind"),
                                     position=call.get("pos"), arguments=_bounded_preview(call.get("args")),
                                     nested=call.get("nested")))
        elif target in DYNAMIC_HELPERS:
            findings.append(_finding("dynamic-resolution-helper", 88,
                                     "pickle uses a helper that can resolve another callable dynamically",
                                     format_kind=kind, callable=target, opcode=call.get("kind"),
                                     position=call.get("pos")))
        if _is_int(call.get("nested")) and call.get("nested") > 0:
            findings.append(_finding("nested-pickle-call", 78,
                                     "callable invocation was recovered from a nested encoded pickle",
                                     verified=True, format_kind=kind, callable=target,
                                     nested=call.get("nested"), position=call.get("pos")))
    for build in report.get("builds", []) if isinstance(report.get("builds"), list) else []:
        if not isinstance(build, Mapping):
            continue
        callable_name = build.get("callable")
        state_text = json.dumps(_bounded_preview(build.get("state")), ensure_ascii=False, default=str)[:2_048]
        if not callable_name or re.search(r"(?i)\b(?:command|shell|subprocess|eval|exec|__setstate__|module)\b", state_text):
            findings.append(_finding("pickle-build-state", 72,
                                     "BUILD applies serialized state; custom __setstate__ behavior requires review",
                                     format_kind=kind, callable=callable_name, state_excerpt=state_text))
    opcode_counts = report.get("opcode_counts") if isinstance(report.get("opcode_counts"), Mapping) else {}
    opcodes = report.get("opcodes") if isinstance(report.get("opcodes"), list) else []
    names = Counter({str(key).upper(): int(value) for key, value in opcode_counts.items()
                     if _is_int(value) and value >= 0})
    for value in opcodes[:MAX_ITEMS]:
        if isinstance(value, Mapping):
            name = value.get("name", value.get("opcode", value.get("op")))
            if isinstance(name, str):
                names[name.upper()] += 1
        elif isinstance(value, str):
            names[value.upper()] += 1
    opcode_risks = {
        "PERSID": (82, "persistent ID delegates object resolution to the loader"),
        "BINPERSID": (82, "persistent ID delegates object resolution to the loader"),
        "EXT1": (76, "extension opcode resolves process-local copyreg registry entries"),
        "EXT2": (76, "extension opcode resolves process-local copyreg registry entries"),
        "EXT4": (76, "extension opcode resolves process-local copyreg registry entries"),
        "NEWOBJ_EX": (62, "object construction receives serialized keyword arguments"),
    }
    for opcode, (score, reason) in opcode_risks.items():
        if names[opcode]:
            findings.append(_finding("pickle-opcode-risk", score, reason, verified=True,
                                     format_kind=kind, opcode=opcode, count=names[opcode]))
    trailing = report.get("trailing_bytes")
    if _is_int(trailing) and trailing > 0:
        findings.append(_finding("pickle-trailing-data", 74,
                                 "bytes follow a complete pickle stream and may carry another payload",
                                 verified=True, format_kind=kind, bytes=trailing))
    if report.get("truncated") is True:
        findings.append(_finding("truncated-pickle", 78,
                                 "pickle stream ended before a complete static walk",
                                 verified=True, format_kind=kind, error=report.get("error")))
    nested = report.get("nested") if isinstance(report.get("nested"), list) else []
    if nested:
        findings.append(_finding("nested-pickle", 70,
                                 "encoded bytes contain one or more additional pickle streams",
                                 verified=True, format_kind=kind, count=len(nested)))
    return findings


def _review_archive_paths(report: Mapping[str, Any], kind: str) -> list[dict[str, Any]]:
    findings = []
    for member in (report.get("members", [])[:MAX_ITEMS]
                   if isinstance(report.get("members"), list) else []):
        if not isinstance(member, str):
            continue
        unsafe, why = _unsafe_path(member)
        if unsafe:
            findings.append(_finding("unsafe-archive-member", 95, why, verified=True,
                                     format_kind=kind, member=member[:1_024]))
    return findings


def review_torch(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    kind, findings = "torch_zip", _review_archive_paths(report, "torch_zip")
    code_members = report.get("code_members") if isinstance(report.get("code_members"), list) else []
    if report.get("torchscript") is True or code_members:
        findings.append(_finding("torchscript-source", 68,
                                 "archive contains executable TorchScript/Python source members",
                                 format_kind=kind, members=code_members[:128]))
    tricks = report.get("zip_tricks") if isinstance(report.get("zip_tricks"), list) else []
    for trick in tricks[:MAX_ITEMS]:
        if isinstance(trick, Mapping):
            findings.append(_finding("ambiguous-zip-metadata", 90,
                                     "ZIP local/directory metadata disagreement can blind ordinary scanners",
                                     verified=True, format_kind=kind, member=trick.get("member"),
                                     detail=trick.get("trick")))
    source_texts = report.get("source_texts") if isinstance(report.get("source_texts"), Mapping) else {}
    for member, source in list(source_texts.items())[:1_000]:
        if not isinstance(source, str):
            continue
        source = source[:MAX_SOURCE]
        patterns = {
            "dynamic-execution": r"(?m)\b(?:eval|exec|compile)\s*\(",
            "process-spawn": r"(?m)\b(?:subprocess\.(?:run|Popen|call)|os\.system|os\.popen)\s*\(",
            "network-access": r"(?m)\b(?:socket\.|requests\.|urllib\.request|httpx\.)",
            "dynamic-import": r"(?m)\b(?:__import__|importlib\.import_module)\s*\(",
        }
        for family, expression in patterns.items():
            match = re.search(expression, source)
            if match:
                findings.append(_finding("torch-source-risk", 88,
                                         "static source contains a side-effect/dynamic-execution primitive",
                                         format_kind=kind, member=str(member)[:1_024], family=family,
                                         line=source.count("\n", 0, match.start()) + 1,
                                         source_digest=hashlib.sha256(source.encode("utf-8", "surrogatepass")).hexdigest()))
    return findings


def _common_findings(report: Mapping[str, Any], kind: str) -> list[dict[str, Any]]:
    findings = []
    duplicate = report.get("duplicate_keys")
    if isinstance(duplicate, list) and duplicate:
        findings.append(_finding("duplicate-key", 78,
                                 "duplicate keys can be interpreted differently by readers/loaders",
                                 verified=True, format_kind=kind, keys=[str(key)[:512] for key in duplicate[:256]]))
    if report.get("tensors_capped") is True:
        findings.append(_finding("analysis-cap-reached", 64,
                                 "static tensor recovery hit its configured cap",
                                 verified=True, format_kind=kind))
    if kind in {"npz", "keras_zip", "torch_zip"}:
        findings.extend(_review_archive_paths(report, kind))
    if kind in {"npy", "npz"} and report.get("object_array") is True:
        findings.append(_finding("object-array-pickle", 86,
                                 "NumPy object arrays deserialize a pickle payload",
                                 verified=True, format_kind=kind))
    return findings


def review_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Apply format-aware security interpretation to an existing static parser report."""
    if not isinstance(report, Mapping):
        raise ValueError("report must be an object")
    kind = str(report.get("kind", "unknown"))
    findings = _common_findings(report, kind)
    if kind == "safetensors":
        findings.extend(review_safetensors(report))
    elif kind == "gguf":
        findings.extend(review_gguf(report))
    elif kind == "onnx":
        findings.extend(review_onnx(report))
    elif kind in {"keras_zip", "hdf5"}:
        findings.extend(review_keras(report))
    if kind in {"pickle", "torch_zip", "torch_legacy", "joblib", "npy", "npz"}:
        findings.extend(review_pickle(report))
    if kind == "torch_zip":
        findings.extend(review_torch(report))
    rows = _deduplicate(findings)
    return {"format": kind, "findings": rows,
            "risk_kinds": list(FORMAT_RISK_MATRIX.get(kind, ())),
            "safe_to_load": None,
            "note": "absence of a finding is not proof that a model is safe to load",
            "artifact_executed": False, "requires_human_review": True}


def _load_existing_reader():
    name = "csctf_r5g_existing_ai_model_reader"
    if name in sys.modules:
        return sys.modules[name]
    path = HERE.parent / "common" / "ai_model_files.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("existing static AI model reader unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def analyze_bytes(data: bytes, name: str = "model") -> dict[str, Any] | None:
    """Delegate byte parsing to the existing safe reader, then apply this risk overlay."""
    if not isinstance(data, bytes):
        raise ValueError("model input must be bytes")
    if len(data) > MAX_MODEL_BYTES:
        raise ValueError("model exceeds 256 MiB cap")
    reader = _load_existing_reader()
    report = reader.analyze(data, name)
    if report is None:
        return None
    public = reader.public(report)
    return {"report": public, "risk": review_report(public)}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="offline risk overlay for existing static model parser reports")
    parser.add_argument("operation", choices=("model", "report", "matrix"))
    parser.add_argument("input", nargs="?")
    try:
        args = parser.parse_args(argv)
        if args.operation == "matrix":
            result: Any = risk_matrix()
        else:
            if not args.input:
                raise ValueError("operation requires an input file")
            raw = Path(args.input).read_bytes()
            if args.operation == "model":
                if len(raw) > MAX_MODEL_BYTES:
                    raise ValueError("model exceeds 256 MiB cap")
                result = analyze_bytes(raw, Path(args.input).name)
                if result is None:
                    raise ValueError("existing reader did not recognize the model format")
            else:
                if len(raw) > MAX_SOURCE:
                    raise ValueError("report exceeds 4 MiB cap")
                result = review_report(json.loads(raw.decode("utf-8")))
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return 0
    except (OSError, ValueError, TypeError, RuntimeError, UnicodeError, json.JSONDecodeError,
            RecursionError, MemoryError, OverflowError) as exc:
        print(f"model_risk: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
