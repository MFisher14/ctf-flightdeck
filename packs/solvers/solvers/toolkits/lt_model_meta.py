#!/usr/bin/env python3
"""TFLite and Core ML model metadata readers (B-251 long tail). Nothing is loaded or run.

TFLite (`TFL3`, a FlatBuffers file) is read with the fields of the published schema through
lt_flat_capnp.Table: the version and description, operator codes, each subgraph's tensors (name,
shape, type, constant buffer), operators and custom options, the model metadata entries with their
buffers, and the signatures. Every non-empty buffer is handed to the flag scan, and a constant
tensor whose values are all printable character codes is also shown as text (`as_text`): a flag
stored as int32 or float32 character codes is read without running the model.

Core ML (`.mlmodel`, a protobuf `Model` with no magic) is read by field number: the specification
version, the model type, the description's inputs, outputs, state and training inputs, the functions
of a multi-function model and its default function name, the predicted feature names, and the
metadata (short description, version, author, license, user-defined pairs). An `.mlpackage` is a
folder: its Data/com.apple.CoreML/model.mlmodel is such a file. A protobuf message is taken for a
model only on the catalog's own test (ctf.formats.detect_longtail): a description of ModelDescription
fields that holds a FeatureDescription (a name and a feature type), or a model-type field.

The TFLite operator names are the published schema's BuiltinOperator values 0 to 161; a later code
(the StableHLO operators) is shown as its number.

Bounds (TFLite). FlatBuffers offsets may name one target any number of times, so the bytes a file
makes the reader copy are not bounded by its size. Every table, string and vector the reader reads,
every buffer it copies and every tensor value it looks at as text is charged to one budget per file,
REACH_FACTOR times the file's size plus REACH_SLACK (lt_flat_capnp.Reach): past it the file is a
FormatError naming the amplification. A buffer that several entries of the buffers vector name (the
same bytes) is copied and handed to the flag scan once. MAX_TENSORS tensors; a tensor's text is read
from MAX_TEXT_VALUES values at most.

    read_tflite(data) / read_coreml(data) -> dict
    detect / inspect / solve                 the engine entry points (_lt_common)
"""
from __future__ import annotations

import math
import struct
import sys

from _lt_common import FormatError, NotThisFormat, cli, need, solve_files, text_or_hex
from ctf.formats import detect_longtail as structure      # _lt_common put the repo root on sys.path
from lt_flat_capnp import Reach, root_table

ENGINE = "toolkits.lt_model_meta"
MAX_TENSORS = 20_000
MAX_TEXT_VALUES = 1 << 16
REACH_FACTOR = 4                   # a TFLite file may make the reader read this many times its own size ...
REACH_SLACK = 1 << 20              # ... plus this many bytes

TENSOR_TYPES = ("FLOAT32", "FLOAT16", "INT32", "UINT8", "INT64", "STRING", "BOOL", "INT16", "COMPLEX64", "INT8",
                "FLOAT64", "COMPLEX128", "UINT64", "RESOURCE", "VARIANT", "UINT32", "UINT16", "INT4")
TENSOR_FORMATS = {"FLOAT32": "<f", "INT32": "<i", "UINT8": "<B", "INT64": "<q", "INT16": "<h", "INT8": "<b",
                  "FLOAT64": "<d", "UINT64": "<Q", "UINT32": "<I", "UINT16": "<H"}
BUILTIN = ("ADD", "AVERAGE_POOL_2D", "CONCATENATION", "CONV_2D", "DEPTHWISE_CONV_2D", "DEPTH_TO_SPACE", "DEQUANTIZE",
           "EMBEDDING_LOOKUP", "FLOOR", "FULLY_CONNECTED", "HASHTABLE_LOOKUP", "L2_NORMALIZATION", "L2_POOL_2D",
           "LOCAL_RESPONSE_NORMALIZATION", "LOGISTIC", "LSH_PROJECTION", "LSTM", "MAX_POOL_2D", "MUL", "RELU",
           "RELU_N1_TO_1", "RELU6", "RESHAPE", "RESIZE_BILINEAR", "RNN", "SOFTMAX", "SPACE_TO_DEPTH", "SVDF", "TANH",
           "CONCAT_EMBEDDINGS", "SKIP_GRAM", "CALL", "CUSTOM", "EMBEDDING_LOOKUP_SPARSE", "PAD",
           "UNIDIRECTIONAL_SEQUENCE_RNN", "GATHER", "BATCH_TO_SPACE_ND", "SPACE_TO_BATCH_ND", "TRANSPOSE", "MEAN", "SUB",
           "DIV", "SQUEEZE", "UNIDIRECTIONAL_SEQUENCE_LSTM", "STRIDED_SLICE", "BIDIRECTIONAL_SEQUENCE_RNN", "EXP",
           "TOPK_V2", "SPLIT", "LOG_SOFTMAX", "DELEGATE", "BIDIRECTIONAL_SEQUENCE_LSTM", "CAST", "PRELU", "MAXIMUM",
           "ARG_MAX", "MINIMUM", "LESS", "NEG", "PADV2", "GREATER", "GREATER_EQUAL", "LESS_EQUAL", "SELECT", "SLICE",
           "SIN", "TRANSPOSE_CONV", "SPARSE_TO_DENSE", "TILE", "EXPAND_DIMS", "EQUAL", "NOT_EQUAL", "LOG", "SUM",
           "SQRT", "RSQRT", "SHAPE", "POW", "ARG_MIN", "FAKE_QUANT", "REDUCE_PROD", "REDUCE_MAX", "PACK",
           "LOGICAL_OR", "ONE_HOT", "LOGICAL_AND", "LOGICAL_NOT", "UNPACK", "REDUCE_MIN", "FLOOR_DIV", "REDUCE_ANY",
           "SQUARE", "ZEROS_LIKE", "FILL", "FLOOR_MOD", "RANGE", "RESIZE_NEAREST_NEIGHBOR", "LEAKY_RELU",
           "SQUARED_DIFFERENCE", "MIRROR_PAD", "ABS", "SPLIT_V", "UNIQUE", "CEIL", "REVERSE_V2", "ADD_N", "GATHER_ND",
           "COS", "WHERE", "RANK", "ELU", "REVERSE_SEQUENCE", "MATRIX_DIAG", "QUANTIZE", "MATRIX_SET_DIAG", "ROUND",
           "HARD_SWISH", "IF", "WHILE", "NON_MAX_SUPPRESSION_V4", "NON_MAX_SUPPRESSION_V5", "SCATTER_ND", "SELECT_V2",
           "DENSIFY", "SEGMENT_SUM", "BATCH_MATMUL", "PLACEHOLDER_FOR_GREATER_OP_CODES", "CUMSUM", "CALL_ONCE",
           "BROADCAST_TO", "RFFT2D", "CONV_3D", "IMAG", "REAL", "COMPLEX_ABS", "HASHTABLE", "HASHTABLE_FIND",
           "HASHTABLE_IMPORT", "HASHTABLE_SIZE", "REDUCE_ALL", "CONV_3D_TRANSPOSE", "VAR_HANDLE", "READ_VARIABLE",
           "ASSIGN_VARIABLE", "BROADCAST_ARGS", "RANDOM_STANDARD_NORMAL", "BUCKETIZE", "RANDOM_UNIFORM", "MULTINOMIAL",
           "GELU", "DYNAMIC_UPDATE_SLICE", "RELU_0_TO_1", "UNSORTED_SEGMENT_PROD", "UNSORTED_SEGMENT_MAX",
           "UNSORTED_SEGMENT_SUM", "ATAN2", "UNSORTED_SEGMENT_MIN", "SIGN", "BITCAST", "BITWISE_XOR", "RIGHT_SHIFT")


def _text(b):
    return None if b is None else b.decode("utf-8", "replace")


def _as_text(raw: bytes, kind: str, reach: Reach | None = None):
    """The buffer's values as characters when every one is a printable character code, else None (a
    NaN or an infinity is no character code). The bytes looked at are charged to `reach`."""
    fmt = TENSOR_FORMATS.get(kind)
    if not fmt or not raw:
        return None
    size = struct.calcsize(fmt)
    if len(raw) % size or len(raw) // size > MAX_TEXT_VALUES:
        return None
    if reach is not None:
        reach.spend(len(raw))
    values = struct.unpack(f"<{len(raw) // size}{fmt[1]}", raw)
    if len(values) < 4 or not all(math.isfinite(v) and v == int(v) and 32 <= v < 127 for v in values):
        return None
    return "".join(chr(int(v)) for v in values)


def read_tflite(data: bytes, blobs=None) -> dict:
    blobs = [] if blobs is None else blobs
    reach = Reach(REACH_FACTOR * len(data) + REACH_SLACK)
    model, ident, prefixed = root_table(data, reach)
    need(ident == b"TFL3", f"the FlatBuffers file identifier is {ident!r}, not TFL3")
    buffers, copied, scan = [], {}, []         # copied: the bytes of each buffer start, read once
    for b in model.tables(4):
        v = b.vector(0)
        if v is None:
            buffers.append(b"")
            continue
        need(v[1] <= len(data) - v[0], f"a buffer of {v[1]} bytes at {v[0]} runs past the file")
        if v[0] not in copied:
            reach.spend(v[1])
            copied[v[0]] = bytes(data[v[0]:v[0] + v[1]])
            if v[1]:
                scan.append((len(buffers), copied[v[0]]))
        buffers.append(copied[v[0]])

    def buffer(i):
        return buffers[i] if 0 <= i < len(buffers) else b""

    codes = []
    for c in model.tables(1):
        code = max(c.scalar(0, "<b"), c.scalar(3, "<i"))
        codes.append({"builtin_code": code, "name": BUILTIN[code] if 0 <= code < len(BUILTIN) else None,
                      "custom_code": _text(c.string(1)), "version": c.scalar(2, "<i", 1)})
    subgraphs, count = [], 0
    for sg in model.tables(2):
        tensors = []
        for t in sg.tables(0):
            count += 1
            need(count <= MAX_TENSORS, f"more than {MAX_TENSORS} tensors")
            kind = t.scalar(1, "<b")
            name = TENSOR_TYPES[kind] if 0 <= kind < len(TENSOR_TYPES) else f"type {kind}"
            raw = buffer(t.scalar(2, "<I"))
            row = {"name": _text(t.string(3)), "shape": t.scalars(0, "<i"), "type": name,
                   "buffer": t.scalar(2, "<I"), "buffer_bytes": len(raw)}
            text = _as_text(raw, name, reach)
            if text is not None:
                row["as_text"] = text
            tensors.append(row)
        ops = []
        for op in sg.tables(3):
            i = op.scalar(0, "<I")
            row = {"opcode_index": i, "opcode": (codes[i]["custom_code"] or codes[i]["name"] or codes[i]["builtin_code"])
                   if i < len(codes) else None, "inputs": op.scalars(1, "<i"), "outputs": op.scalars(2, "<i")}
            custom = op.string(5)
            if custom:
                row["custom_options"] = text_or_hex(custom, 512)
                blobs.append(("custom options", custom))
            ops.append(row)
        subgraphs.append({"name": _text(sg.string(4)), "inputs": sg.scalars(1, "<i"), "outputs": sg.scalars(2, "<i"),
                          "tensors": tensors, "operators": ops})
    metadata = []
    for m in model.tables(6):
        raw = buffer(m.scalar(1, "<I"))
        reach.spend(min(len(raw), 2048))
        metadata.append({"name": _text(m.string(0)), "buffer": m.scalar(1, "<I"), "size": len(raw),
                         "value": text_or_hex(raw, 2048)})
    signatures = []
    for s in model.tables(7):
        def maps(i, s=s):
            return [{"name": _text(m.string(0)), "tensor_index": m.scalar(1, "<I")} for m in s.tables(i)]
        signatures.append({"signature_key": _text(s.string(2)), "subgraph_index": s.scalar(4, "<I"),
                           "inputs": maps(0), "outputs": maps(1)})
    for i, raw in scan:                        # each buffer's bytes once, under the first index that names them
        blobs.append((f"buffer {i}", raw))
    return {"format": "tflite", "version": model.scalar(0, "<I"), "description": _text(model.string(3)),
            "size_prefixed": prefixed, "operator_codes": codes, "subgraphs": subgraphs,
            "buffer_count": len(buffers), "buffer_bytes": sum(len(b) for b in buffers),
            "metadata": metadata, "signatures": signatures}


# ------------------------------------------------------------------ Core ML (protobuf by field number)

MODEL_TYPES = {200: "pipelineClassifier", 201: "pipelineRegressor", 202: "pipeline", 300: "glmRegressor",
               301: "supportVectorRegressor", 302: "treeEnsembleRegressor", 303: "neuralNetworkRegressor",
               400: "glmClassifier", 401: "supportVectorClassifier", 402: "treeEnsembleClassifier",
               403: "neuralNetworkClassifier", 500: "neuralNetwork", 502: "mlProgram", 555: "customModel",
               900: "identity"}
FEATURE_KINDS = {1: "int64", 2: "double", 3: "string", 4: "image", 5: "multiArray", 6: "dictionary", 7: "sequence",
                 8: "state"}


def _varint(buf, o, end):
    v = shift = 0
    while True:
        need(o < end, "a protobuf value runs past the end of its message")
        b = buf[o]
        o += 1
        v |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return v, o
        need(shift < 70, "a protobuf varint is longer than ten bytes")


def pb_fields(buf: bytes) -> list:
    """[(field number, wire type, value)] of one whole message: an int for a varint or a fixed value,
    bytes for a length-delimited one. FormatError when the bytes are not protobuf wire format or a
    value runs past the end of the message."""
    end, out, o = len(buf), [], 0
    while o < end:
        key, o = _varint(buf, o, end)
        field, wire = key >> 3, key & 7
        need(field > 0, "a protobuf field number 0")
        if wire == 0:
            v, o = _varint(buf, o, end)
        elif wire in (1, 5):
            n = 8 if wire == 1 else 4
            need(o + n <= end, "a protobuf value runs past the end of its message")
            v, o = int.from_bytes(buf[o:o + n], "little"), o + n
        elif wire == 2:
            n, o = _varint(buf, o, end)
            need(o + n <= end, "a protobuf value runs past the end of its message")
            v, o = bytes(buf[o:o + n]), o + n
        else:
            raise FormatError(f"the protobuf wire type {wire} is not read (groups are not used by Core ML)")
        out.append((field, wire, v))
    return out


def _one(fields, num, wire=2, default=None):
    return next((v for f, w, v in fields if f == num and w == wire), default)


def _str(fields, num):
    v = _one(fields, num)
    return None if v is None else v.decode("utf-8", "replace")


def _features(fields, num):
    """The repeated FeatureDescription at field `num`: name (1), shortDescription (2), type (3)."""
    out = []
    for f, w, v in fields:
        if f == num and w == 2:
            sub = pb_fields(v)
            kind = _one(sub, 3)
            kinds = [k for k, kw, _ in pb_fields(kind) if k != 1000] if kind else []      # 1000: isOptional
            out.append({"name": _str(sub, 1), "short_description": _str(sub, 2),
                        "type": FEATURE_KINDS.get(kinds[0], f"field {kinds[0]}") if kinds else None})
    return out


def _function(raw: bytes) -> dict:
    """A FunctionDescription (a multi-function model, specification 8 and later): name 1, input 2,
    output 3, predictedFeatureName 4, predictedProbabilitiesName 5, state 6."""
    fn = pb_fields(raw)
    return {"name": _str(fn, 1), "inputs": _features(fn, 2), "outputs": _features(fn, 3), "state": _features(fn, 6),
            "predicted_feature_name": _str(fn, 4), "predicted_probabilities_name": _str(fn, 5)}


def read_coreml(data: bytes, blobs=None) -> dict:
    blobs = [] if blobs is None else blobs
    try:
        model = pb_fields(data)
    except FormatError as e:
        raise NotThisFormat(f"not a protobuf message: {e}") from None
    version, raw = _one(model, 1, 0), _one(model, 2)
    if version is None or raw is None or not 1 <= version <= 64:
        raise NotThisFormat("no Core ML specificationVersion and description")
    try:
        desc = pb_fields(raw)
    except FormatError as e:
        raise NotThisFormat(f"field 2 is not a ModelDescription message: {e}") from None
    if not desc or any(f not in structure.COREML_DESCRIPTION_FIELDS or w != 2 for f, w, _ in desc):
        raise NotThisFormat("the description holds fields a Core ML ModelDescription does not have")
    kinds = [f for f, w, _ in model if f >= 200 and w == 2]
    # the sign that this protobuf message is a model (the catalog's rule): a feature that is a
    # FeatureDescription, directly or inside a function, or a model-type field
    if not kinds and not any(
            (f in structure.COREML_FEATURE_LISTS and structure.coreml_feature(v, 0, len(v)))
            or (f == 20 and structure.coreml_function(v, 0, len(v))) for f, _, v in desc):
        raise NotThisFormat("the description holds no feature with a name and a type, and the message has no "
                            "model type: not a Core ML model")
    try:
        inputs, outputs, state, training = (_features(desc, n) for n in (1, 10, 13, 50))
        functions = [_function(v) for f, _, v in desc if f == 20]
        meta = pb_fields(_one(desc, 100) or b"")
        user = {}
        for f, w, v in meta:
            if f == 100 and w == 2:
                pair = pb_fields(v)
                user[_str(pair, 1) or ""] = _str(pair, 2)
    except FormatError as e:
        raise NotThisFormat(f"a member of the description is not a Core ML message: {e}") from None
    blobs.append(("description", raw))
    out = {"format": "coreml", "specification_version": version, "is_updatable": bool(_one(model, 10, 0, 0)),
           "model_type": MODEL_TYPES.get(kinds[0], f"field {kinds[0]}") if kinds else None,
           "inputs": inputs, "outputs": outputs,
           "predicted_feature_name": _str(desc, 11), "predicted_probabilities_name": _str(desc, 12),
           "short_description": _str(meta, 1), "version_string": _str(meta, 2), "author": _str(meta, 3),
           "license": _str(meta, 4), "user_defined": user}
    if state:                                     # a stateful model (specification 8 and later)
        out["state"] = state
    if training:
        out["training_inputs"] = training
    if functions:                                 # a multi-function model
        out["functions"] = functions
    if _str(desc, 21) is not None:
        out["default_function_name"] = _str(desc, 21)
    return out


def _coreml_head(head: bytes) -> bool:
    """The catalog's Core ML test on the first bytes (ctf.formats.detect_longtail): `08 <version> 12
    <length>`, a description of ModelDescription fields, and a feature that is a FeatureDescription
    or a model-type field after the description."""
    return structure.DETECTORS["coreml"](head)


def detect(head: bytes, name: str = "") -> bool:
    return head[4:8] == b"TFL3" or head[8:12] == b"TFL3" or _coreml_head(head)


def inspect(data: bytes, name: str = "", opts=None):
    blobs = []
    if data[4:8] == b"TFL3" or data[8:12] == b"TFL3":
        return read_tflite(data, blobs), blobs
    return read_coreml(data, blobs), blobs


def solve(challenge_dir, profile=None, **opts):
    """Read the metadata of every TFLite and Core ML model in the handout; scan it and the TFLite buffers."""
    return solve_files(ENGINE, "TFLite/Core ML model", challenge_dir, profile, detect, inspect, opts)


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:], __doc__, detect, inspect))
