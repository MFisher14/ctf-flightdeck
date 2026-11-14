#!/usr/bin/env python3
"""Metadata Forensics reader pack (B-251): the long-tail formats, read by the toolkit readers.

properties_strict.py loads this file by name after the other packs and calls register(M). The lane had
no reader for an Avro container, a Parquet file, a TNEF stream (winmail.dat), a JPEG XL image, a TFLite
model, a Core ML model or a Thrift message: every property of one was an UNKNOWN PROPERTY and its facts
page had no type. This pack does not parse them again: each namespace asks the bounded reader in
solvers/toolkits (lt_avro, lt_thrift_parquet, lt_tnef, lt_jxl, lt_model_meta), loaded by path on first
use, and names its facts:

  avro      codec, record_count, block_count, sync_marker_hex, schema_name, schema_namespace, field_names,
            field_count
  parquet   num_rows, created_by, version, column_names, column_count, row_group_count, codec,
            metadata_keys
  tnef      subject, message_class, date_sent, key, oem_codepage, attachment_count, attachment_names,
            body
  jxl       width, height, is_container, box_types, bits_per_sample, level, codestream_size_bytes
  tflite    version, description, subgraph_count, tensor_count, tensor_names, operator_codes,
            metadata_names, buffer_count
  coreml    specification_version, model_type, author, license, short_description, version_string,
            input_names, output_names, user_defined_keys, state_names, function_names,
            default_function_name
  thrift    method_name, message_type, sequence_id, protocol, field_count, field_types

A file is one of these formats on the format catalog's own structural test
(ctf.formats.detect_longtail.DETECTORS) where the format has a short or no magic (jxl, coreml, thrift),
so the lane and `formats.identify` cannot disagree. A fact whose value is empty (no description, no
attachments, an empty name list) is None, "no such field", never an empty answer.

Every reader is registered unconfirmed: every answer is unsure until the judge accepts a name for it. The
extractor contract is properties_strict's: the value, None when the file is not that format or has no
such field, or M.Unknown when it is that format and the reader refuses it (malformed, a missing decoder,
an encrypted footer): the reader's own reason is the message. A reader file that is missing is a
PackMissing naming it, never a quiet None.
"""
import sys
from pathlib import Path

M = None          # properties_strict, set by register()
TOOLKITS = Path(__file__).resolve().parent.parent / "toolkits"
ALIASES = {"jpegxl": "jxl", "jpeg_xl": "jxl", "winmail": "tnef", "tensorflow_lite": "tflite", "mlmodel": "coreml",
           "core_ml": "coreml"}
_MEMO = {}        # kind -> ((len, hash), facts or the refusal)


def _reader(name: str):
    """A toolkit reader module, loaded by path once. The toolkits folder goes to the END of sys.path (the
    readers import each other flat), so nothing already importable is shadowed."""
    if name in sys.modules:
        return sys.modules[name]
    if str(TOOLKITS) not in sys.path:
        sys.path.append(str(TOOLKITS))
    from ctf import packs
    return packs.load_module(name, TOOLKITS / f"{name}.py", pack=f"long-tail format reader {name}")


def _is_tflite(d):
    return d[4:8] == b"TFL3" or d[8:12] == b"TFL3"


def _structure(kind: str):
    """The catalog's structural test of a format with a short or no magic."""
    def test(d):
        from ctf.formats import detect_longtail
        return detect_longtail.DETECTORS[kind](d)
    return test


# kind -> (reader module, its read function, the cheap test that the bytes are this format)
KINDS = {
    "avro": ("lt_avro", "read_container", lambda d: d[:4] == b"Obj\x01"),
    "parquet": ("lt_thrift_parquet", "read_parquet", lambda d: d[:4] == b"PAR1"),
    "tnef": ("lt_tnef", "read_tnef", lambda d: d[:4] == b"\x78\x9f\x3e\x22"),
    "jxl": ("lt_jxl", "read_jxl", _structure("jxl")),
    "tflite": ("lt_model_meta", "read_tflite", _is_tflite),
    "coreml": ("lt_model_meta", "read_coreml", _structure("coreml")),
    "thrift": ("lt_thrift_parquet", "read_thrift", _structure("thrift")),
}


def is_kind(kind: str, d: bytes) -> bool:
    return bool(KINDS[kind][2](d))


def facts(kind: str, d: bytes):
    """The toolkit reader's facts of `d`, None when it is not that format, M.Unknown when the reader
    refuses it. One parse per file and format: the facts page asks every reader of a namespace."""
    module, read, test = KINDS[kind]
    if not test(d):
        return None
    key = (len(d), hash(d))
    hit = _MEMO.get(kind)
    if hit is None or hit[0] != key:
        common = _reader("_lt_common")
        try:
            got = getattr(_reader(module), read)(d)
        except (common.FormatError, common.NeedsTool, common.NeedsKey) as e:
            got = e
        hit = _MEMO[kind] = (key, got)
    if isinstance(hit[1], Exception):
        raise M.Unknown(f"the {kind} reader refuses the file: {hit[1]}")
    return hit[1]


def _prop(kind, names, fmt, pick):
    def read(n, d):
        f = facts(kind, d)
        if f is None:
            return None
        v = pick(f)
        return None if v is None or v == "" or v == [] else v
    M.prop(*[f"{kind}.{n}" for n in names], fmt=fmt)(read)


def _avro_root(f):
    s = f["schema"]
    return s if isinstance(s, dict) else {}


def _parquet_codec(f):
    codecs = {c.get("codec") for g in f["row_groups"] for c in g["columns"] if c.get("codec")}
    if len(codecs) > 1:
        raise M.Unknown(f"the columns use {len(codecs)} codecs: {', '.join(sorted(codecs))}")
    return next(iter(codecs), None)


def _tensors(f):
    return [t for sg in f["subgraphs"] for t in sg["tensors"]]


def _thrift(f):
    """The one reading of an enveloped message. Several readings are a refusal: the lane does not pick."""
    if len(f["readings"]) != 1:
        raise M.Unknown(f"the bytes read as Thrift in {len(f['readings'])} ways")
    return f["readings"][0]


def _register():
    p = _prop
    p("avro", ("codec", "compression_codec"), "text", lambda f: f["codec"])
    p("avro", ("record_count", "num_records", "row_count"), "integer", lambda f: f["record_count"])
    p("avro", ("block_count", "data_block_count"), "integer", lambda f: f["block_count"])
    p("avro", ("sync_marker_hex", "sync_marker"), "text", lambda f: f["sync_hex"])
    p("avro", ("schema_name", "record_name"), "text", lambda f: _avro_root(f).get("name"))
    p("avro", ("schema_namespace", "namespace"), "text", lambda f: _avro_root(f).get("namespace"))
    p("avro", ("field_names", "schema_field_names", "column_names"), "list",
      lambda f: [str(x.get("name")) for x in _avro_root(f).get("fields", []) if isinstance(x, dict)])
    p("avro", ("field_count", "schema_field_count"), "integer", lambda f: len(_avro_root(f).get("fields", [])) or None)

    p("parquet", ("num_rows", "row_count"), "integer", lambda f: f["num_rows"])
    p("parquet", ("created_by", "writer"), "text", lambda f: f["created_by"])
    p("parquet", ("version", "format_version"), "integer", lambda f: f["version"])
    p("parquet", ("column_names", "column_paths", "field_names"), "list", lambda f: [c["path"] for c in f["columns"]])
    p("parquet", ("column_count", "num_columns"), "integer", lambda f: len(f["columns"]) or None)
    p("parquet", ("row_group_count", "num_row_groups"), "integer", lambda f: len(f["row_groups"]))
    p("parquet", ("codec", "compression_codec", "compression"), "text", _parquet_codec)
    p("parquet", ("metadata_keys", "key_value_metadata_keys"), "list", lambda f: list(f["key_value_metadata"]))

    p("tnef", ("subject", "message_subject"), "text", lambda f: f.get("subject") or f.get("properties", {}).get("subject"))
    p("tnef", ("message_class",), "text", lambda f: f.get("message_class"))
    p("tnef", ("date_sent", "sent_date"), "text", lambda f: f.get("date_sent"))
    p("tnef", ("key", "tnef_key"), "integer", lambda f: f["key"])
    p("tnef", ("oem_codepage", "codepage"), "integer", lambda f: f["oem_codepage"])
    p("tnef", ("attachment_count", "num_attachments"), "integer", lambda f: len(f["attachments"]))
    p("tnef", ("attachment_names", "attachment_filenames"), "list", lambda f: [a["name"] for a in f["attachments"]])
    p("tnef", ("body", "message_body"), "text", lambda f: f.get("body") or f.get("properties", {}).get("body"))

    p("jxl", ("width", "width_pixels", "image_width"), "integer", lambda f: f["width"])
    p("jxl", ("height", "height_pixels", "image_height"), "integer", lambda f: f["height"])
    M.prop("jxl.is_container", "jxl.has_container", fmt="bool")(
        lambda n, d: (lambda f: None if f is None else bool(f["container"]))(facts("jxl", d)))
    p("jxl", ("box_types", "box_type_list", "boxes"), "list", lambda f: [b["type"] for b in f.get("boxes", [])])
    p("jxl", ("bits_per_sample", "bit_depth"), "integer", lambda f: f.get("bits_per_sample"))
    p("jxl", ("level", "codestream_level"), "integer", lambda f: f.get("level"))
    p("jxl", ("codestream_size_bytes", "codestream_bytes"), "integer", lambda f: f["codestream_bytes"])

    p("tflite", ("version", "schema_version"), "integer", lambda f: f["version"])
    p("tflite", ("description", "model_description"), "text", lambda f: f["description"])
    p("tflite", ("subgraph_count", "num_subgraphs"), "integer", lambda f: len(f["subgraphs"]))
    p("tflite", ("tensor_count", "num_tensors"), "integer", lambda f: len(_tensors(f)))
    p("tflite", ("tensor_names",), "list", lambda f: [t["name"] for t in _tensors(f) if t["name"]])
    p("tflite", ("operator_codes", "operator_names", "opcodes"), "list",
      lambda f: [str(c["custom_code"] or c["name"] or c["builtin_code"]) for c in f["operator_codes"]])
    p("tflite", ("metadata_names", "metadata_keys"), "list", lambda f: [m["name"] for m in f["metadata"] if m["name"]])
    p("tflite", ("buffer_count", "num_buffers"), "integer", lambda f: f["buffer_count"])

    p("coreml", ("specification_version", "spec_version"), "integer", lambda f: f["specification_version"])
    p("coreml", ("model_type", "type"), "text", lambda f: f["model_type"])
    p("coreml", ("author", "metadata_author"), "text", lambda f: f["author"])
    p("coreml", ("license", "metadata_license"), "text", lambda f: f["license"])
    p("coreml", ("short_description", "description"), "text", lambda f: f["short_description"])
    p("coreml", ("version_string", "model_version"), "text", lambda f: f["version_string"])
    p("coreml", ("input_names", "input_feature_names"), "list", lambda f: [x["name"] for x in f["inputs"]])
    p("coreml", ("output_names", "output_feature_names"), "list", lambda f: [x["name"] for x in f["outputs"]])
    p("coreml", ("user_defined_keys", "user_defined_metadata_keys"), "list", lambda f: list(f["user_defined"]))
    p("coreml", ("state_names", "state_feature_names"), "list", lambda f: [x["name"] for x in f.get("state", [])])
    p("coreml", ("function_names",), "list", lambda f: [x["name"] for x in f.get("functions", [])])
    p("coreml", ("default_function_name", "default_function"), "text", lambda f: f.get("default_function_name"))

    p("thrift", ("method_name", "method", "message_name"), "text", lambda f: _thrift(f)["envelope"]["name"])
    p("thrift", ("message_type",), "text", lambda f: _thrift(f)["envelope"]["type"])
    p("thrift", ("sequence_id", "seqid"), "integer", lambda f: _thrift(f)["envelope"]["seqid"])
    p("thrift", ("protocol", "wire_protocol"), "text", lambda f: _thrift(f)["protocol"])
    p("thrift", ("field_count", "argument_count"), "integer", lambda f: len(_thrift(f)["struct"]))
    p("thrift", ("field_types", "argument_types"), "list", lambda f: [k.split(":", 1)[1] for k in _thrift(f)["struct"]])


def register(module):
    """properties_strict calls this with its own module object. Returns (names, families) added."""
    global M
    M = module
    before, families = dict(M.REG), len(M.FAMILIES)
    _register()
    for k, old in before.items():   # a name registered before keeps its reader
        if M.REG[k] is not old:
            M.MORE_CLASHES.append(M.REG[k].name)
            M.REG[k] = old
    for kind in KINDS:
        M.NAMESPACES.add(kind)
        M.PACK_NAMESPACES.add(kind)
        M.CONTENT_TOKENS.add(kind)
        M.RELATED.setdefault(kind, (kind,))
        M.MORE_TYPES.append((kind, lambda d, kind=kind: is_kind(kind, d)))
    M.NS_ALIAS.update({k: v for k, v in ALIASES.items() if k not in M.NS_ALIAS})
    M.TIE_FREE.update(M.REG[k].fn for k in M.REG if k not in before)
    return len(M.REG) - len(before), len(M.FAMILIES) - families
