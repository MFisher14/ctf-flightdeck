"""B-251: TFLite and Core ML metadata readers (solvers/toolkits/lt_model_meta.py).

TFLite models are laid out by the corpus writer (ctf/formats/corpus_longtail.py) from the slots of the
published schema; the FlatBuffers reader underneath is pinned to hand-assembled bytes in
test_toolkits_lt_flat_capnp.py. Core ML is checked two ways: messages written by the corpus protobuf
writer, and the real models macOS ships (when this machine has them; reported as not run otherwise).
"""
import glob
import struct

import pytest

import lt_model_meta as mm
from _lt_common import FormatError, NotThisFormat
from ctf import flagfmt
from ctf.formats.corpus_longtail import coreml_model, flat_buffer, pb, pb_msg, tflite_model

SYSTEM_MODELS = "/System/Library/PrivateFrameworks/*/Versions/A/Resources/**/*.mlmodel"


def model(codes=b"", description=b"speech keyword spotter v2"):
    weights = struct.pack("<4f", 0.5, -1.25, 3.0, 8.0)
    return tflite_model(
        description=description,
        tensors=[(b"input", [1, 4], 0, b""), (b"dense/kernel", [4], 0, weights),
                 (b"labels", [len(codes) // 4 or 1], 2, codes), (b"output", [1, 4], 9, b"")],
        metadata=[(b"min_runtime_version", b"1.14.0\x00\x00"), (b"TFLITE_METADATA", b"\x1c\x00\x00\x00M001")],
        opcodes=[(9, None), (32, b"SecretDecode")],
        operators=[(0, [0, 1], [3], None), (1, [3], [3], b"key=open sesame")],
        signature=(b"serving_default", [(b"x", 0)], [(b"y", 3)]))


def test_tflite_structure_tensors_metadata_and_signature():
    blobs = []
    got = mm.read_tflite(model(), blobs)
    assert (got["version"], got["description"], got["size_prefixed"]) == (3, "speech keyword spotter v2", False)
    assert got["operator_codes"] == [
        {"builtin_code": 9, "name": "FULLY_CONNECTED", "custom_code": None, "version": 1},
        {"builtin_code": 32, "name": "CUSTOM", "custom_code": "SecretDecode", "version": 1}]
    (sg,) = got["subgraphs"]
    assert sg["name"] == "main" and sg["inputs"] == [0] and sg["outputs"] == [3]
    assert [(t["name"], t["shape"], t["type"], t["buffer_bytes"]) for t in sg["tensors"]] == [
        ("input", [1, 4], "FLOAT32", 0), ("dense/kernel", [4], "FLOAT32", 16), ("labels", [1], "INT32", 0),
        ("output", [1, 4], "INT8", 0)]
    assert sg["tensors"][1]["buffer"] == 1 and "as_text" not in sg["tensors"][1]
    assert sg["operators"] == [
        {"opcode_index": 0, "opcode": "FULLY_CONNECTED", "inputs": [0, 1], "outputs": [3]},
        {"opcode_index": 1, "opcode": "SecretDecode", "inputs": [3], "outputs": [3], "custom_options": "key=open sesame"}]
    assert got["metadata"] == [
        {"name": "min_runtime_version", "buffer": 2, "size": 8, "value": "hex:" + b"1.14.0\x00\x00".hex()},
        {"name": "TFLITE_METADATA", "buffer": 3, "size": 8, "value": "hex:" + b"\x1c\x00\x00\x00M001".hex()}]
    assert got["signatures"] == [{"signature_key": "serving_default", "subgraph_index": 0,
                                  "inputs": [{"name": "x", "tensor_index": 0}], "outputs": [{"name": "y", "tensor_index": 3}]}]
    assert (got["buffer_count"], got["buffer_bytes"]) == (4, 32)
    assert ("custom options", b"key=open sesame") in blobs and ("buffer 2", b"1.14.0\x00\x00") in blobs


@pytest.mark.parametrize("fmt,kind", [("<i", 2), ("<f", 0), ("<q", 4), ("<B", 3)])
def test_a_constant_tensor_of_character_codes_is_shown_as_text(fmt, kind):
    text = "tensor of character codes"
    raw = b"".join(struct.pack(fmt, ord(c)) for c in text)
    data = tflite_model(tensors=[(b"w", [len(text)], kind, raw),
                                 (b"fraction", [4], 0, struct.pack("<4f", 70.5, 70.0, 71.0, 72.0)),
                                 (b"control", [4], 2, struct.pack("<4i", 10, 70, 71, 72)),
                                 (b"short", [3], 2, struct.pack("<3i", 70, 71, 72)),
                                 (b"ragged", [2], 2, b"FGHIJ")])
    tensors = mm.read_tflite(data)["subgraphs"][0]["tensors"]
    assert tensors[0]["as_text"] == text
    # 70.5 is no character code, 10 is a control code, three values are too few, five bytes are no int32 list
    assert [t["name"] for t in tensors if "as_text" not in t] == ["fraction", "control", "short", "ragged"]


def test_operator_codes_past_the_deprecated_byte_range():
    # builtin codes above 127 do not fit the deprecated int8 field: the int32 field holds them
    got = mm.read_tflite(tflite_model(opcodes=[(150, None), (3, None), (250, None)],
                                      operators=[(0, [], [], None), (2, [], [], None)]))
    assert got["operator_codes"] == [{"builtin_code": 150, "name": "GELU", "custom_code": None, "version": 1},
                                     {"builtin_code": 3, "name": "CONV_2D", "custom_code": None, "version": 1},
                                     {"builtin_code": 250, "name": None, "custom_code": None, "version": 1}]
    assert [o["opcode"] for o in got["subgraphs"][0]["operators"]] == ["GELU", 250]      # no name: the number


def test_tflite_refusals():
    with pytest.raises(FormatError, match="not TFL3"):
        mm.read_tflite(flat_buffer([("u32", 3)], b"ABCD"))
    good = model()
    with pytest.raises(FormatError):
        mm.read_tflite(good[:len(good) // 2])
    with pytest.raises(FormatError, match="more than 20000 tensors"):
        mm.read_tflite(tflite_model(tensors=[(b"t", [1], 0, b"")] * 20_001))


def coreml(**kw):
    return coreml_model(
        spec_version=5, inputs=[("image", "a 224x224 picture", 4), ("threshold", "", 2)],
        outputs=[("label", "the class", 3), ("scores", "", 6)], predicted="label",
        metadata={"short_description": "Leaf classifier", "version": "2.1", "author": "Ada Example", "license": "MIT"},
        user_defined={"com.github.apple.coremltools.version": "7.1", "note": "trained offline"}, **kw)


def test_coreml_description_and_metadata():
    got = mm.read_coreml(coreml())
    assert got == {
        "format": "coreml", "specification_version": 5, "is_updatable": False, "model_type": "neuralNetwork",
        "inputs": [{"name": "image", "short_description": "a 224x224 picture", "type": "image"},
                   {"name": "threshold", "short_description": "", "type": "double"}],
        "outputs": [{"name": "label", "short_description": "the class", "type": "string"},
                    {"name": "scores", "short_description": "", "type": "dictionary"}],
        "predicted_feature_name": "label", "predicted_probabilities_name": None,
        "short_description": "Leaf classifier", "version_string": "2.1", "author": "Ada Example", "license": "MIT",
        "user_defined": {"com.github.apple.coremltools.version": "7.1", "note": "trained offline"}}
    assert mm.read_coreml(coreml(model_field=402))["model_type"] == "treeEnsembleClassifier"
    assert mm.read_coreml(coreml(model_field=777))["model_type"] == "field 777"
    assert mm.read_coreml(coreml() + pb(10, True))["is_updatable"] is True


def test_coreml_is_told_from_other_protobuf_and_other_files():
    assert mm.detect(coreml()[:8192])
    big = coreml_model(inputs=[(f"feature_{i}", "x" * 200, 2) for i in range(80)], metadata={"author": "A"})
    assert len(big) > 16_000 and mm.detect(big[:8192])           # a description longer than the head
    assert mm.read_coreml(big)["author"] == "A"
    onnx_like = pb(1, 8) + pb(2, "pytorch") + pb(3, "2.1")       # ir_version, producer: field 2 is text, not a description
    assert not mm.detect(onnx_like)
    with pytest.raises(NotThisFormat):
        mm.read_coreml(onnx_like)
    with pytest.raises(NotThisFormat, match="fields a Core ML ModelDescription does not have"):
        mm.read_coreml(pb(1, 5) + pb(2, pb(1, pb(1, "x")) + pb(7, 1)))
    assert not mm.detect(pb(1, 5) + pb(2, pb(1, pb(1, "x")) + pb(7, 1)))      # field 7 is no description field
    assert not mm.detect(pb(1, 5) + pb(2, pb(11, "label")))                    # no feature and no metadata
    for other in (b"\x89PNG\r\n\x1a\n" + bytes(40), b"\x08\x05\x12", b"", bytes(64), b"\x08\x05\x12\x02\xff\xff"):
        assert not mm.detect(other)


def test_coreml_reader_on_the_models_this_system_ships():
    """Real models, where the machine has them. What an operating system ships is not this repo's to
    promise, so only what the reader guarantees of any file is asserted: it reads a model or refuses it
    with NotThisFormat (never another exception), detect() and the reader agree, and the facts of a
    model it read are well formed. (When this was written all 14 models of this host were read.)"""
    files = sorted(glob.glob(SYSTEM_MODELS, recursive=True))[:60]
    if not files:
        pytest.skip("needs_realdata: no Core ML model under /System/Library/PrivateFrameworks on this machine")
    for f in files:
        with open(f, "rb") as fh:
            data = fh.read()
        try:
            got = mm.read_coreml(data)
        except NotThisFormat:
            continue                                   # a model newer than the reader: refused by name, not misread
        assert mm.detect(data[:8192], f), f            # what the reader reads, the detector selects
        assert got["format"] == "coreml" and 1 <= got["specification_version"] <= 64, f
        for x in got["inputs"] + got["outputs"] + got.get("state", []):
            assert set(x) == {"name", "short_description", "type"}, f
            assert all(v is None or isinstance(v, str) for v in x.values()), f
        assert got["model_type"] is None or isinstance(got["model_type"], str), f


def test_solve_reads_flags_from_tensor_codes_buffers_and_coreml_metadata(tmp_path):
    flag = flagfmt.cribs()[0] + "int32_character_codes}"
    codes = b"".join(struct.pack("<i", ord(c)) for c in flag)
    (tmp_path / "kws.tflite").write_bytes(model(codes))
    r = mm.solve(tmp_path)
    assert (r.status, r.flags) == ("solved", (flag,)) and "as_text" in r.evidence[0].detail

    raw = flagfmt.cribs()[0] + "raw_metadata_buffer}"
    (tmp_path / "kws.tflite").write_bytes(tflite_model(metadata=[(b"note", b"\xff\x00" + raw.encode())]))
    assert mm.solve(tmp_path).flags == (raw,)

    author = flagfmt.cribs()[0] + "coreml_user_defined}"
    (tmp_path / "kws.tflite").unlink()
    pkg = tmp_path / "Leaf.mlpackage" / "Data" / "com.apple.CoreML"
    pkg.mkdir(parents=True)
    (pkg / "model.mlmodel").write_bytes(coreml_model(inputs=[("x", "", 2)], user_defined={"secret": author}))
    r = mm.solve(tmp_path)
    assert (r.status, r.flags) == ("solved", (author,))
    assert r.evidence[0].path == "Leaf.mlpackage/Data/com.apple.CoreML/model.mlmodel"


def test_solve_statuses(tmp_path):
    assert mm.solve(tmp_path).status == "none"
    (tmp_path / "m.tflite").write_bytes(model())
    r = mm.solve(tmp_path)
    assert r.status == "unsure" and "format=tflite" in r.evidence[0].detail
    (tmp_path / "m.tflite").write_bytes(model()[:200])
    r = mm.solve(tmp_path)
    assert r.status == "unsure" and "malformed TFLite/Core ML model" in r.notes


# ------------------------------------------------------------------ round 1

def test_operator_names_follow_the_published_schema_numbers():
    # anchors along the BuiltinOperator enumeration of the public schema: one name out of place shifts the rest
    assert len(mm.BUILTIN) == 162 and len(set(mm.BUILTIN)) == 162
    for code, name in ((0, "ADD"), (9, "FULLY_CONNECTED"), (25, "SOFTMAX"), (32, "CUSTOM"), (33, "EMBEDDING_LOOKUP_SPARSE"),
                       (34, "PAD"), (53, "CAST"), (70, "EXPAND_DIMS"), (83, "PACK"), (97, "RESIZE_NEAREST_NEIGHBOR"),
                       (114, "QUANTIZE"), (117, "HARD_SWISH"), (127, "PLACEHOLDER_FOR_GREATER_OP_CODES"), (128, "CUMSUM"),
                       (150, "GELU"), (161, "RIGHT_SHIFT")):
        assert mm.BUILTIN[code] == name, code
    got = mm.read_tflite(tflite_model(opcodes=[(53, None), (70, None), (162, None)],
                                      operators=[(0, [], [], None), (1, [], [], None), (2, [], [], None)]))
    assert [c["name"] for c in got["operator_codes"]] == ["CAST", "EXPAND_DIMS", None]      # 162 on: its number
    assert [o["opcode"] for o in got["subgraphs"][0]["operators"]] == ["CAST", "EXPAND_DIMS", 162]


def test_a_signature_names_its_own_subgraph():
    data = tflite_model(tensors=[(b"x", [1], 0, b"")], signature=(b"decode", [(b"x", 0)], [(b"y", 0)]),
                        signature_subgraph=1, extra_subgraphs=[b"decode_body"])
    got = mm.read_tflite(data)
    assert [sg["name"] for sg in got["subgraphs"]] == ["main", "decode_body"]
    assert got["subgraphs"][1] == {"name": "decode_body", "inputs": [], "outputs": [], "tensors": [], "operators": []}
    assert got["signatures"] == [{"signature_key": "decode", "subgraph_index": 1,
                                  "inputs": [{"name": "x", "tensor_index": 0}], "outputs": [{"name": "y", "tensor_index": 0}]}]


def feature(name, kind, text=""):
    """A FeatureDescription: name (1), shortDescription (2), type (3: a FeatureType with field `kind`)."""
    return pb_msg([(1, name)] + ([(2, text)] if text else []) + [(3, pb(kind, b""))])


def test_stateful_and_multi_function_models_are_read(tmp_path):
    encode = pb_msg([(1, "encode"), (2, feature("text", 3)), (3, feature("embedding", 5)), (4, "embedding")])
    decode = pb_msg([(1, "decode"), (2, feature("embedding", 5)), (3, feature("text", 3)), (5, "probabilities"),
                     (6, feature("cache", 8, "the running state"))])
    desc = pb_msg([(1, feature("tokens", 5)), (10, feature("logits", 5)), (13, feature("kv_cache", 8)), (20, encode), (20, decode),
                   (21, "encode"), (50, feature("target", 1)), (100, pb_msg([(3, "Ada Example")]))])
    data = pb(1, 9) + pb(2, desc) + pb(502, b"\x0a\x00")
    assert mm.detect(data[:8192])
    got = mm.read_coreml(data)
    assert (got["specification_version"], got["model_type"], got["author"]) == (9, "mlProgram", "Ada Example")
    assert got["inputs"] == [{"name": "tokens", "short_description": None, "type": "multiArray"}]
    assert got["state"] == [{"name": "kv_cache", "short_description": None, "type": "state"}]
    assert got["training_inputs"] == [{"name": "target", "short_description": None, "type": "int64"}]
    assert got["default_function_name"] == "encode"
    assert got["functions"] == [
        {"name": "encode", "inputs": [{"name": "text", "short_description": None, "type": "string"}],
         "outputs": [{"name": "embedding", "short_description": None, "type": "multiArray"}], "state": [],
         "predicted_feature_name": "embedding", "predicted_probabilities_name": None},
        {"name": "decode", "inputs": [{"name": "embedding", "short_description": None, "type": "multiArray"}],
         "outputs": [{"name": "text", "short_description": None, "type": "string"}],
         "state": [{"name": "cache", "short_description": "the running state", "type": "state"}],
         "predicted_feature_name": None, "predicted_probabilities_name": "probabilities"}]
    plain = mm.read_coreml(coreml())                    # a model with none of them has none of the keys
    assert not {"state", "training_inputs", "functions", "default_function_name"} & set(plain)

    # each of state (13), functions (20) and defaultFunctionName (21) alone: the file is still a Core ML model
    flag = flagfmt.cribs()[0] + "author_of_a_stateful_model}"
    for i, extra in enumerate(((13, feature("s", 8)), (20, pb_msg([(1, "f"), (2, feature("x", 2))])), (21, "main"))):
        one = pb(1, 9) + pb(2, pb_msg([(1, feature("x", 2)), extra, (100, pb_msg([(3, flag)]))])) + pb(502, b"")
        assert mm.detect(one[:8192]) and mm.read_coreml(one)["author"] == flag
        folder = tmp_path / str(i)
        folder.mkdir()
        (folder / "m.mlmodel").write_bytes(one)
        r = mm.solve(folder)
        assert (r.status, r.flags) == ("solved", (flag,))
    # a multi-function model whose features are only inside its functions
    only_functions = pb(1, 9) + pb(2, pb_msg([(20, encode), (21, "encode")]))
    assert mm.detect(only_functions) and mm.read_coreml(only_functions)["functions"][0]["name"] == "encode"


def test_a_small_protobuf_shaped_like_a_model_is_not_one(tmp_path):
    lookalike = bytes.fromhex("0805" "1207" "0a05") + b"hello"          # {1: 5, 2: {1: "hello"}}: field 1 is no feature
    assert not mm.detect(lookalike)
    with pytest.raises(NotThisFormat, match="no feature with a name and a type"):
        mm.read_coreml(lookalike)
    (tmp_path / "blob.bin").write_bytes(lookalike)
    r = mm.solve(tmp_path)
    assert (r.status, r.notes) == ("none", "no TFLite/Core ML model file in the handout")
    for desc in (pb(1, pb(1, "x")),                                     # a name and no type
                 pb(1, pb(3, pb(2, b""))),                              # a type and no name
                 pb(1, pb_msg([(1, "x"), (3, pb(99, b""))])),           # a type no FeatureType has
                 pb(1, pb_msg([(1, "x\x00y"), (3, pb(2, b""))])),      # a name with a control character
                 pb(1, pb_msg([(1, "x"), (3, pb(2, b"")), (4, "more")])),      # a field no FeatureDescription has
                 pb(10, pb_msg([(1, 7), (3, pb(2, b""))])),             # a name that is a number
                 pb(20, pb_msg([(1, "f"), (4, "label")])),              # a function with no feature
                 pb(20, pb_msg([(1, "f"), (2, pb(1, "x"))])),           # a function whose input has no type
                 pb(20, pb_msg([(1, "f"), (2, "plain text")])),         # a function whose input is no message
                 pb(100, pb(3, "Ada"))):                                # metadata alone
        assert not mm.detect(pb(1, 5) + pb(2, desc)), desc
        with pytest.raises(NotThisFormat):
            mm.read_coreml(pb(1, 5) + pb(2, desc))
    # the model type after the description is the other sign: metadata alone, of a real model type, is a model
    typed = pb(1, 5) + pb(2, pb(100, pb(3, "Ada"))) + pb(500, b"\x0a\x00")
    assert mm.detect(typed) and mm.read_coreml(typed)["author"] == "Ada" and mm.read_coreml(typed)["inputs"] == []
    assert not mm.detect(pb(1, 5) + pb(2, pb(100, pb(3, "Ada"))) + pb(10, True))       # isUpdatable is no model type
    assert not mm.detect(pb(1, 5) + pb(2, pb(100, pb(3, "Ada"))) + pb(150, b"x"))      # nor is a field under 200
    # every description field is a message or a string: a varint there is not a description
    assert not mm.detect(pb(1, 5) + pb(2, pb(1, feature("x", 2)) + pb(11, 4)))
    # a feature inside the head is enough when the description runs past it
    long = pb(1, 5) + pb(2, pb(1, feature("x", 2)) + pb(100, pb(3, "A" * 20_000)))
    assert mm.detect(long[:8192]) and mm.read_coreml(long)["inputs"][0]["type"] == "double"


# ------------------------------------------------------------------ round 2: offsets that name one target many times

def traced(fn):
    """(result, peak bytes allocated while fn ran)."""
    import tracemalloc
    tracemalloc.start()
    try:
        return fn(), tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def tensors_of(data):
    from lt_flat_capnp import root_table
    return root_table(data)[0].tables(2)[0].tables(0)


def aim(data, slot_tables, slot, target):
    """Point the offset field `slot` of every table in slot_tables at the absolute position `target`
    (a string or vector: its length word). FlatBuffers offsets only point forward: target is after them."""
    out = bytearray(data)
    for t in slot_tables:
        p = t.pos + t.slots[slot]
        assert p < target
        struct.pack_into("<I", out, p, target - p)
    return bytes(out)


def set_scalar(data, slot_tables, slot, value):
    out = bytearray(data)
    for t in slot_tables:
        struct.pack_into("<I", out, t.pos + t.slots[slot], value)
    return bytes(out)


def test_buffers_named_by_several_entries_are_copied_and_scanned_once():
    flag = flagfmt.cribs()[0] + "one_buffer_many_entries}"
    big = b"\xff" + flag.encode() + bytes(64 << 10)
    data = tflite_model(metadata=[(b"m%d" % i, b"x") for i in range(300)] + [(b"big", big)])
    from lt_flat_capnp import root_table
    model = root_table(data)[0]
    start, count = model.vector(4)
    last = start + 4 * (count - 1)
    target = last + struct.unpack_from("<I", data, last)[0]          # the big buffer's Buffer table
    out = bytearray(data)
    for k in range(1, count - 1):                                     # every entry but the empty one names it
        p = start + 4 * k
        struct.pack_into("<I", out, p, target - p)
    blobs = []
    got, peak = traced(lambda: mm.read_tflite(bytes(out), blobs))
    buffers = [b for label, b in blobs if label.startswith("buffer")]
    assert buffers == [big] and ("buffer 1", big) in blobs              # once, under the first index that names it
    assert got["buffer_count"] == count and got["buffer_bytes"] == (count - 1) * len(big)
    assert peak < 3 * len(big) + (2 << 20), f"{peak} bytes were allocated"   # 300 copies would be 19 MiB
    assert mm.inspect(bytes(out))[0]["metadata"][0]["size"] == len(big)


def test_overlapping_buffers_are_charged_for_every_copy():
    # one region of 2000 words, each the length of a vector from there to the region's end, and 2000
    # Buffer tables each naming a different word: 8 MB of copies out of a file of under 200 KB (the
    # budget is four times the file and 1 MiB)
    n = 2000
    region = b"".join(struct.pack("<I", 4 * (n - i - 1)) for i in range(n))
    data = tflite_model(tensors=[(b"t%d" % i, [1], 5, b"s") for i in range(n)] + [(b"region", [1], 5, region)])
    from lt_flat_capnp import root_table
    model = root_table(data)[0]
    buffers = model.tables(4)
    region_at = buffers[-1].vector(0)[0]
    out = bytearray(data)
    for i, b in enumerate(buffers[1:-1]):
        p = b.pos + b.slots[0]
        struct.pack_into("<I", out, p, region_at + 4 * i - p)
    assert len(out) < 200_000
    with pytest.raises(FormatError, match="an amplification"):
        mm.read_tflite(bytes(out))
    assert mm.read_tflite(data)["buffer_count"] == n + 2                # the same file before the offsets were aimed


def test_a_string_every_tensor_names_is_charged_for_every_name():
    long = b"N" * 50_000
    data = tflite_model(tensors=[(b"t", [1], 0, b"")] * 200 + [(long, [1], 0, b"")])
    tensors = tensors_of(data)
    shared = tensors[-1].pos + tensors[-1].slots[3]
    shared += struct.unpack_from("<I", data, shared)[0]
    with pytest.raises(FormatError, match="an amplification"):
        mm.read_tflite(aim(data, tensors[:-1], 3, shared))
    two = aim(data, tensors[-3:-1], 3, shared)                          # a few names shared: an ordinary file
    assert [t["name"] for t in mm.read_tflite(two)["subgraphs"][0]["tensors"][-3:]] == [long.decode()] * 3


def test_a_shape_every_tensor_names_is_charged_for_every_shape():
    data = tflite_model(tensors=[(b"t", [1], 0, b"")] * 300 + [(b"wide", list(range(20_000)), 0, b"")])
    tensors = tensors_of(data)
    shape = tensors[-1].pos + tensors[-1].slots[0]
    shape += struct.unpack_from("<I", data, shape)[0]
    with pytest.raises(FormatError, match="an amplification"):          # 300 lists of 20,000 numbers
        mm.read_tflite(aim(data, tensors[:-1], 0, shape))


def test_a_buffer_every_tensor_names_is_charged_for_every_text_reading():
    codes = b"A" * 60_000                                              # UINT8 character codes: shown as text
    data = tflite_model(tensors=[(b"t", [1], 3, b"")] * 300 + [(b"text", [len(codes)], 3, codes)])
    tensors = tensors_of(data)
    index = tensors[-1].scalar(2, "<I")
    with pytest.raises(FormatError, match="an amplification"):          # 300 texts of 60,000 characters
        mm.read_tflite(set_scalar(data, tensors[:-1], 2, index))
    assert mm.read_tflite(set_scalar(data, tensors[-3:-1], 2, index))["subgraphs"][0]["tensors"][-1]["as_text"] == "A" * 60_000


def test_a_buffer_every_metadata_entry_names_is_charged_for_every_entry():
    data = tflite_model(metadata=[(b"m", b"")] * 3000 + [(b"big", b"\xff" * 4096)])
    from lt_flat_capnp import root_table
    entries = root_table(data)[0].tables(6)
    index = entries[-1].scalar(1, "<I")
    with pytest.raises(FormatError, match="an amplification"):          # 3000 shown values of 2048 bytes
        mm.read_tflite(set_scalar(data, entries[:-1], 1, index))
    assert len(mm.read_tflite(set_scalar(data, entries[:10], 1, index))["metadata"]) == 3001


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_a_float_tensor_with_no_number_is_no_text_and_no_error(value, tmp_path):
    raw = struct.pack("<5f", 70.0, 71.0, value, 72.0, 73.0)
    data = tflite_model(tensors=[(b"w", [5], 0, raw), (b"d", [5], 10, struct.pack("<5d", 70.0, 71.0, value, 72.0, 73.0))])
    tensors = mm.read_tflite(data)["subgraphs"][0]["tensors"]
    assert [("as_text" in t) for t in tensors] == [False, False]
    assert mm.read_tflite(tflite_model(tensors=[(b"w", [4], 0, struct.pack("<4f", 70.0, 71.0, 72.0, 73.0))]))[
        "subgraphs"][0]["tensors"][0]["as_text"] == "FGHI"
    (tmp_path / "m.tflite").write_bytes(data)
    assert mm.solve(tmp_path).status == "unsure"


def test_mutated_tflite_models_raise_only_the_declared_errors():
    from lt_mutations import bit_flips, mutations, only_declared_errors
    codes = struct.pack("<6f", 70, 76, 65, 71, 33, 0.5)
    base = tflite_model(description=b"keyword spotter",
                        tensors=[(b"in", [1, 4], 0, b""), (b"w", [6], 0, codes), (b"s", [3], 2, struct.pack("<3i", 65, 66, 67))],
                        metadata=[(b"min_runtime_version", b"1.14.0")], opcodes=[(9, None), (32, b"Custom")],
                        operators=[(0, [0, 1], [2], None), (1, [2], [2], b"opt")],
                        signature=(b"serving_default", [(b"x", 0)], [(b"y", 2)]))
    read, refused = only_declared_errors(mm.inspect, mutations(base, 2000, seed=251))
    assert read + refused == 2000 and refused > 200 and read > 200
    read, refused = only_declared_errors(mm.inspect, bit_flips(base))
    assert read + refused == 8 * len(base) and refused > 100
    # NaN and infinity bit patterns in a float tensor (exponent bits all set)
    at = base.index(codes)
    for k in range(6):
        for pattern in (b"\x00\x00\xc0\x7f", b"\x00\x00\x80\x7f", b"\x00\x00\x80\xff"):
            mutated = base[:at + 4 * k] + pattern + base[at + 4 * k + 4:]
            assert "as_text" not in mm.inspect(mutated)[0]["subgraphs"][0]["tensors"][1]


def test_mutated_coreml_models_raise_only_the_declared_errors():
    from lt_mutations import bit_flips, mutations, only_declared_errors
    base = coreml(model_field=402)
    read, refused = only_declared_errors(mm.inspect, mutations(base, 2000, seed=251))
    assert read + refused == 2000 and refused > 100 and read > 100
    read, refused = only_declared_errors(mm.inspect, bit_flips(base))
    assert read + refused == 8 * len(base) and refused > 50
