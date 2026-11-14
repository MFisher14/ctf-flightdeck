"""B-251: the long-tail reader pack of the metadata lane and its catalog rows.

solvers/metadata-forensics/readers_longtail.py names the facts of the toolkit readers (lt_avro,
lt_thrift_parquet, lt_tnef, lt_jxl, lt_model_meta) for the lane; ctf/formats registers the seven formats
with a detector, a corpus sample and checks. The corpus samples are written by
ctf/formats/corpus_longtail.py, which shares no code with the readers; the generic corpus and matrix
tests of B-162 (tests/test_formats_corpus.py, tests/test_formats_matrix.py) also run over them.
"""
import pytest

import labels
from ctf import formats
from ctf.formats import corpus as C
from ctf.formats import corpus_longtail as L
from ctf.formats import detect_longtail
from ctf.formats import matrix as X

LANE = X.lane_module()
PACK = LANE.MORE_MODULES["readers_longtail.py"]
KINDS = ("avro", "parquet", "tnef", "jxl", "tflite", "coreml", "thrift")
CATALOG = formats.load()


@pytest.fixture()
def no_judge(monkeypatch):
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "off")


def ask(prop, name, data):
    answer = LANE.answer_question({"answer_id": "t", "question": f"Determine {prop} for {name}."}, {name: data}, {})
    return X.classify(answer, labels)


def test_the_pack_is_loaded_and_every_format_is_catalogued():
    names, families = LANE.MORE_LOADED["readers_longtail.py"]
    assert names >= 90 and families == 0
    assert not [n for n in LANE.MORE_CLASHES if n.split(".")[0] in KINDS]       # no name was taken by an earlier pack
    by_id = {f.id: f for f in CATALOG}
    for kind in KINDS:
        assert kind in LANE.NAMESPACES and by_id[kind].namespaces == (kind,)
        assert by_id[kind].samples and set(by_id[kind].samples) <= set(L.SAMPLES)
        assert formats.DETECTORS[kind] is detect_longtail.DETECTORS[kind]
    assert [f.rank for f in CATALOG] == list(range(1, len(CATALOG) + 1))
    assert set(L.SAMPLES) == {s for kind in KINDS for s in by_id[kind].samples}


@pytest.mark.parametrize("sid", sorted(L.SAMPLES))
def test_each_sample_is_identified_typed_and_answered_unsure(no_judge, sid):
    s = C.build(sid)
    own = next(f for f in CATALOG if sid in f.samples)
    assert [m.format for m in formats.identify(s.name, s.data, CATALOG) if m.sure] == [own.id]
    assert X.lane_kind(LANE, s.data) == own.id
    asked = 0
    for c in s.checks:
        if c.prop in ("file.size_bytes", "sha256"):
            continue
        status, values, _ = ask(c.prop, s.name, s.data)
        assert status == "unsure", (c.prop, status, values)       # never plain before a judge has spoken
        assert set(values) & X.renderings(c.expected), (c.prop, values, c.expected)
        asked += 1
    assert asked >= 5


@pytest.mark.parametrize("kind", KINDS)
def test_a_reader_is_absent_on_another_format_and_unknown_on_a_broken_file(no_judge, kind):
    own = next(f for f in CATALOG if f.id == kind)
    s = C.build(own.samples[0])
    prop = next(c.prop for c in s.checks if c.prop.startswith(kind + "."))
    reader = LANE.lookup(LANE.canon(prop))
    other = C.build("lnk_shortcut")
    assert reader.fn(other.name, other.data) is None               # not this format: no such field
    assert not PACK.is_kind(kind, other.data)
    # the same format, cut short: the reader refuses it and the extractor says so (never a made-up value)
    cut = {"avro": s.data[:-9], "parquet": s.data[:40] + s.data[-4:], "tnef": s.data[:-3], "jxl": s.data[:40],
           "tflite": s.data[:60], "coreml": s.data[:-2], "thrift": s.data[:-3]}[kind]
    assert PACK.is_kind(kind, cut)
    with pytest.raises(LANE.Unknown, match=f"the {kind} reader refuses the file"):
        reader.fn(s.name, cut)
    status, values, _ = ask(prop, s.name, cut)
    assert not set(values) & X.renderings(next(c.expected for c in s.checks if c.prop == prop))


def test_one_parse_serves_every_reader_of_a_file(monkeypatch, no_judge):
    s = C.build("avro_events")
    module = PACK._reader("lt_avro")
    calls = []
    real = module.read_container
    monkeypatch.setattr(module, "read_container", lambda d: calls.append(len(d)) or real(d))
    PACK._MEMO.clear()
    for prop in ("avro.codec", "avro.record_count", "avro.field_names"):
        assert LANE.lookup(LANE.canon(prop)).fn(s.name, s.data) is not None
    assert calls == [len(s.data)]
    other = s.data + b""                                     # equal bytes: the memo is by content, not identity
    assert LANE.lookup("avro_codec").fn(s.name, bytes(bytearray(other))) == "deflate" and len(calls) == 1
    changed = C.build("avro_events").data.replace(b"deflate", b"deflatE")
    with pytest.raises(LANE.Unknown):
        LANE.lookup("avro_codec").fn(s.name, changed)
    assert len(calls) == 2


def test_aliases_and_a_parquet_file_of_two_codecs(no_judge):
    s = C.build("tnef_winmail")
    status, values, names = ask("winmail.subject", s.name, s.data)
    assert status == "unsure" and "Corpus quarterly figures" in values and any("tnef.subject" in n for n in names)
    j = C.build("jxl_container")
    status, values, _ = ask("jpegxl.height", j.name, j.data)
    assert status == "unsure" and "50" in values

    facts = {"row_groups": [{"columns": [{"codec": "SNAPPY"}, {"codec": "GZIP"}]}]}
    with pytest.raises(LANE.Unknown, match="2 codecs: GZIP, SNAPPY"):
        PACK._parquet_codec(facts)
    assert PACK._parquet_codec({"row_groups": [{"columns": [{"codec": "ZSTD"}, {"codec": "ZSTD"}]}]}) == "ZSTD"


@pytest.mark.parametrize("kind", KINDS)
def test_detectors_are_bounded_and_never_raise(kind):
    test = detect_longtail.DETECTORS[kind]
    own = next(f for f in CATALOG if f.id == kind)
    good = C.build(own.samples[0]).data
    assert test(good) is True
    for cut in range(0, min(len(good), 96)):
        assert test(good[:cut]) in (True, False)
    for sid in sorted(C.BUILDERS):
        if sid not in own.samples:
            assert test(C.build(sid).data) is False, sid          # no other sample of the corpus is this format


def test_detectors_refuse_near_misses():
    d = detect_longtail.DETECTORS
    sample = {k: C.build(next(f for f in CATALOG if f.id == k).samples[0]).data for k in KINDS}
    assert not d["avro"](b"Obj\x02" + sample["avro"][4:])                 # another container version
    assert not d["parquet"](sample["parquet"][:-1]) and not d["parquet"](b"PAR1PAR1")    # no tail magic; too short
    assert d["parquet"](sample["parquet"][:-4] + b"PARE")                 # an encrypted footer is still Parquet
    assert not d["tnef"](sample["tnef"][:5]) and not d["tnef"](b"\x78\x9f\x3e\x23" + sample["tnef"][4:])
    assert not d["jxl"](b"\xff\x0a\x00") and not d["jxl"](b"\x00" + sample["jxl"][1:11] + b"\x0b" + sample["jxl"][12:])
    assert d["jxl"](C.build("jxl_codestream").data)
    assert not d["tflite"](sample["tflite"][:4] + b"TFL4" + sample["tflite"][8:]) and not d["tflite"](sample["tflite"][:15])
    assert d["tflite"](b"\x00\x00\x00\x00" + sample["tflite"])            # size-prefixed: the identifier at 8


def test_coreml_detector_edges():
    test = detect_longtail.DETECTORS["coreml"]
    long = L.coreml_model(inputs=[(f"feature_{i}", "x" * 200, 2) for i in range(80)], metadata={"author": "A"})
    assert len(long) > 2 * detect_longtail.HEAD and test(long)       # a description longer than the head
    assert not test(L.pb(1, 5) + L.pb(2, L.pb(1, L.pb(1, "x")) + L.pb(7, 1)))    # field 7 is no description field
    assert not test(L.pb(1, 8) + L.pb(2, "pytorch") + L.pb(3, "2.1"))           # another protobuf message
    assert not test(L.pb(1, 5) + L.pb(2, L.pb(11, "label")))                     # no feature and no metadata
    assert not test(b"\x08\x05\x12\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")  # a length varint that never ends


# ------------------------------------------------------------------ round 1

def read(prop, name, data):
    return LANE.lookup(LANE.canon(prop)).fn(name, data)


def test_an_empty_fact_is_no_such_field_never_an_empty_answer(no_judge):
    bare = L.tflite_model()                               # no description, no tensors, no metadata
    assert read("tflite.description", "m.tflite", bare) is None                      # "" in the reader's facts
    assert read("tflite.tensor_names", "m.tflite", bare) is None                     # []
    assert read("tflite.metadata_names", "m.tflite", bare) is None
    assert read("tflite.version", "m.tflite", bare) == 3 and read("tflite.tensor_count", "m.tflite", bare) == 0
    full = C.build("tflite_keywords").data
    assert read("tflite.description", "m.tflite", full) == "corpus keyword spotter"
    assert read("tflite.tensor_names", "m.tflite", full) == ["input", "dense/kernel", "output"]
    alone = L.tnef_stream([L.tnef_attr(1, 0x00018004, b"no attachments\x00")])
    assert read("tnef.attachment_names", "winmail.dat", alone) is None               # [] is "no such field"
    assert read("tnef.attachment_count", "winmail.dat", alone) == 0                  # 0 is an answer
    status, values, _ = ask("tflite.description", "m.tflite", bare)
    assert "" not in values


def test_coreml_state_and_function_facts(no_judge):
    def feature(name, kind):
        return L.pb_msg([(1, name), (3, L.pb(kind, b""))])
    desc = L.pb_msg([(1, feature("tokens", 5)), (10, feature("logits", 5)), (13, feature("kv_cache", 8)),
                     (20, L.pb_msg([(1, "encode"), (2, feature("text", 3))])), (20, L.pb_msg([(1, "decode"), (3, feature("text", 3))])),
                     (21, "encode")])
    data = L.pb(1, 9) + L.pb(2, desc) + L.pb(502, b"\x0a\x00")
    assert [m.format for m in formats.identify("Model.mlmodel", data, CATALOG) if m.sure] == ["coreml"]
    assert read("coreml.state_names", "Model.mlmodel", data) == ["kv_cache"]
    assert read("coreml.function_names", "Model.mlmodel", data) == ["encode", "decode"]
    assert read("coreml.default_function_name", "Model.mlmodel", data) == "encode"
    assert read("coreml.model_type", "Model.mlmodel", data) == "mlProgram"
    plain = C.build("coreml_classifier").data             # a model with none of them: no such field
    for prop in ("coreml.state_names", "coreml.function_names", "coreml.default_function_name"):
        assert read(prop, "Classifier.mlmodel", plain) is None


def test_thrift_facts_and_a_message_read_in_several_ways(no_judge):
    s = C.build("thrift_call")
    assert read("thrift.method", s.name, s.data) == "getUser" and read("thrift.seqid", s.name, s.data) == 7
    assert read("thrift.field_types", s.name, s.data) == ["i32", "binary", "bool"]
    reply = L.thrift_message(b"getUser", 2, 7, [])        # a reply with no fields: a count of 0 is an answer
    assert read("thrift.message_type", "r.bin", reply) == "reply" and read("thrift.field_count", "r.bin", reply) == 0
    assert read("thrift.field_types", "r.bin", reply) is None
    with pytest.raises(LANE.Unknown, match="read as Thrift in 2 ways"):
        PACK._thrift({"readings": [{"protocol": "binary"}, {"protocol": "compact"}]})


def test_short_or_no_magic_formats_are_not_identified_on_their_first_bytes_alone():
    d = detect_longtail.DETECTORS
    text = b"\xff\x0a" + b"The quick brown fox jumps over the lazy dog. " * 4
    lookalike = bytes.fromhex("0805" "1207" "0a05") + b"hello"          # {1: 5, 2: {1: "hello"}}
    for name, blob in (("notes.jxl", text), ("blob.mlmodel", lookalike)):
        assert not d["jxl"](blob) and not d["coreml"](blob)
        assert [m for m in formats.identify(name, blob, CATALOG) if m.sure] == []      # the extension alone: never sure
        assert not PACK.is_kind("jxl", blob) and not PACK.is_kind("coreml", blob)
    assert read("jxl.width", "notes.jxl", text) is None and read("coreml.author", "blob.mlmodel", lookalike) is None
    call = C.build("thrift_call").data
    assert d["thrift"](call) and not d["thrift"](call[:12]) and not d["thrift"](b"\x80\x02" + call[2:])
    assert not d["thrift"](call[:19] + b"\x01" + call[20:])               # 1 is no binary-protocol field type
    assert not d["thrift"](call[:8] + b"get User"[:7] + call[15:])        # the method name is an identifier
    for cut in range(len(call)):
        assert d["thrift"](call[:cut]) in (True, False)
