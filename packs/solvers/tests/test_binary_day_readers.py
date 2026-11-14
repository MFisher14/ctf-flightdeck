"""B-240 carry: the Day 30 / Day 31 binary day readers (solvers/binary/d30.py, fields_d30.py, fields_d31.py).

d30.py reads the HGRF campaign graph of three NEKO members (the config capsule, and the loader's graph only when
all three graphs agree with this_role omitted) and hands its answers to fields_d30.py through a per-process stash.
fields_d31.py reads the one CRC-valid HGAU record of a member. Every fixture is built here from known values;
nothing is executed.
"""
import contextlib
import io
import json
import struct
import sys
import zlib

import pytest

import d30
import fields_d30
import fields_d31
import labels


def _rec(magic: bytes, obj, key: int, *, crc=None) -> bytes:
    plain = json.dumps(obj, separators=(",", ":")).encode()
    c = zlib.crc32(plain) if crc is None else crc
    return magic + struct.pack("<BBHI", 1, key, len(plain), c) + bytes(b ^ key for b in plain)


def _neko(graph, role, key, *, extra=b"") -> bytes:
    body = b"NEKO" + bytes(range(32)) + extra
    return body + _rec(b"HGRF", dict(graph, this_role=role), key)


GRAPH = {"schema": "graph.v1", "campaign_id": "BR30-7", "nodes": ["a", "b"], "edges": [["a", "b"]],
         "load_order": ["loader", "library", "config"],
         "config": {"domain": "c2.day30.example.invalid", "mutex": "Global\\BR30_7"}}


def _files(graphs=None, keys=(0x11, 0x22, 0x33)):
    graphs = graphs or (GRAPH, GRAPH, GRAPH)
    return {"d30--sample-loader.n": _neko(graphs[0], "loader", keys[0]),
            "d30--sample-library.n": _neko(graphs[1], "library", keys[1]),
            "d30--sample-config.n": _neko(graphs[2], "config", keys[2])}


def _q(qid, member, prop):
    return {"qid": qid, "id": qid,
            "question": f"Read the record at {member} decoded HGRF JSON property graph.config.{prop}."}


QS = [_q("d30_analysis_config_capsule_graph_config_domain", "d30--sample-config.n", "domain"),
      _q("d30_analysis_config_mutex", "d30--sample-loader.n", "mutex"),
      _q("d30_analysis_config_domain", "d30--sample-loader.n", "domain")]


def _d30(files, questions=QS):
    with contextlib.redirect_stderr(io.StringIO()):
        handed = d30.answers(questions, files, {})
    # the dispatcher sees nothing from d30 itself; fields_d30 hands back the stash for the ids asked
    return handed, fields_d30.fields("d30--sample-config.n", b"", questions)


def test_d30_reads_capsule_and_common_config_through_the_fields_hook():
    handed, got = _d30(_files())
    assert handed == {}
    assert got == {"d30_analysis_config_capsule_graph_config_domain": "c2.day30.example.invalid",
                   "d30_analysis_config_mutex": "Global\\BR30_7",
                   "d30_analysis_config_domain": "c2.day30.example.invalid"}


def test_d30_divergent_graphs_withdraw_the_common_value_but_keep_the_capsule():
    other = dict(GRAPH, config={"domain": "decoy.day30.example.invalid", "mutex": "Global\\BR30_7"})
    _, got = _d30(_files(graphs=(GRAPH, GRAPH, other)))
    assert got == {"d30_analysis_config_capsule_graph_config_domain": "decoy.day30.example.invalid"}


def test_d30_two_valid_records_in_one_member_are_not_unique():
    files = _files()
    files["d30--sample-config.n"] = files["d30--sample-config.n"] + _rec(b"HGRF", dict(GRAPH, this_role="x"), 0x44)
    _, got = _d30(files)
    assert got == {}                     # the capsule is ambiguous and the three graphs are no longer all readable


def test_d30_bad_crc_record_is_not_read():
    files = _files()
    data = files["d30--sample-config.n"]
    files["d30--sample-config.n"] = data[:-1] + bytes([data[-1] ^ 0xFF])
    _, got = _d30(files)
    assert "d30_analysis_config_capsule_graph_config_domain" not in got
    assert "d30_analysis_config_mutex" not in got


def test_d30_question_naming_another_property_is_not_answered():
    q = [_q("d30_analysis_config_capsule_graph_config_domain", "d30--sample-config.n", "mutex")]
    _, got = _d30(_files(), q)
    assert got == {}


def test_fields_d30_without_a_stash_answers_nothing():
    saved = sys.modules.pop(d30.STASH, None)
    try:
        assert fields_d30.fields("x", b"", QS) == {}
    finally:
        if saved is not None:
            sys.modules[d30.STASH] = saved


# ------------------------------------------------------------------------------------------- fields_d31 (HGAU)
def _hgau(cfg, branch="success", key=0x5A, *, crc=None, prefix=b"\x7fELF" + bytes(60)):
    return prefix + _rec(b"HGAU", {"config": cfg, "trace": {"branch": branch}}, key, crc=crc)


CFG31 = {"campaign": "BR31-004", "domain": "gauntlet.day31.example.invalid"}


def _q31(field, fmt=None):
    qid = f"d31_analysis_{field}"
    return {"qid": qid, "question": "...", **({"answer_format": fmt} if fmt else {})}


def test_fields_d31_reads_config_crc_and_branch_from_the_one_valid_record():
    data = _hgau(CFG31)
    rec = fields_d31.record(data)
    assert rec is not None and rec["json"]["config"] == CFG31
    qs = [_q31("gauntlet_config_domain"), _q31("gauntlet_crc32_hex"), _q31("gauntlet_trace_branch")]
    got = fields_d31.fields("m", data, qs)
    plain = json.dumps({"config": CFG31, "trace": {"branch": "success"}}, separators=(",", ":")).encode()
    assert got == {"d31_analysis_gauntlet_config_domain": "gauntlet.day31.example.invalid",
                   "d31_analysis_gauntlet_crc32_hex": "0x%08x" % zlib.crc32(plain),
                   "d31_analysis_gauntlet_trace_branch": "success"}


def test_fields_d31_campaign_of_another_day_is_an_unsure_pick_not_plain():
    data = _hgau(dict(CFG31, campaign="BR30-004"))
    got = fields_d31.fields("m", data, [_q31("gauntlet_config_domain")])
    v = got["d31_analysis_gauntlet_config_domain"]
    assert labels.is_unsure(v)
    assert [opt for _n, opt in labels.parse(v).options] == ["gauntlet.day31.example.invalid"]
    assert fields_d31.override("m", data, [_q31("config_domain")]) == {}     # an unsure pick never overrides


def test_fields_d31_branch_outside_the_vocabulary_is_none():
    data = _hgau(CFG31, branch="maybe")
    assert fields_d31.fields("m", data, [_q31("gauntlet_trace_branch")]) == {}
    fmt = {"kind": "enum", "accepted_values": ["maybe", "never"]}
    assert fields_d31.fields("m", data, [_q31("gauntlet_trace_branch", fmt)]) == {
        "d31_analysis_gauntlet_trace_branch": "maybe"}


@pytest.mark.parametrize("data", [
    _hgau(CFG31, crc=0),                                                         # CRC does not match
    _hgau(CFG31) + _hgau(dict(CFG31, domain="other.invalid"), prefix=b""),        # two different valid records
    b"\x7fELF" + bytes(80),                                                      # no record at all
], ids=["bad-crc", "two-records", "none"])
def test_fields_d31_answers_nothing_without_exactly_one_valid_record(data):
    assert fields_d31.record(data) is None
    assert fields_d31.fields("m", data, [_q31("gauntlet_config_domain"), _q31("gauntlet_crc32_hex")]) == {}
    assert fields_d31.override("m", data, [_q31("config_domain")]) == {}


def test_fields_d31_override_makes_only_the_day_campaign_plain():
    data = _hgau(CFG31)
    assert fields_d31.override("m", data, [_q31("config_domain"), _q31("gauntlet_crc32_hex")]) == {
        "d31_analysis_config_domain": "gauntlet.day31.example.invalid"}
