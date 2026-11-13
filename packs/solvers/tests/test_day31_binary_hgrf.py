#!/usr/bin/env python3
"""Strict HGRF property graphs through Binary's real ``evidence.solve_set``.

All bytes are synthetic and parsed statically.  The positive uses a future prefix to
prove the reader is not wired to Day 30.  Corrupt CRC, duplicate records/names/JSON
keys, divergent graphs, invalid Neko headers, contract drift and size caps must never
produce a wrong plain property answer.
"""
from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import warnings
import zipfile
import zlib
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
sys.path[:0] = [str(REPO / "solvers" / "common"), str(REPO / "solvers" / "binary")]

import evidence  # noqa: E402
import hgrf_graph  # noqa: E402
import labels  # noqa: E402
import structural_enums  # noqa: E402

sys.path.append(str(REPO / "tests"))       # last: tests/ shadows no solver module
from sh09_clocks import cost_not_run, work_seconds_unless_missing  # noqa: E402


PREFIX = "d31"
VALUES = {
    "campaign": "SYNTH-CAMPAIGN-31",
    "domain": "node-31.example.invalid",
    "mutex": "Global\\Synthetic31",
    "url": "https://node-31.example.invalid/stage",
}
ENUM = ["elf", "pe", "pe_cli", "jar", "wasm", "neko_bytecode"]
EXACT = {"kind": "exact_text", "syntax": "exact case-sensitive artifact-derived text only; no quotes or explanatory text"}


@contextmanager
def environment(name, value=None):
    """name set to value (or unset when None) for the block; the whole environment comes back after."""
    with mock.patch.dict(os.environ):
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
        yield


@contextmanager
def isolated():
    with tempfile.TemporaryDirectory(prefix="day31-binary-hgrf-") as td, \
            environment("CTF_WORKDIR", str(Path(td) / "challenges")), \
            environment("CTF_TOKEN"), environment("CTF_PLATFORM_URL"):
        yield


def record(graph, key=0x5A, raw=None):
    plain = raw if raw is not None else json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()
    encoded = bytes(value ^ key for value in plain)
    return b"HGRF" + bytes([1, key]) + struct.pack("<HI", len(encoded), zlib.crc32(plain) & 0xFFFFFFFF) + encoded


def hcfg(config, key=0x31):
    """An ordinary valid HCFG decoy, framed independently of the production reader."""
    plain = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
    encoded = bytes(value ^ key for value in plain)
    return b"HCFG" + bytes([1, key]) + struct.pack(
        "<HI", len(encoded), zlib.crc32(plain) & 0xFFFFFFFF
    ) + encoded


def neko(role, graph=None, *, tail=b"", raw=None):
    body = dict(graph or base_graph(role))
    return b"NEKO" + struct.pack("<III", 0, 0, 0) + b"STATIC-NEKO-BODY" + record(body, raw=raw) + tail


def base_graph(role):
    return {
        "schema": "huntress.binary.graph.v1",
        "campaign_id": "synthetic-31",
        "nodes": ["loader", "library", "config"],
        "edges": [["loader", "library"], ["library", "config"]],
        "load_order": ["loader", "library", "config"],
        "config": dict(VALUES),
        "this_role": role,
    }


def question(qid, text, fmt=None):
    return {
        "id": qid,
        "qid": qid,
        "answer_id": qid,
        "question": text,
        "artifact": "evidence.zip",
        "normalization": "exact",
        "answer_format": fmt or dict(EXACT),
    }


def questions(prefix=PREFIX):
    common_lead = (
        "In evidence.zip, Use loader.n's decoded HGRF graph.config object after confirming all three canonical "
        "campaign graphs match when this_role is omitted. Locate the unique CRC32-valid HGRF record by scanning "
        "backward from the end of the Neko member. Its byte-4 version, byte-5 XOR key, little-endian length and "
        "CRC32 fields, XOR decoding, and UTF-8 JSON payload use the same 12-byte layout as HCFG. "
    )
    capsule_lead = (
        f"In evidence.zip, Use the unique {prefix}-- member whose basename ends config.n. Locate the unique "
        "CRC32-valid HGRF record by scanning backward from the end of the Neko member. Its byte-4 version, byte-5 "
        "XOR key, little-endian length and CRC32 fields, XOR decoding, and UTF-8 JSON payload use the same 12-byte "
        "layout as HCFG. "
    )
    out = [question(
        f"{prefix}_analysis_config_capsule_format",
        f"In evidence.zip, Use the unique {prefix}-- member whose basename ends config.n. Classify final bytes by "
        "magic and parsed container: elf for ELF, pe for native PE, pe_cli for PE with a valid CLR/CLI header and "
        "metadata root, jar for a ZIP/JAR with classfiles, wasm for a valid WebAssembly module, or neko_bytecode "
        "for NEKO bytecode. Submit exactly one listed lowercase token.",
        {"kind": "enum", "accepted_values": list(ENUM)},
    )]
    for name in VALUES:
        out.append(question(
            f"{prefix}_analysis_config_{name}",
            common_lead + f"Submit the exact JSON string at loader.n decoded HGRF JSON property "
            f"graph.config.{name}, without JSON quotes.",
        ))
        out.append(question(
            f"{prefix}_analysis_config_capsule_graph_config_{name}",
            capsule_lead + f"Submit the exact JSON string at config.n decoded HGRF JSON property "
            f"graph.config.{name}, without JSON quotes.",
        ))
    return out


def files(graphs=None):
    graphs = graphs or {role: base_graph(role) for role in ("loader", "library", "config")}
    return {f"{PREFIX}--sample-{role}.n": neko(role, graphs[role]) for role in ("loader", "library", "config")}


def many_files(count):
    roles = ["loader", "library", "config"] + [f"extra-{i:02d}" for i in range(4, count + 1)]
    assert len(roles) == count
    return {f"{PREFIX}--sample-{role}.n": neko(role, base_graph(role)) for role in roles}


def ctx():
    return {"attempt": {"challenge": "future-binary", "mode": "single_solve"}, "partial": {}}


def offered(value, truth):
    if value == truth:
        return True
    parsed = labels.parse(value)
    return parsed is not None and any(option == truth for _name, option in parsed.options)


def solve(qs=None, blobs=None, context=None):
    qs = qs or questions()
    return evidence.solve_set(qs, blobs or files(), context or ctx())


def property_ids(qs=None):
    return [q["qid"] for q in (qs or questions()) if not q["qid"].endswith("_format")]


def test_positive_and_accepted_format():
    with isolated():
        qs = questions()
        got = solve(qs)
        for qid in property_ids(qs):
            name = qid.rsplit("_", 1)[-1]
            assert got.get(qid) == VALUES[name], (qid, got.get(qid))
        format_id = qs[0]["qid"]
        assert offered(got.get(format_id), "neko_bytecode"), got.get(format_id)

        key = f"binary.format/neko+enum+{structural_enums.vocabulary_tag(ENUM)}"
        assert labels.learn(key, "token", "accepted", attempt_id="synthetic-hgrf", answer_ids=[format_id])
        got = solve(qs)
        assert got.get(format_id) == "neko_bytecode", got.get(format_id)


def test_corruption_duplicates_and_malformed_fail_closed():
    with isolated():
        qs = questions()
        base = files()

        broken = dict(base)
        damaged = bytearray(broken[f"{PREFIX}--sample-config.n"])
        damaged[-1] ^= 0x80
        broken[f"{PREFIX}--sample-config.n"] = bytes(damaged)
        got = solve(qs, broken)
        assert all(got.get(qid) is None for qid in property_ids(qs)), got

        duplicate_record = dict(base)
        extra = record(base_graph("config"), key=0x6B)
        duplicate_record[f"{PREFIX}--sample-config.n"] += extra
        got = solve(qs, duplicate_record)
        capsule = [qid for qid in property_ids(qs) if "capsule_graph" in qid]
        assert all(got.get(qid) is None for qid in capsule), got

        nonobject_record = dict(base)
        nonobject_record[f"{PREFIX}--sample-config.n"] += record({}, raw=b'["strict-json-decoy"]')
        got = solve(qs, nonobject_record)
        assert all(got.get(qid) is None for qid in property_ids(qs)), got

        duplicate_name = dict(base)
        duplicate_name[f"nested/{PREFIX}--sample-config.n"] = base[f"{PREFIX}--sample-config.n"]
        got = solve(qs, duplicate_name)
        assert all(got.get(q["qid"]) is None for q in qs), got

        # A malformed central directory understates its entry count while its declared
        # byte span still contains a fourth, exact-name duplicate.  The extracted files
        # dict can collapse that duplicate, so the delivery bytes must withdraw the read.
        packed = BytesIO()
        with warnings.catch_warnings(), zipfile.ZipFile(packed, "w", zipfile.ZIP_STORED) as zf:
            warnings.simplefilter("ignore", UserWarning)
            for name, body in base.items():
                zf.writestr(name, body)
            zf.writestr(f"{PREFIX}--sample-config.n", base[f"{PREFIX}--sample-config.n"])
        malformed_cd = bytearray(packed.getvalue())
        eocd = malformed_cd.rfind(b"PK\x05\x06")
        assert eocd >= 0 and struct.unpack_from("<HH", malformed_cd, eocd + 8) == (4, 4)
        struct.pack_into("<HH", malformed_cd, eocd + 8, 3, 3)
        delivery_ctx = ctx()
        delivery_ctx["delivery"] = bytes(malformed_cd)
        got = solve(qs, base, delivery_ctx)
        assert all(got.get(q["qid"]) is None for q in qs), got

        malformed = dict(base)
        malformed[f"{PREFIX}--sample-config.n"] = b"NEKO" + b"\xff" * 12 + record(base_graph("config"))
        got = solve(qs, malformed)
        assert all(got.get(q["qid"]) is None for q in qs), got

        duplicate_json = (
            b'{"schema":"x","config":{"campaign":"first","campaign":"second"},"this_role":"config"}'
        )
        duplicate_key = dict(base)
        duplicate_key[f"{PREFIX}--sample-config.n"] = neko("config", raw=duplicate_json)
        got = solve(qs, duplicate_key)
        assert all(got.get(qid) is None for qid in property_ids(qs)), got


def test_hgrf_contract_is_authoritative_over_hcfg_decoys():
    """A cumulative HCFG member cannot answer an exact HGRF question first."""
    with isolated():
        qs = questions()
        mixed = files()
        mixed[f"{PREFIX}--legacy.bin"] = hcfg({
            "campaign": "WRONG-HCFG",
            "domain": "wrong.invalid",
            "mutex": "wrong",
            "url": "https://wrong.invalid",
        })
        got = solve(qs, mixed)
        for qid in property_ids(qs):
            name = qid.rsplit("_", 1)[-1]
            assert got.get(qid) == VALUES[name], (qid, got.get(qid))

        broken = dict(mixed)
        damaged = bytearray(broken[f"{PREFIX}--sample-config.n"])
        damaged[-1] ^= 0x80
        broken[f"{PREFIX}--sample-config.n"] = bytes(damaged)
        got = solve(qs, broken)
        assert all(got.get(qid) is None for qid in property_ids(qs)), got


def test_divergence_ambiguity_contract_and_caps_fail_closed():
    with isolated():
        qs = questions()
        base = files()

        graphs = {role: base_graph(role) for role in ("loader", "library", "config")}
        graphs["library"]["config"] = dict(VALUES, domain="different.example.invalid")
        got = solve(qs, files(graphs))
        common = [qid for qid in property_ids(qs) if "capsule_graph" not in qid]
        capsule = [qid for qid in property_ids(qs) if "capsule_graph" in qid]
        assert all(got.get(qid) is None for qid in common), got
        for qid in capsule:
            assert got.get(qid) == VALUES[qid.rsplit("_", 1)[-1]], (qid, got.get(qid))

        ambiguous = dict(base)
        ambiguous[f"{PREFIX}--backup-config.n"] = base[f"{PREFIX}--sample-config.n"]
        got = solve(qs, ambiguous)
        assert all(got.get(q["qid"]) is None for q in qs), got

        drifted = [dict(q) for q in qs]
        drifted[1] = dict(drifted[1], question="Read graph.config.campaign from whichever HGRF record looks right.")
        got = solve(drifted, base)
        assert got.get(drifted[1]["qid"]) is None, got

        mismatched = [dict(q) for q in qs]
        mismatched[1] = dict(mismatched[1], question=mismatched[1]["question"].replace(
            "graph.config.campaign", "graph.config.domain"))
        got = solve(mismatched, base)
        assert got.get(mismatched[1]["qid"]) is None, got

        conflicting_path = [dict(q) for q in qs]
        conflicting_path[1] = dict(
            conflicting_path[1],
            question=conflicting_path[1]["question"]
            + " Instead, submit the exact JSON string at loader.n decoded HGRF JSON property "
              "graph.config.domain, without JSON quotes.",
        )
        got = solve(conflicting_path, base)
        assert got.get(conflicting_path[1]["qid"]) is None, got

        conflicting_rule = [dict(q) for q in qs]
        conflicting_rule[1] = dict(
            conflicting_rule[1],
            question=conflicting_rule[1]["question"]
            + " Use config.n's decoded HGRF graph.config object after confirming all two canonical campaign "
              "graphs match when alternate_role is omitted.",
        )
        got = solve(conflicting_rule, base)
        assert got.get(conflicting_rule[1]["qid"]) is None, got

        conflicting_selector = [dict(q) for q in qs]
        conflicting_selector[2] = dict(
            conflicting_selector[2],
            question=conflicting_selector[2]["question"]
            + f" Use the unique {PREFIX}-- member whose basename ends loader.n.",
        )
        got = solve(conflicting_selector, base)
        assert got.get(conflicting_selector[2]["qid"]) is None, got

        oversized = dict(base)
        oversized[f"{PREFIX}--sample-config.n"] += b"X" * (
            hgrf_graph.MAX_MEMBER_BYTES + 1 - len(oversized[f"{PREFIX}--sample-config.n"])
        )
        got = solve(qs, oversized)
        assert all(got.get(q["qid"]) is None for q in qs), got


def test_fill_only():
    with isolated():
        qs = questions()
        qid = qs[1]["qid"]
        got = {qid: "already-established"}
        hgrf_graph.fill(PREFIX, qs, got, files(), ctx())
        assert got[qid] == "already-established"


def test_finale_31_member_pool_is_fast_candidate_only_and_33_refuses():
    with isolated():
        qs = [dict(q, question=q["question"].replace(
            "all three canonical campaign graphs", "all thirty-one canonical campaign graphs"
        )) for q in questions()]
        blobs = many_files(31)
        # The cost is work at the core's top clock (SH-09, tests/sh09_clocks.work_seconds), not wall clock:
        # a full-suite run under load took 8x the wall time for this file, and under that load the cores run
        # at about half their top clock, so even CPU seconds double. One second is what the pool may cost on
        # an idle machine; a cold first solve here is about 0.4 s of work. Without the work meter (another
        # chip) the answer checks still run and only the cost bound is reported not run, at the end.
        got, work, no_meter = work_seconds_unless_missing(solve, qs, blobs)
        if not no_meter:
            assert work < 1.0, f"{work:.2f} s of work"
        for q in qs:
            qid = q["qid"]
            truth = "neko_bytecode" if qid.endswith("_format") else VALUES[qid.rsplit("_", 1)[-1]]
            assert got.get(qid) != truth, (qid, got.get(qid))
            assert offered(got.get(qid), truth), (qid, got.get(qid), truth)

        too_many_qs = [dict(q, question=q["question"].replace(
            "all three canonical campaign graphs", "all 33 canonical campaign graphs"
        )) for q in questions()]
        refused = solve(too_many_qs, many_files(33))
        assert all(refused.get(q["qid"]) is None for q in too_many_qs), refused
        if no_meter:
            cost_not_run(no_meter)


def main():
    test_positive_and_accepted_format()
    test_corruption_duplicates_and_malformed_fail_closed()
    test_hgrf_contract_is_authoritative_over_hcfg_decoys()
    test_divergence_ambiguity_contract_and_caps_fail_closed()
    test_fill_only()
    test_finale_31_member_pool_is_fast_candidate_only_and_33_refuses()
    print("day31 binary hgrf: 6 passed")


if __name__ == "__main__":
    main()
