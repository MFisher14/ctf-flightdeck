"""Synthetic EKANS profiles: published IOCs, PE-format fixtures, no malware.

Oracle sources are Dragos Appendix A and VMware/Trend Micro's published
markers. PE fixtures are independently serialized below and checked by pefile.
No fixture calls an engine encoder or copies the engine's indicator table.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import struct

import pefile
import pytest

import ot_ekans_profile as target


def synthetic_pe(payload=b"runtime.main\0runtime.morestack\0runtime.goexit\0", *, bits=64):
    """Microsoft PE layout: one inert initialized-data section at file 0x200.

    It contains no executable code and is never run. Header values/offsets are
    written independently with struct; pefile supplies a separate parser.
    """
    optional_size = 240 if bits == 64 else 224
    result = bytearray(0x200)
    result[:2] = b"MZ"
    struct.pack_into("<I", result, 0x3c, 0x80)
    result[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", result, 0x84, 0x8664 if bits == 64 else 0x14c,
                     1, 0, 0, 0, optional_size, 0x0022)
    opt = 0x98
    struct.pack_into("<H", result, opt, 0x20b if bits == 64 else 0x10b)
    struct.pack_into("<II", result, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", result, opt + 56, 0x2000, 0x200)
    struct.pack_into("<H", result, opt + 68, 3)
    struct.pack_into("<I", result, opt + (108 if bits == 64 else 92), 16)
    table = opt + optional_size
    result[table:table + 8] = b".rdata\0\0"
    raw_size = (len(payload) + 511) // 512 * 512
    struct.pack_into("<IIIIIIHHI", result, table + 8, len(payload), 0x1000,
                     raw_size, 0x200, 0, 0, 0, 0, 0x40000040)
    return bytes(result) + payload + bytes(raw_size - len(payload))


@pytest.mark.parametrize("bits", [32, 64])
def test_pe_framing_against_pefile(bits):
    raw = synthetic_pe(bits=bits)
    with pefile.PE(data=raw, fast_load=True) as oracle:
        expected_machine = oracle.FILE_HEADER.Machine
        assert oracle.sections[0].PointerToRawData == 512
        assert oracle.sections[0].get_data().startswith(b"runtime.main\0")
    result = target.pe_go_evidence(raw)
    assert result["machine"] == expected_machine
    assert result["pe_offset"] == 128
    assert result["symbols"] == {"runtime.main": 512, "runtime.morestack": 525, "runtime.goexit": 543}
    profile = target.analyze_bytes(raw)
    assert profile["score"] == 2 and profile["matched"] is False


def test_documented_full_profile_and_group_scores():
    # Dragos: these two processes, mutex, Go. VMware: note and 5-letter suffix.
    raw = synthetic_pe(b"runtime.main\0runtime.morestack\0hdb.exe\0proficyserver.exe\0")
    result = target.analyze({"inert.exe": raw, "C:\\Users\\Analyst\\Desktop\\Fix-Your-Files.txt": b"synthetic note"},
                            mutexes=["Global\\EKANS"],
                            renames=[("plant.csv", "plant.csvAbCdE")])
    assert result["category_scores"] == {"identity": 4, "ransom_note": 3, "ics_processes": 3,
                                          "go_pe": 2, "renaming": 1}
    assert result["score"] == 13 and result["matched"] is True
    assert result["ics_processes"] == ["hdb.exe", "proficyserver.exe"]
    assert result["artifacts"][0]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["compatible_renames"] == [{"before": "plant.csv", "after": "plant.csvAbCdE", "suffix": "AbCdE"}]
    kinds = {entry["kind"] for entry in result["evidence"]}
    assert {"artifact_string", "supplied_mutex_observation", "pe_section_runtime_strings"} <= kinds


@pytest.mark.parametrize("encoding", ["ascii", "utf-16-le"])
def test_literal_ioc_profile_encoding_and_offsets(encoding):
    text = "cover\0Global\\EKANS\0Fix-Your-Files.txt\0hdb.exe\0ccflic0.exe\0"
    raw = text.encode(encoding)
    result = target.analyze_bytes(raw)
    assert result["matched"] is True and result["score"] == 10
    mutex = next(x for x in result["evidence"] if x["indicator"] == "Global\\EKANS")
    assert mutex["kind"] == "artifact_string"
    assert mutex["encoding"] == encoding
    assert mutex["offset"] == len("cover\0".encode(encoding))


@pytest.mark.parametrize("name,data", [
    ("EKANS.exe", b""), ("SNAKE.exe", b""), ("Fix-Your-Files.txt", b""),
    ("article.txt", b"EKANS ransomware also called SNAKE"),
    ("inventory.txt", b"hdb.exe\0proficyserver.exe\0ccflic0.exe"),
    ("marker.bin", b"EKANS"),
])
def test_single_names_or_process_inventory_never_make_a_verdict(name, data):
    result = target.analyze_bytes(data, name=name)
    assert result["matched"] is False
    assert result["score"] <= 3


def test_terminal_marker_and_mutex_string_never_double_count():
    raw = b"Global\\EKANS"
    result = target.analyze_bytes(raw)
    assert result["score"] == 4
    assert result["category_scores"]["identity"] == 4
    assert result["matched"] is False
    assert {x["kind"] for x in result["evidence"]} == {"artifact_string", "terminal_bytes"}
    assert target.analyze_bytes(b"EKANS\0")["score"] == 0


def test_repeated_indicators_do_not_inflate_score():
    result = target.analyze_bytes(b"hdb.exe\0" * 100, processes=["HDB.EXE"] * 100,
                                 mutexes=["EKANS"] * 100)
    assert result["score"] == 5 and result["matched"] is False
    assert result["ics_processes"] == ["hdb.exe"]


def test_token_boundaries_avoid_lookalike_names():
    for encoding in ("ascii", "utf-16-le"):
        raw = "prefixhdb.exe hdb.exe.bak fakeGlobal\\EKANSsuffix NotFix-Your-Files.txt".encode(encoding)
        assert target.analyze_bytes(raw)["score"] == 0


@pytest.mark.parametrize("before,after,expected", [
    ("report.txt", "report.txtQwErT", 1), ("report.txt", "report.txtABCDE", 1),
    ("report.txt", "report.txt12345", 0), ("report.txt", "report.txtABCDEF", 0),
    ("report.txt", "other.txtABCDE", 0), ("report", "reportABCDE", 0),
])
def test_rename_shape_only_with_explicit_pair(before, after, expected):
    result = target.analyze({}, renames=[(before, after)])
    assert result["score"] == expected and result["matched"] is False
    assert any("not proof of randomness" in line for line in result["limitations"])


def test_weak_groups_cannot_cross_threshold_without_corroboration():
    raw = synthetic_pe(b"runtime.main\0runtime.morestack\0hdb.exe\0proficyclient.exe\0")
    result = target.analyze_bytes(raw, renames=[("r.csv", "r.csvabcde")])
    assert result["score"] == 6 and result["matched"] is False
    assert target.analyze_bytes(raw, mutexes=["EKANS"])["matched"] is True


def test_truncated_invalid_pe_and_overlay_runtime_strings_decline():
    raw = synthetic_pe()
    for end in (0, 2, 63, 64, 128, 152, 300, 511, 512, len(raw) - 1):
        assert target.pe_go_evidence(raw[:end]) is None
    assert target.pe_go_evidence(synthetic_pe(b"inert") + b"runtime.main\0runtime.morestack\0") is None
    for offset, replacement in ((0x3c, b"\xff" * 4), (0x86, b"\xff\xff"),
                                (0x98, b"\xff\xff"), (0x98 + 240 + 20, b"\xff" * 4)):
        changed = bytearray(raw)
        changed[offset:offset + len(replacement)] = replacement
        assert target.pe_go_evidence(changed) is None


def test_deterministic_fuzz_never_leaks_stdlib_exceptions():
    rng = random.Random(0xECA2026)
    corpus = [b"", b"\xff" * 1024]
    for length in (1, 2, 3, 8, 31, 63, 64, 127, 255, 511):
        corpus.extend((rng.randbytes(length), b"MZ" + rng.randbytes(length)))
    valid = synthetic_pe()
    corpus.extend(valid[:end] for end in range(0, len(valid), 19))
    for position in rng.sample(range(len(valid)), 24):
        changed = bytearray(valid)
        changed[position] ^= 1 << (position % 8)
        corpus.append(bytes(changed))
    for raw in corpus:
        assert isinstance(target.analyze_bytes(raw), dict)
        result = target.pe_go_evidence(raw)
        assert result is None or isinstance(result, dict)


@pytest.mark.parametrize("bad", [None, 1, "text", {}, [], memoryview(b"x")])
def test_wrong_byte_types_raise_only_declared_error(bad):
    for reader in (target.analyze_bytes, target.pe_go_evidence):
        with pytest.raises(target.EkansError):
            reader(bad)


@pytest.mark.parametrize("kwargs", [
    {"mutexes": "EKANS"}, {"processes": [None]}, {"processes": ["\ud800"]},
    {"renames": [None]}, {"renames": [("one",)]}, {"renames": [("one", 2)]},
    {"mutexes": ["EKANS\0"]},
])
def test_wrong_context_types_raise_declared_error(kwargs):
    with pytest.raises(target.EkansError):
        target.analyze({}, **kwargs)


def test_resource_bounds(monkeypatch):
    monkeypatch.setattr(target, "MAX_ARTIFACT", 10)
    monkeypatch.setattr(target, "MAX_TOTAL", 15)
    monkeypatch.setattr(target, "MAX_ARTIFACTS", 2)
    for artifacts in ({"a": bytes(11)}, {"a": bytes(10), "b": bytes(6)}, {"a": b"", "b": b"", "c": b""}):
        with pytest.raises(target.EkansError):
            target.analyze(artifacts)
    with pytest.raises(target.EkansError):
        target.analyze({}, mutexes=["EKANS"] * 1025)


def test_cli_guard_and_json(tmp_path, capsys):
    assert target.main(["--help"]) == 0
    assert target.main([]) == 2
    assert target.main(["--unknown"]) == 2
    assert target.main([str(tmp_path / "missing")]) == 2
    assert target.main([str(tmp_path)]) == 2
    capsys.readouterr()
    path = tmp_path / "indicators.txt"
    path.write_bytes(b"hdb.exe\0proficyserver.exe\0Fix-Your-Files.txt\0")
    assert target.main([str(path), "--mutex", "EKANS"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["matched"] is True and result["score"] == 10


def test_cli_noninteger_systemexit_is_normalized(monkeypatch):
    def stop(*args, **kwargs):
        raise SystemExit("argument error")
    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", stop)
    assert target.main([]) == 2


def test_cli_stops_reading_at_aggregate_budget(monkeypatch, capsys):
    read_names = []

    def read(name):
        read_names.append(name)
        return b"abc"

    monkeypatch.setattr(target, "_read_file", read)
    monkeypatch.setattr(target, "MAX_TOTAL", 5)
    assert target.main(["first", "second", "third"]) == 2
    assert read_names == ["first", "second"]
    assert "combined artifacts" in capsys.readouterr().err
    read_names.clear()
    # Duplicate paths retain the previous mapping semantics and use one slot.
    assert target.main(["first", "first"]) == 0
    assert len(json.loads(capsys.readouterr().out)["artifacts"]) == 1


@pytest.mark.parametrize("argv", [1, "input.bin", [None], [1], {}])
def test_cli_invalid_argv_returns_usage_error(argv):
    assert target.main(argv) == 2
