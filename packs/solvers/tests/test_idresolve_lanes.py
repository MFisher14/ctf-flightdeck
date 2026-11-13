"""B-010 end to end: renamed question ids reach the lanes' real readers, and nothing else does.

Binary: the Day 1 timed shape (slot<N>_<field>) through solvers/binary/id_conventions.toml and the lane's
own evidence.solve_set, on synthetic ELF64 headers built here. The lane alone answers none of these ids
(the contract mismatch); through the resolver each slot is answered from its own member.

Metadata: the stem-target rule (Huntress improvements row 103) that the master's properties_strict keeps:
a variant that renames the delivered file (roster.csv instead of evidence-note.txt) is answered by stem,
and zero or two files with the id's stem answer nothing.
"""
from __future__ import annotations

import hashlib
import json
import struct

import pytest

from ctf import idresolve as ir
from ctf import paths

BINARY_CONV = paths.repo_root() / "solvers" / "binary" / "id_conventions.toml"


def elf64(entry: int, tail: bytes) -> bytes:
    """A bare ELF64 little-endian x86-64 ET_EXEC header with `tail` after it (no sections)."""
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    return ident + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, entry, 0, 0, 0, 64, 0, 0, 0, 0, 0) + tail


def value_of(answer):
    """A plain answer as it is; an unsure one ("??{json}", the lane's probe form) as its options' values."""
    if isinstance(answer, str) and answer.startswith("??"):
        return [o[1] for o in json.loads(answer[2:])["o"]]
    return [answer]


def ask(qid):
    return {"qid": qid, "id": qid, "question": f"What is {qid} of the sample?",
            "answer_format": {"kind": "exact_text", "syntax": "exact artifact-derived value only"}}


@pytest.mark.needs_tool("py:elftools", "py:capstone")
def test_binary_slot_ids_reach_d01_through_the_resolver(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    import evidence
    files = {"slot-0.elf": elf64(0x401040, b"slot zero body"), "m-slot-1.elf": elf64(0x401230, b"slot one body")}
    ids = ["slot0_sha256", "slot1_sha256", "slot0_entry_point", "slot1_entry_point", "slot0_elf_class",
           "slot3_sha256", "slot0_bogus_field"]

    direct = evidence.solve_set([ask(i) for i in ids], dict(files), {})
    assert all(direct.get(i) is None for i in ids), direct          # the mismatch this item closes

    logs = []
    solver = ir.ResolvingSolver.from_conventions(BINARY_CONV, evidence.solve_set, log=logs.append)
    ctx = {}
    got = solver.solve_set([ask(i) for i in ids], dict(files), ctx)
    # Each answer is the lane's own (plain, or unsure when its form guard has not seen the wording), and
    # read from that slot's member only.
    assert value_of(got["slot0_sha256"]) == [hashlib.sha256(files["slot-0.elf"]).hexdigest()]
    assert value_of(got["slot1_sha256"]) == [hashlib.sha256(files["m-slot-1.elf"]).hexdigest()]
    assert value_of(got["slot0_entry_point"]) == ["0x401040"]
    assert value_of(got["slot1_entry_point"]) == ["0x401230"]
    assert "ELF64" in value_of(got["slot0_elf_class"])
    assert got["slot3_sha256"] is None                    # no member for slot 3
    assert got["slot0_bogus_field"] is None               # no reader: fail closed
    assert ctx["id_resolution"]["counts"] == {"exact": 0, "mapped": 6, "unmatched": 1, "ambiguous": 0}
    assert any("slot3_sha256" in m and "no delivered member" in m for m in logs)
    assert solver.covers([ask("slot0_bogus_field")]) != [] and solver.covers([ask("slot2_marker")]) == []


def meta_q(qid, text):
    return {"qid": qid, "id": qid, "answer_id": qid, "question": text, "artifact": "evidence.zip",
            "answer_format": {"kind": "exact_text", "syntax": "exact artifact-derived value only"}}


@pytest.fixture
def metadata(monkeypatch, tmp_path):
    (tmp_path / "_ledger").mkdir()
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setenv("CTF_EVENT", "huntress")
    import properties_strict
    return properties_strict


def test_metadata_renamed_variant_is_answered_by_stem(metadata):
    roster, note = b"id,name\n1,ann\n2,bo\n", b"evidence note\n"
    files = {"roster.csv": roster, "evidence-note.txt": note}
    qs = [meta_q("roster-filename", "What is the exact filename of the roster?"),
          meta_q("roster-sha256", "What is the SHA-256 digest of the roster?"),
          meta_q("roster-size-bytes", "What is the size in bytes of the roster?"),
          meta_q("evidence-note-md5", "What is the MD5 digest of the evidence note?"),
          meta_q("ghost-filename", "What is the exact filename of the ghost?")]
    got = metadata.solve_set(qs, files, {"delivery_name": "evidence.zip"})
    assert got["roster-filename"] == "roster.csv"
    assert got["roster-sha256"] == hashlib.sha256(roster).hexdigest()
    assert got["roster-size-bytes"] == str(len(roster))
    assert got["evidence-note-md5"] == hashlib.md5(note).hexdigest()
    assert got["ghost-filename"] is None


def test_metadata_two_files_with_the_stem_answer_nothing(metadata):
    files = {"evidence-note.txt": b"a", "evidence-note.md": b"b"}
    got = metadata.solve_set([meta_q("evidence-note-filename", "What is the exact filename of the evidence note?")],
                             files, {"delivery_name": "evidence.zip"})
    assert got["evidence-note-filename"] is None
