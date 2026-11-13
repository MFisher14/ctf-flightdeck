"""B-160: the shipped opcode table held to the shipped reference-pair manifest, and the real-pair oracle.

Always on: the manifest is valid and every pair in it is pinned; the shipped table loads; every
entry of the shipped table cites a pair the manifest pins; and a shipped table that has entries is
PROVEN on the corpus, in a test that fails, never skips, when the corpus is absent
(test_a_shipped_table_with_entries_fails_without_its_proof). A pin row alone is not an oracle: an
entry plus a manifest row with invented digests would satisfy the citation check on any machine, so
a table with entries needs $CTF_REALDATA/plc/ wherever the suite runs. While the table is empty that
test has nothing to prove and needs no corpus.

needs_realdata("plc"): each pinned pair is read from $CTF_REALDATA/plc/<id>/, its digests checked,
and the table proven on it (ot_plc_code.verify_table). The oracle reports NOT RUN with the reason,
never a pass, while nothing can be proven: when no pair is pinned, and when pairs are pinned and
the table is still empty ("pinned, unused": the pairs were read and are usable, and no entry reads
them yet). So pairs can be pinned first (B-160-F1) and entries added later (B-160-F2). The states
are tested below on a synthetic pair.
"""
import hashlib
import json

import pytest

import ot_plc_code as engine
from ctf import paths

MANIFEST = engine.pairs_manifest_path()


def shipped_manifest():
    return json.loads(MANIFEST.read_text())


def test_the_manifest_the_engine_names_exists_and_is_valid():
    # beside the opcode table, not under tests/: the engine reads it at run time
    assert MANIFEST == paths.repo_root() / "solvers" / "toolkits" / "ot_plc_code_pairs.json" and MANIFEST.is_file()
    assert MANIFEST == paths.repo_root() / engine.PAIRS_MANIFEST and MANIFEST.parent == engine.TABLE_PATH.parent
    assert not (paths.repo_root() / "tests" / "real" / "manifest_plc.json").exists()      # one copy only
    manifest = shipped_manifest()
    rows = engine.parse_pairs(manifest)                    # raises on a malformed or unpinned pair
    assert len(rows) == len(manifest["pairs"])
    # the survey B-160 asked for is recorded with its result, and an idea is never listed as a pair
    assert manifest["survey"]["question"] and manifest["survey"]["result"]
    pinned = {row["id"] for row in rows}
    for candidate in manifest["candidates"]:
        assert candidate["id"] not in pinned and candidate["blocker"].strip()
        assert "sample_sha256" not in candidate and "listing_sha256" not in candidate


def test_the_shipped_table_loads_and_every_entry_cites_a_pinned_pair():
    table = engine.load_table("mc7")
    assert table.family == "mc7" and table.source == str(engine.TABLE_PATH)
    rows = engine.parse_pairs(shipped_manifest())
    assert engine.citation_problems(table, rows) == []
    cited = {entry.oracle[0] for entry in table.entries}
    assert cited <= {row["id"] for row in rows}
    assert len(table.entries) <= engine.MAX_ENTRIES


def test_a_shipped_table_with_entries_fails_without_its_proof():
    # Not marked needs_realdata on purpose: with entries in the table and no corpus on this machine
    # this FAILS, so a table with entries cannot merge on a pin row alone. An empty table has
    # nothing to prove (ot_plc_code.unproven_reasons; its rules are tested on a toy table in
    # tests/test_ot_plc_code.py).
    table = engine.read_table("mc7")
    rows = engine.parse_pairs(shipped_manifest())
    reasons = engine.unproven_reasons(table, rows, paths.realdata_root() / "plc")
    assert reasons == [], "the shipped opcode table is not proven:\n" + "\n".join(reasons)


def test_the_shipped_table_file_says_why_codesys_has_no_family():
    shipped = json.loads(engine.TABLE_PATH.read_text())
    assert sorted(shipped["families"]) == sorted(engine.FAMILIES)
    assert "codesys" in shipped["untabled"] and "codesys" not in engine.FAMILIES


def test_what_b160_could_not_build_stays_on_the_build_plan():
    # the standing rule: every gap goes on the list with its blocker, not only into a build log
    plan = (paths.repo_root() / "BUILD-PLAN.md").read_text(encoding="utf-8")
    _, _, tail = plan.partition("# Follow-ups found during the build")
    section = tail.split("\n# ")[0]
    for follow_up, names in (("B-160-F1", engine.PAIRS_MANIFEST), ("B-160-F2", "--verify-pairs"),
                             ("B-160-F3", "CODESYS")):
        items = [line for line in plan.splitlines() if line.startswith(f"- `{follow_up}` ")]
        assert len(items) == 1, f"BUILD-PLAN.md must list follow-up {follow_up} exactly once"
        assert items[0] in section, f"{follow_up} sits outside the follow-up section"
        assert "dep:B-160" in items[0] and names in items[0]
    # F1 can be done on its own: the plan says a pair may be pinned before an entry reads it
    first = next(line for line in plan.splitlines() if line.startswith("- `B-160-F1` "))
    assert "pinned, unused" in first


def prove(table, rows, corpus):
    """The real-pair oracle. Returns when the table is proven on the pinned pairs; skips (NOT RUN)
    with the reason while nothing can be proven; fails on a pair that is missing, changed, unusable
    or contradicted, and on a table with entries that is not proven."""
    if not rows:
        pytest.skip(f"no reference pair is pinned in {engine.PAIRS_MANIFEST}: nothing to prove "
                    "(the B-160 blocker)")
    result = engine.verify_table(table, engine.load_pairs(rows, corpus))      # raises on a bad pair
    failed = {name: outcome["reason"] for name, outcome in result["pairs"].items()
              if not outcome["ok"] and not outcome["unused"]}
    assert not failed, json.dumps(failed, indent=2, sort_keys=True)
    if not table.entries:
        pytest.skip(f"{len(result['unused_pairs'])} pair(s) pinned, unused: the opcode table is empty, so "
                    "nothing is proven (B-160-F2 adds the entries)")
    assert result["ok"], json.dumps(result, indent=2, sort_keys=True)
    return result


@pytest.mark.needs_realdata("plc")
def test_the_shipped_table_is_proven_on_the_real_pairs():
    prove(engine.load_table("mc7"), engine.parse_pairs(shipped_manifest()), paths.realdata_root() / "plc")


# ---- the oracle's states, on a synthetic pair (toy bytes: not MC7, and never the shipped table) ----

SAMPLE, LISTING = bytes.fromhex("15032004"), b"A I 3.5\n= Q 4.0\n"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def toy_table(*entries):
    return engine.parse_table({"schema": "plc-opcodes-1", "families": {"mc7": {"entries": list(entries)}}},
                              "mc7", "toy")


def toy_entry(name, first, stl, pair="toy-pair"):
    return {"id": name, "match": first, "mask": "f8", "length": 2, "stl": stl,
            "operands": [{"name": "bit", "bit": 5, "width": 3, "format": "dec"},
                         {"name": "byte", "bit": 8, "width": 8, "format": "dec"}],
            "oracle": {"pair": pair, "sample_sha256": digest(SAMPLE), "listing_sha256": digest(LISTING)}}


AND = toy_entry("toy.and", "10", "A I {byte}.{bit}")
OUT = toy_entry("toy.out", "20", "= Q {byte}.{bit}")


def pinned(tmp_path, listing=LISTING):
    """One pair pinned and present under a corpus folder, as B-160-F1 leaves it."""
    folder = tmp_path / "plc" / "toy-pair"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "code.bin").write_bytes(SAMPLE)
    (folder / "code.awl").write_bytes(listing)
    rows = engine.parse_pairs({"schema": "plc-pairs-1", "pairs": [{
        "id": "toy-pair", "family": "mc7", "kind": "mc7-code", "sample": "code.bin",
        "sample_sha256": digest(SAMPLE), "listing": "code.awl", "listing_sha256": digest(listing),
        "source": "built in the test", "licence": "synthetic"}]})
    return rows, tmp_path / "plc"


def test_the_oracle_is_not_run_when_no_pair_is_pinned(tmp_path):
    with pytest.raises(pytest.skip.Exception, match="no reference pair is pinned in solvers/toolkits/"):
        prove(toy_table(), [], tmp_path)


def test_a_pair_pinned_before_any_entry_is_pinned_unused_and_not_run(tmp_path):
    # B-160-F1 done on its own: the pair is pinned and present, the table is still empty
    rows, corpus = pinned(tmp_path)
    with pytest.raises(pytest.skip.Exception, match=r"1 pair\(s\) pinned, unused: the opcode table is empty"):
        prove(toy_table(), rows, corpus)
    # the pair is still held to its pin, and it has to be usable as a pair
    (corpus / "toy-pair" / "code.awl").write_bytes(LISTING + b"// edited\n")
    with pytest.raises(engine.PlcCodeError, match="listing code.awl does not have the pinned sha256"):
        prove(toy_table(), rows, corpus)
    (corpus / "toy-pair" / "code.bin").unlink()
    with pytest.raises(engine.PlcCodeError, match="pair toy-pair: sample not readable"):
        prove(toy_table(), rows, corpus)
    rows, corpus = pinned(tmp_path, listing=b"// no statement\n")
    with pytest.raises(engine.PlcCodeError, match="the listing holds no statements"):
        prove(toy_table(), rows, corpus)


def test_the_oracle_passes_only_when_every_entry_is_proven_on_its_pair(tmp_path):
    rows, corpus = pinned(tmp_path)
    assert prove(toy_table(AND, OUT), rows, corpus)["ok"] is True
    # an entry that reads only part of the pair it cites: failed, neither skipped nor 'unused'
    with pytest.raises(AssertionError, match="incomplete: offset 2"):
        prove(toy_table(AND), rows, corpus)
    # entries that cite another pair, while this pair contradicts one of them
    wrong = toy_table(toy_entry("toy.and", "10", "A I {byte}.{bit}", pair="elsewhere"),
                      toy_entry("toy.out", "20", "S Q {byte}.{bit}", pair="elsewhere"))
    with pytest.raises(AssertionError, match="a decoded statement differs from the listing"):
        prove(wrong, rows, corpus)
    # an entry that agrees with an unused pair and is proven on none: the table has entries, so it fails
    with pytest.raises(AssertionError, match="unproven_entries"):
        prove(toy_table(toy_entry("toy.and", "10", "A I {byte}.{bit}", pair="elsewhere")), rows, corpus)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
