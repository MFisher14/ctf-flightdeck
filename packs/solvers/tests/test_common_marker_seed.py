"""B-119: the convention seed the repo ships (solvers/toolkits/seeds/marker/conventions.json).

The seed is the knowledge base's starting point: the three marker shapes CSCTF 2026 used, kept as
conventions over role names with no challenge value. These tests read the shipped file through the
labels seed store, with an empty runtime ledger, and reproduce each shape on synthetic values: the
expected markers are computed here with hashlib from literal preimages. A seed entry that names a
join, digest form or rendering the engine does not have fails here, not at an event.
"""
from __future__ import annotations

import hashlib
import json

import pytest

import labels
import marker_convention as mc
import render_candidates as RC
from ctf import event, paths

SEED = paths.repo_root() / "solvers" / "toolkits" / "seeds" / "marker" / "conventions.json"
BUDGET = 20_000

CASES = {
    "ics": (lambda: [mc.make_field("seed", 911), mc.make_field("register", 30007),
                     mc.make_field("timestamp", "2031-02-03T04:05:06Z"), mc.make_field("station", "0x7B1C"),
                     mc.make_field("header", "ZQX7", "tag")],
            "0x5A515837:0x7B1C:2031-02-03T04:05:06Z:30007:911", 8),
    "networking": (lambda: [mc.make_field("epoch", 1893456789),
                            mc.make_field("session_id", "hss.example.test;1893456789;40404"),
                            mc.make_field("imsi", "901700000012345")],
                   "901700000012345:hss.example.test;1893456789;40404:1893456789", 8),
    "forensics": (lambda: [mc.make_field("distance", 612.3478), mc.make_field("delta_lon", 0.0052),
                           mc.make_field("delta_lat", 0.0011), mc.make_field("approved_lon", "65.4321"),
                           mc.make_field("approved_lat", "12.3456")],
                  "12.345665.43210.0011000.005200612.3", 16),
}


@pytest.fixture(autouse=True)
def _shipped_seed(tmp_path, monkeypatch):
    for name in ("CTF_JUDGE_LEDGER", "CTF_LEDGER_MASK", "CTF_FAMILY_PRIOR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))       # an empty runtime ledger
    labels._cache.clear()
    yield
    labels._cache.clear()


def test_the_seed_is_where_the_labels_store_reads_it():
    assert labels.seed_path(mc.KB_LANE) == SEED and SEED.is_file()


def test_every_seed_entry_names_things_the_engine_has():
    seed = json.loads(SEED.read_text(encoding="utf-8"))
    sample = {"tag": mc.make_field("x", "ABCD", "tag"), "hexid": mc.make_field("x", "0x1F"),
              "integer": mc.make_field("x", 77), "timestamp": mc.make_field("x", "2031-02-03T04:05:06Z"),
              "decimal": mc.make_field("x", 1.25), "text": mc.make_field("x", "word")}
    axes = set()
    for key, entry in seed.items():
        lane, _, rest = key.partition(".")
        axis, _, shape = rest.partition("/")
        axes.add(axis)
        names = entry.get("accepted_names") or [entry["accepted"]]
        assert lane == "marker" and names[0] == entry["accepted"] and entry["rejected"] == [] and not entry["split"]
        assert entry["evidence"] and all("seed" in e for e in entry["evidence"]), key
        for name in names:
            if axis == "convention":
                assert key.endswith(labels.CANDIDATE_MARK) and mc.Convention.parse(name).name == name
            elif axis == "join":
                assert name in dict(RC.JOINS)
            elif axis == "digest":
                assert mc.DigestForm.parse(name).name == name
            else:
                kind = shape.split(".")[0]
                assert axis == "render" and name != "as_stored" and name in mc.render_table(sample[kind]), key
    assert axes == {"convention", "join", "digest", "render"}


@pytest.mark.parametrize("family", sorted(CASES))
def test_a_seeded_convention_answers_its_shape_on_new_values(family):
    make, text, cut = CASES[family]
    marker = hashlib.sha256(text.encode()).hexdigest()[:cut]
    kb = mc.KB()
    (name,) = kb.accepted(family)
    assert mc.Convention.parse(name).preimage(make()) == text
    rep = mc.search(make(), family=family, budget=BUDGET)          # the fields are given in another order
    first = rep.candidates[0]
    assert (first.basis, first.marker, first.preimage, first.convention) == ("kb", marker, text, name)
    assert rep.supported and mc.pick(rep) == ([marker], None)


def test_a_brief_that_states_another_cut_is_not_answered_with_the_seeded_one(tmp_path):
    """The shipped networking convention was accepted as sha256[:8]. A brief of that family that states
    16 hex must get 16-hex candidates only, the seeded fields and order first, and no `candidate`."""
    make, text, _ = CASES["networking"]
    base = tmp_path / "case"
    base.mkdir()
    brief = ("The marker is the SHA-256 of the joined values, cut to the first 16 lower-case hex, as "
             "CSCTF{16_lowercase_hex}.")
    (base / "challenge.json").write_text(json.dumps({"description": brief, "category": "Network"}), encoding="utf-8")
    specs = [f"{f.name}={f.stored}" for f in make()]
    res = mc.solve(base, event.load("csctf"), fields=specs, budget=BUDGET)
    full = hashlib.sha256(text.encode()).hexdigest()
    assert res.status == "unsure" and res.flags[0] == "CSCTF{" + full[:16] + "}"
    assert len(res.flags) > 1 and all(len(f) == len("CSCTF{}") + 16 for f in res.flags)
    assert "kb-recut" in res.evidence[0].detail and "family networking" in res.notes
    eight = brief.replace("16", "8")                                    # the cut the judge accepted: as before
    (base / "challenge.json").write_text(json.dumps({"description": eight, "category": "Network"}), encoding="utf-8")
    res = mc.solve(base, event.load("csctf"), fields=specs, budget=BUDGET)
    assert (res.status, res.flags) == ("candidate", ("CSCTF{" + full[:8] + "}",))


def test_the_seed_orders_the_axes_for_every_family():
    kb = mc.KB()
    assert kb.available and kb.families() == ["ics", "networking", "forensics"]
    assert kb.joins() == ["colon", "none"] and kb.digests() == ["sha256[:8]", "sha256[:16]"]
    assert kb.renders("tag") == ["hex_0x_upper"] and kb.renders("decimal") == ["dp_6", "dp_1"]
    assert kb.renders("timestamp") == kb.renders("hexid") == kb.renders("integer") == kb.renders("text") == []


def test_the_seed_puts_the_missed_rendering_first_in_a_family_it_has_never_seen(tmp_path, monkeypatch):
    fields = [mc.make_field("header", "KLM2", "tag"), mc.make_field("station", "0x19AF"),
              mc.make_field("timestamp", "2032-06-07T08:09:10Z"), mc.make_field("register", 41000),
              mc.make_field("seed", 5)]
    truth = hashlib.sha256(b"0x4B4C4D32:0x19AF:2032-06-07T08:09:10Z:41000:5").hexdigest()[:8]
    seeded = mc.search(fields, [mc.DigestForm.parse("sha256[:8]")], family="energy", budget=BUDGET)
    assert seeded.candidates[0].marker == truth and seeded.candidates[0].basis == "prior"
    monkeypatch.setattr(labels, "seed_path", lambda lane: tmp_path / f"{lane}.json")     # no seed at all
    labels._cache.clear()
    bare = mc.search(fields, [mc.DigestForm.parse("sha256[:8]")], family="energy", budget=BUDGET)
    assert truth not in [c.marker for c in bare.candidates]
