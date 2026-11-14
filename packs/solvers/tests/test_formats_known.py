"""B-087: the known-format fingerprint DB (ctf/formats/known.py, known.toml) and its place in the
B-207 format_fingerprint step, the B-013 sweep and `ctf formats`.

Every member is built here from invented bytes (a seeded generator stands in for ciphertext); no
challenge file is read. The tables under test are the shipped one and small ones written by the test.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import random

import pytest

from ctf import event
from ctf.formats import fingerprint as F
from ctf.formats import known as K


# ---------------------------------------------------------------- helpers

def profile(slug="b087-test"):
    return event.parse({
        "slug": slug, "name": "b087 test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": "https://board.b087.example"},
        "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": []},
    }, src="<test>")


def noise(n, seed=87):
    r = random.Random(seed)
    return bytes(r.randrange(256) for _ in range(n))


def keystore(records=60, prefix=None, extra=0):
    """The key-store geometry: prefix[10] | salt[16] | header[128] + records x 36 | tag[20], all noise."""
    body = noise(16 + 128 + 36 * records + 20 + extra)
    return (prefix if prefix is not None else noise(10, seed=3)) + body


def storage_file(content=b"cover art bytes " * 40, magic=b"\xab\x33\x72\x61"):
    """content | one 4-byte checksum word | the 64-byte trailer (checksum, magic, size, id, type, ff.., 0..)."""
    trailer = (noise(4, 5) + magic + len(content).to_bytes(4, "little") + noise(20, 6)
               + (1).to_bytes(4, "little") + b"\xff\xff\xff\xff" + bytes(24))
    assert len(trailer) == 64
    return content + noise(4, 7) + trailer


def fp_of(name, data):
    return F.fingerprint(name, data)


def entry(table, id_):
    return next(k for k in table if k.id == id_)


SHIPPED = K.load()

GOOD = '''
[[format]]
id = "demo"
label = "Demo record file"
reference = "the demo spec"
basis = "invented for the test"
names = ["demo.dat"]
ascii = ["DEMO"]
entropy_min = 6.5
magic = [{ at = 0, hex = "44454d4f" }]
geometry = { header = 8, record = 12, trailer = 4 }
require = ["magic", "geometry"]
support = ["names", "ascii", "entropy"]
min_support = 1
'''


def write(tmp_path, text):
    p = tmp_path / "known.toml"
    p.write_text(text, encoding="utf-8")
    return p


# ---------------------------------------------------------------- the loader

def test_shipped_table_loads_with_its_entries_and_references():
    ids = [k.id for k in SHIPPED]
    assert len(ids) == len(set(ids))
    assert {"spotify-offline-keystore", "spotify-storage-file", "mozlz4", "android-backup",
            "leveldb-table"} <= set(ids)
    for k in SHIPPED:
        assert k.reference and k.basis and k.label, k.id
        assert set(k.require) | set(k.support) == set(k.signals), k.id
        assert set(k.require) & set(K.CONTENT_SIGNALS), k.id


def test_shipped_keystore_entry_is_the_documented_geometry():
    k = entry(SHIPPED, "spotify-offline-keystore")
    assert (k.geometry.header, k.geometry.record, k.geometry.trailer) == (154, 36, 20)
    assert k.require == ("geometry", "entropy") and set(k.support) == {"names", "ascii"}
    assert k.min_support == 1
    assert "secondfloor" in k.reference


def test_shipped_table_holds_no_key_material_or_procedure_fields():
    # The table names a format and its public reference; it is not a decryption recipe. An entry has
    # exactly the documented keys (the loader refuses any other), and none of them is a key or a step list.
    assert not ({"key", "keys", "iv", "steps", "recipe", "kdf"} & K._KEYS)
    text = K.KNOWN_TABLE.read_text(encoding="utf-8").lower()
    for word in ("pbkdf2", "aes-", "hmac-sha", "iterations"):
        assert word not in text, f"the known-format table spells out a procedure ({word})"


def test_good_table_parses_every_field(tmp_path):
    (k,) = K.load(write(tmp_path, GOOD))
    assert k.id == "demo" and k.reference == "the demo spec" and k.basis == "invented for the test"
    assert k.magic == (K.Sig(0, b"DEMO"),)
    assert k.geometry == K.Geometry(8, 12, 4, 1)
    assert k.ascii == ("DEMO",) and k.names == ("demo.dat",) and k.entropy_min == 6.5
    assert k.require == ("magic", "geometry") and k.support == ("ascii", "names", "entropy")
    assert k.signals == ("magic", "ascii", "names", "geometry", "entropy")


def test_require_defaults_to_every_declared_signal(tmp_path):
    text = GOOD.replace('require = ["magic", "geometry"]\n', "").replace(
        'support = ["names", "ascii", "entropy"]\n', "").replace("min_support = 1\n", "")
    (k,) = K.load(write(tmp_path, text))
    assert k.require == ("magic", "ascii", "names", "geometry", "entropy") and k.support == ()


BAD = [
    ("unknown key", GOOD + 'steps = ["do this"]\n', "unknown keys"),
    ("missing reference", GOOD.replace('reference = "the demo spec"\n', ""), "missing 'reference'"),
    ("empty basis", GOOD.replace('basis = "invented for the test"', 'basis = " "'), "basis must be a non-empty"),
    ("bad id", GOOD.replace('id = "demo"', 'id = "Demo File"'), "lower-case slug"),
    ("bad hex", GOOD.replace('hex = "44454d4f"', 'hex = "44454d4"'), "even-length hex"),
    ("hex too long", GOOD.replace('hex = "44454d4f"', 'hex = "' + "00" * 17 + '"'), "must be 1..16"),
    ("magic unknown key", GOOD.replace("at = 0,", "at = 0, mask = 1,"), "unknown keys ['mask']"),
    ("end offset too close", GOOD.replace("at = 0,", "at = -3,"), "leaves no room"),
    ("record of one", GOOD.replace("record = 12", "record = 1"), "record must be >= 2"),
    ("geometry unknown key", GOOD.replace("trailer = 4", "trailer = 4, pad = 2"), "unknown keys ['pad']"),
    ("geometry without record", GOOD.replace("record = 12, ", ""), "missing 'record'"),
    ("entropy out of range", GOOD.replace("entropy_min = 6.5", "entropy_min = 8.5"), "(0, 8]"),
    ("short ascii token", GOOD.replace('ascii = ["DEMO"]', 'ascii = ["DE"]'), "at least 4"),
    ("undeclared signal", GOOD.replace('names = ["demo.dat"]\n', ""), "declares no such signal"),
    ("unknown signal name", GOOD.replace('"names", "ascii", "entropy"]', '"names", "ascii", "entropy", "crc"]'),
     "signals are"),
    ("signal in both lists", GOOD.replace('require = ["magic", "geometry"]', 'require = ["magic", "geometry", "names"]'),
     "both require and support"),
    ("declared but unused", GOOD.replace('support = ["names", "ascii", "entropy"]', 'support = ["names", "ascii"]'),
     "neither require nor support"),
    ("min_support too large", GOOD.replace("min_support = 1", "min_support = 4"), "exceeds"),
    ("no content signal required", GOOD.replace('require = ["magic", "geometry"]', 'require = ["names", "entropy"]')
     .replace('support = ["names", "ascii", "entropy"]', 'support = ["magic", "geometry", "ascii"]'),
     "must hold a content signal"),
    ("geometry alone", GOOD.replace('require = ["magic", "geometry"]', 'require = ["geometry"]')
     .replace('support = ["names", "ascii", "entropy"]', 'support = ["magic", "names", "ascii", "entropy"]')
     .replace("min_support = 1", "min_support = 0"), "coincidence"),
    ("duplicate id", GOOD + GOOD, "id listed twice"),
    ("wrong top level", 'title = "x"\n' + GOOD, "nothing else"),
    ("empty table", "format = []\n", "non-empty list"),
    ("not toml", "[[format]\n", "not TOML"),
]


@pytest.mark.parametrize("text,needle", [(t, n) for _l, t, n in BAD], ids=[label for label, _t, _n in BAD])
def test_a_bad_table_is_refused_naming_the_fault(tmp_path, text, needle):
    with pytest.raises(K.KnownError) as e:
        K.load(write(tmp_path, text))
    assert needle in str(e.value)
    assert "known.toml" in str(e.value)


def test_a_missing_table_is_an_error_not_an_empty_table(tmp_path):
    with pytest.raises(K.KnownError, match="is not there"):
        K.load(tmp_path / "nope.toml")


# ---------------------------------------------------------------- matching: the record geometry entry

KEYSTORE = entry(SHIPPED, "spotify-offline-keystore")


def test_keystore_matches_on_geometry_entropy_and_its_name():
    data = keystore(records=60)
    reasons = K.match(KEYSTORE, fp_of("cache/offline2", data), data)
    assert reasons is not None
    assert f"size {len(data)} = 154 + 60 x 36 + 20" in reasons
    assert any(r.startswith("entropy") for r in reasons)
    assert "name matches 'offline2'" in reasons


def test_keystore_matches_on_the_header_tag_under_another_name():
    data = keystore(records=60, prefix=b"XX-OFFL2!!")
    reasons = K.match(KEYSTORE, fp_of("blob.bin", data), data)
    assert reasons is not None and "header ascii 'OFFL2'" in reasons
    assert not any(r.startswith("name") for r in reasons)


def test_keystore_geometry_alone_is_not_a_lead():
    # Right size, ciphertext body, but neither the name nor the tag: one file in 36 has this size.
    data = keystore(records=60)
    assert K.match(KEYSTORE, fp_of("blob.bin", data), data) is None


@pytest.mark.parametrize("extra", [1, 17, 35])
def test_keystore_refuses_a_size_that_is_not_whole_records(extra):
    data = keystore(records=60, extra=extra)
    assert K.match(KEYSTORE, fp_of("offline2", data), data) is None


def test_keystore_refuses_a_file_with_no_record():
    data = noise(154 + 20)                      # header and trailer only: zero records
    assert K.match(KEYSTORE, fp_of("offline2", data), data) is None


def test_keystore_refuses_a_low_entropy_body():
    data = bytes(154 + 36 * 60 + 20)            # right size and name, but zeros are not ciphertext
    assert K.match(KEYSTORE, fp_of("offline2", data), data) is None


def test_more_signals_score_higher_and_rank_first():
    both = keystore(records=60, prefix=b"XX-OFFL2!!")
    (c_both,) = K.lookup(fp_of("offline2", both), both, (KEYSTORE,))
    one = keystore(records=60)
    (c_one,) = K.lookup(fp_of("offline2", one), one, (KEYSTORE,))
    assert c_both.score == K.BASE_SCORE + 4 * K.SIGNAL_SCORE
    assert c_one.score == K.BASE_SCORE + 3 * K.SIGNAL_SCORE
    assert c_both.score > c_one.score


def test_lookup_candidate_carries_the_reference_the_id_and_the_reasons():
    data = keystore(records=3)
    (c,) = K.lookup(fp_of("offline2", data), data, SHIPPED)
    assert c.source == "known" and c.ref == "spotify-offline-keystore"
    assert c.tool == KEYSTORE.reference and c.label == KEYSTORE.label
    assert "154 + 3 x 36 + 20" in c.why and KEYSTORE.note in c.why


# ---------------------------------------------------------------- matching: signatures from the end

STORAGE = entry(SHIPPED, "spotify-storage-file")


def test_storage_file_matches_on_its_trailer_whatever_the_name():
    data = storage_file()
    reasons = K.match(STORAGE, fp_of("8e/8ece30.file", data), data)
    assert reasons is not None and "ab337261 at -60" in reasons[0] and "name matches '*.file'" in reasons
    assert K.match(STORAGE, fp_of("renamed.bin", data), data) is not None


def test_storage_file_trailer_must_match_every_signature():
    wrong_magic = storage_file(magic=b"\xab\x33\x72\x62")
    assert K.match(STORAGE, fp_of("x.file", wrong_magic), wrong_magic) is None
    data = bytearray(storage_file())
    data[-1] = 1                                 # the zero tail is part of the trailer
    assert K.match(STORAGE, fp_of("x.file", bytes(data)), bytes(data)) is None
    data = bytearray(storage_file())
    data[-28] = 0                                # the ffffffff word
    assert K.match(STORAGE, fp_of("x.file", bytes(data)), bytes(data)) is None


def test_a_member_shorter_than_an_end_offset_is_no_match_and_no_error():
    data = b"\xab\x33\x72\x61" + bytes(8)        # 12 bytes: the -60 offset is before the start
    assert K.match(STORAGE, fp_of("x.file", data), data) is None
    assert K.lookup(fp_of("x.file", b""), b"", SHIPPED) == []


@pytest.mark.parametrize("name,data,want", [
    ("sessionstore.jsonlz4", b"mozLz40\x00" + (500).to_bytes(4, "little") + noise(300), "mozlz4"),
    ("phone.ab", b"ANDROID BACKUP\n5\n1\nnone\n" + noise(300), "android-backup"),
    ("000005.ldb", noise(400) + bytes.fromhex("57fb808b247547db"), "leveldb-table"),
])
def test_public_formats_are_named(name, data, want):
    leads = K.lookup(fp_of(name, data), data, SHIPPED)
    assert [c.ref for c in leads] == [want]
    assert leads[0].tool == entry(SHIPPED, want).reference


def test_leveldb_magic_elsewhere_in_the_file_is_not_the_footer():
    data = bytes.fromhex("57fb808b247547db") + noise(400)       # at the start, not the end
    assert K.lookup(fp_of("000005.ldb", data), data, SHIPPED) == []


def test_name_globs_ignore_case_and_folders(tmp_path):
    (k,) = K.load(write(tmp_path, GOOD))
    data = b"DEMO" + bytes(4) + bytes(12 * 5) + bytes(4)
    assert "name matches 'demo.dat'" in K.match(k, fp_of("Cache\\sub/DEMO.DAT", data), data)
    # the name does not hold, but the ascii tag satisfies min_support
    reasons = K.match(k, fp_of("other.bin", data), data)
    assert reasons is not None and not any(r.startswith("name") for r in reasons)


def test_lookup_puts_the_entry_with_more_signals_first_and_breaks_ties_by_id(tmp_path):
    one = '''
[[format]]
id = "{id}"
label = "{id} label"
reference = "ref"
basis = "invented for the test"
magic = [{{ at = 0, hex = "44454d4f" }}]
'''
    strong = one.format(id="z-strong") + 'names = ["*.dat"]\nascii = ["DEMO"]\n'
    table = K.load(write(tmp_path, one.format(id="b-weak") + strong + one.format(id="a-weak")))
    data = b"DEMO" + bytes(60)
    leads = K.lookup(fp_of("x.dat", data), data, table)
    assert [c.ref for c in leads] == ["z-strong", "a-weak", "b-weak"]
    assert [c.score for c in leads] == [K.BASE_SCORE + 3 * K.SIGNAL_SCORE] + [K.BASE_SCORE + K.SIGNAL_SCORE] * 2


def test_geometry_needs_min_records_whole_records(tmp_path):
    (k,) = K.load(write(tmp_path, GOOD.replace("trailer = 4 }", "trailer = 4, min_records = 2 }")))
    def demo(records, extra=0):
        return b"DEMO" + bytes(4) + bytes(12 * records + extra) + bytes(4)
    assert K.match(k, fp_of("demo.dat", demo(2)), demo(2)) is not None      # exactly the minimum
    assert K.match(k, fp_of("demo.dat", demo(1)), demo(1)) is None          # one short
    assert K.match(k, fp_of("demo.dat", demo(3, extra=5)), demo(3, extra=5)) is None
    reasons = K.match(k, fp_of("demo.dat", demo(7)), demo(7))
    assert "size 96 = 8 + 7 x 12 + 4" in reasons


# ---------------------------------------------------------------- inside the format_fingerprint step

def test_analyze_reports_the_known_format_with_the_shipped_tables():
    data = keystore(records=40)
    res = F.analyze("offline2", data)
    assert [c.ref for c in res.candidates if c.source == "known"] == ["spotify-offline-keystore"]


def test_analyze_ranks_a_known_format_above_a_bare_magic_hit():
    # gzip's two-byte magic at the start, the LevelDB footer at the end: the composite match is the better lead.
    data = b"\x1f\x8b" + noise(300) + bytes.fromhex("57fb808b247547db")
    res = F.analyze("000007.ldb", data)
    sources = [c.source for c in res.candidates]
    assert sources[0] == "known" and "magic" in sources
    assert res.candidates[0].ref == "leveldb-table"


def test_analyze_with_an_empty_known_table_does_no_known_lookup():
    data = keystore(records=40)
    res = F.analyze("offline2", data, known=())
    assert [c for c in res.candidates if c.source == "known"] == []


def test_analyze_fails_loudly_on_a_broken_shipped_table(tmp_path, monkeypatch):
    monkeypatch.setattr(K, "KNOWN_TABLE", write(tmp_path, GOOD + "oops = 1\n"))
    with pytest.raises(K.KnownError, match="unknown keys"):
        F.analyze("offline2", keystore(records=40))


def test_to_result_gives_the_lead_as_unsure_evidence_naming_the_reference():
    data = keystore(records=40)
    r = F.analyze("offline2", data).to_result()
    assert r.status == "unsure" and r.flags == ()
    match = [e.detail for e in r.evidence if e.kind == "match"]
    assert any("Spotify offline cache key store" in d and "secondfloor" in d for d in match)


# ---------------------------------------------------------------- the sweep

def test_sweep_writes_the_known_format_lead_and_a_note(tmp_path):
    from ctf import sweep
    src = tmp_path / "drop"
    (src / "Storage").mkdir(parents=True)
    (src / "offline2").write_bytes(keystore(records=80, prefix=b"XX-OFFL2!!"))
    (src / "Storage" / "aa11.file").write_bytes(storage_file())
    rep = sweep.sweep(src, profile(), out=tmp_path / "scratch")
    doc = json.loads((tmp_path / "scratch" / ".sweep.json").read_text())
    refs = {c["ref"] for row in doc["fingerprint"] for c in row["candidates"] if c["source"] == "known"}
    assert refs == {"spotify-offline-keystore", "spotify-storage-file"}
    assert any("format_fingerprint" in n and "Spotify offline cache key store" in n and "secondfloor" in n
               for n in rep.notes)


def test_sweep_names_a_broken_known_table_and_goes_on(tmp_path, monkeypatch):
    from ctf import sweep
    monkeypatch.setattr(K, "KNOWN_TABLE", tmp_path / "gone.toml")
    src = tmp_path / "drop"
    src.mkdir()
    (src / "offline2").write_bytes(keystore(records=80))
    rep = sweep.sweep(src, profile(), out=tmp_path / "scratch")
    assert rep.extra.get("fingerprint") == []
    assert any("format_fingerprint not run: KnownError" in n for n in rep.notes)


# ---------------------------------------------------------------- the CLI

def _args(**kw):
    base = {"action": "fingerprint", "catalog": None, "files": [], "online": False, "event": None, "json": False}
    base.update(kw)
    return argparse.Namespace(**base)


def test_cli_fingerprint_prints_the_known_lead_and_its_reference(tmp_path, capsys):
    from ctf.cli import formats as cli
    p = tmp_path / "offline2"
    p.write_bytes(keystore(records=50))
    assert cli.run(_args(files=[p])) == 0
    out = capsys.readouterr().out
    assert "likely Spotify offline cache key store" in out and "secondfloor" in out
    assert "[spotify-offline-keystore]" in out and "<known, score" in out


def test_cli_fingerprint_json_marks_the_source(tmp_path, capsys):
    from ctf.cli import formats as cli
    p = tmp_path / "places.ldb"
    p.write_bytes(noise(200) + bytes.fromhex("57fb808b247547db"))
    assert cli.run(_args(files=[p], json=True)) == 0
    doc = json.loads(capsys.readouterr().out)
    assert [(c["source"], c["ref"]) for c in doc[0]["candidates"]] == [("known", "leveldb-table")]


def test_cli_fingerprint_exits_2_on_a_broken_known_table(tmp_path, capsys, monkeypatch):
    from ctf.cli import formats as cli
    monkeypatch.setattr(K, "KNOWN_TABLE", write(tmp_path, GOOD + "oops = 1\n"))
    p = tmp_path / "offline2"
    p.write_bytes(keystore(records=50))
    assert cli.run(_args(files=[p])) == 2
    assert "unknown keys" in capsys.readouterr().err


def test_cli_known_lists_every_entry_with_its_reference(capsys):
    from ctf.cli import formats as cli
    assert cli.run(_args(action="known")) == 0
    out = capsys.readouterr().out
    for k in SHIPPED:
        assert f"{k.id}: {k.label}" in out and k.reference in out
    assert "matches on: geometry, entropy; plus 1 of ascii, names" in out


def test_cli_known_json_round_trips_the_signals(capsys):
    from ctf.cli import formats as cli
    assert cli.run(_args(action="known", json=True)) == 0
    doc = {row["id"]: row for row in json.loads(capsys.readouterr().out)}
    assert doc["spotify-offline-keystore"]["geometry"] == {"header": 154, "record": 36, "trailer": 20,
                                                          "min_records": 1}
    assert doc["leveldb-table"]["magic"] == [{"at": -8, "hex": "57fb808b247547db"}]
    assert doc["mozlz4"]["require"] == ["magic"] and doc["mozlz4"]["support"] == ["names"]


def test_cli_known_exits_2_on_a_broken_table(tmp_path, capsys, monkeypatch):
    from ctf.cli import formats as cli
    monkeypatch.setattr(K, "KNOWN_TABLE", tmp_path / "gone.toml")
    assert cli.run(_args(action="known")) == 2
    assert "is not there" in capsys.readouterr().err
