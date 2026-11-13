"""B-119: what the constructed-marker fallback reads from a handout, and the engine end to end.

The handout is built here: a JSON event log, an XML configuration, a binary with an ASCII magic, a
key/value text file and a brief, all synthetic, describing one made-up incident. The tests check which
values are found, which evidence corroborates each, what is refused (a witness tag as an input, a
document type declaration, an unpacked copy counted twice, an archive counted as a second source for
its own member, a number inside a longer number, a dot-directory), the in-file witness, and that the
engine entry, the route and the manifest hold together. The knowledge base is empty (a temp seed and
workdir).
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import zipfile

import pytest

import labels
import marker_convention as mc
from ctf import event, paths, sweep
from ctf.engines import manifest, router

TRUTH = "0x5A515837:0x7B1C:2031-02-03T04:05:06Z:30007:911"     # header:station:timestamp:register:seed
DIGEST = hashlib.sha256(TRUTH.encode()).hexdigest()
BRIEF = ("Substation 0x7B1C went dark overnight. Work out what happened from the values two or more "
         "files share, then hand in the resulting marker.\n\nFlag format: **`CSCTF{8_lowercase_hex}`**")


@pytest.fixture(autouse=True)
def _empty_kb(tmp_path, monkeypatch):
    for name in ("CTF_JUDGE_LEDGER", "CTF_LEDGER_MASK", "CTF_FAMILY_PRIOR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    monkeypatch.setattr(labels, "seed_path", lambda lane: seeds / f"{lane}.json")
    labels._cache.clear()
    yield
    labels._cache.clear()


@pytest.fixture
def prof():
    return event.load("csctf")


def handout(tmp_path, *, tag=True, brief=BRIEF):
    """A pulled challenge folder: challenge.json, notes.md and files/."""
    base = tmp_path / "4242-grid-incident"
    files = base / "files"
    files.mkdir(parents=True)
    log = {"station": "0x7B1C", "manifest_seed": 911,
           "events": [{"ts": "2031-02-03T04:05:06Z", "level": "CRITICAL", "register": 30007},
                      {"ts": "2031-02-03T04:07:00Z", "level": "INFO", "register": 30008}]}
    if tag:
        log["tag"] = DIGEST[-8:]
    (files / "event_log.json").write_text(json.dumps(log, indent=1), encoding="utf-8")
    (files / "hmi_config.xml").write_text(
        '<Config><Station id="0x7B1C" name="North-4"/><Firmware header="ZQX7"/><Seed>911</Seed>'
        "<Routine>calibration</Routine></Config>", encoding="utf-8")
    (files / "firmware.bin").write_bytes(b"ZQX7" + bytes(range(0, 64)))
    (files / "override.dat").write_text(
        "register = 30007\nfirst_critical: 2031-02-03T04:05:06Z\nnote: threshold raised\n", encoding="utf-8")
    (files / "audio.bin").write_bytes(b"RIFF" + bytes(40))
    (base / "challenge.json").write_text(json.dumps({"description": brief, "category": "ICS"}), encoding="utf-8")
    (base / "notes.md").write_text("station: 0xDEAD\n", encoding="utf-8")      # the workspace's own file
    return base


def by_name(fields):
    return {f.name: f for f in fields}


# ------------------------------------------------------------------------------------- the files

def test_a_pulled_folder_is_read_from_files_and_unpacked_only(tmp_path):
    base = handout(tmp_path)
    docs, notes = mc.load_handout(base)
    assert [rel for rel, _ in docs] == ["files/audio.bin", "files/event_log.json", "files/firmware.bin",
                                        "files/hmi_config.xml", "files/override.dat"]
    assert notes == [] and dict(docs)["files/firmware.bin"][:4] == b"ZQX7"


def test_a_bare_folder_is_read_without_the_workspace_files_dot_files_and_links(tmp_path):
    base = tmp_path / "bare"
    (base / "sub").mkdir(parents=True)
    (base / "recon").mkdir()
    for rel in ("b.json", "sub/a.txt", "challenge.json", "notes.md", "tried.json", "flag.txt", ".hidden",
                "recon/out.txt"):
        (base / rel).write_text("x=" + rel, encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("seed=911", encoding="utf-8")
    os.symlink(outside, base / "link.txt")                      # a link out of the folder is never followed
    docs, notes = mc.load_handout(base)
    assert [rel for rel, _ in docs] == ["b.json", "sub/a.txt"] and notes == []


def _tree(base, rels, text='{"seed": 911}'):
    for rel in rels:
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text(text, encoding="utf-8")
    return base


def test_a_dot_directory_is_never_entered(tmp_path):
    """`.ctf/` holds an event's credentials and `.git/` is not evidence: in a bare folder the dot rule
    is the only thing between this engine and those files."""
    bare = _tree(tmp_path / "bare", ["a.json", ".ctf/session.json", ".git/config", "sub/.cache/b.json", "sub/c.json"])
    assert [rel for rel, _ in mc.load_handout(bare)[0]] == ["a.json"]      # sub/c.json has a.json's bytes
    (bare / "sub" / "c.json").write_text('{"seed": 911, "n": 1}', encoding="utf-8")
    docs, notes = mc.load_handout(bare)
    assert [rel for rel, _ in docs] == ["a.json", "sub/c.json"] and notes == []
    assert by_name(mc.extract_fields(bare)[0])["seed"].sources == ("a.json", "sub/c.json")
    pulled = _tree(tmp_path / "pulled", ["files/a.json", "files/.ctf/token.json", "unpacked/.hidden/b.json"])
    assert [rel for rel, _ in mc.load_handout(pulled)[0]] == ["files/a.json"]


def test_the_workspace_files_are_skipped_at_the_top_of_a_bare_folder_only(tmp_path):
    bare = tmp_path / "bare"
    for i, rel in enumerate(["notes.md", "sub/notes.md", "sub/flag.txt", "sub/challenge.json"]):
        _tree(bare, [rel], f"n = {i}")
    assert [rel for rel, _ in mc.load_handout(bare)[0]] == ["sub/challenge.json", "sub/flag.txt", "sub/notes.md"]
    pulled = tmp_path / "pulled"                                # a handout may ship a file named notes.md
    for i, rel in enumerate(["notes.md", "files/notes.md", "files/flag.txt", "unpacked/tried.json"]):
        _tree(pulled, [rel], f"n = {i}")
    assert [rel for rel, _ in mc.load_handout(pulled)[0]] == ["files/flag.txt", "files/notes.md",
                                                             "unpacked/tried.json"]


def test_an_unpacked_copy_of_a_file_is_counted_once(tmp_path):
    base = handout(tmp_path)
    (base / "unpacked").mkdir()
    (base / "unpacked" / "event_log.json").write_bytes((base / "files" / "event_log.json").read_bytes())
    docs, notes = mc.load_handout(base)
    assert "unpacked/event_log.json" not in [rel for rel, _ in docs]
    assert notes == ["1 file(s) with the same bytes as an earlier file were counted once"]
    fields, _ = mc.extract_fields(docs, BRIEF)
    assert by_name(fields)["ts_2"].sources == ("files/event_log.json",)        # still held by one file


def test_every_cut_of_the_handout_is_named(tmp_path, monkeypatch):
    base = handout(tmp_path)
    monkeypatch.setattr(mc, "MAX_READ", 16)
    docs, notes = mc.load_handout(base)
    assert all(len(data) <= 16 for _, data in docs)
    assert "files/event_log.json: only the first 16 bytes were read" in notes
    monkeypatch.setattr(mc, "MAX_READ", 4 << 20)
    monkeypatch.setattr(mc, "MAX_TOTAL", 50)
    docs, notes = mc.load_handout(base)
    assert [rel for rel, _ in docs] == ["files/audio.bin", "files/event_log.json"]
    assert any("3 file(s) from files/firmware.bin on were not read" in n for n in notes)
    monkeypatch.setattr(mc, "MAX_FILES", 2)
    assert any("3 file(s) past the first 2 were not read" in n for n in mc.load_handout(base)[1])


# ------------------------------------------------------------------------------------- the fields

def test_named_values_are_found_with_the_evidence_that_holds_each(tmp_path):
    fields, notes = mc.extract_fields(handout(tmp_path), BRIEF)
    got = by_name(fields)
    assert (got["station"].kind, got["station"].stored) == ("hexid", "0x7B1C")
    assert got["station"].sources == ("files/event_log.json", "files/hmi_config.xml", "brief")
    assert (got["manifest_seed"].kind, got["manifest_seed"].value) == ("integer", 911)
    assert got["manifest_seed"].sources == ("files/event_log.json", "files/hmi_config.xml")
    assert (got["ts"].kind, got["ts"].stored) == ("timestamp", "2031-02-03T04:05:06Z")
    assert got["ts"].sources == ("files/event_log.json", "files/override.dat")
    assert got["register"].sources == ("files/event_log.json", "files/override.dat")
    magic = got["firmware_magic"]                               # the binary's ASCII magic, named in the XML too
    assert (magic.kind, magic.stored, magic.sources) == ("tag", "ZQX7", ("files/firmware.bin", "files/hmi_config.xml"))
    # most corroborated first, then the order the files give
    assert [f.name for f in fields[:5]] == ["station", "manifest_seed", "ts", "register", "firmware_magic"]
    once = {f.name: f.stored for f in fields[5:]}
    assert all(len(f.sources) == 1 for f in fields[5:])
    assert once["ts_2"] == "2031-02-03T04:07:00Z" and once["register_2"] == "30008" and once["name"] == "North-4"
    assert notes == []


def test_a_tag_for_the_digest_is_a_witness_not_an_input(tmp_path):
    base = handout(tmp_path)
    fields, _ = mc.extract_fields(base, BRIEF)
    assert "tag" not in by_name(fields) and DIGEST[-8:] not in [f.stored for f in fields]
    assert mc.find_witnesses(base) == ([mc.Witness(DIGEST[-8:], "edge", "files/event_log.json:tag")], [])
    assert mc.find_witnesses(handout(tmp_path / "plain", tag=False)) == ([], [])


def test_a_witness_label_is_read_from_text_and_from_inside_a_binary(tmp_path):
    base = tmp_path / "w"
    base.mkdir()
    (base / "flight.bin").write_bytes(b"FLGT\x00\x01\x00\x03" + b"TAG:9f3c21aa" + b"\x00\x7f")
    (base / "notes.txt").write_text("checksum = 0011223344556677\nMarker: 9F3C21AA\nport: 12345678\n"
                                    "retag:deadbeef00\n", encoding="utf-8")
    got, notes = mc.find_witnesses(base)
    assert [(w.token, w.source) for w in got] == [("9f3c21aa", "flight.bin:tag"),
                                                  ("0011223344556677", "notes.txt:checksum")]
    assert notes == []


def _hash_log(base, tokens):
    (base / "files" / "audit.log").write_text("".join(f"hash={t}\n" for t in tokens), encoding="utf-8")


def test_tags_past_the_cap_are_not_compared_and_the_cut_is_named(tmp_path, prof):
    """A log of hashes is not forty checks on the marker. The first MAX_FILE_WITNESSES tags are
    compared, the cut is named, and a hit's strength counts every tag it was compared beside."""
    noise = [hashlib.sha256(b"audit line %d" % i).hexdigest()[:8] for i in range(40)]
    base = handout(tmp_path, tag=False)
    lines = noise[:10] + [DIGEST[-8:]] + noise[10:]                     # the real tag is the 11th of 41
    _hash_log(base, lines + lines[:5])                                  # a tag repeated is one tag
    found, notes = mc.find_witnesses(base)
    assert mc.MAX_FILE_WITNESSES == 32
    assert [(w.token, w.where, w.source) for w in found] == [(t, "edge", "files/audit.log:hash") for t in lines[:32]]
    cut = (f"the files label 41 hex tags; only the first 32 are compared (the last one compared is {lines[31]}, "
           "files/audit.log:hash) and 9 are not: give the tag that checks the marker as a witness (witness=HEX, "
           "--witness HEX)")
    assert notes == [cut]
    report, _, _ = mc.run(base, prof, budget=60_000)
    first = report.candidates[0]
    assert len(report.witnesses) == 32 and report.witness_hits == 1 and cut in report.notes
    assert (first.basis, first.preimage) == ("witness", TRUTH)
    chance = report.enumerated * 2 * 32 / 16 ** 8                       # either end of the digest, 32 tags
    assert chance < mc.CHANCE_LIMIT
    assert first.detail.endswith(f"{chance:.2g} chance match(es) expected over {report.enumerated} texts and 32 tags")
    # exactly the cap: nothing is cut and nothing is said
    exact = handout(tmp_path / "exact", tag=False)
    _hash_log(exact, noise[:32])
    assert [len(x) for x in mc.find_witnesses(exact)] == [32, 0]
    # the real tag past the cut is not compared; given by the caller it is, beside the 32
    late = handout(tmp_path / "late", tag=False)
    _hash_log(late, noise + [DIGEST[-8:]])
    missed, _, notes = mc.run(late, prof, budget=60_000)
    assert missed.witness_hits == 0 and missed.candidates[0].basis == "prior"
    assert any("only the first 32 are compared" in n for n in notes)
    given, _, _ = mc.run(late, prof, budget=60_000, witness=DIGEST[-8:] + "@suffix")
    assert len(given.witnesses) == 33 and given.candidates[0].preimage == TRUTH
    assert given.candidates[0].detail.endswith("texts and 33 tags")


def test_a_value_that_does_not_read_as_its_shape_is_kept_as_text_and_named(tmp_path, monkeypatch):
    base = tmp_path / "t"
    base.mkdir()
    (base / "a.json").write_text(json.dumps({"logged": "2031-02-30T04:05:06Z", "closed": "2031-02-03T23:59:60Z",
                                             "---": "word", "opened": "2031-02-03T04:05:06Z"}), encoding="utf-8")
    (base / "b.txt").write_text("logged = 2031-02-30T04:05:06Z\n", encoding="utf-8")
    fields, notes = mc.extract_fields(base)
    got = by_name(fields)
    assert sorted(got) == ["closed", "logged", "opened"]
    assert (got["logged"].kind, got["logged"].stored, got["logged"].sources) == (
        "text", "2031-02-30T04:05:06Z", ("a.json", "b.txt"))            # no 30 February: still a value, held twice
    assert (got["closed"].kind, got["closed"].stored) == ("text", "2031-02-03T23:59:60Z")
    assert got["opened"].kind == "timestamp"
    assert notes == [
        "3 named value(s) kept as text: no rendering of the kind it is shaped like exists for it: "
        "a.json: logged=2031-02-30T04:05:06Z (shaped like a timestamp); "
        "a.json: closed=2031-02-03T23:59:60Z (shaped like a timestamp); "
        "b.txt: logged=2031-02-30T04:05:06Z (shaped like a timestamp)",
        "1 named value(s) not kept: a.json: field name '---' has no letter or digit"]
    monkeypatch.setattr(mc, "MAX_NOTED", 1)                             # a long list is counted, not printed
    _, notes = mc.extract_fields(base)
    assert notes[0].endswith("a.json: logged=2031-02-30T04:05:06Z (shaped like a timestamp); and 2 more")
    assert notes[1] == "1 named value(s) not kept: a.json: field name '---' has no letter or digit"


def test_timestamps_that_differ_below_the_second_are_two_values(tmp_path):
    base = tmp_path / "s"
    base.mkdir()
    docs = {"a.json": {"first_alarm": "2031-02-03T04:05:06.100Z"},
            "b.json": {"last_ack": "2031-02-03T04:05:06.900Z"},
            "c.json": {"seen": "2031-02-03T04:05:06.10Z"}}                      # .10 is .100
    for name, doc in docs.items():
        (base / name).write_text(json.dumps(doc), encoding="utf-8")
    fields, notes = mc.extract_fields(base)
    assert {f.name: (f.stored, f.sources) for f in fields} == {
        "first_alarm": ("2031-02-03T04:05:06.100Z", ("a.json", "c.json")),
        "last_ack": ("2031-02-03T04:05:06.900Z", ("b.json",))}
    assert notes == [] and all(f.kind == "timestamp" for f in fields)
    # The whole second, as ISO text and as epoch seconds, is one value of its own. Its spelling in
    # another file still corroborates each of the two above (it is one of their renderings); what it
    # does not do is make them one value.
    (base / "d.json").write_text(json.dumps({"whole": "2031-02-03T04:05:06Z"}), encoding="utf-8")
    (base / "e.json").write_text(json.dumps({"epoch": 1927857906}), encoding="utf-8")
    fields, notes = mc.extract_fields(base)
    assert {f.name: (f.stored, f.sources) for f in fields} == {
        "first_alarm": ("2031-02-03T04:05:06.100Z", ("a.json", "c.json", "d.json", "e.json")),
        "last_ack": ("2031-02-03T04:05:06.900Z", ("b.json", "d.json", "e.json")),
        "whole": ("2031-02-03T04:05:06Z", ("d.json", "e.json"))}
    assert notes == []


def test_a_common_container_magic_is_not_a_field(tmp_path):
    fields, _ = mc.extract_fields(handout(tmp_path), BRIEF)
    assert "audio_magic" not in by_name(fields) and "RIFF" not in [f.stored for f in fields]


def test_a_value_inside_a_longer_number_or_name_does_not_corroborate(tmp_path):
    base = tmp_path / "t"
    base.mkdir()
    (base / "a.json").write_text('{"seed": 911, "level": "critical", "port": 502}', encoding="utf-8")
    (base / "b.txt").write_text("count 19110 and 9112\nfirst_critical_event here\nlisten on :502;\n", encoding="utf-8")
    got = by_name(mc.extract_fields(base)[0])
    assert got["seed"].sources == ("a.json",) and got["level"].sources == ("a.json",)
    assert got["port"].sources == ("a.json", "b.txt")


def test_a_spelling_under_three_characters_corroborates_nothing(tmp_path):
    base = tmp_path / "n"
    base.mkdir()
    (base / "a.json").write_text('{"retries": 7, "zone": "B2", "unit": "kPa"}', encoding="utf-8")
    (base / "b.txt").write_text("wait 7 seconds in zone B2, reading in kPa\n", encoding="utf-8")
    got = by_name(mc.extract_fields(base)[0])
    assert got["retries"].sources == ("a.json",) and got["zone"].sources == ("a.json",)
    assert got["unit"].sources == ("a.json", "b.txt")
    # the same short value NAMED in a second file is corroborated: that is a statement, not a stray token
    (base / "c.txt").write_text("retries = 7\n", encoding="utf-8")
    assert by_name(mc.extract_fields(base)[0])["retries"].sources == ("a.json", "c.txt")


def test_a_string_longer_than_a_field_is_prose(tmp_path):
    base = tmp_path / "p"
    base.mkdir()
    longest, prose = "k" * mc.MAX_VALUE_LEN, "p" * (mc.MAX_VALUE_LEN + 1)
    (base / "a.json").write_text(json.dumps({"key": longest, "summary": prose}), encoding="utf-8")
    fields, _ = mc.extract_fields(base)
    assert [(f.name, f.stored) for f in fields] == [("key", longest)] and mc.MAX_VALUE_LEN == 96


def test_a_json_number_keeps_the_spelling_the_file_gave_it(tmp_path):
    base = tmp_path / "j"
    base.mkdir()
    (base / "a.json").write_text('{"approved_lat": 12.5000, "ratio": 2.5e1, "count": 40, "delta": -0.0010}',
                                 encoding="utf-8")
    (base / "b.txt").write_text("approved_lat = 12.5\n", encoding="utf-8")
    got = by_name(mc.extract_fields(base)[0])
    lat = got["approved_lat"]
    assert (lat.kind, lat.stored, lat.sources) == ("decimal", "12.5000", ("a.json", "b.txt"))
    assert mc.renderings(lat)[0] == ("as_stored", "12.5000") and dict(mc.renderings(lat))["dp_1"] == "12.5"
    assert (got["delta"].kind, got["delta"].stored) == ("decimal", "-0.0010")
    assert (got["ratio"].kind, got["ratio"].stored) == ("decimal", "25.0")      # an exponent form: read as a number
    assert (got["count"].kind, got["count"].value) == ("integer", 40)


def test_a_long_identifier_is_one_field_whether_a_file_gives_it_as_a_number_or_as_text(tmp_path):
    base = tmp_path / "i"
    base.mkdir()
    (base / "a.json").write_text('{"imsi": 901700000012345}', encoding="utf-8")
    (base / "b.txt").write_text("imsi: 901700000012345\n", encoding="utf-8")
    fields, _ = mc.extract_fields(base)
    assert [(f.name, f.kind, f.stored, f.sources) for f in fields] == [
        ("imsi", "text", "901700000012345", ("a.json", "b.txt"))]


def test_a_json_file_nested_too_deeply_is_noted_and_the_others_are_read(tmp_path, prof):
    base = tmp_path / "d"
    base.mkdir()
    (base / "a.json").write_text('{"seed": 911, "station": "0x7B1C"}', encoding="utf-8")
    (base / "b.xml").write_text('<c><Station id="0x7B1C"/></c>', encoding="utf-8")
    (base / "deep.json").write_text("[" * 200_000 + "\nseed = 911\n", encoding="utf-8")
    fields, notes = mc.extract_fields(base)
    got = by_name(fields)
    assert notes == ["deep.json: JSON nested too deeply to parse; read as key: value lines instead"]
    assert got["station"].sources == ("a.json", "b.xml")
    assert got["seed"].sources == ("a.json", "deep.json")       # its key: value lines are still read
    res = mc.solve(base, prof, budget=2000)
    assert res.status == "unsure" and "nested too deeply" in res.notes
    (base / "challenge.json").write_text("[" * 200_000, encoding="utf-8")
    assert mc.read_brief(base) == ("", "", ["challenge.json was not read (RecursionError)"])
    assert mc.solve(base, prof, budget=2000).status == "unsure"


def test_a_corroborated_value_of_a_repeated_name_is_kept_past_the_first_two(tmp_path):
    base = tmp_path / "k"
    base.mkdir()
    (base / "a.json").write_text(json.dumps({"rows": [{"reading": 100 + i} for i in range(5)]}), encoding="utf-8")
    (base / "b.txt").write_text("the operator wrote down 103 by hand\n", encoding="utf-8")
    fields, notes = mc.extract_fields(base)
    assert [(f.name, f.value, f.sources) for f in fields] == [
        ("reading_3", 103, ("a.json", "b.txt")), ("reading", 100, ("a.json",)), ("reading_2", 101, ("a.json",))]
    assert notes == ["2 uncorroborated value(s) of repeated names were not listed (the first 2 of each name are)"]


# ------------------------------------------------------------------------------------- containers

RECORD = json.dumps({"station": "0x7B1C", "seed": 911, "operator": "night-shift"}, indent=1).encode()


def _tar(members: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _zip(members: dict, method=zipfile.ZIP_STORED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


@pytest.mark.parametrize("name,pack", [("handout.tar", _tar), ("handout.zip", _zip)], ids=["tar", "stored-zip"])
def test_an_uncompressed_archive_is_not_a_second_source_for_its_member(tmp_path, prof, name, pack):
    base = tmp_path / "c"
    (base / "files").mkdir(parents=True)
    (base / "unpacked").mkdir()
    blob = pack({"record.json": RECORD})
    assert RECORD in blob                                       # the member's bytes sit in the archive as they are
    (base / "files" / name).write_bytes(blob)
    (base / "unpacked" / "record.json").write_bytes(RECORD)     # unpacked by hand: no <archive>.unpacked/ path
    fields, notes = mc.extract_fields(base)
    assert sorted((f.name, f.sources) for f in fields) == [
        ("operator", ("unpacked/record.json",)), ("seed", ("unpacked/record.json",)),
        ("station", ("unpacked/record.json",))]                 # and no `handout_magic` from the tar's first bytes
    assert notes == [f"files/{name}: holds unpacked/record.json (an archive or image beside what was unpacked "
                     "from it): not a second source, left out of the fields and the corroboration"]
    res = mc.solve(base, prof)
    assert res.status == "none" and not res.flags and "no named value is held by two evidence sources" in res.notes
    # a file that is a second source still counts, with the archive beside it
    (base / "files" / "shift.log").write_text("station 0x7B1C tripped; seed = 911\n", encoding="utf-8")
    got = by_name(mc.extract_fields(base)[0])
    assert got["station"].sources == ("unpacked/record.json", "files/shift.log")
    assert got["seed"].sources == ("unpacked/record.json", "files/shift.log")
    assert got["operator"].sources == ("unpacked/record.json",)


def test_an_archive_intake_unpacked_is_not_a_second_source_even_when_compressed(tmp_path):
    base = tmp_path / "z"
    member = json.dumps({"header": "ZQX7", "log": "trip " * 40}).encode()
    blob = _zip({"inner/ZQX7.json": member}, zipfile.ZIP_DEFLATED)
    assert member not in blob and b"ZQX7.json" in blob          # only the member's NAME is in the clear
    (base / "files").mkdir(parents=True)
    (base / "files" / "pack.zip").write_bytes(blob)
    inner = base / "unpacked" / ("pack.zip" + sweep.SUFFIX) / "inner"
    inner.mkdir(parents=True)
    (inner / "ZQX7.json").write_bytes(member)
    rel = "unpacked/pack.zip.unpacked/inner/ZQX7.json"
    docs, _ = mc.load_handout(base)
    assert mc.containers(docs) == ({"files/pack.zip": rel}, True) and mc.UNPACKED_SUFFIX == sweep.SUFFIX
    fields, notes = mc.extract_fields(docs)
    assert by_name(fields)["header"].sources == (rel,)          # not the zip, whose directory spells ZQX7.json
    assert len(notes) == 1 and notes[0].startswith(f"files/pack.zip: holds {rel}")
    # the same archive with nothing unpacked from it is evidence like any file
    assert mc.containers([d for d in docs if d[0] == "files/pack.zip"] + [("files/x.json", member)]) == ({}, True)
    # an archive inside an unpacked archive, and one unpacked beside itself in a bare folder
    nested = [("unpacked/a.zip.unpacked/in.tar", b"\x00" * 9), ("unpacked/a.zip.unpacked/in.tar.unpacked/r.json", b"{}"),
              ("b.tar", b"\x00" * 9), ("b.tar.unpacked/r.json", b"[]")]
    assert mc.containers(nested)[0] == {"unpacked/a.zip.unpacked/in.tar": "unpacked/a.zip.unpacked/in.tar.unpacked/r.json",
                                        "b.tar": "b.tar.unpacked/r.json"}


def test_what_counts_as_a_container_by_its_bytes(tmp_path):
    line = b"station = 0x7B1C\n"
    # two text files that share a line are two sources, not an archive and its member
    text = [("a.txt", line), ("b.txt", line + b"seed = 911\n")]
    assert mc.containers(text) == ({}, True)
    assert by_name(mc.extract_fields(text)[0])["station"].sources == ("a.txt", "b.txt")
    # a binary that holds a file whole is its container; a file under MIN_MEMBER bytes is too small to tell
    image = b"\x00\x01\x02" + line + b"seed=911" + b"\x00" * 8
    assert mc.MIN_MEMBER == 8
    assert mc.containers([("disk.img", image), ("a.txt", line)]) == ({"disk.img": "a.txt"}, True)
    assert mc.containers([("disk.img", image), ("s.txt", b"seed=911")]) == ({"disk.img": "s.txt"}, True)
    assert mc.containers([("disk.img", image), ("s.txt", b"eed=911")]) == ({}, True)
    assert mc.containers([("disk.img", image), ("other.bin", b"\x00\x01\x02 not inside")]) == ({}, True)


def test_the_container_check_names_its_cut(tmp_path, monkeypatch):
    docs = [("files/handout.tar", _tar({"record.json": RECORD})), ("unpacked/record.json", RECORD)]
    assert mc.containers(docs) == ({"files/handout.tar": "unpacked/record.json"}, True)
    monkeypatch.setattr(mc, "SCAN_BYTES", -1)
    assert mc.containers(docs) == ({}, False)
    _, notes = mc.extract_fields(docs)
    assert any("the check for archives that hold other evidence files stopped at its scan limit" in n for n in notes)


def test_the_container_check_counts_the_bytes_it_compared(monkeypatch):
    """The limit is on bytes searched: each comparison costs the size of the file searched in."""
    big = bytes(range(256)) * 2                                         # 512 bytes, holds neither member
    docs = [("big.bin", big), ("m1.bin", b"\x00member one"), ("m2.bin", b"\x00member two")]
    assert mc.containers(docs) == ({}, True)
    monkeypatch.setattr(mc, "SCAN_BYTES", 512)                          # the first comparison spends it exactly
    assert mc.containers(docs) == ({}, True)
    monkeypatch.setattr(mc, "SCAN_BYTES", 511)                          # one byte short: the second is not made
    assert mc.containers(docs) == ({}, False)
    held = [("big.bin", big + b"\x00member two"), ("m1.bin", b"\x00member one"), ("m2.bin", b"\x00member two")]
    assert mc.containers(held) == ({}, False)                           # ...so the member it holds is not seen
    monkeypatch.setattr(mc, "SCAN_BYTES", 523)
    assert mc.containers(held) == ({"big.bin": "m2.bin"}, True)


def test_a_document_type_declaration_alone_stops_the_xml_parse(tmp_path):
    base = tmp_path / "x"
    base.mkdir()
    (base / "e.xml").write_text('<!DOCTYPE r SYSTEM "r.dtd"><r><Seed>911</Seed></r>', encoding="utf-8")
    assert mc.extract_fields(base) == ([], ["e.xml: declares a DTD or an entity; not parsed"])
    (base / "e.xml").write_text("<r><Seed>911</Seed></r>", encoding="utf-8")       # the same body, no declaration
    fields, notes = mc.extract_fields(base)
    assert [(f.name, f.stored) for f in fields] == [("seed", "911")] and notes == []


def test_an_xml_document_that_declares_a_dtd_is_not_parsed(tmp_path):
    base = tmp_path / "x"
    base.mkdir()
    (base / "c.xml").write_text('<!DOCTYPE r [<!ENTITY a "aaaa">]><r><Seed>911</Seed></r>', encoding="utf-8")
    (base / "d.xml").write_text("<r><Seed>911</Seed><open>", encoding="utf-8")
    fields, notes = mc.extract_fields(base)
    assert fields == []
    assert notes == ["c.xml: declares a DTD or an entity; not parsed"] + [n for n in notes if n.startswith("d.xml")]
    assert any(n.startswith("d.xml: does not parse as XML") for n in notes)


def test_repeated_names_keep_their_first_values_and_say_how_many_were_left(tmp_path, monkeypatch):
    base = tmp_path / "r"
    base.mkdir()
    (base / "a.json").write_text(json.dumps({"rows": [{"reading": 100 + i} for i in range(5)]}), encoding="utf-8")
    fields, notes = mc.extract_fields(base)
    assert [(f.name, f.value) for f in fields] == [("reading", 100), ("reading_2", 101)]
    assert notes == ["3 uncorroborated value(s) of repeated names were not listed (the first 2 of each name are)"]
    monkeypatch.setattr(mc, "MAX_RAW_FIELDS", 3)
    fields, notes = mc.extract_fields(base)
    assert "2 named value(s) past the first 3 were not kept" in notes


def test_the_corroboration_search_names_its_cut(tmp_path, monkeypatch):
    monkeypatch.setattr(mc, "SCAN_BYTES", 0)
    _, notes = mc.extract_fields(handout(tmp_path), BRIEF)
    assert any("corroboration search stopped at its scan limit" in n for n in notes)


def test_the_brief_is_read_from_challenge_json_as_data(tmp_path):
    base = handout(tmp_path)
    assert mc.read_brief(base) == (BRIEF, "ICS", [])
    (base / "challenge.json").write_text("{not json", encoding="utf-8")
    assert mc.read_brief(base) == ("", "", ["challenge.json was not read (JSONDecodeError)"])
    (base / "challenge.json").write_text("[1]", encoding="utf-8")
    assert mc.read_brief(base)[2] == ["challenge.json is not a JSON object"]
    assert mc.read_brief(tmp_path) == ("", "", [])


# ------------------------------------------------------------------------------------- end to end

def test_the_engine_finds_the_marker_the_in_file_tag_confirms(tmp_path, prof):
    res = mc.solve(handout(tmp_path), prof, budget=60_000)
    assert res.status == "candidate" and res.flags[0] == "CSCTF{" + DIGEST[:8] + "}"
    first = res.evidence[0]
    assert first.kind == "witness" and repr(TRUTH) in first.detail
    assert ("sha256[:8];colon;firmware_magic=hex_0x_upper,station=as_stored,ts=as_stored,register=as_stored,"
            "manifest_seed=as_stored") in first.detail
    assert "files/event_log.json:tag" in first.detail
    assert "family ics" in res.notes and "fields station, manifest_seed, ts, register, firmware_magic" in res.notes
    assert "1 witness(es), 1 hit(s)" in res.notes


def test_without_a_check_the_same_handout_gives_an_unsure_ranked_list(tmp_path, prof):
    res = mc.solve(handout(tmp_path, tag=False), prof, budget=60_000)
    assert res.status == "unsure" and len(res.flags) == 12
    verbatim = "0x7B1C:911:2031-02-03T04:05:06Z:30007:ZQX7"            # the fields as found, as stored
    assert res.flags[0] == "CSCTF{" + hashlib.sha256(verbatim.encode()).hexdigest()[:8] + "}"
    assert "0 witness(es), 0 hit(s)" in res.notes


def test_the_brief_states_the_cut_and_the_category_names_the_family(tmp_path, prof):
    brief16 = BRIEF.replace("8_lowercase_hex", "16_lowercase_hex")
    report, unused, _ = mc.run(handout(tmp_path, brief=brief16), prof, budget=60_000)
    assert report.digests == ["sha256[:16]"] and report.family == "ics"
    assert report.candidates[0].flag == "CSCTF{" + DIGEST[:16] + "}"
    assert {f.name for f in unused} >= {"ts_2", "register_2", "name"}
    assert mc.run(handout(tmp_path / "f"), prof, family="Grid Ops", budget=1000)[0].family == "grid_ops"


def test_two_stated_lengths_are_both_hashed_and_the_report_says_so(tmp_path, prof):
    brief = BRIEF + "\n\nAn older build printed the first 16 hex characters."
    report, _, notes = mc.run(handout(tmp_path, brief=brief), prof, budget=60_000)
    assert report.digests == ["sha256[:8]", "sha256[:16]"]
    assert ("the brief states more than one hex length: sha256[:8], sha256[:16] are all hashed, the first "
            "stated first (digest=FORM states one)") in notes
    assert report.candidates[0].flag == "CSCTF{" + DIGEST[:8] + "}"     # the witness confirms the first stated
    said = "more than one hex length"
    assert not any(said in n for n in mc.run(handout(tmp_path / "one"), prof, budget=1000)[2])
    md5 = BRIEF + "\n\nCheck the archive with md5sum before you start."          # two algorithms, one length
    assert not any(said in n for n in mc.run(handout(tmp_path / "md5", brief=md5), prof, budget=1000)[2])
    stated = mc.run(handout(tmp_path / "st", brief=brief), prof, budget=1000, digest="sha256[:8]")
    assert stated[0].digests == ["sha256[:8]"] and not any(said in n for n in stated[2])


def test_a_witness_given_and_found_in_the_files_is_checked_once(tmp_path, prof):
    report, _, _ = mc.run(handout(tmp_path), prof, witness=DIGEST[-8:].upper() + "@suffix", budget=60_000)
    assert report.witnesses == [mc.Witness(DIGEST[-8:], "suffix", "given")]     # the caller's reading of it wins
    assert report.witness_hits == 1 and report.candidates[0].flag == "CSCTF{" + DIGEST[:8] + "}"
    other = "0" * 8
    both, _, _ = mc.run(handout(tmp_path / "o"), prof, witness=other, budget=1000)
    assert [(w.token, w.source) for w in both.witnesses] == [(other, "given"), (DIGEST[-8:], "files/event_log.json:tag")]


def test_an_algorithm_the_brief_names_in_passing_does_not_take_sha256_out_of_the_space(tmp_path, prof):
    brief = BRIEF + "\n\nCheck the archive with md5sum before you start."
    report, _, notes = mc.run(handout(tmp_path, brief=brief), prof, budget=60_000)
    assert report.digests == ["md5[:8]", "sha256[:8]"]
    first = report.candidates[0]
    assert (first.basis, first.flag, first.preimage) == ("witness", "CSCTF{" + DIGEST[:8] + "}", TRUTH)
    assert any(n.startswith("the brief names md5, which may be about something else") and "md5[:8], sha256[:8]" in n
               for n in notes)
    # with no check in the files the two algorithms take turns in the list: neither hides the other
    plain, _, _ = mc.run(handout(tmp_path / "p", tag=False, brief=brief), prof, budget=60_000)
    assert [c.convention.split(";")[0] for c in plain.candidates[:4]] == ["md5[:8]", "sha256[:8]"] * 2
    stated, _, notes = mc.run(handout(tmp_path / "s", brief=brief), prof, budget=1000, digest="sha256[:8]")
    assert stated.digests == ["sha256[:8]"] and not any("the brief names" in n for n in notes)


def test_values_held_by_one_source_are_used_only_when_asked(tmp_path, prof):
    base = tmp_path / "one"
    base.mkdir()
    (base / "only.json").write_text('{"alpha": "left", "beta": "right"}', encoding="utf-8")
    res = mc.solve(base, prof)
    assert res.status == "none" and not res.flags
    assert "no named value is held by two evidence sources" in res.notes
    assert "alpha=left, beta=right" in res.notes and "--field" in res.notes
    asked = mc.solve(base, prof, all_fields=True, digest="sha256[:8]")
    assert asked.status == "unsure"
    assert asked.flags[0] == "CSCTF{" + hashlib.sha256(b"left:right").hexdigest()[:8] + "}"
    capped = mc.run(base, prof, all_fields=True, max_fields=1)
    assert [f.name for f in capped[0].fields] == ["alpha"] and [f.name for f in capped[1]] == ["beta"]


# ------------------------------------------------------------------------------------- routing

MANIFEST = paths.repo_root() / "solvers" / "common" / "marker_convention.manifest.toml"


def test_the_manifest_enters_solve_and_has_no_intake_table():
    m = manifest.load(MANIFEST)
    assert m.id == mc.ENGINE_ID == "common.marker_convention" and m.status == "active"
    assert m.capabilities[0] == "analysis" and m.cost_class == "cheap" and m.needs_tools == ()
    assert m.entry.target_file(paths.repo_root()) == paths.repo_root() / "solvers" / "common" / "marker_convention.py"
    assert m.entry_raw.endswith(":solve") and callable(mc.solve)
    # Its flags are guesses and intake calls one engine flag `solved` (tests/test_common_marker_intake.py):
    # the engine is routed and listed for the agent, never run at intake.
    assert m.intake is None


@pytest.mark.parametrize("category,description,routed", [
    ("ICS", BRIEF, True),
    ("Network", "Trace the roaming fraud through the subscriber records, then recover its marker.", True),
    ("Misc", "Build the marker from the three values the logs agree on.", True),
    ("ICS", "Read the holding registers from the PLC and find the flag.", False),
    ("Forensics", "Carve the image after the JPEG end marker.", False),
    # a hex answer shape is any flag format, not a constructed marker
    ("Forensics", "Find the dropped file. Flag format: CSCTF{32_lowercase_hex}", False),
    ("Crypto", "Answer with the key as 32 lowercase hex characters.", False),
    ("Forensics", "Flag construction: hash the joined values with SHA-256 and keep 16 lowercase hex characters "
                  "from the front.", False),
    ("Web", "Flag derivation is described in the admin page.", False),
], ids=["ics-marker", "telecom-marker", "build-the-marker", "plain-ics", "end-marker", "hex-flag-format",
        "hex-answer", "stated-construction", "flag-derivation"])
def test_the_router_sends_marker_briefs_here_and_others_elsewhere(category, description, routed):
    ids = [hit.manifest.id for hit in router.route(category, description)]
    assert ("common.marker_convention" in ids) is routed
