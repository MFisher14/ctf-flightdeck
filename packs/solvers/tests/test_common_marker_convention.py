"""B-119: the constructed-marker fallback (solvers/common/marker_convention.py).

Fields, renderings, digest forms, witnesses, the search and its ranking, the convention knowledge base
(the labels seed store, B-040), the bounded pick, the guess-budget plan (B-154's VariantSet.plan) and
the engine entry. Every case is synthetic: the three shapes are the ones the CSCTF 2026 markers took
(an ICS five-field join, a telecom verbatim join, fixed-decimal coordinates with an in-file tag), on
made-up values. Expected markers are computed here with hashlib from literal preimages, never by the
engine. The knowledge base starts empty (a temp seed and a temp workdir) unless a test teaches it.
"""
from __future__ import annotations

import hashlib
import json

import pytest

import labels
import marker_convention as mc
import render_candidates as RC
from ctf import event, flagcheck, seedfold
from ctf.result import SolverResult

ICS_TEXT = "0x5A515837:0x7B1C:2031-02-03T04:05:06Z:30007:911"          # header tag ZQX7 as 0x upper hex
ICS_CONV = ("sha256[:8];colon;header=hex_0x_upper,station=as_stored,timestamp=as_stored,"
            "register=as_stored,seed=as_stored")
VERBATIM_CONV = ("sha256[:8];colon;header=as_stored,station=as_stored,timestamp=as_stored,"
                 "register=as_stored,seed=as_stored")
SIBLING_TEXT = "0x4B4C4D32:0x19AF:2032-06-07T08:09:10Z:41000:5"       # header tag KLM2
DRONE_TEXT = "12.345665.43210.0011000.005200612.3"
ICS_KINDS = {"header": "tag", "station": "hexid", "timestamp": "timestamp", "register": "integer",
             "seed": "integer"}
F8 = [mc.DigestForm.parse("sha256[:8]")]
BUDGET = 60_000        # explicit, not the production default: depths 0 and 1 of the five-field space


def search(fields, digests=None, **kw):
    kw.setdefault("budget", BUDGET)
    return mc.search(fields, digests, **kw)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def ics_fields():
    return [mc.make_field("header", "ZQX7", "tag"), mc.make_field("station", "0x7B1C"),
            mc.make_field("timestamp", "2031-02-03T04:05:06Z"), mc.make_field("register", 30007),
            mc.make_field("seed", 911)]


def sibling_fields():
    return [mc.make_field("header", "KLM2", "tag"), mc.make_field("station", "0x19AF"),
            mc.make_field("timestamp", "2032-06-07T08:09:10Z"), mc.make_field("register", 41000),
            mc.make_field("seed", 5)]


def drone_fields():
    return [mc.make_field("approved_lat", "12.3456"), mc.make_field("approved_lon", "65.4321"),
            mc.make_field("delta_lat", 0.0011), mc.make_field("delta_lon", 0.0052),
            mc.make_field("distance", 612.3478)]


@pytest.fixture(autouse=True)
def _empty_kb(tmp_path, monkeypatch):
    for name in ("CTF_JUDGE_LEDGER", "CTF_LEDGER_MASK", "CTF_FAMILY_PRIOR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    monkeypatch.setattr(labels, "seed_path", lambda lane: seeds / f"{lane}.json")
    labels._cache.clear()
    labels._gate_said.clear()
    yield seeds
    labels._cache.clear()


@pytest.fixture
def prof():
    return event.load("csctf")


@pytest.fixture
def case(tmp_path):
    """An empty challenge folder (apart from the temp workdir and seed, which are not evidence)."""
    folder = tmp_path / "case"
    folder.mkdir()
    return folder


# ------------------------------------------------------------------------------------- fields

@pytest.mark.parametrize("value,kind", [
    (b"ZQX7", "tag"), (30007, "integer"), (1893456789, "timestamp"), (0.0011, "decimal"),
    ("2031-02-03T04:05:06Z", "timestamp"), ("2031-02-03 04:05", "timestamp"), ("0x7B1C", "hexid"),
    ("30007", "integer"), ("1893456789", "timestamp"), ("901700000012345", "text"), ("12.3456", "decimal"),
    ("hss.example.test;1893456789;40404", "text"), ("007", "text"), ("-12", "integer"),
    # twelve digits are still a number; a longer run is an identifier, whether a file gave it as a
    # string or as a JSON number
    ("123456789012", "integer"), ("1234567890123", "text"), ("-123456789012", "integer"),
    (123456789012, "integer"), (1234567890123, "text"), (901700000012345, "text"),
], ids=lambda v: f"{type(v).__name__}-{str(v)[:20]}")
def test_kind_is_inferred_from_the_shape_of_the_value(value, kind):
    assert mc.infer_kind(value) == kind
    assert mc.make_field("x", value).kind == kind


def test_a_field_is_checked_when_it_is_made():
    f = mc.make_field(" First Critical-TS ", " 2031-02-03T04:05:06Z ", sources=["a.json", "a.json", "b.xml"])
    assert (f.name, f.value, f.kind, f.sources) == ("first_critical_ts", "2031-02-03T04:05:06Z", "timestamp",
                                                    ("a.json", "b.xml"))
    assert mc.make_field("epoch", "1893456789", "timestamp").value == 1893456789     # epoch seconds are a number
    assert mc.make_field("n", 7, "text").stored == "7"
    big = mc.make_field("imsi", 901700000012345)                  # an identifier read as a JSON number
    assert (big.kind, big.value, big.stored) == ("text", "901700000012345", "901700000012345")
    for name, value, kind, why in [("x", "abc", "timestamp", "does not read as kind"),
                                   ("x", "0xZZ", "hexid", "does not read as kind"),
                                   ("x", 3.5, "integer", "does not read as kind"),
                                   ("x", "v", "colour", "unknown kind"), ("x", True, None, "not a marker value"),
                                   ("x", None, None, "not a marker value"), ("x", "  ", None, "empty value"),
                                   ("--", "v", None, "no letter or digit")]:
        with pytest.raises(mc.MarkerError, match=why):
            mc.make_field(name, value, kind)


def test_a_field_spec_keeps_colons_and_equals_signs_in_the_value():
    f = mc.parse_field("session_id=hss.example.test;1893456789;40404")
    assert (f.name, f.kind, f.value, f.sources) == ("session_id", "text", "hss.example.test;1893456789;40404",
                                                    ("given",))
    f = mc.parse_field("ts:timestamp=2031-02-03T04:05:06Z")
    assert (f.name, f.kind, f.value) == ("ts", "timestamp", "2031-02-03T04:05:06Z")
    f = mc.parse_field("expr:text=a=b:c")
    assert (f.name, f.kind, f.value) == ("expr", "text", "a=b:c")
    f = mc.parse_field({"name": "Header", "value": "ZQX7", "kind": "tag"})
    assert (f.name, f.kind, f.stored) == ("header", "tag", "ZQX7")
    for bad in ("novalue", "=v", {"name": "x"}, {"value": 1}):
        with pytest.raises(mc.MarkerError):
            mc.parse_field(bad)


def test_renderings_start_with_the_stored_spelling_then_render_candidates_spellings():
    header, station, ts, register, seed = ics_fields()
    assert mc.renderings(header) == [("as_stored", "ZQX7"), ("hex_0x_lower", "0x5a515837"),
                                     ("hex_lower", "5a515837"), ("hex_0x_upper", "0x5A515837"),
                                     ("hex_upper", "5A515837")]
    assert mc.renderings(station) == [("as_stored", "0x7B1C"), ("hex_0x_lower", "0x7b1c"), ("hex_lower", "7b1c"),
                                      ("hex_upper", "7B1C"), ("integer", "31516")]
    assert mc.renderings(ts) == [("as_stored", "2031-02-03T04:05:06Z"),
                                 ("iso8601_offset", "2031-02-03T04:05:06+00:00"),
                                 ("iso8601_space", "2031-02-03 04:05:06"), ("epoch_seconds", "1927857906"),
                                 ("epoch_millis", "1927857906000")]
    got = dict(mc.renderings(seed))
    assert got["as_stored"] == "911" and got["hex_0x"] == "0x38f" and got["hex_0x_upper"] == "0x038F"
    assert mc.renderings(mc.make_field("imsi", "901700000012345")) == [("as_stored", "901700000012345")]
    texts = [t for _, t in mc.renderings(register)]
    assert len(texts) == len(set(texts)), "one text is offered once"


def test_a_rendering_the_knowledge_base_names_leads():
    header = ics_fields()[0]
    got = mc.renderings(header, prior=["hex_0x_upper", "no_such_rendering"])
    assert got[0] == ("hex_0x_upper", "0x5A515837") and got[1] == ("as_stored", "ZQX7")
    assert sorted(got) == sorted(mc.renderings(header))


def test_the_render_table_names_every_spelling_including_the_stored_one_again():
    table = mc.render_table(ics_fields()[2])
    assert table["as_stored"] == table["iso8601_z"] == "2031-02-03T04:05:06Z"
    assert mc.render_table(ics_fields()[1])["hex_0x_upper"] == "0x7B1C"


def test_a_rendering_is_found_by_name_when_another_name_spells_the_value_alike():
    digits = mc.make_field("header", "1234", "tag")              # bytes 31 32 33 34: no hex letter to case
    table = mc.render_table(digits)
    assert table["hex_0x_upper"] == table["hex_0x_lower"] == "0x31323334"
    assert mc.renderings(digits) == [("as_stored", "1234"), ("hex_0x_lower", "0x31323334"),
                                     ("hex_lower", "31323334")]
    assert mc.renderings(digits, prior=["hex_0x_upper"])[0] == ("hex_0x_upper", "0x31323334")
    conv = mc.Convention.parse("sha256[:8];colon;header=hex_0x_upper,seed=as_stored")
    assert conv.preimage([digits, mc.make_field("seed", 911)]) == "0x31323334:911"
    assert RC.render_named(b"1234", "hex") == [("hex_0x_lower", "0x31323334"), ("hex_lower", "31323334"),
                                               ("hex_0x_upper", "0x31323334"), ("hex_upper", "31323334")]
    assert RC.render_named("x", "no_such_kind") == [] and RC.render_named(None, "hex") == []


# ------------------------------------------------------------------------------------- digest forms

def test_digest_forms_cut_the_head_the_tail_or_nothing():
    h = sha("x")
    for text, want in [("sha256[:8]", h[:8]), ("sha256[-8:]", h[-8:]), ("sha256", h), ("SHA256[:16]", h[:16]),
                       ("sha256[:8].upper", h[:8].upper())]:
        form = mc.DigestForm.parse(text)
        assert form.apply(h) == want and form.name == text.lower()
    assert mc.DigestForm.parse("md5[:8]").algo == "md5"
    for bad, why in [("sha3[:8]", "digest form"), ("sha256[:65]", "64 hex"), ("md5[:33]", "32 hex"),
                     ("sha256[:0]", "64 hex"), ("sha256[8]", "digest form"), ("", "digest form")]:
        with pytest.raises(mc.MarkerError, match=why):
            mc.DigestForm.parse(bad)


@pytest.mark.parametrize("brief,want", [
    ("Flag format: **`CSCTF{8_lowercase_hex}`**", ["sha256[:8]"]),
    ("keep the first 16 lower-case hex chars of it.", ["sha256[:16]"]),
    ("Submit all 64 hex characters of the SHA-256.", ["sha256"]),
    ("answer: 8 UPPERCASE hex", ["sha256[:8].upper"]),
    # an algorithm other than SHA-256 leads when it alone is named, and SHA-256 is still in the space
    ("the first 8 hex of the MD5", ["md5[:8]", "sha256[:8]"]),
    ("Flag format: CSCTF{8_lowercase_hex}. Check the download with sha1sum first.", ["sha1[:8]", "sha256[:8]"]),
    ("Take 40 hex characters. A SHA-1 and an MD5 are listed.", ["sha1", "sha256[:40]"]),       # md5 has 32
    ("An md5 and a SHA-512 are listed; answer: 16 hex.", ["md5[:16]", "sha512[:16]", "sha256[:16]"]),
    # a named SHA-256 is the algorithm: another name in the brief is about something else
    ("Compute the SHA-256 of the joined fields and submit the first 8 hex characters. The archive's MD5 "
     "is listed in the manifest.", ["sha256[:8]"]),
    ("MD5 of the archive: see the manifest. Marker: sha 256, first 8 hex.", ["sha256[:8]"]),
    ("the first 130 hex of the sha512; else 8 hex", ["sha512[:8]", "sha256[:8]"]),            # no digest is 130 long
    ("SHA-256 hex digest of the record", []),              # 256 is the algorithm, not a length
    ("the port was 8080; 7 hex digits", []),               # an odd length is not a digest cut
    ("", []),
    # a length in the flag format's braces or after first/last is about the answer: it wins over one
    # that stands anywhere else, whichever comes first
    ("addresses are 4 hex digits wide; the flag is CSCTF{8_lowercase_hex}", ["sha256[:8]"]),
    ("The register is 16 hex; marker is first 8 hex chars of sha256", ["sha256[:8]"]),
    ("CSCTF{8_lowercase_hex}. Offsets in the dump are 4 hex wide.", ["sha256[:8]"]),
    # `last` cuts the tail; a word that only ends in it does not
    ("the last 8 hex characters of the SHA-256", ["sha256[-8:]"]),
    ("the LAST 40 uppercase hex of the sha1", ["sha1.upper", "sha256[-40:].upper"]),
    ("at full blast 8 hex", ["sha256[:8]"]),
    # several lengths of the same standing are all kept, in the order stated, each once
    ("CSCTF{16_lowercase_hex}: the first 8 hex of each half, then the first 16 hex", ["sha256[:16]", "sha256[:8]"]),
    ("ids are 4 hex wide and the answer is 8 uppercase hex", ["sha256[:4]", "sha256[:8].upper"]),
    # an algorithm's name starts a word, and md5 is not the start of a number
    ("Marsha 1st and Geisha-1 ran cmd5 on md 50 hosts; answer: 8 hex", ["sha256[:8]"]),
    ("HMAC-SHA1 over the lot, first 8 hex", ["sha1[:8]", "sha256[:8]"]),
], ids=["brace-shape", "sentence", "full", "upper", "md5", "sha1sum", "too-long-for-md5", "named-order",
        "sha256-named", "sha256-named-later", "too-long-for-any", "algo-only", "odd", "empty",
        "brace-over-loose", "first-over-loose", "brace-before-loose", "last-is-the-tail", "last-full-upper",
        "blast-is-not-last", "two-stated", "two-loose", "names-inside-words", "after-a-hyphen"])
def test_the_digest_form_is_read_from_the_brief_by_shape(brief, want):
    assert [f.name for f in mc.forms_from_brief(brief)] == want


def test_forms_of_different_algorithms_alternate_in_the_prior():
    pair = [mc.make_field("a", "left", "text"), mc.make_field("b", "right", "text")]
    forms = [mc.DigestForm.parse(f) for f in ("md5[:8]", "sha256[:8]", "sha256")]
    rep = search(pair, forms, top=6)
    md5 = lambda text: hashlib.md5(text.encode()).hexdigest()[:8]     # noqa: E731
    # the first form of each algorithm takes turns over the compositions; sha256's second form waits
    assert [c.marker for c in rep.candidates] == [md5("left:right"), sha("left:right")[:8],
                                                  md5("leftright"), sha("leftright")[:8],
                                                  md5("right:left"), sha("right:left")[:8]]
    assert [c.convention.split(";")[0] for c in search(pair, forms, top=40).candidates] == (
        ["md5[:8]", "sha256[:8]"] * 18 + ["sha256"] * 4)


# ------------------------------------------------------------------------------------- witnesses

def test_a_witness_matches_the_part_of_the_digest_it_names():
    h = sha("x")
    head, tail, mid = h[:8], h[-8:], h[20:30]
    assert mc.Witness(head, "prefix").match(h) == "prefix" and mc.Witness(head, "suffix").match(h) is None
    assert mc.Witness(tail, "suffix").match(h) == "suffix" and mc.Witness(tail, "prefix").match(h) is None
    assert mc.Witness(head, "edge").match(h) == "prefix" and mc.Witness(tail, "edge").match(h) == "suffix"
    assert mc.Witness(mid, "edge").match(h) is None and mc.Witness(mid, "any").match(h) == "inside"
    assert mc.Witness(tail, "any").match(h) == "suffix"
    assert [mc.Witness(head, w).places(64) for w in mc.WHERE] == [1, 1, 2, 57]


def test_a_witness_spec_is_checked():
    assert mc.parse_witness("ABCDEF01") == mc.Witness("abcdef01", "edge", "given")
    assert mc.parse_witness(" abcdef0123@suffix ") == mc.Witness("abcdef0123", "suffix", "given")
    for bad, why in [("abc", "8 hex"), ("abcdef0", "8 hex"), ("zzzzzzzz", "8 hex"),
                     ("abcdef01@middle", "where is one of")]:
        with pytest.raises(mc.MarkerError, match=why):
            mc.parse_witness(bad)


# ------------------------------------------------------------------------------------- conventions

def test_a_convention_name_round_trips_and_builds_its_text():
    conv = mc.Convention.parse(ICS_CONV)
    assert conv.name == ICS_CONV and conv.digest == "sha256[:8]" and conv.join == "colon"
    assert conv.roles == ("header", "station", "timestamp", "register", "seed")
    assert conv.preimage(ics_fields()) == ICS_TEXT
    assert conv.preimage(reversed(ics_fields())) == ICS_TEXT             # the convention holds the order
    one = mc.Convention.parse("sha256;-;seed=hex_0x")
    assert one.join is None and one.preimage(ics_fields()) == "0x38f" and one.name == "sha256;-;seed=hex_0x"
    named_again = mc.Convention.parse("sha256[:8];pipe;timestamp=iso8601_z,seed=integer")
    assert named_again.preimage(ics_fields()) == "2031-02-03T04:05:06Z|911"


def test_a_convention_is_not_built_without_its_role_or_rendering():
    conv = mc.Convention.parse(ICS_CONV)
    assert conv.preimage(ics_fields()[:4]) is None                               # no seed
    assert mc.Convention.parse("sha256[:8];colon;header=dp_4,seed=as_stored").preimage(ics_fields()) is None


@pytest.mark.parametrize("bad,why", [
    ("sha256[:8];colon", "write <digest>"), ("sha9;colon;a=as_stored,b=as_stored", "digest form"),
    ("sha256;tab;a=as_stored,b=as_stored", "unknown join"), ("sha256;colon;a=as_stored", "one field takes"),
    ("sha256;-;a=as_stored,b=as_stored", "one field takes"), ("sha256;colon;a,b=as_stored", "not <role>"),
    ("sha256;colon;a=as_stored,a=integer", "used twice"), ("sha256;colon;A=as_stored,b=x", "not <role>"),
], ids=["parts", "digest", "join", "single-join", "dash-many", "pair", "dup-role", "case"])
def test_a_malformed_convention_name_is_refused(bad, why):
    with pytest.raises(mc.MarkerError, match=why):
        mc.Convention.parse(bad)


# ------------------------------------------------------------------------------------- the search

def cost_of(name: str, given: list[str]) -> int:
    """The documented prior cost of a convention, computed apart from the engine."""
    conv = mc.Convention.parse(name)
    seq = [given.index(r) for r in conv.roles]
    joins = [n for n, _ in RC.JOINS]
    return (sum(1 for _, x in conv.parts if x != "as_stored") + (0 if seq == sorted(seq) else 1)
            + 2 * (len(given) - len(seq)) + (min(joins.index(conv.join), 3) if conv.join else 0))


def test_with_no_evidence_the_first_candidate_is_every_field_as_stored_colon_joined():
    rep = search(ics_fields(), F8, family="ICS")
    first = rep.candidates[0]
    assert first.preimage == "ZQX7:0x7B1C:2031-02-03T04:05:06Z:30007:911"
    assert first.marker == first.flag == sha(first.preimage)[:8]
    assert (first.rank, first.basis, first.convention) == (1, "prior", VERBATIM_CONV)
    assert rep.family == "ics" and not rep.supported and rep.witness_hits == 0
    assert rep.candidates[1].convention == VERBATIM_CONV.replace(";colon;", ";none;")
    assert [c.rank for c in rep.candidates] == list(range(1, mc.DEFAULT_TOP + 1))


def test_the_prior_ranks_by_the_documented_cost():
    given = [f.name for f in ics_fields()]
    rep = search(ics_fields(), F8, top=400, budget=60_000)
    costs = [cost_of(c.convention, given) for c in rep.candidates]
    assert costs == sorted(costs) and costs[0] == 0 and costs[1] == 1 and max(costs) >= 2
    for c in rep.candidates:                                    # every listed marker is its text's digest
        assert c.marker == sha(c.preimage)[:8]
        assert mc.Convention.parse(c.convention).preimage(ics_fields()) == c.preimage


def test_a_witness_on_the_digest_tail_finds_the_convention_and_ranks_it_first():
    full = sha(ICS_TEXT)
    rep = search(ics_fields(), F8, witnesses=[mc.Witness(full[-8:], "suffix", "log:tag")])
    first = rep.candidates[0]
    assert (first.basis, first.preimage, first.marker, first.convention) == ("witness", ICS_TEXT, full[:8], ICS_CONV)
    assert "suffix" in first.detail and full[-8:] in first.detail and "log:tag" in first.detail
    # 60000 texts, one algorithm, one position, an 8-hex tag: 60000 / 16**8 chance matches expected
    assert rep.enumerated == BUDGET and "1.4e-05 chance match(es) expected over 60000 texts" in first.detail
    assert rep.witness_hits == 1 and rep.supported
    assert rep.candidates[1].basis == "prior" and rep.candidates[1].convention == VERBATIM_CONV
    # the same token is not a hit where it is not the named part of the digest
    miss = search(ics_fields(), F8, witnesses=[mc.Witness(full[-8:], "prefix")])
    assert miss.witness_hits == 0 and miss.candidates[0].basis == "prior" and not miss.supported
    assert any("no witness hit" in n for n in miss.notes)
    edge = search(ics_fields(), F8, witnesses=[mc.Witness(full[-8:], "edge")]).candidates[0]
    assert edge.marker == full[:8] and "2.8e-05 chance match(es)" in edge.detail      # either end: two positions
    inside = search(ics_fields(), F8, witnesses=[mc.Witness(full[20:30], "any")])
    assert inside.candidates[0].preimage == ICS_TEXT and "inside" in inside.candidates[0].detail


def test_the_chance_estimate_counts_every_algorithm_that_was_hashed():
    full = sha(ICS_TEXT)
    two = [mc.DigestForm.parse("sha256[:8]"), mc.DigestForm.parse("md5[:8]")]
    first = search(ics_fields(), two, witnesses=[mc.Witness(full[-8:], "suffix")]).candidates[0]
    # 60000 texts under two algorithms, one position: 2 x 60000 / 16**8 = 2.8e-05 (1.4e-05 for one)
    assert first.preimage == ICS_TEXT and "sha256 digest suffix" in first.detail
    assert "2.8e-05 chance match(es) expected over 60000 texts" in first.detail
    # an md5 tag is found under md5 and is listed for the md5 form only
    tag = hashlib.md5(ICS_TEXT.encode()).hexdigest()
    hit = search(ics_fields(), two, witnesses=[mc.Witness(tag[-8:], "suffix")]).candidates[0]
    assert (hit.basis, hit.marker) == ("witness", tag[:8]) and hit.convention.startswith("md5[:8];")


def test_witness_hits_past_the_cap_are_counted_and_named(monkeypatch):
    verbatim = "ZQX7:0x7B1C:2031-02-03T04:05:06Z:30007:911"
    monkeypatch.setattr(mc, "MAX_HITS", 1)
    rep = search(ics_fields(), F8, witnesses=[mc.Witness(sha(verbatim)[:16], "prefix"),
                                              mc.Witness(sha(ICS_TEXT)[:16], "prefix")])
    assert rep.witness_hits == 2 and [c.basis for c in rep.candidates[:2]] == ["witness", "prior"]
    assert rep.candidates[0].preimage == verbatim
    assert "2 witness hits; only the first 1 are listed" in rep.notes


def test_a_tag_for_the_tail_confirms_a_flag_cut_from_the_head():
    full = sha(DRONE_TEXT)
    rep = search(drone_fields(), [mc.DigestForm.parse("sha256[:16]")], permute=False, budget=400_000,
                    witnesses=[mc.Witness(full[-8:], "edge", "flight_log.bin:tag")], family="forensics")
    first = rep.candidates[0]
    assert (first.basis, first.preimage, first.marker) == ("witness", DRONE_TEXT, full[:16])
    assert first.convention == ("sha256[:16];none;approved_lat=as_stored,approved_lon=as_stored,"
                                "delta_lat=dp_6,delta_lon=dp_6,distance=dp_1")


def test_a_hit_that_chance_could_explain_is_weak_and_ranks_after_a_strong_one(monkeypatch):
    verbatim = "ZQX7:0x7B1C:2031-02-03T04:05:06Z:30007:911"
    short = mc.Witness(sha(verbatim)[-8:], "suffix", "short")           # an 8-hex tag on the first text hashed
    long = mc.Witness(sha(ICS_TEXT)[:16], "prefix", "long")             # a 16-hex tag on a later text
    monkeypatch.setattr(mc, "CHANCE_LIMIT", 1e-8)                       # between the two tags' chances
    rep = search(ics_fields(), F8, witnesses=[short, long])
    assert [(c.basis, c.preimage) for c in rep.candidates[:2]] == [("witness", ICS_TEXT),
                                                                   ("witness-weak", verbatim)]
    assert rep.witness_hits == 2 and rep.supported
    weak_only = search(ics_fields(), F8, witnesses=[short])
    assert weak_only.candidates[0].basis == "witness-weak" and not weak_only.supported
    assert "chance match" in weak_only.candidates[0].detail


def _noise(count: int) -> list:
    """`count` 8-hex tags that are no digest of anything here, each checked anywhere in a digest."""
    return [mc.Witness(sha(f"no such record {i}")[:8], "any", f"log:hash{i}") for i in range(count)]


def test_a_hit_among_many_tags_is_weak_at_the_production_limit():
    """Every tag compared is one more chance of a match. One 8-hex tag checked anywhere in the SHA-256
    of 60000 texts expects 60000 x 57 / 16**8 = 0.0008 chance matches: strong. The same hit beside 16
    more such tags expects 17 times that, 0.014: over the limit, weak. Nothing is patched: the limit
    is the production one, and 0.014 sits between it and 1."""
    assert mc.CHANCE_LIMIT == 0.01
    real = mc.Witness(sha(ICS_TEXT)[20:28], "any", "log:hash")
    alone = search(ics_fields(), F8, witnesses=[real])
    first = alone.candidates[0]
    assert (first.basis, first.preimage) == ("witness", ICS_TEXT) and alone.supported
    assert first.detail.endswith("0.0008 chance match(es) expected over 60000 texts")       # one tag: no count
    rep = search(ics_fields(), F8, witnesses=_noise(16) + [real])
    first = rep.candidates[0]
    assert rep.witness_hits == 1 and (first.basis, first.preimage) == ("witness-weak", ICS_TEXT)
    assert first.detail.endswith("0.014 chance match(es) expected over 60000 texts and 17 tags")
    assert not rep.supported


def test_a_long_tag_is_not_weakened_by_shorter_ones_beside_it():
    """A 16-hex tag that hits is as rare beside sixteen 8-hex tags as alone: only a tag at least as
    long could give a match as good. 60000 / 16**16 = 3.3e-15."""
    long = mc.Witness(sha(ICS_TEXT)[:16], "prefix", "long")
    rep = search(ics_fields(), F8, witnesses=_noise(16) + [long])
    first = rep.candidates[0]
    assert rep.witness_hits == 1 and (first.basis, first.preimage) == ("witness", ICS_TEXT)
    assert first.detail.endswith("3.3e-15 chance match(es) expected over 60000 texts")
    # two tags of one length count each other, whichever hits
    pair = search(ics_fields(), F8, witnesses=[mc.Witness("0" * 16, "prefix"), long]).candidates[0]
    assert pair.detail.endswith("6.5e-15 chance match(es) expected over 60000 texts and 2 tags")


def test_solve_does_not_call_a_hit_among_many_tags_a_candidate(case, prof):
    specs = ["header:tag=ZQX7", "station=0x7B1C", "timestamp=2031-02-03T04:05:06Z", "register=30007", "seed=911"]
    real = sha(ICS_TEXT)[20:28] + "@any"
    base = dict(fields=specs, digest="sha256[:8]", family="ics", budget=BUDGET)
    alone = mc.solve(case, prof, witness=real, **base)
    many = mc.solve(case, prof, witness=[f"{w.token}@any" for w in _noise(16)] + [real], **base)
    assert alone.flags[0] == many.flags[0] == "CSCTF{" + sha(ICS_TEXT)[:8] + "}"
    assert (alone.status, many.status) == ("candidate", "unsure")
    assert "witness-weak" in many.evidence[0].detail and "17 witness(es), 1 hit(s)" in many.notes


def test_the_budget_cuts_the_space_and_the_report_says_so():
    rep = search(ics_fields(), F8, budget=50)
    assert rep.enumerated == 50 and rep.space > 50 and not rep.exhausted
    assert any("hashed 50 of" in n and "not checked" in n for n in rep.notes)
    whole = search(ics_fields(), F8, max_deviations=0, budget=10 ** 6)
    assert whole.enumerated == whole.space == 2880 and whole.exhausted      # (20+60+120+120) orders x 9 joins
    assert not any("hashed" in n for n in whole.notes)
    kept = search(ics_fields(), F8, max_deviations=0, permute=False, budget=10 ** 6)
    assert kept.space == (10 + 10 + 5 + 1) * 9


def test_one_flag_is_listed_once_and_top_caps_the_list():
    twins = [mc.make_field("a", "1", "text"), mc.make_field("b", "1", "text")]
    rep = search(twins, F8, top=50)
    flags = [c.flag for c in rep.candidates]
    assert len(flags) == len(set(flags)) == 9 and rep.space == 18           # a:b and b:a spell one text
    assert len(search(ics_fields(), F8, top=5).candidates) == 5


def test_single_fields_are_tried_only_when_asked():
    pair = [mc.make_field("a", "left", "text"), mc.make_field("b", "right", "text")]
    assert not any(";-;" in c.convention for c in search(pair, F8, top=100).candidates)
    alone = [c for c in search(pair, F8, top=100, min_fields=1).candidates if ";-;" in c.convention]
    assert {c.preimage for c in alone} == {"left", "right"}


def test_later_digest_forms_are_listed_after_the_first_runs_out():
    pair = [mc.make_field("a", "left", "text"), mc.make_field("b", "right", "text")]
    rep = search(pair, top=24)                                           # default forms: sha256[:8], sha256
    assert rep.digests == ["sha256[:8]", "sha256"]
    names = [c.convention.split(";")[0] for c in rep.candidates]
    assert names == ["sha256[:8]"] * 18 + ["sha256"] * 6
    assert len(rep.candidates[0].marker) == 8 and len(rep.candidates[-1].marker) == 64
    assert rep.candidates[18].marker == sha("left:right")


def test_the_flag_is_the_marker_in_the_events_wrapper(prof):
    rep = search(ics_fields(), F8, wrap=mc.wrapper(prof))
    first = rep.candidates[0]
    assert first.flag == "CSCTF{" + first.marker + "}" and len(first.marker) == 8
    assert mc.wrapper(prof, nonstandard=True)("ab12") == "ab12"
    assert mc.wrapper(None)("ab12") == "ab12"


def test_a_search_that_cannot_run_says_why():
    with pytest.raises(mc.MarkerError, match="no fields"):
        search([], F8)
    with pytest.raises(mc.MarkerError, match="at most"):
        search([mc.make_field(f"f{i}", f"v{i}") for i in range(RC.COMPOSE_MAX_FIELDS + 1)], F8)
    with pytest.raises(mc.MarkerError, match="at least 1"):
        search(ics_fields(), F8, budget=0)


# ------------------------------------------------------------------------------------- knowledge base

def test_an_accepted_convention_is_recorded_with_what_it_teaches():
    rows = mc.learn("ICS", ICS_CONV, "accepted", kinds=ICS_KINDS, challenge_id="77")
    assert rows == [("marker.convention/ics#candidates", ICS_CONV), ("marker.join/ics", "colon"),
                    ("marker.digest/ics", "sha256[:8]"), ("marker.render/tag.ics", "hex_0x_upper")]
    kb = mc.KB()
    assert kb.available and kb.accepted("ics") == [ICS_CONV] and kb.rejected("ics") == set()
    assert kb.joins() == ["colon"] and kb.digests() == ["sha256[:8]"]
    assert kb.renders("tag") == ["hex_0x_upper"] and kb.renders("hexid") == [] and kb.renders("timestamp") == []
    assert kb.families() == ["ics"] and kb.accepted("networking") == []
    ledger = (labels.challenges_root() / "_ledger" / "marker.jsonl").read_text(encoding="utf-8")
    written = [json.loads(line) for line in ledger.splitlines()]
    assert [(r["key"], r["name"], r["verdict"], r["attempt_id"]) for r in written] == [
        (k, n, "accepted", "77") for k, n in rows]


def test_a_role_with_no_kind_teaches_no_rendering():
    rows = mc.learn("ics", ICS_CONV, "accepted")
    assert [k for k, _ in rows] == ["marker.convention/ics#candidates", "marker.join/ics", "marker.digest/ics"]
    assert mc.KB().renders("tag") == []


def test_an_accepted_convention_answers_a_sibling_alone(prof):
    truth = sha(SIBLING_TEXT)[:8]
    before = search(sibling_fields(), F8, family="ics", wrap=mc.wrapper(prof))
    assert before.candidates[0].basis == "prior" and before.candidates[0].marker != truth
    assert truth not in [c.marker for c in before.candidates]
    mc.learn("ics", ICS_CONV, "accepted", kinds=ICS_KINDS)
    after = search(sibling_fields(), F8, family="ics", wrap=mc.wrapper(prof))
    first = after.candidates[0]
    assert (first.basis, first.marker, first.preimage, first.convention) == ("kb", truth, SIBLING_TEXT, ICS_CONV)
    assert "family ics" in first.detail and after.supported
    assert mc.pick(after) == (["CSCTF{" + truth + "}"], None)


def test_what_one_family_taught_is_tried_first_in_another():
    mc.learn("ics", ICS_CONV, "accepted", kinds=ICS_KINDS)
    rep = search(sibling_fields(), F8, family="energy")
    first = rep.candidates[0]
    assert first.basis == "prior" and first.marker == sha(SIBLING_TEXT)[:8]       # no convention for `energy`
    assert first.convention == ICS_CONV and not rep.supported
    # a join learned later leads the joins
    mc.learn("drone", "sha256[:8];pipe;a=as_stored,b=as_stored", "accepted")
    assert mc.KB().joins() == ["colon", "pipe"]
    mc.learn("ics", VERBATIM_CONV, "rejected")
    assert mc.KB().joins() == ["colon", "pipe"], "a rejection teaches no join"


def test_a_learned_join_and_digest_form_lead_their_axes():
    pair = [mc.make_field("a", "left", "text"), mc.make_field("b", "right", "text")]
    before = search(pair)
    assert before.digests == ["sha256[:8]", "sha256"] and before.candidates[0].marker == sha("left:right")[:8]
    mc.learn("drone", "sha256;pipe;x=as_stored,y=as_stored", "accepted")
    after = search(pair, family="other")
    assert after.digests == ["sha256", "sha256[:8]"]
    assert [c.marker for c in after.candidates[:2]] == [sha("left|right"), sha("left:right")]
    assert after.candidates[0].convention == "sha256;pipe;a=as_stored,b=as_stored"
    # a stated digest form is the caller's: the knowledge base adds none
    assert search(pair, F8, family="other").digests == ["sha256[:8]"]


def test_an_accepted_convention_keeps_its_own_digest_when_no_cut_is_stated():
    pair = [mc.make_field("a", "left", "text"), mc.make_field("b", "right", "text")]
    mc.learn("legacy", "md5[:8];colon;a=as_stored,b=as_stored", "accepted")
    rep = search(pair, family="legacy")                # no digest given: sha256[:8] and sha256 are defaults
    first = rep.candidates[0]
    assert rep.digests == ["sha256[:8]", "sha256"]                      # md5 is not among the defaults
    assert (first.basis, first.marker) == ("kb", hashlib.md5(b"left:right").hexdigest()[:8])
    # and when the stated forms include the convention's own, it is the accepted convention as it is
    both = search(pair, [mc.DigestForm.parse("sha256[:16]"), mc.DigestForm.parse("md5[:8]")], family="legacy")
    assert (both.candidates[0].basis, both.candidates[0].marker) == ("kb", first.marker) and both.supported


def test_a_stated_digest_recuts_an_accepted_convention_and_that_is_a_guess(prof):
    """The judge's yes was for sha256[:8]. A brief (or the caller) that states 16 hex is about THIS
    challenge: no candidate may be cut the remembered way. What carries over is the fields, their
    order and renderings, listed first, as a guess: not backed, so not the reasoned value."""
    mc.learn("ics", ICS_CONV, "accepted", kinds=ICS_KINDS)
    f16 = mc.DigestForm.parse("sha256[:16]")
    recut = ICS_CONV.replace("sha256[:8]", "sha256[:16]")
    rep = search(sibling_fields(), [f16], family="ics", wrap=mc.wrapper(prof))
    first = rep.candidates[0]
    assert (first.basis, first.marker, first.preimage, first.convention) == (
        "kb-recut", sha(SIBLING_TEXT)[:16], SIBLING_TEXT, recut)
    assert first.detail == ("the judge accepted these fields, order and renderings for family ics under "
                            "sha256[:8]; the digest stated here is sha256[:16]")
    assert all(len(c.marker) == 16 for c in rep.candidates) and not any(c.basis == "kb" for c in rep.candidates)
    assert (f"the judge accepted {ICS_CONV} for family ics, but the digest stated here is sha256[:16]: its "
            "fields, order and renderings are listed under sha256[:16] as a guess (kb-recut), not under "
            "sha256[:8]") in rep.notes
    assert not rep.supported
    flags, unsure = mc.pick(rep)
    assert flags[0] == "CSCTF{" + sha(SIBLING_TEXT)[:16] + "}" and len(flags) == labels.MAX_OPTIONS and unsure
    assert not mc.send_plan(rep, prof, 3).reasoned
    # several stated forms, none the convention's own: one recut for each, in their order
    two = search(sibling_fields(), [mc.DigestForm.parse("md5[:8]"), f16], family="ics")
    assert [(c.basis, c.marker) for c in two.candidates[:2]] == [
        ("kb-recut", hashlib.md5(SIBLING_TEXT.encode()).hexdigest()[:8]), ("kb-recut", sha(SIBLING_TEXT)[:16])]
    assert [c.basis for c in two.candidates[2:]] == ["prior"] * (mc.DEFAULT_TOP - 2)
    # the judge's no to the recut convention is kept like any other
    mc.learn("ics", recut, "rejected")
    again = search(sibling_fields(), [f16], family="ics")
    assert sha(SIBLING_TEXT)[:16] not in [c.marker for c in again.candidates]
    assert any("1 candidate(s) left out" in n for n in again.notes)


def test_solve_under_a_stated_cut_is_unsure_where_the_remembered_cut_was_a_candidate(case, prof):
    mc.learn("ics", ICS_CONV, "accepted", kinds=ICS_KINDS)
    specs = ["header:tag=KLM2", "station=0x19AF", "timestamp=2032-06-07T08:09:10Z", "register=41000", "seed=5"]
    same = mc.solve(case, prof, fields=specs, family="ics", digest="sha256[:8]", budget=BUDGET)
    other = mc.solve(case, prof, fields=specs, family="ics", digest="sha256[:16]", budget=BUDGET)
    assert (same.status, same.flags) == ("candidate", ("CSCTF{" + sha(SIBLING_TEXT)[:8] + "}",))
    assert other.status == "unsure" and other.flags[0] == "CSCTF{" + sha(SIBLING_TEXT)[:16] + "}"
    assert all(len(f) == len("CSCTF{}") + 16 for f in other.flags) and "kb-recut" in other.evidence[0].detail


def test_each_rendering_is_taught_once_per_kind():
    conv = "sha256[:16];none;approved_lat=dp_4,approved_lon=dp_4,delta_lat=dp_6,delta_lon=dp_6,distance=dp_1"
    rows = mc.learn("forensics", conv, "accepted", kinds={r: "decimal" for r in mc.Convention.parse(conv).roles})
    assert rows[3:] == [("marker.render/decimal.forensics", "dp_4"), ("marker.render/decimal.forensics", "dp_6"),
                        ("marker.render/decimal.forensics", "dp_1")]
    assert mc.KB().renders("decimal") == ["dp_4", "dp_6", "dp_1"]


def test_an_accepted_convention_whose_role_is_missing_is_named_not_guessed():
    mc.learn("ics", ICS_CONV, "accepted", kinds=ICS_KINDS)
    rep = search(sibling_fields()[:4], F8, family="ics")
    assert not any(c.basis == "kb" for c in rep.candidates)
    assert any("no field named seed" in n for n in rep.notes)


def test_a_rejected_convention_is_no_longer_offered_for_its_family():
    assert search(ics_fields(), F8, family="ics").candidates[0].convention == VERBATIM_CONV
    assert mc.learn("ics", VERBATIM_CONV, "rejected") == [("marker.convention/ics#candidates", VERBATIM_CONV)]
    rep = search(ics_fields(), F8, family="ics")
    assert VERBATIM_CONV not in [c.convention for c in rep.candidates]
    assert any("1 candidate(s) left out" in n and "rejected" in n for n in rep.notes)
    assert len(rep.candidates) == mc.DEFAULT_TOP                        # the list is still full
    assert mc.KB().rejected("ics") == {VERBATIM_CONV}
    assert search(ics_fields(), F8, family="other").candidates[0].convention == VERBATIM_CONV


def test_a_strong_witness_keeps_a_convention_the_family_rejected_on_other_values(monkeypatch):
    mc.learn("ics", VERBATIM_CONV, "rejected")                # the judge said no for another challenge's values
    verbatim = "KLM2:0x19AF:2032-06-07T08:09:10Z:41000:5"      # this sibling's files carry a tag for exactly that
    full = sha(verbatim)
    plain = search(sibling_fields(), F8, family="ics")
    assert full[:8] not in [c.marker for c in plain.candidates]
    assert any("1 candidate(s) left out" in n for n in plain.notes)
    rep = search(sibling_fields(), F8, family="ics", witnesses=[mc.Witness(full[-8:], "suffix", "log:tag")])
    first = rep.candidates[0]
    assert (first.basis, first.marker, first.preimage, first.convention) == ("witness", full[:8], verbatim,
                                                                             VERBATIM_CONV)
    assert rep.witness_hits == 1 and rep.supported
    assert "the judge rejected this convention for family ics on other values" in first.detail
    assert ("1 candidate(s) kept although the judge rejected their convention for family ics: a strong "
            "witness in this challenge's own files confirms them") in rep.notes
    assert not any("left out" in n for n in rep.notes)        # it is listed once, as the witness hit
    assert [c.marker for c in rep.candidates].count(full[:8]) == 1
    # a hit that chance could explain is not this challenge's answer: the rejection stands
    monkeypatch.setattr(mc, "CHANCE_LIMIT", 1e-9)
    weak = search(sibling_fields(), F8, family="ics", witnesses=[mc.Witness(full[-8:], "suffix")])
    assert weak.witness_hits == 1 and full[:8] not in [c.marker for c in weak.candidates]
    assert not weak.supported and any("1 candidate(s) left out" in n for n in weak.notes)
    assert not any("kept although" in n for n in weak.notes)


def test_without_a_judge_ledger_the_knowledge_base_is_named_as_unread(monkeypatch):
    mc.learn("ics", ICS_CONV, "accepted", kinds=ICS_KINDS)
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "off")
    kb = mc.KB()
    assert not kb.available and "no judge ledger" in kb.reason
    assert kb.accepted("ics") == [] and kb.joins() == [] and kb.families() == [] and kb.rejected("ics") == set()
    with pytest.raises(mc.MarkerError, match="no judge ledger"):
        mc.learn("ics", ICS_CONV, "accepted")
    rep = search(sibling_fields(), F8, family="ics")
    assert not rep.kb_available and any("no judge ledger" in n for n in rep.notes)
    assert rep.candidates[0].basis == "prior"
    flags, unsure = mc.pick(rep)
    assert flags == [c.flag for c in rep.candidates[:labels.MAX_OPTIONS]] and unsure is None


def test_an_unreadable_knowledge_base_is_reported_not_raised(monkeypatch):
    def boom(prefix):
        raise RuntimeError("no event workdir")
    monkeypatch.setattr(labels, "keys", boom)
    kb = mc.KB()
    assert not kb.available and "cannot be read: no event workdir" in kb.reason
    rep = search(ics_fields(), F8, kb=kb)
    assert rep.candidates and any("no event workdir" in n for n in rep.notes)


def test_learn_refuses_what_it_cannot_record(monkeypatch):
    with pytest.raises(mc.MarkerError, match="accepted or rejected"):
        mc.learn("ics", ICS_CONV, "maybe")
    with pytest.raises(mc.MarkerError, match="write <digest>"):
        mc.learn("ics", "colon-join of everything", "accepted")
    with pytest.raises(mc.MarkerError, match="unknown kind"):
        mc.learn("ics", ICS_CONV, "accepted", kinds={"header": "blob"})
    monkeypatch.setattr(labels, "learn", lambda *a, **k: False)
    with pytest.raises(mc.MarkerError, match="did not take"):
        mc.learn("ics", ICS_CONV, "accepted")


def test_the_seed_fold_carries_a_learned_convention_into_the_tracked_seed(_empty_kb):
    mc.learn("ics", ICS_CONV, "accepted", kinds=ICS_KINDS)
    changed = seedfold.fold_all(["marker"], labels_mod=labels)
    assert len(changed["marker"]) == 4
    seed = json.loads((_empty_kb / "marker.json").read_text(encoding="utf-8"))
    assert seed["marker.convention/ics#candidates"]["accepted"] == ICS_CONV
    assert seed["marker.render/tag.ics"]["accepted"] == "hex_0x_upper"
    (labels.challenges_root() / "_ledger" / "marker.jsonl").unlink()      # the next event: the seed alone
    labels._cache.clear()
    assert mc.KB().accepted("ics") == [ICS_CONV] and mc.KB().renders("tag") == ["hex_0x_upper"]


def test_the_marker_lane_is_a_labels_lane_with_its_own_seed_folder():
    assert "marker" in labels.TOOLKIT_PREFIXES and labels.LANE_DIRS["marker"] == "toolkits/seeds/marker"
    assert mc.convention_key(" ICS ") == "marker.convention/ics#candidates"
    assert mc.family_name(None) == "any" and mc.family_name("Operational Security") == "operational_security"
    labels.learn("marker.join/x", "colon", "accepted")
    labels.learn("marker.convention/x" + labels.CANDIDATE_MARK, "c", "rejected")
    assert labels.keys("marker.") == ["marker.join/x", "marker.convention/x#candidates"]
    assert labels.keys("marker.join/") == ["marker.join/x"] and labels.keys("binary.") == []


# ------------------------------------------------------------------------------------- the pick

def test_the_pick_is_a_bounded_unsure_answer_until_the_judge_accepts_a_convention():
    rep = search(ics_fields(), F8, family="ics")
    flags, unsure = mc.pick(rep)
    assert flags == [c.flag for c in rep.candidates[:12]] and len(rep.candidates) > 12
    parsed = labels.parse(unsure)
    assert parsed.key == "marker.convention/ics#candidates" and labels.is_candidate(unsure)
    assert parsed.options == [(c.convention, c.flag) for c in rep.candidates[:12]]
    assert mc.pick(mc.Report("ics", [], [], [], [], 0, 0, 0, True)) == ([], None)


def test_a_strong_witness_outranks_the_familys_accepted_convention():
    mc.learn("ics", VERBATIM_CONV, "accepted")                         # the family's memory says verbatim
    full = sha(ICS_TEXT)
    rep = search(ics_fields(), F8, family="ics", witnesses=[mc.Witness(full[-8:], "suffix")])
    assert [c.basis for c in rep.candidates[:2]] == ["witness", "kb"]
    flags, unsure = mc.pick(rep)
    assert flags[0] == full[:8] and flags[1] == sha("ZQX7:0x7B1C:2031-02-03T04:05:06Z:30007:911")[:8]
    assert len(flags) == 12 and unsure is None


# ------------------------------------------------------------------------------------- the guess-budget plan

def test_an_unbacked_list_is_all_guesses_under_the_budget(prof):
    rep = search(ics_fields(), F8, wrap=mc.wrapper(prof))
    flags = tuple(c.flag for c in rep.candidates)
    plan = mc.send_plan(rep, prof, 0)
    assert (plan.send, plan.held, plan.reasoned, plan.guesses_left) == ((), flags, False, 0)
    plan = mc.send_plan(rep, prof, 3)
    assert plan.send == flags[:3] and plan.held == flags[3:]
    assert mc.send_plan(rep, prof, 1).send == flags[:1]


def test_a_backed_first_candidate_is_the_reasoned_value_and_the_rest_are_guesses(prof):
    rep = search(ics_fields(), F8, wrap=mc.wrapper(prof),
                    witnesses=[mc.Witness(sha(ICS_TEXT)[-8:], "suffix")])
    flags = tuple(c.flag for c in rep.candidates)
    assert flags[0] == "CSCTF{" + sha(ICS_TEXT)[:8] + "}"
    plan = mc.send_plan(rep, prof, 0)
    assert (plan.send, plan.held, plan.reasoned) == (flags[:1], flags[1:], True)
    plan = mc.send_plan(rep, prof, 2)
    assert plan.send == flags[:3] and plan.held == flags[3:]
    assert plan.to_dict() == {"send": list(flags[:3]), "held": list(flags[3:]), "reasoned": True, "guesses_left": 2}


def test_the_plan_is_cut_by_flagchecks_variant_set(prof, monkeypatch):
    calls = []
    real = flagcheck.VariantSet.plan

    def spy(self, guesses_left, allow_nonstandard=False):
        calls.append((guesses_left, [v.value for v in self.ranked]))
        return real(self, guesses_left, allow_nonstandard)

    monkeypatch.setattr(flagcheck.VariantSet, "plan", spy)
    backed = search(ics_fields(), F8, wrap=mc.wrapper(prof), witnesses=[mc.Witness(sha(ICS_TEXT)[-8:], "suffix")])
    unbacked = search(ics_fields(), F8, wrap=mc.wrapper(prof))
    mc.send_plan(backed, prof, 2)
    mc.send_plan(unbacked, prof, 2)
    mc.send_plan(unbacked, prof, 0)                                  # nothing may go out: no cut to make
    assert [n for n, _ in calls] == [2, 1]
    assert calls[0][1] == [c.flag for c in backed.candidates]


def test_a_value_outside_the_flag_format_is_never_planned(prof):
    bare = search(ics_fields(), F8, witnesses=[mc.Witness(sha(ICS_TEXT)[-8:], "suffix")])   # no wrapper
    assert mc.send_plan(bare, prof, 5) == mc.Plan((), (), True, 5)
    allowed = mc.send_plan(bare, prof, 1, allow_nonstandard=True)
    assert allowed.send == tuple(c.flag for c in bare.candidates[:2]) and len(allowed.held) == len(bare.candidates) - 2
    for bad in (-1, True, "3", 1.5):
        with pytest.raises(mc.MarkerError, match="guesses_left"):
            mc.send_plan(bare, prof, bad)
    assert mc.send_plan(mc.Report("ics", [], [], [], [], 0, 0, 0, True), prof, 3) == mc.Plan((), (), False, 3)


# ------------------------------------------------------------------------------------- the engine entry

def test_solve_with_named_fields_and_a_witness_is_a_candidate_never_solved(case, prof):
    full = sha(ICS_TEXT)
    specs = ["header:tag=ZQX7", "station=0x7B1C", "timestamp=2031-02-03T04:05:06Z",
             {"name": "register", "value": 30007}, "seed=911"]
    res = mc.solve(case, prof, fields=specs, witness=full[-8:] + "@suffix", digest="sha256[:8]",
                   family="ics", challenge_id=9001, budget=BUDGET)
    assert isinstance(res, SolverResult) and res.status == "candidate"
    assert res.flags[0] == "CSCTF{" + full[:8] + "}" and len(res.flags) == 12
    assert (res.engine, res.challenge_id) == ("common.marker_convention", "9001")
    assert res.evidence[0].kind == "witness" and ICS_CONV in res.evidence[0].detail
    assert repr(ICS_TEXT) in res.evidence[0].detail and res.evidence[1].kind == "convention"
    assert "candidates only" in res.notes and "family ics" in res.notes
    assert SolverResult.from_json(res.to_json()) == res


def test_solve_ranked_by_priors_alone_is_unsure(case, prof):
    res = mc.solve(case, prof, fields=["a=left", "b=right"])
    assert res.status == "unsure" and res.flags[0] == "CSCTF{" + sha("left:right")[:8] + "}"
    assert all(e.kind == "convention" for e in res.evidence)


def test_solve_backed_by_the_knowledge_base_is_one_candidate(case, prof):
    mc.learn("ics", ICS_CONV, "accepted", kinds=ICS_KINDS)
    specs = ["header:tag=KLM2", "station=0x19AF", "timestamp=2032-06-07T08:09:10Z", "register=41000", "seed=5"]
    res = mc.solve(case, prof, fields=specs, family="ics", digest=["sha256[:8]"], budget=BUDGET)
    assert res.status == "candidate" and res.flags == ("CSCTF{" + sha(SIBLING_TEXT)[:8] + "}",)


def test_solve_never_says_solved_even_with_one_backed_flag(case, prof):
    """The engine's own status. This is NOT what keeps a guess from intake's auto-submit: intake gives
    its own status to an engine's flags (one distinct flag is `solved`). What keeps it out is that the
    engine does not run at intake at all: tests/test_common_marker_intake.py."""
    mc.learn("ics", ICS_CONV, "accepted", kinds=ICS_KINDS)
    specs = ["header:tag=KLM2", "station=0x19AF", "timestamp=2032-06-07T08:09:10Z", "register=41000", "seed=5"]
    one = mc.solve(case, prof, fields=specs, family="ics", digest="sha256[:8]", budget=BUDGET)
    many = mc.solve(case, prof, fields=specs, family="other", digest="sha256[:8]", budget=BUDGET,
                    witness=sha(SIBLING_TEXT)[-8:])
    assert len(one.flags) == 1 and len(many.flags) > 1 and many.flags[0] == one.flags[0]
    assert (one.status, many.status) == ("candidate", "candidate")


@pytest.mark.parametrize("opts,why", [
    ({"fields": ["novalue"]}, "name\\[:kind\\]=value"),
    ({"fields": ["a=1", "a=2"]}, "share a name"),
    ({"fields": ["a=1"], "budget": "lots"}, "option budget must be a whole number"),
    ({"fields": ["a=1"], "digest": "sha7"}, "digest form"),
    ({"fields": ["a=1"], "witness": "xyz"}, "8 hex"),
    ({"max_fields": 99}, "max_fields must be"),
    ({"fields": [f"f{i}=v{i}" for i in range(11)]}, "at most"),
], ids=["spec", "dup", "budget", "digest", "witness", "max-fields", "too-many"])
def test_solve_is_blocked_by_a_bad_option_and_names_it(case, prof, opts, why):
    import re
    res = mc.solve(case, prof, **opts)
    assert res.status == "blocked" and not res.flags and re.search(why, res.notes), res.notes


def test_solve_is_blocked_without_the_challenge_folder(case, prof):
    res = mc.solve(case / "missing", prof, fields=["a=1"])
    assert mc.solve(case, prof).status == "none"                        # an empty folder: nothing to build from
    assert res.status == "blocked" and "challenge folder not found" in res.notes


def test_solve_options_shape_the_search(case, prof):
    base = dict(fields=["a=left", "b=right", "c=mid"], digest="sha256[:8]")
    kept = mc.solve(case, prof, permute="false", max_deviations=0, min_fields=3, **base)
    assert "9 of 9 compositions hashed" in kept.notes                   # one order, nine joins
    assert "54 of 54 compositions hashed" in mc.solve(case, prof, max_deviations=0, min_fields=3, **base).notes
    cut = mc.solve(case, prof, budget=4, top=2, **base)
    assert "4 of " in cut.notes and len(cut.flags) == 2 and "not checked" in cut.notes
    bare = mc.solve(case, prof, nonstandard=True, **base)
    assert bare.flags[0] == sha("left:right:mid")[:8]
    assert mc.solve(case, None, **base).flags[0] == sha("left:right:mid")[:8]      # no profile: no wrapper
