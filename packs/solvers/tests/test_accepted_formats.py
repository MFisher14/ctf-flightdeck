"""B-218: the metadata lane's accepted-format catalog and the pre-event vocabulary harvest.

Every judged attempt here is synthetic, written into tmp_path (outside the checkout) by the test. The
one test that reads a real corpus is gated on $CTF_REAL_CHALLENGES and reported not run without it.
"""
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from ctf import packs, paths

ROOT = paths.repo_root()
LANE = ROOT / "solvers" / "metadata-forensics"
for _p in (str(ROOT / "solvers" / "common"), str(LANE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# The names format_candidates.pick itself loads the catalog module under, so a patched DEFAULT_PATH
# is the one pick reads.
AF = packs.load_module("metadata_accepted_formats", LANE / "accepted_formats.py")
FC = packs.load_module("metadata_format_candidates_b218", LANE / "format_candidates.py")
import labels  # noqa: E402

HEX0X = {"kind": "pattern", "syntax": "lowercase hexadecimal with a 0x prefix and no explanatory text"}
BASE10 = {"kind": "integer", "syntax": "base-10 integer with no units, separators, or explanatory text"}
JSON_ARR = {"kind": "json", "syntax": "compact valid JSON array with exact values and order; no Markdown"}
GUID_HY = {"kind": "pattern", "syntax": "canonical GUID text in 8-4-4-4-12 hexadecimal form, including hyphens"}
EXACT = {"kind": "exact_text", "syntax": "exact artifact-derived value only"}


@pytest.fixture(autouse=True)
def no_judge(monkeypatch):
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "off")


def entry(kind, accepted=None, consistent=None, rejected=(), opts=None, unclassified=0):
    return AF.Entry(kind=kind, opts=dict(opts or {}), accepted=Counter(accepted or {}),
                    consistent=Counter(consistent or {}), rejected=set(rejected), asked=1,
                    unclassified=unclassified)


def catalog(**props):
    return AF.Catalog(properties={k.replace("__", "."): v for k, v in props.items()},
                      syntax={AF.norm_phrase(HEX0X["syntax"]): {"answer_kind": "pattern", "asked": 1}})


# ------------------------------------------------------------------ format_candidates additions

def test_render_all_keeps_coinciding_names_that_render_dedups():
    raw = FC.render_all(0x14C, "integer", width_bits=16)
    assert ("hex_0x_padded", "0x014c") in raw and ("hex_0x_byte", "0x014c") in raw
    deduped = FC.render(0x14C, "integer", width_bits=16)
    assert [v for _, v in deduped].count("0x014c") == 1
    assert FC.render_all(1, "no-such-kind") == [] and FC.render_all("x", "integer") == []


def test_kind_names_lists_every_hypothesis_of_a_kind():
    assert FC.kind_names("integer") == ("integer", "hex_0x_padded", "hex_0x", "hex_0x_byte", "hex_bare")
    assert FC.kind_names("list")[-1] == "sorted+json" and len(FC.kind_names("list")) == 8
    assert FC.kind_names("version") == ("dotted", "dotted_trimmed", "minor_2_digits")
    assert "as_stored" not in FC.kind_names("guid")
    assert FC.kind_names("nope") == ()


def test_order_puts_prefer_first_and_last_last_dropping_nothing():
    opts = [("a", "1"), ("b", "2"), ("c", "3"), ("d", "4"), ("e", "5")]
    out = FC.order(opts, prefer=["d", "b", "zz"], last=["e", "a", "b"])
    # b is in both: last wins; e then a keep last's order; zz (no such option) adds nothing
    assert out == [("d", "4"), ("c", "3"), ("e", "5"), ("a", "1"), ("b", "2")]
    assert FC.order(opts, names_only=True) == ["a", "b", "c", "d", "e"]


def test_ranked_without_a_catalog_is_render_order():
    assert FC.ranked(1024, "integer", catalog=False) == FC.render(1024, "integer")
    got = FC.ranked(0x14C, "integer", catalog=False, width_bits=16)       # two names render 0x014c: one kept
    assert got == FC.render(0x14C, "integer", width_bits=16) and len(got) == 4


def test_ranked_follows_the_property_and_keeps_the_preferred_name_of_a_shared_value():
    cat = catalog(pe__coff_machine_u16_hex=entry("integer", {"hex_0x_byte": 3}, opts={"width_bits": 16}))
    got = FC.ranked(0x14C, "integer", key="metadata.format/pe.coff_machine_u16_hex#candidates", catalog=cat,
                    width_bits=16)
    assert got[0] == ("hex_0x_byte", "0x014c")
    assert "hex_0x_padded" not in [n for n, _ in got]       # same text as the preferred name: one option
    plain = FC.ranked(0x14C, "integer", catalog=False, width_bits=16)
    assert plain[1] == ("hex_0x_padded", "0x014c")             # without the catalog the padded name wins


def test_ranked_puts_what_the_answer_format_rules_out_last():
    cat = AF.Catalog()
    got = FC.ranked(0x3E, "integer", prop="new.thing_u16_hex", catalog=cat, answer_format=HEX0X, width_bits=16)
    names = [n for n, _ in got]
    assert names[-2:] == ["integer", "hex_bare"]
    assert names[0] == "hex_0x_padded"


def test_pick_is_a_candidate_never_plain_and_leads_with_the_accepted_name():
    cat = catalog(msi__product_code_guid=entry("guid", {"braces_upper": 5}, rejected={"hyphen_lower"}))
    got = FC.pick("metadata.format/msi.product_code_guid", bytes(range(16)), "guid", catalog=cat)
    assert labels.is_unsure(got) and labels.is_candidate(got)
    opts = labels.parse(got).options
    assert opts[0][0] == "braces_upper" and opts[-1][0] == "hyphen_lower"
    assert opts[0][1] == "{00010203-0405-0607-0809-0A0B0C0D0E0F}"


def test_pick_reads_the_tracked_catalog_and_fails_loudly_without_it(monkeypatch, tmp_path):
    got = FC.pick("metadata.format/msi.product_code_guid", bytes(range(16)), "guid")
    assert labels.parse(got).options[0][0] == "braces_upper"       # the shipped catalog's judged form
    monkeypatch.setattr(AF, "DEFAULT_PATH", tmp_path / "gone.json")
    monkeypatch.setattr(AF, "_DEFAULT", {})
    with pytest.raises(AF.CatalogError, match="not found"):
        FC.pick("metadata.format/msi.product_code_guid", bytes(range(16)), "guid")


def test_the_lane_fc_candidates_path_uses_the_catalog(monkeypatch):
    from ctf.formats import matrix
    M = matrix.lane_module()
    got = M.fc_candidates("metadata.format/msi.product_code_guid", bytes(range(16)), "guid")
    assert labels.is_candidate(got)
    assert labels.parse(got).options[0][0] == "braces_upper"


@pytest.mark.parametrize("broken", ["missing", "corrupt"])
def test_the_lane_fc_candidates_path_fails_loudly_on_a_broken_catalog(monkeypatch, tmp_path, broken):
    # A missing or corrupt tracked catalog is a broken install: the lane's live path must raise the named
    # CatalogError, never return None ("nothing to offer") as it does for an unrenderable value.
    from ctf.formats import matrix
    M = matrix.lane_module()
    path = tmp_path / "accepted_formats.json"
    if broken == "corrupt":
        path.write_text("{ not json")
    monkeypatch.setattr(AF, "DEFAULT_PATH", path)
    monkeypatch.setattr(AF, "_DEFAULT", {})
    with pytest.raises(AF.CatalogError, match="not found" if broken == "missing" else "unreadable"):
        M.fc_candidates("metadata.format/msi.product_code_guid", bytes(range(16)), "guid")
    # an unrenderable value with a sound catalog is still a quiet None
    monkeypatch.setattr(AF, "DEFAULT_PATH", AF.HERE / "accepted_formats.json")
    assert M.fc_candidates("metadata.format/msi.product_code_guid", object(), "guid") is None


# ------------------------------------------------------------------ property names and kinds

def q(qid, text="", af=None, norm=None):
    out = {"id": qid, "question": text, "answer_format": af or {}}
    if norm is not None:
        out["normalization"] = norm
    return out


@pytest.mark.parametrize("question, want", [
    (q("anything", "Inspect `a.bin`. Determine pe.coff_machine_u16_hex for a.bin."), "pe.coff_machine_u16_hex"),
    (q("set2.d23-sqlite-001-sqlite-page-size-bytes", "no determine here"), "sqlite.page_size_bytes"),
    (q("roster-size-bytes", "Inspect `roster.csv`. What is its exact size in bytes?"), "size_bytes"),
    (q("evidence-note-copy-md5", "Inspect `evidence-note-copy-6c89c5.txt`. What is its MD5 digest?"), "md5"),
    (q("roster-filename", "What is the exact filename of the roster?"), "filename"),
    (q("roster-size-bytes", "What is its exact size in bytes?"), "size_bytes"),
    (q("roster-sha1", "What is its SHA-1 digest?"), "sha1"),
    (q("solo", "Determine nothing"), None),
    (q("mystery-thing", "Something unparseable."), None),             # `something` does not say `thing`
    (q("alpha-beta", "Unrelated words."), None),
])
def test_property_of(question, want):
    assert AF.property_of(question) == want


def test_property_of_uses_harvested_stem_fields_before_the_text():
    question = q("roster-magic-prefix-hex-16", "What are the first sixteen bytes as lowercase hexadecimal?")
    assert AF.property_of(question) is None
    assert AF.property_of(question, known_fields={"magic_prefix_hex_16", "hex_16"}) == "magic_prefix_hex_16"


@pytest.mark.parametrize("key, want", [
    ("metadata.format/pe.coff_machine_u16_hex", "pe.coff_machine_u16_hex"),
    ("metadata.sqlite/page_size_bytes", "sqlite.page_size_bytes"),
    ("metadata.macho/cpu_type_set+order#candidates", "macho.cpu_type_set"),
    ("metadata.nofield", None), (None, None),
])
def test_property_of_key(key, want):
    assert AF.property_of_key(key) == want


@pytest.mark.parametrize("prop, af, want", [
    ("pe.coff_machine_u16_hex", HEX0X, ("integer", {"width_bits": 16})),
    ("pe.address_of_entry_point_rva_hex", HEX0X, ("integer", {"width_bits": 32})),
    ("magic_prefix_hex_16", {"kind": "pattern"}, ("hex", {})),
    ("pe.image_base_hex", HEX0X, ("integer", {})),
    ("msi.product_code_guid", GUID_HY, ("guid", {})),
    ("dotnet.mvid", None, ("guid", {})),
    ("sha256", None, ("digest", {})),
    ("x509.sha256_fingerprint", EXACT, ("digest", {})),
    ("jpeg.sof_dimensions_pixels", EXACT, ("dims", {})),
    ("macho.cpu_type_set", JSON_ARR, ("list", {})),
    ("text.utf8_bom_present", {"kind": "enum", "accepted_values": ["true", "false"]}, ("bool", {})),
    ("eml.priority", {"kind": "enum", "accepted_values": ["low", "high"]}, None),
    ("pdf.header_version", EXACT, ("version", {})),
    ("pe.version_original_filename", EXACT, None),
    ("email.message_id", EXACT, ("message_id", {})),
    ("lnk.target_path_windows", EXACT, ("path", {})),
    ("zip.eocd_total_entries", BASE10, ("integer", {})),
    ("apk.package_name", EXACT, None),
])
def test_infer_kind(prop, af, want):
    assert AF.infer_kind(prop, af) == want


# ------------------------------------------------------------------ classifying a judged text

def test_classify_tells_a_padded_hex_only_when_the_value_shows_it():
    assert AF.classify("0x003e", "integer", width_bits=16) == {"hex_0x_padded"}
    assert AF.classify("0x014c", "integer", width_bits=16) == {"hex_0x_padded", "hex_0x_byte"}
    assert AF.classify("0x3e", "integer", width_bits=16) == {"hex_0x", "hex_0x_byte"}


def test_classify_narrows_by_the_judges_words_but_never_to_nothing():
    assert AF.classify("396", "integer") == {"integer", "hex_bare"}
    assert AF.classify("396", "integer", answer_format=BASE10) == {"integer"}
    # the judge accepted a text our reading of its words rules out: the verdict wins over the reading
    assert AF.classify("0x18c", "integer", answer_format=BASE10) == {"hex_0x"}


def test_classify_lists_sorted_text_is_degenerate_unsorted_is_document_order():
    assert AF.classify('["a","b"]', "list") == {"document_order+json", "sorted+json"}
    assert AF.classify('["only"]', "list") == {"document_order+json", "sorted+json"}
    assert AF.classify('["b","a"]', "list") == {"document_order+json"}
    assert AF.classify("b, a", "list") == {"document_order+comma_space"}
    assert AF.classify("[10,9]", "intlist") == {"document_order+json"}
    assert AF.classify("[9,10]", "intlist") == {"document_order+json", "sorted+json"}


@pytest.mark.parametrize("text, kind, want", [
    ("{21E410F3-C977-465C-80EB-6890DDD3085C}", "guid", {"braces_upper"}),
    ("21e410f3-c977-465c-80eb-6890ddd3085c", "guid", {"hyphen_lower"}),
    ("21e410f3c977465c80eb6890ddd3085c", "guid", {"compact_lower"}),
    ("C:\\Windows\\x.exe", "path", {"back_slash"}),
    ("x.exe", "path", {"forward_slash", "back_slash", "basename"}),
    ("<a@b>", "message_id", {"with_angle"}),
    ("a@b", "message_id", {"without_angle"}),
    ("464x283", "dims", {"x_lower"}),
    ("[464,283]", "dims", {"json"}),
    ("True", "bool", {"True_False"}),
    ("1.4", "version", {"dotted", "dotted_trimmed"}),
    ("1.04", "version", {"dotted", "dotted_trimmed", "minor_2_digits"}),
    ("utf8", "encoding", {"hyphen_lower", "compact_lower"}),
    ("UTF-8", "encoding", {"hyphen_upper"}),
    ("ABCDEF", "digest", {"upper"}),
    ("0400", "hex", {"hex_lower", "hex_upper"}),
    ("", "integer", set()),
    ("zzz", "integer", set()),
])
def test_classify_kinds(text, kind, want):
    assert AF.classify(text, kind) == want


def test_allows_reads_only_what_the_syntax_states():
    assert AF.allows("hex_0x", "integer", None) and AF.allows("hex_0x", "integer", {"kind": "pattern"})
    assert not AF.allows("hex_bare", "integer", HEX0X) and AF.allows("hex_0x_padded", "integer", HEX0X)
    assert not AF.allows("hex_0x", "integer", {"syntax": "hex, use no 0x prefix"})
    assert AF.allows("hex_bare", "integer", {"syntax": "hex, use no 0x prefix"})
    assert not AF.allows("hex_0x", "integer", BASE10)
    assert not AF.allows("hyphen_upper", "guid", {"syntax": "lowercase GUID"})
    assert not AF.allows("True_False", "bool", {"syntax": "lowercase"})
    assert not AF.allows("hyphen_lower", "guid", {"syntax": "UPPERCASE"})
    assert not AF.allows("compact_lower", "guid", GUID_HY) and AF.allows("braces_upper", "guid", GUID_HY)
    assert not AF.allows("braces_upper", "guid", {"syntax": "8-4-4-4-12 without braces"})
    assert not AF.allows("hyphen_lower", "guid", {"syntax": "a GUID in braces"})
    assert not AF.allows("sorted+comma", "list", JSON_ARR) and AF.allows("sorted+json", "list", JSON_ARR)
    asc = {"kind": "json", "syntax": "compact JSON array in ascending order"}
    assert not AF.allows("document_order+json", "list", asc) and AF.allows("sorted+json", "list", asc)
    filed = {"kind": "json", "syntax": "compact JSON array in file order"}
    assert not AF.allows("sorted+json", "list", filed) and AF.allows("document_order+json", "list", filed)
    comma = {"kind": "exact_text", "syntax": "comma-separated names with no spaces"}
    assert AF.allows("sorted+comma", "list", comma)
    assert not AF.allows("sorted+comma_space", "list", comma) and not AF.allows("sorted+json", "list", comma)
    yn = {"kind": "enum", "accepted_values": ["yes", "no"]}
    assert AF.allows("yes_no", "bool", yn) and not AF.allows("true_false", "bool", yn)


# ------------------------------------------------------------------ the catalog file

def test_catalog_round_trips_and_is_deterministic():
    cat = catalog(a__b_hex=entry("integer", {"hex_0x": 2}, {"hex_0x_byte": 1}, {"integer"}),
                  c__d=entry("list", consistent={"sorted+json": 4}))
    again = AF.Catalog.from_json(json.loads(cat.dumps()))
    assert again.dumps() == cat.dumps()
    assert again.properties["a.b_hex"].accepted == Counter({"hex_0x": 2})
    assert again.properties["a.b_hex"].rejected == {"integer"}


@pytest.mark.parametrize("mutate, why", [
    (lambda d: d.update(schema="other/1"), "schema"),
    (lambda d: d.update(extra=1), "unknown keys"),
    (lambda d: d["properties"]["a.b_hex"].update(kind="nope"), "not a format_candidates kind"),
    (lambda d: d["properties"]["a.b_hex"].update(accepted={"braces_upper": 1}), "not integer hypotheses"),
    (lambda d: d["properties"]["a.b_hex"].update(accepted={"hex_0x": 0}), "positive integer"),
    (lambda d: d["properties"]["a.b_hex"].update(split=True), "split does not match"),
    (lambda d: d["properties"]["a.b_hex"].update(opts={"width_bits": 12}), "width_bits"),
    (lambda d: d["properties"]["a.b_hex"].pop("sources"), "missing keys"),
    (lambda d: d["properties"]["a.b_hex"].update(asked=-1), "asked must be a count"),
    (lambda d: d["syntax"].update({"Not Normal": {"answer_kind": "x", "asked": 1}}), "normalised"),
    (lambda d: d.update(unparsed="x"), "unparsed must be a list"),
])
def test_a_broken_catalog_is_refused_with_its_reason(mutate, why):
    raw = json.loads(catalog(a__b_hex=entry("integer", {"hex_0x": 2})).dumps())
    mutate(raw)
    with pytest.raises(AF.CatalogError, match=why):
        AF.Catalog.from_json(raw)


def test_load_names_a_missing_or_unreadable_file(tmp_path):
    with pytest.raises(AF.CatalogError, match="not found"):
        AF.Catalog.load(tmp_path / "none.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(AF.CatalogError, match="unreadable"):
        AF.Catalog.load(bad)


def test_the_tracked_catalog_loads_and_holds_judged_renderings():
    cat = AF.Catalog.load()
    assert cat.lane == "metadata-forensics" and len(cat.properties) >= 10
    assert all(e.asked > 0 for e in cat.properties.values())
    assert cat.properties["msi.product_code_guid"].accepted.most_common(1)[0][0] == "braces_upper"


def test_load_default_rereads_the_file_when_it_changes(monkeypatch, tmp_path):
    path = tmp_path / "cat.json"
    catalog(a__x=entry("integer", {"integer": 1})).save(path)
    monkeypatch.setattr(AF, "DEFAULT_PATH", path)
    monkeypatch.setattr(AF, "_DEFAULT", {})
    first = AF.load_default()
    assert AF.load_default() is first                                   # unchanged: the cached object
    catalog(a__x=entry("integer", {"integer": 1}), b__long_name=entry("bool", {"true_false": 7})).save(path)
    assert set(AF.load_default().properties) == {"a.x", "b.long_name"}


def test_merge_sums_evidence_and_refuses_two_kinds_for_one_property():
    a = catalog(p__x=entry("integer", {"integer": 2}))
    b = catalog(p__x=entry("integer", {"integer": 3}, rejected={"hex_bare"}), p__y=entry("bool", {"true_false": 1}))
    m = a.merge(b)
    assert m.properties["p.x"].accepted["integer"] == 5 and m.properties["p.x"].rejected == {"hex_bare"}
    assert m.properties["p.y"].accepted == Counter({"true_false": 1})
    assert a.properties["p.x"].accepted["integer"] == 2              # merge does not change its inputs
    phrase = AF.norm_phrase(HEX0X["syntax"])
    assert m.syntax[phrase]["asked"] == 2
    with pytest.raises(AF.CatalogError, match="kind"):
        a.merge(catalog(p__x=entry("digest", {"lower": 1})))


# ------------------------------------------------------------------ preference (the probe order)

def test_preference_own_evidence_then_class_then_kind():
    cat = catalog(a__one_u16_hex=entry("integer", {"hex_0x_padded": 1}, opts={"width_bits": 16}),
                  b__count=entry("integer", {"integer": 1}),
                  c__other_count=entry("integer", {"integer": 1}))
    # a new u16 hex: its class (integer/hex/16) says padded, beating the kind's two `integer` votes
    prefer, last = cat.preference("z.new_u16_hex", "integer", {"width_bits": 16})
    assert prefer[0] == "hex_0x_padded" and prefer[1] == "integer" and last == []
    # a new property of another class: the kind's votes alone
    prefer, _ = cat.preference("z.new_size", "integer", {})
    assert prefer == ["integer", "hex_0x_padded"]


def test_preference_counts_one_vote_per_property_not_per_answer():
    cat = catalog(a__x=entry("list", {"document_order+json": 500}),
                  b__y=entry("list", {"sorted+json": 1}), c__z=entry("list", {"sorted+json": 1}))
    prefer, _ = cat.preference("new.list_thing", "list")
    assert prefer[0] == "sorted+json"


def test_preference_breaks_a_tie_with_the_class():
    cat = catalog(pe__m_u16_hex=entry("integer", consistent={"hex_0x_byte": 9, "hex_0x_padded": 9},
                                      opts={"width_bits": 16}),
                  elf__m_u16_hex=entry("integer", {"hex_0x_padded": 3}, opts={"width_bits": 16}))
    prefer, _ = cat.preference("pe.m_u16_hex", "integer", {"width_bits": 16})
    assert prefer[:2] == ["hex_0x_padded", "hex_0x_byte"]


def test_a_split_property_has_no_preference_of_its_own_and_refused_names_go_last():
    split = entry("guid", {"braces_upper": 2}, rejected={"braces_upper", "compact_lower"})
    assert split.split
    cat = catalog(m__g_guid=split)
    prefer, last = cat.preference("m.g_guid", "guid", answer_format=GUID_HY)
    assert "braces_upper" not in prefer
    assert last == ["compact_lower", "compact_upper"]               # the syntax's, then the refused (deduped)
    clean = catalog(m__g_guid=entry("guid", {"hyphen_upper": 1}, rejected={"braces_lower"}))
    order = clean.probe_order("m.g_guid", "guid", {}, GUID_HY)
    assert order[0] == "hyphen_upper"
    assert order[-3:] == ["compact_lower", "compact_upper", "braces_lower"]


def test_a_split_property_does_not_vote_in_class_or_kind_priors():
    # b.two_u16_hex is split (hex_0x_byte both accepted and refused): its accepts, hex_bare among them,
    # must not reach another property of its class or kind.
    split = entry("integer", {"hex_bare": 3, "hex_0x_byte": 1}, rejected={"hex_0x_byte"}, opts={"width_bits": 16})
    assert split.split
    cat = catalog(a__one_u16_hex=entry("integer", {"hex_0x_padded": 1}, opts={"width_bits": 16}),
                  b__two_u16_hex=split)
    prefer, last = cat.preference("z.new_u16_hex", "integer", {"width_bits": 16})
    assert prefer == ["hex_0x_padded"] and last == []
    prefer, _ = cat.preference("z.new_size", "integer", {})          # the kind prior alone
    assert prefer == ["hex_0x_padded"]


# ------------------------------------------------------------------ the harvest (synthetic corpus)

def write_attempt(folder: Path, attempt_id, questions, key=None, verdicts=(), key_attempt=None):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "attempt.json").write_text(json.dumps({"attempt_id": attempt_id, "questions": questions}))
    if key is not None:
        (folder / "key.json").write_text(json.dumps({"attempt_id": key_attempt or attempt_id, "answers": key}))
    if verdicts:
        (folder / "verdicts.jsonl").write_text("".join(json.dumps(v) + "\n" for v in verdicts) + "not json\n")


def verdict(result, values):
    return {"kind": "probe", "ids": list(values), "values": values, "result": result}


QS = [
    q("d09-pe-001-pe-coff-machine-u16-hex", "Inspect `a.exe`. Determine pe.coff_machine_u16_hex for a.exe.", HEX0X),
    q("d19-elf-001-elf-e-machine-u16-hex", "Inspect `c`. Determine elf.e_machine_u16_hex for c.", HEX0X),
    q("d13-msi-001-msi-product-code-guid", "Inspect `i.msi`. Determine msi.product_code_guid for i.msi.", GUID_HY),
    q("d15-ooxml-001-ooxml-external-relationship-targets",
      "Inspect `d.docx`. Determine ooxml.external_relationship_targets for d.docx.", JSON_ARR),
    q("roster-size-bytes", "Inspect `roster.csv`. What is its exact size in bytes?", BASE10, "trim"),
    q("evidence-note-size-bytes", "What is its exact size in bytes?", BASE10),
    q("metadata-day-15-synthesis-sha256-order", "Inspect `e.txt`. Compute ... ascending SHA-256 order", JSON_ARR),
    q("mystery-thing", "Something unparseable.", EXACT),
]


@pytest.fixture
def corpus(tmp_path):
    root = tmp_path / "challenges"
    day = root / "day-01" / "metadata-forensics-day-01-x"
    write_attempt(day / "time_trial", "att-1", QS, key={
        "d09-pe-001-pe-coff-machine-u16-hex": "0x014c",           # padded and byte coincide: consistent
        "d19-elf-001-elf-e-machine-u16-hex": "0x003e",            # padded only: accepted
        "roster-size-bytes": "396", "evidence-note-size-bytes": "12",
        "d15-ooxml-001-ooxml-external-relationship-targets": '["https://a","https://b"]',
    }, verdicts=[
        verdict("CORRECT", {"d13-msi-001-msi-product-code-guid": "{00010203-0405-0607-0809-0A0B0C0D0E0F}"}),
        # same GUID, refused under another spelling: a format verdict
        verdict("incorrect", {"d13-msi-001-msi-product-code-guid": "00010203-0405-0607-0809-0a0b0c0d0e0f"}),
        # a refused value with no accepted text of the same value: says nothing about the format
        verdict("incorrect", {"d19-elf-001-elf-e-machine-u16-hex": "0x28"}),
        # refused unsorted: the document order; the accepted sorted text is then `sorted` for sure
        verdict("incorrect", {"d15-ooxml-001-ooxml-external-relationship-targets": '["https://b","https://a"]'}),
        # a refused multi-id request says nothing per id
        {"kind": "bank", "ids": ["roster-size-bytes", "x"], "values": {"roster-size-bytes": "0x18c", "x": "1"},
         "result": "incorrect"},
    ])
    # a key.json of another attempt is not this attempt's verdicts
    write_attempt(day / "mastery", "att-2", QS[:1], key={"d09-pe-001-pe-coff-machine-u16-hex": "332"},
                  key_attempt="att-OTHER")
    # history copies keep their attempt id out of `sources`
    write_attempt(day / "time_trial" / "history" / "753bcb6a-6136-4b6a-a740-0ad72d663ad3", "att-3", QS[1:2],
                  verdicts=[verdict("accepted", {"d19-elf-001-elf-e-machine-u16-hex": "0x0028"})])
    # never read: a dot-folder, another lane
    write_attempt(day / ".ctf", "att-4", [q("d01-zz-001-zz-secret-count", "", BASE10)], key={"d01-zz-001-zz-secret-count": "1"})
    write_attempt(root / "day-01" / "binary-reverse-day-01-y", "att-5", [q("d01-yy-001-yy-count", "", BASE10)],
                  key={"d01-yy-001-yy-count": "1"})
    return root


def test_harvest_reads_judged_renderings(corpus):
    cat = AF.harvest(corpus)
    elf = cat.properties["elf.e_machine_u16_hex"]
    assert elf.kind == "integer" and elf.opts == {"width_bits": 16}
    assert elf.accepted == Counter({"hex_0x_padded": 2}) and elf.rejected == set()
    pe = cat.properties["pe.coff_machine_u16_hex"]
    assert pe.accepted == Counter() and pe.consistent == Counter({"hex_0x_padded": 1, "hex_0x_byte": 1})
    assert pe.asked == 2                     # asked in both attempts; the mastery key is another attempt's
    msi = cat.properties["msi.product_code_guid"]
    assert msi.accepted == Counter({"braces_upper": 1}) and msi.rejected == {"hyphen_lower"}
    ox = cat.properties["ooxml.external_relationship_targets"]
    assert ox.accepted == Counter({"sorted+json": 1}) and ox.rejected == {"document_order+json"}
    size = cat.properties["size_bytes"]
    assert size.accepted == Counter({"integer": 2}) and size.rejected == set()
    assert size.normalization == {"trim"} and size.answer_kinds == {"integer"}


def test_harvest_records_vocabulary_and_skips_what_it_must(corpus):
    cat = AF.harvest(corpus)
    assert cat.unparsed == {"mystery-thing"}
    # no synthesis id (its own handler), nothing from the dot-folder or the other lane
    assert set(cat.properties) == {"pe.coff_machine_u16_hex", "elf.e_machine_u16_hex", "msi.product_code_guid",
                                   "ooxml.external_relationship_targets", "size_bytes"}
    assert cat.syntax[AF.norm_phrase(HEX0X["syntax"])] == {"answer_kind": "pattern", "asked": 4}
    srcs = cat.properties["elf.e_machine_u16_hex"].sources
    assert srcs == {"day-01/metadata-forensics-day-01-x/time_trial",
                    "day-01/metadata-forensics-day-01-x/time_trial/history"}


def test_harvest_is_deterministic_and_saves_a_loadable_catalog(corpus, tmp_path):
    a, b = AF.harvest(corpus), AF.harvest([corpus])
    assert a.dumps() == b.dumps()
    out = a.save(tmp_path / "cat.json")
    assert AF.Catalog.load(out).dumps() == a.dumps()


def test_the_corpus_must_be_configured_outside_the_checkout(monkeypatch, tmp_path):
    monkeypatch.delenv("CTF_REAL_CHALLENGES", raising=False)
    with pytest.raises(AF.CorpusError, match="CTF_REAL_CHALLENGES"):
        AF.corpus_root()
    with pytest.raises(AF.CorpusError, match="not found"):
        AF.corpus_root(tmp_path / "missing")
    monkeypatch.setenv("CTF_REAL_CHALLENGES", str(tmp_path / "typo"))
    with pytest.raises(AF.CorpusError, match="CTF_REAL_CHALLENGES"):
        AF.corpus_root()
    with pytest.raises(AF.CorpusError, match="inside the checkout"):
        AF.corpus_root(ROOT / "solvers")
    (tmp_path / "empty").mkdir()
    with pytest.raises(AF.CorpusError, match="no judged attempt"):
        AF.harvest(tmp_path / "empty")


def test_the_corpus_variable_is_used_when_no_path_is_given(monkeypatch, corpus):
    monkeypatch.setenv("CTF_REAL_CHALLENGES", str(corpus))
    assert AF.harvest([None]).dumps() == AF.harvest(corpus).dumps()


GUID_Q = q("d13-msi-001-msi-product-code-guid", "Inspect `i.msi`. Determine msi.product_code_guid for i.msi.", GUID_HY)


def test_an_accepted_none_is_no_rendering_and_not_unclassified(tmp_path):
    # `none` is the absent-value answer, not a spelling of the kind: it must neither count as an
    # unclassified judged answer (which would make the brief call the property unshaped) nor as an accept.
    root = tmp_path / "c"
    lane = root / "metadata-forensics-day-01"
    write_attempt(lane / "a", "att-a", [GUID_Q], key={GUID_Q["id"]: "none"})
    write_attempt(lane / "b", "att-b", [GUID_Q], verdicts=[verdict("correct", {GUID_Q["id"]: " None "})])
    write_attempt(lane / "c", "att-c", [GUID_Q], key={GUID_Q["id"]: "{00010203-0405-0607-0809-0A0B0C0D0E0F}"})
    e = AF.harvest(root).properties["msi.product_code_guid"]
    assert e.asked == 3 and e.unclassified == 0
    assert e.accepted == Counter({"braces_upper": 1}) and e.consistent == Counter()


def test_sources_are_capped_at_max_sources_when_saved(tmp_path):
    root = tmp_path / "c"
    n = AF.MAX_SOURCES + 1
    for i in range(n):
        write_attempt(root / "metadata-forensics-day-01" / f"t{i:02d}", f"att-{i}", [GUID_Q])
    e = AF.harvest(root).properties["msi.product_code_guid"]
    assert len(e.sources) == n                                       # every folder is seen
    saved = e.to_json()["sources"]
    assert AF.MAX_SOURCES == 12 and len(saved) == 12
    assert saved == [f"metadata-forensics-day-01/t{i:02d}" for i in range(12)]   # the sorted first 12


def test_harvest_reports_corpus_files_it_cannot_read(corpus):
    lane = corpus / "day-01" / "metadata-forensics-day-01-x"
    (lane / "broken").mkdir()
    (lane / "broken" / "attempt.json").write_text("{ not json")
    write_attempt(lane / "noq", "att-n", [GUID_Q])
    (lane / "noq" / "attempt.json").write_text(json.dumps({"attempt_id": "att-n"}))
    write_attempt(lane / "badkey", "att-k", [GUID_Q])
    (lane / "badkey" / "key.json").write_text("[")
    # valid JSON that is no verdict row (no `values` object), and a blank line that is nothing at all
    (lane / "badkey" / "verdicts.jsonl").write_text('{"result": "correct"}\n[1]\n\n')
    write_attempt(lane / "keylist", "att-l", [GUID_Q])
    (lane / "keylist" / "key.json").write_text(json.dumps({"attempt_id": "att-l", "answers": ["x"]}))
    cat = AF.harvest(corpus)
    pre = "day-01/metadata-forensics-day-01-x/"
    assert sorted(cat.unreadable) == sorted([
        pre + "broken/attempt.json: unreadable JSON (JSONDecodeError)",
        pre + "noq/attempt.json: no questions list",
        pre + "badkey/key.json: unreadable JSON (JSONDecodeError)",
        pre + "keylist/key.json: no answers object",
        pre + "badkey/verdicts.jsonl: 2 line(s) that are no verdict row (JSON object with values)",
        # write_attempt ends each verdicts.jsonl with one `not json` line
        pre + "time_trial/verdicts.jsonl: 1 line(s) that are no verdict row (JSON object with values)",
        pre + "time_trial/history/753bcb6a-6136-4b6a-a740-0ad72d663ad3/verdicts.jsonl: 1 line(s) that are no "
              "verdict row (JSON object with values)",
    ])
    # the readable rest is harvested as before; the report is not part of the saved catalog
    assert cat.properties["msi.product_code_guid"].accepted == Counter({"braces_upper": 1})
    assert "unreadable" not in cat.to_json()
    r = run_cli("harvest", "--corpus", corpus, "--json")
    assert r.returncode == 0 and "WARNING 7 corpus file(s) could not be read" in r.stderr
    assert pre + "broken/attempt.json: unreadable JSON" in r.stderr
    # an untouched corpus file set reports nothing
    clean = corpus.parent / "clean"
    write_attempt(clean / "metadata-forensics-day-01" / "a", "att-a", [GUID_Q], key={GUID_Q["id"]: "none"})
    assert AF.harvest(clean).unreadable == []
    r = run_cli("harvest", "--corpus", clean, "--json")
    assert r.returncode == 0 and "WARNING" not in r.stderr


def test_a_corpus_whose_only_attempt_is_unreadable_names_it(tmp_path):
    folder = tmp_path / "c" / "metadata-forensics-day-01" / "a"
    folder.mkdir(parents=True)
    (folder / "attempt.json").write_text("{")
    with pytest.raises(AF.CorpusError, match="no judged attempt.*unreadable: metadata-forensics-day-01/a/attempt.json"):
        AF.harvest(tmp_path / "c")


# ------------------------------------------------------------------ the pre-clock brief

def test_brief_names_each_status_and_the_missing_piece():
    cat = catalog(
        pe__coff_machine_u16_hex=entry("integer", {"hex_0x_padded": 2}, opts={"width_bits": 16}, unclassified=1),
        zip__names=entry("list", consistent={"sorted+json": 1, "document_order+json": 1}),
        rel__groups=entry("list", unclassified=3),
        size_bytes=entry("integer", {"integer": 1}),
        # split: braces_upper both accepted and refused, so its accepts are no confirmed rendering
        msi__product_code_guid=entry("guid", {"braces_upper": 2}, rejected={"braces_upper"}),
    )
    for af in (EXACT, JSON_ARR, GUID_HY):
        cat.syntax[AF.norm_phrase(af["syntax"])] = {"answer_kind": af["kind"], "asked": 1}
    qs = [
        q("d09-pe-001-pe-coff-machine-u16-hex", "Determine pe.coff_machine_u16_hex for a.", HEX0X),
        q("d07-zip-001-zip-names", "Determine zip.names for z.", JSON_ARR),
        q("d40-elf-001-elf-new-u16-hex", "Determine elf.new_u16_hex for e.", HEX0X),
        q("d41-foo-001-foo-new-dims", "Determine foo.new_dimensions for f.", EXACT),
        q("d42-apk-001-apk-package-name", "Determine apk.package_name for a.apk.", EXACT),
        q("d43-eml-001-eml-priority", "Determine eml.priority for m.", {"kind": "enum", "accepted_values": ["low", "high"]}),
        q("metadata-day-15-synthesis-sha256-order",
          "Files: [\"a\"]. Compute the SHA-256 digest of each file, then list the names in ascending SHA-256 digest order.",
          {"kind": "json", "syntax": "compact JSON array"}),
        q("weird-blob", "No property here.", EXACT),
        q("d44-foo-001-foo-thing", "Determine foo.thing for f.", {"kind": "regex"}),
        q("d30-cluster-001-rel-groups", "Determine rel.groups for c.", JSON_ARR),
        q("roster-size-bytes", "What is its exact size in bytes?", {"kind": "integer", "syntax": "a brand new phrase"}),
        q("d13-msi-001-msi-product-code-guid", "Determine msi.product_code_guid for i.msi.", GUID_HY),
    ]
    got = {f.qid: f for f in AF.brief(qs, cat)}
    assert got["d09-pe-001-pe-coff-machine-u16-hex"].status == "known"
    assert got["d09-pe-001-pe-coff-machine-u16-hex"].probe[0] == "hex_0x_padded"
    assert got["d07-zip-001-zip-names"].status == "consistent"
    assert got["d40-elf-001-elf-new-u16-hex"].status == "prior"
    assert got["d40-elf-001-elf-new-u16-hex"].probe[0] == "hex_0x_padded"
    assert got["d41-foo-001-foo-new-dims"].status == "new" and got["d41-foo-001-foo-new-dims"].probe[0] == "x_lower"
    assert got["d42-apk-001-apk-package-name"].status == "verbatim"
    assert got["d43-eml-001-eml-priority"].status == "enum"
    syn = got["metadata-day-15-synthesis-sha256-order"]
    assert syn.status in ("synth", "unshaped") and syn.prop is None
    weird = got["weird-blob"]
    assert weird.status == "unshaped" and "property name" in weird.missing and weird.attention
    assert got["d44-foo-001-foo-thing"].status == "unshaped" and "'regex'" in got["d44-foo-001-foo-thing"].missing
    rel = got["d30-cluster-001-rel-groups"]
    assert rel.status == "unshaped" and "3 judged answer(s)" in rel.missing
    size = got["roster-size-bytes"]
    assert size.status == "known" and size.prop == "size_bytes"         # a catalog stem field names it
    assert size.new_syntax == "a brand new phrase" and size.attention
    split = got["d13-msi-001-msi-product-code-guid"]
    assert split.status == "new" and split.probe[0] != "braces_upper"   # split accepts are not "known"
    for qid in ("d09-pe-001-pe-coff-machine-u16-hex", "d40-elf-001-elf-new-u16-hex", "d42-apk-001-apk-package-name"):
        assert not got[qid].attention
    assert json.loads(json.dumps(got["d09-pe-001-pe-coff-machine-u16-hex"].to_json()))["status"] == "known"


def test_a_settled_synthesis_id_is_synth_and_an_unsettled_one_is_unshaped():
    from ctf.answerfmt import synth
    qs = [q("metadata-day-15-synthesis-sha256-order",
            "Files: [\"a.txt\", \"b.txt\"]. Compute the full-file SHA-256 digest of each named file, then submit "
            "a compact JSON array of the file names sorted by ascending SHA-256 digest.", JSON_ARR)]
    (f,) = AF.brief(qs, AF.Catalog())
    why = synth.covered(qs[0]["id"], qs[0]["question"], JSON_ARR)
    assert f.status == ("synth" if why is None else "unshaped")
    if why is not None:
        assert why in f.missing


def test_questions_of_reads_bodies_and_lists():
    body = {"questions": [{"question": "a"}, {"question": "b"}], "answer_ids": ["x", "y"]}
    assert [x["id"] for x in AF.questions_of(body)] == ["x", "y"]
    assert AF.questions_of([{"id": "z"}, "junk"]) == [{"id": "z"}]
    assert AF.questions_of({"nope": 1}) == [] and AF.questions_of(None) == []


# ------------------------------------------------------------------ the command line

def run_cli(*args, env=None):
    e = {k: v for k, v in os.environ.items() if k != "CTF_REAL_CHALLENGES"}
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "ctf", "accepted-formats", *map(str, args)], cwd=ROOT,
                          capture_output=True, text=True, env=e, timeout=600)


def test_cli_harvest_writes_a_catalog_and_fails_loudly_without_a_corpus(corpus, tmp_path):
    out = tmp_path / "cat.json"
    r = run_cli("harvest", "--corpus", corpus, "--out", out)
    assert r.returncode == 0, r.stderr
    assert "elf.e_machine_u16_hex [integer/16]: accepted hex_0x_padded x2" in r.stdout
    assert AF.Catalog.load(out).properties["msi.product_code_guid"].rejected == {"hyphen_lower"}
    r = run_cli("harvest")
    assert r.returncode == 2 and "CTF_REAL_CHALLENGES" in r.stderr
    r = run_cli("harvest", "--corpus", corpus, "--check")
    assert r.returncode == 1 and "stale" in r.stderr                 # the synthetic corpus is not the tracked one


def test_cli_check_exit_codes(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"questions": [
        q("d13-msi-001-msi-product-code-guid", "Determine msi.product_code_guid for i.msi.", GUID_HY)]}))
    r = run_cli("check", good)
    assert r.returncode == 0, r.stderr
    assert "known msi.product_code_guid [guid]; probe braces_upper" in r.stdout
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"questions": [q("weird-blob", "No property.", EXACT)]}))
    r = run_cli("check", bad, "--json")
    assert r.returncode == 1 and json.loads(r.stdout)[0]["status"] == "unshaped"
    junk = tmp_path / "junk.json"
    junk.write_text("{")
    assert run_cli("check", junk).returncode == 2
    junk.write_text("{}")
    assert run_cli("check", junk).returncode == 2


def test_cli_show(tmp_path):
    r = run_cli("show", "msi.product_code_guid")
    assert r.returncode == 0
    shown = json.loads(r.stdout)
    assert shown["probe"][0] == "braces_upper" and shown["kind"] == "guid"
    r = run_cli("show", "no.such_property")
    assert r.returncode == 2 and "no.such_property" in r.stderr
    broken = tmp_path / "broken.json"
    broken.write_text("{}")
    r = run_cli("show", "--catalog", broken)
    assert r.returncode == 2 and "schema" in r.stderr


# ------------------------------------------------------------------ the real corpus (not run without it)

def test_the_tracked_catalog_matches_the_judged_corpus():
    root = paths.saved_challenges_root()
    if root is None:
        pytest.skip("not run: CTF_REAL_CHALLENGES is not set (the saved judged attempts of a past event)")
    try:
        fresh = AF.harvest(root)
    except AF.CorpusError as e:
        if "no judged attempt" not in str(e):
            raise
        pytest.skip(f"not run: {e}")
    assert fresh.dumps() == AF.Catalog.load().dumps(), "run: python -m ctf accepted-formats harvest --write"
    # judged truths of the 2026 Metadata lane, as the corpus shows them
    assert fresh.properties["msi.product_code_guid"].accepted.most_common(1)[0][0] == "braces_upper"
    assert fresh.properties["macho.cpu_type_set"].rejected == {"document_order+json"}
