"""B-216: the Binary lane's one id grammar (solvers/binary/field_grammar.py)."""
import pytest

import field_grammar as fg


@pytest.mark.parametrize("qid,family,name,attr,role", [
    # Day 10's has_hcfg_section and its spellings: one family, one name
    ("d10_analysis_has_hcfg_section", "has_section", "hcfg", "presence", None),
    ("d10_analysis_has_section_hcfg", "has_section", "hcfg", "presence", None),
    ("d10_analysis_hcfg_section_present", "has_section", "hcfg", "presence", None),
    ("d10_analysis_section_hcfg_exists", "has_section", "hcfg", "presence", None),
    ("d10_analysis_contains_hcfg_section", "has_section", "hcfg", "presence", None),
    ("d10_analysis_has__rdata_section", "has_section", "rdata", "presence", None),
    # section attributes, synonyms folded
    ("d09_analysis_hcfg_section_offset", "section_attr", "hcfg", "offset", None),
    ("d09_analysis_hcfg_section_file_offset", "section_attr", "hcfg", "offset", None),
    ("d09_analysis_section_text_size", "section_attr", "text", "size", None),
    ("d09_analysis_hcfg_section_virtual_address", "section_attr", "hcfg", "address", None),
    ("d09_analysis_hcfg_section_rva", "section_attr", "hcfg", "address", None),
    # per-build role ids (Day 15/16): the role is what stands before a family that ends an id
    ("d16_analysis_direct_machine", "header", "machine", None, "direct"),
    ("d16_analysis_compact_config_url", "config", "url", None, "compact"),
    ("d16_analysis_stripped_pe_has_hcfg_section", "has_section", "hcfg", "presence", "stripped_pe"),
    ("d17_analysis_stripped_has_symtab", "symbol", None, "presence", "stripped"),
    # symbol family (Day 17 COFF forms, row 323's recover_code)
    ("d01_analysis_recover_code", "symbol", "recover_code", "value", None),
    ("d17_analysis_exported_symbol", "symbol", "exported", "name", None),
    ("d02_analysis_typeinfo_name_symbol", "symbol", "typeinfo_name", "name", None),
    ("d17_analysis_handler_symbols", "symbol", "handler", "list", None),
    ("d12_analysis_symbol_count", "symbol", None, "count", None),
    ("d12_analysis_handler_symbol_count", "symbol", "handler", "count", None),
    ("d05_analysis_check_return_value", "symbol", "check", "value", None),
    ("d01_analysis_has_symtab", "symbol", None, "presence", None),
    ("d01_analysis_is_stripped", "symbol", None, "presence", None),
    # overlays and trailers
    ("d20_analysis_overlay_offset", "overlay", "overlay", "offset", None),
    ("d20_analysis_trailer_length", "overlay", "trailer", "size", None),
    ("d20_analysis_overlay_magic", "overlay", "overlay", "tag", None),
    ("d20_analysis_has_overlay", "overlay", "overlay", "present", None),
    # the rest
    ("d03_artifact_sha256_2", "sha256", None, "2", None),
    ("d02_analysis_config_campaign", "config", "campaign", None, None),
    ("d02_analysis_xor_key_hex", "xor_key", None, None, None),
    ("d02_analysis_has_cpp_vtable", "has_mark", "cpp_vtable", "presence", None),
    ("d08_analysis_section_count", "header", "section_count", None, None),
    ("d08_analysis_import_count", "count", "import", "count", None),
    ("d08_analysis_elf_class", "header", "elf_class", None, None),
    ("d09_analysis_hcfg_offset", "other", None, None, None),
])
def test_ids_parse_into_their_family(qid, family, name, attr, role):
    f = fg.parse(qid)
    assert (f.family, f.name, f.attr, f.role) == (family, name, attr, role)


def test_synonyms_share_one_canonical_spelling():
    spellings = ["d10_analysis_has_hcfg_section", "d10_analysis_has_section_hcfg", "d10_analysis_hcfg_section_present",
                 "d10_analysis_section_hcfg_exists", "D10_ANALYSIS_HAS_HCFG_SECTION"]
    assert {fg.parse(q).canonical() for q in spellings} == {"has_hcfg_section"}
    assert fg.parse("d09_analysis_hcfg_section_file_offset").canonical() == "hcfg_section_offset"
    assert fg.parse("d16_analysis_direct_config_url").canonical() == "config_url"


def test_prefix_area_and_set_are_split_off():
    f = fg.parse("set3.d17_artifact_sha256_1")
    assert (f.set, f.prefix, f.area, f.family, f.attr) == (3, "d17", "artifact", "sha256", "1")
    f = fg.parse("d17_analysis_config_url")
    assert (f.set, f.prefix, f.area) == (None, "d17", "analysis")


def test_a_bare_digest_of_something_is_not_a_role_file_hash():
    f = fg.parse("d28_analysis_handler_symbols_sha256")
    assert f.family == "other" and f.role is None


def test_build_words_pick_the_role_longest_first():
    f = fg.parse("d16_analysis_stripped_pe_config_url", builds=["stripped", "stripped_pe"])
    assert (f.role, f.family, f.name) == ("stripped_pe", "config", "url")
    f = fg.parse("d16_analysis_stripped_config_url", builds=["stripped", "stripped_pe"])
    assert f.role == "stripped" and f.notes == ("role from builds",)


def test_a_role_no_member_name_carries_is_noted():
    f = fg.parse("d16_analysis_ghost_machine", builds=["direct", "compact"])
    assert f.role == "ghost" and any("not a build word" in n for n in f.notes)
    assert fg.parse("d16_analysis_direct_machine", builds=["direct"]).notes == ("role from builds",)


@pytest.mark.parametrize("bad", [None, "", "   ", 7])
def test_unparseable_input_is_family_other_and_never_raises(bad):
    f = fg.parse(bad)
    assert f.family == "other" and f.prefix is None


VOCAB = ("architecture", "elf_class", "machine", "class")      # longest first, as a reader passes it


@pytest.mark.parametrize("qid,want", [
    ("d16_analysis_direct_machine", ("direct", "analysis_machine")),
    ("d16_analysis_net_host_elf_class", ("net_host", "analysis_elf_class")),    # the longest field wins
    ("d16_analysis_net_host_class", ("net_host", "analysis_class")),
    ("d16_analysis_cs_config_url", ("cs", "analysis_config_url")),
    ("d16_analysis_a_config_b_config_c", ("a", "analysis_config_b_config_c")),   # the first config_ starts the field
    ("d16_analysis_config_url", (None, None)),                                   # no role in front
    ("d16_analysis_machine", (None, None)),
    ("d16_analysis_elf_class", (None, None)),            # the whole rest is a field: not `elf` in front of `class`
    ("d16_analysis_direct_entry_point", (None, None)),                           # not in the vocabulary
    ("d16_artifact_direct_machine", (None, None)),                               # another area
    ("d16_analysis_Direct_machine", ("Direct", "analysis_machine")),             # case is kept
    ("analysis_direct_machine", (None, None)),                                   # no prefix
    ("d16", (None, None)),
    (None, (None, None)),
])
def test_split_end_reads_a_role_in_front_of_a_vocabulary_field(qid, want):
    assert fg.split_end(qid, VOCAB) == want


def test_split_end_takes_the_vocabulary_in_the_order_given():
    assert fg.split_end("d16_analysis_net_host_elf_class", ("class", "elf_class")) == ("net_host_elf",
                                                                                       "analysis_class")
    assert fg.split_end("d16_static_x_machine", VOCAB, area="static") == ("x", "static_machine")


def test_generic_role_split_is_the_grammars():
    import evidence
    generic = evidence._generic()        # the Binary lane's generic.py, never script-analysis's by the same name
    for qid in ("d16_analysis_direct_machine", "d16_analysis_cs_config_url", "d16_analysis_machine",
                "d16_analysis_direct_entry_point"):
        assert generic._role_split_qid(qid) == fg.split_end(qid, generic.ROLE_FIELDS)
    for f in ("architecture", "endianness", "elf_class", "elf_type", "machine", "format", "config_url"):
        assert generic._role_split_qid(f"d16_analysis_direct_{f}") == ("direct", f"analysis_{f}")


@pytest.mark.parametrize("field,want", [
    ("has_hcfg_section", ("has_section", "hcfg", "presence")),
    ("has__HCFG_section", ("has_section", "hcfg", "presence")),
    ("has_a_section_b_section", ("has_section", "a_section_b", "presence")),
    ("has___section", ("has_mark", "__section", "presence")),          # no section name: not the family
    ("", ("other", None, None)),
    (None, ("other", None, None)),
])
def test_family_reads_a_bare_field(field, want):
    assert fg.family(field) == want


def test_catalog_has_section_reads_the_name_through_the_grammar(monkeypatch):
    import field_catalog
    pat = next(p for p, slug, fn in field_catalog.RULES if fn is field_catalog.r_has_section)
    # the section table's names, as the catalog's own _section_names reads them from a sample
    monkeypatch.setattr(field_catalog, "_section_names", lambda S: ("elf", {"hcfg", "text"}))
    fmt = {"kind": "enum", "accepted_values": ["true", "false"]}
    yes = field_catalog.r_has_section(object(), fmt, pat.fullmatch("has__HCFG_section"))
    no = field_catalog.r_has_section(object(), fmt, pat.fullmatch("has_rdata_section"))
    assert yes == ("elf", field_catalog._bool("section", True, fmt))
    assert no == ("elf", field_catalog._bool("section", False, fmt))
    assert yes != no
    assert field_catalog.r_has_section(object(), fmt, pat.fullmatch("has___section")) is None


def test_cli_prints_each_parse(capsys):
    assert fg._main(["d10_analysis_has_hcfg_section"]) == 0
    out = capsys.readouterr().out
    assert "family=has_section" in out and "canonical=has_hcfg_section" in out
    assert fg._main([]) == 2
