#!/usr/bin/env python3
"""Tests for B-217: the script lane's language table, id-keyed question reading and generalised
composite-label reader (solvers/script-analysis/lang_table.py), plus its fallback wiring into
descriptor.tag_chain.

Offline and synthetic: no Game Master request, no token, no network, and no specimen is executed. Every
carrier here is a string built in the test. Run:
  sandbox-exec -f .../sb.sb .venv/bin/python -m pytest solvers/script-analysis/test_b217_lang_table.py
"""
import lang_table
import descriptor


# ---------------------------------------------------------------- composite-label reader

def test_composite_single_known_atom():
    r = lang_table.composite_label("B64")
    assert r["chain"] == ["b64"] and r["ok"] and r["unknown"] == []


def test_composite_separators_plus_underscore_gt_dot_dash():
    # the same chain however the author joins the tokens
    for tag in ("HEX+GZ", "HEX_GZ", "HEX>GZ", "hex.gz", "hex-gz"):
        assert lang_table.composite_label(tag)["chain"] == ["hex", "inflate"], tag


def test_composite_keeps_token_order():
    assert lang_table.composite_label("REV+B64")["chain"] == ["rev", "b64"]
    assert lang_table.composite_label("B64+REV")["chain"] == ["b64", "rev"]


def test_composite_synonyms_map_to_canonical_atoms():
    assert lang_table.composite_label("base64-zlib")["chain"] == ["b64", "inflate"]
    assert lang_table.composite_label("gunzip")["chain"] == ["b64", "inflate"]   # lone compressor -> b64 text
    assert lang_table.composite_label("bzip2")["chain"] == ["b64", "bz2"]
    assert lang_table.composite_label("ascii85")["chain"] == ["a85"]


def test_composite_lone_compressor_gets_base64_but_composite_does_not():
    # a bare compression word carries base64; spelled with a text layer, no implicit layer is inserted
    assert lang_table.composite_label("GZ")["chain"] == ["b64", "inflate"]
    assert lang_table.composite_label("HEX+GZ")["chain"] == ["hex", "inflate"]
    # a compressor-FIRST composite gets no implicit b64 layer either, even though its chain[0] is binary-input:
    # the author spelled the text layer (HEX) at the end, so the implicit-base64 rule (lone tag only) must not
    # fire. Guards the `tokens == 1` condition at lang_table.py:147 against a `tokens >= 1` relaxation.
    assert lang_table.composite_label("GZ+HEX")["chain"] == ["inflate", "hex"]
    assert lang_table.composite_label("ZLIB+REV")["chain"] == ["inflate", "rev"]
    # a lone text decoder is never given an implicit layer
    assert lang_table.composite_label("B64")["chain"] == ["b64"]


def test_composite_version_suffix_stripped():
    assert lang_table.composite_label("B64V2")["chain"] == ["b64"]
    assert lang_table.composite_label("rev+b64v10")["chain"] == ["rev", "b64"]


def test_composite_inline_xor_key_parsed():
    r = lang_table.composite_label("XOR5A+B64")
    assert r["key"] == b"\x5a" and r["chain"] == ["b64"]      # the xor layer is a crib, no decode step
    assert r["ok"]


def test_composite_unknown_token_reported_not_guessed():
    r = lang_table.composite_label("B64+WILDCODEC")
    assert not r["ok"]
    assert r["unknown"] == ["WILDCODEC"]
    assert lang_table.descriptor_chain("B64+WILDCODEC") is None


def test_composite_empty_tag_is_not_ok():
    r = lang_table.composite_label("")
    assert not r["ok"] and r["chain"] == [] and r["unknown"] == []


def test_descriptor_chain_rejects_noop_only_tag():
    # PLAIN/RAW/XOR are no-op chains that descriptor's own TAGS already names; the fallback adds no new one
    assert lang_table.descriptor_chain("PLAIN") is None
    assert lang_table.descriptor_chain("XOR") is None


def test_descriptor_chain_only_applicable_atoms():
    chain = lang_table.descriptor_chain("hex+xz")
    assert chain == ["hex", "xz"]
    assert all(a in descriptor.LAYERS or a in descriptor.TAG_LAYERS for a in chain)


# ---------------------------------------------------------------- descriptor.tag_chain fallback wiring

def test_tag_chain_known_tags_unchanged():
    # every existing TAGS entry still returns exactly what the hardcoded table holds
    for tag, want in [("GZHEX", ["hex", "inflate"]), ("B64", ["b64"]), ("RB64", ["rev", "b64"]),
                      ("U16BE", ["b64", "u16be"]), ("PLAIN", [])]:
        assert descriptor.tag_chain(tag) == want, tag


def test_tag_chain_fallback_resolves_new_composite():
    # a separator/synonym the hardcoded split misses: old code returned None, now resolved via lang_table
    assert descriptor.tag_chain("hex.gz") == ["hex", "inflate"]
    assert descriptor.tag_chain("GUNZIP") == ["b64", "inflate"]


def test_tag_chain_still_none_for_unknown_shape():
    assert descriptor.tag_chain("NOTACODEC") is None
    assert descriptor.tag_chain("B64+MYSTERY") is None


def test_tag_chain_fallback_decodes_a_real_payload():
    # build a real v=3 descriptor, base64 then hex-of-base64 under a synonym tag the hardcoded table lacks;
    # the chain from the fallback must actually decode the payload to the plan.
    import base64
    plan = "v=3|language=rust|role=stager|steps=acquire_remote,dispatch_memory|campaign_id=redfox"
    b64 = base64.b64encode(plan.encode()).decode()
    payload = b64.encode().hex()                      # hex of the base64 text  -> chain ["hex","b64"]
    chain = descriptor.tag_chain("hex.base64")        # dotted composite the old split could not read
    assert chain == ["hex", "b64"]
    out = descriptor._apply(payload, chain)
    assert out == plan.encode()


# ---------------------------------------------------------------- language table

def test_profile_for_known_and_aliases():
    assert lang_table.profile_for("Rust") == "c"
    assert lang_table.profile_for("python") == "hash"
    assert lang_table.profile_for("PowerShell") == "ps"
    assert lang_table.profile_for("C++") == "c"
    assert lang_table.profile_for("visual basic") == "vb"


def test_profile_for_unknown_raises_loudly():
    import pytest
    with pytest.raises(lang_table.UnknownLanguage):
        lang_table.profile_for("klingon")


def test_table_covers_many_languages():
    # the item asks for a table over 80+ languages
    assert len(set(lang_table.LANGUAGES)) >= 80


def test_comment_regions_skip_strings():
    # a marker word sitting in a string is not inside a comment region
    text = 'let s = "HUNTRESS_ANALYSIS_V1:B64-ZZZZ";  // HUNTRESS_ANALYSIS_V1:B64-REAL\n'
    regions = lang_table.comment_regions(text, "rust")
    joined = "".join(text[a:b] for a, b in regions)
    assert "REAL" in joined and "ZZZZ" not in joined


def test_comment_regions_block_vs_line():
    text = "code; /* HUNTRESS_X:HEX-aa */ more # not-a-c-comment\n"
    regions = lang_table.comment_regions(text, "c")
    joined = "".join(text[a:b] for a, b in regions)
    assert "HEX-aa" in joined and "not-a-c-comment" not in joined


def test_carriers_reads_marker_in_comment_only():
    text = ('print("HUNTRESS_ANALYSIS_V1:B64-DECOYPAYLOAD")\n'
            '# HUNTRESS_ANALYSIS_V2:GZ-Qm9keQ==\n')
    found = lang_table.carriers(text, "python")
    assert len(found) == 1
    _marker, tag, payload = found[0]
    assert tag == "GZ" and payload == "Qm9keQ=="
    assert lang_table.descriptor_chain(tag) == ["b64", "inflate"]


def test_carriers_bare_split_tag():
    text = "// HUNTRESS_ANALYSIS_V1:SPLIT\n"
    found = lang_table.carriers(text, "javascript")
    assert found and found[0][1] == "SPLIT" and found[0][2] == ""


def test_carriers_decoy_in_other_languages_comment_syntax():
    # a '#' is a comment in python but NOT in C; the same bytes read as C leave the marker in code, unread
    text = '# HUNTRESS_ANALYSIS_V1:HEX-6161\n'
    assert lang_table.carriers(text, "python")        # python: '#' starts a comment -> found
    assert lang_table.carriers(text, "c") == []       # C: '#' is not a comment -> decoy, not read


def test_reader_for_binds_language_and_fails_fast():
    import pytest
    reader = lang_table.reader_for("ruby")
    found = reader("# HUNTRESS_ANALYSIS_V1:B64-YWJj\n")
    assert found and found[0][1] == "B64"
    with pytest.raises(lang_table.UnknownLanguage):
        lang_table.reader_for("nonsense-lang")


# ---------------------------------------------------------------- id-keyed question reading

def test_field_from_id_strips_set_prefix_and_reads_tail():
    assert lang_table.field_from_id("set3.jscript-stager-adapter") == "adapter"
    assert lang_table.field_from_id("jscript-stager-steps") == "steps"
    assert lang_table.field_from_id("vbs-dropper-campaign") == "campaign_id"
    assert lang_table.field_from_id("ps1-impact-stage-count") == "stage_count"


def test_field_from_id_longest_tail_in_plan_keys():
    keys = {"cron_path", "path", "campaign_id", "url"}
    # -cron-path must pick cron_path, not path
    assert lang_table.field_from_id("x-register-cron-path", keys) == "cron_path"
    # -upload-url: upload_url is not a key, so url wins
    assert lang_table.field_from_id("x-upload-url", keys) == "url"


def test_field_from_id_none_when_no_tail_is_a_key():
    assert lang_table.field_from_id("x-mystery-field", {"path", "url"}) is None


def test_field_from_id_three_word_plan_key_tail():
    # the plan field is a 3-word key and only the 3-word tail of the id matches it: neither the 2-word
    # ('cron_path') nor the 1-word ('path') tail is a key, so the longest-tail window must reach back 3
    # words. Pins min(3, len(words)) against a narrowing to min(2, ...), which would return None here.
    keys = {"remote_cron_path"}
    assert lang_table.field_from_id("x-set-remote-cron-path", keys) == "remote_cron_path"
    # and with only the 2-word key present, the 2-word tail is what wins (lower bound of the window intact)
    assert lang_table.field_from_id("x-set-remote-cron-path", {"cron_path"}) == "cron_path"


def test_field_from_id_role_word_before_generic_last_takes_generic_only():
    # a generic trailing word (id/name/value/indicator) normally reads the pair, BUT when the penultimate
    # token is a specimen role word it names the specimen, not a field prefix: 'stager-id' is the 'id'
    # field of the stager, not a 'stager_id' field. Pins the `words[-2] not in _ROLE_WORDS` guard, which a
    # mutation that drops it would turn into 'stager_id'.
    assert lang_table.field_from_id("x-stager-id") == "id"
    assert lang_table.field_from_id("dropper-value") == "value"
    # the paired reading still fires for a non-role penultimate token (guard must not over-fire)
    assert lang_table.field_from_id("x-session-id") == "session_id"


def test_field_from_id_generic_last_word_takes_two():
    # a trailing generic word (id/name/value/indicator) reads the pair, not the bare generic word
    assert lang_table.field_from_id("x-registry-key-name") == "key_name"
    assert lang_table.field_from_id("x-host-value") == "host_value"


def test_field_from_id_reads_from_id_not_wording():
    # two questions, same id, different wording: the field is the same (the point of id-keyed reading)
    q1 = {"qid": "jscript-stager-adapter", "question": "Which adapter does the stager use?"}
    q2 = {"qid": "jscript-stager-adapter", "question": "Name the configured adapter, lowercase."}
    assert lang_table.field_from_id(q1["qid"]) == lang_table.field_from_id(q2["qid"]) == "adapter"


# ---------------------------------------------------------------- prior-day wording diff

def test_changed_wording_flags_reworded_same_format():
    prev = [{"qid": "a-role", "question": "old wording", "answer_format": {"kind": "enum"}}]
    cur = [{"qid": "a-role", "question": "NEW wording", "answer_format": {"kind": "enum"}}]
    assert lang_table.changed_wording(prev, cur) == {"a-role"}


def test_changed_wording_ignores_unchanged_and_new_and_format_change():
    prev = [{"qid": "a", "question": "same", "answer_format": {"kind": "string"}},
            {"qid": "b", "question": "x", "answer_format": {"kind": "string"}}]
    cur = [{"qid": "a", "question": "same", "answer_format": {"kind": "string"}},           # unchanged
           {"qid": "b", "question": "y", "answer_format": {"kind": "enum"}},                 # format changed
           {"qid": "c", "question": "new", "answer_format": {"kind": "string"}}]             # new id
    assert lang_table.changed_wording(prev, cur) == set()


def test_changed_wording_format_syntax_change_is_not_wording():
    prev = [{"qid": "a", "question": "q", "answer_format": {"kind": "string", "syntax": "old"}}]
    cur = [{"qid": "a", "question": "q", "answer_format": {"kind": "string", "syntax": "new"}}]
    # wording held, the syntax changed: that is a format change, handled by answer_forms, not reported here
    assert lang_table.changed_wording(prev, cur) == set()


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
