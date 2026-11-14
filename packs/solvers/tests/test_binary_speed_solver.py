"""B-216: the variant-proof speed solver (speed_solver.py) and its wiring into the Binary lane (evidence.py).

The look-ahead matrix builds one day's sample in every container (ELF, PE, each with and without a symbol
table), every overlay framing under a never-seen tag, and every packaging step a day has taken or may take
next (tests/binary_lookahead.py), and holds the answers to one question set fixed across all of them.
"""
import hashlib

import pytest

import binary_lookahead as L
import evidence
import speed_solver as sp

DAY = 41
CFG = {"campaign": "BR41-ahead", "url": "https://example.invalid/c2", "sleep": 30, "debug": False}
NONE_SYNTAX = "exact text; use the literal none only when the requested field is absent"
HCFG_PAYLOAD = b"H" * 24


def q(field, kind="exact_text", syntax="", accepted=None, prefix=f"d{DAY}"):
    fmt = {"kind": kind, "syntax": syntax}
    if accepted is not None:
        fmt["accepted_values"] = accepted
    return {"qid": f"{prefix}_{field}", "answer_format": fmt}


QUESTIONS = [
    q("artifact_sha256_1"),
    q("analysis_has_hcfg_section", "enum", accepted=["true", "false"]),
    q("analysis_section_hcfg_present", "integer"),
    q("analysis_has_bogus_section", "enum", accepted=["yes", "no"]),
    q("analysis_hcfg_section_size", "integer"),
    q("analysis_recover_code", syntax=NONE_SYNTAX),
    q("analysis_has_symtab", "enum", accepted=["yes", "no"]),
    q("analysis_overlay_size", "integer"),
    q("analysis_overlay_magic"),
    q("analysis_config_campaign"),
    q("analysis_config_sleep", "integer"),
    q("analysis_config_mutex", syntax=NONE_SYNTAX),
    q("analysis_machine"),
]


def _image(container, symbols, overlay):
    if container == "elf":
        return L.elf64([(".text", b"\xc3" * 48, 6, 0x401000), (".hcfg", HCFG_PAYLOAD, 2, 0x402000)],
                       symtab=[("main", 2, 1), ("recover_code", 2, 1)] if symbols else None, overlay=overlay)
    return L.pe64([(".text", b"\xc3" * 512, 0x60000020), (".hcfg", HCFG_PAYLOAD.ljust(512, b"\0"), 0x40000040)],
                  coff_symbols=[("main", 1, 0x20, 2), ("recover_code", 1, 0x20, 2)] if symbols else None,
                  overlay=overlay)


def _expected(container, symbols, framing, image):
    rec = L.record(framing, b"QX41", CFG)
    return {
        f"d{DAY}_artifact_sha256_1": hashlib.sha256(image).hexdigest(),
        f"d{DAY}_analysis_has_hcfg_section": "true",
        f"d{DAY}_analysis_section_hcfg_present": "1",
        f"d{DAY}_analysis_has_bogus_section": "no",
        f"d{DAY}_analysis_hcfg_section_size": str(len(HCFG_PAYLOAD) if container == "elf" else 512),
        f"d{DAY}_analysis_recover_code": None if symbols else "none",
        f"d{DAY}_analysis_has_symtab": "yes" if symbols else "no",
        f"d{DAY}_analysis_overlay_size": str(len(rec)),
        f"d{DAY}_analysis_overlay_magic": "QX41",
        f"d{DAY}_analysis_config_campaign": "BR41-ahead",
        f"d{DAY}_analysis_config_sleep": "30",
        f"d{DAY}_analysis_config_mutex": "none",
        f"d{DAY}_analysis_machine": None,
    }


@pytest.mark.parametrize("packaging", sorted(L.PACKAGINGS))
@pytest.mark.parametrize("framing", ["hdr16crc", "hdr32crc", "len32crc", "len32sha", "tlv32", "footer"])
@pytest.mark.parametrize("container,symbols", [("elf", True), ("elf", False), ("pe", True), ("pe", False)])
def test_answers_do_not_depend_on_packaging_framing_or_tag(packaging, framing, container, symbols):
    image = _image(container, symbols, L.record(framing, b"QX41", CFG))
    files = L.PACKAGINGS[packaging](DAY, image)
    got, why = sp.solve(f"d{DAY}", QUESTIONS, files, {})
    assert got == _expected(container, symbols, framing, image), why


def test_a_file_count_absence_needs_a_by_name_pick():
    image = _image("elf", False, b"")
    ask = [q("artifact_sha256_2", syntax=NONE_SYNTAX)]
    for packaging, want in (("by_name", "none"), ("renamed", "none"), ("day_folder", None), ("no_day_word", None)):
        got, why = sp.solve(f"d{DAY}", ask, L.PACKAGINGS[packaging](DAY, image), {})
        assert got[f"d{DAY}_artifact_sha256_2"] == want, (packaging, why)
    got, _ = sp.solve(f"d{DAY}", [q("artifact_sha256_2")], L.by_name(DAY, image), {})
    assert got[f"d{DAY}_artifact_sha256_2"] is None                   # the syntax does not permit none


def test_number_forms():
    assert sp.number(255, {"kind": "integer"}) == "255"
    assert sp.number(255, {"kind": "pattern", "syntax": "lowercase hexadecimal with a 0x prefix"}) == "0xff"
    assert sp.number(255, {"kind": "exact_text", "syntax": "hexadecimal"}) is None
    assert sp.number(255, {"kind": "exact_text", "syntax": "base-10"}) == "255"
    assert sp.number(None, {}) is None


def test_boolean_forms():
    assert sp.boolean(True, {"kind": "integer"}) == "1"
    assert sp.boolean(False, {"kind": "enum", "accepted_values": ["Present", "Absent"]}) == "Absent"
    assert sp.boolean(True, {"kind": "exact_text", "syntax": "true or false"}) == "true"
    assert sp.boolean(True, {"kind": "exact_text", "syntax": "say whether"}) is None
    assert sp.boolean(True, {"kind": "enum", "accepted_values": ["alpha", "beta"]}) is None


def test_pe_section_size_only_when_raw_and_virtual_agree():
    image = L.pe64([(".text", b"\xc3" * 100, 0x60000020)])            # vsize 100, raw 512
    got, why = sp.solve(f"d{DAY}", [q("analysis_text_section_size", "integer"),
                                    q("analysis_text_section_offset", "integer")], L.by_name(DAY, image), {})
    assert got[f"d{DAY}_analysis_text_section_size"] is None
    assert got[f"d{DAY}_analysis_text_section_offset"] == "512"


def test_a_missing_section_is_none_only_under_permission():
    image = _image("elf", True, b"")
    got, _ = sp.solve(f"d{DAY}", [q("analysis_bogus_section_offset", "exact_text", NONE_SYNTAX),
                                  q("analysis_zzz_section_offset", "integer")], L.by_name(DAY, image), {})
    assert got == {f"d{DAY}_analysis_bogus_section_offset": "none", f"d{DAY}_analysis_zzz_section_offset": None}


def test_two_images_leave_image_facts_unanswered():
    files = {f"d{DAY}--a.bin": _image("elf", False, b""), f"d{DAY}--b.bin": _image("pe", False, b"")}
    got, why = sp.solve(f"d{DAY}", [q("analysis_recover_code", syntax=NONE_SYNTAX)], files, {})
    assert got[f"d{DAY}_analysis_recover_code"] is None
    assert "2 distinct image(s)" in why[f"d{DAY}_analysis_recover_code"]


def test_role_ids_read_their_own_build():
    files = {f"d{DAY}--sample-direct.bin": _image("elf", True, b""),
             f"d{DAY}--sample-compact.bin": _image("elf", False, b"")}
    got, _ = sp.solve(f"d{DAY}", [q("analysis_direct_has_symtab", "integer"),
                                  q("analysis_compact_has_symtab", "integer"),
                                  q("analysis_compact_recover_code", syntax=NONE_SYNTAX)], files, {})
    assert got == {f"d{DAY}_analysis_direct_has_symtab": "1", f"d{DAY}_analysis_compact_has_symtab": "0",
                   f"d{DAY}_analysis_compact_recover_code": "none"}


def test_two_distinct_records_leave_config_unanswered():
    files = {f"d{DAY}--a.bin": _image("elf", False, L.record("hdr16crc", b"QX41", CFG)),
             f"d{DAY}--a.json": L.record("tlv32", b"DCOY", dict(CFG, campaign="decoy"))}
    got, why = sp.solve(f"d{DAY}", [q("analysis_config_campaign")], files, {})
    assert got[f"d{DAY}_analysis_config_campaign"] is None and "single distinct" in why[f"d{DAY}_analysis_config_campaign"]


def test_a_corrupt_record_is_not_read():
    image = _image("elf", False, L.record("hdr16crc", b"QX41", CFG, corrupt=True))
    got, _ = sp.solve(f"d{DAY}", [q("analysis_config_campaign"), q("analysis_overlay_magic")],
                      L.by_name(DAY, image), {})
    assert got == {f"d{DAY}_analysis_config_campaign": None, f"d{DAY}_analysis_overlay_magic": None}


def test_no_overlay_answers_present_false_and_none_under_permission():
    image = _image("elf", False, b"")
    got, _ = sp.solve(f"d{DAY}", [q("analysis_has_overlay", "integer"),
                                  q("analysis_overlay_offset", "exact_text", NONE_SYNTAX),
                                  q("analysis_overlay_size", "integer")], L.by_name(DAY, image), {})
    assert got == {f"d{DAY}_analysis_has_overlay": "0", f"d{DAY}_analysis_overlay_offset": "none",
                   f"d{DAY}_analysis_overlay_size": None}


def test_an_unreadable_section_table_is_not_proof_of_absence():
    image = bytearray(_image("elf", False, b""))
    image[0x28:0x30] = b"\0" * 8                                          # e_shoff = 0: no section table
    got, why = sp.solve(f"d{DAY}", [q("analysis_recover_code", syntax=NONE_SYNTAX),
                                    q("analysis_symbol_count", "integer")], L.by_name(DAY, bytes(image)), {})
    assert got == {f"d{DAY}_analysis_recover_code": None, f"d{DAY}_analysis_symbol_count": None}
    assert "does not prove" in why[f"d{DAY}_analysis_recover_code"]


def test_symbol_count_is_zero_only_on_proven_absence():
    ask = [q("analysis_symbol_count", "integer")]
    assert sp.solve(f"d{DAY}", ask, L.by_name(DAY, _image("pe", False, b"")), {})[0] == {f"d{DAY}_analysis_symbol_count": "0"}
    assert sp.solve(f"d{DAY}", ask, L.by_name(DAY, _image("pe", True, b"")), {})[0] == {f"d{DAY}_analysis_symbol_count": None}


def test_a_reader_that_raises_costs_one_id(monkeypatch):
    def boom(*a):
        raise RuntimeError("synthetic")
    monkeypatch.setitem(sp.FAMILIES, "overlay", boom)
    got, why = sp.solve(f"d{DAY}", [q("analysis_overlay_size", "integer"), q("artifact_sha256_1")],
                        L.by_name(DAY, _image("elf", False, b"x")), {})
    assert got[f"d{DAY}_analysis_overlay_size"] is None and "RuntimeError" in why[f"d{DAY}_analysis_overlay_size"]
    assert got[f"d{DAY}_artifact_sha256_1"] is not None


# ---------------------------------------------------------------------------- evidence.py wiring

def _hygiene(prefix, field, image, syntax=NONE_SYNTAX, value="none"):
    qs = [q(field, syntax=syntax, prefix=prefix)]
    got = {qs[0]["qid"]: value}
    return evidence.hygiene(prefix, qs, got, {f"{prefix}--variant-000.bin": image}, {})[qs[0]["qid"]]


def test_hygiene_keeps_a_none_on_a_stripped_build_of_any_prefix_and_container():
    for image in (_image("elf", False, b""), _image("pe", False, b""), L.macho64(None)):
        assert _hygiene("d42", "analysis_check_return_value", image) == "none"
        assert _hygiene("d42", "analysis_exported_symbol", image) == "none"
    assert _hygiene("d01", "analysis_recover_code", _image("elf", False, b"")) == "none"        # row 323 kept


def test_hygiene_withdraws_a_none_the_bytes_or_the_syntax_do_not_allow():
    assert _hygiene("d42", "analysis_exported_symbol", _image("pe", True, b"")) is None         # COFF names stand
    assert _hygiene("d42", "analysis_exported_symbol", _image("elf", True, b"")) is None        # .symtab stands
    assert _hygiene("d42", "analysis_exported_symbol", _image("elf", False, b""), syntax="exact text") is None
    assert _hygiene("d42", "analysis_has_symtab", _image("elf", False, b"")) is None           # a fact, not an absence


def test_symbol_field_reads_the_grammar():
    assert evidence.symbol_field("d42", "d42_analysis_vtable_symbol")
    assert evidence.symbol_field("d01", "d01_analysis_recover_code")
    assert not evidence.symbol_field("d42", "d42_analysis_symbol_count")
    assert not evidence.symbol_field("d42", "d42_analysis_config_url")


def test_speed_filled_answers_only_what_is_still_none():
    image = _image("elf", False, L.record("hdr16crc", b"QX41", CFG))
    files = L.by_name(DAY, image)
    qs = [q("analysis_overlay_magic"), q("analysis_config_campaign"), q("artifact_sha256_1")]
    got = {f"d{DAY}_analysis_overlay_magic": None, f"d{DAY}_analysis_config_campaign": "kept-by-an-earlier-reader",
           f"d{DAY}_artifact_sha256_1": None}
    out = evidence.speed_filled(f"d{DAY}", qs, dict(got), files, {})
    assert out == {f"d{DAY}_analysis_overlay_magic": "QX41",
                   f"d{DAY}_analysis_config_campaign": "kept-by-an-earlier-reader",
                   f"d{DAY}_artifact_sha256_1": hashlib.sha256(image).hexdigest()}


def test_closing_runs_speed_filled():
    image = _image("elf", False, L.record("len32sha", b"QX41", CFG))
    qs = [q("analysis_overlay_magic"), q("analysis_has_hcfg_section", "integer")]
    out = evidence.closing(f"d{DAY}", qs, {x["qid"]: None for x in qs}, L.renamed(DAY, image), {})
    assert out == {f"d{DAY}_analysis_overlay_magic": "QX41", f"d{DAY}_analysis_has_hcfg_section": "1"}


def test_solve_set_on_a_new_day_answers_through_the_family_reader():
    image = _image("pe", False, L.record("hdr16crc", b"ZN77", CFG))
    qs = [q("analysis_overlay_magic", prefix="d77"), q("analysis_recover_code", syntax=NONE_SYNTAX, prefix="d77")]
    out = evidence.solve_set(qs, {"d77--sample-x.bin": image}, {})
    assert out["d77_analysis_overlay_magic"] == "ZN77"
    assert out["d77_analysis_recover_code"] == "none"


# ---------------------------------------------------------------------------- fix round 1 (verification of B-216)

def test_a_member_the_record_lacks_is_none_without_permission():
    image = _image("elf", True, L.record("hdr16crc", b"QX41", CFG))
    ask = [q("analysis_config_mutex", syntax="exact text, case-sensitive")]
    got, why = sp.solve(f"d{DAY}", ask, L.by_name(DAY, image), {})
    assert got == {f"d{DAY}_analysis_config_mutex": None}
    assert "syntax does not permit" in why[f"d{DAY}_analysis_config_mutex"]


def test_two_sections_of_one_name_leave_its_attributes_unanswered():
    image = L.elf64([(".text", b"\xc3" * 48, 6, 0x401000), (".hcfg", b"A" * 8, 2, 0x402000),
                     (".hcfg", b"B" * 16, 2, 0x403000)])
    got, why = sp.solve(f"d{DAY}", [q("analysis_hcfg_section_offset", "integer"),
                                    q("analysis_hcfg_section_size", "integer")], L.by_name(DAY, image), {})
    assert got == {f"d{DAY}_analysis_hcfg_section_offset": None, f"d{DAY}_analysis_hcfg_section_size": None}
    assert "2 sections are named" in why[f"d{DAY}_analysis_hcfg_section_offset"]


def test_a_syntax_naming_true_and_false_does_not_override_accepted_values():
    fmt = {"kind": "enum", "accepted_values": ["alpha", "beta"], "syntax": "true or false"}
    assert sp.boolean(True, fmt) is None and sp.boolean(False, fmt) is None


def test_the_overlay_tag_is_the_record_that_starts_the_overlay():
    import overlay_records as orr
    tail = b"NOPE" + b"\xff" * 12 + L.record("hdr16crc", b"QX41", CFG)    # a verified record, but at 16
    assert [r.offset for r in orr.records(tail)] == [16]
    got, why = sp.solve(f"d{DAY}", [q("analysis_overlay_magic")], L.by_name(DAY, _image("elf", True, tail)), {})
    assert got == {f"d{DAY}_analysis_overlay_magic": None}
    assert "0 verified record tag(s)" in why[f"d{DAY}_analysis_overlay_magic"]


def test_sha256_0_is_no_file_number():
    files = {f"d{DAY}--variant-000.bin": _image("elf", True, b""), f"d{DAY}--variant-000.cfg": b"side file"}
    got, why = sp.solve(f"d{DAY}", [q("artifact_sha256_0"), q("artifact_sha256_2")], files, {})
    assert got[f"d{DAY}_artifact_sha256_0"] is None
    assert got[f"d{DAY}_artifact_sha256_2"] == hashlib.sha256(b"side file").hexdigest()


def _decoy_beside_a_real_container(day):
    """A raw HCFG decoy in the sample's overlay, and the sample's own HCFG record written as base64 inside a
    line of text: generic reads both (and cannot tell them apart: both name the day, no variant is stated);
    overlay_records reads only the raw one."""
    import base64
    real = {"campaign": f"BR{day}-000", "url": "https://real.invalid/", "mutex": "real"}
    decoy = {"campaign": f"BR{day}-001", "url": "https://decoy.invalid/", "mutex": "decoy"}
    image = L.elf64([(".text", b"\xc3" * 48, 6, 0x401000)], overlay=L.record("hdr16crc", b"HCFG", decoy, key=0x33))
    side = b"config: " + base64.b64encode(L.record("hdr16crc", b"HCFG", real, key=0x33)) + b"\n"
    return {f"d{day}--sample.bin": image, f"d{day}--sample.txt": side}


def test_speed_filled_leaves_a_config_generic_declined():
    files = _decoy_beside_a_real_container(47)
    qs = [q("analysis_config_url", prefix="d47")]
    alone, _ = sp.solve("d47", qs, files, {})
    assert alone == {"d47_analysis_config_url": "https://decoy.invalid/"}    # the weaker reader sees the decoy
    assert "declined" in evidence.lane_config_hold("d47", files, {})
    assert evidence.speed_filled("d47", qs, {"d47_analysis_config_url": None}, files, {}) == \
        {"d47_analysis_config_url": None}
    assert evidence.solve_set(qs, files, {})["d47_analysis_config_url"] is None


def test_speed_filled_leaves_a_config_generic_reads_to_generic():
    image = _image("elf", True, L.record("hdr16crc", b"HCFG", dict(CFG, campaign="BR48-000"), key=0x33))
    files = L.by_name(48, image)
    qs = [q("analysis_config_url", prefix="d48"), q("analysis_overlay_magic", prefix="d48")]
    assert "generic reads" in evidence.lane_config_hold("d48", files, {})
    out = evidence.speed_filled("d48", qs, {x["qid"]: None for x in qs}, files, {})
    assert out == {"d48_analysis_config_url": None, "d48_analysis_overlay_magic": "HCFG"}


def test_lane_config_hold_reads_the_files_the_speed_solver_picked_by_content():
    image = _image("elf", True, L.record("hdr16crc", b"HCFG", dict(CFG, campaign="BR50-000"), key=0x33))
    files = L.no_day_word(50, image)                     # no name says the day: generic's own pool is empty
    picked = sp.Prefix("d50", files, {}).members
    assert [name for name, _ in picked] == ["payload.bin"]
    assert evidence.lane_config_hold("d50", files, {}) == ""
    assert "generic reads" in evidence.lane_config_hold("d50", files, {}, picked)
    qs = [q("analysis_config_url", prefix="d50")]
    assert evidence.speed_filled("d50", qs, {qs[0]["qid"]: None}, files, {}) == {qs[0]["qid"]: None}


def test_speed_filled_answers_config_when_generic_reads_no_container():
    image = _image("pe", False, L.record("hdr16crc", b"ZN78", CFG))
    files = {"d78--sample-x.bin": image}
    assert evidence.lane_config_hold("d78", files, {}) == ""
    qs = [q("analysis_config_campaign", prefix="d78")]
    out = evidence.speed_filled("d78", qs, {qs[0]["qid"]: None}, files, {})
    assert out == {"d78_analysis_config_campaign": "BR41-ahead"}


def test_lane_config_hold_fails_closed_without_generic(monkeypatch):
    monkeypatch.setattr(evidence, "_generic", lambda: None)
    files = {"d78--sample-x.bin": _image("pe", False, L.record("hdr16crc", b"ZN78", CFG))}
    assert "not available" in evidence.lane_config_hold("d78", files, {})
    qs = [q("analysis_config_campaign", prefix="d78")]
    assert evidence.speed_filled("d78", qs, {qs[0]["qid"]: None}, files, {}) == {qs[0]["qid"]: None}


def test_withheld_ids_are_what_a_guard_withdrew_or_the_module_decided():
    qs = [q(f) for f in ("analysis_a", "analysis_b", "analysis_c", "analysis_d")]
    ids = [x["qid"] for x in qs]
    got = {ids[0]: None, ids[1]: None, ids[2]: None, ids[3]: "kept"}
    assert evidence.withheld_ids(qs, given={ids[0], ids[3]}, decided={ids[1], ids[3]}, got=got) == {ids[0], ids[1]}


def test_speed_filled_does_not_undo_a_guard_or_a_module_decision(monkeypatch):
    class Module:      # a day module: a section none hygiene withdraws; it decides on the magic alone
        @staticmethod
        def answers(qs, files, ctx):
            return {"d49_analysis_bogus_section_offset": "none", "d49_analysis_overlay_magic": None}

        @staticmethod
        def handles(field):
            return field == "analysis_overlay_magic"

    monkeypatch.setattr(evidence, "load", lambda prefix: (Module, ""))
    image = _image("elf", False, L.record("hdr16crc", b"QX41", CFG))
    files = L.by_name(49, image)
    qs = [q("analysis_bogus_section_offset", syntax=NONE_SYNTAX, prefix="d49"),
          q("analysis_overlay_magic", prefix="d49"), q("artifact_sha256_1", prefix="d49")]
    # what the speed solver alone would say about each: all three are answers it gives
    assert sp.answers("d49", qs, files, {}) == {"d49_analysis_bogus_section_offset": "none",
                                                "d49_analysis_overlay_magic": "QX41",
                                                "d49_artifact_sha256_1": hashlib.sha256(image).hexdigest()}
    out = evidence.solve_prefix("d49", qs, files, {})
    assert out["d49_analysis_bogus_section_offset"] is None     # hygiene withdrew the module's none
    assert out["d49_analysis_overlay_magic"] is None            # the module decides on it and left it None
    assert out["d49_artifact_sha256_1"] == hashlib.sha256(image).hexdigest()


# ---------------------------------------------------------------------------- fix round 2 (verification of B-216)

def _offset_size(prefix):
    return [q("analysis_overlay_offset", "integer", prefix=prefix), q("analysis_overlay_size", "integer", prefix=prefix)]


def test_zero_fill_before_the_record_leaves_overlay_offset_and_size_unanswered():
    image = _image("elf", True, b"")
    rec = L.record("len32crc", b"QX77", CFG)
    got, why = sp.solve("d77", _offset_size("d77"), {"d77--s.bin": image + b"\0" * 8 + rec}, {})
    assert got == {"d77_analysis_overlay_offset": None, "d77_analysis_overlay_size": None}
    assert "8 zero byte(s)" in why["d77_analysis_overlay_offset"]
    assert "two readings" in why["d77_analysis_overlay_size"]
    # with no fill the image end IS the magic's position, and both are answered
    got, _ = sp.solve("d77", _offset_size("d77"), {"d77--s.bin": image + rec}, {})
    assert got == {"d77_analysis_overlay_offset": str(len(image)), "d77_analysis_overlay_size": str(len(rec))}


def test_the_padded_tail_stays_none_through_the_lane_on_a_new_day():
    """The verifier's probe: an ELF, 8 zero bytes and a len32crc QX77 record, sent through solve_set on a day no
    module covers. Generic leaves the ids None; the speed solver must not answer the image end."""
    image = _image("elf", False, b"") + b"\0" * 8 + L.record("len32crc", b"QX77", CFG)
    out = evidence.solve_set(_offset_size("d77"), {"d77--s.bin": image}, {})
    assert out["d77_analysis_overlay_offset"] is None
    assert out["d77_analysis_overlay_size"] is None


def test_a_wrapper_header_at_the_image_end_is_the_overlays_start():
    """The Day 20-31 shape: a wrapper header (RS20-like, its own magic first) at the image end and a verified record
    inside it. The saved keys judged the image end there, so the inner record is no second reading."""
    image = _image("elf", True, b"")
    tail = b"RS20\x13\x37" + bytes(36) + L.record("hdr16crc", b"QX41", CFG)
    import overlay_records as orr
    assert [r.offset for r in orr.records(tail)] == [42]
    got, _ = sp.solve(f"d{DAY}", _offset_size(f"d{DAY}"), L.by_name(DAY, image + tail), {})
    assert got == {f"d{DAY}_analysis_overlay_offset": str(len(image)),
                   f"d{DAY}_analysis_overlay_size": str(len(tail))}


def test_a_certificate_after_the_overlay_leaves_only_the_size_unanswered():
    rec = L.record("hdr16crc", b"QX41", CFG)
    secs = [(".text", b"\xc3" * 512, 0x60000020)]
    plain = L.pe64(secs, overlay=rec)
    signed = L.pe64(secs, overlay=rec, cert=b"\x30" * 48)
    assert len(signed) == len(plain) + 48                     # the certificate table is appended after the overlay
    got, why = sp.solve(f"d{DAY}", _offset_size(f"d{DAY}"), L.by_name(DAY, signed), {})
    assert got[f"d{DAY}_analysis_overlay_offset"] == str(len(plain) - len(rec))
    assert got[f"d{DAY}_analysis_overlay_size"] is None
    assert "certificate" in why[f"d{DAY}_analysis_overlay_size"]
    got, _ = sp.solve(f"d{DAY}", _offset_size(f"d{DAY}"), L.by_name(DAY, plain), {})
    assert got == {f"d{DAY}_analysis_overlay_offset": str(len(plain) - len(rec)),
                   f"d{DAY}_analysis_overlay_size": str(len(rec))}


def _unpinned_overlay_member():
    """The Day 20 shape (tests/test_day20_binary_overlay.py, case 2): an identity-packed (42, 4, 5) overlay with
    printable bytes before its magic, so several header layouts SHA-match and generic leaves the offset None."""
    import json
    import struct
    import zlib
    plain = json.dumps({"campaign": "BR20-000"}, separators=(",", ":")).encode()
    payload = b"HCFG" + struct.pack("<BBHI", 1, 0x5A, len(plain), zlib.crc32(plain)) + bytes(b ^ 0x5A for b in plain)
    head = b"RS20" + bytes([0x13, 0x37]) + struct.pack("<I", len(payload)) + hashlib.sha256(payload).digest()
    return b"\x7fELF" + bytes(range(256)) * 2 + b"AB" + head + payload


def test_generic_reports_a_never_guess_none_as_decided_and_a_not_read_one_not():
    gen = evidence._generic()
    qs = [q("analysis_overlay_offset", prefix="d20"), q("analysis_overlay_size", prefix="d20"),
          q("analysis_bogus_field", prefix="d20")]
    out, why = gen.answers_with_reasons("d20", qs, {"d20--sample": _unpinned_overlay_member()}, {})
    assert out == {x["qid"]: None for x in qs}
    assert "not uniquely pinned" in why["d20_analysis_overlay_offset"]
    assert isinstance(why["d20_analysis_bogus_field"], gen.NotRead)
    assert gen.decided_ids(out, why) == {"d20_analysis_overlay_offset", "d20_analysis_overlay_size"}
    # no file named for the prefix: nothing was read, so nothing is decided
    out, why = gen.answers_with_reasons("d20", qs, {"other.bin": b"x"}, {})
    assert why == {} and gen.decided_ids(out, why) == frozenset()
    # answers(), as its callers see it, is the first half
    assert gen.answers("d20", qs, {"d20--sample": _unpinned_overlay_member()}, {}) == {x["qid"]: None for x in qs}


def test_a_not_read_reason_is_never_a_decision():
    gen = evidence._generic()
    files = {"d20--a.bin": b"\x00 no header and no container"}
    qs = [q("analysis_config_campaign", prefix="d20"), q("artifact_sha256_3", prefix="d20")]
    out, why = gen.answers_with_reasons("d20", qs, files, {})
    assert out == {x["qid"]: None for x in qs}
    assert all(isinstance(why[x["qid"]], gen.NotRead) for x in qs), why
    assert gen.decided_ids(out, why) == frozenset()
    # a sample generic reads by its header, with no container and no overlay of a shape generic reads
    files = {"d20--b.bin": _image("elf", True, L.record("len32crc", b"QX20", CFG))}
    qs = [q("analysis_config_campaign", prefix="d20"), q("analysis_overlay_offset", "integer", prefix="d20")]
    out, why = gen.answers_with_reasons("d20", qs, files, {})
    assert out == {x["qid"]: None for x in qs}
    assert "no HCFG container decodes" in why["d20_analysis_config_campaign"]
    assert "no trailing packed overlay" in why["d20_analysis_overlay_offset"]
    assert gen.decided_ids(out, why) == frozenset()


def test_decided_ids_are_only_ids_left_none():
    gen = evidence._generic()
    out = {"d20_a": "answered", "d20_b": None, "d20_c": None, "d20_d": None}
    why = {"d20_a": "a reason kept from before a later reader answered", "d20_b": "never-guess",
           "d20_c": gen.NotRead("not read"), "d20_d": None}
    assert gen.decided_ids(out, why) == {"d20_b"}


def test_a_generic_reader_that_raises_decides_nothing(monkeypatch):
    gen = evidence._generic()

    def boom(*a, **k):
        raise ValueError("a reader that fails")

    monkeypatch.setattr(gen, "answer_field", boom)
    qs = [q("analysis_overlay_offset", prefix="d20")]
    out, why = gen.answers_with_reasons("d20", qs, {"d20--b.bin": _image("elf", True, b"")}, {})
    assert out == {"d20_analysis_overlay_offset": None}
    assert "raised ValueError" in why["d20_analysis_overlay_offset"]
    assert gen.decided_ids(out, why) == frozenset()


def _generic_saying(gen, reason):
    def fake(prefix, questions, files, ctx):
        return ({x["qid"]: None for x in questions},
                {"d51_analysis_overlay_magic": reason, "d51_artifact_sha256_1": gen.NotRead("not read")})
    return fake


class _Raises:
    @staticmethod
    def answers(qs, files, ctx):
        raise RuntimeError("a day module that fails")


@pytest.mark.parametrize("module", [None, _Raises], ids=["no-module", "module-raised"])
def test_speed_filled_does_not_undo_a_decision_of_generic_on_the_generic_path(monkeypatch, module):
    gen = evidence._generic()
    image = _image("elf", False, L.record("hdr16crc", b"QX41", CFG))
    files = L.by_name(51, image)
    qs = [q("analysis_overlay_magic", prefix="d51"), q("artifact_sha256_1", prefix="d51")]
    monkeypatch.setattr(evidence, "load", lambda prefix: (module, "no module for the test"))
    monkeypatch.setattr(gen, "answers_with_reasons", _generic_saying(gen, "a never-guess decision of generic's"))
    out = evidence.solve_prefix("d51", qs, files, {})
    assert out["d51_analysis_overlay_magic"] is None
    assert out["d51_artifact_sha256_1"] == hashlib.sha256(image).hexdigest()
    # the same None given as not read is the speed solver's to fill
    monkeypatch.setattr(gen, "answers_with_reasons", _generic_saying(gen, gen.NotRead("no shape generic reads")))
    out = evidence.solve_prefix("d51", qs, files, {})
    assert out["d51_analysis_overlay_magic"] == "QX41"
