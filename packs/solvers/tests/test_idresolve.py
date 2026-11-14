"""B-010: contract-mismatch id resolver (ctf/idresolve.py), fail closed.

Rules, convention files, the answer adapter and the literal-none rule, with stub inner solvers that
record what they were handed (the resolver is the unit under test, never the stub). The binary lane's
convention file is checked against the translation table of the archived Day 1/2 route shims, and run
end to end through the lane's real evidence.solve_set on synthetic ELF headers in test_idresolve_lanes.py.
"""
from __future__ import annotations

import re

import pytest

from ctf import idresolve as ir
from ctf import paths

BINARY_CONV = paths.repo_root() / "solvers" / "binary" / "id_conventions.toml"


def cat(*known, **kw):
    return ir.Catalog(known, **kw)


# ---- single-id rules -------------------------------------------------------------------------------

def test_exact_and_set_prefix():
    c = cat("d01_analysis_entry_point")
    r = ir.resolve("d01_analysis_entry_point", c)
    assert (r.status, r.target, r.rule, r.set) == ("exact", "d01_analysis_entry_point", "exact", None)
    r = ir.resolve("set3.d01_analysis_entry_point", c)
    assert (r.status, r.target, r.set) == ("exact", "d01_analysis_entry_point", 3)


def test_spelling_variant_maps_to_the_known_spelling():
    r = ir.resolve("roster-md5", cat("roster_md5"))
    assert (r.status, r.target, r.rule) == ("mapped", "roster_md5", "spelling")


def test_alias_and_alias_to_an_unknown_target_fails_closed():
    c = cat("d02_analysis_config_url", ids={"url": "d02_analysis_config_url", "mutex": "d02_analysis_config_mutex"})
    r = ir.resolve("url", c)
    assert (r.status, r.target, r.rule) == ("mapped", "d02_analysis_config_url", "alias")
    r = ir.resolve("mutex", c)
    assert r.status == "unmatched" and r.target is None and "not a known id" in r.reason


def test_field_rule_strips_only_the_catalog_head():
    c = cat("d01_analysis_entry_point", "d01_analysis_marker", strip=r"(?:d\d+_)?(?:analysis_)?")
    r = ir.resolve("entry_point", c)
    assert (r.status, r.target, r.rule) == ("mapped", "d01_analysis_entry_point", "field")
    # with the default head (a day only) "analysis_" is part of the field name
    assert ir.resolve("entry_point", cat("d01_analysis_entry_point")).status == "unmatched"
    assert ir.resolve("analysis_entry_point", cat("d01_analysis_entry_point")).target == "d01_analysis_entry_point"


def test_field_rule_is_whole_name_never_a_suffix_or_a_shortening():
    strip = r"(?:d\d+_)?(?:analysis_)?"
    # an asked field that is only the tail of a known one is not that field
    r = ir.resolve("symbols", cat("d02_analysis_exported_symbols", strip=strip))
    assert r.status == "unmatched"
    # an asked id is never shortened onto a known one (a thumbnail's md5 is not the file's md5)
    r = ir.resolve("thumbnail_md5", cat("md5", "sha256"))
    assert r.status == "unmatched"


def test_field_rule_ambiguous_across_days_fails_closed():
    c = cat("d01_analysis_machine", "d04_analysis_machine", strip=r"(?:d\d+_)?(?:analysis_)?")
    r = ir.resolve("machine", c)
    assert r.status == "ambiguous" and r.target is None
    assert set(r.candidates) == {"d01_analysis_machine", "d04_analysis_machine"}


def test_scope_selects_prefix_number_and_alias():
    s = ir.Scope("slot", re.compile(r"slot(?P<n>\d+)_"), prefix="d01_", fields=(("sha256", "artifact_sha256_1"),))
    c = cat("d01_artifact_sha256_1", "d01_analysis_entry_point", "d04_analysis_entry_point",
            strip=r"(?:d\d+_)?(?:analysis_|artifact_)?", scopes=[s])
    r = ir.resolve("set2.slot3_entry_point", c)
    assert (r.status, r.target, r.rule, r.selector, r.set) == ("mapped", "d01_analysis_entry_point", "scope-field",
                                                              ("slot", 3), 2)
    r = ir.resolve("slot0_sha256", c)
    assert (r.status, r.target, r.rule, r.selector) == ("mapped", "d01_artifact_sha256_1", "scope-alias", ("slot", 0))


def test_a_matching_scope_decides_no_fall_through():
    # 'machine' is a unique field outside the scope's prefix, but the scope said d01_ and d01 has none
    s = ir.Scope("slot", re.compile(r"slot(?P<n>\d+)_"), prefix="d01_")
    c = cat("d04_analysis_machine", strip=r"(?:d\d+_)?(?:analysis_)?", scopes=[s])
    assert ir.resolve("machine", c).status == "mapped"
    r = ir.resolve("slot0_machine", c)
    assert r.status == "unmatched" and "scope slot" in r.reason
    r = ir.resolve("slot0_", c)
    assert r.status == "unmatched"


def test_scope_alias_to_unknown_target_fails_closed():
    s = ir.Scope("cpp", re.compile(r"cpp_"), prefix="d02_", fields=(("xor_key", "analysis_xor_key_hex"),))
    r = ir.resolve("cpp_xor_key", cat("d02_analysis_format", scopes=[s]))
    assert r.status == "unmatched" and "d02_analysis_xor_key_hex" in r.reason


def test_stem_rule_one_member():
    c = cat("filename", "md5", "sha256", "size_bytes")
    r = ir.resolve("roster-sha256", c, members=["roster.csv", "evidence-note.txt"])
    assert (r.status, r.target, r.rule, r.selector) == ("mapped", "sha256", "stem", ("file", "roster.csv"))
    r = ir.resolve("evidence-note-size-bytes", c, members=["roster.csv", "evidence-note.txt", "evidence.txt"])
    assert (r.status, r.target, r.selector) == ("mapped", "size_bytes", ("file", "evidence-note.txt"))


def test_stem_rule_two_members_with_the_stem_fail_closed():
    c = cat("filename", "md5")
    r = ir.resolve("evidence-note-filename", c, members=["evidence-note.txt", "evidence-note.md"])
    assert r.status == "ambiguous" and r.target is None
    r = ir.resolve("note-md5", c, members=["note.txt", "note.tar.gz"])
    assert r.status == "ambiguous"


def test_stem_rule_needs_a_delivered_member():
    c = cat("filename", "md5")
    assert ir.resolve("ghost-filename", c, members=["roster.csv"]).status == "unmatched"
    assert ir.resolve("roster-filename", c).status == "unmatched"          # no members given
    # the stem proves only the dropped words; the rest must still be a whole known field
    assert ir.resolve("roster-thumbnail-md5", c, members=["roster.csv"]).status == "unmatched"


def test_resolve_all_collision_fails_both_closed():
    c = cat("d01_analysis_entry_point", strip=r"(?:d\d+_)?(?:analysis_)?")
    rep = ir.resolve_all([{"id": "entry_point"}, {"id": "entry-point"}], c)
    assert [r.status for r in rep.resolutions] == ["ambiguous", "ambiguous"]
    assert not rep.ok and len(rep.problems()) == 2
    # the same field in two different sets is not a collision
    rep = ir.resolve_all([{"id": "set1.entry_point"}, {"id": "set2.entry_point"}], c)
    assert rep.ok and [r.set for r in rep.resolutions] == [1, 2]


def test_report_and_covers():
    c = cat("a_b", "c_d")
    rep = ir.resolve_all(["a_b", {"qid": "zz"}, {"id": "c-d"}], c)
    assert not rep.ok
    js = rep.to_json()
    assert js["counts"] == {"exact": 1, "mapped": 1, "unmatched": 1, "ambiguous": 0}
    assert ir.covers(["a_b", "zz"], c) == [rep.resolutions[1].line()]
    assert rep.resolutions[1].line().startswith("zz: UNMATCHED")
    assert ir.covers(["a_b", "c-d"], c) == []


def test_bad_inputs_are_loud():
    with pytest.raises(ir.ConventionError, match="no known ids"):
        ir.Catalog([])
    with pytest.raises(ir.ConventionError, match="strip regex"):
        ir.Catalog(["x"], strip="(")
    with pytest.raises(ir.ConventionError):
        ir.resolve("", cat("x"))
    with pytest.raises(ir.ConventionError, match="no id"):
        ir.resolve_all([{"question": "what?"}], cat("x"))


def test_from_attempt():
    att = {"questions": [{"id": "set1.d01_analysis_marker"}, {"id": "d01_artifact_sha256_1"}, {"nope": 1}]}
    c = ir.Catalog.from_attempt(att)
    assert c.known == ("d01_analysis_marker", "d01_artifact_sha256_1")
    with pytest.raises(ir.ConventionError):
        ir.Catalog.from_attempt({"questions": []})


# ---- convention files -------------------------------------------------------------------------------

# The archived Day 1/2 route shims' translation table (orient_routes.translate), as asked -> cumulative id.
ORIENT_TABLE = {
    "slot0_elf_class": "d01_analysis_elf_class", "slot3_entry_point": "d01_analysis_entry_point",
    "slot2_recover_code": "d01_analysis_recover_code", "slot1_exported_symbol": "d01_analysis_exported_symbol",
    "slot0_has_symtab": "d01_analysis_has_symtab", "slot4_marker": "d01_analysis_marker",
    "slot1_sha256": "d01_artifact_sha256_1", "slot0_section_names": "d01_analysis_section_names",
    "c_sha256": "d01_artifact_sha256_1", "c_marker": "d01_analysis_marker", "c_has_symtab": "d01_analysis_has_symtab",
    "c_recover_code": "d01_analysis_recover_code", "c_machine": "d01_analysis_machine",
    "cpp_sha256": "d02_artifact_sha256_1", "cpp_format": "d02_analysis_format",
    "cpp_xor_key": "d02_analysis_xor_key_hex", "cpp_config_crc32": "d02_analysis_config_crc32_hex",
    "campaign": "d02_analysis_config_campaign", "domain": "d02_analysis_config_domain",
    "url": "d02_analysis_config_url", "mutex": "d02_analysis_config_mutex",
    "has_cpp_vtable": "d02_analysis_has_cpp_vtable", "has_cpp_typeinfo": "d02_analysis_has_cpp_typeinfo",
    "mangled_score_symbol": "d02_analysis_mangled_score_symbol", "vtable_symbol": "d02_analysis_vtable_symbol",
    "typeinfo_symbol": "d02_analysis_typeinfo_symbol",
}
# Ids the shims left unanswered, and some near misses that must stay unanswered.
ORIENT_REFUSED = ["slot0_recover_kode", "slot2_bogus", "c_xor_key", "cpp_marker", "cpp_entry_point",
                  "urls", "domain_name", "slot_entry_point", "cppx_format", "c_"]


def test_binary_conventions_reproduce_the_shim_table():
    c = ir.load_conventions(BINARY_CONV)
    for asked, want in ORIENT_TABLE.items():
        r = ir.resolve(asked, c)
        assert (r.status, r.target) == ("mapped", want), (asked, r)
    for asked in ORIENT_REFUSED:
        r = ir.resolve(asked, c)
        assert not r.resolved, (asked, r)
    assert ir.resolve("slot12_marker", c).selector == ("slot", 12)
    assert ir.resolve("cpp_format", c).selector == ("cpp", None)
    assert ir.resolve("url", c).selector == ("d02-bare", None)
    # the cumulative ids themselves still pass straight through
    assert ir.resolve("d02_analysis_config_url", c).status == "exact"


def write(tmp_path, text, name="conv.toml"):
    p = tmp_path / name
    p.write_text(text)
    return p


def test_convention_file_errors_are_loud(tmp_path):
    with pytest.raises(ir.ConventionError, match="not found"):
        ir.load_conventions(tmp_path / "missing.toml")
    with pytest.raises(ir.ConventionError, match="unknown key"):
        ir.load_conventions(write(tmp_path, 'known = ["a"]\nalias = {}\n'))
    with pytest.raises(ir.ConventionError, match="unknown key"):
        ir.load_conventions(write(tmp_path, 'known = ["a"]\n[[scope]]\nname = "s"\nmatch = "s_"\nbogus = 1\n'))
    with pytest.raises(ir.ConventionError, match="match is required"):
        ir.load_conventions(write(tmp_path, 'known = ["a"]\n[[scope]]\nname = "s"\n'))
    with pytest.raises(ir.ConventionError, match="does not compile"):
        ir.load_conventions(write(tmp_path, 'known = ["a"]\n[[scope]]\nname = "s"\nmatch = "("\n'))
    with pytest.raises(ir.ConventionError, match="not among the known ids"):
        ir.load_conventions(write(tmp_path, 'known = ["a"]\n[ids]\nx = "b"\n'))
    with pytest.raises(ir.ConventionError, match="duplicate scope"):
        ir.load_conventions(write(tmp_path, 'known = ["a"]\n[[scope]]\nname = "s"\nmatch = "s_"\n'
                                            '[[scope]]\nname = "s"\nmatch = "t_"\n'))
    with pytest.raises(ir.ConventionError, match="not valid TOML"):
        ir.load_conventions(write(tmp_path, 'known = [\n'))
    # with no known ids of its own, the file needs them from the caller
    with pytest.raises(ir.ConventionError, match="no known ids"):
        ir.load_conventions(write(tmp_path, '[ids]\nx = "b"\n'))
    c = ir.load_conventions(write(tmp_path, '[ids]\nx = "b"\n'), known=["b"])
    assert ir.resolve("x", c).target == "b"


# ---- the literal-none rule ---------------------------------------------------------------------------

@pytest.mark.parametrize("fmt,want", [
    ({"syntax": "unsigned base-10 integer, or the literal token none when the recover_code FUNC symbol is absent"}, True),
    ({"syntax": "use the literal none only when the requested field is absent"}, True),
    ({"syntax": "the symbol name, or `none`"}, True),
    ({"kind": "enum", "accepted_values": ["true", "false", "none"]}, True),
    ({"syntax": "exact artifact-derived value only; none of the above"}, False),
    ({"syntax": "unsigned base-10 integer"}, False),
    ({"kind": "enum", "accepted_values": ["true", "false"]}, False),
    (None, False),
])
def test_permits_literal_none(fmt, want):
    q = {"id": "x"} if fmt is None else {"id": "x", "answer_format": fmt}
    assert ir.permits_literal_none(q) is want


# ---- answer_through ---------------------------------------------------------------------------------

class Recorder:
    """An inner lane solver stub: answers <qid>@<sorted member names> and records each call."""

    def __init__(self, answers=None, raise_on=None):
        self.calls, self.answers, self.raise_on = [], answers or {}, raise_on

    def __call__(self, questions, files, ctx):
        self.calls.append(([q["qid"] for q in questions], sorted(files), [q["question"] for q in questions]))
        if self.raise_on and any(n.startswith(self.raise_on) for n in files):
            raise RuntimeError("boom")
        return {q["qid"]: self.answers.get(q["qid"], f"{q['qid']}@{','.join(sorted(files))}") for q in questions}


def slot_catalog():
    s = ir.Scope("slot", re.compile(r"slot(?P<n>\d+)_"), prefix="d01_", fields=(("sha256", "artifact_sha256_1"),),
                 members=r"(?:^|[-_.])slot[-_]?0*{n}(?!\d)", hand_as="d01-", single=True)
    return ir.Catalog(["d01_artifact_sha256_1", "d01_analysis_entry_point", "d01_analysis_recover_code",
                       "d01_analysis_marker"], strip=r"(?:d\d+_)?(?:analysis_|artifact_)?", scopes=[s])


def q(qid, text=None, fmt=None):
    d = {"qid": qid, "id": qid, "question": text or f"What is {qid}?"}
    if fmt is not None:
        d["answer_format"] = fmt
    return d


def test_answer_through_routes_each_slot_to_its_own_member_and_maps_back():
    files = {"slot-0.elf": b"\x7fELF-zero", "m-slot-1.elf": b"\x7fELF-one", "readme.txt": b"hi"}
    stub = Recorder()
    logs = []
    got, rep = ir.answer_through(stub, [q("slot0_entry_point"), q("slot1_entry_point"), q("slot1_sha256"),
                                        q("slot0_nonsense")], files, {}, catalog=slot_catalog(), log=logs.append)
    assert got == {"slot0_entry_point": "d01_analysis_entry_point@d01-slot-0.elf",
                   "slot1_entry_point": "d01_analysis_entry_point@d01-m-slot-1.elf",
                   "slot1_sha256": "d01_artifact_sha256_1@d01-m-slot-1.elf",
                   "slot0_nonsense": None}
    # one call per sample; the question text names the known id the inner solver answers
    assert sorted(c[1] for c in stub.calls) == [["d01-m-slot-1.elf"], ["d01-slot-0.elf"]]
    one = next(c for c in stub.calls if c[1] == ["d01-m-slot-1.elf"])
    assert one[0] == ["d01_analysis_entry_point", "d01_artifact_sha256_1"]
    assert one[2][0] == "What is d01_analysis_entry_point?"
    assert not rep.ok and any("slot0_nonsense" in line for line in logs)


def test_answer_through_fails_closed_on_missing_or_two_bodied_samples():
    files = {"slot-0.elf": b"A", "slot_0.bin": b"B", "slot-1.elf": b"C"}
    stub = Recorder()
    logs = []
    got, _ = ir.answer_through(stub, [q("slot0_marker"), q("slot1_marker"), q("slot5_marker")], files, {},
                               catalog=slot_catalog(), log=logs.append)
    assert got == {"slot0_marker": None, "slot1_marker": "d01_analysis_marker@d01-slot-1.elf", "slot5_marker": None}
    assert any("2 distinct member bodies" in line for line in logs)
    assert any("no delivered member matches" in line for line in logs)
    # the same body under two names is one sample
    got, _ = ir.answer_through(Recorder(), [q("slot0_marker")], {"slot-0.elf": b"A", "x/slot-0.elf": b"A"}, {},
                               catalog=slot_catalog(), log=logs.append)
    assert got["slot0_marker"] is not None


def test_answer_through_literal_none_needs_the_asked_format():
    stub = Recorder(answers={"d01_analysis_recover_code": "none"})
    files = {"slot-0.elf": b"A"}
    allowed = {"syntax": "unsigned base-10 integer, or the literal token none when the recover_code FUNC symbol is absent"}
    got, _ = ir.answer_through(stub, [q("slot0_recover_code", fmt=allowed)], files, {}, catalog=slot_catalog(),
                               log=lambda m: None)
    assert got["slot0_recover_code"] == "none"
    got, _ = ir.answer_through(stub, [q("slot0_recover_code", fmt={"syntax": "unsigned base-10 integer"})], files, {},
                               catalog=slot_catalog(), log=lambda m: None)
    assert got["slot0_recover_code"] is None


def test_answer_through_solver_failure_costs_only_its_sample():
    stub = Recorder(raise_on="d01-slot-1")
    got, _ = ir.answer_through(stub, [q("slot0_marker"), q("slot1_marker")], {"slot-0.elf": b"A", "slot-1.elf": b"B"},
                               {}, catalog=slot_catalog(), log=lambda m: None)
    assert got == {"slot0_marker": "d01_analysis_marker@d01-slot-0.elf", "slot1_marker": None}


def test_answer_through_exact_and_stem_ids():
    c = ir.Catalog(["md5", "filename", "d01_analysis_marker"])
    files = {"evidence.zip": b"PK..", "roster.csv": b"a,b", "notes.txt": b"n"}
    stub = Recorder()
    got, rep = ir.answer_through(stub, [q("roster-md5"), q("d01_analysis_marker")], files,
                                 {"delivery_name": "evidence.zip"}, catalog=c, log=lambda m: None)
    assert got["roster-md5"] == "md5@roster.csv"
    # an exact id is handed on unchanged, with every delivered file
    assert got["d01_analysis_marker"] == "d01_analysis_marker@evidence.zip,notes.txt,roster.csv"
    assert rep.ok


def test_resolving_solver_from_conventions(tmp_path):
    p = write(tmp_path, 'known = ["d01_analysis_marker"]\nstrip = \'(?:d\\d+_)?(?:analysis_)?\'\n'
                        '[[scope]]\nname = "c"\nmatch = "c_"\nprefix = "d01_"\nmembers = \'^day0*1\'\nhand_as = "d01-"\n')
    stub = Recorder()
    solver = ir.ResolvingSolver.from_conventions(p, stub, log=lambda m: None)
    ctx = {"partial": {}}
    got = solver.solve_set([q("c_marker"), q("c_other")], {"day01-c.elf": b"A", "day02-cpp.elf": b"B"}, ctx)
    assert got == {"c_marker": "d01_analysis_marker@d01-day01-c.elf", "c_other": None}
    assert ctx["partial"] == {"c_marker": got["c_marker"]}
    assert ctx["id_resolution"]["counts"]["unmatched"] == 1
    assert solver.covers([q("c_marker")]) == []
    assert solver.covers([q("c_other")]) and "UNMATCHED" in solver.covers([q("c_other")])[0]
    with pytest.raises(ir.ConventionError):
        ir.ResolvingSolver(solver.catalog, None)


def test_each_set_reads_its_own_delivery():
    # Day 1 Mastery shape: three APK deliveries, setN.answer read from delivery-0N only
    c = ir.Catalog(["answer"])
    files = {"delivery-01.apk": b"one", "delivery-02.apk": b"two", "delivery-03.apk": b"three"}
    stub = Recorder()
    got, rep = ir.answer_through(stub, [q(f"set{n}.answer") for n in (1, 2, 3)], files, {},
                                 catalog=c, set_members=ir.SET_MEMBERS, log=lambda m: None)
    assert rep.ok
    assert got == {"set1.answer": "set1.answer@delivery-01.apk", "set2.answer": "set2.answer@delivery-02.apk",
                   "set3.answer": "set3.answer@delivery-03.apk"}
    # without set selection every set sees every delivery (the caller's choice, not a guess)
    got, _ = ir.answer_through(Recorder(), [q("set2.answer")], files, {}, catalog=c, log=lambda m: None)
    assert got["set2.answer"] == "set2.answer@delivery-01.apk,delivery-02.apk,delivery-03.apk"
    # the same through ResolvingSolver
    solver = ir.ResolvingSolver(c, Recorder(), set_members=ir.SET_MEMBERS, log=lambda m: None)
    assert solver.solve_set([q("set3.answer")], files, {}) == {"set3.answer": "set3.answer@delivery-03.apk"}


def test_a_set_with_no_delivery_fails_closed_and_scopes_select_inside_the_set():
    logs = []
    files = {"evidence-1.zip": b"PK1", "evidence-2.zip": b"PK2"}
    got, _ = ir.answer_through(Recorder(), [q("set4.answer")], files, {}, catalog=ir.Catalog(["answer"]),
                               set_members=ir.SET_MEMBERS, log=logs.append)
    assert got["set4.answer"] is None and any("set 4" in m for m in logs)
    # slot scope inside set 2: only set 2's slot-0 member, though set 1 has one too
    s = ir.Scope("slot", re.compile(r"slot(?P<n>\d+)_"), prefix="d01_", members=r"slot0*{n}-", hand_as="d01-")
    c = ir.Catalog(["d01_analysis_marker"], strip=r"(?:d\d+_)?(?:analysis_)?", scopes=[s])
    files = {"slot0-a-1.elf": b"A", "slot0-b-2.elf": b"B"}
    got, _ = ir.answer_through(Recorder(), [q("set2.slot0_marker")], files, {}, catalog=c,
                               set_members=ir.SET_MEMBERS, log=logs.append)
    assert got["set2.slot0_marker"] == "d01_analysis_marker@d01-slot0-b-2.elf"
    with pytest.raises(ir.ConventionError, match="set_members"):
        ir.answer_through(Recorder(), [q("set1.answer")], files, {}, catalog=ir.Catalog(["answer"]),
                          set_members="(")


# ---- verification round 1 ---------------------------------------------------------------------------

def test_two_bodies_under_one_basename_are_not_one_sample():
    # a/slot-0.elf and b/slot-0.elf share a basename: renaming must not let one overwrite the other
    logs = []
    files = {"a/slot-0.elf": b"A", "b/slot-0.elf": b"B"}
    stub = Recorder()
    got, _ = ir.answer_through(stub, [q("slot0_marker")], files, {}, catalog=slot_catalog(), log=logs.append)
    assert got == {"slot0_marker": None} and stub.calls == []
    assert any("2 distinct member bodies" in m and "a/slot-0.elf" in m and "b/slot-0.elf" in m for m in logs)
    # without single = true the scope still refuses to hand two bodies on under one name
    s = ir.Scope("slot", re.compile(r"slot(?P<n>\d+)_"), prefix="d01_", members=r"slot-0*{n}(?!\d)", hand_as="d01-")
    c = ir.Catalog(["d01_analysis_marker"], strip=r"(?:d\d+_)?(?:analysis_)?", scopes=[s])
    sub, why = s.select(files, 0)
    assert sub is None and "would both be handed on as d01-slot-0.elf" in why
    got, _ = ir.answer_through(Recorder(), [q("slot0_marker")], files, {}, catalog=c, log=logs.append)
    assert got == {"slot0_marker": None}
    # one body under two paths is one sample, handed on once
    assert s.select({"a/slot-0.elf": b"A", "b/slot-0.elf": b"A"}, 0) == ({"d01-slot-0.elf": b"A"}, "")


def test_two_sets_in_one_call_without_set_members_fail_closed():
    c = ir.Catalog(["d01_answer"])      # set1.answer / set2.answer both map (field rule) to d01_answer
    files = {"delivery-01.apk": b"one", "delivery-02.apk": b"two"}
    stub, logs = Recorder(), []
    got, rep = ir.answer_through(stub, [q("set1.answer"), q("set2.answer")], files, {}, catalog=c, log=logs.append)
    assert rep.ok and got == {"set1.answer": None, "set2.answer": None} and stub.calls == []
    assert sum("set_members" in m for m in logs) == 2
    # one set per call (the runner's way) still answers
    got, _ = ir.answer_through(Recorder(), [q("set2.answer")], files, {}, catalog=c, log=logs.append)
    assert got == {"set2.answer": "d01_answer@delivery-01.apk,delivery-02.apk"}
    # with set_members each set has its own inner call and its own delivery
    stub = Recorder()
    got, _ = ir.answer_through(stub, [q("set1.answer"), q("set2.answer")], files, {}, catalog=c,
                               set_members=ir.SET_MEMBERS, log=logs.append)
    assert got == {"set1.answer": "d01_answer@delivery-01.apk", "set2.answer": "d01_answer@delivery-02.apk"}
    assert sorted(call[0] for call in stub.calls) == [["d01_answer"], ["d01_answer"]]
    # exact ids keep their set prefix for the inner solver, and each set gets its own call
    stub = Recorder()
    got, _ = ir.answer_through(stub, [q("set1.d01_answer"), q("set2.d01_answer")], files, {}, catalog=c,
                               log=logs.append)
    assert got["set1.d01_answer"].startswith("set1.d01_answer@") and got["set2.d01_answer"].startswith("set2.")
    assert sorted(call[0] for call in stub.calls) == [["set1.d01_answer"], ["set2.d01_answer"]]


class PartialWriter(Recorder):
    """An inner solver that, like evidence.solve_set, copies its answers into ctx['partial']."""

    def __call__(self, questions, files, ctx):
        got = super().__call__(questions, files, ctx)
        ctx.setdefault("partial", {}).update(got)
        return got


def test_inner_partial_answers_never_reach_the_callers_partial():
    ctx = {"partial": {"earlier": "x"}}
    got, _ = ir.answer_through(PartialWriter(), [q("slot0_marker")], {"slot-0.elf": b"A"}, ctx,
                               catalog=slot_catalog(), log=lambda m: None)
    assert ctx["partial"] == {"earlier": "x"} and got["slot0_marker"]
    solver = ir.ResolvingSolver(slot_catalog(), PartialWriter(), log=lambda m: None)
    ctx = {"partial": {}}
    solver.solve_set([q("slot0_marker"), q("slot0_bogus")], {"slot-0.elf": b"A"}, ctx)
    assert ctx["partial"] == {"slot0_marker": "d01_analysis_marker@d01-slot-0.elf"}


def test_an_exact_id_keeps_its_own_literal_none():
    # the none hygiene applies to mapped ids only: an exact id is the lane's own question and its answer
    stub = Recorder(answers={"d01_analysis_recover_code": "none"})
    no_none = {"syntax": "unsigned base-10 integer"}
    got, _ = ir.answer_through(stub, [q("d01_analysis_recover_code", fmt=no_none), q("slot0_recover_code", fmt=no_none)],
                               {"slot-0.elf": b"A"}, {}, catalog=slot_catalog(), log=lambda m: None)
    assert got == {"d01_analysis_recover_code": "none", "slot0_recover_code": None}


def test_scope_prefix_is_a_whole_word():
    s = ir.Scope("slot", re.compile(r"slot(?P<n>\d+)_"), prefix="d01_")
    strip = r"(?:d\d+_)?(?:analysis_)?"
    r = ir.resolve("slot0_marker", ir.Catalog(["d010_analysis_marker"], strip=strip, scopes=[s]))
    assert r.status == "unmatched"
    r = ir.resolve("slot0_marker", ir.Catalog(["d010_analysis_marker", "d01_analysis_marker"], strip=strip, scopes=[s]))
    assert (r.status, r.target) == ("mapped", "d01_analysis_marker")


def test_resolving_solver_covers_takes_member_names():
    solver = ir.ResolvingSolver(ir.Catalog(["sha256", "md5"]), Recorder(), log=lambda m: None)
    assert solver.covers([q("roster-sha256")]) != []                      # no files yet: fail closed
    assert solver.covers([q("roster-sha256")], members=["roster.csv"]) == []
    assert solver.covers([q("roster-sha256")], ["roster.csv", "roster.txt"]) != []   # two members: ambiguous
