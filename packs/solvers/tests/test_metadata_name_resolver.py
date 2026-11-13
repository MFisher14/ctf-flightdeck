"""B-224: the metadata property-name resolver + reader registry.

properties_strict.resolve_name() is one entry in front of REG that merges the formerly separate
resolution steps -- exact lookup(), a data-only alias table (name_aliases.json), synonym() and guess()
(the typed grammar, width/format/unit words and collection suffixes) -- into one order. These tests pin:

  1. the order and the kinds resolve_name reports (registered / alias / synonym / guess / collection / none);
  2. the alias table is DATA, not code: a new JSON entry routes an unseen name with no code change, and
     every shipped entry resolves to a real reader (a dead alias fails the suite, never ships silently);
  3. a missing or malformed table fails LOUD with a named reason (CLAUDE.md rule 6), no silent fallback;
  4. a resolved unseen name stays UNSURE under its own key, its options carrying the reader, while a plain
     identity answer is untouched -- the end-to-end contract matrix.py's nearest rows also check.

No external tool or corpus: the fixtures are a synthetic .lnk (ctf.formats.corpus) and readers already
registered in REG, so the tests run everywhere.
"""
import io
import sys
from contextlib import redirect_stderr
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
MD = REPO / "solvers" / "metadata-forensics"
for _p in (str(REPO), str(REPO / "solvers" / "common"), str(MD)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import labels  # noqa: E402
import properties_strict as ps  # noqa: E402
from ctf.formats import corpus  # noqa: E402


def _ask(askname, sample):
    """properties_strict's answer to 'Determine <askname> for <file>.', stderr swallowed."""
    q = {"answer_id": "t-" + askname.replace(".", "-"),
         "question": f"Determine {askname} for {sample.name}."}
    with redirect_stderr(io.StringIO()):
        return ps.answer_question(q, {sample.name: sample.data}, {})


# ------------------------------------------------------------------ 1. one resolver, one order, named kinds

def test_exact_registered_name_resolves_as_registered():
    r = ps.resolve_name("zip.member_names")
    assert r.kind == "registered"
    assert r.prop is not None and r.reader == "zip.member_names"


def test_family_pattern_name_resolves_as_registered():
    # the md5/sha family is matched by FAMILIES, not a literal REG key: resolve_name must still take it.
    r = ps.resolve_name("sha256")
    assert r.kind == "registered" and r.prop is not None


def test_alias_table_entry_resolves_as_alias_to_its_target_reader():
    # lnk.target_path_win is in no reader; the data table points it at the registered lnk.target_path_windows.
    assert ps.lookup("lnk_target_path_win") is None
    r = ps.resolve_name("lnk.target_path_win")
    assert r.kind == "alias"
    assert r.reader == "lnk.target_path_windows"
    assert r.prop.name == "lnk.target_path_win"   # read under the ASKED name, so it stays unsure there


def test_typed_grammar_name_resolves_as_guess():
    # a width/form name no literal key has, routed by guess()'s typed grammar, not by the alias table.
    r = ps.resolve_name("pe.coff_machine_u16_hex")
    assert r.kind in ("registered", "guess")   # registered if a @prop exists, else the grammar reaches it
    assert r.prop is not None


def test_a_name_nothing_resolves_is_none_with_a_reason():
    r = ps.resolve_name("nonsense.no_such_field_anywhere_xyz")
    assert r.kind is None and r.prop is None
    assert r.reason   # a named reason, never a blank


def test_empty_name_is_none():
    r = ps.resolve_name("")
    assert r.kind is None and r.prop is None


# ------------------------------------------------------------------ 2. the alias table is DATA, not code

def test_every_shipped_alias_resolves_to_a_real_reader():
    table = ps._load_aliases()
    assert table, "the shipped name_aliases.json must carry at least one entry"
    dead = []
    for asked, target in table.items():
        r = ps.resolve_name(asked)
        if r.kind != "alias" or r.prop is None:
            dead.append((asked, target, r.kind))
    assert not dead, f"shipped aliases that do not resolve through the target's reader: {dead}"


def test_a_new_alias_entry_routes_an_unseen_name_with_no_code(monkeypatch):
    # Add a brand-new unseen spelling to the LOADED table (what editing the JSON does) and clear the
    # idresolve catalog cache; resolve_name must route it to the target's reader with no code change.
    unseen = "zip.cd_file_names_vendorspelling"
    target = "zip.central_directory_file_names"
    assert ps.lookup(ps.canon(unseen)) is None and ps.synonym(ps.canon(unseen))[0] is None
    assert ps.canon(target) in ps.REG
    monkeypatch.setitem(ps._ALIASES, ps.canon(unseen), target)
    monkeypatch.setitem(ps._ALIASES_RAW, unseen, target)
    monkeypatch.setattr(ps, "_ALIAS_CATALOG", [None, -1])
    r = ps.resolve_name(unseen)
    assert r.kind == "alias" and r.reader == target


def test_the_alias_match_is_spelling_tolerant_through_idresolve():
    # idresolve canonicalises both sides, so punctuation/case variants of a table key still hit (B-010),
    # with no second matcher in resolve_name.
    assert ps._alias_target("PE/AOE/RVA/HEX") == "pe.address_of_entry_point_rva_hex"


# ------------------------------------------------------------------ 3. loud on a missing / malformed table

def test_missing_alias_table_fails_loud(monkeypatch, tmp_path):
    monkeypatch.setattr(ps, "ALIAS_PATH", tmp_path / "does-not-exist.json")
    monkeypatch.setattr(ps, "_ALIAS_LOADED", [False])
    with pytest.raises(ps.AliasTableError) as exc:
        ps._load_aliases()
    assert "not found" in str(exc.value)


def test_malformed_alias_table_fails_loud(monkeypatch, tmp_path):
    bad = tmp_path / "name_aliases.json"
    bad.write_text('{"aliases": ["not", "an", "object"]}', encoding="utf-8")
    monkeypatch.setattr(ps, "ALIAS_PATH", bad)
    monkeypatch.setattr(ps, "_ALIAS_LOADED", [False])
    with pytest.raises(ps.AliasTableError) as exc:
        ps._load_aliases()
    assert "aliases" in str(exc.value)


def test_self_pointing_alias_fails_loud(monkeypatch, tmp_path):
    bad = tmp_path / "name_aliases.json"
    bad.write_text('{"aliases": {"zip.member_names": "zip.member_names"}}', encoding="utf-8")
    monkeypatch.setattr(ps, "ALIAS_PATH", bad)
    monkeypatch.setattr(ps, "_ALIAS_LOADED", [False])
    with pytest.raises(ps.AliasTableError):
        ps._load_aliases()


# ------------------------------------------------------------------ 4. end-to-end: unsure, reader named, plain untouched

def test_aliased_name_is_answered_unsure_with_the_reader_named():
    sample = corpus.lnk_shortcut()
    ans = _ask("lnk.target_path_win", sample)
    assert labels.is_unsure(ans), "a resolved unseen name must never be plain"
    parsed = labels.parse(ans)
    assert parsed.key == "metadata.format/lnk.target_path_win"   # unsure under the ASKED name's own key
    assert parsed.options, "the alias answer must offer at least one option"
    assert all(n.endswith("~lnk.target_path_windows") for n, _ in parsed.options), \
        f"every option must carry the reader: {[n for n, _ in parsed.options]}"


def test_a_plain_identity_answer_is_unchanged_by_the_resolver():
    sample = corpus.lnk_shortcut()
    ans = _ask("filename", sample)       # filename is a judge-confirmed identity fact: plain
    assert labels.parse(ans) is None     # not an unsure pick
    assert str(ans) == sample.name


def test_an_unaliased_unseen_name_is_still_none_end_to_end():
    sample = corpus.lnk_shortcut()
    ans = _ask("lnk.no_such_field_here_zzz", sample)
    assert ans is None
