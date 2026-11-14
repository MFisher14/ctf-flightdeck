"""R-06: the web proof model under the Huntress profile.

The web readers' never-wrong rule runs on ctf.flagfmt's payoff stand-ins: under an event whose profile
defines [proof] (Huntress: proof_<32 hex>) the payoff is the proof, a proof is never a flag candidate,
and a flag-shaped token is another family that only makes a payoff ambiguous; under a flag event
(CSCTF) the payoff is the flag, as before. These tests pin both events and check both directions.
"""
from __future__ import annotations

import json
import os

import pytest

from ctf import event, flagfmt

import event_pin
import forge_event as FE
import post_exploit as PE
import recon_advanced as RA

HEX_V4 = "0123456789ab4def8abc0123456789ab"        # nibble 12 = 4, nibble 16 = 8: a v4 UUID
HEX_NOT_V4 = "0123456789ab1def2abc0123456789ab"
PROOF = "proof_" + HEX_V4
OTHER_PROOF = "proof_" + "fedcba9876544321" + "8" + "fedcba987654321"
HUNTRESS_FLAG = "flag{" + "ab" * 16 + "}"


@pytest.fixture
def huntress(monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "huntress")


@pytest.fixture
def csctf(monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")


def page(obj, status=200):
    return {"status": status, "body": json.dumps(obj).encode(), "response_headers": {"Content-Type": "application/json"}}


# ------------------------------------------------------------------------------------------ ctf.flagfmt
def test_literal_lead_of_the_huntress_proof():
    assert flagfmt.literal_lead(event.load("huntress").proof.pattern) == "proof_"


@pytest.mark.parametrize("pattern,lead", [
    ("tok-[A-Z]+", "tok-"),
    ("ab?c", "a"),                 # a quantifier takes the last character off the run
    ("abc{3}", "ab"),
    ("abc*", "ab"),
    ("proof{[0-9a-f]+}", "proof"),  # a literal brace, not a quantifier
    ("a|proof_x", ""),             # top-level alternation: no common lead
    ("(?:proof)_x", ""),
    ("[pq]roof_x", ""),
    ("(a|b)c", ""),
])
def test_literal_lead(pattern, lead):
    assert flagfmt.literal_lead(pattern) == lead


def test_literal_lead_ignores_alternation_inside_groups_and_classes():
    assert flagfmt.literal_lead("proof_(?:a|b)[|]") == "proof_"


def test_proof_shape_is_the_lead_with_any_body_any_case(huntress):
    text = f"a {PROOF} b PROOF_AAAAAAAAAAAA c proof_future-format-alph d xproof_abcdef e proof_ab"
    assert flagfmt.PROOF_SHAPE.findall(text) == [PROOF, "PROOF_AAAAAAAAAAAA", "proof_future-format-alph"]


def test_proof_shape_without_a_literal_lead_is_the_anycase_proof():
    prof = event.parse({
        "slug": "r06-nolead", "name": "no lead", "dates": {"start": event._dt.date(2026, 1, 1),
                                                          "end": event._dt.date(2026, 1, 2)},
        "platform": {"kind": "manual"}, "flag": {"prefixes": ["F"]},
        "proof": {"pattern": "(?:tok|key)_[0-9]{4}"},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
    }, src="test")
    ff = flagfmt.for_profile(prof)
    assert ff.proof_shape_regex.pattern == ff.proof_regex_anycase.pattern
    assert ff.proof_shape_regex.findall("TOK_1234 key_99999") == ["TOK_1234"]


def test_proof_stand_ins_match_nothing_without_a_proof(csctf):
    assert flagfmt.PROOF_SHAPE.search(f"{PROOF} PROOF_AAAAAAAAAAAA") is None
    assert flagfmt.payoff_kind() == "flag"


def test_brace_text_is_any_events_flag_shape(huntress):
    hits = flagfmt.BRACE_TEXT.findall("CSCTF{two words} x flag{ab} y PINK{z} {nope} a{b}")
    assert hits == ["CSCTF{two words}", "flag{ab}"]     # body >= 2 chars; a bare brace has no prefix


def test_payoff_stand_ins_follow_the_event(monkeypatch):
    csctf_flag = "CSCTF{payoff}"
    monkeypatch.setenv("CTF_EVENT", "huntress")
    assert flagfmt.payoff_kind() == "proof"
    assert flagfmt.PAYOFF_TEXT.findall(f"{PROOF} {HUNTRESS_FLAG} {csctf_flag}") == [PROOF]
    assert flagfmt.PAYOFF_TEXT.fullmatch(PROOF.upper()) is None
    assert flagfmt.PAYOFF_ANYCASE.fullmatch("PROOF_" + HEX_V4.upper())
    assert flagfmt.PAYOFF_OTHER.findall(f"{PROOF} {HUNTRESS_FLAG} {csctf_flag}") == [HUNTRESS_FLAG, csctf_flag]
    monkeypatch.setenv("CTF_EVENT", "csctf")
    assert flagfmt.PAYOFF_TEXT.findall(f"{PROOF} {csctf_flag}") == [csctf_flag]
    assert flagfmt.PAYOFF_SHAPE.findall(f"{PROOF} {csctf_flag}") == [csctf_flag]
    assert flagfmt.PAYOFF_OTHER.findall(f"{PROOF} {csctf_flag} zz{{x}}") == [csctf_flag, "zz{x}"]


def test_payoff_uuid4(monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "huntress")
    assert flagfmt.PAYOFF_UUID4.fullmatch(PROOF)
    assert flagfmt.PAYOFF_UUID4.fullmatch("proof_" + HEX_NOT_V4) is None
    assert flagfmt.uuid4_token(PROOF) and not flagfmt.uuid4_token("proof_" + HEX_NOT_V4)
    monkeypatch.setenv("CTF_EVENT", "csctf")
    assert flagfmt.PAYOFF_UUID4.fullmatch("CSCTF{x}")


# ------------------------------------------------------------------------------------------ forge_event
def test_extract_success_returns_the_huntress_proof_never_as_a_candidate(huntress):
    got = FE.extract_success(page({"ok": True, "proof": PROOF}))
    assert got["auto"] == PROOF
    assert PROOF not in got["candidates"]
    assert got["uuid4"] is True


def test_extract_success_huntress_non_v4_proof_is_still_the_answer(huntress):
    proof = "proof_" + HEX_NOT_V4
    got = FE.extract_success(page({"ok": True, "proof": proof}))
    assert got["auto"] == proof and got["uuid4"] is False


def test_extract_success_subtracts_a_baseline_proof_decoy(huntress):
    decoy = FE.response_baseline_text(page({"note": f"example token {PROOF}"}))
    got = FE.extract_success(page({"ok": True, "proof": PROOF}), baseline_texts=[decoy])
    assert got["auto"] is None
    assert PROOF in got["baseline_decoys"]
    assert PROOF not in got["candidates"]


def test_extract_success_baseline_decoy_does_not_hide_a_novel_proof(huntress):
    decoy = FE.response_baseline_text(page({"note": f"example token {OTHER_PROOF}"}))
    got = FE.extract_success(page({"ok": True, "proof": PROOF}), baseline_texts=[decoy])
    assert got["auto"] == PROOF


def test_extract_success_uppercase_baseline_proof_still_subtracts(huntress):
    decoy = FE.response_baseline_text(page({"note": PROOF.upper()}))
    got = FE.extract_success(page({"ok": True, "proof": PROOF}), baseline_texts=[decoy])
    assert got["auto"] is None


def test_extract_success_near_miss_proof_is_a_candidate_not_the_answer(huntress):
    got = FE.extract_success(page({"ok": True, "proof": "PROOF_" + HEX_V4.upper()}))
    assert got["auto"] is None
    assert "PROOF_" + HEX_V4.upper() in got["candidates"]


def test_extract_success_flag_beside_a_proof_is_ambiguity_not_an_answer(huntress):
    got = FE.extract_success(page({"ok": True, "proof": PROOF, "note": HUNTRESS_FLAG}))
    assert got["auto"] is None
    assert HUNTRESS_FLAG in got["candidates"]


def test_extract_success_a_flag_alone_is_never_a_huntress_answer(huntress):
    got = FE.extract_success(page({"ok": True, "flag": HUNTRESS_FLAG}))
    assert got["auto"] is None and got["wire"] == []


def test_extract_success_two_proofs_are_ambiguous(huntress):
    got = FE.extract_success(page({"ok": True, "proof": PROOF, "evidence": OTHER_PROOF}))
    assert got["auto"] is None


def test_extract_success_csctf_still_returns_its_flag(csctf):
    got = FE.extract_success(page({"ok": True, "flag": "CSCTF{payoff_value}"}))
    assert got["auto"] == "CSCTF{payoff_value}"
    got = FE.extract_success(page({"ok": True, "flag": PROOF}))
    assert got["auto"] is None                        # no [proof] in csctf: a proof is not an answer


def test_baseline_proofs_record_the_payoff_family(monkeypatch):
    text = f"{PROOF} CSCTF{{decoy}}"
    monkeypatch.setenv("CTF_EVENT", "huntress")
    assert FE.baseline_proofs([text]) == [PROOF]
    monkeypatch.setenv("CTF_EVENT", "csctf")
    assert FE.baseline_proofs([text]) == ["CSCTF{decoy}"]


# ------------------------------------------------------------------------------------------ other readers
def test_post_exploit_note_names_the_payoff_kind():
    assert PE.FLAG_NOTE and "CSCTF" not in PE.FLAG_NOTE and "COURSESTACK" not in PE.FLAG_NOTE


def test_recon_advanced_read_body_refuses_urls_and_payoff_tokens(monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "huntress")
    assert RA._safe_json_read_body("case-17") == "case-17"
    for bad in ("https://evil.test/x", "file:///etc/passwd", "gopher://h/", PROOF, PROOF.upper(),
                HUNTRESS_FLAG):
        assert RA._safe_json_read_body(bad) is RA._AMBIGUOUS, bad
    monkeypatch.setenv("CTF_EVENT", "csctf")
    assert RA._safe_json_read_body("CSCTF{x}") is RA._AMBIGUOUS


def test_recon_advanced_canaries_and_platform_hosts_follow_the_event(monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "huntress")
    assert RA._slug() == "huntress"
    assert RA._platform_hosts() == {"gamemaster.huntress.example"}     # no made-up proxy name
    monkeypatch.setenv("CTF_EVENT", "csctf")
    assert RA._platform_hosts() == {"2026.ctf-platform.example"}


def _profile(platform: dict):
    return event.parse({
        "slug": "r06-hosts", "name": "hosts", "dates": {"start": event._dt.date(2026, 1, 1),
                                                       "end": event._dt.date(2026, 1, 2)},
        "platform": platform, "flag": {"prefixes": ["F"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
    }, src="test")


def test_profile_platform_hosts_parse_and_validate():
    prof = _profile({"kind": "ctfd", "base_url": "https://Board.Example/", "hosts": ["Proxy.Board.Example"]})
    assert prof.platform.hosts == ("Proxy.Board.Example",)
    assert prof.platform.all_hosts() == {"board.example", "proxy.board.example"}
    assert _profile({"kind": "ctfd", "base_url": "https://b.example"}).platform.hosts == ()
    assert _profile({"kind": "manual"}).platform.all_hosts() == frozenset()
    for bad in ("https://p.example", "p.example:8443", "p.example/x", "p example", "-p.example",
                "p.example\n"):
        with pytest.raises(event.EventError, match="platform.hosts"):
            _profile({"kind": "ctfd", "base_url": "https://b.example", "hosts": [bad]})


def test_recon_advanced_rebind_refuses_every_profile_platform_host(monkeypatch):
    prof = _profile({"kind": "ctfd", "base_url": "https://board.example", "hosts": ["proxy.board.example"]})
    monkeypatch.setattr(RA.ctf_event, "current", lambda: prof)
    target = "https://web-1.target.example/"
    assert RA._platform_hosts() == {"board.example", "proxy.board.example"}
    for host in ("board.example", "proxy.board.example", "PROXY.board.example"):
        assert RA._safe_rebind_url(f"http://{host}/x", target) is None, host
    assert RA._safe_rebind_url("http://rebind.other.example/x", target) == "http://rebind.other.example/x"


def test_recon_advanced_platform_hosts_fail_loudly_without_a_host(monkeypatch):
    import dataclasses
    prof = _profile({"kind": "ctfd", "base_url": "https://board.example"})
    broken = dataclasses.replace(prof, platform=event.Platform(kind="ctfd"))
    monkeypatch.setattr(RA.ctf_event, "current", lambda: broken)
    with pytest.raises(RuntimeError, match="names no platform host"):
        RA._platform_hosts()
    manual = dataclasses.replace(prof, platform=event.Platform(kind="manual"))
    monkeypatch.setattr(RA.ctf_event, "current", lambda: manual)
    assert RA._platform_hosts() == set()                  # a manual event has no platform of its own


# ------------------------------------------------------------------------------------------ success_signal
def _text_page(text):
    return {"status": 200, "body": text.encode(), "response_headers": {"Content-Type": "text/plain"}}


def test_success_signal_proof_recovered_is_an_affirmation(huntress):
    assert FE.success_signal(_text_page(f"status: proof_recovered {PROOF}"), host="t.example") is True
    assert FE.success_signal(_text_page(f"status: done {PROOF}"), host="t.example") is False


def test_success_signal_offhost_carrier_cannot_donate_a_proof(huntress):
    host = "t.example"
    # The proof appears only inside an off-host URL: no success.
    assert FE.success_signal(_text_page(f"accepted see https://evil.example/cb?p={PROOF}"), host=host) is False
    # An off-host carrier holding the proof strips it from the whole body, even where it also appears
    # bare: the carrier may have donated it.
    assert FE.success_signal(
        _text_page(f"accepted {PROOF} see https://evil.example/cb?p={PROOF}"), host=host) is False
    # The same body with an on-host URL keeps the proof.
    assert FE.success_signal(
        _text_page(f"accepted {PROOF} see https://{host}/cb?p={PROOF}"), host=host) is True


# ------------------------------------------------------------------------------------------ tests/event_pin.py
def test_event_pin_refuses_an_unknown_profile():
    with pytest.raises(event.EventError):
        event_pin.pin({}, "r06-no-such-event")


def test_event_pin_defines_an_autouse_fixture_and_leaves_the_env_alone():
    g = {"__name__": "test_module"}
    before = os.environ.get("CTF_EVENT")
    event_pin.pin(g, "huntress")
    assert g["PINNED_EVENT"] == "huntress"
    marker = getattr(g["_event_pin"], "_fixture_function_marker", None) or getattr(g["_event_pin"], "_pytestfixturefunction")
    assert marker.autouse is True
    assert os.environ.get("CTF_EVENT") == before


def test_event_pin_script_mode_sets_the_process_event(monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")          # restored after the test
    event_pin.pin({"__name__": "__main__"}, "huntress")
    assert os.environ["CTF_EVENT"] == "huntress"

