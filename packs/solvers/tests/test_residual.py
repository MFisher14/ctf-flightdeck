"""B-254: the irreducible adaptation residual (ctf/residual.py, ctf/cli/residual.py).

Offline. Every test drives the real module against a tmp workdir and a synthetic ledger written in the
test (explicit timestamps, so times to close are exact). The routing test uses the real csctf profile.
No network, no model, no challenge files, nothing sent.
"""
from __future__ import annotations

import argparse
import json

import pytest

from ctf import env, event, ledger, paths, residual, stuck
from ctf.cli import residual as cli
from ctf.platform import gamemaster
from ctf.result import Evidence, SolverResult

ITEM_LANES = {"warmups", "mobile", "metadata", "binary", "script", "web"}


@pytest.fixture
def wd(tmp_path):
    d = tmp_path / "work"
    d.mkdir()
    return d


def write_ledger(wd, recs):
    """Write records with their own ts (ledger.append would stamp the wall clock)."""
    p = ledger.path(wd)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")


def finding(cls="metadata.new_vocabulary", cid="12#owner", **over):
    f = {"residual_class": cls, "challenge_id": cid, "evidence": "owner field read as 'svc_x' by the closest reader",
         "likely_shape": "genuinely new author vocabulary", "controls_tried": ["reader on accepted sample"],
         "bounded_next_probe": "one judge probe on the untimed base"}
    f.update(over)
    return f


def run_cli(argv, capsys):
    p = argparse.ArgumentParser()
    cli.add_arguments(p)
    rc = cli.run(p.parse_args(argv))
    out = capsys.readouterr()
    return rc, out.out, out.err


# --------------------------------------------------------------------------------- classes, playbook

def test_every_class_the_item_names_is_registered_once_per_lane():
    lanes = [c.lane for c in residual.classes()]
    assert set(lanes) == ITEM_LANES and len(lanes) == len(ITEM_LANES)
    assert {c.id for c in residual.classes()} == set(residual.CLASSES)
    for c in residual.classes():
        assert c.id.startswith(c.lane + ".")


def test_each_class_has_a_one_line_playbook_and_every_handoff_field():
    for c in residual.classes():
        assert "\n" not in c.playbook and 40 <= len(c.playbook) <= 220, c.id
        for name in ("title", "no_oracle", "cold_stops_at", "bounded_next_probe", "never"):
            assert getattr(c, name).strip(), (c.id, name)
        assert c.shapes and c.controls, c.id
        assert c.never.startswith("never "), c.id
        # the cold path ends unsure or none: the class's own text says so
        assert "unsure" in c.cold_stops_at and "none" in c.cold_stops_at, c.id


def test_the_evidence_shapes_are_carried():
    shapes = {c.id: " ".join(c.shapes) for c in residual.classes()}
    assert "two complete" in shapes["warmups.lossy_or_unstated_key"]
    assert "hardware keystore" in shapes["mobile.opaque_codec"]
    assert "multiply repairable container" in shapes["metadata.new_vocabulary"]
    assert "structural enum" in shapes["binary.unjudged_enum"]
    assert "unproved whole descriptor" in shapes["script.unproved_descriptor"]
    assert "no response proves" in shapes["web.unproved_effect"]


def test_get_rejects_an_unknown_class_by_name():
    with pytest.raises(residual.ResidualError, match="unknown residual class 'pwn.rop'"):
        residual.get("pwn.rop")
    with pytest.raises(residual.ResidualError):
        residual.get(None)


def test_the_shipped_playbook_doc_is_current_and_lists_every_line():
    doc = (paths.repo_root() / residual.PLAYBOOK_DOC).read_text(encoding="utf-8")
    assert doc == residual.playbook_md(), "run python -m ctf residual playbook --write"
    for c in residual.classes():
        assert f"- **`{c.id}`** ({c.title}): {c.playbook}" in doc
        assert f"- Never: {c.never}." in doc
    for f in residual.FINDING_FIELDS:
        assert f"`{f}`" in doc


def test_cli_playbook_check_fails_on_a_stale_doc_and_write_fixes_it(tmp_path, monkeypatch, capsys):
    (tmp_path / "docs" / "playbooks").mkdir(parents=True)
    monkeypatch.setattr(paths, "repo_root", lambda: tmp_path)
    rc, _, err = run_cli(["playbook", "--check"], capsys)
    assert rc == 1 and "missing" in err
    (tmp_path / residual.PLAYBOOK_DOC).write_text(residual.playbook_md() + "edited\n", encoding="utf-8")
    rc, _, err = run_cli(["playbook", "--check"], capsys)
    assert rc == 1 and "stale" in err
    rc, _, _ = run_cli(["playbook", "--write"], capsys)
    assert rc == 0 and (tmp_path / residual.PLAYBOOK_DOC).read_text(encoding="utf-8") == residual.playbook_md()
    rc, out, _ = run_cli(["playbook", "--check"], capsys)
    assert rc == 0 and "current" in out


def test_cli_classes_and_one_playbook(capsys):
    rc, out, _ = run_cli(["classes"], capsys)
    assert rc == 0 and len(out.strip().splitlines()) == len(residual.CLASSES)
    rc, out, _ = run_cli(["playbook", "binary.unjudged_enum", "--json"], capsys)
    assert rc == 0 and json.loads(out)["lane"] == "binary"
    rc, _, err = run_cli(["playbook", "nope.x"], capsys)
    assert rc == 2 and "unknown residual class" in err


# --------------------------------------------------------------------------------- the handoff

def test_template_prefills_the_bounded_probe_lane_and_never():
    t = residual.handoff_template("web.unproved_effect", challenge_id="7")
    c = residual.CLASSES["web.unproved_effect"]
    assert set(residual.FINDING_FIELDS) <= set(t)
    assert t["bounded_next_probe"] == c.bounded_next_probe and t["never"] == c.never and t["lane"] == "web"
    assert t["challenge_id"] == "7" and t["controls_tried"] == []
    with pytest.raises(residual.ResidualError):
        residual.validate_finding(t)            # a blank template is not a finding


def test_validate_finding_round_trips_and_fills_lane_and_never():
    f = residual.validate_finding(finding())
    assert f.residual_class == "metadata.new_vocabulary" and f.lane == "metadata"
    assert f.never == residual.CLASSES["metadata.new_vocabulary"].never
    assert f.controls_tried == ("reader on accepted sample",)


@pytest.mark.parametrize("field_name", residual.FINDING_FIELDS)
def test_validate_finding_names_each_missing_field(field_name):
    obj = finding()
    del obj[field_name]
    with pytest.raises(residual.ResidualError, match=field_name):
        residual.validate_finding(obj)


@pytest.mark.parametrize("bad", [
    {"evidence": "   "}, {"challenge_id": ""}, {"likely_shape": 3}, {"controls_tried": []},
    {"controls_tried": "reader"}, {"controls_tried": ["ok", " "]}, {"residual_class": "web.xss"},
])
def test_validate_finding_rejects_bad_values(bad):
    with pytest.raises(residual.ResidualError):
        residual.validate_finding(finding(**bad))


def test_validate_finding_rejects_a_non_object():
    with pytest.raises(residual.ResidualError, match="JSON object"):
        residual.validate_finding(["x"])


def test_mark_writes_one_record_with_the_finding_fields(wd):
    rec = residual.mark(residual.validate_finding(finding()), workdir=wd)
    got = [r for r in ledger.read(wd) if r["event"] == residual.RESIDUAL_EVENT]
    assert len(got) == 1 and got[0] == rec
    assert set(rec) - {"ts", "event"} == {"challenge_id", "residual_class", "lane", "evidence", "likely_shape",
                                         "controls_tried", "bounded_next_probe"}
    assert residual.marked(wd) == {"12#owner": "metadata.new_vocabulary"}


def test_marked_latest_wins_and_unknown_classes_are_ignored(wd):
    residual.mark(residual.validate_finding(finding()), workdir=wd)
    residual.mark(residual.validate_finding(finding(cls="binary.unjudged_enum")), workdir=wd)
    write_ledger(wd, [{"ts": 1.0, "event": "residual", "challenge_id": "9", "residual_class": "made.up"}])
    assert residual.marked(wd) == {"12#owner": "binary.unjudged_enum"}


def test_mark_refuses_an_unvalidated_dict(wd):
    with pytest.raises(residual.ResidualError, match="validate_finding"):
        residual.mark(finding(), workdir=wd)


# --------------------------------------------------------------------------------- the hold

def solved(cid="12"):
    return SolverResult("solved", flags=["CSCTF{guess}"], evidence=[Evidence("decode", "xor 0x41")],
                        engine="warmups.crib_decode", challenge_id=cid, notes="one reading")


def test_hold_turns_a_solved_result_into_unsure_and_keeps_the_flags_as_options():
    h = residual.hold(solved(), "warmups.lossy_or_unstated_key", "two complete readings")
    assert h.status == "unsure" and h.flags == ("CSCTF{guess}",)
    assert residual.classes_of(h) == ("warmups.lossy_or_unstated_key",)
    assert h.notes.startswith("one reading\nheld: residual class warmups.lossy_or_unstated_key")
    assert h.evidence[0] == Evidence("decode", "xor 0x41")          # the original evidence is kept
    assert residual.check(h) == []
    assert SolverResult.from_json(h.to_json()) == h                 # still a valid, round-tripping result


def test_hold_turns_a_candidate_into_unsure():
    c = SolverResult("candidate", flags=["a", "b"], challenge_id="3")
    h = residual.hold(c, "mobile.opaque_codec", "native codec")
    assert h.status == "unsure" and h.flags == ("a", "b") and h.notes.startswith("held: ")


@pytest.mark.parametrize("status", ["none", "unsure", "blocked"])
def test_hold_keeps_a_status_that_is_not_forced(status):
    r = SolverResult(status, notes="missing tool x" if status == "blocked" else "")
    h = residual.hold(r, "script.unproved_descriptor", "one copy only")
    assert h.status == status and h.notes == r.notes
    assert residual.classes_of(h) == ("script.unproved_descriptor",)


def test_hold_tags_once():
    h = residual.hold(solved(), "binary.unjudged_enum", "enum name unjudged")
    h2 = residual.hold(h, "binary.unjudged_enum", "again")
    assert [e.kind for e in h2.evidence].count("residual") == 1


def test_hold_needs_a_known_class_and_a_reason():
    with pytest.raises(residual.ResidualError, match="unknown residual class"):
        residual.hold(solved(), "nope", "x")
    with pytest.raises(residual.ResidualError, match="reason"):
        residual.hold(solved(), "binary.unjudged_enum", "  ")


@pytest.mark.parametrize("status", ["solved", "candidate"])
def test_check_flags_a_tagged_forced_answer(status):
    r = SolverResult(status, flags=["x"], challenge_id="5",
                     evidence=[Evidence("residual", "metadata.new_vocabulary: new label")])
    v = residual.check(r)
    assert [x.code for x in v] == ["forced-plain"] and v[0].challenge_id == "5"
    assert "metadata.new_vocabulary" in v[0].message


@pytest.mark.parametrize("status", ["unsure", "none", "blocked"])
def test_check_passes_a_held_or_blocked_residual_result(status):
    r = SolverResult(status, notes="x", evidence=[Evidence("residual", "metadata.new_vocabulary: new label")])
    assert residual.check(r) == []


def test_check_with_a_class_catches_an_untagged_forced_answer():
    assert residual.check(solved()) == []                        # not a residual result: not ours to judge
    v = residual.check(solved(), "web.unproved_effect")
    assert [x.code for x in v] == ["forced-plain"]
    assert residual.check(SolverResult("none"), "web.unproved_effect") == []


def test_check_names_an_unknown_tag_and_rejects_an_unknown_class_argument():
    r = SolverResult("unsure", evidence=[Evidence("residual", "pwn.heap: x")])
    assert [x.code for x in residual.check(r)] == ["unknown-class"]
    r2 = SolverResult("solved", flags=["f"], evidence=[Evidence("residual", "pwn.heap: x")])
    assert [x.code for x in residual.check(r2)] == ["unknown-class"]    # unknown tag alone is not a known class
    with pytest.raises(residual.ResidualError):
        residual.check(solved(), "pwn.heap")


def test_hold_answer_makes_a_value_never_sent_by_the_platform_rule():
    assert residual.hold_answer(None) is None
    assert residual.hold_answer("??a") == "??a"
    assert residual.hold_answer("svc_x") == "??svc_x"
    assert residual.hold_answer(["b", "a"]) == '??["b","a"]'
    for v in ("svc_x", ["b", "a"], 7):
        assert gamemaster.is_unsure(residual.hold_answer(v))       # the gate's own never-sent test


def test_check_answers_flags_only_plain_answers_on_residual_ids():
    ids = {"12#owner": "metadata.new_vocabulary", "12#arch": "binary.unjudged_enum",
           "12#none": "script.unproved_descriptor", "12#gone": "made.up"}
    answers = {"12#owner": "svc_x", "12#arch": "??x86", "12#none": None, "12#other": "plain is fine here",
               "12#list": ["a"]}
    v = residual.check_answers(answers, ids)
    assert sorted((x.code, x.challenge_id) for x in v) == [("forced-plain", "12#owner"), ("unknown-class", "12#gone")]
    held = {k: residual.hold_answer(answers.get(k)) for k in ids if k in answers}
    assert residual.check_answers({**answers, **held}, {k: c for k, c in ids.items() if c != "made.up"}) == []


def test_check_answers_flags_a_list_and_rejects_a_non_object():
    assert [x.code for x in residual.check_answers({"a": ["x", "y"]}, {"a": "binary.unjudged_enum"})] == ["forced-plain"]
    with pytest.raises(residual.ResidualError):
        residual.check_answers(["a"], {})


@pytest.mark.parametrize("value", ["  ??svc_x", '\t??x', 'pick one: ??{"k":"svc_x"}'])
def test_unsure_follows_the_platform_rule_whitespace_led_and_embedded(value):
    assert gamemaster.is_unsure(value)                              # the platform never sends it
    assert residual.hold_answer(value) == value                     # so it is kept as is
    assert residual.check_answers({"12#owner": value}, {"12#owner": "metadata.new_vocabulary"}) == []


def test_a_question_marks_inside_a_plain_answer_do_not_make_it_unsure():
    assert not gamemaster.is_unsure("x ??y")
    assert residual.hold_answer("x ??y") == "??x ??y"
    v = residual.check_answers({"12#owner": "x ??y"}, {"12#owner": "metadata.new_vocabulary"})
    assert [x.code for x in v] == ["forced-plain"]


def test_a_challenge_mark_covers_every_answer_of_it():
    ids = {"12": "binary.unjudged_enum"}
    assert residual.covering(ids, "12#arch") == "12" and residual.covering(ids, "12") == "12"
    assert residual.covering(ids, "120#arch") is None
    v = residual.check_answers({"12#arch": "x86", "12#bits": "??64", "13#a": "plain"}, ids)
    assert [(x.code, x.challenge_id) for x in v] == [("forced-plain", "12#arch")]
    assert "challenge mark '12'" in v[0].message


def test_check_answers_fails_loudly_when_residual_ids_and_answer_keys_do_not_meet():
    ids = {"12#owner": "metadata.new_vocabulary", "14#arch": "binary.unjudged_enum"}
    # the same answer in two namespaces is an error, whatever require_match says
    with pytest.raises(residual.ResidualError, match="'12#owner' vs 'owner'"):
        residual.check_answers({"owner": "svc_x"}, ids, require_match=False)
    with pytest.raises(residual.ResidualError, match="'owner' vs '12#owner'"):
        residual.check_answers({"12#owner": "svc_x"}, {"owner": "metadata.new_vocabulary"})
    # answers, residual ids, and not one meets: nothing was checked
    with pytest.raises(residual.ResidualError, match="no residual id .* covers any answer key"):
        residual.check_answers({"13#size": "4096"}, ids)
    assert residual.check_answers({"13#size": "4096"}, ids, require_match=False) == []
    assert residual.check_answers({}, ids) == []                    # no answers: nothing can be sent
    assert residual.check_answers({"13#size": "4096"}, {"9": "made.up"})[0].code == "unknown-class"
    # some meet: the rest are listed, not an error
    assert residual.check_answers({"12#owner": "??svc_x"}, ids) == []
    assert residual.unmatched({"12#owner": "??svc_x"}, ids) == ["14#arch"]
    assert residual.unmatched({"13#size": "1"}, ids) == ["12#owner", "14#arch"]
    assert residual.unmatched({"13#size": "1"}, {**ids, "9": "made.up"}) == ["12#owner", "14#arch"]
    # an answer another mark already covers is checked, so a same-named bare mark is no mismatch
    assert residual.check_answers({"12#owner": "??x"}, {"12": "metadata.new_vocabulary",
                                                        "owner": "metadata.new_vocabulary"}) == []


def test_a_near_miss_needs_one_ledger_id_and_one_bare_answer_id():
    # two challenges that share an answer name are not one answer in two forms: both keys carry '#'
    ids = {"12#owner": "metadata.new_vocabulary", "14#arch": "binary.unjudged_enum"}
    assert residual.check_answers({"12#owner": "??x", "13#arch": "x"}, ids) == []
    assert residual.unmatched({"12#owner": "??x", "13#arch": "x"}, ids) == ["14#arch"]
    # nor are two ledger ids of the same answer name on different challenges, with require_match off
    assert residual.check_answers({"13#owner": "x"}, {"12#owner": "metadata.new_vocabulary"},
                                  require_match=False) == []


def test_an_answer_on_a_residual_id_of_an_unknown_class_is_named_not_held():
    v = residual.check_answers({"12#owner": "svc_x"}, {"12#owner": "made.up"})
    assert [(x.code, x.challenge_id) for x in v] == [("unknown-class", "12#owner")]


# --------------------------------------------------------------------------------- the submit gate

class _Adapter:
    """A test double of a platform adapter: it records what the gate lets through."""
    kind = "ctfd"

    def __init__(self):
        self.sent = []

    def list_challenges(self):
        return []

    def get_challenge(self, cid):
        raise AssertionError("not used")

    def download_files(self, cid, dest):
        raise AssertionError("not used")

    def submit(self, cid, flag):
        from ctf.platform.base import SubmitResult, SubmitStatus
        self.sent.append((cid, flag))
        return SubmitResult(SubmitStatus.CORRECT, "ok")

    def submit_answers(self, cid, answers):
        from ctf.platform.base import SubmitResult, SubmitStatus
        self.sent.append((cid, dict(answers)))
        return SubmitResult(SubmitStatus.CORRECT, "ok")

    def team_solves(self):
        return []

    def scoreboard(self):
        return []


def test_the_submit_gate_refuses_a_plain_value_on_a_residual_id_without_the_players_go(wd):
    from ctf.platform.base import SubmitStatus
    from ctf.platform.policy import SubmitGate
    adapter = _Adapter()
    gate = SubmitGate(adapter, event.load("csctf"))
    residual.install(gate, workdir=wd)
    assert gate.submit("12#owner", "CSCTF{svc_x}", provenance="p").status is SubmitStatus.CORRECT  # not marked yet
    residual.mark(residual.validate_finding(finding(cid="12#owner")), workdir=wd)
    r = gate.submit("12#owner", "CSCTF{svc_x}", provenance="closest reader")
    assert r.status is SubmitStatus.NOT_ALLOWED and not r.sent
    assert "12#owner (metadata.new_vocabulary) is marked residual" in r.message and "confirmed=True" in r.message
    assert gate.submit("13", "CSCTF{other}", provenance="p").status is SubmitStatus.CORRECT
    r = gate.submit("12#owner", "CSCTF{svc_x}", provenance="the bounded probe", confirmed=True)
    assert r.status is SubmitStatus.CORRECT
    assert adapter.sent == [("12#owner", "CSCTF{svc_x}"), ("13", "CSCTF{other}"), ("12#owner", "CSCTF{svc_x}")]


def test_the_submit_gate_checks_each_answer_of_a_batch_against_a_challenge_mark(wd):
    from ctf.platform.base import SubmitStatus
    from ctf.platform.policy import SubmitGate
    adapter = _Adapter()
    gate = SubmitGate(adapter, event.load("csctf"))
    residual.install(gate, workdir=wd)
    residual.mark(residual.validate_finding(finding(cls="binary.unjudged_enum", cid="14")), workdir=wd)
    r = gate.submit_answers("14", {"arch": "x86", "bits": "??64"}, provenance="p", allow_nonstandard=True)
    assert r.status is SubmitStatus.NOT_ALLOWED and "14#arch (binary.unjudged_enum)" in r.message
    assert "14#bits" not in r.message                                # the unsure one is not a forced guess
    assert adapter.sent == []
    r = gate.submit_answers("15", {"arch": "x86"}, provenance="p", allow_nonstandard=True)
    assert r.status is SubmitStatus.CORRECT and adapter.sent == [("15", {"arch": "x86"})]


def test_gate_refusal_passes_an_unsure_value_a_sweep_and_an_unmarked_id():
    from ctf.platform.policy import SubmitRequest
    ids = {"12#owner": "metadata.new_vocabulary", "9": "made.up"}
    assert residual.gate_refusal(SubmitRequest("12#owner", "  ??svc_x", "p"), ids) is None
    assert residual.gate_refusal(SubmitRequest("12#owner", "svc_x", "p", sweep="auth-1"), ids) is None
    assert residual.gate_refusal(SubmitRequest("12#size", "4096", "p"), ids) is None
    assert residual.gate_refusal(SubmitRequest("9", "x", "p"), ids) is None     # an unknown class holds nothing
    assert "metadata.new_vocabulary" in residual.gate_refusal(SubmitRequest("12#owner", "svc_x", "p"), ids)


def test_a_mark_on_one_answer_holds_a_single_send_on_its_bare_challenge(wd):
    from ctf.platform.base import SubmitStatus
    from ctf.platform.policy import SubmitGate, SubmitRequest
    ids = {"12#owner": "metadata.new_vocabulary", "9#x": "made.up"}
    # an adapter may resolve a bare `12` to its only answer (Game Master does), so the mark holds it
    reason = residual.gate_refusal(SubmitRequest("12", "svc_x", "p"), ids)
    assert reason and "12#owner (metadata.new_vocabulary)" in reason
    assert residual.gate_refusal(SubmitRequest("12", "??svc_x", "p"), ids) is None     # unsure: never sent
    assert residual.gate_refusal(SubmitRequest("12", "svc_x", "p", confirmed=True), ids) is None
    assert residual.gate_refusal(SubmitRequest("1", "svc_x", "p"), ids) is None        # not a prefix match
    assert residual.gate_refusal(SubmitRequest("120", "svc_x", "p"), ids) is None
    assert residual.gate_refusal(SubmitRequest("9", "x", "p"), ids) is None            # unknown class: nothing
    assert residual.gate_refusal(SubmitRequest("12#size", "4096", "p"), ids) is None   # another answer
    adapter = _Adapter()
    gate = SubmitGate(adapter, event.load("csctf"))
    residual.install(gate, workdir=wd)
    residual.mark(residual.validate_finding(finding(cid="12#owner")), workdir=wd)
    r = gate.submit("12", "CSCTF{svc_x}", provenance="closest reader")
    assert r.status is SubmitStatus.NOT_ALLOWED and not r.sent and adapter.sent == []
    assert "12#owner (metadata.new_vocabulary)" in r.message


def test_a_corrupt_ledger_stops_the_send_with_a_named_reason(wd):
    from ctf.platform.policy import SubmitGate
    adapter = _Adapter()
    gate = SubmitGate(adapter, event.load("csctf"))
    residual.install(gate, workdir=wd)
    p = ledger.path(wd)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('{"event": "residual"\n', encoding="utf-8")
    with pytest.raises(residual.ResidualError, match="cannot read the residual marks.*corrupt ledger line"):
        gate.submit("13", "CSCTF{other}", provenance="p")
    assert adapter.sent == []


def test_get_adapter_installs_the_residual_check_on_every_gate(wd, monkeypatch):
    import sys
    import types

    from ctf.platform import get_adapter
    from ctf.platform.policy import SubmitRequest
    mod = types.ModuleType("ctf.platform.ctfd")
    mod.make_adapter = lambda profile: _Adapter()
    monkeypatch.setitem(sys.modules, "ctf.platform.ctfd", mod)
    monkeypatch.setenv("CTF_WORKDIR", str(wd))
    gate = get_adapter(event.load("csctf"))
    req = SubmitRequest("12#owner", "CSCTF{svc_x}", "closest reader")
    assert gate.refusal(req) is None
    residual.mark(residual.validate_finding(finding(cid="12#owner")), workdir=wd)
    assert "is marked residual" in gate.refusal(req)


# --------------------------------------------------------------------------------- the stuck hook

def reject(wd, cid, n):
    for _ in range(n):
        ledger.append("platform.submit", workdir=wd, challenge_id=cid, status="incorrect", judged=True)


def test_route_stuck_refuses_an_id_not_marked_residual(wd):
    reject(wd, "d12_x", 8)
    with pytest.raises(residual.ResidualError, match="not marked residual"):
        residual.route_stuck("d12_x", question="d12_x", files={"f": b"blank"}, workdir=wd)
    assert stuck.stuck_ids(wd) == []


def test_route_stuck_marks_a_residual_id_stuck_and_routes_it(wd):
    from ctf import humanops
    csctf = event.load("csctf")
    residual.mark(residual.validate_finding(finding(cid="d12_hcfg")), workdir=wd)
    reject(wd, "d12_hcfg", stuck.DEFAULT.stuck_after)
    a = residual.route_stuck("d12_hcfg", question="d12_hcfg", files={"f": b"nothing relevant"},
                             workdir=wd, profile=csctf)
    assert a.is_stuck and a.status == stuck.STUCK
    rec = stuck.marked_stuck(wd, "d12_hcfg")
    assert rec["agent"] == "residual:metadata.new_vocabulary" and rec["routed"] is True
    assert any(c.challenge_id == "d12_hcfg" for c in humanops.HumanOps(csctf, workdir=wd).cards())


def test_route_stuck_leaves_an_id_under_the_threshold_alone(wd):
    residual.mark(residual.validate_finding(finding(cid="d12_hcfg")), workdir=wd)
    reject(wd, "d12_hcfg", stuck.DEFAULT.stuck_after - 1)
    a = residual.route_stuck("d12_hcfg", question="d12_hcfg", files={"f": b"nothing"}, workdir=wd)
    assert not a.is_stuck and stuck.marked_stuck(wd, "d12_hcfg") is None


# --------------------------------------------------------------------------------- the frequency report

def event_ledger():
    """Seven challenges, one per closer shape, all detected at t=100."""
    r = [{"ts": 90.0, "event": "wave_open", "wave": "W1", "count": 7}]
    r += [{"ts": 100.0, "event": "detect", "challenge_id": c, "wave": "W1"} for c in "ABCDEFG"]
    r += [
        # A: an engine, then our accepted send -> layer1, 5 s
        {"ts": 102.0, "event": "engine.run", "challenge_id": "A", "engine": "warmups.x", "seconds": 1.0,
         "status": "solved"},
        {"ts": 105.0, "event": "platform.submit", "challenge_id": "A", "status": "correct"},
        # B: an agent launch, then an accepted send -> agent, 300 s
        {"ts": 150.0, "event": "agent_launch", "challenge_id": "B", "harness": "claude"},
        {"ts": 400.0, "event": "platform.submit", "challenge_id": "B#k", "status": "correct"},
        # C: banked by hand (B-036 adapt.closed) -> human, 900 s
        {"ts": 1000.0, "event": "adapt.closed", "challenge_id": "C", "by": "hand", "note": ""},
        # D: a teammate's solve (team-solve stop) -> teammate, 60 s
        {"ts": 160.0, "event": "stop", "challenge_id": "D", "reason": "team_solve", "by": "x"},
        # E: open (a rejection only)
        {"ts": 200.0, "event": "platform.submit", "challenge_id": "E", "status": "incorrect"},
        # F: spend, then a correct timed attempt (B-036) -> agent, 100 s
        {"ts": 150.0, "event": "spend", "challenge_id": "F", "usd": 0.5, "tok": 100},
        {"ts": 200.0, "event": "adapt.attempt", "challenge_id": "F", "outcome": "correct"},
        # G: layer1 accept at 110, then a hand mark at 500: the earliest close wins -> layer1, 10 s
        {"ts": 108.0, "event": "engine.run", "challenge_id": "G", "engine": "binary.y", "seconds": 1.0},
        {"ts": 110.0, "event": "platform.submit", "challenge_id": "G", "status": "correct"},
        {"ts": 500.0, "event": "adapt.closed", "challenge_id": "G", "by": "hand", "note": ""},
        # residual marks and the stuck protocol
        {"ts": 120.0, "event": "residual", "challenge_id": "C", "residual_class": "metadata.new_vocabulary"},
        {"ts": 121.0, "event": "residual", "challenge_id": "E", "residual_class": "binary.unjudged_enum"},
        {"ts": 122.0, "event": "residual", "challenge_id": "E#k", "residual_class": "binary.unjudged_enum"},
        {"ts": 300.0, "event": "stuck", "challenge_id": "E", "status": "stuck"},
        {"ts": 310.0, "event": "stuck", "challenge_id": "Z", "status": "stuck"},
        {"ts": 320.0, "event": "stuck_cleared", "challenge_id": "Z", "reason": "rewritten"},
    ]
    return r


def test_frequency_attributes_each_close_and_times_it_from_detect():
    rep = residual.frequency(event_ledger(), label="huntress")
    by = {c.challenge_id: (c.closer, c.seconds_to_close, c.start) for c in rep.closes}
    assert by == {"A": ("layer1", 5.0, "detect"), "B": ("agent", 300.0, "detect"),
                  "C": ("human", 900.0, "detect"), "D": ("teammate", 60.0, "detect"),
                  "F": ("agent", 100.0, "detect"), "G": ("layer1", 10.0, "detect")}
    assert rep.counts == {"layer1": 2, "agent": 2, "human": 1, "teammate": 1, "other": 0}
    assert rep.novel_ids == ["B", "C", "D", "F"] and rep.novel_share == pytest.approx(4 / 6)
    assert rep.median_seconds["agent"] == (200.0, 2) and rep.median_seconds["layer1"] == (7.5, 2)
    assert rep.median_seconds["other"] == (None, 0)
    assert "E" in rep.open_ids and "Z" in rep.open_ids


def test_frequency_reports_residual_marks_their_ends_and_stuck_ids():
    rep = residual.frequency(event_ledger(), label="huntress")
    # E and E#k are one challenge: the report keys every id the way replay.stage_events does
    assert rep.residual == {"C": "metadata.new_vocabulary", "E": "binary.unjudged_enum"}
    assert rep.residual_by_class["binary.unjudged_enum"] == 1
    assert rep.residual_by_class["metadata.new_vocabulary"] == 1
    assert set(rep.residual_by_class) == set(residual.CLASSES)
    assert rep.residual_closed == {"C": "human"}
    assert rep.stuck == ["E"]                                      # Z was cleared


def test_frequency_keys_an_answer_id_by_its_challenge_like_the_b101_stages():
    """The module's own example id: detect, mark, launch, stuck and accept all on '12#owner'."""
    recs = [{"ts": 10.0, "event": "detect", "challenge_id": "12#owner"},
            {"ts": 11.0, "event": "residual", "challenge_id": "12#owner",
             "residual_class": "metadata.new_vocabulary"},
            {"ts": 20.0, "event": "agent_launch", "challenge_id": "12#owner", "harness": "claude"},
            {"ts": 25.0, "event": "stuck", "challenge_id": "12#owner", "status": "stuck"},
            {"ts": 70.0, "event": "platform.submit", "challenge_id": "12#owner", "status": "correct"}]
    rep = residual.frequency(recs, label="x")
    assert rep.ids_seen == 1 and rep.open_ids == []
    assert [(c.challenge_id, c.closer, c.start, c.seconds_to_close) for c in rep.closes] == \
        [("12", "agent", "detect", 60.0)]
    assert rep.residual == {"12": "metadata.new_vocabulary"}
    assert rep.residual_closed == {"12": "agent"}
    assert rep.stuck == ["12"]
    text = residual.render_report(rep)
    assert "ids seen 1; closed 1; open 0" in text and "  12: metadata.new_vocabulary -> agent, stuck" in text


def test_frequency_keys_the_b036_records_and_several_classes_on_one_challenge():
    recs = [{"ts": 1.0, "event": "detect", "challenge_id": "7"},
            {"ts": 31.0, "event": "adapt.closed", "challenge_id": "7#arch", "by": "hand", "note": ""},
            {"ts": 2.0, "event": "adapt.chain", "challenge_id": "8#a"},
            {"ts": 12.0, "event": "adapt.attempt", "challenge_id": "8#a", "outcome": "correct"},
            {"ts": 3.0, "event": "stop", "challenge_id": "10#k", "reason": "team_solve", "by": "x"},
            {"ts": 1.5, "event": "detect", "challenge_id": "10"},
            {"ts": 5.0, "event": "residual", "challenge_id": "9#x", "residual_class": "binary.unjudged_enum"},
            {"ts": 6.0, "event": "residual", "challenge_id": "9#y", "residual_class": "script.unproved_descriptor"},
            {"ts": 7.0, "event": "stuck", "challenge_id": "9#x", "status": "stuck"},
            {"ts": 8.0, "event": "stuck_cleared", "challenge_id": "9#x", "reason": "rewritten"}]
    rep = residual.frequency(recs, label="x")
    assert rep.ids_seen == 4 and rep.open_ids == ["9"]
    by = {c.challenge_id: (c.closer, c.start, c.seconds_to_close) for c in rep.closes}
    assert by["7"] == ("human", "detect", 30.0)
    assert by["8"][1:] == ("first_record", 10.0)
    assert by["10"] == ("teammate", "detect", 1.5)
    assert rep.residual == {"9": "script.unproved_descriptor"}           # the latest mark wins
    assert rep.residual_by_class["binary.unjudged_enum"] == 1
    assert rep.residual_by_class["script.unproved_descriptor"] == 1
    assert rep.stuck == []
    assert any("challenge 9 carries residual marks in several classes" in n for n in rep.notes)


def test_a_detect_at_the_same_instant_as_the_accept_times_from_detect_at_zero():
    recs = [{"ts": 5.0, "event": "detect", "challenge_id": "S"},
            {"ts": 5.0, "event": "platform.submit", "challenge_id": "S", "status": "correct"}]
    rep = residual.frequency(recs, label="x")
    assert [(c.challenge_id, c.start, c.seconds_to_close) for c in rep.closes] == [("S", "detect", 0.0)]
    assert not any("no earlier record" in n for n in rep.notes)


def test_time_to_close_falls_back_to_the_first_record_and_notes_an_untimed_close():
    recs = [{"ts": 10.0, "event": "agent_launch", "challenge_id": "P", "harness": "codex"},
            {"ts": 70.0, "event": "platform.submit", "challenge_id": "P", "status": "correct"},
            {"ts": 50.0, "event": "adapt.closed", "challenge_id": "Q", "by": "teammate", "note": ""}]
    rep = residual.frequency(recs, label="x")
    by = {c.challenge_id: c for c in rep.closes}
    assert (by["P"].start, by["P"].seconds_to_close, by["P"].closer) == ("first_record", 60.0, "agent")
    assert (by["Q"].start, by["Q"].seconds_to_close, by["Q"].closer) == ("none", None, "teammate")
    assert any("no earlier record" in n and "Q" in n for n in rep.notes)
    assert rep.median_seconds["teammate"] == (None, 0)


def test_a_close_with_no_attributable_stage_is_other_and_not_novel():
    recs = [{"ts": 1.0, "event": "detect", "challenge_id": "R"},
            {"ts": 9.0, "event": "platform.submit", "challenge_id": "R", "status": "already_solved"}]
    rep = residual.frequency(recs, label="x")
    assert rep.counts["other"] == 1 and rep.novel_ids == [] and rep.novel_share == 0.0


def test_an_empty_ledger_has_no_share_and_says_so():
    rep = residual.frequency([], label="x")
    assert rep.novel_share is None and rep.closes == [] and "the ledger is empty" in rep.notes


def test_report_for_names_a_missing_ledger_and_a_corrupt_line(wd):
    with pytest.raises(residual.ResidualError, match="no ledger at"):
        residual.report_for(wd)
    ledger.path(wd).write_text("{not json\n", encoding="utf-8")
    with pytest.raises(residual.ResidualError, match="corrupt ledger line"):
        residual.report_for(wd)


def test_render_report_states_the_novel_share_and_residual_ends():
    text = residual.render_report(residual.frequency(event_ledger(), label="huntress"))
    assert "== huntress: residual frequency ==" in text
    assert "closed only by agent/human/teammate (novel): 4 of 6 (66.7%)" in text
    assert "  C: metadata.new_vocabulary -> human" in text
    assert "  E: binary.unjudged_enum -> open, stuck" in text
    assert "median time to close: layer1 7.5s (n=2), agent 200s (n=2)" in text


# --------------------------------------------------------------------------------- the CLI

def test_cli_mark_then_check_answers(wd, tmp_path, capsys):
    f = tmp_path / "f.json"
    f.write_text(json.dumps(finding()), encoding="utf-8")
    rc, out, _ = run_cli(["--workdir", str(wd), "mark", str(f)], capsys)
    assert rc == 0 and "12#owner" in out
    a = tmp_path / "a.json"
    a.write_text(json.dumps({"12#owner": "svc_x", "12#size": "4096"}), encoding="utf-8")
    rc, out, _ = run_cli(["--workdir", str(wd), "check-answers", str(a)], capsys)
    assert rc == 1 and "forced-plain" in out and "12#owner" in out
    a.write_text(json.dumps({"12#owner": "??svc_x", "12#size": "4096"}), encoding="utf-8")
    rc, out, _ = run_cli(["--workdir", str(wd), "check-answers", str(a)], capsys)
    assert rc == 0


def test_cli_check_answers_names_unmatched_ids_and_fails_when_none_match(wd, tmp_path, capsys):
    for cid in ("12#owner", "14#arch"):
        residual.mark(residual.validate_finding(finding(cid=cid)), workdir=wd)
    a = tmp_path / "a.json"
    a.write_text(json.dumps({"12#owner": "??svc_x"}), encoding="utf-8")
    rc, _, err = run_cli(["--workdir", str(wd), "check-answers", str(a)], capsys)
    assert rc == 0 and "1 residual id(s) cover no answer key" in err and "14#arch" in err
    a.write_text(json.dumps({"13#size": "4096"}), encoding="utf-8")
    rc, _, err = run_cli(["--workdir", str(wd), "check-answers", str(a)], capsys)
    assert rc == 2 and "covers any answer key" in err
    rc, _, err = run_cli(["--workdir", str(wd), "check-answers", str(a), "--allow-unmatched"], capsys)
    assert rc == 0 and "2 residual id(s) cover no answer key" in err
    a.write_text(json.dumps({"owner": "svc_x"}), encoding="utf-8")
    rc, _, err = run_cli(["--workdir", str(wd), "check-answers", str(a), "--allow-unmatched"], capsys)
    assert rc == 2 and "'12#owner' vs 'owner'" in err


def test_cli_mark_rejects_a_bad_finding_and_writes_nothing(wd, tmp_path, capsys):
    f = tmp_path / "f.json"
    f.write_text(json.dumps(finding(controls_tried=[])), encoding="utf-8")
    rc, _, err = run_cli(["--workdir", str(wd), "mark", str(f)], capsys)
    assert rc == 2 and "controls_tried" in err
    assert not ledger.path(wd).exists()


def test_cli_check_and_hold(tmp_path, capsys):
    p = tmp_path / "r.json"
    p.write_text(solved().to_json(), encoding="utf-8")
    rc, out, _ = run_cli(["check", str(p), "--class", "warmups.lossy_or_unstated_key"], capsys)
    assert rc == 1 and "forced-plain" in out
    rc, out, _ = run_cli(["check", str(p)], capsys)
    assert rc == 0
    rc, out, _ = run_cli(["hold", str(p), "--class", "warmups.lossy_or_unstated_key", "--why", "two readings"],
                         capsys)
    assert rc == 0
    held = SolverResult.from_json(out)
    assert held.status == "unsure"
    p.write_text(out, encoding="utf-8")
    rc, _, _ = run_cli(["check", str(p)], capsys)
    assert rc == 0
    p.write_text("not json", encoding="utf-8")
    rc, _, err = run_cli(["check", str(p)], capsys)
    assert rc == 2 and "not JSON" in err


def test_cli_stuck_exit_codes(wd, tmp_path, capsys):
    residual.mark(residual.validate_finding(finding(cid="d14_x")), workdir=wd)
    blank = tmp_path / "blank.bin"
    blank.write_bytes(b"\x00nothing\x00")
    base = ["--workdir", str(wd), "stuck", "d14_x", "--question", "d14_x", "--file", str(blank), "--no-route"]
    rc, out, _ = run_cli(base + ["--rejections", "1"], capsys)
    assert rc == 1 and "ok" in out
    rc, out, _ = run_cli(base + ["--rejections", str(stuck.DEFAULT.stuck_after)], capsys)
    assert rc == 0 and "stuck" in out and stuck.marked_stuck(wd, "d14_x") is not None
    rc, _, err = run_cli(["--workdir", str(wd), "stuck", "other", "--question", "other"], capsys)
    assert rc == 2 and "not marked residual" in err


def test_cli_report_per_workdir_and_the_novel_share_gate(tmp_path, capsys):
    a, b = tmp_path / "huntress", tmp_path / "pink"
    write_ledger(a, event_ledger())
    write_ledger(b, [{"ts": 1.0, "event": "detect", "challenge_id": "1"},
                     {"ts": 2.0, "event": "engine.run", "challenge_id": "1", "engine": "e", "seconds": 0.5},
                     {"ts": 3.0, "event": "platform.submit", "challenge_id": "1", "status": "correct"}])
    rc, out, _ = run_cli(["report", "--workdir", str(a), "--workdir", str(b), "--json"], capsys)
    assert rc == 0
    got = {r["label"]: r for r in json.loads(out)}
    assert got["huntress"]["counts"]["agent"] == 2 and got["pink"]["novel_share"] == 0.0
    rc, _, err = run_cli(["report", "--workdir", str(a), "--workdir", str(b), "--max-novel-share", "0.5"], capsys)
    assert rc == 1 and "huntress" in err and "pink" not in err
    rc, _, _ = run_cli(["report", "--workdir", str(b), "--max-novel-share", "0.0"], capsys)
    assert rc == 0


def test_cli_report_on_a_named_workdir_without_a_ledger_fails_loudly(tmp_path, capsys):
    rc, _, err = run_cli(["report", "--workdir", str(tmp_path / "none")], capsys)
    assert rc == 2 and "no ledger at" in err


def _no_workdir_env(monkeypatch):
    for name in ("CTF_WORKDIR", *env.legacy_names("CTF_WORKDIR")):
        monkeypatch.delenv(name, raising=False)


def test_cli_report_all_events_measures_those_with_a_ledger_and_names_the_rest(tmp_path, monkeypatch, capsys):
    _no_workdir_env(monkeypatch)
    monkeypatch.setattr(paths, "DEFAULT_WORK_BASE", tmp_path)
    write_ledger(tmp_path / "huntress", event_ledger())
    rc, out, err = run_cli(["report", "--all-events"], capsys)
    assert rc == 0 and "== huntress: residual frequency ==" in out
    assert "not measured: csctf: no ledger at" in err
    rc, _, err = run_cli(["report", "--all-events", "--event", "csctf"], capsys)
    assert rc == 2 and "no ledger at" in err                   # a named event must have a ledger


def test_cli_report_all_events_with_nothing_measured_fails(tmp_path, monkeypatch, capsys):
    _no_workdir_env(monkeypatch)
    monkeypatch.setattr(paths, "DEFAULT_WORK_BASE", tmp_path)
    rc, _, err = run_cli(["report", "--all-events"], capsys)
    assert rc == 2 and "no event has a ledger" in err


def test_cli_report_refuses_several_events_under_one_ctf_workdir(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    rc, _, err = run_cli(["report", "--event", "csctf", "--event", "huntress"], capsys)
    assert rc == 2 and "both resolve to the workdir" in err and "CTF_WORKDIR" in err
    rc, _, err = run_cli(["report", "--event", "csctf"], capsys)     # one event under the override is fine
    assert rc == 2 and "no ledger at" in err
    rc, _, err = run_cli(["report", "--event", "no-such-event"], capsys)
    assert rc == 2 and "unknown event" in err
