"""B-119: `ctf marker` (ctf/cli/marker.py): fields, candidates and the guess-budget plan, learn, kb.

The commands run through `ctf.cli.main` on a synthetic handout. The profile is a synthetic TOML with
a stated guess budget; the submit gate, rules, queue and ledger used to spend a guess are real and the
platform is a scripted adapter (test_submit_queue.ScriptedAdapter). The knowledge base starts empty
(a temp seed and workdir). Expected markers come from hashlib over literal preimages.
"""
from __future__ import annotations

import hashlib
import json

import pytest

import ctf.cli as cli
import labels
from ctf import event

from test_flagcheck import gate_for, make
from test_submit_queue import ScriptedAdapter

TRUTH = "0x5A515837:0x7B1C:2031-02-03T04:05:06Z:30007:911"
DIGEST = hashlib.sha256(TRUTH.encode()).hexdigest()
FLAG = "PINK{" + DIGEST[:8] + "}"
VERBATIM = "PINK{" + hashlib.sha256(b"ZQX7:0x7B1C:2031-02-03T04:05:06Z:30007:911").hexdigest()[:8] + "}"
ICS_CONV = ("sha256[:8];colon;header=hex_0x_upper,station=as_stored,timestamp=as_stored,"
            "register=as_stored,seed=as_stored")
FIELDS = ["--field", "header:tag=ZQX7", "--field", "station=0x7B1C", "--field",
          "timestamp=2031-02-03T04:05:06Z", "--field", "register=30007", "--field", "seed=911"]
SIBLING = ["--field", "header:tag=KLM2", "--field", "station=0x19AF", "--field",
           "timestamp=2032-06-07T08:09:10Z", "--field", "register=41000", "--field", "seed=5"]
SIBLING_FLAG = "PINK{" + hashlib.sha256(b"0x4B4C4D32:0x19AF:2032-06-07T08:09:10Z:41000:5").hexdigest()[:8] + "}"
COMMON = ["--digest", "sha256[:8]", "--family", "ics", "--budget", "60000"]


@pytest.fixture
def board(tmp_path, monkeypatch):
    """A synthetic event (guess budget 2), an empty knowledge base and an empty challenge folder."""
    for name in ("CTF_JUDGE_LEDGER", "CTF_LEDGER_MASK", "CTF_FAMILY_PRIOR"):
        monkeypatch.delenv(name, raising=False)
    work = tmp_path / "work"
    monkeypatch.setenv("CTF_WORKDIR", str(work))
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    monkeypatch.setattr(labels, "seed_path", lambda lane: seeds / f"{lane}.json")
    labels._cache.clear()
    labels._gate_said.clear()
    state = {"profile": make(tmp_path, budget=2, stop=9), "work": work, "case": tmp_path / "case"}
    state["case"].mkdir()
    monkeypatch.setattr(event, "current", lambda root=None: state["profile"])
    yield state
    labels._cache.clear()


def run(capsys, *argv):
    code = cli.main(["marker", *map(str, argv)])
    out, err = capsys.readouterr()
    return code, out, err


def test_candidates_with_a_witness_plans_the_reasoned_value_then_guesses_and_holds_the_rest(board, tmp_path, capsys):
    out_file, save = tmp_path / "held.txt", tmp_path / "report.json"
    code, out, _ = run(capsys, "candidates", board["case"], *FIELDS, *COMMON, "--witness", DIGEST[-8:] + "@suffix",
                       "--id", "7", "--out", out_file, "--save", save)
    assert code == 0
    assert f"   1. {FLAG}   [witness] {ICS_CONV}" in out and f"   2. {VERBATIM}   [prior]" in out
    assert "plan: guess budget 2 per challenge, 2 left on challenge 7" in out
    sends = [line.strip() for line in out.splitlines() if line.strip().startswith("send: ")]
    assert sends[0] == f"send: ctf submit 7 '{FLAG}' --source derived --note 'ctf marker candidates, rank 1'"
    assert sends[1] == f"send: ctf submit 7 '{VERBATIM}' --guess --note 'ctf marker candidates, rank 2'"
    assert len(sends) == 3 and sends[2].endswith("--guess --note 'ctf marker candidates, rank 3'")
    assert "the first candidate is a guess" not in out
    held = out_file.read_text(encoding="utf-8").splitlines()
    doc = json.loads(save.read_text(encoding="utf-8"))
    flags = [c["flag"] for c in doc["candidates"]]
    assert held == flags[3:] and len(held) == 21 and f"held for the player: 21 candidate(s) (written to {out_file})" in out
    assert doc["plan"] == {"send": flags[:3], "held": flags[3:], "reasoned": True, "guesses_left": 2}
    assert doc["kinds"]["header"] == "tag" and doc["family"] == "ics" and doc["supported"] is True
    assert "ctf policy authorize-sweep 7" in out and "ctf policy sweep 7" in out


def test_candidates_without_backing_are_all_guesses_and_say_so(board, capsys):
    code, out, _ = run(capsys, "candidates", board["case"], *FIELDS, *COMMON)
    assert code == 0 and f"   1. {VERBATIM}   [prior]" in out
    assert "the first candidate is a guess: no strong witness and no accepted convention backs it" in out
    sends = [line.strip() for line in out.splitlines() if line.strip().startswith("send: ")]
    assert len(sends) == 2 and all("--guess" in s and "--source" not in s for s in sends)
    assert sends[0].startswith(f"send: ctf submit <id> '{VERBATIM}' --guess")
    assert "held for the player: 22 candidate(s) (--out FILE writes them)" in out


def test_the_plan_counts_the_guesses_the_challenge_has_used(board, capsys):
    gate = gate_for(board["profile"], ScriptedAdapter(), board["work"])
    assert gate.submit("7", "PINK{an_earlier_guess}", provenance="old guess", guess=True).sent
    code, out, _ = run(capsys, "candidates", board["case"], *FIELDS, *COMMON, "--id", "7", "--json")
    doc = json.loads(out)
    assert code == 0 and doc["plan"]["guesses_left"] == 1 and doc["plan"]["send"] == [VERBATIM]
    assert len(doc["plan"]["held"]) == 23 and doc["plan"]["reasoned"] is False
    other = json.loads(run(capsys, "candidates", board["case"], *FIELDS, *COMMON, "--id", "8", "--json")[1])
    assert other["plan"]["guesses_left"] == 2 and len(other["plan"]["send"]) == 2


def test_a_zero_guess_budget_sends_nothing_unbacked(board, tmp_path, capsys):
    board["profile"] = make(tmp_path, budget=0)
    code, out, _ = run(capsys, "candidates", board["case"], *FIELDS, *COMMON)
    assert code == 0 and "send: " not in out and "held for the player: 24 candidate(s)" in out
    code, out, _ = run(capsys, "candidates", board["case"], *FIELDS, *COMMON, "--witness", DIGEST[-8:])
    sends = [line for line in out.splitlines() if "send: " in line]
    assert len(sends) == 1 and FLAG in sends[0] and "--source derived" in sends[0]


def test_candidates_options_reach_the_search(board, capsys):
    code, out, _ = run(capsys, "candidates", board["case"], "--field", "a=left", "--field", "b=right",
                       "--field", "c=mid", "--keep-order", "--max-deviations", "0", "--min-fields", "3",
                       "--top", "4", "--nonstandard", "--json")
    doc = json.loads(out)
    assert code == 0 and (doc["space"], doc["enumerated"], doc["exhausted"]) == (9, 9, True)
    assert len(doc["candidates"]) == 4 and doc["digests"] == ["sha256[:8]", "sha256"]
    assert doc["candidates"][0]["flag"] == hashlib.sha256(b"left:right:mid").hexdigest()[:8]      # bare: --nonstandard
    assert doc["plan"]["send"] == [c["flag"] for c in doc["candidates"][:2]]
    assert run(capsys, "candidates", board["case"], "--field", "a=left", "--budget", "0")[0] == 2


def test_a_bare_marker_is_planned_with_the_switch_the_gate_needs_to_take_it(board, capsys):
    bare = hashlib.sha256(b"left:right").hexdigest()[:8]
    args = ["candidates", board["case"], "--field", "a=left", "--field", "b=right", "--digest", "sha256[:8]",
            "--id", "7"]
    code, out, _ = run(capsys, *args, "--nonstandard")
    sends = [line.strip() for line in out.splitlines() if line.strip().startswith("send: ")]
    assert code == 0 and len(sends) == 2
    assert sends[0] == f"send: ctf submit 7 '{bare}' --guess --nonstandard --note 'ctf marker candidates, rank 1'"
    assert all(" --nonstandard " in line for line in sends)
    # the gate refuses the same value without the switch, and takes it with it
    gate = gate_for(board["profile"], ScriptedAdapter(), board["work"])
    refused = gate.submit("7", bare, provenance="ctf marker candidates, rank 1", guess=True)
    assert not refused.sent and "not in the event flag format" in refused.message
    assert gate.submit("7", bare, provenance="ctf marker candidates, rank 1", guess=True, allow_nonstandard=True).sent
    # a value in the flag format is planned without it
    code, out, _ = run(capsys, *args)
    assert code == 0 and "send: " in out and "--nonstandard" not in out


def test_candidates_reads_the_handout_when_no_field_is_given(board, capsys):
    files = board["case"] / "files"
    files.mkdir()
    (files / "a.json").write_text(json.dumps({"station": "0x7B1C", "seed": 911, "tag": DIGEST[-8:]}), encoding="utf-8")
    (files / "b.xml").write_text('<c><Station id="0x7B1C"/><Seed>911</Seed></c>', encoding="utf-8")
    code, out, _ = run(capsys, "fields", board["case"])
    assert code == 0 and " * station:hexid=0x7B1C   (files/a.json, files/b.xml)" in out
    assert " * seed:integer=911   (files/a.json, files/b.xml)" in out and f"witness {DIGEST[-8:]} (files/a.json:tag)" in out
    doc = json.loads(run(capsys, "fields", board["case"], "--json")[1])
    assert [f["name"] for f in doc["fields"]] == ["station", "seed"] and doc["witnesses"][0]["token"] == DIGEST[-8:]
    code, out, _ = run(capsys, "candidates", board["case"], "--json")
    doc = json.loads(out)
    assert code == 0 and [f["name"] for f in doc["fields"]] == ["station", "seed"]
    assert doc["candidates"][0]["flag"] == "PINK{" + hashlib.sha256(b"0x7B1C:911").hexdigest()[:8] + "}"
    assert doc["witnesses"] == [{"token": DIGEST[-8:], "where": "edge", "source": "files/a.json:tag"}]


def test_fields_and_candidates_name_the_witness_tags_that_were_not_compared(board, capsys):
    files = board["case"] / "files"
    files.mkdir()
    (files / "a.json").write_text(json.dumps({"station": "0x7B1C", "seed": 911}), encoding="utf-8")
    (files / "b.xml").write_text('<c><Station id="0x7B1C"/><Seed>911</Seed></c>', encoding="utf-8")
    tags = [hashlib.sha256(b"audit line %d" % i).hexdigest()[:8] for i in range(35)]
    (files / "audit.log").write_text("".join(f"hash={t}\n" for t in tags), encoding="utf-8")
    cut = (f"the files label 35 hex tags; only the first 32 are compared (the last one compared is {tags[31]}, "
           "files/audit.log:hash) and 3 are not")
    code, out, _ = run(capsys, "fields", board["case"])
    assert code == 0 and f"note: {cut}" in out
    assert out.count("\nwitness ") == 32 and f"witness {tags[32]} " not in out
    doc = json.loads(run(capsys, "fields", board["case"], "--json")[1])
    assert [w["token"] for w in doc["witnesses"]] == tags[:32] and any(n.startswith(cut) for n in doc["notes"])
    code, out, _ = run(capsys, "candidates", board["case"])
    assert code == 0 and f"note: {cut}" in out and "32 witness(es), 0 hit(s)" in out


def test_a_stated_digest_lists_the_familys_convention_recut_and_as_a_guess(board, capsys):
    run(capsys, "learn", "--verdict", "accepted", "--family", "ics", "--convention", ICS_CONV, "--kind", "header=tag")
    recut = ICS_CONV.replace("sha256[:8]", "sha256[:16]")
    flag16 = "PINK{" + hashlib.sha256(b"0x4B4C4D32:0x19AF:2032-06-07T08:09:10Z:41000:5").hexdigest()[:16] + "}"
    code, out, _ = run(capsys, "candidates", board["case"], *SIBLING, "--digest", "sha256[:16]", "--family", "ics",
                       "--budget", "60000")
    assert code == 0 and f"   1. {flag16}   [kb-recut] {recut}" in out and SIBLING_FLAG not in out
    assert "under sha256[:8]; the digest stated here is sha256[:16]" in out
    assert "the first candidate is a guess: no strong witness and no accepted convention backs it" in out
    sends = [line.strip() for line in out.splitlines() if line.strip().startswith("send: ")]
    assert sends[0].startswith(f"send: ctf submit <id> '{flag16}' --guess") and "--source" not in "".join(sends)
    # the cut the judge accepted: the convention as it is, the reasoned value
    code, out, _ = run(capsys, "candidates", board["case"], *SIBLING, *COMMON)
    assert f"   1. {SIBLING_FLAG}   [kb] {ICS_CONV}" in out and "--source derived" in out


def test_candidates_with_nothing_to_build_from_exits_one_and_says_what_to_pass(board, capsys):
    (board["case"] / "only.json").write_text('{"alpha": "left"}', encoding="utf-8")
    code, out, err = run(capsys, "candidates", board["case"])
    assert code == 1 and out == ""
    assert "no named value is held by two evidence sources (seen once: alpha=left)" in err and "--field" in err
    assert run(capsys, "candidates", board["case"], "--all-fields")[0] == 0


def test_errors_exit_two_and_name_the_problem(board, tmp_path, capsys):
    for argv, why in [(["candidates", tmp_path / "missing", "--field", "a=1"], "challenge folder not found"),
                      (["candidates", board["case"], "--field", "novalue"], "name[:kind]=value"),
                      (["candidates", board["case"], "--field", "a=1", "--witness", "xyz"], "8 hex"),
                      (["candidates", board["case"], "--field", "a=1", "--digest", "crc32"], "digest form"),
                      (["candidates", board["case"], "--field", "a=1", "--event", "no-such-event"], "no-such-event"),
                      (["candidates", board["case"], "--field", "a=1", "--out", tmp_path / "no" / "dir.txt"], "cannot write"),
                      (["fields", tmp_path / "missing"], "challenge folder not found"),
                      (["learn", "--verdict", "accepted"], "give --from REPORT --flag VALUE"),
                      (["learn", "--verdict", "accepted", "--family", "ics", "--convention", "nope"], "write <digest>"),
                      (["learn", "--verdict", "accepted", "--family", "ics", "--convention", ICS_CONV, "--kind", "header"],
                       "write ROLE=KIND"),
                      (["learn", "--verdict", "accepted", "--from", tmp_path / "missing.json", "--flag", "x"],
                       "cannot read the report")]:
        code, _, err = run(capsys, *argv)
        assert code == 2 and "ctf marker" in err and why in err, (argv, err)


def test_learn_from_a_report_teaches_the_family_and_the_next_run_answers_alone(board, tmp_path, capsys):
    save = tmp_path / "report.json"
    run(capsys, "candidates", board["case"], *FIELDS, *COMMON, "--witness", DIGEST[-8:], "--save", save)
    code, _, err = run(capsys, "learn", "--from", save, "--flag", "PINK{00000000}", "--verdict", "accepted")
    assert code == 2 and "is not a candidate of" in err
    code, out, _ = run(capsys, "learn", "--from", save, "--flag", FLAG, "--verdict", "accepted", "--id", "7")
    assert code == 0
    assert out.splitlines()[:4] == [f"accepted: marker.convention/ics#candidates -> {ICS_CONV}",
                                    "accepted: marker.join/ics -> colon", "accepted: marker.digest/ics -> sha256[:8]",
                                    "accepted: marker.render/tag.ics -> hex_0x_upper"]
    assert "ctf seed-fold marker" in out
    code, out, _ = run(capsys, "learn", "--from", save, "--flag", VERBATIM, "--verdict", "rejected")
    assert code == 0 and out.count("rejected: ") == 1
    # the judged value may be given as the bare marker (what a --nonstandard send carried)
    third = json.loads(save.read_text(encoding="utf-8"))["candidates"][2]
    assert third["flag"] == "PINK{" + third["marker"] + "}"
    code, out, _ = run(capsys, "learn", "--from", save, "--flag", third["marker"], "--verdict", "rejected")
    assert code == 0 and out.splitlines()[0] == f"rejected: marker.convention/ics#candidates -> {third['convention']}"
    doc = json.loads(run(capsys, "kb", "--json")[1])
    assert doc["families"]["ics"]["accepted"] == [ICS_CONV] and len(doc["families"]["ics"]["rejected"]) == 2
    assert doc["joins"] == ["colon"] and doc["digests"] == ["sha256[:8]"] and doc["renderings"] == {"tag": ["hex_0x_upper"]}
    # a sibling of the family, new values, no witness: the accepted convention is the one reasoned value
    code, out, _ = run(capsys, "candidates", board["case"], *SIBLING, *COMMON, "--id", "9")
    assert code == 0 and f"   1. {SIBLING_FLAG}   [kb] {ICS_CONV}" in out
    assert f"send: ctf submit 9 '{SIBLING_FLAG}' --source derived" in out


def test_learn_by_name_and_the_kb_listing(board, capsys):
    code, out, _ = run(capsys, "kb")
    assert code == 0 and "holds no convention yet" in out
    code, out, _ = run(capsys, "learn", "--verdict", "accepted", "--family", "Energy Grid", "--convention", ICS_CONV,
                       "--kind", "Header=TAG", "--kind", "station=hexid")
    assert code == 0 and "accepted: marker.render/tag.energy_grid -> hex_0x_upper" in out and "hexid" not in out
    code, out, _ = run(capsys, "kb", "--family", "energy grid")
    assert code == 0 and "family energy_grid: 1 accepted, 0 rejected" in out and f"accepted  {ICS_CONV}" in out
    assert "fields to name: header, station, timestamp, register, seed" in out
    assert "joins colon; digests sha256[:8]" in out and "tag values: hex_0x_upper before the stored spelling" in out
    run(capsys, "learn", "--verdict", "rejected", "--family", "ics", "--convention", ICS_CONV)
    everything = run(capsys, "kb")[1]
    assert "family energy_grid: 1 accepted, 0 rejected" in everything and "family ics: 0 accepted, 1 rejected" in everything
    only = run(capsys, "kb", "--family", "ICS")[1]
    assert "family ics: 0 accepted, 1 rejected" in only and "energy_grid" not in only and f"rejected  {ICS_CONV}" in only


def test_without_a_judge_ledger_learn_and_kb_refuse_and_candidates_say_so(board, monkeypatch, capsys):
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "off")
    code, _, err = run(capsys, "learn", "--verdict", "accepted", "--family", "ics", "--convention", ICS_CONV)
    assert code == 2 and "no judge ledger" in err
    code, _, err = run(capsys, "kb")
    assert code == 2 and "no judge ledger" in err
    code, out, _ = run(capsys, "candidates", board["case"], *FIELDS, *COMMON)
    assert code == 0 and "note: this event has no judge ledger" in out and f"   1. {VERBATIM}" in out


def test_the_command_is_listed_with_its_help():
    names = {name: (mod, err) for name, mod, err in cli.discover()}
    mod, err = names["marker"]
    assert err is None and "B-119" in mod.HELP
