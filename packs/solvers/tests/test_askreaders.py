"""B-139: ask every registered reader before a lane stops on a MISSING id.

Stub readers (written into a temporary repo root with its own openers/readers.toml) pin the rules:
which ids are MISSING, the order readers are asked, one fact -> an unsure offer (never plain), two facts
-> conflict, no answer -> a named STOP, a failing or unavailable reader is named and never hides another,
the literal none, labels candidates, options already rejected in the labels ledger, the budget, the
lane-solver wrapper, probing through a SubmitGate against a fake Game Master on 127.0.0.1, and the
one-field template an agent fills. tests/test_askreaders_lanes.py runs the real registry on synthetic
samples of the Day 9 shapes.
"""
from __future__ import annotations

import ast
import io
import json
import textwrap
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ctf import askreaders as ar
from ctf import event, paths
from ctf.platform import get_adapter
from ctf.platform.base import SubmitResult, SubmitStatus

LABELS = ar.labels_module()


def q(qid, kind="exact_text", **fmt):
    return {"qid": qid, "id": qid, "answer_id": qid, "question": f"What is {qid}?",
            "answer_format": {"kind": kind, **fmt}}


def make_root(tmp_path: Path, readers: dict, registry: str) -> Path:
    """A repo root with one module per reader ({file stem: source}) and the registry text."""
    root = tmp_path / "root"
    (root / "openers").mkdir(parents=True)
    (root / "solvers" / "stub").mkdir(parents=True)
    for stem, src in readers.items():
        (root / "solvers" / "stub" / f"{stem}.py").write_text(textwrap.dedent(src))
    (root / "openers" / "readers.toml").write_text(textwrap.dedent(registry))
    return root


def entry(name, lanes, stem, call="solve_set", **extra):
    more = "".join(f"{k} = {json.dumps(v)}\n" for k, v in extra.items())
    return (f'[[reader]]\nname = "{name}"\nlanes = {json.dumps(lanes)}\nmodule = "solvers/stub/{stem}.py"\n'
            f'call = "{call}"\n{more}\n')


def table(stem, answers: dict) -> str:
    """A solve_set reader that answers from a fixed {qid: answer} table."""
    return f"ANSWERS = {answers!r}\n\ndef solve_set(questions, files, ctx):\n" \
           f"    return {{q['qid']: ANSWERS.get(q['qid']) for q in questions}}\n"


@pytest.fixture
def work(tmp_path, monkeypatch):
    w = tmp_path / "work"
    w.mkdir()
    monkeypatch.setenv("CTF_WORKDIR", str(w))
    monkeypatch.delenv("CTF_JUDGE_LEDGER", raising=False)
    return w


def unsure(value):
    u = LABELS.parse(value)
    assert u is not None, f"not an unsure answer: {value!r}"
    return u.key, [tuple(o) for o in u.options]


# ------------------------------------------------------------------------------------- the registry

def test_registry_loads_and_rejects_every_malformed_entry(tmp_path):
    good = entry("a", ["metadata"], "a")
    root = make_root(tmp_path, {"a": table("a", {})}, good)
    (r,) = ar.load_registry(root=root)
    assert (r.name, r.lanes, r.call, r.function, r.kind) == ("a", ("metadata",), "solve_set", "solve_set", "reader")
    assert r.path == (root / "solvers/stub/a.py").resolve()
    bad = {
        "unknown key": good.replace('call = "solve_set"', 'call = "solve_set"\nspeed = 1'),
        "duplicate name": good + good,
        "is not there": entry("b", ["metadata"], "nope"),
        "call 'guess'": good.replace('"solve_set"', '"guess"'),
        "kind 'live'": good + entry("c", ["binary"], "a", kind="live"),
        "lanes must be": good.replace('["metadata"]', "[]"),
        "no [[reader]]": "",
    }
    for want, text in bad.items():
        (root / "openers" / "readers.toml").write_text(text)
        with pytest.raises(ar.AskError, match=re_escape(want)):
            ar.load_registry(root=root)
    with pytest.raises(ar.AskError, match="no reader registry"):
        ar.load_registry(root=tmp_path / "elsewhere")


def re_escape(s):
    import re
    return re.escape(s)


def test_the_real_registry_loads_and_each_function_resolves():
    regs = ar.load_registry()
    names = [r.name for r in regs]
    assert {"binary.field_catalog", "metadata.properties_strict", "mobile.apk_facts"} <= set(names)
    for r in regs:
        mod = ar._load_reader(r)
        assert callable(getattr(mod, r.function, None)), f"{r.name}: {r.module} has no {r.function}()"


def test_a_lane_asks_its_own_readers_then_every_lanes_then_live_files(tmp_path, work):
    reg = (entry("everyone", ["*"], "e") + entry("other", ["binary"], "o") + entry("own", ["metadata"], "m"))
    root = make_root(tmp_path, {"e": table("e", {}), "o": table("o", {}), "m": table("m", {})}, reg)
    live = work / "ask-readers" / "metadata"
    live.mkdir(parents=True)
    (live / "field_x.py").write_text(table("x", {}))
    (live / "_helper.py").write_text("")
    names = [r.name for r in ar.readers_for("metadata", root=root, workdir=work)]
    assert names == ["own", "everyone", "live:metadata/field_x"]
    assert [r.name for r in ar.readers_for("binary", root=root, workdir=work)] == ["other", "everyone"]
    with pytest.raises(ar.AskError, match="lane"):
        ar.readers_for("../etc", root=root, workdir=work)


# ------------------------------------------------------------------------------------- MISSING ids

def test_missing_ids_are_none_or_absent_never_unsure_or_plain():
    qs = [q("a"), q("b"), q("c"), q("d"), q("e"), q("z")]
    answers = {"a": "x", "b": None, "c": '??{"k":"metadata.f/x","o":[["n","1"]]}', "e": "", "z": 0}
    assert ar.missing_ids(qs, answers) == ["b", "d"]       # "" and 0 are the bank's answers, not MISSING


# ------------------------------------------------------------------------------------- one fact

def test_one_plain_answer_becomes_an_unsure_offer_never_plain(tmp_path, work):
    root = make_root(tmp_path, {"r": table("r", {"d09-pe-x": "0x8664"})}, entry("meta.r", ["metadata"], "r"))
    rep = ar.ask_missing([q("ok"), q("d09-pe-x")], {"ok": "plain"}, {"s.exe": b"MZ"}, "metadata", root=root,
                         workdir=work)
    assert rep.answers["ok"] == "plain"                    # the bank's answers are kept
    (asked,) = rep.asked                                   # only the MISSING id is asked
    assert asked.outcome == ar.OFFER and rep.ok
    assert unsure(rep.answers["d09-pe-x"]) == ("metadata.ask/d09_pe_x", [("meta.r", "0x8664")])
    assert LABELS.is_unsure(rep.answers["d09-pe-x"])       # never sent as an answer by any runner


def test_readers_that_agree_are_one_fact_and_the_first_keyed_answer_names_the_key(tmp_path, work):
    a = '??{"k":"metadata.format/pe.machine","o":[["integer","34404"],["0x_hex_lower","0x8664"]]}'
    b = '??{"k":"binary.machine/pe","o":[["hex","0x8664"],["name","AMD64"]]}'
    root = make_root(tmp_path, {"p": table("p", {"m": "0x8664"}), "a": table("a", {"m": a}),
                                "b": table("b", {"m": b})},
                     entry("plain", ["metadata"], "p") + entry("ka", ["metadata"], "a") + entry("kb", ["metadata"], "b"))
    rep = ar.ask_missing([q("m")], {}, {"f": b""}, "metadata", root=root, workdir=work)
    (asked,) = rep.asked
    assert asked.outcome == ar.OFFER and len(asked.facts) == 1
    key, opts = unsure(asked.offer)
    assert key == "metadata.format/pe.machine"                 # the first keyed reader's key, not a made-up one
    assert opts == [("plain", "0x8664"), ("integer", "34404"), ("name", "AMD64")]   # one option per value


def test_readers_that_disagree_stop_the_lane_and_nothing_is_guessed(tmp_path, work):
    root = make_root(tmp_path, {"a": table("a", {"m": "0x8664"}), "b": table("b", {"m": "0x014c"})},
                     entry("ra", ["metadata"], "a") + entry("rb", ["metadata"], "b"))
    rep = ar.ask_missing([q("m")], {"m": None}, {"f": b""}, "metadata", root=root, workdir=work)
    (asked,) = rep.asked
    assert asked.outcome == ar.CONFLICT and asked.offer is None and rep.answers["m"] is None
    assert not rep.ok and rep.stops() == [asked]
    assert asked.line().startswith("STOP m: 2 different facts") and "ra" in asked.reason and "rb" in asked.reason


def test_no_reader_knows_the_field_is_a_named_stop(tmp_path, work):
    root = make_root(tmp_path, {"a": table("a", {}), "b": table("b", {"other": "1"})},
                     entry("ra", ["binary"], "a") + entry("rb", ["binary"], "b"))
    rep = ar.ask_missing([q("set2.d10_analysis_has_hcfg_section")], {}, {"f": b""}, "binary", root=root,
                         workdir=work)
    (asked,) = rep.asked
    assert asked.outcome == ar.NO_READER and rep.answers["set2.d10_analysis_has_hcfg_section"] is None
    assert asked.field == "d10_analysis_has_hcfg_section"
    assert "no registered reader knows d10_analysis_has_hcfg_section" in asked.reason
    assert "ra: none" in asked.reason and "rb: none" in asked.reason


def test_a_reader_that_raises_or_cannot_load_is_named_and_the_others_still_answer(tmp_path, work):
    boom = "def solve_set(questions, files, ctx):\n    print('reading header')\n    raise RuntimeError('torn')\n"
    root = make_root(tmp_path, {"boom": boom, "broken": "raise ImportError('half written')\n",
                                "good": table("good", {"m": "7"}), "tools": table("tools", {"m": "8"}),
                                "notdict": "def solve_set(q, f, c):\n    return ['7']\n"},
                     entry("boom", ["metadata"], "boom") + entry("broken", ["metadata"], "broken")
                     + entry("nofn", ["metadata"], "good", function="answers")
                     + entry("tools", ["metadata"], "tools", needs_tools=["no-such-tool-b139"])
                     + entry("notdict", ["metadata"], "notdict") + entry("good", ["metadata"], "good"))
    asked = ar.ask_one(q("m"), {"f": b""}, ar.readers_for("metadata", root=root, workdir=work), "metadata")
    by = {a.reader: a for a in asked.answers}
    assert by["boom"].status == "error" and "RuntimeError: torn" in by["boom"].why
    assert "reading header" in by["boom"].said                      # its own output kept for triage
    assert by["broken"].status == "unavailable" and "does not load" in by["broken"].why
    assert by["nofn"].status == "unavailable" and "no function answers()" in by["nofn"].why
    assert by["tools"].status == "unavailable" and "no-such-tool-b139" in by["tools"].why
    assert by["notdict"].status == "error" and "not a dict" in by["notdict"].why
    assert asked.outcome == ar.OFFER and unsure(asked.offer)[1] == [("good", "7")]


def test_the_literal_none_counts_only_where_the_format_allows_it(tmp_path, work):
    root = make_root(tmp_path, {"n": table("n", {"a": "none", "b": "none"})}, entry("n", ["metadata"], "n"))
    plain = q("a")
    allows = q("b", syntax="the literal none when the sample has no such field")
    rep = ar.ask_missing([plain, allows], {}, {"f": b""}, "metadata", root=root, workdir=work)
    out = {a.qid: a for a in rep.asked}
    assert out["a"].outcome == ar.NO_READER and "literal none" in out["a"].answers[0].why
    assert out["b"].outcome == ar.OFFER and unsure(out["b"].offer)[1] == [("n", "none")]


def test_an_unsure_answers_literal_none_option_is_dropped_where_the_format_forbids_it(tmp_path, work):
    mixed = '??{"k":"metadata.format/pe.x","o":[["absent","none"],["hex","0x5"]]}'
    only = '??{"k":"metadata.format/pe.y","o":[["absent","none"]]}'
    root = make_root(tmp_path, {"n": table("n", {"a": mixed, "b": only, "c": mixed})}, entry("n", ["metadata"], "n"))
    rep = ar.ask_missing([q("a"), q("b"), q("c", accepted_values=["none", "0x5"])], {}, {"f": b""}, "metadata",
                         root=root, workdir=work)
    out = {x.qid: x for x in rep.asked}
    assert unsure(out["a"].offer) == ("metadata.format/pe.x", [("hex", "0x5")])
    assert out["b"].outcome == ar.NO_READER and "literal none" in out["b"].answers[0].why
    assert unsure(out["c"].offer) == ("metadata.format/pe.x", [("absent", "none"), ("hex", "0x5")])


def test_one_member_that_raises_does_not_hide_the_next_members_answer(tmp_path, work):
    src = ("def fields(name, data, questions):\n"
           "    if name == 'a.bin':\n        raise ValueError('bad header')\n"
           "    return {q['qid']: '9' for q in questions}\n")
    root = make_root(tmp_path, {"f": src}, entry("cat", ["binary"], "f", call="fields"))
    asked = ar.ask_one(q("m"), {"a.bin": b"1", "b.bin": b"2"}, ar.readers_for("binary", root=root, workdir=work),
                       "binary")
    assert [(a.member, a.status) for a in asked.answers] == [("a.bin", "error"), ("b.bin", "answered")]
    assert asked.outcome == ar.OFFER


def test_an_unsure_answer_that_does_not_parse_is_a_named_error_not_none(tmp_path, work):
    root = make_root(tmp_path, {"u": table("u", {"m": "??{}", "n": '??{"k":"metadata.format/x","o":[]}'})},
                     entry("u", ["metadata"], "u"))
    rep = ar.ask_missing([q("m"), q("n")], {}, {"f": b""}, "metadata", root=root, workdir=work)
    for asked in rep.asked:
        (a,) = asked.answers
        assert (a.status, asked.outcome) == ("error", ar.NO_READER), asked.qid
        assert "does not parse" in a.why and "u: error" in asked.reason


def test_a_fact_shared_by_a_candidates_answer_and_a_keyed_answer_takes_the_keyed_key(tmp_path, work):
    cand = LABELS.candidates("binary.answer/elf", [("immediate", "0x10")])
    keyed = '??{"k":"binary.entry/elf","o":[["hex","0x10"],["dec","16"]]}'
    root = make_root(tmp_path, {"c": table("c", {"x": cand}), "k": table("k", {"x": keyed})},
                     entry("c", ["binary"], "c") + entry("k", ["binary"], "k"))
    (asked,) = ar.ask_missing([q("x")], {}, {"f": b""}, "binary", root=root, workdir=work).asked
    assert asked.outcome == ar.OFFER and len(asked.facts) == 1
    key, opts = unsure(asked.offer)
    assert key == "binary.entry/elf"            # the candidates reader came first, but its key is a guess list
    assert opts == [("immediate", "0x10"), ("dec", "16")]


def test_a_package_over_the_size_limit_is_a_named_error_and_never_handed_over(tmp_path, work, monkeypatch):
    src = ("CALLED = []\n"
           "def solve_questions(questions, members, blob):\n"
           "    CALLED.append(1)\n"
           "    return {q['qid']: str(sum(len(v) for v in members.values())) for q in questions}\n")
    root = make_root(tmp_path, {"apk": src}, entry("apk", ["mobile"], "apk", call="apk"))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("classes.dex", b"d" * 64)
    files = {"a.apk": buf.getvalue()}
    regs = ar.readers_for("mobile", root=root, workdir=work)
    monkeypatch.setattr(ar, "APK_MAX_BYTES", 63)
    over = ar.ask_one(q("m"), files, regs, "mobile")
    (a,) = over.answers
    assert a.status == "error" and "more than 63 bytes uncompressed" in a.why and over.outcome == ar.NO_READER
    assert ar._load_reader(regs[0]).CALLED == []
    monkeypatch.setattr(ar, "APK_MAX_BYTES", 64)
    at = ar.ask_one(q("m"), files, regs, "mobile")
    assert at.outcome == ar.OFFER and unsure(at.offer)[1] == [("apk", "64")]


def test_a_candidates_answer_with_two_values_is_two_facts(tmp_path, work):
    cand = LABELS.candidates("binary.answer/elf", [("stripped_none", "none"), ("immediate", "0x10")])
    one = LABELS.candidates("binary.answer2/elf", [("immediate", "0x10")])
    root = make_root(tmp_path, {"c": table("c", {"x": cand, "y": one})}, entry("c", ["binary"], "c"))
    rep = ar.ask_missing([q("x", syntax="use the literal none when it is absent"), q("y")], {}, {"f": b""}, "binary", root=root,
                         workdir=work)
    out = {a.qid: a for a in rep.asked}
    assert out["x"].outcome == ar.CONFLICT
    assert out["y"].outcome == ar.OFFER
    key, opts = unsure(out["y"].offer)
    assert key == "binary.answer2/elf" and opts == [("immediate", "0x10")]   # a plain key, not #candidates


def test_options_rejected_in_the_labels_ledger_are_dropped(tmp_path, work):
    a = '??{"k":"metadata.format/pe.thing","o":[["first","1"],["second","0x1"]]}'
    root = make_root(tmp_path, {"a": table("a", {"m": a, "n": '??{"k":"metadata.format/pe.other","o":[["only","5"]]}'})},
                     entry("a", ["metadata"], "a"))
    assert LABELS.learn("metadata.format/pe.thing", "first", "rejected")
    assert LABELS.learn("metadata.format/pe.other", "only", "rejected")
    rep = ar.ask_missing([q("m"), q("n")], {}, {"f": b""}, "metadata", root=root, workdir=work)
    out = {x.qid: x for x in rep.asked}
    assert unsure(out["m"].offer) == ("metadata.format/pe.thing", [("second", "0x1")])
    assert out["n"].outcome == ar.REJECTED and out["n"].offer is None and "rejected" in out["n"].reason


def test_a_spent_budget_skips_the_readers_left_and_says_so(tmp_path, work):
    root = make_root(tmp_path, {"a": table("a", {"m": "1"})}, entry("a", ["metadata"], "a"))
    asked = ar.ask_one(q("m"), {"f": b""}, ar.readers_for("metadata", root=root, workdir=work), "metadata",
                       budget=0)
    assert asked.outcome == ar.NO_READER
    assert asked.answers[0].status == "skipped" and "budget" in asked.answers[0].why


def test_a_fields_catalog_is_asked_per_member_and_two_members_that_differ_conflict(tmp_path, work):
    src = ("def fields(name, data, questions):\n"
           "    return {q['qid']: data[:4].hex() for q in questions if data}\n")
    root = make_root(tmp_path, {"f": src}, entry("cat", ["binary"], "f", call="fields", kind="catalog"))
    regs = ar.readers_for("binary", root=root, workdir=work)
    same = ar.ask_one(q("magic"), {"a.bin": b"\x7fELF..", "b.bin": b"\x7fELF!!", "note": "text, not bytes"},
                      regs, "binary")
    assert [a.member for a in same.answers] == ["a.bin", "b.bin"] and same.outcome == ar.OFFER
    assert unsure(same.offer)[1] == [("cat", "7f454c46")]
    differ = ar.ask_one(q("magic"), {"a.bin": b"\x7fELF", "b.exe": b"MZ\x90\x00"}, regs, "binary")
    assert differ.outcome == ar.CONFLICT


def test_the_inner_ctx_partial_is_never_handed_to_a_reader(tmp_path, work):
    src = "def solve_set(questions, files, ctx):\n    assert 'partial' not in ctx\n    ctx['x'] = 1\n" \
          "    return {q['qid']: '5' for q in questions}\n"
    root = make_root(tmp_path, {"r": src}, entry("r", ["metadata"], "r"))
    ctx = {"partial": {}}
    asked = ar.ask_one(q("m"), {"f": b""}, ar.readers_for("metadata", root=root, workdir=work), "metadata", ctx=ctx)
    assert asked.outcome == ar.OFFER and ctx == {"partial": {}}


# ------------------------------------------------------------------------------------- the lane wrapper

def test_asking_solver_keeps_the_bank_and_fills_missing_ids_with_offers(tmp_path, work):
    root = make_root(tmp_path, {"r": table("r", {"new": "42", "known": "WRONG"})}, entry("r", ["metadata"], "r"))
    bank = {"known": "1", "new": None}

    def lane(questions, files, ctx):
        return dict(bank)

    solver = ar.AskingSolver(lane, "metadata", root=root, workdir=work)
    ctx = {"partial": {}}
    got = solver.solve_set([q("known"), q("new"), q("gone")], {"f": b""}, ctx)
    assert got["known"] == "1"                                   # a banked answer is never re-asked
    assert unsure(got["new"])[1] == [("r", "42")]
    assert got["gone"] is None and bank == {"known": "1", "new": None}
    assert ctx["partial"] == {"new": got["new"]}
    assert ctx["ask_readers"]["counts"] == {"offer": 1, "no_reader": 1, "conflict": 0, "rejected": 0}
    assert [a.qid for a in solver.last_report.stops()] == ["gone"]
    with pytest.raises(ar.AskError):
        ar.AskingSolver(None, "metadata")


# ------------------------------------------------------------------------------------- probing

class FakeGM:
    """A Game Master on 127.0.0.1 that judges each POSTed answer against `key`."""

    def __init__(self):
        self.posts, self.key, self.limit_after = [], {}, None
        gm = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                gm.posts.append(body)
                if gm.limit_after is not None and len(gm.posts) > gm.limit_after:
                    code, reply = 429, {"error": "rate_limited"}
                else:
                    want = gm.key.get(body["challenge"], {})
                    ok = all(want.get(k) == v for k, v in body["answers"].items())
                    code, reply = 200, ({"result": "accepted", "remaining": 1} if ok else {"result": "incorrect"})
                data = json.dumps(reply).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def fake_gm():
    gm = FakeGM()
    yield gm
    gm.close()


FAST = "\n[submit]\nper_minute = 100\ninterval_s = 0.0\nper_challenge_interval_s = 0.0\nmax_hold_s = 30.0\n"


def huntress_at(tmp_path: Path, url: str) -> event.EventProfile:
    src = event.load("huntress").path.read_text()
    src = src.replace('base_url = "https://gamemaster.huntress.example"', f'base_url = "{url}"')
    assert url in src
    (tmp_path / "profiles" / "huntress").mkdir(parents=True)
    (tmp_path / "profiles" / "huntress" / "event.toml").write_text(src + FAST)
    return event.load("huntress", root=tmp_path / "profiles")


def offer_report(tmp_path, work, answers):
    root = make_root(tmp_path, {"r": table("r", answers)}, entry("r", ["metadata"], "r"))
    return ar.ask_missing([q(k) for k in answers], {}, {"f": b""}, "metadata", root=root, workdir=work)


def test_probe_sends_one_option_per_request_until_the_judge_accepts(tmp_path, work, fake_gm, monkeypatch):
    for name in ("CTF_TOKEN", "CTF_PLATFORM_URL"):
        monkeypatch.delenv(name, raising=False)
    rep = offer_report(tmp_path, work, {
        "m": '??{"k":"metadata.format/pe.m","o":[["integer","34404"],["hex","0x8664"],["name","AMD64"]]}'})
    fake_gm.key["metadata-day-09"] = {"m": "0x8664"}
    gate = get_adapter(huntress_at(tmp_path, fake_gm.url))
    verdicts = []
    probes = ar.probe(rep, ar.gate_submit(gate, "metadata-day-09", "ask-readers test"),
                      on_verdict=lambda *v: verdicts.append(v))
    assert [p.status for p in probes] == ["rejected", "accepted"]          # AMD64 is never sent
    assert [p["answers"] for p in fake_gm.posts] == [{"m": "34404"}, {"m": "0x8664"}]
    assert verdicts == [("metadata.format/pe.m", "integer", "rejected"), ("metadata.format/pe.m", "hex", "accepted")]
    with pytest.raises(ar.AskError):
        ar.gate_submit(gate, "metadata-day-09", "")


def test_an_unjudged_answer_holds_every_probe_left_and_learns_nothing(tmp_path, work):
    rep = offer_report(tmp_path, work, {"a": '??{"k":"metadata.format/a","o":[["x","1"],["y","2"]]}', "b": "3"})
    sent = []

    def submit(aid, value):
        sent.append((aid, value))
        return SubmitResult(SubmitStatus.RATE_LIMITED, "rate_limited", retry_after=2)
    verdicts = []
    probes = ar.probe(rep, submit, on_verdict=lambda *v: verdicts.append(v))
    assert sent == [("a", "1")] and verdicts == []
    assert [(p.qid, p.status) for p in probes] == [("a", "held"), ("a", "not_probed"), ("b", "not_probed")]


def test_max_per_id_caps_the_probes_of_one_id(tmp_path, work):
    rep = offer_report(tmp_path, work, {"a": '??{"k":"metadata.format/a","o":[["x","1"],["y","2"],["z","3"]]}'})
    sent = []

    def submit(aid, value):
        sent.append(value)
        return SubmitResult(SubmitStatus.INCORRECT, "incorrect")
    probes = ar.probe(rep, submit, max_per_id=2)
    assert sent == ["1", "2"] and [p.status for p in probes] == ["rejected", "rejected", "not_probed"]
    with pytest.raises(ar.AskError):
        ar.probe(rep, submit, max_per_id=0)


# ------------------------------------------------------------------------------------- the agent case

def test_the_template_is_inert_until_filled_and_then_the_next_ask_finds_it(tmp_path, work):
    root = make_root(tmp_path, {"r": table("r", {})}, entry("r", ["binary"], "r"))
    regs = ar.readers_for("binary", root=root, workdir=work)
    qid = "set1.d09_analysis_hcfg_offset"
    before = ar.ask_one(q(qid), {"s.elf": b"\x7fELF"}, regs, "binary")
    assert before.outcome == ar.NO_READER

    raw = (paths.repo_root() / "templates" / "ask-readers" / "one_field.py").read_text()
    inert = {}
    exec(compile(raw, "one_field.py", "exec"), inert)
    assert inert["solve_set"]([q("__FIELD_ID__x"), q(qid)], {"s": b"x"}, {}) == {}

    path = ar.write_template("binary", qid, before, workdir=work)
    assert path == work / "ask-readers" / "binary" / "field_set1_d09_analysis_hcfg_offset.py"
    text = path.read_text()
    assert f'FIELD_ID = "{qid}"' in text and 'LANE = "binary"' in text
    assert "STOP set1.d09_analysis_hcfg_offset: no registered reader knows" in text and "#   r: none" in text
    with pytest.raises(ar.AskError, match="exists"):
        ar.write_template("binary", qid, before, workdir=work)

    # still inert as written: read() returns None
    assert ar.ask_one(q(qid), {"s.elf": b"\x7fELF"}, ar.readers_for("binary", root=root, workdir=work),
                      "binary").outcome == ar.NO_READER
    path.write_text(text.replace("    return None\n", "    return str(next(iter(files.values())).find(b'ELF'))\n", 1))
    after = ar.ask_one(q(qid), {"s.elf": b"\x7fELF"}, ar.readers_for("binary", root=root, workdir=work), "binary")
    assert after.outcome == ar.OFFER
    assert unsure(after.offer) == ("binary.ask/d09_analysis_hcfg_offset",
                                   [("live:binary/field_set1_d09_analysis_hcfg_offset", "1")])
    # two spellings from the filled file: an unsure answer under the same field key
    path.write_text(path.read_text().replace('return [("as_read", str(value))]',
                                             'return [("dec", str(value)), ("hex", hex(int(value)))]'))
    two = ar.ask_one(q(qid), {"s.elf": b"\x7fELF"}, ar.readers_for("binary", root=root, workdir=work), "binary")
    assert unsure(two.offer) == ("binary.ask/d09_analysis_hcfg_offset", [("dec", "1"), ("hex", "0x1")])


HOSTILE_RAISE = "t\x0bimport os\x85os.getcwd()\u2028x = 1\x00\x0c\x1c\x1d\x1e\u2029y = 2\ud800"


def test_reader_text_in_the_template_stays_comment_and_never_becomes_code(tmp_path, work, capsys):
    raiser = ("def solve_set(questions, files, ctx):\n    print('said\\x00one\\rprint(1)')\n"
              f"    raise RuntimeError({HOSTILE_RAISE!r})\n")
    root = make_root(tmp_path, {"a": table("a", {"m": "x\nprint('PWNED-N')"}),
                                "b": table("b", {"m": "y\rprint('PWNED-R')\r\nz = 3"}), "c": raiser},
                     entry("ra", ["binary"], "a") + entry("rb", ["binary"], "b") + entry("rc", ["binary"], "c"))
    regs = ar.readers_for("binary", root=root, workdir=work)
    asked = ar.ask_one(q("m"), {"f": b""}, regs, "binary")
    assert asked.outcome == ar.CONFLICT and "PWNED-N" in asked.line() and "\n" in asked.line()
    assert [a.status for a in asked.answers] == ["answered", "answered", "error"]
    text = ar.template_text("binary", "m", asked)
    clean = ar.template_text("binary", "m", None)
    assert ast.dump(ast.parse(text)) == ast.dump(ast.parse(clean))        # nothing but comments was added
    compile(text, "field_m.py", "exec")
    text.encode("utf-8")                                                  # no lone surrogate reaches the file
    lines = text.splitlines()
    assert lines == text.removesuffix("\n").split("\n")                   # every break is a real newline
    for needle in ("PWNED-N", "PWNED-R", "import os", "said", "x = 1"):
        hits = [ln for ln in lines if needle in ln]
        assert hits and all(ln.lstrip().startswith("#") for ln in hits), needle
    assert "x\\x0aprint('PWNED-N')" in text and "\\x0bimport os\\x85" in text and "\\ud800" in text
    # written where the next ask runs it: it stays inert, and nothing it quoted is executed
    ar.write_template("binary", "m", asked, workdir=work)
    capsys.readouterr()
    again = ar.ask_one(q("m"), {"f": b""}, ar.readers_for("binary", root=root, workdir=work), "binary")
    live = [a for a in again.answers if a.reader.startswith("live:")]
    assert [a.status for a in live] == ["none"] and "PWNED" not in live[0].said
    assert "PWNED" not in capsys.readouterr().out


def test_template_text_refuses_a_template_without_its_placeholders(tmp_path):
    t = tmp_path / "root" / "templates" / "ask-readers"
    t.mkdir(parents=True)
    (t / "one_field.py").write_text('FIELD_ID = "__FIELD_ID__"\nLANE = "__LANE__"\n')
    with pytest.raises(ar.AskError, match="__CANDIDATES__"):
        ar.template_text("binary", "x", root=tmp_path / "root")


def test_two_threads_asking_at_once_never_mix_their_readers_output(tmp_path, work):
    one = ("def solve_set(questions, files, ctx):\n    print('one-start')\n    ctx['started'].set()\n"
           "    ctx['go'].wait(1.5)\n    print('one-end')\n    return {}\n")
    two = ("import time\ndef solve_set(questions, files, ctx):\n    print('two-start')\n    ctx['go'].set()\n"
           "    time.sleep(0.4)\n    print('two-end')\n    return {}\n")
    root = make_root(tmp_path, {"one": one, "two": two},
                     entry("one", ["metadata"], "one") + entry("two", ["binary"], "two"))
    ctx = {"started": threading.Event(), "go": threading.Event()}
    got = {}

    def ask(lane):
        got[lane] = ar.ask_one(q("m"), {"f": b""}, ar.readers_for(lane, root=root, workdir=work), lane, ctx=ctx)
    t1 = threading.Thread(target=ask, args=("metadata",))
    t1.start()
    assert ctx["started"].wait(10)
    t2 = threading.Thread(target=ask, args=("binary",))
    t2.start()
    t1.join(20)
    t2.join(20)
    assert got["metadata"].answers[0].said == "one-start\none-end\n"
    assert got["binary"].answers[0].said == "two-start\ntwo-end\n"


def test_a_long_reader_output_keeps_its_head_and_its_tail(tmp_path, work):
    src = ("def solve_set(questions, files, ctx):\n"
           "    print('HEAD-LINE ' + 'x' * 20000 + ' TAIL-LINE')\n"
           "    return {}\n")
    root = make_root(tmp_path, {"r": src}, entry("r", ["metadata"], "r"))
    asked = ar.ask_one(q("m"), {"f": b""}, ar.readers_for("metadata", root=root, workdir=work), "metadata")
    said = asked.answers[0].said
    assert said.startswith("HEAD-LINE") and said.rstrip().endswith("TAIL-LINE") and "[... cut ...]" in said
    assert len(said) <= ar.SAID_MAX + len("\n[... cut ...]\n")


def test_cli_list_shows_the_lane_order(tmp_path, work, capsys):
    from ctf import cli
    root = make_root(tmp_path, {"e": table("e", {}), "m": table("m", {})},
                     entry("everyone", ["*"], "e") + entry("own", ["metadata"], "m"))
    assert cli.main(["ask-readers", "list", "--lane", "metadata", "--root", str(root), "--workdir", str(work)]) == 0
    names = [line.split()[0] for line in capsys.readouterr().out.splitlines()]
    assert names == ["own", "everyone"]
    (root / "openers" / "readers.toml").write_text("[[reader]]\nname = 1\n")
    assert cli.main(["ask-readers", "list", "--root", str(root)]) == 2
