"""B-076: solvers/toolkits/http_triage.py -- odd-response ranking, Basic auth and base64 header decoding,
header fragment joins through ctf/fragjoin.py, the CLI's SolverResult and the pcap [intake] table.

Captures are written here (tests/b076_fixtures.py): whole TCP connections carrying HTTP/1.1, the shape of
the Spooky Cleithrophobia capture (twenty POSTs, nineteen 401, one 200 with three base64 header parts).
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import b076_fixtures as fx
import http_triage as ht
from ctf import event, flagfmt
from ctf.engines import manifest as M
from ctf.intake import engines as E
from ctf.intake.guard import Guard

REPO = Path(__file__).resolve().parent.parent
SPOOKY = flagfmt.for_profile(event.load("spooky"))
FLAG = "Spooky{Be0m_Me_Up_Sc0tty_2266}"
MANIFEST = REPO / "solvers" / "toolkits" / "http_triage.manifest.toml"


def ignition_capture(*, winner_index=13, parts=("0tty_2266}", "Spooky{Be0", "m_Me_Up_Sc"), order=(3, 1, 2),
                     decoys=True) -> bytes:
    p = fx.Pcap()
    if decoys:
        p.conversation(fx.http_request("GET", "/status", [("X-Telemetry", "warp_core_telemetry=" + fx.b64("all green 42"))]),
                       fx.http_response(200, "OK", body=b"ok"))
    for i in range(20):
        if i == winner_index:
            heads = [(f"X-Part-{n}", f"deflector_part{n}=" + fx.b64(parts[k])) for k, n in enumerate(order)]
            p.conversation(fx.http_request("POST", "/bridge/ignition?try=%d" % i,
                                           [("Authorization", fx.basic("captain.kirk", "Enterprise-1701-A"))]),
                           fx.http_response(200, "OK", heads, b"IGNITION AUTHORIZED"))
        else:
            p.conversation(fx.http_request("POST", "/bridge/ignition", [("Authorization", fx.basic(f"crew{i}", f"Pw-{i}"))]),
                           fx.http_response(401, "Unauthorized", body=b"IGNITION DENIED"))
    return p.bytes()


def test_the_one_success_among_401s_ranks_first_with_its_credentials():
    res = ht.triage(ignition_capture(), SPOOKY)
    assert len(res["pairs"]) == 21
    top = res["odd"][0]
    assert top["status"] == 200 and top["group"] == "POST /bridge/ignition"
    assert top["statuses"] == {401: 19, 200: 1}
    assert any("a success among 19 401" in r for r in top["reasons"])
    assert any("X-Part-1" in r for r in top["reasons"])                    # its lone base64 headers raise it
    assert [o["status"] for o in res["odd"]] == [200]                     # the 401s and the lone GET are not odd
    won = [b for b in res["basic"] if b["odd"]]
    assert [(b["user"], b["password"], b["status"]) for b in won] == [("captain.kirk", "Enterprise-1701-A", 200)]
    assert len(res["basic"]) == 20 and sum(b["status"] == 401 for b in res["basic"]) == 19


def test_header_parts_are_decoded_and_joined_in_part_order():
    res = ht.triage(ignition_capture(), SPOOKY)
    decoded = {h["field"]: h["text"] for h in res["headers"]}
    assert decoded["X-Part-1:deflector_part1"] == "Spooky{Be0"
    assert decoded["X-Telemetry:warp_core_telemetry"] == "all green 42"
    assert [j["flag"] for j in res["joins"]] == [FLAG]
    assert res["joins"][0]["parts"] == ["X-Part-1:deflector_part1", "X-Part-2:deflector_part2", "X-Part-3:deflector_part3"]
    r = ht.solver_result(res)
    assert r.status == "candidate" and r.flags == (FLAG,)
    assert r.evidence[0].kind == "join"


def test_a_join_that_skips_a_numbered_part_is_dropped():
    a, b, c = (fjf("x_part1", "flag{a"), fjf("x_part2", "b"), fjf("x_part3", "c}"))
    from ctf.fragjoin import Join
    assert ht.coherent(Join("flag{abc}", (a, b, c)))
    assert not ht.coherent(Join("flag{ac}", (a, c)))
    assert ht.coherent(Join("flag{ac}", (a, fjf("unnumbered", "c}"))))


def fjf(name, text):
    from ctf.fragjoin import Field
    return Field("http:header", name, text, 0)


def test_odd_needs_a_group_of_three_and_a_dominant_status():
    p = fx.Pcap()
    for status in (401, 200):
        p.conversation(fx.http_request("GET", "/a"), fx.http_response(status, "x"))
    assert ht.triage(p.bytes(), SPOOKY)["odd"] == []                     # two requests: no majority to stand out from
    p = fx.Pcap()
    for status in (200, 401, 403, 404, 500, 302):
        p.conversation(fx.http_request("GET", "/b"), fx.http_response(status, "x"))
    assert ht.triage(p.bytes(), SPOOKY)["odd"] == []                     # no status answers half
    p = fx.Pcap()
    for status in (401, 401, 401, 200):
        p.conversation(fx.http_request("GET", "/c"), fx.http_response(status, "x"))
    odd = ht.triage(p.bytes(), SPOOKY)["odd"]
    assert [o["status"] for o in odd] == [200] and odd[0]["score"] == pytest.approx(1.75)


def test_a_rare_failure_among_successes_is_odd_but_ranks_below_a_lone_success():
    p = fx.Pcap()
    for status in (200, 200, 200, 200, 500):
        p.conversation(fx.http_request("GET", "/x"), fx.http_response(status, "x"))
    for status in (403, 403, 403, 403, 200):
        p.conversation(fx.http_request("GET", "/y"), fx.http_response(status, "x"))
    odd = ht.triage(p.bytes(), SPOOKY)["odd"]
    assert [(o["group"], o["status"]) for o in odd] == [("GET /y", 200), ("GET /x", 500)]


def test_a_flag_whole_in_one_header_value_is_solved():
    p = fx.Pcap()
    p.conversation(fx.http_request("GET", "/"), fx.http_response(200, "OK", [("X-Secret", fx.b64("spooky{one_header}"))]))
    res = ht.triage(p.bytes(), SPOOKY)
    assert [f["flag"] for f in res["flags"]] == ["spooky{one_header}"]
    r = ht.solver_result(res)
    assert r.status == "solved" and r.flags == ("spooky{one_header}",)


def test_basic_auth_decoding():
    assert ht.basic_auth(fx.basic("captain.kirk", "Enterprise-1701-A")) == ("captain.kirk", "Enterprise-1701-A")
    assert ht.basic_auth("Basic YTpi") == ("a", "b")                     # a short token still decodes
    assert ht.basic_auth("Bearer " + fx.b64("a:b")) is None
    assert ht.basic_auth("Basic " + fx.b64("no colon here")) is None
    assert ht.basic_auth(None) is None


def test_odd_response_with_no_flag_is_unsure_naming_it():
    p = fx.Pcap()
    for status in (401, 401, 401, 200):
        p.conversation(fx.http_request("POST", "/login"), fx.http_response(status, "x"))
    r = ht.solver_result(ht.triage(p.bytes(), SPOOKY))
    assert r.status == "unsure" and "POST /login" in r.notes and "-> 200" in r.notes


def _cli(path: Path, *args):
    env = {k: v for k, v in os.environ.items() if k != "CTF_EVENT"}
    env["CTF_EVENT"] = "spooky"
    return subprocess.run([sys.executable, str(REPO / "solvers" / "toolkits" / "http_triage.py"), *args, str(path)],
                          capture_output=True, text=True, env=env, cwd=str(path.parent), timeout=300)


def test_cli_prints_the_triage_and_a_solver_result_last(tmp_path):
    cap = tmp_path / "Cleithro.pcap"
    cap.write_bytes(ignition_capture())
    out = _cli(cap)
    assert out.returncode == 0, out.stderr
    lines = out.stdout.strip().splitlines()
    res = json.loads(lines[-1])
    assert res["status"] == "candidate" and res["flags"] == [FLAG] and res["engine"] == "toolkits.http_triage"
    assert any(ln.startswith("odd = #") and "-> 200" in ln for ln in lines)
    assert "basic = 'captain.kirk':'Enterprise-1701-A' -> 200 (the odd response)" in lines


def test_cli_on_a_file_that_is_no_capture_is_blocked(tmp_path):
    f = tmp_path / "x.pcap"
    f.write_bytes(b"this is not a capture at all")
    out = _cli(f)
    res = json.loads(out.stdout.strip().splitlines()[-1])
    assert out.returncode == 0 and res["status"] == "blocked" and "not a pcap" in res["notes"]


def test_intake_plans_http_triage_on_a_capture_by_its_magic(tmp_path):
    (tmp_path / "traffic.bin").write_bytes(ignition_capture(decoys=False))
    (tmp_path / "readme.txt").write_text("nothing")
    m = M.load(MANIFEST)
    assert m.intake is not None and m.intake.select == "files" and m.intake.run == "per-file"
    plan = E.plan([m], "misc", "", tmp_path, guard=Guard(mode="hook", reason="test"))
    jobs = [j for j in plan.jobs if j.engine == "toolkits.http_triage"]
    assert [j.files[0].name for j in jobs] == ["traffic.bin"]
    empty = tmp_path / "none"
    empty.mkdir()
    (empty / "readme.txt").write_text("nothing")
    assert not [j for j in E.plan([m], "misc", "", empty, guard=Guard(mode="hook")).jobs if j.engine == m.id]


def _small_group(statuses) -> bytes:
    p = fx.Pcap()
    for i, st in enumerate(statuses):
        p.conversation(fx.http_request("POST", "/login", [("Authorization", fx.basic(f"u{i}", f"p{i}"))]),
                       fx.http_response(st, "OK" if st == 200 else "Unauthorized", body=b"x"))
    return p.bytes()


def test_in_a_small_group_a_status_two_requests_share_is_not_odd_but_a_lone_one_is():
    """n = 5: the rarity cut is max(1, int(5 * RARE_SHARE)) = 1 answer, so two 200s among three 401s are a
    pattern (no odd one out) while one 200 among four 401s is the odd response."""
    assert ht.triage(_small_group([401, 200, 401, 200, 401]), SPOOKY)["odd"] == []
    odd = ht.triage(_small_group([401, 401, 200, 401, 401]), SPOOKY)["odd"]
    assert [(o["status"], o["statuses"]) for o in odd] == [(200, {401: 4, 200: 1})]
