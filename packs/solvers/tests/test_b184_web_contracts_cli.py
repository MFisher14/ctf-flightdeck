"""B-184: the `ctf web-contracts` CLI, driven offline through ctf.cli.main.

Exercises the sub-commands' exit codes and the replay error paths on temp JSON
files -- the surface that let the earlier replay defects (silent capture padding,
a hardcoded proof regex that ignored the event flag format) through.  Nothing
opens a socket; replay runs against a recorded capture file.
"""
from __future__ import annotations

import json

from ctf import flagfmt
from ctf.cli import main


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def _run(argv, capsys):
    rc = main(argv)
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_matrix_command_lists_classes(capsys):
    rc, out, _ = _run(["web-contracts", "matrix"], capsys)
    assert rc == 0
    data = json.loads(out)
    assert data["post_event_forge"]["disposition"] == "cold"
    assert data["novel_web"]["disposition"] == "agent"


def test_route_trust_exit_codes(capsys):
    # trusted -> 0
    rc, out, _ = _run(["web-contracts", "route-trust", "/admin/reset-token",
                       "--base", "http://t.local/", "--advertised", "/admin/reset-token"], capsys)
    assert rc == 0 and json.loads(out)["trusted"] is True
    # off-origin advertised -> untrusted -> exit 1
    rc, out, _ = _run(["web-contracts", "route-trust", "http://evil.example/admin/reset-token",
                       "--base", "http://t.local/", "--advertised", "http://evil.example/admin/reset-token"],
                      capsys)
    assert rc == 1 and json.loads(out)["trusted"] is False


def test_forge_grid_command(capsys):
    rc, out, _ = _run(["web-contracts", "forge-grid", "--fields", '{"Event":"","Owner":"admin"}',
                       "--max", "8"], capsys)
    assert rc == 0
    grid = json.loads(out)
    assert any(c["transport"] == "json" and c["shape"] == "flat"
               and set(c["fields"]) == {"event", "owner"} for c in grid)


def test_forge_grid_rejects_bad_json(capsys):
    rc, _, err = _run(["web-contracts", "forge-grid", "--fields", "not json"], capsys)
    assert rc == 2 and "not valid JSON" in err


def test_route_command_on_evidence_file(tmp_path, capsys):
    ev = {"category": "web", "clue": "POST an Event; the form shows Event and Owner.",
          "method": "POST", "advertised_routes": ["/api/events"],
          "responses": [{"route": "/api/events", "status": 400, "body": "{\"error\":\"missing field\"}"}]}
    path = _write(tmp_path, "ev.json", ev)
    rc, out, _ = _run(["web-contracts", "route", path], capsys)
    assert rc == 0
    assert json.loads(out)["chosen"]["id"] == "post_event_forge"


def test_minimize_command(tmp_path, capsys):
    req = {"fields": {"event": "x", "owner": "a", "signature": "d"}, "transport": "json"}
    path = _write(tmp_path, "req.json", req)
    rc, out, _ = _run(["web-contracts", "minimize", path], capsys)
    assert rc == 0
    first = json.loads(out)["candidates"][0]
    assert set(first["fields"]) == {"event", "owner"}


def test_replay_shorter_capture_fails_loudly(tmp_path, capsys):
    # no silent padding: a capture shorter than the plan must exit 2, not report
    # the padded requests as sent.
    plan = _write(tmp_path, "plan.json", [{"fields": {"n": 0}}, {"fields": {"n": 1}}])
    cap = _write(tmp_path, "cap.json", [{"status": 400, "body": "no"}])
    rc, _, err = _run(["web-contracts", "replay", plan, "--capture", cap], capsys)
    assert rc == 2 and "plan has 2" in err


def test_replay_finds_proof_under_event_flag_format(tmp_path, capsys, monkeypatch):
    # the CLI replay reads the active event flag format (CTF_EVENT), not a
    # hardcoded pattern: under huntress a proof_<32 hex> body is a proof.
    monkeypatch.setenv("CTF_EVENT", "huntress")
    flagfmt.clear_current_cache()
    plan = _write(tmp_path, "plan.json", [{"fields": {"event": "x"}}])
    cap = _write(tmp_path, "cap.json", [{"status": 200, "body": "proof_" + "a" * 32}])
    rc, out, _ = _run(["web-contracts", "replay", plan, "--capture", cap], capsys)
    flagfmt.clear_current_cache()
    assert rc == 0
    assert json.loads(out)["proof"] == "proof_" + "a" * 32


def test_replay_no_proof_exits_one(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "huntress")
    flagfmt.clear_current_cache()
    plan = _write(tmp_path, "plan.json", [{"fields": {"event": "x"}}])
    cap = _write(tmp_path, "cap.json", [{"status": 400, "body": "nope"}])
    rc, out, _ = _run(["web-contracts", "replay", plan, "--capture", cap], capsys)
    flagfmt.clear_current_cache()
    assert rc == 1
    assert json.loads(out)["proof"] is None


def test_fingerprint_command(tmp_path, capsys):
    ev = {"category": "web", "clue": "forge an event", "method": "POST", "responses": [],
          "advertised_routes": []}
    path = _write(tmp_path, "ev.json", ev)
    rc, out, _ = _run(["web-contracts", "fingerprint", path], capsys)
    assert rc == 0
    ranked = json.loads(out)
    assert ranked[0]["id"] == "post_event_forge"
