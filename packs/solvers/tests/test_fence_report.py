"""B-219: the denied-access report (ctf.fence_report) over synthetic agent logs only."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ctf import fence, fence_report, paths

PY = sys.executable


@pytest.fixture
def env3(tmp_path):
    home = (tmp_path / "home" / "player")
    ws = (tmp_path / "work" / "ev")
    repo = (tmp_path / "src" / "ctf-tools")
    for d in (home, ws, repo):
        d.mkdir(parents=True)
    home, ws, repo = home.resolve(), ws.resolve(), repo.resolve()
    f = fence.build(home=home, workspace=ws, repo=repo, user_dir=None,
                    drop=home / "Downloads" / "ev")
    return f, home, ws, tmp_path


def _jsonl(path: Path, rows) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


def claude_transcript(tmp, home, ws):
    def use(i, name, inp):
        return {"type": "assistant", "cwd": str(ws),
                "message": {"role": "assistant", "content": [
                    {"type": "text", "text": "thinking about it"},
                    {"type": "tool_use", "id": f"t{i}", "name": name, "input": inp}]}}

    def res(i, text, err=False):
        return {"type": "user", "cwd": str(ws), "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"t{i}", "is_error": err,
             "content": [{"type": "text", "text": text}]}]}}
    rows = [
        {"type": "summary", "summary": "x"},
        use(1, "Bash", {"command": "cat ~/.codex/history.jsonl | tail -5"}),
        res(1, f"cat: {home}/.codex/history.jsonl: Operation not permitted", err=True),
        use(2, "Read", {"file_path": f"{home}/Library/Messages/chat.db"}),
        res(2, "File content (1 KB)"),
        use(3, "Bash", {"command": "python3 solve.py files/chal.bin && ls ../ev"}),
        res(3, "ok"),
        use(4, "Grep", {"path": "/usr/share/dict", "pattern": "x"}),
        res(4, "no matches"),
        use(5, "Bash", {"command": "curl -s -H 'Authorization: Bearer SECRETTOKEN123' "
                                   "https://chal.example/a/b -o ~/Downloads/ev/out.bin"}),
        res(5, ""),
        use(6, "Glob", {"path": "~/Downloads", "pattern": "*.zip"}),
        res(6, "x.zip"),
    ]
    return _jsonl(tmp / "claude.jsonl", rows)


def codex_rollout(tmp, home, ws):
    def call(i, cmd, workdir=None):
        args = {"cmd": cmd}
        if workdir:
            args["workdir"] = workdir
        return {"type": "response_item", "payload": {"type": "function_call", "name": "exec_command",
                                                     "call_id": f"c{i}", "arguments": json.dumps(args)}}

    def out(i, text):
        return {"type": "response_item", "payload": {"type": "function_call_output", "call_id": f"c{i}",
                                                     "output": text}}
    rows = [
        {"type": "session_meta", "payload": {"id": "abc"}},
        call(1, "sqlite3 ~/.codex/state_5.sqlite 'select * from threads'", str(ws)),
        out(1, "Error: unable to open database: Operation not permitted"),
        call(2, f"ls -la '{home}/Library/Application Support/discord/Cache'"),
        out(2, "total 0"),
        call(3, "log show --last 2h --predicate 'process == \"x\"'"),
        out(3, ""),
        call(4, "strings files/a.bin | grep -i flag", str(ws)),
        out(4, "nothing"),
        # The same command recorded again as a completed item: must not be double counted.
        {"type": "event_msg", "payload": {"type": "item_completed", "item": {
            "type": "CommandExecution", "command": ["/bin/zsh", "-lc", "cat ~/.claude/history.jsonl"],
            "exit_code": 1, "aggregated_output": ""}}},
    ]
    return _jsonl(tmp / "rollout.jsonl", rows)


def test_claude_transcript(env3):
    f, home, ws, tmp = env3
    rep = fence_report.scan_files([claude_transcript(tmp, home, ws)], f)
    assert rep.commands == 6
    cats = {(a.tool, a.category, a.outcome) for a in rep.accesses}
    assert ("Bash", "agent-state", "blocked") in cats
    assert ("Read", "messaging", "ran") in cats
    assert ("Glob", "downloads", "ran") in cats
    assert len(rep.accesses) == 3                       # workspace, /usr, drop folder and URL: none
    assert not any("chal.example" in (a.path or "") for a in rep.accesses)
    text = fence_report.render_text(rep)
    assert "SECRETTOKEN123" not in text and "Bearer" not in text
    assert "SECRETTOKEN123" not in json.dumps(rep.to_dict())


def test_codex_rollout_prefers_function_calls(env3):
    f, home, ws, tmp = env3
    rep = fence_report.scan_files([codex_rollout(tmp, home, ws)], f)
    assert rep.commands == 4                            # the CommandExecution duplicate is ignored
    by = rep.by_category()
    assert by == {"agent-state": 1, "messaging": 1, "unified-log": 1}
    blocked = [a for a in rep.accesses if a.outcome == "blocked"]
    assert [(a.program, a.path) for a in blocked] == [("sqlite3", str(home / ".codex/state_5.sqlite"))]
    log = [a for a in rep.accesses if a.category == "unified-log"][0]
    assert log.path is None and log.program == "log"


def test_codex_items_used_when_no_function_calls(env3):
    f, home, ws, tmp = env3
    p = _jsonl(tmp / "items.jsonl", [
        {"type": "event_msg", "payload": {"type": "item_completed", "item": {
            "type": "CommandExecution", "command": ["/bin/zsh", "-lc", "tmutil listlocalsnapshots /"],
            "exit_code": 0, "aggregated_output": "com.apple.TimeMachine.2026-11-07"}}}])
    rep = fence_report.scan_files([p], f)
    assert rep.commands == 1
    assert {(a.category, a.outcome) for a in rep.accesses} == {("snapshots", "ran"), ("other", "ran")}


def test_codex_exec_json_stream_and_plain_text(env3):
    f, home, ws, tmp = env3
    stream = _jsonl(tmp / "exec.jsonl", [
        {"type": "thread.started", "thread_id": "x"},
        {"type": "item.completed", "item": {"type": "command_execution",
                                            "command": "/bin/zsh -lc 'mdfind flag.txt'",
                                            "aggregated_output": "", "exit_code": 0}},
        {"type": "item.completed", "item": {"type": "agent_message", "text": "done"}},
    ])
    plain = tmp / "cmds.log"
    plain.write_text("# commands\n\nfile files/a.bin\nfind / -name '*.sqlite' 2>/dev/null\n"
                     "cp $HOME/.ssh/id_ed25519 /tmp/k\nsed -e 's/a/b/' notes.md\n"
                     "PATH=/usr/bin:/opt/x/bin env\n")
    rep = fence_report.scan_files([stream, plain], f)
    cats = sorted(a.category for a in rep.accesses)
    assert cats == ["credentials", "other", "spotlight"]
    root = [a for a in rep.accesses if a.category == "other"][0]
    assert root.path == "/" and root.program == "find"


def test_clean_log_and_missing_file(env3):
    f, home, ws, tmp = env3
    p = tmp / "clean.log"
    p.write_text(f"cd {ws}\npython3 -c 'print(1)'\n")
    rep = fence_report.scan_files([p], f)
    assert rep.clean and "no reads outside" in fence_report.render_text(rep)
    with pytest.raises(FileNotFoundError, match="log not found"):
        fence_report.scan_files([tmp / "nope.jsonl"], f)


@pytest.mark.parametrize("cmd,expected", [
    ("cat ~/.codex/a", ["~/.codex/a"]),
    ('python3 -c "open(\'/home/p/.claude/x\').read()"', ["/home/p/.claude/x"]),
    ("dd if=/dev/zero of=$HOME/x bs=1", ["/dev/zero", "$HOME/x"]),
    ("curl https://host.example/a/b", []),
    ("sed -i 's/x/y/g' f", []),
    ("tar -C/opt/out -xf a.tar", ["/opt/out"]),
    ("ls ../../x", ["../../x"]),
])
def test_extract_paths(cmd, expected):
    assert fence_report.extract_paths(cmd) == expected


def test_cli_report_exit_codes(env3, tmp_path):
    f, home, ws, tmp = env3
    bad = tmp / "bad.log"
    bad.write_text("cat ~/pentest-tools/notes.txt\n")
    good = tmp / "good.log"
    good.write_text("ls\n")
    e = dict(os.environ, HOME=str(home), CTF_WORKDIR=str(ws))
    e.pop("CTF_EVENT", None)

    def run(*a):
        return subprocess.run([PY, "-m", "ctf", "fence", *a], cwd=paths.repo_root(), env=e,
                              capture_output=True, text=True, timeout=60)
    r = run("report", str(bad), "--json")
    assert r.returncode == 1, r.stderr
    d = json.loads(r.stdout)
    assert d["by_category"] == {"customer-work": 1} and d["outside_reads"] == 1
    r = run("report", str(good))
    assert r.returncode == 0 and "no reads outside" in r.stdout
    r = run("report", str(tmp / "missing.log"))
    assert r.returncode == 2 and "log not found" in r.stderr
    r = run("check", str(ws / "x"), "~/.codex/y")
    assert r.returncode == 1 and "denied:agent-state" in r.stdout
    r = run("check", str(ws / "x"))
    assert r.returncode == 0 and r.stdout.startswith("allowed")
