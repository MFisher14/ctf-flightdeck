"""tools/codex_handoff.sh and tools/pink_launch.sh (event opener), driven with fake codex/claude/docker.

The fakes are tiny shell scripts written into tmp_path; they record their argv so the tests check the
exact flags the real CLIs would receive. Nothing contacts a network or a real model.
"""
import os
import stat
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HANDOFF = REPO / "tools" / "codex_handoff.sh"
OPENER = REPO / "tools" / "pink_launch.sh"


def _exe(path: Path, body: str) -> Path:
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _fake_codex(tmp_path: Path, fail_msg: str = "") -> Path:
    # Records each argv (one arg per line, calls separated by @@END@@) and writes PREFLIGHT_OK to -o FILE.
    body = f'''
log="{tmp_path}/codex_calls.txt"
{{ printf '%s\\n' "$@"; echo @@END@@; }} >> "$log"
if [ -n "{fail_msg}" ]; then echo "{fail_msg}" >&2; exit 1; fi
while [ $# -gt 0 ]; do
  if [ "$1" = -o ]; then echo "PREFLIGHT_OK done" > "$2"; shift 2; else shift; fi
done
'''
    return _exe(tmp_path / "codex", body)


def _calls(tmp_path: Path):
    p = tmp_path / "codex_calls.txt"
    if not p.exists():
        return []
    chunks = p.read_text().split("@@END@@\n")
    return [c.splitlines() for c in chunks if c.strip()]


def _env(tmp_path: Path, **extra):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("CODEX_", "CTF_EVENT", "CTF_FLAG_HINT", "CTF_OPENER"))}
    env.update(CODEX_BIN=str(tmp_path / "codex"), CODEX_PREFLIGHT_DIR=str(tmp_path / "pf"),
               TMPDIR=str(tmp_path), CTF_OPENER_NOTIFY="0",
               CTF_OPENER_START_DOCKER="0")
    env.update(extra)
    return env


def _handoff(tmp_path, args, stdin="try xor with key 0x41", **extra):
    return subprocess.run(["bash", str(HANDOFF), *args], input=stdin, text=True,
                          capture_output=True, env=_env(tmp_path, **extra), timeout=60)


def _ws(tmp_path) -> Path:
    ws = tmp_path / "ws" / "42-babyrev"
    ws.mkdir(parents=True)
    return ws


# ---------------------------------------------------------------------------------- codex_handoff.sh

def test_handoff_requires_event_name(tmp_path):
    _fake_codex(tmp_path)
    r = _handoff(tmp_path, ["--challenge", str(_ws(tmp_path)), "--brief"])
    assert r.returncode != 0
    assert "no event name" in r.stderr


def test_brief_names_the_event_not_csctf(tmp_path):
    _fake_codex(tmp_path)
    ws = _ws(tmp_path)
    r = _handoff(tmp_path, ["--event", "PINK+ CTF", "--flag-hint", "PINK{...}", "--challenge", str(ws),
                            "--brief", "--label", "a"])
    assert r.returncode == 0, r.stderr
    brief = (ws / "codex_brief-a.md").read_text()
    assert "You are a PINK+ CTF solver agent" in brief
    assert "CSCTF" not in brief
    assert "PINK{...}" in brief
    assert "try xor with key 0x41" in brief
    assert str(ws / "codex_result-a.md") in brief


def test_cyber_brief_drops_ultrafast_and_keeps_daybreak(tmp_path):
    _fake_codex(tmp_path)
    ws = _ws(tmp_path)
    r = _handoff(tmp_path, ["--event", "X", "--challenge", str(ws), "--mode", "cyber"])
    assert r.returncode == 0, r.stderr
    brief = (ws / "codex_brief.md").read_text()
    assert "service_tier" not in brief and "ultrafast" not in brief
    assert "--cyber-access-program daybreak_blue" in brief
    assert "daybreak=false" not in brief


def test_cyber_with_ultrafast_is_refused(tmp_path):
    _fake_codex(tmp_path)
    r = _handoff(tmp_path, ["--event", "X", "--challenge", str(_ws(tmp_path)), "--mode", "cyber"],
                 CODEX_SERVICE_TIER="ultrafast")
    assert r.returncode != 0
    assert "unsupported on the daybreak" in r.stderr


def _wait_for_calls(tmp_path, n, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        calls = _calls(tmp_path)
        if len(calls) >= n:
            return calls
        time.sleep(0.05)
    return _calls(tmp_path)


def test_launch_runs_preflight_then_codex_with_model_override_and_daybreak_off(tmp_path):
    _fake_codex(tmp_path)
    ws = _ws(tmp_path)
    r = _handoff(tmp_path, ["--event", "X", "--challenge", str(ws), "--mode", "deep"],
                 CODEX_MODEL="gpt-other")
    assert r.returncode == 0, r.stderr
    calls = _wait_for_calls(tmp_path, 2)
    assert len(calls) == 2, calls
    pre, launch = calls
    for argv in (pre, launch):
        assert argv[0] == "exec"
        assert argv[argv.index("-m") + 1] == "gpt-other"
        assert "daybreak=false" in argv
        assert "service_tier=ultrafast" in argv
        assert "model_reasoning_effort=high" in argv
    assert "PREFLIGHT_OK" in pre[-1]
    assert "--json" in launch and str(ws / "codex_result.md") in launch


def test_preflight_is_cached_between_launches(tmp_path):
    _fake_codex(tmp_path)
    ws = _ws(tmp_path)
    for label in ("a", "b"):
        r = _handoff(tmp_path, ["--event", "X", "--challenge", str(ws), "--label", label])
        assert r.returncode == 0, r.stderr
    calls = _wait_for_calls(tmp_path, 3)
    time.sleep(0.3)
    calls = _calls(tmp_path)
    preflights = [c for c in calls if any("PREFLIGHT_OK" in a for a in c)]
    assert len(preflights) == 1 and len(calls) == 3, calls


def test_failed_preflight_blocks_launch_with_daybreak_hint(tmp_path):
    _fake_codex(tmp_path, fail_msg="Daybreak is unavailable for model gpt-6-astra")
    ws = _ws(tmp_path)
    r = _handoff(tmp_path, ["--event", "X", "--challenge", str(ws)])
    assert r.returncode != 0
    assert "PREFLIGHT FAILED" in r.stderr and "daybreak" in r.stderr.lower()
    assert "not launching" in r.stderr
    assert len(_calls(tmp_path)) == 1          # only the preflight ran
    assert not (ws / "codex_result.md").exists()


def test_missing_codex_fails_loudly(tmp_path):
    r = _handoff(tmp_path, ["--preflight"], CODEX_BIN=str(tmp_path / "nope"))
    assert r.returncode != 0
    assert "codex CLI not found" in r.stderr


# ------------------------------------------------------------------------------- pink_launch.sh opener

def _fake_claude(tmp_path, ok=True):
    out = "session backgrounded: id abc" if ok else "error: not logged in"
    return _exe(tmp_path / "claude", f'printf "%s\\n" "$@" > "{tmp_path}/claude_args.txt"\n'
                                     f'echo "{out}"\n')


def _fake_docker(tmp_path, up=True):
    return _exe(tmp_path / "docker", "exit 0\n" if up else "exit 1\n")


def _conf(tmp_path, **kv):
    prompt = tmp_path / "prompt.md"
    prompt.write_text("open the board and run the wave")
    base = dict(EVENT_NAME="Test Event", WINDOW_START="20261106", WINDOW_END="20261109",
                PROMPT_FILE=str(prompt), REPO=str(tmp_path), LOG_DIR=str(tmp_path / "logs"),
                DOCKER_WAIT="0")
    base.update(kv)
    conf = tmp_path / "opener.conf"
    conf.write_text("# opener\n" + "".join(f"{k}={v}\n" for k, v in base.items() if v is not None))
    return conf


def _open(tmp_path, conf, today="20261107", **extra):
    env = _env(tmp_path, CLAUDE_BIN=str(tmp_path / "claude"), DOCKER_BIN=str(tmp_path / "docker"),
               CTF_OPENER_TODAY=today, **extra)
    return subprocess.run(["bash", str(OPENER), str(conf)], capture_output=True, text=True, env=env,
                          timeout=60)


def test_opener_launches_once_inside_window(tmp_path):
    _fake_claude(tmp_path); _fake_docker(tmp_path)
    conf = _conf(tmp_path)
    r = _open(tmp_path, conf)
    assert r.returncode == 0, (tmp_path / "logs" / "opener.log").read_text()
    args = (tmp_path / "claude_args.txt").read_text().splitlines()
    assert args[:2] == ["--bg", "--remote-control"]
    assert args[2] == "Test Event wave"
    assert args[args.index("-n") + 1] == "test-event-wave"
    assert args[-1] == "open the board and run the wave"
    assert (tmp_path / "logs" / "opener.done").exists()
    (tmp_path / "claude_args.txt").unlink()
    r2 = _open(tmp_path, conf)
    assert r2.returncode == 0
    assert not (tmp_path / "claude_args.txt").exists()          # lock held: no second session
    assert "already launched" in (tmp_path / "logs" / "opener.log").read_text()


def test_opener_does_nothing_outside_window(tmp_path):
    _fake_claude(tmp_path); _fake_docker(tmp_path)
    r = _open(tmp_path, _conf(tmp_path), today="20261110")
    assert r.returncode == 0
    assert not (tmp_path / "claude_args.txt").exists()
    assert "outside Test Event window" in (tmp_path / "logs" / "opener.log").read_text()


def test_opener_tells_session_when_docker_is_down(tmp_path):
    _fake_claude(tmp_path); _fake_docker(tmp_path, up=False)
    r = _open(tmp_path, _conf(tmp_path))
    assert r.returncode == 0
    prompt_arg = (tmp_path / "claude_args.txt").read_text()
    assert "Docker (the detonation sandbox) was NOT running" in prompt_arg


def test_opener_failed_launch_exits_nonzero_without_lock(tmp_path):
    _fake_claude(tmp_path, ok=False); _fake_docker(tmp_path)
    r = _open(tmp_path, _conf(tmp_path))
    assert r.returncode != 0
    assert not (tmp_path / "logs" / "opener.done").exists()
    assert "did not background a session" in (tmp_path / "logs" / "opener.log").read_text()


def test_opener_rejects_bad_or_missing_config(tmp_path):
    _fake_claude(tmp_path); _fake_docker(tmp_path)
    r = _open(tmp_path, _conf(tmp_path, WINDOW_END="2026-11-09"))
    assert r.returncode != 0 and "WINDOW_END must be YYYYMMDD" in r.stderr
    r = _open(tmp_path, _conf(tmp_path, EVENT_NAME=None))
    assert r.returncode != 0 and "EVENT_NAME missing" in r.stderr
    r = _open(tmp_path, _conf(tmp_path, BOGUS="1"))
    assert r.returncode != 0 and "unknown config key 'BOGUS'" in r.stderr
    assert not (tmp_path / "claude_args.txt").exists()


def test_opener_config_is_parsed_not_sourced(tmp_path):
    _fake_claude(tmp_path); _fake_docker(tmp_path)
    marker = tmp_path / "pwned"
    r = _open(tmp_path, _conf(tmp_path, RC_NAME=f"$(touch {marker})"))
    assert r.returncode == 0
    assert not marker.exists()
    args = (tmp_path / "claude_args.txt").read_text().splitlines()
    assert args[2] == f"$(touch {marker})"
