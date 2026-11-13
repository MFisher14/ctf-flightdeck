"""B-039: the preflight doctor checks (ctf/doctor.py), `ctf preflight`, and the B-039 section of
`ctf doctor`. Everything offline: synthetic manifests, registries and Codex configs under tmp_path, a
stub Codex binary, and the fake CTFd on 127.0.0.1 for the instance probe."""
from __future__ import annotations

import datetime as dt
import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from ctf import doctor, event, flagfmt, paths

UTC = dt.timezone.utc


def profile(categories=("Web",), slug="demo", kind="ctfd", submit_mode="auto", prefixes=("DEMO",),
            body=None, ai="allowed"):
    flag = {"prefixes": list(prefixes)}
    if body:
        flag["body"] = body
    plat = {"kind": kind}
    if kind != "manual":
        plat["base_url"] = "https://demo.example/"
    return event.parse({
        "slug": slug, "name": "Demo CTF", "categories": list(categories),
        "dates": {"start": dt.datetime(2030, 3, 1, tzinfo=UTC), "end": dt.datetime(2030, 3, 3, tzinfo=UTC)},
        "platform": plat, "flag": flag,
        "rules": {"submit_mode": submit_mode, "flag_sharing": "allowed", "ai_on_platform": ai},
    })


# ------------------------------------------------------------------------------- synthetic tree

def write_engine(root: Path, name: str, categories, status="active", with_module=True):
    d = root / "solvers" / "lane"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.manifest.toml").write_text(textwrap.dedent(f"""\
        id = "lane.{name}"
        lane = "lane"
        entry = "solvers.lane.{name}:solve"
        status = "{status}"

        [[routes]]
        category = {json.dumps(list(categories))}
        priority = 50
        """))
    if with_module:
        (d / f"{name}.py").write_text("def solve(d, p):\n    return None\n")


def write_tree(root: Path, *, registry=True, triage=True, registry_body=None):
    write_engine(root, "webby", ["web"])
    write_engine(root, "revy", ["reverse"])
    if registry:
        tk = root / "solvers" / "toolkits"
        tk.mkdir(parents=True, exist_ok=True)
        (tk / "registry.py").write_text(registry_body or "def entries():\n    return [{'key': 'a'}, {'key': 'b'}]\n")
    if triage:
        cm = root / "solvers" / "common"
        cm.mkdir(parents=True, exist_ok=True)
        (cm / "triage.py").write_text("def identify(data):\n    return 'data'\n")
    return root


def manifests(root):
    from ctf.engines import manifest
    return manifest.discover(root)


# ------------------------------------------------------------------------------- categories

def test_routed_categories_counts_active_engines_only(tmp_path):
    write_tree(tmp_path)
    write_engine(tmp_path, "oldie", ["minecraft"], status="retired")
    r = doctor.routed_categories(manifests(tmp_path))
    assert r == {"reverse": ("lane.revy",), "web": ("lane.webby",)}


def test_unrouted_announced_categories_are_reported_with_an_alias_hint(tmp_path):
    write_tree(tmp_path)
    c = doctor.check_categories(profile(("Web", "Reverse engineering", "Minecraft")), manifests(tmp_path))
    assert c.status == "warn"
    assert c.detail.startswith("1/3 announced categories have an engine route")
    assert "'Reverse engineering' (the router reads it as 'reverse engineering'" in c.detail
    assert "reverse, which is routed" in c.detail and "ALIASES in ctf/triage.py" in c.detail
    assert "'Minecraft'" in c.detail and "'Web'" not in c.detail


def test_all_announced_categories_routed_is_ok(tmp_path):
    write_tree(tmp_path)
    c = doctor.check_categories(profile(("Web", "Reversing", "rev")), manifests(tmp_path))
    assert c.status == "ok", c.detail
    assert "Reversing->reverse (1)" in c.detail


def test_retired_engine_does_not_route_its_category(tmp_path):
    write_tree(tmp_path)
    write_engine(tmp_path, "oldie", ["minecraft"], status="retired")
    c = doctor.check_categories(profile(("Minecraft",)), manifests(tmp_path))
    assert c.status == "warn" and "'Minecraft'" in c.detail


def test_no_announced_categories_is_a_warning_naming_the_profile(tmp_path):
    write_tree(tmp_path)
    c = doctor.check_categories(profile(()), manifests(tmp_path))
    assert c.status == "warn" and "no categories announced in the demo profile" in c.detail
    assert "events/demo/event.toml" in c.fix


def test_shipped_csctf_profile_against_the_real_router():
    """Phase 0 verification of B-189: the csctf profile's announced categories against this tree's
    routes. 'Welcome' has no engine (nothing to route); 'Web' always does."""
    c = doctor.check_categories(event.load("csctf"))
    assert c.status == "warn"
    assert "'Welcome'" in c.detail and "'Web'" not in c.detail


# ------------------------------------------------------------------------------- router

def test_router_check_passes_on_a_complete_tree(tmp_path):
    c = doctor.check_router(write_tree(tmp_path))
    assert c.status == "ok", c.detail
    assert "2 manifests, 2 routed engines" in c.detail and "2 registered toolkits" in c.detail


def test_router_check_passes_on_this_checkout():
    c = doctor.check_router()
    assert c.status == "ok", c.detail


def test_router_check_fails_on_a_routed_engine_whose_module_is_gone(tmp_path):
    write_tree(tmp_path)
    write_engine(tmp_path, "ghost", ["crypto"], with_module=False)
    c = doctor.check_router(tmp_path)
    assert c.status == "fail" and "lane.ghost -> solvers/lane/ghost.py" in c.detail


def test_router_check_fails_on_a_bad_manifest(tmp_path):
    write_tree(tmp_path)
    (tmp_path / "solvers" / "lane" / "bad.manifest.toml").write_text('id = "lane.bad"\nbogus = 1\n')
    c = doctor.check_router(tmp_path)
    assert c.status == "fail" and "engine manifests do not load" in c.detail


def test_router_check_fails_without_the_toolkit_registry(tmp_path):
    c = doctor.check_router(write_tree(tmp_path, registry=False))
    assert c.status == "fail" and "toolkit registry" in c.detail


def test_router_check_fails_when_a_registered_toolkit_is_missing(tmp_path):
    body = ("from ctf.packs import PackMissing\n"
            "def entries():\n    raise PackMissing('toolkit:gone', 'gone.py', 'file not there')\n")
    c = doctor.check_router(write_tree(tmp_path, registry_body=body))
    assert c.status == "fail" and "toolkit:gone" in c.detail


def test_router_check_fails_without_the_triage_pack(tmp_path):
    c = doctor.check_router(write_tree(tmp_path, triage=False))
    assert c.status == "fail" and "triage identify pack" in c.detail


# ------------------------------------------------------------------------------- codex model

def codex_root(tmp_path, default="m-default"):
    root = tmp_path / "repo"
    (root / "tools").mkdir(parents=True)
    (root / "tools" / "codex_handoff.sh").write_text(f'#!/bin/bash\ndefault_model="{default}"\n')
    return root


def codex_home(tmp_path, body):
    home = tmp_path / "codexhome"
    home.mkdir(exist_ok=True)
    if body is not None:
        (home / "config.toml").write_text(body)
    return home


def test_handoff_default_model_is_read_from_the_shipped_script():
    m = doctor.handoff_default_model()
    script = (paths.repo_root() / "tools" / "codex_handoff.sh").read_text()
    assert m and f'default_model="{m}"' in script


def test_handoff_that_overrides_the_configured_model_fails(tmp_path):
    root = codex_root(tmp_path)
    env = {"CODEX_HOME": str(codex_home(tmp_path, 'model = "m-config"\n'))}
    c = doctor.check_codex_model(env, root=root)
    assert c.status == "fail"
    assert "'m-default'" in c.detail and "'m-config'" in c.detail
    assert c.fix.startswith("export CODEX_MODEL=m-config")


def test_codex_model_env_matching_the_config_is_ok(tmp_path):
    root = codex_root(tmp_path)
    env = {"CODEX_HOME": str(codex_home(tmp_path, 'model = "m-config"\n')), "CODEX_MODEL": "m-config"}
    c = doctor.check_codex_model(env, root=root)
    assert c.status == "ok" and "run 'm-config' (CODEX_MODEL)" in c.detail


def test_codex_model_env_differing_from_the_config_warns(tmp_path):
    root = codex_root(tmp_path)
    env = {"CODEX_HOME": str(codex_home(tmp_path, 'model = "m-config"\n')), "CODEX_MODEL": "m-other"}
    assert doctor.check_codex_model(env, root=root).status == "warn"


def test_codex_model_default_equal_to_config_or_no_config_is_ok(tmp_path):
    root = codex_root(tmp_path, default="m-same")
    env = {"CODEX_HOME": str(codex_home(tmp_path, 'model = "m-same"\n'))}
    assert doctor.check_codex_model(env, root=root).status == "ok"
    env = {"CODEX_HOME": str(tmp_path / "nowhere")}
    c = doctor.check_codex_model(env, root=root)
    assert c.status == "ok" and "names no model" in c.detail


def test_cyber_mode_reads_codex_cyber_model(tmp_path):
    root = codex_root(tmp_path)
    env = {"CODEX_HOME": str(codex_home(tmp_path, 'model = "m-config"\n')), "CODEX_MODEL": "m-config",
           "CODEX_CYBER_MODEL": "m-cyber"}
    c = doctor.check_codex_model(env, root=root, mode="cyber")
    assert c.status == "warn" and "'m-cyber' (CODEX_CYBER_MODEL)" in c.detail


def test_unreadable_codex_config_fails_without_echoing_it(tmp_path):
    root = codex_root(tmp_path)
    env = {"CODEX_HOME": str(codex_home(tmp_path, 'model = "x\nsecretish = 1\n'))}
    c = doctor.check_codex_model(env, root=root)
    assert c.status == "fail" and "not readable TOML" in c.detail and "secretish" not in c.detail


def test_codex_home_is_codex_home_else_dot_codex_under_home(tmp_path, monkeypatch):
    assert paths.codex_home({"CODEX_HOME": str(tmp_path / "ch")}) == tmp_path / "ch"
    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    assert paths.codex_home({}) == tmp_path / "h" / ".codex"
    (tmp_path / "h" / ".codex").mkdir(parents=True)
    (tmp_path / "h" / ".codex" / "config.toml").write_text('model = "m-home"\n')
    assert doctor.codex_config_model({}) == ("m-home", tmp_path / "h" / ".codex" / "config.toml")


def test_script_without_a_default_model_fails(tmp_path):
    root = tmp_path / "r"
    (root / "tools").mkdir(parents=True)
    (root / "tools" / "codex_handoff.sh").write_text("#!/bin/bash\n")
    c = doctor.check_codex_model({"CODEX_HOME": str(tmp_path)}, root=root)
    assert c.status == "fail" and "default_model" in c.detail


# ------------------------------------------------------------------------------- codex smoke

STUB_OK = """#!/bin/bash
# ctf-codex-stub: logs its argv, writes PREFLIGHT_OK to the -o file
printf '%s\\n' "$@" > "$STUB_ARGV"
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift; fi
  shift
done
echo PREFLIGHT_OK > "$out"
"""

STUB_FAIL = """#!/bin/bash
# ctf-codex-stub
echo "error: Daybreak is unavailable for model m-bad" >&2
exit 1
"""


def stub(tmp_path, body, name="codex"):
    p = tmp_path / name
    p.write_text(body)
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def smoke_env(tmp_path, bin_path, **extra):
    e = {k: v for k, v in os.environ.items() if not k.startswith("CODEX_")}
    e.update(CODEX_BIN=str(bin_path), CODEX_PREFLIGHT_DIR=str(tmp_path / "pf"),
             STUB_ARGV=str(tmp_path / "argv.txt"), **extra)
    return e


@pytest.mark.needs_tool("bash", "perl", "shasum")
def test_codex_smoke_runs_one_call_with_the_handoff_flags(tmp_path):
    env = smoke_env(tmp_path, stub(tmp_path, STUB_OK), CODEX_MODEL="m-picked")
    c = doctor.check_codex_smoke(env)
    assert c.status == "ok", c.detail
    argv = (tmp_path / "argv.txt").read_text().splitlines()
    assert argv[0] == "exec" and argv[argv.index("-m") + 1] == "m-picked"
    assert "Reply with exactly: PREFLIGHT_OK" in argv[-1]


@pytest.mark.needs_tool("bash", "perl", "shasum")
def test_codex_smoke_failure_is_reported_with_the_hint(tmp_path):
    c = doctor.check_codex_smoke(smoke_env(tmp_path, stub(tmp_path, STUB_FAIL)))
    assert c.status == "fail"
    assert "Daybreak is unavailable" in c.detail or "daybreak" in c.detail.lower()


@pytest.mark.needs_tool("bash")
def test_codex_smoke_with_no_codex_binary_fails_naming_it(tmp_path):
    c = doctor.check_codex_smoke(smoke_env(tmp_path, tmp_path / "no-such-codex"))
    assert c.status == "fail" and "codex CLI not found" in c.detail
    assert "CODEX_BIN" in c.fix


def test_codex_smoke_refuses_a_real_call_under_ctf_testing():
    def never(*a, **k):
        raise AssertionError("no subprocess may start")
    e = {k: v for k, v in os.environ.items() if k != "CODEX_BIN"}
    e["CTF_TESTING"] = "1"
    c = doctor.check_codex_smoke(e, run=never)
    assert c.status == "fail" and "refusing a real Codex call" in c.detail


def _never(*a, **k):
    raise AssertionError("no subprocess may start")


@pytest.mark.parametrize("as_name", [False, True])
def test_codex_smoke_under_ctf_testing_refuses_the_codex_on_path(tmp_path, as_name):
    """CODEX_BIN set to the real CLI (the `codex` on PATH, by path or by bare name) is refused too, even
    when it carries the stub marker: the PATH check alone refuses it."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    real = stub(bindir, "#!/bin/bash\n# ctf-codex-stub\nexit 0\n")
    e = {"CTF_TESTING": "1", "PATH": str(bindir), "CODEX_BIN": "codex" if as_name else str(real)}
    c = doctor.check_codex_smoke(e, run=_never)
    assert c.status == "fail" and "is the codex on PATH" in c.detail and "refusing a real Codex call" in c.detail


def test_codex_smoke_under_ctf_testing_runs_a_stub_that_is_not_on_path(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub(bindir, "#!/bin/bash\nexit 0\n")                              # the "real" codex on PATH
    mine = stub(tmp_path, STUB_OK, name="codex-stub")
    calls = []

    class Done:
        returncode, stdout, stderr = 0, "PREFLIGHT_OK\n", ""

    def run(argv, **kw):
        calls.append((argv, kw["env"]["CODEX_BIN"]))
        return Done()
    e = {"CTF_TESTING": "1", "PATH": str(bindir), "CODEX_BIN": str(mine)}
    c = doctor.check_codex_smoke(e, run=run)
    assert c.status == "ok", c.detail
    assert calls and calls[0][0][-3:] == ["--preflight", "--mode", "fast"] and calls[0][1] == str(mine)


def test_codex_smoke_under_ctf_testing_refuses_a_real_cli_off_path(tmp_path):
    """The real CLI named by absolute path while PATH lacks it: no marker, so it is refused."""
    (tmp_path / "opt").mkdir()
    real = stub(tmp_path / "opt", "#!/usr/bin/env node\n// the real CLI\n", name="codex")
    e = {"CTF_TESTING": "1", "PATH": str(tmp_path / "empty"), "CODEX_BIN": str(real)}
    c = doctor.check_codex_smoke(e, run=_never)
    assert c.status == "fail" and "refusing a real Codex call" in c.detail
    assert "does not carry the stub marker 'ctf-codex-stub'" in c.detail and "ctf-codex-stub" in c.fix


def test_codex_smoke_stub_marker_is_looked_for_only_near_the_top(tmp_path):
    """A binary that merely contains the marker string deep inside (past the window) is refused."""
    far = stub(tmp_path, "#!/bin/bash\n" + "#" * (doctor.STUB_MARKER_WINDOW + 10) + "\n# ctf-codex-stub\n",
               name="codex-far")
    e = {"CTF_TESTING": "1", "PATH": str(tmp_path / "empty"), "CODEX_BIN": str(far)}
    c = doctor.check_codex_smoke(e, run=_never)
    assert c.status == "fail" and "does not carry the stub marker" in c.detail


def test_codex_smoke_resolves_a_relative_codex_bin_against_the_root(tmp_path):
    """A relative CODEX_BIN is the file the script would run (cwd = root), not one in the test's cwd."""
    root = tmp_path / "root"
    (root / "tools").mkdir(parents=True)
    (root / "tools" / "codex_handoff.sh").write_text("#!/bin/bash\nexit 0\n")
    (root / "bin").mkdir()
    stub(root / "bin", "#!/bin/bash\nexit 0\n", name="cx")            # no marker, under root
    e = {"CTF_TESTING": "1", "PATH": str(tmp_path / "empty"), "CODEX_BIN": os.path.join("bin", "cx")}
    c = doctor.check_codex_smoke(e, root=root, run=_never)
    assert c.status == "fail" and "does not carry the stub marker" in c.detail


def test_codex_smoke_under_ctf_testing_lets_a_missing_codex_bin_reach_the_script(tmp_path):
    """A CODEX_BIN that names nothing cannot start anything: the script runs and fails "not found"."""
    calls = []

    class Done:
        returncode, stdout, stderr = 1, "", "codex CLI not found ('x'); install it or set CODEX_BIN"

    def run(argv, **kw):
        calls.append(argv)
        return Done()
    e = {"CTF_TESTING": "1", "PATH": str(tmp_path / "empty"), "CODEX_BIN": str(tmp_path / "nothing")}
    c = doctor.check_codex_smoke(e, run=run)
    assert calls and c.status == "fail" and "refusing" not in c.detail and "not found" in c.detail


def test_codex_smoke_unknown_mode_fails():
    assert doctor.check_codex_smoke({}, mode="turbo").status == "fail"


# ------------------------------------------------------------------------------- submit dry run

@pytest.mark.parametrize("mode", ["auto", "confirm"])
def test_submit_dry_run_ok_for_ctfd_modes(mode):
    c = doctor.check_submit_dry_run(profile(submit_mode=mode))
    assert c.status == "ok", c.detail
    assert "nothing sent" in c.detail and "guarded_submit format guard agrees" in c.detail


def test_submit_dry_run_ok_for_a_manual_event():
    c = doctor.check_submit_dry_run(profile(kind="manual", submit_mode="manual"))
    assert c.status == "ok" and "gate refuses every send (manual)" in c.detail


def test_submit_dry_run_catches_a_gate_that_lets_a_non_flag_through(monkeypatch):
    from ctf.platform import policy
    monkeypatch.setattr(policy, "base_checks", lambda prof, req: None)
    c = doctor.check_submit_dry_run(profile())
    assert c.status == "fail" and "gate sent a non-flag value" in c.detail


def test_submit_dry_run_catches_a_gate_that_ignores_confirm_mode(monkeypatch):
    from ctf.platform import policy
    real = policy.base_checks

    def no_confirm(prof, req):
        r = real(prof, req)
        return None if r and "confirm" in r else r
    monkeypatch.setattr(policy, "base_checks", no_confirm)
    c = doctor.check_submit_dry_run(profile(submit_mode="confirm"))
    assert c.status == "fail" and "unconfirmed" in c.detail


def test_submit_dry_run_catches_a_carried_format_guard_that_accepts_anything(monkeypatch):
    from ctf import config
    monkeypatch.setattr(config.Config, "looks_like_flag", lambda self, text: True)
    c = doctor.check_submit_dry_run(profile())
    assert c.status == "fail" and "guarded_submit did not refuse" in c.detail


@pytest.mark.parametrize("mode,named", [
    ("auto", "gate refused a well-formed value"),
    ("confirm", "gate did not send the confirmed well-formed value"),
])
def test_submit_dry_run_catches_a_gate_that_refuses_every_value(monkeypatch, mode, named):
    """The dead-submit-path case: a gate that refuses a well-formed flag must fail the check."""
    from ctf.platform import policy
    monkeypatch.setattr(policy, "base_checks", lambda prof, req: "refused: the gate refuses everything")
    c = doctor.check_submit_dry_run(profile(submit_mode=mode))
    assert c.status == "fail" and named in c.detail, c.detail


def test_submit_dry_run_catches_a_gate_that_sends_on_a_manual_event(monkeypatch):
    from ctf.platform import policy
    real = policy.base_checks

    def ignore_manual(prof, req):
        r = real(prof, req)
        return None if r and "is manual" in r else r
    monkeypatch.setattr(policy, "base_checks", ignore_manual)
    c = doctor.check_submit_dry_run(profile(kind="manual", submit_mode="manual"))
    assert c.status == "fail" and "gate sent a value on a manual event" in c.detail, c.detail


def test_submit_dry_run_catches_a_carried_guard_that_refuses_a_good_flag(monkeypatch):
    """guarded_submit answering 'duplicate' for a never-sent flag (a stale dedupe) is a dead path."""
    from ctf import workspace
    monkeypatch.setattr(workspace.Challenge, "already_tried", lambda self, flag: True)
    c = doctor.check_submit_dry_run(profile())
    assert c.status == "fail" and "guarded_submit refused the well-formed" in c.detail
    assert "duplicate" in c.detail


def test_synth_flag_fits_the_event_body_or_fails_naming_it():
    p = profile(prefixes=("flag",), body="[0-9a-f]{32}")
    f = doctor.synth_flag(p)
    assert flagfmt.for_profile(p).is_flag(f) and len(f) == len("flag{}") + 32
    with pytest.raises(ValueError, match=r"body regex 'Q\{3\}X'"):
        doctor.synth_flag(profile(body="Q{3}X"))
    unknown = profile(prefixes=(), submit_mode="confirm")
    assert flagfmt.for_profile(unknown).is_flag(doctor.synth_flag(unknown))


# ------------------------------------------------------------------------------- instances

def test_instances_without_config_is_skipped_naming_b003():
    c = doctor.check_instances(profile())
    assert c.status == "skip" and "B-003" in c.detail
    c = doctor.check_instances(profile(), {"endpoints": {"plugin": "docker_per_team"}, "cap": None})
    assert c.status == "skip" and "no challenge id" in c.detail


def _fake_client(fake, prof):
    import dataclasses
    from ctf import client, config
    rprof = dataclasses.replace(prof, platform=dataclasses.replace(prof.platform, base_url=fake.base_url))
    cfg = config.Config(base_url=fake.base_url, token=fake.token, team_id=None, workdir=Path("/nonexistent"))
    c = client.CTFd(cfg, profile=rprof)
    c.s.trust_env = False
    return c


def test_instance_probe_reads_the_status_route_of_the_fake():
    from ctf.fakectfd import FakeChallenge, FakeCTFd
    prof = profile()
    board = [FakeChallenge(7, "box", "Web", instance=True), FakeChallenge(8, "plain", "Web")]
    cfg = {"endpoints": {"plugin": "docker_per_team"}, "cap": None}
    with FakeCTFd(board, token="t-probe") as fake:
        c = _fake_client(fake, prof)
        ok = doctor.check_instances(prof, cfg, 7, client=c)
        bad = doctor.check_instances(prof, cfg, 8, client=c)
        hidden = doctor.check_instances(prof, cfg, 99, client=c)
        posts = [r for r in fake.log if r.kind == "instance"]
    assert ok.status == "ok" and "'127.0.0.1:40007'" in ok.detail
    assert bad.status == "fail" and "no instance for this challenge" in bad.detail
    assert hidden.status == "fail" and "scope lock" in hidden.detail
    assert [r.body for r in posts] == [{"chal_id": 7}, {"chal_id": 8}]   # 99 never left the client


# ------------------------------------------------------------------------------- aggregate + CLI

def test_failed_counts_warn_and_skip_only_when_strict():
    cs = [doctor.Check("a", "ok", ""), doctor.Check("b", "warn", ""), doctor.Check("c", "skip", ""),
          doctor.Check("d", "fail", "")]
    assert [c.name for c in doctor.failed(cs)] == ["d"]
    assert [c.name for c in doctor.failed(cs, strict=True)] == ["b", "c", "d"]
    with pytest.raises(ValueError):
        doctor.Check("x", "green", "")


def test_run_checks_order_and_codex_skip(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))       # the allowance check reads the workdir

    def no_host_programs(argv, **kw):
        return subprocess.CompletedProcess(argv, 1, "", "stubbed")
    # an empty PATH and toolbox folder, and a stub run: no host program is probed
    cs = doctor.run_checks(profile(), codex=False, run=no_host_programs, power=False,
                           environ={"PATH": str(tmp_path), "CTF_TOOLBOX_DIR": str(tmp_path / "tb")})
    assert [c.name for c in cs] == ["profile", "categories", "router", "compaction", "codex-smoke",
                                    "submit-dry-run", "instances", "toolbox", "assets", "images", "allowance",
                                    "failover", "token", "brief-rules", "usage", "capabilities"]   # B-190 added the last four
    tb = cs[7]
    assert tb.name == "toolbox" and tb.status == "warn" and "sops missing" in tb.detail, tb.line()   # advisory, not fail
    assert cs[4].status == "skip" and "untested" in cs[4].detail


def test_profile_check_warns_after_the_event_and_on_unknown_prefixes():
    p = profile(prefixes=(), submit_mode="confirm")
    c = doctor.check_profile(p, now=dt.datetime(2031, 1, 1, tzinfo=UTC))
    assert c.status == "warn" and "phase post-event" in c.detail and "prefixes are not known" in c.detail
    c = doctor.check_profile(profile(), now=dt.datetime(2030, 1, 1, tzinfo=UTC))
    assert c.status == "ok" and "phase pre-event" in c.detail


def test_profile_check_fails_when_the_file_on_disk_no_longer_validates(tmp_path):
    root = tmp_path / "events"
    (root / "demo").mkdir(parents=True)
    f = root / "demo" / "event.toml"
    f.write_text(textwrap.dedent("""\
        slug = "demo"
        name = "Demo"
        dates = { start = 2030-03-01T00:00:00Z, end = 2030-03-02T00:00:00Z }
        [platform]
        kind = "ctfd"
        base_url = "https://demo.example"
        [flag]
        prefixes = ["DEMO"]
        [rules]
        submit_mode = "auto"
        flag_sharing = "allowed"
        ai_on_platform = "allowed"
        """))
    p = event.load("demo", root)
    f.write_text(f.read_text().replace('submit_mode = "auto"', 'submit_mode = "sometimes"'))
    c = doctor.check_profile(p, events_root=root)
    assert c.status == "fail" and "rules.submit_mode" in c.detail


def run_ctf(*args, **env):
    e = dict(os.environ, **env)
    return subprocess.run([sys.executable, "-m", "ctf", *args], cwd=paths.repo_root(), env=e,
                          capture_output=True, text=True, timeout=120)


def test_cli_preflight_json_strict_and_bad_event():
    r = run_ctf("preflight", "--event", "pink", "--no-codex", "--json")
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads(r.stdout)
    by = {c["name"]: c for c in doc["checks"]}
    assert doc["passed"] and by["categories"]["status"] == "warn" and "'Minecraft'" in by["categories"]["detail"]
    assert by["codex-smoke"]["status"] == "skip"
    r = run_ctf("preflight", "--event", "pink", "--no-codex", "--strict")
    assert r.returncode == 1 and "PREFLIGHT FAILED" in r.stdout and "categories" in r.stdout
    r = run_ctf("preflight", "--event", "no-such-event", "--no-codex")
    assert r.returncode == 2 and "no event profile 'no-such-event'" in r.stderr


def test_cli_preflight_codex_refused_under_testing_fails(tmp_path):
    e = {"CTF_TESTING": "1", "CODEX_HOME": str(tmp_path / "no-codex-home")}   # never the operator's config
    r = subprocess.run([sys.executable, "-m", "ctf", "preflight", "--event", "pink"], cwd=paths.repo_root(),
                       env={k: v for k, v in dict(os.environ, **e).items() if k != "CODEX_BIN"},
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 1 and "FAIL  codex-smoke" in r.stdout


def test_ctf_doctor_prints_the_b039_section(monkeypatch, capsys, tmp_path):
    """The carried `ctf doctor` ends with the B-039 checks; a failing one fails the doctor."""
    import shutil
    import subprocess as sp
    from ctf import cli, config

    class Done:
        returncode, stdout, stderr = 1, "", ""
    monkeypatch.setattr(sp, "run", lambda *a, **k: Done())             # no docker, no host probes
    monkeypatch.setattr(shutil, "which", lambda t, **k: None)           # the toolbox passes path=
    monkeypatch.setattr(config, "load", lambda: config.Config(base_url="https://demo.example", token=None,
                                                              team_id=None, workdir=tmp_path / "w"))
    monkeypatch.setenv("CTF_EVENT", "pink")
    rc = cli.main(["doctor", "--no-codex"])
    out = capsys.readouterr().out
    assert rc == 1                                                       # docker/tools are missing here
    sec = out[out.index("preflight (B-039"):]
    for name in ("profile", "categories", "router", "codex-smoke", "submit-dry-run", "instances", "toolbox"):
        assert f"] {name}" in sec, sec
    assert "Minecraft" in sec
