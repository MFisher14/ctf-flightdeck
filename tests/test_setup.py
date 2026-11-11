"""First-run help: init writes a config that loads; doctor checks a setup and never shows the key."""

from __future__ import annotations

import os

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli
from ctf_flightdeck.config import ConfigError, load_config
from ctf_flightdeck.lane import IMAGE
from ctf_flightdeck.setup import Answers, Check, doctor, render, report, write_config

ANSWERS = Answers("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY", ("vendor/small", "vendor/big"), "docker")


def test_init_writes_a_config_that_loads_with_the_answers(tmp_path):
    path = write_config(ANSWERS, tmp_path / "config.toml")
    config = load_config(path)
    assert config.models == ("vendor/small", "vendor/big")
    assert (config.api.base_url, config.api.key_env) == ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY")
    assert (config.lanes.runtime, config.lanes.image, config.lanes.max_lanes) == ("docker", IMAGE, 4)
    assert config.lanes.submit == "confirm"  # every flag is approved by the player


def test_a_host_config_names_no_image_and_caps_can_be_off(tmp_path):
    answers = Answers("http://127.0.0.1:11434/v1", "", ("local/model",), "host", token_cap=None, dollar_cap=None)
    config = load_config(write_config(answers, tmp_path / "c.toml"))
    assert (config.lanes.runtime, config.api.key_env) == ("host", "")
    assert (config.lanes.token_cap, config.lanes.dollar_cap) == (None, None)
    assert "image" not in render(answers)


def test_init_never_overwrites_a_config_unless_forced_and_never_writes_a_bad_one(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text("# mine\n")
    with pytest.raises(FileExistsError, match="--force"):
        write_config(ANSWERS, path)
    assert path.read_text() == "# mine\n"
    with pytest.raises(ConfigError):
        write_config(Answers("https://x.example/v1", "OPENROUTER_API_KEY", (), "docker"), tmp_path / "bad.toml")
    assert not (tmp_path / "bad.toml").exists()
    write_config(ANSWERS, path, force=True)
    assert load_config(path).models == ANSWERS.models


def test_init_with_every_answer_as_an_option_says_what_to_do_next(tmp_path):
    target = tmp_path / "cfg" / "config.toml"
    result = CliRunner().invoke(cli.app, ["init", "--provider", "openrouter", "--models", "a/one, b/two", "--docker", "--path", str(target)])
    assert result.exit_code == 0, result.output
    assert load_config(target).models == ("a/one", "b/two")
    assert "export OPENROUTER_API_KEY=<your key>" in result.output
    assert "flightdeck image build" in result.output and "flightdeck doctor" in result.output


def test_init_asks_at_a_terminal(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    target = tmp_path / "config.toml"
    result = CliRunner().invoke(cli.app, ["init", "--path", str(target)], input="local\nlocal/small,local/big\nhost\n")
    assert result.exit_code == 0, result.output
    config = load_config(target)
    assert (config.api.base_url, config.api.key_env, config.lanes.runtime) == ("http://127.0.0.1:11434/v1", "", "host")
    assert "export" not in result.output  # a local server needs no key
    assert config.lanes.dollar_cap is None  # nothing to spend: no cap to ask about


def test_init_away_from_a_terminal_names_the_missing_answer(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    result = CliRunner().invoke(cli.app, ["init", "--provider", "openrouter", "--path", str(tmp_path / "c.toml")])
    assert result.exit_code == 2 and "Models" in result.output
    assert not (tmp_path / "c.toml").exists()


def test_doctor_checks_the_key_variable_without_ever_showing_it(tmp_path, monkeypatch):
    path = write_config(Answers("https://openrouter.ai/api/v1", "MY_DOCTOR_KEY", ("a/b",), "host"), tmp_path / "c.toml")
    unset = {c.name: c for c in doctor(path, environ={})}
    assert not unset["api key"].ok and "MY_DOCTOR_KEY is not set" in unset["api key"].detail
    assert "export MY_DOCTOR_KEY" in unset["api key"].fix
    checks = doctor(path, environ={"MY_DOCTOR_KEY": "value-that-must-not-show"})
    assert {c.name: c for c in checks}["api key"].ok
    text, _ = report(checks)
    assert "value-that-must-not-show" not in text


def test_doctor_without_a_config_says_to_run_init(tmp_path):
    checks = {c.name: c for c in doctor(tmp_path / "missing.toml", environ={})}
    assert not checks["config"].ok and "flightdeck init" in checks["config"].fix
    assert "api key" not in checks  # nothing to check without a config


def test_docker_problems_fail_the_doctor_only_for_a_docker_runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))  # no docker here
    docker_cfg = write_config(ANSWERS, tmp_path / "docker.toml")
    host_cfg = write_config(Answers("https://openrouter.ai/api/v1", "", ("a/b",), "host"), tmp_path / "host.toml")
    docker_checks = {c.name: c for c in doctor(docker_cfg, environ={"OPENROUTER_API_KEY": "x"})}
    assert not docker_checks["docker"].ok and docker_checks["docker"].essential
    assert report(list(docker_checks.values()))[1] == 1
    host_checks = {c.name: c for c in doctor(host_cfg, environ={})}
    assert not host_checks["docker"].ok and not host_checks["docker"].essential
    assert report(list(host_checks.values()))[1] == 0


def test_report_marks_each_check_and_says_what_to_do():
    text, status = report([Check("python", True, "3.12"), Check("api key", False, "K is not set", "export K=...")])
    assert text.splitlines() == ["ok   python: 3.12", "FAIL api key: K is not set", "     fix: export K=..."]
    assert status == 1
    text, status = report([Check("terminal", False, "80x24", "bigger is easier", essential=False)])
    assert status == 0 and text.rstrip().endswith("Ready. Try `flightdeck practice`.")


def test_doctor_says_plainly_when_there_is_no_config_and_points_at_a_broken_one(tmp_path):
    missing = {c.name: c for c in doctor(tmp_path / "none.toml", environ={})}["config"]
    assert missing.detail == f"no config at {tmp_path / 'none.toml'}" and "flightdeck init" in missing.fix
    broken = tmp_path / "broken.toml"
    broken.write_text("[models]\nladder = []\n")
    check = {c.name: c for c in doctor(broken, environ={})}["config"]
    assert not check.ok and "--force" in check.fix and str(broken) in check.detail


def test_init_for_an_mlx_server_needs_no_key_and_no_dollar_cap(tmp_path):
    target = tmp_path / "config.toml"
    result = CliRunner().invoke(cli.app, ["init", "--provider", "mlx", "--models", "mlx-community/some-model", "--host", "--path", str(target)])
    assert result.exit_code == 0, result.output
    config = load_config(target)
    assert (config.api.base_url, config.api.key_env, config.lanes.dollar_cap) == ("http://127.0.0.1:8080/v1", "", None)


def test_doctor_checks_a_local_model_server_answers_and_never_contacts_a_remote_api(tmp_path):
    from fake_model import FakeModelServer

    with FakeModelServer() as server:  # answers GET /v1/models with 404: a server, but not that path
        cfg = write_config(Answers(server.base_url, "", ("m",), "host"), tmp_path / "up.toml")
        checks = {c.name: c for c in doctor(cfg, environ={})}
        assert "model server" in checks and "answered" in checks["model server"].detail
    down = write_config(Answers("http://127.0.0.1:9/v1", "", ("m",), "host"), tmp_path / "down.toml")
    check = {c.name: c for c in doctor(down, environ={})}["model server"]
    assert not check.ok and "nothing answers at http://127.0.0.1:9/v1" in check.detail
    remote = write_config(Answers("https://api.example.test/v1", "", ("m",), "host"), tmp_path / "remote.toml")
    assert "model server" not in {c.name for c in doctor(remote, environ={})}


def test_doctor_checks_the_l1_pack_when_the_config_names_one(tmp_path):
    from l1_kit import python_engine

    base = '[api]\nkey_env = ""\n[models]\nladder = ["m"]\n[lanes]\nruntime = "host"\n'
    good, empty = tmp_path / "pack", tmp_path / "empty"
    python_engine(good, "reader", "def solve(d):\n    pass\n")
    empty.mkdir()
    for pack, ok, detail in [(good, True, "1 engine(s)"), (empty, False, "has no engines"), (tmp_path / "gone", False, "no such pack folder")]:
        path = tmp_path / f"{pack.name}.toml"
        path.write_text(base + f'[l1]\npack = "{pack}"\n')
        (check,) = [c for c in doctor(path, environ={}) if c.name == "l1 pack"]
        assert check.ok is ok and detail in check.detail
    path = tmp_path / "none.toml"
    path.write_text(base)
    assert not [c for c in doctor(path, environ={}) if c.name == "l1 pack"]  # no pack: nothing to check


def test_doctor_never_prints_a_credential_carried_in_the_base_url(tmp_path):
    secret = "query-secret-value-5150"
    path = tmp_path / "q.toml"
    path.write_text(f'[api]\nbase_url = "http://127.0.0.1:9/v1?api_key={secret}"\nkey_env = ""\n'
                    '[models]\nladder = ["m"]\n[lanes]\nruntime = "host"\n')
    check = {c.name: c for c in doctor(path, environ={})}["model server"]
    assert not check.ok and "http://127.0.0.1:9/v1" in check.detail
    assert secret not in check.detail and secret not in report([check])[0]


def test_doctor_checks_a_coding_agent_cli_when_asked(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    keep = [d for d in os.environ.get("PATH", "").split(os.pathsep)
            if d and not any(os.access(os.path.join(d, cli), os.X_OK) for cli in ("claude", "codex"))]
    monkeypatch.setenv("PATH", os.pathsep.join([str(bin_dir), *keep]))
    cfg = write_config(Answers("https://openrouter.ai/api/v1", "", ("a/b",), "host"), tmp_path / "c.toml")
    missing = {c.name: c for c in doctor(cfg, environ={}, agent="claude")}["agent"]
    assert not missing.ok and missing.essential
    exe = bin_dir / "claude"
    exe.write_text("#!/bin/sh\nexit 0\n")
    exe.chmod(0o755)
    secret = "fake-anthropic-credential-for-tests"
    checks = doctor(cfg, environ={"ANTHROPIC_API_KEY": secret, "PATH": os.environ["PATH"]}, agent="claude")
    found = {c.name: c for c in checks}["agent"]
    assert found.ok and str(exe) in found.detail
    assert any(c.name == "agent note" and not c.essential for c in checks)  # its key is visible to its commands
    assert secret not in report(checks)[0]
