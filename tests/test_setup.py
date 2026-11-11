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
    assert "MY_DOCTOR_KEY=<your key> in" in unset["api key"].fix
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


# ---------------------------------------------------------------------- the Anthropic provider and its fallback

CLAUDE_LADDER = ("claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5")
OPENROUTER_LADDER = ("anthropic/claude-haiku-5.5", "anthropic/claude-sonnet-5.5", "anthropic/claude-opus-5.5")
ROUTER_KEY = "fake-router-key-for-init-tests"


def anthropic_init(tmp_path, monkeypatch, *args: str, terminal: bool = False, answers: str = "", router_key: bool = False):
    monkeypatch.setattr(cli, "_at_terminal", lambda: terminal)
    if router_key:
        monkeypatch.setenv("OPENROUTER_API_KEY", ROUTER_KEY)
    else:
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    target = tmp_path / "config.toml"
    result = CliRunner().invoke(cli.app, ["init", "--provider", "anthropic", *args, "--path", str(target)], input=answers)
    return result, target


def test_init_for_anthropic_writes_the_claude_ladder_with_anthropics_prices(tmp_path, monkeypatch):
    from ctf_flightdeck.config import ApiConfig
    from ctf_flightdeck.pricing import Price

    result, target = anthropic_init(tmp_path, monkeypatch, "--host")
    assert result.exit_code == 0, result.output
    config = load_config(target)
    assert config.api == ApiConfig("https://api.anthropic.com", "ANTHROPIC_API_KEY", "anthropic")
    assert config.models == CLAUDE_LADDER
    assert config.prices == {  # dollars per million tokens: input, output, cache reads
        "claude-haiku-5-5": Price(0.10, 0.50, 0.01),
        "claude-sonnet-5-5": Price(2.0, 10.0, 0.10),
        "claude-opus-5-5": Price(4.0, 20.0, 0.20),
    }
    assert config.fallback is None and config.lanes.dollar_cap == 2.0  # caps in dollars work from the start
    assert "put ANTHROPIC_API_KEY=<your key> in" in result.output and "export ANTHROPIC_API_KEY=<your key>" in result.output
    assert "OpenRouter" not in result.output  # no OpenRouter key known: nothing offered


@pytest.mark.parametrize("answer, wanted", [("y", True), ("n", False)])
def test_at_a_terminal_init_for_anthropic_offers_openrouter_as_the_fallback_when_its_key_is_known(tmp_path, monkeypatch, answer, wanted):
    from ctf_flightdeck.config import FallbackConfig

    result, target = anthropic_init(tmp_path, monkeypatch, terminal=True, router_key=True, answers=f"\n{answer}\nhost\n")
    assert result.exit_code == 0, result.output
    assert "OPENROUTER_API_KEY is set: use OpenRouter for a lane whose calls to Anthropic keep failing?" in result.output
    config = load_config(target)
    assert config.models == CLAUDE_LADDER  # the default ladder, taken at the prompt
    if wanted:
        assert config.fallback == FallbackConfig("openai", "https://openrouter.ai/api/v1", "OPENROUTER_API_KEY", OPENROUTER_LADDER)
        assert "these are OpenRouter's names for the same models" in target.read_text()
        assert "put OPENROUTER_API_KEY=<your key> in" in result.output
    else:
        assert config.fallback is None and "[fallback]" not in target.read_text()
    assert ROUTER_KEY not in result.output and ROUTER_KEY not in target.read_text()


def test_an_openrouter_key_in_the_keys_file_is_known_too(tmp_path, monkeypatch):
    keys = tmp_path / "keys.env"
    keys.write_text(f"OPENROUTER_API_KEY={ROUTER_KEY}\n")
    keys.chmod(0o600)
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(keys))
    result, target = anthropic_init(tmp_path, monkeypatch, terminal=True, answers="\ny\nhost\n")
    assert result.exit_code == 0, result.output
    assert load_config(target).fallback.ladder == OPENROUTER_LADDER


def test_away_from_a_terminal_init_mentions_the_fallback_and_writes_it_with_the_option(tmp_path, monkeypatch):
    offered, target = anthropic_init(tmp_path, monkeypatch, "--host", router_key=True)
    assert offered.exit_code == 0, offered.output
    assert load_config(target).fallback is None
    assert "--provider anthropic --fallback` also writes OpenRouter as the fallback" in offered.output
    asked, target = anthropic_init(tmp_path, monkeypatch, "--host", "--fallback", "--force")
    assert asked.exit_code == 0, asked.output
    assert load_config(target).fallback.ladder == OPENROUTER_LADDER
    declined, target = anthropic_init(tmp_path, monkeypatch, "--host", "--no-fallback", "--force", router_key=True)
    assert load_config(target).fallback is None and "--fallback` also writes" not in declined.output


def test_init_refuses_a_fallback_it_cannot_write(tmp_path, monkeypatch):
    unknown, target = anthropic_init(tmp_path, monkeypatch, "--models", "claude-haiku-5-5,claude-some-other-model",
                                     "--host", "--fallback")
    assert unknown.exit_code == 2 and "OpenRouter's name is not known" in unknown.output and not target.exists()
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    other = CliRunner().invoke(cli.app, ["init", "--provider", "openrouter", "--models", "a/b", "--host", "--fallback",
                                         "--path", str(tmp_path / "o.toml")])
    assert other.exit_code == 2 and "--fallback is for --provider anthropic" in other.output


def test_doctor_checks_the_fallback_key_like_the_primarys_in_the_environment_or_the_keys_file(tmp_path, monkeypatch):
    path = tmp_path / "c.toml"
    path.write_text('[api]\nprovider = "anthropic"\n[models]\nladder = ["claude-haiku-5-5"]\n'
                    '[fallback]\nladder = ["anthropic/claude-haiku-5.5"]\n[lanes]\nruntime = "host"\n')
    checks = {c.name: c for c in doctor(path, environ={"ANTHROPIC_API_KEY": "value-that-must-not-show"})}
    assert checks["api key"].ok
    spare = checks["fallback key"]
    assert not spare.ok and spare.essential and spare.detail == "OPENROUTER_API_KEY is not set"
    assert "OPENROUTER_API_KEY=<your key> in" in spare.fix
    assert report(list(checks.values()))[1] == 1  # the run would refuse to start, so doctor fails
    keys = tmp_path / "keys.env"
    keys.write_text("OPENROUTER_API_KEY=value-that-must-not-show-either\n")
    keys.chmod(0o600)
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(keys))
    checks = doctor(path, environ={"ANTHROPIC_API_KEY": "value-that-must-not-show"})
    spare = {c.name: c for c in checks}["fallback key"]
    assert spare.ok and spare.detail == "OPENROUTER_API_KEY is set (in your keys file)"
    text, _ = report(checks)
    assert "must-not-show" not in text


def test_doctor_asks_only_an_openai_style_server_on_this_machine_for_its_models(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text('[api]\nprovider = "anthropic"\nbase_url = "http://127.0.0.1:9"\n[models]\nladder = ["m"]\n'
                    '[fallback]\nbase_url = "http://127.0.0.1:9/v1"\nkey_env = ""\nladder = ["m"]\n[lanes]\nruntime = "host"\n')
    checks = {c.name: c for c in doctor(path, environ={"ANTHROPIC_API_KEY": "x"})}
    assert "model server" not in checks  # an Anthropic API has no OpenAI /models to ask
    assert not checks["fallback server"].ok and "[fallback] base_url" in checks["fallback server"].fix


def test_config_command_shows_the_provider_and_the_fallback_never_a_key(tmp_path, monkeypatch):
    path = tmp_path / "c.toml"
    path.write_text('[api]\nprovider = "anthropic"\n[models]\nladder = ["claude-haiku-5-5"]\n'
                    '[fallback]\nladder = ["anthropic/claude-haiku-5.5"]\n')
    monkeypatch.setenv("ANTHROPIC_API_KEY", "value-that-must-not-show")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    result = CliRunner().invoke(cli.app, ["config", "--path", str(path)])
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    assert "api: https://api.anthropic.com (anthropic)" in lines and "key: ANTHROPIC_API_KEY is set" in lines
    assert "fallback: https://openrouter.ai/api/v1 (openai), key OPENROUTER_API_KEY is NOT set" in lines
    assert "fallback models: anthropic/claude-haiku-5.5" in lines
    assert "must-not-show" not in result.output


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
