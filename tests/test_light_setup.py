"""`init --light` writes the light model's table; `doctor` checks it like the API, never as essential."""

from __future__ import annotations

import importlib.util

from typer.testing import CliRunner

from ctf_flightdeck import cli
from ctf_flightdeck.config import LightConfig, load_config
from ctf_flightdeck.pricing import Price
from ctf_flightdeck.setup import Answers, LightAnswers, doctor, report, write_config


def init(tmp_path, monkeypatch, *args: str):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    target = tmp_path / "config.toml"
    result = CliRunner().invoke(cli.app, ["init", "--provider", "openrouter", "--models", "a/one", "--host",
                                          "--path", str(target), *args])
    return result, target


def test_init_writes_no_light_model_by_default_and_recommends_a_local_one(tmp_path, monkeypatch):
    result, target = init(tmp_path, monkeypatch)
    assert result.exit_code == 0, result.output
    assert load_config(target).light == LightConfig()
    text = target.read_text()
    assert "[light]" in text and 'engine = "rules"' in text and "open-weight" in text and "eval-local" in text
    assert "light model: none, the rules alone. Recommended when you want one: an open-weight model on this machine" in result.output


def test_init_writes_an_open_weight_model_served_on_this_machine(tmp_path, monkeypatch):
    result, target = init(tmp_path, monkeypatch, "--light", "ollama", "--light-model", "qwen3.5:9b")
    assert result.exit_code == 0, result.output
    assert load_config(target).light == LightConfig("openai", "qwen3.5:9b", "http://127.0.0.1:11434/v1", "", thinking=False)
    assert '\nengine = "openai"\nmodel = "qwen3.5:9b"\nbase_url = "http://127.0.0.1:11434/v1"\n' in target.read_text()
    assert ("measure it against the rules: flightdeck eval-local --engine openai --base-url http://127.0.0.1:11434/v1 "
            "--model qwen3.5:9b") in result.output
    result, target = init(tmp_path, monkeypatch, "--light", "mlx", "--light-model", "some-mlx-model", "--force")
    assert load_config(target).light.base_url == "http://127.0.0.1:8080/v1"


def test_init_needs_the_local_models_name_and_suggests_some_to_measure(tmp_path, monkeypatch):
    result, target = init(tmp_path, monkeypatch, "--light", "ollama")
    assert result.exit_code == 2 and not target.exists()
    assert "--light ollama needs --light-model" in result.output
    assert "examples to measure: Qwen3.5 9B, Gemma 4 12B, gpt-oss-20b, Ministral 3 14B or Phi-4-mini" in result.output


def test_init_writes_claude_or_cactus_as_the_light_model_when_asked(tmp_path, monkeypatch):
    result, target = init(tmp_path, monkeypatch, "--light", "anthropic")
    assert result.exit_code == 0, result.output
    assert load_config(target).light == LightConfig("anthropic", "claude-haiku-5-5", "https://api.anthropic.com",
                                                    "ANTHROPIC_API_KEY", price=Price(0.10, 0.50, 0.01))
    assert "a refusal leaves the rules' answer" in result.output
    result, target = init(tmp_path, monkeypatch, "--light", "cactus", "--force")
    assert load_config(target).light == LightConfig("cactus")


def test_init_refuses_a_light_choice_it_does_not_know(tmp_path, monkeypatch):
    result, _ = init(tmp_path, monkeypatch, "--light", "gpt")
    assert result.exit_code == 2 and "--light must be one of rules, ollama, mlx, anthropic, cactus" in result.output
    result, _ = init(tmp_path, monkeypatch, "--light-model", "x")
    assert result.exit_code == 2 and "--light-model needs --light ollama, mlx, anthropic or decider" in result.output


def checks(tmp_path, light: LightAnswers | None, environ=None) -> dict:
    path = write_config(Answers("http://127.0.0.1:9/v1", "", ("m",), "host", light=light), tmp_path / "c.toml", force=True)
    return {c.name: c for c in doctor(path, environ=environ or {})}


def test_doctor_with_the_rules_alone_points_at_a_local_model_and_eval_local(tmp_path):
    check = checks(tmp_path, None)["light model"]
    assert check.ok and not check.essential
    assert "open-weight model on this machine" in check.detail and "flightdeck eval-local" in check.detail


def test_doctor_checks_a_local_light_server_without_failing_the_setup(tmp_path):
    from fake_model import FakeModelServer

    with FakeModelServer() as server:  # answers GET /v1/models with 404: a server, but not that path
        found = checks(tmp_path, LightAnswers("openai", "qwen", server.base_url, ""))
        assert "answered" in found["light server"].detail
        assert server.requests and server.requests[-1]["path"] == "/v1/models"  # asked, on this machine
    down = checks(tmp_path, LightAnswers("openai", "qwen", "http://127.0.0.1:9/v1", ""))
    assert not down["light server"].ok and not down["light server"].essential
    assert "nothing answers at http://127.0.0.1:9/v1" in down["light server"].detail
    assert "[light] base_url" in down["light server"].fix
    assert "flightdeck eval-local --engine openai --model qwen --base-url http://127.0.0.1:9/v1" in down["light model"].detail
    assert "light key" not in down  # a server on this machine needs no key


def test_doctor_checks_the_light_key_and_never_shows_it(tmp_path):
    claude = LightAnswers("anthropic", "claude-haiku-5-5", "https://api.anthropic.com", "FLIGHTDECK_LIGHT_TEST_KEY")
    missing = checks(tmp_path, claude, environ={})
    assert not missing["light key"].ok and not missing["light key"].essential
    assert "FLIGHTDECK_LIGHT_TEST_KEY is not set" in missing["light key"].detail
    assert "refusal leaves the rules' answer" in missing["light model"].detail
    present = checks(tmp_path, claude, environ={"FLIGHTDECK_LIGHT_TEST_KEY": "fake-light-key-0451"})
    assert present["light key"].ok
    text, _ = report(list(present.values()))
    assert "fake-light-key-0451" not in text


def test_doctor_says_whether_cactus_is_installed(tmp_path):
    check = checks(tmp_path, LightAnswers("cactus"))["light model"]
    installed = importlib.util.find_spec("cactus") is not None
    assert check.ok is installed and not check.essential
    if not installed:
        assert 'pip install "ctf-flightdeck[cactus]"' in check.fix


def test_a_failing_light_check_never_fails_doctor(tmp_path, monkeypatch):
    claude = LightAnswers("anthropic", "claude-haiku-5-5", "https://api.anthropic.com", "FLIGHTDECK_LIGHT_TEST_KEY")
    path = write_config(Answers("http://127.0.0.1:9/v1", "", ("m",), "host", light=claude), tmp_path / "c.toml")
    found = [c for c in doctor(path, environ={}) if c.name.startswith("light")]
    assert found and all(not c.essential for c in found)
    text, _ = report(found)
    assert "warn light key" in text  # shown as a warning, not a failure
