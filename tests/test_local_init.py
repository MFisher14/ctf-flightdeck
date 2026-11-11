"""`flightdeck init` and `doctor` for a model server on this machine.

init offers what a benchmark on one machine measured (gpt-oss:20b on Ollama, Qwen3.5 9B on
MLX, Qwen3.5 9B as the light model with thinking off): the default at its prompt, named in its
message away from a terminal, never written unless the player takes it. For a server on this
machine it writes [api] timeout and max_tokens and says why; doctor says what lane calls use.
"""

from __future__ import annotations

from typer.testing import CliRunner

from ctf_flightdeck import cli
from ctf_flightdeck.config import LightConfig, load_config
from ctf_flightdeck.setup import Answers, LightAnswers, doctor, report, write_config

QWEN_MLX = "mlx-community/Qwen3.5-9B-MLX-4bit"
MLX_COMMAND = f"""mlx_lm.server --model {QWEN_MLX} --max-tokens 8192 --chat-template-args '{{"enable_thinking":false}}'"""
# Qwen3.5 9B on Ollama solved 1 of 4 as served in the same benchmark: gpt-oss 20B solved the most, not the only ones
OLLAMA_WHY = "the local model that solved the most practice challenges as served (2 of 4), in a benchmark on one machine"
NOTHING_HERE = "http://127.0.0.1:9/v1"  # on this machine, and nothing listens there


def init(monkeypatch, tmp_path, *args: str, terminal: bool = False, answers: str = "", name: str = "config.toml"):
    monkeypatch.setattr(cli, "_at_terminal", lambda: terminal)
    target = tmp_path / name
    result = CliRunner().invoke(cli.app, ["init", *args, "--path", str(target)], input=answers)
    return result, target


def one_line(text: str) -> str:
    """A config's comments as one line of prose, to find a sentence wrapped over several lines."""
    return " ".join(line.lstrip("#").strip() for line in text.splitlines())


# ---------------------------------------------------------------------- the lanes' model


def test_at_a_terminal_init_for_ollama_offers_gpt_oss_and_writes_a_longer_timeout_and_a_reply_cap(tmp_path, monkeypatch):
    result, target = init(monkeypatch, tmp_path, "--provider", "local", "--host", terminal=True, answers="\n")
    assert result.exit_code == 0, result.output
    config = load_config(target)
    assert config.models == ("gpt-oss:20b",)
    assert f"Suggested: gpt-oss:20b, {OLLAMA_WHY}. Press Enter to take it, or give your own." in result.output
    assert (config.api.timeout, config.api.max_tokens) == (600.0, 8192)
    written = one_line(target.read_text())
    assert "Gemma 4 12B on Ollama, at about 22 tokens a second, ran past 180 s in a benchmark on one machine." in written
    assert "Leave it out for OpenAI's own API: its reasoning models refuse max_tokens." in written
    assert ("lane calls: 600 s per try and replies of up to 8192 tokens, for a server on this machine: a local model can "
            "take minutes for one reply") in result.output


def test_the_player_can_give_another_model_at_the_prompt(tmp_path, monkeypatch):
    result, target = init(monkeypatch, tmp_path, "--provider", "local", "--host", terminal=True, answers="qwen3.5:9b\n")
    assert result.exit_code == 0, result.output
    assert load_config(target).models == ("qwen3.5:9b",)


def test_at_a_terminal_init_for_mlx_offers_qwen_and_the_server_command(tmp_path, monkeypatch):
    result, target = init(monkeypatch, tmp_path, "--provider", "mlx", "--host", terminal=True, answers="\n")
    assert result.exit_code == 0, result.output
    config = load_config(target)
    assert config.models == (QWEN_MLX,) and config.api.base_url == "http://127.0.0.1:8080/v1"
    assert (f"Suggested: {QWEN_MLX}, it solved 2 of 4 practice challenges with thinking off and replies of up to 8192 "
            "tokens, in a benchmark on one machine.") in result.output
    assert f"next: start the MLX server: {MLX_COMMAND}" in result.output
    assert (config.api.timeout, config.api.max_tokens) == (600.0, 8192)


def test_away_from_a_terminal_the_suggestion_is_named_and_nothing_is_written(tmp_path, monkeypatch):
    result, target = init(monkeypatch, tmp_path, "--provider", "local", "--host")
    assert result.exit_code == 2 and not target.exists()
    assert f"give --models ID,ID (weakest first; suggested: --models gpt-oss:20b, {OLLAMA_WHY})" in result.output
    result, target = init(monkeypatch, tmp_path, "--provider", "mlx", "--host")
    assert result.exit_code == 2 and not target.exists()
    assert f"suggested: --models {QWEN_MLX}, it solved 2 of 4 practice challenges" in result.output


def test_away_from_a_terminal_mlx_gets_the_server_command_for_the_model_given(tmp_path, monkeypatch):
    result, target = init(monkeypatch, tmp_path, "--provider", "mlx", "--models", "mlx-community/gemma-4-12B-it-4bit",
                          "--host")
    assert result.exit_code == 0, result.output
    assert ("next: start the MLX server: mlx_lm.server --model mlx-community/gemma-4-12B-it-4bit --max-tokens 8192 "
            """--chat-template-args '{"enable_thinking":false}'   (""") in result.output
    elsewhere, target = init(monkeypatch, tmp_path, "--provider", "mlx", "--base-url", "http://127.0.0.1:8081/v1",
                             "--models", "m/x", "--host", name="port.toml")
    assert elsewhere.exit_code == 0, elsewhere.output
    assert """--chat-template-args '{"enable_thinking":false}' --port 8081   (""" in elsewhere.output


def test_an_api_elsewhere_gets_no_timeout_or_reply_cap_from_init(tmp_path, monkeypatch):
    for provider in ("openrouter", "openai"):
        result, target = init(monkeypatch, tmp_path, "--provider", provider, "--models", "a/b", "--host", name=f"{provider}.toml")
        assert result.exit_code == 0, result.output
        config = load_config(target)
        assert (config.api.timeout, config.api.max_tokens) == (None, None)
        assert "timeout" not in target.read_text().split("[models]")[0] and "lane calls:" not in result.output


def test_a_custom_server_on_this_machine_gets_them_too(tmp_path, monkeypatch):
    result, target = init(monkeypatch, tmp_path, "--provider", "custom", "--base-url", "http://localhost:8000/v1",
                          "--key-env", "", "--models", "m", "--host")
    assert result.exit_code == 0, result.output
    assert (load_config(target).api.timeout, load_config(target).api.max_tokens) == (600.0, 8192)


# ---------------------------------------------------------------------- the light model


def test_at_a_terminal_a_light_model_on_ollama_is_offered_with_thinking_off(tmp_path, monkeypatch):
    result, target = init(monkeypatch, tmp_path, "--provider", "openrouter", "--models", "a/b", "--host",
                          "--light", "ollama", terminal=True, answers="\n")
    assert result.exit_code == 0, result.output
    assert load_config(target).light == LightConfig("openai", "qwen3.5:9b", "http://127.0.0.1:11434/v1", "", thinking=False)
    assert ("Suggested light model: qwen3.5:9b, with thinking off it scored 42 of 44 in eval-local against the rules' "
            "38, in a benchmark on one machine.") in result.output
    written = target.read_text()
    assert "\nthinking = false\n" in written
    assert "Thinking off: each request asks the model to answer without reasoning first." in one_line(written)
    assert "light model: qwen3.5:9b on this machine, thinking off (asked for with each request)" in result.output


def test_a_light_model_on_mlx_is_offered_and_init_says_how_to_serve_it(tmp_path, monkeypatch):
    result, target = init(monkeypatch, tmp_path, "--provider", "openrouter", "--models", "a/b", "--host",
                          "--light", "mlx", terminal=True, answers="\n")
    assert result.exit_code == 0, result.output
    light = load_config(target).light
    assert (light.model, light.base_url, light.thinking) == (QWEN_MLX, "http://127.0.0.1:8080/v1", False)
    assert (f"next: serve the light model: mlx_lm.server --model {QWEN_MLX}   (flightdeck asks for thinking off with each "
            "request, so it needs no flag for that)") in result.output
    shared, _ = init(monkeypatch, tmp_path, "--provider", "mlx", "--models", QWEN_MLX, "--host", "--light", "mlx",
                     "--light-model", QWEN_MLX, name="shared.toml")
    assert shared.exit_code == 0, shared.output
    assert shared.output.count("mlx_lm.server") == 1  # the lanes' server serves the light model too
    other, _ = init(monkeypatch, tmp_path, "--provider", "mlx", "--models", QWEN_MLX, "--host", "--light", "mlx",
                    "--light-model", "mlx-community/gemma-4-12B-it-4bit", name="other.toml")
    assert "note: lanes and the light model share the MLX server at 127.0.0.1:8080, which holds one model at a time" in other.output


def test_away_from_a_terminal_a_local_light_model_must_be_named_and_is_written_with_thinking_off(tmp_path, monkeypatch):
    result, target = init(monkeypatch, tmp_path, "--provider", "openrouter", "--models", "a/b", "--host", "--light", "ollama")
    assert result.exit_code == 2 and not target.exists()
    assert "--light ollama needs --light-model" in result.output
    assert "suggested: --light-model qwen3.5:9b: with thinking off it scored 42 of 44" in result.output
    result, target = init(monkeypatch, tmp_path, "--provider", "openrouter", "--models", "a/b", "--host", "--light", "ollama",
                          "--light-model", "gemma4:12b")
    assert result.exit_code == 0, result.output
    assert load_config(target).light.thinking is False


# ---------------------------------------------------------------------- doctor


def checks(tmp_path, answers: Answers, name: str = "c.toml") -> dict:
    return {c.name: c for c in doctor(write_config(answers, tmp_path / name), environ={})}


def test_doctor_says_what_lane_calls_to_a_server_on_this_machine_use(tmp_path):
    written = checks(tmp_path, Answers(NOTHING_HERE, "", ("m",), "host", timeout=600, max_tokens=8192))["lane calls"]
    assert written.ok and written.detail == (
        f"to {NOTHING_HERE}: replies of up to 8192 tokens (max_tokens, [api] max_tokens), 600 s per try ([api] timeout)")
    default = checks(tmp_path, Answers(NOTHING_HERE, "", ("m",), "host"), name="d.toml")["lane calls"]
    assert default.detail == (
        f"to {NOTHING_HERE}: replies of up to 8192 tokens (max_tokens, the default for a server on this machine), 180 s per "
        "try (the default; a model on this machine can take longer for one reply: timeout = 600 under [api] gives it 10 "
        "minutes, as init writes)")
    text, _ = report([default])
    assert text.startswith("ok   lane calls: to http://127.0.0.1:9/v1: replies of up to 8192 tokens")


def test_doctor_says_nothing_of_the_kind_for_an_api_elsewhere(tmp_path):
    found = checks(tmp_path, Answers("https://openrouter.ai/api/v1", "", ("m",), "host", max_tokens=4096))
    assert "lane calls" not in found


def test_doctor_says_it_for_a_fallback_on_this_machine_too(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text('[api]\nbase_url = "https://openrouter.ai/api/v1"\nkey_env = ""\n[models]\nladder = ["m"]\n'
                    f'[fallback]\nbase_url = "{NOTHING_HERE}"\nkey_env = ""\nladder = ["x"]\ntimeout = 300\n'
                    '[lanes]\nruntime = "host"\n')
    found = {c.name: c for c in doctor(path, environ={})}
    assert "lane calls" not in found
    assert found["fallback calls"].detail == (
        f"to {NOTHING_HERE}: replies of up to 8192 tokens (max_tokens, the default for a server on this machine), 300 s per "
        "try ([fallback] timeout)")


def test_doctor_says_whether_the_light_model_is_asked_for_thinking_off(tmp_path):
    off = checks(tmp_path, Answers(NOTHING_HERE, "", ("m",), "host", light=LightAnswers("openai", "qwen", NOTHING_HERE, "")))
    assert f"openai qwen at {NOTHING_HERE}, thinking off (asked for with each request); measure it" in off["light model"].detail
    on = checks(tmp_path, Answers(NOTHING_HERE, "", ("m",), "host",
                                  light=LightAnswers("openai", "qwen", NOTHING_HERE, "", thinking=True)), name="on.toml")
    assert f"openai qwen at {NOTHING_HERE}, thinking on; measure it" in on["light model"].detail
