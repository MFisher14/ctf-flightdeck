"""`init --light decider` writes the decider's table and says how to start its server; `doctor`
checks the server's GET /health (the fake decider server, fake_decider.py), never as essential.
"""

from __future__ import annotations

import socket

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli
from ctf_flightdeck import light as L
from ctf_flightdeck.config import LightConfig, load_config
from ctf_flightdeck.setup import Answers, LightAnswers, doctor, report, write_config
from fake_decider import MODEL, FakeDeciderServer, Reply, health_body

runner = CliRunner()


def closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def init(tmp_path, monkeypatch, *args: str):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    target = tmp_path / "config.toml"
    result = runner.invoke(cli.app, ["init", "--provider", "openrouter", "--models", "a/one", "--host", "--path",
                                     str(target), *args])
    return result, target


def test_init_writes_a_decider_and_says_how_to_start_its_server(tmp_path, monkeypatch):
    result, target = init(tmp_path, monkeypatch, "--light", "decider")
    assert result.exit_code == 0, result.output
    assert load_config(target).light == LightConfig("decider", "", "http://127.0.0.1:8000", "", 30.0, None, 0.9)
    for words in ("pip install strands-decider",
                  "strands-decider serve StrandsAgents/strands-decider-2B-qwen3.5-v1-2610 --port 8000",
                  "--device mlx", 'pip install -e ".[mlx]"',
                  "flightdeck eval-local --engine decider --base-url http://127.0.0.1:8000"):
        assert words in result.output, words
    assert "threshold = 0.9" in target.read_text() and "key_env" not in target.read_text().split("[light]")[1].split("[")[0]
    result, target = init(tmp_path, monkeypatch, "--light", "decider", "--light-model", MODEL, "--force")
    assert result.exit_code == 0, result.output
    assert load_config(target).light.model == MODEL and f"serving {MODEL}" in result.output


def checks(tmp_path, light: LightAnswers) -> dict:
    path = write_config(Answers("http://127.0.0.1:9/v1", "", ("m",), "host", light=light), tmp_path / "c.toml", force=True)
    return {c.name: c for c in doctor(path, environ={})}


def test_doctor_checks_the_decider_server_and_never_fails_the_setup_on_it(tmp_path):
    with FakeDeciderServer() as server:
        found = checks(tmp_path, LightAnswers("decider", MODEL, server.base_url))
        assert server.requests and server.requests[-1]["path"] == "/health"
    assert found["light server"].ok and not found["light server"].essential
    assert found["light server"].detail == f"{server.base_url} serves {MODEL} (window 4096 tokens)"
    model = found["light model"]
    assert model.ok and not model.essential and "Strands Decider (a decision model)" in model.detail
    assert f"flightdeck eval-local --engine decider --base-url {server.base_url} --model {MODEL}" in model.detail
    assert "light key" not in found  # no key


@pytest.mark.parametrize("health, says, fix", [
    (Reply(404, {"detail": "Not Found"}), "answered /health with HTTP 404, not as a Strands Decider server does",
     "the address `strands-decider serve` listens on"),
    (health_body("strands-decider-E4B-gemma4-v1-2610"), f"serves strands-decider-E4B-gemma4-v1-2610, not {MODEL}",
     f"serve {MODEL} there, or set [light] model in"),
    (health_body(max_length=3072), "has a window of 3072 tokens; flightdeck sizes its requests for 4096",
     "serve a published Strands Decider model"),
])
def test_doctor_warns_about_a_decider_server_it_cannot_use(tmp_path, health, says, fix):
    with FakeDeciderServer(health=health) as server:
        found = checks(tmp_path, LightAnswers("decider", MODEL, server.base_url))
    check = found["light server"]
    assert not check.ok and not check.essential and says in check.detail and fix in check.fix
    text, status = report(list(found.values()))
    assert "warn light server" in text


def test_doctor_says_how_to_start_a_decider_that_is_not_running(tmp_path):
    url = f"http://127.0.0.1:{closed_port()}"
    check = checks(tmp_path, LightAnswers("decider", "", url))["light server"]
    assert not check.ok and not check.essential and f"nothing answers at {url}" in check.detail
    assert "strands-decider serve StrandsAgents/strands-decider-2B-qwen3.5-v1-2610 --port 8000" in check.fix


def test_doctor_says_where_a_deciders_requests_go_when_it_is_not_on_this_machine(tmp_path, monkeypatch):
    monkeypatch.setattr(L, "on_this_machine", lambda url: False)  # as if the fake server were another host
    with FakeDeciderServer() as server:
        model = checks(tmp_path, LightAnswers("decider", "", server.base_url))["light model"]
    assert "its requests (challenge descriptions and lane steps) go to 127.0.0.1, not this machine" in model.detail
