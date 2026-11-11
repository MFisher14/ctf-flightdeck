"""`flightdeck models`, run as a player runs it, on fake machines.

hardware.RealHost is swapped for a FakeHost, so the command probes a scripted machine through
its own code path (hardware.probe with its default servers) and nothing on this machine is
run or asked: the FakeHost answers every command and URL itself, and records them.
"""

from __future__ import annotations

import json
import os
from urllib.parse import urlsplit

import pytest
from fake_host import GIB, FakeHost, apple_mac, linux_box
from typer.testing import CliRunner

from ctf_flightdeck import cli, hardware, model_catalog
from ctf_flightdeck.config import parse_config
from ctf_flightdeck.hardware import OLLAMA, SERVERS

runner = CliRunner()


def tags(*models: tuple[str, int]) -> bytes:
    return json.dumps({"models": [{"name": name, "size": size} for name, size in models]}).encode()


def on(monkeypatch, host: FakeHost) -> FakeHost:
    """`flightdeck models` probes `host` as if it were this machine."""
    monkeypatch.setattr(hardware, "RealHost", lambda environ=os.environ: host)
    return host


def models(*args: str):
    result = runner.invoke(cli.app, ["models", *args], terminal_width=400)
    return result


def section(out: str, title: str) -> str:
    """The block of `out` that starts with the line starting with `title`, up to a blank line."""
    lines = out.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(title))
    end = next((i for i in range(start, len(lines)) if not lines[i].strip()), len(lines))
    return "\n".join(lines[start:end])


def mac_with_ollama(memory: int = 36 * GIB) -> FakeHost:
    return apple_mac(memory=memory, programs={"ollama": "/opt/homebrew/bin/ollama"},
                     http={SERVERS[OLLAMA]: (200, tags(("qwen3.5:9b", 6550825550), ("gpt-oss:20b", 13793441244)))})


# ---------------------------------------------------------------------- the overview, on four machines


def test_on_an_apple_silicon_mac_local_models_that_fit_come_first(monkeypatch):
    host = on(monkeypatch, mac_with_ollama())
    result = models()
    assert result.exit_code == 0, result.output
    out = result.output
    machine = section(out, "This machine")
    assert "macOS on arm64: Apple M4 Max (Apple Silicon)" in machine and "36 GiB, unified" in machine
    assert "ollama at /opt/homebrew/bin/ollama; its server at 127.0.0.1:11434 has pulled 2 models: qwen3.5:9b, gpt-oss:20b" in machine
    assert "nothing is listening at 127.0.0.1:8080" in machine
    assert "Local models may use about 24 GiB here: two thirds of the 36 GiB of unified memory" in out
    assert "An estimate" in out
    lanes = section(out, "Lanes:")
    assert "First: an open-weight model on this machine" in lanes
    assert lanes.index("Fit here:") < lanes.index("Model APIs:")
    assert ("qwen3.5-9b on Ollama (qwen3.5:9b, pulled here): needs about 12.1 GiB (6.1 GiB of weights + 6 GiB for the "
            "context) of the 24 GiB here; fits by size only: not measured for a lane yet") in lanes
    assert "gpt-oss-20b on Ollama (gpt-oss:20b, pulled here): needs about 18.8 GiB" in lanes  # its size from Ollama here
    assert "gemma4-12b on Ollama (gemma4:12b): its size on disk is not recorded in the catalog" in section(lanes, "  Cannot tell:")
    assert "Not for a lane: phi4-mini (the catalog lists it for the light role only)" in lanes
    light = section(out, "Light role:")
    assert "phi4-mini on MLX (mlx-community/Phi-4-mini-instruct-4bit): needs about 4 GiB" in light
    assert "docs/MODELS.md" in out and out.rstrip().endswith("This only recommends: it never changes your config.")
    assert host.fetched == list(SERVERS.values()) and {urlsplit(u).hostname for u in host.fetched} == {"127.0.0.1"}


def test_on_a_linux_box_with_an_nvidia_gpu_its_memory_is_the_budget(monkeypatch):
    on(monkeypatch, linux_box(128 * 1024 * 1024, nvidia="NVIDIA GeForce RTX 4090, 24564\n"))
    out = models().output
    assert "NVIDIA GPU  NVIDIA GeForce RTX 4090, 24 GiB" in out
    assert "Local models may use about 24 GiB here: the memory of the NVIDIA GeForce RTX 4090." in out
    lanes = section(out, "Lanes:")
    assert "First: an open-weight model on this machine" in lanes and "qwen3.5-9b on Ollama (qwen3.5:9b): needs about 12.1 GiB" in lanes
    assert "Not for this machine: qwen3.5-9b on MLX, gpt-oss-20b on MLX, gemma4-12b on MLX (MLX runs on Apple Silicon only)" in lanes


def test_on_a_cpu_only_box_lanes_lead_with_an_api_and_the_light_role_with_the_rules(monkeypatch):
    on(monkeypatch, linux_box(16 * 1024 * 1024))
    out = models().output
    assert "local models run on the CPU and will be slow" in out
    lanes = section(out, "Lanes:")
    assert "First: a model API. Local models would run on the CPU here, and slowly." in lanes
    assert "Fit here" not in lanes  # 8 GiB: no lane fits
    assert "qwen3.5-9b on Ollama (qwen3.5:9b): needs about 12.1 GiB" in section(lanes, "  Do not fit here:")
    light = section(out, "Light role:")
    assert "First: the rules (the default, no model), or a small model that fits." in light
    assert light.index("rules: the default; no model, no cost") < light.index("Fit here, on the CPU (slow):")
    assert light.index("Fit here, on the CPU (slow):") < light.index("Model APIs:")
    assert "phi4-mini on Ollama (phi4-mini): needs about 4.3 GiB" in light


def test_on_a_big_cpu_only_box_local_lane_models_follow_the_apis_smallest_first(monkeypatch):
    on(monkeypatch, linux_box(64 * 1024 * 1024))
    lanes = section(models().output, "Lanes:")
    assert lanes.index("Model APIs:") < lanes.index("Fit here, on the CPU (slow):")


def test_on_wsl_it_is_linux_with_the_virtual_machines_memory(monkeypatch):
    on(monkeypatch, linux_box(32 * 1024 * 1024, osrelease="5.15.153.1-microsoft-standard-WSL2\n",
                              nvidia="NVIDIA GeForce RTX 3060, 12288\n", nvidia_path="/usr/lib/wsl/lib/nvidia-smi"))
    out = models().output
    assert "system      Linux (WSL) on x86_64" in out and "32 GiB, what WSL's virtual machine has (.wslconfig sets it)" in out
    assert "the memory of the NVIDIA GeForce RTX 3060" in out


def test_a_machine_it_cannot_read_gets_cannot_tell_and_the_reason(monkeypatch):
    on(monkeypatch, apple_mac(commands={("/usr/sbin/sysctl", "-n", "hw.memsize"): "garbage\n"}))
    out = models().output
    assert "memory      unknown: sysctl hw.memsize printed something that is not a number of bytes" in out
    assert "Local models: flightdeck cannot tell what fits here: this Mac's memory is unknown" in out
    assert "Fit here" not in out and "First: a model API. flightdeck cannot tell what fits this machine." in out


# ---------------------------------------------------------------------- --json


def test_json_gives_scripts_the_same_advice(monkeypatch):
    on(monkeypatch, mac_with_ollama())
    text = models().output
    result = models("--json")
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["changes_config"] is False and data["measured_results"] == "docs/MODELS.md"
    assert data["machine"]["chip"]["value"] == "Apple M4 Max" and data["machine"]["memory_bytes"]["value"] == 36 * GIB
    assert data["local_models"] == {"where": "apple silicon", "memory_bytes": 24 * GIB, "why": data["local_models"]["why"]}
    assert data["memory_rule"]["estimate"] is True
    assert data["memory_rule"]["context_allowance_bytes"] == {"lanes": 6 * GIB, "light": 2 * GIB}
    lanes = data["roles"]["lanes"]
    assert lanes["lead"] == "local" and [a["id"] for a in lanes["api"]] == ["anthropic", "openrouter"]
    assert [(o["id"], o["runtime"], o["basis"]) for o in lanes["fits"]] == [
        ("qwen3.5-9b", "ollama", "size only"), ("qwen3.5-9b", "mlx", "size only"), ("gpt-oss-20b", "ollama", "size only")]
    assert lanes["fits"][2]["sized_by"] == "server" and lanes["fits"][0]["sized_by"] == "catalog"
    assert [o["basis"] for o in lanes["cannot_tell"]] == [None, None, None]
    for role, title in (("lanes", "Lanes:"), ("light", "Light role:")):  # the text says the same
        block = section(text, title)
        for option in data["roles"][role]["fits"]:
            assert f"{option['id']} on {hardware.RUNTIME_NAMES[option['runtime']]} ({option['model']}" in section(block, "  Fit here")
    assert data["roles"]["light"]["default"] == "rules"


# ---------------------------------------------------------------------- one model: how to get it, and its config lines


def test_one_model_gives_the_commands_and_the_exact_config_lines(monkeypatch, tmp_path):
    on(monkeypatch, apple_mac(programs={"ollama": "/opt/homebrew/bin/ollama"}))
    result = models("qwen3.5-9b")
    assert result.exit_code == 0, result.output
    out = result.output
    assert out.startswith("Qwen3.5 9B (qwen3.5-9b): Qwen3.5, 9.0B parameters, Apache-2.0. For lanes and the light role.")
    assert "Measured: not yet (docs/MODELS.md has the results)." in out
    ollama, mlx = section(out, "On Ollama:"), out[out.index("On MLX:"):]
    assert "here, for lanes: fits: needs about 12.1 GiB" in ollama
    assert "    ollama pull qwen3.5:9b" in ollama
    assert "uv tool install mlx-lm" in mlx  # mlx_lm is not installed on this fake Mac
    assert "    mlx_lm.server --model mlx-community/Qwen3.5-9B-MLX-4bit --host 127.0.0.1 --port 8080" in mlx
    assert "lanes: in your config, these replace its [api], [models] and [prices] tables" in out
    assert ('    [light]\n    engine = "openai"\n    model = "qwen3.5:9b"\n    base_url = "http://127.0.0.1:11434/v1"\n'
            '    key_env = ""') in out
    assert "measure it first: flightdeck eval-local --engine openai --base-url http://127.0.0.1:11434/v1 --model qwen3.5:9b" in out
    data = json.loads(models("qwen3.5-9b", "--json").output)
    assert data["changes_config"] is False
    by_runtime = {b["runtime"]: b for b in data["builds"]}
    assert by_runtime["ollama"]["get"] == ["ollama pull qwen3.5:9b"]
    assert by_runtime["mlx"]["get"][-1] == "mlx_lm.server --model mlx-community/Qwen3.5-9B-MLX-4bit --host 127.0.0.1 --port 8080"
    lanes = by_runtime["mlx"]["roles"]["lanes"]
    config = parse_config(lanes["config"] + '\n[lanes]\nruntime = "host"\n', tmp_path / "c.toml")
    assert (config.api.base_url, config.models) == ("http://127.0.0.1:8080/v1", ("mlx-community/Qwen3.5-9B-MLX-4bit",))
    light = by_runtime["ollama"]["roles"]["light"]
    assert parse_config('[models]\nladder = ["m"]\n' + light["config"], tmp_path / "c.toml").light.model == "qwen3.5:9b"
    assert light["verdict"] == "fits" and light["estimate"] is True


def test_an_api_entry_gives_its_config_lines_without_probing_the_machine(monkeypatch):
    host = on(monkeypatch, apple_mac())
    out = models("anthropic").output
    assert 'provider = "anthropic"' in out and '[prices."claude-opus-5-5"]' in out
    assert "measure it first: flightdeck eval-local --engine anthropic --model claude-haiku-5-5" in out
    assert "can decline security work" in out
    assert host.ran == [] and host.fetched == []
    openrouter = json.loads(models("openrouter", "--json").output)
    assert openrouter["ladder"] == [] and openrouter["models_page"] == "https://openrouter.ai/models"
    assert "VENDOR/SMALL-MODEL" in openrouter["use"]["lanes"]["config"]


def test_an_unknown_model_is_named_with_the_choices(monkeypatch):
    on(monkeypatch, apple_mac())
    result = models("llama-9000")
    assert result.exit_code == 2
    assert "no model 'llama-9000' in the catalog; it has qwen3.5-9b, gpt-oss-20b, gemma4-12b, phi4-mini, anthropic, openrouter" in result.output


def test_a_measured_model_says_so_and_names_where_the_results_are(monkeypatch, tmp_path):
    shipped = (model_catalog.files("ctf_flightdeck") / "models.toml").read_text(encoding="utf-8")
    assert shipped.index('id = "qwen3.5-9b"') < shipped.index("measured = {}") < shipped.index('id = "gpt-oss-20b"')
    measured = shipped.replace("measured = {}", 'measured = { light = "29/30 hints, 1.2 s a job" }', 1)  # Qwen3.5 9B's
    (tmp_path / "models.toml").write_text(measured, encoding="utf-8")
    monkeypatch.setattr(model_catalog, "files", lambda package: tmp_path)
    on(monkeypatch, apple_mac())
    out = models().output
    light = section(out, "Light role:")
    assert ("qwen3.5-9b on Ollama (qwen3.5:9b): needs about 8.1 GiB (6.1 GiB of weights + 2 GiB for the context) of the "
            "24 GiB here; measured: 29/30 hints, 1.2 s a job (docs/MODELS.md)") in light
    fits = section(light, "  Fit here:").splitlines()[1:]
    assert [line.split(" on ")[0].strip() for line in fits][:2] == ["qwen3.5-9b", "qwen3.5-9b"]  # measured first
    assert "fits by size only: not measured for a lane yet" in section(out, "Lanes:")


# ---------------------------------------------------------------------- what it never does


def test_it_never_writes_or_changes_a_config(monkeypatch, tmp_path):
    config = tmp_path / "config.toml"
    config.write_text('[models]\nladder = ["mine"]\n', encoding="utf-8")
    before = (config.read_bytes(), config.stat().st_mtime_ns)
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(config))
    work = tmp_path / "here"
    work.mkdir()
    monkeypatch.chdir(work)
    on(monkeypatch, mac_with_ollama())
    for args in ((), ("--json",), ("qwen3.5-9b",), ("phi4-mini", "--json"), ("anthropic",)):
        assert models(*args).exit_code == 0
    assert (config.read_bytes(), config.stat().st_mtime_ns) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["config.toml", "here"] and list(work.iterdir()) == []


def test_names_a_server_lists_are_shown_folded(monkeypatch):
    evil = "evil\x1b]0;owned\x07\x1b[2Jmodel"
    on(monkeypatch, apple_mac(programs={"ollama": "/opt/homebrew/bin/ollama"},
                              http={SERVERS[OLLAMA]: (200, tags((evil, 5 * GIB)))}))
    out = models().output
    assert "\x1b" not in out and "\x07" not in out and "evil" in out
    assert json.loads(models("--json").output)["machine"]["runtimes"][0]["server"]["models"] == [evil]


def test_a_broken_catalog_stops_the_command_and_says_what_is_wrong(monkeypatch, tmp_path):
    (tmp_path / "models.toml").write_text('[[local]]\nid = "x"\ncolour = "red"\n', encoding="utf-8")
    monkeypatch.setattr(model_catalog, "files", lambda package: tmp_path)
    host = on(monkeypatch, apple_mac())
    result = models()
    assert result.exit_code == 2
    assert "flightdeck: ctf_flightdeck/models.toml: [[local]] entry 1 (x): unknown key colour" in result.output
    assert host.ran == [] and host.fetched == []  # nothing probed for a catalog that cannot be used


def test_models_is_a_set_up_command():
    out = runner.invoke(cli.app, ["--help"], terminal_width=200).output
    panel = out[out.index("Set up"):]
    panel = panel[: panel.index("╰")]
    assert " models " in panel
    help_text = " ".join(runner.invoke(cli.app, ["models", "--help"], terminal_width=200).output.split())
    assert "Usage: flightdeck models [OPTIONS] [ID]" in help_text
    assert "--json" in help_text and "never changes your config" in help_text


@pytest.mark.parametrize("ident", ["qwen3.5-9b", "gpt-oss-20b", "gemma4-12b", "phi4-mini", "anthropic", "openrouter"])
def test_every_entry_can_be_shown_in_text_and_json(ident, monkeypatch):
    on(monkeypatch, linux_box(16 * 1024 * 1024))
    text, data = models(ident), models(ident, "--json")
    assert text.exit_code == 0 and data.exit_code == 0, text.output + data.output
    assert json.loads(data.output)["id"] == ident
