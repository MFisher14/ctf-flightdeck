"""`flightdeck models`, run as a player runs it, on fake machines.

hardware.RealHost is swapped for a FakeHost, so the command probes a scripted machine through
its own code path (hardware.probe with its default servers) and nothing on this machine is
run or asked: the FakeHost answers every command and URL itself, and records them.
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import urlsplit

import pytest
from fake_host import GIB, FakeHost, apple_mac, linux_box
from typer.testing import CliRunner

from ctf_flightdeck import cli, hardware, model_catalog
from ctf_flightdeck.config import parse_config
from ctf_flightdeck.hardware import OLLAMA, SERVERS

runner = CliRunner()


@pytest.fixture(autouse=True)
def no_real_machine(monkeypatch):
    """A test that runs the command without saying which machine it is on fails, rather than
    probing this one (and asking its own Ollama or MLX server)."""

    def unsaid(environ=os.environ):
        raise AssertionError("this test did not say which machine `flightdeck models` runs on: call on()")

    monkeypatch.setattr(hardware, "RealHost", unsaid)


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


def group(block: str, title: str) -> str:
    """The lines under the line `title` in a role's block (each indented four spaces), without the title."""
    lines = block.splitlines()
    start = lines.index(title)
    end = next((i for i in range(start + 1, len(lines)) if not lines[i].startswith("    ")), len(lines))
    return "\n".join(lines[start + 1:end])


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
            "context) of the 24 GiB here; measured: solved 1 of 4 practice challenges as served; tool calls 4/5") in lanes
    assert "gpt-oss-20b on Ollama (gpt-oss:20b, pulled here): needs about 18.8 GiB" in lanes
    assert "Cannot tell" not in out and "fits by size only" not in out  # the catalog has every build's size and result
    assert group(lanes, "  Not for a lane:").splitlines() == [
        "    gpt-oss-20b on MLX: mlx_lm.server passed its tool calls on as text, in gpt-oss's own channel format, so a lane "
        "gets none: tool calls 0/5",
        "    gemma4-12b on Ollama: solved 0 of 4 practice challenges as served, in two runs: each stalled at its third model "
        "call, with no reply within flightdeck's 180 s per try; tool calls 5/5",
        "    gemma4-12b on MLX: solved 0 of 4 practice challenges served as it comes, and 0 of 4 with thinking off and "
        "--max-tokens 8192 (its second reply then took about 181 s, past flightdeck's 180 s per try); tool calls 5/5",
        "    phi4-mini on Ollama: it wrote its tool calls as text, so a lane gets none: tool calls 0/5",
        "    phi4-mini on MLX: mlx_lm.server gives its chat template no tools, so it makes no tool call: tool calls 0/5"]
    light = section(out, "Light role:")
    assert fit_names(light) == ["qwen3.5-9b on MLX", "gpt-oss-20b on Ollama", "gemma4-12b on MLX"]  # 41, 38, 41 of 44
    assert "    phi4-mini on MLX: eval-local 18/44 served as it comes, below the rules' 38/44" in light
    assert "docs/MODELS.md" in out and out.rstrip().endswith("This only recommends: it never changes your config.")
    assert host.fetched == list(SERVERS.values()) and {urlsplit(u).hostname for u in host.fetched} == {"127.0.0.1"}


def test_on_the_36_gb_mac_the_benchmark_ran_on_each_result_shows_under_its_role_beside_its_build(monkeypatch):
    """Every build fits there by size, so each one shows each result: a measured one beside the
    build's fit, a not-for one under its role, and `flightdeck models ID` gives them with the sizes."""
    on(monkeypatch, apple_mac(memory=36 * GIB))
    out = models().output
    assert "Cannot tell" not in out and "not recorded" not in out and "fits by size only" not in out
    shown = 0
    for role, title, others in (("lanes", "Lanes:", "  Not for a lane:"), ("light", "Light role:", "  Not for the light role:")):
        block = section(out, title)
        fits, refused = group(block, "  Fit here:").splitlines(), group(block, others).splitlines()
        for model in model_catalog.load_catalog().local:
            for build in model.builds:
                name = f"{model.id} on {hardware.RUNTIME_NAMES[build.runtime]}"
                if role in build.measured:
                    (line,) = [line for line in fits if line.startswith(f"    {name} (")]
                    assert line.endswith(f"of the 24 GiB here; measured: {build.measured[role]} (docs/MODELS.md)"), line
                    shown += 1
                elif role in build.not_for:
                    assert f"    {name}: {build.not_for[role]}" in refused
                    assert not [line for line in fits if line.startswith(f"    {name} (")]
                    shown += 1
    assert shown == 16  # 6 results and 10 reasons not to, in the catalog
    entry = models("gemma4-12b").output
    assert entry.splitlines()[1] == ("Measured: on MLX, for the light role: eval-local 41/44 with thinking off, against the "
                                     "rules' 38/44 (docs/MODELS.md).")
    ollama, mlx = section(entry, "On Ollama:"), section(entry, "On MLX:")
    assert ollama.startswith("On Ollama: gemma4:12b, Q4_K_M, 7.5 GiB on disk\n  not for lanes: solved 0 of 4 practice challenges")
    assert "  not for the light role: Ollama runs it with thinking on" in ollama and "eval-local 17/44" in ollama
    assert mlx.startswith("On MLX: mlx-community/gemma-4-12B-it-4bit, 4-bit, group size 64, affine, 6.3 GiB on disk\n"
                          "  not for lanes: solved 0 of 4 practice challenges served as it comes")
    assert "  here, for the light role: fits: needs about 8.3 GiB" in mlx and "here, for lanes" not in mlx


QWEN_MLX_SERVER = ("mlx_lm.server --model mlx-community/Qwen3.5-9B-MLX-4bit --host 127.0.0.1 --port 8080 "
                   "--chat-template-args '{\"enable_thinking\":false}' --max-tokens 8192")
THINKING_ON_OLLAMA = ("Ollama runs it with thinking on, which flightdeck's requests do not turn off: so served, eval-local "
                      "2/44 against the rules' 38/44, with no answer in 56 of 58 replies; 42/44 with reasoning_effort none, "
                      "which flightdeck does not send")  # Qwen3.5 9B's


def test_a_thinking_model_is_served_with_thinking_off_and_never_offered_where_flightdeck_cannot_turn_it_off(monkeypatch):
    """Qwen3.5 9B served as it comes thinks first: no answer to the light role's jobs. mlx_lm.server
    can turn that off; nothing flightdeck sends to Ollama can."""
    on(monkeypatch, apple_mac(programs={"ollama": "/opt/homebrew/bin/ollama", "mlx_lm.server": "/opt/bin/mlx_lm.server"}))
    out = models("qwen3.5-9b").output
    ollama, mlx = section(out, "On Ollama:"), out[out.index("On MLX:"):]
    assert ("  get it:\n    " + QWEN_MLX_SERVER + "\n    # keep the arguments after --port 8080: the benchmark behind "
            "docs/MODELS.md served it with them\n") in mlx
    assert f"  not for the light role: {THINKING_ON_OLLAMA}" in ollama
    assert "here, for lanes: fits" in ollama and "the light role: in your config" not in ollama
    assert 'model = "qwen3.5:9b"' not in out and "--light ollama" not in out  # no [light] lines for the Ollama build
    assert "the light role: in your config, these replace its [light] table" in mlx
    overview = models().output
    light = section(overview, "Light role:")
    assert "qwen3.5-9b on MLX" in group(light, "  Fit here:") and "qwen3.5-9b on Ollama" not in group(light, "  Fit here:")
    assert f"    qwen3.5-9b on Ollama: {THINKING_ON_OLLAMA}" in group(light, "  Not for the light role:").splitlines()
    data = json.loads(models("qwen3.5-9b", "--json").output)
    builds = {b["runtime"]: b for b in data["builds"]}
    assert list(builds["ollama"]["roles"]) == ["lanes"] and builds["ollama"]["not_for"] == {"light": THINKING_ON_OLLAMA}
    assert list(builds["mlx"]["roles"]) == ["lanes", "light"]
    assert builds["mlx"]["server_args"] == ["--chat-template-args", '{"enable_thinking":false}', "--max-tokens", "8192"]
    assert builds["mlx"]["get"][0] == QWEN_MLX_SERVER
    not_for = json.loads(models("--json").output)["roles"]["light"]["not_for"]
    assert {"id": "qwen3.5-9b", "runtime": "ollama", "model": "qwen3.5:9b", "why": THINKING_ON_OLLAMA} in not_for


def test_a_build_that_serves_no_role_gets_no_commands_or_config_lines(monkeypatch):
    on(monkeypatch, apple_mac())
    out = models("gpt-oss-20b").output
    mlx = out[out.index("On MLX:"):]
    assert "  not for lanes: mlx_lm.server passed its tool calls on as text" in mlx
    assert "  not for the light role: mlx_lm.server passed every reply on in gpt-oss's own channel format" in mlx
    assert "get it" not in mlx and "mlx_lm.server --model" not in out and "[light]" not in mlx
    data = json.loads(models("gpt-oss-20b", "--json").output)
    mlx_build = next(b for b in data["builds"] if b["runtime"] == "mlx")
    assert (mlx_build["roles"], mlx_build["get"], sorted(mlx_build["not_for"])) == ({}, [], ["lanes", "light"])


PHI_NOT_FOR_LIGHT = {  # Phi-4-mini's light-role results, below the rules' 38/44
    "Ollama": "eval-local 22/44 as served, below the rules' 38/44, flightdeck's default with no model; 15 of 58 replies "
              "held no usable answer",
    "MLX": "eval-local 18/44 served as it comes, below the rules' 38/44, flightdeck's default with no model; 19 of 58 "
           "replies held no usable answer",
}


@pytest.mark.parametrize("host", [
    apple_mac(memory=8 * GIB, chip="Apple M1"),
    linux_box(64 * 1024 * 1024, nvidia="NVIDIA GeForce RTX 4070, 12282\n"),
], ids=["8-gb-m1", "12-gb-rtx-4070"])
def test_where_only_a_model_that_scored_below_the_rules_would_fit_the_light_role_leads_with_the_rules(host, monkeypatch):
    """Phi-4-mini fits these machines by size, but scored 22/44 (Ollama) and 18/44 (MLX) on the
    light role's jobs, against the rules' 38/44: the rules come first, no model is offered as a
    fit, and Phi-4-mini is listed as not for the light role, with its score."""
    on(monkeypatch, host)
    out = models().output
    light = section(out, "Light role:")
    assert light.splitlines()[1:3] == [
        "  First: the rules (the default, no model), or a small model that fits. No model the catalog offers for the light "
        "role is known to fit this machine.",
        "    rules: the default; no model, no cost"]
    assert "Fit here" not in light
    assert [line for line in group(light, "  Not for the light role:").splitlines() if line.startswith("    phi4-mini")] == [
        f"    phi4-mini on {runtime}: {why}" for runtime, why in PHI_NOT_FOR_LIGHT.items()]
    assert "for example: flightdeck models phi4-mini" not in out
    data = json.loads(models("--json").output)["roles"]["light"]
    assert (data["lead"], data["fits"]) == ("rules", [])
    assert [(n["id"], n["runtime"]) for n in data["not_for"] if n["id"] == "phi4-mini"] == [
        ("phi4-mini", "ollama"), ("phi4-mini", "mlx")]


def test_a_model_that_measured_badly_for_every_role_is_offered_for_none_and_says_why(monkeypatch):
    on(monkeypatch, apple_mac(programs={"ollama": "/opt/homebrew/bin/ollama", "mlx_lm.server": "/opt/bin/mlx_lm.server"}))
    out = models("phi4-mini").output
    assert out.splitlines()[:2] == [
        "Phi-4-mini (phi4-mini): Phi-4, 3.8B parameters, MIT. Not offered for any role.",
        "Measured: each runtime below says what it is not for, and why (docs/MODELS.md)."]  # never "not yet"
    assert section(out, "On Ollama:").splitlines()[1:] == [
        "  not for lanes: it wrote its tool calls as text, so a lane gets none: tool calls 0/5",
        f"  not for the light role: {PHI_NOT_FOR_LIGHT['Ollama']}"]
    assert section(out, "On MLX:").splitlines()[1:] == [
        "  not for lanes: mlx_lm.server gives its chat template no tools, so it makes no tool call: tool calls 0/5",
        f"  not for the light role: {PHI_NOT_FOR_LIGHT['MLX']}"]
    for offer in ("get it", "[light]", "[api]", "measure it first", "try it", "flightdeck init"):  # nothing to use it with
        assert offer not in out
    data = json.loads(models("phi4-mini", "--json").output)
    assert data["roles"] == []
    assert [(b["runtime"], b["roles"], b["get"]) for b in data["builds"]] == [("ollama", {}, []), ("mlx", {}, [])]


def test_a_model_is_said_to_be_for_the_roles_a_build_of_it_serves(monkeypatch):
    """Gemma 4 12B is not for lanes on either runtime: its entry and its JSON say it is for the
    light role only, and each runtime says why it is not for lanes."""
    on(monkeypatch, apple_mac())
    out = models("gemma4-12b").output
    assert out.splitlines()[0] == "Gemma 4 12B (gemma4-12b): Gemma 4, 11.9B parameters, Apache-2.0. For the light role."
    assert out.count("\n  not for lanes: solved 0 of 4 practice challenges") == 2
    data = json.loads(models("gemma4-12b", "--json").output)
    assert data["roles"] == ["light"] and [list(b["roles"]) for b in data["builds"]] == [[], ["light"]]
    assert json.loads(models("qwen3.5-9b", "--json").output)["roles"] == ["lanes", "light"]


def test_a_model_listed_for_one_role_only_and_one_with_no_results_say_so(monkeypatch, tmp_path):
    (tmp_path / "models.toml").write_text(
        '[[local]]\nid = "small"\nname = "Small"\nfamily = "Test"\nparameters = "1B"\nlicense = "MIT"\nroles = ["light"]\n\n'
        f'[local.ollama]\nmodel = "small:q4"\nsize_bytes = {GIB}\n', encoding="utf-8")
    monkeypatch.setattr(model_catalog, "files", lambda package: tmp_path)
    on(monkeypatch, apple_mac())
    lanes = section(models().output, "Lanes:")
    assert group(lanes, "  Not for a lane:").splitlines() == ["    small: the catalog lists it for the light role only"]
    assert json.loads(models("--json").output)["roles"]["lanes"]["not_for"] == [
        {"id": "small", "runtime": None, "model": None, "why": "the catalog lists it for the light role only"}]
    assert models("small").output.splitlines()[:2] == [
        "Small (small): Test, 1B parameters, MIT. For the light role.", "Measured: not yet (docs/MODELS.md has the results)."]


def test_on_a_linux_box_with_an_nvidia_gpu_its_memory_is_the_budget(monkeypatch):
    on(monkeypatch, linux_box(128 * 1024 * 1024, nvidia="NVIDIA GeForce RTX 4090, 24564\n"))
    out = models().output
    assert "NVIDIA GPU  NVIDIA GeForce RTX 4090, 24 GiB" in out
    assert "Local models may use about 24 GiB here: the memory of the NVIDIA GeForce RTX 4090." in out
    lanes = section(out, "Lanes:")
    assert "First: an open-weight model on this machine" in lanes and "qwen3.5-9b on Ollama (qwen3.5:9b): needs about 12.1 GiB" in lanes
    assert "Not for this machine: qwen3.5-9b on MLX (MLX runs on Apple Silicon only)" in lanes  # gemma4-12b: not for lanes
    # phi4-mini: not for the light role on either runtime, so not judged for this machine
    assert "Not for this machine: qwen3.5-9b on MLX, gemma4-12b on MLX (MLX runs on Apple Silicon only)" in section(out, "Light role:")


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
    assert light.index("rules: the default; no model, no cost") < light.index("Model APIs:")
    assert "Fit here" not in light  # 8 GiB: phi4-mini would fit by size, but it is not for the light role
    on(monkeypatch, linux_box(32 * 1024 * 1024))  # 16 GiB: gpt-oss-20b fits the light role
    light = section(models().output, "Light role:")
    assert "First: the rules (the default, no model), or a small model that fits." in light
    assert light.index("rules: the default; no model, no cost") < light.index("Fit here, on the CPU (slow):")
    assert light.index("Fit here, on the CPU (slow):") < light.index("Model APIs:")
    assert group(light, "  Fit here, on the CPU (slow):").startswith("    gpt-oss-20b on Ollama (gpt-oss:20b): needs about 14.8 GiB")


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
        ("qwen3.5-9b", "ollama", "measured"), ("qwen3.5-9b", "mlx", "measured"), ("gpt-oss-20b", "ollama", "measured")]
    assert lanes["fits"][2]["measured"] == "solved 2 of 4 practice challenges as served; tool calls 5/5"
    assert {o["sized_by"] for o in lanes["fits"]} == {"catalog"} and lanes["cannot_tell"] == []
    assert lanes["fits"][1]["server_args"] == ["--chat-template-args", '{"enable_thinking":false}', "--max-tokens", "8192"]
    for role, title, others in (("lanes", "Lanes:", "  Not for a lane:"), ("light", "Light role:", "  Not for the light role:")):
        block = section(text, title)  # the text says the same
        for option in data["roles"][role]["fits"]:
            assert f"{option['id']} on {hardware.RUNTIME_NAMES[option['runtime']]} ({option['model']}" in group(block, "  Fit here:")
        not_for = group(block, others).splitlines()
        assert [f"    {n['id']}{' on ' + hardware.RUNTIME_NAMES[n['runtime']] if n['runtime'] else ''}: {n['why']}"
                for n in data["roles"][role]["not_for"]] == not_for
    assert [(n["id"], n["runtime"]) for n in lanes["not_for"]] == [
        ("gpt-oss-20b", "mlx"), ("gemma4-12b", "ollama"), ("gemma4-12b", "mlx"), ("phi4-mini", "ollama"), ("phi4-mini", "mlx")]
    assert data["roles"]["light"]["default"] == "rules"


def test_json_names_the_basis_of_a_fit_only(monkeypatch):
    """"basis" says why a fit is offered; a model that does not fit has none, measured or not."""
    on(monkeypatch, apple_mac(memory=4 * GIB, chip="Apple M1"))  # 2.7 GiB for local models: nothing fits
    light = json.loads(models("--json").output)["roles"]["light"]
    qwen_mlx = next(o for o in light["too_big"] if (o["id"], o["runtime"]) == ("qwen3.5-9b", "mlx"))
    assert (qwen_mlx["verdict"], qwen_mlx["basis"]) == ("too big", None) and qwen_mlx["measured"].startswith("eval-local 41/44")
    assert light["fits"] == []


def test_a_build_with_no_catalog_size_is_sized_by_ollama_here_once_pulled(monkeypatch, tmp_path):
    shipped = (model_catalog.files("ctf_flightdeck") / "models.toml").read_text(encoding="utf-8")
    size = "size_bytes = 13793441566   # results/ollama-gptoss.measure.json: disk.size_bytes\n"
    assert shipped.count(size) == 1
    (tmp_path / "models.toml").write_text(shipped.replace(size, ""), encoding="utf-8")
    monkeypatch.setattr(model_catalog, "files", lambda package: tmp_path)
    on(monkeypatch, mac_with_ollama())  # its Ollama has pulled gpt-oss:20b, and gives 13793441244 bytes
    lanes = json.loads(models("--json").output)["roles"]["lanes"]
    gpt_oss = next(o for o in lanes["fits"] if (o["id"], o["runtime"]) == ("gpt-oss-20b", "ollama"))
    assert (gpt_oss["sized_by"], gpt_oss["size_bytes"], gpt_oss["weights_bytes"]) == ("server", None, 13793441244)
    assert "(12.8 GiB of weights, as Ollama here gives them + 6 GiB for the context)" in section(models().output, "Lanes:")
    on(monkeypatch, apple_mac())  # not pulled here: no size at all
    assert "gpt-oss-20b on Ollama (gpt-oss:20b): its size on disk is not recorded in the catalog, and Ollama here has not " \
           "pulled it" in group(section(models().output, "Lanes:"), "  Cannot tell:")


# ---------------------------------------------------------------------- one model: how to get it, and its config lines


def test_one_model_gives_the_commands_and_the_exact_config_lines(monkeypatch, tmp_path):
    on(monkeypatch, apple_mac(programs={"ollama": "/opt/homebrew/bin/ollama"}))
    result = models("qwen3.5-9b")
    assert result.exit_code == 0, result.output
    out = result.output
    assert out.startswith("Qwen3.5 9B (qwen3.5-9b): Qwen3.5, 9.0B parameters, Apache-2.0. For lanes and the light role.")
    assert out.splitlines()[1] == (
        "Measured: on Ollama, for lanes: solved 1 of 4 practice challenges as served; tool calls 4/5, the fifth a well-formed "
        "call to set_plan, which the test did not offer; on MLX, for lanes: solved 2 of 4 practice challenges with thinking "
        "off and --max-tokens 8192 (0 of 4 served as it comes); tool calls 5/5; on MLX, for the light role: eval-local 41/44 "
        "with thinking off, against the rules' 38/44 (docs/MODELS.md).")
    ollama, mlx = section(out, "On Ollama:"), out[out.index("On MLX:"):]
    assert "here, for lanes: fits: needs about 12.1 GiB" in ollama
    assert "    ollama pull qwen3.5:9b" in ollama
    assert "uv tool install mlx-lm" in mlx  # mlx_lm is not installed on this fake Mac
    assert "    " + QWEN_MLX_SERVER + "\n" in mlx
    assert "lanes: in your config, these replace its [api], [models] and [prices] tables" in out
    assert ('    [light]\n    engine = "openai"\n    model = "mlx-community/Qwen3.5-9B-MLX-4bit"\n'
            '    base_url = "http://127.0.0.1:8080/v1"\n    key_env = ""') in mlx
    assert ("measure it first: flightdeck eval-local --engine openai --base-url http://127.0.0.1:8080/v1 "
            "--model mlx-community/Qwen3.5-9B-MLX-4bit") in mlx
    data = json.loads(models("qwen3.5-9b", "--json").output)
    assert data["changes_config"] is False
    by_runtime = {b["runtime"]: b for b in data["builds"]}
    assert by_runtime["ollama"]["get"] == ["ollama pull qwen3.5:9b"]
    assert by_runtime["mlx"]["get"][-2] == QWEN_MLX_SERVER
    lanes = by_runtime["mlx"]["roles"]["lanes"]
    config = parse_config(lanes["config"] + '\n[lanes]\nruntime = "host"\n', tmp_path / "c.toml")
    assert (config.api.base_url, config.models) == ("http://127.0.0.1:8080/v1", ("mlx-community/Qwen3.5-9B-MLX-4bit",))
    light = by_runtime["mlx"]["roles"]["light"]
    assert parse_config('[models]\nladder = ["m"]\n' + light["config"], tmp_path / "c.toml").light.model == (
        "mlx-community/Qwen3.5-9B-MLX-4bit")
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


def shipped_without_results(*builds: tuple[str, str]) -> str:
    """The shipped catalog's text without the measured table of each (model id, runtime) build given."""
    shipped = (model_catalog.files("ctf_flightdeck") / "models.toml").read_text(encoding="utf-8")
    kept, model, dropping = [], "", False
    for line in shipped.splitlines(keepends=True):
        if line.startswith("["):
            header = re.fullmatch(r"\[local\.(ollama|mlx)\.measured\]\n", line)
            dropping = header is not None and (model, header.group(1)) in builds
        elif line.startswith("id = "):
            model = line.split('"')[1]
        if not dropping:
            kept.append(line)
    return "".join(kept)


def fit_names(block: str) -> list[str]:
    """The builds under "Fit here:" in a role's block, in order ("qwen3.5-9b on MLX")."""
    return [line.strip().split(" (")[0] for line in group(block, "  Fit here:").splitlines()]


def test_a_measured_build_says_so_comes_first_and_names_where_the_results_are(monkeypatch, tmp_path):
    """With the results of Qwen3.5 9B and Gemma 4 12B on MLX taken out of the catalog, those
    builds fit by size only: they come after the measured ones, and say so."""
    text = shipped_without_results(("qwen3.5-9b", "mlx"), ("gemma4-12b", "mlx"))
    (tmp_path / "models.toml").write_text(text, encoding="utf-8")
    monkeypatch.setattr(model_catalog, "files", lambda package: tmp_path)
    unmeasured = [(m.id, b.runtime) for m in model_catalog.load_catalog().local for b in m.builds if not b.measured]
    # gpt-oss-20b on MLX, gemma4-12b on Ollama and phi4-mini have none in the shipped catalog either: only not_for lines
    assert unmeasured == [("qwen3.5-9b", "mlx"), ("gpt-oss-20b", "mlx"), ("gemma4-12b", "ollama"), ("gemma4-12b", "mlx"),
                          ("phi4-mini", "ollama"), ("phi4-mini", "mlx")]
    on(monkeypatch, apple_mac())
    out = models().output
    light = section(out, "Light role:")
    assert fit_names(light) == ["gpt-oss-20b on Ollama", "qwen3.5-9b on MLX", "gemma4-12b on MLX"]
    fits = group(light, "  Fit here:").splitlines()
    assert fits[0].endswith("; measured: eval-local 38/44 as served, against the rules' 38/44 (docs/MODELS.md)")
    assert all(line.endswith("; fits by size only: not measured for the light role yet") for line in fits[1:])
    assert fit_names(section(out, "Lanes:")) == ["qwen3.5-9b on Ollama", "gpt-oss-20b on Ollama", "qwen3.5-9b on MLX"]
    assert models("qwen3.5-9b").output.splitlines()[1] == (
        "Measured: on Ollama, for lanes: solved 1 of 4 practice challenges as served; tool calls 4/5, the fifth a well-formed "
        "call to set_plan, which the test did not offer (docs/MODELS.md).")
    assert models("gemma4-12b").output.splitlines()[1] == (  # its results now are only what it is not for
        "Measured: not yet for the light role; each runtime below says what it is not for, and why (docs/MODELS.md).")
    data = json.loads(models("qwen3.5-9b", "--json").output)
    assert [(b["runtime"], sorted(b["measured"])) for b in data["builds"]] == [("ollama", ["lanes"]), ("mlx", [])]


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
