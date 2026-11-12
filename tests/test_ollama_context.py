"""The context Ollama gives a lane's model (ollama_context.py), and what `flightdeck doctor` and
`flightdeck models` say of it. Ollama is a fake (fake_host.ListServer, real HTTP on 127.0.0.1)
answering /api/ps as Ollama 0.34.2 does; machines are fakes (fake_host.FakeHost); no model is
loaded, pulled or called."""

from __future__ import annotations

import json
import os

import pytest
from fake_host import GIB, Answer, FakeHost, ListServer, apple_mac, linux_box
from typer.testing import CliRunner

from ctf_flightdeck import cli, hardware
from ctf_flightdeck.hardware import OLLAMA, SERVERS, probe
from ctf_flightdeck.ollama_context import (
    Estimate,
    default_contexts,
    default_note,
    lane_finding,
    loaded_contexts,
    ollama_default,
    ollama_root,
)
from ctf_flightdeck.setup import doctor

MIB = 1024**2


def ps(*models: tuple[str, int | None]) -> bytes:
    """Ollama's /api/ps answer, as 0.34.2 gives it, for (name, context_length) pairs."""
    items = []
    for name, tokens in models:
        item = {"name": name, "model": name, "size": 2843161393, "size_vram": 2843161393, "expires_at": "2026-11-11T21:20:14Z",
                "details": {"format": "gguf", "family": "qwen35", "parameter_size": "1.9B", "quantization_level": "Q8_0"}}
        if tokens is not None:
            item["context_length"] = tokens
        items.append(item)
    return json.dumps({"models": items}).encode()


# ---------------------------------------------------------------------- Ollama's default, by GPU memory


@pytest.mark.parametrize(("gpu", "tokens"), [
    (0, 4_096), (23 * GIB - 1, 4_096), (23 * GIB, 32_768), (47 * GIB - 1, 32_768), (47 * GIB, 262_144), (96 * GIB, 262_144),
])
def test_ollama_gives_a_model_a_context_by_its_gpu_memory(gpu, tokens):
    assert ollama_default(gpu) == tokens


@pytest.mark.parametrize(("host", "tokens", "why"), [
    (apple_mac(memory=16 * GIB), (4_096,), "the GPU of this Mac may use 10.7 GiB to 13.4 GiB of its 16 GiB"),
    (apple_mac(memory=32 * GIB), (4_096, 32_768), "the GPU of this Mac may use 21.3 GiB to 26.9 GiB of its 32 GiB"),
    (apple_mac(memory=36 * GIB), (32_768,), "the GPU of this Mac may use 24 GiB to 30.2 GiB of its 36 GiB"),
    (apple_mac(memory=64 * GIB), (32_768, 262_144), "may use 42.7 GiB to 53.8 GiB of its 64 GiB"),
    (linux_box(64 * 1024 * 1024, nvidia="NVIDIA GeForce RTX 4090, 24564\n"), (32_768,), "the NVIDIA GPU memory here is 24 GiB"),
    (linux_box(64 * 1024 * 1024, nvidia="NVIDIA GeForce RTX 3060, 12288\nNVIDIA GeForce RTX 3060, 12288\n"), (32_768,),
     "the NVIDIA GPU memory here is 24 GiB in all"),  # Ollama sums its GPUs
    (linux_box(64 * 1024 * 1024, nvidia="NVIDIA GeForce RTX 4070, 12282\n"), (4_096,), "the NVIDIA GPU memory here is 12 GiB"),
    (linux_box(256 * 1024 * 1024), (4_096,), "it finds no GPU here"),
], ids=["16-gb-mac", "32-gb-mac", "36-gb-mac", "64-gb-mac", "24-gb-gpu", "two-12-gb-gpus", "12-gb-gpu", "no-gpu"])
def test_the_context_ollama_would_give_is_estimated_from_the_gpu_memory_it_finds(host, tokens, why):
    estimate = default_contexts(probe(host, runtimes=False))
    assert estimate.tokens == tokens and why in estimate.why and not estimate.named


def test_ollama_context_length_where_flightdeck_runs_is_taken_and_said_to_be_so():
    mac = probe(apple_mac(memory=16 * GIB), runtimes=False)
    estimate = default_contexts(mac, {"OLLAMA_CONTEXT_LENGTH": "65536"})
    assert (estimate.tokens, estimate.named) == ((65_536,), True)
    assert "OLLAMA_CONTEXT_LENGTH is 65536 where flightdeck runs, and Ollama has it if it was started there too" == estimate.why
    for unusable in ("lots", "64k", "0", "\u00b2"):  # not a whole number above 0 (the last one: a digit int() cannot read)
        estimate = default_contexts(mac, {"OLLAMA_CONTEXT_LENGTH": unusable})
        assert (estimate.tokens, estimate.named) == ((4_096,), False)  # not taken,
        assert estimate.why.endswith("(OLLAMA_CONTEXT_LENGTH where flightdeck runs is not a whole number above 0, so it is not counted)")  # and said
    assert default_contexts(hardware.described(16 * GIB, apple=True), {}).tokens == (4_096,)


def test_a_machine_whose_gpu_cannot_be_read_gets_no_estimate():
    assert default_contexts(probe(linux_box(64 * 1024 * 1024, nvidia="NVIDIA-SMI has failed\n"), runtimes=False)) is None
    rosetta = FakeHost("Darwin", "x86_64", programs={"sysctl": "/usr/sbin/sysctl"},
                       commands={("/usr/sbin/sysctl", "-n", "hw.memsize"): f"{64 * GIB}\n"})
    assert default_contexts(probe(rosetta, runtimes=False)) is None


def test_ollamas_list_of_loaded_models_is_read_strictly():
    assert loaded_contexts(json.loads(ps(("qwen3.5:2b", 32_768), ("gpt-oss:20b", 65_536)))) == {
        "qwen3.5:2b": 32_768, "gpt-oss:20b": 65_536}
    assert loaded_contexts(json.loads(ps(("qwen3.5:2b", None)))) == {}  # an older Ollama gives no context_length
    assert loaded_contexts({"models": []}) == {}
    assert loaded_contexts({"data": []}) is None and loaded_contexts([]) is None
    assert loaded_contexts({"models": [{"context_length": 4096}]}) is None  # a model with no name
    assert loaded_contexts({"models": [{"name": "m", "context_length": True}]}) == {}


# ---------------------------------------------------------------------- whether a lane fits


ESTIMATE_32K = Estimate((32_768,), "the GPU of this Mac may use 24 GiB to 30.2 GiB of its 36 GiB")


def test_a_loaded_model_with_less_context_than_a_lane_needs_is_said_and_fixed():
    finding = lane_finding("127.0.0.1:11434", ("qwen3.5:9b", "gpt-oss:20b"), {"gpt-oss:20b": 32_768, "other:1b": 4_096},
                           ESTIMATE_32K, 50_000, 8_192, source="/home/p/config.toml")
    assert (finding.ok, finding.model, finding.tokens, finding.stated, finding.need) == (False, "gpt-oss:20b", 32_768, True,
                                                                                         66_384)
    assert finding.detail.startswith("Ollama at 127.0.0.1:11434 gives gpt-oss:20b 32,768 tokens of context (as Ollama says "
                                     "of it while it is loaded (`ollama ps`)); a lane needs 66,384: it is refreshed at "
                                     "50,000 prompt tokens, with room for two replies of up to 8,192")
    assert "Ollama drops a lane's oldest messages without saying so" in finding.detail
    assert finding.fix == ("set context = 32768 under [api] in /home/p/config.toml, so a lane is refreshed at 16,384 prompt "
                           "tokens, before it outgrows Ollama; or give Ollama more: set OLLAMA_CONTEXT_LENGTH=65536 where "
                           "Ollama runs and restart Ollama, then set context = 65536 under [api] in /home/p/config.toml (a "
                           "lane is then refreshed at 49,152 prompt tokens)")


def test_a_lane_fits_once_the_config_states_the_context_ollama_gives():
    """[api] context = 65536 with OLLAMA_CONTEXT_LENGTH=65536: refreshed at 49,152, room for two replies."""
    fits = lane_finding("127.0.0.1:11434", ("gpt-oss:20b",), {"gpt-oss:20b": 65_536}, None, 49_152, 8_192,
                        stated_context=65_536)
    assert (fits.ok, fits.need, fits.fix) == (True, 65_536, "")
    assert "it is refreshed at 49,152 prompt tokens ([api] context is 65,536)" in fits.detail
    short = lane_finding("127.0.0.1:11434", ("gpt-oss:20b",), {"gpt-oss:20b": 32_768}, None, 49_152, 8_192,
                         stated_context=65_536)  # the config says more than Ollama gives
    assert not short.ok and "([api] context is 65,536)" in short.detail and short.fix.startswith("set context = 32768")


def test_ollamas_smallest_default_leaves_no_context_to_state_only_one_to_give():
    finding = lane_finding("127.0.0.1:11434", ("qwen3.5:9b",), {}, Estimate((4_096,), "it finds no GPU here"), 50_000, 8_192)
    assert (finding.ok, finding.tokens, finding.stated) == (False, 4_096, False)
    assert "(an estimate: it is not loaded, so Ollama does not say; with no OLLAMA_CONTEXT_LENGTH Ollama gives 4,096 under " \
           "23 GiB of GPU memory, 32,768 from 23 GiB and 262,144 from 47 GiB, and it finds no GPU here)" in finding.detail
    assert finding.fix.startswith("set OLLAMA_CONTEXT_LENGTH=65536 where Ollama runs and restart Ollama")
    assert "set context = 4096" not in finding.fix  # a lane cannot work in 4,096 tokens
    assert finding.fix.endswith("once the model is loaded, `ollama ps` shows the context Ollama gives it, and so does this check")


def test_an_estimate_leads_with_giving_ollama_a_context_and_a_mac_near_a_tier_is_judged_by_the_smaller():
    finding = lane_finding("127.0.0.1:11434", ("phi4-mini",), {"phi4-mini:latest": 65_536} | {}, None, 50_000, 8_192)
    assert finding.stated and finding.tokens == 65_536  # a name without a tag is its ":latest"
    near = lane_finding("127.0.0.1:11434", ("m",), None, Estimate((4_096, 32_768), "the GPU of this Mac may use ..."),
                        50_000, 8_192)
    assert near.tokens == 4_096 and "4,096 tokens of context (or 32,768, an estimate" in near.detail
    estimated = lane_finding("127.0.0.1:11434", ("m",), None, ESTIMATE_32K, 50_000, 8_192)
    assert estimated.fix.startswith("set OLLAMA_CONTEXT_LENGTH=65536") and "; or, if Ollama keeps its 32,768, set " \
                                                                             "context = 32768 under [api]" in estimated.fix
    assert lane_finding("127.0.0.1:11434", ("m",), None, None, 50_000, 8_192) is None


def test_the_note_for_a_machine_with_no_config_to_look_at():
    ok, note = default_note(ESTIMATE_32K, 50_000, 8_192, "there")
    assert not ok and note.startswith("Ollama's context: with no OLLAMA_CONTEXT_LENGTH, Ollama gives a model 32,768 tokens "
                                      "there (the GPU of this Mac")
    assert "A lane needs 66,384" in note and "set OLLAMA_CONTEXT_LENGTH=65536 where Ollama runs, restart it, and set " \
                                             "context = 65536 under [api]" in note
    assert note.endswith("The light role's short prompts fit 4,096.")
    ok, note = default_note(Estimate((262_144,), "the NVIDIA GPU memory here is 48 GiB"), 50_000, 8_192)
    assert ok and "Enough for a lane, which needs 66,384." in note


# ---------------------------------------------------------------------- doctor


def write_config(tmp_path, base_url: str, extra: str = "", fallback: str = "") -> str:
    path = tmp_path / "config.toml"
    path.write_text(f'[api]\nbase_url = "{base_url}"\nkey_env = ""\n{extra}[models]\nladder = ["gpt-oss:20b"]\n'
                    f'[lanes]\nruntime = "host"\n{fallback}')
    return path


def context_checks(path, monkeypatch, host: FakeHost | None = None, environ: dict | None = None):
    monkeypatch.setattr(hardware, "RealHost", lambda environ=os.environ: host or apple_mac(memory=36 * GIB))
    return [c for c in doctor(path, environ=environ or {}) if c.name in ("lane context", "fallback context")]


def ollama(models: bytes) -> ListServer:
    return ListServer({"/api/ps": Answer(body=models), "/v1/models": Answer(body=b'{"data": [{"id": "gpt-oss:20b"}]}')})


def test_doctor_reads_the_context_ollama_gives_a_loaded_model_and_warns_when_a_lane_outgrows_it(tmp_path, monkeypatch):
    with ollama(ps(("gpt-oss:20b", 32_768))) as server:
        path = write_config(tmp_path, server.url("/v1"))
        (check,) = context_checks(path, monkeypatch)
        assert (check.ok, check.essential) == (False, False)
        assert check.detail.startswith(f"Ollama at 127.0.0.1:{server.port} gives gpt-oss:20b 32,768 tokens of context (as "
                                       "Ollama says of it while it is loaded (`ollama ps`)); a lane needs 66,384")
        assert check.fix.startswith(f"set context = 32768 under [api] in {path}, so a lane is refreshed at 16,384")
        assert server.paths.count("/api/ps") == 1
        path = write_config(tmp_path, server.url("/v1"), extra="context = 32768\n")  # the fix: refreshed at 16,384
        (check,) = context_checks(path, monkeypatch)
        assert check.ok and "it is refreshed at 16,384 prompt tokens ([api] context is 32,768)" in check.detail
    _, status = __import__("ctf_flightdeck.setup", fromlist=["report"]).report([check])
    assert status == 0


def test_doctor_estimates_the_context_from_this_machines_gpu_memory_when_nothing_is_loaded(tmp_path, monkeypatch):
    with ollama(ps()) as server:
        path = write_config(tmp_path, server.url("/v1"))
        (check,) = context_checks(path, monkeypatch, apple_mac(memory=16 * GIB))
        assert not check.ok and "gives gpt-oss:20b 4,096 tokens of context (an estimate: it is not loaded" in check.detail
        assert "the GPU of this Mac may use 10.7 GiB to 13.4 GiB of its 16 GiB" in check.detail
        assert check.fix.startswith("set OLLAMA_CONTEXT_LENGTH=65536 where Ollama runs and restart Ollama")
        (check,) = context_checks(path, monkeypatch, apple_mac(memory=16 * GIB), {"OLLAMA_CONTEXT_LENGTH": "65536"})
        assert not check.ok and "65,536 tokens of context" in check.detail  # 65,536 < 66,384 with no [api] context
        assert "OLLAMA_CONTEXT_LENGTH is 65536 where flightdeck runs" in check.detail
        path = write_config(tmp_path, server.url("/v1"), extra="context = 65536\n")
        (check,) = context_checks(path, monkeypatch, apple_mac(memory=16 * GIB), {"OLLAMA_CONTEXT_LENGTH": "65536"})
        assert check.ok


def test_doctor_checks_the_fallbacks_ollama_too_and_never_another_server_or_the_light_role(tmp_path, monkeypatch):
    with ollama(ps(("gpt-oss:20b", 32_768))) as server:
        spare = (f'[fallback]\nbase_url = "{server.url("/v1")}"\nkey_env = ""\nladder = ["gpt-oss:20b"]\n')
        path = write_config(tmp_path, "https://openrouter.ai/api/v1", fallback=spare)
        path.write_text(path.read_text().replace('key_env = ""\n[models]', 'key_env = "OPENROUTER_API_KEY"\n[models]', 1))
        assert [(c.name, c.ok) for c in context_checks(path, monkeypatch)] == [("fallback context", False)]
        light = (f'[light]\nengine = "openai"\nmodel = "gpt-oss:20b"\nbase_url = "{server.url("/v1")}"\nkey_env = ""\n')
        path = write_config(tmp_path, "https://openrouter.ai/api/v1", fallback=light)
        path.write_text(path.read_text().replace('key_env = ""\n[models]', 'key_env = "OPENROUTER_API_KEY"\n[models]', 1))
        assert context_checks(path, monkeypatch) == []  # the light role's prompts fit any context Ollama gives
    with ListServer({"/v1/models": Answer(body=b'{"data": [{"id": "gpt-oss:20b"}]}')}) as other:  # /api/ps: 404
        assert context_checks(write_config(tmp_path, other.url("/v1")), monkeypatch) == []  # not Ollama: nothing to say
    assert context_checks(write_config(tmp_path, "http://127.0.0.1:9/v1"), monkeypatch) == []  # nothing there: not known


def test_doctor_takes_a_silent_ollama_at_its_default_port_for_one_not_running(tmp_path, monkeypatch):
    import httpx

    asked = []

    def refused(url, **kwargs):
        asked.append(str(url))
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "get", refused)
    checks = context_checks(write_config(tmp_path, "http://127.0.0.1:11434/v1"), monkeypatch, apple_mac(memory=36 * GIB))
    assert asked == ["http://127.0.0.1:11434/v1/models", "http://127.0.0.1:11434/api/ps"]  # the model server check's, then ours
    (check,) = checks
    assert not check.ok and "32,768 tokens of context (an estimate" in check.detail
    assert check.detail.endswith("(nothing answered /api/ps there: ConnectError)")


# ---------------------------------------------------------------------- flightdeck models


runner = CliRunner()


@pytest.fixture
def models_on(monkeypatch, tmp_path):
    """`flightdeck models` on a fake machine, with the config at tmp_path/config.toml (absent unless written)."""
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("OLLAMA_CONTEXT_LENGTH", raising=False)

    def run(host: FakeHost, *args: str):
        monkeypatch.setattr(hardware, "RealHost", lambda environ=os.environ: host)
        return runner.invoke(cli.app, ["models", *args], terminal_width=400)

    return run


def mac_serving(loaded: bytes, memory: int = 36 * GIB) -> FakeHost:
    tags = json.dumps({"models": [{"name": "gpt-oss:20b", "size": 13793441566}]}).encode()
    return apple_mac(memory=memory, programs={"ollama": "/opt/homebrew/bin/ollama"},
                     http={SERVERS[OLLAMA]: (200, tags), "http://127.0.0.1:11434/api/ps": (200, loaded)})


def test_models_says_what_ollama_gives_the_configs_lanes_and_the_fix(models_on, tmp_path):
    write_config(tmp_path, "http://127.0.0.1:11434/v1")
    out = models_on(mac_serving(ps(("gpt-oss:20b", 32_768)))).output
    assert "its server at 127.0.0.1:11434 has pulled 1 model: gpt-oss:20b; it has loaded gpt-oss:20b with 32,768 tokens " \
           "of context" in out
    lanes = out[out.index("Lanes:"):out.index("Light role:")]
    assert ("  Your config's lanes: Ollama at 127.0.0.1:11434 gives gpt-oss:20b 32,768 tokens of context (as Ollama says of "
            "it while it is loaded (`ollama ps`)); a lane needs 66,384") in lanes
    assert f"    fix: set context = 32768 under [api] in {tmp_path / 'config.toml'}, so a lane is refreshed at 16,384" in lanes
    assert "Ollama's context: with no OLLAMA_CONTEXT_LENGTH" not in out  # the config's own finding says it
    data = json.loads(models_on(mac_serving(ps(("gpt-oss:20b", 32_768))), "--json").output)
    context = data["roles"]["lanes"]["ollama_context"]
    assert (context["config"], context["ok"], context["tokens"], context["stated"], context["need"]) == (True, False, 32_768,
                                                                                                         True, 66_384)
    assert data["machine"]["runtimes"][0]["server"]["loaded"] == {"gpt-oss:20b": 32_768}


def test_models_without_a_config_notes_ollamas_default_for_this_machine(models_on, tmp_path):
    out = models_on(mac_serving(ps(), memory=16 * GIB)).output
    lanes = out[out.index("Lanes:"):out.index("Light role:")]
    assert ("  Ollama's context: with no OLLAMA_CONTEXT_LENGTH, Ollama gives a model 4,096 tokens here (the GPU of this Mac "
            "may use 10.7 GiB to 13.4 GiB of its 16 GiB, as macOS sets it)") in lanes
    assert "The light role's short prompts fit 4,096." in lanes and "Your config" not in out
    (tmp_path / "config.toml").write_text("[api\n")  # a config that cannot be read is said, not passed over
    lanes = models_on(mac_serving(ps(), memory=16 * GIB)).output
    assert "  Your config is not read here (" in lanes and "`flightdeck doctor` says what is wrong with it." in lanes


def test_models_for_a_described_machine_notes_its_default_and_never_reads_this_ones_config(models_on, tmp_path, monkeypatch):
    write_config(tmp_path, "http://127.0.0.1:11434/v1")

    def probed(environ=os.environ):
        raise AssertionError("a described machine is never probed: this one is not it")

    monkeypatch.setattr(hardware, "RealHost", probed)
    result = runner.invoke(cli.app, ["models", "--memory", "24", "--gpu-memory", "24"], terminal_width=400)
    assert result.exit_code == 0, result.output
    out = result.output
    assert "Your config" not in out
    assert ("  Ollama's context: with no OLLAMA_CONTEXT_LENGTH, Ollama gives a model 32,768 tokens there (the NVIDIA GPU "
            "memory there is 24 GiB)") in out
    data = json.loads(runner.invoke(cli.app, ["models", "--memory", "24", "--gpu-memory", "24", "--json"]).output)
    assert data["roles"]["lanes"]["ollama_context"] == {"config": False, "ok": False, "tokens": [32_768],
                                                        "detail": data["roles"]["lanes"]["ollama_context"]["detail"]}


def test_ollamas_address_leaves_out_a_base_urls_query_and_fragment():
    """Neither is Ollama's, and a query may hold a token: it is not printed, and not asked for /api/ps."""
    assert ollama_root("http://127.0.0.1:11434/v1") == "http://127.0.0.1:11434"
    assert ollama_root("http://127.0.0.1:11434/v1/?token=not-a-real-token#x") == "http://127.0.0.1:11434"
    assert ollama_root("http://[::1]:11434/v1?k=v") == "http://[::1]:11434"


def test_the_fix_does_not_tell_the_player_to_set_the_context_their_config_already_states():
    estimate = Estimate((32_768,), "the GPU memory says so")
    stated = lane_finding("127.0.0.1:11434", ("gpt-oss:20b",), None, estimate, 49_152, 8_192, stated_context=65_536)
    unstated = lane_finding("127.0.0.1:11434", ("gpt-oss:20b",), None, estimate, 49_152, 8_192)
    assert not stated.ok and not unstated.ok
    assert "then set context = 65536" in unstated.fix
    assert stated.fix.startswith("set OLLAMA_CONTEXT_LENGTH=65536 where Ollama runs and restart Ollama;") and "then set context" not in stated.fix
