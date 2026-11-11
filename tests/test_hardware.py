"""What this machine has for local models (hardware.py), on fake machines only.

Every probe here goes through a FakeHost (scripted sysctl, /proc/meminfo and nvidia-smi
output) or, for the runtime servers, through the real HTTP getter to a ListServer the test
starts on 127.0.0.1. No test asks this machine's own Ollama or MLX server anything:
no_real_runtime_ports below fails any request to their ports.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import sys
from urllib.parse import urlsplit

import httpx
import pytest
from fake_host import GIB, Answer, FakeHost, ListServer, apple_mac, linux_box

from ctf_flightdeck import hardware
from ctf_flightdeck.hardware import (
    DOWN,
    LM_STUDIO,
    MIB,
    MLX,
    OLLAMA,
    SERVING,
    UNKNOWN,
    Gpu,
    ProbeError,
    RealHost,
    doctor_line,
    http_get,
    local_only,
    probe,
    summary,
)
from ctf_flightdeck.setup import doctor, report

SYSCTL = "/usr/sbin/sysctl"
NVIDIA_ARGS = ("--query-gpu=name,memory.total", "--format=csv,noheader,nounits")
OFF = {OLLAMA: "http://127.0.0.1:9/api/tags", MLX: "http://127.0.0.1:9/v1/models", LM_STUDIO: "http://127.0.0.1:9/v1/models"}
REAL_PORTS = {11434, 8080, 1234}  # where this machine's own runtimes may be listening
PATIENT = 30.0  # seconds a test server on 127.0.0.1 may take when the test is not about time (a loaded machine is slow)


@pytest.fixture(autouse=True)
def no_real_runtime_ports(monkeypatch):
    """A request to Ollama's, MLX's or LM Studio's own port fails the test before it is sent."""
    real = hardware.http_get

    def guarded(url: str, timeout: float):
        assert urlsplit(url).port not in REAL_PORTS, f"a test asked a real runtime port: {url}"
        return real(url, timeout)

    monkeypatch.setattr(hardware, "http_get", guarded)


def tags(*models: tuple[str, int]) -> bytes:
    return json.dumps({"models": [{"name": name, "model": name, "size": size} for name, size in models]}).encode()


def openai_list(*ids: str) -> bytes:
    return json.dumps({"object": "list", "data": [{"id": i, "object": "model"} for i in ids]}).encode()


# ---------------------------------------------------------------------- four machines


def test_an_apple_silicon_mac():
    host = apple_mac(memory=36 * GIB, chip="Apple M4 Max")
    machine = probe(host, servers=OFF)
    assert (machine.os, machine.arch) == ("macOS", "arm64")
    assert machine.chip.value == "Apple M4 Max" and machine.apple_silicon.value is True
    assert machine.memory.value == 36 * GIB and machine.wsl.value is False
    assert machine.gpus.value == () and machine.gpu_note == "nvidia-smi is not on PATH"
    assert host.ran == [[SYSCTL, "-n", "machdep.cpu.brand_string"], [SYSCTL, "-n", "hw.memsize"]]
    assert all(t <= hardware.COMMAND_TIMEOUT for t in host.timeouts)
    assert summary(machine) == "Apple M4 Max (Apple Silicon), 36 GiB of unified memory"


def test_an_x86_python_on_an_apple_chip_is_apple_silicon_and_an_intel_mac_is_not():
    rosetta = probe(FakeHost("Darwin", "x86_64", programs={"sysctl": SYSCTL}, commands={
        (SYSCTL, "-n", "machdep.cpu.brand_string"): "Apple M1\n", (SYSCTL, "-n", "hw.memsize"): f"{16 * GIB}\n"}),
        runtimes=False)
    assert rosetta.apple_silicon.value is True
    intel = probe(FakeHost("Darwin", "x86_64", programs={"sysctl": SYSCTL}, commands={
        (SYSCTL, "-n", "machdep.cpu.brand_string"): "Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz\n",
        (SYSCTL, "-n", "hw.memsize"): f"{32 * GIB}\n"}), runtimes=False)
    assert intel.apple_silicon.value is False and intel.memory.value == 32 * GIB


def test_a_linux_box_with_nvidia_gpus():
    host = linux_box(65_843_200, nvidia="NVIDIA GeForce RTX 4090, 24564\nNVIDIA RTX A6000, 49140\n")
    machine = probe(host, servers=OFF)
    assert (machine.os, machine.wsl.value) == ("Linux", False)
    assert machine.memory.value == 65_843_200 * 1024
    assert machine.gpus.value == (Gpu("NVIDIA GeForce RTX 4090", 24564 * MIB), Gpu("NVIDIA RTX A6000", 49140 * MIB))
    assert host.ran == [["/usr/bin/nvidia-smi", *NVIDIA_ARGS]]
    assert host.timeouts == [hardware.GPU_TIMEOUT]
    assert machine.chip.value is None and machine.apple_silicon.value is False
    assert "NVIDIA GeForce RTX 4090 (24 GiB)" in summary(machine)


def test_a_cpu_only_linux_box():
    host = linux_box(16 * 1024 * 1024)
    machine = probe(host, servers=OFF)
    assert machine.memory.value == 16 * GIB and machine.gpus.value == ()
    assert machine.gpu_note == "nvidia-smi is not on PATH"
    assert host.ran == []  # nvidia-smi is never run when it is not on PATH
    assert summary(machine) == "Linux on x86_64, 16 GiB of memory, no NVIDIA GPU found"


def test_wsl_counts_as_linux():
    host = linux_box(32 * 1024 * 1024, osrelease="5.15.153.1-microsoft-standard-WSL2\n",
                     nvidia="NVIDIA GeForce RTX 3060, 12288\n", nvidia_path="/usr/lib/wsl/lib/nvidia-smi")
    machine = probe(host, servers=OFF)
    assert (machine.os, machine.wsl.value) == ("Linux", True)
    assert machine.memory.value == 32 * GIB
    assert machine.gpus.value == (Gpu("NVIDIA GeForce RTX 3060", 12 * GIB),)
    assert summary(machine).startswith("Linux (WSL) on x86_64, 32 GiB of memory")


def test_an_unreadable_kernel_release_leaves_wsl_unknown():
    host = linux_box(8 * 1024 * 1024)
    del host.files["/proc/sys/kernel/osrelease"]
    machine = probe(host, runtimes=False)
    assert machine.wsl.value is None and "osrelease cannot be read" in machine.wsl.unknown


# ---------------------------------------------------------------------- a probe that fails is unknown, never a number


@pytest.mark.parametrize("printed", ["", "garbage\n", "-1\n", "0\n", "1e10\n", "36 GB\n", f"{2**60}\n", "12 34\n"])
def test_garbage_from_sysctl_leaves_the_memory_unknown(printed):
    machine = probe(apple_mac(commands={(SYSCTL, "-n", "hw.memsize"): printed}), runtimes=False)
    assert machine.memory.value is None
    assert machine.memory.unknown == "sysctl hw.memsize printed something that is not a number of bytes"


@pytest.mark.parametrize("failure", [ProbeError("sysctl gave no answer within 2 s"), ProbeError("sysctl failed (exit status 1)")])
def test_a_sysctl_that_times_out_or_fails_leaves_the_mac_unknown(failure):
    host = apple_mac(commands={(SYSCTL, "-n", "hw.memsize"): failure, (SYSCTL, "-n", "machdep.cpu.brand_string"): failure})
    host.arch = "x86_64"  # so the chip alone could say Apple Silicon
    machine = probe(host, runtimes=False)
    assert machine.memory.value is None and machine.memory.unknown == str(failure)
    assert machine.chip.value is None and machine.chip.unknown == str(failure)
    assert machine.apple_silicon.value is None and "Rosetta" in machine.apple_silicon.unknown


def test_no_sysctl_on_path_is_named():
    machine = probe(FakeHost("Darwin", "arm64"), runtimes=False)
    assert machine.memory.value is None and machine.memory.unknown == "sysctl is not on PATH"


@pytest.mark.parametrize("printed", ["", "\x1b[2JApple M4\n", "A" * 300 + "\n"])
def test_a_chip_name_that_is_not_one_is_unknown(printed):
    machine = probe(apple_mac(commands={(SYSCTL, "-n", "machdep.cpu.brand_string"): printed}), runtimes=False)
    assert machine.chip.value is None and "not a chip's name" in machine.chip.unknown
    assert machine.apple_silicon.value is True  # an arm64 Python: every arm64 Mac is Apple Silicon


@pytest.mark.parametrize("meminfo", [
    "MemFree: 1234 kB\n",  # no MemTotal
    "MemTotal: 16 MB\n",  # not in kB
    "MemTotal:  abc kB\n",
    "MemTotal: 0 kB\n",
    "MemTotal: 1000 kB\nMemTotal: 2000 kB\n",  # which one?
    "garbage",
])
def test_garbage_in_proc_meminfo_leaves_the_memory_unknown(meminfo):
    machine = probe(linux_box(1, files={"/proc/meminfo": meminfo}), runtimes=False)
    assert machine.memory.value is None
    assert machine.memory.unknown == "/proc/meminfo has no MemTotal line in kB that flightdeck can read"


def test_an_unreadable_proc_meminfo_leaves_the_memory_unknown():
    host = linux_box(1)
    del host.files["/proc/meminfo"]
    machine = probe(host, runtimes=False)
    assert machine.memory.value is None and machine.memory.unknown.startswith("/proc/meminfo cannot be read")


@pytest.mark.parametrize(("printed", "why"), [
    ("NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver.\n", "not a GPU's name and memory"),
    ("NVIDIA GB10, [N/A]\n", "no memory size in MiB"),
    ("NVIDIA GeForce RTX 4090, 24564 MiB\n", "no memory size in MiB"),
    ("NVIDIA GeForce RTX 4090, 24564\n, 8192\n", "not a GPU's name and memory"),
    ("NVIDIA GeForce RTX 4090, 0\n", "no memory size in MiB"),
    ("\x1b[31mGPU, 1024\n", "not a GPU's name and memory"),
])
def test_garbage_from_nvidia_smi_leaves_the_gpus_unknown(printed, why):
    machine = probe(linux_box(8 * 1024 * 1024, nvidia=printed), runtimes=False)
    assert machine.gpus.value is None and why in machine.gpus.unknown


def test_an_nvidia_smi_that_times_out_leaves_the_gpus_unknown():
    machine = probe(linux_box(8 * 1024 * 1024, nvidia=ProbeError("nvidia-smi gave no answer within 5 s")), runtimes=False)
    assert machine.gpus.value is None and machine.gpus.unknown == "nvidia-smi gave no answer within 5 s"
    assert "NVIDIA GPUs unknown" in summary(machine)


def test_an_nvidia_smi_that_lists_nothing_found_no_gpu():
    machine = probe(linux_box(8 * 1024 * 1024, nvidia="\n"), runtimes=False)
    assert machine.gpus.value == () and machine.gpu_note == "nvidia-smi lists no GPU"


def test_another_system_reads_no_memory_and_says_so():
    machine = probe(FakeHost("Windows", "AMD64"), runtimes=False)
    assert machine.os == "Windows" and machine.memory.value is None
    assert "not on Windows" in machine.memory.unknown


# ---------------------------------------------------------------------- the real command runner and program finder


def test_the_runner_gives_a_command_that_runs_too_long_no_answer():
    with pytest.raises(ProbeError, match=r"gave no answer within 0.3 s"):
        RealHost().run([sys.executable, "-c", "import time; time.sleep(30)"], 0.3)


def test_the_runner_names_a_command_that_fails_or_cannot_run(tmp_path):
    with pytest.raises(ProbeError, match=r"failed \(exit status 3\)"):
        RealHost().run([sys.executable, "-c", "raise SystemExit(3)"], 30)
    with pytest.raises(ProbeError, match="cannot be run"):
        RealHost().run([str(tmp_path / "no-such-program")], 30)
    assert RealHost().run([sys.executable, "-c", "print('hello')"], 30) == "hello\n"


def test_programs_are_found_in_paths_absolute_folders_only(tmp_path, monkeypatch):
    for folder in ("here", "system"):
        (tmp_path / folder).mkdir()
        program = tmp_path / folder / "fd-probe-tool"
        program.write_text("")  # never run: only looked up
        program.chmod(program.stat().st_mode | stat.S_IXUSR)
    monkeypatch.chdir(tmp_path)
    found = RealHost({"PATH": os.pathsep.join(["here", "", ".", str(tmp_path / "system")])}).which("fd-probe-tool")
    assert found == str(tmp_path / "system" / "fd-probe-tool")
    assert RealHost({"PATH": os.pathsep.join(["here", "."])}).which("fd-probe-tool") is None


# ---------------------------------------------------------------------- the runtimes, as their servers answer


def test_the_runtimes_and_what_their_servers_list(monkeypatch):
    host = apple_mac(
        programs={"ollama": "/opt/homebrew/bin/ollama", "llama-server": "/usr/local/bin/llama-server"},
        importable=["mlx_lm"],
        http={OFF[OLLAMA]: (200, tags(("qwen3.5:9b", 6550825550), ("phi4-mini:latest", 2491876774)))},
    )
    machine = probe(host, servers={**OFF, MLX: "http://127.0.0.1:10/v1/models", LM_STUDIO: "http://127.0.0.1:11/v1/models"})
    ollama, mlx, llama, studio = machine.runtimes
    assert (ollama.program, ollama.server.state, ollama.server.models) == (
        "/opt/homebrew/bin/ollama", SERVING, ("qwen3.5:9b", "phi4-mini:latest"))
    assert ollama.server.size("qwen3.5:9b") == 6550825550
    assert ollama.server.lists("phi4-mini") and ollama.server.size("phi4-mini") == 2491876774  # ":latest" is the tag's default
    assert not ollama.server.lists("gemma4:12b") and ollama.server.size("gemma4:12b") is None
    assert (mlx.program, mlx.importable, mlx.installed, mlx.server.state) == (None, True, True, DOWN)
    assert (llama.program, llama.server) == ("/usr/local/bin/llama-server", None)
    assert studio.server.state == DOWN and studio.program_name == ""
    assert host.fetched == [OFF[OLLAMA], "http://127.0.0.1:10/v1/models", "http://127.0.0.1:11/v1/models"]


@pytest.mark.parametrize(("answer", "why"), [
    ((200, b"<html>hello</html>"), "not with a model list"),
    ((200, b'{"models": [{"size": 5}]}'), "not with a model list"),  # a model with no name
    ((200, b'{"data": []}'), "not with a model list"),  # an OpenAI list where Ollama's should be
    ((200, b"\xff\xfe"), "not with a model list"),
    ((500, b"{}"), "with HTTP 500"),
    (ProbeError("no answer within 1 s"), "no answer within 1 s"),
])
def test_a_server_that_answers_garbage_or_times_out_is_unknown(answer, why):
    machine = probe(apple_mac(http={OFF[OLLAMA]: answer}), servers=OFF)
    server = machine.runtime(OLLAMA).server
    assert server.state == UNKNOWN and why in server.why and server.models == ()


def test_a_size_that_is_not_a_whole_number_of_bytes_is_left_out():
    body = json.dumps({"models": [{"name": "a:1", "size": "big"}, {"name": "b:1", "size": -4},
                                  {"name": "c:1", "size": 1.5}, {"name": "d:1", "size": True}, {"name": "e:1"}]}).encode()
    server = probe(apple_mac(http={OFF[OLLAMA]: (200, body)}), servers=OFF).runtime(OLLAMA).server
    assert server.state == SERVING and server.models == ("a:1", "b:1", "c:1", "d:1", "e:1")
    assert dict(server.sizes) == {}


def test_without_runtimes_no_server_is_asked_and_no_runtime_looked_for():
    host = apple_mac(programs={"ollama": "/opt/homebrew/bin/ollama"})
    machine = probe(host, runtimes=False)
    assert machine.runtimes == () and host.fetched == []


# ---------------------------------------------------------------------- over real HTTP, to servers the test starts


def test_the_real_getter_reads_each_servers_list_and_asks_only_127_0_0_1():
    routes = {
        "/api/tags": Answer(body=tags(("gpt-oss:20b", 13793441244))),
        "/v1/models": Answer(body=openai_list("mlx-community/Qwen3.5-9B-MLX-4bit")),
        "/studio/v1/models": Answer(body=openai_list("qwen/qwen3.5-9b")),
    }
    with ListServer(routes) as server:
        servers = {OLLAMA: server.url("/api/tags"), MLX: server.url("/v1/models"), LM_STUDIO: server.url("/studio/v1/models")}
        host = FakeHost("Linux", "x86_64", real_http=True)
        machine = probe(host, servers=servers, http_timeout=PATIENT)
    assert machine.runtime(OLLAMA).server.models == ("gpt-oss:20b",)
    assert machine.runtime(OLLAMA).server.size("gpt-oss:20b") == 13793441244
    assert machine.runtime(MLX).server.models == ("mlx-community/Qwen3.5-9B-MLX-4bit",)
    assert machine.runtime(LM_STUDIO).server.models == ("qwen/qwen3.5-9b",)
    assert {urlsplit(url).hostname for url in host.fetched} == {"127.0.0.1"}
    assert server.hosts == [f"127.0.0.1:{server.port}"] * 3
    assert sorted(server.paths) == sorted(routes)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_nothing_listening_is_down_and_a_slow_server_is_unknown():
    with ListServer({"/api/tags": Answer(body=tags(), delay=2.0)}) as slow:
        servers = {OLLAMA: slow.url("/api/tags"), MLX: f"http://127.0.0.1:{free_port()}/v1/models",
                   LM_STUDIO: f"http://127.0.0.1:{free_port()}/v1/models"}
        machine = probe(FakeHost("Linux", "x86_64", real_http=True), servers=servers, http_timeout=0.3)
    ollama = machine.runtime(OLLAMA).server
    assert ollama.state == UNKNOWN and "within 0.3 s" in ollama.why and ollama.models == ()
    assert machine.runtime(MLX).server.state == DOWN and machine.runtime(LM_STUDIO).server.state == DOWN


def test_a_redirect_is_not_followed():
    routes = {"/api/tags": Answer(302, b"", headers=(("Location", "/elsewhere"),)), "/elsewhere": Answer(body=tags())}
    with ListServer(routes) as server:
        status, _ = http_get(server.url("/api/tags"), PATIENT)
    assert status == 302 and server.paths == ["/api/tags"]


def test_a_proxy_in_the_environment_is_not_used(monkeypatch):
    with ListServer({}) as proxy, ListServer({"/api/tags": Answer(body=tags())}) as target:
        for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.setenv(name, f"http://127.0.0.1:{proxy.port}")
        for name in ("NO_PROXY", "no_proxy"):
            monkeypatch.delenv(name, raising=False)
        status, body = http_get(target.url("/api/tags"), PATIENT)
    assert (status, json.loads(body)) == (200, {"models": []})
    assert proxy.paths == [] and target.paths == ["/api/tags"]


def test_an_answer_longer_than_the_cap_is_unknown(monkeypatch):
    monkeypatch.setattr(hardware, "MAX_BODY", 64)
    with ListServer({"/api/tags": Answer(body=tags(*((f"model-{n}:latest", n + 1) for n in range(20))))}) as server:
        machine = probe(FakeHost("Linux", "x86_64", real_http=True), servers={**OFF, OLLAMA: server.url("/api/tags")},
                        http_timeout=PATIENT)
    assert machine.runtime(OLLAMA).server.state == UNKNOWN and "longer than" in machine.runtime(OLLAMA).server.why


@pytest.mark.parametrize("url", [
    "http://localhost:11434/api/tags",  # a hosts file can point localhost anywhere
    "http://10.0.0.5:11434/api/tags",
    "https://127.0.0.1:11434/api/tags",
    "http://user@127.0.0.1:11434/api/tags",
    "http://127.0.0.1.example.com/api/tags",
    "http://[::1]:11434/api/tags",
])
def test_nothing_but_127_0_0_1_is_contacted(url, monkeypatch):
    with pytest.raises(ValueError, match="contact only http://127.0.0.1"):
        local_only(url)
    host = apple_mac()
    with pytest.raises(ValueError):
        probe(host, servers={**OFF, MLX: url})
    assert host.fetched == [] and host.ran == []  # refused before anything was asked

    def no_client(*args, **kwargs):
        raise AssertionError("a client was made for a URL that is not on 127.0.0.1")

    monkeypatch.setattr(httpx, "Client", no_client)
    with pytest.raises(ValueError):
        http_get(url, 1.0)


def test_the_default_servers_are_on_127_0_0_1_at_each_runtimes_port():
    assert hardware.SERVERS == {
        OLLAMA: "http://127.0.0.1:11434/api/tags", MLX: "http://127.0.0.1:8080/v1/models",
        LM_STUDIO: "http://127.0.0.1:1234/v1/models",
    }
    host = apple_mac()
    probe(host)  # the fake host answers: nothing on this machine is asked
    assert host.fetched == list(hardware.SERVERS.values())
    assert {urlsplit(url).hostname for url in host.fetched} == {"127.0.0.1"}


# ---------------------------------------------------------------------- doctor's one line


def test_doctor_names_the_machine_in_one_line_that_is_never_essential(tmp_path, monkeypatch):
    host = apple_mac(memory=36 * GIB, programs={"ollama": "/opt/homebrew/bin/ollama"})
    monkeypatch.setattr(hardware, "RealHost", lambda environ=os.environ: host)
    checks = [c for c in doctor(tmp_path / "none.toml", environ={}) if c.name == "machine"]
    assert len(checks) == 1
    (check,) = checks
    assert (check.ok, check.essential) == (True, False)
    assert check.detail == ("Apple M4 Max (Apple Silicon), 36 GiB of unified memory; "
                            "`flightdeck models` suggests local models that fit")
    assert host.fetched == []  # doctor asks no model server about the machine
    text, _ = report([check])
    assert text.startswith("ok   machine: Apple M4 Max")


def test_doctors_machine_line_stays_a_note_when_every_probe_fails(tmp_path, monkeypatch):
    failing = ProbeError("sysctl gave no answer within 2 s")
    host = apple_mac(commands={(SYSCTL, "-n", "hw.memsize"): failing, (SYSCTL, "-n", "machdep.cpu.brand_string"): failing})
    monkeypatch.setattr(hardware, "RealHost", lambda environ=os.environ: host)
    (check,) = [c for c in doctor(tmp_path / "none.toml", environ={}) if c.name == "machine"]
    assert (check.ok, check.essential) == (True, False) and "memory unknown" in check.detail
    assert doctor_line(host=linux_box(8 * 1024 * 1024)).startswith("Linux on x86_64, 8 GiB of memory, no NVIDIA GPU found;")
