"""The solver pack (packs/solvers) as flightdeck runs it: its one engine, on synthetic
challenges made here. The tests that run the pack need its Python environment (its setup.sh
makes it); without one they report as not run."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import subprocess
import zipfile
from pathlib import Path

import pytest

from ctf_flightdeck import pack as packs
from ctf_flightdeck.l1.manifest import discover
from ctf_flightdeck.l1.runner import run_engine

from l1_kit import challenge_dir, run

PACK = Path(__file__).resolve().parent.parent / "packs" / "solvers"
FORMAT = r"practice\{[a-z0-9_]+\}"

pytestmark = pytest.mark.skipif(not (PACK / "pack.toml").is_file(), reason="not run: this checkout has no packs/solvers")


def adapter():
    spec = importlib.util.spec_from_file_location("fd_intake_engine", PACK / "flightdeck" / "intake_engine.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_packs_image_gets_the_same_debugger_and_decompiler_as_the_lane_image():
    """Lanes run in the pack's image under [l1] lane_tools, so it must not have less than the
    lane image: gdb from Debian, and radare2 with r2ghidra as the very archives the lane image
    pins (the same releases, the same SHA-256 for each architecture, checked the same way).
    `binary.decompile_intake` calls r2, so the pack lists it for `flightdeck doctor`."""
    from ctf_flightdeck.lane import dockerfile

    def steps(text: str) -> tuple[str, str]:
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        start = code.index("RUN set -eu; \\\n    arch=$(dpkg --print-architecture)")
        return code, code[start:code.index("\nWORKDIR /work", start)].rstrip()

    lane_code, lane_steps = steps(dockerfile())
    pack_code, pack_steps = steps((PACK / "flightdeck" / "Dockerfile").read_text(encoding="utf-8"))
    assert pack_steps == lane_steps.replace("the lane image: radare2", "the pack image: radare2") != lane_steps
    assert "sha256sum -c -" in pack_steps and pack_steps.endswith("r2 -q -c 'Lc' -- | grep -q ghidra")
    assert "apt-get install -y --no-install-recommends gdb gdb-multiarch" in pack_code
    assert "r2" in packs.read(PACK).tools and "gdb" not in packs.read(PACK).tools  # no engine calls gdb: it is the lane's


PACK_IMAGE = packs.read(PACK).image.tag if (PACK / "pack.toml").is_file() else ""  # ctf-flightdeck-pack:1


def test_in_the_packs_image_a_lane_can_run_the_packs_decompile_engine(tmp_path):
    """Under [l1] lane_tools a lane runs in the pack's image with the pack mounted read-only, and
    its model calls `solvers run ENGINE`. The pack's other engine images need `docker run`,
    which a lane's container has no way to do (no client, no socket: the fence), so the
    decompiler is in this image: `binary.decompile_intake`, which was `blocked` here for want
    of one, prints the entry function of a native binary as C. The binary is the image's own
    /usr/bin/true, read and never run; the container is a lane's, with no network.

    Needs Docker and the pack's image as today's Dockerfile builds it (`flightdeck pack image`):
    reports as not run otherwise (it fails instead under FLIGHTDECK_REQUIRE_PACK_IMAGE=1), and
    no test builds or pulls it."""
    import asyncio

    from ctf_flightdeck.agent.workspace import DockerWorkspace
    from l1_kit import REQUIRE_PACK_IMAGE, docker_not_run, docker_skip_reason

    reason = docker_skip_reason(PACK_IMAGE)
    if reason:
        docker_not_run(f"not run: {reason} (`flightdeck pack image` builds it)", require=REQUIRE_PACK_IMAGE)
    if packs.missing_in_image(PACK_IMAGE, ["r2"]):
        docker_not_run(f"not run: {PACK_IMAGE} on this machine was built before the pack's image had r2 (`flightdeck pack image` "
                       "builds today's)", require=REQUIRE_PACK_IMAGE)
    handout = challenge_dir(tmp_path / "board", "demo", {"note.txt": "a native binary\n"}, id="demo", category="rev")
    box = DockerWorkspace(tmp_path / "lane", handout, image=PACK_IMAGE, name=f"flightdeck-test-pack-{os.getpid()}",
                          mounts=[(PACK, str(PACK))], probe_tools=True)

    async def scenario():
        await box.prepare()
        try:
            return await box.run(f"cp /usr/bin/true sample && {PACK}/flightdeck/solvers -f '{FORMAT}' run binary.decompile_intake . 2>&1",
                                 timeout=300)
        finally:
            await box.close()

    done = asyncio.run(scenario())
    assert done.exit_code == 0, done.output.decode()
    result = json.loads(done.output.decode().strip().splitlines()[-1])
    assert result["status"] != "blocked" and result["engine"] == "binary.decompile_intake", result
    assert {"kind": "decompile", "detail": "r2ghidra decompiled entry0 of sample", "path": "recon/decompile/sample/entry0.c",
            "offset": None} in result["evidence"]
    assert "__libc_start_main" in (box.root / "recon" / "decompile" / "sample" / "entry0.c").read_text()
    assert box.shell_tools == ("gdb", "gdb-multiarch", "r2", "pdg")  # and the lane's brief names them here too


REQUIRE_PACK = "FLIGHTDECK_REQUIRE_PACK"  # =1: a test that needs the pack's environment fails where there is none (CI)


def needs_environment() -> None:
    if (PACK / ".venv" / "bin" / "python").exists():
        return
    why = "the pack has no Python environment (packs/solvers/setup.sh makes it)"
    if os.environ.get(REQUIRE_PACK) == "1":
        pytest.fail(f"{REQUIRE_PACK}=1, and {why}")
    pytest.skip(f"not run: {why}")


def intake(handout: Path, tmp_path: Path, flag_format: str = FORMAT):
    (manifest,) = discover(PACK)
    return run(run_engine(manifest, handout, workdir=tmp_path / "work", flag_format=flag_format))


@pytest.mark.parametrize(("pattern", "prefixes"), [
    (r"practice\{[a-z0-9_]+\}", ("practice",)),
    (r"(?:flag|CTF)\{[^}]+\}", ("flag", "CTF")),
    (r"(flag|ctf)\{.+\}", ("flag", "ctf")),
    (r"^EVENT_2026\{\w+\}$", ("EVENT_2026",)),
    (r"\w{1,64}\{[^{}\s]{1,256}\}", ()),          # flightdeck's default: any word
    (r"(?:flag|[A-Z]+)\{.+\}", ()),               # one alternative is not literal: none is taken
    (r"[0-9a-f]{32}", ()),                        # no brace at all
])
def test_the_adapter_reads_only_certainly_literal_prefixes_out_of_a_flag_format(pattern, prefixes):
    assert adapter().prefixes_of(pattern) == prefixes


def test_the_adapter_lists_a_handout_without_flightdecks_own_files_or_symlinks(tmp_path):
    folder = challenge_dir(tmp_path / "board", "demo", {"a.txt": "x", "sub/b.bin": b"\x00"})
    (folder / ".flightdeck").mkdir()
    (folder / ".flightdeck" / "prepare.log").write_text("flightdeck's own\n")
    (folder / "link").symlink_to(tmp_path)
    engine = adapter()
    assert [p.as_posix() for p in engine.handout_files(folder, None)] == ["a.txt", "sub/b.bin"]
    assert [p.as_posix() for p in engine.handout_files(folder, ["a.txt", "../outside", "link"])] == ["a.txt"]


def test_the_pack_declares_itself_and_has_one_engine_for_every_challenge():
    info = packs.read(PACK)
    assert info.name == "flightdeck-solvers" and info.setup == (str(PACK / "setup.sh"),)
    assert info.image is not None and info.image.dockerfile == PACK / "flightdeck" / "Dockerfile"
    (manifest,) = discover(PACK)
    assert manifest.id == "solvers.intake" and manifest.routes[0].any and manifest.output == "result"


def test_the_pack_finds_a_flag_inside_an_archive_under_two_layers_of_base64(tmp_path):
    needs_environment()
    flag = "practice{nested_layers_42}"
    folder = challenge_dir(tmp_path / "board", "layers", {"readme.txt": "peel it\n"})
    with zipfile.ZipFile(folder / "bundle.zip", "w") as archive:
        archive.writestr("deep/note.txt", "nothing here\n" + base64.b64encode(base64.b64encode(flag.encode())).decode() + "\n")
    result = intake(folder, tmp_path)
    assert (result.status, result.flags) == ("solved", (flag,))
    assert result.evidence and "bundle.zip" in result.evidence[0].detail
    assert result.notes.startswith("handout: ") and "unpacked member" in result.notes.splitlines()[0]


def test_the_pack_reports_none_for_a_handout_with_no_flag_and_says_what_it_saw(tmp_path):
    needs_environment()
    folder = challenge_dir(tmp_path / "board", "empty", {"notes.txt": "nothing of interest in here\n"})
    result = intake(folder, tmp_path)
    assert (result.status, result.flags) == ("none", ())
    assert "handout: 1 file(s)" in result.notes


def test_candidates_are_told_as_text_and_never_handed_over_as_flags(tmp_path):
    """Under auto submit flightdeck sends every flag of a result; the pack proves nothing about a
    candidate, so it reports none as a flag."""
    needs_environment()
    folder = challenge_dir(tmp_path / "board", "two", {"a.txt": "practice{first_one}\n", "b.txt": "practice{second_one}\n"})
    result = intake(folder, tmp_path)
    assert (result.status, result.flags) == ("unsure", ())
    first = result.notes.splitlines()[0]
    assert first.startswith("candidates, not proven") and "practice{first_one}" in first and "practice{second_one}" in first


def test_a_value_outside_the_events_flag_format_is_never_reported(tmp_path):
    needs_environment()
    folder = challenge_dir(tmp_path / "board", "upper", {"a.txt": "see PRACTICE{Not_The_Format} here\n"})
    result = intake(folder, tmp_path)  # the pack matches a prefix in any case; the event's format is lower-case only
    assert (result.status, result.flags) == ("none", ())
    assert "do not match the event's flag format" in result.notes


def test_with_no_literal_prefix_the_pack_looks_for_the_common_ones_and_says_so(tmp_path):
    needs_environment()
    folder = challenge_dir(tmp_path / "board", "common", {"a.txt": "here: flag{the_common_shape}\n"})
    result = intake(folder, tmp_path, flag_format=r"\w{1,64}\{[^{}\s]{1,256}\}")
    assert (result.status, result.flags) == ("solved", ("flag{the_common_shape}",))
    assert "names no literal prefix" in result.notes


def test_the_wrapper_says_blocked_when_the_pack_has_no_python(tmp_path):
    copy = tmp_path / "pack"
    (copy / "flightdeck").mkdir(parents=True)
    script = copy / "flightdeck" / "run-intake"
    script.write_bytes((PACK / "flightdeck" / "run-intake").read_bytes())
    script.chmod(0o755)
    env = {"PATH": os.environ["PATH"]}
    if Path("/opt/flightdeck-pack/venv/bin/python").exists():
        pytest.skip("not run: this machine has a pack environment at /opt/flightdeck-pack")
    done = subprocess.run([str(script), str(tmp_path)], capture_output=True, text=True, env=env)
    answer = json.loads(done.stdout.strip().splitlines()[-1])
    assert done.returncode == 0 and answer["status"] == "blocked" and "setup.sh" in answer["notes"]


def test_a_run_with_the_pack_solves_a_layered_challenge_before_any_model_call(tmp_path):
    """The whole path a player takes: a board, the pack as [l1] pack, a run. The pack's intake
    finds the flag (zip, then base64 twice), the player approves it, the board's answers file
    says it is right, and the lane's model was never called."""
    needs_environment()
    import asyncio
    import hashlib

    from ctf_flightdeck.core import interventions as iv
    from ctf_flightdeck.core.model import LaneState
    from ctf_flightdeck.run import RunOptions, prepare_run

    from fake_model import FakeModelServer

    flag = "practice{nested_layers_42}"
    root = tmp_path / "board"
    folder = root / "layers"
    folder.mkdir(parents=True)
    with zipfile.ZipFile(folder / "bundle.zip", "w") as archive:
        archive.writestr("deep/note.txt", base64.b64encode(base64.b64encode(flag.encode())).decode() + "\n")
    (folder / "challenge.json").write_text(json.dumps({"name": "Layers", "category": "misc", "points": 50, "description": "Peel it."}))
    (root / "board.json").write_text(json.dumps({"event": "Test Event", "flag_format": FORMAT}))
    (root / "answers.sha256.json").write_text(json.dumps({"layers": hashlib.sha256(flag.encode()).hexdigest()}))
    with FakeModelServer() as server:
        config = tmp_path / "config.toml"
        config.write_text(
            f'[api]\nbase_url = "{server.base_url}"\nkey_env = ""\n[models]\nladder = ["fake/small"]\n'
            f'[lanes]\nmax_lanes = 1\nruntime = "host"\n[run]\ndir = "{tmp_path / "runs"}"\n'
            f'[l1]\npack = "{PACK}"\nlane_tools = true\n')
        run = prepare_run(RunOptions(board=root, config=config, runtime="host", pack=PACK))
        assert [m.id for m in run.driver.l1.manifests] == ["solvers.intake"]
        assert f"{PACK}/flightdeck/solvers" in run.driver.l1.toolkit  # what a lane's brief says of the pack

        async def main():
            run.release()
            (lane,) = run.deck.lanes.values()
            for _ in range(600):
                if lane.pending is not None:
                    break
                await asyncio.sleep(0.1)
            assert lane.pending is not None and lane.pending.flag == flag
            assert run.deck.apply(iv.Approve(lane.id)).ok
            for _ in range(100):
                if lane.state is LaneState.SOLVED:
                    break
                await asyncio.sleep(0.1)
            assert lane.state is LaneState.SOLVED
            await run.shutdown()

        asyncio.run(main())
        run.close()
        assert server.chats() == []
