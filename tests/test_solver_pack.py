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


def needs_environment() -> None:
    if not (PACK / ".venv" / "bin" / "python").exists():
        pytest.skip("not run: the pack has no Python environment (packs/solvers/setup.sh makes it)")


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
