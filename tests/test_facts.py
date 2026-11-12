"""A lane's handout facts and the first look's text (agent/facts.py): each file's name and size,
what `file -b` says of it (run in the lane's workspace: in Docker, inside the lane's container),
an excerpt of its printable strings, and what a lane's brief takes of a light model's first
look: its triage lines and its brief, flag-shaped text removed and cut at a line.

Host workspaces under tmp_path; one test uses a real container of debian:bookworm-slim when the
image is here (never pulled). The handouts are synthetic: their executables, if anything ever
ran them, would only leave a mark."""

from __future__ import annotations

import asyncio
import re
import shutil
import time
from pathlib import Path

import pytest

from ctf_flightdeck.agent import facts as F
from ctf_flightdeck.agent.workspace import DockerWorkspace, HostWorkspace
from l1_kit import DOCKER_IMAGE, docker_not_run, docker_skip_reason

FLAG = r"t\{[a-z0-9_]+\}"
NEEDS_FILE = pytest.mark.skipif(shutil.which("file") is None, reason="the `file` command is not on this machine")


def handout(tmp_path: Path, name: str, files: dict[str, str | bytes]) -> Path:
    folder = tmp_path / "board" / name
    folder.mkdir(parents=True)
    for rel, content in files.items():
        target = folder / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content) if isinstance(content, bytes) else target.write_text(content)
    return folder


def facts_in(workspace, names, *, then=None):
    async def main():
        await workspace.prepare()
        if then is not None:
            then()
        try:
            return await F.handout_facts(workspace, names)
        finally:
            await workspace.close()

    return asyncio.run(main())


# ---------------------------------------------------------------------- the facts


@NEEDS_FILE
def test_handout_facts_give_each_files_name_size_what_file_says_and_its_strings(tmp_path):
    blob = b"\x00\x01abc\x00hello world\x00hello world\x00" + b"\x00".join(b"string number %d" % i for i in range(12))
    folder = handout(tmp_path, "facts", {"note.txt": "just some words here\n", "blob.bin": blob, "long.bin": b"L" * 500})
    names = ["note.txt", "blob.bin", "long.bin", "missing.txt", *(f"pad{i}" for i in range(40))]
    facts = facts_in(HostWorkspace(tmp_path / "work", folder), names)
    assert len(facts.files) == F.MAX_FACT_FILES and facts.more == len(names) - F.MAX_FACT_FILES
    note, blob_facts, long, missing = facts.files[:4]
    assert note.size == len("just some words here\n") and "text" in note.file and note.strings == ("just some words here",)
    assert blob_facts.size == len(blob) and blob_facts.file
    assert blob_facts.strings[0] == "hello world" and "abc" not in blob_facts.strings  # under 6 characters: left out
    assert len(blob_facts.strings) == F.STRINGS_SHOWN and blob_facts.strings.count("hello world") == 1  # the first 8, each once
    assert long.strings == ("L" * (F.STRING_CHARS - 3) + "...",)
    assert (missing.size, missing.file, missing.strings) == (None, "", ())
    data = facts.data()
    assert data[3] == {"name": "missing.txt", "size": "not in the workspace"}
    assert data[-1] == f"and {len(names) - F.MAX_FACT_FILES} more files, not read"
    assert facts.problem == ""


@NEEDS_FILE
def test_the_facts_never_run_a_handout_file_and_a_name_is_never_a_command(tmp_path):
    marker = tmp_path / "ran"
    script = f"#!/bin/sh\necho ran >> '{marker}'\n"
    files = {"file": script, "strings": script, "run.sh": script, "-v": script, "sub/head": script,
             "$(touch made-by-a-name)": "plain text\n", "x;touch made-by-a-name;y": "plain text\n"}
    folder = handout(tmp_path, "trap", files)
    for rel in ("file", "strings", "run.sh", "-v", "sub/head"):
        (folder / rel).chmod(0o755)
    facts = facts_in(HostWorkspace(tmp_path / "work", folder), list(files))
    assert [f.name for f in facts.files] == list(files) and all(f.file for f in facts.files)  # `file` read each one
    assert "script" in facts.files[2].file and "text" in facts.files[5].file
    assert not marker.exists()  # nothing of the handout ran
    assert list(tmp_path.rglob("made-by-a-name")) == []  # and no name was ever a command


def test_a_workspace_without_file_says_so_and_keeps_names_sizes_and_strings(tmp_path, monkeypatch):
    folder = handout(tmp_path, "nofile", {"data.bin": b"\x00secret-ish string\x00"})
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    # bash is found when the workspace is prepared; then PATH holds no `file`
    facts = facts_in(HostWorkspace(tmp_path / "work", folder), ["data.bin"], then=lambda: monkeypatch.setenv("PATH", str(empty)))
    assert facts.problem == "`file` is not installed in the lane's workspace"
    (only,) = facts.files
    assert (only.size, only.file, only.strings) == (19, "", ("secret-ish string",))


def test_in_docker_the_facts_run_file_in_the_lanes_container_and_never_the_handout(tmp_path):
    reason = docker_skip_reason()
    if reason:
        docker_not_run(reason)
    folder = handout(tmp_path, "boxed", {"file": "#!/bin/sh\necho ran >> ran\n", "data.bin": b"\x00hello there\x00"})
    (folder / "file").chmod(0o755)
    name = f"flightdeck-test-facts-{time.time_ns()}"
    workspace = DockerWorkspace(tmp_path / "work", folder, image=DOCKER_IMAGE, name=name, network="none")
    facts = facts_in(workspace, ["file", "data.bin"])
    # this machine has `file` and the slim image has not: the command ran in the container
    assert facts.problem == f"`file` is not installed in the lane's container (image {DOCKER_IMAGE})"
    assert [(f.name, f.size, f.strings) for f in facts.files] == [
        ("file", 26, ("#!/bin/sh", "echo ran >> ran")), ("data.bin", 13, ("hello there",))]
    assert not (tmp_path / "work" / "ran").exists()


def test_the_file_command_quotes_every_name_and_puts_it_after_the_options():
    command = F.file_command(["-v", "a b", "it's", "$(touch x)"])
    assert "for f in -v 'a b' 'it'\"'\"'s' '$(touch x)'; do file -b -- \"$f\"" in command
    assert command.startswith("command -v file >/dev/null 2>&1 || {")


def test_a_long_description_never_crowds_the_handouts_facts_out_of_what_the_light_model_reads():
    """A board's long description (a story, pasted source) is cut for route and recon, so the
    handout's facts still reach the light model: in a model's prompt, and in a decision model's
    state, whose window is smaller. A description that fits is the board's as it is."""
    from ctf_flightdeck import light as L
    from ctf_flightdeck.core.model import Challenge
    from fake_decider import FakeDeciderServer, picks

    facts = F.HandoutFacts((F.FileFacts("capture.pcapng", 123456, "pcapng capture file - version 1.0", ("tcp stream",)),))
    told = "The ship's log. " * 400  # 6,400 characters
    data = F.challenge_data(Challenge("long", "Long Story", "", 100, description=told), facts, [])
    for messages in (L.choice_messages(L.ROUTE, data, L.FAMILY, L.FAMILY.choices), L.recon_messages(data)):
        user = messages[1]["content"]
        assert "- capture.pcapng (123,456 bytes)" in user and "file says: pcapng capture file - version 1.0" in user
        assert "[cut: the description is 6,400 characters in all]" in user
    assert data["description"].startswith(told[:F.DESCRIPTION_CHARS])

    async def decide():
        engine = L.DeciderLight(decider.base_url, timeout=5.0)
        try:
            return await engine.ask_choice(L.ROUTE, data, L.FAMILY, L.FAMILY.choices)
        finally:
            await engine.aclose()

    with FakeDeciderServer(responder=picks("network-capture", 0.95)) as decider:
        assert asyncio.run(decide()).choice == "network-capture"
    (asked,) = [r for r in decider.requests if r["json"]]
    assert "- capture.pcapng (123,456 bytes)" in asked["json"]["state"]
    short = "We pulled this off the 20-metre band.\nIt warbles."
    assert F.challenge_data(Challenge("short", "Short", "for", 100, description=short), facts, [])["description"] == short


# ---------------------------------------------------------------------- the first look's text


def test_the_first_look_replaces_every_flag_and_cuts_at_a_line():
    pattern = re.compile(FLAG)
    text = F.first_look("audio-signal", "for", "Decode it: the flag is not t{abc} but t{d_e}.\nline two", pattern)
    assert text.splitlines() == [
        "Specialist it suits: audio-signal (audio and radio signals: SSTV, Morse, DTMF tones, text in a spectrogram)",
        "Category: for? (a guess: the board names no category flightdeck knows)",
        "Decode it: the flag is not [flag-shaped text removed] but [flag-shaped text removed].",
        "line two",
    ]
    assert F.first_look("", "", "", pattern) == "" and F.first_look("", "", " \n ", pattern) == ""
    # a flag format that matches flightdeck's own words: the lane gets no first look, never a flag-shaped one
    assert F.first_look("audio-signal", "", "a brief", re.compile(r"[a-z]+-[a-z]+")) == ""
    assert F.cut_at_line("one two three", 100) == "one two three"
    cut = F.cut_at_line("x" * 30 + " " + "y" * 200, 120)
    assert cut.startswith("x" * 30 + "\n[cut:") and len(cut) <= 120  # no line break in reach: cut at a space


# ---------------------------------------------------------------------- what the run says


def test_the_run_says_what_route_and_recon_do_and_whether_their_calls_are_priced():
    from ctf_flightdeck import light as L
    from ctf_flightdeck.config import LightConfig

    local = L.build(LightConfig(engine="openai", model="m", base_url="http://127.0.0.1:9/v1"), None)
    paid = L.build(LightConfig(engine="anthropic", model="claude-haiku-5-5", base_url="http://127.0.0.1:9"), "unit-test-key")
    try:
        (shared,) = F.first_look_notes(L.Lights(engines={"judge": local, "route": local, "recon": local}))
        assert shared.startswith("light model: openai m routes each challenge (the specialist family it suits, and its "
                                 "category where the board names none flightdeck knows, shown as a guess, never in "
                                 "place of the board's) and writes a first look at each challenge's handout")
        assert "a lane never waits for it: what is not back by its first model call is left out of its brief" in shared
        assert "unpriced" not in shared  # a server on this machine costs nothing
        route, recon = F.first_look_notes(L.Lights(engines={"route": local, "recon": paid}))
        assert "routes each challenge" in route and "writes a first look" not in route
        assert recon.startswith("light model: anthropic claude-haiku-5-5 writes a first look")
        assert ("unpriced: a lane's dollar total is then only partly known, and its dollar cap holds on the part that "
                "is known (route and recon never make a lane ask you)") in recon
        assert F.first_look_notes(L.Lights(engines={"judge": local})) == [] and F.first_look_notes(None) == []
    finally:
        asyncio.run(local.aclose())
        asyncio.run(paid.aclose())
