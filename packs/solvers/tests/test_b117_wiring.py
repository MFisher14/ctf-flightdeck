"""B-117: the visual stego engines are wired into routing, the runner and intake.

One synthetic challenge folder holds a two-emoji stream, a Flash movie, an animated GIF and a
saved page; the router sends each file to its engine in an unrelated category, and intake runs
each engine as its own guarded process with no model and reads the flag out of its result."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

import b117_fixtures as fx
from ctf import event
from ctf.engines import manifest, router

pytestmark = pytest.mark.needs_tool("py:PIL", "py:qrcode")

REPO = Path(__file__).resolve().parents[1]
ENGINES = ("toolkits.symbol_stream", "toolkits.swf_parse", "toolkits.gif_reveal", "web.route_crawl")
BLUE, WHITE = "\U0001F7E6", "\u2b1c"
# Every engine process below gets this budget in place of intake's 40 to 60 s and the runner's
# defaults: on a machine loaded far past its cores a Python start alone can take that long. It is a
# guard against a hang, not a claim about speed.
BUDGET = 3600.0


def emoji_grid(flag):
    return "\n".join("".join(BLUE if cell else WHITE for cell in row) for row in fx.qr_modules(flag, 3)) + "\n"


def flash_movie(flag):
    frame = fx.avm1_pool(flag) + fx.avm1_push(("const", 0)) + fx.avm1(0x26) + b"\x00"
    return fx.swf_cws(fx.swf_body(fx.swf_tag(12, frame) + fx.swf_tag(0, b"")))


def animation(flag):
    return fx.gif_bytes([fx.bar_frame(0), fx.bar_frame(1)], comment=flag.encode())


def write_handout(folder: Path) -> dict:
    flags = {name: "CSCTF{wired_%s}" % name.split(".")[1] for name in ENGINES}
    folder.mkdir(parents=True)
    (folder / "theater.dat").write_text(emoji_grid(flags["toolkits.symbol_stream"]), encoding="utf-8")
    (folder / "flashback.swf").write_bytes(flash_movie(flags["toolkits.swf_parse"]))
    (folder / "feed.gif").write_bytes(animation(flags["toolkits.gif_reveal"]))
    (folder / "page.html").write_text(f"<html><!-- {flags['web.route_crawl']} --></html>", encoding="utf-8")
    return flags


def test_each_file_routes_to_its_engine_whatever_the_category(tmp_path):
    write_handout(tmp_path / "all")
    ids = [hit.manifest.id for hit in router.route("misc", "Operation Dawn", tmp_path / "all")]
    assert {"toolkits.symbol_stream", "toolkits.swf_parse", "toolkits.gif_reveal"} <= set(ids)
    assert ids[0] == "toolkits.swf_parse"                           # a Flash movie is the most telling file
    only_text = tmp_path / "text"
    only_text.mkdir()
    (only_text / "notes.txt").write_text("plain words, no symbols")
    assert not set(ENGINES) & {hit.manifest.id for hit in router.route("misc", "Operation Dawn", only_text)}
    # the block glyphs of a text drawing route too
    (only_text / "grid.txt").write_text("██  █\n", encoding="utf-8")
    assert "toolkits.symbol_stream" in {hit.manifest.id for hit in router.route("misc", "x", only_text)}


@pytest.mark.parametrize("category,brief,engine", [
    ("stego", "the file holds only two emoji, nothing else", "toolkits.symbol_stream"),
    ("misc", "an old flash game from the archive", "toolkits.swf_parse"),
    ("forensics", "watch the animated gif closely", "toolkits.gif_reveal"),
    ("web", "a camera feed nobody took down", "web.route_crawl"),
    ("stego", "a qr with a missing finder pattern", "toolkits.qr_matrix"),
])
def test_brief_words_route_to_the_engine(category, brief, engine, tmp_path):
    ids = [hit.manifest.id for hit in router.route(category, brief, tmp_path)]
    assert engine in ids[:3], ids[:6]
    assert engine not in [hit.manifest.id for hit in router.route("pwn", "a heap overflow in the allocator", tmp_path)]


def test_route_crawl_keywords_stay_in_the_web_lane(tmp_path):
    assert "web.route_crawl" not in [h.manifest.id for h in router.route("forensics", "a security camera recording", tmp_path)]


def test_manifests_declare_the_contract_entry_and_intake_adapter():
    by_id = {m.id: m for m in manifest.discover()}
    for name in ENGINES:
        m = by_id[name]
        assert m.entry_raw.endswith(":solve") and m.cost_class == "cheap" and m.status == "active"
        assert m.intake is not None and m.intake.run == "challenge" and m.intake.select == "files"
    # the one that starts tesseract says so, so intake runs it only under the OS sandbox; the
    # crawler's saved run leaves the frames of a saved GIF to it and starts nothing
    assert [by_id[name].intake.spawns for name in ENGINES] == [False, False, True, False]


def test_intake_runs_each_engine_with_no_model(tmp_path):
    from ctf.intake import engines as E
    from ctf.intake import guard as G
    cd = tmp_path / "117-visual"
    flags = write_handout(cd / "unpacked")
    allow = G.Guard("os", (), "test: spawn allowed, no OS wrapper (the suite sandbox denies the network)")
    plan = E.plan(manifest.discover(), "misc", "Operation Dawn", cd / "unpacked", guard=allow)
    jobs = {job.engine: job for job in plan.jobs}
    assert set(ENGINES) <= set(jobs)
    hook = E.plan(manifest.discover(), "misc", "Operation Dawn", cd / "unpacked", guard=G.Guard("hook", (), "test"))
    skipped = {skip.engine for skip in hook.skipped}
    assert "toolkits.gif_reveal" in skipped                          # it starts tesseract: OS guard only
    assert not {"toolkits.symbol_stream", "toolkits.swf_parse", "web.route_crawl"} & skipped
    ctx = E.Context(challenge_dir=cd, folder=cd / "unpacked", out_root=cd / "recon" / "engines",
                    profile=event.load("csctf"), guard=allow, root=REPO, python=sys.executable,
                    challenge_id="117", record=False)
    for name in ENGINES:
        run = E.run_job(jobs[name], ctx, timeout=BUDGET)
        assert run.status == "ok", (name, (cd / run.errors).read_text())
        assert flags[name] in run.flags, (name, run.flags, run.result_status)
    # each engine saw only its own material: the Flash movie's flag is not the stream reader's
    stream = E.run_job(jobs["toolkits.symbol_stream"], ctx, timeout=BUDGET)
    assert stream.flags == (flags["toolkits.symbol_stream"],) and stream.result_status == "solved"
    assert (cd / "recon" / "symbol_stream").is_dir() and (cd / "recon" / "swf_parse").is_dir()
    assert list((cd / "recon" / "gif_reveal").glob("unpacked_feed.gif.frame*.png"))


@pytest.mark.parametrize("engine", ENGINES)
def test_ctf_run_calls_the_engine_and_prints_its_result(engine, tmp_path):
    """`python -m ctf run <id> <challenge_dir>`: the documented way an agent runs one of these."""
    import json
    import os
    import subprocess
    from ctf.engines import runner
    cd = tmp_path / "ch"
    flags = write_handout(cd / "files")
    env = {**os.environ, "CTF_EVENT": "csctf", "CTF_WORKDIR": str(tmp_path / "work")}
    done = subprocess.run(runner.command(engine, [str(cd), "--opt", "ocr=off", "--opt", "seconds=3600"], record=False),
                          capture_output=True, text=True, env=env, cwd=REPO, timeout=BUDGET)
    assert done.returncode == 0, done.stderr
    result = json.loads(done.stdout.strip().splitlines()[-1])
    assert result["engine"] == engine and flags[engine] in result["flags"], result
    if engine == "web.route_crawl":
        # the crawler reads the saved GIF beside the page too: two different flags are candidates
        assert result["status"] == "candidate"
        assert result["flags"] == [flags["toolkits.gif_reveal"], flags["web.route_crawl"]]
    else:
        assert result["status"] == "solved" and result["flags"] == [flags[engine]]


def test_intake_defaults_of_the_two_gif_readers_fit_one_challenge_budget():
    """Intake gives one challenge 60 s for all its engines and passes no `seconds`: each engine runs
    on its own default. The two that read a saved GIF must leave room for each other and for the
    rest (round 1 of verification: 90 s and 40 s defaults spent the budget and lost a result)."""
    import gif_reveal
    import route_crawl
    from ctf.intake import DEFAULT_ENGINE_BUDGET
    by_id = {m.id: m for m in manifest.discover()}
    assert route_crawl.SAVED_SECONDS + gif_reveal.DEFAULT_SECONDS <= DEFAULT_ENGINE_BUDGET / 2
    for name, own in (("web.route_crawl", route_crawl.SAVED_SECONDS), ("toolkits.gif_reveal", gif_reveal.DEFAULT_SECONDS)):
        assert own < by_id[name].intake.timeout <= DEFAULT_ENGINE_BUDGET, name
