"""B-034: tool-output hygiene, the shared read map, and the `ctf read` command.

Each test fails when the behaviour under it is wrong: a cap that does not cap, a window rule that lets
a whole file through, a map that does not seed or that drops a concurrent agent's read, a read command
that floods, leaks a secret path, or does not refuse a whole-file window.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import os
import subprocess
import sys
import textwrap
import zipfile

import pytest

import archive_expand
from ctf import event, hygiene, paths, readmap, sweep
from ctf.cli import read as cli_read

_PROFILE = event.load("csctf")


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    monkeypatch.delenv("CTF_EVENT", raising=False)          # no event fence.toml layered on the deny roots
    monkeypatch.setattr(archive_expand.pw, "candidates", lambda: [b"infected"])


# --------------------------------------------------------------------------- hygiene: token estimate

def test_estimate_tokens_uses_the_bytes_per_token_ratio():
    assert hygiene.estimate_tokens("") == 0
    assert hygiene.estimate_tokens("a" * 360) == math.ceil(360 / hygiene.BYTES_PER_TOKEN)
    # multi-byte characters are counted by their UTF-8 length, not character count
    s = "€" * 100          # 3 bytes each
    assert hygiene.estimate_tokens(s) == math.ceil(300 / hygiene.BYTES_PER_TOKEN)
    assert hygiene.estimate_tokens(b"\x00\x01\x02") == math.ceil(3 / hygiene.BYTES_PER_TOKEN)


# --------------------------------------------------------------------------- hygiene: cap_text

def test_cap_text_leaves_small_output_untouched():
    cap = hygiene.cap_text("one\ntwo\nthree", max_tokens=hygiene.CAP_TOKENS)
    assert not cap.capped
    assert cap.text == "one\ntwo\nthree"
    assert cap.render() == "one\ntwo\nthree"       # no note appended when nothing was cut


def test_cap_text_caps_large_output_and_names_the_cut():
    body = "\n".join(f"line {i}" for i in range(1000))
    cap = hygiene.cap_text(body, max_tokens=40)
    assert cap.capped
    assert cap.shown_tokens <= 40 + 2             # whole lines only: at most one line of overshoot
    assert cap.shown_lines < cap.total_lines == 1000
    # the note is honest about how much was hidden and how to get it
    hidden = cap.total_lines - cap.shown_lines
    assert f"{hidden} of 1000 lines" in cap.note
    assert "--lines or --grep" in cap.note and "--no-cap" in cap.note
    assert cap.render().endswith(cap.note)
    # the kept text is the head of the input, in order
    assert cap.text.splitlines()[0] == "line 0"


def test_cap_text_max_lines_limit_is_enforced():
    body = "\n".join(str(i) for i in range(500))
    cap = hygiene.cap_text(body, max_tokens=hygiene.CAP_TOKENS, max_lines=10)
    assert cap.capped and cap.shown_lines == 10


def test_cap_text_head_tail_keeps_both_ends():
    body = "\n".join(f"L{i}" for i in range(1000))
    cap = hygiene.cap_text(body, max_tokens=60, keep="head-tail")
    assert cap.capped
    lines = cap.text.splitlines()
    assert lines[0] == "L0" and lines[-1] == "L999"
    assert any("elided" in ln for ln in lines)


def test_cap_text_head_tail_counts_exactly_the_elided_lines():
    body = "\n".join(f"L{i}" for i in range(1000))
    cap = hygiene.cap_text(body, max_tokens=60, keep="head-tail")
    lines = cap.text.split("\n")
    markers = [ln for ln in lines if "elided" in ln]
    assert len(markers) == 1
    kept = len(lines) - 1                                   # every line but the marker is an input line
    hidden = 1000 - kept
    assert markers[0] == f"... [ctf: {hidden} line(s) elided] ..."
    assert f"{hidden} of 1000 lines" in cap.note
    # the kept lines are a true head and a true tail of the input
    i = lines.index(markers[0])
    assert lines[:i] == [f"L{k}" for k in range(i)]
    assert lines[i + 1:] == [f"L{k}" for k in range(1000 - (kept - i), 1000)]


@pytest.mark.parametrize("kwargs", [{"max_tokens": 0}, {"max_tokens": -1}, {"max_lines": 0},
                                    {"keep": "middle"}])
def test_cap_text_rejects_bad_arguments(kwargs):
    with pytest.raises(hygiene.HygieneError):
        hygiene.cap_text("x", **kwargs)


# --------------------------------------------------------------------------- hygiene: window_advice

def test_window_advice_refuses_whole_file_and_large_windows():
    assert not hygiene.window_advice(None).ok           # whole file
    assert "whole-file window" in hygiene.window_advice(None).reason
    assert not hygiene.window_advice(hygiene.WINDOW_LINES).ok          # at the limit
    assert not hygiene.window_advice(hygiene.WINDOW_LINES + 50).ok
    assert hygiene.window_advice(hygiene.WINDOW_LINES - 1).ok          # just under
    assert hygiene.window_advice(10).ok


def test_window_advice_treats_a_query_as_targeted():
    # a grep of any size is targeted, even past the line cap
    assert hygiene.window_advice(10_000, query=True).ok
    assert hygiene.window_advice(None, query=True).ok


def test_looks_binary():
    assert not hygiene.looks_binary(b"plain ascii text\nwith newlines\n")
    assert hygiene.looks_binary(b"text\x00more")               # a NUL byte
    assert hygiene.looks_binary(bytes(range(0, 40)) * 10)      # mostly control bytes
    assert not hygiene.looks_binary(b"")


def test_looks_binary_threshold_without_a_nul_byte():
    # 40% control bytes (no NUL) is binary; 20% is text with some noise
    noisy = (b"\x01\x02\x03\x04" + b"abcdef") * 100
    assert b"\x00" not in noisy and hygiene.looks_binary(noisy)
    mild = (b"\x01\x02" + b"abcdefgh") * 100
    assert not hygiene.looks_binary(mild)


# --------------------------------------------------------------------------- readmap

def _sweep_dir(tmp_path, *files):
    """A pulled challenge (challenge.json + files/) swept by the real ctf.sweep, so the map seeds from
    the manifest the sweep actually writes (originals' scratch paths are unpacked/..., not files/...)."""
    d = tmp_path / "chal"
    (d / "files").mkdir(parents=True)
    (d / "challenge.json").write_text(json.dumps({"id": 1, "name": "x", "category": "Forensics",
                                                  "description": ""}))
    for name, content in files:
        (d / "files" / name).write_bytes(content)
    sweep.sweep(d, _PROFILE)
    return d


def _zip(members: dict) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        for n, data in members.items():
            z.writestr(n, data)
    return bio.getvalue()


def test_readmap_seeds_from_the_sweep_manifest(tmp_path):
    d = _sweep_dir(tmp_path, ("a.txt", b"aaa\n"), ("b.txt", b"bbbb\n"),
                   ("h.zip", _zip({"inner.txt": b"inner text\n"})))
    raw = json.loads((d / readmap.SWEEP_PATH).read_text())
    # the real manifest records an original's scratch-copy path, which ctf read never reads by
    assert {e["path"] for e in raw["manifest"] if e["original"]} == {
        "unpacked/a.txt", "unpacked/b.txt", "unpacked/h.zip"}
    m = readmap.ReadMap.open(d)
    # originals are keyed where they live (the path ctf read records), members by their scratch path
    assert {"files/a.txt", "files/b.txt", "files/h.zip"} <= set(m.entries)
    assert "unpacked/a.txt" not in m.entries
    member = [p for p in m.entries if p.endswith("inner.txt")]
    assert member == ["unpacked/h.zip.unpacked/inner.txt"]
    assert m.lookup(member[0]).sha256 == hashlib.sha256(b"inner text\n").hexdigest()
    a = m.lookup("files/a.txt")
    assert a.size == 4 and a.sha256 == hashlib.sha256(b"aaa\n").hexdigest() and a.kind
    assert a.reads == []            # seeded, not yet read


def test_seeded_hash_links_a_read_of_the_scratch_copy_to_the_original(tmp_path, capsys):
    d = _sweep_dir(tmp_path, ("notes.txt", b"".join(b"row %d\n" % i for i in range(20))))
    # alice reads the sweep's scratch copy; bob then reads the original: same bytes, so bob is told
    assert cli_read.run(_args(path=str(d / "unpacked" / "notes.txt"), lines="1-5", agent="alice")) == 0
    capsys.readouterr()
    assert cli_read.run(_args(path=str(d / "files" / "notes.txt"), lines="2-4", agent="bob")) == 0
    out = capsys.readouterr().out
    assert "already read by alice" in out and "the same bytes as unpacked/notes.txt" in out
    # the read is recorded against the original's seeded entry, which kept intake's hash
    ent = readmap.ReadMap.load(d).lookup("files/notes.txt")
    assert [r.agent for r in ent.reads] == ["bob"] and ent.kind


def test_readmap_without_a_sweep_is_empty_not_an_error(tmp_path):
    (tmp_path / "chal" / "recon").mkdir(parents=True)
    m = readmap.ReadMap.open(tmp_path / "chal")
    assert m.entries == {}


def test_readmap_refuses_a_corrupt_sweep(tmp_path):
    d = tmp_path / "chal"
    (d / "unpacked").mkdir(parents=True)
    (d / "unpacked" / ".sweep.json").write_text("{not json")
    with pytest.raises(readmap.ReadMapError):
        readmap.ReadMap.open(d)


def test_readmap_refuses_a_wrong_schema_map(tmp_path):
    d = tmp_path / "chal"
    (d / "recon").mkdir(parents=True)
    (d / readmap.MAP_PATH).write_text(json.dumps({"schema": 99, "entries": []}))
    with pytest.raises(readmap.ReadMapError):
        readmap.ReadMap.load(d)


def test_prior_reads_finds_another_agent_but_not_your_own(tmp_path):
    d = _sweep_dir(tmp_path, ("a.txt", b"a"))
    m = readmap.ReadMap.open(d)
    m.record("files/a.txt", "sha", 1, "text", "lines:1-5", tokens=10, agent="alice", at=1.0)
    assert m.prior_reads("files/a.txt", "lines:1-5", exclude_agent="alice") == []
    other = m.prior_reads("files/a.txt", "lines:1-5", exclude_agent="bob")
    assert len(other) == 1 and other[0].agent == "alice"
    # a different selector is a different read
    assert m.prior_reads("files/a.txt", "lines:6-9", exclude_agent="bob") == []


def test_save_merges_a_concurrent_agents_record(tmp_path):
    d = _sweep_dir(tmp_path, ("a.txt", b"a"))
    a = readmap.ReadMap.open(d)
    b = readmap.ReadMap.open(d)               # both load the same seeded map before either writes
    a.record("files/a.txt", "sha", 1, "text", "lines:1-5", tokens=10, agent="alice", at=1.0)
    a.save()
    b.record("files/a.txt", "sha", 1, "text", "grep:flag", tokens=7, agent="bob", at=2.0)
    b.save()                                  # b loaded before a saved: must not drop alice's read
    final = readmap.ReadMap.load(d)
    reads = final.lookup("files/a.txt").reads
    agents = sorted((r.agent, r.selector) for r in reads)
    assert agents == [("alice", "lines:1-5"), ("bob", "grep:flag")]


def test_save_does_not_duplicate_the_same_read(tmp_path):
    d = _sweep_dir(tmp_path, ("a.txt", b"a"))
    m = readmap.ReadMap.open(d)
    m.record("files/a.txt", "sha", 1, "text", "lines:1-5", tokens=10, agent="alice", at=1.0)
    m.save()
    m.save()                                  # saving twice must not double the read
    final = readmap.ReadMap.load(d)
    assert len(final.lookup("files/a.txt").reads) == 1


def test_agent_id_reads_ctf_agent(monkeypatch):
    monkeypatch.delenv("CTF_AGENT", raising=False)
    assert readmap.agent_id() == "agent"
    assert readmap.agent_id(environ={"CTF_AGENT": "worker-3"}) == "worker-3"


# --------------------------------------------------------------------------- ctf read CLI

def _args(**over):
    p = argparse.ArgumentParser()
    cli_read.add_arguments(p)
    defaults = {"lines": None, "grep": None, "around": 2, "max_tokens": hygiene.CAP_TOKENS,
                "max_lines": None, "full": False, "no_cap": False, "bytes": None, "map": None,
                "no_map": False, "agent": None}
    ns = argparse.Namespace(**{**defaults, **over})
    return ns


def _chal(tmp_path, name="notes.txt", nlines=300):
    d = tmp_path / "chal"
    (d / "files").mkdir(parents=True)
    (d / "recon").mkdir(parents=True)
    (d / "challenge.json").write_text("{}")
    body = "\n".join(f"line {i} content" for i in range(nlines))
    (d / "files" / name).write_bytes(body.encode())
    return d, d / "files" / name


def test_read_refuses_a_whole_file_window(tmp_path, capsys):
    d, f = _chal(tmp_path)
    assert cli_read.run(_args(path=str(f))) == 1
    err = capsys.readouterr().err
    assert "refused" in err and "window" in err
    # nothing printed to stdout: the flood did not happen
    assert capsys.readouterr().out == ""


def test_read_full_allows_the_whole_file_but_still_caps(tmp_path, capsys):
    d, f = _chal(tmp_path)
    assert cli_read.run(_args(path=str(f), full=True, max_tokens=40)) == 0
    out = capsys.readouterr().out
    assert "1:line 0 content" in out
    assert "output capped" in out                 # the cap note is present
    assert "line 299 content" not in out          # and the tail did not come through


def test_read_full_no_cap_prints_everything(tmp_path, capsys):
    d, f = _chal(tmp_path, nlines=200)
    assert cli_read.run(_args(path=str(f), full=True, no_cap=True)) == 0
    out = capsys.readouterr().out
    assert "200:line 199 content" in out and "output capped" not in out


def test_read_large_range_is_refused_small_range_is_served(tmp_path, capsys):
    d, f = _chal(tmp_path)
    assert cli_read.run(_args(path=str(f), lines="1-200")) == 1
    assert "large window" in capsys.readouterr().err
    assert cli_read.run(_args(path=str(f), lines="5-8")) == 0
    out = capsys.readouterr().out
    assert "5:line 4 content" in out and "8:line 7 content" in out and "9:line 8 content" not in out


def test_read_grep_returns_matches_with_context(tmp_path, capsys):
    d, f = _chal(tmp_path)
    assert cli_read.run(_args(path=str(f), grep="line 42 ", around=1)) == 0
    out = capsys.readouterr().out
    assert "43:line 42 content" in out and "42:line 41 content" in out and "44:line 43 content" in out


def test_read_refuses_a_secret_path(tmp_path, capsys):
    (tmp_path / ".env").write_text("CTF_TOKEN=secret")
    assert cli_read.run(_args(path=str(tmp_path / ".env"))) == cli_read.REFUSED_EXIT
    out = capsys.readouterr()
    assert "secret" in out.err and "secret" not in out.out and out.out == ""


def test_read_missing_file_is_an_error(tmp_path, capsys):
    assert cli_read.run(_args(path=str(tmp_path / "nope.txt"))) == 2
    assert "no such file" in capsys.readouterr().err


def test_read_binary_gets_a_summary_not_a_dump_and_hex_preview_is_offered(tmp_path, capsys):
    # B-199 changed the binary default from a refusal (exit 1) to the binary-first summary (exit 0);
    # the summary's content is tested in tests/test_b199_reading.py
    f = tmp_path / "blob.bin"
    f.write_bytes(bytes(range(256)) * 4)
    assert cli_read.run(_args(path=str(f), no_map=True)) == 0
    out = capsys.readouterr().out
    assert out.startswith("[binary] blob.bin: 1024 bytes")
    assert out.count("\n") < 40                   # a summary, not 1024 bytes of hex
    assert cli_read.run(_args(path=str(f), bytes=32, no_map=True)) == 0
    out = capsys.readouterr().out
    assert "00000000" in out                       # a hex offset column


def test_read_records_in_the_shared_map_and_warns_a_second_agent(tmp_path, capsys):
    d, f = _chal(tmp_path)
    assert cli_read.run(_args(path=str(f), grep="line 7 ", agent="alice")) == 0
    capsys.readouterr()
    # the map now holds alice's grep read
    m = readmap.ReadMap.load(d)
    ent = m.lookup("files/notes.txt")
    assert ent is not None and any(r.agent == "alice" and r.selector == "grep:line 7 " for r in ent.reads)
    # a second agent making the same read is told it was already read
    assert cli_read.run(_args(path=str(f), grep="line 7 ", agent="bob")) == 0
    out = capsys.readouterr().out
    assert "already read by alice" in out


def test_read_no_map_does_not_touch_the_map(tmp_path, capsys):
    d, f = _chal(tmp_path)
    assert cli_read.run(_args(path=str(f), lines="1-3", no_map=True)) == 0
    assert not (d / readmap.MAP_PATH).exists()


# --------------------------------------------------------------------------- readmap: round-1 fixes

_SAVER = textwrap.dedent("""
    import os, sys, time
    sys.path.insert(0, sys.argv[1])
    from ctf import readmap
    d, me, go, n = sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
    while not os.path.exists(go):
        time.sleep(0.002)
    for i in range(n):
        m = readmap.ReadMap.open(d)
        m.record("files/a.txt", "s" * 64, 1, "text", f"lines:{i + 1}-{i + 1}", tokens=1, agent=me,
                 at=1000.0 + i)
        m.save()
""")


def test_concurrent_saves_from_many_processes_keep_every_record(tmp_path):
    d = tmp_path / "chal"
    (d / "recon").mkdir(parents=True)
    script = tmp_path / "saver.py"
    script.write_text(_SAVER)
    go = tmp_path / "go"
    procs, n = 6, 20
    env_ = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    ps = [subprocess.Popen([sys.executable, "-I", str(script), str(paths.repo_root()), str(d), f"w{k}",
                            str(go), str(n)], env=env_, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
          for k in range(procs)]
    go.write_text("go")                                   # all six start saving at the same moment
    for p in ps:
        out, err = p.communicate(timeout=120)
        assert p.returncode == 0, err.decode()
    reads = readmap.ReadMap.load(d).lookup("files/a.txt").reads
    assert len(reads) == procs * n                        # no save overwrote another's records
    assert {(r.agent, r.selector) for r in reads} == {(f"w{k}", f"lines:{i + 1}-{i + 1}")
                                                      for k in range(procs) for i in range(n)}
    assert not list((d / "recon").glob("*.tmp"))


def test_save_fills_a_blank_hash_from_this_map_and_takes_a_newer_one(tmp_path):
    d = tmp_path / "chal"
    (d / "recon").mkdir(parents=True)
    first = readmap.ReadMap.open(d)
    first.record("files/a.txt", "", 0, "text", "grep:x", tokens=1, agent="alice", at=1.0)
    first.save()
    assert readmap.ReadMap.load(d).lookup("files/a.txt").sha256 == ""
    other = readmap.ReadMap(file=d / readmap.MAP_PATH,
                            entries={"files/a.txt": readmap.FileEntry("files/a.txt", "a" * 64, 7, "text")})
    other.save()                                          # no reads of its own, but it knows the hash
    ent = readmap.ReadMap.load(d).lookup("files/a.txt")
    assert ent.sha256 == "a" * 64 and ent.size == 7
    # the file changed: a later read of the new content makes the entry's hash the new one
    later = readmap.ReadMap.load(d)
    later.record("files/a.txt", "b" * 64, 9, "text", "grep:y", tokens=1, agent="bob", at=5.0)
    later.save()
    ent = readmap.ReadMap.load(d).lookup("files/a.txt")
    assert ent.sha256 == "b" * 64 and ent.size == 9
    # a map that loaded before the change and saves an older read does not roll the hash back
    stale = readmap.ReadMap(file=d / readmap.MAP_PATH, entries={"files/a.txt": readmap.FileEntry(
        "files/a.txt", "a" * 64, 7, "text", [readmap.FileRead("carol", 2.0, "grep:z", 1, "a" * 64)])})
    stale.save()
    assert readmap.ReadMap.load(d).lookup("files/a.txt").sha256 == "b" * 64


def test_prior_reads_are_oldest_first(tmp_path):
    m = readmap.ReadMap(file=tmp_path / "m.json")
    m.record("f", "s", 1, "text", "grep:x", tokens=1, agent="late", at=30.0)
    m.record("f", "s", 1, "text", "grep:x", tokens=1, agent="early", at=10.0)
    m.record("f", "s", 1, "text", "grep:x", tokens=1, agent="mid", at=20.0)
    assert [r.agent for r in m.prior_reads("f", "grep:x")] == ["early", "mid", "late"]
    assert [r.agent for r in m.prior_reads("f", "grep:x", sha256="s")] == ["early", "mid", "late"]


@pytest.mark.parametrize("earlier,now,want", [
    ("lines:1-40", "lines:1-39", True), ("lines:1-40", "lines:40-60", True),
    ("lines:1-40", "lines:41-60", False), ("lines:50-60", "lines:1-49", False),
    ("full", "lines:5-9", True), ("lines:5-9", "full", True), ("full", "full", True),
    ("grep:a", "grep:a", True), ("grep:a", "grep:b", False), ("grep:a", "lines:1-5", False),
    ("full", "grep:a", False), ("bytes:16", "bytes:64", True), ("bytes:16", "lines:1-2", False),
])
def test_overlaps(earlier, now, want):
    assert readmap.overlaps(earlier, now) is want


def test_prior_reads_counts_an_overlapping_range_but_not_changed_content(tmp_path):
    m = readmap.ReadMap(file=tmp_path / "m.json")
    m.record("f", "old", 1, "text", "lines:1-40", tokens=1, agent="alice", at=1.0)
    assert [r.agent for r in m.prior_reads("f", "lines:1-39", exclude_agent="bob")] == ["alice"]
    assert m.prior_reads("f", "lines:41-50", exclude_agent="bob") == []
    # the file changed since alice read it: her read is not of these bytes
    assert m.prior_reads("f", "lines:1-39", sha256="new") == []
    assert [r.agent for r in m.prior_reads("f", "lines:1-39", sha256="old")] == ["alice"]
    # bob then reads the new bytes (the entry's hash moves on): alice's read is still of the old bytes
    m.record("f", "new", 1, "text", "lines:1-40", tokens=1, agent="bob", at=3.0)
    assert m.lookup("f").sha256 == "new" and m.lookup("f").reads[0].sha256 == "old"
    assert [r.agent for r in m.prior_reads("f", "lines:1-39", sha256="new")] == ["bob"]
    # same bytes under another path count when the hash is given
    m.record("g", "same", 1, "text", "grep:k", tokens=1, agent="alice", at=2.0)
    assert [r.agent for r in m.prior_reads("h", "grep:k", sha256="same")] == ["alice"]
    assert m.prior_reads("h", "grep:k") == []


def test_open_seeds_a_sweep_even_when_a_read_came_first(tmp_path):
    d = _sweep_dir(tmp_path, ("a.txt", b"aaa\n"), ("b.txt", b"bbb\n"))
    early = readmap.ReadMap.load(d)
    early.record("files/a.txt", hashlib.sha256(b"aaa\n").hexdigest(), 4, "text", "grep:a", tokens=1,
                 agent="alice", at=1.0)
    early.save()                                         # the map now exists, without b.txt
    m = readmap.ReadMap.open(d)
    assert "files/b.txt" in m.entries and len(m.lookup("files/a.txt").reads) == 1


# --------------------------------------------------------------------------- ctf read: round-1 fixes

def test_read_same_agent_is_told_it_already_read_the_content(tmp_path, capsys):
    d, f = _chal(tmp_path)
    assert cli_read.run(_args(path=str(f), lines="1-40", agent="alice")) == 0
    first = capsys.readouterr().out
    assert "already read" not in first
    assert cli_read.run(_args(path=str(f), lines="1-39", agent="alice")) == 0
    out = capsys.readouterr().out
    assert "you (alice) already read files/notes.txt (lines:1-40, overlapping)" in out
    assert "already read by" not in out
    # the file changes: the earlier read no longer counts
    f.write_bytes(f.read_bytes() + b"\nappended")
    assert cli_read.run(_args(path=str(f), lines="1-39", agent="alice")) == 0
    assert "already read" not in capsys.readouterr().out


def test_read_range_running_past_the_end_is_clamped(tmp_path, capsys):
    d, f = _chal(tmp_path)                                # 300 lines
    assert cli_read.run(_args(path=str(f), lines="290-400", agent="a")) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "290:line 289 content" and out[-1] == "300:line 299 content" and len(out) == 11
    sels = [r.selector for r in readmap.ReadMap.load(d).lookup("files/notes.txt").reads]
    assert sels == ["lines:290-300"]


@pytest.mark.parametrize("spec", ["500", "400-450", "301-"])
def test_read_range_starting_past_the_end_is_a_named_error(tmp_path, capsys, spec):
    d, f = _chal(tmp_path)
    assert cli_read.run(_args(path=str(f), lines=spec)) == 2
    cap = capsys.readouterr()
    assert "past the end of the file (300 lines)" in cap.err and cap.out == ""


def test_read_bad_grep_pattern_is_a_named_error(tmp_path, capsys):
    d, f = _chal(tmp_path)
    assert cli_read.run(_args(path=str(f), grep="(")) == 2
    cap = capsys.readouterr()
    assert "bad --grep pattern" in cap.err and cap.out == ""


def test_read_a_trailing_newline_is_not_a_line(tmp_path, capsys):
    d = tmp_path / "chal"
    (d / "recon").mkdir(parents=True)
    f149 = d / "a.txt"
    f149.write_text("".join(f"r{i}\n" for i in range(149)))
    assert cli_read.run(_args(path=str(f149))) == 0          # 149 lines is under the 150-line window
    out = capsys.readouterr().out.splitlines()
    assert out[-1] == "149:r148" and not any(ln.startswith("150:") for ln in out)
    f150 = d / "b.txt"
    f150.write_text("".join(f"r{i}\n" for i in range(150)))
    assert cli_read.run(_args(path=str(f150))) == 1          # 150 lines is the window limit


def test_read_bytes_preview_is_capped(tmp_path, capsys):
    f = tmp_path / "blob.bin"
    f.write_bytes(bytes(range(256)) * 2000)
    assert cli_read.run(_args(path=str(f), bytes=300000, no_map=True)) == 0
    out = capsys.readouterr().out
    assert "output capped" in out
    assert hygiene.estimate_tokens(out) < hygiene.CAP_TOKENS + 200
    assert cli_read.run(_args(path=str(f), bytes=0, no_map=True)) == 2


def test_read_refuses_a_symlink_into_a_credentials_folder(tmp_path, capsys):
    d, f = _chal(tmp_path)
    (d / ".ctf").mkdir()
    (d / ".ctf" / "tok").write_text("SYNTHETIC-NOT-A-TOKEN")
    (d / "files" / "link.txt").symlink_to("../.ctf/tok")
    assert cli_read.run(_args(path=str(d / "files" / "link.txt"))) == cli_read.REFUSED_EXIT
    cap = capsys.readouterr()
    assert "symbolic link" in cap.err and "SYNTHETIC" not in cap.out + cap.err
    # a linked parent folder is caught by resolving the path
    (d / "files" / "sub").symlink_to("../.ctf")
    assert cli_read.run(_args(path=str(d / "files" / "sub" / "tok"))) == cli_read.REFUSED_EXIT
    cap = capsys.readouterr()
    assert ".ctf" in cap.err and "SYNTHETIC" not in cap.out + cap.err


def test_read_refuses_a_git_folder(tmp_path, capsys):
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    (tmp_path / "repo" / ".git" / "config").write_text("[credential]\n")
    assert cli_read.run(_args(path=str(tmp_path / "repo" / ".git" / "config"))) == cli_read.REFUSED_EXIT
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("store", [".codex/auth.json", ".claude/settings.json", ".ssh/id_x",
                                   "Library/Cookies/c.bin"])
def test_read_refuses_a_fence_denied_home_store(tmp_path, monkeypatch, capsys, store):
    home = tmp_path / "home"
    target = home / store
    target.parent.mkdir(parents=True)
    target.write_text("SYNTHETIC-NOT-A-SECRET")
    monkeypatch.setenv("HOME", str(home))
    assert cli_read.run(_args(path="~/" + store)) == cli_read.REFUSED_EXIT
    cap = capsys.readouterr()
    assert "read fence denies" in cap.err and cap.out == ""
    # a file elsewhere under the same home is not a denied store
    ok = home / "work" / "n.txt"
    ok.parent.mkdir()
    ok.write_text("fine\n")
    assert cli_read.run(_args(path="~/work/n.txt", no_map=True)) == 0
    assert "1:fine" in capsys.readouterr().out


def test_read_env_files_follow_the_sweeps_rule(tmp_path, capsys):
    loose = tmp_path / "proj"
    loose.mkdir()
    (loose / ".env.local").write_text("K=SYNTHETIC")
    assert cli_read.run(_args(path=str(loose / ".env.local"))) == cli_read.REFUSED_EXIT
    assert capsys.readouterr().out == ""
    # a .env the platform handed out in a pulled challenge's files/ is challenge data, as in the sweep
    d, _ = _chal(tmp_path)
    (d / "files" / ".env").write_text("APP_KEY=challenge-data\n")
    assert cli_read.run(_args(path=str(d / "files" / ".env"))) == 0
    assert "1:APP_KEY=challenge-data" in capsys.readouterr().out


def test_read_infers_a_challenge_dir_from_recon_alone(tmp_path, capsys):
    d = tmp_path / "chal"
    (d / "recon").mkdir(parents=True)
    (d / "logs").mkdir()
    (d / "logs" / "a.txt").write_text("hello\n")
    assert cli_read.run(_args(path=str(d / "logs" / "a.txt"), lines="1", agent="x")) == 0
    assert readmap.ReadMap.load(d).lookup("logs/a.txt").reads[0].selector == "lines:1-1"


def test_read_without_a_challenge_dir_says_the_read_is_not_recorded(tmp_path, capsys):
    f = tmp_path / "loose.txt"
    f.write_text("x\n")
    assert cli_read.run(_args(path=str(f))) == 0
    cap = capsys.readouterr()
    assert "not recorded" in cap.err and "1:x" in cap.out


def test_read_map_errors_exit_2_and_print_nothing(tmp_path, capsys):
    d, f = _chal(tmp_path)
    (d / readmap.MAP_PATH).write_text("{broken")
    assert cli_read.run(_args(path=str(f), lines="1-3")) == 2
    cap = capsys.readouterr()
    assert "shared read map unavailable" in cap.err and cap.out == ""
    # --no-map still reads
    assert cli_read.run(_args(path=str(f), lines="1-3", no_map=True)) == 0
    capsys.readouterr()
    # --map at a folder that is not there is an error, and creates nothing
    nowhere = tmp_path / "nowhere"
    assert cli_read.run(_args(path=str(f), lines="1-3", map=str(nowhere))) == 2
    assert "not a directory" in capsys.readouterr().err and not nowhere.exists()


# --------------------------------------------------------------------------- round 2 (verification)

def test_read_refuses_a_linked_parent_into_a_git_folder(tmp_path, capsys):
    # .git/ is not one of the fence's DENY_NAMES, so only the resolved-path check catches this
    d, _ = _chal(tmp_path)
    (d / ".git").mkdir()
    (d / ".git" / "config").write_text("[credential]\nhelper = SYNTHETIC-NOT-A-SECRET\n")
    (d / "files" / "g").symlink_to("../.git")
    assert cli_read.run(_args(path=str(d / "files" / "g" / "config"))) == cli_read.REFUSED_EXIT
    cap = capsys.readouterr()
    assert ".git/" in cap.err and cap.out == "" and "SYNTHETIC" not in cap.err


@pytest.mark.parametrize("spelling", [".CTF/tok", "files/../.Ctf/tok", ".GIT/config", ".Git/config",
                                      ".ENV"])
def test_read_secret_names_are_compared_case_folded(tmp_path, capsys, spelling):
    # the default macOS volume is case-insensitive: .CTF/tok opens .ctf/tok
    d, _ = _chal(tmp_path)
    (d / ".ctf").mkdir()
    (d / ".ctf" / "tok").write_text("SYNTHETIC-NOT-A-TOKEN")
    (d / ".git").mkdir()
    (d / ".git" / "config").write_text("SYNTHETIC-NOT-A-TOKEN")
    (d / ".env").write_text("SYNTHETIC-NOT-A-TOKEN")
    assert cli_read.run(_args(path=str(d) + "/" + spelling, no_map=True)) == cli_read.REFUSED_EXIT
    cap = capsys.readouterr()
    assert cap.out == "" and "SYNTHETIC" not in cap.err


@pytest.mark.parametrize("store", [".CODEX/auth.json", ".Claude/settings.json", ".SSH/id_x",
                                   "library/cookies/c.bin"])
def test_read_fence_stores_are_compared_case_folded(tmp_path, monkeypatch, capsys, store):
    home = tmp_path / "home"
    target = home / store.lower()
    target.parent.mkdir(parents=True)
    target.write_text("SYNTHETIC-NOT-A-SECRET")
    monkeypatch.setenv("HOME", str(home))
    assert cli_read.run(_args(path="~/" + store, no_map=True)) == cli_read.REFUSED_EXIT
    cap = capsys.readouterr()
    assert "read fence denies" in cap.err and cap.out == ""


def test_read_uses_the_fences_notification_rule(tmp_path, monkeypatch, capsys):
    # build()'s DARWIN_USER_DIR rule is part of the reader's fence too (one source: fence.read_fence)
    ud = tmp_path / "ud"
    db = ud / "com.apple.notificationcenter" / "db2" / "db"
    db.parent.mkdir(parents=True)
    db.write_text("SYNTHETIC")
    monkeypatch.setattr(cli_read._fence, "darwin_user_dir", lambda: ud)
    assert cli_read.run(_args(path=str(db), no_map=True)) == cli_read.REFUSED_EXIT
    assert "notifications" in capsys.readouterr().err
    other = ud / "other.txt"
    other.write_text("ok\n")
    assert cli_read.run(_args(path=str(other), no_map=True)) == 0


def test_read_honours_the_events_strict_home(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    (home / "other").mkdir(parents=True)
    (home / "other" / "n.txt").write_text("private\n")
    (home / "work" / "c").mkdir(parents=True)
    (home / "work" / "c" / "n.txt").write_text("challenge\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CTF_EVENT", "ev")
    monkeypatch.setenv("CTF_WORKDIR", str(home / "work"))
    monkeypatch.setattr(cli_read._fence, "load_config",
                        lambda slug: cli_read._fence.FenceConfig(strict_home=slug == "ev"))
    assert cli_read.run(_args(path=str(home / "other" / "n.txt"), no_map=True)) == cli_read.REFUSED_EXIT
    cap = capsys.readouterr()
    assert "home" in cap.err and cap.out == ""
    # the event's workspace stays readable in strict mode
    assert cli_read.run(_args(path=str(home / "work" / "c" / "n.txt"), no_map=True)) == 0
    assert "1:challenge" in capsys.readouterr().out


def test_read_fence_has_the_same_rules_as_build(tmp_path):
    from ctf import fence
    home, repo, ws, ud = (tmp_path / n for n in ("home", "repo", "ws", "ud"))
    cfg = fence.FenceConfig(drop_folder=home / "Downloads" / "ev", allow_read=(tmp_path / "extra",),
                            deny_read=(tmp_path / "op",), strict_home=True)
    built = fence.from_config(cfg, repo=repo, workspace=ws, home=home, user_dir=ud, toolchain=())
    rf = fence.read_fence(cfg, repo=repo, workspace=ws, home=home, user_dir=ud)
    assert rf.deny == built.deny and rf.deny_names == built.deny_names
    assert (rf.drop, rf.extra_read, rf.strict_home) == (built.drop, built.extra_read, True)
    assert any(d.category == "notifications" for d in rf.deny)
    assert any(d.category == "home" for d in rf.deny)
    # without a workspace the repo stands in (outside an event there is none)
    assert fence.read_fence(fence.FenceConfig(), repo=repo, home=home, user_dir=None).workspace == repo


def test_read_bytes_is_one_selection(tmp_path, capsys):
    d, f = _chal(tmp_path)
    p = argparse.ArgumentParser()
    cli_read.add_arguments(p)
    for other in (["--lines", "1-3"], ["--grep", "line"]):
        with pytest.raises(SystemExit) as e:
            p.parse_args([str(f), "--bytes", "16", *other])
        assert e.value.code == 2
    capsys.readouterr()
    # a Namespace built by a caller is refused too, not silently resolved one way
    assert cli_read.run(_args(path=str(f), bytes=16, lines="1-3")) == 2
    cap = capsys.readouterr()
    assert "--bytes cannot be combined" in cap.err and cap.out == ""
    assert cli_read.run(_args(path=str(f), bytes=16, grep="line")) == 2


def test_read_path_outside_map_dir_is_refused(tmp_path, capsys):
    d, f = _chal(tmp_path)
    other = tmp_path / "other"
    (other / "recon").mkdir(parents=True)
    g = tmp_path / "notes.txt"
    g.write_text("x\n")
    assert cli_read.run(_args(path=str(g), lines="1", map=str(other))) == 2
    cap = capsys.readouterr()
    assert "not inside --map" in cap.err and cap.out == ""
    assert not (other / readmap.MAP_PATH).exists()
    # a PATH under --map DIR is keyed by its path there
    assert cli_read.run(_args(path=str(f), lines="1", map=str(d), agent="a")) == 0
    assert readmap.ReadMap.load(d).lookup("files/notes.txt") is not None
    # --no-map ignores --map entirely
    assert cli_read.run(_args(path=str(g), lines="1", map=str(other), no_map=True)) == 0


def test_read_infers_the_challenge_dir_through_a_linked_parent(tmp_path, capsys):
    # the map key is the file's real path under the challenge that holds it
    d, f = _chal(tmp_path)
    (tmp_path / "view").mkdir()
    (tmp_path / "view" / "files").symlink_to(d / "files")
    assert cli_read.run(_args(path=str(tmp_path / "view" / "files" / "notes.txt"), lines="1", agent="a")) == 0
    assert readmap.ReadMap.load(d).lookup("files/notes.txt") is not None
