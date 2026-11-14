"""B-178: per-challenge scratch under <challenge>/.scratch with a per-pass manifest (ctf.scratch)."""
from __future__ import annotations

import hashlib
import json
import os
import threading

import pytest

from ctf import scratch
from ctf.cli import main as ctf_main


@pytest.fixture
def wd(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    (tmp_path / "12-web-login").mkdir()
    (tmp_path / "7-rev").mkdir()
    (tmp_path / "70-other").mkdir()
    return tmp_path


def test_challenge_dir_resolves_id_prefix_exact_and_path(wd):
    assert scratch.challenge_dir("12") == (wd / "12-web-login").resolve()
    assert scratch.challenge_dir("12-web-login") == (wd / "12-web-login").resolve()
    # "7" must not match "70-other": the id is followed by "-"
    assert scratch.challenge_dir("7") == (wd / "7-rev").resolve()
    assert scratch.challenge_dir(str(wd / "70-other")) == (wd / "70-other").resolve()


def test_challenge_dir_missing_and_ambiguous_fail_by_name(wd):
    with pytest.raises(scratch.ScratchError, match="no challenge folder for '99'"):
        scratch.challenge_dir("99")
    (wd / "12-second").mkdir()
    with pytest.raises(scratch.ScratchError, match="ambiguous"):
        scratch.challenge_dir("12")
    with pytest.raises(scratch.ScratchError, match="does not exist"):
        scratch.challenge_dir(str(wd / "nope"))


def test_open_pass_numbers_sequentially_and_writes_open_manifest(wd):
    chal = wd / "12-web-login"
    p1 = scratch.open_pass(chal, "Angr sweep!", agent="rev-1", goal="g1", now=100.0)
    p2 = scratch.open_pass(chal, "second try")
    assert p1.name == "001-angr-sweep" and p2.name == "002-second-try"
    assert p1.parent == chal / ".scratch"
    m = json.loads((p1 / "MANIFEST.json").read_text())
    assert m["status"] == "open" and m["agent"] == "rev-1" and m["goal"] == "g1"
    assert m["purpose"] == "Angr sweep!" and m["started"] == 100.0 and m["files"] is None


def test_open_pass_rejects_empty_purpose_and_missing_folder(wd):
    with pytest.raises(scratch.ScratchError, match="purpose"):
        scratch.open_pass(wd / "12-web-login", "!!!")
    with pytest.raises(scratch.ScratchError, match="does not exist"):
        scratch.open_pass(wd / "nope", "x")


def test_concurrent_opens_never_share_a_number(wd):
    chal = wd / "12-web-login"
    out, errs = [], []

    def go(i):
        try:
            out.append(scratch.open_pass(chal, f"worker {i}").name.split("-")[0])
        except Exception as e:  # pragma: no cover - reported below
            errs.append(e)

    ts = [threading.Thread(target=go, args=(i,)) for i in range(12)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errs
    assert sorted(out) == [f"{i:03d}" for i in range(1, 13)]


def test_close_records_every_file_with_sha256_and_never_follows_symlinks(wd, tmp_path):
    chal = wd / "12-web-login"
    p = scratch.open_pass(chal, "work")
    (p / "out.bin").write_bytes(b"abc")
    (p / "sub").mkdir()
    (p / "sub" / "n.txt").write_text("hello")
    outside = tmp_path / "secret-outside"
    outside.write_text("do not hash me")
    os.symlink(outside, p / "link")
    m = scratch.close_pass(p, "closed", note="ruled out xor", now=200.0)
    files = {f["path"]: f for f in m["files"]}
    assert set(files) == {"out.bin", "sub/n.txt", "link"}
    assert files["out.bin"] == {"path": "out.bin", "bytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
    assert files["sub/n.txt"]["sha256"] == hashlib.sha256(b"hello").hexdigest()
    assert files["link"] == {"path": "link", "symlink": str(outside)}
    on_disk = scratch.read_manifest(p)
    assert on_disk["status"] == "closed" and on_disk["note"] == "ruled out xor" and on_disk["ended"] == 200.0
    with pytest.raises(scratch.ScratchError, match="already closed"):
        scratch.close_pass(p, "failed")


def test_close_status_is_checked(wd):
    p = scratch.open_pass(wd / "12-web-login", "work")
    with pytest.raises(scratch.ScratchError, match="close status"):
        scratch.close_pass(p, "open")


def test_large_files_listed_by_size_only(wd, monkeypatch):
    monkeypatch.setattr(scratch, "HASH_LIMIT", 4)
    p = scratch.open_pass(wd / "12-web-login", "work")
    (p / "big").write_bytes(b"12345")
    (p / "small").write_bytes(b"1234")
    files = {f["path"]: f for f in scratch.close_pass(p)["files"]}
    assert files["big"]["sha256"] is None and files["big"]["bytes"] == 5
    assert files["small"]["sha256"] is not None


def test_prune_keeps_newest_closed_and_never_touches_open(wd):
    chal = wd / "12-web-login"
    ps = [scratch.open_pass(chal, f"p{i}") for i in range(5)]
    for p in ps[:4]:
        scratch.close_pass(p)
    removed = scratch.prune(chal, keep=2)
    assert removed == [ps[0].name, ps[1].name]
    left = [m["pass"] for m in scratch.passes(chal)]
    assert left == [ps[2].name, ps[3].name, ps[4].name]
    assert scratch.prune(chal, keep=0) == [ps[2].name, ps[3].name]
    assert [m["pass"] for m in scratch.passes(chal)] == [ps[4].name]   # the open pass survives


def test_passes_refuses_unknown_entries_and_symlinked_root(wd, tmp_path):
    chal = wd / "12-web-login"
    scratch.open_pass(chal, "a")
    (chal / ".scratch" / "random-folder").mkdir()
    with pytest.raises(scratch.ScratchError, match="unexpected entry"):
        scratch.passes(chal)
    chal2 = wd / "7-rev"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, chal2 / ".scratch")
    with pytest.raises(scratch.ScratchError, match="symlink"):
        scratch.open_pass(chal2, "x")


def test_corrupt_manifest_is_an_error(wd):
    p = scratch.open_pass(wd / "12-web-login", "a")
    (p / "MANIFEST.json").write_text("{nope")
    with pytest.raises(scratch.ScratchError, match="corrupt manifest"):
        scratch.passes(wd / "12-web-login")


def test_env_for_points_temp_files_at_the_pass(wd):
    p = scratch.open_pass(wd / "12-web-login", "a")
    e = scratch.env_for(p)
    assert e["TMPDIR"] == str(p.resolve()) == e["CTF_SCRATCH_DIR"] == e["TMP"] == e["TEMP"]


def test_cli_new_list_close_prune(wd, capsys):
    assert ctf_main(["scratch", "new", "12", "--purpose", "first"]) == 0
    path = capsys.readouterr().out.strip()
    assert path.endswith("12-web-login/.scratch/001-first")
    (wd / "12-web-login" / ".scratch" / "001-first" / "x.txt").write_text("x")
    assert ctf_main(["scratch", "new", "12", "--purpose", "second", "--shell"]) == 0
    out = capsys.readouterr().out
    assert "export TMPDIR=" in out and "002-second" in out
    assert ctf_main(["scratch", "close", "12", "001-first", "--note", "done"]) == 0
    assert "1 file(s) recorded" in capsys.readouterr().out
    assert ctf_main(["scratch", "list", "12", "--json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert [(m["pass"], m["status"]) for m in listed] == [("001-first", "closed"), ("002-second", "open")]
    assert ctf_main(["scratch", "prune", "12", "--keep", "0"]) == 0
    assert "removed 001-first" in capsys.readouterr().out
    assert ctf_main(["scratch", "close", "12", "../escape"]) == 2
    assert "bad pass name" in capsys.readouterr().err
    assert ctf_main(["scratch", "new", "404", "--purpose", "x"]) == 2
    assert "no challenge folder" in capsys.readouterr().err
