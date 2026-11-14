"""B-117: the helper the visual stego engines share (solvers/toolkits/_visual_stego.py): which
files of a challenge an engine reads, and the status rule. Everything is written here."""
from __future__ import annotations

import os

import pytest

import _visual_stego as vs
import image_carve


def _write(path, data=b"x"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _names(challenge, cap=100):
    paths, skipped = vs.challenge_paths(challenge, cap)
    return [rel for rel, _path in paths], skipped


def test_links_are_never_followed_out_of_the_challenge(tmp_path):
    """A link in a handout must not pull in a file from outside the challenge folder."""
    outside = tmp_path / "outside"
    _write(outside / "secret.txt", b"not part of the challenge")
    _write(outside / "folder" / "inner.txt")
    challenge = tmp_path / "ch"
    _write(challenge / "real.txt")
    _write(challenge / "sub" / "deep.txt")
    os.symlink(outside / "secret.txt", challenge / "linked.txt")
    os.symlink(outside / "folder", challenge / "linked_folder", target_is_directory=True)
    os.symlink(challenge / "real.txt", challenge / "sub" / "alias.txt")      # a link inside it is a link too
    os.symlink(challenge / "missing", challenge / "dangling")
    names, skipped = _names(challenge)
    assert names == ["real.txt", "sub/deep.txt"] and skipped == []
    paths, _ = vs.challenge_paths(challenge, 100)
    assert all(not path.is_symlink() and path.is_file() for _rel, path in paths)
    assert [path for _rel, path in paths] == [challenge / "real.txt", challenge / "sub" / "deep.txt"]


def test_recon_output_and_bookkeeping_are_not_read_back(tmp_path):
    challenge = tmp_path / "ch"
    for name in ("page.html", "recon/swf_parse/movie.avm1.txt", "recon/gif_reveal/a.frame0.png", ".git/config",
                 "sub/recon/again.txt", "sub/kept.txt", "challenge.json", "notes.md", "triage.md", ".sweep.json",
                 ".sweep-owner", ".lock", "sub/notes.md"):
        _write(challenge / name)
    names, skipped = _names(challenge)
    assert names == ["page.html", "sub/kept.txt"] and skipped == []
    # the lists are image_carve's: one place says what is not the challenge
    assert vs.SKIP_DIRS is image_carve.SKIP_DIRS and vs.SKIP_FILES is image_carve.SKIP_FILES
    assert {"recon", ".git"} <= vs.SKIP_DIRS and "challenge.json" in vs.SKIP_FILES
    assert sorted(image_carve.challenge_files(challenge)) == names   # the Phase 1 walk reads the same files


def test_scratch_copy_wins_then_files_then_the_folder(tmp_path):
    challenge = tmp_path / "ch"
    _write(challenge / "loose.txt")
    assert _names(challenge)[0] == ["loose.txt"]
    _write(challenge / "files" / "handout.bin")
    assert _names(challenge)[0] == ["files/handout.bin"]             # relative to the challenge, not to files/
    _write(challenge / "unpacked" / "member.txt")
    _write(challenge / "unpacked" / "z" / "inner.txt")
    assert _names(challenge)[0] == ["unpacked/member.txt", "unpacked/z/inner.txt"]


def test_size_cap_is_named_and_a_missing_folder_is_loud(tmp_path):
    challenge = tmp_path / "ch"
    _write(challenge / "small.bin", b"1234")
    _write(challenge / "exact.bin", b"12345678")
    _write(challenge / "big.bin", b"123456789")
    names, skipped = _names(challenge, cap=8)
    assert names == ["exact.bin", "small.bin"]
    assert skipped == ["big.bin: 9 bytes is over the 8 byte cap, not read"]
    with pytest.raises(FileNotFoundError, match="no such challenge folder"):
        vs.challenge_paths(tmp_path / "absent", 8)
    with pytest.raises(FileNotFoundError):
        vs.challenge_paths(challenge / "small.bin", 8)               # a file is not a challenge folder


def test_safe_name_and_status_rule():
    assert vs.safe_name("files/a b/c.gif") == "files_a_b_c.gif" and vs.safe_name("///") == "_"
    assert vs.safe_name("") == "file" and len(vs.safe_name("x" * 500)) == 120
    assert vs.status_of(["F"], [], False) == "solved" and vs.status_of(["F", "F"], ["F"], True) == "solved"
    assert vs.status_of(["F", "G"], [], False) == "candidate" and vs.status_of(["F"], ["G"], False) == "candidate"
    assert vs.status_of([], ["G"], True) == "candidate"              # OCR alone is never more
    assert vs.status_of([], [], True) == "unsure" and vs.status_of([], [], False) == "none"


def test_code_reader_missing(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "zxingcpp", None)
    monkeypatch.setitem(sys.modules, "pyzbar", None)
    assert vs.code_reader_missing() == "codes not read: neither py:zxingcpp nor py:pyzbar is importable"
    fake = type(sys)("pyzbar")
    fake.pyzbar = type(sys)("pyzbar.pyzbar")
    monkeypatch.setitem(sys.modules, "pyzbar", fake)
    monkeypatch.setitem(sys.modules, "pyzbar.pyzbar", fake.pyzbar)
    assert vs.code_reader_missing() is None                          # pyzbar alone is enough
