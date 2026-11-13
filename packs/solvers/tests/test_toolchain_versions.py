"""B-188: version notes in challenge files and the tagged image they pick (ctf/toolchain/versions.py).

Challenge folders here are synthetic: text and bytes written by the test. Nothing is executed.
"""
from __future__ import annotations

import os
import socket
import threading
from pathlib import Path

import pytest

from ctf.toolchain import images, versions


def notes(text: str, path: str = "README.md") -> set[tuple[str, str]]:
    return {(n.tool, n.version) for n in versions.scan_text(text, path)}


@pytest.mark.parametrize("text, want", [
    ("SageMath version 10.5, Release Date: 2024-12-04", ("sage", "10.5")),
    ("FROM sagemath/sagemath:10.5", ("sage", "10.5")),
    ("tested with sage 10.4.1", ("sage", "10.4.1")),
    ("Sage v9.8 was used", ("sage", "9.8")),
    ("FROM python:3.11-slim", ("python", "3.11")),
    ("Python 3.10.12 (main)", ("python", "3.10.12")),
    ("built against GLIBC 2.35", ("glibc", "2.35")),
    ("the provided libc-2.31.so", ("glibc", "2.31")),
    ("FROM ubuntu:22.04", ("ubuntu", "22.04")),
    ("Ubuntu 20.04 LTS", ("ubuntu", "20.04")),
    ("FROM python:3.12-slim-bookworm", ("debian", "12")),
    ("debian:trixie", ("debian", "13")),
    ("gcc version 11.4.0", ("gcc", "11.4.0")),
    ("OpenSSL 1.1.1w", ("openssl", "1.1.1w")),
    ("FROM node:18-alpine", ("node", "18")),
    ("FROM openjdk:17", ("java", "17")),
])
def test_text_patterns(text, want):
    assert want in notes(text)


@pytest.mark.parametrize("text", [
    "send the message 1.2 times",            # 'sage' inside a word
    "GLIBC_2.34 symbol version",             # a symbol version is not the libc release
    "the graph has node 3.5 weight",         # node without node:/v/version
    "sage is a herb",
])
def test_text_patterns_do_not_fire_on_lookalikes(text):
    found = notes(text)
    assert not any(t in ("sage", "glibc", "node") for t, _ in found), found


def test_pins_and_from_lines_only_in_their_files():
    req = "pycryptodome==3.20.0\nDissect.Cstruct == 4.7  # x\nrequests>=2\n"
    assert notes(req, "requirements.txt") >= {("py:pycryptodome", "3.20.0"), ("py:dissect-cstruct", "4.7")}
    assert not any(t.startswith("py:") for t, _ in notes(req, "notes.txt"))
    df = "FROM --platform=linux/amd64 sagemath/sagemath:10.5 AS s\n"
    assert ("image:sagemath/sagemath", "10.5") in notes(df, "docker/Dockerfile")
    assert not any(t.startswith("image:") for t, _ in notes(df, "notes.txt"))


def test_binary_patterns_read_the_libc_banner_and_compiler_comment():
    blob = (b"\x7fELF\x00\x00" + b"GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.8) stable release version 2.35.\x00"
            + b"GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0\x00" + b"GLIBC_2.34\x00")
    got = {(n.tool, n.version) for n in versions.scan_binary(blob, "libc.so.6")}
    assert got == {("glibc", "2.35"), ("gcc", "11.4.0"), ("ubuntu", "22.04")}


def test_scan_walks_text_and_binary_files_with_their_own_patterns(tmp_path):
    (tmp_path / "README.md").write_text("Needs SageMath 10.5 exactly.\n\nsee sage 10.5 again\n")
    (tmp_path / "chal").write_bytes(b"\x00\x01ELF sage 10.7 GNU C Library (Debian GLIBC 2.36-9) stable release version 2.36.")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "Dockerfile").write_text("FROM python:3.11-slim\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("sage 9.0\n")
    os.symlink(tmp_path / "README.md", tmp_path / "link.md")
    sc = versions.scan(tmp_path)
    got = {(n.tool, n.version, n.path) for n in sc.notes}
    assert ("sage", "10.5", "README.md") in got
    assert ("glibc", "2.36", "chal") in got and ("python", "3.11", "sub/Dockerfile") in got
    assert not any(v == "10.7" for _, v, _ in got)                    # a binary is read for binary patterns only
    assert not any(p.startswith(".git") for *_, p in got)
    assert [n.line for n in sc.notes if n.tool == "sage"] == [1]      # one note per tool, version and file
    assert sc.skipped == ("link.md (symlink)",) and sc.files == 3 and not sc.truncated


def test_scan_caps_files_and_size(tmp_path, monkeypatch):
    for i in range(5):
        (tmp_path / f"f{i}.txt").write_text(f"Python 3.{i}\n")
    sc = versions.scan(tmp_path, max_files=2)
    assert sc.truncated and sc.files == 2
    monkeypatch.setattr(versions, "MAX_TEXT_BYTES", 64)
    big = tmp_path / "big"
    big.mkdir()
    (big / "a.txt").write_text("x" * 100 + " sage 10.5\n")
    sc = versions.scan(big)
    assert sc.notes == () and sc.skipped and "over 64 bytes" in sc.skipped[0]
    with pytest.raises(FileNotFoundError):
        versions.scan(tmp_path / "missing")


def _scan_with_deadline(folder, seconds=10.0):
    """versions.scan in a daemon thread: a scan that blocks (on a FIFO) fails the test instead of
    hanging the run."""
    box = {}
    t = threading.Thread(target=lambda: box.setdefault("scan", versions.scan(folder)), daemon=True)
    t.start()
    t.join(seconds)
    assert not t.is_alive(), "versions.scan blocked (it opened something that is not a regular file)"
    return box["scan"]


def test_scan_skips_a_fifo_instead_of_blocking_on_it(tmp_path):
    (tmp_path / "README.md").write_text("tested with sage 10.5\n")
    os.mkfifo(tmp_path / "pipe")
    sc = _scan_with_deadline(tmp_path)
    assert "pipe (not a regular file)" in sc.skipped
    assert sc.files == 1 and {(x.tool, x.version) for x in sc.notes} == {("sage", "10.5")}


def test_scan_never_opens_what_lstat_says_is_not_a_regular_file(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("sage 10.5\n")
    os.mkfifo(tmp_path / "pipe")
    opened = []
    real_open = os.open

    def spy(path, *a, **kw):
        opened.append(Path(path).name)
        return real_open(path, *a, **kw)
    monkeypatch.setattr(versions.os, "open", spy)
    sc = _scan_with_deadline(tmp_path)
    monkeypatch.undo()
    assert opened == ["a.txt"] and "pipe (not a regular file)" in sc.skipped


def test_scan_does_not_block_on_a_file_swapped_for_a_fifo_after_the_check(tmp_path, monkeypatch):
    """The race: lstat saw a regular file, the open meets a FIFO. The open must not block (O_NONBLOCK)
    and the fstat recheck must skip it."""
    (tmp_path / "a.txt").write_text("sage 10.5\n")
    os.mkfifo(tmp_path / "pipe")
    regular = os.lstat(tmp_path / "a.txt")
    real_lstat = os.lstat
    monkeypatch.setattr(versions.os, "lstat",
                        lambda p, *a, **kw: regular if Path(p).name == "pipe" else real_lstat(p, *a, **kw))
    sc = _scan_with_deadline(tmp_path)
    monkeypatch.undo()
    assert "pipe (not a regular file)" in sc.skipped and sc.files == 1


def test_scan_skips_a_unix_socket(tmp_path):
    (tmp_path / "a.txt").write_text("python 3.11\n")
    sock = socket.socket(socket.AF_UNIX)
    # AF_UNIX paths are short on macOS: bind relative to the folder
    old = os.getcwd()
    os.chdir(tmp_path)
    try:
        sock.bind("s.sock")
    finally:
        os.chdir(old)
    try:
        sc = _scan_with_deadline(tmp_path)
    finally:
        sock.close()
    assert sc.skipped == ("s.sock (not a regular file)",) and sc.files == 1


def img(name, tag, sage, default=False):
    return images.Image(name=name, tag=tag, dockerfile="d/D", context="d", versions=(("sage", sage),),
                        default_for=("sage",) if default else ())


IMGS = [img("sage-10.5", "ctf-sage:10.5", "10.5"), img("sage-10.7", "ctf-sage:10.7", "10.7", default=True)]


def n(v, path="README.md", line=1):
    return versions.VersionNote("sage", v, path, line, f"sage {v}")


def test_pick_ok_prefix_missing_conflict_and_default():
    p, = versions.pick([n("10.5")], IMGS)
    assert (p.status, p.tag) == ("ok", "ctf-sage:10.5") and "README.md:1" in p.reason
    p, = versions.pick([n("10.5.1")], IMGS)
    assert (p.status, p.tag) == ("ok", "ctf-sage:10.5")
    p, = versions.pick([n("10")], IMGS)                                  # too vague to choose
    assert p.status == "missing"
    for other in ("10.50", "10.55", "10.5a"):                           # not a 10.5 release
        p, = versions.pick([n(other)], IMGS)
        assert (p.status, p.image) == ("missing", None), other
    p, = versions.pick([n("10.3")], IMGS)
    assert p.status == "missing" and p.image is None and "10.3" in p.reason and "tools/images.toml" in p.reason
    p, = versions.pick([n("10.5"), n("10.7", "b.txt", 4)], IMGS)
    assert p.status == "conflict" and p.wanted == ("10.5", "10.7") and "b.txt:4" in p.reason
    p, = versions.pick([], IMGS)
    assert (p.status, p.tag) == ("default", "ctf-sage:10.7") and "ctf-sage:10.5" in p.reason
    p, = versions.pick([], IMGS[:1])
    assert p.status == "missing" and "default_for" in p.reason


def test_pick_versions_one_image_serves_are_one_want_not_a_conflict():
    p, = versions.pick([n("10.5"), n("10.5.1", "b.txt", 3)], IMGS)
    assert (p.status, p.tag, p.wanted) == ("ok", "ctf-sage:10.5", ("10.5", "10.5.1"))
    assert "README.md:1" in p.reason and "b.txt:3" in p.reason
    p, = versions.pick([n("10.5"), n("10.5.1"), n("10.7", "c.txt", 2)], IMGS)
    assert p.status == "conflict" and p.wanted == ("10.5", "10.5.1", "10.7") and "c.txt:2" in p.reason
    p, = versions.pick([n("10.3"), n("10.4")], IMGS)                     # two versions no image has
    assert p.status == "conflict" and p.image is None
    p, = versions.pick([n("10.5"), n("10.50")], IMGS)                    # one served, one not
    assert p.status == "conflict"


def test_pick_ignores_tools_no_image_provides():
    assert versions.pick([versions.VersionNote("glibc", "2.35", "x", 1, "")], IMGS)[0].tool == "sage"
    assert versions.pick([], []) == []


def test_real_manifest_picks_sage_10_5_from_a_dockerfile(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM sagemath/sagemath:10.5\nCOPY chall.sage .\n")
    p, = versions.pick(versions.scan(tmp_path).notes, images.load())
    assert (p.status, p.tag) == ("ok", "ctf-sage:10.5")


def test_py_mismatches_compare_against_the_venv():
    ns = [versions.VersionNote("py:pycryptodome", "3.20.0", "requirements.txt", 1, ""),
          versions.VersionNote("py:requests", "2.34.2", "requirements.txt", 2, ""),
          versions.VersionNote("sage", "10.5", "x", 1, "")]
    have = {"pycryptodome": "3.24.0", "requests": "2.34.2"}
    got = versions.py_mismatches(ns, version_of=have.get)
    assert [(m.tool, h) for m, h in got] == [("py:pycryptodome", "3.24.0")]
    assert versions.installed_version("ctf-b188-not-installed") is None
