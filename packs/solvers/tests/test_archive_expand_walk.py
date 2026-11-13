"""B-013: tools/archive_expand.py's opt-in wide walk (Walk): tar, whole-file gzip/bz2/xz, RAR/7z through
7-Zip, budgets, depth, link safety, full chains, and the legacy walk left unchanged.

Every fixture is built here with the standard library encoders (or 7-Zip itself, marked needs_tool).
"""
import bz2
import gzip
import io
import lzma
import os
import shutil
import subprocess
import tarfile
import zipfile

import pytest

import archive_expand as ae


@pytest.fixture(autouse=True)
def _only_infected(monkeypatch):
    monkeypatch.setattr(ae.pw, "candidates", lambda: [b"infected"])


def zip_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression=compression) as z:
        for name, data in entries:
            z.writestr(name, data)
    return bio.getvalue()


def tar_bytes(entries, links=()):
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as t:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        for name, target, kind in links:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.linkname = target
            t.addfile(info)
    return bio.getvalue()


def walk_of(name, data, **kw):
    w = ae.Walk(**kw)
    out = {}
    ae.expand(name, data, out, opts=w)
    return out, w


def test_tar_members_are_read_with_full_chains():
    raw = tar_bytes([("logs/a.txt", b"alpha"), ("b.bin", b"\x00\x01")])
    out, w = walk_of("handout.tar", raw)
    assert out["handout.tar -> logs/a.txt"] == b"alpha"
    assert out["handout.tar -> b.bin"] == b"\x00\x01"
    chains = {c: bytes(b) for c, _k, b in w.rows}
    assert chains[("handout.tar", "logs/a.txt")] == b"alpha"
    assert w.rows[0][0] == ("handout.tar",)          # the delivery first
    assert w.notes == []


def test_legacy_walk_keeps_tar_and_gzip_opaque():
    tgz = gzip.compress(tar_bytes([("a.txt", b"alpha")]), mtime=0)
    out = {}
    ae.expand("x.tgz", tgz, out)
    assert list(out) == ["x.tgz"]
    out = {}
    ae.expand("x.tar", tar_bytes([("a.txt", b"alpha")]), out)
    assert list(out) == ["x.tar"]


@pytest.mark.parametrize("name,compress,inner", [
    ("x.tgz", lambda b: gzip.compress(b, mtime=0), "x.tar"),
    ("x.tar.bz2", bz2.compress, "x.tar"),
    ("x.tar.xz", lzma.compress, "x.tar"),
])
def test_compressed_tar_is_inflated_then_opened(name, compress, inner):
    out, w = walk_of(name, compress(tar_bytes([("deep/flag.txt", b"payload")])))
    assert out[f"{name} -> {inner}"][257:262] == b"ustar"
    assert out[f"{inner} -> deep/flag.txt"] == b"payload"
    assert (name, inner, "deep/flag.txt") in [c for c, _k, _b in w.rows]


def test_plain_gzip_of_text_is_inflated_and_concatenated_members_kept():
    data = gzip.compress(b"part one ", mtime=0) + gzip.compress(b"part two", mtime=0)
    out, _ = walk_of("access.log.gz", data)
    assert out["access.log.gz -> access.log"] == b"part one part two"


def test_gzip_bomb_is_dropped_with_a_note():
    bomb = gzip.compress(b"\x00" * (4 << 20), mtime=0)
    out, w = walk_of("bomb.gz", bomb, max_member=1 << 20)
    assert list(out) == ["bomb.gz"]
    assert any("inflates past the member limit" in n for n in w.notes)


def test_tar_link_entries_are_their_target_text_never_the_target(tmp_path):
    secret = tmp_path / "host-secret.txt"
    secret.write_bytes(b"HOST FILE CONTENT")
    raw = tar_bytes([("ok.txt", b"ok")], links=[("evil", str(secret), tarfile.SYMTYPE),
                                                ("hard", "ok.txt", tarfile.LNKTYPE)])
    out, _ = walk_of("t.tar", raw)
    assert out["t.tar -> evil"] == os.fsencode(str(secret))
    assert out["t.tar -> hard"] == b"ok.txt"
    assert all(b"HOST FILE CONTENT" not in bytes(v) for v in out.values())


def test_depth_limit_stops_and_says_so():
    inner = zip_bytes([("core.txt", b"deepest")])
    for i in range(4):
        inner = zip_bytes([(f"level{i}.zip", inner)])
    out, w = walk_of("top.zip", inner, max_depth=2)
    assert not any(k.endswith("core.txt") for k in out)
    assert any("depth limit of 2" in n for n in w.notes)
    out, w = walk_of("top.zip", inner, max_depth=6)
    assert any(k.endswith("-> core.txt") for k in out)


def test_member_count_budget_stops_the_walk():
    raw = zip_bytes([(f"m{i}.txt", b"x") for i in range(20)])
    out, w = walk_of("many.zip", raw, max_members=5)
    assert sum(" -> " in k for k in out) == 5
    assert w.full and any("budget" in n for n in w.notes)


def test_total_bytes_budget_stops_the_walk():
    raw = zip_bytes([(f"m{i}.bin", b"y" * 1000) for i in range(10)], compression=zipfile.ZIP_STORED)
    out, w = walk_of("big.zip", raw, max_total=3500)
    assert sum(" -> " in k for k in out) == 3
    assert w.total <= 3500 and w.full


def test_zip_member_over_the_member_limit_is_not_inflated(monkeypatch):
    read = []
    original = ae.pw.Opener.read

    def spy(self, info):
        read.append(info.filename)
        return original(self, info)

    monkeypatch.setattr(ae.pw.Opener, "read", spy)
    raw = zip_bytes([("huge.bin", b"\x00" * (2 << 20)), ("small.txt", b"s")])
    out, w = walk_of("z.zip", raw, max_member=1 << 20)
    assert read == ["small.txt"]                     # the declared size decided; huge.bin was never inflated
    assert "z.zip -> huge.bin" not in out
    assert out["z.zip -> small.txt"] == b"s"
    assert any("huge.bin" in n and "member limit" in n for n in w.notes)


def test_missing_7zip_is_a_note_not_silence(monkeypatch):
    monkeypatch.setattr(ae.shutil, "which", lambda name: None)
    out, w = walk_of("a.7z", ae.SEVENZ_MAGIC + b"\x00" * 32)
    assert list(out) == ["a.7z"]
    assert any("needs 7-Zip" in n for n in w.notes)
    out, w = walk_of("a.rar", ae.RAR_MAGIC + b"\x01\x00" + b"\x00" * 32)
    assert any("needs 7-Zip" in n for n in w.notes)


@pytest.mark.needs_tool("7zz")
def test_7z_symlink_member_is_link_text_not_host_file(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_bytes(b"inside")
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"HOST FILE CONTENT")
    os.symlink(secret, src / "link")
    arc = tmp_path / "t.7z"
    subprocess.run([shutil.which("7zz"), "a", "-snl", str(arc), str(src)], check=True, capture_output=True)
    out, w = walk_of("t.7z", arc.read_bytes())
    assert out["t.7z -> src/a.txt"] == b"inside"
    # 7-Zip may spell the temp folder without /private; the link's text names the file either way.
    assert out["t.7z -> src/link"].endswith(b"/secret.txt")
    assert all(b"HOST FILE CONTENT" not in bytes(v) for v in out.values())
    # The legacy walk reads links the same way now (it used to read the target's bytes).
    legacy = {}
    ae.expand("t.7z", arc.read_bytes(), legacy)
    assert legacy["t.7z -> src/link"].endswith(b"/secret.txt")


@pytest.mark.needs_tool("7zz")
def test_7z_listed_size_over_budget_is_not_extracted(tmp_path):
    src = tmp_path / "big.bin"
    src.write_bytes(b"\x00" * (1 << 20))
    arc = tmp_path / "b.7z"
    subprocess.run([shutil.which("7zz"), "a", str(arc), str(src)], check=True, capture_output=True)
    out, w = walk_of("b.7z", arc.read_bytes(), max_total=1000)
    assert list(out) == ["b.7z"]
    assert any("7-Zip lists 1048576 bytes" in n for n in w.notes)


def test_nested_zip_rows_carry_the_whole_chain():
    raw = zip_bytes([("inner/stage.zip", zip_bytes([("x.js", b"js")]))])
    out, w = walk_of("evidence.zip", raw)
    assert ("evidence.zip", "inner/stage.zip", "x.js") in [c for c, _k, _b in w.rows]
