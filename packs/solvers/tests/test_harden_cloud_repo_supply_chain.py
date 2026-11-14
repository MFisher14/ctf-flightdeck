"""Real archive/hash oracles and static package/repository fixtures; no execution.

Sources: git-scm.com/docs/pack-format; PyPA recording-installed-packages;
docs.npmjs.com/cli/v11/configuring-npm/package-json; GitHub workflow syntax.
"""
import base64
import bz2
import gzip
import hashlib
import io
import json
import lzma
import pickle
import random
import socket
import struct
import subprocess
import tarfile
import zipfile
import zlib

import pytest

import repo_supply_chain as engine


def tar(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tf:
        for path, body in entries.items():
            info = tarfile.TarInfo(path); info.size = len(body); info.mtime = 0
            tf.addfile(info, io.BytesIO(body))
    return out.getvalue()


def clean(call):
    try:
        call()
    except Exception as exc:
        assert type(exc) in (ValueError, engine.Incomplete), f"leaked {type(exc).__name__}: {exc}"


@pytest.mark.parametrize("compress,wbits", [(zlib.compress, 15), (lambda x: gzip.compress(x, mtime=0), 31), (lambda x: gzip.compress(x, mtime=0), 47)])
def test_inflate_real_compressor_and_output_cap(compress, wbits):
    raw = b"CSCTF{independent_compressor}" * 200
    packed = compress(raw)
    assert engine.inflate(packed, len(raw), wbits) == raw
    with pytest.raises(ValueError, match="size cap"):
        engine.inflate(packed, 32, wbits)


@pytest.mark.parametrize("compress", [lambda x: x, lambda x: gzip.compress(x, mtime=0), bz2.compress, lzma.compress])
def test_expand_real_nested_archives(compress):
    body = b'{"name":"fixture","version":"1.0.0"}'
    archive = compress(tar({"package/package.json": body, "package/flag.txt": b"CSCTF{archive_bytes}"}))
    result = engine.expand({"delivery": archive})
    assert result["delivery -> package/package.json"] == body
    assert result["delivery -> package/flag.txt"] == b"CSCTF{archive_bytes}"
    assert ("delivery", "package/flag.txt", b"CSCTF{archive_bytes}") in engine.listing(result)


def test_expand_zip_and_total_member_caps(monkeypatch):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("payload", (2020, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(info, b"A" * 10000)
    packed = out.getvalue()
    monkeypatch.setattr(engine, "MAX_MEMBER", 32)
    assert engine.expand({"x.zip": packed}) == {"x.zip": packed}
    monkeypatch.setattr(engine, "MAX_MEMBER", 20000)
    monkeypatch.setattr(engine, "MAX_TOTAL", len(packed) + 10)
    notes = []
    assert engine.expand({"x.zip": packed}, notes) == {"x.zip": packed}
    assert any("larger than" in note for note in notes)


@pytest.mark.parametrize("suffix,compress", [("gz", lambda x: gzip.compress(x, mtime=0)), ("bz2", bz2.compress), ("xz", lzma.compress)])
def test_single_stream_expansion(suffix, compress):
    content = b"CSCTF{stream}" * 1000
    name = f"payload.{suffix}"
    packed = compress(content)
    assert engine.expand({name: packed})[f"{name} -> payload"] == content


@pytest.mark.parametrize("suffix,compress", [
    ("gz", lambda x: gzip.compress(x, mtime=0)),
    ("bz2", bz2.compress),
    ("xz", lzma.compress),
])
def test_single_stream_cap_does_not_publish_partial_member(monkeypatch, suffix, compress):
    name = f"payload.{suffix}"
    packed = compress(b"CSCTF{stream}" * 1000)
    monkeypatch.setattr(engine, "MAX_MEMBER", 32)
    assert engine.expand({name: packed}) == {name: packed}


def test_from_paths_reads_files_but_does_not_follow_symlinks(tmp_path):
    repo = tmp_path / "repo"; repo.mkdir()
    (repo / ".hidden").write_bytes(b"included")
    outside = tmp_path / "outside"; outside.write_bytes(b"excluded")
    (repo / "link").symlink_to(outside)
    assert engine.from_paths([repo]) == {"repo/.hidden": b"included"}


def test_git_delta_documented_copy_and_insert():
    # Git delta: source=6,destination=7; copy offset0 length3; insertXYZ; copy offset5 length1.
    assert engine.apply_git_delta(b"abcdef", bytes.fromhex("06 07 90 03 03 58 59 5a 91 05 01")) == b"abcXYZf"


def test_git_loose_objects_hashes_and_snapshot():
    objects = {}
    def add(kind, body):
        raw = f"{kind} {len(body)}".encode() + b"\x00" + body
        oid = hashlib.sha1(raw).hexdigest()
        objects[f"objects/{oid[:2]}/{oid[2:]}"] = zlib.compress(raw)
        return oid
    blob = add("blob", b"CSCTF{git_loose_fixture}\n")
    tree = add("tree", b"100644 flag.txt\x00" + bytes.fromhex(blob))
    commit = add("commit", f"tree {tree}\nauthor Test <test@example.invalid> 1000000000 +0000\ncommitter Test <test@example.invalid> 1000000000 +0000\n\nfixture\n".encode())
    objects["HEAD"] = b"ref: refs/heads/main\n"; objects["refs/heads/main"] = commit.encode() + b"\n"
    repo = engine.GitRepo(objects)
    assert repo.complete is True
    assert repo.blob(blob) == b"CSCTF{git_loose_fixture}\n"
    assert repo.snapshot(commit) == {"flag.txt": blob}
    assert repo.refs()["refs/heads/main"] == commit


def test_package_hooks_and_setup_are_never_executed(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("static analysis attempted execution/network")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(pickle, "loads", forbidden)
    doc = {"name": "fixture", "version": "2.0.0", "main": "index.js", "bin": "cli.js",
           "scripts": {"postinstall": "node setup.js", "test": "node test.js"},
           "dependencies": {"normal": "^1.0.0", "local": "file:../local"}}
    facts = engine.read_package_json(json.dumps(doc).encode(), {"setup.js": b'fetch("https://example.invalid/fixture")'})
    assert (facts["name"], facts["version"], facts["entry"], facts["bin"]) == ("fixture", "2.0.0", "index.js", {"fixture": "cli.js"})
    assert facts["dependencies_not_from_registry"] == {"local": "file:../local"}
    hook = next(h for h in facts["hooks"] if h["when"] == "postinstall")
    assert hook["files"] == ["setup.js"] and hook["install_time"] is True
    assert hook["urls"] == ["https://example.invalid/fixture"]
    source = b'import os\nfrom setuptools import setup\nos.system("must never execute")\nsetup(name="fixture", version="2.0", cmdclass={"install": Custom})\n'
    facts = engine.read_setup_py(source)
    assert facts["args"] == {"name": "fixture", "version": "2.0"}
    assert facts["cmdclass"] == ["install"]
    assert facts["calls"] == [{"call": "os.system", "arg": "must never execute", "line": 3}]


def test_record_real_hash_and_tamper():
    body = b"print('fixture')\n"
    digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip("=")
    record = f"pkg.py,sha256={digest},{len(body)}\npkg.dist-info/RECORD,,\n".encode()
    members = {"pkg.py": body, "pkg.dist-info/RECORD": record}
    assert engine.check_record(members, "pkg.dist-info/RECORD") == {"rows": 2, "mismatched": [], "missing": [], "unlisted": []}
    members["pkg.py"] = b"tampered"
    mismatch = engine.check_record(members, "pkg.dist-info/RECORD")["mismatched"][0]
    assert mismatch["actual_hex"] == hashlib.sha256(b"tampered").hexdigest()
    assert mismatch["recorded_hex"] == hashlib.sha256(body).hexdigest()
    assert mismatch["actual_size"] == 8 and mismatch["hash_differs"] is True


def test_static_workflow_manifest_gem_and_pth_vectors():
    workflow = b'name: Fixture\non: [pull_request_target]\njobs:\n  build:\n    runs-on: self-hosted\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo ${{ secrets.TEST_TOKEN }}\n'
    facts = engine.read_workflow(workflow)
    assert facts["triggers"] == ["pull_request_target"]
    assert facts["secrets_used"] == ["TEST_TOKEN"] and facts["uses"] == ["actions/checkout@v4"]
    assert len(facts["notes"]) == 3
    assert engine.pth_lines(b"plain/path\nimport os\nimport\tsys\n # comment\n") == ["import os", "import\tsys"]
    assert engine.read_manifest_mf(b"Manifest-Version: 1.0\r\nMain-Class: com.example.\r\n Main\r\n\r\nName: ignored\r\n") == {"Manifest-Version": "1.0", "Main-Class": "com.example.Main"}
    facts = engine.read_gem_spec(b"--- !ruby/object:Gem::Specification\nname: fixture\nversion: !ruby/object:Gem::Version\n  version: 1.2.3\nextensions: [ext/extconf.rb]\n")
    assert (facts["name"], facts["version"], facts["extensions"]) == ("fixture", "1.2.3", ["ext/extconf.rb"])


def test_crx2_documented_header_and_extension_id():
    key = b"synthetic-public-key"; signature = b"signature"; zipped = b"PK\x03\x04fixture"
    raw = b"Cr24" + struct.pack("<III", 2, len(key), len(signature)) + key + signature + zipped
    facts = engine.crx_parts(raw)
    expected = "".join(chr(ord("a") + int(nibble, 16)) for nibble in hashlib.sha256(key).hexdigest()[:32])
    assert facts["zip"] == zipped and facts["id"] == expected


def test_byte_fuzz_static_readers():
    rng = random.Random(612)
    samples = [b"", b"\xff" * 4096, rng.randbytes(2048), b'{"name":', b"PK\x03\x04", b"x" * 65536]
    for function in [engine.read_package_json, engine.read_setup_py, engine.read_manifest_mf, engine.pth_lines]:
        for raw in samples:
            clean(lambda: function(raw))
    for raw in samples:
        assert isinstance(engine.expand({"fixture": raw}), dict)


def test_inflate_rejects_incomplete_stream():
    raw = gzip.compress(b"complete-payload", mtime=0)[:-8]
    with pytest.raises(ValueError):
        engine.inflate(raw, 1024, 31)


@pytest.mark.parametrize("delta", [b"", b"\x80", b"\x06\x07\x91"])
def test_git_delta_truncation_fail_closed(delta):
    clean(lambda: engine.apply_git_delta(b"abcdef", delta))


def test_crx_truncated_header_fail_closed():
    clean(lambda: engine.crx_parts(b"Cr24" + struct.pack("<II", 2, 0)))


@pytest.mark.parametrize("function", [engine.read_workflow, engine.read_gem_spec])
def test_yaml_malformed_fail_closed(function):
    clean(lambda: function(b"x: ["))


def test_missing_record_fail_closed():
    clean(lambda: engine.check_record({}, "pkg.dist-info/RECORD"))
