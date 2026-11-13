"""The [intake] input adapter in engine manifests (B-002, docs/CONTRACTS.md section 6)."""
from __future__ import annotations

from pathlib import Path

import pytest

from ctf import paths
from ctf.engines import manifest as M
from ctf.intake import engines as E

P = Path("solvers/toolkits/x.manifest.toml")
CLI = M.parse_entry(P, "cli:python solvers/toolkits/x.py")
FN = M.parse_entry(P, "solvers.toolkits.x:solve")


def spec(raw, entry=CLI, caps=()):
    return M.parse_intake(P, raw, entry, caps)


def test_defaults_per_run_mode():
    s = spec({"run": "per-file", "match": ["ext:.png"]})
    assert (s.select, s.args, s.max_files, s.timeout, s.spawns) == ("route", ("{file}",), 8, 30, False)
    assert spec({"run": "all-files", "match": ["ext:.png"]}).args == ("{files}",)
    assert spec({"run": "folder"}).args == ("{folder}",)
    assert spec({"run": "challenge"}, entry=FN).args == ()


def test_full_table_round_trips():
    s = spec({"run": "per-file", "select": "files", "match": ["magic:%PDF-", "name:*.pdf"],
              "args": ["--json", "{file}", "--out={out}"], "max_files": 3, "timeout": 12, "spawns": True})
    assert s == M.IntakeSpec(run="per-file", select="files", match=("magic:%PDF-", "name:*.pdf"),
                             args=("--json", "{file}", "--out={out}"), max_files=3, timeout=12, spawns=True)


@pytest.mark.parametrize("raw, entry, caps, key", [
    ([], CLI, (), "intake: expected a table"),
    ({"run": "folder", "speed": 1}, CLI, (), "intake.speed: unknown key"),
    ({"match": ["ext:.x"]}, CLI, (), "intake.run: required key missing"),
    ({"run": "each"}, CLI, (), "intake.run: 'each' not one of"),
    ({"run": "folder", "select": "always"}, CLI, (), "intake.select: 'always' not one of"),
    ({"run": "per-file"}, CLI, (), "intake.match: required for run = 'per-file'"),
    ({"run": "all-files"}, CLI, (), "intake.match: required"),
    ({"run": "folder", "select": "files"}, CLI, (), "intake.match: required"),
    ({"run": "folder", "match": ["png"]}, CLI, (), "intake.match[0]"),
    ({"run": "per-file", "match": ["ext:.x"]}, FN, (), "intake.run: 'per-file': a module:function entry"),
    ({"run": "challenge"}, CLI, (), "intake.run: \"challenge\" is the module:function contract"),
    ({"run": "challenge", "args": ["x"]}, FN, (), "intake.args: a module:function entry takes no argv"),
    ({"run": "folder", "args": "{folder}"}, CLI, (), "intake.args: expected a list"),
    ({"run": "folder", "args": ["{folder}", "{home}"]}, CLI, (), "intake.args[1]: {home} is not one of"),
    ({"run": "all-files", "match": ["ext:.x"], "args": ["--in={files}"]}, CLI, (), "use it alone"),
    ({"run": "folder", "args": ["{folder}", "{file}"]}, CLI, (), "{file} needs run = \"per-file\""),
    ({"run": "per-file", "match": ["ext:.x"], "args": ["{file}", "{files}"]}, CLI, (), "{files} needs run"),
    ({"run": "per-file", "match": ["ext:.x"], "args": ["{folder}"]}, CLI, (), "no {file} passes the input"),
    ({"run": "all-files", "match": ["ext:.x"], "args": ["{out}"]}, CLI, (), "no {files} passes the input"),
    ({"run": "folder", "args": ["--quiet"]}, CLI, (), "no {challenge} or {folder}"),
    ({"run": "folder", "max_files": 0}, CLI, (), "intake.max_files: 0 outside 1-64"),
    ({"run": "folder", "max_files": True}, CLI, (), "intake.max_files: expected an integer"),
    ({"run": "folder", "timeout": 601}, CLI, (), "intake.timeout: 601 outside 1-600"),
    ({"run": "folder", "spawns": "yes"}, CLI, (), "intake.spawns: expected true or false"),
    ({"run": "challenge"}, FN, ("library",), "a library engine is import-only"),
])
def test_bad_tables_name_the_key(raw, entry, caps, key):
    with pytest.raises(M.ManifestError) as ei:
        spec(raw, entry, caps)
    assert str(P) in str(ei.value) and key in str(ei.value)


def test_folder_run_may_pass_the_challenge_instead_of_the_folder():
    assert spec({"run": "folder", "args": ["--dir", "{challenge}"]}).args == ("--dir", "{challenge}")


def test_parse_reads_the_table_and_rejects_it_on_a_bad_entry_kind(tmp_path):
    base = {"id": "toolkits.x", "lane": "toolkits", "entry": "cli:python solvers/toolkits/x.py"}
    m = M.parse({**base, "intake": {"run": "folder"}}, P)
    assert m.intake == M.IntakeSpec(run="folder", args=("{folder}",))
    assert M.parse(base, P).intake is None
    with pytest.raises(M.ManifestError, match="intake.run"):
        M.parse({**base, "entry": "solvers.toolkits.x:solve", "intake": {"run": "folder"}}, P)


def _png():
    return b"\x89PNG\r\n\x1a\n" + b"\x00" * 16


@pytest.mark.parametrize("name, head, engine", [
    ("a.png", _png(), "metadata_forensics.file_properties"),
    ("b.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 8, "metadata_forensics.file_properties"),
    ("c.gif", b"GIF89a" + b"\x00" * 8, "metadata_forensics.file_properties"),
    ("d.tif", b"II*\x00\x08\x00\x00\x00", "metadata_forensics.file_properties"),
    ("doc", b"%PDF-1.7\n", "toolkits.pdf_revisions"),
])
def test_repo_adapters_take_their_files_and_not_others(name, head, engine):
    ms = {m.id: m for m in M.discover(paths.repo_root())}
    m = ms[engine]
    assert m.intake is not None and m.intake.select == "files" and m.intake.run == "per-file"
    assert E.files_matching(m.intake.match, [(Path(name), head)])
    assert not E.files_matching(m.intake.match, [(Path("notes.txt"), b"hello %PDF- GIF8 \x89PNG")])
