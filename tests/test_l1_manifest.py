"""Manifests: what a valid one gives, every way one can be wrong (a ManifestError naming the
file and the key), and how discover() walks a pack."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest

from ctf_flightdeck.l1.manifest import (
    Entry,
    ManifestError,
    Route,
    discover,
    file_pattern,
    generated_root,
    load,
    manifest_files,
    pack_file,
    read_pack,
)

from l1_kit import write_manifest


@pytest.fixture
def pack(tmp_path: Path) -> Path:
    p = tmp_path / "pack"
    p.mkdir()
    (p / "decode_layers.py").write_text("def solve(d):\n    return None\n")
    (p / "tool.sh").write_text("#!/bin/sh\necho hi\n")
    (p / "tool.sh").chmod(0o755)
    (p / "plain.sh").write_text("#!/bin/sh\necho hi\n")
    (p / "plain.sh").chmod(0o644)
    return p


def test_a_full_manifest_loads_with_every_field(pack):
    path = write_manifest(pack, "b64", """
        id = "decode.base64_layers"
        entry = "decode_layers.py:solve"
        tags = ["crypto", "decode"]
        needs_tools = ["python3", "zsteg"]
        timeout_seconds = 30
        output = "result"

        [[routes]]
        category = ["cry"]
        keywords = ["base64"]
        files = ["ext:.txt", "magic:PK", "magic:0x1f8b", "name:*.pcap"]
        priority = 60

        [[routes]]
        keywords = ["layers", "onion"]
        """)
    m = load(path)
    assert m.id == "decode.base64_layers"
    assert m.entry == Entry("python", "decode_layers.py", "solve")
    assert m.entry_file == pack / "decode_layers.py"
    assert (m.tags, m.needs_tools, m.timeout_seconds, m.output) == (("crypto", "decode"), ("python3", "zsteg"), 30, "result")
    assert m.routes == (
        Route(("cry",), ("base64",), ("ext:.txt", "magic:PK", "magic:0x1f8b", "name:*.pcap"), 60),
        Route((), ("layers", "onion"), (), 50),
    )
    assert m.path == path and m.base == pack


def test_defaults_and_a_cli_entry(pack):
    m = load(write_manifest(pack, "tool", """
        id = "tool"
        entry = "cli:./tool.sh --fast 'two words'"
        [[routes]]
        files = ["name:*.bin"]
        """))
    assert m.entry == Entry("cli", None, None, ("./tool.sh", "--fast", "two words"))
    assert m.entry_file is None
    assert (m.tags, m.needs_tools, m.timeout_seconds, m.output) == ((), (), 60, "result")
    assert m.routes[0].priority == 50


def test_a_cli_entry_may_name_a_command_on_path_or_an_absolute_program(pack):
    for i, entry in enumerate(("cli:python3 x.py", "cli:/usr/bin/env python3", "cli:zsteg -a")):
        m = load(write_manifest(pack, f"e{i}", f'id = "e{i}"\nentry = "{entry}"\n[[routes]]\nkeywords = ["k"]\n'))
        assert m.entry.kind == "cli"


ROUTE = '[[routes]]\nkeywords = ["k"]\n'
HEAD = 'id = "e"\nentry = "decode_layers.py:solve"\n'


@pytest.mark.parametrize(
    ("text", "key", "words"),
    [
        ('id = "e"\nentry = "decode_layers.py:solve"\nroute = []\n' + ROUTE, "route", "unknown key"),
        ('id = "e"\nentry = "decode_layers.py:solve"\ntimeout = 5\n' + ROUTE, "timeout", "unknown key"),
        ('entry = "decode_layers.py:solve"\n' + ROUTE, "id", "is missing"),
        ('id = "Decode"\nentry = "decode_layers.py:solve"\n' + ROUTE, "id", "lower-case"),
        ('id = "-x"\nentry = "decode_layers.py:solve"\n' + ROUTE, "id", "lower-case"),
        ('id = "a/b"\nentry = "decode_layers.py:solve"\n' + ROUTE, "id", "lower-case"),
        ('id = 7\nentry = "decode_layers.py:solve"\n' + ROUTE, "id", "lower-case"),
        (f'id = "{"a" * 101}"\nentry = "decode_layers.py:solve"\n' + ROUTE, "id", "at most 100"),
        ('id = "e"\n' + ROUTE, "entry", "is missing"),
        ('id = "e"\nentry = ""\n' + ROUTE, "entry", "must be"),
        ('id = "e"\nentry = 3\n' + ROUTE, "entry", "must be"),
        ('id = "e"\nentry = "decode_layers.py"\n' + ROUTE, "entry", "must be"),
        ('id = "e"\nentry = "decode_layers.py:"\n' + ROUTE, "entry", "not a python function name"),
        ('id = "e"\nentry = "decode_layers.py:so-lve"\n' + ROUTE, "entry", "not a python function name"),
        ('id = "e"\nentry = "tool.sh:solve"\n' + ROUTE, "entry", "names a .py file"),
        ('id = "e"\nentry = "missing.py:solve"\n' + ROUTE, "entry", "does not exist"),
        ('id = "e"\nentry = "../decode_layers.py:solve"\n' + ROUTE, "entry", "with no .."),
        ('id = "e"\nentry = "/etc/x.py:solve"\n' + ROUTE, "entry", "relative path"),
        ('id = "e"\nentry = "cli:"\n' + ROUTE, "entry", "is empty"),
        ('id = "e"\nentry = "cli:   "\n' + ROUTE, "entry", "is empty"),
        ('id = "e"\nentry = "cli:./tool.sh \'open"\n' + ROUTE, "entry", "does not split"),
        ('id = "e"\nentry = "cli:./missing.sh"\n' + ROUTE, "entry", "does not exist"),
        ('id = "e"\nentry = "cli:./plain.sh"\n' + ROUTE, "entry", "is not executable"),
        ('id = "e"\nentry = "cli:../tool.sh"\n' + ROUTE, "entry", "with no .."),
        (HEAD + 'tags = "crypto"\n' + ROUTE, "tags", "must be a list"),
        (HEAD + 'tags = ["Crypto"]\n' + ROUTE, "tags[0]", "lower-case"),
        (HEAD + 'tags = ["ok", ""]\n' + ROUTE, "tags[1]", "non-empty"),
        (HEAD + 'tags = ["two words"]\n' + ROUTE, "tags[0]", "no spaces"),
        (HEAD + 'needs_tools = ["zsteg", 3]\n' + ROUTE, "needs_tools[1]", "non-empty string"),
        (HEAD + 'needs_tools = ["/usr/bin/zsteg"]\n' + ROUTE, "needs_tools[0]", "not a path"),
        (HEAD + "timeout_seconds = 0\n" + ROUTE, "timeout_seconds", "1..600"),
        (HEAD + "timeout_seconds = 601\n" + ROUTE, "timeout_seconds", "1..600"),
        (HEAD + "timeout_seconds = 1.5\n" + ROUTE, "timeout_seconds", "1..600"),
        (HEAD + "timeout_seconds = true\n" + ROUTE, "timeout_seconds", "1..600"),
        (HEAD + 'output = "json"\n' + ROUTE, "output", '"result" or "text"'),
        (HEAD, "routes", "is missing"),
        (HEAD + "routes = []\n", "routes", "is empty"),
        (HEAD + "[routes]\nkeywords = ['k']\n", "routes", "[[routes]] tables"),
        (HEAD + 'routes = ["k"]\n', "routes", "[[routes]] tables"),
        (HEAD + "[[routes]]\npriority = 10\n", "routes[0]", "has no condition"),
        (HEAD + ROUTE + "[[routes]]\nkeyword = ['k']\n", "routes[1].keyword", "unknown key"),
        (HEAD + "[[routes]]\nkeywords = []\n", "routes[0].keywords", "non-empty list"),
        (HEAD + "[[routes]]\nkeywords = 'base64'\n", "routes[0].keywords", "non-empty list"),
        (HEAD + "[[routes]]\nkeywords = ['Base64']\n", "routes[0].keywords[0]", "lower-case"),
        (HEAD + "[[routes]]\nkeywords = ['']\n", "routes[0].keywords[0]", "non-empty string"),
        (HEAD + "[[routes]]\ncategory = ['Cry']\n", "routes[0].category[0]", "lower-case"),
        (HEAD + "[[routes]]\ncategory = ['crypto']\n", "routes[0].category[0]", "short code 'cry'"),
        (HEAD + "[[routes]]\ncategory = ['forensics']\n", "routes[0].category[0]", "short code 'for'"),
        (HEAD + "[[routes]]\nfiles = ['.txt']\n", "routes[0].files[0]", "must start with ext:, magic: or name:"),
        (HEAD + "[[routes]]\nfiles = ['size:10']\n", "routes[0].files[0]", "must start with ext:"),
        (HEAD + "[[routes]]\nfiles = ['ext:txt']\n", "routes[0].files[0]", "with its dot"),
        (HEAD + "[[routes]]\nfiles = ['ext:.']\n", "routes[0].files[0]", "with its dot"),
        (HEAD + "[[routes]]\nfiles = ['name:']\n", "routes[0].files[0]", "file-name glob"),
        (HEAD + "[[routes]]\nfiles = ['name:dir/*.txt']\n", "routes[0].files[0]", "with no /"),
        (HEAD + "[[routes]]\nfiles = ['magic:']\n", "routes[0].files[0]", "the bytes a file starts with"),
        (HEAD + "[[routes]]\nfiles = ['magic:0x1f8']\n", "routes[0].files[0]", "whole bytes in hex"),
        (HEAD + "[[routes]]\nfiles = ['magic:0xzz']\n", "routes[0].files[0]", "whole bytes in hex"),
        (HEAD + "[[routes]]\nfiles = ['magic:0x']\n", "routes[0].files[0]", "whole bytes in hex"),
        (HEAD + "[[routes]]\nfiles = ['magic:☃']\n", "routes[0].files[0]", "latin-1"),
        (HEAD + f"[[routes]]\nfiles = ['magic:{'A' * 4097}']\n", "routes[0].files[0]", "4096"),
        (HEAD + "[[routes]]\nkeywords = ['k']\npriority = 101\n", "routes[0].priority", "0..100"),
        (HEAD + "[[routes]]\nkeywords = ['k']\npriority = -1\n", "routes[0].priority", "0..100"),
        (HEAD + "[[routes]]\nkeywords = ['k']\npriority = true\n", "routes[0].priority", "0..100"),  # a bool is not an int
        (HEAD + "[[routes]]\nkeywords = ['k']\npriority = '60'\n", "routes[0].priority", "0..100"),
    ],
)
def test_every_manifest_error_names_the_file_and_the_key(pack, text, key, words):
    path = pack / "bad.manifest.toml"
    path.write_text(text)
    with pytest.raises(ManifestError) as caught:
        load(path)
    error = caught.value
    assert error.path == path and error.key == key
    assert str(error).startswith(f"{path}: {key}: ")
    assert words in error.problem


@pytest.mark.parametrize(
    ("content", "words"),
    [
        (b'id = "e"\nentry = \n', "is not valid TOML"),
        (b'id = "\xff"\n', "is not UTF-8 text"),
        (b"x" * (256 * 1024 + 1), "too big for a manifest"),
    ],
)
def test_an_unreadable_manifest_is_an_error_naming_the_file(pack, content, words):
    path = pack / "bad.manifest.toml"
    path.write_bytes(content)
    with pytest.raises(ManifestError, match=words) as caught:
        load(path)
    assert caught.value.path == path and caught.value.key is None


def test_a_python_entry_may_not_leave_the_pack_through_a_symlink(tmp_path, pack):
    outside = tmp_path / "elsewhere.py"
    outside.write_text("def solve(d):\n    return None\n")
    os.symlink(outside, pack / "link.py")
    path = write_manifest(pack, "e", 'id = "e"\nentry = "link.py:solve"\n' + ROUTE)
    with pytest.raises(ManifestError, match="leaves .* through a symlink"):
        load(path)
    (pack / "sub").mkdir()
    os.symlink(pack / "decode_layers.py", pack / "sub" / "inside.py")  # a symlink that stays inside is fine
    assert load(write_manifest(pack, "f", 'id = "f"\nentry = "sub/inside.py:solve"\n' + ROUTE)).entry.path == "sub/inside.py"


def test_a_python_entry_is_relative_to_the_manifests_own_folder(pack):
    (pack / "deep" / "er").mkdir(parents=True)
    (pack / "deep" / "er" / "x.py").write_text("def solve(d):\n    return None\n")
    m = load(write_manifest(pack / "deep", "x", 'id = "x"\nentry = "er/x.py:solve"\n' + ROUTE))
    assert m.base == pack / "deep" and m.entry_file == pack / "deep" / "er" / "x.py"
    with pytest.raises(ManifestError, match="does not exist"):  # not resolved against the pack root
        load(write_manifest(pack / "deep" / "er", "y", 'id = "y"\nentry = "er/x.py:solve"\n' + ROUTE))


def test_a_generated_manifest_starts_its_paths_at_the_imported_folder(pack):
    (pack / "crypto").mkdir()
    (pack / "crypto" / "rsa.py").write_text("def solve(d):\n    return None\n")
    path = write_manifest(pack / ".flightdeck" / "generated" / "crypto", "rsa.py", 'id = "g"\nentry = "crypto/rsa.py:solve"\n' + ROUTE)
    assert generated_root(path) == pack
    assert generated_root(pack / "crypto" / "rsa.py") is None
    m = load(path)
    assert m.base == pack and m.entry_file == pack / "crypto" / "rsa.py"


def test_discover_finds_every_manifest_sorted_by_id_and_skips_hidden_and_private_folders(pack, tmp_path):
    write_manifest(pack, "z", 'id = "zeta"\nentry = "decode_layers.py:solve"\n' + ROUTE)
    (pack / "nested" / "deeper").mkdir(parents=True)
    (pack / "nested" / "deeper" / "e.py").write_text("def solve(d):\n    return None\n")
    write_manifest(pack / "nested" / "deeper", "e", 'id = "alpha"\nentry = "e.py:solve"\n' + ROUTE)
    write_manifest(pack / ".git", "h", 'id = "hidden-dir"\nentry = "cli:true"\n' + ROUTE)
    write_manifest(pack, ".dot", 'id = "hidden-file"\nentry = "cli:true"\n' + ROUTE)
    write_manifest(pack / ".flightdeck", "p", 'id = "private"\nentry = "cli:true"\n' + ROUTE)
    write_manifest(pack / ".flightdeck" / "other", "p", 'id = "private-other"\nentry = "cli:true"\n' + ROUTE)
    write_manifest(pack / ".flightdeck" / "generated", "g", 'id = "generated"\nentry = "cli:true"\n' + ROUTE)
    write_manifest(pack / "sub" / ".flightdeck" / "generated", "g", 'id = "generated-sub"\nentry = "cli:true"\n' + ROUTE)
    (pack / "notes.toml").write_text("not a manifest = 1\n")
    outside = tmp_path / "outside"
    write_manifest(outside, "o", 'id = "outside"\nentry = "cli:true"\n' + ROUTE)
    os.symlink(outside, pack / "linked-dir")  # never followed
    assert [m.id for m in discover(pack)] == ["alpha", "generated", "generated-sub", "zeta"]
    assert "generated" not in [load(p).id for p in manifest_files(pack, generated=False)]
    assert [m.id for m in discover(pack / "nested")] == ["alpha"]


PLANTED = 'id = "aaa.planted"\nentry = "cli:./x.sh"\noutput = "text"\n[[routes]]\nkeywords = ["e"]\npriority = 100\n'


def plant(folder: Path) -> None:
    """What a hostile handout ships: a manifest and an executable script for it."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "x.manifest.toml").write_text(PLANTED)
    (folder / "x.sh").write_text("#!/bin/sh\necho t{planted}\n")
    (folder / "x.sh").chmod(0o755)


def test_folders_that_hold_a_challenges_files_are_never_searched_and_are_reported(pack):
    write_manifest(pack, "mine", 'id = "mine"\nentry = "decode_layers.py:solve"\n' + ROUTE)
    challenge = pack / "examples" / "evil"
    plant(challenge)
    (challenge / "challenge.json").write_text('{"name": "Evil", "category": "misc", "points": 1}')
    board = pack / "boards" / "event"
    plant(board / "loose")
    (board / "board.json").write_text('{"event": "x"}')
    workspace = pack / "runs" / "20261111-000000" / "grep"  # an engine's copy of a challenge, its challenge.json gone
    plant(workspace)
    (workspace / ".flightdeck").mkdir()
    (workspace / ".flightdeck" / "prepare.log").write_text("copied 2 files\n")
    write_manifest(challenge, "broken", 'id = "broken"\n')  # a challenge's broken manifest breaks nothing
    found = read_pack(pack)
    assert [m.id for m in found.manifests] == ["mine"] and discover(pack) == found.manifests
    assert found.skipped == [
        (board, "a board folder (it has a board.json)"),
        (challenge, "a challenge folder (it has a challenge.json)"),
        (workspace, "a flightdeck workspace, a copy of a challenge (it has .flightdeck/prepare.log)"),
    ]
    assert manifest_files(pack) == [pack / "mine.manifest.toml"]


def test_a_dangling_symlink_named_challenge_json_still_marks_a_challenge(pack, tmp_path):
    plant(pack / "c")
    os.symlink(tmp_path / "nowhere", pack / "c" / "challenge.json")
    assert discover(pack) == [] and read_pack(pack).skipped[0][0] == pack / "c"


def test_a_pack_that_is_itself_a_challenge_board_or_workspace_is_an_error(tmp_path):
    for name, marker in (("chal", "challenge.json"), ("board", "board.json"), ("ws", ".flightdeck/prepare.log")):
        folder = tmp_path / name
        plant(folder)
        (folder / marker).parent.mkdir(parents=True, exist_ok=True)
        (folder / marker).write_text("{}")
        with pytest.raises(ManifestError, match="not a pack of engines") as caught:
            discover(folder)
        assert caught.value.path == folder


def test_two_manifests_with_one_id_name_both_files(pack):
    first = write_manifest(pack, "a", 'id = "same"\nentry = "decode_layers.py:solve"\n' + ROUTE)
    second = write_manifest(pack / "sub", "b", 'id = "same"\nentry = "cli:true"\n' + ROUTE)
    with pytest.raises(ManifestError) as caught:
        discover(pack)
    message = str(caught.value)
    assert str(first) in message and str(second) in message and caught.value.key == "id"


def test_discover_fails_loudly_on_one_bad_manifest_and_on_a_missing_pack(pack, tmp_path):
    write_manifest(pack, "good", 'id = "good"\nentry = "decode_layers.py:solve"\n' + ROUTE)
    write_manifest(pack, "bad", 'id = "bad"\nentry = "decode_layers.py:solve"\n')
    with pytest.raises(ManifestError, match="routes: is missing"):
        discover(pack)
    with pytest.raises(ManifestError, match="no such pack folder"):
        discover(tmp_path / "nope")
    (tmp_path / "file").write_text("x")
    with pytest.raises(ManifestError, match="is not a folder"):
        discover(tmp_path / "file")


def test_an_empty_pack_has_no_engines(tmp_path):
    (tmp_path / "empty").mkdir()
    assert discover(tmp_path / "empty") == []


def test_file_patterns_parse_to_what_the_router_compares():
    assert file_pattern("ext:.TAR.GZ") == ("ext", ".tar.gz")
    assert file_pattern("name:*.pcap") == ("name", "*.pcap")
    assert file_pattern("magic:PK\u0003\u0004") == ("magic", b"PK\x03\x04")
    assert file_pattern("magic:ÿØ") == ("magic", b"\xff\xd8")  # latin-1
    assert file_pattern("magic:0x1F8b") == ("magic", b"\x1f\x8b")
    with pytest.raises(ValueError):
        file_pattern("magic:0x1f 8b")


def test_pack_file_names_only_existing_files_inside_the_base(pack):
    assert pack_file("tool.sh", pack) == pack / "tool.sh"
    assert pack_file("./tool.sh", pack) == pack / "tool.sh"
    for word in ("--fast", "python3", "/bin/sh", "../pack/tool.sh", ".", "", "missing.sh"):
        assert pack_file(word, pack) is None, word


def test_a_manifest_text_can_be_dedented_as_written_in_the_docs(pack):
    text = textwrap.dedent("""\
        id = "decode.base64_layers"          # required
        entry = "decode_layers.py:solve"     # required
        [[routes]]
        category = ["cry"]
        keywords = ["base64"]
        files = ["ext:.txt", "magic:PK", "name:*.pcap"]
        priority = 60
        """)
    (pack / "doc.manifest.toml").write_text(text)
    assert load(pack / "doc.manifest.toml").routes[0].priority == 60
