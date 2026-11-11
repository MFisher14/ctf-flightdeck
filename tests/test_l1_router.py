"""Routing: each matcher on synthetic handouts, the all-conditions rule, scores and order,
and handout files treated as untrusted (symlinks, FIFOs, hostile names, size limits)."""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from ctf_flightdeck.agent.workspace import HostWorkspace
from ctf_flightdeck.l1.manifest import Entry, Manifest, Route
from ctf_flightdeck.l1.router import MAX_FILES, HandoutFiles, Hit, route

from l1_kit import challenge, run


def engine(engine_id: str, *routes: Route) -> Manifest:
    return Manifest(engine_id, Entry("cli", None, None, ("true",)), (), (), 60, "text", routes, Path(f"/pack/{engine_id}.manifest.toml"))


def ids(hits: list[Hit]) -> list[str]:
    return [hit.manifest.id for hit in hits]


@pytest.fixture
def handout(tmp_path: Path) -> Path:
    h = tmp_path / "handout"
    (h / "sub" / "deeper").mkdir(parents=True)
    (h / "challenge.json").write_text('{"name": "x", "category": "misc", "points": 1}')
    (h / "notes.TXT").write_text("plain text\n")
    (h / "dump.tar.gz").write_bytes(b"\x1f\x8b\x08\x00rest")
    (h / "sub" / "deeper" / "archive.bin").write_bytes(b"PK\x03\x04zip inside")
    (h / "sub" / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0jpeg")
    return h


def test_category_matches_the_boards_short_code(handout):
    rule = Route(category=("cry", "for"))
    assert ids(route([engine("e", rule)], challenge(category="cry"), handout)) == ["e"]
    assert ids(route([engine("e", rule)], challenge(category="Crypto"), handout)) == ["e"]  # a raw name is mapped
    assert ids(route([engine("e", rule)], challenge(category="web"), handout)) == []


def test_a_keyword_is_a_substring_of_the_name_and_description_ignoring_case(handout):
    rule = Route(keywords=("base64", "onion"))
    assert ids(route([engine("e", rule)], challenge("Base64 Bonanza"), handout)) == ["e"]
    assert ids(route([engine("e", rule)], challenge("Layers", description="Peel the ONION."), handout)) == ["e"]
    assert ids(route([engine("e", rule)], challenge("Layers", description="peel it"), handout)) == []
    # name + " " + description: a keyword can span the join, never a word glued across it
    assert ids(route([engine("e", Route(keywords=("dolls nest",)))], challenge("Dolls", description="nest"), handout)) == ["e"]
    assert ids(route([engine("e", Route(keywords=("dollsnest",)))], challenge("Dolls", description="nest"), handout)) == []


@pytest.mark.parametrize(
    ("pattern", "matches"),
    [
        ("ext:.txt", True),  # notes.TXT: case-insensitive
        ("ext:.tar.gz", True),  # a multi-part suffix
        ("ext:.gz", True),
        ("ext:.zip", False),
        ("ext:.jpg", True),  # found in a subfolder
        ("name:*.bin", True),  # two levels down
        ("name:notes.*", True),
        ("name:NOTES.*", False),  # globs are case-sensitive
        ("name:sub", False),  # a directory is not a file
        ("magic:PK\u0003\u0004", True),
        ("magic:ÿØÿ", True),  # latin-1 text is bytes 0xff 0xd8 0xff
        ("magic:0x1f8b08", True),
        ("magic:0x1f8b09", False),
        ("magic:plain text", True),
        ("magic:text", False),  # must be at the start
        ("name:challenge.json", False),  # the board's own metadata is not a handout file
        ("ext:.json", False),
    ],
)
def test_file_patterns(handout, pattern, matches):
    hits = route([engine("e", Route(files=(pattern,)))], challenge(), handout)
    assert ids(hits) == (["e"] if matches else [])


def test_one_matching_file_pattern_of_several_is_enough(handout):
    hits = route([engine("e", Route(files=("ext:.zip", "name:*.jpg")))], challenge(), handout)
    assert ids(hits) == ["e"] and "photo.jpg" in hits[0].reason and "name:*.jpg" in hits[0].reason


def test_every_condition_a_route_states_must_hold(handout):
    rule = Route(category=("cry",), keywords=("rsa",), files=("ext:.txt",))
    assert ids(route([engine("e", rule)], challenge("Tiny RSA", category="cry"), handout)) == ["e"]
    assert ids(route([engine("e", rule)], challenge("Tiny RSA", category="web"), handout)) == []
    assert ids(route([engine("e", rule)], challenge("Tiny AES", category="cry"), handout)) == []
    no_txt = Route(category=("cry",), keywords=("rsa",), files=("ext:.pem",))
    assert ids(route([engine("e", no_txt)], challenge("Tiny RSA", category="cry"), handout)) == []


def test_the_best_matching_route_gives_the_score_and_hits_sort_by_priority_then_id(handout):
    manifests = [
        engine("b-low", Route(keywords=("demo",), priority=10)),
        engine("a-mid", Route(keywords=("demo",), priority=50)),
        engine("c-two-routes", Route(keywords=("demo",), priority=20), Route(files=("ext:.txt",), priority=90), Route(keywords=("nope",), priority=100)),
        engine("a-tie", Route(keywords=("demo",), priority=50)),
        engine("z-miss", Route(keywords=("absent",), priority=99)),
    ]
    hits = route(manifests, challenge("Demo"), handout)
    assert [(h.manifest.id, h.priority) for h in hits] == [("c-two-routes", 90), ("a-mid", 50), ("a-tie", 50), ("b-low", 10)]
    assert hits[0].reason == "file 'notes.TXT' (ext:.txt)"  # the route that scored, not the first that matched


def test_the_reason_names_each_condition_that_held(handout):
    rule = Route(category=("cry",), keywords=("base64",), files=("magic:PK",))
    [hit] = route([engine("e", rule)], challenge("Base64 zip", category="cry"), handout)
    assert hit.reason == "category cry, keyword 'base64', file 'sub/deeper/archive.bin' (magic:PK)"


def test_symlinks_in_a_handout_are_never_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
    h = tmp_path / "h"
    h.mkdir()
    os.symlink(outside / "secret.pcap", h / "link.pcap")
    os.symlink(outside, h / "linkdir")
    for pattern in ("name:*.pcap", "magic:0xd4c3b2a1", "name:secret.pcap"):
        assert route([engine("e", Route(files=(pattern,)))], challenge(), h) == []


def test_a_fifo_in_a_handout_cannot_hang_routing(tmp_path):
    h = tmp_path / "h"
    h.mkdir()
    os.mkfifo(h / "aaa.bin")  # first in name order
    (h / "zzz.bin").write_bytes(b"MAGIC")
    out: list[list[Hit]] = []
    worker = threading.Thread(target=lambda: out.append(route([engine("e", Route(files=("magic:MAGIC",)))], challenge(), h)), daemon=True)
    worker.start()
    worker.join(10)
    assert not worker.is_alive(), "route() blocked on a FIFO"
    assert ids(out[0]) == ["e"] and "zzz.bin" in out[0][0].reason


def test_at_most_2000_handout_files_are_looked_at(tmp_path):
    h = tmp_path / "h"
    h.mkdir()
    for i in range(MAX_FILES):
        (h / f"f{i:05d}.dat").write_bytes(b"")
    (h / "zzzz").mkdir()
    (h / "zzzz" / "late.pcap").write_bytes(b"")  # walked after every file of the top folder
    assert route([engine("e", Route(files=("name:*.pcap",)))], challenge(), h) == []
    (h / "f00000.dat").unlink()
    assert ids(route([engine("e", Route(files=("name:*.pcap",)))], challenge(), h)) == ["e"]


def test_flightdecks_own_folder_and_a_nested_challenge_json(tmp_path):
    h = tmp_path / "h"
    (h / ".flightdeck").mkdir(parents=True)
    (h / ".flightdeck" / "x.pcap").write_bytes(b"")
    assert route([engine("e", Route(files=("name:*.pcap",)))], challenge(), h) == []
    (h / "inner").mkdir()
    (h / "inner" / "challenge.json").write_text("{}")  # only the top one is the board's
    assert ids(route([engine("e", Route(files=("name:challenge.json",)))], challenge(), h)) == ["e"]
    (h / ".hidden.pcap").write_bytes(b"")  # hidden handout files are handout files
    assert ids(route([engine("e", Route(files=("name:*.pcap",)))], challenge(), h)) == ["e"]


def test_a_hostile_file_name_is_made_safe_in_the_reason(tmp_path):
    h = tmp_path / "h"
    h.mkdir()
    (h / "evil\x1b[31m‮.txt").write_text("x")
    [hit] = route([engine("e", Route(files=("ext:.txt",)))], challenge(), h)
    assert "\x1b" not in hit.reason and "‮" not in hit.reason
    assert "^[" in hit.reason  # the escape is shown, not sent to the terminal


def test_files_are_only_read_when_a_magic_pattern_needs_them(tmp_path, monkeypatch):
    h = tmp_path / "h"
    h.mkdir()
    (h / "a.txt").write_text("x")
    from ctf_flightdeck.l1 import router

    opened: list[str] = []
    real = router._head
    monkeypatch.setattr(router, "_head", lambda root, rel: opened.append(rel) or real(root, rel))
    route([engine("e", Route(files=("ext:.txt", "name:*.txt")))], challenge(), h)
    assert opened == []
    route([engine("e", Route(files=("magic:x",))), engine("f", Route(files=("magic:x",)))], challenge(), h)
    assert opened == ["a.txt"]  # read once, for both engines


def test_routing_sees_exactly_the_files_an_engines_copy_will_have(tmp_path):
    # the real M1 copy is the reference: if copy_handout's rules change, this fails
    h = tmp_path / "h"
    for rel in ("challenge.json", "top.txt", ".hidden.bin", "sub/a.pyc", "sub/deep/b.txt", "__pycache__/x.cpython-311.pyc",
                "sub/__pycache__/y.cpython-312.pyc", ".flightdeck/home/.bashrc", "sub/.flightdeck/kept.txt"):
        (h / rel).parent.mkdir(parents=True, exist_ok=True)
        (h / rel).write_bytes(b"x")
    os.symlink(h / "top.txt", h / "link.txt")
    os.symlink(h / "sub", h / "linkdir")
    os.mkfifo(h / "pipe")
    copy = tmp_path / "copy"
    run(HostWorkspace(copy, h).prepare())
    copied = sorted(
        str(path.relative_to(copy).as_posix()) for path in copy.rglob("*")
        if path.is_file() and not path.relative_to(copy).as_posix().startswith(".flightdeck/")
    )
    assert sorted(rel for rel, _ in HandoutFiles(h).files()) == [rel for rel in copied if rel != "challenge.json"]
    assert "sub/.flightdeck/kept.txt" in copied and "sub/a.pyc" in copied  # what is copied is routed on


def test_a_file_in_a_pycache_folder_never_routes_an_engine_that_would_not_see_it(tmp_path):
    h = tmp_path / "h"
    (h / "__pycache__").mkdir(parents=True)
    (h / "__pycache__" / "chall.cpython-311.pyc").write_bytes(b"\x6f\x0d\x0d\x0a" + b"\x00" * 12)
    pyc = engine("rev.pyc", Route(files=("ext:.pyc", "magic:0x6f0d0d0a"), priority=90))
    assert route([pyc], challenge(category="rev"), h) == []  # the copy has no __pycache__, so nothing to give it
    (h / "chall.pyc").write_bytes(b"\x6f\x0d\x0d\x0a" + b"\x00" * 12)  # a .pyc of the handout's own is copied
    [hit] = route([pyc], challenge(category="rev"), h)
    assert hit.reason == "file 'chall.pyc' (ext:.pyc)"


def test_a_handout_that_is_not_a_directory_is_an_error(tmp_path):
    with pytest.raises(ValueError, match="not a directory"):
        route([engine("e", Route(keywords=("x",)))], challenge(), tmp_path / "missing")
