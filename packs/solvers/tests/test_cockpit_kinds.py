"""B-209: what a dropped file is, and what is wrong with a challenge's drop (ctf/cockpit/kinds.py).

Every fixture is a few synthetic bytes written here; no challenge file is used.
"""
from __future__ import annotations

import struct

import pytest

from ctf.cockpit import kinds


def _write(tmp_path, name, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def _elf(etype: int, big: bool = False) -> bytes:
    ident = b"\x7fELF" + bytes([2, 2 if big else 1, 1]) + b"\x00" * 9
    return ident + struct.pack(">H" if big else "<H", etype) + b"\x00" * 46


@pytest.mark.parametrize("name,data,kind,role", [
    ("box.lime", b"EMiL\x01\x00\x00\x00" + b"\x00" * 40, "memory", "capture"),
    ("anything.bin", b"EMiL" + b"\x00" * 40, "memory", "capture"),       # magic wins over the name
    ("crash.dmp", b"PAGEDU64" + b"\x00" * 40, "memory", "capture"),
    ("core", _elf(4), "memory", "capture"),
    ("core.be", _elf(4, big=True), "memory", "capture"),
    ("prog", _elf(2), "elf", "file"),
    ("prog.be", _elf(2, big=True), "elf", "file"),
    ("t.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20, "pcap", "capture"),
    ("t.pcapng", b"\x0a\x0d\x0d\x0a" + b"\x00" * 20, "pcap", "capture"),
    ("disk.E01", b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 20, "disk", "capture"),
    ("Security.evtx", b"ElfFile\x00" + b"\x00" * 20, "evtx", "capture"),
    ("symbols.json.xz", b"\xfd7zXZ\x00" + b"\x00" * 20, "symbols", "helper"),
    ("linux-5.15-symbols.json", b'{"metadata": {}}', "symbols", "helper"),
    ("sslkeys.log", b"CLIENT_RANDOM 00 11\n", "keylog", "helper"),
    ("chal.zip", b"PK\x03\x04" + b"\x00" * 20, "archive", "file"),
    ("t.tar", b"x" * 257 + b"ustar\x0000" + b"\x00" * 250, "archive", "file"),
    ("page.zip", b"\n  <!DOCTYPE html><html><body>Sign in</body></html>", "html", "file"),
    ("mem.raw", b"\x00\x01\x02\x03" * 16, "memory", "capture"),           # raw: by its extension only
    ("notes.txt", b"hello spooky\n", "text", "file"),
    ("blob.bin", bytes(range(0, 32)) * 4, "data", "file"),
    ("empty.pcap", b"", "empty", "file"),
])
def test_classify(tmp_path, name, data, kind, role):
    k = kinds.classify(_write(tmp_path, name, data))
    assert (k.kind, k.role) == (kind, role), k


def test_classify_reads_only_the_head(tmp_path):
    # A big capture costs one small read: the tail is never looked at.
    p = tmp_path / "big.lime"
    with open(p, "wb") as fh:
        fh.write(b"EMiL" + b"\x00" * 60)
        fh.seek(64 << 20)
        fh.write(b"<html>")
    assert kinds.classify(p).kind == "memory"


@pytest.mark.parametrize("name,data,code", [
    ("chal.zip", b"<!doctype html><html>virus scan warning</html>", "disguised_html"),
    ("capture.pcap", b"<html><head>", "disguised_html"),
    ("capture.pcap", b"PK\x03\x04" + b"\x00" * 20, "extension_mismatch"),
    ("dump.lime", b"%PDF-1.7", "extension_mismatch"),
    ("archive.7z", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20, "extension_mismatch"),
    ("x.zip", b"", "empty_file"),
])
def test_file_problems_flag(tmp_path, name, data, code):
    p = _write(tmp_path, name, data)
    probs = kinds.file_problems(name, kinds.classify(p))
    assert [x.code for x in probs] == [code]
    assert probs[0].file == name and name in probs[0].message


@pytest.mark.parametrize("name,data", [
    ("page.html", b"<!DOCTYPE html><html>"),           # an HTML file named as one is fine
    ("readme.txt", b"<html> in a text file"),
    ("capture.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20),
    ("capture.pcap", b"some text that is not a pcap"),  # weak content proves nothing
    ("mem.lime", b"\x00\x11" * 30),                     # raw .lime (no header) is still a capture by name
    ("chal.zip", b"PK\x03\x04" + b"\x00" * 20),
    ("prog", _elf(2)),
])
def test_file_problems_quiet(tmp_path, name, data):
    assert kinds.file_problems(name, kinds.classify(_write(tmp_path, name, data))) == []


def _k(kind):
    return kinds.Kind(kind, {"memory": "capture", "pcap": "capture", "symbols": "helper",
                             "keylog": "helper"}.get(kind, "file"), kind)


def test_helper_without_capture_is_the_peering_eyes_case():
    probs = kinds.challenge_problems({"symbols.json.xz": _k("symbols")}, "a memory dump of a box")
    assert [(p.code, p.file) for p in probs] == [("helper_without_capture", "symbols.json.xz")]
    assert "memory image" in probs[0].message
    # The described capture is the same missing thing: not reported twice.
    assert not any(p.code == "capture_missing" for p in probs)


def test_helper_with_its_capture_is_fine():
    assert kinds.challenge_problems({"symbols.json.xz": _k("symbols"), "box.lime": _k("memory")},
                                    "a memory dump") == []


def test_keylog_without_pcap():
    probs = kinds.challenge_problems({"keys.log": _k("keylog")})
    assert [p.code for p in probs] == ["helper_without_capture"] and "packet capture" in probs[0].message
    assert kinds.challenge_problems({"keys.log": _k("keylog"), "t.pcap": _k("pcap")}) == []


@pytest.mark.parametrize("desc,cap", [
    ("Analyse the memory dump with volatility", "memory image"),
    ("Find the exfil in the pcap", "packet capture"),
    ("We took a forensic image of the laptop", "disk image"),
])
def test_described_capture_missing(desc, cap):
    probs = kinds.challenge_problems({"readme.txt": _k("text")}, desc)
    assert [p.code for p in probs] == ["capture_missing"] and cap in probs[0].message
    assert "archive" not in probs[0].message


def test_described_capture_missing_hedges_when_an_archive_may_hold_it():
    [p] = kinds.challenge_problems({"chal.zip": _k("archive")}, "the pcap is attached")
    assert p.code == "capture_missing" and "archive here may hold it" in p.message


def test_described_capture_present_or_no_files():
    assert kinds.challenge_problems({"t.pcap": _k("pcap")}, "find it in the pcap") == []
    assert kinds.challenge_problems({}, "find it in the pcap") == []        # the files need covers it
    assert kinds.challenge_problems({"a.png": _k("image")}, "a photo of a ghost") == []


@pytest.mark.parametrize("name,partial", [("x.zip.crdownload", True), ("x.part", True),
                                          ("Unconfirmed 1.download", True), ("x.zip", False),
                                          ("parts.txt", False)])
def test_is_partial(name, partial):
    assert kinds.is_partial(name) is partial


def test_matches_is_case_insensitive_glob_on_the_base_name():
    assert kinds.matches("*.LIME", "sub/box.lime")
    assert not kinds.matches("*.lime", "box.lime.txt")
