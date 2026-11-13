"""B-136: the Linux memory-image triage opener (the Volatility triage half of Spooky's Peering Eyes).

  .venv/bin/python -m pytest tests/test_b136_vol_triage.py

Offline, and nothing here touches Docker: every image and symbol table is built in the test, the
sandbox is either a stand-in `docker` program ($CTF_DOCKER, as tests/test_stego_review.py does it) or a
stub of memory.vol, and time is an injected step clock. What is checked:

  banner     memory.carve_linux_banners reads the kernel's whole banner; isf_banner reads the banner a
             table was made for (plain, xz, gz, bz2; across a read-block boundary; the same value
             Volatility 3's own identifier reads).
  match      linux_isfs / match_linux_isf pick a table by exact banner, never by release or file name,
             walk a bounded tree without entering hidden folders, and say what is missing; the pack is
             the `linux/<table>` zip the sandbox takes; memory_depth.select_profile states the same.
  vol        vol() hands the pack to the sandbox runner and tells "never ran" from "ran and failed";
             vol_save matches the table itself, stops after a sandbox that is down, and keeps a budget.
  model      a linux.bash table is shell history, not the shell's command line; saved tables replay.
  opener     vol_triage: flags and flag leads through ctf.flagfmt, the Volatility stage read into
             processes, history, notable processes and the hand-off; not run is said with its reason;
             a fragment is never printed in a form intake could read back as a flag.
  wiring     the opener arms under the network guard, intake plans and runs it, triage routes to it.
  round 2    names from the handout cannot start a report line; the longest table banner wins; the
             report is said line by line (a killed run has printed what it had); the banner carve and
             the AVML decompression keep a budget; a table over the pack limit is not packed; an AVML
             version 2 image is decompressed (cramjam) and read; two intake survivors.
"""
from __future__ import annotations

import base64
import bz2
import dataclasses
import gzip
import hashlib
import inspect
import io
import json
import lzma
import os
import shlex
import shutil
import struct
import subprocess
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path

import pytest

import memory          # solvers/toolkits (the root conftest puts it on sys.path)
import memory_depth
import vol_triage
from ctf import event, flagfmt, openers, triage
from ctf.engines import manifest as EM
from ctf.engines import runner
from ctf.intake import engines as IE
from ctf.intake import guard as G
from ctf.openers import fixtures
from ctf.openers import memory_fixtures as MF
from ctf.result import SolverResult

REPO = Path(__file__).resolve().parent.parent

B1 = ("Linux version 6.5.0-test-amd64 (dev@build) (gcc-13 (Test 13.2.0) 13.2.0, GNU ld (Test) 2.41) "
      "#1 SMP PREEMPT_DYNAMIC Test 6.5.6-1 (2026-03-03)")
B1_OTHER_BUILD = B1.replace("#1 SMP", "#2 SMP").replace("(2026-03-03)", "(2026-04-04)")   # same release, other table
B2 = "Linux version 5.10.0-other-arm64 (dev@build) (gcc (Test 10.2.1) 10.2.1) #1 SMP Test 5.10.200-1 (2026-01-05)"


class Clock:
    """A step clock: time moves only when a test (or a stub) moves it."""

    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def _isf_doc(banner: str, *, tail: bytes = b"\n\x00", before: str = "", meta: dict | None = None) -> bytes:
    """A Linux ISF, written here independently of the opener's fixture module: `before` is put in the
    metadata (padding), `meta` adds metadata keys (decoys that stand before the symbols), and the
    banner symbol's constant data is base64(banner + tail)."""
    raw = banner.encode() + tail
    doc = {"metadata": {"format": "6.2.0", "note": before, **(meta or {})},
           "base_types": {"pointer": {"size": 8, "signed": False, "kind": "int", "endian": "little"}},
           "user_types": {}, "enums": {},
           "symbols": {"init_task": {"address": 18446744071600106560},
                       "linux_banner": {"type": {"count": len(raw), "kind": "array", "subtype": {"kind": "base", "name": "char"}},
                                        "address": 18446744071594008672,
                                        "constant_data": base64.b64encode(raw).decode()}}}
    return json.dumps(doc).encode()


def _lime(*pages: bytes) -> bytes:
    out, start = b"", 0x100000
    for body in pages:
        out += b"EMiL" + struct.pack("<IQQ", 1, start, start + len(body) - 1) + bytes(8) + body
        start += len(body)
    return out


def _page(*strings: bytes, size: int = 4096) -> bytes:
    buf, at = bytearray(size), 0x80
    for s in strings:
        buf[at:at + len(s)] = s
        at += len(s) + 64
    return bytes(buf)


def _image(tmp_path: Path, *strings: bytes, banner: str | None = B1, name: str = "mem.lime") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    kernel = _page(*([banner.encode() + b"\n\x00"] if banner else []), *strings)
    p = tmp_path / name
    p.write_bytes(_lime(bytes(4096), kernel))
    return p


@pytest.fixture
def work(tmp_path, monkeypatch):
    """A fresh event workdir: the symbol folder and the saved tables live under it."""
    w = tmp_path / "work"
    w.mkdir()
    monkeypatch.setenv("CTF_WORKDIR", str(w))
    return w


# ============================================================================== banners and tables

def test_carve_linux_banners_reads_the_whole_banner_and_counts_it():
    data = _page(B1.encode() + b"\n\x00", b"dmesg: " + B1.encode() + b"\x00", B2.encode() + b"\n",
                 b"Linux version 6.5\x00", b"see Linux version history for details\x00")
    assert memory.carve_linux_banners(data) == Counter({B1: 2, B2: 1})
    assert memory.carve_banners(data)["6.5.0-test-amd64"] == 2          # the short form is still what it was
    assert memory.banner_key(B1.encode() + b"\n\x00") == B1 == memory.banner_key(f"  {B1}\x00\n")


@pytest.mark.parametrize("suffix, pack", [(".json", lambda b: b), (".json.xz", lzma.compress),
                                          (".json.gz", lambda b: gzip.compress(b, mtime=0)), (".json.bz2", bz2.compress)],
                         ids=["plain", "xz", "gz", "bz2"])
def test_isf_banner_reads_the_banner_a_table_was_made_for(tmp_path, suffix, pack):
    p = tmp_path / f"table{suffix}"
    p.write_bytes(pack(_isf_doc(B1)))
    assert memory.isf_banner(p) == B1


def test_isf_banner_is_none_for_what_is_not_a_linux_table(tmp_path):
    cases = {
        "mac.json": json.dumps({"symbols": {"version": {"constant_data": base64.b64encode(b"Darwin Kernel Version 22.1.0").decode()}}}).encode(),
        "notes.json": b'{"about": "the \\"linux_banner\\" symbol is described here, there is none"}',
        "nokernel.json": _isf_doc("hello world, not a kernel banner at all"),
        "short.json": _isf_doc("Linux version "),
        "badb64.json": _isf_doc(B1).replace(b'"constant_data": "', b'"constant_data": "!!'),
        "cut.json.xz": lzma.compress(_isf_doc(B1))[:60],
        "liar.json.xz": _isf_doc(B1),                     # named xz, is plain JSON
        "empty.json": b"",
    }
    for name, body in cases.items():
        (tmp_path / name).write_bytes(body)
        assert memory.isf_banner(tmp_path / name) is None, name
    assert memory.isf_banner(tmp_path / "absent.json") is None


def test_isf_banner_skips_a_decoy_and_reads_the_symbol(tmp_path):
    """A `linux_banner` key that stands before the symbol and is not it (a metadata string of that name,
    an object of that name whose constant data is no kernel banner) is passed over, and the symbol
    after it is read."""
    decoys = [{"linux_banner": "see the symbols table"},
              {"linux_banner": {"constant_data": base64.b64encode(b"not a kernel banner").decode()}},
              {"linux_banner": {"address": 1}},
              {"linux_banner": {"constant_data": "*** not base64 ***"}}]
    for n, decoy in enumerate(decoys):
        doc = _isf_doc(B1, meta=decoy)
        assert doc.count(b'"linux_banner"') == 2 and doc.find(b'"linux_banner"') < doc.find(b'"symbols"'), decoy
        p = tmp_path / f"t{n}.json"
        p.write_bytes(doc)
        assert memory.isf_banner(p) == B1, decoy


@pytest.mark.parametrize("back", [5, 40], ids=["key-split-by-the-block", "object-split-by-the-block"])
def test_isf_banner_finds_the_symbol_across_a_read_block_boundary(tmp_path, back):
    """A table is read in 1 MiB blocks: the key may be cut by a block's end (5 bytes of it in the first
    block), or stand whole at the end of one with its object in the next."""
    probe = _isf_doc(B1, before="")
    at = probe.find(b'"linux_banner"')
    doc = _isf_doc(B1, before="x" * ((1 << 20) - back - at))
    assert doc.find(b'"linux_banner"') == (1 << 20) - back
    p = tmp_path / "big.json"
    p.write_bytes(doc)
    assert memory.isf_banner(p) == B1
    assert memory.isf_banner(p, read_max=1 << 19) is None        # the banner lies beyond what may be read


@pytest.mark.needs_tool("py:volatility3")
def test_the_synthetic_table_is_read_by_volatilitys_own_identifier():
    """The fixture is evidence only if it has the shape Volatility reads: its LinuxIdentifier takes the
    same banner out of both the test's table and the opener fixture's."""
    from volatility3.framework.automagic import symbol_cache
    for doc in (_isf_doc(B1), MF.isf(B1)):
        raw = symbol_cache.LinuxIdentifier.get_identifier(json.loads(doc))
        assert raw is not None and memory.banner_key(raw) == B1


def test_linux_isfs_walks_a_bounded_tree_and_names_what_it_left_out(tmp_path):
    d = tmp_path / "delivery"
    for rel, body in {"a.json.xz": lzma.compress(_isf_doc(B1)), "sub/b.json": _isf_doc(B2),
                      "d1/d2/d3/ok.json": _isf_doc(B1_OTHER_BUILD), "d1/d2/d3/d4/too-deep.json": _isf_doc(B2),
                      ".ctf/token.json": _isf_doc(B2), ".hidden.json": _isf_doc(B2),
                      "notes.json": b'{"k": 1}', "readme.txt": B1.encode(), "table.xz": lzma.compress(_isf_doc(B2))}.items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_bytes(body)
    (d / "link.json").symlink_to(d / "sub" / "b.json")
    (d / "linkdir").symlink_to(d / "sub", target_is_directory=True)
    tables, notes = memory.linux_isfs([d, tmp_path / "nowhere"])
    assert [(p.relative_to(d).as_posix(), b) for p, b in tables] == [
        ("a.json.xz", B1), ("d1/d2/d3/ok.json", B1_OTHER_BUILD), ("sub/b.json", B2)]
    assert any("nowhere: no such folder" in n for n in notes)
    assert any("1 candidate file(s) hold no Linux banner (notes.json)" in n for n in notes)
    twice, _ = memory.linux_isfs([d, d])                                  # one file is one table, however it is reached
    assert len(twice) == 3
    three = tmp_path / "three"
    three.mkdir()
    for name in ("a.json", "b.json", "c.json"):
        (three / name).write_bytes(_isf_doc(B1))
    two, cut = memory.linux_isfs([three], files_max=2)                    # exactly files_max are opened, and the cut is said
    assert [p.name for p, _ in two] == ["a.json", "b.json"] and cut == [f"{three}: more than 2 candidate tables: the rest was not opened"]
    assert [len(t) for t in memory.linux_isfs([three], files_max=3)] == [3, 0]


def test_match_linux_isf_is_by_exact_banner_never_by_release_or_name(tmp_path):
    d = tmp_path / "t"
    d.mkdir()
    (d / "aaa-first.json").write_bytes(_isf_doc(B1_OTHER_BUILD))
    assert memory.match_linux_isf(Counter({B1: 3}), [d])[:2] == (None, None)
    _, _, note = memory.match_linux_isf(Counter({B1: 3}), [d])
    assert "no local ISF for" in note and "aaa-first.json is for the same release but another build" in note
    assert "Nothing is fetched" in note and str(d) in note
    (d / "zzz-right.json.xz").write_bytes(lzma.compress(_isf_doc(B1)))
    path, made_for, note = memory.match_linux_isf(Counter({B1: 3}), [d])
    assert (path, made_for) == (d / "zzz-right.json.xz", B1) and "was made for this kernel" in note
    # a carved run that goes on after the banner (no line end in that copy) still names the table
    assert memory.match_linux_isf([B1 + " trailing text"], [d])[0] == d / "zzz-right.json.xz"
    # ... but a table whose banner is LONGER than what was carved does not (it is another banner)
    assert memory.match_linux_isf([B1[:-12]], [d])[0] is None
    # the most frequent carved banner is tried first
    (d / "mmm-other.json").write_bytes(_isf_doc(B2))
    assert memory.match_linux_isf(Counter({B2: 5, B1: 1}), [d])[0] == d / "mmm-other.json"
    assert memory.match_linux_isf(Counter({B2: 1, B1: 5}), [d])[0] == d / "zzz-right.json.xz"
    assert memory.match_linux_isf(Counter(), [d]) == (
        None, None, "no Linux banner was carved from the image: there is no kernel to match a symbol table to")


def test_linux_symbol_pack_is_the_zip_the_sandbox_takes_and_is_reused(tmp_path, work):
    table = tmp_path / "symbols.json.xz"
    table.write_bytes(lzma.compress(_isf_doc(B1)))
    pack = memory.linux_symbol_pack(table, B1 + "\n\x00")
    assert pack.name == "linux.zip" and pack.parent.parent == memory.symbols_folder() == work / "_memory" / "_symbols"
    with zipfile.ZipFile(pack) as z:
        assert z.namelist() == ["linux/symbols.json.xz"]              # where Volatility looks: <symbols>/linux.zip!linux/*.json.xz
        assert z.read("linux/symbols.json.xz") == table.read_bytes()
        assert z.getinfo("linux/symbols.json.xz").compress_type == zipfile.ZIP_STORED
    assert [p.name for p in pack.parent.iterdir()] == ["linux.zip"]   # no temporary file is left
    stamp, info = pack.stat().st_mtime_ns, {}
    assert pack.parent.name == ("linux-" + hashlib.sha256(B1.encode()).hexdigest()[:16]
                                + "-" + hashlib.sha256(table.read_bytes()).hexdigest()[:16])
    assert memory.linux_symbol_pack(table, B1, info) == pack and pack.stat().st_mtime_ns == stamp and info == {"reused": True}
    assert memory.linux_symbol_pack(table, B2, info).parent != pack.parent and info == {"reused": False}   # another banner
    # Another table that carries the same banner (a repaired one after a damaged one, the right one after
    # a decoy) gets a pack of its own: the first is never served in its place.
    table.write_bytes(lzma.compress(_isf_doc(B1, before="the repaired table")))
    second = memory.linux_symbol_pack(table, B1, info)
    assert second != pack and info == {"reused": False} and zipfile.ZipFile(second).read("linux/symbols.json.xz") == table.read_bytes()
    assert zipfile.ZipFile(pack).read("linux/symbols.json.xz") == lzma.compress(_isf_doc(B1))     # the first is untouched


def test_linux_symbols_for_matches_the_image_to_the_table_beside_it(tmp_path, work):
    img = _image(tmp_path / "files")
    assert memory.linux_symbols_for(img)[0] is None                    # no table anywhere yet
    (tmp_path / "files" / "symbols.json.xz").write_bytes(lzma.compress(_isf_doc(B1)))
    pack, note = memory.linux_symbols_for(img)
    assert pack is not None and zipfile.ZipFile(pack).namelist() == ["linux/symbols.json.xz"] and "symbols.json.xz" in note
    # the event's symbol folder is looked at too: a table saved there serves an image delivered alone
    alone = _image(tmp_path / "other", banner=B2)
    assert memory.linux_symbols_for(alone)[0] is None
    (memory.symbols_folder() / "linux").mkdir(parents=True)
    (memory.symbols_folder() / "linux" / "k.json").write_bytes(_isf_doc(B2))
    assert zipfile.ZipFile(memory.linux_symbols_for(alone)[0]).namelist() == ["linux/k.json"]
    empty = tmp_path / "empty.lime"
    empty.write_bytes(b"")
    assert memory.linux_symbols_for(empty) == (None, "empty.lime is empty: no banner to match a symbol table to")


# ============================================================================== memory_depth.select_profile

META = {"banner": B1, "image_format": "lime"}


def test_select_profile_states_a_matched_table():
    got = memory_depth.select_profile("linux", META, isf_index={B1_OTHER_BUILD: "/t/other.json", B1 + "\n\x00": "/t/right.json.xz"})
    assert got.symbol_strategy == memory_depth.ISF_MATCHED and got.symbol_hint == "/t/right.json.xz"
    assert got.evidence[-1] == "isf=matched" and got.version == "Linux 6.5.0-test-amd64" and got.architecture == "x64"
    # the banner supplied may run on after the table's; the longest table banner it starts with wins
    longer = memory_depth.select_profile("linux", {**META, "banner": B1 + " extra"},
                                         isf_index={B1[:60]: "/t/short.json", B1: "/t/right.json.xz"})
    assert longer.symbol_hint == "/t/right.json.xz"


def test_select_profile_never_picks_a_table_by_release_alone():
    got = memory_depth.select_profile("linux", META, isf_index={B1_OTHER_BUILD: "/t/other.json"})
    assert got.symbol_strategy == memory_depth.ISF_UNMATCHED
    assert got.symbol_hint == "linux-6.5.0-test-amd64-x64.json.xz" and got.evidence[-1] == "isf=unmatched (1 local)"
    assert memory_depth.select_profile("linux", META, isf_index={}).evidence[-1] == "isf=unmatched (0 local)"


def test_select_profile_without_an_index_is_what_it_was_and_a_named_isf_is_kept():
    plain = memory_depth.select_profile("linux", META)
    assert plain.symbol_strategy == "exact-banner ISF generated offline from matching vmlinux/System.map"
    assert plain.evidence == (f"banner={B1}", "arch=x64") and plain.symbol_hint == "linux-6.5.0-test-amd64-x64.json.xz"
    named = memory_depth.select_profile("linux", {**META, "isf": "mine/table.json.xz"}, isf_index={B1: "/t/right.json.xz"})
    assert named.symbol_hint == "mine/table.json.xz" and named.symbol_strategy == plain.symbol_strategy
    assert named.evidence == plain.evidence


@pytest.mark.parametrize("index", [["not", "a", "mapping"], {7: "/t/x.json"}, {"Windows 10": "/t/x.json"},
                                   {B1: None}, {B1: b"/t/x.json"}, {B1: ""},
                                   {f"Linux version 6.{i}.0-x (b) #1": "/t/x.json" for i in range(memory_depth.MAX_ISF_INDEX + 1)},
                                   {B1: "/t/a.json", B1 + "\x00": "/t/b.json"}],
                         ids=["list", "int-key", "not-a-banner", "none-path", "bytes-path", "empty-path", "too-many", "two-paths-one-banner"])
def test_select_profile_rejects_a_malformed_index(index):
    assert memory_depth.select_profile("linux", META, isf_index=index) is None


# ============================================================================== vol() and the sandbox runner

class FakeSandbox:
    """What memory.vol imports as `sandbox`: records each run() call and answers as told."""

    class SandboxDown(RuntimeError):
        pass

    class Result:
        def __init__(self, code, stdout, stderr=b""):
            self.code, self.stdout, self.stderr = code, stdout, stderr

    def __init__(self, answer):
        self.answer, self.calls = answer, []

    def run(self, tool, args, **kw):
        self.calls.append((tool, list(args), kw))
        got = self.answer(args)
        if isinstance(got, Exception):
            raise got
        return got


def test_vol_never_starts_a_container_when_told_and_tells_never_ran_from_failed(tmp_path, monkeypatch):
    img = tmp_path / "mem.lime"
    img.write_bytes(b"EMiL" + bytes(60))
    pack = tmp_path / "linux.zip"
    pack.write_bytes(b"PK\x05\x06" + bytes(18))
    box = FakeSandbox(lambda args: FakeSandbox.Result(0, b'[{"PID": 1, "COMM": "systemd"}]'))
    monkeypatch.setitem(sys.modules, "sandbox", box)
    rows, note = memory.vol(img, "linux.psaux", symbols=pack, start=False, timeout=77)
    assert rows == [{"PID": 1, "COMM": "systemd"}] and note == "linux.psaux: 1 rows"
    tool, args, kw = box.calls[-1]
    assert tool == "vol" and args == ["-q", "-r", "json", "--offline", "-s", "{in1}/..", "-f", "{in0}", "linux.psaux"]
    assert kw["start"] is False and kw["timeout"] == 77
    assert kw["inputs"][0] == img and kw["inputs"][1] == ("linux.zip", pack.read_bytes())
    memory.vol(img, "banners.Banners", start=False)
    assert box.calls[-1][2]["start"] is False and box.calls[-1][1][-3:] == ["-f", "{in}", "banners.Banners"]
    memory.vol(img, "linux.psaux", symbols=pack)                       # the default leaves the runner's own default alone
    memory.vol(img, "banners.Banners")
    assert all("start" not in kw for _t, _a, kw in box.calls[-2:])

    box.answer = lambda args: FakeSandbox.SandboxDown("not started; run tools/sandbox.py start first (no container)")
    rows, note = memory.vol(img, "linux.psaux", symbols=pack, start=False)
    assert rows is None and note.startswith("sandbox down: not started;") and memory.not_run(note)
    box.answer = lambda args: FakeSandbox.Result(1, b"", b"Unsatisfied requirement plugins.PsAux.kernel.symbol_table_name\n")
    rows, note = memory.vol(img, "linux.psaux", symbols=pack)
    assert rows is None and "failed (Unsatisfied requirement" in note and not memory.not_run(note)
    assert memory.not_run("linux.psaux could not be run (FileNotFoundError: vol)")
    assert memory.not_run("where must be sandbox or venv, not 'host'")
    assert not memory.not_run("linux.psaux took more than 600 s") and not memory.not_run("linux.psaux: 4 rows")


FAKE_DOCKER = r'''#!{python}
import json, os, sys, zipfile
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
if args[0] == "image":
    print("sha256:" + "1" * 64)
    sys.exit(0)
if args[0] == "exec" and "vol" in args:
    v = args[args.index("vol") + 1:]
    host = lambda p: p.replace("/drop/", os.environ["FAKE_DROP"] + "/", 1)
    ok = os.path.isfile(host(v[v.index("-f") + 1])) and "-s" in v
    if ok:
        pack = os.path.join(os.path.normpath(host(v[v.index("-s") + 1])), "linux.zip")
        ok = os.path.isfile(pack) and zipfile.ZipFile(pack).namelist() == ["linux/symbols.json.xz"]
    if not ok:
        sys.stderr.write("Unsatisfied requirement plugins.PsAux.kernel.symbol_table_name\n")
        sys.exit(1)
    print(json.dumps([{{"PID": 1, "PPID": 0, "COMM": "systemd", "ARGS": "/sbin/init", "__children": []}}]))
    sys.exit(0)
if args[0] == "exec":
    sys.exit(0)
sys.stderr.write("Error response from daemon: No such container: x\n")
sys.exit(1)
'''


@pytest.fixture
def stand_in_docker(tmp_path, monkeypatch):
    """tools/sandbox.py itself, driven by a stand-in docker program: no daemon, no container, no image.
    The stand-in answers a `vol` exec only when the image and a linux.zip pack holding the table are
    in the call's drop folder, where the `-f` and `-s` arguments point."""
    box = tmp_path / "box"
    (box / "v2" / "drop").mkdir(parents=True)
    (box / "v2" / "out").mkdir(parents=True)
    fake = tmp_path / "bin" / "docker"
    fake.parent.mkdir()
    fake.write_text(FAKE_DOCKER.format(python=sys.executable))
    fake.chmod(0o755)
    log = tmp_path / "docker-calls.jsonl"
    monkeypatch.setenv("CTF_DOCKER", str(fake))
    monkeypatch.setenv("CTF_SANDBOX_DIR", str(box))
    monkeypatch.setenv("CTF_SANDBOX_NAME", f"b136-test-{os.getpid()}")
    monkeypatch.delenv("CTF_SANDBOX_IMAGE", raising=False)
    monkeypatch.setenv("FAKE_LOG", str(log))
    monkeypatch.setenv("FAKE_DROP", str(box / "v2" / "drop"))
    monkeypatch.delitem(sys.modules, "sandbox", raising=False)      # a fresh tools/sandbox.py, with this environment
    import sandbox
    # Wall clock: every call of the stand-in is an interpreter start, and tools/sandbox.py gives a
    # status probe 5 s. On a machine at a load of 100+ a start can take longer, which would read as
    # "the daemon does not answer". The probe limit is not what this test is about, so it is lifted.
    monkeypatch.setattr(sandbox, "PROBE_TIMEOUT", 600.0)
    yield lambda: [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
    sys.modules.pop("sandbox", None)


def test_vol_hands_the_linux_pack_to_the_real_sandbox_runner(tmp_path, work, stand_in_docker, monkeypatch):
    img = _image(tmp_path / "files")
    (tmp_path / "files" / "symbols.json.xz").write_bytes(lzma.compress(_isf_doc(B1)))
    pack, _note = memory.linux_symbols_for(img)
    rows, note = memory.vol(img, "linux.psaux", symbols=pack, start=False)
    assert rows == [{"PID": 1, "PPID": 0, "COMM": "systemd", "ARGS": "/sbin/init", "__children": []}], note
    execs = [c for c in stand_in_docker() if c[0] == "exec" and "vol" in c]
    v = execs[-1][execs[-1].index("vol") + 1:]
    assert v[:4] == ["-q", "-r", "json", "--offline"] and v[-1] == "linux.psaux"
    assert v[v.index("-s") + 1].endswith("/linux.zip/..") and v[v.index("-f") + 1].endswith("/mem.lime")
    assert not any(c[0] in ("run", "start", "rm", "pull", "build") for c in stand_in_docker())   # nothing is started
    rows, note = memory.vol(img, "linux.psaux", start=False)             # no pack: the plugin runs and fails
    assert rows is None and "Unsatisfied requirement" in note and not memory.not_run(note)
    monkeypatch.setenv("CTF_DOCKER", str(tmp_path / "bin" / "no-docker-here"))
    rows, note = memory.vol(img, "linux.psaux", symbols=pack, start=False)
    assert rows is None and note.startswith("sandbox down: docker is not installed") and memory.not_run(note)


# ============================================================================== vol_save

def _record_vol(monkeypatch, answer):
    calls = []

    def vol(image, plugin, **kw):
        calls.append((plugin, kw))
        return answer(plugin, kw)
    monkeypatch.setattr(memory, "vol", vol)
    return calls


ROWS = [{"PID": 1, "PPID": 0, "COMM": "systemd", "ARGS": "/sbin/init", "__children": []}]


def test_vol_save_auto_matches_the_table_and_runs_every_plugin_with_the_pack(tmp_path, work, monkeypatch):
    img = _image(tmp_path / "files")
    (tmp_path / "files" / "symbols.json.xz").write_bytes(lzma.compress(_isf_doc(B1)))
    calls = _record_vol(monkeypatch, lambda plugin, kw: (ROWS, f"{plugin}: 1 rows"))
    said, results = [], {}
    folder = memory.vol_save(img, "linux", symbols="auto", plugins=["banners.Banners", "linux.psaux"], say=said.append,
                             results=results)
    assert folder == work / "_memory" / memory.fingerprint(img.read_bytes())
    packs = {kw["symbols"] for _p, kw in calls}
    assert [p for p, _kw in calls] == ["banners.Banners", "linux.psaux"] and len(packs) == 1
    assert zipfile.ZipFile(packs.pop()).namelist() == ["linux/symbols.json.xz"]
    assert all(kw["where"] == "sandbox" and kw["timeout"] == 600.0 and "start" not in kw for _p, kw in calls)
    assert said[0].startswith("OK   symbols: symbols.json.xz was made for this kernel")
    assert json.loads((folder / "linux.psaux.json").read_text()) == ROWS
    assert results == {"banners.Banners": (ROWS, "banners.Banners: 1 rows"), "linux.psaux": (ROWS, "linux.psaux: 1 rows")}


def test_vol_save_auto_with_no_table_runs_only_what_needs_none_and_says_the_rest(tmp_path, work, monkeypatch):
    img = _image(tmp_path / "files")
    (tmp_path / "files" / "symbols.json.xz").write_bytes(lzma.compress(_isf_doc(B1_OTHER_BUILD)))
    calls = _record_vol(monkeypatch, lambda plugin, kw: (ROWS, f"{plugin}: 1 rows"))
    said, results = [], {}
    folder = memory.vol_save(img, "linux", symbols="auto", plugins=["linux.psaux", "banners.Banners", "linux.bash"],
                             say=said.append, results=results)
    assert [p for p, _kw in calls] == ["banners.Banners"] and calls[0][1]["symbols"] is None
    assert said[0].startswith("FAIL symbols: no local ISF for")
    assert "SKIP linux.psaux not run (no symbol table (ISF) for this kernel)" in said
    assert results["linux.bash"] == (None, "linux.bash not run (no symbol table (ISF) for this kernel)")
    assert sorted(p.name for p in folder.iterdir()) == ["banners.Banners.json"]      # a skipped plugin leaves no table
    with pytest.raises(ValueError, match="symbols='auto' matches a Linux ISF"):
        memory.vol_save(img, "windows", symbols="auto", say=said.append)
    assert [p for p, _kw in calls] == ["banners.Banners"]


def test_vol_save_stops_asking_once_volatility_never_ran(tmp_path, work, monkeypatch):
    img = _image(tmp_path / "files")
    down = "sandbox down: docker is not installed: the image is not read"
    calls = _record_vol(monkeypatch, lambda plugin, kw: (None, down))
    said, results = [], {}
    folder = memory.vol_save(img, "linux", plugins=["linux.psaux", "linux.bash", "linux.pslist"], say=said.append,
                             results=results, start=False)
    assert [p for p, _kw in calls] == ["linux.psaux"] and calls[0][1]["start"] is False      # the image is not copied in twice more
    assert said == [f"FAIL {down}", f"SKIP linux.bash not run ({down})", f"SKIP linux.pslist not run ({down})"]
    assert results["linux.pslist"] == (None, f"linux.pslist not run ({down})") and list(folder.iterdir()) == []
    # a plugin that ran and failed stops nothing: the next one is still asked
    calls2 = _record_vol(monkeypatch, lambda plugin, kw: (None, f"{plugin} failed (boom)") if plugin == "linux.psaux" else (ROWS, "ok"))
    memory.vol_save(img, "linux", plugins=["linux.psaux", "linux.bash"], say=said.append)
    assert [p for p, _kw in calls2] == ["linux.psaux", "linux.bash"] and sorted(p.name for p in folder.iterdir()) == ["linux.bash.json"]


def test_vol_save_keeps_a_budget_on_an_injected_clock(tmp_path, work, monkeypatch):
    """Time here is the step clock the stub moves (100 s per plugin), never the wall clock."""
    img = _image(tmp_path / "files")
    clock = Clock(0.0)

    def answer(plugin, kw):
        clock.t += 100.0
        return ROWS, f"{plugin}: 1 rows"
    calls = _record_vol(monkeypatch, answer)
    results = {}
    memory.vol_save(img, "linux", plugins=["a", "b", "c", "d"], say=lambda s: None, timeout=120.0, deadline=250.0,
                    clock=clock, results=results)
    assert [(p, kw["timeout"]) for p, kw in calls] == [("a", 120.0), ("b", 120.0), ("c", 50.0)]
    assert results["d"] == (None, "d not run (no time left: 0 s of the run's budget)")
    clock.t, calls[:] = 0.0, []
    memory.vol_save(img, "linux", plugins=["a", "b"], say=lambda s: None, deadline=100.0 + memory.VOL_MIN_SLICE, clock=clock)
    assert [(p, kw["timeout"]) for p, kw in calls] == [("a", 105.0), ("b", memory.VOL_MIN_SLICE)]      # exactly the least slice: run
    clock.t, calls[:] = 0.0, []
    memory.vol_save(img, "linux", plugins=["a", "b"], say=lambda s: None, deadline=104.9, clock=clock)
    assert [p for p, _kw in calls] == ["a"]                                                          # under it: not started


# ============================================================================== the model

PSAUX = [{"PID": 1, "PPID": 0, "COMM": "systemd", "ARGS": "/sbin/init splash", "__children": []},
         {"PID": 670, "PPID": 640, "COMM": "Xorg", "ARGS": "/usr/lib/xorg/Xorg :0 -seat seat0 -auth /var/run/lightdm/root/:0 vt7", "__children": []},
         {"PID": 2311, "PPID": 2304, "COMM": "bash", "ARGS": "-bash", "__children": []},
         {"PID": 28889, "PPID": 2311, "COMM": "insmod", "ARGS": "insmod ./lime-6.5.0.ko path=/tmp/out.lime format=lime", "__children": []},
         {"PID": 28906, "PPID": 2311, "COMM": "python3", "ARGS": "python3 watcher_job.py", "__children": []}]
BASH = [{"PID": 2311, "Process": "bash", "CommandTime": "2026-03-03T10:00:00+00:00", "Command": "cd ~/work", "__children": []},
        {"PID": 2311, "Process": "bash", "CommandTime": "2026-03-03T10:00:05+00:00", "Command": "python3 watcher_job.py", "__children": []}]
PSLIST = [{"OFFSET (V)": 149533581377536 + i, "PID": r["PID"], "TID": r["PID"], "PPID": r["PPID"], "COMM": r["COMM"],
           "UID": 0, "GID": 0, "EUID": 0, "EGID": 0, "CREATION TIME": "2026-03-03T09:00:00+00:00", "File output": "Disabled",
           "__children": []} for i, r in enumerate(PSAUX)]


def test_bash_history_is_history_and_never_the_shells_command_line():
    model = memory.Model()
    kinds = [model.absorb(t, "table") for rows in (PSAUX, BASH) for t in memory.tables_from_json(rows)[0]]
    assert kinds == ["proc", "history"]
    assert model.procs[2311]["args"] == "-bash" and (2311, "args") not in model.clash
    assert model.history == [
        {"pid": 2311, "name": "bash", "time": "2026-03-03T10:00:00+00:00", "command": "cd ~/work", "src": "table"},
        {"pid": 2311, "name": "bash", "time": "2026-03-03T10:00:05+00:00", "command": "python3 watcher_job.py", "src": "table"}]
    # a process table that happens to carry a command time is still a process table (it names the parent)
    other = memory.Model()
    assert other.absorb([{"pid": 5, "ppid": 1, "command": "/bin/x", "commandtime": "2026-03-03T10:00:00"}], "table") == "proc"
    assert other.history == [] and other.procs[5]["args"] == "/bin/x"
    # the text form Volatility prints is read the same way
    text = "PID\tProcess\tCommandTime\tCommand\n2311\tbash\t2026-03-03 10:00:00.000000 UTC\tcd ~/work\n"
    third = memory.Model()
    assert memory.read_tables(third, "bash.txt", text.encode()) == ["history"] and third.history[0]["command"] == "cd ~/work"


def test_saved_linux_tables_replay_through_build_model(tmp_path, work, monkeypatch):
    img = _image(tmp_path / "files")
    answers = {"linux.psaux": PSAUX, "linux.bash": BASH}
    _record_vol(monkeypatch, lambda plugin, kw: (answers[plugin], f"{plugin}: {len(answers[plugin])} rows"))
    memory.vol_save(img, "linux", plugins=["linux.psaux", "linux.bash"], say=lambda s: None)
    model = memory.build_model({"mem.lime": img.read_bytes()})
    assert model.procs[28906]["args"] == "python3 watcher_job.py" and model.procs[28906]["ppid"] == 2311
    assert model.procs[2311]["args"] == "-bash" and not model.clash
    assert [h["command"] for h in model.history] == ["cd ~/work", "python3 watcher_job.py"]
    assert model.kernel_banners == Counter({B1: 1})                     # the whole banner, beside the short release
    assert model.banners == Counter({"6.5.0-test-amd64": 1})
    report = memory.report([img])
    assert "history pid=2311 bash 2026-03-03T10:00:05+00:00 'python3 watcher_job.py' src=table" in report
    assert f"banner(carved, whole: what names the kernel's ISF) {B1} x1" in report


# ============================================================================== vol_triage: the no-tool stage

FLAG = "CSCTF{whole_flag_1}"            # the suite's default event is csctf


def test_scan_flags_tells_a_flag_from_a_lead_with_no_flag_after_it():
    data = _page(FLAG.encode() + b"\x00", b"CSCTF{f1rst_h4lf_\x00", b'secret = "CSCTF{quoted_part"\n', b"CSCTF{abc\x00",
                 b"CSCTF{abcd\x00", FLAG.encode() + b"\n", b"csctf{lower_prefix_too}")
    got = vol_triage.scan_flags(data)
    assert (got["status"], got["reason"], got["scanned"]) == ("ran", "", len(data))
    assert [(h["value"], h["count"], h["offset"]) for h in got["flags"]] == [
        (FLAG, 2, data.find(FLAG.encode())), ("csctf{lower_prefix_too}", 1, data.find(b"csctf{lower"))]
    assert [(h["value"], h["count"], h["offset"]) for h in got["fragments"]] == [
        ("CSCTF{f1rst_h4lf_", 1, data.find(b"CSCTF{f1rst")), ("CSCTF{quoted_part", 1, data.find(b"CSCTF{quoted")),
        ("CSCTF{abcd", 1, data.find(b"CSCTF{abcd"))]                    # 4 body bytes is a fragment, 3 (abc) is not
    assert got["fragments"][0]["prefix"] == "CSCTF" and got["fragments"][0]["body"] == "f1rst_h4lf_"
    assert vol_triage.spell(got["fragments"][0]) == '"CSCTF" + "{" + "f1rst_h4lf_"'


def test_scan_flags_does_not_take_a_span_of_binary_bytes_for_a_flag():
    """csctf's body is anything but a closing brace: from a lead, across NULs and pointers, to the next
    brace in reach. That span is noise. The lead is a fragment at most, and a real flag that stands
    inside the span is still found."""
    noise = b"CSCTF{looks_fine\x00\x00\x10\xff\x00" + FLAG.encode() + b"\x00\x01}"
    got = vol_triage.scan_flags(bytes(32) + noise + bytes(32))
    assert [(h["value"], h["offset"]) for h in got["flags"]] == [(FLAG, 32 + noise.find(FLAG.encode()))]
    assert [h["value"] for h in got["fragments"]] == ["CSCTF{looks_fine"]
    assert flagfmt.find_flags(noise)[0].startswith("CSCTF{looks_fine\x00")       # what the bare format would have said
    nested = b"CSCTF{outer_CTF{inner}"                                         # one printable flag, one hit
    assert [h["value"] for h in vol_triage.scan_flags(nested)["flags"]] == ["CSCTF{outer_CTF{inner}"]


def test_scan_flags_counts_each_hit_once_whatever_the_chunks():
    """A flag across a chunk's end, a lead that starts in a chunk's last bytes and a flag wholly in the
    next chunk are each one hit: the overlap window must not count the next chunk's twice."""
    data = bytearray(256)
    data[60:60 + len(FLAG)] = FLAG.encode()                 # across the first chunk's end (64)
    data[126:126 + 16] = b"CSCTF{split_lead"                # the lead itself across the second chunk's end (128)
    data[200:200 + len(FLAG)] = FLAG.encode()               # wholly inside the fourth chunk
    whole = vol_triage.scan_flags(bytes(data))
    for chunk in (64, 7, 1):
        got = vol_triage.scan_flags(bytes(data), chunk=chunk)
        assert got["flags"] == whole["flags"] == [{"value": FLAG, "offset": 60, "count": 2, "prefix": "CSCTF", "body": ""}], chunk
        assert [(h["value"], h["offset"], h["count"]) for h in got["fragments"]] == [("CSCTF{split_lead", 126, 1)], chunk


def test_scan_flags_follows_the_events_case_rule(monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "spooky")
    data = _page(b"SpOoKy{mixed_case_prefix}\x00", b"spooky{f1rst_h4lf_\x00", FLAG.encode())
    got = vol_triage.scan_flags(data)
    assert [h["value"] for h in got["flags"]] == ["SpOoKy{mixed_case_prefix}"]          # another event's flag is not one
    assert [vol_triage.spell(h) for h in got["fragments"]] == ['"spooky" + "{" + "f1rst_h4lf_"']


def test_scan_flags_is_not_run_without_a_flag_format_and_says_why(monkeypatch):
    data = _page(FLAG.encode())
    monkeypatch.delenv("CTF_EVENT")
    got = vol_triage.scan_flags(data)
    assert got["status"] == "not run" and "CTF_EVENT" in got["reason"] and got["flags"] == got["fragments"] == []
    unknown = event.parse({"slug": "b136-unknown", "name": "unknown format",
                           "dates": {"start": event._dt.date(2026, 1, 1), "end": event._dt.date(2026, 1, 2)},
                           "platform": {"kind": "manual"}, "flag": {"prefixes": []},
                           "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"}}, src="test")
    monkeypatch.setattr(flagfmt, "current", lambda: flagfmt.for_profile(unknown))
    got = vol_triage.scan_flags(data)
    assert (got["status"], got["reason"], got["flags"]) == ("not run", "the event profile states no flag prefix yet", [])


def test_scan_flags_stops_at_its_deadline_and_says_where():
    """The clock is a counter read once per chunk: the budget is spent after the first chunk."""
    data = bytearray(192)
    data[4:4 + len(FLAG)] = FLAG.encode()
    data[150:150 + 19] = b"CSCTF{second_flag!}"
    ticks = iter(range(100))
    got = vol_triage.scan_flags(bytes(data), clock=lambda: next(ticks), deadline=0.5, chunk=64)
    assert got["status"] == "cut" and got["scanned"] == 64 and got["reason"] == "the scan budget ran out at offset 0x40 of 0xc0"
    assert [h["value"] for h in got["flags"]] == [FLAG]
    full = vol_triage.scan_flags(bytes(data), clock=lambda: 0.0, deadline=0.5, chunk=64)
    assert full["status"] == "ran" and [h["value"] for h in full["flags"]] == [FLAG, "CSCTF{second_flag!}"]


def _lines(result) -> list:
    return vol_triage.render(result)


def _triage(image, **kw) -> dict:
    """vol_triage.triage on a clock that stands still unless the test passes its own: the scan and
    Volatility budgets are then never spent by a slow machine, only by a test that moves the clock."""
    kw.setdefault("clock", Clock())
    return vol_triage.triage(image, **kw)


NO_CLOCK = ["--budget", "86400"]    # main() reads the wall clock: a day's budget cannot run out under any machine load


def test_triage_matches_the_delivered_table_and_makes_the_pack(tmp_path, work):
    img = _image(tmp_path / "files")
    (tmp_path / "files" / "aaa-other-build.json").write_bytes(_isf_doc(B1_OTHER_BUILD))
    (tmp_path / "files" / "symbols.json.xz").write_bytes(lzma.compress(_isf_doc(B1)))
    result = _triage(img)
    table = result["table"]
    assert table["path"] == tmp_path / "files" / "symbols.json.xz" and table["label"] == "delivery" and table["tables"] == 2
    assert table["profile"].symbol_strategy == memory_depth.ISF_MATCHED and table["profile"].symbol_hint == str(table["path"])
    assert zipfile.ZipFile(table["pack"]).namelist() == ["linux/symbols.json.xz"]
    lines = _lines(result)
    assert lines[0] == f"== mem.lime: {img.stat().st_size} bytes, format lime, 2 range(s)"
    for want in (f"kernel_banner = {B1} x1", "kernel_release = 6.5.0-test-amd64", "arch = x64",
                 "isf = matched symbols.json.xz [delivery]: symbols.json.xz was made for this kernel (its banner is the image's)",
                 f"symbol_strategy = {memory_depth.ISF_MATCHED}", f"symbol_pack = {table['pack']}",
                 "flag_scan = ran over 8256 bytes: 0 flag(s), 0 lead(s) with no complete flag",
                 "volatility = not run (--vol not given)",
                 f"next = python -m ctf run toolkits.vol_triage {img} --vol   (outside intake's network guard: it cuts the docker socket)"):
        assert want in lines, want
    assert not any(l.startswith("handoff =") for l in lines)             # nothing was asked for that did not happen
    res = vol_triage.solver_result(result)
    assert res.status == "none" and res.engine == "toolkits.vol_triage"
    assert res.notes == "mem.lime: kernel 6.5.0-test-amd64; ISF matched; flag scan ran; Volatility not run"


def test_triage_without_a_table_says_what_is_missing_and_offers_no_next_step(tmp_path, work):
    img = _image(tmp_path / "files")
    (tmp_path / "files" / "symbols.json.xz").write_bytes(lzma.compress(_isf_doc(B1_OTHER_BUILD)))
    result = _triage(img)
    lines = _lines(result)
    assert result["table"]["path"] is None and result["table"]["pack"] is None
    assert any(l.startswith("isf = none (no local ISF for 'Linux version 6.5.0-test-amd64") and
               "symbols.json.xz is for the same release but another build" in l for l in lines)
    assert f"symbol_strategy = {memory_depth.ISF_UNMATCHED}" in lines and "symbol_hint = linux-6.5.0-test-amd64-x64.json.xz" in lines
    assert not any(l.startswith(("next =", "symbol_pack =", "isf = matched")) for l in lines)
    blank = _triage(_image(tmp_path / "blank", banner=None))
    lines = _lines(blank)
    assert lines[1].startswith("kernel_banner = none (") and not any(l.startswith(("kernel_release", "arch", "symbol_")) for l in lines)
    assert "isf = none (no Linux banner was carved from the image: there is no kernel to match a symbol table to)" in lines
    assert vol_triage.solver_result(blank).notes.startswith("mem.lime: no Linux banner; no local ISF;")


def test_triage_looks_in_the_symbols_folders_and_says_where_the_table_was(tmp_path, work):
    img = _image(tmp_path / "files")
    extra = tmp_path / "extra"
    extra.mkdir()
    (extra / "k.json").write_bytes(_isf_doc(B1))
    assert _triage(img)["table"]["path"] is None
    got = _triage(img, symbols=[str(extra)])["table"]
    assert (got["path"], got["label"]) == (extra / "k.json", "--symbols")
    assert vol_triage.symbol_folders(img, [str(img.parent), str(extra)])[0] == [
        (img.parent, "delivery"), (extra, "--symbols"), (memory.symbols_folder(), "symbol folder")]    # one folder, one look
    other = _image(tmp_path / "files2", banner=B2)
    (memory.symbols_folder() / "saved").mkdir(parents=True, exist_ok=True)
    (memory.symbols_folder() / "saved" / "arm.json").write_bytes(_isf_doc(B2))
    got = _triage(other)["table"]
    assert (got["path"].name, got["label"], got["profile"].architecture) == ("arm.json", "symbol folder", "arm64")


def test_triage_with_no_workdir_matches_but_says_the_pack_was_not_written(tmp_path, monkeypatch):
    img = _image(tmp_path / "files")
    (tmp_path / "files" / "symbols.json.xz").write_bytes(lzma.compress(_isf_doc(B1)))

    def no_workdir():
        raise event.EventError("no event workdir: CTF_WORKDIR is not set")
    monkeypatch.setattr(memory, "symbols_folder", no_workdir)
    result = _triage(img, run_vol=True)
    lines = _lines(result)
    assert result["table"]["path"] is not None and result["table"]["pack"] is None
    assert "isf_note = the event's symbol folder was not looked at (no workdir: no event workdir: CTF_WORKDIR is not set)" in lines
    assert "symbol_pack = not written (no workdir: no event workdir: CTF_WORKDIR is not set)" in lines
    assert "volatility = not run (no symbol table (ISF) for this kernel: see isf)" in lines and not any(l.startswith("next =") for l in lines)


def test_a_banner_that_names_no_architecture_takes_arch_from_the_caller(tmp_path, work):
    bare = "Linux version 6.8.0-45-generic (buildd@host) (gcc 13.2.0) #45-Test SMP Fri Aug 30 12:02:04 UTC 2026"
    img = _image(tmp_path / "files", banner=bare)
    (tmp_path / "files" / "t.json").write_bytes(_isf_doc(bare))
    lines = _lines(_triage(img))
    assert "isf = matched t.json [delivery]: t.json was made for this kernel (its banner is the image's)" in lines   # the match needs no arch
    assert any(l.startswith("symbol_strategy = not selected (") and "--arch" in l for l in lines)
    assert not any(l.startswith("arch =") for l in lines)
    lines = _lines(_triage(img, arch="arm64"))
    assert "arch = arm64" in lines and f"symbol_strategy = {memory_depth.ISF_MATCHED}" in lines


def test_solver_result_is_solved_candidate_or_unsure_by_what_was_carved(tmp_path, work):
    one = _triage(_image(tmp_path / "one", FLAG.encode() + b"\x00", FLAG.encode() + b"\n"))
    res = vol_triage.solver_result(one)
    at = (tmp_path / "one" / "mem.lime").read_bytes().find(FLAG.encode())
    assert (res.status, res.flags) == ("solved", (FLAG,))
    assert (res.evidence[0].kind, res.evidence[0].path, res.evidence[0].offset) == ("carve", "mem.lime", at)
    assert f"flag(carved) = {FLAG} x2 first at 0x{at:x}" in _lines(one)
    two = vol_triage.solver_result(_triage(_image(tmp_path / "two", FLAG.encode(), b"\x00CSCTF{another_one}")))
    assert (two.status, two.flags) == ("candidate", (FLAG, "CSCTF{another_one}")) and len(two.evidence) == 2
    part = _triage(_image(tmp_path / "part", b"CSCTF{f1rst_h4lf_\x00"))
    res = vol_triage.solver_result(part)
    assert (res.status, res.flags) == ("unsure", ()) and '"CSCTF" + "{" + "f1rst_h4lf_"' in res.notes
    assert "a fragment is never submitted" in res.notes and res.evidence[0].offset == (tmp_path / "part" / "mem.lime").read_bytes().find(b"CSCTF{f1rst")
    lines = _lines(part)
    assert any(l.startswith('flag_fragment(carved) = "CSCTF" + "{" + "f1rst_h4lf_" x1 first at 0x') for l in lines)
    assert any(l.startswith("handoff = a flag lead with no closing brace was carved") for l in lines)
    # beside a whole flag the fragment is still listed, but nothing says "the rest is somewhere else"
    both = _lines(_triage(_image(tmp_path / "both", FLAG.encode() + b"\x00", b"CSCTF{f1rst_h4lf_\x00")))
    assert any(l.startswith("flag_fragment(carved) =") for l in both) and not any(l.startswith("handoff =") for l in both)


@pytest.mark.parametrize("slug, lead", [("csctf", b"CSCTF{f1rst_h4lf_"), ("spooky", b"spooky{f1rst_h4lf_"), ("pink", b"PINK{f1rst_h4lf_")])
def test_a_fragment_is_never_printed_in_a_form_that_reads_back_as_a_flag(tmp_path, work, monkeypatch, capsys, slug, lead):
    """Intake scans an engine's stdout for the event's flag format when its result names no flag. The
    last line is a JSON object, so a lead printed as it stands would be closed by that object's brace
    and come back as a flag that is in no file."""
    monkeypatch.setenv("CTF_EVENT", slug)
    img = _image(tmp_path / "files", lead + b'"\n', lead + b"\x00")
    assert vol_triage.main([str(img), *NO_CLOCK]) == 0
    out = capsys.readouterr().out
    res = SolverResult.from_json(out.strip().splitlines()[-1])
    assert res.status == "unsure" and res.flags == () and "f1rst_h4lf_" in out
    assert flagfmt.find_flags(out) == [] and flagfmt.find_flags_packed(out) == []
    assert not flagfmt.LEAD_TEXT.search(out)                             # not even the lead stands in the output


# ============================================================================== vol_triage: the Volatility stage

def _vol_stub(monkeypatch, answers):
    calls = []

    def vol(image, plugin, **kw):
        calls.append((plugin, kw))
        got = answers[plugin] if isinstance(answers, dict) else answers(plugin)
        return got if isinstance(got, tuple) else (got, f"{plugin}: {len(got)} rows")
    monkeypatch.setattr(memory, "vol", vol)
    return calls


def _delivery(tmp_path, *strings):
    img = _image(tmp_path / "files", *strings)
    (tmp_path / "files" / "symbols.json.xz").write_bytes(lzma.compress(_isf_doc(B1)))
    return img


def test_the_volatility_stage_reads_processes_history_and_what_stands_out(tmp_path, work, monkeypatch):
    img = _delivery(tmp_path, b"python3 watcher_job.py\x00", b"File \"watcher_job.py\", line 33\x00")
    calls = _vol_stub(monkeypatch, {"linux.psaux": PSAUX, "linux.bash": BASH, "linux.pslist": PSLIST})
    result = _triage(img, run_vol=True)
    vol = result["vol"]
    assert [p for p, _kw in calls] == ["linux.psaux", "linux.bash", "linux.pslist"]
    assert all(kw["symbols"] == str(result["table"]["pack"]) and kw["where"] == "sandbox" and "start" not in kw for _p, kw in calls)
    assert vol["status"] == "ran" and vol["folder"] == work / "_memory" / memory.fingerprint(img.read_bytes())
    assert [(r["plugin"], r["rows"]) for r in vol["plugins"]] == [("linux.psaux", 5), ("linux.bash", 2), ("linux.pslist", 5)]
    assert [(m["pid"], m["kind"], m["script"]) for m in result["notable"]] == [
        (670, "display", ""), (28889, "writable-path", ""), (28889, "kernel-module", ""), (28906, "script", "watcher_job.py")]
    first = img.read_bytes().find(b"watcher_job.py")
    assert result["pivots"] == [{"name": "watcher_job.py", "count": 2, "offsets": [first, img.read_bytes().find(b"watcher_job.py", first + 1)]}]
    lines = _lines(result)
    for want in (f"volatility = ran; tables saved under {vol['folder']}", "vol linux.psaux = 5 rows", "vol linux.bash = 2 rows",
                 "proc pid=2311 ppid=2304 comm='bash' args='-bash'",                    # psaux's, not a history line
                 "proc pid=28906 ppid=2311 comm='python3' args='python3 watcher_job.py'",
                 "history pid=2311 time=2026-03-03T10:00:05+00:00 command='python3 watcher_job.py'",
                 "notable = pid 28906 'python3' [script] 'python3 watcher_job.py'",
                 "notable = pid 28889 'insmod' [kernel-module] './lime-6.5.0.ko'",
                 "notable = pid 28889 'insmod' [writable-path] '/tmp/out.lime'",
                 f"pivot(carved) = 'watcher_job.py' stands 2 time(s) in the image, first at 0x{first:x}, 0x{result['pivots'][0]['offsets'][1]:x}"):
        assert want in lines, want
    pixels = [l for l in lines if l.startswith("handoff = pixels: 'Xorg' (pid 670) holds the screen.")]
    assert len(pixels) == 1 and "linux.proc.Maps --pid 670 --dump" in pixels[0] and "a model or a human" in pixels[0]
    assert not any(l.startswith("next =") for l in lines)                 # --vol was given: there is no next step to offer
    res = vol_triage.solver_result(result)
    assert res.status == "none" and res.notes.endswith("Volatility ran (5 processes, 2 history rows)")
    # the same image, later and offline: the saved tables are the model's
    model = memory.build_model({"mem.lime": img.read_bytes()})
    assert model.procs[670]["name"] == "Xorg" and len(model.history) == 2


def test_the_volatility_stage_is_not_run_when_the_sandbox_is_down_and_says_so(tmp_path, work, monkeypatch):
    img = _delivery(tmp_path)
    down = "sandbox down: docker is not installed: the image is not read"
    calls = _vol_stub(monkeypatch, lambda plugin: (None, down))
    result = _triage(img, run_vol=True, start=False)
    assert [p for p, _kw in calls] == ["linux.psaux"] and calls[0][1]["start"] is False
    assert result["vol"]["status"] == "not run" and result["vol"]["reason"] == down and result["vol"]["procs"] == []
    lines = _lines(result)
    assert f"volatility = not run ({down})" in lines
    assert f"vol linux.bash = no table (linux.bash not run ({down}))" in lines
    assert any(l.startswith("handoff = the Volatility stage did not read the image (sandbox down:") for l in lines)
    assert not any(l.startswith(("proc ", "history ", "notable ")) for l in lines)


def test_the_volatility_stage_needs_a_table_and_is_not_started_without_one(tmp_path, work, monkeypatch):
    img = _image(tmp_path / "files")
    calls = _vol_stub(monkeypatch, lambda plugin: ROWS)
    result = _triage(img, run_vol=True)
    assert calls == [] and (result["vol"]["status"], result["vol"]["reason"]) == (
        "not run", "no symbol table (ISF) for this kernel: see isf")
    assert not (work / "_memory").exists()                               # nothing was hashed, saved or copied


def test_the_volatility_stage_is_partial_or_failed_by_what_came_back(tmp_path, work, monkeypatch):
    img = _delivery(tmp_path)
    _vol_stub(monkeypatch, {"linux.psaux": PSAUX, "linux.bash": (None, "linux.bash failed (no bash in this image)"),
                            "linux.pslist": PSLIST})
    part = _triage(img, run_vol=True)
    assert part["vol"]["status"] == "partial" and part["vol"]["reason"] == "linux.bash failed (no bash in this image)"
    assert len(part["vol"]["procs"]) == 5 and part["vol"]["history"] == []
    lines = _lines(part)
    assert any(l.startswith("volatility = partial (linux.bash failed (no bash in this image)); tables saved under ") for l in lines)
    assert "vol linux.bash = no table (linux.bash failed (no bash in this image))" in lines
    assert not any("did not read the image" in l for l in lines)
    _vol_stub(monkeypatch, lambda plugin: (None, f"{plugin} failed (Unsatisfied requirement)"))
    bad = _triage(img, run_vol=True, plugins=("linux.psaux", "linux.bash"))
    assert (bad["vol"]["status"], bad["vol"]["reason"]) == ("failed", "linux.psaux failed (Unsatisfied requirement)")
    lines = _lines(bad)
    assert any(l.startswith("volatility = failed (linux.psaux failed (Unsatisfied requirement))") for l in lines)
    assert any(l.startswith("handoff = the Volatility stage did not read the image (linux.psaux failed") for l in lines)


def test_the_volatility_stage_keeps_its_budget_on_the_injected_clock(tmp_path, work, monkeypatch):
    img = _delivery(tmp_path)
    clock = Clock(0.0)

    def answer(plugin):
        clock.t += 400.0
        return PSAUX if plugin == "linux.psaux" else BASH
    calls = _vol_stub(monkeypatch, answer)
    result = _triage(img, run_vol=True, vol_budget=500.0, clock=clock)
    assert [(p, kw["timeout"]) for p, kw in calls] == [("linux.psaux", 500.0), ("linux.bash", 100.0)]
    assert result["vol"]["status"] == "partial"
    assert result["vol"]["reason"] == "linux.pslist not run (no time left: 0 s of the run's budget)"


def test_long_tables_are_cut_and_the_cut_is_said(tmp_path, work, monkeypatch):
    img = _delivery(tmp_path)
    many = [{"PID": 2311, "Process": "bash", "CommandTime": f"2026-03-03T10:{i // 60:02d}:{i % 60:02d}+00:00",
             "Command": f"echo {i}", "__children": []} for i in range(vol_triage.LISTED + 7)]
    _vol_stub(monkeypatch, {"linux.psaux": PSAUX, "linux.bash": many, "linux.pslist": PSLIST})
    lines = _lines(_triage(img, run_vol=True))
    assert len([l for l in lines if l.startswith("history pid=")]) == vol_triage.LISTED
    assert "history = 7 more not listed" in lines and not any(l.startswith("proc =") for l in lines)


def test_notable_rules():
    procs = [{"pid": 1, "name": "systemd", "args": "/sbin/init"},
             {"pid": 2, "name": "python3", "args": "/usr/bin/python3 -u /opt/app/run.py --port 80"},
             {"pid": 3, "name": "sudo", "args": "sudo python3 keylog.py"},
             {"pid": 4, "name": "python3", "args": "python3 -m http.server 8000"},
             {"pid": 5, "name": "bash", "args": "bash"},
             {"pid": 6, "name": "payload", "args": "/dev/shm/.x/payload --quiet"},
             {"pid": 7, "name": "sh", "args": "sh -c /usr/bin/updater"},
             {"pid": 8, "name": "modprobe", "args": "/sbin/modprobe -q rootkit_mod"},
             {"pid": 9, "name": "Xwayland", "args": None},
             {"pid": 10, "name": "x", "args": "/usr/bin/Xvfb :99 -screen 0 1280x720x24"},
             {"pid": 11, "name": "cat", "args": "cat /etc/Xorg.conf"}]
    assert [(m["pid"], m["kind"], m["script"] or m["detail"]) for m in vol_triage.notable(procs)] == [
        (2, "script", "run.py"), (3, "script", "keylog.py"), (6, "writable-path", "/dev/shm/.x/payload"),
        (8, "kernel-module", "rootkit_mod"), (9, "display", ""), (10, "display", "/usr/bin/Xvfb :99 -screen 0 1280x720x24")]


def test_pivots_count_a_name_and_leave_short_ones_out():
    data = b"\x00".join([b"keylog.py"] * 5 + [b"a.py"] * 3)
    assert vol_triage.pivots(data, ["keylog.py", "a.py", "keylog.py", "absent_one.py"]) == [
        {"name": "keylog.py", "count": 5, "offsets": [0, 10, 20]}, {"name": "absent_one.py", "count": 0, "offsets": []}]


# ============================================================================== the command and the wiring

def test_main_ends_with_a_solver_result_and_blocks_on_an_image_it_cannot_read(tmp_path, work, capsys):
    assert vol_triage.main([str(tmp_path / "absent.lime")]) == 0
    out = capsys.readouterr().out.strip().splitlines()
    res = SolverResult.from_json(out[-1])
    assert res.status == "blocked" and "absent.lime could not be read (FileNotFoundError" in res.notes
    empty = tmp_path / "empty.lime"
    empty.write_bytes(b"")
    assert vol_triage.main([str(empty)]) == 0
    assert SolverResult.from_json(capsys.readouterr().out.strip().splitlines()[-1]).notes.startswith(
        "empty.lime could not be read (ValueError: empty.lime is empty)")
    img = _image(tmp_path / "files", FLAG.encode())
    assert vol_triage.main([str(img), *NO_CLOCK]) == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert SolverResult.from_json(out[-1]).flags == (FLAG,) and out[0].startswith("== mem.lime: ")
    for bad in (["--plugins", "linux.psaux;rm -rf", str(img)], ["--plugins", ",", str(img)], ["--budget", "0", str(img)],
                ["--vol-budget", "-1", str(img)]):
        assert vol_triage.main(bad) == 2, bad
    with pytest.raises(SystemExit) as stop:
        vol_triage.main([])
    assert stop.value.code == 2


def test_the_opener_arms_every_case_and_control_under_the_network_guard():
    """The shipped opener, as `python -m ctf arm` runs it: the real engine in a child process under the
    audit-hook guard (no socket, no child process), a fresh workdir, no event."""
    o = openers.for_lane("memory-forensics")
    assert o.engine == "toolkits.vol_triage" and o.category == "Forensics" and not o.needs_os_sandbox
    assert {c.fixture for c in o.all_cases} == {"memory_lime_with_table", "memory_lime_two_tables"}
    assert set(o.controls) == {"memory_lime_foreign_table", "memory_lime_no_banner"}
    r = openers.arm(o, guard="hook", timeout=300)      # 300 s: a wall-clock cap for four interpreter starts under machine load
    assert r.status == openers.ARMED, f"{r.reason}\n{r.output}"
    assert len(r.cases) == 4 and all(c.status == openers.ARMED and c.exit_code == 0 for c in r.cases), r.cases
    assert not r.missing and set(r.found) == {e for c in o.all_cases for e in c.expect}


def test_the_openers_key_is_the_match_not_the_release_or_the_file_name(tmp_path, monkeypatch):
    """The foreign-table control has the base's image, the base's table NAME and the base's kernel
    RELEASE: only the exact-banner match tells them apart, and the key is anchored on it. Each
    delivery has a workdir of its own, as `ctf arm` gives each run: a pack saved for the base would
    otherwise serve the control's image, which is the base's."""
    o = openers.for_lane("memory-forensics")
    outs = {}
    for fx in ("memory_lime_with_table", "memory_lime_foreign_table"):
        (tmp_path / f"work-{fx}").mkdir()
        monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / f"work-{fx}"))
        p = fixtures.build(fx, tmp_path / fx)
        outs[fx] = vol_triage.render(_triage(p))
        assert sorted(q.name for q in p.parent.iterdir()) == ["mem.lime", "symbols.json.xz"]
    assert [e for e in o.expect if not any(e in l for l in outs["memory_lime_with_table"])] == []
    absent = [e for e in o.expect if not any(e in l for l in outs["memory_lime_foreign_table"])]
    assert absent == ["isf = matched symbols.json.xz [delivery]",
                      "symbol_strategy = exact-banner ISF matched among the local symbol tables"]
    assert "kernel_release = 6.1.0-armed-amd64" in outs["memory_lime_foreign_table"]


def test_intake_plans_and_runs_the_opener_on_a_memory_image(tmp_path):
    """The manifest's [intake] table: a LiME file in the handout is given to the opener with the
    handout folder as a --symbols folder, under the guard, and its SolverResult is what intake reads."""
    chal = tmp_path / "chal"
    files = chal / "files"
    img = _image(files / "dump", FLAG.encode() + b"\x00", name="capture.bin")       # LiME by its bytes, not its name
    (files / "tables").mkdir()
    (files / "tables" / "symbols.json.xz").write_bytes(lzma.compress(_isf_doc(B1)))  # not beside the image: found through {folder}
    (files / "notes.txt").write_text("a memory capture of the workstation")
    m = EM.load(REPO / "solvers" / "toolkits" / "vol_triage.manifest.toml")
    assert m.intake.args == ("--symbols", "{folder}", "{file}") and not m.intake.spawns and m.cost_class == "cheap"
    g = G.resolve("hook")
    plan = IE.plan([m], "forensics", "", files, guard=g)
    jobs = [j for j in plan.jobs if j.manifest.id == "toolkits.vol_triage"]
    assert len(jobs) == 1 and [f.name for f in jobs[0].files] == ["capture.bin"], [(s.engine, s.reason) for s in plan.skipped]
    assert IE.plan([m], "forensics", "", files / "tables", guard=g).jobs == []       # no image, no job
    ctx = IE.Context(challenge_dir=chal, folder=files, out_root=chal / "recon" / "engines", profile=event.load("csctf"),
                     guard=g, root=REPO, python=sys.executable, challenge_id="b136", record=False, workdir=tmp_path / "work")
    (tmp_path / "work").mkdir()
    run = IE.run_job(jobs[0], ctx, timeout=300)        # 300 s: a wall-clock cap for one interpreter start under machine load
    out = (chal / run.output).read_text()
    assert run.status == "ok" and run.exit_code == 0, (chal / run.errors).read_text()
    assert (run.result_status, run.flags) == ("solved", (FLAG,))
    assert "isf = matched symbols.json.xz [--symbols]" in out and "kernel_release = 6.5.0-test-amd64" in out
    assert (tmp_path / "work" / "_memory" / "_symbols").is_dir()                      # the pack is ready for --vol
    assert img.exists()


def test_triage_routes_a_memory_brief_and_a_lime_file_to_the_opener(tmp_path):
    assert "toolkits.vol_triage" in [r["id"] for r in triage.suggest("forensics", "a memory dump of the admin's laptop")["routes"]]
    (tmp_path / "x.lime").write_bytes(b"EMiL" + bytes(60))
    assert "toolkits.vol_triage" in [r["id"] for r in triage.suggest("forensics", "what was running?", files_dir=tmp_path)["routes"]]
    assert runner.resolve("vol_triage").id == "toolkits.vol_triage"


# ============================================================================== round 1: untrusted tables, budgets

class Ticks:
    """A clock that moves one step every time it is read: 0, 1, 2, ... Whoever reads it spends time,
    so a search that reads it per folder, per candidate and per block is cut after a known number of
    reads, whatever the machine does."""

    def __init__(self, step: float = 1.0):
        self.t, self.step = -step, step

    def __call__(self) -> float:
        self.t += self.step
        return self.t


def _deep(levels: int = 12000) -> bytes:
    """A .json whose `linux_banner` value nests deeper than the JSON reader's stack: no table, and
    it must not take the opener down."""
    return b'{"linux_banner": ' + b'{"a": ' * levels + b"1" + b"}" * levels + b"}"


def test_a_table_nested_too_deep_to_parse_is_no_table_and_never_a_crash(tmp_path, work, capsys):
    img = _image(tmp_path / "files", FLAG.encode() + b"\x00")
    (tmp_path / "files" / "aaa-deep.json").write_bytes(_deep())
    (tmp_path / "files" / "symbols.json.xz").write_bytes(lzma.compress(_isf_doc(B1)))
    with pytest.raises(RecursionError):                                   # the decoy is what it is said to be
        json.loads(_deep())
    assert memory.isf_banner(tmp_path / "files" / "aaa-deep.json") is None
    tables, notes = memory.linux_isfs([tmp_path / "files"])
    assert [p.name for p, _ in tables] == ["symbols.json.xz"]
    assert notes == [f"{tmp_path / 'files'}: 1 candidate file(s) hold no Linux banner (aaa-deep.json)"]
    assert vol_triage.main([str(img), *NO_CLOCK]) == 0                    # the command intake runs, to its last line
    out = capsys.readouterr().out.strip().splitlines()
    assert any(l.startswith("isf = matched symbols.json.xz [delivery]") for l in out)
    assert SolverResult.from_json(out[-1]).flags == (FLAG,)


def test_a_table_search_that_fails_is_said_and_the_flags_still_print(tmp_path, work, monkeypatch):
    """Whatever reading a handout file raises is the isf note; it is not a traceback that loses the
    banner and the flags. The reader is replaced by one that raises (a stand-in for a fault no
    fixture reaches), so what is tested is vol_triage's handling, not the reader."""
    img = _image(tmp_path / "files", FLAG.encode() + b"\x00")
    (tmp_path / "files" / "symbols.json.xz").write_bytes(lzma.compress(_isf_doc(B1)))

    def boom(path, **kw):
        raise RuntimeError("the reader fell over\nsecond line")
    monkeypatch.setattr(memory, "isf_banner", boom)
    result = _triage(img)
    lines = _lines(result)
    isf = [l for l in lines if l.startswith("isf = ")]
    assert len(isf) == 1 and isf[0].startswith("isf = none (no local ISF for ")
    assert "the table search failed (RuntimeError: the reader fell over)" in isf[0] and "second line" not in isf[0]
    assert f"kernel_banner = {B1} x1" in lines and vol_triage.solver_result(result).flags == (FLAG,)


def test_isf_banner_parses_a_bounded_number_of_keys(tmp_path):
    """A table has one `linux_banner` symbol; a file with key after key that is not it costs a parse
    each. Exactly keys_max are parsed: the symbol behind 64 decoys is not reached by default."""
    decoys = {f"k{i:02d}": {"linux_banner": {"address": i}} for i in range(memory.ISF_KEYS_MAX)}
    doc = _isf_doc(B1, meta=decoys)
    assert doc.count(b'"linux_banner"') == memory.ISF_KEYS_MAX + 1 == 65
    p = tmp_path / "many.json"
    p.write_bytes(doc)
    assert memory.isf_banner(p) is None
    assert memory.isf_banner(p, keys_max=memory.ISF_KEYS_MAX + 1) == B1
    one_less = tmp_path / "fewer.json"
    one_less.write_bytes(_isf_doc(B1, meta=dict(list(decoys.items())[1:])))
    assert memory.isf_banner(one_less) == B1                              # 63 decoys: the symbol is the 64th key


def test_isf_banner_stops_reading_at_its_deadline(tmp_path):
    """The clock is read before every 1 MiB block. The banner lies in the third block."""
    probe = _isf_doc(B1)
    doc = _isf_doc(B1, before="x" * ((2 << 20) + 100))
    assert (2 << 20) < doc.find(b'"linux_banner"') < (3 << 20) and probe
    p = tmp_path / "big.json"
    p.write_bytes(doc)
    assert memory.isf_banner(p, clock=Ticks(), deadline=1.5) is None      # read at 0 and 1; the third read is late
    assert memory.isf_banner(p, clock=Ticks(), deadline=2.0) == B1        # exactly on the deadline is not past it
    assert memory.isf_banner(p) == B1                                     # no deadline: no clock is read
    reads = Ticks()
    assert memory.isf_banner(p, clock=reads, deadline=99.0) == B1 and reads.t == 2.0


def test_linux_isfs_keeps_a_deadline_and_names_where_it_stopped(tmp_path):
    """One read of the clock per folder level, one before each candidate, one per block of a
    candidate's read, one after a candidate with no banner. a.json answers in its first block; b.json
    is two blocks of padding with no banner; c.json is never reached by a short budget."""
    d, later = tmp_path / "d", tmp_path / "later"
    d.mkdir()
    later.mkdir()
    (d / "a.json").write_bytes(_isf_doc(B1))
    (d / "b.json").write_bytes(b'{"pad": "' + b"x" * ((1 << 20) + 50) + b'"}')
    (d / "c.json").write_bytes(_isf_doc(B2))
    (later / "z.json").write_bytes(_isf_doc(B2))
    cut = memory.ISF_CUT
    assert cut == "the table search's budget ran out"

    def run(deadline):
        tables, notes = memory.linux_isfs([d, later], clock=Ticks(), deadline=deadline)
        return [p.name for p, _ in tables], notes
    assert run(-1.0) == ([], [f"{d}: {cut}: 0 candidate(s) opened, the rest was not looked at", f"{later}: not looked at ({cut})"])
    # reads: 0 the folder, 1 before a.json, 2 a.json's block (found), 3 before b.json
    assert run(2.5) == (["a.json"], [f"{d}: {cut} before b.json: 1 candidate(s) opened, the rest was not looked at",
                                     f"{later}: not looked at ({cut})"])
    # ... 4 b.json's first block, 5 its second: late, so its read is cut and it is NOT said to hold no banner
    assert run(4.5) == (["a.json"], [f"{d}: {cut} while reading b.json: 2 candidate(s) opened, the rest was not looked at",
                                     f"{later}: not looked at ({cut})"])
    names, notes = run(1000.0)
    assert names == ["a.json", "c.json", "z.json"] and notes == [f"{d}: 1 candidate file(s) hold no Linux banner (b.json)"]
    assert memory.linux_isfs([d, later])[0] == memory.linux_isfs([d, later], clock=Ticks(), deadline=1000.0)[0]


def test_linux_isfs_stops_walking_after_walk_max_names_and_says_so(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    for name in ("a.txt", "b.txt"):
        (d / name).write_bytes(b"x")
    (d / "c.json").write_bytes(_isf_doc(B1))
    assert memory.linux_isfs([d], walk_max=2) == ([], [f"{d}: more than 2 files: the rest was not looked at"])
    tables, notes = memory.linux_isfs([d], walk_max=3)                    # exactly walk_max names are looked at
    assert [p.name for p, _ in tables] == ["c.json"] and notes == []
    assert memory.ISF_WALK_MAX == 20000


def test_match_linux_isf_says_a_cut_search_first_whatever_else_there_is_to_say(tmp_path):
    cut = f"{tmp_path}: {memory.ISF_CUT} before k.json: 3 candidate(s) opened, the rest was not looked at"
    notes = [f"/f{i}: no such folder" for i in range(8)] + [cut]
    path, banner, note = memory.match_linux_isf(Counter({B1: 1}), [tmp_path], tables=([], notes))
    assert (path, banner) == (None, None) and f"; {cut}; /f0: no such folder" in note and "/f5" not in note


def test_the_flags_are_scanned_before_the_table_search_and_keep_their_share_of_the_budget(tmp_path, work):
    """The handout's own files must not spend the flags' time. On a clock that moves with every
    read, a delivery whose first candidate eats the table search's budget still has its flag carved,
    and the cut is said; the same delivery on a clock that stands still matches its table."""
    img = _image(tmp_path / "files", FLAG.encode() + b"\x00")
    (tmp_path / "files" / "aaa-pad.json").write_bytes(b'{"pad": "' + b"x" * ((3 << 20) + 50) + b'"}')
    (tmp_path / "files" / "symbols.json.xz").write_bytes(lzma.compress(_isf_doc(B1)))
    # reads: 0 the start, 1 the carve's one chunk (its deadline is 0.3 * 6 = 1.8), 2 the scan's one chunk
    # (0.6 * 6 = 3.6), 3 the folder, 4 before aaa-pad.json, 5 and 6 its first blocks, 7 its third: past the
    # budget of 6
    result = _triage(img, clock=Ticks(), budget=6.0)
    assert result["banners"] == Counter({B1: 1}) and result["carve_cut"] is None
    assert result["flags"]["status"] == "ran" and [h["value"] for h in result["flags"]["flags"]] == [FLAG]
    lines = _lines(result)
    isf = [l for l in lines if l.startswith("isf = ")][0]
    assert isf.startswith("isf = none (") and f"{memory.ISF_CUT} while reading aaa-pad.json: 1 candidate(s) opened" in isf
    assert vol_triage.solver_result(result).status == "solved" and not any(l.startswith("next =") for l in lines)
    still = _triage(img)
    assert still["table"]["path"] == tmp_path / "files" / "symbols.json.xz" and still["flags"]["status"] == "ran"
    # the scan's own deadline is SCAN_SHARE of the budget, counted from the start: with a budget of 1 the
    # scan's look at the clock (2) is already past 0.6, and the carve's (1) past 0.3
    late = _triage(img, clock=Ticks(), budget=1.0)
    assert late["flags"]["status"] == "cut" and late["flags"]["reason"] == f"the scan budget ran out at offset 0x0 of 0x{img.stat().st_size:x}"
    assert late["flags"]["flags"] == [] and vol_triage.SCAN_SHARE == 0.6
    assert late["carve_cut"] == 0 and not late["banners"] and vol_triage.CARVE_SHARE == 0.3
    edge = _triage(img, clock=Ticks(), budget=2.0 / vol_triage.SCAN_SHARE + 0.01)       # just inside both shares: carved, scanned
    assert edge["flags"]["status"] == "ran" and edge["carve_cut"] is None and edge["banners"] == Counter({B1: 1})
    short = _triage(img, clock=Ticks(), budget=2.0 / vol_triage.SCAN_SHARE - 0.02)      # just outside both
    assert short["flags"]["status"] == "cut" and short["carve_cut"] == 0


def test_linux_symbols_for_gives_the_table_search_a_budget(tmp_path, work):
    img = _image(tmp_path / "files")
    (tmp_path / "files" / "aaa-pad.json").write_bytes(b'{"pad": "' + b"x" * ((3 << 20) + 50) + b'"}')
    (tmp_path / "files" / "symbols.json.xz").write_bytes(lzma.compress(_isf_doc(B1)))
    pack, note = memory.linux_symbols_for(img, budget=3.0, clock=Ticks())
    assert pack is None and f"{memory.ISF_CUT} while reading aaa-pad.json" in note
    pack, note = memory.linux_symbols_for(img, budget=1000.0, clock=Ticks())
    assert pack is not None and "symbols.json.xz was made for this kernel" in note
    # The default is a real budget. It is read off the signature, not timed: a run on the wall clock
    # would be an upper bound on this machine's speed.
    assert inspect.signature(memory.linux_symbols_for).parameters["budget"].default == memory.ISF_SEARCH_BUDGET == 60.0


# ============================================================================== round 1: one kernel through the report

def test_the_report_is_about_the_kernel_the_table_matches(tmp_path, work):
    """Three copies of another kernel's banner and one of this one's: the table is this one's, so the
    banner, the release, the arch, the isf line and the result's notes all name this one."""
    img = _image(tmp_path / "files", B2.encode() + b"\x00", B2.encode() + b"\n", B2.encode() + b"\x00")
    # with no table for either, the most frequent banner is the kernel
    result = _triage(img)
    lines = _lines(result)
    assert result["banners"] == Counter({B2: 3, B1: 1}) and result["table"]["kernel"] == B2
    assert f"kernel_banner = {B2} x3" in lines and f"kernel_banner(other) = {B1} x1" in lines
    assert "kernel_release = 5.10.0-other-arm64" in lines and "arch = arm64" in lines
    assert vol_triage.solver_result(result).notes.startswith("mem.lime: kernel 5.10.0-other-arm64; no local ISF;")
    # with the table of the less frequent one beside the image, the report is about that one
    (tmp_path / "files" / "t.json").write_bytes(_isf_doc(B1))
    result = _triage(img)
    assert result["table"]["kernel"] == B1
    lines = _lines(result)
    at = lines.index(f"kernel_banner = {B1} x1")
    assert lines[at + 1:at + 4] == [f"kernel_banner(other) = {B2} x3", "kernel_release = 6.5.0-test-amd64", "arch = x64"]
    assert "isf = matched t.json [delivery]: t.json was made for this kernel (its banner is the image's)" in lines
    # the other kernel is named only as what it is: another carved banner (and the most frequent text of the carve)
    assert f"banners(carved) = 2 distinct, the most frequent: {B2} x3" in lines
    assert not any("5.10.0-other-arm64" in l for l in lines if not l.startswith(("kernel_banner(other)", "banners(carved)")))
    assert vol_triage.solver_result(result).notes == "mem.lime: kernel 6.5.0-test-amd64; ISF matched; flag scan ran; Volatility not run"


def test_other_banners_are_listed_up_to_a_cap(tmp_path, work):
    extra = [B1.replace("#1 SMP", f"#{n} SMP") for n in (3, 4, 5, 6)]
    img = _image(tmp_path / "files", B1.encode() + b"\x00", *[b.encode() + b"\x00" for b in extra])
    lines = _lines(_triage(img))
    assert f"kernel_banner = {B1} x2" in lines
    others = [l for l in lines if l.startswith("kernel_banner(other) = ")]
    assert others == [f"kernel_banner(other) = {b} x1" for b in extra[:vol_triage.OTHER_BANNERS]] and vol_triage.OTHER_BANNERS == 3


# ============================================================================== round 1: AVML, and what is not Linux

def _snappy(*literals: bytes) -> bytes:
    """A snappy framed stream of one compressed chunk whose block is a run of literal elements, one
    per argument (what a compressor writes for bytes it has not seen before). Between two literals
    stands a tag: text the compressor cut in two no longer stands whole in the file."""
    def lit(p: bytes) -> bytes:
        n = len(p) - 1
        if n < 60:
            return bytes([n << 2]) + p
        return (bytes([60 << 2, n]) if n < 256 else bytes([61 << 2]) + n.to_bytes(2, "little")) + p
    size, varint = sum(len(p) for p in literals), b""
    while True:
        varint += bytes([(size & 0x7f) | (0x80 if size > 0x7f else 0)])
        size >>= 7
        if not size:
            break
    chunk = bytes(4) + varint + b"".join(lit(p) for p in literals)       # 4 bytes: the chunk's checksum, read by nothing here
    return b"\xff\x06\x00\x00sNaPpY" + b"\x00" + len(chunk).to_bytes(3, "little") + chunk


def _avml2(tmp_path: Path, *literals: bytes, name: str = "mem.avml", size: int | None = None) -> Path:
    """An AVML version 2 file of one range: the header (inclusive end, as LiME's), the snappy framed
    stream of the literals, and the 8-byte trailer. size: what the header states the range holds
    (default: what the literals hold)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    p = tmp_path / name
    size = sum(len(part) for part in literals) if size is None else size
    stream = _snappy(*literals)
    p.write_bytes(b"AVML" + struct.pack("<IQQ", 2, 0x100000, 0x100000 + size - 1) + bytes(8) + stream + struct.pack("<Q", len(stream)))
    return p


@pytest.mark.needs_tool("py:cramjam")
def test_a_compressed_avml_image_is_decompressed_and_read(tmp_path, work):
    """AVML version 2 is snappy-compressed. The banner and the flag here are each cut in two by the
    compressor (neither stands whole in the file): the stage decompresses the range and finds both,
    at the offsets they have in the LiME file avml-convert would write."""
    banner, flag = B1.encode() + b"\n\x00", FLAG.encode()
    parts = (bytes(64) + banner[:9], banner[9:] + bytes(64) + flag[:9], flag[9:] + bytes(64))
    cut = _avml2(tmp_path / "cut", *parts)
    raw = cut.read_bytes()
    assert raw.count(b"Linux version ") == 0 and raw.count(flag) == 0 and memory.image_format(raw) == "avml"
    (tmp_path / "cut" / "t.json").write_bytes(_isf_doc(B1))
    result = _triage(cut)
    body = b"".join(parts)
    assert result["compressed"] is True and result["format"] == "avml" and result["banners"] == Counter({B1: 1})
    assert result["unpacked"] == {"status": "ran", "reason": "", "ranges": 1, "bytes": len(body), "where": result["unpacked"]["where"]}
    lines = _lines(result)
    assert lines[0] == f"== mem.avml: {cut.stat().st_size} bytes, format avml version 2 (snappy-compressed ranges)"
    assert lines[1] == (f"image_note = AVML version 2: decompressed, 1 range(s), {len(body)} bytes. The offsets below are offsets "
                        "in the LiME file avml-convert writes of this image, not in the file itself")
    assert f"kernel_banner = {B1} x1" in lines and any(l.startswith("isf = matched t.json [delivery]") for l in lines)
    at = 32 + body.index(flag)                                          # the LiME copy: a 32-byte header, then the range
    assert f"flag(carved) = {FLAG} x1 first at 0x{at:x}" in lines
    res = vol_triage.solver_result(result)
    assert (res.status, res.flags) == ("solved", (FLAG,))
    assert res.notes == "mem.avml: kernel 6.5.0-test-amd64; AVML version 2: decompressed; ISF matched; flag scan ran; Volatility not run"
    assert res.evidence[0].detail == f"{FLAG} stands 1 time(s) in the decompressed image (offsets: its LiME copy)"
    # the same range as a LiME file gives the same banners and the same flag at the same offset
    (tmp_path / "lime").mkdir()
    (tmp_path / "lime" / "mem.lime").write_bytes(_lime(body))
    plain = _triage(tmp_path / "lime" / "mem.lime")
    assert plain["compressed"] is False and plain["unpacked"] is None and not any(l.startswith("image_note") for l in _lines(plain))
    assert (plain["banners"], plain["flags"]["flags"]) == (result["banners"], result["flags"]["flags"])
    assert vol_triage.solver_result(plain).evidence[0].detail == f"{FLAG} stands 1 time(s) in the image's bytes"


def test_an_image_with_no_linux_banner_is_sent_to_the_engine_that_reads_it(tmp_path, work):
    img = _image(tmp_path / "my files", banner=None, name="win.vmem")
    lines = _lines(_triage(img))
    assert lines[1].startswith("kernel_banner = none (no 'Linux version' banner in the image")
    assert lines[1].endswith(f"This opener reads Linux images only: a Windows image is toolkits.memory's, "
                             f"python -m ctf run toolkits.memory '{img}')")       # the path has a space: quoted
    assert runner.resolve("toolkits.memory").id == "toolkits.memory"            # the engine named is one that exists


# ============================================================================== round 1: the pack and the next step

def test_the_next_step_carries_the_symbols_folders_and_runs_as_printed(tmp_path, work, monkeypatch, capsys):
    """The table is found only through --symbols (as at intake, which passes the handout folder). The
    printed command, run as it stands, finds it again and runs the plugins."""
    img = _image(tmp_path / "my files")
    extra = tmp_path / "tables here"
    extra.mkdir()
    (extra / "k.json").write_bytes(_isf_doc(B1))
    assert vol_triage.main([str(img), "--symbols", str(extra), *NO_CLOCK]) == 0
    nxt = [l for l in capsys.readouterr().out.splitlines() if l.startswith("next = ")]
    assert nxt == [f"next = python -m ctf run toolkits.vol_triage '{img}' --symbols '{extra}' --vol   "
                   "(outside intake's network guard: it cuts the docker socket)"]
    argv = shlex.split(nxt[0].split("   (")[0])
    assert argv[:5] == ["next", "=", "python", "-m", "ctf"] and argv[5:7] == ["run", "toolkits.vol_triage"]
    for pack in list(memory.symbols_folder().glob("linux-*")):            # no saved pack: only --symbols can find the table
        shutil.rmtree(pack)
    calls = _vol_stub(monkeypatch, {"linux.psaux": PSAUX, "linux.bash": BASH, "linux.pslist": PSLIST})
    assert vol_triage.main([*argv[7:], *NO_CLOCK]) == 0
    out = capsys.readouterr().out
    assert "isf = matched k.json [--symbols]" in out and "vol linux.psaux = 5 rows" in out
    assert [p for p, _kw in calls] == ["linux.psaux", "linux.bash", "linux.pslist"]


def test_a_pack_saved_earlier_serves_the_image_when_the_table_is_gone(tmp_path, work, monkeypatch):
    img = _image(tmp_path / "files")
    table = tmp_path / "files" / "symbols.json.xz"
    table.write_bytes(lzma.compress(_isf_doc(B1)))
    assert memory.saved_linux_pack(Counter({B1: 1})) == (None, None, "no pack was saved earlier for this kernel")
    first = _triage(img)
    pack = first["table"]["pack"]
    assert first["table"]["reused"] is False and f"symbol_pack = {pack}" in _lines(first)
    again = _lines(_triage(img))                                           # the same table again: the pack is reused, and said
    assert f"symbol_pack = {pack} (reused: saved earlier from this very table)" in again
    table.unlink()
    result = _triage(img)
    got = result["table"]
    assert (got["path"], got["pack"], got["label"], got["banner"], got["reused"]) == (pack, pack, "saved pack", B1, True)
    assert got["profile"].symbol_strategy == memory_depth.ISF_MATCHED and got["profile"].symbol_hint == str(pack)
    lines = _lines(result)
    assert "isf = matched linux.zip [saved pack]: a pack saved earlier for this kernel holds symbols.json.xz" in lines
    assert f"symbol_pack = {pack}" in lines and f"next = python -m ctf run toolkits.vol_triage {img} --vol   " \
        "(outside intake's network guard: it cuts the docker socket)" in lines
    calls = _vol_stub(monkeypatch, {"linux.psaux": PSAUX, "linux.bash": BASH, "linux.pslist": PSLIST})
    assert _triage(img, run_vol=True)["vol"]["status"] == "ran" and {kw["symbols"] for _p, kw in calls} == {str(pack)}
    assert memory.linux_symbols_for(img) == (pack, "a pack saved earlier for this kernel holds symbols.json.xz")
    # another kernel's image finds nothing; a file that is no pack, under a pack's name, is passed over
    other = _triage(_image(tmp_path / "other", banner=B2))
    assert other["table"]["path"] is None and other["table"]["pack"] is None
    junk = pack.parent.with_name(pack.parent.name[:-16] + "0" * 16)
    junk.mkdir()
    (junk / "linux.zip").write_bytes(b"not a zip at all")
    stray = pack.parent.with_name(pack.parent.name[:-16] + "1" * 16)
    stray.mkdir()
    with zipfile.ZipFile(stray / "linux.zip", "w") as z:
        z.writestr("windows/ntkrnlmp.json", "{}")                         # a zip, but not a pack of Linux tables
    assert memory.saved_linux_pack([B1])[0] == pack
    # two packs for one banner (a second table carried it): the newest, and the note says there are two
    table.write_bytes(lzma.compress(_isf_doc(B1, before="another table for the same banner")))
    second = memory.linux_symbol_pack(table, B1)
    os.utime(pack, ns=(1_000_000_000, 1_000_000_000))
    assert memory.saved_linux_pack([B1]) == (second, B1, "a pack saved earlier for this kernel holds symbols.json.xz "
                                                         "(2 packs were saved for this banner: the newest is used)")
    os.utime(second, ns=(500_000_000, 500_000_000))
    assert memory.saved_linux_pack(Counter({B1: 1}))[0] == pack
    assert memory.saved_linux_pack([B1 + " and more"])[0] is None          # by the exact banner only


# ============================================================================== round 1: the Volatility stage

def test_text_from_the_image_cannot_start_a_report_line(tmp_path, work, monkeypatch):
    """A process name or an argument with a line break in it (a `python -c` script; a crafted image)
    is printed as a literal: no line of the report begins inside it."""
    img = _delivery(tmp_path)
    forged = "flag(carved) = CSCTF{forged_by_the_image} x1 first at 0x0"
    psaux = [{"PID": 7, "PPID": 1, "COMM": "python3", "ARGS": f"python3 /opt/job.py\n{forged}\nisf = matched evil", "__children": []},
             {"PID": 8, "PPID": 1, "COMM": "X\nnext = evil", "ARGS": "/usr/bin/Xorg :0\nvolatility = ran", "__children": []}]
    _vol_stub(monkeypatch, {"linux.psaux": psaux, "linux.bash": [], "linux.pslist": []})
    result = _triage(img, run_vol=True)
    assert [(m["pid"], m["kind"]) for m in result["notable"]] == [(7, "script"), (8, "display")]
    lines = _lines(result)
    assert all("\n" not in l and "\r" not in l for l in lines)
    assert f"notable = pid 7 'python3' [script] {('python3 /opt/job.py' + chr(10) + forged + chr(10) + 'isf = matched evil')!r}" in lines
    assert "notable = pid 8 'X\\nnext = evil' [display] '/usr/bin/Xorg :0\\nvolatility = ran'" in lines
    assert any(l.startswith("handoff = pixels: 'X\\nnext = evil' (pid 8) holds the screen.") for l in lines)
    report = "\n".join(lines).splitlines()
    assert not any(l.startswith(("flag(carved) =", "isf = matched evil", "next = evil")) for l in report)
    assert [l for l in report if l.startswith("volatility = ")] == [f"volatility = ran; tables saved under {result['vol']['folder']}"]


def test_a_volatility_stage_with_no_time_for_its_first_plugin_is_not_run(tmp_path, work, monkeypatch):
    """Skipped for the budget is `not run`, never `failed`: nothing looked at the image."""
    img = _delivery(tmp_path)
    calls = _vol_stub(monkeypatch, {"linux.psaux": PSAUX, "linux.bash": BASH, "linux.pslist": PSLIST})
    result = _triage(img, run_vol=True, vol_budget=memory.VOL_MIN_SLICE - 1.0)
    assert calls == [] and result["vol"]["status"] == "not run"
    assert result["vol"]["reason"] == "linux.psaux not run (no time left: 4 s of the run's budget)"
    assert "volatility = not run (linux.psaux not run (no time left: 4 s of the run's budget))" in _lines(result)


def test_run_volatility_is_in_the_sandbox_and_never_online_unless_told(tmp_path, work, monkeypatch):
    img = _delivery(tmp_path)
    pack = _triage(img)["table"]["pack"]
    calls = _vol_stub(monkeypatch, {"linux.psaux": PSAUX, "linux.bash": BASH, "linux.pslist": PSLIST})
    got = vol_triage.run_volatility(img, pack, clock=Clock())             # the defaults, as a caller with no options has them
    assert got["status"] == "ran" and len(calls) == 3
    assert all(kw["where"] == "sandbox" and kw["online"] is False and "start" not in kw for _p, kw in calls)


def test_a_history_row_with_no_command_is_not_a_history_line():
    model = memory.Model()
    rows = [{"PID": 9, "Process": "bash", "CommandTime": "2026-03-03T10:00:00+00:00", "Command": None},
            {"PID": 9, "Process": "bash", "CommandTime": "2026-03-03T10:00:01+00:00", "Command": "ls"}]
    kinds = [model.absorb(t, "table") for t in memory.tables_from_json(rows)[0]]
    assert kinds == ["history"] and [(h["pid"], h["command"]) for h in model.history] == [(9, "ls")]


def test_a_fragment_ends_at_a_space_and_at_a_byte_that_is_not_printable_ascii():
    data = _page(b"CSCTF{part one of two\x00", b"CSCTF{high\x80tail\x00", b"CSCTF{dele\x7fted\x00", b"CSCTF{tabs\tafter\x00")
    assert [h["value"] for h in vol_triage.scan_flags(data)["fragments"]] == ["CSCTF{part", "CSCTF{high", "CSCTF{dele", "CSCTF{tabs"]


def test_pivots_search_for_a_bounded_number_of_names():
    names = [f"script_{i:02d}.py" for i in range(vol_triage.PIVOT_NAMES + 2)]
    got = vol_triage.pivots(b"\x00".join(n.encode() for n in names), names)
    assert [p["name"] for p in got] == names[:8] and all(p["count"] == 1 for p in got) and vol_triage.PIVOT_NAMES == 8


# ============================================================================== round 1: the command's options

BARE = "Linux version 6.8.0-45-generic (buildd@host) (gcc 13.2.0) #45-Test SMP Fri Aug 30 12:02:04 UTC 2026"


def _bare_delivery(tmp_path):
    img = _image(tmp_path / "files", banner=BARE)
    (tmp_path / "files" / "t.json").write_bytes(_isf_doc(BARE))
    return img


def test_main_without_vol_starts_nothing(tmp_path, work, monkeypatch, capsys):
    img = _bare_delivery(tmp_path)
    calls = _vol_stub(monkeypatch, {"linux.psaux": PSAUX, "linux.bash": BASH, "linux.pslist": PSLIST})
    assert vol_triage.main([str(img), *NO_CLOCK]) == 0
    out = capsys.readouterr().out
    assert calls == [] and "volatility = not run (--vol not given)" in out and "\narch = " not in out


def test_main_with_vol_runs_the_plugins_in_the_sandbox_by_default(tmp_path, work, monkeypatch, capsys):
    """`python -m ctf run toolkits.vol_triage <image> --vol`, the command the no-tool stage prints:
    the three plugins, in the sandbox, offline, a container started when none is up."""
    img = _bare_delivery(tmp_path)
    calls = _vol_stub(monkeypatch, {"linux.psaux": PSAUX, "linux.bash": BASH, "linux.pslist": PSLIST})
    assert vol_triage.main([str(img), "--vol", *NO_CLOCK]) == 0
    out = capsys.readouterr().out
    assert [p for p, _kw in calls] == ["linux.psaux", "linux.bash", "linux.pslist"]
    assert all(kw["where"] == "sandbox" and kw["online"] is False and "start" not in kw for _p, kw in calls)
    # The default stage budget (1500 s) leaves a plugin its whole 600 s. (Wall clock: this holds unless
    # the three stubbed calls take more than 900 s, which no machine load makes them.)
    assert all(kw["timeout"] == 600.0 for _p, kw in calls)
    assert "vol linux.psaux = 5 rows" in out and "volatility = ran; tables saved under " in out
    assert SolverResult.from_json(out.strip().splitlines()[-1]).notes.endswith("Volatility ran (5 processes, 2 history rows)")


def test_main_passes_every_option_of_the_volatility_stage(tmp_path, work, monkeypatch, capsys):
    img = _bare_delivery(tmp_path)
    calls = _vol_stub(monkeypatch, {"linux.psaux": PSAUX, "linux.bash": BASH, "linux.pslist": PSLIST})
    assert vol_triage.main([str(img), "--vol", "--no-start", "--arch", "arm64", "--vol-budget", "400", "--where", "venv",
                            "--plugins", "linux.bash, linux.psaux", *NO_CLOCK]) == 0
    out = capsys.readouterr().out
    assert [p for p, _kw in calls] == ["linux.bash", "linux.psaux"]                     # --plugins, in the order given
    assert all(kw["where"] == "venv" and kw["start"] is False and kw["online"] is False for _p, kw in calls)   # --where, --no-start
    # --vol-budget: a plugin gets what is left of 400 s, never the 600 s it has under the default budget.
    # (Wall clock, so only the bound that holds on any machine is asserted: at most 400.)
    assert all(0.0 < kw["timeout"] <= 400.0 for _p, kw in calls)
    assert "arch = arm64" in out.splitlines()                                           # --arch


def test_the_printed_command_runs_through_the_real_sandbox_runner(tmp_path, work, stand_in_docker, capsys):
    """main([image, --vol, --no-start]) down to tools/sandbox.py and a stand-in docker program: the
    image and the pack are in each call's drop folder, three plugins run, nothing is started."""
    img = _delivery(tmp_path)
    assert vol_triage.main([str(img), "--vol", "--no-start", *NO_CLOCK]) == 0
    out = capsys.readouterr().out
    assert "volatility = ran; tables saved under " in out and "vol linux.psaux = 1 rows" in out and "vol linux.pslist = 1 rows" in out
    assert "proc pid=1 ppid=0 comm='systemd' args='/sbin/init'" in out.splitlines()
    execs = [c[c.index("vol") + 1:] for c in stand_in_docker() if c[0] == "exec" and "vol" in c]
    assert [v[-1] for v in execs] == ["linux.psaux", "linux.bash", "linux.pslist"]
    assert all(v[:4] == ["-q", "-r", "json", "--offline"] and v[v.index("-s") + 1].endswith("/linux.zip/..") for v in execs)
    assert not any(c[0] in ("run", "start", "rm", "pull", "build") for c in stand_in_docker())


# ============================================================================== round 1: intake and routes

MATCHED = [("capture.bin", b"EMiL" + bytes(60)), ("dump.dat", b"AVML" + struct.pack("<IQQ", 2, 0, 4095) + bytes(8) + _snappy(bytes(40))),
           ("a.lime", b"no magic in this one"), ("b.avml", b"nor in this one"), ("c.mem", bytes(64)), ("d.VMEM", bytes(64))]


@pytest.mark.parametrize("name, body", MATCHED, ids=[n for n, _ in MATCHED])
def test_intake_takes_each_kind_of_memory_image_the_manifest_names(tmp_path, name, body):
    (tmp_path / name).write_bytes(body)
    (tmp_path / "notes.txt").write_bytes(b"a capture")
    (tmp_path / "disk.raw").write_bytes(bytes(64))
    m = EM.load(REPO / "solvers" / "toolkits" / "vol_triage.manifest.toml")
    plan = IE.plan([m], "misc", "", tmp_path, guard=G.resolve("hook"))
    assert [[f.name for f in j.files] for j in plan.jobs] == [[name]] and plan.skipped == []


def test_intake_hands_the_opener_an_image_the_sweep_left_out_for_size(tmp_path):
    """engines.plan: an original that is not in the scratch folder (the sweep copies none over 256 MiB,
    and a memory image is nearly always larger) reaches an engine that says `originals = true`, by
    its own path, and no other engine."""
    files, scratch = tmp_path / "files", tmp_path / "unpacked"
    img = _image(files)
    scratch.mkdir()
    (scratch / "symbols.json.xz").write_bytes(lzma.compress(_isf_doc(B1)))
    m = EM.load(REPO / "solvers" / "toolkits" / "vol_triage.manifest.toml")
    assert m.intake.originals is True
    g = G.resolve("hook")
    assert IE.plan([m], "forensics", "", scratch, guard=g).jobs == []                    # as it was: not in scratch, no job
    left = IE.left_out(files, read=set())
    assert [(f, head[:4]) for f, head in left] == [(img, b"EMiL")]
    jobs = IE.plan([m], "forensics", "", scratch, guard=g, originals=left).jobs
    assert [(j.manifest.id, j.files) for j in jobs] == [("toolkits.vol_triage", (img,))]
    plain = dataclasses.replace(m, intake=dataclasses.replace(m.intake, originals=False))
    assert IE.plan([plain], "forensics", "", scratch, guard=g, originals=left).jobs == []   # an engine that did not ask gets none


def test_left_out_lists_what_the_sweep_did_not_read_and_enters_no_secret_folder(tmp_path):
    files = tmp_path / "files"
    for rel in ("big.lime", "sub/deep.mem", "small.txt", ".ctf/token.lime", ".git/x.lime"):
        (files / rel).parent.mkdir(parents=True, exist_ok=True)
        (files / rel).write_bytes(b"EMiL" + rel.encode())
    (files / "link.lime").symlink_to(files / "big.lime")
    (files / "linkdir").symlink_to(files / "sub", target_is_directory=True)
    got = IE.left_out(files, read={"small.txt"})
    assert [(f.relative_to(files).as_posix(), head) for f, head in got] == [
        ("big.lime", b"EMiLbig.lime"), ("sub/deep.mem", b"EMiLsub/deep.mem")]
    assert IE.left_out(files, read={"small.txt", "big.lime", "sub/deep.mem"}) == []
    assert IE.left_out(tmp_path / "absent", read=()) == [] and IE.left_out(None, read=()) == []


def test_the_originals_key_is_checked_at_discovery(tmp_path):
    m = EM.load(REPO / "solvers" / "toolkits" / "vol_triage.manifest.toml")
    raw = {"select": "files", "run": "per-file", "match": ["ext:.lime"], "args": ["{file}"]}
    assert EM.parse_intake(tmp_path / "x.toml", raw, m.entry).originals is False
    assert EM.parse_intake(tmp_path / "x.toml", {**raw, "originals": True}, m.entry).originals is True
    with pytest.raises(EM.ManifestError, match=r"intake\.originals.*expected true or false, got str"):
        EM.parse_intake(tmp_path / "x.toml", {**raw, "originals": "yes"}, m.entry)
    with pytest.raises(EM.ManifestError, match=r"intake\.originals.*needs run = \"per-file\""):
        EM.parse_intake(tmp_path / "x.toml", {"run": "folder", "match": ["ext:.lime"], "args": ["{folder}"], "originals": True}, m.entry)


class _Handout:
    """A platform adapter that serves one challenge from memory (ctf.intake.intake_one's `adapter`)."""
    kind = "fake"

    def __init__(self, challenge, files: dict):
        self.challenge, self.files = challenge, files

    def get_challenge(self, cid):
        return self.challenge

    def download_files(self, cid, dest):
        for rel, data in self.files.items():
            (Path(dest) / rel).parent.mkdir(parents=True, exist_ok=True)
            (Path(dest) / rel).write_bytes(data)
        return [Path(dest) / rel for rel in self.files]


def test_one_intake_runs_the_opener_on_an_image_over_the_sweeps_source_limit(tmp_path, monkeypatch):
    """The whole intake of one challenge, with the sweep's per-file limit set below the image's size
    (the image here is 8 KiB; a real one is over the real limit of 256 MiB): the sweep leaves the image
    out and says so, and the opener still runs on it, by its path in files/, and its flag is read."""
    from ctf import intake as I, sweep
    from ctf.platform import Challenge
    monkeypatch.setattr(sweep, "MAX_SOURCE", 6000)
    image = _lime(bytes(4096), _page(B1.encode() + b"\n\x00", FLAG.encode() + b"\x00"))
    assert len(image) > 6000
    ad = _Handout(Challenge(id="36", name="Eyes", category="forensics", points=500, description="what was on the screen?",
                            files=(), solved_by_team=False),
                  {"mem.lime": image, "symbols.json.xz": lzma.compress(_isf_doc(B1))})
    m = EM.load(REPO / "solvers" / "toolkits" / "vol_triage.manifest.toml")
    rep = I.intake_one("36", event.load("csctf"), adapter=ad, workdir=tmp_path / "wd", manifests=[m],
                       options=I.Options(net_guard="hook", record=False, engine_budget=300.0))    # 300 s: one interpreter start under load
    assert any("not read 'mem.lime'" in n and "over the source limit of 6000" in n for n in rep.notes), rep.notes
    assert not (rep.dir / "unpacked" / "mem.lime").exists() and (rep.dir / "unpacked" / "symbols.json.xz").is_file()
    assert [(r.engine, r.inputs, r.status, r.result_status, r.flags) for r in rep.runs] == [
        ("toolkits.vol_triage", ("files/mem.lime",), "ok", "solved", (FLAG,))], [(s.engine, s.reason) for s in rep.plan.skipped]
    out = (rep.dir / rep.runs[0].output).read_text()
    assert "isf = matched symbols.json.xz [delivery]" in out and "kernel_release = 6.5.0-test-amd64" in out
    # with the limit above the image's size nothing is left out and the image is taken from the scratch copy, once
    monkeypatch.setattr(sweep, "MAX_SOURCE", 256 << 20)
    rep = I.intake_one("36", event.load("csctf"), adapter=ad, workdir=tmp_path / "wd2", manifests=[m],
                       options=I.Options(net_guard="hook", record=False, engine_budget=300.0))
    assert [(r.engine, r.inputs, r.flags) for r in rep.runs] == [("toolkits.vol_triage", ("unpacked/mem.lime",), (FLAG,))]


def test_a_brief_that_names_no_system_goes_to_the_general_memory_engine_first(tmp_path):
    """The opener is Linux-only: `a memory dump` alone ranks it after toolkits.memory; a Linux capture
    format or plugin in the brief, or a LiME/AVML file, ranks it before."""
    def order(description, files_dir=None):
        ids = [r["id"] for r in triage.suggest("forensics", description, files_dir=files_dir)["routes"]]
        return ids.index("toolkits.vol_triage"), ids.index("toolkits.memory")
    for brief in ("a memory dump of the admin's laptop", "RAM dump attached", "memory forensics 101", "a memory capture"):
        opener, general = order(brief)
        assert general < opener, brief
    for brief in ("the .lime capture is attached", "taken with avml", "run linux.psaux on it", "the dwarf2json table is included"):
        opener, general = order(brief)
        assert opener < general, brief
    (tmp_path / "x.lime").write_bytes(b"EMiL" + bytes(60))
    opener, general = order("what was running?", files_dir=tmp_path)
    assert opener < general
    by_priority = {tuple(r.keywords): r.priority for r in EM.load(REPO / "solvers" / "toolkits" / "vol_triage.manifest.toml").routes}
    general_priority = max(r.priority for r in runner.resolve("toolkits.memory").routes if "forensics" in r.category)
    assert by_priority[("memory dump", "memory capture", "memory forensics", "ram dump")] < general_priority


@pytest.mark.needs_tool("git")
def test_the_lane_gates_key_follows_every_fixture_builder_module(tmp_path, monkeypatch):
    """ctf.adapt.regress keys an opener case on the fixture code. The memory builders live in
    ctf/openers/memory_fixtures.py, not in fixtures.py: a builder module that changes must change the
    lane's key, or the gate keeps a warm verdict for fixtures that are no longer what was replayed."""
    import adapt_repo as AR
    from ctf.adapt import regress as R
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "gate-state"))
    for k in AR.PROBE_VARS:
        monkeypatch.delenv(k, raising=False)
    root = AR.make_repo(tmp_path)
    wd = tmp_path / "work"
    wd.mkdir()
    # the synthetic checkout links ctf/ to the real one; give it an openers/ folder of its own, so a
    # builder module can be added and edited without touching the repo
    (root / "ctf").unlink()
    (root / "ctf" / "openers").mkdir(parents=True)
    for entry in (REPO / "ctf").iterdir():
        if entry.name not in ("openers", "__pycache__"):
            (root / "ctf" / entry.name).symlink_to(entry, target_is_directory=entry.is_dir())
    for entry in (REPO / "ctf" / "openers").iterdir():
        if entry.name != "__pycache__":
            (root / "ctf" / "openers" / entry.name).symlink_to(entry, target_is_directory=entry.is_dir())
    assert (root / "ctf" / "openers" / "memory_fixtures.py").is_file() and R.FIXTURE_GLOB == "ctf/openers/*fixtures.py"
    extra = root / "ctf" / "openers" / "extra_fixtures.py"
    extra.write_text("BUILDERS = {}\n")
    k1 = R.current_lane_key("probe", root=root, workdir=wd)
    assert R.current_lane_key("probe", root=root, workdir=wd) == k1          # stable
    extra.write_text("BUILDERS = {}  # edited\n")
    k2 = R.current_lane_key("probe", root=root, workdir=wd)
    assert k2 != k1
    extra.unlink()                                                          # a builder module removed is a change too
    assert R.current_lane_key("probe", root=root, workdir=wd) not in (k1, k2)


# ============================================================================== round 2: names from the handout

FORGED = "flag(carved) = CSCTF{forged_by_a_file_name} x1 first at 0x0"
KEYS = ("== ", "image_note = ", "banners(carved) = ", "kernel_banner = ", "kernel_banner(other) = ", "kernel_release = ", "arch = ",
        "isf = ", "isf_note = ", "symbol_strategy = ", "symbol_hint = ", "symbol_pack = ", "flag_scan = ", "volatility = ",
        "next = ", "handoff = ")
BREAKS = "\n\r\x0b\x0c\x1c\x1d\x1e\x85  "        # every character str.splitlines (intake's reader) ends a line at


def _report(capsys) -> list:
    """What main printed, split the way intake splits an engine's stdout; the last line is the result."""
    lines = capsys.readouterr().out.splitlines()
    SolverResult.from_json(lines[-1])
    assert [l for l in lines[:-1] if not l.startswith(KEYS)] == []      # no line begins with anything but a key of the report
    return lines


def test_shown_writes_a_name_on_one_line_and_leaves_a_plain_name_alone():
    assert memory.shown("symbols.json.xz") == "symbols.json.xz" and memory.shown(Path("/a b/ç é.json")) == "/a b/ç é.json"
    assert memory.shown("a\nb\rc\x00d\x1be") == "a\\nb\\rc\\x00d\\x1be" and memory.shown("a b\x85c") == "a\\u2028b\\x85c"
    for c in BREAKS:
        assert len(memory.shown(f"x{c}{FORGED}").splitlines()) == 1, repr(c)
    assert memory.shown("bad\udc80name") == "bad\\udc80name"            # a name that is not text (surrogateescape) prints too


def test_a_name_from_the_handout_cannot_start_a_report_line(tmp_path, work, capsys):
    """A table, an image and a folder of the handout whose names hold a line break and a forged
    `flag(carved)` line: every name is printed inside the line it belongs to, with the break
    escaped, and the report holds no flag line."""
    files = tmp_path / f"handout\n{FORGED}\nfolder"
    img = _image(files, name=f"mem\n{FORGED}\n.lime")
    table = files / f"x\n{FORGED}\nt.json"
    table.write_bytes(_isf_doc(B1))
    esc = FORGED.join(("\\n", "\\n"))                                   # the break as it must be printed
    assert vol_triage.main([str(img), *NO_CLOCK]) == 0
    lines = _report(capsys)
    assert lines[0] == f"== mem{esc}.lime: {img.stat().st_size} bytes, format lime, 2 range(s)"
    assert f"isf = matched x{esc}t.json [delivery]: x{esc}t.json was made for this kernel (its banner is the image's)" in lines
    assert [l for l in lines if l.startswith("next = ")] == [
        f"next = python -m ctf run toolkits.vol_triage $'{tmp_path}/handout{esc}folder/mem{esc}.lime' --vol   "
        "(outside intake's network guard: it cuts the docker socket)"]
    res = SolverResult.from_json(lines[-1])
    assert (res.status, res.flags) == ("none", ()) and "flag_scan = ran over 8256 bytes: 0 flag(s), 0 lead(s) with no complete flag" in lines
    # the table is gone: the pack saved from it is named by the table's name, on one line
    table.unlink()
    assert vol_triage.main([str(img), *NO_CLOCK]) == 0
    assert f"isf = matched linux.zip [saved pack]: a pack saved earlier for this kernel holds x{esc}t.json" in _report(capsys)
    # no table and no pack: the folders, the table of another build and the file that is no table are all named in one line
    shutil.rmtree(memory.symbols_folder())
    (files / f"other\n{FORGED}\n.json").write_bytes(_isf_doc(B1_OTHER_BUILD))
    (files / f"blank\n{FORGED}\n.json").write_bytes(b"{}")
    absent = tmp_path / f"absent\n{FORGED}\n"
    assert vol_triage.main([str(img), "--symbols", str(absent), *NO_CLOCK]) == 0
    isf = [l for l in _report(capsys) if l.startswith("isf = ")]
    assert len(isf) == 1 and isf[0].startswith("isf = none (no local ISF for 'Linux version 6.5.0-test-amd64")
    for want in (f"other{esc}.json is for the same release but another build", f"under {tmp_path}/handout{esc}folder, ",
                 f"{tmp_path}/absent{esc}: no such folder", f"1 candidate file(s) hold no Linux banner (blank{esc}.json)"):
        assert want in isf[0], want
    # an image this opener does not read, and one that is not there: the command and the reason stand on one line
    win = _image(tmp_path / "win", banner=None, name=f"win\n{FORGED}\n.vmem")
    assert vol_triage.main([str(win), *NO_CLOCK]) == 0
    lines = _report(capsys)
    assert lines[1].endswith(f"python -m ctf run toolkits.memory $'{tmp_path}/win/win{esc}.vmem')")
    assert vol_triage.main([str(tmp_path / f"gone\n{FORGED}\n.lime")]) == 0
    lines = _report(capsys)
    assert len(lines) == 2 and lines[0].startswith(f"== gone{esc}.lime: not read (gone{esc}.lime could not be read (FileNotFoundError")


def test_the_toolkits_own_notes_name_a_file_on_one_line(tmp_path, work, monkeypatch):
    """memory.py's notes are read by more than the opener (its own report prints them): each name in
    them is escaped where the note is made."""
    esc = FORGED.join(("\\n", "\\n"))
    d = tmp_path / f"dir\n{FORGED}\n"
    d.mkdir()
    right, blank = d / f"x\n{FORGED}\nt.json", d / f"blank\n{FORGED}\n.json"
    right.write_bytes(_isf_doc(B1))
    blank.write_bytes(b"{}")
    gone = tmp_path / f"gone\n{FORGED}\n"
    tables, notes = memory.linux_isfs([d, gone])
    assert [p for p, _ in tables] == [right]
    assert notes == [f"{tmp_path}/dir{esc}: 1 candidate file(s) hold no Linux banner (blank{esc}.json)", f"{tmp_path}/gone{esc}: no such folder"]
    assert memory.match_linux_isf([B1], [d])[2] == f"x{esc}t.json was made for this kernel (its banner is the image's)"
    miss = memory.match_linux_isf([B1_OTHER_BUILD], [d, gone])[2]
    assert len(miss.splitlines()) == 1 and f"x{esc}t.json is for the same release but another build" in miss
    assert f"under {tmp_path}/dir{esc}, {tmp_path}/gone{esc} (made for" in miss
    # a search the clock cut names the file it stopped at, and the folder it never looked at
    _t, cut = memory.linux_isfs([d, d / "sub"], deadline=0.5, clock=Ticks())      # reads: 0 the folder, 1 before the first candidate
    assert cut == [f"{tmp_path}/dir{esc}: {memory.ISF_CUT} before blank{esc}.json: 0 candidate(s) opened, the rest was not looked at",
                   f"{tmp_path}/dir{esc}/sub: not looked at ({memory.ISF_CUT})"]
    _t, cut = memory.linux_isfs([d], deadline=1.5, clock=Ticks())                  # ... 2 inside the first candidate's read
    assert cut == [f"{tmp_path}/dir{esc}: {memory.ISF_CUT} while reading blank{esc}.json: 1 candidate(s) opened, the rest was not looked at"]
    memory.linux_symbol_pack(right, B1)
    assert memory.saved_linux_pack([B1])[2] == f"a pack saved earlier for this kernel holds x{esc}t.json"
    monkeypatch.setattr(memory, "ISF_PACK_MAX", 1)
    with pytest.raises(memory.TableTooLarge) as too:
        memory.linux_symbol_pack(right, B1)
    assert str(too.value).startswith(f"x{esc}t.json is {right.stat().st_size} bytes, over the 1 a pack takes")


def test_a_line_break_in_a_note_never_reaches_the_report(tmp_path, work, monkeypatch):
    """Not only names: whatever a part of the stage puts in a note (here the Volatility stage's
    reason) is printed with its breaks escaped."""
    img = _delivery(tmp_path)
    _vol_stub(monkeypatch, lambda plugin: (None, f"{plugin} failed: Traceback\n{FORGED}\rnext = evil isf = matched evil"))
    said = []
    result = _triage(img, run_vol=True, say=said.append)
    lines = _lines(result)
    assert all(len(l.splitlines()) == 1 for l in lines) and not any(l.startswith(("flag(carved)", "next = evil", "isf = matched evil")) for l in lines)
    assert f"vol linux.psaux = no table (linux.psaux failed: Traceback\\n{FORGED}\\rnext = evil\\u2028isf = matched evil)" in lines
    assert said == lines                                                # what is said while it works is escaped the same way


@pytest.mark.needs_tool("bash")
def test_the_next_step_of_a_path_with_a_line_break_is_one_line_the_shell_reads_back(tmp_path, work, capsys):
    img = _image(tmp_path / "it's a\\ folder", name="mem\nx 'q'\t.lime")
    extra = tmp_path / "tables\nhere"
    extra.mkdir()
    (extra / "k.json").write_bytes(_isf_doc(B1))
    assert vol_triage.main([str(img), "--symbols", str(extra), *NO_CLOCK]) == 0
    nxt = [l for l in _report(capsys) if l.startswith("next = ")]
    assert len(nxt) == 1 and nxt[0].startswith("next = python -m ctf run toolkits.vol_triage $'")
    command = nxt[0][len("next = "):].split("   (outside")[0]
    # 300 s: a wall-clock cap for one shell start under machine load
    got = subprocess.run(["bash", "-c", f"printf '%s\\0' {command}"], capture_output=True, timeout=300)
    assert got.returncode == 0, got.stderr
    assert got.stdout.split(b"\0")[:-1] == [os.fsencode(a) for a in (
        "python", "-m", "ctf", "run", "toolkits.vol_triage", str(img), "--symbols", str(extra), "--vol")]
    assert vol_triage._shell("plain name") == "'plain name'" and vol_triage._shell("plain") == "plain"     # shlex.quote, as before


# ============================================================================== round 2: the longest banner

def test_of_several_tables_the_one_with_the_longest_banner_is_the_kernels(tmp_path, work):
    """A table that carries only the first 60 characters of the banner stands before the kernel's
    own in walk order. It matches by Volatility's test, and alone it is taken (and said to be only a
    start); beside the exact table it is not. memory_depth.select_profile agrees."""
    files = tmp_path / "files"
    img = _image(files)
    short = B1[:60]
    assert short == short.strip() and B1.startswith(short)
    (files / "a-decoy.json").write_bytes(_isf_doc(short))
    assert memory.match_linux_isf(Counter({B1: 1}), [files]) == (
        files / "a-decoy.json", short, f"a-decoy.json was made for this kernel (its banner is the first 60 of the {len(B1)} characters carved)")
    (files / "symbols.json.xz").write_bytes(lzma.compress(_isf_doc(B1)))
    assert memory.match_linux_isf(Counter({B1: 1}), [files]) == (
        files / "symbols.json.xz", B1, "symbols.json.xz was made for this kernel (its banner is the image's)")
    # a carved run that goes on past the banner: still the longest start of it
    path, made_for, note = memory.match_linux_isf([B1 + " and more"], [files])
    assert (path.name, made_for) == ("symbols.json.xz", B1)
    assert note == f"symbols.json.xz was made for this kernel (its banner is the first {len(B1)} of the {len(B1) + 9} characters carved)"
    result = _triage(img)
    table = result["table"]
    assert (table["path"], table["banner"], table["tables"]) == (files / "symbols.json.xz", B1, 2)
    assert zipfile.ZipFile(table["pack"]).namelist() == ["linux/symbols.json.xz"]
    assert table["profile"].symbol_strategy == memory_depth.ISF_MATCHED and table["profile"].symbol_hint == str(table["path"])
    assert "isf = matched symbols.json.xz [delivery]: symbols.json.xz was made for this kernel (its banner is the image's)" in _lines(result)
    # two tables with the same banner: the first in walk order, as before
    (files / "b-same.json").write_bytes(_isf_doc(B1, before="another table for the same banner"))
    assert memory.match_linux_isf([B1], [files])[0] == files / "b-same.json"


# ============================================================================== round 2: intake survivors

def test_plan_gives_an_originals_engine_its_scratch_files_and_the_left_out_ones(tmp_path):
    """One image under the sweep's limit (in the scratch copy) and one over it (left out): both are
    given to the opener, the scratch one first, each by its own path."""
    files, scratch = tmp_path / "files", tmp_path / "unpacked"
    big = _image(files, name="big.lime")
    small = _image(scratch, name="small.lime")
    m = EM.load(REPO / "solvers" / "toolkits" / "vol_triage.manifest.toml")
    g = G.resolve("hook")
    left = IE.left_out(files, read=set())
    assert [f for f, _ in left] == [big] and m.intake.max_files == 2
    plan = IE.plan([m], "forensics", "", scratch, guard=g, originals=left)
    assert [(j.manifest.id, j.files, j.index) for j in plan.jobs] == [
        ("toolkits.vol_triage", (small,), 0), ("toolkits.vol_triage", (big,), 1)] and plan.skipped == []
    # one more left-out image: over the engine's max_files, and said
    _image(files, name="huge.lime")
    plan = IE.plan([m], "forensics", "", scratch, guard=g, originals=IE.left_out(files, read=set()))
    assert [j.files for j in plan.jobs] == [(small,), (big,)]
    assert [(s.engine, s.reason) for s in plan.skipped] == [("toolkits.vol_triage", "1 more matching file(s) over its max_files = 2")]


def test_left_out_lists_a_bounded_number_of_files(tmp_path, monkeypatch):
    files = tmp_path / "files"
    for rel in ("a.lime", "b.lime", "sub/c.lime", "sub/d.lime", "z.lime"):
        (files / rel).parent.mkdir(parents=True, exist_ok=True)
        (files / rel).write_bytes(b"EMiL")
    assert len(IE.left_out(files, read=set())) == 5 and IE.MAX_INPUT_FILES == 5000
    monkeypatch.setattr(IE, "MAX_INPUT_FILES", 4)
    assert [f.relative_to(files).as_posix() for f, _ in IE.left_out(files, read=set())] == ["a.lime", "b.lime", "z.lime", "sub/c.lime"]
    monkeypatch.setattr(IE, "MAX_INPUT_FILES", 1)
    assert [f.name for f, _ in IE.left_out(files, read={"a.lime"})] == ["b.lime"]       # what the sweep read does not count


# ============================================================================== round 2: said as it is found

def test_the_report_is_said_line_by_line_as_each_part_is_found(tmp_path, work, monkeypatch):
    img = _delivery(tmp_path, FLAG.encode() + b"\x00", b"CSCTF{f1rst_h4lf_\x00")
    _vol_stub(monkeypatch, {"linux.psaux": PSAUX, "linux.bash": BASH, "linux.pslist": PSLIST})
    for kw in ({}, {"run_vol": True}, {"budget": 1.0, "clock": Ticks()}):
        said = []
        result = _triage(img, say=said.append, **kw)
        assert said == vol_triage.render(result) and said[0].startswith("== mem.lime: ") and len(said) >= 5, kw
    said = []
    blank = _triage(_image(tmp_path / "blank", banner=None), say=said.append)
    assert said == vol_triage.render(blank) and said[1].startswith("kernel_banner = none (")
    # each part is said before the next one starts: the header and the banner before the scan, the flags
    # before the table search (the part that reads the handout's own files), the table before Volatility
    said, seen = [], {}
    real = {name: getattr(vol_triage, name) for name in ("scan_flags", "find_table", "run_volatility")}

    def spy(name):
        def call(*args, **kw):
            seen[name] = list(said)
            return real[name](*args, **kw)
        return call
    for name in real:
        monkeypatch.setattr(vol_triage, name, spy(name))
    result = _triage(img, say=said.append, run_vol=True)
    head = [f"== mem.lime: {img.stat().st_size} bytes, format lime, 2 range(s)", f"banners(carved) = 1 distinct, the most frequent: {B1} x1"]
    assert seen["scan_flags"] == head
    assert [l.split(" = ")[0] for l in seen["find_table"][2:]] == ["flag_scan", "flag(carved)", "flag_fragment(carved)"]
    assert [l.split(" = ")[0] for l in seen["run_volatility"][5:]] == [
        "kernel_banner", "kernel_release", "arch", "isf", "symbol_strategy", "symbol_hint", "symbol_pack"]
    assert said[len(seen["run_volatility"])].startswith("volatility = ran") and said == vol_triage.render(result)
    assert vol_triage.PARTS == (vol_triage.head_lines, vol_triage.image_lines, vol_triage.carve_lines, vol_triage.flag_lines,
                                vol_triage.table_lines, vol_triage.vol_lines, vol_triage.tail_lines)


KILLED_RUN = """
import os, signal, sys
sys.path.insert(0, sys.argv[1])
import vol_triage


def killed(*args, **kw):        # what intake's limit does to a run: SIGKILL, with nothing run after it
    os.kill(os.getpid(), signal.SIGKILL)


vol_triage.find_table = killed
vol_triage.main([sys.argv[2], "--budget", "86400"])
"""


def test_a_killed_run_has_already_printed_what_it_found(tmp_path, work):
    """The opener in a process of its own, its stdout a file (as at intake), killed with SIGKILL when
    the table search starts: the header, the banner and the carved flag are in the file. Printed
    after the stage, or printed and not flushed, the file would be empty."""
    img = _delivery(tmp_path, FLAG.encode() + b"\x00")
    out = tmp_path / "out.txt"
    with open(out, "wb") as fo:
        # 300 s: a wall-clock cap for one interpreter start under machine load
        proc = subprocess.run([sys.executable, "-c", KILLED_RUN, str(REPO / "solvers" / "toolkits"), str(img)],
                              stdout=fo, stderr=subprocess.PIPE, timeout=300)
    assert proc.returncode == -9, proc.stderr.decode("utf-8", "replace")
    at = img.read_bytes().index(FLAG.encode())
    assert out.read_text().splitlines() == [
        f"== mem.lime: {img.stat().st_size} bytes, format lime, 2 range(s)",
        f"banners(carved) = 1 distinct, the most frequent: {B1} x1",
        f"flag_scan = ran over {img.stat().st_size} bytes: 1 flag(s), 0 lead(s) with no complete flag",
        f"flag(carved) = {FLAG} x1 first at 0x{at:x}"]
    assert flagfmt.current().find_flags(out.read_text()) == [FLAG]      # what intake reads off a killed run's stdout


# ============================================================================== round 2: the carve on the clock

def test_the_banner_carve_counts_each_banner_once_whatever_the_chunks_and_keeps_a_deadline():
    data = bytes(100) + B1.encode() + b"\n\x00" + bytes(50) + B2.encode() + b"\x00" + bytes(70) + B1.encode() + b"\x00"
    whole = Counter({B1: 2, B2: 1})
    info = {"cut": "stale"}
    assert memory.carve_linux_banners(data, info=info) == whole and info == {"cut": None}
    for chunk in (1, 7, 13, 14, 15, 64, 101, 4096):                     # the needle is 14 bytes: it straddles most of these
        assert memory.carve_linux_banners(data, chunk=chunk) == whole, chunk
    assert sum(memory.carve_linux_banners(data, limit=2, chunk=7).values()) == 2 and memory.CARVE_CHUNK == 64 << 20

    def never():
        raise AssertionError("the clock is not read when there is no deadline")
    assert memory.carve_linux_banners(data, clock=never) == whole
    # a clock that moves one step a read (0, 1, 2): two chunks of 128 are read, the third look is past 1.5
    second = data.index(B2.encode())
    assert data.index(B1.encode()) < 128 and second >= 256
    assert memory.carve_linux_banners(data, deadline=1.5, clock=Ticks(), chunk=128, info=info) == Counter({B1: 1}) and info == {"cut": 256}
    assert memory.carve_linux_banners(data, deadline=-1.0, clock=Ticks(), info=info) == Counter() and info == {"cut": 0}
    assert memory.carve_linux_banners(data, deadline=1e9, clock=Ticks(), chunk=128, info=info) == whole and info == {"cut": None}


def test_a_banner_carve_the_clock_cut_is_said(tmp_path, work):
    img = _image(tmp_path / "files")
    late = _triage(img, clock=Ticks(), budget=1.0)                       # the carve's look at the clock (1) is past 0.3
    lines = _lines(late)
    assert lines[1] == ("kernel_banner = none (the banner carve's budget ran out at offset 0x0: what stands after it was not read; "
                        "run this again with a larger --budget)")
    assert "not a Linux kernel's memory" not in "\n".join(lines) and "toolkits.memory" not in "\n".join(lines)
    # a carve cut after it found something says both
    assert vol_triage.carve_lines({"banners": Counter({B1: 2, B2: 1}), "carve_cut": 0x4000000}) == [
        f"banners(carved) = 2 distinct, the most frequent: {B1} x2 (the banner carve's budget ran out at offset 0x4000000: "
        "what stands after it was not read)"]
    assert vol_triage.carve_lines({"banners": Counter({B1: 2}), "carve_cut": None}) == [f"banners(carved) = 1 distinct, the most frequent: {B1} x2"]


# ============================================================================== round 2: the pack's limit

def test_a_table_over_the_pack_limit_is_matched_but_not_packed(tmp_path, work, monkeypatch):
    assert memory.ISF_PACK_MAX == 512 << 20 and issubclass(memory.TableTooLarge, OSError)
    img = _image(tmp_path / "files")
    table = tmp_path / "files" / "t.json"
    table.write_bytes(_isf_doc(B1))
    size = table.stat().st_size
    monkeypatch.setattr(memory, "ISF_PACK_MAX", size - 1)
    with pytest.raises(memory.TableTooLarge) as too:
        memory.linux_symbol_pack(table, B1)
    why = f"t.json is {size} bytes, over the {size - 1} a pack takes: compress the table (xz) and run this again"
    assert str(too.value) == why and not list(work.rglob("*.zip")) and not list(work.rglob("*.tmp"))
    result = _triage(img)
    lines = _lines(result)
    assert result["table"]["path"] == table and result["table"]["pack"] is None
    assert "isf = matched t.json [delivery]: t.json was made for this kernel (its banner is the image's)" in lines
    assert f"symbol_pack = not written (TableTooLarge: {why})" in lines and not any(l.startswith("next =") for l in lines)
    assert memory.linux_symbols_for(img) == (
        None, f"t.json was made for this kernel (its banner is the image's), but no pack was made of it: {why}")
    monkeypatch.setattr(memory, "ISF_PACK_MAX", size)                    # at the limit: packed
    assert zipfile.ZipFile(memory.linux_symbol_pack(table, B1)).namelist() == ["linux/t.json"]


def test_a_temporary_pack_file_a_killed_run_left_is_removed_once_it_is_old(tmp_path, work):
    table = tmp_path / "t.json"
    table.write_bytes(_isf_doc(B1))
    pack = memory.linux_symbol_pack(table, B1)
    pack.unlink()
    old, fresh, other = pack.with_name(".linux.zip.111.tmp"), pack.with_name(".linux.zip.222.tmp"), pack.with_name("notes.tmp")
    for f in (old, fresh, other):
        f.write_bytes(b"half a pack")
    # File times are wall-clock by nature. The bound holds at any load: `old` and `other` are a minute past
    # the limit, `fresh` would have to wait an hour inside this test to pass it.
    long_ago = time.time() - memory.PACK_TMP_STALE - 60
    os.utime(old, (long_ago, long_ago))
    os.utime(other, (long_ago, long_ago))
    assert memory.linux_symbol_pack(table, B1) == pack and zipfile.ZipFile(pack).namelist() == ["linux/t.json"]
    assert sorted(p.name for p in pack.parent.iterdir()) == [".linux.zip.222.tmp", "linux.zip", "notes.tmp"]
    assert memory.PACK_TMP_STALE == 3600.0


# ============================================================================== round 2: AVML version 2

def _noise(n: int) -> bytes:
    """n bytes no compressor shortens, the same every run (a stored chunk in the snappy framing)."""
    out = b"".join(hashlib.sha256(i.to_bytes(4, "little")).digest() for i in range(n // 32 + 1))
    return out[:n]


def _avml_head(start: int, size: int) -> bytes:
    return b"AVML" + struct.pack("<IQQ", 2, start, start + size - 1) + bytes(8)


def _avml_range(body: bytes, start: int) -> bytes:
    """One range as AVML writes it: the header, the snappy framed stream (cramjam's own, with real
    checksums), and the 8-byte trailer that holds the stream's length."""
    import cramjam
    stream = bytes(cramjam.snappy.compress(body))
    return _avml_head(start, len(body)) + stream + struct.pack("<Q", len(stream))


def _lime_range(body: bytes, start: int) -> bytes:
    return b"EMiL" + struct.pack("<IQQ", 1, start, start + len(body) - 1) + bytes(8) + body


def _chunk_kinds(stream: bytes) -> list:
    kinds, pos = [], 0
    while pos + 4 <= len(stream):
        kinds.append(stream[pos])
        pos += 4 + int.from_bytes(stream[pos + 1:pos + 4], "little")
    return kinds


def _to_lime(data: bytes, **kw) -> tuple:
    out = io.BytesIO()
    info = memory.avml_to_lime(data, out, **kw)
    return info, out.getvalue()


@pytest.mark.needs_tool("py:cramjam")
def test_avml_to_lime_writes_the_lime_file_of_the_ranges():
    import cramjam
    one = bytes(70000) + B1.encode() + b"\n\x00" + _noise(150000) + FLAG.encode() + bytes(3000)
    two = bytes(70000) + b"the second range" + bytes(4096)
    kinds = _chunk_kinds(bytes(cramjam.snappy.compress(one)))
    assert kinds[0] == 0xff and {0x00, 0x01} <= set(kinds) and len(kinds) >= 4     # compressed and stored chunks, several of each range
    data = _avml_range(one, 0x1000) + _avml_range(two, 0x9000000)
    assert memory.image_format(data) == "avml" and [s["size"] for s in memory.lime_segments(data)] == [None]
    info, got = _to_lime(data)
    assert info == {"status": "ran", "reason": "", "ranges": 2, "bytes": len(one) + len(two)}
    assert got == _lime_range(one, 0x1000) + _lime_range(two, 0x9000000)
    assert [(s["start"], s["size"], s["version"]) for s in memory.lime_segments(got)] == [(0x1000, len(one), 1), (0x9000000, len(two), 1)]
    # padding and other skippable chunks are passed over; a stored chunk is taken as it stands
    stream = (_snappy(b"abc" * 10) + b"\xfe\x03\x00\x00pad" + b"\x80\x02\x00\x00xx"
              + b"\x01" + (4 + 5).to_bytes(3, "little") + bytes(4) + b"plain")
    info, got = _to_lime(_avml_head(0x2000, 35) + stream + bytes(8))
    assert info["status"] == "ran" and got == _lime_range(b"abc" * 10 + b"plain", 0x2000)
    # a range gives no more than its header states
    info, got = _to_lime(_avml_head(0x2000, 25) + _snappy(b"abc" * 10) + bytes(8))
    assert (info["status"], info["bytes"]) == ("ran", 25) and got == _lime_range((b"abc" * 10)[:25], 0x2000)


@pytest.mark.needs_tool("py:volatility3")
@pytest.mark.needs_tool("py:cramjam")
def test_the_synthetic_avml_image_is_laid_out_as_volatilitys_own_avml_layer_reads_it(monkeypatch):
    """No real AVML file can be made here, so the layout these tests build (and avml_to_lime reads) is
    checked against an independent reader of real ones: Volatility 3's AVML layer. Its walk is its
    own (the header as `<IIQQQ`, frames until more than end - start bytes are out, which is right
    only for an inclusive end, then 8 trailer bytes); only its snappy call, a system libsnappy
    through ctypes, is replaced by cramjam's. Both readers must see the same ranges."""
    import cramjam
    from volatility3.framework.layers import avml
    monkeypatch.setattr(avml, "uncompress", lambda raw: bytes(cramjam.snappy.decompress_raw(raw)))
    one, two = bytes(70000) + B1.encode() + bytes(70000), b"second" * 20000
    data = _avml_range(one, 0x1000) + _avml_range(two, 0x9000000)
    offset, ranges = 0, []
    while offset + 4 < len(data):
        magic, version, start, end, _padding = struct.unpack_from("<IIQQQ", data, offset)
        assert (magic, version) == (0x4C4D5641, 2)
        segments, consumed = avml.AVMLLayer._read_snappy_frames(None, data[offset + 32:offset + 32 + (end - start)], end - start)
        ranges.append((start, sum(size for _at, _mapped, size, _mapped_size, _compressed in segments)))
        offset += 32 + consumed + 8
    assert offset == len(data) and ranges == [(0x1000, len(one)), (0x9000000, len(two))]
    info, got = _to_lime(data)
    assert info["status"] == "ran" and [(s["start"], s["size"]) for s in memory.lime_segments(got)] == ranges


STOPS = [
    ("the-file-ends", b"", "the file ends inside the range"),
    ("chunk-past-the-end", b"\x00\xff\xff\x00", "the chunk at offset {at} runs past the end of the file"),
    ("no-checksum", b"\x00\x02\x00\x00ab", "the chunk at offset {at} is shorter than its checksum"),
    ("not-snappy", b"\x00\x08\x00\x00" + bytes(4) + b"\x05abc", "the chunk at offset {at} is not snappy data (snappy: corrupt input"),
    ("declares-a-megabyte", b"\x00\x08\x00\x00" + bytes(4) + b"\x80\x80\x40\x00", "the chunk at offset {at} declares more than the format's 65536 bytes"),
    ("reserved-type", b"\x02\x00\x00\x00", "the chunk at offset {at} has the reserved type 0x02"),
    ("another-stream", b"\xff\x06\x00\x00sNaPpX", "the stream identifier at offset {at} is not snappy's"),
]


@pytest.mark.needs_tool("py:cramjam")
@pytest.mark.parametrize("after, why", [(a, w) for _n, a, w in STOPS], ids=[n for n, _a, _w in STOPS])
def test_avml_to_lime_names_where_a_range_stops_and_writes_what_it_holds(after, why):
    """A range whose header states 100 bytes and whose stream gives 40, then stops for a reason: the
    copy is a LiME file of those 40 bytes (its header says 40), and the reason is named."""
    good = _avml_head(0x4000, 100) + _snappy(bytes(range(40)))
    info, got = _to_lime(good + after)
    assert (info["status"], info["ranges"], info["bytes"]) == ("cut", 1, 40)
    want = "range 1 (0x4000..0x4063) holds 40 of its 100 bytes: " + why.replace("{at}", f"0x{len(good):x}")
    assert info["reason"].startswith(want), info["reason"]
    assert got == _lime_range(bytes(range(40)), 0x4000)
    assert [(s["start"], s["size"]) for s in memory.lime_segments(got)] == [(0x4000, 40)]


@pytest.mark.needs_tool("py:cramjam")
def test_avml_to_lime_stops_at_what_is_no_range_and_writes_no_empty_one():
    body = bytes(300) + b"kept"
    whole = _avml_range(body, 0x1000)
    # after a whole range: bytes that are no header, and a header of another version
    info, got = _to_lime(whole + b"j" * 40)
    assert info == {"status": "cut", "ranges": 1, "bytes": 304,
                    "reason": f"the bytes at offset 0x{len(whole):x} are not an AVML range header: 40 byte(s) after range 1 were not read"}
    assert got == _lime_range(body, 0x1000)
    info, got = _to_lime(whole + b"AVML" + struct.pack("<IQQ", 1, 0x5000, 0x5fff) + bytes(8) + bytes(64))
    assert info["status"] == "cut" and got == _lime_range(body, 0x1000)
    assert info["reason"] == (f"the header at offset 0x{len(whole):x} is not a version 2 range (version 1, 0x5000..0x5fff): "
                              "96 byte(s) after range 1 were not read")
    # a second range whose first chunk is damaged holds nothing: it is not written, and it is named
    info, got = _to_lime(whole + _avml_head(0x8000, 64) + b"\xff\x06\x00\x00sNaPpY" + b"\x00\x08\x00\x00" + bytes(4) + b"\x05abc")
    assert (info["status"], info["ranges"], info["bytes"]) == ("cut", 1, 304) and got == _lime_range(body, 0x1000)
    assert info["reason"].startswith("range 2 (0x8000..0x803f) holds 0 of its 64 bytes: the chunk at offset ")
    # bytes that do not begin with a version 2 range at all: not run, and nothing is written
    for data, why in ((_lime_range(body, 0), "the bytes at offset 0x0 are not an AVML range header"),
                      (b"AVML" + struct.pack("<IQQ", 2, 9, 3) + bytes(8), "the header at offset 0x0 is not a version 2 range (version 2, 0x9..0x3)"),
                      (b"AVML" + bytes(8), "the bytes at offset 0x0 are not an AVML range header")):
        assert _to_lime(data) == ({"status": "not run", "reason": why, "ranges": 0, "bytes": 0}, b"")


@pytest.mark.needs_tool("py:cramjam")
def test_avml_to_lime_keeps_a_budget_and_a_reserve_of_free_space():
    body = bytes(300000)                                                # five chunks: four of 64 KiB and the rest
    data = _avml_range(body, 0)

    def never():
        raise AssertionError("neither the clock nor the free space is looked at without a deadline or a `free`")
    assert _to_lime(data, clock=never, step=1)[0]["status"] == "ran"
    # step 100000: looked at after the second chunk (131072 bytes) and after the fourth (262144). The clock
    # moves one step a read (0, 1): the second look is past 0.5
    info, got = _to_lime(data, deadline=0.5, clock=Ticks(), step=100000)
    assert info == {"status": "cut", "ranges": 1, "bytes": 262144,
                    "reason": "range 1 (0x0..0x493df) holds 262144 of its 300000 bytes: the decompression budget ran out"}
    assert got == _lime_range(bytes(262144), 0)
    assert _to_lime(data, deadline=1.0, clock=Ticks(), step=100000)[0]["status"] == "ran"       # 1 is not past 1
    looks = []
    info, got = _to_lime(data, step=100000, free=lambda: looks.append(1) or 10, reserve=11)
    assert info["reason"] == "range 1 (0x0..0x493df) holds 131072 of its 300000 bytes: fewer than 11 bytes are free where the copy is written"
    assert got == _lime_range(bytes(131072), 0) and looks == [1]
    assert _to_lime(data, step=100000, free=lambda: 11, reserve=11)[0]["status"] == "ran"       # the reserve itself is enough
    defaults = inspect.signature(memory.avml_to_lime).parameters
    assert (defaults["step"].default, defaults["reserve"].default) == (16 << 20, 1 << 30) == (memory.AVML_STEP, memory.AVML_RESERVE)
    assert memory.AVML_CHUNK_MAX == 65536


def test_an_avml_image_is_not_decompressed_without_the_snappy_reader_and_says_so(tmp_path, work, monkeypatch):
    """No cramjam: the stage reads the file's bytes as they stand, as it did before, and names the
    missing module. A banner the compressor cut in two is then not found, and the reason given is
    the compression, not `not Linux`."""
    monkeypatch.setitem(sys.modules, "cramjam", None)                   # `import cramjam` raises ImportError
    banner = B1.encode() + b"\n\x00"
    assert _to_lime(_avml_head(0, 4) + _snappy(b"abcd") + bytes(8)) == (
        {"status": "not run", "reason": "py:cramjam is not installed (requirements.in pins it): there is no snappy reader",
         "ranges": 0, "bytes": 0}, b"")
    cut = _avml2(tmp_path / "cut", bytes(64) + banner[:9], banner[9:] + bytes(64))
    result = _triage(cut)
    lines = _lines(result)
    assert result["compressed"] is True and not result["banners"] and result["unpacked"]["bytes"] == 0
    assert lines[1] == ("image_note = AVML version 2: not decompressed (py:cramjam is not installed (requirements.in pins it): "
                        "there is no snappy reader). This stage read the file's bytes as they stand, so a banner, a flag or a lead "
                        "the compressor cut in two is not found. Convert the image (avml-convert <image> <out.lime>) and run this on the result")
    assert lines[2].startswith("kernel_banner = none (no 'Linux version' banner stands whole in the compressed bytes")
    assert "not a Linux kernel's memory" not in "\n".join(lines) and "toolkits.memory" not in "\n".join(lines)
    res = vol_triage.solver_result(result)
    assert res.status == "none" and res.notes.startswith("mem.avml: no Linux banner; AVML version 2 (snappy): the carve read compressed bytes;")
    # a banner the compressor left whole is still carved from the file's bytes, with the note beside it
    (tmp_path / "whole").mkdir()
    (tmp_path / "whole" / "t.json").write_bytes(_isf_doc(B1))
    whole = _lines(_triage(_avml2(tmp_path / "whole", bytes(64) + banner + bytes(64))))
    assert whole[1].startswith("image_note = AVML version 2: not decompressed (py:cramjam") and f"kernel_banner = {B1} x1" in whole
    assert any(l.startswith("isf = matched t.json [delivery]") for l in whole)


@pytest.mark.needs_tool("py:cramjam")
def test_intake_runs_the_opener_on_a_compressed_avml_image_under_the_guard(tmp_path):
    """The whole path as intake takes it: the engine in a child process under the audit-hook guard
    (no socket, no child process) decompresses the image into its temporary copy and reads the flag
    the compressor had cut in two."""
    chal = tmp_path / "chal"
    files = chal / "files"
    banner, flag = B1.encode() + b"\n\x00", FLAG.encode()
    img = _avml2(files, bytes(64) + banner[:9], banner[9:] + bytes(64) + flag[:9], flag[9:] + bytes(64), name="dump.dat")
    assert img.read_bytes().count(flag) == 0
    (files / "t.json").write_bytes(_isf_doc(B1))
    m = EM.load(REPO / "solvers" / "toolkits" / "vol_triage.manifest.toml")
    g = G.resolve("hook")
    jobs = IE.plan([m], "forensics", "", files, guard=g).jobs
    assert [[f.name for f in j.files] for j in jobs] == [["dump.dat"]]                # AVML by its bytes, not its name
    ctx = IE.Context(challenge_dir=chal, folder=files, out_root=chal / "recon" / "engines", profile=event.load("csctf"),
                     guard=g, root=REPO, python=sys.executable, challenge_id="b136", record=False, workdir=tmp_path / "work")
    (tmp_path / "work").mkdir()
    run = IE.run_job(jobs[0], ctx, timeout=300)        # 300 s: a wall-clock cap for one interpreter start under machine load
    out = (chal / run.output).read_text().splitlines()
    assert run.status == "ok" and run.exit_code == 0, (chal / run.errors).read_text()
    assert (run.result_status, run.flags) == ("solved", (FLAG,))
    assert out[1].startswith("image_note = AVML version 2: decompressed, 1 range(s), ") and f"kernel_banner = {B1} x1" in out
    assert "isf = matched t.json [delivery]: t.json was made for this kernel (its banner is the image's)" in out


@pytest.mark.needs_tool("py:cramjam")
def test_an_avml_image_decompressed_in_part_says_what_the_report_is_about(tmp_path, work):
    banner = B1.encode() + b"\n\x00"
    body = bytes(64) + banner[:9] + banner[9:] + bytes(64)
    part = _avml2(tmp_path / "part", bytes(64) + banner[:9], banner[9:] + bytes(64), size=8192)     # the header states more than the stream holds
    result = _triage(part)
    lines = _lines(result)
    assert (result["unpacked"]["status"], result["unpacked"]["ranges"], result["unpacked"]["bytes"]) == ("cut", 1, len(body))
    assert lines[1].startswith(f"image_note = AVML version 2: decompressed in part, 1 range(s), {len(body)} bytes "
                               f"(range 1 (0x100000..0x101fff) holds {len(body)} of its 8192 bytes: ")
    assert lines[1].endswith("); what follows is about that part only. The offsets below are offsets in the LiME file "
                             "avml-convert writes of this image, not in the file itself")
    assert f"kernel_banner = {B1} x1" in lines
    assert vol_triage.solver_result(result).notes.startswith("mem.avml: kernel 6.5.0-test-amd64; AVML version 2: decompressed in part;")
    # nothing Linux in the part that was read: that is not said to be `not Linux`
    bare = _lines(_triage(_avml2(tmp_path / "bare", bytes(200), size=8192)))
    assert bare[2] == ("kernel_banner = none (no 'Linux version' banner in the part that was decompressed: that does not say "
                       "the image is not Linux; see image_note)")
    assert "toolkits.memory" not in "\n".join(bare)
    # decompressed whole and no banner in it: then it is said, as for a LiME image
    none = _lines(_triage(_avml2(tmp_path / "none", bytes(200))))
    assert none[2].startswith("kernel_banner = none (no 'Linux version' banner in the image: not a Linux kernel's memory")


@pytest.mark.needs_tool("py:cramjam")
def test_the_decompression_has_its_share_of_the_budget_a_reserve_and_a_scratch_folder(tmp_path, work, monkeypatch, capsys):
    """The wiring of the decompression: its deadline is UNPACK_SHARE of the stage's budget on the
    stage's clock, the free space it watches is the scratch folder's, and the copy is a nameless
    temporary file there (nothing is left behind)."""
    import tempfile
    img = _avml2(tmp_path / "files", bytes(64) + B1.encode() + b"\n\x00" + bytes(64))
    seen, dirs, real, real_tmp = {}, [], memory.avml_to_lime, tempfile.TemporaryFile

    def spy(data, out, **kw):
        seen.update(kw, free_now=kw["free"]())
        return real(data, out, **kw)

    def tmp(*args, **kw):
        dirs.append(kw.get("dir"))
        return real_tmp(*args, **kw)
    monkeypatch.setattr(memory, "avml_to_lime", spy)
    monkeypatch.setattr(vol_triage.tempfile, "TemporaryFile", tmp)
    asked = []

    class Usage:
        free = 4
    monkeypatch.setattr(vol_triage.shutil, "disk_usage", lambda where: asked.append(where) or Usage())
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    clock = Clock(500.0)
    result = _triage(img, clock=clock, budget=40.0, scratch=scratch)
    assert seen["deadline"] == 500.0 + 40.0 * vol_triage.UNPACK_SHARE == 508.0 and seen["clock"] is clock
    assert (seen["free_now"], asked, dirs) == (4, [str(scratch)], [str(scratch)])
    assert result["unpacked"]["where"] == str(scratch) and result["banners"] == Counter({B1: 1}) and list(scratch.iterdir()) == []
    # the default is the system's temporary folder; --scratch reaches the stage
    dirs.clear()
    assert _triage(img)["unpacked"]["where"] == tempfile.gettempdir() and dirs == [tempfile.gettempdir()]
    dirs.clear()
    assert vol_triage.main([str(img), "--scratch", str(scratch), *NO_CLOCK]) == 0
    assert dirs == [str(scratch)] and f"kernel_banner = {B1} x1" in capsys.readouterr().out.splitlines()
    # a scratch folder that is not there: nothing is decompressed, the reason names the folder, the file's bytes are read
    lines = _lines(_triage(img, scratch=tmp_path / "absent"))
    assert lines[1].startswith(f"image_note = AVML version 2: not decompressed (the decompressed copy could not be written under "
                               f"{tmp_path / 'absent'} (FileNotFoundError")
    assert f"kernel_banner = {B1} x1" in lines                           # this banner stands whole in a literal


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
