"""The codec graph wired into the lanes (B-163): `ctf codec`, the `common.codec_graph` engine, the warmups
breadth pack, and intake's fastlane decode. Every input is synthetic; nothing runs a challenge binary or
the network.
"""
from __future__ import annotations

import base64
import json

import pytest

from ctf import cli, event, packs
from ctf.codec import FlagOracle, Graph, core
from ctf.codec import pack as P
from ctf.intake import decode as D

CSCTF = event.load("csctf")
FLAG = "CSCTF{graph_wired_in}"
PLAIN = f"well done, the flag is {FLAG} for you".encode()
CRIB = "Nice work decoding this warmup! Submit this answer: "


def rot47(b):
    return bytes(33 + (c - 33 + 47) % 94 if 33 <= c <= 126 else c for c in b)


def composed(plain=PLAIN):
    """ROT47(Base64(Base64(P))): the carried crib decoder misses it (Day 30 audit U1)."""
    return rot47(base64.b64encode(base64.b64encode(plain)))


# --------------------------------------------------------------------------- intake fastlane

def test_intake_decode_reaches_a_composed_flag_through_the_graph(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    from ctf import fastlane
    files = tmp_path / "files"
    files.mkdir()
    (files / "blob.txt").write_bytes(composed())
    assert fastlane._crib_flag(composed()) is None, "precondition: the crib decoder alone misses this chain"
    hits = D.decode_hits({"description": ""}, files, fastlane=fastlane)
    assert [(h.flag, h.chain, h.decoder, h.verdict) for h in hits] == [(FLAG, ("rot47", "b64", "b64"), D.GRAPH, D.FLAG)]
    assert "(codec graph)" in hits[0].how
    assert D.decode_hits({"description": ""}, files, fastlane=fastlane, graph=False) == []


def test_intake_judges_graph_hits_with_the_graphs_own_representation_steps(tmp_path, monkeypatch):
    # gzip is a representation step the crib decoder has no name for: a graph chain gzip+rot47 whose reading
    # is symbol noise around the flag is still a FLAG (the gzip layer confirms it), not an unconfirmed
    # loose-only decode. The crib decoder is held to "no reading" here so the graph branch is what runs.
    import gzip
    import types
    monkeypatch.setenv("CTF_EVENT", "csctf")
    from ctf import fastlane
    noise = b"9xwJ&F9!}t^!YUZ!F&SwBaXq]ke*Yg__c'FyE@h{pX#e&qvJpa~_f`" * 3
    files = tmp_path / "files"
    files.mkdir()
    (files / "blob.bin").write_bytes(gzip.compress(rot47(noise + b" CSCTF{gzip_layer} " + noise), mtime=0))
    no_crib = types.SimpleNamespace(_crib=fastlane._crib, _crib_flag=lambda data: None,
                                    _read_small_files=fastlane._read_small_files,
                                    _encoded_blobs_from_desc=fastlane._encoded_blobs_from_desc)
    hits = D.decode_hits({"description": ""}, files, fastlane=no_crib)
    assert [(h.flag, h.chain, h.verdict) for h in hits] == [("CSCTF{gzip_layer}", ("gzip", "rot47"), D.FLAG)]
    assert D.judge(hits[0].flag, hits[0].chain, hits[0].reading, D._strict_steps(fastlane._crib))[0] == D.UNCONFIRMED, \
        "precondition: under the crib decoder's names alone this chain would be loose-only"


def test_intake_decode_graph_hits_with_two_flags_are_both_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    from ctf import fastlane
    files = tmp_path / "files"
    files.mkdir()
    (files / "a.txt").write_bytes(composed(b"first CSCTF{one_value} here"))
    (files / "b.txt").write_bytes(composed(b"second CSCTF{two_value} here"))
    hits = D.decode_hits({"description": ""}, files, fastlane=fastlane)
    assert sorted(h.flag for h in hits) == ["CSCTF{one_value}", "CSCTF{two_value}"]


def test_intake_end_to_end_solves_a_composed_handout(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    from ctf import intake as I
    from ctf.platform.base import Challenge

    class Adapter:
        kind = "fake"

        def get_challenge(self, cid):
            return Challenge(id=cid, name="layers", category="crypto", points=50, description="decode it")

        def download_files(self, cid, dest):
            p = dest / "chef.txt"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(composed())
            return [p]

        def submit(self, cid, flag):
            raise AssertionError("intake never submits")

    rep = I.intake_one("7", CSCTF, adapter=Adapter(), workdir=tmp_path / "wd",
                       options=I.Options(net_guard="hook", engines=False, record=False))
    assert rep.status == "solved" and FLAG in rep.flags, (rep.flags, rep.notes)
    assert any("codec graph" in w for w in rep.flags[FLAG])


# --------------------------------------------------------------------------- engine

def _challenge(tmp_path, files: dict):
    d = tmp_path / "chal"
    (d / "files").mkdir(parents=True)
    for name, data in files.items():
        (d / "files" / name).write_bytes(data)
    return d


def test_engine_solves_a_composed_flag(tmp_path):
    import codec_graph as E
    r = E.solve(_challenge(tmp_path, {"x.txt": composed()}), CSCTF)
    assert r.status == "solved" and list(r.flags) == [FLAG]
    assert "rot47+b64+b64" in r.evidence[0].detail


def test_engine_two_flags_is_a_candidate_and_nothing_is_none(tmp_path):
    import codec_graph as E
    r = E.solve(_challenge(tmp_path, {"a.txt": composed(b"x CSCTF{aa} y"), "b.txt": composed(b"x CSCTF{bb} y")}), CSCTF)
    assert r.status == "candidate" and sorted(r.flags) == ["CSCTF{aa}", "CSCTF{bb}"]
    r = E.solve(_challenge(tmp_path / "n", {"a.txt": b"nothing encoded here at all"}), CSCTF)
    assert r.status == "none" and not r.flags


def test_engine_reads_numbered_records_with_a_slug_crib(tmp_path):
    import codec_graph as E
    text = (CRIB + "amber-cobalt-violet-42").encode()
    pieces = [text[:20], text[20:45], text[45:]]
    encs = [base64.b64encode, lambda b: b.hex().encode(), base64.b32encode]
    data = b"\n".join(b"%02d\t%s" % (i + 1, e(p)) for i, (p, e) in enumerate(zip(pieces, encs)))
    r = E.solve(_challenge(tmp_path, {"mastery.txt": data}), CSCTF, crib=CRIB, slug="1")
    assert r.status == "candidate" and list(r.flags) == ["amber-cobalt-violet-42"], r.notes
    assert "slug answer, not an event flag" in r.notes


def test_engine_names_a_missing_pack(tmp_path):
    import codec_graph as E
    r = E.solve(_challenge(tmp_path, {"a.txt": b"x"}), CSCTF, pack="nosuchpack")
    assert r.status == "blocked" and "nosuchpack" in r.notes


# --------------------------------------------------------------------------- breadth pack

def test_warmups_pack_adds_named_codecs_that_compose():
    pack = P.load("warmups")
    names = {c.name for c in pack}
    assert "warmups.b91" in names and "warmups.z85" in names
    assert not names & {c.name for c in core()}, "pack names never shadow the core set"
    assert "warmups.rot13" not in names
    # base91 is pack-only; wrapped in base64 it decodes only with the pack in the graph.
    b91 = next(c for c in pack if c.name == "warmups.b91")
    enc91 = _b91_encode(PLAIN)
    assert b91.decode(enc91) == PLAIN, "precondition: the independent base91 encoder matches the pack decoder"
    data = base64.b64encode(enc91)
    oracle = FlagOracle(CSCTF)
    assert Graph().search(data, oracle).hits == []
    r = Graph(core() + pack).search(data, oracle)
    assert r.unique == FLAG and r.hits[0].chain == ("b64", "warmups.b91") and r.hits[0].confirmed


def _b91_encode(data: bytes) -> bytes:
    """basE91 (Joachim Henke), written from the published algorithm."""
    tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
    out, b, n = [], 0, 0
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out += [tbl[v % 91], tbl[v // 91]]
    if n:
        out.append(tbl[b % 91])
        if n > 7 or b > 90:
            out.append(tbl[b // 91])
    return "".join(out).encode()


def test_pack_errors_are_named(tmp_path, monkeypatch):
    with pytest.raises(packs.PackError, match="unknown codec pack"):
        P.load("nosuchpack")
    monkeypatch.setitem(P.PACKS, "ghost", ("b163_ghost_pack", "packs/ghost.py", "STRICT"))
    with pytest.raises(packs.PackMissing, match="ghost"):
        P.load("ghost", root=tmp_path)
    (tmp_path / "packs").mkdir()
    (tmp_path / "packs" / "broken.py").write_text("raise RuntimeError('broken on import')\n")
    monkeypatch.setitem(P.PACKS, "broken", ("b163_broken_pack", "packs/broken.py", "STRICT"))
    with pytest.raises(packs.PackLoadError, match="broken on import"):
        P.load("broken", root=tmp_path)
    (tmp_path / "packs" / "empty.py").write_text("STRICT = []\n")
    monkeypatch.setitem(P.PACKS, "empty", ("b163_empty_pack", "packs/empty.py", "STRICT"))
    with pytest.raises(packs.PackLoadError, match="no decoder list"):
        P.load("empty", root=tmp_path)


def test_pack_root_is_honoured_after_the_module_is_cached(tmp_path):
    # fastlane imports crib_decode under the pack's module name; a load from another root must not hand back
    # that cached module (it once returned 60 codecs from an empty root), nor replace it.
    import sys
    P.load("warmups")
    cached = sys.modules["crib_decode"]
    with pytest.raises(packs.PackMissing, match="warmups"):
        P.load("warmups", root=tmp_path)
    own = tmp_path / "solvers" / "warmups"
    own.mkdir(parents=True)
    (own / "crib_decode.py").write_text("def d_only_here(b):\n    return None\n\nSTRICT = [d_only_here]\n")
    assert [c.name for c in P.load("warmups", root=tmp_path)] == ["warmups.only_here"]
    assert sys.modules["crib_decode"] is cached, "a pack under another root never replaces the cached module"
    assert len(P.load("warmups")) > 1


# --------------------------------------------------------------------------- intake graph budget

def _no_crib_fastlane(fastlane, blobs):
    import types
    return types.SimpleNamespace(_crib=fastlane._crib, _crib_flag=lambda data: None,
                                 _read_small_files=lambda files_dir: list(blobs),
                                 _encoded_blobs_from_desc=lambda text: [])


def test_the_intake_graph_budget_stops_later_blobs(monkeypatch, tmp_path):
    # Six blobs the crib decoder misses, each graph search taking 1.0 s of a fake clock: with GRAPH_BUDGET 4 s
    # the graph is asked for the first four (t = 0, 1, 2, 3), every one of them under the intake deadline.
    # The fifth comes up at exactly t = GRAPH_BUDGET: a spent budget means no graph, so it and the sixth are
    # skipped (a graph started at its deadline would stop at its first step anyway).
    import types
    from ctf import fastlane
    clock = [100.0]
    monkeypatch.setattr(D, "time", types.SimpleNamespace(monotonic=lambda: clock[0]))
    asked = []

    def slow_graph(data, deadline):
        asked.append((data, deadline))
        clock[0] += 1.0
        return []
    monkeypatch.setattr(D, "_graph_hits", slow_graph)
    blobs = [(f"f{i}.txt", b"blob %d" % i) for i in range(6)]
    assert D.GRAPH_BUDGET == 4.0
    D.decode_hits({"description": ""}, tmp_path, fastlane=_no_crib_fastlane(fastlane, blobs))
    assert [d for d, _ in asked] == [b"blob 0", b"blob 1", b"blob 2", b"blob 3"]
    assert {dl for _, dl in asked} == {100.0 + D.GRAPH_BUDGET}


def test_one_blob_graph_search_ends_at_the_intake_deadline(monkeypatch):
    # The per-blob budget (1 s) never runs past what is left of the intake's: with the intake deadline
    # already gone the graph stops before its first step, though the blob is one base64 layer from the flag.
    import time
    monkeypatch.setenv("CTF_EVENT", "csctf")
    data = base64.b64encode(PLAIN)
    assert [f for f, _, _ in D._graph_hits(data, time.monotonic() + 30)] == [FLAG]
    assert D._graph_hits(data, time.monotonic() - 1) == []

# --------------------------------------------------------------------------- CLI

def _run(argv, capsys):
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_decodes_a_blob_with_the_event_format(tmp_path, capsys):
    f = tmp_path / "blob.txt"
    f.write_bytes(composed())
    code, out, _ = _run(["codec", str(f), "--event", "csctf"], capsys)
    assert code == 0 and FLAG in out and "rot47+b64+b64" in out
    code, out, _ = _run(["codec", str(f), "--event", "csctf", "--json"], capsys)
    data = json.loads(out)
    assert code == 0 and data[0]["answers"] == [FLAG]


def test_cli_exit_one_for_nothing_and_for_ambiguity(tmp_path, capsys):
    f = tmp_path / "plain.txt"
    f.write_bytes(b"just words, nothing encoded")
    code, out, _ = _run(["codec", str(f), "--event", "csctf"], capsys)
    assert code == 1 and "nothing reached" in out
    g = tmp_path / "two.txt"
    g.write_bytes(base64.b64encode(b"CSCTF{one} and CSCTF{two}"))
    code, out, _ = _run(["codec", str(g), "--event", "csctf"], capsys)
    assert code == 1 and "AMBIGUOUS" in out


def test_cli_records_and_consensus(tmp_path, capsys):
    text = (CRIB + "quiet-harbor-maple-17").encode()
    f = tmp_path / "m.txt"
    f.write_bytes(b"01\t%s\n02\t%s\n" % (base64.b64encode(text[:30]), text[30:].hex().encode()))
    code, out, _ = _run(["codec", str(f), "--records", "--crib", CRIB, "--slug"], capsys)
    assert code == 0 and "quiet-harbor-maple-17" in out
    code, out, _ = _run(["codec", str(f), str(f), str(f), "--consensus", "--crib", CRIB, "--slug"], capsys)
    assert code == 0 and out.count("quiet-harbor-maple-17") == 3


def test_cli_usage_errors_exit_two(tmp_path, capsys):
    f = tmp_path / "blob.txt"
    f.write_bytes(b"abc")
    assert _run(["codec", str(tmp_path / "missing.txt"), "--event", "csctf"], capsys)[0] == 2
    code, _, err = _run(["codec", str(f), "--records", "--crib", "x", "--slug"], capsys)
    assert code == 2 and "numbered record" in err
    code, _, err = _run(["codec", str(f), "--pack", "nosuchpack", "--event", "csctf"], capsys)
    assert code == 2 and "nosuchpack" in err
    code, _, err = _run(["codec", str(f), "--min-n", "0", "--crib", "x"], capsys)
    assert code == 2
