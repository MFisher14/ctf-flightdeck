"""B-001 hand-merge hm-13: the warm worker pools carried from Huntress speedrun/solvers.

speedrun/solvers/binary_par.py, script_pool.py, script_worker.py. Fixtures are built here: a synthetic
WinZip AES (AE-2) zip and a stored zip of small text specimens. The speed reader used by these tests is
`fast_read` below, plugged in through $CTF_SPEED_SCRIPT_FAST exactly as a real one would be.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib
import os
import struct
import zlib
from pathlib import Path

import pytest

from speedrun import common
from speedrun.solvers import binary_par, script_pool, script_worker

ROOT = Path(__file__).resolve().parent.parent
PLUG = "tests.test_speedrun_pools_hm13:fast_read"


# ---- the plug-in speed reader the tests use ---------------------------------------------------------

def fast_read(member, text, qs):
    """Answers every question of a specimen whose text starts 'ANSWER=<v>' with <v>; None otherwise."""
    if not text.startswith("ANSWER="):
        return None
    value = text.split("=", 1)[1].strip()
    return {q["qid"]: f"{value}:{q['qid']}" for q in qs}


def partial_read(member, text, qs):
    """Answers only the first question (not whole)."""
    return {qs[0]["qid"]: "x"} if qs else {}


# ---- zip builders ---------------------------------------------------------------------------------

def _zip(entries):
    """entries: [(name, method, flags, crc, csize, size, extra, body)] -> zip bytes."""
    out, cd = bytearray(), bytearray()
    for name, method, flags, crc, csize, size, extra, body in entries:
        n = name.encode()
        off = len(out)
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 51, flags, method, 0, 0x21, crc, csize, size,
                           len(n), len(extra)) + n + extra + body
        cd += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 51, 51, flags, method, 0, 0x21, crc, csize,
                          size, len(n), len(extra), 0, 0, 0, 0, off) + n + extra
    cd_off = len(out)
    out += cd
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(cd), cd_off, 0)
    return bytes(out)


def stored_zip(members: dict) -> bytes:
    return _zip([(k, 0, 0, zlib.crc32(v), len(v), len(v), b"", v) for k, v in members.items()])


def aes_zip(name: str, plain: bytes, password: bytes, strength: int = 3) -> bytes:
    """One AE-2 member, deflated, as WinZip writes it."""
    if common._AES is None:
        pytest.fail("pycryptodome(x) is required by speedrun.common and is missing from .venv")
    klen = {1: 16, 2: 24, 3: 32}[strength]
    salt = hashlib.sha256(name.encode()).digest()[:klen // 2]
    dk = hashlib.pbkdf2_hmac("sha1", password, salt, 1000, 2 * klen + 2)
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    comp = c.compress(plain) + c.flush()
    ctr = common._Counter.new(128, initial_value=1, little_endian=True)
    enc = common._AES.new(dk[:klen], common._AES.MODE_CTR, counter=ctr).encrypt(comp)
    mac = hmac.new(dk[klen:2 * klen], enc, hashlib.sha1).digest()[:10]
    body = salt + dk[2 * klen:] + enc + mac
    extra = struct.pack("<HHH2sBH", 0x9901, 7, 2, b"AE", strength, 8)
    return _zip([(name, 99, 1, 0, len(body), len(plain), extra, body)])


PLAIN = b"".join(b"line %d of a specimen body\n" % i for i in range(400))


# ---- script_worker ---------------------------------------------------------------------------------

def test_fast_member_reads_aes_member_exactly():
    z = common.open_zip(aes_zip("a.ps1", PLAIN, common.PASSWORD))
    assert z.entry("a.ps1").aes == 3
    assert script_worker.fast_member(z, "a.ps1") == PLAIN


def test_fast_member_wrong_key_goes_the_full_way_not_garbage():
    # Opened with a password that is not the zip's: the half-derivation yields garbage, which must be
    # detected and the member read the full way (which tries the stored passwords, PASSWORD among them).
    data = aes_zip("b.js", PLAIN, common.PASSWORD)
    z = common.open_zip(data, password=b"definitely-not-it")
    assert script_worker.fast_member(z, "b.js") == PLAIN


def test_load_fast_reader_specs():
    assert script_worker.load_fast_reader("") is None
    assert script_worker.load_fast_reader(None) is None
    got = script_worker.load_fast_reader(PLUG)
    assert got.__name__ == "fast_read" and got("m", "ANSWER=z", [{"qid": "q"}]) == {"q": "z:q"}
    for bad in ("no_colon", "json:", ":dumps", "no_such_module_hm13:read", "json:no_such_attr", "json:__doc__"):
        with pytest.raises(script_worker.FastReaderError) as ei:
            script_worker.load_fast_reader(bad)
        assert script_worker.FAST_ENV in str(ei.value)


def test_bad_fast_env_fails_loudly_on_first_read(monkeypatch):
    monkeypatch.setenv("CTF_SPEED_SCRIPT_FAST", "no_such_module_hm13:read")
    monkeypatch.setattr(script_worker, "FAST", script_worker._UNSET)
    qs = [{"answer_id": "a", "qid": "a", "text": "", "accepted_values": None}]
    with pytest.raises(script_worker.FastReaderError) as ei:
        script_worker.read_fast("x.ps1", b"ANSWER=1", qs)
    assert "no_such_module_hm13" in str(ei.value)
    monkeypatch.delenv("CTF_SPEED_SCRIPT_FAST")
    monkeypatch.setattr(script_worker, "FAST", script_worker._UNSET)
    assert script_worker.fast_reader() is None


def test_read_fast_contract(monkeypatch):
    qs = [{"answer_id": "set1.a", "qid": "a", "text": "", "accepted_values": None},
          {"answer_id": "set1.b", "qid": "b", "text": "", "accepted_values": None}]
    monkeypatch.setattr(script_worker, "FAST", None)
    assert script_worker.read_fast("x.ps1", b"ANSWER=1", qs) is None          # no reader: shipped solver
    monkeypatch.setattr(script_worker, "FAST", fast_read)
    assert script_worker.read_fast("x.ps1", b"\xef\xbb\xbfANSWER=7", qs) == {"set1.a": "7:a", "set1.b": "7:b"}
    assert script_worker.read_fast("x.ps1", b"other", qs) is None
    monkeypatch.setattr(script_worker, "FAST", partial_read)
    assert script_worker.read_fast("x.ps1", b"ANSWER=1", qs) is None          # not whole: shipped solver
    monkeypatch.setattr(script_worker, "FAST", fast_read)
    monkeypatch.setattr(script_worker, "_FORCE", {"ps1"})
    assert script_worker.read_fast("x.ps1", b"ANSWER=1", qs) is None
    assert script_worker.read_fast("x.js", b"ANSWER=1", qs) == {"set1.a": "1:a", "set1.b": "1:b"}


def test_run_lean_answers_and_lists_the_rest(monkeypatch):
    monkeypatch.setattr(script_worker, "FAST", fast_read)
    data = stored_zip({"s1.ps1": b"ANSWER=one", "s2.js": b"unknown", "s3.py": b"ANSWER=three"})
    tasks = [(None, "s1.ps1", [("set0.q1", "q1", None, None)]),
             (None, "s2.js", [("set0.q2", "q2", None, None)]),
             (None, "s3.py", [("set0.q3", None, None, None)])]
    got = script_worker.run_lean(data, tasks)
    assert got == {"set0.q1": "one:q1", "set0.q3": "three:q3", "__need__": [1]}


def test_shipped_solver_missing_is_named(monkeypatch, tmp_path):
    monkeypatch.setattr(script_worker, "ROOT", tmp_path)
    monkeypatch.setattr(script_worker, "_SHIPPED", None)
    with pytest.raises(script_worker.ShippedSolverMissing) as ei:
        script_worker.shipped()
    assert "analyze.py" in str(ei.value)


# ---- script_pool -----------------------------------------------------------------------------------

def _attempt(members):
    qs = [{"id": f"set0.{m}-x", "artifact": f"outer.zip -> {m}", "question": "q?"} for m in members]
    return {"questions": qs, "answer_ids": [q["id"] for q in qs]}


def test_group_shapes_and_refusals():
    att = _attempt(["a.ps1", "b.js", "a.ps1"])
    got = script_pool._group(att, {"outer.zip"})
    assert [(c, m, [x[0] for x in lean]) for c, m, lean, _raw in got] == [
        ("outer.zip", "a.ps1", ["set0.a.ps1-x", "set0.a.ps1-x"]), ("outer.zip", "b.js", ["set0.b.js-x"])]
    assert script_pool._group(att, {"a.ps1", "b.js"})[0][0] is None      # member at the top level
    assert script_pool._group(att, {"other.zip"}) is None                  # not in this delivery
    bad = {"questions": [{"id": "x", "artifact": "delivery 2: outer.zip -> a.ps1"}], "answer_ids": ["x"]}
    assert script_pool._group(bad, {"outer.zip"}) is None


def test_split_is_contiguous_and_complete():
    tasks = [(None, f"m{i}.{'py' if i % 3 else 'sh'}", [], []) for i in range(97)]
    for n in (1, 2, 5, 10):
        shares = script_pool._split(tasks, n)
        assert 1 <= len(shares) <= n
        assert [t for s in shares for t in s] == tasks
    sizes = [len(s) for s in script_pool._split(tasks, 4)]
    assert max(sizes) - min(sizes) <= 6, sizes


def test_solve_in_process_returns_plain_dict(monkeypatch):
    monkeypatch.setattr(script_worker, "FAST", fast_read)
    script_pool.stop()
    monkeypatch.setattr(script_pool, "_ready", __import__("threading").Event())   # no workers
    data = stored_zip({"a.ps1": b"ANSWER=A", "b.js": b"ANSWER=B"})
    got = script_pool.solve(_attempt(["a.ps1", "b.js"]), [_delivery("outer.zip", data)], {})
    assert type(got) is dict
    assert got == {"set0.a.ps1-x": "A:a.ps1-x", "set0.b.js-x": "B:b.js-x"}
    assert script_pool.solve(_attempt(["a.ps1"]), [_delivery("x", b"not a zip")], {}) is None


def _delivery(filename, data):
    return common.Delivery(0, filename, data)


def test_pool_workers_answer_over_pipes(monkeypatch):
    """Two real worker processes (python -I script_worker.py) answer a try; one specimen goes to the
    shipped solver round ("full") because the speed reader does not answer it."""
    monkeypatch.setenv("CTF_SPEED_SCRIPT_FAST", PLUG)
    script_pool.stop()
    monkeypatch.setattr(script_pool, "_ready", __import__("threading").Event())
    members = {f"m{i:02d}.ps1": b"ANSWER=v%d" % i for i in range(12)}
    members["odd.sh"] = b"echo nothing to see"
    data = stored_zip(members)
    try:
        script_pool.start(2)
        script_pool.wait_ready(120)
        assert len(script_pool.alive()) == 2, "workers did not boot"
        got = script_pool.solve(_attempt(list(members)), [_delivery("outer.zip", data)], {})
        assert len(script_pool.LAST) == 2 and all(x and x[1] > 0 for x in script_pool.LAST)
        for i in range(12):
            assert got[f"set0.m{i:02d}.ps1-x"] == f"v{i}:m{i:02d}.ps1-x"
        assert type(got) is dict
        assert all(not k.startswith("__") for k in got)
    finally:
        script_pool.stop()


# ---- binary_par -----------------------------------------------------------------------------------

def test_binary_par_env_and_prefix_match(monkeypatch):
    monkeypatch.setenv("CTF_SPEED_BINARY_WORKERS", "3")
    mod = importlib.reload(binary_par)
    try:
        assert mod._WORKERS == 3
        r = mod._mine("d12")
        assert r.match("d12.bin") and r.match("D12_cfg.dat") and not r.match("d123.bin")
    finally:
        monkeypatch.delenv("CTF_SPEED_BINARY_WORKERS")
        importlib.reload(binary_par)


def test_binary_par_missing_solver_is_named(tmp_path):
    with pytest.raises(binary_par.ShippedSolverMissing) as ei:
        binary_par.solver_path(tmp_path)
    assert "evidence.py" in str(ei.value)
    assert binary_par.solver_path() == ROOT / "solvers" / "binary" / "evidence.py"


def test_binary_par_loads_the_shipped_solver():
    ev = binary_par.load_shipped()
    for name in ("solve_prefix", "static_reader", "module_for", "sendable"):
        assert callable(getattr(ev, name)), name
    import judged_forms  # noqa: F401 - plan_tasks imports it without a fallback


def test_pool_worker_with_bad_fast_reader_never_reports_ready(monkeypatch):
    monkeypatch.setenv("CTF_SPEED_SCRIPT_FAST", "no_such_module_hm13:read")
    script_pool.stop()
    monkeypatch.setattr(script_pool, "_ready", __import__("threading").Event())
    try:
        script_pool.start(1)
        script_pool.wait_ready(60)
        assert script_pool.alive() == []
    finally:
        script_pool.stop()
