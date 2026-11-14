"""B-135: the ransomware keystream seed-form search (solvers/toolkits/ransom_keystream.py) and the glibc
srand/rand model it adds to solvers/common/modern_crypto.py.

The row it closes, CSCTF 9073 (Ghost in the Historian), is rebuilt synthetically: an ext volume whose
`*.enc` files are XORed with an xorshift32 keystream seeded ((time ^ pid) * 0x9e3779b1) mod 2^32, one
4-byte word per block, the state shared across the files in alphasort order; the time is the files'
mtime, the PID is in a log line, and the deleted encryptor sits in free blocks. Every generator model is
pinned to published or real-libc vectors, not to itself.
"""
from __future__ import annotations

import datetime as dt
import io
import json
import os
import random
import subprocess
import sys
import zipfile
from pathlib import Path

import numpy as np
import pytest

import archive_expand
import ext_fixture as ef
import ransom_keystream as rk
from _shadowed import common_module
from ctf import event, flagfmt, sweep

REPO = Path(__file__).resolve().parents[1]
M32 = 0xFFFFFFFF


def _profile(prefixes=("CSCTF",)):
    return event.parse({
        "slug": "b135-test", "name": "ransom keystream test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "manual"},
        "flag": {"prefixes": list(prefixes)},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
    }, src="<test>")


PROFILE = _profile()
mc = common_module("modern_crypto")                 # solvers/common, not the toolkit face
FF = flagfmt.for_profile(PROFILE)

# glibc 2.x srand(seed); rand() x5, read from a real glibc in a --network none container while building.
GLIBC = {0: [1804289383, 846930886, 1681692777, 1714636915, 1957747793],
         1: [1804289383, 846930886, 1681692777, 1714636915, 1957747793],
         42: [71876166, 708592740, 1483128881, 907283241, 442951012],
         0x80000000: [1336741213, 1210407648, 1447044896, 337392383, 82502902],
         0xDEADBEEF: [352217057, 918588210, 499345174, 513054021, 248820349],
         0xFFFFFFFF: [254925627, 1205188300, 366127624, 1401405153, 76053476],
         0x7FFFFFFF: [1065668062, 2142264300, 1066566375, 1064012770, 2141034222],
         0x651A4351: [2038052065, 1870908963, 1786315563, 1732266406, 1513974156]}


# ----------------------------------------------------------------------------- generator models
@pytest.mark.parametrize("seed", sorted(GLIBC))
def test_glibc_rand_matches_real_glibc_including_negative_int32_seeds(seed):
    assert mc.glibc_rand_outputs(seed, 5) == GLIBC[seed]
    batch = rk._outputs_batch(np, rk.Gen("glibc", "word"), np.array([seed], dtype=np.uint64), 5)
    assert [int(v) for v in batch[0]] == GLIBC[seed]
    st = rk.Stream(rk.Gen("glibc", "word"), seed)
    assert [st._next() for _ in range(5)] == GLIBC[seed]


def test_glibc_seed_recover_and_the_cli_operation(tmp_path):
    outs = mc.glibc_rand_outputs(31337, 4)
    got = mc.glibc_seed_recover(outs, 31000, 32000)
    assert got["seed"] == 31337 and got["next"] == mc.glibc_rand_outputs(31337, 5)[4]
    assert mc.glibc_seed_recover(outs, 0, 1000) is None
    assert mc.glibc_seed_recover(outs, 0, 2_000_000) is None           # over MAX_SEED_CANDIDATES
    j = tmp_path / "in.json"
    j.write_text(json.dumps({"outputs": outs, "seed_start": 31300, "seed_stop": 31400}))
    p = subprocess.run([sys.executable, str(REPO / "solvers/toolkits/prng_recovery.py"), "glibc-seed", str(j)],
                       capture_output=True, text=True, check=True)
    assert json.loads(p.stdout)["candidate"]["seed"] == 31337


def test_reference_vectors_of_the_other_generators():
    # C++11 [rand.predef]: the 10000th output of a default-constructed std::mt19937 (seed 5489).
    st = rk.Stream(rk.Gen("mt19937", "word"), 5489)
    first = st._next()
    for _ in range(9998):
        st._next()
    assert first == 3499211612 and st._next() == 4123659995
    # Marsaglia, "Xorshift RNGs" (2003): xorshift32 13/17/5 from y = 2463534242.
    assert rk.Stream(rk.Gen("xorshift32", "word", (13, 17, 5)), 2463534242)._next() == 723471715
    # MSVC srand(1): rand() = 41, 18467, 6334, 26500, 19169.
    st = rk.Stream(rk.Gen("msvcrt", "byte"), 1)
    assert [st._next() for _ in range(5)] == [41, 18467, 6334, 26500, 19169]


@pytest.mark.parametrize("gen", rk.default_gens(), ids=lambda g: g.name)
def test_batch_keystream_equals_the_per_seed_stream(gen):
    seeds = np.array([1, 0x12345678, 0x9E3779B1, 0xFFFFFFFF, 1759378385], dtype=np.uint64)
    batch = rk.keystream_batch(np, gen, seeds, 23)
    for row, sd in zip(batch, seeds):
        assert row.tobytes() == rk.Stream(gen, int(sd)).take(23), gen.name


def test_a_stream_takes_whole_outputs_per_file():
    g = rk.Gen("xorshift32", "word", (13, 17, 5))
    whole = rk.Stream(g, 99).take(12)
    st = rk.Stream(g, 99)
    a, b = st.take(5), st.take(4)                  # 5 bytes use two words; the next file starts at word 3
    assert a == whole[:5] and b == whole[8:12]


# ----------------------------------------------------------------------------- forms, hints, parsing
def test_seed_table_forms_and_provenance():
    t, pid = 1759378385, 2761400
    seeds, prov = rk.seed_table(np, [rk.TimeCand(t, "mtime x")], [pid], [0x9E3779B1])
    want = ((t ^ pid) * 0x9E3779B1) & M32
    where = [int(s) for s in seeds].index(want)
    p = prov[where]
    assert (p.form, p.t, p.pid, p.source) == ("(time^pid)*0x9e3779b1", t, pid, "mtime x")
    vals = {int(s) for s in seeds}
    assert {t, pid, t ^ pid, (t + pid) & M32, t ^ (pid << 16) & M32, (t * 0x9E3779B1) & M32,
            ((t * 0x9E3779B1) & M32) ^ pid, ((t + pid) * 0x9E3779B1) & M32,
            t ^ ((pid * 0x9E3779B1) & M32)} <= vals
    seeds2, _ = rk.seed_table(np, [rk.TimeCand(t, "x")], [pid], [], pid_only=False)
    assert pid not in {int(s) for s in seeds2}


SHIFTS = bytes.fromhex("c1e00d") + bytes.fromhex("31c1") + bytes.fromhex("c1e811") + bytes.fromhex("c1e005")


def test_hints_from_elf_read_imul_constants_and_shift_triples():
    code = bytes.fromhex("69c0b179379e") + bytes.fromhex("4869c9f591452500") + SHIFTS
    h = rk.hints_from_elf(ef.elf(code), "x")
    assert 0x9E3779B1 in h.multipliers
    assert 0x254591F5 in h.multipliers and (13, 17, 5) in h.triples32
    assert rk.hints_from_elf(b"MZ" + code).multipliers == set()       # only an ELF is read
    even = rk.hints_from_elf(ef.elf(bytes.fromhex("69c000000100")))  # 0x10000: too few bits, even
    assert even.multipliers == set()


def test_hints_from_text_read_pseudocode():
    h = rk.hints_from_text("uVar1 = (local_10 ^ pid) * 0x2545f491;\n x = x ^ x << 7; x = x ^ x >> 9;\n"
                           " x = x ^ x << 8;\n", "main.c")
    assert 0x2545F491 in h.multipliers and (7, 9, 8) in h.triples32 and h.sources == ["main.c"]


def test_pid_and_timestamp_parsing():
    text = ("2026-10-02 04:12 historian[811]: poll ok\n"
            "2026-10-02 04:13 historian_enc[2761400]: starting encryption sweep\n"
            "2026-10-02T06:13:05+02:00 pid=4242 done\n")
    assert rk.pids_from_text(text) == [811, 2761400, 4242]
    st = rk.stamps_from_text(text, "h.log")
    base = 1790914380                                            # 2026-10-02 04:13:00 UTC
    assert (base - 60, 60, False, "h.log:1", True) in st
    assert (base, 60, False, "h.log:2", True) in st
    assert (base + 5, 1, True, "h.log:3", True) in st              # +02:00 converted to UTC


def test_plausibility_by_the_original_name():
    assert rk.Cipher("a.cfg.enc", "a", b"").expect == "text"
    assert rk.Cipher("p.png.locked", "a", b"").expect == b"\x89PNG\r\n\x1a\n"
    assert rk.Cipher("blob.dat.enc", "a", b"").expect == "unknown"
    assert rk.plausible(b"KEY=value\n" * 20, "text") is True
    assert rk.plausible(bytes(range(256)), "text") is False
    assert rk.plausible(b"\x89PNG\r\n\x1a\nxx", b"\x89PNG\r\n\x1a\n") is True
    assert rk.plausible(b"\x00" * 64, b"%PDF-") is False
    assert rk.plausible(bytes(range(200)), "unknown") is None


# ----------------------------------------------------------------------------- end to end
T0 = 1790914385                    # 2026-10-02 04:13:05 UTC
PID = 2761400
FLAG = "CSCTF{xorshift_ghost_synthetic_b135_0f1e2d}"
PLAIN = {
    "grid_topology.cfg": (b"# substation historian\nNODE=HIST01\nSAFETY_INTERLOCK_TOKEN=" + FLAG.encode()
                          + b"\nFEEDERS=12\n" + b"LINE=ok\n" * 40),
    "historian_cache.dat": bytes(random.Random(7).randrange(256) for _ in range(777)),
    "node_status.json": json.dumps({"nodes": [{"id": i, "ok": True} for i in range(30)]}).encode(),
}


def encrypt(plain: dict, gen: rk.Gen, seed: int, *, shared=True, seeds_per_file=None) -> dict:
    out = {}
    st = rk.Stream(gen, seed)
    for name in sorted(plain, key=lambda n: (n + ".enc").encode()):
        if not shared:
            st = rk.Stream(gen, seeds_per_file[name])
        data = plain[name]
        out[name + ".enc"] = bytes(a ^ b for a, b in zip(data, st.take(len(data))))
    return out


def encryptor_elf(mult: int = 0x9E3779B1) -> bytes:
    code = b"\x55\x89\xf8\x31\xf0" + b"\x69\xc0" + mult.to_bytes(4, "little") + SHIFTS + b"\xc3"
    return ef.elf(code, extra=b"\x90" * 600, pad_to=2600)


def historian_image(enc: dict, *, mtime=T0, elf: bytes | None = None, log_line=None) -> bytes:
    img = ef.Ext(blocks=1024, extents=True)
    var = img.mkdir("var")
    hist = img.mkdir("historian", parent=var)
    logs = img.mkdir("log", parent=var)
    for name, data in enc.items():
        img.add(name, data, parent=hist, mtime=mtime)
    line = log_line or f"2026-10-02 04:13 historian_enc[{PID}]: starting encryption sweep\n"
    img.add("historian.log", ("2026-10-02 03:58 historian[811]: poll ok\n" + line).encode(), parent=logs,
            mtime=mtime + 40)
    img.orphan(mode=0o100755, mtime=mtime - 3)                 # the deleted encryptor's inode
    if elf:
        img.free_write(elf)
    return img.build()


def pulled(tmp_path, files: dict, cid=9073):
    ch = tmp_path / "wd" / f"{cid}-x"
    (ch / "files").mkdir(parents=True)
    (ch / "challenge.json").write_text(json.dumps({"id": cid, "name": "x", "category": "Forensics",
                                                   "description": "recover the token: CSCTF{...}"}))
    for name, data in files.items():
        (ch / "files" / name).write_bytes(data)
    return ch


def zipped(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in members.items():
            z.writestr(n, d)
    return buf.getvalue()


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    monkeypatch.setattr(archive_expand.pw, "candidates", lambda: [b"infected"])


XS32 = rk.Gen("xorshift32", "word", (13, 17, 5))


def test_ghost_in_the_historian_shape_end_to_end_after_the_pull_sweep(tmp_path):
    seed = ((T0 ^ PID) * 0x9E3779B1) & M32
    enc = encrypt(PLAIN, XS32, seed)
    raw = historian_image(enc, elf=encryptor_elf())
    ch = pulled(tmp_path, {"ghost.zip": zipped({"evidence-flat.vmdk": raw, "brief.txt": b"timeline brief"})})
    rep = sweep.sweep(ch, PROFILE)
    assert FLAG not in json.dumps(rep.result.to_dict())               # the sweep alone cannot read it
    r = rk.solve(ch, PROFILE, cpu_seconds=600)
    assert r.status == "solved" and r.flags == (FLAG,)
    assert "form=(time^pid)*0x9e3779b1" in r.notes and f"pid={PID}" in r.notes
    assert "prng=xorshift32(13/17/5)-word" in r.notes and "layout=shared:alphasort" in r.notes
    assert "time from mtime" in r.notes                               # the exact tier, from ext-listing.json
    out = ch / "recon" / "ransom_keystream"
    assert (out / "grid_topology.cfg").read_bytes() == PLAIN["grid_topology.cfg"]
    assert (out / "historian_cache.dat").read_bytes() == PLAIN["historian_cache.dat"]
    assert (out / "node_status.json").read_bytes() == PLAIN["node_status.json"]
    seedrec = json.loads((out / "seed.json").read_text())
    assert seedrec["seed"] == seed and seedrec["time"] == T0 and seedrec["pid"] == PID
    assert any(e.path == "recon/ransom_keystream/grid_topology.cfg" for e in r.evidence)


def _bare(tmp_path, enc: dict, log: str) -> Path:
    ch = tmp_path / "drop"
    (ch / "files").mkdir(parents=True)
    for n, d in enc.items():
        (ch / "files" / n).write_bytes(d)
    (ch / "files" / "historian.log").write_text(log)
    return ch


def test_log_minute_stamp_alone_finds_the_second(tmp_path):
    seed = ((T0 ^ PID) * 0x9E3779B1) & M32
    ch = _bare(tmp_path, encrypt(PLAIN, XS32, seed), f"2026-10-02 04:13 historian_enc[{PID}]: start\n")
    r = rk.solve(ch, PROFILE, cpu_seconds=600, generators="xorshift32-word")
    assert r.status == "solved" and r.flags == (FLAG,)
    assert "time from files/historian.log:1" in r.notes and "UTC" not in r.notes.split("prng=")[0]


def test_a_local_time_log_is_found_only_by_the_hour_shift_tier(tmp_path):
    seed = ((T0 ^ PID) * 0x9E3779B1) & M32
    enc = encrypt(PLAIN, XS32, seed)
    ch = _bare(tmp_path, enc, f"2026-10-02 00:13 historian_enc[{PID}]: start\n")     # EDT, UTC-4
    r = rk.solve(ch, PROFILE, cpu_seconds=600, generators="xorshift32-word")
    assert r.status == "solved" and "read as UTC-4" in r.notes


def test_the_multiplier_comes_from_the_carved_encryptor_when_no_table_constant_fits(tmp_path):
    odd = 0x2545F491                                   # not in MULTIPLIERS
    assert odd not in rk.MULTIPLIERS
    seed = ((T0 ^ PID) * odd) & M32
    enc = encrypt(PLAIN, XS32, seed)
    no_elf = pulled(tmp_path / "a", {"img.raw": historian_image(enc)})
    sweep.sweep(no_elf, PROFILE)
    r0 = rk.solve(no_elf, PROFILE, cpu_seconds=600, generators="xorshift32-word")
    assert r0.status == "none" and not r0.flags
    with_elf = pulled(tmp_path / "b", {"img.raw": historian_image(enc, elf=encryptor_elf(odd))})
    sweep.sweep(with_elf, PROFILE)
    carved = list((with_elf / "unpacked").rglob("ext-unallocated/*.elf"))
    assert len(carved) == 1
    r1 = rk.solve(with_elf, PROFILE, cpu_seconds=600, generators="xorshift32-word")
    assert r1.status == "solved" and r1.flags == (FLAG,) and f"(time^pid)*{odd:#x}" in r1.notes
    assert "img.raw.unpacked/ext-unallocated/blk" in r1.notes      # the hint source is named


def test_shift_triple_from_pseudocode_selects_the_xorshift_variant(tmp_path):
    g = rk.Gen("xorshift32", "word", (7, 9, 8))
    seed = (T0 * 0x9E3779B9) & M32
    ch = _bare(tmp_path, encrypt(PLAIN, g, seed), "2026-10-02 04:13:05Z encryptor started\n")
    r0 = rk.solve(ch, PROFILE, cpu_seconds=600, generators="xorshift32")
    assert r0.status == "none"
    (ch / "recon" / "decompile" / "enc").mkdir(parents=True)
    (ch / "recon" / "decompile" / "enc" / "main.c").write_text("x ^= x << 7;\nx ^= x >> 9;\nx ^= x << 8;\n")
    r1 = rk.solve(ch, PROFILE, cpu_seconds=600, generators="xorshift32")
    assert r1.status == "solved" and "prng=xorshift32(7/9/8)-word" in r1.notes


def test_glibc_rand_per_file_reseed_from_each_files_own_mtime(tmp_path):
    g = rk.Gen("glibc", "byte")
    names = sorted(PLAIN)
    times = {n: T0 + 7 * i for i, n in enumerate(names)}
    enc = encrypt(PLAIN, g, 0, shared=False, seeds_per_file={n: times[n] for n in names})
    img = ef.Ext(blocks=1024)
    d = img.mkdir("data")
    for n in names:
        img.add(n + ".enc", enc[n + ".enc"], parent=d, mtime=times[n])
    ch = pulled(tmp_path, {"disk.img": img.build()})
    sweep.sweep(ch, PROFILE)
    r = rk.solve(ch, PROFILE, cpu_seconds=600, generators="glibc-byte")
    assert r.status == "solved" and r.flags == (FLAG,)
    assert "layout=single" in r.notes and "form=time " in r.notes


def test_shared_stream_in_mtime_order(tmp_path):
    # the encryptor walked the files oldest first, which is not their alphabetical order
    names = ["node_status.json", "grid_topology.cfg", "historian_cache.dat"]
    times = {n: T0 + i for i, n in enumerate(names)}
    seed = (T0 ^ PID) & M32
    st, enc = rk.Stream(XS32, seed), {}
    for n in names:
        enc[n + ".enc"] = bytes(a ^ b for a, b in zip(PLAIN[n], st.take(len(PLAIN[n]))))
    img = ef.Ext(blocks=1024)
    d = img.mkdir("data")
    for n in sorted(names):
        img.add(n + ".enc", enc[n + ".enc"], parent=d, mtime=times[n])
    img.add("enc.log", f"locker[{PID}] started\n".encode(), parent=d)
    ch = pulled(tmp_path, {"disk.img": img.build()})
    sweep.sweep(ch, PROFILE)
    r = rk.solve(ch, PROFILE, cpu_seconds=600, generators="xorshift32-word")
    assert r.status == "solved" and "layout=shared:mtime" in r.notes
    assert "files=node_status.json.enc,grid_topology.cfg.enc,historian_cache.dat.enc" in r.notes


def test_zip_member_utc_mtime_is_an_exact_time(tmp_path):
    seed = (T0 ^ PID) & M32
    g = rk.Gen("msvcrt", "byte")
    enc = encrypt(PLAIN, g, seed)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, d in enc.items():
            zi = zipfile.ZipInfo(n, date_time=(2020, 1, 1, 0, 0, 0))
            zi.extra = b"UT\x05\x00\x01" + T0.to_bytes(4, "little")
            z.writestr(zi, d)
        z.writestr("ops.log", f"historian_enc[{PID}] done\n")
    ch = pulled(tmp_path, {"handout.zip": buf.getvalue()})
    sweep.sweep(ch, PROFILE)
    r = rk.solve(ch, PROFILE, cpu_seconds=600, generators="msvcrt")
    assert r.status == "solved" and "zip UT mtime" in r.notes and "form=time^pid" in r.notes


def test_two_distinct_flags_make_a_candidate(tmp_path):
    plain = dict(PLAIN)
    plain["node_status.json"] = b'{"backup": "CSCTF{second_flag_decoy}"}'
    seed = (T0 * 0x9E3779B1) & M32
    ch = _bare(tmp_path, encrypt(plain, XS32, seed), "2026-10-02 04:13:05Z encryptor started\n")
    r = rk.solve(ch, PROFILE, cpu_seconds=600, generators="xorshift32-word")
    assert r.status == "candidate" and set(r.flags) == {FLAG, "CSCTF{second_flag_decoy}"}


def test_plausible_decryption_without_a_flag_is_unsure(tmp_path):
    plain = {k: (v.replace(FLAG.encode(), b"none-here") if isinstance(v, bytes) else v) for k, v in PLAIN.items()}
    seed = (T0 * 0x9E3779B1) & M32
    ch = _bare(tmp_path, encrypt(plain, XS32, seed), "2026-10-02 04:13:05Z encryptor started\n")
    r = rk.solve(ch, PROFILE, cpu_seconds=600, generators="xorshift32-word")
    assert r.status == "unsure" and not r.flags and "no flag" in r.notes
    assert (ch / "recon/ransom_keystream/grid_topology.cfg").read_bytes() == plain["grid_topology.cfg"]


def test_no_seed_candidate_is_blocked_and_no_ciphertext_is_none(tmp_path):
    ch = tmp_path / "c"
    (ch / "files").mkdir(parents=True)
    (ch / "files" / "x.cfg.enc").write_bytes(os.urandom(64))
    r = rk.solve(ch, PROFILE)
    assert r.status == "blocked" and "times=" in r.notes and "ext-listing.json" in r.notes
    (ch / "files" / "x.cfg.enc").unlink()
    (ch / "files" / "readme.txt").write_text("hello")
    r2 = rk.solve(ch, PROFILE)
    assert r2.status == "none" and "no ciphertext" in r2.notes


def test_explicit_times_and_pids_options(tmp_path):
    seed = ((T0 + PID) * 0x41C64E6D) & M32
    ch = tmp_path / "c"
    (ch / "files").mkdir(parents=True)
    for n, d in encrypt(PLAIN, XS32, seed).items():
        (ch / "files" / n).write_bytes(d)
    r = rk.solve(ch, PROFILE, times=str(T0 - 1), pids=str(PID), generators="xorshift32-word", cpu_seconds=600)
    assert r.status == "solved" and "times= +1s" in r.notes
    bad = rk.solve(ch, PROFILE, times=str(T0), pids=str(PID), generators="nope")
    assert bad.status == "blocked" and "names no known generator" in bad.notes


def test_cpu_budget_stops_the_search_and_says_so():
    enc = encrypt(PLAIN, XS32, 12345)
    ciphers = [rk.Cipher(n, n, d) for n, d in enc.items()]
    ticks = iter(range(10_000))
    res = rk.search(ciphers, [("exact", [rk.TimeCand(T0 + i, "x") for i in range(50_000)])], [PID], FF,
                    gens=[XS32], multipliers=[], cpu_seconds=2, clock=lambda: next(ticks))
    assert res.truncated.startswith("CPU budget of 2 s spent in tier exact") and not res.found
    assert res.tried == 2 * rk.BATCH                     # two batches ran before the third check failed


def test_seed_cap_truncates_a_tier_and_notes_it():
    ciphers = [rk.Cipher("a.cfg.enc", "a", os.urandom(40))]
    res = rk.search(ciphers, [("exact", [rk.TimeCand(T0 + i, "x") for i in range(100)])], [PID], FF,
                    gens=[XS32], max_seeds=150)
    assert res.tiers[0][1] == 150 and "seed cap 150" in res.truncated
    assert any("over the cap of 150" in n for n in res.notes)


def test_crib_option_gates_the_first_file(tmp_path):
    seed = (T0 * 0x9E3779B1) & M32
    ch = _bare(tmp_path, encrypt(PLAIN, XS32, seed), "2026-10-02 04:13:05Z encryptor started\n")
    assert rk.solve(ch, PROFILE, generators="xorshift32-word", crib="NOT-THERE", cpu_seconds=600).status == "none"
    r = rk.solve(ch, PROFILE, generators="xorshift32-word", crib="# substation", cpu_seconds=600)
    assert r.status == "solved"


def test_manifest_routes_ransomware_wording():
    from ctf.engines import router
    picks = router.route("forensics", "the encryptor ransomware left .enc files; recover the config")
    ids = [h.manifest.id for h in picks]
    assert "toolkits.ransom_keystream" in ids[:5]


# ----------------------------------------------------------------------------- verification round 1
def test_manifest_inputs_and_file_route_name_every_ransom_suffix():
    import tomllib
    doc = tomllib.loads((REPO / "solvers/toolkits/ransom_keystream.manifest.toml").read_text())
    want = [f"ext:{s}" for s in rk.SUFFIXES]
    assert doc["inputs"] == want
    assert [r["files"] for r in doc["routes"] if "files" in r] == [want]


def test_a_single_ciphertext_of_unknown_type_is_solved(tmp_path):
    plain = b"handover token: " + FLAG.encode() + b"\nrotate after the outage window\n"
    ch = tmp_path / "c"
    (ch / "files").mkdir(parents=True)
    (ch / "files" / "secret.enc").write_bytes(
        bytes(a ^ b for a, b in zip(plain, rk.Stream(XS32, T0).take(len(plain)))))
    assert rk.Cipher("secret.enc", "x", b"").expect == "unknown"
    r = rk.solve(ch, PROFILE, times=str(T0), generators="xorshift32-word", cpu_seconds=600)
    assert r.status == "solved" and r.flags == (FLAG,) and "form=time " in r.notes
    assert (ch / "recon/ransom_keystream/secret").read_bytes() == plain


def test_seventy_percent_printable_is_not_text():
    data = b"A" * 70 + bytes(range(0x80, 0x80 + 30))
    assert rk.plausible(data, "text") is False
    assert rk.plausible(data, "unknown") is None
    assert rk.plausible(b"A" * 96 + b"\x80" * 4, "text") is True          # 96 %: over the 95 % line


def _xor(plain: bytes, g: rk.Gen, seed: int) -> bytes:
    return bytes(a ^ b for a, b in zip(plain, rk.Stream(g, seed).take(len(plain))))


def test_the_search_stops_after_the_first_tier_that_gives_a_flag():
    t1 = T0 + 1000
    a = b"# config\nTOKEN=" + FLAG.encode() + b"\n" + b"LINE=ok\n" * 10
    b = b"# backup\nOLD=CSCTF{decoy_in_a_later_tier}\n" + b"LINE=ok\n" * 10
    ciphers = [rk.Cipher("a.cfg.enc", "a.cfg.enc", _xor(a, XS32, T0)),
               rk.Cipher("b.cfg.enc", "b.cfg.enc", _xor(b, XS32, t1))]
    tiers = [("exact", [rk.TimeCand(T0, "e")]), ("logs", [rk.TimeCand(t1, "l")])]
    res = rk.search(ciphers, tiers, [], FF, gens=[XS32], multipliers=[])
    assert [t[0] for t in res.tiers] == ["exact"]
    assert {f for d in res.found for f in d.flags} == {FLAG}
    later = rk.search(ciphers, tiers[1:], [], FF, gens=[XS32], multipliers=[])   # the decoy is findable
    assert {f for d in later.found for f in d.flags} == {"CSCTF{decoy_in_a_later_tier}"}


def test_pid_only_seeds_are_searched_in_the_exact_tier_only():
    ciphers = [rk.Cipher("a.cfg.enc", "a", bytes(random.Random(3).randrange(256) for _ in range(40)))]
    tiers = [("exact", [rk.TimeCand(T0, "e")]), ("logs", [rk.TimeCand(T0 + 5000, "l")])]
    res = rk.search(ciphers, tiers, [PID], FF, gens=[XS32], multipliers=[])
    # exact: time, pid, time^pid, time+pid, time^(pid<<16); logs: the same less the bare pid
    assert [(n, s) for n, s, _ in res.tiers] == [("exact", 5), ("logs", 4)]


def test_an_implausible_first_file_is_rejected_even_when_it_holds_a_flag():
    prov = rk.Prov("time", T0, None, "x")
    junk = b"CSCTF{decoy_bin}" + bytes(range(0x80, 0x100)) * 2          # printable head, binary body
    c = rk.Cipher("a.cfg.enc", "a", _xor(junk, XS32, 77))
    assert rk.plausible(junk, "text") is False and FF.find_flags(junk)
    assert rk._verify([c], XS32, 77, prov, 0, FF, None) == []
    good = rk.Cipher("a.cfg.enc", "a", _xor(b"KEY=" + FLAG.encode() + b"\n", XS32, 77))
    assert [d.flags for d in rk._verify([good], XS32, 77, prov, 0, FF, None)] == [[FLAG]]


def test_a_shared_order_is_tried_only_from_the_file_whose_gate_passed():
    # b is empty, so in path order [b, a] the stream reaches a exactly as in alphasort order [a, b]:
    # only the orders that start with the gated file (a) are decrypted from it
    prov = rk.Prov("time", T0, None, "x")
    a = rk.Cipher("a.txt.enc", "z/a.txt.enc", _xor(b"plain text body\n" * 4, XS32, 5))
    b = rk.Cipher("b.txt.enc", "a/b.txt.enc", b"")
    assert [n for n, _ in rk.orders([a, b])] == ["alphasort", "path"]
    assert [d.layout for d in rk._verify([a, b], XS32, 5, prov, 0, FF, None)] == ["single", "shared:alphasort"]


def test_an_even_constant_is_not_a_multiplier_hint():
    even, odd = 0x9E3779B0, 0x9E3779B1
    assert 8 <= bin(even).count("1") <= 24
    elf_of = lambda k: ef.elf(b"\x69\xc0" + k.to_bytes(4, "little"))          # noqa: E731
    assert rk.hints_from_elf(elf_of(even)).multipliers == set()
    assert rk.hints_from_elf(elf_of(odd)).multipliers == {odd}
    assert rk.hints_from_text(f"x = y * {even:#x};").multipliers == set()


def test_zip_ut_extra_is_an_mtime_only_when_its_mtime_flag_is_set():
    def one(flags: int) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            zi = zipfile.ZipInfo("a.cfg.enc", date_time=(2020, 1, 1, 0, 0, 0))
            zi.extra = b"UT\x05\x00" + bytes([flags]) + T0.to_bytes(4, "little")
            z.writestr(zi, b"x")
        return buf.getvalue()

    exact, local, by = rk._zip_times(one(0x2), "h.zip")            # access time only: not an mtime
    assert exact == [] and by == {} and len(local) == 1
    exact, _, by = rk._zip_times(one(0x3), "h.zip")
    assert [c.t for c in exact] == [T0] and by == {"a.cfg.enc": T0}


def test_the_time_window_reaches_both_edges():
    got = rk._spread([rk.TimeCand(100, "x")], 2)
    assert sorted(c.t for c in got) == [98, 99, 100, 101, 102]
    assert {c.t: c.source for c in got}[102] == "x +2s" and {c.t: c.source for c in got}[98] == "x -2s"


def test_a_minute_stamp_covers_its_seconds_00_to_59():
    base = 1790914380                                                   # 2026-10-02 04:13:00 UTC
    g = rk.Gathered(logged=[(base, 60, False, "l:1", True)])
    tiers = dict(rk.build_tiers(g, [], 2))
    assert sorted(c.t for c in tiers["logs"]) == list(range(base, base + 60))
    assert base - 3600 * 4 in {c.t for c in tiers["logs-tz"]} and base - 4 * 3600 + 59 in \
        {c.t for c in tiers["logs-tz"]}


def test_a_second_precision_stamp_is_searched_over_the_window_either_side():
    base = 1790914385                                                   # 2026-10-02 04:13:05 UTC
    g = rk.Gathered(logged=[(base, 1, False, "l:1", True)])
    tiers = dict(rk.build_tiers(g, [], 2))
    assert sorted(c.t for c in tiers["logs"]) == list(range(base - 2, base + 3))
    shifted = {c.t for c in tiers["logs-tz"]}
    assert {base - 2 - 4 * 3600, base + 2 - 4 * 3600} <= shifted        # the zone tier keeps the window
    g = rk.Gathered(logged=[(base, 1, True, "epoch", True)])            # an epoch / explicit-zone stamp
    assert sorted(c.t for c in dict(rk.build_tiers(g, [], 1))["logs"]) == [base - 1, base, base + 1]


def test_a_listing_that_is_not_a_json_object_is_noted_not_a_crash(tmp_path):
    ch = tmp_path / "c"
    (ch / "files").mkdir(parents=True)
    (ch / "files" / "ext-listing.json").write_text("[1, 2, 3]")
    (ch / "unpacked" / "d").mkdir(parents=True)
    (ch / "unpacked" / "d" / "ext-listing.json").write_text('{"files": 7}')
    (ch / "files" / "a.cfg.enc").write_bytes(b"\x01" * 32)
    g = rk.gather(ch)
    assert len(g.ciphers) == 1
    assert sum("not an ext listing" in n for n in g.notes) == 2
    assert any(n.startswith("files/ext-listing.json") for n in g.notes)


def test_plaintexts_with_one_basename_in_two_folders_do_not_overwrite_each_other_or_seed_json(tmp_path):
    pa = json.dumps({"token": FLAG, "site": "a"}).encode()
    pb = json.dumps({"token": "none", "site": "b", "pad": "x" * 40}).encode()
    st = rk.Stream(XS32, T0)                                 # one stream, alphasort: same name, then path
    ca = bytes(x ^ y for x, y in zip(pa, st.take(len(pa))))
    cb = bytes(x ^ y for x, y in zip(pb, st.take(len(pb))))
    ch = tmp_path / "c"
    for sub, data in (("a", ca), ("b", cb)):
        (ch / "files" / sub).mkdir(parents=True)
        (ch / "files" / sub / "seed.json.enc").write_bytes(data)
    r = rk.solve(ch, PROFILE, times=str(T0), generators="xorshift32-word", cpu_seconds=600)
    assert r.status == "solved" and "layout=shared:alphasort" in r.notes
    paths = [e.path for e in r.evidence]
    assert len(set(paths)) == 2 and "recon/ransom_keystream/seed.json" not in paths
    assert sorted((ch / p).read_bytes() for p in paths) == sorted([pa, pb])
    assert json.loads((ch / "recon/ransom_keystream/seed.json").read_text())["seed"] == T0
