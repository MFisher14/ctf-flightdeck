"""B-245: audio stego carriers read with no key on hand (solvers/toolkits/audio_carriers.py).

Every carrier is synthetic, built here by the embedders in tests/b245_fixtures.py from the published
descriptions of each method. The invariant under test: a reading is PLAIN only when a stored
length + CRC-32 proves it; a clean cover, a corrupted CRC and an ambiguous pair give plain None."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import numpy as np
import pytest

REPO = Path(__file__).resolve().parent.parent
for p in ("tests", "solvers/toolkits", "solvers/common"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))

import audio_carriers as ac            # noqa: E402
import b245_fixtures as fx             # noqa: E402
import _carrier_judge as cj            # noqa: E402

FLAG = b"flag{spread_spectrum_ok}"
MSG = fx.len_crc(FLAG)
BITS = fx.bits_of(MSG)


def _dsss_wav(chips_seed=5, nchips=31, spc=4, alpha=1500.0, lead=0, bits=BITS):
    rng = np.random.default_rng(chips_seed)
    chips = rng.choice([-1, 1], size=nchips)
    L = nchips * spc
    x = fx.cover(lead + L * len(bits) + 1000, seed=2, amp=3000)
    y = x.copy()
    y[lead:] = fx.dsss_embed(x[lead:], bits, chips, spc, alpha)
    return fx.wav16(np.round(y)), L


# ---- spread spectrum --------------------------------------------------------------------------------

@pytest.mark.parametrize("seed,nchips,spc", [(5, 31, 4), (5, 63, 2), (6, 63, 2)])
def test_symbol_periods_finds_the_symbol_not_a_multiple(seed, nchips, spc):
    # (6, 63, 2): the symbol's own lag scores z 7, under PERIOD_MIN_Z, while its multiples score 9-11.
    # (5, 63, 2): it scores 9 but ranks below PERIOD_MAX_PEAKS of its multiples. Both come back only
    # as a divisor of the peaks
    data, L = _dsss_wav(chips_seed=seed, nchips=nchips, spc=spc)
    pcm = ac.load_pcm(data)
    found = ac.symbol_periods(pcm.floats[:, 0])
    assert found and found[0][0] == L, found


def test_symbol_periods_divisor_gate_is_what_admits_a_weak_symbol():
    data, L = _dsss_wav(chips_seed=6, nchips=63, spc=2)
    x = ac.load_pcm(data).floats[:, 0]
    assert L not in [lag for lag, _ in ac.symbol_periods(x, divisor_z=ac.PERIOD_MIN_Z)]
    assert ac.symbol_periods(x)[0][0] == L


def test_divisor_gate_admits_a_weak_symbol_with_exactly_two_multiples():
    # max_lag 503 = 4 x 126 - 1 leaves room for only two multiples of the 126-sample symbol (252, 378).
    # The symbol's own lag scores z 7, under PERIOD_MIN_Z, so only the divisor gate can admit it, and
    # "two or more multiples" is met exactly at its edge
    data, L = _dsss_wav(chips_seed=6, nchips=63, spc=2)
    x = ac.load_pcm(data).floats[:, 0]
    strict = [lag for lag, _ in ac.symbol_periods(x, max_lag=4 * L - 1, divisor_z=ac.PERIOD_MIN_Z)]
    assert L not in strict and sorted(strict) == [2 * L, 3 * L], strict
    found = ac.symbol_periods(x, max_lag=4 * L - 1)
    assert [lag for lag, _ in found] == [L, 2 * L, 3 * L], found


def test_period_divisors():
    assert ac.period_divisors([(240, 9.0)]) == [120, 80, 60, 48, 40, 30]
    # 9 x 50 and 11 x 50: 50 is no divisor p/2 .. p/8 of either, only their gcd
    assert ac.period_divisors([(450, 9.0), (550, 9.0)]) == [225, 150, 90, 75, 50, 275, 110]
    # 252: /2 /3 /4 /6 /7, then gcd(252, 378) = 126 again, then 378: /2 /7 (the rest repeat)
    assert ac.period_divisors([(252, 9.0), (378, 9.0)]) == [126, 84, 63, 42, 36, 189, 54]
    assert ac.period_divisors([(10, 9.0)]) == [5]                  # 10/2; 10/5 = 2 is a chip, not a symbol
    # a lag that was itself detected (120) is not repeated as a divisor
    assert ac.period_divisors([(240, 9.0), (120, 8.0)]) == [80, 60, 48, 40, 30, 24, 20, 15]


def test_dsss_wide_chips_need_the_divisor_sweep():
    # 15 chips x 8 samples: a 32-sample window holds four chips, so the window-local correlation is
    # weak; only 960 = 8 x 120 clears the gate. The sweep tries its divisors and the rank-1 fit at 120
    # decodes
    data, L = _dsss_wav(chips_seed=10, nchips=15, spc=8)
    found = ac.symbol_periods(ac.load_pcm(data).floats[:, 0])
    assert L not in [lag for lag, _ in found] and L in ac.period_divisors(found)
    res = ac.survey(data, methods=("dsss",))
    assert res["plain"] == FLAG and res["method"].startswith(f"dsss ch0 L{L} ")


def test_dsss_symbol_seen_only_as_the_gcd_of_two_far_multiples():
    # 13 chips x 8 samples (L 104, not in DSSS_LENGTHS): the detector keeps only 16 x 104 = 1664 and
    # 27 x 104 = 2808. 104 is no divisor p/2 .. p/8 of either; only their gcd gives it, and the blind
    # sweep decodes there
    data, L = _dsss_wav(chips_seed=10, nchips=13, spc=8)
    assert L not in ac.DSSS_LENGTHS
    found = ac.symbol_periods(ac.load_pcm(data).floats[:, 0])
    lags = [lag for lag, _ in found]
    assert lags == [16 * L, 27 * L], found
    assert L in ac.period_divisors(found)
    res = ac.survey(data, methods=("dsss",))
    assert res["plain"] == FLAG and res["method"].startswith(f"dsss ch0 L{L} "), res["method"]


def test_symbol_periods_finds_nothing_in_a_clean_cover():
    x = fx.cover(60000, seed=11) / 32768
    assert all(lag != 124 for lag, _ in ac.symbol_periods(x))


@pytest.mark.parametrize("nchips,spc", [(31, 4), (63, 2)])
@pytest.mark.parametrize("seed", [5, 6, 7])
def test_dsss_blind_sweep_recovers_the_payload(seed, nchips, spc):
    data, L = _dsss_wav(chips_seed=seed, nchips=nchips, spc=spc)
    res = ac.survey(data, methods=("dsss",))
    assert res["plain"] == FLAG, [n for n in res["notes"] if "dsss" in n][:4]
    assert res["method"].startswith(f"dsss ch0 L{L} ")
    assert f"stegodepth_spread chips={nchips}x{spc}" in res["method"]


def test_dsss_unframed_text_is_a_candidate_not_plain():
    # no stored length + CRC: the text comes back as a candidate of the right fit, never as plain.
    # Seed 6 at 31x4 is a cover where the symbol (124) scores under the gate on this payload
    text = b"the hidden message is flag{unframed_text_dsss} ok"
    data, L = _dsss_wav(chips_seed=6, bits=fx.bits_of(text))
    res = ac.survey(data, methods=("dsss",))
    assert res["plain"] is None and res["proven"] == {}
    hits = [n for n, v in res["candidates"] if "flag{unframed_text_dsss}" in str(v)]
    assert any(n.startswith(f"dsss ch0 L{L} ") for n in hits), res["candidates"][:4]


def test_dsss_period_not_in_the_fixed_set_needs_the_detector():
    # 124 is not in DSSS_LENGTHS: with only the fixed set the sweep cannot read it
    assert 124 not in ac.DSSS_LENGTHS
    data, _ = _dsss_wav()
    res = ac.survey(data, methods=("dsss",), dsss_lengths=ac.DSSS_LENGTHS)
    assert res["plain"] is None
    res = ac.survey(data, methods=("dsss",), dsss_lengths=(124,))
    assert res["plain"] == FLAG


def test_dsss_fit_gates_a_true_symbol_over_a_wrong_one():
    data, L = _dsss_wav()
    x = ac.load_pcm(data).floats[:, 0]
    good = ac.dsss_fit(x, L)
    bad = ac.dsss_fit(x, L + 3)
    assert good.score >= ac.DSSS_MIN_BIMODALITY and good.structure > ac.DSSS_MIN_STRUCTURE
    assert bad.score < good.score


# ---- echo hiding ------------------------------------------------------------------------------------

def _echo_wav(window=1024, d0=50, d1=100):
    x = fx.cover(window * len(BITS) + 100, seed=3, tones=False)
    return fx.wav16(np.round(fx.echo_embed(x, BITS, window, d0, d1, 0.5)))


def test_echo_fit_finds_both_delays():
    pcm = ac.load_pcm(_echo_wav(d0=37, d1=81))
    fit = ac.echo_fit(pcm.floats[:, 0], 1024)
    assert (fit.delay_zero, fit.delay_one) == (37, 81)


def test_echo_blind_sweep_recovers_the_payload():
    res = ac.survey(_echo_wav(), methods=("echo",))
    assert res["plain"] == FLAG
    assert "W1024" in res["method"] and "d50/100" in res["method"]


def test_echo_window_outside_the_sweep_is_not_claimed():
    res = ac.survey(_echo_wav(window=1100), methods=("echo",))
    assert res["plain"] is None
    res = ac.survey(_echo_wav(window=1100), methods=("echo",), echo_windows=(1100,))
    assert res["plain"] == FLAG


# ---- phase coding -----------------------------------------------------------------------------------

@pytest.mark.parametrize("place", ["low", "high"])
def test_phase_coding_recovers_the_payload(place):
    msg = fx.len_crc(b"flag{phase_coded}")
    y = fx.phase_embed(fx.cover(8192 * 4, seed=4), fx.bits_of(msg), 2048, place=place)
    res = ac.survey(fx.wav16(np.round(y)), methods=("phase",))
    assert res["plain"] == b"flag{phase_coded}"
    assert res["method"].startswith("phase ch0 L2048")


@pytest.mark.parametrize("order", ["asc", "desc"])
def test_phase_run_one_bin_short_is_read_from_the_bin_before(order):
    # the message's first bin (lowest bin ascending, highest bin descending) sits 0.3 rad off +-pi/2:
    # same sign, same bit, but outside PHASE_TOL, so the detected run starts one bin late
    pay = b"flag{phase_coded}"
    bits = fx.bits_of(fx.len_crc(pay))
    placed = bits if order == "asc" else bits[::-1]
    first = 0 if order == "asc" else len(placed) - 1
    delta = -0.3 if placed[first] == 0 else 0.3          # toward zero phase: the sign survives
    y = fx.phase_embed(fx.cover(8192 * 4, seed=4), placed, 2048, place="high", jitter={first: delta})
    res = ac.survey(fx.wav16(np.round(y)), methods=("phase",))
    assert res["plain"] == pay
    want = "start-1 asc" if order == "asc" else "end+1 desc"
    assert want in res["method"], res["method"]


@pytest.mark.parametrize("pay,L,seed,extra", [
    (b"flag{phase_coded}", 2048, 5, 3),
    (b"flag{a_longer_phase_coded_payload_x}", 1024, 7, 8),
])
def test_phase_run_extended_by_chance_bins_is_trimmed(pay, L, seed, extra):
    # cover bins sit within PHASE_TOL of +-pi/2 by chance (about 6%); the gap bridging chains `extra`
    # of them onto the low end of a high-band message
    bits = fx.bits_of(fx.len_crc(pay))
    y = fx.phase_embed(fx.cover(8192 * 4, seed=seed), bits, L, place="high")
    res = ac.survey(fx.wav16(np.round(y)), methods=("phase",))
    first_bin = L // 2 - len(bits)
    assert any(f"bins {first_bin - extra}..{L // 2 - 1} " in n for n in res["notes"]), res["notes"]
    assert res["plain"] == pay


def test_phase_core_trims_isolated_chance_hits():
    hit = np.zeros(120, bool)
    hit[[10, 13]] = True             # chance hits, bridged onto the run
    hit[16:100] = True
    hit[102] = True
    hit[24] = False                  # one miss inside the message
    runs = ac.phase_runs(hit)
    assert runs == [(10, 93)]
    assert ac.phase_core(hit, 10, 93) == (16, 100)
    flat = np.ones(5, bool)
    assert ac.phase_core(flat, 0, 5) == (0, 5)
    sparse = np.array([1, 0, 1, 0, 1, 0, 1], bool)       # no 3 hits in a row: the run as found
    assert ac.phase_core(sparse, 0, 7) == (0, 7)


def test_phase_runs_bridges_small_gaps_and_drops_short_runs():
    hit = np.zeros(100, bool)
    hit[10:40] = True
    hit[20] = False                  # one miss inside: bridged
    hit[60:70] = True                # 10 bins: under PHASE_MIN_RUN
    assert ac.phase_runs(hit) == [(10, 30)]


# ---- parity, G.711, containers ----------------------------------------------------------------------

def test_parity_coding_region_8():
    ints = np.round(fx.cover(40000, seed=5)).astype(np.int64)
    res = ac.survey(fx.wav16(fx.parity_embed(ints, BITS, 8)), methods=("parity",))
    assert res["plain"] == FLAG and res["method"].startswith("parity ch0 R8 ")


def test_parity_bits_is_the_xor_of_region_lsbs():
    lsb = np.array([1, 0, 1, 1, 0, 0, 1, 0, 1], dtype=np.int64)
    assert ac.parity_bits(lsb, 3).tolist() == [0, 1, 0]
    assert ac.parity_bits(lsb, 1).tolist() == lsb.tolist()


def test_g711_decoders_match_the_itu_table():
    mu = ac.mulaw_decode(np.array([0xFF, 0x7F, 0x00, 0x80], dtype=np.uint8)).tolist()
    assert mu == [0, 0, -32124, 32124]
    a = ac.alaw_decode(np.array([0xD5, 0x55, 0xAA, 0x2A], dtype=np.uint8)).tolist()
    assert a == [8, -8, 32256, -32256]


def _g711_wav(codes: np.ndarray, tag: int) -> bytes:
    body = codes.astype(np.uint8).tobytes()
    fmt = struct.pack("<HHIIHH", tag, 1, 8000, 8000, 1, 8)
    chunks = b"fmt " + struct.pack("<I", len(fmt)) + fmt + b"data" + struct.pack("<I", len(body)) + body
    return b"RIFF" + struct.pack("<I", 4 + len(chunks)) + b"WAVE" + chunks


@pytest.mark.parametrize("tag,codec", [(7, "mu-law"), (6, "a-law")])
def test_g711_code_byte_lsb(tag, codec):
    codes = np.random.default_rng(7).integers(0, 256, size=4000)
    codes[:len(BITS)] = (codes[:len(BITS)] & 0xFE) | np.asarray(BITS)
    res = ac.survey(_g711_wav(codes, tag), methods=("parity",))
    assert res["plain"] == FLAG and res["method"].startswith(f"lsb {codec} code")


def _aiff16(ints: np.ndarray, rate=8000) -> bytes:
    body = ints.astype(">i2").tobytes()
    # 80-bit extended for 8000: exponent 16383 + 12, mantissa 8000 << (63 - 12)
    ext = struct.pack(">HQ", 16383 + 12, 8000 << 51)
    comm = struct.pack(">HIH", 1, len(ints), 16) + ext
    ssnd = struct.pack(">II", 0, 0) + body
    chunks = b"COMM" + struct.pack(">I", len(comm)) + comm + b"SSND" + struct.pack(">I", len(ssnd)) + ssnd
    return b"FORM" + struct.pack(">I", 4 + len(chunks)) + b"AIFF" + chunks


def _au16(ints: np.ndarray) -> bytes:
    body = ints.astype(">i2").tobytes()
    return b".snd" + struct.pack(">IIIII", 24, len(body), 3, 8000, 1) + body


@pytest.mark.parametrize("build,container", [(_aiff16, "aiff"), (_au16, "au")])
def test_non_wav_containers_are_read(build, container):
    ints = np.round(fx.cover(30000, seed=6)).astype(np.int64)
    data = build(fx.parity_embed(ints, BITS, 4))
    pcm = ac.load_pcm(data)
    assert pcm.container == container and pcm.rate == 8000 and pcm.frames == 30000
    assert ac.load_pcm(pcm.raw).ints.tolist() == pcm.ints.tolist()     # the WAV view is lossless
    res = ac.survey(data, methods=("parity",))
    assert res["plain"] == FLAG and "R4" in res["method"]


# ---- silence-interval coding ------------------------------------------------------------------------

def _silence_wav(bits, k=2, base=40):
    rng = np.random.default_rng(8)
    parts = [np.round(rng.standard_normal(200) * 3000 + 5000)]
    for i in range(0, len(bits), k):
        v = int("".join(map(str, bits[i:i + k])), 2)
        parts.append(np.zeros(base + v))
        parts.append(np.round(rng.standard_normal(150) * 3000 + 5000))
    return fx.wav16(np.concatenate(parts))


def test_silence_interval_coding():
    res = ac.survey(_silence_wav(BITS, k=2), methods=("silence",))
    assert res["plain"] == FLAG and " k2 " in res["method"]


def test_silence_runs_drops_the_lead_in_and_tail():
    x = np.array([0] * 20 + [500] * 5 + [0] * 9 + [500] * 5 + [0] * 3 + [500] + [0] * 30)
    assert ac.silence_runs(x, 0).tolist() == [9]
    assert ac.interval_bits(np.array([9, 6]), 2).tolist() == [0, 1, 1, 0]


# ---- never wrong -------------------------------------------------------------------------------------

def test_clean_cover_gives_no_plain():
    res = ac.survey(fx.wav16(np.round(fx.cover(80000, seed=9))))
    assert res["plain"] is None and res["proven"] == {} and res["candidates"] == []


def test_corrupted_crc_is_not_plain():
    bad = bytearray(MSG)
    bad[-1] ^= 0x40
    ints = np.round(fx.cover(40000, seed=5)).astype(np.int64)
    res = ac.survey(fx.wav16(fx.parity_embed(ints, fx.bits_of(bytes(bad)), 8)), methods=("parity",))
    assert res["plain"] is None


def test_two_distinct_proven_payloads_are_ambiguous():
    other = fx.len_crc(b"flag{a_second_payload}")
    left = fx.parity_embed(np.round(fx.cover(40000, seed=5)).astype(np.int64), BITS, 8)
    right = np.round(fx.cover(40000, seed=6)).astype(np.int64)
    ob = np.asarray(fx.bits_of(other))
    right[:len(ob)] = (right[:len(ob)] & ~1) | ob                  # plain LSB of the right channel
    res = ac.survey(fx.wav16(np.stack([left, right], axis=1), channels=2), methods=("parity",))
    assert res["plain"] is None
    assert set(res["proven"]) == {FLAG, b"flag{a_second_payload}"}
    assert any("ambiguous" in n for n in res["notes"])


def test_survey_refuses_bad_parameters_and_says_why_it_reads_nothing():
    with pytest.raises(ac.AudioCarrierError):
        ac.survey(b"", methods=("telepathy",))
    with pytest.raises(ac.AudioCarrierError):
        ac.survey(b"", max_bits=3)
    res = ac.survey(b"not audio at all")
    assert res["plain"] is None and "not a recording" in res["notes"][0]


def test_cli_prints_one_json_line_per_file(tmp_path, capsys):
    p = tmp_path / "a.wav"
    ints = np.round(fx.cover(40000, seed=5)).astype(np.int64)
    p.write_bytes(fx.wav16(fx.parity_embed(ints, BITS, 8)))
    assert ac.main([str(p), "--method", "parity"]) == 0
    import json
    line = json.loads(capsys.readouterr().out.strip())
    assert bytes.fromhex(line["plain_hex"]) == FLAG
    assert ac.main([str(tmp_path / "missing.wav")]) == 2


# ---- routing -----------------------------------------------------------------------------------------

def _routed(description, files_dir=None):
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from ctf.engines import router
    return [h.manifest.id for h in router.route("stego", description, files_dir, root=REPO)]


@pytest.mark.parametrize("text", ["the flag is hidden with echo hiding", "a DSSS watermark in this recording",
                                  "phase coding of the first segment"])
def test_plain_audio_carrier_words_route_to_the_blind_reader_first(text):
    ids = _routed(text)
    assert ids and ids[0] == "toolkits.audio_carriers", ids[:4]


def test_spread_spectrum_routes_here_only_with_a_recording(tmp_path):
    rec = tmp_path / "rec"
    rec.mkdir()
    (rec / "song.wav").write_bytes(b"RIFF")
    assert _routed("spread spectrum stego", rec)[0] == "toolkits.audio_carriers"
    img = tmp_path / "img"
    img.mkdir()
    (img / "cover.png").write_bytes(b"\x89PNG")
    assert "toolkits.audio_carriers" not in _routed("spread spectrum stego", img)


# ---- the judge ---------------------------------------------------------------------------------------

def test_judge_short_or_flat_proof_is_a_candidate_not_plain():
    S = cj.Survey("t")
    assert S.judge(fx.len_crc(b"abc") + b"\x00" * 8, "short") == "candidate"
    assert S.judge(fx.len_crc(b"A" * 12), "flat") == "candidate"
    assert S.judge(fx.len_crc(b"flag{ok_value}"), "good") == "plain"
    assert S.result()["plain"] == b"flag{ok_value}"


def test_judge_files_only_offers_no_text_and_no_short_crc():
    text = b"just a printable start of text here" + bytes(range(200, 220))
    short = fx.len_crc(b"abc") + b"\x00" * 8
    loose, strict = cj.Survey("t"), cj.Survey("t", files_only=True)
    assert loose.judge(text, "x") == "candidate" and strict.judge(text, "x") == "none"
    assert loose.judge(short, "y") == "candidate" and strict.judge(short, "y") == "none"
    assert strict.result()["candidates"] == []
    assert strict.judge(fx.len_crc(b"flag{ok_value}"), "z") == "plain"


def test_pack_bits_both_orders():
    assert cj.pack_bits([0, 1, 0, 0, 0, 0, 0, 1, 1]) == b"A"
    assert cj.pack_bits([1, 0, 0, 0, 0, 0, 1, 0], msb_first=False) == b"A"
