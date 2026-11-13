"""B-158: the IQ-to-frames demodulation library and dispatcher (solvers/toolkits/iq_demod.py).

Every capture is synthesised in the test by the transmitters in tests/iq_synth.py (written from the
published air interfaces, importing nothing from the engine), put through a channel (leading and
trailing silence, a carrier offset, noise, an awkward sample rate) and handed to the demodulator;
the assertions are on what must come back: the transmitted bits, the frame the bit-level parser
accepts, the planted flag. The unit tests pin each block so a mutation to one of them fails even
where the end-to-end search has more than one way to the flag.

No wall-clock bounds (rule 16): the one budget test drives an injected step clock.
"""
import json
import math
import os

import numpy as np
import pytest

import iq_demod as iqd
import iq_synth as syn
from ctf import event, flagfmt

FLAG = "CSCTF{iq_demod_b158_4c1f9a07e2}"


@pytest.fixture
def ff():
    return flagfmt.current()        # conftest sets CTF_EVENT=csctf (prefixes include CSCTF)


def cap_of(iq, rate, name="synthetic.cf32"):
    iq = np.asarray(iq).astype(np.complex64)
    return iqd.Capture(name, "cf32", rate, "option" if rate else "none", iq=iq, total_samples=iq.size)


def ppm_pixels(ppm):
    w, h = iqd._ppm_size(ppm)
    return np.frombuffer(ppm.split(b"\n", 3)[3], dtype=np.uint8).reshape(h, w, 3)


# ---- loading ---------------------------------------------------------------------------------------

def test_iq_from_bytes_scales_each_format_exactly():
    cu8 = iqd.iq_from_bytes(bytes([0, 255, 255, 0]), "cu8")
    assert cu8.tolist() == [complex(-1, 1), complex(1, -1)]
    cs8 = iqd.iq_from_bytes(np.array([64, -128, 0, 127], dtype=np.int8).tobytes(), "cs8")
    assert cs8.tolist() == [complex(0.5, -1.0), complex(0, 127 / 128)]
    cs16 = iqd.iq_from_bytes(np.array([16384, -32768], dtype="<i2").tobytes(), "cs16")
    assert cs16.tolist() == [complex(0.5, -1.0)]
    cf32 = iqd.iq_from_bytes(np.array([0.25, -0.75, 3.0, 4.0], dtype="<f4").tobytes(), "cf32")
    assert cf32.tolist() == [complex(0.25, -0.75), complex(3, 4)]


def test_iq_from_bytes_refuses_ragged_nonfinite_and_unknown():
    with pytest.raises(iqd.IQDemodError, match="not whole I/Q pairs"):
        iqd.iq_from_bytes(b"\x00\x01\x02", "cu8")
    with pytest.raises(iqd.IQDemodError, match="non-finite"):
        iqd.iq_from_bytes(np.array([1.0, np.inf], dtype="<f4").tobytes(), "cf32")
    with pytest.raises(iqd.IQDemodError, match="unsupported IQ format 'cs24'"):
        iqd.iq_from_bytes(b"\x00" * 12, "cs24")


def test_load_capture_takes_format_from_the_extension_and_rate_from_the_name(tmp_path):
    iq = np.exp(2j * np.pi * 0.01 * np.arange(64))
    path = tmp_path / "g001_433.92M_250k.cu8"
    path.write_bytes(syn.to_cu8(iq, scale=1.0))
    cap = iqd.load_capture(path)
    assert (cap.fmt, cap.rate, cap.rate_source, cap.samples, cap.total_samples) == ("cu8", 250000.0, "name", 64, 64)
    assert np.max(np.abs(cap.iq - iq)) < 0.012        # 8-bit quantisation only
    assert iqd.load_capture(path, rate=1e6).rate_source == "option"
    assert iqd.load_capture(path, rate=1e6).rate == 1e6


def test_load_capture_without_a_stated_format_or_rate(tmp_path):
    path = tmp_path / "capture.bin"
    path.write_bytes(syn.to_cs16(np.ones(32, dtype=complex)))
    with pytest.raises(iqd.IQDemodError, match="pass --format"):
        iqd.load_capture(path)
    cap = iqd.load_capture(path, fmt="cs16")
    assert cap.fmt == "cs16" and cap.samples == 32
    assert cap.rate is None and cap.rate_source == "none"      # nothing states it: never guessed
    with pytest.raises(iqd.IQDemodError, match="unsupported IQ format"):
        iqd.load_capture(path, fmt="cs24")
    with pytest.raises(iqd.IQDemodError, match="--rate must be a positive"):
        iqd.load_capture(path, fmt="cs16", rate=-5.0)


def test_load_capture_says_what_it_dropped_or_cut(tmp_path):
    path = tmp_path / "odd.cs16"
    path.write_bytes(syn.to_cs16(np.ones(100, dtype=complex)) + b"\x07")
    cap = iqd.load_capture(path)
    assert cap.samples == 100 and any("1 trailing byte(s) dropped" in n for n in cap.notes)
    cut = iqd.load_capture(path, skip=10, max_samples=40)
    assert cut.samples == 40 and cut.total_samples == 100
    assert any("cut to 40 of 100 samples" in n for n in cut.notes)
    whole = iqd.load_capture(path, skip=10)
    assert whole.samples == 90 and not any("cut to" in n for n in whole.notes)


def test_load_capture_skip_starts_at_the_named_sample(tmp_path):
    ramp = np.arange(50) / 64.0 + 0j
    path = tmp_path / "ramp.cf32"
    path.write_bytes(syn.to_cf32(ramp))
    cap = iqd.load_capture(path, skip=7, max_samples=3)
    assert cap.iq.real.tolist() == [7 / 64.0, 8 / 64.0, 9 / 64.0]


def test_an_empty_capture_is_an_error_not_a_quiet_nothing_found(tmp_path, ff):
    empty = tmp_path / "empty_433.92M_250k.cu8"
    empty.write_bytes(b"")
    with pytest.raises(iqd.IQDemodError, match=r"empty_433.92M_250k.cu8: the capture holds no samples "
                                               r"\(empty file, or --skip past its end\)"):
        iqd.load_capture(empty)
    short = tmp_path / "short.cs16"
    short.write_bytes(syn.to_cs16(np.ones(10, dtype=complex)))
    assert iqd.load_capture(short, skip=9).samples == 1
    for skip in (10, 500):
        with pytest.raises(iqd.IQDemodError, match="short.cs16: the capture holds no samples"):
            iqd.load_capture(short, skip=skip)
    wav = tmp_path / "iq.wav"
    wav.write_bytes(syn.stereo_wav(np.exp(2j * np.pi * 0.03 * np.arange(40)), 48000))
    for skip in (40, 500):                                           # at the end, and well past it
        with pytest.raises(iqd.IQDemodError, match="iq.wav: the capture holds no samples"):
            iqd.load_capture(wav, skip=skip)
    # a Capture built some other way is refused by the dispatcher before any demodulator runs
    with pytest.raises(iqd.IQDemodError, match="nothing.cf32: the capture holds no samples"):
        iqd.demodulate(cap_of(np.zeros(0), 48000, name="nothing.cf32"), ff=ff)


def test_main_blocks_on_an_empty_capture(tmp_path, capsys):
    empty = tmp_path / "empty_48k.cu8"
    empty.write_bytes(b"")
    assert iqd.main([str(empty)]) == 1
    out, err = capsys.readouterr()
    result = json.loads(out.strip().splitlines()[-1])
    assert result["status"] == "blocked" and "the capture holds no samples" in result["notes"]
    assert "Mean of empty slice" not in err


def test_load_capture_wav_skip_reaches_past_the_read_cap(tmp_path, monkeypatch):
    # the WAV is seeked, not read whole then sliced: --skip steps through a WAV longer than the cap
    monkeypatch.setattr(iqd, "MAX_SAMPLES", 300)
    ramp = (np.arange(1000) % 997) / 1000.0
    path = tmp_path / "long.wav"
    path.write_bytes(syn.mono_wav(ramp, 8000))
    cap = iqd.load_capture(path, skip=500)
    assert cap.samples == 300 and cap.total_samples == 1000
    assert np.max(np.abs(cap.audio - ramp[500:800])) < 1e-4
    assert any("cut to 300 of 1000 frames" in n for n in cap.notes)
    tail = iqd.load_capture(path, skip=900)
    assert tail.samples == 100 and np.max(np.abs(tail.audio - ramp[900:])) < 1e-4
    assert not any("cut to" in n for n in tail.notes)


def test_a_wav_or_sigmf_meta_is_never_read_whole(tmp_path, monkeypatch):
    # untrusted handouts: the WAV is streamed and an oversized meta is refused on its size alone
    import pathlib
    wav = tmp_path / "iq.wav"
    wav.write_bytes(syn.stereo_wav(np.exp(2j * np.pi * 0.03 * np.arange(200)), 48000))
    (tmp_path / "rec.sigmf-data").write_bytes(syn.to_cs16(np.ones(40, dtype=complex)))
    meta = tmp_path / "rec.sigmf-meta"
    with meta.open("wb") as fh:
        fh.write(b'{"global": {"core:datatype": "ci16_le"}}')
        fh.truncate(iqd.SIGMF_META_MAX + 1)                          # sparse: big on disk, cheap to make
    reads = []
    real_open = pathlib.Path.open

    def no_read_bytes(self):
        raise AssertionError(f"{self.name} read whole")

    def watched_open(self, *a, **kw):
        reads.append(self.name)
        return real_open(self, *a, **kw)
    monkeypatch.setattr(pathlib.Path, "read_bytes", no_read_bytes)
    monkeypatch.setattr(pathlib.Path, "open", watched_open)
    assert iqd.load_capture(wav, max_samples=50).samples == 50
    with pytest.raises(iqd.IQDemodError, match="rec.sigmf-meta is over 4 MiB: not read"):
        iqd.load_capture(tmp_path / "rec.sigmf-data")
    assert "rec.sigmf-meta" not in reads


def test_load_capture_reads_sigmf_meta(tmp_path):
    iq = np.exp(2j * np.pi * 0.02 * np.arange(40))
    (tmp_path / "rec.sigmf-data").write_bytes(syn.to_cs16(iq, scale=1.0))
    meta = {"global": {"core:datatype": "ci16_le", "core:sample_rate": 96000}}
    (tmp_path / "rec.sigmf-meta").write_text(json.dumps(meta))
    cap = iqd.load_capture(tmp_path / "rec.sigmf-data")
    assert (cap.fmt, cap.rate, cap.rate_source, cap.samples) == ("cs16", 96000.0, "sigmf", 40)
    assert np.max(np.abs(cap.iq - iq)) < 1e-3
    stated = iqd.load_capture(tmp_path / "rec.sigmf-data", rate=48000.0)   # --rate outranks the meta
    assert (stated.rate, stated.rate_source) == (48000.0, "option")
    meta["global"]["core:datatype"] = "cf64_le"
    (tmp_path / "rec.sigmf-meta").write_text(json.dumps(meta))
    with pytest.raises(iqd.IQDemodError, match="SigMF datatype 'cf64_le' is not read"):
        iqd.load_capture(tmp_path / "rec.sigmf-data")
    (tmp_path / "rec.sigmf-meta").unlink()
    with pytest.raises(iqd.IQDemodError, match="has no rec.sigmf-meta beside it"):
        iqd.load_capture(tmp_path / "rec.sigmf-data")


def test_load_capture_reads_a_stereo_wav_as_iq_and_a_mono_wav_as_audio(tmp_path):
    iq = 0.8 * np.exp(2j * np.pi * 0.03 * np.arange(200))
    stereo = tmp_path / "iq.wav"
    stereo.write_bytes(syn.stereo_wav(iq, 48000, scale=0.8))
    cap = iqd.load_capture(stereo)
    assert (cap.fmt, cap.rate, cap.rate_source) == ("wav-iq", 48000.0, "wav")
    assert np.max(np.abs(cap.iq - iq)) < 1e-3
    mono = tmp_path / "audio.wav"
    mono.write_bytes(syn.mono_wav(iq.real, 11025))
    cap = iqd.load_capture(mono)
    assert cap.fmt == "wav-audio" and cap.iq is None and cap.rate == 11025.0
    assert np.max(np.abs(cap.audio - iq.real)) < 1e-3
    assert any("mono WAV" in n for n in cap.notes)


@pytest.mark.parametrize("source", ["rtl=0", "rtl_tcp:127.0.0.1:1234", "hackrf=0", "soapy:driver=rtlsdr", "-"])
def test_a_live_source_is_refused_by_name(source):
    with pytest.raises(iqd.IQDemodError, match="names a live source.*never opens an SDR"):
        iqd.load_capture(source)


def test_a_device_or_pipe_or_flowgraph_is_refused(tmp_path):
    fifo = tmp_path / "live.cu8"
    os.mkfifo(fifo)
    with pytest.raises(iqd.IQDemodError, match="not a regular file"):
        iqd.load_capture(fifo)
    grc = tmp_path / "receiver.grc"
    grc.write_text("options:\n  id: receiver\n")
    with pytest.raises(iqd.IQDemodError, match="GNU Radio flowgraph: it is not run"):
        iqd.load_capture(grc)
    with pytest.raises(iqd.IQDemodError, match="absent.cu8"):
        iqd.load_capture(tmp_path / "absent.cu8")


def test_a_saved_file_whose_name_looks_like_a_device_is_still_read(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "rtl=0").write_bytes(syn.to_cu8(np.ones(8, dtype=complex)))
    assert iqd.load_capture("rtl=0", fmt="cu8").samples == 8


# ---- signal helpers --------------------------------------------------------------------------------

def test_discriminator_is_the_phase_step():
    tone = np.exp(2j * np.pi * 0.0625 * np.arange(100))
    d = iqd.discriminator(tone)
    assert d.size == 99 and np.allclose(d, 2 * np.pi * 0.0625)
    assert np.allclose(iqd.discriminator(np.conj(tone)), -2 * np.pi * 0.0625)
    assert iqd.discriminator(tone[:1]).size == 0


def test_boxcar_is_a_centred_mean():
    x = np.arange(10, dtype=float)
    assert np.allclose(iqd.boxcar(x, 3)[1:-1], x[1:-1])         # the mean of i-1, i, i+1
    assert iqd.boxcar(x, 3)[0] == pytest.approx(0.5)             # the window shrinks at the edge
    assert np.allclose(iqd.boxcar(x, 1), x)
    step = np.concatenate((np.zeros(8), np.ones(8)))
    assert iqd.boxcar(step, 4)[8] == pytest.approx(0.5)


def test_sample_at_interpolates_on_a_fractional_clock():
    ramp = np.arange(20, dtype=float) * 2.0
    got = iqd.sample_at(ramp, 0.5, 2.25)
    assert np.allclose(got, 2.0 * (0.5 + 2.25 * np.arange(got.size)))
    assert got.size == 9 and 0.5 + 2.25 * 8 <= 19 < 0.5 + 2.25 * 9
    assert iqd.sample_at(ramp, 0.5, 2.25, count=3).size == 3
    assert iqd.sample_at(ramp, 30.0, 1.0).size == 0


def test_bursts_finds_each_keyed_stretch():
    x = np.concatenate((np.zeros(1000), np.ones(3000), np.zeros(2000), np.ones(500), np.zeros(800))) + 0j
    x = x + syn.noise(x.size, 0.02, 4)
    spans = iqd.bursts(x)
    assert len(spans) == 2
    assert abs(spans[0][0] - 1000) <= 20 and abs(spans[0][1] - 4000) <= 20
    assert abs(spans[1][0] - 6000) <= 20 and abs(spans[1][1] - 6500) <= 20
    carrier = np.ones(5000, dtype=complex) + syn.noise(5000, 0.02, 5)
    assert iqd.bursts(carrier) == [(0, 5000)]                   # no on/off contrast: one stretch
    assert iqd.bursts(x[:10]) == []
    # one short burst in a long quiet capture (a key-fob press): the floor is the noise, not the burst
    fob = syn.noise(400000, 0.05, 6)
    fob[250000:251000] += 1.0
    (only,) = iqd.bursts(fob)
    assert abs(only[0] - 250000) <= 20 and abs(only[1] - 251000) <= 20
    assert iqd.bursts(syn.noise(400000, 0.05, 7)) == [(0, 400000)]   # noise alone has no burst


def test_coarse_offset_is_the_centre_of_the_occupied_spectrum():
    rng = np.random.default_rng(4)
    flat = np.fft.ifft(np.where(np.abs(np.fft.fftfreq(65536)) < 0.1, 1.0, 0.0)
                       * np.exp(2j * np.pi * rng.random(65536)))      # a flat band 0.2 wide, random phases
    flat = flat / np.abs(flat).max()
    n = np.arange(flat.size)
    for centre in (0.0, 0.07, -0.21, 0.47):                         # 0.47: the band wraps round the edge
        moved = flat * np.exp(2j * np.pi * centre * n) + syn.noise(flat.size, 0.01, 2)
        got = iqd.coarse_offset(moved)
        assert abs((got - centre + 0.5) % 1.0 - 0.5) < 0.005, centre
    assert iqd.coarse_offset(flat[:100]) == 0.0
    # the signal may start late: the spectrum is averaged over stretches spread across the capture
    quiet_then = np.concatenate((syn.noise(40000, 0.01, 3), flat * np.exp(2j * np.pi * 0.2 * n)))
    assert abs(iqd.coarse_offset(quiet_then) - 0.2) < 0.005
    # in noise a third as dense as the signal, the noise floor must come off before the centroid
    loud = flat * np.exp(2j * np.pi * 0.3 * n) + syn.noise(flat.size, math.sqrt(1.5 * np.mean(np.abs(flat) ** 2)), 9)
    assert abs(iqd.coarse_offset(loud) - 0.3) < 0.01


def test_run_lengths_matches_the_carried_helper():
    import rf
    rng = np.random.default_rng(11)
    levels = rng.integers(0, 2, 500)
    assert iqd.run_lengths(levels) == rf.runs(levels.tolist())
    assert iqd.run_lengths([1, 1, 1]) == [3] and iqd.run_lengths([0, 0, 1]) == [-2, 1]
    assert iqd.run_lengths([]) == []


def test_pack_bits_orders():
    assert iqd.pack_bits("0100000101") == b"A"                  # ragged tail dropped
    assert iqd.pack_bits("10000010", msb_first=False) == b"A"
    assert iqd.pack_bits(np.array([0, 1, 0, 0, 0, 0, 1, 0], dtype=np.uint8)) == b"B"


# ---- crib selection --------------------------------------------------------------------------------

@pytest.mark.parametrize("order", ["msb", "lsb"])
@pytest.mark.parametrize("inverted", [False, True])
@pytest.mark.parametrize("offset", range(8))
def test_crib_bits_finds_a_flag_at_any_offset_polarity_and_order(ff, offset, inverted, order):
    # every one of the 8 x 2 x 2 readings is reachable: a flag at bit offset 7 is not missed
    body = syn.bits_of(b"junk " + FLAG.encode() + b" tail", msb_first=order == "msb")
    if inverted:
        body = [1 - b for b in body]
    bits = [1, 0, 1, 1, 0, 0, 1, 0][:offset] + body
    hits = iqd.crib_bits(np.array(bits, dtype=np.uint8), ff)
    assert hits and hits[0][2] == (FLAG,)
    assert hits[0][0] == f"bit offset {offset}, {order}-first" + (", inverted" if inverted else "")
    assert [h for h in hits if h[2]] == [hits[0]]                   # no other reading carries it
    as_text = iqd.crib_bits("".join(map(str, bits)), ff)            # a bit string reads the same
    assert as_text[0][:3] == hits[0][:3]


def test_crib_bits_reports_a_lead_and_nothing_else(ff):
    lead_only = iqd.crib_bits(np.array(syn.bits_of(b"xx CSCTF{cut_off"), dtype=np.uint8), ff)
    assert lead_only and lead_only[0][2] == () and lead_only[0][3] is True
    rng = np.random.default_rng(2)
    assert iqd.crib_bits(rng.integers(0, 2, 4000).astype(np.uint8), ff) == []


def test_the_wav_adapter_crib_step_is_usable_on_its_own(ff):
    # B-158 builds on B-083's framings and ranking: wav_linecode exposes them as two functions
    import wav_linecode as wl
    text = "".join(map(str, syn.bits_of(b"\xaa\x7e" + FLAG.encode() + b"\x00")))
    noise = "".join(map(str, np.random.default_rng(1).integers(0, 2, 400).tolist()))
    cands = wl.stream_candidates({"a:nrz": text, "b:nrz": noise, "short": "010000010101"}, ff,
                                 byte_sources={"u:uart": b"xx\x7e" + FLAG.encode()})
    assert {c.scheme for c in cands} == {"a:nrz", "b:nrz", "u:uart"}            # under 16 bits is not a stream
    assert {(c.scheme, c.framing, c.bit_order) for c in cands if c.flags} == {
        ("a:nrz", "raw", "msb"), ("a:nrz", "sync", "msb"), ("u:uart", "raw", "lsb"), ("u:uart", "sync", "lsb")}
    ranked = wl.rank_candidates(list(reversed(cands)))
    assert ranked[0].flags == (FLAG,) and ranked[0].data == FLAG.encode()       # the tightest framing of the flag
    assert [bool(c.flags) for c in ranked] == sorted((bool(c.flags) for c in ranked), reverse=True)
    assert wl.stream_candidates({}, ff) == []


# ---- GFSK ------------------------------------------------------------------------------------------

def gfsk_capture(frame, sps=10.4, deviation=0.05, bt=0.5, lead=700, tail=900, cfo=0.01, sigma=0.05, seed=1):
    return syn.channel(syn.fsk_iq(syn.bits_of(frame), sps, deviation, bt=bt), lead=lead, tail=tail, cfo=cfo,
                       sigma=sigma, seed=seed)


def test_gfsk_bits_recovers_the_bits_and_the_bit_clock_without_a_rate():
    data = b"\xaa\xaa\x2d\xd4" + bytes(range(40, 72))
    bits = syn.bits_of(data)
    got = iqd.gfsk_bits(syn.fsk_iq(bits, 7.3, 0.04, bt=0.5))
    assert got is not None
    assert got["sps"] == pytest.approx(7.3, rel=0.01)
    assert got["bits"].tolist() == bits
    assert got["eye"] > 8 and got["run_fit"] > 0.95
    assert got["deviation"] == pytest.approx(2 * np.pi * 0.04, rel=0.12)


def test_gfsk_bits_rejects_what_is_not_two_level():
    assert iqd.gfsk_bits(np.exp(2j * np.pi * 0.01 * np.arange(4000))) is None      # a bare carrier
    assert iqd.gfsk_bits(np.ones(10, dtype=complex)) is None


def test_gfsk_frame_with_a_sync_word_gives_the_flag_and_the_baud(ff):
    frame = b"\xaa\xaa\xaa\xaa\x7e" + FLAG.encode() + b"\x00\x00"
    res = iqd.demod_gfsk(cap_of(gfsk_capture(frame), 250000), ff)
    assert res.flags == (FLAG,)
    assert res.params["baud"] == pytest.approx(250000 / 10.4, rel=0.01)
    assert res.params["deviation_hz"] == pytest.approx(0.05 * 250000, rel=0.12)
    best = max(res.frames, key=iqd._rank)
    assert best.flags == (FLAG,) and "framing sync" in best.summary


def test_gfsk_needs_no_sample_rate(ff):
    frame = b"\xaa\xaa\xaa\xaa\x7e" + FLAG.encode() + b"\x00\x00"
    res = iqd.demod_gfsk(cap_of(gfsk_capture(frame), None), ff)
    assert res.flags == (FLAG,) and "baud" not in res.params and res.params["samples_per_bit"] == pytest.approx(10.4, rel=0.01)


def test_gfsk_flag_at_an_odd_bit_offset_is_found_by_bit_slip(ff):
    bits = [1, 0] * 20 + [1, 1, 0] + syn.bits_of(FLAG.encode()) + [0, 1] * 8
    iq = syn.channel(syn.fsk_iq(bits, 8.0, 0.06), lead=300, tail=300, sigma=0.03)
    res = iqd.demod_gfsk(cap_of(iq, None), ff)
    assert res.flags == (FLAG,)
    hit = next(f for f in res.frames if f.flags)
    assert "bit offset" in hit.summary and "bit offset 0" not in hit.summary   # not on a byte boundary
    assert hit.data.find(FLAG.encode()) >= 0


def _pn9(data, seed=0x1FF):
    """CC1101 data whitening: x^9 + x^5 + 1, the low bit of the state XORs each data bit, LSB first."""
    state, out = seed, bytearray()
    for byte in data:
        value = 0
        for bit in range(8):
            value |= (((byte >> bit) & 1) ^ (state & 1)) << bit
            state = (state >> 1) | ((((state >> 0) ^ (state >> 5)) & 1) << 8)
        out.append(value)
    return bytes(out)


def test_gfsk_pn9_whitened_payload_after_a_sync_word(ff):
    assert _pn9(b"\x00" * 4).hex() == "ffe11d9a"            # the published CC1101 PN9 sequence start
    frame = b"\xaa\xaa\xaa\xaa\xd3\x91" + _pn9(bytes([len(FLAG)]) + FLAG.encode() + b"\x12\x34")
    res = iqd.demod_gfsk(cap_of(gfsk_capture(frame, sps=8.0), 100000), ff)
    assert res.flags == (FLAG,)
    hit = next(f for f in res.frames if f.flags)
    assert hit.fields == {"sync_word": "d391", "whitening": "pn9"}


def test_gfsk_manchester_coded_frame(ff):
    payload = b"\xaa\xaa\x7e" + FLAG.encode() + b"\x00"
    chips = []
    for b in syn.bits_of(payload):
        chips += [0, 1] if b else [1, 0]                       # IEEE 802.3: 1 is low-to-high
    iq = syn.channel(syn.fsk_iq(chips, 6.0, 0.06), lead=200, tail=200, sigma=0.03)
    res = iqd.demod_gfsk(cap_of(iq, None), ff)
    assert res.flags == (FLAG,)
    assert any("manchester_ieee" in f.summary for f in res.frames if f.flags)


def test_gfsk_slow_burst_in_a_long_noisy_capture(ff):
    # 40 samples per bit, deviation near the discriminator noise: needs the long smoothing window
    # and the slicer's hysteresis (a plain slice chatters at every crossing and reads a 1-sample bit)
    frame = b"\xaa\xaa\xaa\xaa\x7e" + FLAG.encode() + b"\x00\x00"
    iq = syn.noise(300000, 0.07, 3)
    burst = syn.fsk_iq(syn.bits_of(frame), 40.0, 0.01, bt=0.5)
    iq[120000:120000 + burst.size] += burst
    res = iqd.demod_gfsk(cap_of(iq, 2000000), ff)
    assert res.flags == (FLAG,)
    assert res.params["samples_per_bit"] == pytest.approx(40.0, rel=0.01) and res.params["bursts"] == 1
    got = iqd.gfsk_bits(iq[120000 - 16:120000 + burst.size + 16])
    assert got["smoothing"] >= 9 and got["eye"] > 6 and got["run_fit"] > 0.9


def test_gfsk_noise_and_a_carrier_give_no_frames(ff):
    noise = iqd.demod_gfsk(cap_of(syn.noise(20000, 1.0, 9), 250000), ff)
    assert noise.frames == [] and noise.note == "no two-level FSK burst found"
    reading = iqd.gfsk_bits(syn.noise(20000, 1.0, 9))             # noise slices into runs, but not into bits
    assert reading is not None and reading["run_fit"] < 0.6 < iqd.GFSK_MIN_RUN_FIT
    tone = iqd.demod_gfsk(cap_of(np.exp(2j * np.pi * 0.02 * np.arange(20000)), 250000), ff)
    assert tone.frames == []


def test_gfsk_selection_is_by_the_event_prefix_not_a_hardcoded_one():
    spec = event.FlagSpec(prefixes=("ZZTOP",), body=flagfmt.current().spec.body, case="exact")
    other = flagfmt.FlagFormat(spec)
    frame = b"\xaa\xaa\xaa\xaa\x7e" + FLAG.encode() + b"\x00\x00"
    res = iqd.demod_gfsk(cap_of(gfsk_capture(frame), 250000), other)
    assert res.flags == ()
    zz = b"\xaa\xaa\xaa\xaa\x7e" + b"ZZTOP{other_event_flag}" + b"\x00\x00"
    assert iqd.demod_gfsk(cap_of(gfsk_capture(zz), 250000), other).flags == ("ZZTOP{other_event_flag}",)


# ---- POCSAG ----------------------------------------------------------------------------------------

def pocsag_capture(rate, baud, address=1234567, text="PAGE " + FLAG, cfo=0.003, sigma=0.05, invert=False):
    bits = syn.pocsag_bits(address, text)
    # POCSAG keys a 1 as the lower frequency (-4.5 kHz)
    iq = syn.fsk_iq([1 - b for b in bits], rate / baud, 4500.0 / rate)
    iq = syn.channel(iq, lead=int(rate * 0.1), tail=int(rate * 0.1), cfo=cfo, sigma=sigma)
    return np.conj(iq) if invert else iq


def test_the_test_encoder_reproduces_the_published_pocsag_codewords():
    # the idle and sync codewords are fixed by the standard: both must be codewords of this encoder
    assert syn.pocsag_codeword(syn.POCSAG_IDLE >> 11) == syn.POCSAG_IDLE == 0x7A89C197
    assert syn.pocsag_codeword(syn.POCSAG_SYNC >> 11) == syn.POCSAG_SYNC == 0x7CD215D8


@pytest.mark.parametrize("rate,baud", [(22050, 512), (22050, 1200), (48000, 2400), (250000, 1200)])
def test_pocsag_message_from_iq_at_each_baud_and_awkward_rates(ff, rate, baud):
    res = iqd.demod_pocsag(cap_of(pocsag_capture(rate, baud), rate), ff)
    assert res.params["baud"] == baud
    assert res.params["polarity"] == "1 = lower frequency (standard)"
    assert len(res.frames) == 1
    msg = res.frames[0]
    assert msg.fields["address"] == 1234567 and msg.fields["function"] == 3
    assert msg.fields["alphanumeric"] == "PAGE " + FLAG
    assert msg.fields["corrected_bits"] == []                  # every codeword arrived intact
    assert msg.flags == (FLAG,) and msg.validated


def test_pocsag_with_a_carrier_offset_larger_than_the_deviation(ff):
    # the receiver was tuned 6 kHz off: both tones are on one side of zero, so the slicer must find
    # the midpoint of the two tones itself
    res = iqd.demod_pocsag(cap_of(pocsag_capture(48000, 1200, cfo=6000.0 / 48000), 48000), ff)
    assert res.flags == (FLAG,) and res.params["polarity"] == "1 = lower frequency (standard)"


def test_pocsag_spectrum_inverted_capture(ff):
    res = iqd.demod_pocsag(cap_of(pocsag_capture(48000, 1200, invert=True), 48000), ff)
    assert res.params["polarity"] == "1 = higher frequency (inverted)"
    assert res.flags == (FLAG,)


def test_pocsag_agrees_with_the_carried_integral_rate_chain(ff):
    import rf_demod_full as rfd
    iq = pocsag_capture(12000, 1200, address=88, text="CROSS CHECK 42", cfo=0.0, sigma=0.0)
    ours = iqd.demod_pocsag(cap_of(iq, 12000), ff)
    theirs = rfd.acquire_pocsag([complex(v) for v in iq], 12000.0)
    assert theirs["acquired"] and theirs["baud"] == 1200
    assert [(m["address"], m["function"], m["alphanumeric"]) for m in theirs["messages"]] == \
        [(f.fields["address"], f.fields["function"], f.fields["alphanumeric"]) for f in ours.frames] == \
        [(88, 3, "CROSS CHECK 42")]


def test_pocsag_names_why_it_did_not_run_or_found_nothing(ff):
    iq = pocsag_capture(22050, 1200)
    assert iqd.demod_pocsag(cap_of(iq, None), ff).error == "pocsag: the sample rate is unknown (pass --rate)"
    low = iqd.demod_pocsag(cap_of(syn.noise(20000, 1.0, 4), 4000), ff)   # under 2 samples at 2400 baud
    assert low.frames == [] and "2400 baud needs >= 4800 Hz" in low.note
    assert low.params == {"not_tried": "2400 baud needs >= 4800 Hz"}
    noise = iqd.demod_pocsag(cap_of(syn.noise(40000, 1.0, 3), 22050), ff)
    assert noise.frames == [] and "no POCSAG sync word" in noise.note
    audio = iqd.Capture("a.wav", "wav-audio", 22050.0, "wav", audio=np.zeros(100))
    assert "needs IQ" in iqd.demod_pocsag(audio, ff).error


def test_fsk_symbols_reads_bits_at_a_fractional_clock():
    bits = np.random.default_rng(6).integers(0, 2, 400)
    sps = 18.375
    d = np.repeat(bits * 2.0 - 1.0, 147)[::8]                  # 147 / 8 samples per bit
    got, eye = iqd.fsk_symbols(d, sps)
    assert got.tolist() == bits.tolist()[:got.size] and got.size >= 399
    assert eye > 10
    assert iqd.fsk_symbols(d[:20], sps)[0].size == 0


# ---- P25 -------------------------------------------------------------------------------------------

def test_the_test_encoder_nid_matches_the_published_generator_matrix():
    # iq_synth divides by the standard's generator polynomial; sec_lmr_p25 carries OP25's generator
    # matrix. Agreement on every data unit pins the test's transmitter against a second source.
    import sec_lmr_p25 as p25
    for nac in (0x000, 0x001, 0x293, 0x800, 0xFFF):
        for duid in (0x0, 0x3, 0x5, 0x7, 0xA, 0xC, 0xF):
            assert syn.p25_nid(nac, duid) == p25._bch_codeword((nac << 4) | duid), (nac, duid)


@pytest.mark.parametrize("rate,sps", [(48000, 10.0), (50000, 50000 / 4800.0), (24000, 5.0)])
def test_p25_dibits_are_the_transmitted_bits(rate, sps):
    bits = syn.p25_frame_bits(0x293, 0x5, seed=8)
    iq = syn.channel(syn.c4fm_iq(bits, sps, rate=rate), lead=777, tail=600, cfo=0.004, sigma=0.03)
    hits = iqd.p25_dibits(iq, rate)
    assert len(hits) == 1
    hit = hits[0]
    assert hit["bits"][:len(bits)].tolist() == bits
    assert hit["correlation"] > 0.95 and hit["inverted"] is False
    assert abs(hit["sample"] - (777 + 8.5 * sps)) <= sps / 2        # the centre of the first sync symbol
    assert hit["deviation_hz"] == pytest.approx(1800.0, rel=0.05)
    assert hit["offset_hz"] == pytest.approx(0.004 * rate, abs=30.0)


def test_p25_slicer_follows_a_carrier_offset_of_most_of_a_level(ff):
    # 900 Hz off tune: the levels sit at -900, +300, +1500, +2700 Hz, so fixed thresholds misread them
    bits = syn.p25_frame_bits(0x293, 0x5, seed=8)
    iq = syn.channel(syn.c4fm_iq(bits, 10), lead=500, tail=500, cfo=900.0 / 48000, sigma=0.03)
    (hit,) = iqd.p25_dibits(iq, 48000)
    assert hit["bits"][:len(bits)].tolist() == bits
    assert hit["offset_hz"] == pytest.approx(900.0, abs=30.0)


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_p25_slicer_splits_the_levels_midway_under_noise_and_low_deviation(ff, seed):
    # 10% under the nominal 600 Hz per level, in noise: the outer/inner split must sit midway
    # between the levels (2 in level units). Moved to 2.4 or 1.6, a few symbols in this LDU1 slip.
    bits = syn.p25_frame_bits(0x293, 0x5, seed=8)
    iq = syn.channel(syn.c4fm_iq(bits, 10, deviation_hz=540.0), lead=500, tail=500, cfo=0.002, sigma=0.2, seed=seed)
    (hit,) = iqd.p25_dibits(iq, 48000)
    assert hit["bits"][:len(bits)].tolist() == bits
    assert hit["deviation_hz"] == pytest.approx(1620.0, rel=0.05)
    frames = [f for f in iqd.demod_p25(cap_of(iq, 48000), ff).frames if f.validated]
    assert [f.fields["data_unit"] for f in frames] == ["LDU1"]
    assert frames[0].data == iqd.pack_bits(iqd.p25_strip_status(np.array(bits))[112:])


def test_p25_frames_reach_the_bit_level_parser_and_the_crib(ff):
    payload = syn.bits_of(b"\x00\x00" + FLAG.encode())
    bits = (syn.p25_frame_bits(0x293, 0x3) + syn.p25_frame_bits(0x293, 0x0, payload)
            + syn.p25_frame_bits(0x293, 0x5) + syn.p25_frame_bits(0x293, 0xA) + syn.p25_frame_bits(0x293, 0xF))
    iq = syn.channel(syn.c4fm_iq(bits, 10), lead=1000, tail=1000, cfo=0.003, sigma=0.05)
    res = iqd.demod_p25(cap_of(iq, 48000), ff)
    frames = [f for f in res.frames if f.validated]
    assert [f.fields["data_unit"] for f in frames] == ["TDU", "HDU", "LDU1", "LDU2", "TDULC"]
    assert [f.fields["bit_length"] for f in frames] == [144, 792, 1728, 1728, 432]
    assert all(f.fields["nac"] == 0x293 for f in frames)
    starts = [f.fields["sample"] for f in frames]
    want = [1000 + 85 + 10 * n // 2 for n in (0, 144, 144 + 792, 144 + 792 + 1728, 144 + 792 + 2 * 1728)]
    assert all(abs(a - b) <= 3 for a, b in zip(starts, want))
    hdu = frames[1]
    assert [r["name"] for r in hdu.fields["regions"]] == ["frame_sync", "nid", "encoded_header", "null"]
    # the flag was planted in the structural bits: the status symbol every 70 bits is removed first
    assert res.flags == (FLAG,) and hdu.flags == (FLAG,)
    assert res.params == {"samples_per_symbol": 10.0, "frame_syncs": 5, "nid_failures": 0}
    assert res.note == "payload beyond the NID stays FEC-coded (not decoded here)"      # what a frame is not


def test_p25_packet_data_unit_runs_to_the_next_frame_sync(ff):
    # a PDU has no fixed length: the parser takes any, so the frame must end where the next one starts
    bits = (syn.p25_frame_bits(0x111, 0x3) + syn.p25_frame_bits(0x111, 0xC, total=576, seed=9)
            + syn.p25_frame_bits(0x111, 0x3))
    iq = syn.channel(syn.c4fm_iq(bits, 10), lead=400, tail=400, sigma=0.03)
    frames = [f for f in iqd.demod_p25(cap_of(iq, 48000), ff).frames if f.validated]
    assert [(f.fields["data_unit"], f.fields["bit_length"]) for f in frames] == [("TDU", 144), ("PDU", 576), ("TDU", 144)]
    assert frames[1].data == iqd.pack_bits(iqd.p25_strip_status(np.array(bits[144:144 + 576]))[112:])


def test_p25_strip_status_removes_two_bits_in_seventy_two():
    bits = np.arange(150) % 2
    kept = iqd.p25_strip_status(bits)
    assert kept.size == 146
    assert kept.tolist() == [b for i, b in enumerate(bits.tolist()) if i % 72 < 70]


def test_p25_spectrum_inverted_capture(ff):
    bits = syn.p25_frame_bits(0x5A5, 0x7, seed=3)
    iq = np.conj(syn.channel(syn.c4fm_iq(bits, 10), lead=500, tail=500, sigma=0.03))
    res = iqd.demod_p25(cap_of(iq, 48000), ff)
    frames = [f for f in res.frames if f.validated]
    assert len(frames) == 1 and frames[0].fields["data_unit"] == "TSDU" and frames[0].fields["nac"] == 0x5A5
    assert frames[0].fields["inverted"] is True
    assert frames[0].data == iqd.pack_bits(iqd.p25_strip_status(np.array(bits))[112:])


def test_p25_a_sync_without_a_valid_nid_is_counted_not_framed(ff):
    bits = syn.p25_frame_bits(0x293, 0x3)
    for i in range(48, 48 + 22, 2):                                # wreck 11 NID bits
        bits[i] ^= 1
    iq = syn.channel(syn.c4fm_iq(bits, 10), lead=500, tail=500)
    res = iqd.demod_p25(cap_of(iq, 48000), ff)
    assert res.frames == [] and res.params["frame_syncs"] == 1 and res.params["nid_failures"] == 1
    assert res.note == "1 frame sync(s) found but no NID decoded"


def test_p25_names_why_it_did_not_run_or_found_nothing(ff):
    assert iqd.demod_p25(cap_of(syn.noise(100, 1.0, 1), None), ff).error == "p25: the sample rate is unknown (pass --rate)"
    with pytest.raises(iqd.IQDemodError, match="under 2 samples per C4FM symbol"):
        iqd.p25_dibits(syn.noise(1000, 1.0, 1), 8000)
    noise = iqd.demod_p25(cap_of(syn.noise(30000, 1.0, 2), 48000), ff)
    assert noise.frames == [] and noise.note == "no P25 phase-1 frame sync (0x5575F5FF77FF) in the C4FM symbol stream"


# ---- TETRA -----------------------------------------------------------------------------------------

def test_tetra_dibits_follow_the_etsi_phase_mapping():
    steps = np.exp(1j * np.array([np.pi / 4, 3 * np.pi / 4, -3 * np.pi / 4, -np.pi / 4]))
    assert iqd.tetra_dibits(steps).tolist() == [0, 0, 0, 1, 1, 1, 1, 0]
    # a quarter turn of residual carrier moves every step one quadrant on; the argument undoes it
    assert iqd.tetra_dibits(steps * 1j, quarter_turns=1).tolist() == [0, 0, 0, 1, 1, 1, 1, 0]
    assert iqd.tetra_dibits(steps * 1j).tolist() == [0, 1, 1, 1, 1, 0, 0, 0]
    # I/Q swapped: every step is mirrored
    assert iqd.tetra_dibits(np.conj(steps), inverted=True).tolist() == [0, 0, 0, 1, 1, 1, 1, 0]


def test_rrc_taps_are_unit_energy_and_a_matched_pair_is_nyquist():
    for sps in (4.0, 5.5):
        taps = iqd.rrc_taps(sps)
        assert float(np.sum(taps * taps)) == pytest.approx(1.0)
        assert np.allclose(taps, taps[::-1])
    taps = iqd.rrc_taps(4.0)
    pair = np.convolve(taps, taps)
    mid = pair.size // 2
    assert pair[mid] == pytest.approx(1.0, abs=1e-3)
    others = pair[mid % 4::4]
    assert np.sum(np.abs(others) > 0.02) == 1                  # zero at every other symbol instant


def tetra_downlink(seed=3, n=5):
    rng = np.random.default_rng(seed)
    kinds = [syn.tetra_ndb(rng), syn.tetra_sb(rng), syn.tetra_ndb(rng, syn.TETRA_N2)]
    kinds += [syn.tetra_ndb(rng) for _ in range(n - 3)]
    return "".join(kinds)


def test_tetra_symbols_recover_the_transmitted_bits_and_the_carrier_offset():
    bits = tetra_downlink()
    iq = syn.channel(syn.pi4dqpsk_iq(bits, 4), cfo=0.0015, sigma=0.02)
    sym = iqd.tetra_symbols(iq, 72000)
    assert sym["lock"] > 0.9 and sym["sps"] == 4.0
    assert sym["coarse_step"] + sym["cfo_step"] == pytest.approx(2 * np.pi * 0.0015 * 4, abs=0.01)
    assert abs(sym["cfo_step"]) < 0.2                              # the spectrum centre took most of it
    got = iqd.tetra_dibits(sym["d"])
    assert got.size == len(bits)
    assert "".join(map(str, got.tolist())) == bits


def test_tetra_noise_has_no_symbol_lock():
    for seed in (5, 6, 7, 8):
        assert iqd.tetra_symbols(syn.noise(40000, 1.0, seed), 72000)["lock"] < 0.08 < iqd.TETRA_MIN_LOCK
    with pytest.raises(iqd.IQDemodError, match="under 2 samples per symbol"):
        iqd.tetra_symbols(syn.noise(4000, 1.0, 5), 24000)


@pytest.mark.parametrize("rate,cfo_hz", [(72000, 150.0), (100000, -400.0), (288000, 900.0), (72000, 3000.0),
                                         (288000, -20000.0)])
def test_tetra_downlink_bursts_at_whole_fractional_and_high_rates(ff, rate, cfo_hz):
    bits = tetra_downlink()
    base = syn.pi4dqpsk_iq(bits, 16)                             # 288 kHz
    iq = base if rate == 288000 else syn.resample(base, rate / 288000.0)
    iq = syn.channel(iq, cfo=cfo_hz / rate, sigma=0.02)
    res = iqd.demod_tetra(cap_of(iq, rate), ff)
    frames = [f for f in res.frames if f.validated]
    assert [f.fields["burst_type"] for f in frames] == ["ndb-cont", "sb-cont", "ndb-cont", "ndb-cont", "ndb-cont"]
    assert [f.fields["bit"] for f in frames] == [0, 510, 1020, 1530, 2040]
    assert [f.fields["training"] for f in frames] == [
        {"normal": "normal-1"}, {"frequency_correction": True, "sync": True}, {"normal": "normal-2"},
        {"normal": "normal-1"}, {"normal": "normal-1"}]
    assert all(f.fields["training_valid"] and f.validated == "all ETSI training sequences" for f in frames)
    assert frames[0].data == iqd.pack_bits(bits[:510])
    assert res.note == "burst blocks stay scrambled and FEC-coded (not decoded here)"
    # 3 kHz is past a quarter turn per symbol; 20 kHz is outside the matched filter until re-centred
    assert res.params["carrier_offset_hz"] == pytest.approx(cfo_hz, abs=40.0)
    assert res.params["inverted"] is False and res.params["lock"] > 0.8
    # a high rate is averaged down to 4-8 samples per symbol before the matched filter
    assert res.params["samples_per_symbol"] == {72000: 4.0, 100000: 5.556, 288000: 4.0}[rate]


def test_tetra_uplink_bursts_between_silence(ff):
    rng = np.random.default_rng(12)
    a, b = syn.tetra_nub(rng), syn.tetra_nub(rng, syn.TETRA_N2)
    gap = np.zeros(900, dtype=complex)
    iq = np.concatenate((gap, syn.pi4dqpsk_iq(a, 4), gap, syn.pi4dqpsk_iq(b, 4), gap))
    res = iqd.demod_tetra(cap_of(syn.channel(iq, cfo=0.001, sigma=0.02), 72000), ff)
    frames = [f for f in res.frames if f.validated]
    assert [f.fields["burst_type"] for f in frames] == ["nub", "nub"]
    assert [f.fields["training"] for f in frames] == [{"normal": "normal-1"}, {"normal": "normal-2"}]
    assert frames[0].data == iqd.pack_bits(a) and frames[1].data == iqd.pack_bits(b)


def test_tetra_a_wrong_stated_centre_is_recovered_by_the_quarter_turn_search(ff):
    # the 4th-power law knows the carrier step only modulo a quarter turn (4.5 kHz); told the carrier
    # is at 0 when it is 3 kHz up, the demodulator must still land on the right quadrant
    iq = syn.channel(syn.pi4dqpsk_iq(tetra_downlink(), 4), cfo=3000.0 / 72000, sigma=0.02)
    res = iqd.demod_tetra(cap_of(iq, 72000), ff, centre_hz=0.0)
    assert len([f for f in res.frames if f.fields.get("training_valid")]) == 5
    assert res.params["carrier_offset_hz"] == pytest.approx(3000.0, abs=40.0)
    assert res.params["centre"] == "stated (--centre-hz)"
    sym = iqd.tetra_symbols(iq, 72000, centre_hz=0.0)
    assert sym["coarse_step"] == 0.0 and abs(sym["cfo_step"]) < math.pi / 4      # the law alone falls short
    told = iqd.demodulate(cap_of(iq, 72000), ["tetra"], ff=ff, centre_hz=3000.0).results[0]
    assert told.params["carrier_offset_hz"] == pytest.approx(3000.0, abs=40.0)
    assert told.params["centre"] == "stated (--centre-hz)"
    found = iqd.demodulate(cap_of(iq, 72000), ["tetra"], ff=ff).results[0]
    assert found.params["centre"] == "centre of the spectrum" and len(found.frames) == 5


def test_tetra_spectrum_inverted_capture(ff):
    iq = np.conj(syn.channel(syn.pi4dqpsk_iq(tetra_downlink(), 4), cfo=0.001, sigma=0.02))
    res = iqd.demod_tetra(cap_of(iq, 72000), ff)
    assert res.params["inverted"] is True
    assert len([f for f in res.frames if f.fields.get("training_valid")]) == 5


def test_tetra_flag_in_a_burst_block_is_found_by_the_crib(ff):
    rng = np.random.default_rng(21)
    flag_bits = "".join(map(str, syn.bits_of(b"CSCTF{tetra_blk_7}")))
    block = (flag_bits + syn._rand_bits(216, rng))[:216]
    bits = syn.tetra_ndb(rng) + syn.tetra_ndb(rng, block1=block) + syn.tetra_ndb(rng)
    res = iqd.demod_tetra(cap_of(syn.channel(syn.pi4dqpsk_iq(bits, 4), sigma=0.02), 72000), ff)
    assert res.flags == ("CSCTF{tetra_blk_7}",)
    assert len([f for f in res.frames if f.validated]) == 3


def test_tetra_bursts_tolerates_one_wrong_training_bit_and_no_more():
    rng = np.random.default_rng(31)
    clean = np.array(list(map(int, syn.tetra_ndb(rng) + syn.tetra_ndb(rng))), dtype=np.uint8)
    assert [b["bit"] for b in iqd.tetra_bursts(clean)] == [0, 510]
    one = clean.copy()
    one[244 + 5] ^= 1                                               # one bit of the first training
    found = iqd.tetra_bursts(one)
    assert [b["bit"] for b in found] == [0, 510]
    assert found[0]["training_errors"] == 1 and found[0]["report"]["training_valid"] is False
    two = one.copy()
    two[244 + 11] ^= 1
    assert [b["bit"] for b in iqd.tetra_bursts(two)] == [510]


def test_tetra_bursts_an_all_exact_layout_beats_one_with_more_checks_right_but_one_wrong(monkeypatch):
    # In the ETSI pi/4 table every layout that holds a given training sequence has the same number
    # of sequence checks, so "all checks exact" and "most checks valid" never disagree there. The
    # rule still matters if the parser's table grows: a layout whose every check is exact proves the
    # burst type, and must win over a longer one that gets more checks right but has one wrong.
    # Here a made-up pi/4 layout "xb" (an uplink burst plus three trailing tails) is added to the
    # parser's table; the stream holds an exact uplink burst followed by two good tails and a bad one.
    import sec_lmr_tetra as tetra
    xb = tetra._LAYOUTS[("nub", "pi/4")] + (("x1", 4, "tail"), ("x2", 4, "tail"), ("x3", 4, "tail"))
    monkeypatch.setitem(tetra._LAYOUTS, ("xb", "pi/4"), xb)
    monkeypatch.setitem(tetra._BURST_NAMES, "xb", "test-only longer uplink burst")
    nub = "1100" + "0" * 216 + syn.TETRA_N1 + "0" * 216 + "1100"
    stream = nub + "1100" + "1100" + "0000" + "0" * 20
    found = iqd.tetra_bursts(np.array(list(map(int, stream)), dtype=np.uint8))
    assert len(found) == 1
    row = found[0]
    assert (row["bit"], row["training_bit"], row["training_errors"]) == (0, 220, 0)
    assert row["report"]["burst_type"] == "nub" and row["report"]["training_valid"] is True
    assert row["bits"].size == 462
    # the losing reading really did get more checks right: 5 of 6 against 3 of 3
    loser = tetra.parse_air_burst(iqd.pack_bits(stream[:474] + "0" * 6), 474, burst_type="xb",
                                  modulation="pi/4")
    assert sum(r["valid"] for r in loser["sequence_checks"]) == 5 and loser["training_valid"] is False


@pytest.mark.parametrize("seed", [1, 2])
def test_tetra_bursts_a_valid_burst_replaces_an_overlapping_chance_match(seed):
    # a training sequence with one wrong bit turns up at bit 250 of the filler, so a burst "starting"
    # before the real one at bit 300 is read first; the real burst, every sequence exact, must win
    rng = np.random.default_rng(seed)
    pre = list(syn._rand_bits(300, rng))
    hurt = list(syn.TETRA_N1)
    hurt[5] = "1" if hurt[5] == "0" else "0"
    pre[250:272] = hurt
    stream = "".join(pre) + syn.tetra_ndb(rng) + syn.tetra_ndb(rng, syn.TETRA_N2) + syn._rand_bits(300, rng)
    found = iqd.tetra_bursts(np.array(list(map(int, stream)), dtype=np.uint8))
    assert [(b["bit"], b["report"]["training_valid"]) for b in found] == [(300, True), (810, True)]
    assert found[0]["training_bit"] == 300 + 244 and found[0]["training_errors"] == 0


def test_tetra_a_lone_burst_with_a_wrong_training_bit_is_not_reported(ff):
    # one error is allowed in a training sequence, but a 22-bit match with one error also occurs by
    # chance in a long stream, so it counts only beside a burst whose sequences are all exact
    rng = np.random.default_rng(41)
    hurt = list(syn.tetra_ndb(rng))
    hurt[244 + 3] = "1" if hurt[244 + 3] == "0" else "0"
    hurt = "".join(hurt)
    filler = syn._rand_bits(510, rng)
    alone = iqd.demod_tetra(cap_of(syn.channel(syn.pi4dqpsk_iq(filler + hurt + filler, 4), sigma=0.02), 72000), ff)
    assert [f for f in alone.frames if f.validated] == [] and alone.params["bursts"] == 0
    assert alone.note == ("pi/4-DQPSK symbol lock but no TETRA burst with its training sequences intact "
                          "(1 lone training-sequence match(es) with a wrong bit: not reported)")
    beside = iqd.demod_tetra(cap_of(syn.channel(syn.pi4dqpsk_iq(syn.tetra_ndb(rng) + hurt + filler, 4), sigma=0.02), 72000), ff)
    frames = [f for f in beside.frames if f.validated]
    assert [f.fields["bit"] for f in frames] == [0, 510]
    assert [f.validated for f in frames] == ["all ETSI training sequences", "training sequence"]
    assert frames[1].fields["training_errors"] == 1 and frames[1].fields["training_valid"] is False


def test_tetra_symbol_lock_on_another_signal_is_not_a_burst(ff):
    fsk = syn.fsk_iq(np.random.default_rng(3).integers(0, 2, 3000).tolist(), 4.0, 0.03)
    res = iqd.demod_tetra(cap_of(syn.channel(fsk, sigma=0.02), 72000), ff)
    assert [f for f in res.frames if f.validated] == []
    assert res.note.startswith("pi/4-DQPSK symbol lock but no TETRA burst") or res.note.startswith("no pi/4-DQPSK symbol lock")


def test_sequence_hits_only_on_symbol_boundaries():
    seq = "1101000011101001110100"
    bits = np.array(list(map(int, "0" * 7 + seq + "0" * 9 + seq + "00")), dtype=np.uint8)
    assert iqd._sequence_hits(bits, seq, 0) == [(38, 0)]           # the copy at the odd offset 7 is not a burst
    assert iqd._sequence_hits(bits[:10], seq, 0) == []


def test_tetra_names_why_it_did_not_run_or_found_nothing(ff):
    assert iqd.demod_tetra(cap_of(syn.noise(100, 1.0, 1), None), ff).error == "tetra: the sample rate is unknown (pass --rate)"
    noise = iqd.demod_tetra(cap_of(syn.noise(40000, 1.0, 7), 72000), ff)
    assert [f for f in noise.frames if f.validated] == []
    assert noise.note.startswith("no pi/4-DQPSK symbol lock at 18000 symbols/s")


# ---- LoRa ------------------------------------------------------------------------------------------

def lora_symbols(payload, sf, cr, ldro=False, has_crc=True, implicit=False):
    import test_rf2_lora_phy as ref        # the test-only Tapparel transmit chain already in the suite
    return ref._ref_frame(payload, sf, cr, implicit=implicit, has_crc=has_crc, ldro=ldro)


def lora_capture(payload, sf, os=1, cr=1, ldro=False, lead=333, cfo_bins=0.0, sigma=0.1, **kw):
    n = 1 << sf
    pre = {k: kw.pop(k) for k in ("preamble", "sync_word") if k in kw}
    pkt = syn.lora_iq(lora_symbols(payload, sf, cr, ldro=ldro, **kw), sf, os, **pre)
    return syn.channel(pkt, lead=lead, tail=3 * n * os + 17, cfo=cfo_bins / (n * os), sigma=sigma)


def test_lora_dechirp_agrees_with_the_carried_aligned_demodulator():
    import rf_demod_full as rfd
    symbols = [0, 1, 37, 64, 100, 127, 5, 90]
    iq = np.concatenate([syn.lora_symbol(s, 7) for s in symbols])
    bins, share = iqd.lora_dechirp(iq, 0, 7)
    assert bins.tolist() == symbols == rfd.lora_symbol_bins(list(iq), 7)
    assert np.allclose(share, 1.0)                                  # a clean chirp is all in one bin
    assert iqd.lora_dechirp(iq, 0, 7, count=3)[0].tolist() == symbols[:3]
    assert iqd.lora_dechirp(iq, 128 * 6, 7)[0].tolist() == symbols[6:]
    down = np.concatenate([syn.lora_symbol(0, 7, down=True)] * 2)
    assert iqd.lora_dechirp(down, 0, 7, down=True)[0].tolist() == [0, 0]
    assert iqd.lora_dechirp(down, 0, 7)[1].max() < 0.2              # a downchirp is no upchirp symbol
    shifted = iq * np.exp(2j * np.pi * 3 * np.arange(iq.size) / 128)
    assert iqd.lora_dechirp(shifted, 0, 7, shift=3.0)[0].tolist() == symbols
    assert iqd.lora_dechirp(iq, 0, 7, os=1, pad=4)[0].tolist() == symbols


def test_fractional_shift_moves_a_tone_by_part_of_a_sample():
    n = np.arange(256)
    tone = np.exp(2j * np.pi * 10 * n / 256)
    assert np.allclose(iqd.fractional_shift(tone, 0.5), np.exp(2j * np.pi * 10 * (n + 0.5) / 256))
    assert np.allclose(iqd.fractional_shift(tone, -0.25), np.exp(2j * np.pi * 10 * (n - 0.25) / 256))
    assert np.allclose(iqd.fractional_shift(tone, 0.0), tone) and iqd.fractional_shift(tone[:0], 0.5).size == 0


def test_lora_dechirp_reads_oversampled_symbols():
    symbols = [3, 200, 77]
    iq = np.concatenate([syn.lora_symbol(s, 8, os=4) for s in symbols])
    bins, share = iqd.lora_dechirp(iq, 0, 8, os=4)
    assert bins.tolist() == symbols
    assert 0.6 < share.min() <= share.max() < 0.7                  # the per-chip average costs the band edges


@pytest.mark.parametrize("sf,os,cr,ldro,lead,cfo_bins", [
    (7, 1, 1, False, 333, 0.0),
    (7, 1, 4, False, 64, 0.4),            # a fractional carrier offset
    (8, 2, 4, False, 1001, 3.3),
    (9, 4, 2, False, 77, -5.5),
    (10, 1, 3, False, 2500, 20.0),
    (11, 1, 1, True, 5000, 2.0),          # low-data-rate optimisation
])
def test_lora_packet_from_an_unaligned_capture(ff, sf, os, cr, ldro, lead, cfo_bins):
    payload = FLAG.encode()
    iq = lora_capture(payload, sf, os=os, cr=cr, ldro=ldro, lead=lead, cfo_bins=cfo_bins)
    res = iqd.demod_lora(cap_of(iq, 125000.0 * os), ff, sfs=(sf,))
    assert len(res.frames) == 1
    f = res.frames[0]
    assert f.data == payload and f.flags == (FLAG,)
    assert f.validated == "payload CRC-16"
    assert (f.fields["spreading_factor"], f.fields["coding_rate"], f.fields["samples_per_chip"]) == (sf, cr, os)
    assert f.fields["low_data_rate_optimization"] is ldro
    assert f.fields["sync_word"] == "0x12" and f.fields["preamble_symbols"] == 8
    assert f.fields["cfo_bins"] == pytest.approx(cfo_bins, abs=0.15)
    assert abs(f.fields["start_sample"] - lead) <= os
    assert f.fields["bandwidth_hz"] == 125000.0 and f.fields["iq_swapped"] is False


def test_lora_half_a_chip_of_timing_offset_is_absorbed(ff):
    # sampled halfway between chips: every upchirp reads half a bin off, which the preamble's own
    # residual bin removes before the data symbols are read
    symbols = lora_symbols(FLAG.encode(), 8, 4)
    fine = syn.channel(syn.lora_iq(symbols, 8, os=4), lead=802, tail=4 * 256 * 3, sigma=0.05)
    res = iqd.demod_lora(cap_of(fine[::4], 125000.0), ff, sfs=(8,))        # 802 / 4 = 200.5 chips in
    assert res.flags == (FLAG,) and res.frames[0].fields["samples_per_chip"] == 1
    assert abs(res.frames[0].fields["start_sample"] - 200.5) <= 1
    assert res.frames[0].fields["corrected_codewords"] == 0                # read clean, not rescued by the FEC


def test_lora_oversampled_grid_moves_to_the_symbol_boundary(ff):
    # 200.5 chips in at 4 samples per chip: the first estimate is half a chip out, the second moves the
    # grid two samples; coding rate 4/5 corrects nothing, so every symbol must read right
    iq = lora_capture(FLAG.encode(), 8, os=4, cr=1, lead=802, sigma=0.05)
    res = iqd.demod_lora(cap_of(iq, 500000.0), ff, sfs=(8,))
    f = res.frames[0]
    assert f.data == FLAG.encode() and f.fields["corrected_codewords"] == 0
    assert abs(f.fields["start_sample"] - 802) <= 1
    for lead in (800, 801, 803):                                    # every sample phase of the chip
        (pkt,) = iqd.lora_acquire(syn.channel(syn.lora_iq(lora_symbols(b"phase", 8, 1), 8, os=4), lead=lead, tail=4096), 8, 4)
        assert abs(pkt["start"] - lead) <= 1 and pkt["symbol_quality"] > 0.8, lead


def test_lora_data_symbols_are_derotated_by_the_carrier_alone():
    # 2 samples per chip: the per-chip average reads a quarter chip late, which shows in the
    # preamble as a quarter bin. Taking that out of the data symbols as well smears each one across
    # its wrap (share about 0.65); with only the carrier removed they stay sharp. Both sample phases.
    symbols = lora_symbols(b"quarter chip", 8, 1)
    base = syn.lora_iq(symbols, 8, os=4)
    for lead, cfo_bins in ((800, 0.0), (801, 0.0), (800, 2.25)):
        iq = syn.channel(base, lead=lead, tail=4 * 256 * 3, cfo=cfo_bins / (256 * 4))[::2]
        (pkt,) = iqd.lora_acquire(iq, 8, 2)
        assert pkt["symbols"][:len(symbols)] == symbols
        assert pkt["symbol_quality"] > 0.78 and pkt["cfo_bins"] == pytest.approx(cfo_bins, abs=0.07), (lead, cfo_bins)


def test_lora_spreading_factor_is_found_not_assumed(ff):
    iq = lora_capture(FLAG.encode(), 9, cr=2, lead=4321, cfo_bins=1.7)
    res = iqd.demod_lora(cap_of(iq, 125000.0), ff)                  # every spreading factor is tried
    assert [f.fields["spreading_factor"] for f in res.frames] == [9]
    assert res.flags == (FLAG,)


def test_lora_reports_preamble_length_and_sync_word(ff):
    iq = lora_capture(b"public network frame", 8, preamble=12, sync_word=0x34, lead=900)
    res = iqd.demod_lora(cap_of(iq, 125000.0), ff, sfs=(8,))
    f = res.frames[0]
    assert f.data == b"public network frame" and f.flags == ()
    assert f.fields["sync_word"] == "0x34" and f.fields["preamble_symbols"] == 12


def test_lora_packet_without_a_crc_is_vouched_for_by_its_header_only(ff):
    iq = lora_capture(b"no crc on this one", 7, has_crc=False)
    res = iqd.demod_lora(cap_of(iq, 125000.0), ff, sfs=(7,))
    assert res.frames[0].data == b"no crc on this one"
    assert res.frames[0].validated == "explicit header checksum" and res.frames[0].fields["crc_present"] is False


def test_lora_implicit_header_needs_the_caller_to_state_it(ff):
    payload = b"implicit header payload!"
    iq = lora_capture(payload, 7, cr=2, implicit=True)
    blind = iqd.demod_lora(cap_of(iq, 125000.0), ff, sfs=(7,))
    assert blind.frames == [] and blind.params["preambles"] == 1
    assert "no packet passed its header checksum" in blind.note and "--lora-implicit" in blind.note
    told = iqd.demod_lora(cap_of(iq, 125000.0), ff, sfs=(7,), implicit=(len(payload), 2, 1))
    assert told.frames[0].data == payload and told.frames[0].validated == "payload CRC-16"


def test_lora_iq_swapped_capture(ff):
    iq = np.conj(lora_capture(FLAG.encode(), 7, lead=500, cfo_bins=1.0))
    res = iqd.demod_lora(cap_of(iq, 125000.0), ff, sfs=(7,))
    assert res.flags == (FLAG,) and res.frames[0].fields["iq_swapped"] is True


def test_lora_two_packets_in_one_capture(ff):
    iq = np.concatenate((lora_capture(b"first packet", 7, lead=200), lora_capture(FLAG.encode(), 7, lead=611, cfo_bins=0.3)))
    res = iqd.demod_lora(cap_of(iq, 125000.0), ff, sfs=(7,))
    assert [f.data for f in res.frames] == [b"first packet", FLAG.encode()]
    assert res.frames[0].fields["start_sample"] < res.frames[1].fields["start_sample"]


def test_lora_the_same_payload_sent_twice_is_two_frames(ff):
    one = lora_capture(b"repeat me", 7, lead=150)
    res = iqd.demod_lora(cap_of(np.concatenate((one, one)), 125000.0), ff, sfs=(7,))
    assert [f.data for f in res.frames] == [b"repeat me", b"repeat me"]
    assert res.frames[1].fields["start_sample"] - res.frames[0].fields["start_sample"] == one.size


def test_lora_implicit_header_without_a_crc_is_marked_unchecked(ff):
    payload = b"nothing vouches for this"
    iq = lora_capture(payload, 7, cr=1, implicit=True, has_crc=False)
    res = iqd.demod_lora(cap_of(iq, 125000.0), ff, sfs=(7,), implicit=(len(payload), 1, 0))
    assert res.frames[0].data == payload and res.frames[0].validated == ""
    assert "unchecked (implicit header, no CRC)" in res.frames[0].summary
    report = iqd.demodulate(cap_of(iq, 125000.0), ["lora"], ff=ff, lora_implicit=(len(payload), 1, 0))
    assert iqd.solver_result("c.cu8", report).status == "none"      # an unchecked reading is not a decode


def test_an_unchecked_reading_that_shows_the_flag_lead_is_unsure_not_none(ff):
    payload = b"CSCTF{cut_off_before_the_closing"                    # the lead, no closing brace
    iq = lora_capture(payload, 7, cr=1, implicit=True, has_crc=False)
    report = iqd.demodulate(cap_of(iq, 125000.0), ["lora"], ff=ff, lora_implicit=(len(payload), 1, 0))
    (frame,) = report.results[0].frames
    assert frame.validated == "" and frame.flags == () and frame.lead is True
    assert iqd.solver_result("c.cu8", report).status == "unsure"


def test_lora_cut_packet_and_noise_give_no_frame(ff):
    iq = lora_capture(FLAG.encode(), 7, lead=100)
    cut = iq[:100 + 128 * 30]                                       # the capture ends mid-payload
    res = iqd.demod_lora(cap_of(cut, 125000.0), ff, sfs=(7,))
    assert res.frames == [] and res.params["preambles"] == 1
    noise = iqd.demod_lora(cap_of(syn.noise(60000, 1.0, 4), 125000.0), ff)
    assert noise.frames == [] and noise.note == "no LoRa preamble + SFD found"


def test_lora_oversamplings_from_the_rate():
    assert iqd.lora_oversamplings(None) == [1, 2, 4, 8]
    assert iqd.lora_oversamplings(125000.0) == [1, 2, 3, 4, 6, 8, 12, 16]     # 125 kHz first, then narrower
    assert iqd.lora_oversamplings(500000.0) == [4, 2, 1, 8, 12, 16, 24, 32, 48, 64]
    assert iqd.lora_oversamplings(1000000.0) == [8, 4, 2, 16, 24, 32, 48, 64]
    assert iqd.lora_oversamplings(1024000.0) == []


def test_lora_names_a_rate_that_fits_no_bandwidth(ff):
    res = iqd.demod_lora(cap_of(syn.noise(5000, 1.0, 1), 1024000.0), ff)
    assert res.error.startswith("lora: 1.024e+06 Hz is not a whole multiple of a LoRa bandwidth")
    assert "--lora-os" in res.error
    stated = iqd.demod_lora(cap_of(lora_capture(FLAG.encode(), 7, os=2), 1024000.0), ff, sfs=(7,), oversamplings=[2])
    assert stated.flags == (FLAG,)


# ---- SSTV ------------------------------------------------------------------------------------------

COLOURS = [(200, 40, 90), (30, 220, 120), (128, 128, 128), (250, 10, 60), (60, 60, 200), (90, 180, 30),
           (10, 250, 250), (240, 240, 20)]


def audio_cap(samples, rate):
    return iqd.Capture("audio.wav", "wav-audio", float(rate), "wav", audio=np.asarray(samples, dtype=np.float64))


@pytest.mark.parametrize("rate,lead_ms", [(16000, 437.3), (48000, 1203.9), (11025, 250.0)])
def test_sstv_headers_finds_the_leader_wherever_it_starts(rate, lead_ms):
    audio = syn.scottie_lines(rate, COLOURS[:2], lead_ms=lead_ms)
    starts = iqd.sstv_headers(audio, rate)
    assert len(starts) == 1
    assert starts[0] == round(lead_ms * rate / 1000.0)             # to the sample


def test_sstv_headers_finds_each_transmission_and_none_in_noise():
    rate = 16000
    one = syn.scottie_lines(rate, COLOURS[:1], lead_ms=300.0)
    two = syn.scottie_lines(rate, COLOURS[:1], lead_ms=800.0)
    starts = iqd.sstv_headers(np.concatenate((one, two)), rate)
    assert len(starts) == 2
    assert starts == [4800, one.size + 12800]
    rng = np.random.default_rng(8)
    assert iqd.sstv_headers(rng.standard_normal(rate * 3) * 0.3, rate) == []
    tone = np.sin(2 * np.pi * 1900 * np.arange(rate * 3) / rate)
    assert iqd.sstv_headers(tone, rate) == []                       # a leader tone alone is not a header
    assert iqd.sstv_headers(one[:1000], rate) == []


def test_inst_freq_tracks_a_tone_step():
    rate = 16000
    w = syn.ToneWriter(rate)
    w.tone(1900, 100)
    w.tone(1200, 50)
    f = iqd.inst_freq(w.finish(), rate, 1.0)
    assert np.allclose(f[200:1400], 1900, atol=5) and np.allclose(f[1800:2200], 1200, atol=5)
    crossing = int(np.flatnonzero(f[1500:1700] < 1550)[0]) + 1500
    assert abs(crossing - 1600) <= 4


def test_sstv_from_a_mono_wav_whose_header_is_not_at_sample_zero(ff):
    import signal_stego_depth as ssd
    rate = 16000
    audio = syn.scottie_lines(rate, COLOURS, lead_ms=437.3)
    # the gap this closes: the carried decoder needs the header at sample 0 and sees nothing here
    assert ssd.detect_sstv_vis(ssd.Audio(rate, audio)) is None
    res = iqd.demod_sstv(audio_cap(audio, rate), ff)
    assert res.params["headers"] == 1 and len(res.frames) == 1
    f = res.frames[0]
    assert (f.fields["vis"], f.fields["mode"], f.fields["width"], f.fields["height"]) == (56, "Scottie S2", 320, 8)
    assert f.fields["start_s"] == pytest.approx(0.4373, abs=0.0002)
    assert f.fields["sync_pulses"] == 8 and "reclocked" not in f.fields
    px = ppm_pixels(f.data)
    for row, colour in enumerate(COLOURS):
        assert np.abs(np.median(px[row], axis=0) - np.array(colour)).max() <= 1, row
        assert np.abs(px[row, 8:-8].astype(int) - np.array(colour)).max() <= 2, row
    assert f.validated and f.flags == ()                            # a picture is never a flag by itself
    shown = iqd.report_dict(iqd.demodulate(audio_cap(audio, rate), ["sstv"], ff=ff))["protocols"][0]["frames"][0]
    assert shown["data_hex"] == "" and shown["fields"]["height"] == 8     # the pixels stay out of the JSON report


@pytest.mark.parametrize("rate,fmt", [(48000, "cu8"), (250000, "cs16")])
def test_sstv_from_fm_iq(ff, tmp_path, rate, fmt):
    audio = syn.scottie_lines(rate, COLOURS, lead_ms=612.5)
    iq = syn.channel(syn.fm_iq(audio, rate, deviation_hz=3000.0), cfo=0.01, tail=rate // 10)
    path = tmp_path / f"sstv_145.800M_{rate // 1000}k.{fmt}"
    path.write_bytes(syn.to_cu8(iq) if fmt == "cu8" else syn.to_cs16(iq))
    cap = iqd.load_capture(path)
    assert cap.rate == rate and cap.rate_source == "name"
    res = iqd.demod_sstv(cap, ff)
    assert res.params["audio"] == "FM-demodulated to 48000 Hz"
    f = res.frames[0]
    assert (f.fields["vis"], f.fields["mode"]) == (56, "Scottie S2")
    assert f.fields["start_s"] == pytest.approx(0.6125, abs=0.001)
    px = ppm_pixels(f.data)
    assert px.shape[0] >= 7                                         # the squelch tail may cost the last line
    for row in range(px.shape[0]):
        assert np.abs(np.median(px[row], axis=0) - np.array(COLOURS[row])).max() <= 6, row


def test_fm_audio_recovers_the_modulating_tone():
    rate = 250000
    t = np.arange(rate // 2) / rate
    iq = syn.fm_iq(0.5 * np.sin(2 * np.pi * 1900 * t), rate, deviation_hz=3000.0)
    audio, out_rate = iqd.fm_audio(iq * np.exp(2j * np.pi * 0.02 * np.arange(iq.size)), rate)
    assert out_rate == 48000 and abs(audio.size - 24000) <= 2
    spec = np.abs(np.fft.rfft(audio[2000:22000] * np.hanning(20000)))
    assert abs(np.argmax(spec) * 48000 / 20000 - 1900) <= 3
    assert abs(float(np.mean(audio))) < 0.01                        # the carrier offset is not in the audio
    with pytest.raises(iqd.IQDemodError, match="too low for SSTV audio"):
        iqd.fm_audio(iq[:1000], 4000)
    low, low_rate = iqd.fm_audio(syn.fm_iq(np.sin(2 * np.pi * 1200 * np.arange(11025) / 11025), 11025), 11025)
    assert low_rate == 11025 and abs(low.size - 11025) <= 1         # a low capture rate is kept, not raised


@pytest.mark.parametrize("error", [0.004, -0.003])
def test_sstv_clock_error_is_measured_from_the_line_syncs(error):
    rate = 16000
    audio = syn.scottie_lines(int(round(rate * (1 + error))), COLOURS, lead_ms=200.0)   # played on a wrong clock
    start = iqd.sstv_headers(audio, rate)[0]
    got, pulses = iqd.sstv_clock_error(audio, rate, start, iqd.SSTV_LINE_MS[56])
    assert pulses == 8
    assert got == pytest.approx(error, abs=2e-4)
    assert iqd.sstv_clock_error(audio[:start + rate], rate, start, iqd.SSTV_LINE_MS[56]) == (None, 1)


def test_sstv_line_periods_match_the_mode_scan_times():
    import rf2_sstv_modes as modes
    for vis, spec in modes.MODES.items():
        scans = {"scottie": 3, "robot36": 1.5, "robot72": 2, "pd": 4}[spec.family]
        overhead = iqd.SSTV_LINE_MS[vis] - scans * spec.scan_ms
        assert overhead == pytest.approx({"scottie": 13.5, "robot36": 18.0, "robot72": 24.0, "pd": 22.08}[spec.family])
    assert iqd.SSTV_LINE_MS[44] == pytest.approx(446.446) and iqd.SSTV_LINE_MS[40] == pytest.approx(226.798)


def test_sstv_recording_on_a_wrong_clock_is_reclocked_before_decoding(ff):
    rate = 16000
    audio = syn.scottie_lines(int(round(rate * 1.004)), COLOURS, lead_ms=200.0)
    audio = np.concatenate((audio, np.zeros(rate // 20)))           # the recording runs on past the picture
    fixed = iqd.demod_sstv(audio_cap(audio, rate), ff)
    f = fixed.frames[0]
    assert f.fields["reclocked"] is True and f.fields["clock_error_ppm"] == pytest.approx(4000, abs=200)
    px = ppm_pixels(f.data)
    assert px.shape[0] >= 7                 # the last line's final pixel can fall into the silence after it
    for row in range(px.shape[0]):
        assert np.abs(np.median(px[row], axis=0) - np.array(COLOURS[row])).max() <= 2, row
    # without the correction the carried decoder loses line sync in the first line: no picture at all
    raw = iqd.demod_sstv(audio_cap(audio, rate), ff, min_drift_ms=math.inf)
    assert "reclocked" not in raw.frames[0].fields and raw.frames[0].fields["clock_error_ppm"] == f.fields["clock_error_ppm"]
    assert raw.frames[0].data == b"" and "picture not decoded" in raw.frames[0].summary


def test_sstv_martin_goes_to_the_carried_martin_decoder(ff):
    rate = 48000
    audio = syn.martin_lines(rate, COLOURS[:6], lead_ms=150.0)
    res = iqd.demod_sstv(audio_cap(audio, rate), ff)
    f = res.frames[0]
    assert (f.fields["vis"], f.fields["mode"], f.fields["height"]) == (44, "Martin M1", 6)
    px = ppm_pixels(f.data)
    for row, colour in enumerate(COLOURS[:6]):
        assert np.abs(np.median(px[row], axis=0) - np.array(colour)).max() <= 40, row   # that decoder's 100 Hz grid


def test_sstv_pd_and_robot36_rows_come_in_pairs(ff):
    rate = 16000
    periods = [(80, 150, 110, 160), (200, 100, 140, 60), (120, 128, 128, 30)]
    f = iqd.demod_sstv(audio_cap(syn.pd_lines(rate, periods, lead_ms=321.0), rate), ff).frames[0]
    assert (f.fields["mode"], f.fields["sync_pulses"]) == ("PD50", 3)
    px = ppm_pixels(f.data)
    assert px.shape == (6, 320, 3)                                  # one scan period is two rows
    for k, (y0, red_y, blue_y, y1) in enumerate(periods):
        assert np.abs(np.median(px[2 * k], axis=0) - syn.yuv_rgb(y0, red_y, blue_y)).max() <= 2
        assert np.abs(np.median(px[2 * k + 1], axis=0) - syn.yuv_rgb(y1, red_y, blue_y)).max() <= 2
    lines = [(80, 150), (160, 110), (100, 90), (220, 170), (50, 128)]
    g = iqd.demod_sstv(audio_cap(syn.robot36_lines(rate, lines, lead_ms=77.0), rate), ff).frames[0]
    assert g.fields["mode"] == "Robot 36"
    px = ppm_pixels(g.data)
    assert px.shape == (4, 320, 3)                                  # five lines: the odd one has no partner
    assert np.abs(np.median(px[0], axis=0) - syn.yuv_rgb(80, 150, 110)).max() <= 2
    assert np.abs(np.median(px[3], axis=0) - syn.yuv_rgb(220, 90, 170)).max() <= 2


def test_sstv_leader_whose_vis_fails_parity_is_reported_not_decoded(ff):
    rate = 16000
    w = syn.ToneWriter(rate)
    w.tone(1500, 80)
    syn.sstv_header(w, 56, bad_parity=True)
    w.tone(1200, 9)
    w.video(100, 600)
    res = iqd.demod_sstv(audio_cap(w.finish(), rate), ff)
    assert res.params["headers"] == 1 and len(res.frames) == 1
    f = res.frames[0]
    assert f.summary == "leader at 0.080 s but the VIS code failed its check"
    assert f.validated == "" and f.data == b"" and f.fields == {"start_s": 0.08}


def test_sstv_mode_without_a_pixel_decoder_is_named(ff):
    rate = 16000
    w = syn.ToneWriter(rate)
    w.tone(1500, 120)
    syn.sstv_header(w, 96)                                          # PD180: VIS known, no decoder in the tree
    w.tone(1200, 20)
    w.video(100, 400)
    res = iqd.demod_sstv(audio_cap(w.finish(), rate), ff)
    f = res.frames[0]
    assert f.fields["vis"] == 96 and f.data == b""
    assert "PD180 (VIS 96)" in f.summary and "no pixel decoder for this mode" in f.summary
    assert f.validated == "leader + VIS parity"


def test_sstv_capture_cut_inside_a_line_keeps_the_lines_before_it(ff):
    rate = 16000
    audio = syn.scottie_lines(rate, COLOURS, lead_ms=100.0)
    cut = audio[:audio.size - int(rate * 0.2)]                      # 200 ms short: inside the last line
    f = iqd.demod_sstv(audio_cap(cut, rate), ff).frames[0]
    assert ppm_pixels(f.data).shape[0] == 7
    short = audio[:int(rate * (0.1 + 0.91 + 0.1))]                  # the header and a tenth of a second
    g = iqd.demod_sstv(audio_cap(short, rate), ff).frames[0]
    assert g.data == b"" and "ends before one complete scan line" in g.summary


@pytest.mark.needs_tool("py:PIL")
def test_sstv_picture_is_written_to_the_out_folder(ff, tmp_path):
    from PIL import Image
    rate = 16000
    cap = audio_cap(syn.scottie_lines(rate, COLOURS[:3], lead_ms=50.0), rate)
    cap.name = "iss pass.wav"
    res = iqd.demod_sstv(cap, ff, out_dir=tmp_path / "out")
    path = res.frames[0].fields["file"]
    assert path == str(tmp_path / "out" / "iss pass.sstv0.png")
    with Image.open(path) as im:
        assert im.size == (320, 3)
        assert max(abs(a - b) for a, b in zip(im.getpixel((160, 1)), COLOURS[1])) <= 1


def test_sstv_names_why_it_did_not_run_or_found_nothing(ff):
    assert iqd.demod_sstv(cap_of(syn.noise(100, 1.0, 1), None), ff).error == "sstv: the sample rate is unknown (pass --rate)"
    quiet = iqd.demod_sstv(cap_of(syn.noise(60000, 1.0, 2), 48000), ff)
    assert quiet.frames == [] and "no SSTV calibration header" in quiet.note
    assert "too low" in iqd.demod_sstv(audio_cap(np.zeros(8000), 4000), ff).error


# ---- dispatcher ------------------------------------------------------------------------------------

def test_parse_protocols():
    assert iqd.parse_protocols(None) == list(iqd.PROTOCOLS) == iqd.parse_protocols("all")
    assert iqd.parse_protocols("LoRa, p25,lora") == ["lora", "p25"]
    with pytest.raises(iqd.IQDemodError, match=r"no demodulator for dmr, nxdn \(have pocsag, gfsk, lora, p25, tetra, sstv\)"):
        iqd.parse_protocols("p25,dmr,nxdn")


def test_dispatcher_picks_the_flag_frame_and_other_protocols_stay_quiet(ff):
    report = iqd.demodulate(cap_of(pocsag_capture(22050, 1200), 22050), ff=ff, budget=1e9)
    assert [r.proto for r in report.results] == list(iqd.PROTOCOLS)
    assert report.flags == (FLAG,)
    assert report.best.proto == "pocsag" and report.best.flags == (FLAG,)
    by = {r.proto: r for r in report.results}
    assert by["pocsag"].frames and not by["pocsag"].error
    for other in ("lora", "p25", "tetra", "sstv"):
        assert [f for f in by[other].frames if f.validated] == [], other
    assert by["lora"].error.startswith("lora: 22050 Hz is not a whole multiple")   # named, not skipped


@pytest.mark.parametrize("proto", ["p25", "tetra", "lora"])
def test_dispatcher_finds_each_protocol_among_all(ff, proto):
    if proto == "p25":
        iq, rate = syn.channel(syn.c4fm_iq(syn.p25_frame_bits(0x293, 0x7), 10), lead=800, tail=800, sigma=0.03), 48000
    elif proto == "tetra":
        iq, rate = syn.channel(syn.pi4dqpsk_iq(tetra_downlink(), 4), cfo=0.001, sigma=0.02), 72000
    else:
        iq, rate = lora_capture(b"a lora packet, no flag", 8, lead=700, cfo_bins=1.2), 125000
    report = iqd.demodulate(cap_of(iq, rate), ff=ff, budget=1e9)
    solid = {r.proto: [f for f in r.frames if f.validated] for r in report.results}
    assert solid[proto], proto
    assert [p for p, frames in solid.items() if frames] == [proto]    # no other protocol claims the capture
    assert report.flags == () and report.best.proto == proto


def test_dispatcher_ranks_a_flag_reading_over_a_validated_frame_without_one(ff):
    rng = np.random.default_rng(21)
    flag_bits = "".join(map(str, syn.bits_of(b"CSCTF{tetra_blk_7}")))
    block = (flag_bits + syn._rand_bits(216, rng))[:216]
    bits = syn.tetra_ndb(rng) + syn.tetra_ndb(rng, block1=block) + syn.tetra_ndb(rng)
    report = iqd.demodulate(cap_of(syn.channel(syn.pi4dqpsk_iq(bits, 4), sigma=0.02), 72000), ["tetra"], ff=ff)
    assert sum(1 for f in report.results[0].frames if f.validated) == 3
    # the flag sits at bit 14 of a burst, so only the bit-slip reading (not a validated frame) carries it
    assert report.best.flags == ("CSCTF{tetra_blk_7}",) and report.best.validated == ""
    assert iqd.solver_result("t.cf32", report).status == "solved"


def test_dispatcher_ranks_a_validated_frame_over_a_more_printable_unvalidated_one(ff, monkeypatch):
    # neither frame has a flag or its lead: the one a protocol check vouches for is the best, even
    # though the bit-slip reading beside it is all printable text and the validated one is binary
    def vouched(cap, ff):
        return iqd.ProtoResult("p25", frames=[iqd.Frame("p25", "LDU1 NAC 0x293", data=bytes(range(0, 250, 7)),
                                                        validated="frame sync + NID BCH(63,16,23)")])

    def slip(cap, ff):
        return iqd.ProtoResult("gfsk", frames=[iqd.Frame("gfsk", "bit offset 3", data=b"plain readable words here")])
    monkeypatch.setitem(iqd.DEMODS, "p25", vouched)
    monkeypatch.setitem(iqd.DEMODS, "gfsk", slip)
    for order in (["gfsk", "p25"], ["p25", "gfsk"]):
        report = iqd.demodulate(cap_of(syn.noise(100, 1.0, 1), 48000), order, ff=ff, budget=1e9)
        assert report.flags == () and not any(f.lead for r in report.results for f in r.frames)
        assert report.best.proto == "p25" and report.best.validated, order


def test_dispatcher_budget_is_cpu_time_on_an_injected_clock(ff):
    ticks = iter([0.0, 1.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0])        # start, then one reading per protocol
    report = iqd.demodulate(cap_of(syn.noise(4000, 1.0, 1), 48000), protocols=["gfsk", "p25", "tetra"], ff=ff,
                            budget=5.0, clock=lambda: next(ticks))
    assert [bool(r.error) for r in report.results] == [False, True, True]
    assert report.results[1].error == "p25: not run, the 5 s CPU budget was spent by the protocols before it (--budget)"


def test_dispatcher_budget_exactly_spent_stops_the_next_protocol(ff):
    # the boundary: 5 s used of a 5 s budget is spent; 4.5 s is not
    ticks = iter([0.0, 1.0, 4.5, 5.0])             # start, then the reading before gfsk, p25, tetra
    report = iqd.demodulate(cap_of(syn.noise(4000, 1.0, 1), 48000), protocols=["gfsk", "p25", "tetra"], ff=ff,
                            budget=5.0, clock=lambda: next(ticks))
    assert [bool(r.error) for r in report.results] == [False, False, True]
    assert report.results[2].error.startswith("tetra: not run, the 5 s CPU budget was spent")


def test_dispatcher_isolates_a_protocol_that_cannot_import(ff, monkeypatch):
    def broken(cap, ff):
        raise ImportError("No module named 'sec_lmr_p25'")
    monkeypatch.setitem(iqd.DEMODS, "p25", broken)
    frame = b"\xaa\xaa\xaa\xaa\x7e" + FLAG.encode() + b"\x00\x00"
    report = iqd.demodulate(cap_of(gfsk_capture(frame), 250000), protocols=["p25", "gfsk"], ff=ff, budget=1e9)
    assert report.result("p25").error == "p25: a module it builds on does not import: No module named 'sec_lmr_p25'"
    assert report.result("gfsk").flags == (FLAG,) and report.flags == (FLAG,)


def test_a_renamed_parser_table_is_named_not_a_bare_attribute_error(ff, monkeypatch):
    # iq_demod reads the ETSI / TIA layout tables of sec_lmr_tetra and sec_lmr_p25 (underscore names)
    import sec_lmr_p25
    import sec_lmr_tetra
    monkeypatch.delattr(sec_lmr_tetra, "_LAYOUTS")
    monkeypatch.delattr(sec_lmr_p25, "_PHASE1_LENGTHS")
    tetra_iq = syn.channel(syn.pi4dqpsk_iq(tetra_downlink(), 4), cfo=0.001, sigma=0.02)
    tetra = iqd.demodulate(cap_of(tetra_iq, 72000), ["tetra"], ff=ff, budget=1e9).result("tetra")
    assert tetra.error == ("tetra: sec_lmr_tetra no longer has _LAYOUTS (renamed?): this engine reads its layout "
                           "tables, so it cannot frame bursts until iq_demod is updated to the new names")
    p25_iq = syn.channel(syn.c4fm_iq(syn.p25_frame_bits(0x293, 0x7), 10), lead=800, tail=800, sigma=0.03)
    p25 = iqd.demodulate(cap_of(p25_iq, 48000), ["p25"], ff=ff, budget=1e9).result("p25")
    assert p25.error.startswith("p25: sec_lmr_p25 no longer has _PHASE1_LENGTHS (renamed?)")
    assert iqd.solver_result("t.cf32", iqd.demodulate(cap_of(p25_iq, 48000), ["p25"], ff=ff)).status == "blocked"


def test_dispatcher_names_a_protocol_that_fails_and_runs_the_rest(ff, monkeypatch):
    def broken(cap, ff, **options):
        raise KeyError("training")
    monkeypatch.setitem(iqd.DEMODS, "tetra", broken)
    report = iqd.demodulate(cap_of(pocsag_capture(22050, 1200), 22050), protocols=["tetra", "pocsag"], ff=ff)
    assert report.result("tetra").error == "tetra: failed on this capture: KeyError: 'training'"
    assert report.flags == (FLAG,)


def test_solver_result_carries_the_capture_notes(ff, tmp_path):
    path = tmp_path / "long_48k.cu8"
    path.write_bytes(syn.to_cu8(syn.noise(30000, 1.0, 5)))
    cap = iqd.load_capture(path, max_samples=20000)
    result = iqd.solver_result(str(path), iqd.demodulate(cap, ["gfsk", "p25"], ff=ff))
    assert result.status == "none" and "capture cut to 20000 of 30000 samples" in result.notes


def test_dispatcher_refuses_an_unknown_protocol(ff):
    with pytest.raises(iqd.IQDemodError, match="no demodulator for dmr"):
        iqd.demodulate(cap_of(syn.noise(100, 1.0, 1), 48000), protocols=["dmr"], ff=ff)


def test_solver_result_statuses(ff):
    frame = b"\xaa\xaa\xaa\xaa\x7e" + FLAG.encode() + b"\x00\x00"
    solved = iqd.solver_result("c.cu8", iqd.demodulate(cap_of(gfsk_capture(frame), 250000), ["gfsk"], ff=ff))
    assert solved.status == "solved" and solved.flags == (FLAG,) and solved.engine == "toolkits.iq_demod"
    assert solved.evidence[0].kind == "decode" and solved.evidence[0].path == "c.cu8"
    assert "framing sync" in solved.evidence[0].detail

    lora = iqd.demodulate(cap_of(lora_capture(b"no flag in this packet", 7), 125000.0), ["lora"], ff=ff)
    unsure = iqd.solver_result("c.cu8", lora)
    assert unsure.status == "unsure" and unsure.flags == ()
    assert "decoded 1 lora frame(s) but no flag in the event format" in unsure.notes

    none = iqd.solver_result("c.cu8", iqd.demodulate(cap_of(syn.noise(30000, 1.0, 1), 48000), ["gfsk", "p25"], ff=ff))
    assert none.status == "none" and "no two-level FSK burst found" in none.notes and "no P25 phase-1 frame sync" in none.notes

    blocked = iqd.solver_result("c.cu8", iqd.demodulate(cap_of(syn.noise(3000, 1.0, 1), None), ["p25", "tetra", "sstv"], ff=ff))
    assert blocked.status == "blocked"
    for proto in ("p25", "tetra", "sstv"):
        assert f"{proto}: the sample rate is unknown (pass --rate)" in blocked.notes


def test_solver_result_wrong_event_prefix_is_not_solved():
    spec = event.FlagSpec(prefixes=("ZZTOP",), body=flagfmt.current().spec.body, case="exact")
    report = iqd.demodulate(cap_of(lora_capture(FLAG.encode(), 7), 125000.0), ["lora"], ff=flagfmt.FlagFormat(spec))
    assert report.flags == () and iqd.solver_result("c.cu8", report).status == "unsure"


# ---- CLI + manifest --------------------------------------------------------------------------------

def _last_json(out):
    return json.loads(out.strip().splitlines()[-1])


def test_main_prints_a_triage_then_a_solved_result(tmp_path, capsys):
    path = tmp_path / "pager_153.350M_22050.cu8"
    path.write_bytes(syn.to_cu8(pocsag_capture(22050, 1200, sigma=0.02)))
    rc = iqd.main([str(path), "--rate", "22050", "--proto", "pocsag,gfsk"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "pocsag: 1 frame(s)" in out and f"FLAG(S): ['{FLAG}']" in out
    result = _last_json(out)
    assert result["status"] == "solved" and result["flags"] == [FLAG] and result["engine"] == "toolkits.iq_demod"
    assert result["evidence"][0]["path"] == str(path)


def test_main_json_and_out_folder(tmp_path, capsys):
    path = tmp_path / "lora_868.1M_125k.cf32"
    path.write_bytes(syn.to_cf32(lora_capture(FLAG.encode(), 7, lead=400)))
    rc = iqd.main([str(path), "--proto", "lora", "--json", "--out", str(tmp_path / "out")])
    lines = capsys.readouterr().out.strip().splitlines()
    assert rc == 0 and len(lines) == 2
    full = json.loads(lines[0])
    assert full["capture"] == {"name": path.name, "format": "cf32", "rate": 125000.0, "rate_source": "name",
                               "samples": full["capture"]["samples"], "total_samples": full["capture"]["samples"], "notes": []}
    assert full["flags"] == [FLAG]
    frame = full["protocols"][0]["frames"][0]
    assert bytes.fromhex(frame["data_hex"]) == FLAG.encode() and frame["fields"]["spreading_factor"] == 7
    assert json.loads(lines[1])["status"] == "solved"
    saved = json.loads((tmp_path / "out" / f"{path.name}.report.json").read_text())
    assert saved == full


def test_main_blocks_with_the_reason_on_a_live_source_or_unknown_protocol(tmp_path, capsys):
    rc = iqd.main(["rtl_tcp:127.0.0.1:1234"])
    captured = capsys.readouterr()
    result = _last_json(captured.out)
    assert rc == 1 and result["status"] == "blocked" and "never opens an SDR" in result["notes"]
    assert "names a live source" in captured.err
    path = tmp_path / "x.cu8"
    path.write_bytes(syn.to_cu8(syn.noise(64, 1.0, 1)))
    rc = iqd.main([str(path), "--proto", "dmr"])
    result = _last_json(capsys.readouterr().out)
    assert rc == 1 and result["status"] == "blocked" and "no demodulator for dmr" in result["notes"]


def test_main_with_no_rate_runs_what_needs_none_and_names_the_rest(tmp_path, capsys):
    frame = b"\xaa\xaa\xaa\xaa\x7e" + FLAG.encode() + b"\x00\x00"
    path = tmp_path / "burst.cs8"
    iq = gfsk_capture(frame, sigma=0.02)
    a = np.empty(iq.size * 2)
    a[0::2], a[1::2] = iq.real, iq.imag
    path.write_bytes(np.clip(np.rint(a * 100), -128, 127).astype(np.int8).tobytes())
    rc = iqd.main([str(path)])
    out = capsys.readouterr().out
    assert rc == 0 and _last_json(out)["flags"] == [FLAG]
    assert "p25: NOT RUN: p25: the sample rate is unknown (pass --rate)" in out
    assert "rate unknown" in out


def test_manifest_declares_the_iq_intake_and_routes():
    from ctf import paths
    from ctf.engines import manifest as M
    man = M.load(paths.repo_root() / "solvers/toolkits/iq_demod.manifest.toml")
    assert man.id == "toolkits.iq_demod" and man.cost_class == "cheap"
    assert man.entry_raw == "cli:python solvers/toolkits/iq_demod.py"
    assert man.intake is not None and man.intake.select == "files" and man.intake.run == "per-file"
    for ext in (".cu8", ".cs8", ".cs16", ".cf32", ".cfile", ".sigmf-data"):
        assert f"ext:{ext}" in man.intake.match, ext
    assert "{file}" in man.intake.args and "{out}" in man.intake.args
    assert man.intake.spawns is False                               # it starts no program


def test_intake_selects_the_engine_for_an_iq_file_and_not_for_text(tmp_path):
    from ctf import paths
    from ctf.engines import manifest as M
    from ctf.intake import engines as IE
    (tmp_path / "capture_433.92M_250k.cu8").write_bytes(syn.to_cu8(syn.noise(256, 1.0, 1)))
    (tmp_path / "notes.txt").write_text("not a capture")
    man = M.load(paths.repo_root() / "solvers/toolkits/iq_demod.manifest.toml")
    matched = [f.name for f, _why in IE.files_matching(man.intake.match, IE.input_files(tmp_path))]
    assert matched == ["capture_433.92M_250k.cu8"]


def test_router_sends_an_iq_capture_here(tmp_path):
    from ctf.engines import router
    (tmp_path / "signal.cf32").write_bytes(syn.to_cf32(syn.noise(64, 1.0, 1)))
    hits = router.route("misc", "we recorded this off the air, demodulate the iq capture", files_dir=tmp_path)
    assert "toolkits.iq_demod" in [h.manifest.id for h in hits]
