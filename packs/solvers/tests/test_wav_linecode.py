"""B-083: the FSK / line-code WAV decode adapter.

Every fixture is synthesised here (no captured or committed WAV, rule 4): a known flag is encoded
into a known line code + framing, written to an in-memory PCM WAV, and the adapter is asked to
recover it. End-to-end tests prove the crib-driven search finds the planted flag; the unit tests pin
each building block (line codes, framings, CRC, tone/baud estimation) so a mutation to any one of them
fails a test even though the end-to-end search has redundant paths.

The two real challenges this closes are reproduced in kind:
  - tone_burst (csctf 9080): binary FSK 1000/2000 Hz, 50 baud, aa-preamble, 0x7E sync, MSB ASCII.
  - telltale  (csctf 9081): Manchester 1 kbit/s under 50 Hz mains + baseline drift, 0x7E sync,
    length byte, ASCII payload, CRC-8 (poly 0x07) trailer.
"""
import io
import math
import wave

import numpy as np
import pytest

import wav_linecode as wl
from ctf import flagfmt

FLAG_FSK = "CSCTF{tone_burst_4481dda445a0a227c3a8eb90fda4fd92}"
FLAG_MAN = "CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}"


# ---- synthesis helpers (fixtures are built, never captured) -----------------------------------------

def _to_wav(samples, rate, width=2):
    s = np.clip(np.asarray(samples, dtype=np.float64), -1.0, 1.0)
    if width == 2:
        pcm = (s * 32767).astype("<i2").tobytes()
    elif width == 1:
        pcm = ((s * 127) + 128).astype(np.uint8).tobytes()
    else:
        raise ValueError(width)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(width)
        w.setframerate(rate)
        w.writeframes(pcm)
    return buf.getvalue()


def _bits(data, msb_first=True):
    out = []
    for byte in data:
        for k in range(8):
            out.append((byte >> (7 - k)) & 1 if msb_first else (byte >> k) & 1)
    return out


def fsk_wav(payload, rate=8000, baud=50, f0=1000, f1=2000, lead_s=0.24, msb_first=True):
    """A tone-burst-style FSK WAV: aa-preamble, 0x7E sync, then the payload as 8-bit ASCII."""
    frame = b"\xaa\xaa\xaa\xaa\x7e" + payload.encode()
    spb = rate // baud
    chunks = [np.zeros(int(rate * lead_s))]
    for b in _bits(frame, msb_first):
        t = np.arange(spb) / rate
        chunks.append(0.8 * np.sin(2 * math.pi * (f1 if b else f0) * t))
    chunks.append(np.zeros(int(rate * 0.1)))
    return _to_wav(np.concatenate(chunks), rate)


def manchester_wav(payload, rate=48000, baud=1000, add_noise=True):
    """A telltale-style Manchester WAV: preamble, 0x7E sync, length, payload, CRC-8, wrapped in a
    longer recording with a slow baseline drift and 50 Hz mains hum, data as a burst in the middle."""
    body = bytes([len(payload)]) + payload.encode()
    frame = b"\xaa" * 8 + b"\x7e" + body + bytes([wl.crc8(body)])
    spb = rate // baud
    half = spb // 2
    sig = []
    for b in _bits(frame, True):            # IEEE 802.3: 1 -> low,high (01); 0 -> high,low (10)
        if b:
            sig += [np.full(half, -1.0), np.full(half, 1.0)]
        else:
            sig += [np.full(half, 1.0), np.full(half, -1.0)]
    sig = np.concatenate(sig)
    if add_noise:
        pre = np.random.RandomState(1).normal(0, 0.05, 12000)
        post = np.random.RandomState(2).normal(0, 0.05, 6000)
        full = np.concatenate([pre, sig, post])
        t = np.arange(full.size) / rate
        full = full + 0.3 * np.sin(2 * math.pi * 0.5 * t) + 0.2 + 0.15 * np.sin(2 * math.pi * 50 * t)
    else:
        full = sig
    return _to_wav(full, rate)


def uart_wav(payload, rate=48000, baud=1200):
    """An NRZ 8N1 UART WAV: idle high, start bit, 8 data bits LSB-first, stop bit, per byte."""
    spb = rate // baud
    levels = [np.ones(spb * 10)]
    for byte in payload.encode():
        frame = [0] + [(byte >> k) & 1 for k in range(8)] + [1]
        for bit in frame:
            levels.append(np.full(spb, 1.0 if bit else -1.0))
    levels.append(np.ones(spb * 10))
    return _to_wav(np.concatenate(levels), rate)


def nrzi_wav(payload, rate=48000, baud=2000):
    """A differential (NRZ-I) WAV: a transition encodes a 1, a hold a 0; aa-preamble + 0x7E sync."""
    frame = b"\xaa" * 4 + b"\x7e" + payload.encode()
    level, syms = 1, []
    for b in _bits(frame, True):
        if b:
            level ^= 1
        syms.append(level)
    spb = rate // baud
    sig = np.concatenate([np.full(spb, 1.0 if s else -1.0) for s in syms])
    return _to_wav(sig, rate)


def hdlc_wav(payload, rate=48000, baud=4000):
    """A bit-stuffed HDLC WAV: flag 0x7E, zero-stuffed payload + 2 FCS bytes, flag; NRZ on the wire."""
    body = payload.encode() + b"\x00\x00"       # 2 placeholder FCS bytes (dropped on deframe)
    stuffed, ones = [], 0
    for c in _bits(body, True):
        stuffed.append(c)
        if c == 1:
            ones += 1
            if ones == 5:
                stuffed.append(0)
                ones = 0
        else:
            ones = 0
    flag = [0, 1, 1, 1, 1, 1, 1, 0]
    allbits = flag + stuffed + flag
    spb = rate // baud
    sig = np.concatenate([np.full(spb, 1.0 if b else -1.0) for b in allbits])
    return _to_wav(sig, rate)


def hdlc_multiframe_wav(payloads, rate=48000, baud=4000):
    """A bit-stuffed HDLC WAV carrying several back-to-back frames (flag, stuffed payload + 2 FCS
    bytes, flag, ...), NRZ on the wire. Each payload deframes to its own candidate, so one capture can
    carry both a full-flag frame and a shorter prefix-only frame."""
    flag = [0, 1, 1, 1, 1, 1, 1, 0]
    allbits = list(flag)
    for payload in payloads:
        body = payload.encode() + b"\x00\x00"   # 2 placeholder FCS bytes (dropped on deframe)
        ones = 0
        for c in _bits(body, True):
            allbits.append(c)
            if c == 1:
                ones += 1
                if ones == 5:
                    allbits.append(0)
                    ones = 0
            else:
                ones = 0
        allbits += flag
    spb = rate // baud
    sig = np.concatenate([np.full(spb, 1.0 if b else -1.0) for b in allbits])
    return _to_wav(sig, rate)


@pytest.fixture
def ff():
    return flagfmt.current()      # conftest sets CTF_EVENT=csctf (prefixes include CSCTF)


# ---- end-to-end: the planted flag is recovered from each line code / framing -------------------------

def test_fsk_tone_burst_recovers_flag(ff):
    dec = wl.decode(fsk_wav(FLAG_FSK), ff)
    assert dec.flags == (FLAG_FSK,)
    assert dec.tones == (1000.0, 2000.0)
    assert round(dec.baud) == 50
    assert dec.best.scheme.startswith("fsk")


def test_manchester_telltale_recovers_flag(ff):
    dec = wl.decode(manchester_wav(FLAG_MAN), ff)
    assert FLAG_MAN in dec.flags
    assert "manchester" in dec.best.scheme


def test_uart_8n1_recovers_flag(ff):
    dec = wl.decode(uart_wav("CSCTF{uart_eight_n_one}"), ff)
    assert "CSCTF{uart_eight_n_one}" in dec.flags
    assert "uart8n1" in dec.best.scheme


def test_nrzi_differential_recovers_flag(ff):
    dec = wl.decode(nrzi_wav("CSCTF{nrzi_differential_ok}"), ff)
    assert "CSCTF{nrzi_differential_ok}" in dec.flags
    assert "nrzi" in dec.best.scheme


def test_hdlc_frame_recovers_flag(ff):
    dec = wl.decode(hdlc_wav("CSCTF{hdlc_frame_xyz}"), ff)
    assert "CSCTF{hdlc_frame_xyz}" in dec.flags
    assert dec.best.framing == "hdlc"


def test_fsk_8bit_wav_also_decodes(ff):
    # 8-bit unsigned PCM, a different sample width, still decodes (load normalises both).
    data = fsk_wav(FLAG_FSK)
    rate, sig = wl.load(data)
    # rebuild as 8-bit
    data8 = _to_wav(sig, rate, width=1)
    dec = wl.decode(data8, ff)
    assert FLAG_FSK in dec.flags


# ---- no false positives: a capture with no flag yields nothing ---------------------------------------

def test_pure_noise_yields_no_flag(ff):
    noise = _to_wav(np.random.RandomState(9).normal(0, 0.3, 48000), 48000)
    dec = wl.decode(noise, ff)
    assert dec.flags == ()
    assert not dec.ok


def test_non_flag_payload_is_not_reported_as_flag(ff):
    # A perfectly decodable FSK burst whose ASCII is not a flag must not surface a flag.
    dec = wl.decode(fsk_wav("just some plain text, no braces here"), ff)
    assert dec.flags == ()


def test_wrong_event_prefix_does_not_match(monkeypatch):
    # The flag is crib-selected: under an event whose prefix is not CSCTF, the same bytes (which
    # contain 'CSCTF{...}') must not be returned as that event's flag. Proves selection is by the
    # event flag format, not a hardcoded 'CSCTF'.
    from ctf import event
    spec = event.FlagSpec(prefixes=("ZZTOP",), body=flagfmt.current().spec.body, case="exact")
    ff = flagfmt.FlagFormat(spec)
    dec = wl.decode(fsk_wav(FLAG_FSK), ff)
    assert dec.flags == ()          # CSCTF{...} is not a ZZTOP{...} flag


def test_best_is_the_flag_candidate_not_a_shorter_lead(ff):
    # Crib selection must put a candidate that actually carries a flag at dec.best, even when a rival
    # candidate (no flag, only the PREFIX{ lead) would win every other tie-break -- here a shorter,
    # equally printable frame. One HDLC capture with two frames: a full flag, then a shorter prefix-
    # only payload. The flag is aggregated into dec.flags regardless of the ranking, so only
    # dec.best.flags distinguishes the correct key `(has_flag, lead, printable, -len)` from one that
    # drops the leading has_flag term: without it the shorter lead frame outranks the flag frame.
    flag = "CSCTF{hdlc_rank_flag}"             # 21 bytes, a full flag
    lead_only = "CSCTF{partial_lead"           # 18 bytes, the lead but no closing brace -> no flag
    dec = wl.decode(hdlc_multiframe_wav([flag, lead_only]), ff)
    assert flag in dec.flags                   # the flag is recovered either way
    assert dec.best is not None
    assert dec.best.flags                       # the chosen reading is the one carrying the flag
    assert flag in dec.best.flags
    assert dec.best.framing == "hdlc"


def test_best_is_the_tighter_framing_among_equal_flag_candidates(ff):
    # When two candidates both carry the SAME flag and tie on every earlier key term -- both have the
    # flag (has_flag), both have the lead, both are fully printable (ratio 1.0) -- the length tiebreak
    # `-len(c.data)` must pick the shorter, tighter framing (the payload closest to the flag) over a
    # longer blob that merely contains the same flag plus trailing filler. Two HDLC frames: one is the
    # flag alone, the other is the flag followed by printable filler (all ASCII, so printable_ratio is
    # 1.0 for both, and the only remaining discriminator is length). Flipping the tiebreak to
    # `len(c.data)` would put the longer blob at dec.best, which this pins against.
    short = "CSCTF{rank_short}"                  # 17 bytes: the flag, nothing more
    longer = short + "AAAAAAAAAA"                # 27 bytes: same flag + printable filler after `}`
    dec = wl.decode(hdlc_multiframe_wav([short, longer]), ff)
    assert dec.flags == (short,)                 # one flag, found in both frames
    assert dec.best is not None
    assert dec.best.framing == "hdlc"
    assert dec.best.flags and short in dec.best.flags
    # the tighter frame wins the tiebreak: dec.best is the flag-only payload, not the padded blob
    assert dec.best.data == short.encode()
    assert len(dec.best.data) < len(longer.encode())


# ---- unit locks: each building block, so a mutation to it fails a test -------------------------------

def test_crc8_matches_telltale_published_value():
    # From the 9081 writeup: CRC-8 poly 0x07 init 0x00 over (length byte 0x30 + payload) == 0x37.
    payload = b"CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}"
    assert wl.crc8(bytes([len(payload)]) + payload) == 0x37
    assert wl.crc8(b"") == 0x00
    assert wl.crc8(b"\x00") == 0x00


def test_goertzel_power_peaks_at_the_tone():
    rate = 8000
    t = np.arange(1600) / rate
    sig = np.sin(2 * math.pi * 1000 * t)
    assert wl.goertzel_power(sig, rate, 1000) > 50 * wl.goertzel_power(sig, rate, 2000)


def test_goertzel_power_rowwise_2d():
    rate = 8000
    block = 160
    rows = np.stack([np.sin(2 * math.pi * 1000 * np.arange(block) / rate),
                     np.sin(2 * math.pi * 2000 * np.arange(block) / rate)])
    p1000 = wl.goertzel_power(rows, rate, 1000)
    p2000 = wl.goertzel_power(rows, rate, 2000)
    assert p1000.shape == (2,)
    assert p1000[0] > p2000[0] and p2000[1] > p1000[1]


def test_dominant_tones_finds_the_two_fsk_tones():
    rate = 8000
    t = np.arange(4000) / rate
    sig = np.sin(2 * math.pi * 1000 * t) + np.sin(2 * math.pi * 2000 * t)
    tones = sorted(wl.dominant_tones(sig, rate, 2))
    assert len(tones) == 2
    assert abs(tones[0] - 1000) < 20 and abs(tones[1] - 2000) < 20


def test_dominant_tones_single_tone_is_not_fsk():
    rate = 8000
    t = np.arange(4000) / rate
    assert wl.dominant_tones(np.sin(2 * math.pi * 1000 * t), rate, 2) == []


def test_nrz_bits_and_polarity():
    assert wl.nrz_bits([1, 0, 1, 1, 0, 0]) == "101100"
    assert wl.nrz_bits([1, 0, 1, 1, 0, 0], invert=True) == "010011"


def test_nrzi_bits_transition_encoding():
    # symbols: a transition means 1 (default), a hold means 0. First symbol carries no bit.
    syms = [0, 1, 1, 0, 0, 1]      # transitions at 0->1, 1->0, 0->1  => 1,0,1,0,1
    assert wl.nrzi_bits(syms, transition_is_one=True) == "10101"
    assert wl.nrzi_bits(syms, transition_is_one=False) == "01010"


def test_manchester_bits_ieee_and_thomas():
    # 01 -> 1 (IEEE), 10 -> 0: chips for bits 1,0,1,0 are 01 10 01 10 (>= 8 chips to be read)
    chips = [0, 1, 1, 0, 0, 1, 1, 0]
    bits, invalid = wl.manchester_bits(chips, "ieee")
    assert bits == "1010" and invalid == 0
    thomas, _ = wl.manchester_bits(chips, "thomas")
    assert thomas == "0101"


def test_manchester_bits_rejects_non_manchester():
    # a constant chip stream pairs as 00/11 at both phases -> not Manchester
    bits, invalid = wl.manchester_bits([1, 1, 1, 1, 1, 1, 1, 1], "ieee")
    assert bits == "" or invalid > 0


def test_uart_8n1_decodes_and_drops_bad_stop():
    # 'A' = 0x41, bits LSB-first 1,0,0,0,0,0,1,0; frame = start 0 + data + stop 1
    good = [1] * 4 + [0] + [1, 0, 0, 0, 0, 0, 1, 0] + [1] + [1] * 4
    assert wl.uart_8n1(good) == b"A"
    # stop bit low and nothing decodable after it: the frame is dropped, no byte emitted
    bad = [1] * 4 + [0] + [1, 0, 0, 0, 0, 0, 1, 0] + [0]
    assert wl.uart_8n1(bad) == b""


def test_pack_bits_msb_lsb():
    assert wl.pack_bits("01000001") == b"A"
    assert wl.pack_bits("10000010", msb_first=False) == b"A"


def test_sync_align_realigns_on_sync_word():
    # bits that start mid-byte, with a 0x7E sync pattern somewhere; align returns bytes from the sync.
    pre = "011"                       # junk, not byte-aligned
    payload = b"\x7eHI"
    bits = pre + "".join(str(b) for b in _bits(payload, True))
    out = wl.sync_align(bits, 0x7E, msb_first=True)
    assert out == b"\x7eHI"
    assert wl.sync_align("0000111100001111", 0x7E) is None


def test_payload_after_sync():
    assert wl.payload_after_sync(b"\xaa\xaa\x7eHELLO") == b"HELLO"
    assert wl.payload_after_sync(b"no sync byte here") is None


def test_hdlc_frames_destuffs_and_drops_fcs():
    # payload chosen to contain a run of ones forcing a stuffed zero
    payload = b"\xff\xf0"
    body = payload + b"\x00\x00"
    stuffed, ones = [], 0
    for c in _bits(body, True):
        stuffed.append(c)
        if c == 1:
            ones += 1
            if ones == 5:
                stuffed.append(0)
                ones = 0
        else:
            ones = 0
    flag = [0, 1, 1, 1, 1, 1, 1, 0]
    bits = "".join(str(b) for b in flag + stuffed + flag)
    frames = wl.hdlc_frames(bits)
    assert frames == [payload]


def test_symbols_from_runs_roundtrip():
    # +3 run -> three 1s, -2 run -> two 0s, at unit 1
    assert wl.symbols_from_runs([3, -2, 1], 1) == [1, 1, 1, 0, 0, 1]
    # at unit 20, a run of 40 is two symbols
    assert wl.symbols_from_runs([40, -20], 20) == [1, 1, 0]


def test_highpass_subtract_removes_dc_and_drift():
    rate = 48000
    t = np.arange(48000) / rate
    sig = np.sign(np.sin(2 * math.pi * 1000 * t)) + 5.0 + 0.3 * np.sin(2 * math.pi * 0.5 * t)
    hp = wl.highpass_subtract(sig, int(rate * 0.02))
    assert abs(float(np.mean(hp))) < 0.1       # DC and slow drift gone
    assert float(np.std(hp)) > 0.5             # the 1 kHz square survives


def test_adaptive_threshold_tracks_baseline():
    rate = 48000
    t = np.arange(4800) / rate
    sig = np.sign(np.sin(2 * math.pi * 500 * t)) + 3.0 * t      # strong ramp baseline
    lv = wl.adaptive_threshold(sig, int(rate * 0.02))
    # roughly balanced ones and zeros despite the ramp (a global threshold would be all-ones late)
    assert 0.3 < lv.mean() < 0.7


def test_load_rejects_non_wav():
    assert wl.load(b"not a riff file at all") == (None, None)
    assert wl.load(b"") == (None, None)


def test_load_reads_pcm_wav():
    rate, sig = wl.load(fsk_wav(FLAG_FSK))
    assert rate == 8000
    assert sig is not None and sig.size > 1000
    assert float(np.max(np.abs(sig))) <= 1.0 + 1e-9


# ---- CLI + intake wiring (acceptance: B-002 runs it at intake) --------------------------------------

def test_cli_main_emits_solved_solverresult(tmp_path, capsys):
    from ctf.result import SolverResult
    p = tmp_path / "burst.wav"
    p.write_bytes(fsk_wav(FLAG_FSK))
    rc = wl.main([str(p)])
    assert rc == 0
    out = capsys.readouterr().out.strip().splitlines()
    res = SolverResult.from_json(out[-1])
    assert res.status == "solved"
    assert FLAG_FSK in res.flags
    assert res.evidence and res.evidence[0].kind == "decode"


def test_cli_main_reports_none_on_noise(tmp_path, capsys):
    from ctf.result import SolverResult
    p = tmp_path / "noise.wav"
    p.write_bytes(_to_wav(np.random.RandomState(3).normal(0, 0.3, 24000), 48000))
    wl.main([str(p)])
    res = SolverResult.from_json(capsys.readouterr().out.strip().splitlines()[-1])
    assert res.status in ("none", "unsure")
    assert not res.flags


def test_manifest_declares_wav_intake():
    from ctf.engines import manifest as M
    from ctf import paths
    man = M.load(paths.repo_root() / "solvers/toolkits/wav_linecode.manifest.toml")
    assert man.id == "toolkits.wav_linecode"
    assert man.intake is not None
    assert man.intake.select == "files" and man.intake.run == "per-file"
    assert "ext:.wav" in man.intake.match and "magic:RIFF" in man.intake.match


def test_intake_plan_selects_adapter_for_a_wav(tmp_path):
    # The [intake] table makes B-002's intake run this engine on a WAV handout.
    from ctf.intake import engines as IE
    from ctf.engines import manifest as M
    from ctf import paths
    (tmp_path / "capture.wav").write_bytes(fsk_wav(FLAG_FSK))
    man = M.load(paths.repo_root() / "solvers/toolkits/wav_linecode.manifest.toml")
    heads = IE.input_files(tmp_path)
    matched = IE.files_matching(man.intake.match, heads)
    assert any(f.name == "capture.wav" for f, _why in matched)
