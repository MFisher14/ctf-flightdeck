"""Synthetic IQ for the B-158 tests: small transmitters written from the published air interfaces.

Nothing here imports the engine under test (solvers/toolkits/iq_demod.py) or any decoder: each
function is a modulator or an encoder transcribed from the standard it names, so a capture built
here is an independent input, not the demodulator run backwards. No file is committed; every capture
is built in memory by the test that needs it (rule 4).

  fsk_iq            2-level (G)FSK: frequency +-deviation per bit, optional Gaussian shaping
  pocsag_bits       POCSAG batch: preamble, sync, address + alphanumeric message, BCH(31,21) + parity
  p25_frame_bits    P25 phase-1 data unit: frame sync, NID (BCH(63,16,23) + parity), status symbols
  c4fm_iq           P25 C4FM: dibits -> 4 levels, the TIA-102 shaping (raised cosine 0.2 x inverse sinc)
  tetra_ndb / tetra_sb / tetra_nub      TETRA bursts by the ETSI EN 300 392-2 layouts
  pi4dqpsk_iq       pi/4-DQPSK with a root-raised-cosine 0.35 modulation filter
  lora_iq           LoRa packet: preamble, sync word, 2.25 downchirps, data symbols; any oversampling
  ToneWriter + sstv_header + scottie_lines / martin_lines / pd_lines / robot36_lines
                    SSTV audio (phase-continuous tones), then fm_iq
  to_cu8 / to_cs16 / to_cf32 / stereo_wav / mono_wav     capture file bytes
"""
import io
import math
import wave

import numpy as np


# ---- file formats ----------------------------------------------------------------------------------

def to_cu8(iq, scale=0.9):
    iq = np.asarray(iq) * (scale / max(1e-12, float(np.max(np.abs(iq)))))
    a = np.empty(iq.size * 2)
    a[0::2], a[1::2] = iq.real, iq.imag
    return np.clip(np.rint(a * 127.5 + 127.5), 0, 255).astype(np.uint8).tobytes()


def to_cs16(iq, scale=0.9):
    iq = np.asarray(iq) * (scale / max(1e-12, float(np.max(np.abs(iq)))))
    a = np.empty(iq.size * 2)
    a[0::2], a[1::2] = iq.real, iq.imag
    return np.rint(a * 32767).astype("<i2").tobytes()


def to_cf32(iq):
    a = np.empty(np.asarray(iq).size * 2, dtype="<f4")
    a[0::2], a[1::2] = np.real(iq), np.imag(iq)
    return a.tobytes()


def _wav(frames, rate, channels):
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(np.rint(np.clip(frames, -1, 1) * 32767).astype("<i2").tobytes())
    return buf.getvalue()


def stereo_wav(iq, rate, scale=0.9):
    iq = np.asarray(iq) * (scale / max(1e-12, float(np.max(np.abs(iq)))))
    a = np.empty(iq.size * 2)
    a[0::2], a[1::2] = iq.real, iq.imag
    return _wav(a, rate, 2)


def mono_wav(samples, rate):
    return _wav(np.asarray(samples, dtype=np.float64), rate, 1)


# ---- channel ---------------------------------------------------------------------------------------

def noise(n, sigma, seed):
    rng = np.random.default_rng(seed)
    return sigma * (rng.standard_normal(n) + 1j * rng.standard_normal(n)) / math.sqrt(2.0)


def channel(iq, *, lead=0, tail=0, cfo=0.0, sigma=0.0, seed=1, phase=0.7):
    """A burst in a capture: `lead` and `tail` samples of silence around it, a carrier offset of
    `cfo` cycles per sample, a fixed phase, and complex white noise of standard deviation sigma."""
    x = np.concatenate((np.zeros(lead, dtype=complex), np.asarray(iq, dtype=complex), np.zeros(tail, dtype=complex)))
    x = x * np.exp(1j * (2 * np.pi * cfo * np.arange(x.size) + phase))
    return x + noise(x.size, sigma, seed) if sigma else x


def bits_of(data, msb_first=True):
    out = []
    for byte in data:
        for k in range(8):
            out.append((byte >> (7 - k)) & 1 if msb_first else (byte >> k) & 1)
    return out


# ---- FSK / GFSK ------------------------------------------------------------------------------------

def fsk_iq(bits, sps, deviation, bt=None):
    """2-level FSK at `sps` samples per bit (may be fractional): a 1 is +deviation, a 0 is -deviation
    (cycles per sample). bt: Gaussian pre-modulation filter bandwidth x bit time (GFSK); None = plain."""
    n = int(round(len(bits) * sps))
    idx = np.minimum((np.arange(n) / sps).astype(int), len(bits) - 1)
    f = (2.0 * np.asarray(bits, dtype=np.float64)[idx] - 1.0) * deviation
    if bt:
        sigma = math.sqrt(math.log(2.0)) * sps / (2.0 * math.pi * bt)
        k = np.arange(-int(4 * sigma), int(4 * sigma) + 1)
        g = np.exp(-0.5 * (k / sigma) ** 2)
        f = np.convolve(f, g / g.sum(), mode="same")
    return np.exp(2j * np.pi * np.cumsum(f))


# ---- POCSAG (ITU-R M.584) --------------------------------------------------------------------------

POCSAG_SYNC = 0x7CD215D8
POCSAG_IDLE = 0x7A89C197


def pocsag_codeword(info21):
    """A 32-bit POCSAG codeword of 21 information bits: BCH(31,21) check bits (generator
    x^10+x^9+x^8+x^6+x^5+x^3+1 = 0x769), then one even-parity bit."""
    reg = info21 << 10
    for bit in range(30, 9, -1):
        if reg & (1 << bit):
            reg ^= 0x769 << (bit - 10)
    word31 = (info21 << 10) | (reg & 0x3FF)
    return (word31 << 1) | (bin(word31).count("1") & 1)


def pocsag_bits(address, text, function=3, preamble_bits=576):
    """One transmission: the 1010... preamble, then batches of sync + 16 codewords. The address
    codeword goes in the frame its low three bits name; the alphanumeric text follows as message
    codewords (7-bit characters, least-significant bit first, packed 20 bits per codeword); every
    other slot is the idle codeword."""
    stream = []
    for ch in text.encode("ascii"):
        stream += [(ch >> k) & 1 for k in range(7)]
    stream += [0] * (-len(stream) % 20)
    msgs = []
    for i in range(0, len(stream), 20):
        info = (1 << 20) | int("".join(map(str, stream[i:i + 20])), 2)
        msgs.append(pocsag_codeword(info))
    words = [POCSAG_IDLE] * (2 * (address & 7))
    words.append(pocsag_codeword(((address >> 3) << 2) | (function & 3)))
    words += msgs
    words.append(POCSAG_IDLE)
    words += [POCSAG_IDLE] * (-len(words) % 16)
    bits = [1, 0] * (preamble_bits // 2)
    for i in range(0, len(words), 16):
        for w in [POCSAG_SYNC] + words[i:i + 16]:
            bits += [(w >> (31 - k)) & 1 for k in range(32)]
    return bits


# ---- P25 phase 1 (TIA-102.BAAA) --------------------------------------------------------------------

P25_SYNC = 0x5575F5FF77FF
P25_BCH_GENERATOR = 0o6331141367235453     # g(x) of the (63,16,23) BCH code, degree 47
P25_LENGTHS = {0x0: 792, 0x3: 144, 0x5: 1728, 0x7: 720, 0xA: 1728, 0xF: 432}
P25_DUID_PARITY = {0x0: 0, 0x3: 0, 0x5: 1, 0x7: 0, 0xA: 1, 0xC: 0, 0xF: 0}   # the P column of the DUID table


def p25_nid(nac, duid):
    """The 64-bit NID: NAC (12 bits) + DUID (4 bits), 47 BCH check bits, then the parity bit the
    data-unit table assigns to that DUID."""
    info = ((nac & 0xFFF) << 4) | (duid & 0xF)
    reg = info << 47
    for bit in range(62, 46, -1):
        if reg & (1 << bit):
            reg ^= P25_BCH_GENERATOR << (bit - 47)
    word63 = (info << 47) | (reg & ((1 << 47) - 1))
    return (word63 << 1) | P25_DUID_PARITY[duid & 0xF]


def p25_frame_bits(nac, duid, payload_bits=None, seed=5, status=(1, 0), total=None):
    """The transmitted bits of one data unit: frame sync, NID, then payload, with a status symbol
    (two bits) after every 70 bits. payload_bits fills the structural bits after the NID (default:
    seeded random bits); it is padded or cut to the data unit's length. `total` is the transmitted
    length of a packet data unit (DUID 0xC), which has no fixed one: a multiple of 72 bits."""
    total = total or P25_LENGTHS[duid]
    logical_len = total - 2 * (total // 72)
    rng = np.random.default_rng(seed)
    body = list(payload_bits) if payload_bits is not None else []
    need = logical_len - 112
    body = (body + rng.integers(0, 2, max(0, need - len(body))).tolist())[:need]
    logical = [(P25_SYNC >> (47 - k)) & 1 for k in range(48)]
    nid = p25_nid(nac, duid)
    logical += [(nid >> (63 - k)) & 1 for k in range(64)]
    logical += body
    out = []
    for i in range(0, logical_len, 70):
        out += logical[i:i + 70] + list(status)
    assert len(out) == total
    return out


def c4fm_iq(bits, sps, rate=None, deviation_hz=600.0):
    """C4FM: dibits 01 -> +3, 00 -> +1, 10 -> -1, 11 -> -3 (x deviation_hz, so the outer levels are
    +-1800 Hz), shaped by the TIA-102 transmit filter: a raised cosine (roll-off 0.2) times the
    inverse-sinc pre-emphasis (pi f T / sin(pi f T)), which an integrate-and-dump receiver undoes.
    `sps` samples per symbol (4800 symbols/s; rate defaults to 4800 * sps). Eight symbol times of
    unmodulated carrier lead in and out, so the first data symbol starts 8 * sps samples in."""
    rate = rate or 4800.0 * sps
    level = {(0, 1): 3.0, (0, 0): 1.0, (1, 0): -1.0, (1, 1): -3.0}
    syms = np.array([level[(bits[i], bits[i + 1])] for i in range(0, len(bits) - 1, 2)])
    guard = 8                                           # symbols of bare carrier either side of the data
    over = 8                                            # built 8x oversampled so symbol centres land on the grid
    sps, rate = sps * over, rate * over
    n = int(round((syms.size + 2 * guard) * sps))
    impulses = np.zeros(n)
    centres = np.minimum(np.rint((np.arange(syms.size) + guard + 0.5) * sps).astype(int), n - 1)
    impulses[centres] = syms * sps
    f = np.fft.rfftfreq(n, 1.0 / rate)
    t_sym = 1.0 / 4800.0
    rc = np.zeros(f.size)
    lo, hi = 0.8 / (2 * t_sym), 1.2 / (2 * t_sym)        # 1920 Hz and 2880 Hz
    rc[f <= lo] = 1.0
    mid = (f > lo) & (f < hi)
    rc[mid] = 0.5 + 0.5 * np.cos(np.pi * (f[mid] - lo) / (hi - lo))
    x = np.pi * f * t_sym
    inv_sinc = np.ones(f.size)
    nz = (x > 1e-9) & (f < hi)
    inv_sinc[nz] = x[nz] / np.sin(x[nz])
    shaped = np.fft.irfft(np.fft.rfft(impulses) * rc * inv_sinc, n)
    return np.exp(2j * np.pi * np.cumsum(shaped * deviation_hz / rate))[::over]


# ---- TETRA (ETSI EN 300 392-2 clause 9) ------------------------------------------------------------

TETRA_N1 = "1101000011101001110100"           # normal training sequence 1
TETRA_N2 = "0111101001000011011110"           # normal training sequence 2
TETRA_Q = "1011011100000110101101"            # normal training sequence 3 (q1..q22)
TETRA_SYNC = "11000001100111001110100111000001100111"   # synchronisation training sequence
TETRA_TAIL = "1100"
TETRA_FCB = "1" * 8 + "0" * 64 + "1" * 8      # frequency correction field


def _rand_bits(n, rng):
    return "".join(map(str, rng.integers(0, 2, n).tolist()))


def tetra_ndb(rng, training=TETRA_N1, block1=None, block2=None):
    """A normal continuous downlink burst, 510 bits: q11..q22, 2 phase-adjustment bits, block 1
    (216), broadcast (14), training (22), broadcast (16), block 2 (216), 2 phase bits, q1..q10."""
    b1 = block1 if block1 is not None else _rand_bits(216, rng)
    b2 = block2 if block2 is not None else _rand_bits(216, rng)
    burst = (TETRA_Q[10:] + _rand_bits(2, rng) + b1 + _rand_bits(14, rng) + training
             + _rand_bits(16, rng) + b2 + _rand_bits(2, rng) + TETRA_Q[:10])
    assert len(burst) == 510
    return burst


def tetra_sb(rng):
    """A synchronisation continuous downlink burst, 510 bits: q11..q22, 2 phase bits, frequency
    correction (80), sync block 1 (120), synchronisation training (38), broadcast (30), block 2
    (216), 2 phase bits, q1..q10."""
    burst = (TETRA_Q[10:] + _rand_bits(2, rng) + TETRA_FCB + _rand_bits(120, rng) + TETRA_SYNC
             + _rand_bits(30, rng) + _rand_bits(216, rng) + _rand_bits(2, rng) + TETRA_Q[:10])
    assert len(burst) == 510
    return burst


def tetra_nub(rng, training=TETRA_N1):
    """A normal uplink burst, 462 bits: tail (4), block 1 (216), training (22), block 2 (216), tail (4)."""
    burst = TETRA_TAIL + _rand_bits(216, rng) + training + _rand_bits(216, rng) + TETRA_TAIL
    assert len(burst) == 462
    return burst


def pi4dqpsk_iq(bits, sps, alpha=0.35):
    """pi/4-DQPSK (EN 300 392-2 clause 5): each bit pair is a phase step, 00 -> +pi/4, 01 -> +3pi/4,
    11 -> -3pi/4, 10 -> -pi/4; the symbols are impulses through a root-raised-cosine filter of
    roll-off alpha, built here in the frequency domain (the square root of the raised-cosine
    spectrum). `sps` is a whole number of samples per symbol (18000 symbols/s)."""
    step = {"00": math.pi / 4, "01": 3 * math.pi / 4, "11": -3 * math.pi / 4, "10": -math.pi / 4}
    text = bits if isinstance(bits, str) else "".join(map(str, bits))
    phase = np.cumsum([step[text[i:i + 2]] for i in range(0, len(text) - 1, 2)])
    syms = np.concatenate(([1.0 + 0j], np.exp(1j * phase)))     # a reference symbol, then the steps
    n = syms.size * sps
    up = np.zeros(n, dtype=complex)
    up[sps // 2::sps] = syms
    f = np.abs(np.fft.fftfreq(n, 1.0 / sps))                    # in symbol rates
    rc = np.zeros(n)
    lo, hi = (1 - alpha) / 2.0, (1 + alpha) / 2.0
    rc[f <= lo] = 1.0
    mid = (f > lo) & (f < hi)
    rc[mid] = 0.5 * (1 + np.cos(np.pi / alpha * (f[mid] - lo)))
    return np.fft.ifft(np.fft.fft(up) * np.sqrt(rc))


def resample(iq, ratio):
    """A capture re-read at `ratio` times its sample rate (linear interpolation; build the capture
    well oversampled first)."""
    t = np.arange(int(np.asarray(iq).size * ratio)) / ratio
    x = np.asarray(iq)
    return np.interp(t, np.arange(x.size), x.real) + 1j * np.interp(t, np.arange(x.size), x.imag)


# ---- LoRa ------------------------------------------------------------------------------------------

def lora_symbol(value, sf, os=1, down=False):
    """One LoRa symbol at `os` samples per chip: an upchirp whose frequency starts `value` bins
    above the band's lower edge, rises one bandwidth per symbol and wraps at the upper edge (a
    downchirp when down=True). The phase is the integral of that frequency, k^2/2N + (value/N - 1/2) k
    cycles at chip time k, less one cycle per chip after the wrap, so the wrap is explicit at any
    oversampling (at one sample per chip it is a whole cycle and vanishes)."""
    n = 1 << sf
    k = np.arange(n * os) / float(os)
    cycles = k * k / (2.0 * n) + (value / float(n) - 0.5) * k
    wrap = n - value
    cycles = cycles - np.where(k >= wrap, k - wrap, 0.0)
    return np.exp(-2j * np.pi * cycles) if down else np.exp(2j * np.pi * cycles)


def lora_iq(symbols, sf, os=1, preamble=8, sync_word=0x12):
    """A whole packet: `preamble` upchirps, the two sync-word symbols (8 x each nibble), 2.25
    downchirps, then the data symbols (raw bins, as the Tapparel transmit chain emits them)."""
    parts = [lora_symbol(0, sf, os) for _ in range(preamble)]
    parts += [lora_symbol(8 * (sync_word >> 4), sf, os), lora_symbol(8 * (sync_word & 0xF), sf, os)]
    down = lora_symbol(0, sf, os, down=True)
    parts += [down, down, down[:down.size // 4]]
    parts += [lora_symbol(int(s), sf, os) for s in symbols]
    return np.concatenate(parts)


# ---- SSTV ------------------------------------------------------------------------------------------

class ToneWriter:
    """Phase-continuous tones laid end to end on an exact millisecond schedule."""

    def __init__(self, rate):
        self.rate, self.phase, self.elapsed_ms, self.samples, self.parts = rate, 0.0, 0.0, 0, []

    def tone(self, frequency, duration_ms):
        target_ms = self.elapsed_ms + duration_ms
        target = int(round(target_ms * self.rate / 1000.0))
        count = target - self.samples
        self.parts.append(0.7 * np.sin(self.phase + 2 * np.pi * frequency * np.arange(count) / self.rate))
        self.phase = (self.phase + 2 * np.pi * frequency * count / self.rate) % (2 * np.pi)
        self.elapsed_ms, self.samples = target_ms, target

    def video(self, value, duration_ms):
        self.tone(1500.0 + float(value) * 800.0 / 255.0, duration_ms)

    def finish(self):
        return np.concatenate(self.parts)


def sstv_header(writer, vis, bad_parity=False):
    """The calibration header: 300 ms 1900 Hz, 10 ms 1200 Hz, 300 ms 1900 Hz, then the VIS code
    (start bit 1200 Hz, seven bits least-significant first 1100 = 1 / 1300 = 0, even parity, stop).
    bad_parity sends the wrong parity bit."""
    writer.tone(1900, 300)
    writer.tone(1200, 10)
    writer.tone(1900, 300)
    writer.tone(1200, 30)
    bits = [(vis >> k) & 1 for k in range(7)]
    bits.append((sum(bits) & 1) ^ int(bad_parity))
    for bit in bits:
        writer.tone(1100 if bit else 1300, 30)
    writer.tone(1200, 30)


def scottie_lines(rate, colours, vis=56, scan_ms=88.064, lead_ms=0.0):
    """Scottie audio (S2 by default): `lead_ms` of silence, the header, the starting sync, then one
    line per (red, green, blue) in `colours`, each a flat colour: porch, green, porch, blue, sync,
    porch, red. Returns the samples."""
    writer = ToneWriter(rate)
    _lead_in(writer, rate, lead_ms)
    sstv_header(writer, vis)
    writer.tone(1200, 9)
    for red, green, blue in colours:
        writer.tone(1500, 1.5)
        writer.video(green, scan_ms)
        writer.tone(1500, 1.5)
        writer.video(blue, scan_ms)
        writer.tone(1200, 9)
        writer.tone(1500, 1.5)
        writer.video(red, scan_ms)
    return writer.finish()


def martin_lines(rate, colours, vis=44, scan_ms=146.432, lead_ms=0.0):
    """Martin audio (M1 by default): header, then per line sync (4.862 ms), porch, green, porch,
    blue, porch, red, porch (each porch 0.572 ms at 1500 Hz)."""
    writer = ToneWriter(rate)
    _lead_in(writer, rate, lead_ms)
    sstv_header(writer, vis)
    for red, green, blue in colours:
        writer.tone(1200, 4.862)
        writer.tone(1500, 0.572)
        for value in (green, blue, red):
            writer.video(value, scan_ms)
            writer.tone(1500, 0.572)
    return writer.finish()


def _lead_in(writer, rate, lead_ms):
    if lead_ms:
        writer.parts.append(np.zeros(int(round(lead_ms * rate / 1000.0))))
        writer.samples = writer.parts[0].size
        writer.elapsed_ms = writer.samples * 1000.0 / rate


def pd_lines(rate, periods, vis=93, scan_ms=91.520, lead_ms=0.0):
    """PD audio (PD50 by default): header, then per scan period a 20 ms sync, a 2.08 ms porch and
    four scans, Y of the first row, R-Y, B-Y, Y of the second row, each a flat value. `periods` is a
    list of (y0, red_y, blue_y, y1): one entry is two picture rows."""
    writer = ToneWriter(rate)
    _lead_in(writer, rate, lead_ms)
    sstv_header(writer, vis)
    for y0, red_y, blue_y, y1 in periods:
        writer.tone(1200, 20)
        writer.tone(1500, 2.08)
        for value in (y0, red_y, blue_y, y1):
            writer.video(value, scan_ms)
    return writer.finish()


def robot36_lines(rate, lines, lead_ms=0.0):
    """Robot 36 audio: header, then per line a 9 ms sync, a 3 ms porch, 88 ms of luminance, a 4.5 ms
    separator (1500 Hz before R-Y on even lines, 2300 Hz before B-Y on odd ones), a 1.5 ms porch and
    44 ms of that chroma. `lines` is a list of (y, chroma)."""
    writer = ToneWriter(rate)
    _lead_in(writer, rate, lead_ms)
    sstv_header(writer, 8)
    for index, (y, chroma) in enumerate(lines):
        writer.tone(1200, 9)
        writer.tone(1500, 3)
        writer.video(y, 88)
        writer.tone(2300 if index % 2 else 1500, 4.5)
        writer.tone(1900, 1.5)
        writer.video(chroma, 44)
    return writer.finish()


def yuv_rgb(y, red_y, blue_y):
    """The N7CXI colour equations the Robot and PD modes use, rounded to 8 bits."""
    red = 0.003906 * (298.082 * (y - 16) + 408.583 * (red_y - 128))
    green = 0.003906 * (298.082 * (y - 16) - 100.291 * (blue_y - 128) - 208.120 * (red_y - 128))
    blue = 0.003906 * (298.082 * (y - 16) + 516.411 * (blue_y - 128))
    return np.clip(np.rint([red, green, blue]), 0, 255).astype(np.uint8)


def fm_iq(audio, rate, deviation_hz=3000.0):
    """Narrow-band FM of audio already at the IQ sample rate: the carrier phase is the running sum
    of the audio times the deviation."""
    return np.exp(2j * np.pi * deviation_hz * np.cumsum(np.asarray(audio, dtype=np.float64)) / rate)
