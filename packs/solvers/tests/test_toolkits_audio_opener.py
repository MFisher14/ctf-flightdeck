"""B-129: decode_morse_tone wired into the forensics opener (toolkits.audio_opener) and run at intake.

Every recording is synthesised here (rule 4): Morse keyed from a timing table the test holds,
DTMF from the standard row/column pairs, MP3s encoded in-process by libsndfile, ID3 tags and EXIF
blocks built byte by byte (or by PIL). Every text, caption and file name here is neutral and written
for this test; the only thing taken from the Nosocomephobia drop (the item spec's regression) is its
keying shape: a 548 Hz tone, dot 25 ms, dash 75 ms, word gap 165 ms, and a message that uses quotes,
"??" and "...". The intake test uses a fake platform adapter; no network is used.
"""
from __future__ import annotations

import io
import struct
import sys
import zipfile
from pathlib import Path

import numpy as np
import pytest

from ctf import event, flagfmt, paths

REPO = paths.repo_root()
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import audio_opener as ao  # noqa: E402
import signal_stego_depth as sig  # noqa: E402

SPOOKY = event.load("spooky")
FF = flagfmt.for_profile(SPOOKY)
INV = {v: k for k, v in sig.MORSE.items()}


def _soundfile_mp3() -> bool:
    try:
        import soundfile
    except (ImportError, OSError):
        return False
    return "MP3" in soundfile.available_formats()


needs_mp3 = pytest.mark.skipif(not _soundfile_mp3(), reason="soundfile/libsndfile with MPEG (MP3) support is absent")
needs_sf = pytest.mark.needs_tool("py:soundfile")

# Neutral text written for this test, with the punctuation classes the regression needs (quotes, "??", "...").
MESSAGE = 'TESTING?? THIS IS A RECORDED BEACON... THE "SPARE" KEY IS IN LOCKER 42'
CAPTION = "Harbour wall, looking east, circa 1900"


# ---- synthesis ---------------------------------------------------------------------------------

def morse_signal(text, rate, *, hz=548.0, dot=25, dash=75, intra=25, char=75, word=165, amp=0.5,
                 lead=300, noise=0.0, seed=7):
    def ms(m):
        return int(round(rate * m / 1000))

    def tone(m):
        return amp * np.sin(2 * np.pi * hz * np.arange(ms(m)) / rate)
    out = [np.zeros(ms(lead))]
    for wi, w in enumerate(text.split(" ")):
        if wi:
            out.append(np.zeros(ms(word)))
        for ci, c in enumerate(w):
            if ci:
                out.append(np.zeros(ms(char)))
            for si, mark in enumerate(INV[c]):
                if si:
                    out.append(np.zeros(ms(intra)))
                out.append(tone(dot if mark == "." else dash))
    out.append(np.zeros(ms(lead)))
    x = np.concatenate(out)
    if noise:
        x = x + np.random.RandomState(seed).normal(0, noise, x.size)
    return x


def wav_bytes(x, rate, **tags):
    import soundfile as sf
    b = io.BytesIO()
    with sf.SoundFile(b, "w", rate, 1, format="WAV", subtype="PCM_16") as f:
        for k, v in tags.items():
            setattr(f, k, v)
        f.write(np.clip(x, -1, 1))
    return b.getvalue()


def mp3_bytes(x, rate):
    import soundfile as sf
    b = io.BytesIO()
    sf.write(b, np.clip(x, -1, 1), rate, format="MP3")
    return b.getvalue()


DTMF = {k: (r, c) for r, row in zip(sig.DTMF_ROWS, sig.DTMF_KEYS) for c, k in zip(sig.DTMF_COLS, row)}


def dtmf_signal(keys, rate=8000, press=80, gap=60, odd=None, click=None, click_ms=20):
    out = [np.zeros(rate // 5)]
    t = np.arange(int(rate * press / 1000)) / rate
    for i, k in enumerate(keys):
        if click is not None and i == click:                             # a short burst of key 5 before key i
            tc = np.arange(int(rate * click_ms / 1000)) / rate
            r, c = DTMF["5"]
            out += [0.3 * np.sin(2 * np.pi * r * tc) + 0.3 * np.sin(2 * np.pi * c * tc), np.zeros(int(rate * gap / 1000))]
        if odd is not None and i == odd:
            out.append(0.5 * np.sin(2 * np.pi * 548 * t))
        else:
            r, c = DTMF[k]
            out.append(0.3 * np.sin(2 * np.pi * r * t) + 0.3 * np.sin(2 * np.pi * c * t))
        out.append(np.zeros(int(rate * gap / 1000)))
    out.append(np.zeros(rate // 5))
    return np.concatenate(out)


def _syncsafe(n):
    return bytes([(n >> 21) & 0x7F, (n >> 14) & 0x7F, (n >> 7) & 0x7F, n & 0x7F])


def id3v2(frames, major=3):
    body = b""
    for fid, payload in frames:
        size = _syncsafe(len(payload)) if major == 4 else struct.pack(">I", len(payload))
        body += fid.encode() + size + b"\x00\x00" + payload
    return b"ID3" + bytes([major, 0, 0]) + _syncsafe(len(body)) + body


def id3v1(title="", comment="", year=""):
    def pad(s, n):
        return s.encode("latin-1")[:n].ljust(n, b"\x00")
    return b"TAG" + pad(title, 30) + pad("", 30) + pad("", 30) + pad(year, 4) + pad(comment, 30) + b"\xff"


def jpeg_with_description(text):
    from PIL import Image
    im = Image.new("RGB", (8, 8), "white")
    ex = Image.Exif()
    ex[0x010E] = text
    b = io.BytesIO()
    im.save(b, "JPEG", exif=ex.tobytes())
    return b.getvalue()


# ---- the carried decoder: lattice, tolerance, table ------------------------------------------

def test_the_nosocomephobia_timing_fits_the_lattice_only_because_of_the_tolerance():
    # 25/75/165 ms: the word gap is 6.6 units, not 7 (error 0.4 = 0.057 of 7). Exact 5 ms blocks at
    # 8 kHz make the run lengths exact, so the boundary is the tolerance alone.
    audio = sig.Audio(8000, morse_signal(MESSAGE, 8000))
    assert sig.decode_morse_tone(audio) == MESSAGE.encode()
    assert sig.decode_morse_tone(audio, tolerance=0.06) == MESSAGE.encode()
    assert sig.decode_morse_tone(audio, tolerance=0.05) is None
    # the same text with a true 7-unit word gap passes even a tight tolerance: the 165 ms gap is the cause
    exact = sig.Audio(8000, morse_signal(MESSAGE, 8000, word=175))
    assert sig.decode_morse_tone(exact, tolerance=0.05) == MESSAGE.encode()


def test_quote_and_ampersand_are_in_the_morse_table():
    assert sig.MORSE[".-..-."] == '"' and sig.MORSE[".-..."] == "&"
    audio = sig.Audio(8000, morse_signal('SAY "R&D"', 8000))
    assert sig.decode_morse_tone(audio) == b'SAY "R&D"'


def test_tone_hz_keys_on_the_tone_where_broadband_hum_hides_it():
    rate = 8000
    x = morse_signal("SOS HELP", rate, amp=0.3)
    x = x + 0.3 * np.sin(2 * np.pi * 60 * np.arange(x.size) / rate)      # mains hum under the keying
    audio = sig.Audio(rate, x)
    assert sig.decode_morse_tone(audio) is None
    assert sig.decode_morse_tone(audio, tone_hz=548.0) == b"SOS HELP"
    assert sig.decode_morse_tone(audio, tone_hz=1500.0) is None          # nothing keyed there
    assert sig.decode_morse_tone(audio, tone_hz=rate) is None            # above Nyquist: refused


def test_long_gaps_reads_a_pause_as_a_word_break_but_keeps_the_tone_lattice():
    rate = 8000
    a = morse_signal("SOS", rate)
    b = morse_signal("SOS", rate)
    pause = np.zeros(int(rate * 0.9))                                    # 36 units of silence
    audio = sig.Audio(rate, np.concatenate([a, pause, b]))
    assert sig.decode_morse_tone(audio) is None
    assert sig.decode_morse_tone(audio, long_gaps=True) == b"SOS SOS"
    bad = sig.Audio(rate, morse_signal("SOS", rate, dash=125))           # a 5-unit tone fits nothing
    assert sig.decode_morse_tone(bad, long_gaps=True) is None
    long_tone = sig.Audio(rate, morse_signal("SOS", rate, dash=225))     # a 9-unit tone is no word gap
    assert sig.decode_morse_tone(long_tone, long_gaps=True) is None


def test_long_gaps_takes_any_silence_over_seven_units_whatever_the_tolerance():
    # a 7.6-unit gap (190 ms at a 25 ms unit, exact 5 ms blocks) is off the lattice by 0.6 units:
    # a tight tolerance refuses it, long_gaps reads it as the word gap it is
    rate = 8000
    audio = sig.Audio(rate, morse_signal("SOS SOS", rate, word=190))
    assert sig.decode_morse_tone(audio, tolerance=0.05) is None
    assert sig.decode_morse_tone(audio, tolerance=0.05, long_gaps=True) == b"SOS SOS"
    # a gap under 7 units still has to fit the tolerance: 6.6 units (165 ms) at 0.05 is refused
    short = sig.Audio(rate, morse_signal("SOS SOS", rate, word=165))
    assert sig.decode_morse_tone(short, tolerance=0.05, long_gaps=True) is None


def test_keyed_runs_needs_two_levels():
    rate = 8000
    assert sig.keyed_runs(sig.Audio(rate, 0.3 * np.sin(2 * np.pi * 548 * np.arange(rate) / rate)), tone_hz=548) is None
    runs = sig.keyed_runs(sig.Audio(rate, morse_signal("E E", rate)), tone_hz=548)
    assert runs == [(True, 5), (False, 33), (True, 5)]


def test_dtmf_key_classifies_a_pair_and_refuses_a_single_tone():
    t = np.arange(400) / 8000
    assert sig.dtmf_key(0.3 * np.sin(2 * np.pi * 852 * t) + 0.3 * np.sin(2 * np.pi * 1477 * t), 8000) == "9"
    assert sig.dtmf_key(0.5 * np.sin(2 * np.pi * 548 * t), 8000) is None


# ---- the opener's pieces ---------------------------------------------------------------------

def test_sniff_by_content():
    assert ao.sniff(b"RIFF\x00\x00\x00\x00WAVEfmt ") == "wav"
    assert ao.sniff(b"RIFF\x00\x00\x00\x00WEBPVP8 ") is None
    assert ao.sniff(b"ID3\x03\x00\x00\x00\x00\x00\x00") == "mp3"
    assert ao.sniff(b"\xff\xfb\x90\xc4\x00") == "mp3"
    assert ao.sniff(b"\xff\xd8\xff\xe0\x00") is None                     # JPEG is not a frame sync
    assert ao.sniff(b"fLaC\x00\x00\x00\x22") == "flac"
    assert ao.sniff(b"OggS\x00\x02") == "ogg"
    assert ao.sniff(b"FORM\x00\x00\x00\x00AIFF") == "aiff"
    assert ao.image_kind(b"RIFF\x00\x00\x00\x00WEBPVP8 ") == "webp"


def test_sniff_refuses_a_frame_sync_with_reserved_fields():
    # 11 sync bits alone are common in binary data: the version, layer and bitrate fields must be valid
    assert ao.sniff(b"\xff\xfb\x90\xc4") == "mp3"                       # MPEG-1 layer III, 128 kbit/s
    assert ao.sniff(b"\xff\xf9\x90\xc4") is None                         # layer bits 00: reserved
    assert ao.sniff(b"\xff\xeb\x90\xc4") is None                         # version bits 01: reserved
    assert ao.sniff(b"\xff\xfb\xf0\xc4") is None                         # bitrate index 1111: bad


def test_dominant_tones_finds_the_carrier_and_nothing_in_noise():
    rate = 22050
    tones = ao.dominant_tones(morse_signal(MESSAGE, rate, noise=0.05), rate)
    assert tones and abs(tones[0].hz - 548.0) < 2.0
    assert all(t.prominence >= ao.TONE_FLOOR for t in tones)
    assert ao.dominant_tones(np.random.RandomState(1).normal(0, 0.3, rate * 2), rate) == []


def test_dominant_tones_keeps_both_tones_of_a_pair_and_drops_side_lobes():
    rate = 8000
    t = np.arange(rate) / rate
    pair = ao.dominant_tones(0.3 * np.sin(2 * np.pi * 770 * t) + 0.3 * np.sin(2 * np.pi * 1336 * t), rate)
    assert sorted(round(x.hz) for x in pair) == [770, 1336]
    one = ao.dominant_tones(0.5 * np.sin(2 * np.pi * 548 * t) + np.random.RandomState(2).normal(0, 1e-4, rate), rate)
    assert len(one) == 1 and abs(one[0].hz - 548) < 1
    weak = ao.dominant_tones(0.5 * np.sin(2 * np.pi * 548 * t) + 0.02 * np.sin(2 * np.pi * 1500 * t), rate)
    assert [round(x.hz) for x in weak] == [548]                       # -28 dB: under TONE_SPREAD
    # on/off keying puts sidebands within a few tens of Hz of the carrier: one keyed tone, one entry
    for x, r in ((morse_signal(MESSAGE, 8000), 8000), (morse_signal("E E E E", 8000, dot=100, intra=100, char=300,
                                                                     word=700), 8000)):
        keyed = ao.dominant_tones(x, r)
        assert len(keyed) == 1 and abs(keyed[0].hz - 548) < 3, keyed


def test_keying_reports_the_runs_in_ms():
    k = ao.keying(morse_signal("E E", 8000), 8000, 548.0)
    assert k.on_ms == (25.0, 25.0) and k.off_ms == (165.0,) and k.unit_ms == 25.0
    assert "unit ~25 ms" in k.summary() and "548.0 Hz" in k.summary()


def test_read_morse_falls_back_to_the_broadband_envelope_when_no_tone_stands_out():
    # Morse keyed as white-noise bursts: no narrow tone, so only the broadband envelope reads it
    rate = 8000
    keyed = morse_signal("NOISE CODE", rate, amp=1.0)
    x = np.where(keyed != 0, np.random.RandomState(5).normal(0, 0.3, keyed.size), 0.0)
    pcm = ao.Pcm(rate, x, 1, rate, x.size / rate)
    tones = ao.dominant_tones(x, rate)
    assert tones == []
    got = ao.read_morse(pcm, tones)
    assert got is not None and got.text == "NOISE CODE" and got.tone_hz is None and got.unit_ms == 25.0
    # with a keyed tone present the tone reading comes first and names its frequency
    tone = ao.Pcm(rate, morse_signal("SOS", rate), 1, rate, 1.0)
    assert ao.read_morse(tone, ao.dominant_tones(tone.samples, rate)).tone_hz is not None


def test_read_morse_reads_a_sentence_pause_as_a_word_break():
    # two transmissions 900 ms apart (36 units): the opener reads the pause as a word gap
    rate = 8000
    x = np.concatenate([morse_signal("SOS", rate), np.zeros(int(rate * 0.9)), morse_signal("CQ", rate)])
    pcm = ao.Pcm(rate, x, 1, rate, x.size / rate)
    got = ao.read_morse(pcm, ao.dominant_tones(x, rate))
    assert got is not None and got.text == "SOS CQ" and abs(got.tone_hz - 548.0) < 3.0


def test_read_dtmf_reads_every_press_or_nothing():
    pcm = ao.Pcm(8000, dtmf_signal("159#*0D"), 1, 8000, 1.0)
    assert ao.read_dtmf(pcm) == "159#*0D"
    odd = ao.Pcm(8000, dtmf_signal("159#*0D", odd=3), 1, 8000, 1.0)
    assert ao.read_dtmf(odd) is None
    assert ao.read_dtmf(ao.Pcm(8000, dtmf_signal("15"), 1, 8000, 1.0)) is None          # under min_keys
    assert ao.read_dtmf(ao.Pcm(8000, dtmf_signal("1590", press=20), 1, 8000, 1.0)) is None   # clicks, not presses


def test_one_click_among_real_presses_refuses_the_dtmf_read():
    # four real 80 ms presses with one 20 ms burst between them: the burst is not skipped (that would
    # read "1590" and hide an unexplained event); every tone run must be a full press.
    clean = ao.Pcm(8000, dtmf_signal("1590"), 1, 8000, 1.0)
    assert ao.read_dtmf(clean) == "1590"
    assert ao.read_dtmf(ao.Pcm(8000, dtmf_signal("1590", click=2), 1, 8000, 1.0)) is None
    # a 30 ms burst is a press (the minimum), so it is read as key 5
    assert ao.read_dtmf(ao.Pcm(8000, dtmf_signal("1590", click=2, click_ms=30), 1, 8000, 1.0)) == "15590"


def test_more_presses_than_the_cap_refuse_the_dtmf_read(monkeypatch):
    # a recording with more keys than MAX_DTMF_KEYS is not a keypad message: refuse it rather than
    # print an unbounded key string. At the cap exactly the read still stands.
    pcm = ao.Pcm(8000, dtmf_signal("1590"), 1, 8000, 1.0)
    monkeypatch.setattr(ao, "MAX_DTMF_KEYS", 4)
    assert ao.read_dtmf(pcm, min_keys=1) == "1590"
    monkeypatch.setattr(ao, "MAX_DTMF_KEYS", 3)
    assert ao.read_dtmf(pcm, min_keys=1) is None
    monkeypatch.setattr(ao, "MAX_DTMF_KEYS", 2)
    assert ao.read_dtmf(pcm, min_keys=1) is None


def test_the_shortest_accepted_press_is_classified_whole():
    # 30 ms presses (DTMF_MIN_PRESS_MS) read: the whole run goes to dtmf_key. Classifying only the
    # middle 10 ms block (a key-up trim) cannot separate 697 from 770 Hz and loses every key.
    assert ao.DTMF_MIN_PRESS_MS == 30.0
    pcm = ao.Pcm(8000, dtmf_signal("159#*0D", press=30), 1, 8000, 1.0)
    assert ao.read_dtmf(pcm) == "159#*0D"


def test_id3_tags_v23_v24_and_v1():
    comm = b"\x03eng" + b"\x00" + b"pier, circa 1900"
    txxx = b"\x01" + "where".encode("utf-16") + b"\x00\x00" + "Locker 42".encode("utf-16")
    tag = id3v2([("TIT2", b"\x00side A recording"), ("COMM", comm), ("TXXX", txxx),
                 ("WOAR", b"http://example.invalid/a")], major=3)
    rows = dict(ao.id3_tags(tag + b"\xff\xfb\x90\xc4" + b"\x00" * 200 + id3v1("tape", "test me", "1999")))
    assert rows["TIT2"] == "side A recording"
    assert rows["COMM"] == "pier, circa 1900"
    assert rows["TXXX:where"] == "Locker 42"
    assert rows["WOAR"] == "http://example.invalid/a"
    assert rows["v1.title"] == "tape" and rows["v1.comment"] == "test me" and rows["v1.year"] == "1999"
    # v2.4 sizes are syncsafe: a 200-byte frame (0xC8 as a plain integer) only parses as syncsafe
    long = "x" * 199
    rows4 = dict(ao.id3_tags(id3v2([("TPE1", b"\x03" + long.encode()), ("TALB", b"\x03after")], major=4)))
    assert rows4["TPE1"] == long and rows4["TALB"] == "after"


def test_id3_extended_header_is_skipped_before_the_frames():
    frames = id3v2([("TIT2", b"\x00after ext"), ("TPE1", b"\x00someone")], major=3)[10:]
    # v2.3: a 4-byte size that excludes itself (6), 2 flag bytes, 4 bytes of padding size
    ext3 = struct.pack(">I", 6) + b"\x00\x00" + b"\x00\x00\x00\x00"
    raw3 = b"ID3\x03\x00\x40" + _syncsafe(len(ext3) + len(frames)) + ext3 + frames
    assert dict(ao.id3_tags(raw3)) == {"TIT2": "after ext", "TPE1": "someone"}
    frames4 = id3v2([("TIT2", b"\x03after ext")], major=4)[10:]
    # v2.4: a syncsafe size that includes itself (6), one flag byte count, one flag byte
    ext4 = _syncsafe(6) + b"\x01\x00"
    raw4 = b"ID3\x04\x00\x40" + _syncsafe(len(ext4) + len(frames4)) + ext4 + frames4
    assert dict(ao.id3_tags(raw4)) == {"TIT2": "after ext"}


def test_id3_v22_three_letter_frames():
    frames = b"TT2" + (9).to_bytes(3, "big") + b"\x00old tape" + b"COM" + (9).to_bytes(3, "big") + b"\x00eng\x00note"
    raw = b"ID3\x02\x00\x00" + _syncsafe(len(frames)) + frames
    assert dict(ao.id3_tags(raw)) == {"TT2": "old tape", "COM": "note"}


@pytest.mark.needs_tool("py:PIL", "py:exifread")
def test_an_embedded_cover_picture_has_its_exif_read():
    jpg = jpeg_with_description("taken at the pier")
    apic = b"\x00image/jpeg\x00\x03cover\x00" + jpg
    rep = ao.open_audio("a.mp3", id3v2([("APIC", apic)]) + b"\xff\xfb\x90\xc4" + b"\x00" * 64, "mp3")
    assert ("APIC:image/jpeg", f"{len(jpg)} bytes") in rep.tags
    assert rep.pictures and ("Image ImageDescription", "taken at the pier") in rep.pictures[0][1]
    assert "APIC:image/jpeg exif Image ImageDescription = taken at the pier" in ao.triage_text(ao.Opening(audio=[rep]))


def test_unsynchronised_and_compressed_frames_are_named_not_decoded():
    tag = bytearray(id3v2([("TIT2", b"\x00x")]))
    tag[5] = 0x80
    assert ao.id3_tags(bytes(tag)) == [("ID3", "tag is unsynchronised; frames not decoded")]
    frame = b"TIT2" + struct.pack(">I", 5) + b"\x00\x80" + b"\x00abcd"
    raw = b"ID3\x03\x00\x00" + _syncsafe(len(frame)) + frame
    (name, why), = ao.id3_tags(raw)
    assert name == "TIT2" and "not decoded" in why


@pytest.mark.parametrize("flags", [0x0008, 0x0004, 0x0002])   # v2.4: compressed, encrypted, unsynchronised
def test_v24_compressed_encrypted_or_unsynchronised_frames_are_named_not_decoded(flags):
    frame = b"TIT2" + _syncsafe(5) + flags.to_bytes(2, "big") + b"\x00abcd"
    raw = b"ID3\x04\x00\x00" + _syncsafe(len(frame)) + frame
    (name, why), = ao.id3_tags(raw)
    assert name == "TIT2" and "not decoded" in why and f"{flags:#06x}" in why


def test_v24_status_flags_alone_do_not_stop_a_frame_being_decoded():
    # v2.4 status flags (tag alter 0x4000, file alter 0x2000, read only 0x1000) leave the body plain,
    # and 0x0080/0x0040 sit where v2.3 puts compression and encryption: none of them hides the text.
    for flags in (0x4000, 0x2000, 0x1000, 0x0080):
        frame = b"TIT2" + _syncsafe(5) + flags.to_bytes(2, "big") + b"\x00abcd"
        raw = b"ID3\x04\x00\x00" + _syncsafe(len(frame)) + frame
        assert ao.id3_tags(raw) == [("TIT2", "abcd")], hex(flags)


@pytest.mark.needs_tool("py:PIL", "py:exifread")
def test_exif_text_puts_the_description_first():
    rows = ao.exif_text(jpeg_with_description(CAPTION))
    assert rows[0] == ("Image ImageDescription", CAPTION)


def test_exif_without_exifread_is_a_named_failure(monkeypatch):
    monkeypatch.setitem(sys.modules, "exifread", None)
    with pytest.raises(ao.ToolMissing, match="exifread"):
        ao.exif_text(b"\xff\xd8\xff")


# ---- decoding to PCM ---------------------------------------------------------------------------

@needs_mp3
def test_decode_pcm_reads_an_mp3_in_process():
    x = morse_signal("SOS", 22050)
    pcm = ao.decode_pcm(mp3_bytes(x, 22050))
    assert pcm.rate == 22050 and pcm.channels == 1 and not pcm.note
    assert abs(pcm.seconds - x.size / 22050) < 0.2


@needs_sf
def test_an_mp3_without_mpeg_support_is_a_named_failure_not_a_fallback(monkeypatch):
    import soundfile
    have = dict(soundfile.available_formats())
    have.pop("MP3", None)
    monkeypatch.setattr(soundfile, "available_formats", lambda: have)
    with pytest.raises(ao.ToolMissing, match="no MPEG support"):
        ao.decode_pcm(b"\xff\xfb\x90\xc4" + b"\x00" * 64)
    rep = ao.open_audio("a.mp3", b"\xff\xfb\x90\xc4" + b"\x00" * 64, "mp3")
    assert "no MPEG support" in rep.blocked
    op = ao.Opening(audio=[rep])
    res = ao.result_of(op)
    assert res.status == "blocked" and "no MPEG support" in res.notes


def test_one_blocked_file_among_decoded_ones_is_named_but_does_not_block_the_result():
    ok = ao.AudioReport("a.wav", "wav", morse=ao.MorseRead("SOS", 548.0, 25.0))
    bad = ao.AudioReport("b.mp3", "mp3", blocked="no MPEG support here")
    res = ao.result_of(ao.Opening(audio=[ok, bad]))
    assert res.status == "unsure" and "b.mp3: not decoded (no MPEG support here)" in res.notes
    assert "a.wav: morse: SOS" in res.notes


def test_a_blocked_file_beside_a_decoded_one_with_no_text_is_none_not_blocked():
    # one file was decoded and read (nothing in it), one could not be decoded: the drop was opened,
    # so the result is "none" with the blocked file named, not "blocked"
    quiet = ao.AudioReport("a.wav", "wav", pcm_line="wav, 8000 Hz, 1 ch, 1.0 s")
    bad = ao.AudioReport("b.mp3", "mp3", blocked="no MPEG support here")
    res = ao.result_of(ao.Opening(audio=[quiet, bad]))
    assert res.status == "none" and "b.mp3: not decoded (no MPEG support here)" in res.notes
    assert ao.result_of(ao.Opening(audio=[bad])).status == "blocked"


@needs_sf
def test_the_audio_file_cap_is_said_out_loud(tmp_path, monkeypatch):
    monkeypatch.setattr(ao, "MAX_AUDIO_FILES", 1)
    for n in ("a.wav", "b.wav"):
        (tmp_path / n).write_bytes(wav_bytes(np.zeros(800), 8000))
    op = ao.open_paths([tmp_path], FF)
    assert [a.name for a in op.audio] == ["a.wav"]
    assert op.skipped == ["b.wav: over the 1 audio file cap"]


def test_missing_soundfile_is_a_named_failure(monkeypatch):
    monkeypatch.setitem(sys.modules, "soundfile", None)
    with pytest.raises(ao.ToolMissing, match="soundfile"):
        ao.decode_pcm(b"RIFF\x00\x00\x00\x00WAVE")


@needs_sf
def test_long_audio_is_decimated_and_truncation_is_said(monkeypatch):
    rate = 44100
    x = morse_signal("SOS SOS", rate, noise=0.01)
    data = wav_bytes(x, rate)
    monkeypatch.setattr(sig, "MAX_SAMPLES", x.size // 3 + 10)
    pcm = ao.decode_pcm(data)
    assert pcm.rate == 14700 and "decimated x3" in pcm.note
    assert abs(ao.dominant_tones(pcm.samples, pcm.rate)[0].hz - 548.0) < 3.0
    assert ao.read_morse(pcm, ao.dominant_tones(pcm.samples, pcm.rate)).text == "SOS SOS"
    short = ao.decode_pcm(data, max_seconds=0.5)
    assert "only the first 0.5 s decoded" in short.note and abs(short.seconds - 0.5) < 0.01


@needs_sf
def test_undecodable_audio_is_a_failure_not_a_block():
    rep = ao.open_audio("broken.wav", b"RIFF\x10\x00\x00\x00WAVEjunkjunk", "wav")
    assert rep.failed and not rep.blocked


# ---- the regression: the Nosocomephobia drop shape, end to end ------------------------------

@needs_mp3
def test_a_noisy_mp3_keyed_at_25_75_165_ms_reads_through_the_opener():
    rate = 44100
    data = mp3_bytes(morse_signal(MESSAGE, rate, noise=0.08), rate)
    rep = ao.open_audio("tape.mp3", data, ao.sniff(data))
    assert not rep.blocked and not rep.failed
    assert abs(rep.tones[0].hz - 548.0) < 3.0
    assert rep.morse is not None and rep.morse.text == MESSAGE
    assert rep.morse.tone_hz is not None and abs(rep.morse.unit_ms - 25.0) < 6.0
    assert rep.dtmf is None
    text = ao.triage_text(ao.Opening(audio=[rep]))
    assert MESSAGE in text and "548." in text


@needs_mp3
def test_mp3_dtmf_reads_through_the_opener():
    data = mp3_bytes(dtmf_signal("0123456789"), 8000)
    rep = ao.open_audio("keys.mp3", data, "mp3")
    assert rep.dtmf == "0123456789" and rep.morse is None


# ---- CLI and result ----------------------------------------------------------------------------

def _run(argv, capsys):
    from ctf.result import SolverResult
    code = ao.main(argv)
    out = capsys.readouterr().out
    return code, out, SolverResult.from_json(out.strip().splitlines()[-1])


@needs_mp3
@pytest.mark.needs_tool("py:PIL", "py:exifread")
def test_cli_on_a_drop_folder_prints_morse_tags_and_the_sibling_exif(tmp_path, capsys):
    drop = tmp_path / "drop"
    drop.mkdir()
    tag = id3v2([("TIT2", b"\x00side A")])
    (drop / "rec.mp3").write_bytes(tag + mp3_bytes(morse_signal(MESSAGE, 22050, noise=0.05), 22050))
    (drop / "picture.jpg").write_bytes(jpeg_with_description(CAPTION))
    (drop / "readme.txt").write_text("not audio")
    code, out, res = _run([str(tmp_path), "--event", "spooky"], capsys)
    assert code == 0
    assert "morse (" in out and MESSAGE in out
    assert "tag TIT2 = side A" in out
    assert f"exif drop/picture.jpg: Image ImageDescription = {CAPTION}" in out
    assert res.status == "unsure" and not res.flags
    assert res.evidence[0].path == "drop/rec.mp3" and MESSAGE[:40] in res.evidence[0].detail
    assert CAPTION in res.notes


@needs_sf
def test_cli_names_a_flag_in_a_tag_as_a_candidate(tmp_path, capsys):
    f = tmp_path / "song.wav"
    f.write_bytes(wav_bytes(np.zeros(8000), 8000, comment="spooky{t4gs_t4lk}"))
    code, out, res = _run([str(f), "--event", "spooky"], capsys)
    assert res.status == "candidate" and res.flags == ("spooky{t4gs_t4lk}",)
    assert res.evidence[-1].kind == "metadata" and "sndfile.comment" in res.evidence[-1].detail
    assert "FLAG spooky{t4gs_t4lk}" in out


@needs_sf
def test_cli_on_noise_is_none_and_on_no_audio_says_so(tmp_path, capsys):
    f = tmp_path / "hiss.wav"
    f.write_bytes(wav_bytes(np.random.RandomState(4).normal(0, 0.2, 16000), 8000))
    _code, out, res = _run([str(f), "--event", "spooky"], capsys)
    assert res.status == "none" and "morse: no reading fits" in out
    t = tmp_path / "t"
    t.mkdir()
    (t / "a.txt").write_text("hello")
    _code, _out, res = _run([str(t), "--event", "spooky"], capsys)
    assert res.status == "none" and "no audio file" in res.notes


def test_cli_without_a_profile_is_blocked(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(ao._event, "current", lambda: (_ for _ in ()).throw(ao._event.EventError("none here")))
    (tmp_path / "x.wav").write_bytes(b"RIFF")
    _code, _out, res = _run([str(tmp_path)], capsys)
    assert res.status == "blocked" and "no event profile" in res.notes


def test_cli_refuses_a_missing_path(tmp_path, capsys):
    assert ao.main([str(tmp_path / "nope.mp3"), "--event", "spooky"]) == 2


# ---- wired into intake ---------------------------------------------------------------------------

def test_manifest_runs_at_intake_on_any_audio_file():
    from ctf.engines import manifest
    from ctf.intake import engines as E
    m = {x.id: x for x in manifest.discover(REPO)}["toolkits.audio_opener"]
    assert m.intake.select == "files" and m.intake.run == "folder" and m.cost_class == "cheap"
    assert "{folder}" in m.intake.args and not m.has("legacy-output") and not m.has("library")
    for name, head in (("x.bin", b"ID3\x04"), ("x.bin", b"\xff\xfb\x90"), ("x.bin", b"\xff\xf3\x80"),
                       ("x.bin", b"\xff\xe3\x48"), ("x.bin", b"fLaC"), ("x.bin", b"OggS"),
                       ("x.bin", b"RIFF\x00\x00\x00\x00WAVE"), ("song.mp3", b"\x00")):
        assert E.files_matching(m.intake.match, [(Path(name), head)]), (name, head)
    assert not E.files_matching(m.intake.match, [(Path("a.png"), b"\x89PNG")])
    assert not E.files_matching(m.intake.match, [(Path("a.jpg"), b"\xff\xd8\xff")])


def test_router_sends_morse_briefs_here():
    from ctf.engines import router
    assert "toolkits.audio_opener" in [h.manifest.id for h in router.route("forensics", "a cassette full of beeps")]
    assert "toolkits.audio_opener" in [h.manifest.id for h in router.route("misc", "decode the morse")]


class _Adapter:
    kind = "fake"

    def __init__(self, ch, files):
        self.ch, self.files = ch, files

    def get_challenge(self, cid):
        return self.ch

    def list_challenges(self):
        return [self.ch]

    def download_files(self, cid, dest):
        out = []
        for rel, data in self.files.items():
            p = Path(dest) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            out.append(p)
        return out

    def submit(self, cid, flag):
        raise AssertionError("intake never submits")

    def team_solves(self):
        return []


def _drop_intake(tmp_path):
    """Hook-guard intake of a zipped drop (an MP3 keyed at 25/75/165 ms and a captioned photo)."""
    from ctf import intake as I
    from ctf.platform.base import Challenge, FileRef
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("drop/tape.mp3", mp3_bytes(morse_signal(MESSAGE, 22050, noise=0.05), 22050))
        zf.writestr("drop/photo.jpg", jpeg_with_description(CAPTION))
    ch = Challenge(id="7", name="Tape", category="forensics", points=100,
                   description="a tape and a photo", files=(FileRef("drop.zip"),))
    return I.intake_one("7", SPOOKY, adapter=_Adapter(ch, {"drop.zip": z.getvalue()}), workdir=tmp_path / "wd",
                        options=I.Options(net_guard="hook", record=False))


@needs_mp3
@pytest.mark.needs_tool("py:PIL", "py:exifread")
def test_intake_matches_the_unzipped_mp3_and_the_hook_guard_names_why_it_waits(tmp_path):
    # soundfile needs ctypes, which the hook-only guard refuses: the engine is skipped with that
    # reason (never run to a misleading "blocked"), and it is planned on the zip's MP3 member.
    rep = _drop_intake(tmp_path)
    assert not [r for r in rep.runs if r.engine == "toolkits.audio_opener"]
    why = [s.reason for s in rep.plan.skipped if s.engine == "toolkits.audio_opener"]
    assert why and "starts other programs" in why[0]


@needs_mp3
@pytest.mark.needs_tool("py:PIL", "py:exifread")
def test_intake_opens_the_zipped_audio_drop_under_the_os_guard_with_no_model(tmp_path):
    from ctf.engines import manifest
    from ctf.intake import engines as E
    from ctf.intake import guard as G
    rep = _drop_intake(tmp_path)
    folder = rep.dir / "unpacked"
    assert any(f.name == "tape.mp3" for f, _ in E.input_files(folder))
    # the suite itself runs inside a deny-network sandbox, where a nested sandbox-exec cannot start:
    # an os guard with no wrapper keeps the audit hook in os mode (ctypes allowed), as intake would
    allow = G.Guard("os", (), "test: os-mode hook, no OS wrapper (the suite sandbox denies the network)")
    plan = E.plan(manifest.discover(REPO), "forensics", "a tape and a photo", folder, guard=allow)
    job = next(j for j in plan.jobs if j.engine == "toolkits.audio_opener")
    ctx = E.Context(challenge_dir=rep.dir, folder=folder, out_root=tmp_path / "engines", profile=SPOOKY,
                    guard=allow, root=REPO, python=sys.executable, challenge_id="7", record=False)
    run = E.run_job(job, ctx)
    out = (rep.dir / run.output).read_text() if not run.output.startswith("/") else Path(run.output).read_text()
    assert run.status == "ok" and run.result_status == "unsure", out[-2000:]
    assert MESSAGE in out and f"Image ImageDescription = {CAPTION}" in out
    assert "548." in out
