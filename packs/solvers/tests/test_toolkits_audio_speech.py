"""B-087: the speech lane (solvers/toolkits/audio_speech.py): find, decode, gate, transcribe, sweep.

Every recording is built here with numpy (tones, a synthetic voice of harmonics and noise bursts) or,
where a real voice matters, synthesized on the spot by the system's `say` (needs_tool: not run where
it is absent). No challenge file is read and no flag here is a past challenge's. The Whisper backends
are absent from the build host, so they are driven through stand-ins: a stub `whisper-cli` program the
test writes, and a fake `faster_whisper` module; the two tests that need the real thing are marked and
report as not run. No model is ever downloaded and Docker is never started (ffmpeg-in-the-sandbox is
always a stand-in). Budgets are explicit and far above what the work takes; nothing asserts an upper
bound on elapsed time.
"""
from __future__ import annotations

import datetime as dt
import io
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import time
import types
from pathlib import Path

import numpy as np
import pytest
import soundfile as sf

import audio_speech as a
from ctf import event

REPO = Path(__file__).resolve().parent.parent
SR = 16000
FLAG = "ACME{sp0ken_w0rd}"
SPELLED = ("The flag is A C M E open curly brace s p zero k e n underscore w zero r d close curly brace. "
           "Thank you for listening.")
BIG = 3600.0          # a budget in seconds that never binds


# ---------------------------------------------------------------- fixtures built here

def profile(prefixes=("ACME",), case="exact"):
    return event.parse({
        "slug": "b087-speech", "name": "b087 speech",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": "https://board.b087.example"},
        "flag": {"prefixes": list(prefixes), "body": "[^{}\\n]{1,128}", "case": case},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": []},
    }, src="<test>")


PROF = profile()


def tone(freq, ms, amp=0.6, sr=SR):
    t = np.arange(int(sr * ms / 1000.0)) / sr
    return amp * np.sin(2 * np.pi * freq * t)


def silence(ms, sr=SR):
    return np.zeros(int(sr * ms / 1000.0))


def ladder(text, base=300.0, step=25.0):
    """One tone per character, freq = base + step * code, 220 ms on and 40 ms off (audio_tones' shape)."""
    chunks = [silence(40)]
    for c in text:
        chunks += [tone(base + step * ord(c), 220), silence(40)]
    return np.concatenate(chunks)


def dtmf(on=80, off=50, keys="4433555666"):
    rows = {"3": 697, "4": 770, "5": 770, "6": 770}
    cols = {"3": 1477, "4": 1209, "5": 1336, "6": 1477}
    return np.concatenate([np.concatenate([tone(rows[k], on, 0.4) + tone(cols[k], on, 0.4), silence(off)])
                           for k in keys])


def voice(seconds=3.0, seed=1, sr=SR):
    """Speech-like sound: voiced stretches (a gliding pitch with 24 harmonics under two formants) between
    noise bursts and pauses. Not intelligible; it has the spectrum of a voice, which is what the gate reads."""
    rng = np.random.default_rng(seed)
    out, total = [], 0
    while total < seconds * sr:
        n = int(sr * rng.uniform(0.12, 0.30))
        t = np.arange(n) / sr
        f0 = rng.uniform(95, 190) * (1 + 0.08 * np.sin(2 * np.pi * rng.uniform(3, 6) * t))
        phase = 2 * np.pi * np.cumsum(f0) / sr
        f1, f2 = rng.uniform(300, 900), rng.uniform(1100, 2500)
        seg = np.zeros(n)
        for k in range(1, 25):
            fk = k * f0.mean()
            seg += (np.exp(-((fk - f1) / 250.0) ** 2) + 0.7 * np.exp(-((fk - f2) / 350.0) ** 2) + 0.05) * np.sin(k * phase)
        seg *= np.hanning(n)
        burst = rng.standard_normal(int(sr * rng.uniform(0.04, 0.10))) * 0.3
        out += [seg / np.abs(seg).max() * 0.6, burst, silence(rng.uniform(20, 80), sr)]
        total += n + len(burst)
    return np.concatenate(out)[: int(seconds * sr)]


def wav(x, sr=SR, subtype="PCM_16"):
    buf = io.BytesIO()
    sf.write(buf, np.asarray(x, dtype=np.float64), sr, format="WAV", subtype=subtype)
    return buf.getvalue()


def ogg_page(body, serial=0x4242, seq=0, flags=2):
    assert len(body) < 255
    return b"OggS" + bytes([0, flags]) + struct.pack("<qIII", 0, serial, seq, 0) + bytes([1, len(body)]) + body


def ogg_vorbis(x, sr=SR):
    buf = io.BytesIO()
    sf.write(buf, np.asarray(x, dtype=np.float32), sr, format="OGG", subtype="VORBIS")
    return buf.getvalue()


class Stub:
    """A stand-in transcriber: answers(samples, call number) -> text; every call is kept."""
    name = "stub-whisper"

    def __init__(self, answers):
        self.answers = answers if callable(answers) else (lambda samples, n, _a=answers: _a)
        self.calls = []

    def __call__(self, samples, language="en", deadline=None, prompt=None):
        self.calls.append({"samples": np.array(samples), "language": language, "deadline": deadline, "prompt": prompt})
        return self.answers(samples, len(self.calls) - 1)


def never(samples, **kw):
    raise AssertionError("the transcriber was called for a recording that is not speech")


def no_backend(monkeypatch, tmp_path):
    """No Whisper program, no module, no model: what the build host has, made certain for the test."""
    monkeypatch.setattr(a, "_which", lambda name, environ=None: None)
    monkeypatch.setattr(a, "_has_module", lambda name: False)
    monkeypatch.setenv("CTF_TOOLBOX_DIR", str(tmp_path / "no-toolbox"))
    monkeypatch.delenv("CTF_ASSET_WHISPER_GGML", raising=False)
    monkeypatch.delenv("CTF_ASSET_WHISPER_CT2", raising=False)


def delivery(tmp_path, files, name="55-voicemail"):
    cd = tmp_path / name
    (cd / "files").mkdir(parents=True)
    for n, data in files.items():
        (cd / "files" / n).parent.mkdir(parents=True, exist_ok=True)
        (cd / "files" / n).write_bytes(data)
    return cd


# ---------------------------------------------------------------- finding audio

@pytest.mark.parametrize("name,head,want", [
    ("a.bin", b"RIFF\x24\x00\x00\x00WAVEfmt ", "wav"),
    ("a.bin", b"RF64\xff\xff\xff\xffWAVEds64", "wav"),
    ("a.bin", b"OggS\x00\x02" + bytes(10), "ogg"),
    ("a.bin", b"fLaC\x00\x00\x00\x22" + bytes(8), "flac"),
    ("a.bin", b"ID3\x04\x00\x00\x00\x00\x00\x00" + bytes(6), "mp3"),
    ("a.bin", b"FORM\x00\x00\x00\x10AIFFCOMM", "aiff"),
    ("a.bin", b"FORM\x00\x00\x00\x10AIFCCOMM", "aiff"),
    ("clip.M4A", bytes(4) + b"ftypM4A " + bytes(4), "m4a"),
    ("dir.v2/voice.opus", bytes(16), "opus"),
    ("notes.txt", b"RIFF\x24\x00\x00\x00WAVEfmt ", "wav"),          # the bytes say so, whatever the name
    ("a.bin", b"RIFF\x24\x00\x00\x00AVI LIST", None),               # RIFF, but a video
    ("a.bin", b"FORM\x00\x00\x00\x10ILBMBMHD", None),               # IFF, but a picture
    ("song", b"\x89PNG\r\n\x1a\n" + bytes(8), None),
    ("archive.wav.zip", b"PK\x03\x04" + bytes(12), None),
    ("folder.wav/readme", b"just words here!", None),
])
def test_audio_kind_goes_by_magic_then_extension(name, head, want):
    assert a.audio_kind(name, head) == want


# ---------------------------------------------------------------- Ogg: leading pages with no codec header

def test_leading_ogg_page_without_a_codec_header_is_dropped():
    stream = ogg_vorbis(tone(440, 500))
    data, dropped = a.strip_leading_ogg_pages(ogg_page(b"APP!") + stream)
    assert dropped == 1 and data == stream
    data, dropped = a.strip_leading_ogg_pages(ogg_page(b"one") + ogg_page(b"two", seq=1) + stream)
    assert dropped == 2 and data == stream


def test_an_ordinary_ogg_and_anything_doubtful_is_left_alone():
    stream = ogg_vorbis(tone(440, 500))
    assert a.strip_leading_ogg_pages(stream) == (stream, 0)
    junk_only = ogg_page(b"APP!") + ogg_page(b"more", seq=1)
    assert a.strip_leading_ogg_pages(junk_only) == (junk_only, 0)             # no codec header follows
    far = b"".join(ogg_page(b"pad%d" % i, seq=i) for i in range(a.OGG_SCAN_PAGES + 1)) + stream
    assert a.strip_leading_ogg_pages(far) == (far, 0)                         # further than is looked
    cut = (ogg_page(b"APP!") + stream)[:40]
    assert a.strip_leading_ogg_pages(cut) == (cut, 0)                         # a page that is not whole
    assert a.strip_leading_ogg_pages(b"RIFFnot ogg at all") == (b"RIFFnot ogg at all", 0)


def test_the_last_page_looked_at_may_still_be_the_codec_header():
    stream = ogg_vorbis(tone(440, 500))
    lead = b"".join(ogg_page(b"pad%d" % i, seq=i) for i in range(a.OGG_SCAN_PAGES))
    data, dropped = a.strip_leading_ogg_pages(lead + stream)
    assert dropped == a.OGG_SCAN_PAGES and data == stream


def test_decode_reads_an_ogg_behind_a_foreign_page_and_says_so():
    x = tone(440, 1000)
    au = a.decode("track.ogg", ogg_page(b"APP!") + ogg_vorbis(x))
    assert au.how == "libsndfile" and len(au.samples) == SR
    assert any("dropped 1 leading Ogg page" in n for n in au.notes)
    spec = np.abs(np.fft.rfft(au.samples))
    assert abs(int(spec.argmax()) - 440) <= 2                                 # 1 s: one bin is 1 Hz


# ---------------------------------------------------------------- decoding

def test_decode_resamples_to_16k_mono_and_keeps_the_pitch():
    left = tone(1000, 2000, sr=44100)
    au = a.decode("x.wav", wav(np.stack([left, left], axis=1), sr=44100))
    assert au.rate_in == 44100 and au.channels == 2 and au.how == "libsndfile"
    assert len(au.samples) == 2 * SR and au.samples.dtype == np.float32
    assert au.seconds == pytest.approx(2.0)
    spec = np.abs(np.fft.rfft(au.samples))
    assert abs(spec.argmax() / 2.0 - 1000.0) <= 2.0                           # 2 s: one bin is 0.5 Hz
    assert au.difference is None                                              # both channels the same


def test_decode_keeps_the_stereo_difference_only_when_the_channels_differ():
    hidden, cover = voice(2.0, seed=4), voice(2.0, seed=5)
    au = a.decode("x.wav", wav(np.stack([cover + hidden, cover], axis=1), subtype="FLOAT"))
    assert au.difference is not None
    assert np.allclose(au.difference, hidden, atol=1e-5)                      # left minus right, not the sum
    assert np.allclose(au.samples, cover + hidden / 2, atol=1e-5)
    faint = a.decode("x.wav", wav(np.stack([cover + 0.01 * hidden, cover], axis=1), subtype="FLOAT"))
    assert faint.difference is None                                           # under DIFF_MIN of the mix
    assert a.decode("x.wav", wav(cover)).difference is None                   # mono


def test_decode_cuts_a_long_recording_and_names_the_cut(monkeypatch):
    monkeypatch.setattr(a, "MAX_AUDIO_SECONDS", 1.0)
    au = a.decode("x.wav", wav(tone(500, 3000)))
    assert len(au.samples) == SR
    assert any("only the first 1 s" in n for n in au.notes)
    assert a.decode("y.wav", wav(tone(500, 900))).notes == []                 # under the limit: no note


def test_decode_sends_what_libsndfile_refuses_to_the_transcoder():
    seen = []

    def to_wav(data, name):
        seen.append((data, name))
        return wav(tone(700, 500))

    au = a.decode("clip.m4a", b"\x00\x00\x00\x20ftypM4A not really", to_wav=to_wav)
    assert seen == [(b"\x00\x00\x00\x20ftypM4A not really", "clip.m4a")]
    assert au.how == "ffmpeg in the sandbox" and len(au.samples) == SR // 2
    good = []
    a.decode("fine.wav", wav(tone(700, 500)), to_wav=lambda d, n: good.append(n))
    assert good == []                                                         # libsndfile read it: not transcoded


def test_decode_names_both_refusals_when_nothing_reads_it():
    def to_wav(data, name):
        raise a.DecodeError("ffmpeg in the sandbox: sandbox down: no docker")

    with pytest.raises(a.DecodeError) as e:
        a.decode("clip.m4a", b"not audio at all, just bytes", to_wav=to_wav)
    assert "libsndfile does not read it" in str(e.value) and "sandbox down: no docker" in str(e.value)


def test_default_transcoder_is_the_sandbox_ffmpeg_and_its_refusal_is_named(monkeypatch):
    calls = []
    fake = types.ModuleType("stego_tools")

    def to_wav(data, rate=22050, channels=1, name=None, filters=None):
        calls.append({"rate": rate, "channels": channels, "name": name, "data": data})
        return types.SimpleNamespace(ok=False, data=None, note="sandbox down: docker is not running: not read")

    fake.to_wav = to_wav
    monkeypatch.setitem(sys.modules, "stego_tools", fake)
    with pytest.raises(a.DecodeError, match="ffmpeg in the sandbox: sandbox down: docker is not running"):
        a.decode("sub/clip.m4a", b"not audio at all, just bytes")
    assert calls == [{"rate": 16000, "channels": 2, "name": "clip.m4a", "data": b"not audio at all, just bytes"}]
    fake.to_wav = lambda data, **kw: types.SimpleNamespace(ok=True, data=wav(tone(600, 250)), note="")
    assert len(a.decode("clip.m4a", b"not audio at all, just bytes").samples) == SR // 4


def test_pcm16_wav_is_what_a_wave_reader_expects():
    x = np.concatenate([tone(300, 100, amp=0.5), [2.0, -2.0]])               # two samples beyond full scale
    data, rate = sf.read(io.BytesIO(a.pcm16_wav(x)), dtype="int16")
    assert rate == SR and data.ndim == 1 and len(data) == len(x)
    assert data[-2] == 32767 and data[-1] == -32767                           # clipped, not wrapped
    assert np.allclose(data[:-2] / 32767.0, x[:-2], atol=1 / 32767)


# ---------------------------------------------------------------- the gate

TONE_SOUNDS = {
    "tone ladder": lambda: ladder("ACME{t0ne}"),
    "dtmf 80 ms keys": lambda: dtmf(80, 50),
    "dtmf 50 ms keys": lambda: dtmf(50, 50),
    "one steady tone": lambda: tone(1000, 2000),
    "tone ladder in light noise": lambda: ladder("ACME{t0ne}") + 0.03 * np.random.default_rng(3).standard_normal(
        len(ladder("ACME{t0ne}"))),
}
VOICE_SOUNDS = {
    "synthetic voice": lambda: voice(3.0, seed=1),
    "another synthetic voice": lambda: voice(3.0, seed=9),
    "white noise": lambda: 0.3 * np.random.default_rng(5).standard_normal(2 * SR),
    "voice over a mains hum": lambda: voice(3.0, seed=2) + tone(50, 3000, amp=0.15),
}


@pytest.mark.parametrize("label", sorted(TONE_SOUNDS))
def test_gate_reads_keyed_tones_as_tones(label):
    g = a.gate(TONE_SOUNDS[label]())
    assert g.kind == a.TONES, (label, g)
    assert g.few >= a.TONE_FRAMES and g.peaks <= 2


@pytest.mark.parametrize("label", sorted(VOICE_SOUNDS))
def test_gate_reads_voice_and_noise_as_other(label):
    g = a.gate(VOICE_SOUNDS[label]())
    assert g.kind == a.OTHER, (label, g)
    assert g.few < a.VOICE_FRAMES and g.peaks >= 3


@pytest.mark.parametrize("samples", [np.zeros(SR), tone(440, 30), tone(440, 500, amp=1e-4), np.zeros(0)],
                         ids=["zeros", "shorter than a frame", "under the silence level", "empty"])
def test_gate_reads_nothing_as_silent(samples):
    assert a.gate(samples).kind == a.SILENT


def test_gate_reads_a_voice_after_key_tones_as_mixed():
    # two seconds of DTMF, then a short voice: mostly tones by time, but the voice must still be heard
    keys = np.tile(dtmf(80, 50), 2)
    g = a.gate(np.concatenate([keys, voice(0.6, seed=6)]))
    assert g.kind == a.MIXED, g
    assert a.VOICE_FRAMES <= g.few < a.TONE_FRAMES


@pytest.mark.needs_tool("say")
def test_gate_reads_a_real_synthesized_voice_as_other(tmp_path):
    # A real voice, from the system synthesizer: the gate must send it to the transcriber.
    p = tmp_path / "say.wav"
    r = subprocess.run(["say", "-o", str(p), "--data-format=LEI16@16000",
                        "Seven three, six five, six three. The meeting is at the old bridge at midnight."],
                       capture_output=True)
    if r.returncode != 0 or not p.is_file():
        pytest.skip(f"not run: say could not synthesize a recording here (exit {r.returncode})")
    au = a.decode("say.wav", p.read_bytes())
    g = a.gate(au.samples)
    assert g.kind == a.OTHER, g


# ---------------------------------------------------------------- spoken spelling

P = ("ACME",)


@pytest.mark.parametrize("said,want", [
    # letters, digit words and symbol names inside the braces; the prefix spelled out
    ("The flag is A C M E open curly brace capital Q seven comma m four z underscore j nine v question mark close curly brace.",
     "The flag is ACME{Q7,m4z_j9v?}"),
    # the transcriber's list commas are prosody once a comma is SAID; digits written as digits; P-I-N-K style hyphens
    ("The flag is A-C-M-E, open curly bracket, capital Q, 7, comma, M, 4, Z, underscore, J, 9, V, close curly bracket.",
     "The flag is ACME{Q7,m4z_j9v}"),
    # whole words between the braces; the prefix said as a word in any case
    ("acme open brace hello underscore world close brace", "ACME{hello_world}"),
    ("Acme left curly brace hello dash world right curly brace", "ACME{hello-world}"),
    # a brace said with no open/close alternates; NATO letters are lower-case
    ("alpha charlie mike echo curly brace november alpha tango oscar curly brace thanks", "ACME{nato} thanks"),
    # said case: "capital"/"upper case" raise one letter; once case is said the rest are lower
    ("A C M E open brace upper case X lower case Y capital zulu Q close brace", "ACME{XyZq}"),
    # no case said at all: letters stay as the transcriber wrote them
    ("A C M E open brace X y Z close brace", "ACME{XyZ}"),
    # symbols by name
    ("A C M E open brace a at sign b hash c dollar sign d percent e plus f equals g slash h back slash i close brace",
     "ACME{a@b#c$d%e+f=g/h\\i}"),
    ("A C M E open brace a dot b exclamation mark c star d colon e semicolon f tilde g pipe h close brace",
     "ACME{a.b!c*d:e;f~g|h}"),
    ("A C M E open paren one two three close paren", "ACME(123)"),
    # digits read aloud outside any brace are glued too (a spoken hex or decimal string)
    ("The code is four three, five four, four six, seven b.", "The code is 4354467b"),
    # a symbol name that is unambiguous joins its neighbours anywhere
    ("the user is admin underscore backup", "the user is admin_backup"),
])
def test_spoken_spelling_is_written_out(said, want):
    forms = a.spoken_forms(said, P)
    assert forms and forms[0] == ("spelled", want)


@pytest.mark.parametrize("said", [
    "Hello there, this is a normal sentence with one dash of salt.",
    "Meet me at the old bridge at midnight. Bring two keys, a map and plan B.",
    "I gave him a 5 star review, period.",
    "The capital city is small.",
])
def test_ordinary_speech_has_no_spelled_form(said):
    assert a.spoken_forms(said, P) == []


def test_three_spellable_tokens_are_not_a_run_but_four_are():
    assert a.spoken_forms("take exit 4 B 7 then turn left", P) == []
    assert a.spoken_forms("take exit 4 B 7 C then turn left", P) == [("spelled", "take exit 4B7C then turn left")]
    # punctuation the transcriber put between the tokens does not break the run
    assert a.spoken_forms("take exit 4, B, 7, C. Then turn left", P) == [("spelled", "take exit 4B7C Then turn left")]


def test_transcribers_own_punctuation_is_kept_only_when_nothing_was_said_by_name():
    # The transcriber wrote the signs itself and spaced them: both readings are offered, prosody-free first.
    forms = a.spoken_forms("Acme { Q7, m4z_j9v? }", P)
    assert forms == [("spelled", "ACME{Q7m4z_j9v}"), ("spelled, punctuation kept", "ACME{Q7,m4z_j9v?}")]
    # A character said by name ("comma") makes the written commas prosody: one reading only.
    forms = a.spoken_forms("Acme { Q, 7, comma, m, 4, z }", P)
    assert forms == [("spelled", "ACME{Q7,m4z}")]
    # Braces said by name do not count as a said character: the body was still written by the transcriber.
    forms = a.spoken_forms("Acme open curly brace Q7, m4z close curly brace", P)
    assert [f[1] for f in forms] == ["ACME{Q7m4z}", "ACME{Q7,m4z}"]


def test_only_an_event_prefix_before_the_brace_is_respelled():
    assert a.spoken_forms("acme open brace x y z close brace", ("ACME",))[0][1] == "ACME{xyz}"
    assert a.spoken_forms("other open brace x y z close brace", ("ACME",))[0][1] == "other{xyz}"
    # longest prefix first, and only where it stands right before the brace
    assert a.spoken_forms("acme2 open brace x y z close brace about acme", ("ACME", "AcMe2"))[0][1] == "AcMe2{xyz} about acme"


@pytest.mark.parametrize("prefixes", [("ctf", "ACTF"), ("ACTF", "ctf")])
def test_a_prefix_inside_a_longer_one_does_not_respell_it(prefixes):
    # ctf ends ACTF: the longer prefix is written first and the shorter one must not respell its tail.
    said = "actf open brace x y z w close brace then ctf open brace q close brace"
    assert a.spoken_forms(said, prefixes)[0][1] == "ACTF{xyzw} then ctf{q}"
    assert a.text_flags(said, profile(prefixes=prefixes), graph=False) == [("ACTF{xyzw}", "spelled"), ("ctf{q}", "spelled")]


def test_literal_braces_from_the_transcriber_open_and_close_the_glue():
    assert a.spoken_forms("so ACME{ one two three } and then five more words", P)[0][1] == \
        "so ACME{123} and then five more words"


# ---------------------------------------------------------------- the flag sweep of a reading

def test_text_flags_finds_a_flag_as_read_and_as_spelled():
    assert a.text_flags(f"it says {FLAG} twice, {FLAG}", PROF, graph=False) == [(FLAG, "as read")]
    assert a.text_flags(SPELLED, PROF, graph=False) == [(FLAG, "spelled")]
    assert a.text_flags(SPELLED, PROF, spoken=False, graph=False) == []       # tones are not spelling


def test_text_flags_follows_the_profile_not_the_active_event():
    # the suite's active event is csctf: its flag in a transcript is not this profile's flag
    assert a.text_flags("the answer is CSCTF{another_events_flag}", PROF) == []
    other = profile(prefixes=("CSCTF",))
    assert a.text_flags("the answer is CSCTF{another_events_flag}", other) == [("CSCTF{another_events_flag}", "as read")]


def test_text_flags_decodes_digits_read_aloud_through_the_codec_graph():
    said = " ".join({"0": "zero", "1": "one", "2": "two", "3": "three", "4": "four", "5": "five", "6": "six",
                     "7": "seven", "8": "eight", "9": "nine"}.get(c, c) for c in "ACME{h3x}".encode().hex())
    text = f"Write this down: {said}. That is all."
    hits = a.text_flags(text, PROF, time.monotonic() + BIG)
    assert [f for f, _how in hits] == ["ACME{h3x}"]
    assert hits[0][1].startswith("spelled, decoded") and "hex" in hits[0][1]
    assert a.text_flags(text, PROF, time.monotonic() + BIG, graph=False) == []
    assert a.text_flags(text, PROF, time.monotonic() - 1.0) == []             # no time left: the graph is not started


def test_text_flags_packed_scan_has_no_left_boundary():
    text = "xx" + FLAG                                                        # decoded tone codes: no separator
    assert a.text_flags(text, PROF, graph=False) == []
    assert a.text_flags(text, PROF, graph=False, spoken=False, packed=True) == [(FLAG, "as read")]


def test_text_flags_with_an_unknown_flag_format_reads_the_brace_shape_and_skips_the_graph():
    # No prefix is known yet (an event at its open): flagfmt matches any word{...}, so the spelled form
    # is still found; the codec graph has no format to aim at and is not started.
    unknown = profile(prefixes=())
    assert a.text_flags(SPELLED, unknown, time.monotonic() + BIG) == [(FLAG, "spelled")]
    said = " ".join("ACME{h3x}".encode().hex())
    assert a.text_flags(f"Write this down: {said}. That is all.", unknown, time.monotonic() + BIG) == []


def test_clean_transcript_drops_timestamps_and_sound_tags():
    raw = ("[00:00:00.000 --> 00:00:02.500]   The flag is\n"
           "[00:00:02.500 --> 00:00:04.000]  [BLANK_AUDIO]\n\n"
           "  A C M E (music) open brace\n[MUSIC PLAYING]\n")
    assert a.clean_transcript(raw) == "The flag is A C M E open brace"


# ---------------------------------------------------------------- whisper-cli, through a stub program

def stub_cli(tmp_path, body, name="whisper-cli"):
    """A program named like whisper.cpp's CLI. It records its arguments and the WAV it was handed."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    seen = tmp_path / "seen"
    seen.mkdir(exist_ok=True)
    script = bindir / name
    script.write_text("#!/bin/sh\n"
                      f"out='{seen}'\n"
                      "printf '%s\\n' \"$@\" > \"$out/argv\"\n"
                      "for arg in \"$@\"; do\n"
                      "  if [ \"$prev\" = \"-f\" ]; then cp \"$arg\" \"$out/heard.wav\"; fi\n"
                      "  prev=\"$arg\"\n"
                      "done\n" + body, encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script, seen


SAYS_FLAG = ("cat <<'EOT'\n"
             "[00:00:00.000 --> 00:00:03.000]   The flag is A C M E open curly brace\n"
             "[00:00:03.000 --> 00:00:06.000]   s p zero k e n underscore w zero r d close curly brace\n"
             "[BLANK_AUDIO]\n"
             "EOT\n")


def test_whisper_cli_is_handed_a_16k_wav_and_the_model_and_its_output_is_cleaned(tmp_path):
    script, seen = stub_cli(tmp_path, SAYS_FLAG)
    model = tmp_path / "ggml-test.bin"
    model.write_bytes(b"not a real model")
    x = voice(1.0, seed=3).astype(np.float32)
    text = a.WhisperCli(str(script), str(model), threads=2)(x, language="en", deadline=time.monotonic() + BIG)
    assert text == "The flag is A C M E open curly brace s p zero k e n underscore w zero r d close curly brace"
    argv = (seen / "argv").read_text().splitlines()
    assert argv[:2] == ["-m", str(model)] and argv[2] == "-f"
    assert argv[4:] == ["-l", "en", "-t", "2", "-np", "-nt"]
    heard, rate = sf.read(str(seen / "heard.wav"), dtype="float64")
    info = sf.info(str(seen / "heard.wav"))
    assert rate == SR and info.channels == 1 and info.subtype == "PCM_16"
    assert len(heard) == len(x) and np.allclose(heard, np.clip(x, -1.0, 1.0), atol=2 / 32767)
    assert not Path(argv[3]).exists()                                         # the temporary WAV is removed


def test_whisper_cli_passes_language_and_prompt_only_when_given(tmp_path):
    script, seen = stub_cli(tmp_path, "echo hello\n")
    w = a.WhisperCli(str(script), "/models/m.bin")
    assert w(tone(300, 200), language="auto", prompt="ACME{") == "hello"
    argv = (seen / "argv").read_text().splitlines()
    assert argv[argv.index("-l") + 1] == "auto" and argv[-2:] == ["--prompt", "ACME{"]
    w(tone(300, 200))
    assert "--prompt" not in (seen / "argv").read_text().splitlines()


def test_whisper_cli_failure_is_named_with_its_last_error_line(tmp_path):
    script, _seen = stub_cli(tmp_path, "echo 'whisper_init: loading'\necho 'error: failed to load model' >&2\nexit 3\n")
    with pytest.raises(a.TranscribeError, match="whisper-cli exit 3: error: failed to load model"):
        a.WhisperCli(str(script), "/models/m.bin")(tone(300, 200))
    with pytest.raises(a.TranscribeError, match="did not start"):
        a.WhisperCli(str(tmp_path / "no-such-program"), "/models/m.bin")(tone(300, 200))


def test_whisper_cli_is_not_started_without_time_and_is_stopped_at_the_deadline(tmp_path):
    script, seen = stub_cli(tmp_path, "exec sleep 30\n")
    w = a.WhisperCli(str(script), "/models/m.bin")
    with pytest.raises(a.TranscribeError, match="out of time before whisper-cli started"):
        w(tone(300, 200), deadline=time.monotonic() - 1.0)
    assert not (seen / "argv").exists()                                       # never started
    # Wall-clock on purpose: the stub sleeps 30 s and the budget is 3 s (room for a stalled host to reach
    # the call), so the only way out is the kill at the deadline. Lower bound only (a loaded host is slower
    # to start and to kill, never faster).
    t0 = time.monotonic()
    with pytest.raises(a.TranscribeError, match="stopped after .*out of time") as e:
        w(tone(300, 200), deadline=t0 + 3.0)
    assert time.monotonic() - t0 >= 2.9
    assert not isinstance(e.value, a.TranscribeCut)                           # it printed nothing: nothing to keep


def test_whisper_cli_stopped_at_the_deadline_keeps_what_it_had_printed(tmp_path, monkeypatch):
    # What subprocess.run hands over when it kills the program at the timeout: what it had printed.
    def killed(argv, **kw):
        assert kw["timeout"] > 0 and kw["capture_output"] is True
        raise subprocess.TimeoutExpired(argv, kw["timeout"], output=b"[00:00:00.000 --> 00:00:02.000]   The flag is A C M E\n")

    monkeypatch.setattr(a.subprocess, "run", killed)
    with pytest.raises(a.TranscribeCut) as e:
        a.WhisperCli("whisper-cli", "/models/m.bin")(tone(300, 200), deadline=time.monotonic() + BIG)
    assert e.value.text == "The flag is A C M E"                              # cleaned like a whole transcript
    assert "stopped after" in str(e.value) and "out of time" in str(e.value) and "cut" in str(e.value)


def test_a_real_program_killed_at_the_deadline_hands_back_what_it_printed(tmp_path):
    # The same through a real process. Wall-clock on purpose: the program prints one segment at once and
    # then hangs; 5 s is room for a stalled host to start it. Lower bound only.
    script = tmp_path / "whisper-cli"
    script.write_text("#!/bin/sh\necho '[00:00:00.000 --> 00:00:02.000]   The flag is A C M E'\nexec sleep 60\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    t0 = time.monotonic()
    with pytest.raises(a.TranscribeCut) as e:
        a.WhisperCli(str(script), "/models/m.bin")(tone(300, 200), deadline=t0 + 5.0)
    assert time.monotonic() - t0 >= 4.9
    assert e.value.text == "The flag is A C M E"


# ---------------------------------------------------------------- faster-whisper, through a fake module

def fake_faster_whisper(monkeypatch, segments, fail=None):
    # FasterWhisper sets HF_HUB_OFFLINE in the process environment: start every test without it and
    # have monkeypatch put the environment back afterwards (set first, so the restore is recorded).
    monkeypatch.setenv("HF_HUB_OFFLINE", "test")
    monkeypatch.delenv("HF_HUB_OFFLINE")
    rec = {"init": [], "transcribe": []}
    mod = types.ModuleType("faster_whisper")

    class WhisperModel:
        def __init__(self, path, **kw):
            rec["init"].append((path, kw))
            if fail == "load":
                raise RuntimeError("Unable to open file 'model.bin'")

        def transcribe(self, audio, **kw):
            rec["transcribe"].append((audio, kw))
            return (types.SimpleNamespace(text=t) for t in segments), types.SimpleNamespace(language="en")

    mod.WhisperModel = WhisperModel
    monkeypatch.setitem(sys.modules, "faster_whisper", mod)
    return rec


def test_faster_whisper_loads_the_model_folder_offline_and_joins_the_segments(tmp_path, monkeypatch):
    rec = fake_faster_whisper(monkeypatch, [" The flag is", " A C M E", " open brace x close brace "])
    assert "HF_HUB_OFFLINE" not in os.environ
    fw = a.FasterWhisper(str(tmp_path / "ct2-model"), threads=3)
    x = voice(1.0, seed=3)
    assert fw(x, language="en", deadline=time.monotonic() + BIG) == "The flag is A C M E open brace x close brace"
    (path, kw), = rec["init"]
    assert path == str(tmp_path / "ct2-model")                               # a folder on disk, never a model name
    assert kw["local_files_only"] is True and kw["device"] == "cpu" and kw["cpu_threads"] == 3
    assert os.environ["HF_HUB_OFFLINE"] == "1"
    (audio, tk), = rec["transcribe"]
    assert audio.dtype == np.float32 and np.allclose(audio, x, atol=1e-6)
    assert tk["language"] == "en" and tk["initial_prompt"] is None
    fw(x, language="auto", prompt="ACME{")
    assert len(rec["init"]) == 1                                              # the model is loaded once
    assert rec["transcribe"][1][1]["language"] is None and rec["transcribe"][1][1]["initial_prompt"] == "ACME{"


class StepClock:
    """time.monotonic for the module under test: it moves only when the test moves it."""

    def __init__(self, now=1000.0):
        self.now = now

    def monotonic(self):
        return self.now


def step_clock(monkeypatch, now=1000.0):
    clock = StepClock(now)
    monkeypatch.setattr(a, "time", types.SimpleNamespace(monotonic=clock.monotonic))
    return clock


def test_faster_whisper_cut_at_the_budget_keeps_what_was_heard(monkeypatch):
    clock = step_clock(monkeypatch)

    def segments():                             # the model's generator: the second segment takes past the budget
        yield "first part"
        clock.now += 100.0
        yield "second part"
        yield "third part"

    rec = fake_faster_whisper(monkeypatch, segments())
    with pytest.raises(a.TranscribeCut) as e:
        a.FasterWhisper("/models/ct2")(tone(300, 200), deadline=clock.now + 50.0)
    assert e.value.text == "first part second part" and "out of time" in str(e.value)
    assert len(rec["transcribe"]) == 1


def test_faster_whisper_is_not_started_without_time(monkeypatch):
    rec = fake_faster_whisper(monkeypatch, ["never heard"])
    with pytest.raises(a.TranscribeError, match="out of time before faster-whisper started") as e:
        a.FasterWhisper("/models/ct2")(tone(300, 200), deadline=time.monotonic() - 1.0)
    assert not isinstance(e.value, a.TranscribeCut)
    assert rec == {"init": [], "transcribe": []}                              # the model was not even loaded


def test_faster_whisper_load_failure_is_a_named_error(monkeypatch):
    fake_faster_whisper(monkeypatch, [], fail="load")
    with pytest.raises(a.TranscribeError, match="faster-whisper: RuntimeError: Unable to open file"):
        a.FasterWhisper("/models/ct2")(tone(300, 200))


# ---------------------------------------------------------------- finding a backend

def ggml(tmp_path, size=31_000_000, name="ggml-x.bin"):
    p = tmp_path / name
    with open(p, "wb") as fh:
        fh.truncate(size)                      # sparse: the size is what the asset check reads
    return p


def ct2(tmp_path, files=("model.bin", "config.json")):
    d = tmp_path / "ct2"
    d.mkdir(exist_ok=True)
    for f in files:
        (d / f).write_bytes(b"x")
    return d


def env_for(tmp_path, **extra):
    return {"PATH": str(tmp_path / "bin"), "CTF_TOOLBOX_DIR": str(tmp_path / "no-toolbox"), **extra}


def test_no_backend_names_every_missing_program_module_and_model(tmp_path, monkeypatch):
    monkeypatch.setattr(a, "_has_module", lambda name: False)
    (tmp_path / "bin").mkdir()
    t, missing = a.find_backend("auto", environ=env_for(tmp_path))
    assert t is None and len(missing) == 2
    assert missing[0].startswith("whisper-cli: whisper-cli is not on PATH") and "asset whisper-ggml is missing" in missing[0]
    assert missing[1].startswith("faster-whisper: the faster_whisper module is not installed")
    assert "asset whisper-ct2 is missing" in missing[1]
    assert "brew install whisper-cpp" in missing[0] and "never fetches" in missing[0]
    t, missing = a.find_backend("faster-whisper", environ=env_for(tmp_path))
    assert t is None and len(missing) == 1 and missing[0].startswith("faster-whisper:")


def test_whisper_cli_backend_needs_both_the_program_and_a_model(tmp_path, monkeypatch):
    monkeypatch.setattr(a, "_has_module", lambda name: False)
    script, _seen = stub_cli(tmp_path, "echo hi\n")
    model = ggml(tmp_path)
    t, missing = a.find_backend("auto", environ=env_for(tmp_path))            # the program, no model
    assert t is None and "whisper-cli is not on PATH" not in missing[0] and "asset whisper-ggml is missing" in missing[0]
    t, missing = a.find_backend("auto", environ=env_for(tmp_path, CTF_ASSET_WHISPER_GGML=str(model)))
    assert isinstance(t, a.WhisperCli) and missing == []
    assert (t.binary, t.model) == (str(script), str(model))
    script.unlink()                                                           # the model, no program
    t, missing = a.find_backend("auto", environ=env_for(tmp_path, CTF_ASSET_WHISPER_GGML=str(model)))
    assert t is None and "whisper-cli is not on PATH" in missing[0] and "whisper-ggml" not in missing[0]


def test_whisper_cpp_is_accepted_as_the_programs_older_name(tmp_path, monkeypatch):
    monkeypatch.setattr(a, "_has_module", lambda name: False)
    script, _seen = stub_cli(tmp_path, "echo hi\n", name="whisper-cpp")
    t, _missing = a.find_backend("whisper-cli", model=str(ggml(tmp_path, size=10)), environ=env_for(tmp_path))
    assert isinstance(t, a.WhisperCli) and t.binary == str(script)


def test_a_truncated_model_file_is_broken_not_used(tmp_path, monkeypatch):
    monkeypatch.setattr(a, "_has_module", lambda name: False)
    stub_cli(tmp_path, "echo hi\n")
    small = ggml(tmp_path, size=1_000_000)
    t, missing = a.find_backend("whisper-cli", environ=env_for(tmp_path, CTF_ASSET_WHISPER_GGML=str(small)))
    assert t is None and "asset whisper-ggml is broken" in missing[0] and "CTF_ASSET_WHISPER_GGML" in missing[0]


def test_faster_whisper_backend_takes_a_model_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(a, "_has_module", lambda name: name == "faster_whisper")
    (tmp_path / "bin").mkdir()
    folder = ct2(tmp_path)
    t, missing = a.find_backend("auto", environ=env_for(tmp_path, CTF_ASSET_WHISPER_CT2=str(folder)))
    assert isinstance(t, a.FasterWhisper) and t.model == str(folder) and missing == []
    (tmp_path / "half").mkdir()
    half = ct2(tmp_path / "half", files=("config.json",))
    t, missing = a.find_backend("faster-whisper", environ=env_for(tmp_path, CTF_ASSET_WHISPER_CT2=str(half)))
    assert t is None and "asset whisper-ct2 is broken" in missing[0]         # no model.bin in the folder


def test_auto_prefers_whisper_cli_and_an_explicit_backend_is_obeyed(tmp_path, monkeypatch):
    monkeypatch.setattr(a, "_has_module", lambda name: True)
    stub_cli(tmp_path, "echo hi\n")
    env = env_for(tmp_path, CTF_ASSET_WHISPER_GGML=str(ggml(tmp_path)), CTF_ASSET_WHISPER_CT2=str(ct2(tmp_path)))
    assert isinstance(a.find_backend("auto", environ=env)[0], a.WhisperCli)
    assert isinstance(a.find_backend("faster-whisper", environ=env)[0], a.FasterWhisper)
    assert a.find_backend("whisper-cli", threads=7, environ=env)[0].threads == 7
    with pytest.raises(a.OptionError, match="backend must be auto or one of"):
        a.find_backend("whisper-large", environ=env)


def test_model_option_replaces_the_asset_and_must_be_the_right_kind(tmp_path, monkeypatch):
    monkeypatch.setattr(a, "_has_module", lambda name: True)
    stub_cli(tmp_path, "echo hi\n")
    model, folder = ggml(tmp_path, size=10), ct2(tmp_path)
    t, _m = a.find_backend("whisper-cli", model=str(model), environ=env_for(tmp_path))
    assert t.model == str(model)                                              # no size floor on an explicit path
    t, missing = a.find_backend("whisper-cli", model=str(folder), environ=env_for(tmp_path))
    assert t is None and f"model={folder} is not a file" in missing[0]
    t, missing = a.find_backend("faster-whisper", model=str(model), environ=env_for(tmp_path))
    assert t is None and f"model={model} is not a folder" in missing[0]
    t, _m = a.find_backend("auto", model=str(folder), environ=env_for(tmp_path))
    assert isinstance(t, a.FasterWhisper)                                     # a folder is the CTranslate2 backend's


def test_a_model_inside_the_checkout_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(a, "_has_module", lambda name: False)
    stub_cli(tmp_path, "echo hi\n")
    repo = tmp_path / "checkout"
    (repo / "models").mkdir(parents=True)
    inside = ggml(repo / "models", size=10)
    monkeypatch.setattr("ctf.paths.repo_root", lambda: repo)
    t, missing = a.find_backend("whisper-cli", model=str(inside), environ=env_for(tmp_path))
    assert t is None and "inside the checkout" in missing[0]
    outside = ggml(tmp_path, size=10)
    assert a.find_backend("whisper-cli", model=str(outside), environ=env_for(tmp_path))[0] is not None


def test_shipped_asset_manifest_declares_both_models_as_optional():
    from ctf.toolchain import assets
    by = {x.name: x for x in assets.load()}
    g, c = by["whisper-ggml"], by["whisper-ct2"]
    assert (g.kind, g.role, g.env) == ("file", "optional", ("CTF_ASSET_WHISPER_GGML",))
    assert (c.kind, c.role, c.env) == ("dir", "optional", ("CTF_ASSET_WHISPER_CT2",))
    assert g.min_bytes >= 30_000_000 and set(c.contains) == {"model.bin", "config.json"}
    for x in (g, c):
        assert all(cand.startswith("{toolbox}/") for cand in x.candidates)    # never a path inside the repo


# ---------------------------------------------------------------- the lane, with a stand-in transcriber

def test_spoken_flag_is_a_candidate_with_the_transcript_as_evidence(tmp_path):
    cd = delivery(tmp_path, {"voicemail.wav": wav(voice(3.0, sr=22050), sr=22050), "readme.txt": b"listen closely"})
    (cd / "challenge.json").write_text(json.dumps({"id": 55, "name": "voicemail"}))
    stub = Stub(SPELLED)
    r = a.solve(cd, PROF, transcriber=stub, seconds=BIG, prompt="spelled flag")
    assert r.status == "candidate" and r.flags == (FLAG,)                     # speech is lossy: never `solved`
    assert r.engine == a.ENGINE and r.challenge_id == "55"
    kinds = [e.kind for e in r.evidence]
    assert kinds == ["audio", "transcript", "speech-flag"]
    assert "reads as other" in r.evidence[0].detail and r.evidence[0].path == "files/voicemail.wav"
    assert "[original] via stub-whisper" in r.evidence[1].detail and "open curly brace" in r.evidence[1].detail
    assert r.evidence[2].detail == f"{FLAG} <- [original] spelled"
    assert "lossy" in r.notes
    (call,) = stub.calls                                                      # the plain recording said it: one pass
    assert len(call["samples"]) == 3 * SR                                     # 3 s at 22.05 kHz, resampled to 16 kHz
    assert call["language"] == "en" and call["prompt"] == "spelled flag" and call["deadline"] is not None
    out = cd / "recon" / "audio_speech"
    text = (out / "files_voicemail.wav.original.txt").read_text()
    assert text.splitlines()[0] == SPELLED and f"[spelled] The flag is {FLAG} Thank you for listening" in text
    doc = json.loads((out / "report.json").read_text())
    assert doc["schema"] == 1 and doc["flags"] == [FLAG] and doc["backend"] == "stub-whisper"
    assert doc["files"][0]["gate"]["kind"] == "other" and doc["files"][0]["readings"][0]["flags"] == [[FLAG, "spelled"]]


def test_speech_without_a_backend_is_blocked_naming_what_to_install(tmp_path, monkeypatch):
    no_backend(monkeypatch, tmp_path)
    cd = delivery(tmp_path, {"voicemail.wav": wav(voice(2.0))})
    r = a.solve(cd, PROF, seconds=BIG)
    assert r.status == "blocked" and r.flags == ()
    for needle in ("whisper-cli is not on PATH", "faster_whisper module is not installed", "asset whisper-ggml is missing",
                   "asset whisper-ct2 is missing", "nothing is downloaded", "files/voicemail.wav (no speech-to-text backend)"):
        assert needle in r.notes, needle
    doc = json.loads((cd / "recon" / "audio_speech" / "report.json").read_text())
    assert doc["backend"] is None and len(doc["missing"]) == 2 and doc["files"][0]["state"] == "not-transcribed"


def test_tones_are_read_by_the_tone_readers_and_never_need_whisper(tmp_path, monkeypatch):
    no_backend(monkeypatch, tmp_path)
    cd = delivery(tmp_path, {"beeps.wav": wav(ladder("ACME{t0ne_l4dder}"))})
    r = a.solve(cd, PROF, transcriber=never, seconds=BIG)
    assert r.status == "candidate" and r.flags == ("ACME{t0ne_l4dder}",)
    assert [e.kind for e in r.evidence] == ["audio", "tone-reading", "tone-flag"]
    assert "reads as tones" in r.evidence[0].detail and "tone ladder" in r.evidence[1].detail
    r = a.solve(cd, PROF, seconds=BIG)                                        # no stub, no backend: still not blocked
    assert r.status == "candidate" and r.flags == ("ACME{t0ne_l4dder}",)


def test_tones_with_no_flag_and_silence_are_none_not_blocked(tmp_path, monkeypatch):
    no_backend(monkeypatch, tmp_path)
    cd = delivery(tmp_path, {"beeps.wav": wav(dtmf(80, 50)), "quiet.wav": wav(np.zeros(SR))})
    r = a.solve(cd, PROF, seconds=BIG)
    assert r.status == "none" and "tone readers found no flag" in r.notes
    reads = {e.path: e.detail for e in r.evidence if e.kind == "audio"}
    assert "reads as tones" in reads["files/beeps.wav"] and "reads as silent" in reads["files/quiet.wav"]


def test_dtmf_keys_are_read_through_audio_stego(tmp_path, monkeypatch):
    no_backend(monkeypatch, tmp_path)
    rep = a.examine({"keys.wav": wav(dtmf(120, 80))}, PROF, deadline=time.monotonic() + BIG)
    labels = {r.label: r.text for r in rep.files[0].readings}
    assert labels.get("audio_stego dtmf_forward") == "4433555666"
    assert rep.files[0].gate.kind == a.TONES and rep.files[0].state == a.READ


def test_speech_on_hears_tones_and_speech_off_hears_nothing(tmp_path, monkeypatch):
    no_backend(monkeypatch, tmp_path)
    files = {"beeps.wav": wav(dtmf(80, 50)), "voice.wav": wav(voice(2.0))}
    stub = Stub("nothing of note")
    rep = a.examine(files, PROF, transcriber=stub, speech="on", variants=("original",), deadline=time.monotonic() + BIG)
    assert len(stub.calls) == 2                                               # the tones were heard too
    stub = Stub("nothing of note")
    rep = a.examine(files, PROF, transcriber=stub, speech="off", deadline=time.monotonic() + BIG)
    assert stub.calls == []
    assert [(f.name, f.state, f.reason) for f in rep.files] == [("beeps.wav", "read", ""),
                                                               ("voice.wav", "not-transcribed", "speech=off")]
    r = a.result_of(rep)
    assert r.status == "none" and "voice.wav (speech=off)" in r.notes        # asked for, so not `blocked`


def test_a_voice_after_key_tones_is_both_read_as_tones_and_heard(tmp_path):
    mixed = np.concatenate([np.tile(dtmf(80, 50), 2), voice(0.6, seed=6)])
    stub = Stub(SPELLED)
    rep = a.examine({"call.wav": wav(mixed)}, PROF, transcriber=stub, deadline=time.monotonic() + BIG)
    f = rep.files[0]
    assert f.gate.kind == a.MIXED and len(stub.calls) == 1
    assert {r.source for r in f.readings} == {"tones", "stub-whisper"}
    assert rep.flags() == [FLAG]


def test_when_the_plain_recording_says_nothing_the_difference_and_the_reverse_are_heard():
    hidden, cover = voice(2.0, seed=4), voice(2.0, seed=5)
    data = wav(np.stack([cover + hidden, cover], axis=1), subtype="FLOAT")

    def answers(samples, n):
        return SPELLED if n == 2 else "la la la"

    stub = Stub(answers)
    rep = a.examine({"song.wav": data}, PROF, transcriber=stub, deadline=time.monotonic() + BIG)
    assert len(stub.calls) == 3
    mono = cover + hidden / 2
    assert np.allclose(stub.calls[0]["samples"], mono, atol=1e-5)
    assert np.allclose(stub.calls[1]["samples"], hidden, atol=1e-5)           # left minus right
    assert np.array_equal(stub.calls[2]["samples"], stub.calls[0]["samples"][::-1])
    assert [r.label for r in rep.files[0].readings] == ["original", "stereo_difference", "reversed"]
    assert rep.files[0].readings[2].flags == [(FLAG, "spelled")] and rep.flags() == [FLAG]


def test_later_variants_are_skipped_once_a_flag_is_heard_and_variants_can_be_restricted():
    hidden, cover = voice(2.0, seed=4), voice(2.0, seed=5)
    data = wav(np.stack([cover + hidden, cover], axis=1), subtype="FLOAT")
    stub = Stub(lambda samples, n: SPELLED if n == 1 else "la la la")
    rep = a.examine({"song.wav": data}, PROF, transcriber=stub, deadline=time.monotonic() + BIG)
    assert [r.label for r in rep.files[0].readings] == ["original", "stereo_difference"]     # reversed not needed
    stub = Stub("la la la")
    a.examine({"song.wav": data}, PROF, transcriber=stub, variants=("reversed",), deadline=time.monotonic() + BIG)
    assert len(stub.calls) == 1 and np.allclose(stub.calls[0]["samples"][::-1], cover + hidden / 2, atol=1e-5)
    stub = Stub("la la la")
    a.examine({"mono.wav": wav(cover)}, PROF, transcriber=stub, deadline=time.monotonic() + BIG)
    assert len(stub.calls) == 2                                               # mono: no difference to hear


def test_speech_with_no_flag_is_unsure_and_the_transcript_is_written(tmp_path):
    cd = delivery(tmp_path, {"memo.wav": wav(voice(2.0))})
    said = "The safe combination is the year the bridge was built. CSCTF{another_events_flag}"
    r = a.solve(cd, PROF, transcriber=Stub(said), seconds=BIG, variants="original")
    assert r.status == "unsure" and r.flags == ()
    assert "read the transcripts" in r.notes and str(cd / "recon" / "audio_speech") in r.notes
    assert (cd / "recon" / "audio_speech" / "files_memo.wav.original.txt").read_text().splitlines()[0] == said


def test_speech_in_which_nothing_is_heard_is_none(tmp_path):
    cd = delivery(tmp_path, {"hiss.wav": wav(0.2 * np.random.default_rng(1).standard_normal(SR))})
    r = a.solve(cd, PROF, transcriber=Stub(""), seconds=BIG)
    assert r.status == "none" and r.flags == ()
    assert [e.kind for e in r.evidence].count("transcript") == 2              # original and reversed, both empty


def test_a_transcriber_that_fails_on_every_recording_is_blocked_naming_it(tmp_path):
    def boom(samples, **kw):
        raise a.TranscribeError("whisper-cli exit 3: error: failed to load model")

    boom.name = "whisper-cli"
    cd = delivery(tmp_path, {"memo.wav": wav(voice(2.0))})
    r = a.solve(cd, PROF, transcriber=boom, seconds=BIG, variants="original")
    assert r.status == "blocked"
    assert "was not transcribed (whisper-cli)" in r.notes and "failed to load model" in r.notes


def test_a_cut_transcript_is_used_and_the_cut_is_reported(tmp_path):
    def cut(samples, **kw):
        raise a.TranscribeCut("The flag is A C M E open brace c u t close brace", "faster-whisper was stopped at the budget (out of time)")

    cd = delivery(tmp_path, {"memo.wav": wav(voice(2.0))})
    r = a.solve(cd, PROF, transcriber=cut, seconds=BIG)
    assert r.status == "candidate" and r.flags == ("ACME{cut}",)
    assert "budget ran out" in r.notes and "stopped at the budget" in [e for e in r.evidence if e.kind == "transcript"][0].detail


def test_out_of_time_before_a_recording_is_named_and_nothing_is_transcribed(tmp_path):
    stub = Stub(SPELLED)
    rep = a.examine({"a.wav": wav(voice(1.0)), "b.wav": wav(voice(1.0, seed=2))}, PROF, transcriber=stub,
                    deadline=time.monotonic() - 1.0)
    assert stub.calls == [] and rep.out_of_time
    assert [(f.state, f.reason) for f in rep.files] == [("not-decoded", "out of time")] * 2
    r = a.result_of(rep)
    assert r.status == "blocked" and "raise seconds=" in r.notes


def test_an_undecodable_recording_is_named_and_does_not_hide_the_others(tmp_path):
    def to_wav(data, name):
        raise a.DecodeError("ffmpeg in the sandbox: sandbox down: no docker")

    files = {"broken.mp3": b"ID3" + bytes(40), "voice.wav": wav(voice(2.0))}
    rep = a.examine(files, PROF, transcriber=Stub(SPELLED), to_wav=to_wav, deadline=time.monotonic() + BIG)
    r = a.result_of(rep)
    assert r.status == "candidate" and r.flags == (FLAG,)
    assert "Not decoded: broken.mp3" in r.notes and "sandbox down: no docker" in r.notes
    alone = a.examine({"broken.mp3": b"ID3" + bytes(40)}, PROF, transcriber=Stub(SPELLED), to_wav=to_wav,
                      deadline=time.monotonic() + BIG)
    r = a.result_of(alone)
    assert r.status == "blocked" and "no audio file could be decoded" in r.notes and "libsndfile does not read it" in r.notes


def test_only_max_files_recordings_are_examined_and_the_rest_are_named(monkeypatch):
    monkeypatch.setattr(a, "MAX_FILES", 2)
    files = {f"t{i}.wav": wav(tone(400 + 100 * i, 300)) for i in range(3)}
    rep = a.examine(files, PROF, transcriber=never, deadline=time.monotonic() + BIG)
    assert [f.name for f in rep.files] == ["t0.wav", "t1.wav"]
    assert rep.skipped == ["t2.wav: over the 2 audio files examined in one delivery"]
    assert any(e.kind == "skipped" and "t2.wav" in e.detail for e in a.result_of(rep).evidence)


def test_a_delivery_with_no_audio_is_none(tmp_path):
    cd = delivery(tmp_path, {"readme.txt": b"nothing to hear", "pic.png": b"\x89PNG\r\n\x1a\n" + bytes(20)})
    r = a.solve(cd, PROF, transcriber=never, seconds=BIG)
    assert r.status == "none" and r.notes == "no audio file in the delivery" and r.evidence == ()
    assert not (cd / "recon").exists()                                        # nothing examined, nothing written


# ---------------------------------------------------------------- the engine contract

def test_delivery_audio_prefers_the_sweeps_copy_and_skips_recon(tmp_path):
    cd = tmp_path / "9-drop"
    for sub in ("files", "unpacked/inner", "unpacked/recon", "recon"):
        (cd / sub).mkdir(parents=True)
    data = wav(tone(500, 200))
    (cd / "files" / "orig.wav").write_bytes(data)
    (cd / "unpacked" / "orig.wav").write_bytes(data)
    (cd / "unpacked" / "inner" / "member.ogg").write_bytes(ogg_vorbis(tone(500, 200)))
    (cd / "unpacked" / "inner" / "notes.txt").write_bytes(b"words")
    (cd / "unpacked" / "recon" / "old.wav").write_bytes(data)
    (cd / "recon" / "ours.wav").write_bytes(data)
    assert sorted(a.delivery_audio(cd)) == ["unpacked/inner/member.ogg", "unpacked/orig.wav"]
    shutil.rmtree(cd / "unpacked")
    assert sorted(a.delivery_audio(cd)) == ["files/orig.wav"]
    shutil.rmtree(cd / "files")
    (cd / "loose.wav").write_bytes(data)
    assert sorted(a.delivery_audio(cd)) == ["loose.wav"]                      # the folder itself; recon/ still skipped


def test_a_single_recording_can_be_given_and_writes_nothing_unless_asked(tmp_path):
    p = tmp_path / "recovered.ogg"
    p.write_bytes(ogg_page(b"APP!") + ogg_vorbis(voice(2.0)))
    r = a.solve(p, PROF, transcriber=Stub(SPELLED), seconds=BIG)
    assert r.status == "candidate" and r.flags == (FLAG,)
    assert "dropped 1 leading Ogg page" in r.evidence[0].detail and r.evidence[0].path == "recovered.ogg"
    assert sorted(x.name for x in tmp_path.iterdir()) == ["recovered.ogg"]
    out = tmp_path / "out"
    a.solve(p, PROF, transcriber=Stub(SPELLED), seconds=BIG, out=str(out))
    assert sorted(x.name for x in out.iterdir()) == ["recovered.ogg.original.txt", "report.json"]


def test_a_missing_folder_and_bad_options_are_blocked_with_the_reason(tmp_path):
    r = a.solve(tmp_path / "nope", PROF)
    assert r.status == "blocked" and "no such challenge folder or file" in r.notes
    cd = delivery(tmp_path, {"v.wav": wav(voice(1.0))})
    for opts, needle in (({"seconds": "soon"}, "seconds and threads are numbers"), ({"seconds": 0}, "seconds must be > 0"),
                         ({"threads": 0}, "threads >= 1"), ({"backend": "whisper-large"}, "backend must be auto or one of"),
                         ({"variants": "original,backwards"}, "variants are"), ({"variants": ""}, "variants are"),
                         ({"speech": "maybe"}, "speech must be one of"), ({"graph": "maybe"}, "graph must be on or off"),
                         ({"modle": "/x"}, "unknown option(s) ['modle']")):
        r = a.solve(cd, PROF, transcriber=never, **opts)
        assert r.status == "blocked" and r.notes.startswith("bad option:") and needle in r.notes, opts


def test_graph_option_turns_the_decode_of_readings_off(tmp_path):
    said = " ".join({"0": "zero", "3": "three", "4": "four", "5": "five", "6": "six", "7": "seven", "8": "eight"}.get(c, c)
                    for c in "ACME{h3x}".encode().hex())
    cd = delivery(tmp_path, {"digits.wav": wav(voice(2.0))})
    r = a.solve(cd, PROF, transcriber=Stub(said), seconds=BIG, variants="original")
    assert r.status == "candidate" and r.flags == ("ACME{h3x}",)
    r = a.solve(cd, PROF, transcriber=Stub(said), seconds=BIG, variants="original", graph="off")
    assert r.status == "unsure" and r.flags == ()


def test_solve_end_to_end_through_the_stub_whisper_cli_on_path(tmp_path, monkeypatch):
    # The whole production path but for the model: PATH lookup, model option, WAV hand-off, cleaning, sweep.
    script, seen = stub_cli(tmp_path, SAYS_FLAG)
    monkeypatch.setenv("PATH", f"{script.parent}{os.pathsep}{os.environ['PATH']}")
    model = tmp_path / "ggml-test.bin"
    model.write_bytes(b"not a real model")
    cd = delivery(tmp_path, {"voicemail.flac": _flac(voice(2.0))})
    r = a.solve(cd, PROF, backend="whisper-cli", model=str(model), seconds=BIG, language="auto")
    assert r.status == "candidate" and r.flags == (FLAG,)
    assert "[original] via whisper-cli" in [e for e in r.evidence if e.kind == "transcript"][0].detail
    argv = (seen / "argv").read_text().splitlines()
    assert argv[1] == str(model) and argv[argv.index("-l") + 1] == "auto"
    assert sf.info(str(seen / "heard.wav")).frames == 2 * SR


def _flac(x, sr=SR):
    buf = io.BytesIO()
    sf.write(buf, np.asarray(x, dtype=np.float64), sr, format="FLAC", subtype="PCM_16")
    return buf.getvalue()


# ---------------------------------------------------------------- manifest: routes and intake

def test_audio_routes_here_in_any_category_and_the_words_alone_do_not(tmp_path):
    from ctf.engines import router
    (tmp_path / "plain").mkdir()
    (tmp_path / "plain" / "notes.txt").write_text("plain words")
    assert a.ENGINE not in [h.manifest.id for h in router.route("misc", "listen to the recording of the song", tmp_path / "plain")]
    (tmp_path / "audio").mkdir()
    (tmp_path / "audio" / "voicemail.bin").write_bytes(ogg_vorbis(tone(440, 200)))        # by magic, not by name
    quiet = {h.manifest.id: h.priority for h in router.route("osint", "Operation Dawn", tmp_path / "audio")}
    loud = {h.manifest.id: h.priority for h in router.route("osint", "Listen to the voicemail he left", tmp_path / "audio")}
    assert quiet[a.ENGINE] == 27 and loud[a.ENGINE] == 64


@pytest.mark.parametrize("category,brief,specialist", [
    ("stego", "Listen to this song, something is hidden in it", "toolkits.audio_stego"),
    ("stego", "We intercepted a recording of the beeps", "toolkits.audio_stego"),
    ("misc", "listen closely to the song", "toolkits.audio_tones"),
    ("misc", "a recording of some beeps", "toolkits.audio_tones"),
])
def test_everyday_audio_words_do_not_lift_the_speech_lane_over_the_specialists(tmp_path, category, brief, specialist):
    from ctf.engines import router
    (tmp_path / "song.wav").write_bytes(wav(tone(440, 200)))
    hits = {h.manifest.id: h.priority for h in router.route(category, brief, tmp_path)}
    assert hits[a.ENGINE] == 27                                               # the file route only
    assert hits[specialist] > hits[a.ENGINE], hits


def test_intake_runs_it_on_audio_only_under_a_medium_cost_cap(tmp_path):
    from ctf.engines import manifest
    from ctf.intake import engines as E
    from ctf.intake import guard as G
    ms = manifest.discover()
    mine = next(m for m in ms if m.id == a.ENGINE)
    assert mine.cost_class == "medium" and mine.intake.run == "challenge" and mine.intake.spawns
    assert set(mine.needs_tools) == {"py:numpy", "py:scipy", "py:soundfile"}  # Whisper is found at run time
    cd = tmp_path / "31-beeps"
    (cd / "unpacked").mkdir(parents=True)
    (cd / "unpacked" / "beeps.wav").write_bytes(wav(ladder("PINK{t0ne_l4dder}")))
    allow = G.Guard("os", (), "test: spawn allowed, no OS wrapper (the suite sandbox denies the network)")
    cheap = E.plan(ms, "misc", "some beeps", cd / "unpacked", guard=allow)
    assert a.ENGINE not in [j.engine for j in cheap.jobs]
    assert any(s.engine == a.ENGINE and "cost_class medium" in s.reason for s in cheap.skipped)
    medium = E.plan(ms, "misc", "some beeps", cd / "unpacked", guard=allow, max_cost="medium")
    job = next(j for j in medium.jobs if j.engine == a.ENGINE)
    ctx = E.Context(challenge_dir=cd, folder=cd / "unpacked", out_root=cd / "recon" / "engines",
                    profile=event.load("pink"), guard=allow, root=REPO, python=sys.executable,
                    challenge_id="31", record=False)
    run = E.run_job(job, ctx)
    assert run.status == "ok", (cd / run.errors).read_text()
    assert run.result_status == "candidate" and list(run.flags) == ["PINK{t0ne_l4dder}"]
    assert (cd / "recon" / "audio_speech" / "report.json").is_file()


# ---------------------------------------------------------------- edges the first pass left open

def test_gate_counts_spectral_peaks_not_loudness():
    chord = tone(500, 2000, 0.3) + tone(900, 2000, 0.3) + tone(1400, 2000, 0.3)
    g = a.gate(chord)
    assert g.kind == a.OTHER and g.peaks == 3 and g.few == 0.0               # three at once is not a keyed tone
    faint, strong = 0.6 * 10 ** (-30 / 20), 0.6 * 10 ** (-12 / 20)
    assert a.gate(tone(500, 2000) + tone(1000, 2000, faint) + tone(1500, 2000, faint)).kind == a.TONES
    assert a.gate(tone(500, 2000) + tone(1000, 2000, strong) + tone(1500, 2000, strong)).kind == a.OTHER
    assert a.gate(tone(700, 2000, 0.3) + tone(720, 2000, 0.3)).kind == a.TONES   # one lobe: one peak


def test_gate_judges_only_the_frames_that_sound():
    hiss = 0.01 * np.random.default_rng(4).standard_normal(SR)               # far under a tenth of the tone
    g = a.gate(np.concatenate([tone(700, 1000), hiss]))
    assert g.kind == a.TONES and g.few == 1.0


def test_gate_judges_a_long_recording_over_its_whole_length(monkeypatch):
    monkeypatch.setattr(a, "GATE_SECONDS", 2.0)
    monkeypatch.setattr(a, "GATE_WINDOW", 0.5)
    late_voice = np.concatenate([np.tile(dtmf(80, 50), 4)[: 4 * SR], voice(4.0, seed=7)])
    g = a.gate(late_voice)                                                    # tones for 4 s, then a voice
    assert g.kind != a.TONES and g.seconds == pytest.approx(8.0)
    assert a.gate(late_voice[: 4 * SR]).kind == a.TONES                       # the start alone would say tones


def test_tone_reader_limits_and_failures_are_named_not_hidden(monkeypatch):
    import audio_tones
    data = wav(dtmf(120, 80))
    monkeypatch.setattr(a, "STEGO_MAX_BYTES", 1000)
    f = a.examine({"keys.wav": data}, PROF, deadline=time.monotonic() + BIG).files[0]
    assert not any(r.label.startswith("audio_stego") for r in f.readings)
    assert any("audio_stego not run: the file is over" in n for n in f.notes)

    def broken(*args, **kw):
        raise RuntimeError("fft exploded")

    monkeypatch.setattr(audio_tones, "decode", broken)
    rep = a.examine({"keys.wav": data}, PROF, deadline=time.monotonic() + BIG)
    assert any("audio_tones did not read it: RuntimeError: fft exploded" in n for n in rep.files[0].notes)
    r = a.result_of(rep)
    assert r.status == "none" and "fft exploded" in r.evidence[0].detail


def test_audio_stego_is_given_pcm_wav_only():
    rep = a.examine({"keys.flac": _flac(dtmf(120, 80))}, PROF, deadline=time.monotonic() + BIG)
    f = rep.files[0]
    assert f.gate.kind == a.TONES and f.kind == "flac"
    assert not any(r.label.startswith("audio_stego") for r in f.readings)
    assert not any("audio_stego" in n for n in f.notes)


def test_the_backend_is_looked_up_once_and_only_when_speech_is_there(monkeypatch):
    calls = []

    def fake(want, model, threads, environ):
        calls.append((want, model, threads))
        return Stub("la la la"), []

    monkeypatch.setattr(a, "find_backend", fake)
    rep = a.examine({"a.wav": wav(voice(1.0)), "b.wav": wav(voice(1.0, seed=2))}, PROF, backend="whisper-cli",
                    model="/models/m.bin", threads=3, variants=("original",), deadline=time.monotonic() + BIG)
    assert calls == [("whisper-cli", "/models/m.bin", 3)] and rep.backend == "stub-whisper"
    assert [len(f.readings) for f in rep.files] == [1, 1]
    calls.clear()
    a.examine({"t.wav": wav(dtmf(80, 50))}, PROF, deadline=time.monotonic() + BIG)
    assert calls == []


def test_a_tone_flag_in_a_mixed_recording_does_not_stop_the_voice_being_heard(monkeypatch):
    monkeypatch.setattr(a, "tone_readings", lambda audio, original, kind, deadline: ([("tone ladder (auto)", "ACME{t0ne}")], []))
    mixed = np.concatenate([np.tile(dtmf(80, 50), 2), voice(0.6, seed=6)])
    stub = Stub("the voice says ACME{v01ce}")
    rep = a.examine({"call.wav": wav(mixed)}, PROF, transcriber=stub, deadline=time.monotonic() + BIG)
    assert rep.files[0].gate.kind == a.MIXED and len(stub.calls) == 1
    assert rep.flags() == ["ACME{t0ne}", "ACME{v01ce}"]
    r = a.result_of(rep)
    assert r.status == "candidate" and [e.kind for e in r.evidence] == ["audio", "tone-reading", "tone-flag",
                                                                         "transcript", "speech-flag"]


def test_challenge_id_option_wins_and_a_long_transcript_is_quoted_short_but_written_whole(tmp_path):
    cd = delivery(tmp_path, {"talk.wav": wav(voice(2.0))})
    (cd / "challenge.json").write_text(json.dumps({"id": 55}))
    long = " ".join(f"word{i}" for i in range(1500))
    r = a.solve(cd, PROF, transcriber=Stub(long), seconds=BIG, variants="original", challenge_id="X7")
    assert r.challenge_id == "X7" and r.status == "unsure"
    quoted = [e.detail for e in r.evidence if e.kind == "transcript"][0]
    assert "word0 word1" in quoted and "word1499" not in quoted and len(quoted) < a.EVIDENCE_TEXT + 80
    assert (cd / "recon" / "audio_speech" / "files_talk.wav.original.txt").read_text().strip() == long


def test_delivery_audio_skips_links_and_oversized_files(tmp_path, monkeypatch):
    import image_carve
    cd = tmp_path / "d"
    (cd / "files").mkdir(parents=True)
    data = wav(tone(500, 200))
    (cd / "files" / "ok.wav").write_bytes(data)
    (tmp_path / "outside.wav").write_bytes(data)
    (cd / "files" / "link.wav").symlink_to(tmp_path / "outside.wav")
    (cd / "files" / "big.wav").write_bytes(data + bytes(5000))
    monkeypatch.setattr(image_carve, "MAX_FILE", len(data) + 100)
    assert sorted(a.delivery_audio(cd)) == ["files/ok.wav"]


def test_a_rotated_flag_in_a_transcript_is_not_reported_on_a_loose_chain_alone():
    import codecs
    text = f"the note says {codecs.encode('ACME{rot_thirteen}', 'rot13')} and no more"
    from ctf.codec import FlagOracle, search
    loose = search(text.encode(), FlagOracle(PROF), deadline=time.monotonic() + BIG).hits
    assert [(h.answer, h.confirmed) for h in loose] == [("ACME{rot_thirteen}", False)]    # the graph does reach it
    assert a.text_flags(text, PROF, time.monotonic() + BIG) == []                         # and the lane keeps it out


# ---------------------------------------------------------------- round 1 of verification: the lane's wiring

def lsb_wav(text, copies=16):
    """A recording that is silence to the ear: every sample is 0 or 1, and the LSBs spell `text`."""
    bits = [int(b) for ch in (text * copies).encode() for b in f"{ch:08b}"]
    buf = io.BytesIO()
    sf.write(buf, np.array(bits, dtype=np.int16), SR, format="WAV", subtype="PCM_16")
    return buf.getvalue()


def test_a_silent_recording_still_goes_to_the_tone_readers():
    # Silence to the gate, a message in the sample LSBs to audio_stego: silent files must be read too.
    rep = a.examine({"quiet.wav": lsb_wav("ACME{l5b_1n_s1lence} ")}, PROF, transcriber=never,
                    deadline=time.monotonic() + BIG)
    f = rep.files[0]
    assert f.gate.kind == a.SILENT and f.state == a.READ
    assert "audio_stego sample_lsb_ch0_text" in [r.label for r in f.readings]
    assert rep.flags() == ["ACME{l5b_1n_s1lence}"]
    assert a.result_of(rep).status == "candidate"


def test_a_tone_reading_is_scanned_with_no_left_boundary():
    # Decoded tone codes have no separators: junk glued before the flag must not hide it.
    rep = a.examine({"beeps.wav": wav(ladder("zqACME{gl0ed}"))}, PROF, transcriber=never,
                    deadline=time.monotonic() + BIG)
    texts = [r.text for r in rep.files[0].readings]
    assert any("zqACME{gl0ed}" in t for t in texts), texts
    assert rep.flags() == ["ACME{gl0ed}"]


def test_a_tone_reading_is_not_read_as_spoken_spelling(monkeypatch):
    # Spelling words in a tone reading are characters someone keyed, not a voice: not written out.
    monkeypatch.setattr(a, "tone_readings", lambda audio, original, kind, deadline: ([("tone ladder (auto)", SPELLED)], []))
    rep = a.examine({"beeps.wav": wav(dtmf(80, 50))}, PROF, transcriber=never, graph=False,
                    deadline=time.monotonic() + BIG)
    (r,) = rep.files[0].readings
    assert r.source == "tones" and r.text == SPELLED and r.flags == [] and rep.flags() == []


def test_the_two_stream_xor_pass_of_audio_tones_is_run_and_swept(monkeypatch):
    import audio_tones
    calls = []

    def reader(path, **kw):                    # what the carried reader gives for a two-stream recording
        calls.append(kw)
        return {"candidates": [("xor(codes)", "ACME{tw0_streams}")] if kw.get("xor") else [("auto", "k#1")]}

    monkeypatch.setattr(audio_tones, "decode", reader)
    rep = a.examine({"beeps.flac": _flac(ladder("ab"))}, PROF, transcriber=never, deadline=time.monotonic() + BIG)
    assert calls == [{}, {"xor": True}]
    labels = {r.label: r.flags for r in rep.files[0].readings}
    assert labels["tone ladder, two streams (xor(codes))"] == [("ACME{tw0_streams}", "as read")]
    assert rep.flags() == ["ACME{tw0_streams}"]


def test_no_variant_is_transcribed_once_the_budget_is_spent(monkeypatch):
    clock = step_clock(monkeypatch)

    def slow(samples, n):                      # the first hearing takes the whole budget
        clock.now += 100.0
        return "la la la"

    stub = Stub(slow)
    rep = a.examine({"memo.wav": wav(voice(2.0))}, PROF, transcriber=stub, graph=False, deadline=clock.now + 50.0)
    f = rep.files[0]
    assert len(stub.calls) == 1 and [r.label for r in f.readings] == ["original"]
    assert "reversed not transcribed: out of time" in f.notes and rep.out_of_time
    assert "budget ran out" in a.result_of(rep).notes


@pytest.mark.parametrize("error,late", [("whisper-cli was stopped after 3.0 s (out of time)", True),
                                        ("whisper-cli exit 3: error: failed to load model", False)])
def test_a_transcriber_stopped_at_the_budget_marks_the_report_out_of_time(error, late):
    def stopped(samples, **kw):
        raise a.TranscribeError(error)

    rep = a.examine({"memo.wav": wav(voice(2.0))}, PROF, transcriber=stopped, variants=("original",),
                    deadline=time.monotonic() + BIG)
    assert rep.out_of_time is late and rep.files[0].state == a.NOT_TRANSCRIBED
    assert ("budget ran out" in a.result_of(rep).notes) is late


# ---------------------------------------------------------------- round 1: memory is bounded by the decode, not the file

@pytest.mark.parametrize("rate", [8000, 11025, 16000, 22050, 44100, 48000, 96000])
def test_block_by_block_resampling_equals_the_one_shot_call(rate):
    from scipy.signal import resample_poly
    import math
    x = np.random.default_rng(rate).standard_normal(3 * rate + 7)
    rs = a._Resampler(rate)
    cuts = np.cumsum([1000, 333, 1, 4097, 12000, 50, 70000])
    out = [rs.feed(part) for part in np.split(x, cuts[cuts < len(x)])] + [rs.end()]
    got = np.concatenate(out)
    g = math.gcd(16000, rate)
    want = resample_poly(x, 16000 // g, rate // g)
    assert len(got) == len(want)
    assert np.allclose(got, want, atol=1e-4), float(np.max(np.abs(got - want)))


def test_decode_in_small_blocks_gives_the_same_samples(monkeypatch):
    left, right = tone(1000, 1500, sr=44100), 0.5 * tone(3000, 1500, sr=44100)
    data = wav(np.stack([left, right], axis=1), sr=44100, subtype="FLOAT")
    whole = a.decode("x.wav", data)
    monkeypatch.setattr(a, "DECODE_BLOCK", 2048)
    blocks = a.decode("x.wav", data)
    assert len(blocks.samples) == len(whole.samples) == int(1.5 * SR)
    assert np.allclose(blocks.samples, whole.samples, atol=1e-5)
    assert np.allclose(blocks.difference, whole.difference, atol=1e-5)


def _silent_flac(seconds, rate, channels):
    buf = io.BytesIO()
    with sf.SoundFile(buf, "w", samplerate=rate, channels=channels, format="FLAC", subtype="PCM_16") as f:
        block = np.zeros((rate, channels), dtype=np.int16)
        for _ in range(seconds):
            f.write(block)
    return buf.getvalue()


def test_a_small_file_of_many_high_rate_channels_decodes_in_bounded_memory():
    # 10 s of 8-channel 192 kHz silence is a few kB of FLAC and 61 MB as float32 samples; read whole, a
    # half-hour of it would be 11 GB. Decoded block by block it never holds more than a block or two.
    import tracemalloc
    data = _silent_flac(10, 192000, 8)
    assert len(data) < 1 << 20
    tracemalloc.start()
    try:
        au = a.decode("bomb.flac", data)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert au.rate_in == 192000 and au.channels == 8 and len(au.samples) == 10 * SR
    assert au.frames_total == 10 * 192000
    assert peak < 24 << 20, f"peak {peak >> 20} MiB"


def test_decode_stops_at_the_deadline_and_says_so(monkeypatch):
    monkeypatch.setattr(a, "DECODE_BLOCK", 4096)
    data = wav(tone(500, 2000))
    au = a.decode("x.wav", data, deadline=time.monotonic() - 1.0)
    assert len(au.samples) == 4096 and au.out_of_time                       # one block, then the stop
    assert au.notes == ["decoding stopped at the budget after 0.256 s (out of time)"]
    full = a.decode("x.wav", data, deadline=time.monotonic() + BIG)
    assert len(full.samples) == 2 * SR and not full.out_of_time and full.notes == []


def test_a_decode_cut_by_the_budget_marks_the_report_out_of_time(monkeypatch):
    clock = StepClock()

    def ticking():                            # every look at the clock moves it a second
        clock.now += 1.0
        return clock.now - 1.0

    monkeypatch.setattr(a, "time", types.SimpleNamespace(monotonic=ticking))
    monkeypatch.setattr(a, "DECODE_BLOCK", 4096)
    rep = a.examine({"keys.wav": wav(np.tile(dtmf(80, 50), 2))}, PROF, transcriber=never, graph=False,
                    deadline=clock.now + 1.5)
    f = rep.files[0]
    assert f.state == a.READ and any("decoding stopped at the budget" in n for n in f.notes)
    assert rep.out_of_time and "budget ran out" in a.result_of(rep).notes


def test_tone_readers_get_the_16k_mono_decode_of_a_file_too_big_to_read_whole(monkeypatch):
    import audio_tones
    real, seen = audio_tones.decode, []

    def watch(path, **kw):
        info = sf.info(str(path))
        seen.append((info.samplerate, info.channels))
        return real(path, **kw)

    monkeypatch.setattr(audio_tones, "decode", watch)
    x = ladder("ACME{big_t0ne_ladder}")
    data = wav(np.stack([x, x], axis=1))
    rep = a.examine({"beeps.wav": data}, PROF, transcriber=never, deadline=time.monotonic() + BIG)
    assert seen == [(SR, 2), (SR, 2)] and rep.flags() == ["ACME{big_t0ne_ladder}"]       # under the budget: the file itself
    seen.clear()
    monkeypatch.setattr(a, "TONES_MAX_BYTES", len(x) * 2 * 8 - 1)
    rep = a.examine({"beeps.wav": data}, PROF, transcriber=never, deadline=time.monotonic() + BIG)
    assert seen == [(SR, 1), (SR, 1)] and rep.flags() == ["ACME{big_t0ne_ladder}"]
    assert any(n.startswith("audio_tones read the 16 kHz mono decode") for n in rep.files[0].notes)


def test_a_delivery_reads_each_recording_only_when_it_is_examined(tmp_path, monkeypatch):
    monkeypatch.setattr(a, "MAX_FILES", 2)
    cd = delivery(tmp_path, {"a.wav": wav(tone(500, 300)), "b.wav": wav(tone(600, 300)), "c.wav": wav(tone(700, 300))})
    files = a.delivery_audio(cd)
    assert sorted(files) == ["files/a.wav", "files/b.wav", "files/c.wav"] and len(files) == 3
    assert files.head("files/a.wav")[:4] == b"RIFF"
    (cd / "files" / "a.wav").write_bytes(wav(ladder("ACME{l4te_t0ne_ladder}")))           # changed after the listing
    (cd / "files" / "c.wav").unlink()                                         # past MAX_FILES: never read
    rep = a.examine(files, PROF, transcriber=never, deadline=time.monotonic() + BIG)
    assert rep.flags() == ["ACME{l4te_t0ne_ladder}"]                                      # the bytes were read when examined
    assert [f.name for f in rep.files] == ["files/a.wav", "files/b.wav"]
    assert rep.skipped == ["files/c.wav: over the 2 audio files examined in one delivery"]


# ---------------------------------------------------------------- round 2 of verification

def raw_wav(rate, samples):
    """A 16-bit mono PCM WAV whose header says `rate`, whatever the rate (sf.write refuses some)."""
    pcm = (np.clip(np.asarray(samples, dtype=np.float64), -1, 1) * 32767).astype("<i2").tobytes()
    return struct.pack("<4sI4s4sIHHIIHH4sI", b"RIFF", 36 + len(pcm), b"WAVE", b"fmt ", 16, 1, 1, rate,
                       (rate * 2) & 0xFFFFFFFF, 2, 16, b"data", len(pcm)) + pcm


def no_transcoder(data, name):
    raise a.DecodeError("no transcoder here")


@pytest.mark.parametrize("rate", [768001, 100000007, 2147483647])
def test_a_header_declaring_a_huge_sample_rate_is_refused_before_any_filter_is_designed(rate, monkeypatch):
    # libsndfile opens an 8 kB WAV that says 100 MHz; resampling it would design a 2e9-tap filter.
    import scipy.signal
    designed = []
    monkeypatch.setattr(scipy.signal, "resample_poly", lambda x, up, down, **kw: designed.append((up, down)))
    data = raw_wav(rate, np.zeros(4000))
    assert sf.info(io.BytesIO(data)).samplerate == rate                       # libsndfile does open it
    with pytest.raises(a.DecodeError) as e:
        a.decode("bomb.wav", data, to_wav=no_transcoder)
    assert f"the header declares {rate} Hz, over the 768000 Hz" in str(e.value)
    assert "no transcoder here" in str(e.value) and designed == []


def test_the_highest_rate_allowed_is_decoded():
    x = tone(1000, 50, sr=a.MAX_RATE)
    au = a.decode("fast.wav", raw_wav(a.MAX_RATE, x), to_wav=no_transcoder)
    assert au.rate_in == a.MAX_RATE and len(au.samples) == int(0.05 * SR) and au.notes == []


def test_the_resampling_filter_stays_small_for_an_odd_rate_and_the_pitch_is_kept(monkeypatch):
    common = a._Resampler(44100)
    assert (common.up, common.down, common.exact) == (160, 441, True)
    odd = a._Resampler(767999)                         # prime to 16000: exactly it would be 16000/767999
    assert odd.down <= a.RATIO_DENOMINATOR and not odd.exact
    assert abs(odd.up / odd.down - 16000 / 767999) < 1e-6
    import scipy.signal
    real, seen = scipy.signal.resample_poly, []

    def spy(x, up, down, **kw):
        seen.append(max(up, down))
        return real(x, up, down, **kw)

    monkeypatch.setattr(scipy.signal, "resample_poly", spy)
    au = a.decode("odd.wav", raw_wav(767999, tone(1000, 200, sr=767999)), to_wav=no_transcoder)
    assert seen and max(seen) <= max(SR, a.RATIO_DENOMINATOR)
    assert abs(len(au.samples) - int(0.2 * SR)) <= 2
    assert au.notes == [f"resampled from 767999 Hz at the nearest ratio {odd.up}/{odd.down}"]
    body = au.samples[200:-200]
    spectrum = np.abs(np.fft.rfft(body))
    assert abs(np.argmax(spectrum) * SR / len(body) - 1000) < 10


def test_a_failure_while_flushing_the_resampler_is_a_decode_error(monkeypatch):
    def broken(self):
        raise MemoryError("filter too large")

    monkeypatch.setattr(a._Resampler, "end", broken)
    with pytest.raises(a.DecodeError) as e:
        a.decode("x.wav", wav(tone(500, 300, sr=44100), sr=44100), to_wav=no_transcoder)
    assert "filter too large" in str(e.value) and "no transcoder here" in str(e.value)


def test_a_recording_cut_at_the_limit_keeps_its_full_length_for_the_tone_readers(monkeypatch):
    # Only 1 s of the 2 s stereo file is decoded, but audio_tones would read all of it: its size is
    # judged by the file's length, so over TONES_MAX_BYTES it gets the mono decode.
    import audio_tones
    seen = []

    def watch(path, **kw):
        info = sf.info(str(path))
        seen.append((info.samplerate, info.channels))
        return {"candidates": []}

    monkeypatch.setattr(audio_tones, "decode", watch)
    monkeypatch.setattr(a, "MAX_AUDIO_SECONDS", 1.0)
    x = np.tile(dtmf(80, 50), 20)[: 2 * SR]
    data = wav(np.stack([x, x], axis=1))
    au = a.decode("beeps.wav", data)
    assert len(au.samples) == SR and au.frames_total == 2 * SR
    monkeypatch.setattr(a, "TONES_MAX_BYTES", 300_000)                     # 1 s would be 256 000, 2 s 512 000
    rep = a.examine({"beeps.wav": data}, PROF, transcriber=never, graph=False, deadline=time.monotonic() + BIG)
    assert seen == [(SR, 1), (SR, 1)]
    assert any(n.startswith("audio_tones read the 16 kHz mono decode") for n in rep.files[0].notes)


def test_a_file_that_ends_on_the_block_that_reaches_the_deadline_is_whole(monkeypatch):
    monkeypatch.setattr(a, "DECODE_BLOCK", 4096)
    data = wav(tone(500, 1000)[:4096])
    au = a.decode("x.wav", data, deadline=time.monotonic() - 1.0)
    assert len(au.samples) == 4096 and not au.out_of_time and au.notes == []


def test_a_file_exactly_as_long_as_the_limit_is_not_called_cut(monkeypatch):
    monkeypatch.setattr(a, "MAX_AUDIO_SECONDS", 1.0)
    au = a.decode("x.wav", wav(tone(500, 1000)))
    assert len(au.samples) == SR and au.notes == []


def test_the_transcoded_copy_is_decoded_under_the_deadline_too(monkeypatch):
    monkeypatch.setattr(a, "DECODE_BLOCK", 4096)
    long = wav(tone(500, 2000))
    au = a.decode("x.weird", b"not audio at all" * 8, to_wav=lambda data, name: long,
                  deadline=time.monotonic() - 1.0)
    assert au.how == "ffmpeg in the sandbox" and au.out_of_time and len(au.samples) == 4096


class Spies:
    def __init__(self, monkeypatch, clock=None, ladder_cost=0.0):
        import audio_stego
        import audio_tones
        self.tones, self.stego = [], []

        def tones(path, **kw):
            self.tones.append(kw)
            if clock is not None:
                clock.now += ladder_cost
            return {"candidates": [("auto", "ACME{f1rst_pass}")] if not kw else []}

        def stego(data):
            self.stego.append(len(data))
            return {"candidates": []}

        monkeypatch.setattr(audio_tones, "decode", tones)
        monkeypatch.setattr(audio_stego, "analyze", stego)


def test_tone_readers_are_not_started_once_the_decode_has_spent_the_budget(monkeypatch):
    clock = step_clock(monkeypatch)
    spies = Spies(monkeypatch)
    real = a.decode

    def slow_decode(*args, **kw):                # decoding takes the rest of the budget
        au = real(*args, **kw)
        clock.now += 100.0
        return au

    monkeypatch.setattr(a, "decode", slow_decode)
    rep = a.examine({"keys.wav": wav(dtmf(80, 50))}, PROF, transcriber=never, graph=False, deadline=clock.now + 50.0)
    f = rep.files[0]
    assert f.gate.kind == a.TONES
    assert spies.tones == [] and spies.stego == []
    assert f.notes == ["tone readers not run: out of time"] and rep.out_of_time
    assert "budget ran out" in a.result_of(rep).notes


def test_each_tone_reader_pass_starts_only_while_there_is_time(monkeypatch):
    clock = step_clock(monkeypatch)
    spies = Spies(monkeypatch, clock, ladder_cost=100.0)       # the first pass takes the budget
    rep = a.examine({"keys.wav": wav(dtmf(80, 50))}, PROF, transcriber=never, graph=False, deadline=clock.now + 50.0)
    f = rep.files[0]
    assert spies.tones == [{}] and spies.stego == []
    assert "audio_tones tone ladder, two streams not run: out of time" in f.notes
    assert "audio_stego not run: out of time" in f.notes and rep.out_of_time
    assert rep.flags() == ["ACME{f1rst_pass}"]                 # what was read before the budget ran out is kept


def test_with_time_left_every_tone_reader_pass_runs(monkeypatch):
    clock = step_clock(monkeypatch)
    spies = Spies(monkeypatch, clock, ladder_cost=1.0)
    rep = a.examine({"keys.wav": wav(dtmf(80, 50))}, PROF, transcriber=never, graph=False, deadline=clock.now + 50.0)
    assert spies.tones == [{}, {"xor": True}] and len(spies.stego) == 1
    assert not rep.out_of_time and not any(a.OUT_OF_TIME in n for n in rep.files[0].notes)
    assert rep.flags() == ["ACME{f1rst_pass}"]


# ---------------------------------------------------------------- the real thing (not run without it)

def _say(tmp_path, text):
    p = tmp_path / "said.wav"
    r = subprocess.run(["say", "-o", str(p), "--data-format=LEI16@16000", text], capture_output=True)
    if r.returncode != 0 or not p.is_file():
        pytest.skip(f"not run: say could not synthesize a recording here (exit {r.returncode})")
    return p


def _real_backend(name):
    t, missing = a.find_backend(name)
    if t is None:
        pytest.skip(f"not run: no model for the {name} backend ({'; '.join(missing)})")
    return t


@pytest.mark.slow
@pytest.mark.needs_tool("say", "whisper-cli")
def test_real_whisper_cli_transcribes_a_synthesized_sentence(tmp_path):
    _real_backend("whisper-cli")
    p = _say(tmp_path, "The quick brown fox jumps over the lazy dog.")
    r = a.solve(p, PROF, backend="whisper-cli", seconds=BIG, variants="original")
    assert r.status == "unsure"
    heard = [e.detail.lower() for e in r.evidence if e.kind == "transcript"][0]
    assert "quick brown fox" in heard and "lazy dog" in heard


@pytest.mark.slow
@pytest.mark.needs_tool("say", "py:faster_whisper")
def test_real_faster_whisper_transcribes_a_synthesized_sentence(tmp_path):
    _real_backend("faster-whisper")
    p = _say(tmp_path, "The quick brown fox jumps over the lazy dog.")
    r = a.solve(p, PROF, backend="faster-whisper", seconds=BIG, variants="original")
    assert r.status == "unsure"
    heard = [e.detail.lower() for e in r.evidence if e.kind == "transcript"][0]
    assert "quick brown fox" in heard and "lazy dog" in heard
