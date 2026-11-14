"""B-158: the IQ demodulators against real off-air captures, when an operator has supplied them.

The synthetic suite (tests/test_iq_demod.py) proves each demodulator against a transmitter written
from the standard. What it cannot prove is behaviour on a real receiver's output (filters, drift,
fading, adjacent signals). That needs real captures, and none is in the repo or fetched by build
work. The corpus lives outside the repo, under the real-data root (B-204's layout):

    $CTF_REALDATA/rf-iq/<any folder>/<capture>               a saved IQ file (or a WAV)
    $CTF_REALDATA/rf-iq/<any folder>/<capture>.expect.json   what it must demodulate to:
        {"protocol": "pocsag",        one of iq_demod.PROTOCOLS
         "rate": 22050,               Hz; omit when the file states it (SigMF meta, WAV, file name)
         "format": "cu8",             omit when the extension states it
         "min_frames": 1,             protocol-validated frames required (default 1)
         "contains": "TEST PAGE",     optional: text that must appear in a frame's text or bytes
         "source": "...", "licence": "..."}   where it came from; kept for the operator, not checked

`test_labelled_real_captures` is marked needs_realdata("rf-iq"): without that folder it is reported
NOT RUN, never green. The judging itself is tested on a synthetic corpus built in tmp_path, so the
oracle is known to fail a capture that does not meet its label.

The carried `rf` kit (tests/real/manifest_c.json) already holds four real receiver captures, the
rtl_433 test files in rf/rtl433 (250 kHz .cu8, on-off keyed remotes and weather sensors). None of
them is a protocol this engine demodulates, which makes them the real negative control:
`test_real_ook_captures_are_claimed_by_no_protocol` (needs_realdata("rf")) checks that real receiver
noise and real bursts load, are found as bursts, and are decoded as nothing.

The corpus is untrusted data: a capture is read as bytes by the engine and nothing in it is executed;
the .expect.json is parsed as plain JSON and only the fields above are read.
"""
import json

import numpy as np
import pytest

import iq_demod as iqd
import iq_synth as syn
from ctf import flagfmt, paths

EXPECT_SUFFIX = ".expect.json"


def judge(root):
    """Run every labelled capture under `root`. Returns (cases checked, [failure lines])."""
    failures, checked = [], 0
    ff = flagfmt.current()
    for exp_path in sorted(root.rglob("*" + EXPECT_SUFFIX)):
        capture = exp_path.with_name(exp_path.name[:-len(EXPECT_SUFFIX)])
        label = str(capture.relative_to(root))
        checked += 1
        try:
            exp = json.loads(exp_path.read_text(encoding="utf-8"))
            proto = exp["protocol"]
            if proto not in iqd.PROTOCOLS:
                raise ValueError(f"protocol {proto!r} is not one of {', '.join(iqd.PROTOCOLS)}")
            rate = exp.get("rate")
            if rate is not None and (isinstance(rate, bool) or not isinstance(rate, (int, float)) or rate <= 0):
                raise ValueError("rate must be a positive number")
            need = int(exp.get("min_frames", 1))
        except (OSError, ValueError, KeyError, TypeError) as e:
            failures.append(f"{label}: unreadable expectation: {type(e).__name__}: {e}")
            continue
        if not capture.is_file():
            failures.append(f"{label}: the capture named by {exp_path.name} is absent")
            continue
        try:
            cap = iqd.load_capture(capture, fmt=exp.get("format"), rate=float(rate) if rate else None)
        except iqd.IQDemodError as e:
            failures.append(f"{label}: not loaded: {e}")
            continue
        res = iqd.demodulate(cap, [proto], ff=ff, budget=600.0).results[0]
        if res.error:
            failures.append(f"{label}: {proto} not attempted: {res.error}")
            continue
        solid = [f for f in res.frames if f.validated]
        if len(solid) < need:
            failures.append(f"{label}: {len(solid)} validated {proto} frame(s), expected at least {need} ({res.note})")
            continue
        text = exp.get("contains")
        if text and not any(text in f.text or text.encode() in f.data for f in solid):
            failures.append(f"{label}: no {proto} frame contains {text!r}")
    return checked, failures


def _write_case(folder, name, data, **expect):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_bytes(data)
    (folder / (name + EXPECT_SUFFIX)).write_text(json.dumps(expect))


def test_the_oracle_passes_a_capture_that_meets_its_label_and_fails_one_that_does_not(tmp_path):
    bits = syn.pocsag_bits(424242, "REAL CORPUS ORACLE")
    pager = syn.to_cu8(syn.channel(syn.fsk_iq([1 - b for b in bits], 22050 / 1200, 4500 / 22050), lead=2000, tail=2000))
    noise = syn.to_cu8(syn.noise(20000, 1.0, 3))
    good = tmp_path / "good"
    _write_case(good / "pocsag", "page.cu8", pager, protocol="pocsag", rate=22050, contains="CORPUS ORACLE")
    _write_case(good / "pocsag", "named_153.35M_22.05k.cu8", pager, protocol="pocsag", min_frames=1)  # rate from the name
    assert judge(good) == (2, [])

    bad = tmp_path / "bad"
    _write_case(bad, "silent.cu8", noise, protocol="pocsag", rate=22050)                 # nothing in it
    _write_case(bad, "mislabelled.cu8", pager, protocol="p25", rate=48000)               # the wrong protocol
    _write_case(bad, "wrong_text.cu8", pager, protocol="pocsag", rate=22050, contains="NOT THERE")
    _write_case(bad, "two.cu8", pager, protocol="pocsag", rate=22050, min_frames=2)      # only one message
    _write_case(bad, "norate.cu8", pager, protocol="pocsag")                             # nothing states the rate
    _write_case(bad, "unknown.cu8", pager, protocol="dmr", rate=22050)
    (bad / "gone.cu8.expect.json").write_text(json.dumps({"protocol": "pocsag", "rate": 22050}))
    (bad / "broken.cu8.expect.json").write_text("{not json")
    checked, failures = judge(bad)
    assert checked == 8
    by = {line.split(":")[0]: line for line in failures}
    assert set(by) == {"silent.cu8", "mislabelled.cu8", "wrong_text.cu8", "two.cu8", "norate.cu8", "unknown.cu8",
                       "gone.cu8", "broken.cu8"}
    assert "0 validated pocsag frame(s), expected at least 1" in by["silent.cu8"]
    assert "0 validated p25 frame(s)" in by["mislabelled.cu8"]
    assert "no pocsag frame contains 'NOT THERE'" in by["wrong_text.cu8"]
    assert "1 validated pocsag frame(s), expected at least 2" in by["two.cu8"]
    assert "pocsag not attempted: pocsag: the sample rate is unknown" in by["norate.cu8"]
    assert "protocol 'dmr' is not one of" in by["unknown.cu8"]
    assert "is absent" in by["gone.cu8"] and "unreadable expectation" in by["broken.cu8"]


def test_the_oracle_reads_a_stereo_wav_capture(tmp_path):
    bits = syn.pocsag_bits(7, "WAV IQ")
    iq = syn.channel(syn.fsk_iq([1 - b for b in bits], 48000 / 1200, 4500 / 48000), lead=3000, tail=3000)
    _write_case(tmp_path, "sdr_recording.wav", syn.stereo_wav(iq, 48000), protocol="pocsag", contains="WAV IQ")
    assert judge(tmp_path) == (1, [])
    assert np.iscomplexobj(iqd.load_capture(tmp_path / "sdr_recording.wav").iq)


@pytest.mark.needs_realdata("rf-iq")
def test_labelled_real_captures():
    root = paths.realdata_root() / "rf-iq"
    checked, failures = judge(root)
    assert checked, f"{root} holds no <capture>{EXPECT_SUFFIX}: label each capture (see this file's docstring)"
    assert not failures, "\n".join(failures)


@pytest.mark.needs_realdata("rf")
def test_real_ook_captures_are_claimed_by_no_protocol():
    folder = paths.realdata_root() / "rf" / "rtl433"
    captures = sorted(folder.glob("*.cu8"))
    assert captures, f"{folder} holds no .cu8 capture (the rf kit of tests/real/manifest_c.json)"
    ff = flagfmt.current()
    for path in captures:
        cap = iqd.load_capture(path, rate=250000.0)              # rtl_433 test files are 250 kHz
        assert cap.fmt == "cu8" and cap.samples == path.stat().st_size // 2 and cap.notes == [], path.name
        spans = iqd.bursts(cap.iq)
        assert spans and spans != [(0, cap.samples)], path.name   # keyed bursts over a real noise floor
        report = iqd.demodulate(cap, ff=ff, budget=600.0)
        assert [r.proto for r in report.results] == list(iqd.PROTOCOLS)
        assert [r.error for r in report.results] == [""] * len(iqd.PROTOCOLS), path.name    # every one ran
        claimed = {r.proto: [f.summary for f in r.frames if f.validated or f.lead] for r in report.results}
        assert claimed == {p: [] for p in iqd.PROTOCOLS}, path.name
        assert report.flags == () and iqd.solver_result(str(path), report).status == "none", path.name
