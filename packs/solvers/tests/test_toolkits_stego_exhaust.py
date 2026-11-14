"""B-182: the stego exhaustion harness (solvers/toolkits/stego_exhaust.py), its CLI (ctf/cli/stego_exhaust.py)
and the two stego_tools pieces it added (stegseek_seed, no_start).

Every fixture is built here: random covers drawn with numpy, encoded by Pillow, the LSB bits written by
this file's own embedder, PNG chunks and WAV files packed by hand. Nothing from a challenge is read, every
flag is made up for these tests. The stego sandbox is never touched: the harness gets a fake sandbox
object, and the stego_tools tests replace tools/sandbox.py with a fake module, so stegseek and exiftool
are never run. Budgets are explicit and far above what the work takes (the machine is shared); time is
driven by an injected clock where the test is about the clock, and no test asserts an upper bound on
elapsed time.
"""
from __future__ import annotations

import argparse
import base64
import codecs
import io
import json
import shutil
import struct
import sys
import types
import zipfile
import zlib
from pathlib import Path

import numpy as np
import pytest

import event_pin

REPO = Path(__file__).resolve().parents[1]
for _p in (REPO / "solvers" / "toolkits", REPO / "solvers" / "common", REPO / "solvers" / "warmups"):
    if str(_p) not in sys.path:
        sys.path.append(str(_p))

import carve_stego as cs            # noqa: E402
import render_ocr_sweep as rs       # noqa: E402
import stego_exhaust as se          # noqa: E402
import stego_tools as st            # noqa: E402
from ctf import event, flagfmt      # noqa: E402
from ctf import hypothesis as hyp   # noqa: E402

event_pin.pin(globals(), "csctf")   # carve_stego reads the current event's flag shape
PROFILE = event.load("csctf")
FF = flagfmt.for_profile(PROFILE)
LONG = 3600.0                       # an explicit budget no test comes near
FLAG = "CSCTF{exhaust_fixture_one}"
OTHER = "CSCTF{exhaust_fixture_two}"


# ---- fixtures ----------------------------------------------------------------------------------------

def _cover(h=48, w=48, seed=7, ch=3):
    return np.random.default_rng(seed).integers(0, 256, (h, w, ch), dtype=np.uint8)


def _png_bytes(arr) -> bytes:
    from PIL import Image
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, "PNG")
    return buf.getvalue()


def _embed(arr, payload: bytes, bit=0, chan=None):
    """payload's bits, MSB first, into bit `bit` of the samples row by row (channel `chan` only, or every
    channel interleaved): our own embedder, not carve_stego's reader."""
    out = arr.copy()
    bits = np.unpackbits(np.frombuffer(payload, np.uint8))
    if chan is None:
        flat = out.reshape(-1)
    else:
        flat = out[..., chan].reshape(-1).copy()
    assert len(bits) <= flat.size
    mask = np.uint8(0xFF ^ (1 << bit))
    flat[:len(bits)] = (flat[:len(bits)] & mask) | (bits.astype(np.uint8) << bit)
    if chan is not None:
        out[..., chan] = flat.reshape(out.shape[:2])
    return out


def _chunk(typ: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + typ + body + struct.pack(">I", zlib.crc32(typ + body) & 0xFFFFFFFF)


def _with_chunks(png: bytes, *chunks) -> bytes:
    """The PNG with extra chunks placed right before its IEND."""
    end = png.rindex(b"IEND") - 4
    return png[:end] + b"".join(chunks) + png[end:]


def _zip_with(name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, data)
    return buf.getvalue()


def _wav(samples, rate=8000) -> bytes:
    import wave
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(np.asarray(samples, dtype="<i2").tobytes())
    return buf.getvalue()


def _noise(n=8000, seed=3):
    return np.random.default_rng(seed).integers(-3000, 3000, n).astype(np.int16)


def _wav_lsb(payload: bytes, n=8000) -> bytes:
    s = _noise(n).astype(np.int32)
    bits = np.unpackbits(np.frombuffer(payload, np.uint8)).astype(np.int32)
    s[:len(bits)] = (s[:len(bits)] & ~1) | bits
    return _wav(s.astype(np.int16))


def _jpeg(arr) -> bytes:
    from PIL import Image
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, "JPEG", quality=90)
    return buf.getvalue()


class FakeSandbox:
    """Answers stegseek_seed and exif as stego_tools Recs and counts the calls."""

    def __init__(self, seed=None, exif=None):
        self.seed = seed or (lambda data: st.Rec(ok=True, note="stegseek --seed: no steghide seed in this cover",
                                                 tool="stegseek"))
        self.exif_rec = exif or (lambda data: st.Rec(ok=True, data={}, note="exiftool: 0 tags", tool="exiftool"))
        self.calls = []

    def stegseek_seed(self, data):
        self.calls.append("stegseek")
        return self.seed(data)

    def exif(self, data, name):
        self.calls.append("exiftool")
        return self.exif_rec(data)


def _down(note="sandbox down: not started; run tools/sandbox.py start first: not read"):
    return FakeSandbox(seed=lambda d: st.Rec(note=note, tool="stegseek"), exif=lambda d: st.Rec(note=note, tool="exiftool"))


def _run(files, **kw):
    kw.setdefault("sandbox", FakeSandbox())
    kw.setdefault("ocr", "off")
    kw.setdefault("deadline", None)
    return se.exhaust(files, FF, **kw)


def _by(rep, step, file=None):
    got = [o for o in rep.outcomes if o.step == step and (file is None or o.file == file)]
    assert got, f"no {step} outcome for {file}: {[(o.file, o.step) for o in rep.outcomes]}"
    return got[0]


# ---- the verdict -------------------------------------------------------------------------------------

def test_clean_png_is_nothing_further_complete_and_names_every_step():
    rep = _run({"clean.png": _png_bytes(_cover())})
    v = rep.verdict()
    assert v["verdict"] == se.V_NOTHING and v["complete"] is True and v["flags"] == []
    png_steps = [o.step for o in rep.outcomes if o.file == "clean.png" and not o.step.startswith(se.RENDER_PREFIX)]
    want = [s.key for s in se.CATALOG if "png" in s.kinds]
    assert png_steps == want                                     # every step of the catalog for a PNG, in order
    assert "stegseek-seed" not in png_steps                      # steghide does not hide in a PNG
    assert {o.state for o in rep.outcomes} == {se.NEGATIVE}
    assert any(o.step == se.RENDER_PREFIX + rs.PROBE_PLANE for o in rep.outcomes)     # B-126's sweep ran on it
    assert rep.outcomes[-1].step == se.TEXT_DECODE
    text = se.verdict_text(rep)
    assert text.splitlines()[0].startswith("stego_exhaust verdict: NOTHING FURTHER (complete)")
    assert "Do not try these steps again" in text.splitlines()[0]
    assert "not covered by the catalog:" in text


def test_the_verdict_is_deterministic_whatever_the_order_of_the_files():
    a, b = _png_bytes(_cover(seed=1)), _wav(_noise())
    one = _run({"a.png": a, "b.wav": b})
    two = _run({"b.wav": b, "a.png": a})
    assert json.dumps(one.verdict(), sort_keys=True) == json.dumps(two.verdict(), sort_keys=True)
    assert se.verdict_text(one) == se.verdict_text(two)
    assert [o.file for o in one.outcomes if o.file][:1] == ["a.png"]


def test_sandbox_down_steps_are_not_run_never_negative():
    jpg = _jpeg(_cover())
    rep = _run({"c.jpg": jpg}, sandbox=_down())
    v = rep.verdict()
    assert v["verdict"] == se.V_NOTHING and v["complete"] is False
    nr = {x["step"]: x["evidence"] for x in v["not_run"]}
    assert set(nr) == {"stegseek-seed", "exiftool", se.TEXT_DECODE}
    assert "sandbox down" in nr["stegseek-seed"] and "sandbox down" in nr["exiftool"]
    # the texts exiftool would recover were not decoded: the decode is not ruled out either
    assert "not ruled out: 2 steps that recover texts did not run" in nr[se.TEXT_DECODE]
    assert _by(rep, "exiftool").state == se.NOT_RUN and _by(rep, "stegseek-seed").state == se.NOT_RUN
    head = se.verdict_text(rep).splitlines()[0]
    assert "NOT RUN" in head and "not negative" in head and "(complete)" not in head
    assert "not run (NOT negative):" in se.verdict_text(rep)


def test_a_tool_missing_from_the_image_is_not_run():
    missing = lambda d: st.Rec(note="stegseek exit 127: stegseek: not found", tool="stegseek", code=127)  # noqa: E731
    rep = _run({"s.bmp": _bmp(_cover())}, sandbox=FakeSandbox(seed=missing))
    o = _by(rep, "stegseek-seed")
    assert o.state == se.NOT_RUN and "not found" in o.evidence
    assert rep.verdict()["complete"] is False


def _bmp(arr) -> bytes:
    from PIL import Image
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, "BMP")
    return buf.getvalue()


def test_not_a_carrier_is_skipped_by_name_and_solve_says_blocked(tmp_path):
    rep = _run({"notes.txt": b"just some notes, nothing here at all\n"})
    assert rep.outcomes == [] and rep.files == {}
    assert rep.skipped == ["notes.txt: a text file, not a carrier the catalog sweeps"]
    v = rep.verdict()
    assert v["complete"] is False and v["steps_ran"] == 0                  # an empty sweep is never complete
    assert se.verdict_text(rep).splitlines()[0].startswith("stego_exhaust verdict: NO CARRIER")
    d = tmp_path / "ch"
    (d / "files").mkdir(parents=True)
    (d / "files" / "notes.txt").write_bytes(b"just some notes, nothing here at all\n")
    res = se.solve(d, PROFILE, sandbox="off", ocr="off", ledger="off", seconds=LONG)
    assert res.status == "blocked" and list(res.flags) == []
    assert "no carrier in the delivery" in res.notes


# ---- the steps ---------------------------------------------------------------------------------------

def test_lsb_bit0_flag_is_found_and_solved_plain():
    png = _png_bytes(_embed(_cover(), FLAG.encode() + b"\x00"))
    rep = _run({"l.png": png})
    assert rep.verdict()["verdict"] == se.V_FLAG and rep.verdict()["flags"] == [FLAG]
    o = _by(rep, "lsb-planes")
    assert o.state == se.FLAG and FLAG in o.plain and "bit0" in o.evidence
    res = se.result_of(rep)
    assert res.status == "solved" and list(res.flags) == [FLAG]


def test_a_high_bit_plane_of_one_channel_is_read():
    png = _png_bytes(_embed(_cover(64, 64), FLAG.encode() + b"\x00", bit=5, chan=1))
    rep = _run({"h.png": png})
    assert _by(rep, "lsb-planes").state == se.FLAG
    pg = _by(rep, "plane-grep")
    assert pg.state == se.FLAG and "bit5 G" in pg.evidence
    assert "160 plane readings searched" in pg.evidence          # 8 bits x 5 channel sets x 2 orders x 2 bit orders


def test_plane_grep_reads_base64_of_the_flag_in_a_plane():
    blob = base64.b64encode(b"noise before " + FLAG.encode() + b" and after")
    png = _png_bytes(_embed(_cover(64, 64), blob, bit=3, chan=2))
    rep = _run({"b.png": png})
    pg = _by(rep, "plane-grep")
    assert pg.state == se.FLAG and pg.flags == [FLAG] and "bit3 B" in pg.evidence


def test_plane_grep_is_not_run_when_the_flag_prefix_is_unknown():
    import datetime as dt
    p = event.parse({"slug": "b182-noprefix", "name": "t", "dates": {"start": dt.date(2026, 1, 1),
                     "end": dt.date(2026, 1, 2)}, "platform": {"kind": "manual"}, "flag": {"prefixes": []},
                     "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"}},
                    src="<test>")
    ff = flagfmt.for_profile(p)
    assert not ff.known
    rep = se.exhaust({"n.png": _png_bytes(_cover())}, ff, sandbox=FakeSandbox(), ocr="off")
    assert _by(rep, "plane-grep").state == se.NOT_RUN and "prefix is not known" in _by(rep, "plane-grep").evidence
    assert _by(rep, se.TEXT_DECODE).state == se.NOT_RUN
    assert rep.verdict()["complete"] is False


def test_trailing_zip_after_the_png_end_is_carved_and_unpacked():
    png = _png_bytes(_cover()) + _zip_with("inner/flag.txt", FLAG.encode())
    rep = _run({"t.png": png})
    o = _by(rep, "trailing")
    assert o.state == se.FLAG and o.flags == [FLAG] and "after the png end" in o.evidence
    assert _by(rep, "carve").state == se.FLAG


def test_a_png_after_a_jpeg_is_swept_as_a_file_of_its_own():
    inner = _png_bytes(_embed(_cover(32, 32, seed=9), OTHER.encode() + b"\x00"))
    rep = _run({"host.jpg": _jpeg(_cover()) + inner})
    child = [n for n, i in rep.files.items() if i["depth"] == 1]
    assert len(child) == 1 and child[0].startswith("host.jpg" + cs.ARROW)
    assert rep.files[child[0]]["kind"] == "png" and rep.files[child[0]]["parent"] == "host.jpg"
    assert _by(rep, "lsb-planes", child[0]).state == se.FLAG
    assert rep.verdict()["flags"] == [OTHER]


def test_chunk_crc_repairs_a_cut_ihdr_and_sweeps_the_repaired_picture():
    png = _png_bytes(_cover(40, 40))
    body = bytearray(png[16:29])
    struct.pack_into(">I", body, 4, 20)                           # height 40 -> 20; the CRC stays that of 40
    cut = png[:16] + bytes(body) + png[29:]
    rep = _run({"cut.png": cut})
    o = _by(rep, "chunk-crc", "cut.png")
    assert "wrong CRC: IHDR" in o.evidence and "IHDR CRC matches 40x40" in o.evidence
    fixed = [n for n in rep.files if "IHDR repaired to 40x40" in n]
    assert fixed and rep.files[fixed[0]]["depth"] == 1


def test_chunk_crc_reads_a_nonstandard_chunk():
    png = _with_chunks(_png_bytes(_cover()), _chunk(b"fLAg", FLAG.encode()))
    o = _by(_run({"c.png": png}), "chunk-crc")
    assert o.state == se.FLAG and "non-standard: fLAg" in o.evidence


def test_metadata_fields_split_across_text_chunks_are_concatenated_in_name_order():
    half = len(FLAG) // 2
    # file order: the second half first, so only the field-name order joins the flag
    png = _with_chunks(_png_bytes(_cover()), _chunk(b"tEXt", b"b_part\x00" + FLAG[half:].encode()),
                       _chunk(b"tEXt", b"a_part\x00" + FLAG[:half].encode()))
    rep = _run({"m.png": png})
    o = _by(rep, "metadata-concat")
    assert o.state == se.FLAG and o.flags == [FLAG] and "concatenated in field-name order" in o.evidence
    assert "concatenated in file order" not in o.evidence
    # nothing else reads it: a half alone is no flag
    assert [x.step for x in rep.outcomes if x.state == se.FLAG] == ["metadata-concat"]


def test_exiftool_tags_are_searched_alone_and_concatenated():
    half = len(FLAG) // 2
    row = {"XMP-dc:Creator": FLAG[:half], "XMP-dc:Title": FLAG[half:], "ExifTool:Warning": "a made-up warning"}
    sb = FakeSandbox(exif=lambda d: st.Rec(ok=True, data=row, note="exiftool: 2 tags", tool="exiftool"))
    rep = _run({"e.png": _png_bytes(_cover())}, sandbox=sb)
    o = _by(rep, "exiftool")
    assert o.state == se.FLAG and o.flags == [FLAG] and "Warning: a made-up warning" in o.evidence
    assert sb.calls.count("exiftool") == 1


def test_rot13_of_the_flag_in_metadata_is_reached_by_the_text_decode(monkeypatch):
    monkeypatch.setattr(se, "DECODE_SECONDS", 60.0)              # a budget the shared machine cannot cut
    png = _with_chunks(_png_bytes(_cover()), _chunk(b"tEXt", b"Comment\x00" + codecs.encode(FLAG, "rot13").encode()))
    rep = _run({"r.png": png})
    assert _by(rep, "metadata-concat").state == se.RECOVERED
    td = _by(rep, se.TEXT_DECODE)
    assert td.state == se.FLAG and td.flags == [FLAG]
    res = se.result_of(rep)
    assert res.status == "candidate" and list(res.flags) == [FLAG]    # a decoded flag is never `solved`


def test_steganalysis_fires_an_indicator_never_a_flag(monkeypatch):
    png = _png_bytes(_cover())
    assert _by(_run({"s.png": png}), "steganalysis").state == se.NEGATIVE          # random cover: no detector
    seen = []
    hit = types.SimpleNamespace(method="chi-square", channel="R", score=0.97, evidence="made-up pair counts")
    monkeypatch.setattr(se.sa, "analyze_image", lambda data: seen.append(data) or (hit,))
    rep = _run({"s.png": png})
    o = _by(rep, "steganalysis")
    assert seen == [png] and o.state == se.INDICATOR and o.flags == []
    assert "chi-square on R (score 0.97): made-up pair counts" in o.evidence
    v = rep.verdict()
    assert v["verdict"] == se.V_NOTHING and [x["step"] for x in v["indicators"]] == ["steganalysis"]


def test_steganalysis_does_not_apply_to_a_gif():
    from PIL import Image
    buf = io.BytesIO()
    Image.fromarray(_cover()[..., 0]).convert("P").save(buf, "GIF")
    rep = _run({"g.gif": buf.getvalue()})
    o = _by(rep, "steganalysis")
    assert o.state == se.NA and "does not apply" in o.evidence
    assert rep.verdict()["complete"] is True                  # n/a is no gap in the catalog


def test_wav_lsb_and_named_tools_run_on_a_wav():
    wav = _wav_lsb(FLAG.encode() + b"\x00")
    rep = _run({"w.wav": wav})
    assert _by(rep, "wav-lsb").state == se.FLAG
    named = _by(rep, "wav-named-tools")
    assert named.state in (se.NEGATIVE, se.FLAG, se.RECOVERED) and "WavSteg" in named.evidence
    assert _by(rep, "stegseek-seed").state == se.NEGATIVE           # the fake says: no seed
    assert any(o.step == se.RENDER_PREFIX + rs.PROBE_SPEC for o in rep.outcomes)   # B-126's spectrogram probe


def test_stegseek_payload_reaches_the_flag_and_encrypted_data_is_open():
    def found(d):
        r = st.Rec(ok=True, note="stegseek --seed: steghide data (seed 1a2b3c4d), 26 bytes extracted",
                   tool="stegseek", files={"payload": FLAG.encode()})
        r.data = {"seed": "1a2b3c4d", "size": "26 B", "algorithm": "none", "name": "f.txt"}
        return r

    def locked(d):
        r = st.Rec(ok=True, note="stegseek --seed: steghide data, not extracted", tool="stegseek")
        r.data = {"seed": "1a2b3c4d", "size": "26 B", "algorithm": "rijndael-128", "name": None}
        return r

    jpg = _jpeg(_cover())
    rep = _run({"s.jpg": jpg}, sandbox=FakeSandbox(seed=found))
    assert _by(rep, "stegseek-seed").state == se.FLAG and rep.verdict()["flags"] == [FLAG]
    rep = _run({"s.jpg": jpg}, sandbox=FakeSandbox(seed=locked))
    o = _by(rep, "stegseek-seed")
    assert o.state == se.OPEN and "needs its passphrase" in o.evidence and "rijndael-128" in o.evidence
    v = rep.verdict()
    assert v["verdict"] == se.V_OPEN and [x["step"] for x in v["open"]] == ["stegseek-seed"]
    assert se.verdict_text(rep).splitlines()[0].startswith("stego_exhaust verdict: OPEN")
    assert se.result_of(rep).status == "unsure"


def test_an_encrypted_zip_member_is_open_not_negative():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("secret.txt", b"x" * 40)
    raw = bytearray(buf.getvalue())
    # set the encryption bit in the local header and the central directory entry: unzip asks a password
    raw[6] |= 1
    cd = raw.rindex(b"PK\x01\x02")
    raw[cd + 8] |= 1
    rep = _run({"z.png": _png_bytes(_cover()) + bytes(raw)})
    o = _by(rep, "trailing")
    assert o.state == se.OPEN and "encrypted archive member" in o.evidence
    assert rep.verdict()["verdict"] == se.V_OPEN


# ---- rejected flags ----------------------------------------------------------------------------------

def test_a_rejected_flag_is_reported_as_rejected_never_as_the_flag():
    png = _png_bytes(_embed(_cover(), FLAG.encode() + b"\x00"))
    rep = _run({"l.png": png}, rejected=[FLAG])
    v = rep.verdict()
    assert v["flags"] == [] and v["verdict"] == se.V_NOTHING and v["rejected_reached"] == [FLAG]
    assert _by(rep, "lsb-planes").state == se.REJECTED
    assert "rejected flags reached again" in se.verdict_text(rep)
    assert se.result_of(rep).status == "none"
    # a second flag beside the rejected one still wins
    both = _png_bytes(_embed(_cover(), FLAG.encode() + b"\x00")) + _zip_with("f.txt", OTHER.encode())
    v2 = _run({"l.png": both}, rejected=[FLAG]).verdict()
    assert v2["flags"] == [OTHER] and v2["verdict"] == se.V_FLAG


# ---- the clock ---------------------------------------------------------------------------------------

def test_past_the_deadline_every_step_is_not_run_and_solve_is_blocked():
    rep = _run({"x.png": _png_bytes(_cover())}, deadline=10.0, clock=lambda: 11.0)
    file_steps = [o for o in rep.outcomes if o.file == "x.png"]
    assert file_steps and all(o.state == se.NOT_RUN and "out of time" in o.evidence for o in file_steps)
    v = rep.verdict()
    assert v["complete"] is False and v["steps_ran"] == 0
    assert se.result_of(rep).status == "blocked"


def test_a_clock_that_runs_out_midway_leaves_the_rest_not_run():
    ticks = iter(range(10 ** 6))
    rep = _run({"x.png": _png_bytes(_cover())}, deadline=3, clock=lambda: next(ticks))
    states = [o.state for o in rep.outcomes if o.file == "x.png"]
    assert se.NEGATIVE in states and se.NOT_RUN in states
    assert states.index(se.NOT_RUN) > states.index(se.NEGATIVE)
    assert rep.verdict()["complete"] is False
    assert se.result_of(rep).status == "unsure"


def test_a_scan_the_deadline_cuts_inside_carve_stego_is_not_run_never_negative():
    # the harness's own clock says there is time (0 < 1), so every step starts; carve_stego's scans read
    # time.monotonic() against the same deadline, which any running machine is far past (monotonic > 1 s):
    # each scan stops at once and says "out of time". No upper bound on elapsed time is involved.
    rep = _run({"x.png": _png_bytes(_cover())}, deadline=1.0, clock=lambda: 0.0)
    lsb = _by(rep, "lsb-planes")
    assert lsb.state == se.NOT_RUN and "cut: lsb: out of time: not ruled out" in lsb.evidence
    deep = _by(rep, "lsb-deep")
    assert deep.state == se.NOT_RUN and "out of time" in deep.evidence
    assert _by(rep, "trailing").state == se.NEGATIVE                  # a step the deadline does not reach
    assert _by(rep, "plane-grep").state == se.NEGATIVE                # judged by the harness's clock: it ran
    v = rep.verdict()
    assert v["complete"] is False and {"lsb-planes", "lsb-deep"} <= {x["step"] for x in v["not_run"]}


def test_a_carrier_larger_than_the_carve_window_is_not_ruled_out(monkeypatch):
    png = _png_bytes(_cover())
    monkeypatch.setattr(se.cs, "MAX_SCAN", len(png))                  # the whole file is in the window
    assert _by(_run({"x.png": png}), "carve").state == se.NEGATIVE
    monkeypatch.setattr(se.cs, "MAX_SCAN", len(png) - 1)              # one byte past it
    rep = _run({"x.png": png})
    o = _by(rep, "carve")
    assert o.state == se.NOT_RUN and f"only the first {len(png) - 1} of the {len(png)} bytes" in o.evidence
    assert rep.verdict()["complete"] is False
    # a flag found in the window still stands
    big = _png_bytes(_cover()) + _zip_with("f.txt", FLAG.encode())
    monkeypatch.setattr(se.cs, "MAX_SCAN", len(big) - 1)
    assert _by(_run({"x.png": big}), "carve").state == se.FLAG


def test_two_files_with_the_same_bytes_are_swept_once():
    png = _png_bytes(_cover())
    rep = _run({"a.png": png, "b.png": png})
    assert list(rep.files) == ["a.png"]
    assert rep.skipped == ["b.png: the same bytes as a file already swept"]
    assert not [o for o in rep.outcomes if o.file == "b.png"]


# ---- the hypothesis ledger ---------------------------------------------------------------------------

def test_every_step_is_recorded_and_a_second_run_reruns_nothing(tmp_path, monkeypatch):
    png = _png_bytes(_cover())
    sb = FakeSandbox()
    one = _run({"p.png": png}, sandbox=sb, cid="b182-a", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert one.verdict()["verdict"] == se.V_NOTHING and one.verdict()["complete"]
    tried = hyp.methods_tried("b182-a", tmp_path)
    for s in se.CATALOG:
        if "png" in s.kinds:
            assert tried[hyp.normalize_method(se.method_of(s.key, "p.png", se._sha(png)))] == "negative"
    assert tried[hyp.normalize_method(se.text_decode_method({"p.png": png}))] == "negative"
    assert any(k.startswith(rs.ENGINE.lower()) for k in tried)            # B-126's probes, by its own file_checklist

    def boom(*a, **k):
        raise AssertionError("a settled step was run again")
    for name in ("lsb_scan", "plane_scan", "lsb_deep_scan", "lsb_extract", "trailing", "carve", "png_chunks"):
        monkeypatch.setattr(se.cs, name, boom)
    monkeypatch.setattr(se.rs, "examine", boom)
    monkeypatch.setattr(se.sa, "analyze_image", boom)
    sb2 = FakeSandbox()
    before = len(hyp.entries("b182-a", tmp_path))
    two = _run({"p.png": png}, sandbox=sb2, cid="b182-a", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert sb2.calls == []
    assert all(o.ledger for o in two.outcomes)
    assert [(o.file, o.step, o.state) for o in two.outcomes] == [(o.file, o.step, o.state) for o in one.outcomes]
    assert two.verdict()["verdict"] == se.V_NOTHING and two.verdict()["complete"]
    assert len(hyp.entries("b182-a", tmp_path)) == before                 # nothing new was written by run two


def test_a_step_not_run_is_recorded_as_error_and_run_next_time(tmp_path):
    png = _png_bytes(_cover())
    _run({"p.png": png}, sandbox=_down(), cid="b182-b", workdir=tmp_path, ledger=True, profile=PROFILE)
    m = se.method_of("exiftool", "p.png", se._sha(png))
    assert hyp.seen("b182-b", m, tmp_path)["result"] == "error"
    assert not hyp.should_skip("b182-b", m, tmp_path).skip
    sb = FakeSandbox()
    rep = _run({"p.png": png}, sandbox=sb, cid="b182-b", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert sb.calls == ["exiftool"]                                         # only the step that had not run
    assert _by(rep, "exiftool").state == se.NEGATIVE and _by(rep, "exiftool").ledger is None
    assert _by(rep, "lsb-planes").ledger is not None
    assert hyp.seen("b182-b", m, tmp_path)["result"] == "negative"
    # a partial run, then a full one: the catalog is complete (the settled steps gave their texts again)
    td = _by(rep, se.TEXT_DECODE)
    assert td.state == se.NEGATIVE and td.ledger is None
    assert rep.verdict()["complete"] is True and rep.verdict()["verdict"] == se.V_NOTHING
    assert hyp.seen("b182-b", se.text_decode_method({"p.png": png}), tmp_path)["result"] == "negative"
    sb3 = FakeSandbox()
    three = _run({"p.png": png}, sandbox=sb3, cid="b182-b", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert sb3.calls == [] and three.verdict()["complete"] is True


def test_a_changed_file_is_a_new_method():
    a, b = _png_bytes(_cover(seed=1)), _png_bytes(_cover(seed=2))
    assert se.method_of("carve", "x.png", se._sha(a)) != se.method_of("carve", "x.png", se._sha(b))
    assert se.text_decode_method({"x.png": a}) != se.text_decode_method({"x.png": b})
    assert se.text_decode_method({"x.png": a, "y.png": b}) == se.text_decode_method({"y.png": b, "x.png": a})


def test_a_flag_marked_false_positive_in_the_ledger_counts_as_rejected(tmp_path):
    png = _png_bytes(_embed(_cover(), FLAG.encode() + b"\x00"))
    one = _run({"l.png": png}, cid="b182-c", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert one.verdict()["flags"] == [FLAG]
    m = se.method_of("lsb-planes", "l.png", se._sha(png))
    assert hyp.seen("b182-c", m, tmp_path)["result"] == "positive"
    hyp.mark_false_positive("b182-c", m, agent="operator", evidence="the platform said no", workdir=tmp_path)
    two = _run({"l.png": png}, cid="b182-c", workdir=tmp_path, ledger=True, profile=PROFILE)
    v = two.verdict()
    assert FLAG in v["rejected"] and v["flags"] == [] and FLAG in v["rejected_reached"]
    assert _by(two, "lsb-planes").state == se.REJECTED


def test_a_rejected_reading_is_filed_as_positive_then_false_positive(tmp_path):
    png = _png_bytes(_embed(_cover(), FLAG.encode() + b"\x00"))
    _run({"l.png": png}, rejected=[FLAG], cid="b182-d", workdir=tmp_path, ledger=True, profile=PROFILE)
    m = hyp.normalize_method(se.method_of("lsb-planes", "l.png", se._sha(png)))
    rows = [r for r in hyp.entries("b182-d", tmp_path) if r["method_key"] == m]
    assert [r["result"] for r in rows] == ["positive", "false_positive"] and rows[0]["payload"] == FLAG
    assert hyp.should_skip("b182-d", m, tmp_path).skip


def test_a_rejected_reading_over_a_standing_positive_adds_only_the_correction(tmp_path):
    png = _png_bytes(_embed(_cover(), FLAG.encode() + b"\x00"))
    m = se.method_of("lsb-planes", "l.png", se._sha(png))
    # another agent filed the reading as an unverified positive (a brute family): it settles nothing
    hyp.record("b182-d2", hypothesis="h", method=m, result="positive", payload=FLAG, family="lsb-brute",
               agent="other", workdir=tmp_path)
    assert not hyp.should_skip("b182-d2", m, tmp_path).skip
    rep = _run({"l.png": png}, rejected=[FLAG], cid="b182-d2", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert _by(rep, "lsb-planes").state == se.REJECTED and _by(rep, "lsb-planes").ledger is None
    rows = [r for r in hyp.entries("b182-d2", tmp_path) if r["method_key"] == hyp.normalize_method(m)]
    assert [(r["result"], r["agent"]) for r in rows] == [("positive", "other"), ("false_positive", se.ENGINE)]


def test_a_carrier_inside_a_changed_host_brings_back_what_was_found_inside_it(tmp_path):
    """The host's bytes changed (its steps run fresh) but the PNG after its end did not: that carrier's
    steps are settled, so what an earlier run found inside it comes back from the ledger."""
    inner = _png_bytes(_cover(32, 32, seed=9))
    files = {"host.jpg": _jpeg(_cover()) + inner}
    children = [n for n, i in _run(files).files.items() if i["depth"] == 1]
    assert len(children) == 1 and children[0].startswith("host.jpg" + cs.ARROW)
    child = children[0]
    for s in se.CATALOG:
        if "png" in s.kinds:
            hyp.record("b182-h", hypothesis="h", method=se.method_of(s.key, child, se._sha(inner)), result="negative",
                       agent="test", profile=PROFILE, workdir=tmp_path)
    grand = f"{child}{cs.ARROW}bit0 RGB xy msb-first"
    hyp.record("b182-h", hypothesis="h", method=se.method_of("lsb-planes", grand, "ab" * 32), result="positive",
               payload=OTHER, agent="test", profile=PROFILE, workdir=tmp_path)
    hyp.record("b182-h", hypothesis="h", method=se.text_decode_method(files), result="negative", agent="test",
               workdir=tmp_path)
    rep = _run(files, cid="b182-h", workdir=tmp_path, ledger=True, record=False, profile=PROFILE)
    assert all(o.ledger is None for o in rep.outcomes if o.file == "host.jpg")      # the host ran fresh
    back = _by(rep, "lsb-planes", grand)
    assert back.state == se.FLAG and back.flags == [OTHER] and f"found inside {child}" in back.evidence
    assert rep.files[grand]["parent"] == child
    assert rep.verdict()["flags"] == [OTHER]


def test_an_open_step_inside_a_carrier_is_reached_again_through_the_settled_host(tmp_path):
    """The decode is settled, but the ledger leaves a step of a carrier found inside the host open: the
    host's settled steps run again so the carrier is found and that step runs (and is recorded)."""
    files = {"host.jpg": _jpeg(_cover()) + _png_bytes(_cover(32, 32, seed=9))}
    one = _run(files, cid="b182-i", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert one.verdict()["complete"] is True
    child = next(n for n, i in one.files.items() if i["depth"] == 1)
    m = _by(one, "lsb-planes", child).method
    hyp.record("b182-i", hypothesis="h", method=m, result="error", agent="test", workdir=tmp_path)
    two = _run(files, cid="b182-i", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert _by(two, se.TEXT_DECODE).ledger is not None                       # the decode stayed settled
    o = _by(two, "lsb-planes", child)
    assert o.ledger is None and o.state == se.NEGATIVE and two.files[child].get("from_ledger") is None
    assert two.verdict()["complete"] is True
    assert hyp.seen("b182-i", m, tmp_path)["result"] == "negative"


def test_a_render_item_whose_every_flag_is_rejected_is_rejected():
    """B-126's checklist is judged under one rejected flag at a time: an item holding two flags, both
    rejected, is a positive under each, and must still come out REJECTED, never FLAG."""
    arr = _cover(128, 160)
    bits = np.zeros((128, 160), dtype=np.uint8)
    for y in (30, 80):
        bits[y:y + 2, 20:120] = 1
    for x in (40, 90):
        bits[20:100, x] = 1
    arr[:, :, 2] = (arr[:, :, 2] & 0xFE) | bits                        # a drawing in blue bit 0
    reads = []

    def read(png, scale=1, deadline=None):
        reads.append(scale)
        return f"{FLAG} {OTHER}"

    rep = _run({"d.png": _png_bytes(arr)}, ocr="auto", read=read, rejected=[FLAG, OTHER])
    assert reads                                                       # the plane was read
    plane = _by(rep, se.RENDER_PREFIX + rs.PROBE_PLANE)
    assert plane.state == se.REJECTED and plane.flags == [] and plane.rejected
    assert "was rejected" in plane.evidence
    v = rep.verdict()
    assert v["flags"] == [] and v["verdict"] != se.V_FLAG


def test_a_flag_found_inside_a_carrier_survives_a_second_run(tmp_path):
    inner = _png_bytes(_embed(_cover(32, 32, seed=9), OTHER.encode() + b"\x00"))
    files = {"host.jpg": _jpeg(_cover()) + inner}
    one = _run(files, cid="b182-e", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert one.verdict()["flags"] == [OTHER]
    two = _run(files, cid="b182-e", workdir=tmp_path, ledger=True, profile=PROFILE)
    v = two.verdict()
    assert v["flags"] == [OTHER] and v["verdict"] == se.V_FLAG
    child = [o for o in two.outcomes if o.file and cs.ARROW in o.file]
    assert child and all(o.ledger for o in child)
    assert any(o.step == "lsb-planes" and o.state == se.FLAG for o in child)


def test_settled_steps_are_run_again_for_their_texts_while_the_decode_is_open(tmp_path, monkeypatch):
    monkeypatch.setattr(se, "DECODE_SECONDS", 60.0)              # a budget the shared machine cannot cut
    png = _with_chunks(_png_bytes(_cover()), _chunk(b"tEXt", b"Comment\x00" + codecs.encode(FLAG, "rot13").encode()))
    ff_files = {"p.png": png}
    # an earlier run recorded every file step but its text decode did not finish (error)
    for s in se.CATALOG:
        if "png" in s.kinds:
            hyp.record("b182-f", hypothesis="h", method=se.method_of(s.key, "p.png", se._sha(png)), result="negative",
                       agent="test", workdir=tmp_path)
    hyp.record("b182-f", hypothesis="h", method=se.text_decode_method(ff_files), result="error", agent="test",
               workdir=tmp_path)
    sb = FakeSandbox()
    before = len(hyp.entries("b182-f", tmp_path))
    rep = _run(ff_files, sandbox=sb, cid="b182-f", workdir=tmp_path, ledger=True, record=False, profile=PROFILE)
    # the settled steps keep the ledger's result, but metadata-concat was run again and its rot13 text decoded
    assert all(o.ledger and o.state == se.NEGATIVE for o in rep.outcomes if o.step in se.STEP_KEYS)
    assert sb.calls == ["exiftool"]                              # exiftool too was run again, for its tags
    td = _by(rep, se.TEXT_DECODE)
    assert td.ledger is None and td.state == se.FLAG and td.flags == [FLAG]
    assert len(hyp.entries("b182-f", tmp_path)) == before        # record=False: nothing written


def test_a_settled_step_that_cannot_run_again_leaves_the_decode_not_run(tmp_path):
    jpg = _jpeg(_cover())
    files = {"c.jpg": jpg}
    one = _run(files, cid="b182-f2", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert one.verdict()["complete"] is True
    # the decode is reopened (an operator, a newer engine): the next run needs every text again
    hyp.record("b182-f2", hypothesis="h", method=se.text_decode_method(files), result="error", agent="test",
               workdir=tmp_path)
    # the store holds what the settled steps recovered: with the sandbox down they need not run again
    kept = _run(files, sandbox=_down(), cid="b182-f2", workdir=tmp_path, ledger=True, record=False, profile=PROFILE)
    assert _by(kept, se.TEXT_DECODE).state == se.NEGATIVE and kept.verdict()["complete"] is True
    # without the store (filed by another agent, or removed) the settled exiftool must run again, and cannot
    shutil.rmtree(se.store_dir("b182-f2", tmp_path))
    rep = _run(files, sandbox=_down(), cid="b182-f2", workdir=tmp_path, ledger=True, profile=PROFILE)
    ex = _by(rep, "exiftool")
    assert ex.state == se.NEGATIVE and ex.ledger                  # the settled result stands: not NOT RUN
    td = _by(rep, se.TEXT_DECODE)
    assert td.state == se.NOT_RUN and "could not be run again" in td.evidence
    assert "c.jpg stegseek-seed: sandbox down" in td.evidence and "--no-ledger" not in td.evidence
    assert rep.verdict()["complete"] is False
    assert hyp.seen("b182-f2", se.text_decode_method(files), tmp_path)["result"] == "error"
    assert hyp.seen("b182-f2", se.method_of("exiftool", "c.jpg", se._sha(jpg)), tmp_path)["result"] == "negative"


def test_a_settled_step_run_again_and_cut_leaves_the_decode_not_ruled_out(tmp_path, monkeypatch):
    png = _png_bytes(_cover())
    files = {"p.png": png}
    for s in se.CATALOG:
        if "png" in s.kinds:
            hyp.record("b182-f4", hypothesis="h", method=se.method_of(s.key, "p.png", se._sha(png)), result="negative",
                       agent="test", workdir=tmp_path)
    hyp.record("b182-f4", hypothesis="h", method=se.text_decode_method(files), result="error", agent="test",
               workdir=tmp_path)

    def cut_scan(px, bits=(0, 1), deadline=None, skipped=None):
        # a reading too long to be a text for the decoder (so the decode itself finds nothing), then the clock
        skipped.append("lsb: out of time")
        long = "x" * 20000 + FLAG
        return [{"method": "bit0 RGB xy msb-first", "what": "text", "kind": None, "text": long, "data": long.encode()}]

    monkeypatch.setattr(se.cs, "lsb_scan", cut_scan)
    rep = _run(files, cid="b182-f4", workdir=tmp_path, ledger=True, record=False, profile=PROFILE)
    assert _by(rep, "lsb-planes").state == se.NEGATIVE                      # the ledger's result stands
    td = _by(rep, se.TEXT_DECODE)
    assert td.state == se.NOT_RUN and "p.png lsb-planes: lsb: out of time" in td.evidence
    assert rep.verdict()["complete"] is False


def test_a_sandbox_down_run_then_a_sandbox_up_run_recovers_the_hidden_text(tmp_path, monkeypatch):
    """The verifier's probe: run 1 with the sandbox down files text-decode as error; the run after it
    must recover the texts of the steps run 1 settled and decode them, not leave the decode NOT RUN for
    ever; a --no-ledger run between them changes nothing."""
    monkeypatch.setattr(se, "DECODE_SECONDS", 60.0)
    png = _with_chunks(_png_bytes(_cover()), _chunk(b"tEXt", b"Comment\x00a plain remark, no flag in it"))
    files = {"r.png": png}
    one = _run(files, sandbox=_down(), cid="b182-f3", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert _by(one, se.TEXT_DECODE).state == se.NOT_RUN and one.verdict()["complete"] is False
    assert hyp.seen("b182-f3", se.method_of("metadata-concat", "r.png", se._sha(png)), tmp_path)["result"] == "negative"
    _run(files, cid="b182-f3", workdir=tmp_path, ledger=False)       # --no-ledger: reads and writes nothing
    two = _run(files, cid="b182-f3", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert _by(two, "metadata-concat").ledger is not None          # settled in run 1, not recorded again
    td = _by(two, se.TEXT_DECODE)
    assert td.state == se.NEGATIVE and td.ledger is None
    assert td.evidence.startswith("1 texts through crib_decode")    # the remark run 1 settled was decoded
    assert two.verdict()["complete"] is True
    for _ in range(2):
        sb = FakeSandbox()
        later = _run(files, sandbox=sb, cid="b182-f3", workdir=tmp_path, ledger=True, profile=PROFILE)
        assert sb.calls == [] and later.verdict()["complete"] is True and _by(later, se.TEXT_DECODE).ledger


BIG = 10.0 ** 9                     # a step clock far past time.monotonic(): carve_stego's own deadline checks
#                                     (against monotonic) never fire, only the harness's injected clock does


def _step_clock(budget):
    """(clock, deadline): one tick per clock() call, the deadline `budget` ticks after the start."""
    n = [0]

    def clock():
        n[0] += 1
        return BIG + n[0]
    return clock, BIG + budget


def _settled_steps(rep):
    return {(o.file, o.step) for o in rep.outcomes if o.ledger is not None}


@pytest.mark.parametrize("keep_store", [True, False], ids=["store-kept", "store-removed"])
def test_a_run_the_clock_cut_is_finished_by_the_next_runs_on_the_same_budget(tmp_path, keep_store):
    """The verifier's probe: a budget too short for one run. Settled steps are handed back by the store
    (no clock), or, without it, run again only after every unsettled step: so each run settles more,
    and the catalog completes. Re-running the settled steps first (in catalog order) spends the
    budget on them every run, and plane-grep (33 ticks of a 36-tick budget) never gets to finish."""
    png = _png_bytes(_cover()[..., 0])                  # grey: one channel set, 32 plane readings
    files = {"g.png": png}
    reps = []
    for _ in range(4):
        if not keep_store:
            shutil.rmtree(se.store_dir("b182-k", tmp_path), ignore_errors=True)
        clock, deadline = _step_clock(36)
        reps.append(_run(files, cid="b182-k", workdir=tmp_path, ledger=True, profile=PROFILE, deadline=deadline,
                         clock=clock))
    assert reps[0].verdict()["complete"] is False and _by(reps[0], "plane-grep").state == se.NOT_RUN
    done = next(i for i, r in enumerate(reps) if r.verdict()["complete"])
    assert done <= 2
    for a, b in zip(reps[:done], reps[1:done + 1]):
        assert _settled_steps(a) < _settled_steps(b)    # every run that was cut is followed by progress
    assert _by(reps[done], "plane-grep").state == se.NEGATIVE
    assert _by(reps[done], se.TEXT_DECODE).state == se.NEGATIVE
    assert all(r.verdict()["complete"] for r in reps[done:])


def test_with_the_sandbox_down_settled_steps_are_not_run_again_and_texts_not_decoded_again(tmp_path, monkeypatch):
    """The sandbox stays down for three runs: exiftool is NOT RUN each time, so the decode cannot settle.
    The settled steps still hand back their texts from the store (no reader runs again) and the texts
    already read with no flag are not decoded again. Once the sandbox is up, only exiftool runs and
    only its new text is decoded."""
    monkeypatch.setattr(se, "DECODE_SECONDS", 60.0)
    calls = {"lsb_scan": 0, "carve": 0, "trailing": 0, "decode": 0}

    def counting(name, fn):
        def wrapped(*a, **k):
            calls[name] += 1
            return fn(*a, **k)
        return wrapped
    for name in ("lsb_scan", "carve", "trailing"):
        monkeypatch.setattr(se.cs, name, counting(name, getattr(se.cs, name)))
    monkeypatch.setattr(se.rs, "keyless_readings", counting("decode", se.rs.keyless_readings))
    png = _with_chunks(_png_bytes(_cover()), _chunk(b"tEXt", b"Comment\x00a plain remark, no flag in it"))
    files = {"r.png": png}
    one = _run(files, sandbox=_down(), cid="b182-m", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert calls["lsb_scan"] == calls["carve"] == calls["trailing"] == 1 and calls["decode"] >= 1
    after_one = dict(calls)
    td = _by(one, se.TEXT_DECODE)
    assert td.state == se.NOT_RUN and "r.png exiftool" in td.evidence
    for _ in range(2):
        rep = _run(files, sandbox=_down(), cid="b182-m", workdir=tmp_path, ledger=True, profile=PROFILE)
        assert calls == after_one                       # no reader ran again, no text was decoded again
        assert _by(rep, "exiftool").state == se.NOT_RUN and _by(rep, "lsb-planes").ledger is not None
        td = _by(rep, se.TEXT_DECODE)
        assert td.state == se.NOT_RUN and "not read again" in td.evidence and "r.png exiftool" in td.evidence
        assert rep.verdict()["complete"] is False
    row = {"XMP-dc:Creator": codecs.encode(FLAG, "rot13")}
    sb = FakeSandbox(exif=lambda d: st.Rec(ok=True, data=row, note="exiftool: 1 tag", tool="exiftool"))
    up = _run(files, sandbox=sb, cid="b182-m", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert sb.calls == ["exiftool"]
    assert calls["lsb_scan"] == after_one["lsb_scan"] and calls["decode"] == after_one["decode"] + 1
    td = _by(up, se.TEXT_DECODE)
    assert td.state == se.FLAG and td.flags == [FLAG] and td.ledger is None
    assert up.verdict()["flags"] == [FLAG]


def test_a_carrier_a_settled_step_found_is_handed_back_by_the_store_and_checked(tmp_path, monkeypatch):
    inner = _png_bytes(_embed(_cover(32, 32, seed=9), OTHER.encode() + b"\x00"))
    files = {"host.jpg": _jpeg(_cover()) + inner}
    one = _run(files, cid="b182-n", workdir=tmp_path, ledger=True, profile=PROFILE)
    child = next(n for n, i in one.files.items() if i["depth"] == 1)
    store = se.store_dir("b182-n", tmp_path)
    # only the steps that hand something on are kept (plane-grep and steganalysis only judge)
    for f in ("host.jpg", child):
        kind, sha = one.files[f]["kind"], one.files[f]["sha256"]
        for s in se.CATALOG:
            if kind in s.kinds:
                kept = se._entry_path(store, se.method_of(s.key, f, sha)).is_file()
                assert kept == (s.key in se.REPLAY_STEPS), (f, s.key)

    def boom(*a, **k):
        raise AssertionError("a settled step was run again")
    monkeypatch.setattr(se.cs, "trailing", boom)
    monkeypatch.setattr(se.cs, "carve", boom)
    two = _run(files, cid="b182-n", workdir=tmp_path, ledger=True, record=False, profile=PROFILE)
    assert two.files[child]["sha256"] == se._sha(inner) and two.files[child].get("from_ledger") is None
    assert two.verdict()["flags"] == [OTHER]
    # a blob that does not match its name is never swept in place of the carrier: the ledger's record of
    # that carrier comes back instead
    (store / "blobs" / se._sha(inner)).write_bytes(_png_bytes(_cover(32, 32, seed=10)))
    three = _run(files, cid="b182-n", workdir=tmp_path, ledger=True, record=False, profile=PROFILE)
    assert three.files[child].get("from_ledger") is True and three.files[child]["sha256"] is None
    assert three.verdict()["flags"] == [OTHER]


def test_the_human_steps_of_a_settled_step_come_back_from_the_store(tmp_path):
    files = {"w.wav": _wav(_noise())}
    one = _run(files, cid="b182-o", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert one.human_steps
    two = _run(files, cid="b182-o", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert _by(two, "wav-named-tools").ledger is not None
    assert two.human_steps == one.human_steps


def test_a_step_cut_after_reaching_a_flag_is_not_kept_in_the_store(tmp_path, monkeypatch):
    """A flag settles a step even when the clock cut it; what it handed on is then only part of what
    it would have, so the store does not keep it (a later run that needs it runs the step again)."""
    def cut_scan(px, bits=(0, 1), deadline=None, skipped=None):
        skipped.append("lsb: out of time")
        return [{"method": "bit0 RGB xy msb-first", "what": "text", "kind": None, "text": FLAG, "data": FLAG.encode()}]
    monkeypatch.setattr(se.cs, "lsb_scan", cut_scan)
    png = _png_bytes(_cover())
    rep = _run({"p.png": png}, cid="b182-p", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert _by(rep, "lsb-planes").state == se.FLAG
    store, sha = se.store_dir("b182-p", tmp_path), se._sha(png)
    assert not se._entry_path(store, se.method_of("lsb-planes", "p.png", sha)).exists()
    assert se._entry_path(store, se.method_of("trailing", "p.png", sha)).is_file()


def test_a_text_that_decoded_to_a_flag_is_decoded_again_when_the_decode_is_reopened(tmp_path, monkeypatch):
    monkeypatch.setattr(se, "DECODE_SECONDS", 60.0)
    png = _with_chunks(_png_bytes(_cover()), _chunk(b"tEXt", b"Comment\x00" + codecs.encode(FLAG, "rot13").encode()))
    files = {"r.png": png}
    one = _run(files, cid="b182-q", workdir=tmp_path, ledger=True, profile=PROFILE)
    assert _by(one, se.TEXT_DECODE).flags == [FLAG]
    hyp.record("b182-q", hypothesis="h", method=se.text_decode_method(files), result="error", agent="test",
               workdir=tmp_path)
    two = _run(files, cid="b182-q", workdir=tmp_path, ledger=True, profile=PROFILE)
    td = _by(two, se.TEXT_DECODE)
    assert td.ledger is None and td.state == se.FLAG and td.flags == [FLAG]   # only a text with no flag is remembered


def test_a_store_entry_is_used_only_for_its_own_method_and_schema(tmp_path):
    png = _png_bytes(_cover())
    _run({"p.png": png}, cid="b182-r", workdir=tmp_path, ledger=True, profile=PROFILE)
    store, method = se.store_dir("b182-r", tmp_path), se.method_of("metadata-concat", "p.png", se._sha(png))

    def restored():
        run = se._Run(FF, deadline=None, rejected=(), sandbox=FakeSandbox(), clock=lambda: 0.0)
        run.store = store
        return se._restore(run, method, "p.png", 0)
    assert restored() is True
    p = se._entry_path(store, method)
    row = json.loads(p.read_text())
    p.write_text(json.dumps({**row, "schema": se.STORE_SCHEMA + 1}))
    assert restored() is False
    p.write_text(json.dumps({**row, "method": "toolkits.stego_exhaust carve p.png@000000000000"}))
    assert restored() is False
    p.write_text("{not json")
    assert restored() is False


def test_the_decode_memory_is_kept_per_flag_format():
    other = flagfmt.for_profile(event.load("huntress"))
    assert se.decode_key(FF, "some text") == se.decode_key(FF, "some text")
    assert se.decode_key(FF, "some text") != se.decode_key(FF, "other text")
    assert se.decode_key(FF, "some text") != se.decode_key(other, "some text")


def test_ledger_needs_a_challenge_id():
    with pytest.raises(ValueError, match="challenge id"):
        se.exhaust({}, FF, ledger=True)


# ---- the engine contract and the CLI -----------------------------------------------------------------

def _challenge(tmp_path, name, data, cid=None):
    d = tmp_path / "chal"
    (d / "files").mkdir(parents=True)
    (d / "files" / name).write_bytes(data)
    if cid:
        (d / "challenge.json").write_text(json.dumps({"id": cid}), encoding="utf-8")
    return d


def test_solve_writes_the_verdict_and_reports_the_flag(tmp_path):
    d = _challenge(tmp_path, "l.png", _png_bytes(_embed(_cover(), FLAG.encode() + b"\x00")))
    res = se.solve(d, PROFILE, sandbox="off", ocr="off", ledger="off", seconds=LONG)
    assert res.status == "solved" and list(res.flags) == [FLAG] and res.engine == se.ENGINE
    out = d / "recon" / "stego_exhaust"
    v = json.loads((out / "verdict.json").read_text(encoding="utf-8"))
    assert v["verdict"] == "flag" and v["flags"] == [FLAG]
    assert (out / "verdict.txt").read_text(encoding="utf-8").startswith("stego_exhaust verdict: FLAG")


def test_solve_with_the_sandbox_off_is_unsure_and_names_the_steps(tmp_path):
    d = _challenge(tmp_path, "c.png", _png_bytes(_cover()))
    res = se.solve(d, PROFILE, sandbox="off", ocr="off", ledger="off", seconds=LONG)
    assert res.status == "unsure" and list(res.flags) == []
    assert "not run:" in res.notes and "exiftool" in res.notes and "sandbox steps are off" in res.notes


def test_solve_refuses_a_bad_option_by_name(tmp_path):
    d = _challenge(tmp_path, "c.png", _png_bytes(_cover()))
    res = se.solve(d, PROFILE, sandbox="maybe", ledger="off")
    assert res.status == "blocked" and "sandbox must be" in res.notes
    res = se.solve(d, PROFILE, ledger="on", sandbox="off")
    assert res.status == "blocked" and "challenge id" in res.notes


def test_solve_uses_the_ledger_of_challenge_json(tmp_path):
    d = _challenge(tmp_path, "c.png", _png_bytes(_cover()), cid="b182-g")
    wd = tmp_path / "wd"
    se.solve(d, PROFILE, sandbox="off", ocr="off", workdir=str(wd), seconds=LONG)
    assert hyp.entries("b182-g", wd)
    assert all(r["agent"] == se.ENGINE for r in hyp.entries("b182-g", wd))


def _cli(argv):
    from ctf.cli import stego_exhaust as cli
    p = argparse.ArgumentParser()
    cli.add_arguments(p)
    return cli.run(p.parse_args(argv))


def test_cli_prints_the_verdict_and_writes_it(tmp_path, capsys):
    d = _challenge(tmp_path, "c.png", _png_bytes(_cover()))
    assert _cli([str(d), "--event", "csctf", "--no-sandbox", "--no-ledger", "--ocr", "off",
                 "--seconds", str(LONG)]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("stego_exhaust verdict: NOTHING FURTHER from the")
    assert "exiftool" in out and (d / "recon" / "stego_exhaust" / "verdict.json").is_file()
    assert _cli([str(d), "--event", "csctf", "--no-sandbox", "--no-ledger", "--ocr", "off", "--json",
                 "--rejected", FLAG, "--seconds", str(LONG)]) == 0
    v = json.loads(capsys.readouterr().out)
    assert v["rejected"] == [FLAG] and v["complete"] is False


def test_cli_missing_folder_exits_2(tmp_path, capsys):
    assert _cli([str(tmp_path / "nope"), "--event", "csctf"]) == 2
    assert "no such challenge folder" in capsys.readouterr().err


def test_the_command_is_discovered():
    from ctf import cli
    got = {name: (mod, err) for name, mod, err in cli.discover()}
    assert "stego-exhaust" in got and got["stego-exhaust"][1] is None


# ---- stego_tools: stegseek --seed and no_start -------------------------------------------------------

class _FakeSandboxModule(types.ModuleType):
    def __init__(self, result=None, down=None):
        super().__init__("sandbox")
        self.calls = []
        self.result, self.down = result, down

        class SandboxDown(RuntimeError):
            pass

        class Lit(str):
            pass

        self.SandboxDown, self.Lit = SandboxDown, Lit

    def run(self, tool, args, inputs=(), timeout=60, start=True):
        self.calls.append({"tool": tool, "args": list(args), "start": start})
        if self.down:
            raise self.SandboxDown(self.down)
        return self.result


def _result(stdout="", stderr="", code=0, files=None):
    return types.SimpleNamespace(code=code, stdout=stdout.encode(), stderr=stderr.encode(), files=files or {},
                                 note="", timed_out=code == 124)


def _fake(monkeypatch, **kw):
    mod = _FakeSandboxModule(**kw)
    monkeypatch.setattr(st, "_sandbox", lambda: mod)
    monkeypatch.setattr(st, "on_timed_path", lambda: False)
    return mod


def test_stegseek_seed_found_and_extracted(monkeypatch):
    out = ('StegSeek 0.6\n\n[i] Found (possible) seed: "1A2B3C4D"\n\tPlain size: 26.0 Byte(s)\n'
           '\tEncryption Algorithm: none\n[i] Original filename: "f.txt".\n[i] Extracting to "payload".\n')
    mod = _fake(monkeypatch, result=_result(stdout=out, files={"payload": FLAG.encode()}))
    r = st.stegseek_seed(_jpeg(_cover()))
    assert r.ok and r.data == {"seed": "1a2b3c4d", "size": "26.0 Byte(s)", "algorithm": "none", "name": "f.txt"}
    assert r.files["payload"] == FLAG.encode() and "26 bytes extracted" in r.note
    assert mod.calls[0]["tool"] == "stegseek" and "--seed" in mod.calls[0]["args"]
    assert mod.calls[0]["start"] is True                    # outside no_start a call may start the container


def test_stegseek_seed_encrypted_needs_the_passphrase(monkeypatch):
    out = ('[i] Found (possible) seed: "0badf00d"\n\tPlain size: 120.0 Byte(s) (compressed)\n'
           '\tEncryption Algorithm: rijndael-128\n\tEncryption Mode: cbc\n')
    _fake(monkeypatch, result=_result(stdout=out))
    r = st.stegseek_seed(b"BM" + b"\x00" * 64)
    assert r.ok and r.data["seed"] == "0badf00d" and r.data["algorithm"] == "rijndael-128"
    assert r.files == {} and "needs the passphrase" in r.note


def test_stegseek_seed_no_seed_and_output_not_understood(monkeypatch):
    _fake(monkeypatch, result=_result(stderr="[!] error: Could not find a valid seed.\n", code=1))
    r = st.stegseek_seed(_jpeg(_cover()))
    assert r.ok and r.data is None and r.note == "stegseek --seed: no steghide seed in this cover"
    _fake(monkeypatch, result=_result(stderr="something else went wrong\n", code=1))
    r = st.stegseek_seed(_jpeg(_cover()))
    assert not r.ok and r.data is None and "output not understood" in r.note and "something else" in r.note


def test_stegseek_seed_killed_is_not_read(monkeypatch):
    _fake(monkeypatch, result=_result(stdout='[i] Found (possible) seed: "1a2b3c4d"\n', code=137))
    r = st.stegseek_seed(_jpeg(_cover()))
    assert not r.ok and r.data is None and r.note.endswith(": not read")


def test_no_start_passes_start_false_and_restores(monkeypatch):
    mod = _fake(monkeypatch, down="not started; run tools/sandbox.py start first")
    with st.no_start():
        r = st.exif(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
        with st.no_start():
            pass
        st.stegseek_seed(_jpeg(_cover()))
    assert [c["start"] for c in mod.calls] == [False, False]
    assert not r.ok and r.note.startswith("sandbox down: not started")
    st.exif(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    assert mod.calls[-1]["start"] is True


def test_the_harness_never_starts_the_sandbox(monkeypatch):
    mod = _fake(monkeypatch, down="not started; run tools/sandbox.py start first")
    rep = se.exhaust({"s.jpg": _jpeg(_cover())}, FF, ocr="off")          # the default SandboxTools
    assert {c["tool"] for c in mod.calls} == {"stegseek", "exiftool"}
    assert all(c["start"] is False for c in mod.calls)
    nr = {x["step"]: x["evidence"] for x in rep.verdict()["not_run"]}
    assert set(nr) == {"stegseek-seed", "exiftool", se.TEXT_DECODE}
    assert "sandbox down: not started" in nr["stegseek-seed"] and "sandbox down: not started" in nr["exiftool"]


@pytest.mark.live
@pytest.mark.needs_tool("docker")
def test_stegseek_seed_reads_real_stegseek_output_in_the_sandbox():
    """The --seed parser against the real stegseek, in a stego sandbox container that is ALREADY up (it
    is never started here: no_start). Not run unless --run-live / CTF_RUN_LIVE=1. Human step: the v2
    stego sandbox image with steghide and stegseek, started (tools/sandbox.py start), then this test
    with --run-live; until then it is listed as not run, and the parser is proven only against the
    output strings the tests above wrote."""
    cover = _jpeg(_cover(256, 256, seed=11))
    with st.no_start():
        clean = st.stegseek_seed(cover)
        if clean.note.startswith("sandbox down"):
            pytest.skip(f"not run: the stego sandbox is not up ({clean.note})")
        assert clean.ok, clean.note
        assert clean.data is None and clean.note == "stegseek --seed: no steghide seed in this cover"
        emb = st.call("steghide", ["embed", "-cf", "{in0}", "-ef", "{in1}", "-sf", "{out}/stego.jpg", "-p", st._lit(""),
                                   "-e", "none", "-f", "-q"], [("cover.jpg", cover), ("secret.txt", FLAG.encode())])
        assert emb.ok and "stego.jpg" in emb.files, emb.note
        got = st.stegseek_seed(emb.files["stego.jpg"])
    assert got.ok, got.note
    assert got.data["seed"] and got.data["algorithm"] == "none" and got.data["name"] == "secret.txt"
    assert got.files["payload"] == FLAG.encode()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
