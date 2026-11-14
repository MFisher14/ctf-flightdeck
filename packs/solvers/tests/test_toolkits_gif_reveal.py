"""B-117: the timed-reveal GIF reader (solvers/toolkits/gif_reveal.py).

Every animation is drawn here with Pillow or assembled from bytes. The OCR step is driven by a
stand-in reader that tells the synthetic frames apart by a bar in their top row, so the order,
budget and status rules are tested without tesseract; one test at the end reads a rendered frame
with the real tesseract and reports as not run where it is absent."""
from __future__ import annotations

import gc
import io
import json
import struct
import time
import weakref

import pytest

import b117_fixtures as fx
import gif_reveal as gr
import image_carve
from ctf import flagfmt

pytestmark = pytest.mark.needs_tool("py:PIL")

PROFILE = fx.profile()
# Every engine call below gets an explicit budget: the production defaults are wall-clock seconds,
# and this suite runs on a machine loaded far past its cores.
BUDGET = 3600.0
FF = flagfmt.for_profile(PROFILE)
FLAG = "CSCTF{read_off_the_last_frame}"


def reader(texts, seen=None):
    """A stand-in OCR: the text for a bar frame is texts[bar width - 1]; a picture whose top row
    does not start dark at x = 0 (a diff, the lightest overlay) reads as texts.get("other")."""
    def read(png, deadline=None):
        first, count = fx.bar_of(png)
        key = count - 1 if first == 0 else "other"
        if seen is not None:
            seen.append(key)
        return texts.get(key, "")
    return read


def no_codes(data, **kw):
    return []


def animation(n=4, durations=100, **kw):
    return fx.gif_bytes([fx.bar_frame(k) for k in range(n)], durations=durations, **kw)


# ---- structure -------------------------------------------------------------------------------------

def test_blocks_of_a_hand_built_file():
    def sub(*parts):
        return b"".join(bytes([len(p)]) + p for p in parts) + b"\x00"

    data = (b"GIF89a" + struct.pack("<HHBBB", 4, 3, 0x80, 0, 0) + bytes(6)             # 2-colour global table
            + b"\x21\xff" + sub(b"NETSCAPE2.0", b"\x01\x03\x00")
            + b"\x21\xfe" + sub(b"hello, ", b"world")
            + b"\x21\xf9" + sub(struct.pack("<BHB", (2 << 2) | 1, 25, 7))
            + b"\x2c" + struct.pack("<HHHHB", 1, 2, 2, 1, 0x80) + bytes(6) + b"\x02" + sub(b"\x4c\x01")
            + b"\x21\x01" + sub(b"plain text ext")
            + b"\x2c" + struct.pack("<HHHHB", 0, 0, 4, 3, 0) + b"\x02" + sub(b"\x4c\x01")
            + b"\x3b" + b"TAIL!")
    got = gr.blocks(data)
    assert got["size"] == (4, 3) and got["loop"] == 3 and got["apps"] == ["NETSCAPE2.0"]
    assert got["comments"] == ["hello, world"] and got["trailing"] == 5 and got["truncated"] is False
    assert got["frames"] == [
        {"index": 0, "delay_ms": 250, "disposal": 2, "transparent": 7, "left": 1, "top": 2, "width": 2, "height": 1},
        {"index": 1, "delay_ms": 0, "disposal": 0, "transparent": None, "left": 0, "top": 0, "width": 4, "height": 3}]
    cut = gr.blocks(data[:-8])                                      # ends inside the second image
    assert cut["truncated"] is True and len(cut["frames"]) == 1 and cut["trailing"] == 0
    no_table = b"GIF87a" + struct.pack("<HHBBB", 1, 1, 0, 0, 0) + b"\x3b"
    assert gr.blocks(no_table) == {"size": (1, 1), "frames": [], "comments": [], "apps": [], "loop": None,
                                   "trailing": 0, "truncated": False}
    for bad in (b"GIF88a" + bytes(20), b"GIF89a\x01", b"\x89PNG\r\n\x1a\n" + bytes(20)):
        with pytest.raises(gr.GifError):
            gr.blocks(bad)


def test_blocks_of_a_pillow_file():
    data = animation(3, durations=[500, 10, 20000], loop=None, comment=b"made by hand")
    got = gr.blocks(data + b"after")
    assert [f["delay_ms"] for f in got["frames"]] == [500, 10, 20000]
    assert got["loop"] is None and got["comments"] == ["made by hand"] and got["trailing"] == 5
    assert gr.blocks(animation(2, loop=0))["loop"] == 0 and gr.blocks(animation(2, loop=5))["loop"] == 5


def test_suspects():
    def named(*delays):
        return gr.suspects([{"delay_ms": d} for d in delays])

    assert named(500, 10, 500) == [(1, "brief: shown 10 ms, the median frame 500 ms")]
    assert named(20, 20, 20, 20) == []                              # a fast animation, not a hidden frame
    assert named(0, 0, 0) == [] and named(40) == [] and named() == []
    assert [k for k, _w in named(40, 160)] == [0] and named(40, 159) == []      # under four times: no
    assert named(49, 196)[0][0] == 0 and named(50, 400) == []       # 50 ms is not brief
    assert named(0, 50)[0][0] == 0 and named(0, 49) == []           # the long one must itself be visible
    assert named(100, 10000, 100) == [(2, "held back: it follows a frame held 10 s")]
    assert named(100, 9990, 100) == []
    assert named(12500, 100)[0] == (1, "held back: it follows a frame held 12.5 s")
    assert named(10000, 10, 10000) == [(1, "brief: shown 10 ms, the median frame 10000 ms")]   # one reason a frame


# ---- frames ----------------------------------------------------------------------------------------

def test_frames_are_composited_counted_and_capped(monkeypatch):
    data = animation(5)
    got, total = gr.frames(data)
    assert total == 5 and len(got) == 5 and all(f.mode == "RGB" and f.size == (48, 24) for f in got)
    for k, frame in enumerate(got):
        assert fx.bar_of(gr._png(frame)) == (0, k + 1)
    few, total = gr.frames(data, max_frames=2)
    assert total == 5 and len(few) == 2
    with pytest.raises(gr.GifError, match="cannot open"):
        gr.frames(b"GIF89a" + bytes(40))
    # a Reel hands the same frames on one at a time and counts them
    reel = gr.Reel(data)
    assert (reel.total, reel.limit, reel.read, reel.cut, reel.size) == (5, 5, 0, "", (48, 24))
    assert [(k, fx.bar_of(gr._png(frame))) for k, frame in reel] == [(k, (0, k + 1)) for k in range(5)]
    assert reel.read == 5 and gr.Reel(data, max_frames=2).limit == 2
    late = gr.Reel(data, deadline=time.monotonic() - 1)
    assert list(late) == [] and (late.read, late.cut) == (0, "out of time before frame 0")
    # how many frames are read: 64, fewer when they would hold more than 32 megapixels between them
    assert gr.frame_cap(48, 24) == gr.frame_cap(800, 600) == gr.MAX_FRAMES == 64
    assert gr.frame_cap(1024, 768) == 40 and gr.frame_cap(2000, 2000) == 8 and gr.frame_cap(0, 0) == 64
    monkeypatch.setattr(gr, "MAX_TOTAL_PIXELS", 48 * 24 * 3 + 5)
    assert gr.frame_cap(48, 24) == 3 and gr.Reel(data).limit == 3 and len(gr.frames(data)[0]) == 3
    monkeypatch.setattr(gr, "MAX_TOTAL_PIXELS", 10)
    assert gr.frame_cap(48, 24) == 1                                 # one frame is always read
    monkeypatch.setattr(gr, "MAX_PIXELS", 48 * 24 - 1)
    with pytest.raises(gr.GifError, match="pixel cap"):
        gr.frames(data)


def test_transparent_frames_land_on_white():
    from PIL import Image
    base = Image.new("RGBA", (8, 8), (0, 0, 0, 0))
    base.putpixel((1, 1), (0, 0, 0, 255))
    second = base.copy()
    second.putpixel((5, 5), (0, 0, 0, 255))
    out = io.BytesIO()
    base.save(out, format="GIF", save_all=True, append_images=[second], duration=100, disposal=1, transparency=0)
    got, _total = gr.frames(out.getvalue())
    assert got[0].getpixel((0, 0)) == (255, 255, 255) and got[0].getpixel((1, 1)) == (0, 0, 0)
    assert got[1].getpixel((5, 5)) == (0, 0, 0) and got[1].getpixel((6, 6)) == (255, 255, 255)


def _gray(pixels, size=(4, 1)):
    from PIL import Image
    image = Image.new("L", size, 255)
    for x, value in enumerate(pixels):
        image.putpixel((x, 0), value)
    return image.convert("RGB")


def test_reveal_gives_distinct_frames_diffs_and_overlays():
    a, b, c = _gray([0, 255, 255, 255]), _gray([0, 0, 255, 255]), _gray([0, 0, 255, 200])
    got = list(gr.reveal(enumerate([a, b, a, c, b])))
    assert [label for label, _image in got if label.startswith("frame ")] == ["frame 0", "frame 1", "frame 3"]
    steps = [(label, image) for label, image in gr.reveal(enumerate([a, b, b, a, b, c])) if label.startswith("diff ")]
    # b->b changes nothing; a->b repeats; b->a changes the same pixel as a->b, so it is the same picture
    assert [label for label, _image in steps] == ["diff 0->1", "diff 4->5"]
    assert [steps[0][1].getpixel((x, 0)) for x in range(4)] == [255, 0, 255, 255]
    assert [steps[1][1].getpixel((x, 0)) for x in range(4)] == [255, 255, 255, 0]     # 255 -> 200: 55 levels
    # a change of exactly the threshold is not a change; one level more is
    assert [label for label, _i in gr.reveal(enumerate([_gray([100]), _gray([100 + gr.DIFF_THRESHOLD])]))] == [
        "frame 0", "frame 1", "overlay darkest", "overlay lightest"]
    assert [label for label, _i in gr.reveal(enumerate([_gray([100]), _gray([101 + gr.DIFF_THRESHOLD])]))] == [
        "frame 0", "frame 1", "diff 0->1", "overlay darkest", "overlay lightest"]
    both = dict(gr.reveal(enumerate([_gray([0, 255, 90, 255]), _gray([255, 255, 30, 10]), _gray([255, 0, 200, 255])])))
    assert [both["overlay darkest"].getpixel((x, 0)) for x in range(4)] == [0, 0, 30, 10]
    assert [both["overlay lightest"].getpixel((x, 0)) for x in range(4)] == [255, 255, 200, 255]
    # one frame, or one frame repeated, has nothing to overlay; no frame at all gives nothing
    assert [label for label, _i in gr.reveal(enumerate([a, a, a]))] == ["frame 0"]
    assert list(gr.reveal(iter(()))) == []
    # the index a diff is named by is the frame's own, not its place in what was handed over
    assert [label for label, _i in gr.reveal([(3, a), (7, b)])] == ["frame 3", "frame 7", "diff 3->7",
                                                                    "overlay darkest", "overlay lightest"]


def test_reveal_order_and_the_order_the_ocr_reads_in():
    labels = [label for label, _image in gr.reveal(gr.Reel(animation(4)))]
    # made in one pass: each frame, then how it differs from the one before; the overlays last
    assert labels == ["frame 0", "frame 1", "diff 0->1", "frame 2", "diff 1->2", "frame 3", "diff 2->3",
                      "overlay darkest", "overlay lightest"]
    # read: the frames a viewer would not see first, then the other frames, the diffs, the overlays
    assert gr.read_order(labels, [(2, "brief"), (9, "past the cap")]) == [
        "frame 2", "frame 0", "frame 1", "frame 3", "diff 0->1", "diff 1->2", "diff 2->3",
        "overlay darkest", "overlay lightest"]
    assert gr.read_order(labels, [(3, "held back"), (1, "brief")])[:4] == ["frame 3", "frame 1", "frame 0", "frame 2"]
    assert gr.read_order(["frame 0"], []) == ["frame 0"] and gr.read_order([], [(0, "brief")]) == []


def test_identifiers():
    text = "UNIT BAY-41 dark. see KX 58, TRN_26 and BAY41; not Bay-9, A-1, ABCDEFG-1, BAY-12345 or XBAY-41Z"
    assert gr.identifiers(text) == ["BAY-41", "KX 58", "TRN_26", "BAY41"]
    assert gr.identifiers("BAY-41 BAY-41") == ["BAY-41"] and gr.identifiers("") == [] and gr.identifiers(None) == []


# ---- the engine ------------------------------------------------------------------------------------

def test_ocr_flags_are_candidates_and_identifiers_are_kept(tmp_path):
    data = animation(4, durations=[500, 10, 500, 500])
    seen = []
    texts = {0: "static", 1: f"sign says {FLAG}", 2: "next unit: KX-58 then BAY 63", 3: ""}
    rep = gr.examine({"feed.gif": data}, FF, read=reader(texts, seen), codes=no_codes, out_dir=tmp_path)
    anim = rep.animations[0]
    assert (anim.total, anim.read, anim.suspects[0][0]) == (4, 4, 1)
    # the brief frame is read first, then the rest in order, the diffs, the overlays
    assert seen == [1, 0, 2, 3, "other", "other", "other", 3, 0]
    assert [(r.source, r.flags, r.identifiers) for r in anim.readings] == [
        ("frame 1", [FLAG], []), ("frame 0", [], []), ("frame 2", [], ["KX-58", "BAY 63"]),
        ("overlay lightest", [], [])]
    assert anim.ocr_flags == [FLAG] and anim.identifiers == ["KX-58", "BAY 63"] and rep.ocr == "run"
    res = gr.result_of(rep, root=tmp_path)
    assert res.status == "candidate" and res.flags == (FLAG,)        # OCR alone is never solved
    assert [e.detail for e in res.evidence if e.kind == "ocr"] == ["OCR of frame 1"]
    assert "frame 1 is brief: shown 10 ms" in res.notes and "identifiers read by OCR: KX-58, BAY 63" in res.notes
    assert "4 frames 48x24, delays 10, 500 ms, loops forever" in res.notes
    names = sorted(p.name for p in rep.written)
    assert names == sorted(f"feed.gif.{part}.png" for part in
                           ("frame0", "frame1", "frame2", "frame3", "diff0-1", "diff1-2", "diff2-3",
                            "overlaydarkest", "overlaylightest"))
    assert fx.bar_of((tmp_path / "feed.gif.frame2.png").read_bytes()) == (0, 3)
    assert fx.bar_of((tmp_path / "feed.gif.diff1-2.png").read_bytes()) == (2, 1)      # only the new column


def test_flags_in_bytes_and_codes_are_proven(tmp_path):
    commented = animation(2, comment=b"note to self: CSCTF{in_a_comment_block}") + b"\x00CSCTF{after_the_trailer}"
    rep = gr.examine({"c.gif": commented}, FF, read=reader({}), codes=no_codes)
    assert rep.animations[0].proven == [("CSCTF{in_a_comment_block}", "carve", "comment block 0"),
                                        ("CSCTF{after_the_trailer}", "carve", "25 bytes after the trailer")]
    res = gr.result_of(rep)
    assert res.status == "candidate" and len(res.flags) == 2 and "25 bytes after the trailer" in res.notes

    one = gr.result_of(gr.examine({"c.gif": animation(2, comment=b"CSCTF{only_one}")}, FF, read=reader({}),
                                  codes=no_codes))
    assert one.status == "solved" and one.flags == ("CSCTF{only_one}",) and one.evidence[0].kind == "carve"

    def codes(data, **kw):
        assert kw["planes"] is False and kw["max_frames"] == gr.MAX_FRAMES
        return [{"format": "qr_code", "text": "CSCTF{in_a_code}", "bytes": b"", "how": "frame 1"},
                {"format": "qr_code", "text": "go to /decks/bilge/", "bytes": b"", "how": "frame 0"}]

    coded = gr.result_of(gr.examine({"q.gif": animation(2)}, FF, read=reader({0: "CSCTF{in_a_code}"}), codes=codes))
    assert coded.status == "solved" and coded.flags == ("CSCTF{in_a_code}",)
    assert coded.evidence[0].kind == "decode" and coded.evidence[0].detail == "flag in qr_code in frame 1"
    assert not [e for e in coded.evidence if e.kind == "ocr"]        # the OCR reading of the same flag adds nothing
    assert "qr_code in frame 0 reads 'go to /decks/bilge/'" in coded.notes
    # a proven flag and a different OCR reading: the OCR one keeps it from being solved
    mixed = gr.result_of(gr.examine({"q.gif": animation(2, comment=b"CSCTF{proven}")}, FF,
                                    read=reader({1: "CSCTF{misread}"}), codes=no_codes))
    assert mixed.status == "candidate" and mixed.flags == ("CSCTF{proven}", "CSCTF{misread}")


@pytest.mark.needs_tool("py:qrcode", "py:zxingcpp")
def test_code_in_a_brief_frame_is_read_by_the_real_decoder():
    from PIL import Image
    code = Image.open(io.BytesIO(fx.matrix_png(fx.qr_modules("CSCTF{flashed_qr}", 2), scale=4)))
    blank = Image.new("L", code.size, 255)
    dot = blank.copy()
    dot.putpixel((3, 3), 0)
    data = fx.gif_bytes([blank, code, dot], durations=[1000, 10, 1000])
    res = gr.result_of(gr.examine({"flash.gif": data}, FF, ocr="off"))
    assert res.status == "solved" and res.flags == ("CSCTF{flashed_qr}",)
    detail = res.evidence[0].detail                                  # the format name is the decoder's
    assert detail.startswith("flag in qr") and detail.endswith(" in frame 1") and res.evidence[0].kind == "decode"
    assert "OCR off" in res.notes


def test_animation_without_a_flag_is_unsure_and_a_still_is_none(tmp_path):
    rep = gr.examine({"plain.gif": animation(3)}, FF, read=reader({}), codes=no_codes, out_dir=tmp_path)
    res = gr.result_of(rep, root=tmp_path)
    assert res.status == "unsure" and res.flags == () and len(rep.written) == 7
    assert all(e.detail == "written" for e in res.evidence)
    seen = []
    still = gr.examine({"still.gif": animation(1), "note.txt": b"GIF but not really", "pic.png": b"\x89PNG"}, FF,
                       read=reader({0: FLAG}, seen), codes=no_codes, out_dir=tmp_path / "still")
    assert [a.file for a in still.animations] == ["still.gif"] and still.written == [] and seen == []
    assert not (tmp_path / "still").exists()
    assert gr.result_of(still).status == "none"
    broken = gr.examine({"bad.gif": b"GIF89a" + bytes(30)}, FF, read=reader({}), codes=no_codes)
    assert broken.animations == [] and broken.skipped[0].startswith("bad.gif: not read: cannot open")
    assert gr.result_of(broken).status == "none"


def test_ocr_off_missing_and_on(tmp_path, monkeypatch):
    data = animation(3)
    off = gr.examine({"a.gif": data}, FF, ocr="off", read=lambda *a, **k: pytest.fail("OCR ran"), codes=no_codes)
    assert off.ocr == "off" and off.animations[0].readings == []
    assert "OCR off" in gr.result_of(off).notes

    calls = []

    def absent(png, deadline=None):
        calls.append(1)
        raise image_carve.ToolMissing("tesseract is not on PATH")

    auto = gr.examine({"a.gif": data, "b.gif": animation(2)}, FF, read=absent, codes=no_codes, out_dir=tmp_path)
    assert len(calls) == 1                                           # asked once, not once a frame or a file
    assert auto.ocr == "not run: tesseract is not on PATH; the frames are written for a human or model read"
    assert len(auto.written) == 7 + 5                                # both files' frames are still written
    res = gr.result_of(auto)
    assert res.status == "unsure" and "OCR not run: tesseract is not on PATH" in res.notes
    with pytest.raises(gr.ToolMissing, match="tesseract is not on PATH"):
        gr.examine({"a.gif": data}, FF, ocr="on", read=absent, codes=no_codes)
    with pytest.raises(ValueError):
        gr.examine({}, FF, ocr="maybe")

    (tmp_path / "ch" / "files").mkdir(parents=True)
    (tmp_path / "ch" / "files" / "a.gif").write_bytes(data)
    monkeypatch.setattr(image_carve, "ocr_text", absent)
    blocked = gr.solve(tmp_path / "ch", PROFILE, seconds=BUDGET, ocr="on")
    assert blocked.status == "blocked" and "tesseract is not on PATH" in blocked.notes
    assert gr.solve(tmp_path / "ch", PROFILE, seconds=BUDGET).status == "unsure"     # auto: named, not blocked


def test_deadline_and_frame_cap_are_named(monkeypatch, tmp_path):
    seen = []
    rep = gr.examine({"a.gif": animation(4)}, FF, read=reader({}, seen), codes=no_codes,
                     deadline=time.monotonic() - 1)
    # out of time before the first frame: nothing is composited, and that is said
    assert seen == [] and rep.skipped == ["a.gif: out of time before frame 0: 4 of its 4 frames were not read"]
    assert (rep.animations[0].total, rep.animations[0].read) == (4, 0)
    assert gr.result_of(rep).status == "unsure"                      # not read is not "nothing there"

    def slow(png, deadline=None):
        raise image_carve.OutOfBudget("tesseract --psm 6 stopped after 0.1 s")

    rep = gr.examine({"a.gif": animation(4)}, FF, read=slow, codes=no_codes)
    assert rep.skipped == ["a.gif: OCR out of time in frame 0: tesseract --psm 6 stopped after 0.1 s"]
    monkeypatch.setattr(gr, "MAX_FRAMES", 3)
    rep = gr.examine({"a.gif": animation(5)}, FF, read=reader({}), codes=no_codes)
    assert (rep.animations[0].total, rep.animations[0].read) == (5, 3)
    assert "a.gif: 5 frames, only the first 3 were read" in rep.skipped
    cut = animation(3)[:-1]                                           # the trailer byte is gone
    rep = gr.examine({"cut.gif": cut}, FF, read=reader({}), codes=no_codes)
    assert "cut.gif: the file ends before its trailer" in rep.skipped


def test_the_deadline_stops_the_frames_and_the_writing_not_only_the_ocr(monkeypatch, tmp_path):
    """Time is a clock this test moves: one second for every picture written. With 2.5 s, two
    frames and the diff between them are written, the third frame is never composited, the
    overlays are not written, and each of those is named."""
    class Clock:
        now = 1000.0

        def monotonic(self):
            return self.now

    clock = Clock()
    real_png = gr._png

    def png(image):
        clock.now += 1.0
        return real_png(image)

    monkeypatch.setattr(gr, "time", clock)
    monkeypatch.setattr(gr, "_png", png)
    seen = []
    rep = gr.examine({"a.gif": animation(6)}, FF, read=reader({}, seen), codes=no_codes, out_dir=tmp_path,
                     deadline=1002.5)
    assert sorted(path.name for path in rep.written) == ["a.gif.diff0-1.png", "a.gif.frame0.png", "a.gif.frame1.png"]
    assert sorted(path.name for path in tmp_path.iterdir()) == sorted(path.name for path in rep.written)
    assert (rep.animations[0].total, rep.animations[0].read) == (6, 2) and seen == []
    assert rep.skipped == ["a.gif: out of time before frame 2: 4 of its 6 frames were not read",
                           "a.gif: out of time: overlay darkest, overlay lightest not written",
                           "a.gif: OCR out of time before frame 0; it is written for a human or model read"]
    res = gr.result_of(rep, root=tmp_path)
    assert res.status == "unsure" and "a.gif: 6 frames 48x24" in res.notes


def _wide_gif(frames=64, side=2000):
    """A GIF whose logical screen is side x side and whose frames are one black pixel each, built
    from bytes: about 1,500 bytes on disk for 64 frames of four megapixels once composited."""
    def sub(*parts):
        return b"".join(bytes([len(part)]) + part for part in parts) + b"\x00"

    out = b"GIF89a" + struct.pack("<HHBBB", side, side, 0x80, 0, 0) + bytes((255, 255, 255, 0, 0, 0))
    for k in range(frames):
        out += b"\x21\xf9" + sub(struct.pack("<BHB", 1 << 2, 10, 0))               # keep each frame, 100 ms
        out += b"\x2c" + struct.pack("<HHHHB", k, 0, 1, 1, 0) + b"\x02" + sub(b"\x4c\x01")
    return out + b"\x3b"


def test_pixels_over_all_frames_are_capped_and_named(tmp_path):
    """The shape that took 1.4 GB at intake: 64 frames x 4 megapixels in a file of 1.5 kB. Counted,
    not timed: 8 frames are read (32 megapixels between them), 17 pictures are written, not 129,
    and the code reader is given the same bound."""
    data = _wide_gif()
    assert len(data) < 1600 and gr.blocks(data)["size"] == (2000, 2000) and len(gr.blocks(data)["frames"]) == 64
    asked = []

    def codes(data, **kw):
        asked.append(kw["max_frames"])
        return []

    rep = gr.examine({"wide.gif": data}, FF, ocr="off", codes=codes, out_dir=tmp_path)
    anim = rep.animations[0]
    assert (anim.total, anim.read) == (64, 8) and asked == [8]
    assert 8 * 2000 * 2000 <= gr.MAX_TOTAL_PIXELS < 9 * 2000 * 2000
    assert len(rep.written) == 8 + 7 + 2 == len(list(tmp_path.iterdir()))
    assert rep.skipped == ["wide.gif: 64 frames, only the first 8 were read: the cap of 32000000 pixels over all "
                           "the frames of one GIF"]
    assert "wide.gif: 64 frames 2000x2000" in gr.result_of(rep).notes


def test_one_frame_is_held_at_a_time(monkeypatch, tmp_path):
    """The engine composites, writes and lets go: when a frame is built, at most the one before it
    is still alive, however many came earlier. (Holding every frame cost 12 MB each.)"""
    alive = []
    real_iter = gr.Reel.__iter__

    def watched(self):
        refs = []
        for k, frame in real_iter(self):
            gc.collect()
            alive.append(sum(1 for ref in refs if ref() is not None))
            refs.append(weakref.ref(frame))
            yield k, frame
            del frame

    monkeypatch.setattr(gr.Reel, "__iter__", watched)
    seen = []
    rep = gr.examine({"a.gif": animation(12)}, FF, read=reader({}, seen), codes=no_codes, out_dir=tmp_path)
    assert len(alive) == 12 and max(alive) <= 1, alive
    assert len(rep.written) == 12 + 11 + 2 and len(seen) == 25       # every picture was still written and read
    # with no output folder the pictures go to a temporary one for the OCR, which is removed
    made = []
    real_tmp = gr.tempfile.TemporaryDirectory

    def spool(*args, **kw):
        made.append(real_tmp(*args, **kw))
        return made[-1]

    monkeypatch.setattr(gr.tempfile, "TemporaryDirectory", spool)
    seen.clear()
    del alive[:]
    rep = gr.examine({"a.gif": animation(12)}, FF, read=reader({}, seen), codes=no_codes)
    assert len(seen) == 25 and rep.written == [] and max(alive) <= 1
    assert len(made) == 1 and not gr.Path(made[0].name).exists()
    # ... and with no OCR either, nobody would look at the frames: they are not composited at all
    del alive[:], made[:]
    rep = gr.examine({"a.gif": animation(12)}, FF, ocr="off", codes=no_codes)
    assert alive == [] and made == [] and (rep.animations[0].total, rep.animations[0].read) == (12, 0)
    assert gr.result_of(rep).status == "unsure" and rep.ocr == "off"


def test_a_file_cut_inside_its_second_frame_is_a_still(tmp_path, monkeypatch):
    """Pillow counts the frame the file starts; reading it fails. One readable frame is a still:
    nothing is left written for it."""
    seen = []
    rep = gr.examine({"cut.gif": animation(2)[:-5]}, FF, read=reader({}, seen), codes=no_codes, out_dir=tmp_path)
    assert (rep.animations[0].total, rep.animations[0].read) == (1, 1)
    assert rep.written == [] and list(tmp_path.iterdir()) == [] and seen == []
    assert gr.result_of(rep).status == "none" and rep.skipped == ["cut.gif: the file ends before its trailer"]
    # three frames, cut inside the third: the two whole ones are an animation, and the count says two
    rep = gr.examine({"cut.gif": animation(3)[:-5]}, FF, read=reader({}), codes=no_codes, out_dir=tmp_path)
    assert (rep.animations[0].total, rep.animations[0].read) == (2, 2)
    assert sorted(path.name for path in rep.written) == [f"cut.gif.{part}.png" for part in (
        "diff0-1", "frame0", "frame1", "overlaydarkest", "overlaylightest")]
    assert gr.frames(animation(3)[:-5])[1] == 2
    # a file whose first frame cannot be read at all: its blocks and codes were read, and it is named
    monkeypatch.setattr(gr.Reel, "__iter__", lambda self: (_ for _ in ()).throw(gr.GifError("cannot read frame 0: boom")))
    rep = gr.examine({"a.gif": animation(2, comment=b"CSCTF{in_the_comment}")}, FF, read=reader({}), codes=no_codes)
    assert rep.skipped == ["a.gif: frames not read: cannot read frame 0: boom"]
    assert gr.result_of(rep).flags == ("CSCTF{in_the_comment}",)


def test_prefixes_reach_the_ocr_flag_reader():
    texts = {1: "CSCTF(read with round brackets)"}
    with_prefix = gr.examine({"a.gif": animation(2)}, FF, read=reader(texts), codes=no_codes, prefixes=("CSCTF",))
    assert with_prefix.animations[0].ocr_flags[0] == "CSCTF{read_with_round_brackets}"
    without = gr.examine({"a.gif": animation(2)}, FF, read=reader(texts), codes=no_codes)
    assert without.animations[0].ocr_flags == []


def test_solve_writes_frames_under_recon_and_reads_only_gifs(tmp_path, monkeypatch):
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "feed.gif").write_bytes(animation(3, durations=[500, 10, 500]))
    (tmp_path / "files" / "renamed.dat").write_bytes(animation(2))
    (tmp_path / "files" / "fake.gif").write_bytes(b"not a gif at all")
    monkeypatch.setattr(image_carve, "ocr_text", reader({1: "BAY-41", 2: FLAG}))
    res = gr.solve(tmp_path, PROFILE, seconds=BUDGET)
    assert res.status == "candidate" and res.flags == (FLAG,) and res.engine == "toolkits.gif_reveal"
    written = [e.path for e in res.evidence if e.detail == "written"]
    assert len(written) == 7 + 5 and all(p.startswith("recon/gif_reveal/files_") for p in written)
    assert "files/feed.gif: identifiers read by OCR: BAY-41" in res.notes
    assert "fake.gif" not in res.notes
    out = tmp_path / "elsewhere"
    gr.solve(tmp_path, PROFILE, seconds=BUDGET, out=str(out), ocr="off")
    assert len(list(out.iterdir())) == 12
    with pytest.raises(FileNotFoundError):
        gr.solve(tmp_path / "missing", PROFILE, seconds=BUDGET)


def test_cli(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    monkeypatch.setattr(image_carve, "ocr_text", reader({1: f"BAY-41 {FLAG}"}))
    path = tmp_path / "feed.gif"
    path.write_bytes(animation(3, durations=[500, 10, 500]))
    assert gr.main([str(path), "--out", str(tmp_path / "out"), "--seconds", "3600"]) == 0
    out = capsys.readouterr().out
    assert "feed.gif: 3 frames, 1 a viewer would not see" in out
    assert f"[frame 1] flags=['{FLAG}'] identifiers=['BAY-41']" in out and out.count("written: ") == 7
    result = json.loads(out.strip().splitlines()[-1])
    assert result["status"] == "candidate" and result["flags"] == [FLAG]
    assert gr.main([str(tmp_path / "absent.gif")]) == 2 and "no such file" in capsys.readouterr().err

    def absent(png, deadline=None):
        raise image_carve.ToolMissing("tesseract is not on PATH")

    monkeypatch.setattr(image_carve, "ocr_text", absent)
    assert gr.main([str(path), "--ocr", "on"]) == 2 and "tesseract is not on PATH" in capsys.readouterr().err


# ---- the real OCR ----------------------------------------------------------------------------------

@pytest.mark.needs_tool("tesseract")
def test_real_tesseract_reads_the_frame_a_viewer_never_sees():
    frames = [fx.bar_frame(0, (420, 90)), fx.text_image("CSCTF{REVEAL42}", (420, 90)),
              fx.text_image("BAY-41 KX 58", (420, 90)), fx.bar_frame(3, (420, 90))]
    data = fx.gif_bytes(frames, durations=[500, 10, 500, 500])
    rep = gr.examine({"feed.gif": data}, FF, codes=no_codes, prefixes=("CSCTF",))
    anim = rep.animations[0]
    assert anim.readings[0].source == "frame 1" and anim.readings[0].flags == ["CSCTF{REVEAL42}"]
    assert {"BAY-41", "KX 58"} <= set(anim.identifiers)
    res = gr.result_of(rep)
    assert res.status == "candidate" and "CSCTF{REVEAL42}" in res.flags


# ---- round 1 of verification -----------------------------------------------------------------------

def test_blocks_agrees_with_the_phase_1_walker_on_what_both_keep():
    """gif_reveal.blocks is a second GIF block walk beside carve_stego.gif_blocks, because it keeps
    more (delays, boxes, the loop count, the tail). On what both keep they must not differ."""
    import carve_stego
    for data in (animation(5, durations=[500, 10, 20, 30, 40], comment=b"a note"), animation(2, loop=None),
                 fx.gif_bytes([fx.bar_frame(0)])):
        ours, theirs = gr.blocks(data), carve_stego.gif_blocks(data)
        assert (len(ours["frames"]), ours["comments"], ours["apps"]) == (theirs["frames"], theirs["comments"], theirs["apps"])
    # the one place they differ, on purpose: a file cut inside an image. Phase 1 counts the image
    # it started; this one lists only the frames whose data is all there, and says `truncated`.
    cut = animation(3)[:-40]
    ours, theirs = gr.blocks(cut), carve_stego.gif_blocks(cut)
    assert (len(ours["frames"]), theirs["frames"], ours["truncated"]) == (2, 3, True)
    assert (ours["comments"], ours["apps"]) == (theirs["comments"], theirs["apps"])


def test_default_budget_bounds_the_ocr_and_fits_intake(tmp_path, monkeypatch):
    """solve() with no `seconds`: the production default is what stops the OCR. Time is a clock
    the stand-in OCR moves (one second a reading), so nothing here depends on how fast the machine is."""
    from ctf.engines import manifest
    from ctf.intake import DEFAULT_ENGINE_BUDGET

    class Clock:
        now = 1000.0

        def monotonic(self):
            return self.now

    clock = Clock()
    (tmp_path / "feed.gif").write_bytes(animation(14))               # 14 frames, 13 diffs, 2 overlays to read
    read = []

    def ocr(png, deadline=None):
        read.append(deadline)
        clock.now += 1.0                                             # a reading takes a second; nothing else takes any
        return ""

    import carve_stego
    monkeypatch.setattr(image_carve, "ocr_text", ocr)
    monkeypatch.setattr(carve_stego, "decode_codes", no_codes)
    monkeypatch.setattr(gr, "time", clock)
    res = gr.solve(tmp_path, PROFILE)
    # a reading starts while the budget is not spent: 21 start in 20 s, the 22nd does not
    assert len(read) == int(gr.DEFAULT_SECONDS) + 1 == 21
    assert set(read) == {1000.0 + gr.DEFAULT_SECONDS}                # each OCR call is handed the same deadline
    assert "feed.gif: OCR out of time before diff 7->8; it is written for a human or model read" in res.notes
    written = [e.path for e in res.evidence if e.detail == "written"]
    assert len(written) == 29                                        # what was not read is still on disk
    # the default leaves room in the challenge's intake budget, and the process timeout leaves
    # room for the engine to stop by itself and report
    intake = {m.id: m for m in manifest.discover()}["toolkits.gif_reveal"].intake
    assert gr.DEFAULT_SECONDS <= DEFAULT_ENGINE_BUDGET / 3
    assert 2 * gr.DEFAULT_SECONDS <= intake.timeout <= DEFAULT_ENGINE_BUDGET


def test_missing_code_reader_is_named(monkeypatch):
    import sys
    data = animation(2, comment=b"CSCTF{still_found_in_a_comment}")
    assert gr.result_of(gr.examine({"a.gif": data}, FF, ocr="off")).notes.count("codes not read") == 0
    monkeypatch.setitem(sys.modules, "zxingcpp", None)               # neither camera decoder imports
    monkeypatch.setitem(sys.modules, "pyzbar", None)
    rep = gr.examine({"a.gif": data, "b.gif": animation(3), "notes.txt": b"not a gif"}, FF, ocr="off")
    note = "codes not read: neither py:zxingcpp nor py:pyzbar is importable"
    assert rep.skipped == [note]                                     # once, not once a file
    res = gr.result_of(rep)
    assert note in res.notes and res.flags == ("CSCTF{still_found_in_a_comment}",)
    # nothing to read codes from, nothing to say; a caller's own reader is not second-guessed
    assert gr.examine({"notes.txt": b"not a gif"}, FF, ocr="off").skipped == []
    assert gr.examine({"a.gif": data}, FF, ocr="off", codes=no_codes).skipped == []
    monkeypatch.setitem(sys.modules, "zxingcpp", type(sys)("zxingcpp"))
    assert gr.examine({"a.gif": data}, FF, ocr="off", codes=no_codes).skipped == []
    import _visual_stego as vs
    assert vs.code_reader_missing() is None                          # zxing-cpp alone is enough
