"""B-030: the image carve family (solvers/toolkits/image_carve.py) and carve_stego.judge_blob's
length-prefixed files. Every fixture is built here: synthetic pixels, our own PNG/BMP encoder, our own
dumps. Nothing from a challenge is read."""
from __future__ import annotations

import datetime as dt
import gzip
import io
import json
import random
import struct
import sys
import tarfile
import time
import zipfile
import zlib
from pathlib import Path

import pytest

import carve_stego as cs
import image_carve as ic
from ctf import event, flagfmt

REPO = Path(__file__).resolve().parents[1]


def _profile(prefixes=("CSCTF",), slug="b030-test"):
    return event.parse({
        "slug": slug, "name": "image carve test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "manual"},
        "flag": {"prefixes": list(prefixes)},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
    }, src="<test>")


PROFILE = _profile()
FF = flagfmt.for_profile(PROFILE)


# ---- fixture builders ------------------------------------------------------------------------------

def _filter(rows, ch, cycle):
    """Filtered scanlines: filter types from `cycle` (0 none, 1 sub, 2 up), row by row."""
    out, prev = bytearray(), bytes(len(rows[0]))
    for y, row in enumerate(rows):
        f = cycle[y % len(cycle)]
        if f == 1:
            line = bytes((row[i] - (row[i - ch] if i >= ch else 0)) & 255 for i in range(len(row)))
        elif f == 2:
            line = bytes((row[i] - prev[i]) & 255 for i in range(len(row)))
        else:
            line = row
        out.append(f)
        out += line
        prev = row
    return bytes(out)


def _png(w, h, ch, rows, *, flush=None, every=16, chunk=8192, cycle=(0,), level=9, points=None, depth=8):
    """Our own PNG encoder: filters from `cycle`, an optional zlib flush every `every` rows, IDAT
    chunks of `chunk` bytes. `points` gets (file offset, raw offset) of every flush point."""
    raw = _filter(rows, ch * depth // 8, cycle)
    co = zlib.compressobj(level)
    stride = w * ch * depth // 8 + 1
    parts, zlen = [], 0
    for y in range(h):
        parts.append(co.compress(raw[y * stride:(y + 1) * stride]))
        zlen += len(parts[-1])
        if flush is not None and y % every == every - 1:
            parts.append(co.flush(flush))
            zlen += len(parts[-1])
            if points is not None:
                points.append((33 + (zlen // chunk) * (chunk + 12) + 8 + zlen % chunk, (y + 1) * stride))
    parts.append(co.flush())
    z = b"".join(parts)
    out = ic.PNG_SIG + ic._chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, depth, {1: 0, 3: 2, 4: 6}[ch], 0, 0, 0))
    for i in range(0, len(z), chunk):
        out += ic._chunk(b"IDAT", z[i:i + chunk])
    return out + ic._chunk(b"IEND", b"")


def _noise_rows(w, h, ch, seed):
    rnd = random.Random(seed)
    rows = []
    for y in range(h):
        row = bytearray()
        for x in range(w):
            px = [rnd.randrange(256), (x * 3 + y * 5) & 255, rnd.randrange(256) if (x // 8 + y // 8) % 3 else 40]
            row += bytes((px + [255])[:ch])
        rows.append(bytes(row))
    return rows


def _cropped(orig_rows, w, h, ch, crop_w, crop_h, **kw):
    """aCropalypse: a smaller PNG written over the start of the original file, never truncated."""
    orig = _png(w, h, ch, orig_rows, **kw)
    assert orig.startswith(ic.PNG_SIG)
    crop = _png(crop_w, crop_h, ch, [r[:crop_w * ch] for r in orig_rows[:crop_h]])
    assert len(crop) < len(orig)
    return crop + orig[len(crop):], orig


def _rows_of(png):
    px = cs.png_pixels(png, by="stdlib")
    rs = px["width"] * px["channels"]
    return [px["data"][i * rs:(i + 1) * rs] for i in range(px["height"])]


def _embed(samples: bytearray, payload: bytes, bit: int = 0):
    bits = "".join(f"{b:08b}" for b in payload)
    assert len(bits) <= len(samples)
    for i, c in enumerate(bits):
        samples[i] = (samples[i] & ~(1 << bit) & 255) | (int(c) << bit)


def _rgb_png(w, h, samples: bytes) -> bytes:
    rows = [samples[y * w * 3:(y + 1) * w * 3] for y in range(h)]
    return _png(w, h, 3, rows)


def _tgz(name: str, body: bytes) -> bytes:
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as t:
        info = tarfile.TarInfo(name)
        info.size = len(body)
        t.addfile(info, io.BytesIO(body))
    return gzip.compress(b.getvalue(), mtime=0)


def _zip(members: dict) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n, body in members.items():
            z.writestr(n, body)
    return b.getvalue()


# ---- aCropalypse -----------------------------------------------------------------------------------

def test_acropalypse_full_flush_rebuilds_every_row_after_the_restart_exactly():
    W, H = 320, 400
    rows = _noise_rows(W, H, 4, seed=5)
    f, _orig = _cropped(rows, W, H, 4, 200, 100, flush=zlib.Z_FULL_FLUSH, cycle=(1, 2, 0))
    rec = ic.acropalypse(f)
    assert rec, "no recovery"
    r = rec[0]
    # the cropped IHDR says 200 wide: 320 came from the filter bytes, and RGBA (the crop's own type)
    # beats 1280 x grey, which has the same row length and is a common screen width
    assert (r.width, r.channels, r.color_type) == (320, 4, 6)
    assert r.how.startswith("width from the scanline filter bytes")
    assert [(c.width, c.channels) for c in rec][:2] == [(320, 4), (1280, 1)]
    got = _rows_of(r.png)
    assert r.height == len(got) and r.height >= 300
    want = rows[H - r.height:]
    # the first rebuilt row has no previous row (its Up filter reads zeros); every row after it is exact
    assert got[1:] == want[1:]
    assert r.tail_offset == cs.primary(f)[1]


def test_acropalypse_sync_flush_restarts_with_the_zero_window():
    W, H = 320, 400
    rows = _noise_rows(W, H, 4, seed=6)
    points = []
    f, _orig = _cropped(rows, W, H, 4, 320, 100, flush=zlib.Z_SYNC_FLUSH, every=16, points=points)
    rec = ic.acropalypse(f)
    assert rec and (rec[0].width, rec[0].channels) == (320, 4)
    r = rec[0]
    # a sync flush keeps the window, so the block after it refers back into bytes that are gone: the
    # zero window lets inflate restart at the first flush point after the crop all the same
    end = cs.primary(f)[1]
    first = next(raw_at for file_at, raw_at in points if file_at >= end + 4)
    assert r.inflated >= H * (W * 4 + 1) - first
    got = _rows_of(r.png)
    assert got[-1] == rows[-1]
    exact = sum(g == w for g, w in zip(got, rows[H - r.height:]))
    assert exact >= r.height // 5


def test_acropalypse_finds_a_bit_aligned_block_start_with_no_flush_at_all():
    W, H = 320, 400
    rows = _noise_rows(W, H, 4, seed=5)
    f, _orig = _cropped(rows, W, H, 4, 200, 100, flush=None)
    rec = ic.acropalypse(f)
    assert rec and (rec[0].width, rec[0].channels) == (320, 4)
    assert rec[0].start_bit % 8 != 0                     # only a bit shift finds this block start
    assert _rows_of(rec[0].png)[-1] == rows[-1]


def test_restart_prefers_the_earliest_offset_and_rejects_a_stream_that_does_not_end():
    rnd = random.Random(1)
    body = bytes(rnd.randrange(256) for _ in range(5000))
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    first = co.compress(body[:2500]) + co.flush(zlib.Z_FULL_FLUSH)
    second = co.compress(body[2500:]) + co.flush()
    stream = first + second
    bit, out = ic.restart(stream)
    assert bit == 0 and out == body
    bit, out = ic.restart(b"\x13\x37" + second)           # junk before the restart point
    assert out.endswith(body[2500:]) and bit <= 16          # the earliest start (junk may decode and resync)
    assert ic.restart(second)[1] == body[2500:]
    assert ic.restart(stream[:-40]) is None               # cut short: never reaches the final block
    assert ic.restart(stream + bytes(range(64))) is None  # junk after the end: more than the slack


def test_the_ihdr_width_carries_a_flat_image_the_scan_cannot_read():
    W, H = 300, 120
    rows = [bytes([10, 200, 30]) * W for _ in range(H)]          # one colour, Up filter: rows are 2 + zeros
    f, _orig = _cropped(rows, W, H, 3, 300, 30, flush=zlib.Z_FULL_FLUSH, cycle=(2,))
    raw = ic.restart(ic.tail_stream(f[cs.primary(f)[1]:])[0])[1]
    assert ic.scan_stride(raw) is None                           # nothing to tell rows apart
    rec = ic.acropalypse(f)
    # every width fits a flat image: the IHDR's is taken first, then the common widths by row length
    assert (rec[0].width, rec[0].channels) == (300, 3)
    assert [(r.width, r.channels) for r in rec[:4]] == [(300, 3), (300, 4), (300, 1), (300, 2)]
    assert all(r.how.startswith("the IHDR width") for r in rec[:4])
    common = rec[4:]
    assert common and all(r.how.startswith("a common screen width") for r in common)
    assert [r.width * r.channels for r in common] == sorted(r.width * r.channels for r in common)


def test_a_given_width_comes_first_only_when_its_rows_fit():
    W, H = 320, 400
    f, _orig = _cropped(_noise_rows(W, H, 4, seed=5), W, H, 4, 200, 100, flush=zlib.Z_FULL_FLUSH)
    assert all(r.how != "width given" for r in ic.acropalypse(f, widths=[321]))
    rec = ic.acropalypse(f, widths=[320])
    assert rec[0].how == "width given" and (rec[0].width, rec[0].channels) == (320, 4)


def test_filter_fit_counts_clean_rows_from_the_bottom():
    stride = 4
    raw = b"\x05abc" + b"\x04xyz" + b"\x00xyz" + b"\x02xyz"
    assert ic.filter_fit(raw, stride) == (4, 3)                 # 5 is no filter byte: the top row is not clean
    assert ic.filter_fit(b"\x09" + raw[1:], stride) == (4, 3)
    assert ic.filter_fit(raw[:4] + b"\x07" + raw[5:], stride) == (4, 2)
    assert ic.filter_fit(b"", stride) == (0, 0)


def test_fits_needs_a_quarter_of_the_rows_clean_and_the_scan_needs_enough_rows():
    rnd = random.Random(8)
    stride = 41
    good = b"".join(bytes([rnd.randrange(5)]) + bytes(rnd.randrange(5, 256) for _ in range(stride - 1))
                    for _ in range(20))
    assert ic.fits(good, stride) and ic.scan_stride(good) == stride
    junk = bytes(rnd.randrange(5, 256) for _ in range(stride * 17))
    mixed = junk + good[-3 * stride:]                           # 3 clean rows of 20
    assert ic.filter_fit(mixed, stride) == (20, 3)
    assert not ic.fits(mixed, stride) and ic.fits(mixed, stride, least=3) is False
    assert ic.fits(junk[:stride * 9] + good[-3 * stride:], stride)          # 3 clean rows of 12
    assert ic.scan_stride(good[-6 * stride:]) is None          # six rows are too few to tell a stride
    assert ic.scan_stride(good[-7 * stride:]) is None          # so are seven
    assert ic.scan_stride(good[-8 * stride:]) == stride        # eight (SCAN_ROWS) are enough


def test_no_recovery_without_a_deflate_tail():
    rows = _noise_rows(64, 32, 3, seed=2)
    png = _png(64, 32, 3, rows)
    assert ic.acropalypse(png) == []
    assert ic.acropalypse(png + _zip({"flag.txt": b"CSCTF{z}"})) == []     # an archive is no IDAT tail
    assert ic.acropalypse(png + bytes(400)) == []
    # a deflate stream that ends right, but in no IDAT/IEND framing: not an older image's tail
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    bare = co.compress(_filter(_noise_rows(64, 40, 3, seed=9), 3, (1,))) + co.flush() + b"\x00\x00\x00\x00"
    assert ic.restart(bare) is not None and ic.acropalypse(png + bare) == []


def test_tail_stream_drops_the_broken_chunks_crc_and_unwraps_the_whole_chunks():
    a, b, c = b"A" * 50, b"B" * 70, b"C" * 30
    tail = a + b"\xde\xad\xbe\xef" + ic._chunk(b"IDAT", b) + ic._chunk(b"IDAT", c) + ic._chunk(b"IEND", b"")
    assert ic.tail_stream(tail) == (a + b + c, 2, True)
    assert ic.tail_stream(tail[:-12]) == (a + b + c, 2, False)          # the IEND was cut off
    assert ic.tail_stream(b"no chunks here") == (b"no chunks here", 0, False)


def _idat_body(png):
    return b"".join(c["data"] for c in cs.png_chunks(png) if c["type"] == "IDAT")


def test_an_older_tail_after_the_zlib_stream_inside_idat_is_rebuilt(tmp_path):
    """The after-IDAT shape: nothing follows IEND, but the IDAT chunks hold, after the crop's zlib
    stream ends, the rest of the older image's deflate stream (the bytes it was written over)."""
    W, H = 320, 400
    rows = _noise_rows(W, H, 4, seed=5)
    orig = _png(W, H, 4, rows, flush=zlib.Z_FULL_FLUSH, cycle=(1, 2, 0))
    crop = _png(200, 100, 4, [r[:200 * 4] for r in rows[:100]])
    z_crop, z_orig = _idat_body(crop), _idat_body(orig)
    body = z_crop + z_orig[len(z_crop):]
    step = 4000                                                  # several IDAT chunks: the offset maps through them
    f = crop[:33] + b"".join(ic._chunk(b"IDAT", body[i:i + step]) for i in range(0, len(body), step))
    f += ic._chunk(b"IEND", b"")
    assert cs.primary(f)[1] == len(f)                            # nothing after IEND
    L = len(z_crop)
    assert ic.idat_tail(f) == (33 + (L // step) * (step + 12) + 8 + L % step, z_orig[L:])
    rec = ic.acropalypse(f)
    assert rec and all(r.tail == ic.AFTER_IDAT for r in rec)
    r = rec[0]
    assert (r.width, r.channels) == (320, 4) and r.tail_offset == ic.idat_tail(f)[0]
    got = _rows_of(r.png)
    assert r.height >= 300 and got[1:] == rows[H - r.height:][1:]
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "shot.png").write_bytes(f)
    res = ic.solve(tmp_path, PROFILE, ocr="off")
    assert res.status == "unsure" and "of the tail after the zlib stream in IDAT at offset" in res.notes
    # a plain PNG's stream ends where its IDAT does; zeros after the stream are padding, never a tail
    plain = _png(64, 32, 3, _noise_rows(64, 32, 3, seed=2))
    assert ic.idat_tail(plain) is None
    padded = plain[:33] + ic._chunk(b"IDAT", _idat_body(plain) + bytes(64)) + ic._chunk(b"IEND", b"")
    assert ic.idat_tail(padded) is None and ic.acropalypse(padded) == []


def test_a_given_width_the_scan_also_finds_is_one_reading():
    W, H = 320, 400
    f, _orig = _cropped(_noise_rows(W, H, 4, seed=5), W, H, 4, 200, 100, flush=zlib.Z_FULL_FLUSH)
    readings = [(r.width, r.channels) for r in ic.acropalypse(f, widths=[320])]
    assert readings[0] == (320, 4) and readings.count((320, 4)) == 1
    assert len(readings) == len(set(readings))


def test_a_16_bit_older_image_is_named_and_not_rebuilt_as_8_bit():
    W, H = 160, 200
    rows = _noise_rows(W * 2, H, 4, seed=19)                     # 8 bytes a pixel: RGBA, 16 bits a sample
    orig = _png(W, H, 4, rows, flush=zlib.Z_FULL_FLUSH, cycle=(1, 2, 0), depth=16)
    crop = _png(100, 50, 4, [r[:100 * 8] for r in rows[:50]], depth=16)
    f = crop + orig[len(crop):]
    end = cs.primary(f)[1]
    assert ic.restart(ic.tail_stream(f[end:])[0]) is not None     # the tail restarts: only the depth stops it
    skipped = []
    assert ic.acropalypse(f, skipped=skipped) == []
    assert skipped == ["acropalypse (after IEND): 16-bit images are not rebuilt"]


# ---- fragmented PNG --------------------------------------------------------------------------------

S = 512


def _sectors(data):
    data = data + bytes((-len(data)) % S)
    return [data[i:i + S] for i in range(0, len(data), S)]


def _text(k):
    line = b"$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A\r\n"
    return [(line * 8)[:S] for _ in range(k)]


def _zero(k):
    return [bytes(S) for _ in range(k)]


def _flotsam(seed=7, chunk=1 << 20):
    rnd = random.Random(seed)
    rows = [bytes(rnd.randrange(256) for _ in range(160 * 3)) for _ in range(48)]
    png = _png(160, 48, 3, rows, chunk=chunk)
    secs = _sectors(png)
    A, B, C, D = secs[:6], secs[6:10], secs[10:13], secs[13:]
    decoy = [bytes(rnd.randrange(256) for _ in range(S)) for _ in range(len(C))]   # same size as C
    layout = _text(2) + B + _zero(1) + decoy + _zero(2) + C + _text(1) + D + _zero(3) + A + _zero(2)
    starts = {}
    pos = 0
    for name, part in (("t", _text(2)), ("B", B), ("z", _zero(1)), ("x", decoy), ("z2", _zero(2)), ("C", C),
                       ("t2", _text(1)), ("D", D), ("z3", _zero(3)), ("A", A)):
        starts[name] = pos
        pos += len(part) * S
    return b"".join(layout), png, starts


def test_out_of_order_fragments_are_joined_into_the_exact_png():
    dump, png, at = _flotsam()
    h = dump.find(ic.PNG_SIG)
    assert h == at["A"] and not ic.intact_at(dump, h)       # in place it does not walk
    got = ic.reassemble_png(dump)
    assert len(got) == 1
    r = got[0]
    assert r.png == png and r.offset == at["A"] and (r.width, r.height) == (160, 48)
    assert [s for s, _e in r.pieces] == [at["A"], at["B"], at["C"], at["D"]]
    assert not r.contiguous and r.block_size == 512


def test_many_idat_chunks_and_a_decoy_the_size_of_a_fragment():
    dump, png, at = _flotsam(seed=11, chunk=700)             # chunk headers fall inside the fragments
    got = ic.reassemble_png(dump)
    assert got and got[0].png == png
    assert [s for s, _e in got[0].pieces] == [at["A"], at["B"], at["C"], at["D"]]


def test_a_spent_search_budget_is_named_never_silent():
    dump, _png_, _at = _flotsam()
    skipped = []
    assert ic.reassemble_png(dump, max_nodes=1, skipped=skipped) == []
    assert any("search budget of 1 nodes spent" in s for s in skipped)


def test_an_intact_png_inside_a_dump_is_left_to_the_carver():
    rows = _noise_rows(40, 20, 3, seed=3)
    png = _png(40, 20, 3, rows)
    dump = b"".join(_text(3)) + png + b"".join(_zero(2))
    assert ic.intact_at(dump, 3 * S)
    assert ic.reassemble_png(dump) == []


def test_raw_size_matches_the_png_spec_for_interlaced_and_plain_images():
    assert ic.raw_size(160, 48, 8, 2, 0) == 48 * (1 + 480)
    assert ic.raw_size(1, 1, 8, 6, 1) == 1 + 4                 # Adam7 pass 1 only
    # 8x8 grey 1-bit, Adam7: passes of 1x1, 1x1, 2x1, 2x2, 4x2, 4x4, 8x4 pixels, 2 bytes a row each
    assert ic.raw_size(8, 8, 1, 0, 1) == 2 * (1 + 1 + 1 + 2 + 2 + 4 + 4)
    assert ic.raw_size(8, 8, 8, 5, 0) is None


def _lay(parts):
    """Join sector lists into a dump; return it and the byte offset of each part."""
    at, pos = [], 0
    for p in parts:
        at.append(pos)
        pos += len(p) * S
    return b"".join(sum(parts, [])), at


def test_a_private_chunk_split_across_fragments_is_proven_by_its_crc():
    """A decoy the size of the middle fragment, placed first, inflates nothing wrong (the chunk is
    not image data): only the chunk CRC tells the true middle from it."""
    rnd = random.Random(21)
    rows = [bytes(rnd.randrange(256) for _ in range(30 * 3)) for _ in range(10)]
    png = _png(30, 10, 3, rows)
    priv = bytes(rnd.randrange(256) for _ in range(2048))
    png = png[:33] + ic._chunk(b"prVt", priv) + png[33:]
    secs = _sectors(png)
    A, B, C = secs[:2], secs[2:4], secs[4:]
    decoy = [bytes(rnd.randrange(256) for _ in range(S)) for _ in range(2)]
    dump, at = _lay([_text(1), decoy, _zero(1), B, _zero(1), C, _zero(2), A, _zero(1)])
    got = ic.reassemble_png(dump)
    assert got and got[0].png == png
    assert [s for s, _e in got[0].pieces] == [at[7], at[3], at[5]]


def test_a_low_entropy_text_chunk_in_the_header_fragment_is_kept():
    """The header block holds a long tEXt chunk (plain words, low entropy): the chunks that verify in
    place hold the header fragment together."""
    rnd = random.Random(23)
    rows = [bytes(rnd.randrange(256) for _ in range(60 * 3)) for _ in range(20)]
    png = _png(60, 20, 3, rows)
    words = b"Comment\x00" + b"bridge log, last fix recorded at the chart table; " * 24
    png = png[:33] + ic._chunk(b"tEXt", words) + png[33:]
    secs = _sectors(png)
    assert not ic.may_hold_png(*ic.block_stats(secs[0] + secs[1], 0, S)[0])  # the header block reads as text
    A, B = secs[:5], secs[5:]
    dump, at = _lay([_text(1), B, _zero(2), A, _zero(1)])
    got = ic.reassemble_png(dump)
    assert got and got[0].png == png and [s for s, _e in got[0].pieces] == [at[3], at[1]]


def test_block_classes_keep_low_entropy_image_data_and_drop_text_and_erased_blocks():
    rnd = random.Random(41)
    flat = zlib.compress(bytes(200) * 400, 9)[:S]               # a flat area: deflate codes repeat
    blocks = [bytes(S), b"\xff" * S, _text(1)[0], bytes(rnd.randrange(256) for _ in range(S)),
              (flat + bytes(rnd.randrange(256) for _ in range(S)))[:S], bytes([7, 9]) * (S // 2)]
    stats = ic.block_stats(b"".join(blocks), 0, S)
    assert [ic.may_hold_png(e, t) for e, t in stats] == [False, False, False, True, True, True]
    assert stats[0] == (0.0, 0.0) and stats[2][1] == 1.0 and 7.0 < stats[3][0] <= 8.0
    assert stats[5] == (1.0, 0.5)                               # two values, half of them tab


def test_walk_and_the_inflate_checks():
    rows = _noise_rows(20, 6, 3, seed=4)
    png = _png(20, 6, 3, rows)
    want = ic.raw_size(20, 6, 8, 2, 0)
    state, end, idat, _need = ic._walk(png, want)
    assert (state, end) == ("done", len(png)) and ic._whole(idat, want)
    bad = bytearray(png)
    bad[40] ^= 1                                                # a byte of the IDAT body: its CRC fails
    assert ic._walk(bytes(bad), want)[0] == "fail"
    ln = struct.unpack_from(">I", png, 33)[0]
    assert ic._walk(png[:60], want) == ("need", 33, png[41:60], 33 + 12 + ln - 60 + 12)
    assert not ic._whole(idat, want - 1) and not ic._whole(idat, want + 1)
    assert ic._prefix_ok(idat[:len(idat) // 2], want)
    assert not ic._prefix_ok(b"\x78\xda" + b"\xff" * 50, want)          # a reserved block type
    assert not ic._prefix_ok(idat, want - 10)                               # more than the IHDR implies
    assert ic._prefix_ok(idat, want)                                        # a whole stream of the right size
    assert not ic._prefix_ok(idat, want + 10)                               # it ended before the IHDR's size
    short = zlib.compress(bytes(want - 1))
    assert not ic._prefix_ok(short, want) and ic._prefix_ok(short[:5], want)


def _runs_dump(far: bool):
    """A PNG in two pieces (A holds the header) and 45 one-sector decoys, each set apart by zeros.
    IDAT chunks of 300 bytes: every wrong sector breaks a chunk CRC at once."""
    rnd = random.Random(43)
    png = _png(60, 20, 3, _noise_rows(60, 20, 3, seed=17), chunk=300, cycle=(1,), level=6)
    secs = _sectors(png)
    A, B = secs[:2], secs[2:]
    decoys = sum(([[bytes(rnd.randrange(256) for _ in range(S))], _zero(1)] for _ in range(45)), [])
    parts = [A, _zero(1)] + decoys + [B, _zero(1)] if far else decoys + [A, _zero(1), B, _zero(1)]
    dump, _at = _lay(parts)
    return dump, png


def test_more_than_max_runs_candidate_runs_keeps_the_nearest_and_says_so():
    dump, png = _runs_dump(far=False)
    skipped = []
    got = ic.reassemble_png(dump, block_sizes=(512,), skipped=skipped)
    assert got and got[0].png == png
    assert skipped == ["fragments: 46 candidate runs at block size 512; the 40 nearest the header are searched"]
    dump, png = _runs_dump(far=True)                    # the true second piece is the 46th nearest
    skipped = []
    assert ic.reassemble_png(dump, block_sizes=(512,), skipped=skipped) == []
    assert skipped == ["fragments: 46 candidate runs at block size 512; the 40 nearest the header are searched"]


def test_the_zlib_prefix_check_keeps_the_search_small():
    """A compressible image in one IDAT, six decoys the size of a fragment: no chunk boundary falls
    inside the image data, so only the zlib prefix check prunes (without it, about 86000 nodes)."""
    rnd = random.Random(31)
    png = _png(160, 140, 3, _noise_rows(160, 140, 3, seed=3), chunk=1 << 20, cycle=(1,), level=6)
    secs = _sectors(png)
    k = len(secs) // 6
    parts = [secs[:k], secs[k:2 * k], secs[2 * k:3 * k], secs[3 * k:4 * k], secs[4 * k:5 * k], secs[5 * k:]]
    decoys = [[bytes(rnd.randrange(256) for _ in range(S)) for _ in range(k)] for _ in range(6)]
    seq = [decoys[0], parts[3], decoys[1], parts[1], decoys[2], parts[5], decoys[3], parts[2], decoys[4], parts[4],
           decoys[5], parts[0]]
    dump, _at = _lay(sum(([p, _zero(1)] for p in seq), []))
    got = ic.reassemble_png(dump, block_sizes=(512,))
    assert got and got[0].png == png
    assert got[0].nodes <= 200, got[0].nodes


# ---- judge_blob: a length before a file ------------------------------------------------------------

def test_judge_blob_takes_a_length_prefixed_gzip_both_byte_orders():
    tgz = _tgz("caption.txt", b"recon annotation")
    rnd = random.Random(4)
    noise = bytes(rnd.randrange(256) for _ in range(300))
    for fmt in (">I", "<I"):
        got = cs.judge_blob(struct.pack(fmt, len(tgz)) + tgz + noise)
        assert got[:2] == ("file", "gzip") and got[2] == tgz
    # a length that overruns the reading, or one that does not cover the file, proves nothing
    assert cs.judge_blob(struct.pack(">I", len(tgz) + 400) + tgz + noise[:100]) is None
    assert cs.judge_blob(struct.pack(">I", 20) + tgz + noise) is None
    assert cs.judge_blob(struct.pack(">I", 200) + noise) is None


def test_judge_blob_takes_a_tar_and_a_length_prefixed_tar():
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.USTAR_FORMAT) as t:
        info = tarfile.TarInfo("a.txt")
        info.size = 5
        t.addfile(info, io.BytesIO(b"hello"))
    tar = b.getvalue()
    got = cs.judge_blob(tar)
    assert got[:2] == ("file", "tar") and got[2] == tar[:1536]
    got = cs.judge_blob(struct.pack("<I", len(tar)) + tar)
    assert got[:2] == ("file", "tar")
    assert cs._tar_size(tar) == 1536                            # header, one data block, the zero block
    broken = bytearray(tar)
    broken[0] ^= 0x01                                           # the name changed, the checksum not
    assert cs._tar_size(bytes(broken)) is None and cs.judge_blob(bytes(broken)) is None


# ---- LSB routing -----------------------------------------------------------------------------------

def _cover(w, h, seed):
    rnd = random.Random(seed)
    return bytearray(rnd.randrange(256) for _ in range(w * h * 3))


def test_two_planes_two_length_prefixed_gzip_tars_both_reported():
    """csctf 9160's shape: plane 0 and plane 1 each carry length + gzip(tar); the agent picks."""
    w, h = 96, 96
    s = _cover(w, h, 9)
    p0 = _tgz("caption.txt", b"decoy caption CSCTF{plane_zero_decoy}")
    p1 = _tgz("annotation.txt", b"recon: CSCTF{plane_one_real}")
    _embed(s, struct.pack(">I", len(p0)) + p0, bit=0)
    _embed(s, struct.pack(">I", len(p1)) + p1, bit=1)
    png = _rgb_png(w, h, bytes(s))
    hits = [x for x in ic.image_payloads("plate.png", png, FF) if x.channel == "lsb"]
    by_flag = {f: x.method for x in hits for f in x.flags}
    assert set(by_flag) == {"CSCTF{plane_zero_decoy}", "CSCTF{plane_one_real}"}
    assert by_flag["CSCTF{plane_zero_decoy}"].startswith("bit0 RGB xy msb-first")
    assert by_flag["CSCTF{plane_one_real}"].startswith("bit1 RGB xy msb-first")
    assert "/gunzip/annotation.txt" in by_flag["CSCTF{plane_one_real}"]


def test_a_deflated_zip_in_the_lsbs_is_opened():
    w, h = 96, 96
    s = _cover(w, h, 14)
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("notes/key.txt", "padding " * 40 + "CSCTF{zipped_in_the_plane}")
    payload = b.getvalue()
    assert b"CSCTF{" not in payload
    _embed(s, payload, bit=0)
    hits = [x for x in ic.image_payloads("z.png", _rgb_png(w, h, bytes(s)), FF) if x.channel == "lsb"]
    assert [x.flags for x in hits if x.flags] == [["CSCTF{zipped_in_the_plane}"]]
    assert "/notes/key.txt" in next(x.method for x in hits if x.flags)


def test_nul_ended_base64_in_the_lsbs_is_decoded_to_the_flag(tmp_path):
    """spooky eisoptrophobia's shape: a NUL-ended base64 run in bit 0 of R,G,B interleaved."""
    import base64
    w, h = 64, 64
    s = _cover(w, h, 12)
    flag = "spooky{the_reflection_test}"
    _embed(s, base64.b64encode(flag.encode()) + b"\x00", bit=0)
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "mirror.png").write_bytes(_rgb_png(w, h, bytes(s)))
    res = ic.solve(tmp_path, _profile(("spooky",), "spooky-t"), ocr="off")
    assert res.status == "solved" and res.flags == (flag,)
    assert res.evidence[0].kind == "decode" and res.evidence[0].path == "files/mirror.png"


def test_a_bmp_goes_to_the_lsb_reader_too(tmp_path):
    w, h = 40, 30
    s = _cover(w, h, 13)
    _embed(s, b"CSCTF{bmp_lsb_routed}\x00", bit=0)
    row = (w * 3 + 3) & ~3
    pix = b"".join(bytes(s[y * w * 3:(y + 1) * w * 3]) + bytes(row - w * 3) for y in range(h))
    bmp = (b"BM" + struct.pack("<IHHI", 54 + len(pix), 0, 0, 54)
           + struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(pix), 2835, 2835, 0, 0) + pix)
    assert cs.sniff(bmp) == "bmp"
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "x.bmp").write_bytes(bmp)
    res = ic.solve(tmp_path, PROFILE, ocr="off")
    assert res.status == "solved" and res.flags == ("CSCTF{bmp_lsb_routed}",)


def test_a_zip_after_iend_is_opened_and_its_member_searched(tmp_path):
    """spooky arachnophobia's shape: a zip holding flag.txt appended after IEND."""
    png = _png(32, 32, 3, _noise_rows(32, 32, 3, seed=1)) + _zip({"flag.txt": b"spooky{8_legs_test}\n"})
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "spider.png").write_bytes(png)
    res = ic.solve(tmp_path, _profile(("spooky",), "spooky-t"), ocr="off")
    assert res.status == "solved" and res.flags == ("spooky{8_legs_test}",)
    assert res.evidence[0].kind == "carve"


def test_two_lsb_flags_make_a_candidate_and_the_payloads_are_written(tmp_path):
    w, h = 96, 96
    s = _cover(w, h, 9)
    p0, p1 = _tgz("a.txt", b"CSCTF{one}"), _tgz("b.txt", b"CSCTF{two}")
    _embed(s, struct.pack(">I", len(p0)) + p0, bit=0)
    _embed(s, struct.pack(">I", len(p1)) + p1, bit=1)
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "p.png").write_bytes(_rgb_png(w, h, bytes(s)))
    res = ic.solve(tmp_path, PROFILE, ocr="off")
    assert res.status == "candidate" and set(res.flags) == {"CSCTF{one}", "CSCTF{two}"}
    written = sorted((tmp_path / "recon" / "image_carve").iterdir())
    assert {p.read_bytes() for p in written if p.suffix == ".gz"} == {p0, p1}


def test_a_plain_png_is_none(tmp_path):
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "plain.png").write_bytes(_png(32, 32, 3, _noise_rows(32, 32, 3, seed=8)))
    res = ic.solve(tmp_path, PROFILE)
    assert res.status == "none" and res.flags == ()


# ---- the OCR gate ----------------------------------------------------------------------------------

def _text_rows(w, h, text):
    from PIL import Image, ImageDraw, ImageFont
    im = Image.new("RGBA", (w, h), (255, 255, 255, 255))
    d = ImageDraw.Draw(im)
    d.text((10, h - 70), text, fill=(0, 0, 0, 255), font=ImageFont.load_default(size=30))
    rnd = random.Random(3)
    for _ in range(4000):                                   # speckle in the top half: real rows to tell apart
        im.putpixel((rnd.randrange(w), rnd.randrange(h // 2)), (rnd.randrange(256), 90, rnd.randrange(256), 255))
    data = im.tobytes()
    return [data[y * w * 4:(y + 1) * w * 4] for y in range(h)]


@pytest.mark.needs_tool("tesseract", "py:PIL")
def test_ocr_gate_reads_the_flag_off_an_acropalypse_rebuild(tmp_path):
    W, H = 720, 260
    rows = _text_rows(W, H, "KEY: CSCTF{TAIL_RECOVERED_KEY}")
    f, _orig = _cropped(rows, W, H, 4, 400, 60, flush=zlib.Z_FULL_FLUSH, cycle=(1, 2, 0))
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "shot.png").write_bytes(f)
    res = ic.solve(tmp_path, PROFILE)
    assert res.status == "candidate"                       # OCR is never more than a candidate
    assert "CSCTF{TAIL_RECOVERED_KEY}" in res.flags
    assert any(e.kind == "ocr" and "aCropalypse rebuild 720x" in e.detail for e in res.evidence)
    assert any(p.name.startswith("files_shot.png.acropalypse-720x") for p in (tmp_path / "recon" / "image_carve").iterdir())
    # the gate: the first reading that reads a flag ends the file's OCR; the other readings are not read
    rep = ic.examine({"shot.png": f}, FF, prefixes=("CSCTF",))
    assert len(rep.recoveries) > 1 and rep.recoveries[0].ocr_flags == ["CSCTF{TAIL_RECOVERED_KEY}"]
    assert all(r.ocr is None for r in rep.recoveries[1:]) and rep.ocr == "run"


@pytest.mark.needs_tool("tesseract", "py:PIL")
def test_ocr_gate_reads_a_reassembled_png(tmp_path):
    from PIL import Image, ImageDraw, ImageFont
    im = Image.new("RGB", (720, 120), "white")
    ImageDraw.Draw(im).text((10, 40), "KEY: CSCTF{FRAGMENTS_JOINED}", fill="black", font=ImageFont.load_default(size=30))
    rnd = random.Random(2)
    for _ in range(9000):
        im.putpixel((rnd.randrange(720), rnd.randrange(0, 25)), (rnd.randrange(256), rnd.randrange(256), 9))
    data = im.tobytes()
    png = _png(720, 120, 3, [data[y * 2160:(y + 1) * 2160] for y in range(120)], cycle=(1,))
    secs = _sectors(png)
    k = len(secs) // 2
    dump = b"".join(_text(2) + secs[k:] + _zero(2) + secs[:k] + _zero(1))
    (tmp_path / "flash.img").write_bytes(dump)               # a bare folder: the files are the folder's own
    res = ic.solve(tmp_path, PROFILE)
    assert "CSCTF{FRAGMENTS_JOINED}" in res.flags and res.status == "candidate"
    assert any(e.kind == "ocr" and "fragmented PNG joined from 2 pieces" in e.detail for e in res.evidence)


def test_ocr_missing_is_named_and_the_rebuild_still_written(tmp_path, monkeypatch):
    W, H = 320, 400
    f, _orig = _cropped(_noise_rows(W, H, 4, seed=5), W, H, 4, 200, 100, flush=zlib.Z_FULL_FLUSH)
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "shot.png").write_bytes(f)
    monkeypatch.setattr(ic.shutil, "which", lambda name: None)
    res = ic.solve(tmp_path, PROFILE)
    assert res.status == "unsure" and res.flags == ()
    assert "OCR gate not run: tesseract is not on PATH" in res.notes
    assert any(e.path and e.path.startswith("recon/image_carve/") and e.path.endswith(".png") for e in res.evidence)
    blocked = ic.solve(tmp_path, PROFILE, ocr="on")
    assert blocked.status == "blocked" and "tesseract is not on PATH" in blocked.notes
    given = ic.solve(tmp_path, PROFILE, ocr="off", widths="320")          # --opt widths=320 arrives as a string
    assert "320x" in given.notes and "(width given)" in given.notes and "OCR off" in given.notes


def _rec(file, w, png=b"p"):
    return ic.Recovery(w, 10, 4, 6, png, 0, 0, 0, "test", file=file)


def test_ocr_gate_stops_a_source_at_its_first_flag_and_names_what_time_left_out():
    calls = []

    def read(png, deadline=None):
        calls.append(png)
        return {b"a2": "KEY: CSCTF{SECOND_READING}", b"b1": "KEY: CSCTF{OTHER_FILE}"}.get(png, "nothing here")

    ims = [_rec("a.png", 1, b"a1"), _rec("a.png", 2, b"a2"), _rec("a.png", 3, b"a3"), _rec("b.png", 1, b"b1"),
           _rec("b.png", 2, b"b2")]
    ic.ocr_gate(ims, FF, ("CSCTF",), read=read)
    assert calls == [b"a1", b"a2", b"b1"]                       # a3 and b2 never read
    assert [i.ocr_flags for i in ims] == [[], ["CSCTF{SECOND_READING}"], [], ["CSCTF{OTHER_FILE}"], []]
    skipped, calls[:] = [], []
    ic.ocr_gate([_rec("c.png", 7)], FF, deadline=0.0, skipped=skipped, read=read)
    assert calls == [] and skipped == ["OCR gate: out of time before c.png (acropalypse 7x10)"]


def test_ocr_gate_passes_its_deadline_to_the_reader_and_names_a_cut_reading():
    seen = []

    def read(png, deadline=None):
        seen.append(deadline)
        raise ic._OutOfBudget("tesseract --psm 6 stopped after 0.1 s")

    ims, skipped = [_rec("d.png", 5)], []
    dl = time.monotonic() + 100
    ic.ocr_gate(ims, FF, deadline=dl, skipped=skipped, read=read)
    assert seen == [dl] and ims[0].ocr is None and ims[0].ocr_flags == []
    assert skipped == ["OCR gate: out of time in d.png (acropalypse 5x10): tesseract --psm 6 stopped after 0.1 s"]


def _stub_tesseract(tmp_path, monkeypatch, body):
    stub = tmp_path / "bin" / "tesseract"
    stub.parent.mkdir(exist_ok=True)
    stub.write_text("#!/bin/sh\n" + body + "\n")
    stub.chmod(0o755)
    monkeypatch.setattr(ic.shutil, "which", lambda name: str(stub) if name == "tesseract" else None)


@pytest.mark.needs_tool("py:PIL")
def test_ocr_text_gives_tesseract_only_the_time_left(tmp_path, monkeypatch):
    """A stub tesseract (our own shell script) that hangs: the reading stops at the deadline, not
    after the per-mode timeout."""
    png = _png(8, 8, 3, _noise_rows(8, 8, 3, seed=1))
    _stub_tesseract(tmp_path, monkeypatch, "printf 'KEY: CSCTF{STUB_READ}\\n'")
    text = ic.ocr_text(png, deadline=time.monotonic() + 30)
    assert text.count("CSCTF{STUB_READ}") == len(ic.OCR_PSMS)
    _stub_tesseract(tmp_path, monkeypatch, "exec sleep 6")
    t0 = time.monotonic()
    with pytest.raises(ic._OutOfBudget, match=r"tesseract --psm 6 stopped after 0\.[0-9] s"):
        ic.ocr_text(png, deadline=t0 + 0.6)
    assert time.monotonic() - t0 < 3
    with pytest.raises(ic._OutOfBudget, match="no time left for tesseract --psm 6"):
        ic.ocr_text(png, deadline=time.monotonic() - 1)


def test_a_flag_both_proven_and_read_by_ocr_is_one_solved_flag():
    rep = ic.Report(hits=[ic.Hit("a.png", "lsb", "bit0 RGB", ["CSCTF{both_ways}"], "preview")])
    im = _rec("a.png", 320)
    im.ocr_flags = ["CSCTF{both_ways}"]
    rep.recoveries.append(im)
    res = ic.result_of(rep)
    assert res.status == "solved" and res.flags == ("CSCTF{both_ways}",)
    assert [e.kind for e in res.evidence] == ["decode"]
    other = _rec("a.png", 321)
    other.ocr_flags = ["CSCTF{read_only}"]
    rep.recoveries.append(other)
    res = ic.result_of(rep)
    assert res.status == "candidate" and res.flags == ("CSCTF{both_ways}", "CSCTF{read_only}")
    assert [e.kind for e in res.evidence] == ["decode", "ocr"]


def test_ocr_flags_reads_bracket_and_underscore_slips_only_for_the_stated_prefix():
    text = "KEY: CSCTFiTAIL_KEY}\nother: CSCTF(SECOND ONE)\nnoise XYZiABC}"
    # the default body has no spaces: the as-read form is no flag, the other two are
    assert ic.ocr_flags(text, FF, ("CSCTF",)) == ["CSCTF{TAIL_KEY}", "CSCTF{SECOND_ONE}", "CSCTF{SECONDONE}"]
    assert ic.ocr_flags(text, FF, ()) == []
    assert ic.ocr_flags("CSCTF{AS_READ}", FF, ()) == ["CSCTF{AS_READ}"]
    # a prefix that ends another prefix is not read inside it (CTF in CSCTF)
    two = flagfmt.for_profile(event.parse({            # csctf's own shape: two prefixes, spaces allowed
        "slug": "two-prefix", "name": "t", "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "manual"}, "flag": {"prefixes": ["CSCTF", "CTF"], "body": "[^}\\n]{1,256}"},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"}}, src="<t>"))
    assert ic.ocr_flags("KEY: CSCTFiABC_1}", two, ("CSCTF", "CTF")) == ["CSCTF{ABC_1}"]
    assert ic.ocr_flags("KEY: CSCTF{ABC 1}", two, ("CSCTF", "CTF")) == ["CSCTF{ABC_1}", "CSCTF{ABC 1}", "CSCTF{ABC1}"]
    hexy = flagfmt.for_profile(event.parse({
        "slug": "hexy", "name": "h", "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "manual"}, "flag": {"prefixes": ["flag"], "body": "[0-9a-f]{8}"},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"}}, src="<t>"))
    assert ic.ocr_flags("flag(0a1b 2c3d)", hexy, ("flag",)) == ["flag{0a1b2c3d}"]     # only the form the body allows


# ---- the engine contract, routing, intake ----------------------------------------------------------

def test_challenge_files_prefer_the_sweep_copy_and_skip_recon(tmp_path):
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "a.png").write_bytes(b"x")
    assert set(ic.challenge_files(tmp_path)) == {"files/a.png"}
    (tmp_path / "unpacked" / "z.zip.unpacked").mkdir(parents=True)
    (tmp_path / "unpacked" / "a.png").write_bytes(b"x")
    (tmp_path / "unpacked" / "z.zip.unpacked" / "m.bmp").write_bytes(b"y")
    (tmp_path / "unpacked" / ".sweep.json").write_text("{}")
    (tmp_path / "unpacked" / "recon").mkdir()
    (tmp_path / "unpacked" / "recon" / "old.png").write_bytes(b"z")
    assert set(ic.challenge_files(tmp_path)) == {"unpacked/a.png", "unpacked/z.zip.unpacked/m.bmp"}
    with pytest.raises(FileNotFoundError):
        ic.challenge_files(tmp_path / "nope")


def test_images_route_here_and_to_carve_stego_in_any_category(tmp_path):
    from ctf.engines import router
    (tmp_path / "plate.png").write_bytes(_png(8, 8, 3, _noise_rows(8, 8, 3, seed=1)))
    ids = [h.manifest.id for h in router.route("misc", "Operation Dawn", tmp_path)]
    assert "toolkits.image_carve" in ids and "toolkits.carve_stego" in ids
    other = tmp_path / "other"
    other.mkdir()
    (other / "notes.txt").write_text("plain words")
    ids = [h.manifest.id for h in router.route("misc", "Operation Dawn", other)]
    assert "toolkits.image_carve" not in ids and "toolkits.carve_stego" not in ids
    ids = [h.manifest.id for h in router.route("forensics", "a cropped screenshot of the console", other)]
    assert ids[0] == "toolkits.image_carve"


def test_intake_runs_the_engine_on_a_dump_with_no_model(tmp_path):
    from ctf.engines import manifest
    from ctf.intake import engines as E
    from ctf.intake import guard as G
    ms = manifest.discover()
    dump, _png_, _at = _flotsam()
    cd = tmp_path / "9075-flotsam"
    (cd / "unpacked").mkdir(parents=True)
    (cd / "unpacked" / "recorder-sectors.img").write_bytes(dump)
    (cd / "unpacked" / "flag.png").write_bytes(
        _png(32, 32, 3, _noise_rows(32, 32, 3, seed=1)) + _zip({"f.txt": b"spooky{intake_saw_it}"}))
    allow = G.Guard("os", (), "test: spawn allowed, no OS wrapper (the suite sandbox denies the network)")
    p = E.plan(ms, "forensics", "a raw dump", cd / "unpacked", guard=allow)
    job = next(j for j in p.jobs if j.engine == "toolkits.image_carve")
    assert job.manifest.intake.run == "challenge" and job.manifest.intake.spawns
    hook = E.plan(ms, "forensics", "a raw dump", cd / "unpacked", guard=G.Guard("hook", (), "test"))
    assert "toolkits.image_carve" in {s.engine for s in hook.skipped}       # it starts tesseract: os guard only
    ctx = E.Context(challenge_dir=cd, folder=cd / "unpacked", out_root=cd / "recon" / "engines",
                    profile=event.load("spooky"), guard=allow, root=REPO, python=sys.executable,
                    challenge_id="9075", record=False)
    run = E.run_job(job, ctx)
    assert run.status == "ok", (cd / run.errors).read_text()
    assert run.flags == ("spooky{intake_saw_it}",)
    rebuilt = list((cd / "recon" / "image_carve").glob("unpacked_recorder-sectors.img.fragments-*.png"))
    assert len(rebuilt) == 1 and rebuilt[0].read_bytes() == _png_


def test_cli_prints_the_result_json_last(tmp_path, capsys):
    f = tmp_path / "spider.png"
    f.write_bytes(_png(16, 16, 3, _noise_rows(16, 16, 3, seed=1)) + _zip({"flag.txt": b"spooky{cli_path}"}))
    assert ic.main([str(f), "--event", "spooky", "--ocr", "off"]) == 0
    last = capsys.readouterr().out.strip().splitlines()[-1]
    d = json.loads(last)
    assert d["status"] == "solved" and d["flags"] == ["spooky{cli_path}"] and d["engine"] == "toolkits.image_carve"
    assert ic.main([str(tmp_path / "missing.png"), "--event", "spooky"]) == 2
