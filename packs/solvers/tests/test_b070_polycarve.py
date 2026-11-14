"""B-070: polyglot carve recursion (ctf/polycarve.py) and its place in the sweep (ctf/sweep.py).

An archive inside or behind an image goes back into the archive walk, so its members are unpacked,
hashed and searched. Every fixture is built here; nothing is executed and nothing touches the network.
"""
import gzip
import io
import zipfile

import pytest

import archive_expand
import b070_fixtures as fx
from ctf import event, polycarve, sweep

CSCTF = event.load("csctf")
FLAG = b"CSCTF{carved_out_of_the_icon}"


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    monkeypatch.setattr(archive_expand.pw, "candidates", lambda: [b"infected"])


def chains(rep) -> list:
    return [" -> ".join(e.chain) for e in rep.manifest]


# ---------------------------------------------------------------- carve(): one content

def test_a_zip_after_a_png_is_carved_at_the_exact_offset_and_only_once():
    png = fx.png()
    z = fx.zip_bytes({"k/flag.txt": FLAG * 8, "k/more.txt": b"x" * 50})
    notes = []
    got = polycarve.carve(("icon.png",), png + z, None, notes)
    assert got == [(f"carved@0x{len(png):x}.zip", z)]          # the zip's own bytes, nothing of the image
    assert len(notes) == 1 and "after its end" in notes[0] and "member CRCs" in notes[0]
    assert polycarve.carve(("icon.png",), png, None, []) == []  # an image and nothing else gives nothing


@pytest.mark.parametrize("kind,make", [("png", fx.png), ("jpeg", fx.jpeg), ("gif", fx.gif), ("bmp", fx.bmp),
                                       ("webp", fx.webp)])
def test_every_image_kind_is_a_host_with_a_validated_end(kind, make):
    img = make()
    z = fx.zip_bytes({"k/flag.txt": FLAG * 8})
    assert polycarve.image_kind(img) == kind
    assert polycarve.host_end(img, kind) == (len(img), "validated")
    notes = []
    assert polycarve.carve((f"a.{kind}",), img + z, None, notes) == [(f"carved@0x{len(img):x}.zip", z)]
    assert f"of the {kind} image (after its end" in notes[0]
    # bytes that are no archive, after the validated end, are the overlay: exactly those bytes
    assert polycarve.carve((f"a.{kind}",), img + b"key=hunter2;", None, []) == [(f"overlay@0x{len(img):x}.bin", b"key=hunter2;")]


def test_only_an_image_is_a_carve_host():
    z = fx.zip_bytes({"a.txt": b"hello" * 30})
    for host in (b"plain text first\n", b"\x7fELF" + bytes(60), b"%PDF-1.4\n" + bytes(40), z):
        assert polycarve.image_kind(host + z) is None
        assert polycarve.carve(("x.bin",), host + z, None, []) == []
    assert [polycarve.image_kind(d) for d in (fx.png(), fx.gif(), b"\xff\xd8\xff\xe0" + bytes(8))] == ["png", "gif", "jpeg"]


def test_a_zip_whose_directory_counts_from_the_start_of_the_image_still_opens():
    png = fx.png()
    z = fx.zip_bytes({"abs.txt": b"offsets from the file start " * 4})
    shifted = fx.shift_zip(z, len(png))
    assert shifted != z
    got = polycarve.carve(("a.png",), png + shifted, None, [])
    assert [n for n, _ in got] == [f"carved@0x{len(png):x}.zip"]
    walk = archive_expand.Walk()
    rows = polycarve.cascade([(("a.png",), png + shifted)], walk, [], archive_expand)
    assert (("a.png", f"carved@0x{len(png):x}.zip", "abs.txt"), b"offsets from the file start " * 4) in rows


def test_a_stream_stored_inside_the_carved_zip_is_not_carved_a_second_time():
    inner = gzip.compress(b"a stream stored in the zip " * 5, mtime=0)
    z = fx.zip_bytes({"log.gz": inner}, compression=zipfile.ZIP_STORED)
    png = fx.png()
    assert inner in z                                           # stored: the gzip stream is visible in the zip
    got = polycarve.carve(("a.png",), png + z, None, [])
    assert [n for n, _ in got] == [f"carved@0x{len(png):x}.zip"]


def test_an_overlay_the_walk_opens_is_not_also_carved_from_the_inside(tmp_path):
    import tarfile
    inner = fx.zip_bytes({"flag.txt": FLAG * 3})
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        info = tarfile.TarInfo("inner.zip")
        info.size, info.mtime = len(inner), 0
        tf.addfile(info, io.BytesIO(inner))
    tar, png = bio.getvalue(), fx.png()
    assert inner in tar                                         # a tar stores its members as they are
    got = polycarve.carve(("a.png",), png + tar, None, [])
    assert got == [(f"overlay@0x{len(png):x}.bin", tar)]        # the tar; not the zip inside it a second time
    rep = sweep.sweep(fx.pulled(tmp_path, {"a.png": png + tar}), CSCTF)
    assert chains(rep) == ["a.png", f"a.png -> overlay@0x{len(png):x}.bin",
                           f"a.png -> overlay@0x{len(png):x}.bin -> inner.zip",
                           f"a.png -> overlay@0x{len(png):x}.bin -> inner.zip -> flag.txt"]
    assert rep.result.flags == (FLAG.decode(),)


def test_two_archives_behind_one_image_are_both_carved_in_offset_order():
    png = fx.png()
    z = fx.zip_bytes({"one.txt": b"1" * 40})
    g = gzip.compress(b"second archive " * 6, mtime=0)
    got = polycarve.carve(("a.png",), png + z + g, None, [])
    assert got == [(f"carved@0x{len(png):x}.zip", z), (f"carved@0x{len(png) + len(z):x}.gz", g)]


def test_an_archive_in_a_private_chunk_is_carved_from_inside_the_image():
    z = fx.zip_bytes({"in/chunk.txt": b"inside the image " * 4})
    data = fx.png(private=z)
    at = data.index(z)
    notes = []
    got = polycarve.carve(("a.png",), data, None, notes)
    assert got == [(f"carved@0x{at:x}.zip", z)]
    assert "inside it" in notes[0] and "after its end" not in notes[0]


def _tar_holding(name: str, body: bytes) -> bytes:
    import tarfile
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        info = tarfile.TarInfo(name)
        info.size, info.mtime = len(body), 0
        tf.addfile(info, io.BytesIO(body))
    return bio.getvalue()


@pytest.mark.parametrize("behind", ["rar", "tar"])
def test_an_archive_inside_the_image_is_kept_when_the_overlay_is_one_the_walk_opens(behind):
    # Verification finding (round 1): an overlay the walk opens used to hide every archive, including the
    # one inside the image before its end.
    z = fx.zip_bytes({"in/chunk.txt": b"inside the image " * 4})
    data = fx.png(private=z)
    at, end = data.index(z), len(data)
    if behind == "rar":
        tail = b"Rar!\x1a\x07\x00" + b"junk that is no real rar body " * 3
    else:
        tail = _tar_holding("inner.zip", fx.zip_bytes({"t.txt": b"in the tar " * 5}))
    got = polycarve.carve(("a.png",), data + tail, None, [])
    # the chunk's zip, and the overlay; nothing carved from inside the overlay (the tar's zip is the walk's)
    assert got == [(f"carved@0x{at:x}.zip", z), (f"overlay@0x{end:x}.bin", tail)]


def test_sweep_reads_a_chunk_zip_beside_an_overlay_the_walk_opens(tmp_path):
    z = fx.zip_bytes({"in/chunk.txt": FLAG * 3})
    data = fx.png(private=z)
    tail = _tar_holding("inner.zip", fx.zip_bytes({"t.txt": b"in the tar " * 5}))
    rep = sweep.sweep(fx.pulled(tmp_path, {"a.png": data + tail}), CSCTF)
    assert rep.result.flags == (FLAG.decode(),)
    assert f"a.png -> carved@0x{data.index(z):x}.zip -> in/chunk.txt" in chains(rep)
    assert f"a.png -> overlay@0x{len(data):x}.bin -> inner.zip -> t.txt" in chains(rep)
    carved = {part for c in chains(rep) for part in c.split(" -> ") if part.startswith("carved@")}
    assert carved == {f"carved@0x{data.index(z):x}.zip"}          # the tar's zip is not carved a second time


def test_trailing_bytes_that_are_no_validated_archive_become_an_overlay_member():
    png = fx.png()
    notes = []
    assert polycarve.carve(("a.png",), png + b"the key is hunter2\n", None, notes) == \
        [(f"overlay@0x{len(png):x}.bin", b"the key is hunter2\n")]
    assert "19 bytes follow the png image's end" in notes[0] and "validated" in notes[0]
    second = fx.png(text={"Comment": "second image"})
    assert polycarve.carve(("a.png",), png + second, None, []) == [(f"overlay@0x{len(png):x}.bin", second)]
    # padding, or fewer than MIN_OVERLAY real bytes, is not a member
    assert polycarve.carve(("a.png",), png + b"\n\x00\x00  \r\n", None, []) == []
    assert polycarve.carve(("a.png",), png + b"\n" + b"x" * (polycarve.MIN_OVERLAY - 1), None, []) == []
    assert len(polycarve.carve(("a.png",), png + b"\n" + b"x" * polycarve.MIN_OVERLAY, None, [])) == 1


def test_host_end_is_validated_or_structural_or_none():
    good, bad = fx.png(), fx.png(break_crc=True)
    assert polycarve.host_end(good, "png") == (len(good), "validated")
    assert polycarve.host_end(bad, "png") == (len(bad), "structural")     # carving.py rejects the CRC
    cut = good[:-12]                                                      # no IEND at all
    end, why = polycarve.host_end(cut, "png")
    assert end is None and "png image whose end cannot be found" in why
    z = fx.zip_bytes({"a.txt": b"behind a damaged image " * 3})
    got = polycarve.carve(("a.png",), bad + z, None, [])
    assert got == [(f"carved@0x{len(bad):x}.zip", z)]                     # no overlay twin beside the carve
    # a valid image later in the file is not the host: the end is the first image's, by its structure
    assert polycarve.host_end(bad + good, "png") == (len(bad), "structural")
    assert polycarve.carve(("a.png",), bad + good, None, []) == [(f"overlay@0x{len(bad):x}.bin", good)]


def test_an_image_that_cannot_be_bounded_with_a_zip_signature_says_so():
    cut = fx.png()[:-12]
    notes = []
    assert polycarve.carve(("a.png",), cut + b"PK\x05\x06" + bytes(4), None, notes) == []
    assert any("zip end-of-directory signature" in n and "carve it by hand" in n for n in notes)


def test_an_image_over_the_carve_limit_is_a_note_not_a_silent_skip(monkeypatch):
    monkeypatch.setattr(polycarve._carving(), "MAX_SCAN", 100)
    data = fx.png() + fx.zip_bytes({"a.txt": b"y" * 200})
    notes = []
    assert len(data) > 100 and polycarve.carve(("a.png",), data, None, notes) == []
    assert any("over the carve limit of 100" in n for n in notes)


def test_a_carved_piece_counts_against_the_walk_budget():
    png = fx.png()
    z = fx.zip_bytes({"a.txt": b"z" * 300})
    walk = archive_expand.Walk(max_member=len(z) - 1)
    notes = []
    assert polycarve.cascade([(("a.png",), png + z)], walk, notes, archive_expand) == []
    assert any("over the member limit" in n for n in walk.notes)
    assert len(z) < 300
    walk = archive_expand.Walk(max_member=300)
    rows = polycarve.cascade([(("a.png",), png + z)], walk, [], archive_expand)
    assert [c for c, _ in rows] == [("a.png", f"carved@0x{len(png):x}.zip"),
                                    ("a.png", f"carved@0x{len(png):x}.zip", "a.txt")]
    assert walk.count == 2 and walk.total == len(z) + 300      # the piece and its member, both counted


def test_cascade_survives_a_carver_that_raises_and_goes_on(monkeypatch):
    png = fx.png()
    z = fx.zip_bytes({"ok.txt": b"still here " * 5})
    real = polycarve.carve

    def flaky(chain, data, walk, notes):
        if chain == ("bad.png",):
            raise RuntimeError("hostile bytes")
        return real(chain, data, walk, notes)
    monkeypatch.setattr(polycarve, "carve", flaky)
    notes = []
    rows = polycarve.cascade([(("bad.png",), png + z), (("good.png",), png + z)], archive_expand.Walk(), notes,
                             archive_expand)
    assert [c[0] for c, _ in rows] == ["good.png", "good.png"]
    assert any(n.startswith("bad.png: carving failed") and "RuntimeError: hostile bytes" in n for n in notes)


def test_cascade_is_one_level_the_output_is_not_carved_again():
    inner = fx.gif() + fx.zip_bytes({"deep.txt": b"two levels down " * 3})
    outer = fx.png() + fx.zip_bytes({"inner.gif": inner})
    rows = polycarve.cascade([(("outer.png",), outer)], archive_expand.Walk(), [], archive_expand)
    names = [c[-1] for c, _ in rows]
    assert names == [f"carved@0x{len(fx.png()):x}.zip", "inner.gif"]


# ---------------------------------------------------------------- in the sweep

def test_sweep_finds_a_flag_deflated_in_a_zip_behind_a_png(tmp_path):
    png = fx.png()
    data = png + fx.zip_bytes({"k/flag.txt": FLAG + b"\n" + b"padding " * 40})
    assert FLAG not in data                                      # deflated: the raw bytes do not show it
    ch = fx.pulled(tmp_path, {"telemetry_icon.png": data})
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.status == "solved" and rep.result.flags == (FLAG.decode(),)
    carved = f"telemetry_icon.png -> carved@0x{len(png):x}.zip"
    assert chains(rep) == ["telemetry_icon.png", carved, carved + " -> k/flag.txt"]
    hit = rep.flags[FLAG.decode()][0]
    assert rep._locations()[hit.sha256] == [carved + " -> k/flag.txt"] and hit.method == "plain"
    member = ch / "unpacked" / "telemetry_icon.png.unpacked" / f"carved@0x{len(png):x}.zip.unpacked" / "k" / "flag.txt"
    assert member.read_bytes().startswith(FLAG)                  # written to the scratch copy, findable by path
    assert any("a zip archive of" in n and "telemetry_icon.png" in n for n in rep.notes)
    assert (ch / "files" / "telemetry_icon.png").read_bytes() == data   # the original is untouched


def test_sweep_carves_an_image_that_is_itself_an_archive_member(tmp_path):
    png = fx.png()
    icon = png + fx.zip_bytes({"flag.txt": FLAG * 3})
    ch = fx.pulled(tmp_path, {"handout.zip": fx.zip_bytes({"assets/icon.png": icon, "README.md": b"hi"})})
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.flags == (FLAG.decode(),)
    assert f"handout.zip -> assets/icon.png -> carved@0x{len(png):x}.zip -> flag.txt" in chains(rep)


def test_sweep_recurses_image_in_archive_in_image(tmp_path):
    gif, png = fx.gif(), fx.png()
    inner = gif + fx.zip_bytes({"deep/flag.txt": FLAG * 4})
    outer = png + fx.zip_bytes({"inner.gif": inner})
    assert FLAG not in outer
    ch = fx.pulled(tmp_path, {"outer.png": outer})
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.status == "solved" and rep.result.flags == (FLAG.decode(),)
    want = (f"outer.png -> carved@0x{len(png):x}.zip -> inner.gif -> carved@0x{len(gif):x}.zip -> deep/flag.txt")
    assert want in chains(rep)
    assert len(chains(rep)) == len(set(chains(rep)))             # each member once: nothing carved twice


def test_sweep_stops_recursing_at_the_round_limit_and_says_so(tmp_path, monkeypatch):
    gif, png = fx.gif(), fx.png()
    inner = gif + fx.zip_bytes({"deep/flag.txt": FLAG * 4})
    outer = png + fx.zip_bytes({"inner.gif": inner})
    monkeypatch.setattr(sweep, "DEEPEN", 1)
    rep = sweep.sweep(fx.pulled(tmp_path, {"outer.png": outer}), CSCTF)
    assert rep.result.flags == ()                                # the inner image was reached, not carved
    assert f"outer.png -> carved@0x{len(png):x}.zip -> inner.gif" in chains(rep)
    assert any("not searched for further images or archives (limit of 1 rounds)" in n for n in rep.notes)


def test_sweep_opens_a_gzip_stream_behind_a_gif(tmp_path):
    gif = fx.gif()
    data = gif + gzip.compress(b"log line\n" * 20 + FLAG + b"\n", mtime=0)
    assert FLAG not in data
    rep = sweep.sweep(fx.pulled(tmp_path, {"anim.gif": data}), CSCTF)
    assert rep.result.flags == (FLAG.decode(),)
    assert any(c.startswith(f"anim.gif -> carved@0x{len(gif):x}.gz -> ") for c in chains(rep))


@pytest.mark.needs_tool("py:pyzipper")
def test_an_encrypted_zip_behind_an_image_is_opened_through_the_overlay(tmp_path):
    import pyzipper
    bio = io.BytesIO()
    with pyzipper.AESZipFile(bio, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b"infected")
        z.writestr("locked/flag.txt", FLAG * 2)
    png = fx.png()
    data = png + bio.getvalue()
    assert FLAG not in data
    # its member CRCs cannot be checked without the password, so it is not a validated carve ...
    assert [n for n, _ in polycarve.carve(("a.png",), data, None, [])] == [f"overlay@0x{len(png):x}.bin"]
    # ... and the walk opens the overlay with the known archive passwords
    rep = sweep.sweep(fx.pulled(tmp_path, {"a.png": data}), CSCTF)
    assert rep.result.flags == (FLAG.decode(),)
    assert f"a.png -> overlay@0x{len(png):x}.bin -> locked/flag.txt" in chains(rep)


def test_an_image_with_nothing_behind_it_adds_no_member_and_no_note(tmp_path):
    ch = fx.pulled(tmp_path, {"plain.png": fx.png(text={"Comment": "nothing here"}), "note.txt": b"hello"})
    rep = sweep.sweep(ch, CSCTF)
    assert chains(rep) == ["note.txt", "plain.png"]
    assert not any("carved" in n or "overlay" in n or "follow the" in n for n in rep.notes)
    assert rep.to_dict()["git"] == []
