"""Hand-merge batch hm-07: the fixes carried on top of the CSCTF versions of binfmt, cloud_container and lang_sh.

All fixtures are synthetic bytes built here; nothing is executed.
"""
import gzip
import io
import struct
import tarfile

import binfmt as B
import cloud_container as engine
import lang_sh


# ---------------------------------------------------------------- binfmt.elf

def _elf_one_load(e_shoff, e_shnum=0, e_shentsize=64):
    """A 64-bit LE ELF with one PT_LOAD program header and a section header pointer of our choosing."""
    data = bytearray(0x100)
    data[:16] = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, 0x401000, 64, e_shoff, 0, 64, 56, 1,
                     e_shentsize, e_shnum, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0x400000, 0x100, 0x100, 0x1000)
    return bytes(data)


def test_elf_garbage_shoff_with_zero_shnum_keeps_program_headers():
    got = B.elf(_elf_one_load(e_shoff=0xDEADBEEF))      # section zero lies far outside the file
    assert got is not None
    assert got["sections"] is None
    assert got["segments"] is not None and len(got["segments"]) == 1
    seg = got["segments"][0]
    assert (seg["type"], seg["vaddr"], seg["filesz"]) == (1, 0x400000, 0x100)


def test_elf_short_shentsize_with_zero_shnum_keeps_program_headers():
    got = B.elf(_elf_one_load(e_shoff=0x80, e_shentsize=8))  # entry too small to hold section zero
    assert got["sections"] is None
    assert len(got["segments"]) == 1


# ---------------------------------------------------------------- cloud_container._ingest

def _tar(files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in files:
            item = tarfile.TarInfo(name)
            item.size = len(body)
            archive.addfile(item, io.BytesIO(body))
    return out.getvalue()


def test_damaged_non_evidence_gzip_is_skipped_not_cut():
    blob = gzip.compress(bytes(range(256)) * 64, mtime=0)
    ev = engine.load({"noise.bin.gz": blob[: len(blob) // 2]})
    assert ev.cut == set()


def test_damaged_gzip_holding_json_cuts_evidence():
    doc = b'{"resources": [' + b'{"type": "aws_s3_bucket", "name": "x"},' * 2000 + b'{}]}'
    blob = gzip.compress(doc, mtime=0)
    ev = engine.load({"state.json.gz": blob[: len(blob) // 2]})
    assert {"image", "logs", "tf", "files"} <= ev.cut
    assert any("did not open whole" in n for n in ev.notes)


def test_malformed_tar_is_a_note_not_a_cut():
    raw = bytearray(_tar([("a.txt", b"hello")]))
    raw[148:156] = b"0000000\0"                      # break the header checksum; 'ustar' magic stays
    assert engine.is_tar(bytes(raw))
    ev = engine.load({"broken.tar": bytes(raw)})
    assert ev.cut == set()
    assert any("broken.tar" in n and "did not open" in n for n in ev.notes)


def test_limit_cut_still_cuts_all_evidence():
    ev = engine.load({"big.tar": _tar([("a.txt", b"x" * 4096)])}, max_total=100)
    assert {"image", "logs", "tf", "files"} <= ev.cut


# ---------------------------------------------------------------- cloud_container.deleted_files

def _docker(layers):
    import hashlib
    import json

    def j(doc):
        return json.dumps(doc).encode()
    config = j({"rootfs": {"type": "layers",
                           "diff_ids": ["sha256:" + hashlib.sha256(b).hexdigest() for b in layers]}})
    names = [f"{i:064x}/layer.tar" for i in range(len(layers))]
    manifest = j([{"Config": "config.json", "RepoTags": ["t:1"], "Layers": names}])
    return {"manifest.json": manifest, "config.json": config, **dict(zip(names, layers))}


def test_deleted_files_can_list_recreated_paths():
    image = engine.read_image(_docker([_tar([("secret", b"old")]), _tar([(".wh.secret", b"")]),
                                       _tar([("secret", b"new")]), _tar([("gone", b"g")]),
                                       _tar([(".wh.gone", b"")])]))[0]
    assert [r["path"] for r in engine.deleted_files(image)] == ["gone"]
    rows = {r["path"]: r for r in engine.deleted_files(image, include_recreated=True)}
    assert set(rows) == {"secret", "gone"}
    assert rows["secret"]["recreated"] is True and rows["gone"]["recreated"] is False
    assert rows["secret"]["entry"].data == b"old"


# ---------------------------------------------------------------- lang_sh.answers

def test_lang_sh_answers_nothing_without_generic(monkeypatch, capsys):
    monkeypatch.setattr(lang_sh, "generic", None)
    q = {"qid": "q1", "member": "a.sh", "id": "x-steps", "text": "steps?"}
    assert lang_sh.answers([q], {"a.sh": b"echo hi\n"}, {}) == {}
    assert "generic.py not found" in capsys.readouterr().err
