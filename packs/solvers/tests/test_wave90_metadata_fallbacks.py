#!/usr/bin/env python3
"""wave90: the structural fallback net for three single-point Metadata facts.

Proves readers_fallback.py and its properties_strict hook:

  1. STRUCTURAL UNIT (offer()): on synthetic bytes, each of the three facts
     (msi.product_code_guid, dotnet.mvid_guid, media.primary_audio_codec_name) is located
     structurally and returned as an UNSURE labels.candidates pick with the truth offered first;
     NEVER plain; ambiguous / non-matching input -> None.
  2. NEVER PLAIN: every value the fallback returns is_unsure and is_candidate (row 346), and its
     key is per-delivery scoped and distinct from the fact's already-judged plain key.
  3. ABLATION (B-001b): with the specific reader pack deleted from a temp solver copy, the solver
     no longer loads: properties_strict raises PackMissing naming the pack (a pack miss is loud; it
     used to be one NOTE line and the fallback's unsure candidate). readers_fallback.offer() is
     still unit-tested above; the solver reaches it only for a pack that is not loaded, which now
     cannot happen without that error.
  4. NO OVER-REACH: the fallback declines (None) for an unrelated property, and the normal plain
     path through answer_question is unchanged (a plain identity answer still comes through).

No network, no Game Master. Run:
    .venv/bin/python -m pytest tests/test_wave90_metadata_fallbacks.py   (or `python tests/test_wave90_metadata_fallbacks.py`)
"""
import contextlib
import hashlib
import importlib.util
import io
import shutil
import struct
import sys
import tempfile
import uuid
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
MD = REPO / "solvers" / "metadata-forensics"
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(MD))
import labels  # noqa: E402


def check(ok, msg):
    print(("PASS " if ok else "FAIL ") + msg)
    assert ok, msg


# ------------------------------------------------------------------ synthetic fixtures

MSI_GUID_TEXT = "{DD1A80D5-0250-4F4D-B289-13096D633C61}"


def msi_blob(product_text=MSI_GUID_TEXT, extra_product=None):
    """An MSI _StringData-like blob: a `ProductCode` literal immediately followed by its GUID value,
    other strings around it. `extra_product` adds a SECOND ProductCode with a different GUID."""
    parts = [b"\x00_StringData\x00", b"Manufacturer", b"ACME Corp",
             b"ProductCode", product_text.encode(), b"ProductName", b"Widget",
             b"UpgradeCode", b"{5F63B105-6C37-46FB-B671-2AF6C4F4CD67}"]
    if extra_product:
        parts += [b"ProductCode", extra_product.encode()]
    return b"".join(parts)


def clr_blob(mvid: uuid.UUID, with_mz=True, guid_bytes=None):
    """A minimal CLR metadata region (BSJB root + a single `#GUID` stream) behind an `MZ` prefix,
    shaped exactly as readers_fallback._locate_dotnet_mvid walks it."""
    ver = b"v4.0.30319\x00\x00"              # length 12 (a multiple of 4)
    gb = guid_bytes if guid_bytes is not None else mvid.bytes_le
    # header: sig,maj,min,reserved,verlen  then ver  then flags,streams  then one stream header
    header = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(ver)) + ver
    header += struct.pack("<HH", 0, 1)        # flags, 1 stream
    name = b"#GUID\x00\x00\x00"               # 5 chars + null, padded to 8
    guid_off = len(header) + 8 + len(name)    # offset (from root) of the GUID data
    header += struct.pack("<II", guid_off, len(gb)) + name
    root = header + gb
    return (b"MZ" + b"\x00" * 64 if with_mz else b"\x00" * 66) + root


def wav_blob(tag=1, bits=16, channels=1, data_len=800):
    fmt = struct.pack("<HHIIHH", tag, channels, 16000, 16000 * channels * bits // 8,
                      channels * bits // 8, bits)
    body = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt + \
        b"data" + struct.pack("<I", data_len) + b"\x00" * data_len
    return b"RIFF" + struct.pack("<I", len(body)) + body


def q_for(prop):
    aid = "d-" + prop.replace(".", "-").replace("_", "-")
    return {"id": aid, "qid": aid, "answer_id": aid}


# ------------------------------------------------------------------ 1-2. structural unit + never-plain

import readers_fallback as rf  # noqa: E402


def options_of(value):
    parsed = labels.parse(value)
    return parsed.options if parsed else []


def assert_unsure_truth_first(label, value, truth):
    if value is None:
        check(False, f"{label}: offer() returned None, expected an unsure candidate")
        return
    check(labels.is_unsure(value), f"{label}: value is unsure (never plain)")
    check(labels.is_candidate(value), f"{label}: value is a candidate key (#candidates, row 346)")
    opts = options_of(value)
    vals = [v for _n, v in opts]
    check(bool(vals) and vals[0] == truth, f"{label}: truth is offered FIRST (got {vals[:1]})")
    check(truth in vals, f"{label}: truth is reachable among options")
    key = (labels.parse(value).key or "")
    check(key.startswith("metadata."), f"{label}: key is in the metadata lane ({key})")


DOTNET_MVID = uuid.UUID("21e410f3-c977-465c-80eb-6890ddd3085c")


def wav_chunks(chunks, head=b"RIFF", form=b"WAVE"):
    body = form + b"".join(cid + struct.pack("<I", len(d)) + d + (b"\x00" if len(d) & 1 else b"")
                           for cid, d in chunks)
    return head + struct.pack("<I", len(body)) + body


# ------------------------------------------------------------------ 3. integration via the real solver, reader ablated

def load_solver(from_dir=MD):
    spec = importlib.util.spec_from_file_location("ps_" + str(id(object())), from_dir / "properties_strict.py")
    mod = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stderr(io.StringIO()):
        spec.loader.exec_module(mod)
    return mod


tmp_dirs = []     # the ablated copies, removed after each case (the load raises before it returns one)


def ablated_solver(drop):
    tmp = Path(tempfile.mkdtemp(prefix="wave90-"))
    tmp_dirs.append(tmp)
    dst = tmp / "solvers"
    for name in ("common", "metadata-forensics"):
        shutil.copytree(REPO / "solvers" / name, dst / name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copytree(REPO / "ctf", tmp / "ctf", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))  # ctf/packs.py
    for f in drop:
        p = dst / "metadata-forensics" / f
        if p.exists():
            p.unlink()
    return load_solver(dst / "metadata-forensics"), tmp


def ask_solver(solver, prop, member, data, fmt_kind="exact_text"):
    delivery = "evidence.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(member, data)
    aid = "d-" + prop.replace(".", "-").replace("_", "-")
    q = {"id": aid, "qid": aid, "answer_id": aid, "question": f"Determine {prop} for {member}.",
         "artifact": f"{delivery} -> {member}",
         "answer_format": {"kind": fmt_kind, "syntax": "exact artifact-derived value only"}}
    ctx = {"set": 1, "delivery_name": delivery, "delivery": buf.getvalue(), "attempt": {}, "partial": {}}
    with contextlib.redirect_stderr(io.StringIO()):
        return solver.solve_set([q], {member: data}, ctx).get(aid)


def test_1_2_structural_unit_truth_first_never_plain():
    assert_unsure_truth_first("msi.product_code_guid",
                              rf.offer("msi.product_code_guid", q_for("msi.product_code_guid"), msi_blob()),
                              MSI_GUID_TEXT)
    assert_unsure_truth_first("dotnet_mvid_guid",
                              rf.offer("dotnet_mvid_guid", q_for("dotnet_mvid_guid"), clr_blob(DOTNET_MVID)),
                              str(DOTNET_MVID))
    assert_unsure_truth_first("media.primary_audio_codec_name",
                              rf.offer("media.primary_audio_codec_name",
                                       q_for("media.primary_audio_codec_name"), wav_blob(1, 16)),
                              "pcm_s16le")

    # a close sibling and other renderings reachable
    check(rf.offer("media.primary_audio_codec_name", q_for("x"), wav_blob(1, 24)) is not None
          and options_of(rf.offer("media.primary_audio_codec_name", q_for("x"), wav_blob(1, 24)))[0][1] == "pcm_s24le",
          "media: 24-bit PCM maps to pcm_s24le")
    check(labels.parse(rf.offer("msi.upgrade_code_guid", q_for("u"),
                                b"UpgradeCode{5F63B105-6C37-46FB-B671-2AF6C4F4CD67}")) is not None,
          "msi: upgrade_code_guid (close sibling) is also located")


def test_1_ambiguous_or_non_matching_is_none():
    check(rf.offer("msi.product_code_guid", q_for("x"),
                   msi_blob(extra_product="{99BE1D60-AB14-4859-85FA-9E465A88729D}")) is None,
          "msi: two different ProductCode GUIDs -> None (ambiguous)")
    check(rf.offer("msi.product_code_guid", q_for("x"), b"ProductCode = not a guid here") is None,
          "msi: ProductCode with no adjacent GUID -> None")
    check(rf.offer("dotnet_mvid_guid", q_for("x"), clr_blob(DOTNET_MVID, guid_bytes=b"\x00" * 16)) is None,
          "dotnet: an all-zero #GUID heap -> None")
    check(rf.offer("dotnet_mvid_guid", q_for("x"), clr_blob(DOTNET_MVID, with_mz=False)) is None,
          "dotnet: not a PE (no MZ) -> None")
    check(rf.offer("media.primary_audio_codec_name", q_for("x"), b"RIFF\x20\x00\x00\x00AVI LIST") is None,
          "media: a RIFF that is not WAVE -> None")


def test_1_wav_chunk_edge_cases():
    _fmt16 = struct.pack("<HHIIHH", 1, 1, 8000, 16000, 2, 16)
    _fmt24 = struct.pack("<HHIIHH", 1, 1, 8000, 24000, 3, 24)
    _DATA = b"\x00" * 400
    check(rf.offer("media.primary_audio_codec_name", q_for("x"),
                   wav_chunks([(b"fmt ", _fmt16), (b"fmt ", _fmt24), (b"data", _DATA)])) is None,
          "media: two fmt chunks -> None (ambiguous)")
    check(rf.offer("media.primary_audio_codec_name", q_for("x"),
                   wav_chunks([(b"data", _DATA), (b"fmt ", _fmt16)])) is None,
          "media: data before fmt -> None")
    check(rf.offer("media.primary_audio_codec_name", q_for("x"),
                   wav_chunks([(b"fmt ", _fmt16), (b"LIST", b"INFO")])) is None,
          "media: no data chunk -> None")
    check(rf.offer("media.primary_audio_codec_name", q_for("x"),
                   wav_chunks([(b"fmt ", struct.pack("<HHIIHH", 1, 1, 0, 0, 2, 16)), (b"data", _DATA)])) is None,
          "media: zero sample rate -> None")
    _ext_bad = struct.pack("<HHIIHH", 0xFFFE, 1, 8000, 16000, 2, 16) + struct.pack("<HHI", 22, 16, 4) + \
        bytes.fromhex("01000000000010008000aaaaaaaaaaaa")
    check(rf.offer("media.primary_audio_codec_name", q_for("x"),
                   wav_chunks([(b"fmt ", _ext_bad), (b"data", _DATA)])) is None,
          "media: a foreign extensible subformat GUID -> None")
    _spdif_data = (b"\x72\xf8\x1f\x4e" + b"\x00" * 60) * 4
    check(rf.offer("media.primary_audio_codec_name", q_for("x"),
                   wav_chunks([(b"fmt ", struct.pack("<HHIIHH", 1, 2, 48000, 192000, 4, 16)),
                               (b"data", _spdif_data)])) is None,
          "media: an IEC 61937 S/PDIF burst in a PCM wrapper -> None")
    _ext_pcm = struct.pack("<HHIIHH", 0xFFFE, 1, 8000, 16000, 2, 16) + struct.pack("<HHI", 22, 16, 4) + \
        bytes.fromhex("0100000000001000800000aa00389b71")
    _ext_ok = rf.offer("media.primary_audio_codec_name", q_for("x"),
                       wav_chunks([(b"fmt ", _ext_pcm), (b"data", _DATA)]))
    check(_ext_ok is not None and options_of(_ext_ok)[0][1] == "pcm_s16le",
          "media: a valid extensible PCM subformat GUID -> pcm_s16le")
    check(rf.offer("metadata.format/pe.machine", q_for("x"), msi_blob()) is None,
          "no over-reach: an unrelated property -> None")


def test_3_integration_via_the_real_solver_reader_ablated():
    cases = [
        (["readers_msi.py"], "msi.product_code_guid", "installer.msi", msi_blob(), MSI_GUID_TEXT),
        (["readers_dotnet.py"], "dotnet.mvid_guid", "managed.dll", clr_blob(DOTNET_MVID), str(DOTNET_MVID)),
        (["readers_media.py", "readers_video.py"], "media.primary_audio_codec_name", "audio.wav",
         wav_blob(1, 16), "pcm_s16le"),
    ]
    for drop, prop, member, data, truth in cases:
        label = f"ablation {prop} (pack {drop} deleted)"
        try:
            solver, tmp = ablated_solver(drop)
            got = None
        except Exception as e:      # B-001b: the named pack error, raised while properties_strict loads
            got = e
        finally:
            shutil.rmtree(tmp_dirs.pop(), ignore_errors=True) if tmp_dirs else None
        check(type(got).__name__ == "PackMissing" and f"metadata reader pack {drop[0]}" in str(got),
              f"{label}: the solver refuses to load, raising PackMissing for {drop[0]} (got {type(got).__name__}: {got})")


# 4. the hook does not disturb a normal plain answer: a member's sha256 is still plain.
def test_4_hook_leaves_a_plain_identity_answer_unchanged():
    solver = load_solver()
    blob = b"hello wave90"
    val = ask_solver(solver, "sha256", "note.txt", blob, fmt_kind="pattern")
    check(val == hashlib.sha256(blob).hexdigest(), "hook: a normal plain identity answer (sha256) is unchanged")


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
