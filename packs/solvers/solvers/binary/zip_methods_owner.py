"""Shared reader for `analysis_compression_methods` (Day 8 asks it of the d06 and d07 jars).

The fact: the zip compression method numbers of the archive's entries, distinct, in the order they
first appear in the central directory (for the base jars: stored, then deflate). The judge's
spelling (numbers or names) and order are not judged yet, so the answer is labels.pick with one
key for every jar: binary.compression_methods/zip. Values are JSON arrays (compact).

Day 8 judged the numbers (`[0,8]`, the reading `int`). In every archive it judged the order of first
appearance is also the ascending order, so which of the two the judge means is not known. An archive
where they differ (a deflated entry before the first stored one) is therefore answered under a key
of its own, binary.compression_methods/zip+order, with both orders as options: never the accepted
reading's plain value (tests/variants.py's decoy_before found it: `[8,0]` where the key says `[0,8]`).
"""
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
import labels  # noqa: E402

NAMES = {0: "stored", 8: "deflate", 9: "deflate64", 12: "bzip2", 14: "lzma", 93: "zstd", 95: "xz", 99: "aes"}
NAMES_ED = {0: "stored", 8: "deflated", 9: "deflate64", 12: "bzip2", 14: "lzma", 93: "zstd", 95: "xz", 99: "aes"}
PY = {0: "ZIP_STORED", 8: "ZIP_DEFLATED", 12: "ZIP_BZIP2", 14: "ZIP_LZMA"}


def methods(data):
    """Distinct methods in first-appearance order, or None when data is not a readable zip."""
    if not isinstance(data, (bytes, bytearray)) or data[:2] != b"PK":
        return None
    try:
        z = zipfile.ZipFile(io.BytesIO(bytes(data)))
        seen = []
        for i in z.infolist():
            if i.compress_type not in seen:
                seen.append(i.compress_type)
        return seen or None
    except Exception:
        return None


def answer(data):
    ms = methods(data)
    if not ms or any(m not in NAMES for m in ms):
        return None
    srt = sorted(ms)
    if srt != ms:
        return labels.pick("binary.compression_methods/zip+order", [("ascending", srt), ("first_appearance", list(ms))])
    opts = [
        ("names", [NAMES[m] for m in ms]),
        ("int", list(ms)),
        ("names_ed", [NAMES_ED[m] for m in ms]),
        ("int_str", [str(m) for m in ms]),
        ("upper", [NAMES[m].upper() for m in ms]),
        ("upper_ed", [NAMES_ED[m].upper() for m in ms]),
    ]
    if all(m in PY for m in ms):
        opts.append(("python", [PY[m] for m in ms]))
    return labels.pick("binary.compression_methods/zip", opts)


def fields_for(prefix, sample_name, data, questions):
    out = {}
    for q in questions:
        qid = q.get("qid") or q.get("id") or q.get("answer_id")
        field = qid.split("_", 1)[1] if "_" in qid else qid
        if field == "analysis_compression_methods":
            v = answer(data)
            if v is not None:
                out[qid] = v
    return out
