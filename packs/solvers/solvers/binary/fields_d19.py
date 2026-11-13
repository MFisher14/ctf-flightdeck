"""Day 19 live fix: the d19 sample's config sits in a packed PK19 overlay (Day 19 'static unpacking').

The question states the whole procedure: find the final PK19 overlay in the d19 member; k1 at +5, k2 at
+6, packed length u32le at +8, the unpacked SHA-256 at +12, packed bytes at +44; each byte
ror8(b ^ k2, 3) ^ k1; verify the SHA-256; the HCFG record is at unpacked offset 0 (CRC-32 checked, JSON).
Anything that does not verify answers None. overlay_offset is the magic's offset in the member,
overlay_size the member length minus it.
"""
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

MAGIC = b"PK19"   # the magic this unit names (Day 19); RS20 is Day 20's


def _ror8(v, n):
    return ((v >> n) | (v << (8 - n))) & 0xFF


def overlay(data: bytes):
    """(offset, unpacked bytes) of the final overlay magic, or None when it does not verify."""
    at = data.rfind(MAGIC)
    if at < 0:
        return None
    if at + 44 > len(data):
        return None
    k1, k2 = data[at + 5], data[at + 6]
    ln = struct.unpack_from("<I", data, at + 8)[0]
    want = data[at + 12:at + 44]
    packed = data[at + 44:at + 44 + ln]
    if len(packed) != ln:
        return None
    table = bytes(_ror8(b ^ k2, 3) ^ k1 for b in range(256))
    out = packed.translate(table)
    if hashlib.sha256(out).digest() != want:
        return None
    return at, out


def record(blob: bytes):
    if len(blob) < 12 or blob[:4] != b"HCFG":
        return None
    ver, key = blob[4], blob[5]
    ln, crc = struct.unpack_from("<HI", blob, 6)
    body = blob[12:12 + ln]
    if len(body) != ln:
        return None
    payload = bytes(b ^ key for b in body)
    if zlib.crc32(payload) != crc:
        return None
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    return {"version": ver, "key": key, "crc": crc, "config": obj}


def _qid(q):
    return q.get("qid") or q.get("id") or q.get("answer_id")


def fields(sample_name, data, questions):
    data = bytes(data)
    ov = overlay(data)
    if ov is None:
        return {}
    at, unpacked = ov
    rec = record(unpacked)
    out = {}
    for q in questions:
        qid = _qid(q)
        if not isinstance(qid, str) or "_" not in qid:
            continue
        field = qid.split("_", 1)[1]
        if field == "analysis_overlay_offset":
            out[qid] = str(at)
        elif field == "analysis_overlay_size":
            out[qid] = str(len(data) - at)
        elif rec is None:
            continue
        elif field == "analysis_config_crc32_hex":
            out[qid] = f"0x{rec['crc']:08x}"
        elif field == "analysis_hcfg_version":
            out[qid] = str(rec["version"])
        elif field.startswith("analysis_config_"):
            v = rec["config"].get(field[len("analysis_config_"):])
            if isinstance(v, str) and v:
                out[qid] = v
    return out


if __name__ == "__main__":
    blob = Path(sys.argv[1]).read_bytes()
    ov = overlay(blob)
    print("overlay", None if ov is None else (ov[0], len(blob) - ov[0], len(ov[1])))
    if ov:
        print(record(ov[1]))
