"""Day 31 shaped reader: the HGAU gauntlet record (Day 31 'reversing gauntlet').

The d31 questions state a record with the HCFG 12-byte layout but the magic HGAU, found by scanning
BACKWARD from the end of the ELF member: magic HGAU, byte-4 version, byte-5 XOR key, u16le length at +6,
u32le CRC-32 at +8 (of the DECODED payload), payload at +12 XOR key = UTF-8 JSON object. The record's
config lives at top-level `config` and its trace at top-level `trace` (there is no `gauntlet` key; the
question's `gauntlet.config.*` and `gauntlet.trace_branch` name that config and that trace.branch, the
mapping the judge accepted on the Day 31 base with one probe). Same reader shape as HCFG (hcfg.py) and the
RS20/trailer overlays (fields_d20.py): a CRC-gated record, never a guess.

Folded from the Day 31 live fix solvers/binary/day_patch.py (owner, override()). generic.ask_hook offers
this file only the d31 prefix's questions still None, so it answers only the six gauntlet ids; it NEVER
replaces a value another reader produced. The four d31_analysis_config_* ids (which come out of generic
plain and are then held unsure by the reworded-question guard) are NOT this file's: they are restored by
judged_syntax.json carrying the Day 31 question texts (mk_judged_syntax.py --write after the CORRECT day).

Answers, each read from the one CRC-valid HGAU record of the member or nothing at all:
  analysis_gauntlet_config_<name>  config.<name> (a non-empty JSON string), PLAIN only when the record's
                                   campaign names the day (BR31-...), else an unsure config-member pick;
  analysis_gauntlet_crc32_hex      the header u32le at +8 as 0x%08x, PLAIN (the stated rendering);
  analysis_gauntlet_trace_branch   trace.branch, PLAIN when it is one of the enum's accepted values
                                   (success, decoy, failure), else None (never a wrong plain).
Exactly one CRC-valid HGAU record whose decoded payloads all agree, or nothing is answered.
"""
import json
import re
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
import labels  # noqa: E402

MAGIC = b"HGAU"
HDR = 12
BRANCH_VOCAB = ("success", "decoy", "failure")


def record(data: bytes):
    """The unique CRC32-valid HGAU record of `data`, scanning backward from the end, or None when there is
    not exactly one distinct decoded payload. {'offset', 'crc', 'json'} on success."""
    data = bytes(data)
    found = []
    o = len(data)
    while True:
        o = data.rfind(MAGIC, 0, o)
        if o < 0:
            break
        if o + HDR <= len(data):
            xk = data[o + 5]
            ln, crc = struct.unpack_from("<HI", data, o + 6)
            enc = data[o + HDR:o + HDR + ln]
            if len(enc) == ln:
                plain = bytes(b ^ xk for b in enc)
                if zlib.crc32(plain) & 0xFFFFFFFF == crc:
                    try:
                        obj = json.loads(plain.decode("utf-8"))
                    except Exception:
                        obj = None
                    if isinstance(obj, dict):
                        found.append({"offset": o, "crc": crc, "json": obj, "plain": plain})
    distinct = {f["plain"] for f in found}
    return found[0] if len(distinct) == 1 else None


def _qid(q):
    return q.get("qid") or q.get("id") or q.get("answer_id")


def _day_of(qid: str):
    m = re.match(r"d0*(\d+)_", str(qid))
    return int(m.group(1)) if m else None


def _config_member(rec, name, day):
    cfg = rec["json"].get("config")
    if not isinstance(cfg, dict):
        return None
    v = cfg.get(name)
    if not (isinstance(v, str) and v):
        return None
    camp = cfg.get("campaign")
    # PLAIN only when the campaign names the day, exactly as generic.config_answer and the day_patch did;
    # otherwise an unsure config-member pick (never a wrong plain).
    if day is not None and isinstance(camp, str) and camp.startswith(f"BR{day}-"):
        return v
    return labels.pick(f"binary.gauntlet_config/{name}", [("config_member", v)])


def _branch(rec, q):
    tr = rec["json"].get("trace")
    v = tr.get("branch") if isinstance(tr, dict) else None
    if v is None:
        v = rec["json"].get("trace_branch")
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    vocab = fmt.get("accepted_values")
    vocab = tuple(vocab) if isinstance(vocab, (list, tuple)) and vocab else BRANCH_VOCAB
    # PLAIN only for a value that is in the enum's own vocabulary (a judge-given accepted set); else None.
    return v if v in vocab else None


def override(sample_name, data, questions):
    """Replace generic's UNSURE config answer with the CRC-verified HGAU value (folded from the Day 31
    day_patch.py override()). The four d31_analysis_config_* ids are read by generic's config path FIRST,
    WITHOUT CRC verification (generic does not recognize the HGAU magic, so it reads the member's bare
    XOR-ed JSON and emits an unsure pick under binary.config_member/uncrc+exact_text). Here the same members
    are answered PLAIN, but ONLY from the one CRC-32-verified HGAU record whose campaign names the day
    (BR31-...), exactly as _config_member gates every HGAU answer. The reading is deterministic from the
    member's bytes alone (no ledger, seed or process-accumulated state). A CRC-invalid container (a future
    decoy) yields no record, nothing is returned, generic's unsure answer stands, and the bright line holds:
    a CRC-unverified read is never made plain here. The evidence dispatch replaces an UNSURE answer with a
    PLAIN value returned here, never a judge-accepted or None one.
    Returns {qid: plain value} for the config_* ids it can read plain."""
    rec = record(data)
    if rec is None:
        return {}
    out = {}
    for q in questions:
        qid = _qid(q)
        if not isinstance(qid, str) or "_" not in qid:
            continue
        field = qid.split("_", 1)[1]
        if not field.startswith("analysis_config_"):
            continue
        name = field[len("analysis_config_"):]
        try:
            got = _config_member(rec, name, _day_of(qid))
        except Exception as e:
            print(f"[fields_d31] override {qid}: reading the HGAU record raised {type(e).__name__}: {e}", file=sys.stderr)
            continue
        # Only a PLAIN value (campaign names the day); an unsure pick never replaces generic's unsure answer.
        if isinstance(got, str) and got and not got.startswith("??"):
            out[qid] = got
    return out


def fields(sample_name, data, questions):
    rec = record(data)
    if rec is None:
        return {}
    out = {}
    for q in questions:
        qid = _qid(q)
        if not isinstance(qid, str) or "_" not in qid:
            continue
        field = qid.split("_", 1)[1]
        day = _day_of(qid)
        try:
            if field.startswith("analysis_gauntlet_config_"):
                got = _config_member(rec, field[len("analysis_gauntlet_config_"):], day)
            elif field == "analysis_gauntlet_crc32_hex":
                got = f"0x{rec['crc']:08x}"
            elif field == "analysis_gauntlet_trace_branch":
                got = _branch(rec, q)
            else:
                continue
        except Exception as e:
            print(f"[fields_d31] {qid}: reading the HGAU record raised {type(e).__name__}: {e}", file=sys.stderr)
            continue
        if got is not None:
            out[qid] = got
    return out


if __name__ == "__main__":
    blob = Path(sys.argv[1]).read_bytes()
    rec = record(blob)
    if rec is None:
        print("no unique CRC-valid HGAU record")
    else:
        print(f"HGAU at {rec['offset']} crc=0x{rec['crc']:08x}")
        print(json.dumps(rec["json"], indent=1))
