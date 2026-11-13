#!/usr/bin/env python3
"""Day 29 Binary variant-diffing regression through the shipped dispatcher (evidence.solve_set reaches
solvers/binary/d29.py, the day reader this freezes).

The two role builds deliberately carry different valid HCFG records.  A
prefix-level ``config_*`` question asks for a value common to both builds and
must therefore stay unanswered, while an ``optimized_config_*`` question must
read only the O3 member.  This freezes the distinction that the real Day 29
base, Time Trial, and Mastery depended on.
"""
import contextlib
import hashlib
import io
import json
import struct
import sys
import zipfile
import zlib
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "binary"))


def _record(obj, key):
    plain = json.dumps(obj, separators=(",", ":")).encode()
    return (b"HCFG" + struct.pack("<BBHI", 1, key, len(plain), zlib.crc32(plain))
            + bytes(value ^ key for value in plain))


def _sample(obj, key):
    # The day reader needs only a named role member and a CRC-valid HCFG.  The
    # bounded ELF64 header also keeps format/machine on their normal path.
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", header, 16, 2)   # ET_EXEC
    struct.pack_into("<H", header, 18, 62)  # EM_X86_64
    return bytes(header) + _record(obj, key)


def _delivery(names, files):
    """Real ZIP bytes whose central-directory order is intentionally explicit."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as archive:
        for name in names:
            archive.writestr(name, files[name])
    return out.getvalue()


def _question(field, role=""):
    qid = f"d29_analysis_{field}"
    named = f"Use the unique d29-- member whose basename ends {role}. " if role else ""
    return {
        "id": qid,
        "qid": qid,
        "question": named + f"Submit the HCFG record's {field.rsplit('_', 1)[-1]} property.",
        "answer_format": {"kind": "exact_text", "syntax": "exact artifact-derived string"},
    }


def _header_question(field, role):
    qid = f"d29_analysis_{role}_{field}"
    lead = f"Use the unique d29-- member whose basename ends {'O3' if role == 'optimized' else 'O0'}.elf. "
    if field == "format":
        text = ("Classify final bytes by magic and parsed container: elf for ELF, pe for native PE, "
                "pe_cli for PE with a valid CLR/CLI header and metadata root, jar for a ZIP/JAR with "
                "classfiles, wasm for a valid WebAssembly module, or neko_bytecode for NEKO bytecode.")
        answer_format = {"kind": "enum", "accepted_values":
                         ["elf", "pe", "pe_cli", "jar", "wasm", "neko_bytecode"]}
    else:
        text = "Read the ELF e_machine field and submit its unsigned base-10 numeric value."
        answer_format = {"kind": "integer", "syntax": "base-10 integer"}
    return {"id": qid, "qid": qid, "question": lead + text, "answer_format": answer_format}


def _hash_question(number):
    qid = f"d29_artifact_sha256_{number}"
    return {
        "id": qid,
        "qid": qid,
        "question": ("Use all d29-- members in ZIP central-directory order. Compute SHA-256 over the exact "
                     f"bytes of member {number}, where members are the d29-- members in ZIP central-directory "
                     "order (1-based)."),
        "answer_format": {"kind": "pattern", "syntax": "exactly 64 lowercase hexadecimal characters"},
    }


def test_divergent_role_configs_withdraw_common_but_keep_optimized():
    import evidence
    import labels

    o0 = {
        "campaign": "BR29-O0",
        "domain": "debug.day29.example.invalid",
        "url": "https://debug.day29.example.invalid/api/BR29-O0",
        "mutex": "Global\\HuntressBR29_O0",
    }
    o3 = {
        "campaign": "BR29-O3",
        "domain": "fast.day29.example.invalid",
        "url": "https://fast.day29.example.invalid/api/BR29-O3",
        "mutex": "Global\\HuntressBR29_O3",
    }
    files = {
        "d29--sample-O0.elf": _sample(o0, 0x31),
        "d29--sample-O3.elf": _sample(o3, 0x73),
    }
    # Put O3 first in the archive but O0 first in ``files``.  The two digest
    # ids therefore prove that the runtime uses ZIP central-directory order,
    # not dict or lexical order.
    archive_order = ["d29--sample-O3.elf", "d29--sample-O0.elf"]
    delivery = _delivery(archive_order, files)
    questions = [_hash_question(1), _hash_question(2)]
    questions += [_header_question(field, role)
                  for role in ("optimized", "unoptimized") for field in ("format", "machine")]
    questions += [_question(f"config_{field}") for field in ("campaign", "domain", "mutex", "url")]
    questions += [_question(f"optimized_config_{field}", "O3.elf")
                  for field in ("campaign", "domain", "mutex", "url")]

    with contextlib.redirect_stderr(io.StringIO()):
        got = evidence.solve_set(
            questions,
            files,
            {"set": 1, "delivery_name": "evidence.zip", "delivery": delivery, "attempt": {}},
        )

    assert set(got) == {question["qid"] for question in questions}
    assert got["d29_artifact_sha256_1"] == hashlib.sha256(files[archive_order[0]]).hexdigest()
    assert got["d29_artifact_sha256_2"] == hashlib.sha256(files[archive_order[1]]).hexdigest()
    for role in ("optimized", "unoptimized"):
        assert got[f"d29_analysis_{role}_format"] == "elf"
        assert got[f"d29_analysis_{role}_machine"] == "62"
    for field in ("campaign", "domain", "mutex", "url"):
        assert got[f"d29_analysis_config_{field}"] is None
        qid = f"d29_analysis_optimized_config_{field}"
        value = got[qid]
        parsed = labels.parse(value) if labels.is_unsure(value) else None
        if parsed is None:
            assert value == o3[field], (field, value)
        else:
            assert {option for _name, option in parsed.options} == {o3[field]}
        assert o0[field] not in got[qid]


if __name__ == "__main__":
    test_divergent_role_configs_withdraw_common_but_keep_optimized()
    print("day29 binary variants: 14/14 delta ids exercised")
