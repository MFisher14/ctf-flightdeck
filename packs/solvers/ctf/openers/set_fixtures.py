"""Synthetic multi-delivery Mastery fixtures for the armed openers (B-042).

A Mastery ships each set its own file, and the files of two sets usually share a name (three
`blob.txt`, two `evidence.zip`) and their members' names. These builders write a saved attempt in the
layout `ctf.deliveries.read_attempt` reads (`attempt.json` beside `artifact/`), in the three shapes
the first days of Huntress dealt, and return the path of its `attempt.json`. `openers.run_input` runs
the lane's opener engine once per set on the set's own delivery, so the frozen key of each case says
which set printed which answer from which delivery.

  one delivery per set, named by the questions    warmups_mastery_deliveries, apk_mastery_deliveries,
                                                  elf64_mastery_deliveries
  one delivery per set, in set order              powershell_mastery_deliveries
  one bundle with a numbered member per set       warmups_mastery_bundle, metadata_mastery_bundle

Each `*_crossed` builder is the control of its lane: the same attempt with the files of sets 1 and 2
exchanged. Every set still gets an answer there, the neighbour's, so a key that only names the answers
would hold on it; a key that names the set and the delivery does not. Nothing here is a real challenge
file. The bodies come from the single-file builders in `fixtures.py`.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path
from typing import Callable

WARMUPS_SET_SLUGS = ("first-set-delivery-41", "second-set-delivery-42", "third-set-delivery-43")
WARMUPS_BUNDLE_SLUGS = ("first-bundle-member-51", "second-bundle-member-52")
APK_SET_CODES = ("ANS-A1A1A1A1A1A10001", "ANS-B2B2B2B2B2B20002")
PS_SETS = (
    {"a": "http://pool.invalid.example:3333/set-one", "b": "wallet_synthetic_0011_set_one",
     "c": "Global\\SetOneMiner11"},
    {"a": "http://pool.invalid.example:3333/set-two", "b": "wallet_synthetic_0012_set_two",
     "c": "Global\\SetTwoMiner12"},
)
# Width x height of each set's evidence.png: same member name, other bytes. Neither is the 2x1 image of the
# opener's base case, whose key would otherwise hold on the crossed control.
PNG_SETS = ((3, 2), (4, 3))
ELF_SETS = ((b"synthetic-set-one", 4101), (b"synthetic-set-two", 4202))     # .huntress marker, recover_code's constant


def _fx():
    from . import fixtures            # at call time: fixtures.py imports this module for its BUILDERS
    return fixtures


def _zip(members: list[tuple[str, bytes]]) -> bytes:
    """A stored zip with fixed dates: the same bytes on every machine and zlib build."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, body in members:
            zf.writestr(zipfile.ZipInfo(name, date_time=(2026, 10, 1, 0, 0, 0)), body)
    return buf.getvalue()


def write_attempt(dest: Path, deliveries: list[tuple[str, bytes]], questions: list[dict]) -> Path:
    """Write a saved attempt (attempt.json, artifact/<file> or artifact/delivery-NN/<file>) and return
    the attempt.json path."""
    dest = Path(dest)
    art = dest / "artifact"
    for i, (name, data) in enumerate(deliveries):
        folder = art if len(deliveries) == 1 else art / f"delivery-{i + 1:02d}"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / name).write_bytes(data)
    attempt = {
        "mode": "mastery",
        "questions": questions,
        "answer_ids": [q["id"] for q in questions],
        "artifacts": [{"filename": name, "sha256": hashlib.sha256(data).hexdigest()} for name, data in deliveries],
    }
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / "attempt.json"
    out.write_text(json.dumps(attempt, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return out


def _question(n: int, qid: str, artifact: str, text: str) -> dict:
    return {"id": f"set{n}.{qid}", "question": text, "artifact": artifact, "set": n}


# --------------------------------------------------------------------------- warmups

def _record(slug: str) -> bytes:
    """One numbered Mastery record, `01<TAB><base64 note>`: the record number is 01 in every delivery."""
    return b"01\t" + base64.b64encode(_fx()._note(slug).encode()) + b"\n"


def _warmups_deliveries(dest: Path, slugs) -> Path:
    qs = [_question(n, "message", f"delivery {n}: blob.txt", "Decode the assigned blob completely.")
          for n in range(1, len(slugs) + 1)]
    return write_attempt(dest, [("blob.txt", _record(s)) for s in slugs], qs)


def warmups_mastery_deliveries(dest: Path) -> Path:
    """Day-1 Mastery: three deliveries, all named blob.txt, each one numbered record; the questions
    name their delivery (`delivery 2: blob.txt`)."""
    return _warmups_deliveries(dest, WARMUPS_SET_SLUGS)


def warmups_mastery_bundle(dest: Path) -> Path:
    """Day-4 Mastery: one bundle zip with a numbered member per set (blob-01.txt, blob-02.txt); the
    questions name the member, not a delivery. The members are written last set first, so reading
    them in archive order pairs them wrongly."""
    members = [(f"blob-{n:02d}.txt", _record(s)) for n, s in enumerate(WARMUPS_BUNDLE_SLUGS, 1)]
    qs = [_question(n, "message", f"blob-{n:02d}.txt", "Decode the assigned blob completely.")
          for n in range(1, len(members) + 1)]
    return write_attempt(dest, [("warmups-mastery.zip", _zip(members[::-1]))], qs)


def warmups_mastery_crossed(dest: Path) -> Path:
    """Control: the Day-1 Mastery with the files of sets 1 and 2 exchanged."""
    a, b, c = WARMUPS_SET_SLUGS
    return _warmups_deliveries(dest, (b, a, c))


# --------------------------------------------------------------------------- script analysis

_PS_NATIVE = ["System.Diagnostics.Process", "Microsoft.Win32.Registry", "System.Net.WebClient",
              "System.Threading.Mutex"]


def _powershell_deliveries(dest: Path, descs) -> Path:
    fx = _fx()
    deliveries = [("evidence.zip", _zip([("resource-sample.ps1", fx._ps_specimen(d, _PS_NATIVE))])) for d in descs]
    qs = [_question(n, qid, f"evidence-{n:02d}.zip -> resource-sample.ps1", text)
          for n in range(1, len(descs) + 1)
          for qid, text in (("resource-url", "What exact URL is embedded in the resource sample?"),
                            ("resource-wallet", "What exact wallet indicator is embedded in the resource sample?"),
                            ("resource-mutex", "What exact mutex indicator is embedded in the resource sample?"))]
    return write_attempt(dest, deliveries, qs)


def powershell_mastery_deliveries(dest: Path) -> Path:
    """Day-2 Mastery: two deliveries, both evidence.zip, both holding resource-sample.ps1. No question
    names a delivery (they say evidence-01.zip, a name no delivery carries): set N reads delivery N."""
    return _powershell_deliveries(dest, PS_SETS)


def powershell_mastery_crossed(dest: Path) -> Path:
    """Control: the same Mastery with the two deliveries exchanged."""
    return _powershell_deliveries(dest, PS_SETS[::-1])


# --------------------------------------------------------------------------- metadata

def _metadata_bundle(dest: Path, sizes) -> Path:
    fx = _fx()
    members = [(f"metadata-evidence-{n:02d}.zip", _zip([("evidence.png", fx._png(w, h))]))
               for n, (w, h) in enumerate(sizes, 1)]
    qs = [_question(n, qid, f"metadata-evidence-{n:02d}.zip -> evidence.png", text)
          for n in range(1, len(sizes) + 1)
          for qid, text in (("evidence-sha256", "What is its SHA-256 digest?"),
                            ("evidence-dimensions", "What are its pixel dimensions?"))]
    return write_attempt(dest, [("metadata-mastery-bundle.zip", _zip(members[::-1]))], qs)


def metadata_mastery_bundle(dest: Path) -> Path:
    """Day-3 Mastery: one bundle zip holding a numbered evidence zip per set, each with an
    evidence.png of its own (same member name, other bytes); written last set first."""
    return _metadata_bundle(dest, PNG_SETS)


def metadata_mastery_crossed(dest: Path) -> Path:
    """Control: the same bundle with the two evidence zips' contents exchanged."""
    return _metadata_bundle(dest, PNG_SETS[::-1])


# --------------------------------------------------------------------------- mobile

def _apk_deliveries(dest: Path, codes) -> Path:
    fx = _fx()
    deliveries = [(f"sample_mastery_{n:02d}.apk",
                   fx._apk({"schema": "huntress.mobile.puzzle.v1", "day": 1, "codec": "plain", "data": code}))
                  for n, code in enumerate(codes, 1)]
    qs = [_question(n, "answer", f"delivery {n}: sample_mastery_{n:02d}.apk", "What is the answer code?")
          for n in range(1, len(codes) + 1)]
    return write_attempt(dest, deliveries, qs)


def apk_mastery_deliveries(dest: Path) -> Path:
    """Day-1 Mastery: one APK per set, named by the questions (`delivery 2: sample_mastery_02.apk`)."""
    return _apk_deliveries(dest, APK_SET_CODES)


def apk_mastery_crossed(dest: Path) -> Path:
    """Control: the same Mastery with the two APKs' contents exchanged (the file names stay)."""
    return _apk_deliveries(dest, APK_SET_CODES[::-1])


# --------------------------------------------------------------------------- binary

def _elf_deliveries(dest: Path, specs) -> Path:
    fx = _fx()
    deliveries = [("sample.elf", fx._elf64(marker=marker + b"\x00", code=b"\xb8" + struct.pack("<I", value) + b"\xc3"))
                  for marker, value in specs]          # mov eax, <value> ; ret
    qs = [_question(n, qid, f"delivery {n}: sample.elf", text)
          for n in range(1, len(specs) + 1)
          for qid, text in (("analysis_marker", "What is the marker value?"),
                            ("analysis_recover_code", "What does recover_code return?"))]
    return write_attempt(dest, deliveries, qs)


def elf64_mastery_deliveries(dest: Path) -> Path:
    """Two deliveries, both sample.elf, one per set, named by the questions. The binary opener's engine
    reads one ELF, so each set's delivery is the ELF itself here; the Day-1 Binary Mastery shipped an
    evidence zip per set, which that engine does not open."""
    return _elf_deliveries(dest, ELF_SETS)


def elf64_mastery_crossed(dest: Path) -> Path:
    """Control: the same Mastery with the two ELFs exchanged."""
    return _elf_deliveries(dest, ELF_SETS[::-1])


BUILDERS: dict[str, Callable[[Path], Path]] = {
    "warmups_mastery_deliveries": warmups_mastery_deliveries,
    "warmups_mastery_bundle": warmups_mastery_bundle,
    "warmups_mastery_crossed": warmups_mastery_crossed,
    "powershell_mastery_deliveries": powershell_mastery_deliveries,
    "powershell_mastery_crossed": powershell_mastery_crossed,
    "metadata_mastery_bundle": metadata_mastery_bundle,
    "metadata_mastery_crossed": metadata_mastery_crossed,
    "apk_mastery_deliveries": apk_mastery_deliveries,
    "apk_mastery_crossed": apk_mastery_crossed,
    "elf64_mastery_deliveries": elf64_mastery_deliveries,
    "elf64_mastery_crossed": elf64_mastery_crossed,
}
