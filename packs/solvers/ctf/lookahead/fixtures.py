"""Computed-field forecast fixtures for the daily look-ahead (B-256): synthetic specimens whose answers
are stated computations over the delivered members (the computed.py class).

Huntress Day 23 (backlog row 494): the Mobile look-ahead staged only named ciphers with the data in the
document and never the computed class, so the armed solver had no handler and the live build took three
rounds; Day 28 Binary met twenty stated computations it had left "safe None". This no-model step stages
that class for a lane every night, through each delivery encoding the lane has seen:

    names = stage_computed(matrix_dir, lane, seed=..., chains=None)    # specimen folders
    data = encode_chain(("base64", "zlib"), plain)                     # bytes that decode_chain undoes

Each specimen asks the computed.py templates (member count, member size, member md5/sha1/sha256, the
digest of the members' digests in name order, with and without newlines), worded exactly as the
templates read, and key.json holds the answers computed here from the delivered bytes with hashlib
(an independent path from computed.answer; the tests check the two agree). The chains staged are the
lane's `real_encodings` when it declares any (so the night also exercises each real encoding), else
[["raw"]], unless `chains` is given. Encoders exist for every codec matrix.decode_chain reads; each
staged member is decoded back through matrix.decode_chain before it is kept, so a fixture whose bytes do
not hold its claimed chain is never written. Re-staging rewrites only folders this module staged
(STAGED_NOTE); any other folder of the same name is refused.
"""
from __future__ import annotations

import base64
import bz2
import gzip
import hashlib
import json
import lzma
import random
import shutil
import zlib
from pathlib import Path

from . import LookaheadError
from . import matrix as _matrix

STAGED_NOTE = "staged by ctf.lookahead.fixtures (B-256)"
PREFIX = "computed"


def _encode(codec: str, data: bytes) -> bytes:
    if codec == "base64":
        return base64.b64encode(data)
    if codec == "base64url":
        return base64.urlsafe_b64encode(data).rstrip(b"=")
    if codec == "base32":
        return base64.b32encode(data)
    if codec == "hex":
        return data.hex().encode("ascii")
    if codec == "zlib":
        return zlib.compress(data)
    if codec == "gzip":
        return gzip.compress(data, mtime=0)
    if codec == "bz2":
        return bz2.compress(data)
    if codec == "xz":
        return lzma.compress(data)
    if codec == "utf-16le":
        return data.decode("utf-8").encode("utf-16-le")
    if codec == "reverse":
        return data[::-1]
    raise LookaheadError(f"codec {codec!r} has no encoder here (known: {', '.join(_matrix.CODECS)})")


def encode_chain(chain, plain: bytes) -> bytes:
    """The delivered bytes for `plain` under `chain` (outermost first, as a specimen declares it):
    the innermost layer is applied first. matrix.decode_chain(chain, result) == plain."""
    chain = _matrix.check_chain(chain, "encoding")
    if chain == ("raw",):
        return plain
    data = plain
    for codec in reversed(chain):
        data = _encode(codec, data)
    return data


def _q(qid: str, text: str, kind: str) -> dict:
    return {"id": qid, "question": text, "answer_format": {"kind": kind}}


_H = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}


def _questions_and_key(members: dict[str, bytes]) -> tuple[list[dict], dict]:
    names = sorted(members)
    qs = [_q("computed_count", "How many members are in the delivered evidence set?", "integer")]
    key: dict = {"computed_count": len(members)}
    for i, n in enumerate(names):
        qs.append(_q(f"computed_size_{i}", f"What is the size in bytes of member '{n}'?", "integer"))
        key[f"computed_size_{i}"] = len(members[n])
        algo = ("md5", "sha1", "sha256")[i % 3]
        qs.append(_q(f"computed_{algo}_{i}", f"What is the {algo} of member '{n}'?", "exact_text"))
        key[f"computed_{algo}_{i}"] = _H[algo](members[n]).hexdigest()
    md5s = [_H["md5"](members[n]).hexdigest() for n in names]
    sha256s = [_H["sha256"](members[n]).hexdigest() for n in names]
    qs.append(_q("computed_digests_nl", "What is the sha256 of the concatenation of the members' md5 hex "
                 "digests in name order, separated by newlines?", "exact_text"))
    key["computed_digests_nl"] = _H["sha256"]("\n".join(md5s).encode("ascii")).hexdigest()
    qs.append(_q("computed_digests", "What is the sha1 of the concatenation of the members' sha256 hex "
                 "digests in name order?", "exact_text"))
    key["computed_digests"] = _H["sha1"]("".join(sha256s).encode("ascii")).hexdigest()
    return qs, key


def _plain_members(rng: random.Random, text: bool) -> dict[str, bytes]:
    out = {}
    for i in range(rng.randint(2, 4)):
        n = rng.randint(40, 400)
        if text:      # utf-16le needs text that is valid UTF-8 before encoding
            body = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789 \n") for _ in range(n)).encode()
        else:
            body = bytes(rng.getrandbits(8) for _ in range(n))
        out[f"m{i}_{rng.randrange(16 ** 4):04x}.bin"] = body
    return out


def _ours(sdir: Path) -> bool:
    try:
        return STAGED_NOTE in (sdir / _matrix.SPECIMEN_FILE).read_text(encoding="utf-8")
    except OSError:
        return False


def stage_computed(matrix_dir, lane: str, *, seed=0, chains=None) -> list[str]:
    """Stage one computed-field specimen per chain under <matrix>/<lane>/, named
    `computed-<chain joined by _>`. Returns the specimen names; the matrix is re-loaded afterwards."""
    mdir = Path(matrix_dir)
    m = _matrix.load(mdir)
    if lane not in m.lanes:
        raise LookaheadError(f"{mdir}: lane {lane!r} is not declared in {_matrix.MATRIX_FILE} "
                             f"(declared: {', '.join(m.lanes)}); declare it with its reader first")
    if chains is None:
        chains = m.lanes[lane].real_encodings or (("raw",),)
    chains = [_matrix.check_chain(list(c), f"chain #{i + 1}") for i, c in enumerate(chains)]
    if not chains:
        raise LookaheadError("no encoding chain to stage")
    names = []
    for chain in chains:
        name = f"{PREFIX}-{'_'.join(chain)}"
        sdir = mdir / lane / name
        if sdir.exists():
            if not _ours(sdir):
                raise LookaheadError(f"{sdir}: exists and was not staged by the computed-fixture step; "
                                     "not overwriting")
            shutil.rmtree(sdir)
        rng = random.Random(f"b256-computed:{seed}:{lane}:{'+'.join(chain)}")
        plain = _plain_members(rng, text="utf-16le" in chain)
        delivered = {}
        for n, body in plain.items():
            data = encode_chain(chain, body)
            if _matrix.decode_chain(chain, data) != body:      # never write a fixture that does not hold
                raise LookaheadError(f"{name}/{n}: the encoder does not round-trip {'+'.join(chain)}")
            delivered[n] = data
        qs, key = _questions_and_key(delivered)
        (sdir / _matrix.FILES_DIR).mkdir(parents=True)
        for n, data in delivered.items():
            (sdir / _matrix.FILES_DIR / n).write_bytes(data)
        (sdir / _matrix.QUESTIONS_FILE).write_text(json.dumps(qs, indent=1), encoding="utf-8")
        (sdir / _matrix.KEY_FILE).write_text(json.dumps(key, indent=1), encoding="utf-8")
        note = f"{STAGED_NOTE}: computed fields, delivered as {'+'.join(chain)}"
        (sdir / _matrix.SPECIMEN_FILE).write_text(
            f"encoding = {json.dumps(list(chain))}\nnote = {json.dumps(note)}\n", encoding="utf-8")
        names.append(name)
    _matrix.load(mdir)
    return names
