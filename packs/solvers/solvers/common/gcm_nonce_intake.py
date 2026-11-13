"""No-model intake adapter for the AES-GCM nonce-reuse (forbidden attack) recovery (B-060).

The GF(2^128) maths already ships in :mod:`crypto_depth` (``gcm_recover_subkey``): given two or more
ciphertext+tag pairs made under one key and one reused nonce, it recovers the authentication subkey
H = E_K(0^128) and the tag mask S = E_K(J0), returning a UNIQUE pair only when a third pair pins it.
What was missing was the no-model wiring: the sweep (B-013) unpacks a handout, but nothing mapped the
``*_hex`` / ``*_b64`` field names a real dispatch export uses into that call, and nothing then tried the
recovered S / H as AES keys over the leftover sealed blob. This engine is that adapter.

Contract entry (``solve(challenge_dir, profile)``) run by intake with ``[intake] run = "challenge",
select = "files", match = ["ext:.json"]`` (B-002), modelled on ``ecdsa_recovery``'s adapter. It:

  1. reads every JSON handout under the challenge folder (originals in ``files/`` and the sweep's
     unpacked members in ``unpacked/``; intake's own ``recon/`` and root metadata files are skipped,
     and the sweep's credential fence holds: nothing in a ``.ctf/`` / ``.git/`` folder or named
     ``.env*`` is read), plus each small non-JSON member as a raw candidate sealed blob,
  2. normalises field names: a ``ciphertext_hex`` / ``tag_b64`` / ``nonce_hex`` field is read as its
     role (ciphertext, tag, aad, nonce) with its encoding (hex, base64, base64url, base32) decoded,
     so the ``*_hex`` names that ``modern_crypto._gcm_pairs`` rejected are now understood,
  3. groups the (aad, ciphertext, tag) observations by nonce and calls ``gcm_recover_subkey``,
     accepting ONLY a unique H (every supplied tag reproduces; a non-unique or unverified result is
     declined), then
  4. trials S and H as AES-128 keys (CTR with a zero counter, ECB, CBC with a zero IV, and the GCM
     keystream under a recovered nonce) over EVERY leftover blob (role-less fields and tagless
     ciphertext fields of every JSON document, and the raw members), gated by the event flag format
     (``ctf.flagfmt`` is the single flag source; this module defines no regex of its own).

Offline: no network, no oracle, no spawned process, and the handout is never executed. The recovered
H / S are never emitted as a flag on their own (the judge's spelling for them is unknown); only a value
that matches the event flag format and came out of a decryption is returned as a flag.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
from pathlib import Path

try:                                       # package import under ctf.* ; flat import under the engine boot
    from . import crypto_depth as _depth
except ImportError:                        # pragma: no cover - exercised only outside a package layout
    import crypto_depth as _depth


MAX_JSON_BYTES = 4 * 1024 * 1024           # a single handout JSON read at most
MAX_FILES = 64                             # JSON files scanned per challenge
MAX_OBSERVATIONS = 64                      # (aad, ct, tag) records fed to the recovery
MAX_BLOB = 1 * 1024 * 1024                 # one decoded blob, bytes
MAX_BLOBS = 64                             # leftover field blobs kept from one JSON document
MAX_TRIAL_BLOBS = 256                      # leftover blobs trialled in all, every source together
MAX_MEMBERS = 64                           # non-JSON handout members read as raw sealed blobs
MAX_MEMBER_BYTES = 64 * 1024               # one raw member read at most (a sealed flag is small)
MAX_JSON_NODES = 100_000                   # bound the recursive walk of one document

# Intake writes these under the challenge folder; they are not challenge data. Only at the challenge
# ROOT: a handout member called challenge.json deeper down (say under unpacked/) is still read.
_SKIP_DIRS = {"recon"}
_SKIP_ROOT_NAMES = {"challenge.json", "attempt.json", "notes.md", ".sweep.json"}
_SKIP_RELS = {"unpacked/.sweep.json"}      # the sweep's own report (ctf.sweep.REPORT under its out dir)

# Field-name roles, matched against the base name AFTER the encoding suffix is stripped.
_CT_BASES = frozenset({"ciphertext", "ct", "c", "cipher", "enc", "encrypted",
                       "dispatch_ciphertext", "message_ciphertext"})
_TAG_BASES = frozenset({"tag", "auth_tag", "authtag", "authentication_tag", "mac", "gmac", "t"})
_AAD_BASES = frozenset({"aad", "ad", "associated_data", "additional_data", "adata", "header"})
_NONCE_BASES = frozenset({"nonce", "iv", "j0"})

# Encoding suffixes, longest first so `base64url` wins over `b64`/`url`.
_ENC_SUFFIXES = (
    ("base64url", "b64url"), ("base64-url", "b64url"), ("b64url", "b64url"),
    ("base64", "b64"), ("b64", "b64"),
    ("base32", "b32"), ("b32", "b32"),
    ("hex", "hex"),
)
_HEX_RE = re.compile(r"\A(?:0[xX])?[0-9a-fA-F]+\Z")
_B64_RE = re.compile(r"\A[A-Za-z0-9+/_\-]+={0,2}\Z")


def _split_encoding(name: str) -> tuple[str, str | None]:
    """``("ciphertext", "hex")`` from ``ciphertext_hex``; ``(name, None)`` when no suffix is present."""
    low = name.lower()
    for suffix, enc in _ENC_SUFFIXES:
        for sep in ("_", "-"):
            tail = sep + suffix
            if low.endswith(tail) and len(low) > len(tail):
                return low[: -len(tail)], enc
        if low == suffix:
            return "", enc
    return low, None


def _role(base: str) -> str | None:
    if base in _CT_BASES:
        return "ct"
    if base in _TAG_BASES:
        return "tag"
    if base in _AAD_BASES:
        return "aad"
    if base in _NONCE_BASES:
        return "nonce"
    return None


def _decode(value, enc: str | None) -> bytes | None:
    """Bytes of a scalar field under its declared (or inferred) encoding, or None.

    A declared encoding is honoured strictly; an undeclared one is read as hex when the string is
    hex-shaped, else base64. Non-strings and values over :data:`MAX_BLOB` are rejected."""
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s or len(s) > MAX_BLOB * 2:
        return None
    try:
        body = s[2:] if s[:2] in ("0x", "0X") else s       # strip only a literal 0x prefix
        if enc == "hex" or (enc is None and _HEX_RE.match(s) and len(body) % 2 == 0):
            if len(body) % 2:
                return None
            out = bytes.fromhex(body)
        elif enc == "b64":
            out = base64.b64decode(s, validate=True)
        elif enc == "b64url":
            out = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        elif enc == "b32":
            out = base64.b32decode(s, casefold=True)
        elif enc is None and _B64_RE.match(s) and len(s) % 4 == 0:
            out = base64.b64decode(s, validate=True)
        else:
            return None
    except (binascii.Error, ValueError):
        return None
    return out if 0 < len(out) <= MAX_BLOB else None


class _Reading:
    """What one JSON document yields: GCM observations (per nonce) and leftover blobs to trial."""

    def __init__(self):
        self.observations: list[tuple[bytes, bytes, bytes, bytes | None]] = []  # aad, ct, tag, nonce
        self.blobs: list[tuple[str, bytes]] = []        # (field name, bytes) candidate ciphertext
        self.nonces: list[bytes] = []

    def _scalar_fields(self, obj: dict) -> dict[str, tuple[str, bytes]]:
        """{role or 'blob': (field, bytes)} for one dict's directly-held scalar fields."""
        picked: dict[str, tuple[str, bytes]] = {}
        for name, value in obj.items():
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            base, enc = _split_encoding(name)
            raw = _decode(value, enc)
            if raw is None:
                continue
            role = _role(base)
            if role is None:
                if len(self.blobs) < MAX_BLOBS:
                    self.blobs.append((name, raw))
                continue
            picked.setdefault(role, (name, raw))          # first field of each role in this dict wins
        return picked

    def walk(self, node, inherited_nonce: bytes | None, budget: list[int]) -> None:
        budget[0] += 1
        if budget[0] > MAX_JSON_NODES:
            return
        if isinstance(node, dict):
            fields = self._scalar_fields(node)
            nonce = fields["nonce"][1] if "nonce" in fields else inherited_nonce
            if "nonce" in fields and fields["nonce"][1] not in self.nonces:
                self.nonces.append(fields["nonce"][1])
            if "ct" in fields and "tag" in fields and len(fields["tag"][1]) == 16:
                if len(self.observations) < MAX_OBSERVATIONS:
                    aad = fields["aad"][1] if "aad" in fields else b""
                    self.observations.append((aad, fields["ct"][1], fields["tag"][1], nonce))
            elif "ct" in fields and len(self.blobs) < MAX_BLOBS:
                # A ciphertext with no 16-byte tag beside it is not a GCM record: it is a leftover sealed
                # value (e.g. {"sealed": {"ciphertext_hex": ...}}), so it is trialled like any other blob.
                self.blobs.append(fields["ct"])
            for value in node.values():
                if isinstance(value, (dict, list)):
                    self.walk(value, nonce, budget)
        elif isinstance(node, list):
            for value in node:
                if isinstance(value, (dict, list)):
                    self.walk(value, inherited_nonce, budget)


def _group_by_nonce(observations):
    """[(nonce_or_None, [(aad, ct, tag), ...])], largest group first.

    Observations are grouped by the nonce in scope where they were read; the forbidden attack needs one
    reused nonce, and mixing nonces would fail verification. ``gcm_recover_subkey`` re-verifies every
    tag, so a wrong grouping simply recovers nothing."""
    groups: dict[bytes | None, list[tuple[bytes, bytes, bytes]]] = {}
    for aad, ct, tag, nonce in observations:
        groups.setdefault(nonce, []).append((aad, ct, tag))
    ordered = sorted(groups.items(), key=lambda kv: -len(kv[1]))
    # When no record carried its own nonce they all share the single `None` bucket, which is correct.
    return ordered


def _unique_subkey(triples):
    """The single verified ``(H, S)`` for these pairs, or None when fewer than three pairs are given or
    the recovery is not unique. Three pairs are required because with exactly two every GF(2^128) root
    is self-consistent and :func:`gcm_recover_subkey` then returns several candidates."""
    if len(triples) < 3:
        return None
    try:
        candidates = _depth.gcm_recover_subkey(triples)
    except (TypeError, ValueError, ArithmeticError):
        return None
    if len(candidates) != 1:
        return None
    h, s = candidates[0]
    # gcm_recover_subkey already verifies, but re-check here so the gate cannot silently weaken.
    if all(_depth.gcm_tag(h, s, aad, ct) == tag for aad, ct, tag in triples):
        return h, s
    return None


def _trial_decrypts(key: bytes, blob: bytes, nonce: bytes | None):
    """[(mode, plaintext)] of ``blob`` under ``key`` across the AES modes a GCM-keyed seal may use.

    Raises :class:`ImportError` when pycryptodome is absent (surfaced as a named `blocked`, no silent
    fallback)."""
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    outs = []
    try:
        ctr = Counter.new(128, initial_value=0)
        outs.append(("aes-ctr", AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(blob)))
    except (ValueError, TypeError):
        pass
    if blob and len(blob) % 16 == 0:
        for mode, kwargs in (("aes-ecb", {}), ("aes-cbc", {"iv": b"\x00" * 16})):
            try:
                cipher = AES.new(key, AES.MODE_ECB if mode == "aes-ecb" else AES.MODE_CBC, **kwargs)
                outs.append((mode, cipher.decrypt(blob)))
            except (ValueError, TypeError):
                pass
    if nonce and len(blob) > 0:
        try:
            outs.append(("aes-gcm-keystream", AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt(blob)))
        except (ValueError, TypeError):
            pass
    return outs


def _excluded(rel: Path) -> bool:
    """True for a file the engine must not read: intake's own files at the challenge root, the sweep's
    report, and (the sweep's credential fence, ``ctf.sweep``) a file itself named ``.ctf`` / ``.git``
    or ``.env`` / ``.env.*``. Folders (intake's root recon/, ``.ctf/`` and ``.git/`` at any depth, links)
    are pruned once, in :func:`_iter_files`, so nothing under them reaches here."""
    from ctf import sweep as _sweep

    parts = rel.parts
    if not parts:
        return True
    if len(parts) == 1 and parts[0] in _SKIP_ROOT_NAMES:
        return True
    if rel.as_posix() in _SKIP_RELS:
        return True
    return rel.name in _sweep.SECRET_DIRS or _sweep.is_secret_file(rel.name)


def _iter_files(challenge_dir: Path):
    """(relative path, path) of each regular file under the challenge folder, sorted, never following a
    link and never descending into a credentials folder (``ctf.sweep.SECRET_DIRS``) or intake's recon/."""
    from ctf import sweep as _sweep

    # followlinks=False: a linked folder is listed in `dirs` but never entered (the read fence).
    for folder, dirs, names in os.walk(challenge_dir, followlinks=False):
        here = Path(folder)
        keep = []
        for d in sorted(dirs):
            if d in _sweep.SECRET_DIRS or (here == challenge_dir and d in _SKIP_DIRS):
                continue
            keep.append(d)
        dirs[:] = keep
        for n in sorted(names):
            path = here / n
            rel = path.relative_to(challenge_dir)
            if _excluded(rel) or path.is_symlink() or not path.is_file():
                continue
            yield rel, path


def _gather(challenge_dir: Path):
    """``(docs, members)``: ``docs`` is ``[(rel, _Reading)]`` for each JSON handout; ``members`` is
    ``[(rel, None or "decoded text", bytes)]`` for the non-JSON members (the raw bytes, plus their
    hex/base64 decoding when the member is such text). Every count and size is bounded."""
    docs, members = [], []
    n_json = n_members = 0
    for rel, path in _iter_files(challenge_dir):
        try:
            size = path.stat().st_size
        except OSError:
            continue
        posix = rel.as_posix()
        if path.suffix.lower() == ".json" and n_json < MAX_FILES and size <= MAX_JSON_BYTES:
            try:
                obj = json.loads(path.read_text(encoding="utf-8", errors="strict"))
            except (OSError, ValueError):
                obj = None
            if obj is not None:
                n_json += 1
                reading = _Reading()
                reading.walk(obj, None, [0])
                docs.append((posix, reading))
                continue
        if n_members >= MAX_MEMBERS or not 0 < size <= MAX_MEMBER_BYTES:
            continue
        try:
            data = path.read_bytes()[:MAX_MEMBER_BYTES]
        except OSError:
            continue
        n_members += 1
        members.append((posix, None, data))
        try:
            text = data.decode("ascii").strip()
        except UnicodeDecodeError:
            continue
        decoded = _decode(text, None)
        if decoded is not None and decoded != data:
            members.append((posix, "decoded text", decoded))
    return docs, members


def solve(challenge_dir, profile, **opts):
    """Contract entry: recover a GCM nonce-reuse subkey from a handout and open the sealed blob it keys.

    Every JSON handout is read first; the first one holding >= 3 reused-nonce records that pin a unique
    subkey supplies H / S. Then EVERY leftover blob is trialled, wherever it sits: the recovering
    document's own fields first (the sealed order usually ships beside the intercepts), then the other
    JSON documents' fields (those sorted before it included), then the raw non-JSON members.

    Returns ``solved`` with the flag when a trialled decryption yields an event-format flag; ``unsure``
    with the recovered H / S in the notes when a unique subkey is found but no blob opens to a flag;
    ``blocked`` when a sealed blob is present but pycryptodome is missing; ``none`` otherwise."""
    from ctf import flagfmt
    from ctf.result import Cost, Evidence, SolverResult

    challenge_dir = Path(challenge_dir)
    engine_id = "common.gcm_nonce_intake"
    ff = flagfmt.for_profile(profile)

    docs, members = _gather(challenge_dir)
    recovered = None          # (rel, nonce, H, S) of the first unique subkey
    saw_observations = False
    for rel, reading in docs:
        if reading.observations:
            saw_observations = True
        for nonce, triples in _group_by_nonce(reading.observations):
            found = _unique_subkey(triples)
            if found is not None:
                # Records with no nonce of their own in scope: use the nonce the document names elsewhere.
                recovered = (rel, nonce or (reading.nonces[0] if reading.nonces else None),
                             found[0], found[1])
                break
        if recovered is not None:
            break

    if recovered is not None:
        src = recovered[0]
        blobs = [(r, name, raw) for r, rd in docs if r == src for name, raw in rd.blobs]
        blobs += [(r, name, raw) for r, rd in docs if r != src for name, raw in rd.blobs]
        blobs += members
        dropped = max(0, len(blobs) - MAX_TRIAL_BLOBS)
        blobs = blobs[:MAX_TRIAL_BLOBS]
        opened = _try_open(recovered, blobs, ff, engine_id, SolverResult, Evidence, Cost)
        if isinstance(opened, SolverResult):
            return opened
        if opened == "blocked":
            return SolverResult(status="blocked", engine=engine_id,
                                notes="recovered a unique GCM subkey but pycryptodome "
                                      "(py:Crypto) is required to open the sealed blob")

    if recovered is None:
        if saw_observations:
            return SolverResult(status="none", engine=engine_id,
                                notes="GCM ciphertext+tag records were read but no reused-nonce subkey "
                                      "recovered uniquely (need >= 3 single-nonce pairs that verify)")
        return SolverResult(status="none", engine=engine_id,
                            notes="no AES-GCM nonce-reuse material (ciphertext_hex/tag_hex records "
                                  "under a shared nonce) found in the JSON handouts")

    rel, nonce, h, s = recovered
    note = (f"recovered a unique GCM subkey from {rel}: H=E_K(0^128)={h:032x}, S=E_K(J0)={s:032x}. "
            f"No leftover blob ({len(blobs)} tried) opened to a flag under S/H (tried AES-CTR, ECB, "
            "CBC, GCM-keystream). If a sealed value ships elsewhere, decrypt it with S (or H) as the "
            "AES-128 key.")
    if dropped:
        note += f" {dropped} further blob(s) were not tried (over the bound of {MAX_TRIAL_BLOBS})."
    return SolverResult(status="unsure", engine=engine_id, notes=note, cost=Cost())


_KEY_LABELS = {"S": "S=E_K(J0)", "H": "H=E_K(0^128)"}


def _try_open(recovered, blobs, ff, engine_id, SolverResult, Evidence, Cost):
    """A ``solved`` SolverResult when a blob opens to a flag, the string ``"blocked"`` when the AES
    backend is missing, else None. ``blobs`` is ``[(source rel, field name or None, bytes)]``."""
    src, nonce, h, s = recovered
    if not blobs:
        return None
    for key_name, key in (("S", s.to_bytes(16, "big")), ("H", h.to_bytes(16, "big"))):
        label = _KEY_LABELS[key_name]
        for blob_rel, blob_name, blob in blobs:
            try:
                candidates = _trial_decrypts(key, blob, nonce)
            except ImportError:
                return "blocked"
            for mode, plain in candidates:
                flags = ff.find_flags(plain)
                if flags:
                    where = f"field {blob_name!r} of {blob_rel}" if blob_name else blob_rel
                    ev = Evidence("decrypt",
                                  f"{mode} of {where} under the recovered GCM {label} -> {flags[0]}",
                                  path=blob_rel)
                    note = (f"AES-GCM forbidden attack: recovered the unique subkey from {src} "
                            f"(H={h:032x}, S={s:032x}); {mode} of {where} under {label} "
                            "revealed the flag.")
                    return SolverResult(status="solved", flags=(flags[0],), evidence=(ev,),
                                        engine=engine_id, notes=note, cost=Cost())
    return None
