#!/usr/bin/env python3
"""Shared, offline-only primitives for the Round-5a orchestration layer.

This module deliberately has no dependency on the CTFd client, sockets, submission code, or
challenge runtimes.  It normalizes bounded artifacts, recognizes archetypes, records engine attempts,
and ranks flag-shaped values together with their derivation.  ``verified`` means only that the stated
local transform/integrity relation was checked; every candidate remains ``submission_ready=False`` so
the human must review it.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import os
import re
import time
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Callable


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_ARTIFACTS = 64
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_DESCRIPTION = 64 * 1024
MAX_CATEGORY = 256
MAX_CANDIDATES = 128
MAX_DERIVATION_STEPS = 32

FLAG_TEXT_RE = flagfmt.TEXT
FLAG_BYTES_RE = flagfmt.BYTES
_PLACEHOLDER_BODIES = {
    "...", "flag", "your_flag", "example", "example_flag", "insert_flag_here",
    "replace_me", "redacted", "placeholder", "test", "sample",
}
_PLACEHOLDER_TOKENS = {
    "your", "flag", "example", "redacted", "replace", "me", "insert", "sample",
    "test", "placeholder", "here", "value", "answer", "todo", "changeme", "xxx",
}
_CONFIDENCE = {"low": 1, "medium": 2, "high": 3}


class R5AInputError(ValueError):
    """A bounded-input or result-contract error safe to show at a CLI boundary."""


@dataclasses.dataclass(frozen=True)
class Artifact:
    """One immutable artifact read as data, never imported or executed."""

    name: str
    data: bytes
    source: str
    truncated: bool = False

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def suffix(self) -> str:
        return Path(self.name).suffix.lower()

    def public(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "size_read": len(self.data),
            "truncated": self.truncated,
            "sha256_read": self.sha256,
        }


def _safe_name(value: Any, fallback: str) -> str:
    text = value if isinstance(value, str) and value else fallback
    text = "".join(character if character.isprintable() else "_" for character in text)
    text = Path(text).name[:240]
    return text or fallback


def _display_text(value: Any, *, maximum: int = 1000) -> str:
    """Bound and escape non-printing characters before text reaches a terminal-facing report."""
    text = str(value)
    safe = "".join(
        character if character.isprintable() else f"\\u{ord(character):04x}"
        for character in text
    )
    return safe[:maximum]


def _read_path(path: Path, *, cap: int) -> Artifact:
    try:
        size = path.stat().st_size
        if not path.is_file():
            raise R5AInputError(f"not a regular file: {path}")
        with path.open("rb") as handle:
            data = handle.read(cap + 1)
    except (OSError, ValueError) as exc:
        raise R5AInputError(f"cannot read {path}: {exc}") from None
    truncated = size > cap or len(data) > cap
    return Artifact(_safe_name(path.name, "artifact.bin"), data[:cap], str(path), truncated)


def _one_artifact(value: Any, *, index: int, cap: int, explicit_name: str | None = None) -> Artifact:
    fallback = f"artifact-{index}.bin"
    if isinstance(value, Artifact):
        if not isinstance(value.name, str) or not isinstance(value.source, str):
            raise R5AInputError(f"invalid Artifact metadata at index {index}")
        if not isinstance(value.data, (bytes, bytearray, memoryview)):
            raise R5AInputError(f"invalid Artifact data at index {index}")
        if type(value.truncated) is not bool:
            raise R5AInputError(f"invalid Artifact truncation marker at index {index}")
        raw = bytes(value.data)
        return Artifact(_safe_name(value.name, fallback), raw[:cap], value.source[:1000],
                        value.truncated or len(raw) > cap)
    if isinstance(value, (os.PathLike, Path)):
        path = Path(value)
        if path.exists():
            artifact = _read_path(path, cap=cap)
            return (artifact if explicit_name is None else
                    Artifact(_safe_name(explicit_name, fallback), artifact.data,
                             artifact.source, artifact.truncated))
        raise R5AInputError(f"artifact path does not exist: {path}")
    if isinstance(value, str) and explicit_name is None:
        path = Path(value)
        if path.exists():
            return _read_path(path, cap=cap)
        # A string supplied as a mapping value is content; a bare string is intentionally a path.
        raise R5AInputError(f"artifact path does not exist: {path}")
    if isinstance(value, str):
        raw = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    else:
        raise R5AInputError(f"unsupported artifact input at index {index}: {type(value).__name__}")
    return Artifact(_safe_name(explicit_name, fallback), raw[:cap], "memory", len(raw) > cap)


def normalize_artifacts(files: Any, *, per_file_cap: int = MAX_ARTIFACT_BYTES,
                        total_cap: int = MAX_TOTAL_BYTES) -> list[Artifact]:
    """Normalize paths, ``{name: bytes}``, ``(name, bytes)`` pairs, or :class:`Artifact` values.

    The returned data is bounded.  An over-cap member is marked truncated so a dispatcher can decline
    a whole-file parse rather than silently treating a prefix as complete.
    """
    if not isinstance(per_file_cap, int) or not 1 <= per_file_cap <= MAX_ARTIFACT_BYTES:
        raise R5AInputError("invalid per-file cap")
    if not isinstance(total_cap, int) or not 1 <= total_cap <= MAX_TOTAL_BYTES:
        raise R5AInputError("invalid total cap")
    if files is None:
        return []

    items: list[tuple[str | None, Any]] = []
    if isinstance(files, Mapping):
        try:
            for index, (name, value) in enumerate(files.items()):
                if index >= MAX_ARTIFACTS:
                    raise R5AInputError(f"too many artifacts (> {MAX_ARTIFACTS})")
                if not isinstance(name, str):
                    raise R5AInputError("artifact mapping names must be text")
                items.append((name, value))
        except R5AInputError:
            raise
        except Exception as exc:
            raise R5AInputError(f"cannot enumerate artifact mapping: {type(exc).__name__}") from None
    elif isinstance(files, Artifact) or isinstance(files, (str, os.PathLike, Path)):
        items = [(None, files)]
    elif (isinstance(files, tuple) and len(files) == 2 and isinstance(files[0], str)
          and isinstance(files[1], (str, bytes, bytearray, memoryview))):
        items = [(files[0], files[1])]
    elif isinstance(files, Sequence) and not isinstance(files, (str, bytes, bytearray, memoryview)):
        try:
            for index, value in enumerate(files):
                if index >= MAX_ARTIFACTS:
                    raise R5AInputError(f"too many artifacts (> {MAX_ARTIFACTS})")
                if (isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str)
                        and isinstance(value[1], (str, bytes, bytearray, memoryview))):
                    items.append((value[0], value[1]))
                else:
                    items.append((None, value))
        except R5AInputError:
            raise
        except Exception as exc:
            raise R5AInputError(f"cannot enumerate artifact sequence: {type(exc).__name__}") from None
    else:
        raise R5AInputError("files must be paths, named bytes, or a bounded sequence")

    if len(items) > MAX_ARTIFACTS:
        raise R5AInputError(f"too many artifacts ({len(items)} > {MAX_ARTIFACTS})")
    out: list[Artifact] = []
    total = 0
    for index, (name, value) in enumerate(items):
        remaining = total_cap - total
        if remaining <= 0:
            raise R5AInputError(f"artifact bytes exceed total cap ({total_cap})")
        artifact = _one_artifact(value, index=index, cap=min(per_file_cap, remaining),
                                 explicit_name=name)
        out.append(artifact)
        total += len(artifact.data)
        if artifact.truncated and len(artifact.data) == remaining and remaining < per_file_cap:
            raise R5AInputError(f"artifact bytes exceed total cap ({total_cap})")
    return out


def normalize_description(description: Any) -> str:
    if description is None:
        return ""
    if not isinstance(description, str):
        raise R5AInputError("description must be text")
    if len(description) > MAX_DESCRIPTION:
        raise R5AInputError(f"description exceeds {MAX_DESCRIPTION} characters")
    return description


def normalize_category(category: Any) -> str:
    if category is None:
        return ""
    if not isinstance(category, str):
        raise R5AInputError("category must be text")
    if len(category) > MAX_CATEGORY:
        raise R5AInputError(f"category exceeds {MAX_CATEGORY} characters")
    return _display_text(category, maximum=MAX_CATEGORY)


def is_placeholder_flag(value: str) -> bool:
    if not isinstance(value, str) or FLAG_TEXT_RE.fullmatch(value) is None:
        return True
    if not value.isprintable():
        return True
    body = value[value.find("{") + 1:-1].strip().casefold()
    normalized = re.sub(r"[\s._-]+", "_", body).strip("_")
    tokens = [token for token in re.split(r"[^a-z0-9]+", body) if token]
    compact = "".join(tokens)
    obvious = bool(tokens) and all(
        token in _PLACEHOLDER_TOKENS or token.isdigit() for token in tokens
    ) and any(token in _PLACEHOLDER_TOKENS - {"value", "answer", "here", "me"}
              for token in tokens)
    patterned = re.fullmatch(
        r"(?:yourflag|flaghere|flagvalue|youranswer|answerhere|redactedflag|replaceme|"
        r"insertflaghere|sampleflag|testflag|flag|sample|test|redacted|answer|value|"
        r"placeholder|example)\d*", compact,
    ) is not None
    return (body in _PLACEHOLDER_BODIES or normalized in _PLACEHOLDER_BODIES or
            not body or set(body) <= {".", "*", "?", "_", "-"} or obvious or patterned)


def flag_hits(blob: bytes | str, *, source: str = "unknown") -> list[dict[str, Any]]:
    """Return exact flag-shaped substrings and offsets, filtering documentation placeholders."""
    if isinstance(blob, str):
        raw = blob.encode("utf-8", "replace")
    elif isinstance(blob, (bytes, bytearray, memoryview)):
        raw = bytes(blob)
    else:
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in FLAG_BYTES_RE.finditer(raw):
        try:
            value = match.group(0).decode("utf-8", "strict")
        except UnicodeDecodeError:
            continue
        if value in seen or is_placeholder_flag(value):
            continue
        seen.add(value)
        out.append({"value": value, "offset": match.start(), "source": source})
    return out


def make_candidate(value: str, *, archetype: str, engine: str, source: str,
                   derivation: Sequence[str], verified: bool = False,
                   confidence: str = "low", evidence: Sequence[str] = (),
                   warnings: Sequence[str] = ()) -> dict[str, Any]:
    """Create one review-only candidate under a strict, JSON-safe contract."""
    if not isinstance(value, str) or is_placeholder_flag(value):
        raise R5AInputError("candidate is not a non-placeholder flag-shaped value")
    if confidence not in _CONFIDENCE:
        raise R5AInputError("invalid candidate confidence")
    steps = [_display_text(step) for step in derivation if str(step).strip()]
    if not steps:
        raise R5AInputError("candidate needs a derivation")
    if len(steps) > MAX_DERIVATION_STEPS:
        steps = steps[:MAX_DERIVATION_STEPS]
    return {
        "value": value,
        "archetype": _display_text(archetype),
        "engine": _display_text(engine),
        "source": _display_text(source),
        "confidence": confidence,
        "verified": bool(verified),
        "submission_ready": False,
        "requires_human_review": True,
        "derivation": steps,
        "evidence": [_display_text(item) for item in evidence if str(item).strip()][:32],
        "warnings": [_display_text(item) for item in warnings if str(item).strip()][:32],
    }


def make_attempt(engine: str, *, status: str, score: int = 0,
                 evidence: Sequence[str] = (), error: str | None = None,
                 elapsed_ms: float | None = None) -> dict[str, Any]:
    if status not in {"selected", "completed", "declined", "unavailable", "error", "skipped"}:
        raise R5AInputError("invalid attempt status")
    row: dict[str, Any] = {
        "engine": _display_text(engine), "status": status, "score": int(score),
        "evidence": [_display_text(item) for item in evidence if str(item).strip()][:32],
    }
    if error:
        row["error"] = _display_text(str(error).splitlines()[0])
    if elapsed_ms is not None:
        row["elapsed_ms"] = round(max(0.0, float(elapsed_ms)), 3)
    return row


def empty_report(dispatcher: str, artifacts: Sequence[Artifact]) -> dict[str, Any]:
    return {
        "schema": "csctf-r5a-autosolve-v1",
        "dispatcher": dispatcher,
        "offline": True,
        "network_requests": 0,
        "submitted": False,
        "artifacts": [item.public() for item in artifacts],
        "attempts": [],
        "candidates": [],
        "observations": [],
        "warnings": [],
    }


def safe_engine_call(engine: str, function: Callable[..., Any], *args: Any,
                     score: int = 0, **kwargs: Any) -> tuple[Any, dict[str, Any]]:
    """Call a local parser boundary and convert ordinary failures/SystemExit into an attempt row."""
    started = time.monotonic()
    try:
        value = function(*args, **kwargs)
        declined = (value is None or (type(value) is list and not value)
                    or (type(value) is dict and not value)
                    or (type(value) is str and not value))
        status = "declined" if declined else "completed"
    except (Exception, SystemExit) as exc:  # never leak a parser traceback through orchestration
        elapsed = (time.monotonic() - started) * 1000
        return None, make_attempt(engine, status="error", score=score,
                                  error=f"{type(exc).__name__}: {exc}", elapsed_ms=elapsed)
    elapsed = (time.monotonic() - started) * 1000
    return value, make_attempt(engine, status=status, score=score, elapsed_ms=elapsed)


def _candidate_key(candidate: Mapping[str, Any]) -> tuple[int, int, int, str]:
    return (
        1 if candidate.get("verified") is True else 0,
        _CONFIDENCE.get(str(candidate.get("confidence")), 0),
        len(candidate.get("evidence") or ()),
        str(candidate.get("value") or ""),
    )


def _candidate_quality(candidate: Mapping[str, Any]) -> tuple[int, int, int, int]:
    return (
        1 if candidate.get("verified") is True else 0,
        _CONFIDENCE.get(str(candidate.get("confidence")), 0),
        int(candidate.get("corroborations") or 1),
        len(candidate.get("evidence") or ()),
    )


def rank_candidates(candidates: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate exact values, combine provenance, and rank without selecting a winner."""
    merged: dict[str, dict[str, Any]] = {}
    for raw in candidates:
        value = raw.get("value") if isinstance(raw, Mapping) else None
        if not isinstance(value, str) or is_placeholder_flag(value):
            continue
        row = dict(raw)
        row["submission_ready"] = False
        row["requires_human_review"] = True
        if value not in merged:
            merged[value] = row
            merged[value]["corroborations"] = 1
            merged[value]["derivation_paths"] = 1
            merged[value]["sources"] = [str(row.get("source") or "unknown")]
            continue
        old = merged[value]
        old["derivation_paths"] = int(old.get("derivation_paths", 1)) + 1
        old_verified = old.get("verified") is True
        row_verified = row.get("verified") is True
        replace_primary = ((row_verified and not old_verified) or
                           (row_verified == old_verified and
                            _CONFIDENCE.get(str(row.get("confidence")), 0) >
                            _CONFIDENCE.get(str(old.get("confidence")), 0)))
        if replace_primary:
            # A verified branch is authoritative over an unverified one even when its confidence is
            # lower.  Never launder an unverified branch's confidence/engine into a verified result.
            for key in ("archetype", "engine", "confidence"):
                old[key] = row.get(key)
        old["verified"] = old_verified or row_verified
        for key in ("derivation", "evidence", "warnings"):
            combined = list(old.get(key) or [])
            for item in row.get(key) or []:
                if item not in combined:
                    combined.append(item)
            old[key] = combined[:MAX_DERIVATION_STEPS if key == "derivation" else 32]
        sources = list(old.get("sources") or [])
        new_source = str(row.get("source") or "unknown")
        if new_source not in sources:
            sources.append(new_source)
        old["sources"] = sorted(sources)
        old["corroborations"] = len(sources)
        old["source"] = "; ".join(old["sources"])
    rows = sorted(merged.values(), key=_candidate_key, reverse=True)[:MAX_CANDIDATES]
    top_quality = max((_candidate_quality(row) for row in rows), default=None)
    top_tied = (top_quality is not None and
                sum(_candidate_quality(row) == top_quality for row in rows) > 1)
    for index, row in enumerate(rows, 1):
        row["rank"] = index
        row["rank_reason"] = (
            f"verified={bool(row.get('verified'))}; confidence={row.get('confidence', 'low')}; "
            f"corroborations={row.get('corroborations', 1)}"
        )
        if top_tied and _candidate_quality(row) == top_quality:
            row["quality_tie"] = True
            row["warnings"] = list(row.get("warnings") or [])
            warning = "top candidates have equal evidence quality; ordering is lexical, not evidence"
            if warning not in row["warnings"]:
                row["warnings"].append(warning)
            row["rank_reason"] += "; tied top quality (ordering is not evidence)"
    return rows


def finalize_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Enforce the public no-submit contract and JSON serializability."""
    out = dict(report)
    out["offline"] = True
    out["network_requests"] = 0
    out["submitted"] = False
    out["candidates"] = rank_candidates(out.get("candidates") or [])
    out["candidate_count"] = len(out["candidates"])
    out["human_review_required"] = bool(out["candidates"] or out.get("observations"))
    # This is a contract assertion, not a custom encoder that could hide unserializable engine data.
    try:
        json.dumps(out, sort_keys=True, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise R5AInputError(f"dispatcher produced non-JSON result: {exc}") from None
    return out


_ARCHETYPE_TERMS: dict[str, tuple[str, ...]] = {
    "encoding-chain": ("encode", "decode", "base64", "base 64", "base32", "base 32",
                       "base85", "base 85", "hex", "cyberchef", "layers"),
    "xor-keystream": ("xor", "keystream", "one time pad", "otp reuse", "crib drag"),
    "classical-cipher": ("caesar", "vigenere", "substitution", "rail fence", "columnar", "morse"),
    "rsa-ecc": ("rsa", "coppersmith", "wiener", "elliptic", "ecc", "ecdsa", "nonce reuse"),
    "crypto-oracle": ("padding oracle", "parity oracle", "bleichenbacher", "manger", "oracle"),
    "prng": ("prng", "random", "mt19937", "lcg", "xorshift", "xoshiro", "pcg"),
    "image-stego": ("stego", "lsb", "dct", "dwt", "pixels", "image", "png", "jpeg"),
    "audio-stego": ("audio", "wav", "spectrogram", "dtmf", "fsk", "sstv", "tones"),
    "archive-key-leak": ("archive", "zip", "7z", "tar", "keepass", "rclone", "sops", "age key"),
    "qr-barcode": ("qr", "barcode", "datamatrix", "aztec", "pdf417"),
    "pcap-network": ("pcap", "packet", "wireshark", "dns", "tcp stream", "network capture"),
    "maldoc": ("macro", "maldoc", "ole", "docm", "vba", "powershell", "pdf javascript"),
    "disk-forensics": ("disk image", "qcow", "vmdk", "vhdx", "ewf", "apfs", "btrfs"),
    "pwn-recon": ("format string", "rop", "ret2libc", "heap", "buffer overflow", "got", "plt"),
    "reverse-engineering": ("reverse", "binary", "elf", "pe", "wasm", "decompile", "pyinstaller"),
    "web-trust": ("jwt", "session", "ssti", "xxe", "ssrf", "graphql", "idor", "web"),
    "blockchain": ("blockchain", "wallet", "bitcoin", "ethereum", "solidity", "evm"),
    "database": ("sqlite", "database", "sql dump", "csv", "registry"),
    "email-metadata": ("email", "eml", "phishing", "exif", "metadata", "pst", "ost"),
    "firmware-mobile": ("firmware", "uf2", "apk", "ios", "macho", "dyld", "baseband"),
    "ics-rf": ("modbus", "dnp3", "bacnet", "s7comm", "opc-ua", "profinet", "zigbee", "ble"),
}


def classify_archetypes(description: str, artifacts: Sequence[Artifact]) -> list[dict[str, Any]]:
    """Rank common archetypes from description, suffix, and bounded magic only."""
    description = normalize_description(description)
    haystack = description.casefold()
    normalized_haystack = re.sub(r"[-_/]+", " ", haystack)
    scores = {name: 0 for name in _ARCHETYPE_TERMS}
    evidence: dict[str, list[str]] = {name: [] for name in _ARCHETYPE_TERMS}
    for archetype, terms in _ARCHETYPE_TERMS.items():
        for term in terms:
            # Short protocol/format names (PE, QR, ECC, JWT, …) must be whole tokens.  A raw
            # substring check would classify ordinary words such as "inspect" as PE reversing.
            normalized_term = re.sub(r"[-_/]+", " ", term)
            if ((len(normalized_term) <= 3 and re.search(
                    r"(?<![a-z0-9])" + re.escape(normalized_term) + r"(?![a-z0-9])",
                    normalized_haystack))
                    or (len(normalized_term) > 3 and normalized_term in normalized_haystack)):
                scores[archetype] += 4
                evidence[archetype].append(f"description:{term}")

    for artifact in artifacts:
        data, suffix = artifact.data, artifact.suffix
        signals: list[tuple[str, str]] = []
        if data.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF8", b"RIFF")):
            if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
                signals.append(("audio-stego", "magic:WAVE"))
            else:
                signals.append(("image-stego", "magic:image"))
                signals.append(("qr-barcode", "image may carry symbol"))
        if data.startswith((b"PK\x03\x04", b"7z\xbc\xaf'\x1c", b"Rar!\x1a\x07", b"\x1f\x8b")):
            signals.append(("archive-key-leak", "magic:archive"))
        if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
            signals.append(("pcap-network", "magic:pcap"))
        if data.startswith((b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"%PDF-")):
            signals.append(("maldoc", "magic:document"))
        if data.startswith((b"\x7fELF", b"MZ", b"\x00asm", b"\xca\xfe\xba\xbe")):
            signals.extend((("reverse-engineering", "magic:executable"),
                            ("pwn-recon", "executable recon")))
        if data.startswith(b"SQLite format 3\x00"):
            signals.append(("database", "magic:sqlite"))
        if data.startswith((b"QFI\xfb", b"vhdxfile", b"KDMV")):
            signals.append(("disk-forensics", "magic:disk-image"))
        if suffix in {".wav", ".flac", ".mp3", ".ogg"}:
            signals.append(("audio-stego", f"suffix:{suffix}"))
        if suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".pgm"}:
            signals.extend((("image-stego", f"suffix:{suffix}"), ("qr-barcode", f"suffix:{suffix}")))
        if suffix in {".pcap", ".pcapng", ".cap"}:
            signals.append(("pcap-network", f"suffix:{suffix}"))
        if suffix in {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pdf", ".rtf"}:
            signals.append(("maldoc", f"suffix:{suffix}"))
        if suffix in {".eml", ".mbox", ".msg", ".pst", ".ost"}:
            signals.append(("email-metadata", f"suffix:{suffix}"))
        if suffix in {".zip", ".7z", ".rar", ".tar", ".gz", ".xz"}:
            signals.append(("archive-key-leak", f"suffix:{suffix}"))
        if suffix in {".elf", ".exe", ".dll", ".so", ".wasm", ".pyc", ".jar", ".class"}:
            signals.append(("reverse-engineering", f"suffix:{suffix}"))
        if suffix in {".db", ".sqlite", ".csv", ".tsv", ".sql"}:
            signals.append(("database", f"suffix:{suffix}"))
        for archetype, signal in signals:
            scores[archetype] += 5
            evidence[archetype].append(f"{artifact.name}:{signal}")

    rows = [{"archetype": name, "score": score, "evidence": evidence[name]}
            for name, score in scores.items() if score > 0]
    if not rows:
        rows = [{"archetype": "unknown", "score": 1,
                 "evidence": ["no strong keyword, suffix, or magic signal"]}]
    return sorted(rows, key=lambda row: (-row["score"], row["archetype"]))


_GROUPS = {
    "crypto": {"encoding-chain", "xor-keystream", "classical-cipher", "rsa-ecc",
               "crypto-oracle", "prng"},
    "forensics": {"image-stego", "audio-stego", "archive-key-leak", "qr-barcode",
                  "pcap-network", "maldoc", "disk-forensics", "database", "email-metadata",
                  "firmware-mobile", "ics-rf"},
    "exploit": {"pwn-recon", "reverse-engineering", "web-trust", "blockchain"},
}


def dispatcher_scores(archetypes: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    scores = {name: 0 for name in _GROUPS}
    evidence = {name: [] for name in _GROUPS}
    unknown = any(row.get("archetype") == "unknown" for row in archetypes)
    for row in archetypes:
        archetype = str(row.get("archetype"))
        score = int(row.get("score") or 0)
        for group, names in _GROUPS.items():
            if archetype in names:
                scores[group] += score
                evidence[group].append(archetype)
    if unknown:
        scores = {name: 1 for name in _GROUPS}
        evidence = {name: ["unknown fallback"] for name in _GROUPS}
    rows = [{"dispatcher": name, "score": score, "evidence": evidence[name]}
            for name, score in scores.items() if score > 0]
    return sorted(rows, key=lambda row: (-row["score"], row["dispatcher"]))


def direct_artifact_report(description: str, artifacts: Sequence[Artifact]) -> dict[str, Any]:
    """Exact-string backstop. Description hits remain unverified; file hits need global uniqueness."""
    report = empty_report("r5a_direct_flag_scan", artifacts)
    file_hits: list[tuple[Artifact, dict[str, Any]]] = []
    for artifact in artifacts:
        hits = flag_hits(artifact.data, source=artifact.name)
        report["attempts"].append(make_attempt("direct-byte-flag-scan", status="completed",
                                               score=10 if hits else 0,
                                               evidence=[f"{artifact.name}:{len(hits)} exact hit(s)"]))
        file_hits.extend((artifact, hit) for hit in hits)
    distinct = {hit["value"] for _, hit in file_hits}
    # Global uniqueness: a single scanned value only PROVES uniqueness when every artifact was read in
    # full. If ANY sibling was truncated by the read caps, a competing value could sit past its cutoff,
    # so a lone hit in a complete file must NOT be stamped verified (it could be a decoy while the real
    # flag lies in the unscanned tail of a large sibling).
    any_truncated = any(a.truncated for a in artifacts)
    for artifact, hit in file_hits:
        verified = len(distinct) == 1 and not any_truncated
        warnings = []
        if any_truncated:
            warnings.append("a supplied artifact was truncated; unseen competing values may exist")
        report["candidates"].append(make_candidate(
            hit["value"], archetype="direct-artifact-flag", engine="exact byte scan",
            source=artifact.name, verified=verified, confidence="high" if verified else "medium",
            derivation=[f"read bounded bytes from {artifact.name}",
                        f"matched exact flag syntax at byte offset {hit['offset']}"],
            evidence=[f"sha256(read)={artifact.sha256}", f"distinct file values={len(distinct)}",
                      f"all artifacts read in full={not any_truncated}"],
            warnings=warnings,
        ))
    for hit in flag_hits(description, source="description"):
        report["candidates"].append(make_candidate(
            hit["value"], archetype="description-flag", engine="exact description scan",
            source="description", verified=False, confidence="low",
            derivation=["matched a non-placeholder flag-shaped string in challenge description"],
            evidence=[f"character offset={hit['offset']}"],
            warnings=["challenge prose can contain examples; corroborate before using"],
        ))
    return finalize_report(report)


def public_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False,
                      allow_nan=False) + "\n"

