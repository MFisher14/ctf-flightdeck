#!/usr/bin/env python3
"""Offline Round-5a dispatcher for common cryptographic challenge archetypes.

This module is orchestration only: it feeds bounded static bytes to existing engines,
records why each engine ran, and returns ranked flag-shaped candidates plus derivations.
It never imports a CTF client, opens a socket, executes an artifact, or submits a value.

Public API::

    dispatch(description, files) -> JSON-safe report

``files`` may be a mapping of names to bytes/paths, a sequence of paths, a sequence
of ``(name, bytes)`` pairs, or one path/bytes value.  Invalid/oversized entries are
reported and skipped rather than raising at the dispatcher boundary.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Mapping


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
MAX_FILES = 32
MAX_FILE_BYTES = 1 << 20
MAX_TOTAL_BYTES = 8 << 20
MAX_TEXT = 256 << 10
MAX_SECONDS = 6.0
MAX_PRNG_INTEGER_DIGITS = 1234  # < 4096 bits; bounds int conversion and arithmetic
FLAG_RE = flagfmt.BYTES
FLAG_TEXT_RE = flagfmt.TEXT
_PLACEHOLDERS = {
    "...", "flag", "example", "example_flag", "your_flag", "placeholder",
    "redacted", "replace_me", "insert_flag_here", "test", "sample",
}
_CONFIDENCE = {"low": 0, "medium": 1, "high": 2}


def _load(alias: str, path: Path):
    if alias in sys.modules:
        return sys.modules[alias]
    spec = importlib.util.spec_from_file_location(alias, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"engine unavailable: {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(alias) is module:
            sys.modules.pop(alias, None)
        raise
    return module


def _engines():
    """Load existing engines lazily; importing this dispatcher itself has no side effects."""
    crib = _load("r5a_crib_decode_engine", ROOT / "solvers" / "warmups" / "crib_decode.py")
    modern = _load("r5a_modern_crypto_engine", HERE / "modern_crypto.py")
    return crib, modern


def _core():
    # Use the canonical module name.  ``autosolve`` passes Artifact instances created by
    # that module; loading the same source under a private alias would create a different class
    # identity and make normalize_artifacts reject the otherwise valid handoff.
    return _load("dispatch_core", HERE / "dispatch_core.py")


def _bounded_path(path: Path) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds {MAX_FILE_BYTES}-byte dispatcher cap")
    return data


def _normalise_files(files: Any) -> tuple[dict[str, bytes], list[str]]:
    """Return bounded named bytes and non-fatal ingestion notes."""
    notes: list[str] = []
    if files is None:
        entries: Iterable[Any] = ()
    elif isinstance(files, Mapping):
        entries = list(files.items())
    elif isinstance(files, (str, Path, bytes, bytearray, memoryview)):
        entries = [files]
    else:
        try:
            entries = list(files)
        except (TypeError, MemoryError):
            return {}, ["files input is not a bounded iterable"]

    out: dict[str, bytes] = {}
    total = 0
    for index, item in enumerate(entries):
        if index >= MAX_FILES:
            notes.append(f"file cap reached ({MAX_FILES})")
            break
        name: str
        value: Any
        if isinstance(item, tuple) and len(item) == 2:
            name, value = str(item[0]), item[1]
        elif isinstance(item, (str, Path)):
            value = Path(item)
            name = value.name
        elif isinstance(item, (bytes, bytearray, memoryview)):
            name, value = f"artifact_{index}.bin", item
        else:
            notes.append(f"entry {index} has unsupported type")
            continue
        try:
            if isinstance(value, (str, Path)):
                path = Path(value)
                data = _bounded_path(path)
                if not name or name == str(value):
                    name = path.name
            elif isinstance(value, (bytes, bytearray, memoryview)):
                data = bytes(value)
                if len(data) > MAX_FILE_BYTES:
                    raise ValueError(f"entry exceeds {MAX_FILE_BYTES}-byte dispatcher cap")
            else:
                raise ValueError("value is neither bytes nor a path")
        except (OSError, TypeError, ValueError, MemoryError) as exc:
            notes.append(f"{name or index}: {exc}")
            continue
        if total + len(data) > MAX_TOTAL_BYTES:
            notes.append(f"total byte cap reached ({MAX_TOTAL_BYTES})")
            break
        clean = Path(name).name or f"artifact_{index}.bin"
        while clean in out:
            clean = f"{index}_{clean}"
        out[clean] = data
        total += len(data)
    return out, notes


def _flag_values(value: Any) -> list[str]:
    if isinstance(value, bytes):
        raw = []
        for match in FLAG_RE.finditer(value):
            try:
                raw.append(match.group(0).decode("utf-8", "strict"))
            except UnicodeDecodeError:
                continue
    else:
        raw = [m.group(0) for m in FLAG_TEXT_RE.finditer(str(value or ""))]
    out: list[str] = []
    for flag in raw:
        body = flag[flag.find("{") + 1:-1].strip().casefold()
        if body in _PLACEHOLDERS or not body or set(body) <= {".", "*", "?", "_", "-"}:
            continue
        if flag not in out:
            out.append(flag)
    return out


def _candidate(value: str, archetype: str, source: str, derivation: list[str], *,
               verified: bool, confidence: str) -> dict[str, Any]:
    return _core().make_candidate(
        value, archetype=archetype, engine=f"dispatch_crypto/{archetype}",
        source=source, confidence=confidence, verified=verified,
        derivation=[str(step)[:500] for step in derivation[:16]],
    )


def _attempt(archetype: str, engine: str, status: str, detail: str, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "archetype": archetype,
        "engine": engine,
        "status": status,
        "detail": str(detail)[:1000],
    }
    row.update(extra)
    return row


def _question(description: str) -> dict[str, Any]:
    return {
        "id": "r5a-offline-review",
        "question": (description + " Recover the plaintext flag in the event's flag format.")[:16000],
        "answer_format": {"pattern": flagfmt.current().pattern},
    }


def _chain_transform_stated(description: str, chain: list[str]) -> bool:
    """Require every heuristic transform in a decoder chain to be specifically named."""
    low = description.casefold()
    for raw in chain:
        step = str(raw).casefold()
        if step.startswith("xor"):
            if re.search(r"\bxor\b|\b(?:one|two)[ -]time pad\b|\bkeystream\b", low) is None:
                return False
        elif step == "rot13" or step.endswith("_rot13"):
            if re.search(r"\brot[- ]?13\b", low) is None:
                return False
        elif (match := re.search(r"caesar[_:-]?(\d+)", step)) is not None:
            shift = re.escape(match.group(1))
            if re.search(rf"\b(?:rot[- ]?{shift}|caesar(?:\s+(?:shift\s*)?)?{shift})\b", low) is None:
                return False
        elif "atbash" in step:
            if re.search(r"\batbash\b", low) is None:
                return False
        elif "swapcase" in step:
            if re.search(r"\bswap[ -]?case\b", low) is None:
                return False
        elif re.search(r"affine|vigenere|rail|column|substitution", step):
            # These step names carry recovered keys/orders. Merely naming the family does not pin
            # the chosen key, and this dispatcher does not parse enough prose to validate it.
            return False
    return True


def _encoding_pass(crib, named: dict[str, bytes], description: str, deadline: float,
                   attempts: list, candidates: list):
    for name, data in named.items():
        if time.monotonic() >= deadline:
            attempts.append(_attempt("encoding-chain", "crib_decode.solve_blob", "budget-exhausted",
                                     "global dispatcher deadline reached"))
            return
        try:
            got = crib.solve_blob(data, budget=min(0.35, max(0.05, deadline - time.monotonic())), retry=0)
            last = dict(getattr(crib, "LAST", {}) or {})
        except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError, MemoryError, OSError) as exc:
            attempts.append(_attempt("encoding-chain", "crib_decode.solve_blob", "declined", f"{name}: {exc}"))
            continue
        if not got:
            note = last.get("note") or "no exact flag-shaped decode"
            attempts.append(_attempt("encoding-chain", "crib_decode.solve_blob", "no-candidate",
                                     f"{name}: {note}"))
            continue
        answer, chains, _decoded = got
        flags = _flag_values(answer)
        if not flags:
            attempts.append(_attempt("encoding-chain", "crib_decode.solve_blob", "review-only",
                                     f"{name}: decoder produced a non-flag answer"))
            continue
        chain = list(chains[0]) if chains else []
        # The selected solve_blob answer is its simplest exact path. If another different flag has
        # the same path length, the engine cannot establish which one the challenge asks for.
        minimal = []
        all_flags = last.get("flags") if isinstance(last.get("flags"), list) else []
        valid_rows = [row for row in all_flags
                      if isinstance(row, tuple) and len(row) >= 2
                      and isinstance(row[0], str) and isinstance(row[1], (tuple, list))]
        complete_ambiguity_evidence = bool(valid_rows) and len(valid_rows) == len(all_flags)
        if valid_rows:
            shortest = min(len(row[1]) for row in valid_rows)
            minimal = list(dict.fromkeys(row[0] for row in valid_rows if len(row[1]) == shortest))
        # Malformed engine provenance cannot prove uniqueness. Keep the exact decoded value for
        # review, but decline the stronger verified-local assertion.
        unambiguous = (complete_ambiguity_evidence and len(flags) == 1 and len(minimal) == 1
                       and minimal[0] == flags[0])
        guessed_transform = any(re.search(
            r"(?:xor|caesar|rot\d*|atbash|affine|vigenere|rail|column|substitution|swapcase)",
            str(step), re.I) for step in chain)
        family_stated = _chain_transform_stated(description, chain)
        locally_verified = unambiguous and (not guessed_transform or family_stated)
        for flag in flags:
            candidates.append(_candidate(
                flag, "encoding-chain", name,
                [f"crib_decode selected exact path: {' -> '.join(chain) if chain else 'raw bytes'}",
                 "flag-shaped value extracted from the resulting bytes",
                 "minimal-path ambiguity check passed" if unambiguous else "equal-rank alternatives remain",
                 "transform family was stated" if family_stated else
                 ("codec path needs no guessed key" if not guessed_transform else
                  "transform/key was inferred only from flag shape")],
                verified=locally_verified,
                confidence="high" if locally_verified else "medium",
            ))
        attempts.append(_attempt("encoding-chain", "crib_decode.solve_blob", "candidate",
                                 f"{name}: exact decoder path", chain=chain, unambiguous=unambiguous,
                                 transform_family_stated=family_stated,
                                 verified_local=locally_verified))


def _classical_hypothesis_stated(description: str, hypothesis: str) -> bool:
    """True only when prose pins the specific reversible classical transform."""
    low, hypothesis = description.casefold(), hypothesis.casefold()
    if hypothesis == "rot13":
        return re.search(r"\brot[- ]?13\b", low) is not None
    match = re.fullmatch(r"caesar_(\d+)", hypothesis)
    if match:
        shift = re.escape(match.group(1))
        return re.search(rf"\b(?:rot[- ]?{shift}|caesar(?:\s+(?:shift\s*)?)?{shift})\b", low) is not None
    if hypothesis == "atbash":
        return re.search(r"\batbash\b", low) is not None
    if hypothesis == "morse":
        return re.search(r"\bmorse\b", low) is not None
    if hypothesis == "baconian":
        return re.search(r"\bbacon(?:ian)?\b", low) is not None
    match = re.fullmatch(r"rail_fence_(\d+)", hypothesis)
    if match:
        rails = re.escape(match.group(1))
        return re.search(rf"\brail[ -]?fence(?:\s+cipher)?(?:\s+with)?\s+{rails}\s+rails?\b|"
                         rf"\b{rails}[ -]?rail[ -]?fence\b", low) is not None
    match = re.fullmatch(r"affine_(\d+)_(\d+)", hypothesis)
    if match and re.search(r"\baffine\b", low):
        a, b = map(re.escape, match.groups())
        return (re.search(rf"\ba\s*[:=]\s*{a}\b", low) is not None and
                re.search(rf"\bb\s*[:=]\s*{b}\b", low) is not None)
    return False


def _classical_pass(modern, named: dict[str, bytes], description: str, deadline: float,
                    attempts: list, candidates: list):
    engine = getattr(modern, "classical", None)
    if engine is None:
        attempts.append(_attempt("classical-cipher", "classical.solve_classical", "unavailable",
                                 "existing classical toolkit did not load"))
        return
    keyword = re.search(r"\b(?:caesar|rot-?\d*|vigenere|atbash|affine|rail[ -]?fence|columnar|classical|"
                        r"substitution|playfair|morse|baconian?)\b", description, re.I)
    for name, data in named.items():
        if time.monotonic() >= deadline:
            return
        if len(data) > MAX_TEXT:
            continue
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            try:
                text = data.decode("latin-1")
            except UnicodeError:
                continue
        letter_ratio = sum(ch.isalpha() for ch in text) / max(1, len(text))
        if not keyword and (len(text) < 6 or letter_ratio < 0.55):
            continue
        try:
            all_rows = engine.solve_classical(text, deadline=min(deadline, time.monotonic() + 0.8))
            rows = all_rows[:128]
            complete = len(all_rows) <= len(rows)
        except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError, MemoryError) as exc:
            attempts.append(_attempt("classical-cipher", "classical.solve_classical", "declined", f"{name}: {exc}"))
            continue
        flagged = []
        for hypothesis, plaintext in rows:
            for flag in _flag_values(plaintext):
                hypothesis = str(hypothesis)
                flagged.append((flag, hypothesis,
                                _classical_hypothesis_stated(description, hypothesis)))
        unique = list(dict.fromkeys(flag for flag, _, _ in flagged))
        for flag, hypothesis, stated in flagged:
            unambiguous = complete and len(unique) == 1 and stated
            candidates.append(_candidate(
                flag, "classical-cipher", name,
                [f"classical hypothesis: {hypothesis}", "transformed plaintext contains the flag-shaped value",
                 "the description pins this exact transform and the complete search produced one distinct flag"
                 if unambiguous else "family was unstated, or multiple/unexamined readings remain"],
                verified=unambiguous, confidence="high" if unambiguous else "low",
            ))
        attempts.append(_attempt("classical-cipher", "classical.solve_classical",
                                 "candidate" if flagged else "no-candidate",
                                 f"{name}: {len(rows)} bounded hypotheses, {len(unique)} distinct flag readings; complete={complete}",
                                 stated_hypotheses=sum(1 for _, _, stated in flagged if stated)))


def _modern_pass(modern, named: dict[str, bytes], description: str, deadline: float,
                 attempts: list, candidates: list):
    q = _question(description)
    try:
        material = modern.material(named, description)
        proof = modern.Proof(q)
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError, MemoryError) as exc:
        attempts.append(_attempt("modern-crypto", "modern_crypto.material", "declined", str(exc)))
        return
    signal = (description + " " + " ".join(named) + " " + material.all_text[:20000]).lower()

    if re.search(r"\b(?:xor|keystream|two[- ]time pad|one[- ]time pad|stream cipher)\b", signal):
        try:
            got = modern.solve_xor(material, q, proof, min(deadline, time.monotonic() + 1.2))
        except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError, MemoryError) as exc:
            got = None
            attempts.append(_attempt("xor-keystream", "modern_crypto.solve_xor", "declined", str(exc)))
        if got:
            judged, key = got
            values = _flag_values(judged.get("value"))
            for flag in values:
                candidates.append(_candidate(
                    flag, "xor-keystream", "challenge material",
                    ["existing XOR engine found exactly one plaintext satisfying the explicit flag grammar",
                     f"recovered XOR key: {bytes(key).hex()}", "plaintext was replayed through XOR"],
                    verified=True, confidence="high",
                ))
            attempts.append(_attempt("xor-keystream", "modern_crypto.solve_xor", "candidate" if values else "solved-nonflag",
                                     "single/repeating-key XOR proof", key_hex=bytes(key).hex()))
        else:
            attempts.append(_attempt("xor-keystream", "modern_crypto.solve_xor", "no-candidate",
                                     "no unique plaintext satisfied the flag proof"))
        try:
            reuse = modern.solve_reuse(material, q, proof)
        except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError, MemoryError) as exc:
            reuse = None
            attempts.append(_attempt("keystream-reuse", "modern_crypto.solve_reuse", "declined", str(exc)))
        if reuse:
            vals = _flag_values(reuse.get("value"))
            for flag in vals:
                candidates.append(_candidate(
                    flag, "keystream-reuse", "challenge material",
                    ["two-time-pad relation P xor C1 xor C2 was applied", "one value uniquely satisfied the flag grammar"],
                    verified=True, confidence="high",
                ))
            attempts.append(_attempt("keystream-reuse", "modern_crypto.solve_reuse",
                                     "candidate" if vals else "solved-nonflag", "crib-confirmed keystream reuse"))
        try:
            ranked = modern.solve_repeating_xor(material, q, proof, min(deadline, time.monotonic() + 0.8))
        except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError, MemoryError) as exc:
            ranked = []
            attempts.append(_attempt("xor-keystream", "modern_crypto.solve_repeating_xor", "declined", str(exc)))
        for keysize, key, plaintext, score in ranked[:5]:
            for flag in _flag_values(plaintext):
                candidates.append(_candidate(
                    flag, "xor-keystream", "challenge material",
                    [f"ranked repeating-XOR hypothesis key length {keysize}", f"key={key.hex()}",
                     f"language fitness={score:.6f}", "fitness recovery is a hypothesis, not a proof"],
                    verified=False, confidence="medium",
                ))

    if re.search(r"\b(?:aes|des|3des|rc4|chacha|cipher|decrypt)\b", signal):
        try:
            got = modern.solve_sym(material, q, proof, min(deadline, time.monotonic() + 1.5))
        except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError, MemoryError) as exc:
            got = None
            attempts.append(_attempt("stated-key-cipher", "modern_crypto.solve_sym", "declined", str(exc)))
        if got:
            judged, cipher_name, key = got
            vals = _flag_values(judged.get("value"))
            for flag in vals:
                candidates.append(_candidate(
                    flag, "stated-key-cipher", "challenge material",
                    [f"stated-key candidate uniquely decrypted as {cipher_name}",
                     f"key reading used: {bytes(key).hex()}", "padding/authentication or explicit flag grammar validated plaintext"],
                    verified=True, confidence="high",
                ))
            attempts.append(_attempt("stated-key-cipher", "modern_crypto.solve_sym",
                                     "candidate" if vals else "solved-nonflag", str(cipher_name)))

    rsa_marked = bool(re.search(r"\b(?:rsa|modulus|public exponent|wiener|hastad|fermat|coppersmith|franklin[- ]reiter)\b", signal))
    rsa_marked = rsa_marked or bool(material.params.many("n") and material.params.many("e"))
    if rsa_marked and time.monotonic() < deadline:
        try:
            rows = modern.solve_rsa(material, min(deadline, time.monotonic() + 2.0))
        except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError, MemoryError) as exc:
            rows = []
            attempts.append(_attempt("rsa-weakness", "modern_crypto.solve_rsa", "declined", str(exc)))
        for row in rows:
            hits = []
            for reading, plaintext in row.messages:
                for flag in _flag_values(plaintext):
                    hits.append(flag)
                    candidates.append(_candidate(
                        flag, "rsa-weakness", "challenge material",
                        [f"verified RSA attack: {row.attack}", f"plaintext reading: {reading}",
                         "existing engine replayed the RSA/factor/root relation before returning"],
                        verified=True, confidence="high",
                    ))
            attempts.append(_attempt(
                "rsa-weakness", "modern_crypto.solve_rsa", "candidate" if hits else "solved-nonflag",
                f"attack={row.attack}; messages={len(row.messages)}",
                attack=row.attack, repaired_parameter=row.repaired,
                factors=[str(v) for v in (row.factors or [])[:16]],
            ))
        if not rows:
            attempts.append(_attempt("rsa-weakness", "modern_crypto.solve_rsa", "no-candidate",
                                     "no bounded verified RSA weakness recovered plaintext"))

    ecc_marked = bool(re.search(r"\b(?:ecc|elliptic|weak curve|singular curve|anomalous curve|ecdsa|nonce reuse|hidden number)\b", signal))
    if ecc_marked and time.monotonic() < deadline:
        for archetype, engine_name, fn in (
            ("ecc-weakness", "modern_crypto.solve_ecc", lambda: modern.solve_ecc(material, q, min(deadline, time.monotonic() + 1.5))),
            ("ecdsa-nonce-reuse", "modern_crypto.solve_ecdsa", lambda: modern.solve_ecdsa(material, q)),
            ("ecdsa-hidden-number", "modern_crypto.solve_ecdsa_hnp", lambda: modern.solve_ecdsa_hnp(material, q, min(deadline, time.monotonic() + 1.5))),
        ):
            try:
                got = fn()
            except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError, MemoryError) as exc:
                got = None
                attempts.append(_attempt(archetype, engine_name, "declined", str(exc)))
            if got:
                if archetype == "ecc-weakness":
                    outcome = {"private_scalar": str(got[0]), "weakness": str(got[1]), "verified": True}
                elif archetype == "ecdsa-nonce-reuse":
                    outcome = {"private_scalar": str(got[0]), "nonce": str(got[1]), "curve": str(got[2]), "verified": True}
                else:
                    outcome = {"private_scalar": str(got[0]), "curve": str(got[1]), "verified": True}
                attempts.append(_attempt(archetype, engine_name, "recovered-key",
                                         "key relation replayed by existing engine", outcome=outcome))
            else:
                attempts.append(_attempt(archetype, engine_name, "no-candidate", "required verified relation was absent"))


def _integer_sequences(named: dict[str, bytes]) -> list[tuple[str, list[int]]]:
    out: list[tuple[str, list[int]]] = []
    for name, data in named.items():
        if len(data) > MAX_TEXT:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        try:
            value = json.loads(text)
        except (json.JSONDecodeError, ValueError, RecursionError, MemoryError):
            value = None
        candidates: list[Any] = []
        if isinstance(value, list):
            candidates.append(value)
        elif isinstance(value, dict):
            candidates += [value.get(k) for k in ("outputs", "values", "observations")]
        integer = rf"-?\d{{1,{MAX_PRNG_INTEGER_DIGITS}}}"
        for match in re.finditer(rf"\[\s*({integer}(?:\s*,\s*{integer}){{2,4095}})\s*\]", text[:MAX_TEXT]):
            candidates.append([int(v) for v in re.findall(r"-?\d+", match.group(1))])
        lines = [line.strip().rstrip(",") for line in text.splitlines()]
        if len(lines) >= 3 and all(re.fullmatch(integer, line or "x") for line in lines[:4096]):
            candidates.append([int(line) for line in lines[:4096]])
        for row in candidates:
            if (isinstance(row, list) and 2 <= len(row) <= 4096
                    and all(type(v) is int and abs(v).bit_length() <= 4096 for v in row)):
                item = (name, list(row))
                if item not in out:
                    out.append(item)
    return out[:8]


def _prng_pass(modern, named: dict[str, bytes], description: str, deadline: float, attempts: list):
    low = (description + " " + " ".join(named)).lower()
    if not re.search(r"\b(?:prng|random|rng|mt19937|mersenne|lcg|java\.util\.random|xorshift|xoshiro|pcg)\b", low):
        return
    try:
        sequences = _integer_sequences(named)
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError, MemoryError) as exc:
        attempts.append(_attempt("prng-prediction", "integer-sequence parser", "declined", str(exc)))
        return
    if not sequences:
        attempts.append(_attempt("prng-prediction", "modern_crypto PRNG recovery", "no-candidate",
                                 "no bounded integer output sequence found"))
        return
    lib = modern.lib
    for name, values in sequences:
        probes: list[tuple[str, Any]] = []
        if re.search(r"\b(?:mt19937|mersenne|python random)\b", low) and len(values) >= 624:
            probes.append(("mt_clone", lambda: lib.mt_clone(values, 1)))
        if re.search(r"\bjava(?:\.util\.random)?\b", low) and len(values) >= 2:
            probes.append(("java_random_recover", lambda: lib.java_random_recover(values)))
        if re.search(r"\blcg\b", low) and len(values) >= 6:
            probes.append(("lcg_recover", lambda: lib.lcg_recover(values)))
        if re.search(r"\bxorshift\b", low) and len(values) >= 3:
            probes.append(("xorshift_predict", lambda: lib.xorshift_predict(values)))
        if re.search(r"\bpcg\b", low) and len(values) >= 4:
            probes.append(("pcg32_predict", lambda: lib.pcg32_predict(values, deadline=min(deadline, time.monotonic() + 0.5))))
        for engine_name, probe in probes:
            if time.monotonic() >= deadline:
                return
            try:
                got = probe()
            except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError, MemoryError) as exc:
                got = None
                attempts.append(_attempt("prng-prediction", engine_name, "declined", f"{name}: {exc}"))
            if got is None:
                attempts.append(_attempt("prng-prediction", engine_name, "no-candidate",
                                         f"{name}: ambiguous or replay failed"))
                continue
            if engine_name == "mt_clone":
                outcome = {"next": str(got[0][0]), "verified_outputs": int(got[1]),
                           "verified": bool(got[1] > 0)}
            elif engine_name == "lcg_recover":
                outcome = {"modulus": str(got[0]), "multiplier": str(got[1]), "increment": str(got[2]),
                           "next": str(got[3]), "verified_transitions": int(got[4]),
                           "verified": bool(got[4] > 0)}
            elif engine_name == "xorshift_predict":
                outcome = {"next": str(got[0]), "width": int(got[1]), "variant": str(got[2]),
                           "verified_transitions": int(got[3]), "verified": bool(got[3] > 0)}
            elif isinstance(got, dict):
                outcome = {str(k): (str(v) if isinstance(v, int) and abs(v) > (1 << 53) else v)
                           for k, v in got.items()}
            else:
                outcome = {"next": str(got[0]), "verified": bool(got[-1])}
            attempts.append(_attempt("prng-prediction", engine_name, "prediction",
                                     f"{name}: state/prediction replay completed", outcome=outcome))


def _oracle_plans(description: str, attempts: list):
    low = description.lower()
    plans = []
    if re.search(r"\b(?:cbc|pkcs#?7)\b[^.]{0,80}\bpadding[- ]oracle\b|\bpadding[- ]oracle\b", low):
        plans.append(("cbc-padding-oracle", "crypto_oracles.cbc_padding_oracle_decrypt",
                      "provide one bounded check(ciphertext)->bool callback for the assigned target; strict PKCS#7 validation"))
    if re.search(r"\b(?:rsa[- ]?)?(?:parity|lsb)[- ]oracle\b", low):
        plans.append(("rsa-parity-oracle", "crypto_oracles.rsa_parity_oracle_recover",
                      "provide a bounded parity callback; recovered integer is re-encrypted before acceptance"))
    if re.search(r"\bbleichenbacher\b|\bpkcs#?1(?:[- ]v1\.5)?[- ]oracle\b", low):
        plans.append(("bleichenbacher-oracle", "crypto_oracles.bleichenbacher_pkcs1_v1_5_recover",
                      "provide a bounded PKCS#1 v1.5 predicate; decode structure after interval convergence"))
    if re.search(r"\bmanger\b|\boaep[- ]oracle\b", low):
        plans.append(("manger-oaep-oracle", "crypto_oracles.manger_oaep_recover",
                      "provide a bounded leading-zero predicate; OAEP-decode and hash-check locally"))
    for archetype, engine, detail in plans:
        attempts.append(_attempt(archetype, engine, "plan-only", detail,
                                 requires_assigned_target_callback=True, network_requests=0,
                                 executed=False, candidate_only=True))


def _rank(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _core().rank_candidates(candidates)


def _run_bounded_pass(label: str, function, attempts: list[dict[str, Any]], *args: Any) -> None:
    """Contain an unexpected existing-engine failure at the orchestration boundary."""
    try:
        function(*args)
    except (Exception, SystemExit) as exc:
        attempts.append(_attempt(label, function.__name__, "declined",
                                 f"unexpected engine boundary failure: {type(exc).__name__}: {exc}"))


def dispatch(description: str, files: Any, *, category: str = "") -> dict[str, Any]:
    """Run bounded offline crypto dispatch and return a JSON-safe human-review report."""
    core = _core()
    try:
        description = core.normalize_description(description)
        if isinstance(files, (bytes, bytearray, memoryview)):
            files = [("artifact_0.bin", bytes(files))]
        artifacts = core.normalize_artifacts(files, per_file_cap=MAX_FILE_BYTES,
                                             total_cap=MAX_TOTAL_BYTES)
    except (Exception, SystemExit) as exc:
        report = core.empty_report("r5a_crypto", [])
        report["warnings"].append(str(exc))
        report["category"] = str(category or "")
        return core.finalize_report(report)
    named: dict[str, bytes] = {}
    processed_artifacts = artifacts[:MAX_FILES]
    for index, artifact in enumerate(processed_artifacts):
        if artifact.truncated:
            continue
        name = artifact.name
        if name in named:
            name = f"{index}_{name}"
            while name in named:
                name = f"_{name}"
        named[name] = artifact.data
    ingestion = [f"{artifact.name}: truncated input declined by whole-file engines"
                 for artifact in processed_artifacts if artifact.truncated]
    if len(artifacts) > MAX_FILES:
        ingestion.append(f"file cap reached ({MAX_FILES}); {len(artifacts) - MAX_FILES} artifact(s) skipped")
    attempts: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    evidence = [f"artifact {name}: {len(data)} bytes" for name, data in named.items()]
    deadline = time.monotonic() + MAX_SECONDS
    try:
        crib, modern = _engines()
    except (Exception, SystemExit) as exc:
        report = core.empty_report("r5a_crypto", artifacts)
        report.update({"category": str(category or ""), "score": 0.0,
                       "evidence": evidence, "ingestion_notes": ingestion,
                       "attempts": [_attempt("crypto", "engine-loader", "unavailable", str(exc))]})
        return core.finalize_report(report)

    _run_bounded_pass("encoding-chain", _encoding_pass, attempts,
                      crib, named, description, deadline, attempts, candidates)
    _run_bounded_pass("classical-cipher", _classical_pass, attempts,
                      modern, named, description, deadline, attempts, candidates)
    _run_bounded_pass("modern-crypto", _modern_pass, attempts,
                      modern, named, description, deadline, attempts, candidates)
    _run_bounded_pass("prng-prediction", _prng_pass, attempts,
                      modern, named, description, deadline, attempts)
    _run_bounded_pass("crypto-oracle", _oracle_plans, attempts, description, attempts)
    ranked = _rank(candidates)
    matched = sum(row["status"] not in ("no-candidate", "declined", "unavailable") for row in attempts)
    score = min(1.0, round((0.55 if ranked else 0.0) + min(0.45, matched * 0.08), 3))
    report = core.empty_report("r5a_crypto", artifacts)
    report.update({
        "category": str(category or ""), "score": score, "evidence": evidence,
        "ingestion_notes": ingestion, "attempts": attempts, "candidates": ranked,
        "limits": {"max_files": MAX_FILES, "max_file_bytes": MAX_FILE_BYTES,
                   "max_total_bytes": MAX_TOTAL_BYTES, "max_seconds": MAX_SECONDS},
    })
    return core.finalize_report(report)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="dispatch_crypto.py", description="offline crypto archetype dispatcher")
    parser.add_argument("files", nargs="*")
    parser.add_argument("--description", default="")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        if not args.files and not args.description:
            raise ValueError("provide at least one file or --description")
        report = dispatch(args.description, args.files)
        print(json.dumps(report, sort_keys=True, ensure_ascii=False,
                         indent=None if args.json else 2))
        return 0
    except (OSError, TypeError, ValueError, OverflowError, UnicodeError, RecursionError, MemoryError) as exc:
        print(f"dispatch_crypto: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
