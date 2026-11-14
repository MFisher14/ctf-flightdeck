#!/usr/bin/env python3
"""Bounded, metadata-only profiling of WhatsApp and Signal database artifacts.

This module deliberately complements :mod:`mobile_artifacts`: that engine already
contains the repository's byte-backed SQLite and WAL parser.  Here, its parsed
schema is reduced to table/column/count metadata and compared with version-aware
WhatsApp and Signal table families.  No message value is returned, no SQLite SQL
is executed, and encrypted artifacts are identified but never decrypted.

The table names used for WhatsApp are community-observed forensic signatures, not
a stable vendor schema.  A classification therefore always includes its exact
evidence and never claims that an application was active at acquisition time.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping

import mobile_artifacts


class MessengerProfileError(ValueError):
    """The supplied messenger artifact or schema facts are invalid or oversized."""


MAX_INPUT = 128 << 20
MAX_TABLES = 1024
MAX_COLUMNS = 1024
MAX_SCHEMA_COLUMNS = 32_768
MAX_COMPANIONS = 64
MAX_PATH = 4096
MAX_NAME = 4096
SQLITE_MAGIC = b"SQLite format 3\x00"
_CRYPT_SUFFIX = re.compile(r"\.crypt(12|14|15)$", re.IGNORECASE)


def _artifact_bytes(data: bytes | bytearray | memoryview) -> bytes:
    try:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise MessengerProfileError("artifact input must be bytes")
        raw = bytes(data)
        if not raw:
            raise MessengerProfileError("artifact is empty")
        if len(raw) > MAX_INPUT:
            raise MessengerProfileError("artifact exceeds 128 MiB cap")
        return raw
    except MessengerProfileError:
        raise
    except Exception as exc:
        raise MessengerProfileError("could not normalize artifact bytes") from exc


def _display_name(filename: str | os.PathLike[str] | None) -> str:
    try:
        if filename is None:
            return "<memory>"
        value = os.fspath(filename)
        if not isinstance(value, str) or not value or len(value) > MAX_PATH:
            raise MessengerProfileError("filename must be a non-empty text path")
        return value
    except MessengerProfileError:
        raise
    except Exception as exc:
        raise MessengerProfileError("invalid artifact filename") from exc


def _companion_report(filename: str, companions: Iterable[str | os.PathLike[str]] | None) -> dict[str, Any]:
    if companions is None:
        values: list[str] = []
    else:
        if isinstance(companions, (str, bytes, os.PathLike)):
            raise MessengerProfileError("companions must be an iterable of paths, not one path")
        try:
            supplied = list(companions)
        except Exception as exc:
            raise MessengerProfileError("invalid companion path collection") from exc
        if len(supplied) > MAX_COMPANIONS:
            raise MessengerProfileError("companion count exceeds cap")
        values = []
        for value in supplied:
            try:
                rendered = os.fspath(value)
            except Exception as exc:
                raise MessengerProfileError("invalid companion path") from exc
            if not isinstance(rendered, str) or not rendered or len(rendered) > MAX_PATH:
                raise MessengerProfileError("companion paths must be non-empty text")
            values.append(rendered)

    base = Path(filename).name if filename != "<memory>" else ""
    rows = []
    for value in sorted(set(values)):
        leaf = Path(value).name
        if leaf.endswith("-wal"):
            role = "wal"
        elif leaf.endswith("-shm"):
            role = "shm"
        else:
            role = "other"
        matches_main = bool(base and leaf in {base + "-wal", base + "-shm"})
        rows.append({"path": value, "role": role, "matches_main": matches_main})
    return {
        "artifacts": rows,
        "wal_present": any(item["role"] == "wal" and item["matches_main"] for item in rows),
        "shm_present": any(item["role"] == "shm" and item["matches_main"] for item in rows),
    }


def _columns(table: Any) -> list[str]:
    if not isinstance(table, Mapping):
        raise MessengerProfileError("table report must be a mapping")
    value = table.get("columns", [])
    if not isinstance(value, list) or len(value) > MAX_COLUMNS:
        raise MessengerProfileError("table column metadata is invalid or oversized")
    if not all(isinstance(item, str) and len(item) <= MAX_NAME for item in value):
        raise MessengerProfileError("table column names must be text")
    return value


def _candidate(kind: str, family: str, platform: str, variant: str, score: int,
               evidence: list[str]) -> dict[str, Any]:
    return {
        "kind": kind,
        "family": family,
        "platform": platform,
        "variant": variant,
        "score": min(score, 100),
        "evidence": evidence,
    }


def classify_schema(tables: Mapping[str, Any]) -> dict[str, Any]:
    """Classify supplied table metadata without inspecting any row value.

    ``tables`` is the mapping returned under ``parse_sqlite(...)["tables"]``.
    The result carries every matching candidate, so a caller can audit precisely
    why the top family was selected.
    """
    try:
        if not isinstance(tables, Mapping):
            raise MessengerProfileError("tables must be a mapping")
        if len(tables) > MAX_TABLES:
            raise MessengerProfileError("table count exceeds cap")
        by_lower: dict[str, tuple[str, set[str]]] = {}
        schema_columns = 0
        for name, table in tables.items():
            if not isinstance(name, str) or not name or len(name) > MAX_NAME:
                raise MessengerProfileError("table names must be non-empty text")
            lowered = name.lower()
            if lowered in by_lower:
                raise MessengerProfileError("case-colliding table names are ambiguous")
            columns = _columns(table)
            schema_columns += len(columns)
            if schema_columns > MAX_SCHEMA_COLUMNS:
                raise MessengerProfileError("aggregate schema column count exceeds cap")
            by_lower[lowered] = (name, {column.lower() for column in columns})
        names = set(by_lower)
        candidates: list[dict[str, Any]] = []

        # Current Signal Android.  Requiring thread+recipient prevents its shared
        # `message` name from being mistaken for modern WhatsApp.
        signal_current = {"message", "thread", "recipient"}
        if signal_current <= names:
            evidence = [f"table:{name}" for name in sorted(signal_current)]
            score = 88
            if "attachment" in names:
                score += 8
                evidence.append("table:attachment")
            for support in ("reaction", "mention", "story_send", "story_sends", "session", "sessions"):
                if support in names:
                    score += 1
                    evidence.append(f"table:{support}")
            candidates.append(_candidate("signal-android", "signal", "android", "current", score, evidence))

        # Older Signal Android generations stored SMS and MMS in separate tables.
        if {"sms", "mms", "thread"} <= names:
            evidence = ["table:mms", "table:sms", "table:thread"]
            score = 90 + (4 if "recipient" in names else 0) + (3 if "attachment" in names else 0)
            if "recipient" in names:
                evidence.append("table:recipient")
            if "attachment" in names:
                evidence.append("table:attachment")
            candidates.append(_candidate("signal-android", "signal", "android", "legacy-sms-mms", score, evidence))

        # Signal iOS GRDB/SQLCipher schema.  These model_ names are much stronger
        # than generic Core Data support tables.
        if {"model_tsinteraction", "model_tsthread"} <= names:
            evidence = ["table:model_TSInteraction", "table:model_TSThread"]
            score = 92
            for support in ("model_signalrecipient", "grdb_migrations", "attachment",
                            "messageattachmentreference", "callrecord", "editrecord"):
                if support in names:
                    score += 2
                    evidence.append(f"table:{support}")
            candidates.append(_candidate("signal-ios", "signal", "ios", "grdb", score, evidence))

        # Modern WhatsApp Android requires all three relational anchors; `message`
        # on its own is intentionally not evidence because Signal also uses it.
        if {"message", "chat", "jid"} <= names:
            evidence = ["table:chat", "table:jid", "table:message"]
            score = 90
            for support in ("message_media", "message_location", "message_add_on", "jid_map",
                            "group_participant_user", "call_log"):
                if support in names:
                    score += 2
                    evidence.append(f"table:{support}")
            candidates.append(_candidate("whatsapp-android", "whatsapp", "android", "modern", score, evidence))

        # Legacy WhatsApp can be recognized by its message key columns even when
        # chat_list was omitted from a challenge fixture.
        legacy_columns = by_lower.get("messages", ("", set()))[1]
        legacy_keys = {"key_remote_jid", "key_from_me"}
        if "messages" in names and ("chat_list" in names or legacy_keys <= legacy_columns):
            evidence = ["table:messages"]
            score = 78
            if "chat_list" in names:
                score += 7
                evidence.append("table:chat_list")
            for column in sorted(legacy_keys & legacy_columns):
                score += 4
                evidence.append(f"messages.column:{column}")
            candidates.append(_candidate("whatsapp-android", "whatsapp", "android", "legacy", score, evidence))

        # wa.db can be supplied independently from msgstore.db.
        if "wa_contacts" in names:
            evidence = ["table:wa_contacts"]
            score = 70 + (5 if "wa_group_admin_settings" in names else 0)
            if "wa_group_admin_settings" in names:
                evidence.append("table:wa_group_admin_settings")
            candidates.append(_candidate("whatsapp-android-contacts", "whatsapp", "android",
                                         "contacts", score, evidence))

        # WhatsApp iOS uses Core Data-style ZWA tables.  Z_METADATA by itself is
        # never enough because every Core Data app may have it.
        if {"zwamessage", "zwachatsession"} <= names:
            evidence = ["table:ZWACHATSESSION", "table:ZWAMESSAGE"]
            score = 92
            for support in ("zwamediaitem", "zwamessageinfo", "zwagroupmember",
                            "zwaprofilepushname", "z_metadata", "z_primarykey"):
                if support in names:
                    score += 1
                    evidence.append(f"table:{support}")
            candidates.append(_candidate("whatsapp-ios", "whatsapp", "ios", "chatstorage", score, evidence))
        elif "zwaaddressbookcontact" in names:
            candidates.append(_candidate("whatsapp-ios-contacts", "whatsapp", "ios",
                                         "contactsv2", 70, ["table:ZWAADDRESSBOOKCONTACT"]))

        candidates.sort(key=lambda item: (-item["score"], item["kind"], item["variant"]))
        if not candidates:
            return {"kind": "unknown", "family": "unknown", "platform": "unknown",
                    "variant": None, "confidence": "none", "score": 0,
                    "evidence": [], "candidates": []}
        top = candidates[0]
        tied = [item for item in candidates if item["score"] == top["score"]]
        # A merged/challenge-crafted DB can intentionally contain two complete
        # schemas.  Do not let a small support-table score difference turn that
        # into a false single-app claim.
        strong_conflicts = [item for item in candidates[1:]
                            if item["score"] >= 85
                            and (item["family"], item["platform"])
                            != (top["family"], top["platform"])]
        if len({item["kind"] for item in tied}) > 1 or strong_conflicts:
            return {"kind": "ambiguous", "family": "unknown", "platform": "unknown",
                    "variant": None, "confidence": "none", "score": top["score"],
                    "evidence": [], "candidates": candidates}
        confidence = "high" if top["score"] >= 85 else "medium" if top["score"] >= 65 else "low"
        return {**top, "confidence": confidence, "candidates": candidates}
    except MessengerProfileError:
        raise
    except Exception as exc:
        raise MessengerProfileError("could not classify messenger schema") from exc


def _schema_summary(report: Mapping[str, Any]) -> tuple[list[dict[str, Any]], Mapping[str, Any]]:
    try:
        tables = report.get("tables")
        if not isinstance(tables, Mapping) or len(tables) > MAX_TABLES:
            raise MessengerProfileError("SQLite table report is invalid or oversized")
        summary = []
        schema_columns = 0
        for name in sorted(tables, key=lambda value: value.lower() if isinstance(value, str) else ""):
            if not isinstance(name, str):
                raise MessengerProfileError("SQLite table name is not text")
            table = tables[name]
            columns = _columns(table)
            schema_columns += len(columns)
            if schema_columns > MAX_SCHEMA_COLUMNS:
                raise MessengerProfileError("aggregate schema column count exceeds cap")
            rows = table.get("rows", [])
            if not isinstance(rows, list):
                raise MessengerProfileError("SQLite row metadata is invalid")
            root_page = table.get("root_page")
            summary.append({"name": name, "columns": columns, "column_count": len(columns),
                            "row_count": len(rows), "root_page": root_page})
        return summary, tables
    except MessengerProfileError:
        raise
    except Exception as exc:
        raise MessengerProfileError("could not summarize SQLite schema") from exc


def _filename_hint(filename: str) -> dict[str, Any] | None:
    leaf = Path(filename).name.lower()
    if leaf == "signal.db":
        return {"kind": "signal-android-candidate", "family": "signal", "platform": "android",
                "confidence": "low", "evidence": ["filename:signal.db"]}
    if leaf == "signal.sqlite":
        return {"kind": "signal-ios-candidate", "family": "signal", "platform": "ios",
                "confidence": "low", "evidence": ["filename:signal.sqlite"]}
    if leaf in {"msgstore.db", "wa.db"}:
        return {"kind": "whatsapp-android-candidate", "family": "whatsapp", "platform": "android",
                "confidence": "low", "evidence": [f"filename:{leaf}"]}
    if leaf in {"chatstorage.sqlite", "contactsv2.sqlite"}:
        return {"kind": "whatsapp-ios-candidate", "family": "whatsapp", "platform": "ios",
                "confidence": "low", "evidence": [f"filename:{leaf}"]}
    return None


def profile_artifact(data: bytes | bytearray | memoryview, *,
                     filename: str | os.PathLike[str] | None = None,
                     companions: Iterable[str | os.PathLike[str]] | None = None) -> dict[str, Any]:
    """Return a bounded table-only profile or an explicit encrypted/opaque decline."""
    raw = _artifact_bytes(data)
    name = _display_name(filename)
    sidecars = _companion_report(name, companions)
    digest = hashlib.sha256(raw).hexdigest()
    leaf = Path(name).name
    crypt = _CRYPT_SUFFIX.search(leaf)
    common: dict[str, Any] = {
        "filename": name,
        "size": len(raw),
        "sha256": digest,
        "sidecars": sidecars,
        "decryption_attempted": False,
        "message_values_reported": False,
    }
    if crypt:
        return {
            **common,
            "status": "encrypted-backup",
            "classification": {
                "kind": "whatsapp-android-backup", "family": "whatsapp", "platform": "android",
                "variant": f"crypt{crypt.group(1)}", "confidence": "high",
                "evidence": [f"suffix:.crypt{crypt.group(1)}"],
            },
            "tables": [],
            "requires": "matching WhatsApp backup key/password/passkey and a separate approved decryptor",
            "reason": "encrypted WhatsApp backup; this profiler never decrypts or guesses keys",
        }
    if not raw.startswith(SQLITE_MAGIC):
        return {
            **common,
            "status": "opaque",
            "classification": _filename_hint(name) or {
                "kind": "opaque-database-candidate", "family": "unknown", "platform": "unknown",
                "confidence": "none", "evidence": [],
            },
            "tables": [],
            "requires": "caller-supplied plaintext database or matching key plus an approved decryptor",
            "reason": "no plaintext SQLite header; artifact may be SQLCipher, encrypted, compressed, or unrelated",
        }

    try:
        parsed = mobile_artifacts.parse_sqlite(raw)
    except Exception:
        # Signal iOS may intentionally retain a plaintext SQLCipher header, so a
        # header followed by an unreadable schema cannot safely be called corrupt.
        return {
            **common,
            "status": "opaque-or-malformed",
            "classification": _filename_hint(name) or {
                "kind": "opaque-sqlite-header-candidate", "family": "unknown",
                "platform": "unknown", "confidence": "none", "evidence": ["header:SQLite format 3"],
            },
            "tables": [],
            "requires": "validated plaintext database, or a matching key and approved decryptor",
            "reason": "SQLite header is present but bounded schema parsing failed; encrypted and corrupt are indistinguishable",
        }

    tables, raw_tables = _schema_summary(parsed)
    classification = classify_schema(raw_tables)
    return {
        **common,
        "status": "plaintext-sqlite",
        "classification": classification,
        "sqlite": {
            "page_size": parsed.get("page_size"),
            "page_count": parsed.get("page_count"),
            "encoding": parsed.get("encoding"),
        },
        "tables": tables,
    }


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
    except Exception as exc:
        raise MessengerProfileError(f"could not read artifact: {path}") from exc
    if len(data) > MAX_INPUT:
        raise MessengerProfileError("artifact exceeds 128 MiB cap")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="supplied database or encrypted backup artifact")
    parser.add_argument("--companion", action="append", default=[], metavar="PATH",
                        help="name of a supplied WAL/SHM companion (repeatable; presence only)")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        report = profile_artifact(_read_bounded(args.artifact), filename=str(args.artifact),
                                  companions=args.companion)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except MessengerProfileError as exc:
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 2
    except Exception:
        # The CLI is a fail-closed boundary too; unexpected library failures are
        # never allowed to expose a stdlib traceback for hostile input.
        print(f"{parser.prog}: analysis failed safely", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
