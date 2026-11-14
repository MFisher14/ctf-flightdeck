#!/usr/bin/env python3
"""Offline BAI2 statement reader with continuation and control-total validation.

Reads line-delimited 01/02/03/16/88/49/98/99 records. Supports funds types
blank/Z/0/1/2/S/V/D. Principal amounts are raw integer currency units (no
guessed decimal places); funds-distribution amounts are not counted twice.
Integrity checks are not authentication or proof of fraud.

Sources: bankrec.support.qvalent.com/docs/statements/bai2/ and
docs.oracle.com/en/cloud/saas/netsuite/ns-online-help/article_0706020435.html
CLI: ./.venv/bin/python solvers/toolkits/fin2_bai2.py FILE
"""
import argparse
import datetime
import json
from pathlib import Path
import re
import sys

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100000


class BAI2Error(ValueError):
    """Malformed, unsupported, or resource-limited BAI2 input."""


def _num(value, label, signed=False, optional=False):
    if optional and value == "":
        return None
    pattern = r"[+-]?[0-9]{1,20}" if signed else r"[+]?[0-9]{1,20}"
    if not re.fullmatch(pattern, value):
        raise BAI2Error(f"invalid {label}")
    return int(value)


def _get(fields, pos):
    if pos >= len(fields):
        raise BAI2Error("truncated record or funds distribution")
    return fields[pos]


def _date(value, optional=False):
    if optional and not value:
        return
    if not re.fullmatch(r"[0-9]{6}", value):
        raise BAI2Error("date must have YYMMDD format")
    try:
        datetime.date(2000 + int(value[:2]), int(value[2:4]), int(value[4:6]))
    except ValueError as exc:
        raise BAI2Error("invalid calendar date") from exc


def _time(value):
    if value in {"", "2400", "9999"}:
        return
    if not re.fullmatch(r"[0-9]{4}", value) or int(value[:2]) > 23 or int(value[2:]) > 59:
        raise BAI2Error("invalid time")


def _funds(fields, pos):
    code = _get(fields, pos)
    pos += 1
    result = {"type": code}
    if code in {"", "Z", "0", "1", "2"}:
        return result, pos
    if code == "S":
        result["availability"] = [_num(_get(fields, pos + i), "availability amount", True, True) for i in range(3)]
        return result, pos + 3
    if code == "V":
        value_date, value_time = _get(fields, pos), _get(fields, pos + 1)
        _date(value_date)
        _time(value_time)
        result.update(value_date=value_date, value_time=value_time)
        return result, pos + 2
    if code == "D":
        count = _num(_get(fields, pos), "distribution count")
        pos += 1
        if count > 1000:
            raise BAI2Error("too many availability distributions")
        result["distributions"] = []
        for _ in range(count):
            days = _num(_get(fields, pos), "availability days")
            amount = _num(_get(fields, pos + 1), "availability amount", True)
            result["distributions"].append({"days": days, "amount": amount})
            pos += 2
        return result, pos
    raise BAI2Error(f"unsupported funds type {code!r}")


def _logical_records(data):
    if not isinstance(data, (str, bytes)) or not data or len(data) > MAX_BYTES:
        raise BAI2Error("expected nonempty ASCII bytes/text up to 16 MiB")
    if isinstance(data, bytes):
        try:
            data = data.decode("ascii")
        except UnicodeDecodeError as exc:
            raise BAI2Error("BAI2 must be ASCII") from exc
    if any(ord(c) > 126 or (ord(c) < 32 and c not in "\r\n") for c in data):
        raise BAI2Error("nonprintable or non-ASCII input")
    if "\r" in data.replace("\r\n", ""):
        raise BAI2Error("bare carriage return")
    lines = data.replace("\r\n", "\n").split("\n")
    if lines[-1] == "":
        lines.pop()
    if len(lines) > MAX_RECORDS:
        raise BAI2Error("too many physical records")
    records = []
    for number, line in enumerate(lines, 1):
        if len(line) > 65536 or not re.match(r"[0-9]{2},", line):
            raise BAI2Error(f"invalid physical record at line {number}")
        code = line[:2]
        terminated = line.endswith("/")
        value = line[:-1] if terminated else line
        if code == "88":
            if not records or records[-1]["type"] not in {"03", "16"}:
                raise BAI2Error(f"orphan continuation at line {number}")
            records[-1]["parts"].append(value[3:])
            records[-1]["raw_lines"].append(line)
            records[-1]["physical_records"] += 1
            if records[-1]["type"] == "03" and not terminated:
                raise BAI2Error("summary continuation requires slash terminator")
        elif code in {"01", "02", "03", "16", "49", "98", "99"}:
            if code != "16" and not terminated:
                raise BAI2Error(f"missing slash terminator at line {number}")
            records.append({"type": code, "record": number, "physical_records": 1,
                            "parts": [value], "raw_lines": [line]})
        else:
            raise BAI2Error(f"unsupported record type {code!r}")
    return records, lines


def _join_parts(record):
    value = record["parts"][0]
    if record["type"] == "03":
        pieces = [value]
        for before, part in zip(record["parts"], record["parts"][1:]):
            pieces.append(("" if before.endswith(",") else ",") + part)
        return "".join(pieces)
    text_parts = []
    in_text = False
    for part in record["parts"][1:]:
        if in_text:
            text_parts.append(part)
            continue
        fields = value.split(",")
        # Once the six fixed fields (+ optional funds fields) are complete,
        # continuations are text, including commas/slashes, not more CSV fields.
        try:
            _, end = _funds(fields, 3)
            header_end = end + 2
        except BAI2Error:
            header_end = None
        if header_end is not None and len(fields) > header_end:
            in_text = True
            text_parts.append(part)
        elif header_end is not None and len(fields) == header_end:
            in_text = True
            text_parts.append("," + part)
        else:
            value += ("" if value.endswith(",") else ",") + part
            if len(value) > 65536:
                raise BAI2Error("transaction header exceeds 64 KiB")
    return value + "".join(text_parts)


def _summary(record):
    fields = _join_parts(record).split(",")
    if len(fields) < 3 or not fields[1] or "/" in ",".join(fields):
        raise BAI2Error("invalid account summary")
    currency = fields[2]
    if currency and not re.fullmatch(r"[A-Z]{3}", currency):
        raise BAI2Error("invalid account currency")
    result = {"record": record["record"], "account": fields[1], "currency": currency,
              "summaries": [], "transactions": []}
    pos = 3
    while pos < len(fields):
        if len(fields) - pos == 1 and fields[pos] == "":
            break
        code = _get(fields, pos)
        if not re.fullmatch(r"[0-9]{3}", code):
            raise BAI2Error("invalid summary type code")
        amount = _num(_get(fields, pos + 1), "summary amount", int(code) < 100, True)
        items = _num(_get(fields, pos + 2), "item count", optional=True)
        funds, end = _funds(fields, pos + 3)
        result["summaries"].append({"type_code": code, "amount": amount, "item_count": items, "funds": funds})
        pos = end
    return result


def _transaction(record):
    fields = _join_parts(record).split(",")
    code = _get(fields, 1)
    if not re.fullmatch(r"[0-9]{3}", code):
        raise BAI2Error("invalid transaction type code")
    amount = _num(_get(fields, 2), "transaction amount", optional=True)
    funds, pos = _funds(fields, 3)
    bank_ref, customer_ref = _get(fields, pos), _get(fields, pos + 1)
    if "/" in bank_ref + customer_ref:
        raise BAI2Error("slash in reference")
    return {"record": record["record"], "type_code": code, "amount": amount, "funds": funds,
            "bank_reference": bank_ref, "customer_reference": customer_ref,
            "text": ",".join(fields[pos + 2:]), "raw_parts": record["parts"],
            "raw_lines": record["raw_lines"]}


def parse_bai2(data):
    """Return hierarchy, principal totals, integrity issues and flags; raise BAI2Error on malformed input."""
    records, lines = _logical_records(data)
    if not records or records[0]["type"] != "01":
        raise BAI2Error("missing file header")
    first = records[0]["parts"][0].split(",")
    if len(first) != 9 or first[8] != "2" or not first[1] or not first[2] or "/" in ",".join(first):
        raise BAI2Error("invalid BAI2 file header")
    _date(first[3])
    _time(first[4])
    if not first[5]:
        raise BAI2Error("missing file ID")
    for value in first[6:8]:
        _num(value, "physical/block length", optional=True)
    result = {"format": "BAI2", "header": {"sender": first[1], "receiver": first[2],
              "date": first[3], "time": first[4], "file_id": first[5]},
              "groups": [], "issues": [], "record_count": len(lines), "authentication": "not verified"}
    group = account = None
    done = False
    total = 0

    def check(label, actual, expected, line):
        if actual != expected:
            result["issues"].append({"check": label, "record": line, "actual": actual, "expected": expected})

    for record in records[1:]:
        code, line = record["type"], record["record"]
        if done:
            raise BAI2Error("data after file trailer")
        if code not in {"03", "16"}:
            f = record["parts"][0].split(",")
            if any("/" in value for value in f):
                raise BAI2Error("slash outside text")
        if code == "02":
            if group is not None or len(f) != 8 or not f[2] or f[3] not in {"1", "2", "3", "4"}:
                raise BAI2Error("invalid/nested group header")
            _date(f[4])
            _time(f[5])
            if f[6] and not re.fullmatch(r"[A-Z]{3}", f[6]):
                raise BAI2Error("invalid group currency")
            group = {"record": line, "receiver": f[1], "originator": f[2], "status": f[3],
                     "date": f[4], "time": f[5], "currency": f[6], "date_modifier": f[7],
                     "accounts": [], "computed_total": 0}
        elif code == "03":
            if group is None or account is not None:
                raise BAI2Error("orphan/nested account")
            account = _summary(record)
            account["currency"] = account["currency"] or group["currency"] or "USD"
        elif code == "16":
            if account is None:
                raise BAI2Error("transaction outside account")
            account["transactions"].append(_transaction(record))
        elif code == "49":
            if account is None or len(f) != 3:
                raise BAI2Error("invalid/orphan account trailer")
            computed = sum(item["amount"] or 0 for item in account["summaries"] + account["transactions"])
            stated = _num(f[1], "account control", True)
            count = _num(f[2], "account record count")
            check("account total", stated, computed, line)
            check("account record count", count, line - account["record"] + 1, line)
            account.update(control_total=stated, computed_total=computed, record_count=count)
            group["accounts"].append(account)
            group["computed_total"] += computed
            account = None
        elif code == "98":
            if group is None or account is not None or not group["accounts"] or len(f) != 4:
                raise BAI2Error("invalid/premature group trailer")
            stated = _num(f[1], "group control", True)
            count = _num(f[2], "account count")
            record_count = _num(f[3], "group record count")
            check("group total", stated, group["computed_total"], line)
            check("group account count", count, len(group["accounts"]), line)
            check("group record count", record_count, line - group["record"] + 1, line)
            group.update(control_total=stated, record_count=record_count)
            total += group["computed_total"]
            result["groups"].append(group)
            group = None
        elif code == "99":
            if group is not None or not result["groups"] or len(f) != 4:
                raise BAI2Error("invalid/premature file trailer")
            stated = _num(f[1], "file control", True)
            count = _num(f[2], "group count")
            record_count = _num(f[3], "file record count")
            check("file total", stated, total, line)
            check("file group count", count, len(result["groups"]), line)
            check("file record count", record_count, len(lines), line)
            result.update(control_total=stated, computed_total=total)
            done = True
        else:
            raise BAI2Error(f"unexpected record type {code}")
    if not done:
        raise BAI2Error("missing file trailer")
    result["valid"] = not result["issues"]
    decoded_text = [t["text"] for g in result["groups"] for a in g["accounts"] for t in a["transactions"]]
    result["flags"] = list(dict.fromkeys(flagfmt.TEXT.findall("\n".join(lines + decoded_text))))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (TypeError, ValueError):
        return 2
    try:
        with Path(args.file).open("rb") as stream:
            report = parse_bai2(stream.read(MAX_BYTES + 1))
        print(json.dumps(report, indent=2))
        return 0 if report["valid"] else 1
    except (BAI2Error, OSError, ValueError) as exc:
        print(f"fin2_bai2: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
