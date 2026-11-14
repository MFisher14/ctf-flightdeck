#!/usr/bin/env python3
"""Offline NACHA ACH common-origination reader and control checker.

Supports PPD/CCD/WEB/TEL, checking/savings monetary, prenote and zero-dollar
entries, and type-05 addenda. IAT, CTX, returns and NOCs need other layouts and
are deliberately rejected. Amounts are integer US cents. Controls detect
corruption, not authenticity; the optional batch MAC is extracted, not verified.

Reference: https://achdevguide.nacha.org/ach-file-details
CLI: ./.venv/bin/python solvers/toolkits/fin2_ach.py FILE [--allow-unpadded]
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
_CREDIT = {"22", "23", "24", "32", "33", "34"}
_DEBIT = {"27", "28", "29", "37", "38", "39"}
_ZERO = {"23", "24", "28", "29", "33", "34", "38", "39"}


class ACHError(ValueError):
    """Malformed, unsupported, or resource-limited ACH input."""


def _number(value, label):
    if not re.fullmatch(r"[0-9]{1,12}", value):
        raise ACHError(f"invalid numeric field: {label}")
    return int(value)


def _date(value, label, optional=False):
    if optional and value == " " * 6:
        return
    if not re.fullmatch(r"[0-9]{6}", value):
        raise ACHError(f"invalid date: {label}")
    try:
        datetime.date(2000 + int(value[:2]), int(value[2:4]), int(value[4:]))
    except ValueError as exc:
        raise ACHError(f"invalid calendar date: {label}") from exc


def _routing_ok(value):
    return (bool(re.fullmatch(r"[0-9]{9}", value)) and value != "000000000"
            and sum(int(d) * w for d, w in zip(value, (3, 7, 1) * 3)) % 10 == 0)


def _records(data):
    if not isinstance(data, (str, bytes)) or not data or len(data) > MAX_BYTES:
        raise ACHError("expected nonempty ASCII bytes/text up to 16 MiB")
    if isinstance(data, bytes):
        try:
            data = data.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ACHError("ACH must be ASCII") from exc
    if any(ord(c) > 126 or (ord(c) < 32 and c not in "\r\n") for c in data):
        raise ACHError("nonprintable or non-ASCII input")
    if "\r" in data.replace("\r\n", ""):
        raise ACHError("bare carriage return")
    if "\n" in data:
        rows = data.replace("\r\n", "\n").split("\n")
        if rows[-1] == "":
            rows.pop()
    else:
        if len(data) % 94:
            raise ACHError("packed ACH length is not a multiple of 94")
        rows = [data[i:i + 94] for i in range(0, len(data), 94)]
    if not rows or len(rows) > MAX_RECORDS or any(len(r) != 94 for r in rows):
        raise ACHError("every record must be 94 bytes; at most 100000 records")
    return rows


def parse_ach(data, *, require_padding=True):
    """Return extracted fields, control checks, and flags; or raise ACHError.

    ``valid`` means this supported layout and its numerical controls passed,
    not that payment authorization, account ownership or MAC was verified.
    Unpadded bank exports are accepted only with require_padding=False.
    """
    if type(require_padding) is not bool:
        raise ACHError("require_padding must be boolean")
    rows = _records(data)
    first = rows[0]
    if first[:3] != "101" or first[34:40] != "094101":
        raise ACHError("invalid file header/record size/blocking factor/format")
    if not re.fullmatch(r" [0-9]{9}", first[3:13]):
        raise ACHError("immediate destination must be blank plus nine digits")
    if not first[13:23].strip():
        raise ACHError("missing immediate origin")
    if not re.fullmatch(r"[A-Z0-9]", first[33]):
        raise ACHError("invalid file ID modifier")
    _date(first[23:29], "creation date")
    if first[29:33] != " " * 4:
        t = first[29:33]
        if not re.fullmatch(r"[0-9]{4}", t) or int(t[:2]) > 23 or int(t[2:]) > 59:
            raise ACHError("invalid creation time")
    result = {"format": "NACHA", "profile": "PPD/CCD/WEB/TEL checking/savings origination",
              "header": {"destination": first[3:13].strip(), "origin": first[13:23].strip(),
                         "creation_date": first[23:29], "creation_time": first[29:33].strip(),
                         "file_id": first[33], "destination_name": first[40:63].rstrip(),
                         "origin_name": first[63:86].rstrip(), "reference": first[86:94].rstrip()},
              "batches": [], "issues": [], "record_count": len(rows),
              "authentication": "not verified"}
    issues = result["issues"]

    def check(label, actual, expected, line):
        if actual != expected:
            issues.append({"check": label, "record": line, "actual": actual, "expected": expected})

    check("destination routing checksum", _routing_ok(first[4:13]), True, 1)
    batch = None
    entry = None
    done = False
    pad = 0
    traces = set()
    totals = {"entry_addenda_count": 0, "entry_hash": 0, "debit_cents": 0, "credit_cents": 0}
    previous_batch_number = 0
    for line, row in enumerate(rows[1:], 2):
        typ = row[0]
        if done:
            if row != "9" * 94:
                raise ACHError(f"non-padding record after file control at {line}")
            pad += 1
            continue
        if typ == "5":
            if batch is not None:
                raise ACHError(f"nested batch at {line}")
            sec = row[50:53]
            if sec not in {"PPD", "CCD", "WEB", "TEL"}:
                raise ACHError(f"unsupported SEC {sec!r}; require its specific layout")
            if row[1:4] not in {"200", "220", "225"}:
                raise ACHError("unsupported service class")
            if not row[4:20].strip() or not row[40:50].strip():
                raise ACHError("missing company name/identification")
            _date(row[69:75], "effective date", optional=True)
            _number(row[79:87], "originating DFI")
            number = _number(row[87:94], "batch number")
            check("batch number ascending", number > previous_batch_number, True, line)
            previous_batch_number = number
            batch = {"record": line, "service_class": row[1:4], "company_name": row[4:20].rstrip(),
                     "discretionary_data": row[20:40].rstrip(), "company_id": row[40:50], "sec": sec,
                     "description": row[53:63].rstrip(), "effective_date": row[69:75],
                     "originating_dfi": row[79:87], "number": number, "entries": [],
                     "computed": dict.fromkeys(totals, 0)}
            entry = None
        elif typ == "6":
            if batch is None:
                raise ACHError(f"entry outside batch at {line}")
            if entry is not None:
                check("addenda indicator", len(entry["addenda"]), int(entry["addenda_indicator"]), entry["record"])
            code = row[1:3]
            if code not in _CREDIT | _DEBIT:
                raise ACHError(f"unsupported transaction code {code!r}")
            routing = row[3:12]
            _number(routing, "receiving routing")
            amount = _number(row[29:39], "amount")
            trace = row[79:94]
            if not re.fullmatch(r"[0-9]{15}", trace):
                raise ACHError("invalid trace number")
            if row[78] not in "01":
                raise ACHError("invalid addenda indicator")
            if not row[12:29].strip() or not row[54:76].strip():
                raise ACHError("missing receiving account/name")
            entry = {"record": line, "transaction_code": code, "direction": "credit" if code in _CREDIT else "debit",
                     "routing": routing, "account": row[12:29].rstrip(), "amount_cents": amount,
                     "identification": row[39:54].rstrip(), "name": row[54:76].rstrip(),
                     "discretionary_data": row[76:78].rstrip(), "trace": trace,
                     "addenda_indicator": row[78], "addenda": []}
            check("receiving routing checksum", _routing_ok(routing), True, line)
            check("trace DFI", trace[:8], batch["originating_dfi"], line)
            check("unique trace", trace not in traces, True, line)
            if batch["entries"]:
                check("ascending trace", trace > batch["entries"][-1]["trace"], True, line)
            traces.add(trace)
            if code in _ZERO:
                check("prenote/zero-dollar amount", amount, 0, line)
            if batch["service_class"] == "220":
                check("credit-only batch", entry["direction"], "credit", line)
            if batch["service_class"] == "225":
                check("debit-only batch", entry["direction"], "debit", line)
            if batch["sec"] == "TEL":
                check("TEL addenda forbidden", row[78], "0", line)
                check("TEL debit only", entry["direction"], "debit", line)
            batch["entries"].append(entry)
            c = batch["computed"]
            c["entry_addenda_count"] += 1
            c["entry_hash"] = (c["entry_hash"] + int(routing[:8])) % 10**10
            c[entry["direction"] + "_cents"] += amount
        elif typ == "7":
            if batch is None or entry is None:
                raise ACHError(f"orphan addenda at {line}")
            if row[1:3] != "05":
                raise ACHError("only type-05 addenda supported, not returns/NOCs")
            sequence = _number(row[83:87], "addenda sequence")
            detail = _number(row[87:94], "entry detail sequence")
            check("addenda sequence", sequence, 1, line)
            check("addenda trace link", detail, int(entry["trace"][-7:]), line)
            entry["addenda"].append({"record": line, "text": row[3:83].rstrip(), "sequence": sequence})
            batch["computed"]["entry_addenda_count"] += 1
        elif typ == "8":
            if batch is None or not batch["entries"]:
                raise ACHError(f"empty/orphan batch control at {line}")
            check("addenda indicator", len(entry["addenda"]), int(entry["addenda_indicator"]), entry["record"])
            control = {"entry_addenda_count": _number(row[4:10], "entry/addenda count"),
                       "entry_hash": _number(row[10:20], "entry hash"),
                       "debit_cents": _number(row[20:32], "debit total"),
                       "credit_cents": _number(row[32:44], "credit total")}
            check("service class agreement", row[1:4], batch["service_class"], line)
            check("company ID agreement", row[44:54], batch["company_id"], line)
            check("originating DFI agreement", row[79:87], batch["originating_dfi"], line)
            check("batch number agreement", _number(row[87:94], "batch number"), batch["number"], line)
            if row[73:79] != " " * 6:
                raise ACHError("batch control reserved field must be blank")
            for key, value in control.items():
                check("batch " + key, value, batch["computed"][key], line)
                totals[key] += batch["computed"][key]
            totals["entry_hash"] %= 10**10
            batch["control"] = control
            batch["mac"] = row[54:73].rstrip()
            result["batches"].append(batch)
            batch = entry = None
        elif typ == "9" and row != "9" * 94:
            if batch is not None or not result["batches"]:
                raise ACHError(f"premature file control at {line}")
            if row[55:] != " " * 39:
                raise ACHError("file control reserved field must be blank")
            control = {"entry_addenda_count": _number(row[13:21], "file entry count"),
                       "entry_hash": _number(row[21:31], "file entry hash"),
                       "debit_cents": _number(row[31:43], "file debit"),
                       "credit_cents": _number(row[43:55], "file credit")}
            for key, value in control.items():
                check("file " + key, value, totals[key], line)
            check("file batch count", _number(row[1:7], "batch count"), len(result["batches"]), line)
            check("file block count", _number(row[7:13], "block count"), (len(rows) + 9) // 10, line)
            result["control"] = control
            done = True
        else:
            raise ACHError(f"unexpected record type {typ!r} at {line}")
    if not done:
        raise ACHError("missing file control")
    if require_padding:
        check("ten-record blocking", len(rows) % 10, 0, len(rows))
    result["padding_records"] = pad
    result["computed"] = totals
    packed = "\n".join(rows).encode("latin-1", "replace")     # fixed width: no word boundary before a flag
    result["flags"] = list(dict.fromkeys(m.decode("latin-1") for m in flagfmt.BYTES.findall(packed)))
    result["valid"] = not issues
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file")
    parser.add_argument("--allow-unpadded", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (TypeError, ValueError):
        return 2
    try:
        with Path(args.file).open("rb") as stream:
            report = parse_ach(stream.read(MAX_BYTES + 1), require_padding=not args.allow_unpadded)
        print(json.dumps(report, indent=2))
        return 0 if report["valid"] else 1
    except (ACHError, OSError, ValueError) as exc:
        print(f"fin2_ach: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
