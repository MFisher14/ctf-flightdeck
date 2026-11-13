#!/usr/bin/env python3
"""Offline USMTF/ADatP-3 slash-set syntax inspection, not a message catalog.

Accept one MSGID-bearing message, optionally prefixed by an ACP-style envelope.
Preserve repeated sets, slash fields, placeholders and raw line folding. This
does not validate a particular MIL-STD-6040 edition's mandatory fields, routing,
classification, origin or authenticity. Binary VMF is a different format.

Reference: USMC MCIP 3-03Di Appendix B published GENADMIN template.
CLI: defense_usmtf.py message.txt
Public parsers raise only DefenseUSMTFError for malformed/unsupported input.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_BYTES = 2 * 1024 * 1024
MAX_SETS = 8192
MAX_FIELDS = 4096


class DefenseUSMTFError(ValueError):
    """Malformed, ambiguous, oversized or unsupported military message text."""


def parse_usmtf(value: bytes | str) -> dict:
    """Return syntax and exact evidence; repeated sets remain an ordered list.

    A literal // terminates a set even within narrative; no ad-hoc escaping is
    invented. Real informal messages violating that rule are rejected. Field
    text is whitespace-normalized for reading; raw set text is also returned.
    """
    if type(value) not in (bytes, str) or len(value) > MAX_BYTES:
        raise DefenseUSMTFError("expected bounded UTF-8 bytes or text")
    try:
        text = value.decode("utf-8") if type(value) is bytes else value
        if len(text.encode("utf-8")) > MAX_BYTES:
            raise DefenseUSMTFError("message exceeds byte limit")
    except UnicodeError as exc:
        raise DefenseUSMTFError("invalid UTF-8 text") from exc
    if any(ord(c) < 32 and c not in "\t\r\n" or ord(c) == 127 for c in text):
        raise DefenseUSMTFError("control character in message")
    start = re.search(r"(?m)^[ \t]*(?:EXER|OPER|MSGID)/", text)
    if start is None:
        raise DefenseUSMTFError("no initial MSGID/EXER/OPER set")
    prefix = text[:start.start()]
    # Avoid silently discarding a partial or malformed MSGID in the envelope.
    if "MSGID/" in prefix:
        raise DefenseUSMTFError("ambiguous message start")
    body = text[start.start():]
    if body.count("//") > MAX_SETS:
        raise DefenseUSMTFError("too many sets")
    chunks = body.split("//")
    tail = chunks.pop().strip()
    if tail and any(line.strip() not in ("BT", "NNNN")
                    for line in tail.splitlines() if line.strip()):
        raise DefenseUSMTFError("unterminated set or unsupported trailer")
    sets = []
    for chunk in chunks:
        raw = chunk.strip()
        match = re.match(r"([A-Z][A-Z0-9-]{0,31})/", raw)
        if match is None:
            raise DefenseUSMTFError("invalid set identifier or empty set")
        name = match.group(1)
        raw_fields = raw[match.end():].split("/")
        if len(raw_fields) > MAX_FIELDS:
            raise DefenseUSMTFError("too many fields")
        fields = [" ".join(field.split()) for field in raw_fields]
        record = {"name": name, "fields": fields, "raw": raw}
        if name == "GENTEXT":
            if len(fields) < 2 or not fields[0]:
                raise DefenseUSMTFError("GENTEXT requires label and narrative")
            record["label"] = fields[0]
            record["text"] = "/".join(fields[1:])
        sets.append(record)
    ids = [i for i, record in enumerate(sets) if record["name"] == "MSGID"]
    if len(ids) != 1:
        raise DefenseUSMTFError("exactly one MSGID required")
    i = ids[0]
    if any(record["name"] not in ("EXER", "OPER") for record in sets[:i]):
        raise DefenseUSMTFError("unsupported set before MSGID")
    if not sets[i]["fields"][0]:
        raise DefenseUSMTFError("MSGID requires a message type")
    return {"format": "USMTF slash-set syntax", "envelope": prefix,
            "message_type": sets[i]["fields"][0], "sets": sets,
            "trailer": tail,
            "flags": list(dict.fromkeys(flagfmt.TEXT.findall(text))),
            "scope": "syntax only; no catalog or authenticity validation"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="UTF-8 message text, one message")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with Path(args.file).open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        print(json.dumps(parse_usmtf(raw), indent=2))
        return 0
    except (DefenseUSMTFError, OSError, ValueError) as exc:
        print(f"defense_usmtf: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
