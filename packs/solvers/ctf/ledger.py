"""The event ledger: one append-only JSONL under the workdir. B-101 builds the replay on it; B-033
records spend and extend decisions in it.

    from ctf import ledger
    ledger.append("candidate", challenge_id="12", engine="warmups.crib_decode")
    for rec in ledger.read(): ...

Each line: {"ts": <epoch float>, "event": <event_type>, ...fields}. Lines are written with one
os.write on an O_APPEND descriptor under an exclusive flock, so concurrent solvers never interleave.

Event types are lower_snake words (dots allowed for namespacing, e.g. "web.request"). The stage
vocabulary B-101 times is: detect, claim, first_tool, candidate, submit, accepted, rejected,
spend, budget_extend, stop. New types need no registration.

Never put a secret in a field: keys that name one (token, cookie, authorization, password, secret,
api_key) are refused, so a token COUNT is the field "tok" (in_tok, out_tok), and a flag value belongs in a field only when the event allows it to be
written to local disk (it always is, in the workdir; writeups redact separately).
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Iterator

from . import paths

LEDGER_NAME = "ledger.jsonl"
_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
_SECRET_KEYS = re.compile(r"(token|cookie|authorization|password|passwd|secret|api_?key)", re.I)
_RESERVED = {"ts", "event"}
# A token COUNT is a number, not a secret, but the key rule cannot tell them apart, so counts are
# spelled "tok" (docs/CONTRACTS.md section 10): one spelling, no allow-list.
COUNT_KEY_HINT = "a token count is spelled 'tok' (tok, in_tok, out_tok)"


def path(workdir: Path | None = None) -> Path:
    return (paths.workdir() if workdir is None else Path(workdir)) / LEDGER_NAME


def append(event_type: str, *, workdir: Path | None = None, **fields: Any) -> dict:
    if not _TYPE_RE.match(event_type or ""):
        raise ValueError(f"bad ledger event type {event_type!r} (lower_snake, dots for namespaces)")
    bad = sorted(k for k in fields if _SECRET_KEYS.search(k))
    if bad:
        hint = (f"; {COUNT_KEY_HINT}" if any("token" in k.lower() for k in bad) else "")
        raise ValueError(f"ledger fields may not carry secrets: {', '.join(bad)}{hint}")
    clash = _RESERVED & set(fields)
    if clash:
        raise ValueError(f"ledger fields may not use reserved key(s): {', '.join(sorted(clash))}")
    rec = {"ts": time.time(), "event": event_type, **fields}
    line = (json.dumps(rec, default=str, separators=(",", ":")) + "\n").encode("utf-8")
    p = path(workdir)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, line)
    finally:
        os.close(fd)
    return rec


def read(workdir: Path | None = None) -> Iterator[dict]:
    p = path(workdir)
    if not p.exists():
        return
    with open(p, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as e:
                    raise ValueError(f"{p}:{n}: corrupt ledger line: {e}") from None
