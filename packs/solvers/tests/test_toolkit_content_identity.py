#!/usr/bin/env python3
"""Regression for artifact-local cache/dedup identities.

This exercises the real toolkit functions with a forced SHA-1 collision.  Before the migration the
second distinct Windows export, cloud record/file, PowerPoint storage and Web access log disappeared,
and RF reused the first AFSK cache entry: a wrong conflict collapse. The production paths now use SHA-256, so distinct bytes stay
distinct while an exact duplicate is still read once.  Protocol/answer SHA-1 behavior is outside these
paths and remains unchanged.

  PYTHONDONTWRITEBYTECODE=1 .venv/bin/python tests/test_toolkit_content_identity.py
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import sys
from contextlib import contextmanager
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
TOOLKITS = REPO / "solvers" / "toolkits"
FAILED = []


def check(label, condition, detail=""):
    print(("ok   " if condition else "FAIL ") + label
          + ("" if condition or not detail else "  [" + str(detail)[:900] + "]"))
    if not condition:
        FAILED.append(label)


def load(stem):
    name = "content_identity_" + stem
    spec = importlib.util.spec_from_file_location(name, TOOLKITS / f"{stem}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class _CollidingSha1:
    """A hashlib-compatible digest whose every input collides; test-only negative control."""

    def __init__(self, data=b""):
        self.data = bytes(data)

    def update(self, data):
        self.data += bytes(data)

    def digest(self):
        return b"\x5a" * 20

    def hexdigest(self):
        return "5a" * 20


@contextmanager
def forced_sha1_collision():
    original = hashlib.sha1
    hashlib.sha1 = _CollidingSha1
    try:
        yield
    finally:
        hashlib.sha1 = original


def windows_dedup(windows):
    head = b"Windows Registry Editor Version 5.00\r\n\r\n"
    one = head + b"[HKEY_CURRENT_USER\\Software\\One]\r\n\"v\"=\"one\"\r\n"
    two = head + b"[HKEY_CURRENT_USER\\Software\\Two]\r\n\"v\"=\"two\"\r\n"
    copy = bytes(bytearray(one))
    with forced_sha1_collision():
        rows = windows._unique({"one.reg": one, "two.reg": two, "copy.reg": copy})
    check("windows._unique keeps two SHA-1-colliding distinct registry exports and drops the exact copy",
          len(rows) == 2 and {body for _name, body in rows} == {one, two}, rows)


def _cloud_event(event_id, op, ip):
    return {
        "eventVersion": "1.08", "eventID": event_id, "eventTime": "2026-10-29T12:00:00Z",
        "eventSource": "iam.amazonaws.com", "eventName": op, "awsRegion": "us-east-1",
        "sourceIPAddress": ip,
        "userIdentity": {"type": "IAMUser", "userName": "analyst"},
    }


def cloud_dedup(cloudlogs):
    # Same event id but different normalized fields is not a repeat; an exact third row is.  A
    # second file with another event is also distinct.  The forced SHA-1 collision reaches both old
    # dedup sites (record identity and whole-file identity).
    first = _cloud_event("evt-same-id", "CreateUser", "192.0.2.10")
    changed = _cloud_event("evt-same-id", "DeleteUser", "192.0.2.11")
    other = _cloud_event("evt-other", "CreateAccessKey", "192.0.2.12")
    body_a = json.dumps({"Records": [first, changed, dict(first)]}, sort_keys=True).encode()
    body_b = json.dumps({"Records": [other]}, sort_keys=True).encode()
    with forced_sha1_collision():
        log = cloudlogs.load({"a.json": body_a, "b.json": body_b})
    check("cloudlogs keeps a same-id changed event, collapses only the exact repeat, and reads both files",
          len(log.events) == 3 and {e["op"] for e in log.events} == {"CreateUser", "DeleteUser", "CreateAccessKey"}
          and sum(f["repeats"] for f in log.files) == 1 and len(log.files) == 2,
          {"events": [(e["id"], e["op"]) for e in log.events], "files": log.files})


def maldoc_dedup(maldoc):
    def storage(fill):
        raw = maldoc.OLE_MAGIC + bytes([fill]) * 56
        return struct.pack("<HHI", 0, 0x1011, len(raw)) + raw, raw

    record_a, raw_a = storage(0x41)
    record_b, raw_b = storage(0x42)
    record_copy, _ = storage(0x41)
    with forced_sha1_collision():
        rows = maldoc.ppt_storages(record_a + record_b + record_copy)
    check("maldoc PowerPoint storage dedup keeps distinct colliding bodies and drops the exact body",
          rows == [raw_a, raw_b], [len(row) for row in rows])


def web_dedup(web):
    one = (b'192.0.2.1 - - [29/Oct/2026:12:00:00 +0000] "GET /one HTTP/1.1" 200 1\n')
    two = (b'192.0.2.2 - - [29/Oct/2026:12:00:01 +0000] "GET /two HTTP/1.1" 200 2\n')
    copy = bytes(bytearray(one))
    with forced_sha1_collision():
        view = web._View({"one.log": one, "two.log": two, "copy.log": copy})
        report = view.log()
    check("web delivery view keeps distinct colliding logs and drops the exact content duplicate",
          len(view.files) == 2 and report["files"] == 2
          and {row["path"] for row in report["rows"]} == {"/one", "/two"},
          {"files": [name for name, _ in view.files], "report": report})


def rf_cache(rf):
    calls = []
    original = rf.wav_samples
    rf._AFSK_SEEN.clear()
    rf.wav_samples = lambda data: (calls.append(bytes(data)) or (None, None))
    try:
        with forced_sha1_collision():
            rf.afsk_text(b"RIFF-distinct-one")
            rf.afsk_text(b"RIFF-distinct-two")
            rf.afsk_text(bytes(bytearray(b"RIFF-distinct-one")))
    finally:
        rf.wav_samples = original
        rf._AFSK_SEEN.clear()
    check("rf AFSK cache computes each distinct colliding body once and reuses only exact content",
          calls == [b"RIFF-distinct-one", b"RIFF-distinct-two"], calls)


def full_scopes(ese, osint, modern_crypto):
    check("ESE delivery candidate identity is the full SHA-256",
          ese._digest(b"ese-a") == hashlib.sha256(b"ese-a").hexdigest()
          and len(ese._digest(b"ese-a")) == 64)
    check("OSINT canonical-value candidate identity is the full SHA-256",
          osint._value_scope("2001:db8::1") == hashlib.sha256(b"2001:db8::1").hexdigest()
          and len(osint._value_scope("2001:db8::1")) == 64)
    material = modern_crypto._DlogMaterial({"group.txt": b"p=23\ng=5\nh=8\n"})
    q = {"question": "What is x?", "answer_format": {"kind": "integer"}, "artifact": "group.txt"}
    inst = {"p": 23, "g": 5, "order": 22, "pubs": {"h": 8}, "c1": None, "c2": None, "privs": []}
    fp = modern_crypto._dlog_fingerprint(q, material, inst, "log", "h")
    check("discrete-log candidate identity is the full SHA-256", len(fp) == 64 and int(fp, 16) >= 0, fp)


def main():
    sys.path[:0] = [str(REPO / "solvers" / "common"), str(TOOLKITS)]
    windows, cloudlogs, maldoc = load("windows"), load("cloudlogs"), load("maldoc")
    web, rf = load("web"), load("rf")
    ese, osint, modern_crypto = load("ese_reader"), load("osint"), load("modern_crypto")
    windows_dedup(windows)
    cloud_dedup(cloudlogs)
    maldoc_dedup(maldoc)
    web_dedup(web)
    rf_cache(rf)
    full_scopes(ese, osint, modern_crypto)
    print("ok" if not FAILED else f"FAILED: {len(FAILED)}: " + "; ".join(FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
