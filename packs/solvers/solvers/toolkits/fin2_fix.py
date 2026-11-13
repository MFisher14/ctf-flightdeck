#!/usr/bin/env python3
"""Bounded offline FIX 4.2/4.4/FIXT.1.1 wire reader and session auditor.

Public API: parse_stream(data, pipe=False), parse_message(data, pipe=False),
analyze(data, pipe=False, initial_sequence=None), main(argv=None).
Malformed input raises FixError; protocol/session anomalies are returned as
findings. ``pipe=True`` explicitly treats every | as a log-rendered SOH (do not
use for binary payloads). Raw wire bytes remain the authoritative input.

Preserves repeated tags and length-delimited binary data. Does not claim full
application-dictionary validation, TCP reassembly, signature verification or
exchange-specific order-state validation. Feed a reconstructed stream or a log
containing only messages, in capture order; CR/LF between messages are allowed.
No sockets, external commands, untrusted execution or flag submission.

References: FIX Session Layer (June 2020), FIXT 1.1 (March 2008), official
FIXimate 4.2/4.4/5.0SP2 dictionaries. CheckSum is error detection, not authenticity.
"""
from __future__ import annotations

import argparse
import datetime as _dt
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

MAX_BYTES = 8 * 1024 * 1024
MAX_MESSAGES = 10000
MAX_FIELDS = 4096
MAX_VALUE = 1024 * 1024
MAX_SEQUENCE = 2147483647
SOH = b"\x01"
VERSIONS = {"FIX.4.2", "FIX.4.4", "FIXT.1.1"}
APP_VERSIONS = {"4": "FIX.4.2", "5": "FIX.4.3", "6": "FIX.4.4",
                "7": "FIX.5.0", "8": "FIX.5.0SP1", "9": "FIX.5.0SP2"}
# Explicit standard Length/Data pairs; an unknown extension remains opaque.
LENGTH_DATA = {90: 91, 93: 89, 95: 96, 212: 213, 348: 349, 350: 351,
               352: 353, 354: 355, 356: 357, 358: 359, 360: 361,
               362: 363, 364: 365, 445: 446, 618: 619, 621: 622}
DATA_TAGS = frozenset(LENGTH_DATA.values())
NAMES = {8: "BeginString", 9: "BodyLength", 10: "CheckSum", 35: "MsgType",
         34: "MsgSeqNum", 49: "SenderCompID", 56: "TargetCompID", 52: "SendingTime",
         43: "PossDupFlag", 97: "PossResend", 122: "OrigSendingTime",
         7: "BeginSeqNo", 16: "EndSeqNo", 36: "NewSeqNo", 123: "GapFillFlag",
         98: "EncryptMethod", 108: "HeartBtInt", 112: "TestReqID",
         141: "ResetSeqNumFlag", 1128: "ApplVerID", 1137: "DefaultApplVerID",
         1: "Account", 11: "ClOrdID", 41: "OrigClOrdID", 37: "OrderID",
         17: "ExecID", 150: "ExecType", 39: "OrdStatus", 55: "Symbol",
         54: "Side", 38: "OrderQty", 40: "OrdType", 44: "Price",
         32: "LastQty", 31: "LastPx", 14: "CumQty", 151: "LeavesQty",
         6: "AvgPx", 15: "Currency", 58: "Text", 355: "EncodedText",
         453: "NoPartyIDs", 448: "PartyID", 447: "PartyIDSource", 452: "PartyRole"}
TYPES = {"0": "Heartbeat", "1": "TestRequest", "2": "ResendRequest",
         "3": "Reject", "4": "SequenceReset", "5": "Logout", "A": "Logon",
         "D": "NewOrderSingle", "F": "OrderCancelRequest", "G": "OrderCancelReplaceRequest",
         "8": "ExecutionReport", "9": "OrderCancelReject", "V": "MarketDataRequest",
         "W": "MarketDataSnapshotFullRefresh", "X": "MarketDataIncrementalRefresh",
         "j": "BusinessMessageReject", "AE": "TradeCaptureReport"}
ADMIN = frozenset(("0", "1", "2", "3", "4", "5", "A"))
SINGLETON = frozenset((8, 9, 10, 35, 34, 49, 56, 52, 50, 57, 142, 143,
                       43, 97, 122, 7, 16, 36, 123, 98, 108, 112, 141, 1128, 1137))
FLAG_RE = flagfmt.TEXT


class FixError(ValueError):
    """Invalid/unsupported FIX input or an analysis resource limit."""


def _wire(data, pipe):
    if not isinstance(pipe, bool):
        raise FixError("pipe must be a bool")
    if not isinstance(data, (bytes, bytearray, str)):
        raise FixError("input must be bytes, bytearray or a Latin-1 string")
    if len(data) > MAX_BYTES:
        raise FixError("input exceeds 8 MiB limit")
    try:
        raw = data.encode("latin-1") if isinstance(data, str) else bytes(data)
    except UnicodeError as exc:
        raise FixError("FIX text must be Latin-1 encodable") from exc
    return raw.replace(b"|", SOH) if pipe else raw


def _uint(value, label, maximum=MAX_SEQUENCE, minimum=0):
    if not value or len(value) > 12 or not value.isascii() or not value.isdigit():
        raise FixError(f"{label}: expected bounded unsigned integer")
    number = int(value)
    if not minimum <= number <= maximum:
        raise FixError(f"{label}: outside supported range")
    return number


def _time(value):
    if not re.fullmatch(r"[0-9]{8}-[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,12})?", value):
        raise FixError("invalid UTCTimestamp")
    # FIX permits leap second 60. Validate the calendar using 59 for that second.
    base = value[:17]
    if base[-2:] == "60":
        base = base[:-2] + "59"
    try:
        _dt.datetime.strptime(base, "%Y%m%d-%H:%M:%S")
    except ValueError as exc:
        raise FixError("invalid UTCTimestamp date/time") from exc
    return (value[:17], value[18:].ljust(12, "0"))


def _plain(raw, pos, end):
    stop = raw.find(SOH, pos, end)
    if stop < 0 or stop - pos > MAX_VALUE:
        raise FixError(f"unterminated/oversized field at offset {pos}")
    eq = raw.find(b"=", pos, stop)
    if eq < 0:
        raise FixError(f"field lacks '=' at offset {pos}")
    tag = _uint(raw[pos:eq], "tag", 999999, 1)
    value = raw[eq + 1:stop]
    if not value:
        raise FixError(f"empty value for tag {tag}")
    return tag, value, stop + 1


def _fields(raw, pos, end):
    out = []
    pending = None
    while pos < end:
        if len(out) >= MAX_FIELDS:
            raise FixError("too many fields in one message")
        if pending is None:
            tag, value, after = _plain(raw, pos, end)
            if tag in DATA_TAGS:
                raise FixError(f"data tag {tag} lacks its immediately preceding length")
        else:
            tag, length = pending
            prefix = str(tag).encode("ascii") + b"="
            start = pos + len(prefix)
            after = start + length + 1
            if not raw.startswith(prefix, pos) or after > end or raw[after - 1:after] != SOH:
                raise FixError(f"length/data mismatch at offset {pos}")
            value = raw[start:after - 1]
            pending = None
        out.append((tag, value.decode("latin-1")))
        if tag in LENGTH_DATA:
            pending = (LENGTH_DATA[tag], _uint(value, "data length", MAX_VALUE))
        pos = after
    if pending is not None:
        raise FixError("data length has no following data field")
    return out


def _parse(raw):
    messages = []
    pos = 0
    while pos < len(raw):
        while pos < len(raw) and raw[pos] in (10, 13):
            pos += 1
        if pos == len(raw):
            break
        if len(messages) >= MAX_MESSAGES:
            raise FixError("too many messages")
        start = pos
        tag, version, pos = _plain(raw, pos, len(raw))
        if tag != 8 or version.decode("latin-1") not in VERSIONS:
            raise FixError(f"expected FIX.4.2/FIX.4.4/FIXT.1.1 BeginString at {start}")
        tag, length, body_start = _plain(raw, pos, len(raw))
        if tag != 9:
            raise FixError("BodyLength must be second")
        body_length = _uint(length, "BodyLength", MAX_BYTES, 1)
        trailer = body_start + body_length
        pos = trailer + 7
        if pos > len(raw) or not re.fullmatch(rb"10=[0-9]{3}\x01", raw[trailer:pos]):
            raise FixError(f"BodyLength does not land on CheckSum at {trailer}")
        checksum = int(raw[trailer + 3:trailer + 6])
        computed = sum(raw[start:trailer]) % 256
        if checksum != computed:
            raise FixError(f"CheckSum mismatch at {start}: declared {checksum:03d}, computed {computed:03d}")
        pairs = [(8, version.decode("latin-1")), (9, length.decode("ascii"))]
        pairs += _fields(raw, body_start, trailer)
        pairs.append((10, f"{checksum:03d}"))
        if len(pairs) < 4 or pairs[2][0] != 35:
            raise FixError("MsgType must be third")
        singleton = {}
        for tag, value in pairs:
            if tag in SINGLETON:
                if tag in singleton:
                    raise FixError(f"duplicate singleton tag {tag}")
                singleton[tag] = value
        for required in (34, 49, 56, 52):
            if required not in singleton:
                raise FixError(f"required session header tag {required} missing")
        seq = _uint(singleton[34], "MsgSeqNum", minimum=1)
        _time(singleton[52])
        if 122 in singleton:
            _time(singleton[122])
        messages.append({"offset": start, "length": pos - start,
                         "version": singleton[8], "msg_type": singleton[35],
                         "type_name": TYPES.get(singleton[35], "Unknown/extension"),
                         "sequence": seq, "sender": singleton[49], "target": singleton[56],
                         "checksum": checksum, "body_length": body_length,
                         "fields": [{"tag": t, "name": NAMES.get(t, "Unknown/extension"), "value": v}
                                    for t, v in pairs]})
    if not messages:
        raise FixError("no FIX messages")
    return messages


def parse_stream(data, *, pipe=False):
    """Read all complete messages, preserving field order and duplicate group tags."""
    return _parse(_wire(data, pipe))


def parse_message(data, *, pipe=False):
    """Read exactly one complete FIX message, otherwise raise FixError."""
    messages = parse_stream(data, pipe=pipe)
    if len(messages) != 1:
        raise FixError("expected exactly one message")
    return messages[0]


def analyze(data, *, pipe=False, initial_sequence=None):
    """Read messages and audit capture-order session behavior without replaying it.

    None anchors each direction at its first captured sequence (partial capture).
    Pass initial_sequence=1 for a complete session capture. Higher-than-expected
    messages are held until gaps fill; late PossDup messages do not rewind state.
    Findings are evidence for review, not proof of fraud.
    """
    if initial_sequence is not None and (type(initial_sequence) is not int or
                                         not 1 <= initial_sequence <= MAX_SEQUENCE):
        raise FixError("initial_sequence must be None or an integer in 1..2147483647")
    messages = parse_stream(data, pipe=pipe)
    states, tests, findings, text_parts = {}, {}, [], []

    def issue(index, code, detail):
        findings.append({"message": index, "code": code, "detail": detail})

    def apply_ordered(index, state):
        """Apply lifecycle/application effects only when a sequence is accepted."""
        message = messages[index]
        values = {f["tag"]: f["value"] for f in message["fields"] if f["tag"] in SINGLETON}
        kind = message["msg_type"]
        message["session_applied"] = True
        if kind == "A":
            if message["version"] == "FIXT.1.1":
                state["app"] = values.get(1137)
            state["logged_on"] = True
            state["observed_logon"] = True
        elif kind == "5":
            state["logged_on"] = False
        elif kind not in ADMIN:
            if not state["logged_on"] and (initial_sequence is not None or state["observed_logon"]):
                issue(index, "application_outside_session", "application message before Logon or after Logout")
            version = values.get(1128, state["app"])
            message["application_version"] = (APP_VERSIONS.get(version, version)
                                              if message["version"] == "FIXT.1.1" else message["version"])

    def buffer(index, advance, state):
        seq = messages[index]["sequence"]
        if seq in state["pending"]:
            prior_advance, prior_index = state["pending"][seq]
            def content(i):
                return [(f["tag"], f["value"]) for f in messages[i]["fields"]
                        if f["tag"] not in (9, 10, 43, 52, 122)]
            conflict = prior_advance != advance or content(prior_index) != content(index)
            issue(index, "conflicting_buffered_sequence" if conflict else "duplicate_buffered_sequence",
                  "keeping the first valid buffered message for this sequence")
        else:
            state["pending"][seq] = (advance, index)

    for index, message in enumerate(messages):
        values = {f["tag"]: f["value"] for f in message["fields"] if f["tag"] in SINGLETON}
        def get(tag, default=None):
            return values.get(tag, default)
        # SubIDs identify traders/desks, not separate sequence-number spaces.
        # Distinct sessions reusing identical CompIDs require separate captures.
        endpoint = get(49)
        peer = get(56)
        key = (message["version"], endpoint, peer)
        reverse = (message["version"], peer, endpoint)
        seq, kind = message["sequence"], message["msg_type"]
        message["session_applied"] = False
        if kind not in ADMIN:
            explicit = get(1128)
            message["application_version"] = (APP_VERSIONS.get(explicit, explicit)
                                              if message["version"] == "FIXT.1.1" else message["version"])
            message["application"] = [{"name": f["name"], "value": f["value"]}
                                      for f in message["fields"]
                                      if f["tag"] in (1, 11, 41, 37, 17, 150, 39, 55, 54, 38, 40,
                                                      44, 32, 31, 14, 151, 6, 15)]
        state = states.setdefault(key, {"next": initial_sequence or seq, "pending": {},
                                        "app": None, "logged_on": False, "observed_logon": False})
        for tag in (43, 97, 123, 141):
            if get(tag) is not None and get(tag) not in ("Y", "N"):
                issue(index, "invalid_boolean", f"tag {tag} must be Y or N")
        if get(43) == "Y":
            if get(122) is None:
                issue(index, "missing_orig_sending_time", "PossDupFlag=Y requires OrigSendingTime")
            elif _time(get(122)) > _time(get(52)):
                issue(index, "future_orig_sending_time", "OrigSendingTime exceeds SendingTime")
        if kind == "A":
            for tag in (98, 108):
                if get(tag) is None:
                    issue(index, "missing_logon_field", f"Logon lacks tag {tag}")
                else:
                    _uint(get(tag), NAMES[tag])
            if get(141) == "Y":
                if seq != 1:
                    issue(index, "reset_logon_sequence", "ResetSeqNumFlag=Y requires MsgSeqNum=1")
                else:
                    state["next"], state["pending"] = 1, {}
                # Observe each direction's reset Logon independently, so the
                # acknowledgement does not erase the already-observed Logon.
                issue(index, "logon_reset", "Logon requests sequence-number reset")
            if message["version"] == "FIXT.1.1":
                if get(1137) is None:
                    issue(index, "missing_app_version", "FIXT Logon lacks DefaultApplVerID")
        expected = state["next"]
        reset_mode = kind == "4" and get(123) != "Y"
        if reset_mode:
            issue(index, "sequence_reset", "SequenceReset Reset mode ignores its MsgSeqNum")
        elif seq > expected:
            issue(index, "sequence_gap", f"expected {expected}, observed {seq}; buffering later message")
        elif seq < expected:
            issue(index, "possible_duplicate" if get(43) == "Y" else "sequence_too_low",
                  f"expected {expected}, observed {seq}")
        if kind == "4":
            if get(36) is None:
                issue(index, "missing_new_seq_no", "SequenceReset lacks NewSeqNo")
            else:
                new = _uint(get(36), "NewSeqNo", minimum=1)
                if not reset_mode and seq < expected and new <= expected:
                    issue(index, "duplicate_gap_fill", "stale GapFill ignored without rewinding sequence")
                elif new <= expected or (not reset_mode and new <= seq):
                    issue(index, "invalid_sequence_reset", f"NewSeqNo={new} does not advance expected={expected}")
                elif reset_mode or seq <= expected:
                    apply_ordered(index, state)
                    state["next"] = new
                    state["pending"] = {n: v for n, v in state["pending"].items() if n >= new}
                else:
                    buffer(index, new, state)
                    issue(index, "deferred_gap_fill", "out-of-order GapFill needs earlier gap filled first")
        elif seq == expected:
            apply_ordered(index, state)
            state["next"] += 1
        elif seq > expected:
            buffer(index, seq + 1, state)
        while state["next"] in state["pending"]:
            previous = state["next"]
            state["next"], pending_index = state["pending"].pop(state["next"])
            apply_ordered(pending_index, state)
            if state["next"] > previous + 1:
                state["pending"] = {n: v for n, v in state["pending"].items() if n >= state["next"]}
        if kind == "2":
            if get(7) is None or get(16) is None:
                issue(index, "missing_resend_range", "ResendRequest requires BeginSeqNo and EndSeqNo")
            else:
                begin = _uint(get(7), "BeginSeqNo", minimum=1)
                end = _uint(get(16), "EndSeqNo")
                if end != 0 and end < begin:
                    issue(index, "invalid_resend_range", "EndSeqNo precedes BeginSeqNo")
                message["resend_range"] = {"begin": begin, "end": end, "through_latest": end == 0}
        if kind == "1":
            if get(112) is None:
                issue(index, "missing_test_req_id", "TestRequest requires TestReqID")
            else:
                tests[(reverse, get(112))] = index
        elif kind == "0" and get(112) is not None:
            if tests.pop((key, get(112)), None) is None:
                issue(index, "unmatched_heartbeat", "heartbeat TestReqID has no captured TestRequest")
        for f in message["fields"]:
            if f["tag"] in (58, 355):
                text_parts.append({"message": index, "tag": f["tag"], "value": f["value"]})
    for (_, req), index in tests.items():
        issue(index, "unanswered_test_request", f"no captured heartbeat for TestReqID={req}")
    flags, seen_flags = [], set()
    for message in messages:
        for f in message["fields"]:
            for flag in FLAG_RE.findall(f["value"]):
                if flag not in seen_flags:
                    seen_flags.add(flag)
                    flags.append(flag)
    text_joined = "".join(part["value"] for part in text_parts)
    return {"format": "FIX", "messages": messages, "findings": findings,
            "sessions": [{"version": k[0], "sender": k[1], "target": k[2],
                          "next_expected": v["next"], "buffered_sequences": sorted(v["pending"])}
                         for k, v in states.items()],
            "text_fragments": text_parts, "flags": flags,
            "joined_text_candidates": list(dict.fromkeys(FLAG_RE.findall(text_joined))),
            "notes": ["Joined text follows capture order across all messages; review fragment provenance.",
                      "Checksums are not message authentication; application dictionaries are not validated."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="raw FIX stream or log containing only messages")
    parser.add_argument("--pipe", action="store_true", help="normalize pipe-rendered SOH (text logs only)")
    parser.add_argument("--initial-sequence", type=int, default=None, help="expected first sequence in each direction")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (TypeError, ValueError):
        return 2
    try:
        with Path(args.file).open("rb") as handle:
            data = handle.read(MAX_BYTES + 1)
        result = analyze(data, pipe=args.pipe, initial_sequence=args.initial_sequence)
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except (FixError, OSError, ValueError, TypeError) as exc:
        print(f"fin2_fix: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
