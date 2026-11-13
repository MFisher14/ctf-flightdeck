#!/usr/bin/env python3
"""Modbus/TCP capture replay with a spec-driven witness/report builder behind a known-answer gate.

Offline only: it reads a supplied PCAP/PCAPNG (through ics_capture) and never opens a socket.

What is mechanical, and done here with no model:

1. ADUs in capture order. Each directional TCP stream is reassembled, split on the MBAP header and
   every ADU is placed at the capture packet that completed it, so requests and responses of both
   directions form one sequence (`capture_adus`).
2. Pairing (`pair`). `pending`: a response answers the one pending request with its transaction id
   and unit in the reverse flow. `immediate`: a response counts only when the ADU directly before it
   is its request. A transaction is *accepted* only on a well-formed normal response: FC03/FC04 byte
   count = 2 x quantity, FC06 echo identical, FC16 echo of start and quantity.
3. Register-state replay (`replay`). A write (FC06/FC16) takes effect on its accepted normal response,
   an accepted FC03 refreshes the words it covers, and an exception, an unanswered request or a bad
   echo changes nothing. Every transaction gets the state immediately before and after its response.

What arrives as prose per challenge, and is therefore a spec (TOML) an agent writes from the handout:
the scope, the target-write selection and its unsafe predicate, the readback confirmation rule, the
derived columns, and the output grammar -- a `witness` (prefix || selected PDUs, hashed) or a `report`
(templated text lines with aggregates, hashed) -- with its hash, truncation, encoding and wrapper.
Templates: solvers/toolkits/modbus_replay_templates/; reference: docs/toolkits/modbus_replay.md.

The known-answer gate: the spec carries the handout's test vector(s). Nothing is emitted -- no value,
no flag, no output file -- unless every vector reproduces through the same serialisation, hash and
encoding code the capture rows go through, and every stated row check and count expectation holds.
"""
from __future__ import annotations

import argparse
import ast
import base64
import bisect
import hashlib
import json
import operator
import os
import re
import struct
import sys
import time
import tomllib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

try:
    from . import ics_capture as _cap
except ImportError:  # flat import (engine sys.path) or direct script execution
    import ics_capture as _cap

ENGINE = "toolkits.modbus_replay"
SPEC_NAMES = ("modbus-replay.toml", "recon/modbus-replay.toml")
OUT_DIR = "recon/modbus_replay"
MAX_MBAP_LENGTH = 254            # unit id + the 253-byte PDU ceiling
MAX_LISTED = 5000                # transactions / timeline rows written to replay.json
MAX_BITS = 4096                  # an expression value wider than this is refused
PCAP_MAGICS = (b"\x0a\x0d\x0d\x0a", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
               b"\xa1\xb2\x3c\x4d")
SKIP_DIRS = {"recon", ".git", ".ctf"}
CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap")
DAMAGE = ("tcp-gap", "conflicting-retransmission", "framing-lost")


class ReplayError(ValueError):
    """A named refusal: `reason` is a short code, `detail` says what and where."""

    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason, self.detail = reason, detail


# ----------------------------------------------------------------------------- 1. ADUs in capture order

@dataclass(frozen=True)
class Adu:
    ordinal: int                 # position in the capture-ordered sequence of all Modbus ADUs
    packet: int                  # capture packet that completed the ADU
    timestamp: float | None
    direction: str               # request (to the server port) | response
    client: str
    client_port: int
    server: str
    server_port: int
    session: int                 # TCP connection count on this 4-tuple (a new SYN starts a new one)
    tid: int
    pid: int
    length: int
    unit: int
    pdu: bytes                   # function code || function data (no MBAP, no unit)
    malformed: str = ""          # why the ADU is rejected; "" when well formed

    @property
    def function(self) -> int:
        return self.pdu[0] & 0x7F if self.pdu else -1

    @property
    def is_exception(self) -> bool:
        return bool(self.pdu) and bool(self.pdu[0] & 0x80)

    @property
    def conversation(self) -> tuple[str, int, str, int, int]:
        return (self.client, self.client_port, self.server, self.server_port, self.session)

    @property
    def raw(self) -> bytes:
        return struct.pack(">HHHB", self.tid, self.pid, self.length, self.unit) + self.pdu


def conversation_text(conv: tuple) -> str:
    return f"{conv[0]}:{conv[1]} -> {conv[2]}:{conv[3]} (connection {conv[4]})"


def capture_adus(data: bytes, *, server_port: int = 502) -> tuple[list[Adu], list[dict[str, Any]]]:
    """Every Modbus/TCP ADU of a capture, both directions, in capture order, plus findings.

    An ADU sits at the capture packet at which the stream was whole up to its last byte (when TCP
    could first deliver it), so segment boundaries (an ADU split over packets, several ADUs in one
    packet, out-of-order segments, retransmissions) neither split nor reorder it.
    Raises ics_capture.ParseError for an unreadable capture."""
    packets, findings = _cap.extract_transports(data)
    stamps = {row["packet_index"]: row.get("timestamp") for row in packets}
    found: list[tuple[tuple[int, int, int], dict[str, Any]]] = []
    for stream_index, stream in enumerate(_cap.reassemble_tcp(packets)):
        to_server = stream["destination_port"] == server_port
        from_server = stream["source_port"] == server_port
        if not (to_server or from_server):
            continue
        if to_server and from_server:
            findings.append({"kind": "ambiguous-direction", "severity": "warning",
                             "detail": f"both ports are {server_port}: {stream['source']} -> "
                                       f"{stream['destination']} left out"})
            continue
        direction = "request" if to_server else "response"
        client, client_port, server = ((stream["source"], stream["source_port"], stream["destination"])
                                       if to_server else
                                       (stream["destination"], stream["destination_port"], stream["source"]))
        conv = (client, client_port, server, server_port, stream["session"])
        if stream["gaps"]:
            findings.append({"kind": "tcp-gap", "severity": "warning", "conversation": conv,
                             "direction": direction, "detail": f"{stream['gaps']} gap(s) in the {direction} stream"})
        if stream["conflicting_retransmitted_bytes"]:
            findings.append({"kind": "conflicting-retransmission", "severity": "warning", "conversation": conv,
                             "direction": direction,
                             "detail": f"{stream['conflicting_retransmitted_bytes']} retransmitted byte(s) disagree"})
        for chunk in stream["chunks"]:
            blob, offsets = chunk["data"], chunk["segment_offsets"]
            delivered: list[int] = []      # delivered[k]: the packet at which segments 0..k had all arrived
            for index in chunk["packet_indices"]:
                delivered.append(max(index, delivered[-1]) if delivered else index)
            offset = 0
            while offset < len(blob):
                left = len(blob) - offset
                if left < 8:
                    findings.append({"kind": "truncated-adu", "severity": "info", "conversation": conv,
                                     "direction": direction, "detail": f"{left} trailing byte(s), no whole MBAP ADU"})
                    break
                tid, pid, length = struct.unpack_from(">HHH", blob, offset)
                if length < 2:
                    findings.append({"kind": "framing-lost", "severity": "warning", "conversation": conv,
                                     "direction": direction,
                                     "detail": f"MBAP Length {length} at stream offset {offset}: cannot find the next ADU"})
                    break
                end = offset + 6 + length
                if end > len(blob):
                    findings.append({"kind": "truncated-adu", "severity": "info", "conversation": conv,
                                     "direction": direction,
                                     "detail": f"ADU tid 0x{tid:04X} needs {6 + length} bytes, {left} captured"})
                    break
                packet = delivered[bisect.bisect_left(offsets, end) - 1]    # the segment holding the last byte
                malformed = ""
                if pid != 0:
                    malformed = f"nonzero protocol identifier 0x{pid:04X}"
                elif length > MAX_MBAP_LENGTH:
                    malformed = f"MBAP Length {length} over {MAX_MBAP_LENGTH}"
                found.append(((packet, stream_index, offset), dict(
                    packet=packet, timestamp=stamps.get(packet), direction=direction, client=client,
                    client_port=client_port, server=server, server_port=server_port, session=stream["session"],
                    tid=tid, pid=pid, length=length, unit=blob[offset + 6], pdu=bytes(blob[offset + 7:end]),
                    malformed=malformed)))
                offset = end
    found.sort(key=lambda pair: pair[0])
    return [Adu(ordinal=ordinal, **row) for ordinal, (_key, row) in enumerate(found)], findings


@dataclass(frozen=True)
class Scope:
    server_port: int = 502
    client: str | None = None
    server: str | None = None
    client_port: int | None = None
    unit: int | None = None


def conversations(adus: list[Adu]) -> list[tuple]:
    return sorted({adu.conversation for adu in adus})


def scope_adus(adus: list[Adu], scope: Scope) -> tuple[list[Adu], tuple]:
    """The ADUs of the one conversation the scope names (then of its unit). A scope that leaves no
    conversation, or more than one, is a named error: the engine never picks one for you."""
    keep = [adu for adu in adus
            if (scope.client is None or adu.client == scope.client)
            and (scope.server is None or adu.server == scope.server)
            and (scope.client_port is None or adu.client_port == scope.client_port)]
    found = conversations(keep)
    if not found:
        raise ReplayError("no-modbus", f"no Modbus/TCP conversation on server port {scope.server_port} matches the scope")
    if len(found) > 1:
        raise ReplayError("ambiguous-conversation",
                          "the scope matches several conversations; narrow [scope] (client, server, client_port): "
                          + "; ".join(conversation_text(conv) for conv in found))
    if scope.unit is not None:
        keep = [adu for adu in keep if adu.unit == scope.unit]
        if not keep:
            raise ReplayError("no-modbus", f"no ADU with unit {scope.unit} in {conversation_text(found[0])}")
    return keep, found[0]


# ----------------------------------------------------------------------------- 2. pairing

@dataclass
class Txn:
    index: int
    request: Adu
    response: Adu | None = None
    kind: str = "unanswered"     # normal | exception | unanswered | rejected
    reason: str = ""             # why it is not accepted; "" for an accepted or simply unanswered one
    start: int | None = None
    quantity: int | None = None
    words: tuple[int, ...] = ()  # the words written (FC06/FC16) or read back (FC03/FC04)
    before: Mapping[int, int] = field(default_factory=dict)   # holding registers just before the response
    after: Mapping[int, int] = field(default_factory=dict)    # ... and just after it

    @property
    def function(self) -> int:
        return self.request.function

    @property
    def accepted(self) -> bool:
        return self.kind == "normal" and not self.reason

    @property
    def order(self) -> int:
        """Where the transaction takes its place in the capture: its response, else its request."""
        return self.response.ordinal if self.response is not None else self.request.ordinal


def _words(blob: bytes) -> tuple[int, ...]:
    return tuple(int.from_bytes(blob[i:i + 2], "big") for i in range(0, len(blob), 2))


def _open(index: int, adu: Adu) -> Txn:
    txn, pdu = Txn(index=index, request=adu), adu.pdu
    if adu.malformed:
        txn.kind, txn.reason = "rejected", adu.malformed
    elif adu.is_exception or not pdu:
        txn.kind, txn.reason = "rejected", "request carries an exception function code"
    elif adu.function in (3, 4):
        if len(pdu) == 5 and 1 <= int.from_bytes(pdu[3:5], "big") <= 125:
            txn.start, txn.quantity = int.from_bytes(pdu[1:3], "big"), int.from_bytes(pdu[3:5], "big")
        else:
            txn.kind, txn.reason = "rejected", f"malformed FC{adu.function:02d} request"
    elif adu.function == 6:
        if len(pdu) == 5:
            txn.start, txn.quantity, txn.words = int.from_bytes(pdu[1:3], "big"), 1, _words(pdu[3:5])
        else:
            txn.kind, txn.reason = "rejected", "malformed FC06 request"
    elif adu.function == 16:
        quantity = int.from_bytes(pdu[3:5], "big") if len(pdu) >= 6 else 0
        if len(pdu) >= 6 and 1 <= quantity <= 123 and pdu[5] == 2 * quantity and len(pdu) == 6 + 2 * quantity:
            txn.start, txn.quantity, txn.words = int.from_bytes(pdu[1:3], "big"), quantity, _words(pdu[6:])
        else:
            txn.kind, txn.reason = "rejected", "malformed FC16 request"
    return txn


def _answers(request: Adu, response: Adu) -> bool:
    return (not response.malformed and response.tid == request.tid and response.pid == request.pid
            and response.unit == request.unit and response.function == request.function)


def _close(txn: Txn, adu: Adu) -> None:
    txn.response = adu
    if txn.kind == "rejected":          # a malformed request never becomes an accepted transaction
        return
    pdu, request = adu.pdu, txn.request.pdu
    if adu.is_exception:
        txn.kind = "exception"
        if len(pdu) != 2:
            txn.reason = "malformed exception response"
        return
    txn.kind = "normal"
    if txn.function in (3, 4):
        if len(pdu) >= 2 and pdu[1] == 2 * txn.quantity and len(pdu) == 2 + pdu[1]:
            txn.words = _words(pdu[2:])
        else:
            txn.reason = f"FC{txn.function:02d} response byte count is not twice the request quantity"
    elif txn.function == 6:
        if pdu != request:
            txn.reason = "FC06 response does not echo the request"
    elif txn.function == 16:
        if pdu != request[:5]:
            txn.reason = "FC16 response does not echo start address and quantity"


def pair(adus: list[Adu], mode: str = "pending") -> tuple[list[Txn], list[dict[str, Any]]]:
    """Requests paired with their responses under one of two rules (module docstring, step 2)."""
    if mode not in ("pending", "immediate"):
        raise ReplayError("spec", f"pairing mode must be pending or immediate, not {mode!r}")
    txns: list[Txn] = []
    findings: list[dict[str, Any]] = []

    def orphan(adu: Adu, why: str) -> None:
        findings.append({"kind": "orphan-response", "severity": "warning", "ordinal": adu.ordinal,
                         "packet": adu.packet, "detail": f"response tid 0x{adu.tid:04X} unit {adu.unit}: {why}"})

    if mode == "immediate":
        waiting: Txn | None = None
        for adu in adus:
            if adu.direction == "request":
                waiting = _open(len(txns), adu)
                txns.append(waiting)
            else:
                if waiting is not None and _answers(waiting.request, adu):
                    _close(waiting, adu)
                else:
                    orphan(adu, "the ADU directly before it is not its request")
                waiting = None
        return txns, findings

    pending: dict[tuple[int, int], list[Txn]] = {}
    answered: dict[tuple[int, int], Txn] = {}
    for adu in adus:
        key = (adu.tid, adu.unit)
        if adu.direction == "request":
            txn = _open(len(txns), adu)
            txns.append(txn)
            if not adu.malformed:
                pending.setdefault(key, []).append(txn)
            continue
        if adu.malformed:
            orphan(adu, f"rejected ADU ({adu.malformed})")
            continue
        waiting_rows = pending.pop(key, [])
        if len(waiting_rows) == 1 and _answers(waiting_rows[0].request, adu):
            _close(waiting_rows[0], adu)
            answered[key] = waiting_rows[0]
        elif len(waiting_rows) > 1:
            for txn in waiting_rows:
                txn.kind, txn.reason = "rejected", "transaction id was pending more than once when a response came"
            orphan(adu, f"{len(waiting_rows)} requests were pending with this transaction id")
        elif waiting_rows:
            waiting_rows[0].kind, waiting_rows[0].reason = "rejected", "its response has another function code"
            orphan(adu, "function code does not match its request")
        elif key in answered:
            answered[key].reason = answered[key].reason or "a duplicate response followed"
            orphan(adu, "duplicate response to an answered request")
        else:
            orphan(adu, "no pending request")
    return txns, findings


# ----------------------------------------------------------------------------- 3. register-state replay

def replay(txns: list[Txn], *, initial: Mapping[int, int] | None = None,
           fc03_refresh: bool = True) -> list[dict[str, Any]]:
    """Replay holding-register state over the transactions; return the timeline of changes.

    Sets `txn.before` / `txn.after` (address -> word; treat them as read-only, unchanged states share
    one mapping). FC06/FC16 apply on their accepted normal response; an accepted FC03 refreshes every
    word it covers; nothing else changes state."""
    state: dict[int, int] = dict(initial or {})
    timeline: list[dict[str, Any]] = []
    for txn in sorted(txns, key=lambda row: row.order):
        txn.before = state
        writes = txn.function in (6, 16)
        if txn.accepted and (writes or (txn.function == 3 and fc03_refresh)):
            changed = {txn.start + k: word for k, word in enumerate(txn.words) if state.get(txn.start + k) != word}
            if changed:
                for address, word in changed.items():
                    timeline.append({"ordinal": txn.response.ordinal, "packet": txn.response.packet,
                                     "tid": txn.request.tid, "function": txn.function,
                                     "source": "write" if writes else "read",
                                     "address": address, "old": state.get(address), "new": word})
                state = {**state, **changed}
        txn.after = state
    return timeline


# ----------------------------------------------------------------------------- expressions and templates

_BINOPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.FloorDiv: operator.floordiv,
           ast.Mod: operator.mod, ast.BitAnd: operator.and_, ast.BitOr: operator.or_, ast.BitXor: operator.xor,
           ast.LShift: operator.lshift, ast.RShift: operator.rshift}
_CMPOPS = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt, ast.LtE: operator.le,
           ast.Gt: operator.gt, ast.GtE: operator.ge}
_FUNCS = {"abs": abs, "min": min, "max": max}


class Expr:
    """An integer expression from a spec: + - * // % & | ^ << >>, comparisons, and/or/not,
    `a if c else b`, abs/min/max, names and integer literals. Nothing else parses (no attribute
    access, no calls of anything else, no `/`), so a spec cannot run code."""

    def __init__(self, text: Any, where: str):
        if not isinstance(text, str) or not text.strip():
            raise ReplayError("spec", f"{where} must be a non-empty expression string")
        try:
            tree = ast.parse(text.strip(), mode="eval")
        except SyntaxError as exc:
            raise ReplayError("spec", f"{where}: not an expression ({exc.msg}): {text!r}") from None
        self.text, self.where, self.names = text.strip(), where, set()
        self._body = tree.body
        self._check(self._body)

    def _bad(self, what: str) -> ReplayError:
        return ReplayError("spec", f"{self.where}: {what} in {self.text!r}")

    def _check(self, node: ast.AST) -> None:
        if isinstance(node, ast.BoolOp):
            children = node.values
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.Not, ast.USub, ast.UAdd)):
            children = [node.operand]
        elif isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Div):
                raise self._bad("'/' is not allowed, use '//' (integer floor division)")
            if type(node.op) not in _BINOPS:
                raise self._bad(f"operator {type(node.op).__name__} is not allowed")
            children = [node.left, node.right]
        elif isinstance(node, ast.Compare):
            if any(type(op) not in _CMPOPS for op in node.ops):
                raise self._bad("only == != < <= > >= comparisons are allowed")
            children = [node.left, *node.comparators]
        elif isinstance(node, ast.IfExp):
            children = [node.test, node.body, node.orelse]
        elif isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in _FUNCS or node.keywords or not node.args:
                raise self._bad("only abs(), min() and max() may be called")
            children = list(node.args)
        elif isinstance(node, ast.Name):
            self.names.add(node.id)
            return
        elif isinstance(node, ast.Constant) and type(node.value) in (int, bool):
            return
        else:
            raise self._bad(f"{type(node).__name__} is not allowed")
        for child in children:
            self._check(child)

    def eval(self, names: Mapping[str, Any]) -> int:
        return self._eval(self._body, names)

    def _eval(self, node: ast.AST, names: Mapping[str, Any]) -> int:
        if isinstance(node, ast.Constant):
            return int(node.value)
        if isinstance(node, ast.Name):
            if node.id not in names:
                raise ReplayError("undefined-name", f"{self.where}: {node.id!r} has no value in {self.text!r}")
            return int(names[node.id])
        if isinstance(node, ast.BoolOp):
            wanted = isinstance(node.op, ast.Or)
            for child in node.values:
                if bool(self._eval(child, names)) == wanted:
                    return int(wanted)
            return int(not wanted)
        if isinstance(node, ast.UnaryOp):
            value = self._eval(node.operand, names)
            return int(not value) if isinstance(node.op, ast.Not) else (-value if isinstance(node.op, ast.USub) else value)
        if isinstance(node, ast.BinOp):
            left, right = self._eval(node.left, names), self._eval(node.right, names)
            if isinstance(node.op, (ast.FloorDiv, ast.Mod)) and right == 0:
                raise ReplayError("expression", f"{self.where}: division by zero in {self.text!r}")
            if isinstance(node.op, (ast.LShift, ast.RShift)) and not 0 <= right <= MAX_BITS:
                raise ReplayError("expression", f"{self.where}: shift by {right} in {self.text!r}")
            value = _BINOPS[type(node.op)](left, right)
            if value.bit_length() > MAX_BITS:
                raise ReplayError("expression", f"{self.where}: value over {MAX_BITS} bits in {self.text!r}")
            return value
        if isinstance(node, ast.Compare):
            left = self._eval(node.left, names)
            for op, comparator in zip(node.ops, node.comparators):
                right = self._eval(comparator, names)
                if not _CMPOPS[type(op)](left, right):
                    return 0
                left = right
            return 1
        if isinstance(node, ast.IfExp):
            return self._eval(node.body if self._eval(node.test, names) else node.orelse, names)
        return int(_FUNCS[node.func.id](*(self._eval(arg, names) for arg in node.args)))  # ast.Call


_FIELD = re.compile(r"\{\{|\}\}|\{([A-Za-z_][A-Za-z0-9_]*)(?::([^{}]*))?\}|[{}]")
_FORMAT = re.compile(r"0?([0-9]*)[dxX]\Z")
MAX_FIELD_WIDTH = 64             # a report field padded wider than this is a spec mistake, not a format


class Template:
    """A report line: literal text with `{name}` or `{name:04X}` fields (format: optional zero fill,
    optional width, then d, x or X); `{{` and `}}` are literal braces. Nothing else is interpreted."""

    def __init__(self, text: Any, where: str):
        if not isinstance(text, str):
            raise ReplayError("spec", f"{where} must be a string")
        self.text, self.where = text, where
        self.names: set[str] = set()
        for match in _FIELD.finditer(text):
            if match.group(0) in ("{", "}"):
                raise ReplayError("spec", f"{where}: stray brace at column {match.start() + 1} in {text!r} "
                                          "(fields are {name} or {name:04X}; double a literal brace)")
            if match.group(1):
                self.names.add(match.group(1))
                fmt = match.group(2)
                if fmt is not None:
                    shape = _FORMAT.match(fmt)
                    if shape is None:
                        raise ReplayError("spec", f"{where}: field format {fmt!r} in {text!r} is not "
                                                  "[0][width](d|x|X)")
                    if shape.group(1) and int(shape.group(1)) > MAX_FIELD_WIDTH:
                        raise ReplayError("spec", f"{where}: field width {int(shape.group(1))} in {text!r} is over "
                                                  f"{MAX_FIELD_WIDTH}")

    def render(self, names: Mapping[str, Any]) -> str:
        def one(match: re.Match) -> str:
            if match.group(0) in ("{{", "}}"):
                return match.group(0)[0]
            name = match.group(1)
            if name not in names:
                raise ReplayError("undefined-name", f"{self.where}: {name!r} has no value in {self.text!r}")
            return format(int(names[name]), match.group(2) or "d")
        return _FIELD.sub(one, self.text)


# ----------------------------------------------------------------------------- 4. the spec

PARTS = {
    "request_pdu": lambda txn: txn.request.pdu,
    "response_pdu": lambda txn: txn.response.pdu,
    "request_adu": lambda txn: txn.request.raw,
    "response_adu": lambda txn: txn.response.raw,
    "request_data": lambda txn: txn.request.pdu[1:],
    "response_data": lambda txn: txn.response.pdu[1:],
}
HASHES = ("none", "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512")
ENCODINGS = ("hex", "hex-upper", "base32", "base32-nopad", "base64", "base64-nopad", "base64url", "base64url-nopad")
AGGREGATES = ("bitmask", "sum", "count")
# [expect] counts that say something about which transactions the policy selected; the others (adus,
# transactions, accepted, exceptions, unanswered, rejected, writes) are fixed before any selection is made.
SELECTION_COUNTS = ("targets", "ineligible", "discarded", "unselected", "rows")
COUNTS = ("adus", "transactions", "accepted", "exceptions", "unanswered", "rejected", "writes", "targets",
          "ineligible", "discarded", "unselected", "rows")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_RESERVED = {"i", "n", "tid", "unit", "function", "start", "quantity", "ordinal", "packet", "rb_tid",
             "abs", "min", "max", "True", "False", "None"}


def _table(value: Any, where: str, allowed: tuple[str, ...]) -> dict:
    if not isinstance(value, dict):
        raise ReplayError("spec", f"{where} must be a table")
    extra = sorted(set(value) - set(allowed))
    if extra:
        raise ReplayError("spec", f"{where}: unknown key(s) {', '.join(extra)} (known: {', '.join(allowed)})")
    return value


def _int(value: Any, where: str, low: int = 0, high: int = 0xFFFF) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ReplayError("spec", f"{where} must be an integer {low}..{high}, not {value!r}")
    return value


def _choice(value: Any, where: str, choices: tuple[str, ...]) -> str:
    if value not in choices:
        raise ReplayError("spec", f"{where} must be one of {', '.join(choices)}, not {value!r}")
    return value


def _name(value: Any, where: str, taken: set[str]) -> str:
    if not isinstance(value, str) or not _IDENT.match(value):
        raise ReplayError("spec", f"{where}: {value!r} is not a name (letters, digits, underscore)")
    if value in _RESERVED or value.startswith(("prev_", "init_")) or re.fullmatch(r"w[0-9]+", value):
        raise ReplayError("spec", f"{where}: {value!r} is a reserved name")
    if value in taken:
        raise ReplayError("spec", f"{where}: the name {value!r} is used twice")
    taken.add(value)
    return value


def _int_table(value: Any, where: str, high: int = (1 << 64) - 1) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ReplayError("spec", f"{where} must be a table of name = integer")
    return {str(key): _int(item, f"{where}.{key}", 0, high) for key, item in value.items()}


def _hex(value: Any, where: str) -> bytes:
    if not isinstance(value, str):
        raise ReplayError("spec", f"{where} must be a hex string")
    try:
        return bytes.fromhex(re.sub(r"[\s:,]", "", value))
    except ValueError:
        raise ReplayError("spec", f"{where} is not hex: {value!r}") from None


@dataclass(frozen=True)
class Readback:
    function: int
    start: int
    quantity: int
    fields: tuple[str, ...]


@dataclass(frozen=True)
class Select:
    function: int = 16
    start: tuple[int, ...] | None = None
    quantity: tuple[int, ...] | None = None
    window: tuple[int, int] | None = None
    state: str = "before"
    when: Expr | None = None
    order: str = "response"
    readback: Readback | None = None


@dataclass(frozen=True)
class Aggregate:
    name: str
    kind: str
    expr: Expr | None
    width: int
    first: str


@dataclass(frozen=True)
class Output:
    kind: str                                  # witness | report
    prefix: bytes = b""
    parts: tuple[str, ...] = ()
    header: tuple[Template, ...] = ()
    row: Template | None = None
    footer: tuple[Template, ...] = ()
    newline: str = "\n"
    final_newline: bool = False
    aggregates: tuple[Aggregate, ...] = ()
    hash: str = "sha256"
    digest_bytes: int = 0                      # 0 = the whole digest
    encoding: str = "hex"
    wrap: str = "event"


@dataclass(frozen=True)
class Vector:
    name: str
    rows: tuple[dict, ...]
    initial: dict[str, int] | None
    expect: str | None
    expect_digest: str | None
    expect_text: str | None
    expect_rows: tuple[dict[str, int], ...] | None
    expect_initial: dict[str, int] | None


@dataclass(frozen=True)
class Spec:
    source: str
    capture_file: str | None
    allow_damaged: bool
    scope: Scope
    pairing: str
    registers: dict[str, int]
    initial_state: dict[int, int]
    unknown: int | None
    fc03_refresh: bool
    select: Select
    row_initial: dict[str, int]
    derive: tuple[tuple[str, Expr], ...]
    checks: tuple[tuple[str, Expr], ...]
    expect: dict[str, int]
    output: Output
    vectors: tuple[Vector, ...]


def _int_list(value: Any, where: str) -> tuple[int, ...]:
    rows = value if isinstance(value, list) else [value]
    if not rows:
        raise ReplayError("spec", f"{where} must not be empty")
    return tuple(_int(item, where) for item in rows)


def _parse_output(raw: Any, taken: set[str]) -> Output:
    common = ("kind", "hash", "digest_bytes", "encoding", "wrap")
    kind = _choice(_table(raw, "[output]", common + (
        "prefix_hex", "prefix_text", "parts", "header", "row", "footer", "newline", "final_newline", "aggregate",
    )).get("kind"), "output.kind", ("witness", "report"))
    fields: dict[str, Any] = {"kind": kind}
    if kind == "witness":
        _table(raw, "[output] (kind witness)", common + ("prefix_hex", "prefix_text", "parts"))
        if "prefix_hex" in raw and "prefix_text" in raw:
            raise ReplayError("spec", "output: give prefix_hex or prefix_text, not both (their order would be a guess)")
        prefix = _hex(raw.get("prefix_hex", ""), "output.prefix_hex")
        text = raw.get("prefix_text", "")
        if not isinstance(text, str):
            raise ReplayError("spec", "output.prefix_text must be a string")
        parts = raw.get("parts")
        if not isinstance(parts, list) or not parts:
            raise ReplayError("spec", f"output.parts must list what each selected transaction contributes, in order "
                                      f"({', '.join(PARTS)})")
        fields.update(prefix=prefix + text.encode("utf-8"),
                      parts=tuple(_choice(part, "output.parts", tuple(PARTS)) for part in parts))
    else:
        _table(raw, "[output] (kind report)", common + ("header", "row", "footer", "newline", "final_newline", "aggregate"))
        for key in ("header", "footer"):
            lines = raw.get(key, [])
            if not isinstance(lines, list):
                raise ReplayError("spec", f"output.{key} must be a list of lines")
            fields[key] = tuple(Template(line, f"output.{key}[{k}]") for k, line in enumerate(lines))
        fields["row"] = Template(raw["row"], "output.row") if "row" in raw else None
        if not (fields["header"] or fields["row"] or fields["footer"]):
            raise ReplayError("spec", "output (kind report) needs header, row or footer lines")
        fields["newline"] = {"lf": "\n", "crlf": "\r\n"}[_choice(raw.get("newline", "lf"), "output.newline", ("lf", "crlf"))]
        if type(raw.get("final_newline", False)) is not bool:
            raise ReplayError("spec", "output.final_newline must be true or false")
        fields["final_newline"] = raw.get("final_newline", False)
        aggregates = []
        rows = raw.get("aggregate", [])
        if not isinstance(rows, list):
            raise ReplayError("spec", "[[output.aggregate]] must be an array of tables")
        for k, item in enumerate(rows):
            where = f"output.aggregate[{k}]"
            _table(item, where, ("name", "kind", "expr", "width", "first"))
            agg_kind = _choice(item.get("kind"), f"{where}.kind", AGGREGATES)
            if agg_kind == "count" and "expr" not in item:
                expr = None
            else:
                expr = Expr(item.get("expr"), f"{where}.expr")
            aggregates.append(Aggregate(
                name=_name(item.get("name"), f"{where}.name", taken), kind=agg_kind, expr=expr,
                width=_int(item.get("width", 64), f"{where}.width", 1, MAX_BITS),
                first=_choice(item.get("first", "msb"), f"{where}.first", ("msb", "lsb"))))
        fields["aggregates"] = tuple(aggregates)
    fields["hash"] = _choice(raw.get("hash", "sha256"), "output.hash", HASHES)
    fields["digest_bytes"] = _int(raw.get("digest_bytes", 0), "output.digest_bytes", 0, 64)
    fields["encoding"] = _choice(raw.get("encoding", "hex"), "output.encoding", ENCODINGS)
    wrap = raw.get("wrap", "event")
    if not isinstance(wrap, str) or (wrap not in ("event", "none") and wrap.count("{}") != 1):
        raise ReplayError("spec", 'output.wrap must be "event" (the event flag prefix), "none", or text with one {} '
                                  'where the value goes, e.g. "FLAG{{}}"')
    fields["wrap"] = wrap
    return Output(**fields)


def _parse_vector(raw: Any, k: int, output: Output) -> Vector:
    where = f"vector[{k}]"
    _table(raw, where, ("name", "rows", "initial", "expect", "expect_digest", "expect_text", "expect_rows",
                        "expect_initial"))
    rows_raw = raw.get("rows")
    if not isinstance(rows_raw, list) or not rows_raw:
        raise ReplayError("spec", f"{where}.rows must be a non-empty array of tables")
    rows = []
    for j, item in enumerate(rows_raw):
        if output.kind == "witness":
            _table(item, f"{where}.rows[{j}]", output.parts)
            missing = [part for part in output.parts if part not in item]
            if missing:
                raise ReplayError("spec", f"{where}.rows[{j}] lacks {', '.join(missing)} (hex)")
            rows.append({"_parts": {part: _hex(item[part], f"{where}.rows[{j}].{part}") for part in output.parts}})
        else:
            rows.append(dict(_int_table(item, f"{where}.rows[{j}]")))
    expect, digest, text = raw.get("expect"), raw.get("expect_digest"), raw.get("expect_text")
    for key, value in (("expect", expect), ("expect_digest", digest), ("expect_text", text)):
        if value is not None and not isinstance(value, str):
            raise ReplayError("spec", f"{where}.{key} must be a string")
    if expect is None and digest is None:
        raise ReplayError("spec", f"{where} states no expect (the encoded value) and no expect_digest (hex of the "
                                  "whole digest): a vector that stops at the text does not test the hash or encoding")
    if text is not None and output.kind != "report":
        raise ReplayError("spec", f"{where}.expect_text is for a report output")
    expect_rows = raw.get("expect_rows")
    if expect_rows is not None:
        if not isinstance(expect_rows, list) or len(expect_rows) != len(rows):
            raise ReplayError("spec", f"{where}.expect_rows must have one table per row ({len(rows)})")
        expect_rows = tuple(_int_table(item, f"{where}.expect_rows[{j}]") for j, item in enumerate(expect_rows))
    return Vector(
        name=str(raw.get("name", f"vector {k + 1}")), rows=tuple(rows),
        initial=_int_table(raw["initial"], f"{where}.initial") if "initial" in raw else None,
        expect=expect, expect_digest=re.sub(r"\s", "", digest).lower() if digest is not None else None,
        expect_text=text, expect_rows=expect_rows,
        expect_initial=_int_table(raw["expect_initial"], f"{where}.expect_initial") if "expect_initial" in raw else None)


def parse_spec(raw: Any, source: str = "<spec>") -> Spec:
    """Validate a decoded spec table. Every problem is a ReplayError('spec', ...) naming the key."""
    _table(raw, "the spec", ("schema", "capture", "scope", "pairing", "registers", "replay", "select", "rows",
                             "expect", "output", "vector"))
    if raw.get("schema") != 1:
        raise ReplayError("spec", f"schema must be 1, not {raw.get('schema')!r}")
    taken: set[str] = set()
    capture = _table(raw.get("capture", {}), "[capture]", ("file", "allow_damaged"))
    if "file" in capture and not isinstance(capture["file"], str):
        raise ReplayError("spec", "capture.file must be a file name")
    if type(capture.get("allow_damaged", False)) is not bool:
        raise ReplayError("spec", "capture.allow_damaged must be true or false")
    scope_raw = _table(raw.get("scope", {}), "[scope]", ("server_port", "client", "server", "client_port", "unit"))
    for key in ("client", "server"):
        if key in scope_raw and not isinstance(scope_raw[key], str):
            raise ReplayError("spec", f"scope.{key} must be an address string")
    scope = Scope(
        server_port=_int(scope_raw.get("server_port", 502), "scope.server_port", 1),
        client=scope_raw.get("client"), server=scope_raw.get("server"),
        client_port=_int(scope_raw["client_port"], "scope.client_port", 1) if "client_port" in scope_raw else None,
        unit=_int(scope_raw["unit"], "scope.unit", 0, 255) if "unit" in scope_raw else None)
    pairing = _choice(_table(raw.get("pairing", {}), "[pairing]", ("mode",)).get("mode", "pending"),
                      "pairing.mode", ("pending", "immediate"))
    registers_raw = raw.get("registers", {})
    if not isinstance(registers_raw, dict):
        raise ReplayError("spec", "[registers] must be a table of name = address")
    registers = {_name(name, "[registers]", taken): _int(address, f"registers.{name}")
                 for name, address in registers_raw.items()}
    replay_raw = _table(raw.get("replay", {}), "[replay]", ("initial", "unknown", "fc03_refresh"))
    initial_state = {}
    for name, value in _int_table(replay_raw.get("initial", {}), "replay.initial", 0xFFFF).items():
        if name not in registers:
            raise ReplayError("spec", f"replay.initial.{name} is not a name in [registers]")
        initial_state[registers[name]] = value
    if type(replay_raw.get("fc03_refresh", True)) is not bool:
        raise ReplayError("spec", "replay.fc03_refresh must be true or false")

    select_raw = _table(raw.get("select", {}), "[select]", ("function", "start", "quantity", "window", "state",
                                                            "when", "order", "readback"))
    window = None
    if "window" in select_raw:
        window = _int_list(select_raw["window"], "select.window")
        if len(window) != 2 or window[0] > window[1]:
            raise ReplayError("spec", "select.window must be [lowest address, highest address]")
    readback = None
    if "readback" in select_raw:
        rb = _table(select_raw["readback"], "[select.readback]", ("function", "start", "quantity", "fields"))
        quantity = _int(rb.get("quantity"), "select.readback.quantity", 1, 125)
        names = rb.get("fields")
        if not isinstance(names, list) or len(names) != quantity:
            raise ReplayError("spec", f"select.readback.fields must name the {quantity} word(s) read back, in order")
        readback = Readback(function=_int(rb.get("function", 3), "select.readback.function", 3, 4),
                            start=_int(rb.get("start"), "select.readback.start"), quantity=quantity,
                            fields=tuple(_name(name, "select.readback.fields", taken) for name in names))
    function = _int(select_raw.get("function", 16), "select.function", 1, 127)
    if function not in (6, 16):
        raise ReplayError("spec", f"select.function must be 6 or 16 (a register write), not {function}")
    select = Select(
        function=function,
        start=_int_list(select_raw["start"], "select.start") if "start" in select_raw else None,
        quantity=_int_list(select_raw["quantity"], "select.quantity") if "quantity" in select_raw else None,
        window=window, state=_choice(select_raw.get("state", "before"), "select.state", ("before", "after")),
        when=Expr(select_raw["when"], "select.when") if "when" in select_raw else None,
        order=_choice(select_raw.get("order", "response"), "select.order", ("response", "request")),
        readback=readback)

    rows_raw = _table(raw.get("rows", {}), "[rows]", ("initial", "derive", "check"))
    derive = []
    for k, item in enumerate(rows_raw.get("derive", [])):
        _table(item, f"rows.derive[{k}]", ("name", "expr"))
        derive.append((_name(item.get("name"), f"rows.derive[{k}].name", taken),
                       Expr(item.get("expr"), f"rows.derive[{k}].expr")))
    checks = []
    for k, item in enumerate(rows_raw.get("check", [])):
        _table(item, f"rows.check[{k}]", ("name", "expr"))
        checks.append((str(item.get("name", f"check {k + 1}")), Expr(item.get("expr"), f"rows.check[{k}].expr")))
    expect = {key: _int(value, f"expect.{key}", 0, 1 << 32)
              for key, value in _table(raw.get("expect", {}), "[expect]", COUNTS).items()}
    if "output" not in raw:
        raise ReplayError("spec", "[output] is missing: kind = \"witness\" or \"report\"")
    output = _parse_output(raw["output"], taken)
    vectors_raw = raw.get("vector", [])
    if not isinstance(vectors_raw, list):
        raise ReplayError("spec", "[[vector]] must be an array of tables")
    return Spec(
        source=source, capture_file=capture.get("file"), allow_damaged=capture.get("allow_damaged", False),
        scope=scope, pairing=pairing, registers=registers, initial_state=initial_state,
        unknown=_int(replay_raw["unknown"], "replay.unknown") if "unknown" in replay_raw else None,
        fc03_refresh=replay_raw.get("fc03_refresh", True), select=select,
        row_initial=_int_table(rows_raw.get("initial", {}), "rows.initial"),
        derive=tuple(derive), checks=tuple(checks), expect=expect, output=output,
        vectors=tuple(_parse_vector(item, k, output) for k, item in enumerate(vectors_raw)))


def load_spec(path: Path) -> Spec:
    try:
        raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReplayError("spec", f"cannot read {path}: {exc.strerror or exc}") from None
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ReplayError("spec", f"{path} is not valid TOML: {exc}") from None
    return parse_spec(raw, str(path))


# ----------------------------------------------------------------------------- 5. rows

def _public(row: Mapping[str, Any]) -> dict[str, int]:
    return {key: value for key, value in row.items() if not key.startswith("_")}


def select_rows(txns: list[Txn], adus: list[Adu], spec: Spec) -> tuple[list[dict], dict[str, int], list[dict]]:
    """The rows the spec selects, with counts and every discarded target (and why).

    A target is an accepted write of `select.function` that passes the structural filter (start,
    quantity, window). With a readback rule it is kept only when the next client ADU after its normal
    response is the exact read named, itself accepted, and not already claimed by an earlier write.
    `when` is evaluated on the register state just before (or after) the write's normal response."""
    sel = spec.select
    writes = [txn for txn in txns if txn.accepted and txn.function == sel.function]
    targets = [txn for txn in writes
               if (sel.start is None or txn.start in sel.start)
               and (sel.quantity is None or txn.quantity in sel.quantity)
               and (sel.window is None or (sel.window[0] <= txn.start and txn.start + txn.quantity - 1 <= sel.window[1]))]
    by_request = {txn.request.ordinal: txn for txn in txns}
    request_ordinals = sorted(by_request)
    claimed: dict[int, int] = {}
    rows: list[dict] = []
    discards: list[dict] = []
    unselected = 0
    for txn in sorted(targets, key=lambda row: row.response.ordinal):
        row: dict[str, Any] = {"tid": txn.request.tid, "unit": txn.request.unit, "function": txn.function,
                               "start": txn.start, "quantity": txn.quantity, "ordinal": txn.response.ordinal,
                               "packet": txn.response.packet}
        row.update({f"w{k}": word for k, word in enumerate(txn.words)})
        if sel.readback is not None:
            at = bisect.bisect_right(request_ordinals, txn.response.ordinal)
            read = by_request[request_ordinals[at]] if at < len(request_ordinals) else None
            why = _readback_problem(read, sel.readback, claimed)
            if why:
                discards.append({"tid": txn.request.tid, "packet": txn.response.packet, "reason": why})
                continue
            claimed[read.index] = txn.index
            row.update(zip(sel.readback.fields, read.words))
            row["rb_tid"] = read.request.tid
        state = txn.before if sel.state == "before" else txn.after
        for name, address in spec.registers.items():
            if address in state:
                row[name] = state[address]
            elif spec.unknown is not None:
                row[name] = spec.unknown
        if sel.when is not None:
            unknown = sorted(name for name in sel.when.names if name in spec.registers and name not in row)
            if unknown:
                raise ReplayError("register-unknown",
                                  f"{', '.join(unknown)} had no observed value {sel.state} the response of write tid "
                                  f"0x{txn.request.tid:04X} (packet {txn.response.packet}); give [replay] initial "
                                  "values, or [replay] unknown = <word> to assume one")
            if not sel.when.eval(row):
                unselected += 1
                continue
        row["_parts"] = {name: bytes(part(txn)) for name, part in PARTS.items()}
        row["_request_ordinal"] = txn.request.ordinal
        rows.append(row)
    if sel.order == "request":
        rows.sort(key=lambda row: row["_request_ordinal"])
    counts = {
        "adus": len(adus), "transactions": len(txns),
        "accepted": sum(txn.accepted for txn in txns),
        "exceptions": sum(txn.kind == "exception" for txn in txns),
        "unanswered": sum(txn.kind == "unanswered" for txn in txns),
        "rejected": sum(txn.kind == "rejected" or (txn.kind == "normal" and bool(txn.reason)) for txn in txns),
        "writes": len(writes), "targets": len(targets), "ineligible": len(writes) - len(targets),
        "discarded": len(discards), "unselected": unselected, "rows": len(rows),
    }
    return rows, counts, discards


def _readback_problem(read: Txn | None, rule: Readback, claimed: Mapping[int, int]) -> str:
    wanted = f"FC{rule.function:02d} start 0x{rule.start:04X} quantity {rule.quantity}"
    if read is None:
        return f"no client ADU follows the write's normal response (wanted {wanted})"
    if read.function != rule.function or read.start != rule.start or read.quantity != rule.quantity:
        return f"the next client ADU (tid 0x{read.request.tid:04X}) is not the readback {wanted}"
    if not read.accepted:
        return f"the readback tid 0x{read.request.tid:04X} was not confirmed ({read.reason or read.kind})"
    if read.index in claimed:
        return f"the readback tid 0x{read.request.tid:04X} already confirms an earlier write"
    return ""


def derive_rows(rows: list[dict], initial: Mapping[str, int], derive: tuple[tuple[str, Expr], ...],
                checks: tuple[tuple[str, Expr], ...] = ()) -> tuple[dict[str, int], list[str]]:
    """Number the rows (`i`), give each the previous row's fields as `prev_<name>` (row 0: the initial
    row), compute the derived columns in order and run the checks. Returns the initial row (its
    derived columns computed where they need no previous row) and the check failures."""
    first = dict(initial)
    for name, expr in derive:
        try:
            first[name] = expr.eval(first)
        except ReplayError as exc:
            if exc.reason != "undefined-name":
                raise
    failures: list[str] = []
    previous = first
    for i, row in enumerate(rows):
        row["i"] = i
        row.update({f"prev_{key}": value for key, value in _public(previous).items() if not key.startswith("prev_")})
        for name, expr in derive:
            row[name] = expr.eval(row)
        for name, expr in checks:
            if not expr.eval(row):
                failures.append(f"row {i} (tid 0x{row.get('tid', 0):04X}): check {name!r} is false: {expr.text}")
        previous = row
    return first, failures


# ----------------------------------------------------------------------------- 6. output

@dataclass(frozen=True)
class Built:
    material: bytes              # what is hashed: P || T for a witness, the report text for a report
    text: str | None             # the report text
    digest: str                  # hex of the whole digest
    value: str                   # the encoded (and truncated) answer, before the wrapper


def encode(blob: bytes, encoding: str) -> str:
    if encoding in ("hex", "hex-upper"):
        return blob.hex().upper() if encoding == "hex-upper" else blob.hex()
    base, _, nopad = encoding.partition("-")
    text = {"base32": base64.b32encode, "base64": base64.b64encode, "base64url": base64.urlsafe_b64encode}[base](blob)
    return text.decode("ascii").rstrip("=") if nopad else text.decode("ascii")


def build_output(rows: list[dict], initial: Mapping[str, int], output: Output) -> Built:
    """Serialise rows, hash, truncate, encode. The one code path for capture rows and vector rows."""
    text = None
    if output.kind == "witness":
        material = output.prefix + b"".join(row["_parts"][part] for row in rows for part in output.parts)
    else:
        scope: dict[str, int] = {"n": len(rows)}
        scope.update({f"init_{key}": value for key, value in _public(initial).items()})
        for agg in output.aggregates:
            if agg.kind == "count":
                scope[agg.name] = sum(1 for row in rows if agg.expr is None or agg.expr.eval(row))
            elif agg.kind == "sum":
                scope[agg.name] = sum(agg.expr.eval(row) for row in rows)
            else:
                if len(rows) > agg.width:
                    raise ReplayError("aggregate", f"bitmask {agg.name!r} is {agg.width} bits wide but there are "
                                                   f"{len(rows)} rows")
                scope[agg.name] = sum(1 << (agg.width - 1 - i if agg.first == "msb" else i)
                                      for i, row in enumerate(rows) if agg.expr.eval(row))
        lines = [line.render(scope) for line in output.header]
        if output.row is not None:
            lines += [output.row.render({**scope, **_public(row)}) for row in rows]
        lines += [line.render(scope) for line in output.footer]
        text = output.newline.join(lines) + (output.newline if output.final_newline else "")
        material = text.encode("utf-8")
    digest = material if output.hash == "none" else hashlib.new(output.hash, material).digest()
    if output.digest_bytes > len(digest):
        raise ReplayError("spec", f"output.digest_bytes {output.digest_bytes} is more than the {len(digest)}-byte digest")
    taken = digest[:output.digest_bytes] if output.digest_bytes else digest
    return Built(material=material, text=text, digest=digest.hex(), value=encode(taken, output.encoding))


def _flag_format(profile: Any = None):
    """The event's FlagFormat (the given profile, else the current event); a named error without one."""
    from ctf import flagfmt
    try:
        return flagfmt.for_profile(profile) if profile is not None else flagfmt.current()
    except Exception as exc:
        raise ReplayError("event", f"no event flag format ({type(exc).__name__}: {exc}); pass --event, or give "
                                   "output.wrap as text") from None


def wrap_value(value: str, wrap: str, profile: Any = None) -> str:
    if wrap == "none":
        return value
    if wrap != "event":
        return wrap.replace("{}", value)
    try:
        lead = _flag_format(profile).cribs()[0]
    except LookupError as exc:
        raise ReplayError("wrap", f'output.wrap = "event" but {exc}; give the wrapper as text with one {{}} where '
                                  "the value goes") from None
    if not lead.endswith("{"):      # the closing brace below only makes sense after an opening one
        raise ReplayError("wrap", f'output.wrap = "event" but the event\'s flag lead {lead!r} does not end in "{{"; '
                                  "give the wrapper as text with one {} where the value goes")
    return f"{lead}{value}}}"


# ----------------------------------------------------------------------------- 7. the known-answer gate

def run_vectors(spec: Spec) -> list[dict[str, Any]]:
    """Run every handout vector through derive_rows + build_output; one result per vector."""
    results = []
    for vector in spec.vectors:
        problems: list[str] = []
        covers = ["serialisation"]
        try:
            rows = [dict(row) for row in vector.rows]
            first, _ = derive_rows(rows, vector.initial if vector.initial is not None else spec.row_initial, spec.derive)
            built = build_output(rows, first, spec.output)
            if vector.expect_initial is not None:
                covers.append("derived columns")
                problems += [f"initial {key}: expected {want}, got {first.get(key)!r}"
                             for key, want in vector.expect_initial.items() if first.get(key) != want]
            if vector.expect_rows is not None:
                covers.append("derived columns")
                problems += [f"row {j} {key}: expected {want}, got {rows[j].get(key)!r}"
                             for j, wanted in enumerate(vector.expect_rows)
                             for key, want in wanted.items() if rows[j].get(key) != want]
            if vector.expect_text is not None and built.text != vector.expect_text:
                problems.append(f"text differs: expected {vector.expect_text!r}, got {built.text!r}")
            if vector.expect_digest is not None:
                covers.append("hash")
                if built.digest != vector.expect_digest:
                    problems.append(f"digest differs: expected {vector.expect_digest}, got {built.digest}")
            if vector.expect is not None:
                covers += ["hash", "encoding"]
                if built.value != vector.expect:
                    problems.append(f"value differs: expected {vector.expect}, got {built.value}")
        except ReplayError as exc:
            problems.append(str(exc))
        results.append({"name": vector.name, "passed": not problems, "problems": problems,
                        "covers": sorted(set(covers))})
    return results


def gate_reason(results: list[dict[str, Any]]) -> str:
    """'' when the gate is open; otherwise why nothing may be emitted."""
    if not results:
        return ("no-test-vector: the spec has no [[vector]]; copy the handout's test vector into it (or work one "
                "by hand from the prose) so the recipe is checked before anything is emitted")
    failed = [f"{row['name']}: {'; '.join(row['problems'])}" for row in results if not row["passed"]]
    if failed:
        return "vector-mismatch: " + " | ".join(failed)
    return ""


@dataclass
class Outcome:
    conversation: tuple
    counts: dict[str, int]
    rows: list[dict]
    discards: list[dict]
    txns: list[Txn]
    timeline: list[dict]
    findings: list[dict]
    vectors: list[dict]
    refusals: list[str]          # why nothing was emitted; empty when it was
    built: Built | None = None
    flag: str | None = None
    selection_checked: bool = False   # a selection [expect] count (SELECTION_COUNTS) or a row check was stated

    @property
    def emitted(self) -> bool:
        return self.built is not None


def run_spec(spec: Spec, data: bytes, profile: Any = None) -> Outcome:
    """Capture + spec -> Outcome. The value is built only when the gate is open and every row check
    and count expectation holds; otherwise `refusals` says why and `built` stays None."""
    adus, findings = capture_adus(data, server_port=spec.scope.server_port)
    scoped, conv = scope_adus(adus, spec.scope)
    findings = [row for row in findings if row.get("conversation") in (None, conv)]
    damage = [row for row in findings if row["kind"] in DAMAGE]
    if damage and not spec.allow_damaged:
        raise ReplayError("capture-damaged", "; ".join(f"{row['kind']}: {row['detail']}" for row in damage)
                          + " -- the replay would not be the whole conversation ([capture] allow_damaged = true "
                            "to go on anyway)")
    txns, pair_findings = pair(scoped, spec.pairing)
    timeline = replay(txns, initial=spec.initial_state, fc03_refresh=spec.fc03_refresh)
    rows, counts, discards = select_rows(txns, scoped, spec)
    first, check_failures = derive_rows(rows, spec.row_initial, spec.derive, spec.checks)
    refusals = list(check_failures)
    refusals += [f"expect.{key} = {want}, the capture gives {counts[key]}"
                 for key, want in spec.expect.items() if counts[key] != want]
    vectors = run_vectors(spec)
    gate = gate_reason(vectors)
    if gate:
        refusals.insert(0, gate)
    outcome = Outcome(conversation=conv, counts=counts, rows=rows, discards=discards, txns=txns, timeline=timeline,
                      findings=findings + pair_findings, vectors=vectors, refusals=refusals,
                      selection_checked=bool(spec.checks or set(spec.expect) & set(SELECTION_COUNTS)))
    if not refusals:
        outcome.built = build_output(rows, first, spec.output)
        outcome.flag = wrap_value(outcome.built.value, spec.output.wrap, profile)
    return outcome


# ----------------------------------------------------------------------------- 8. the engine contract

def find_captures(challenge_dir: Path) -> tuple[list[tuple[str, bytes]], list[str]]:
    """(captures, skipped). captures: (relative name, bytes) of every PCAP/PCAPNG of a challenge: the
    sweep's scratch copy (`unpacked/`) when there is one, else `files/`, else the folder; plus, when
    nothing was unpacked, capture members of zip handouts (`x.zip!member`). Identical bytes are listed
    once. skipped: "name (why)" for everything that may hold a capture but was not read: a zip that will
    not open, an encrypted or unreadable member, a capture over the size cap, a symlinked capture file."""
    challenge_dir = Path(challenge_dir)
    if not challenge_dir.is_dir():
        raise FileNotFoundError(f"no such challenge folder: {challenge_dir}")
    swept = (challenge_dir / "unpacked").is_dir()
    root = next((challenge_dir / name for name in ("unpacked", "files") if (challenge_dir / name).is_dir()), challenge_dir)
    out: list[tuple[str, bytes]] = []
    skipped: list[str] = []
    seen: set[bytes] = set()
    cap = _cap.MAX_CAPTURE

    def add(name: str, blob: bytes) -> None:
        digest = hashlib.sha256(blob).digest()
        if digest not in seen:
            seen.add(digest)
            out.append((name, blob))

    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = sorted(name for name in dirnames if name not in SKIP_DIRS and not (here / name).is_symlink())
        for name in sorted(filenames):
            path = here / name
            rel = str(path.relative_to(challenge_dir))
            if path.is_symlink():          # never followed out of the folder; named when it looks like a capture
                if name.lower().endswith(CAPTURE_SUFFIXES):
                    skipped.append(f"{rel} (a symlink, not followed)")
                continue
            if not path.is_file() or path.stat().st_size == 0:
                continue
            with open(path, "rb") as handle:
                head = handle.read(4)
            if head in PCAP_MAGICS:
                size = path.stat().st_size
                if size > cap:
                    skipped.append(f"{rel} (a capture of {size} bytes, over the {cap}-byte cap)")
                else:
                    add(rel, path.read_bytes())
            elif head == b"PK\x03\x04" and not swept:
                _zip_captures(path, rel, cap, add, skipped)
    return out, skipped


def _zip_captures(path: Path, rel: str, cap: int, add, skipped: list[str]) -> None:
    """Add the capture members of one zip handout; name every member (or the whole zip) not read."""
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError, NotImplementedError, ValueError) as exc:
        skipped.append(f"{rel} (the zip will not open: {type(exc).__name__}: {exc})")
        return
    with archive:
        for info in archive.infolist():
            if info.is_dir() or info.file_size == 0:
                continue
            member_name = f"{rel}!{info.filename}"
            if info.flag_bits & 0x1:
                skipped.append(f"{member_name} (an encrypted member: unzip it with the handout's password)")
                continue
            try:
                with archive.open(info) as member:
                    if member.read(4) not in PCAP_MAGICS:
                        continue
                if info.file_size > cap:
                    skipped.append(f"{member_name} (a capture of {info.file_size} bytes, over the {cap}-byte cap)")
                    continue
                add(member_name, archive.read(info))
            except (zipfile.BadZipFile, RuntimeError, OSError, NotImplementedError, EOFError, ValueError) as exc:
                skipped.append(f"{member_name} (the member is unreadable: {type(exc).__name__}: {exc})")


def summarise(data: bytes, *, server_port: int = 502) -> dict[str, Any]:
    """The no-spec pass over one capture: per conversation, pair (pending rule) and replay."""
    adus, findings = capture_adus(data, server_port=server_port)
    rows = []
    for conv in conversations(adus):
        scoped = [adu for adu in adus if adu.conversation == conv]
        txns, pair_findings = pair(scoped, "pending")
        timeline = replay(txns)
        functions: dict[str, int] = {}
        for txn in txns:
            if txn.accepted:
                functions[f"fc{txn.function:02d}"] = functions.get(f"fc{txn.function:02d}", 0) + 1
        rows.append({
            "conversation": conversation_text(conv), "units": sorted({adu.unit for adu in scoped}),
            "adus": len(scoped), "transactions": len(txns), "accepted": sum(txn.accepted for txn in txns),
            "accepted_by_function": dict(sorted(functions.items())),
            "exceptions": sum(txn.kind == "exception" for txn in txns),
            "unanswered": sum(txn.kind == "unanswered" for txn in txns),
            "rejected": sum(txn.kind == "rejected" or (txn.kind == "normal" and bool(txn.reason)) for txn in txns),
            "registers_seen": len(max(txns, key=lambda txn: txn.order).after) if txns else 0,
            "transactions_list": [txn_record(txn) for txn in txns[:MAX_LISTED]],
            "timeline": timeline[:MAX_LISTED],
            "findings": [_plain(row) for row in findings if row.get("conversation") == conv] + pair_findings,
        })
    return {"adus": len(adus), "conversations": rows}


def _plain(finding: dict[str, Any]) -> dict[str, Any]:
    out = dict(finding)
    if "conversation" in out:
        out["conversation"] = conversation_text(out["conversation"])
    return out


def txn_record(txn: Txn) -> dict[str, Any]:
    return {
        "index": txn.index, "tid": txn.request.tid, "unit": txn.request.unit, "function": txn.function,
        "kind": txn.kind, "accepted": txn.accepted, "reason": txn.reason, "start": txn.start,
        "quantity": txn.quantity, "words": list(txn.words), "request_packet": txn.request.packet,
        "response_packet": txn.response.packet if txn.response is not None else None,
        "request_pdu": txn.request.pdu.hex(), "response_pdu": txn.response.pdu.hex() if txn.response is not None else None,
    }


def _rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def _spec_path(challenge_dir: Path, opts: Mapping[str, Any]) -> Path | None:
    if opts.get("spec"):
        path = Path(str(opts["spec"]))
        return path if path.is_absolute() else challenge_dir / path
    return next((challenge_dir / name for name in SPEC_NAMES if (challenge_dir / name).is_file()), None)


def solve(challenge_dir: Path, profile=None, **opts):
    """Engine contract. opts: spec (path of the spec TOML; default <challenge>/modbus-replay.toml, then
    recon/modbus-replay.toml), out (folder for replay.json and the hashed material; default
    <challenge>/recon/modbus_replay).

    No spec: `unsure` with the pairing/replay facts of every Modbus capture (`none` when there is no
    Modbus; `blocked` when there is none in what was read but some of the handout -- an encrypted or
    broken zip, an oversized, symlinked or unparseable capture -- was not read). With a spec: `solved` when the
    known-answer gate is open and a stated selection check held, `candidate` when the gate is open but
    the spec states no selection [expect] count (SELECTION_COUNTS) and no row check (the selection itself
    is then untested), `unsure` with the refusal when the gate is shut or a check failed, `blocked` on a
    named spec or capture problem. Anything not read is listed in the notes whatever the status."""
    from ctf.result import Cost, Evidence, SolverResult
    t0 = time.monotonic()
    challenge_dir = Path(challenge_dir)
    out_dir = Path(str(opts["out"])) if opts.get("out") else challenge_dir / OUT_DIR

    def result(status: str, notes: str, flags=(), evidence=()):
        return SolverResult(status=status, flags=tuple(flags), evidence=tuple(evidence), engine=ENGINE,
                            cost=Cost(seconds=round(time.monotonic() - t0, 3)), notes=notes)

    spec_path = _spec_path(challenge_dir, opts)
    try:
        spec = load_spec(spec_path) if spec_path is not None else None
        server_port = spec.scope.server_port if spec is not None else 502
        found, not_read = find_captures(challenge_dir)
        captures, unreadable = [], list(not_read)
        for name, blob in found:
            try:
                adus, _ = capture_adus(blob, server_port=server_port)
            except (_cap.ParseError, ValueError) as exc:
                unreadable.append(f"{name} ({exc})")
                continue
            if adus:
                captures.append((name, blob))
    except ReplayError as exc:
        return result("blocked", str(exc))
    except FileNotFoundError as exc:
        return result("blocked", str(exc))
    skipped = f"; unreadable capture(s): {', '.join(unreadable)}" if unreadable else ""
    if not captures and unreadable:    # the capture may be in what could not be read: never claim "none"
        return result("blocked", f"unreadable-input: no Modbus/TCP ADU on server port {server_port} in what could be "
                                 f"read, but some of the handout was not read: {', '.join(unreadable)}")
    if not captures:
        return result("none", f"no Modbus/TCP ADU on server port {server_port} in the challenge's captures")

    if spec is None:
        evidence, report = [], {}
        for name, blob in captures:
            summary = report[name] = summarise(blob, server_port=server_port)
            for row in summary["conversations"]:
                evidence.append(Evidence(kind="wire", path=name, detail=(
                    f"{row['conversation']} unit(s) {row['units']}: {row['transactions']} transactions, "
                    f"{row['accepted']} accepted {row['accepted_by_function']}, {row['exceptions']} exception(s), "
                    f"{row['unanswered']} unanswered, {row['rejected']} rejected")))
        _write_json(out_dir / "replay.json", {"engine": ENGINE, "captures": report})
        return result("unsure", evidence=evidence, notes=(
            f"Modbus/TCP paired and replayed with no spec (transactions and the register timeline: "
            f"{out_dir / 'replay.json'}). The policy and output grammar are prose: write "
            f"{challenge_dir / SPEC_NAMES[0]} from the handout (templates in solvers/toolkits/"
            f"modbus_replay_templates/, reference docs/toolkits/modbus_replay.md), including the handout's test "
            f"vector, then run: python -m ctf run {ENGINE} {challenge_dir}{skipped}"))

    if spec.capture_file is not None:
        wanted = [(name, blob) for name, blob in captures
                  if name == spec.capture_file or re.split(r"[/!]", name)[-1] == spec.capture_file]
        if not wanted:
            return result("blocked", f"capture-missing: [capture] file = {spec.capture_file!r} is not among the Modbus "
                                     f"captures: {', '.join(name for name, _ in captures)}")
        captures = wanted
    if len(captures) > 1:
        return result("blocked", "ambiguous-capture: several captures hold Modbus; name one with [capture] file: "
                                 + ", ".join(name for name, _ in captures))
    name, blob = captures[0]
    try:
        outcome = run_spec(spec, blob, profile)
    except ReplayError as exc:
        return result("blocked", f"{exc} (spec {spec_path}, capture {name})")
    counts = outcome.counts
    payload = {
        "engine": ENGINE, "spec": str(spec_path), "capture": name,
        "conversation": conversation_text(outcome.conversation), "counts": counts,
        "rows": [{key: value for key, value in _public(row).items() if not key.startswith("prev_")}
                 for row in outcome.rows[:MAX_LISTED]],
        "discarded": outcome.discards,
        "vectors": outcome.vectors, "refusals": outcome.refusals, "emitted": outcome.emitted,
        "transactions": [txn_record(txn) for txn in outcome.txns[:MAX_LISTED]],
        "timeline": outcome.timeline[:MAX_LISTED], "findings": [_plain(row) for row in outcome.findings],
    }
    evidence = [Evidence(kind="wire", path=name, detail=(
        f"{conversation_text(outcome.conversation)}: {counts['transactions']} transactions, {counts['accepted']} "
        f"accepted, {counts['writes']} accepted FC{spec.select.function:02d} writes -> {counts['targets']} targets, "
        f"{counts['ineligible']} ineligible, {counts['discarded']} discarded, {counts['unselected']} not selected, "
        f"{counts['rows']} rows"))]
    material_name = "witness.bin" if spec.output.kind == "witness" else "report.txt"
    if not outcome.emitted:
        (out_dir / material_name).unlink(missing_ok=True)      # never leave an earlier run's output beside a refusal
        _write_json(out_dir / "replay.json", payload)
        return result("unsure", evidence=evidence, notes=(
            "nothing emitted: " + " || ".join(outcome.refusals) + f" (details: {out_dir / 'replay.json'}){skipped}"))
    payload.update(value=outcome.built.value, flag=outcome.flag, digest=outcome.built.digest)
    _write_json(out_dir / "replay.json", payload)
    (out_dir / material_name).write_bytes(outcome.built.material)
    passed = ", ".join(f"{row['name']} ({'/'.join(row['covers'])})" for row in outcome.vectors)
    evidence.append(Evidence(kind="oracle", detail=f"known-answer vector(s) reproduced: {passed}"))
    evidence.append(Evidence(kind="decode", path=_rel(out_dir / material_name, challenge_dir), detail=(
        f"{spec.output.hash} over {len(outcome.built.material)} byte(s) of {spec.output.kind} material, "
        f"{spec.output.encoding}{f' of the first {spec.output.digest_bytes} bytes' if spec.output.digest_bytes else ''}")))
    notes = [f"{counts['rows']} row(s) from {name}; hashed material in {out_dir / material_name}"]
    status = "solved"
    if not outcome.selection_checked:
        status = "candidate"
        notes.append("the vector tests the serialisation, not which transactions were selected, and the spec states "
                     f"no [expect] count of the selection ({', '.join(SELECTION_COUNTS)}) and no [[rows.check]]: "
                     "read the selection in replay.json before submitting")
    try:
        in_format = _flag_format(profile).is_flag(outcome.flag)
    except ReplayError as exc:      # no resolvable event: say so, never assume the format
        in_format = False
        notes.append(f"flag format not checked: {exc.detail}")
    if not in_format:
        status = "candidate"
        notes.append("the value as wrapped is not in the event's flag format: check output.wrap against the handout")
    return result(status, flags=[outcome.flag], evidence=evidence, notes="; ".join(notes) + skipped)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="modbus_replay.py", description=__doc__.split("\n\n")[0])
    parser.add_argument("challenge_dir", type=Path, help="a challenge folder (or any folder holding the capture)")
    parser.add_argument("--spec", help="the spec TOML (default: <folder>/modbus-replay.toml)")
    parser.add_argument("--out", help="output folder (default: <folder>/recon/modbus_replay)")
    parser.add_argument("--event", help="event slug (default: the current event)")
    args = parser.parse_args(argv)
    if not args.challenge_dir.is_dir():
        print(f"modbus_replay.py: no such folder: {args.challenge_dir}", file=sys.stderr)
        return 2
    profile = None
    if args.event:
        from ctf import event
        profile = event.load(args.event)
    opts = {key: value for key, value in (("spec", args.spec), ("out", args.out)) if value}
    res = solve(args.challenge_dir, profile, **opts)
    for item in res.evidence:
        print(f"[{item.kind}] {item.detail}")
    print(res.notes)
    print(res.to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
