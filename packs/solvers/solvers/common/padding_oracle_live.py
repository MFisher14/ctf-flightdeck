#!/usr/bin/env python3
"""Live, scope-locked, query-budgeted padding-oracle client for crypto_oracles' attacks (B-244).

crypto_oracles.py holds the attacks (CBC PKCS#7 decrypt/encrypt, Bleichenbacher, Manger, RSA LSB) and
takes a ``check(ciphertext) -> bool`` callback; it has no transport by design. This module is that
callback for a challenge service:

* **Scope lock.** The target's host and port pass ``ctf.scope.check_host`` (the event profile's
  rules.live_service_scope, never the platform) in the constructor, before any name is resolved or
  any socket opened.
* **Per-challenge query budget.** ``QueryBudget`` keeps the count in
  ``<workdir>/oracle/<challenge>.json`` under a file lock, so the budget holds across processes and
  restarts: a second run continues the first run's count. The limit is fixed when the budget is first
  opened; changing it needs ``extend=True`` (``--extend`` on the command line, a human decision) and
  is recorded in the event ledger (``oracle.budget``). A query over the limit raises
  ``OracleLimitError`` before anything is sent.
* **Strict verdicts.** A spec names what a *valid* answer looks like (status codes and/or a body
  regex) and, optionally, what an *invalid* one looks like. With both, an answer matching neither is
  an ``OracleProtocolError`` (an error page is never read as "bad padding"). Transport failures raise.
  A spec with only a valid rule reads every other answer as invalid: the CLI warns about that on
  stderr, and the ``oracle.open`` ledger record says ``verdicts = "valid-only"`` (else "strict").

A spec (TOML or JSON):

    kind = "http"                         # or "tcp"
    url = "http://chal.x.example:8080/"   # http: scheme, host, port; tcp: host = ..., port = ...
    method = "GET"                        # http
    path = "/decrypt?c={ct_hex}"          # http: path and query template
    body = ""                             # http: body template (POST)
    headers = {Content-Type = "..."}      # http: header templates; values are never logged
    send = "{ct_hex}\\n"                  # tcp: what is sent per query
    banner_until = "> "                   # tcp: read up to this before the first query (optional)
    reply_until = "\\n"                   # tcp: one answer ends here
    persistent = true                     # keep one connection (tcp and http)
    valid_status = [200]                  # verdict rules: any of these may be given
    valid_regex = "OK"
    invalid_status = [500]
    invalid_regex = "padding"
    timeout = 10.0
    min_interval = 0.0                    # seconds between queries (politeness)

Placeholders: {ct_hex} {ct_HEX} {ct_b64} {ct_b64url} {ct_int} (the ciphertext in that encoding).

    padding_oracle_live.py run --spec S --challenge ID --attack cbc-decrypt --ciphertext HEX [--max-queries N]
    padding_oracle_live.py probe --spec S --challenge ID --ciphertext HEX      one query, its verdict
    padding_oracle_live.py status --challenge ID                               the budget in force
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import http.client
import json
import os
import re
import socket
import sys
import time
import tomllib
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

try:
    from ctf import ledger as _ledger, paths as _paths, scope as _scope
except ModuleNotFoundError:                 # a script run: put the checkout root on sys.path
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import ledger as _ledger, paths as _paths, scope as _scope

import crypto_oracles as co

MAX_REPLY = 1 << 20
MAX_LIMIT = co.MAX_QUERIES
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ATTACKS = ("cbc-decrypt", "cbc-encrypt", "bleichenbacher", "manger", "rsa-lsb")
VALID_ONLY_WARNING = ("padding_oracle_live: warning: the spec has no invalid rule (invalid_status / "
                      "invalid_regex): every answer that is not valid, a 429, a 502 or a rate-limit page "
                      "included, is read as invalid padding. Add an invalid rule so such answers raise.")


class OracleTransportError(co.OracleError):
    """The target could not be reached or answered outside the protocol (a closed socket, a timeout)."""


class BudgetError(co.OracleError):
    """The per-challenge budget is unset, or a different limit was asked for without extend."""


# ---- the persistent per-challenge budget ---------------------------------------------------------------

class QueryBudget:
    """A query counter shared by every process working one challenge. ``take()`` reserves one query
    (or raises OracleLimitError); the count survives restarts."""

    def __init__(self, challenge_id: str, *, limit: int | None = None, workdir: Path | None = None,
                 extend: bool = False, by: str | None = None):
        if not isinstance(challenge_id, str) or not _ID_RE.match(challenge_id):
            raise ValueError(f"challenge id {challenge_id!r} must be 1-128 of [A-Za-z0-9._-]")
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int)
                                  or not 0 < limit <= MAX_LIMIT):
            raise ValueError(f"max queries must be in 1..{MAX_LIMIT}")
        self.challenge_id = challenge_id
        self.workdir = Path(workdir) if workdir is not None else _paths.workdir()
        self.path = self.workdir / "oracle" / f"{challenge_id}.json"
        with self._locked() as state:
            if state is None:
                if limit is None:
                    raise BudgetError(f"no oracle query budget for challenge {challenge_id!r}: pass "
                                      f"--max-queries N the first time (it is then kept in {self.path})")
                state = {"challenge_id": challenge_id, "limit": limit, "used": 0}
                self._write(state)
                _ledger.append("oracle.budget", workdir=self.workdir, challenge_id=challenge_id,
                               limit=limit, used=0, action="set")
            elif limit is not None and limit != state["limit"]:
                if not extend:
                    raise BudgetError(f"challenge {challenge_id!r} already has an oracle budget of "
                                      f"{state['limit']} ({state['used']} used); changing it to {limit} "
                                      f"needs --extend (a human decision)")
                _ledger.append("oracle.budget", workdir=self.workdir, challenge_id=challenge_id,
                               limit=limit, used=state["used"], action="extend", previous=state["limit"],
                               by=by or "unknown")
                state["limit"] = limit
                self._write(state)
            self.limit, self.used = state["limit"], state["used"]

    # The state file is rewritten whole under an exclusive flock on a sibling lock file.
    class _Lock:
        def __init__(self, owner: "QueryBudget"):
            self.owner = owner

        def __enter__(self):
            self.owner.path.parent.mkdir(parents=True, exist_ok=True)
            self.fd = os.open(str(self.owner.path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(self.fd, fcntl.LOCK_EX)
            return self.owner._read()

        def __exit__(self, *exc):
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)

    def _locked(self):
        return QueryBudget._Lock(self)

    def _read(self) -> dict | None:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        state = json.loads(raw)
        if (not isinstance(state, dict) or state.get("challenge_id") != self.challenge_id
                or not isinstance(state.get("limit"), int) or not isinstance(state.get("used"), int)):
            raise BudgetError(f"{self.path} is not a budget file for {self.challenge_id!r}; refusing to guess")
        return state

    def _write(self, state: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)

    def take(self) -> int:
        """Reserve one query; returns the new used count. Raises OracleLimitError at the limit."""
        with self._locked() as state:
            if state is None:
                raise BudgetError(f"budget file {self.path} disappeared")
            self.limit = state["limit"]
            if state["used"] >= state["limit"]:
                self.used = state["used"]
                raise co.OracleLimitError(f"challenge {self.challenge_id!r}: oracle query budget of "
                                          f"{state['limit']} is used up ({self.path})")
            state["used"] += 1
            self._write(state)
            self.used = state["used"]
            return self.used

    @property
    def remaining(self) -> int:
        with self._locked() as state:
            return 0 if state is None else max(0, state["limit"] - state["used"])

    @staticmethod
    def peek(challenge_id: str, workdir: Path | None = None) -> dict | None:
        if not isinstance(challenge_id, str) or not _ID_RE.match(challenge_id):
            raise ValueError(f"challenge id {challenge_id!r} must be 1-128 of [A-Za-z0-9._-]")
        wd = Path(workdir) if workdir is not None else _paths.workdir()
        p = wd / "oracle" / f"{challenge_id}.json"
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None


# ---- the spec --------------------------------------------------------------------------------------------

@dataclass
class OracleSpec:
    kind: str
    host: str
    port: int
    scheme: str = "http"
    method: str = "GET"
    path: str = "/"
    body: str = ""
    headers: dict = field(default_factory=dict)
    send: str = "{ct_hex}\n"
    banner_until: str = ""
    reply_until: str = "\n"
    persistent: bool = True
    valid_status: tuple = ()
    valid_regex: str | None = None
    invalid_status: tuple = ()
    invalid_regex: str | None = None
    timeout: float = 10.0
    min_interval: float = 0.0

    @classmethod
    def from_dict(cls, raw: dict) -> "OracleSpec":
        if not isinstance(raw, dict):
            raise ValueError("an oracle spec is a table")
        known = {f for f in cls.__dataclass_fields__} | {"url"}
        extra = sorted(set(raw) - known)
        if extra:
            raise ValueError(f"unknown spec keys: {', '.join(extra)}")
        kind = raw.get("kind")
        if kind not in ("http", "tcp"):
            raise ValueError("spec kind must be 'http' or 'tcp'")
        kw = {k: v for k, v in raw.items() if k != "url"}
        if kind == "http":
            url = raw.get("url")
            if not isinstance(url, str):
                raise ValueError("an http spec needs url = 'http(s)://host:port/'")
            parts = urllib.parse.urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValueError(f"bad http url {url!r}")
            kw.update(scheme=parts.scheme, host=parts.hostname,
                      port=parts.port or (443 if parts.scheme == "https" else 80))
            if "path" not in raw and parts.path:
                kw["path"] = parts.path + (("?" + parts.query) if parts.query else "")
        else:
            if not isinstance(raw.get("host"), str) or not isinstance(raw.get("port"), int):
                raise ValueError("a tcp spec needs host and port")
        for key in ("valid_status", "invalid_status"):
            if key in kw:
                vals = kw[key]
                if not isinstance(vals, list) or not all(isinstance(v, int) for v in vals):
                    raise ValueError(f"{key} must be a list of integers")
                kw[key] = tuple(vals)
        spec = cls(**kw)
        if not 0 < int(spec.port) < 65536:
            raise ValueError("port must be 1..65535")
        if not (spec.valid_status or spec.valid_regex):
            raise ValueError("a spec needs a validity rule (valid_status and/or valid_regex)")
        if kind == "tcp" and (spec.valid_status or spec.invalid_status):
            raise ValueError("status rules apply to http specs only")
        for rx in (spec.valid_regex, spec.invalid_regex):
            if rx is not None:
                re.compile(rx)
        if not 0 < float(spec.timeout) <= 300 or not 0 <= float(spec.min_interval) <= 60:
            raise ValueError("timeout must be in (0, 300] and min_interval in [0, 60]")
        return spec

    @property
    def strict(self) -> bool:
        """True when the spec also says what an *invalid* answer looks like. Without that rule every
        answer that is not valid (a 429, a 502, a rate-limit page) is read as "invalid padding"."""
        return bool(self.invalid_status) or self.invalid_regex is not None

    @classmethod
    def load(cls, path: Path) -> "OracleSpec":
        path = Path(path)
        text = path.read_text(encoding="utf-8")
        raw = json.loads(text) if path.suffix == ".json" else tomllib.loads(text)
        return cls.from_dict(raw)


def render(template: str, ct: bytes) -> str:
    values = {"ct_hex": ct.hex(), "ct_HEX": ct.hex().upper(), "ct_b64": base64.b64encode(ct).decode(),
              "ct_b64url": base64.urlsafe_b64encode(ct).decode().rstrip("="),
              "ct_int": str(int.from_bytes(ct, "big"))}
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError) as exc:
        raise ValueError(f"bad placeholder in template {template!r}: {exc}") from None


# ---- the client ------------------------------------------------------------------------------------------

class OutOfScope(_scope.OutOfScope):
    """The oracle target is outside the event's live-service scope."""


class LiveOracle:
    """``oracle(ciphertext) -> bool``: one budgeted query to the in-scope target.

    RSA attacks hand ints when called with ``oracle_input="int"``; bytes are the default. An int is
    sent as its minimal big-endian bytes unless ``int_width`` is set (the modulus size)."""

    def __init__(self, spec: OracleSpec, budget: QueryBudget, *, profile=None, int_width: int | None = None):
        _scope.check_host(spec.host, spec.port, what=f"padding-oracle target {spec.host}:{spec.port}",
                          profile=profile, error=OutOfScope)
        self.spec, self.budget, self.int_width = spec, budget, int_width
        self.queries = 0
        self.verdicts = {True: 0, False: 0}
        self._conn = None
        self._sock = None
        self._buf = b""
        self._last = 0.0
        self._opened = False

    # transport -----------------------------------------------------------------------------------------
    def _pace(self) -> None:
        if self.spec.min_interval:
            wait = self.spec.min_interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
        self._last = time.monotonic()

    def _http(self, ct: bytes) -> tuple[int, bytes]:
        s = self.spec
        if self._conn is None:
            cls = http.client.HTTPSConnection if s.scheme == "https" else http.client.HTTPConnection
            self._conn = cls(s.host, s.port, timeout=s.timeout)
        headers = {k: render(str(v), ct) for k, v in s.headers.items()}
        body = render(s.body, ct).encode() if s.body else None
        try:
            self._conn.request(s.method, render(s.path, ct), body=body, headers=headers)
            resp = self._conn.getresponse()
            data = resp.read(MAX_REPLY + 1)
        except (OSError, http.client.HTTPException) as exc:
            self._close_transport()
            raise OracleTransportError(f"http query to {s.host}:{s.port} failed: {type(exc).__name__}: {exc}") from exc
        if len(data) > MAX_REPLY:
            # the rest of the body is still unread: this connection cannot carry another request
            self._close_transport()
            raise OracleTransportError("reply over 1 MiB")
        if not s.persistent or resp.getheader("Connection", "").lower() == "close":
            self._close_transport()
        return resp.status, data

    def _recv_until(self, marker: bytes) -> bytes:
        while marker not in self._buf:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise OracleTransportError("the target closed the connection mid-answer")
            self._buf += chunk
            if len(self._buf) > MAX_REPLY:
                raise OracleTransportError("reply over 1 MiB without the end marker")
        head, _, self._buf = self._buf.partition(marker)
        return head

    def _tcp(self, ct: bytes) -> tuple[int, bytes]:
        s = self.spec
        try:
            if self._sock is None:
                self._sock = socket.create_connection((s.host, s.port), timeout=s.timeout)
                # one small request per answer: Nagle would hold each query back for the last ACK
                self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self._buf = b""
                if s.banner_until:
                    self._recv_until(s.banner_until.encode())
            self._sock.sendall(render(s.send, ct).encode())
            reply = self._recv_until(s.reply_until.encode())
        except OracleTransportError:
            # an oversized or cut-off answer leaves unread bytes on the socket and in _buf: keeping
            # either would hand the next query the tail of this one's answer
            self._close_transport()
            raise
        except OSError as exc:
            self._close_transport()
            raise OracleTransportError(f"tcp query to {s.host}:{s.port} failed: {type(exc).__name__}: {exc}") from exc
        if not s.persistent:
            self._close_transport()
        return 0, reply

    def _close_transport(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
                self._buf = b""

    # verdict -------------------------------------------------------------------------------------------
    def verdict(self, status: int, body: bytes) -> bool:
        s = self.spec
        text = body.decode("latin-1")

        def matches(statuses, regex):
            if not statuses and regex is None:
                return False
            ok_status = (not statuses) or status in statuses
            ok_regex = regex is None or re.search(regex, text) is not None
            return ok_status and ok_regex

        if matches(s.valid_status, s.valid_regex):
            return True
        if s.invalid_status or s.invalid_regex is not None:
            if matches(s.invalid_status, s.invalid_regex):
                return False
            raise co.OracleProtocolError(f"the target's answer matches neither the valid nor the invalid "
                                         f"rule (status {status}, {len(body)} bytes): not read as a verdict")
        return False

    def __call__(self, ciphertext) -> bool:
        if isinstance(ciphertext, int) and not isinstance(ciphertext, bool):
            width = self.int_width or max(1, (ciphertext.bit_length() + 7) // 8)
            ct = ciphertext.to_bytes(width, "big")
        elif isinstance(ciphertext, (bytes, bytearray)):
            ct = bytes(ciphertext)
        else:
            raise TypeError("the oracle takes bytes or an int")
        if not self._opened:
            self._opened = True
            _ledger.append("oracle.open", workdir=self.budget.workdir, challenge_id=self.budget.challenge_id,
                           target=f"{self.spec.host}:{self.spec.port}", kind=self.spec.kind,
                           verdicts="strict" if self.spec.strict else "valid-only",
                           limit=self.budget.limit, used=self.budget.used)
        self.budget.take()                  # raises at the limit, before anything is sent
        self.queries += 1
        self._pace()
        status, body = self._http(ct) if self.spec.kind == "http" else self._tcp(ct)
        answer = self.verdict(status, body)
        self.verdicts[answer] += 1
        return answer

    def close(self) -> None:
        self._close_transport()
        if self._opened:
            _ledger.append("oracle.close", workdir=self.budget.workdir, challenge_id=self.budget.challenge_id,
                           target=f"{self.spec.host}:{self.spec.port}", queries=self.queries,
                           used=self.budget.used, limit=self.budget.limit)
            self._opened = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---- attacks over the live oracle -----------------------------------------------------------------------

def run_attack(oracle: LiveOracle, attack: str, *, ciphertext: bytes = b"", iv: bytes | None = None,
               block_size: int = 16, plaintext: bytes = b"", n: int | None = None, e: int | None = None,
               label: bytes = b"", hash_name: str = "sha1") -> dict:
    """Run one crypto_oracles attack through `oracle`; the attack's own budget is the remaining
    per-challenge budget. Returns {"attack", "result_hex", "verified", "queries"}."""
    if attack not in ATTACKS:
        raise ValueError(f"attack must be one of {ATTACKS}")
    remaining = oracle.budget.remaining
    if remaining < 1:
        raise co.OracleLimitError(f"challenge {oracle.budget.challenge_id!r}: oracle budget used up")
    if attack == "cbc-decrypt":
        out = co.cbc_padding_oracle_decrypt(ciphertext, oracle, iv=iv, block_size=block_size,
                                            max_queries=remaining)
        verified = "pkcs7-unpadded"
    elif attack == "cbc-encrypt":
        out = co.cbc_padding_oracle_encrypt(plaintext, oracle, block_size=block_size, max_queries=remaining)
        verified = "built-from-oracle"
    else:
        if n is None or e is None:
            raise ValueError(f"{attack} needs --n and --e")
        oracle.int_width = (n.bit_length() + 7) // 8
        if attack == "bleichenbacher":
            out = co.bleichenbacher_pkcs1_v1_5_recover(ciphertext, n, e, oracle, max_queries=remaining)
        elif attack == "manger":
            out = co.manger_oaep_recover(ciphertext, n, e, oracle, label=label, hash_name=hash_name,
                                         max_queries=remaining)
        else:
            val = co.rsa_parity_oracle_recover(ciphertext, n, e, oracle, max_queries=remaining)
            out = None if val is None else val.to_bytes(oracle.int_width, "big")
        verified = "re-encrypts" if out is not None else False
    return {"attack": attack, "result_hex": None if out is None else out.hex(), "verified": verified,
            "queries": oracle.queries, "budget_used": oracle.budget.used, "budget_limit": oracle.budget.limit}


# ---- CLI -------------------------------------------------------------------------------------------------

class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ValueError(message)


def _hex(text: str | None) -> bytes:
    if text is None:
        return b""
    try:
        return bytes.fromhex(text.strip())
    except ValueError:
        raise ValueError("expected even-length hex") from None


def _int(text: str | None) -> int | None:
    if text is None:
        return None
    t = text.strip()
    return int(t, 16) if t.lower().startswith("0x") else int(t)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="padding_oracle_live.py")
    sub = parser.add_subparsers(dest="op", required=True)
    for name in ("run", "probe"):
        sp = sub.add_parser(name)
        sp.add_argument("--spec", required=True)
        sp.add_argument("--challenge", required=True)
        sp.add_argument("--ciphertext", help="hex")
        sp.add_argument("--max-queries", type=int)
        sp.add_argument("--extend", action="store_true", help="change an existing budget (a human decision)")
        sp.add_argument("--by", help="who extended it (recorded in the ledger)")
        if name == "run":
            sp.add_argument("--attack", required=True, choices=ATTACKS)
            sp.add_argument("--iv", help="hex (cbc-decrypt; else the ciphertext starts with the IV)")
            sp.add_argument("--block-size", type=int, default=16)
            sp.add_argument("--plaintext", help="hex (cbc-encrypt)")
            sp.add_argument("--n")
            sp.add_argument("--e")
            sp.add_argument("--label", default="", help="hex OAEP label (manger)")
            sp.add_argument("--hash", default="sha1")
    st = sub.add_parser("status")
    st.add_argument("--challenge", required=True)
    try:
        args = parser.parse_args(argv)
        if args.op == "status":
            state = QueryBudget.peek(args.challenge)
            print(json.dumps(state or {"challenge_id": args.challenge, "budget": None}, sort_keys=True))
            return 0 if state else 1
        spec = OracleSpec.load(Path(args.spec))
        if not spec.strict:
            print(VALID_ONLY_WARNING, file=sys.stderr)
        budget = QueryBudget(args.challenge, limit=args.max_queries, extend=args.extend, by=args.by)
        with LiveOracle(spec, budget) as oracle:
            if args.op == "probe":
                if not args.ciphertext:
                    raise ValueError("probe needs --ciphertext")
                answer = oracle(_hex(args.ciphertext))
                print(json.dumps({"valid": answer, "budget_used": budget.used, "budget_limit": budget.limit}))
                return 0
            out = run_attack(oracle, args.attack, ciphertext=_hex(args.ciphertext), iv=_hex(args.iv) or None,
                             block_size=args.block_size, plaintext=_hex(args.plaintext), n=_int(args.n),
                             e=_int(args.e), label=_hex(args.label), hash_name=args.hash)
        print(json.dumps(out, sort_keys=True))
        return 0 if out["result_hex"] is not None else 1
    except _scope.OutOfScope as exc:
        print(f"padding_oracle_live: refused: {exc}", file=sys.stderr)
        return 4
    except co.OracleLimitError as exc:
        print(f"padding_oracle_live: budget: {exc}", file=sys.stderr)
        return 5
    except (co.OracleError, OSError, ValueError, TypeError, tomllib.TOMLDecodeError) as exc:
        print(f"padding_oracle_live: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
