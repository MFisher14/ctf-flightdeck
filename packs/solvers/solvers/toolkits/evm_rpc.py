#!/usr/bin/env python3
"""Read-only EVM JSON-RPC reader (B-243): chain state for a blockchain challenge that hands out a node URL.

OFF unless the event allows it. Two gates run in the constructor, before any socket is opened:

  1. the event profile says `rules.chain_rpc = "allowed"` (default "forbidden": no chain reads at all);
  2. the node URL passes `ctf.scope.check_url`: its host is in `rules.live_service_scope` (or a
     player-pointed service) and it is never the event platform.

A refusal raises RpcRefused (an ctf.scope.OutOfScope) naming the reason. Then only READ methods are sent:
`READ_METHODS` is an allowlist (eth_chainId, eth_getStorageAt, eth_getCode, eth_call, ...). Anything that
writes, signs, unlocks, mines or changes node state (eth_sendRawTransaction, eth_sign, personal_*,
anvil_* / hardhat_* / evm_* cheat codes, debug_*) is refused before the request is built. eth_call executes
contract code on the node against a state snapshot and commits nothing, so it counts as a read.

Transport: one HTTP(S) POST per call through http.client (no environment proxies), a timeout, no redirect
following (a 3xx is an error: a redirect could leave the scope), a response size cap, and the JSON-RPC
`id` checked. Nothing is retried. Nothing private is ever sent: there is no signing code here.

    from evm_rpc import RpcReader
    r = RpcReader("http://10.13.37.5:8545")             # gates run here
    r.chain_id(); r.get_code(addr); r.get_storage_at(addr, 0); r.call(to, data)

Engine (contract entry `solve`, docs/CONTRACTS.md sections 6-7):
    python -m ctf run toolkits.evm_rpc <challenge_dir> --opt url=http://NODE:8545 --opt address=0x... [--opt slots=32]
reads the contract's code and storage slots (following Solidity string slots, short and long) and
searches them for the event flag format.

CLI (prints JSON):
    python solvers/toolkits/evm_rpc.py URL storage ADDRESS SLOT [--block latest]
    python solvers/toolkits/evm_rpc.py URL code ADDRESS
    python solvers/toolkits/evm_rpc.py URL balance ADDRESS
    python solvers/toolkits/evm_rpc.py URL call TO DATA_HEX
    python solvers/toolkits/evm_rpc.py URL raw METHOD [JSON_PARAM ...]
A storage slot of a mapping entry comes from blockchain.storage_slot / nested_storage_slot (offline).
"""
from __future__ import annotations

import argparse
import http.client
import itertools
import json
import re
import sys
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
_REPO = HERE.parent.parent
if __name__ == "__main__" and sys.path and Path(sys.path[0] or ".").resolve() == HERE:
    sys.path.pop(0)
if str(_REPO) not in sys.path:
    sys.path.insert(1, str(_REPO))

from ctf import event as _event  # noqa: E402
from ctf import scope as _scope  # noqa: E402

MAX_RESPONSE = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 20.0

# The only methods this reader sends. Every one reads chain or node state and changes nothing.
READ_METHODS = frozenset({
    "eth_chainId", "net_version", "web3_clientVersion", "eth_blockNumber", "eth_gasPrice",
    "eth_getBalance", "eth_getCode", "eth_getStorageAt", "eth_getTransactionCount", "eth_call",
    "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getBlockByNumber", "eth_getBlockByHash",
    "eth_getLogs", "eth_getProof", "eth_estimateGas",
})
BLOCK_TAGS = ("latest", "earliest", "pending", "safe", "finalized")
_ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
_HASH = re.compile(r"0x[0-9a-fA-F]{64}")
_HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_QTY = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)")


class RpcRefused(_scope.OutOfScope):
    """The reader may not contact this node, or may not send this method. Raised before any connection."""


class RpcError(RuntimeError):
    """The node answered, but not with a usable JSON-RPC result (an error object, bad JSON, a wrong id,
    an HTTP error, a redirect, an oversize body)."""


def _profile(profile):
    """The profile the gates read, in ctf.scope's order (public API only): the one passed, else the one
    pinned with ctf.scope.pin, else ctf.event.current(). It is then passed explicitly to check_url, so
    both gates read the same profile."""
    if profile is not None:
        return profile
    pinned = _scope.pinned()
    if pinned is not None:
        return pinned
    try:
        return _event.current()
    except _event.EventError as exc:
        raise RpcRefused(f"no event profile, so no chain reads: {exc}") from None


def _block(block) -> str:
    if isinstance(block, bool):
        raise ValueError("block must be a tag or a non-negative int")
    if isinstance(block, int):
        if block < 0:
            raise ValueError("block number must be >= 0")
        return hex(block)
    if isinstance(block, str) and (block in BLOCK_TAGS or _QTY.fullmatch(block)):
        return block
    raise ValueError(f"block must be one of {', '.join(BLOCK_TAGS)}, an int or a 0x quantity, not {block!r}")


def _address(value) -> str:
    if not isinstance(value, str) or not _ADDR.fullmatch(value):
        raise ValueError(f"not a 0x-prefixed 20-byte address: {value!r}")
    return value


def _slot(value) -> str:
    if isinstance(value, bool):
        raise ValueError("slot must be an int, a 0x quantity or 32 bytes")
    if isinstance(value, int):
        if not 0 <= value < 1 << 256:
            raise ValueError("storage slot out of range")
        return hex(value)
    if isinstance(value, (bytes, bytearray)) and len(value) == 32:
        return "0x" + bytes(value).hex()
    if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{1,64}", value):
        return hex(int(value, 16))
    raise ValueError(f"storage slot must be an int, a 0x quantity or 32 bytes, not {value!r}")


def _hexbytes(value, what) -> bytes:
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        raise RpcError(f"{what}: the node returned {str(value)[:80]!r}, not 0x-prefixed hex bytes")
    return bytes.fromhex(value[2:])


def _quantity(value, what) -> int:
    if not isinstance(value, str) or not _QTY.fullmatch(value):
        raise RpcError(f"{what}: the node returned {str(value)[:80]!r}, not a 0x quantity")
    return int(value, 16)


class RpcReader:
    """A read-only JSON-RPC client for one node URL, admitted by the event profile (see the module doc)."""

    def __init__(self, url: str, *, profile: _event.EventProfile | None = None, timeout: float = DEFAULT_TIMEOUT,
                 max_response: int = MAX_RESPONSE):
        if not isinstance(url, str):
            raise RpcRefused("node URL must be text")
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise RpcRefused(f"node URL must be http(s)://host[:port][/path], not {url!r}")
        if parts.username or parts.password:
            raise RpcRefused("node URL must not carry credentials")
        prof = _profile(profile)
        if prof.rules.chain_rpc != "allowed":
            raise RpcRefused(f"event {prof.slug!r} does not allow chain reads (rules.chain_rpc = "
                             f"{prof.rules.chain_rpc!r}; the player sets it to \"allowed\" in event.toml)")
        _scope.check_url(url, what=f"EVM RPC node {url!r}", profile=prof, error=RpcRefused)
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("timeout must be > 0")
        self.url = url
        self._parts = parts
        self.timeout = float(timeout)
        self.max_response = int(max_response)
        self._ids = itertools.count(1)

    # ---- transport
    def _connection(self):
        p = self._parts
        cls = http.client.HTTPSConnection if p.scheme == "https" else http.client.HTTPConnection
        return cls(p.hostname, p.port, timeout=self.timeout)

    def request(self, method: str, params: list | None = None):
        """The `result` of one JSON-RPC call. Refuses a method outside READ_METHODS before connecting."""
        if method not in READ_METHODS:
            raise RpcRefused(f"{method!r} is not a read-only method this reader sends "
                             f"(allowed: {', '.join(sorted(READ_METHODS))})")
        params = [] if params is None else params
        if not isinstance(params, list):
            raise ValueError("params must be a list")
        rid = next(self._ids)
        body = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}).encode()
        path = self._parts.path or "/"
        if self._parts.query:
            path += "?" + self._parts.query
        conn = self._connection()
        try:
            conn.request("POST", path, body=body, headers={"Content-Type": "application/json",
                                                           "Accept": "application/json"})
            resp = conn.getresponse()
            if 300 <= resp.status < 400:
                raise RpcError(f"{method}: HTTP {resp.status} redirect not followed (it could leave the scope)")
            raw = resp.read(self.max_response + 1)
            if len(raw) > self.max_response:
                raise RpcError(f"{method}: response larger than {self.max_response} bytes")
            if resp.status != 200:
                raise RpcError(f"{method}: HTTP {resp.status}")
        except (OSError, http.client.HTTPException) as exc:
            raise RpcError(f"{method}: transport error: {exc}") from None
        finally:
            conn.close()
        try:
            doc = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise RpcError(f"{method}: the node did not return JSON") from None
        if not isinstance(doc, dict) or doc.get("id") != rid:
            raise RpcError(f"{method}: the response id does not match the request")
        if doc.get("error") is not None:
            err = doc["error"]
            msg = err.get("message") if isinstance(err, dict) else err
            raise RpcError(f"{method}: node error: {str(msg)[:200]}")
        if "result" not in doc:
            raise RpcError(f"{method}: no result in the response")
        return doc["result"]

    # ---- typed reads
    def chain_id(self) -> int:
        return _quantity(self.request("eth_chainId"), "eth_chainId")

    def block_number(self) -> int:
        return _quantity(self.request("eth_blockNumber"), "eth_blockNumber")

    def get_balance(self, address: str, block="latest") -> int:
        return _quantity(self.request("eth_getBalance", [_address(address), _block(block)]), "eth_getBalance")

    def get_transaction_count(self, address: str, block="latest") -> int:
        return _quantity(self.request("eth_getTransactionCount", [_address(address), _block(block)]),
                         "eth_getTransactionCount")

    def get_code(self, address: str, block="latest") -> bytes:
        return _hexbytes(self.request("eth_getCode", [_address(address), _block(block)]), "eth_getCode")

    def get_storage_at(self, address: str, slot, block="latest") -> bytes:
        """The 32-byte word at `slot` (left-padded: some nodes return a short quantity)."""
        raw = self.request("eth_getStorageAt", [_address(address), _slot(slot), _block(block)])
        if isinstance(raw, str) and re.fullmatch(r"0x[0-9a-fA-F]{1,64}", raw) and len(raw) % 2:
            raw = "0x0" + raw[2:]
        word = _hexbytes(raw, "eth_getStorageAt")
        if len(word) > 32:
            raise RpcError("eth_getStorageAt: the node returned more than 32 bytes")
        return word.rjust(32, b"\0")

    def call(self, to: str, data: bytes | str, block="latest", sender: str | None = None) -> bytes:
        """eth_call: run `data` against `to` on a state snapshot; nothing is committed or signed."""
        if isinstance(data, (bytes, bytearray)):
            data = "0x" + bytes(data).hex()
        if not isinstance(data, str) or not _HEX.fullmatch(data):
            raise ValueError("call data must be bytes or 0x-prefixed hex")
        tx = {"to": _address(to), "data": data}
        if sender is not None:
            tx["from"] = _address(sender)
        return _hexbytes(self.request("eth_call", [tx, _block(block)]), "eth_call")

    def get_transaction(self, tx_hash: str):
        if not isinstance(tx_hash, str) or not _HASH.fullmatch(tx_hash):
            raise ValueError("transaction hash must be 0x + 64 hex")
        return self.request("eth_getTransactionByHash", [tx_hash])

    def get_receipt(self, tx_hash: str):
        if not isinstance(tx_hash, str) or not _HASH.fullmatch(tx_hash):
            raise ValueError("transaction hash must be 0x + 64 hex")
        return self.request("eth_getTransactionReceipt", [tx_hash])


# ---------------------------------------------------------------------------- storage words -> text

def _keccak():
    """keccak-256 from the offline toolkit (pycryptodome), or None when no library provides it."""
    import importlib
    return importlib.import_module("solvers.toolkits.blockchain").keccak


def decode_storage_string(word: bytes):
    """How a Solidity `string`/`bytes` state variable sits in its own slot:
    ("short", data) for the inline form (data left-aligned, last byte = 2*len, len <= 31, the rest zero,
    the data's last byte non-zero),
    ("long", length) for the out-of-line form (the slot holds 2*len+1, the data starts at keccak(slot)),
    else None (the word is not a string slot, or it is ambiguous: an even word with junk past `len`)."""
    if not isinstance(word, (bytes, bytearray)) or len(word) != 32:
        return None
    v = int.from_bytes(word, "big")
    last = word[31]
    if last % 2 == 0:
        n = last // 2
        # a string's last byte is taken as non-zero: else every small even integer (42 = 0x2a) would read
        # as a string of NUL bytes
        if n == 0 or n > 31 or word[n - 1] == 0 or any(word[n:31]):
            return None
        return ("short", bytes(word[:n]))
    length = (v - 1) // 2
    if 32 <= length <= MAX_STRING_BYTES:
        return ("long", length)
    return None


MAX_STRING_BYTES = 4096
DEFAULT_SLOTS = 16
MAX_SLOTS = 256
ENGINE_ID = "toolkits.evm_rpc"
_SOLVE_OPTS = frozenset({"url", "address", "slots", "block", "timeout"})


def _slot_list(value):
    if value is None:
        return list(range(DEFAULT_SLOTS))
    if isinstance(value, bool):
        raise ValueError("slots must be an int count, or a list of slot numbers")
    if isinstance(value, int):
        if not 1 <= value <= MAX_SLOTS:
            raise ValueError(f"slots as a count must be 1..{MAX_SLOTS}")
        return list(range(value))
    if isinstance(value, list) and value and len(value) <= MAX_SLOTS:
        out = []
        for s in value:
            if isinstance(s, bool) or not isinstance(s, (int, str)):
                raise ValueError(f"slot {s!r} is not an int or a 0x quantity")
            out.append(int(_slot(s), 16))
        return list(dict.fromkeys(out))
    raise ValueError(f"slots must be a count 1..{MAX_SLOTS} or a non-empty list of at most {MAX_SLOTS} slots")


def read_contract_state(reader: "RpcReader", address: str, slots, block="latest") -> dict:
    """Read `address`'s code and the storage words at `slots`, following Solidity string slots.
    {"code": bytes, "words": {slot: bytes}, "strings": {slot: bytes}, "notes": [str]}. Every request goes
    through `reader`, so the profile and scope gates already ran."""
    address = _address(address)
    out = {"code": reader.get_code(address, block), "words": {}, "strings": {}, "notes": []}
    for slot in slots:
        word = reader.get_storage_at(address, slot, block)
        out["words"][slot] = word
        form = decode_storage_string(word)
        if form is None:
            continue
        if form[0] == "short":
            out["strings"][slot] = form[1]
            continue
        keccak = _keccak()
        base = keccak(slot.to_bytes(32, "big")) if keccak else None
        if base is None:
            out["notes"].append(f"slot {slot} looks like a long string of {form[1]} bytes, but keccak-256 is "
                                "unavailable (pycryptodome), so its data slots were not read")
            continue
        start = int.from_bytes(base, "big")
        data = b"".join(reader.get_storage_at(address, (start + i) % (1 << 256), block)
                        for i in range((form[1] + 31) // 32))
        out["strings"][slot] = data[:form[1]]
    return out


def solve(challenge_dir, profile=None, **opts):
    """Engine entry: read a deployed contract's storage over JSON-RPC and look for the flag.

    Options: ``url`` (the node, required), ``address`` (the contract, required), ``slots`` (a count from
    slot 0, default 16, or a list of slot numbers; at most 256), ``block`` (tag or number, default latest),
    ``timeout`` (seconds per request, default 20, at most 120). The event must say
    ``rules.chain_rpc = "allowed"`` and the node must be in ``rules.live_service_scope``: otherwise, and
    for a missing url/address or a node that does not answer, the result is ``blocked`` with the reason.
    One distinct flag in the storage words, the strings they hold or the runtime code is ``solved``,
    several ``candidate``; non-zero state with no flag is ``unsure`` (the words are the evidence), an empty
    account ``none``."""
    from ctf import flagfmt
    from ctf.result import Evidence, SolverResult

    unknown = sorted(set(opts) - _SOLVE_OPTS)
    if unknown:
        raise ValueError(f"evm_rpc: unknown option(s) {', '.join(unknown)}; known: {', '.join(sorted(_SOLVE_OPTS))}")
    url, address = opts.get("url"), opts.get("address")
    if not isinstance(url, str) or not url.strip() or not isinstance(address, str) or not address.strip():
        return SolverResult(status="blocked", engine=ENGINE_ID,
                            notes="no target: pass --opt url=<node URL> --opt address=<0x contract>; this engine "
                                  "never picks a node or a contract itself")
    timeout = opts.get("timeout", DEFAULT_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 120:
        raise ValueError("evm_rpc: timeout must be a number of seconds in (0, 120]")
    slots = _slot_list(opts.get("slots"))
    block = opts.get("block", "latest")
    _block(block)
    _address(address)
    try:
        reader = RpcReader(url, profile=profile, timeout=float(timeout))
        state = read_contract_state(reader, address, slots, block)
    except RpcRefused as exc:
        return SolverResult(status="blocked", engine=ENGINE_ID, notes=f"refused: {exc}")
    except RpcError as exc:
        return SolverResult(status="blocked", engine=ENGINE_ID, notes=f"the node did not answer usably: {exc}")

    flags: list[str] = []
    evidence: list[Evidence] = []

    def scan(data: bytes, where: str):
        for flag in flagfmt.find_flags_packed(data, profile):
            if flag not in flags:
                flags.append(flag)
                evidence.append(Evidence(kind="wire", detail=f"flag format in {where} of {address}"))

    for slot, text in state["strings"].items():
        scan(text, f"the string held at storage slot {slot}")
    for slot, word in state["words"].items():
        scan(word, f"storage slot {slot}")
    scan(state["code"], "the runtime code")
    nonzero = [(s, w) for s, w in state["words"].items() if any(w)]
    for slot, word in nonzero[:12]:
        text = state["strings"].get(slot)
        shown = f"string {text.decode('latin-1')[:200]!r}" if text is not None else "0x" + word.hex()
        evidence.append(Evidence(kind="wire", detail=f"storage slot {slot}: {shown}"))
    notes = [f"read {len(slots)} storage slot(s) and {len(state['code'])} bytes of code of {address} at {block}"]
    notes += state["notes"]
    if flags:
        status = "solved" if len(flags) == 1 else "candidate"
    else:
        status = "unsure" if nonzero or state["code"] else "none"
    return SolverResult(status=status, flags=tuple(flags), evidence=tuple(evidence), engine=ENGINE_ID,
                        notes="; ".join(notes))


# ---------------------------------------------------------------------------- CLI

class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def _json_param(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return text


def main(argv=None) -> int:
    p = _Parser(prog="evm_rpc", description="read-only EVM JSON-RPC (needs rules.chain_rpc = allowed)")
    p.add_argument("url")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--block", default="latest")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("storage"); s.add_argument("address"); s.add_argument("slot")
    s = sub.add_parser("code"); s.add_argument("address")
    s = sub.add_parser("balance"); s.add_argument("address")
    s = sub.add_parser("call"); s.add_argument("to"); s.add_argument("data")
    s = sub.add_parser("raw"); s.add_argument("method"); s.add_argument("params", nargs="*")
    try:
        a = p.parse_args(argv)
        block = int(a.block) if a.block.isdigit() else a.block
        r = RpcReader(a.url, timeout=a.timeout)
        if a.cmd == "storage":
            slot = int(a.slot) if a.slot.isdigit() else a.slot
            word = r.get_storage_at(a.address, slot, block)
            out = {"slot": _slot(slot), "word": "0x" + word.hex(), "uint": int.from_bytes(word, "big"),
                   "ascii": word.rstrip(b"\0").decode("latin-1") if word.rstrip(b"\0").isascii() else None}
        elif a.cmd == "code":
            code = r.get_code(a.address, block)
            out = {"address": a.address, "code": "0x" + code.hex(), "length": len(code)}
        elif a.cmd == "balance":
            out = {"address": a.address, "wei": r.get_balance(a.address, block)}
        elif a.cmd == "call":
            out = {"to": a.to, "result": "0x" + r.call(a.to, a.data, block).hex()}
        else:
            out = {"method": a.method, "result": r.request(a.method, [_json_param(x) for x in a.params])}
    except RpcRefused as exc:
        print(f"evm_rpc: refused: {exc}", file=sys.stderr)
        return 3
    except (RpcError, ValueError) as exc:
        print(f"evm_rpc: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
