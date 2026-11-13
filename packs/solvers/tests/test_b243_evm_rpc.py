"""B-243: the read-only EVM JSON-RPC reader (solvers/toolkits/evm_rpc.py) and the rules.chain_rpc profile key.

Every live call goes to a fake JSON-RPC node this test starts on 127.0.0.1; the fake records what reached
it, so a refusal is proven to happen before any request.
"""
import datetime as dt
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from eth_hash.auto import keccak as eth_keccak

import evm_rpc
from ctf import event, eventscaffold, paths, scope
from ctf.engines import manifest
from ctf.result import SolverResult


def _profile(chain_rpc="allowed", live_scope=("127.0.0.0/8",)):
    rules = {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
             "live_service_scope": list(live_scope)}
    if chain_rpc is not None:
        rules["chain_rpc"] = chain_rpc
    return event.parse({
        "slug": "rpc-test", "name": "rpc test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.rpc-platform.test"},
        "flag": {"prefixes": []}, "rules": rules}, src="tests/test_b243_evm_rpc.py")


STORAGE = {0: "0x" + "00" * 31 + "2a", 1: "0x" + b"s3cr3t pa55word".ljust(32, b"\0").hex()}
CODE = "0x6080604052"


class _Node(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        req = json.loads(body)
        self.seen.append((self.path, req))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://203.0.113.9/")
            self.end_headers()
            return
        if self.path == "/big":
            out = json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": "0x" + "00" * 4096}).encode()
        elif self.path == "/wrong-id":
            out = json.dumps({"jsonrpc": "2.0", "id": req["id"] + 1, "result": "0x1"}).encode()
        elif self.path == "/error":
            out = json.dumps({"jsonrpc": "2.0", "id": req["id"],
                              "error": {"code": -32000, "message": "execution reverted"}}).encode()
        elif self.path == "/short-word":
            out = json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": "0x2a"}).encode()
        else:
            m, p = req["method"], req["params"]
            if m == "eth_chainId":
                res = "0x7a69"
            elif m == "eth_getStorageAt":
                res = STORAGE.get(int(p[1], 16), "0x" + "00" * 32)
            elif m == "eth_getCode":
                res = CODE
            elif m == "eth_getBalance":
                res = "0xde0b6b3a7640000"
            elif m == "eth_call":
                res = "0x" + "00" * 31 + "01"
            else:
                res = None
            out = json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": res}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


@pytest.fixture
def node():
    _Node.seen = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Node)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", _Node.seen
    finally:
        srv.shutdown()
        srv.server_close()


ADDR = "0x" + "12" * 20


def test_profile_key_defaults_to_forbidden_and_is_validated():
    assert _profile(chain_rpc=None).rules.chain_rpc == "forbidden"
    assert _profile("allowed").rules.chain_rpc == "allowed"
    with pytest.raises(event.EventError, match="chain_rpc"):
        _profile("sometimes")
    data = eventscaffold.profile_data(slug="x-ctf", name="X", start=dt.date(2026, 1, 1), end=dt.date(2026, 1, 2),
                                      kind="manual", submit_mode="manual", ai_on_platform="allowed")
    assert data["rules"]["chain_rpc"] == "forbidden"
    data = eventscaffold.profile_data(slug="x-ctf", name="X", start=dt.date(2026, 1, 1), end=dt.date(2026, 1, 2),
                                      kind="manual", submit_mode="manual", ai_on_platform="allowed",
                                      chain_rpc="allowed")
    assert eventscaffold.validate(data, "x-ctf").rules.chain_rpc == "allowed"


def test_reads_from_an_allowed_in_scope_node(node):
    url, seen = node
    r = evm_rpc.RpcReader(url, profile=_profile())
    assert r.chain_id() == 31337
    assert r.get_storage_at(ADDR, 0) == bytes(31) + b"\x2a"
    assert r.get_storage_at(ADDR, 1).rstrip(b"\0") == b"s3cr3t pa55word"
    assert r.get_code(ADDR) == bytes.fromhex("6080604052")
    assert r.get_balance(ADDR) == 10 ** 18
    assert r.call(ADDR, b"\x12\x34\x56\x78") == bytes(31) + b"\x01"
    methods = [req["method"] for _, req in seen]
    assert methods == ["eth_chainId", "eth_getStorageAt", "eth_getStorageAt", "eth_getCode", "eth_getBalance",
                       "eth_call"]
    assert seen[1][1]["params"] == [ADDR, "0x0", "latest"]
    assert seen[5][1]["params"] == [{"to": ADDR, "data": "0x12345678"}, "latest"]


def test_forbidden_profile_refuses_before_any_request(node):
    url, seen = node
    with pytest.raises(evm_rpc.RpcRefused, match="chain_rpc"):
        evm_rpc.RpcReader(url, profile=_profile("forbidden"))
    with pytest.raises(evm_rpc.RpcRefused, match="chain_rpc"):
        evm_rpc.RpcReader(url, profile=_profile(None))
    # the suite's pinned profile does not set chain_rpc: the default refuses too
    with pytest.raises(evm_rpc.RpcRefused, match="chain_rpc"):
        evm_rpc.RpcReader(url)
    assert seen == []
    assert issubclass(evm_rpc.RpcRefused, scope.OutOfScope)


def test_profile_is_resolved_through_public_scope_and_event_apis(node, monkeypatch):
    # order: the profile passed, else the scope pin, else event.current(); no event at all is a refusal
    url, seen = node
    prev = scope.pinned()
    scope.unpin()
    try:
        monkeypatch.setattr(event, "current", lambda *a, **k: _profile())
        assert evm_rpc.RpcReader(url).chain_id() == 31337                     # event.current() admits it
        scope.pin(_profile("forbidden"))
        with pytest.raises(evm_rpc.RpcRefused, match="chain_rpc"):            # the pin wins over current()
            evm_rpc.RpcReader(url)
        assert evm_rpc.RpcReader(url, profile=_profile()).chain_id() == 31337 # an explicit profile wins
        scope.unpin()

        def no_event(*a, **k):
            raise event.EventError("no event profile found")
        monkeypatch.setattr(event, "current", no_event)
        with pytest.raises(evm_rpc.RpcRefused, match="no event profile"):
            evm_rpc.RpcReader(url)
    finally:
        scope.unpin()
        if prev is not None:
            scope.pin(prev)
    assert len(seen) == 2


def test_out_of_scope_node_and_platform_are_refused(node):
    url, seen = node
    with pytest.raises(evm_rpc.RpcRefused, match="live_service_scope"):
        evm_rpc.RpcReader(url, profile=_profile(live_scope=("10.0.0.0/8",)))
    with pytest.raises(evm_rpc.RpcRefused):
        evm_rpc.RpcReader("https://board.rpc-platform.test/rpc",
                          profile=_profile(live_scope=("*.rpc-platform.test",)))
    for bad in ("ftp://127.0.0.1/", "127.0.0.1:8545", "http://user:pw@127.0.0.1/"):
        with pytest.raises(evm_rpc.RpcRefused):
            evm_rpc.RpcReader(bad, profile=_profile())
    assert seen == []


@pytest.mark.parametrize("method", ["eth_sendRawTransaction", "eth_sendTransaction", "eth_sign",
                                    "personal_unlockAccount", "anvil_setStorageAt", "hardhat_impersonateAccount",
                                    "evm_mine", "debug_traceTransaction", "eth_signTypedData_v4"])
def test_write_and_signing_methods_are_refused_before_sending(node, method):
    url, seen = node
    r = evm_rpc.RpcReader(url, profile=_profile())
    with pytest.raises(evm_rpc.RpcRefused, match="read-only"):
        r.request(method, [])
    assert seen == []


def test_transport_failures_are_named_errors(node):
    url, seen = node
    prof = _profile()
    with pytest.raises(evm_rpc.RpcError, match="redirect"):
        evm_rpc.RpcReader(url + "/redirect", profile=prof).chain_id()
    assert [p for p, _ in seen] == ["/redirect"]           # the redirect target was never contacted
    with pytest.raises(evm_rpc.RpcError, match="larger than"):
        evm_rpc.RpcReader(url + "/big", profile=prof, max_response=1024).chain_id()
    with pytest.raises(evm_rpc.RpcError, match="id"):
        evm_rpc.RpcReader(url + "/wrong-id", profile=prof).chain_id()
    with pytest.raises(evm_rpc.RpcError, match="execution reverted"):
        evm_rpc.RpcReader(url + "/error", profile=prof).call(ADDR, "0x")
    # a node that returns a short quantity for a storage word: left-padded to 32 bytes
    assert evm_rpc.RpcReader(url + "/short-word", profile=prof).get_storage_at(ADDR, 0) == bytes(31) + b"\x2a"


def test_parameter_validation():
    with pytest.raises(ValueError):
        evm_rpc._address("0x1234")
    with pytest.raises(ValueError):
        evm_rpc._slot(-1)
    with pytest.raises(ValueError):
        evm_rpc._slot(1 << 256)
    assert evm_rpc._slot(bytes(31) + b"\x05") == "0x" + "00" * 31 + "05"
    assert evm_rpc._slot("0x0a") == "0xa"
    assert evm_rpc._block(16) == "0x10" and evm_rpc._block("finalized") == "finalized"
    with pytest.raises(ValueError):
        evm_rpc._block("yesterday")


def test_cli_storage_and_refusal(node, capsys):
    url, seen = node
    assert evm_rpc.main([url, "storage", ADDR, "1"]) == 3        # the suite profile does not allow chain reads
    assert seen == []
    prev = scope.pinned()
    scope.pin(_profile())
    try:
        assert evm_rpc.main([url, "storage", ADDR, "1"]) == 0
    finally:
        scope.pin(prev)
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["ascii"] == "s3cr3t pa55word"
    assert out["slot"] == "0x1"


# ---------------------------------------------------------------------------- the engine entry (solve)

LONG_FLAG = "rpcctf{a_long_string_lives_at_keccak_of_its_slot}"
SHORT_FLAG = "rpcctf{short_inline}"
CODE_FLAG = "rpcctf{constant_in_code}"


def _flag_profile(chain_rpc="allowed"):
    return event.parse({
        "slug": "rpc-test", "name": "rpc test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.rpc-platform.test"},
        "flag": {"prefixes": ["rpcctf"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["127.0.0.0/8"], "chain_rpc": chain_rpc}}, src="tests/test_b243_evm_rpc.py")


def _short(text: bytes) -> str:
    return "0x" + (text.ljust(31, b"\0") + bytes([2 * len(text)])).hex()


def _long_storage(slot: int, text: bytes) -> dict:
    """Solidity's layout of a string of 32+ bytes: the slot holds 2*len+1, the data starts at keccak(slot).
    keccak here is eth_hash's, independent of the toolkit's."""
    out = {slot: "0x" + (2 * len(text) + 1).to_bytes(32, "big").hex()}
    base = int.from_bytes(eth_keccak(slot.to_bytes(32, "big")), "big")
    padded = text.ljust(-(-len(text) // 32) * 32, b"\0")
    for i in range(0, len(padded), 32):
        out[base + i // 32] = "0x" + padded[i:i + 32].hex()
    return out


class _StateNode(BaseHTTPRequestHandler):
    seen: list = []
    storage: dict = {}
    code = "0x"

    def log_message(self, *a):
        pass

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        self.seen.append(req)
        m, p = req["method"], req["params"]
        if m == "eth_getStorageAt":
            res = self.storage.get(int(p[1], 16), "0x" + "00" * 32)
        elif m == "eth_getCode":
            res = self.code
        else:
            res = None
        out = json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": res}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


@pytest.fixture
def state_node():
    _StateNode.seen, _StateNode.storage, _StateNode.code = [], {}, "0x"
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _StateNode)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", _StateNode
    finally:
        srv.shutdown()
        srv.server_close()


def test_decode_storage_string_forms():
    assert evm_rpc.decode_storage_string(bytes.fromhex(_short(b"hello")[2:])) == ("short", b"hello")
    assert evm_rpc.decode_storage_string((2 * 100 + 1).to_bytes(32, "big")) == ("long", 100)
    assert evm_rpc.decode_storage_string(bytes(32)) is None                       # zero: no string
    assert evm_rpc.decode_storage_string(bytes(31) + b"\x2a") is None             # uint 42, not 21 NULs
    assert evm_rpc.decode_storage_string(b"a" * 31 + b"\x3e") == ("short", b"a" * 31)   # the longest inline
    assert evm_rpc.decode_storage_string(b"z" + bytes(30) + b"\x02") == ("short", b"z")
    junk = bytearray.fromhex(_short(b"hi")[2:])
    junk[10] = 1                                                                  # a byte past len
    assert evm_rpc.decode_storage_string(bytes(junk)) is None
    assert evm_rpc.decode_storage_string(b"\xff" * 31 + b"\x40") is None          # len 32 cannot be inline
    assert evm_rpc.decode_storage_string((2 * 31 + 1).to_bytes(32, "big")) is None    # "long" but < 32 bytes
    assert evm_rpc.decode_storage_string((2 * 32 + 1).to_bytes(32, "big")) == ("long", 32)
    top = evm_rpc.MAX_STRING_BYTES
    assert evm_rpc.decode_storage_string((2 * top + 1).to_bytes(32, "big")) == ("long", top)
    assert evm_rpc.decode_storage_string((2 * (top + 1) + 1).to_bytes(32, "big")) is None
    assert evm_rpc.decode_storage_string(bytes(31)) is None


def test_engine_reads_a_long_string_slot_and_finds_the_flag(state_node):
    url, node = state_node
    addr = "0x" + "ab" * 20
    node.storage = {0: "0x" + "00" * 31 + "07", **_long_storage(2, LONG_FLAG.encode())}
    res = evm_rpc.solve(".", _flag_profile(), url=url, address=addr, slots=4)
    assert isinstance(res, SolverResult)
    assert res.status == "solved" and res.flags == (LONG_FLAG,)
    assert any("string held at storage slot 2" in e.detail for e in res.evidence)
    methods = {r["method"] for r in node.seen}
    assert methods == {"eth_getCode", "eth_getStorageAt"}
    read_slots = [int(r["params"][1], 16) for r in node.seen if r["method"] == "eth_getStorageAt"]
    base = int.from_bytes(eth_keccak((2).to_bytes(32, "big")), "big")
    assert read_slots == [0, 1, 2, base, base + 1, 3]       # slots 0-3, and the 2 data slots of the 50-byte string
    assert {r["params"][-1] for r in node.seen} == {"latest"}


def test_engine_two_flags_are_candidates_and_code_is_searched(state_node):
    url, node = state_node
    node.storage = {1: _short(SHORT_FLAG.encode())}
    node.code = "0x6080" + CODE_FLAG.encode().hex() + "00"
    res = evm_rpc.solve(".", _flag_profile(), url=url, address="0x" + "cd" * 20, slots=[1, "0x5"], block=7)
    assert res.status == "candidate" and set(res.flags) == {SHORT_FLAG, CODE_FLAG}
    read_slots = [int(r["params"][1], 16) for r in node.seen if r["method"] == "eth_getStorageAt"]
    assert read_slots == [1, 5]
    assert {r["params"][-1] for r in node.seen} == {"0x7"}
    node.seen.clear()
    node.code = "0x"
    res = evm_rpc.solve(".", _flag_profile(), url=url, address="0x" + "cd" * 20)
    assert res.status == "solved" and res.flags == (SHORT_FLAG,)
    read_slots = [int(r["params"][1], 16) for r in node.seen if r["method"] == "eth_getStorageAt"]
    assert read_slots == list(range(evm_rpc.DEFAULT_SLOTS))


def test_engine_without_a_flag_is_unsure_or_none(state_node):
    url, node = state_node
    node.storage = {0: _short(b"just a name")}
    res = evm_rpc.solve(".", _flag_profile(), url=url, address="0x" + "11" * 20, slots=2)
    assert res.status == "unsure" and res.flags == ()
    assert any("just a name" in e.detail for e in res.evidence)
    node.storage, node.code = {}, "0x6080"
    assert evm_rpc.solve(".", _flag_profile(), url=url, address="0x" + "11" * 20, slots=2).status == "unsure"
    node.code = "0x"
    assert evm_rpc.solve(".", _flag_profile(), url=url, address="0x" + "11" * 20, slots=2).status == "none"


def test_engine_is_blocked_without_permission_or_target(state_node):
    url, node = state_node
    node.storage = {1: _short(SHORT_FLAG.encode())}
    res = evm_rpc.solve(".", _flag_profile("forbidden"), url=url, address="0x" + "cd" * 20)
    assert res.status == "blocked" and "chain_rpc" in res.notes and res.flags == ()
    res = evm_rpc.solve(".", _flag_profile(), address="0x" + "cd" * 20)
    assert res.status == "blocked" and "url" in res.notes
    res = evm_rpc.solve(".", _flag_profile(), url=url)
    assert res.status == "blocked" and "address" in res.notes
    assert node.seen == []
    with pytest.raises(ValueError, match="unknown option"):
        evm_rpc.solve(".", _flag_profile(), url=url, address="0x" + "cd" * 20, host="x")
    for bad in ({"slots": 0}, {"slots": evm_rpc.MAX_SLOTS + 1}, {"slots": []}, {"slots": True},
                {"slots": [1.5]}, {"timeout": 0}, {"timeout": 121}, {"block": "yesterday"}, {"address": "0x12"}):
        with pytest.raises(ValueError):
            evm_rpc.solve(".", _flag_profile(), **{"url": url, "address": "0x" + "cd" * 20, **bad})
    assert node.seen == []
    # the bounds themselves are accepted: one slot (slot 0, empty; the flag sits in slot 1), 120 s
    res = evm_rpc.solve(".", _flag_profile(), url=url, address="0x" + "cd" * 20, slots=1, timeout=120)
    assert res.status == "none"
    assert [int(r["params"][1], 16) for r in node.seen if r["method"] == "eth_getStorageAt"] == [0]


def test_engine_unreachable_node_is_blocked(state_node):
    url, _ = state_node
    dead = url.rsplit(":", 1)[0] + ":1"
    res = evm_rpc.solve(".", _flag_profile(), url=dead, address="0x" + "cd" * 20)
    assert res.status == "blocked" and "did not answer" in res.notes


def test_manifest_entry_is_the_solve_contract():
    m = manifest.load(paths.repo_root() / "solvers" / "toolkits" / "evm_rpc.manifest.toml")
    assert m.entry_raw == "solvers.toolkits.evm_rpc:solve"
    assert m.has("executes") and not m.has("library")
