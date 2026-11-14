#!/usr/bin/env python3
"""Offline tests of solvers/toolkits/blockchain.py (read-only EVM/Bitcoin facts). No network, no token.

  .venv/bin/python -m pytest tests/test_day26_blockchain.py   (or `python tests/test_day26_blockchain.py`)

Vectors are published ones (EIP-155 example tx, EIP-55 addresses, BIP173/350 addresses, the Satoshi address,
keccak("")) plus transactions signed here with the module's own secp256k1 and a fixed nonce. Every answer is an
unsure labels.pick (nothing is judged); the checks read the options back. Fuzz: hundreds of junk, truncated and
mutated blobs must give no exception and no answer for what is not a valid artifact.
"""
import json
import os
import random
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="test_blockchain_")
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import labels      # noqa: E402
import blockchain as b   # noqa: E402


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:300]}]"))
    assert ok, f"{label}  [{str(detail)[:300]}]"


def Q(qid, text):
    return {"qid": qid, "answer_id": qid, "question": text, "answer_format": {"kind": "exact_text"}}


def ask(text, files, qid="q"):
    return b.solve_set([Q(qid, text)], files, {})[qid]


def opts(v):
    p = labels.parse(v) if v is not None else None
    return None if p is None else p.options


def first(v):
    o = opts(v)
    return o[0][1] if o else None


def values(v):
    return [x[1] for x in (opts(v) or [])]


def sign(h32, d, k):
    z = int.from_bytes(h32, "big")
    R = b._mul(k, b._G)
    r = R[0] % b._N
    s = pow(k, -1, b._N) * (z + r * d) % b._N
    rec = R[1] & 1
    if s > b._N // 2:
        s, rec = b._N - s, rec ^ 1
    return r, s, rec


D = 0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318
ADDR = b.pub_to_address(b._mul(D, b._G))

# ---- the EIP-155 example transaction
RAW155 = bytes.fromhex("f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83")
HEXF = {"tx.txt": ("0x" + RAW155.hex()).encode()}

# ---- an EIP-1559 tx carrying transfer() calldata, signed here (fixed nonce), with a mini ABI
TO = bytes.fromhex("dac17f958d2ee523a2206206994597c13d831ec7")
RECIP = bytes.fromhex("ab5801a7d398351b8be11c439e05c5b3259aec9b")
CD = bytes.fromhex("a9059cbb") + b"\0" * 12 + RECIP + (1234567).to_bytes(32, "big")
BODY = [1, 7, 2 * 10 ** 9, 30 * 10 ** 9, 60000, TO, 0, CD, []]
R1559, S1559, REC1559 = sign(b.keccak(b"\x02" + b.rlp_encode(BODY)), D, 0x1234567890abcdef)
RAW1559 = b"\x02" + b.rlp_encode(BODY + [REC1559, R1559, S1559])
ABI = [{"type": "function", "name": "transfer", "inputs": [{"name": "recipient", "type": "address"}, {"name": "amount", "type": "uint256"}],
        "outputs": [{"type": "bool"}]},
       {"type": "event", "name": "Transfer", "anonymous": False, "inputs": [
           {"name": "from", "type": "address", "indexed": True}, {"name": "to", "type": "address", "indexed": True},
           {"name": "value", "type": "uint256", "indexed": False}]}]

# ---- a legacy and a segwit bitcoin tx
H160 = bytes.fromhex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18")
_SPK1 = b"\x76\xa9\x14" + H160 + b"\x88\xac"
_OPR = b"\x6a\x05hello"
BTC_INS = b"\x01" + bytes.fromhex("11" * 32)[::-1] + struct.pack("<I", 1) + b"\x00" + struct.pack("<I", 0xFFFFFFFD)
BTC_OUTS = (b"\x02" + struct.pack("<Q", 5000) + bytes([len(_SPK1)]) + _SPK1 + struct.pack("<Q", 0) + bytes([len(_OPR)])
            + _OPR)
BTC = struct.pack("<i", 2) + BTC_INS + BTC_OUTS + struct.pack("<I", 700000)
SEG = struct.pack("<i", 2) + b"\x00\x01" + BTC_INS + BTC_OUTS + b"\x02\x02aa\x01b" + struct.pack("<I", 0)

# ---- creation bytecode: constructor + runtime with a 3-selector dispatcher and solc metadata
SELS = ["a9059cbb", "70a08231", "18160ddd"]
_rt = b"\x60\x80\x60\x40\x52" + b"\x60\x00\x35\x60\xe0\x1c"
for _i, _sl in enumerate(SELS):
    _rt += b"\x80\x63" + bytes.fromhex(_sl) + b"\x14\x60" + bytes([0x40 + _i]) + b"\x57"
_rt += b"\x00" + b"\x7f" + b"Only the owner".ljust(32, b"\0") + b"\x60\x00\xfd"
RUNTIME = _rt + b"\xa1\x64solc\x43\x00\x08\x13" + b"\x00\x0a"
_CTOR = b"\x60\x80\x60\x40\x52"
OFF = len(_CTOR) + 2 + 1 + 2 + 2 + 1 + 2 + 1       # PUSH1 len DUP1 PUSH1 off PUSH1 0 CODECOPY PUSH1 0 RETURN
CREATION = _CTOR + b"\x60" + bytes([len(RUNTIME)]) + b"\x80\x60" + bytes([OFF]) + b"\x60\x00\x39\x60\x00\xf3" + RUNTIME
CF = {"c.hex": ("0x" + CREATION.hex()).encode()}


def test_eip155_example_transaction():
    tx = b.decode_evm_tx(RAW155)
    check("keccak256('') and the transfer selector", b.keccak(b"").hex().startswith("c5d24601") and
          b.selector_of_signature("transfer(address,uint256)").hex() == "a9059cbb")
    check("EIP-155 tx decodes: chain 1, nonce 9, 1 ether, to 0x3535..., signing hash daf5a779...",
          tx and tx["chain_id"] == 1 and tx["nonce"] == 9 and tx["value"] == 10 ** 18 and tx["to"] == "35" * 20
          and tx["signing_hash"].startswith("daf5a779ae97"))
    check("EIP-155 tx sender is the published 0x9d8A62f6...", tx and tx["from"] == "9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f")
    hexf = HEXF
    check("sender question -> checksummed address first", first(ask("Which address sent this transaction?", hexf)) ==
          "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F")
    check("value question with wei -> 1000000000000000000 first",
          first(ask("What is the value in wei?", hexf)) == "1000000000000000000")
    check("value question with ether -> 1 first", first(ask("How much ether is transferred?", hexf)) == "1")
    check("chain id and nonce", first(ask("What is the chain ID?", hexf)) == "1" and first(ask("What is the nonce?", hexf)) == "9")
    check("gas price asked in gwei -> 20", first(ask("What is the gas price in gwei?", hexf)) == "20")
    check("two fields in one question -> None", ask("What is the nonce and the chain id?", hexf) is None)
    check("key prefix is blockchain.*", labels.parse(ask("What is the nonce?", hexf)).key.startswith("blockchain.tx_nonce/"))
    check("every answer is unsure (nothing judged), never a bare plain value", labels.is_unsure(ask("What is the nonce?", hexf)))


def test_eip1559_transfer_calldata_against_an_abi():
    body, raw1559, abi = BODY, RAW1559, ABI
    r, s, rec = R1559, S1559, REC1559
    t2 = b.decode_evm_tx(raw1559)
    check("EIP-1559 tx decodes and recovers the signer we signed with", t2 and t2["type"] == 2 and t2["from"] == ADDR.hex()
          and t2["selector"] == "a9059cbb" and t2["max_fee"] == 30 * 10 ** 9)
    files = {"tx.hex": ("0x" + raw1559.hex()).encode(), "abi.json": json.dumps(abi).encode()}
    check("selector against the provided ABI -> function name transfer",
          first(ask("Which function does this transaction call? Give the function name.", files)) == "transfer")
    check("ABI decode by parameter name: the amount argument",
          first(ask("What is the amount argument of the call?", files)) == "1234567")
    check("ABI decode by parameter name: the recipient argument, checksummed",
          first(ask("What is the recipient argument of the call?", files)) == b.eip55(RECIP))
    check("ABI decode by ordinal: the second argument", first(ask("What is the second argument of the call?", files)) == "1234567")
    check("selector hex with 0x first", first(ask("What is the 4-byte function selector?", files)) == "0xa9059cbb")
    check("a selector with no ABI and a common-table hit is offered, under a +common_table shape",
          "common_table" in labels.parse(ask("What is the function name?", {"tx.hex": ("0x" + raw1559.hex()).encode()})).key)
    unk = b"\x02" + b.rlp_encode(body[:7] + [bytes.fromhex("deadbeef") + b"\0" * 32] + body[8:] + [rec, r, s])
    check("an unknown selector with no ABI -> None for the function name",
          ask("What is the function name?", {"u": ("0x" + unk.hex()).encode()}) is None)
    check("selector of a signature typed in the question",
          first(ask("What is the selector of transfer(address,uint256)?", {})) == "0xa9059cbb")
    check("a non-canonical signature (uint) is never hashed", ask("What is the selector of transfer(address,uint)?", {}) is None)


# ---- ABI decode edge cases and event logs
def test_abi_decode_edge_cases_and_event_logs():
    abi = ABI
    check("abi_decode: strict padding", b.abi_decode(["address"], b"\x01" + b"\0" * 11 + RECIP) is None and
          b.abi_decode(["address"], b"\0" * 12 + RECIP) == ["0x" + RECIP.hex()])
    check("abi_decode: string + dynamic array", b.abi_decode(["string", "uint256[]"],
          (64).to_bytes(32, "big") + (128).to_bytes(32, "big") + (2).to_bytes(32, "big") + b"hi" + b"\0" * 30
          + (2).to_bytes(32, "big") + (5).to_bytes(32, "big") + (6).to_bytes(32, "big")) == ["hi", [5, 6]])
    check("abi_decode: an offset past the data is None", b.abi_decode(["string"], (999).to_bytes(32, "big")) is None)
    ev = b.parse_abi(abi)["events"][0]
    log = {"address": "0x" + TO.hex(), "topics": ["0x" + ev["topic"], "0x" + "00" * 12 + ADDR.hex(), "0x" + "00" * 12 + RECIP.hex()],
           "data": "0x" + (999).to_bytes(32, "big").hex()}
    lf = {"receipt.json": json.dumps({"logs": [log]}).encode(), "abi.json": json.dumps(abi).encode()}
    check("event log: topic0 matches the ABI event, name read", first(ask("Which event was emitted? event name", lf)) == "Transfer")
    check("event log: the value argument decoded", first(ask("What is the value in the event?", lf)) == "999")
    check("topic0 of an event signature", first(ask("What is the topic0 of Transfer(address,address,uint256)?", {"abi.json": json.dumps(abi).encode()}))
          == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")


# ---- EIP-55
def test_eip55_and_key_derivation():
    hexf = HEXF
    for a in ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
              "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"):
        check(f"EIP-55 vector {a[:8]} valid", b.classify_eth_address(a)["checksum"] == "valid")
    v = ask("Is the checksum of this address valid?", {"a.txt": b"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"})
    check("valid checksum -> yes first, shape eip55_valid", first(v) == "yes" and "eip55_valid" in labels.parse(v).key)
    bad = "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    v = ask("Is the checksum of this address valid?", {"a.txt": bad.encode()})
    check("wrong-case address -> 'no' under its own shape (unsure)", first(v) == "no" and "eip55_invalid" in labels.parse(v).key
          and labels.is_unsure(v))
    v = ask("What is the correctly checksummed form of " + bad.lower() + "?", {})
    check("checksummed form from an address in the question text", first(v) == "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
    check("a single-case address has no checksum to validate -> None",
          ask("Is the checksum valid?", {"a.txt": bad.lower().encode()}) is None)
    v = ask("Derive the address from this public key", {"pub.hex": ("0x04" + b._G[0].to_bytes(32, "big").hex() + b._G[1].to_bytes(32, "big").hex()).encode()})
    check("address from a provided public key (key 1 -> 0x7E5F4552...)", first(v) == "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
    K = "0x" + (1).to_bytes(32, "big").hex()
    v = ask("What address does this private key control?", {"key.txt": K.encode()})
    check("address from a provided private key", first(v) == "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
    check("the private key itself is always None", ask("What is the private key?", {"key.txt": K.encode()}) is None)
    check("a seed/flag question is None", ask("What is the flag?", hexf) is None and ask("Give the seed phrase", hexf) is None)
    sec = (0xabcdef0123456789 << 192 | 12345).to_bytes(32, "big").hex()
    out = b.solve_set([Q("a", "What address does this private key control?"), Q("b", "What is the private key?")],
                      {"k.txt": sec.encode()}, {})
    check("no answer string contains the secret hex; the key file alone gives no signal",
          all(sec not in str(x) for x in out.values()) and out["b"] is None
          and b.signals([Q("a", "What is the private key of this Ethereum wallet?")], {"k.txt": sec.encode()}) == 0.0, out)


# ---- signatures
def test_signatures():
    msg = "hello ctf"
    hh = b.keccak(b"\x19Ethereum Signed Message:\n" + str(len(msg)).encode() + msg.encode())
    r, s, rec = sign(hh, D, 0xabcdef1234567)
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + rec])
    js = {"s.json": json.dumps({"message": msg, "signature": "0x" + sig.hex(), "address": b.eip55(ADDR)}).encode()}
    check("EIP-191 signer proven by the claimed address", first(ask("Which address signed the message?", js)) == b.eip55(ADDR))
    js2 = {"s.json": json.dumps({"message": msg, "signature": "0x" + sig.hex()}).encode()}
    check("message with no claimed address: scheme unproven -> None", ask("Which address signed the message?", js2) is None)
    js3 = {"s.json": json.dumps({"hash": "0x" + hh.hex(), "signature": "0x" + sig.hex()}).encode()}
    check("signature over a given hash recovers the signer", first(ask("Who signed this hash? ecrecover", js3)) == b.eip55(ADDR))
    sig_bad = sig[:10] + bytes([sig[10] ^ 1]) + sig[11:]
    check("a corrupted signature never yields the signer",
          first(ask("Who signed this hash? ecrecover", {"s.json": json.dumps({"hash": "0x" + hh.hex(), "signature": "0x" + sig_bad.hex()}).encode()}))
          != b.eip55(ADDR))


# ---- base58 / bech32 / Bitcoin
def test_base58_bech32_bitcoin():
    SAT = {"a": b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}
    check("Satoshi address is P2PKH, hash160 62e907b1...",
          "p2pkh" in values(ask("What type of address is this?", SAT)) and
          first(ask("What is the hash160 of this address?", SAT)) == "62e907b15cbf27d5425399ebf6f0fb50ebb88f18")
    check("BIP173 vector is P2WPKH (bech32)", "p2wpkh" in values(ask("What is the address type?", {"a": b"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"})))
    check("BIP350 taproot vector is P2TR (bech32m)", "p2tr" in values(ask("What is the address type?", {"a":
          b"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"})))
    check("a bech32 string with a flipped character is not an address", b.classify_btc_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5") is None
          and ask("What is the address type?", {"a": b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"}) is None)
    check("a base58 string with a bad checksum is None", ask("What type of address is this?", {"a": b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"}) is None)
    wif = b.b58check_encode(0x80, b"\x11" * 32 + b"\x01")
    check("a WIF is recognised and never decoded out", b.classify_btc_address(wif)["kind"] == "wif"
          and ask("What is the hash160 of this?", {"a": wif.encode()}) is None)
    check("segwit v0 with a wrong witness program length is invalid",
          b.segwit_decode(b.bech32_encode("bc", [0] + b._convertbits([1] * 21, 8, 5, True), "bech32")) is None)

    ins, outs, btc = BTC_INS, BTC_OUTS, BTC
    bt = b.decode_btc_tx(btc)
    check("bitcoin legacy tx parses: 1 in, 2 out, p2pkh + op_return, txid = dsha256", bt and len(bt["inputs"]) == 1 and
          [o["type"] for o in bt["outputs"]] == ["p2pkh", "op_return"] and bt["outputs"][0]["address"] == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
          and bt["txid"] == b.sha256d(btc)[::-1].hex())
    bf = {"tx.hex": btc.hex().encode()}
    check("btc: locktime / outputs / op_return data", first(ask("What is the locktime?", bf)) == "700000" and
          first(ask("How many outputs does the transaction have?", bf)) == "2" and first(ask("What is the OP_RETURN data?", bf)) == "hello")
    check("btc: value of the first output in satoshi; a bare 'output 1' is ambiguous -> None",
          first(ask("What is the value of the first output in satoshis?", bf)) == "5000" and ask("What is the value of output 1 in satoshis?", bf) is None)
    check("btc: vout 0 is zero-based", first(ask("How many satoshis does vout 0 pay?", bf)) == "5000")
    seg = SEG
    sg = b.decode_btc_tx(seg)
    check("segwit tx: witness skipped, txid excludes it, wtxid differs", sg and sg["segwit"] and sg["txid"] != sg["wtxid"]
          and sg["txid"] == b.sha256d(struct.pack("<i", 2) + ins + outs + struct.pack("<I", 0))[::-1].hex())
    check("btc tx with trailing garbage / truncation is None", b.decode_btc_tx(btc + b"\0") is None and b.decode_btc_tx(btc[:-1]) is None)


# ---- bytecode
def test_bytecode():
    sels, runtime, off, creation, cf = SELS, RUNTIME, OFF, CREATION, CF
    assert creation[off:] == runtime
    rep = b.bytecode_report(creation)
    check("bytecode: creation split found (offset/length), runtime selector table", rep and rep["creation"] and rep["runtime_offset"] == off
          and rep["runtime_length"] == len(runtime) and rep["selectors"] == sels, rep)
    check("bytecode: solc version from metadata, one PUSH literal string", rep["solc"] == "0.8.19" and rep["strings"] == ["Only the owner"])
    check("bytecode answers: count / list / runtime offset / solc / literal",
          first(ask("How many function selectors does the dispatcher have?", cf)) == "3"
          and first(ask("List all function selectors", cf)) == "0xa9059cbb,0x70a08231,0x18160ddd"
          and first(ask("At what offset does the runtime code start?", cf)) == str(off)
          and first(ask("Which solc compiler version compiled it?", cf)) == "0.8.19"
          and first(ask("What is the revert message string in the bytecode?", cf)) == "Only the owner")
    check("bytecode answers carry the heuristic in their shape", "solc_eq_pattern" in labels.parse(ask("How many function selectors?", cf)).key)
    check("JSON {'bytecode': {'object': ...}} is read", first(ask("How many function selectors?", {"o.json": json.dumps({"bytecode": {"object": "0x" + creation.hex()}}).encode()})) == "3")
    check("the disassembler names opcodes", [x[2] for x in b.disassemble(bytes.fromhex("6080604052"))] == ["PUSH1", "PUSH1", "MSTORE"])
    check("no CODECOPY/RETURN site -> no split", b.split_creation(runtime) is None)


# ---- signals and absent inputs
def test_signals_and_absent_inputs():
    hexf = HEXF
    Qs = [Q("a", "What is the sender of this Ethereum transaction?")]
    check("signals: a parsed tx plus vocabulary scores over the threshold", b.signals(Qs, hexf) >= 0.6, b.signals(Qs, hexf))
    check("signals: a 64-byte zero blob is 0.0", b.signals([Q("a", "What is it?")], {"a.bin": bytes(64)}) == 0.0)
    check("signals: junk with blockchain words but no artifact is 0.0", b.signals(Qs, {"a.txt": b"hello world"}) == 0.0)
    check("no files, no question text address -> None", ask("What is the sender?", {}) is None)


# ---- fuzz
def test_fuzz_and_every_answer_is_a_blockchain_pick():
    hexf, cf, raw1559, btc, seg, creation = HEXF, CF, RAW1559, BTC, SEG, CREATION
    rnd = random.Random(26)
    valid = [RAW155, raw1559, btc, seg, creation]
    qs = [Q("a", "Which address sent this transaction?"), Q("b", "What is the value in wei?"), Q("c", "What is the function selector?"),
          Q("d", "How many function selectors does the dispatcher have?"), Q("e", "How many outputs does the transaction have?"),
          Q("f", "What is the nonce?"), Q("g", "What type of address is this?"), Q("h", "What is the checksum form of the address?")]
    bad_plain = bad_exc = n = 0

    def run(blob_files):
        nonlocal bad_exc, n
        n += 1
        try:
            return b.solve_set(qs, blob_files, {})
        except Exception as e:  # noqa: BLE001
            bad_exc += 1
            print("EXC", repr(e))
            return {}

    for _ in range(150):                 # pure junk, as hex text and as raw bytes
        blob = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 200)))
        for files_ in ({"j.bin": blob}, {"j.hex": ("0x" + blob.hex()).encode()}, {"j.txt": blob.hex().upper().encode()}):
            out = run(files_)
            for k in "acdef":              # tx / bytecode / btc answers from junk would be a wrong plain
                if out.get(k) is not None:
                    bad_plain += 1
    for src in valid:                    # every truncation of a valid tx is None
        if src is creation:
            continue
        for cut in range(1, len(src) - 1, max(1, len(src) // 40)):
            out = run({"t.hex": ("0x" + src[:cut].hex()).encode()})
            if any(out.get(k) is not None for k in "acef"):
                bad_plain += 1
        for _ in range(120):             # single and double bit flips
            m = bytearray(src)
            for _ in range(rnd.choice((1, 1, 2))):
                m[rnd.randrange(len(m))] ^= 1 << rnd.randrange(8)
            run({"m.hex": ("0x" + bytes(m).hex()).encode()})
            d = b.decode_evm_tx(bytes(m))
            if d is not None and src in (RAW155, raw1559):
                inner = bytes(m)[1:] if m[0] < 0xC0 else bytes(m)
                body_ = b.rlp_decode(inner)
                if body_ is None or b.rlp_encode(body_) != inner:      # a survivor must be canonical RLP of its own bytes
                    bad_plain += 1
    for _ in range(100):                 # near-miss text addresses, bech32
        a = list("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
        a[rnd.randrange(2, len(a))] = rnd.choice("0123456789abcdefABCDEFgG")
        s_ = "".join(a)
        v = run({"a.txt": s_.encode()}).get("h")
        c = b.classify_eth_address(s_)
        if v is not None and (c is None or first(v) != c["checksummed"]):
            bad_plain += 1
        t_ = list("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        t_[rnd.randrange(3, len(t_))] = rnd.choice("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
        if "".join(t_) != "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" and b.classify_btc_address("".join(t_)) is not None:
            bad_plain += 1
    check(f"fuzz: {n} runs, no exception", bad_exc == 0, bad_exc)
    check("fuzz: PLAIN(bad) = 0 (junk, truncations, mutants, near-miss addresses)", bad_plain == 0, bad_plain)

    allv = [ask("What is the nonce?", hexf), ask("Which address sent this transaction?", hexf), ask("How many function selectors?", cf)]
    check("every emitted answer is a pick under blockchain.*", all(labels.parse(x) and labels.parse(x).key.startswith("blockchain.") for x in allv))


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
