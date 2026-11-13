"""B-243: blockchain depth in solvers/toolkits/blockchain.py.

- the router: a segwit yes/no question routes to the segwit field (it used to name two fields and return
  None), a what/which address-type question that also says "segwit" routes to the type;
- ABI: tuples, nested tuples, tuple[] / tuple[k] and arrays of dynamic types decode, checked against
  eth_abi as the oracle (never against this module's own encoder), with bounds and canonical-encoding checks;
- EIP-7702 (type 4) set-code transactions decode, checked against eth_account as the oracle.
"""
import random

import eth_abi
import pytest
from eth_account import Account
from eth_hash.auto import keccak

import blockchain as b
import labels


@pytest.fixture(autouse=True)
def _workdir(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))


def Q(text, qid="q"):
    return {"qid": qid, "answer_id": qid, "question": text, "answer_format": {"kind": "exact_text"}}


def ask(text, files):
    return b.solve_set([Q(text)], files, {})["q"]


def options(ans):
    p = labels.parse(ans) if ans is not None else None
    return None if p is None else dict(p.options)


def key(ans):
    return labels.parse(ans).key


def lists(v):
    return [lists(x) for x in v] if isinstance(v, (list, tuple)) else v


# ---------------------------------------------------------------------------- router: segwit yes/no

P2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"       # BIP173 vector
P2PKH = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"                # the Satoshi address
P2SH = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
P2TR = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"   # BIP350 vector


def _btc_tx(segwit: bool) -> bytes:
    spk = b"\x76\xa9\x14" + bytes(range(20)) + b"\x88\xac"
    ins = b"\x01" + bytes([0x11] * 32) + (1).to_bytes(4, "little") + b"\x00" + (0xFFFFFFFD).to_bytes(4, "little")
    outs = b"\x01" + (5000).to_bytes(8, "little") + bytes([len(spk)]) + spk
    if segwit:
        return (2).to_bytes(4, "little") + b"\x00\x01" + ins + outs + b"\x02\x02aa\x01b" + bytes(4)
    return (2).to_bytes(4, "little") + ins + outs + bytes(4)


@pytest.mark.parametrize("text", [
    "Is this transaction segwit?",
    "Does this transaction use segwit?",
    "Is this a segwit transaction? Answer yes or no.",
])
def test_segwit_yes_no_routes_to_the_segwit_field(text):
    assert b.route(Q(text)) == {"btc_segwit"}
    seg = {"tx.hex": _btc_tx(True).hex().encode()}
    legacy = {"tx.hex": _btc_tx(False).hex().encode()}
    yes, no = ask(text, seg), ask(text, legacy)
    assert options(yes)["yes_no"] == "yes" and options(yes)["true_false"] == "true"
    assert options(no)["yes_no"] == "no" and options(no)["true_false"] == "false"
    assert key(yes).startswith("blockchain.is_segwit/segwit")
    assert key(no).startswith("blockchain.is_segwit/legacy")


def test_segwit_or_legacy_choice_names_its_own_answers():
    text = "Is this transaction segwit or legacy?"
    assert b.route(Q(text)) == {"btc_segwit"}
    assert options(ask(text, {"tx.hex": _btc_tx(True).hex().encode()})) == {"choice": "segwit"}
    assert options(ask(text, {"tx.hex": _btc_tx(False).hex().encode()})) == {"choice": "legacy"}


def test_what_kind_of_address_question_naming_segwit_routes_to_the_type():
    text = f"What kind of address is {P2WPKH}: legacy, segwit or taproot?"
    assert b.route(Q(text)) == {"addr_type"}
    assert "p2wpkh" in options(ask(text, {})).values()


def test_segwit_version_question_is_the_version_field():
    assert b.route(Q("What is the segwit version of this address?")) == {"addr_wver"}
    assert options(ask(f"What is the segwit version of {P2WPKH}?", {})) == {"decimal": "0"}


def test_segwit_question_without_a_form_stays_ambiguous():
    # neither a yes/no opening nor a what/which one: the two fields remain and the answer is None
    assert b.route(Q("segwit")) == {"addr_type", "btc_segwit"}
    assert ask("segwit", {"tx.hex": _btc_tx(True).hex().encode()}) is None


def test_which_question_naming_only_segwit_stays_ambiguous():
    # a what/which opening that names no address type apart from the segwit word itself is not the
    # address-type field: "which input is segwit" asks neither for the type nor for a yes/no
    for text in ("Which input is segwit?", "What part of this transaction is segwit?"):
        assert b.route(Q(text)) == {"addr_type", "btc_segwit"}
        assert ask(text, {"tx.hex": _btc_tx(True).hex().encode()}) is None


@pytest.mark.parametrize("text", [
    "Which input is segwit? yes or no",
    "What is the answer, yes or no: is this transaction segwit?",
])
def test_segwit_question_with_both_forms_stays_ambiguous(text):
    # a what/which opening together with a yes/no form: neither field wins, as for the checksum
    # fields, so both stay and the question gets no answer
    assert b.route(Q(text)) == {"addr_type", "btc_segwit"}
    assert ask(text, {"tx.hex": _btc_tx(True).hex().encode()}) is None
    assert ask(text, {"tx.hex": _btc_tx(False).hex().encode()}) is None


@pytest.mark.parametrize("text", [
    "Q3: is this transaction segwit?",
    "Question 2. Does this transaction use segwit?",
    "1) Is this segwit?",
    "2. is this a segwit transaction?",
    "(a) Is this transaction segwit?",
    "[4] Does this transaction use segwit?",
])
def test_numbered_segwit_yes_no_question_routes_to_the_segwit_field(text):
    assert b.route(Q(text)) == {"btc_segwit"}
    assert options(ask(text, {"tx.hex": _btc_tx(True).hex().encode()}))["yes_no"] == "yes"
    assert options(ask(text, {"tx.hex": _btc_tx(False).hex().encode()}))["yes_no"] == "no"


def test_numbered_what_kind_question_and_checksum_forms_keep_their_form():
    assert b.route(Q(f"Q1: What kind of address is {P2WPKH}: legacy, segwit or taproot?")) == {"addr_type"}
    assert "checksum_valid" in b.route(Q("Q2: Is the address checksum valid?"))
    assert "checksum_form" in b.route(Q("3) What is the EIP-55 checksum form of the address?"))
    # a number that is part of the question is not an enumerator: no opening, so still ambiguous
    assert b.route(Q("1.5 segwit")) == {"addr_type", "btc_segwit"}


def test_segwit_yes_no_about_an_address():
    assert options(ask(f"Is {P2WPKH} a segwit address?", {}))["yes_no"] == "yes"
    assert options(ask(f"Is {P2PKH} a segwit address?", {}))["yes_no"] == "no"
    # taproot (witness v1, bech32m) is segwit too
    tr = ask(f"Is {P2TR} a segwit address?", {})
    assert options(tr) == {"yes_no": "yes", "true_false": "true"}
    assert key(tr).startswith("blockchain.address_is_segwit/bech32m_p2tr")
    # a P2SH address may or may not wrap a segwit script: no answer
    assert ask(f"Is {P2SH} a segwit address?", {}) is None
    # two addresses: which one is meant is not said
    assert ask(f"Is {P2WPKH} or {P2PKH} a segwit address?", {}) is None


# ---------------------------------------------------------------------------- ABI tuples

TUPLE_VECTORS = [
    (["(uint256,address)"], [(5, "0x" + "ab" * 20)]),
    (["(uint256,string)[]", "bytes"], [[(1, "a"), (2, "bcdefgh" * 10)], b"xyz"]),
    (["((uint8,bytes)[2],bool)"], [([(1, b"q"), (2, b"")], True)]),
    (["string[]"], [["a", "", "hello world, longer than thirty-two bytes!"]]),
    (["bytes[2]", "uint256"], [[b"1", b"22"], 7]),
    (["(int8,bytes3)[3]"], [[(-1, b"abc"), (0, b"\0\0\0"), (127, b"zzz")]]),
    (["((address,(uint16,string)),int256[])"], [(("0x" + "01" * 20, (65535, "deep")), [-1, 2, -3])]),
    (["(bool,bytes32)", "(string)"], [(False, bytes(range(32))), ("x",)]),
    (["(uint256[],string)[2]"], [[([1, 2], "p"), ([], "")]]),
]


@pytest.mark.parametrize("types,values", TUPLE_VECTORS)
def test_tuple_decode_matches_eth_abi(types, values):
    data = eth_abi.encode(types, values)
    got = b.abi_decode(types, data)
    assert got is not None
    assert lists(got) == lists(eth_abi.decode(types, data))
    # a tuple type is a Python tuple, an array a list
    for t, v in zip(types, got):
        if t.endswith("]"):
            assert isinstance(v, list)
        elif t.startswith("("):
            assert isinstance(v, tuple)


def test_random_tuple_vectors_match_eth_abi():
    rng = random.Random(243)
    for _ in range(60):
        a = rng.randrange(1 << 256)
        s = "".join(rng.choice("abcxyz") for _ in range(rng.randrange(70)))
        arr = [(rng.randrange(256), bytes(rng.randrange(256) for _ in range(rng.randrange(40))))
               for _ in range(rng.randrange(4))]
        types = ["(uint256,(string,(uint8,bytes)[]))", "bool"]
        values = [(a, (s, arr)), bool(rng.randrange(2))]
        data = eth_abi.encode(types, values)
        assert lists(b.abi_decode(types, data)) == lists(eth_abi.decode(types, data))


def test_tuple_decode_rejects_malformed_and_noncanonical():
    types = ["(uint256,string)"]
    good = eth_abi.encode(types, [(1, "hi")])
    assert b.abi_decode(types, good) is not None
    assert b.abi_decode(types, good + bytes(32)) is None                    # trailing garbage
    assert b.abi_decode(types, good[:-32]) is None                          # truncated tail
    bad = bytearray(good)
    bad[-1] = 1                                                            # non-zero padding after "hi"
    assert b.abi_decode(types, bytes(bad)) is None
    bad = bytearray(good)
    bad[31] = 0x60                                                         # outer offset 0x20 -> 0x60
    assert b.abi_decode(types, bytes(bad)) is None
    # an inner pointer far past the data
    bad = bytearray(good)
    bad[32 + 32 + 31] = 0xFF
    bad[32 + 32 + 30] = 0xFF
    assert b.abi_decode(types, bytes(bad)) is None
    # a dynamic-array length the data cannot hold is refused without allocating it
    arr = ["(uint256,string)[]"]
    huge = (32).to_bytes(32, "big") + (1 << 200).to_bytes(32, "big")
    assert b.abi_decode(arr, huge) is None
    # out-of-range component values are refused like top-level ones
    bad = bytearray(eth_abi.encode(["(uint8,bool)"], [(1, True)]))
    bad[63] = 2                                                            # bool = 2
    assert b.abi_decode(["(uint8,bool)"], bytes(bad)) is None


def test_aliased_pointers_are_bounded_and_rejected():
    # every head word of a string[] points at the same tail: decodes nothing canonical, refused cheaply
    n = 2000
    tail = (1).to_bytes(32, "big") + b"a".ljust(32, b"\0")
    data = (32).to_bytes(32, "big") + n.to_bytes(32, "big") + (n * 32).to_bytes(32, "big") * n + tail
    assert b.abi_decode(["string[]"], data) is None


def test_value_budget_caps_decode_work(monkeypatch):
    types = ["(uint8,string)[]"]
    data = eth_abi.encode(types, [[(i % 256, "v") for i in range(40)]])
    assert len(b.abi_decode(types, data)[0]) == 40
    # 40 tuples of 2 values plus the array and the tuples themselves exceed a budget of 100 decoded values
    monkeypatch.setattr(b, "MAX_ABI_VALUES", 100)
    assert b.abi_decode(types, data) is None
    monkeypatch.setattr(b, "MAX_ABI_VALUES", 200)
    assert b.abi_decode(types, data) is not None


def test_value_budget_charges_string_bytes(monkeypatch):
    # a long string costs one budget unit per 32-byte word copied, so many head words aliased onto one
    # long tail cannot multiply the copying work past the budget
    types = ["(string)[]"]
    data = eth_abi.encode(types, [[("x" * (32 * 150),)]])
    monkeypatch.setattr(b, "MAX_ABI_VALUES", 100)
    assert b.abi_decode(types, data) is None
    monkeypatch.setattr(b, "MAX_ABI_VALUES", 160)
    assert b.abi_decode(types, data) == [[("x" * (32 * 150),)]]
    # aliased: 50 tuples whose string pointers all lead to one 150-word tail exhaust a 1000-unit budget
    k, tail_words = 50, 150
    tail = (32 * tail_words).to_bytes(32, "big") + b"y" * (32 * tail_words)
    heads = b"".join((32 * k).to_bytes(32, "big") for _ in range(k))             # every element -> one tuple
    tup = (32).to_bytes(32, "big")                                              # the tuple: its string at +32
    data = (32).to_bytes(32, "big") + k.to_bytes(32, "big") + heads + tup + tail
    monkeypatch.setattr(b, "MAX_ABI_VALUES", 1000)
    calls = []
    real = b._genc_seq
    monkeypatch.setattr(b, "_genc_seq", lambda *a: calls.append(1) or real(*a))
    assert b.abi_decode(types, data) is None
    assert calls == []                      # refused by the budget during decode, before any re-encode


def test_abi_type_parser_bounds_and_canonical_form():
    assert b.abi_type_str(b.parse_abi_type("((uint256,address)[2],bytes)[]")) == "((uint256,address)[2],bytes)[]"
    for bad in ("()", "(uint256,)", "(uint,address)", "uint256[0]", "uint256[01]", "( uint256)", "tuple",
                "(uint256", "uint256)", "uint7", "bytes33", "(" * 40 + "uint256" + ")" * 40):
        assert b.parse_abi_type(bad) is None, bad


def test_tuple_signature_selector_and_json_abi():
    entry = {"name": "fill", "type": "function", "inputs": [
        {"name": "order", "type": "tuple", "components": [
            {"name": "maker", "type": "address"}, {"name": "amount", "type": "uint256"},
            {"name": "meta", "type": "tuple", "components": [{"name": "memo", "type": "string"}]}]},
        {"name": "sigs", "type": "bytes[]"}]}
    sig = "fill((address,uint256,(string)),bytes[])"
    assert b.signature_of(entry) == sig
    assert b.selector_of_signature(sig) == keccak(sig.encode())[:4]
    abi = b.parse_abi([entry])
    order = ("0x" + "7e" * 20, 10 ** 18, ("gm",))
    calldata = keccak(sig.encode())[:4] + eth_abi.encode(["(address,uint256,(string))", "bytes[]"],
                                                         [order, [b"\x01", b""]])
    fn, args = b.decode_calldata(abi, calldata)
    assert fn["name"] == "fill"
    assert args[0] == ("order", "(address,uint256,(string))", order)
    assert args[1] == ("sigs", "bytes[]", [b"\x01", b""])
    files = {"abi.json": __import__("json").dumps([entry]).encode(), "cd.hex": calldata.hex().encode()}
    # a struct field named by the question
    amount = ask("What is the amount argument in wei?", files)
    assert options(amount)["wei"] == str(10 ** 18)
    assert options(ask("What is the memo parameter?", files)) == {"raw": "gm"}
    maker = ask("What is the maker argument?", files)
    assert options(maker)["checksummed"].lower() == "0x" + "7e" * 20


def test_selector_of_a_tuple_signature_typed_in_the_question():
    sig = "submit((uint256,address)[],bytes32)"
    ans = ask(f"What is the function selector of {sig}?", {})
    assert options(ans)["hex_0x"] == "0x" + keccak(sig.encode())[:4].hex()
    # the prose parenthesis around it is not part of the signature
    ans = ask(f"What is the selector (of {sig})?", {})
    assert options(ans)["hex_0x"] == "0x" + keccak(sig.encode())[:4].hex()


def test_event_with_a_tuple_argument_decodes_and_indexed_tuple_is_a_hash():
    event = {"type": "event", "name": "Filled", "anonymous": False, "inputs": [
        {"name": "who", "type": "address", "indexed": True},
        {"name": "key", "type": "tuple", "indexed": True, "components": [{"name": "k", "type": "uint256"}]},
        {"name": "fill", "type": "tuple", "indexed": False, "components": [
            {"name": "price", "type": "uint256"}, {"name": "note", "type": "string"}]}]}
    sig = "Filled(address,(uint256),(uint256,string))"
    topic0 = keccak(sig.encode())
    who = bytes(12) + bytes.fromhex("5a" * 20)
    log = {"topics": [topic0, who, keccak(eth_abi.encode(["(uint256)"], [(9,)]))],
           "data": eth_abi.encode(["(uint256,string)"], [(777, "ok")])}
    dec = b._decode_event(b.parse_abi([event])["events"][0], log)
    names = {n: v for n, _, v in dec}
    assert names["fill"] == (777, "ok")
    assert names["who"] == "0x" + "5a" * 20
    assert "key" not in names                                   # an indexed tuple is only a hash


# ---------------------------------------------------------------------------- EIP-7702 (type 4)

KEY = b"\x11" * 32
DELEGATE_KEY = b"\x22" * 32
DELEGATE_TO = "0x" + "c0de" * 10


def _signed_7702(auth_count=1, chain=1):
    acct = Account.from_key(KEY)
    auths = [Account.from_key(DELEGATE_KEY).sign_authorization(
        {"chainId": chain, "address": DELEGATE_TO, "nonce": i}) for i in range(auth_count)]
    tx = {"type": 4, "chainId": chain, "nonce": 3, "maxPriorityFeePerGas": 2 * 10 ** 9, "maxFeePerGas": 30 * 10 ** 9,
          "gas": 90000, "to": "0x" + "33" * 20, "value": 5, "data": b"\xa9\x05\x9c\xbb", "accessList": [],
          "authorizationList": auths}
    return acct.sign_transaction(tx)


def test_eip7702_transaction_decodes_against_eth_account():
    signed = _signed_7702()
    tx = b.decode_evm_tx(bytes(signed.raw_transaction))
    assert tx is not None
    assert tx["type"] == 4 and tx["chain_id"] == 1 and tx["nonce"] == 3
    assert tx["max_priority_fee"] == 2 * 10 ** 9 and tx["max_fee"] == 30 * 10 ** 9
    assert tx["gas_limit"] == 90000 and tx["value"] == 5 and tx["selector"] == "a9059cbb"
    assert tx["hash"] == bytes(signed.hash).hex()
    assert tx["from"] == Account.from_key(KEY).address.lower()[2:]
    assert tx["to"] == "33" * 20 and tx["creation"] is False
    assert len(tx["authorizations"]) == 1
    auth = tx["authorizations"][0]
    assert auth["address"] == DELEGATE_TO[2:] and auth["chain_id"] == 1 and auth["nonce"] == 0
    assert auth["authority"] == Account.from_key(DELEGATE_KEY).address.lower()[2:]


def test_eip7702_questions():
    files = {"tx.txt": ("0x" + bytes(_signed_7702().raw_transaction).hex()).encode()}
    ty = ask("What is the transaction type?", files)
    assert options(ty)["name"] == "eip7702" and options(ty)["number"] == "4"
    assert key(ty).startswith("blockchain.tx_type/eip7702")
    delegate = ask("Which address does the EOA delegate to?", files)
    assert options(delegate)["lowercase"] == DELEGATE_TO
    authority = ask("Who signed the authorization?", files)
    assert options(authority)["lowercase"] == Account.from_key(DELEGATE_KEY).address.lower()
    sender = ask("Which address sent this transaction?", files)
    assert options(sender)["lowercase"] == Account.from_key(KEY).address.lower()
    assert options(ask("How many authorizations does it carry?", files)) == {"decimal": "1"}
    two = {"tx.txt": ("0x" + bytes(_signed_7702(auth_count=2).raw_transaction).hex()).encode()}
    assert options(ask("How many authorizations does it carry?", two)) == {"decimal": "2"}
    assert ask("Which address does the EOA delegate to?", two) is None      # which one is not said


def _sign(h32, d, k):
    z = int.from_bytes(h32, "big")
    R = b._mul(k, b._G)
    r = R[0] % b._N
    s = pow(k, -1, b._N) * (z + r * d) % b._N
    rec = R[1] & 1
    if s > b._N // 2:
        s, rec = b._N - s, rec ^ 1
    return r, s, rec


def _raw7702(auths, to=b"\x33" * 20):
    body = [1, 0, 1, 2, 21000, to, 0, b"", [], auths]
    r, s, rec = _sign(b.keccak(b"\x04" + b.rlp_encode(body)), 0x1234, 0x777)
    return b"\x04" + b.rlp_encode(body + [rec, r, s])


def test_eip7702_rejections():
    one_auth = [[1, b"\x44" * 20, 0, 0, 5, 7]]
    assert b.decode_evm_tx(_raw7702(one_auth)) is not None
    assert b.decode_evm_tx(_raw7702([])) is None                             # empty authorization list
    assert b.decode_evm_tx(_raw7702(one_auth, to=b"")) is None               # 7702 cannot create a contract
    assert b.decode_evm_tx(_raw7702([[1, b"\x44" * 19, 0, 0, 5, 7]])) is None  # short delegate address
    assert b.decode_evm_tx(_raw7702([[1, b"\x44" * 20, 0, 0, 5]])) is None    # 5-field authorization
    # an authorization whose s is in the upper half has no authority (EIP-7702 rejects it), the tx still decodes
    high_s = b.decode_evm_tx(_raw7702([[1, b"\x44" * 20, 0, 0, 5, b._N - 7]]))
    assert high_s["authorizations"][0]["authority"] is None
    # a type byte past 4 is still not a transaction this module decodes
    assert b.decode_evm_tx(b"\x05" + _raw7702(one_auth)[1:]) is None


def test_eip7702_high_s_twin_of_a_real_authorization_has_no_authority():
    # (r, N-s, y^1) recovers the same public key as (r, s, y): only the EIP's low-s rule can refuse it
    d = 0xC0FFEE
    addr = b"\x44" * 20
    h = keccak(b"\x05" + b.rlp_encode([1, addr, 3]))
    r, s, rec = _sign(h, d, 0x5151)
    assert s <= b._N // 2
    want = b.pub_to_address(b._mul(d, b._G)).hex()
    hi_s, hi_rec = b._N - s, rec ^ 1
    # the twin is a valid secp256k1 signature of the same key (checked independently of this module)
    assert Account._recover_hash(h, vrs=(hi_rec, r, hi_s)).lower()[2:] == want
    tx = b.decode_evm_tx(_raw7702([[1, addr, 3, rec, r, s], [1, addr, 3, hi_rec, r, hi_s]]))
    assert tx["authorizations"][0]["authority"] == want
    assert tx["authorizations"][1]["authority"] is None


def test_eip7702_authority_matches_an_independent_recovery():
    d = 0xBEEF
    addr = b"\x44" * 20
    h = keccak(b"\x05" + b.rlp_encode([1, addr, 9]))
    r, s, rec = _sign(h, d, 0x4242)
    tx = b.decode_evm_tx(_raw7702([[1, addr, 9, rec, r, s]]))
    want = Account._recover_hash(h, vrs=(rec, r, s)).lower()[2:]
    assert tx["authorizations"][0]["authority"] == want
    assert want == b.pub_to_address(b._mul(d, b._G)).hex()
