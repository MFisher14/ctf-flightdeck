"""External vector locks and deterministic fuzz for blockchain report APIs.

Oracles: pyevmasm assembler/disassembler; cbor2 encoder; EIP-1167's exact
published proxy; EIP-55's published address. Router tests are explicitly
contract locks (routing is an application policy, not a protocol oracle).
No engine output is used to prepare expected values or another test's input.
"""
import json
import random

import cbor2
import pyevmasm
import pytest

import blockchain as chain


EIP55 = "0x52908400098527886E0F7030069857D2E4169EE7"
# https://eips.ethereum.org/EIPS/eip-1167, exact standard clone bytecode.
PROXY = bytes.fromhex("363d3d373d3d3d363d73" + "be" * 20 + "5af43d82803e903d91602b57fd5bf3")


def asm(text):
    return bytes.fromhex(pyevmasm.assemble_hex(text).removeprefix("0x"))


def independent_rows(data):
    result = []
    for row in pyevmasm.disassemble_all(data):
        name = "KECCAK256" if row.name == "SHA3" else row.name
        immediate = row.operand.to_bytes(row.operand_size, "big") if row.operand_size else None
        result.append((row.pc, row.opcode, name, immediate))
    return result


def metadata_code(ipfs=False):
    values = {"solc": bytes([0, 8, 20])}
    if ipfs:
        values["ipfs"] = b"\x12\x20" + bytes(range(32))
    metadata = cbor2.dumps(values)
    body = asm("PUSH1 0x2a\nPOP\nSTOP")
    return body + metadata + len(metadata).to_bytes(2, "big"), body, metadata


def clean_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except chain._Bad:
        return None
    except BaseException as exc:
        pytest.fail(f"undeclared {type(exc).__name__}: {exc}")


def test_disassemble_published_eip1167_proxy():
    assert chain.disassemble(PROXY) == independent_rows(PROXY)
    assert len(PROXY) == 45
    assert PROXY[10:30] == bytes.fromhex("be" * 20)


def test_disassemble_independent_assembler_and_hash_mnemonic():
    code = asm("PUSH1 0x2a\nDUP1\nPUSH1 0x00\nMSTORE\nPUSH1 0x20\nPUSH1 0x00\nSHA3\nSTOP")
    assert chain.disassemble(code) == independent_rows(code)


def test_solc_metadata_cbor_library_vector():
    code, _body, metadata = metadata_code()
    assert chain.solc_metadata(code) == (len(metadata) + 2, {"solc": "0.8.20", "keys": ["solc"]})


def test_split_creation_with_independent_assembler():
    runtime = asm("PUSH1 0x2a\nPOP\nSTOP")
    # PUSH1 length; DUP1; PUSH1 offset; zero; CODECOPY; zero; RETURN.
    init = asm(f"PUSH1 {len(runtime)}\nDUP1\nPUSH1 9\nRETURNDATASIZE\nCODECOPY\nRETURNDATASIZE\nRETURN")
    assert len(init) == 9
    code = init + runtime
    assert chain.split_creation(code) == (9, len(runtime))
    assert chain.split_creation(code[:-1]) is None
    report = chain.bytecode_report(code)
    assert (report["creation"], report["runtime_offset"], report["runtime_length"]) == (True, 9, len(runtime))
    assert report["n_instructions"] == len(independent_rows(runtime))


def test_dispatch_table_independently_encoded_selectors():
    # ERC20 transfer(address,uint256), balanceOf(address), no registry lookups.
    code = asm("PUSH4 0xa9059cbb\nEQ\nPUSH1 0x20\nJUMPI\n"
               "PUSH4 0x70a08231\nDUP2\nEQ\nPUSH1 0x30\nJUMPI\nSTOP")
    assert chain.dispatch_table(code) == [("a9059cbb", 32), ("70a08231", 48)]
    assert chain.dispatch_table(code + code) == [("a9059cbb", 32), ("70a08231", 48)]


def test_push_strings_independent_assembler_literal():
    text = b"CSCTF{push_vector}"
    code = asm(f"PUSH{len(text)} 0x{text.hex()}\nPOP\nSTOP")
    assert chain.push_strings(code) == [text.decode()]
    assert chain.push_strings(code, minlen=len(text) + 1) == []


def test_report_published_proxy_and_library_metadata():
    report = chain.bytecode_report(PROXY)
    assert report["total_length"] == 45
    assert report["creation"] is False and report["metadata"] is False
    assert report["n_instructions"] == len(independent_rows(PROXY))
    code, body, _ = metadata_code()
    report = chain.bytecode_report(code)
    assert report["solc"] == "0.8.20" and report["metadata"] is True
    assert report["n_instructions"] == len(independent_rows(body))


def test_read_artifacts_eip55_and_cbor_tailed_code():
    rows = chain.read_artifacts({"address.txt": EIP55.encode()})
    assert len(rows) == 1
    assert rows[0]["kind"] == "eth_address"
    assert rows[0]["obj"]["bytes"] == bytes.fromhex(EIP55[2:])
    assert rows[0]["obj"]["checksummed"] == EIP55
    # A standard prologue is an explicit recognition rule for bytecode artifacts.
    raw = asm("PUSH1 0x80\nPUSH1 0x40\nMSTORE\nSTOP")
    rows = chain.read_artifacts({"code.json": json.dumps({"bytecode": raw.hex()}).encode()})
    assert [(x["kind"], x["obj"]["code"]) for x in rows] == [("bytecode", raw)]


@pytest.mark.parametrize("question,expected", [
    ("Is this checksum valid?", {"checksum_valid"}),
    ("Give the EIP-55 checksum address", {"checksum_form"}),
    ("what is the function selector?", {"selector"}),
    ("what is the first argument value?", {"arg_n"}),
    ("How many instructions?", {"n_insns"}),
    ("", set()),
])
def test_route_contract_lock(question, expected):
    assert chain.route({"question": question}) == expected


def test_solve_set_contract_lock_no_evidence_no_answer():
    context = {"partial": {"kept": "existing"}}
    assert chain.solve_set([{"qid": "x", "question": "What is the transaction hash?"}], {}, context) == {"x": None}
    assert context == {"partial": {"kept": "existing"}}
    assert chain.solve_set([], {}, {}) == {}


def test_signals_contract_lock_requires_recognized_evidence():
    question = [{"question": "Ethereum EIP-55 checksum address"}]
    assert chain.signals(question, {}) == 0.0
    assert chain.signals(question, {"noise": b"not an artifact"}) == 0.0
    assert 0.0 < chain.signals(question, {"address.txt": EIP55.encode()}) <= 1.0
    assert chain.signals([], {}) == 0.0


def test_main_eip55_and_unrecognized_file(tmp_path, capsys):
    path = tmp_path / "address.txt"
    path.write_text(EIP55)
    assert chain.main([str(path)]) == 0
    assert EIP55 in capsys.readouterr().out
    path.write_bytes(b"not an artifact")
    assert chain.main([str(path)]) == 0
    assert "no EVM or Bitcoin artifact recognised" in capsys.readouterr().out
    assert chain.main([]) == 2
    assert chain.main([str(tmp_path / "missing")]) == 0


@pytest.mark.parametrize("operation", ["wallet", "keystore", "slot", "wif", "brainwallet"])
def test_wallet_cli_help_returns_status(operation, capsys):
    assert chain.main([operation, "--help"]) == 0
    assert "usage:" in capsys.readouterr().out


@pytest.mark.parametrize("fn", [chain.disassemble, chain.solc_metadata, chain.split_creation,
                                 chain.dispatch_table, chain.push_strings, chain.bytecode_report])
def test_binary_api_deterministic_fuzz(fn):
    rng = random.Random(116755)
    for data in [b"", b"\0", b"\x7f", b"\xff", *[rng.randbytes(n) for n in range(90)]]:
        clean_call(fn, data)


def test_artifact_and_router_deterministic_fuzz():
    rng = random.Random(1967)
    for n in range(60):
        data = rng.randbytes(n)
        files = {"sample": data}
        question = {"qid": "x", "question": data.decode("latin1")}
        clean_call(chain.read_artifacts, files)
        clean_call(chain.route, question)
        clean_call(chain.solve_set, [question], files, {})
        clean_call(chain.signals, [question], files)
    for files in (None, {}, [], {"x": None}, {"x": 42}, {"x": "text"}):
        clean_call(chain.read_artifacts, files)


@pytest.mark.parametrize("entrypoint", ["solc_metadata", "bytecode_report"])
def test_bug_standard_solidity_ipfs_metadata(entrypoint):
    code, _, metadata = metadata_code(ipfs=True)
    if entrypoint == "solc_metadata":
        assert chain.solc_metadata(code) == (len(metadata) + 2, {"solc": "0.8.20", "keys": ["ipfs", "solc"]})
    else:
        assert chain.bytecode_report(code)["solc"] == "0.8.20"


@pytest.mark.parametrize("name,args", [
    ("disassemble", (None,)), ("solc_metadata", (None,)), ("split_creation", (None,)),
    ("dispatch_table", (None,)), ("push_strings", (None,)), ("bytecode_report", (123,)),
    ("route", (None,)), ("solve_set", ([None], {}, {})),
    ("signals", ([None], {})), ("main", (None,)),
])
def test_bug_malformed_api_shape_leaks_builtin(name, args):
    clean_call(getattr(chain, name), *args)
