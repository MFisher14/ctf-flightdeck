"""Independent vector locks and bounded fuzz for the existing EVM auditors.

Oracles: pyevmasm 0.2.3; solidity-parser 0.1.1 lexer/AST; EIP-1967's
published slots; EIP-3855/1153/5656 opcode assignments; Solidity's published
storage packing and tx.origin examples. No engine output constructs an oracle.

These legacy modules have no custom exception class. Their explicit validation
exceptions (ValueError, and evm_audit's TypeError) are the local contracts; tests
still detect incidental KeyError, AttributeError, OverflowError and SystemExit.
"""
from collections import Counter
import json
import random

from antlr4 import InputStream
import pyevmasm
import pytest
from solidity_parser import parser as solidity_parser
from solidity_parser.solidity_antlr4.SolidityLexer import SolidityLexer

import evm_audit as audit
import evm_security as security


SOURCE = '''pragma solidity ^0.8.0;
contract Wallet {
    address owner;
    string label = "CSCTF{source_vector}";
    // tx.origin and selfdestruct inside comments are not instructions.
    function transfer(address target, uint amount) public {
        require(tx.origin == owner);
        target.transfer(amount);
    }
    function plus(uint x) public pure returns (uint) { return x + 1; }
}
'''
BYTECODE = bytes.fromhex("60016002015b3260ff14f455ff")
IMPLEMENTATION_SLOT = int("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)
ADMIN_SLOT = int("b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", 16)


def oracle_instructions(code):
    return [dict(offset=x.pc, opcode=x.opcode, name=x.name,
                 immediate=x.operand.to_bytes(x.operand_size, "big").hex() if x.operand_size else "",
                 truncated=False) for x in pyevmasm.disassemble_all(code)]


def oracle_mask(source):
    chars = list(source)
    lexer = SolidityLexer(InputStream(source))
    for token in lexer.getAllTokens():
        if token.type in (SolidityLexer.COMMENT, SolidityLexer.LINE_COMMENT,
                          SolidityLexer.StringLiteralFragment):
            for i in range(token.start, token.stop + 1):
                if chars[i] != "\n":
                    chars[i] = " "
    return "".join(chars)


def oracle_functions(source):
    tree = solidity_parser.parse(source, loc=True)
    return [node for contract in tree["children"] if contract["type"] == "ContractDefinition"
            for node in contract["subNodes"] if node["type"] == "FunctionDefinition"]


def clean_call(fn, *args, allowed=(ValueError, TypeError), **kwargs):
    try:
        return fn(*args, **kwargs)
    except BaseException as exc:
        assert type(exc) in allowed, f"leaked {type(exc).__name__}: {exc}"
        return None


@pytest.mark.parametrize("source", [SOURCE, "contract C{string x='a\\\'b';/*x\ny*/}",
                                    "// comment\ncontract C{}", "contract C{}"])
def test_sanitize_matches_independent_solidity_lexer(source):
    assert audit.sanitize_solidity(source) == oracle_mask(source)


def test_solidity_function_offsets_and_names_match_independent_ast():
    expected = oracle_functions(SOURCE)
    actual = audit.solidity_functions(oracle_mask(SOURCE))
    assert [x["name"] for x in actual] == [x["name"] for x in expected]
    assert [SOURCE.count("\n", 0, x["start"]) + 1 for x in actual] == [x["loc"]["start"]["line"] for x in expected]
    for row in actual:
        assert SOURCE[row["body_start"] - 1] == "{" and SOURCE[row["end"] - 1] == "}"


def test_source_analysis_uses_ast_function_and_state_facts():
    result = audit.analyze_solidity_source(SOURCE)
    expected = oracle_functions(SOURCE)
    contracts = [x for x in solidity_parser.parse(SOURCE)["children"] if x["type"] == "ContractDefinition"]
    variables = [v["name"] for c in contracts for node in c["subNodes"]
                 if node["type"] == "StateVariableDeclaration" for v in node["variables"]]
    assert result["functions"] == [{"name": x["name"], "line": x["loc"]["start"]["line"]} for x in expected]
    assert result["state_variables"] == sorted(variables)
    assert result["pragma_overflow_checked"] is True
    assert [(x["kind"], x["line"]) for x in result["findings"] if x["kind"] == "tx-origin-auth"] == [("tx-origin-auth", 7)]


def test_security_source_published_tx_origin_pattern_and_no_verdict():
    # Solidity security-considerations.html#tx-origin publishes this comparison.
    result = security.analyze_source(SOURCE)
    findings = result["findings"]
    assert [(x["kind"], x["evidence"]["line"]) for x in findings] == [("tx-origin-auth", 7)]
    assert result["source_bytes"] == len(SOURCE.encode())
    assert result["vulnerability_verdict"] is None
    assert all(not x["vulnerability_verified"] for x in findings)


@pytest.mark.parametrize("value", [BYTECODE, bytearray(BYTECODE), BYTECODE.hex(), "0x" + BYTECODE.hex(),
                                   "0X" + " \n".join(BYTECODE.hex()[i:i + 2] for i in range(0, len(BYTECODE.hex()), 2))])
def test_bytecode_parse_and_disassembly_match_external_library(value):
    assert audit.parse_bytecode(value) == BYTECODE
    assert audit.disassemble(value) == oracle_instructions(BYTECODE)


def test_published_modern_opcode_assignments():
    # https://eips.ethereum.org/EIPS/eip-{3855,1153,5656}
    rows = audit.disassemble(bytes.fromhex("5c5d5e5f00"))
    assert [(x["offset"], x["name"], x["immediate"]) for x in rows] == [
        (0, "TLOAD", ""), (1, "TSTORE", ""), (2, "MCOPY", ""), (3, "PUSH0", ""), (4, "STOP", "")]


def test_basic_blocks_use_independently_disassembled_input():
    # JUMPI at 2 has a valid target JUMPDEST at 6 and fallthrough at 3.
    rows = oracle_instructions(bytes.fromhex("6006576000565b00"))
    blocks = audit.basic_blocks(rows)
    assert [(x["start"], x["end"], x["edges"]) for x in blocks] == [(0, 2, [3, 6]), (3, 5, [0]), (6, 7, [])]


def test_dispatch_selector_from_erc20_published_transfer_signature():
    # ERC20 transfer(address,uint256) selector a9059cbb, independently encoded.
    rows = oracle_instructions(bytes.fromhex("63a9059cbb14600a57005b00"))
    assert audit.function_selectors(rows) == [{"selector": "0xa9059cbb", "destination": 10, "offset": 0}]


def test_audit_bytecode_facts_match_independent_disassembler():
    rows = oracle_instructions(BYTECODE)
    result = audit.analyze_evm_bytecode(BYTECODE)
    assert result["size"] == len(BYTECODE)
    assert result["instruction_count"] == len(rows)
    assert result["opcodes"] == dict(Counter(x["name"] for x in rows))
    assert {x["offset"] for x in result["findings"] if x["kind"] == "selfdestruct"} == {12}


def test_security_bytecode_facts_and_eip1967_published_slots():
    assert security.EIP1967_IMPLEMENTATION == IMPLEMENTATION_SLOT
    assert security.EIP1967_ADMIN == ADMIN_SLOT
    code = b"\x7f" + IMPLEMENTATION_SLOT.to_bytes(32, "big") + b"\x54\x7f" + ADMIN_SLOT.to_bytes(32, "big") + b"\x54\x00"
    result = security.analyze_bytecode(code)
    assert result["length"] == len(code)
    assert result["instruction_count"] == len(oracle_instructions(code))
    assert {x["evidence"] for x in result["findings"] if x["kind"] == "eip1967-slot"} == {
        f"{IMPLEMENTATION_SLOT:064x}", f"{ADMIN_SLOT:064x}"}
    assert result["vulnerability_verdict"] is None


def test_storage_packing_published_solidity_example():
    # Solidity layout_in_storage.html: uint16 g/h share slot 45 at offsets 0/2.
    left = [{"label": "g", "slot": "45", "offset": 0, "bytes": 2, "type": "uint16"},
            {"label": "h", "slot": "45", "offset": 2, "bytes": 2, "type": "uint16"}]
    right = [{"label": "counter", "slot": "45", "offset": 1, "bytes": 2, "type": "uint16"}]
    collisions = security.compare_storage_layout(left, right)["collisions"]
    assert {(x["proxy"]["label"], x["implementation"]["label"]) for x in collisions} == {("g", "counter"), ("h", "counter")}
    assert all(x["overlap_verified"] and not x["vulnerability_verified"] for x in collisions)


def test_artifact_router_and_cli_vectors(tmp_path, capsys):
    code_path = tmp_path / "code.bin"
    code_path.write_bytes(BYTECODE)
    source_path = tmp_path / "Wallet.sol"
    source_path.write_text(SOURCE)
    assert audit.analyze_artifact(BYTECODE)["opcodes"] == dict(Counter(x["name"] for x in oracle_instructions(BYTECODE)))
    assert audit.analyze_artifact(SOURCE.encode(), "Wallet.sol")["functions"][0]["name"] == oracle_functions(SOURCE)[0]["name"]
    assert audit.main([str(code_path)]) == 0
    assert json.loads(capsys.readouterr().out)["instruction_count"] == len(oracle_instructions(BYTECODE))
    assert security.main(["source", str(source_path)]) == 0
    assert json.loads(capsys.readouterr().out)["source_bytes"] == len(SOURCE.encode())


@pytest.mark.parametrize("fn", [audit.sanitize_solidity, audit.solidity_functions, audit.analyze_solidity_source,
                                 security.analyze_source])
def test_deterministic_source_fuzz(fn):
    rng = random.Random(196755)
    for text in ["", "/*", '"\\', "\0", "\ud800", *[rng.randbytes(n).decode("latin1") for n in range(80)]]:
        clean_call(fn, text)


@pytest.mark.parametrize("fn", [audit.parse_bytecode, audit.disassemble, audit.analyze_evm_bytecode,
                                 audit.analyze_artifact, security.analyze_bytecode])
def test_deterministic_binary_fuzz(fn):
    rng = random.Random(38551153)
    for data in [b"", b"\x7f", b"\x60", b"\xff", *[rng.randbytes(n) for n in range(100)]]:
        clean_call(fn, data)


@pytest.mark.parametrize("fn", [audit.basic_blocks, audit.function_selectors])
def test_instruction_list_empty_and_random_valid_structure_fuzz(fn):
    rng = random.Random(5656)
    clean_call(fn, [])
    for _ in range(50):
        rows = oracle_instructions(b"".join(rng.choice((b"\0", b"\x5b", b"\x32", b"\x60\x00", b"\x63\x12\x34\x56\x78")) for _ in range(8)))
        clean_call(fn, rows)


def test_storage_layout_empty_and_malformed_fuzz():
    for value in (None, "", b"", 1, [], {}, [None], [{}], [{"slot": "-1"}], [{"slot": "0", "bytes": 33}]):
        clean_call(security.compare_storage_layout, value, [], allowed=(ValueError,))
    rng = random.Random(1967)
    for _ in range(100):
        left = [{"slot": str(rng.randrange(-2, 5)), "offset": rng.randrange(-2, 34), "bytes": rng.randrange(-1, 34)}]
        clean_call(security.compare_storage_layout, left, [], allowed=(ValueError,))


def test_bug_pragma_exclusive_upper_bound_is_not_checked_arithmetic():
    assert audit.analyze_solidity_source("pragma solidity <0.8.0; contract C{} ")["pragma_overflow_checked"] is False


def test_bug_shifted_same_named_storage_field_is_collision():
    left = [{"slot": "0", "offset": 0, "bytes": 16, "label": "value", "type": "uint128"}]
    right = [{"slot": "0", "offset": 8, "bytes": 16, "label": "value", "type": "uint128"}]
    assert len(security.compare_storage_layout(left, right)["collisions"]) == 1


@pytest.mark.parametrize("fn", [audit.basic_blocks, audit.function_selectors])
def test_bug_missing_instruction_fields_leak_keyerror(fn):
    clean_call(fn, [{}])


def test_bug_artifact_nonbytes_type_leaks_attributeerror():
    clean_call(audit.analyze_artifact, "6000")


def test_bug_infinite_storage_offset_leaks_overflowerror():
    clean_call(security.compare_storage_layout, [{"slot": "0", "offset": float("inf")}], [], allowed=(ValueError,))


@pytest.mark.parametrize("fn", [audit.main, security.main])
def test_bug_main_help_leaks_systemexit(fn):
    assert clean_call(fn, ["--help"], allowed=()) == 0


def test_bug_audit_main_missing_file(tmp_path):
    assert clean_call(audit.main, [str(tmp_path / "absent")], allowed=()) == 2


def test_security_cli_malformed_inputs_are_return_codes(tmp_path, capsys):
    assert security.main([]) == 2
    assert security.main(["source", str(tmp_path / "absent")]) == 2
    malformed = tmp_path / "broken.json"
    malformed.write_text('{"x":')
    assert security.main(["layout", str(malformed), str(malformed)]) == 2


@pytest.mark.parametrize("constraint,checked", [
    ("^0.8.0", True), (">=0.8.0 <0.9.0", True), ("0.8.20", True),
    ("^0.8.0 || ^0.9.0", True), ("^0.7.6", False), ("<0.9.0", False),
    (">=0.7.0 <0.9.0", False), ("<0.8.0 || ^0.8.0", False),
])
def test_compiler_range_lower_bound_regression(constraint, checked):
    result = audit.analyze_solidity_source(f"pragma solidity {constraint}; contract C {{}}")
    assert result["pragma_overflow_checked"] is checked


def test_identical_storage_field_remains_compatible():
    layout = [{"slot": "0", "offset": 8, "bytes": 16, "label": "value", "type": "uint128"}]
    result = security.compare_storage_layout(layout, layout)
    assert result["collisions"] == []
    assert result["safe_verdict"] is None


@pytest.mark.parametrize("fn", [audit.basic_blocks, audit.function_selectors])
@pytest.mark.parametrize("rows", [None, {}, [None], [{"offset": 0}],
                                  [{"offset": 0, "name": "PUSH1", "immediate": "gg"}],
                                  [{"offset": 0, "name": "PUSH1", "immediate": "0000"}]])
def test_instruction_fields_fail_closed_without_builtin_access_errors(fn, rows):
    with pytest.raises(ValueError):
        fn(rows)


@pytest.mark.parametrize("fn", [audit.main, security.main])
def test_cli_noninteger_systemexit_returns_error(monkeypatch, fn):
    def exit_string(*args, **kwargs):
        raise SystemExit("invalid status")
    monkeypatch.setattr(audit.argparse.ArgumentParser, "parse_args", exit_string)
    assert fn([]) == 2
