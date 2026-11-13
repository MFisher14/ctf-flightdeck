"""Deterministic tests for bounded static deobfuscation."""

from __future__ import annotations

import ast
import base64
import sys
from pathlib import Path
import zlib

import pytest


REPO = Path(__file__).resolve().parents[1]
BINARY = REPO / "solvers" / "binary"
sys.path.insert(0, str(BINARY))

import deobfuscation as deob  # noqa: E402


def test_language_and_obfuscation_detection_is_evidence_ordered():
    source = """
const x = String.fromCharCode(82,53,68);
const y = atob('Uk9VTkQ1');
eval(x + y);
"""
    assert deob.detect_languages(source) == ("javascript",)
    findings = deob.detect_obfuscation(source)
    assert [row.technique for row in findings] == ["string_array", "dynamic_eval"]
    assert [row.offset for row in findings] == sorted(row.offset for row in findings)
    assert all(row.next_step.endswith(".") for row in findings)


def test_javascript_constant_recovery_handles_char_base64_and_escapes():
    source = r'''
const a = String.fromCharCode(82,53,68);
const b = atob("Uk9VTkQ1");
const c = "\x48\x69\u0021";
'''
    rows = deob.recover_constant_strings(source, "javascript")
    got = {(row.technique, row.value) for row in rows}
    assert ("character_constants", "R5D") in got
    assert ("base64_literal", "ROUND5") in got
    assert ("escaped_literal", "Hi!") in got
    assert all(row.to_dict()["offline"] and not row.to_dict()["executed"] for row in rows)


def test_php_layers_rot13_and_character_calls_are_bounded():
    payload = b"<?php echo 'ROUND5'; ?>"
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    raw = compressor.compress(payload) + compressor.flush()
    encoded = base64.b64encode(raw).decode("ascii")
    source = (
        f"<?php $x=gzinflate(base64_decode('{encoded}')); "
        "$y=str_rot13('EBHAQ5'); $z=chr(82).chr(53).chr(68); ?>"
    )
    rows = deob.recover_constant_strings(source, "php")
    got = {(row.technique, row.value) for row in rows}
    assert ("base64_gzinflate", payload.decode()) in got
    assert ("rot13_literal", "ROUND5") in got
    assert ("character_constants", "R5D") in got


def test_powershell_vba_and_dotnet_constant_recovery():
    command = "Write-Output ROUND5"
    encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
    ps = f"powershell -EncodedCommand {encoded}; IEX ([char]82+[char]53+[char]68)"
    ps_rows = deob.recover_constant_strings(ps, "powershell")
    assert ("encoded_command", command) in {(row.technique, row.value) for row in ps_rows}
    assert ("character_constants", "R5D") in {(row.technique, row.value) for row in ps_rows}

    vba = 'Sub X(): a = Chr(82) & ChrW(53) & Chr(68): b=StrReverse("5DNUOR"): End Sub'
    vba_rows = deob.recover_constant_strings(vba, "vba")
    assert {row.value for row in vba_rows} >= {"R5D", "ROUND5"}

    blob = base64.b64encode(b"ROUND5").decode("ascii")
    dotnet = f'var x=Convert.FromBase64String("{blob}"); var y=new char[]{{(char)82,(char)53,(char)68}};'
    dotnet_rows = deob.recover_constant_strings(dotnet, "dotnet")
    assert {row.value for row in dotnet_rows} >= {"ROUND5", "R5D"}


def test_explicit_string_cipher_reversal_has_no_guessing():
    plain = b"ROUND5"
    key = b"KEY"
    xor = bytes(value ^ key[index % len(key)] for index, value in enumerate(plain))
    assert deob.reverse_string_cipher(xor, scheme="repeating_xor", key=key) == plain

    added = bytes((value + 7) & 0xFF for value in plain)
    assert deob.reverse_string_cipher(added, scheme="add", key=7) == plain
    subtracted = bytes((value - 7) & 0xFF for value in plain)
    assert deob.reverse_string_cipher(subtracted, scheme="sub", key=7) == plain

    encrypted = deob.reverse_string_cipher(
        plain, scheme="rolling_xor", key=1, seed=3, multiplier=17, increment=9
    )
    assert deob.reverse_string_cipher(
        encrypted, scheme="rolling_xor", key=1, seed=3, multiplier=17, increment=9
    ) == plain
    with pytest.raises(deob.DeobfuscationInputError, match="unsupported"):
        deob.reverse_string_cipher(plain, scheme="aes", key=b"known")


def test_constant_xor_array_recovery_is_language_specific_and_literal_only():
    js = "const decoded = [114,21,100].map(x => x ^ 0x20);"
    rows = deob.recover_xor_array_strings(js, "javascript")
    assert [(row.technique, row.value, row.encoding) for row in rows] == [
        ("xor_numeric_array", "R5D", "utf-8+xor-0x20")
    ]
    combined = deob.recover_constant_strings(js, "javascript")
    assert any(row.technique == "xor_numeric_array" and row.value == "R5D" for row in combined)

    dynamic = "const decoded = values.map(x => x ^ runtimeKey);"
    assert deob.recover_xor_array_strings(dynamic, "javascript") == ()


def test_nested_constant_layers_are_peeled_breadth_first_with_parentage():
    inner = "const result = String.fromCharCode(82,53,68);"
    outer = f'const stage = atob("{base64.b64encode(inner.encode()).decode()}");'
    rows = deob.peel_constant_layers(outer, language="javascript", max_depth=3)
    assert [(row.depth, row.technique, row.value, row.parent) for row in rows] == [
        (1, "base64_literal", inner, None),
        (2, "character_constants", "R5D", 0),
    ]
    with pytest.raises(deob.DeobfuscationInputError, match="max_depth"):
        deob.peel_constant_layers(outer, max_depth=0)


def test_control_flow_flattening_recovery_builds_graph_and_readable_ir():
    supplied = """
state = 0x10;
while (running) {
  switch (state) {
    case 0x10:
      first();
      state = 0x20;
      break;
    case 0x20:
      if (flag) state = 0x30; else state = 0x40;
      break;
    case 0x30:
      return good;
    case 0x40:
      throw bad;
    case 0x99:
      dead();
      return;
  }
}
"""
    result = deob.recover_flattened_switch(supplied)
    assert result.entry == 0x10
    assert [block.label for block in result.blocks] == [0x10, 0x20, 0x30, 0x40, 0x99]
    assert result.blocks[0].successors == (0x20,)
    assert result.blocks[1].successors == (0x30, 0x40)
    assert result.reachable == (0x10, 0x20, 0x30, 0x40)
    assert result.unreachable == (0x99,)
    assert result.linear_prefix == (0x10, 0x20)
    assert result.external_targets == ()
    assert "block_0x10:" in result.readable_ir
    assert "branch block_0x30, block_0x40" in result.readable_ir

    external = deob.recover_flattened_switch(
        "state=1;\ncase 1:\n state=2; break;\n", state_variable="state"
    )
    assert external.external_targets == (2,)
    assert external.reachable == (1,)


def test_opaque_predicates_are_literal_proofs_only():
    supplied = """
if (1 == 1) yes();
if ((x ^ x) == 0) yes2();
if (n * (n + 1) % 2 == 0) yes3();
if (unknown(x)) maybe();
"""
    rows = deob.find_opaque_predicates(supplied)
    assert [row.technique for row in rows] == [
        "constant_true",
        "self_xor_zero",
        "consecutive_product_even",
    ]
    assert all("proven outcome" in row.next_step for row in rows)


def test_combined_report_never_claims_execution():
    source = "state=1; switch(state) {\ncase 1:\n state=2; break;\ncase 2:\n return;\n}\n"
    report = deob.deobfuscate_source(source, language="javascript", state_variable="state")
    serialized = report.to_dict()
    assert serialized["offline"] is True and serialized["executed"] is False
    assert report.control_flow is not None
    assert report.control_flow.linear_prefix == (1, 2)
    assert isinstance(report.decoded_layers, tuple)


def test_caps_duplicates_and_invalid_inputs_fail_closed():
    with pytest.raises(deob.DeobfuscationInputError, match="exceeds"):
        deob.detect_obfuscation("x" * (deob.MAX_SOURCE + 1))
    with pytest.raises(deob.DeobfuscationInputError, match="unsupported language"):
        deob.recover_constant_strings("text", "perl")
    with pytest.raises(deob.DeobfuscationInputError, match="duplicate"):
        deob.recover_flattened_switch("case 1:\nstate=2;\ncase 1:\nreturn;")
    with pytest.raises(deob.DeobfuscationInputError, match="identifier"):
        deob.recover_flattened_switch("case 1: return;", state_variable="x;evil")
    cases = "\n".join(f"case {index}: state={index + 1};" for index in range(deob.MAX_CASES + 1))
    with pytest.raises(deob.DeobfuscationInputError, match="cases"):
        deob.recover_flattened_switch(cases)


def test_module_has_no_runtime_loader_process_network_or_dynamic_execution():
    tree = ast.parse((BINARY / "deobfuscation.py").read_text(encoding="utf-8"))
    imports: set[str] = set()
    direct_calls: set[str] = set()
    attribute_calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                direct_calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                attribute_calls.add(node.func.attr)
    assert not imports.intersection(
        {"socket", "requests", "urllib.request", "subprocess", "marshal", "pickle", "importlib", "runpy"}
    )
    assert not direct_calls.intersection({"eval", "exec", "compile", "open", "__import__"})
    assert not attribute_calls.intersection(
        {"system", "popen", "Popen", "run", "load", "loads", "connect", "send", "urlopen"}
    )
