from __future__ import annotations

import hashlib
import sys
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import netplay as N  # noqa: E402


def test_safe_bigint_and_modular_expression_no_eval(monkeypatch):
    assert N.safe_bigint_expr("Calculate: (2**100 + 7) % 97?") == str((2**100 + 7) % 97)
    assert N.safe_bigint_expr("What is 2^100 mod 17?") == str(pow(2, 100, 17))
    assert N.safe_bigint_expr("Compute pow(7, 1234, 101)?") == str(pow(7, 1234, 101))
    for hostile in ("Evaluate __import__('os').system('id')?", "Calculate 2**999999?"):
        try:
            N.safe_bigint_expr(hostile)
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe/unbounded expression was accepted")


def test_hashing_families_and_base_conversion():
    assert N.hashing_family("Compute SHA256 hash of 'abc'") == hashlib.sha256(b"abc").hexdigest()
    assert N.hashing_family("CRC32 checksum of text='hello' as hexadecimal") == f"{zlib.crc32(b'hello') & 0xffffffff:08x}"
    assert N.hashing_family("BLAKE2s digest of hex input=0001") == hashlib.blake2s(b"\x00\x01").hexdigest()
    assert N.base_conversion("Convert deadBEEF from base 16 to base 10") == str(0xDEADBEEF)
    assert N.base_conversion("101101 from base 2 into base 36") == "19"


def test_list_sequence_and_classical_handlers():
    assert N.list_operations("Sort ascending list [9,2,2,1]") == "1,2,2,9"
    assert N.list_operations("Dedupe list [3,1,3,2,1]") == "3,1,2"
    assert N.list_operations("Sum list [5,-2,9]") == "12"
    assert N.integer_sequence("What is the 25th prime?") == "97"
    assert N.integer_sequence("Fibonacci term 100") == "354224848179261915075"
    assert N.integer_sequence("How many Collatz steps starting from 27?") == "111"
    assert N.classical_transform("Apply ROT13 to 'uryyb'") == "hello"
    assert N.classical_transform("Caesar shift by 3: text='Abc Xyz'") == "Def Abc"


def test_auto_dispatches_general_handlers():
    assert N.auto_handler("Convert ff from base 16 to base 10") == "255"
    assert N.auto_handler("Compute SHA-1 hash of 'fixture'") == hashlib.sha1(b"fixture").hexdigest()
    assert N.auto_handler("What is the 10th prime?") == "29"
    assert N.auto_handler("Evaluate (123456789 * 9) + 1?") == str(123456789 * 9 + 1)


def test_pow_auto_handler_verifies_returned_suffix():
    prompt = ('Proof of work: find a decimal suffix so sha256(prefix + suffix) starts with 00. '
              'prefix="netplay-fixture:" max attempts=100000')
    answer = N.auto_handler(prompt)
    assert answer is not None
    digest = hashlib.sha256(b"netplay-fixture:" + answer.encode()).digest()
    assert digest[0] == 0

