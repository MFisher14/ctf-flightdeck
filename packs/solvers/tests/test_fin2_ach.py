"""Independent fixed-column fixtures from Nacha's published record tables."""
import random

import pytest

from fin2_ach import ACHError, main, parse_ach


def record(*values):
    """Reference fixture writer: explicit one-based positions, no engine encoder."""
    buf = [" "] * 94
    for start, text in values:
        buf[start - 1:start - 1 + len(text)] = text
    assert len(buf) == 94
    return "".join(buf)


def fixture(entries=None, sec="CCD", addenda=True):
    entries = entries or [("22", "021000021", 1250), ("27", "121000248", 400)]
    rows = [record((1, "101"), (4, " 021000021"), (14, " 121000248"), (24, "261106"),
                   (30, "1200A094101"), (41, "BANK"), (64, "ORIGIN"))]
    rows.append(record((1, "5200"), (5, "TEST COMPANY"), (41, "1234567890"), (51, sec),
                       (54, "PAYROLL"), (70, "261106"), (79, "1"), (80, "02100002"), (88, "0000001")))
    for n, (code, routing, cents) in enumerate(entries, 1):
        rows.append(record((1, "6" + code + routing), (13, "000123"), (30, f"{cents:010d}"),
                           (40, "EMPLOYEE"), (55, "RECEIVER"), (79, "1" if addenda and n == 1 else "0"),
                           (80, "02100002" + f"{n:07d}")))
        if addenda and n == 1:
            rows.append(record((1, "705CSCTF{addenda_evidence}"), (84, "0001"), (88, "0000001")))
    # Oracle: independent arithmetic on fixture source values, not parsed fields.
    hash_value = sum(int(routing[:8]) for _, routing, _ in entries) % 10000000000
    credits = sum(amount for code, _, amount in entries if code in ("22", "32"))
    debits = sum(amount for code, _, amount in entries if code in ("27", "37"))
    count = len(entries) + int(addenda)
    rows.append(record((1, "8200"), (5, f"{count:06d}"), (11, f"{hash_value:010d}"),
                       (21, f"{debits:012d}"), (33, f"{credits:012d}"), (45, "1234567890"),
                       (80, "02100002"), (88, "0000001")))
    blocks = (len(rows) + 1 + 9) // 10
    rows.append(record((1, "9"), (2, "000001"), (8, f"{blocks:06d}"), (14, f"{count:08d}"),
                       (22, f"{hash_value:010d}"), (32, f"{debits:012d}"), (44, f"{credits:012d}")))
    rows += ["9" * 94] * ((-len(rows)) % 10)
    return rows


def test_extract_and_independent_controls():
    result = parse_ach("\r\n".join(fixture()).encode())
    assert result["valid"]
    assert result["computed"] == {"entry_addenda_count": 3, "entry_hash": 14200026,
                                   "debit_cents": 400, "credit_cents": 1250}
    entry = result["batches"][0]["entries"][0]
    assert entry["routing"] == "021000021"
    assert entry["account"] == "000123"
    assert entry["addenda"][0]["text"] == "CSCTF{addenda_evidence}"
    assert result["flags"] == ["CSCTF{addenda_evidence}"]
    assert parse_ach("".join(fixture()))["valid"]


def test_published_nacha_hash_vector():
    # Nacha 2025 Appendix Three: 05600507+05140225+11400065=22140797.
    # Reference check digit: negative weighted sum of eight digits mod ten.
    entries = []
    for partial in ["05600507", "05140225", "11400065"]:
        checksum = (-sum(int(c) * w for c, w in zip(partial, [3, 7, 1, 3, 7, 1, 3, 7]))) % 10
        entries.append(("22", partial + str(checksum), 10))
    result = parse_ach("\n".join(fixture(entries)))
    assert result["valid"]
    assert result["computed"]["entry_hash"] == 22140797


def test_published_hash_truncation_vector():
    # Published example: 123456789012 truncated to its last 10 digits.
    whole, remainder = divmod(123456789012, 99999999)
    entries = []
    for number in [99999999] * whole + [remainder]:
        partial = f"{number:08d}"
        checksum = (-sum(int(c) * w for c, w in zip(partial, [3, 7, 1, 3, 7, 1, 3, 7]))) % 10
        entries.append(("22", partial + str(checksum), 10))
    result = parse_ach("\n".join(fixture(entries)))
    assert result["valid"]
    assert result["computed"]["entry_hash"] == 3456789012


@pytest.mark.parametrize("index,start,value,issue", [
    (2, 30, "0000001251", "credit_cents"),
    (2, 4, "021000022", "routing checksum"),
    (3, 88, "0000002", "trace link"),
    (3, 84, "0002", "addenda sequence"),
    (4, 80, "021000020000001", "unique trace"),
    (5, 11, "0000000000", "entry_hash"),
    (6, 8, "000002", "block count"),
])
def test_tampering_has_evidence(index, start, value, issue):
    rows = fixture()
    row = rows[index]
    rows[index] = row[:start - 1] + value + row[start - 1 + len(value):]
    result = parse_ach("\n".join(rows))
    assert not result["valid"]
    assert any(issue in item["check"] for item in result["issues"])


def test_account_tampering_is_not_authenticated_by_controls():
    rows = fixture()
    rows[2] = rows[2][:12] + "999123" + rows[2][18:]
    result = parse_ach("\n".join(rows))
    assert result["valid"]
    assert result["authentication"] == "not verified"


def test_unpadded_explicit_and_missing_control():
    rows = [r for r in fixture() if r != "9" * 94]
    assert not parse_ach("\n".join(rows))["valid"]
    assert parse_ach("\n".join(rows), require_padding=False)["valid"]
    with pytest.raises(ACHError):
        parse_ach("\n".join(rows[:-1]))


@pytest.mark.parametrize("sec", ["PPD", "CCD", "WEB"])
def test_common_sec(sec):
    assert parse_ach("\n".join(fixture(sec=sec)))["valid"]


def test_tel_and_unsupported_layouts():
    assert parse_ach("\n".join(fixture([("27", "021000021", 400)], "TEL", False)))["valid"]
    for sec in ["IAT", "CTX", "BOC"]:
        with pytest.raises(ACHError):
            parse_ach("\n".join(fixture(sec=sec)))


@pytest.mark.parametrize("data", [None, 1, {}, b"", "", "x", b"\xff" * 94, "\u0661" * 94, "101" + " " * 91])
def test_bad_inputs_only_declared_error(data):
    with pytest.raises(ACHError):
        parse_ach(data)


def test_mutation_contract():
    rng = random.Random(613)
    original = "\n".join(fixture())
    for _ in range(200):
        pos = rng.randrange(len(original))
        mutant = original[:pos] + rng.choice("09 x\x00\xff") + original[pos + 1:]
        try:
            result = parse_ach(mutant)
            assert isinstance(result["valid"], bool)
        except ACHError:
            pass


def test_cli(tmp_path, capsys):
    path = tmp_path / "payments.ach"
    path.write_text("\n".join(fixture()))
    assert main([str(path)]) == 0
    assert main(["--help"]) == 0
    assert main([]) == 2
    assert main([str(path) + ".missing"]) == 2
