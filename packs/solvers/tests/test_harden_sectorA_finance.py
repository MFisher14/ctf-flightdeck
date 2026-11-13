"""Independent vector locks and fail-closed checks for finance parsers.

The fixtures below are written from the public format specifications, never
from an engine encoder.  ISO 20022 is additionally validated by lxml against
the published XSD before its engine result is inspected.
"""

from pathlib import Path
import random

from lxml import etree
import pytest

import fin2_ach as ach
import fin2_bai2 as bai2
import fin2_fix as fix
import fin2_iso20022 as iso20022
import fin2_swift as swift


# ISO 20022 pain.001.001.09, authored directly from the ISO message grammar:
# https://www.iso20022.org/iso-20022-message-definitions
ISO_PAIN = b'''<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.001.001.09">
<CstmrCdtTrfInitn><GrpHdr><MsgId>HARDEN-ISO-1</MsgId><CreDtTm>2026-11-05T12:00:00</CreDtTm>
<NbOfTxs>1</NbOfTxs><CtrlSum>19.95</CtrlSum><InitgPty><Nm>Grid Operator</Nm></InitgPty></GrpHdr>
<PmtInf><PmtInfId>PMT-1</PmtInfId><PmtMtd>TRF</PmtMtd><NbOfTxs>1</NbOfTxs><CtrlSum>19.95</CtrlSum>
<PmtTpInf><SvcLvl><Cd>SEPA</Cd></SvcLvl></PmtTpInf><ReqdExctnDt><Dt>2026-11-06</Dt></ReqdExctnDt>
<Dbtr><Nm>Grid Operator</Nm></Dbtr><DbtrAcct><Id><IBAN>DE89370400440532013000</IBAN></Id></DbtrAcct>
<DbtrAgt><FinInstnId><BICFI>DEUTDEFF</BICFI></FinInstnId></DbtrAgt><ChrgBr>SLEV</ChrgBr>
<CdtTrfTxInf><PmtId><EndToEndId>ORACLE-E2E-1</EndToEndId></PmtId>
<Amt><InstdAmt Ccy="EUR">19.95</InstdAmt></Amt><Cdtr><Nm>Relay Vendor</Nm></Cdtr>
<CdtrAcct><Id><IBAN>GB82WEST12345698765432</IBAN></Id></CdtrAcct>
<RmtInf><Ustrd>CSCTF{iso_vector}</Ustrd></RmtInf></CdtTrfTxInf></PmtInf>
</CstmrCdtTrfInitn></Document>'''


def _fixed_record(*fields):
    """Write a 94-column NACHA record from documented one-based offsets."""
    result = [" "] * 94
    for start, value in fields:
        result[start - 1:start - 1 + len(value)] = value
    assert len(result) == 94
    return "".join(result)


def _ach_reference():
    """One-credit PPD file, with controls derived independently by hand."""
    routing = "021000021"
    routing_prefix = int(routing[:8])
    amount = 1_234
    rows = [
        _fixed_record(
            (1, "101"), (4, " 021000021"), (14, " 121000248"),
            (24, "261105"), (30, "1200A094101"),
            (41, "DESTINATION BANK"), (64, "GRID OPERATOR"),
        ),
        _fixed_record(
            (1, "5220"), (5, "GRID OPERATOR"), (41, "1234567890"),
            (51, "PPD"), (54, "PAYMENT"), (70, "261106"), (79, "1"),
            (80, "02100002"), (88, "0000001"),
        ),
        _fixed_record(
            (1, "622" + routing), (13, "123456789"),
            (30, f"{amount:010d}"), (40, "INVOICE-1"),
            (55, "RELAY VENDOR"), (79, "0"),
            (80, "02100002" + "0000001"),
        ),
        _fixed_record(
            (1, "8220"), (5, "000001"), (11, f"{routing_prefix:010d}"),
            (21, "000000000000"), (33, f"{amount:012d}"),
            (45, "1234567890"), (80, "02100002"), (88, "0000001"),
        ),
        _fixed_record(
            (1, "9"), (2, "000001"), (8, "000001"), (14, "00000001"),
            (22, f"{routing_prefix:010d}"), (32, "000000000000"),
            (44, f"{amount:012d}"),
        ),
    ]
    rows.extend(["9" * 94] * 5)
    return "\n".join(rows).encode("ascii")


def _fix_reference_frame():
    """Encode one FIX frame solely from the published wire framing rules."""
    soh = b"\x01"
    fields = [
        (35, "D"), (49, "GRID"), (56, "BANK"), (34, "7"),
        (52, "20261105-12:00:00"), (11, "ORDER-7"), (55, "POWER"),
        (54, "1"), (38, "25"), (40, "2"), (44, "19.95"),
    ]
    body = b"".join(f"{tag}={value}".encode("ascii") + soh for tag, value in fields)
    prefix = b"8=FIX.4.4\x01" + f"9={len(body)}".encode("ascii") + soh
    checksum = sum(prefix + body) % 256
    return prefix + body + f"10={checksum:03d}".encode("ascii") + soh


# SWIFT PMPG's published mandatory-field MT103 example:
# https://www.swift.com/sites/default/files/documents/
# swift_pmpg_guidelines_exceptionsandinvestigations.pdf
SWIFT_MT103 = b""":20:2233NA
:23B:CRED
:32A:120828HKD12786,78
:50K:/122267890
BIOCOM
123 Windsor St
Toronto, ON M8Y 1A4
Canada
:59:/324788294
Lee Import
78 Sing Wood Rd
Happy Valley
Hong Kong
:71A:SHA"""


def _bai2_reference():
    """BAI2 hierarchy with manually calculated totals and record counts."""
    return "\n".join([
        "01,SENDER,RECEIVER,261105,1200,1,,,2/",
        "02,RECEIVER,ORIGIN,1,261105,1200,USD,/",
        "03,POWER-ACCOUNT,USD,010,1000,1,0/",
        "16,195,250,Z,BANKREF,CUSTREF,CSCTF{bai2_vector}/",
        "49,1250,3/",
        "98,1250,1,5/",
        "99,1250,1,7/",
    ]).encode("ascii")


def test_iso20022_published_schema_and_hand_derived_values():
    schema_path = (Path(iso20022.__file__).with_name("fin2_schemas") /
                   "pain.001.001.09.xsd")
    root = etree.fromstring(ISO_PAIN)
    oracle = etree.XMLSchema(etree.parse(str(schema_path)))
    assert oracle.validate(root), str(oracle.error_log)

    result = iso20022.analyze(ISO_PAIN, sepa=True)
    assert result["schema_valid"] and result["valid"]
    assert result["message_id"] == "HARDEN-ISO-1"
    assert result["transactions"] == [{
        "end_to_end_id": "ORACLE-E2E-1",
        "instruction_id": None,
        "transaction_id": None,
        "amount": "19.95",
        "currency": "EUR",
        "debtor": "Grid Operator",
        "debtor_account": "DE89370400440532013000",
        "creditor": "Relay Vendor",
        "creditor_account": "GB82WEST12345698765432",
        "remittance": ["CSCTF{iso_vector}"],
    }]


def test_ach_documented_columns_routing_and_controls():
    raw = _ach_reference()
    routing = "021000021"
    assert len(raw.splitlines()) == 10
    assert all(len(row) == 94 for row in raw.splitlines())
    assert sum(int(digit) * weight for digit, weight in
               zip(routing, (3, 7, 1) * 3)) % 10 == 0

    result = ach.parse_ach(raw)
    assert result["valid"]
    assert result["computed"] == {
        "entry_addenda_count": 1,
        "entry_hash": 2_100_002,
        "debit_cents": 0,
        "credit_cents": 1_234,
    }
    assert result["batches"][0]["entries"][0]["amount_cents"] == 1_234


def test_fix_reference_body_length_checksum_and_all_public_views():
    raw = _fix_reference_frame()
    body_start = raw.index(b"\x01", raw.index(b"9=")) + 1
    checksum_start = raw.rindex(b"10=")
    declared_length = int(raw[raw.index(b"9=") + 2:body_start - 1])
    assert declared_length == checksum_start - body_start
    assert int(raw[checksum_start + 3:checksum_start + 6]) == sum(raw[:checksum_start]) % 256

    message = fix.parse_message(raw)
    stream = fix.parse_stream(raw)
    report = fix.analyze(raw)
    assert stream == [message]
    assert (message["version"], message["msg_type"], message["sequence"]) == (
        "FIX.4.4", "D", 7,
    )
    assert message["body_length"] == declared_length
    # The analyzer annotates parsed messages with session/application state.
    assert report["messages"][0]["fields"] == message["fields"]
    assert report["messages"][0]["sequence"] == message["sequence"]
    assert report["findings"] == []
    assert report["sessions"][0]["next_expected"] == 8


def test_swift_published_mt103_field_semantics():
    result = swift.parse_messages(SWIFT_MT103, message_type="103")[0]
    fields = {field["tag"]: field for field in result["fields"]}
    assert result["message_type"] == "103"
    assert fields["32A"]["decoded"] == {
        "currency": "HKD", "amount": "12786.78", "value_date": "120828",
    }
    assert fields["50K"]["decoded"]["account"] == "122267890"
    assert fields["59"]["decoded"]["name_address"][0] == "Lee Import"
    assert fields["71A"]["value"] == "SHA"


def test_bai2_documented_hierarchy_manual_totals_and_counts():
    result = bai2.parse_bai2(_bai2_reference())
    assert result["valid"]
    assert result["record_count"] == 7
    assert result["computed_total"] == 1_250
    account = result["groups"][0]["accounts"][0]
    assert account["record_count"] == 3
    assert account["computed_total"] == 1_250
    assert account["transactions"][0]["amount"] == 250
    assert result["flags"] == ["CSCTF{bai2_vector}"]


def _malformed(kind, valid, maximum, seed):
    if kind == "empty":
        return b""
    if kind == "random":
        return random.Random(seed).randbytes(257)
    if kind == "truncated-valid":
        return valid[:max(1, len(valid) // 2)]
    if kind == "bit-flipped":
        changed = bytearray(valid)
        changed[len(changed) // 2] ^= 1
        return bytes(changed)
    if kind == "oversized":
        return b"X" * (maximum + 1)
    raise AssertionError(kind)


def _only_declared_error(call, payload, error):
    try:
        call(payload)
    except error:
        return
    except BaseException as exc:  # includes accidental SystemExit from library code
        pytest.fail(
            f"leaked {type(exc).__name__} instead of {error.__name__}: {exc}",
            pytrace=True,
        )


FUZZ_KINDS = ["empty", "random", "truncated-valid", "bit-flipped", "oversized"]


@pytest.mark.parametrize("kind", FUZZ_KINDS)
def test_iso20022_fail_closed_fuzz(kind):
    payload = _malformed(kind, ISO_PAIN, iso20022.MAX_BYTES, 20_022)
    _only_declared_error(iso20022.analyze, payload, iso20022.ISO20022Error)


@pytest.mark.parametrize("kind", FUZZ_KINDS)
def test_ach_fail_closed_fuzz(kind):
    payload = _malformed(kind, _ach_reference(), ach.MAX_BYTES, 6_132)
    _only_declared_error(ach.parse_ach, payload, ach.ACHError)


@pytest.mark.parametrize("entrypoint", ["parse_stream", "parse_message", "analyze"])
@pytest.mark.parametrize("kind", FUZZ_KINDS)
def test_fix_all_parse_entrypoints_fail_closed_fuzz(entrypoint, kind):
    payload = _malformed(kind, _fix_reference_frame(), fix.MAX_BYTES, 44_044)
    _only_declared_error(getattr(fix, entrypoint), payload, fix.FixError)


@pytest.mark.parametrize("kind", FUZZ_KINDS)
def test_swift_fail_closed_fuzz(kind):
    payload = _malformed(kind, SWIFT_MT103, swift.MAX_BYTES, 10_305)
    call = lambda data: swift.parse_messages(data, message_type="103")
    _only_declared_error(call, payload, swift.SwiftError)


@pytest.mark.parametrize("kind", FUZZ_KINDS)
def test_bai2_fail_closed_fuzz(kind):
    payload = _malformed(kind, _bai2_reference(), bai2.MAX_BYTES, 2_002)
    _only_declared_error(bai2.parse_bai2, payload, bai2.BAI2Error)
