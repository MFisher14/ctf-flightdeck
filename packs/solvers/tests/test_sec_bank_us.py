"""Independent vectors for the passive US interbank-payment profiler.

The XML and fixed-column messages below are literal, hand-built fixtures from
the published Federal Reserve/Moov, Nacha, ISO 20022, and ISO 8583 layouts.  No
engine encoder or engine-produced output is used as an oracle.
"""

from pathlib import Path
import random

from lxml import etree
import pytest

import sec_bank_us as U


def fedwire_pacs008() -> bytes:
    """Reduced equivalent of Moov's published PACS008_CustomerCreditTransfer."""
    return b'''<fw:FedwireFundsIncoming xmlns:fw="urn:fedwirefunds:incoming:v001">
  <fw:FedwireFundsIncomingMessage><fw:FedwireFundsCustomerCreditTransfer>
    <h:AppHdr xmlns:h="urn:iso:std:iso:20022:tech:xsd:head.001.001.03">
      <h:Fr><h:FIId><h:FinInstnId><h:ClrSysMmbId><h:MmbId>123456789</h:MmbId></h:ClrSysMmbId></h:FinInstnId></h:FIId></h:Fr>
      <h:To><h:FIId><h:FinInstnId><h:ClrSysMmbId><h:MmbId>021151080</h:MmbId></h:ClrSysMmbId></h:FinInstnId></h:FIId></h:To>
      <h:BizMsgIdr>Customer Credit Transfer Sample</h:BizMsgIdr>
      <h:MsgDefIdr>pacs.008.001.08</h:MsgDefIdr><h:BizSvc>TEST</h:BizSvc>
      <h:MktPrctc><h:Id>frb.fedwire.01</h:Id></h:MktPrctc>
      <h:CreDt>2024-02-28T09:00:00.123-04:00</h:CreDt>
    </h:AppHdr>
    <p:Document xmlns:p="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">
      <p:FIToFICstmrCdtTrf><p:GrpHdr>
        <p:MsgId>20240228B1QDRCQR000001</p:MsgId><p:CreDtTm>2024-02-28T09:00:00.123-04:00</p:CreDtTm>
        <p:NbOfTxs>1</p:NbOfTxs><p:TtlIntrBkSttlmAmt Ccy="USD">500000.00</p:TtlIntrBkSttlmAmt>
        <p:IntrBkSttlmDt>2024-02-28</p:IntrBkSttlmDt><p:SttlmInf><p:SttlmMtd>CLRG</p:SttlmMtd></p:SttlmInf>
      </p:GrpHdr><p:CdtTrfTxInf>
        <p:PmtId><p:InstrId>Variation6InstrId001</p:InstrId><p:EndToEndId>Variation6EtoEId001</p:EndToEndId>
          <p:TxId>FedwireTx001</p:TxId><p:UETR>8a562c67-ca16-48ba-b074-65581be6f011</p:UETR></p:PmtId>
        <p:PmtTpInf><p:SvcLvl><p:Cd>G001</p:Cd></p:SvcLvl><p:LclInstrm><p:Prtry>CTRC</p:Prtry></p:LclInstrm></p:PmtTpInf>
        <p:IntrBkSttlmAmt Ccy="USD">500000.00</p:IntrBkSttlmAmt><p:ChrgBr>SHAR</p:ChrgBr>
        <p:Dbtr><p:Nm>Corporation Z</p:Nm></p:Dbtr><p:DbtrAcct><p:Id><p:IBAN>DE89370400440532013000</p:IBAN></p:Id></p:DbtrAcct>
        <p:DbtrAgt><p:FinInstnId><p:BICFI>DEUTDEFF</p:BICFI></p:FinInstnId></p:DbtrAgt>
        <p:CdtrAgt><p:FinInstnId><p:BICFI>WESTGB2L</p:BICFI></p:FinInstnId></p:CdtrAgt>
        <p:Cdtr><p:Nm>Individual X</p:Nm></p:Cdtr><p:CdtrAcct><p:Id><p:IBAN>GB82WEST12345698765432</p:IBAN></p:Id></p:CdtrAcct>
        <p:RmtInf><p:Ustrd>Insurance Benefit/Policy XXAB9876</p:Ustrd></p:RmtInf>
      </p:CdtTrfTxInf></p:FIToFICstmrCdtTrf>
    </p:Document>
  </fw:FedwireFundsCustomerCreditTransfer></fw:FedwireFundsIncomingMessage>
</fw:FedwireFundsIncoming>'''


def fednow_pacs002() -> bytes:
    return b'''<Envelope>
  <h:AppHdr xmlns:h="urn:iso:std:iso:20022:tech:xsd:head.001.001.03">
    <h:Fr><h:FIId><h:FinInstnId><h:ClrSysMmbId><h:MmbId>011000015</h:MmbId></h:ClrSysMmbId></h:FinInstnId></h:FIId></h:Fr>
    <h:To><h:FIId><h:FinInstnId><h:ClrSysMmbId><h:MmbId>021000021</h:MmbId></h:ClrSysMmbId></h:FinInstnId></h:FIId></h:To>
    <h:BizMsgIdr>FN-STATUS-1</h:BizMsgIdr><h:MsgDefIdr>pacs.002.001.10</h:MsgDefIdr>
    <h:BizSvc>fednow.instant</h:BizSvc><h:CreDt>2026-11-05T12:00:00.123Z</h:CreDt>
  </h:AppHdr>
  <p:Document xmlns:p="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">
    <p:FIToFIPmtStsRpt><p:GrpHdr><p:MsgId>FN-RPT-1</p:MsgId><p:CreDtTm>2026-11-05T12:00:00.123Z</p:CreDtTm></p:GrpHdr>
      <p:OrgnlGrpInfAndSts><p:OrgnlMsgId>FN-PAY-1</p:OrgnlMsgId><p:OrgnlMsgNmId>pacs.008.001.08</p:OrgnlMsgNmId><p:GrpSts>ACCP</p:GrpSts></p:OrgnlGrpInfAndSts>
      <p:TxInfAndSts><p:StsId>FN-STS-1</p:StsId><p:OrgnlInstrId>FN-I-1</p:OrgnlInstrId>
        <p:OrgnlEndToEndId>FN-E2E-1</p:OrgnlEndToEndId><p:OrgnlTxId>FN-TX-1</p:OrgnlTxId>
        <p:OrgnlUETR>8a562c67-ca16-48ba-b074-65581be6f011</p:OrgnlUETR><p:TxSts>ACTC</p:TxSts>
      </p:TxInfAndSts>
    </p:FIToFIPmtStsRpt>
  </p:Document>
</Envelope>'''


def pacs004() -> bytes:
    return b'''<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.004.001.10">
  <PmtRtr><GrpHdr><MsgId>RETURN-1</MsgId><CreDtTm>2026-11-05T12:00:00Z</CreDtTm><NbOfTxs>1</NbOfTxs>
    <SttlmInf><SttlmMtd>CLRG</SttlmMtd></SttlmInf></GrpHdr>
    <OrgnlGrpInf><OrgnlMsgId>PAY-1</OrgnlMsgId><OrgnlMsgNmId>pacs.008.001.08</OrgnlMsgNmId></OrgnlGrpInf>
    <TxInf><RtrId>RET-TX-1</RtrId><OrgnlInstrId>I-1</OrgnlInstrId><OrgnlEndToEndId>E-1</OrgnlEndToEndId>
      <OrgnlTxId>T-1</OrgnlTxId><RtrdIntrBkSttlmAmt Ccy="USD">12.34</RtrdIntrBkSttlmAmt>
      <RtrRsnInf><Rsn><Cd>AC01</Cd></Rsn><AddtlInf>bad account</AddtlInf></RtrRsnInf>
    </TxInf>
  </PmtRtr>
</Document>'''


def _record(*values: tuple[int, str]) -> str:
    """Independent one-based fixed-column writer from Nacha's published table."""
    row = [" "] * 94
    for start, value in values:
        row[start - 1 : start - 1 + len(value)] = value
    assert len(row) == 94
    return "".join(row)


def _routing(partial: str) -> str:
    check = (-sum(int(c) * w for c, w in zip(partial, (3, 7, 1, 3, 7, 1, 3, 7)))) % 10
    return partial + str(check)


def nacha_fixture() -> bytes:
    # Nacha's published hash example: 05600507 + 05140225 + 11400065 = 22140797.
    partials = ["05600507", "05140225", "11400065"]
    rows = [
        _record((1, "101"), (4, " 021000021"), (14, " 121000248"), (24, "261106"),
                (30, "1200A094101"), (41, "DEST BANK"), (64, "ORIGIN BANK")),
        _record((1, "5220"), (5, "TEST COMPANY"), (41, "1234567890"), (51, "CCD"),
                (54, "PAYROLL"), (70, "261106"), (79, "1"), (80, "02100002"), (88, "0000001")),
    ]
    for sequence, partial in enumerate(partials, 1):
        rows.append(
            _record((1, "622" + _routing(partial)), (13, "000123"), (30, "0000000010"),
                    (40, f"EMP{sequence}"), (55, f"RECEIVER {sequence}"),
                    (79, "1" if sequence == 1 else "0"),
                    (80, "02100002" + f"{sequence:07d}"))
        )
        if sequence == 1:
            rows.append(_record((1, "705published layout addenda"), (84, "0001"), (88, "0000001")))
    entry_hash = sum(map(int, partials)) % 10_000_000_000
    count = 4  # three entries plus one addenda
    rows.append(
        _record((1, "8220"), (5, f"{count:06d}"), (11, f"{entry_hash:010d}"),
                (21, f"{0:012d}"), (33, f"{30:012d}"), (45, "1234567890"),
                (80, "02100002"), (88, "0000001"))
    )
    blocks = (len(rows) + 1 + 9) // 10
    rows.append(
        _record((1, "9"), (2, "000001"), (8, f"{blocks:06d}"), (14, f"{count:08d}"),
                (22, f"{entry_hash:010d}"), (32, f"{0:012d}"), (44, f"{30:012d}"))
    )
    rows += ["9" * 94] * ((-len(rows)) % 10)
    return "\n".join(rows).encode("ascii")


ISO8583_AUTH = (
    b"0100" + b"7224048000808000" + b"16" + b"4111111111111111"
    + b"000000" + b"000000001234" + b"1105123456" + b"123456"
    + b"2712" + b"051" + b"00" + b"TERMID01" + b"840"
)
ISO8583_DE70 = b"0800" + b"8000000000000000" + b"0400000000000000" + b"301"


def test_fedwire_published_wrapper_and_independent_xsd_oracle() -> None:
    root = etree.fromstring(fedwire_pacs008())
    documents = root.xpath("//*[local-name()='Document']")
    assert len(documents) == 1
    schema_path = Path(__file__).parents[1] / "solvers/toolkits/fin2_schemas/pacs.008.001.08.xsd"
    schema = etree.XMLSchema(etree.parse(str(schema_path)))
    assert schema.validate(documents[0]), str(schema.error_log)

    result = U.parse_iso20022(fedwire_pacs008())
    assert result["valid"] is True
    assert result["wrapper"] == "FedwireFundsIncoming"
    assert result["rail_assessment"]["selected"] == "fedwire"
    header = result["business_application_header"]
    assert (header["from"], header["to"]) == ("123456789", "021151080")
    assert header["message_definition_id"] == "pacs.008.001.08"
    assert header["market_practice"] == "frb.fedwire.01"
    tx = result["transactions"][0]
    assert tx["uetr"] == "8a562c67-ca16-48ba-b074-65581be6f011"
    assert tx["amount"] == {"value": "500000.00", "currency": "USD"}
    assert tx["debtor_agent"] == "DEUTDEFF" and tx["creditor_agent"] == "WESTGB2L"


def test_fednow_status_and_bah_mismatch_evidence() -> None:
    result = U.parse_iso20022(fednow_pacs002(), rail="fednow")
    assert result["valid"] is True
    assert result["rail_assessment"]["selected"] == "fednow"
    assert result["original_group"] == {
        "message_id": "FN-PAY-1",
        "message_name": "pacs.008.001.08",
        "group_status": "ACCP",
        "reasons": [],
    }
    status = result["transaction_statuses"][0]
    assert status["transaction_status"] == "ACTC"
    assert status["original_uetr"] == "8a562c67-ca16-48ba-b074-65581be6f011"

    bad = fednow_pacs002().replace(
        b"<h:MsgDefIdr>pacs.002.001.10</h:MsgDefIdr>",
        b"<h:MsgDefIdr>pacs.009.001.08</h:MsgDefIdr>",
    )
    report = U.parse_iso20022(bad, rail="fednow")
    assert report["valid"] is False
    assert "bah_message_mismatch" in {item["code"] for item in report["issues"]}


def test_bare_document_does_not_invent_rail_and_return_family() -> None:
    root = etree.fromstring(fedwire_pacs008())
    document = etree.tostring(root.xpath("//*[local-name()='Document']")[0])
    bare = U.parse_iso20022(document)
    assert bare["wrapper"] == "bare-Document"
    assert bare["rail_assessment"]["selected"] is None
    assert set(bare["rail_assessment"]["candidates"]) == {"fednow", "fedwire"}

    returned = U.parse_iso20022(pacs004(), rail="fedwire")
    assert returned["family"] == "pacs.004"
    assert returned["original_group"]["message_id"] == "PAY-1"
    assert returned["returns"][0]["returned_amount"] == {
        "value": "12.34",
        "currency": "USD",
    }


def test_nacha_fixed_width_published_hash_and_controls() -> None:
    result = U.parse_nacha(nacha_fixture())
    assert result["valid"] is True
    assert result["record_count"] == 10
    assert result["computed"] == {
        "entry_addenda_count": 4,
        "entry_hash": 22_140_797,
        "debit_cents": 0,
        "credit_cents": 30,
    }
    assert [entry["routing"][:8] for entry in result["batches"][0]["entries"]] == [
        "05600507", "05140225", "11400065"
    ]


def test_iso8583_published_bitmap_vector_and_secondary_bitmap() -> None:
    result = U.parse_iso8583(ISO8583_AUTH, encoding="ascii")
    assert result["mti"]["raw"] == "0100"
    assert result["present_fields"] == [2, 3, 4, 7, 11, 14, 22, 25, 41, 49]
    fields = {item["de"]: item["value"] for item in result["fields"]}
    assert fields == {
        2: "4111111111111111", 3: "000000", 4: "000000001234",
        7: "1105123456", 11: "123456", 14: "2712", 22: "051",
        25: "00", 41: "TERMID01", 49: "840",
    }
    second = U.parse_iso8583(ISO8583_DE70, encoding="ascii")
    assert second["has_secondary_bitmap"] is True
    assert second["present_fields"] == [70]
    assert second["fields"][0]["value"] == "301"


def _assert_clean_or_declared(function, *args, **kwargs) -> None:
    try:
        result = function(*args, **kwargs)
    except Exception as exc:  # contract assertion intentionally catches all
        assert type(exc) is U.SecBankUSError
    else:
        assert isinstance(result, dict)


@pytest.mark.parametrize("value", [None, 7, {}, [], b"", "", b"\xff\xfe\x00"])
def test_all_public_entrypoints_fail_closed_on_bad_types_and_bytes(value) -> None:
    for function in (U.parse_iso20022, U.parse_nacha, U.parse_iso8583):
        with pytest.raises(U.SecBankUSError) as caught:
            function(value)
        assert type(caught.value) is U.SecBankUSError


def test_fail_closed_truncation_random_and_bit_flips() -> None:
    vectors = [
        (U.parse_iso20022, fedwire_pacs008(), {}),
        (U.parse_nacha, nacha_fixture(), {}),
        (U.parse_iso8583, ISO8583_AUTH, {"encoding": "ascii"}),
    ]
    rng = random.Random(0x5ECBAA)
    for function, vector, kwargs in vectors:
        for end in sorted({0, 1, 4, len(vector) // 4, len(vector) // 2, len(vector) - 1}):
            _assert_clean_or_declared(function, vector[:end], **kwargs)
        for position in (1, len(vector) // 2, len(vector) - 2):
            mutant = bytearray(vector)
            mutant[position] ^= 0x80
            _assert_clean_or_declared(function, bytes(mutant), **kwargs)
        for _ in range(12):
            _assert_clean_or_declared(function, rng.randbytes(rng.randrange(1, 96)), **kwargs)


def test_xml_security_duplicate_and_rail_conflict_evidence() -> None:
    hostile = [
        b'<!DOCTYPE x [<!ENTITY e "boom">]><x>&e;</x>',
        b'<x xmlns:i="http://www.w3.org/2001/XInclude"><i:include href="file:///etc/passwd"/></x>',
        b'<x><Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10"/><Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10"/></x>',
        fednow_pacs002().replace(b"</Envelope>", b"<h:AppHdr xmlns:h=\"urn:iso:std:iso:20022:tech:xsd:head.001.001.03\"/></Envelope>"),
    ]
    for value in hostile:
        with pytest.raises(U.SecBankUSError) as caught:
            U.parse_iso20022(value)
        assert type(caught.value) is U.SecBankUSError

    conflict = U.parse_iso20022(fedwire_pacs008(), rail="fednow")
    assert conflict["valid"] is False
    assert "rail_evidence_conflict" in {item["code"] for item in conflict["issues"]}


def test_strict_iso8583_failures_and_adapter_error_wrapping() -> None:
    bad_messages = [
        ISO8583_AUTH[:-1],
        ISO8583_AUTH + b"X",
        b"0800" + b"8000000000000000" + b"0400",
        b"0100" + b"not-a-hex-bitmap",
    ]
    for value in bad_messages:
        with pytest.raises(U.SecBankUSError) as caught:
            U.parse_iso8583(value, encoding="ascii")
        assert type(caught.value) is U.SecBankUSError
    with pytest.raises(U.SecBankUSError):
        U.parse_iso8583(ISO8583_AUTH, encoding="auto")
    with pytest.raises(U.SecBankUSError):
        U.parse_iso8583(ISO8583_AUTH, spec="2023")
    with pytest.raises(U.SecBankUSError):
        U.parse_iso8583(ISO8583_AUTH, strip_mli="yes")

    with pytest.raises(U.SecBankUSError) as caught:
        U.parse_nacha(nacha_fixture()[:94])
    assert type(caught.value) is U.SecBankUSError


def test_nested_apphdr_unknown_version_and_empty_skeletons() -> None:
    nested_header = b'''<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">
      <FIToFIPmtStsRpt><AppHdr xmlns="urn:iso:std:iso:20022:tech:xsd:head.001.001.03">
        <BizSvc>fednow.instant</BizSvc></AppHdr><GrpHdr><MsgId>x</MsgId>
        <CreDtTm>2026-11-05T12:00:00Z</CreDtTm></GrpHdr>
        <OrgnlGrpInfAndSts><OrgnlMsgId>o</OrgnlMsgId><OrgnlMsgNmId>pacs.008.001.08</OrgnlMsgNmId>
        <GrpSts>ACCP</GrpSts></OrgnlGrpInfAndSts></FIToFIPmtStsRpt></Document>'''
    empty_status = b'''<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10">
      <FIToFIPmtStsRpt><GrpHdr/></FIToFIPmtStsRpt></Document>'''
    empty_notice = b'''<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.054.001.08">
      <BkToCstmrDbtCdtNtfctn><GrpHdr/></BkToCstmrDbtCdtNtfctn></Document>'''
    for value in (nested_header, empty_status, empty_notice):
        with pytest.raises(U.SecBankUSError) as caught:
            U.parse_iso20022(value)
        assert type(caught.value) is U.SecBankUSError

    future = fednow_pacs002().replace(b"pacs.002.001.10", b"pacs.002.999.99")
    report = U.parse_iso20022(future, rail="fednow")
    assert report["valid"] is False
    assert "unsupported_rail_message_version" in {
        item["code"] for item in report["issues"]
    }


def test_tertiary_bitmap_indicator_is_rejected() -> None:
    value = b"0800" + b"8000000000000000" * 2
    with pytest.raises(U.SecBankUSError) as caught:
        U.parse_iso8583(value, encoding="ascii")
    assert type(caught.value) is U.SecBankUSError


def test_released_views_invalid_options_and_oversized_inputs() -> None:
    for function, kwargs in (
        (U.parse_iso20022, {}),
        (U.parse_nacha, {}),
        (U.parse_iso8583, {"encoding": "ascii"}),
    ):
        view = memoryview(bytearray(b"x"))
        view.release()
        with pytest.raises(U.SecBankUSError) as caught:
            function(view, **kwargs)
        assert type(caught.value) is U.SecBankUSError

    for call in (
        lambda: U.parse_iso20022(fednow_pacs002(), rail=[]),
        lambda: U.parse_nacha(nacha_fixture(), require_padding="yes"),
        lambda: U.parse_iso8583(ISO8583_AUTH, encoding=[]),
    ):
        with pytest.raises(U.SecBankUSError) as caught:
            call()
        assert type(caught.value) is U.SecBankUSError

    with pytest.raises(U.SecBankUSError):
        U.parse_iso20022(b"x" * (U.MAX_XML_BYTES + 1))
    with pytest.raises(U.SecBankUSError):
        U.parse_nacha(b"x" * (U.MAX_BINARY_BYTES + 1))
    with pytest.raises(U.SecBankUSError):
        U.parse_iso8583(b"x" * (U.MAX_BINARY_BYTES + 1), encoding="ascii")


def test_guarded_cli(tmp_path, capsys, monkeypatch) -> None:
    assert U.main(["--help"]) == 0
    assert U.main([]) == 2
    assert U.main(["iso20022", str(tmp_path / "missing.xml")]) == 2

    xml_path = tmp_path / "fedwire.xml"
    xml_path.write_bytes(fedwire_pacs008())
    assert U.main(["iso20022", str(xml_path)]) == 0

    iso_path = tmp_path / "auth.bin"
    iso_path.write_bytes(ISO8583_AUTH)
    assert U.main(["iso8583", str(iso_path), "--encoding", "ascii"]) == 0
    assert '"type": "iso8583"' in capsys.readouterr().out

    def noninteger_exit(self, argv):  # noqa: ANN001
        raise SystemExit("bad")

    monkeypatch.setattr("argparse.ArgumentParser.parse_args", noninteger_exit)
    assert U.main([]) == 2

