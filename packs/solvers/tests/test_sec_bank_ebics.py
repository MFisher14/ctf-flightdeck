"""Independent vectors for the passive EBICS/EPC sector engine.

The XML literals below are written from the published wire layouts.  No engine
encoder is used.  The pacs.008 and camt.053 documents are additionally checked
with the pinned published XSDs before their extraction assertions are made.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from pathlib import Path
import random

from lxml import etree
import pytest

import sec_bank_ebics as E


DS = "http://www.w3.org/2000/09/xmldsig#"
H004 = "urn:org:ebics:H004"
H005 = "urn:org:ebics:H005"
ISO = "urn:iso:std:iso:20022:tech:xsd:"


def h005_transfer() -> bytes:
    """EBICS 3.0 specification transfer example, with ellipses made base64."""
    payload = base64.b64encode(b"published H005 transfer payload").decode()
    digest = base64.b64encode(bytes(range(32))).decode()
    signature = base64.b64encode(b"synthetic-signature-bytes").decode()
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<ebicsRequest xmlns="{H005}" xmlns:ds="{DS}" Version="H005" Revision="1">
  <header authenticate="true">
    <static>
      <HostID>EBIXHOST</HostID>
      <TransactionID>ABCDEF41394644363445313243ABCDEF</TransactionID>
      <NumSegments>4</NumSegments>
    </static>
    <mutable>
      <TransactionPhase>Transfer</TransactionPhase>
      <SegmentNumber lastSegment="true">4</SegmentNumber>
    </mutable>
  </header>
  <AuthSignature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#xpointer(//*[@authenticate='true'])">
        <ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>{digest}</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>{signature}</ds:SignatureValue>
  </AuthSignature>
  <body><DataTransfer><OrderData>{payload}</OrderData></DataTransfer></body>
</ebicsRequest>'''.encode()


def h004_hvu() -> bytes:
    """Published EBICS 2.5 legacy-order shape (HVU/DZNNN/IZV)."""
    return f'''<ebicsRequest xmlns="{H004}" Version="H004" Revision="1">
  <header authenticate="true">
    <static><HostID>HOST004</HostID><PartnerID>PARTNER</PartnerID><UserID>USER</UserID>
      <OrderDetails><OrderType>HVU</OrderType><OrderAttribute>DZNNN</OrderAttribute>
        <HVUOrderParams><OrderTypes>IZV</OrderTypes></HVUOrderParams>
      </OrderDetails><SecurityMedium>0000</SecurityMedium>
    </static>
    <mutable><TransactionPhase>Initialisation</TransactionPhase></mutable>
  </header>
  <body><DataTransfer><OrderData>WA==</OrderData></DataTransfer></body>
</ebicsRequest>'''.encode()


def h005_btf() -> bytes:
    return f'''<ebicsRequest xmlns="{H005}" Version="H005" Revision="1">
  <header authenticate="true"><static><HostID>BANKHOST</HostID>
    <OrderDetails><AdminOrderType>BTD</AdminOrderType><BTDOrderParams>
      <Service><ServiceName>STM</ServiceName><Scope>CH</Scope><ServiceOption>SCI</ServiceOption>
        <Container containerType="ZIP"/><MsgName version="08" variant="001">camt.053</MsgName>
      </Service><DateRange><Start>2025-10-01</Start><End>2025-10-05</End></DateRange>
    </BTDOrderParams></OrderDetails></static>
    <mutable><TransactionPhase>Initialisation</TransactionPhase></mutable>
  </header><body><TransferReceipt><ReceiptCode>0</ReceiptCode></TransferReceipt></body>
</ebicsRequest>'''.encode()


def iso_doc(message: str, body: str) -> bytes:
    return f'<Document xmlns="{ISO}{message}">{body}</Document>'.encode()


def pacs008() -> bytes:
    return iso_doc(
        "pacs.008.001.08",
        '''<FIToFICstmrCdtTrf><GrpHdr><MsgId>SCTI-001</MsgId>
<CreDtTm>2025-10-05T12:00:00.123Z</CreDtTm><NbOfTxs>1</NbOfTxs>
<TtlIntrBkSttlmAmt Ccy="EUR">120.48</TtlIntrBkSttlmAmt><IntrBkSttlmDt>2025-10-05</IntrBkSttlmDt>
<SttlmInf><SttlmMtd>CLRG</SttlmMtd></SttlmInf></GrpHdr>
<CdtTrfTxInf><PmtId><InstrId>INSTR-1</InstrId><EndToEndId>E2E-1</EndToEndId>
<TxId>TX-1</TxId><UETR>8a562c67-ca16-48ba-b074-65581be6f011</UETR></PmtId>
<PmtTpInf><SvcLvl><Cd>SEPA</Cd></SvcLvl><LclInstrm><Cd>INST</Cd></LclInstrm></PmtTpInf>
<IntrBkSttlmAmt Ccy="EUR">120.48</IntrBkSttlmAmt><IntrBkSttlmDt>2025-10-05</IntrBkSttlmDt>
<AccptncDtTm>2025-10-05T12:00:00.123Z</AccptncDtTm><ChrgBr>SLEV</ChrgBr>
<Dbtr><Nm>Alice Example</Nm></Dbtr><DbtrAcct><Id><IBAN>DE89370400440532013000</IBAN></Id></DbtrAcct>
<DbtrAgt><FinInstnId><BICFI>DEUTDEFF</BICFI></FinInstnId></DbtrAgt>
<CdtrAgt><FinInstnId><BICFI>WESTGB2L</BICFI></FinInstnId></CdtrAgt>
<Cdtr><Nm>Bob Example</Nm></Cdtr><CdtrAcct><Id><IBAN>GB82WEST12345698765432</IBAN></Id></CdtrAcct>
<RmtInf><Ustrd>CSCTF{schema_checked_pacs}</Ustrd></RmtInf></CdtTrfTxInf>
</FIToFICstmrCdtTrf>''',
    )


def camt053() -> bytes:
    return iso_doc(
        "camt.053.001.08",
        '''<BkToCstmrStmt><GrpHdr><MsgId>STMT-1</MsgId><CreDtTm>2025-10-05T12:00:00Z</CreDtTm></GrpHdr>
<Stmt><Id>S-1</Id><CreDtTm>2025-10-05T12:00:00Z</CreDtTm>
<Acct><Id><IBAN>DE89370400440532013000</IBAN></Id><Ccy>EUR</Ccy></Acct>
<Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy="EUR">200.00</Amt>
<CdtDbtInd>CRDT</CdtDbtInd><Dt><Dt>2025-10-04</Dt></Dt></Bal>
<Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy="EUR">79.52</Amt>
<CdtDbtInd>CRDT</CdtDbtInd><Dt><Dt>2025-10-05</Dt></Dt></Bal>
<Ntry><NtryRef>N-1</NtryRef><Amt Ccy="EUR">120.48</Amt><CdtDbtInd>DBIT</CdtDbtInd>
<Sts><Cd>BOOK</Cd></Sts><BkTxCd><Prtry><Cd>SCTI</Cd></Prtry></BkTxCd>
<NtryDtls><TxDtls><Refs><EndToEndId>E2E-1</EndToEndId></Refs>
<RmtInf><Ustrd>statement evidence</Ustrd></RmtInf></TxDtls></NtryDtls></Ntry>
</Stmt></BkToCstmrStmt>''',
    )


def pacs002(status: str = "ACCP") -> bytes:
    reason = "" if status == "ACCP" else "<StsRsnInf><Rsn><Cd>AC01</Cd></Rsn><AddtlInf>bad account</AddtlInf></StsRsnInf>"
    return iso_doc(
        "pacs.002.001.10",
        f'''<FIToFIPmtStsRpt><GrpHdr><MsgId>STATUS-1</MsgId><CreDtTm>2025-10-05T12:00:01.123Z</CreDtTm></GrpHdr>
<OrgnlGrpInfAndSts><OrgnlMsgId>SCTI-001</OrgnlMsgId><OrgnlMsgNmId>pacs.008.001.08</OrgnlMsgNmId>
<GrpSts>{status}</GrpSts>{reason}</OrgnlGrpInfAndSts>
<TxInfAndSts><StsId>STS-1</StsId><OrgnlInstrId>INSTR-1</OrgnlInstrId>
<OrgnlEndToEndId>E2E-1</OrgnlEndToEndId><OrgnlTxId>TX-1</OrgnlTxId>
<OrgnlUETR>8a562c67-ca16-48ba-b074-65581be6f011</OrgnlUETR><TxSts>{status}</TxSts>{reason}
<OrgnlTxRef><PmtTpInf><LclInstrm><Cd>INST</Cd></LclInstrm></PmtTpInf></OrgnlTxRef>
</TxInfAndSts></FIToFIPmtStsRpt>''',
    )


def camt054() -> bytes:
    return iso_doc(
        "camt.054.001.08",
        '''<BkToCstmrDbtCdtNtfctn><GrpHdr><MsgId>NOTIFY-1</MsgId><CreDtTm>2025-10-05T12:00:02Z</CreDtTm></GrpHdr>
<Ntfctn><Id>NTF-1</Id><CreDtTm>2025-10-05T12:00:02Z</CreDtTm>
<Acct><Id><IBAN>DE89370400440532013000</IBAN></Id><Ccy>EUR</Ccy></Acct>
<Ntry><NtryRef>NTRY-1</NtryRef><Amt Ccy="EUR">120.48</Amt><CdtDbtInd>CRDT</CdtDbtInd>
<Sts><Cd>INFO</Cd></Sts><AcctSvcrRef>ASR-1</AcctSvcrRef>
<NtryDtls><TxDtls><Refs><EndToEndId>E2E-1</EndToEndId><TxId>TX-1</TxId></Refs>
<RmtInf><Ustrd>instant notification</Ustrd></RmtInf></TxDtls></NtryDtls>
</Ntry></Ntfctn></BkToCstmrDbtCdtNtfctn>''',
    )


def validate_published_schema(data: bytes, message: str) -> None:
    path = Path(E.__file__).with_name("fin2_schemas") / f"{message}.xsd"
    schema = etree.XMLSchema(etree.parse(str(path)))
    root = etree.fromstring(data)
    assert schema.validate(root), str(schema.error_log)


def test_published_h005_transfer_vector_and_signature_evidence() -> None:
    report = E.parse_ebics(h005_transfer())
    assert report["protocol_version"] == "H005"
    assert report["revision"] == "1"
    assert report["header"] == {
        **report["header"],
        "host_id": "EBIXHOST",
        "transaction_id": "ABCDEF41394644363445313243ABCDEF",
        "transaction_phase": "Transfer",
        "segment_number": "4",
        "last_segment": "true",
        "number_of_segments": "4",
    }
    signature = report["auth_signature"]
    assert signature["present"] is True and signature["verified"] is False
    assert signature["signature_method"].endswith("rsa-sha256")
    assert signature["references"][0]["uri"] == "#xpointer(//*[@authenticate='true'])"
    assert signature["references"][0]["digest_method"].endswith("sha256")
    payload = b"published H005 transfer payload"
    assert report["body"]["order_data"] == {
        "encoded_chars": len(base64.b64encode(payload)),
        "decoded_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    assert report["security_state"] == "signature-present-not-verified"


def test_h004_legacy_order_and_h005_btf_are_distinct() -> None:
    legacy = E.parse_ebics(h004_hvu())
    assert legacy["protocol_version"] == "H004"
    assert legacy["order"]["order_type"] == "HVU"
    assert legacy["order"]["order_attribute"] == "DZNNN"
    assert legacy["order"]["order_parameters"]["OrderTypes"] == ["IZV"]
    assert "btf" not in legacy["order"]

    modern = E.parse_ebics(h005_btf())
    assert modern["order"]["admin_order_type"] == "BTD"
    btf = modern["order"]["btf"]
    assert btf["direction"] == "download"
    assert btf["service"]["ServiceName"]["value"] == "STM"
    assert btf["service"]["Scope"]["value"] == "CH"
    assert btf["service"]["ServiceOption"]["value"] == "SCI"
    assert btf["service"]["Container"]["attributes"]["containerType"] == "ZIP"
    assert btf["service"]["MsgName"] == {
        "value": "camt.053",
        "attributes": {"variant": "001", "version": "08"},
    }
    assert btf["date_range"] == {"start": "2025-10-01", "end": "2025-10-05"}


def test_pacs008_is_xsd_valid_and_sct_inst_fields_are_extended() -> None:
    data = pacs008()
    validate_published_schema(data, "pacs.008.001.08")
    report = E.parse_iso20022(data, profile="sct-inst-2025")
    assert report["schema_valid"] is True and report["valid"] is True
    assert report["group_header"]["message_id"] == "SCTI-001"
    tx = report["transactions"][0]
    assert tx["uetr"] == "8a562c67-ca16-48ba-b074-65581be6f011"
    assert tx["settlement_amount"] == {"value": "120.48", "currency": "EUR"}
    assert tx["local_instruments"] == ["INST"]
    assert tx["service_levels"] == ["SEPA"]
    assert tx["debtor_agent"] == "DEUTDEFF" and tx["creditor_agent"] == "WESTGB2L"
    assert report["sct_inst"]["conforms_to_checked_subset"] is True
    assert report["flags"] == ["CSCTF{schema_checked_pacs}"]


def test_camt053_is_xsd_valid_and_delegated_without_rebuilding() -> None:
    data = camt053()
    validate_published_schema(data, "camt.053.001.08")
    report = E.parse_iso20022(data)
    assert report["schema_valid"] is True and report["valid"] is True
    statement = report["statements"][0]
    assert statement["account"] == "DE89370400440532013000"
    assert statement["entries"][0]["amount"] == "-120.48"
    assert statement["reconciled"] is True


@pytest.mark.parametrize("status", ["ACCP", "RJCT"])
def test_pacs002_status_correlation_and_profile(status: str) -> None:
    report = E.parse_iso20022(pacs002(status), profile="sct-inst-2025")
    assert report["valid"] is True
    assert report["original_group"]["message_id"] == "SCTI-001"
    assert report["original_group"]["message_name"] == "pacs.008.001.08"
    assert report["original_group"]["group_status"] == status
    tx = report["statuses"][0]
    assert tx["original_end_to_end_id"] == "E2E-1"
    assert tx["original_uetr"] == "8a562c67-ca16-48ba-b074-65581be6f011"
    assert tx["transaction_status"] == status
    assert tx["original_local_instrument"] == "INST"
    assert report["sct_inst"]["observed_statuses"] == [status, status]
    assert report["sct_inst"]["conforms_to_checked_subset"] is True
    if status == "RJCT":
        assert tx["reasons"][0]["code"] == "AC01"


def test_camt054_is_a_notification_not_a_statement() -> None:
    report = E.parse_iso20022(camt054())
    assert report["valid"] is True
    assert report["report_kind"] == "debit-credit-notification"
    assert "statements" not in report
    notice = report["notifications"][0]
    assert notice["account"] == "DE89370400440532013000"
    entry = notice["entries"][0]
    assert entry["amount"] == {"value": "120.48", "currency": "EUR"}
    assert entry["status"] == "INFO"
    assert entry["transactions"][0]["end_to_end_id"] == "E2E-1"
    assert entry["transactions"][0]["remittance"] == ["instant notification"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.replace(b'Version="H005"', b'Version="H004"', 1),
        lambda value: value.replace(b"<HostID>EBIXHOST</HostID>", b"<HostID>EBIXHOST</HostID><HostID>HIDDEN</HostID>"),
        lambda value: value.replace(b"<body>", b"<body><DataTransfer/>", 1),
        lambda value: value.replace(b"URI=\"#xpointer", b"URI=\"https://evil.invalid/#xpointer"),
        lambda value: value.replace(base64.b64encode(b"published H005 transfer payload"), b"not!base64"),
    ],
)
def test_ebics_structural_tampering_fails_closed(mutation) -> None:
    with pytest.raises(E.SecBankEbicsError) as caught:
        E.parse_ebics(mutation(h005_transfer()))
    assert type(caught.value) is E.SecBankEbicsError


def test_mixed_protocol_namespace_and_wrong_xmldsig_namespace() -> None:
    mixed = h005_transfer().replace(
        b"<HostID>EBIXHOST</HostID>",
        f'<HostID>EBIXHOST</HostID><x:OrderDetails xmlns:x="{H004}"/>'.encode(),
    )
    wrong_ds = h005_transfer().replace(DS.encode(), b"urn:not-xmldsig")
    for data in (mixed, wrong_ds):
        with pytest.raises(E.SecBankEbicsError) as caught:
            E.parse_ebics(data)
        assert type(caught.value) is E.SecBankEbicsError


@pytest.mark.parametrize(
    "data",
    [
        b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
        b'<!DOCTYPE x SYSTEM "https://invalid.example/x.dtd"><x/>',
        b'<ebicsRequest xmlns="urn:org:ebics:H005" Version="H005"><header/><body><xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd"/></body></ebicsRequest>',
    ],
)
def test_xml_external_features_are_forbidden(data: bytes) -> None:
    with pytest.raises(E.SecBankEbicsError) as caught:
        E.parse_ebics(data)
    assert type(caught.value) is E.SecBankEbicsError


@pytest.mark.parametrize("entrypoint", [E.parse_ebics, E.parse_iso20022])
@pytest.mark.parametrize("bad", [None, 0, {}, [], b"", "", b"\xff\xfe", b"noise"])
def test_bad_types_and_noise_raise_only_declared_error(entrypoint, bad) -> None:
    with pytest.raises(E.SecBankEbicsError) as caught:
        entrypoint(bad)
    assert type(caught.value) is E.SecBankEbicsError


def test_released_buffer_and_oversize_raise_only_declared_error() -> None:
    view = memoryview(bytearray(h005_transfer()))
    view.release()
    for entrypoint, data in (
        (E.parse_ebics, view),
        (E.parse_iso20022, view),
        (E.parse_ebics, b"x" * (E.MAX_BYTES + 1)),
        (E.parse_iso20022, b"x" * (E.MAX_BYTES + 1)),
    ):
        with pytest.raises(E.SecBankEbicsError) as caught:
            entrypoint(data)
        assert type(caught.value) is E.SecBankEbicsError


@pytest.mark.parametrize("data", [h005_transfer(), pacs002()])
def test_every_truncation_and_seeded_mutation_is_clean_or_declared(data: bytes) -> None:
    entrypoint = E.parse_ebics if b"ebicsRequest" in data else E.parse_iso20022
    for end in range(0, len(data), 29):
        with pytest.raises(E.SecBankEbicsError) as caught:
            entrypoint(data[:end])
        assert type(caught.value) is E.SecBankEbicsError
    rng = random.Random(0xEB1C5)
    for _ in range(80):
        pos = rng.randrange(len(data))
        mutant = data[:pos] + bytes([data[pos] ^ (1 << rng.randrange(8))]) + data[pos + 1 :]
        try:
            result = entrypoint(mutant)
            assert isinstance(result, dict)
        except E.SecBankEbicsError as exc:
            assert type(exc) is E.SecBankEbicsError


def test_iso_document_cardinality_profile_and_decimal_fail_closed() -> None:
    duplicate_body = pacs002().replace(
        b"</Document>",
        b"<FIToFIPmtStsRpt><GrpHdr><MsgId>x</MsgId><CreDtTm>2025-01-01T00:00:00Z</CreDtTm></GrpHdr></FIToFIPmtStsRpt></Document>",
    )
    bad_decimal = camt054().replace(b">120.48<", b">NaN<")
    for data in (duplicate_body, bad_decimal):
        with pytest.raises(E.SecBankEbicsError) as caught:
            E.parse_iso20022(data)
        assert type(caught.value) is E.SecBankEbicsError
    with pytest.raises(E.SecBankEbicsError) as caught:
        E.parse_iso20022(pacs002(), profile=[])
    assert type(caught.value) is E.SecBankEbicsError


@pytest.mark.parametrize(
    "data,entrypoint",
    [
        (
            b'<ebicsRequest xmlns="urn:org:ebics:H005" Version="H005"><header/><body/></ebicsRequest>',
            E.parse_ebics,
        ),
        (
            iso_doc(
                "pacs.002.001.10",
                "<FIToFIPmtStsRpt><GrpHdr/></FIToFIPmtStsRpt>",
            ),
            E.parse_iso20022,
        ),
        (
            iso_doc(
                "camt.054.001.08",
                "<BkToCstmrDbtCdtNtfctn><GrpHdr/></BkToCstmrDbtCdtNtfctn>",
            ),
            E.parse_iso20022,
        ),
    ],
)
def test_schema_invalid_empty_skeletons_fail_closed(data, entrypoint) -> None:
    with pytest.raises(E.SecBankEbicsError) as caught:
        entrypoint(data)
    assert type(caught.value) is E.SecBankEbicsError


def test_cli_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "transfer.xml"
    path.write_bytes(h005_transfer())
    assert E.main(["ebics", str(path)]) == 0
    assert E.main(["--help"]) == 0
    assert E.main([]) == 2
    assert E.main(["ebics", str(path) + ".missing"]) == 2

    def noninteger_exit(self, args=None, namespace=None):  # noqa: ANN001
        raise SystemExit("not-an-int")

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", noninteger_exit)
    assert E.main([]) == 2

