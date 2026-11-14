"""Independent vectors for the passive OpenADR/SAE EV-grid analyzer.

The literal IDs and report values below are published by the OpenADR Alliance
Demand Response Program Guide v1.1.  The XML itself is a hand-authored fixture
following the documented OpenADR 2.0b envelope/layout and was independently
validated against the published OpenADR 2.0b XSD family; it is not emitted by
the engine.  lxml XPath assertions independently establish each oracle value
before the engine's extraction is compared with it.
"""

from __future__ import annotations

import argparse
import json

import pytest
from lxml import etree

import sec_evcharge_openadr as oadr


NS = {
    "oadr": "http://openadr.org/oadr-2.0b/2012/07",
    "ei": "http://docs.oasis-open.org/ns/energyinterop/201110",
    "pyld": "http://docs.oasis-open.org/ns/energyinterop/201110/payloads",
    "xcal": "urn:ietf:params:xml:ns:icalendar-2.0",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


EVENT_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<oadr:oadrPayload
 xmlns:oadr="http://openadr.org/oadr-2.0b/2012/07"
 xmlns:ei="http://docs.oasis-open.org/ns/energyinterop/201110"
 xmlns:pyld="http://docs.oasis-open.org/ns/energyinterop/201110/payloads"
 xmlns:xcal="urn:ietf:params:xml:ns:icalendar-2.0"
 xmlns:strm="urn:ietf:params:xml:ns:icalendar-2.0:stream"
 xmlns:emix="http://docs.oasis-open.org/ns/emix/2011/06"
 xmlns:gml="http://www.opengis.net/gml/3.2"
 xmlns:dsp="http://openadr.org/oadr-2.0b/2012/07/xmldsig-properties"
 xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
 <ds:Signature>
  <ds:SignedInfo>
   <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
   <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
   <ds:Reference URI="#signed-event-1">
    <ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>AA==</ds:DigestValue>
   </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AA==</ds:SignatureValue>
  <ds:Object>
   <ds:SignatureProperties>
    <ds:SignatureProperty Id="replay-property-1" Target="#signed-event-1">
     <dsp:ReplayProtect>
      <dsp:timestamp>2013-02-01T20:53:31Z</dsp:timestamp>
      <dsp:nonce EncodingType="urn:ietf:params:xml:ns:base64">bm9uY2U=</dsp:nonce>
     </dsp:ReplayProtect>
    </ds:SignatureProperty>
   </ds:SignatureProperties>
  </ds:Object>
 </ds:Signature>
 <oadr:oadrSignedObject oadr:Id="signed-event-1">
  <oadr:oadrDistributeEvent ei:schemaVersion="2.0b">
   <pyld:requestID>OadrDisReq091214_043740_513</pyld:requestID>
   <ei:vtnID>TH_VTN</ei:vtnID>
   <oadr:oadrEvent>
    <ei:eiEvent>
     <ei:eventDescriptor>
      <ei:eventID>EV-PUBLIC-CHARGING-1</ei:eventID>
      <ei:modificationNumber>0</ei:modificationNumber>
      <ei:priority>1</ei:priority>
      <ei:eiMarketContext><emix:marketContext>http://market.example/retail</emix:marketContext></ei:eiMarketContext>
      <ei:createdDateTime>2013-02-01T20:53:32Z</ei:createdDateTime>
      <ei:eventStatus>far</ei:eventStatus>
      <ei:testEvent>false</ei:testEvent>
     </ei:eventDescriptor>
     <ei:eiActivePeriod>
      <xcal:properties>
       <xcal:dtstart><xcal:date-time>2013-02-02T00:00:00Z</xcal:date-time></xcal:dtstart>
       <xcal:duration><xcal:duration>PT30M</xcal:duration></xcal:duration>
      </xcal:properties>
      <xcal:components/>
     </ei:eiActivePeriod>
     <ei:eiEventSignals>
      <ei:eiEventSignal>
       <strm:intervals>
        <ei:interval>
         <xcal:dtstart><xcal:date-time>2013-02-02T00:00:00Z</xcal:date-time></xcal:dtstart>
         <xcal:duration><xcal:duration>PT15M</xcal:duration></xcal:duration>
         <xcal:uid><xcal:text>0</xcal:text></xcal:uid>
         <ei:signalPayload><ei:payloadFloat><ei:value>1.5</ei:value></ei:payloadFloat></ei:signalPayload>
        </ei:interval>
        <ei:interval>
         <xcal:dtstart><xcal:date-time>2013-02-02T00:15:00Z</xcal:date-time></xcal:dtstart>
         <xcal:duration><xcal:duration>PT15M</xcal:duration></xcal:duration>
         <xcal:uid><xcal:text>1</xcal:text></xcal:uid>
         <ei:signalPayload><ei:payloadFloat><ei:value>0.5</ei:value></ei:payloadFloat></ei:signalPayload>
        </ei:interval>
       </strm:intervals>
       <ei:signalName>SIMPLE</ei:signalName>
       <ei:signalType>level</ei:signalType>
       <ei:signalID>SIG-EV-1</ei:signalID>
       <ei:currentValue><ei:payloadFloat><ei:value>0.0</ei:value></ei:payloadFloat></ei:currentValue>
      </ei:eiEventSignal>
     </ei:eiEventSignals>
     <ei:eiTarget><ei:resourceID>EVSE-17</ei:resourceID><ei:venID>VEN-EV-CHARGER-1</ei:venID></ei:eiTarget>
    </ei:eiEvent>
    <oadr:oadrResponseRequired>always</oadr:oadrResponseRequired>
   </oadr:oadrEvent>
  </oadr:oadrDistributeEvent>
 </oadr:oadrSignedObject>
</oadr:oadrPayload>
"""


REPORT_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<oadr:oadrPayload
 xmlns:oadr="http://openadr.org/oadr-2.0b/2012/07"
 xmlns:ei="http://docs.oasis-open.org/ns/energyinterop/201110"
 xmlns:pyld="http://docs.oasis-open.org/ns/energyinterop/201110/payloads"
 xmlns:xcal="urn:ietf:params:xml:ns:icalendar-2.0"
 xmlns:strm="urn:ietf:params:xml:ns:icalendar-2.0:stream">
 <oadr:oadrSignedObject oadr:Id="signed-report-1">
  <oadr:oadrUpdateReport ei:schemaVersion="2.0b">
   <pyld:requestID>ReportUpdReqID130615_192730_445</pyld:requestID>
   <oadr:oadrReport>
    <strm:intervals>
     <ei:interval>
      <xcal:dtstart><xcal:date-time>2013-06-15T19:27:30Z</xcal:date-time></xcal:dtstart>
      <xcal:duration><xcal:duration>PT5M</xcal:duration></xcal:duration>
      <xcal:uid><xcal:text>0</xcal:text></xcal:uid>
      <oadr:oadrReportPayload>
       <ei:rID>real_power</ei:rID>
       <ei:confidence>100</ei:confidence>
       <ei:accuracy>0.0</ei:accuracy>
       <ei:payloadFloat><ei:value>500.0</ei:value></ei:payloadFloat>
       <oadr:oadrDataQuality>Quality Good - Non Specific</oadr:oadrDataQuality>
      </oadr:oadrReportPayload>
     </ei:interval>
    </strm:intervals>
    <ei:eiReportID>RP_54321</ei:eiReportID>
    <ei:reportRequestID>RR_54321</ei:reportRequestID>
    <ei:reportSpecifierID>RS_12345</ei:reportSpecifierID>
    <ei:reportName>METADATA_TELEMETRY_USAGE</ei:reportName>
    <ei:createdDateTime>2013-06-15T19:27:30Z</ei:createdDateTime>
   </oadr:oadrReport>
   <ei:venID>VEN_123</ei:venID>
  </oadr:oadrUpdateReport>
 </oadr:oadrSignedObject>
</oadr:oadrPayload>
"""


def test_alliance_program_guide_event_anchor_and_handbuilt_eievent():
    # Independent lxml extraction establishes the published fixture values.
    root = etree.fromstring(EVENT_XML)
    assert root.xpath("string(//pyld:requestID)", namespaces=NS) == "OadrDisReq091214_043740_513"
    assert root.xpath("string(//ei:vtnID)", namespaces=NS) == "TH_VTN"
    assert root.xpath("count(//ei:interval)", namespaces=NS) == 2.0

    result = oadr.parse_openadr2(EVENT_XML)
    assert result["format"] == "openadr-2.0b"
    assert result["operation"] == "oadrDistributeEvent"
    assert result["schema_version"] == "2.0b"
    assert result["request_id"] == "OadrDisReq091214_043740_513"
    assert result["vtn_id"] == "TH_VTN"
    event = result["events"][0]
    assert event["descriptor"]["event_id"] == "EV-PUBLIC-CHARGING-1"
    assert event["descriptor"]["modification_number"] == 0
    assert event["active_period"] == {
        "start": "2013-02-02T00:00:00Z",
        "duration": "PT30M",
        "notification": None,
        "ramp_up": None,
        "recovery": None,
        "tolerance": {"start_after": None},
    }
    assert event["targets"] == {
        "venID": ["VEN-EV-CHARGER-1"], "resourceID": ["EVSE-17"]
    }
    assert event["response_required"] == "always"
    signal = event["signals"][0]
    assert (signal["signal_name"], signal["signal_type"], signal["signal_id"]) == (
        "SIMPLE", "level", "SIG-EV-1"
    )
    assert [row["uid"] for row in signal["intervals"]] == ["0", "1"]
    assert [row["payloads"][0]["value"] for row in signal["intervals"]] == [1.5, 0.5]


def test_xmldsig_inventory_is_structural_not_a_verification_oracle():
    result = oadr.parse_openadr2(EVENT_XML)
    signature = result["signature"]
    assert signature["present"] is True
    assert signature["signed_object_id"] == "signed-event-1"
    assert signature["signatures"][0]["references"][0]["uri"] == "#signed-event-1"
    assert signature["signatures"][0]["references"][0]["resolved_within_document"] is True
    assert signature["wrapping_indicators"] == []
    assert signature["profile_indicators"] == []
    assert signature["signatures"][0]["replay_protect"] == {
        "present": True,
        "count": 1,
        "timestamp": "2013-02-01T20:53:31Z",
        "nonce_present": True,
    }
    assert signature["cryptographically_verified"] is False


def test_signed_openadr2_reports_missing_replay_protection() -> None:
    missing = EVENT_XML.replace(b"ReplayProtect", b"NotReplayProtect")
    signature = oadr.parse_openadr2(missing)["signature"]
    assert signature["wrapping_indicators"] == []
    assert signature["profile_indicators"] == [
        {"code": "missing-replay-protect", "signature": 0, "count": 0}
    ]


def test_alliance_program_guide_fast_dr_report_anchor():
    root = etree.fromstring(REPORT_XML)
    assert root.xpath("string(//pyld:requestID)", namespaces=NS) == "ReportUpdReqID130615_192730_445"
    assert root.xpath("string(//ei:rID)", namespaces=NS) == "real_power"
    assert float(root.xpath("string(//ei:payloadFloat/ei:value)", namespaces=NS)) == 500.0

    result = oadr.parse_openadr2(REPORT_XML)
    assert result["operation"] == "oadrUpdateReport"
    assert result["request_id"] == "ReportUpdReqID130615_192730_445"
    report = result["reports"][0]
    assert report["report_id"] == "RP_54321"
    assert "duration" not in report
    assert report["intervals"][0]["duration"] == "PT5M"
    payload = report["intervals"][0]["payloads"][0]
    assert payload["r_id"] == "real_power"
    assert payload["confidence"] == 100
    assert payload["accuracy"] == 0.0
    assert payload["data_quality"] == "Quality Good - Non Specific"
    assert payload["value"] == 500.0
    assert payload["value_type"] == "payloadFloat"


@pytest.mark.parametrize(
    "bad_report",
    [
        REPORT_XML.replace(b"<ei:value>500.0</ei:value>", b"<ei:value>NaN</ei:value>"),
        REPORT_XML.replace(b"<ei:confidence>100</ei:confidence>", b"<ei:confidence>101</ei:confidence>"),
    ],
    ids=("nonfinite-payload", "confidence-out-of-range"),
)
def test_openadr2_numeric_report_fields_fail_closed(bad_report):
    with pytest.raises(oadr.SecEvchargeOpenADRError):
        oadr.parse_openadr2(bad_report)


@pytest.mark.parametrize(
    "bad_xml",
    [
        EVENT_XML.replace(
            b"2013-02-01T20:53:32Z", b"not-a-date", 1
        ),
        EVENT_XML.replace(
            b"2013-02-02T00:00:00Z", b"2013-02-30T00:00:00Z", 1
        ),
        EVENT_XML.replace(b"PT30M", b"not-a-duration", 1),
    ],
    ids=("created-date-time", "dtstart-calendar", "duration"),
)
def test_openadr2_temporal_fields_fail_closed(bad_xml):
    with pytest.raises(oadr.SecEvchargeOpenADRError):
        oadr.parse_openadr2(bad_xml)


@pytest.mark.parametrize(
    "bad_xml",
    [
        b'<!DOCTYPE x [<!ENTITY xx "boom">]><x/>',
        EVENT_XML.replace(b"<oadr:oadrPayload", b"<?audit no?>\n<oadr:oadrPayload", 1),
        EVENT_XML.replace(
            b"<oadr:oadrDistributeEvent ei:schemaVersion=\"2.0b\">",
            b'<oadr:oadrDistributeEvent ei:schemaVersion="2.0b"><xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd"/>',
            1,
        ),
        EVENT_XML.replace(
            b'xmlns:oadr="http://openadr.org/oadr-2.0b/2012/07"',
            b'xmlns:oadr="urn:not-openadr"',
            1,
        ),
        EVENT_XML.replace(
            b"</oadr:oadrDistributeEvent>",
            b"</oadr:oadrDistributeEvent><oadr:oadrPoll><ei:venID>VEN-1</ei:venID></oadr:oadrPoll>",
            1,
        ),
        EVENT_XML.replace(
            b"<ei:eventDescriptor>", b'<ei:eventDescriptor Id="signed-event-1">', 1
        ),
        EVENT_XML.replace(b'ei:schemaVersion="2.0b"', b'ei:schemaVersion="2.0a"', 1),
        EVENT_XML.replace(
            b"<ei:eventDescriptor>",
            b'<ds:Signature><ds:SignedInfo/></ds:Signature><ei:eventDescriptor>',
            1,
        ),
        EVENT_XML.replace(b"<ei:eventID>", b"<ds:eventID>", 1).replace(
            b"</ei:eventID>", b"</ds:eventID>", 1
        ),
    ],
    ids=(
        "dtd-entity", "processing-instruction", "xinclude", "wrong-namespace",
        "multiple-operations", "duplicate-id", "wrong-schema-version", "nested-signature",
        "wrong-namespace-local-name-spoof",
    ),
)
def test_openadr2_security_and_cardinality_fail_closed(bad_xml):
    with pytest.raises(oadr.SecEvchargeOpenADRError):
        oadr.parse_openadr2(bad_xml)


PROGRAM = {
    "objectType": "PROGRAM",
    "id": "program-1",
    "programName": "EV managed charging",
    "createdDateTime": "2026-01-02T03:04:05Z",
    "timeZoneOffset": "-PT5H",
}
EVENT = {
    "objectType": "EVENT",
    "id": "event-1",
    "programID": "program-1",
    "intervals": [
        {
            "id": -7,
            "intervalPeriod": {"start": "2026-01-02T04:00:00Z", "duration": "-P1W"},
            "payloads": [{"type": "PRICE", "values": [0.15]}],
        }
    ],
}
REPORT = {
    "objectType": "REPORT",
    "id": "report-1",
    "programID": "program-1",
    "eventID": "event-1",
    "clientName": "VEN client",
    "resources": [
        {
            "resourceName": "EVSE 17",
            "intervals": [
                {"id": 1, "payloads": [{"type": "POWER_REAL", "values": [500.0]}]}
            ],
        }
    ],
}
RESOURCE = {
    "objectType": "RESOURCE",
    "id": "resource-1",
    "resourceName": "EVSE 17",
    "venID": "ven-1",
}
VEN = {"objectType": "VEN", "id": "ven-1", "venName": "Fleet VEN"}
SUBSCRIPTION = {
    "objectType": "SUBSCRIPTION",
    "id": "subscription-1",
    "clientName": "VEN client",
    "programID": "program-1",
    "objectOperations": [
        {
            "objects": ["EVENT", "REPORT"],
            "operations": ["READ", "UPDATE"],
            "callbackUrl": "https://ven.example.test/openadr/callback",
        }
    ],
}


def test_openadr3_pinned_resource_shapes_and_time_fields():
    parsed = oadr.parse_openadr3(
        json.dumps(EVENT), version="3.0.1", resource_kind="event"
    )
    assert parsed["format"] == "openadr-3"
    assert parsed["version"] == "3.0.1"
    assert parsed["resource_kind"] == "event"
    assert parsed["id"] == "event-1"
    assert parsed["object"]["intervals"][0]["id"] == -7
    assert parsed["object"]["intervals"][0]["intervalPeriod"]["duration"] == "-P1W"
    assert parsed["object"]["intervals"][0]["payloads"][0] == {
        "type": "PRICE", "values": [0.15]
    }

    program = oadr.parse_openadr3(
        json.dumps(PROGRAM), version="3.0.1", resource_kind="program"
    )
    assert program["object"]["timeZoneOffset"] == "-PT5H"


def test_openadr3_priority_is_a_nonnegative_integer():
    assert oadr.parse_openadr3(
        json.dumps({**EVENT, "priority": 0}),
        version="3.0.1",
        resource_kind="event",
    )["object"]["priority"] == 0
    for invalid in (-1, True, 1.5, None):
        with pytest.raises(oadr.SecEvchargeOpenADRError, match="priority"):
            oadr.parse_openadr3(
                json.dumps({**EVENT, "priority": invalid}),
                version="3.0.1",
                resource_kind="event",
            )


def test_openadr3_schema_permits_empty_arrays_and_signed_interval_ids():
    empty_event = {**EVENT, "intervals": []}
    assert oadr.parse_openadr3(
        json.dumps(empty_event), version="3.0.1", resource_kind="event"
    )["valid"] is True
    assert oadr.parse_openadr3(
        '{"type":"PRICE","values":[]}',
        version="3.0.1", resource_kind="valuesMap",
    )["valid"] is True
    empty_report = {**REPORT, "resources": []}
    assert oadr.parse_openadr3(
        json.dumps(empty_report), version="3.0.1", resource_kind="report"
    )["valid"] is True
    empty_subscription = {**SUBSCRIPTION, "objectOperations": []}
    assert oadr.parse_openadr3(
        json.dumps(empty_subscription), version="3.0.1", resource_kind="subscription"
    )["valid"] is True


def test_openadr3_subscription_nested_required_fields_and_enums():
    parsed = oadr.parse_openadr3(
        json.dumps(SUBSCRIPTION), version="3.0.1", resource_kind="subscription"
    )
    assert parsed["object"]["objectOperations"][0]["objects"] == ["EVENT", "REPORT"]
    assert parsed["object"]["objectOperations"][0]["operations"] == ["READ", "UPDATE"]

    bad_operations = [
        {"objects": ["EVENT"], "operations": ["READ"]},
        {"objects": ["NOT_AN_OBJECT"], "operations": ["READ"],
         "callbackUrl": "https://ven.example.test/callback"},
        {"objects": ["EVENT"], "operations": ["EXECUTE"],
         "callbackUrl": "https://ven.example.test/callback"},
        {"objects": ["EVENT"], "operations": ["READ"], "callbackUrl": "/relative"},
    ]
    for operation in bad_operations:
        candidate = {**SUBSCRIPTION, "objectOperations": [operation]}
        with pytest.raises(oadr.SecEvchargeOpenADRError):
            oadr.parse_openadr3(
                json.dumps(candidate), version="3.0.1", resource_kind="subscription"
            )


def test_openadr3_subscription_operations_are_version_pinned():
    operation_300 = {
        "objects": ["EVENT", "REPORT"],
        "operations": ["GET", "POST", "PUT", "DELETE"],
        "callbackUrl": "https://ven.example.test/callback",
    }
    subscription_300 = {**SUBSCRIPTION, "objectOperations": [operation_300]}
    parsed = oadr.parse_openadr3(
        json.dumps(subscription_300), version="3.0.0", resource_kind="subscription"
    )
    assert parsed["object"]["objectOperations"][0]["operations"] == [
        "GET", "POST", "PUT", "DELETE"
    ]

    with pytest.raises(oadr.SecEvchargeOpenADRError, match="OpenADR 3.0.1"):
        oadr.parse_openadr3(
            json.dumps(subscription_300), version="3.0.1", resource_kind="subscription"
        )
    with pytest.raises(oadr.SecEvchargeOpenADRError, match="OpenADR 3.0.0"):
        oadr.parse_openadr3(
            json.dumps(SUBSCRIPTION), version="3.0.0", resource_kind="subscription"
        )


def test_openadr2_accepts_gml_inside_normative_emix_service_area():
    with_service_area = EVENT_XML.replace(
        b"</ei:eiTarget>",
        b'<emix:serviceArea><gml:Point gml:id="service-point-1">'
        b"<gml:pos>44.4268 26.1025</gml:pos></gml:Point></emix:serviceArea>"
        b"</ei:eiTarget>",
        1,
    )
    result = oadr.parse_openadr2(with_service_area)
    assert result["events"][0]["targets"]["serviceArea"] == ["44.4268 26.1025"]


def test_openadr3_supplied_bundle_reference_oracle():
    bundle = {
        "programs": [PROGRAM], "events": [EVENT], "reports": [REPORT],
        "subscriptions": [SUBSCRIPTION], "resources": [RESOURCE], "vens": [VEN],
    }
    good = oadr.analyze_openadr3_bundle(bundle, version="3.0.1")
    assert good["valid"] is True
    assert good["issues"] == []
    assert good["counts"] == {
        "program": 1, "event": 1, "report": 1,
        "subscription": 1, "ven": 1, "resource": 1,
    }

    bad = json.loads(json.dumps(bundle))
    bad["events"][0]["programID"] = "program-missing"
    bad["reports"][0]["eventID"] = "event-missing"
    checked = oadr.analyze_openadr3_bundle(bad, version="3.0.1")
    assert checked["valid"] is False
    assert {(row["source_kind"], row["field"]) for row in checked["issues"]} == {
        ("event", "programID"), ("report", "eventID")
    }


@pytest.mark.parametrize(
    ("raw", "version", "kind"),
    [
        ('{"programName":"one","programName":"two"}', "3.0.1", "program"),
        ('{"programName":"one","score":NaN}', "3.0.1", "program"),
        (json.dumps(EVENT), "3.1.0", "event"),
        ('{"objectType":"PROGRAM"}', "3.0.1", "program"),
        (json.dumps({**PROGRAM, "objectType": "EVENT"}), "3.0.1", "program"),
        (json.dumps({**EVENT, "intervals": [{"id": 1 << 31, "payloads": []}]}), "3.0.1", "event"),
        (json.dumps({**PROGRAM, "timeZoneOffset": "UTC-05:00"}), "3.0.1", "program"),
    ],
)
def test_openadr3_strict_json_and_version_boundaries(raw, version, kind):
    with pytest.raises(oadr.SecEvchargeOpenADRError):
        oadr.parse_openadr3(raw, version=version, resource_kind=kind)


def test_sae_family_catalog_does_not_invent_a_wire_format():
    catalog = oadr.sae_catalog("J2847/1")
    assert catalog["standards"]["J2847/1"]["application_protocol"] == (
        "Smart Energy Profile 2.0 / IEEE 2030.5"
    )
    assert catalog["generic_wire_format"] is None
    mapped = oadr.map_sae_use_case("bidirectional-der")
    assert mapped["standards"] == ["J2836/3", "J2847/3", "IEEE 2030.5"]
    assert mapped["wire_decoder"] is None


@pytest.mark.parametrize(
    "call",
    [
        lambda: oadr.parse_openadr2(None),
        lambda: oadr.parse_openadr3("{}", version=object(), resource_kind="program"),
        lambda: oadr.parse_openadr3("{}", version="3.0.1", resource_kind=object()),
        lambda: oadr.analyze_openadr3_bundle({"programs": [object()]}, version="3.0.1"),
        lambda: oadr.sae_catalog(42),
        lambda: oadr.map_sae_use_case(None),
    ],
)
def test_all_public_malformed_paths_raise_only_declared_error(call):
    with pytest.raises(oadr.SecEvchargeOpenADRError):
        call()


def test_guarded_cli_and_real_file(tmp_path, monkeypatch):
    path = tmp_path / "event.xml"
    path.write_bytes(EVENT_XML)
    assert oadr.main(["openadr2", str(path)]) == 0
    assert oadr.main([]) == 2
    assert oadr.main(["--help"]) == 0

    def noninteger_exit(self, argv=None):
        raise SystemExit("argument error")

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", noninteger_exit)
    assert oadr.main([]) == 2
