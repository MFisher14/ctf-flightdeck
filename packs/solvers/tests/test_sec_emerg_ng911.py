"""Independent RFC/NENA-derived vectors for the offline NG9-1-1 reader.

The XML and SIP fixtures are hand-built from RFC 6442 section 5.1
(https://www.rfc-editor.org/rfc/rfc6442.html), RFC 5222 figures 1/5
(https://www.rfc-editor.org/rfc/rfc5222.html), RFC 7852 sections 4/7
(https://www.rfc-editor.org/rfc/rfc7852.html), and the APCO/NENA 2.105.1-2017
IEPD's published ``EIDD Sample CallHandlingToIncidentHandling.xml`` plus a
minimum-instance EIDD.  They are not emitted by the engine under test.
"""

import base64
import json

import pytest

import sec_emerg_ng911 as engine


PIDF_POINT = b"""<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf"
 xmlns:gp="urn:ietf:params:xml:ns:pidf:geopriv10"
 xmlns:gbp="urn:ietf:params:xml:ns:pidf:geopriv10:basicPolicy"
 xmlns:gml="http://www.opengis.net/gml"
 xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model"
 entity="pres:alice@atlanta.example.com">
 <dm:device id="target123-1">
  <gp:geopriv>
   <gp:location-info><gml:location><gml:Point srsName="urn:ogc:def:crs:EPSG::4326"><gml:pos>32.86726 -97.16054</gml:pos></gml:Point></gml:location></gp:location-info>
   <gp:usage-rules><gbp:retransmission-allowed>false</gbp:retransmission-allowed></gp:usage-rules>
   <gp:method>GPS</gp:method>
  </gp:geopriv>
  <dm:timestamp>2007-12-02T14:00:00Z</dm:timestamp>
 </dm:device>
</presence>"""


PIDF_CIVIC = b"""<presence xmlns="urn:ietf:params:xml:ns:pidf"
 xmlns:gp="urn:ietf:params:xml:ns:pidf:geopriv10"
 xmlns:cl="urn:ietf:params:xml:ns:pidf:geopriv10:civicAddr"
 xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" entity="pres:caller@example.test">
 <dm:device id="phone"><gp:geopriv><gp:location-info>
  <cl:civicAddress><cl:country>US</cl:country><cl:A1>OH</cl:A1><cl:A3>Columbus</cl:A3><cl:RD>Airport</cl:RD><cl:STS>DR</cl:STS><cl:HNO>2901</cl:HNO><cl:PC>43219</cl:PC></cl:civicAddress>
 </gp:location-info><gp:usage-rules/><gp:method>Manual</gp:method></gp:geopriv></dm:device>
</presence>"""


LOST_QUERY = b"""<?xml version="1.0" encoding="UTF-8"?>
<findService xmlns="urn:ietf:params:xml:ns:lost1"
 xmlns:gml="http://www.opengis.net/gml" serviceBoundary="value" recursive="true">
 <location id="6020688f1ce1896d" profile="geodetic-2d">
  <gml:Point srsName="urn:ogc:def:crs:EPSG::4326"><gml:pos>37.775 -122.422</gml:pos></gml:Point>
 </location><service>urn:service:sos.police</service>
</findService>"""


LOST_RESPONSE = b"""<findServiceResponse xmlns="urn:ietf:params:xml:ns:lost1">
 <mapping expires="2030-01-01T00:00:00Z" lastUpdated="2026-01-01T00:00:00Z"
  source="ecrf.state.example" sourceId="mapping-1">
  <displayName xml:lang="en">Columbus PSAP</displayName><service>urn:service:sos</service>
  <serviceBoundaryReference source="ecrf.state.example" key="boundary-1"/>
  <uri>sip:psap@esinet.example</uri><serviceNumber>911</serviceNumber>
 </mapping><locationValidation><valid>country A1 A3 RD HNO PC</valid><unchecked>STS</unchecked></locationValidation>
 <warnings source="ecrf.state.example"><defaultMappingReturned/></warnings>
 <path><via source="ecrf.state.example"/></path><locationUsed id="6020688f1ce1896d"/>
</findServiceResponse>"""


def emergency_block(token="ProviderInfo", reference="provider-1@example.test"):
    ns = f"urn:ietf:params:xml:ns:EmergencyCallData:{token}"
    content = {
        "ProviderInfo": (
            f"<DataProviderReference>{reference}</DataProviderReference>"
            "<DataProviderString>Diamond State Exemplar</DataProviderString>"
            "<ProviderID>urn:nena:companyid:example</ProviderID>"
            "<ProviderIDSeries>NENA</ProviderIDSeries>"
            "<TypeOfProvider>Access Network Provider</TypeOfProvider>"
            "<ContactURI>tel:+1-302-555-0000</ContactURI><Language>en</Language>"
        ),
        "ServiceInfo": (
            f"<DataProviderReference>{reference}</DataProviderReference>"
            "<ServiceEnvironment>home</ServiceEnvironment>"
            "<ServiceType>wireless</ServiceType><ServiceMobility>mobile</ServiceMobility>"
        ),
        "DeviceInfo": f"<DataProviderReference>{reference}</DataProviderReference>",
        "SubscriberInfo": (
            f"<DataProviderReference>{reference}</DataProviderReference>"
            '<SubscriberData><vcard xmlns="urn:ietf:params:xml:ns:vcard-4.0">'
            "<fn><text>Example Subscriber</text></fn></vcard></SubscriberData>"
        ),
        "Comment": (
            f"<DataProviderReference>{reference}</DataProviderReference>"
            '<Comment xml:lang="en">Published-profile example.</Comment>'
        ),
    }[token]
    privacy = ' privacyRequested="false"' if token == "SubscriberInfo" else ""
    return f'<EmergencyCallData.{token} xmlns="{ns}"{privacy}>{content}</EmergencyCallData.{token}>'.encode()


EIDD = b"""<eidd:EmergencyIncidentDataDocument xmlns:eidd="http://eidd.nena.org"
 xmlns:nc="http://niem.gov/niem/niem-core/2.0">
 <eidd:ReasonForIssueRegistryText>new incident</eidd:ReasonForIssueRegistryText>
 <nc:DocumentCreationDate>2026-11-05T12:00:00Z</nc:DocumentCreationDate>
 <eidd:IssuingElementIdentification>callhandling@psap.example</eidd:IssuingElementIdentification>
 <nc:DocumentIdentification>550e8400-e29b-41d4-a716-446655440000</nc:DocumentIdentification>
 <eidd:Agent><eidd:AgentIdentification>agent-7</eidd:AgentIdentification><eidd:AgentDeviceRoleRegistryText>call-taker</eidd:AgentDeviceRoleRegistryText></eidd:Agent>
</eidd:EmergencyIncidentDataDocument>"""


# APCO/NENA EIDD IEPD member, with insignificant whitespace normalized:
# schema/information/EIDD-IEPD/xml/EIDD Sample CallHandlingToIncidentHandling.xml
EIDD_PUBLISHED_SAMPLE = b"""<?xml version="1.0" encoding="UTF-8"?>
<!-- Sample EIDD Instance where call information passed from Call Handling to Incident Handling FE  -->
<eidd:EmergencyIncidentDataDocument xmlns:eidd="http://eidd.nena.org" xmlns:nc="http://niem.gov/niem/niem-core/2.0" xmlns:pidf="urn:ietf:params:xml:ns:pidf" xmlns:vcard="urn:ietf:params:xml:ns:vcard-4.0" xmlns:ansi-nist="http://niem.gov/niem/ansi-nist/2.0" xmlns:j="http://niem.gov/niem/domains/jxdm/4.1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:n1="http://www.altova.com/samplexml/other-namespace" xmlns:com="urn:ietf:params:xml:ns:EmergencyCallData:Comment" xmlns:ecd-dev="urn:ietf:params:xml:ns:EmergencyCallData:DeviceInfo" xmlns:svc="urn:ietf:params:xml:ns:EmergencyCallData:ServiceInfo" xmlns:pi="urn:ietf:params:xml:ns:EmergencyCallData:ProviderInfo" xmlns:ecd-sub="urn:ietf:params:xml:ns:EmergencyCallData:SubscriberInfo" xsi:schemaLocation="http://eidd.nena.org ../xsd/EIDD.xsd">
 <eidd:IncidentTrackingIdentification>
  <nc:IdentificationID>urn:nena:uid:incidentid:a56e556d873:bcf.state.or.us</nc:IdentificationID>
 </eidd:IncidentTrackingIdentification>
 <eidd:ReasonForIssueRegistryText>CallAnswered</eidd:ReasonForIssueRegistryText>
 <nc:DocumentCreationDate>
  <nc:DateTime>2015-11-02T08:20:00-08:00</nc:DateTime>
 </nc:DocumentCreationDate>
 <eidd:IssuingElementIdentification>callhandling.boec.psap.or.us</eidd:IssuingElementIdentification>
 <nc:DocumentIdentification>
  <nc:IdentificationID>124e4567-e89b-12d3-a456-426655440000</nc:IdentificationID>
 </nc:DocumentIdentification>
 <eidd:Agent>
  <eidd:AgentIdentification>
   <nc:IdentificationID>JohnGJones@boec.psap.or.us</nc:IdentificationID>
  </eidd:AgentIdentification>
  <eidd:AgentWorkstationPositionIdentification>
   <nc:IdentificationID>2@boec.psap.or.us</nc:IdentificationID>
  </eidd:AgentWorkstationPositionIdentification>
  <eidd:AgentDeviceRoleRegistryText>Call taker</eidd:AgentDeviceRoleRegistryText>
  <eidd:Agency>
   <nc:OrganizationIdentification>
    <nc:IdentificationID>boec.psap.or.us</nc:IdentificationID>
   </nc:OrganizationIdentification>
   <eidd:AgencyRoleDescriptionRegistryText>CallReceiving</eidd:AgencyRoleDescriptionRegistryText>
   <eidd:AgencyContactURL>https://boec.org/xcard.xcf</eidd:AgencyContactURL>
  </eidd:Agency>
 </eidd:Agent>
 <eidd:Call>
  <eidd:CallIdentifier>urn:nena:uid:callid:a58e556d874:bcf.state.or.us</eidd:CallIdentifier>
  <eidd:CallTypeDescriptionRegistryText>EmergencyCall</eidd:CallTypeDescriptionRegistryText>
  <nc:ActivityDateRange>
   <nc:StartDate>
    <nc:DateTime>2015-11-02T08:19:49-01:00</nc:DateTime>
   </nc:StartDate>
  </nc:ActivityDateRange>
  <eidd:CallStatusRegistryText>Active</eidd:CallStatusRegistryText>
  <eidd:DeviceCallBackInformationURL>tel:1-503-823-1234</eidd:DeviceCallBackInformationURL>
  <eidd:CallerCallBackInformationURL>tel:1-503-823-1234</eidd:CallerCallBackInformationURL>
  <eidd:Location>
   <eidd:LocationTypeDescriptionRegistryText>Caller</eidd:LocationTypeDescriptionRegistryText>
   <eidd:LocationByReferenceURL>sip:call12345@somecell.example.com </eidd:LocationByReferenceURL>
   <eidd:CellTowerSectorID>59, 194, Alpha</eidd:CellTowerSectorID>
  </eidd:Location>
 </eidd:Call>
</eidd:EmergencyIncidentDataDocument>"""


def sip_message(body, content_type, extra_headers):
    headers = [
        "INVITE urn:service:sos SIP/2.0",
        "Via: SIP/2.0/TLS ingress.example;branch=z9hG4bK1",
        "From: <sips:caller@example.test>;tag=one",
        "To: <urn:service:sos>",
        "Call-ID: fixed-call@example.test",
        "CSeq: 1 INVITE",
        *extra_headers,
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "",
        "",
    ]
    return "\r\n".join(headers).encode() + body


def multipart(*parts, boundary="ng911-boundary"):
    output = bytearray()
    for content_type, content_id, data in parts:
        output += f"--{boundary}\r\nContent-Type: {content_type}\r\n".encode()
        if content_id:
            output += f"Content-ID: <{content_id}>\r\n".encode()
        output += b"Content-Transfer-Encoding: binary\r\n\r\n" + data + b"\r\n"
    output += f"--{boundary}--\r\n".encode()
    return bytes(output), f'multipart/mixed; boundary="{boundary}"'


def test_pidf_lo_rfc_point_and_civic_vectors():
    point = engine.parse_pidf_lo(PIDF_POINT)
    assert point["entity"] == "pres:alice@atlanta.example.com"
    location = point["location_objects"][0]
    assert location["source"] == {"kind": "device", "id": "target123-1"}
    assert location["locations"][0]["coordinates"] == [32.86726, -97.16054]
    assert location["usage_rules"]["retransmission-allowed"] == "false"
    assert location["method"] == "GPS"
    assert location["timestamp"] == "2007-12-02T14:00:00Z"

    civic = engine.parse_pidf_lo(PIDF_CIVIC)["location_objects"][0]["locations"][0]
    assert civic["kind"] == "civic"
    assert civic["fields"]["country"] == "US"
    assert civic["fields"]["RD"] == "Airport"
    assert "A6" not in civic["fields"]

    with_confidence = PIDF_POINT.replace(
        b'xmlns:gml="http://www.opengis.net/gml"',
        b'xmlns:gml="http://www.opengis.net/gml" xmlns:con="urn:ietf:params:xml:ns:geopriv:conf"',
    ).replace(b"</gp:location-info>",
              b'</gp:location-info><con:confidence pdf="normal">95</con:confidence>')
    confidence = engine.parse_pidf_lo(with_confidence)["location_objects"][0]
    assert confidence["confidence"] == [{"value": 95.0, "pdf": "normal"}]
    assert any("Point" in issue for issue in confidence["issues"])
    numeric_boolean = engine.parse_pidf_lo(
        PIDF_POINT.replace(b">false</gbp:retransmission-allowed>",
                           b">0</gbp:retransmission-allowed>")
    )
    assert numeric_boolean["location_objects"][0]["usage_rules"]["retransmission-allowed"] == "false"


def test_rfc5491_circle_grammar_and_mandatory_usage_rules():
    circle = b'''<presence xmlns="urn:ietf:params:xml:ns:pidf"
     xmlns:gp="urn:ietf:params:xml:ns:pidf:geopriv10"
     xmlns:gml="http://www.opengis.net/gml"
     xmlns:gs="http://www.opengis.net/pidflo/1.0" entity="pres:circle@example.test">
     <tuple id="circle"><status><gp:geopriv><gp:location-info>
      <gs:Circle srsName="urn:ogc:def:crs:EPSG::4326"><gml:pos>42.5463 -73.2512</gml:pos>
       <gs:radius uom="urn:ogc:def:uom:EPSG::9001">850.24</gs:radius></gs:Circle>
     </gp:location-info><gp:usage-rules/></gp:geopriv></status></tuple></presence>'''
    location = engine.parse_pidf_lo(circle)["location_objects"][0]["locations"][0]
    assert location["shape"] == "Circle"
    assert location["parameters"] == [{
        "name": "radius", "value": 850.24, "uom": "urn:ogc:def:uom:EPSG::9001"
    }]
    with pytest.raises(engine.NG911Error):
        engine.parse_pidf_lo(circle.replace(
            b'<gs:radius uom="urn:ogc:def:uom:EPSG::9001">850.24</gs:radius>', b""
        ))
    with pytest.raises(engine.NG911Error):
        engine.parse_pidf_lo(PIDF_CIVIC.replace(b"<gp:usage-rules/>", b""))
    out_of_order = PIDF_CIVIC.replace(
        b"<cl:country>US</cl:country>", b""
    ).replace(
        b"<cl:PC>43219</cl:PC>",
        b"<cl:PC>43219</cl:PC><cl:country>US</cl:country>",
    )
    with pytest.raises(engine.NG911Error):
        engine.parse_pidf_lo(out_of_order)


def test_lost_rfc_query_response_error_and_redirect():
    query = engine.parse_lost(LOST_QUERY)
    assert query["message"] == "findService"
    assert query["service"] == "urn:service:sos.police"
    assert query["location"]["value"]["coordinates"] == [37.775, -122.422]
    assert query["recursive"] is True

    response = engine.parse_lost(LOST_RESPONSE, expected_location_id="6020688f1ce1896d")
    assert response["mappings"][0]["uris"] == ["sip:psap@esinet.example"]
    assert response["mappings"][0]["boundary"]["mode"] == "reference"
    assert response["location_used"] == ["6020688f1ce1896d"]
    assert response["expected_location_id_matched"] is True
    assert response["location_validation"]["valid"][:2] == ["country", "A1"]
    assert response["warnings"][0]["code"] == "defaultMappingReturned"
    assert response["path"] == ["ecrf.state.example"]
    with pytest.raises(engine.NG911Error):
        engine.parse_lost(LOST_RESPONSE, expected_location_id="different")
    with pytest.raises(engine.NG911Error):
        engine.parse_lost(LOST_QUERY.replace(b'profile="geodetic-2d"', b'profile="civic"'))

    inferred = engine.parse_lost(LOST_QUERY.replace(b' profile="geodetic-2d"', b""))
    assert inferred["locations"][0]["interpreted_profile"] == "geodetic-2d"
    extra = b'''<location id="three-d" profile="geodetic-3d"
      xmlns:gml="http://www.opengis.net/gml"><gml:Point
      srsName="urn:ogc:def:crs:EPSG::4979"><gml:pos>37.775 -122.422 10</gml:pos>
      </gml:Point></location>'''
    multiprofile = LOST_QUERY.replace(b"<service>", extra + b"<service>")
    parsed_multi = engine.parse_lost(multiprofile)
    assert [item["interpreted_profile"] for item in parsed_multi["locations"]] == [
        "geodetic-2d", "geodetic-3d"
    ]

    error = engine.parse_lost(b'<errors xmlns="urn:ietf:params:xml:ns:lost1" source="ecrf.example"><locationInvalid id="x"/></errors>')
    assert error["errors"][0]["code"] == "locationInvalid"
    redirect = engine.parse_lost(b'<redirect xmlns="urn:ietf:params:xml:ns:lost1" target="lost.example" source="old.example"/>')
    assert redirect["target"] == "lost.example" and redirect["fetched"] is False

    with pytest.raises(engine.NG911Error):
        engine.parse_lost(LOST_RESPONSE.replace(b' sourceId="mapping-1"', b""))
    no_cache = engine.parse_lost(
        LOST_RESPONSE.replace(b'expires="2030-01-01T00:00:00Z"', b'expires="NO-CACHE"')
    )
    assert no_cache["mappings"][0]["expires"] == "NO-CACHE"
    with pytest.raises(engine.NG911Error):
        engine.parse_lost(LOST_RESPONSE.replace(
            b'expires="2030-01-01T00:00:00Z"', b'expires="2030-01-01T01:00:00+01:00"'
        ))
    with pytest.raises(engine.NG911Error):
        engine.parse_lost(LOST_RESPONSE.replace(b' xml:lang="en"', b""))
    with pytest.raises(engine.NG911Error):
        engine.parse_lost(LOST_RESPONSE.replace(b">911</serviceNumber>", b">9A1</serviceNumber>"))
    with pytest.raises(engine.NG911Error):
        engine.parse_lost(b'<redirect xmlns="urn:ietf:params:xml:ns:lost1" target="lost.example"/>')
    with pytest.raises(engine.NG911Error):
        engine.parse_lost(b'<redirect xmlns="urn:ietf:params:xml:ns:lost1" target="lost.example" source="old.example" expires="NO-CACHE"/>')
    with pytest.raises(engine.NG911Error):
        engine.parse_lost(LOST_RESPONSE.replace(
            b'<serviceBoundaryReference source="ecrf.state.example" key="boundary-1"/>',
            b"<serviceBoundaryReference/>",
        ))


@pytest.mark.parametrize("token", ["ProviderInfo", "ServiceInfo", "DeviceInfo", "SubscriberInfo", "Comment"])
def test_all_rfc7852_block_mime_root_namespace_triples(token):
    result = engine.parse_emergency_call_data(
        emergency_block(token),
        content_type=f"application/EmergencyCallData.{token}+xml",
        purpose=f"EmergencyCallData.{token}",
    )
    assert result["block"] == token
    assert result["data_provider_references"] == ["provider-1@example.test"]


def test_rfc7852_required_cardinality_and_conditional_fields():
    duplicate = emergency_block("Comment").replace(
        b"</EmergencyCallData.Comment>",
        b"<DataProviderReference>second@example.test</DataProviderReference>"
        b"</EmergencyCallData.Comment>",
    )
    with pytest.raises(engine.NG911Error):
        engine.parse_emergency_call_data(duplicate)
    nonwireless = emergency_block("ServiceInfo").replace(
        b"<ServiceEnvironment>home</ServiceEnvironment>", b""
    ).replace(b"<ServiceType>wireless</ServiceType>", b"<ServiceType>voip</ServiceType>")
    with pytest.raises(engine.NG911Error):
        engine.parse_emergency_call_data(nonwireless)
    device = emergency_block("DeviceInfo").replace(
        b"</EmergencyCallData.DeviceInfo>",
        b"<DeviceSpecificData>https://device.example/data</DeviceSpecificData>"
        b"</EmergencyCallData.DeviceInfo>",
    )
    with pytest.raises(engine.NG911Error):
        engine.parse_emergency_call_data(device)
    missing_provider_id = emergency_block("ProviderInfo").replace(
        b"<ProviderID>urn:nena:companyid:example</ProviderID>", b""
    ).replace(b"<ProviderIDSeries>NENA</ProviderIDSeries>", b"")
    with pytest.raises(engine.NG911Error):
        engine.parse_emergency_call_data(missing_provider_id)
    unpaired_provider_id = emergency_block("ProviderInfo").replace(
        b"<ProviderIDSeries>NENA</ProviderIDSeries>", b""
    )
    with pytest.raises(engine.NG911Error):
        engine.parse_emergency_call_data(unpaired_provider_id)


def test_legacy_eidd_and_current_eido_are_distinct():
    eidd = engine.parse_eidd(EIDD)
    assert eidd["type"] == "eidd" and eidd["status"] == "legacy-withdrawn"
    assert eidd["document_id"] == "550e8400-e29b-41d4-a716-446655440000"

    published = engine.parse_eidd(EIDD_PUBLISHED_SAMPLE)
    assert published["issuing_element"] == "callhandling.boec.psap.or.us"
    assert published["creation_date"] == "2015-11-02T08:20:00-08:00"
    assert published["document_id"] == "124e4567-e89b-12d3-a456-426655440000"
    assert any("official IEPD sample" in issue for issue in published["issues"])

    raw = json.dumps({
        "$id": "urn:emergency:uid:incidentid:abc123:psap.example",
        "eidoVersion": "1.0",
        "lastUpdateTimeStamp": "2026-11-05T12:00:00Z",
        "updatedByAgencyReference": {"$ref": "psap.example"},
        "issuingElementIdentification": "psap.example",
        "agencyComponent": [{
            "$id": "psap.example",
            "lastUpdateTimeStamp": "2026-11-05T12:00:00Z",
            "updatedByAgencyReference": {"$ref": "psap.example"},
            "agencyRoleDescriptionRegistryText": ["CallReceiving"],
            "agencyType": ["police"],
        }],
    }).encode()
    eido = engine.parse_eido(raw)
    assert eido["type"] == "eido" and eido["format"] == "JSON"
    assert eido["version"] == "1.0"
    assert any(item["id"] == "psap.example" for item in eido["components"])


def test_i3_sip_multipart_cid_geolocation_and_additional_data():
    provider = emergency_block("ProviderInfo")
    body, content_type = multipart(
        ("application/pidf+xml", "target123@atlanta.example.com", PIDF_POINT),
        ("application/EmergencyCallData.ProviderInfo+xml", "provider@example.test", provider),
    )
    wire = sip_message(body, content_type, [
        "Route: <sip:esrp@esinet.example;lr>",
        "Geolocation: <cid:target123@atlanta.example.com>",
        "Geolocation-Routing: yes",
        "Call-Info: <cid:provider@example.test>;purpose=EmergencyCallData.ProviderInfo",
        "Call-Info: <urn:emergency:uid:callid:abc123:bcf.example>;purpose=emergency-CallId",
    ])
    result = engine.parse_ng911_sip(wire)
    assert result["service_urn"] == "urn:service:sos"
    assert result["geolocation_routing"] == {"raw": "yes", "effective": "yes"}
    assert result["geolocations"][0]["pidf_lo"]["type"] == "pidf-lo"
    assert result["additional_data"][0]["data"]["block"] == "ProviderInfo"
    assert result["network_activity"] is False
    assert len(result["mime_parts"]) == 2


def test_cid_percent_decoding_and_strict_mime_transfer_encodings():
    body, content_type = multipart(
        ("application/pidf+xml", "target/123@example.test", PIDF_POINT),
    )
    wire = sip_message(body, content_type, [
        "Geolocation: <cid:target%2F123@example.test>",
    ])
    assert engine.parse_ng911_sip(wire)["geolocations"][0]["by_value"] is True

    def encoded_wire(cte, payload):
        boundary = "encoded-boundary"
        encoded_body = (
            f"--{boundary}\r\nContent-Type: application/pidf+xml\r\n"
            "Content-ID: <encoded@example.test>\r\n"
            f"Content-Transfer-Encoding: {cte}\r\n\r\n"
        ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()
        return sip_message(encoded_body, f"multipart/mixed; boundary={boundary}", [
            "Geolocation: <cid:encoded@example.test>",
        ])

    with pytest.raises(engine.NG911Error):
        engine.parse_ng911_sip(encoded_wire(
            "base64", b"!!!!" + base64.b64encode(PIDF_POINT)
        ))
    with pytest.raises(engine.NG911Error):
        engine.parse_ng911_sip(encoded_wire(
            "quoted-printable", b"<!--=ZZ-->" + PIDF_POINT
        ))


@pytest.mark.parametrize("content_type", [
    "garbage",
    "application",
    "text/plain; bad",
    'text/plain; charset="unterminated',
])
def test_malformed_content_type_is_not_repaired(content_type):
    with pytest.raises(engine.NG911Error):
        engine.parse_ng911_sip(sip_message(b"x", content_type, []))

    boundary = "bad-content-type"
    body = (
        f"--{boundary}\r\nContent-Type: {content_type}\r\n\r\nx\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    with pytest.raises(engine.NG911Error):
        engine.parse_ng911_sip(sip_message(
            body, f"multipart/mixed; boundary={boundary}", []
        ))


def test_geolocation_routing_absent_or_extension_is_effectively_no():
    plain = sip_message(b"", "application/sdp", [])
    absent = engine.parse_ng911_sip(plain)
    assert absent["geolocation_routing"]["effective"] == "no"

    extended = sip_message(b"", "application/sdp", ["Geolocation-Routing: maybe"])
    result = engine.parse_ng911_sip(extended)
    assert result["geolocation_routing"]["effective"] == "no"
    assert any("unknown Geolocation-Routing" in issue for issue in result["issues"])


def test_auto_dispatch_and_no_network_reference_preservation():
    assert engine.analyze(PIDF_POINT)["type"] == "pidf-lo"
    wire = sip_message(b"", "application/sdp", [
        "Geolocation: <https://lis.example/location/one>",
        "Call-Info: <https://adr.example/provider/one>;purpose=EmergencyCallData.ProviderInfo",
    ])
    result = engine.analyze(wire)
    assert result["geolocations"][0]["fetched"] is False
    assert result["additional_data"][0]["fetched"] is False


@pytest.mark.parametrize("call,args", [
    (engine.parse_pidf_lo, (None,)),
    (engine.parse_pidf_lo, ("\ud800",)),
    (engine.parse_lost, (b"<findService/>",)),
    (engine.parse_emergency_call_data, (b"<x/>",)),
    (engine.parse_eidd, (b"<x/>",)),
    (engine.parse_eido, (b'{"x":NaN}',)),
    (engine.parse_ng911_sip, (b"INVITE bad SIP/2.0\r\n",)),
    (engine.analyze, (object(),)),
])
def test_public_apis_never_leak_stdlib_or_backend_exceptions(call, args):
    with pytest.raises(engine.NG911Error):
        call(*args)


def test_duplicate_json_dtd_bad_crs_missing_cid_and_mime_boundary_fail_closed():
    with pytest.raises(engine.NG911Error):
        engine.parse_eido(b'{"$id":"urn:emergency:uid:x:y","$id":"urn:emergency:uid:z:y","eidoVersion":"1.0"}')
    with pytest.raises(engine.NG911Error):
        engine.parse_pidf_lo(b'<!DOCTYPE x [<!ENTITY y "z">]><presence xmlns="urn:ietf:params:xml:ns:pidf" entity="x">&y;</presence>')
    with pytest.raises(engine.NG911Error):
        engine.parse_pidf_lo(PIDF_POINT.replace(b"EPSG::4326", b"EPSG::3857"))

    missing = sip_message(b"", "application/sdp", ["Geolocation: <cid:no-such-part>"])
    with pytest.raises(engine.NG911Error):
        engine.parse_ng911_sip(missing)

    broken_body = b"--broken\r\nContent-Type: application/pidf+xml\r\n\r\n" + PIDF_POINT
    broken = sip_message(broken_body, "multipart/mixed; boundary=broken", [])
    with pytest.raises(engine.NG911Error):
        engine.parse_ng911_sip(broken)

    duplicate_type = sip_message(b"", "application/sdp", []).replace(
        b"Content-Type: application/sdp\r\n",
        b"Content-Type: application/sdp\r\nContent-Type: application/pidf+xml\r\n",
    )
    with pytest.raises(engine.NG911Error):
        engine.parse_ng911_sip(duplicate_type)

    with pytest.raises(engine.NG911Error):
        engine.parse_eidd(EIDD.replace(b"<eidd:Agent>", b"<eidd:Other>").replace(
            b"</eidd:Agent>", b"</eidd:Other>"
        ))


def test_cli_guarded_argparse_and_json_output(tmp_path, capsys):
    assert engine.main([]) == 2
    assert engine.main(42) == 2
    assert engine.main(["pidf", "\ud800"]) == 2
    path = tmp_path / "location.xml"
    path.write_bytes(PIDF_POINT)
    assert engine.main(["pidf", str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["type"] == "pidf-lo"

