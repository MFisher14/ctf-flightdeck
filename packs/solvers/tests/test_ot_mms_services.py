"""Independent ISO 9506 / X.227 / X.226 BER vectors for the MMS engine.

The reference constructor below implements only ASN.1 identifier/length wrapping;
all schemas and expected values are handwritten from these primary sources:
https://github.com/wireshark/wireshark/blob/master/epan/dissectors/asn1/mms/mms.asn
https://github.com/wireshark/wireshark/blob/master/epan/dissectors/asn1/acse/acse.asn
https://github.com/wireshark/wireshark/blob/master/epan/dissectors/asn1/pres/ISO8823-PRESENTATION.asn
https://github.com/mz-automation/libiec61850/blob/v1.6_develop/src/mms/iso_mms/asn1c/TypeSpecification.c
https://github.com/rwl/OpenIEC61850/blob/master/src/mms/jmms/asn1/mms/moreASN1Files/mms-epfl.asn
No engine encoder or previously decoded engine output is used as an oracle.
"""

import math
import random

import pytest

import ot_mms_services as mms


def tlv(identifier, payload):
    """Minimal independent definite-length BER constructor, not a MMS encoder."""
    if isinstance(identifier, int):
        identifier = bytes([identifier])
    size = len(payload)
    if size < 128:
        length = bytes([size])
    else:
        octets = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(octets)]) + octets
    return identifier + length + payload


def context(number, payload, constructed=True):
    first = 0xA0 if constructed else 0x80
    if number < 31:
        return tlv(first | number, payload)
    parts = [number & 127]
    while number >> 7:
        number >>= 7
        parts.insert(0, 0x80 | (number & 127))
    return tlv(bytes([first | 31] + parts), payload)


def integer(value, identifier=0x02):
    size = max(1, (value.bit_length() + 8) // 8)
    return tlv(identifier, value.to_bytes(size, "big", signed=True))


def visible(text):
    return tlv(0x1A, text.encode("ascii"))


def domain_name(domain="LD0", item="LLN0$ST$Mod$stVal"):
    return context(1, visible(domain) + visible(item))


def named_variable(name=None):
    # VariableSpecification.name is EXPLICIT [0] ObjectName.
    if name is None:
        name = domain_name()
    return tlv(0x30, context(0, name))


def variable_list(*names):
    # VariableAccessSpecification.listOfVariable is IMPLICIT [0] SEQUENCE OF.
    return context(0, b"".join(named_variable(name) for name in names))


def request(number, body, constructed=True, invoke_id=7):
    return context(0, integer(invoke_id) + context(number, body, constructed))


def response(number, body, constructed=True, invoke_id=7):
    return context(1, integer(invoke_id) + context(number, body, constructed))


def read_request():
    # Read-Request.variableAccessSpecification is EXPLICIT [1].
    return request(4, context(1, variable_list(domain_name())))


def filename(*parts):
    # FileName is SEQUENCE OF GraphicString, not VisibleString or UTF8String.
    return b"".join(tlv(0x19, part.encode("ascii")) for part in parts)


APP_CONTEXT = bytes.fromhex("060528ca220203")  # 1.0.9506.2.3
MMS_SYNTAX = bytes.fromhex("060528ca220201")  # 1.0.9506.2.1
ACSE_SYNTAX = bytes.fromhex("060452010001")  # 2.2.1.0.1
BER_SYNTAX = bytes.fromhex("06025101")  # 2.1.1


def association_request(inner=None):
    payload = context(1, APP_CONTEXT)
    if inner is not None:
        # Association-data is SEQUENCE OF EXTERNAL, IMPLICIT [30].
        external = tlv(0x28, MMS_SYNTAX + integer(3) + context(0, inner))
        payload += context(30, external)
    return tlv(0x60, payload)


def association_response(result=0, diagnostic=0):
    return tlv(
        0x61,
        context(1, APP_CONTEXT)
        + context(2, integer(result))
        + context(3, context(1, integer(diagnostic))),
    )


def presentation_data(inner, context_id=3):
    # Fully-encoded-data [APPLICATION 1] IMPLICIT SEQUENCE OF PDV-list.
    return tlv(0x61, tlv(0x30, integer(context_id) + context(0, inner)))


def presentation_connect(inner):
    acse = tlv(0x30, integer(1) + ACSE_SYNTAX + tlv(0x30, BER_SYNTAX))
    data = tlv(0x30, integer(3) + MMS_SYNTAX + tlv(0x30, BER_SYNTAX))
    return tlv(
        0x31,
        context(0, integer(1, 0x80))
        + context(2, context(4, acse + data) + presentation_data(inner, 1)),
    )


def test_read_domain_name_and_explicit_wrappers():
    parsed = mms.parse_mms(read_request())
    assert parsed["protocol"] == "mms"
    assert parsed["pdu"] == "confirmed_request"
    assert parsed["invoke_id"] == 7
    assert parsed["service"] == {"number": 4, "name": "read"}
    assert parsed["details"]["specification_with_result"] is False
    assert parsed["details"]["variable_access"] == {
        "kind": "list_of_variable",
        "variables": [
            {"name": {"scope": "domain", "domain_id": "LD0", "item_id": "LLN0$ST$Mod$stVal"}}
        ],
    }


@pytest.mark.parametrize("tag,scope", [(0, "vmd"), (2, "aa")])
def test_read_named_variable_lists(tag, scope):
    name = context(tag, b"dataset", False)
    wire = request(4, tlv(0x80, b"\xff") + context(1, context(1, name)))
    result = mms.parse_mms(wire)["details"]
    assert result["specification_with_result"] is True
    assert result["variable_access"] == {
        "kind": "variable_list_name",
        "name": {"scope": scope, "identifier": "dataset"},
    }


def test_write_typed_values_and_signed_integer():
    names = variable_list(domain_name("LD0", "GGIO1$SP$Int$setVal"), domain_name("LD0", "GGIO1$SP$Ena$setVal"))
    wire = request(5, names + context(0, integer(-129, 0x85) + tlv(0x83, b"\xff")))
    result = mms.parse_mms(wire)
    assert result["service"] == {"number": 5, "name": "write"}
    assert result["details"]["data"] == [
        {"type": "integer", "value": -129},
        {"type": "boolean", "value": True},
    ]
    assert result["details"]["variable_access"]["variables"][1]["name"]["item_id"] == "GGIO1$SP$Ena$setVal"


def test_get_variable_access_attributes_and_structure_type():
    query = request(6, context(0, domain_name()))
    assert mms.parse_mms(query)["details"]["name"]["item_id"] == "LLN0$ST$Mod$stVal"
    # TypeSpecification.structure.components entries contain explicit [1] type.
    component = tlv(0x30, tlv(0x80, b"stVal") + context(1, tlv(0x85, b"\x20")))
    structure = context(2, context(1, component))
    wire = response(6, tlv(0x80, b"\x00") + context(2, structure))
    details = mms.parse_mms(wire)["details"]
    assert details["mms_deletable"] is False
    assert details["type_specification"] == {
        "type": "structure", "packed": False,
        "components": [{"name": "stVal", "type_specification": {"type": "integer", "width": 32}}],
    }


def test_define_named_variable_numeric_address_and_array_type():
    array = context(1, integer(4, 0x81) + context(2, tlv(0x83, b"")))
    wire = request(7, context(0, domain_name()) + context(1, integer(4096, 0x80)) + context(2, array))
    details = mms.parse_mms(wire)["details"]
    assert details["name"]["scope"] == "domain"
    assert details["address"] == {"kind": "numeric", "value": 4096}
    assert details["type_specification"] == {
        "type": "array", "packed": False, "number_of_elements": 4,
        "element_type": {"type": "boolean"},
    }
    assert mms.parse_mms(response(7, b"", constructed=False))["details"] == {}


@pytest.mark.parametrize("type_wire,expected", [
    (context(7, integer(32) + integer(8)), {"type": "floating_point", "format_width": 32, "exponent_width": 8}),
    (tlv(0x91, b""), {"type": "utc_time"}),
    (integer(-255, 0x90), {"type": "mms_string", "size": -255}),
])
def test_iec61850_type_extensions_from_libiec61850(type_wire, expected):
    # libiec61850's asn1c TypeSpecification.c: floatingpoint has UNIVERSAL
    # INTEGER members, utcTime is IMPLICIT NULL, mMSString is Integer32.
    wire = response(6, tlv(0x80, b"\x00") + context(2, type_wire))
    assert mms.parse_mms(wire)["details"]["type_specification"] == expected


def test_mms_string_type_explicit_epfl_variant():
    # OpenIEC61850's mms-epfl.asn TypeDescription.mMSString is [16] Integer32,
    # without IMPLICIT, unlike the libiec61850 ASN.1 variant above.
    wire = response(6, tlv(0x80, b"\x00") + context(2, context(16, integer(-255))))
    assert mms.parse_mms(wire)["details"]["type_specification"] == {"type": "mms_string", "size": -255}


def test_define_and_get_named_variable_list():
    wire = request(11, domain_name("LD0", "events") + variable_list(domain_name()))
    details = mms.parse_mms(wire)["details"]
    assert details["name"]["item_id"] == "events"
    assert details["variables"][0]["name"]["item_id"] == "LLN0$ST$Mod$stVal"
    get_wire = request(12, domain_name("LD0", "events"))
    assert mms.parse_mms(get_wire)["details"]["name"]["item_id"] == "events"
    reply = response(12, tlv(0x80, b"\xff") + context(1, named_variable(domain_name())))
    details = mms.parse_mms(reply)["details"]
    assert details["mms_deletable"] is True
    assert details["variables"][0]["name"]["domain_id"] == "LD0"


def test_define_and_get_named_type():
    wire = request(14, context(0, b"CounterType", False) + tlv(0x86, b"\x20"))
    details = mms.parse_mms(wire)["details"]
    assert details["name"] == {"scope": "vmd", "identifier": "CounterType"}
    assert details["type_specification"] == {"type": "unsigned", "width": 32}
    reply = response(15, tlv(0x80, b"\xff") + tlv(0x86, b"\x20"))
    assert mms.parse_mms(reply)["details"]["type_specification"] == {"type": "unsigned", "width": 32}


@pytest.mark.parametrize("number", [10, 13, 16])
def test_delete_objects_default_scope_and_counts(number):
    wire = request(number, context(1, domain_name()))
    details = mms.parse_mms(wire)["details"]
    assert details["scope_of_delete"] == 0
    assert details["names"][0]["domain_id"] == "LD0"
    reply = response(number, integer(3, 0x80) + integer(2, 0x81))
    assert mms.parse_mms(reply)["details"] == {"number_matched": 3, "number_deleted": 2}


def test_status_identify_and_object_names():
    assert mms.parse_mms(request(0, b"\xff", constructed=False))["details"]["extended_derivation"] is True
    assert mms.parse_mms(response(0, integer(0, 0x80) + integer(1, 0x81)))["details"] == {
        "logical_status": 0, "physical_status": 1,
    }
    identify = response(2, tlv(0x80, b"IED vendor") + tlv(0x81, b"relay") + tlv(0x82, b"1.0"))
    assert mms.parse_mms(identify)["details"] == {"vendor": "IED vendor", "model": "relay", "revision": "1.0"}
    # ObjectClass basicObjectClass [0], ObjectScope domainSpecific [1].
    query = request(1, context(0, integer(0, 0x80)) + context(1, tlv(0x81, b"LD0")))
    assert mms.parse_mms(query)["details"] == {
        "object_class": 0, "object_scope": {"scope": "domain", "domain_id": "LD0"},
    }
    reply = response(1, context(0, visible("LLN0") + visible("GGIO1")))
    assert mms.parse_mms(reply)["details"] == {"identifiers": ["LLN0", "GGIO1"], "more_follows": True}


@pytest.mark.parametrize("pdu,name", [(8, "initiate_request"), (9, "initiate_response")])
def test_initiate_negotiation(pdu, name):
    detail = integer(1, 0x80) + tlv(0x81, b"\x05\xf0\x00") + tlv(0x82, b"\x00\x0c")
    wire = context(pdu, integer(65000, 0x80) + integer(5, 0x81) + integer(6, 0x82)
                   + integer(10, 0x83) + context(4, detail))
    parsed = mms.parse_mms(wire)
    assert parsed["pdu"] == name
    assert parsed["details"] == {
        "max_outstanding_calling": 5, "max_outstanding_called": 6,
        "version": 1, "local_detail": 65000, "nesting_level": 10,
        "parameter_cbb": {"hex": "f000", "unused_bits": 5, "bit_length": 11},
        "services_supported": {"hex": "0c", "unused_bits": 0, "bit_length": 8},
    }


def test_confirmed_error_class_and_description():
    error = context(0, integer(3, 0x87)) + tlv(0x82, b"access denied")
    parsed = mms.parse_mms(context(2, integer(7, 0x80) + context(2, error)))
    assert parsed["pdu"] == "confirmed_error"
    assert parsed["invoke_id"] == 7
    assert parsed["details"] == {"error_class": 7, "code": 3, "additional_description": "access denied"}


def test_read_response_success_and_failure():
    wire = response(4, context(1, integer(257, 0x86) + tlv(0x80, b"\x03")))
    result = mms.parse_mms(wire)
    assert result["pdu"] == "confirmed_response"
    assert result["details"]["access_results"] == [
        {"success": True, "data": {"type": "unsigned", "value": 257}},
        {"success": False, "error": 3, "error_name": "object_access_denied"},
    ]


def test_information_report_named_dataset():
    access = context(1, domain_name("LD0", "LLN0$DS$events"))
    data = context(0, tlv(0x8A, b"CSCTF{offline_mms}") + integer(42, 0x85))
    wire = context(3, context(0, access + data))
    result = mms.parse_mms(wire)
    assert result["pdu"] == "unconfirmed"
    assert result["service"] == {"number": 0, "name": "information_report"}
    assert result["details"]["variable_access"]["name"]["item_id"] == "LLN0$DS$events"
    assert result["details"]["access_results"] == [
        {"success": True, "data": {"type": "visible_string", "value": "CSCTF{offline_mms}"}},
        {"success": True, "data": {"type": "integer", "value": 42}},
    ]


def test_large_first_oid_subidentifier():
    # X.690: first subidentifier is base128(40*2+999)=base128(1079)=88 37.
    wire = response(4, context(1, tlv(0x8F, bytes.fromhex("883703"))))
    value = mms.parse_mms(wire)["details"]["access_results"][0]["data"]
    assert value == {"type": "object_identifier", "value": "2.999.3"}


def test_file_open_high_tag_request():
    wire = request(72, context(0, filename("COMTRADE", "trip.cfg")) + integer(512, 0x81))
    result = mms.parse_mms(wire)
    assert result["service"] == {"number": 72, "name": "file_open"}
    assert result["details"]["file_name"] == ["COMTRADE", "trip.cfg"]
    assert result["details"]["initial_position"] == 512


def test_file_open_response_attributes():
    attrs = integer(123456, 0x80) + tlv(0x81, b"20261105120000Z")
    wire = response(72, integer(9, 0x80) + context(1, attrs))
    details = mms.parse_mms(wire)["details"]
    assert details["frsm_id"] == 9
    assert details["file_attributes"]["size_of_file"] == 123456
    assert details["file_attributes"]["last_modified"] == "20261105120000Z"


@pytest.mark.parametrize("number,name", [(73, "file_read"), (74, "file_close")])
def test_primitive_file_service_requests(number, name):
    wire = request(number, b"\x7f", constructed=False)
    result = mms.parse_mms(wire)
    assert result["service"] == {"number": number, "name": name}
    assert result["details"]["frsm_id"] == 127


@pytest.mark.parametrize("suffix,expected", [(b"", True), (b"\x81\x01\x00", False)])
def test_file_read_binary_payload_and_default_more_follows(suffix, expected):
    payload = b"\x00\xffCSCTF{file_payload}\x00"
    details = mms.parse_mms(response(73, tlv(0x80, payload) + suffix))["details"]
    assert details["file_data"] == payload
    assert details["more_follows"] is expected


def test_file_rename_and_delete():
    wire = request(75, context(0, filename("old.cfg")) + context(1, filename("new.cfg")))
    details = mms.parse_mms(wire)["details"]
    assert details["current_file_name"] == ["old.cfg"]
    assert details["new_file_name"] == ["new.cfg"]
    result = mms.parse_mms(request(76, filename("old.cfg")))
    assert result["service"]["name"] == "file_delete"
    assert result["details"]["file_name"] == ["old.cfg"]


def test_file_directory_explicit_sequence_wrapper():
    wire = request(77, context(0, filename("*")) + context(1, filename("previous.cfg")))
    details = mms.parse_mms(wire)["details"]
    assert details["file_specification"] == ["*"]
    assert details["continue_after"] == ["previous.cfg"]
    entry = tlv(0x30, context(0, filename("trip.cfg")) + context(1, integer(1024, 0x80)))
    # [0] SEQUENCE OF DirectoryEntry: explicit wrapping is required here.
    reply = response(77, context(0, tlv(0x30, entry)))
    result = mms.parse_mms(reply)["details"]
    assert result["more_follows"] is False
    assert result["directory_entries"][0]["file_name"] == ["trip.cfg"]
    assert result["directory_entries"][0]["file_attributes"]["size_of_file"] == 1024


def test_read_journal_range():
    # TimeOfDay uses 4-byte milliseconds since midnight plus optional 2-byte days.
    start = bytes.fromhex("000003e8")  # 1000 milliseconds
    body = (
        context(0, domain_name("LD0", "eventJournal"))
        + context(1, tlv(0x80, start))
        + context(2, integer(10, 0x81))
        + context(4, visible("GGIO1$ST$Ind1$stVal"))
        + context(5, tlv(0x80, start) + tlv(0x81, b"entry42"))
    )
    result = mms.parse_mms(request(65, body))
    assert result["service"] == {"number": 65, "name": "read_journal"}
    assert result["details"]["journal_name"] == {
        "scope": "domain", "domain_id": "LD0", "item_id": "eventJournal"
    }
    assert result["details"]["list_of_variables"] == ["GGIO1$ST$Ind1$stVal"]
    assert result["details"]["range_stop"] == {"number_of_entries": 10}


def test_journal_status_and_create_delete():
    result = mms.parse_mms(response(68, integer(513, 0x80) + tlv(0x81, b"\xff")))
    assert result["service"] == {"number": 68, "name": "report_journal_status"}
    assert result["details"]["current_entries"] == 513
    assert result["details"]["mms_deletable"] is True
    for number, name in [(69, "create_journal"), (70, "delete_journal")]:
        parsed = mms.parse_mms(request(number, context(0, context(0, b"events", False))))
        assert parsed["service"]["name"] == name
        assert parsed["details"]["journal_name"] == {"scope": "vmd", "identifier": "events"}


def test_write_journal_annotation_and_read_journal_entry():
    time = tlv(0x80, bytes.fromhex("000003e80000"))
    content = time + tlv(0x83, b"breaker opened")
    write = request(66, context(0, domain_name("LD0", "events")) + context(1, tlv(0x30, content)))
    details = mms.parse_mms(write)["details"]
    expected_content = {
        "occurrence_time": {"milliseconds": 1000, "days_since_1984": 0, "iso": "1984-01-01T00:00:01+00:00"},
        "annotation": "breaker opened",
    }
    assert details["entries"] == [expected_content]
    # JournalEntry.originatingApplication [1] is explicit ApplicationReference SEQUENCE.
    entry = tlv(0x30, tlv(0x80, b"id42") + context(1, tlv(0x30, b"")) + context(2, content))
    read = response(65, context(0, entry))
    assert mms.parse_mms(read)["details"] == {
        "entries": [{"entry_identifier": "69643432", "originating_application": {}, "content": expected_content}],
        "more_follows": False,
    }


def test_write_journal_data_event_and_value():
    event = context(0, context(0, domain_name("LD0", "trip")) + integer(1, 0x81))
    var = tlv(0x30, tlv(0x80, b"current") + context(1, integer(500, 0x85)))
    content = tlv(0x80, bytes.fromhex("00000000")) + context(2, event + context(1, var))
    wire = request(66, context(0, context(0, b"events", False)) + context(1, tlv(0x30, content)))
    entry = mms.parse_mms(wire)["details"]["entries"][0]
    assert entry["event"] == {
        "name": {"scope": "domain", "domain_id": "LD0", "item_id": "trip"}, "current_state": 1,
    }
    assert entry["variables"] == [{"tag": "current", "data": {"type": "integer", "value": 500}}]


def test_initialize_journal_limit_and_count():
    limit = tlv(0x80, bytes.fromhex("000003e8")) + tlv(0x81, b"id42")
    wire = request(67, context(0, domain_name("LD0", "events")) + context(1, limit))
    assert mms.parse_mms(wire)["details"]["limit"] == {"time": {"milliseconds": 1000}, "entry": "69643432"}
    assert mms.parse_mms(response(67, b"\x2a", constructed=False))["details"] == {"entries_deleted": 42}


def test_obtain_file_source_and_destination():
    wire = request(46, context(1, filename("source.cfg")) + context(2, filename("dest.cfg")))
    assert mms.parse_mms(wire)["details"] == {"source_file": ["source.cfg"], "destination_file": ["dest.cfg"]}


def test_acse_aarq_external_contains_mms():
    parsed = mms.parse_acse(association_request(read_request()))
    assert parsed["protocol"] == "acse"
    assert parsed["pdu"] == "aarq"
    assert parsed["application_context"] == "1.0.9506.2.3"
    external = parsed["user_information"][0]
    assert external["direct_reference"] == "1.0.9506.2.1"
    assert external["indirect_reference"] == 3
    assert external["encoding"] == "single_asn1_type"
    assert external["mms"]["service"]["name"] == "read"


@pytest.mark.parametrize("result,diagnostic", [(0, 0), (1, 2)])
def test_acse_aare_result_and_user_diagnostic(result, diagnostic):
    parsed = mms.parse_acse(association_response(result, diagnostic))
    assert parsed["pdu"] == "aare"
    assert parsed["application_context"] == "1.0.9506.2.3"
    assert parsed["result"] == result
    assert parsed["diagnostic"] == {"source": "acse_service_user", "value": diagnostic}


def test_acse_authentication_and_application_titles():
    wire = tlv(0x60, context(1, APP_CONTEXT) + context(2, MMS_SYNTAX)
               + context(3, integer(12)) + tlv(0x8A, b"\x07\x80")
               + context(12, tlv(0x80, b"offline-password")))
    parsed = mms.parse_acse(wire)
    assert parsed["called_ap_title"] == "1.0.9506.2.1"
    assert parsed["called_ae_qualifier"] == 12
    assert parsed["acse_requirements"] == {"hex": "80", "unused_bits": 7, "bit_length": 1}
    assert parsed["authentication"] == {"kind": "charstring", "value": "offline-password"}


@pytest.mark.parametrize("tag,pdu", [(0x62, "rlrq"), (0x63, "rlre")])
def test_acse_release(tag, pdu):
    result = mms.parse_acse(tlv(tag, integer(0, 0x80)))
    assert result["pdu"] == pdu
    assert result["reason"] == 0


def test_acse_abort():
    result = mms.parse_acse(tlv(0x64, integer(1, 0x80) + integer(2, 0x81)))
    assert result["pdu"] == "abrt"
    assert result["abort_source"] == 1
    assert result["diagnostic"] == 2


def test_presentation_cp_contexts_and_nested_association():
    parsed = mms.parse_presentation(presentation_connect(association_request(read_request())))
    assert parsed["protocol"] == "presentation"
    assert parsed["pdu"] == "cp"
    assert parsed["contexts"] == [
        {"id": 1, "abstract_syntax": "2.2.1.0.1", "transfer_syntaxes": ["2.1.1"]},
        {"id": 3, "abstract_syntax": "1.0.9506.2.1", "transfer_syntaxes": ["2.1.1"]},
    ]
    pdv = parsed["pdvs"][0]
    assert pdv["context_id"] == 1
    assert pdv["encoding"] == "single_asn1_type"
    assert pdv["acse"]["pdu"] == "aarq"
    assert pdv["acse"]["user_information"][0]["mms"]["invoke_id"] == 7


def test_presentation_data_context_routes_mms():
    parsed = mms.parse_presentation(presentation_data(read_request()), contexts={3: "1.0.9506.2.1"})
    assert parsed["pdu"] == "data"
    assert parsed["pdvs"][0]["context_id"] == 3
    assert parsed["pdvs"][0]["mms"]["service"]["name"] == "read"


def test_presentation_cpa_results_and_aare():
    accepted = tlv(0x30, integer(0, 0x80) + tlv(0x81, bytes.fromhex("5101")))
    rejected = tlv(0x30, integer(2, 0x80) + integer(1, 0x82))
    wire = tlv(0x31, context(0, integer(1, 0x80)) + context(
        2, context(5, accepted + rejected) + presentation_data(association_response(), 1)))
    result = mms.parse_presentation(wire, contexts={1: "2.2.1.0.1"})
    assert result["pdu"] == "cpa"
    assert result["context_results"] == [
        {"result": 0, "transfer_syntax": "2.1.1"}, {"result": 2, "provider_reason": 1},
    ]
    assert result["pdvs"][0]["acse"]["result"] == 0


@pytest.mark.parametrize("layer,wire,protocol", [
    ("mms", read_request(), "mms"),
    ("acse", association_request(), "acse"),
    ("presentation", presentation_connect(association_request()), "presentation"),
    ("auto", read_request(), "mms"),
    ("auto", association_request(), "acse"),
    ("auto", presentation_connect(association_request()), "presentation"),
])
def test_analyze_layer_dispatch(layer, wire, protocol):
    assert mms.analyze(wire, layer=layer)["protocol"] == protocol


@pytest.mark.parametrize("parse", [mms.parse_mms, mms.parse_acse, mms.parse_presentation, mms.analyze])
@pytest.mark.parametrize("value", [None, {}, [], 123, "", "雪\ud800", b"", b"\xff", b"\x30\x80\x00\x00"])
def test_fail_closed_wrong_types_and_malformed_ber(parse, value):
    try:
        parse(value)
    except mms.MMSParseError:
        pass


@pytest.mark.parametrize("parse", [mms.parse_mms, mms.parse_acse, mms.parse_presentation, mms.analyze])
def test_deterministic_random_and_long_input_never_leaks(parse):
    rng = random.Random(9506227)
    corpus = [bytes(rng.randrange(256) for _ in range(size)) for size in (1, 2, 3, 7, 31, 127, 512, 4096)]
    corpus += [b"A" * 65536, b"\xa0\x84\xff\xff\xff\xff", b"\xbf\x80\x80\x80\x80\x80\x01\x00"]
    for wire in corpus:
        try:
            parse(wire)
        except mms.MMSParseError:
            pass


@pytest.mark.parametrize("wire", [
    request(4, variable_list(domain_name())),  # omitted explicit [1]
    request(4, context(1, context(0, context(0, domain_name())))),  # omitted SEQUENCE item
    request(4, context(1, variable_list(domain_name()))) + b"\x00",  # trailing byte
    request(4, context(1, variable_list(domain_name())))[:-1],  # truncated payload
    response(4, context(1, tlv(0x85, b""))),  # empty INTEGER
    response(4, context(1, tlv(0x8F, b"\x88"))),  # unterminated OID subidentifier
    response(4, context(1, tlv(0x83, b"\x00\x01"))),  # invalid BOOLEAN width
])
def test_schema_invalid_mms_rejected(wire):
    with pytest.raises(mms.MMSParseError):
        mms.parse_mms(wire)


def test_nested_data_depth_limit():
    data = integer(1, 0x85)
    for _ in range(64):
        data = context(2, data)
    with pytest.raises(mms.MMSParseError):
        mms.parse_mms(response(4, context(1, data)))


def test_ber_node_budget_rejects_excessive_access_results():
    # Shared network_ics_depth.MAX_BER is 100000; fewer than 301KB on the wire.
    wire = response(4, context(1, b"\x83\x01\x00" * 100001))
    with pytest.raises(mms.MMSParseError):
        mms.parse_mms(wire)


def test_input_size_budget():
    with pytest.raises(mms.MMSParseError):
        mms.parse_mms(b"A" * (mms.MAX_INPUT + 1))


@pytest.mark.parametrize("contexts", [[], {"3": "1.0.9506.2.1"}, {3: None}, {3: []}])
def test_invalid_context_mapping_is_fail_closed(contexts):
    with pytest.raises(mms.MMSParseError):
        mms.parse_presentation(presentation_data(read_request()), contexts=contexts)


def test_cli_parse_failures_are_guarded(capsys):
    assert mms.main(["--definitely-invalid-option"]) == 2
    assert mms.main(["--help"]) == 0
    capsys.readouterr()


@pytest.mark.parametrize("argv", [[None], [1], [b"--help"], 123])
def test_cli_non_string_arguments_are_guarded(argv, capsys):
    assert mms.main(argv) == 2
    capsys.readouterr()


def test_rename_class_name_and_new_identifier():
    wire = request(3, context(0, integer(9, 0x80)) + context(1, domain_name("LD0", "old"))
                   + tlv(0x82, b"new"))
    details = mms.parse_mms(wire)["details"]
    assert details == {
        "object_class": 9,
        "current_name": {"scope": "domain", "domain_id": "LD0", "item_id": "old"},
        "new_identifier": "new",
    }


def test_operator_input_output_and_defaults():
    query = request(17, tlv(0x80, b"operator1") + context(2, visible("Enter command"))
                    + integer(5000, 0x83))
    details = mms.parse_mms(query)["details"]
    assert details["operator_station_name"] == "operator1"
    assert details["echo"] is True
    assert details["list_of_prompt_data"] == ["Enter command"]
    assert details["input_time_out"] == 5000
    assert mms.parse_mms(response(17, b"ACK", constructed=False))["details"] == {"input": "ACK"}
    out = request(18, tlv(0x80, b"operator1") + context(1, visible("alarm") + visible("acknowledged")))
    assert mms.parse_mms(out)["details"] == {
        "operator_station_name": "operator1", "list_of_output_data": ["alarm", "acknowledged"],
    }


def test_domain_initiate_download_and_upload():
    wire = request(26, tlv(0x80, b"LD0") + context(1, visible("MMS") + visible("IEC61850"))
                   + tlv(0x82, b"\xff"))
    assert mms.parse_mms(wire)["details"] == {
        "domain_name": "LD0", "list_of_capabilities": ["MMS", "IEC61850"], "sharable": True,
    }
    upload = response(29, integer(321, 0x80) + context(1, visible("MMS")))
    assert mms.parse_mms(upload)["details"] == {"ulsm_id": 321, "list_of_capabilities": ["MMS"]}


@pytest.mark.parametrize("number", [27, 29, 36, 37])
def test_primitive_domain_name_requests(number):
    assert mms.parse_mms(request(number, b"LD0", constructed=False))["details"] == {"domain_name": "LD0"}


@pytest.mark.parametrize("number", [30, 31])
def test_primitive_upload_state_requests(number):
    assert mms.parse_mms(request(number, b"\x01\x41", constructed=False))["details"] == {"ulsm_id": 321}


@pytest.mark.parametrize("number", [27, 30])
def test_domain_segment_binary_load_data_and_default(number):
    data = b"\x00\xffsegment\x00"
    details = mms.parse_mms(response(number, tlv(0x80, data)))["details"]
    assert details == {"load_data": {"kind": "non_coded", "data": data}, "more_follows": True}


def test_domain_terminate_download_error_detail():
    # ServiceError.errorClass resource(3), code memory-unavailable(1).
    discard = context(0, integer(1, 0x83))
    wire = request(28, tlv(0x80, b"LD0") + context(1, discard))
    assert mms.parse_mms(wire)["details"] == {
        "domain_name": "LD0", "discard": {"error_class": 3, "code": 1},
    }


@pytest.mark.parametrize("number", [32, 34])
def test_domain_download_and_load_file(number):
    wire = request(number, tlv(0x80, b"LD0") + context(1, visible("cap"))
                   + tlv(0x82, b"\x00") + context(4, filename("config", "domain.bin")))
    details = mms.parse_mms(wire)["details"]
    assert details == {
        "domain_name": "LD0", "list_of_capabilities": ["cap"], "sharable": False,
        "file_name": ["config", "domain.bin"],
    }


@pytest.mark.parametrize("number", [33, 35])
def test_domain_upload_and_store_file(number):
    wire = request(number, tlv(0x80, b"LD0") + context(1, filename("domain.bin")))
    details = mms.parse_mms(wire)["details"]
    assert details == {"domain_name": "LD0", "file_name": ["domain.bin"]}


def test_domain_attributes():
    wire = response(37, context(0, visible("cap")) + integer(2, 0x81) + tlv(0x82, b"\xff")
                    + tlv(0x83, b"\x00") + context(4, visible("program")) + integer(1, 0x85))
    assert mms.parse_mms(wire)["details"] == {
        "list_of_capabilities": ["cap"], "state": 2, "mms_deletable": True,
        "sharable": False, "list_of_program_invocations": ["program"], "upload_in_progress": 1,
    }


def test_create_program_invocation_defaults():
    wire = request(38, tlv(0x80, b"program") + context(1, visible("LD0") + visible("LD1")))
    assert mms.parse_mms(wire)["details"] == {
        "program_invocation_name": "program", "list_of_domain_name": ["LD0", "LD1"], "reusable": True,
    }


@pytest.mark.parametrize("number", [39, 45])
def test_primitive_program_name_request(number):
    assert mms.parse_mms(request(number, b"program", constructed=False))["details"] == {
        "program_invocation_name": "program",
    }


@pytest.mark.parametrize("number", [40, 42])
def test_start_resume_program_argument(number):
    wire = request(number, tlv(0x80, b"program") + tlv(0x81, b"--offline"))
    assert mms.parse_mms(wire)["details"] == {
        "program_invocation_name": "program", "execution_argument": {"kind": "simple_string", "value": "--offline"},
    }


@pytest.mark.parametrize("number", [41, 43, 44])
def test_stop_reset_kill_program_name(number):
    assert mms.parse_mms(request(number, tlv(0x80, b"program")))["details"] == {
        "program_invocation_name": "program",
    }


def test_program_attributes():
    wire = response(45, integer(3, 0x80) + context(1, visible("LD0")) + tlv(0x82, b"\x00")
                    + tlv(0x83, b"\xff") + tlv(0x84, b"\xff") + tlv(0x85, b"start"))
    assert mms.parse_mms(wire)["details"] == {
        "state": 3, "list_of_domain_names": ["LD0"], "mms_deletable": False,
        "reusable": True, "monitor": True, "start_argument": "start",
    }


@pytest.mark.parametrize("number", [3, 8, 18, 20, 21, 22, 26, 28, 31, 32, 33, 34, 35, 36,
                                    38, 39, 40, 41, 42, 43, 44, 47, 51, 52, 53, 57, 62])
def test_additional_null_service_responses(number):
    result = mms.parse_mms(response(number, b"", constructed=False))
    assert result["details"] == {}


def test_capability_list_universal_visible_continuation():
    assert mms.parse_mms(request(71, visible("previous")))["details"] == {"continue_after": "previous"}


def test_negative_bcd_rejected():
    # OpenIEC61850 MMS2003 Data.bcd: INTEGER -- shall not be negative.
    with pytest.raises(mms.MMSParseError):
        mms.parse_mms(response(4, context(1, integer(-1, 0x8D))))


def test_acse_implementation_information():
    # X.227 implementation-information [29] IMPLICIT GraphicString.
    wire = tlv(0x60, context(1, APP_CONTEXT) + tlv(0x9D, b"RTU release 17"))
    assert mms.parse_acse(wire)["implementation_information"] == "RTU release 17"


def test_scattered_access_definition_and_attributes():
    # ScatteredAccessDescription row: optional componentName[0], explicit
    # VariableSpecification[1] containing explicit name[0] ObjectName.
    row = tlv(0x30, tlv(0x80, b"position") + context(1, context(0, domain_name())))
    wire = request(8, context(0, domain_name("LD0", "view")) + context(1, row))
    details = mms.parse_mms(wire)["details"]
    expected = [{"component_name": "position", "variable_specification": {"name": {
        "scope": "domain", "domain_id": "LD0", "item_id": "LLN0$ST$Mod$stVal",
    }}}]
    assert details["scattered_access_name"]["item_id"] == "view"
    assert details["scattered_access_description"] == expected
    assert mms.parse_mms(request(9, domain_name("LD0", "view")))["details"]["scattered_access_name"]["item_id"] == "view"
    attrs = mms.parse_mms(response(9, tlv(0x80, b"\xff") + context(1, row)))["details"]
    assert attrs == {"mms_deletable": True, "scattered_access_description": expected}


def test_take_control_defaults_and_token_response():
    wire = request(19, context(0, context(0, b"gate", False)))
    assert mms.parse_mms(wire)["details"] == {
        "semaphore_name": {"scope": "vmd", "identifier": "gate"},
        "priority": 64, "relinquish_if_connection_lost": True,
    }
    assert mms.parse_mms(response(19, tlv(0x80, b"")))["details"] == {"no_result": True}
    assert mms.parse_mms(response(19, tlv(0x81, b"owner")))["details"] == {"named_token": "owner"}


def test_relinquish_and_define_semaphore():
    name = context(0, context(0, b"gate", False))
    assert mms.parse_mms(request(20, name + tlv(0x81, b"owner")))["details"] == {
        "semaphore_name": {"scope": "vmd", "identifier": "gate"}, "named_token": "owner",
    }
    assert mms.parse_mms(request(21, name + integer(256, 0x81)))["details"]["number_of_tokens"] == 256


@pytest.mark.parametrize("number", [22, 23])
def test_unary_semaphore_name(number):
    assert mms.parse_mms(request(number, context(0, b"gate", False)))["details"] == {
        "semaphore_name": {"scope": "vmd", "identifier": "gate"},
    }


def test_semaphore_status_counts():
    wire = response(23, tlv(0x80, b"\xff") + integer(1, 0x81) + integer(10, 0x82)
                    + integer(3, 0x83) + integer(2, 0x84))
    assert mms.parse_mms(wire)["details"] == {
        "mms_deletable": True, "class": 1, "number_of_tokens": 10,
        "number_of_owned_tokens": 3, "number_of_hung_tokens": 2,
    }


def test_pool_semaphore_token_states():
    query = request(24, context(0, context(0, b"gate", False)) + tlv(0x81, b"previous"))
    assert mms.parse_mms(query)["details"]["name_to_start_after"] == "previous"
    tokens = tlv(0x80, b"a") + tlv(0x81, b"b") + tlv(0x82, b"c")
    assert mms.parse_mms(response(24, context(0, tokens)))["details"] == {
        "list_of_named_tokens": [{"state": "free", "name": "a"}, {"state": "owned", "name": "b"},
                                 {"state": "hung", "name": "c"}],
        "more_follows": True,
    }


def test_semaphore_entry_status_application_reference_and_defaults():
    query = request(25, context(0, context(0, b"gate", False)) + integer(1, 0x81) + tlv(0x82, b"id1"))
    assert mms.parse_mms(query)["details"]["entry_id_to_start_after"] == b"id1"
    entry = tlv(0x30, tlv(0x80, b"id2") + integer(0, 0x81) + context(2, tlv(0x30, b"")))
    assert mms.parse_mms(response(25, context(0, entry)))["details"] == {
        "list_of_semaphore_entry": [{"entry_id": b"id2", "entry_class": 0,
            "application_reference": {}, "priority": 64, "relinquish_if_connection_lost": True}],
        "more_follows": True,
    }


def test_define_and_get_event_condition_defaults():
    wire = request(47, context(0, domain_name("LD0", "trip")) + integer(1, 0x81))
    details = mms.parse_mms(wire)["details"]
    assert details["event_condition_name"]["item_id"] == "trip"
    assert details["class"] == 1
    assert details["priority"] == details["severity"] == 64
    attrs = mms.parse_mms(response(49, integer(1, 0x81) + context(6, tlv(0x81, b""))))["details"]
    assert attrs == {"mms_deletable": False, "class": 1, "priority": 64, "severity": 64,
                     "alarm_summary_reports": False, "monitored_variable": {"undefined": True}}


@pytest.mark.parametrize("number,key", [(49, "event_condition_name"), (50, "event_condition_name"),
                                       (55, "event_action_name"), (56, "event_action_name"),
                                       (60, "event_enrollment_name")])
def test_unary_event_names(number, key):
    assert mms.parse_mms(request(number, domain_name("LD0", "trip")))["details"] == {
        key: {"scope": "domain", "domain_id": "LD0", "item_id": "trip"},
    }


@pytest.mark.parametrize("number", [48, 54, 58])
def test_delete_event_specific_objects_and_count(number):
    details = mms.parse_mms(request(number, context(0, domain_name("LD0", "trip"))))["details"]
    assert details == {"scope": "specific", "names": [{"scope": "domain", "domain_id": "LD0", "item_id": "trip"}]}
    assert mms.parse_mms(response(number, b"\x02", constructed=False))["details"] == {"candidates_not_deleted": 2}


def test_report_event_condition_state_transition():
    wire = response(50, integer(2, 0x80) + integer(3, 0x81) + tlv(0x82, b"\xff")
                    + context(3, integer(1234, 0x81)))
    assert mms.parse_mms(wire)["details"] == {
        "current_state": 2, "number_of_event_enrollments": 3, "enabled": True,
        "time_of_last_transition_to_active": {"sequence_identifier": 1234},
    }


def test_alter_event_condition_and_trigger_priority():
    wire = request(51, context(0, domain_name("LD0", "trip")) + tlv(0x81, b"\xff")
                   + integer(5, 0x82) + tlv(0x83, b"\x00") + integer(100, 0x84))
    details = mms.parse_mms(wire)["details"]
    assert details["enabled"] is True
    assert details["priority"] == 5
    assert details["alarm_summary_reports"] is False
    assert details["evaluation_interval"] == 100
    triggered = request(52, context(0, domain_name("LD0", "trip")) + integer(9, 0x81))
    assert mms.parse_mms(triggered)["details"]["priority"] == 9


def test_event_action_nested_service_and_modifiers():
    # Complete ISO9506 schema from OpenIEC61850 has mandatory service[2],
    # omitted in the older Wireshark ASN.1. Here it requests Identify (NULL).
    modifier = context(1, context(0, context(0, b"gate", False)))
    wire = request(53, context(0, domain_name("LD0", "onTrip")) + context(1, modifier)
                   + context(2, tlv(0x82, b"")))
    details = mms.parse_mms(wire)["details"]
    assert details["confirmed_service_request"] == {"service": {"number": 2, "name": "identify"}, "details": {}}
    assert details["list_of_modifier"] == [{"kind": "attach_to_semaphore",
        "semaphore_name": {"scope": "vmd", "identifier": "gate"},
        "priority": 64, "relinquish_if_connection_lost": True}]
    reply = response(55, context(1, modifier) + context(2, tlv(0x82, b"")))
    assert mms.parse_mms(reply)["details"]["mms_deletable"] is False
    assert mms.parse_mms(response(56, b"\x03", constructed=False))["details"] == {"number_of_event_enrollments": 3}


def test_define_event_enrollment_transitions_and_acknowledgment():
    wire = request(57, context(0, domain_name("LD0", "subscription"))
                   + context(1, domain_name("LD0", "trip")) + tlv(0x82, b"\x01\x04") + integer(3, 0x83))
    details = mms.parse_mms(wire)["details"]
    assert details["event_enrollment_name"]["item_id"] == "subscription"
    assert details["event_condition_transition"] == {"hex": "04", "unused_bits": 1, "bit_length": 7}
    assert details["alarm_acknowledgment_rule"] == 3


def test_alter_and_report_event_enrollment():
    wire = request(59, context(0, domain_name("LD0", "subscription")) + integer(2, 0x82))
    assert mms.parse_mms(wire)["details"]["alarm_acknowledgment_rule"] == 2
    reply = response(59, context(0, integer(2, 0x80)) + context(1, tlv(0x80, b"\x00\x00\x03\xe8")))
    assert mms.parse_mms(reply)["details"] == {
        "current_state": {"state": 2}, "transition_time": {"time_of_day": {"milliseconds": 1000}},
    }
    status = response(60, tlv(0x80, b"\x01\x04") + integer(1, 0x82) + integer(7, 0x84))
    assert mms.parse_mms(status)["details"] == {
        "event_condition_transitions": {"hex": "04", "unused_bits": 1, "bit_length": 7},
        "notification_lost": False, "duration": 1, "current_state": 7,
    }


def test_event_enrollment_attributes_entries():
    assert mms.parse_mms(request(61, b""))["details"] == {"scope_of_request": 1}
    entry = tlv(0x30, context(0, domain_name("LD0", "subscription"))
                + context(1, context(0, domain_name("LD0", "trip"))) + integer(1, 0x85) + integer(7, 0x87))
    details = mms.parse_mms(response(61, context(0, entry)))["details"]
    assert details["more_follows"] is False
    assert details["list_of_event_enrollment"] == [{
        "event_enrollment_name": {"scope": "domain", "domain_id": "LD0", "item_id": "subscription"},
        "event_condition_name": {"name": {"scope": "domain", "domain_id": "LD0", "item_id": "trip"}},
        "mms_deletable": False, "enrollment_class": 1, "duration": 0, "invoke_id": 7,
    }]


def test_acknowledge_event_notification_sequence_time():
    wire = request(62, context(0, domain_name("LD0", "subscription")) + integer(2, 0x82)
                   + context(3, integer(123, 0x81)))
    details = mms.parse_mms(wire)["details"]
    assert details["acknowledged_state"] == 2
    assert details["time_of_acknowledged_transition"] == {"sequence_identifier": 123}


@pytest.mark.parametrize("number", [63, 64])
def test_alarm_summary_filter_defaults(number):
    wire = request(number, context(3, integer(1, 0x80) + integer(250, 0x81)))
    assert mms.parse_mms(wire)["details"] == {
        "enrollments_only": True, "active_alarms_only": True, "acknowledgment_filter": 0,
        "severity_filter": {"most_severe": 1, "least_severe": 250},
    }


def test_alarm_and_alarm_enrollment_summary_entries():
    row = tlv(0x30, context(0, domain_name("LD0", "trip")) + integer(5, 0x81)
              + integer(2, 0x82) + integer(1, 0x83))
    details = mms.parse_mms(response(63, context(0, row)))["details"]
    assert details == {"list_of_alarm_summary": [{
        "event_condition_name": {"scope": "domain", "domain_id": "LD0", "item_id": "trip"},
        "severity": 5, "current_state": 2, "unacknowledged_state": 1}], "more_follows": False}
    row = tlv(0x30, context(0, domain_name("LD0", "subscription")) + integer(5, 0x83) + integer(2, 0x84))
    details = mms.parse_mms(response(64, context(0, row)))["details"]
    assert details["list_of_alarm_enrollment_summary"][0]["notification_lost"] is False
    assert details["list_of_alarm_enrollment_summary"][0]["severity"] == 5
    assert details["more_follows"] is False


def test_unconfirmed_event_notification_nested_result():
    # Wireshark ISO9506 EventNotification uses a name-or-undefined choice at [1].
    action = domain_name("LD0", "onTrip") + context(0, tlv(0x94, b""))  # relinquishControl response NULL
    body = context(0, domain_name("LD0", "subscription")) + context(1, context(0, domain_name("LD0", "trip")))
    body += integer(5, 0x82) + integer(2, 0x83) + context(4, integer(123, 0x81)) + context(8, action)
    parsed = mms.parse_mms(context(3, context(2, body)))
    assert parsed["service"] == {"number": 2, "name": "event_notification"}
    details = parsed["details"]
    assert details["severity"] == 5
    assert details["transition_time"] == {"sequence_identifier": 123}
    assert details["notification_lost"] is False
    assert details["action_result"]["success"] == {
        "service": {"number": 20, "name": "relinquish_control"}, "details": {},
    }


@pytest.mark.parametrize("wire_hex", [
    # X.226 section 6.2.2.7: initial CP context identifiers must be odd.
    "312ba003800101a224a4123010020102060528ca220201300406025101610e300c020102a007a0050201078200",
    # X.226 section 6.2.3.6: acceptance requires a selected transfer syntax.
    "310ea003800101a207a5053003800100",
    # X.226 section 8.4.2.6: CP data must name one of the proposed contexts.
    "312ba003800101a224a4123010020103060528ca220201300406025101610e300c020105a007a0050201078200",
])
def test_presentation_negotiation_constraints(wire_hex):
    with pytest.raises(mms.MMSParseError):
        mms.parse_presentation(bytes.fromhex(wire_hex))


@pytest.mark.parametrize("value", [0.0, 1.0, 1.5, -2.25, 123.0, 1e-8,
                                   (3, 2, -1), (-9, 2, -2), (1, 2, 100), (1, 2, -100)])
def test_mms_real_against_independent_pyasn1_encoder(value):
    from pyasn1.codec.ber.decoder import decode
    from pyasn1.codec.ber.encoder import encode
    from pyasn1.type.univ import Real

    encoded = encode(Real(value))
    assert encoded[0] == 9 and encoded[1] < 128
    expected = float(decode(encoded, asn1Spec=Real())[0])
    # IMPLICIT tagging changes only the universal REAL tag to MMS Data.real[8].
    wire = response(4, context(1, bytes([0x88]) + encoded[1:]))
    assert mms.parse_mms(wire)["details"]["access_results"][0]["data"] == {
        "type": "real", "value": expected,
    }


@pytest.mark.parametrize("payload,expected", [
    (bytes.fromhex("90ff0c"), 1.5),  # base8 exponent-1 mantissa12
    (bytes.fromhex("a0ff18"), 1.5),  # base16 exponent-1 mantissa24
    (bytes.fromhex("88ff03"), 6.0),  # scale2, base2 exponent-1 mantissa3
    (b"\x01123", 123.0), (b"\x02-2.25", -2.25), (b"\x0312.5E2", 1250.0),
])
def test_real_binary_bases_scaling_and_decimal_forms(payload, expected):
    from pyasn1.codec.ber.decoder import decode
    from pyasn1.type.univ import Real

    oracle, rest = decode(tlv(9, payload), asn1Spec=Real())
    assert not rest and float(oracle) == expected
    parsed = mms.parse_mms(response(4, context(1, tlv(0x88, payload))))
    assert parsed["details"]["access_results"][0]["data"] == {"type": "real", "value": expected}


def test_confirmed_request_top_level_semaphore_modifier():
    # Confirmed-RequestPDU.listOfModifier is an optional universal SEQUENCE OF.
    modifier = context(1, context(0, context(0, b"gate", False)) + integer(7, 0x82))
    wire = context(0, integer(7) + tlv(0x30, modifier) + tlv(0x82, b""))
    parsed = mms.parse_mms(wire)
    assert parsed["service"] == {"number": 2, "name": "identify"}
    assert parsed["modifiers"] == [{
        "kind": "attach_to_semaphore", "semaphore_name": {"scope": "vmd", "identifier": "gate"},
        "priority": 7, "relinquish_if_connection_lost": True,
    }]
    assert parsed["modifiers_hex"] == modifier.hex()


def test_real_nan_special_from_x690():
    # ITU-T X.690 (02/2021) 8.5.9: 01000010 means NOT-A-NUMBER.
    # https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I!!PDF-E&lang=e&type=items
    parsed = mms.parse_mms(response(4, context(1, tlv(0x88, b"\x42"))))
    assert parsed["details"]["access_results"][0]["data"] == {"type": "real", "value": "nan"}


def test_real_minus_zero_special_from_x690():
    # Same primary standard 8.5.9: 01000011 means minus zero. The sign matters.
    parsed = mms.parse_mms(response(4, context(1, tlv(0x88, b"\x43"))))
    value = parsed["details"]["access_results"][0]["data"]["value"]
    assert value == 0.0
    assert math.copysign(1.0, value) == -1.0
