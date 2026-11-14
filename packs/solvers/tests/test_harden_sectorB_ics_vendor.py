"""Independent vector locks and fail-closed fuzz for ICS vendor exports.

The fixtures are handwritten from Rockwell 1756-RM014, PLCopen TC6 XML 2.01,
and CiA 306 EDS semantics.  No production-engine serializer is used.
"""
from __future__ import annotations

import io
import random
from pathlib import Path
from typing import Callable

import pytest

import ics_vendor_devices as devices
import ics_vendor_exports as exports
import ics_vendor_l5x as l5x


L5X_VECTOR = b'''<?xml version="1.0" encoding="UTF-8"?>
<RSLogix5000Content SchemaRevision="1.0" SoftwareRevision="37.00">
 <Controller Name="SectorB"><Tags>
  <Tag Name="OperatorMessage" DataType="STRING">
   <Data Format="String" Length="13"><![CDATA['ALARM$3A PUMP 7']]></Data>
  </Tag>
 </Tags><Programs><Program Name="Main"><Routines><Routine Name="Run" Type="RLL">
  <RLLContent><Rung Number="0"><Text><![CDATA[XIC(Start)OTE(Pump);]]></Text></Rung></RLLContent>
 </Routine></Routines></Program></Programs></Controller>
</RSLogix5000Content>'''


PLCOPEN_VECTOR = b'''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://www.plcopen.org/xml/tc6_0201"
 xmlns:xhtml="http://www.w3.org/1999/xhtml">
 <fileHeader companyName="CSCTF Test" productName="Independent TC6 fixture"/>
 <contentHeader name="SectorB"/>
 <types><dataTypes/><pous><pou name="Pump" pouType="program">
  <interface><localVars><variable name="Pressure" address="%MW10">
   <type><INT/></type><initialValue><simpleValue value="42"/></initialValue>
  </variable></localVars></interface>
  <body><ST><xhtml:p>Motor := Pressure &gt; 40;</xhtml:p></ST></body>
 </pou></pous></types>
</project>'''


EDS_VECTOR = '''[FileInfo]
FileName=sector-b.eds
FileVersion=1
[DeviceInfo]
VendorName=Independent Vendor
VendorNumber=0x0000002A
[1000]
ParameterName=Device Type
ObjectType=7
DataType=7
AccessType=ro
DefaultValue=0x00000191
[1200]
ParameterName=Server SDO
ObjectType=9
SubNumber=1
[1200sub1]
ParameterName=COB-ID Client to Server
ObjectType=7
DataType=7
AccessType=ro
DefaultValue=$NODEID+1536
'''


def _finding(report: dict, name: str) -> dict:
    return next(item for item in report["tags"] if item["name"] == name)


def test_l5x_vector_lock_matches_rockwell_documented_xml_and_dollar_hex_semantics():
    # 1756-RM014: the root is RSLogix5000Content; controller Tags contain
    # Data Format="String", and $xx encodes one byte in a Logix string.
    assert l5x.decode_logix_string("'A$3AB$N'") == "A:B\r\n"
    report = l5x.parse_l5x(L5X_VECTOR)
    assert report["format"] == "rockwell-l5x"
    assert report["metadata"]["SchemaRevision"] == "1.0"
    tag = _finding(report, "OperatorMessage")
    assert tag["scope"] == "Controller:SectorB"
    assert tag["decoded_strings"] == [{
        "path": "/RSLogix5000Content/Controller[1]/Tags[1]/Tag[1]/Data[1]/String",
        "value": "ALARM: PUMP 7",
    }]
    assert report["logic"][0]["scope"] == "Controller:SectorB/Program:Main"
    assert report["logic"][0]["text"] == "XIC(Start)OTE(Pump);"


def test_vendor_export_vector_lock_matches_plcopen_tc6_201_hierarchy():
    report = exports.parse_export(PLCOPEN_VECTOR, name="sector-b.xml")
    assert report["format"] == "plcopen-xml"
    assert report["metadata"]["fileHeader"] == {
        "companyName": "CSCTF Test",
        "productName": "Independent TC6 fixture",
    }
    assert report["metadata"]["contentHeader"] == {"name": "SectorB"}
    assert [(item["name"], item["scope"], item["section"]) for item in report["variables"]] == [
        ("Pressure", "pou:Pump", "localVars")
    ]
    variable = report["variables"][0]
    assert variable["address"] == "%MW10"
    assert variable["type"] == "INT"
    assert variable["initial_value"]["children"][0]["attributes"] == {"value": "42"}
    assert report["logic"][0]["language"] == "ST"
    assert report["logic"][0]["text"] == "Motor := Pressure > 40;"


def test_device_description_vector_lock_matches_independent_canopen_library():
    canopen_eds = pytest.importorskip("canopen.objectdictionary.eds")
    reference = canopen_eds.import_eds(io.StringIO(EDS_VECTOR), node_id=7)
    report = devices.parse(EDS_VECTOR, kind="canopen")
    parsed = {(item["index"], item["subindex"]): item["fields"] for item in report["objects"]}

    assert report["format"] == "canopen-eds"
    assert int(parsed[(0x1000, None)]["DefaultValue"], 0) == reference[0x1000].default
    assert parsed[(0x1000, None)]["ParameterName"] == reference[0x1000].name
    assert parsed[(0x1200, 1)]["ParameterName"] == reference[0x1200][1].name
    assert int(parsed[(0x1200, 1)]["DataType"], 0) == reference[0x1200][1].data_type
    assert parsed[(0x1200, 1)]["DefaultValue"] == "$NODEID+1536"
    assert reference[0x1200][1].default == 1543


def _malformed_corpus(valid: bytes, *, oversize: int) -> list[tuple[str, bytes]]:
    rng = random.Random(0x5EC70B)
    cases: list[tuple[str, bytes]] = [("empty", b"")]
    cases.extend((f"random-{index}", rng.randbytes(size)) for index, size in enumerate((1, 7, 31, 127)))
    for index, cut in enumerate((1, len(valid) // 4, len(valid) // 2, len(valid) - 1)):
        cases.append((f"truncated-{index}", valid[:cut]))
    for index, position in enumerate((0, len(valid) // 5, len(valid) // 2, len(valid) - 2)):
        changed = bytearray(valid)
        changed[position] ^= 0xFF
        cases.append((f"bit-flipped-{index}", bytes(changed)))
    cases.append(("oversized", b"X" * (oversize + 1)))
    return cases


def _assert_clean_or_declared(
    function: Callable[[bytes], object],
    error: type[Exception],
    payload: bytes,
) -> None:
    try:
        result = function(payload)
    except Exception as exc:  # the assertion deliberately inspects the exact leaked type
        assert type(exc) is error, f"leaked {type(exc).__name__}: {exc}"
    else:
        assert isinstance(result, dict)


@pytest.mark.parametrize(
    ("module", "entrypoint", "valid", "error"),
    [
        (l5x, l5x.parse_l5x, L5X_VECTOR, l5x.ParseError),
        (exports, exports.parse_export, PLCOPEN_VECTOR, exports.ExportError),
        (devices, devices.parse, EDS_VECTOR.encode("ascii"), devices.ParseError),
    ],
    ids=("l5x-parse", "vendor-export-parse", "device-description-parse"),
)
def test_memory_parse_entrypoints_fail_closed_for_all_mutation_families(
    module, entrypoint, valid, error,
):
    for _label, payload in _malformed_corpus(valid, oversize=module.MAX_INPUT):
        _assert_clean_or_declared(entrypoint, error, payload)


@pytest.mark.parametrize(
    ("module", "file_entrypoint", "valid", "error", "suffix"),
    [
        (l5x, l5x.analyze_file, L5X_VECTOR, l5x.ParseError, ".L5X"),
        (exports, exports.analyze_file, PLCOPEN_VECTOR, exports.ExportError, ".xml"),
        (devices, devices.parse_file, EDS_VECTOR.encode("ascii"), devices.ParseError, ".eds"),
    ],
    ids=("l5x-file", "vendor-export-file", "device-description-file"),
)
def test_file_parse_entrypoints_fail_closed_for_all_mutation_families(
    tmp_path: Path, module, file_entrypoint, valid, error, suffix,
):
    artifact = tmp_path / ("mutated" + suffix)
    for _label, payload in _malformed_corpus(valid, oversize=module.MAX_INPUT):
        artifact.write_bytes(payload)
        try:
            result = file_entrypoint(artifact)
        except Exception as exc:  # inspect exact exception, not a broad pytest match
            assert type(exc) is error, f"leaked {type(exc).__name__}: {exc}"
        else:
            assert isinstance(result, dict)


def test_logix_literal_decoder_fail_closed_for_all_mutation_families():
    valid = "'CSCTF$7BsectorB$7D'"
    rng = random.Random(1553)
    corpus: list[object] = [
        "",
        None,
        b"'bytes'",
        rng.randbytes(32).decode("latin-1"),
        valid[:1],
        valid[:-1],
        valid[:8],
        valid.replace("$7B", "$ZB"),
        "'" + ("A" * (l5x.MAX_INPUT + 1)) + "'",
    ]
    for value in corpus:
        try:
            result = l5x.decode_logix_string(value)
        except Exception as exc:
            assert type(exc) is l5x.ParseError, f"leaked {type(exc).__name__}: {exc}"
        else:
            assert isinstance(result, str)


@pytest.mark.parametrize(
    ("entrypoint", "error", "bad_path"),
    [
        (l5x.analyze_file, l5x.ParseError, None),
        (exports.analyze_file, exports.ExportError, None),
        (devices.parse_file, devices.ParseError, None),
    ],
)
def test_file_entrypoints_normalize_malformed_path_types(entrypoint, error, bad_path):
    with pytest.raises(error) as captured:
        entrypoint(bad_path)
    assert type(captured.value) is error

