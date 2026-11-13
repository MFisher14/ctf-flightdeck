#!/usr/bin/env python3
"""Pure, offline regressions for WSDL/protobuf/gRPC-web metadata parsing."""

import ast
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))
import service_descriptors as sd  # noqa: E402


FAILS = []


def check(name, condition, detail=""):
    print(("ok   " if condition else "FAIL ") + name
          + ("" if condition else f" [{str(detail)[:1200]}]"))
    if not condition:
        FAILS.append(name)


WSDL11 = b'''<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
 xmlns:tns="urn:cases" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
 xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:cases">
 <import namespace="urn:common" location="/contracts/common.wsdl"/>
 <types><xsd:schema targetNamespace="urn:cases">
  <xsd:import namespace="urn:foreign" schemaLocation="https://evil.invalid/types.xsd"/>
  <xsd:element name="GetCaseRequest" type="xsd:string"/>
  <xsd:complexType name="Case"><xsd:sequence/></xsd:complexType>
  <xsd:simpleType name="State"><xsd:restriction base="xsd:string"/></xsd:simpleType>
  <xsd:attribute name="caseId" type="xsd:string"/>
 </xsd:schema></types>
 <message name="GetCaseInput"><part name="body" element="tns:GetCaseRequest"/></message>
 <message name="GetCaseOutput"><part name="body" type="tns:Case"/></message>
 <portType name="CasePortType"><operation name="GetCase">
  <input message="tns:GetCaseInput"/><output message="tns:GetCaseOutput"/>
 </operation></portType>
 <binding name="CaseSoap" type="tns:CasePortType"><soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
  <operation name="GetCase"><soap:operation soapAction="urn:cases/GetCase"/></operation>
 </binding>
 <service name="Cases">
  <port name="same" binding="tns:CaseSoap"><soap:address location="/soap/cases"/></port>
  <port name="foreign" binding="tns:CaseSoap"><soap12:address location="https://evil.invalid/soap"/></port>
 </service>
</definitions>'''


WSDL20 = b'''<description xmlns="http://www.w3.org/ns/wsdl"
 xmlns:tns="urn:hello" xmlns:wsoap="http://www.w3.org/ns/wsdl/soap"
 xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:hello">
 <types><xs:schema><xs:element name="HelloRequest"/><xs:element name="HelloReply"/></xs:schema></types>
 <interface name="HelloInterface"><operation name="SayHello" pattern="http://www.w3.org/ns/wsdl/in-out">
  <input element="tns:HelloRequest"/><output element="tns:HelloReply"/>
 </operation></interface>
 <binding name="HelloBinding" interface="tns:HelloInterface" type="http://www.w3.org/ns/wsdl/soap">
  <operation ref="tns:SayHello" wsoap:action="urn:hello/SayHello"/>
 </binding>
 <service name="Hello" interface="tns:HelloInterface">
  <endpoint name="hello" binding="tns:HelloBinding" address="soap"/>
 </service>
</description>'''


PROTO = br'''syntax = "proto3";
// package fake; service Fake { rpc Nope (Bad) returns (Worse); }
package acme.greeter.v1;
import "google/protobuf/empty.proto";
/* service AlsoFake { rpc Bad (X) returns (Y); } */
message HelloRequest { string name = 1; }
message HelloReply { string text = 1; }
enum Mood { MOOD_UNSPECIFIED = 0; }
option java_package = "service StringFake { rpc Nope (X) returns (Y); }";
service Greeter {
 rpc SayHello (HelloRequest) returns (HelloReply);
 rpc Chat (stream acme.greeter.v1.HelloRequest)
     returns (stream .acme.greeter.v1.HelloReply) {}
}
'''


GRPC_WEB = br'''
// new grpc.web.MethodDescriptor('/fake.Bad/Nope', grpc.web.MethodType.UNARY, fake.In, fake.Out);
const methodDescriptor_Greeter_SayHello = new grpc.web.MethodDescriptor(
  '/acme.greeter.v1.Greeter/SayHello', grpc.web.MethodType.UNARY,
  proto.acme.greeter.v1.HelloRequest, proto.acme.greeter.v1.HelloReply,
  function(request) { return request.serializeBinary(); });
const methodDescriptor_Greeter_Watch = new grpc.web.MethodDescriptor(
  '/acme.greeter.v1.Greeter/Watch', grpc.web.MethodType.SERVER_STREAMING,
  proto.acme.greeter.v1.HelloRequest, proto.acme.greeter.v1.HelloReply);
'''


def test_wsdl_versions_and_metadata():
    one = sd.parse_wsdl(WSDL11, base_url="https://target.test/app/",
                        source_url="/contracts/cases.wsdl")
    check("WSDL 1.1 root and namespace", one and one["dialect"] == "wsdl-1.1"
          and one["target_namespace"] == "urn:cases", one)
    check("WSDL 1.1 messages and part references", one["messages"] == [
        {"name": "GetCaseInput", "parts": [{"name": "body", "element": "GetCaseRequest"}]},
        {"name": "GetCaseOutput", "parts": [{"name": "body", "type": "Case"}]},
    ], one["messages"])
    operation = one["operations"][0]
    check("WSDL 1.1 operation and SOAPAction", operation["name"] == "GetCase"
          and operation["input"] == "GetCaseInput" and operation["output"] == "GetCaseOutput"
          and operation["soap_action"] == "urn:cases/GetCase"
          and operation["requestable"] is False, operation)
    check("WSDL XSD names retained", one["xsd"] == {
        "elements": ["GetCaseRequest"], "complex_types": ["Case"],
        "simple_types": ["State"], "attributes": ["caseId"],
    }, one["xsd"])
    check("WSDL imports never fetched", len(one["imports"]) == 2
          and all(row["fetched"] is False and row["requestable"] is False for row in one["imports"]),
          one["imports"])
    addresses = {row["port"]: row for row in one["addresses"]}
    check("SOAP same-origin address stays nonrequestable", addresses["same"]["same_origin"] is True
          and addresses["same"]["resolved"] == "https://target.test/soap/cases"
          and addresses["same"]["requestable"] is False, addresses)
    check("SOAP off-origin address explicitly marked", addresses["foreign"]["off_origin"] is True
          and addresses["foreign"]["same_origin"] is False
          and addresses["foreign"]["requestable"] is False, addresses)

    two = sd.parse_wsdl(WSDL20, base_url="https://target.test/base/",
                        source_url="https://target.test/contracts/hello.wsdl")
    check("WSDL 2.0 description accepted", two and two["dialect"] == "wsdl-2.0", two)
    check("WSDL 2.0 operation/action/message elements", two["operations"] == [{
        "name": "SayHello", "interface": "HelloInterface", "requestable": False,
        "input": "HelloRequest", "output": "HelloReply", "binding": "HelloBinding",
        "soap_action": "urn:hello/SayHello",
    }], two["operations"])
    check("WSDL 2.0 endpoint is metadata only", two["addresses"][0]["resolved"]
          == "https://target.test/contracts/soap"
          and two["addresses"][0]["requestable"] is False, two["addresses"])


def test_xml_rejection_and_bounds():
    evil = b'''<!DOCTYPE definitions [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
      <definitions xmlns="http://schemas.xmlsoap.org/wsdl/">&xxe;</definitions>'''
    check("DOCTYPE and ENTITY rejected before XML parsing", sd.parse_wsdl(evil) is None)
    utf16_evil = '''<?xml version="1.0" encoding="UTF-16"?>
      <!DOCTYPE definitions [<!ENTITY x "urn:expanded">]>
      <definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="&x;"/>'''.encode("utf-16")
    check("UTF-16 cannot hide DOCTYPE/ENTITY from the pre-parse guard",
          sd.parse_wsdl(utf16_evil) is None)
    utf16_good = WSDL11.decode("utf-8").replace(
        '<?xml version="1.0"?>', '<?xml version="1.0" encoding="UTF-16"?>').encode("utf-16")
    check("bounded ordinary UTF-16 WSDL remains supported",
          sd.parse_wsdl(utf16_good) is not None)
    check("wrong XML dialect rejected", sd.parse_wsdl(b"<definitions/>") is None)
    check("oversized WSDL rejected", sd.parse_wsdl(b" " * (sd.MAX_BYTES + 1)) is None)
    deep = (b'<definitions xmlns="http://schemas.xmlsoap.org/wsdl/">'
            + b"<x>" * (sd.MAX_XML_DEPTH + 2) + b"</x>" * (sd.MAX_XML_DEPTH + 2)
            + b"</definitions>")
    check("deep XML tree rejected", sd.parse_wsdl(deep) is None)
    old = sd.MAX_XML_NODES
    try:
        sd.MAX_XML_NODES = 4
        check("XML node cap enforced", sd.parse_wsdl(WSDL11) is None)
    finally:
        sd.MAX_XML_NODES = old


def test_proto_metadata_and_bounds():
    result = sd.parse_proto(PROTO, source_url="/generated/service.proto")
    check("proto package/messages/enums extracted", result["package"] == "acme.greeter.v1"
          and result["messages"] == ["HelloRequest", "HelloReply"]
          and result["enums"] == ["Mood"], result)
    check("proto comments and strings do not forge declarations", len(result["services"]) == 1
          and result["services"][0]["name"] == "Greeter"
          and [row["name"] for row in result["rpcs"]] == ["SayHello", "Chat"], result)
    chat = result["rpcs"][1]
    check("proto RPC types and stream directions", chat["input"] == "acme.greeter.v1.HelloRequest"
          and chat["output"] == "acme.greeter.v1.HelloReply"
          and chat["client_streaming"] is True and chat["server_streaming"] is True
          and chat["requestable"] is False, chat)
    check("proto imports metadata-only", result["imports"] == [{
        "path": "google/protobuf/empty.proto", "fetched": False, "requestable": False,
    }], result["imports"])
    check("unbalanced proto rejected", sd.parse_proto(b"service X { rpc A (I) returns (O);") is None)
    deep = b"message X {" * (sd.MAX_PROTO_DEPTH + 1) + b"}" * (sd.MAX_PROTO_DEPTH + 1)
    check("deep proto rejected", sd.parse_proto(deep) is None)
    check("oversized proto rejected", sd.parse_proto(b" " * (sd.MAX_BYTES + 1)) is None)
    old = sd.MAX_PROTO_DECLARATIONS
    try:
        sd.MAX_PROTO_DECLARATIONS = 2
        check("proto declaration cap enforced", sd.parse_proto(PROTO) is None)
    finally:
        sd.MAX_PROTO_DECLARATIONS = old


def test_grpc_web_and_dispatch():
    result = sd.parse_grpc_web(GRPC_WEB, source_url="/assets/api_grpc_web_pb.js")
    check("generated gRPC-web service and package", len(result["services"]) == 1
          and result["services"][0]["name"] == "Greeter"
          and result["services"][0]["package"] == "acme.greeter.v1", result)
    check("generated gRPC-web comments ignored", [row["name"] for row in result["rpcs"]]
          == ["SayHello", "Watch"], result["rpcs"])
    watch = result["rpcs"][1]
    check("gRPC-web types/path/stream metadata", watch["path"] == "/acme.greeter.v1.Greeter/Watch"
          and watch["input"] == "acme.greeter.v1.HelloRequest"
          and watch["output"] == "acme.greeter.v1.HelloReply"
          and watch["server_streaming"] is True and watch["requestable"] is False, watch)
    check("dispatcher recognizes all three passive formats",
          sd.parse(WSDL11, path="/a.wsdl", base_url="https://target.test")["kind"] == "wsdl"
          and sd.parse(PROTO, path="/a.proto")["kind"] == "protobuf"
          and sd.parse(GRPC_WEB, path="/api_grpc_web_pb.js")["kind"] == "grpc-web")
    check("unrecognized bytes fail closed", sd.parse(b"hello", path="/app.js") is None)


def test_transport_free_contract():
    source = (REPO / "solvers" / "web" / "service_descriptors.py").read_text()
    tree = ast.parse(source)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    check("parser imports no transport/process package",
          not ({"requests", "httpx", "urllib3", "socket", "subprocess", "asyncio"} & imports), imports)
    results = [sd.parse_wsdl(WSDL11), sd.parse_proto(PROTO), sd.parse_grpc_web(GRPC_WEB)]
    check("every successful parser declares zero network requests", all(row["network_requests"] == 0
          and row["metadata_only"] is True and row["flag"] is None for row in results), results)
    check("bytes-only API rejects text input", sd.parse_wsdl(WSDL11.decode()) is None
          and sd.parse_proto(PROTO.decode()) is None and sd.parse_grpc_web(GRPC_WEB.decode()) is None)


if __name__ == "__main__":
    tests = [test_wsdl_versions_and_metadata, test_xml_rejection_and_bounds,
             test_proto_metadata_and_bounds, test_grpc_web_and_dispatch,
             test_transport_free_contract]
    for test in tests:
        try:
            test()
        except Exception as exc:
            check(test.__name__, False, repr(exc))
    print(("FAIL" if FAILS else "PASS"), "test_web_service_descriptors", len(FAILS), "failed")
    raise SystemExit(bool(FAILS))
