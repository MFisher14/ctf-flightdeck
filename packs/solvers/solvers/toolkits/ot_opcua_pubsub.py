#!/usr/bin/env python3
"""Bounded, offline OPC UA UADP PubSub and NodeSet2 XML inspection.

Extends ics_app_depth's UA Binary primitives; it does not implement UACP again.
UADP layouts are OPC 10000-14 7.2.4, using Part 6 binary encodings. NodeSet2
is Part 6 Annex F. No sockets, XML schema fetching, signature verification,
decryption, or execution. RawData requires external metadata and stays opaque.
Binary value decoding reuses ics_app_depth. A resource preflight limits flat
arrays to 4096 and rejects arrays of recursive Variant/DataValue/DiagnosticInfo
elements; scalar nesting retains the baseline depth limit.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import struct
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote, unquote

import ics_app_depth as ua
import ics_vendor_devices as devices

MAX_INPUT = min(ua.MAX_FRAME, devices.MAX_INPUT)
MAX_ITEMS = min(ua.MAX_ITEMS, devices.MAX_NODES)
NODESET_NS = "http://opcfoundation.org/UA/2011/03/UANodeSet.xsd"
UA_NS = "http://opcfoundation.org/UA/"


class ParseError(ValueError):
    """Malformed, unsupported, ambiguous, or over-limit supplied evidence."""


def _blob(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ParseError("input must be bytes-like")
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    if size > MAX_INPUT:
        raise ParseError("input exceeds size limit")
    return bytes(data)


class _Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, size):
        if size < 0 or size > len(self.data) - self.pos:
            raise ParseError("truncated UADP field")
        value = self.data[self.pos:self.pos + size]
        self.pos += size
        return value

    def number(self, fmt):
        return struct.unpack("<" + fmt, self.take(struct.calcsize("<" + fmt)))[0]

    def primitive(self, parser):
        if parser in (ua.parse_opcua_variant, ua.parse_opcua_datavalue):
            _preflight_value(self.data, self.pos, datavalue=parser is ua.parse_opcua_datavalue)
        value, end = parser(self.data, self.pos)
        if end < self.pos or end > len(self.data):
            raise ParseError("UA primitive exceeded payload")
        self.pos = end
        return value

    def remaining(self):
        return len(self.data) - self.pos


def _preflight_value(data, offset, *, datavalue=False, depth=0):
    """Check allocation-driving prefixes; actual values use the existing decoder."""
    if depth > ua.MAX_DEPTH or offset >= len(data):
        raise ParseError("value prefix is truncated or exceeds nesting limit")
    flags = data[offset]
    offset += 1
    if datavalue:
        if flags & 1:
            _preflight_value(data, offset, depth=depth + 1)
        return
    kind = flags & 63
    if flags & 128:
        if kind == 0:
            raise ParseError("Null Variant array is reserved")
        if kind in (23, 24, 25):
            raise ParseError("recursive Variant array element types are unsupported")
        if len(data) - offset < 4:
            raise ParseError("truncated Variant array count")
        count = struct.unpack_from("<i", data, offset)[0]
        if not -1 <= count <= 4096:
            raise ParseError("Variant array exceeds 4096-element limit")
    elif kind in (23, 24):
        _preflight_value(data, offset, datavalue=kind == 23, depth=depth + 1)


def _padding(reader, out):
    padding = reader.take(reader.remaining())
    if any(padding):
        raise ParseError("nonzero trailing DataSetMessage bytes")
    out["padding_size"] = len(padding)


def _dataset(data):
    reader = _Reader(data)
    flags = reader.number("B")
    out = {"flags1": flags, "valid": bool(flags & 1), "size": len(data)}
    if not out["valid"]:
        out.update(payload_status="invalid-message", opaque_hex=reader.take(reader.remaining()).hex())
        return out
    flags2 = reader.number("B") if flags & 128 else 0
    encoding, kind = (flags >> 1) & 3, flags2 & 15
    if encoding == 3 or flags2 & 192 or kind not in (0, 1, 2, 3):
        raise ParseError("unsupported DataSetMessage type or reserved flags")
    if flags2 & 32 and not flags2 & 16:
        raise ParseError("DataSetMessage picoseconds require timestamp")
    if kind == 2 and encoding != 0:
        raise ParseError("event fields must use Variant encoding")
    if encoding == 1 and kind != 0:
        raise ParseError("RawData is only valid for key frames")
    out.update(flags2=flags2, field_encoding=("Variant", "RawData", "DataValue")[encoding],
               message_type=("key-frame", "delta-frame", "event", "keep-alive")[kind])
    if flags & 8:
        out["sequence_number"] = reader.number("H")
    if flags2 & 16:
        out["timestamp"] = ua._ua_datetime(reader.number("q"))
    if flags2 & 32:
        out["picoseconds_raw"] = reader.number("H")
        out["picoseconds"] = min(out["picoseconds_raw"], 9999)
    if flags & 16:
        out["status"] = reader.number("H")
        out["status_code"] = out["status"] << 16
    if flags & 32:
        out["configuration_major"] = reader.number("I")
    if flags & 64:
        out["configuration_minor"] = reader.number("I")
    out["header_size"] = reader.pos
    if kind == 3:
        out.update(payload_status="decoded", fields=[])
        _padding(reader, out)
        return out
    if kind == 0 and reader.remaining() == 0:
        out.update(payload_status="heartbeat", fields=[])
        return out
    if encoding == 1:
        out.update(payload_status="metadata-required", opaque_hex=reader.take(reader.remaining()).hex())
        return out
    count = reader.number("H")
    if count > MAX_ITEMS:
        raise ParseError("too many DataSet fields")
    fields, indexes = [], set()
    output_size = 0
    for index in range(count):
        if kind == 1:
            index = reader.number("H")
            if index in indexes:
                raise ParseError("duplicate delta field index")
            indexes.add(index)
        value = reader.primitive(ua.parse_opcua_variant if encoding == 0 else ua.parse_opcua_datavalue)
        output_size += len(json.dumps(value))
        if output_size > devices.MAX_OUTPUT_CHARS:
            raise ParseError("DataSet output exceeds limit")
        fields.append({"index": index, "value": value})
    out.update(payload_status="decoded", field_count=count, fields=fields)
    _padding(reader, out)
    return out


def parse_dataset_message(data):
    """Decode one length-delimited DataSetMessage; metadata-less RawData is opaque."""
    try:
        return _dataset(_blob(data))
    except ParseError:
        raise
    except (ua.ParseError, ValueError, TypeError, IndexError, KeyError, OverflowError, RecursionError, struct.error) as exc:
        raise ParseError("invalid DataSetMessage: " + str(exc)) from exc


def _network(data, signature_size, dataset_sizes):
    reader = _Reader(data)
    output_size = 0
    flags = reader.number("B")
    if flags & 15 != 1:
        raise ParseError("unsupported UADP version")
    ext1 = reader.number("B") if flags & 128 else 0
    ext2 = reader.number("B") if ext1 & 128 else 0
    if ext2 & 0xFC:
        raise ParseError("discovery/action/reserved NetworkMessages are not supported")
    if ext1 & 64 and not ext1 & 32:
        raise ParseError("network picoseconds require timestamp")
    out = {"format": "UADP", "version": 1, "flags": flags, "extended_flags1": ext1,
           "extended_flags2": ext2, "dataset_messages": []}
    if flags & 16:
        kind = ext1 & 7
        if kind > 4:
            raise ParseError("reserved PublisherId type")
        value = reader.primitive(ua._ua_string) if kind == 4 else reader.number(("B", "H", "I", "Q")[kind])
        out["publisher_id"] = {"type": ("Byte", "UInt16", "UInt32", "UInt64", "String")[kind], "value": value}
    elif ext1 & 7:
        raise ParseError("PublisherId type set without PublisherId")
    if ext1 & 8:
        out["dataset_class_id"] = str(uuid.UUID(bytes_le=reader.take(16)))
    if flags & 32:
        group_flags = reader.number("B")
        if group_flags & 240:
            raise ParseError("reserved GroupFlags")
        group = {"flags": group_flags}
        for bit, key, fmt in ((1, "writer_group_id", "H"), (2, "group_version", "I"),
                              (4, "network_message_number", "H"), (8, "sequence_number", "H")):
            if group_flags & bit:
                group[key] = reader.number(fmt)
        if group.get("network_message_number") == 0:
            raise ParseError("NetworkMessageNumber zero is invalid")
        out["group"] = group
    writer_ids = None
    if flags & 64:
        # Chunk payload headers carry a single WriterId and no count byte.
        count = 1 if ext2 & 1 else reader.number("B")
        if not count:
            raise ParseError("empty DataSet payload header")
        writer_ids = [reader.number("H") for _ in range(count)]
        out["writer_ids"] = writer_ids
    if ext1 & 32:
        out["timestamp"] = ua._ua_datetime(reader.number("q"))
    if ext1 & 64:
        out["picoseconds_raw"] = reader.number("H")
        out["picoseconds"] = min(out["picoseconds_raw"], 9999)
    if ext2 & 2:
        if writer_ids is not None and len(writer_ids) != 1:
            raise ParseError("promoted fields require one DataSetMessage")
        promoted_reader = _Reader(reader.take(reader.number("H")))
        promoted = []
        while promoted_reader.remaining():
            if len(promoted) >= MAX_ITEMS:
                raise ParseError("too many promoted fields")
            value = promoted_reader.primitive(ua.parse_opcua_variant)
            output_size += len(json.dumps(value))
            if output_size > devices.MAX_OUTPUT_CHARS:
                raise ParseError("promoted fields output exceeds limit")
            promoted.append(value)
        out["promoted_fields"] = promoted
    footer_size = 0
    security = None
    if ext1 & 16:
        sf = reader.number("B")
        if sf & 240 or sf & 2 and not sf & 1:
            raise ParseError("invalid SecurityFlags")
        security = {"flags": sf, "signed": bool(sf & 1), "encrypted": bool(sf & 2),
                    "force_key_reset": bool(sf & 8), "token_id": reader.number("I"),
                    "authentication": "not-verified"}
        security["nonce_hex"] = reader.take(reader.number("B")).hex()
        if sf & 4:
            footer_size = reader.number("H")
        security["footer_size"] = footer_size
        out["security"] = security
    out["header_size"] = reader.pos
    if security and (security["encrypted"] or security["signed"] and signature_size is None):
        if reader.remaining() < footer_size + (signature_size or 0):
            raise ParseError("truncated protected payload")
        out.update(payload_status="encrypted" if security["encrypted"] else "signature-size-required",
                   protected_payload_hex=reader.take(reader.remaining()).hex())
        return out
    sig_size = signature_size or 0
    if sig_size and not (security and security["signed"]):
        raise ParseError("signature size specified for unsigned message")
    if footer_size + sig_size > reader.remaining():
        raise ParseError("security trailer exceeds payload")
    payload = reader.take(reader.remaining() - footer_size - sig_size)
    if security:
        security["footer_hex"] = reader.take(footer_size).hex()
        security["signature_hex"] = reader.take(sig_size).hex()
    if ext2 & 1:
        if writer_ids is not None and len(writer_ids) != 1:
            raise ParseError("chunk header requires one DataSetWriterId")
        chunk = _Reader(payload)
        part = {"sequence_number": chunk.number("H"), "offset": chunk.number("I"), "total_size": chunk.number("I")}
        value = chunk.primitive(ua._ua_bytestring)
        if value is None or chunk.remaining() or part["total_size"] > MAX_INPUT or part["offset"] + len(value) > part["total_size"]:
            raise ParseError("invalid chunk range or data")
        part["data_hex"] = value.hex()
        out.update(payload_status="chunk", chunk=part)
        return out
    if writer_ids is None:
        if dataset_sizes is None:
            out.update(payload_status="reader-configuration-required", opaque_hex=payload.hex())
            return out
        sizes = dataset_sizes
    elif len(writer_ids) == 1:
        sizes = [len(payload)]
    else:
        size_reader = _Reader(payload)
        sizes = [size_reader.number("H") for _ in writer_ids]
        payload = size_reader.take(size_reader.remaining())
    if not sizes or any(size <= 0 for size in sizes) or sum(sizes) != len(payload):
        raise ParseError("DataSetMessage sizes do not match payload")
    if ext2 & 2 and len(sizes) != 1:
        raise ParseError("promoted fields require one DataSetMessage")
    cursor = 0
    for index, size in enumerate(sizes):
        message = _dataset(payload[cursor:cursor + size])
        output_size += len(json.dumps(message))
        if output_size > devices.MAX_OUTPUT_CHARS:
            raise ParseError("UADP dataset output exceeds limit")
        if writer_ids is not None:
            message["writer_id"] = writer_ids[index]
        out["dataset_messages"].append(message)
        cursor += size
    out["payload_status"] = "decoded"
    return out


def parse_uadp(data, *, signature_size=None, dataset_sizes=None):
    """Inspect one transport-delimited UADP message, never decrypting/authenticating.

    signature_size is required to separate signed plaintext from its signature.
    dataset_sizes supplies reader configuration when the PayloadHeader is absent.
    Without these facts the affected payload remains explicitly opaque.
    """
    try:
        if signature_size is not None and (type(signature_size) is not int or not 0 < signature_size <= 65535):
            raise ParseError("invalid signature size")
        if dataset_sizes is not None and (not isinstance(dataset_sizes, (list, tuple)) or
                not 0 < len(dataset_sizes) <= 255 or any(type(n) is not int or not 0 < n <= MAX_INPUT for n in dataset_sizes)):
            raise ParseError("invalid reader DataSetMessage sizes")
        return _network(_blob(data), signature_size, dataset_sizes)
    except ParseError:
        raise
    except (ua.ParseError, ValueError, TypeError, IndexError, KeyError, OverflowError, RecursionError, struct.error) as exc:
        raise ParseError("invalid UADP message: " + str(exc)) from exc


def _nodeid(text, namespaces, aliases, *, expanded=False):
    if not isinstance(text, str) or len(text) > devices.MAX_PATH:
        raise ParseError("invalid NodeId text")
    text = aliases.get(text, text)
    if len(text) > devices.MAX_PATH:
        raise ParseError("NodeId alias exceeds text limit")
    server, uri = 0, None
    if expanded and text.startswith("svr="):
        part, sep, text = text.partition(";")
        if not sep or not part[4:].isascii() or not part[4:].isdigit():
            raise ParseError("invalid expanded server index")
        server = int(part[4:])
        if server > 0xFFFFFFFF:
            raise ParseError("server index overflow")
    if expanded and text.startswith("nsu="):
        part, sep, text = text.partition(";")
        if not sep or not part[4:]:
            raise ParseError("invalid namespace URI")
        if re.search(r'%(?![0-9a-fA-F]{2})', part[4:]):
            raise ParseError("invalid namespace URI percent escape")
        uri = unquote(part[4:], encoding="utf-8", errors="strict")
    match = re.fullmatch(r"(?:ns=([0-9]+);)?([isgb])=(.*)", text, re.S)
    if not match:
        raise ParseError("invalid NodeId or undefined alias: " + text[:120])
    ns, kind, value = int(match[1] or 0), match[2], match[3]
    if ns > 65535 or ns >= len(namespaces) or uri is not None and ns:
        raise ParseError("NodeId namespace is not declared")
    if uri is not None and uri in namespaces:
        ns, uri = namespaces.index(uri), None
    if kind == "i":
        if not value.isascii() or not value.isdigit() or int(value) > 0xFFFFFFFF:
            raise ParseError("invalid numeric NodeId")
        raw = b"\x02" + struct.pack("<HI", ns, int(value))
    elif kind == "s":
        encoded = value.encode("utf-8")
        raw = b"\x03" + struct.pack("<Hi", ns, len(encoded)) + encoded
    elif kind == "g":
        raw = b"\x04" + struct.pack("<H", ns) + uuid.UUID(value).bytes_le
    else:
        encoded = base64.b64decode(value, validate=True)
        raw = b"\x05" + struct.pack("<Hi", ns, len(encoded)) + encoded
    result, _ = ua.parse_opcua_nodeid(raw)
    result["namespace_uri"] = uri if uri is not None else namespaces[ns]
    if server:
        result["server_index"] = server
    identifier = result["identifier"]
    if kind == "b":
        identifier = base64.b64encode(bytes.fromhex(identifier)).decode("ascii")
    encoded_uri = quote(uri, safe=":/?#[]@!$&'()*+,-._~=") if uri is not None else None
    prefix = (f"svr={server};" if server else "") + (f"nsu={encoded_uri};" if uri is not None else f"ns={ns};" if ns else "")
    result["text"] = prefix + kind + "=" + str(identifier)
    return result


def _xml_value(element):
    # Preserve the typed XML tree: custom structures require their model schema.
    return {"tag": element.tag, "attributes": dict(sorted(element.attrib.items())),
            "text": element.text or "", "children": [_xml_value(child) for child in element if isinstance(child.tag, str)]}


def _nodeset(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    data = _blob(data)
    root = ET.fromstring(data, parser=ET.XMLParser(target=devices._Tree()))
    tag = "{" + NODESET_NS + "}"
    if root.tag != tag + "UANodeSet":
        raise ParseError("not a NodeSet2 XML document")
    namespaces = [UA_NS] + [(el.text or "").strip() for el in root.findall(tag + "NamespaceUris/" + tag + "Uri")]
    if any(not uri for uri in namespaces) or len(set(namespaces)) != len(namespaces) or len(namespaces) > 65536:
        raise ParseError("invalid namespace URI table")
    servers = [(el.text or "").strip() for el in root.findall(tag + "ServerUris/" + tag + "Uri")]
    aliases = {}
    for element in root.findall(tag + "Aliases/" + tag + "Alias"):
        name, value = element.get("Alias"), element.text or ""
        if not name or name in aliases:
            raise ParseError("duplicate or empty NodeId alias")
        aliases[name] = _nodeid(value, namespaces, {})["text"]
    nodes, identities, findings = [], set(), []
    output_size = 0
    classes = {"UANode", "UAObject", "UAVariable", "UAMethod", "UAView", "UAObjectType", "UAVariableType", "UADataType", "UAReferenceType"}
    for element in root:
        if not isinstance(element.tag, str) or not element.tag.startswith(tag) or element.tag[len(tag):] not in classes:
            continue
        nodeid = _nodeid(element.get("NodeId"), namespaces, aliases)
        identity = nodeid["text"]
        if identity in identities:
            findings.append({"kind": "duplicate-node-id", "node_id": identity})
        identities.add(identity)
        node = {"node_class": element.tag[len(tag):], "node_id": nodeid,
                "attributes": dict(sorted(element.attrib.items())), "references": []}
        browse = element.get("BrowseName")
        if browse is None:
            raise ParseError("NodeSet node has no BrowseName")
        match = re.fullmatch(r"(?:(\d+):)?(.*)", browse, re.S)
        ns = int(match[1] or 0)
        if ns >= len(namespaces):
            raise ParseError("BrowseName namespace is not declared")
        node["browse_name"] = {"namespace": ns, "name": match[2], "namespace_uri": namespaces[ns]}
        for key in ("DataType", "ParentNodeId"):
            if element.get(key) is not None:
                node[key] = _nodeid(element.get(key), namespaces, aliases)
        for name in ("DisplayName", "Description", "InverseName"):
            node[name] = [{"locale": el.get("Locale"), "text": el.text or ""} for el in element.findall(tag + name)]
        value = element.find(tag + "Value")
        if value is not None:
            node["value_xml"] = _xml_value(value)
        for ref in element.findall(tag + "References/" + tag + "Reference"):
            forward_text = ref.get("IsForward", "true")
            if forward_text not in ("true", "false", "1", "0"):
                raise ParseError("invalid Reference IsForward boolean")
            target = _nodeid(ref.text or "", namespaces, aliases, expanded=True)
            if target.get("server_index", 0) > len(servers):
                raise ParseError("Reference server index is not declared")
            reference_type = _nodeid(ref.get("ReferenceType"), namespaces, aliases)
            forward = forward_text in ("true", "1")
            node["references"].append({"reference_type": reference_type, "target": target,
                "is_forward": forward, "source_id": identity if forward else target["text"],
                "target_id": target["text"] if forward else identity})
            output_size += len(json.dumps(node["references"][-1]))
            if output_size > devices.MAX_OUTPUT_CHARS:
                raise ParseError("NodeSet output exceeds limit")
        output_size += len(json.dumps({key: value for key, value in node.items() if key != "references"}))
        if output_size > devices.MAX_OUTPUT_CHARS:
            raise ParseError("NodeSet output exceeds limit")
        nodes.append(node)
        if len(nodes) > MAX_ITEMS:
            raise ParseError("too many NodeSet nodes")
    for node in nodes:
        for ref in node["references"]:
            # Out-of-document references are legal, not unresolved-model errors.
            ref["target_scope"] = "internal" if ref["target"]["text"] in identities else "external"
    return {"format": "NodeSet2", "namespace_uris": namespaces, "server_uris": servers,
            "aliases": dict(sorted(aliases.items())), "nodes": nodes, "findings": findings,
            "models": [_xml_value(el) for el in root.findall(tag + "Models/" + tag + "Model")]}


def parse_nodeset(data):
    """Parse NodeSet2 nodes, typed XML values, alias-resolved references and directions."""
    try:
        return _nodeset(data)
    except ParseError:
        raise
    except (ua.ParseError, devices.ParseError, ET.ParseError, ValueError, TypeError, LookupError,
            OverflowError, RecursionError, struct.error, binascii.Error) as exc:
        raise ParseError("invalid NodeSet2: " + str(exc)) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("uadp", "dataset", "nodeset"))
    parser.add_argument("input", type=Path)
    parser.add_argument("--signature-size", type=int)
    parser.add_argument("--dataset-sizes", type=int, nargs="+")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with args.input.open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
        report = (parse_uadp(data, signature_size=args.signature_size, dataset_sizes=args.dataset_sizes)
                  if args.mode == "uadp" else parse_dataset_message(data) if args.mode == "dataset" else parse_nodeset(data))
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0
    except (OSError, ParseError) as exc:
        print("ot_opcua_pubsub: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
