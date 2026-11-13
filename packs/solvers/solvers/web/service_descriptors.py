#!/usr/bin/env python3
"""Strict, transport-free WSDL, protobuf, and gRPC-web metadata parsers.

Callers must supply bytes obtained from an exact target-local link.  This
module deliberately has no HTTP, socket, reflection, or RPC client.  Import
locations, SOAP addresses, and RPC method paths are returned as metadata with
``requestable=False``; none is followed or invoked.
"""

from __future__ import annotations

import re
import urllib.parse
import xml.etree.ElementTree as ET


MAX_BYTES = 1024 * 1024
MAX_XML_NODES = 10_000
MAX_XML_DEPTH = 32
MAX_ITEMS = 256
MAX_PARTS = 64
MAX_PROTO_DEPTH = 32
MAX_PROTO_DECLARATIONS = 2_000
MAX_TEXT = 512

WSDL11 = "http://schemas.xmlsoap.org/wsdl/"
WSDL20 = "http://www.w3.org/ns/wsdl"
XSD_NAMESPACES = {
    "http://www.w3.org/1999/XMLSchema",
    "http://www.w3.org/2000/10/XMLSchema",
    "http://www.w3.org/2001/XMLSchema",
}
SOAP_OPERATION_NAMESPACES = {
    "http://schemas.xmlsoap.org/wsdl/soap/",
    "http://schemas.xmlsoap.org/wsdl/soap12/",
    "http://www.w3.org/ns/wsdl/soap",
}
FORBIDDEN_XML = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.I)
XML_DECL_ENCODING = re.compile(
    r"^\ufeff?\s*<\?xml\b[^>]*\bencoding\s*=\s*['\"]([^'\"]+)['\"]",
    re.I,
)

_PROTO_PACKAGE = re.compile(
    r"(?m)^\s*package\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;"
)
_PROTO_IMPORT = re.compile(
    r'''(?m)^\s*import(?:\s+(?:public|weak))?\s+["']([^"'\r\n]{1,512})["']\s*;'''
)
_PROTO_MESSAGE = re.compile(r"\bmessage\s+([A-Za-z_]\w*)\s*\{")
_PROTO_ENUM = re.compile(r"\benum\s+([A-Za-z_]\w*)\s*\{")
_PROTO_SERVICE = re.compile(r"\bservice\s+([A-Za-z_]\w*)\s*\{")
_PROTO_RPC = re.compile(
    r"\brpc\s+([A-Za-z_]\w*)\s*\(\s*(stream\s+)?"
    r"(\.?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\)\s*"
    r"returns\s*\(\s*(stream\s+)?"
    r"(\.?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\)",
    re.S,
)
_GRPC_DESCRIPTOR = re.compile(
    r"(?:new\s+)?(?:[A-Za-z_$][\w$]*\.)*MethodDescriptor\s*\(\s*"
    r"([\"'])(/[A-Za-z0-9_.-]+/[A-Za-z_]\w*)\1\s*,\s*"
    r"(?:[A-Za-z_$][\w$]*\.)*(UNARY|SERVER_STREAMING|CLIENT_STREAMING|BIDI_STREAMING)\s*,\s*"
    r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*,\s*"
    r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)",
    re.S,
)


def _raw(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    value = bytes(data)
    if not value or len(value) > MAX_BYTES:
        return None
    return value


def _xml_text(raw):
    """Decode only UTF-8/ASCII or UTF-16 XML for pre-parse DTD inspection.

    Searching raw ASCII bytes is encoding-blind: UTF-16 can hide ``DOCTYPE``
    and ``ENTITY`` from that guard, after which ElementTree expands internal
    entities before post-parse node limits run. Decode the bounded document
    first, reject unsupported/inconsistent declarations, and scan the actual
    XML characters before invoking any parser.
    """
    if not isinstance(raw, bytes):
        return None
    encoding = "utf-8-sig"
    allowed = {"utf-8", "utf8", "us-ascii", "ascii"}
    if raw.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return None  # UTF-32 is unnecessary for observed descriptors.
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
        allowed = {"utf-16", "utf16", "utf-16le", "utf-16be", "utf16le", "utf16be"}
    elif raw.startswith(b"<\x00?\x00"):
        encoding = "utf-16-le"
        allowed = {"utf-16", "utf16", "utf-16le", "utf16le"}
    elif raw.startswith(b"\x00<\x00?"):
        encoding = "utf-16-be"
        allowed = {"utf-16", "utf16", "utf-16be", "utf16be"}
    try:
        text = raw.decode(encoding, "strict")
    except (LookupError, UnicodeDecodeError):
        return None
    if "\x00" in text:
        return None
    declaration = XML_DECL_ENCODING.search(text[:1024])
    if declaration and declaration.group(1).strip().lower() not in allowed:
        return None
    return text


def _short(value, limit=MAX_TEXT):
    if value is None:
        return None
    text = str(value).strip()
    if (not text or len(text.encode("utf-8", "replace")) > limit
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in text)):
        return None
    return text


def _tag(value):
    if isinstance(value, str) and value.startswith("{") and "}" in value:
        namespace, local = value[1:].split("}", 1)
        return namespace, local
    return "", str(value or "")


def _qname(value):
    text = _short(value, 256)
    if text is None:
        return None
    return text.rsplit(":", 1)[-1]


def _origin(url):
    try:
        parsed = urllib.parse.urlsplit(url)
    except (TypeError, ValueError):
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    default = 443 if parsed.scheme.lower() == "https" else 80
    try:
        port = parsed.port or default
    except ValueError:
        return None
    return parsed.scheme.lower(), parsed.hostname.rstrip(".").lower(), port


def _location(value, base_url):
    location = _short(value, 2048)
    if location is None:
        return None
    try:
        resolved = urllib.parse.urljoin(base_url or "", location)
    except (TypeError, ValueError):
        resolved = location
    base_origin = _origin(base_url)
    target_origin = _origin(resolved)
    same_origin = None
    if target_origin is not None and base_origin is not None:
        same_origin = target_origin == base_origin
    elif target_origin is None:
        try:
            is_relative = not urllib.parse.urlsplit(location).netloc
        except ValueError:
            is_relative = False
        if is_relative:
            same_origin = True if base_origin is not None else None
    return {
        "location": location,
        "resolved": _short(resolved, 2048),
        "same_origin": same_origin,
        "off_origin": same_origin is False,
        "requestable": False,
    }


def _bounded_xml(root):
    count = 0
    stack = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_XML_NODES or depth > MAX_XML_DEPTH:
            return False
        stack.extend((child, depth + 1) for child in list(node))
    return True


def _empty(kind, source_url=None):
    return {
        "kind": kind,
        "source": _short(source_url, 2048),
        "metadata_only": True,
        "network_requests": 0,
        "requestable": False,
        "flag": None,
    }


def parse_wsdl(data, *, base_url="", source_url=None):
    """Parse WSDL 1.1/2.0 bytes without resolving any external resource."""
    raw = _raw(data)
    text = _xml_text(raw) if raw is not None else None
    if text is None or FORBIDDEN_XML.search(text):
        return None
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, ValueError, OverflowError):
        return None
    namespace, local = _tag(root.tag)
    expected_root = WSDL11 if local == "definitions" else WSDL20 if local == "description" else None
    if namespace != expected_root:
        return None
    if not _bounded_xml(root):
        return None

    dialect = "wsdl-1.1" if namespace == WSDL11 else "wsdl-2.0"
    try:
        effective_base = urllib.parse.urljoin(base_url or "", source_url or "") or base_url
    except (TypeError, ValueError):
        effective_base = base_url
    result = _empty("wsdl", source_url)
    result.update({
        "dialect": dialect,
        "target_namespace": _short(root.attrib.get("targetNamespace"), 512),
        "imports": [],
        "xsd": {"elements": [], "complex_types": [], "simple_types": [], "attributes": []},
        "messages": [],
        "operations": [],
        "addresses": [],
    })

    for node in root.iter():
        ns, name = _tag(node.tag)
        if name in {"import", "include", "redefine", "override"} and ns in ({WSDL11, WSDL20} | XSD_NAMESPACES):
            row = {
                "kind": name,
                "namespace": _short(node.attrib.get("namespace"), 512),
                "fetched": False,
                "requestable": False,
            }
            location = node.attrib.get("location") or node.attrib.get("schemaLocation")
            if location:
                row.update(_location(location, effective_base) or {})
            if len(result["imports"]) < MAX_ITEMS:
                result["imports"].append(row)
        if ns in XSD_NAMESPACES and name in {"element", "complexType", "simpleType", "attribute"}:
            value = _short(node.attrib.get("name"), 256)
            key = {"element": "elements", "complexType": "complex_types",
                   "simpleType": "simple_types", "attribute": "attributes"}[name]
            if value and value not in result["xsd"][key] and len(result["xsd"][key]) < MAX_ITEMS:
                result["xsd"][key].append(value)

    if namespace == WSDL11:
        _wsdl11(root, result, effective_base)
    else:
        _wsdl20(root, result, effective_base)
    return result


def _wsdl11(root, result, base_url):
    messages = {}
    for message in root.findall(f"{{{WSDL11}}}message")[:MAX_ITEMS]:
        name = _short(message.attrib.get("name"), 256)
        if not name:
            continue
        parts = []
        for part in message.findall(f"{{{WSDL11}}}part")[:MAX_PARTS]:
            row = {"name": _short(part.attrib.get("name"), 256)}
            element = _qname(part.attrib.get("element"))
            typename = _qname(part.attrib.get("type"))
            if element:
                row["element"] = element
            if typename:
                row["type"] = typename
            parts.append(row)
        messages[name] = {"name": name, "parts": parts}
    result["messages"] = list(messages.values())

    interface_ops = {}
    for interface in root.findall(f"{{{WSDL11}}}portType")[:MAX_ITEMS]:
        interface_name = _short(interface.attrib.get("name"), 256)
        for operation in interface.findall(f"{{{WSDL11}}}operation")[:MAX_ITEMS]:
            name = _short(operation.attrib.get("name"), 256)
            if not name or len(interface_ops) >= MAX_ITEMS:
                continue
            row = {"name": name, "interface": interface_name, "requestable": False}
            for member in list(operation):
                _ns, direction = _tag(member.tag)
                if direction in {"input", "output"}:
                    row[direction] = _qname(member.attrib.get("message"))
                elif direction == "fault":
                    row.setdefault("faults", []).append(_qname(member.attrib.get("message")))
            interface_ops[(interface_name, name)] = row

    binding_by_name = {}
    bound = []
    for binding in root.findall(f"{{{WSDL11}}}binding")[:MAX_ITEMS]:
        binding_name = _short(binding.attrib.get("name"), 256)
        interface_name = _qname(binding.attrib.get("type"))
        binding_by_name[binding_name] = interface_name
        for operation in binding.findall(f"{{{WSDL11}}}operation")[:MAX_ITEMS]:
            name = _short(operation.attrib.get("name"), 256)
            if not name or len(bound) >= MAX_ITEMS:
                continue
            row = dict(interface_ops.get((interface_name, name), {
                "name": name, "interface": interface_name, "requestable": False,
            }))
            row["binding"] = binding_name
            for child in list(operation):
                ns, local = _tag(child.tag)
                if local == "operation" and ns in SOAP_OPERATION_NAMESPACES:
                    action = _short(child.attrib.get("soapAction") or child.attrib.get("action"), 2048)
                    if action:
                        row["soap_action"] = action
            bound.append(row)
    result["operations"] = bound or list(interface_ops.values())

    for service in root.findall(f"{{{WSDL11}}}service")[:MAX_ITEMS]:
        service_name = _short(service.attrib.get("name"), 256)
        for port in service.findall(f"{{{WSDL11}}}port")[:MAX_ITEMS]:
            port_name = _short(port.attrib.get("name"), 256)
            binding_name = _qname(port.attrib.get("binding"))
            for child in list(port):
                ns, local = _tag(child.tag)
                if local != "address" or ns not in SOAP_OPERATION_NAMESPACES:
                    continue
                location = _location(child.attrib.get("location"), base_url)
                if location and len(result["addresses"]) < MAX_ITEMS:
                    result["addresses"].append({
                        "service": service_name, "port": port_name,
                        "binding": binding_name, **location,
                    })


def _wsdl20(root, result, base_url):
    interface_ops = {}
    for interface in root.findall(f"{{{WSDL20}}}interface")[:MAX_ITEMS]:
        interface_name = _short(interface.attrib.get("name"), 256)
        for operation in interface.findall(f"{{{WSDL20}}}operation")[:MAX_ITEMS]:
            name = _short(operation.attrib.get("name"), 256)
            if not name or len(interface_ops) >= MAX_ITEMS:
                continue
            row = {"name": name, "interface": interface_name, "requestable": False}
            for member in list(operation):
                _ns, direction = _tag(member.tag)
                if direction in {"input", "output"}:
                    row[direction] = _qname(member.attrib.get("element"))
                elif direction in {"infault", "outfault"}:
                    row.setdefault("faults", []).append(_qname(member.attrib.get("ref")))
            interface_ops[(interface_name, name)] = row

    bindings = {}
    bound = []
    for binding in root.findall(f"{{{WSDL20}}}binding")[:MAX_ITEMS]:
        binding_name = _short(binding.attrib.get("name"), 256)
        interface_name = _qname(binding.attrib.get("interface"))
        bindings[binding_name] = interface_name
        for operation in binding.findall(f"{{{WSDL20}}}operation")[:MAX_ITEMS]:
            ref = _qname(operation.attrib.get("ref"))
            if not ref or len(bound) >= MAX_ITEMS:
                continue
            row = dict(interface_ops.get((interface_name, ref), {
                "name": ref, "interface": interface_name, "requestable": False,
            }))
            row["binding"] = binding_name
            for attr, value in operation.attrib.items():
                attr_ns, attr_name = _tag(attr)
                if attr_name == "action" and attr_ns in SOAP_OPERATION_NAMESPACES:
                    action = _short(value, 2048)
                    if action:
                        row["soap_action"] = action
            bound.append(row)
    result["operations"] = bound or list(interface_ops.values())

    for service in root.findall(f"{{{WSDL20}}}service")[:MAX_ITEMS]:
        service_name = _short(service.attrib.get("name"), 256)
        for endpoint in service.findall(f"{{{WSDL20}}}endpoint")[:MAX_ITEMS]:
            location = _location(endpoint.attrib.get("address"), base_url)
            if location and len(result["addresses"]) < MAX_ITEMS:
                result["addresses"].append({
                    "service": service_name,
                    "endpoint": _short(endpoint.attrib.get("name"), 256),
                    "binding": _qname(endpoint.attrib.get("binding")),
                    **location,
                })


def _strip_comments(text):
    """Replace comments with whitespace while preserving strings and offsets."""
    out = list(text)
    index = 0
    quote = None
    escaped = False
    block = False
    line = False
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if line:
            if char in "\r\n":
                line = False
            else:
                out[index] = " "
            index += 1
            continue
        if block:
            out[index] = " " if char not in "\r\n" else char
            if char == "*" and nxt == "/":
                out[index + 1] = " "
                block = False
                index += 2
            else:
                index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {'"', "'", "`"}:
            quote = char
            index += 1
        elif char == "/" and nxt == "/":
            out[index] = out[index + 1] = " "
            line = True
            index += 2
        elif char == "/" and nxt == "*":
            out[index] = out[index + 1] = " "
            block = True
            index += 2
        else:
            index += 1
    if block or quote:
        return None
    return "".join(out)


def _mask_strings(text):
    out = list(text)
    quote = None
    escaped = False
    for index, char in enumerate(text):
        if quote:
            if char not in "\r\n":
                out[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in {'"', "'", "`"}:
            quote = char
            out[index] = " "
    return "".join(out)


def _brace_check(masked):
    depth = 0
    count = 0
    for char in masked:
        if char == "{":
            depth += 1
            count += 1
            if depth > MAX_PROTO_DEPTH or count > MAX_PROTO_DECLARATIONS:
                return False
        elif char == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _block_end(masked, opening):
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def parse_proto(data, *, source_url=None):
    """Parse a linked ``.proto`` file as grammar metadata; never reflect."""
    raw = _raw(data)
    if raw is None or b"\x00" in raw:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    clean = _strip_comments(text)
    if clean is None:
        return None
    masked = _mask_strings(clean)
    if not _brace_check(masked):
        return None

    declaration_count = sum(len(regex.findall(masked)) for regex in
                            (_PROTO_PACKAGE, _PROTO_MESSAGE, _PROTO_ENUM, _PROTO_SERVICE, _PROTO_RPC))
    if declaration_count > MAX_PROTO_DECLARATIONS:
        return None
    packages = _PROTO_PACKAGE.findall(masked)
    if len(packages) > 1:
        return None
    package = packages[0] if packages else None
    result = _empty("protobuf", source_url)
    result.update({
        "dialect": "proto",
        "package": package,
        "imports": [{"path": value, "fetched": False, "requestable": False}
                    for value in _PROTO_IMPORT.findall(clean)[:MAX_ITEMS]],
        "messages": list(dict.fromkeys(_PROTO_MESSAGE.findall(masked)))[:MAX_ITEMS],
        "enums": list(dict.fromkeys(_PROTO_ENUM.findall(masked)))[:MAX_ITEMS],
        "services": [],
        "rpcs": [],
    })
    for match in list(_PROTO_SERVICE.finditer(masked))[:MAX_ITEMS]:
        service = match.group(1)
        opening = masked.find("{", match.start(), match.end())
        end = _block_end(masked, opening)
        if opening < 0 or end is None:
            return None
        methods = []
        for rpc in list(_PROTO_RPC.finditer(masked, opening + 1, end))[:MAX_ITEMS]:
            row = {
                "name": rpc.group(1),
                "package": package,
                "service": service,
                "input": rpc.group(3).lstrip("."),
                "output": rpc.group(5).lstrip("."),
                "client_streaming": bool(rpc.group(2)),
                "server_streaming": bool(rpc.group(4)),
                "requestable": False,
            }
            methods.append(row)
            if len(result["rpcs"]) < MAX_ITEMS:
                result["rpcs"].append(row)
        result["services"].append({"name": service, "package": package,
                                   "methods": methods, "requestable": False})
    return result


def _js_type(value):
    parts = [part for part in str(value).split(".") if part not in {"proto", "$proto"}]
    return ".".join(parts) or None


def parse_grpc_web(data, *, source_url=None):
    """Parse generated gRPC-web MethodDescriptor declarations as metadata."""
    raw = _raw(data)
    if raw is None or b"\x00" in raw:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    clean = _strip_comments(text)
    if clean is None:
        return None
    result = _empty("grpc-web", source_url)
    result.update({"dialect": "grpc-web-generated", "services": [], "rpcs": []})
    services = {}
    for match in _GRPC_DESCRIPTOR.finditer(clean):
        if len(result["rpcs"]) >= MAX_ITEMS:
            break
        method_path = match.group(2)
        qualified_service, name = method_path[1:].split("/", 1)
        if "." in qualified_service:
            package, service = qualified_service.rsplit(".", 1)
        else:
            package, service = None, qualified_service
        mode = match.group(3)
        row = {
            "name": name,
            "path": method_path,
            "package": package,
            "service": service,
            "input": _js_type(match.group(4)),
            "output": _js_type(match.group(5)),
            "client_streaming": mode in {"CLIENT_STREAMING", "BIDI_STREAMING"},
            "server_streaming": mode in {"SERVER_STREAMING", "BIDI_STREAMING"},
            "requestable": False,
        }
        signature = (method_path, row["input"], row["output"])
        if not any((old["path"], old["input"], old["output"]) == signature for old in result["rpcs"]):
            result["rpcs"].append(row)
            services.setdefault((package, service), []).append(row)
    for (package, service), methods in list(services.items())[:MAX_ITEMS]:
        result["services"].append({"name": service, "package": package,
                                   "methods": methods, "requestable": False})
    return result if result["rpcs"] else None


def parse(data, *, path="", content_type="", base_url="", source_url=None):
    """Dispatch exact-linked descriptor bytes by suffix/type, then signature."""
    lower_path = str(path or source_url or "").lower().split("?", 1)[0]
    lower_type = str(content_type or "").lower()
    raw = _raw(data)
    if raw is None:
        return None
    if lower_path.endswith(".wsdl") or "wsdl" in lower_type:
        return parse_wsdl(raw, base_url=base_url, source_url=source_url or path)
    if lower_path.endswith(".proto") or "protobuf" in lower_type:
        return parse_proto(raw, source_url=source_url or path)
    if lower_path.endswith(("_grpc_web_pb.js", "grpc-web.js", "grpc_web.js")):
        return parse_grpc_web(raw, source_url=source_url or path)
    prefix = raw.lstrip()[:512]
    if prefix.startswith(b"<"):
        parsed = parse_wsdl(raw, base_url=base_url, source_url=source_url or path)
        if parsed is not None:
            return parsed
    if re.search(br"(?m)^\s*(?:syntax\s*=|package\s+|service\s+)", raw[:8192]):
        parsed = parse_proto(raw, source_url=source_url or path)
        if parsed is not None:
            return parsed
    if b"MethodDescriptor" in raw[:MAX_BYTES]:
        return parse_grpc_web(raw, source_url=source_url or path)
    return None


parse_service_descriptor = parse
