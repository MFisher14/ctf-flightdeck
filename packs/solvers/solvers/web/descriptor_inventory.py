#!/usr/bin/env python3
"""Bounded, metadata-only AsyncAPI and OpenRPC descriptor normalizer.

This module has no network client.  ``endpoint_inventory`` may hand it an
already-fetched, exact same-origin descriptor.  It never turns a channel,
server, JSON-RPC method, callback, or example into a request.

Supported dialects are AsyncAPI 2.x/3.x and OpenRPC 1.x in JSON, plus YAML
when PyYAML is available.  Only local JSON-pointer references are followed;
external references, cycles, oversized trees, and unsupported versions fail
closed or contribute no fields.
"""

from __future__ import annotations

import html
import importlib.util
import json
import re
import urllib.parse
from pathlib import Path

try:  # JSON remains available on installations without the optional package.
    import yaml as _yaml
except Exception:  # pragma: no cover
    _yaml = None


HERE = Path(__file__).resolve().parent


def _load(name, path):
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:  # pragma: no cover - an absent shared policy fails closed below
        return None


_security_json = _load("csctf_descriptor_security_json", HERE / "security_json.py")


MAX_DOCUMENT = 2 * 1024 * 1024
MAX_NODES = 20_000
MAX_DEPTH = 16
MAX_ALIASES = 64
MAX_REFS = 32
MAX_OPERATIONS = 128
MAX_CHANNELS = 128
MAX_METHODS = 128
MAX_SERVERS = 16
MAX_FIELDS = 64
MAX_VALUES = 8
MAX_LEADS = 4
MAX_TEXT = 512

TAG = re.compile(r"(?is)<(?:link|a)\b([^>]*)>")
ATTR = re.compile(r'''(?is)\b([a-z_:][-a-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))''')
PATH_TOKEN = re.compile(r'''(?ix)(?:https?://[^\s"'<>]+|/[a-z0-9_~.!$&()*+,;=:@%/?#-]+)''')
NAMED_DESCRIPTOR = re.compile(r"(?i)(?:asyncapi|openrpc)")


def _attrs(raw):
    out = {}
    for match in ATTR.finditer(str(raw or "")[:16_000]):
        value = next((v for v in match.groups()[1:] if v is not None), "")
        out[match.group(1).lower()] = html.unescape(value.strip())
    return out


def html_leads(base_url, at, text, safe_path):
    """Exact ``rel=service-desc`` links from ``link`` or ``a`` elements."""
    out = []
    for match in TAG.finditer(str(text or "")[:MAX_DOCUMENT]):
        attrs = _attrs(match.group(1))
        rel = {part for part in re.split(r"\s+", attrs.get("rel", "").lower()) if part}
        if "service-desc" not in rel:
            continue
        try:
            path = safe_path(base_url, attrs.get("href"), at)
        except Exception:
            path = None
        if path and path not in out:
            out.append(path)
        if len(out) >= MAX_LEADS:
            break
    return out


def text_leads(base_url, at, text, safe_path):
    """Exact AsyncAPI/OpenRPC paths named by target-local prompt or JS text.

    A generic ``.json`` string is never a lead.  The path itself must name the
    dialect, or appear in the same short statement as an AsyncAPI, OpenRPC, or
    service-description label.  ``safe_path`` owns the same-origin decision.
    """
    source = str(text or "")[:MAX_DOCUMENT]
    out = []
    for match in PATH_TOKEN.finditer(source):
        raw = html.unescape(match.group(0)).rstrip(".,;)]}")
        prefix = source[max(0, match.start() - 128):match.start()]
        # A label must lead directly into this path on the same statement;
        # a dialect word elsewhere in a page/script does not bless every JSON
        # string around it.
        labeled = re.search(
            r"(?is)(?:asyncapi|openrpc|service[-_ ]desc(?:riptor)?)[^/\r\n]{0,120}$", prefix
        )
        if not (NAMED_DESCRIPTOR.search(raw) or labeled):
            continue
        try:
            path = safe_path(base_url, raw, at)
        except Exception:
            path = None
        if path and path not in out:
            out.append(path)
        if len(out) >= MAX_LEADS:
            break
    return out


def _bounded_tree(value):
    nodes = 0
    active = set()

    def walk(item, depth):
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            return False
        if isinstance(item, (dict, list)):
            ident = id(item)
            if ident in active:
                return False
            active.add(ident)
            values = item.values() if isinstance(item, dict) else item
            ok = all(walk(child, depth + 1) for child in values)
            active.remove(ident)
            return ok
        return item is None or isinstance(item, (str, int, float, bool))

    return walk(value, 0)


def _page_bytes(page):
    if not isinstance(page, dict):
        return b""
    value = page.get("body")
    if value in (None, b""):
        value = page.get("text") or ""
    if isinstance(value, str):
        value = value.encode("utf-8", "replace")
    if not isinstance(value, (bytes, bytearray)):
        value = str(value or "").encode("utf-8", "replace")
    return bytes(value)


def _yaml_load_unique(text):
    """Load YAML only after rejecting parser-ambiguous mapping graphs.

    SafeLoader prevents object construction but still applies last-wins behavior
    to duplicate members and accepts merge keys. Descriptors are contracts, so
    reject exact/canonical collisions, merges, complex keys, recursive aliases,
    and over-limit graphs before constructing ordinary Python values.
    """
    if _yaml is None or _security_json is None:
        raise ValueError("YAML policy parser unavailable")
    root = _yaml.compose(text, Loader=_yaml.SafeLoader)
    if root is None:
        raise ValueError("empty YAML")
    count = [0]
    active = set()

    def inspect(node, depth):
        count[0] += 1
        if count[0] > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError("YAML structure limit")
        # SafeLoader constructs implicit integers/floats only after this node
        # walk.  On Python versions without the interpreter's decimal-digit
        # guard, a very long numeric scalar can otherwise consume substantial
        # CPU before the ordinary tree bounds get a chance to reject it.
        # Inspect the cheap source lexeme while it is still a ScalarNode.
        if (isinstance(node, _yaml.nodes.ScalarNode)
                and node.tag in ("tag:yaml.org,2002:int", "tag:yaml.org,2002:float")
                and len(str(node.value)) > _security_json.DEFAULT_MAX_NUMBER_CHARS):
            raise ValueError("YAML number character limit")
        ident = id(node)
        if ident in active:
            raise ValueError("recursive YAML alias")
        if isinstance(node, (_yaml.nodes.MappingNode, _yaml.nodes.SequenceNode)):
            active.add(ident)
            try:
                if isinstance(node, _yaml.nodes.MappingNode):
                    seen = set()
                    for key_node, value_node in node.value:
                        if not isinstance(key_node, _yaml.nodes.ScalarNode):
                            raise ValueError("complex YAML mapping key")
                        # Descriptor object members are strings.  SafeLoader
                        # otherwise constructs lexically different ``1`` and
                        # ``true`` as Python int/bool keys that compare equal,
                        # silently restoring last-wins semantics after this
                        # preflight duplicate check.
                        if key_node.tag != "tag:yaml.org,2002:str":
                            raise ValueError("non-string YAML mapping key")
                        key = str(key_node.value)
                        if key == "<<":
                            raise ValueError("YAML merge key")
                        canonical = _security_json.canonical_key(key)
                        if canonical in seen:
                            raise ValueError("duplicate or colliding YAML mapping key")
                        seen.add(canonical)
                        inspect(value_node, depth + 1)
                else:
                    for child in node.value:
                        inspect(child, depth + 1)
            finally:
                active.discard(ident)

    inspect(root, 0)
    return _yaml.safe_load(text)


def _load_page(page):
    raw = _page_bytes(page)
    if not raw or len(raw) > MAX_DOCUMENT:
        return None, None
    try:
        text = raw.decode("utf-8-sig", "strict")
    except UnicodeDecodeError:
        return None, None
    stripped = text.lstrip()
    doc, encoding = None, None
    try:
        if _security_json is None:
            return None, None
        doc = _security_json.loads(
            stripped, max_chars=MAX_DOCUMENT, max_members=MAX_NODES,
            max_nodes=MAX_NODES, max_depth=MAX_DEPTH,
        )
        encoding = "json"
    except Exception:
        # A malformed, duplicate-keyed, or canonically colliding JSON-looking
        # contract must not be reinterpreted with YAML's different semantics.
        if stripped[:1] in ("{", "["):
            return None, None
        if (_yaml is None or len(re.findall(r"(?m)(?:^|[\s\[{,])\*[A-Za-z0-9_.-]+", text)) > MAX_ALIASES
                or not re.search(r"(?m)^\s*(?:asyncapi|openrpc)\s*:", text[:8192])):
            return None, None
        try:
            doc, encoding = _yaml_load_unique(text), "yaml"
        except Exception:
            return None, None
    if not isinstance(doc, dict) or not _bounded_tree(doc):
        return None, None
    return doc, encoding


def _pointer(doc, ref):
    if not isinstance(ref, str) or not ref.startswith("#/") or len(ref) > 1024:
        return None
    cur = doc
    try:
        parts = ref[2:].split("/")
        if len(parts) > MAX_DEPTH:
            return None
        for raw in parts:
            key = urllib.parse.unquote(raw).replace("~1", "/").replace("~0", "~")
            if isinstance(cur, dict):
                cur = cur[key]
            elif isinstance(cur, list) and key.isdigit() and int(key) < len(cur):
                cur = cur[int(key)]
            else:
                return None
        return cur
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def _resolve(doc, value, *, seen=(), depth=0):
    if not isinstance(value, dict) or depth > MAX_DEPTH:
        return value if isinstance(value, dict) else {}
    ref = value.get("$ref")
    if not isinstance(ref, str):
        return value
    if not ref.startswith("#/") or ref in seen or len(seen) >= MAX_REFS:
        return {}
    target = _pointer(doc, ref)
    if not isinstance(target, dict):
        return {}
    base = _resolve(doc, target, seen=seen + (ref,), depth=depth + 1)
    if not isinstance(base, dict):
        return {}
    # Annotation/example siblings cannot make a metadata-only parser active;
    # retaining them is useful across dialect patch versions.
    out = dict(base)
    out.update({key: val for key, val in value.items() if key != "$ref"})
    return out


def _short(value, limit=MAX_TEXT):
    if not isinstance(value, (str, int, float, bool)):
        return None
    text = str(value).strip()
    if (not text or len(text.encode("utf-8", "replace")) > limit
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in text)):
        return None
    return text


def _values(schema, *containers):
    out = []
    for container in (schema,) + containers:
        if not isinstance(container, dict):
            continue
        candidates = []
        if isinstance(container.get("enum"), list):
            candidates.extend(container["enum"][:MAX_VALUES])
        for key in ("example", "default", "const"):
            if key in container:
                candidates.append(container[key])
        examples = container.get("examples")
        if isinstance(examples, list):
            candidates.extend(examples[:MAX_VALUES])
        elif isinstance(examples, dict):
            for example in list(examples.values())[:MAX_VALUES]:
                candidates.append(example.get("value") if isinstance(example, dict) else example)
        for candidate in candidates:
            value = _short(candidate, 160)
            if value is not None and value not in out:
                out.append(value)
            if len(out) >= MAX_VALUES:
                return out
    return out


def _fields(doc, schema):
    schema = _resolve(doc, schema)
    if not isinstance(schema, dict):
        return []
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return []
    required = {str(value) for value in (schema.get("required") or []) if isinstance(value, str)}
    out = []
    for name, raw in list(properties.items())[:MAX_FIELDS]:
        clean = _short(name, 100)
        field = _resolve(doc, raw)
        if clean is None or not isinstance(field, dict):
            continue
        out.append({"name": clean, "required": clean in required, "values": _values(field)})
    return out


def _security(value):
    out = []
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict):
            continue
        for name in item:
            clean = _short(name, 100)
            if clean and clean not in out:
                out.append(clean)
            if len(out) >= 16:
                return out
    return out


def _ref_name(value):
    if not isinstance(value, dict) or not isinstance(value.get("$ref"), str):
        return None
    ref = value["$ref"]
    if not ref.startswith("#/"):
        return None
    return _short(urllib.parse.unquote(ref.rsplit("/", 1)[-1]).replace("~1", "/").replace("~0", "~"), 160)


def _message_meta(doc, value):
    names, fields = [], []

    def one(item, depth=0):
        if depth > 4 or not isinstance(item, dict):
            return
        ref_name = _ref_name(item)
        resolved = _resolve(doc, item)
        name = ref_name or _short(resolved.get("name") or resolved.get("title"), 160)
        if name and name not in names:
            names.append(name)
        for branch in resolved.get("oneOf") if isinstance(resolved.get("oneOf"), list) else []:
            one(branch, depth + 1)
        for field in _fields(doc, resolved.get("payload")):
            if field not in fields and len(fields) < MAX_FIELDS:
                fields.append(field)

    one(value)
    return names[:16], fields[:MAX_FIELDS]


def _same_origin_server(base_url, raw, protocol=None):
    value = _short(raw, 512)
    row = {"protocol": _short(protocol, 40), "same_origin": False, "requestable": False}
    if value is None or "{" in value or "}" in value:
        row["templated"] = bool(value)
        return row
    candidate = value if "://" in value else ""
    try:
        parsed = urllib.parse.urlsplit(candidate)
        base = urllib.parse.urlsplit(base_url)
        if parsed.scheme.lower() not in ("http", "https", "ws", "wss") or not parsed.hostname:
            return row
        mapped = {"ws": "http", "wss": "https"}.get(parsed.scheme.lower(), parsed.scheme.lower())
        pport = parsed.port or (443 if mapped == "https" else 80)
        bport = base.port or (443 if base.scheme.lower() == "https" else 80)
        row["same_origin"] = mapped == base.scheme.lower() and parsed.hostname.lower() == base.hostname.lower() and pport == bport
        if row["same_origin"]:
            row["endpoint"] = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
    except (TypeError, ValueError):
        pass
    return row


def _async_servers(doc, base_url):
    out = []
    servers = doc.get("servers")
    for name, raw in list(servers.items())[:MAX_SERVERS] if isinstance(servers, dict) else []:
        server = _resolve(doc, raw)
        if not isinstance(server, dict):
            continue
        address = server.get("url")
        if address is None and server.get("host"):
            protocol = _short(server.get("protocol"), 40) or ""
            scheme = protocol if protocol in ("http", "https", "ws", "wss") else ""
            address = (scheme + "://" if scheme else "") + str(server.get("host")) + str(server.get("pathname") or "")
        row = _same_origin_server(base_url, address, server.get("protocol"))
        row["name"] = _short(name, 100)
        out.append(row)
    return out


def _asyncapi(doc, version, base_url):
    operations, channels = [], []
    major = int(version.split(".", 1)[0])
    raw_channels = doc.get("channels")
    channel_map = raw_channels if isinstance(raw_channels, dict) else {}
    for key, raw in list(channel_map.items())[:MAX_CHANNELS]:
        channel = _resolve(doc, raw)
        if not isinstance(channel, dict):
            continue
        address = _short(channel.get("address") if major >= 3 else key, 256) or _short(key, 256)
        if address and address not in channels:
            channels.append(address)
        if major >= 3:
            continue
        for action in ("publish", "subscribe"):
            operation = _resolve(doc, channel.get(action))
            if not isinstance(operation, dict) or not operation:
                continue
            names, fields = _message_meta(doc, operation.get("message"))
            operations.append({
                "surface": "asyncapi", "protocol": "asyncapi", "spec_version": "asyncapi-" + version,
                "method": "MESSAGE", "action": action, "path": "-", "channel": address or "-",
                # v2: the channel key is the channel address itself.
                "address_known": bool(address),
                "operation_id": _short(operation.get("operationId"), 160), "messages": names,
                "fields": fields, "params": [], "response_fields": [],
                "security": _security(operation.get("security")), "requestable": False,
            })
            if len(operations) >= MAX_OPERATIONS:
                break
        if len(operations) >= MAX_OPERATIONS:
            break

    if major >= 3:
        raw_operations = doc.get("operations")
        for key, raw in list(raw_operations.items())[:MAX_OPERATIONS] if isinstance(raw_operations, dict) else []:
            operation = _resolve(doc, raw)
            if not isinstance(operation, dict):
                continue
            channel_ref = operation.get("channel")
            channel_name = _ref_name(channel_ref)
            channel = _resolve(doc, channel_ref)
            address = _short(channel.get("address"), 256) if isinstance(channel, dict) else None
            messages, fields = [], []
            raw_messages = operation.get("messages")
            for message in raw_messages if isinstance(raw_messages, list) else []:
                names, found_fields = _message_meta(doc, message)
                for name in names:
                    if name not in messages:
                        messages.append(name)
                for field in found_fields:
                    if field not in fields and len(fields) < MAX_FIELDS:
                        fields.append(field)
            if not messages and isinstance(channel, dict):
                for name, message in list((channel.get("messages") or {}).items())[:16] \
                        if isinstance(channel.get("messages"), dict) else []:
                    found_names, found_fields = _message_meta(doc, message)
                    candidate = _short(name, 160)
                    for value in ([candidate] if candidate else []) + found_names:
                        if value not in messages:
                            messages.append(value)
                    for field in found_fields:
                        if field not in fields and len(fields) < MAX_FIELDS:
                            fields.append(field)
            operations.append({
                "surface": "asyncapi", "protocol": "asyncapi", "spec_version": "asyncapi-" + version,
                "method": "MESSAGE", "action": _short(operation.get("action"), 40) or "-", "path": "-",
                "channel": address or channel_name or "-",
                # v3: a null or absent address is unknown/dynamic; ``channel`` then holds only the
                # channel id, which is a name, not a route.
                "address_known": bool(address),
                "operation_id": _short(operation.get("operationId") or key, 160),
                "messages": messages[:16], "fields": fields[:MAX_FIELDS], "params": [], "response_fields": [],
                "security": _security(operation.get("security")), "requestable": False,
            })
            if len(operations) >= MAX_OPERATIONS:
                break
    return operations[:MAX_OPERATIONS], channels[:MAX_CHANNELS], _async_servers(doc, base_url)


def _openrpc_servers(doc, base_url):
    out = []
    for raw in list(doc.get("servers") or [])[:MAX_SERVERS] if isinstance(doc.get("servers"), list) else []:
        server = _resolve(doc, raw)
        if not isinstance(server, dict):
            continue
        row = _same_origin_server(base_url, server.get("url"))
        row["name"] = _short(server.get("name"), 100)
        out.append(row)
    return out


def _openrpc(doc, version, base_url):
    operations, methods = [], []
    for raw in list(doc.get("methods") or [])[:MAX_METHODS] if isinstance(doc.get("methods"), list) else []:
        method = _resolve(doc, raw)
        if not isinstance(method, dict):
            continue
        name = _short(method.get("name"), 200)
        if not name:
            continue
        params = []
        for raw_param in list(method.get("params") or [])[:MAX_FIELDS] if isinstance(method.get("params"), list) else []:
            param = _resolve(doc, raw_param)
            if not isinstance(param, dict):
                continue
            pname = _short(param.get("name"), 100)
            schema = _resolve(doc, param.get("schema"))
            if pname:
                params.append({"name": pname, "required": bool(param.get("required")),
                               "values": _values(schema, param)})
        result = _resolve(doc, method.get("result"))
        result_fields = _fields(doc, result.get("schema")) if isinstance(result, dict) else []
        tags = []
        for tag in list(method.get("tags") or [])[:16] if isinstance(method.get("tags"), list) else []:
            value = _short(tag.get("name") if isinstance(tag, dict) else tag, 100)
            if value and value not in tags:
                tags.append(value)
        operations.append({
            "surface": "openrpc", "protocol": "json-rpc", "spec_version": "openrpc-" + version,
            "method": "RPC", "action": "call", "path": "-", "name": name,
            "operation_id": name, "params": params, "fields": [], "response_fields": result_fields,
            "tags": tags, "security": [], "requestable": False,
        })
        methods.append(name)
        if len(operations) >= MAX_OPERATIONS:
            break
    return operations, methods, _openrpc_servers(doc, base_url)


def parse_document(doc, *, base_url, path="<descriptor>", encoding="object"):
    """Normalize one already-decoded mapping.  No I/O and no proof return."""
    if not isinstance(doc, dict) or not _bounded_tree(doc):
        return None
    async_version = _short(doc.get("asyncapi"), 40)
    rpc_version = _short(doc.get("openrpc"), 40)
    if bool(async_version) == bool(rpc_version):
        return None
    if async_version:
        if re.fullmatch(r"(?:2|3)\.\d+(?:\.\d+)?", async_version) is None:
            return None
        operations, names, servers = _asyncapi(doc, async_version, base_url)
        kind, cls, version = "asyncapi", "asyncapi", async_version
        count_key, named = "channels", names
    else:
        if re.fullmatch(r"1\.\d+(?:\.\d+)?", rpc_version or "") is None:
            return None
        operations, names, servers = _openrpc(doc, rpc_version, base_url)
        kind, cls, version = "openrpc", "json_rpc", rpc_version
        count_key, named = "methods", names
    evidence = f"{kind}_descriptor"
    finding = {"class": cls, "confirmed": True, "evidence": evidence, "path": path,
               "version": version, "operations": len(operations), count_key: len(named),
               "protocols": sorted({row.get("protocol") for row in servers if row.get("protocol")})[:8]}
    return {"kind": kind, "class": cls, "version": version, "path": path, "encoding": encoding,
            "operations": operations, count_key: named, "servers": servers, "finding": finding,
            "requestable": False, "flag": None}


def parse_page(base_url, path, page):
    """Parse one successful descriptor response supplied by endpoint inventory."""
    try:
        status = int(page.get("status"))
    except (AttributeError, TypeError, ValueError):
        return None
    if status != 200:
        return None
    doc, encoding = _load_page(page)
    return parse_document(doc, base_url=base_url, path=path, encoding=encoding) if doc is not None else None
