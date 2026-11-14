#!/usr/bin/env python3
"""netplay -- a generic interactive nc/REPL harness for the "quiz/compute-over-a-socket" family.

2025 had ~12 of these (programming Interview-1..6, linux Interview-1..4, misc Romeo-and-Julia) and
2024 the "Programming" lane (Multiply 1/2, Math Master, Geography Master, Pwntools): a service sends
a prompt that poses a small computation, you send the answer, repeat until it hands you the flag.
They are high-solve FAST POINTS, often with a rotating 5-min flag, and CSCTF scoring DECAYS as teams
solve, so driving them to the flag in the first minutes is worth real points.

Transport is nc by default, or SSH (`--ssh user`) when the login shell itself is the REPL. The 2024
Programming handlers (multiply_char, math_csv, country_capital with a static offline capital table,
and pwntools_quiz) answer entirely offline -- no network lookups.

This file is the driver plus a library of pure `prompt -> answer` handlers for the recurring 2025
patterns. It does the networking (pwntools `remote`, or a stdlib-socket fallback) and the loop; the
handler just answers one prompt. Nothing here guesses or sweeps a flag: the service states the task,
the handler computes the single correct answer, and the flag is read back out of the stream.

  .venv/bin/python tools/netplay.py <host> <port> [--handler NAME] [--auto]
  .venv/bin/python tools/netplay.py <host> <port> --script FILE
  .venv/bin/python tools/netplay.py <host> <port> --ssh user [--handler NAME]
  .venv/bin/python tools/netplay.py --list                 # the handler library

--handler NAME   drive the loop with one named handler from the library (below).
--auto           drive the loop with the auto-dispatcher, which reads each prompt and picks the
                 handler that fits it. Good default for an unknown service.
--script FILE    run a scripted send/expect sequence (JSON, see --help-script) instead of the loop.
--delim BYTES    the prompt delimiter the loop reads up to (default: auto -- a trailing ':', '?',
                 '>', or a blank line). Repeatable framing lives in the service, not here.
--timeout S      per-recv timeout (default 10). The loop never sleeps; it blocks on the socket.
--max-rounds N   stop after N prompts without a flag (default 200) -- a guard, not a sweep.

CSCTF rules bind this tool: point it only at the squad's ONE assigned target, never scan or flood,
and never submit a flag from here (it prints the flag; submission goes through ctf.submit's guard).
The handlers parse their parameters (prefix, key, salt, tag, secret) OUT OF the prompt text, so one
handler covers every instance of its pattern without editing.
"""
from __future__ import annotations

import argparse
import ast
import base64
import binascii
import hashlib
import hmac
import json
import re
import socket
import sys
import zlib
from pathlib import Path
from typing import Callable, List, Optional, Tuple

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt, scope
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import flagfmt, scope

FLAG_RE = flagfmt.BYTES


# --------------------------------------------------------------------------------------------------
# Connection abstraction: pwntools remote() when available, else a stdlib socket. Same tiny surface.
# --------------------------------------------------------------------------------------------------

class Conn:
    """A minimal interface over either a pwntools tube or a raw socket.

    The driver frames prompts two ways:
      * recv_prompt(timeout, quiet) -- block up to `timeout` for the first byte, then keep reading
        until the socket stays silent for `quiet` seconds (or an explicit delimiter is seen). This is
        how a quiz service frames: a block of text, then it waits for us. Robust to internal ':'.
      * recv_until(delims, timeout) -- read up to and including the first delimiter (for scripts).
    """

    def recv_prompt(self, timeout: float, quiet: float,
                    delims: Optional[List[bytes]] = None) -> bytes:  # pragma: no cover - iface
        raise NotImplementedError

    def recv_until(self, delims: List[bytes], timeout: float) -> bytes:  # pragma: no cover - iface
        raise NotImplementedError

    def recv_some(self, timeout: float) -> bytes:  # pragma: no cover - iface
        raise NotImplementedError

    def send(self, data: bytes) -> None:  # pragma: no cover - iface
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - iface
        raise NotImplementedError


def _first_delim_end(buf: bytes, delims: List[bytes]) -> Optional[int]:
    """Index just past the earliest delimiter occurrence in buf, or None."""
    best = None
    for d in delims:
        i = buf.find(d)
        if i != -1:
            end = i + len(d)
            if best is None or end < best:
                best = end
    return best


class PwnConn(Conn):
    def __init__(self, tube):
        self._t = tube

    def recv_prompt(self, timeout: float, quiet: float,
                    delims: Optional[List[bytes]] = None) -> bytes:
        # Block for the first byte, then drain until the tube is quiet for `quiet`.
        try:
            first = self._t.recv(timeout=timeout)
        except EOFError:
            return b""
        if not first:
            return b""
        out = first
        while True:
            if delims and _first_delim_end(out, delims) is not None:
                break
            try:
                more = self._t.recv(timeout=quiet)
            except EOFError:
                break
            if not more:
                break
            out += more
        return out

    def recv_until(self, delims: List[bytes], timeout: float) -> bytes:
        try:
            return self._t.recvuntil(tuple(delims), timeout=timeout, drop=False)
        except EOFError:
            try:
                return self._t.recvrepeat(0.1)
            except EOFError:
                return b""

    def recv_some(self, timeout: float) -> bytes:
        try:
            return self._t.recv(timeout=timeout)
        except EOFError:
            return b""

    def send(self, data: bytes) -> None:
        self._t.send(data)

    def close(self) -> None:
        try:
            self._t.close()
        except Exception:
            pass


class SocketConn(Conn):
    """Stdlib-socket fallback for when pwntools is unavailable (or deliberately bypassed)."""

    def __init__(self, sock: socket.socket):
        self._s = sock
        self._buf = b""

    def recv_prompt(self, timeout: float, quiet: float,
                    delims: Optional[List[bytes]] = None) -> bytes:
        # Drain any buffered bytes first, then block up to `timeout` for the first chunk, then read
        # until a `quiet`-second silence (or a delimiter). No sleeps; purely blocked on the socket.
        out = self._buf
        self._buf = b""
        first_wait = timeout if not out else quiet
        self._s.settimeout(first_wait)
        if not out:
            try:
                chunk = self._s.recv(65536)
            except (socket.timeout, TimeoutError):
                return b""
            if not chunk:
                return b""
            out += chunk
        self._s.settimeout(quiet)
        while True:
            if delims and _first_delim_end(out, delims) is not None:
                break
            try:
                chunk = self._s.recv(65536)
            except (socket.timeout, TimeoutError):
                break
            if not chunk:  # peer closed
                break
            out += chunk
        return out

    def recv_until(self, delims: List[bytes], timeout: float) -> bytes:
        self._s.settimeout(timeout)
        while True:
            hit = _first_delim_end(self._buf, delims)
            if hit is not None:
                out, self._buf = self._buf[:hit], self._buf[hit:]
                return out
            try:
                chunk = self._s.recv(65536)
            except (socket.timeout, TimeoutError):
                out, self._buf = self._buf, b""
                return out
            if not chunk:  # peer closed
                out, self._buf = self._buf, b""
                return out
            self._buf += chunk

    def recv_some(self, timeout: float) -> bytes:
        if self._buf:
            out, self._buf = self._buf, b""
            return out
        self._s.settimeout(timeout)
        try:
            return self._s.recv(65536)
        except (socket.timeout, TimeoutError):
            return b""

    def send(self, data: bytes) -> None:
        self._s.sendall(data)

    def close(self) -> None:
        try:
            self._s.close()
        except Exception:
            pass


def connect(host: str, port: int, ssh_user: Optional[str] = None, timeout: float = 10.0,
            prefer_pwntools: bool = True, ssh_pass: Optional[str] = None,
            ssh_keyfile: Optional[str] = None) -> Conn:
    """Open a connection to the assigned target. pwntools remote()/ssh when available, else socket.

    SSH transport: when ssh_user is set the loop runs over an SSH channel instead of a bare TCP port.
    Many Linux/Programming challenges hand you `ssh user@host -p PORT` whose login shell *is* the REPL
    (the quiz starts on connect). We open the session and return its interactive shell channel, which
    behaves exactly like the nc tube from the driver's point of view -- so every handler works
    unchanged over SSH. Auth is by key (ssh_keyfile) or password (ssh_pass); the default port is 22
    unless the challenge states another. Requires pwntools (paramiko under the hood).

    Scope (R-13): the host and port pass ctf.scope.check_host first, so a host outside the event
    profile's rules.live_service_scope, or the event platform, raises ctf.scope.OutOfScope before
    any transport is imported, any name is resolved or any socket is opened.
    """
    if ssh_user:
        port = port or 22
    scope.check_host(host, port, what=f"netplay target {host}:{port}")
    if ssh_user:
        from pwn import ssh  # pwntools required for ssh
        session = ssh(user=ssh_user, host=host, port=port, timeout=timeout,
                      password=ssh_pass, keyfile=ssh_keyfile)
        return PwnConn(session.shell())  # interactive login-shell channel == the REPL
    if prefer_pwntools:
        try:
            from pwn import remote
            return PwnConn(remote(host, port, timeout=timeout))
        except ImportError:
            pass
    s = socket.create_connection((host, port), timeout=timeout)
    return SocketConn(s)


# --------------------------------------------------------------------------------------------------
# Static offline data tables for the Programming-quiz handlers (no network, deterministic).
# --------------------------------------------------------------------------------------------------

# Country -> capital. Keys are lowercased; common alternate names alias to the same capital so the
# matcher finds e.g. "usa"/"united states", "uk"/"united kingdom", "south korea"/"korea, south".
CAPITALS: dict[str, str] = {
    "afghanistan": "Kabul", "albania": "Tirana", "algeria": "Algiers", "andorra": "Andorra la Vella",
    "angola": "Luanda", "antigua and barbuda": "Saint John's", "argentina": "Buenos Aires",
    "armenia": "Yerevan", "australia": "Canberra", "austria": "Vienna", "azerbaijan": "Baku",
    "bahamas": "Nassau", "bahrain": "Manama", "bangladesh": "Dhaka", "barbados": "Bridgetown",
    "belarus": "Minsk", "belgium": "Brussels", "belize": "Belmopan", "benin": "Porto-Novo",
    "bhutan": "Thimphu", "bolivia": "Sucre", "bosnia and herzegovina": "Sarajevo", "bosnia": "Sarajevo",
    "botswana": "Gaborone", "brazil": "Brasilia", "brunei": "Bandar Seri Begawan",
    "bulgaria": "Sofia", "burkina faso": "Ouagadougou", "burundi": "Gitega", "cabo verde": "Praia",
    "cape verde": "Praia", "cambodia": "Phnom Penh", "cameroon": "Yaounde", "canada": "Ottawa",
    "central african republic": "Bangui", "chad": "N'Djamena", "chile": "Santiago", "china": "Beijing",
    "colombia": "Bogota", "comoros": "Moroni", "congo": "Brazzaville",
    "democratic republic of the congo": "Kinshasa", "dr congo": "Kinshasa", "costa rica": "San Jose",
    "croatia": "Zagreb", "cuba": "Havana", "cyprus": "Nicosia", "czechia": "Prague",
    "czech republic": "Prague", "denmark": "Copenhagen", "djibouti": "Djibouti", "dominica": "Roseau",
    "dominican republic": "Santo Domingo", "ecuador": "Quito", "egypt": "Cairo", "el salvador": "San Salvador",
    "equatorial guinea": "Malabo", "eritrea": "Asmara", "estonia": "Tallinn", "eswatini": "Mbabane",
    "swaziland": "Mbabane", "ethiopia": "Addis Ababa", "fiji": "Suva", "finland": "Helsinki",
    "france": "Paris", "gabon": "Libreville", "gambia": "Banjul", "georgia": "Tbilisi",
    "germany": "Berlin", "ghana": "Accra", "greece": "Athens", "grenada": "Saint George's",
    "guatemala": "Guatemala City", "guinea": "Conakry", "guinea-bissau": "Bissau", "guyana": "Georgetown",
    "haiti": "Port-au-Prince", "honduras": "Tegucigalpa", "hungary": "Budapest", "iceland": "Reykjavik",
    "india": "New Delhi", "indonesia": "Jakarta", "iran": "Tehran", "iraq": "Baghdad",
    "ireland": "Dublin", "israel": "Jerusalem", "italy": "Rome", "ivory coast": "Yamoussoukro",
    "cote d'ivoire": "Yamoussoukro", "jamaica": "Kingston", "japan": "Tokyo", "jordan": "Amman",
    "kazakhstan": "Astana", "kenya": "Nairobi", "kiribati": "Tarawa", "kosovo": "Pristina",
    "kuwait": "Kuwait City", "kyrgyzstan": "Bishkek", "laos": "Vientiane", "latvia": "Riga",
    "lebanon": "Beirut", "lesotho": "Maseru", "liberia": "Monrovia", "libya": "Tripoli",
    "liechtenstein": "Vaduz", "lithuania": "Vilnius", "luxembourg": "Luxembourg",
    "madagascar": "Antananarivo", "malawi": "Lilongwe", "malaysia": "Kuala Lumpur", "maldives": "Male",
    "mali": "Bamako", "malta": "Valletta", "marshall islands": "Majuro", "mauritania": "Nouakchott",
    "mauritius": "Port Louis", "mexico": "Mexico City", "micronesia": "Palikir", "moldova": "Chisinau",
    "monaco": "Monaco", "mongolia": "Ulaanbaatar", "montenegro": "Podgorica", "morocco": "Rabat",
    "mozambique": "Maputo", "myanmar": "Naypyidaw", "burma": "Naypyidaw", "namibia": "Windhoek",
    "nauru": "Yaren", "nepal": "Kathmandu", "netherlands": "Amsterdam", "new zealand": "Wellington",
    "nicaragua": "Managua", "niger": "Niamey", "nigeria": "Abuja", "north korea": "Pyongyang",
    "north macedonia": "Skopje", "macedonia": "Skopje", "norway": "Oslo", "oman": "Muscat",
    "pakistan": "Islamabad", "palau": "Ngerulmud", "palestine": "Ramallah", "panama": "Panama City",
    "papua new guinea": "Port Moresby", "paraguay": "Asuncion", "peru": "Lima", "philippines": "Manila",
    "poland": "Warsaw", "portugal": "Lisbon", "qatar": "Doha", "romania": "Bucharest",
    "russia": "Moscow", "rwanda": "Kigali", "saint kitts and nevis": "Basseterre",
    "saint lucia": "Castries", "saint vincent and the grenadines": "Kingstown", "samoa": "Apia",
    "san marino": "San Marino", "sao tome and principe": "Sao Tome", "saudi arabia": "Riyadh",
    "senegal": "Dakar", "serbia": "Belgrade", "seychelles": "Victoria", "sierra leone": "Freetown",
    "singapore": "Singapore", "slovakia": "Bratislava", "slovenia": "Ljubljana",
    "solomon islands": "Honiara", "somalia": "Mogadishu", "south africa": "Pretoria",
    "south korea": "Seoul", "korea": "Seoul", "south sudan": "Juba", "spain": "Madrid",
    "sri lanka": "Sri Jayawardenepura Kotte", "sudan": "Khartoum", "suriname": "Paramaribo",
    "sweden": "Stockholm", "switzerland": "Bern", "syria": "Damascus", "taiwan": "Taipei",
    "tajikistan": "Dushanbe", "tanzania": "Dodoma", "thailand": "Bangkok", "timor-leste": "Dili",
    "east timor": "Dili", "togo": "Lome", "tonga": "Nuku'alofa", "trinidad and tobago": "Port of Spain",
    "tunisia": "Tunis", "turkey": "Ankara", "turkmenistan": "Ashgabat", "tuvalu": "Funafuti",
    "uganda": "Kampala", "ukraine": "Kyiv", "united arab emirates": "Abu Dhabi", "uae": "Abu Dhabi",
    "united kingdom": "London", "uk": "London", "great britain": "London", "england": "London",
    "united states": "Washington, D.C.", "united states of america": "Washington, D.C.",
    "usa": "Washington, D.C.", "uruguay": "Montevideo", "uzbekistan": "Tashkent", "vanuatu": "Port Vila",
    "vatican city": "Vatican City", "venezuela": "Caracas", "vietnam": "Hanoi", "yemen": "Sana'a",
    "zambia": "Lusaka", "zimbabwe": "Harare",
}

# pwntools-API Q&A: ordered (regex, answer), most-specific first. The answer is the exact API token
# the quiz expects. Kept to the surface the 2024 Pwntools quiz drilled (connect, recv/send, logging).
PWNTOOLS_QA: List[Tuple[str, str]] = [
    (r"log.?level|verbos|logging level|quiet.*output|set.*log", "context.log_level"),
    (r"all (?:remaining|the) (?:data|bytes)|until (?:the )?(?:connection|socket) (?:closes|is closed)|"
     r"receive everything", "recvall"),
    (r"receive.*until|read.*until|up to (?:a|the) (?:given |specific )?(?:delimiter|string|pattern)",
     "recvuntil"),
    (r"(?:receive|read).*(?:one )?line|a single line|newline[- ]terminated", "recvline"),
    (r"exactly (\d+|n|some number of) bytes|a fixed number of bytes", "recv"),
    (r"receive|read (?:some )?(?:data|bytes)", "recv"),
    (r"send.*(?:with|append|adding|followed by|plus|then).*(?:newline|line ?feed|\\n)|send a line|"
     r"send.*line[- ]terminated", "sendline"),
    (r"send (?:raw )?(?:data|bytes)(?! ?line)", "send"),
    (r"interactive|drop (?:me |you )?into|talk to (?:the )?(?:shell|process) (?:by hand|manually)",
     "interactive"),
    (r"connect.*(?:remote|host(?:[: ]|/)port|over (?:the )?network|tcp)|open.*remote|"
     r"remote (?:host|server|target)", "remote"),
    (r"(?:start|launch|run|spawn).*local.*(?:binary|process|program)|run.*locally", "process"),
    (r"load.*elf|parse.*elf|elf (?:object|header)|open.*binary.*symbols", "ELF"),
    (r"de.?bruijn|cyclic pattern|unique (?:pattern|sequence)", "cyclic"),
    (r"find.*offset.*cyclic|locate.*cyclic|cyclic.*find", "cyclic_find"),
    (r"pack.*(?:64|eight bytes)|64-bit little", "p64"),
    (r"pack.*(?:32|four bytes)|32-bit little", "p32"),
    (r"unpack.*64", "u64"),
    (r"unpack.*32", "u32"),
]


# --------------------------------------------------------------------------------------------------
# Handler library: each a pure prompt(str) -> answer(str), parsing its parameters out of the prompt.
# --------------------------------------------------------------------------------------------------

def _grab(pattern: str, text: str, group: int = 1, flags: int = re.I) -> Optional[str]:
    m = re.search(pattern, text, flags)
    return m.group(group) if m else None


def clf_bytes_sum(prompt: str) -> str:
    """Sum the BYTES field of CLF log lines with METHOD=GET, PATH startswith a stated prefix, STATUS 200.

    Common Log Format:  host ident authuser [date] "METHOD PATH PROTO" STATUS BYTES
    The prefix is read from the prompt (e.g. "paths starting with /api"). Missing bytes ('-') count 0.
    """
    # Capture the path after the keyword WITHOUT swallowing the slash-gap or trailing punctuation:
    # skip non-slash chars up to the first '/', then take the path run (stops at whitespace/comma/;).
    prefix = _grab(r"(?:prefix|start(?:s|ing)?\s*with|begin\w*\s*with)[^/\n]*(/[^\s,;]*)", prompt)
    if prefix is None:
        prefix = _grab(r"(/[\w./~-]+)", prompt) or "/"
    # Strip sentence punctuation the capture may have picked up (e.g. "/api," or "/api/v1.").
    prefix = prefix.rstrip(".,;:!?)'\"]}") or "/"
    want_status = _grab(r"status\s*(?:code\s*)?(?:=|==|is|of)?\s*(\d{3})", prompt) or "200"
    want_method = (_grab(r"method\s*(?:=|==|is|of)?\s*([A-Z]+)", prompt) or "GET").upper()
    pfx_seg = prefix.rstrip("/")
    line_re = re.compile(
        r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+[^"]*"\s+(?P<status>\d{3})\s+(?P<bytes>-|\d+)')
    total = 0
    for m in line_re.finditer(prompt):
        if m.group("method").upper() != want_method:
            continue
        path = m.group("path")
        # Segment-boundary prefix: match the prefix itself or anything under it, but not a path that
        # merely shares the leading string (e.g. prefix /api must not match /apidocs).
        if not (path == prefix or path == pfx_seg or path.startswith(pfx_seg + "/")):
            continue
        if m.group("status") != want_status:
            continue
        b = m.group("bytes")
        total += 0 if b == "-" else int(b)
    return str(total)


def xor_hex(prompt: str) -> str:
    """XOR all dash/space/comma-separated hex bytes in the prompt -> a 2-hex-digit result (lowercase)."""
    # Pull the token list after a ':' if present, else the whole prompt; keep only hex-byte tokens.
    tail = prompt.split(":", 1)[1] if ":" in prompt else prompt
    toks = re.findall(r"\b[0-9a-fA-F]{2}\b", tail)
    acc = 0
    for t in toks:
        acc ^= int(t, 16)
    return f"{acc:02x}"


def b64_sort_concat(prompt: str) -> str:
    """Base64 fragments each carrying an index; sort by index, decode, concatenate -> text.

    Accepts "<index>:<b64>" or "<index> <b64>" or "[<index>] <b64>" per line.
    """
    frags: List[Tuple[int, str]] = []
    for line in prompt.splitlines():
        m = re.search(r"(?:^|\b)\[?(\d+)\]?\s*[:=)\]]?\s*([A-Za-z0-9+/=]{4,})\s*$", line)
        if m:
            frags.append((int(m.group(1)), m.group(2)))
    if not frags:
        # fallback: pairs anywhere in the text
        for m in re.finditer(r"(\d+)\s*[:=]\s*([A-Za-z0-9+/=]{4,})", prompt):
            frags.append((int(m.group(1)), m.group(2)))
    frags.sort(key=lambda p: p[0])
    out = b"".join(base64.b64decode(_pad64(f)) for _, f in frags)
    return out.decode("utf-8", "replace")


def tlv_sort_concat(prompt: str) -> str:
    """Parse type/len(BE)/value TLV records; for a stated tag, sort fragments by index and concat.

    The prompt carries a hex TLV blob and names the tag to collect (e.g. "collect tag 0x01").
    Record layout: 1-byte type, 2-byte big-endian length, then that many value bytes. The first byte
    of each value is a fragment index; the rest is the fragment payload.
    """
    want = _grab(r"tag\s*(?:=|==|is|of)?\s*(?:0x)?([0-9a-fA-F]{1,2})", prompt)
    want_tag = int(want, 16) if want else 1
    blob_hex = _grab(r"\b((?:[0-9a-fA-F]{2}){6,})\b", prompt)
    if not blob_hex:
        return ""
    data = bytes.fromhex(blob_hex)
    frags: List[Tuple[int, bytes]] = []
    i = 0
    n = len(data)
    while i + 3 <= n:
        t = data[i]
        ln = int.from_bytes(data[i + 1:i + 3], "big")
        i += 3
        val = data[i:i + ln]
        i += ln
        if len(val) < 1:
            continue
        if t == want_tag:
            frags.append((val[0], val[1:]))
    frags.sort(key=lambda p: p[0])
    return b"".join(v for _, v in frags).decode("utf-8", "replace")


def hmac_sha256_hex(prompt: str) -> str:
    """HMAC-SHA256(key, token || salt) as lowercase hex. key/token/salt parsed from the prompt."""
    key = _grab(r"key\s*(?:==|=|:|\bis\b)\s*['\"]?([^\s'\"]+)", prompt)
    token = _grab(r"token\s*(?:==|=|:|\bis\b)\s*['\"]?([^\s'\"]+)", prompt)
    salt = _grab(r"salt\s*(?:==|=|:|\bis\b)\s*['\"]?([^\s'\"]+)", prompt)
    if key is None or token is None:
        raise ValueError("hmac_sha256_hex: key/token not found in prompt")
    msg = (token + (salt or "")).encode()
    return hmac.new(key.encode(), msg, hashlib.sha256).hexdigest()


def hs256_jwt(prompt: str) -> str:
    """Manual HS256 JWT: b64url(header).b64url(payload).b64url(HMAC-SHA256(secret, h+'.'+p)), no '='.

    header/payload are JSON objects quoted in the prompt; secret is parsed from the prompt. If no
    header is stated, the standard {"alg":"HS256","typ":"JWT"} is used.
    """
    secret = _grab(r"secret\s*(?:==|=|:|\bis\b)\s*['\"]?([^\s'\"]+)", prompt)
    if secret is None:
        raise ValueError("hs256_jwt: secret not found in prompt")
    payload = _grab_json(prompt, "payload")
    if payload is None:
        payload = _grab_json_any(prompt)
    if payload is None:
        raise ValueError("hs256_jwt: payload JSON not found in prompt")
    header = _grab_json(prompt, "header") or '{"alg":"HS256","typ":"JWT"}'
    h = _b64url(_canon_json(header))
    p = _b64url(_canon_json(payload))
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def repl_shell_escape(prompt: str) -> List[str]:
    """For a language REPL over nc (e.g. Julia): the lines that escape to a shell and read the flag.

    Returns a list of lines to send in order. The escape line is read from the prompt if the service
    states one (e.g. "use run(`/bin/sh`)"); otherwise the Julia default is used. This is a scripted
    send sequence, not a single-answer handler -- the driver sends each line and watches for the flag.
    """
    esc = _grab(r"(run\(`[^`]+`\))", prompt, flags=0)
    lines = []
    if esc:
        lines.append(esc)
    else:
        lines.append("run(`/bin/sh`)")
    lines.append("cat /flag.txt")
    return lines


# --------------------------------------------------------------------------------------------------
# 2024 "Programming" quiz archetypes (Multiply, Math Master, Geography Master, Pwntools).
# Each is a pure prompt -> answer, parsing the task out of the prompt. All deterministic, no network.
# --------------------------------------------------------------------------------------------------

def multiply_char(prompt: str) -> str:
    """Repeat a single character N times (2024 Multiply 1/2).

    The service names a character and a count, e.g. "repeat 'A' 317 times", "give me x 250 times",
    or "print the character '!' 400 times". Multiply 2 uses digits/punctuation too. We pull the
    quoted/stated char and the integer out of the prompt and return char*N -- the one exact answer.
    """
    n = _grab(r"(\d{1,6})\s*times", prompt)
    if n is None:
        n = _grab(r"\b(\d{1,6})\b", prompt)
    if n is None:
        raise ValueError("multiply_char: repeat count not found in prompt")
    count = int(n)
    # The character: prefer an explicitly quoted one, else the token after 'character'/'char'/'letter'.
    ch = _grab(r"(?:character|char|letter|symbol)\s*[:=]?\s*['\"`](.)['\"`]", prompt)
    if ch is None:
        ch = _grab(r"['\"`](.)['\"`]", prompt)
    if ch is None:
        ch = _grab(r"(?:character|char|letter|symbol)\s*[:=]?\s*(\S)", prompt)
    if ch is None:
        raise ValueError("multiply_char: character to repeat not found in prompt")
    return ch * count


def math_csv(prompt: str) -> str:
    """Reduce a comma/space-separated list of numbers by a stated operation (2024 Math Master).

    The prompt states an operation word (sum/add, subtract/difference, multiply/product, divide,
    max/min) and a CSV/space list of integers (occasionally floats). We parse both and return the
    single result. Answers must land under 1s -- this is pure arithmetic, so it does.
    """
    low = prompt.lower()
    # Collect the numbers from the data portion. Prefer a comma-separated run; else all numbers after
    # the first ':' (so the operation words in the question text aren't mistaken for data).
    data = prompt
    m = re.search(r"[:=]\s*([-\d.,\s]+)$", prompt.strip())
    if m:
        data = m.group(1)
    nums_raw = re.findall(r"-?\d+(?:\.\d+)?", data)
    if not nums_raw:
        nums_raw = re.findall(r"-?\d+(?:\.\d+)?", prompt)
    nums = [float(x) if "." in x else int(x) for x in nums_raw]
    if not nums:
        raise ValueError("math_csv: no numbers found in prompt")

    def _fmt(v):
        if isinstance(v, float) and v.is_integer():
            return str(int(v))
        return str(v)

    if re.search(r"\b(sum|add|addition|total|plus)\b", low):
        return _fmt(sum(nums))
    if re.search(r"\b(product|multiply|multipl\w*|times)\b", low):
        acc = 1
        for v in nums:
            acc *= v
        return _fmt(acc)
    if re.search(r"\b(subtract|difference|minus|substract)\b", low):
        acc = nums[0]
        for v in nums[1:]:
            acc -= v
        return _fmt(acc)
    if re.search(r"\b(divide|division|quotient)\b", low):
        acc = nums[0]
        for v in nums[1:]:
            acc /= v
        return _fmt(acc)
    if re.search(r"\b(max|maximum|largest|biggest|highest)\b", low):
        return _fmt(max(nums))
    if re.search(r"\b(min|minimum|smallest|lowest)\b", low):
        return _fmt(min(nums))
    if re.search(r"\b(average|mean)\b", low):
        return _fmt(sum(nums) / len(nums))
    # Default to the most common Math Master operation: a sum.
    return _fmt(sum(nums))


def country_capital(prompt: str) -> str:
    """Return the capital city for a country named in the prompt (2024 Geography Master).

    Uses a static offline country->capital table (no network). The country is matched as the longest
    table key that appears in the prompt, so multi-word names ("United States", "South Korea") win
    over any single-word substring. Returns the capital exactly as the table spells it.
    """
    low = prompt.lower()
    best_key = None
    for key in CAPITALS:
        if re.search(r"\b" + re.escape(key) + r"\b", low):
            if best_key is None or len(key) > len(best_key):
                best_key = key
    if best_key is None:
        raise ValueError("country_capital: no known country found in prompt")
    return CAPITALS[best_key]


def pwntools_quiz(prompt: str) -> str:
    """Answer a pwntools-API trivia prompt (2024 Pwntools) from a rule table.

    Each rule is (regex over the lowercased prompt) -> the API token to send. Ordered most-specific
    first. Returns the single correct API name/attribute the question asks for.
    """
    low = prompt.lower()
    for pattern, answer in PWNTOOLS_QA:
        if re.search(pattern, low):
            return answer
    raise ValueError("pwntools_quiz: no rule matched the prompt")


# --------------------------------------------------------------------------------------------------
# General parse-the-prompt handlers.  These parse data only; no eval/exec and bounded arithmetic.
# --------------------------------------------------------------------------------------------------

_INT_BITS = 16_384
_AST_NODES = 128


def _bounded_int(value: int) -> int:
    if not isinstance(value, int) or value.bit_length() > _INT_BITS:
        raise ValueError("integer result exceeds the handler bound")
    return value


def _safe_int_ast(node: ast.AST, budget: list[int]) -> int:
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError("expression is too complex")
    if isinstance(node, ast.Expression):
        return _safe_int_ast(node.body, budget)
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return _bounded_int(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub, ast.Invert)):
        value = _safe_int_ast(node.operand, budget)
        return _bounded_int(+value if isinstance(node.op, ast.UAdd) else
                            -value if isinstance(node.op, ast.USub) else ~value)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "pow" \
            and len(node.args) == 3 and not node.keywords:
        base, exponent, modulus = (_safe_int_ast(arg, budget) for arg in node.args)
        if exponent < 0 or exponent > 10_000 or modulus == 0:
            raise ValueError("pow arguments outside the handler bound")
        return _bounded_int(pow(base, exponent, modulus))
    if not isinstance(node, ast.BinOp):
        raise ValueError("unsupported expression node")
    left = _safe_int_ast(node.left, budget)
    right = _safe_int_ast(node.right, budget)
    op = node.op
    if isinstance(op, ast.Add):
        result = left + right
    elif isinstance(op, ast.Sub):
        result = left - right
    elif isinstance(op, ast.Mult):
        if left and right and left.bit_length() + right.bit_length() > _INT_BITS + 1:
            raise ValueError("multiplication exceeds the handler bound")
        result = left * right
    elif isinstance(op, (ast.FloorDiv, ast.Mod)):
        if right == 0:
            raise ValueError("division by zero")
        result = left // right if isinstance(op, ast.FloorDiv) else left % right
    elif isinstance(op, ast.Pow):
        if right < 0 or right > 4096:
            raise ValueError("exponent outside the handler bound")
        if left not in (-1, 0, 1) and abs(left).bit_length() * right > _INT_BITS:
            raise ValueError("power exceeds the handler bound")
        result = pow(left, right)
    elif isinstance(op, ast.LShift):
        if right < 0 or right > _INT_BITS:
            raise ValueError("shift outside the handler bound")
        result = left << right
    elif isinstance(op, ast.RShift):
        if right < 0 or right > _INT_BITS:
            raise ValueError("shift outside the handler bound")
        result = left >> right
    elif isinstance(op, ast.BitAnd):
        result = left & right
    elif isinstance(op, ast.BitOr):
        result = left | right
    elif isinstance(op, ast.BitXor):
        result = left ^ right
    else:
        raise ValueError("unsupported arithmetic operator")
    return _bounded_int(result)


def safe_bigint_expr(prompt: str) -> str:
    """Evaluate one bounded integer/modular expression through a strict AST allowlist (never eval)."""
    if len(prompt) > 64_000:
        raise ValueError("safe_bigint_expr: prompt too large")
    text = prompt.strip()
    expression = _grab(r"(?:calculate|evaluate|compute|solve|what\s+is)\s*(?:the\s+value\s+of)?\s*[:=]?\s*"
                       r"([^\n?]{1,4096})(?:\?|\n|$)", text)
    if expression is None:
        expression = _grab(r"expression\s*[:=]\s*([^\n?]{1,4096})", text)
    if expression is None:
        raise ValueError("safe_bigint_expr: no explicit expression found")
    expression = expression.strip().rstrip("= :")
    # Conventional quiz wording: "2^100 mod 17" means exponentiation, unlike Python's XOR.
    modular = re.fullmatch(r"(.+?)\s+(?:mod|modulo)\s+(0[xob])?[0-9a-f_]+", expression, re.I)
    modulus = None
    if modular:
        tail = re.search(r"(?:mod|modulo)\s+((?:0[xob])?[0-9a-f_]+)$", expression, re.I)
        assert tail is not None
        modulus = int(tail.group(1), 0)
        expression = modular.group(1).replace("^", "**")
    try:
        tree = ast.parse(expression, mode="eval")
    except (SyntaxError, ValueError) as exc:
        raise ValueError("safe_bigint_expr: invalid expression") from exc
    value = _safe_int_ast(tree, [_AST_NODES])
    if modulus is not None:
        if modulus <= 0 or modulus.bit_length() > _INT_BITS:
            raise ValueError("safe_bigint_expr: invalid modulus")
        value %= modulus
    return str(value)


def hashing_family(prompt: str) -> str:
    """Hash explicitly supplied text/hex with MD5/SHA/CRC32/BLAKE2; return the requested digest."""
    low = prompt.lower()
    match = re.search(r"\b(md5|sha-?1|sha-?256|sha-?512|crc-?32|blake2b|blake2s)\b", low)
    if not match:
        raise ValueError("hashing_family: algorithm not found")
    algorithm = match.group(1).replace("-", "")
    hex_data = _grab(r"(?:hex|bytes)\s*(?:data|input|message)?\s*[:=]\s*([0-9a-fA-F]{2,8192})", prompt)
    quoted = _grab(r"(?:hash|digest|checksum)(?:\s+of)?\s*['\"]([^'\"\n]{0,8192})['\"]", prompt)
    if quoted is None:
        quoted = _grab(r"(?:text|input|message|string)\s*[:=]\s*['\"]?([^'\"\n]{1,8192})", prompt)
    if hex_data is not None:
        if len(hex_data) % 2:
            raise ValueError("hashing_family: odd-length hex input")
        data = bytes.fromhex(hex_data)
    elif quoted is not None:
        data = quoted.strip().encode()
    else:
        raise ValueError("hashing_family: explicit input not found")
    if algorithm == "crc32":
        value = zlib.crc32(data) & 0xFFFFFFFF
        return str(value) if re.search(r"\bdecimal\b|\bbase\s*10\b", low) else f"{value:08x}"
    constructor = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256,
                   "sha512": hashlib.sha512, "blake2b": hashlib.blake2b,
                   "blake2s": hashlib.blake2s}[algorithm]
    try:
        digest = constructor(data, usedforsecurity=False).digest()
    except TypeError:  # SHA/BLAKE constructors on implementations without usedforsecurity
        digest = constructor(data).digest()
    return base64.b64encode(digest).decode() if "base64" in low else digest.hex()


_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"


def base_conversion(prompt: str) -> str:
    """Convert one explicitly stated integer between bases 2..36."""
    match = re.search(r"(?:convert\s+)?([0-9A-Za-z]{1,4096})\s+(?:from\s+)?base\s*"
                      r"(\d{1,2})\s+(?:to|into)\s+base\s*(\d{1,2})", prompt, re.I)
    if not match:
        raise ValueError("base_conversion: expected VALUE from base A to base B")
    raw, source, target = match.group(1).lower(), int(match.group(2)), int(match.group(3))
    if not 2 <= source <= 36 or not 2 <= target <= 36:
        raise ValueError("base_conversion: bases must be 2..36")
    try:
        value = int(raw, source)
    except ValueError as exc:
        raise ValueError("base_conversion: digit outside source base") from exc
    _bounded_int(value)
    if value == 0:
        return "0"
    out = []
    while value:
        value, digit = divmod(value, target)
        out.append(_DIGITS[digit])
    return "".join(reversed(out))


def list_operations(prompt: str) -> str:
    """Apply one stated sort/reverse/dedupe/sum/min/max operation to a bounded literal list."""
    low = prompt.lower()
    literal = _grab(r"(\[[^\]\n]{1,16384}\])", prompt)
    if literal is not None:
        try:
            values = json.loads(literal)
        except json.JSONDecodeError as exc:
            raise ValueError("list_operations: malformed JSON list") from exc
    else:
        tail = prompt.split(":", 1)[1] if ":" in prompt else prompt
        values = [int(item) for item in re.findall(r"-?\d+", tail)]
    if not isinstance(values, list) or not 1 <= len(values) <= 10_000:
        raise ValueError("list_operations: list length outside 1..10000")
    if not all(isinstance(v, (int, float, str)) and not isinstance(v, bool) for v in values):
        raise ValueError("list_operations: only scalar list entries are supported")
    if re.search(r"\bdedupe|de-duplicate|remove duplicates|unique\b", low):
        result = list(dict.fromkeys(values))
    elif re.search(r"\breverse\b", low):
        result = list(reversed(values))
    elif re.search(r"\bsort(?:ed)?\b", low):
        if len({type(v) for v in values}) != 1:
            raise ValueError("list_operations: mixed types cannot be sorted")
        result = sorted(values, reverse=bool(re.search(r"descending|decreasing", low)))
    elif re.search(r"\bsum|total\b", low):
        if not all(isinstance(v, (int, float)) for v in values):
            raise ValueError("list_operations: sum requires numbers")
        return str(sum(values))
    elif re.search(r"\bmin(?:imum)?|smallest\b", low):
        return str(min(values))
    elif re.search(r"\bmax(?:imum)?|largest\b", low):
        return str(max(values))
    else:
        raise ValueError("list_operations: operation not found")
    separator = "," if "comma" in low or literal is not None else " "
    return separator.join(str(value) for value in result)


def _nth_prime(index: int) -> int:
    if not 1 <= index <= 100_000:
        raise ValueError("prime index outside 1..100000")
    primes: list[int] = []
    candidate = 2
    while len(primes) < index:
        is_prime = True
        for prime in primes:
            if prime * prime > candidate:
                break
            if candidate % prime == 0:
                is_prime = False
                break
        if is_prime:
            primes.append(candidate)
        candidate = 3 if candidate == 2 else candidate + 2
    return primes[-1]


def integer_sequence(prompt: str) -> str:
    """Return a bounded nth prime/Fibonacci value or Collatz step count."""
    low = prompt.lower()
    n_text = _grab(r"(?:n\s*=|number\s*=|starting\s+(?:at|from)|for)\s*(\d{1,18})", low)
    if "prime" in low:
        n_text = _grab(r"(?:the\s+)?(\d{1,6})(?:st|nd|rd|th)?\s+prime", low) or n_text
        if n_text is None:
            raise ValueError("integer_sequence: prime index not found")
        return str(_nth_prime(int(n_text)))
    if "fib" in low:
        n_text = _grab(r"(?:fib(?:onacci)?\s*(?:number|term)?\s*(?:at|for|n\s*=)?\s*|"
                       r"the\s+)(\d{1,6})(?:st|nd|rd|th)?(?:\s+fibonacci)?", low) or n_text
        if n_text is None or not 0 <= int(n_text) <= 10_000:
            raise ValueError("integer_sequence: Fibonacci index outside 0..10000")
        a, b = 0, 1
        for _ in range(int(n_text)):
            a, b = b, a + b
        return str(a)
    if "collatz" in low:
        n_text = _grab(r"(?:collatz[^\d]{0,40}|starting\s+(?:at|from)\s*)(\d{1,18})", low) or n_text
        if n_text is None or not 1 <= int(n_text) <= 10**18:
            raise ValueError("integer_sequence: invalid Collatz start")
        value, steps = int(n_text), 0
        while value != 1 and steps < 10_000_000:
            value = value // 2 if value % 2 == 0 else 3 * value + 1
            steps += 1
        if value != 1:
            raise ValueError("integer_sequence: Collatz step cap reached")
        return str(steps)
    raise ValueError("integer_sequence: unsupported sequence")


def classical_transform(prompt: str) -> str:
    """Apply a stated ROT13/Caesar/reverse transform to one quoted string."""
    text = _grab(r"['\"]([^'\"\n]{0,16384})['\"]", prompt)
    if text is None:
        text = _grab(r"(?:text|input|string)\s*[:=]\s*([^\n]{1,16384})", prompt)
    if text is None:
        raise ValueError("classical_transform: explicit text not found")
    low = prompt.lower()
    if "rot13" in low:
        import codecs
        return codecs.decode(text, "rot_13")
    if "reverse" in low:
        return text[::-1]
    shift_text = _grab(r"(?:caesar|rot(?:ate)?)\s*(?:shift)?\s*(?:by|=|:)?\s*(-?\d{1,3})", low)
    if shift_text is not None:
        shift = int(shift_text) % 26
        out = []
        for char in text:
            if "a" <= char <= "z":
                out.append(chr((ord(char) - 97 + shift) % 26 + 97))
            elif "A" <= char <= "Z":
                out.append(chr((ord(char) - 65 + shift) % 26 + 65))
            else:
                out.append(char)
        return "".join(out)
    raise ValueError("classical_transform: transform not found")


def proof_of_work(prompt: str) -> str:
    """Solve an explicit bounded PoW prompt via the offline toolkit; never opens another connection."""
    toolkit = Path(__file__).resolve().parent.parent / "solvers" / "toolkits"
    if str(toolkit) not in sys.path:
        sys.path.insert(0, str(toolkit))
    import pow_solver
    result = pow_solver.solve_prompt(prompt, workers=1)
    if result is None:
        raise ValueError("proof_of_work: prompt unsupported or no result within its bound")
    return result


# ---- small codec helpers --------------------------------------------------------------------------

def _pad64(s: str) -> bytes:
    s = s.strip()
    return (s + "=" * (-len(s) % 4)).encode()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _canon_json(obj_text: str) -> bytes:
    """Re-serialize a JSON object compactly (no spaces) so the signature is deterministic."""
    return json.dumps(json.loads(obj_text), separators=(",", ":"), sort_keys=False).encode()


def _grab_json(text: str, label: str) -> Optional[str]:
    """Find the JSON object that follows '<label>' in the text (brace-matched)."""
    m = re.search(label + r"\s*(?:=|==|is|:)?\s*(\{)", text, re.I)
    if not m:
        return None
    return _brace_match(text, m.start(1))


def _grab_json_any(text: str) -> Optional[str]:
    m = re.search(r"\{", text)
    if not m:
        return None
    return _brace_match(text, m.start())


def _brace_match(text: str, start: int) -> Optional[str]:
    depth = 0
    for i in range(start, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


# --------------------------------------------------------------------------------------------------
# Handler registry and the auto-dispatcher.
# --------------------------------------------------------------------------------------------------

HANDLERS: dict[str, Callable[[str], str]] = {
    "clf_bytes_sum": clf_bytes_sum,
    "xor_hex": xor_hex,
    "b64_sort_concat": b64_sort_concat,
    "hmac_sha256_hex": hmac_sha256_hex,
    "hs256_jwt": hs256_jwt,
    "tlv_sort_concat": tlv_sort_concat,
    "multiply_char": multiply_char,
    "math_csv": math_csv,
    "country_capital": country_capital,
    "pwntools_quiz": pwntools_quiz,
    "safe_bigint_expr": safe_bigint_expr,
    "hashing_family": hashing_family,
    "base_conversion": base_conversion,
    "list_operations": list_operations,
    "integer_sequence": integer_sequence,
    "classical_transform": classical_transform,
    "proof_of_work": proof_of_work,
}

# repl_shell_escape returns a list, so it is driven differently (a scripted send), not registered here.


def auto_handler(prompt: str) -> Optional[str]:
    """Guess which handler fits a prompt and return its answer, or None if nothing matches.

    Ordered most-specific-first so a distinguishing token wins before a looser one.
    """
    low = prompt.lower()
    # Explicit proof-of-work gate. This must precede ordinary hashing because both name SHA-256.
    if ("proof of work" in low or "proof-of-work" in low or re.search(r"\bpow\b", low)
            or "leading zero" in low or re.search(r"starts?\s+with\s+0{2,}", low)) \
            and re.search(r"sha(?:-|_)?(?:1|256|512)", low):
        try:
            return proof_of_work(prompt)
        except Exception:
            pass
    # pwntools quiz: mentions pwntools/pwnlib, or a tell-tale API verb pair. Try first -- its rules
    # are specific and it raises (not a wrong guess) when nothing matches.
    if "pwntools" in low or "pwnlib" in low or ("pwn" in low and "function" in low):
        try:
            return pwntools_quiz(prompt)
        except Exception:
            pass
    # Geography: asks for a capital and names a country from the table.
    if "capital" in low:
        try:
            return country_capital(prompt)
        except Exception:
            pass
    # Sequences precede ordinary arithmetic/list reducers: "10th prime" contains an integer but is
    # not an instruction to sum a list.
    if re.search(r"\b(?:prime|fib(?:onacci)?|collatz)\b", low):
        try:
            return integer_sequence(prompt)
        except Exception:
            pass
    if re.search(r"\bconvert\b.*\bbase\s*\d+\b.*\bbase\s*\d+\b", low):
        try:
            return base_conversion(prompt)
        except Exception:
            pass
    if (re.search(r"\b(md5|sha-?1|sha-?256|sha-?512|crc-?32|blake2[bs])\b", low)
            and re.search(r"\b(hash|digest|checksum|text|input|message|string|hex)\b", low)):
        try:
            return hashing_family(prompt)
        except Exception:
            pass
    if re.search(r"\b(rot13|caesar|reverse (?:the )?(?:text|string))\b", low):
        try:
            return classical_transform(prompt)
        except Exception:
            pass
    if re.search(r"\b(sort|sorted|reverse|dedupe|de-duplicate|unique|remove duplicates|list)\b", low) \
            and ("[" in prompt or len(re.findall(r"-?\d+", prompt)) >= 2):
        try:
            return list_operations(prompt)
        except Exception:
            pass
    # Multiply: repeat a character N times.
    if re.search(r"\b(repeat|print|send|give|output)\b", low) and re.search(r"\btimes\b", low):
        try:
            return multiply_char(prompt)
        except Exception:
            pass
    # Math Master: an arithmetic operation word over a list of numbers (CSV/space separated).
    if re.search(r"\b(sum|add|product|multiply|subtract|difference|divide|average|mean|max|min)\w*\b",
                 low) and len(re.findall(r"-?\d+(?:\.\d+)?", prompt)) >= 2:
        try:
            return math_csv(prompt)
        except Exception:
            pass
    # JWT: mentions jwt/HS256 token building with a secret and a payload JSON.
    if ("jwt" in low or "hs256" in low) and "secret" in low and "{" in prompt:
        try:
            return hs256_jwt(prompt)
        except Exception:
            pass
    # HMAC: mentions hmac and has key+token.
    if "hmac" in low and "key" in low and "token" in low:
        try:
            return hmac_sha256_hex(prompt)
        except Exception:
            pass
    # TLV: mentions tlv / type-length-value / a 'tag' plus a long hex blob.
    if ("tlv" in low or "type-length" in low or "type/len" in low or "tag" in low) \
            and re.search(r"(?:[0-9a-fA-F]{2}){8,}", prompt):
        try:
            out = tlv_sort_concat(prompt)
            if out:
                return out
        except Exception:
            pass
    # CLF: log lines with "GET ... HTTP".
    if re.search(r'"[A-Z]+\s+\S+\s+HTTP', prompt) and ("byte" in low or "sum" in low or "log" in low):
        try:
            return clf_bytes_sum(prompt)
        except Exception:
            pass
    # base64 fragments with indices.
    if ("base64" in low or "b64" in low) and re.search(r"\d+\s*[:=]\s*[A-Za-z0-9+/=]{4,}", prompt):
        try:
            return b64_sort_concat(prompt)
        except Exception:
            pass
    # XOR of hex bytes.
    if "xor" in low and re.search(r"\b[0-9a-fA-F]{2}\b", prompt):
        try:
            return xor_hex(prompt)
        except Exception:
            pass
    # General integer expression is deliberately last: it accepts only a strict AST subset, but a
    # more specific handler above better captures output formatting and prompt semantics.
    if re.search(r"\b(calculate|evaluate|compute|solve|what is|expression)\b", low) \
            and re.search(r"\d\s*(?:\*\*|//|[%+*/<>&|^-])\s*\d", prompt):
        try:
            return safe_bigint_expr(prompt)
        except Exception:
            pass
    return None


# --------------------------------------------------------------------------------------------------
# The driver.
# --------------------------------------------------------------------------------------------------

def find_flag(data: bytes) -> Optional[str]:
    m = FLAG_RE.search(data)
    return m.group(0).decode("utf-8", "replace") if m else None


def run_loop(conn: Conn, handler: Callable[[str], str], *, delims: Optional[List[bytes]] = None,
             timeout: float = 10.0, quiet: float = 0.3, max_rounds: int = 200,
             on_round: Optional[Callable[[int, str, str], None]] = None) -> Optional[str]:
    """Read prompt -> handler -> send, repeat until a flag appears. Returns the flag or None.

    No sleeps: each round blocks on the socket, draining the whole prompt block until the service
    goes quiet (or an explicit `delims` boundary is hit). The accumulated stream is scanned for a
    flag after every read, so a flag that arrives mid-stream is caught immediately.
    """
    seen = b""
    for rnd in range(max_rounds):
        chunk = conn.recv_prompt(timeout, quiet, delims)
        if not chunk:
            break
        seen += chunk
        flag = find_flag(seen)
        if flag:
            return flag
        prompt = chunk.decode("utf-8", "replace")
        try:
            answer = handler(prompt)
        except Exception as e:
            raise RuntimeError(f"handler failed on prompt {prompt!r}: {e}") from e
        if answer is None:
            # auto-dispatcher found nothing; this block was likely a banner -- keep reading.
            continue
        if on_round:
            on_round(rnd, prompt, answer)
        conn.send(answer.encode() + b"\n")
    # Final drain for a trailing flag.
    tail = conn.recv_some(timeout)
    if tail:
        seen += tail
    return find_flag(seen)


def run_script(conn: Conn, steps: List[dict], *, timeout: float = 10.0) -> Optional[str]:
    """Run a scripted send/expect sequence. Each step is {"expect": str?, "send": str}.

    "expect" (optional) is a substring waited for before sending; "send" is the line to send. A flag
    seen at any point is returned. This covers repl_shell_escape and any fixed interaction.
    """
    seen = b""
    for step in steps:
        exp = step.get("expect")
        if exp is not None:
            got = conn.recv_until([exp.encode()], timeout)
            seen += got
            flag = find_flag(seen)
            if flag:
                return flag
        send = step.get("send")
        if send is not None:
            conn.send(send.encode() + b"\n")
    # Drain the tail until the flag appears or the service goes quiet (two empty reads).
    empties = 0
    while empties < 2:
        tail = conn.recv_some(timeout)
        if tail:
            seen += tail
            flag = find_flag(seen)
            if flag:
                return flag
        else:
            empties += 1
    return find_flag(seen)


# --------------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------------

def report(flag: Optional[str]) -> int:
    if flag:
        print(f"[+] FLAG  {flag}")
        return 0
    print("[-] no flag recovered (service closed or pattern unmatched)")
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="interactive nc/REPL harness for socket quiz challenges")
    p.add_argument("host", nargs="?")
    p.add_argument("port", nargs="?", type=int)
    p.add_argument("--ssh", dest="ssh_user", default=None,
                   help="connect over SSH as this user (the login shell is the REPL); port defaults to 22")
    p.add_argument("--ssh-pass", dest="ssh_pass", default=None, help="SSH password (else key/agent)")
    p.add_argument("--ssh-key", dest="ssh_keyfile", default=None, help="SSH private key file")
    p.add_argument("--handler", default=None, help="named handler to drive the loop")
    p.add_argument("--auto", action="store_true", help="use the auto-dispatcher")
    p.add_argument("--script", default=None, help="JSON file: [{expect?, send}, ...]")
    p.add_argument("--delim", default=None, help="prompt delimiter (literal bytes)")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--max-rounds", type=int, default=200)
    p.add_argument("--list", action="store_true", help="list the handler library and exit")
    args = p.parse_args(argv)

    if args.list:
        print("handlers:")
        for name, fn in HANDLERS.items():
            doc = (fn.__doc__ or "").strip().splitlines()[0]
            print(f"  {name:18s} {doc}")
        print(f"  {'repl_shell_escape':18s} "
              f"{repl_shell_escape.__doc__.strip().splitlines()[0]} (via --script)")
        return 0

    if args.host is None or (args.port is None and not args.ssh_user):
        p.error("host and port are required (or use --list; SSH defaults the port to 22)")

    try:
        conn = connect(args.host, args.port, ssh_user=args.ssh_user, timeout=args.timeout,
                       ssh_pass=args.ssh_pass, ssh_keyfile=args.ssh_keyfile)
    except scope.OutOfScope as e:
        print(f"netplay: refused: {e}", file=sys.stderr)
        return 2
    try:
        if args.script:
            with open(args.script, "r", encoding="utf-8") as fh:
                steps = json.load(fh)
            flag = run_script(conn, steps, timeout=args.timeout)
        else:
            if args.auto or not args.handler:
                handler = auto_handler
            else:
                if args.handler not in HANDLERS:
                    p.error(f"unknown handler {args.handler!r}; see --list")
                handler = HANDLERS[args.handler]
            delims = [args.delim.encode()] if args.delim else None

            def _log(rnd, prompt, answer):
                print(f"[{rnd}] <- {prompt.strip()[:80]!r}  -> {answer[:80]!r}", file=sys.stderr)

            flag = run_loop(conn, handler, delims=delims, timeout=args.timeout,
                            max_rounds=args.max_rounds, on_round=_log)
    finally:
        conn.close()
    return report(flag)


if __name__ == "__main__":
    sys.exit(main())
