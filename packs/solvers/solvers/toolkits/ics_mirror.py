#!/usr/bin/env python3
"""Live ICS instance mirror + protocol evidence pack (B-081).

CSCTF 9118 "silent-breaker" (and its siblings) exposed a live per-team instance -- an IEC-104 RTU, an
AVR firmware blob served over a WS console, a bare-metal RSP target -- that had to be spawned behind
the breakglass, mirrored by hand, and decoded one packet at a time before a human could reason about
it. This module mechanises the fetch-and-decode half, which is the part that costs no judgement, and
leaves the judgement (what the evidence means, which flag to submit) to the player/model:

  * **Start through the scheduler only.** `start_instance` goes through `ctf.instsched.start_capped`
    with the event's slot ledger, so the local cap (3 at CSCTF) binds across every process and a
    fourth start is a named `CapReached`, never a silent over-spawn. This module starts an instance
    and never tears it down (spawn-only-while-working, B-003); the operator frees the slot on solve.

  * **GET-only mirror of documented routes.** `mirror_http` fetches a caller-supplied list of
    *documented* routes with `solvers/toolkits/web.py::WebClient` built `get_only=True`, so a non-GET
    can never reach the target and the scope guard (`ctf.scope`) has already refused an out-of-scope
    or platform host before the socket opened. It mirrors only the routes the caller names; it does
    no discovery and no crawling.

  * **Raw TCP via the live harness.** `read_iec104_stream` reads raw bytes off a scope-locked
    `live_harness.Session` (which opens through `pwn_target.PwnTarget` -> the same scope guard) and
    `decode_iec104` runs the carried `ics_scada` IEC-104 dissector over them. `decode_avr_hex` parses
    served AVR firmware with `rf.ihex_parse`; `disassemble_avr` shells out to `avr-objdump` and, when
    it is absent, fails loudly with a named reason (never a silent skip). `cbc_mac_forge` wraps
    `crypto_faults.cbc_mac_length_extension` for the WS-console CBC-MAC path. The RSP target is driven
    by `solvers/toolkits/rsp.py` (B-056) -- this module does not re-implement it.

  * **State-changing requests are never automatic.** `authorize_state_change` refuses every budgeted
    POST (/confirm-target, /submit, a forged command) unless the event profile sets
    `rules.web_state_changing = true` AND the caller passes explicit player approval. The mirror
    client itself is GET-only, so the only road to a state change is this gate.

  * **A pre-parsed evidence pack.** `write_pack` writes `index.json` plus the raw mirrored bodies and
    the decoded records under one folder, so the model receives parsed evidence instead of a live
    socket.

Everything the target returns is DATA: it is decoded, written to the pack and returned, never executed
and never treated as an instruction. No model runs here; nothing is submitted.

CLI (offline helpers only; no connection is made):

  .venv/bin/python solvers/toolkits/ics_mirror.py iec104 <capture.bin>   # decode a raw IEC-104 stream
  .venv/bin/python solvers/toolkits/ics_mirror.py avr <firmware.hex>     # parse served AVR Intel-HEX
  .venv/bin/python solvers/toolkits/ics_mirror.py endpoint '<connect-info>'  # parse an instance endpoint
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
for _p in (str(HERE), str(COMMON)):
    if _p not in sys.path:
        sys.path.insert(1, _p)

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import event as _event
    from ctf import instsched as _sched
except ModuleNotFoundError:  # pragma: no cover - only when run as a bare script outside the checkout
    sys.path.append(str(HERE.parents[1]))
    from ctf import event as _event
    from ctf import instsched as _sched

import crypto_faults  # noqa: E402  (solvers/common: CBC-MAC length extension)
import ics_scada  # noqa: E402     (solvers/toolkits: the IEC-104 dissector)
import rf  # noqa: E402            (solvers/toolkits: Intel-HEX / AVR image parsing)

AVR_OBJDUMP = "avr-objdump"
DEFAULT_IEC104_MAX_BYTES = 256 * 1024       # a mirrored IEC-104 burst is small; cap it anyway
DEFAULT_IEC104_MAX_READS = 256              # recv() calls before a read is declared complete
DEFAULT_HTTP_MAX_BYTES = 4 * 1024 * 1024    # per mirrored body
# IEC-104 Type IDs 45..69 and 100..107 are controls/commands (sco/dco/rco, interrogation, clock sync).
_IEC104_COMMAND_TYPES = frozenset(range(45, 70)) | frozenset(range(100, 108))


class MirrorError(RuntimeError):
    """A mirror-level problem with a named reason (no silent fallback)."""


class NeedsTool(MirrorError):
    """A required external tool (avr-objdump) is not available; named, never a silent skip."""


class StateChangeRefused(MirrorError):
    """A budgeted state-changing request was attempted without the profile + approval that gate it."""


# ======================================================================================
#  Instance endpoint parsing
# ======================================================================================

@dataclass(frozen=True)
class Endpoint:
    """Where a started instance lives, parsed from an InstanceInfo.connection_info string."""
    host: str
    port: int
    scheme: str | None = None            # http/https/ws/wss when the connect info named one, else None

    @property
    def addr(self) -> tuple[str, int]:
        return (self.host, int(self.port))

    @property
    def base_url(self) -> str:
        """An http(s) base URL for the WebClient mirror (ws/wss alias to http/https for the GET upgrade)."""
        scheme = self.scheme or "http"
        if scheme == "ws":
            scheme = "http"
        elif scheme == "wss":
            scheme = "https"
        return f"{scheme}://{self.host}:{self.port}/"


_HOSTPORT = re.compile(r"^\[?(?P<host>[^\s\]]+?)\]?[:\s]+(?P<port>\d{1,5})\b")


def parse_endpoint(connection_info: str) -> Endpoint:
    """Parse an instance endpoint out of a platform connection-info string.

    Handles a URL (``http://h:port/``), a ``host:port`` pair, and the common handout spellings
    ``nc host port`` / ``host port``.  The first usable host:port on the first non-empty line wins.
    A string with no host:port is a MirrorError (named), never a guess."""
    if not isinstance(connection_info, str) or not connection_info.strip():
        raise MirrorError("instance has no connection_info; start it before mirroring it")
    for line in connection_info.splitlines():
        line = line.strip()
        if not line:
            continue
        if "://" in line:
            parts = urllib.parse.urlsplit(line)
            if parts.hostname and parts.port:
                return Endpoint(parts.hostname.lower(), int(parts.port), parts.scheme.lower() or None)
            continue
        # "nc host port" -> drop a leading command word before matching host:port.
        candidate = line
        words = line.split()
        if len(words) >= 3 and words[0].lower() in ("nc", "ncat", "netcat", "telnet", "connect"):
            candidate = " ".join(words[1:])
        m = _HOSTPORT.match(candidate)
        if m:
            port = int(m.group("port"))
            if 1 <= port <= 65535:
                return Endpoint(m.group("host").lower(), port, None)
    raise MirrorError(f"could not find a host:port in connection_info {connection_info!r}")


# ======================================================================================
#  HTTP mirror (GET-only, documented routes)
# ======================================================================================

@dataclass(frozen=True)
class DocumentedRoute:
    """One documented route to mirror.  The mirror is GET-only by construction, so there is no method
    field: a state-changing route is never mirrored (it goes through authorize_state_change instead)."""
    path: str
    note: str = ""


@dataclass
class MirroredResource:
    route: str
    url: str
    status: int | None
    content_type: str
    size: int
    sha256: str
    body: bytes = b""
    saved_as: str | None = None          # path under the pack, set by write_pack
    error: str | None = None

    def to_dict(self) -> dict:
        d = {"route": self.route, "url": self.url, "status": self.status,
             "content_type": self.content_type, "size": self.size, "sha256": self.sha256}
        if self.saved_as is not None:
            d["saved_as"] = self.saved_as
        if self.error is not None:
            d["error"] = self.error
        return d


def mirror_http(client: Any, routes: Iterable[DocumentedRoute | str], *,
                max_bytes: int = DEFAULT_HTTP_MAX_BYTES) -> list[MirroredResource]:
    """GET each documented route through `client` (a web.WebClient built get_only, or any object with a
    ``.get(path) -> entry dict``) and return the mirrored resources.

    The client is GET-only, so nothing here can change state.  A route that raises (unreachable, a
    refused redirect) is recorded as a resource with ``error`` set and does not stop the rest -- the
    mirror is best-effort over a flaky live instance.  Nothing is submitted and no model runs."""
    out: list[MirroredResource] = []
    for route in routes:
        r = route if isinstance(route, DocumentedRoute) else DocumentedRoute(str(route))
        try:
            entry = client.get(r.path)
        except Exception as e:  # noqa: BLE001 - recorded by route, never dropped
            out.append(MirroredResource(r.path, "", None, "", 0, "", error=f"{type(e).__name__}: {e}"))
            continue
        body = entry.get("body") or b""
        if not isinstance(body, (bytes, bytearray)):
            body = str(body).encode("utf-8", "replace")
        body = bytes(body)[:max_bytes]
        headers = entry.get("response_headers") or {}
        ctype = ""
        for k, v in headers.items():
            if str(k).lower() == "content-type":
                ctype = str(v)
                break
        out.append(MirroredResource(
            r.path, str(entry.get("final_url") or entry.get("url") or ""),
            entry.get("status"), ctype, len(body), hashlib.sha256(body).hexdigest(), body=body))
    return out


# ======================================================================================
#  Raw IEC-104 read + decode
# ======================================================================================

def read_iec104_stream(session: Any, *, max_bytes: int = DEFAULT_IEC104_MAX_BYTES,
                       max_reads: int = DEFAULT_IEC104_MAX_READS) -> bytes:
    """Read a raw IEC-104 byte burst off a scope-locked `live_harness.Session` (or any object with a
    ``recv_raw() -> bytes``).  Reads until the peer stops sending, `max_bytes` is reached, or
    `max_reads` empty/partial reads elapse.  Sends nothing: IEC-104 RTUs push unsolicited ASDUs, so a
    read-only mirror never has to transmit.  The bytes are returned as DATA for `decode_iec104`."""
    buf = bytearray()
    for _ in range(max_reads):
        try:
            chunk = session.recv_raw()
        except Exception as e:  # noqa: BLE001 - a drop ends the read; what we have is still evidence
            if buf:
                break
            raise MirrorError(f"IEC-104 read failed before any byte arrived: {type(e).__name__}: {e}") from e
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) >= max_bytes:
            break
    return bytes(buf[:max_bytes])


def decode_iec104(raw: bytes) -> dict:
    """Decode a raw IEC-104 (APCI/ASDU) byte stream with the carried `ics_scada` dissector.

    Returns a pre-parsed record: every APDU (I/S/U), the control commands singled out (sco/dco/rco,
    interrogation, clock sync -- CSCTF 9118's C_SC_NA_1 single command lives here), and a small
    summary.  Mapping that evidence to a flag is the model's job, never this module's."""
    if not isinstance(raw, (bytes, bytearray)):
        raise MirrorError("decode_iec104 wants raw bytes")
    raw = bytes(raw)
    apdus = ics_scada.iter_iec104(raw)
    commands: list[dict] = []
    formats: dict[str, int] = {}
    for rec in apdus:
        fmt = rec.get("format")
        formats[fmt] = formats.get(fmt, 0) + 1
        asdu = rec.get("asdu")
        if not isinstance(asdu, Mapping):
            continue
        type_id = asdu.get("type_id")
        name = str(asdu.get("type_name") or "")
        is_command = type_id in _IEC104_COMMAND_TYPES or name.startswith("C_")
        if is_command:
            commands.append({
                "type_id": type_id,
                "type_name": name,
                "cause": asdu.get("cause_name"),
                "common_address": asdu.get("common_address"),
                "tx_sequence": rec.get("tx_sequence"),
                "information_objects": asdu.get("information_objects", []),
            })
    return {
        "protocol": "IEC-104",
        "bytes": len(raw),
        "apdu_count": len(apdus),
        "formats": formats,
        "command_count": len(commands),
        "commands": commands,
        "apdus": apdus,
    }


# ======================================================================================
#  AVR firmware (served Intel-HEX) + disassembly
# ======================================================================================

def decode_avr_hex(text: str | bytes) -> dict:
    """Parse served AVR firmware in Intel-HEX with `rf.ihex_parse`.

    Returns the ihex facts plus the reconstructed flash image as hex (`image_hex`) so the pack carries
    bytes a disassembler can be pointed at.  A non-ihex blob is a named MirrorError."""
    parsed = rf.ihex_parse(text)
    if not parsed:
        raise MirrorError("not Intel-HEX: rf.ihex_parse found no records (served an .elf or raw .bin?)")
    image = parsed.get("image") or b""
    out = dict(parsed)
    out.pop("image", None)
    out["image_hex"] = bytes(image).hex()
    out["image_size"] = len(image)
    return out


def disassemble_avr(image: bytes, *, mcu: str = "avr5", start_addr: int = 0,
                    objdump: str | None = None, timeout: float = 60.0) -> str:
    """Disassemble an AVR flash image with `avr-objdump` (a static disassembler, not execution).

    `avr-objdump` is optional; when it is not on PATH this raises `NeedsTool` naming it (install
    `binutils-avr` / `avr-binutils`), never a silent skip.  `mcu` is an objdump `-m avr` architecture
    (avr1..avr6, or a specific part); the caller names the device."""
    if not isinstance(image, (bytes, bytearray)) or not image:
        raise MirrorError("disassemble_avr wants a non-empty flash image (bytes)")
    tool = objdump or shutil.which(AVR_OBJDUMP)
    if not tool:
        raise NeedsTool(
            f"AVR disassembly needs {AVR_OBJDUMP} on PATH; install binutils-avr (Debian/Ubuntu: "
            f"apt-get install binutils-avr; macOS: brew install avr-binutils) and retry, or pass "
            f"objdump= to point at it")
    import tempfile
    with tempfile.NamedTemporaryFile(prefix="avr-image-", suffix=".bin", delete=True) as fh:
        fh.write(bytes(image))
        fh.flush()
        cmd = [tool, "-D", "-b", "binary", "-m", f"avr:{mcu}" if mcu.isdigit() else mcu,
               f"--adjust-vma=0x{start_addr:x}", fh.name]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError) as e:
            raise MirrorError(f"{AVR_OBJDUMP} failed to run: {e}") from e
    if proc.returncode != 0:
        raise MirrorError(f"{AVR_OBJDUMP} exited {proc.returncode}: {proc.stderr.strip()[:400]}")
    return proc.stdout


# ======================================================================================
#  CBC-MAC forge (WS-console path) -- a plan for human review, never auto-sent
# ======================================================================================

def cbc_mac_forge(first_message: bytes, first_tag: bytes, second_message: bytes, second_tag: bytes,
                  *, block_size: int = 16) -> dict:
    """Build the zero-IV raw CBC-MAC length-extension plan (`crypto_faults.cbc_mac_length_extension`).

    Returns the forged candidate, its expected tag and the stated assumptions, for human review.  It
    asserts nothing about a remote oracle and auto-sends nothing."""
    plan = crypto_faults.cbc_mac_length_extension(
        first_message, first_tag, second_message, second_tag, block_size=block_size)
    return {"candidate_hex": plan.candidate.hex(), "expected_tag_hex": plan.expected_tag.hex(),
            "assumptions": list(plan.assumptions)}


# ======================================================================================
#  State-changing request gate (budgeted POSTs are never automatic)
# ======================================================================================

def authorize_state_change(action: str, *, approved: bool = False,
                           profile: _event.EventProfile | None = None) -> bool:
    """Gate a budgeted, state-changing request (a POST to /confirm-target, /submit, a forged command).

    Refuses unless BOTH hold: the active event profile sets `rules.web_state_changing = true`, and the
    caller passes `approved=True` (explicit player approval for this action).  The mirror never flips
    either on its own -- a state change is never automatic (B-081/Open O-2).  Returns True or raises
    `StateChangeRefused` naming which condition failed."""
    prof = profile if profile is not None else _event.current()
    if not getattr(prof.rules, "web_state_changing", False):
        raise StateChangeRefused(
            f"{action!r} is a state-changing request; event {prof.slug!r} sets "
            f"rules.web_state_changing = false (Open O-2), so the mirror never sends it")
    if not approved:
        raise StateChangeRefused(
            f"{action!r} is a budgeted state-changing request; event {prof.slug!r} allows "
            f"web_state_changing but it still needs explicit player approval (approved=True)")
    return True


def post_state_change(client: Any, path: str, data: Any = None, *, action: str, approved: bool = False,
                      profile: _event.EventProfile | None = None) -> Any:
    """Send ONE authorized state-changing POST through a (non-get_only) client, after the gate passes.

    `authorize_state_change` runs first, so an unauthorized call raises before any byte is sent."""
    authorize_state_change(action, approved=approved, profile=profile)
    return client.post(path, data=data)


# ======================================================================================
#  The evidence pack
# ======================================================================================

@dataclass
class EvidencePack:
    challenge_id: str
    endpoint: Endpoint | None = None
    http: list[MirroredResource] = field(default_factory=list)
    iec104: dict | None = None
    avr: dict | None = None
    cbc_mac: dict | None = None
    notes: list[str] = field(default_factory=list)

    def index(self) -> dict:
        return {
            "item": "B-081",
            "challenge_id": self.challenge_id,
            "endpoint": None if self.endpoint is None else {
                "host": self.endpoint.host, "port": self.endpoint.port, "scheme": self.endpoint.scheme},
            "http": [r.to_dict() for r in self.http],
            "iec104": self.iec104,
            "avr": self.avr,
            "cbc_mac": self.cbc_mac,
            "notes": list(self.notes),
        }


def _slug(path: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", path.strip("/")) or "root"
    return s[:80]


def write_pack(pack: EvidencePack, out_dir: Path | str) -> Path:
    """Write the pre-parsed evidence pack under `out_dir`: `index.json`, the raw mirrored bodies under
    `http/`, the raw IEC-104 capture + decoded JSON under `iec104/`, the AVR facts under `avr/`.

    Returns the pack directory.  The model reads this folder instead of a live socket."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    if pack.http:
        http_dir = out / "http"
        http_dir.mkdir(exist_ok=True)
        used: dict[str, int] = {}
        for res in pack.http:
            if res.error is not None and not res.body:
                continue
            base = _slug(res.route)
            n = used.get(base, 0)
            used[base] = n + 1
            name = base if n == 0 else f"{base}.{n}"
            (http_dir / name).write_bytes(res.body)
            res.saved_as = f"http/{name}"
    if pack.iec104 is not None:
        iec_dir = out / "iec104"
        iec_dir.mkdir(exist_ok=True)
        raw_hex = pack.iec104.pop("_raw_hex", None)
        if raw_hex is not None:
            (iec_dir / "capture.bin").write_bytes(bytes.fromhex(raw_hex))
        (iec_dir / "decoded.json").write_text(json.dumps(pack.iec104, indent=2, default=str),
                                              encoding="utf-8")
    if pack.avr is not None:
        avr_dir = out / "avr"
        avr_dir.mkdir(exist_ok=True)
        (avr_dir / "firmware.json").write_text(json.dumps(pack.avr, indent=2, default=str),
                                               encoding="utf-8")
        image_hex = pack.avr.get("image_hex")
        if image_hex:
            (avr_dir / "flash.bin").write_bytes(bytes.fromhex(image_hex))
    (out / "index.json").write_text(json.dumps(pack.index(), indent=2, default=str), encoding="utf-8")
    return out


# ======================================================================================
#  Orchestrator: start (capped) -> mirror -> decode -> pack
# ======================================================================================

@dataclass
class MirrorReport:
    challenge_id: str
    endpoint: Endpoint | None
    pack_dir: Path | None
    http: list[MirroredResource] = field(default_factory=list)
    iec104: dict | None = None
    notes: list[str] = field(default_factory=list)


def start_instance(controller: Any, ledger: Any, challenge_id: str, *, cap: int | None) -> Any:
    """Start our instance for `challenge_id` through the B-003 scheduler, respecting the local cap.

    The ledger's flock is held only for the check-and-start, not the mirror.  A start that would
    exceed `cap` raises `ctf.instsched.CapReached` (named).  Returns the InstanceInfo.  This module
    never stops an instance -- the slot is freed on solve by the operator (spawn-only-while-working)."""
    with ledger:
        return _sched.start_capped(controller, ledger, str(challenge_id), cap=cap)


def default_http_client(base_url: str):  # pragma: no cover - exercised via a real loopback in tests
    """A GET-only web.WebClient for the mirror (scope-checked in its constructor)."""
    import web as _web
    return _web.WebClient(base_url, get_only=True)


def default_iec104_session(host: str, port: int):  # pragma: no cover - needs pwn_target socket
    """A scope-locked raw live_harness.Session for the IEC-104 read."""
    import live_harness as _lh
    return _lh.Session(str(host), int(port))


def run_mirror(controller: Any, challenge_id: str, *, out_dir: Path | str, ledger: Any, cap: int | None,
               routes: Sequence[DocumentedRoute | str] = (), iec104: bool = False,
               http_client_factory: Callable[[str], Any] = default_http_client,
               iec104_session_factory: Callable[[str, int], Any] = default_iec104_session,
               iec104_max_bytes: int = DEFAULT_IEC104_MAX_BYTES) -> MirrorReport:
    """On pull: start the instance (capped), mirror its documented GET routes, read+decode its IEC-104
    stream when asked, and write a pre-parsed evidence pack.  Returns a MirrorReport.

    It never submits, never POSTs, never runs a model, and never tears the instance down.  A failing
    mirror leg is recorded in the pack's notes; a start over the cap, or an unparseable endpoint, is a
    named error."""
    info = start_instance(controller, ledger, challenge_id, cap=cap)
    endpoint = parse_endpoint(getattr(info, "connection_info", "") or "")
    pack = EvidencePack(challenge_id=str(challenge_id), endpoint=endpoint)

    if routes:
        try:
            client = http_client_factory(endpoint.base_url)
            pack.http = mirror_http(client, routes)
        except Exception as e:  # noqa: BLE001 - recorded; the IEC-104 leg still runs
            pack.notes.append(f"http mirror failed: {type(e).__name__}: {e}")

    if iec104:
        try:
            session = iec104_session_factory(endpoint.host, endpoint.port)
            opened = session.connect() if hasattr(session, "connect") else session
            try:
                raw = read_iec104_stream(opened, max_bytes=iec104_max_bytes)
            finally:
                if hasattr(session, "close"):
                    session.close()
            decoded = decode_iec104(raw)
            decoded["_raw_hex"] = raw.hex()
            pack.iec104 = decoded
        except Exception as e:  # noqa: BLE001 - recorded in notes, never dropped
            pack.notes.append(f"iec104 read failed: {type(e).__name__}: {e}")

    pack_dir = write_pack(pack, out_dir)
    return MirrorReport(str(challenge_id), endpoint, pack_dir, http=pack.http,
                        iec104=pack.iec104, notes=pack.notes)


# ======================================================================================
#  Offline CLI (no connection is made)
# ======================================================================================

def _read_arg_bytes(path: str) -> bytes:
    return Path(path).read_bytes()


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip().splitlines()[0])
        print("usage: ics_mirror.py {iec104 <capture.bin> | avr <firmware.hex> | endpoint <connect-info>}")
        return 0 if argv else 2
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "iec104":
            if not rest:
                print("iec104: needs a capture file", file=sys.stderr)
                return 2
            decoded = decode_iec104(_read_arg_bytes(rest[0]))
            print(json.dumps(decoded, indent=2, default=str))
            return 0
        if cmd == "avr":
            if not rest:
                print("avr: needs an Intel-HEX file", file=sys.stderr)
                return 2
            text = Path(rest[0]).read_text(encoding="utf-8", errors="replace")
            print(json.dumps(decode_avr_hex(text), indent=2, default=str))
            return 0
        if cmd == "endpoint":
            if not rest:
                print("endpoint: needs a connection-info string", file=sys.stderr)
                return 2
            ep = parse_endpoint(rest[0])
            print(json.dumps({"host": ep.host, "port": ep.port, "scheme": ep.scheme,
                              "base_url": ep.base_url}, indent=2))
            return 0
    except MirrorError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"unknown command {cmd!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
