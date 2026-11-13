#!/usr/bin/env python3
"""Live-service probe and exploit harness scoped to assigned instances (B-205).

A thin, mechanical driver for a live remote service (a pwn/web socket a squad was assigned). It carries
the player's own bytes to the target and reports what came back; it generates no exploit. The reasoning
-- what to send -- stays the player's. What the harness mechanises is everything *around* that: a
scope-locked session, a framing map so one `request()` is one request/one response, banner read, raw
-byte send, request replay, a PASS/FAIL loop against a caller-supplied oracle, and -- the part that
cost CSCTF solves -- an instance-lifecycle helper that notices the per-team instance rotated mid
-exploit, re-establishes the session (re-checking scope) and replays the deterministic *fast prefix* of
the chain so the slow interactive tail can resume instead of starting over.

Scope is never this module's own: every connection goes through `pwn_target.PwnTarget`, whose
constructor calls `chat_target.assert_host_in_scope` -> `ctf.scope.check_host`, read from the current
event profile's `rules.live_service_scope` on every call. A rotated endpoint is a *new* target, so the
session factory builds a fresh `PwnTarget` for it and the scope guard runs again before the socket is
opened. There is no default scope; an empty scope refuses everything. The event platform is never a
target.

Everything the target returns is DATA: it is logged to the session transcript and returned to the
caller, never executed and never treated as an instruction.

The "exploit primitives" here (`p64`/`u64`/`flat`/`cyclic`/`cyclic_find`) are mechanical byte helpers
-- packing, concatenation, a De Bruijn offset pattern -- not an exploit library. They assemble bytes a
caller reasoned about; they fire nothing.

CLI (offline helpers only; no connection is made):

  .venv/bin/python solvers/toolkits/live_harness.py framings           # the framing modes
  .venv/bin/python solvers/toolkits/live_harness.py cyclic <n> [width]  # a De Bruijn pattern (offset finding)
  .venv/bin/python solvers/toolkits/live_harness.py find <hexbytes> [width]  # its offset in the pattern
"""
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(1, str(HERE))
import chat_target as ct     # noqa: E402  (errors + the shared scope guard)
import pwn_target as pt      # noqa: E402  (the scope-checked raw-TCP recon socket)

PASS = "PASS"
FAIL = "FAIL"

FRAMINGS = ("raw", "line", "prompt", "length")
DEFAULT_READ_TIMEOUT = 8.0


class HarnessError(RuntimeError):
    """A harness-level problem (bad framing config, a frame that never completed). Loud, never silent."""


# ======================================================================================
#  Framing map: how one logical request/response is delimited on the wire.
# ======================================================================================

@dataclass(frozen=True)
class Framing:
    """How to wrap an outgoing payload and recognise a complete incoming response.

    mode:
      - "raw"    : send the payload unchanged; one socket read is one response (no delimiter).
      - "line"   : append `terminator` (default b"\\n") when sending; a response ends at the first
                   `terminator`, which is stripped from the returned bytes.
      - "prompt" : append `terminator` when sending; a response ends at (and includes) `prompt`
                   (e.g. b"> " for a menu). Use when the service re-prints a prompt after each reply.
      - "length" : prefix the payload with its length in `length_bytes` bytes (`byteorder`); a response
                   is that same length-prefixed framing, and the returned bytes are the body only.
    """
    mode: str = "line"
    terminator: bytes = b"\n"
    prompt: bytes = b""
    length_bytes: int = 4
    byteorder: str = "big"

    def __post_init__(self):
        if self.mode not in FRAMINGS:
            raise HarnessError(f"unknown framing mode {self.mode!r}; known: {', '.join(FRAMINGS)}")
        if self.mode in ("line", "prompt") and not self.terminator:
            raise HarnessError(f"framing mode {self.mode!r} needs a non-empty terminator")
        if self.mode == "prompt" and not self.prompt:
            raise HarnessError("framing mode 'prompt' needs a non-empty prompt delimiter")
        if self.mode == "length":
            if not 1 <= int(self.length_bytes) <= 8:
                raise HarnessError(f"framing length_bytes must be 1..8, got {self.length_bytes!r}")
            if self.byteorder not in ("big", "little"):
                raise HarnessError(f"framing byteorder must be 'big' or 'little', got {self.byteorder!r}")

    def frame(self, payload) -> bytes:
        """The exact bytes to put on the wire for `payload` under this framing."""
        payload = _as_bytes(payload)
        if self.mode == "raw":
            return payload
        if self.mode in ("line", "prompt"):
            return payload + self.terminator
        n = len(payload)
        try:
            prefix = n.to_bytes(self.length_bytes, self.byteorder)
        except OverflowError:
            raise HarnessError(f"payload of {n} bytes does not fit a {self.length_bytes}-byte length "
                               f"prefix") from None
        return prefix + payload

    def complete(self, buf: bytes):
        """(frame_body, rest) when `buf` holds a complete response, else (None, buf).

        In "raw" mode any non-empty buffer is already one response; the caller does a single read.
        """
        if self.mode == "raw":
            return (buf, b"") if buf else (None, buf)
        if self.mode == "line":
            i = buf.find(self.terminator)
            if i < 0:
                return None, buf
            return buf[:i], buf[i + len(self.terminator):]
        if self.mode == "prompt":
            i = buf.find(self.prompt)
            if i < 0:
                return None, buf
            end = i + len(self.prompt)
            return buf[:end], buf[end:]
        # length
        w = self.length_bytes
        if len(buf) < w:
            return None, buf
        n = int.from_bytes(buf[:w], self.byteorder)
        if len(buf) < w + n:
            return None, buf
        return buf[w:w + n], buf[w + n:]


# ======================================================================================
#  PASS/FAIL result and oracle builders (the caller decides what a win looks like).
# ======================================================================================

@dataclass(frozen=True)
class ProbeResult:
    verdict: str                 # PASS | FAIL
    request: bytes               # the exact payload sent (pre-framing)
    response: bytes              # the exact response body (post-deframing)

    @property
    def passed(self) -> bool:
        return self.verdict == PASS


Oracle = Callable[[bytes], bool]


def contains(marker) -> Oracle:
    """PASS when the response contains `marker` (bytes/str)."""
    m = _as_bytes(marker)
    return lambda resp: m in resp


def not_contains(marker) -> Oracle:
    m = _as_bytes(marker)
    return lambda resp: m not in resp


def matches(pattern) -> Oracle:
    """PASS when the response matches a compiled/byte regex `pattern`."""
    import re
    rx = pattern if hasattr(pattern, "search") else re.compile(_as_bytes(pattern), re.S)
    return lambda resp: rx.search(resp) is not None


def flag_oracle(profile=None) -> Oracle:
    """PASS when the response contains a flag in the event's flag format (ctf.flagfmt).

    `profile` is an EventProfile; without one the current event's format is used. This is the loop that
    turns "beat the service" into a stop: the harness fires the caller's candidates until the target
    hands back a flag.
    """
    from ctf import flagfmt
    fmt = flagfmt.for_profile(profile) if profile is not None else flagfmt.current()
    return lambda resp: bool(fmt.find_flags(resp))


# ======================================================================================
#  Session: a scope-locked connection with framing, replay and a PASS/FAIL loop.
# ======================================================================================

class Session:
    """One framed conversation with one in-scope target. Mechanical: it sends the caller's bytes.

    Build it from a host+port, an existing `PwnTarget`, or `from_endpoint({"host","port"})` /
    `from_registry(name_or_url)`. The target is scope-checked (ctf.scope) before any socket opens.
    """

    def __init__(self, target, port=None, *, framing: Framing | None = None,
                 read_timeout: float = DEFAULT_READ_TIMEOUT, **target_kw):
        if isinstance(target, pt.PwnTarget):
            self.target = target
        else:
            self.target = pt.PwnTarget(target, port, **target_kw)
        self.framing = framing or Framing()
        self.read_timeout = float(read_timeout)
        self._buf = b""

    # -- factories ---------------------------------------------------------------------
    @classmethod
    def from_endpoint(cls, endpoint: Mapping, **kw) -> "Session":
        """Build from a connect-info mapping {"host","port", ...} (e.g. ctf.instances status)."""
        host = endpoint.get("host")
        port = endpoint.get("port")
        if not host or not port:
            raise ct.OutOfScope(f"endpoint needs host and port; got {endpoint!r}")
        return cls(str(host), int(port), **kw)

    @classmethod
    def from_registry(cls, name_or_url, **kw) -> "Session":
        framing = kw.pop("framing", None)
        read_timeout = kw.pop("read_timeout", DEFAULT_READ_TIMEOUT)
        target = pt.PwnTarget.from_registry(name_or_url, **kw)
        return cls(target, framing=framing, read_timeout=read_timeout)

    @property
    def host(self):
        return self.target.host

    @property
    def port(self):
        return self.target.port

    @property
    def transcript(self):
        return self.target.transcript

    def save_transcript(self, path):
        return self.target.save_transcript(path)

    # -- connection ---------------------------------------------------------------------
    def connect(self):
        self.target.connect()
        return self

    def close(self):
        self.target.close()
        self._buf = b""

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()
        return False

    # -- raw wire (no framing) ----------------------------------------------------------
    def send_raw(self, data):
        """Send EXACTLY the bytes the caller passes. No framing, no payload generation."""
        self.target.send(data)

    def recv_raw(self, limit=pt.MAX_READ) -> bytes:
        """One best-effort read of whatever is buffered or arriving. Any framing leftover comes first."""
        if self._buf:
            out, self._buf = self._buf, b""
            return out
        return self.target.recv(limit)

    # -- framed wire --------------------------------------------------------------------
    def _read_frame(self, framing: Framing) -> bytes:
        deadline = time.monotonic() + self.read_timeout
        while True:
            body, rest = framing.complete(self._buf)
            if body is not None:
                self._buf = rest
                return body
            if time.monotonic() >= deadline:
                raise HarnessError(
                    f"framing {framing.mode!r}: no complete response within {self.read_timeout}s "
                    f"({len(self._buf)} byte(s) buffered)")
            chunk = self.target.recv()
            if not chunk:
                # raw mode: a closed/empty read ends the response. Others: keep waiting until deadline.
                if framing.mode == "raw":
                    out, self._buf = self._buf, b""
                    return out
                continue
            self._buf += chunk

    def banner(self, framing: Framing | None = None) -> bytes:
        """Read the service's opening banner/prompt (one frame). Logged; returned as DATA."""
        return self._read_frame(framing or self.framing)

    def request(self, payload, framing: Framing | None = None) -> bytes:
        """Frame `payload`, send it, and read one framed response. The unit of replay and the loop."""
        fr = framing or self.framing
        self.send_raw(fr.frame(payload))
        return self._read_frame(fr)

    def replay(self, payloads: Iterable, framing: Framing | None = None) -> list:
        """Send a recorded sequence of payloads in order, returning each framed response."""
        return [self.request(p, framing) for p in payloads]

    # -- PASS/FAIL loop -----------------------------------------------------------------
    def check(self, payload, oracle: Oracle, framing: Framing | None = None) -> ProbeResult:
        """One request, judged by `oracle(response) -> bool`: PASS or FAIL."""
        resp = self.request(payload, framing)
        verdict = PASS if oracle(resp) else FAIL
        return ProbeResult(verdict, _as_bytes(payload), resp)

    def run_until(self, candidates: Iterable, oracle: Oracle,
                  framing: Framing | None = None) -> ProbeResult | None:
        """Fire `candidates` in order until one PASSes; return that result (or the last FAIL, or None)."""
        last = None
        for cand in candidates:
            last = self.check(cand, oracle, framing)
            if last.passed:
                return last
        return last


# ======================================================================================
#  Chain: an ordered exploit chain with a replayable "fast prefix" checkpoint.
# ======================================================================================

@dataclass
class Step:
    """One request in a chain. `fast=True` marks it as deterministic setup that is safe and quick to
    replay after a rotation (the fast prefix); the interactive/slow tail is `fast=False`. An `oracle`
    (optional) must PASS for the chain to continue past this step."""
    payload: bytes
    oracle: Oracle | None = None
    name: str = ""
    fast: bool = True


@dataclass
class Chain:
    """An ordered list of Steps with a checkpoint. `checkpoint` is the index of the last step that
    completed; `-1` means nothing has run. The *fast prefix* is the leading run of `fast` steps: on a
    rotation it is replayed on a fresh session to rebuild state before the tail resumes."""
    steps: list = field(default_factory=list)
    checkpoint: int = -1
    results: list = field(default_factory=list)

    def fast_prefix(self) -> list:
        out = []
        for s in self.steps:
            if not s.fast:
                break
            out.append(s)
        return out

    def _run_range(self, session: Session, start: int, stop: int,
                   framing: Framing | None, record: bool) -> list:
        res = []
        for i in range(start, stop):
            step = self.steps[i]
            r = session.check(step.payload, step.oracle or _always_pass, framing)
            res.append(r)
            if record:
                self.checkpoint = i
                self.results.append(r)
            if step.oracle is not None and not r.passed:
                raise HarnessError(
                    f"chain step {i}{' (' + step.name + ')' if step.name else ''} did not PASS its "
                    f"oracle; stopping before the next step")
        return res

    def run(self, session: Session, *, start: int = 0, framing: Framing | None = None) -> list:
        """Run steps [start, end) on `session`, recording progress. Raises on an oracle FAIL."""
        return self._run_range(session, start, len(self.steps), framing, record=True)

    def replay_prefix(self, session: Session, *, framing: Framing | None = None) -> list:
        """Re-run the fast prefix on a fresh `session` (no checkpoint change): rebuild state after a
        rotation. Raises if a prefix step's oracle FAILs (the new instance is not in the expected state)."""
        pref = self.fast_prefix()
        return self._run_range(session, 0, len(pref), framing, record=False)


def _always_pass(_resp: bytes) -> bool:
    return True


# ======================================================================================
#  Instance lifecycle: detect rotation, re-establish, replay the fast prefix.
# ======================================================================================

@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    remaining: float | None = None     # seconds until this instance rotates, if the source reports it

    @property
    def addr(self):
        return (self.host, int(self.port))


class InstanceLifecycle:
    """Track one assigned instance across its rotations.

    `source()` returns the instance's current connect info as a mapping with host/port (and optionally a
    `remaining` seconds field) -- e.g. `lambda: instances.status(cid)` from ctf.instances. The instance
    rotates (CSCTF's ~5-minute cycle), which hands out a NEW host:port; `session_factory(host, port)`
    builds a Session for it, and because that goes through PwnTarget the scope guard re-runs on the new
    endpoint. When a chain is supplied, re-establishing replays its fast prefix so the tail resumes.
    """

    def __init__(self, source: Callable[[], Mapping], session_factory: Callable[[str, int], Session],
                 *, chain: Chain | None = None):
        self.source = source
        self.session_factory = session_factory
        self.chain = chain
        self._endpoint: Endpoint | None = None
        self._session: Session | None = None

    @classmethod
    def from_instances(cls, instances, cid: int, session_factory: Callable[[str, int], Session],
                       **kw) -> "InstanceLifecycle":
        """Drive a ctf.instances.Instances-managed challenge instance: source = instances.status(cid)."""
        return cls(lambda: instances.status(cid), session_factory, **kw)

    def read_endpoint(self) -> Endpoint:
        """The instance's current endpoint from the source. Raises if the source gives no host/port."""
        info = self.source()
        if not isinstance(info, Mapping):
            raise HarnessError(f"instance source returned {type(info).__name__}, expected a mapping with "
                               f"host/port")
        host = info.get("host")
        port = info.get("port")
        if not host or not port:
            raise HarnessError(f"instance source gave no host/port (got {info!r}); the instance may not be "
                               f"started -- spawn it before driving it")
        rem = info.get("remaining")
        try:
            rem = float(rem) if rem is not None else None
        except (TypeError, ValueError):
            rem = None
        return Endpoint(str(host), int(port), rem)

    @property
    def endpoint(self) -> Endpoint | None:
        """The endpoint we last established a session on (not a fresh read)."""
        return self._endpoint

    def rotated(self) -> bool:
        """True when the source now reports a different host:port than our established session."""
        if self._endpoint is None:
            return False
        return self.read_endpoint().addr != self._endpoint.addr

    def rotation_imminent(self, threshold: float) -> bool:
        """True when the source reports `remaining <= threshold` seconds (rotate pre-emptively)."""
        if self._endpoint is None:
            return False
        rem = self.read_endpoint().remaining
        return rem is not None and rem <= threshold

    def _open(self) -> Session:
        """Open a fresh session to the current endpoint (no prefix replay). Scope is enforced inside
        session_factory -> PwnTarget, so a rotated, out-of-scope endpoint is refused here."""
        ep = self.read_endpoint()
        if self._session is not None:
            self._session.close()
        self._session = self.session_factory(ep.host, ep.port)
        self._endpoint = ep
        return self._session

    def establish(self, *, chain: Chain | None = None) -> tuple:
        """Re-establish after a rotation: open a fresh session AND replay the chain's fast prefix to
        rebuild state. Returns (session, prefix_results). Use for the rotation path; the initial run
        uses _open()/run_chain, which runs the prefix as ordinary steps exactly once."""
        session = self._open()
        chain = chain if chain is not None else self.chain
        prefix_results = chain.replay_prefix(session) if chain is not None else []
        return session, prefix_results

    def session(self, *, chain: Chain | None = None) -> Session:
        """A live session to the current endpoint. First call opens one; a rotation re-establishes and
        replays the fast prefix. An unchanged endpoint returns the existing session."""
        if self._session is None:
            return self._open()
        if self.rotated():
            return self.establish(chain=chain)[0]
        return self._session

    def run_chain(self, chain: Chain | None = None, *, framing: Framing | None = None,
                  rotation_threshold: float = 0.0, max_rotations: int = 16) -> list:
        """Run `chain` to completion across rotations.

        Before each step the source is polled: on a rotation (new host:port) or when `remaining` drops to
        `rotation_threshold`, a fresh session is opened and the fast prefix replayed, then the tail
        resumes after the prefix. A connection error mid-step is treated as a rotation too. Returns the
        chain's recorded results. Raises HarnessError if the instance rotates more than `max_rotations`
        times (a loop guard) or an oracle FAILs.
        """
        chain = chain if chain is not None else self.chain
        if chain is None:
            raise HarnessError("run_chain needs a chain (pass one, or construct the lifecycle with chain=)")
        prefix_len = len(chain.fast_prefix())
        if self._session is None:
            self._open()
        session = self._session
        i = max(chain.checkpoint + 1, 0)
        rotations = 0
        while i < len(chain.steps):
            try:
                if (self.rotated() or (rotation_threshold > 0 and self.rotation_imminent(rotation_threshold))):
                    rotations += 1
                    if rotations > max_rotations:
                        raise HarnessError(f"instance rotated more than max_rotations={max_rotations} "
                                           f"times; giving up rather than looping")
                    session, _ = self.establish(chain=chain)
                    i = max(i, prefix_len)
                    continue
                step = chain.steps[i]
                r = session.check(step.payload, step.oracle or _always_pass, framing)
            except (ct.VPNRequired, ConnectionError, OSError) as e:
                # A drop mid-exploit is a rotation on this platform: re-establish and replay the prefix.
                rotations += 1
                if rotations > max_rotations:
                    raise HarnessError(f"instance dropped and rotated more than max_rotations="
                                       f"{max_rotations} times: {e}") from e
                session, _ = self.establish(chain=chain)
                i = max(i, prefix_len)
                continue
            chain.checkpoint = i
            chain.results.append(r)
            if step.oracle is not None and not r.passed:
                raise HarnessError(
                    f"chain step {i}{' (' + step.name + ')' if step.name else ''} did not PASS its oracle")
            i += 1
        return chain.results


# ======================================================================================
#  Exploit primitives: mechanical byte helpers (no exploit logic; the caller supplies the values).
# ======================================================================================

def _as_bytes(x) -> bytes:
    if isinstance(x, str):
        return x.encode()
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    raise TypeError(f"expected bytes/str, got {type(x).__name__}")


def _pack(value: int, width: int, byteorder: str = "little", signed: bool = False) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"pack needs an int, got {type(value).__name__}")
    try:
        return value.to_bytes(width, byteorder, signed=signed)
    except OverflowError:
        raise HarnessError(f"value {value:#x} does not fit {width} byte(s) (signed={signed})") from None


def p8(v, **kw):  return _pack(v, 1, **kw)
def p16(v, **kw): return _pack(v, 2, **kw)
def p32(v, **kw): return _pack(v, 4, **kw)
def p64(v, **kw): return _pack(v, 8, **kw)


def _unpack(data, byteorder: str = "little", signed: bool = False) -> int:
    return int.from_bytes(_as_bytes(data), byteorder, signed=signed)


def u8(d, **kw):  return _unpack(_need(d, 1), **kw)
def u16(d, **kw): return _unpack(_need(d, 2), **kw)
def u32(d, **kw): return _unpack(_need(d, 4), **kw)
def u64(d, **kw): return _unpack(_need(d, 8), **kw)


def _need(data, width: int) -> bytes:
    b = _as_bytes(data)
    if len(b) != width:
        raise HarnessError(f"expected exactly {width} byte(s), got {len(b)}")
    return b


def flat(*parts) -> bytes:
    """Concatenate bytes/str/int parts (ints packed as 8-byte little-endian, the common pwn default)."""
    out = bytearray()
    for p in parts:
        out += p64(p) if isinstance(p, int) and not isinstance(p, bool) else _as_bytes(p)
    return bytes(out)


_CYCLIC_ALPHABET = b"abcdefghijklmnopqrstuvwxyz"


def cyclic(length: int, width: int = 4, alphabet: bytes = _CYCLIC_ALPHABET) -> bytes:
    """The first `length` bytes of a De Bruijn sequence over `alphabet` with `width`-byte uniqueness:
    every `width`-byte window in the prefix is distinct, so a crash's overwritten bytes name the offset
    (see cyclic_find). A mechanical offset-finding aid, not an exploit. `length` may not exceed the
    sequence capacity len(alphabet)**width (there are no more unique windows)."""
    if width < 1:
        raise HarnessError("cyclic width must be >= 1")
    if len(set(alphabet)) < 2:
        raise HarnessError("cyclic alphabet needs at least 2 distinct bytes")
    k = len(alphabet)
    capacity = k ** width
    if length > capacity:
        raise HarnessError(f"cyclic length {length} exceeds the unique capacity {capacity} "
                           f"(len(alphabet)={k} ** width={width}); widen the alphabet or width")
    seq = bytearray()
    a = [0] * (k * width)

    def db(t, p):
        if len(seq) >= length:
            return
        if t > width:
            if width % p == 0:
                for j in range(1, p + 1):
                    if len(seq) >= length:
                        return
                    seq.append(alphabet[a[j]])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for c in range(a[t - p] + 1, k):
                a[t] = c
                db(t + 1, t)
    db(1, 1)
    return bytes(seq[:length])


def cyclic_find(sub, width: int = 4, alphabet: bytes = _CYCLIC_ALPHABET) -> int:
    """The byte offset of `sub` (the first `width` bytes, or an int unpacked to `width`) within the
    cyclic() sequence, or -1. `sub` is typically the value found in a crashed register."""
    if isinstance(sub, int) and not isinstance(sub, bool):
        sub = sub.to_bytes(width, "little")
    sub = _as_bytes(sub)[:width]
    if len(sub) < width:
        raise HarnessError(f"cyclic_find needs at least {width} bytes, got {len(sub)}")
    full = cyclic(len(alphabet) ** width, width, alphabet)
    return full.find(sub)


# ======================================================================================
#  CLI (offline)
# ======================================================================================

def main(argv):
    if not argv:
        print("usage: live_harness.py framings | cyclic <n> [width] | find <hexbytes> [width]",
              file=sys.stderr)
        return 2
    cmd = argv[0]
    if cmd == "framings":
        for m in FRAMINGS:
            print(m)
        return 0
    if cmd == "cyclic":
        if len(argv) < 2 or not argv[1].isdigit():
            print("usage: live_harness.py cyclic <n> [width]", file=sys.stderr)
            return 2
        width = int(argv[2]) if len(argv) > 2 and argv[2].isdigit() else 4
        sys.stdout.buffer.write(cyclic(int(argv[1]), width) + b"\n")
        return 0
    if cmd == "find":
        if len(argv) < 2:
            print("usage: live_harness.py find <hexbytes> [width]", file=sys.stderr)
            return 2
        try:
            sub = bytes.fromhex(argv[1])
        except ValueError:
            print(f"not hex: {argv[1]!r}", file=sys.stderr)
            return 2
        width = int(argv[2]) if len(argv) > 2 and argv[2].isdigit() else 4
        print(cyclic_find(sub, width))
        return 0
    print(f"unknown command {cmd!r}; use: framings | cyclic | find", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
