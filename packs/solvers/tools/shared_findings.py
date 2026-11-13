"""Shared findings board with a pinned acceptance gate (B-165): the swarm's single source of truth.

When a dozen agents (and a couple of Codex sessions) race one static-RE challenge, they each
discover pieces -- an opcode's meaning, a decoded string, a candidate input. Without a shared log
they rediscover the same facts and, worse, each declares victory on an unproven guess. This board
is an append-only JSONL file every racer appends to under one exclusive OS advisory lock (so
concurrent appends never interleave), plus an **acceptance gate pinned to the board**.

The gate lives with the board, not with the writer: ``<stem>.gate.json`` next to the log holds the
gate's declarative spec (a digest to match, a regex the candidate must fully match, or a
predicate's name plus the sha256 of its code), and the log itself carries the same spec in a
``gate_pin`` anchor row (its first line on a fresh board). Both are written once (by ``ctf
re-workbench scaffold --gate-*``, or by the first board opened with a gate) and a board opened with
a different gate is refused. Deleting the gate file does not unpin the board (the anchor still
holds and refuses a looser gate); a gate file that no longer matches the anchor raises GateTampered
on accept and flags every accepted row on read. A regex that matches the empty string or arbitrary
unrelated text is refused as a gate. ``accept()`` runs the *pinned* gate, and every read re-runs
it: ``accepted()`` lists only rows that re-verify now, and ``audit()`` names every accepted-status
row that does not (forged by hand, accepted under another gate, or from a predicate gate the
reader did not supply). A row is never trusted for its status field alone. All of this is a guard
against racing agents' mistakes and shortcuts, not against a hostile local user: anyone who can
rewrite the files can rewrite both.

  FindingsBoard(path, gate=...)    the log; ``gate`` pins (or must equal) the board's gate
    .record(finding)               append a hypothesis / note / candidate
    .accept(finding)               run the pinned gate; append an accepted row or raise AcceptanceRejected
    .entries() / .latest()         every row / reduced by key (last wins; an accepted row is sticky)
    .audit()                       re-verify every accepted-status row: [Verdict(finding, ok, reason)]
    .accepted() / .flagged()       the rows that re-verify / the ones that do not
    .pin_gate(spec) / .pinned_gate() / .anchored_gate()

  digest_gate(algo, expected_hex)  accept iff hash(candidate) == expected (the preimage-of-a-compare case)
  regex_gate(pattern)              accept iff the candidate fully matches pattern
  flagfmt_gate(ff=None)            accept iff the candidate is a flag in the event's format (ctf.flagfmt)
  predicate_gate(check, name=...)  accept iff check(candidate_bytes) -- the agent's reimplemented
                                   validator. Its name and code digest are pinned (another callable
                                   under the same name is refused); a reader re-verifies it only by
                                   passing the same predicate, else the row is flagged.

Gate-passed is not platform-accepted: a passed candidate goes through ``ctf submit`` (the event's
submit_mode and SubmitGate decide). ``ledger_workdir=`` mirrors each accept to the event ledger as a
``candidate`` record.

This is operator / swarm infrastructure, not a challenge solver, so it lives in tools/ (on the
engine sys.path: ``import shared_findings`` works under tools/ctfpy and the suite) with no engine
manifest or triage route.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import time
import types
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

try:  # POSIX advisory locking; present on macOS and Linux. Absent = appends refuse (see _append).
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "FindingsError",
    "GateTampered",
    "AcceptanceRejected",
    "Finding",
    "FindingsBoard",
    "GateSpec",
    "Verdict",
    "digest_gate",
    "predicate_gate",
    "regex_gate",
    "flagfmt_gate",
    "gate_path",
    "code_digest",
    "KINDS",
    "STATUSES",
]

SCHEMA = 1
KINDS = ("hypothesis", "note", "candidate", "accepted")
STATUSES = ("open", "accepted", "rejected")
GATE_KINDS = ("digest", "regex", "predicate")
_FILE_MODE = 0o600          # the board holds candidate flags: owner-only, like ctf.ledger


class FindingsError(ValueError):
    """The findings log or its gate file is malformed, or a finding / gate is not well-formed."""


class GateTampered(FindingsError):
    """The board's gate file no longer matches the gate anchored in the log's ``gate_pin`` row: the
    gate was swapped after pinning. Nothing on the board is trusted until a human looks."""


class AcceptanceRejected(RuntimeError):
    """A finding did not pass the acceptance gate; ``reason`` says why. Nothing was accepted."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class Finding:
    """One entry on the board.

    key: a stable dedupe id (hypothesis name, "flag", an opcode id ...). agent: who recorded it.
    kind: hypothesis | note | candidate | accepted. candidate: a proposed input/flag. proof: free-form
    supporting data; an accepted row also carries ``proof["gate"]``, the pinned gate spec it passed.
    evidence: one-line human-checkable strings. status is set by the board (open on record, accepted
    on a passed gate).
    """

    key: str
    agent: str
    summary: str
    kind: str = "note"
    candidate: str | None = None
    evidence: tuple[str, ...] = ()
    proof: dict | None = None
    status: str = "open"
    ts: float = 0.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", tuple(self.evidence))
        if not self.key or not isinstance(self.key, str):
            raise FindingsError("finding.key must be a non-empty string")
        if not isinstance(self.agent, str) or not self.agent:
            raise FindingsError("finding.agent must be a non-empty string")
        if self.kind not in KINDS:
            raise FindingsError(f"finding.kind must be one of {', '.join(KINDS)}; got {self.kind!r}")
        if self.status not in STATUSES:
            raise FindingsError(f"finding.status must be one of {', '.join(STATUSES)}")

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "ts": self.ts,
            "key": self.key,
            "agent": self.agent,
            "kind": self.kind,
            "summary": self.summary,
            "candidate": self.candidate,
            "evidence": list(self.evidence),
            "proof": self.proof,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: dict, *, where: str = "") -> "Finding":
        if not isinstance(d, dict):
            raise FindingsError(f"{where}: a finding row must be a JSON object")
        if d.get("schema") != SCHEMA:
            raise FindingsError(f"{where}: unsupported findings schema (want {SCHEMA})")
        kind, status = d.get("kind", "note"), d.get("status", "open")
        if (kind == "accepted") != (status == "accepted"):
            raise FindingsError(
                f"{where}: inconsistent row: kind {kind!r} with status {status!r} "
                "(only accept() writes an accepted row, and it sets both)"
            )
        try:
            return cls(
                key=d["key"], agent=d["agent"], summary=d.get("summary", ""),
                kind=kind, candidate=d.get("candidate"),
                evidence=tuple(d.get("evidence", ())), proof=d.get("proof"),
                status=status, ts=float(d.get("ts", 0.0)),
            )
        except KeyError as exc:
            raise FindingsError(f"{where}: finding row missing field {exc}") from None


# ----------------------------------------------------------------------------------- gates

# A regex gate that fully matches every one of these unrelated strings constrains nothing ('.+',
# '[^\n]*', '\S+.*' ...): refused, like one that matches the empty string.
_UNRELATED_PROBES = ("junk", "Z", "0 9", "~!@#$%", "zz-zz{}", "été")

_PLAIN = (str, bytes, int, float, complex, bool, type(None), type(Ellipsis))


def code_digest(check: Callable) -> str:
    """sha256 over what a predicate *does*: its bytecode, constants (nested code objects included),
    the names it references, its argument shape, its default values and its closure values.

    The same source written again in another process (or another file) gives the same digest; a
    different function under the same name does not. Closure / default values must be plain data
    (str, bytes, numbers, None, tuples / lists / sets / dicts of those, compiled regexes) or Python
    functions (digested the same way); anything else is refused, since its state cannot be pinned.
    Limits: the *values* of module globals the predicate reads by name are not pinned (only their
    names), and the digest is tied to the Python version's bytecode -- every racer uses the same venv.
    """
    fn = check
    if not isinstance(fn, types.FunctionType):
        raise FindingsError(
            f"predicate_gate needs a plain Python function (its code is what gets pinned); got "
            f"{type(check).__name__}"
        )
    h = hashlib.sha256()

    def tag(t: bytes, payload: bytes = b"") -> None:
        h.update(t + len(payload).to_bytes(8, "big") + payload)

    def feed_code(c: types.CodeType, seen: set[int]) -> None:
        tag(b"code", c.co_code)
        tag(b"args", repr((c.co_argcount, c.co_posonlyargcount, c.co_kwonlyargcount, c.co_flags & 0x0F)).encode())
        tag(b"names", repr(c.co_names).encode())
        tag(b"consts", str(len(c.co_consts)).encode())
        for k in c.co_consts:
            feed_value(k, seen, "constant")

    def feed_value(v: object, seen: set[int], where: str) -> None:
        if isinstance(v, types.CodeType):
            feed_code(v, seen)
        elif isinstance(v, _PLAIN):
            tag(type(v).__name__.encode(), repr(v).encode())
        elif isinstance(v, (tuple, list)):
            tag(type(v).__name__.encode(), str(len(v)).encode())
            for item in v:
                feed_value(item, seen, where)
        elif isinstance(v, (set, frozenset)):
            items = sorted(v, key=repr)
            tag(b"set", str(len(items)).encode())
            for item in items:
                feed_value(item, seen, where)
        elif isinstance(v, dict):
            tag(b"dict", str(len(v)).encode())
            for key in sorted(v, key=repr):
                feed_value(key, seen, where)
                feed_value(v[key], seen, where)
        elif isinstance(v, re.Pattern):
            tag(b"re", repr((v.pattern, v.flags)).encode())
        elif isinstance(v, types.FunctionType):
            if id(v) in seen:              # a recursive helper: digest it once
                tag(b"fn-again", v.__qualname__.encode())
                return
            seen.add(id(v))
            feed_function(v, seen)
        else:
            raise FindingsError(
                f"predicate_gate cannot pin a {where} of type {type(v).__name__}; close over plain "
                "data (str/bytes/numbers/tuples/dicts) or Python functions"
            )

    def feed_function(f: types.FunctionType, seen: set[int]) -> None:
        feed_code(f.__code__, seen)
        feed_value(tuple(f.__defaults__ or ()), seen, "default value")
        feed_value(dict(f.__kwdefaults__ or {}), seen, "default value")
        cells = f.__closure__ or ()
        tag(b"closure", str(len(cells)).encode())
        for cell in cells:
            try:
                content = cell.cell_contents
            except ValueError:             # an empty cell (a name bound after the closure was made)
                tag(b"empty-cell")
                continue
            feed_value(content, seen, "closure value")

    feed_function(fn, {id(fn)})
    return h.hexdigest()


class GateSpec:
    """A declarative acceptance gate: serializable (``to_dict``) so it can be pinned to a board and
    re-run by any reader, and callable (``spec(finding) -> bool``).

    kind digest: params algo, expected (lower hex), encoding. kind regex: params pattern, ignorecase
    (fullmatch, no strip; a pattern that matches the empty string or arbitrary unrelated text is
    refused). kind predicate: params name and code (``code_digest`` of the predicate); the callable
    lives only in the process that built it, so a predicate gate is ``replayable`` only where the
    reader supplies a predicate with the same code digest.
    """

    def __init__(self, kind: str, params: dict, check: Callable[[bytes], bool] | None = None):
        if kind not in GATE_KINDS:
            raise FindingsError(f"gate kind must be one of {', '.join(GATE_KINDS)}; got {kind!r}")
        self.kind = kind
        self.params = dict(params)
        self._check = check
        if kind == "digest":
            algo, expected = self.params.get("algo"), self.params.get("expected")
            if not isinstance(algo, str) or not isinstance(expected, str):
                raise FindingsError("digest gate needs string algo and expected")
            try:
                hashlib.new(algo)
            except (ValueError, TypeError) as exc:
                raise FindingsError(f"unknown digest algorithm {algo!r}: {exc}") from None
            want = expected.strip().lower()
            if not want or any(ch not in "0123456789abcdef" for ch in want):
                raise FindingsError("digest gate expected must be a hex digest")
            self.params["expected"] = want
            self.params.setdefault("encoding", "utf-8")
        elif kind == "regex":
            pattern = self.params.get("pattern")
            if not isinstance(pattern, str):
                raise FindingsError("regex gate needs a string pattern")
            self.params["ignorecase"] = bool(self.params.get("ignorecase", False))
            try:
                self._rx = re.compile(pattern, re.IGNORECASE if self.params["ignorecase"] else 0)
            except re.error as exc:
                raise FindingsError(f"regex gate pattern does not compile: {exc}") from None
            if self._rx.fullmatch("") is not None:
                raise FindingsError(f"regex gate {pattern!r} accepts the empty string; a gate must constrain")
            if all(self._rx.fullmatch(p) is not None for p in _UNRELATED_PROBES):
                raise FindingsError(
                    f"regex gate {pattern!r} accepts arbitrary unrelated text "
                    f"({', '.join(map(repr, _UNRELATED_PROBES))}); a gate must constrain"
                )
        else:  # predicate
            name = self.params.get("name")
            if not isinstance(name, str) or not name:
                raise FindingsError("predicate gate needs a non-empty name (it is what gets pinned)")
            if check is not None:
                digest = code_digest(check)
                pinned = self.params.get("code", digest)
                if pinned != digest:
                    raise FindingsError(
                        f"predicate gate {name!r}: the callable's code digest {digest[:16]}... does not "
                        f"match the given digest {str(pinned)[:16]}..."
                    )
                self.params["code"] = digest
            code = self.params.get("code")
            if not isinstance(code, str) or len(code) != 64 or any(ch not in "0123456789abcdef" for ch in code):
                raise FindingsError(
                    f"predicate gate {name!r} needs the sha256 'code' digest of its predicate "
                    "(a pin by name alone can be spoofed by any callable)"
                )

    @property
    def replayable(self) -> bool:
        """True when this spec can re-run the check by itself (not a predicate without its callable)."""
        return self.kind != "predicate" or self._check is not None

    def to_dict(self) -> dict:
        return {"gate": self.kind, **self.params}

    @classmethod
    def from_dict(cls, d: dict, *, where: str = "gate") -> "GateSpec":
        if not isinstance(d, dict) or "gate" not in d:
            raise FindingsError(f"{where}: a gate spec must be a JSON object with a 'gate' field")
        params = {k: v for k, v in d.items() if k != "gate"}
        return cls(d["gate"], params)

    def same_as(self, other: "GateSpec") -> bool:
        return self.to_dict() == other.to_dict()

    def describe(self) -> str:
        if self.kind == "digest":
            return f"digest {self.params['algo']} == {self.params['expected']}"
        if self.kind == "regex":
            return f"regex fullmatch {self.params['pattern']!r}" + (" (ignorecase)" if self.params["ignorecase"] else "")
        return f"predicate {self.params['name']!r} (code sha256 {self.params['code'][:16]}...)"

    def __call__(self, f: Finding) -> bool:
        if f.candidate is None:
            return False
        if self.kind == "digest":
            raw = f.candidate.encode(self.params["encoding"])
            return hashlib.new(self.params["algo"], raw).hexdigest().lower() == self.params["expected"]
        if self.kind == "regex":
            return self._rx.fullmatch(f.candidate) is not None
        if self._check is None:
            raise FindingsError(
                f"predicate gate {self.params['name']!r} has no callable here; pass "
                "predicate_gate(check, name=...) to the board to run it"
            )
        return bool(self._check(f.candidate.encode("utf-8")))

    def __repr__(self) -> str:
        return f"GateSpec({self.describe()})"


def digest_gate(algo: str, expected_hex: str, *, encoding: str = "utf-8") -> GateSpec:
    """Accept iff ``hash(candidate)`` equals ``expected_hex`` -- the preimage-of-a-byte-compare case."""
    return GateSpec("digest", {"algo": algo, "expected": expected_hex, "encoding": encoding})


def regex_gate(pattern: str, *, ignorecase: bool = False) -> GateSpec:
    """Accept iff the candidate *fully* matches ``pattern`` (a partial match is rejected)."""
    return GateSpec("regex", {"pattern": pattern, "ignorecase": ignorecase})


def flagfmt_gate(ff=None) -> GateSpec:
    """Accept iff the candidate is one flag in the event's format: ``ff`` (a ctf.flagfmt.FlagFormat)
    or, when None, ``ctf.flagfmt.current()`` (raises ctf.event.EventError when no event resolves).
    Pinned as the compiled flag regex, so a reader re-verifies without loading the event."""
    if ff is None:
        try:
            from ctf import flagfmt  # noqa: PLC0415
        except ModuleNotFoundError:  # a bare run with only tools/ on sys.path
            import sys as _sys  # noqa: PLC0415
            _sys.path.append(str(Path(__file__).resolve().parents[1]))
            from ctf import flagfmt  # noqa: PLC0415
        ff = flagfmt.current()
    rx = ff.regex
    return GateSpec("regex", {"pattern": rx.pattern, "ignorecase": bool(rx.flags & re.IGNORECASE)})


def predicate_gate(check: Callable[[bytes], bool], *, name: str | None = None) -> GateSpec:
    """Accept iff ``check(candidate_bytes)`` is true -- the agent's reimplemented validator.

    ``name`` (default: the function's ``__name__``; a lambda needs an explicit name) and the
    predicate's ``code_digest`` are what get pinned, so another callable under the same name is
    refused. A reader without the same predicate cannot re-verify these rows: ``audit`` flags them."""
    label = name or getattr(check, "__name__", "")
    if not label or label == "<lambda>":
        raise FindingsError("predicate_gate needs name=... for a lambda (the name is what gets pinned)")
    return GateSpec("predicate", {"name": label}, check)


def gate_path(board_path: str | os.PathLike) -> Path:
    """The pinned-gate file of a board: ``findings.jsonl`` -> ``findings.gate.json``."""
    p = Path(board_path)
    return p.with_name(p.stem + ".gate.json")


@dataclass(frozen=True)
class Verdict:
    finding: Finding
    ok: bool
    reason: str          # "" when ok; why the row does not re-verify otherwise


# ----------------------------------------------------------------------------------- board

class FindingsBoard:
    """Append-only JSONL findings log shared by a swarm, with an acceptance gate pinned to it.

    ``gate`` is a GateSpec (``digest_gate`` / ``regex_gate`` / ``flagfmt_gate`` / ``predicate_gate``).
    A board with no pinned gate pins the one given; a board already pinned refuses a different one
    (a racer cannot swap in a looser gate). A predicate gate's callable is kept for this process.
    Appends hold an exclusive advisory lock so concurrent writers never interleave a line.
    """

    def __init__(self, path: str | os.PathLike, gate: GateSpec | None = None, *,
                 ledger_workdir: str | os.PathLike | None = None):
        self.path = Path(path)
        self.ledger_workdir = None if ledger_workdir is None else Path(ledger_workdir)
        if gate is not None and not isinstance(gate, GateSpec):
            raise FindingsError(
                "gate must be a GateSpec (digest_gate / regex_gate / flagfmt_gate / predicate_gate); "
                "a bare callable cannot be pinned or re-verified by other readers"
            )
        self.gate = gate
        if gate is not None:
            self.pin_gate(gate)

    # -- the pinned gate ---------------------------------------------------------------------

    @property
    def gate_file(self) -> Path:
        return gate_path(self.path)

    def _gate_file_spec(self) -> GateSpec | None:
        gf = self.gate_file
        if not gf.exists():
            return None
        try:
            data = json.loads(gf.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise FindingsError(f"{gf}: not JSON: {exc}") from None
        return GateSpec.from_dict(data, where=str(gf))

    def anchored_gate(self) -> GateSpec | None:
        """The gate recorded in the log's first ``gate_pin`` row (the anchor), or None."""
        for where, obj in self._rows():
            if "gate_pin" in obj:
                return GateSpec.from_dict(obj["gate_pin"], where=f"{where} gate_pin")
        return None

    def pinned_gate(self) -> GateSpec | None:
        """The board's pinned gate (None if none is pinned). A predicate spec gets this board's
        callable when the board was opened with the same predicate gate.

        The gate file and the log's anchor row must agree: a gate file changed after pinning raises
        GateTampered. A deleted gate file does not unpin the board -- the anchor still holds."""
        on_file = self._gate_file_spec()
        anchor = self.anchored_gate()
        if on_file is not None and anchor is not None and not on_file.same_as(anchor):
            raise GateTampered(
                f"{self.gate_file} holds [{on_file.describe()}] but {self.path} was pinned to "
                f"[{anchor.describe()}] (its gate_pin row); the gate file was changed after pinning"
            )
        spec = on_file or anchor
        if spec is not None and spec.kind == "predicate" and self.gate is not None and self.gate.same_as(spec):
            spec = self.gate
        return spec

    def pin_gate(self, spec: GateSpec) -> GateSpec:
        """Pin ``spec`` as the board's gate (write-once): the gate file plus a ``gate_pin`` anchor row
        in the log (its first line on a fresh board). Re-pinning the same spec is a no-op (it restores
        a deleted gate file or a missing anchor); a different spec raises FindingsError naming both."""
        if not isinstance(spec, GateSpec):
            raise FindingsError("pin_gate needs a GateSpec")
        existing = self.pinned_gate()
        if existing is not None and not existing.same_as(spec):
            raise FindingsError(
                f"board {self.path} is pinned to gate [{existing.describe()}]; refusing "
                f"[{spec.describe()}] (the gate is write-once; see {self.gate_file.name})"
            )
        if not self.gate_file.exists():
            self._publish_gate_file(spec)
        self._append_anchor(spec)
        return self.pinned_gate()  # type: ignore[return-value]

    def _append_anchor(self, spec: GateSpec) -> None:
        """Append the ``gate_pin`` row unless the log already has one (checked under the lock)."""
        row = {"schema": SCHEMA, "ts": time.time(), "gate_pin": spec.to_dict()}
        with self._locked() as fd:
            existing = self.anchored_gate()
            if existing is not None:
                if not existing.same_as(spec):     # another racer anchored a different gate first
                    raise FindingsError(
                        f"board {self.path} is pinned to gate [{existing.describe()}]; refusing "
                        f"[{spec.describe()}] (the gate is write-once)"
                    )
                return
            os.write(fd, (json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8"))
            os.fsync(fd)

    def _publish_gate_file(self, spec: GateSpec) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = (json.dumps(spec.to_dict(), sort_keys=True) + "\n").encode("utf-8")
        # write a private temp file, then hard-link it into place: the link fails if another racer
        # pinned first, and a reader never sees a half-written gate file
        tmp = self.gate_file.with_name(f".{self.gate_file.name}.{os.getpid()}.{time.time_ns()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _FILE_MODE)
        try:
            try:
                os.write(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(tmp, self.gate_file)
            except FileExistsError:        # another racer pinned between our check and now
                other = self._gate_file_spec()
                if other is not None and not other.same_as(spec):
                    raise FindingsError(
                        f"board {self.path} is pinned to gate [{other.describe()}]; refusing "
                        f"[{spec.describe()}] (the gate is write-once; see {self.gate_file.name})"
                    ) from None
        finally:
            tmp.unlink(missing_ok=True)

    # -- writing --------------------------------------------------------------------------

    def _append(self, finding: Finding) -> Finding:
        stamped = finding if finding.ts else replace(finding, ts=time.time())
        line = json.dumps(stamped.to_dict(), separators=(",", ":"), ensure_ascii=False) + "\n"
        with self._locked() as fd:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        return stamped

    @contextlib.contextmanager
    def _locked(self):
        """An append descriptor on the log holding the exclusive advisory lock."""
        if fcntl is None:
            raise FindingsError(
                "fcntl advisory locking is unavailable on this platform; refusing to append "
                "unlocked (concurrent racers could interleave lines)"
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, _FILE_MODE)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield fd
        finally:
            os.close(fd)            # closing the descriptor releases the flock

    def record(self, finding: Finding) -> Finding:
        """Append a hypothesis / note / candidate. Its status stays ``open`` (use ``accept`` to gate)."""
        if finding.kind == "accepted" or finding.status == "accepted":
            raise FindingsError("use accept() to add an accepted finding; record() never accepts")
        return self._append(finding)

    def accept(self, finding: Finding) -> Finding:
        """Run the board's pinned gate; on a pass append an ``accepted`` row, else raise.

        The row written carries ``proof["gate"]`` (the pinned spec it passed), so a reader can replay
        the check. Nothing is written on a rejection.
        """
        gate = self.pinned_gate()
        if gate is None:
            raise FindingsError(
                f"board {self.path} has no pinned acceptance gate; open it with gate=... or "
                "scaffold it with --gate-digest / --gate-regex / --gate-flagfmt"
            )
        if finding.candidate is None:
            raise AcceptanceRejected("no candidate value to accept")
        if not gate.replayable:
            raise FindingsError(
                f"board is pinned to {gate.describe()}; open it with that predicate_gate to accept"
            )
        if not gate(finding):
            raise AcceptanceRejected(
                f"candidate {finding.candidate!r} failed the acceptance gate [{gate.describe()}]"
            )
        proof = dict(finding.proof or {})
        proof["gate"] = gate.to_dict()
        accepted = self._append(replace(finding, kind="accepted", status="accepted", proof=proof))
        if self.ledger_workdir is not None:
            self._mirror_to_ledger(accepted, gate)
        return accepted

    def _mirror_to_ledger(self, f: Finding, gate: GateSpec) -> None:
        try:
            from ctf import ledger  # noqa: PLC0415
        except ModuleNotFoundError:  # a bare run with only tools/ on sys.path
            import sys as _sys  # noqa: PLC0415
            _sys.path.append(str(Path(__file__).resolve().parents[1]))
            from ctf import ledger  # noqa: PLC0415
        ledger.append("candidate", workdir=self.ledger_workdir, engine="tools.shared_findings",
                      key=f.key, agent=f.agent, candidate=f.candidate, gate=gate.kind,
                      board=str(self.path))

    # -- reading --------------------------------------------------------------------------

    def _rows(self):
        """(where, object) for every non-blank line; a line that is not a JSON object raises."""
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, 1):
                raw = raw.strip()
                if not raw:
                    continue
                where = f"{self.path}:{lineno}"
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise FindingsError(f"{where}: not JSON: {exc}") from None
                if not isinstance(obj, dict):
                    raise FindingsError(f"{where}: a row must be a JSON object")
                yield where, obj

    def entries(self) -> list[Finding]:
        """Every finding row in log order (``gate_pin`` anchor rows are not findings). A malformed
        row raises FindingsError naming its line number."""
        return [Finding.from_dict(obj, where=where) for where, obj in self._rows() if "gate_pin" not in obj]

    def latest(self) -> dict[str, Finding]:
        """Reduce the log by key, last row wins -- except that a later open row never replaces an
        accepted one (a note recorded under "flag" must not hide the flag). Raw: use accepted() for
        the rows that re-verify."""
        out: dict[str, Finding] = {}
        for f in self.entries():
            prev = out.get(f.key)
            if prev is not None and prev.status == "accepted" and f.status != "accepted":
                continue
            out[f.key] = f
        return out

    def audit(self) -> list[Verdict]:
        """Re-verify every accepted-status row in the log (all of them, not a last-wins reduction)
        against the pinned gate, now. A row passes only if the gate re-runs and accepts it."""
        rows = [f for f in self.entries() if f.status == "accepted"]
        if not rows:
            return []
        try:
            gate = self.pinned_gate()
        except GateTampered as exc:
            return [Verdict(f, False, f"untrusted: {exc}") for f in rows]
        out: list[Verdict] = []
        for f in rows:
            if gate is None:
                out.append(Verdict(f, False, "unverifiable: the board has no pinned gate"))
            elif not gate.replayable:
                out.append(Verdict(f, False, f"unverifiable here: {gate.describe()} not supplied to this reader"))
            elif not gate(f):
                out.append(Verdict(f, False, f"fails the pinned gate [{gate.describe()}]"))
            else:
                out.append(Verdict(f, True, ""))
        return out

    def accepted(self) -> list[Finding]:
        """Every accepted row that re-verifies against the pinned gate now, in log order."""
        return [v.finding for v in self.audit() if v.ok]

    def flagged(self) -> list[Verdict]:
        """Accepted-status rows that do not re-verify (forged, other gate, or unverifiable here)."""
        return [v for v in self.audit() if not v.ok]
