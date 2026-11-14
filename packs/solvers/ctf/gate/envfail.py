"""Tell an ENVIRONMENT problem (Docker daemon down, a sandbox-denied bind, a missing external tool)
apart from a code defect, from a gate file's test outcomes alone (B-137).

On Oct 9 the Huntress acceptance gate went red on five of thirteen runs; three of those reds were not
code defects. Two were the environment: the Docker daemon was down behind a load-timing check, and a
sandbox denied a bind. A gate that paints those the same red as a real failure cries wolf, and the
real failure hides in the noise.

The gate never probes Docker, the network or a tool itself: that would be its own new source of
flakiness, and (for Docker) a forbidden touch of a production daemon. It classifies from the junit the
pytest child already wrote, plus the tail of the child's log. The rule is deliberately strict so a
broken test can never dress itself up as ENV:

    a file is ENV only when it has at least one failing or erroring case AND every failing/erroring
    message matches an environment signature.

One real assertion beside an environment one keeps the whole file red. The signatures are the two the
incident named (a Docker daemon that will not answer, a sandbox that denied a bind/listen/connect)
plus an explicit, auditable marker a test may emit on purpose: a line containing ``GATE-ENV: <reason>``
(or ``GATE_ENV``). A test that depends on a tool the gate cannot see — Ghidra, a built image — catches
its own specific "not available" error and re-raises it as ``GATE-ENV: ghidra not on PATH``; the gate
then reports ENV, not FAIL, and the operator is not sent chasing a green-code red.

ENV is not a pass. The file did not test what it set out to test, so its result is never stored warm
and the summary counts it apart. It is also not a FAIL: it does not make the gate red, because the
code under test is not what broke. The stable fail log (``ctf/gate/faillog.py``) lists ENV files under
their own heading so an arm run records what the environment, not the code, left unproven.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

# Each signature: (short name, compiled case-insensitive pattern). Kept narrow on purpose -- a pattern
# that matched a common assertion message would let a real failure masquerade as the environment.
_SIGNATURES: tuple[tuple[str, re.Pattern], ...] = (
    ("docker-daemon", re.compile(
        r"cannot connect to the docker daemon"
        r"|is the docker daemon running"
        r"|error while fetching server api version"
        r"|docker daemon is not (?:running|reachable|available)"
        r"|error response from daemon",
        re.IGNORECASE)),
    ("sandbox-deny", re.compile(
        r"deny\(1\) network"
        r"|sandbox-exec: .*not permitted"
        r"|(?:bind|listen|connect|socket)[^\n]{0,80}operation not permitted"
        r"|operation not permitted[^\n]{0,80}(?:bind|listen|connect|socket)"
        r"|sandbox[^\n]{0,40}(?:denied|blocked|forbidden)",
        re.IGNORECASE)),
    # An explicit, intentional marker: a test that knows its own environment is missing says so. This
    # is the supported way to flag a missing tool/image/corpus as ENV rather than a code failure.
    ("gate-env-marker", re.compile(r"GATE[-_]ENV\b\s*:?\s*(?P<reason>[^\n]*)", re.IGNORECASE)),
)


@dataclass(frozen=True)
class EnvVerdict:
    is_env: bool
    signature: str = ""     # the signature name that matched (the first one, when several did)
    reason: str = ""        # a short human reason for the row detail and the fail log

    def __bool__(self) -> bool:
        return self.is_env


def _match(message: str) -> tuple[str, str] | None:
    """(signature name, reason) for the first signature this one message matches, else None."""
    for name, rx in _SIGNATURES:
        m = rx.search(message)
        if m:
            reason = ""
            if "reason" in rx.groupindex:
                reason = (m.groupdict().get("reason") or "").strip()
            return name, reason
    return None


def classify(messages: list[str]) -> EnvVerdict:
    """Judge a file's failing/erroring messages. ENV only when there is at least one non-empty message
    and every non-empty message matches an environment signature. An empty list is not ENV (there was
    nothing to blame on the environment)."""
    seen = [m for m in messages if m and m.strip()]
    if not seen:
        return EnvVerdict(False)
    first_name, first_reason = "", ""
    for m in seen:
        hit = _match(m)
        if hit is None:
            return EnvVerdict(False)   # a message with no environment signature: a real failure, keep red
        if not first_name:
            first_name, first_reason = hit
    reason = first_reason or _DEFAULT_REASON.get(first_name, first_name)
    return EnvVerdict(True, signature=first_name, reason=reason)


_DEFAULT_REASON = {
    "docker-daemon": "the Docker daemon did not answer (environment, not the code)",
    "sandbox-deny": "the sandbox denied a socket operation (environment, not the code)",
    "gate-env-marker": "the test declared its environment unavailable",
}


def junit_bad_messages(path: Path) -> list[str]:
    """Every failing or erroring testcase's message, from a pytest junit XML: the `message` attribute
    and the element text of each <failure>/<error> child. A skipped-only case is not failing, so it is
    not included. Unreadable XML yields no messages (the caller falls back to the log tail)."""
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return []
    out: list[str] = []
    for tc in root.iter("testcase"):
        for child in tc:
            if child.tag in ("failure", "error"):
                parts = [child.get("message") or "", child.text or ""]
                joined = "\n".join(p for p in parts if p)
                out.append(joined)
    return out
