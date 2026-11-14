"""Strict not-run for the gate (B-196): a test file whose tests did not all run is not green.

At CSCTF a green suite hid skips: optional packages were missing on the run box until a human asked.
The pytest plugin already reports every test that did not run (ctf/testing/pytest_plugin.py); this
module reads the same facts from a child's junit report so `ctf gate run` can fail on them:

  * a `<skipped>` test case: its message is the skip reason (`needs_tool: radare2 not available`, ...),
    or for an xfail (`type="pytest.xfail"`) the xfail reason (`known-fail: ...` from known_failures.toml);
  * a `ctf_not_run` property: the parts of a test that ran but reported part of itself not run
    (pytest_plugin.record_not_run), each with its own reason.

Kinds are the plugin's (pytest_plugin.KINDS): needs_realdata, needs_tool, live, known-fail, xfail, skip.
The gate is strict by default: a file with any not-run item whose kind is not allowed is NOTRUN (red).
Allowed kinds come from tests/gate.toml `not_run_ok` plus `ctf gate run --allow-not-run KIND` ("any"
turns strictness off for the run, and the summary still counts what did not run).
"""
from __future__ import annotations

import ast
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

KINDS = ("needs_realdata", "needs_tool", "live", "known-fail", "xfail", "skip")
ANY = "any"
PROPERTY = "ctf_not_run"            # pytest_plugin.NOT_RUN_PROPERTY


@dataclass(frozen=True)
class NotRun:
    test: str                       # junit classname::name, plus [label] for a recorded part
    reason: str
    kind: str


def kind_of(reason: str, *, xfail: bool = False) -> str:
    """The plugin's kind for a skip reason (an xfail is `known-fail` or `xfail`)."""
    r = (reason or "").strip()
    if r.startswith("Skipped: "):
        r = r[len("Skipped: "):]
    if xfail:
        return "known-fail" if r.startswith("known-fail") else "xfail"
    for k in KINDS:
        if r == k or r.startswith(k + ":"):
            return k
    return "skip"


def from_junit(path: Path) -> list[NotRun]:
    """Every not-run item of one pytest junit report. Raises ET.ParseError on a broken report."""
    out = []
    root = ET.parse(path).getroot()
    for tc in root.iter("testcase"):
        name = f"{tc.get('classname', '')}::{tc.get('name', '')}"
        sk = tc.find("skipped")
        if sk is not None:
            xfail = sk.get("type") == "pytest.xfail"
            reason = sk.get("message") or (sk.text or "").strip() or ("xfail" if xfail else "skip")
            out.append(NotRun(name, reason, kind_of(reason, xfail=xfail)))
        props = tc.find("properties")
        for p in (props.findall("property") if props is not None else ()):
            if p.get("name") != PROPERTY:
                continue
            try:
                parts = ast.literal_eval(p.get("value", ""))
            except (ValueError, SyntaxError):
                out.append(NotRun(name, f"unreadable {PROPERTY} property", "skip"))
                continue
            for item in parts if isinstance(parts, (list, tuple)) else [parts]:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    reason, label = str(item[0]), str(item[1])
                    out.append(NotRun(f"{name} [{label}]", reason, kind_of(reason)))
                else:                     # never dropped: an unreadable part still did not run
                    out.append(NotRun(name, f"unreadable {PROPERTY} part {item!r:.60}", "skip"))
    return out


def check_allow(kinds) -> tuple[str, ...]:
    """Validate an allow list; raises ValueError naming an unknown kind."""
    kinds = tuple(kinds)
    bad = [k for k in kinds if k not in KINDS and k != ANY]
    if bad:
        raise ValueError(f"unknown not-run kind(s) {bad}; known: {', '.join(KINDS)} (or {ANY})")
    return kinds


def blocking(items, allow) -> list[NotRun]:
    """The items whose kind is not allowed (none when `any` is allowed)."""
    allow = set(allow)
    if ANY in allow:
        return []
    return [x for x in items if x.kind not in allow]
