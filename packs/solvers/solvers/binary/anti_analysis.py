"""Static anti-debug, anti-VM, and anti-analysis evidence with inert notes.

Inputs are supplied bytes or saved disassembly/source text.  Findings never
patch an artifact or interact with a debugger/VM.  Defeat guidance is a
declarative review plan that requires proving the controlling branch first.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Iterable


MAX_INPUT = 16 << 20
MAX_FINDINGS = 512


class AntiAnalysisInputError(ValueError):
    pass


@dataclass(frozen=True)
class AntiAnalysisFinding:
    identifier: str
    category: str
    platform: str
    confidence: int
    offsets: tuple[int, ...]
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class DefeatNote:
    finding: str
    precondition: str
    declarative_action: str
    validation: str
    risk: str


@dataclass(frozen=True)
class AntiAnalysisReport:
    score: int
    findings: tuple[AntiAnalysisFinding, ...]
    defeat_notes: tuple[DefeatNote, ...]
    summary: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class _Rule:
    identifier: str
    category: str
    platform: str
    confidence: int
    literals: tuple[bytes, ...]
    require_all: bool = False


_RULES = (
    _Rule("win-debugger-api", "anti-debug", "windows", 96,
          (b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent")),
    _Rule("win-native-debug-query", "anti-debug", "windows", 94,
          (b"NtQueryInformationProcess", b"ProcessDebugPort"), True),
    _Rule("win-debug-object", "anti-debug", "windows", 92,
          (b"ProcessDebugObjectHandle", b"ProcessDebugFlags")),
    _Rule("win-debug-output", "anti-debug", "windows", 80,
          (b"OutputDebugStringA", b"OutputDebugStringW")),
    _Rule("linux-ptrace", "anti-debug", "linux", 93, (b"ptrace", b"PTRACE_TRACEME")),
    _Rule("linux-tracerpid", "anti-debug", "linux", 98,
          (b"/proc/self/status", b"TracerPid"), True),
    _Rule("mac-deny-attach", "anti-debug", "macos", 98, (b"PT_DENY_ATTACH",)),
    _Rule("mac-process-query", "anti-debug", "macos", 88,
          (b"KERN_PROC_PID", b"P_TRACED"), True),
    _Rule("timing-api", "timing", "cross-platform", 82,
          (b"QueryPerformanceCounter", b"GetTickCount", b"clock_gettime", b"mach_absolute_time")),
    _Rule("vmware-fingerprint", "anti-vm", "cross-platform", 96,
          (b"VMXh", b"VMware", b"vmtoolsd")),
    _Rule("virtualbox-fingerprint", "anti-vm", "cross-platform", 94,
          (b"VBox", b"VirtualBox", b"vboxservice")),
    _Rule("qemu-fingerprint", "anti-vm", "cross-platform", 91,
          (b"QEMU", b"qemu-ga", b"TCGTCGTCG")),
    _Rule("hypervisor-vendor", "anti-vm", "cross-platform", 91,
          (b"KVMKVMKVM", b"Microsoft Hv", b"XenVMMXenVMM", b"bhyve bhyve")),
    _Rule("dmi-fingerprint", "anti-vm", "linux", 83,
          (b"/sys/class/dmi/id", b"product_name", b"sys_vendor"), True),
    _Rule("analysis-process-list", "tool-detection", "cross-platform", 88,
          (b"x64dbg", b"ollydbg", b"procmon", b"wireshark", b"ida64", b"ghidra", b"frida", b"strace")),
    _Rule("resource-fingerprint", "sandbox", "cross-platform", 72,
          (b"GlobalMemoryStatusEx", b"GetSystemInfo", b"dwNumberOfProcessors")),
    _Rule("long-sleep", "sandbox", "cross-platform", 62,
          (b"NtDelayExecution", b"SleepEx", b"nanosleep")),
    # CRC32 by itself is ubiquitous in benign file/container parsing.  Keep
    # it as supporting evidence only; the explicit self-check strings remain
    # independently useful leads.
    _Rule("self-integrity", "integrity", "cross-platform", 78,
          (b"checksum mismatch", b"self checksum", b"verify_integrity")),
    _Rule("self-integrity-crc32", "integrity", "cross-platform", 84,
          (b"CRC32", b"checksum mismatch"), True),
    _Rule("environment-hook-check", "environment", "cross-platform", 84,
          (b"LD_PRELOAD", b"DYLD_INSERT_LIBRARIES", b"AppInit_DLLs")),
)


_TEXT_RULES: tuple[tuple[str, str, str, int, re.Pattern[str], str], ...] = (
    ("x86-rdtsc", "timing", "x86", 90, re.compile(r"(?im)^\s*(?:[0-9a-f]+:)?[^\n]{0,256}\brdtscp?\b"), "RDTSC/RDTSCP timing instruction"),
    ("x86-cpuid", "anti-vm", "x86", 82, re.compile(r"(?im)^\s*(?:[0-9a-f]+:)?[^\n]{0,256}\bcpuid\b"), "CPUID environment query"),
    ("x86-descriptor-query", "anti-vm", "x86", 78, re.compile(r"(?im)^\s*(?:[0-9a-f]+:)?[^\n]{0,256}\b(?:sidt|sgdt|sldt)\b"), "descriptor-table environment query"),
    ("trap-probe", "anti-debug", "cross-platform", 78, re.compile(r"(?im)^\s*(?:[0-9a-f]+:)?[^\n]{0,256}\b(?:int3|icebp|ud2|brk)\b"), "debugger-visible trap instruction"),
    ("peb-being-debugged", "anti-debug", "windows", 93,
     re.compile(r"(?is)(?:fs\s*:\s*\[\s*0x?30\s*\]|gs\s*:\s*\[\s*0x?60\s*\]).{0,160}(?:\+\s*2|BeingDebugged)"),
     "PEB BeingDebugged access"),
    ("ntglobalflag", "anti-debug", "windows", 91,
     re.compile(r"(?is)(?:NtGlobalFlag|PEB).{0,160}(?:0x68|0xbc).{0,80}(?:0x70|heap)"),
     "PEB NtGlobalFlag/heap debug flags"),
)


def _input(value: bytes | str) -> tuple[bytes, str]:
    if isinstance(value, bytes):
        raw = value
        text = value.decode("latin1", "replace")
    elif isinstance(value, str):
        text = value
        raw = value.encode("utf-8", "replace")
    else:
        raise TypeError("anti-analysis input must be bytes or text")
    if len(raw) > MAX_INPUT:
        raise AntiAnalysisInputError("input exceeds the 16 MiB cap")
    return raw, text


def _all_offsets(folded_haystack: bytes, folded_needle: bytes, cap: int = 16) -> tuple[int, ...]:
    offsets = []
    start = 0
    while len(offsets) < cap:
        offset = folded_haystack.find(folded_needle, start)
        if offset < 0:
            break
        offsets.append(offset)
        start = offset + 1
    return tuple(offsets)


def _note(finding: AntiAnalysisFinding) -> DefeatNote:
    common_precondition = "Trace data flow from this evidence to the exact controlling comparison/branch."
    common_validation = "Compare both modeled outcomes and confirm normal program semantics continue past the check."
    risk = "Do not patch marker strings or branches until checksum and shared-call-site effects are ruled out."
    actions = {
        "anti-debug": "Model the queried debug status as the documented non-debugged value in a reviewed sandbox trace.",
        "anti-vm": "Record the fingerprint inputs, then model a documented bare-metal value without changing unrelated CPUID/device data.",
        "timing": "Replace only the compared elapsed-time values with a deterministic plausible interval in the analysis model.",
        "tool-detection": "Model the process/module enumeration result with the named analysis tool absent.",
        "sandbox": "Model realistic resource or delay values; preserve the surrounding scheduling/control flow.",
        "integrity": "Identify the hashed byte ranges and expected digest before considering any separate code-path model.",
        "environment": "Model the queried environment key as absent while preserving all unrelated environment data.",
    }
    return DefeatNote(finding.identifier, common_precondition, actions[finding.category], common_validation, risk)


def analyze_anti_analysis(value: bytes | str) -> AntiAnalysisReport:
    raw, text = _input(value)
    folded = raw.lower()
    findings = []
    for rule in _RULES:
        matches = [(literal.decode("ascii", "replace"), _all_offsets(folded, literal.lower())) for literal in rule.literals]
        present = [(name, offsets) for name, offsets in matches if offsets]
        if (rule.require_all and len(present) != len(rule.literals)) or (not rule.require_all and not present):
            continue
        offsets = tuple(sorted({offset for _name, values in present for offset in values}))
        evidence = tuple(f"{name} at " + ",".join(f"0x{offset:x}" for offset in values) for name, values in present)
        confidence = rule.confidence if rule.require_all or len(present) > 1 else max(55, rule.confidence - 8)
        findings.append(AntiAnalysisFinding(rule.identifier, rule.category, rule.platform, confidence, offsets, evidence))
    for identifier, category, platform, confidence, pattern, explanation in _TEXT_RULES:
        matches = list(pattern.finditer(text))[:16]
        if matches:
            findings.append(AntiAnalysisFinding(
                identifier, category, platform, confidence,
                tuple(match.start() for match in matches),
                tuple([explanation, *(match.group(0).strip()[:160] for match in matches[:4])]),
            ))
    unique = {(row.identifier, row.offsets): row for row in findings}
    ordered = tuple(sorted(unique.values(), key=lambda row: (row.offsets[0] if row.offsets else MAX_INPUT,
                                                              row.category, row.identifier)))[:MAX_FINDINGS]
    categories = sorted({row.category for row in ordered})
    score = min(100, sum(max(5, row.confidence // 12) for row in ordered) + len(categories) * 4)
    summary = tuple(f"{category}: {sum(row.category == category for row in ordered)} finding(s)" for category in categories)
    return AntiAnalysisReport(score, ordered, tuple(_note(row) for row in ordered), summary)


def findings_by_category(report: AntiAnalysisReport, category: str) -> tuple[AntiAnalysisFinding, ...]:
    if not isinstance(report, AntiAnalysisReport):
        raise TypeError("report must be AntiAnalysisReport")
    allowed = {rule.category for rule in _RULES} | {row[1] for row in _TEXT_RULES}
    if category not in allowed:
        raise ValueError("unsupported anti-analysis category")
    return tuple(row for row in report.findings if row.category == category)


__all__ = [
    "AntiAnalysisInputError", "AntiAnalysisFinding", "DefeatNote", "AntiAnalysisReport",
    "analyze_anti_analysis", "findings_by_category",
]
