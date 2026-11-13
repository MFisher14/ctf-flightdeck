#!/usr/bin/env python3
"""Offline Linux Kconfig and runtime-fact attack-surface profiler.

The profiler consumes caller-supplied text only.  It never reads ``/proc``,
contacts a host, executes a binary, or turns a documented default into an
observed runtime fact.  Missing Kconfig symbols and missing runtime controls
remain ``unknown``; only an explicit ``# CONFIG_FOO is not set`` (or ``=n``)
is build-time evidence that a symbol is off.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from functools import wraps
import json
from pathlib import Path
import re
import shlex
import sys
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence, TypeVar, cast


MAX_INPUT_BYTES = 2 << 20
MAX_CONFIG_LINES = 100_000
MAX_CONFIG_SYMBOLS = 50_000
MAX_SYSCTL_FACTS = 4_096
MAX_CMDLINE_BYTES = 64 << 10
MAX_CMDLINE_TOKENS = 4_096
MAX_VALUE_LENGTH = 8_192

BUILD_STATES = frozenset(("on", "off", "module", "unknown"))
RUNTIME_STATES = frozenset(("on", "off", "restricted", "not-applicable", "unknown"))
EFFECTIVE_STATES = frozenset(("on", "off", "restricted", "unknown"))

# Kconfig symbols are conventionally uppercase, but real upstream symbols such
# as CONFIG_SCSI_DC395x retain lowercase characters.
_CONFIG_NAME = re.compile(r"CONFIG_[A-Za-z0-9_]+\Z")
_CONFIG_UNSET = re.compile(r"# (CONFIG_[A-Za-z0-9_]+) is not set\Z")
_CONFIG_ASSIGN = re.compile(r"(CONFIG_[A-Za-z0-9_]+)=(.*)\Z")
_SYSCTL_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")
_CMDLINE_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")


class WpgapKconfigError(ValueError):
    """A supplied config/fact set is malformed, ambiguous, or too large."""


_F = TypeVar("_F", bound=Callable[..., Any])


def _fail_closed(function: _F) -> _F:
    """Normalize malformed public API inputs to :class:`WpgapKconfigError`."""

    @wraps(function)
    def guarded(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except WpgapKconfigError:
            raise
        except Exception as exc:
            raise WpgapKconfigError(
                f"{function.__name__} received malformed input"
            ) from exc

    return cast(_F, guarded)


@dataclass(frozen=True)
class KconfigFacts:
    """Parsed Kconfig values and their exact source lines."""

    values: Mapping[str, str]
    evidence: Mapping[str, str]

    def __post_init__(self) -> None:
        try:
            if not isinstance(self.values, Mapping) or not isinstance(self.evidence, Mapping):
                raise WpgapKconfigError("Kconfig facts must be mappings")
            values = dict(self.values)
            evidence = dict(self.evidence)
            if any(not isinstance(key, str) or not isinstance(value, str) for key, value in values.items()):
                raise WpgapKconfigError("Kconfig facts must contain text names and values")
            if any(not isinstance(key, str) or not isinstance(value, str) for key, value in evidence.items()):
                raise WpgapKconfigError("Kconfig evidence must contain text names and lines")
            if set(values) != set(evidence):
                raise WpgapKconfigError("Kconfig values and evidence must name the same symbols")
            object.__setattr__(self, "values", MappingProxyType(values))
            object.__setattr__(self, "evidence", MappingProxyType(evidence))
        except WpgapKconfigError:
            raise
        except Exception as exc:
            raise WpgapKconfigError("malformed Kconfig facts") from exc

    def state(self, name: str) -> str:
        if not isinstance(name, str):
            raise WpgapKconfigError("Kconfig symbol name must be text")
        value = self.values.get(name)
        if value == "y":
            return "on"
        if value == "m":
            return "module"
        if value == "n":
            return "off"
        return "unknown"

    def line(self, name: str) -> str | None:
        if not isinstance(name, str):
            raise WpgapKconfigError("Kconfig symbol name must be text")
        return self.evidence.get(name)


@dataclass(frozen=True)
class SysctlFacts:
    """Normalized, caller-supplied sysctl names and raw values."""

    values: Mapping[str, str]

    def __post_init__(self) -> None:
        try:
            if not isinstance(self.values, Mapping):
                raise WpgapKconfigError("sysctl facts must be a mapping")
            values = dict(self.values)
            if any(not isinstance(key, str) or not isinstance(value, str) for key, value in values.items()):
                raise WpgapKconfigError("sysctl facts must contain text names and values")
            object.__setattr__(self, "values", MappingProxyType(values))
        except WpgapKconfigError:
            raise
        except Exception as exc:
            raise WpgapKconfigError("malformed sysctl facts") from exc


@dataclass(frozen=True)
class CmdlineFacts:
    """Parsed post-boot kernel command-line tokens (last assignment wins)."""

    tokens: tuple[str, ...]
    values: Mapping[str, str | None]

    def __post_init__(self) -> None:
        try:
            if not isinstance(self.tokens, tuple) or any(not isinstance(token, str) for token in self.tokens):
                raise WpgapKconfigError("cmdline tokens must be a tuple of text")
            if not isinstance(self.values, Mapping):
                raise WpgapKconfigError("cmdline facts must be a mapping")
            values = dict(self.values)
            if any(
                not isinstance(key, str) or (value is not None and not isinstance(value, str))
                for key, value in values.items()
            ):
                raise WpgapKconfigError("cmdline facts contain invalid names or values")
            object.__setattr__(self, "values", MappingProxyType(values))
        except WpgapKconfigError:
            raise
        except Exception as exc:
            raise WpgapKconfigError("malformed cmdline facts") from exc

    def has(self, name: str) -> bool:
        if not isinstance(name, str):
            raise WpgapKconfigError("kernel parameter name must be text")
        return name in self.values

    def value(self, name: str) -> str | None:
        if not isinstance(name, str):
            raise WpgapKconfigError("kernel parameter name must be text")
        return self.values.get(name)


@dataclass(frozen=True)
class Finding:
    """One mitigation or attack-surface conclusion with source evidence."""

    name: str
    category: str
    build_state: str
    runtime_state: str
    effective_state: str
    evidence: tuple[str, ...]
    caveats: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        try:
            if not isinstance(self.name, str) or not self.name:
                raise WpgapKconfigError("finding name is invalid")
            if not isinstance(self.category, str) or self.category not in {"mitigation", "primitive"}:
                raise WpgapKconfigError("finding category is invalid")
            if not isinstance(self.build_state, str) or self.build_state not in BUILD_STATES:
                raise WpgapKconfigError("finding build state is invalid")
            if not isinstance(self.runtime_state, str) or self.runtime_state not in RUNTIME_STATES:
                raise WpgapKconfigError("finding runtime state is invalid")
            if not isinstance(self.effective_state, str) or self.effective_state not in EFFECTIVE_STATES:
                raise WpgapKconfigError("finding effective state is invalid")
            if not isinstance(self.evidence, tuple) or any(not isinstance(item, str) for item in self.evidence):
                raise WpgapKconfigError("finding evidence must be a tuple of text")
            if not isinstance(self.caveats, tuple) or any(not isinstance(item, str) for item in self.caveats):
                raise WpgapKconfigError("finding caveats must be a tuple of text")
        except WpgapKconfigError:
            raise
        except Exception as exc:
            raise WpgapKconfigError("malformed finding") from exc

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "category": self.category,
            "build_state": self.build_state,
            "runtime_state": self.runtime_state,
            "effective_state": self.effective_state,
            "evidence": list(self.evidence),
            "caveats": list(self.caveats),
        }


@dataclass(frozen=True)
class KernelProfile:
    """Deterministic static profile; no live target was queried."""

    findings: tuple[Finding, ...]
    config_symbol_count: int
    sysctl_fact_count: int
    cmdline_token_count: int

    def __post_init__(self) -> None:
        try:
            if not isinstance(self.findings, tuple) or any(not isinstance(item, Finding) for item in self.findings):
                raise WpgapKconfigError("profile findings must be a tuple of Finding values")
            counts = (self.config_symbol_count, self.sysctl_fact_count, self.cmdline_token_count)
            if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
                raise WpgapKconfigError("profile input counts must be nonnegative integers")
        except WpgapKconfigError:
            raise
        except Exception as exc:
            raise WpgapKconfigError("malformed kernel profile") from exc

    def get(self, name: str) -> Finding:
        if not isinstance(name, str):
            raise WpgapKconfigError("finding name must be text")
        for finding in self.findings:
            if finding.name == name:
                return finding
        raise WpgapKconfigError(f"unknown finding: {name}")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "wpgap-kconfig-profile-v1",
            "offline": True,
            "live_requests": 0,
            "state_contract": {
                "build": ["on", "off", "module", "unknown"],
                "runtime": ["on", "off", "restricted", "not-applicable", "unknown"],
                "effective": ["on", "off", "restricted", "unknown"],
                "missing_fact": "unknown",
            },
            "input_counts": {
                "config_symbols": self.config_symbol_count,
                "sysctl_facts": self.sysctl_fact_count,
                "cmdline_tokens": self.cmdline_token_count,
            },
            "findings": [finding.as_dict() for finding in self.findings],
        }


def _bounded_text(text: object, label: str, limit: int = MAX_INPUT_BYTES) -> str:
    if not isinstance(text, str):
        raise WpgapKconfigError(f"{label} must be text")
    if "\x00" in text:
        raise WpgapKconfigError(f"{label} contains NUL")
    try:
        length = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise WpgapKconfigError(f"{label} is not valid UTF-8 text") from exc
    if length > limit:
        raise WpgapKconfigError(f"{label} exceeds the bounded input limit")
    return text


def _decode_kconfig_string(raw: str, line_number: int) -> str:
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        raise WpgapKconfigError(f"unterminated Kconfig string on line {line_number}")
    result: list[str] = []
    index = 1
    while index < len(raw) - 1:
        char = raw[index]
        if char != "\\":
            if char == '"':
                raise WpgapKconfigError(f"unescaped quote on line {line_number}")
            result.append(char)
            index += 1
            continue
        index += 1
        if index >= len(raw) - 1 or raw[index] not in {'"', "\\"}:
            raise WpgapKconfigError(f"invalid Kconfig escape on line {line_number}")
        result.append(raw[index])
        index += 1
    return "".join(result)


@_fail_closed
def parse_kconfig(text: str) -> KconfigFacts:
    """Parse a full Kconfig output or fragment without inventing missing keys."""

    source = _bounded_text(text, "Kconfig")
    lines = source.splitlines()
    if len(lines) > MAX_CONFIG_LINES:
        raise WpgapKconfigError("Kconfig has too many lines")
    values: dict[str, str] = {}
    evidence: dict[str, str] = {}
    for line_number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        unset = _CONFIG_UNSET.fullmatch(stripped)
        if unset:
            name, value = unset.group(1), "n"
        else:
            assignment = _CONFIG_ASSIGN.fullmatch(stripped)
            if assignment:
                name, raw = assignment.groups()
                if not raw or len(raw) > MAX_VALUE_LENGTH:
                    raise WpgapKconfigError(f"invalid value on line {line_number}")
                if raw.startswith('"'):
                    value = _decode_kconfig_string(raw, line_number)
                else:
                    if any(char.isspace() for char in raw) or "#" in raw:
                        raise WpgapKconfigError(f"invalid unquoted value on line {line_number}")
                    value = raw
            elif stripped.startswith("CONFIG_") or stripped.startswith("# CONFIG_"):
                raise WpgapKconfigError(f"malformed Kconfig line {line_number}")
            else:
                continue
        if not _CONFIG_NAME.fullmatch(name):
            raise WpgapKconfigError(f"invalid Kconfig name on line {line_number}")
        if name in values:
            raise WpgapKconfigError(f"duplicate Kconfig symbol {name}")
        values[name] = value
        evidence[name] = stripped
        if len(values) > MAX_CONFIG_SYMBOLS:
            raise WpgapKconfigError("Kconfig has too many symbols")
    return KconfigFacts(values, evidence)


def _normalize_sysctl_name(name: object) -> str:
    if not isinstance(name, str):
        raise WpgapKconfigError("sysctl names must be text")
    result = name.strip()
    if result.startswith("/proc/sys/"):
        result = result[len("/proc/sys/"):]
    if result.startswith("sysctl."):
        result = result[len("sysctl."):]
    result = result.replace("/", ".")
    if not result or not _SYSCTL_NAME.fullmatch(result):
        raise WpgapKconfigError(f"invalid sysctl name: {name!r}")
    return result


def _normalize_sysctl_value(value: object, name: str) -> str:
    if isinstance(value, bool) or value is None or isinstance(value, (list, dict)):
        raise WpgapKconfigError(f"sysctl {name} must have a scalar value")
    if not isinstance(value, (str, int, float)):
        raise WpgapKconfigError(f"sysctl {name} must have a scalar value")
    result = str(value).strip()
    if "\x00" in result or len(result) > MAX_VALUE_LENGTH:
        raise WpgapKconfigError(f"invalid value for sysctl {name}")
    return result


def _json_object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise WpgapKconfigError(f"duplicate sysctl JSON key {name}")
        result[name] = value
    return result


@_fail_closed
def parse_sysctl_facts(text: str) -> SysctlFacts:
    """Parse flat JSON or ``name=value`` lines from a supplied snapshot."""

    source = _bounded_text(text, "sysctl facts")
    values: dict[str, str] = {}
    stripped_source = source.lstrip()
    if stripped_source.startswith("{"):
        try:
            document = json.loads(source, object_pairs_hook=_json_object_without_duplicates)
        except WpgapKconfigError:
            raise
        except (json.JSONDecodeError, RecursionError) as exc:
            raise WpgapKconfigError("sysctl JSON is malformed") from exc
        if not isinstance(document, dict):
            raise WpgapKconfigError("sysctl JSON must be an object")
        rows = list(document.items())
    else:
        rows: list[tuple[object, object]] = []
        for line_number, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" not in stripped:
                raise WpgapKconfigError(f"sysctl line {line_number} needs name=value")
            name, value = stripped.split("=", 1)
            rows.append((name, value))
    if len(rows) > MAX_SYSCTL_FACTS:
        raise WpgapKconfigError("too many sysctl facts")
    for raw_name, raw_value in rows:
        name = _normalize_sysctl_name(raw_name)
        if name in values:
            raise WpgapKconfigError(f"duplicate sysctl fact {name}")
        values[name] = _normalize_sysctl_value(raw_value, name)
    return SysctlFacts(values)


@_fail_closed
def parse_cmdline(text: str) -> CmdlineFacts:
    """Parse a supplied kernel command line; duplicate keys use the last token."""

    source = _bounded_text(text, "kernel command line", MAX_CMDLINE_BYTES)
    try:
        tokens = shlex.split(source, comments=False, posix=True)
    except ValueError as exc:
        raise WpgapKconfigError("kernel command line has invalid quoting") from exc
    if len(tokens) > MAX_CMDLINE_TOKENS:
        raise WpgapKconfigError("kernel command line has too many tokens")
    values: dict[str, str | None] = {}
    for token in tokens:
        if not token or len(token) > MAX_VALUE_LENGTH or "\x00" in token:
            raise WpgapKconfigError("kernel command line has an invalid token")
        name, separator, value = token.partition("=")
        if not _CMDLINE_NAME.fullmatch(name):
            raise WpgapKconfigError(f"invalid kernel parameter name: {name!r}")
        values[name] = value if separator else None
    return CmdlineFacts(tuple(tokens), values)


def _config_any(config: KconfigFacts, names: Sequence[str]) -> tuple[str, tuple[str, ...]]:
    observed = [(name, config.state(name)) for name in names if name in config.values]
    evidence = tuple(config.evidence[name] for name, _state in observed)
    states = {state for _name, state in observed}
    if "on" in states:
        return "on", evidence
    if "module" in states:
        return "module", evidence
    if "off" in states:
        return "off", evidence
    return "unknown", ()


def _config_one(config: KconfigFacts, name: str) -> tuple[str, tuple[str, ...]]:
    state = config.state(name)
    line = config.line(name)
    return state, (() if line is None else (line,))


def _config_int(config: KconfigFacts, name: str) -> tuple[int | None, tuple[str, ...]]:
    if name not in config.values:
        return None, ()
    raw = config.values[name]
    line = config.evidence[name]
    try:
        value = int(raw, 0)
    except (TypeError, ValueError, OverflowError):
        return None, (line,)
    return value, (line,)


def _fact_int(sysctls: SysctlFacts, name: str) -> tuple[int | None, tuple[str, ...]]:
    if name not in sysctls.values:
        return None, ()
    raw = sysctls.values[name]
    try:
        value = int(raw, 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise WpgapKconfigError(f"sysctl {name} must be an integer") from exc
    return value, (f"{name}={raw}",)


def _effective(build: str, runtime: str, *, static: bool = False) -> str:
    if build == "off" or runtime == "off":
        return "off"
    if static:
        return build if build in {"on", "off"} else "unknown"
    if runtime in {"on", "off", "restricted"} and build == "on":
        return runtime
    return "unknown"


def _finding(
    name: str,
    category: str,
    build: str,
    runtime: str,
    evidence: Sequence[str],
    caveats: Sequence[str] = (),
    *,
    static: bool = False,
    effective: str | None = None,
) -> Finding:
    return Finding(
        name=name,
        category=category,
        build_state=build,
        runtime_state=runtime,
        effective_state=(effective if effective is not None else _effective(build, runtime, static=static)),
        evidence=tuple(dict.fromkeys(item for item in evidence if item)),
        caveats=tuple(caveats),
    )


def _static_config_finding(
    config: KconfigFacts,
    name: str,
    symbols: Sequence[str],
    caveats: Sequence[str] = (),
) -> Finding:
    build, evidence = _config_any(config, symbols)
    runtime = "not-applicable" if build in {"on", "off"} else "unknown"
    return _finding(name, "mitigation", build, runtime, evidence, caveats, static=True)


def _cmd_value(cmdline: CmdlineFacts, name: str) -> tuple[bool, str | None, tuple[str, ...]]:
    if not cmdline.has(name):
        return False, None, ()
    value = cmdline.value(name)
    token = name if value is None else f"{name}={value}"
    return True, value, (f"cmdline:{token}",)


def _profile_control_flow(config: KconfigFacts, cmdline: CmdlineFacts) -> list[Finding]:
    findings: list[Finding] = []

    cfi_build, cfi_evidence = _config_any(config, ("CONFIG_CFI", "CONFIG_CFI_CLANG"))
    permissive = config.state("CONFIG_CFI_PERMISSIVE")
    has_cfi, cfi_value, cfi_cmd = _cmd_value(cmdline, "cfi")
    cfi_runtime = "unknown"
    if cfi_build == "off":
        cfi_runtime = "not-applicable"
    elif has_cfi and cfi_value == "off":
        cfi_runtime = "off"
    elif has_cfi and cfi_value == "warn":
        cfi_runtime = "restricted"
    elif permissive == "on":
        cfi_runtime = "restricted"
    elif has_cfi and cfi_value in {"kcfi", "fineibt"}:
        cfi_runtime = "on"
    findings.append(_finding(
        "forward_edge_cfi", "mitigation", cfi_build, cfi_runtime,
        (*cfi_evidence,
         *(line for line in (
             config.line("CONFIG_CFI_PERMISSIVE"), config.line("CONFIG_CFI_AUTO_DEFAULT"),
         ) if line is not None), *cfi_cmd),
        ("Build support alone does not prove runtime mode or compatible hardware.",),
    ))

    ibt_build, ibt_evidence = _config_one(config, "CONFIG_X86_KERNEL_IBT")
    has_ibt, ibt_value, ibt_cmd = _cmd_value(cmdline, "ibt")
    ibt_runtime = "not-applicable" if ibt_build == "off" else "unknown"
    if ibt_build != "off" and has_ibt and ibt_value == "off":
        ibt_runtime = "off"
    elif ibt_build != "off" and has_ibt and ibt_value == "warn":
        ibt_runtime = "restricted"
    findings.append(_finding(
        "x86_kernel_ibt", "mitigation", ibt_build, ibt_runtime,
        (*ibt_evidence, *ibt_cmd),
        ("Actual enforcement requires CET/IBT-capable hardware; upstream does not document ibt=on.",),
    ))

    fine_build, fine_evidence = _config_one(config, "CONFIG_FINEIBT")
    fine_runtime = "not-applicable" if fine_build == "off" else "unknown"
    if fine_build != "off" and has_cfi and cfi_value == "fineibt":
        fine_runtime = "on"
    elif fine_build != "off" and has_cfi and cfi_value in {"off", "kcfi"}:
        fine_runtime = "off"
    elif fine_build != "off" and has_cfi and cfi_value == "warn":
        fine_runtime = "restricted"
    findings.append(_finding(
        "fineibt", "mitigation", fine_build, fine_runtime,
        (*fine_evidence, *cfi_cmd),
        ("Auto-selection and hardware support are unobserved when cfi= is absent.",),
    ))

    kaslr_build, kaslr_evidence = _config_one(config, "CONFIG_RANDOMIZE_BASE")
    nokaslr, _value, nokaslr_ev = _cmd_value(cmdline, "nokaslr")
    kaslr_runtime = "not-applicable" if kaslr_build == "off" else ("off" if nokaslr else "unknown")
    findings.append(_finding(
        "kaslr", "mitigation", kaslr_build, kaslr_runtime,
        (*kaslr_evidence, *nokaslr_ev),
        ("A missing nokaslr token is not proof that randomization succeeded at boot.",),
    ))

    kpti_build, kpti_evidence = _config_any(
        config, ("CONFIG_MITIGATION_PAGE_TABLE_ISOLATION", "CONFIG_PAGE_TABLE_ISOLATION")
    )
    mitigations_present, mitigations_value, mitigations_ev = _cmd_value(cmdline, "mitigations")
    nopti, _nopti_value, nopti_ev = _cmd_value(cmdline, "nopti")
    pti_present, pti_value, pti_ev = _cmd_value(cmdline, "pti")
    kpti_runtime = "not-applicable" if kpti_build == "off" else "unknown"
    if kpti_build != "off" and ((mitigations_present and mitigations_value == "off") or nopti or (pti_present and pti_value == "off")):
        kpti_runtime = "off"
    elif kpti_build != "off" and pti_present and pti_value == "on":
        kpti_runtime = "on"
    findings.append(_finding(
        "kpti", "mitigation", kpti_build, kpti_runtime,
        (*kpti_evidence, *mitigations_ev, *nopti_ev, *pti_ev),
        ("pti=auto or an absent token remains conditional on CPU/runtime policy.",),
    ))

    stack_build, stack_evidence = _config_one(config, "CONFIG_RANDOMIZE_KSTACK_OFFSET")
    stack_present, stack_value, stack_cmd = _cmd_value(cmdline, "randomize_kstack_offset")
    stack_runtime = "not-applicable" if stack_build == "off" else "unknown"
    if stack_build != "off" and stack_present and stack_value in {"off", "0"}:
        stack_runtime = "off"
    elif stack_build != "off" and stack_present and stack_value in {"on", "1"}:
        stack_runtime = "on"
    findings.append(_finding(
        "randomize_kstack_offset", "mitigation", stack_build, stack_runtime,
        (*stack_evidence, *(config.line("CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT"),), *stack_cmd),
        ("The DEFAULT option is not promoted to observed runtime enforcement.",),
    ))
    return findings


def _profile_static_hardening(config: KconfigFacts) -> list[Finding]:
    findings = [
        _static_config_finding(config, "strict_kernel_rwx", ("CONFIG_STRICT_KERNEL_RWX",)),
        _static_config_finding(config, "strict_module_rwx", ("CONFIG_STRICT_MODULE_RWX",)),
        _static_config_finding(config, "vmap_stack", ("CONFIG_VMAP_STACK",)),
        _static_config_finding(config, "fortify_source", ("CONFIG_FORTIFY_SOURCE",)),
        _static_config_finding(
            config, "stack_protector", ("CONFIG_STACKPROTECTOR_STRONG", "CONFIG_STACKPROTECTOR"),
            ("STACKPROTECTOR_STRONG is the stronger form; this finding only records presence.",),
        ),
        _static_config_finding(config, "slab_freelist_random", ("CONFIG_SLAB_FREELIST_RANDOM",)),
        _static_config_finding(config, "slab_freelist_hardened", ("CONFIG_SLAB_FREELIST_HARDENED",)),
        _static_config_finding(
            config, "slab_virtual", ("CONFIG_SLAB_VIRTUAL",),
            ("SLAB_VIRTUAL is a kernelCTF/downstream mitigation; omission may mean unsupported.",),
        ),
        _static_config_finding(
            config, "kmalloc_partition_caches", ("CONFIG_KMALLOC_PARTITION_CACHES",),
            ("This is the master choice; typed and random child modes are reported separately.",),
        ),
        _static_config_finding(
            config, "typed_kmalloc_partitioning", ("CONFIG_KMALLOC_PARTITION_TYPED",),
            ("Typed allocation-site partitioning is distinct from randomized cache selection.",),
        ),
        _static_config_finding(
            config, "random_kmalloc_caches", ("CONFIG_KMALLOC_PARTITION_RANDOM", "CONFIG_RANDOM_KMALLOC_CACHES"),
            ("Random cache partitioning is not equivalent to typed partitioning.",),
        ),
        _static_config_finding(config, "kmalloc_split_varsize", ("CONFIG_KMALLOC_SPLIT_VARSIZE",)),
        _static_config_finding(config, "slab_buckets", ("CONFIG_SLAB_BUCKETS",)),
    ]
    typed = next(item for item in findings if item.name == "typed_kmalloc_partitioning")
    master_line = config.line("CONFIG_KMALLOC_PARTITION_CACHES")
    if master_line is not None:
        findings[findings.index(typed)] = Finding(
            name=typed.name,
            category=typed.category,
            build_state=typed.build_state,
            runtime_state=typed.runtime_state,
            effective_state=typed.effective_state,
            evidence=tuple(dict.fromkeys((*typed.evidence, master_line))),
            caveats=typed.caveats,
        )
    return findings


def _profile_allocator_defaults(config: KconfigFacts, cmdline: CmdlineFacts) -> list[Finding]:
    merge_state = config.state("CONFIG_SLAB_MERGE_DEFAULT")
    merge_line = config.line("CONFIG_SLAB_MERGE_DEFAULT")
    build = "unknown"
    if merge_state == "off":
        build = "on"
    elif merge_state == "on":
        build = "off"
    runtime = "unknown"
    command_evidence: list[str] = []
    for token in cmdline.tokens:
        name = token.split("=", 1)[0]
        if name in {"slab_nomerge", "slub_nomerge"}:
            runtime = "on"
            command_evidence.append(f"cmdline:{token}")
        elif name in {"slab_merge", "slub_merge"}:
            runtime = "off"
            command_evidence.append(f"cmdline:{token}")
    slab = _finding(
        "slab_merge_disabled", "mitigation", build, runtime,
        (*(() if merge_line is None else (merge_line,)), *command_evidence),
        ("Kconfig describes the default; only a supplied boot token is treated as runtime evidence.",),
        effective=(runtime if runtime in {"on", "off"} else "unknown"),
    )

    usercopy_build, usercopy_evidence = _config_one(config, "CONFIG_HARDENED_USERCOPY")
    usercopy_present, usercopy_value, usercopy_cmd = _cmd_value(cmdline, "hardened_usercopy")
    usercopy_runtime = "not-applicable" if usercopy_build == "off" else "unknown"
    if usercopy_build != "off" and usercopy_present and usercopy_value in {"on", "1"}:
        usercopy_runtime = "on"
    elif usercopy_build != "off" and usercopy_present and usercopy_value in {"off", "0"}:
        usercopy_runtime = "off"
    usercopy_default = config.line("CONFIG_HARDENED_USERCOPY_DEFAULT_ON")
    hardened_usercopy = _finding(
        "hardened_usercopy", "mitigation", usercopy_build, usercopy_runtime,
        (*usercopy_evidence,
         *(() if usercopy_default is None else (usercopy_default,)), *usercopy_cmd),
        ("The DEFAULT_ON symbol is a compiled default, not observed runtime enforcement.",),
    )

    results = [slab, hardened_usercopy]
    for finding_name, config_name, command_name in (
        ("init_on_alloc", "CONFIG_INIT_ON_ALLOC_DEFAULT_ON", "init_on_alloc"),
        ("init_on_free", "CONFIG_INIT_ON_FREE_DEFAULT_ON", "init_on_free"),
    ):
        default_state, default_evidence = _config_one(config, config_name)
        present, value, cmd_evidence = _cmd_value(cmdline, command_name)
        runtime_state = "unknown"
        if present and value == "1":
            runtime_state = "on"
        elif present and value == "0":
            runtime_state = "off"
        results.append(_finding(
            finding_name, "mitigation", default_state, runtime_state,
            (*default_evidence, *cmd_evidence),
            ("Build state records the compiled default, not observed runtime state.",),
            effective=(runtime_state if runtime_state in {"on", "off"} else "unknown"),
        ))

    none_state = config.state("CONFIG_RANDSTRUCT_NONE")
    full_state = config.state("CONFIG_RANDSTRUCT_FULL")
    perf_state = config.state("CONFIG_RANDSTRUCT_PERFORMANCE")
    rand_evidence = tuple(
        line for line in (
            config.line("CONFIG_RANDSTRUCT_NONE"),
            config.line("CONFIG_RANDSTRUCT_FULL"),
            config.line("CONFIG_RANDSTRUCT_PERFORMANCE"),
            config.line("CONFIG_RANDSTRUCT"),
        ) if line is not None
    )
    rand_build = "unknown"
    rand_effective = "unknown"
    if full_state == "on":
        rand_build = rand_effective = "on"
    elif perf_state == "on":
        rand_build = "on"
        rand_effective = "restricted"
    elif none_state == "on":
        rand_build = rand_effective = "off"
    results.append(_finding(
        "randstruct", "mitigation", rand_build, "not-applicable" if rand_build != "unknown" else "unknown",
        rand_evidence,
        ("Performance mode is weaker than full randomization; seed secrecy is not inferable.",),
        effective=rand_effective,
    ))
    return results


def _profile_module_policy(config: KconfigFacts, sysctls: SysctlFacts, cmdline: CmdlineFacts) -> list[Finding]:
    results: list[Finding] = []
    sig_build, sig_evidence = _config_one(config, "CONFIG_MODULE_SIG")
    force_state, force_evidence = _config_one(config, "CONFIG_MODULE_SIG_FORCE")
    sig_present, sig_value, sig_cmd = _cmd_value(cmdline, "module.sig_enforce")
    sig_runtime = "not-applicable" if sig_build == "off" else "unknown"
    if sig_build != "off" and (force_state == "on" or (sig_present and sig_value == "1")):
        sig_runtime = "on"
    elif sig_build != "off" and sig_present and sig_value == "0" and force_state != "on":
        sig_runtime = "off"
    results.append(_finding(
        "module_signature_enforcement", "mitigation", sig_build, sig_runtime,
        (*sig_evidence, *force_evidence, *sig_cmd),
        ("CONFIG_MODULE_SIG without FORCE verifies signatures permissively and may only taint unsigned modules.",),
    ))

    lockdown_build, lockdown_evidence = _config_one(config, "CONFIG_SECURITY_LOCKDOWN_LSM")
    forced_integrity = config.state("CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY") == "on"
    forced_conf = config.state("CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY") == "on"
    lock_present, lock_value, lock_cmd = _cmd_value(cmdline, "lockdown")
    lockdown_runtime = "not-applicable" if lockdown_build == "off" else "unknown"
    if lockdown_build != "off" and (
        forced_integrity or forced_conf or (lock_present and lock_value in {"integrity", "confidentiality"})
    ):
        lockdown_runtime = "on"
    results.append(_finding(
        "kernel_lockdown", "mitigation", lockdown_build, lockdown_runtime,
        (*lockdown_evidence,
         *(line for line in (
             config.line("CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY"),
             config.line("CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY"),
             config.line("CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE"),
         ) if line is not None), *lock_cmd),
        ("Secure Boot and LSM ordering may enable lockdown without a lockdown= token.",),
    ))
    return results


def _profile_namespaces_and_async(config: KconfigFacts, sysctls: SysctlFacts) -> list[Finding]:
    results: list[Finding] = []

    user_build, user_evidence = _config_one(config, "CONFIG_USER_NS")
    max_user, max_evidence = _fact_int(sysctls, "user.max_user_namespaces")
    clone, clone_evidence = _fact_int(sysctls, "kernel.unprivileged_userns_clone")
    user_runtime = "not-applicable" if user_build == "off" else "unknown"
    if max_user is not None and max_user < 0:
        raise WpgapKconfigError("user.max_user_namespaces cannot be negative")
    if clone not in {None, 0, 1}:
        raise WpgapKconfigError("kernel.unprivileged_userns_clone must be 0 or 1")
    if user_build != "off" and (max_user == 0 or clone == 0):
        user_runtime = "off"
    elif user_build != "off" and max_user is not None and max_user > 0 and clone == 1:
        user_runtime = "on"
    results.append(_finding(
        "unprivileged_user_namespaces", "primitive", user_build, user_runtime,
        (*user_evidence, *max_evidence, *clone_evidence),
        ("kernel.unprivileged_userns_clone is downstream; LSM policy may impose another gate.",),
    ))

    io_build, io_evidence = _config_one(config, "CONFIG_IO_URING")
    io_disabled, io_disabled_ev = _fact_int(sysctls, "kernel.io_uring_disabled")
    io_group, io_group_ev = _fact_int(sysctls, "kernel.io_uring_group")
    if io_disabled not in {None, 0, 1, 2}:
        raise WpgapKconfigError("kernel.io_uring_disabled must be 0, 1, or 2")
    io_runtime = "not-applicable" if io_build == "off" else "unknown"
    if io_build != "off" and io_disabled == 0:
        io_runtime = "on"
    elif io_build != "off" and io_disabled == 1:
        io_runtime = "restricted"
    elif io_build != "off" and io_disabled == 2:
        io_runtime = "off"
    results.append(_finding(
        "io_uring", "primitive", io_build, io_runtime,
        (*io_evidence, *io_disabled_ev, *io_group_ev),
        ("Values 1/2 gate new rings; already-created rings are not invalidated.",),
    ))

    bpf_build, bpf_evidence = _config_one(config, "CONFIG_BPF_SYSCALL")
    bpf_disabled, bpf_disabled_ev = _fact_int(sysctls, "kernel.unprivileged_bpf_disabled")
    if bpf_disabled not in {None, 0, 1, 2}:
        raise WpgapKconfigError("kernel.unprivileged_bpf_disabled must be 0, 1, or 2")
    bpf_runtime = "not-applicable" if bpf_build == "off" else "unknown"
    if bpf_build != "off" and bpf_disabled == 0:
        bpf_runtime = "on"
    elif bpf_build != "off" and bpf_disabled in {1, 2}:
        bpf_runtime = "off"
    results.append(_finding(
        "unprivileged_bpf", "primitive", bpf_build, bpf_runtime,
        (*bpf_evidence, *(line for line in (
            config.line("CONFIG_BPF"), config.line("CONFIG_BPF_JIT"),
            config.line("CONFIG_BPF_JIT_ALWAYS_ON"), config.line("CONFIG_BPF_UNPRIV_DEFAULT_OFF"),
        ) if line is not None), *bpf_disabled_ev),
        ("BPF_UNPRIV_DEFAULT_OFF only selects initial value 2; it is not runtime evidence.",
         "Privileged BPF remains separate from this unprivileged primitive."),
    ))

    jit_build, jit_evidence = _config_one(config, "CONFIG_BPF_JIT")
    jit_harden, jit_harden_ev = _fact_int(sysctls, "net.core.bpf_jit_harden")
    if jit_harden not in {None, 0, 1, 2}:
        raise WpgapKconfigError("net.core.bpf_jit_harden must be 0, 1, or 2")
    jit_runtime = "not-applicable" if jit_build == "off" else "unknown"
    if jit_build != "off" and jit_harden == 0:
        jit_runtime = "off"
    elif jit_build != "off" and jit_harden in {1, 2}:
        jit_runtime = "on"
    results.append(_finding(
        "bpf_jit_hardening", "mitigation", jit_build, jit_runtime,
        (*jit_evidence, *jit_harden_ev),
        ("Value 1 hardens unprivileged JIT use; value 2 applies hardening to all users.",),
    ))

    uffd_build, uffd_evidence = _config_one(config, "CONFIG_USERFAULTFD")
    uffd, uffd_ev = _fact_int(sysctls, "vm.unprivileged_userfaultfd")
    if uffd not in {None, 0, 1}:
        raise WpgapKconfigError("vm.unprivileged_userfaultfd must be 0 or 1")
    uffd_runtime = "not-applicable" if uffd_build == "off" else "unknown"
    if uffd_build != "off" and uffd == 0:
        uffd_runtime = "restricted"
    elif uffd_build != "off" and uffd == 1:
        uffd_runtime = "on"
    results.append(_finding(
        "userfaultfd_kernel_faults", "primitive", uffd_build, uffd_runtime,
        (*uffd_evidence, *uffd_ev),
        ("Value 0 still permits UFFD_USER_MODE_ONLY and /dev/userfaultfd has independent permissions.",),
    ))
    return results


def _profile_compiled_primitives(config: KconfigFacts) -> list[Finding]:
    specifications = (
        ("af_packet", ("CONFIG_PACKET",), "CAP_NET_RAW/netns and socket policy are runtime gates."),
        ("sysv_ipc", ("CONFIG_SYSVIPC",), "Limits, seccomp, and LSM policy are unobserved."),
        ("posix_mqueue", ("CONFIG_POSIX_MQUEUE",), "Limits, seccomp, and LSM policy are unobserved."),
        ("kernel_keyrings", ("CONFIG_KEYS",), "Key permissions, quotas, seccomp, and LSM policy are unobserved."),
        ("fuse", ("CONFIG_FUSE_FS",), "A module build also needs the module and /dev/fuse access."),
        ("nftables", ("CONFIG_NF_TABLES",), "CAP_NET_ADMIN in a usable network namespace is unobserved."),
        ("devmem", ("CONFIG_DEVMEM",), "Device permissions, STRICT_DEVMEM, lockdown, and architecture policy are unobserved."),
        ("debugfs", ("CONFIG_DEBUG_FS",), "Build support does not prove debugfs is mounted or accessible."),
        ("ia32_emulation", ("CONFIG_IA32_EMULATION",), "Compat syscall reach still depends on seccomp and process policy."),
        ("kernel_tls", ("CONFIG_TLS",), "Socket-family and namespace policy remain runtime gates."),
        ("crypto_user_aead", ("CONFIG_CRYPTO_USER_API_AEAD",), "User API availability remains subject to runtime policy."),
        ("af_unix_oob", ("CONFIG_AF_UNIX_OOB",), "Socket access remains subject to namespace and LSM policy."),
    )
    results: list[Finding] = []
    for name, symbols, caveat in specifications:
        build, evidence = _config_any(config, symbols)
        runtime = "not-applicable" if build == "off" else "unknown"
        results.append(_finding(name, "primitive", build, runtime, evidence, (caveat,)))
    return results


def _profile_endgames(config: KconfigFacts, sysctls: SysctlFacts) -> list[Finding]:
    results: list[Finding] = []

    modules_build, modules_evidence = _config_one(config, "CONFIG_MODULES")
    modules_disabled, modules_disabled_ev = _fact_int(sysctls, "kernel.modules_disabled")
    if modules_disabled not in {None, 0, 1}:
        raise WpgapKconfigError("kernel.modules_disabled must be 0 or 1")
    modules_runtime = "not-applicable" if modules_build == "off" else "unknown"
    if modules_build != "off" and modules_disabled == 0:
        modules_runtime = "restricted"
    elif modules_build != "off" and modules_disabled == 1:
        modules_runtime = "off"
    results.append(_finding(
        "module_loading", "primitive", modules_build, modules_runtime,
        (*modules_evidence, *modules_disabled_ev),
        ("An open modules_disabled gate still requires privilege and may face signature/lockdown policy.",),
    ))

    modprobe_build = modules_build
    modprobe_evidence = list(modules_evidence)
    for name in ("CONFIG_MODPROBE_PATH", "CONFIG_STATIC_USERMODEHELPER", "CONFIG_STATIC_USERMODEHELPER_PATH"):
        line = config.line(name)
        if line is not None:
            modprobe_evidence.append(line)
    modprobe_value = sysctls.values.get("kernel.modprobe")
    static_helper = config.state("CONFIG_STATIC_USERMODEHELPER")
    static_path = config.values.get("CONFIG_STATIC_USERMODEHELPER_PATH")
    modprobe_runtime = "not-applicable" if modules_build == "off" else "unknown"
    if modules_build != "off" and (
        modules_disabled == 1 or (static_helper == "on" and static_path == "")
    ):
        modprobe_runtime = "off"
    elif modules_build != "off" and static_helper == "on" and static_path is not None:
        modprobe_runtime = "restricted"
        modprobe_evidence.append(f"static-usermode-helper={static_path}")
    elif modules_build != "off" and modprobe_value == "":
        modprobe_runtime = "off"
        modprobe_evidence.append("kernel.modprobe=")
    elif modules_build != "off" and modprobe_value is not None:
        modprobe_runtime = "restricted"
        modprobe_evidence.append(f"kernel.modprobe={modprobe_value}")
    results.append(_finding(
        "modprobe_helper", "primitive", modprobe_build, modprobe_runtime,
        modprobe_evidence,
        ("A nonempty helper path is only a candidate; triggerability and path writability are unobserved.",),
    ))

    core_build, core_evidence = _config_one(config, "CONFIG_COREDUMP")
    core = sysctls.values.get("kernel.core_pattern")
    core_runtime = "not-applicable" if core_build == "off" else "unknown"
    core_ev: list[str] = list(core_evidence)
    if core_build != "off" and core is not None:
        core_ev.append(f"kernel.core_pattern={core}")
        core_runtime = "on" if core.startswith("|") else "off"
    results.append(_finding(
        "core_pattern_pipe", "primitive", core_build, core_runtime, core_ev,
        ("A pipe handler is not proof that an attacker can overwrite it or trigger a qualifying dump.",),
    ))

    kexec_build, kexec_evidence = _config_any(config, ("CONFIG_KEXEC", "CONFIG_KEXEC_FILE"))
    kexec_disabled, kexec_disabled_ev = _fact_int(sysctls, "kernel.kexec_load_disabled")
    if kexec_disabled not in {None, 0, 1}:
        raise WpgapKconfigError("kernel.kexec_load_disabled must be 0 or 1")
    kexec_runtime = "not-applicable" if kexec_build == "off" else "unknown"
    if kexec_build != "off" and kexec_disabled == 0:
        kexec_runtime = "restricted"
    elif kexec_build != "off" and kexec_disabled == 1:
        kexec_runtime = "off"
    results.append(_finding(
        "kexec_loading", "primitive", kexec_build, kexec_runtime,
        (*kexec_evidence, *kexec_disabled_ev, *(line for line in (
            config.line("CONFIG_KEXEC_SIG"), config.line("CONFIG_KEXEC_SIG_FORCE"),
        ) if line is not None)),
        ("An open toggle still requires privilege and may face signature/lockdown policy.",),
    ))
    return results


def _profile_leak_surfaces(config: KconfigFacts, sysctls: SysctlFacts) -> list[Finding]:
    results: list[Finding] = []
    kallsyms_build, kallsyms_evidence = _config_one(config, "CONFIG_KALLSYMS")
    kptr, kptr_ev = _fact_int(sysctls, "kernel.kptr_restrict")
    if kptr not in {None, 0, 1, 2}:
        raise WpgapKconfigError("kernel.kptr_restrict must be 0, 1, or 2")
    kptr_runtime = "not-applicable" if kallsyms_build == "off" else "unknown"
    if kallsyms_build != "off" and kptr == 0:
        kptr_runtime = "restricted"
    elif kallsyms_build != "off" and kptr == 1:
        kptr_runtime = "restricted"
    elif kallsyms_build != "off" and kptr == 2:
        kptr_runtime = "off"
    results.append(_finding(
        "kptr_disclosure", "primitive", kallsyms_build, kptr_runtime,
        (*kallsyms_evidence, *(line for line in (config.line("CONFIG_KALLSYMS_ALL"),) if line), *kptr_ev),
        ("Even value 0 hashes ordinary %p output; this finding concerns %pK-style disclosure only.",
         "File permissions and other leak paths are unobserved."),
    ))

    printk_build, printk_evidence = _config_one(config, "CONFIG_PRINTK")
    dmesg, dmesg_ev = _fact_int(sysctls, "kernel.dmesg_restrict")
    if dmesg not in {None, 0, 1}:
        raise WpgapKconfigError("kernel.dmesg_restrict must be 0 or 1")
    dmesg_runtime = "not-applicable" if printk_build == "off" else "unknown"
    if printk_build != "off" and dmesg == 0:
        dmesg_runtime = "on"
    elif printk_build != "off" and dmesg == 1:
        dmesg_runtime = "restricted"
    results.append(_finding(
        "unprivileged_dmesg", "primitive", printk_build, dmesg_runtime,
        (*printk_evidence, *dmesg_ev),
        ("Value 0 opens this sysctl gate but file permissions and LSM policy may still restrict reads.",),
    ))

    perf_build, perf_evidence = _config_one(config, "CONFIG_PERF_EVENTS")
    perf, perf_ev = _fact_int(sysctls, "kernel.perf_event_paranoid")
    perf_runtime = "not-applicable" if perf_build == "off" else "unknown"
    perf_caveats = ["The numeric paranoid level is graded and is preserved as evidence."]
    if perf_build != "off" and perf is not None:
        perf_runtime = "on" if perf < 0 else "restricted"
        if perf >= 2:
            perf_caveats.append("Level >=2 denies kernel profiling without CAP_PERFMON.")
        elif perf >= 1:
            perf_caveats.append("Level >=1 additionally denies CPU events without CAP_PERFMON.")
        else:
            perf_caveats.append("Level >=0 denies raw/ftrace tracepoints without CAP_PERFMON.")
    results.append(_finding(
        "unprivileged_perf", "primitive", perf_build, perf_runtime,
        (*perf_evidence, *perf_ev), perf_caveats,
    ))

    mmap_build = "on"
    mmap_evidence: list[str] = []
    mmap_min, mmap_ev = _fact_int(sysctls, "vm.mmap_min_addr")
    lsm_floor, lsm_ev = _config_int(config, "CONFIG_LSM_MMAP_MIN_ADDR")
    mmap_evidence.extend(mmap_ev); mmap_evidence.extend(lsm_ev)
    mmap_runtime = "unknown"
    if mmap_min is not None and mmap_min < 0:
        raise WpgapKconfigError("vm.mmap_min_addr cannot be negative")
    if lsm_floor is not None and lsm_floor < 0:
        raise WpgapKconfigError("CONFIG_LSM_MMAP_MIN_ADDR cannot be negative")
    if (mmap_min is not None and mmap_min > 0) or (lsm_floor is not None and lsm_floor > 0):
        mmap_runtime = "restricted"
    elif mmap_min == 0 and lsm_floor == 0:
        mmap_runtime = "on"
    results.append(_finding(
        "low_address_mmap", "primitive", mmap_build, mmap_runtime,
        mmap_evidence,
        ("A zero sysctl is insufficient when the LSM minimum is missing; effective floor is the maximum.",),
    ))

    yama_build, yama_evidence = _config_one(config, "CONFIG_SECURITY_YAMA")
    ptrace, ptrace_ev = _fact_int(sysctls, "kernel.yama.ptrace_scope")
    if ptrace is not None and ptrace not in {0, 1, 2, 3}:
        raise WpgapKconfigError("kernel.yama.ptrace_scope must be in 0..3")
    yama_runtime = "not-applicable" if yama_build == "off" else "unknown"
    if yama_build != "off" and ptrace == 0:
        yama_runtime = "off"
    elif yama_build != "off" and ptrace in {1, 2, 3}:
        yama_runtime = "on"
    results.append(_finding(
        "yama_ptrace_restriction", "mitigation", yama_build, yama_runtime,
        (*yama_evidence, *ptrace_ev),
        ("Scopes 1, 2, and 3 have increasing restrictions; scope 3 is irreversible.",),
    ))
    return results


@_fail_closed
def profile_kernel(
    config_text: str,
    sysctl_text: str = "",
    cmdline_text: str = "",
) -> KernelProfile:
    """Build a deterministic profile from supplied static text artifacts."""

    config = parse_kconfig(config_text)
    sysctls = parse_sysctl_facts(sysctl_text)
    cmdline = parse_cmdline(cmdline_text)
    findings: list[Finding] = []
    findings.extend(_profile_control_flow(config, cmdline))
    findings.extend(_profile_static_hardening(config))
    findings.extend(_profile_allocator_defaults(config, cmdline))
    findings.extend(_profile_module_policy(config, sysctls, cmdline))
    findings.extend(_profile_namespaces_and_async(config, sysctls))
    findings.extend(_profile_compiled_primitives(config))
    findings.extend(_profile_endgames(config, sysctls))
    findings.extend(_profile_leak_surfaces(config, sysctls))
    names = [finding.name for finding in findings]
    if len(names) != len(set(names)):
        raise WpgapKconfigError("internal finding names are not unique")
    return KernelProfile(
        findings=tuple(findings),
        config_symbol_count=len(config.values),
        sysctl_fact_count=len(sysctls.values),
        cmdline_token_count=len(cmdline.tokens),
    )


def _read_text(path: str, label: str, limit: int = MAX_INPUT_BYTES) -> str:
    try:
        raw = Path(path).read_bytes()
    except (OSError, RuntimeError, ValueError) as exc:
        raise WpgapKconfigError(f"cannot read {label}") from exc
    if len(raw) > limit:
        raise WpgapKconfigError(f"{label} exceeds the bounded input limit")
    try:
        return raw.decode("utf-8")
    except UnicodeError as exc:
        raise WpgapKconfigError(f"{label} is not UTF-8") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wpgap_kconfig_profile",
        description="Offline Linux Kconfig/sysctl/cmdline attack-surface profiler",
    )
    parser.add_argument("config", help="supplied UTF-8 Linux .config or fragment")
    parser.add_argument("--sysctl", metavar="FILE", help="supplied JSON or name=value sysctl facts")
    command = parser.add_mutually_exclusive_group()
    command.add_argument("--cmdline", help="supplied kernel command-line text")
    command.add_argument("--cmdline-file", metavar="FILE", help="file containing supplied command-line text")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the guarded CLI and return a process-style integer status."""

    parser = _parser()
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception:
        parser._print_message("wpgap_kconfig_profile: error: malformed argv\n", sys.stderr)
        return 2
    try:
        config_text = _read_text(arguments.config, "Kconfig")
        sysctl_text = "" if arguments.sysctl is None else _read_text(arguments.sysctl, "sysctl facts")
        if arguments.cmdline_file is not None:
            cmdline_text = _read_text(arguments.cmdline_file, "kernel command line", MAX_CMDLINE_BYTES)
        else:
            cmdline_text = arguments.cmdline or ""
        document = profile_kernel(config_text, sysctl_text, cmdline_text).as_dict()
        print(json.dumps(
            document,
            sort_keys=True,
            indent=2 if arguments.pretty else None,
            separators=None if arguments.pretty else (",", ":"),
        ))
        return 0
    except WpgapKconfigError as exc:
        parser._print_message(f"wpgap_kconfig_profile: error: {exc}\n", sys.stderr)
        return 2
    except Exception:
        parser._print_message("wpgap_kconfig_profile: error: malformed CLI input\n", sys.stderr)
        return 2


__all__ = [
    "WpgapKconfigError",
    "KconfigFacts",
    "SysctlFacts",
    "CmdlineFacts",
    "Finding",
    "KernelProfile",
    "parse_kconfig",
    "parse_sysctl_facts",
    "parse_cmdline",
    "profile_kernel",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
