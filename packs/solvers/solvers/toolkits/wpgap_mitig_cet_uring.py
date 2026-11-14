#!/usr/bin/env python3
"""Offline CET ground truth and seccomp-to-io_uring capability analysis.

The module consumes bytes and caller-supplied saved status only.  It never loads an ELF,
installs a seccomp filter, creates an io_uring instance, performs a syscall, or executes a
target.  Two deliberately separate analyzers are provided:

``analyze_cet``
    Parses raw ELF note-section bytes and combines their GNU property declaration with
    explicit loader/thread facts.  ENDBR observations are used only when classifying a
    supplied indirect-transfer surface; they never imply IBT enforcement.

``analyze_io_uring``
    Reuses the repository's Linux-seccomp cBPF decoder/interpreter for exact syscall
    arguments, then intersects the result with supplied ring, opcode-probe, restriction,
    resource, and permission facts.  It emits open/read/emit reach, not a "seccomp bypass."

Public analysis functions expose only :class:`WpgapMitigError` for invalid input.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from functools import wraps
from pathlib import Path
from typing import Any, TypeVar

try:  # package and flat-basename imports are both supported by the repository
    from . import pwn_seccomp as _seccomp
    from . import seccomp_patterns as _patterns
except ImportError:  # pragma: no cover - pytest imports solver modules by basename
    import pwn_seccomp as _seccomp
    import seccomp_patterns as _patterns


class WpgapMitigError(ValueError):
    """Malformed, contradictory, incomplete, or unsupported analyzer input."""


MAX_NOTE_BYTES = 1024 * 1024
MAX_STATUS_BYTES = 256 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_NOTES = 256
MAX_PROPERTIES = 256
MAX_SURFACES = 256
MAX_OPS = 128
MAX_TEXT = 512

NT_GNU_PROPERTY_TYPE_0 = 5
GNU_PROPERTY_X86_FEATURE_1_AND = 0xC0000002
GNU_PROPERTY_X86_FEATURE_1_IBT = 1 << 0
GNU_PROPERTY_X86_FEATURE_1_SHSTK = 1 << 1

IO_URING_SYSCALLS = {
    "setup": 425,
    "enter": 426,
    "register": 427,
}
IORING_ENTER_SQ_WAKEUP = 1 << 1
IORING_REGISTER_ENABLE_RINGS = 12

VERDICT_USABLE = "usable"
VERDICT_BLOCKED = "blocked"
VERDICT_UNKNOWN = "unknown"
VERDICT_NA = "not_applicable"

_KERNEL_RE = re.compile(r"^[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?(?:[-+._A-Za-z0-9]*)?$")
_OP_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.:/ -]{1,128}$")

# These are consistency floors, never support proofs.  Exact supported_ops wins.
_OP_FLOORS: Mapping[str, tuple[int, int]] = {
    "READV": (5, 1), "WRITEV": (5, 1), "READ_FIXED": (5, 1),
    "WRITE_FIXED": (5, 1), "SENDMSG": (5, 3), "RECVMSG": (5, 3),
    "ACCEPT": (5, 5), "CONNECT": (5, 5), "OPENAT": (5, 6),
    "OPENAT2": (5, 6), "READ": (5, 6), "WRITE": (5, 6),
    "SEND": (5, 6), "RECV": (5, 6), "SPLICE": (5, 7), "TEE": (5, 8),
    "SOCKET": (5, 19), "SEND_ZC": (6, 0), "SENDMSG_ZC": (6, 1),
    "READ_MULTISHOT": (6, 7), "FIXED_FD_INSTALL": (6, 8),
    "RECV_ZC": (6, 15), "PIPE": (6, 16),
}

_FD_OPS = frozenset({
    "OPENAT", "OPENAT2", "READ", "READV", "READ_FIXED", "READ_MULTISHOT",
    "WRITE", "WRITEV", "WRITE_FIXED", "SEND", "SENDMSG", "SEND_ZC",
    "SENDMSG_ZC", "RECV", "RECVMSG", "RECV_ZC", "SPLICE", "TEE",
    "ACCEPT", "CONNECT", "CLOSE", "STATX", "FIXED_FD_INSTALL", "URING_CMD",
})

_T = TypeVar("_T")


def _declared_contract(function: Callable[..., _T]) -> Callable[..., _T]:
    """Translate every ordinary implementation/input exception at a public boundary."""

    @wraps(function)
    def wrapper(*args: object, **kwargs: object) -> _T:
        try:
            return function(*args, **kwargs)
        except WpgapMitigError:
            raise
        except Exception as exc:
            raise WpgapMitigError("malformed or unsupported analyzer input") from exc

    return wrapper


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise WpgapMitigError(f"{label} must be an object")
    for key in value:
        if not isinstance(key, str):
            raise WpgapMitigError(f"{label} keys must be strings")
    return value


def _bounded_text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise WpgapMitigError(f"{label} must be text")
    if (not value and not allow_empty) or len(value.encode("utf-8")) > MAX_TEXT:
        raise WpgapMitigError(f"{label} has an invalid length")
    return value


def _uint(value: object, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise WpgapMitigError(f"{label} must be an integer in 0..{maximum:#x}")
    return value


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _read_u32(data: bytes, offset: int, endian: str, label: str) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise WpgapMitigError(f"truncated {label}")
    return int.from_bytes(data[offset:offset + 4], endian)


def _state(value: object, label: str) -> str:
    if value is True:
        return VERDICT_USABLE
    if value is False:
        return VERDICT_BLOCKED
    if value is None:
        return VERDICT_UNKNOWN
    if isinstance(value, str):
        normalized = value.strip().lower().replace("-", "_")
        aliases = {
            "enabled": VERDICT_USABLE, "supported": VERDICT_USABLE,
            "available": VERDICT_USABLE, "allowed": VERDICT_USABLE,
            "allow": VERDICT_USABLE, "continued": VERDICT_USABLE,
            "continue": VERDICT_USABLE, "usable": VERDICT_USABLE,
            "disabled": VERDICT_BLOCKED, "unsupported": VERDICT_BLOCKED,
            "unavailable": VERDICT_BLOCKED, "denied": VERDICT_BLOCKED,
            "deny": VERDICT_BLOCKED, "blocked": VERDICT_BLOCKED,
            "unknown": VERDICT_UNKNOWN, "conditional": VERDICT_UNKNOWN,
            "unresolved": VERDICT_UNKNOWN,
        }
        if normalized in aliases:
            return aliases[normalized]
    raise WpgapMitigError(f"{label} must be enabled/disabled/unknown (or bool/null)")


def _optional_state(values: Mapping[str, object], key: str, label: str) -> str:
    return _state(values.get(key), f"{label}.{key}")


def _and_states(*states: str) -> str:
    if any(item == VERDICT_BLOCKED for item in states):
        return VERDICT_BLOCKED
    if any(item == VERDICT_UNKNOWN for item in states):
        return VERDICT_UNKNOWN
    return VERDICT_USABLE


def _or_states(*states: str) -> str:
    if any(item == VERDICT_USABLE for item in states):
        return VERDICT_USABLE
    if any(item == VERDICT_UNKNOWN for item in states):
        return VERDICT_UNKNOWN
    return VERDICT_BLOCKED


def _merge_observation(explicit: str, observed: str, label: str) -> str:
    if explicit == VERDICT_UNKNOWN:
        return observed
    if observed == VERDICT_UNKNOWN:
        return explicit
    if explicit != observed:
        raise WpgapMitigError(f"contradictory saved facts for {label}")
    return explicit


def _enabled_word(state: str) -> str:
    return {
        VERDICT_USABLE: "enabled",
        VERDICT_BLOCKED: "disabled",
        VERDICT_UNKNOWN: "unknown",
    }[state]


def _support_word(state: str) -> str:
    return {
        VERDICT_USABLE: "supported",
        VERDICT_BLOCKED: "unsupported",
        VERDICT_UNKNOWN: "unknown",
    }[state]


@_declared_contract
def parse_gnu_property_notes(
    note_bytes: bytes | bytearray,
    *,
    elf_class: int = 64,
    endian: str = "little",
) -> dict[str, object]:
    """Strictly parse raw ELF note-section bytes and x86 FEATURE_1_AND.

    ``note_bytes`` is the contents of an ELF note section or note segment, not a complete ELF.
    No feature bit is treated as runtime state.  A missing feature property is represented by
    ``None`` rather than by ``False``.
    """

    if not isinstance(note_bytes, (bytes, bytearray)):
        raise WpgapMitigError("note_bytes must be bytes")
    data = bytes(note_bytes)
    if len(data) > MAX_NOTE_BYTES:
        raise WpgapMitigError(f"note data exceeds {MAX_NOTE_BYTES} bytes")
    if elf_class not in (32, 64):
        raise WpgapMitigError("elf_class must be 32 or 64")
    if endian not in ("little", "big"):
        raise WpgapMitigError("endian must be 'little' or 'big'")

    offset = 0
    notes: list[dict[str, object]] = []
    property_note_count = 0
    feature_mask: int | None = None
    unknown_properties: list[dict[str, object]] = []
    property_alignment = 8 if elf_class == 64 else 4

    while offset < len(data):
        if len(notes) >= MAX_NOTES:
            raise WpgapMitigError(f"note count exceeds {MAX_NOTES}")
        if len(data) - offset < 12:
            raise WpgapMitigError("truncated ELF note header")
        namesz = _read_u32(data, offset, endian, "note namesz")
        descsz = _read_u32(data, offset + 4, endian, "note descsz")
        note_type = _read_u32(data, offset + 8, endian, "note type")
        note_start = offset
        offset += 12

        name_end = offset + namesz
        name_padded_end = offset + _align(namesz, 4)
        if name_end > len(data) or name_padded_end > len(data):
            raise WpgapMitigError("truncated ELF note name")
        name = data[offset:name_end]
        offset = name_padded_end

        desc_end = offset + descsz
        desc_padded_end = offset + _align(descsz, 4)
        if desc_end > len(data) or desc_padded_end > len(data):
            raise WpgapMitigError("truncated ELF note descriptor")
        descriptor = data[offset:desc_end]
        offset = desc_padded_end

        is_gnu_property = name == b"GNU\x00" and note_type == NT_GNU_PROPERTY_TYPE_0
        notes.append({
            "offset": note_start,
            "name_hex": name.hex(),
            "type": note_type,
            "descriptor_size": descsz,
            "gnu_property": is_gnu_property,
        })
        if not is_gnu_property:
            continue

        property_note_count += 1
        if property_note_count > 1:
            raise WpgapMitigError("multiple GNU property notes are ambiguous")
        prop_offset = 0
        previous_type = -1
        count = 0
        while prop_offset < len(descriptor):
            if count >= MAX_PROPERTIES:
                raise WpgapMitigError(f"GNU property count exceeds {MAX_PROPERTIES}")
            if len(descriptor) - prop_offset < 8:
                raise WpgapMitigError("truncated GNU property header")
            prop_type = _read_u32(descriptor, prop_offset, endian, "GNU property type")
            prop_size = _read_u32(descriptor, prop_offset + 4, endian, "GNU property size")
            if prop_type <= previous_type:
                raise WpgapMitigError("GNU properties must be strictly ordered and unique")
            previous_type = prop_type
            payload_start = prop_offset + 8
            payload_end = payload_start + prop_size
            next_offset = _align(payload_end, property_alignment)
            if payload_end > len(descriptor) or next_offset > len(descriptor):
                raise WpgapMitigError("truncated GNU property payload or alignment")
            payload = descriptor[payload_start:payload_end]
            count += 1

            if prop_type == GNU_PROPERTY_X86_FEATURE_1_AND:
                if prop_size != 4:
                    raise WpgapMitigError("GNU_PROPERTY_X86_FEATURE_1_AND must contain one uint32")
                if feature_mask is not None:
                    raise WpgapMitigError("duplicate GNU_PROPERTY_X86_FEATURE_1_AND")
                feature_mask = int.from_bytes(payload, endian)
            else:
                unknown_properties.append({
                    "type": f"0x{prop_type:08x}",
                    "size": prop_size,
                    "data_hex": payload.hex(),
                })
            prop_offset = next_offset

    unknown_bits = None if feature_mask is None else feature_mask & ~(
        GNU_PROPERTY_X86_FEATURE_1_IBT | GNU_PROPERTY_X86_FEATURE_1_SHSTK
    )
    return {
        "scope": "ELF declaration only; not loader or runtime enforcement",
        "elf_class": elf_class,
        "endian": endian,
        "note_count": len(notes),
        "property_note_present": property_note_count == 1,
        "feature_property_present": feature_mask is not None,
        "feature_mask": None if feature_mask is None else f"0x{feature_mask:08x}",
        "ibt": None if feature_mask is None else bool(feature_mask & GNU_PROPERTY_X86_FEATURE_1_IBT),
        "shstk": None if feature_mask is None else bool(feature_mask & GNU_PROPERTY_X86_FEATURE_1_SHSTK),
        "unknown_feature_bits": None if unknown_bits is None else f"0x{unknown_bits:08x}",
        "unknown_properties": unknown_properties,
        "notes": notes,
    }


@_declared_contract
def parse_proc_status(status_text: str) -> dict[str, object]:
    """Extract saved x86 thread-feature lines without inferring userspace IBT."""

    if not isinstance(status_text, str):
        raise WpgapMitigError("proc status must be text")
    if len(status_text.encode("utf-8")) > MAX_STATUS_BYTES:
        raise WpgapMitigError(f"proc status exceeds {MAX_STATUS_BYTES} bytes")
    fields: dict[str, list[str]] = {}
    relevant = {"x86_Thread_features", "x86_Thread_features_locked"}
    for line_number, line in enumerate(status_text.splitlines(), 1):
        if len(line.encode("utf-8")) > 4096:
            raise WpgapMitigError(f"proc status line {line_number} is too long")
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        if key not in relevant:
            continue
        if key in fields:
            raise WpgapMitigError(f"duplicate {key} in proc status")
        tokens = raw.split()
        if any(not re.fullmatch(r"[a-z0-9_]{1,64}", token) for token in tokens):
            raise WpgapMitigError(f"invalid token in {key}")
        fields[key] = tokens

    active = fields.get("x86_Thread_features")
    locked = fields.get("x86_Thread_features_locked")
    return {
        "source": "/proc/PID/status saved text",
        "active_tokens": active,
        "locked_tokens": locked,
        "shstk": "unknown" if active is None else (
            "enabled" if "shstk" in active else "disabled"
        ),
        "wrss": "unknown" if active is None else (
            "enabled" if "wrss" in active else "disabled"
        ),
        "shstk_locked": "unknown" if locked is None else (
            "enabled" if "shstk" in locked else "disabled"
        ),
        "ibt": "unknown",
        "ibt_reason": "upstream x86 thread-feature SHSTK tokens are not user-IBT evidence",
    }


def _loader_value(value: object, label: str) -> str:
    if isinstance(value, str) and value.strip().lower() == "rejected":
        return "rejected"
    return _state(value, label)


def _surface_entry(
    transfer: str,
    surface: Mapping[str, object],
    ibt: str,
    no_track: str,
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if transfer in {"direct_call", "direct_jump"}:
        return VERDICT_USABLE, ["direct transfers are not gated by IBT"]
    if transfer == "return":
        return VERDICT_NA, ["IBT does not gate this transfer kind"]
    if transfer in {"signal_restore", "context_restore"}:
        special = _state(surface.get("special_runtime_authorized"), "surface.special_runtime_authorized")
        return special, ["special restoration semantics require an explicit saved runtime fact"]

    target = _state(surface.get("target_endbr"), "surface.target_endbr")
    notrack_fact = _state(surface.get("notrack"), "surface.notrack")
    if notrack_fact == VERDICT_USABLE:
        if no_track == VERDICT_USABLE:
            return VERDICT_USABLE, ["exact callsite is NOTRACK and saved runtime enables NO_TRACK behavior"]
        if no_track == VERDICT_UNKNOWN:
            if target == VERDICT_USABLE:
                return VERDICT_USABLE, [
                    "target has ENDBR and is admissible whether the supplied NOTRACK callsite is honored or tracked",
                    "ENDBR compatibility does not prove IBT enforcement",
                ]
            return VERDICT_UNKNOWN, ["NO_TRACK behavior is unknown for the supplied NOTRACK callsite"]
        reasons.append("NO_TRACK behavior is disabled; treating the indirect transfer as tracked")
    elif notrack_fact == VERDICT_UNKNOWN and no_track == VERDICT_USABLE:
        if target == VERDICT_USABLE:
            return VERDICT_USABLE, [
                "target has ENDBR and is admissible for a tracked branch; an unknown NOTRACK prefix cannot make it less admissible",
                "ENDBR compatibility does not prove IBT enforcement",
            ]
        return VERDICT_UNKNOWN, ["whether this callsite uses NOTRACK is unknown"]

    if ibt == VERDICT_BLOCKED:
        return VERDICT_USABLE, reasons + ["saved thread status says IBT is disabled"]
    if ibt == VERDICT_USABLE:
        if target == VERDICT_USABLE:
            return VERDICT_USABLE, reasons + [
                "IBT is enabled and the tracked target begins with the supplied ENDBR fact",
                "target semantics beyond CET were not assessed",
            ]
        if target == VERDICT_BLOCKED:
            return VERDICT_BLOCKED, reasons + ["IBT is enabled and the tracked target lacks ENDBR"]
        return VERDICT_UNKNOWN, reasons + ["IBT is enabled but the target ENDBR fact is unknown"]
    if target == VERDICT_USABLE:
        return VERDICT_USABLE, reasons + [
            "the target is CET-compatible whether IBT is enabled or disabled",
            "ENDBR compatibility does not establish the unknown enforcement state",
        ]
    if target == VERDICT_BLOCKED:
        return VERDICT_UNKNOWN, reasons + ["target lacks ENDBR, but IBT enforcement is unknown"]
    return VERDICT_UNKNOWN, reasons + ["IBT enforcement and target ENDBR state are both unknown"]


def _surface_return(
    transfer: str,
    surface: Mapping[str, object],
    shstk: str,
) -> tuple[str, list[str]]:
    if transfer in {"direct_jump", "indirect_jump"}:
        return VERDICT_NA, ["the supplied transfer does not itself perform RET"]
    if transfer in {"signal_restore", "context_restore"}:
        special = _state(surface.get("special_runtime_authorized"), "surface.special_runtime_authorized")
        return special, ["special restoration semantics are not generalized from ordinary RET"]
    if transfer in {"direct_call", "indirect_call"}:
        returns = _state(surface.get("returns"), "surface.returns")
        if returns == VERDICT_BLOCKED:
            return VERDICT_NA, ["caller states this call surface does not return"]
        if returns == VERDICT_UNKNOWN:
            return VERDICT_UNKNOWN, ["whether the call surface returns is unknown"]

    matching = _state(surface.get("shadow_return_match"), "surface.shadow_return_match")
    if matching == VERDICT_USABLE:
        return VERDICT_USABLE, ["supplied facts establish a matching architectural/shadow return pair"]
    if shstk == VERDICT_BLOCKED:
        return VERDICT_USABLE, ["saved thread status says SHSTK is disabled"]
    if matching == VERDICT_BLOCKED:
        if shstk == VERDICT_USABLE:
            return VERDICT_BLOCKED, ["SHSTK is enabled and the ordinary RET pair is mismatched"]
        return VERDICT_UNKNOWN, ["the RET pair is mismatched but SHSTK enforcement is unknown"]
    if shstk == VERDICT_USABLE:
        return VERDICT_UNKNOWN, ["SHSTK is enabled but no matching-return fact was supplied"]
    return VERDICT_UNKNOWN, ["SHSTK enforcement and shadow-return matching are unknown"]


def _combined_surface(entry: str, return_state: str) -> str:
    values = [value for value in (entry, return_state) if value != VERDICT_NA]
    if not values:
        return VERDICT_UNKNOWN
    return _and_states(*values)


@_declared_contract
def analyze_cet(
    note_bytes: bytes | bytearray,
    runtime_status: Mapping[str, object],
    *,
    elf_class: int = 64,
    endian: str = "little",
) -> dict[str, object]:
    """Separate CET declaration, support, loader choice, enforcement, and surfaces."""

    declaration = parse_gnu_property_notes(note_bytes, elf_class=elf_class, endian=endian)
    status = _mapping(runtime_status, "runtime_status")
    hardware = _mapping(status.get("hardware", {}), "runtime_status.hardware")
    kernel = _mapping(status.get("kernel", {}), "runtime_status.kernel")
    loader = _mapping(status.get("loader", {}), "runtime_status.loader")
    thread = _mapping(status.get("thread", {}), "runtime_status.thread")

    support = {
        "hardware": {
            "ibt": _optional_state(hardware, "ibt", "hardware"),
            "shstk": _optional_state(hardware, "shstk", "hardware"),
        },
        "kernel": {
            "user_ibt": _optional_state(kernel, "user_ibt", "kernel"),
            "user_shstk": _optional_state(kernel, "user_shstk", "kernel"),
        },
    }
    loader_state = {
        "ibt": _loader_value(loader.get("ibt"), "loader.ibt"),
        "shstk": _loader_value(loader.get("shstk"), "loader.shstk"),
        "source": _bounded_text(loader.get("source", "unspecified"), "loader.source"),
    }
    thread_state = {
        "ibt": _optional_state(thread, "ibt", "thread"),
        "shstk": _optional_state(thread, "shstk", "thread"),
        "shstk_locked": _optional_state(thread, "shstk_locked", "thread"),
        "wrss": _optional_state(thread, "wrss", "thread"),
        "no_track": _optional_state(thread, "no_track", "thread"),
        "source": _bounded_text(thread.get("source", "unspecified"), "thread.source"),
    }

    proc_report: dict[str, object] | None = None
    if "proc_status" in status:
        proc_report = parse_proc_status(status["proc_status"])
        for feature in ("shstk", "shstk_locked", "wrss"):
            observed = proc_report[feature]
            observed_state = _state(observed, f"proc_status.{feature}")
            thread_state[feature] = _merge_observation(
                str(thread_state[feature]), observed_state, f"thread.{feature}"
            )

    if "arch_shstk_status" in status:
        arch_status = _mapping(status["arch_shstk_status"], "arch_shstk_status")
        for feature in ("shstk", "wrss"):
            observed = _optional_state(arch_status, feature, "arch_shstk_status")
            thread_state[feature] = _merge_observation(
                str(thread_state[feature]), observed, f"thread.{feature}"
            )

    for feature, kernel_name in (("ibt", "user_ibt"), ("shstk", "user_shstk")):
        if thread_state[feature] == VERDICT_USABLE and support["hardware"][feature] == VERDICT_BLOCKED:
            raise WpgapMitigError(f"thread {feature} cannot be enabled when hardware support is disabled")
        if thread_state[feature] == VERDICT_USABLE and support["kernel"][kernel_name] == VERDICT_BLOCKED:
            raise WpgapMitigError(f"thread {feature} cannot be enabled when kernel support is disabled")
    if thread_state["wrss"] == VERDICT_USABLE and thread_state["shstk"] == VERDICT_BLOCKED:
        raise WpgapMitigError("WRSS cannot be enabled while SHSTK is disabled")

    raw_surfaces = status.get("surfaces", [])
    if not isinstance(raw_surfaces, Sequence) or isinstance(raw_surfaces, (str, bytes, bytearray)):
        raise WpgapMitigError("runtime_status.surfaces must be an array")
    if len(raw_surfaces) > MAX_SURFACES:
        raise WpgapMitigError(f"surface count exceeds {MAX_SURFACES}")
    allowed_transfers = {
        "indirect_call", "indirect_jump", "direct_call", "direct_jump", "return",
        "signal_restore", "context_restore",
    }
    analyzed_surfaces: list[dict[str, object]] = []
    for index, raw in enumerate(raw_surfaces):
        surface = _mapping(raw, f"surface {index}")
        name = _bounded_text(surface.get("name", f"surface-{index}"), f"surface {index}.name")
        if not _NAME_RE.fullmatch(name):
            raise WpgapMitigError(f"surface {index}.name contains unsupported characters")
        transfer = _bounded_text(surface.get("transfer"), f"surface {index}.transfer")
        if transfer not in allowed_transfers:
            raise WpgapMitigError(f"unsupported transfer kind {transfer!r}")
        entry, entry_reasons = _surface_entry(
            transfer, surface, str(thread_state["ibt"]), str(thread_state["no_track"])
        )
        ret, return_reasons = _surface_return(transfer, surface, str(thread_state["shstk"]))
        analyzed_surfaces.append({
            "name": name,
            "transfer": transfer,
            "entry": entry,
            "return": ret,
            "overall": _combined_surface(entry, ret),
            "entry_reasons": entry_reasons,
            "return_reasons": return_reasons,
        })

    warnings: list[str] = []
    if declaration["ibt"] is True and thread_state["ibt"] != VERDICT_USABLE:
        warnings.append("ELF declares IBT compatibility, but saved thread status does not establish IBT enforcement")
    if declaration["shstk"] is True and thread_state["shstk"] != VERDICT_USABLE:
        warnings.append("ELF declares SHSTK compatibility, but saved thread status does not establish SHSTK enforcement")
    if declaration["ibt"] is not True and thread_state["ibt"] == VERDICT_USABLE:
        warnings.append("runtime IBT is enabled without an IBT declaration; explicit runtime evidence remains authoritative")
    if declaration["shstk"] is not True and thread_state["shstk"] == VERDICT_USABLE:
        warnings.append("runtime SHSTK is enabled without a SHSTK declaration; explicit runtime evidence remains authoritative")

    counts = {state: 0 for state in (VERDICT_USABLE, VERDICT_BLOCKED, VERDICT_UNKNOWN)}
    for item in analyzed_surfaces:
        overall = item["overall"]
        if isinstance(overall, str) and overall in counts:
            counts[overall] += 1
    rendered_support = {
        "hardware": {
            "ibt": _support_word(str(support["hardware"]["ibt"])),
            "shstk": _support_word(str(support["hardware"]["shstk"])),
        },
        "kernel": {
            "user_ibt": _support_word(str(support["kernel"]["user_ibt"])),
            "user_shstk": _support_word(str(support["kernel"]["user_shstk"])),
        },
    }
    rendered_loader = {
        "ibt": loader_state["ibt"] if loader_state["ibt"] == "rejected" else
        _enabled_word(str(loader_state["ibt"])),
        "shstk": loader_state["shstk"] if loader_state["shstk"] == "rejected" else
        _enabled_word(str(loader_state["shstk"])),
        "source": loader_state["source"],
    }
    rendered_thread = {
        feature: _enabled_word(str(thread_state[feature]))
        for feature in ("ibt", "shstk", "shstk_locked", "wrss", "no_track")
    }
    rendered_thread["source"] = str(thread_state["source"])
    return {
        "analysis": "CET evidence layers and transfer admissibility",
        "declaration": declaration,
        "support": rendered_support,
        "loader": rendered_loader,
        "thread": rendered_thread,
        "enforcement": {
            "ibt": _enabled_word(str(thread_state["ibt"])),
            "shstk": _enabled_word(str(thread_state["shstk"])),
            "basis": "saved per-thread facts only; declaration and loader state are not promoted",
        },
        "proc_status": proc_report,
        "surfaces": analyzed_surfaces,
        "surface_counts": counts,
        "warnings": warnings,
        "non_conclusions": [
            "ENDBR presence is not evidence that IBT is enabled",
            "an admissible transfer is not proof that its target is semantically useful",
            "no generic CET-bypass conclusion is produced",
        ],
    }


def _kernel_version(value: object) -> tuple[int, int, int] | None:
    if value is None:
        return None
    text = _bounded_text(value, "kernel_version")
    if not _KERNEL_RE.fullmatch(text):
        raise WpgapMitigError("kernel_version must begin with major.minor[.patch]")
    match = re.match(r"^([0-9]{1,3})\.([0-9]{1,3})(?:\.([0-9]{1,3}))?", text)
    if match is None:
        raise WpgapMitigError("kernel_version must begin with major.minor[.patch]")
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def _exact_args(value: object, label: str) -> tuple[int, ...] | None:
    if value is None:
        return None
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise WpgapMitigError(f"{label} must be exactly six unsigned 64-bit integers")
    if len(value) != 6:
        raise WpgapMitigError(f"{label} must contain exactly six syscall arguments")
    return tuple(_uint(item, f"{label}[{index}]", 0xFFFFFFFFFFFFFFFF) for index, item in enumerate(value))


def _syscall_decision(
    program: Sequence[_seccomp.Instruction],
    *,
    name: str,
    number: int,
    audit_arch: int,
    args: tuple[int, ...] | None,
    endian: str,
    complete: str,
    mediation: str,
) -> dict[str, object]:
    if args is None:
        return {
            "name": name, "number": number, "args": None, "action": None,
            "raw": None, "verdict": VERDICT_UNKNOWN,
            "reason": "exact six-argument syscall tuple was not supplied",
        }
    try:
        raw = _seccomp.execute_filter(program, number, audit_arch, args, endian)
    except _seccomp.SeccompError as exc:
        raise WpgapMitigError(f"seccomp evaluation failed for {name}: {exc}") from exc
    action = raw & _seccomp.SECCOMP_RET_ACTION_FULL
    rendered = _seccomp.action_name(raw)
    if action in {_seccomp.SECCOMP_RET_ALLOW, _seccomp.SECCOMP_RET_LOG}:
        if complete == VERDICT_USABLE:
            verdict = VERDICT_USABLE
            reason = "effective supplied filter directly allows execution"
        else:
            verdict = VERDICT_UNKNOWN
            reason = "this filter allows the call, but additional stacked filters are not excluded"
    elif action in {_seccomp.SECCOMP_RET_USER_NOTIF, _seccomp.SECCOMP_RET_TRACE}:
        if mediation == VERDICT_BLOCKED:
            verdict = VERDICT_BLOCKED
            reason = "saved supervisor/tracer outcome denies this exact call"
        elif mediation == VERDICT_USABLE and complete == VERDICT_USABLE:
            verdict = VERDICT_USABLE
            reason = "saved supervisor/tracer outcome continues this exact call"
        else:
            verdict = VERDICT_UNKNOWN
            reason = "USER_NOTIF/TRACE outcome is unresolved or additional filters are possible"
    else:
        verdict = VERDICT_BLOCKED
        reason = f"seccomp action {rendered} does not execute the syscall"
    return {
        "name": name,
        "number": number,
        "args": list(args),
        "action": rendered,
        "raw": f"0x{raw:08x}",
        "verdict": verdict,
        "reason": reason,
    }


def _resource(resources: Mapping[str, object], key: str) -> str:
    return _state(resources.get(key), f"resources.{key}")


def _permission(permissions: Mapping[str, object], op: str) -> str:
    value = permissions.get(op, permissions.get("default"))
    return _state(value, f"permissions.{op}")


def _restriction_state(
    op: str,
    *,
    restricted: str,
    allowed_ops: set[str],
    allowed_flags: int,
    required_flags: int,
    op_flags: Mapping[str, int],
) -> tuple[str, str]:
    if restricted == VERDICT_BLOCKED:
        return VERDICT_USABLE, "ring is explicitly unrestricted"
    if restricted == VERDICT_UNKNOWN:
        return VERDICT_UNKNOWN, "effective ring restrictions are unknown"
    if op not in allowed_ops:
        return VERDICT_BLOCKED, "opcode is absent from the effective ring restriction allowlist"
    flags = op_flags.get(op, 0)
    if flags & ~allowed_flags:
        return VERDICT_BLOCKED, "SQE uses flags outside the effective allowed-SQE mask"
    if flags & required_flags != required_flags:
        return VERDICT_BLOCKED, "SQE omits flags required by the effective restriction mask"
    return VERDICT_USABLE, "opcode and supplied SQE flags satisfy effective ring restrictions"


def _operation_resources(
    op: str,
    resources: Mapping[str, object],
    target_fd: str,
) -> tuple[str, list[str], list[str]]:
    """Return resource gate, reasons, and generic ORW roles for one opcode."""

    ordinary = _resource(resources, "ordinary_buffer")
    output = _resource(resources, "output_fd")
    path = _resource(resources, "path")
    registered = _resource(resources, "registered_buffer")
    iovecs = _resource(resources, "iovecs")
    socket = _resource(resources, "connected_socket")
    pipe = _resource(resources, "pipe")
    msghdr = _resource(resources, "msghdr")
    zc_completion = _resource(resources, "zc_completion")
    buffer_selection = _resource(resources, "buffer_selection")

    if op in {"OPENAT", "OPENAT2"}:
        return path, ["path memory/dir basis is required"], ["open"]
    if op == "READ":
        return _and_states(target_fd, ordinary), ["target fd and ordinary buffer are required"], ["read"]
    if op == "READV":
        return _and_states(target_fd, iovecs), ["target fd and valid iovecs are required"], ["read"]
    if op == "READ_FIXED":
        return _and_states(target_fd, registered), ["target fd and matching registered buffer are required"], ["read"]
    if op == "READ_MULTISHOT":
        return _and_states(target_fd, buffer_selection), ["target fd and buffer-selection resources are required"], ["read"]
    if op == "WRITE":
        return _and_states(output, ordinary), ["output fd and ordinary buffer are required"], ["emit"]
    if op == "WRITEV":
        return _and_states(output, iovecs), ["output fd and valid iovecs are required"], ["emit"]
    if op == "WRITE_FIXED":
        return _and_states(output, registered), ["output fd and matching registered buffer are required"], ["emit"]
    if op == "SEND":
        return _and_states(socket, ordinary), ["connected socket and ordinary buffer are required"], ["emit"]
    if op == "SENDMSG":
        return _and_states(socket, msghdr), ["connected socket and valid msghdr are required"], ["emit"]
    if op == "SEND_ZC":
        return _and_states(socket, ordinary, zc_completion), [
            "connected socket, ordinary buffer, and zero-copy completion handling are required"
        ], ["emit"]
    if op == "SENDMSG_ZC":
        return _and_states(socket, msghdr, zc_completion), [
            "connected socket, msghdr, and zero-copy completion handling are required"
        ], ["emit"]
    if op == "SPLICE":
        file_to_pipe = _and_states(target_fd, pipe)
        pipe_to_output = _and_states(pipe, output)
        return _or_states(file_to_pipe, pipe_to_output), [
            f"file_to_pipe={file_to_pipe}", f"pipe_to_output={pipe_to_output}",
            "at least one splice endpoint must be a pipe",
        ], ["read_if_file_to_pipe", "emit_if_pipe_to_output"]
    if op == "RECV":
        return _and_states(socket, ordinary), ["connected socket and ordinary buffer are required"], ["socket_read"]
    if op == "RECVMSG":
        return _and_states(socket, msghdr), ["connected socket and msghdr are required"], ["socket_read"]
    if op == "RECV_ZC":
        return _and_states(socket, registered), ["connected socket and registered zero-copy resources are required"], ["socket_read"]
    if op == "TEE":
        return pipe, ["two suitable pipes are required; TEE is not a generic target read or emit"], []
    if op in {"SOCKET", "PIPE", "ACCEPT", "CONNECT", "FIXED_FD_INSTALL", "STATX", "CLOSE"}:
        return VERDICT_UNKNOWN, ["this lifecycle/metadata operation needs operation-specific facts and is not promoted to ORW"], []
    if op == "URING_CMD":
        return VERDICT_UNKNOWN, ["URING_CMD is device-specific and intentionally opaque"], []
    return VERDICT_UNKNOWN, ["no generic resource model exists for this exact opcode"], []


def _sqpoll_file_gate(
    ring: Mapping[str, object],
    resources: Mapping[str, object],
    op: str,
) -> tuple[str, str]:
    """Apply the saved IORING_FEAT_SQPOLL_NONFIXED/fixed-file fact."""

    if op not in _FD_OPS:
        return VERDICT_USABLE, "opcode is not modeled as consuming an fd"
    sqpoll = _optional_state(ring, "sqpoll", "ring")
    if sqpoll == VERDICT_BLOCKED:
        return VERDICT_USABLE, "ordinary (non-SQPOLL) ring does not require SQPOLL fixed-file handling"
    fixed_files = _resource(resources, "fixed_files")
    nonfixed = _optional_state(ring, "sqpoll_nonfixed", "ring")
    if sqpoll == VERDICT_UNKNOWN:
        if fixed_files == VERDICT_USABLE:
            return VERDICT_USABLE, "fixed-file resources make fd operations usable in either ring mode"
        return VERDICT_UNKNOWN, "ring mode and SQPOLL file-registration requirements are unresolved"
    if nonfixed == VERDICT_USABLE:
        return VERDICT_USABLE, "saved IORING_FEAT_SQPOLL_NONFIXED fact permits ordinary fds"
    if fixed_files == VERDICT_USABLE:
        return VERDICT_USABLE, "suitable files were already registered for SQPOLL"
    if nonfixed == VERDICT_BLOCKED:
        return fixed_files, "SQPOLL non-fixed-file support is absent, so suitable registered files are required"
    return VERDICT_UNKNOWN, "SQPOLL non-fixed-file feature status is unknown and fixed files are unavailable"


def _ring_acquisition(
    ring: Mapping[str, object],
    decisions: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    exists = _optional_state(ring, "exists", "ring")
    creation = _optional_state(ring, "creation_policy", "ring")
    setup = str(decisions["setup"]["verdict"])
    if exists == VERDICT_USABLE:
        acquired = VERDICT_USABLE
        acquire_reason = "a pre-existing ring is supplied; setup filtering is irrelevant to acquisition"
        setup_required: bool | None = False
    elif exists == VERDICT_BLOCKED:
        acquired = _and_states(setup, creation)
        acquire_reason = "no ring exists, so exact setup reach and creation policy are both required"
        setup_required = True
    else:
        create_alternative = _and_states(setup, creation)
        acquired = _or_states(VERDICT_UNKNOWN, create_alternative)
        acquire_reason = "existing-ring state is unknown; a proven creation path could still establish acquisition"
        setup_required = None

    mapped = _optional_state(ring, "mapped", "ring")
    if mapped != VERDICT_USABLE:
        mapped = _or_states(mapped, _optional_state(ring, "mapping_reach", "ring"))
    enabled_now = _optional_state(ring, "enabled", "ring")
    enabled = enabled_now
    register_required: bool | None = False
    if enabled != VERDICT_USABLE:
        register_required = True if enabled_now == VERDICT_BLOCKED else None
        enable_policy = _optional_state(ring, "enable_policy", "ring")
        register = str(decisions["register"]["verdict"])
        register_args = decisions["register"].get("args")
        exact_enable = VERDICT_UNKNOWN
        if isinstance(register_args, list) and len(register_args) == 6:
            exact_enable = (
                VERDICT_USABLE
                if register_args[1] == IORING_REGISTER_ENABLE_RINGS
                else VERDICT_BLOCKED
            )
            if "fd" in ring:
                ring_fd = _uint(ring["fd"], "ring.fd", 0x7FFFFFFF)
                if register_args[0] != ring_fd:
                    exact_enable = VERDICT_BLOCKED
        enable_path = _and_states(register, exact_enable, enable_policy)
        enabled = _or_states(enabled_now, enable_path)
    overall = _and_states(acquired, mapped, enabled)
    return {
        "acquired": acquired,
        "mapped": mapped,
        "enabled": enabled,
        "overall": overall,
        "setup_required": setup_required,
        "register_required": register_required,
        "reason": acquire_reason,
    }


def _submission_state(
    ring: Mapping[str, object],
    acquisition: Mapping[str, object],
    enter_decision: Mapping[str, object],
    enter_args: tuple[int, ...] | None,
) -> dict[str, object]:
    base = str(acquisition["overall"])
    sqpoll = _optional_state(ring, "sqpoll", "ring")
    enter = str(enter_decision["verdict"])
    if enter_args is None:
        ring_fd_match = VERDICT_UNKNOWN
        ordinary_enter = VERDICT_UNKNOWN
    else:
        if "fd" in ring:
            ring_fd = _uint(ring["fd"], "ring.fd", 0x7FFFFFFF)
            ring_fd_match = VERDICT_USABLE if enter_args[0] == ring_fd else VERDICT_BLOCKED
        else:
            ring_fd_match = VERDICT_UNKNOWN
        submits_entries = VERDICT_USABLE if enter_args[1] > 0 else VERDICT_BLOCKED
        ordinary_enter = _and_states(enter, ring_fd_match, submits_entries)
    if sqpoll == VERDICT_BLOCKED:
        return {
            "verdict": _and_states(base, ordinary_enter),
            "path": "io_uring_enter",
            "reason": (
                "ordinary ring submission requires an allowed exact call targeting ring.fd with to_submit > 0"
            ),
        }
    if sqpoll == VERDICT_UNKNOWN:
        alternative = _or_states(ordinary_enter, VERDICT_UNKNOWN)
        return {
            "verdict": _and_states(base, alternative),
            "path": "unknown ordinary/SQPOLL mode",
            "reason": "SQPOLL mode is unknown; a directly usable enter call is sufficient, otherwise unresolved",
        }

    awake = _optional_state(ring, "sq_thread_awake", "ring")
    need_wakeup = _optional_state(ring, "sq_need_wakeup", "ring")
    if awake == VERDICT_USABLE and need_wakeup == VERDICT_BLOCKED:
        return {
            "verdict": base,
            "path": "awake SQPOLL",
            "reason": "saved status says the SQ poller is awake and SQ_NEED_WAKEUP is clear",
        }
    if need_wakeup == VERDICT_USABLE:
        has_flag = enter_args is not None and bool(enter_args[3] & IORING_ENTER_SQ_WAKEUP)
        wake_call = _and_states(enter, ring_fd_match) if has_flag else VERDICT_BLOCKED
        return {
            "verdict": _and_states(base, wake_call),
            "path": "SQPOLL wakeup via io_uring_enter",
            "reason": (
                "SQ_NEED_WAKEUP is set; exact enter is evaluated with IORING_ENTER_SQ_WAKEUP"
                if has_flag else
                "SQ_NEED_WAKEUP is set, but the supplied exact enter flags omit IORING_ENTER_SQ_WAKEUP"
            ),
        }
    if ordinary_enter == VERDICT_USABLE:
        return {
            "verdict": base,
            "path": "io_uring_enter fallback",
            "reason": "SQPOLL liveness is not proven, but exact io_uring_enter is usable",
        }
    return {
        "verdict": _and_states(base, VERDICT_UNKNOWN),
        "path": "unresolved SQPOLL",
        "reason": "poller liveness/wakeup state is insufficient and a matching, submitting enter is not proven usable",
    }


@_declared_contract
def analyze_io_uring(
    filter_source: bytes | bytearray | Sequence[object] | Mapping[str, object],
    capability_facts: Mapping[str, object],
    *,
    endian: str = "little",
) -> dict[str, object]:
    """Evaluate exact io_uring control calls and an opcode/resource capability matrix."""

    if endian not in ("little", "big"):
        raise WpgapMitigError("endian must be 'little' or 'big'")
    facts = _mapping(capability_facts, "capability_facts")
    try:
        program = _patterns.decode_filter(filter_source, endian=endian)
    except (_patterns.SeccompPatternError, _seccomp.SeccompError) as exc:
        raise WpgapMitigError(f"invalid Linux seccomp filter: {exc}") from exc

    architecture = _bounded_text(facts.get("architecture", "amd64"), "architecture")
    if architecture not in _seccomp.AUDIT_ARCH:
        raise WpgapMitigError(
            f"unsupported architecture {architecture!r}; choose {', '.join(sorted(_seccomp.AUDIT_ARCH))}"
        )
    audit_arch = _seccomp.AUDIT_ARCH[architecture]
    complete = _state(facts.get("filter_is_complete"), "filter_is_complete")
    syscall_numbers = dict(IO_URING_SYSCALLS)
    if "syscall_numbers" in facts:
        supplied_numbers = _mapping(facts["syscall_numbers"], "syscall_numbers")
        for name in IO_URING_SYSCALLS:
            if name in supplied_numbers:
                syscall_numbers[name] = _uint(supplied_numbers[name], f"syscall_numbers.{name}", 0x7FFFFFFF)

    raw_calls = _mapping(facts.get("syscalls", {}), "syscalls")
    mediation_map = _mapping(facts.get("supervisor_outcomes", {}), "supervisor_outcomes")
    call_args: dict[str, tuple[int, ...] | None] = {}
    decisions: dict[str, dict[str, object]] = {}
    for name in ("setup", "enter", "register"):
        call_args[name] = _exact_args(raw_calls.get(name), f"syscalls.{name}")
        mediation = _state(mediation_map.get(name), f"supervisor_outcomes.{name}")
        decisions[name] = _syscall_decision(
            program,
            name=f"io_uring_{name}",
            number=syscall_numbers[name],
            audit_arch=audit_arch,
            args=call_args[name],
            endian=endian,
            complete=complete,
            mediation=mediation,
        )

    ring = _mapping(facts.get("ring", {}), "ring")
    acquisition = _ring_acquisition(ring, decisions)
    submission = _submission_state(ring, acquisition, decisions["enter"], call_args["enter"])

    raw_supported = facts.get("supported_ops")
    if not isinstance(raw_supported, Sequence) or isinstance(raw_supported, (str, bytes, bytearray)):
        raise WpgapMitigError("supported_ops must be an exact probe-derived array")
    if len(raw_supported) > MAX_OPS:
        raise WpgapMitigError(f"supported_ops exceeds {MAX_OPS} entries")
    supported: set[str] = set()
    for index, value in enumerate(raw_supported):
        op = _bounded_text(value, f"supported_ops[{index}]").upper()
        if not _OP_RE.fullmatch(op):
            raise WpgapMitigError(f"invalid opcode name {op!r}")
        if op in supported:
            raise WpgapMitigError(f"duplicate supported opcode {op}")
        supported.add(op)

    raw_considered = facts.get("considered_ops", sorted(supported))
    if not isinstance(raw_considered, Sequence) or isinstance(raw_considered, (str, bytes, bytearray)):
        raise WpgapMitigError("considered_ops must be an array")
    if len(raw_considered) > MAX_OPS:
        raise WpgapMitigError(f"considered_ops exceeds {MAX_OPS} entries")
    considered: list[str] = []
    for index, value in enumerate(raw_considered):
        op = _bounded_text(value, f"considered_ops[{index}]").upper()
        if not _OP_RE.fullmatch(op) or op in considered:
            raise WpgapMitigError("considered_ops must contain unique UAPI-style names")
        considered.append(op)

    restricted = _optional_state(ring, "restricted", "ring")
    raw_allowed_ops = ring.get("allowed_ops", [])
    if not isinstance(raw_allowed_ops, Sequence) or isinstance(raw_allowed_ops, (str, bytes, bytearray)):
        raise WpgapMitigError("ring.allowed_ops must be an array")
    allowed_ops: set[str] = set()
    for index, value in enumerate(raw_allowed_ops):
        op = _bounded_text(value, f"ring.allowed_ops[{index}]").upper()
        if not _OP_RE.fullmatch(op) or op in allowed_ops:
            raise WpgapMitigError("ring.allowed_ops must contain unique UAPI-style names")
        allowed_ops.add(op)
    allowed_flags = _uint(ring.get("allowed_sqe_flags", 0), "ring.allowed_sqe_flags", 0xFF)
    required_flags = _uint(ring.get("required_sqe_flags", 0), "ring.required_sqe_flags", 0xFF)
    if required_flags & ~allowed_flags:
        raise WpgapMitigError("required SQE flags must be a subset of allowed SQE flags")
    raw_op_flags = _mapping(ring.get("op_sqe_flags", {}), "ring.op_sqe_flags")
    op_flags: dict[str, int] = {}
    for key, value in raw_op_flags.items():
        normalized = _bounded_text(key, "ring.op_sqe_flags key").upper()
        if key != normalized or not _OP_RE.fullmatch(normalized) or normalized in op_flags:
            raise WpgapMitigError("ring.op_sqe_flags keys must be unique uppercase UAPI-style names")
        op_flags[normalized] = _uint(value, f"ring.op_sqe_flags.{key}", 0xFF)

    resources = _mapping(facts.get("resources", {}), "resources")
    permissions = _mapping(facts.get("permissions", {}), "permissions")
    kernel_version = _kernel_version(facts.get("kernel_version"))
    warnings: list[str] = []
    for op in sorted(supported):
        floor = _OP_FLOORS.get(op)
        if floor is not None and kernel_version is not None and kernel_version[:2] < floor:
            warnings.append(
                f"{op} is supplied as supported below its upstream {floor[0]}.{floor[1]} floor; "
                "the exact probe fact is retained (possible backport/custom kernel)"
            )

    # First pass establishes open reach without depending on a newly returned fd.
    preliminary: dict[str, dict[str, object]] = {}
    for op in considered:
        support = VERDICT_USABLE if op in supported else VERDICT_BLOCKED
        restriction, restriction_reason = _restriction_state(
            op,
            restricted=restricted,
            allowed_ops=allowed_ops,
            allowed_flags=allowed_flags,
            required_flags=required_flags,
            op_flags=op_flags,
        )
        permission = _permission(permissions, op)
        file_gate, file_reason = _sqpoll_file_gate(ring, resources, op)
        resource_state, resource_reasons, roles = _operation_resources(
            op, resources, _resource(resources, "target_fd")
        )
        verdict = _and_states(
            str(submission["verdict"]), support, restriction, permission, file_gate, resource_state
        )
        preliminary[op] = {
            "op": op,
            "verdict": verdict,
            "kernel_support": support,
            "submission": submission["verdict"],
            "restriction": restriction,
            "permission": permission,
            "sqpoll_file_gate": file_gate,
            "resources": resource_state,
            "roles": roles,
            "reasons": [
                "exact supported-op set includes this opcode" if support == VERDICT_USABLE else
                "exact supported-op set excludes this opcode",
                restriction_reason,
                file_reason,
                *resource_reasons,
            ],
        }

    opener_states = [
        str(preliminary[op]["verdict"]) for op in ("OPENAT", "OPENAT2") if op in preliminary
    ]
    opener = _or_states(*opener_states) if opener_states else VERDICT_BLOCKED
    preopened = _resource(resources, "target_fd")
    can_chain = _resource(resources, "cqes_readable")
    derived_fd = _and_states(opener, can_chain)
    target_fd = _or_states(preopened, derived_fd)
    open_reach = _or_states(preopened, opener)

    # Second pass lets a proven OPENAT CQE feed exact read/splice resource gates.
    matrix: list[dict[str, object]] = []
    for op in considered:
        row = dict(preliminary[op])
        restriction = str(row["restriction"])
        permission = str(row["permission"])
        file_gate = str(row["sqpoll_file_gate"])
        support = str(row["kernel_support"])
        resource_state, resource_reasons, roles = _operation_resources(op, resources, target_fd)
        row["resources"] = resource_state
        row["roles"] = roles
        row["verdict"] = _and_states(
            str(submission["verdict"]), support, restriction, permission, file_gate, resource_state
        )
        row["reasons"] = list(row["reasons"][:3]) + resource_reasons
        matrix.append(row)

    by_op = {str(row["op"]): row for row in matrix}
    memory_read_candidates: list[str] = []
    memory_emit_candidates: list[str] = []
    for op in ("READ", "READV", "READ_FIXED", "READ_MULTISHOT"):
        if op in by_op:
            memory_read_candidates.append(str(by_op[op]["verdict"]))
    for op in ("WRITE", "WRITEV", "WRITE_FIXED", "SEND", "SENDMSG", "SEND_ZC", "SENDMSG_ZC"):
        if op in by_op:
            memory_emit_candidates.append(str(by_op[op]["verdict"]))
    splice_file_to_pipe = VERDICT_BLOCKED
    splice_pipe_to_output = VERDICT_BLOCKED
    if "SPLICE" in by_op:
        splice_base = _and_states(
            str(by_op["SPLICE"]["submission"]),
            str(by_op["SPLICE"]["kernel_support"]),
            str(by_op["SPLICE"]["restriction"]),
            str(by_op["SPLICE"]["permission"]),
            str(by_op["SPLICE"]["sqpoll_file_gate"]),
        )
        splice_file_to_pipe = _and_states(
            splice_base, target_fd, _resource(resources, "pipe")
        )
        splice_pipe_to_output = _and_states(
            splice_base, _resource(resources, "pipe"), _resource(resources, "output_fd")
        )
    memory_read = (
        _or_states(*memory_read_candidates) if memory_read_candidates else VERDICT_BLOCKED
    )
    memory_emit = (
        _or_states(*memory_emit_candidates) if memory_emit_candidates else VERDICT_BLOCKED
    )
    read_reach = _or_states(memory_read, splice_file_to_pipe)
    emit_reach = _or_states(memory_emit, splice_pipe_to_output)
    memory_route = _and_states(
        open_reach, memory_read, memory_emit, _resource(resources, "memory_dataflow")
    )
    pipe_route = _and_states(
        open_reach, splice_file_to_pipe, splice_pipe_to_output,
        _resource(resources, "pipe_dataflow"),
    )
    complete_orw = _or_states(memory_route, pipe_route)

    return {
        "analysis": "seccomp-gated io_uring capability matrix",
        "architecture": architecture,
        "audit_arch": f"0x{audit_arch:08x}",
        "kernel_version": facts.get("kernel_version"),
        "filter_instruction_count": len(program),
        "filter_is_complete": {
            VERDICT_USABLE: True,
            VERDICT_BLOCKED: False,
            VERDICT_UNKNOWN: None,
        }[complete],
        "syscalls": decisions,
        "seccomp_visibility": {
            "visible": "io_uring_setup/register/enter number and six scalar arguments",
            "not_visible": "SQE opcode and pointed-to payload in mapped ring memory",
            "scope": "visibility does not establish that any SQE is supported, permitted, or resource-complete",
        },
        "ring_gate": acquisition,
        "submission": submission,
        "supported_ops_source": "exact caller-supplied probe/equivalent fact; version floors are warnings only",
        "matrix": matrix,
        "reach": {
            "open_reach": open_reach,
            "read_reach": read_reach,
            "emit_reach": emit_reach,
            "orw_equivalent": complete_orw,
            "target_fd": target_fd,
            "splice_file_to_pipe": splice_file_to_pipe,
            "splice_pipe_to_output": splice_pipe_to_output,
            "connected_memory_route": memory_route,
            "connected_pipe_route": pipe_route,
        },
        "warnings": warnings,
        "non_conclusions": [
            "no generic seccomp-bypass conclusion is produced",
            "ordinary syscall ORW was not re-analyzed by this io_uring-specific engine",
            "URING_CMD and unknown opcodes are not promoted to generic capabilities",
        ],
    }


@_declared_contract
def analyze_document(document: Mapping[str, object]) -> dict[str, object]:
    """Analyze one JSON-compatible document containing a CET or io_uring request."""

    value = _mapping(document, "document")
    mode = _bounded_text(value.get("mode"), "document.mode")
    if mode == "cet":
        note_hex_value = value.get("note_hex", "")
        if not isinstance(note_hex_value, str):
            raise WpgapMitigError("document.note_hex must be text")
        note_hex = note_hex_value
        if len(note_hex) > MAX_NOTE_BYTES * 2:
            raise WpgapMitigError("document.note_hex is too large")
        try:
            note = bytes.fromhex(note_hex)
        except ValueError as exc:
            raise WpgapMitigError("document.note_hex must be hexadecimal") from exc
        runtime = _mapping(value.get("runtime", {}), "document.runtime")
        elf_class = _uint(value.get("elf_class", 64), "document.elf_class", 64)
        return analyze_cet(
            note, runtime, elf_class=elf_class,
            endian=_bounded_text(value.get("endian", "little"), "document.endian"),
        )
    if mode == "io_uring":
        filter_source = value.get("filter")
        if filter_source is None:
            raise WpgapMitigError("document.filter is required")
        facts = _mapping(value.get("facts", {}), "document.facts")
        return analyze_io_uring(
            filter_source, facts,
            endian=_bounded_text(value.get("endian", "little"), "document.endian"),
        )
    raise WpgapMitigError("document.mode must be 'cet' or 'io_uring'")


def _read_bytes(path: str, maximum: int, label: str) -> bytes:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(maximum + 1)
    except OSError as exc:
        raise WpgapMitigError(f"cannot read {label}: {exc}") from exc
    if len(data) > maximum:
        raise WpgapMitigError(f"{label} exceeds {maximum} bytes")
    return data


def _read_json(path: str, label: str) -> object:
    raw = _read_bytes(path, MAX_JSON_BYTES, label)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WpgapMitigError(f"{label} is not valid UTF-8 JSON") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wpgap_mitig_cet_uring.py",
        description="offline CET and seccomp-to-io_uring ground-truth analyzer",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    cet = commands.add_parser("cet", help="analyze raw ELF note bytes plus saved runtime JSON")
    cet.add_argument("note", help="raw ELF note-section bytes")
    cet.add_argument("runtime", help="saved CET runtime facts as JSON")
    cet.add_argument("--elf-class", type=int, choices=(32, 64), default=64)
    cet.add_argument("--endian", choices=("little", "big"), default="little")
    uring = commands.add_parser("io-uring", help="analyze a JSON cBPF filter and io_uring facts")
    uring.add_argument("filter", help="JSON sock_filter instruction records")
    uring.add_argument("facts", help="saved ring/kernel/resource facts as JSON")
    uring.add_argument("--endian", choices=("little", "big"), default="little")
    document = commands.add_parser("document", help="analyze a combined JSON request")
    document.add_argument("input", help="combined request JSON")
    return parser


def _dispatch(arguments: argparse.Namespace) -> dict[str, object]:
    if arguments.command == "cet":
        note = _read_bytes(arguments.note, MAX_NOTE_BYTES, "note file")
        runtime = _mapping(_read_json(arguments.runtime, "runtime file"), "runtime file")
        return analyze_cet(note, runtime, elf_class=arguments.elf_class, endian=arguments.endian)
    if arguments.command == "io-uring":
        source = _read_json(arguments.filter, "filter file")
        facts = _mapping(_read_json(arguments.facts, "facts file"), "facts file")
        return analyze_io_uring(source, facts, endian=arguments.endian)
    if arguments.command == "document":
        return analyze_document(_mapping(_read_json(arguments.input, "input file"), "input file"))
    raise WpgapMitigError("unknown command")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the guarded offline JSON CLI."""

    parser = _parser()
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception:
        parser._print_message("wpgap_mitig_cet_uring: error: malformed argv\n", sys.stderr)
        return 2
    try:
        report = _dispatch(arguments)
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    except WpgapMitigError as exc:
        parser._print_message(f"wpgap_mitig_cet_uring: error: {exc}\n", sys.stderr)
        return 2
    except Exception:
        parser._print_message("wpgap_mitig_cet_uring: error: malformed CLI input\n", sys.stderr)
        return 2


__all__ = [
    "WpgapMitigError",
    "NT_GNU_PROPERTY_TYPE_0",
    "GNU_PROPERTY_X86_FEATURE_1_AND",
    "GNU_PROPERTY_X86_FEATURE_1_IBT",
    "GNU_PROPERTY_X86_FEATURE_1_SHSTK",
    "IO_URING_SYSCALLS",
    "IORING_ENTER_SQ_WAKEUP",
    "IORING_REGISTER_ENABLE_RINGS",
    "parse_gnu_property_notes",
    "parse_proc_status",
    "analyze_cet",
    "analyze_io_uring",
    "analyze_document",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
