#!/usr/bin/env python3
"""Offline mobile protection, obfuscation, and deterministic smali patch planning.

No application, bytecode, native library, device command, or external tool is executed.
The engine consumes supplied text/bytes and returns evidence and exact in-memory edits.
Patch application is guarded by a SHA-256 precondition and byte-for-byte line checks.

Coverage includes root/emulator/debugger/hooking/signature/pinning/RASP checks,
DexGuard/Allatori/R8-style obfuscation evidence, ProGuard and Allatori mapping reversal,
bounded string transforms, and auditable smali bypass automation.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import difflib
import hashlib
import io
import json
import re
import xml.etree.ElementTree as ET
import zipfile
import zlib
from pathlib import Path
from typing import Any, Mapping


MAX_TEXT = 64 << 20
MAX_ARCHIVE = 256 << 20
MAX_MEMBER = 64 << 20
MAX_MEMBERS = 65_536
MAX_TOTAL = 512 << 20
MAX_METHODS = 200_000
MAX_FINDINGS = 100_000
MAX_TRANSFORM = 8 << 20


class ProtectionError(ValueError):
    pass


_METHOD = re.compile(
    r"^\s*\.method\s+(?P<flags>.*?)\s+(?P<name>[^\s(]+)\((?P<args>[^)]*)\)(?P<ret>\S+)\s*$"
)
_CLASS = re.compile(r"^\s*\.class\s+.*?L([^;]+);\s*$", re.M)
_SMALI_METHOD = re.compile(r"^\s*\.method\s+.*?\s([^\s(]+)\(", re.M)

_CATEGORY_PATTERNS = {
    "root": re.compile(
        r"(?i)(?:isrooted|rootbeer|magisk|zygisk|superuser|/system/(?:xbin/)?su|/sbin/su|"
        r"test-keys|busybox|supersu|com\.topjohnwu|which\s+su|ro\.debuggable|ro\.secure)"
    ),
    "debugger": re.compile(
        r"(?i)(?:isdebuggerconnected|waitingfordebugger|debug\.isDebuggerConnected|TracerPid|ptrace|"
        r"/proc/(?:self|\d+)/(?:status|maps)|debuggerd)"
    ),
    "emulator": re.compile(
        r"(?i)(?:isemulator|goldfish|ranchu|genymotion|qemu|sdk_gphone|vbox86|generic_x86|"
        r"Build;->(?:FINGERPRINT|MODEL|HARDWARE|PRODUCT|BRAND|DEVICE))"
    ),
    "hooking": re.compile(
        r"(?i)(?:frida|gum-js-loop|27042|xposed|lsposed|substrate|cydia|edxposed|riru|"
        r"lib(?:substrate|frida)|de\.robv\.android\.xposed)"
    ),
    "signature-integrity": re.compile(
        r"(?i)(?:getSigningCertificateHistory|getApkContentsSigners|getSignatures|SigningInfo|"
        r"MessageDigest;->digest|signature|tamper|integrity|SafetyNet|play\.core\.integrity)"
    ),
    "tls-pinning": re.compile(
        r"(?i)(?:CertificatePinner|checkServerTrusted|X509TrustManager|HostnameVerifier|"
        r"SSLPeerUnverifiedException|network_security_config|pin-set|sha256/)"
    ),
    "rasp": re.compile(
        r"(?i)(?:dexguard|guardsquare|promon|shield|appdome|approov|threatmetrix|liapp|"
        r"securing\.suite|runtime.?application.?self.?protection|anti.?tamper|anti.?hook)"
    ),
}

_SDK_MARKERS = {
    "dexguard": re.compile(r"(?i)(?:com/guardsquare/dexguard|dexguard|com/saikoa/dexguard)"),
    "allatori": re.compile(r"(?i)(?:allatori|com/allatori)"),
    "appdome": re.compile(r"(?i)(?:appdome|com/appdome)"),
    "promon-shield": re.compile(r"(?i)(?:promon|shield4j|com/promon)"),
    "approov": re.compile(r"(?i)(?:approov|io/approov)"),
    "rootbeer": re.compile(r"(?i)(?:com/scottyab/rootbeer|rootbeer)"),
}

_CALLSITE_FALSE = re.compile(
    r"(?i)(?:Landroid/os/Debug;->isDebuggerConnected\(\)Z|Ljava/io/File;->exists\(\)Z|"
    r"L[^;]*(?:RootBeer|RootCheck|EmulatorCheck|HookCheck)[^;]*;->[^\s(]+\([^)]*\)Z)"
)
_MOVE_RESULT = re.compile(r"^(?P<indent>\s*)move-result(?:/from16)?\s+(?P<reg>[vp]\d+)\s*(?:#.*)?$")


def _digest(text: str) -> str:
    try:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
    except UnicodeError as exc:
        raise ProtectionError("text is not valid UTF-8") from exc


def _methods(text: str) -> list[dict[str, Any]]:
    if not isinstance(text, str) or len(text.encode("utf-8", "replace")) > MAX_TEXT:
        raise ProtectionError("smali text exceeds cap")
    lines = text.splitlines()
    output, index = [], 0
    while index < len(lines):
        match = _METHOD.match(lines[index])
        if not match:
            index += 1
            continue
        end = index + 1
        while end < len(lines) and not re.match(r"^\s*\.end\s+method\b", lines[end]):
            end += 1
        if end >= len(lines):
            raise ProtectionError(f"unterminated smali method at line {index + 1}")
        output.append({"start": index, "end": end, "header": lines[index], "body": lines[index + 1:end],
                       "flags": match.group("flags").split(), "name": match.group("name"),
                       "arguments": match.group("args"), "return_type": match.group("ret")})
        if len(output) > MAX_METHODS:
            raise ProtectionError("smali method count exceeds cap")
        index = end + 1
    return output


def _categories(text: str) -> list[str]:
    return sorted(name for name, pattern in _CATEGORY_PATTERNS.items() if pattern.search(text))


def _boolean_polarity(name: str) -> bool | None:
    lowered = name.lower()
    if re.search(r"(?:notrooted|notdebugged|notemulated|notcompromised|notinfected|clean|checkpassed)", lowered):
        return True
    if re.search(r"(?:rooted|debugger|emulator|tamper|compromised|hooked|instrumented|frida|xposed|detected)", lowered):
        return False
    if re.search(r"(?:valid|trusted|verified|integrityok|safe|secure)", lowered):
        return True
    return None


def _return_body(return_type: str, polarity: bool | None) -> list[str] | None:
    if return_type == "V":
        return ["    .locals 0", "    return-void"]
    if return_type == "Z" and polarity is not None:
        return ["    .locals 1", f"    const/4 v0, 0x{1 if polarity else 0:x}", "    return v0"]
    if return_type in {"B", "S", "C", "I", "F"}:
        return ["    .locals 1", "    const/4 v0, 0x0", "    return v0"]
    if return_type in {"J", "D"}:
        return ["    .locals 2", "    const-wide/16 v0, 0x0", "    return-wide v0"]
    return None


def _patch_id(path: str, kind: str, start: int, original: list[str], replacement: list[str]) -> str:
    material = json.dumps([path, kind, start, original, replacement], separators=(",", ":"), ensure_ascii=False)
    return _digest(material)[:20]


def plan_smali_patches(text: str, *, path: str = "classes.smali") -> dict[str, Any]:
    """Return exact, non-overlapping edits; ambiguous gate polarity remains analysis-only."""
    lines = text.splitlines()
    source_hash = _digest(text)
    patches, findings = [], []
    for method in _methods(text):
        method_text = method["header"] + "\n" + "\n".join(method["body"])
        categories = _categories(method_text)
        if not categories:
            continue
        evidence = []
        for relative, line in enumerate(method["body"], start=method["start"] + 2):
            hit = _categories(line)
            if hit:
                evidence.append({"line": relative, "categories": hit, "text": line.strip()[:500]})
        finding = {"path": path, "method": method["name"], "start_line": method["start"] + 1,
                   "end_line": method["end"] + 1, "categories": categories, "evidence": evidence}
        findings.append(finding)
        flags = set(method["flags"])
        polarity = _boolean_polarity(method["name"])
        replacement = _return_body(method["return_type"], polarity)
        unsafe_directives = any(re.match(r"\s*\.(?:annotation|catch|catchall)\b", line) for line in method["body"])
        semantic_safe = ((method["return_type"] == "Z" and polarity is not None)
                         or (method["return_type"] == "V" and
                             method["name"].lower() in {"checkservertrusted", "checkclienttrusted"}))
        whole_method_safe = (replacement is not None and semantic_safe
                             and not flags & {"abstract", "native"} and not unsafe_directives)
        if whole_method_safe:
            original = method["body"]
            patch = {"path": path, "kind": "replace-method-body", "method": method["name"],
                     "categories": categories, "start_line": method["start"] + 2,
                     "end_line": method["end"], "original": original, "replacement": replacement,
                     "safe": True, "reason": "gate method name gives deterministic return polarity",
                     "source_sha256": source_hash}
            patch["id"] = _patch_id(path, patch["kind"], patch["start_line"], original, replacement)
            patches.append(patch)
            continue
        # A narrow call-site edit is safe only for a known boolean detector followed by
        # an immediate move-result.  The call remains but its result is forced false.
        body = method["body"]
        for body_index, line in enumerate(body[:-1]):
            if not _CALLSITE_FALSE.search(line):
                continue
            next_index = body_index + 1
            while next_index < len(body) and (not body[next_index].strip() or body[next_index].lstrip().startswith("#")):
                next_index += 1
            if next_index >= len(body):
                continue
            move = _MOVE_RESULT.match(body[next_index])
            if not move:
                continue
            replacement_line = f"{move.group('indent')}const/4 {move.group('reg')}, 0x0"
            absolute = method["start"] + 1 + next_index
            original = [lines[absolute]]
            replacement_lines = [replacement_line]
            patch = {"path": path, "kind": "force-call-result-false", "method": method["name"],
                     "categories": sorted(set(categories) & {"root", "debugger", "emulator", "hooking"}),
                     "start_line": absolute + 1, "end_line": absolute + 1, "original": original,
                     "replacement": replacement_lines, "safe": True,
                     "reason": "known boolean detector has an immediate move-result",
                     "source_sha256": source_hash}
            patch["id"] = _patch_id(path, patch["kind"], patch["start_line"], original, replacement_lines)
            patches.append(patch)
    # Remove any overlapping narrow edit defensively and sort deterministically.
    patches.sort(key=lambda item: (item["start_line"], item["end_line"], item["id"]))
    accepted, occupied = [], set()
    for patch in patches:
        span = set(range(patch["start_line"], patch["end_line"] + 1))
        if span & occupied:
            continue
        occupied |= span
        accepted.append(patch)
    return {"path": path, "source_sha256": source_hash, "findings": findings,
            "patches": accepted, "ambiguous_findings": [item for item in findings
            if not any(patch["method"] == item["method"] for patch in accepted)]}


def apply_smali_plan(text: str, plan: Mapping[str, Any], *, selected_ids: set[str] | None = None) -> dict[str, Any]:
    """Apply a plan in memory after strict hash/span/original checks."""
    if plan.get("source_sha256") != _digest(text):
        raise ProtectionError("smali source hash does not match patch plan")
    patches = [dict(item) for item in plan.get("patches", [])
               if selected_ids is None or item.get("id") in selected_ids]
    if selected_ids is not None and selected_ids - {item.get("id") for item in patches}:
        raise ProtectionError("selected patch id is absent from plan")
    lines = text.splitlines()
    spans = []
    for patch in patches:
        if not patch.get("safe"):
            raise ProtectionError("refusing an unsafe patch")
        start, end = patch.get("start_line"), patch.get("end_line")
        if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start or end > len(lines):
            raise ProtectionError("patch span is invalid")
        if lines[start - 1:end] != patch.get("original"):
            raise ProtectionError("patch original lines do not match source")
        original, replacement = patch.get("original"), patch.get("replacement")
        if (not isinstance(original, list) or not isinstance(replacement, list)
                or not all(isinstance(line, str) for line in original + replacement)):
            raise ProtectionError("patch lines must be string lists")
        expected_id = _patch_id(str(patch.get("path")), str(patch.get("kind")), start, original, replacement)
        if patch.get("id") != expected_id:
            raise ProtectionError("patch id does not match its contents")
        spans.append((start, end, patch))
    spans.sort(key=lambda item: item[:2])
    for left, right in zip(spans, spans[1:]):
        if left[1] >= right[0]:
            raise ProtectionError("patch spans overlap")
    output = list(lines)
    for start, end, patch in reversed(spans):
        output[start - 1:end] = patch["replacement"]
    patched = "\n".join(output) + ("\n" if text.endswith("\n") else "")
    diff = "\n".join(difflib.unified_diff(text.splitlines(), patched.splitlines(),
                                           fromfile=plan.get("path", "before.smali"),
                                           tofile=plan.get("path", "after.smali"), lineterm=""))
    return {"patched_text": patched, "source_sha256": _digest(text), "patched_sha256": _digest(patched),
            "applied_ids": [patch["id"] for _, _, patch in spans], "diff": diff}


def apply_smali_files(smali_files: Mapping[str, str], plans: list[Mapping[str, Any]],
                      *, selected_by_path: Mapping[str, set[str]] | None = None) -> dict[str, Any]:
    """Apply exact plans to a supplied in-memory file mapping, never touching disk."""
    plan_by_path = {}
    for plan in plans:
        path = plan.get("path")
        if not isinstance(path, str) or path in plan_by_path:
            raise ProtectionError("plans must have unique string paths")
        plan_by_path[path] = plan
    unknown = set(plan_by_path) - set(smali_files)
    if unknown:
        raise ProtectionError(f"plan path is absent from supplied files: {sorted(unknown)[0]}")
    output, reports = dict(smali_files), []
    for path in sorted(plan_by_path):
        selected = selected_by_path.get(path) if selected_by_path is not None else None
        report = apply_smali_plan(smali_files[path], plan_by_path[path], selected_ids=selected)
        output[path] = report["patched_text"]
        reports.append({"path": path, **{key: value for key, value in report.items() if key != "patched_text"}})
    return {"files": output, "reports": reports}


def parse_proguard_mapping(text: str) -> dict[str, Any]:
    if not isinstance(text, str) or len(text.encode("utf-8", "replace")) > MAX_TEXT:
        raise ProtectionError("mapping exceeds cap")
    classes, current = {}, None
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        match = re.match(r"^([^\s].*?)\s+->\s+([^:]+):\s*$", raw)
        if match:
            original, obfuscated = match.group(1).strip(), match.group(2).strip()
            current = {"original": original, "obfuscated": obfuscated, "members": [], "line": lineno}
            classes[obfuscated] = current
            continue
        if current is None:
            continue
        member = re.match(
            r"^\s+(?:(\d+):(?:(\d+):)?\s*)?(.+?)\s+([^\s(]+)(\([^)]*\))?(?::\d+(?::\d+)?)?\s+->\s+(\S+)\s*$",
            raw,
        )
        if member:
            current["members"].append({"type": member.group(3), "original": member.group(4),
                                       "arguments": member.group(5), "obfuscated": member.group(6),
                                       "line": lineno})
    return {"format": "proguard", "classes": classes, "class_count": len(classes),
            "member_count": sum(len(item["members"]) for item in classes.values())}


def parse_allatori_mapping(text: str) -> dict[str, Any]:
    if not isinstance(text, str) or len(text.encode("utf-8", "replace")) > MAX_TEXT:
        raise ProtectionError("mapping exceeds cap")
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, UnicodeError, LookupError) as exc:
        raise ProtectionError("invalid Allatori XML mapping") from exc
    classes = {}
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1].lower() != "class":
            continue
        original = node.attrib.get("old") or node.attrib.get("original") or node.attrib.get("name")
        obfuscated = node.attrib.get("new") or node.attrib.get("obfuscated")
        if not original or not obfuscated:
            continue
        entry = {"original": original, "obfuscated": obfuscated, "members": []}
        for child in node:
            tag = child.tag.rsplit("}", 1)[-1].lower()
            if tag not in {"method", "field"}:
                continue
            old = child.attrib.get("old") or child.attrib.get("original") or child.attrib.get("name")
            new = child.attrib.get("new") or child.attrib.get("obfuscated")
            if old and new:
                entry["members"].append({"kind": tag, "original": old, "obfuscated": new})
        classes[obfuscated] = entry
    return {"format": "allatori", "classes": classes, "class_count": len(classes),
            "member_count": sum(len(item["members"]) for item in classes.values())}


def parse_obfuscation_mapping(text: str) -> dict[str, Any]:
    return parse_allatori_mapping(text) if text.lstrip().startswith("<") else parse_proguard_mapping(text)


def deobfuscate_descriptor(value: str, mapping: Mapping[str, Any]) -> str:
    classes = mapping.get("classes", {})
    output = value
    for obfuscated, entry in sorted(classes.items(), key=lambda item: -len(item[0])):
        original = entry.get("original")
        if not isinstance(original, str):
            continue
        output = output.replace("L" + obfuscated.replace(".", "/") + ";",
                                "L" + original.replace(".", "/") + ";")
        output = re.sub(rf"(?<![\w$]){re.escape(obfuscated)}(?![\w$])", original, output)
    return output


def deobfuscate_stacktrace(text: str, mapping: Mapping[str, Any]) -> str:
    classes = mapping.get("classes", {})

    def frame(match: re.Match) -> str:
        class_name, method = match.group(1), match.group(2)
        entry = classes.get(class_name)
        if not entry:
            return match.group(0)
        candidates = sorted({item.get("original") for item in entry.get("members", [])
                             if item.get("obfuscated") == method and item.get("original")})
        method_name = candidates[0] if len(candidates) == 1 else method
        return "at " + entry["original"] + "." + method_name + "("

    output = re.sub(r"\bat\s+([\w.$]+)\.([\w$<>]+)\(", frame, text)
    return deobfuscate_descriptor(output, mapping)


def transform_string(value: bytes | str, operations: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply an explicit, bounded transform chain recovered from static code evidence."""
    current: bytes = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    if len(current) > MAX_TRANSFORM or len(operations) > 64:
        raise ProtectionError("string transform exceeds cap")
    trace = []
    for index, operation in enumerate(operations):
        if not isinstance(operation, dict):
            raise ProtectionError("transform operation must be an object")
        name = operation.get("op")
        before = hashlib.sha256(current).hexdigest()
        if name in {"base64", "base64url"}:
            try:
                current = base64.b64decode(current, altchars=b"-_" if name == "base64url" else None, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ProtectionError("invalid base64 transform input") from exc
        elif name == "hex":
            try:
                current = bytes.fromhex(current.decode("ascii"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise ProtectionError("invalid hex transform input") from exc
        elif name == "reverse":
            current = current[::-1]
        elif name in {"xor", "add", "sub", "rol", "ror"}:
            key = operation.get("key")
            keys = list(key) if isinstance(key, (bytes, bytearray, list, tuple)) else [key]
            if not keys or any(not isinstance(item, int) or not 0 <= item <= 255 for item in keys):
                raise ProtectionError("transform key must contain bytes")
            out = bytearray()
            for pos, byte in enumerate(current):
                amount = keys[pos % len(keys)]
                if name == "xor":
                    out.append(byte ^ amount)
                elif name == "add":
                    out.append((byte + amount) & 0xFF)
                elif name == "sub":
                    out.append((byte - amount) & 0xFF)
                elif name == "rol":
                    shift = amount & 7; out.append(((byte << shift) | (byte >> ((8 - shift) & 7))) & 0xFF)
                else:
                    shift = amount & 7; out.append(((byte >> shift) | (byte << ((8 - shift) & 7))) & 0xFF)
            current = bytes(out)
        elif name == "xor-index":
            key = operation.get("key", 0)
            if not isinstance(key, int) or not 0 <= key <= 255:
                raise ProtectionError("xor-index key must be a byte")
            current = bytes(byte ^ ((key + pos) & 0xFF) for pos, byte in enumerate(current))
        else:
            raise ProtectionError(f"unsupported transform {name!r}")
        if len(current) > MAX_TRANSFORM:
            raise ProtectionError("transformed string exceeds cap")
        trace.append({"index": index, "operation": name, "input_sha256": before,
                      "output_sha256": hashlib.sha256(current).hexdigest(), "length": len(current)})
    encoding = operation.get("encoding", "utf-8") if operations else "utf-8"
    if not isinstance(encoding, str):
        raise ProtectionError("transform encoding must be a string")
    try:
        text = current.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        text = None
    return {"bytes": current, "text": text, "hex": current.hex(), "trace": trace}


def recover_alternating_xor(value: str, even_key: int, odd_key: int) -> str:
    """Reverse the common Allatori-style alternating UTF-16 character XOR."""
    if not isinstance(value, str) or len(value.encode("utf-8", "surrogatepass")) > MAX_TRANSFORM:
        raise ProtectionError("alternating-XOR string exceeds cap")
    if any(not isinstance(key, int) or not 0 <= key <= 0xFFFF for key in (even_key, odd_key)):
        raise ProtectionError("alternating-XOR keys must be UTF-16 values")
    raw = bytearray(value.encode("utf-16le", "surrogatepass"))
    for offset in range(0, len(raw), 2):
        key = even_key if offset % 4 == 0 else odd_key
        unit = int.from_bytes(raw[offset:offset + 2], "little") ^ key
        raw[offset:offset + 2] = unit.to_bytes(2, "little")
    return raw.decode("utf-16le", "surrogatepass")


def encrypted_string_calls(text: str, *, path: str = "classes.smali") -> list[dict[str, Any]]:
    """Inventory literal -> static String decryptor call sites without executing them."""
    if not isinstance(text, str) or len(text.encode("utf-8", "replace")) > MAX_TEXT:
        raise ProtectionError("smali text exceeds cap")
    lines = text.splitlines()
    output = []
    constant = re.compile(r'^\s*const-string(?:/jumbo)?\s+([vp]\d+),\s*("(?:[^"\\]|\\.)*")')
    call = re.compile(r"invoke-static\s+\{([^}]*)\},\s*(L[^;]+;->[^(]+\(Ljava/lang/String;\)Ljava/lang/String;)")
    for index, line in enumerate(lines):
        match = constant.match(line)
        if not match:
            continue
        register, quoted = match.groups()
        try:
            literal = json.loads(quoted)
        except json.JSONDecodeError:
            continue
        for target_index in range(index + 1, min(index + 6, len(lines))):
            invoked = call.search(lines[target_index])
            if not invoked:
                continue
            registers = [item.strip() for item in invoked.group(1).split(",") if item.strip()]
            if registers == [register]:
                output.append({"path": path, "literal_line": index + 1, "call_line": target_index + 1,
                               "register": register, "literal": literal, "target": invoked.group(2)})
            break
        if len(output) >= MAX_FINDINGS:
            break
    return output


def detect_obfuscation(smali_files: Mapping[str, str]) -> dict[str, Any]:
    classes, methods, short_classes, short_methods, unicode_names = 0, 0, 0, 0, []
    family_evidence, reflection, decrypt_calls = {}, [], []
    for path in sorted(smali_files):
        text = smali_files[path]
        if len(text.encode("utf-8", "replace")) > MAX_TEXT:
            raise ProtectionError(f"{path}: smali exceeds cap")
        for match in _CLASS.finditer(text):
            classes += 1
            name = match.group(1).rsplit("/", 1)[-1]
            short_classes += len(name) <= 2
            if any(ord(char) > 127 for char in name):
                unicode_names.append({"path": path, "name": name})
        for match in _SMALI_METHOD.finditer(text):
            methods += 1
            name = match.group(1)
            short_methods += name not in {"<init>", "<clinit>"} and len(name) <= 2
        for family, pattern in _SDK_MARKERS.items():
            if pattern.search(text):
                family_evidence.setdefault(family, []).append(path)
        decrypt_calls.extend(encrypted_string_calls(text, path=path))
        for lineno, line in enumerate(text.splitlines(), 1):
            if re.search(r"Ljava/lang/(?:Class|reflect/Method);->(?:forName|invoke)", line):
                reflection.append({"path": path, "line": lineno, "text": line.strip()})
    return {"class_count": classes, "method_count": methods,
            "short_class_ratio": short_classes / classes if classes else 0.0,
            "short_method_ratio": short_methods / methods if methods else 0.0,
            "unicode_names": unicode_names[:MAX_FINDINGS],
            "reflection_sites": reflection[:MAX_FINDINGS], "string_decrypt_calls": decrypt_calls[:MAX_FINDINGS],
            "families": [{"family": family, "paths": sorted(set(paths))}
                         for family, paths in sorted(family_evidence.items())],
            "likely_obfuscated": bool(family_evidence or (classes >= 4 and short_classes / classes >= 0.6)
                                      or (methods >= 8 and short_methods / methods >= 0.6))}


def analyze_rasp(smali_files: Mapping[str, str], *, manifest: str | None = None,
                 native_files: Mapping[str, bytes] | None = None) -> dict[str, Any]:
    findings, plans = [], []
    for path in sorted(smali_files):
        text = smali_files[path]
        plan = plan_smali_patches(text, path=path)
        plans.append(plan)
        for finding in plan["findings"]:
            findings.append({"kind": "smali-protection", **finding})
    manifest_report = {}
    if manifest:
        if len(manifest.encode("utf-8", "replace")) > MAX_TEXT:
            raise ProtectionError("manifest exceeds cap")
        try:
            root = ET.fromstring(manifest)
            app = next((node for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "application"), None)
            if app is not None:
                attrs = {key.rsplit("}", 1)[-1]: value for key, value in app.attrib.items()}
                manifest_report = {key: attrs.get(key) for key in (
                    "debuggable", "testOnly", "extractNativeLibs", "networkSecurityConfig", "usesCleartextTraffic")
                    if key in attrs}
                if attrs.get("debuggable", "false").lower() == "true":
                    findings.append({"kind": "manifest-debuggable", "severity": "high"})
                if attrs.get("networkSecurityConfig"):
                    findings.append({"kind": "manifest-network-security-config", "value": attrs["networkSecurityConfig"]})
        except ET.ParseError:
            manifest_report = {"error": "binary or malformed AndroidManifest.xml"}
        except (UnicodeError, LookupError) as exc:
            raise ProtectionError("invalid manifest encoding") from exc
    native_report = []
    markers = {"root": (b"/system/xbin/su", b"magisk", b"zygisk"),
               "debugger": (b"TracerPid", b"ptrace", b"/proc/self/status"),
               "hooking": (b"frida", b"gum-js-loop", b"xposed", b"27042")}
    for path, data in sorted((native_files or {}).items()):
        if len(data) > MAX_MEMBER:
            raise ProtectionError(f"{path}: native artifact exceeds cap")
        lower = data.lower()
        evidence = []
        for category, values in markers.items():
            for marker in values:
                offsets, cursor = [], 0
                while len(offsets) < 32:
                    hit = lower.find(marker.lower(), cursor)
                    if hit < 0:
                        break
                    offsets.append(hit); cursor = hit + 1
                if offsets:
                    evidence.append({"category": category, "marker": marker.decode("ascii"), "offsets": offsets})
        if evidence:
            native_report.append({"path": path, "sha256": hashlib.sha256(data).hexdigest(), "evidence": evidence})
            findings.append({"kind": "native-protection", "path": path,
                             "categories": sorted({item["category"] for item in evidence})})
    return {"findings": findings[:MAX_FINDINGS], "plans": plans,
            "obfuscation": detect_obfuscation(smali_files), "manifest": manifest_report,
            "native": native_report}


def _bundle(data: bytes) -> dict[str, bytes]:
    if len(data) > MAX_ARCHIVE:
        raise ProtectionError("bundle exceeds cap")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, UnicodeError, NotImplementedError) as exc:
        raise ProtectionError("bundle is not a ZIP") from exc
    infos = archive.infolist()
    if len(infos) > MAX_MEMBERS:
        raise ProtectionError("bundle member count exceeds cap")
    output, total = {}, 0
    for info in infos:
        if info.is_dir():
            continue
        if info.file_size < 0 or info.file_size > MAX_MEMBER:
            raise ProtectionError("bundle member exceeds cap")
        total += info.file_size
        if total > MAX_TOTAL:
            raise ProtectionError("bundle expanded size exceeds cap")
        path = info.filename.replace("\\", "/").lstrip("/")
        if not path or ".." in path.split("/") or path in output:
            raise ProtectionError("unsafe or duplicate bundle path")
        try:
            with archive.open(info) as handle:
                body = handle.read(info.file_size + 1)
        except (zipfile.BadZipFile, OSError, RuntimeError, EOFError, zlib.error) as exc:
            raise ProtectionError("invalid bundle member") from exc
        if len(body) != info.file_size:
            raise ProtectionError("truncated bundle member")
        output[path] = body
    return output


def inspect_protection_bundle(data: bytes) -> dict[str, Any]:
    files = _bundle(data)
    smali = {path: body.decode("utf-8", "replace") for path, body in files.items() if path.endswith(".smali")}
    manifest_body = next((body for path, body in files.items() if path.endswith("AndroidManifest.xml")), None)
    manifest = manifest_body.decode("utf-8", "replace") if manifest_body else None
    native = {path: body for path, body in files.items() if path.endswith((".so", ".dylib"))}
    report = analyze_rasp(smali, manifest=manifest, native_files=native)
    mappings = []
    for path, body in sorted(files.items()):
        if path.lower().endswith(("mapping.txt", "mapping.xml")):
            try:
                mappings.append({"path": path, "report": parse_obfuscation_mapping(body.decode("utf-8"))})
            except (UnicodeDecodeError, ProtectionError) as exc:
                mappings.append({"path": path, "error": str(exc)})
    report["mappings"] = mappings
    report["member_count"] = len(files)
    return report


def _json_default(value: Any):
    if isinstance(value, bytes):
        return {"length": len(value), "sha256": hashlib.sha256(value).hexdigest(), "hex": value.hex()}
    if isinstance(value, set):
        return sorted(value)
    raise TypeError(type(value).__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="smali file or ZIP of supplied static artifacts")
    parser.add_argument("--apply", action="store_true", help="include in-memory patched smali output")
    args = parser.parse_args(argv)
    try:
        with args.artifact.open("rb") as handle:
            data = handle.read(MAX_ARCHIVE + 1)
        if len(data) > MAX_ARCHIVE:
            raise ProtectionError("artifact exceeds cap")
        if data.startswith(b"PK"):
            report = inspect_protection_bundle(data)
        else:
            text = data.decode("utf-8")
            plan = plan_smali_patches(text, path=args.artifact.name)
            report = {"plan": plan}
            if args.apply:
                report["application"] = apply_smali_plan(text, plan)
    except (OSError, UnicodeDecodeError, ProtectionError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True, default=_json_default))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
