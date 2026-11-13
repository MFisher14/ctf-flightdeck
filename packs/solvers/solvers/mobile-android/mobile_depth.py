#!/usr/bin/env python3
"""Offline mobile payload planning and cross-platform package triage.

This engine never launches an app, attaches Frida, invokes adb, or makes a request.  It turns
already-delivered Android/iOS artifacts and caller-supplied hook descriptions into ranked commands,
patch suggestions, and scripts for the player to inspect and run in the scoped Docker/device setup:

* exported Android components and deep-link filters -> ranked ``adb shell am``/``content`` payloads;
* smali source -> method-local bypass suggestions (root/debug/pinning/signature gates), never applied;
* APK/IPA bundles -> bounded Flutter/React-Native string and asset inventory;
* a JSON hook specification -> Android or iOS Frida JavaScript, generated but never executed;
* IPA -> Info.plist, URL schemes, ATS, entitlements, privacy usage keys, and embedded string leads.

All archive reads are entry/size bounded and happen in memory.  Challenge data is never eval'd,
exec'd, unpickled, or imported.
"""
from __future__ import annotations

import argparse
import io
import json
import plistlib
import re
import shlex
import struct
import sys
import zipfile
import zlib
from pathlib import Path
from urllib.parse import quote
from xml.parsers.expat import ExpatError

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt


class ArtifactError(ValueError):
    """A mobile package is malformed, unsupported, or outside parser limits."""


MAX_INPUT = 128 << 20
MAX_JSON = 1 << 20
MAX_ENTRIES = 4096
MAX_MEMBER = 32 << 20
MAX_TOTAL = 96 << 20
MAX_COMPONENTS = 512
MAX_CANDIDATES = 256
MAX_HOOKS = 64
MAX_TEXT = 1 << 20

_PRINTABLE = re.compile(rb"[\x20-\x7e]{5,512}")
_LEAD = re.compile(
    r"(?i)(?:flag\{|https?://|wss?://|api[_-]?key|secret|token|password|"
    r"firebase|graphql|deep[_ -]?link|oauth|client[_-]?id)"
)
_SAFE_NAME = re.compile(r"^(?:\.)?[A-Za-z_$][A-Za-z0-9_.$/<>:-]{0,255}$")


def _ranked(kind: str, value: str, reason: str, score: int, **extra) -> dict:
    item = {"kind": kind, "value": value, "reason": reason, "score": int(score)}
    item.update(extra)
    return item


def _bounded_file(path: str, limit: int = MAX_INPUT) -> bytes:
    with Path(path).open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"input exceeds {limit} byte cap")
    return data


def _bounded_json(path: str) -> dict:
    raw = _bounded_file(path, MAX_JSON)
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def _archive_members(blob: bytes) -> dict[str, bytes]:
    """Read a ZIP-like APK/IPA without extracting, rejecting zip-bomb shaped inputs."""
    if not isinstance(blob, (bytes, bytearray)):
        raise ArtifactError("archive input must be bytes")
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ENTRIES:
                raise ArtifactError("archive entry count exceeds cap")
            out: dict[str, bytes] = {}
            total = 0
            for info in infos:
                if info.is_dir():
                    continue
                if info.file_size < 0 or info.file_size > MAX_MEMBER:
                    continue
                total += info.file_size
                if total > MAX_TOTAL:
                    raise ArtifactError("archive expanded-size cap exceeded")
                with archive.open(info, "r") as handle:
                    body = handle.read(info.file_size + 1)
                if len(body) != info.file_size or len(body) > MAX_MEMBER:
                    raise ArtifactError("archive member size did not match its bounded header")
                out[info.filename] = body
            return out
    except ArtifactError:
        raise
    except (zipfile.BadZipFile, OSError, EOFError, RuntimeError, ValueError, struct.error, zlib.error) as exc:
        raise ArtifactError("input is not a readable APK/IPA/ZIP") from exc


def _full_component(package: str, name: str) -> str:
    if name.startswith("."):
        return package + name
    if "." not in name:
        return package + "." + name
    return name


def _is_exported(component: dict) -> bool:
    value = component.get("exported")
    return value is True or (value is None and bool(component.get("filters")))


def _extra_args(extras: dict | None) -> str:
    if not extras:
        return ""
    if not isinstance(extras, dict) or len(extras) > 64:
        raise ValueError("extras must be an object with at most 64 keys")
    args = []
    for key, value in sorted(extras.items()):
        if not isinstance(key, str) or not _SAFE_NAME.fullmatch(key):
            raise ValueError("invalid Android extra name")
        if isinstance(value, bool):
            args.extend(("--ez", shlex.quote(key), "true" if value else "false"))
        elif isinstance(value, int) and not isinstance(value, bool):
            args.extend(("--el", shlex.quote(key), str(value)))
        elif isinstance(value, str) and len(value) <= 4096:
            args.extend(("--es", shlex.quote(key), shlex.quote(value)))
        else:
            raise ValueError("extra values must be bounded strings, booleans, or integers")
    return " " + " ".join(args)


def _filter_uris(component: dict) -> list[str]:
    uris = []
    for intent_filter in component.get("filters") or ():
        if not isinstance(intent_filter, dict):
            continue
        for data in (intent_filter.get("data") or ())[:16]:
            if not isinstance(data, dict):
                continue
            scheme = data.get("scheme")
            if not isinstance(scheme, str) or not scheme or len(scheme) > 64:
                continue
            host = data.get("host") if isinstance(data.get("host"), str) else ""
            port = data.get("port") if str(data.get("port", "")).isdigit() else ""
            path = next((data.get(key) for key in ("path", "pathPrefix", "pathPattern")
                         if isinstance(data.get(key), str)), "/")
            authority = host + ((":" + str(port)) if port else "")
            uri = scheme + "://" + authority + quote(path or "/", safe="/%{}*.-_~")
            if len(uri) <= 4096 and uri not in uris:
                uris.append(uri)
    return uris[:16]


def build_exploit_intents(manifest: dict, extras: dict | None = None) -> list[dict]:
    """Return ranked player-run payloads for exported components in normalized manifest facts."""
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    package = manifest.get("package")
    components = manifest.get("components") or []
    if not isinstance(package, str) or not package or len(package) > 256:
        raise ValueError("manifest package is missing or invalid")
    if not isinstance(components, list) or len(components) > MAX_COMPONENTS:
        raise ValueError("component list exceeds cap")
    suffix = _extra_args(extras)
    candidates = []
    for component in components:
        if not isinstance(component, dict) or not _is_exported(component):
            continue
        name, kind = component.get("name"), component.get("kind", "activity")
        if not isinstance(name, str) or not name or not _SAFE_NAME.fullmatch(name):
            continue
        full = _full_component(package, name)
        target = shlex.quote(package + "/" + full)
        permission = component.get("permission")
        guarded = isinstance(permission, str) and bool(permission)
        if kind in ("activity", "activity-alias"):
            uris = _filter_uris(component)
            if uris:
                for uri in uris:
                    command = ("adb shell am start -W -a android.intent.action.VIEW -d "
                               + shlex.quote(uri) + " -n " + target + suffix)
                    candidates.append(_ranked(
                        "deep-link", command,
                        "exported VIEW component with an explicit URI filter", 100 - 20 * guarded,
                        component=full, uri=uri, permission=permission,
                    ))
            else:
                command = "adb shell am start -W -n " + target + suffix
                candidates.append(_ranked("activity-intent", command, "exported activity", 80 - 20 * guarded,
                                          component=full, permission=permission))
        elif kind == "service":
            command = "adb shell am startservice -n " + target + suffix
            candidates.append(_ranked("service-intent", command, "exported service", 75 - 20 * guarded,
                                      component=full, permission=permission))
        elif kind == "receiver":
            actions = []
            for filt in component.get("filters") or ():
                if isinstance(filt, dict):
                    actions.extend(a for a in filt.get("actions") or () if isinstance(a, str))
            action = actions[0] if actions else package + ".CTF_ACTION"
            command = "adb shell am broadcast -a " + shlex.quote(action) + " -n " + target + suffix
            candidates.append(_ranked("broadcast-intent", command, "exported broadcast receiver", 72 - 20 * guarded,
                                      component=full, action=action, permission=permission))
        elif kind == "provider":
            authorities = component.get("authorities")
            if isinstance(authorities, str) and authorities:
                authority = authorities.split(";")[0]
                command = "adb shell content query --uri " + shlex.quote("content://" + authority + "/")
                candidates.append(_ranked("provider-query", command, "exported content provider", 78 - 20 * guarded,
                                          component=full, authority=authority, permission=permission))
    return sorted(candidates[:MAX_CANDIDATES], key=lambda item: (-item["score"], item["kind"], item["value"]))


_METHOD = re.compile(r"(?ms)^\.method\b(?P<head>[^\n]*)\n(?P<body>.*?)^\.end method\s*$")


def suggest_smali_patches(source: str) -> list[dict]:
    """Rank bypass snippets for suspicious smali methods without editing or executing them."""
    if not isinstance(source, str) or len(source) > MAX_TEXT:
        raise ValueError("smali source must be text within the 1 MiB cap")
    findings = []
    rules = (
        ("tls-pinning", 100, re.compile(r"(?i)CertificatePinner|checkServerTrusted|TrustManager|SSLPeerUnverified")),
        ("signature-check", 92, re.compile(r"(?i)getPackageInfo|SigningInfo|GET_SIGNATURES|certificate|signature")),
        ("root-check", 90, re.compile(r"(?i)(?:/system/(?:xbin/)?su|test-keys|RootBeer|magisk|busybox)")),
        ("debug-check", 84, re.compile(r"(?i)isDebuggerConnected|FLAG_DEBUGGABLE|Debug\.isDebugger")),
        ("emulator-check", 78, re.compile(r"(?i)goldfish|ranchu|generic_x86|Build;->FINGERPRINT|qemu")),
    )
    for method_index, match in enumerate(_METHOD.finditer(source)):
        if method_index >= 4096:
            break
        head, body = match.group("head").strip(), match.group("body")
        name_match = re.search(r"([^\s(]+)\(([^)]*)\)(\S+)", head)
        if not name_match:
            continue
        method, return_type = name_match.group(1), name_match.group(3)
        for category, score, pattern in rules:
            if not pattern.search(body + "\n" + head):
                continue
            if return_type == "V":
                snippet = ".locals 0\n    return-void"
                outcome = "return without enforcing the check"
            elif return_type == "Z":
                value = "0x1" if category == "tls-pinning" else "0x0"
                snippet = ".locals 1\n    const/4 v0, " + value + "\n    return v0"
                outcome = "force the boolean gate to the bypass value"
            elif return_type.startswith("L") or return_type.startswith("["):
                snippet = ".locals 1\n    const/4 v0, 0x0\n    return-object v0"
                outcome = "return null (review callers before applying)"
            else:
                snippet = ".locals 1\n    const/4 v0, 0x0\n    return v0"
                outcome = "return zero (review the exact primitive width)"
            findings.append(_ranked(
                "smali-patch", snippet, f"{category}: {outcome}", score,
                category=category, method=method, method_header=head,
            ))
            break
    return sorted(findings[:MAX_CANDIDATES], key=lambda item: (-item["score"], item["method"]))


def _interesting_strings(body: bytes, origin: str) -> list[dict]:
    out = []
    for match in _PRINTABLE.finditer(body[:MAX_MEMBER]):
        text = match.group().decode("utf-8", "replace")
        # The active event's flag lead (PINK{, spooky{) ranks first; R-16: it was a hard-coded csctf{/chronos{.
        event_lead = bool(flagfmt.LEAD_TEXT.search(text))
        if event_lead or _LEAD.search(text):
            score = 100 if event_lead else 75
            out.append(_ranked("bundle-string", text, "security-relevant printable string", score,
                               origin=origin, offset=match.start()))
            if len(out) >= 64:
                break
    return out


def extract_crossplatform(blob: bytes) -> dict:
    """Bounded Flutter/React-Native asset and string inventory from an APK/IPA/ZIP."""
    members = _archive_members(blob)
    names = sorted(members)
    react = [name for name in names if name.endswith(("index.android.bundle", "main.jsbundle"))
             or "hermes" in name.lower()]
    flutter = [name for name in names if name.endswith(("libapp.so", "App.framework/App"))
               or "flutter_assets/" in name or name.endswith("AssetManifest.json")]
    assets = [name for name in names if any(marker in name.lower() for marker in
              ("assets/", "res/raw/", "flutter_assets/", ".bundle/"))][:MAX_CANDIDATES]
    candidates = []
    for name in (react + flutter)[:64]:
        candidates.extend(_interesting_strings(members[name], name))
        if len(candidates) >= MAX_CANDIDATES:
            break
    return {
        "frameworks": (["react-native"] if react else []) + (["flutter"] if flutter else []),
        "react_native_members": react[:64],
        "flutter_members": flutter[:64],
        "assets": assets,
        "candidates": sorted(candidates[:MAX_CANDIDATES], key=lambda item: (-item["score"], item["origin"])),
    }


def _js_string(value) -> str:
    return json.dumps(value, ensure_ascii=True)


def generate_frida_script(spec: dict) -> str:
    """Generate, but never run, a bounded Android-Java or iOS-ObjC Frida hook script."""
    if not isinstance(spec, dict):
        raise ValueError("hook specification must be an object")
    platform = spec.get("platform")
    hooks = spec.get("hooks")
    if platform not in ("android", "ios") or not isinstance(hooks, list) or not 1 <= len(hooks) <= MAX_HOOKS:
        raise ValueError("platform must be android/ios with 1..64 hooks")
    lines = ["// Generated offline by mobile_depth.py; review before use."]
    if platform == "android":
        lines.append("Java.perform(function () {")
        for index, hook in enumerate(hooks):
            if not isinstance(hook, dict):
                raise ValueError("each hook must be an object")
            cls, method = hook.get("class"), hook.get("method")
            overload = hook.get("overload", [])
            if not (isinstance(cls, str) and _SAFE_NAME.fullmatch(cls)
                    and isinstance(method, str) and _SAFE_NAME.fullmatch(method)
                    and isinstance(overload, list) and len(overload) <= 16
                    and all(isinstance(value, str) and len(value) <= 256 for value in overload)):
                raise ValueError("invalid Android class/method/overload")
            var = f"h{index}"
            accessor = f"Java.use({_js_string(cls)})[{_js_string(method)}]"
            if overload:
                accessor += ".overload(" + ", ".join(_js_string(item) for item in overload) + ")"
            lines.append(f"  var {var} = {accessor};")
            lines.append(f"  {var}.implementation = function () {{")
            lines.append(f"    console.log({_js_string(cls + '.' + method)} + ' args=' + JSON.stringify([].slice.call(arguments))); ")
            if "return" in hook:
                lines.append("    return " + _js_string(hook["return"]) + ";")
            else:
                lines.append(f"    var result = {var}.apply(this, arguments);")
                lines.append("    console.log('return=' + result);")
                lines.append("    return result;")
            lines.append("  };")
        lines.append("});")
    else:
        lines.append("if (!ObjC.available) { throw new Error('Objective-C runtime unavailable'); }")
        for index, hook in enumerate(hooks):
            if not isinstance(hook, dict):
                raise ValueError("each hook must be an object")
            cls, selector = hook.get("class"), hook.get("selector")
            if not (isinstance(cls, str) and _SAFE_NAME.fullmatch(cls)
                    and isinstance(selector, str) and 0 < len(selector) <= 256):
                raise ValueError("invalid Objective-C class/selector")
            var = f"m{index}"
            lines.append(f"var {var} = ObjC.classes[{_js_string(cls)}][{_js_string(selector)}];")
            lines.append(f"Interceptor.attach({var}.implementation, {{")
            lines.append(f"  onEnter: function(args) {{ console.log({_js_string(cls + ' ' + selector)}); }},")
            lines.append("  onLeave: function(retval) { console.log('return=' + retval); }")
            lines.append("});")
    script = "\n".join(lines) + "\n"
    if len(script) > MAX_TEXT:
        raise ValueError("generated script exceeds cap")
    return script


def triage_ipa(blob: bytes) -> dict:
    """Return bounded, static iOS plist/entitlement/string findings from an IPA."""
    members = _archive_members(blob)
    info_names = [name for name in members if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name)]
    if len(info_names) != 1:
        raise ArtifactError("IPA must contain exactly one app Info.plist")
    try:
        info = plistlib.loads(members[info_names[0]])
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError, LookupError, ExpatError) as exc:
        raise ArtifactError("Info.plist is invalid") from exc
    if not isinstance(info, dict):
        raise ArtifactError("Info.plist root must be a dictionary")
    schemes = []
    for item in info.get("CFBundleURLTypes", []) if isinstance(info.get("CFBundleURLTypes", []), list) else []:
        if isinstance(item, dict) and isinstance(item.get("CFBundleURLSchemes"), list):
            schemes.extend(value for value in item.get("CFBundleURLSchemes", [])
                           if isinstance(value, str) and len(value) <= 256)
    query_schemes = [value for value in info.get("LSApplicationQueriesSchemes", [])
                     if isinstance(value, str) and len(value) <= 256] if isinstance(
                         info.get("LSApplicationQueriesSchemes", []), list) else []
    entitlements = []
    for name, body in members.items():
        if "entitlement" not in name.lower() or len(body) > MAX_MEMBER:
            continue
        try:
            value = plistlib.loads(body)
        except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError, LookupError, ExpatError):
            continue
        if isinstance(value, dict):
            entitlements.append({"member": name, "values": value})
    leads = []
    executable = info.get("CFBundleExecutable")
    if isinstance(executable, str):
        suffix = ".app/" + executable
        for name, body in members.items():
            if name.endswith(suffix):
                leads.extend(_interesting_strings(body, name))
    ats = info.get("NSAppTransportSecurity") if isinstance(info.get("NSAppTransportSecurity"), dict) else {}
    privacy = {key: value for key, value in info.items()
               if isinstance(key, str) and key.startswith("NS") and key.endswith("UsageDescription")
               and isinstance(value, str)}
    return {
        "bundle_id": info.get("CFBundleIdentifier"),
        "display_name": info.get("CFBundleDisplayName") or info.get("CFBundleName"),
        "versions": {"short": info.get("CFBundleShortVersionString"), "build": info.get("CFBundleVersion")},
        "url_schemes": list(dict.fromkeys(schemes)),
        "queried_schemes": list(dict.fromkeys(query_schemes)),
        "associated_domains": info.get("com.apple.developer.associated-domains", []),
        "ats": ats,
        "privacy_usage": privacy,
        "entitlements": entitlements[:64],
        "candidates": sorted(leads[:MAX_CANDIDATES], key=lambda item: (-item["score"], item["origin"])),
    }


def _manifest_from_path(path: str) -> dict:
    raw = _bounded_file(path)
    if raw.lstrip().startswith(b"{"):
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("manifest JSON root must be an object")
        return value.get("manifest", value)
    members = _archive_members(raw)
    body = members.get("AndroidManifest.xml")
    if body is None:
        raise ValueError("APK has no AndroidManifest.xml")
    try:
        import apk_facts  # same-directory module; pure static AXML reader
        facts = apk_facts.manifest_facts(body)
    except Exception as exc:  # normalize optional parser failures at the CLI boundary
        raise ValueError("could not parse the compiled Android manifest") from exc
    if not facts:
        raise ValueError("could not parse the compiled Android manifest")
    return facts


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="mobile_depth.py")
    sub = parser.add_subparsers(dest="operation", required=True)
    intent = sub.add_parser("intent", help="rank exported-component/deep-link adb payloads")
    intent.add_argument("input", help="APK or normalized manifest JSON")
    intent.add_argument("--extras", help="bounded JSON object of intent extras")
    smali = sub.add_parser("smali", help="suggest method-local smali bypass patches")
    smali.add_argument("input")
    bundle = sub.add_parser("bundles", help="inventory Flutter/React-Native strings/assets")
    bundle.add_argument("input")
    frida = sub.add_parser("frida", help="generate a Frida script from JSON")
    frida.add_argument("input")
    ios = sub.add_parser("ios", help="triage an IPA's plist/entitlements/strings")
    ios.add_argument("input")
    parser.add_argument("--json", action="store_true")
    for command in (intent, smali, bundle, frida, ios):
        command.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    try:
        args = parser.parse_args(argv)
        if args.operation == "intent":
            extras = _bounded_json(args.extras) if args.extras else None
            result = {"candidates": build_exploit_intents(_manifest_from_path(args.input), extras)}
        elif args.operation == "smali":
            source = _bounded_file(args.input, MAX_TEXT).decode("utf-8", "replace")
            result = {"candidates": suggest_smali_patches(source)}
        elif args.operation == "bundles":
            result = extract_crossplatform(_bounded_file(args.input))
        elif args.operation == "frida":
            result = {"script": generate_frida_script(_bounded_json(args.input))}
        else:
            result = triage_ipa(_bounded_file(args.input))
        if args.json:
            print(json.dumps(result, sort_keys=True, default=str))
        elif args.operation == "frida":
            print(result["script"], end="")
        else:
            for rank, candidate in enumerate(result.get("candidates", []), 1):
                print(f"{rank}. [{candidate['score']}] {candidate['kind']}: {candidate['value']}")
            summary = {key: value for key, value in result.items() if key != "candidates"}
            if summary:
                print(json.dumps(summary, sort_keys=True, default=str))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (KeyError, OSError, TypeError, ValueError, OverflowError, UnicodeError,
            RecursionError, MemoryError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        print(f"mobile_depth: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
