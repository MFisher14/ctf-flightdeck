#!/usr/bin/env python3
"""Offline Round-5A dispatcher for forensic, media, and capture archetypes.

This module is deliberately an orchestration layer, not another parser.  It feeds bounded byte
inputs to the repository's existing static engines and turns exact flag-shaped observations into
ranked, provenance-rich candidates for a human.  It never opens a socket, executes an artifact,
submits a value, or promotes an ambiguous engine suggestion to a verified result.

Public API::

    dispatch(description, files, *, budget_seconds=5.0) -> JSON-safe dict

``files`` may be ``{name: bytes}``, paths, or ``(name, bytes)`` pairs.  Inputs outside the hard
file/count/aggregate limits are declined rather than truncated and parsed as complete artifacts.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
import time
from pathlib import Path
from typing import Any


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
COMMON = ROOT / "solvers" / "common"
WARMUPS = ROOT / "solvers" / "warmups"
for _directory in (COMMON, WARMUPS, HERE):
    if str(_directory) not in sys.path:
        sys.path.append(str(_directory))

from dispatch_core import (  # noqa: E402
    Artifact,
    MAX_ARTIFACTS,
    MAX_ARTIFACT_BYTES,
    MAX_CANDIDATES,
    MAX_DESCRIPTION,
    MAX_TOTAL_BYTES,
    R5AInputError,
    empty_report,
    finalize_report,
    flag_hits,
    make_attempt,
    make_candidate,
    normalize_artifacts,
    normalize_description,
    safe_engine_call,
)

MAX_WALK_NODES = 20_000
MAX_CAPTURE_PACKETS = 100_000
FLAG_RE = flagfmt.TEXT
FLAG_BYTES_RE = flagfmt.BYTES


_MODULES: dict[str, Any] = {}


def _engine(name: str, folder: Path = HERE):
    """Load a repository engine under a private name without importing challenge files."""
    key = f"{folder}:{name}"
    if key in _MODULES:
        return _MODULES[key]
    path = folder / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"r5a_existing_{name}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load existing engine {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _MODULES[key] = module
    return module


def _normalise(files) -> tuple[list[Artifact], list[str]]:
    try:
        artifacts = normalize_artifacts(files)
    except R5AInputError as exc:
        return [], [str(exc)]
    notes = [f"{item.name}: truncated by shared {MAX_ARTIFACT_BYTES}-byte cap; whole-file parsers decline it"
             for item in artifacts if item.truncated]
    return artifacts, notes


def _json_summary(value: Any, *, depth: int = 0) -> Any:
    """Bound an evidence value while keeping the final report JSON-safe."""
    if depth > 4:
        return "<depth-cap>"
    if value is None or isinstance(value, (bool, int, float, str)):
        return value if not isinstance(value, str) or len(value) <= 500 else value[:497] + "..."
    if isinstance(value, (bytes, bytearray, memoryview)):
        blob = bytes(value)
        return {"bytes": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}
    if isinstance(value, dict):
        return {str(k)[:100]: _json_summary(v, depth=depth + 1) for k, v in list(value.items())[:50]}
    if isinstance(value, (list, tuple, set)):
        return [_json_summary(v, depth=depth + 1) for v in list(value)[:50]]
    return str(value)[:500]


class _Collector:
    def __init__(self):
        self._candidates: list[dict] = []
        self.attempts: list[dict] = []
        self.declines: list[str] = []

    def attempt(self, archetype: str, engine: str, status: str, **evidence) -> None:
        allowed = status if status in {"selected", "completed", "declined", "unavailable", "error", "skipped"} else "error"
        self.attempts.append(make_attempt(
            engine, status=allowed,
            evidence=[f"archetype={archetype}", json.dumps(_json_summary(evidence), sort_keys=True)],
        ))

    def decline(self, message: str) -> None:
        if message not in self.declines and len(self.declines) < 100:
            self.declines.append(message[:500])

    def add(self, value: str, *, archetype: str, engine: str, source: str,
            derivation: list[str], verified: bool, confidence: float) -> None:
        if len(self._candidates) >= MAX_CANDIDATES * 4:
            self.decline(f"candidate cap {MAX_CANDIDATES} reached")
            return
        label = "high" if confidence >= 0.9 else "medium" if confidence >= 0.6 else "low"
        try:
            row = make_candidate(
                value, archetype=archetype, engine=engine, source=source,
                derivation=[f"engine={engine}", *derivation], verified=verified, confidence=label,
                evidence=[f"source={source}"],
                warnings=[] if verified else ["candidate path is not independently integrity-verified"],
            )
        except R5AInputError:
            return
        self._candidates.append(row)

    def flags(self, value: Any, *, archetype: str, engine: str, source: str,
              derivation: list[str], verified: bool, confidence: float) -> None:
        for hit in flag_hits(value, source=source):
            self.add(hit["value"], archetype=archetype, engine=engine, source=source,
                     derivation=derivation, verified=verified, confidence=confidence)

    def scan_tree(self, value: Any, *, archetype: str, engine: str, source: str,
                  derivation: list[str], verified: bool, confidence: float) -> None:
        stack, seen, nodes = [value], set(), 0
        while stack and nodes < MAX_WALK_NODES:
            item = stack.pop()
            nodes += 1
            if isinstance(item, (str, bytes, bytearray, memoryview)):
                self.flags(item, archetype=archetype, engine=engine, source=source,
                           derivation=derivation, verified=verified, confidence=confidence)
                continue
            ident = id(item)
            if ident in seen:
                continue
            seen.add(ident)
            if isinstance(item, dict):
                pairs = list(item.items())[:1000]
                stack.extend(key for key, _ in pairs)
                stack.extend(value for _, value in pairs)
            elif isinstance(item, (list, tuple, set)):
                stack.extend(list(item)[:1000])
        if stack:
            self.decline(f"{engine}: recursive evidence walk stopped at {MAX_WALK_NODES} nodes")

    def ranked(self) -> list[dict]:
        return list(self._candidates)


def _score_routes(description: str, inputs: list[Artifact]) -> list[dict]:
    text = description.lower()
    names = " ".join(x.name.lower() for x in inputs)
    heads = b" ".join(x.data[:16] for x in inputs)
    rules = {
        "archive_key_leak": (r"archive|zip|7z|tar|password|passphrase|key.?leak|keepass|rclone|sops", b"PK\x03\x04" in heads),
        "image_stego": (r"steg|image|pixel|lsb|dct|dwt|png|jpeg|gif|webp", any(x.data.startswith((b"\x89PNG", b"\xff\xd8", b"GIF8", b"RIFF")) for x in inputs)),
        "audio_stego": (r"audio|wav|aiff|dtmf|spectrogram|sstv|fsk|psk", any(x.data.startswith((b"RIFF", b"FORM")) for x in inputs)),
        "qr_barcode": (r"qr|barcode|data.?matrix|aztec|pdf417", any(s in names for s in (".png", ".jpg", ".jpeg", ".gif", ".webp"))),
        "pcap_reconstruction": (r"pcap|packet|capture|traffic|wireshark|tcp stream|network", any(x.data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a") for x in inputs)),
        "maldoc": (r"maldoc|macro|office|document|pdf|rtf|ole|vba|phish", any(Path(x.name).suffix.lower() in {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf", ".pdf", ".hta", ".wsf"} for x in inputs)),
        "email": (r"email|e-mail|phish|eml|message|attachment", any(x.name.lower().endswith((".eml", ".msg", ".mbox")) for x in inputs)),
        "disk_filesystem": (r"disk|qcow|vmdk|vhd|ewf|apfs|btrfs|ntfs|filesystem|forensic image", any(s in names for s in (".qcow", ".qcow2", ".vmdk", ".vhd", ".vhdx", ".e01"))),
        "firmware_mobile": (r"firmware|flash|uf2|squashfs|jffs|ubifs|u-boot|macho|dyld|mobile", any(x.data.startswith((b"UF2\n", b"\xcf\xfa\xed\xfe", b"dyld_v1")) or x.name.lower().endswith(".uf2") for x in inputs)),
    }
    out = []
    for name, (pattern, by_magic) in rules.items():
        reasons = []
        if re.search(pattern, text):
            reasons.append("description")
        if by_magic:
            reasons.append("file signature/name")
        if reasons:
            out.append({"archetype": name, "score": round(min(1.0, 0.45 + 0.25 * len(reasons)), 2),
                        "reasons": reasons})
    return sorted(out, key=lambda r: (-r["score"], r["archetype"]))


def _stated_keys(description: str, inputs: list[Artifact]) -> list[bytes]:
    """Collect only explicitly stated/delivered archive keys, never a generated wordlist."""
    pattern = re.compile(r"(?i)\b(?:password|passphrase|archive key|zip key)\s*(?:is|=|:)\s*['\"]?([^\s'\";,]{1,128})")
    out = []
    for match in pattern.finditer(description[:MAX_DESCRIPTION]):
        value = match.group(1).encode("utf-8", "strict")
        if value not in out:
            out.append(value)
        if len(out) >= 16:
            break
    key_name = re.compile(r"(?i)(?:pass(?:word|phrase)?|archive.?key|zip.?key|secret)")
    assignment = re.compile(r"(?i)^\s*(?:password|passphrase|archive[_ -]?key|zip[_ -]?key)\s*[:=]\s*(\S{1,128})\s*$")
    for item in inputs:
        if len(out) >= 16:
            break
        if item.truncated or len(item.data) > 4096 or not key_name.search(item.name):
            continue
        try:
            text = item.data.decode("utf-8", "strict")
        except UnicodeDecodeError:
            continue
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        candidates: list[str] = []
        if len(lines) == 1 and 1 <= len(lines[0]) <= 128 and not any(ch.isspace() for ch in lines[0]):
            candidates.append(lines[0])
        for line in lines[:32]:
            match = assignment.fullmatch(line)
            if match:
                candidates.append(match.group(1))
        for candidate in candidates:
            value = candidate.encode("utf-8", "strict")
            if value not in out:
                out.append(value)
            if len(out) >= 16:
                break
    return out


def _raw_pass(inputs: list[Artifact], c: _Collector) -> None:
    distinct = {hit["value"] for item in inputs for hit in flag_hits(item.data, source=item.name)}
    for item in inputs:
        c.flags(item.data, archetype="byte_evidence", engine="bounded exact byte scan", source=item.name,
                derivation=["read bounded artifact bytes", "match one complete flag-format substring"],
                verified=len(distinct) == 1 and not item.truncated,
                confidence=1.0 if len(distinct) == 1 and not item.truncated else 0.7)


def _archive_pass(description: str, inputs: list[Artifact], c: _Collector, deadline: float) -> None:
    keys = _stated_keys(description, inputs)
    try:
        archive_passwords = _engine("archive_passwords", COMMON)
    except Exception as exc:
        c.decline(f"archive_passwords unavailable: {type(exc).__name__}")
        return
    selected = [x for x in inputs if not x.truncated and
                (x.data.startswith(b"PK\x03\x04") or x.name.lower().endswith(".zip"))]
    for item in selected:
        if time.monotonic() > deadline:
            c.decline("archive pass stopped at dispatcher budget")
            break
        result, attempt = safe_engine_call("archive_passwords.read_all", archive_passwords.read_all,
                                           item.data, cands=keys, score=8)
        attempt["evidence"].append("archetype=archive_key_leak")
        c.attempts.append(attempt)
        try:
            if result is None:
                continue
            members, locked = result
            attempt["evidence"].extend([
                f"source={item.name}", f"members={len(members)}", f"locked={len(locked)}",
                f"explicitly stated keys tried={len(keys)}",
            ])
            for member, body in members.items():
                c.flags(body, archetype="archive_key_leak", engine="archive_passwords.read_all",
                        source=f"{item.name} -> {member}",
                        derivation=["validate ZIP structure", "open member with no key or an explicitly stated key",
                                    "scan exact extracted member bytes"], verified=True, confidence=0.99)
        except (TypeError, ValueError) as exc:
            c.attempt("archive_key_leak", "archive_passwords.read_all", "error",
                      source=item.name, error=type(exc).__name__)


def _stego_pass(inputs: list[Artifact], c: _Collector, deadline: float) -> None:
    try:
        carve = _engine("carve_stego")
    except Exception as exc:
        c.decline(f"carve_stego unavailable: {type(exc).__name__}")
        return
    selected = [x for x in inputs if not x.truncated and
                x.data.startswith((b"\x89PNG", b"\xff\xd8", b"GIF8", b"RIFF", b"BM", b"RIFF"))]
    for item in selected:
        if time.monotonic() > deadline:
            c.decline("stego pass stopped at dispatcher budget")
            break
        skipped: list[str] = []
        try:
            findings = carve.scan(item.name, item.data, deep=True, deadline=deadline, skipped=skipped)
            c.attempt("image_audio_stego", "carve_stego.scan", "completed", source=item.name,
                      findings=len(findings), skipped=skipped)
            for finding in findings:
                channel = str(finding.get("channel") or "unknown")
                method = str(finding.get("method") or "unknown")
                value = finding.get("text") if finding.get("text") is not None else finding.get("data")
                c.flags(value, archetype="image_audio_stego", engine="carve_stego.scan",
                        source=item.name,
                        derivation=[f"parse {carve.sniff(item.data)} container", f"extract {channel}: {method}",
                                    "match exact flag in extracted bytes/text"],
                        verified=finding.get("validated") is True and not skipped, confidence=0.96)
            if item.data.startswith((b"\x89PNG", b"\xff\xd8", b"GIF8", b"RIFF", b"BM")):
                codes = carve.decode_codes(item.data, planes=False, deadline=deadline, skipped=skipped)
                c.attempt("qr_barcode", "carve_stego.decode_codes", "completed", source=item.name,
                          decoded=len(codes), skipped=skipped)
                for code in codes:
                    c.scan_tree(code, archetype="qr_barcode", engine="carve_stego.decode_codes",
                                source=item.name,
                                derivation=["decode image pixels with installed barcode backend",
                                            "preserve decoded payload verbatim", "match exact flag-format payload"],
                                verified=True, confidence=0.99)
        except Exception as exc:
            c.attempt("image_audio_stego", "carve_stego.scan", "declined", source=item.name,
                      error=type(exc).__name__)

    try:
        audio = _engine("audio_stego")
    except Exception as exc:
        c.decline(f"audio_stego unavailable: {type(exc).__name__}")
        return
    for item in [x for x in inputs if not x.truncated and x.data.startswith((b"RIFF", b"FORM"))]:
        try:
            report = audio.analyze(item.data)
            c.attempt("audio_stego", "audio_stego.analyze", "completed", source=item.name,
                      candidates=len(report.get("candidates", [])), notes=report.get("notes", []))
            for label, value in report.get("candidates", []):
                c.flags(value, archetype="audio_stego", engine="audio_stego.analyze", source=item.name,
                        derivation=[f"apply bounded audio transform {label}", "decode candidate signal/text",
                                    "match flag-format text; transform choice still needs human review"],
                        verified=False, confidence=0.65)
        except Exception as exc:
            c.attempt("audio_stego", "audio_stego.analyze", "declined", source=item.name,
                      error=type(exc).__name__)


def _pcap_pass(inputs: list[Artifact], c: _Collector, deadline: float) -> None:
    try:
        network = _engine("network")
        creds = _engine("pcap_creds")
    except Exception as exc:
        c.decline(f"capture engines unavailable: {type(exc).__name__}")
        return
    for item in [x for x in inputs if not x.truncated]:
        if time.monotonic() > deadline:
            c.decline("capture pass stopped at dispatcher budget")
            break
        try:
            if not network.is_capture(item.data):
                continue
            cap = network.read(item.data, name=item.name, limit=MAX_CAPTURE_PACKETS)
            c.attempt("pcap_reconstruction", "network.Capture", "completed", source=item.name,
                      packets=len(cap.packets), damaged=cap.damaged, truncated=cap.truncated,
                      protocols=dict(cap.protocols()))
            for packet in cap.packets:
                if packet.payload:
                    c.flags(packet.payload, archetype="pcap_reconstruction", engine="network.Capture packets",
                            source=item.name,
                            derivation=["validate pcap/pcapng record bounds", "decode link/IP/transport payload",
                                        "match exact captured payload bytes"],
                            verified=not cap.truncated, confidence=0.95)
            streams = cap.streams()
            for key, stream in streams.items():
                c.flags(stream.get("data", b""), archetype="pcap_reconstruction",
                        engine="network.Capture.streams", source=item.name,
                        derivation=["reassemble TCP sequence ranges", f"select stream {key}",
                                    "match exact flag in reassembled bytes"],
                        verified=not cap.truncated and not stream.get("gaps"), confidence=0.98)
            for method in ("http", "objects"):
                try:
                    value = getattr(cap, method)()
                except Exception:
                    continue
                c.scan_tree(value, archetype="pcap_reconstruction", engine=f"network.Capture.{method}",
                            source=item.name,
                            derivation=["reassemble bounded capture", f"parse {method} objects",
                                        "match exact decoded field/body"],
                            verified=not cap.truncated and cap.damaged is None, confidence=0.96)
            facts = creds.extract(item.data)
            c.attempt("pcap_credentials", "pcap_creds.extract", "completed", source=item.name,
                      credential_facts=len(facts))
        except Exception as exc:
            c.attempt("pcap_reconstruction", "network/pcap_creds", "declined", source=item.name,
                      error=type(exc).__name__)


def _mail_pass(inputs: list[Artifact], c: _Collector, deadline: float) -> None:
    try:
        mail_engine = _engine("email")
    except Exception as exc:
        c.decline(f"email engine unavailable: {type(exc).__name__}")
        return

    def visit(mail, source: str, depth: int = 0) -> None:
        if depth > 4:
            c.decline(f"{source}: nested-mail depth cap")
            return
        for body in list(getattr(mail, "bodies", []))[:100]:
            c.flags(body.get("text", ""), archetype="email", engine="email.load bodies", source=source,
                    derivation=["parse MIME structure", "decode declared transfer encoding/charset",
                                "match exact body text"], verified=not bool(getattr(mail, "doubt", None)),
                    confidence=0.96)
            if body.get("inner"):
                c.flags(body["inner"], archetype="email", engine="email.load inner base64", source=source,
                        derivation=["parse MIME body", "strictly decode inner base64", "match exact bytes"],
                        verified=False, confidence=0.7)
        for attachment in list(getattr(mail, "attachments", []))[:100]:
            c.flags(attachment.get("data", b""), archetype="email", engine="email.load attachments",
                    source=f"{source} -> {attachment.get('filename') or 'attachment'}",
                    derivation=["parse MIME part boundaries", "decode Content-Transfer-Encoding",
                                "match exact attachment bytes"],
                    verified=attachment.get("exact") is True and not bool(getattr(mail, "doubt", None)),
                    confidence=0.97)
        for nested in list(getattr(mail, "nested", []))[:20]:
            visit(nested, source + " -> nested", depth + 1)

    for item in [x for x in inputs if not x.truncated]:
        low = item.name.lower()
        looks = low.endswith((".eml", ".msg", ".mbox")) or b"MIME-Version:" in item.data[:65536]
        if not looks or time.monotonic() > deadline:
            continue
        try:
            mails = mail_engine.load(item.data, item.name)
            c.attempt("email", "email.load", "completed", source=item.name, messages=len(mails))
            for mail in mails[:200]:
                visit(mail, item.name)
        except Exception as exc:
            c.attempt("email", "email.load", "declined", source=item.name, error=type(exc).__name__)


def _maldoc_pass(description: str, inputs: list[Artifact], c: _Collector, deadline: float) -> None:
    try:
        maldoc = _engine("maldoc")
    except Exception as exc:
        c.decline(f"maldoc engine unavailable: {type(exc).__name__}")
        return
    terms = re.search(r"(?i)\b(?:maldoc|macro|office|vba|dde|rtf|pdf|hta|phish|document)\b", description)
    extensions = {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf", ".pdf", ".hta", ".wsf", ".sct", ".slk"}
    for item in [x for x in inputs if not x.truncated]:
        if not terms and Path(item.name).suffix.lower() not in extensions:
            continue
        if time.monotonic() > deadline:
            c.decline("maldoc pass stopped at dispatcher budget")
            break
        try:
            doc = maldoc.parse(item.data, item.name)
            derived = maldoc.derived(doc)
            rules = maldoc.yara_scan(item.data, derived)
            c.attempt("maldoc", "maldoc.parse", "completed", source=item.name, kind=doc.get("kind"),
                      damaged=doc.get("damaged", False), yara=rules, handoff=len(maldoc.handoff(doc)))
            c.flags(derived, archetype="maldoc", engine="maldoc.parse/derived", source=item.name,
                    derivation=[f"parse document family {doc.get('kind')}",
                                "decode embedded scripts/text without execution", "match exact derived text"],
                    verified=not bool(doc.get("damaged")), confidence=0.94)
            for child_name, body in maldoc.handoff(doc):
                c.flags(body, archetype="maldoc", engine="maldoc.handoff", source=f"{item.name} -> {child_name}",
                        derivation=["parse document container", "extract embedded script bytes",
                                    "match exact script text"],
                        verified=not bool(doc.get("damaged")), confidence=0.95)
        except Exception as exc:
            c.attempt("maldoc", "maldoc.parse", "declined", source=item.name, error=type(exc).__name__)


def _metadata_pass(description: str, inputs: list[Artifact], c: _Collector) -> None:
    """Route byte-proven metadata through the existing offline lead extractor."""
    try:
        osint = _engine("osint")
    except Exception as exc:
        c.decline(f"offline metadata engine unavailable: {type(exc).__name__}")
        return
    usable = {item.name: item.data for item in inputs if not item.truncated}
    if not usable:
        return
    # Only artifact metadata belongs in this verified path.  Feeding challenge prose to the lead
    # miner would let a flag-shaped example in the description masquerade as byte-proven metadata.
    questions: list[dict] = []
    leads, attempt = safe_engine_call("osint.gather_leads (offline metadata)", osint.gather_leads,
                                      questions, usable, score=5)
    attempt["evidence"].append("archetype=email_metadata")
    c.attempts.append(attempt)
    if leads:
        c.scan_tree(leads, archetype="email_metadata", engine="osint.gather_leads",
                    source="delivery metadata",
                    derivation=["parse bounded EXIF/XMP/IPTC/document metadata offline",
                                "preserve byte-derived metadata value", "match exact flag-format value"],
                    verified=True, confidence=0.92)


def _disk_firmware_pass(inputs: list[Artifact], c: _Collector, deadline: float) -> None:
    try:
        disks = _engine("disk_images")
    except Exception as exc:
        c.decline(f"disk_images unavailable: {type(exc).__name__}")
        disks = None
    if disks is not None:
        for item in [x for x in inputs if not x.truncated]:
            if time.monotonic() > deadline:
                break
            try:
                kind = disks.detect_container(item.data)
                if kind in ("raw-or-unknown", "not-disk-elf", "vmdk-descriptor"):
                    continue
                result = disks.unwrap(item.data)
                c.attempt("disk_filesystem", "disk_images.unwrap", "completed" if result.raw is not None else "declined",
                          source=item.name, **result.report())
                if result.raw is not None:
                    c.flags(result.raw, archetype="disk_filesystem", engine="disk_images.unwrap",
                            source=item.name,
                            derivation=[f"detect {kind}", "validate container metadata/allocation checks",
                                        "reconstruct raw bytes", "match exact reconstructed bytes"],
                            verified=True, confidence=0.99)
            except Exception as exc:
                c.attempt("disk_filesystem", "disk_images.unwrap", "declined", source=item.name,
                          error=type(exc).__name__)

    try:
        firmware = _engine("firmware_walk")
        report = firmware.walk({x.name: x.data for x in inputs if not x.truncated})
        c.attempt("firmware", "firmware_walk.walk", "completed", images=len(report.get("images", [])))
        c.scan_tree(report, archetype="firmware", engine="firmware_walk.walk", source="delivery",
                    derivation=["validate known firmware container/node checksums",
                                "walk bounded entries/properties", "match exact recovered value"],
                    verified=False, confidence=0.7)
    except Exception as exc:
        c.attempt("firmware", "firmware_walk.walk", "declined", error=type(exc).__name__)

    try:
        mobile = _engine("mobile_rf_depth")
    except Exception as exc:
        c.decline(f"mobile_rf_depth unavailable: {type(exc).__name__}")
        return
    for item in [x for x in inputs if not x.truncated]:
        if not (item.name.lower().endswith(".uf2") or len(item.data) >= 512 and item.data[:4] == mobile.UF2_MAGIC0.to_bytes(4, "little")):
            continue
        try:
            report = mobile.parse_uf2(item.data)
            c.attempt("firmware_mobile", "mobile_rf_depth.parse_uf2", "completed", source=item.name,
                      complete=report.get("complete"), gaps=report.get("gaps"),
                      reconstruction_verified=report.get("reconstruction_verified"))
            if report.get("image") is not None:
                c.flags(report["image"], archetype="firmware_mobile", engine="mobile_rf_depth.parse_uf2",
                        source=item.name,
                        derivation=["validate every UF2 block magic/number/range",
                                    "require complete conflict-free contiguous address coverage",
                                    "reconstruct flash bytes", "match exact reconstructed bytes"],
                        verified=bool(report.get("reconstruction_verified")), confidence=0.99)
        except Exception as exc:
            c.attempt("firmware_mobile", "mobile_rf_depth.parse_uf2", "declined", source=item.name,
                      error=type(exc).__name__)


def dispatch(description: str, files, *, category: str = "", budget_seconds: float = 5.0) -> dict:
    """Run bounded offline forensic dispatch and return ranked human-review candidates."""
    try:
        description = normalize_description(description)
    except R5AInputError as exc:
        description = ""
        description_error = str(exc)
    else:
        description_error = None
    try:
        budget = float(budget_seconds)
    except (TypeError, ValueError):
        budget = 5.0
    budget = max(0.25, min(30.0, budget))
    inputs, notes = _normalise(files)
    c = _Collector()
    if description_error:
        c.decline(description_error)
    for note in notes:
        c.decline(note)
    routes = _score_routes(description, inputs)
    deadline = time.monotonic() + budget
    _archive_pass(description, inputs, c, deadline)
    _stego_pass(inputs, c, deadline)
    _pcap_pass(inputs, c, deadline)
    _mail_pass(inputs, c, deadline)
    _maldoc_pass(description, inputs, c, deadline)
    _metadata_pass(description, inputs, c)
    _disk_firmware_pass(inputs, c, deadline)
    # The exact-byte backstop runs last, so a parser-backed derivation remains the primary provenance
    # when the same value is visible both in the outer bytes and through a validated engine.
    _raw_pass(inputs, c)
    report = empty_report("dispatch_forensics", inputs)
    report.update({
        "category": str(category or "")[:100],
        "executed_artifacts": False,
        "description_sha256": hashlib.sha256(description.encode()).hexdigest(),
        "routes": routes,
        "attempts": c.attempts,
        "candidates": c.ranked(),
        "observations": [f"route {row['archetype']} score={row['score']}" for row in routes],
        "warnings": c.declines,
        "limits": {"files": MAX_ARTIFACTS, "file_bytes": MAX_ARTIFACT_BYTES,
                   "total_bytes": MAX_TOTAL_BYTES, "budget_seconds": budget,
                   "capture_packets": MAX_CAPTURE_PACKETS, "candidate_count": MAX_CANDIDATES},
    })
    return finalize_report(report)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="offline forensic/media autosolve dispatcher")
    parser.add_argument("files", nargs="*")
    parser.add_argument("--description", default="")
    parser.add_argument("--budget", type=float, default=5.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = dispatch(args.description, args.files, budget_seconds=args.budget)
    except Exception as exc:  # guarded CLI boundary; library paths above already fail closed
        print(f"dispatch_forensics: {type(exc).__name__}: {str(exc)[:160]}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"routes={len(report['routes'])} attempts={len(report['attempts'])} "
              f"candidates={len(report['candidates'])}")
        for row in report["candidates"]:
            status = "verified-bytes" if row["verified"] else "review"
            print(f"{row['rank']:>2} {status:14} {row['value']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
