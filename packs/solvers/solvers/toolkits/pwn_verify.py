"""Deterministic verification and coverage manifests for r5b payload builders.

There are two deliberately separate evidence levels:

``static-roundtrip``
    The payload, placement map, widths, tuple contract, canonical JSON, and
    digests agree.  This proves serialization, not exploitability.

``container-roundtrip``
    A fixed, harmless parser in the already-local ``csctf-sandbox:2`` image
    independently decodes the canonical envelope and emits a caller-selected
    marker.  The runner always uses ``--pull=never --network none``, a read-only
    root and mount, dropped capabilities, and bounded resources.  It accepts no
    image or command from the caller.

Machine-code execution remains the responsibility of the purpose-built QEMU
tests.  This module never treats byte parsing as execution evidence.
"""
from __future__ import annotations

import base64
import hashlib
import inspect
import json
from dataclasses import dataclass
from pathlib import Path
import subprocess
import tempfile
from types import ModuleType
from typing import Mapping, Sequence

try:
    from contract import BuildError, PayloadBuild
except ImportError:  # pragma: no cover - package-style import
    from .contract import BuildError, PayloadBuild


MAX_ARTIFACT = 16 * 1024 * 1024
MAX_LABELS = 16_384
MAX_MARKER = 512
DOCKER_IMAGE = "csctf-sandbox:2"
ENVELOPE_NAME = "r5b_envelope.json"


class VerificationError(BuildError):
    """The object or its serialized representation violates the contract."""


@dataclass(frozen=True, order=True)
class VerificationRecord:
    """Canonical evidence for one inert payload."""

    name: str
    strategy: str
    architecture: str
    length: int
    payload_sha256: str
    map_sha256: str
    placement_count: int
    described_bytes: int
    overlap_bytes: int
    evidence: str = "static-roundtrip"
    marker_label: str = ""
    marker_sha256: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "strategy": self.strategy,
            "architecture": self.architecture,
            "length": self.length,
            "payload_sha256": self.payload_sha256,
            "map_sha256": self.map_sha256,
            "placement_count": self.placement_count,
            "described_bytes": self.described_bytes,
            "overlap_bytes": self.overlap_bytes,
            "evidence": self.evidence,
            "marker_label": self.marker_label,
            "marker_sha256": self.marker_sha256,
        }


@dataclass(frozen=True)
class CoverageManifest:
    """Sorted records plus public builder coverage for a set of modules."""

    records: tuple[VerificationRecord, ...]
    builders: tuple[str, ...]
    exercised: tuple[str, ...]
    missing: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return not self.missing

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "r5b-verification-v1",
            "complete": self.complete,
            "builders": list(self.builders),
            "exercised": list(self.exercised),
            "missing": list(self.missing),
            "records": [record.as_dict() for record in self.records],
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise VerificationError("value is not canonical-JSON serializable") from exc


def coerce_payload(value: object) -> PayloadBuild:
    """Accept only the shared contract or an explicit ``as_payload_build`` adapter."""

    if isinstance(value, PayloadBuild):
        return value
    adapter = getattr(value, "as_payload_build", None)
    if not callable(adapter):
        raise VerificationError("builder result is not a PayloadBuild and has no audited adapter")
    converted = adapter()
    if not isinstance(converted, PayloadBuild):
        raise VerificationError("as_payload_build() did not return PayloadBuild")
    return converted


def _envelope(build: PayloadBuild) -> dict[str, object]:
    return {
        "schema": "r5b-payload-v1",
        "payload_b64": base64.b64encode(build.payload).decode("ascii"),
        "payload_sha256": hashlib.sha256(build.payload).hexdigest(),
        "placements": dict(build.placements),
        "widths": dict(build.widths),
        "architecture": build.architecture,
        "strategy": build.strategy,
        "base_address": build.base_address,
        "metadata": dict(build.metadata),
    }


def verify_payload(
    name: str,
    value: object,
    *,
    marker_label: str | None = None,
    expected_marker: bytes | None = None,
) -> VerificationRecord:
    """Independently round-trip one payload and return static evidence.

    If ``marker_label`` is supplied, the field must have a declared width.  An
    optional ``expected_marker`` proves exact bytes at that placement.  It does
    not imply those bytes were executed.
    """

    if not isinstance(name, str) or not name or len(name) > 256:
        raise VerificationError("name must be 1..256 characters")
    build = coerce_payload(value)
    if not build.payload or len(build.payload) > MAX_ARTIFACT:
        raise VerificationError(f"payload must be 1..{MAX_ARTIFACT} bytes")
    if len(build.placements) > MAX_LABELS:
        raise VerificationError("placement map exceeds bounded label count")

    # Exercise the promised two-value builder contract, not merely attributes.
    try:
        unpacked_payload, unpacked_placements = build
    except (TypeError, ValueError) as exc:
        raise VerificationError("payload result does not tuple-unpack to two values") from exc
    if unpacked_payload != build.payload or dict(unpacked_placements) != dict(build.placements):
        raise VerificationError("tuple contract disagrees with payload attributes")

    envelope = _envelope(build)
    wire = _canonical_json(envelope)
    decoded = json.loads(wire.decode("utf-8"))
    try:
        payload = base64.b64decode(decoded["payload_b64"], validate=True)
    except (KeyError, ValueError) as exc:
        raise VerificationError("canonical envelope payload is invalid") from exc
    if payload != build.payload:
        raise VerificationError("payload changed during canonical round-trip")
    payload_digest = hashlib.sha256(payload).hexdigest()
    if decoded["payload_sha256"] != payload_digest:
        raise VerificationError("payload digest disagrees after round-trip")

    coverage = bytearray(len(payload))
    for label, offset in build.placements.items():
        if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= len(payload):
            raise VerificationError(f"invalid placement offset: {label}")
        if label in build.widths:
            width = build.widths[label]
            if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
                raise VerificationError(f"invalid placement width: {label}")
            if offset + width > len(payload):
                raise VerificationError(f"placement overruns payload: {label}")
            for index in range(offset, offset + width):
                # Saturation is enough to distinguish described/overlapping
                # bytes and keeps adversarial all-overlap maps bounded.
                coverage[index] = min(2, coverage[index] + 1)

    marker_digest = ""
    chosen_label = marker_label or ""
    if marker_label is not None:
        if marker_label not in build.placements or marker_label not in build.widths:
            raise VerificationError("marker label needs a placement and declared width")
        marker = build.slice(marker_label)
        if expected_marker is not None and marker != bytes(expected_marker):
            raise VerificationError("marker bytes do not match expected_marker")
        marker_digest = hashlib.sha256(marker).hexdigest()
    elif expected_marker is not None:
        raise VerificationError("expected_marker requires marker_label")

    map_material = {
        "placements": dict(build.placements),
        "widths": dict(build.widths),
        "base_address": build.base_address,
    }
    return VerificationRecord(
        name=name,
        strategy=build.strategy,
        architecture=build.architecture,
        length=len(payload),
        payload_sha256=payload_digest,
        map_sha256=hashlib.sha256(_canonical_json(map_material)).hexdigest(),
        placement_count=len(build.placements),
        described_bytes=sum(1 for count in coverage if count),
        overlap_bytes=sum(1 for count in coverage if count > 1),
        marker_label=chosen_label,
        marker_sha256=marker_digest,
    )


def public_builders(module: ModuleType) -> tuple[str, ...]:
    """Return stable fully-qualified names for functions defined as ``build_*``."""

    if not isinstance(module, ModuleType):
        raise VerificationError("public_builders expects a module")
    names = []
    for name, value in inspect.getmembers(module, inspect.isfunction):
        if name.startswith("build_") and getattr(value, "__module__", None) == module.__name__:
            names.append(f"{module.__name__}.{name}")
    return tuple(sorted(names))


def make_manifest(
    modules: Sequence[ModuleType],
    samples: Mapping[str, object],
) -> CoverageManifest:
    """Verify samples and report exactly which public builders remain unexercised."""

    if isinstance(modules, (str, bytes)) or not isinstance(samples, Mapping):
        raise VerificationError("modules must be a sequence and samples a mapping")
    builder_names = tuple(sorted({name for module in modules for name in public_builders(module)}))
    unknown = sorted(set(samples).difference(builder_names))
    if unknown:
        raise VerificationError(f"samples name non-builders: {', '.join(unknown)}")
    records = tuple(sorted(verify_payload(name, value) for name, value in samples.items()))
    exercised = tuple(sorted(samples))
    missing = tuple(name for name in builder_names if name not in samples)
    return CoverageManifest(records, builder_names, exercised, missing)


def require_complete(manifest: CoverageManifest) -> None:
    """Fail with a stable list when a claimed coverage manifest is incomplete."""

    if not isinstance(manifest, CoverageManifest):
        raise VerificationError("require_complete expects CoverageManifest")
    if manifest.missing:
        raise VerificationError("unexercised builders: " + ", ".join(manifest.missing))


_CONTAINER_SCRIPT = r'''import base64, hashlib, json, pathlib, sys
p = pathlib.Path("/work/r5b_envelope.json")
raw = p.read_bytes()
if len(raw) > 24 * 1024 * 1024:
    raise SystemExit(20)
obj = json.loads(raw.decode("utf-8"))
if obj.get("schema") != "r5b-container-roundtrip-v1":
    raise SystemExit(21)
payload = base64.b64decode(obj["payload_b64"], validate=True)
marker = base64.b64decode(obj["marker_b64"], validate=True)
if hashlib.sha256(payload).hexdigest() != obj["payload_sha256"]:
    raise SystemExit(22)
for key, offset in obj["placements"].items():
    if not isinstance(key, str) or not isinstance(offset, int) or not 0 <= offset <= len(payload):
        raise SystemExit(23)
for key, width in obj["widths"].items():
    if key not in obj["placements"] or not isinstance(width, int) or width < 1:
        raise SystemExit(24)
    if obj["placements"][key] + width > len(payload):
        raise SystemExit(25)
sys.stdout.buffer.write(marker)
'''


def docker_roundtrip_argv(directory: Path) -> tuple[str, ...]:
    """Return the fixed, inspectable sandbox command for one envelope directory."""

    resolved = Path(directory).resolve()
    if not resolved.is_dir() or not (resolved / ENVELOPE_NAME).is_file():
        raise VerificationError("round-trip directory lacks r5b_envelope.json")
    return (
        "docker", "run", "--pull=never", "--rm",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64",
        "--memory", "256m", "--mount",
        f"type=bind,src={resolved},dst=/work,readonly",
        DOCKER_IMAGE, "python3", "-I", "-c", _CONTAINER_SCRIPT,
    )


def run_sacrificial_roundtrip(
    value: object,
    *,
    marker: bytes = b"R5B_CONTAINER_ROUNDTRIP_OK\n",
    timeout: float = 30,
) -> VerificationRecord:
    """Parse one payload in the fixed networkless container and assert its marker.

    This is a serialization check only.  The returned evidence string says so;
    it never claims that exploit bytes or a chain executed.
    """

    build = coerce_payload(value)
    if not isinstance(marker, bytes) or not 1 <= len(marker) <= MAX_MARKER:
        raise VerificationError(f"marker must be 1..{MAX_MARKER} immutable bytes")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 90:
        raise VerificationError("timeout must be in 1..90 seconds")
    static = verify_payload("container-input", build)
    envelope = {
        "schema": "r5b-container-roundtrip-v1",
        "payload_b64": base64.b64encode(build.payload).decode("ascii"),
        "payload_sha256": static.payload_sha256,
        "placements": dict(build.placements),
        "widths": dict(build.widths),
        "marker_b64": base64.b64encode(marker).decode("ascii"),
    }
    with tempfile.TemporaryDirectory(prefix="r5b_verify_") as temporary:
        directory = Path(temporary)
        (directory / ENVELOPE_NAME).write_bytes(_canonical_json(envelope))
        completed = subprocess.run(
            docker_roundtrip_argv(directory),
            check=False,
            capture_output=True,
            timeout=float(timeout),
        )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", "replace")[:1000]
        raise VerificationError(f"sacrificial container failed ({completed.returncode}): {stderr}")
    if completed.stdout != marker:
        raise VerificationError("sacrificial container marker mismatch")
    return VerificationRecord(
        **{
            **static.as_dict(),
            "evidence": "container-static-roundtrip",
            "marker_label": "external-verifier-marker",
            "marker_sha256": hashlib.sha256(marker).hexdigest(),
        }
    )
