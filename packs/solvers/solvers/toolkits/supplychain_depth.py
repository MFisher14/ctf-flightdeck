#!/usr/bin/env python3
"""Offline software-supply-chain and build/IaC provenance analysis.

All registries, repositories, images, attestations, and workflow data must be supplied
as artifacts.  The engine performs no dependency installation, signature service
lookup, network resolution, build, or deployment.
"""
from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import json
import re
import shlex
from collections import deque
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence

MAX_INPUT = 64 * 1024 * 1024
MAX_FILES = 200_000
MAX_COMPONENTS = 500_000
MAX_NESTING = 256
_SEVERITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_SECRET_FILE = re.compile(
    r"(?:^|/)(?:\.env(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)|credentials|"
    r".*(?:secret|private[-_.]?key|keystore).*)(?:$|\.)", re.I
)
_SECRET_LITERAL = re.compile(
    rb"(?:AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    rb"(?:password|passwd|token|api[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]?[^\s'\"]{8,})", re.I
)
_SECRET_KEY = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|connection[_-]?string)",
    re.I,
)


def _finding(kind: str, severity: str, message: str, confidence: str = "medium", **evidence: object) -> dict:
    item = {"kind": kind, "severity": severity, "confidence": confidence, "message": message}
    item.update({key: value for key, value in evidence.items() if value is not None})
    return item


def _sort(findings: Iterable[dict]) -> list[dict]:
    unique: dict[str, dict] = {}
    for item in findings:
        unique[json.dumps(item, sort_keys=True, default=str)] = item
    return sorted(unique.values(), key=lambda item: (
        -_SEVERITY.get(str(item.get("severity")), 0), str(item.get("kind")),
        str(item.get("package", "")), str(item.get("path", "")), int(item.get("line", 0)),
    ))


def _levenshtein(left: str, right: str, cap: int = 2) -> int:
    """Bounded edit distance for comparisons against a caller-supplied trusted set."""
    if abs(len(left) - len(right)) > cap:
        return cap + 1
    if len(left) == len(right):
        changed = [index for index, pair in enumerate(zip(left, right)) if pair[0] != pair[1]]
        if (len(changed) == 2 and changed[1] == changed[0] + 1
                and left[changed[0]] == right[changed[1]]
                and left[changed[1]] == right[changed[0]]):
            return 1
    previous = list(range(len(right) + 1))
    for row, lchar in enumerate(left, 1):
        current = [row]
        for column, rchar in enumerate(right, 1):
            current.append(min(current[-1] + 1, previous[column] + 1,
                               previous[column - 1] + (lchar != rchar)))
        if min(current) > cap:
            return cap + 1
        previous = current
    return previous[-1]


def _dependency_sections(manifest: Mapping[str, object]) -> dict[str, str]:
    result = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
                    "resolutions", "overrides"):
        values = manifest.get(section, {})
        if isinstance(values, Mapping):
            for name, version in values.items():
                result[str(name)] = str(version)
    return result


def analyze_package_manifest(manifest: Mapping[str, object], lock: Mapping[str, object] | None = None,
                             trusted_names: Sequence[str] = ()) -> dict:
    """Inspect package metadata and compare names only to a supplied trusted corpus."""
    dependencies = _dependency_sections(manifest)
    findings = []
    locked_names: set[str] = set()
    if isinstance(lock, Mapping):
        lock_packages = lock.get("packages", {})
        if isinstance(lock_packages, Mapping):
            for path, info in lock_packages.items():
                if path and "node_modules/" in str(path):
                    locked_names.add(str(path).rsplit("node_modules/", 1)[-1])
                if isinstance(info, Mapping):
                    resolved = str(info.get("resolved", ""))
                    if resolved.startswith("http://"):
                        findings.append(_finding("insecure-package-resolution", "high",
                                                 "lockfile resolves a package over plaintext HTTP", "high",
                                                 package=str(path), resolved=resolved))
                    if info.get("resolved") and not info.get("integrity") and not resolved.startswith(("file:", "link:")):
                        findings.append(_finding("missing-lock-integrity", "medium",
                                                 "locked package lacks an integrity digest",
                                                 package=str(path), resolved=resolved))
                    if info.get("hasInstallScript"):
                        findings.append(_finding("dependency-install-script", "medium",
                                                 "locked dependency declares an installation script",
                                                 package=str(path)))
        lock_deps = lock.get("dependencies", {})
        if isinstance(lock_deps, Mapping):
            locked_names.update(str(name) for name in lock_deps)
    for name, specifier in sorted(dependencies.items()):
        if lock is not None and name not in locked_names:
            findings.append(_finding("dependency-missing-from-lock", "high",
                                     "declared dependency is not represented in supplied lock metadata",
                                     "high", package=name, specifier=specifier))
        if specifier in {"*", "latest", "next"} or re.fullmatch(r"(?:>=|>|\^|~)?\s*0(?:\.0(?:\.0)?)?", specifier):
            findings.append(_finding("floating-dependency", "medium",
                                     "dependency uses an unconstrained/floating version", "high",
                                     package=name, specifier=specifier))
        if re.search(r"(?:github:|git\+|https?://.*\.git)(?![^#]*#[0-9a-fA-F]{40}(?:$|&))", specifier):
            findings.append(_finding("unpinned-git-dependency", "high",
                                     "git dependency is not pinned to a full commit digest",
                                     package=name, specifier=specifier))
        for trusted in trusted_names:
            distance = _levenshtein(name.lower(), str(trusted).lower(), 1)
            if 0 < distance <= 1:
                findings.append(_finding("trusted-name-near-match", "high",
                                         "dependency is one edit from a caller-supplied trusted package name",
                                         package=name, trusted_name=str(trusted), distance=distance))
                break
    scripts = manifest.get("scripts", {})
    if isinstance(scripts, Mapping):
        for name, command in scripts.items():
            text = str(command)
            if re.search(r"\b(?:curl|wget)\b[^|;&]*(?:\||&&)\s*(?:sh|bash|node|python)\b", text, re.I):
                findings.append(_finding("download-and-execute-script", "critical",
                                         "package lifecycle downloads and executes remote content",
                                         script=str(name)))
            if str(name) in {"preinstall", "install", "postinstall", "prepare"}:
                findings.append(_finding("package-lifecycle-script", "medium",
                                         "package defines an automatically invoked lifecycle script",
                                         script=str(name)))
    publish = manifest.get("publishConfig", {})
    if (manifest.get("private") is not True and isinstance(publish, Mapping)
            and not publish.get("registry") and str(manifest.get("name", "")).startswith("@")):
        findings.append(_finding("scoped-package-registry-unspecified", "medium",
                                 "publishable scoped package has no explicit registry",
                                 package=manifest.get("name")))
    return {"kind": "package-manifest-analysis", "name": manifest.get("name"),
            "dependencies": dependencies, "locked_names": sorted(locked_names),
            "findings": _sort(findings)}


def analyze_text_lockfile(text: str, name: str) -> dict:
    """Analyze requirements/Cargo/Go/Yarn-style lock text without resolving it."""
    if len(text.encode("utf-8", "replace")) > MAX_INPUT:
        raise ValueError("lockfile exceeds input cap")
    lower = Path(name).name.lower()
    findings, records = [], []
    if lower.startswith("requirements") or lower.endswith((".in", ".txt")):
        for line_number, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(("--index-url", "--extra-index-url")):
                continue
            records.append({"line": line_number, "requirement": line})
            vcs_requirement = bool(re.search(r"(?:git|https?|ssh)\+", line, re.I))
            immutable_revision = bool(re.search(
                r"(?:git|https?|ssh)\+[^\s#]+(?:@|#)[0-9a-fA-F]{40,64}(?:$|[#&\s])", line, re.I))
            if vcs_requirement and not immutable_revision:
                findings.append(_finding("unpinned-vcs-requirement", "high",
                                         "VCS requirement has no evident revision", line=line_number))
            elif not re.search(r"(?:===|==)\s*[^,;\s]+", line) and not line.startswith(("-r", "-c")):
                findings.append(_finding("unpinned-python-requirement", "medium",
                                         "Python requirement is not exactly version-pinned",
                                         line=line_number, requirement=line))
            if "--hash=" not in line:
                findings.append(_finding("python-requirement-without-hash", "low",
                                         "requirement has no supplied artifact hash", line=line_number))
    elif lower == "cargo.lock":
        blocks = re.split(r"(?m)^\[\[package]]\s*$", text)[1:]
        for block in blocks:
            package = re.search(r'(?m)^name\s*=\s*"([^"]+)"', block)
            version = re.search(r'(?m)^version\s*=\s*"([^"]+)"', block)
            source = re.search(r'(?m)^source\s*=\s*"([^"]+)"', block)
            checksum = re.search(r'(?m)^checksum\s*=\s*"([^"]+)"', block)
            record = {"name": package.group(1) if package else "", "version": version.group(1) if version else "",
                      "source": source.group(1) if source else "", "checksum": checksum.group(1) if checksum else ""}
            records.append(record)
            if record["source"].startswith("registry+") and not record["checksum"]:
                findings.append(_finding("cargo-package-without-checksum", "high",
                                         "registry package lacks a checksum", package=record["name"]))
            if (record["source"].startswith("git+")
                    and not re.search(r"#[0-9a-fA-F]{40,64}$", record["source"])):
                findings.append(_finding("cargo-unpinned-git-source", "high",
                                         "git package source lacks a commit fragment", package=record["name"]))
    elif lower == "go.sum":
        for line_number, line in enumerate(text.splitlines(), 1):
            fields = line.split()
            records.append({"line": line_number, "fields": fields})
            if len(fields) != 3 or not fields[-1].startswith("h1:"):
                findings.append(_finding("malformed-go-sum", "medium",
                                         "go.sum record lacks a module/version/h1 digest triplet",
                                         line=line_number))
    else:
        current = ""
        for line_number, raw in enumerate(text.splitlines(), 1):
            if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
                current = raw.rstrip()[:-1]
                records.append({"line": line_number, "selector": current})
            if re.match(r"\s*(?:resolved|resolution)\s+['\"]?http://", raw):
                findings.append(_finding("insecure-lock-resolution", "high",
                                         "lock record resolves over plaintext HTTP", line=line_number,
                                         package=current))
            if re.match(r"\s*version\s+['\"]?(?:latest|\*)", raw):
                findings.append(_finding("floating-lock-version", "medium",
                                         "lock record contains a floating version", line=line_number,
                                         package=current))
    return {"kind": "text-lockfile-analysis", "format": lower,
            "records": records, "findings": _sort(findings)}


def analyze_sbom(document: Mapping[str, object], artifacts: Mapping[str, bytes] | None = None) -> dict:
    """Validate supplied CycloneDX/SPDX identity, graph, and artifact digests."""
    artifacts = artifacts or {}
    findings, components, dependencies = [], [], []
    format_name = "unknown"
    if "bomFormat" in document or "components" in document:
        format_name = "cyclonedx"
        raw_components = document.get("components", [])
        raw_dependencies = document.get("dependencies", [])
        if not isinstance(raw_components, Sequence) or isinstance(raw_components, (str, bytes)):
            raise ValueError("SBOM components must be an array")
        metadata = document.get("metadata", {})
        root_component = metadata.get("component") if isinstance(metadata, Mapping) else None
        queue = deque(raw_components)
        if isinstance(root_component, Mapping):
            queue.appendleft(root_component)
        refs = set()
        expanded_ids = set()
        index = 0
        while queue:
            if len(components) >= MAX_COMPONENTS:
                raise ValueError("SBOM component count exceeds cap")
            component = queue.popleft()
            if not isinstance(component, Mapping):
                continue
            identity = id(component)
            if identity in expanded_ids:
                continue
            expanded_ids.add(identity)
            ref = str(component.get("bom-ref", component.get("purl", f"index:{index}")))
            index += 1
            if ref in refs:
                findings.append(_finding("duplicate-sbom-reference", "high",
                                         "SBOM component reference is duplicated", "high", package=ref))
            refs.add(ref)
            record = {"ref": ref, "name": component.get("name"), "version": component.get("version"),
                      "purl": component.get("purl"), "hashes": component.get("hashes", [])}
            components.append(record)
            if not record["version"]:
                findings.append(_finding("sbom-component-without-version", "medium",
                                         "SBOM component has no version", package=record["name"]))
            if not record["purl"] and not component.get("cpe"):
                findings.append(_finding("sbom-component-without-identity", "low",
                                         "SBOM component has no purl or CPE", package=record["name"]))
            nested = component.get("components", [])
            if isinstance(nested, Sequence) and not isinstance(nested, (str, bytes)):
                queue.extend(nested)
        if isinstance(raw_dependencies, Sequence) and not isinstance(raw_dependencies, (str, bytes)):
            for dependency in raw_dependencies:
                if not isinstance(dependency, Mapping):
                    continue
                source = str(dependency.get("ref", ""))
                targets = [str(value) for value in dependency.get("dependsOn", [])]
                dependencies.append({"ref": source, "depends_on": targets})
                for ref in [source] + targets:
                    if ref and ref not in refs:
                        findings.append(_finding("dangling-sbom-reference", "medium",
                                                 "SBOM dependency graph references an unknown component",
                                                 package=ref))
    elif "spdxVersion" in document or "packages" in document:
        format_name = "spdx"
        raw_packages = document.get("packages", [])
        refs = set()
        for package in raw_packages if isinstance(raw_packages, Sequence) else []:
            if not isinstance(package, Mapping):
                continue
            ref = str(package.get("SPDXID", ""))
            if ref in refs:
                findings.append(_finding("duplicate-sbom-reference", "high",
                                         "SPDX package identifier is duplicated", package=ref))
            refs.add(ref)
            components.append({"ref": ref, "name": package.get("name"),
                               "version": package.get("versionInfo"),
                               "hashes": package.get("checksums", [])})
            if package.get("filesAnalyzed") is False and not package.get("packageVerificationCode"):
                findings.append(_finding("spdx-package-unverified", "low",
                                         "SPDX package was not file-analyzed and has no verification code",
                                         package=package.get("name")))
        for relation in document.get("relationships", []) if isinstance(document.get("relationships", []), Sequence) else []:
            if isinstance(relation, Mapping):
                dependencies.append(dict(relation))
                for key in ("spdxElementId", "relatedSpdxElement"):
                    ref = str(relation.get(key, ""))
                    if ref and ref not in refs and ref != str(document.get("SPDXID", "")):
                        findings.append(_finding("dangling-sbom-reference", "medium",
                                                 "SPDX relationship references an unknown element", package=ref))
    else:
        raise ValueError("unrecognized SBOM format")

    # Verify only explicit supplied file/hash pairs; no registry retrieval.
    for component in components:
        candidate = artifacts.get(str(component.get("name", "")))
        if candidate is None:
            continue
        hashes = component.get("hashes", [])
        for digest in hashes if isinstance(hashes, Sequence) else []:
            if not isinstance(digest, Mapping):
                continue
            algorithm = str(digest.get("alg", digest.get("algorithm", ""))).lower().replace("-", "")
            expected = str(digest.get("content", digest.get("checksumValue", ""))).lower()
            if algorithm not in hashlib.algorithms_available:
                continue
            actual = hashlib.new(algorithm, candidate).hexdigest()
            if actual != expected:
                findings.append(_finding("sbom-artifact-digest-mismatch", "critical",
                                         "supplied artifact does not match its SBOM digest", "high",
                                         package=component.get("name"), algorithm=algorithm,
                                         expected=expected, actual=actual))
    return {"kind": "sbom-analysis", "format": format_name, "components": components,
            "dependencies": dependencies, "findings": _sort(findings)}


def _decode_dsse(document: Mapping[str, object]) -> tuple[Mapping[str, object], dict]:
    if "payload" not in document or "payloadType" not in document:
        return document, {"envelope": False, "signatures": []}
    try:
        payload = base64.b64decode(str(document["payload"]), validate=True)
        statement = json.loads(payload)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError, RecursionError) as error:
        raise ValueError("invalid DSSE payload") from error
    if not isinstance(statement, Mapping):
        raise ValueError("DSSE payload must be a statement object")
    raw_signatures = document.get("signatures", [])
    valid_shape = (isinstance(raw_signatures, Sequence)
                   and not isinstance(raw_signatures, (str, bytes))
                   and all(isinstance(item, Mapping) for item in raw_signatures))
    signatures = list(raw_signatures) if valid_shape else []
    return statement, {"envelope": True, "payload_type": document.get("payloadType"),
                       "signatures": signatures, "signatures_valid_shape": valid_shape}


def analyze_provenance(document: Mapping[str, object], artifacts: Mapping[str, bytes] | None = None) -> dict:
    """Validate supplied in-toto/SLSA structure and subject/material hashes."""
    artifacts = artifacts or {}
    statement, envelope = _decode_dsse(document)
    findings = []
    if not str(statement.get("_type", "")).endswith("Statement/v1"):
        findings.append(_finding("nonstandard-attestation-type", "medium",
                                 "attestation does not declare in-toto Statement/v1"))
    predicate_type = str(statement.get("predicateType", ""))
    predicate = statement.get("predicate", {})
    predicate = predicate if isinstance(predicate, Mapping) else {}
    build_definition = predicate.get("buildDefinition", {})
    build_definition = build_definition if isinstance(build_definition, Mapping) else {}
    run_details = predicate.get("runDetails", {})
    run_details = run_details if isinstance(run_details, Mapping) else {}
    builder = run_details.get("builder", predicate.get("builder", {}))
    if not isinstance(builder, Mapping) or not builder.get("id"):
        findings.append(_finding("provenance-builder-missing", "high",
                                 "provenance has no builder identity"))
    build_type = build_definition.get("buildType", predicate.get("buildType"))
    if not build_type:
        findings.append(_finding("provenance-build-type-missing", "medium",
                                 "provenance has no build type"))
    subjects = []
    for subject in statement.get("subject", []) if isinstance(statement.get("subject", []), Sequence) else []:
        if not isinstance(subject, Mapping):
            continue
        name, digests = str(subject.get("name", "")), subject.get("digest", {})
        subjects.append({"name": name, "digest": digests})
        if not isinstance(digests, Mapping) or not digests:
            findings.append(_finding("provenance-subject-without-digest", "high",
                                     "provenance subject has no digest", package=name))
        if name in artifacts and isinstance(digests, Mapping):
            for algorithm, expected in digests.items():
                normalized = str(algorithm).lower().replace("-", "")
                if normalized not in hashlib.algorithms_available:
                    continue
                actual = hashlib.new(normalized, artifacts[name]).hexdigest()
                if actual.lower() != str(expected).lower():
                    findings.append(_finding("provenance-subject-mismatch", "critical",
                                             "supplied subject bytes do not match provenance", "high",
                                             package=name, algorithm=algorithm,
                                             expected=expected, actual=actual))
    materials = build_definition.get("resolvedDependencies", predicate.get("materials", []))
    if not materials:
        findings.append(_finding("provenance-materials-missing", "medium",
                                 "provenance does not enumerate build inputs"))
    if envelope["envelope"] and not envelope["signatures"]:
        findings.append(_finding("unsigned-dsse-envelope", "critical",
                                 "DSSE envelope contains no signatures", "high"))
    if envelope["envelope"] and not envelope.get("signatures_valid_shape", True):
        findings.append(_finding("malformed-dsse-signatures", "high",
                                 "DSSE signatures must be an array of signature objects", "high"))
    if envelope["envelope"] and envelope["signatures"]:
        findings.append(_finding("dsse-signature-unverified", "info",
                                 "signature metadata is present but no caller-supplied verification key was provided"))
    if isinstance(materials, Sequence) and not isinstance(materials, (str, bytes)):
        for material in materials:
            if not isinstance(material, Mapping):
                continue
            name = str(material.get("uri", material.get("name", "")))
            digests = material.get("digest", {})
            if name not in artifacts or not isinstance(digests, Mapping):
                continue
            for algorithm, expected in digests.items():
                normalized = str(algorithm).lower().replace("-", "")
                if normalized not in hashlib.algorithms_available:
                    continue
                actual = hashlib.new(normalized, artifacts[name]).hexdigest()
                if actual.lower() != str(expected).lower():
                    findings.append(_finding("provenance-material-mismatch", "critical",
                                             "supplied build material does not match provenance", "high",
                                             package=name, algorithm=algorithm,
                                             expected=expected, actual=actual))
    invocation = build_definition.get("externalParameters", predicate.get("invocation", {}))
    if _SECRET_LITERAL.search(json.dumps(invocation, sort_keys=True).encode()):
        findings.append(_finding("secret-in-provenance-parameters", "high",
                                 "provenance invocation embeds secret-like material"))
    return {"kind": "provenance-analysis", "predicate_type": predicate_type,
            "envelope": envelope, "subjects": subjects, "materials": materials,
            "findings": _sort(findings)}


def analyze_github_workflow(workflow: Mapping[str, object]) -> dict:
    """Audit a supplied parsed GitHub Actions workflow."""
    findings, jobs_out = [], []
    triggers = workflow.get("on", workflow.get(True, {}))  # YAML 1.1 loaders may turn `on` into True.
    trigger_names = {triggers} if isinstance(triggers, str) else (
        set(triggers) if isinstance(triggers, Mapping) else set(triggers or []))
    permissions = workflow.get("permissions", {})
    if permissions == "write-all":
        findings.append(_finding("workflow-write-all", "critical",
                                 "workflow grants write access to all token scopes", "high"))
    if isinstance(permissions, Mapping) and str(permissions.get("id-token", "")).lower() == "write":
        findings.append(_finding("workflow-oidc-token", "medium",
                                 "workflow can mint an OIDC identity token; trust policy review is required"))
    dangerous_trigger = "pull_request_target" in trigger_names
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, Mapping):
        raise ValueError("workflow jobs must be an object")
    for job_name, job in jobs.items():
        if not isinstance(job, Mapping):
            continue
        runner = job.get("runs-on", job.get("runsOn"))
        labels = [runner] if isinstance(runner, str) else list(runner or [])
        if any(str(value).lower() == "self-hosted" for value in labels):
            findings.append(_finding("self-hosted-workflow-runner", "high",
                                     "job executes on a self-hosted runner", job=str(job_name)))
        job_permissions = job.get("permissions", permissions)
        write_permissions = (job_permissions == "write-all"
                             or (isinstance(job_permissions, Mapping)
                                 and any(str(value).lower() == "write"
                                         for value in job_permissions.values())))
        if dangerous_trigger and write_permissions:
            findings.append(_finding("privileged-pull-request-target", "critical",
                                     "pull_request_target job has non-minimal token permissions",
                                     job=str(job_name)))
        steps_out = []
        for index, step in enumerate(job.get("steps", []) if isinstance(job.get("steps", []), Sequence) else []):
            if not isinstance(step, Mapping):
                continue
            uses = str(step.get("uses", ""))
            run = str(step.get("run", ""))
            steps_out.append({"index": index, "name": step.get("name"), "uses": uses,
                              "has_run": bool(run)})
            if uses:
                ref = uses.rsplit("@", 1)[1] if "@" in uses else ""
                immutable_action = bool(re.fullmatch(r"[0-9a-fA-F]{40}", ref))
                immutable_container = bool(re.search(r"@sha256:[0-9a-fA-F]{64}$", uses))
                if not immutable_action and not immutable_container and not uses.startswith("./"):
                    findings.append(_finding("workflow-action-not-sha-pinned", "high",
                                             "third-party action is not pinned to a full commit digest",
                                             job=str(job_name), step=index, action=uses))
                if dangerous_trigger and uses.lower().startswith("actions/checkout"):
                    checkout_ref = str(step.get("with", {}).get("ref", "")) if isinstance(step.get("with", {}), Mapping) else ""
                    if "github.event.pull_request.head" in checkout_ref:
                        findings.append(_finding("untrusted-checkout-in-target-context", "critical",
                                                 "privileged target-context job checks out pull-request code",
                                                 "high", job=str(job_name), step=index))
            if run and re.search(
                    r"\$\{\{\s*(?:github\.(?:event\.(?:issue|pull_request|comment|head_commit|commits|workflow_run)|"
                    r"head_ref)|inputs\.)", run, re.I):
                findings.append(_finding("workflow-expression-injection", "critical",
                                         "untrusted event text is interpolated directly into a shell script",
                                         job=str(job_name), step=index))
            environment = step.get("env", {})
            arguments = step.get("with", {})
            secret_values = []
            if isinstance(environment, Mapping):
                secret_values.extend(environment.values())
            if isinstance(arguments, Mapping):
                secret_values.extend(arguments.values())
            immutable_ref = uses.rsplit("@", 1)[1] if "@" in uses else ""
            if uses and any("secrets." in str(value) for value in secret_values) \
                    and not uses.startswith("./") and not re.fullmatch(r"[0-9a-fA-F]{40}", immutable_ref):
                findings.append(_finding("secret-to-unpinned-action", "critical",
                                         "secret is passed to an action without an immutable trusted pin",
                                         job=str(job_name), step=index, action=uses))
        jobs_out.append({"name": str(job_name), "runner": labels, "steps": steps_out})
    return {"kind": "github-workflow-analysis", "triggers": sorted(str(value) for value in trigger_names),
            "jobs": jobs_out, "findings": _sort(findings)}


def analyze_dockerfile(text: str) -> dict:
    """Inspect Dockerfile build provenance, secret handling, and pinning."""
    if len(text.encode("utf-8", "replace")) > MAX_INPUT:
        raise ValueError("Dockerfile exceeds input cap")
    logical = []
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not buffer:
            start = number
        buffer += stripped[:-1] + " " if stripped.endswith("\\") else stripped
        if not stripped.endswith("\\"):
            if buffer and not buffer.startswith("#"):
                logical.append((start, buffer.strip()))
            buffer = ""
    findings, instructions = [], []
    for line_number, line in logical:
        match = re.match(r"([A-Za-z]+)\s+(.*)", line, re.S)
        if not match:
            continue
        instruction, argument = match.group(1).upper(), match.group(2).strip()
        instructions.append({"line": line_number, "instruction": instruction, "argument": argument})
        if instruction == "FROM":
            image = argument.split(" AS ", 1)[0].split(" as ", 1)[0].strip()
            immutable_image = bool(re.search(r"@sha256:[0-9a-fA-F]{64}$", image))
            if image != "scratch" and not immutable_image:
                findings.append(_finding("base-image-not-digest-pinned", "high",
                                         "base image is not pinned by content digest",
                                         line=line_number, image=image))
            if image != "scratch" and (image.endswith(":latest") or ":" not in image.rsplit("/", 1)[-1]):
                findings.append(_finding("floating-base-image", "medium",
                                         "base image tag is floating/implicit", line=line_number,
                                         image=image))
        if instruction in {"ARG", "ENV"} and _SECRET_KEY.search(argument.split("=", 1)[0]):
            findings.append(_finding("build-secret-in-arg-env", "high",
                                     "secret-like value is declared through image metadata",
                                     line=line_number))
        if instruction in {"RUN", "ADD"} and re.search(r"\b(?:curl|wget)\b[^|;&]*(?:\||&&)\s*(?:sh|bash|python|node)\b", argument, re.I):
            findings.append(_finding("docker-download-and-execute", "critical",
                                     "image build downloads and immediately executes content",
                                     line=line_number))
        checksum_pinned = bool(re.search(r"--checksum=sha256:[0-9a-fA-F]{64}(?:\s|$)", argument))
        if instruction == "ADD" and re.search(r"https?://", argument) and not checksum_pinned:
            findings.append(_finding("remote-docker-add", "high",
                                     "ADD retrieves a remote artifact without an evident local digest check",
                                     line=line_number))
        if instruction == "RUN" and re.search(r"\b(?:apt-get|apt|apk|yum|dnf)\s+(?:install|add)\b", argument):
            if not re.search(r"(?:=[0-9]|-[0-9][\w.+:~-]*-[0-9])", argument):
                findings.append(_finding("unpinned-system-packages", "medium",
                                         "system packages are installed without versions",
                                         line=line_number))
        if instruction in {"COPY", "ADD"}:
            source = argument.split()[0] if argument.split() else ""
            if source in {".", "./", "*"}:
                findings.append(_finding("broad-build-context-copy", "medium",
                                         "build copies the broad context into an image",
                                         line=line_number, source=source))
    return {"kind": "dockerfile-analysis", "instructions": instructions,
            "findings": _sort(findings)}


def _dockerignore_patterns(content: bytes | str) -> list[str]:
    text = content.decode("utf-8", "replace") if isinstance(content, bytes) else content
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def _ignored(path: str, patterns: Sequence[str]) -> bool:
    ignored = False
    for pattern in patterns:
        negate = pattern.startswith("!")
        value = pattern[1:] if negate else pattern
        anchored = value.startswith("/")
        value = value.lstrip("/").rstrip("/")
        parts = PurePosixPath(path).parts
        if anchored or "/" in value:
            matched = fnmatch.fnmatch(path, value) or fnmatch.fnmatch(path, value + "/**")
        else:
            matched = any(fnmatch.fnmatch(part, value) for part in parts)
        if matched:
            ignored = not negate
    return ignored


def _copy_sources(argument: str) -> list[str]:
    """Return local COPY/ADD sources from a normalized Dockerfile argument."""
    if re.search(r"(?:^|\s)--from(?:=|\s)", argument):
        return []
    stripped = argument.strip()
    if stripped.startswith("["):
        try:
            values = json.loads(stripped)
        except json.JSONDecodeError:
            return []
        return [str(value) for value in values[:-1]] if isinstance(values, list) else []
    try:
        fields = shlex.split(argument)
    except ValueError:
        return []
    fields = [field for field in fields if not field.startswith("--")]
    return fields[:-1] if len(fields) >= 2 else []


def analyze_build_context(files: Mapping[str, bytes | str]) -> dict:
    """Review a supplied build-context map; never reads local files or follows links."""
    if len(files) > MAX_FILES:
        raise ValueError("build context file count exceeds cap")
    normalized = {str(PurePosixPath(path.replace("\\", "/"))):
                  (value if isinstance(value, bytes) else value.encode()) for path, value in files.items()}
    patterns = _dockerignore_patterns(normalized.get(".dockerignore", b""))
    dockerfile = normalized.get("Dockerfile", normalized.get("dockerfile", b"")).decode("utf-8", "replace")
    docker_report = analyze_dockerfile(dockerfile) if dockerfile else {"instructions": [], "findings": []}
    findings = list(docker_report["findings"])
    included = []
    for path, content in sorted(normalized.items()):
        if path == ".dockerignore" or _ignored(path, patterns):
            continue
        included.append(path)
        if _SECRET_FILE.search(path):
            findings.append(_finding("secret-file-in-build-context", "high",
                                     "secret-like file is included in build context", "high", path=path))
        if len(content) <= 2 * 1024 * 1024 and _SECRET_LITERAL.search(content):
            findings.append(_finding("secret-literal-in-build-context", "critical",
                                     "included build-context file contains secret-like material",
                                     path=path))
    broad_copy = any(item["kind"] == "broad-build-context-copy" for item in docker_report["findings"])
    copy_sources = []
    for instruction in docker_report["instructions"]:
        if instruction["instruction"] in {"COPY", "ADD"}:
            copy_sources.extend(_copy_sources(str(instruction["argument"])))
    for path in included:
        if _SECRET_FILE.search(path):
            targeted = any(
                source in {".", "./", "*", path}
                or (source.rstrip("/") and path.startswith(source.rstrip("/") + "/"))
                or fnmatch.fnmatch(path, source)
                for source in copy_sources
            )
            if broad_copy or targeted:
                findings.append(_finding("secret-copied-into-image", "critical",
                                         "COPY/ADD can persist a secret-like file in an image layer",
                                         "high", path=path))
    return {"kind": "build-context-analysis", "dockerignore": patterns,
            "included_files": included, "dockerfile": docker_report,
            "findings": _sort(findings)}


def analyze_iac_supply_chain(document: Mapping[str, object]) -> dict:
    """Inspect parsed Terraform/Helm/Kustomize/Kubernetes supply-chain references."""
    findings, references = [], []

    # Exposure checks deliberately operate only on supplied values. Dynamic secret
    # references are recorded as such and not treated as plaintext credentials.
    dynamic_secret = re.compile(
        r"(?:\$\{|\{\{|resolve:|(?:keyvault|secretsmanager|secretmanager|parameterstore)(?::|/))",
        re.I,
    )
    kind = str(document.get("kind", ""))
    if kind.lower() == "secret":
        for field in ("data", "stringData"):
            values = document.get(field, {})
            if isinstance(values, Mapping) and values:
                findings.append(_finding("literal-kubernetes-secret", "high",
                                         "Kubernetes Secret embeds values directly in the manifest",
                                         "high", path=field, keys=sorted(str(key) for key in values)))
    if kind.lower() == "configmap":
        values = document.get("data", {})
        if isinstance(values, Mapping):
            for key, value in values.items():
                if _SECRET_KEY.search(str(key)) and not dynamic_secret.search(str(value)):
                    findings.append(_finding("secret-in-configmap", "high",
                                             "ConfigMap contains a secret-like literal", "high",
                                             path=f"data.{key}"))

    parameters = document.get("Parameters", {})
    if isinstance(parameters, Mapping):
        for name, config in parameters.items():
            if not _SECRET_KEY.search(str(name)) or not isinstance(config, Mapping):
                continue
            if config.get("NoEcho") is not True:
                findings.append(_finding("cloudformation-secret-parameter-visible", "high",
                                         "secret-like CloudFormation parameter does not enable NoEcho",
                                         path=f"Parameters.{name}"))
            default = config.get("Default")
            if default not in (None, "") and not dynamic_secret.search(str(default)):
                findings.append(_finding("cloudformation-secret-default", "critical",
                                         "secret-like CloudFormation parameter has a literal default",
                                         "high", path=f"Parameters.{name}"))

    outputs = document.get("output", document.get("outputs", document.get("Outputs", {})))
    if isinstance(outputs, Mapping):
        for name, config in outputs.items():
            config = config if isinstance(config, Mapping) else {"value": config}
            value = config.get("value", config.get("Value"))
            if (_SECRET_KEY.search(str(name)) or _SECRET_KEY.search(str(value))) and not config.get("sensitive", False):
                findings.append(_finding("sensitive-iac-output", "high",
                                         "secret-like IaC output is not marked sensitive",
                                         path=f"outputs.{name}"))

    modules = document.get("module", document.get("modules", {}))
    if isinstance(modules, Mapping):
        for name, config in modules.items():
            config = config if isinstance(config, Mapping) else {}
            source, version = str(config.get("source", "")), config.get("version")
            references.append({"kind": "terraform-module", "name": str(name),
                               "source": source, "version": version})
            remote_git = source.startswith(("git::", "github.com/", "https://"))
            if remote_git and not re.search(r"[?&]ref=[0-9a-fA-F]{40}(?:$|&)", source):
                findings.append(_finding("terraform-module-not-commit-pinned", "high",
                                         "remote Terraform module is not pinned to a full commit",
                                         package=str(name), source=source))
            if source and not version and not remote_git and not source.startswith(("./", "../")):
                findings.append(_finding("terraform-module-version-missing", "medium",
                                         "registry Terraform module has no version constraint",
                                         package=str(name), source=source))
    providers = document.get("required_providers", document.get("requiredProviders", {}))
    if isinstance(providers, Mapping):
        for name, config in providers.items():
            config = config if isinstance(config, Mapping) else {"version": config}
            version = str(config.get("version", ""))
            references.append({"kind": "terraform-provider", "name": str(name),
                               "source": config.get("source"), "version": version})
            if not version or version in {"*", ">= 0"}:
                findings.append(_finding("terraform-provider-unconstrained", "high",
                                         "Terraform provider has no meaningful version constraint",
                                         package=str(name)))

    helm_dependencies = document.get("dependencies", [])
    if str(document.get("apiVersion", "")).startswith("v2") and isinstance(helm_dependencies, Sequence):
        for dependency in helm_dependencies:
            if not isinstance(dependency, Mapping):
                continue
            name, version = str(dependency.get("name", "")), str(dependency.get("version", ""))
            references.append({"kind": "helm-chart", "name": name,
                               "source": dependency.get("repository"), "version": version})
            if not version or any(char in version for char in "*xX><~^"):
                findings.append(_finding("helm-chart-not-exactly-pinned", "high",
                                         "Helm dependency does not use an exact chart version",
                                         package=name, version=version))
            repository = str(dependency.get("repository", ""))
            if repository.startswith("http://"):
                findings.append(_finding("insecure-helm-repository", "high",
                                         "Helm dependency uses plaintext HTTP", package=name,
                                         source=repository))

    resources = document.get("resources", [])
    if isinstance(resources, Sequence) and not isinstance(resources, (str, bytes)):
        for resource in resources:
            value = str(resource)
            references.append({"kind": "kustomize-resource", "source": value})
            if re.search(r"(?:https?://|github\.com/|git::)", value) and not re.search(
                    r"[?&](?:ref|version)=[0-9a-fA-F]{40}(?:$|&)", value):
                findings.append(_finding("kustomize-remote-not-commit-pinned", "high",
                                         "remote Kustomize resource is not pinned to a full commit",
                                         source=value))

    def walk_images(value: object, path: str = "", depth: int = 0,
                    active: set[int] | None = None) -> None:
        if depth > MAX_NESTING:
            raise ValueError("IaC nesting exceeds cap")
        if not isinstance(value, (Mapping, Sequence)) or isinstance(value, (str, bytes)):
            return
        active = active if active is not None else set()
        identity = id(value)
        if identity in active:
            raise ValueError("cyclic IaC structure")
        active.add(identity)
        if isinstance(value, Mapping):
            try:
                for key, child in value.items():
                    child_path = f"{path}.{key}" if path else str(key)
                    if str(key) == "image" and isinstance(child, str):
                        references.append({"kind": "container-image", "path": child_path, "source": child})
                        if not re.search(r"@sha256:[0-9a-fA-F]{64}$", child):
                            findings.append(_finding("iac-image-not-digest-pinned", "high",
                                                     "container image is not pinned by a valid digest",
                                                     path=child_path, image=child))
                    walk_images(child, child_path, depth + 1, active)
            finally:
                active.remove(identity)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            try:
                for index, child in enumerate(value):
                    walk_images(child, f"{path}[{index}]", depth + 1, active)
            finally:
                active.remove(identity)

    walk_images(document)
    return {"kind": "iac-supply-chain-analysis", "references": references,
            "findings": _sort(findings)}


def analyze_artifact(data: bytes, name: str = "artifact") -> dict:
    if len(data) > MAX_INPUT:
        raise ValueError("artifact exceeds input cap")
    lower = Path(name).name.lower()
    if lower in {"dockerfile", "containerfile"}:
        return analyze_dockerfile(data.decode("utf-8", "replace"))
    if lower in {"requirements.txt", "requirements.in", "cargo.lock", "go.sum", "yarn.lock", "pnpm-lock.yaml"}:
        return analyze_text_lockfile(data.decode("utf-8", "replace"), lower)
    try:
        parsed = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("artifact format requires a parsed mapping API or JSON") from error
    if not isinstance(parsed, Mapping):
        raise ValueError("supply-chain JSON must be an object")
    if "bomFormat" in parsed or "spdxVersion" in parsed:
        return analyze_sbom(parsed)
    if "predicateType" in parsed or ("payload" in parsed and "payloadType" in parsed):
        return analyze_provenance(parsed)
    if "jobs" in parsed:
        return analyze_github_workflow(parsed)
    if str(parsed.get("apiVersion", "")).startswith("v2") and "dependencies" in parsed:
        return analyze_iac_supply_chain(parsed)
    if "dependencies" in parsed or "devDependencies" in parsed:
        return analyze_package_manifest(parsed)
    return analyze_iac_supply_chain(parsed)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="supplied manifest/lock/SBOM/provenance artifact")
    args = parser.parse_args(argv)
    print(json.dumps(analyze_artifact(args.artifact.read_bytes(), args.artifact.name),
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
