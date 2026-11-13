#!/usr/bin/env python3
"""Offline container-escape and serverless artifact analysis.

The module inspects supplied manifests, OCI configs, proc/cgroup snapshots, and
function archives.  It never starts a container, invokes a cloud API, or touches the
host runtime socket.
"""
from __future__ import annotations

import argparse
import io
import json
import re
import stat
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence

MAX_INPUT = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_EXPANDED = 512 * 1024 * 1024
MAX_MEMBER_SCAN = 2 * 1024 * 1024
MAX_NESTING = 256
_SEVERITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

_DANGEROUS_CAPABILITIES = {
    "CAP_SYS_ADMIN", "SYS_ADMIN", "CAP_SYS_MODULE", "SYS_MODULE", "CAP_SYS_PTRACE", "SYS_PTRACE",
    "CAP_DAC_READ_SEARCH", "DAC_READ_SEARCH", "CAP_DAC_OVERRIDE", "DAC_OVERRIDE",
    "CAP_SYS_RAWIO", "SYS_RAWIO", "CAP_NET_ADMIN", "NET_ADMIN", "CAP_BPF", "BPF",
    "CAP_PERFMON", "PERFMON", "CAP_SYS_CHROOT", "SYS_CHROOT", "CAP_MKNOD", "MKNOD",
}
_CAP_NAMES = [
    "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID",
    "SETPCAP", "LINUX_IMMUTABLE", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW",
    "IPC_LOCK", "IPC_OWNER", "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT",
    "SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "MKNOD",
    "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG",
    "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF", "CHECKPOINT_RESTORE",
]
_SENSITIVE_HOST_PATHS = ("/", "/proc", "/sys", "/dev", "/etc", "/var/run", "/run", "/boot")
_SECRET_NAME = re.compile(
    r"(?:secret|password|passwd|token|api[_-]?key|private[_-]?key|client[_-]?secret|connection[_-]?string)", re.I
)
_SECRET_VALUE = re.compile(
    rb"(?:AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    rb"(?:password|passwd|token|api[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]?[^\s'\"]{8,})", re.I
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
        str(item.get("workload", "")), str(item.get("container", "")), str(item.get("path", "")),
    ))


def _pod_specs(document: object, _depth: int = 0,
               _active: set[int] | None = None) -> list[tuple[str, Mapping[str, object], Mapping[str, object]]]:
    if _depth > MAX_NESTING:
        raise ValueError("workload nesting exceeds cap")
    results: list[tuple[str, Mapping[str, object], Mapping[str, object]]] = []
    if not isinstance(document, (Mapping, Sequence)) or isinstance(document, (str, bytes)):
        return results
    active = _active if _active is not None else set()
    identity = id(document)
    if identity in active:
        raise ValueError("cyclic workload structure")
    active.add(identity)
    try:
        if isinstance(document, Sequence) and not isinstance(document, (str, bytes)):
            for item in document:
                results.extend(_pod_specs(item, _depth + 1, active))
            return results
        if not isinstance(document, Mapping):
            return results
        if str(document.get("kind", "")).lower() == "list":
            return _pod_specs(document.get("items", []), _depth + 1, active)
        metadata = document.get("metadata", {})
        metadata = metadata if isinstance(metadata, Mapping) else {}
        name = str(metadata.get("name", document.get("name", "workload")))
        kind = str(document.get("kind", "Pod"))
        spec = document.get("spec", document)
        if not isinstance(spec, Mapping):
            return results
        template = spec.get("template")
        # CronJob wraps a Job template, which in turn wraps the Pod template.
        if not isinstance(template, Mapping) and isinstance(spec.get("jobTemplate"), Mapping):
            job_spec = spec["jobTemplate"].get("spec", {})
            if isinstance(job_spec, Mapping):
                template = job_spec.get("template")
        if isinstance(template, Mapping):
            template_meta = template.get("metadata", {})
            template_spec = template.get("spec", {})
            if isinstance(template_spec, Mapping):
                combined_meta = dict(metadata)
                if isinstance(template_meta, Mapping):
                    combined_meta.update(template_meta)
                results.append((f"{kind}/{name}", template_spec, combined_meta))
        elif "containers" in spec or "initContainers" in spec:
            results.append((f"{kind}/{name}", spec, metadata))
        return results
    finally:
        active.remove(identity)


def analyze_container_workload(document: object) -> dict:
    """Audit Kubernetes-style workload mappings for escape primitives."""
    findings, workloads = [], []
    for workload, spec, metadata in _pod_specs(document):
        pod_security = spec.get("securityContext", {})
        pod_security = pod_security if isinstance(pod_security, Mapping) else {}
        if spec.get("hostPID") is True:
            findings.append(_finding("host-pid-namespace", "high", "workload joins the host PID namespace",
                                     "high", workload=workload))
        if spec.get("hostNetwork") is True:
            findings.append(_finding("host-network-namespace", "medium", "workload joins the host network namespace",
                                     "high", workload=workload))
        if spec.get("hostIPC") is True:
            findings.append(_finding("host-ipc-namespace", "high", "workload joins the host IPC namespace",
                                     "high", workload=workload))
        if spec.get("shareProcessNamespace") is True:
            findings.append(_finding("shared-process-namespace", "medium",
                                     "containers share a process namespace", "high", workload=workload))
        if spec.get("automountServiceAccountToken", True) is not False:
            findings.append(_finding("service-account-token-mounted", "medium",
                                     "service-account token automount is not disabled", workload=workload,
                                     service_account=spec.get("serviceAccountName", "default")))

        raw_volumes = spec.get("volumes", [])
        volumes = {}
        if isinstance(raw_volumes, Sequence) and not isinstance(raw_volumes, (str, bytes)):
            for volume in raw_volumes:
                if not isinstance(volume, Mapping):
                    continue
                name = str(volume.get("name", ""))
                host_path = volume.get("hostPath")
                if isinstance(host_path, Mapping):
                    path = str(host_path.get("path", ""))
                    volumes[name] = {"host_path": path, "type": host_path.get("type")}
                    severity = "critical" if path in {"/", "/var/run", "/run"} else "high"
                    findings.append(_finding("host-path-volume", severity,
                                             "workload exposes a host filesystem path", "high",
                                             workload=workload, volume=name, path=path))
                if "projected" in volume and isinstance(volume["projected"], Mapping):
                    sources = volume["projected"].get("sources", [])
                    source_items = (sources if isinstance(sources, Sequence)
                                    and not isinstance(sources, (str, bytes)) else [])
                    if any(isinstance(source, Mapping) and "serviceAccountToken" in source
                           for source in source_items):
                        findings.append(_finding("projected-service-account-token", "medium",
                                                 "projected volume contains a service-account token",
                                                 workload=workload, volume=name))

        container_records = []
        for group in ("initContainers", "containers", "ephemeralContainers"):
            raw_containers = spec.get(group, [])
            if not isinstance(raw_containers, Sequence) or isinstance(raw_containers, (str, bytes)):
                continue
            for container in raw_containers:
                if not isinstance(container, Mapping):
                    continue
                name = str(container.get("name", "unnamed"))
                security = container.get("securityContext", {})
                security = security if isinstance(security, Mapping) else {}
                effective = dict(pod_security)
                effective.update(security)
                record = {"name": name, "group": group, "image": container.get("image"),
                          "security_context": effective}
                container_records.append(record)
                if effective.get("privileged") is True:
                    findings.append(_finding("privileged-container", "critical",
                                             "container is explicitly privileged", "high",
                                             workload=workload, container=name))
                if effective.get("allowPrivilegeEscalation", True) is not False:
                    findings.append(_finding("privilege-escalation-allowed", "high",
                                             "no-new-privileges is not enforced", workload=workload,
                                             container=name))
                run_as_user = effective.get("runAsUser")
                if run_as_user == 0 or (run_as_user is None and effective.get("runAsNonRoot") is not True):
                    findings.append(_finding("container-may-run-as-root", "medium",
                                             "container is not constrained to a non-root UID",
                                             workload=workload, container=name))
                if effective.get("readOnlyRootFilesystem") is not True:
                    findings.append(_finding("writable-root-filesystem", "low",
                                             "container root filesystem is not explicitly read-only",
                                             workload=workload, container=name))
                caps = effective.get("capabilities", {})
                caps = caps if isinstance(caps, Mapping) else {}
                raw_added = caps.get("add", [])
                added = ({str(value).upper() for value in raw_added}
                         if isinstance(raw_added, Sequence) and not isinstance(raw_added, (str, bytes)) else set())
                dangerous = sorted(added & _DANGEROUS_CAPABILITIES)
                if dangerous:
                    findings.append(_finding("dangerous-linux-capability", "critical",
                                             "container adds escape-relevant Linux capabilities", "high",
                                             workload=workload, container=name, capabilities=dangerous))
                seccomp = effective.get("seccompProfile", {})
                seccomp_type = str(seccomp.get("type", "")) if isinstance(seccomp, Mapping) else ""
                if seccomp_type.lower() == "unconfined":
                    findings.append(_finding("seccomp-unconfined", "high",
                                             "container disables seccomp filtering", "high",
                                             workload=workload, container=name))
                elif not seccomp_type:
                    findings.append(_finding("seccomp-unspecified", "low",
                                             "container does not declare a seccomp profile",
                                             workload=workload, container=name))
                for port in container.get("ports", []) if isinstance(container.get("ports", []), Sequence) else []:
                    if isinstance(port, Mapping) and port.get("hostPort"):
                        findings.append(_finding("host-port", "medium",
                                                 "container binds a port in the host namespace",
                                                 workload=workload, container=name, port=port.get("hostPort")))
                mounts = container.get("volumeMounts", [])
                if isinstance(mounts, Sequence) and not isinstance(mounts, (str, bytes)):
                    for mount in mounts:
                        if not isinstance(mount, Mapping):
                            continue
                        volume = volumes.get(str(mount.get("name", "")))
                        mount_path = str(mount.get("mountPath", ""))
                        if volume and not mount.get("readOnly", False):
                            findings.append(_finding("writable-host-path", "critical",
                                                     "hostPath is writable inside the container", "high",
                                                     workload=workload, container=name,
                                                     path=volume["host_path"], mount_path=mount_path))
                        if "docker.sock" in mount_path or "containerd.sock" in mount_path or "crio.sock" in mount_path:
                            findings.append(_finding("runtime-socket-mounted", "critical",
                                                     "container runtime control socket is mounted", "high",
                                                     workload=workload, container=name, path=mount_path))
        annotations = metadata.get("annotations", {})
        if isinstance(annotations, Mapping):
            for key, value in annotations.items():
                if ("apparmor" in str(key).lower() or "seccomp" in str(key).lower()) and str(value).lower().endswith("unconfined"):
                    findings.append(_finding("runtime-profile-unconfined", "high",
                                             "workload annotation disables a runtime security profile", "high",
                                             workload=workload, annotation=key))
        workloads.append({"name": workload, "volumes": volumes, "containers": container_records})
    return {"kind": "container-workload-analysis", "workloads": workloads,
            "findings": _sort(findings)}


def analyze_oci_runtime_config(config: Mapping[str, object]) -> dict:
    """Audit a supplied OCI runtime-spec configuration."""
    if not isinstance(config, Mapping):
        raise ValueError("OCI runtime config must be a mapping")
    linux = config.get("linux", {})
    process = config.get("process", {})
    linux = linux if isinstance(linux, Mapping) else {}
    process = process if isinstance(process, Mapping) else {}
    findings = []
    root = config.get("root", {})
    root = root if isinstance(root, Mapping) else {}
    if root.get("readonly") is not True:
        findings.append(_finding("oci-writable-rootfs", "medium",
                                 "OCI root filesystem is not explicitly read-only"))
    hooks = config.get("hooks", {})
    if isinstance(hooks, Mapping):
        hook_records = []
        for value in hooks.values():
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                hook_records.extend(value)
        if hook_records:
            findings.append(_finding("oci-lifecycle-hooks", "high",
                                     "OCI configuration registers host-executed lifecycle hooks", "high",
                                     hooks=len(hook_records)))
    namespaces = {str(item.get("type")): item.get("path") for item in linux.get("namespaces", [])
                  if isinstance(item, Mapping)} if isinstance(linux.get("namespaces", []), Sequence) else {}
    for namespace in ("pid", "network", "ipc", "mount", "user"):
        if namespace not in namespaces:
            severity = "critical" if namespace in {"mount", "user"} else "high"
            findings.append(_finding("oci-host-namespace", severity,
                                     "OCI config omits an isolating namespace", "high", namespace=namespace))
        elif namespaces[namespace]:
            findings.append(_finding("oci-joined-namespace", "high",
                                     "OCI config joins an existing namespace path", "high",
                                     namespace=namespace, path=namespaces[namespace]))
    capabilities = process.get("capabilities", {})
    capabilities = capabilities if isinstance(capabilities, Mapping) else {}
    raw_effective = capabilities.get("effective", [])
    effective = ({str(value).upper() for value in raw_effective}
                 if isinstance(raw_effective, Sequence) and not isinstance(raw_effective, (str, bytes)) else set())
    dangerous = sorted(effective & _DANGEROUS_CAPABILITIES)
    if dangerous:
        findings.append(_finding("oci-dangerous-capabilities", "critical",
                                 "OCI effective set includes escape-relevant capabilities", "high",
                                 capabilities=dangerous))
    if process.get("noNewPrivileges") is not True:
        findings.append(_finding("oci-no-new-privileges-disabled", "high",
                                 "OCI process may gain privileges through exec transitions"))
    user = process.get("user", {})
    root_user = str(user.get("uid", 0)) == "0" if isinstance(user, Mapping) else True
    if root_user:
        findings.append(_finding("oci-root-user", "medium", "OCI process runs as or defaults to UID 0"))
    seccomp = linux.get("seccomp")
    if not isinstance(seccomp, Mapping):
        findings.append(_finding("oci-no-seccomp", "high", "OCI config has no seccomp policy"))
    elif str(seccomp.get("defaultAction", "")).upper() in {"SCMP_ACT_ALLOW", "ALLOW"}:
        findings.append(_finding("oci-seccomp-default-allow", "high",
                                 "OCI seccomp policy defaults to allowing syscalls", "high"))
    devices = linux.get("devices", [])
    safe_devices = {"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty"}
    risky_devices = [item for item in devices if isinstance(item, Mapping)
                     and str(item.get("path", "")) not in safe_devices] \
        if isinstance(devices, Sequence) and not isinstance(devices, (str, bytes)) else []
    if risky_devices:
        findings.append(_finding("oci-host-devices", "high", "OCI config exposes nonstandard host devices",
                                 "high", devices=len(risky_devices),
                                 paths=[item.get("path") for item in risky_devices]))
    resources = linux.get("resources", {})
    resources = resources if isinstance(resources, Mapping) else {}
    device_rules = resources.get("devices", [])
    if isinstance(device_rules, Sequence) and not isinstance(device_rules, (str, bytes)):
        broad_rules = [rule for rule in device_rules if isinstance(rule, Mapping) and rule.get("allow") is True
                       and (rule.get("major") in (None, -1) or rule.get("minor") in (None, -1))]
        if broad_rules:
            findings.append(_finding("oci-broad-device-allow", "high",
                                     "OCI cgroup device rules broadly allow host devices", "high",
                                     rules=len(broad_rules)))
    propagation = str(linux.get("rootfsPropagation", "private")).lower()
    if propagation in {"shared", "rshared", "slave", "rslave"}:
        findings.append(_finding("oci-shared-mount-propagation", "high",
                                 "OCI root mount propagation can expose host/container mount changes",
                                 "high", propagation=propagation))
    mounts = []
    for mount in config.get("mounts", []) if isinstance(config.get("mounts", []), Sequence) else []:
        if not isinstance(mount, Mapping):
            continue
        source, destination = str(mount.get("source", "")), str(mount.get("destination", ""))
        raw_options = mount.get("options", [])
        options = ({str(value) for value in raw_options}
                   if isinstance(raw_options, Sequence) and not isinstance(raw_options, (str, bytes)) else set())
        mounts.append({"source": source, "destination": destination, "options": sorted(options)})
        sensitive = source in _SENSITIVE_HOST_PATHS or source.startswith(("/proc", "/sys", "/dev", "/var/run", "/run"))
        if sensitive and "ro" not in options:
            findings.append(_finding("oci-writable-sensitive-mount", "critical",
                                     "sensitive host path is mounted writable", "high",
                                     path=source, destination=destination))
        if source.endswith(("docker.sock", "containerd.sock", "crio.sock")):
            findings.append(_finding("oci-runtime-socket", "critical",
                                     "OCI mount exposes a container runtime socket", "high", path=source))
    return {"kind": "oci-runtime-analysis", "namespaces": namespaces, "mounts": mounts,
            "findings": _sort(findings)}


def analyze_runtime_snapshot(files: Mapping[str, bytes | str]) -> dict:
    """Analyze caller-supplied proc/cgroup/mount snapshots; no local paths are read."""
    if not isinstance(files, Mapping):
        raise ValueError("runtime snapshot must be a mapping of path to content")
    normalized = {}
    for path, value in files.items():
        if isinstance(value, bytes):
            normalized[str(path)] = value
        elif isinstance(value, str):
            normalized[str(path)] = value.encode()
        else:
            raise ValueError("snapshot content must be bytes or text")
    findings, evidence = [], {}
    status = normalized.get("/proc/self/status", normalized.get("proc/self/status", b"")).decode("utf-8", "replace")
    cap_match = re.search(r"(?m)^CapEff:\s*([0-9a-fA-F]+)", status)
    if cap_match:
        bits = int(cap_match.group(1), 16)
        caps = [name for index, name in enumerate(_CAP_NAMES) if bits & (1 << index)]
        evidence["effective_capabilities"] = caps
        dangerous = sorted({"CAP_" + name for name in caps} & _DANGEROUS_CAPABILITIES)
        if dangerous:
            findings.append(_finding("snapshot-dangerous-capabilities", "critical",
                                     "runtime snapshot has escape-relevant effective capabilities", "high",
                                     capabilities=dangerous))
    mounts = normalized.get("/proc/self/mountinfo", normalized.get("proc/self/mountinfo", b"")).decode("utf-8", "replace")
    evidence["mount_lines"] = len(mounts.splitlines())
    for line in mounts.splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            continue
        mount_point = fields[4].replace("\\040", " ")
        options = set(fields[5].split(","))
        separator = fields.index("-")
        source = fields[separator + 2] if separator + 2 < len(fields) else ""
        if mount_point in {"/sys/fs/cgroup", "/proc", "/sys"} and "rw" in options:
            findings.append(_finding("snapshot-writable-kernel-filesystem", "high",
                                     "kernel control filesystem is writable", "high",
                                     path=mount_point, source=source))
        if source.endswith(("docker.sock", "containerd.sock", "crio.sock")) or mount_point.endswith(
                ("docker.sock", "containerd.sock", "crio.sock")):
            findings.append(_finding("snapshot-runtime-socket", "critical",
                                     "runtime socket is visible in supplied mount snapshot", "high",
                                     path=mount_point, source=source))
    cgroup = normalized.get("/proc/1/cgroup", normalized.get("proc/1/cgroup", b"")).decode("utf-8", "replace")
    evidence["cgroup"] = cgroup.strip().splitlines()
    for path in normalized:
        if path.endswith(("docker.sock", "containerd.sock", "crio.sock")):
            findings.append(_finding("snapshot-runtime-socket", "critical",
                                     "supplied snapshot includes a runtime socket path", "high", path=path))
        if path.endswith(("/release_agent", "/notify_on_release")):
            findings.append(_finding("snapshot-cgroup-v1-release-agent", "high",
                                     "supplied snapshot includes cgroup-v1 release-agent controls", path=path))
    return {"kind": "runtime-snapshot-analysis", "files": sorted(normalized),
            "evidence": evidence, "findings": _sort(findings)}


def _suspicious_environment(environment: object, function: str, findings: list[dict]) -> None:
    if not isinstance(environment, Mapping):
        return
    variables = environment.get("Variables", environment.get("variables", environment))
    if not isinstance(variables, Mapping):
        return
    for key, value in variables.items():
        if _SECRET_NAME.search(str(key)) and value not in (None, "", "REDACTED", "***"):
            dynamic = isinstance(value, Mapping) or bool(re.search(
                r"\$\{|\{\{|resolve:|(?:keyvault|secretsmanager|secretmanager|parameterstore)(?::|/)",
                str(value), re.I,
            ))
            if not dynamic:
                findings.append(_finding("plaintext-serverless-secret", "high",
                                         "secret-like environment variable contains a literal value", "high",
                                         function=function, variable=str(key)))


def _policy_findings(policy: object, function: str, findings: list[dict]) -> None:
    policies = policy if isinstance(policy, Sequence) and not isinstance(policy, (str, bytes)) else [policy]
    for item in policies:
        if not isinstance(item, Mapping):
            continue
        document = item.get("PolicyDocument", item)
        if not isinstance(document, Mapping):
            continue
        statements = document.get("Statement", document.get("statement", []))
        statements = statements if isinstance(statements, Sequence) and not isinstance(statements, (str, bytes)) else [statements]
        for statement in statements:
            if not isinstance(statement, Mapping) or str(statement.get("Effect", "Allow")).lower() != "allow":
                continue
            actions = statement.get("Action", statement.get("action", []))
            resources = statement.get("Resource", statement.get("resource", []))
            actions = [actions] if isinstance(actions, str) else list(actions) if isinstance(actions, (list, tuple)) else []
            resources = [resources] if isinstance(resources, str) else list(resources) if isinstance(resources, (list, tuple)) else []
            if "*" in actions or any(str(value).endswith(":*") for value in actions):
                findings.append(_finding("serverless-wildcard-actions", "high",
                                         "function role permits wildcard actions", "high",
                                         function=function, actions=actions))
            if "*" in resources and any(re.search(r"(?:Put|Create|Update|Delete|Invoke|PassRole|AssumeRole|\*)", str(action), re.I)
                                        for action in actions):
                findings.append(_finding("serverless-wildcard-resource", "high",
                                         "mutating function permissions apply to every resource", "high",
                                         function=function, actions=actions))


def analyze_serverless_config(document: Mapping[str, object]) -> dict:
    """Audit supplied AWS/SAM/Serverless, Azure Functions, or GCP function config."""
    if not isinstance(document, Mapping):
        raise ValueError("serverless config must be a mapping")
    findings, functions, graph = [], [], []
    resources = document.get("Resources", {})
    if isinstance(resources, Mapping):
        for logical_id, resource in resources.items():
            if not isinstance(resource, Mapping):
                continue
            resource_type = str(resource.get("Type", ""))
            props = resource.get("Properties", {})
            props = props if isinstance(props, Mapping) else {}
            if resource_type in {"AWS::Lambda::Function", "AWS::Serverless::Function"}:
                name = str(logical_id)
                functions.append({"name": name, "provider": "aws", "runtime": props.get("Runtime"),
                                  "handler": props.get("Handler"), "role": props.get("Role")})
                _suspicious_environment(props.get("Environment", {}), name, findings)
                _policy_findings(props.get("Policies", []), name, findings)
                url_config = props.get("FunctionUrlConfig", {})
                if (isinstance(url_config, Mapping)
                        and str(url_config.get("AuthType", "")).upper() == "NONE"):
                    findings.append(_finding("public-lambda-url", "critical",
                                             "function URL configuration explicitly disables authentication",
                                             "high", function=name))
                if props.get("Role"):
                    graph.append({"from": name, "to": str(props["Role"]), "relation": "assumes-role"})
                events = props.get("Events", {})
                if isinstance(events, Mapping):
                    for event_name, event in events.items():
                        event = event if isinstance(event, Mapping) else {}
                        event_type = str(event.get("Type", ""))
                        event_props = event.get("Properties", {})
                        event_props = event_props if isinstance(event_props, Mapping) else {}
                        graph.append({"from": f"event:{event_name}", "to": name, "relation": event_type})
                        auth = event_props.get("Auth")
                        auth_authorizer = auth.get("Authorizer") if isinstance(auth, Mapping) else auth
                        direct_authorizer = event_props.get("Authorizer")
                        scopes = event_props.get("AuthorizationScopes")
                        api_key = event_props.get("ApiKeyRequired") is True
                        authorized = (api_key or bool(scopes)
                                      or str(auth_authorizer or "").upper() not in {"", "NONE", "NULL"}
                                      or str(direct_authorizer or "").upper() not in {"", "NONE", "NULL"})
                        if event_type.lower() in {"api", "httpapi"} and not authorized:
                            findings.append(_finding("unauthenticated-function-event", "high",
                                                     "HTTP function event has no evident authorizer",
                                                     function=name, event=event_name))
                if props.get("VpcConfig") in (None, {}):
                    findings.append(_finding("function-outside-vpc", "info",
                                             "function has no supplied VPC isolation configuration",
                                             function=name))
            elif resource_type == "AWS::Lambda::Url":
                target = str(props.get("TargetFunctionArn", logical_id))
                if str(props.get("AuthType", "")).upper() == "NONE":
                    findings.append(_finding("public-lambda-url", "critical",
                                             "Lambda function URL explicitly disables authentication", "high",
                                             function=target))
                graph.append({"from": f"url:{logical_id}", "to": target, "relation": "invokes"})
            elif resource_type == "AWS::Lambda::Permission":
                principal = props.get("Principal")
                action = str(props.get("Action", ""))
                if principal == "*" and "InvokeFunction" in action:
                    findings.append(_finding("public-lambda-permission", "critical",
                                             "Lambda invocation permission grants every principal", "high",
                                             function=props.get("FunctionName", logical_id)))
            elif resource_type in {"AWS::IAM::Role", "AWS::IAM::Policy"}:
                _policy_findings(props.get("Policies", props.get("PolicyDocument", [])), str(logical_id), findings)

    # Serverless Framework shape.
    raw_functions = document.get("functions", {})
    if isinstance(raw_functions, Mapping):
        for name, config in raw_functions.items():
            config = config if isinstance(config, Mapping) else {"handler": config}
            functions.append({"name": str(name), "provider": document.get("provider", {}).get("name", "serverless")
                              if isinstance(document.get("provider", {}), Mapping) else "serverless",
                              "runtime": config.get("runtime"), "handler": config.get("handler")})
            _suspicious_environment(config.get("environment", {}), str(name), findings)
            for index, event in enumerate(config.get("events", []) if isinstance(config.get("events", []), Sequence) else []):
                if not isinstance(event, Mapping):
                    continue
                graph.append({"from": f"event:{name}:{index}", "to": str(name),
                              "relation": next(iter(event), "event")})
                http = event.get("http", event.get("httpApi"))
                authenticated = False
                if isinstance(http, Mapping):
                    authorizer = http.get("authorizer")
                    authenticated = (http.get("private") is True or bool(http.get("authorizationScopes"))
                                     or str(authorizer or "").lower() not in {"", "none", "null"})
                if http is not None and not authenticated:
                    findings.append(_finding("unauthenticated-function-event", "high",
                                             "HTTP event has no evident authorizer", function=str(name)))
    provider = document.get("provider", {})
    if isinstance(provider, Mapping):
        iam = provider.get("iam", {})
        nested_statements = []
        if isinstance(iam, Mapping):
            role = iam.get("role", {})
            if isinstance(role, Mapping):
                nested_statements = role.get("statements", [])
        _policy_findings(provider.get("iamRoleStatements", nested_statements), "provider-default", findings)
        _suspicious_environment(provider.get("environment", {}), "provider-default", findings)

    # Azure function.json/local.settings.json shape.
    bindings = document.get("bindings", [])
    binding_items = (list(bindings) if isinstance(bindings, Sequence)
                     and not isinstance(bindings, (str, bytes)) else [])
    azure_bindings = [item for item in binding_items
                      if isinstance(item, Mapping) and "type" in item]
    if azure_bindings:
        function_name = str(document.get("name", "azure-function"))
        functions.append({"name": function_name, "provider": "azure", "runtime": None,
                          "handler": document.get("scriptFile")})
        for binding in azure_bindings:
            if str(binding.get("type", "")).lower() == "httptrigger" and str(binding.get("authLevel", "function")).lower() == "anonymous":
                findings.append(_finding("anonymous-azure-function", "critical",
                                         "HTTP trigger allows anonymous invocation", "high",
                                         function=function_name))
            graph.append({"from": f"binding:{binding.get('type')}", "to": function_name,
                          "relation": str(binding.get("direction", "trigger"))})
    values = document.get("Values", {})
    if isinstance(values, Mapping):
        _suspicious_environment(values, "azure-local-settings", findings)

    # GCP export/deployment shapes.
    invokers = document.get("invokers", document.get("iam", []))
    if isinstance(invokers, Sequence) and not isinstance(invokers, (str, bytes)):
        if any(str(value) in {"allUsers", "allAuthenticatedUsers"} for value in invokers):
            findings.append(_finding("public-gcp-function", "critical",
                                     "function grants invocation to a public principal", "high",
                                     function=document.get("name", document.get("entryPoint"))))
    for binding in binding_items:
        if not isinstance(binding, Mapping) or "members" not in binding:
            continue
        members = binding.get("members", [])
        if (isinstance(members, Sequence) and not isinstance(members, (str, bytes))
                and any(str(member) in {"allUsers", "allAuthenticatedUsers"} for member in members)):
            findings.append(_finding("public-gcp-function", "critical",
                                     "IAM binding grants a role to a public principal", "high",
                                     function=document.get("name", document.get("entryPoint")),
                                     role=binding.get("role")))
    _suspicious_environment(document.get("environmentVariables", {}),
                            str(document.get("name", document.get("entryPoint", "gcp-function"))), findings)
    return {"kind": "serverless-config-analysis", "functions": functions, "graph": graph,
            "findings": _sort(findings)}


def inspect_serverless_zip(data: bytes) -> dict:
    """Inventory a supplied function archive in memory without extracting it."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("archive input must be bytes")
    if len(data) > MAX_INPUT:
        raise ValueError("archive exceeds compressed input cap")
    findings, members = [], []
    total = 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError) as error:
        raise ValueError("invalid function ZIP archive") from error
    infos = archive.infolist()
    if len(infos) > MAX_ARCHIVE_MEMBERS:
        raise ValueError("archive member count exceeds cap")
    for info in infos:
        total += info.file_size
        if total > MAX_ARCHIVE_EXPANDED:
            raise ValueError("archive expanded-size cap exceeded")
        path = PurePosixPath(info.filename.replace("\\", "/"))
        traversal = path.is_absolute() or ".." in path.parts
        mode = info.external_attr >> 16
        symlink = stat.S_ISLNK(mode)
        members.append({"path": info.filename, "size": info.file_size, "compressed": info.compress_size,
                        "traversal": traversal, "symlink": symlink})
        if traversal:
            findings.append(_finding("archive-path-traversal", "high",
                                     "function archive member escapes an extraction root", "high",
                                     path=info.filename))
        if symlink:
            findings.append(_finding("archive-symlink", "medium",
                                     "function archive contains a symbolic link", "high", path=info.filename))
        lower = info.filename.lower()
        if lower.endswith((".so", ".dll", ".dylib", ".node")):
            findings.append(_finding("serverless-native-binary", "medium",
                                     "function package contains a native binary requiring sandboxed review",
                                     path=info.filename))
        basename = PurePosixPath(lower).name
        secret_filename = (_SECRET_NAME.search(basename) or basename == ".env"
                           or basename.endswith(".env"))
        if secret_filename and lower.endswith(
                (".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".pem", ".key", ".p12")):
            findings.append(_finding("secret-like-package-file", "high",
                                     "function package contains a secret-like configuration file",
                                     path=info.filename))
        if not info.is_dir() and info.file_size <= MAX_MEMBER_SCAN and not symlink:
            try:
                content = archive.read(info)
            except (RuntimeError, OSError, zipfile.BadZipFile, zlib.error):
                continue
            if _SECRET_VALUE.search(content):
                findings.append(_finding("embedded-function-secret", "critical",
                                         "function package contains secret-like literal material",
                                         path=info.filename))
    return {"kind": "serverless-zip-analysis", "compressed_size": len(data),
            "expanded_size": total, "members": members, "findings": _sort(findings)}


def analyze_artifact(data: bytes, name: str = "artifact") -> dict:
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("artifact must be bytes")
    if zipfile.is_zipfile(io.BytesIO(data)):
        return inspect_serverless_zip(data)
    if len(data) > MAX_INPUT:
        raise ValueError("artifact exceeds input cap")
    try:
        parsed = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("runtime artifact must be JSON or ZIP") from error
    if isinstance(parsed, Sequence) and not isinstance(parsed, (str, bytes)):
        if all(isinstance(item, Mapping) for item in parsed):
            return analyze_container_workload(parsed)
        raise ValueError("runtime JSON array must contain workload objects")
    if not isinstance(parsed, Mapping):
        raise ValueError("runtime JSON must be an object")
    if "ociVersion" in parsed or ("linux" in parsed and "process" in parsed):
        return analyze_oci_runtime_config(parsed)
    if "kind" in parsed and ("spec" in parsed or str(parsed.get("kind", "")).lower() == "list"):
        return analyze_container_workload(parsed)
    if any(key in parsed for key in ("Resources", "functions", "bindings", "Values", "environmentVariables")):
        return analyze_serverless_config(parsed)
    if all(isinstance(value, (str, bytes)) for value in parsed.values()):
        return analyze_runtime_snapshot(parsed)
    raise ValueError("unrecognized cloud runtime artifact")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="supplied JSON or function ZIP")
    args = parser.parse_args(argv)
    print(json.dumps(analyze_artifact(args.artifact.read_bytes(), args.artifact.name),
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
