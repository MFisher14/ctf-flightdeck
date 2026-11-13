import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import cloud_runtime_depth as cloud


def kinds(report):
    return {item["kind"] for item in report["findings"]}


def test_kubernetes_workload_finds_escape_primitives_and_runtime_socket():
    document = {
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "escape"},
        "spec": {"template": {"metadata": {"annotations": {
            "container.apparmor.security.beta.kubernetes.io/main": "unconfined"}}, "spec": {
            "hostPID": True, "hostNetwork": True, "hostIPC": True,
            "serviceAccountName": "builder",
            "volumes": [{"name": "root", "hostPath": {"path": "/"}},
                        {"name": "sock", "hostPath": {"path": "/var/run/docker.sock"}}],
            "containers": [{
                "name": "main", "image": "tool:latest",
                "securityContext": {"privileged": True, "runAsUser": 0,
                                    "capabilities": {"add": ["SYS_ADMIN", "NET_ADMIN"]},
                                    "seccompProfile": {"type": "Unconfined"}},
                "ports": [{"containerPort": 80, "hostPort": 8080}],
                "volumeMounts": [{"name": "root", "mountPath": "/host"},
                                 {"name": "sock", "mountPath": "/var/run/docker.sock"}],
            }],
        }}},
    }
    report = cloud.analyze_container_workload(document)
    assert {
        "host-pid-namespace", "host-network-namespace", "host-ipc-namespace",
        "service-account-token-mounted", "host-path-volume", "privileged-container",
        "privilege-escalation-allowed", "container-may-run-as-root",
        "writable-root-filesystem", "dangerous-linux-capability", "seccomp-unconfined",
        "host-port", "writable-host-path", "runtime-socket-mounted",
        "runtime-profile-unconfined",
    } <= kinds(report)
    assert report["workloads"][0]["name"] == "Deployment/escape"


def test_hardened_workload_avoids_escape_findings():
    document = {"kind": "Pod", "metadata": {"name": "safe"}, "spec": {
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 10001},
        "containers": [{"name": "app", "image": "app@sha256:" + "a" * 64,
                        "securityContext": {"allowPrivilegeEscalation": False,
                                            "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]},
                                            "seccompProfile": {"type": "RuntimeDefault"}}}],
    }}
    report = cloud.analyze_container_workload(document)
    assert report["findings"] == []


def test_oci_config_namespace_capability_seccomp_device_and_mount_depth():
    config = {
        "ociVersion": "1.1.0",
        "process": {"user": {"uid": 0}, "noNewPrivileges": False,
                    "capabilities": {"effective": ["CAP_SYS_ADMIN", "CAP_CHOWN"]}},
        "linux": {"namespaces": [{"type": "pid", "path": "/proc/1/ns/pid"}],
                  "seccomp": {"defaultAction": "SCMP_ACT_ALLOW"},
                  "devices": [{"path": "/dev/kvm"}]},
        "mounts": [{"source": "/sys", "destination": "/sys", "options": ["rw"]},
                   {"source": "/run/containerd/containerd.sock", "destination": "/run/socket",
                    "options": ["rw"]}],
    }
    report = cloud.analyze_oci_runtime_config(config)
    assert {
        "oci-host-namespace", "oci-joined-namespace", "oci-dangerous-capabilities",
        "oci-no-new-privileges-disabled", "oci-root-user", "oci-seccomp-default-allow",
        "oci-host-devices", "oci-writable-sensitive-mount", "oci-runtime-socket",
    } <= kinds(report)
    assert report["namespaces"] == {"pid": "/proc/1/ns/pid"}


def test_supplied_runtime_snapshot_decodes_caps_mounts_and_paths_only():
    cap_sys_admin = 1 << cloud._CAP_NAMES.index("SYS_ADMIN")
    files = {
        "/proc/self/status": f"Name:\ttest\nCapEff:\t{cap_sys_admin:016x}\n",
        "/proc/self/mountinfo": (
            "36 25 0:32 / /sys/fs/cgroup rw,nosuid,nodev - cgroup2 cgroup rw\n"
            "37 25 0:33 / /run/docker.sock rw - tmpfs /var/run/docker.sock rw\n"
        ),
        "/proc/1/cgroup": "0::/docker/demo\n",
        "/sys/fs/cgroup/release_agent": "",
    }
    report = cloud.analyze_runtime_snapshot(files)
    assert {"snapshot-dangerous-capabilities", "snapshot-writable-kernel-filesystem",
            "snapshot-runtime-socket", "snapshot-cgroup-v1-release-agent"} <= kinds(report)
    assert report["evidence"]["effective_capabilities"] == ["SYS_ADMIN"]
    assert report["files"] == sorted(files)


def test_aws_serverless_config_builds_graph_and_finds_public_paths_and_role_scope():
    document = {
        "Resources": {
            "Worker": {"Type": "AWS::Serverless::Function", "Properties": {
                "Runtime": "python3.13", "Handler": "app.handler", "Role": "WorkerRole",
                "Environment": {"Variables": {"DB_PASSWORD": "super-secret-value"}},
                "Policies": [{"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}],
                "Events": {"PublicApi": {"Type": "HttpApi", "Properties": {"Path": "/run"}}},
            }},
            "WorkerUrl": {"Type": "AWS::Lambda::Url", "Properties": {
                "TargetFunctionArn": "Worker", "AuthType": "NONE"}},
        }
    }
    report = cloud.analyze_serverless_config(document)
    assert {"plaintext-serverless-secret", "serverless-wildcard-actions",
            "serverless-wildcard-resource", "unauthenticated-function-event",
            "function-outside-vpc", "public-lambda-url"} <= kinds(report)
    assert {edge["relation"] for edge in report["graph"]} >= {"assumes-role", "HttpApi", "invokes"}


def test_azure_gcp_and_serverless_framework_public_triggers():
    azure = cloud.analyze_serverless_config({
        "name": "HttpFn", "scriptFile": "index.js",
        "bindings": [{"type": "httpTrigger", "direction": "in", "authLevel": "anonymous"}],
        "Values": {"API_TOKEN": "literal-secret-token"},
    })
    assert {"anonymous-azure-function", "plaintext-serverless-secret"} <= kinds(azure)
    gcp = cloud.analyze_serverless_config({
        "name": "gcpFn", "entryPoint": "run", "invokers": ["allUsers"],
        "environmentVariables": {"CLIENT_SECRET": "literal-value"},
    })
    assert {"public-gcp-function", "plaintext-serverless-secret"} <= kinds(gcp)
    framework = cloud.analyze_serverless_config({
        "provider": {"name": "aws"},
        "functions": {"hello": {"handler": "handler.run", "events": [{"http": {"path": "/"}}]}},
    })
    assert "unauthenticated-function-event" in kinds(framework)


def test_serverless_zip_inventory_is_in_memory_bounded_and_detects_secrets_native_and_traversal():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("handler.py", "def handler(event, context): return 1")
        archive.writestr("config.env", "API_KEY=abcdefghijklmnop")
        archive.writestr("lib/native.so", b"\x7fELF")
        archive.writestr("../escape.txt", "data")
    report = cloud.inspect_serverless_zip(buffer.getvalue())
    assert {"secret-like-package-file", "embedded-function-secret",
            "serverless-native-binary", "archive-path-traversal"} <= kinds(report)
    assert report["expanded_size"] == sum(member["size"] for member in report["members"])
    routed = cloud.analyze_artifact(buffer.getvalue(), "function.zip")
    assert routed["kind"] == "serverless-zip-analysis"
    with pytest.raises(ValueError, match="invalid"):
        cloud.inspect_serverless_zip(b"not-a-zip")


def test_artifact_routing_and_size_cap(monkeypatch):
    pod = {"kind": "Pod", "metadata": {"name": "x"}, "spec": {"containers": []}}
    assert cloud.analyze_artifact(json.dumps(pod).encode(), "pod.json")["kind"] == "container-workload-analysis"
    monkeypatch.setattr(cloud, "MAX_INPUT", 2)
    with pytest.raises(ValueError, match="cap"):
        cloud.analyze_artifact(b"{} ", "x.json")


def test_list_workloads_none_projected_sources_and_empty_zip_are_handled():
    listed = {"kind": "List", "items": [{"kind": "Pod", "metadata": {"name": "p"}, "spec": {
        "automountServiceAccountToken": False,
        "volumes": [{"name": "projection", "projected": {"sources": None}}],
        "containers": [{"name": "c", "securityContext": {
            "runAsNonRoot": True, "runAsUser": 1, "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True, "seccompProfile": {"type": "RuntimeDefault"},
            "capabilities": {"add": "SYS_ADMIN"},
        }}],
    }}]}
    report = cloud.analyze_artifact(json.dumps(listed).encode(), "list.json")
    assert report["workloads"][0]["name"] == "Pod/p"
    assert "dangerous-linux-capability" not in kinds(report)  # malformed scalar is not iterated as characters
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w"):
        pass
    assert cloud.analyze_artifact(buffer.getvalue(), "empty.zip")["kind"] == "serverless-zip-analysis"
