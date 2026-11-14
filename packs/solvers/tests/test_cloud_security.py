"""Synthetic offline cloud, Kubernetes, metadata-plan, and OCI risk fixtures."""
from __future__ import annotations

import io
import json
import sys
import tarfile
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import cloud_security as security  # noqa: E402


def _tar(members: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, body in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(body))
    return stream.getvalue()


def test_iam_wildcards_trust_and_escalation_combinations():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Broad", "Effect": "Allow",
             "Action": ["iam:PassRole", "lambda:CreateFunction"], "Resource": "*"},
            {"Sid": "Trust", "Effect": "Allow", "Action": "sts:AssumeRole",
             "Principal": {"AWS": "*"}},
            {"Sid": "EverythingElse", "Effect": "Allow", "NotAction": "billing:*", "Resource": "*"},
        ],
    }
    findings = security.analyze_iam_policy(policy)
    kinds = {item["kind"] for item in findings}
    assert "iam-notaction-allow" in kinds
    assert "iam-public-trust" in kinds
    assert "iam-escalation-chain" in kinds
    assert "iam-wildcard-resource" in kinds
    assert findings[0]["score"] == 100


def test_k8s_rbac_and_workload_risks():
    objects = [
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
         "metadata": {"name": "danger"},
         "rules": [{"apiGroups": ["*"], "resources": ["secrets", "pods/exec"],
                    "verbs": ["*", "escalate"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
         "metadata": {"name": "public-admin"}, "roleRef": {"name": "cluster-admin"},
         "subjects": [{"kind": "Group", "name": "system:unauthenticated"}]},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "app"},
         "spec": {"template": {"spec": {"hostNetwork": True,
            "volumes": [{"name": "root", "hostPath": {"path": "/"}}],
            "containers": [{"name": "app", "image": "ctf/app",
                            "securityContext": {"privileged": True,
                                                "capabilities": {"add": ["SYS_ADMIN"]}}}]}}}},
    ]
    findings = security.analyze_k8s(objects)
    kinds = {item["kind"] for item in findings}
    assert {"k8s-rbac-wildcard", "k8s-rbac-escalation", "k8s-secret-access",
            "k8s-pod-exec", "k8s-cluster-admin-binding", "k8s-anonymous-binding",
            "k8s-host-network", "k8s-hostpath", "k8s-privileged", "k8s-capabilities"} <= kinds


def test_metadata_chains_include_required_headers_and_never_send():
    aws = security.metadata_chain("aws", role="ChallengeRole")
    assert aws[0]["method"] == "PUT"
    assert "X-aws-ec2-metadata-token-ttl-seconds" in aws[0]["headers"]
    assert aws[2]["url"].endswith("/ChallengeRole")

    gcp = security.metadata_chain("gcp")
    assert all(item["headers"].get("Metadata-Flavor") == "Google" for item in gcp)
    azure = security.metadata_chain("azure")
    assert azure[0]["headers"] == {"Metadata": "true"}


def test_deleted_oci_layer_and_environment_secrets_are_reported():
    layer1 = _tar({"app/config": b"password=synthetic-layer-secret\n"})
    layer2 = _tar({"app/.wh.config": b""})
    config = {
        "config": {"Env": ["API_TOKEN=synthetic-env-secret"]},
        "rootfs": {"diff_ids": ["sha256:" + "1" * 64, "sha256:" + "2" * 64]},
        "history": [{"created_by": "COPY config /app/config"}, {"created_by": "RUN rm /app/config"}],
    }
    store = {
        "manifest.json": json.dumps([{"Config": "config.json", "RepoTags": ["ctf:test"],
                                       "Layers": ["l1/layer.tar", "l2/layer.tar"]}]).encode(),
        "config.json": json.dumps(config).encode(),
        "l1/layer.tar": layer1,
        "l2/layer.tar": layer2,
    }
    images = security.cloud.read_image(store, "fixture")
    findings = security.scan_images(images)
    assert any(item["kind"] == "container-env-secret" and item["name"] == "API_TOKEN"
               for item in findings)
    deleted = next(item for item in findings if item["kind"] == "container-secret")
    assert deleted["source"] == "app/config"
    assert deleted["deleted"] is True
    assert deleted["value"] == "synthetic-layer-secret"


def test_cloudformation_and_terraform_shaped_exposures():
    document = {
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "PublicRead"}},
            "SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {"SecurityGroupIngress": [
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}
            ]}},
            "Role": {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": "*"}]
            }}},
        },
        "resource_changes": [{"change": {"after": {"publicly_accessible": True,
                                                       "client_secret": "synthetic-iac-secret"}}}],
    }
    findings = security.analyze_iac(document)
    kinds = {item["kind"] for item in findings}
    assert "iac-public-bucket" in kinds
    assert "iac-world-ingress" in kinds
    assert "iam-public-trust" in kinds
    assert "iac-public-resource" in kinds
    assert any(item["kind"] == "iac-secret" and item["value"] == "synthetic-iac-secret"
               for item in findings)


def test_guarded_cli_json_and_garbage(tmp_path, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}),
                      encoding="utf-8")
    assert security.main(["iam", str(policy), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["candidates"]

    garbage = tmp_path / "bad"
    garbage.write_bytes(b"{not-json")
    assert security.main(["iam", str(garbage)]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("cloud_security: ")
    assert "Traceback" not in captured.err


def test_oci_cli_alias_is_guarded(tmp_path, capsys):
    bad_image = tmp_path / "not-oci.bin"
    bad_image.write_bytes(b"not an image")
    rc = security.main(["oci", str(bad_image), "--json"])
    assert rc in (0, 2)
    assert "Traceback" not in capsys.readouterr().err


def test_recursive_k8s_list_is_bounded():
    recursive = {"kind": "SyntheticList"}
    recursive["items"] = [recursive]
    assert security.analyze_k8s(recursive) == []

