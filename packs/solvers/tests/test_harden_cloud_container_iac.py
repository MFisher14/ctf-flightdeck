"""Independent OCI layer/descriptor and Kubernetes/CloudFormation/HCL vectors.

Oracles: OCI image-spec layer.md and descriptor.md, Kubernetes Secret docs,
stdlib tarfile/gzip/hashlib (fixture generation only). No container is started.
"""
import base64
import gzip
import hashlib
import io
import json
import random
import tarfile

import pytest

import container_iac as engine


def tar(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in entries.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(body), 0o640, 0
            archive.addfile(info, io.BytesIO(body))
    return out.getvalue()


def js(value):
    return json.dumps(value, sort_keys=True).encode()


CONFIG = {"architecture": "amd64", "os": "linux", "config": {"Env": ["TOKEN=fixture-secret", "PATH=/bin"]},
          "history": [{"created_by": "ENV password=history-secret"}]}


def docker(layers, manifest=None):
    entries = {"config.json": js(CONFIG)}
    entries.update({f"layer{i}.tar": value for i, value in enumerate(layers)})
    entries["manifest.json"] = js(manifest if manifest is not None else [{"Config": "config.json", "Layers": list(entries)[1:]}])
    return tar(entries)


def oci(layers):
    entries = {"oci-layout": js({"imageLayoutVersion": "1.0.0"})}
    def blob(body, kind):
        digest = hashlib.sha256(body).hexdigest()
        entries[f"blobs/sha256/{digest}"] = body
        return {"mediaType": kind, "digest": f"sha256:{digest}", "size": len(body)}
    config = blob(js(CONFIG), "application/vnd.oci.image.config.v1+json")
    descriptors = [blob(body, "application/vnd.oci.image.layer.v1.tar+gzip") for body in layers]
    manifest = blob(js({"schemaVersion": 2, "config": config, "layers": descriptors}), "application/vnd.oci.image.manifest.v1+json")
    entries["index.json"] = js({"schemaVersion": 2, "manifests": [manifest]})
    return tar(entries)


@pytest.mark.parametrize("kind", ["docker", "oci"])
def test_whiteouts_overwrites_digests_and_recovered_secrets(kind):
    first = tar({"etc/token": b"password=old-secret", "cache/old": b"old", "cache/nested/x": b"x", "keep": b"before"})
    second = tar({"etc/.wh.token": b"", "cache/.wh..wh..opq": b"", "cache/new": b"new", "keep": b"after"})
    layers = [first, second] if kind == "docker" else [gzip.compress(x, mtime=0) for x in [first, second]]
    result = engine.analyze_image_archive(docker(layers) if kind == "docker" else oci(layers))
    assert result.format == {"docker": "docker-save", "oci": "oci-layout"}[kind]
    assert {p: v.content for p, v in result.files.items()} == {"cache/new": b"new", "keep": b"after"}
    assert {v.path: (v.content, v.reason) for v in result.recovered} == {
        "etc/token": (b"password=old-secret", "whiteout@layer-1"),
        "cache/old": (b"old", "opaque-whiteout@layer-1"),
        "cache/nested/x": (b"x", "opaque-whiteout@layer-1"),
        "keep": (b"before", "overwritten@layer-1")}
    assert [x["digest"] for x in result.layers] == ["sha256:" + hashlib.sha256(x).hexdigest() for x in layers]
    report = result.report()
    assert report["layer_count"] == 2 and report["final_file_count"] == 2
    assert report["config"] == {"architecture": "amd64", "os": "linux", "environment_names": ["PATH", "TOKEN"], "history_entries": 1}
    assert any(f.get("recovered") and f.get("value") == "old-secret" for f in report["findings"])
    assert any(f["kind"] == "config-env-secret" and f["value"] == "fixture-secret" for f in report["findings"])
    assert result.files["keep"].metadata()["sha256"] == hashlib.sha256(b"after").hexdigest()


def test_oci_digest_mismatch_is_rejected():
    raw = oci([gzip.compress(tar({"a": b"known"}), mtime=0)])
    # Change body while keeping its content-addressed path and descriptor intact.
    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
        entries = {m.name: tf.extractfile(m).read() for m in tf}
    path = next(p for p, value in entries.items() if value == js(CONFIG))
    entries[path] += b" "
    with pytest.raises(ValueError, match="digest mismatch"):
        engine.analyze_image_archive(tar(entries))


def test_kubernetes_secret_and_privileged_pod_exact_findings():
    docs = [{"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "creds", "namespace": "lab"},
             "data": {"password": base64.b64encode(b"CSCTF{offline_fixture}").decode()}},
            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "test"}, "spec": {
                "hostPID": True, "automountServiceAccountToken": False,
                "volumes": [{"hostPath": {"path": "/"}}], "containers": [{"name": "worker",
                "securityContext": {"privileged": True, "allowPrivilegeEscalation": False},
                "env": [{"name": "API_TOKEN", "value": "fixture"}]}]}}]
    direct = engine.analyze_k8s_manifests(docs)
    assert {f["kind"] for f in direct} == {"k8s-secret-in-manifest", "k8s-host-namespace", "k8s-hostpath", "k8s-privileged-container", "k8s-env-secret"}
    secret = next(f for f in direct if f["kind"] == "k8s-secret-in-manifest")
    assert (secret["object"], secret["value"], secret["encoding"]) == ("Secret/lab/creds", "CSCTF{offline_fixture}", "base64")
    result = engine.analyze_iac_artifact(js(docs), "pods.json")
    assert result["formats"] == ["kubernetes"] and result["document_count"] == 2
    yaml = b"apiVersion: v1\nkind: Secret\nmetadata: {name: creds}\nstringData: {password: fixture-secret}\n"
    assert engine.analyze_iac_artifact(yaml)["findings"][0]["value"] == "fixture-secret"


def test_cloudformation_and_terraform_documented_fields():
    cfn = {"Parameters": {"Password": {"Default": "example"}}, "Resources": {
        "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "PublicRead"}},
        "SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {"SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0", "FromPort": 22, "ToPort": 22, "IpProtocol": "tcp"}]}}}}
    facts = engine.analyze_cloudformation(cfn)
    assert {f["kind"] for f in facts} == {"cfn-sensitive-parameter-visible", "cfn-sensitive-default", "cfn-public-bucket", "cfn-world-open-ingress"}
    assert next(f for f in facts if f["kind"] == "cfn-world-open-ingress")["from_port"] == 22
    hcl = '# token = "ignore"\nprovider "aws" {\n token = "known-token"\n}\nresource "aws_s3_bucket" "x" {\n acl = "public-read"\n}\n'
    found = engine.analyze_terraform_text(hcl)
    assert [(f["kind"], f["line"]) for f in found] == [("terraform-provider-credential", 3), ("terraform-public-acl", 6)]
    plan = {"terraform_version": "1.9.0", "resource_changes": [{"address": "example.x", "change": {"after": {"password": "known-secret"}}}]}
    assert any(f["source"] == "example.x" and f["value"] == "known-secret" for f in engine.analyze_terraform_json(plan))


def clean(call):
    try:
        call()
    except Exception as exc:
        assert type(exc) is ValueError, f"leaked {type(exc).__name__}: {exc}"


def test_image_deterministic_byte_fuzz():
    valid = docker([tar({"a": b"abc"})])
    rng = random.Random(610)
    cases = [b"", b"\xff" * 4096, rng.randbytes(4096), valid[:10], valid[:511]]
    for offset in [0, 1, 257, 300]:
        value = bytearray(valid); value[offset] ^= 0x80; cases.append(bytes(value))
    for raw in cases:
        clean(lambda: engine.analyze_image_archive(raw))


@pytest.mark.parametrize("cap,value", [("MAX_ARCHIVE", 32), ("MAX_MEMBER", 32), ("MAX_TOTAL", 32), ("MAX_MEMBERS", 1)])
def test_image_archive_caps(monkeypatch, cap, value):
    raw = docker([tar({"one": b"x" * 64, "two": b"y" * 64})])
    monkeypatch.setattr(engine, cap, value)
    with pytest.raises(ValueError):
        engine.analyze_image_archive(raw)


def test_compressed_layer_expansion_cap(monkeypatch):
    raw = docker([gzip.compress(tar({"large": b"A" * 100_000}), mtime=0)])
    assert len(raw) < 32768
    monkeypatch.setattr(engine, "MAX_ARCHIVE", 32768)
    with pytest.raises(ValueError, match="expanded cap"):
        engine.analyze_image_archive(raw)


def test_iac_size_and_finding_caps(monkeypatch):
    monkeypatch.setattr(engine, "MAX_MEMBER", 32)
    with pytest.raises(ValueError):
        engine.analyze_iac_artifact(b"x" * 33)
    monkeypatch.setattr(engine, "MAX_MEMBER", 4096)
    monkeypatch.setattr(engine, "MAX_FINDINGS", 2)
    assert len(engine.analyze_iac_artifact(js({"password": "aaaaaa", "token": "bbbbbb", "secret": "cccccc"}))["findings"]) == 2


def test_utf8_iac_truncation_mutation_and_nested_values():
    seed = b'{"apiVersion":"v1","kind":"Secret","metadata":{"name":"x"},"stringData":{"password":"fixture"}}'
    samples = [b"", b"{}", b"[]", b"null", b"x" * 8192]
    samples += [seed[:end] for end in range(0, len(seed), 7)]
    for offset in range(0, len(seed), 11):
        changed = bytearray(seed); changed[offset] ^= 1; samples.append(bytes(changed))
    for raw in samples:
        clean(lambda: engine.analyze_iac_artifact(raw))
    nested = {"password": "fixture"}
    for _ in range(100):
        nested = {"child": nested}
    assert engine.analyze_terraform_json(nested) == []  # bounded structured walk


def test_iac_non_utf8_fail_closed():
    clean(lambda: engine.analyze_iac_artifact(b"\xff"))


def test_docker_invalid_layers_fail_closed():
    clean(lambda: engine.analyze_image_archive(docker([], [{"Config": "config.json", "Layers": None}])))


def test_oci_invalid_descriptor_fail_closed():
    clean(lambda: engine.analyze_image_archive(tar({"index.json": js({"manifests": [None]})})))


@pytest.mark.parametrize("function,value", [(engine.analyze_cloudformation, None), (engine.analyze_terraform_json, {"resource_changes": [{"change": 1}]}), (engine.analyze_k8s_manifests, None), (engine.public_config, {"config": {"Env": None}})])
def test_structured_field_fail_closed(function, value):
    clean(lambda: function(value))


def test_truncated_tar_member_fail_closed():
    clean(lambda: engine.analyze_image_archive(tar({"manifest.json": b"x" * 1024})[:600]))


def test_cli_help_guard(capsys):
    assert engine.main(["--help"]) == 0
