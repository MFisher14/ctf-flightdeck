import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import identity_graph as identity


def finding_kinds(report):
    return {item["kind"] for item in report["findings"]}


def test_aws_sts_path_conditions_group_policy_and_explicit_deny():
    user_arn = "arn:aws:iam::123456789012:user/alice"
    role_arn = "arn:aws:iam::123456789012:role/Admin"
    artifact = {
        "account_id": "123456789012",
        "groups": [{"name": "operators", "policies": [{"Statement": [{
            "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": role_arn}]}]}],
        "users": [{"name": "alice", "groups": ["operators"]},
                  {"name": "denied", "policies": [{"Statement": [
                      {"Effect": "Allow", "Action": "*", "Resource": "*"},
                      {"Effect": "Deny", "Action": "*", "Resource": "*"}]}]}],
        "roles": [{"name": "Admin", "trust": {"Statement": [{
            "Effect": "Allow", "Principal": {"AWS": user_arn}, "Action": "sts:AssumeRole",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]},
            "policies": [{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}]}],
    }
    report = identity.analyze_aws_identity(artifact, [user_arn])
    assert report["paths_to_admin"]
    assert [edge["kind"] for edge in report["paths_to_admin"][0]] == ["sts-assume-role", "has-capability"]
    assert report["paths_to_admin"][0][0]["conditional"] is True
    assert any(item.get("principal") == role_arn and item.get("technique") == "iam-admin" for item in report["findings"])
    assert not any(item.get("principal", "").endswith("user/denied") for item in report["findings"])


def test_aws_passrole_chain_and_broad_trust():
    artifact = {"account_id": "1", "users": [{"name": "bob", "policies": [{"Statement": [{
        "Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        "Resource": "*"}]}]}], "roles": [{"name": "open", "trust": {"Statement": [{
            "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": "*"}]}}]}
    report = identity.analyze_aws_identity(artifact)
    assert any(item.get("technique") == "passrole-lambda" for item in report["findings"])
    assert "aws-broad-role-trust" in finding_kinds(report)


def test_aws_notaction_and_assume_role_resource_scope_are_respected():
    artifact = {"account_id": "1", "users": [
        {"name": "excluded", "policies": [{"Statement": [{"Effect": "Allow",
            "NotAction": ["sts:AssumeRole"], "Resource": "*"}]}]},
        {"name": "wrong-resource", "policies": [{"Statement": [{"Effect": "Allow",
            "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::1:role/Other"}]}]},
    ], "roles": [{"name": "Admin", "trust": {"Statement": [{"Effect": "Allow",
        "Action": "sts:AssumeRole", "Principal": "*"}]}, "policies": [{"Statement": [{
            "Effect": "Allow", "Action": "*", "Resource": "*"}]}]}]}
    report = identity.analyze_aws_identity(artifact)
    assume_edges = [edge for edge in report["edges"] if edge["kind"] == "sts-assume-role"
                    and ":user/" in edge["source"]]
    assert assume_edges == []
    excluded = next(item for item in report["nodes"] if item["id"].endswith("user/excluded"))
    assert excluded["kind"] == "aws-user"
    assert any(item["kind"] == "aws-notaction-allow" and item["principal"].endswith("user/excluded")
               for item in report["findings"])
    assert not any(item.get("technique") == "iam-admin" and item.get("principal", "").endswith("user/excluded")
                   for item in report["findings"])


def test_azure_and_gcp_privilege_graphs():
    azure = {
        "roleDefinitions": [{"id": "r1", "properties": {"roleName": "Grantor", "permissions": [{
            "actions": ["Microsoft.Authorization/roleAssignments/write"], "notActions": []}]}}],
        "roleAssignments": [{"properties": {"principalId": "p1", "roleDefinitionId": "r1", "scope": "/subscriptions/s1"}}],
    }
    az = identity.analyze_azure_identity(azure)
    assert az["paths_to_privilege"]
    assert any(item["action"].endswith("roleassignments/write") for item in az["findings"])

    gcp = {"bindings": [{"role": "roles/custom.impersonator", "members": ["user:a@example.test"]}],
           "role_definitions": {"roles/custom.impersonator": {"includedPermissions": [
               "iam.serviceAccounts.getAccessToken", "resourcemanager.projects.setIamPolicy"]}}}
    gc = identity.analyze_gcp_identity(gcp)
    assert gc["paths_to_privilege"]
    assert {item["permission"] for item in gc["findings"]} == {
        "iam.serviceaccounts.getaccesstoken", "resourcemanager.projects.setiampolicy"}


def test_k8s_aggregated_rbac_admission_and_namespace_analysis():
    objects = [
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
         "metadata": {"name": "secret-reader", "labels": {"aggregate": "yes"}},
         "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
         "metadata": {"name": "aggregate"},
         "aggregationRule": {"clusterRoleSelectors": [{"matchLabels": {"aggregate": "yes"}}]}, "rules": []},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
         "metadata": {"name": "bind"}, "roleRef": {"kind": "ClusterRole", "name": "aggregate"},
         "subjects": [{"kind": "ServiceAccount", "namespace": "app", "name": "worker"}]},
        {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration",
         "metadata": {"name": "weak"}, "webhooks": [{"name": "weak.test", "failurePolicy": "Ignore",
             "clientConfig": {"url": "https://127.0.0.1/hook"},
             "rules": [{"operations": ["*"], "resources": ["*"]}]}]},
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "app", "labels": {}}},
        {"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy", "metadata": {"name": "audit"},
         "spec": {"validationFailureAction": "Audit"}},
    ]
    report = identity.analyze_k8s_security(objects)
    found = finding_kinds(report)
    assert "rbac-credential-access" in found
    assert {"admission-fail-open", "admission-external-url", "admission-broad-scope",
            "pod-security-not-enforced", "admission-audit-only"} <= found
    assert report["role_count"] == 2 and report["object_count"] == len(objects)


def test_k8s_anonymous_and_dangling_bindings_are_explicit():
    objects = [{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                "metadata": {"name": "public"}, "roleRef": {"kind": "ClusterRole", "name": "missing"},
                "subjects": [{"kind": "Group", "name": "system:unauthenticated"}]}]
    found = finding_kinds(identity.analyze_k8s_security(objects))
    assert {"rbac-anonymous-binding", "rbac-dangling-role-ref"} <= found


def test_yaml_loader_is_offline_and_multi_document():
    data = b"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: one\n---\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: two\n"
    docs = identity.load_documents(data)
    assert [doc["metadata"]["name"] for doc in docs] == ["one", "two"]


def test_identity_loader_input_bound(monkeypatch):
    monkeypatch.setattr(identity, "MAX_INPUT", 4)
    with pytest.raises(ValueError, match="cap"):
        identity.load_documents(b"{}" * 10)
