#!/usr/bin/env python3
"""Offline AWS/Azure/GCP identity and Kubernetes RBAC/admission graph analysis.

Inputs are exported JSON/YAML artifacts.  No cloud SDK, token, API, cluster or network
access is used.  Conditions that cannot be evaluated from the artifact remain marked
as conditional instead of being assumed satisfiable.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
from collections import defaultdict, deque
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

MAX_NODES = 100_000
MAX_EDGES = 500_000
MAX_PATHS = 10_000
MAX_INPUT = 32 * 1024 * 1024


def _list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _strings(value) -> list[str]:
    return [str(item) for item in _list(value) if isinstance(item, (str, int))]


def _finding(kind: str, severity: str, message: str, **evidence) -> dict:
    out = {"kind": kind, "severity": severity, "message": message}
    out.update({key: value for key, value in evidence.items() if value is not None})
    return out


def _sorted_findings(findings: list[dict]) -> list[dict]:
    rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    dedup = {(item.get("kind"), item.get("principal"), item.get("role"), item.get("object"), item.get("message")): item
             for item in findings}
    return sorted(dedup.values(), key=lambda item: (-rank.get(item.get("severity"), 0),
                                                     str(item.get("kind")), str(item.get("principal", ""))))


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self._edge_keys: set[tuple] = set()

    def node(self, ident: str, kind: str, **metadata) -> str:
        if len(self.nodes) >= MAX_NODES and ident not in self.nodes:
            raise ValueError("identity graph node cap exceeded")
        record = self.nodes.setdefault(ident, {"id": ident, "kind": kind})
        record.update({key: value for key, value in metadata.items() if value is not None})
        return ident

    def edge(self, source: str, target: str, kind: str, *, conditional: bool = False, **metadata) -> None:
        key = (source, target, kind, conditional, json.dumps(metadata, sort_keys=True, default=str))
        if key in self._edge_keys:
            return
        if len(self.edges) >= MAX_EDGES:
            raise ValueError("identity graph edge cap exceeded")
        self._edge_keys.add(key)
        record = {"source": source, "target": target, "kind": kind, "conditional": conditional}
        record.update({key: value for key, value in metadata.items() if value is not None})
        self.edges.append(record)

    def paths(self, starts: list[str], targets: set[str], max_depth: int = 8) -> list[list[dict]]:
        adjacency: dict[str, list[dict]] = defaultdict(list)
        for edge in self.edges:
            adjacency[edge["source"]].append(edge)
        out = []
        for start in starts:
            queue = deque([(start, [], {start})])
            while queue and len(out) < MAX_PATHS:
                node, path, seen = queue.popleft()
                if node in targets and path:
                    out.append(path)
                    continue
                if len(path) >= max_depth:
                    continue
                for edge in sorted(adjacency.get(node, []), key=lambda item: (item["target"], item["kind"])):
                    if edge["target"] not in seen:
                        queue.append((edge["target"], path + [edge], seen | {edge["target"]}))
        return out

    def report(self) -> dict:
        return {"nodes": sorted(self.nodes.values(), key=lambda item: item["id"]),
                "edges": sorted(self.edges, key=lambda item: (item["source"], item["target"], item["kind"]))}


def _aws_statements(policy) -> list[dict]:
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            return []
    if not isinstance(policy, dict):
        return []
    statements = policy.get("Statement", policy.get("statement", []))
    return [item for item in _list(statements) if isinstance(item, dict)][:MAX_NODES]


def _action_matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def _collect_permissions(policies: list[dict]) -> dict:
    allow, deny = [], []
    for policy in policies:
        for statement in _aws_statements(policy):
            effect = str(statement.get("Effect", "")).lower()
            condition = statement.get("Condition")
            resources = _strings(statement.get("Resource", "*"))
            actions = _strings(statement.get("Action"))
            not_actions = [item.lower() for item in _strings(statement.get("NotAction"))]
            target = allow if effect == "allow" else deny if effect == "deny" else None
            if target is not None:
                for action in actions:
                    target.append({"action": action.lower(), "resources": resources,
                                   "not_actions": [], "condition": condition, "sid": statement.get("Sid")})
                if not_actions:
                    target.append({"action": "*", "resources": resources, "not_actions": not_actions,
                                   "condition": condition, "sid": statement.get("Sid")})
    return {"allow": allow, "deny": deny}


def _entry_matches(entry: dict, action: str) -> bool:
    excluded = entry.get("not_actions", [])
    return ((action != "*" and not any(_action_matches(pattern, action) for pattern in excluded))
            if excluded else _action_matches(entry["action"], action))


def _resource_matches(pattern: str, resource: str) -> bool:
    return fnmatch.fnmatchcase(resource.lower(), pattern.lower())


def _permission(perms: dict, action: str, resource: str | None = None) -> tuple[bool, bool, list[str]]:
    grants = [entry for entry in perms["allow"] if _entry_matches(entry, action)
              and (resource is None or any(_resource_matches(pattern, resource) for pattern in entry["resources"]))]
    if not grants:
        return False, False, []
    unconditional_denies = [entry for entry in perms["deny"]
                            if _entry_matches(entry, action)
                            and (resource is None or any(_resource_matches(pattern, resource) for pattern in entry["resources"]))
                            and not entry["condition"]]
    if unconditional_denies:
        return False, False, []
    conditional_denies = [entry for entry in perms["deny"]
                           if _entry_matches(entry, action)
                           and (resource is None or any(_resource_matches(pattern, resource) for pattern in entry["resources"]))
                           and entry["condition"]]
    conditional = all(bool(entry["condition"]) for entry in grants) or bool(conditional_denies)
    resources = sorted({resource for entry in grants for resource in entry["resources"]})
    return True, conditional, resources


_AWS_TECHNIQUES = {
    "iam-admin": (["*"], "effective administrator wildcard"),
    "create-policy-version": (["iam:CreatePolicyVersion"], "can replace a managed policy version"),
    "set-policy-version": (["iam:SetDefaultPolicyVersion"], "can activate an existing managed policy version"),
    "attach-user-policy": (["iam:AttachUserPolicy"], "can attach a managed policy to a user"),
    "put-user-policy": (["iam:PutUserPolicy"], "can write an inline user policy"),
    "put-role-policy": (["iam:PutRolePolicy"], "can write an inline role policy"),
    "attach-role-policy": (["iam:AttachRolePolicy"], "can attach a managed policy to a role"),
    "update-role-trust": (["iam:UpdateAssumeRolePolicy"], "can modify a role trust policy"),
    "create-access-key": (["iam:CreateAccessKey"], "can create long-lived credentials for a user"),
    "reset-console-password": (["iam:UpdateLoginProfile"], "can reset another IAM user's console password"),
    "passrole-lambda": (["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "can run Lambda under a passed role"),
    "passrole-ec2": (["iam:PassRole", "ec2:RunInstances"], "can launch EC2 under a passed role"),
    "passrole-cloudformation": (["iam:PassRole", "cloudformation:CreateStack"], "can create a stack under a passed role"),
    "replace-lambda": (["lambda:UpdateFunctionCode", "lambda:InvokeFunction"], "can replace and invoke Lambda code"),
    "ssm-command": (["ssm:SendCommand"], "can issue Systems Manager commands"),
    "assume-role": (["sts:AssumeRole"], "can request an STS role session"),
}


def _aws_principal_name(item: dict, kind: str, account: str | None) -> str:
    name = str(item.get("arn") or item.get("Arn") or item.get("name") or item.get("UserName") or item.get("RoleName"))
    if name.startswith("arn:"):
        return name
    account = account or "unknown"
    return f"arn:aws:iam::{account}:{kind}/{name}"


def _policy_documents(item: dict, managed: dict) -> list[dict]:
    documents = []
    for key in ("policies", "inline_policies", "PolicyDocument", "policy_documents"):
        for policy in _list(item.get(key)):
            if isinstance(policy, dict) and "PolicyDocument" in policy:
                policy = policy["PolicyDocument"]
            if isinstance(policy, dict):
                documents.append(policy)
    for key in ("attached_policies", "managed_policies", "AttachedManagedPolicies"):
        for ref in _list(item.get(key)):
            arn = ref.get("PolicyArn") if isinstance(ref, dict) else ref
            if arn in managed:
                value = managed[arn]
                if isinstance(value, dict) and "PolicyDocument" in value:
                    value = value["PolicyDocument"]
                if isinstance(value, dict):
                    documents.append(value)
            if isinstance(arn, str) and arn.endswith("AdministratorAccess"):
                documents.append({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    return documents


def _trust_principals(role: dict) -> list[dict]:
    trust = role.get("trust") or role.get("AssumeRolePolicyDocument") or role.get("assume_role_policy") or {}
    out = []
    for statement in _aws_statements(trust):
        if str(statement.get("Effect", "")).lower() != "allow":
            continue
        actions = [x.lower() for x in _strings(statement.get("Action"))]
        if not any(_action_matches(pattern, "sts:AssumeRole") or _action_matches(pattern, "sts:AssumeRoleWithWebIdentity") for pattern in actions):
            continue
        principal = statement.get("Principal")
        values = []
        if isinstance(principal, dict):
            for ptype, entries in principal.items():
                values.extend((ptype, value) for value in _strings(entries))
        else:
            values.extend(("AWS", value) for value in _strings(principal))
        for ptype, value in values:
            out.append({"type": ptype, "principal": value, "condition": statement.get("Condition")})
    return out


def analyze_aws_identity(document: dict, starts: list[str] | None = None) -> dict:
    if not isinstance(document, dict):
        raise TypeError("AWS artifact must be an object")
    account = str(document.get("account_id")) if document.get("account_id") is not None else None
    managed = document.get("managed_policies", {}) if isinstance(document.get("managed_policies"), dict) else {}
    users = [item for item in _list(document.get("users")) if isinstance(item, dict)]
    roles = [item for item in _list(document.get("roles")) if isinstance(item, dict)]
    groups = [item for item in _list(document.get("groups")) if isinstance(item, dict)]
    if len(users) + len(roles) + len(groups) > MAX_NODES:
        raise ValueError("AWS identity artifact exceeds principal cap")
    graph, findings = Graph(), []
    principals: dict[str, dict] = {}
    group_policies = {}
    for group in groups:
        name = str(group.get("name") or group.get("GroupName"))
        group_policies[name] = _policy_documents(group, managed)
    for item, kind in [(user, "user") for user in users] + [(role, "role") for role in roles]:
        arn = _aws_principal_name(item, kind, account)
        policies = _policy_documents(item, managed)
        if kind == "user":
            for group_name in _strings(item.get("groups")):
                policies.extend(group_policies.get(group_name, []))
        perms = _collect_permissions(policies)
        principals[arn] = {"item": item, "kind": kind, "permissions": perms}
        graph.node(arn, f"aws-{kind}", name=item.get("name") or item.get("UserName") or item.get("RoleName"))

    admin_nodes = set()
    for arn, principal in principals.items():
        for entry in principal["permissions"]["allow"]:
            if entry.get("not_actions"):
                findings.append(_finding("aws-notaction-allow", "high",
                                         "Allow with NotAction grants a broad complement of permissions",
                                         principal=arn, exclusions=entry["not_actions"],
                                         conditional=bool(entry.get("condition"))))
        for technique, (required, description) in _AWS_TECHNIQUES.items():
            checks = [_permission(principal["permissions"], action) for action in required]
            if all(check[0] for check in checks):
                if technique == "iam-admin" and not any("*" in check[2] for check in checks):
                    continue
                capability = "aws-capability:" + technique
                conditional = any(check[1] for check in checks)
                graph.node(capability, "aws-capability", description=description, admin=(technique == "iam-admin"))
                graph.edge(arn, capability, "has-capability", conditional=conditional, actions=required,
                           resources=sorted({resource for check in checks for resource in check[2]}))
                severity = "critical" if technique == "iam-admin" else "high"
                findings.append(_finding("aws-escalation-capability", severity, description,
                                         principal=arn, technique=technique, conditional=conditional))
                if technique == "iam-admin":
                    admin_nodes.add(capability)

    role_by_arn = {arn: entry for arn, entry in principals.items() if entry["kind"] == "role"}
    for role_arn, entry in role_by_arn.items():
        for trust in _trust_principals(entry["item"]):
            trusted = trust["principal"]
            wildcard = trusted == "*" or trusted.endswith(":root")
            condition = trust["condition"]
            if wildcard:
                findings.append(_finding("aws-broad-role-trust", "critical" if trusted == "*" and not condition else "high",
                                         "role trust accepts a wildcard or account root principal",
                                         role=role_arn, trusted_principal=trusted, condition=condition))
            for source_arn, source in principals.items():
                account_root_match = trusted.endswith(":root") and source_arn.split(":")[4:5] == trusted.split(":")[4:5]
                if trusted not in ("*", source_arn) and not account_root_match:
                    continue
                allowed, action_conditional, resources = _permission(source["permissions"], "sts:AssumeRole", role_arn)
                if allowed:
                    graph.edge(source_arn, role_arn, "sts-assume-role",
                               conditional=bool(condition) or action_conditional,
                               trust_condition=condition, resources=resources)

    start_nodes = starts or sorted(arn for arn, entry in principals.items() if entry["kind"] == "user")
    paths = graph.paths(start_nodes, admin_nodes)
    return {"provider": "aws", **graph.report(), "findings": _sorted_findings(findings),
            "paths_to_admin": paths, "starts": start_nodes}


_AZURE_DANGEROUS = {
    "*": "full Azure control-plane access",
    "microsoft.authorization/roleassignments/write": "can grant Azure RBAC roles",
    "microsoft.authorization/roledefinitions/write": "can create or modify custom roles",
    "microsoft.managedidentity/userassignedidentities/federatedidentitycredentials/write": "can add federated credentials to an identity",
    "microsoft.compute/virtualmachines/runcommand/action": "can execute a VM run-command",
    "microsoft.compute/virtualmachines/extensions/write": "can install a VM extension",
    "microsoft.automation/automationaccounts/jobs/write": "can create an Automation job",
    "microsoft.keyvault/vaults/secrets/read": "can read Key Vault secrets through the control plane",
}


def analyze_azure_identity(document: dict, starts: list[str] | None = None) -> dict:
    definitions = {}
    for definition in _list(document.get("roleDefinitions") or document.get("role_definitions")):
        if not isinstance(definition, dict):
            continue
        props = definition.get("properties", definition)
        ident = str(definition.get("id") or definition.get("name") or props.get("roleName"))
        definitions[ident] = props
    graph, findings = Graph(), []
    principals = set()
    targets = set()
    for assignment in _list(document.get("roleAssignments") or document.get("role_assignments")):
        if not isinstance(assignment, dict):
            continue
        props = assignment.get("properties", assignment)
        principal = str(props.get("principalId") or props.get("principal_id"))
        role_id = str(props.get("roleDefinitionId") or props.get("role_definition_id"))
        definition = definitions.get(role_id) or definitions.get(role_id.rsplit("/", 1)[-1]) or {}
        role_name = str(definition.get("roleName") or role_id)
        scope = str(props.get("scope") or assignment.get("scope") or "/")
        principals.add(principal)
        graph.node("azure-principal:" + principal, "azure-principal")
        role_node = graph.node("azure-role:" + role_id, "azure-role", name=role_name)
        graph.edge("azure-principal:" + principal, role_node, "role-assignment",
                   conditional=bool(props.get("condition")), scope=scope, condition=props.get("condition"))
        permissions = _list(definition.get("permissions"))
        actions = [action.lower() for permission in permissions if isinstance(permission, dict)
                   for action in _strings(permission.get("actions"))]
        not_actions = [action.lower() for permission in permissions if isinstance(permission, dict)
                       for action in _strings(permission.get("notActions"))]
        for dangerous, description in _AZURE_DANGEROUS.items():
            if any(_action_matches(pattern, dangerous) or _action_matches(pattern, "*") for pattern in actions) and not any(
                    _action_matches(pattern, dangerous) for pattern in not_actions):
                cap = graph.node("azure-capability:" + dangerous, "azure-capability", description=description,
                                 admin=dangerous in {"*", "microsoft.authorization/roleassignments/write"})
                graph.edge(role_node, cap, "grants-action", action=dangerous, scope=scope)
                targets.add(cap)
                findings.append(_finding("azure-escalation-capability", "critical" if dangerous in {"*", "microsoft.authorization/roleassignments/write"} else "high",
                                         description, principal=principal, role=role_name, scope=scope, action=dangerous))
    start_nodes = ["azure-principal:" + value for value in (starts or sorted(principals))]
    return {"provider": "azure", **graph.report(), "findings": _sorted_findings(findings),
            "paths_to_privilege": graph.paths(start_nodes, targets), "starts": start_nodes}


_GCP_DANGEROUS = {
    "resourcemanager.projects.setiampolicy": "can change project IAM policy",
    "iam.serviceaccounts.setiampolicy": "can change a service account IAM policy",
    "iam.serviceaccounts.actas": "can attach/use a service account",
    "iam.serviceaccountkeys.create": "can create a service account key",
    "iam.serviceaccounts.getaccesstoken": "can mint a service account access token",
    "cloudfunctions.functions.create": "can deploy Cloud Functions",
    "cloudfunctions.functions.update": "can replace Cloud Functions code/configuration",
    "run.services.create": "can deploy a Cloud Run service",
    "compute.instances.setmetadata": "can alter instance metadata/startup scripts",
}


def analyze_gcp_identity(document: dict, starts: list[str] | None = None) -> dict:
    policy = document.get("policy", document)
    role_defs = document.get("role_definitions", {}) if isinstance(document.get("role_definitions"), dict) else {}
    graph, findings, principals, targets = Graph(), set(), set(), set()
    for binding in _list(policy.get("bindings") if isinstance(policy, dict) else None):
        if not isinstance(binding, dict):
            continue
        role = str(binding.get("role"))
        role_node = graph.node("gcp-role:" + role, "gcp-role", name=role)
        permissions = _strings((role_defs.get(role) or {}).get("includedPermissions")) if isinstance(role_defs.get(role), dict) else []
        if role in {"roles/owner", "roles/editor"}:
            permissions.append("*")
        for member in _strings(binding.get("members")):
            principals.add(member)
            principal_node = graph.node("gcp-principal:" + member, "gcp-principal")
            graph.edge(principal_node, role_node, "role-binding", conditional=bool(binding.get("condition")),
                       condition=binding.get("condition"))
            for permission, description in _GCP_DANGEROUS.items():
                if "*" in permissions or permission in [item.lower() for item in permissions]:
                    cap = graph.node("gcp-capability:" + permission, "gcp-capability", description=description,
                                     admin=permission.endswith("setiampolicy"))
                    graph.edge(role_node, cap, "grants-permission", permission=permission)
                    targets.add(cap)
                    findings.add((member, role, permission, description, bool(binding.get("condition"))))
    finding_list = [_finding("gcp-escalation-capability", "critical" if permission.endswith("setiampolicy") else "high",
                             description, principal=member, role=role, permission=permission, conditional=conditional)
                    for member, role, permission, description, conditional in findings]
    start_nodes = ["gcp-principal:" + value for value in (starts or sorted(principals))]
    return {"provider": "gcp", **graph.report(), "findings": _sorted_findings(finding_list),
            "paths_to_privilege": graph.paths(start_nodes, targets), "starts": start_nodes}


def _objects(value) -> list[dict]:
    queue = list(value) if isinstance(value, list) else [value]
    out = []
    while queue and len(out) < MAX_NODES:
        item = queue.pop(0)
        if not isinstance(item, dict):
            continue
        if str(item.get("kind", "")).endswith("List") and isinstance(item.get("items"), list):
            queue.extend(item["items"])
        else:
            out.append(item)
    return out


def _kmeta(obj: dict) -> tuple[str, str, dict]:
    meta = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
    return str(meta.get("namespace", "default")), str(meta.get("name", "")), meta


def _rule_dangers(rule: dict) -> list[tuple[str, str, str]]:
    verbs = set(_strings(rule.get("verbs")))
    resources = set(_strings(rule.get("resources")))
    api_groups = set(_strings(rule.get("apiGroups")))
    out = []
    if "*" in verbs or "*" in resources or "*" in api_groups:
        out.append(("rbac-wildcard", "critical", "wildcard RBAC permission"))
    if verbs & {"escalate", "bind", "impersonate"}:
        out.append(("rbac-escalation-verb", "critical", "explicit RBAC escalation/impersonation verb"))
    if resources & {"secrets", "serviceaccounts/token"} and verbs & {"*", "get", "list", "watch", "create"}:
        out.append(("rbac-credential-access", "high", "secret or service-account token access"))
    if resources & {"pods/exec", "pods/attach", "pods/ephemeralcontainers", "nodes/proxy"} and verbs & {"*", "create", "get", "update", "patch"}:
        out.append(("rbac-code-execution", "high", "interactive pod/node subresource access"))
    if resources & {"roles", "clusterroles", "rolebindings", "clusterrolebindings"} and verbs & {"*", "create", "update", "patch"}:
        out.append(("rbac-policy-write", "critical", "can create or modify RBAC policy objects"))
    if resources & {"certificatesigningrequests/approval", "signers"} and verbs & {"*", "approve", "sign", "update"}:
        out.append(("rbac-certificate-approval", "high", "can approve/sign Kubernetes certificates"))
    if resources & {"daemonsets", "deployments", "pods", "jobs", "cronjobs"} and verbs & {"*", "create", "update", "patch"}:
        out.append(("rbac-workload-write", "high", "can create or modify executable workloads"))
    return out


def analyze_k8s_security(value, subjects: list[str] | None = None) -> dict:
    objects = _objects(value)
    roles: dict[tuple[str, str, str], dict] = {}
    graph, findings = Graph(), []
    for obj in objects:
        kind = str(obj.get("kind", ""))
        namespace, name, meta = _kmeta(obj)
        if kind in {"Role", "ClusterRole"}:
            key = (kind, namespace if kind == "Role" else "", name)
            roles[key] = {"rules": [rule for rule in _list(obj.get("rules")) if isinstance(rule, dict)],
                          "labels": meta.get("labels", {}), "aggregationRule": obj.get("aggregationRule")}
    # Resolve aggregated ClusterRoles by matchLabels until stable.
    for _ in range(len(roles) + 1):
        changed = False
        for key, role in roles.items():
            aggregation = role.get("aggregationRule")
            if key[0] != "ClusterRole" or not isinstance(aggregation, dict):
                continue
            combined = list(role["rules"])
            for selector in _list(aggregation.get("clusterRoleSelectors")):
                labels = selector.get("matchLabels", {}) if isinstance(selector, dict) else {}
                for other_key, other in roles.items():
                    if other_key[0] == "ClusterRole" and labels and all(other.get("labels", {}).get(k) == v for k, v in labels.items()):
                        combined.extend(other["rules"])
            canonical = {json.dumps(rule, sort_keys=True): rule for rule in combined}
            if len(canonical) != len(role["rules"]):
                role["rules"] = list(canonical.values()); changed = True
        if not changed:
            break

    bound_subjects = set()
    for obj in objects:
        kind = str(obj.get("kind", ""))
        namespace, name, _ = _kmeta(obj)
        identity = f"{kind}/{namespace}/{name}"
        if kind in {"RoleBinding", "ClusterRoleBinding"}:
            ref = obj.get("roleRef") if isinstance(obj.get("roleRef"), dict) else {}
            ref_kind, ref_name = str(ref.get("kind", "ClusterRole")), str(ref.get("name", ""))
            role_key = (ref_kind, namespace if ref_kind == "Role" else "", ref_name)
            role = roles.get(role_key, {"rules": []})
            if role_key not in roles:
                findings.append(_finding("rbac-dangling-role-ref", "low",
                                         "binding refers to a role absent from the supplied artifact",
                                         object=identity, role=f"{ref_kind}/{ref_name}"))
            role_id = graph.node(f"k8s-role:{role_key[0]}:{role_key[1]}:{role_key[2]}", "k8s-role")
            for subject in _list(obj.get("subjects")):
                if not isinstance(subject, dict):
                    continue
                subject_kind = str(subject.get("kind", ""))
                subject_ns = str(subject.get("namespace", namespace))
                subject_name = str(subject.get("name", ""))
                subject_id = f"{subject_kind}:{subject_ns}:{subject_name}"
                bound_subjects.add(subject_id)
                graph.node("k8s-subject:" + subject_id, "k8s-subject")
                graph.edge("k8s-subject:" + subject_id, role_id, "rbac-binding", binding=identity)
                if subject_name in {"system:anonymous", "system:unauthenticated"}:
                    findings.append(_finding("rbac-anonymous-binding", "critical",
                                             "binding grants permissions to anonymous/unauthenticated subjects",
                                             principal=subject_id, role=f"{role_key[0]}/{role_key[2]}", object=identity))
                for index, rule in enumerate(role["rules"]):
                    for danger, severity, message in _rule_dangers(rule):
                        cap = graph.node("k8s-capability:" + danger, "k8s-capability", description=message,
                                         admin=danger in {"rbac-wildcard", "rbac-policy-write", "rbac-escalation-verb"})
                        graph.edge(role_id, cap, "grants-rbac", rule=index, verbs=_strings(rule.get("verbs")),
                                   resources=_strings(rule.get("resources")))
                        findings.append(_finding(danger, severity, message, principal=subject_id,
                                                 role=f"{role_key[0]}/{role_key[2]}", object=identity, rule=index))
        elif kind in {"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"}:
            for index, webhook in enumerate(_list(obj.get("webhooks"))):
                if not isinstance(webhook, dict):
                    continue
                if webhook.get("failurePolicy", "Fail") == "Ignore":
                    findings.append(_finding("admission-fail-open", "high", "admission webhook ignores failures",
                                             object=identity, webhook=webhook.get("name"), index=index))
                config = webhook.get("clientConfig") if isinstance(webhook.get("clientConfig"), dict) else {}
                if config.get("url"):
                    findings.append(_finding("admission-external-url", "medium", "admission webhook uses an external URL",
                                             object=identity, webhook=webhook.get("name"), url=config.get("url")))
                for rule in _list(webhook.get("rules")):
                    if isinstance(rule, dict) and ("*" in _strings(rule.get("resources")) or "*" in _strings(rule.get("operations"))):
                        findings.append(_finding("admission-broad-scope", "medium", "admission webhook rule uses a wildcard",
                                                 object=identity, webhook=webhook.get("name")))
        elif kind == "Namespace":
            labels = (obj.get("metadata") or {}).get("labels", {}) if isinstance(obj.get("metadata"), dict) else {}
            enforce = labels.get("pod-security.kubernetes.io/enforce") if isinstance(labels, dict) else None
            if enforce not in {"baseline", "restricted"}:
                findings.append(_finding("pod-security-not-enforced", "medium", "namespace does not enforce baseline/restricted Pod Security",
                                         object=identity, enforce=enforce))
        elif kind in {"ClusterPolicy", "Policy"} and str(obj.get("apiVersion", "")).startswith("kyverno.io/"):
            spec = obj.get("spec") if isinstance(obj.get("spec"), dict) else {}
            if str(spec.get("validationFailureAction", "Audit")).lower() == "audit":
                findings.append(_finding("admission-audit-only", "medium", "Kyverno validation is audit-only",
                                         object=identity))
        elif "constraints.gatekeeper.sh/" in str(obj.get("apiVersion", "")):
            spec = obj.get("spec") if isinstance(obj.get("spec"), dict) else {}
            if str(spec.get("enforcementAction", "deny")).lower() in {"dryrun", "warn"}:
                findings.append(_finding("admission-audit-only", "medium", "Gatekeeper constraint is not enforcing deny",
                                         object=identity))

    starts = ["k8s-subject:" + value for value in (subjects or sorted(bound_subjects))]
    targets = {node["id"] for node in graph.nodes.values() if node.get("admin")}
    return {"provider": "kubernetes", **graph.report(), "findings": _sorted_findings(findings),
            "paths_to_cluster_privilege": graph.paths(starts, targets), "starts": starts,
            "role_count": len(roles), "object_count": len(objects)}


def load_documents(data: bytes) -> list:
    if len(data) > MAX_INPUT:
        raise ValueError("identity artifact exceeds input cap")
    text = data.decode("utf-8", "strict")
    try:
        value = json.loads(text)
        return value if isinstance(value, list) else [value]
    except json.JSONDecodeError:
        if yaml is None:
            raise ValueError("YAML input requires PyYAML")
        return [item for item in yaml.safe_load_all(text) if item is not None]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline cloud identity and Kubernetes privilege graph")
    parser.add_argument("provider", choices=("aws", "azure", "gcp", "k8s"))
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--start", action="append", default=[])
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args(argv)
    documents = load_documents(args.artifact.read_bytes())
    value = documents if args.provider == "k8s" else documents[0]
    function = {"aws": analyze_aws_identity, "azure": analyze_azure_identity,
                "gcp": analyze_gcp_identity, "k8s": analyze_k8s_security}[args.provider]
    report = function(value, args.start or None)
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
