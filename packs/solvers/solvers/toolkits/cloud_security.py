#!/usr/bin/env python3
"""Offline cloud/container misconfiguration and payload-plan analyzer.

This complements ``cloud_container.py``'s artifact readers with security interpretation:

* AWS-style IAM identity/trust policy risks and privilege-escalation combinations;
* Kubernetes workload and RBAC risks from parsed JSON/YAML manifest objects;
* player-run SSRF-to-cloud-metadata request chains (generated only, never sent);
* Docker/OCI current and deleted-layer secret evidence;
* Terraform/CloudFormation exposure and secret findings.

The CLI reads only local files.  It performs no discovery request, credential validation, target
probe, or submission.  YAML, when used, goes through the existing bounded ``safe_load_all`` reader;
there is no ``yaml.load``, pickle, eval, or exec.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from urllib.parse import quote


HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
MAX_INPUT = 128 << 20
MAX_DOC = 16 << 20
MAX_NODES = 200000
MAX_FINDINGS = 2000
MAX_SCAN_BYTES = 4 << 20
MAX_IMAGES = 64


def _load_module(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cloud = _load_module("csctf_cloud_container_base", COMMON / "cloud_container.py")


def _finding(kind: str, score: int, reason: str, **fields) -> dict:
    row = {"kind": kind, "score": int(score), "reason": reason}
    row.update(fields)
    return row


def _string_list(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)][:10000]
    return []


def _statements(policy) -> list[dict]:
    if not isinstance(policy, dict):
        return []
    statements = policy.get("Statement", policy.get("statement", []))
    if isinstance(statements, dict):
        statements = [statements]
    return [item for item in statements[:10000] if isinstance(item, dict)] if isinstance(statements, list) else []


_PRIV_ACTIONS = {
    "iam:passrole": "pass an existing privileged role to a compute service",
    "iam:createpolicyversion": "replace a managed policy's default version",
    "iam:attachuserpolicy": "attach a managed policy to a user",
    "iam:attachrolepolicy": "attach a managed policy to a role",
    "iam:putuserpolicy": "write an inline user policy",
    "iam:putrolepolicy": "write an inline role policy",
    "iam:updateassumerolepolicy": "change a role trust policy",
    "iam:createaccesskey": "create another user's access key",
    "sts:assumerole": "assume a role",
    "lambda:updatefunctioncode": "replace Lambda code",
    "ssm:sendcommand": "run a command through Systems Manager",
    "ec2:runinstances": "launch compute with a chosen instance profile",
    "cloudformation:createstack": "create resources through CloudFormation",
}


def analyze_iam_policy(policy: dict, *, name: str = "policy") -> list[dict]:
    """Rank static IAM policy/trust-policy risks; conditions are reported, never assumed bypassed."""
    findings, allowed = [], set()
    for index, statement in enumerate(_statements(policy)):
        effect = str(statement.get("Effect", statement.get("effect", ""))).lower()
        if effect != "allow":
            continue
        actions = [item.lower() for item in _string_list(statement.get("Action"))]
        not_actions = [item.lower() for item in _string_list(statement.get("NotAction"))]
        resources = _string_list(statement.get("Resource"))
        condition = statement.get("Condition")
        sid = statement.get("Sid", index)
        allowed.update(actions)
        if not_actions:
            findings.append(_finding("iam-notaction-allow", 98,
                                     "Allow with NotAction grants every action except the listed set",
                                     policy=name, statement=sid, not_action=not_actions,
                                     resource=resources, condition=condition))
        if any(action == "*" or action.endswith(":*") for action in actions):
            score = 100 if not condition else 88
            findings.append(_finding("iam-wildcard-action", score,
                                     "Allow grants a wildcard action set",
                                     policy=name, statement=sid, actions=actions, resource=resources,
                                     condition=condition))
        if "*" in resources and actions:
            score = 92 if any(action in _PRIV_ACTIONS or action == "*" for action in actions) else 70
            if condition:
                score -= 10
            findings.append(_finding("iam-wildcard-resource", score,
                                     "allowed actions apply to every resource",
                                     policy=name, statement=sid, actions=actions, condition=condition))
        for action in actions:
            if action in _PRIV_ACTIONS:
                findings.append(_finding("iam-privilege-action", 85 if not condition else 72,
                                         _PRIV_ACTIONS[action], policy=name, statement=sid,
                                         action=action, resource=resources, condition=condition))
        principal = statement.get("Principal")
        principals = []
        if isinstance(principal, str):
            principals = [principal]
        elif isinstance(principal, dict):
            for value in principal.values():
                principals.extend(_string_list(value))
        if "*" in principals:
            findings.append(_finding("iam-public-trust", 100 if not condition else 82,
                                     "trust/resource policy allows every principal",
                                     policy=name, statement=sid, condition=condition))
    def has(action: str) -> bool:
        service = action.split(":", 1)[0] + ":*"
        return action in allowed or service in allowed or "*" in allowed
    combos = (
        (("iam:passrole", "lambda:createfunction"), "PassRole plus Lambda creation can execute as the passed role"),
        (("iam:passrole", "ec2:runinstances"), "PassRole plus EC2 launch can expose the passed instance role"),
        (("iam:passrole", "cloudformation:createstack"), "PassRole plus stack creation can provision as the passed role"),
        (("lambda:updatefunctioncode", "lambda:invokefunction"), "replace-and-invoke can run code as a Lambda execution role"),
    )
    for actions, reason in combos:
        if all(has(action) for action in actions):
            findings.append(_finding("iam-escalation-chain", 97, reason, policy=name, actions=list(actions)))
    return sorted(findings[:MAX_FINDINGS], key=lambda item: (-item["score"], item["kind"], str(item.get("statement", ""))))


def _flatten_k8s(objects) -> list[dict]:
    queue = list(objects[:10000]) if isinstance(objects, list) else [objects]
    out, cursor, seen = [], 0, set()
    while cursor < len(queue) and cursor < MAX_NODES and len(out) < 10000:
        item = queue[cursor]
        cursor += 1
        if not isinstance(item, dict):
            continue
        identity = id(item)
        if identity in seen:
            continue
        seen.add(identity)
        if isinstance(item.get("items"), list) and str(item.get("kind", "")).endswith("List"):
            remaining = max(0, MAX_NODES - len(queue))
            queue.extend(item["items"][:min(10000, remaining)])
        else:
            out.append(item)
    return out


def _pod_spec(obj: dict):
    kind = str(obj.get("kind", ""))
    spec = obj.get("spec") if isinstance(obj.get("spec"), dict) else None
    if not spec:
        return None
    if kind in ("Pod",):
        return spec
    if isinstance(spec.get("jobTemplate"), dict) and isinstance(spec["jobTemplate"].get("spec"), dict):
        spec = spec["jobTemplate"]["spec"]       # CronJob nests the pod template one level deeper
    template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    return template.get("spec") if isinstance(template.get("spec"), dict) else None


def analyze_k8s(objects) -> list[dict]:
    findings = []
    for obj in _flatten_k8s(objects):
        kind = str(obj.get("kind", ""))
        meta = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
        name, namespace = meta.get("name"), meta.get("namespace", "default")
        identity = f"{kind}/{namespace}/{name}"
        if kind in ("Role", "ClusterRole"):
            for index, rule in enumerate((obj.get("rules", [])
                                          if isinstance(obj.get("rules"), list) else [])[:10000]):
                if not isinstance(rule, dict):
                    continue
                verbs, resources = _string_list(rule.get("verbs")), _string_list(rule.get("resources"))
                api_groups = _string_list(rule.get("apiGroups"))
                if "*" in verbs or "*" in resources or "*" in api_groups:
                    findings.append(_finding("k8s-rbac-wildcard", 98, "RBAC rule contains a wildcard",
                                             object=identity, rule=index, verbs=verbs,
                                             resources=resources, api_groups=api_groups))
                sensitive = sorted(set(verbs) & {"escalate", "bind", "impersonate"})
                if sensitive:
                    findings.append(_finding("k8s-rbac-escalation", 100,
                                             "RBAC grants an explicit privilege-escalation verb",
                                             object=identity, rule=index, verbs=sensitive))
                if set(resources) & {"secrets", "serviceaccounts/token"} and set(verbs) & {
                        "get", "list", "watch", "create", "update", "patch", "*"}:
                    findings.append(_finding("k8s-secret-access", 92,
                                             "RBAC grants access to secrets or service-account tokens",
                                             object=identity, rule=index, verbs=verbs, resources=resources))
                if any(resource in {"pods/exec", "pods/attach", "pods/ephemeralcontainers"} for resource in resources):
                    findings.append(_finding("k8s-pod-exec", 90,
                                             "RBAC grants an interactive pod subresource",
                                             object=identity, rule=index, verbs=verbs, resources=resources))
        if kind in ("RoleBinding", "ClusterRoleBinding"):
            role_ref = obj.get("roleRef") if isinstance(obj.get("roleRef"), dict) else {}
            subjects = (obj.get("subjects") if isinstance(obj.get("subjects"), list) else [])[:10000]
            role_name = role_ref.get("name")
            names = [subject.get("name") for subject in subjects if isinstance(subject, dict)]
            if role_name == "cluster-admin":
                findings.append(_finding("k8s-cluster-admin-binding", 100,
                                         "binding grants the built-in cluster-admin role",
                                         object=identity, subjects=names))
            if any(value in ("system:anonymous", "system:unauthenticated") for value in names):
                findings.append(_finding("k8s-anonymous-binding", 100,
                                         "binding grants a role to an anonymous/unauthenticated subject",
                                         object=identity, role=role_name, subjects=names))
        spec = _pod_spec(obj)
        if not spec:
            continue
        if spec.get("hostNetwork") is True:
            findings.append(_finding("k8s-host-network", 88, "pod shares the node network namespace", object=identity))
        if spec.get("hostPID") is True or spec.get("hostIPC") is True:
            findings.append(_finding("k8s-host-namespace", 92, "pod shares a node process/IPC namespace", object=identity))
        if spec.get("automountServiceAccountToken") is not False:
            findings.append(_finding("k8s-service-account-token", 45,
                                     "service-account token automount is not disabled", object=identity,
                                     service_account=spec.get("serviceAccountName", "default")))
        for volume in (spec.get("volumes", []) if isinstance(spec.get("volumes"), list) else [])[:10000]:
            if not isinstance(volume, dict) or not isinstance(volume.get("hostPath"), dict):
                continue
            path = volume["hostPath"].get("path")
            score = 100 if path in ("/", "/var/run/docker.sock", "/run/containerd/containerd.sock") else 85
            findings.append(_finding("k8s-hostpath", score, "pod mounts a node filesystem path",
                                     object=identity, volume=volume.get("name"), path=path))
        containers = []
        for field in ("initContainers", "containers", "ephemeralContainers"):
            value = spec.get(field)
            if isinstance(value, list):
                containers.extend((field, item) for item in value[:10000] if isinstance(item, dict))
        pod_context = spec.get("securityContext") if isinstance(spec.get("securityContext"), dict) else {}
        for field, container in containers:
            context = container.get("securityContext") if isinstance(container.get("securityContext"), dict) else {}
            label = f"{identity}:{field}/{container.get('name')}"
            if context.get("privileged") is True:
                findings.append(_finding("k8s-privileged", 100, "container is privileged", object=label))
            if context.get("allowPrivilegeEscalation") is True:
                findings.append(_finding("k8s-allow-escalation", 90,
                                         "container explicitly permits privilege escalation", object=label))
            caps = (context.get("capabilities") or {}).get("add") if isinstance(context.get("capabilities"), dict) else []
            caps = caps if isinstance(caps, list) else []
            dangerous = [cap for cap in caps if str(cap).upper() in
                         {"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "DAC_READ_SEARCH", "SYS_MODULE", "ALL"}]
            if dangerous:
                findings.append(_finding("k8s-capabilities", 95,
                                         "container adds high-impact Linux capabilities",
                                         object=label, capabilities=dangerous))
            run_as_user = context.get("runAsUser", pod_context.get("runAsUser"))
            non_root = context.get("runAsNonRoot", pod_context.get("runAsNonRoot"))
            if run_as_user == 0 or non_root is False:
                findings.append(_finding("k8s-root", 70, "container is configured to run as root", object=label))
    return sorted(findings[:MAX_FINDINGS], key=lambda item: (-item["score"], item["kind"], str(item.get("object", ""))))


def metadata_chain(provider: str, *, role: str | None = None, path: str | None = None) -> list[dict]:
    """Generate request descriptions for an assigned SSRF sink; never perform them."""
    provider = str(provider).lower()
    if role is not None and (not isinstance(role, str) or len(role) > 512):
        raise ValueError("role name exceeds cap")
    if path is not None and (not isinstance(path, str) or len(path) > 2048):
        raise ValueError("metadata path exceeds cap")
    if provider == "aws":
        base = "http://169.254.169.254/latest"
        role_path = quote(role, safe="-_.~") if role else "<ROLE_FROM_PREVIOUS_RESPONSE>"
        steps = [
            _finding("metadata-request", 100, "obtain an IMDSv2 session token", method="PUT",
                     url=base + "/api/token", headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}),
            _finding("metadata-request", 98, "list the attached IAM role", method="GET",
                     url=base + "/meta-data/iam/security-credentials/",
                     headers={"X-aws-ec2-metadata-token": "<TOKEN>"}),
            _finding("metadata-request", 97, "retrieve temporary credentials for the listed role", method="GET",
                     url=base + "/meta-data/iam/security-credentials/" + role_path,
                     headers={"X-aws-ec2-metadata-token": "<TOKEN>"}),
            _finding("metadata-request", 45, "IMDSv1 fallback only when the challenge deliberately leaves it enabled",
                     method="GET", url=base + "/meta-data/iam/security-credentials/", headers={}),
        ]
    elif provider == "gcp":
        base = "http://metadata.google.internal/computeMetadata/v1"
        steps = [
            _finding("metadata-request", 100, "list service accounts", method="GET",
                     url=base + "/instance/service-accounts/", headers={"Metadata-Flavor": "Google"}),
            _finding("metadata-request", 98, "retrieve the default service-account token", method="GET",
                     url=base + "/instance/service-accounts/default/token", headers={"Metadata-Flavor": "Google"}),
            _finding("metadata-request", 85, "inspect project attributes", method="GET",
                     url=base + "/project/attributes/?recursive=true", headers={"Metadata-Flavor": "Google"}),
        ]
    elif provider == "azure":
        base = "http://169.254.169.254/metadata"
        steps = [
            _finding("metadata-request", 100, "request the managed-identity token for ARM", method="GET",
                     url=base + "/identity/oauth2/token?api-version=2018-02-01&resource="
                         + quote("https://management.azure.com/", safe=""), headers={"Metadata": "true"}),
            _finding("metadata-request", 90, "inspect instance metadata", method="GET",
                     url=base + "/instance?api-version=2021-02-01", headers={"Metadata": "true"}),
        ]
    else:
        raise ValueError("provider must be aws, gcp, or azure")
    if path:
        steps.insert(0, _finding("metadata-request", 100, "caller-supplied metadata path", method="GET",
                                 url=steps[0]["url"].split("/latest", 1)[0].rstrip("/") + "/" + path.lstrip("/"),
                                 headers=steps[0].get("headers", {})))
    return steps


_SECRET_NAME = re.compile(r"(?i)(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|client[_-]?secret)")
_SECRET_PATTERNS = (
    ("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 100),
    ("aws-access-key", re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"), 98),
    ("jwt", re.compile(rb"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"), 86),
    ("secret-assignment", re.compile(rb"(?i)(?:password|secret|token|api[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]?([^\s'\";,]{4,256})"), 82),
)


def _scan_secret_bytes(body: bytes, source: str, layer=None, deleted=False) -> list[dict]:
    findings = []
    sample = body[:MAX_SCAN_BYTES]
    for kind, pattern, score in _SECRET_PATTERNS:
        for match in pattern.finditer(sample):
            value = match.group(1) if match.lastindex else match.group(0)
            findings.append(_finding("container-secret", score, f"{kind} pattern in image evidence",
                                     secret_type=kind, source=source, layer=layer, deleted=deleted,
                                     offset=match.start(), value=value.decode("utf-8", "replace")))
            if len(findings) >= 64:
                return findings
    return findings


def scan_images(images) -> list[dict]:
    findings = []
    for image in list(images)[:MAX_IMAGES]:
        if not isinstance(image, cloud.Image):
            continue
        for key, value in image.env.items():
            if _SECRET_NAME.search(key) and value:
                findings.append(_finding("container-env-secret", 92,
                                         "image environment variable has a secret-bearing name",
                                         image=image.origin, name=key, value=value, deleted=False))
        for index, history in enumerate(image.history[:10000]):
            command = history.get("created_by") if isinstance(history, dict) else None
            if isinstance(command, str) and _SECRET_NAME.search(command):
                findings.extend(_scan_secret_bytes(command.encode(), f"history[{index}]", layer=index))
        for path, (entry, layer) in cloud.final_listing(image).items():
            if entry.data is not None:
                findings.extend(_scan_secret_bytes(entry.data, path, layer=layer.index + 1, deleted=False))
            if len(findings) >= MAX_FINDINGS:
                break
        for item in cloud.deleted_files(image):
            entry = item["entry"]
            if entry.data is not None:
                findings.extend(_scan_secret_bytes(entry.data, item["path"],
                                                   layer=item["added"].index + 1, deleted=True))
            if len(findings) >= MAX_FINDINGS:
                break
    return sorted(findings[:MAX_FINDINGS], key=lambda item: (-item["score"], not item.get("deleted", False), item.get("source", "")))


def _walk(value, path="$", depth=0, state=None):
    if state is None:
        state = [0]
    if depth > 40 or state[0] >= MAX_NODES:
        return
    state[0] += 1
    yield path, value
    if isinstance(value, dict):
        for key, item in list(value.items())[:MAX_NODES]:
            yield from _walk(item, f"{path}.{str(key)[:128]}", depth + 1, state)
    elif isinstance(value, list):
        for index, item in enumerate(value[:MAX_NODES]):
            yield from _walk(item, f"{path}[{index}]", depth + 1, state)


def analyze_iac(document) -> list[dict]:
    """Analyze CloudFormation/Terraform-shaped JSON and generic secret-bearing leaves."""
    findings = []
    resources = document.get("Resources") if isinstance(document, dict) else None
    if isinstance(resources, dict):
        for logical, resource in list(resources.items())[:10000]:
            if not isinstance(resource, dict):
                continue
            rtype = resource.get("Type")
            props = resource.get("Properties") if isinstance(resource.get("Properties"), dict) else {}
            source = f"Resources.{logical}"
            if rtype == "AWS::S3::Bucket":
                if str(props.get("AccessControl", "")).lower() in ("publicread", "publicreadwrite", "authenticatedread"):
                    findings.append(_finding("iac-public-bucket", 100, "S3 bucket ACL is public", source=source))
                pab = props.get("PublicAccessBlockConfiguration")
                if isinstance(pab, dict) and any(pab.get(key) is False for key in
                                                ("BlockPublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
                    findings.append(_finding("iac-public-access-block", 88,
                                             "one or more S3 public-access protections are disabled", source=source))
            if rtype == "AWS::EC2::SecurityGroup":
                for rule in props.get("SecurityGroupIngress", []) if isinstance(props.get("SecurityGroupIngress"), list) else []:
                    if not isinstance(rule, dict):
                        continue
                    cidr = rule.get("CidrIp") or rule.get("CidrIpv6")
                    if cidr in ("0.0.0.0/0", "::/0"):
                        findings.append(_finding("iac-world-ingress", 95,
                                                 "security-group ingress is open to the world",
                                                 source=source, protocol=rule.get("IpProtocol"),
                                                 from_port=rule.get("FromPort"), to_port=rule.get("ToPort"), cidr=cidr))
            if rtype in ("AWS::RDS::DBInstance", "AWS::OpenSearchService::Domain") and props.get("PubliclyAccessible") is True:
                findings.append(_finding("iac-public-service", 95, "managed data service is publicly accessible", source=source))
            if rtype in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role"):
                for field in ("PolicyDocument", "AssumeRolePolicyDocument"):
                    policy = props.get(field)
                    if isinstance(policy, dict):
                        findings.extend(analyze_iam_policy(policy, name=f"{source}.{field}"))
    for path, value in _walk(document):
        leaf = path.rsplit(".", 1)[-1]
        if _SECRET_NAME.search(leaf) and isinstance(value, (str, int, float)) and str(value):
            findings.append(_finding("iac-secret", 90, "secret-bearing field has an inline value",
                                     source=path, value=str(value)[:4096]))
        if leaf.lower() in ("cidr_blocks", "cidrblock", "cidrip"):
            values = value if isinstance(value, list) else [value]
            if any(item in ("0.0.0.0/0", "::/0") for item in values):
                findings.append(_finding("iac-world-cidr", 90, "infrastructure rule contains a world-open CIDR", source=path))
        if leaf.lower() in ("publicly_accessible", "associate_public_ip_address") and value is True:
            findings.append(_finding("iac-public-resource", 82, "resource is explicitly assigned public reachability", source=path))
    # Deduplicate equivalent generic/specific findings without hiding distinct source paths.
    def _hashable(value):
        return value if isinstance(value, (str, int, float, bool, type(None))) else json.dumps(value, sort_keys=True, default=str)
    unique = {}
    for finding in findings:
        key = (finding["kind"], _hashable(finding.get("source")), _hashable(finding.get("statement")), _hashable(finding.get("action")))
        unique.setdefault(key, finding)
    return sorted(list(unique.values())[:MAX_FINDINGS], key=lambda item: (-item["score"], item["kind"], str(item.get("source", ""))))


def _read(path: str, limit: int = MAX_INPUT) -> bytes:
    with Path(path).open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("input exceeds size cap")
    return data


def _documents(raw: bytes):
    try:
        value = json.loads(raw.decode("utf-8"))
        return value if isinstance(value, list) else [value]
    except (ValueError, UnicodeError):
        text = raw.decode("utf-8", "replace")
        docs = cloud._yaml_docs(text)
        if not docs:
            raise ValueError("input is neither bounded JSON nor safe YAML")
        return docs


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="cloud_security.py")
    sub = parser.add_subparsers(dest="operation", required=True)
    for name in ("iam", "k8s", "iac", "image", "oci"):
        command = sub.add_parser(name)
        command.add_argument("input")
        command.add_argument("--json", action="store_true")
    metadata = sub.add_parser("metadata")
    metadata.add_argument("provider", choices=("aws", "gcp", "azure"))
    metadata.add_argument("--role")
    metadata.add_argument("--path")
    metadata.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.operation == "metadata":
            result = {"candidates": metadata_chain(args.provider, role=args.role, path=args.path)}
        elif args.operation in ("image", "oci"):
            raw = _read(args.input)
            evidence = cloud.load({Path(args.input).name: raw}, budget=10.0, max_total=MAX_INPUT)
            result = {"candidates": scan_images(evidence.images), "images": len(evidence.images),
                      "notes": evidence.notes[:100]}
        else:
            raw = _read(args.input, MAX_DOC)
            docs = _documents(raw)
            if args.operation == "iam":
                findings = [item for index, doc in enumerate(docs)
                            for item in analyze_iam_policy(doc, name=f"document[{index}]")]
            elif args.operation == "k8s":
                findings = analyze_k8s(docs)
            else:
                findings = [item for doc in docs for item in analyze_iac(doc)]
            result = {"candidates": sorted(findings[:MAX_FINDINGS], key=lambda item: -item["score"])}
        print(json.dumps(result, sort_keys=True, default=str))
        return 0
    except (OSError, TypeError, ValueError, OverflowError, UnicodeError, json.JSONDecodeError,
            RecursionError, MemoryError) as exc:
        print(f"cloud_security: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
