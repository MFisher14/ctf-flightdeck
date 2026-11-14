"""Cloud policy vectors from AWS/Kubernetes schemas; all evidence stays offline.

Oracles: AWS IAM policy-element reference; Kubernetes Pod/CronJob API;
CloudFormation S3/SecurityGroup properties; OCI layer whiteout semantics.
"""
import hashlib
import json
import os
import random
import socket
import subprocess
import urllib.request

import pytest
import yaml

import cloud_security as cs


@pytest.fixture(autouse=True)
def no_live_calls(monkeypatch):
    calls = []

    def blocked(*args, **kwargs):
        calls.append('forbidden process/network call')
        raise AssertionError(calls[-1])

    for module, names in [(os, ['system', 'popen']),
                          (subprocess, ['Popen', 'run', 'call']),
                          (socket, ['create_connection']),
                          (urllib.request, ['urlopen'])]:
        for name in names:
            monkeypatch.setattr(module, name, blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(socket.socket, 'connect_ex', blocked)
    yield calls
    assert calls == []


def clean_call(fn, value):
    # These legacy modules declare no custom Error; ValueError is their explicit
    # rejection contract. Do not accept arbitrary builtins as parser errors.
    try:
        return fn(value)
    except ValueError as exc:
        assert type(exc) is ValueError, f'leaked {type(exc).__name__}: {exc}'
        return None


def test_iam_allow_deny_condition_and_escalation_vector():
    condition = {'StringEquals': {'aws:PrincipalOrgID': 'o-example'}}
    policy = json.loads(json.dumps({'Version': '2012-10-17', 'Statement': [
        {'Sid': 'delegate', 'Effect': 'Allow', 'Action': ['iam:PassRole', 'lambda:CreateFunction'],
         'Resource': '*'},
        {'Sid': 'trust', 'Effect': 'Allow', 'Action': 'sts:AssumeRole', 'Principal': '*',
         'Resource': 'arn:aws:iam::123456789012:role/test', 'Condition': condition},
        {'Sid': 'deny', 'Effect': 'Deny', 'Action': '*', 'Resource': '*'}]}))
    rows = cs.analyze_iam_policy(policy, name='reference')
    assert all(row.get('statement') != 'deny' for row in rows)
    chain = next(row for row in rows if row['kind'] == 'iam-escalation-chain')
    assert chain['actions'] == ['iam:passrole', 'lambda:createfunction']
    trust = next(row for row in rows if row['kind'] == 'iam-public-trust')
    assert (trust['policy'], trust['statement'], trust['condition']) == ('reference', 'trust', condition)
    delegation = next(row for row in rows if row.get('action') == 'iam:passrole')
    assert delegation['resource'] == ['*']
    assert delegation['statement'] == 'delegate'


POD_YAML = """
apiVersion: v1
kind: Pod
metadata: {name: worker, namespace: factory}
spec:
  hostPID: true
  automountServiceAccountToken: false
  volumes: [{name: root, hostPath: {path: /}}]
  containers:
    - name: app
      image: fixture:1
      securityContext:
        privileged: true
        runAsUser: 0
        allowPrivilegeEscalation: true
        capabilities: {add: [SYS_ADMIN]}
      volumeMounts: [{name: root, mountPath: /host}]
"""


def test_kubernetes_yaml_pod_fields():
    rows = cs.analyze_k8s(yaml.safe_load(POD_YAML))
    assert {row['kind'] for row in rows} == {
        'k8s-host-namespace', 'k8s-hostpath', 'k8s-privileged',
        'k8s-allow-escalation', 'k8s-capabilities', 'k8s-root'}
    mount = next(row for row in rows if row['kind'] == 'k8s-hostpath')
    assert (mount['object'], mount['volume'], mount['path']) == ('Pod/factory/worker', 'root', '/')
    caps = next(row for row in rows if row['kind'] == 'k8s-capabilities')
    assert caps['capabilities'] == ['SYS_ADMIN']


def test_rbac_binding_fields():
    rows = cs.analyze_k8s({'kind': 'ClusterRoleBinding', 'metadata': {'name': 'all'},
                           'roleRef': {'name': 'cluster-admin'},
                           'subjects': [{'kind': 'Group', 'name': 'system:unauthenticated'}]})
    assert {row['kind'] for row in rows} == {'k8s-cluster-admin-binding', 'k8s-anonymous-binding'}
    assert all(row['subjects'] == ['system:unauthenticated'] for row in rows)


def test_cronjob_nested_pod_privilege():
    pod = yaml.safe_load(POD_YAML)
    cron = {'apiVersion': 'batch/v1', 'kind': 'CronJob', 'metadata': {'name': 'daily'},
            'spec': {'schedule': '0 0 * * *', 'jobTemplate': {'spec': {'template': {'spec': pod['spec']}}}}}
    assert any(row['kind'] == 'k8s-privileged' for row in cs.analyze_k8s(cron))


def test_iac_json_cloudformation_and_terraform_fields():
    document = {'Resources': {
        'Bucket': {'Type': 'AWS::S3::Bucket', 'Properties': {'AccessControl': 'PublicRead'}},
        'Firewall': {'Type': 'AWS::EC2::SecurityGroup', 'Properties': {
            'SecurityGroupIngress': [{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'CidrIp': '0.0.0.0/0'}]}}},
        'resource': {'aws_db_instance': {'db': {'password': 'CSCTF{inline}', 'publicly_accessible': True}}}}
    rows = cs.analyze_iac(json.loads(json.dumps(document)))
    assert any(row['kind'] == 'iac-public-bucket' and row['source'] == 'Resources.Bucket' for row in rows)
    ingress = next(row for row in rows if row['kind'] == 'iac-world-ingress')
    assert (ingress['protocol'], ingress['from_port'], ingress['to_port'], ingress['cidr']) == ('tcp', 22, 22, '0.0.0.0/0')
    secret = next(row for row in rows if row['kind'] == 'iac-secret')
    assert (secret['source'], secret['value']) == ('$.resource.aws_db_instance.db.password', 'CSCTF{inline}')


def test_metadata_request_plans_are_inert_and_escape_role():
    aws = cs.metadata_chain('aws', role='role/name')
    assert aws[0]['method'] == 'PUT'
    assert aws[0]['url'] == 'http://169.254.169.254/latest/api/token'
    assert aws[0]['headers'] == {'X-aws-ec2-metadata-token-ttl-seconds': '21600'}
    assert aws[2]['url'].endswith('/iam/security-credentials/role%2Fname')
    assert all(row['headers'] == {'Metadata-Flavor': 'Google'} for row in cs.metadata_chain('gcp'))
    assert cs.metadata_chain('azure')[0]['headers'] == {'Metadata': 'true'}


def test_image_secret_values_and_deleted_layer_provenance():
    # Independently authored OCI model: second layer whiteouts the first secret.
    image = cs.cloud.Image('fixture-image', 'oci')
    image.config = {'config': {'Env': ['API_TOKEN=CSCTF{env}']}, 'history': []}
    first, second = cs.cloud.Layer(0, 'base'), cs.cloud.Layer(1, 'cleanup')
    body = b'password=CSCTF{deleted}'
    first.entries['opt/credentials.env'] = cs.cloud.Entry(
        'opt/credentials.env', 'file', len(body), 0o600, None, body,
        hashlib.sha256(body).hexdigest(), False)
    second.whiteouts = ['opt/credentials.env']
    image.layers = [first, second]
    rows = cs.scan_images([image])
    assert any(row['kind'] == 'container-env-secret' and row['value'] == 'CSCTF{env}' for row in rows)
    deleted = next(row for row in rows if row['kind'] == 'container-secret')
    assert (deleted['source'], deleted['value'], deleted['layer'], deleted['deleted']) == (
        'opt/credentials.env', 'CSCTF{deleted}', 1, True)


@pytest.mark.parametrize('value', [None, 1, '', [], {}, {'Statement': [None, 'bad', {}]},
                                     {'spec': {'containers': [None, {'securityContext': None}]}}])
def test_public_mapping_analyzers_fail_closed(value):
    for fn in [cs.analyze_iam_policy, cs.analyze_k8s, cs.analyze_iac]:
        clean_call(fn, value)


def test_seeded_documents_and_cycles_remain_bounded(monkeypatch):
    rng = random.Random(606)
    for _ in range(30):
        document = {rng.choice(['Statement', 'spec', 'Resources', 'secret']): rng.choice([None, 1, [], {}, '\uffff'])}
        for fn in [cs.analyze_iam_policy, cs.analyze_k8s, cs.analyze_iac]:
            clean_call(fn, document)
    cyclic = {}; cyclic['self'] = cyclic
    clean_call(cs.analyze_iac, cyclic)
    monkeypatch.setattr(cs, 'MAX_NODES', 16)
    assert isinstance(cs.analyze_iac([{'password': 'x'}] * 1000), list)
    for value in ['', 'unknown', '\uffff', 'x' * 1000]:
        with pytest.raises(ValueError):
            cs.metadata_chain(value)


def test_iac_malformed_iam_sid_fail_closed():
    clean_call(cs.analyze_iac, {'Resources': {'Role': {'Type': 'AWS::IAM::Role', 'Properties': {
        'AssumeRolePolicyDocument': {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*', 'Sid': []}]}}}}})


def test_scan_images_malformed_entry_fail_closed():
    clean_call(cs.scan_images, [{}])


def test_k8s_malformed_capabilities_fail_closed():
    clean_call(cs.analyze_k8s, {'kind': 'Pod', 'spec': {'containers': [
        {'name': 'broken', 'securityContext': {'capabilities': {'add': 7}}}]}})
