"""Static runtime fixtures, based on OCI/Kubernetes/SAM and stdlib ZIP writers."""
import io
import json
import random
import stat
import struct
import zipfile

import pytest
import yaml

import cloud_runtime_depth as cr
from test_harden_cloud_cloud_security import POD_YAML, clean_call, no_live_calls


def kinds(report):
    return {row['kind'] for row in report['findings']}


def zip_fixture(entries=None):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path, body in entries or [('.env', b'password=CSCTF{offline}'),
                                    ('../outside', b'outside'), ('native.so', b'ELF fixture')]:
            info = zipfile.ZipInfo(path, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, body)
        link = zipfile.ZipInfo('link', date_time=(2020, 1, 1, 0, 0, 0))
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, '../target')
    return stream.getvalue()


def test_kubernetes_pod_and_cronjob_share_real_spec_semantics():
    pod = yaml.safe_load(POD_YAML)
    cron = {'kind': 'CronJob', 'metadata': {'name': 'daily'},
            'spec': {'jobTemplate': {'spec': {'template': {'spec': pod['spec']}}}}}
    for doc, name in [(pod, 'Pod/worker'), (cron, 'CronJob/daily')]:
        report = cr.analyze_container_workload(doc)
        assert report['workloads'][0]['name'] == name
        assert report['workloads'][0]['volumes'] == {'root': {'host_path': '/', 'type': None}}
        assert {'privileged-container', 'host-pid-namespace', 'dangerous-linux-capability',
                'writable-host-path'} <= kinds(report)
        assert 'service-account-token-mounted' not in kinds(report)
        cap = next(row for row in report['findings'] if row['kind'] == 'dangerous-linux-capability')
        assert cap['capabilities'] == ['SYS_ADMIN']


def oci_fixture():
    return {'ociVersion': '1.1.0', 'root': {'path': 'rootfs', 'readonly': True},
            'process': {'user': {'uid': 1000}, 'noNewPrivileges': True,
                        'capabilities': {'effective': ['CAP_SYS_ADMIN']}},
            'linux': {'namespaces': [{'type': x} for x in ['pid', 'network', 'ipc', 'mount', 'user']],
                      'seccomp': {'defaultAction': 'SCMP_ACT_ERRNO'}},
            'mounts': [{'source': '/var/run/docker.sock', 'destination': '/runtime.sock',
                        'options': ['bind', 'rw']}]}


def test_oci_json_namespaces_capabilities_and_socket():
    report = cr.analyze_artifact(json.dumps(oci_fixture()).encode(), 'config.json')
    assert report['kind'] == 'oci-runtime-analysis'
    assert report['namespaces'] == {x: None for x in ['pid', 'network', 'ipc', 'mount', 'user']}
    assert kinds(report) == {'oci-dangerous-capabilities', 'oci-writable-sensitive-mount', 'oci-runtime-socket'}
    cap = next(row for row in report['findings'] if row['kind'] == 'oci-dangerous-capabilities')
    assert cap['capabilities'] == ['CAP_SYS_ADMIN']
    assert report['mounts'] == [{'source': '/var/run/docker.sock', 'destination': '/runtime.sock', 'options': ['bind', 'rw']}]


def test_proc_snapshot_uses_supplied_bytes_and_linux_capability_bit21():
    report = cr.analyze_runtime_snapshot({
        '/proc/self/status': b'Name:\tfixture\nCapEff:\t0000000000200000\n',
        '/proc/self/mountinfo': b'22 1 0:20 / /sys/fs/cgroup rw,nosuid - cgroup cgroup rw\n',
        '/proc/1/cgroup': '1:name=systemd:/docker/fixture\n'})
    assert report['evidence']['effective_capabilities'] == ['SYS_ADMIN']
    assert report['evidence']['mount_lines'] == 1
    assert report['evidence']['cgroup'] == ['1:name=systemd:/docker/fixture']
    assert kinds(report) == {'snapshot-dangerous-capabilities', 'snapshot-writable-kernel-filesystem'}


def test_sam_yaml_resources_graph_and_literal_secret_redaction():
    doc = yaml.safe_load('''
Resources:
  Worker:
    Type: AWS::Serverless::Function
    Properties:
      Runtime: python3.12
      Handler: app.handler
      Role: arn:aws:iam::123456789012:role/worker
      FunctionUrlConfig: {AuthType: NONE}
      Environment:
        Variables: {API_TOKEN: 'CSCTF{literal}', DB_PASSWORD: '{{resolve:secretsmanager:db}}'}
      Events:
        Public: {Type: HttpApi, Properties: {Path: /, Method: GET}}
        Private: {Type: HttpApi, Properties: {Auth: {Authorizer: JWT}}}
''')
    report = cr.analyze_serverless_config(doc)
    assert report['functions'] == [{'name': 'Worker', 'provider': 'aws', 'runtime': 'python3.12',
                                   'handler': 'app.handler', 'role': 'arn:aws:iam::123456789012:role/worker'}]
    assert {'from': 'event:Public', 'to': 'Worker', 'relation': 'HttpApi'} in report['graph']
    assert {'from': 'Worker', 'to': 'arn:aws:iam::123456789012:role/worker', 'relation': 'assumes-role'} in report['graph']
    secrets = [row for row in report['findings'] if row['kind'] == 'plaintext-serverless-secret']
    assert [row['variable'] for row in secrets] == ['API_TOKEN']
    assert 'CSCTF{literal}' not in json.dumps(report)
    assert [row['event'] for row in report['findings'] if row['kind'] == 'unauthenticated-function-event'] == ['Public']
    assert 'public-lambda-url' in kinds(report)


def test_azure_and_gcp_public_invocation():
    azure = cr.analyze_serverless_config({'scriptFile': 'main.py', 'bindings': [
        {'type': 'httpTrigger', 'direction': 'in', 'name': 'req', 'authLevel': 'anonymous'}]})
    assert 'anonymous-azure-function' in kinds(azure)
    gcp = cr.analyze_serverless_config({'invokers': ['allUsers'], 'environmentVariables': {'API_KEY': 'literal'}})
    assert {'public-gcp-function', 'plaintext-serverless-secret'} <= kinds(gcp)


def test_real_zip_members_traversal_symlink_secret_and_expanded_size():
    data = zip_fixture()
    report = cr.inspect_serverless_zip(data)
    assert report['compressed_size'] == len(data)
    assert report['expanded_size'] == sum(map(len, [b'password=CSCTF{offline}', b'outside', b'ELF fixture', b'../target']))
    members = {row['path']: row for row in report['members']}
    assert members['../outside']['traversal'] is True
    assert members['link']['symlink'] is True
    assert {'archive-path-traversal', 'archive-symlink', 'serverless-native-binary',
            'secret-like-package-file', 'embedded-function-secret'} <= kinds(report)
    assert cr.analyze_artifact(data)['kind'] == 'serverless-zip-analysis'


@pytest.mark.parametrize('limit,value', [('MAX_INPUT', 16), ('MAX_ARCHIVE_MEMBERS', 1), ('MAX_ARCHIVE_EXPANDED', 8)])
def test_small_archive_caps_reject_before_unbounded_expansion(monkeypatch, limit, value):
    monkeypatch.setattr(cr, limit, value)
    with pytest.raises(ValueError):
        cr.inspect_serverless_zip(zip_fixture())


def test_workload_depth_and_cycle_guards(monkeypatch):
    monkeypatch.setattr(cr, 'MAX_NESTING', 8)
    nested = {}; nested['kind'] = 'List'; nested['items'] = [nested]
    with pytest.raises(ValueError):
        cr.analyze_container_workload(nested)
    doc = {}
    for _ in range(12):
        doc = [doc]
    with pytest.raises(ValueError):
        cr.analyze_container_workload(doc)


def test_byte_parser_seeded_truncation_bitflip_and_oversized_corpus(monkeypatch):
    rng = random.Random(606)
    data = zip_fixture()
    corpus = [b'', b'\xff' * 256, b'PK\x03\x04', b'[' * 1000, b'x' * 4097]
    corpus += [rng.randbytes(size) for size in [1, 8, 32, 256]]
    corpus += [data[:size] for size in [1, 4, 16, 32, len(data) - 1]]
    # Header and end-record mutations, not compressed payload data.
    for offset in [0, 2, 8, len(data) - 1]:
        mutated = bytearray(data); mutated[offset] ^= 0x80; corpus.append(bytes(mutated))
    monkeypatch.setattr(cr, 'MAX_INPUT', 4096)
    for blob in corpus:
        for fn in [cr.analyze_artifact, cr.inspect_serverless_zip]:
            clean_call(fn, blob)


def test_mapping_parser_malformed_fields_stay_closed():
    values = [{}, {'spec': None}, {'process': 1, 'linux': None, 'mounts': 7},
              {'Resources': [1], 'functions': None}, {'bindings': None}]
    for doc in values:
        for fn in [cr.analyze_container_workload, cr.analyze_oci_runtime_config, cr.analyze_serverless_config]:
            clean_call(fn, doc)
    for value in [b'', b'\xff' * 256, b'garbage - rw', b'CapEff: BAD\n']:
        clean_call(cr.analyze_runtime_snapshot, {'/proc/self/status': value, '/proc/self/mountinfo': value})


@pytest.mark.parametrize('fn', [cr.analyze_oci_runtime_config, cr.analyze_runtime_snapshot, cr.analyze_serverless_config])
def test_runtime_top_level_wrong_type_fail_closed(fn):
    clean_call(fn, None)


@pytest.mark.parametrize('fn', [cr.analyze_artifact, cr.inspect_serverless_zip])
def test_runtime_byte_wrong_type_fail_closed(fn):
    clean_call(fn, 'not bytes')


def test_runtime_snapshot_malformed_value_fail_closed():
    clean_call(cr.analyze_runtime_snapshot, {'/proc/self/status': 7})


def test_serverless_policy_malformed_action_fail_closed():
    clean_call(cr.analyze_serverless_config, {'Resources': {'Role': {'Type': 'AWS::IAM::Role',
        'Properties': {'Policies': [{'Statement': [{'Effect': 'Allow', 'Action': 7, 'Resource': '*'}]}]}}}})


def test_zip_invalid_deflate_fail_closed():
    data = bytearray(zip_fixture([('fixture.txt', b'a' * 100)]))
    # ZIP local file header: filename/extra lengths at offsets 26/28.
    name_len, extra_len = struct.unpack_from('<HH', data, 26)
    start = 30 + name_len + extra_len
    # Set first DEFLATE block BTYPE=3, reserved by RFC 1951 section 3.2.3.
    data[start] = (data[start] & ~7) | 7
    clean_call(cr.inspect_serverless_zip, bytes(data))
