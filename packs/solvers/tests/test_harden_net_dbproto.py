"""Independent protocol locks and deterministic malformed-stream checks.

Reference writers: Scapy MQTT/LDAP, redis-py RESP, PyMySQL handshake writer,
pg8000 startup/password/query writer. Their transport endpoints are in-memory
fixtures: no socket is opened. Syslog vectors are RFC5424 §6.5/RFC3164 §5.4.
No production encoder or parser result supplies expected values.
"""
from io import BytesIO
import hashlib
import inspect
import random
import re
from types import SimpleNamespace

import pytest
from scapy.contrib.mqtt import MQTT, MQTTConnect, MQTTPublish, MQTTSubscribe, MQTTTopicQOS
from scapy.layers.ldap import (LDAP, LDAP_BindRequest, LDAP_BindResponse,
                              LDAP_Authentication_simple, LDAP_SearchRequest,
                              LDAP_Filter, LDAP_FilterPresent)
from redis.connection import PythonRespSerializer
from pymysql.connections import Connection
from pymysql.constants import CLIENT
from pymysql.protocol import MysqlPacket
import pymysql._auth
import pg8000.core

import net_dbproto as db


CLIENT_KEY = ('192.0.2.1', 40000, '192.0.2.2', 5432, 0)
SERVER_KEY = ('192.0.2.2', 5432, '192.0.2.1', 40000, 0)


class Capture:
    """Only a transport container; does not decode or transform test bytes."""
    def __init__(self, client=b'', server=b'', packets=()):
        self.rows = {
            CLIENT_KEY: SimpleNamespace(data=client, sport=40000, dport=5432),
            SERVER_KEY: SimpleNamespace(data=server, sport=5432, dport=40000),
        }
        self.packets = packets
        self.sha256 = hashlib.sha256(client + server + b''.join(p.payload for p in packets)).hexdigest()
        self.size = len(client) + len(server) + sum(len(p.payload) for p in packets)

    def streams(self):
        return self.rows


def mqtt_wire():
    connect = bytes(MQTT(type=1) / MQTTConnect(
        protoname=b'MQTT', protolevel=4, usernameflag=1, passwordflag=1,
        cleansess=1, klive=60, clientId=b'sensor-17', username=b'operator',
        password=b'CSCTF{mqtt_password}'))
    publish = bytes(MQTT(type=3, QOS=1) / MQTTPublish(
        topic=b'plant/reactor', msgid=0x1234, value=b'CSCTF{mqtt_payload}'))
    subscribe = bytes(MQTT(type=8, QOS=1) / MQTTSubscribe(
        msgid=7, topics=[MQTTTopicQOS(topic=b'plant/+/alarm', QOS=1),
                         MQTTTopicQOS(topic=b'plant/#', QOS=0)]))
    return connect + publish + subscribe


def resp_wire():
    serializer = PythonRespSerializer(4096, lambda v: v if isinstance(v, bytes) else str(v).encode())
    commands = [(b'AUTH', b'operator', b'CSCTF{redis_password}'),
                (b'SET', b'plant', b'CSCTF{stored}\r\n$not_a_frame'), (b'GET', b'plant')]
    return b''.join(piece for cmd in commands for piece in serializer.pack(*cmd))


def mysql_wire(monkeypatch, auth_blob=None):
    """Run PyMySQL's real handshake serializer on an in-memory sink."""
    writer = Connection(user='operator', password='secret', database='control',
                        defer_connect=True, ssl_disabled=True)
    writer.server_version = '8.0.36'
    writer.server_capabilities = (CLIENT.PROTOCOL_41 | CLIENT.SECURE_CONNECTION |
                                  CLIENT.CONNECT_WITH_DB | CLIENT.PLUGIN_AUTH |
                                  CLIENT.PLUGIN_AUTH_LENENC_CLIENT_DATA)
    writer.client_flag |= writer.server_capabilities
    writer._auth_plugin_name = 'mysql_native_password'
    writer.salt = b'01234567890123456789'
    writer._next_seq_id = 1
    parts = []
    writer._write_bytes = parts.append
    writer._read_packet = lambda: MysqlPacket(b'\x00\x00\x00\x02\x00\x00\x00', 'utf8')
    with monkeypatch.context() as m:
        if auth_blob is not None:
            m.setattr(pymysql._auth, 'scramble_native_password', lambda password, salt: auth_blob)
        writer._request_authentication()
    writer._next_seq_id = 0
    writer.write_packet(b'\x03SELECT \'CSCTF{mysql_query}\'')
    return b''.join(parts)


class MemoryDuplex:
    def __init__(self, replies):
        self.replies, self.writes = BytesIO(replies), []

    def read(self, n):
        return self.replies.read(n)

    def write(self, data):
        self.writes.append(bytes(data))
        return len(data)

    def flush(self):
        pass

    def close(self):
        pass

    def makefile(self, mode):
        return self


def postgres_wire(monkeypatch, md5=False):
    # Authoritative PostgreSQL message formats: R length8 code3; R length12
    # code5 + four salt bytes; R length8 code0; Z length5 idle='I'.
    request = bytes.fromhex('520000000c00000005') + b'salt' if md5 else bytes.fromhex('520000000800000003')
    server = request + bytes.fromhex('5200000008000000005a0000000549')
    transport = MemoryDuplex(server)
    with monkeypatch.context() as m:
        m.setattr(pg8000.core, '_make_socket', lambda *a, **k: transport)
        conn = pg8000.core.CoreConnection(user='operator', database='control',
            password='CSCTF{pg_password}', application_name='harden-test', ssl_context=False)
        conn.send_QUERY("SELECT 'CSCTF{pg_query}'")
    return b''.join(transport.writes), server


def ldap_wire():
    bind = bytes(LDAP(messageID=7, protocolOp=LDAP_BindRequest(
        version=3, bind_name=b'cn=operator,dc=example,dc=test',
        authentication=LDAP_Authentication_simple(b'CSCTF{ldap_password}'))))
    search = bytes(LDAP(messageID=8, protocolOp=LDAP_SearchRequest(
        baseObject=b'ou=devices,dc=example,dc=test', scope=2, derefAliases=0,
        sizeLimit=0, timeLimit=0, attrsOnly=False,
        filter=LDAP_Filter(filter=LDAP_FilterPresent(present=b'objectClass')))))
    response = bytes(LDAP(messageID=7, protocolOp=LDAP_BindResponse(
        resultCode=0, matchedDN=b'', diagnosticMessage=b'')))
    return bind + search, response


# Published RFC5424 §6.5 example 1, with its literal message content.
SYSLOG_5424 = (b'<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - '
               b'\xef\xbb\xbf\'su root\' failed for lonvick on /dev/pts/8')
# Published RFC3164 §5.4 example.
SYSLOG_3164 = b'<34>Oct 11 22:14:15 mymachine su: \'su root\' failed for lonvick on /dev/pts/8'


def test_mqtt_scapy_vector():
    facts = db.mqtt_facts(Capture(mqtt_wire()))
    assert facts['connect'] == [{'level': 4, 'client_id': b'sensor-17',
                                'username': b'operator', 'password': b'CSCTF{mqtt_password}'}]
    assert facts['publish'] == [{'topic': b'plant/reactor', 'payload': b'CSCTF{mqtt_payload}'}]
    assert facts['subscribe'] == [{'topic': b'plant/+/alarm'}, {'topic': b'plant/#'}]


def test_redis_reference_serializer_preserves_embedded_framing():
    facts = db.redis_facts(Capture(resp_wire()))
    assert facts == {'auth_user': [b'operator'], 'auth_pass': [b'CSCTF{redis_password}'],
                     'set_key': [b'plant'], 'set_value': [b'CSCTF{stored}\r\n$not_a_frame'],
                     'get_key': [b'plant'], 'commands': ['AUTH', 'SET', 'GET']}


def test_mysql_reference_writer(monkeypatch):
    facts = db.mysql_facts(Capture(mysql_wire(monkeypatch)))
    assert facts['user'] == [b'operator']
    assert facts['database'] == [b'control']
    assert facts['query'] == [b"SELECT 'CSCTF{mysql_query}'"]


def test_mysql_published_handshake_response41():
    # MySQL developer manual Protocol::HandshakeResponse41, example for 5.5.8.
    wire = bytes.fromhex('''
        54 00 00 01 8d a6 0f 00 00 00 00 01 08 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 70 61 6d 00 14 ab 09 ee f6 bc b1 32
        3e 61 14 38 65 c0 99 1d 95 7d 75 d4 47 74 65 73
        74 00 6d 79 73 71 6c 5f 6e 61 74 69 76 65 5f 70
        61 73 73 77 6f 72 64 00''')
    facts = db.mysql_facts(Capture(wire))
    assert facts['user'] == [b'pam']
    assert facts['database'] == [b'test']


@pytest.mark.parametrize('auth_length', [0, 250, 251, 300, 65535, 65536])
def test_mysql_lenenc_auth_database(monkeypatch, auth_length):
    wire = mysql_wire(monkeypatch, auth_blob=b'A' * auth_length)
    assert db.mysql_facts(Capture(wire))['database'] == [b'control']


def mysql_auth_response(auth, flags):
    # Protocol::HandshakeResponse41: capability, max packet, charset, reserved,
    # NUL-terminated username, authentication response, NUL-terminated database.
    body = (flags.to_bytes(4, 'little') + b'\x00\x00\x00\x01\x21' + b'\x00' * 23
            + b'operator\x00' + auth + b'control\x00')
    return len(body).to_bytes(3, 'little') + b'\x01' + body


@pytest.mark.parametrize('length', [b'\x03', b'\xfc\x03\x00',
                                    b'\xfd\x03\x00\x00', b'\xfe\x03' + b'\x00' * 7])
def test_mysql_lenenc_auth_all_integer_forms(length):
    # PyMySQL's independent integer reader verifies each wire representation.
    assert MysqlPacket(length, 'utf8').read_length_encoded_integer() == 3
    flags = (CLIENT.PROTOCOL_41 | CLIENT.CONNECT_WITH_DB | CLIENT.SECURE_CONNECTION
             | CLIENT.PLUGIN_AUTH_LENENC_CLIENT_DATA)
    wire = mysql_auth_response(length + b'abc', flags)
    assert db.mysql_facts(Capture(wire))['database'] == [b'control']


@pytest.mark.parametrize('auth', [b'', b'\xfb', b'\xff', b'\xfc', b'\xfc\x01',
                                 b'\xfd\x01\x00', b'\xfe' + b'\x00' * 6,
                                 b'\xfc\xff\xff', b'\xfd\xff\xff\xff',
                                 b'\xfe' + b'\xff' * 8, b'\xfaabc'])
def test_mysql_lenenc_auth_malformed(auth):
    flags = (CLIENT.PROTOCOL_41 | CLIENT.CONNECT_WITH_DB | CLIENT.SECURE_CONNECTION
             | CLIENT.PLUGIN_AUTH_LENENC_CLIENT_DATA)
    # Omit the database so truncated length fields remain truncated on the wire.
    wire = mysql_auth_response(auth, flags)
    body = wire[4:-len(b'control\x00')]
    wire = len(body).to_bytes(3, 'little') + b'\x01' + body
    wire += b'\x02\x00\x00\x00\x03Q'
    facts = db.mysql_facts(Capture(wire))
    assert facts['database'] == []
    assert facts['query'] == []


def test_postgres_reference_writer(monkeypatch):
    client, server = postgres_wire(monkeypatch)
    facts = db.pg_facts(Capture(client, server))
    assert facts == {'user': [b'operator'], 'database': [b'control'], 'app': [b'harden-test'],
                     'password': [b'CSCTF{pg_password}'], 'md5': [],
                     'query': [b"SELECT 'CSCTF{pg_query}'"]}


def test_postgres_md5_wire_reference_writer(monkeypatch):
    import hashlib
    client, server = postgres_wire(monkeypatch, md5=True)
    inner = hashlib.md5(b'CSCTF{pg_password}operator').hexdigest().encode()
    expected = b'md5' + hashlib.md5(inner + b'salt').hexdigest().encode()
    facts = db.pg_facts(Capture(client, server))
    assert facts['md5'] == [expected]
    assert facts['password'] == []


def test_ldap_scapy_bind_search_and_result():
    client, server = ldap_wire()
    facts = db.ldap_facts(Capture(client, server))
    assert facts == {'bind_dn': [b'cn=operator,dc=example,dc=test'],
                     'bind_pw': [b'CSCTF{ldap_password}'],
                     'bound_ok_dn': [b'cn=operator,dc=example,dc=test'],
                     'search_base': [b'ou=devices,dc=example,dc=test']}


@pytest.mark.parametrize('wire,host', [(SYSLOG_5424, b'mymachine.example.com'), (SYSLOG_3164, b'mymachine')])
def test_published_syslog(wire, host):
    packet = SimpleNamespace(proto=17, payload=wire, sport=30000, dport=514, frag=0)
    facts = db.syslog_facts(Capture(packets=[packet]))
    assert facts == {'host': [host], 'app': [b'su'], 'facility': [b'4'], 'severity': [b'2']}


def test_public_entrypoint_inventory():
    # This family exposes *_facts and field, with no public parse_* / is_*.
    discovered = {name for name, fn in inspect.getmembers(db, inspect.isfunction)
                  if fn.__module__ == db.__name__ and not name.startswith('_')}
    assert discovered == {'mqtt_facts', 'redis_facts', 'mysql_facts', 'pg_facts',
                          'ldap_facts', 'syslog_facts', 'field'}


class Question:
    success = False
    def __init__(self, value): self.value = value
    def has(self, pattern): return bool(re.search(pattern, self.value, re.I))
    def asks(self, pattern): return self.has(pattern)


def test_public_field_dispatch_from_reference_capture():
    def choose(question, values, field, protocol):
        return {'values': values, 'field': field, 'protocol': protocol}
    result = db.field(Question('MQTT client identifier'), Capture(mqtt_wire()), dict, choose)
    assert result == {'values': ['sensor-17'], 'field': 'mqtt_client_id', 'protocol': 'mqtt'}


def malformed(seed, good):
    rng = random.Random(seed)
    yield b''
    for n in (1, 2, 3, 4, 7, 16, 31, 64, 255, 1024):
        yield b'\xff' * n
        yield b'\x00' * n
        yield rng.randbytes(n)
    # Preserve real protocol magic/header and truncate at every boundary.
    for n in range(len(good)):
        yield good[:n]
    for _ in range(96):
        mutant = bytearray(good)
        if mutant:
            index = rng.randrange(len(mutant))
            mutant[index] ^= 1 << rng.randrange(8)
        yield bytes(mutant)


@pytest.mark.parametrize('name', ['mqtt_facts', 'redis_facts', 'mysql_facts', 'pg_facts', 'ldap_facts', 'syslog_facts'])
def test_fail_closed_public_facts(name, monkeypatch):
    ldap, _ = ldap_wire()
    pg, _ = postgres_wire(monkeypatch)
    vectors = {'mqtt_facts': mqtt_wire(), 'redis_facts': resp_wire(),
               'mysql_facts': mysql_wire(monkeypatch), 'pg_facts': pg,
               'ldap_facts': ldap, 'syslog_facts': SYSLOG_5424}
    reader = getattr(db, name)
    for blob in malformed(0xDB00 + list(vectors).index(name), vectors[name]):
        packet = SimpleNamespace(proto=17, payload=blob, sport=30000, dport=514, frag=0)
        cap = Capture(blob, blob, [packet])
        # This engine declares no exception type: every escape is a failure.
        result = reader(cap)
        assert isinstance(result, dict)


@pytest.mark.parametrize('name', ['_mqtt_packets', '_mqtt_connect', '_resp_commands',
                                 '_mysql_packets', '_pg_startup', '_pg_messages', '_ldap_messages'])
def test_fail_closed_private_wire_parsers(name, monkeypatch):
    ldap, _ = ldap_wire()
    pg, _ = postgres_wire(monkeypatch)
    connect = bytes(MQTTConnect(protoname=b'MQTT', protolevel=4, clientId=b'sensor-17'))
    vectors = {'_mqtt_packets': mqtt_wire(), '_mqtt_connect': connect,
               '_resp_commands': resp_wire(), '_mysql_packets': mysql_wire(monkeypatch),
               '_pg_startup': pg, '_pg_messages': bytes.fromhex('520000000800000003'),
               '_ldap_messages': ldap}
    reader = getattr(db, name)
    for blob in malformed(0xDA00 + list(vectors).index(name), vectors[name]):
        reader(blob)


def test_fail_closed_public_field_dispatch():
    for question in ['MQTT password', 'Redis password', 'MySQL database',
                     'PostgreSQL query', 'LDAP bind', 'syslog hostname']:
        for blob in malformed(0xF1E1D, mqtt_wire()):
            cap = Capture(blob, blob)
            db.field(Question(question), cap, dict,
                     lambda question, values, field, protocol: (values, field, protocol))
