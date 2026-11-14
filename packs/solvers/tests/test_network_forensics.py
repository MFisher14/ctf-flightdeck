"""Deterministic offline tests for the isolated r5e network-forensics depth."""

from __future__ import annotations

import base64
import dataclasses
import gzip
import hashlib
import io
import struct

import dpkt
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scapy.utils import PcapReader

from solvers.toolkits import network_ics_depth as depth
from solvers.toolkits import network_forensics as nf


CLIENT = "192.0.2.10"
SERVER = "198.51.100.20"
CLIENT_MAC = bytes.fromhex("020000000010")
SERVER_MAC = bytes.fromhex("020000000020")


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip4(src: str, dst: str, payload: bytes, protocol: int, ident: int = 1) -> bytes:
    source = bytes(int(part) for part in src.split("."))
    destination = bytes(int(part) for part in dst.split("."))
    header = bytearray(struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000,
        64, protocol, 0, source, destination,
    ))
    struct.pack_into("!H", header, 10, checksum(bytes(header)))
    return bytes(header) + payload


def tcp(sport: int, dport: int, seq: int, flags: int, payload: bytes = b"") -> bytes:
    # A zero checksum represents checksum-offload/not captured; the strict reader accepts
    # zero but rejects any present nonzero checksum that does not verify.
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 65535, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, len(payload) + 8, 0) + payload


def ethernet(payload: bytes, *, client_to_server: bool = True) -> bytes:
    src, dst = ((CLIENT_MAC, SERVER_MAC) if client_to_server else (SERVER_MAC, CLIENT_MAC))
    return dst + src + b"\x08\x00" + payload


def tcp_frame(src: str, dst: str, sport: int, dport: int, seq: int,
              flags: int, payload: bytes = b"", ident: int = 1) -> bytes:
    return ethernet(ip4(src, dst, tcp(sport, dport, seq, flags, payload), 6, ident),
                    client_to_server=src == CLIENT)


def udp_frame(src: str, dst: str, sport: int, dport: int,
              payload: bytes, ident: int = 1) -> bytes:
    return ethernet(ip4(src, dst, udp(sport, dport, payload), 17, ident),
                    client_to_server=src == CLIENT)


def pcap(frames: list[bytes]) -> bytes:
    output = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames):
        output += struct.pack("<IIII", 1_800_000_000 + index, index * 1000, len(frame), len(frame))
        output += frame
    return bytes(output)


def ng_block(block_type: int, body: bytes) -> bytes:
    length = 12 + len(body)
    assert length % 4 == 0
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def pcapng(frames: list[bytes]) -> bytes:
    section = ng_block(0x0A0D0D0A, b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1))
    interface = ng_block(1, struct.pack("<HHI", 1, 0, 65535))
    packets = bytearray()
    for index, frame in enumerate(frames):
        padded = frame + b"\x00" * ((-len(frame)) & 3)
        packets += ng_block(6, struct.pack("<IIIII", 0, 0, index + 1, len(frame), len(frame)) + padded)
    return section + interface + bytes(packets)


def tcp_capture(client_data: bytes, server_data: bytes, *, client_port: int = 40000,
                server_port: int = 80, disorder: bool = False,
                conflict: bool = False) -> bytes:
    cseq, sseq = 1000, 9000
    frames = [
        tcp_frame(CLIENT, SERVER, client_port, server_port, cseq, 0x02, ident=1),
        tcp_frame(SERVER, CLIENT, server_port, client_port, sseq, 0x12, ident=2),
    ]
    csplit = max(1, len(client_data) // 2)
    cparts = [
        tcp_frame(CLIENT, SERVER, client_port, server_port, cseq + 1, 0x18,
                  client_data[:csplit], ident=3),
        tcp_frame(CLIENT, SERVER, client_port, server_port, cseq + 1 + csplit, 0x18,
                  client_data[csplit:], ident=4),
    ]
    if disorder:
        cparts.reverse()
    frames.extend(cparts)
    if client_data:
        frames.append(tcp_frame(CLIENT, SERVER, client_port, server_port, cseq + 1, 0x18,
                                client_data[:min(8, len(client_data))], ident=5))
    if conflict and len(client_data) >= 6:
        frames.append(tcp_frame(CLIENT, SERVER, client_port, server_port, cseq + 3, 0x18,
                                b"BAD!", ident=6))
    if server_data:
        ssplit = max(1, len(server_data) // 2)
        frames.extend([
            tcp_frame(SERVER, CLIENT, server_port, client_port, sseq + 1 + ssplit, 0x18,
                      server_data[ssplit:], ident=7),
            tcp_frame(SERVER, CLIENT, server_port, client_port, sseq + 1, 0x18,
                      server_data[:ssplit], ident=8),
        ])
    frames.extend([
        tcp_frame(CLIENT, SERVER, client_port, server_port, cseq + 1 + len(client_data), 0x11, ident=9),
        tcp_frame(SERVER, CLIENT, server_port, client_port, sseq + 1 + len(server_data), 0x11, ident=10),
    ])
    return pcap(frames)


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"


def dns_query(name: str, ident: int = 0x1234, qtype: int = 1) -> bytes:
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(name: str, ident: int = 0x1234, *, txt: bytes | None = None) -> bytes:
    question = dns_name(name) + struct.pack("!HH", 16 if txt is not None else 1, 1)
    if txt is None:
        rdata, rtype = bytes([203, 0, 113, 9]), 1
    else:
        assert len(txt) <= 255
        rdata, rtype = bytes([len(txt)]) + txt, 16
    answer = b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata
    return struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0) + question + answer


def dns_chunk_query(name: str, index: int, total: int, chunk: bytes, ident: int) -> bytes:
    encoded = base64.b32encode(chunk).decode("ascii").rstrip("=")
    return dns_query(f"{index}-{total}-{encoded}.{name}", ident=ident, qtype=16)


def tls_record(handshake_type: int, body: bytes) -> bytes:
    handshake = bytes([handshake_type]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def tls_client_hello(random: bytes) -> bytes:
    body = b"\x03\x03" + random + b"\x00\x00\x02\x13\x01\x01\x00\x00\x00"
    return tls_record(1, body)


def tls_server_hello() -> bytes:
    body = (b"\x03\x03" + b"S" * 32 + b"\x00\x13\x01\x00" +
            b"\x00\x06\x00\x2b\x00\x02\x03\x04")
    return tls_record(2, body)


def keylog(random: bytes, secret: bytes, label: str = "CLIENT_TRAFFIC_SECRET_0") -> bytes:
    return f"{label} {random.hex()} {secret.hex()}\n".encode("ascii")


def smb2_header(command: int, flags: int, message_id: int) -> bytes:
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    struct.pack_into("<H", header, 4, 64)
    struct.pack_into("<H", header, 12, command)
    struct.pack_into("<I", header, 16, flags)
    struct.pack_into("<Q", header, 24, message_id)
    return bytes(header)


def netbios(message: bytes) -> bytes:
    return b"\x00" + len(message).to_bytes(3, "big") + message


def smb_create_request(name: str, message_id: int) -> bytes:
    encoded = name.encode("utf-16-le")
    body = bytearray(56)
    struct.pack_into("<H", body, 0, 57)
    struct.pack_into("<H", body, 44, 120)
    struct.pack_into("<H", body, 46, len(encoded))
    return netbios(smb2_header(5, 0, message_id) + bytes(body) + encoded)


def smb_create_response(file_id: bytes, size: int, message_id: int) -> bytes:
    body = bytearray(90)
    struct.pack_into("<H", body, 0, 89)
    struct.pack_into("<Q", body, 48, size)
    body[64:80] = file_id
    return netbios(smb2_header(5, 1, message_id) + bytes(body))


def smb_read_request(file_id: bytes, size: int, message_id: int) -> bytes:
    body = bytearray(49)
    struct.pack_into("<H", body, 0, 49)
    struct.pack_into("<I", body, 4, size)
    body[16:32] = file_id
    return netbios(smb2_header(8, 0, message_id) + bytes(body))


def smb_read_response(data: bytes, message_id: int) -> bytes:
    body = bytearray(16)
    struct.pack_into("<H", body, 0, 17)
    body[2] = 80
    struct.pack_into("<I", body, 4, len(data))
    return netbios(smb2_header(8, 1, message_id) + bytes(body) + data)


def ws_frame(payload: bytes, opcode: int = 1, *, masked: bool = True, fin: bool = True) -> bytes:
    assert len(payload) < 126
    first = (0x80 if fin else 0) | opcode
    if not masked:
        return bytes([first, len(payload)]) + payload
    mask = b"\x11\x22\x33\x44"
    encoded = bytes(byte ^ mask[index & 3] for index, byte in enumerate(payload))
    return bytes([first, 0x80 | len(payload)]) + mask + encoded


def h2_frame(frame_type: int, flags: int, stream: int, payload: bytes = b"") -> bytes:
    return len(payload).to_bytes(3, "big") + bytes([frame_type, flags]) + stream.to_bytes(4, "big") + payload


def test_capture_admission_pcap_pcapng_and_independent_cross_checks():
    frame = udp_frame(CLIENT, SERVER, 53000, 53, dns_query("admit.example"))
    classic = pcap([frame])
    modern = pcapng([frame])

    admitted = nf.admit_capture(classic)
    assert admitted is not None
    assert admitted.format == "pcap"
    assert admitted.packets == 1
    assert admitted.linktypes == (1,)
    assert admitted.dpkt_crosschecked
    assert len(list(dpkt.pcap.Reader(io.BytesIO(classic)))) == admitted.packets
    with PcapReader(io.BytesIO(classic)) as reader:
        assert len(list(reader)) == admitted.packets

    admitted_ng = nf.admit_capture(modern)
    assert admitted_ng is not None
    assert admitted_ng.format == "pcapng"
    assert admitted_ng.packets == 1
    assert len(list(dpkt.pcapng.Reader(io.BytesIO(modern)))) == admitted_ng.packets
    with PcapReader(io.BytesIO(modern)) as reader:
        assert len(list(reader)) == admitted_ng.packets

    assert nf.admit_capture(classic[:-1]) is None
    corrupt_ng = bytearray(modern)
    corrupt_ng[-1] ^= 1  # duplicated block length no longer agrees
    assert nf.admit_capture(bytes(corrupt_ng)) is None
    oversized_original_lie = bytearray(classic)
    struct.pack_into("<I", oversized_original_lie, 24 + 12, len(frame) - 1)
    assert nf.admit_capture(bytes(oversized_original_lie)) is None


def test_tcp_reassembly_disorder_retransmit_conflict_gap_and_checksum_decline():
    payload = b"GET /sequence HTTP/1.1\r\nHost: sequence.test\r\n\r\n"
    capture = tcp_capture(payload, b"", disorder=True)
    streams = nf.reassemble_tcp(capture)
    assert streams is not None and len(streams) == 1
    assert streams[0].data == payload
    assert streams[0].complete
    assert streams[0].retransmitted_bytes == min(8, len(payload))

    assert nf.reassemble_tcp(tcp_capture(payload, b"", conflict=True)) is None

    # A two-byte hole between captured ranges is never silently collapsed.
    gap_frames = [
        tcp_frame(CLIENT, SERVER, 41000, 80, 100, 0x02),
        tcp_frame(CLIENT, SERVER, 41000, 80, 101, 0x18, b"abc"),
        tcp_frame(CLIENT, SERVER, 41000, 80, 106, 0x18, b"def"),
        tcp_frame(CLIENT, SERVER, 41000, 80, 109, 0x11),
    ]
    assert nf.reassemble_tcp(pcap(gap_frames)) is None

    bad_checksum = bytearray(tcp_capture(payload, b""))
    first_record = 24 + 16
    tcp_checksum_offset = first_record + 14 + 20 + 16
    bad_checksum[tcp_checksum_offset:tcp_checksum_offset + 2] = b"\x12\x34"
    assert nf.reassemble_tcp(bytes(bad_checksum)) is None


def test_http_chunk_content_decode_pairing_objects_and_corrupt_decline():
    upload = b"DATA"
    request = (b"POST /drop/upload.bin HTTP/1.1\r\nHost: files.test\r\n"
               b"Content-Length: 4\r\n\r\n" + upload)
    compressed = gzip.compress(b"download-object")
    split = len(compressed) // 2
    chunks = (f"{split:x}\r\n".encode() + compressed[:split] + b"\r\n" +
              f"{len(compressed) - split:x};x=y\r\n".encode() + compressed[split:] +
              b"\r\n0\r\nX-Proof: complete\r\n\r\n")
    response = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                b"Content-Encoding: gzip\r\nContent-Disposition: attachment; filename=answer.bin\r\n\r\n" + chunks)

    req_messages = nf.decode_http_stream(request)
    resp_messages = nf.decode_http_stream(response)
    assert req_messages is not None and req_messages[0].body == upload
    assert resp_messages is not None and resp_messages[0].body == b"download-object"
    assert resp_messages[0].trailers == (("x-proof", "complete"),)

    objects = nf.reconstruct_http_objects(request, response)
    assert objects is not None
    assert [(obj.direction, obj.name, obj.data) for obj in objects] == [
        ("upload", "upload.bin", upload),
        ("download", "answer.bin", b"download-object"),
    ]
    assert all(obj.sha256 == hashlib.sha256(obj.data).hexdigest() for obj in objects)

    parsed = dpkt.http.Request(request)
    assert parsed.method == "POST" and parsed.body == upload

    assert nf.decode_http_stream(request[:-1]) is None
    assert nf.decode_http_stream(
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\na"
    ) is None
    assert nf.reconstruct_http_objects(request, response[:-1]) is None
    assert nf.decode_http_stream(b"HTTP/1.1 200 OK\r\n\r\nbody") is None
    close_delimited = nf.decode_http_stream(b"HTTP/1.0 200 OK\r\n\r\nbody", eof=True)
    assert close_delimited is not None and close_delimited[0].body == b"body"


def test_dns_messages_tcp_transactions_txt_and_label_object_with_declines():
    name = "payload.example"
    query = dns_query(name, qtype=16)
    response = dns_response(name, txt=b"CSCTF{dns_txt}")
    decoded_query = nf.decode_dns_message(query)
    decoded_response = nf.decode_dns_message(response)
    assert decoded_query is not None and not decoded_query.response
    assert decoded_response is not None and decoded_response.response
    assert decoded_response.answers[0].value == (b"CSCTF{dns_txt}",)

    independent = dpkt.dns.DNS(response)
    assert independent.id == decoded_response.ident
    assert independent.an[0].type == dpkt.dns.DNS_TXT

    tcp_stream = len(query).to_bytes(2, "big") + query + len(response).to_bytes(2, "big") + response
    tcp_messages = nf.decode_dns_tcp_stream(tcp_stream)
    assert tcp_messages == (decoded_query, decoded_response)

    datagrams = [
        nf.DNSDatagram(CLIENT, 53000, SERVER, 53, query, "udp", 1_000),
        nf.DNSDatagram(SERVER, 53, CLIENT, 53000, response, "udp", 1_250),
    ]
    transactions = nf.reconstruct_dns_transactions(datagrams)
    assert transactions is not None and transactions[0].latency_ns == 250
    assert transactions[0].query.questions == transactions[0].response.questions
    retransmitted = datagrams + [dataclasses.replace(datagrams[-1], timestamp_ns=1_300)]
    assert len(nf.reconstruct_dns_transactions(retransmitted) or ()) == 1

    txt_objects = nf.extract_dns_txt_objects([decoded_response])
    assert txt_objects is not None and txt_objects[0].data == b"CSCTF{dns_txt}"
    assert txt_objects[0].sha256 == hashlib.sha256(txt_objects[0].data).hexdigest()

    content = b"byte-exact-dns-tunnel-object"
    part_a, part_b = content[:12], content[12:]
    chunks = [
        nf.decode_dns_message(dns_chunk_query("exfil.test", 2, 2, part_b, 2)),
        nf.decode_dns_message(dns_chunk_query("exfil.test", 1, 2, part_a, 1)),
    ]
    assert all(chunks)
    rebuilt = nf.reconstruct_dns_label_object(
        chunks, "exfil.test", expected_sha256=hashlib.sha256(content).hexdigest()
    )
    assert rebuilt is not None and rebuilt.data == content

    assert nf.decode_dns_message(response[:-1]) is None
    assert nf.decode_dns_message(b"\x00" * 12 + b"junk") is None
    assert nf.decode_dns_tcp_stream(tcp_stream[:-1]) is None
    bad_datagrams = datagrams[:-1] + [dataclasses.replace(datagrams[-1], payload=response[:-1])]
    assert nf.reconstruct_dns_transactions(bad_datagrams) is None
    forged = dataclasses.replace(decoded_response, raw=decoded_response.raw[:-1])
    assert nf.extract_dns_txt_objects([forged]) is None
    assert nf.reconstruct_dns_label_object(chunks[:1], "exfil.test") is None
    assert nf.reconstruct_dns_label_object(chunks, "exfil.test", expected_sha256="00" * 32) is None


def test_smb2_complete_read_object_and_truncated_or_conflicting_decline():
    file_id = bytes(range(16))
    content = b"PK\x03\x04synthetic-smb-object"
    client_stream = (smb_create_request(r"evidence\payload.zip", 11) +
                     smb_read_request(file_id, len(content), 12))
    server_stream = (smb_create_response(file_id, len(content), 11) +
                     smb_read_response(content, 12))
    capture = tcp_capture(client_stream, server_stream, client_port=42000, server_port=445, disorder=True)
    objects = nf.reconstruct_smb2_files(capture)
    assert objects is not None and len(objects) == 1
    assert objects[0].protocol == "smb2"
    assert objects[0].direction == "download"
    assert objects[0].name == "payload.zip"
    assert objects[0].data == content
    assert objects[0].sha256 == hashlib.sha256(content).hexdigest()

    truncated_server = server_stream[:-1]
    assert nf.reconstruct_smb2_files(
        tcp_capture(client_stream, truncated_server, client_port=42001, server_port=445)
    ) is None
    assert nf.reconstruct_smb2_files(
        tcp_capture(client_stream, server_stream, client_port=42002, server_port=445, conflict=True)
    ) is None


def test_websocket_fragmentation_control_utf8_and_corrupt_decline():
    stream = (ws_frame(b"hel", opcode=1, fin=False) + ws_frame(b"lo", opcode=0) +
              ws_frame(b"probe", opcode=9) + ws_frame((1000).to_bytes(2, "big") + b"done", opcode=8))
    transcript = nf.decode_websocket_stream(stream, from_client=True)
    assert transcript is not None
    assert transcript.messages == (nf.WebSocketMessage(1, b"hello", "hello"),)
    assert transcript.pings == (b"probe",)
    assert transcript.close_code == 1000 and transcript.close_reason == "done"

    assert nf.decode_websocket_stream(ws_frame(b"unmasked", masked=False), from_client=True) is None
    assert nf.decode_websocket_stream(ws_frame(b"\xff", opcode=1), from_client=True) is None
    assert nf.decode_websocket_stream(ws_frame(b"unfinished", opcode=2, fin=False), from_client=True) is None
    assert nf.decode_websocket_stream(stream[:-1], from_client=True) is None


def test_http2_preface_frames_continuations_and_corrupt_decline():
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    stream = preface + h2_frame(4, 0, 0) + h2_frame(1, 0x04, 1, b"\x82")
    frames = nf.decode_http2_frames(stream, expect_preface=True)
    assert frames is not None
    assert [(frame.frame_type, frame.stream_id) for frame in frames] == [(4, 0), (1, 1)]

    fragmented_headers = (h2_frame(1, 0, 3, b"\x82") +
                          h2_frame(9, 0x04, 3, b"\x84"))
    assert nf.decode_http2_frames(fragmented_headers) is not None
    assert nf.decode_http2_frames(h2_frame(1, 0, 3, b"\x82") + h2_frame(0, 1, 3, b"x")) is None
    assert nf.decode_http2_frames(stream[:-1], expect_preface=True) is None
    invalid_setting = h2_frame(4, 0, 0, struct.pack("!HI", 2, 2))
    assert nf.decode_http2_frames(invalid_setting) is None
    assert nf.decode_http2_frames(h2_frame(6, 0, 1, b"12345678")) is None

    # Padding belongs after the priority/promised-stream fixed fields.  These frames
    # advertise so much padding that those mandatory fields fall inside padding.
    bad_padded_priority = h2_frame(1, 0x28, 3, b"\x04" + b"\x00" * 5)
    bad_padded_push = h2_frame(5, 0x08, 3, b"\x04" + b"\x00" * 4)
    assert nf.decode_http2_frames(bad_padded_priority) is None
    assert nf.decode_http2_frames(bad_padded_push) is None

    good_padded_priority = h2_frame(
        1, 0x2C, 3, b"\x01" + (1).to_bytes(4, "big") + b"\x10\x82\x00"
    )
    good_padded_push = h2_frame(
        5, 0x0C, 3, b"\x01" + (5).to_bytes(4, "big") + b"\x82\x00"
    )
    assert nf.decode_http2_frames(good_padded_priority) is not None
    assert nf.decode_http2_frames(good_padded_push) is not None


@pytest.mark.parametrize("bad", [None, 0, 10**100, object(), [], {}, "text", bytearray(b"x")])
def test_public_api_parameter_type_matrix_fails_closed(bad):
    request = b"GET / HTTP/1.1\r\nHost: type.test\r\n\r\n"
    response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
    query = dns_query("type.test")
    frame = udp_frame(CLIENT, SERVER, 53000, 53, query)
    capture = pcap([frame])
    random = b"T" * 32
    secret = b"S" * 32
    keys = keylog(random, secret)

    byte_decoders = [
        lambda: nf.admit_capture(bad),
        lambda: nf.reassemble_tcp(bad),
        lambda: nf.decode_http_stream(bad),
        lambda: nf.reconstruct_http_objects(bad, response),
        lambda: nf.reconstruct_http_objects(request, bad),
        lambda: nf.decode_dns_message(bad),
        lambda: nf.decode_dns_tcp_stream(bad),
        lambda: nf.reconstruct_dns_transactions(bad),
        lambda: nf.extract_dns_txt_objects(bad),
        lambda: nf.reconstruct_dns_label_object(bad, "type.test"),
        lambda: nf.reconstruct_smb2_files(bad),
        lambda: nf.decode_websocket_stream(bad, from_client=True),
        lambda: nf.decode_http2_frames(bad),
        lambda: nf.parse_keylog(bad),
        lambda: nf.plan_tls_decryption(bad, keys),
        lambda: nf.plan_tls_decryption(capture, bad),
        lambda: nf.plan_quic_decryption(bad, keys),
        lambda: nf.plan_quic_decryption(capture, bad),
        lambda: nf.decrypt_tls13(bad, keys, random, "CLIENT_TRAFFIC_SECRET_0", 0x1301),
        lambda: nf.decrypt_quic_packet(bad, keys, random, "CLIENT_TRAFFIC_SECRET_0", 0x1301,
                                       dcid_length=4),
    ]
    for decoder in byte_decoders:
        assert decoder() is None

    message = nf.decode_http_stream(request)[0]
    parsed_keys = nf.parse_keylog(keys)
    assert message.header(bad) is None
    assert parsed_keys is not None and parsed_keys.secret(bad, "CLIENT_TRAFFIC_SECRET_0") is None
    assert parsed_keys.secret(random, bad) is None


def test_public_api_keyword_and_forged_record_types_fail_closed():
    request = b"GET / HTTP/1.1\r\nHost: type.test\r\n\r\n"
    response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
    query = dns_query("type.test")
    capture = pcap([udp_frame(CLIENT, SERVER, 53000, 53, query)])
    h2 = h2_frame(4, 0, 0)
    ws = ws_frame(b"x")
    random, secret = b"T" * 32, b"S" * 32
    keys = keylog(random, secret)

    assert nf.admit_capture(capture, crosscheck="yes") is None
    assert nf.decode_http_stream(request, eof=1) is None
    assert nf.reconstruct_http_objects(request, response, server_eof=object()) is None
    assert nf.decode_dns_message(query, tcp="udp") is None
    assert nf.decode_websocket_stream(ws, from_client=1) is None
    assert nf.decode_http2_frames(h2, expect_preface=1) is None

    decoded = nf.decode_dns_message(query)
    assert decoded is not None
    for suffix in (None, 1, b"type.test", [], {}):
        assert nf.reconstruct_dns_label_object([decoded], suffix) is None
    for digest in (1, b"00", [], {}):
        assert nf.reconstruct_dns_label_object([decoded], "type.test", expected_sha256=digest) is None
    assert nf.reconstruct_dns_label_object(None, "type.test") is None

    base = nf.DNSDatagram(CLIENT, 53000, SERVER, 53, query)
    forged = [
        dataclasses.replace(base, src=[]),
        dataclasses.replace(base, sport="53000"),
        dataclasses.replace(base, payload="dns"),
        dataclasses.replace(base, timestamp_ns="now"),
    ]
    for row in forged:
        assert nf.reconstruct_dns_transactions([row]) is None

    huge_integer = 10**100
    assert nf.plan_quic_decryption(capture, keys, client_random=huge_integer) is None
    assert nf.decrypt_tls13(b"record", keys, huge_integer,
                            "CLIENT_TRAFFIC_SECRET_0", 0x1301) is None
    assert nf.decrypt_quic_packet(b"packet", keys, huge_integer,
                                  "CLIENT_TRAFFIC_SECRET_0", 0x1301, dcid_length=4) is None
    assert nf.decrypt_tls13(b"record", keys, random,
                            "CLIENT_TRAFFIC_SECRET_0", [], search_updates=[]) is None
    assert nf.decrypt_quic_packet(b"packet", keys, random,
                                  "CLIENT_TRAFFIC_SECRET_0", 0x1301,
                                  dcid_length=[], largest_packet_number=[], search_updates=[]) is None


def test_keylog_strict_parse_conflicts_and_malformed_decline():
    random = bytes(range(32))
    secret = bytes(range(32, 64))
    material = (b"# synthetic keys only\n" + keylog(random, secret) +
                keylog(random, secret))
    parsed = nf.parse_keylog(material)
    assert parsed is not None and len(parsed.entries) == 1
    assert parsed.secret(random, "CLIENT_TRAFFIC_SECRET_0") == secret
    assert parsed.secret(random.hex(), "CLIENT_TRAFFIC_SECRET_0") == secret

    conflicting = material + keylog(random, b"Z" * 32)
    assert nf.parse_keylog(conflicting) is None
    assert nf.parse_keylog(b"CLIENT_TRAFFIC_SECRET_0 nothex also-not-hex\n") is None
    assert nf.parse_keylog(b"UNSUPPORTED_LABEL " + random.hex().encode() + b" " + secret.hex().encode()) is None
    assert nf.parse_keylog(b"\xff\n") is None


def test_tls_and_quic_offline_plans_correlate_only_supplied_secrets():
    random = bytes(range(32))
    secret = bytes(reversed(range(32)))
    keys = keylog(random, secret)
    capture = tcp_capture(tls_client_hello(random), tls_server_hello(),
                          client_port=44300, server_port=443)
    plans = nf.plan_tls_decryption(capture, keys)
    assert plans is not None and len(plans) == 1
    assert plans[0].protocol == "tls"
    assert plans[0].client_random == random.hex()
    assert plans[0].cipher_suite == 0x1301
    assert plans[0].engine == "network_ics_depth.decrypt_tls13_keylog"
    assert nf.plan_tls_decryption(capture, keylog(b"X" * 32, secret)) is None
    assert nf.plan_tls_decryption(capture[:-1], keys) is None

    fake_quic = b"\xc0\x00\x00\x00\x01\x08QUICDCID\x00" + b"\x00" * 20
    quic_capture = pcap([udp_frame(CLIENT, SERVER, 44000, 443, fake_quic)])
    plan = nf.plan_quic_decryption(quic_capture, keys)
    assert plan is not None
    assert plan.protocol == "quic" and plan.packet_count == 1
    assert plan.client_random == random.hex()
    not_quic = bytearray(fake_quic)
    not_quic[0] &= ~0x40
    assert nf.plan_quic_decryption(
        pcap([udp_frame(CLIENT, SERVER, 44000, 443, bytes(not_quic))]), keys
    ) is None
    assert nf.plan_quic_decryption(quic_capture, keys, client_random=b"Y" * 32) is None


def make_tls13_ciphertext(secret: bytes, content: bytes) -> bytes:
    kind, _hash_name, key, iv = depth._traffic_keys(secret, 0x1301)
    assert kind == "aesgcm"
    inner = content + b"\x17" + b"\x00\x00"
    header = b"\x17\x03\x03" + (len(inner) + 16).to_bytes(2, "big")
    ciphertext = AESGCM(key).encrypt(depth._nonce(iv, 0), inner, header)
    return header + ciphertext


def make_quic_short_ciphertext(secret: bytes, plaintext: bytes = b"\x01\x00\x00\x00") -> bytes:
    suite = 0x1301
    dcid = b"\x01\x02\x03\x04"
    packet_number = 0
    first = 0x40  # fixed bit, key phase zero, one-byte packet number
    pn = b"\x00"
    header = bytes([first]) + dcid + pn
    kind, hash_name, key, iv = depth._traffic_keys(secret, suite, quic=True)
    assert kind == "aesgcm" and hash_name == "sha256"
    ciphertext = AESGCM(key).encrypt(depth._nonce(iv, packet_number), plaintext, header)
    packet = bytearray(header + ciphertext)
    hp_key = depth.tls._hkdf_expand_label(secret, b"quic hp", b"", 16, "sha256")
    pn_offset = 1 + len(dcid)
    sample_offset = pn_offset + 4
    sample = bytes(packet[sample_offset:sample_offset + 16])
    assert len(sample) == 16
    encryptor = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    mask = (encryptor.update(sample) + encryptor.finalize())[:5]
    packet[0] ^= mask[0] & 0x1F
    packet[pn_offset] ^= mask[1]
    return bytes(packet)


def test_authenticated_tls13_decryption_and_tag_corruption_decline():
    random = b"R" * 32
    secret = bytes(range(32))
    keys = keylog(random, secret)
    record = make_tls13_ciphertext(secret, b"authenticated tls content")
    decoded = nf.decrypt_tls13(record, keys, random, "CLIENT_TRAFFIC_SECRET_0", 0x1301)
    assert decoded is not None
    assert decoded.records == (b"authenticated tls content",)
    assert decoded.content_types == (23,)

    corrupt = bytearray(record)
    corrupt[-1] ^= 1
    assert nf.decrypt_tls13(bytes(corrupt), keys, random,
                            "CLIENT_TRAFFIC_SECRET_0", 0x1301) is None
    assert nf.decrypt_tls13(record[:-1], keys, random,
                            "CLIENT_TRAFFIC_SECRET_0", 0x1301) is None
    assert nf.decrypt_tls13(record, keys, random,
                            "SERVER_TRAFFIC_SECRET_0", 0x1301) is None


def test_authenticated_quic_decryption_and_tag_corruption_decline():
    random = b"Q" * 32
    secret = bytes(range(31, -1, -1))
    keys = keylog(random, secret)
    packet = make_quic_short_ciphertext(secret)
    decoded = nf.decrypt_quic_packet(
        packet, keys, random, "CLIENT_TRAFFIC_SECRET_0", 0x1301, dcid_length=4
    )
    assert decoded is not None
    assert decoded.packet_number == 0
    assert decoded.plaintext == b"\x01\x00\x00\x00"
    assert decoded.frames is not None
    assert decoded.frames[0]["name"] == "ping"

    corrupt = bytearray(packet)
    corrupt[-1] ^= 1
    assert nf.decrypt_quic_packet(
        bytes(corrupt), keys, random, "CLIENT_TRAFFIC_SECRET_0", 0x1301, dcid_length=4
    ) is None
    assert nf.decrypt_quic_packet(
        packet, keys, random, "CLIENT_TRAFFIC_SECRET_0", 0x1301
    ) is None
    assert nf.decrypt_quic_packet(
        packet, keylog(b"Z" * 32, secret), random,
        "CLIENT_TRAFFIC_SECRET_0", 0x1301, dcid_length=4
    ) is None
