#!/usr/bin/env python3
"""Offline tests of solvers/common/tls_keylog.py: in-process TLS decryption when the session keys
ship in the delivery, and the never-wrong boundary.

  .venv/bin/python tests/test_tls_keylog_decrypt.py

No network, no token. The fixtures are built here by a REAL OpenSSL handshake over ssl.MemoryBIO
(so the ciphertext and the NSS key log come from the library, not from the module under test), the
wire bytes are framed into a pcap, and the key log is shipped as a member beside it. The module
must recover exactly what was sent. The labels ledger is a fresh temporary folder, so no accepted
name can turn an unsure answer plain.

  [A] TLS 1.2 AES-128-GCM: the recovered GET path and the transferred file's sha256+size equal
      ground truth; solve_set answers method/host/path/status/content-type UNSURE (never plain),
      and the named file's sha256+size PLAIN and byte-exact.
  [B] TLS 1.3 (AES-128-GCM-SHA256): the same assertions.
  [C] the same pcap with NO key log member => facts decrypted False, every solve_set id None.
  [D] one byte flipped in an application-data record => its tag fails => that request is absent
      (the GET path is None), never a partial or guessed read.
  [E] a flag in the plaintext is text-is-data: reported in the facts, never answered (id None).
"""
import hashlib
import os
import ssl
import struct
import sys
import tempfile
from pathlib import Path

os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="tlskeylog_")
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))

import tls_keylog as tk          # noqa: E402

from cryptography import x509    # noqa: E402
from cryptography.x509.oid import NameOID   # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization   # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa          # noqa: E402
import datetime                  # noqa: E402

CLIENT_IP, SERVER_IP = "10.0.0.1", "10.0.0.2"
CLIENT_PORT, SERVER_PORT = 44321, 443

_failures = []


def check(name, cond):
    print(("ok   " if cond else "FAIL ") + name)
    if not cond:
        _failures.append(name)


# ---- a self-signed cert, made once -----------------------------------------------------------------

def _make_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), False)
            .sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp(prefix="tlscert_")
    cert_pem = Path(d) / "cert.pem"
    key_pem = Path(d) / "key.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return str(cert_pem), str(key_pem)


_CERT, _KEY = _make_cert()


def tls_exchange(version, ciphers, request, response):
    """Run a real handshake + one request/response over MemoryBIO. Returns (wire_chunks, keylog
    bytes), wire_chunks a list of (direction 'c2s'|'s2c', bytes)."""
    keylog_path = Path(tempfile.mkdtemp(prefix="keylog_")) / "sslkeylog.txt"
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.minimum_version = sctx.maximum_version = version
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.check_hostname = False
    cctx.verify_mode = ssl.CERT_NONE
    cctx.minimum_version = cctx.maximum_version = version
    if ciphers:
        sctx.set_ciphers(ciphers)
        cctx.set_ciphers(ciphers)
    sctx.load_cert_chain(_CERT, _KEY)
    cctx.keylog_filename = str(keylog_path)
    sctx.keylog_filename = str(keylog_path)

    cin, cout = ssl.MemoryBIO(), ssl.MemoryBIO()
    sin, sout = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = cctx.wrap_bio(cin, cout, server_hostname="example.test")
    server = sctx.wrap_bio(sin, sout, server_side=True)
    chunks = []

    def pump():
        d = cout.read()
        if d:
            chunks.append(("c2s", d))
            sin.write(d)
        d = sout.read()
        if d:
            chunks.append(("s2c", d))
            cin.write(d)

    chd = shd = False
    for _ in range(40):
        if not chd:
            try:
                client.do_handshake()
                chd = True
            except ssl.SSLWantReadError:
                pass
        pump()
        if not shd:
            try:
                server.do_handshake()
                shd = True
            except ssl.SSLWantReadError:
                pass
        pump()
        if chd and shd:
            break
    assert chd and shd, "handshake did not complete"

    client.write(request)
    pump()
    got = b""
    while len(got) < len(request):
        try:
            got += server.read(65536)
        except ssl.SSLWantReadError:
            break
    server.write(response)
    pump()
    # drain any post-handshake tickets the server sent as application records
    for _ in range(4):
        pump()
    keylog = keylog_path.read_bytes()
    return chunks, keylog


# ---- pcap framing ----------------------------------------------------------------------------------

def _ipv4_tcp(src, sport, dst, dport, seq, payload):
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 1, (5 << 4), 0x18, 65535, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0, 64, 6, 0)
    ip += bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split("."))
    return ip + tcp


def build_pcap(chunks, mss=1400):
    """A little-endian pcap (linktype RAW IPv4) carrying the wire chunks as in-order TCP segments."""
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
    cseq = sseq = 1
    ts = 0
    for direction, data in chunks:
        for off in range(0, len(data), mss):
            seg = data[off:off + mss]
            if direction == "c2s":
                pkt = _ipv4_tcp(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, cseq, seg)
                cseq += len(seg)
            else:
                pkt = _ipv4_tcp(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT, sseq, seg)
                sseq += len(seg)
            ts += 1
            out += struct.pack("<IIII", ts, 0, len(pkt), len(pkt)) + pkt
    return bytes(out)


# ---- the fixtures ----------------------------------------------------------------------------------

GET_PATH = "/secret/quarterly/report.txt"
BODY = b"CONFIDENTIAL QUARTERLY REPORT\nrevenue: 1234567\n" * 97
BODY_SHA = hashlib.sha256(BODY).hexdigest()
REQUEST = (f"GET {GET_PATH} HTTP/1.1\r\nHost: files.example.test\r\n"
           "User-Agent: curl/8.0\r\nAccept: */*\r\n\r\n").encode()
RESPONSE = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Disposition: attachment; filename=\"report.txt\"\r\n"
            b"Content-Length: " + str(len(BODY)).encode() + b"\r\n\r\n" + BODY)


def q(qid, question, syntax=""):
    return {"qid": qid, "answer_id": qid, "question": question,
            "answer_format": {"syntax": syntax}}


def run_case(label, version, ciphers):
    chunks, keylog = tls_exchange(version, ciphers, REQUEST, RESPONSE)
    pcap = build_pcap(chunks)
    files = {"evidence.pcap": pcap, "sslkeylog.txt": keylog}

    f = tk.facts(files)
    check(f"[{label}] decrypted", f["decrypted"])
    paths = [r.get("path") for r in f["requests"]]
    check(f"[{label}] GET path recovered exactly", GET_PATH in paths)
    methods = [r.get("method") for r in f["requests"]]
    check(f"[{label}] method GET recovered", "GET" in methods)
    hosts = [r.get("host") for r in f["requests"]]
    check(f"[{label}] Host header recovered", "files.example.test" in hosts)
    obj = next((o for o in f["objects"] if o.get("name") == "report.txt"), None)
    check(f"[{label}] transferred object present and complete", obj is not None)
    if obj:
        check(f"[{label}] object sha256 == ground truth", obj["sha256"] == BODY_SHA)
        check(f"[{label}] object size == ground truth", obj["size"] == len(BODY))
    statuses = [r.get("status") for r in f["responses"]]
    check(f"[{label}] status 200 recovered", 200 in statuses)

    # solve_set never-wrong: facts-derived picks are unsure; the named digest/size are plain & exact.
    questions = [
        q("m", "What HTTP method did the client use?"),
        q("h", "What host did the client request?"),
        q("p", "What path did the client GET?"),
        q("s", "What status code did the server return?"),
        q("ct", "What Content-Type did the server send?"),
        q("sha", "What is the sha256 of report.txt?"),
        q("sz", "What is the size of report.txt in bytes?"),
    ]
    ans = tk.solve_set(questions, files, {})
    for uid in ("m", "h", "p", "s", "ct"):
        v = ans[uid]
        check(f"[{label}] {uid} is unsure (never plain)", isinstance(v, str) and v.startswith("??"))
    check(f"[{label}] sha256 answer is PLAIN and byte-exact", ans["sha"] == BODY_SHA)
    check(f"[{label}] size answer is PLAIN and byte-exact", ans["sz"] == len(BODY))
    return chunks, keylog, pcap


def main():
    # [A] TLS 1.2 AES-128-GCM
    chunks12, keylog12, pcap12 = run_case("A tls1.2-gcm", ssl.TLSVersion.TLSv1_2, "ECDHE-RSA-AES128-GCM-SHA256")
    # [B] TLS 1.3
    run_case("B tls1.3", ssl.TLSVersion.TLSv1_3, None)

    # [C] no key log => None everywhere
    files_nokey = {"evidence.pcap": pcap12}
    f = tk.facts(files_nokey)
    check("[C] no key log: decrypted False", not f["decrypted"])
    check("[C] no key log: no requests", not f["requests"])
    questions = [q("m", "What HTTP method did the client use?"),
                 q("p", "What path did the client GET?"),
                 q("sha", "What is the sha256 of report.txt?")]
    ans = tk.solve_set(questions, files_nokey, {})
    check("[C] no key log: every id None", all(ans[i] is None for i in ("m", "p", "sha")))

    # [D] one-byte-corrupted application-data record => tag fails => request absent (None)
    # Corrupt a byte well inside the first client->server application record (the encrypted GET).
    corrupt = bytearray(pcap12)
    # find the client's GET application data: the largest c2s chunk after the handshake carries it;
    # flip a byte deep in the last c2s chunk's tail (ciphertext), which lands inside an app record.
    c2s_offsets = []
    off = 24
    while off + 16 <= len(corrupt):
        _, _, caplen, _ = struct.unpack("<IIII", corrupt[off:off + 16])
        pkt_off = off + 16
        if pkt_off + 20 > len(corrupt):
            break
        src = ".".join(str(b) for b in corrupt[pkt_off + 12:pkt_off + 16])   # IPv4 src (RAW linktype)
        if src == CLIENT_IP:
            c2s_offsets.append((pkt_off, caplen))
        off = pkt_off + caplen
    # the last client segment holds the GET ciphertext tail; flip a byte near its end
    tgt_off, tgt_len = c2s_offsets[-1]
    flip = tgt_off + tgt_len - 8          # inside the AEAD ciphertext/tag region
    corrupt[flip] ^= 0x01
    files_corrupt = {"evidence.pcap": bytes(corrupt), "sslkeylog.txt": keylog12}
    fc = tk.facts(files_corrupt)
    check("[D] corrupted GET record no longer decrypts to the GET path",
          GET_PATH not in [r.get("path") for r in fc["requests"]])
    ansd = tk.solve_set([q("p", "What path did the client GET?")], files_corrupt, {})
    check("[D] corrupted: path answer is None (no guess)", ansd["p"] is None)

    # [E] a flag in the plaintext is text-is-data: reported, never answered
    flag_resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 36\r\n\r\n"
                 b"welcome flag{do_not_submit_me_12345}")
    ch, kl = tls_exchange(ssl.TLSVersion.TLSv1_2, "ECDHE-RSA-AES128-GCM-SHA256",
                          b"GET /login HTTP/1.1\r\nHost: x\r\n\r\n", flag_resp)
    files_flag = {"c.pcap": build_pcap(ch), "keys.txt": kl}
    ff = tk.facts(files_flag)
    check("[E] flag reported in plaintext facts",
          any("flag{" in s["value"] for s in ff["secrets_in_plaintext"]))
    ansf = tk.solve_set([q("fl", "What is the flag?")], files_flag, {})
    check("[E] flag id answered None (never submitted)", ansf["fl"] is None)

    # [F] never-guess boundary of the only PLAIN path: a question that NAMES a file which was
    # NOT transferred must not be answered from an unrelated sole object (a wrong plain digest).
    # pcap12 transferred exactly one object, report.txt; ask about an absent secret.bin.
    files_one = {"evidence.pcap": pcap12, "sslkeylog.txt": keylog12}
    absent = tk.solve_set([q("sha", "What is the sha256 of secret.bin?"),
                           q("sz", "What is the size of secret.bin in bytes?")], files_one, {})
    check("[F] sha256 of an ABSENT named file is None (no wrong plain)", absent["sha"] is None)
    check("[F] size of an ABSENT named file is None (no wrong plain)", absent["sz"] is None)
    # and the genuine single-value case for the file that IS present stays correct & plain
    present = tk.solve_set([q("sha", "What is the sha256 of report.txt?"),
                            q("sz", "What is the size of report.txt in bytes?")], files_one, {})
    check("[F] sha256 of the PRESENT named file is plain & byte-exact", present["sha"] == BODY_SHA)
    check("[F] size of the PRESENT named file is plain & byte-exact", present["sz"] == len(BODY))
    # a version-number token in the question must not block the sole-object fallback (no false None)
    ver = tk.solve_set([q("sz", "What is the size of the file sent over HTTP/1.1 in bytes?")], files_one, {})
    check("[F] version token does not cause a false None", ver["sz"] == len(BODY))

    print()
    if _failures:
        print(f"{len(_failures)} FAILED: " + "; ".join(_failures))
        return 1
    print("all tls_keylog tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
