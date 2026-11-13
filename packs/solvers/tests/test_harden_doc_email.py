"""Independent MIME/SQLite vectors and deterministic email parser robustness.

The toolkit email.py intentionally proxies the stdlib when imported by basename;
load it with a private alias so BytesParser remains an independent stdlib oracle.
No messages are sent and no HTML, attachment, or supplied source is executed.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
import hashlib
import importlib.util
import io
import mailbox
from pathlib import Path
import random
import re
import sqlite3
import sys

import pytest

import email_chat_forensics as messaging


_PATH = Path(__file__).resolve().parents[1] / "solvers/toolkits/email.py"
_SPEC = importlib.util.spec_from_file_location("_harden_doc_email_tool", _PATH)
mailtool = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = mailtool
_SPEC.loader.exec_module(mailtool)

PAYLOAD = b"\x00CSCTF{M1ME_Exact_Bytes}\xff\x10"
DATE = "Fri, 06 Nov 2026 13:00:00 +0000"


def make_email(identifier="root@example.invalid", *, parent=None, attachment=True):
    """Stdlib serializer, explicit MIME boundaries, no engine encoders."""
    msg = EmailMessage(policy=policy.SMTP)
    msg["From"] = '"Alice, Analyst" <alice@example.invalid>'
    msg["To"] = "Bob <bob@example.invalid>"
    msg["Cc"] = "Carol <carol@example.invalid>"
    msg["Subject"] = "Evidence — café"
    msg["Date"] = DATE
    msg["Message-ID"] = f"<{identifier}>"
    if parent is not None:
        msg["In-Reply-To"] = f"<{parent}>"
        msg["References"] = f"<{parent}>"
    msg["Received"] = "from relay.example.invalid (relay.example.invalid [192.0.2.4]) by mx.example.invalid with ESMTP id ABC123 for <bob@example.invalid>; " + DATE
    msg["X-Originating-IP"] = "[192.0.2.4]"
    msg["Authentication-Results"] = "mx.example.invalid; spf=pass smtp.mailfrom=alice@example.invalid; dkim=pass header.d=example.invalid; dmarc=pass header.from=example.invalid"
    msg.set_content("CSCTF{Plain_Body}\nVisit https://evidence.example.invalid/report?q=1", cte="quoted-printable")
    if attachment:
        msg.add_attachment(PAYLOAD, maintype="application", subtype="octet-stream", filename="preuve-é.bin")
        msg.set_boundary("harden-doc-fixed-boundary")
    return msg.as_bytes()


def _oracle(raw):
    return BytesParser(policy=policy.default).parsebytes(raw)


def test_eml_headers_mime_and_load_vector_lock():
    raw = make_email()
    expected = _oracle(raw)
    actual = mailtool.parse_eml(raw, "evidence.eml")
    assert not actual.doubt
    for header in ("Subject", "Message-ID", "Date", "From", "To", "Cc"):
        assert actual.get(header) == str(expected[header])
    assert actual.get_all("Received") == [str(x) for x in expected.get_all("Received")]
    assert actual.raw_all("Message-ID") == [str(expected["Message-ID"])]
    body = expected.get_body(preferencelist=("plain",))
    assert actual.bodies[0]["text"] == body.get_content()
    attachment = next(expected.iter_attachments())
    got = actual.attachments[0]
    assert got["data"] == attachment.get_payload(decode=True) == PAYLOAD
    assert got["filename"] == attachment.get_filename()
    assert got["declared_type"] == attachment.get_content_type()
    assert got["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
    assert got["size"] == len(PAYLOAD) and got["exact"] is True
    assert mailtool.sniff(raw) == "eml"
    loaded = mailtool.load(raw, "evidence.eml")
    assert len(loaded) == 1 and loaded[0].attachments[0]["data"] == PAYLOAD


def test_addresses_received_auth_and_dates_vector_lock():
    raw = make_email()
    expected = _oracle(raw)
    mail = mailtool.parse_eml(raw)
    addresses = mailtool.addresses(mail)
    for key, header in (("from", "From"), ("to", "To"), ("cc", "Cc")):
        assert addresses[key] == getaddresses([str(expected[header])])
    hop = mailtool.received_chain(mail)[0]
    assert hop["from"] == "relay.example.invalid"
    assert hop["by"] == "mx.example.invalid"
    assert hop["ips"] == ["192.0.2.4"]
    assert hop["with"] == "ESMTP" and hop["id"] == "ABC123"
    assert hop["for"] == "bob@example.invalid"
    assert parsedate_to_datetime(hop["date"]) == parsedate_to_datetime(DATE)
    assert mailtool.originating(mail)["ip"] == "192.0.2.4"
    auth = mailtool.auth_results(mail)
    for method in ("spf", "dkim", "dmarc"):
        assert auth[method]["result"] == "pass"
    assert auth["dkim"]["props"]["header.d"] == "example.invalid"
    dt = parsedate_to_datetime(str(expected["Date"]))
    dates = dict(mailtool.date_forms(str(expected["Date"])))
    assert dates["iso_offset"] == dt.isoformat()
    assert dates["epoch"] == str(int(dt.timestamp()))


def test_url_helpers_and_triage_vector_lock():
    mail = mailtool.parse_eml(make_email())
    urls = mailtool.urls(mail, qr=False)
    assert [x["url"] for x in urls] == ["https://evidence.example.invalid/report?q=1"]
    assert mailtool.refang("hxxps://example[.]invalid/a") == "https://example.invalid/a"
    assert mailtool.defang("https://example.invalid/a") == "hxxps://example[.]invalid/a"
    assert mailtool.is_defanged("hxxps://example[.]invalid/a") is True
    assert mailtool.url_host("https://example.invalid:443/a") == "example.invalid"
    assert mailtool.domain_of("Alice@Example.Invalid") == "example.invalid"
    # RFC3492's standard German label example, plus stdlib IDNA oracle.
    domain = "bücher.example"
    form = mailtool.idn_forms(domain)
    assert form["punycode"] == domain.encode("idna").decode()
    assert form["unicode"] == domain
    assert mailtool.skeleton("café") == "cafe"
    summary = mailtool.triage(mail, qr=False)
    assert summary["sha256"] == hashlib.sha256(mail.raw).hexdigest()
    assert summary["subject"] == "Evidence — café"
    assert summary["attachments"][0]["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
    assert mailtool.ext_mismatch(mail.attachments[0]) is None
    assert "Evidence — café" in mailtool.report(mail, qr=False)


def test_smuggling_static_literal_matches_base64_library():
    encoded = base64.b64encode(PAYLOAD).decode()
    msg = EmailMessage(policy=policy.SMTP)
    msg["From"], msg["To"], msg["Subject"] = "a@example.invalid", "b@example.invalid", "Static HTML"
    msg.set_content(f'<script>const bytes=atob("{encoded}");</script><a download="evidence.bin">save</a>', subtype="html")
    mail = mailtool.parse_eml(msg.as_bytes())
    found = mailtool.smuggling(mail)
    assert len(found) == 1
    assert found[0]["payloads"][0]["data"] == base64.b64decode(encoded, validate=True)
    assert found[0]["download_names"] == ["evidence.bin"]


def test_email_artifact_vector_lock():
    raw = make_email()
    oracle = _oracle(raw)
    result = messaging.decode_email_artifact(raw)
    assert result is not None and result.kind == "eml"
    msg = result.messages[0]
    assert result.sha256 == hashlib.sha256(raw).hexdigest()
    assert msg.message_id == str(oracle["Message-ID"])[1:-1]
    assert msg.subject == str(oracle["Subject"])
    assert msg.sender == str(oracle["From"])
    assert msg.recipients == (str(oracle["To"]), str(oracle["Cc"]))
    assert msg.date == parsedate_to_datetime(str(oracle["Date"])).astimezone(timezone.utc).isoformat()
    assert msg.objects[0].data == next(oracle.iter_attachments()).get_payload(decode=True)
    assert msg.objects[0].filename == next(oracle.iter_attachments()).get_filename()


def test_mbox_vector_lock_against_mailbox(tmp_path):
    one = make_email(attachment=False).replace(b"\r\n", b"\n")
    two = make_email("reply@example.invalid", parent="root@example.invalid", attachment=False).replace(b"\r\n", b"\n")
    separator = b"From alice@example.invalid Fri Nov  6 13:00:00 2026\n"
    raw = separator + one.rstrip(b"\n") + b"\n\n" + separator + two
    path = tmp_path / "reference.mbox"
    path.write_bytes(raw)
    expected_box = mailbox.mbox(path, create=False)
    try:
        expected = list(expected_box)
    finally:
        expected_box.close()
    actual = mailtool.parse_mbox(raw, "reference.mbox")
    assert len(actual) == len(expected) == 2
    assert [m.get("Message-ID") for m in actual] == [m["Message-ID"] for m in expected]
    assert mailtool.sniff(raw) == "mbox"
    assert len(mailtool.load(raw)) == 2
    strict = messaging.decode_email_artifact(raw, name="reference.mbox")
    assert strict is not None and len(strict.messages) == 2


def test_threads_vector_lock_from_rfc_header_relations():
    raw = [make_email(attachment=False), make_email("reply@example.invalid", parent="root@example.invalid", attachment=False)]
    parsed = [_oracle(r) for r in raw]
    expected_edge = (str(parsed[1]["In-Reply-To"])[1:-1], str(parsed[1]["Message-ID"])[1:-1])
    threads = messaging.build_email_threads(raw)
    assert len(threads) == 1
    assert threads[0].root_id == str(parsed[0]["Message-ID"])[1:-1]
    assert threads[0].edges == (expected_edge,)


def make_chat():
    """SQLite itself serializes the file and queries the reference rows."""
    with sqlite3.connect(":memory:") as db:
        db.executescript("""
          CREATE TABLE threads(id INTEGER PRIMARY KEY, title TEXT);
          CREATE TABLE messages(id INTEGER PRIMARY KEY, thread_id INTEGER, sender TEXT,
             body TEXT, timestamp_ms INTEGER, from_me INTEGER);
          CREATE TABLE attachments(id INTEGER PRIMARY KEY, message_id INTEGER, filename TEXT,
             mime TEXT, data BLOB, sha256 TEXT);
        """)
        db.execute("INSERT INTO threads VALUES(?,?)", (3, "Evidence"))
        db.execute("INSERT INTO messages VALUES(?,?,?,?,?,?)", (7, 3, "Alice", "CSCTF{sqlite_row}", 1793970000000, 0))
        db.execute("INSERT INTO attachments VALUES(?,?,?,?,?,?)", (11, 7, "test.bin", "application/octet-stream", PAYLOAD, hashlib.sha256(PAYLOAD).hexdigest()))
        db.commit()
        rows = db.execute("SELECT id,thread_id,sender,body,timestamp_ms,from_me FROM messages").fetchall()
        return db.serialize(), rows


def test_chat_vector_lock_against_sqlite():
    raw, rows = make_chat()
    result = messaging.decode_chat_database(raw)
    assert result is not None and result.schema == "generic_chat"
    assert result.threads == (("3", "Evidence"),)
    row = rows[0]
    msg = result.messages[0]
    assert (msg.identifier, msg.thread_id, msg.sender, msg.text) == (str(row[0]), str(row[1]), row[2], row[3])
    assert msg.timestamp == datetime.fromtimestamp(row[4] / 1000, timezone.utc).isoformat()
    assert msg.from_me is bool(row[5])
    assert result.attachments[0].data == PAYLOAD
    assert result.sha256 == hashlib.sha256(raw).hexdigest()


def _fuzz_bytes():
    rng = random.Random(0xE4A11)
    corpus = [b"", b"\xff", b"\xff" * 512]
    for magic in (b"%PDF-1.7\n", b"PK\x03\x04", bytes.fromhex("d0cf11e0a1b11ae1"), b"SQLite format 3\x00"):
        corpus.extend(magic[:n] for n in range(len(magic) + 1))
        corpus.extend(magic + rng.randbytes(n) for n in (0, 1, 7, 31, 511))
    corpus.extend(rng.randbytes(n) for n in (0, 1, 2, 7, 15, 31, 63, 127, 255, 512))
    valid = make_email()
    corpus.extend(valid[:n] for n in (1, 7, 15, 100, len(valid) // 2, len(valid) - 1))
    for offset in rng.sample(range(len(valid)), 16):
        changed = bytearray(valid)
        changed[offset] ^= 1 << (offset % 8)
        corpus.append(bytes(changed))
    return corpus


@pytest.mark.parametrize("reader", ["parse_eml", "parse_mbox", "sniff", "load", "cfb_streams", "parse_msg"])
def test_email_parse_entrypoints_fuzz_no_undeclared_exception(reader):
    function = getattr(mailtool, reader)
    for data in _fuzz_bytes():
        try:
            value = function(data)
        except ValueError as exc:
            # These two APIs explicitly document ValueError for non-CFB bytes;
            # subclasses such as UnicodeDecodeError are NOT accepted.
            assert reader in ("cfb_streams", "parse_msg") and type(exc) is ValueError
        else:
            assert value is not None


@pytest.mark.parametrize("reader", [messaging.decode_email_artifact, messaging.decode_chat_database])
def test_strict_byte_parsers_fuzz_never_throw(reader):
    for data in _fuzz_bytes():
        value = reader(data)
        assert value is None or isinstance(value, (messaging.EmailArtifact, messaging.ChatArchive))


def test_thread_fuzz_never_throws():
    for raw in _fuzz_bytes():
        result = messaging.build_email_threads([raw])
        assert result is None or isinstance(result, tuple)


def test_valid_chat_truncations_and_bitflips_never_throw():
    raw, _ = make_chat()
    for end in (1, 15, 16, 99, 511, len(raw) // 2, len(raw) - 1):
        assert messaging.decode_chat_database(raw[:end]) is None
    for position in (0, 8, 15, 16, 20, 99, 100, 511, len(raw) - 1):
        changed = bytearray(raw)
        changed[position] ^= 0x80
        result = messaging.decode_chat_database(bytes(changed))
        assert result is None or isinstance(result, messaging.ChatArchive)


def test_mail_inspectors_fuzz_never_throw():
    for raw in _fuzz_bytes():
        mail = mailtool.parse_eml(raw)
        for reader in (mailtool.received_chain, mailtool.originating, mailtool.auth_results,
                       mailtool.addresses, mailtool.mismatches, mailtool.urls,
                       mailtool.link_mismatches, mailtool.homoglyphs, mailtool.smuggling):
            reader(mail)


@pytest.mark.parametrize("bad", [None, True, 3, "text", [], {}])
def test_strict_parser_type_contract(bad):
    assert messaging.decode_email_artifact(bad) is None
    assert messaging.decode_chat_database(bad) is None
    assert messaging.build_email_threads(bad) is None


OVERFLOW_DATE = "Fri, 31 Dec 9999 23:59:59 -2359"


def test_date_forms_out_of_range_utc_fails_closed():
    # parsedate_to_datetime accepts the local date; normalizing it exceeds the
    # datetime range. A parser should return only the as-written candidate.
    assert mailtool.date_forms(OVERFLOW_DATE) == [("as_written", OVERFLOW_DATE)]


def test_email_artifact_out_of_range_utc_fails_closed():
    raw = ("From: a@example.invalid\r\nTo: b@example.invalid\r\nSubject: Date edge\r\n"
           "Message-ID: <edge@example.invalid>\r\nDate: " + OVERFLOW_DATE + "\r\n\r\nbody\r\n").encode()
    assert messaging.decode_email_artifact(raw) is None


def test_email_thread_out_of_range_utc_fails_closed():
    raw = ("From: a@example.invalid\r\nTo: b@example.invalid\r\nSubject: Date edge\r\n"
           "Message-ID: <edge@example.invalid>\r\nDate: " + OVERFLOW_DATE + "\r\n\r\nbody\r\n").encode()
    assert messaging.build_email_threads([raw]) is None


@pytest.mark.parametrize("value, expected", [
    ("Fri, 31 Dec 9999 00:00:00 -2359", datetime(9999, 12, 31, 23, 59, tzinfo=timezone.utc)),
    ("Mon, 01 Jan 0100 00:00:00 +2359", datetime(99, 12, 31, 0, 1, tzinfo=timezone.utc)),
])
def test_valid_extreme_dates_still_normalize(value, expected):
    # Explicit calendar arithmetic checks that the overflow guard preserves
    # representable dates near the parser's supported year boundaries.
    dates = dict(mailtool.date_forms(value))
    assert dates["epoch"] == str(int(expected.timestamp()))
    raw = ("From: a@example.invalid\r\nTo: b@example.invalid\r\nSubject: Date edge\r\n"
           "Message-ID: <edge@example.invalid>\r\nDate: " + value + "\r\n\r\nbody\r\n").encode()
    artifact = messaging.decode_email_artifact(raw)
    assert artifact is not None
    assert artifact.messages[0].date == expected.isoformat()
    threads = messaging.build_email_threads([raw])
    assert threads is not None
    assert threads[0].messages[0].date == expected.isoformat()


def make_msg():
    from test_harden_doc_office import make_cfb
    headers = ("From: Alice <alice@example.invalid>\r\nTo: Bob <bob@example.invalid>\r\n"
               "Subject: MSG vector\r\nMessage-ID: <msg@example.invalid>\r\nDate: " + DATE)
    values = {
        "__substg1.0_007D001F": (headers + "\0").encode("utf-16-le"),
        "__substg1.0_0037001F": "MSG vector\0".encode("utf-16-le"),
        "__substg1.0_1000001F": "CSCTF{MAPI_Body}\0".encode("utf-16-le"),
    }
    return make_cfb(values), headers


def test_cfb_and_msg_vector_lock_against_olefile():
    import olefile
    raw, headers = make_msg()
    with olefile.OleFileIO(io.BytesIO(raw)) as ole:
        expected_streams = {"/".join(path): ole.openstream(path).read() for path in ole.listdir()}
    assert mailtool.cfb_streams(raw) == expected_streams
    expected_headers = _oracle(headers.encode() + b"\r\n\r\n")
    actual = mailtool.parse_msg(raw, "vector.msg")
    for field in ("Subject", "Message-ID", "From", "To", "Date"):
        assert actual.get(field) == str(expected_headers[field])
    expected_body = expected_streams["__substg1.0_1000001F"].decode("utf-16-le").rstrip("\0")
    assert actual.bodies[0]["text"] == expected_body == "CSCTF{MAPI_Body}"
    assert mailtool.sniff(raw) == "msg"
    assert mailtool.load(raw)[0].bodies[0]["text"] == expected_body
    strict = messaging.decode_email_artifact(raw, name="vector.msg")
    assert strict is not None and strict.kind == "msg"
    assert strict.messages[0].bodies == (("text/plain", expected_body),)


def test_valid_cfb_truncations_and_bitflips_fail_closed():
    raw, _ = make_msg()
    corpus = [raw[:end] for end in (0, 7, 31, 75, 511, 512, 513, 1023, 1536, len(raw) - 1)]
    for offset in (8, 30, 32, 44, 48, 56, 64, 76, 512, 1024, 1536):
        changed = bytearray(raw)
        changed[offset] ^= 0x80
        corpus.append(bytes(changed))
    for data in corpus:
        for reader in (mailtool.cfb_streams, mailtool.parse_msg):
            try:
                reader(data)
            except ValueError as exc:
                assert type(exc) is ValueError
        result = messaging.decode_email_artifact(data, name="truncated.msg")
        assert result is None or isinstance(result, messaging.EmailArtifact)
