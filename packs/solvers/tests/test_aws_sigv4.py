"""aws_sigv4: compute/verify AWS Signature Version 4 against AWS's authoritative vectors."""
from __future__ import annotations

import pytest

import aws_sigv4 as s

# Authoritative constants from AWS documentation (non-circular anchors):
SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
AKID = "AKIDEXAMPLE"
# AWS General Reference, "Examples of how to derive a signing key for Signature Version 4":
DOC_SIGNING_KEY = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
# aws4_testsuite "get-vanilla":
VANILLA_SIG = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
VANILLA_CR = (
    "GET\n"
    "/\n"
    "\n"
    "host:example.amazonaws.com\n"
    "x-amz-date:20150830T123600Z\n"
    "\n"
    "host;x-amz-date\n"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)


def test_signing_key_matches_aws_doc_vector():
    assert s.signing_key(SECRET, "20150830", "us-east-1", "iam").hex() == DOC_SIGNING_KEY


def test_empty_payload_sha256_constant():
    assert s.EMPTY_SHA256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_get_vanilla_canonical_request_and_signature():
    res = s.sign(SECRET, "20150830T123600Z", "us-east-1", "service", "GET", "/",
                 {"host": "example.amazonaws.com"})
    assert res["canonical_request"] == VANILLA_CR
    assert res["signature"] == VANILLA_SIG
    assert res["credential_scope"] == "20150830/us-east-1/service/aws4_request"
    assert res["signed_headers"] == "host;x-amz-date"


def test_authorization_header_shape():
    res = s.sign(SECRET, "20150830T123600Z", "us-east-1", "service", "GET", "/",
                 {"host": "example.amazonaws.com"}, access_key=AKID)
    assert res["authorization"] == (
        f"AWS4-HMAC-SHA256 Credential={AKID}/20150830/us-east-1/service/aws4_request, "
        f"SignedHeaders=host;x-amz-date, Signature={VANILLA_SIG}")


def test_verify_roundtrip_and_tamper():
    args = (SECRET, "20150830T123600Z", "us-east-1", "service", "GET", "/",
            {"host": "example.amazonaws.com"})
    assert s.verify(*args, VANILLA_SIG) is True
    assert s.verify(*args, VANILLA_SIG.upper()) is True          # case-insensitive hex
    assert s.verify(*args, "0" * 64) is False                    # wrong signature
    # wrong secret -> different signature -> verify fails
    assert s.verify("AnotherSecretKeyEXAMPLE", "20150830T123600Z", "us-east-1", "service",
                    "GET", "/", {"host": "example.amazonaws.com"}, VANILLA_SIG) is False


def test_query_and_header_canonicalization():
    # unsorted query + mixed-case/underspaced headers must canonicalize deterministically
    res = s.sign(SECRET, "20150830T123600Z", "us-east-1", "service", "get", "/",
                 {"Host": "example.amazonaws.com", "My-Header1": "  value1 ", "X-Amz-Date": "20150830T123600Z"},
                 query=[("Param2", "value2"), ("Param1", "value1")])
    cr = res["canonical_request"]
    assert "Param1=value1&Param2=value2" in cr                   # sorted query
    assert "my-header1:value1\n" in cr                           # trimmed + lowercased
    assert res["signed_headers"] == "host;my-header1;x-amz-date"


def test_presign_url_has_signature_and_scope():
    url = s.presign_url(SECRET, AKID, "20150830T123600Z", "us-east-1", "s3", "GET",
                        "examplebucket.s3.amazonaws.com", "/test.txt", expires=86400)
    assert url.startswith("https://examplebucket.s3.amazonaws.com/test.txt?")
    assert "X-Amz-Signature=" in url
    assert "X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request" in url
    assert "X-Amz-Expires=86400" in url
    # the signature is 64 hex chars
    sig = url.split("X-Amz-Signature=")[1]
    assert len(sig) == 64 and all(c in "0123456789abcdef" for c in sig)


def test_fail_closed():
    with pytest.raises(s.SigV4Error):
        s.signing_key("", "20150830", "us-east-1", "iam")        # empty secret
    with pytest.raises(s.SigV4Error):
        s.signing_key(SECRET, "2015-08-30", "us-east-1", "iam")  # bad date stamp
    with pytest.raises(s.SigV4Error):
        s.sign(SECRET, "badstamp", "us-east-1", "service", "GET", "/", {"host": "h"})
    assert s.verify(SECRET, "badstamp", "us-east-1", "service", "GET", "/", {"host": "h"}, VANILLA_SIG) is False


def test_cli(capsys):
    assert s.main(["key", SECRET, "20150830", "us-east-1", "iam"]) == 0
    assert DOC_SIGNING_KEY in capsys.readouterr().out
    assert s.main(["sign", SECRET, "20150830T123600Z", "us-east-1", "service", "GET", "/",
                   "example.amazonaws.com", "--access-key", AKID]) == 0
    out = capsys.readouterr().out
    assert VANILLA_SIG in out
    assert s.main(["key", "", "20150830", "us-east-1", "iam"]) == 1   # empty secret -> error
    assert s.main(["--help"]) == 0
