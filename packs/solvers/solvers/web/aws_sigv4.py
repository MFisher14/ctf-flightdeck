#!/usr/bin/env python3
"""Compute and verify AWS Signature Version 4 (SigV4) — auth headers and presigned URLs, offline.

Cloud/web challenges hand you an AWS access key + secret and ask you to forge a valid request, or
hand you a signed request and ask you to recover/verify the signature.  SigV4 is a fixed HMAC-SHA256
chain: a per-request *signing key* is derived from the secret and the credential scope
(date/region/service), then used to sign a canonical form of the request.  This computes every stage
(canonical request → string-to-sign → signing key → signature), builds the Authorization header and
query-presigned URLs, and verifies a claimed signature.  Pure stdlib (hmac/hashlib), offline — it
never sends a request and never submits.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import sys
from typing import Iterable
from urllib.parse import quote

ALGORITHM = "AWS4-HMAC-SHA256"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class SigV4Error(Exception):
    """Malformed input — fail closed."""


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    """Derive the SigV4 signing key: HMAC chain over AWS4+secret → date → region → service → terminator."""
    if not isinstance(secret, str) or not secret:
        raise SigV4Error("secret must be a non-empty str")
    if len(date_stamp) != 8 or not date_stamp.isdigit():
        raise SigV4Error("date_stamp must be YYYYMMDD")
    k_date = _hmac(("AWS4" + secret).encode("utf-8"), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def _canonical_uri(path: str) -> str:
    # each segment is URI-encoded, '/' preserved; AWS does NOT double-encode for S3 but does for others —
    # we use the general (non-S3) rule: encode the already-normalized path, keeping '/'.
    if not path:
        return "/"
    return quote(path, safe="/-_.~")


def _canonical_query(query: list[tuple[str, str]]) -> str:
    # sort by encoded key then encoded value; encode both with the unreserved set.
    enc = sorted((quote(k, safe="-_.~"), quote(v, safe="-_.~")) for k, v in query)
    return "&".join(f"{k}={v}" for k, v in enc)


def _canonical_headers(headers: dict[str, str]) -> tuple[str, str]:
    # lower-case names, trim values, sort; signed-headers is the ';'-joined sorted names.
    norm = {k.lower().strip(): " ".join(str(v).split()) for k, v in headers.items()}
    names = sorted(norm)
    canon = "".join(f"{n}:{norm[n]}\n" for n in names)
    return canon, ";".join(names)


def canonical_request(method: str, path: str, query: list[tuple[str, str]],
                      headers: dict[str, str], payload_hash: str) -> tuple[str, str]:
    """Build the canonical request string and its signed-headers list."""
    canon_headers, signed = _canonical_headers(headers)
    cr = "\n".join([method.upper(), _canonical_uri(path), _canonical_query(query or []),
                    canon_headers, signed, payload_hash])
    return cr, signed


def string_to_sign(amz_date: str, scope: str, canonical_req: str) -> str:
    """AWS4-HMAC-SHA256 \\n amz_date \\n scope \\n sha256(canonical_request)."""
    return "\n".join([ALGORITHM, amz_date, scope, _sha256_hex(canonical_req.encode("utf-8"))])


def credential_scope(date_stamp: str, region: str, service: str) -> str:
    return f"{date_stamp}/{region}/{service}/aws4_request"


def sign(secret: str, amz_date: str, region: str, service: str, method: str, path: str,
         headers: dict[str, str], *, query: list[tuple[str, str]] | None = None,
         payload: bytes = b"", access_key: str | None = None) -> dict:
    """Sign a request. amz_date is YYYYMMDDTHHMMSSZ. Returns the signature, canonical request,
    string-to-sign, credential scope, signed headers and (if access_key given) the Authorization header."""
    if len(amz_date) != 16 or amz_date[8] != "T" or amz_date[-1] != "Z":
        raise SigV4Error("amz_date must be YYYYMMDDTHHMMSSZ")
    date_stamp = amz_date[:8]
    payload_hash = _sha256_hex(payload)
    hdrs = dict(headers)
    hdrs.setdefault("x-amz-date", amz_date)
    cr, signed = canonical_request(method, path, query or [], hdrs, payload_hash)
    scope = credential_scope(date_stamp, region, service)
    sts = string_to_sign(amz_date, scope, cr)
    key = signing_key(secret, date_stamp, region, service)
    signature = hmac.new(key, sts.encode("utf-8"), hashlib.sha256).hexdigest()
    out = {"signature": signature, "canonical_request": cr, "string_to_sign": sts,
           "credential_scope": scope, "signed_headers": signed, "payload_hash": payload_hash}
    if access_key:
        out["authorization"] = (f"{ALGORITHM} Credential={access_key}/{scope}, "
                                f"SignedHeaders={signed}, Signature={signature}")
    return out


def verify(secret: str, amz_date: str, region: str, service: str, method: str, path: str,
           headers: dict[str, str], claimed_signature: str, *,
           query: list[tuple[str, str]] | None = None, payload: bytes = b"") -> bool:
    """Recompute the signature and constant-time compare it against a claimed one."""
    try:
        got = sign(secret, amz_date, region, service, method, path, headers,
                   query=query, payload=payload)["signature"]
    except SigV4Error:
        return False
    return hmac.compare_digest(got, claimed_signature.strip().lower())


def presign_url(secret: str, access_key: str, amz_date: str, region: str, service: str,
                method: str, host: str, path: str, *, expires: int = 3600,
                extra_query: list[tuple[str, str]] | None = None) -> str:
    """Build a query-string presigned URL (UNSIGNED-PAYLOAD), as used for S3 GET links."""
    date_stamp = amz_date[:8]
    scope = credential_scope(date_stamp, region, service)
    query = list(extra_query or []) + [
        ("X-Amz-Algorithm", ALGORITHM),
        ("X-Amz-Credential", f"{access_key}/{scope}"),
        ("X-Amz-Date", amz_date),
        ("X-Amz-Expires", str(expires)),
        ("X-Amz-SignedHeaders", "host"),
    ]
    cr, _ = canonical_request(method, path, query, {"host": host}, "UNSIGNED-PAYLOAD")
    sts = string_to_sign(amz_date, scope, cr)
    key = signing_key(secret, date_stamp, region, service)
    signature = hmac.new(key, sts.encode("utf-8"), hashlib.sha256).hexdigest()
    qs = _canonical_query(query) + f"&X-Amz-Signature={signature}"
    return f"https://{host}{_canonical_uri(path)}?{qs}"


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Compute/verify AWS SigV4 (offline).")
    sub = p.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("sign", help="sign a request")
    for name in ("secret", "amz_date", "region", "service", "method", "path", "host"):
        s.add_argument(name)
    s.add_argument("--access-key")
    k = sub.add_parser("key", help="just derive the signing key (hex)")
    for name in ("secret", "date_stamp", "region", "service"):
        k.add_argument(name)
    try:
        a = p.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if a.mode == "key":
            print(signing_key(a.secret, a.date_stamp, a.region, a.service).hex())
        else:
            res = sign(a.secret, a.amz_date, a.region, a.service, a.method, a.path,
                       {"host": a.host}, access_key=a.access_key)
            print(f"signature: {res['signature']}")
            if "authorization" in res:
                print(f"authorization: {res['authorization']}")
    except SigV4Error as exc:
        print(f"aws_sigv4: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
