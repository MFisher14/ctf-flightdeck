#!/usr/bin/env python3
"""Identify a hash / password-hash / token string and name its hashcat + john modes, offline.

The standard first step of a crypto/forensics challenge: "what IS this string?".  Given a candidate,
rank the likely algorithms by charset + length + structural prefix, and point at the hashcat `-m` and
john `--format` that crack it (so `solvers/toolkits/hashcrack.py` / john can take over).  This only
IDENTIFIES — it never cracks, submits, or invents a value.  Ranked candidates, most-specific first.
"""
from __future__ import annotations

import argparse
import re
import sys
from typing import Iterable

# structural (prefix / shape) signatures — these are unambiguous, so they rank first.
_STRUCTURAL = [
    (re.compile(r"^\$2[abxy]?\$\d\d\$[./A-Za-z0-9]{53}$"), "bcrypt", 3200, "bcrypt"),
    (re.compile(r"^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$"), "md5crypt", 500, "md5crypt"),
    (re.compile(r"^\$apr1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$"), "Apache apr1 / md5apr1", 1600, "md5crypt-long"),
    (re.compile(r"^\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}$"), "sha256crypt", 7400, "sha256crypt"),
    (re.compile(r"^\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}$"), "sha512crypt", 1800, "sha512crypt"),
    (re.compile(r"^\$y\$"), "yescrypt", None, "crypt"),
    (re.compile(r"^\$7\$"), "scrypt", 8900, "scrypt"),
    (re.compile(r"^\$argon2(id|i|d)\$"), "argon2", None, "argon2"),
    (re.compile(r"^\$pbkdf2(-sha(256|512|1))?\$"), "PBKDF2", None, "pbkdf2"),
    (re.compile(r"^pbkdf2_sha256\$\d+\$"), "Django PBKDF2-SHA256", 10000, "django"),
    (re.compile(r"^sha1\$[^$]*\$[0-9a-f]{40}$"), "Django SHA1 (salted)", 124, "django"),
    (re.compile(r"^\$P\$[./A-Za-z0-9]{31}$"), "phpass (WordPress/phpBB)", 400, "phpass"),
    (re.compile(r"^\$H\$[./A-Za-z0-9]{31}$"), "phpass (older)", 400, "phpass"),
    (re.compile(r"^\{SSHA\}[A-Za-z0-9+/=]+$"), "LDAP {SSHA}", 111, "salted-sha1"),
    (re.compile(r"^\{SHA\}[A-Za-z0-9+/=]{28}$"), "LDAP {SHA}", 101, "nsldap"),
    # NetNTLMv1 (mode 5500): user::domain:LMresp(48):NTresp(48) with an optional 8-byte server challenge.
    (re.compile(r"^[^:]+::[^:]*:[0-9a-f]{48}:[0-9a-f]{48}(:[0-9a-f]{16})?$", re.I), "NetNTLMv1", 5500, "netntlm"),
    # NetNTLMv2 (mode 5600): user::domain:serverChallenge(16):NTproof(32):blob(variable hex).
    (re.compile(r"^[^:]+::[^:]*:[0-9a-f]{16}:[0-9a-f]{32}:[0-9a-f]+$", re.I), "NetNTLMv2", 5600, "netntlmv2"),
    # The LMresp:NTresp:challenge triplet is also surfaced as a lower-ranked v2 candidate for compatibility.
    (re.compile(r"^[^:]+::[^:]*:[0-9a-f]{48}:[0-9a-f]{48}:[0-9a-f]{16}$", re.I), "NetNTLMv2", 5600, "netntlmv2"),
    # Kerberoast etype selects the hashcat mode: AES256 (18)->19700, AES128 (17)->19600, RC4 (23)->13100.
    (re.compile(r"^\$krb5tgs\$18\$"), "Kerberos TGS-REP (AES256, etype 18)", 19700, "krb5tgs-aes256"),
    (re.compile(r"^\$krb5tgs\$17\$"), "Kerberos TGS-REP (AES128, etype 17)", 19600, "krb5tgs-aes128"),
    (re.compile(r"^\$krb5tgs\$23\$"), "Kerberos TGS-REP (RC4, etype 23)", 13100, "krb5tgs"),
    (re.compile(r"^\$krb5tgs\$"), "Kerberos TGS-REP (Kerberoast)", 13100, "krb5tgs"),
    (re.compile(r"^\$krb5asrep\$"), "Kerberos AS-REP (AS-REP roast)", 18200, "krb5asrep"),
    (re.compile(r"^\$DCC2\$"), "Domain Cached Credentials 2 (mscash2)", 2100, "mscash2"),
    (re.compile(r"^[0-9a-f]{32}:[0-9a-f]{32}$", re.I), "NTLM:LM or salted-md5", 1000, "nt"),
    (re.compile(r"^\*[0-9A-F]{40}$"), "MySQL 4.1+ (SHA1(SHA1))", 300, "mysql-sha1"),
    (re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$"), "JWT (JSON Web Token)", None,
     "— decode header/payload; HS256 secret cracks with hashcat -m 16500"),
    (re.compile(r"^\$sha1\$\d+\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{28}$"), "sha1crypt", 15100, "sha1crypt"),
]

# plain hex digests by length -> (name, hashcat_mode) candidates, most-likely first.
_HEX_LEN = {
    8:   [("CRC-32", None), ("Adler-32", None)],
    16:  [("MySQL323 (old)", 200), ("CRC-64", None)],
    32:  [("MD5", 0), ("NTLM", 1000), ("MD4", 900), ("LM (half)", 3000),
          ("RIPEMD-128", None), ("double-MD5", 2600)],
    40:  [("SHA-1", 100), ("RIPEMD-160", 6000), ("Tiger-160", None), ("SHA-1(MD5)", 4700)],
    56:  [("SHA-224", 1300), ("SHA3-224", 17300)],
    64:  [("SHA-256", 1400), ("SHA3-256 / Keccak-256", 17400), ("RIPEMD-256", None),
          ("BLAKE2s-256", None), ("GOST R 34.11-94", 6900), ("SHA-256(MD5)", 3800)],
    96:  [("SHA-384", 10800), ("SHA3-384", 17500)],
    128: [("SHA-512", 1700), ("SHA3-512 / Keccak-512", 17600), ("BLAKE2b-512", 600),
          ("Whirlpool", 6100)],
}


def _charset(s: str) -> str:
    if re.fullmatch(r"[0-9a-fA-F]+", s):
        return "hex"
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
        return "base64"
    if re.fullmatch(r"[A-Za-z0-9_-]+", s):
        return "base64url"
    return "mixed"


def identify(value: object, *, top: int = 12) -> list[dict]:
    """Ranked [{name, confidence, hashcat_mode, john_format, note}] for a candidate hash/token string."""
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            return []
    if not isinstance(value, str):
        return []
    if not isinstance(top, int) or isinstance(top, bool) or top < 0:
        top = 12
    s = value.strip()
    if not s or len(s) > 4096:
        return []
    out: list[dict] = []
    # 1) structural prefixes (unambiguous)
    for pat, name, mode, john in _STRUCTURAL:
        if pat.match(s):
            note = john if isinstance(john, str) and john.startswith("—") else ""
            out.append({"name": name, "confidence": "high", "hashcat_mode": mode,
                        "john_format": None if note else john, "note": note})
    # 2) plain hex digests by length
    cs = _charset(s)
    if cs == "hex" and not out:
        for name, mode in _HEX_LEN.get(len(s), []):
            out.append({"name": name, "confidence": "medium", "hashcat_mode": mode,
                        "john_format": None, "note": f"{len(s)}-hex digest"})
    # 3) base64 blob that decodes to a known raw-digest length
    if cs in ("base64", "base64url") and not out:
        import base64
        try:
            pad = "=" * ((-len(s)) % 4)
            raw = (base64.urlsafe_b64decode if cs == "base64url" else base64.b64decode)(s + pad)
            lut = {16: "raw MD5/MD4/NTLM", 20: "raw SHA-1/RIPEMD-160", 28: "raw SHA-224",
                   32: "raw SHA-256/BLAKE2s", 48: "raw SHA-384", 64: "raw SHA-512/BLAKE2b"}
            if len(raw) in lut:
                out.append({"name": f"base64-encoded {lut[len(raw)]}", "confidence": "low",
                            "hashcat_mode": None, "john_format": None,
                            "note": f"decodes to {len(raw)} raw bytes"})
        except Exception:
            pass
    if not out:
        out.append({"name": "unknown", "confidence": "none", "hashcat_mode": None,
                    "john_format": None, "note": f"{cs}, length {len(s)}"})
    return out[:top]


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Identify a hash/token string and name its crack modes "
                                            "(offline; identifies only, never cracks).")
    p.add_argument("value", help="the candidate hash/token (or '-' to read one line from stdin)")
    p.add_argument("--json", action="store_true")
    try:
        a = p.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    value = sys.stdin.readline().strip() if a.value == "-" else a.value
    results = identify(value)
    if a.json:
        import json
        print(json.dumps(results, indent=1))
    else:
        for r in results:
            mode = f"  hashcat -m {r['hashcat_mode']}" if r["hashcat_mode"] is not None else ""
            jf = f"  john --format={r['john_format']}" if r["john_format"] else ""
            print(f"[{r['confidence']:6}] {r['name']}{mode}{jf}" + (f"   ({r['note']})" if r["note"] else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
