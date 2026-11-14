# Toolkit `asn1_reader`: ASN.1/DER + X.509 / PKCS / PEM / SSH / PGP

Built 2026-10-23 (gap-analysis ticket **C2**, `docs/retro/ctf-solver-gap-analysis.md`). ASN.1/DER parsing used
to live only welded to PE Authenticode; there was no category-agnostic reader for a bare certificate, key, CSR,
CRL, SSH public key or PGP packet delivery. This reads the **structure and fingerprints** of such an artifact.
Offline, static. It uses `cryptography` / `asn1crypto` when they are in the `.venv` and a bounded pure-Python
DER walk otherwise; every reader is fail-closed.

**RECON only.** Nothing is a key that is used, a signature that is verified, or a secret that is submitted. A
private key's own secret parameters (the private exponent, the primes) are never an answer. The flag is `None`.

## Run first

```bash
.venv/bin/python solvers/toolkits/asn1_reader.py <file>...          # facts per file
.venv/bin/python solvers/toolkits/asn1_reader.py <file> --json      # as JSON
```

As a solver: `solvers/toolkits/asn1_reader.py` has `solve_set` and `signals(questions, files)` (0..1,
0.0 when nothing validates) for running the whole file set at once.

By hand, from Python:

```python
sys.path.insert(0, "solvers/toolkits"); import asn1_reader as T
T.classify(data, name)   # {"kind": "x509"|"key"|"ssh"|"pgp"|"pem", "facts": {...}} or None
T.pem_blocks(data)       # [(LABEL, der_bytes)] of every -----BEGIN X----- block
T.ssh_pubkey(text)       # {ssh_type, ssh_fingerprint_sha256, ssh_fingerprint_md5, ssh_bits, ssh_comment}
T.pgp_key(binary)        # {pgp_fingerprint, pgp_keyid, pgp_algo, pgp_created, pgp_userid}  (public key packets)
```

## What it reads

| Kind | Validated by | Facts |
| --- | --- | --- |
| x509 | a PEM `CERTIFICATE` block or a raw DER `SEQUENCE{tbs, sigAlg, BITSTRING}` | SHA-1/SHA-256/MD5 **fingerprint** (a digest of the exact DER bytes), serial, subject/issuer (full DN and common name), notBefore/notAfter, signature algorithm, public-key algorithm/size, modulus, version |
| key | a PEM `PUBLIC KEY` / `PRIVATE KEY` block (PKCS#1/PKCS#8/SPKI) | algorithm (rsa/ec/…), key size, RSA modulus and public exponent, EC curve — **never the private parameters** |
| ssh | an OpenSSH public-key line (`ssh-rsa`/`ssh-ed25519`/`ecdsa-sha2-nistp*`/…) | key type, SHA256 and MD5 fingerprints (as `ssh-keygen -l`), bit length, comment |
| pgp | an OpenPGP public-key packet (binary or ASCII-armored) | v4 fingerprint (SHA-1 of `0x99‖len‖body`), key id (last 8 bytes), public-key algorithm, creation time, User ID |

A truncated or ambiguous parse, a private key's secret parameters, and anything unproven are **`None`**. Bounded:
64 MiB file, 8 MiB scan, ≤100000 TLV nodes, ≤40 deep.

## Never-guess

A fingerprint and a serial are a deterministic read of exact bytes, so they are **high-confidence**: returned as
`labels.pick(key, options)` of their renderings (lower hex, upper hex, colon-hex; decimal vs hex for a serial),
a ranked candidate list you read with `labels.show(...)` and reason to one value. A **selection** among several
equal fields (which SAN, the spelling of a DN), an author-chosen algorithm name and every timestamp are
less-certain candidates. Keys are `asn1_reader.<field>/<shape>` (`asn1_reader.fingerprint_sha256/x509`,
`asn1_reader.serial/x509`, `asn1_reader.ssh_fingerprint/ssh`, `asn1_reader.pgp_keyid/pgp`). This is RECON only
(flag `None`); no value here is submitted.
