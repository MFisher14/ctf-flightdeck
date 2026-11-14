#!/usr/bin/env python3
"""Metadata Forensics reader pack of 2026-10-08, part 2: documents, keys, model files, text formats.

Loaded by properties_strict.py like readers_more.py (see that file for the contract): register(M)
adds extractors to the wrapper's registry, every one unconfirmed, so nothing here is ever plain.

What is here, by namespace (all new):
  plist         XML and binary property lists: format, keys, any value by its key path, the trailer
  x509 pem ssh  certificates (subject, issuer, serial, validity, fingerprints, SAN), PEM labels,
                OpenSSH public keys (type, bits, comment, fingerprints) and private key headers
  jwt           a JSON Web Token's header and claims
  gguf safetensors pickle npy   model and array files: header counts, metadata, pickle imports
  eml           mail headers, addresses, the Date in UTC, attachments
  json xml html csv ini zoneidentifier rtf torrent   structure and fields of text and bencoded files
  font woff     sfnt (TrueType, OpenType) name and head tables, WOFF headers
  icc           ICC colour profiles, alone or embedded in a JPEG, PNG or WebP: header fields, tag table,
                description and copyright (the Day 21 look-ahead)

A value read from a key-value container (a plist key, a JSON path, a mail header) is formatted by
the type it is stored as (the wrapper's class `any`). A key path is spelled with underscores and
must select exactly one value: 'plist.program_arguments', 'json.metadata_kernelspec_name'.
cryptography (already in the venv) is imported only when an x509 question is asked.
"""
import base64
import binascii
import datetime
import functools
import hashlib
import io
import json
import re
import struct

M = None
SECTIONS = []
NEW = {}
ALIASES = {}
LIMIT = 1 << 16
TEXT_MAX = 1 << 22  # bytes of a text document that are parsed


def section(fn):
    SECTIONS.append(fn)
    return fn


def U(msg):
    raise M.Unknown(msg)


def reg(ns, names, fmt, fn):
    names = [names] if isinstance(names, str) else list(names)
    M.prop(*[f"{ns}.{x}" for x in names], fmt=fmt)(fn)


def of(parse, get):
    def fn(n, d):
        r = parse(d)
        return None if r is None else get(r)
    return fn


def namespace(ns, tokens=(), test=None, archive=False, alias=()):
    NEW[ns] = (tuple(tokens), test, archive)
    for a in alias:
        ALIASES[a] = ns


def register(module):
    global M
    M = module
    before = dict(M.REG)
    families = len(M.FAMILIES)
    for s in SECTIONS:
        s()
    for k, old in before.items():  # a name that was registered before keeps its reader: nothing judged is replaced
        if M.REG[k] is not old:
            M.MORE_CLASHES.append(M.REG[k].name)
            M.REG[k] = old
    for ns, (tokens, test, archive) in NEW.items():
        M.NAMESPACES.add(ns)
        if archive:
            M.ARCHIVE_NAMESPACES.update({ns, *tokens})
        else:
            M.PACK_NAMESPACES.add(ns)
            M.CONTENT_TOKENS.update({ns, *tokens})
        M.RELATED.setdefault(ns, (ns,))
        if test is not None:
            M.MORE_TYPES.append((ns, test))
    M.NS_ALIAS.update(ALIASES)
    M.TIE_FREE.update(M.REG[k].fn for k in M.REG if k not in before)
    return len(M.REG) - len(before), len(M.FAMILIES) - families


def as_text(d: bytes):
    """A text document's characters, or None when the bytes are not text (or are too many)."""
    if not d or len(d) > TEXT_MAX:
        return None
    try:
        if d[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return d.decode("utf-16")
        if b"\x00" in d:
            return None
        return d.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def key_names(k) -> set:
    """The spellings a container's key goes by in a property name: CFBundleIdentifier is
    cfbundleidentifier, cf_bundle_identifier and bundle_identifier; general.architecture is
    general_architecture."""
    k = str(k)
    plain = M.canon(k)
    split = M.canon(re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", "_", k))
    return {x for x in (plain, split, re.sub(r"^(?:cf|ls|ns)_", "", split)) if x}


def walk(obj, field: str):
    """The one value reached from `obj` by dict keys (and list indexes) whose names, joined by
    underscores, spell `field`. Returns (found, value); two different values are Unknown."""
    hits, steps = [], [0]

    def go(o, rest, depth):
        steps[0] += 1
        if steps[0] > 50000 or depth > 16:
            U("a key path search that does not end")
        if rest == "":
            hits.append(o)
            return
        if isinstance(o, dict):
            for k, v in o.items():
                for name in key_names(k.decode("utf-8", "replace") if isinstance(k, bytes) else k):
                    if rest == name or rest.startswith(name + "_"):
                        go(v, rest[len(name) + 1:], depth + 1)
        elif isinstance(o, (list, tuple)):
            m = re.match(r"(\d+)(?:_|$)", rest)
            if m and int(m.group(1)) < len(o):
                go(o[int(m.group(1))], rest[m.end():], depth + 1)
    go(obj, field, 0)
    distinct = []
    for h in hits:
        if not any(h is x or (type(h) is type(x) and h == x) for x in distinct):
            distinct.append(h)
    if len(distinct) > 1:
        U("the key path names more than one value")
    return (True, distinct[0]) if distinct else (False, None)


def plain_value(v):
    """A walked value as something the class `any` formats; a null is no value."""
    if v is None:
        return None
    if isinstance(v, (bool, int, float, str, bytes, datetime.datetime, list, tuple, dict)):
        if isinstance(v, (str, bytes, list, tuple, dict)) and not v:
            return None
        if isinstance(v, datetime.datetime) and v.tzinfo is not None:
            v = v.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return v
    U(f"a value of type {type(v).__name__} that is not read")


def path_family(parse, root=lambda r: r):
    def fn(n, d, field):
        r = parse(d)
        if r is None:
            return None
        found, v = walk(root(r), field)
        return plain_value(v) if found else None
    return fn


# ------------------------------------------------------------------ property lists

@functools.lru_cache(maxsize=8)
def _plist(d: bytes):
    """(format, object) of a property list, or None when the file is not one."""
    if d[:6] == b"bplist":
        kind = "binary"
    elif b"<plist" in d[:2048] and d.lstrip(b"\xef\xbb\xbf \t\r\n")[:1] == b"<":
        kind = "xml"
    else:
        return None
    if len(d) > TEXT_MAX:
        U("a property list larger than is parsed")
    import plistlib
    try:
        return kind, plistlib.loads(d)
    except Exception as e:
        U(f"the property list does not parse ({type(e).__name__})")


def _bplist_trailer(d: bytes):
    if d[:6] != b"bplist":
        return None
    if len(d) < 40:
        U("a binary property list without its trailer")
    return struct.unpack(">6xBBQQQ", d[-32:])  # offset int size, object ref size, objects, top object, offset table offset


@section
def _reg_plist():
    namespace("plist", tokens=("plist", "bplist"), test=lambda d: d[:6] == b"bplist" or b"<plist" in d[:2048],
              alias=("bplist", "property_list", "info_plist"))
    reg("plist", ("format", "encoding_format", "serialization"), "label", of(_plist, lambda p: p[0]))
    reg("plist", ("top_level_type", "root_type", "root_object_type"), "label",
        of(_plist, lambda p: {dict: "dict", list: "array", str: "string", bool: "boolean", int: "integer", float: "real",
                              bytes: "data"}.get(type(p[1])) or U("a root object of a type that is not named")))
    reg("plist", ("key_count", "top_level_key_count", "root_key_count"), "integer",
        of(_plist, lambda p: len(p[1]) if isinstance(p[1], dict) else U("the root object is not a dictionary")))
    reg("plist", ("keys", "top_level_keys", "root_keys", "key_names"), "list",
        of(_plist, lambda p: [str(k) for k in p[1]] or None if isinstance(p[1], dict) else U("the root object is not a dictionary")))
    reg("plist", ("object_count", "trailer_object_count", "trailer_num_objects", "num_objects"), "integer",
        of(_bplist_trailer, lambda t: t[2]))
    reg("plist", ("object_ref_size", "trailer_object_ref_size", "object_reference_size_bytes"), "integer",
        of(_bplist_trailer, lambda t: t[1]))
    reg("plist", ("offset_int_size", "trailer_offset_int_size", "offset_table_entry_size_bytes"), "integer",
        of(_bplist_trailer, lambda t: t[0]))
    reg("plist", ("offset_table_offset", "trailer_offset_table_offset", "offset_table_start"), "integer",
        of(_bplist_trailer, lambda t: t[4]))
    reg("plist", ("top_object", "trailer_top_object", "root_object_index"), "integer", of(_bplist_trailer, lambda t: t[3]))
    reg("plist", ("version", "header_version", "bplist_version"), "text",
        lambda n, d: d[6:8].decode("ascii") if d[:6] == b"bplist" and d[6:8].isdigit() else None)
    M.family(r"plist_(?:value_|key_)?(.+)", "any")(path_family(_plist, lambda p: p[1]))


# ------------------------------------------------------------------ certificates and keys

PEM_RX = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n(.*?)-----END \1-----", re.S)


def _pem(d: bytes):
    """[(label, DER bytes)] of the PEM blocks of a text file, or None when it holds none."""
    if b"-----BEGIN " not in d[:1 << 16] or len(d) > TEXT_MAX:
        return None
    out = []
    for label, body in PEM_RX.findall(d)[:256]:
        lines = [x for x in body.replace(b"\r", b"").split(b"\n") if x and b":" not in x]  # RFC 1421 headers left out
        try:
            out.append((label.decode(), base64.b64decode(b"".join(lines), validate=True)))
        except (binascii.Error, ValueError):
            U("a PEM block whose base64 does not decode")
    return out or U("a PEM header without a complete block")


@functools.lru_cache(maxsize=4)
def _cert(d: bytes):
    """(the certificate as cryptography reads it, its DER bytes), or None when the file is not one."""
    blocks = _pem(d)
    if blocks is not None:
        certs = [der for label, der in blocks if label in ("CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE")]
        if not certs:
            return None
        if len(certs) > 1:
            U("several certificates: the name does not say which one is asked")
        der, strict = certs[0], True
    elif d[:1] == b"\x30" and 64 < len(d) < 1 << 16:
        der, strict = d, False
    else:
        return None
    try:
        from cryptography import x509
    except ImportError:
        U("the cryptography library is not installed")
    try:
        return x509.load_der_x509_certificate(der), der
    except Exception as e:
        return U(f"the certificate does not parse ({type(e).__name__})") if strict else None


def _name_forms(name):
    """A distinguished name: RFC 4514 (most specific first), as openssl prints it, the common name."""
    from cryptography.x509.oid import NameOID
    short = {"commonName": "CN", "countryName": "C", "organizationName": "O", "organizationalUnitName": "OU",
             "localityName": "L", "stateOrProvinceName": "ST", "emailAddress": "emailAddress", "serialNumber": "serialNumber",
             "domainComponent": "DC"}
    parts = [(short.get(a.oid._name, a.oid.dotted_string), a.value if isinstance(a.value, str) else a.value.hex()) for a in name]
    cn = [a.value for a in name.get_attributes_for_oid(NameOID.COMMON_NAME) if isinstance(a.value, str)]
    out = [("rfc4514", name.rfc4514_string()), ("comma_space", ", ".join(f"{k}={v}" for k, v in parts)),
           ("openssl", ", ".join(f"{k} = {v}" for k, v in parts)), ("comma", ",".join(f"{k}={v}" for k, v in parts))]
    return out + ([("common_name", cn[0])] if len(cn) == 1 else [])


def _name_attr(name, oid_name):
    from cryptography.x509.oid import NameOID
    values = [a.value for a in name.get_attributes_for_oid(getattr(NameOID, oid_name)) if isinstance(a.value, str)]
    if len(values) > 1:
        U("the name has several such attributes")
    return values[0] or None if values else None


def _stamp(dt: datetime.datetime):
    return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, True)


def _fingerprint(digest: bytes):
    h = digest.hex()
    pairs = ":".join(h[i:i + 2] for i in range(0, len(h), 2))
    return [("hex_lower", h), ("colon_hex_upper", pairs.upper()), ("hex_upper", h.upper()), ("colon_hex_lower", pairs)]


def _cert_key(cert):
    """(algorithm word, bits, curve name or None, RSA exponent or None) of a certificate's public key."""
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa", key.key_size, None, key.public_numbers().e
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ec", key.curve.key_size, key.curve.name, None
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ed25519", 256, None, None
    if isinstance(key, ed448.Ed448PublicKey):
        return "ed448", 456, None, None
    if isinstance(key, dsa.DSAPublicKey):
        return "dsa", key.key_size, None, None
    U("a public key of a kind that is not read")


def _cert_ext(cert, cls_name):
    from cryptography import x509
    try:
        return cert.extensions.get_extension_for_class(getattr(x509, cls_name)).value
    except x509.ExtensionNotFound:
        return None


SSH_TYPES = (b"ssh-rsa", b"ssh-dss", b"ssh-ed25519", b"ecdsa-sha2-nistp256", b"ecdsa-sha2-nistp384", b"ecdsa-sha2-nistp521",
             b"sk-ssh-ed25519@openssh.com", b"sk-ecdsa-sha2-nistp256@openssh.com")
SSH_BITS = {"ssh-ed25519": 256, "sk-ssh-ed25519@openssh.com": 256, "ecdsa-sha2-nistp256": 256,
            "sk-ecdsa-sha2-nistp256@openssh.com": 256, "ecdsa-sha2-nistp384": 384, "ecdsa-sha2-nistp521": 521}


def _ssh_strings(blob: bytes, count: int):
    out, i = [], 0
    for _ in range(count):
        if i + 4 > len(blob):
            U("the key blob is cut")
        n = struct.unpack(">I", blob[i:i + 4])[0]
        if i + 4 + n > len(blob):
            U("the key blob is cut")
        out.append(blob[i + 4:i + 4 + n])
        i += 4 + n
    return out, i


@functools.lru_cache(maxsize=8)
def _ssh(d: bytes):
    """(key type, key blob, comment or None) of the one OpenSSH public key line of a file, or None."""
    if len(d) > 1 << 16 or not any(t + b" " in d[:4096] for t in SSH_TYPES):
        return None
    lines = [x.strip() for x in d.splitlines() if x.strip() and not x.lstrip().startswith(b"#")]
    keys = [m for m in (re.match(rb"(?:\S+ )?(" + b"|".join(re.escape(t) for t in SSH_TYPES) +
                                 rb") ([A-Za-z0-9+/]+={0,2})(?: (.*))?$", x) for x in lines) if m]
    if not keys:
        return None
    if len(keys) != 1 or len(lines) != 1:
        U("several keys or other lines: the name does not say which key is asked")
    kind, b64, comment = keys[0].groups()
    try:
        blob = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        U("a key whose base64 does not decode")
    if _ssh_strings(blob, 1)[0][0] != kind:
        U("the key blob names another key type than the line")
    return kind.decode(), blob, (comment.decode("utf-8", "replace").strip() or None) if comment else None


def _ssh_bits(key):
    kind, blob, _ = key
    if kind in SSH_BITS:
        return SSH_BITS[kind]
    parts, _ = _ssh_strings(blob, 3)
    number = parts[2] if kind == "ssh-rsa" else parts[1]  # rsa: type, e, n; dss: type, p, ...
    return int.from_bytes(number, "big").bit_length()


def _ssh_private(d: bytes):
    """(cipher, kdf, the public key blob) of an OpenSSH private key file, or None."""
    blocks = _pem(d) if b"OPENSSH PRIVATE KEY" in d[:256] else None
    if not blocks or blocks[0][0] != "OPENSSH PRIVATE KEY":
        return None
    body = blocks[0][1]
    if body[:15] != b"openssh-key-v1\x00":
        U("an OpenSSH private key of a format that is not read")
    (cipher, kdf, _), i = _ssh_strings(body[15:], 3)
    count = struct.unpack(">I", body[15 + i:19 + i])[0]
    if count != 1:
        U("a key file with several keys")
    (public,), _ = _ssh_strings(body[19 + i:], 1)
    return cipher.decode(), kdf.decode(), public


def _b64url(seg: bytes):
    try:
        return base64.urlsafe_b64decode(seg + b"=" * (-len(seg) % 4))
    except (binascii.Error, ValueError):
        U("a token part whose base64url does not decode")


@functools.lru_cache(maxsize=8)
def _jwt(d: bytes):
    """(header, payload, signature bytes) of a file that holds one JSON Web Token, or None."""
    s = d.strip()
    if not 20 < len(s) < 1 << 16 or not re.fullmatch(rb"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", s):
        return None
    h, p, sig = s.split(b".")
    try:
        header = json.loads(_b64url(h))
    except Exception:
        return None
    if not isinstance(header, dict) or "alg" not in header:
        return None
    try:
        payload = json.loads(_b64url(p))
    except ValueError:
        U("a token whose payload is not JSON")
    return header, payload, _b64url(sig)


@section
def _reg_keys():
    namespace("pem", tokens=("pem",), test=lambda d: b"-----BEGIN " in d[:256])
    reg("pem", ("label", "type", "block_label", "block_type", "header_label"), "text",
        of(_pem, lambda b: b[0][0] if len({x for x, _ in b}) == 1 else U("blocks of several kinds")))
    reg("pem", ("labels", "block_labels", "block_types"), "list", of(_pem, lambda b: [x for x, _ in b]))
    reg("pem", ("block_count", "object_count"), "integer", of(_pem, lambda b: len(b)))
    reg("pem", ("der_size_bytes", "decoded_size_bytes"), "integer",
        of(_pem, lambda b: len(b[0][1]) if len(b) == 1 else U("several blocks")))
    for algo in ("md5", "sha1", "sha256"):
        reg("pem", (f"der_{algo}", f"decoded_{algo}"), "hex",
            of(_pem, lambda b, algo=algo: hashlib.new(algo, b[0][1]).hexdigest() if len(b) == 1 else U("several blocks")))

    namespace("x509", tokens=("crt", "cer", "der", "cert"), test=lambda d: b"-----BEGIN CERTIFICATE-----" in d[:256],
              alias=("cert", "certificate", "crt", "x509_certificate", "tls_certificate", "ssl_certificate"))
    reg("x509", ("subject", "subject_dn", "subject_name", "subject_distinguished_name"), "forms", of(_cert, lambda c: _name_forms(c[0].subject)))
    reg("x509", ("issuer", "issuer_dn", "issuer_name", "issuer_distinguished_name"), "forms", of(_cert, lambda c: _name_forms(c[0].issuer)))
    for who in ("subject", "issuer"):
        for names, oid in ((("common_name", "cn"), "COMMON_NAME"), (("organization", "o", "organization_name"), "ORGANIZATION_NAME"),
                           (("organizational_unit", "ou"), "ORGANIZATIONAL_UNIT_NAME"), (("country", "c", "country_name"), "COUNTRY_NAME"),
                           (("locality", "l"), "LOCALITY_NAME"), (("state", "st", "state_or_province"), "STATE_OR_PROVINCE_NAME"),
                           (("email", "email_address"), "EMAIL_ADDRESS")):
            reg("x509", [f"{who}_{x}" for x in names], "text",
                of(_cert, lambda c, who=who, oid=oid: _name_attr(getattr(c[0], who), oid)))
    reg("x509", ("serial_number", "serial", "certificate_serial_number"), "serial", of(_cert, lambda c: c[0].serial_number))
    reg("x509", ("not_before", "not_valid_before", "validity_not_before", "valid_from"), "timestamp",
        of(_cert, lambda c: _stamp(c[0].not_valid_before_utc)))
    reg("x509", ("not_after", "not_valid_after", "validity_not_after", "valid_until", "valid_to", "expiry", "expires"), "timestamp",
        of(_cert, lambda c: _stamp(c[0].not_valid_after_utc)))
    reg("x509", ("version", "certificate_version"), "forms",
        of(_cert, lambda c: [("bare", str(c[0].version.value + 1)), ("v_prefixed", f"v{c[0].version.value + 1}")]))
    reg("x509", ("signature_algorithm", "signature_algorithm_name"), "forms",
        of(_cert, lambda c: [("name", c[0].signature_algorithm_oid._name), ("dotted", c[0].signature_algorithm_oid.dotted_string)]))
    reg("x509", ("signature_algorithm_oid",), "text", of(_cert, lambda c: c[0].signature_algorithm_oid.dotted_string))
    reg("x509", ("signature_hash_algorithm", "signature_hash"), "label",
        of(_cert, lambda c: c[0].signature_hash_algorithm.name if c[0].signature_hash_algorithm else U("no separate hash")))
    reg("x509", ("public_key_algorithm", "key_algorithm", "public_key_type", "key_type"), "label", of(_cert, lambda c: _cert_key(c[0])[0]))
    reg("x509", ("public_key_bits", "key_size_bits", "public_key_size_bits", "key_size", "public_key_size", "key_bits"), "integer",
        of(_cert, lambda c: _cert_key(c[0])[1]))
    reg("x509", ("public_key_curve", "ec_curve", "curve", "curve_name"), "text", of(_cert, lambda c: _cert_key(c[0])[2]))
    reg("x509", ("rsa_public_exponent", "public_exponent", "rsa_exponent"), "integer", of(_cert, lambda c: _cert_key(c[0])[3]))
    for algo in ("md5", "sha1", "sha256"):
        reg("x509", (f"fingerprint_{algo}", f"{algo}_fingerprint", f"thumbprint_{algo}", f"{algo}_thumbprint", f"der_{algo}"), "forms",
            of(_cert, lambda c, algo=algo: _fingerprint(hashlib.new(algo, c[1]).digest())))
    reg("x509", ("self_signed", "is_self_signed", "self_issued"), "bool", of(_cert, lambda c: c[0].subject == c[0].issuer))
    reg("x509", ("is_ca", "ca", "basic_constraints_ca"), "bool",
        of(_cert, lambda c: (lambda e: bool(e.ca) if e is not None else U("no basic constraints extension"))(_cert_ext(c[0], "BasicConstraints"))))

    def san(kind):
        def get(c):
            from cryptography import x509
            e = _cert_ext(c[0], "SubjectAlternativeName")
            if e is None:
                return None
            return [str(v) for v in e.get_values_for_type(getattr(x509, kind))] or None
        return of(_cert, get)
    reg("x509", ("subject_alt_names", "subject_alternative_names", "san_dns_names", "dns_names", "san", "subject_alt_dns_names"),
        "list", san("DNSName"))
    reg("x509", ("san_ip_addresses", "subject_alt_ip_addresses", "ip_addresses"), "list", san("IPAddress"))
    reg("x509", ("san_email_addresses", "subject_alt_email_addresses"), "list", san("RFC822Name"))
    reg("x509", ("extension_count",), "integer", of(_cert, lambda c: len(c[0].extensions)))
    reg("x509", ("extension_oids",), "list", of(_cert, lambda c: [e.oid.dotted_string for e in c[0].extensions] or None))
    reg("x509", ("extension_names",), "list", of(_cert, lambda c: [e.oid._name for e in c[0].extensions] or None))
    reg("x509", ("der_size_bytes",), "integer", of(_cert, lambda c: len(c[1])))

    namespace("ssh", tokens=("pub",), test=lambda d: _ssh(d) is not None,
              alias=("ssh_key", "ssh_public_key", "sshkey", "openssh", "authorized_keys", "ssh_pubkey"))
    reg("ssh", ("key_type", "type", "algorithm", "public_key_type", "key_algorithm"), "text", of(_ssh, lambda k: k[0]))
    reg("ssh", ("comment", "key_comment", "public_key_comment"), "text", of(_ssh, lambda k: k[2]))
    reg("ssh", ("key_bits", "bits", "key_size_bits", "key_size", "public_key_bits", "key_length_bits"), "integer", of(_ssh, _ssh_bits))

    def fp256(blob):
        b = base64.b64encode(hashlib.sha256(blob).digest()).decode()
        return [("prefixed", "SHA256:" + b.rstrip("=")), ("base64_unpadded", b.rstrip("=")), ("base64", b),
                ("hex_lower", hashlib.sha256(blob).hexdigest())]

    def fpmd5(blob):
        h = hashlib.md5(blob).hexdigest()
        pairs = ":".join(h[i:i + 2] for i in range(0, 32, 2))
        return [("colon_hex_lower", pairs), ("prefixed", "MD5:" + pairs), ("hex_lower", h)]
    reg("ssh", ("fingerprint_sha256", "sha256_fingerprint", "fingerprint", "public_key_fingerprint_sha256", "key_fingerprint"), "forms",
        of(_ssh, lambda k: fp256(k[1])))
    reg("ssh", ("fingerprint_md5", "md5_fingerprint", "public_key_fingerprint_md5"), "forms", of(_ssh, lambda k: fpmd5(k[1])))
    reg("ssh", ("rsa_public_exponent", "public_exponent"), "integer",
        of(_ssh, lambda k: int.from_bytes(_ssh_strings(k[1], 2)[0][1], "big") if k[0] == "ssh-rsa" else U("not an RSA key")))
    reg("ssh", ("private_key_cipher", "private_key_cipher_name", "private_key_encryption"), "text", of(_ssh_private, lambda p: p[0]))
    reg("ssh", ("private_key_kdf", "private_key_kdf_name"), "text", of(_ssh_private, lambda p: p[1]))
    reg("ssh", ("private_key_encrypted", "private_key_is_encrypted", "private_key_passphrase_protected"), "bool",
        of(_ssh_private, lambda p: p[0] != "none"))
    reg("ssh", ("private_key_type", "private_key_algorithm"), "text",
        of(_ssh_private, lambda p: _ssh_strings(p[2], 1)[0][0].decode()))
    reg("ssh", ("private_key_public_fingerprint_sha256", "private_key_fingerprint_sha256", "private_key_fingerprint"), "forms",
        of(_ssh_private, lambda p: fp256(p[2])))

    namespace("jwt", tokens=("jwt", "token"), test=lambda d: _jwt(d) is not None, alias=("json_web_token", "jws"))
    reg("jwt", ("algorithm", "alg", "header_algorithm", "signing_algorithm"), "text",
        of(_jwt, lambda t: t[0]["alg"] if isinstance(t[0]["alg"], str) else U("an alg that is not text")))
    reg("jwt", ("signature_size_bytes", "signature_length_bytes"), "integer", of(_jwt, lambda t: len(t[2])))
    reg("jwt", ("signature_hex", "signature"), "hex", of(_jwt, lambda t: t[2].hex() or None))
    reg("jwt", ("signature_present", "signed", "is_signed", "has_signature"), "bool", of(_jwt, lambda t: bool(t[2])))
    reg("jwt", ("header_keys", "header_fields", "header_parameter_names"), "list", of(_jwt, lambda t: [str(k) for k in t[0]] or None))
    reg("jwt", ("payload_keys", "claim_names", "claims", "payload_fields"), "list",
        of(_jwt, lambda t: [str(k) for k in t[1]] or None if isinstance(t[1], dict) else U("a payload that is not an object")))
    for claim in ("exp", "iat", "nbf"):
        reg("jwt", (f"payload_{claim}", f"claim_{claim}", claim), "unixtime",
            of(_jwt, lambda t, claim=claim: (lambda v: None if v is None else v if isinstance(v, int) and not isinstance(v, bool) and v >= 0
                                             else U("a time claim that is not a whole number"))(t[1].get(claim) if isinstance(t[1], dict) else None)))
    M.family(r"jwt_header_(.+)", "any")(path_family(_jwt, lambda t: t[0]))
    M.family(r"jwt_(?:payload_|claims_|claim_)?(.+)", "any")(path_family(_jwt, lambda t: t[1]))


# ------------------------------------------------------------------ model and array files

GGUF_SCALAR = {0: "<B", 1: "<b", 2: "<H", 3: "<h", 4: "<I", 5: "<i", 6: "<f", 7: "<?", 10: "<Q", 11: "<q", 12: "<d"}


@functools.lru_cache(maxsize=4)
def _gguf(d: bytes):
    """(version, tensor count, {key: value}) of a GGUF header; an array longer than 64 items is
    kept as its length only, or None when the file is not GGUF."""
    if d[:4] != b"GGUF":
        return None
    version = M._at("<I", d, 4)[0]
    if version not in (2, 3):
        U("a GGUF version that is not read")
    tensors, count = M._at("<QQ", d, 8)
    if count > 4096:
        U("more metadata entries than are walked")
    i, meta, budget = 24, {}, [2_000_000]

    def string(i):
        n = M._at("<Q", d, i)[0]
        if n > 1 << 20 or i + 8 + n > len(d):
            U("a string that runs past the file")
        return d[i + 8:i + 8 + n], i + 8 + n

    def value(kind, i, depth=0):
        budget[0] -= 1
        if budget[0] < 0 or depth > 4:
            U("metadata larger than is walked")
        if kind in GGUF_SCALAR:
            fmt = GGUF_SCALAR[kind]
            return M._at(fmt, d, i)[0], i + struct.calcsize(fmt)
        if kind == 8:
            raw, i = string(i)
            return raw.decode("utf-8", "replace"), i
        if kind == 9:
            sub, n = M._at("<IQ", d, i)
            i += 12
            if sub in GGUF_SCALAR and n > 64:  # a long numeric array: stepped over, not read
                size = struct.calcsize(GGUF_SCALAR[sub])
                if i + n * size > len(d):
                    U("an array that runs past the file")
                return ("array", n), i + n * size
            items = []
            for _ in range(n):
                v, i = value(sub, i, depth + 1)
                if len(items) <= 64:
                    items.append(v)
            return (items if n <= 64 else ("array", n)), i
        U("a metadata value of a type that is not read")
    for _ in range(count):
        key, i = string(i)
        kind = M._at("<I", d, i)[0]
        meta[key.decode("utf-8", "replace")], i = value(kind, i + 4)
    return version, tensors, meta


def _gguf_field(n, d, field):
    g = _gguf(d)
    if g is None:
        return None
    hits = [v for k, v in g[2].items() if field in key_names(k)]
    if len(hits) != 1:
        return U("several keys spell that name") if hits else None
    v = hits[0]
    if isinstance(v, tuple):
        U(f"an array of {v[1]} items, which is not read")
    return plain_value(v)


@functools.lru_cache(maxsize=4)
def _safetensors(d: bytes):
    """(header length, header object) of a safetensors file, or None."""
    if len(d) < 10 or d[8:9] != b"{":
        return None
    n = struct.unpack("<Q", d[:8])[0]
    if not 2 <= n <= min(len(d) - 8, 100 << 20):
        return None
    try:
        head = json.loads(d[8:8 + n])
    except (ValueError, RecursionError):
        return None
    return (n, head) if isinstance(head, dict) else None


def _st_tensors(head: dict):
    return {k: v for k, v in head.items() if k != "__metadata__" and isinstance(v, dict)}


@functools.lru_cache(maxsize=4)
def _pickle(d: bytes):
    """(protocol, opcode count, global names, has REDUCE) of a pickle stream of protocol 2 or later,
    read with pickletools (nothing is ever unpickled), or None when the file is not one."""
    if len(d) < 3 or d[0] != 0x80 or not 2 <= d[1] <= 5 or len(d) > 1 << 26:
        return None
    import pickletools
    count, globals_, reduce_, strings = 0, [], False, []
    try:
        for op, arg, _ in pickletools.genops(d):
            count += 1
            if count > 2_000_000:
                U("more opcodes than are walked")
            if op.name == "GLOBAL":
                globals_.append(arg.replace(" ", "."))
            elif op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "BINUNICODE8"):
                strings.append(arg)
                continue
            elif op.name in ("MEMOIZE", "BINPUT", "LONG_BINPUT", "PUT"):
                continue
            elif op.name == "STACK_GLOBAL":
                if len(strings) < 2:
                    U("a STACK_GLOBAL whose names are not the two strings before it")
                globals_.append(f"{strings[-2]}.{strings[-1]}")
            elif op.name in ("REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"):
                reduce_ = reduce_ or op.name == "REDUCE"
            strings = []
    except M.Unknown:
        raise
    except Exception as e:
        U(f"the stream does not read as a pickle ({type(e).__name__})")
    return d[1], count, globals_, reduce_


def _npy(d: bytes):
    if d[:6] != b"\x93NUMPY" or len(d) < 12:
        return None
    major, minor = d[6], d[7]
    n, at = (struct.unpack("<H", d[8:10])[0], 10) if major == 1 else (struct.unpack("<I", d[8:12])[0], 12)
    if n > 1 << 16 or at + n > len(d):
        U("a header that runs past the file")
    import ast
    try:
        head = ast.literal_eval(d[at:at + n].decode("latin-1"))
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        U("a header that is not a literal dictionary")
    if not isinstance(head, dict):
        U("a header that is not a dictionary")
    return (major, minor), n, head


@section
def _reg_models():
    namespace("gguf", test=lambda d: d[:4] == b"GGUF")
    reg("gguf", ("version", "header_version", "format_version"), "integer", of(_gguf, lambda g: g[0]))
    reg("gguf", ("tensor_count", "header_tensor_count"), "integer", of(_gguf, lambda g: g[1]))
    reg("gguf", ("metadata_kv_count", "header_metadata_kv_count", "metadata_count", "kv_count", "metadata_key_count"), "integer",
        of(_gguf, lambda g: len(g[2])))
    reg("gguf", ("metadata_keys", "metadata_key_names", "kv_keys"), "list", of(_gguf, lambda g: list(g[2]) or None))
    M.family(r"gguf_(?:metadata_|kv_)?(.+)", "any")(_gguf_field)

    namespace("safetensors", test=lambda d: _safetensors(d) is not None)
    reg("safetensors", ("header_size_bytes", "header_length_bytes", "header_length", "header_size", "json_header_size_bytes"), "integer",
        of(_safetensors, lambda s: s[0]))
    reg("safetensors", ("tensor_count",), "integer", of(_safetensors, lambda s: len(_st_tensors(s[1]))))
    reg("safetensors", ("tensor_names", "tensor_keys"), "list", of(_safetensors, lambda s: list(_st_tensors(s[1])) or None))
    reg("safetensors", ("dtypes", "tensor_dtypes", "unique_dtypes"), "list",
        of(_safetensors, lambda s: list(dict.fromkeys(str(v.get("dtype")) for v in _st_tensors(s[1]).values())) or None))
    reg("safetensors", ("metadata_keys", "metadata_key_names"), "list",
        of(_safetensors, lambda s: [str(k) for k in s[1].get("__metadata__") or {}] or None))
    reg("safetensors", ("metadata_present", "has_metadata"), "bool", of(_safetensors, lambda s: bool(s[1].get("__metadata__"))))
    first = lambda s: next(iter(_st_tensors(s[1]).items()), (None, {}))
    reg("safetensors", ("first_tensor_name",), "text", of(_safetensors, lambda s: first(s)[0]))
    reg("safetensors", ("first_tensor_dtype",), "text", of(_safetensors, lambda s: first(s)[1].get("dtype")))
    reg("safetensors", ("first_tensor_shape",), "intlist", of(_safetensors, lambda s: first(s)[1].get("shape") or None))
    M.family(r"safetensors_metadata_(.+)", "any")(path_family(_safetensors, lambda s: s[1].get("__metadata__") or {}))

    namespace("pickle", tokens=("pkl", "pt", "pth", "joblib"), test=lambda d: len(d) > 2 and d[0] == 0x80 and 2 <= d[1] <= 5,
              alias=("pkl",))
    reg("pickle", ("protocol", "protocol_version", "proto"), "integer", of(_pickle, lambda p: p[0]))
    reg("pickle", ("opcode_count",), "integer", of(_pickle, lambda p: p[1]))
    reg("pickle", ("global_imports", "globals", "imports", "imported_globals", "global_names"), "list",
        of(_pickle, lambda p: list(dict.fromkeys(p[2])) or None))
    reg("pickle", ("global_import_count", "global_count"), "integer", of(_pickle, lambda p: len(set(p[2]))))
    reg("pickle", ("imported_modules", "modules"), "list",
        of(_pickle, lambda p: list(dict.fromkeys(g.rsplit(".", 1)[0] for g in p[2])) or None))
    reg("pickle", ("reduce_present", "has_reduce", "uses_reduce", "reduce_opcode_present"), "bool", of(_pickle, lambda p: p[3]))

    namespace("npy", test=lambda d: d[:6] == b"\x93NUMPY", alias=("numpy",))
    reg("npy", ("version", "format_version", "header_version"), "dotted", of(_npy, lambda h: h[0]))
    reg("npy", ("header_length", "header_len", "header_size_bytes", "header_length_bytes"), "integer", of(_npy, lambda h: h[1]))
    reg("npy", ("dtype", "descr", "header_descr"), "text",
        of(_npy, lambda h: h[2]["descr"] if isinstance(h[2].get("descr"), str) else U("a structured dtype, which is not read")))
    reg("npy", ("fortran_order", "header_fortran_order"), "bool",
        of(_npy, lambda h: h[2]["fortran_order"] if isinstance(h[2].get("fortran_order"), bool) else U("no fortran_order")))
    reg("npy", ("shape", "header_shape"), "intlist",
        of(_npy, lambda h: list(h[2]["shape"]) if isinstance(h[2].get("shape"), tuple) and h[2]["shape"]
           else U("a scalar array, or no shape")))
    reg("npy", ("dimension_count", "ndim"), "integer",
        of(_npy, lambda h: len(h[2]["shape"]) if isinstance(h[2].get("shape"), tuple) else U("no shape")))


# ------------------------------------------------------------------ mail

MAIL_HEADS = re.compile(rb"^(from|to|subject|date|received|message-id|mime-version|return-path|delivered-to):", re.I | re.M)


UTF8_BOM = b"\xef\xbb\xbf"
# Day 18 look-ahead (build item 5). An mbox is read by its first message's header block, so a field of "the
# message" in a file of several is any of them: Unknown. A separator is a line that starts 'From ' (mboxo,
# mboxrd); an unescaped body line of that form counts too, which only ever makes the answer None.
MBOX_FROM = re.compile(rb"(?:\A|(?<=\n))From \S")
# One msg-id token of a Message-ID header (RFC 5322 3.6.4): what stands beside it is a comment or noise.
MSGID_TOKEN = re.compile(r"<[^<>]*>")


@functools.lru_cache(maxsize=4)
def _eml(d: bytes):
    """The header block of an RFC 5322 message as an email.message.Message, or None. A UTF-8 BOM in
    front of the first header is read through (Day 18 look-ahead: the message was None before)."""
    if d[:3] == UTF8_BOM:
        d = d[3:]
    if len(d) > 1 << 25 or not re.match(rb"[A-Za-z][A-Za-z0-9-]*:[ \t]|From ", d[:80]):
        return None
    m = re.search(rb"\r?\n\r?\n", d)
    head = d[:m.start() + 2] if m else d
    if len(head) > 1 << 20 or len(set(x.lower() for x in MAIL_HEADS.findall(head))) < 2:
        return None
    import email.parser
    import email.policy
    return email.parser.BytesHeaderParser(policy=email.policy.compat32).parsebytes(head)


def _mbox_count(d: bytes) -> int:
    """How many messages an mbox holds (1 for a file that does not start with an mbox 'From ' line)."""
    if d[:3] == UTF8_BOM:
        d = d[3:]
    return len(MBOX_FROM.findall(d)) if d[:5] == b"From " else 1


def _eml1(d: bytes):
    """_eml() for the readers of one message's fields: Unknown for an mbox of several messages."""
    msg = _eml(d)
    if msg is not None:
        n = _mbox_count(d)
        if n > 1:
            U(f"an mbox of {n} messages: a field of one message is not settled by it")
    return msg


def _mail_value(raw) -> str:
    """A header's value unfolded and with its RFC 2047 words decoded."""
    import email.header
    s = re.sub(r"\r?\n[ \t]+", " ", str(raw)).strip()
    try:
        return str(email.header.make_header(email.header.decode_header(s)))
    except Exception:
        U("a header whose encoded words do not decode")


def _mail_header(n, d, field):
    msg = _eml1(d)
    if msg is None:
        return None
    values = [_mail_value(v) for v in msg.get_all(field.replace("_", "-")) or []]
    if len(set(values)) > 1:
        U(f"the message has {len(values)} such headers")
    if field == "message_id" and values and values[0]:
        # Day 18 look-ahead (build item 5): the judged form is the header as written (Day 16, raw~eml.message_id),
        # seen only as one <...> token. Anything beside the token (a comment, a trailing word) leaves open
        # which the judge takes: the token first, the whole value second, under names no day has judged.
        tokens = MSGID_TOKEN.findall(values[0])
        if len(tokens) > 1:
            U(f"the Message-ID holds {len(tokens)} <...> tokens")
        if len(tokens) == 1 and tokens[0] != values[0].strip():
            raise M.Ambiguous([("angle_token", tokens[0]), ("raw_full", values[0])])
    return values[0] or None if values else None


def _mail_addr(header: str, part: str):
    def get(msg):
        import email.utils
        values = msg.get_all(header) or []
        if len(values) != 1:
            return U("several such headers") if values else None
        pairs = email.utils.getaddresses([_mail_value(values[0])])
        if len(pairs) != 1 or "@" not in pairs[0][1]:
            U("not exactly one address")
        name, addr = pairs[0]
        return {"address": addr, "domain": addr.rsplit("@", 1)[1], "name": name or None, "local": addr.rsplit("@", 1)[0]}[part]
    return of(_eml1, get)


def _mail_date(msg):
    import email.utils
    values = msg.get_all("Date") or []
    if len(values) != 1:
        return U("several Date headers") if values else None
    raw = _mail_value(values[0])
    out = [("rfc2822", raw)]
    try:
        dt = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return out
    if dt.tzinfo is not None:
        utc = dt.astimezone(datetime.timezone.utc)
        stamp = utc.strftime("%Y-%m-%dT%H:%M:%S")
        out += [("iso_z", stamp + "Z"), ("iso", dt.replace(tzinfo=None).strftime("%Y-%m-%dT%H:%M:%S")),
                ("unix", str(int(utc.timestamp())))]
    return out


def _mail_parts(d: bytes):
    """The attachment file names of a message, in order, or None when the file is not a message."""
    if _eml1(d) is None:
        return None
    import email
    import email.policy
    try:
        msg = email.message_from_bytes(d[3:] if d[:3] == UTF8_BOM else d, policy=email.policy.compat32)
        names = []
        for i, part in enumerate(msg.walk()):
            if i > 4096:
                U("more parts than are walked")
            name = part.get_filename()
            if name:
                names.append(_mail_value(name))
        return names
    except M.Unknown:
        raise
    except Exception as e:
        U(f"the message body does not parse ({type(e).__name__})")


@section
def _reg_mail():
    namespace("eml", tokens=("eml", "mbox"), test=lambda d: _eml(d) is not None, alias=("email", "mail", "rfc822", "message"))
    reg("eml", ("date", "header_date", "date_header", "sent_date"), "forms", of(_eml1, _mail_date))
    for names, header, part in ((("from_address", "sender_address", "from_email", "from_email_address"), "From", "address"),
                                (("from_domain", "sender_domain"), "From", "domain"),
                                (("from_display_name", "from_name", "sender_name"), "From", "name"),
                                (("to_address", "recipient_address", "to_email"), "To", "address"),
                                (("to_domain", "recipient_domain"), "To", "domain"),
                                (("reply_to_address",), "Reply-To", "address"), (("reply_to_domain",), "Reply-To", "domain"),
                                (("return_path_address", "envelope_from"), "Return-Path", "address"),
                                (("return_path_domain",), "Return-Path", "domain")):
        reg("eml", names, "text", _mail_addr(header, part))
    reg("eml", ("received_count", "received_header_count", "hop_count"), "integer", of(_eml1, lambda m: len(m.get_all("Received") or [])))
    reg("eml", ("header_names", "header_fields", "header_order"), "list", of(_eml1, lambda m: list(m.keys()) or None))
    reg("eml", ("header_count",), "integer", of(_eml1, lambda m: len(m.keys())))
    reg("eml", ("content_type_main", "media_type", "mime_type"), "text", of(_eml1, lambda m: m.get_content_type()))
    reg("eml", ("boundary", "mime_boundary", "multipart_boundary"), "text", of(_eml1, lambda m: m.get_boundary()))
    reg("eml", ("attachment_names", "attachment_filenames", "attachments"), "list", lambda n, d: (_mail_parts(d) or None) if _eml1(d) else None)
    reg("eml", ("attachment_count",), "integer", lambda n, d: len(_mail_parts(d)) if _eml1(d) else None)

    def to_list(n, d):
        import email.utils
        msg = _eml1(d)
        if msg is None:
            return None
        addrs = [a for _, a in email.utils.getaddresses([_mail_value(v) for v in msg.get_all("To") or []]) if a]
        return addrs or None
    reg("eml", ("to_addresses", "recipient_addresses", "recipients"), "list", to_list)
    _reg_mail_identity(to_list)
    M.family(r"eml_(?:header_)?([a-z0-9_]+)", "text")(_mail_header)


# Row 319 (the Day 20 build): the identity headers of a message as explicit readers, under the spellings a question
# uses that the catch-all family `eml_<header>` does not reach (`subject_line`, `message_id_header`, `cc_address`,
# `correlation_id`). Each reads the one header as written (unfolded, RFC 2047 words decoded) through _mail_header, so
# message_id keeps its Day 18 rules, and the names the family already read keep their extractor and their key: only
# `metadata.format/email_message_id` (`raw~eml.message_id`, Day 16) is judged, every other name is unsure.
MAIL_IDENTITY = (("message_id", ("message_id", "message_id_header", "msgid", "message_identifier")),
                 ("subject", ("subject", "subject_line", "subject_header", "subject_text")),
                 ("in_reply_to", ("in_reply_to", "in_reply_to_header", "in_reply_to_id", "parent_message_id")),
                 ("references", ("references", "references_header", "reference_ids")),
                 ("return_path", ("return_path", "return_path_header")),
                 ("sender", ("sender", "sender_header")),
                 ("x_mailer", ("x_mailer", "mailer", "mailer_name", "x_mailer_header")),
                 ("user_agent", ("user_agent", "user_agent_header")))
CORRELATION = re.compile(r"(?i)^x-(?:[a-z0-9]+-)*correlation(?:-id)?$")


def _correlation_id(n, d):
    """The value of the one X-...-Correlation (or -Correlation-ID) header, or None; two such headers that differ are
    Unknown."""
    msg = _eml1(d)
    if msg is None:
        return None
    vals = {_mail_value(v) for k, v in msg.items() if CORRELATION.match(k)}
    if len(vals) > 1:
        U(f"{len(vals)} correlation headers that differ")
    return vals.pop() or None if vals else None


def _reg_mail_identity(to_list):
    for header, names in MAIL_IDENTITY:
        reg("eml", names, "text", lambda n, d, h=header: _mail_header(n, d, h))
    reg("eml", ("correlation_id", "correlation_header", "x_correlation_id"), "text", _correlation_id)
    reg("eml", ("cc_address", "cc_email"), "text", _mail_addr("Cc", "address"))
    reg("eml", ("cc_domain",), "text", _mail_addr("Cc", "domain"))

    def cc_list(n, d):
        import email.utils
        msg = _eml1(d)
        if msg is None:
            return None
        addrs = [a for _, a in email.utils.getaddresses([_mail_value(v) for v in msg.get_all("Cc") or []]) if a]
        return addrs or None
    reg("eml", ("cc_addresses", "cc_recipients"), "list", cc_list)


# ------------------------------------------------------------------ JSON, XML, HTML, CSV, INI

@functools.lru_cache(maxsize=4)
def _json(d: bytes):
    """(the document,) of a JSON file, or None. Wrapped so that a null document is not 'no file'."""
    t = as_text(d)
    if t is None or t.lstrip()[:1] not in ("{", "["):
        return None
    try:
        return (json.loads(t),)
    except RecursionError:
        U("a document nested deeper than is parsed")
    except ValueError:
        return None


JSON_TYPE = {dict: "object", list: "array", str: "string", bool: "boolean", int: "number", float: "number"}


def _xml_head(d: bytes):
    """(declaration attributes, root tag text, the document text) of an XML document, or None."""
    t = as_text(d)
    if t is None:
        return None
    s = t.lstrip()
    if not s.startswith("<") or s[:15].lower().startswith(("<!doctype html", "<html")):
        return None
    decl = re.match(r"<\?xml\s+([^?]*)\?>", s)
    body = re.sub(r"<!--.*?-->|<\?.*?\?>|<!DOCTYPE[^\[>]*(?:\[.*?\])?\s*>", "", s[:1 << 16], flags=re.S)
    m = re.search(r"<([A-Za-z_][\w.:-]*)((?:\s[^<>]*)?)/?>", body)
    if not m:
        return None
    return decl.group(1) if decl else "", m.group(0), m.group(1), s


def _attr(tag: str, name: str):
    import html
    found = re.findall(rf"""\s{re.escape(name)}\s*=\s*(?:"([^"]*)"|'([^']*)')""", tag)
    if len(found) > 1:
        U(f"the attribute {name} is given twice")
    return html.unescape(found[0][0] or found[0][1]) or None if found else None


def _xml_root_attr(n, d, field):
    x = _xml_head(d)
    if x is None:
        return None
    names = [a for a in re.findall(r"\s([A-Za-z_][\w.:-]*)\s*=", x[1]) if M.canon(a) == field]
    if len(set(names)) != 1:
        return U("several attributes spell that name") if names else None
    return _attr(x[1], names[0])


def _html(d: bytes):
    t = as_text(d)
    if t is None or not re.search(r"<!doctype\s+html|<html[\s>]", t[:4096], re.I):
        return None
    return t


def _html_meta(n, d, field):
    import html
    t = _html(d)
    if t is None:
        return None
    values = []
    for tag in re.findall(r"<meta\s[^<>]*>", t[:1 << 20], re.I)[:2000]:  # [^<>]: a tag that never closes is not scanned to the end
        key = next((v for v in (_attr(tag, a) for a in ("name", "property", "http-equiv", "itemprop")) if v), None)
        if key and M.canon(key) == field:
            values.append(_attr(tag, "content") or "")
    if len(set(values)) > 1:
        U("several meta elements of that name")
    return html.unescape(values[0]) or None if values else None


def _html_attrs(tag: str, attr: str):
    def fn(n, d):
        t = _html(d)
        if t is None:
            return None
        out = []
        for el in re.findall(rf"<{tag}\s[^<>]*>", t, re.I)[:5000]:
            v = _attr(el, attr)
            if v:
                out.append(v)
        return out or None
    return fn


CSV_DELIMS = {",": "comma", ";": "semicolon", "\t": "tab", "|": "pipe"}


@functools.lru_cache(maxsize=4)
def _csv(d: bytes):
    """(delimiter, rows) of a delimited text file whose first line uses exactly one of , ; tab |."""
    t = as_text(d)
    if t is None or not t.strip():
        return None
    first = t.splitlines()[0]
    used = [c for c in CSV_DELIMS if c in first]
    if len(used) != 1:
        return U("the first line uses several delimiters") if used else None
    import csv
    try:
        rows = [r for i, r in zip(range(500001), csv.reader(io.StringIO(t, newline=""), delimiter=used[0]))]
    except csv.Error as e:
        U(f"the file does not read as delimited text ({e})")
    if len(rows) > 500000:
        U("more rows than are read")
    while rows and not rows[-1]:
        rows.pop()
    return used[0], rows


@functools.lru_cache(maxsize=4)
def _ini(d: bytes):
    """{section: {key: [values]}} (names canonical) of an INI-style text with at least one section, or None."""
    t = as_text(d)
    # Blanks of one line only: `\s*` after `^` under re.M also runs over the line ends, and a text of
    # two megabytes of empty lines then took minutes (each line start scans to the end of the text).
    if t is None or not re.search(r"^[ \t]*\[[^\]\r\n]+\][ \t]*\r?$", t, re.M):
        return None
    out, section_ = {}, None
    for line in t.splitlines()[:200000]:
        s = line.strip()
        if not s or s[0] in ";#":
            continue
        m = re.fullmatch(r"\[([^\]]+)\]", s)
        if m:
            section_ = out.setdefault(M.canon(m.group(1)), {})
            continue
        k, sep, v = s.partition("=")
        if sep and section_ is not None and M.canon(k):
            section_.setdefault(M.canon(k), []).append(v.strip())
    return out if any(out.values()) else None


def _ini_get(ini: dict, section_: str, key: str):
    values = ini.get(section_, {}).get(key, [])
    if len(values) > 1:
        U(f"the key {key} is given several times")
    return values[0] or None if values else None


def _ini_field(n, d, field):
    ini = _ini(d)
    if ini is None:
        return None
    tokens, hits = field.split("_"), []
    for i in range(1, len(tokens)):
        sec, key = "_".join(tokens[:i]), "_".join(tokens[i:])
        if key in ini.get(sec, {}):
            hits.append(_ini_get(ini, sec, key))
    if len(hits) > 1:
        U("the name splits into a section and a key in several ways")
    return hits[0] if hits else None


URLZONE = {0: "URLZONE_LOCAL_MACHINE", 1: "URLZONE_INTRANET", 2: "URLZONE_TRUSTED", 3: "URLZONE_INTERNET", 4: "URLZONE_UNTRUSTED"}


def _zone(d: bytes):
    ini = _ini(d)
    return ini.get("zonetransfer") if ini and "zonetransfer" in ini else None


@section
def _reg_text():
    namespace("json", tokens=("json", "ipynb", "har", "geojson"), test=lambda d: _json(d) is not None)
    reg("json", ("top_level_type", "root_type", "type"), "label",
        of(_json, lambda j: JSON_TYPE.get(type(j[0])) or ("null" if j[0] is None else U("a root of a type that is not named"))))
    reg("json", ("key_count", "top_level_key_count", "root_key_count"), "integer",
        of(_json, lambda j: len(j[0]) if isinstance(j[0], dict) else U("the root is not an object")))
    reg("json", ("keys", "top_level_keys", "root_keys", "key_names"), "list",
        of(_json, lambda j: list(j[0]) or None if isinstance(j[0], dict) else U("the root is not an object")))
    reg("json", ("array_length", "top_level_array_length", "length", "item_count", "element_count"), "integer",
        of(_json, lambda j: len(j[0]) if isinstance(j[0], list) else U("the root is not an array")))
    M.family(r"json_(?:value_|field_|key_|path_)?(.+)", "any")(path_family(_json, lambda j: j[0]))

    namespace("xml", tokens=("xml",), test=lambda d: _xml_head(d) is not None)
    reg("xml", ("version", "declaration_version", "xml_version"), "text", of(_xml_head, lambda x: _attr(" " + x[0], "version")))
    reg("xml", ("encoding", "declared_encoding", "declaration_encoding"), "text", of(_xml_head, lambda x: _attr(" " + x[0], "encoding")))
    reg("xml", ("standalone", "declaration_standalone"), "text", of(_xml_head, lambda x: _attr(" " + x[0], "standalone")))
    reg("xml", ("root_element", "root_tag", "root_name", "root_element_name", "document_element"), "text", of(_xml_head, lambda x: x[2]))
    reg("xml", ("root_namespace", "root_xmlns", "default_namespace", "xmlns"), "text", of(_xml_head, lambda x: _attr(x[1], "xmlns")))
    reg("xml", ("root_attribute_names", "root_attributes"), "list",
        of(_xml_head, lambda x: re.findall(r"\s([A-Za-z_][\w.:-]*)\s*=", x[1]) or None))
    reg("xml", ("doctype_present", "has_doctype"), "bool", of(_xml_head, lambda x: bool(re.search(r"<!DOCTYPE\s", x[3]))))
    reg("xml", ("doctype_name", "doctype"), "text",
        of(_xml_head, lambda x: (lambda m: m.group(1) if m else None)(re.search(r"<!DOCTYPE\s+([^\s\[>]+)", x[3]))))
    reg("xml", ("external_entity_present", "has_external_entity", "xxe_present", "external_entity_declared"), "bool",
        of(_xml_head, lambda x: bool(re.search(r"<!ENTITY\s+%?\s*\S+\s+(?:SYSTEM|PUBLIC)\s", x[3]))))
    reg("xml", ("entity_count", "entity_declaration_count"), "integer", of(_xml_head, lambda x: len(re.findall(r"<!ENTITY\s", x[3]))))
    reg("xml", ("comment_count",), "integer", of(_xml_head, lambda x: len(re.findall(r"<!--", x[3]))))
    M.family(r"xml_root_(?:attribute|attr)_([a-z0-9_]+)", "text")(_xml_root_attr)

    namespace("html", tokens=("html", "htm"), test=lambda d: _html(d) is not None, alias=("htm",))

    def title(n, d):
        import html
        t = _html(d)
        if t is None:
            return None
        # Nothing after the last closing tag is searched: a run of opening tags with no closing
        # one would each be scanned to the end of the text (minutes on two megabytes).
        last = [m.end() for m in re.finditer(r"</title>", t, re.I)]
        found = re.findall(r"<title(?:\s[^<>]*)?>(.*?)</title>", t[:last[-1]], re.I | re.S) if last else []
        if len(found) > 1:
            U("several title elements")
        return html.unescape(found[0]).strip() or None if found else None
    reg("html", ("title", "title_text", "page_title"), "text", title)
    reg("html", ("lang", "language", "html_lang"), "text",
        lambda n, d: (lambda t: None if t is None else (lambda m: _attr(m.group(0), "lang") if m else None)(
            re.search(r"<html\s[^>]*>", t, re.I)))(_html(d)))
    reg("html", ("script_count", "script_element_count", "script_tag_count"), "integer",
        of(_html, lambda t: len(re.findall(r"<script[\s>]", t, re.I))))
    reg("html", ("script_sources", "script_srcs", "external_script_urls", "script_src_urls"), "list", _html_attrs("script", "src"))
    reg("html", ("form_actions", "form_action_urls"), "list", _html_attrs("form", "action"))
    reg("html", ("iframe_sources", "iframe_srcs", "iframe_urls"), "list", _html_attrs("iframe", "src"))
    reg("html", ("link_hrefs", "stylesheet_urls"), "list", _html_attrs("link", "href"))
    reg("html", ("anchor_hrefs", "link_urls", "a_hrefs"), "list", _html_attrs("a", "href"))
    reg("html", ("comment_count",), "integer", of(_html, lambda t: len(re.findall(r"<!--", t))))
    reg("html", ("doctype",), "text",
        of(_html, lambda t: (lambda m: m.group(1).strip() if m else None)(re.search(r"<!doctype\s+([^>]*)>", t[:4096], re.I))))
    M.family(r"html_meta_([a-z0-9_]+)", "text")(_html_meta)

    namespace("csv", tokens=("csv", "tsv"), alias=("tsv",))
    reg("csv", ("delimiter", "separator", "field_delimiter"), "forms", of(_csv, lambda c: [("raw", c[0]), ("name", CSV_DELIMS[c[0]])]))

    def columns(c):
        widths = {len(r) for r in c[1] if r}
        if len(widths) != 1:
            U("rows of several widths")
        return widths.pop()
    reg("csv", ("column_count", "field_count", "header_column_count", "columns"), "integer", of(_csv, columns))
    reg("csv", ("header", "column_names", "headers", "header_fields", "header_row", "field_names"), "list",
        of(_csv, lambda c: c[1][0] if c[1] and all(c[1][0]) else U("a header row with an empty field")))

    def rows(c):
        n = len(c[1])
        raise M.Ambiguous([("data_rows", str(n - 1)), ("with_header", str(n))])
    reg("csv", ("row_count", "record_count", "rows"), "integer", of(_csv, rows))
    reg("csv", ("data_row_count", "data_record_count"), "integer", of(_csv, lambda c: len(c[1]) - 1))

    namespace("ini", tokens=("ini", "inf", "url", "desktop", "cfg", "conf", "service"), alias=("inf", "desktop", "internet_shortcut"))
    reg("ini", ("section_names", "sections"), "list", of(_ini, lambda i: list(i) or None))
    reg("ini", ("section_count",), "integer", of(_ini, lambda i: len(i)))
    M.family(r"ini_(.+)", "text")(_ini_field)

    namespace("zoneidentifier", test=lambda d: _zone(d) is not None,
              alias=("zone_identifier", "motw", "mark_of_the_web", "zone", "zonetransfer", "zone_transfer", "ads_zone_identifier"))

    def zone_id(z):
        v = _ini_get({"z": z}, "z", "zoneid")
        return None if v is None else (URLZONE.get(int(v)), int(v)) if v.isdigit() else U("a ZoneId that is not a number")
    reg("zoneidentifier", ("zone_id", "zoneid", "zone_transfer_zone_id", "zone"), "code", of(_zone, zone_id))
    for names, key in ((("host_url", "hosturl", "download_url", "source_url"), "hosturl"),
                       (("referrer_url", "referrerurl", "referrer"), "referrerurl"),
                       (("last_writer_package_family_name",), "lastwriterpackagefamilyname"),
                       (("app_zone_id",), "appzoneid"), (("host_ip_address",), "hostipaddress")):
        reg("zoneidentifier", names, "text", of(_zone, lambda z, key=key: _ini_get({"z": z}, "z", key)))


# ------------------------------------------------------------------ RTF, torrents

def _rtf(d: bytes):
    return d if d[:5] == b"{\\rtf" and len(d) <= 1 << 26 else None


def _rtf_info(n, d, field):
    r = _rtf(d)
    if r is None:
        return None
    word = {"comment": "doccomm"}.get(field, field).encode()
    found = re.findall(rb"\{\\" + word + rb"(?![a-z])[ ]?([^{}]*)\}", r[:1 << 20])
    if len(found) != 1:
        return U(f"several {field} groups") if found else None
    if b"\\" in found[0]:
        U(f"the {field} text uses control words, which are not decoded")
    return found[0].decode("latin-1").strip() or None


def _rtf_time(word: bytes):
    def get(r):
        found = re.findall(rb"\{\\" + word + rb"((?:\\[a-z]+-?\d+\s?)+)\}", r[:1 << 20])
        if len(found) != 1:
            return U("several such groups") if found else None
        f = {k.decode(): int(v) for k, v in re.findall(rb"\\([a-z]+)(-?\d+)", found[0])}
        if not all(k in f for k in ("yr", "mo", "dy")):
            U("a time group without a date")
        return (f["yr"], f["mo"], f["dy"], f.get("hr", 0), f.get("min", 0), f.get("sec", 0), False)
    return of(_rtf, get)


def _bdecode(d: bytes):
    """(value, {b'info': (start, end)}) of a bencoded file, or raises Unknown. Iteration is bounded."""
    spans, count = {}, [0]

    def item(i, depth):
        count[0] += 1
        if count[0] > 500000 or depth > 32 or i >= len(d):
            U("a bencoded value that is cut or larger than is read")
        c = d[i:i + 1]
        if c == b"i":
            end = d.index(b"e", i)
            return int(d[i + 1:end]), end + 1
        if c == b"l":
            out, i = [], i + 1
            while d[i:i + 1] != b"e":
                v, i = item(i, depth + 1)
                out.append(v)
            return out, i + 1
        if c == b"d":
            out, i = {}, i + 1
            while d[i:i + 1] != b"e":
                k, i = item(i, depth + 1)
                if not isinstance(k, bytes):
                    U("a dictionary key that is not a string")
                start = i
                v, i = item(i, depth + 1)
                if depth == 0 and k == b"info":
                    spans[k] = (start, i)
                out[k] = v
            return out, i + 1
        if c.isdigit():
            colon = d.index(b":", i)
            n = int(d[i:colon])
            if colon + 1 + n > len(d):
                U("a string that runs past the file")
            return d[colon + 1:colon + 1 + n], colon + 1 + n
        U("a byte that starts no bencoded value")
    try:
        value, end = item(0, 0)
    except (ValueError, RecursionError):
        U("the file does not read as bencode")
    return value, spans


@functools.lru_cache(maxsize=4)
def _torrent(d: bytes):
    if d[:1] != b"d" or b"4:info" not in d or len(d) > 1 << 26:
        return None
    value, spans = _bdecode(d)
    if not isinstance(value, dict) or not isinstance(value.get(b"info"), dict) or b"info" not in spans:
        return None
    return value, hashlib.sha1(d[spans[b"info"][0]:spans[b"info"][1]]).hexdigest()


def _btext(v):
    if v is None:
        return None
    if not isinstance(v, bytes):
        U("a value that is not a string")
    try:
        return v.decode("utf-8") or None
    except UnicodeDecodeError:
        U("text that does not decode")


def _bint(v):
    if v is None:
        return None
    return v if isinstance(v, int) and v >= 0 else U("a value that is not a whole number")


def _torrent_files(t):
    info = t[0][b"info"]
    if b"files" in info:
        files = info[b"files"]
        if not isinstance(files, list) or not all(isinstance(f, dict) and isinstance(f.get(b"path"), list) for f in files):
            U("a files list that is not read")
        return [("/".join(_btext(p) or "" for p in f[b"path"]), _bint(f.get(b"length"))) for f in files]
    return [(_btext(info.get(b"name")), _bint(info.get(b"length")))]


@section
def _reg_misc():
    namespace("rtf", tokens=("rtf",), test=lambda d: d[:5] == b"{\\rtf")
    M.family(r"rtf_(?:info_)?(title|subject|author|manager|company|operator|category|keywords|comment|doccomm)", "text")(_rtf_info)
    reg("rtf", ("creation_time", "info_creatim", "creatim", "created", "info_creation_time"), "timestamp", _rtf_time(b"creatim"))
    reg("rtf", ("revision_time", "info_revtim", "revtim", "modified", "info_revision_time"), "timestamp", _rtf_time(b"revtim"))
    reg("rtf", ("print_time", "info_printim", "printim", "last_printed"), "timestamp", _rtf_time(b"printim"))
    reg("rtf", ("version", "header_version", "rtf_version"), "integer",
        of(_rtf, lambda r: (lambda m: int(m.group(1)) if m else U("no version follows \\rtf"))(re.match(rb"\{\\rtf(\d+)", r))))
    reg("rtf", ("ansi_code_page", "ansicpg", "code_page"), "integer",
        of(_rtf, lambda r: (lambda m: int(m.group(1)) if m else None)(re.search(rb"\\ansicpg(\d+)", r[:4096]))))
    reg("rtf", ("generator", "info_generator"), "text",
        of(_rtf, lambda r: (lambda m: m.group(1).decode("latin-1").strip().rstrip(";").strip() or None if m else None)(
            re.search(rb"\{\\\*\\generator ([^{}\\]*)\}", r[:1 << 20]))))
    reg("rtf", ("object_count", "embedded_object_count"), "integer", of(_rtf, lambda r: len(re.findall(rb"\\object(?![a-z])", r))))
    reg("rtf", ("object_present", "has_embedded_object", "embedded_object_present"), "bool",
        of(_rtf, lambda r: bool(re.search(rb"\\object(?![a-z])", r))))
    reg("rtf", ("object_class", "objclass", "ole_object_class"), "text",
        of(_rtf, lambda r: (lambda f: f[0].decode("latin-1").strip() if len(set(f)) == 1 else U("several object classes") if f else None)(
            re.findall(rb"\{\\\*\\objclass ([^{}\\]*)\}", r))))
    for names, word in ((("info_page_count", "page_count", "nofpages"), b"nofpages"), (("info_word_count", "word_count", "nofwords"), b"nofwords"),
                        (("info_character_count", "character_count", "nofchars"), b"nofchars"),
                        (("info_editing_minutes", "editing_minutes", "edmins"), b"edmins"),
                        (("info_internal_version", "internal_version", "vern"), b"vern"),
                        (("info_revision_number", "revision_number"), b"version")):
        reg("rtf", names, "integer",
            of(_rtf, lambda r, word=word: (lambda f: int(f[0]) if len(f) == 1 else U("several such words") if f else None)(
                re.findall(rb"\{\\" + word + rb"(\d+)\}", r[:1 << 20]))))

    namespace("torrent", tokens=("torrent",), test=lambda d: d[:1] == b"d" and b"4:info" in d[:1 << 16], alias=("bittorrent",))
    reg("torrent", ("announce", "announce_url", "tracker", "tracker_url"), "text", of(_torrent, lambda t: _btext(t[0].get(b"announce"))))
    reg("torrent", ("name", "info_name"), "text", of(_torrent, lambda t: _btext(t[0][b"info"].get(b"name"))))
    reg("torrent", ("piece_length", "info_piece_length", "piece_length_bytes", "piece_size_bytes"), "integer",
        of(_torrent, lambda t: _bint(t[0][b"info"].get(b"piece length"))))
    reg("torrent", ("piece_count", "info_piece_count", "pieces"), "integer",
        of(_torrent, lambda t: (lambda p: len(p) // 20 if isinstance(p, bytes) and len(p) % 20 == 0 else U("no SHA-1 piece list"))(
            t[0][b"info"].get(b"pieces"))))
    reg("torrent", ("creation_date", "created", "creation_time"), "unixtime", of(_torrent, lambda t: _bint(t[0].get(b"creation date"))))
    reg("torrent", ("created_by", "creator"), "text", of(_torrent, lambda t: _btext(t[0].get(b"created by"))))
    reg("torrent", ("comment",), "text", of(_torrent, lambda t: _btext(t[0].get(b"comment"))))
    reg("torrent", ("info_hash", "infohash", "info_hash_sha1", "info_sha1", "btih"), "hex", of(_torrent, lambda t: t[1]))
    reg("torrent", ("file_count", "info_file_count"), "integer", of(_torrent, lambda t: len(_torrent_files(t))))
    reg("torrent", ("file_names", "file_paths", "info_file_paths"), "list",
        of(_torrent, lambda t: [n for n, _ in _torrent_files(t)] if all(n for n, _ in _torrent_files(t)) else U("a file without a name")))
    reg("torrent", ("total_size_bytes", "total_length_bytes", "length_bytes", "info_length"), "integer",
        of(_torrent, lambda t: sum(s for _, s in _torrent_files(t)) if all(s is not None for _, s in _torrent_files(t))
           else U("a file without a length")))
    reg("torrent", ("private", "is_private", "info_private"), "bool",
        of(_torrent, lambda t: (lambda v: None if v is None else v == 1)(t[0][b"info"].get(b"private"))))
    reg("torrent", ("announce_list", "trackers", "tracker_urls"), "list",
        of(_torrent, lambda t: (lambda al: None if al is None else [_btext(u) for tier in al for u in tier]
                                if isinstance(al, list) and all(isinstance(x, list) for x in al) else U("an announce list that is not read"))(
            t[0].get(b"announce-list"))))


# ------------------------------------------------------------------ fonts

SFNT_NAMES = {0: ("copyright", "copyright_notice"), 1: ("family", "family_name", "font_family"),
              2: ("subfamily", "subfamily_name", "style", "style_name"), 3: ("unique_id", "unique_identifier"),
              4: ("full_name", "full_font_name"), 5: ("version_string", "name_version"), 6: ("postscript_name",),
              7: ("trademark",), 8: ("manufacturer", "manufacturer_name"), 9: ("designer",), 10: ("description",),
              11: ("vendor_url",), 12: ("designer_url",), 13: ("license", "license_description"), 14: ("license_url",),
              16: ("typographic_family", "preferred_family"), 17: ("typographic_subfamily", "preferred_subfamily")}


@functools.lru_cache(maxsize=4)
def _sfnt(d: bytes):
    """{table tag: (offset, length)} of a TrueType or OpenType font (not a collection), or None."""
    if d[:4] not in (b"\x00\x01\x00\x00", b"OTTO", b"true"):
        return U("a font collection: the name does not say which font is asked") if d[:4] == b"ttcf" else None
    count = M._at(">H", d, 4)[0]
    if not 0 < count <= 256:
        return None
    out = {}
    for i in range(count):
        tag, _, off, ln = M._at(">4sIII", d, 12 + 16 * i)
        if not re.fullmatch(rb"[\x20-\x7e]{4}", tag):
            return None
        out[tag.decode()] = (off, ln)
    return out


def _sfnt_table(d: bytes, tag: str):
    t = _sfnt(d)
    if t is None:
        return None
    if tag not in t:
        U(f"the font has no {tag} table")
    off, ln = t[tag]
    if off + ln > len(d):
        U(f"the {tag} table runs past the file")
    return d[off:off + ln]


def _sfnt_name(name_id: int):
    def fn(n, d):
        t = _sfnt_table(d, "name")
        if t is None:
            return None
        _, count, strings = M._at(">HHH", t, 0)
        values = set()
        for i in range(min(count, 4096)):
            platform, encoding, language, nid, ln, off = M._at(">HHHHHH", t, 6 + 12 * i)
            if nid != name_id:
                continue
            raw = t[strings + off:strings + off + ln]
            if platform == 3 and language == 0x409 or platform == 0:
                values.add(raw.decode("utf-16-be", "replace"))
            elif platform == 1 and language == 0:
                values.add(raw.decode("mac_roman", "replace"))
        if len(values) > 1:
            U("the English name records disagree")
        return values.pop() or None if values else None
    return fn


def _woff(d: bytes):
    if d[:4] == b"wOFF":
        flavor, length, tables, _, sfnt_size, major, minor = M._at(">4sIHHIHH", d, 4)
    elif d[:4] == b"wOF2":
        flavor, length, tables, _, sfnt_size, _, major, minor = M._at(">4sIHHIIHH", d, 4)
    else:
        return None
    return flavor, length, tables, sfnt_size, (major, minor), d[:4].decode()


@section
def _reg_fonts():
    namespace("font", tokens=("ttf", "otf"), test=lambda d: d[:4] in (b"\x00\x01\x00\x00", b"OTTO", b"true", b"ttcf"),
              alias=("ttf", "otf", "sfnt", "truetype", "opentype"))
    for nid, names in SFNT_NAMES.items():
        reg("font", list(names) + [f"name_{names[0]}", f"name_id_{nid}", f"name_table_{names[0]}"], "text", _sfnt_name(nid))
    reg("font", ("table_count", "num_tables", "header_num_tables", "table_directory_count"), "integer", of(_sfnt, lambda t: len(t)))
    reg("font", ("table_tags", "tables", "table_names"), "list", of(_sfnt, lambda t: list(t)))
    reg("font", ("sfnt_version", "header_sfnt_version", "scaler_type"), "forms",
        lambda n, d: (None if _sfnt(d) is None else
                      [("0x_hex_lower", "0x" + d[:4].hex()), ("hex_lower", d[:4].hex())]
                      + ([("fourcc", d[:4].decode())] if d[:4] in (b"OTTO", b"true") else [])))
    reg("font", ("outline_format", "flavor"), "label",
        lambda n, d: None if _sfnt(d) is None else ("cff" if d[:4] == b"OTTO" else "truetype"))

    def head(fmt, at):
        return lambda n, d: (lambda t: None if t is None else M._at(fmt, t, at)[0])(_sfnt_table(d, "head"))
    reg("font", ("units_per_em", "head_units_per_em"), "integer", head(">H", 18))
    reg("font", ("created", "head_created", "creation_time"), "mactime", head(">q", 20))
    reg("font", ("modified", "head_modified", "modification_time"), "mactime", head(">q", 28))
    reg("font", ("head_flags",), "number", head(">H", 16))
    reg("font", ("mac_style", "head_mac_style"), "number", head(">H", 44))
    reg("font", ("checksum_adjustment", "head_checksum_adjustment"), "number", head(">I", 8))

    def revision(n, d):
        t = _sfnt_table(d, "head")
        if t is None:
            return None
        raw = M._at(">i", t, 4)[0]
        v = raw / 65536
        return [("3dp", f"{v:.3f}"), ("2dp", f"{v:.2f}"), ("raw", repr(round(v, 6))), ("0x_hex_lower", f"0x{raw & 0xFFFFFFFF:08x}")]
    reg("font", ("revision", "font_revision", "head_font_revision"), "forms", revision)
    reg("font", ("glyph_count", "num_glyphs", "maxp_num_glyphs"), "integer",
        lambda n, d: (lambda t: None if t is None else M._at(">H", t, 4)[0])(_sfnt_table(d, "maxp")))
    reg("font", ("vendor_id", "os2_vendor_id", "os2_ach_vend_id", "ach_vend_id"), "text",
        lambda n, d: (lambda t: None if t is None else (t[58:62].decode("latin-1").rstrip(" \x00") or None))(_sfnt_table(d, "OS/2")))
    reg("font", ("weight_class", "os2_weight_class", "us_weight_class"), "integer",
        lambda n, d: (lambda t: None if t is None else M._at(">H", t, 4)[0])(_sfnt_table(d, "OS/2")))
    reg("font", ("embedding_flags", "os2_fs_type", "fs_type"), "number",
        lambda n, d: (lambda t: None if t is None else M._at(">H", t, 8)[0])(_sfnt_table(d, "OS/2")))

    namespace("woff", tokens=("woff", "woff2"), test=lambda d: d[:4] in (b"wOFF", b"wOF2"), alias=("woff2",))
    reg("woff", ("flavor", "header_flavor", "sfnt_flavor"), "forms",
        of(_woff, lambda w: [("0x_hex_lower", "0x" + w[0].hex()), ("hex_lower", w[0].hex())]
           + ([("fourcc", w[0].decode())] if w[0] in (b"OTTO", b"true") else [])))
    reg("woff", ("table_count", "num_tables", "header_num_tables"), "integer", of(_woff, lambda w: w[2]))
    reg("woff", ("total_sfnt_size_bytes", "header_total_sfnt_size", "total_sfnt_size", "uncompressed_size_bytes"), "integer",
        of(_woff, lambda w: w[3]))
    reg("woff", ("length_bytes", "header_length", "length"), "integer", of(_woff, lambda w: w[1]))
    reg("woff", ("version", "header_version", "font_version"), "dotted", of(_woff, lambda w: w[4]))
    reg("woff", ("signature", "header_signature", "format"), "text", of(_woff, lambda w: w[5]))
    # The Day 21 look-ahead (docs/retro/day-21-predictions-metadata.md): the sfnt version and the WOFF flavor
    # asked as a 32-bit hex number (ttf.sfnt_version_u32_hex was None: a 'forms' reader takes no width word).
    # '<name>_value' is the number twin guess() reads a typed name of a forms reader through, so
    # ttf.sfnt_version_u32_hex (or _hex) offers 0x00010000 first. No registered name may end in a width
    # (row 178's guard): the typed names are guess()'s.
    sfnt_number = lambda n, d: None if _sfnt(d) is None else M._at(">I", d, 0)[0]   # noqa: E731
    M.prop("font.sfnt_version_value", "font.header_sfnt_version_value", "font.scaler_type_value", fmt="integer",
           bits=32)(sfnt_number)
    M.prop("woff.flavor_value", "woff.header_flavor_value", "woff.sfnt_flavor_value", fmt="integer",
           bits=32)(of(_woff, lambda w: struct.unpack(">I", w[0])[0]))


# ------------------------------------------------------------------ ICC colour profiles (the Day 21 look-ahead)
#
# An ICC profile (ICC.1:2022, v2 and v4) as a file of its own (.icc, .icm, any name: the header's 'acsp'
# at offset 36 says what it is) or embedded in an image: a JPEG's APP2 ICC_PROFILE segments joined in
# their sequence order, a PNG's iCCP chunk (inflated), a WebP's ICCP chunk. Header fields by their
# offsets, the tag table, and the text tags (desc, cprt, dmnd, dmdd) of type desc, text or mluc.
# Everything is unsure: no day has judged a name of this namespace. A field the header leaves zero
# (profile ID, manufacturer, model, creator) is None, so the answer is the unsure `none`.

ICC_CLASSES = {"scnr": "Input Device Profile", "mntr": "Display Device Profile", "prtr": "Output Device Profile",
               "link": "DeviceLink Profile", "spac": "ColorSpace Conversion Profile", "abst": "Abstract Profile",
               "nmcl": "NamedColor Profile"}
ICC_INTENTS = {0: "perceptual", 1: "media_relative_colorimetric", 2: "saturation", 3: "icc_absolute_colorimetric"}
ICC_MAX = 1 << 24   # bytes of an embedded profile that are joined or inflated


def _icc_text(b: bytes, codec="latin-1"):
    """Bytes of a text field as text; Unknown where they do not decode (a wrong character is a wrong answer)."""
    try:
        return b.decode(codec)
    except UnicodeDecodeError:
        U("text that does not decode")


def _icc_alone(d: bytes):
    return len(d) >= 132 and d[36:40] == b"acsp"


def _icc_jpeg(d: bytes):
    if d[:2] != b"\xff\xd8":
        return None
    parts = {}
    for m, body in M._jpeg_walk(d)[0]:
        if m == 0xE2 and body[:12] == b"ICC_PROFILE\x00" and len(body) >= 14:
            seq, count = body[12], body[13]
            if seq in parts or not 1 <= seq <= count:
                U("the JPEG's ICC_PROFILE segments repeat or are out of range")
            parts[seq] = (count, body[14:])
    if not parts:
        return None
    counts = {c for c, _ in parts.values()}
    if len(counts) != 1 or sorted(parts) != list(range(1, counts.pop() + 1)):
        U("the JPEG's ICC_PROFILE segments are not one whole sequence")
    return b"".join(parts[i][1] for i in sorted(parts))


def _icc_png(d: bytes):
    if d[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    bodies = [b for t, b in M._png_chunks(d) if t == "iCCP"]
    if not bodies:
        return None
    if len(bodies) > 1:
        U("the PNG has two iCCP chunks")
    body = bodies[0]
    z = body.find(b"\x00")
    if not 0 < z < 80 or len(body) < z + 2 or body[z + 1] != 0:
        U("an iCCP chunk that is not read (name or compression method)")
    import zlib
    obj = zlib.decompressobj()
    try:
        out = obj.decompress(body[z + 2:], ICC_MAX + 1)
    except zlib.error:
        U("the iCCP profile does not inflate")
    if len(out) > ICC_MAX or not obj.eof:
        U("the iCCP profile is cut or too large")
    return out


def _icc_webp(d: bytes):
    if d[:4] != b"RIFF" or d[8:12] != b"WEBP":
        return None
    bodies = [b for k, b in (M._riff(d, b"WEBP") or []) if k == "ICCP"]
    if len(bodies) > 1:
        U("the WebP has two ICCP chunks")
    return bodies[0] if bodies else None


def _formats_pack():
    """readers_formats.py (loaded after this pack; read at call time). Unknown, named, when it is not loaded."""
    rf = getattr(M, "MORE_MODULES", {}).get("readers_formats.py")
    if rf is None:
        U("readers_formats.py is not loaded, so a TIFF or HEIF container is not walked")
    return rf


ICC_TIFF_TAG = 34675   # InterColorProfile (TIFF/EP, TIFF 6 technical note): the profile's bytes, type UNDEFINED


def _icc_tiff(d: bytes):
    """B-248: the ICC profile of a TIFF's first IFD (tag 34675), or None. The IFD chain is readers_formats'."""
    if d[:4] not in (b"II*\x00", b"MM\x00*", b"II+\x00", b"MM\x00+"):
        return None
    t = _formats_pack()._tiff(d)
    if t is None or not t["ifds"] or ICC_TIFF_TAG not in t["ifds"][0]:
        return None
    typ, count, raw = t["ifds"][0][ICC_TIFF_TAG]
    if typ not in (1, 7) or len(raw) != count:
        U("the TIFF's InterColorProfile tag is not a byte array")
    return raw


def _icc_heif(d: bytes):
    """B-248: the ICC profile of a HEIF/AVIF primary item: its colr property of colour type 'prof' or 'rICC' (an
    'nclx' colr carries no profile). Two profiles on the primary item are Unknown; none is None."""
    if d[4:8] != b"ftyp":
        return None
    rf = _formats_pack()
    h = rf._heif(d)
    if h is None:
        return None
    props = h["props"]
    if h["primary"] is not None and h["primary"] in h["assoc"]:
        bodies = [props[i - 1][1] for i in h["assoc"][h["primary"]] if 0 < i <= len(props) and props[i - 1][0] == "colr"]
    else:
        bodies = [body for k, body in props if k == "colr"]
    profiles = [b[4:] for b in bodies if b[:4] in (b"prof", b"rICC")]
    if len(profiles) > 1:
        U("the HEIF primary item has two ICC colour properties")
    return profiles[0] if profiles else None


@functools.lru_cache(maxsize=8)
def _icc_bytes(d: bytes):
    """The ICC profile the file is or embeds, or None."""
    if _icc_alone(d):
        return d
    for read in (_icc_jpeg, _icc_png, _icc_webp, _icc_tiff, _icc_heif):
        p = read(d)
        if p is not None:
            if not _icc_alone(p):
                U("the embedded ICC profile has no 'acsp' signature")
            return p
    return None


@functools.lru_cache(maxsize=8)
def _icc(d: bytes):
    """The header and tag table of the profile the file is or embeds, or None."""
    p = _icc_bytes(d)
    if p is None:
        return None
    size = M._at(">I", p, 0)[0]
    count = M._at(">I", p, 128)[0]
    if count > 1024 or 132 + 12 * count > len(p):
        U("the ICC tag table runs past the profile")
    tags = []
    for i in range(count):
        sig, off, ln = M._at(">4sII", p, 132 + 12 * i)
        tags.append((sig.decode("latin-1"), off, ln))
    return {"p": p, "size": size, "tags": tags}


def _icc_sig(at: int, zero_none=True):
    """A four-character signature of the header: trimmed first, then as stored (trailing spaces kept)."""
    def fn(n, d):
        h = _icc(d)
        if h is None:
            return None
        raw = h["p"][at:at + 4]
        if zero_none and raw == b"\x00\x00\x00\x00":
            return None
        if not re.fullmatch(rb"[\x21-\x7e][\x20-\x7e]{0,3}[\x00 ]*", raw):
            U("a signature field that is not text")
        stored = raw.decode("latin-1")
        forms = [("trimmed", stored.rstrip(" \x00"))]
        if stored != forms[0][1]:
            forms.append(("fourcc", stored.replace("\x00", " ")))
        return forms
    return fn


def _icc_text_tag(d: bytes, sig: str):
    """The text of one tag (type desc, text or mluc): an mluc's English record, else its only text."""
    h = _icc(d)
    if h is None:
        return None
    hits = {(off, ln) for s, off, ln in h["tags"] if s == sig}
    if not hits:
        return None
    if len(hits) > 1:
        U(f"two {sig} tags")
    off, ln = hits.pop()
    p = h["p"]
    if off + ln > len(p) or ln < 12:
        U(f"the {sig} tag runs past the profile")
    body = p[off:off + ln]
    kind = body[:4]
    if kind == b"desc":
        count = M._at(">I", body, 8)[0]
        if count == 0 or 12 + count > len(body):
            U(f"the {sig} tag's ASCII text is cut")
        return _icc_text(body[12:12 + count].split(b"\x00", 1)[0]) or None
    if kind == b"text":
        return _icc_text(body[8:].split(b"\x00", 1)[0], "latin-1") or None
    if kind == b"mluc":
        n, rec = M._at(">II", body, 8)
        if n == 0 or rec != 12 or 16 + 12 * n > len(body):
            U(f"the {sig} tag's records are not read")
        recs = []
        for i in range(n):
            lang, country, rl, ro = M._at(">2s2sII", body, 16 + 12 * i)
            if ro + rl > len(body) or rl % 2:
                U(f"a {sig} record runs past its tag")
            recs.append((lang + country, body[ro:ro + rl].decode("utf-16-be", "replace").rstrip("\x00")))
        english = {t for lc, t in recs if lc == b"enUS"} or {t for lc, t in recs if lc[:2] == b"en"}
        if english:
            if len(english) > 1:
                U(f"the {sig} tag's English records disagree")
            return english.pop() or None
        if len({t for _, t in recs}) > 1:
            U(f"the {sig} tag has records in several languages and none in English")
        return recs[0][1] or None
    U(f"the {sig} tag's type {kind!r} is not a text type")


@section
def _reg_icc():
    namespace("icc", tokens=("icc", "icm"), test=_icc_alone,
              alias=("icc_profile", "iccprofile", "icm", "colorsync", "color_profile", "colour_profile"))
    reg("icc", ("profile_size", "profile_size_bytes", "header_profile_size", "declared_size", "declared_size_bytes"),
        "integer", of(_icc, lambda h: h["size"]))
    reg("icc", ("preferred_cmm", "preferred_cmm_type", "cmm_type", "profile_cmm_type", "cmm"), "forms", _icc_sig(4))

    def version(n, d):
        h = _icc(d)
        if h is None:
            return None
        raw = M._at(">I", h["p"], 8)[0]
        major, minor, bugfix = raw >> 24, (raw >> 20) & 0xF, (raw >> 16) & 0xF
        return [("dotted", f"{major}.{minor}.{bugfix}"), ("short", f"{major}.{minor}"),
                ("0x_hex_lower", f"0x{raw:08x}"), ("integer", str(raw >> 16))]
    reg("icc", ("profile_version", "version", "header_version", "spec_version"), "forms", version)

    def device_class(n, d):
        forms = _icc_sig(12, zero_none=False)(n, d)
        if forms is None:
            return None
        name = ICC_CLASSES.get(forms[0][1])
        return forms + ([("name", name)] if name else [])
    reg("icc", ("device_class", "profile_class", "profile_device_class", "class", "header_device_class"), "forms",
        device_class)
    reg("icc", ("color_space", "colour_space", "data_color_space", "data_colour_space", "color_space_data",
                "colorspace"), "forms", _icc_sig(16, zero_none=False))
    reg("icc", ("pcs", "profile_connection_space", "connection_space", "pcs_color_space"), "forms",
        _icc_sig(20, zero_none=False))

    def created(n, d):
        h = _icc(d)
        if h is None:
            return None
        y, mo, dd, hh, mi, ss = M._at(">6H", h["p"], 24)
        if (y, mo, dd) == (0, 0, 0):
            return None
        if not (1 <= mo <= 12 and 1 <= dd <= 31 and hh < 24 and mi < 60 and ss < 61):
            U("a creation date that is no date")
        return (y, mo, dd, hh, mi, ss, True)
    reg("icc", ("creation_datetime", "creation_date", "creation_date_time", "date_time", "profile_date_time",
                "created", "creation_time", "header_date_time"), "timestamp", created)
    reg("icc", ("signature", "file_signature", "profile_file_signature", "magic"), "forms", _icc_sig(36, zero_none=False))
    reg("icc", ("primary_platform", "platform", "platform_signature"), "forms", _icc_sig(40))
    reg("icc", ("flags", "profile_flags", "cmm_flags"), "number", of(_icc, lambda h: M._at(">I", h["p"], 44)[0]))
    reg("icc", ("device_manufacturer", "manufacturer"), "forms", _icc_sig(48))
    reg("icc", ("device_model", "model"), "forms", _icc_sig(52))
    reg("icc", ("device_attributes", "attributes"), "number", of(_icc, lambda h: M._at(">Q", h["p"], 56)[0]))
    reg("icc", ("rendering_intent", "header_rendering_intent", "intent"), "integer",
        of(_icc, lambda h: M._at(">I", h["p"], 64)[0] & 0xFFFF))
    reg("icc", ("rendering_intent_name",), "label",
        of(_icc, lambda h: ICC_INTENTS.get(M._at(">I", h["p"], 64)[0] & 0xFFFF) or U("a rendering intent outside 0..3")))
    reg("icc", ("creator", "profile_creator", "creator_signature"), "forms", _icc_sig(80))
    reg("icc", ("profile_id", "profile_id_md5", "profile_md5", "id", "profile_id_hex"), "hex",
        of(_icc, lambda h: h["p"][84:100].hex() if any(h["p"][84:100]) else None))
    reg("icc", ("tag_count", "tag_table_count", "number_of_tags"), "integer", of(_icc, lambda h: len(h["tags"])))
    reg("icc", ("tag_signatures", "tags", "tag_names", "tag_list", "tag_table_signatures"), "list",
        of(_icc, lambda h: [s for s, _, _ in h["tags"]] or None))
    for sig, names in (("desc", ("profile_description", "description", "desc", "description_tag")),
                       ("cprt", ("copyright", "profile_copyright", "cprt")),
                       ("dmnd", ("device_manufacturer_description", "device_mfg_desc", "dmnd")),
                       ("dmdd", ("device_model_description", "device_model_desc", "dmdd"))):
        reg("icc", names, "text", lambda n, d, sig=sig: _icc_text_tag(d, sig))
    reg("icc", ("embedded_size_bytes", "embedded_profile_size_bytes", "byte_length"), "integer",
        lambda n, d: None if _icc_bytes(d) is None else len(_icc_bytes(d)))
    # The same facts of a profile embedded in an image, under the image's own namespace (an existing name is kept).
    for ns in ("jpeg", "png", "webp", "image", "exif"):
        for word, target in (("icc_profile_description", "icc.profile_description"),
                             ("icc_description", "icc.profile_description"),
                             ("icc_profile_version", "icc.profile_version"),
                             ("icc_color_space", "icc.color_space"),
                             ("icc_profile_size_bytes", "icc.embedded_size_bytes"),
                             ("icc_device_class", "icc.device_class"),
                             ("icc_copyright", "icc.copyright")):
            if M.canon(f"{ns}.{word}") not in M.REG:
                p = M.REG[M.canon(target)]
                M.prop(f"{ns}.{word}", fmt=p.fmt)(p.fn)

    def iccp_name(n, d):
        if d[:8] != b"\x89PNG\r\n\x1a\n":
            return None
        bodies = [b for t, b in M._png_chunks(d) if t == "iCCP"]
        if not bodies:
            return None
        if len(bodies) > 1:
            U("the PNG has two iCCP chunks")
        z = bodies[0].find(b"\x00")
        if not 0 < z < 80:
            U("an iCCP chunk whose name is not read")
        return _icc_text(bodies[0][:z])
    for nm in ("png.iccp_profile_name", "png.icc_profile_name", "png.iccp_name"):
        if M.canon(nm) not in M.REG:
            M.prop(nm, fmt="text")(iccp_name)
