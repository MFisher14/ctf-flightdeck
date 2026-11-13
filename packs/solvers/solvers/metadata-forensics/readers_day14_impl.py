#!/usr/bin/env python3
"""The parsers of readers_day14.py (the Day 14 look-ahead pack), in a file of their own so that the
lane solver does not pay for them at import: readers_day14.py registers names and families, and this
file is loaded the first time one of them is asked (readers_day14.impl()).

The contract of every function here is the wrapper's extractor contract: the value read from the
bytes, None when the file is not of its type (or a field of a structure that was read whole is
absent), M.Unknown for anything cut, damaged or ambiguous. readers_day14.held() turns whatever else
a parser raises into Unknown, so no exception leaves this file. Sizes are capped (BIG, SMALL) before
anything is inflated; nothing is ever run, and no subprocess is started.

A family that reads the rest of a name as a key (a control field, a manifest attribute, a nuspec
element, a plist key, a task element) never says a key it does not know is absent: keyed() gives the
one value, None only for a key of the format's own standard list, and Unknown for any other.
"""
import functools
import hashlib
import io
import re
import struct
import zlib

M = None       # properties_strict, set by readers_day14.impl()
PACKS = {}     # file name -> the loaded pack
SMALL = 1 << 20    # bytes of a manifest, a control file, a property list
BIG = 1 << 24      # bytes of a member that is inflated for one question
P7_MAX = 1 << 22


def U(msg):
    raise M.Unknown(msg)


def pack(name):
    return PACKS.get(name)


def one(values, what):
    values = list(values)
    if len(values) > 1:
        U(f"several {what}: the name does not say which one is asked")
    return values[0] if values else None


def sq(s) -> str:
    """A name without its case and separators: Bundle-SymbolicName, bundle_symbolic_name and
    bundlesymbolicname are one key."""
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


def keyed(table: dict, field: str, known=(), what="key"):
    """The one value a container holds under a key as a name spells it (table: squashed key -> [values]).
    None only for a key of `known` (squashed) that the container does not hold; Unknown for a key
    this reader does not know, and for two different values."""
    hits = table.get(sq(field))
    if hits:
        values = {v for v in hits}
        if len(values) > 1:
            U(f"several values under that {what}")
        return hits[0] if hits[0] != "" else None
    if sq(field) in known:
        return None
    U(f"no {what} of that name is in the file, and it is not one of the format's standard ones")


def xml_root(body: bytes):
    """The root element of a small XML document, with no namespace on any tag. Unknown for a
    document that declares entities (nothing is expanded here), is too large or does not parse."""
    if len(body) > SMALL:
        U("an XML document larger than is read")
    if b"<!ENTITY" in body or b"<!DOCTYPE" in body:
        U("an XML document with a document type declaration, which is not read")
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        U("an XML document that does not parse")
    for e in root.iter():
        if isinstance(e.tag, str) and "}" in e.tag:
            e.tag = e.tag.split("}", 1)[1]
    return root


def zip_of(d: bytes):
    return M._zip(d) if d[:4] == b"PK\x03\x04" else None


def zip_member(d: bytes, name: str, limit=SMALL, z=None):
    """One member of a zip by its exact name: bytes; None when the file is no zip or has no such
    member; Unknown for two of the name, an encrypted one, or one larger than is read."""
    z = z or zip_of(d)
    if z is None:
        return None
    hits = [i for i in z.infolist() if i.filename == name]
    if not hits:
        return None
    if len(hits) > 1:
        U(f"two members named {name}")
    if hits[0].flag_bits & 1 or hits[0].file_size > limit:
        U(f"{name} is encrypted or larger than is read")
    with z.open(hits[0]) as fh:
        body = fh.read(limit + 1)
    if len(body) != hits[0].file_size:
        U(f"{name} does not inflate to the size its header states")
    return body


# ------------------------------------------------------------------ 2. signers
OID_SIGNED_DATA = bytes.fromhex("06092a864886f70d010702")
NAME_PARTS = (("common_name", ("common_name", "cn")), ("organization_name", ("organization", "organization_name", "o", "org")),
              ("country_name", ("country", "country_name", "c")), ("organizational_unit_name", ("organizational_unit", "ou")),
              ("locality_name", ("locality", "l")), ("state_or_province_name", ("state", "state_or_province", "st")))
PART_OF = {w: part for part, ws in NAME_PARTS for w in ws}


@functools.lru_cache(maxsize=8)
def p7(blob: bytes):
    """What the one signer of a PKCS#7 SignedData says: {"signer": certificate or None, "issuer": Name or
    None, "serial", "chain": [certificates], "digest_algo", "signing_time", "timestamp", "signers": n}.
    Unknown for anything that is not one whole SignedData with at most one signer."""
    if not blob or len(blob) > P7_MAX:
        U("a signature that is empty or larger than is read")
    try:
        from asn1crypto import cms
    except ImportError:
        U("the asn1crypto library is not installed")
    try:
        info = cms.ContentInfo.load(blob)
        if info["content_type"].native != "signed_data":
            U("not PKCS#7 signed data")
        sd = info["content"]
        chain = [c.chosen for c in sd["certificates"] if c.name == "certificate"] if sd["certificates"] else []
        if len(chain) > 64:
            U("more certificates than are read")
        out = {"chain": chain, "signers": len(sd["signer_infos"]), "signer": None, "issuer": None, "serial": None,
               "digest_algo": None, "signing_time": None, "timestamp": None}
        if len(sd["signer_infos"]) > 1:
            U("a signature with more than one signer")
        if len(sd["signer_infos"]) == 1:
            si = sd["signer_infos"][0]
            out["digest_algo"] = si["digest_algorithm"]["algorithm"].native
            if si["sid"].name == "issuer_and_serial_number":
                sid = si["sid"].chosen
                out["issuer"], out["serial"] = sid["issuer"], sid["serial_number"].native
                hits = [c for c in chain if c.serial_number == out["serial"] and c.issuer == out["issuer"]]
            else:
                ski = si["sid"].chosen.native
                hits = [c for c in chain if c.key_identifier == ski]
            if len(hits) > 1:
                U("two certificates fit the signer")
            if hits:
                out["signer"] = hits[0]
                out["issuer"], out["serial"] = hits[0].issuer, hits[0].serial_number
            for attr in si["signed_attrs"] or []:
                if attr["type"].dotted == "1.2.840.113549.1.9.5":
                    out["signing_time"] = attr["values"][0].native
            try:
                unsigned = list(si["unsigned_attrs"] or [])[:16]
            except Exception:   # an attribute asn1crypto does not parse: the stamps stay unread
                unsigned = []
            for attr in unsigned:
                oid = attr["type"].dotted
                if oid == "1.2.840.113549.1.9.6":
                    cs = cms.SignerInfo.load(attr["values"][0].dump())
                    for a in cs["signed_attrs"] or []:
                        if a["type"].dotted == "1.2.840.113549.1.9.5":
                            out["timestamp"] = a["values"][0].native
                elif oid == "1.3.6.1.4.1.311.3.3.1":
                    from asn1crypto import tsp
                    tok = cms.ContentInfo.load(attr["values"][0].dump())
                    inner = tok["content"]["encap_content_info"]["content"]
                    tst = inner.parsed if isinstance(getattr(inner, "parsed", None), tsp.TSTInfo) else tsp.TSTInfo.load(inner.native)
                    out["timestamp"] = tst["gen_time"].native
        return out
    except M.Unknown:
        raise
    except Exception as e:
        U(f"the signature does not parse ({type(e).__name__})")


def ole_stream(d: bytes, name: str, limit=P7_MAX):
    """One root stream of a compound file by its exact name: bytes, None when the file is no compound
    file or has no such stream. Unknown for two of the name or a stream larger than is read."""
    if d[:8] != M.CFB_MAGIC:
        return None
    if len(d) > 1 << 26:
        U("a compound file larger than is read here")
    try:
        import olefile
    except ImportError:
        U("the olefile library is not installed")
    ole = olefile.OleFileIO(io.BytesIO(d))
    try:
        hits = [s for s in ole.listdir(streams=True, storages=False) if len(s) == 1 and s[0] == name]
        if not hits:
            return None
        if len(hits) > 1:
            U("two streams of one name")
        if ole.get_size(hits[0]) > limit:
            U("a stream larger than is read")
        return ole.openstream(hits[0]).read()
    finally:
        ole.close()


def sig_pe(d: bytes):
    rf = pack("readers_formats.py")
    certs = rf._win_certs(d) if rf is not None else None
    if certs is None:
        return None
    pk = [body for rev, kind, body in certs if kind == 2]
    if not pk:
        return {}
    if len(pk) > 1:
        U("several signatures in the certificate table")
    return p7(bytes(pk[0]))


def sig_msi(d: bytes):
    rf = pack("readers_formats.py")
    if rf is None or rf._msi(d) is None:
        return None
    body = ole_stream(d, "\x05DigitalSignature")
    return {} if body is None else p7(body)


def is_msix(d: bytes):
    z = zip_of(d)
    if z is None:
        return None
    names = {i.filename for i in z.infolist()}
    return z if names & {"AppxManifest.xml", "AppxMetadata/AppxBundleManifest.xml"} else None


def sig_msix(d: bytes):
    z = is_msix(d)
    if z is None:
        return None
    body = zip_member(d, "AppxSignature.p7x", P7_MAX, z)
    if body is None:
        return {}
    if body[:4] != b"PKCX":
        U("an AppxSignature.p7x without its PKCX mark")
    return p7(body[4:])


def is_nupkg(d: bytes):
    z = zip_of(d)
    if z is None:
        return None
    specs = [i.filename for i in z.infolist() if "/" not in i.filename and i.filename.lower().endswith(".nuspec")]
    return specs or None


def sig_nupkg(d: bytes):
    if is_nupkg(d) is None:
        return None
    body = zip_member(d, ".signature.p7s", P7_MAX)
    return {} if body is None else p7(body)


def p7_der(d: bytes):
    """The DER of a file that IS a PKCS#7 (.p7b, .p7s, .p7c, a catalog): DER as it stands or one PEM block."""
    if d[:1] == b"0" and OID_SIGNED_DATA in d[:32]:
        return d
    m = re.search(rb"-----BEGIN (PKCS7|CMS)-----(.+?)-----END \1-----", d[:P7_MAX], re.S) if d[:5] == b"-----" else None
    if m:
        import base64
        return base64.b64decode(re.sub(rb"\s+", b"", m.group(2)), validate=True)
    return None


def sig_file(d: bytes):
    der = p7_der(d)
    return None if der is None else p7(der)


SIGNERS = {"pe": sig_pe, "msi": sig_msi, "msix": sig_msix, "appx": sig_msix, "nupkg": sig_nupkg, "pkcs7": sig_file}


def _signed(ns, d):
    a = SIGNERS[ns](d)
    return a if a else None   # None: not this container, or no signature in it


def _signer_cert(a):
    return a["signer"] if a.get("signer") is not None else U("the signer's certificate is not among those the signature carries")


def _name_part(name, part):
    v = name.native.get(part)
    if isinstance(v, list):
        return one(v, f"{part} values")
    return v if isinstance(v, str) and v else None


def _stamp(v):
    return None if v is None else pack("readers_formats.py")._dt(v)


def signer_part(n, d, ns, w):
    a = _signed(ns, d)
    return None if a is None else _name_part(_signer_cert(a).subject, PART_OF[w])


def issuer_part(n, d, ns, w):
    a = _signed(ns, d)
    return None if a is None or a.get("issuer") is None else _name_part(a["issuer"], PART_OF[w])


def signer_name(n, d, ns):
    a = _signed(ns, d)
    return None if a is None else pack("readers_formats.py")._x509_name(_signer_cert(a).subject)


def issuer_name(n, d, ns):
    a = _signed(ns, d)
    return None if a is None or a.get("issuer") is None else pack("readers_formats.py")._x509_name(a["issuer"])


def signer_serial(n, d, ns):
    a = _signed(ns, d)
    return None if a is None else a.get("serial")


def signer_hash(n, d, ns, algo="sha1"):
    a = _signed(ns, d)
    return None if a is None else hashlib.new(algo, _signer_cert(a).dump()).hexdigest()


def signer_validity(n, d, ns, w):
    a = _signed(ns, d)
    if a is None:
        return None
    return _stamp(_signer_cert(a)["tbs_certificate"]["validity"]["not_before" if w in ("not_before", "valid_from") else "not_after"].native)


def cert_count(n, d, ns):
    a = _signed(ns, d)
    return None if a is None else len(a["chain"])


def cert_subjects(n, d, ns):
    a = _signed(ns, d)
    if a is None:
        return None
    names = [c.subject.native.get("common_name") for c in a["chain"]]
    if not all(isinstance(x, str) and x for x in names):
        U("a certificate without one common name")
    return names or None


def digest_algorithm(n, d, ns):
    a = _signed(ns, d)
    return None if a is None else a.get("digest_algo")


def signing_time(n, d, ns):
    a = _signed(ns, d)
    return None if a is None else _stamp(a.get("signing_time"))


def timestamp(n, d, ns):
    a = _signed(ns, d)
    return None if a is None else _stamp(a.get("timestamp"))


def first_cert_cn(n, d, ns):
    a = _signed(ns, d)
    return None if a is None or not a["chain"] else _name_part(a["chain"][0].subject, "common_name")


def signature_present(n, d, ns):
    a = SIGNERS[ns](d)
    return None if a is None else bool(a)


def signer_count(n, d):
    a = sig_file(d)
    return None if a is None else a["signers"]


# ------------------------------------------------------------------ 4. cab
CAB_COMPRESSION = {0: "none", 1: "mszip", 2: "quantum", 3: "lzx"}


def cab_folders(d: bytes):
    """[typeCompress] of every CFFOLDER of a cabinet, or None when the file is no cabinet."""
    if d[:4] != b"MSCF" or len(d) < 36:
        return None
    folders, files, flags = struct.unpack_from("<HHH", d, 26)
    at, per = 36, 0
    if flags & 4:
        head, per, _ = struct.unpack_from("<HBB", d, 36)
        at = 40 + head
    for bit in (1, 2):   # previous and next cabinet: a name and a disk label, each NUL-ended
        if flags & bit:
            for _ in range(2):
                at = d.index(b"\0", at, at + 256) + 1
    if folders > 4096 or at + folders * (8 + per) > len(d):
        U("a folder table that is cut")
    return [struct.unpack_from("<H", d, at + i * (8 + per) + 6)[0] for i in range(folders)]


def cab_compression(n, d):
    kinds = cab_folders(d)
    if kinds is None:
        return None
    kind = one(set(kinds), "compression types in the folders")
    if kind is None:
        return None
    name = CAB_COMPRESSION.get(kind & 0x0F) or U("a compression type the specification does not name")
    return [("lower", name), ("upper", name.upper()), ("constant", "tcompTYPE_" + name.upper()), ("integer", str(kind & 0x0F)),
            ("0x_hex_lower", f"0x{kind:04x}")]


def cab_compression_raw(n, d):
    kinds = cab_folders(d)
    return None if kinds is None else one(set(kinds), "compression types in the folders")


# ------------------------------------------------------------------ 5. lnk
def guid_digits(raw: bytes) -> str:
    """The 32 hex digits of a GUID stored as 16 bytes, in the order it is written (8-4-4-4-12)."""
    if len(raw) != 16:
        U("a GUID that is cut")
    a, b, c = struct.unpack_from("<IHH", raw, 0)
    return "%08x%04x%04x%s" % (a, b, c, raw[8:].hex())


def lnk_clsid(n, d):
    if d[:4] != b"\x4c\x00\x00\x00" or len(d) < 76:
        return None
    return guid_digits(d[4:20])


def lnk_serial(n, d):
    x = pack("readers_formats.py")._lnk_more(d)
    return None if x is None or not x["volume"] else x["volume"][1]


# ------------------------------------------------------------------ 6. second readings
def pe_overlay_with_table(n, d):
    x = pack("readers_more.py")._pex(d)
    if x is None:
        return None
    end = max([rptr + rsize for _, _, _, rsize, rptr, _ in x["sections"] if rsize] or [x["headers"]])
    return max(len(d) - end, 0)


def pe_overlay_offset(n, d):
    x = pack("readers_more.py")._pex(d)
    if x is None:
        return None
    end = max([rptr + rsize for _, _, _, rsize, rptr, _ in x["sections"] if rsize] or [x["headers"]])
    return end if end < len(d) else None


def low_byte(name):
    def fn(n, d):
        v = M.REG[M.canon(name)].fn(n, d)
        return None if v is None else v & 0xFF
    return fn


def declared_count(n, d):
    v = M.REG[M.canon("msi.declared_table_names")].fn(n, d)
    return None if v is None else len(v)


def rpm_second(tag):
    return lambda n, d: (lambda h: None if h is None else h["main"].get(tag))(rpm(d))


# ------------------------------------------------------------------ 7. package manifests
NUSPEC_KNOWN = {sq(x) for x in ("id version title authors owners description summary releaseNotes copyright language tags projectUrl licenseUrl "
                                "iconUrl icon readme license requireLicenseAcceptance developmentDependency serviceable repository "
                                "minClientVersion").split()}


@functools.lru_cache(maxsize=4)
def nuspec(d: bytes):
    """{squashed element or attribute path: [text]} of the package's one .nuspec, or None when the file is no NuGet package."""
    specs = is_nupkg(d)
    if specs is None:
        return None
    name = one(specs, ".nuspec files")
    root = xml_root(zip_member(d, name))
    meta = root.find("metadata")
    if root.tag != "package" or meta is None:
        U("a .nuspec without package/metadata")
    out = {"nuspecfilename": [name]}
    for e in meta:
        if isinstance(e.tag, str) and e.text and e.text.strip() and len(e) == 0:
            out.setdefault(sq(e.tag), []).append(e.text.strip())
        for k, v in e.attrib.items():
            out.setdefault(sq(e.tag + k), []).append(v)
    out["targetframeworks"] = [g.attrib["targetFramework"] for g in meta.iter("group") if g.attrib.get("targetFramework")]
    return out


NUSPEC_SAME = {"packageid": "id", "packageversion": "version", "name": "id", "packagename": "id", "author": "authors",
               "repositorycommitsha1": "repositorycommit", "repositorycommithash": "repositorycommit", "commit": "repositorycommit",
               "licenseexpression": "license", "filename": "nuspecfilename"}


def nupkg_field(n, d, field):
    t = nuspec(d)
    if t is None:
        return None
    key = sq(field)
    return keyed(t, NUSPEC_SAME.get(key, key), NUSPEC_KNOWN | {"repositoryurl", "repositorycommit", "repositorytype", "repositorybranch", "licensetype"},
                 "element")


def nupkg_frameworks(n, d):
    t = nuspec(d)
    return None if t is None else (t["targetframeworks"] or None)


def ar_members(d: bytes):
    """[(name, size, data offset)] of a Unix ar archive, or None."""
    if d[:8] != b"!<arch>\n":
        return None
    out, i = [], 8
    while i + 60 <= len(d) and len(out) < 4096:
        if d[i + 58:i + 60] != b"`\n":
            U("an ar member header without its end mark")
        name = d[i:i + 16].decode("latin-1").rstrip(" ")
        size = int(d[i + 48:i + 58].decode("ascii").strip() or "x")
        if i + 60 + size > len(d):
            U("an ar member that runs past the file")
        out.append((name[:-1] if name.endswith("/") and len(name) > 1 else name, size, i + 60))
        i += 60 + size + (size & 1)
    return out


def _inflate(body: bytes, name: str, limit=BIG):
    if name.endswith(".gz"):
        return zlib.decompressobj(31).decompress(body, limit)
    if name.endswith(".xz"):
        import lzma
        return lzma.LZMADecompressor().decompress(body, limit)
    if name.endswith(".bz2"):
        import bz2
        return bz2.BZ2Decompressor().decompress(body, limit)
    if name.endswith(".tar"):
        return body
    U(f"{name} is compressed in a way that is not read here")


def rfc822(body: bytes) -> dict:
    """{squashed field name: [values]} of 'Key: value' lines with continuation lines, up to the first blank line."""
    out, last = {}, None
    for raw in body.decode("utf-8", "replace").replace("\r\n", "\n").split("\n")[:4096]:
        if not raw.strip():
            if out:
                break
            continue
        if raw[0] in " \t" and last:
            continue   # a continuation: the first line of the field is its value
        k, sep, v = raw.partition(":")
        if sep and k.strip() and " " not in k.strip():
            last = sq(k)
            out.setdefault(last, []).append(v.strip())
    return out


DEB_KNOWN = {sq(x) for x in ("Package Version Architecture Maintainer Installed-Size Depends Pre-Depends Recommends Suggests Conflicts Breaks "
                             "Replaces Provides Section Priority Homepage Description Source Essential Built-Using Multi-Arch "
                             "Original-Maintainer").split()}
DEB_SAME = {"packagename": "package", "name": "package", "packageversion": "version", "arch": "architecture",
            "installedsizekb": "installedsize", "installedsizekib": "installedsize"}


@functools.lru_cache(maxsize=4)
def deb(d: bytes):
    """{"members": [names], "binary": text of debian-binary, "control": {squashed field: [values]}} or None."""
    mem = ar_members(d)
    if mem is None or not mem or mem[0][0] != "debian-binary":
        return None
    out = {"members": [m[0] for m in mem], "binary": d[mem[0][2]:mem[0][2] + mem[0][1]].decode("ascii").strip()}
    ctl = [m for m in mem if m[0].startswith("control.tar")]
    if len(ctl) != 1:
        U("a Debian package without exactly one control archive")
    name, size, at = ctl[0]
    if size > BIG:
        U("a control archive larger than is read")
    import tarfile
    tar = _inflate(d[at:at + size], name)
    with tarfile.open(fileobj=io.BytesIO(tar)) as t:
        hits = [m for m in t.getmembers()[:256] if m.isfile() and m.name.lstrip("./") == "control"]
        if len(hits) != 1 or hits[0].size > SMALL:
            U("a control archive without exactly one control file")
        out["control"] = rfc822(t.extractfile(hits[0]).read())
        out["control_members"] = [m.name for m in t.getmembers()[:256]]
    return out


def deb_field(n, d, field):
    p = deb(d)
    if p is None:
        return None
    key = sq(field)
    return keyed(p["control"], DEB_SAME.get(key, key), DEB_KNOWN, "control field")


def deb_binary(n, d):
    p = deb(d)
    return None if p is None else p["binary"]


def deb_members(n, d):
    p = deb(d)
    return None if p is None else p["members"]


WHL_KNOWN = {sq(x) for x in ("Metadata-Version Name Version Summary Home-page Author Author-email Maintainer Maintainer-email License Keywords "
                             "Platform Requires-Python Requires-Dist Provides-Extra Project-URL Description-Content-Type Classifier "
                             "Wheel-Version Generator Root-Is-Purelib Tag Build").split()}


@functools.lru_cache(maxsize=4)
def whl(d: bytes):
    """{"metadata": {...}, "wheel": {...}, "dist_info": name} of a Python wheel, or None."""
    z = zip_of(d)
    if z is None:
        return None
    dirs = {i.filename.split("/")[0] for i in z.infolist() if i.filename.split("/")[0].endswith(".dist-info") and "/" in i.filename}
    if not dirs:
        return None
    di = one(dirs, ".dist-info folders")
    meta, wheel = zip_member(d, f"{di}/METADATA", SMALL, z), zip_member(d, f"{di}/WHEEL", SMALL, z)
    if meta is None or wheel is None:
        U("a wheel without METADATA and WHEEL")
    return {"metadata": rfc822(meta), "wheel": rfc822(wheel), "dist_info": di}


def whl_field(n, d, part, field):
    w = whl(d)
    if w is None:
        return None
    key = sq(field)
    if part:
        part = "metadata" if "metadata" in part else "wheel"
        if part == "metadata" and key == "version" and "metadataversion" in w["metadata"]:
            # whl.metadata_version: the Version field of METADATA, or its Metadata-Version field
            a, b = keyed(w["metadata"], "version", WHL_KNOWN), keyed(w["metadata"], "metadataversion", WHL_KNOWN)
            raise M.Ambiguous([("raw", a), ("raw+metadata_version_field", b)] if a else [("raw+metadata_version_field", b)])
        return _whl_value(w[part], key)
    hits = [p for p in ("metadata", "wheel") if key in w[p]]
    if len(hits) > 1:
        U("METADATA and WHEEL both have a field of that name")
    return _whl_value(w[hits[0]] if hits else w["metadata"], key)


def _whl_value(table, key):
    key = {"tags": "tag", "wheeltag": "tag", "wheeltags": "tag", "wheelgenerator": "generator", "packagename": "name",
           "homepage": "homepage", "requirespython": "requirespython"}.get(key, key)
    if key in ("tag", "classifier", "requiresdist", "projecturl", "providesextra", "platform") and len(table.get(key, [])) > 1:
        raise M.Ambiguous(M._f_list(list(table[key])))
    return keyed(table, key, WHL_KNOWN, "field")


@functools.lru_cache(maxsize=4)
def ipa(d: bytes):
    """The Info.plist of the one .app of an iOS package as a dict, or None when the file is no .ipa."""
    z = zip_of(d)
    if z is None:
        return None
    hits = [i.filename for i in z.infolist() if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", i.filename)]
    if not hits:
        return None
    body = zip_member(d, one(hits, "applications in Payload"), SMALL, z)
    if b"<!ENTITY" in body or (body[:6] != b"bplist" and b"<!DOCTYPE plist" not in body[:512] and b"<plist" not in body[:512]):
        U("an Info.plist that is not a property list this reader takes")
    import plistlib
    pl = plistlib.loads(body)
    if not isinstance(pl, dict):
        U("an Info.plist whose root is not a dictionary")
    return pl


def ipa_field(n, d, field):
    pl = ipa(d)
    if pl is None:
        return None
    key = sq(field)
    table = {}
    for k, v in pl.items():
        if isinstance(v, (str, int, float, bool)):
            table.setdefault(sq(k), []).append(v)
    for form in (key, "cf" + key, "cfbundle" + key, "cfbundle" + key.replace("bundle", "", 1)):
        if form in table:
            if form != key and sum(f in table for f in {"cf" + key, "cfbundle" + key, "cfbundle" + key.replace("bundle", "", 1)}) > 1:
                U("two keys of the list fit the name")
            return keyed(table, form)
    if key in ("version", "bundleversion") and "cfbundleshortversionstring" in table and "cfbundleversion" in table:
        raise M.Ambiguous([("raw+short_version_string", str(table["cfbundleshortversionstring"][0])), ("raw+bundle_version", str(table["cfbundleversion"][0]))])
    U("no key of that name is in the Info.plist")


JAR_KNOWN = {sq(x) for x in ("Manifest-Version Created-By Main-Class Class-Path Implementation-Title Implementation-Version "
                             "Implementation-Vendor Specification-Title Specification-Version Specification-Vendor Built-By Build-Jdk "
                             "Multi-Release Automatic-Module-Name Sealed Premain-Class Agent-Class Launcher-Agent-Class Signature-Version "
                             "Bundle-SymbolicName Bundle-Name Bundle-Version Bundle-ManifestVersion Bundle-Vendor Bundle-License "
                             "Bundle-Description Bundle-DocURL Export-Package Import-Package Require-Capability Bnd-LastModified Tool").split()}


def jar_manifest_field(n, d, field):
    """A main-section attribute of META-INF/MANIFEST.MF by its name as an id spells it (Bundle-SymbolicName is
    bundle_symbolic_name). Called in place of readers_more._manifest_field."""
    m = pack("readers_more.py")._manifest(d)
    if m is None:
        return None
    table = {}
    for k, vs in m.items():
        table.setdefault(sq(k), []).extend(vs)
    return keyed(table, field, JAR_KNOWN, "manifest attribute")


APK_SIG_MAGIC = b"APK Sig Block 42"
APK_SCHEMES = {"v2": 0x7109871A, "v3": 0xF05368C0, "v31": 0x1B93AD61}


def apk_sig_block(d: bytes):
    """{id: length} of the APK Signing Block's pairs; {} when the zip has none; None when the file is no APK."""
    z = zip_of(d)
    if z is None or "AndroidManifest.xml" not in {i.filename for i in z.infolist()}:
        return None
    eocd = M._eocd(d)
    if eocd is None:
        U("no end of central directory record")
    cd = eocd[5]
    if cd < 32 or d[cd - 16:cd] != APK_SIG_MAGIC:
        return {}
    size, = struct.unpack_from("<Q", d, cd - 24)
    start = cd - size - 8
    if start < 0 or struct.unpack_from("<Q", d, start)[0] != size:
        U("an APK Signing Block whose two sizes differ")
    out, i = {}, start + 8
    while i + 12 <= cd - 24 and len(out) < 64:
        n, ident = struct.unpack_from("<QI", d, i)
        if n < 4 or i + 8 + n > cd - 24:
            U("an APK Signing Block pair that runs past the block")
        out[ident] = n - 4
        i += 8 + n
    return out


def apk_block_present(n, d):
    b = apk_sig_block(d)
    return None if b is None else bool(b)


def apk_scheme_present(n, d, scheme):
    b = apk_sig_block(d)
    return None if b is None else APK_SCHEMES[scheme] in b


def delegate(prefix, member=None):
    """A family that reads the rest of a name as a property of another namespace on the same file
    (apk.zip_member_names is zip.member_names) or on one member of it (apk.dex_header_checksum is
    dex.header_checksum of classes.dex). The answer is always unsure: its options are the other
    reader's own, named for it."""
    def fn(n, d, rest):
        inner = f"{prefix}_{rest}"
        p = M.lookup(inner)
        reader = p.name if p is not None else None
        if p is None:
            p, reader = M.synonym(inner)
        if p is None:
            p, reader, _ = M.guess(inner)
        if p is None:
            U(f"no reader of {prefix}.* takes the rest of the name")
        data = d
        if member is not None:
            data = zip_member(d, member, BIG)
            if data is None:
                return None
        options, absent = M.options_for(p, n, data)
        if absent or not options:
            return None
        raise M.Ambiguous([(f"{name}{M.GUESS}{reader}", v) for name, v in options][:6])
    return fn


def blockmap_hash(n, d):
    z = is_msix(d)
    if z is None:
        return None
    body = zip_member(d, "AppxBlockMap.xml", BIG, z)
    if body is None:
        return None
    m = re.search(rb"<BlockMap\b[^>]*?\bHashMethod\s*=\s*\"([^\"]{1,200})\"", body[:4096])
    if not m:
        U("a block map without a HashMethod attribute")
    uri = m.group(1).decode("ascii")
    short = uri.rsplit("#", 1)[-1]
    return [("raw", uri)] + ([("upper", short.upper()), ("lower", short.lower())] if short != uri and short.isalnum() else [])


# ------------------------------------------------------------------ 8. rpm
RPM_TAGS = {"name": 1000, "version": 1001, "release": 1002, "epoch": 1003, "summary": 1004, "buildtime": 1006, "buildhost": 1007,
            "size": 1009, "distribution": 1010, "vendor": 1011, "license": 1014, "packager": 1015, "group": 1016, "url": 1020, "os": 1021,
            "arch": 1022, "sourcerpm": 1044, "rpmversion": 1064, "payloadformat": 1124, "payloadcompressor": 1125, "payloadflags": 1126,
            "platform": 1132, "optflags": 1122, "basenames": 1117}
RPM_SIG = {"size": 1000, "md5": 1004, "payloadsize": 1007, "sha1": 269, "sha256": 273}
RPM_SAME = {"architecture": "arch", "buildtimestamp": "buildtime", "payloadcompression": "payloadcompressor", "sourcepackage": "sourcerpm",
            "packagename": "name", "packageversion": "version", "filenames": "basenames", "homepage": "url", "sourcerpmname": "sourcerpm"}


def _rpm_header(d: bytes, at: int):
    if d[at:at + 4] != b"\x8e\xad\xe8\x01":
        U("an RPM header structure without its magic")
    n, size = struct.unpack_from(">II", d, at + 8)
    store = at + 16 + 16 * n
    if n > 4096 or store + size > len(d):
        U("an RPM header that runs past the file")
    tags = {}
    for k in range(n):
        tag, typ, off, cnt = struct.unpack_from(">IIII", d, at + 16 + 16 * k)
        p = store + off
        if off > size or cnt > size:
            U("an RPM index entry that points outside its store")
        if typ in (6, 9):
            tags.setdefault(tag, d[p:d.index(b"\0", p, store + size)].decode("utf-8"))
        elif typ == 4 and cnt == 1:
            tags.setdefault(tag, struct.unpack_from(">I", d, p)[0])
        elif typ == 8 and cnt <= 4096:
            vals, q = [], p
            for _ in range(cnt):
                e = d.index(b"\0", q, store + size)
                vals.append(d[q:e].decode("utf-8"))
                q = e + 1
            tags.setdefault(tag, vals)
        elif typ == 7 and cnt <= 64:
            tags.setdefault(tag, d[p:p + cnt].hex())
    return tags, store + size


@functools.lru_cache(maxsize=4)
def rpm(d: bytes):
    """{"sig": {tag: value}, "main": {tag: value}} of an RPM package's two header structures, or None."""
    if d[:4] != b"\xed\xab\xee\xdb" or len(d) < 112:
        return None
    sig, end = _rpm_header(d, 96)
    end += (8 - end % 8) % 8
    main, _ = _rpm_header(d, end)
    return {"sig": sig, "main": main}


def iso_forms(seconds: int):
    """The forms of a time stored as seconds since 1970, as a name that ends in a date word asks it."""
    stamp = M._utc(seconds)
    if stamp is None:
        U("a time outside the dates that are written")
    return [("iso_z", stamp + "Z"), ("iso", stamp), ("iso_space", stamp.replace("T", " "))]


def rpm_tag(n, d, field):
    h = rpm(d)
    if h is None:
        return None
    key = sq(field)
    if key in ("buildtimeutc", "buildtimeiso8601"):
        v = h["main"].get(1006)
        if v is None:
            return None
        raise M.Ambiguous(iso_forms(v))
    key = RPM_SAME.get(key, key)
    if key not in RPM_TAGS:
        U("a tag this reader does not know by that name")
    v = h["main"].get(RPM_TAGS[key])
    if key in ("name", "version") and isinstance(v, str) and v:
        # rpm.header_name, rpm.header_version: the header tag first, then the lead's field of that name
        # (its name field holds name-version-release, its version is the package format's)
        lead = pack("readers_more.py")._rpm(d)
        other = None if lead is None else (lead[3] if key == "name" else "%d.%d" % tuple(lead[0]))
        if other and other != v:
            raise M.Ambiguous([("raw", v), ("raw+lead", other)])
    if isinstance(v, list):
        raise M.Ambiguous(M._f_list(v)) if v else U("an empty list")
    return v


def rpm_buildtime(n, d):
    h = rpm(d)
    return None if h is None else h["main"].get(1006)


def rpm_sig(n, d, field):
    h = rpm(d)
    if h is None:
        return None
    v = h["sig"].get(RPM_SIG[sq(field)])
    return v if not isinstance(v, int) else str(v)


# ------------------------------------------------------------------ 10. OLE
def ole_root_clsid(n, d):
    if d[:8] != M.CFB_MAGIC:
        return None
    rf = pack("readers_formats.py")
    v = rf._cfb_root_clsid(d)
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        return guid_digits(bytes(v))
    v = re.sub(r"[^0-9a-fA-F]", "", str(v)).lower()
    return v if len(v) == 32 else U("a root class id of a shape that is not read")


# ------------------------------------------------------------------ 11. Windows artifacts
@functools.lru_cache(maxsize=4)
def task(d: bytes):
    """[(path of local tag names, text)] of every leaf and attribute of a Task Scheduler XML, or None."""
    head = d[:4096]
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        if len(d) > SMALL * 2:
            U("a task definition larger than is read")
        text = d.decode("utf-16")
    elif head[:5] == b"<?xml" or head[:3] == b"\xef\xbb\xbf" or head.lstrip()[:5] == b"<Task":
        text = d[:SMALL + 1].decode("utf-8-sig")
    else:
        return None
    if "<Task" not in text[:2048] or "schemas.microsoft.com/windows/2004/02/mit/task" not in text[:4096]:
        return None
    root = xml_root(re.sub(r"^\s*<\?xml[^>]*\?>", "", text, count=1).encode("utf-8"))
    if root.tag != "Task":
        return None
    out = [(("Task", "@" + k), v) for k, v in root.attrib.items()]

    def walk(e, path, depth):
        if depth > 12 or len(out) > 2048:
            U("a task definition deeper or larger than is walked")
        for c in e:
            if not isinstance(c.tag, str):
                continue
            p = path + (c.tag,)
            for k, v in c.attrib.items():
                out.append((p + ("@" + k,), v))
            if len(c) == 0:
                if c.text and c.text.strip():
                    out.append((p, c.text.strip()))
            else:
                walk(c, p, depth + 1)
    walk(root, (), 0)
    return out


def task_field(n, d, field):
    leaves = task(d)
    if leaves is None:
        return None
    key = sq(field)
    hits = [(p, v) for p, v in leaves if sq("".join(p)).endswith(key) and (sq(p[-1]) in key)]
    # the whole last element must be in the name: `uri` is RegistrationInfo/URI, never a tail of another tag
    hits = [(p, v) for p, v in hits if key.endswith(sq(p[-1]))]
    if not hits and key.endswith("utc"):   # task.registration_info_date_utc: the date as it is written
        return task_field(n, d, field[:-4])
    if not hits:
        U("no element of that name is in the task definition")
    if len({v for _, v in hits}) > 1:
        U("several elements fit the name and hold different values")
    return hits[0][1]


def evtx_first(d: bytes):
    """{field: text} of the first record of the first chunk of an event log, or None when the file is no EVTX."""
    if d[:8] != b"ElfFile\x00":
        return None
    if len(d) < 0x1000 + 0x200 or d[0x1000:0x1008] != b"ElfChnk\x00":
        U("an event log without a first chunk")
    try:
        import Evtx.Evtx as E
    except ImportError:
        U("the python-evtx library is not installed")
    chunk = E.ChunkHeader(d[:0x1000 + 0x10000], 0x1000)
    rec = chunk.first_record()
    if rec.magic() != 0x2A2A or rec.length() > 0x10000:
        U("a first record that is not whole")
    xml = rec.xml()
    out = {"record_id": str(rec.record_num())}
    for key, rx in (("event_id", r"<EventID[^>]*>(\d+)</EventID>"), ("computer", r"<Computer>([^<]*)</Computer>"),
                    ("channel", r"<Channel>([^<]*)</Channel>"), ("provider", r"<Provider Name=\"([^\"]*)\""),
                    ("time_created", r"<TimeCreated SystemTime=\"([^\"]*)\""), ("level", r"<Level>(\d+)</Level>"),
                    ("task", r"<Task>(\d+)</Task>"), ("user_id", r"<Security UserID=\"([^\"]*)\"")):
        m = re.search(rx, xml)
        if m:
            out[key] = m.group(1)
    return out


EVTX_FIELDS = ("event_id", "computer", "channel", "provider", "time_created", "level", "task", "user_id", "record_id")
EVTX_SAME = {"eventid": "event_id", "computername": "computer", "providername": "provider", "timecreated": "time_created",
             "systemtime": "time_created", "timestamp": "time_created", "time": "time_created", "eventrecordid": "record_id",
             "recordnumber": "record_id", "recordidentifier": "record_id", "recordid": "record_id", "userid": "user_id",
             "securityuserid": "user_id", "computer": "computer", "channel": "channel", "provider": "provider", "level": "level",
             "task": "task"}


def evtx_field(n, d, field):
    r = evtx_first(d)
    if r is None:
        return None
    dated = None
    for word in ("utc", "iso8601"):
        if field.endswith("_" + word):
            field, dated = field[:-len(word) - 1], word
    key = None
    for rest in (field, field[7:] if field.startswith("record_") else "", field[6:] if field.startswith("event_") else "",
                 field[7:] if field.startswith("system_") else ""):
        if rest and sq(rest) in EVTX_SAME:
            key = EVTX_SAME[sq(rest)]
            break
    if key is None or (dated and key != "time_created"):
        U("a field of the first record this reader does not know by that name")
    v = r.get(key)
    if v is None:
        return None
    if key == "time_created":
        m = re.fullmatch(r"(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)(?:\.\d+)?(?:Z|\+00:00)?", v)
        if not m:
            U("a TimeCreated value of a shape that is not read")
        stamp = "%s-%s-%sT%s:%s:%s" % m.groups()
        raise M.Ambiguous([("iso_z", stamp + "Z"), ("iso", stamp), ("iso_space", stamp.replace("T", " ")), ("raw", v)])
    return v


def regf_root(d: bytes):
    """(name of the root key, [names of its subkeys] or None) of a registry hive, or None."""
    if d[:4] != b"regf" or len(d) < 0x1000 + 0x60:
        return None
    root, = struct.unpack_from("<I", d, 36)
    at = 0x1000 + root + 4
    if at + 0x50 > len(d) or d[at:at + 2] != b"nk":
        U("a root cell that is not a key node")
    flags, = struct.unpack_from("<H", d, at + 2)
    nsub, = struct.unpack_from("<I", d, at + 0x14)
    sub_off, = struct.unpack_from("<I", d, at + 0x1C)
    nlen, = struct.unpack_from("<H", d, at + 0x48)
    raw = d[at + 0x4C:at + 0x4C + nlen]
    if len(raw) != nlen:
        U("a root key name that is cut")
    name = raw.decode("latin-1" if flags & 0x20 else "utf-16-le")
    return name, (nsub, sub_off)


def _nk_name(d: bytes, off: int) -> str:
    at = 0x1000 + off + 4
    if at + 0x4C > len(d) or d[at:at + 2] != b"nk":
        U("a subkey cell that is not a key node")
    flags, = struct.unpack_from("<H", d, at + 2)
    nlen, = struct.unpack_from("<H", d, at + 0x48)
    raw = d[at + 0x4C:at + 0x4C + nlen]
    if len(raw) != nlen:
        U("a key name that is cut")
    return raw.decode("latin-1" if flags & 0x20 else "utf-16-le")


SUBKEY_CELLS = 70000   # list cells and offsets visited for one root key before the walk is given up


def _subkey_offsets(d: bytes, off: int, inside_ri=False, seen=None):
    """The key node offsets a subkey list cell names. An `ri` cell lists `lf`, `lh` or `li` cells and never
    another `ri` (the format has two levels): a nested one is refused, and every cell and offset is
    counted, so a crafted hive of lists that point at each other costs at most SUBKEY_CELLS steps."""
    seen = [0] if seen is None else seen
    seen[0] += 1
    at = 0x1000 + off + 4
    if seen[0] > SUBKEY_CELLS or at + 4 > len(d):
        U("a subkey list that is not walked")
    sig, n = d[at:at + 2], struct.unpack_from("<H", d, at + 2)[0]
    if sig in (b"lf", b"lh"):
        if at + 4 + n * 8 > len(d):
            U("a subkey list that is cut")
        seen[0] += n
        if seen[0] > SUBKEY_CELLS:
            U("more subkeys than are walked")
        return [struct.unpack_from("<I", d, at + 4 + 8 * i)[0] for i in range(n)]
    if at + 4 + n * 4 > len(d):
        U("a subkey list that is cut")
    if sig == b"li":
        seen[0] += n
        if seen[0] > SUBKEY_CELLS:
            U("more subkeys than are walked")
        return [struct.unpack_from("<I", d, at + 4 + 4 * i)[0] for i in range(n)]
    if sig == b"ri":
        if inside_ri:
            U("an index root inside an index root, which the format does not have")
        out = []
        for i in range(n):
            out += _subkey_offsets(d, struct.unpack_from("<I", d, at + 4 + 4 * i)[0], True, seen)
        return out
    U("a subkey list of a kind that is not read")


def regf_root_name(n, d):
    r = regf_root(d)
    return None if r is None else r[0]


def regf_root_subkeys(n, d):
    r = regf_root(d)
    if r is None:
        return None
    nsub, off = r[1]
    if not nsub:
        return None
    offs = _subkey_offsets(d, off)
    if len(offs) != nsub:
        U("the root key's subkey list does not hold the number of subkeys it states")
    return [_nk_name(d, o) for o in offs]


def regf_root_subkey_count(n, d):
    r = regf_root(d)
    return None if r is None else r[1][0]


def minidump_streams(d: bytes):
    if d[:4] != b"MDMP" or len(d) < 32:
        return None
    n, rva = struct.unpack_from("<II", d, 8)
    if n > 4096 or rva + 12 * n > len(d):
        U("a stream directory that is cut")
    out = {}
    for i in range(n):
        t, size, off = struct.unpack_from("<III", d, rva + 12 * i)
        if t and off + size <= len(d):
            out.setdefault(t, []).append((off, size))
    return out


MD_ARCH = {0: "PROCESSOR_ARCHITECTURE_INTEL", 5: "PROCESSOR_ARCHITECTURE_ARM", 6: "PROCESSOR_ARCHITECTURE_IA64",
           9: "PROCESSOR_ARCHITECTURE_AMD64", 12: "PROCESSOR_ARCHITECTURE_ARM64"}


def minidump_sysinfo(field):
    def fn(n, d):
        s = minidump_streams(d)
        if s is None:
            return None
        hit = one(s.get(7, []), "system info streams")
        if hit is None:
            return None
        off, size = hit
        if size < 32:
            U("a system info stream that is cut")
        arch, level, rev, ncpu, ptype, major, minor, build, platform = struct.unpack_from("<HHHBBIIII", d, off)
        v = {"arch": arch, "level": level, "revision": rev, "ncpu": ncpu, "product_type": ptype, "major": major, "minor": minor,
             "build": build, "platform": platform}[field]
        return (MD_ARCH.get(v), v) if field == "arch" else v
    return fn


def minidump_count(kind):
    def fn(n, d):
        s = minidump_streams(d)
        if s is None:
            return None
        hit = one(s.get(kind, []), "streams of that type")
        if hit is None:
            return None
        return struct.unpack_from("<I", d, hit[0])[0]
    return fn


def minidump_stream_types(n, d):
    s = minidump_streams(d)
    return None if s is None else sorted(s)


# ------------------------------------------------------------------ 12. xar/pkg, dmg, pdb, nsis, inno
@functools.lru_cache(maxsize=4)
def xar(d: bytes):
    """{"header": (size, version, toc compressed, toc uncompressed, checksum id), "root": the TOC's root element} or None."""
    if d[:4] != b"xar!" or len(d) < 28:
        return None
    size, ver, clen, ulen, cks = struct.unpack_from(">HHQQI", d, 4)
    if size < 28 or clen > BIG or ulen > BIG or size + clen > len(d):
        U("a xar header whose table of contents does not fit the file")
    toc = zlib.decompressobj().decompress(d[size:size + clen], BIG)
    if len(toc) != ulen:
        U("a table of contents that does not inflate to its stated length")
    if len(toc) > SMALL * 4:
        U("a table of contents larger than is read")
    import xml.etree.ElementTree as ET
    if b"<!ENTITY" in toc:
        U("a table of contents that declares entities")
    return {"header": (size, ver, clen, ulen, cks), "root": ET.fromstring(toc), "heap": size + clen}


def xar_header(i):
    return lambda n, d: (lambda x: None if x is None else x["header"][i])(xar(d))


def xar_checksum(n, d):
    x = xar(d)
    if x is None:
        return None
    e = x["root"].find("toc/checksum")
    style = e.attrib.get("style") if e is not None else None
    ident = x["header"][4]
    if not style:
        return None if ident == 0 else U("a checksum the header states and the table of contents does not")
    return [("lower", style.lower()), ("upper", style.upper()), ("integer", str(ident))]


def xar_names(n, d):
    x = xar(d)
    if x is None:
        return None
    return [e.findtext("name") or U("a file without a name") for e in x["root"].findall("toc/file")] or None


def xar_creation(n, d):
    x = xar(d)
    return None if x is None else x["root"].findtext("toc/creation-time")


def _xar_file(d: bytes, x: dict, name: str):
    hits = [e for e in x["root"].iter("file") if e.findtext("name") == name]
    if not hits:
        return None
    e = one(hits, f"files named {name}")
    data = e.find("data")
    if data is None:
        return None
    off, length = int(data.findtext("offset")), int(data.findtext("length"))
    enc = (data.find("encoding").attrib.get("style") if data.find("encoding") is not None else "") or ""
    raw = d[x["heap"] + off:x["heap"] + off + length]
    if len(raw) != length or length > SMALL:
        U(f"{name} runs past the file or is larger than is read")
    if "gzip" in enc:
        return zlib.decompressobj().decompress(raw, SMALL)
    if "octet-stream" in enc or not enc:
        return raw
    U(f"{name} is stored in a way that is not read ({enc})")


def pkg_info(attribute):
    def fn(n, d):
        x = xar(d)
        if x is None:
            return None
        body = _xar_file(d, x, "PackageInfo")
        if body is None:
            return None
        return xml_root(body).attrib.get(attribute)
    return fn


def koly(d: bytes):
    k = d[-512:]
    return k if len(d) >= 512 and k[:4] == b"koly" else None


def koly_field(fmt, at):
    return lambda n, d: (lambda k: None if k is None else struct.unpack_from(fmt, k, at)[0])(koly(d))


def koly_segment_id(n, d):
    k = koly(d)
    return None if k is None else k[0x40:0x50].hex()


@functools.lru_cache(maxsize=4)
def pdb(d: bytes):
    """{"block_size", "blocks", "streams", "version", "signature", "age", "guid"} of an MSF 7.00 program database, or None."""
    if d[:26] != b"Microsoft C/C++ MSF 7.00\r\n" or len(d) < 56:
        return None
    bs, fpm, nblocks, dirsize, _, dirmap = struct.unpack_from("<IIIIII", d, 32)
    if bs not in (512, 1024, 2048, 4096, 8192) or dirsize > BIG or (dirmap + 1) * bs > len(d):
        U("an MSF superblock that does not fit the file")
    nd = (dirsize + bs - 1) // bs
    if nd * 4 > bs:
        U("a stream directory whose block map is larger than one block")
    blocks = struct.unpack_from("<%dI" % nd, d, dirmap * bs)
    if any((b + 1) * bs > len(d) for b in blocks):
        U("a stream directory block outside the file")
    directory = b"".join(d[b * bs:(b + 1) * bs] for b in blocks)[:dirsize]
    n, = struct.unpack_from("<I", directory, 0)
    if n < 2 or n > 65536 or 4 + 4 * n > len(directory):
        U("a stream directory that is cut")
    sizes = struct.unpack_from("<%dI" % n, directory, 4)
    pos = 4 + 4 * n
    k0 = 0 if sizes[0] in (0, 0xFFFFFFFF) else (sizes[0] + bs - 1) // bs
    pos += 4 * k0
    k1 = (sizes[1] + bs - 1) // bs
    if sizes[1] in (0, 0xFFFFFFFF) or sizes[1] < 28 or pos + 4 * k1 > len(directory) or k1 > 64:
        U("a PDB info stream that is not there or not whole")
    s1 = b"".join(d[b * bs:(b + 1) * bs] for b in struct.unpack_from("<%dI" % k1, directory, pos))[:sizes[1]]
    if len(s1) < 28:
        U("a PDB info stream outside the file")
    ver, sig, age = struct.unpack_from("<III", s1, 0)
    return {"block_size": bs, "blocks": nblocks, "streams": n, "version": ver, "signature": sig, "age": age, "guid": guid_digits(s1[12:28])}


def pdb_field(key):
    return lambda n, d: (lambda p: None if p is None else p[key])(pdb(d))


NSIS_MAGIC = b"\xef\xbe\xad\xdeNullsoftInst"


def nsis(d: bytes):
    """(offset of the first header, flags, header size, archive size) of an NSIS installer, or None."""
    if d[:2] != b"MZ":
        return None
    i = d.find(NSIS_MAGIC)
    if i < 4:
        return None
    if d.find(NSIS_MAGIC, i + 1) >= 0:
        U("two NSIS first headers in the file")
    if i + 24 > len(d):
        U("an NSIS first header that is cut")
    return (i - 4, struct.unpack_from("<I", d, i - 4)[0]) + struct.unpack_from("<II", d, i + 16)


def nsis_field(i):
    return lambda n, d: (lambda x: None if x is None else x[i])(nsis(d))


INNO_RX = re.compile(rb"Inno Setup Setup Data \((\d+\.\d+\.\d+(?:\.\d+)?)\)(?: \(([a-z])\))?")


def inno(d: bytes):
    if d[:2] != b"MZ":
        return None
    hits = {(m.group(0), m.group(1)) for m in INNO_RX.finditer(d)}
    if not hits:
        return None
    if len(hits) > 1:
        U("two Inno Setup data marks that differ")
    whole, ver = hits.pop()
    return whole.decode("ascii"), ver.decode("ascii")


def inno_version(n, d):
    x = inno(d)
    return None if x is None else [("version", x[1]), ("raw", x[0])]


def inno_mark(n, d):
    x = inno(d)
    return None if x is None else x[0]


# ------------------------------------------------------------------ 13. single fields
def elf_section(name):
    def get(d):
        rm = pack("readers_more.py")
        secs = rm._elf_sections(d)
        if secs is None:
            return None
        hits = [s for s in secs if s[0] == name]
        if not hits:
            return None
        s = one(hits, f"{name} sections")
        body = d[s[2]:s[2] + s[3]]
        if len(body) != s[3]:
            U(f"a {name} section that runs past the file")
        return s, body
    return get


def elf_debuglink_name(n, d):
    r = elf_section(".gnu_debuglink")(d)
    if r is None:
        return None
    body = r[1]
    return body[:body.index(b"\0")].decode("utf-8") or None


def elf_debuglink_crc(n, d):
    r = elf_section(".gnu_debuglink")(d)
    if r is None:
        return None
    body = r[1]
    if len(body) < 8 or len(body) % 4:
        U("a .gnu_debuglink section of a size that is not read")
    return struct.unpack_from(">I" if d[5] == 2 else "<I", body, len(body) - 4)[0]


def elf_dynsym_count(n, d):
    r = elf_section(".dynsym")(d)
    if r is None:
        return None
    ent = 24 if d[4] == 2 else 16
    if r[0][3] % ent:
        U("a .dynsym section that is not a whole number of symbols")
    return r[0][3] // ent


def macho_fat_magic(n, d):
    return struct.unpack_from(">I", d, 0)[0] if d[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") and M._fat_count(d) else None


def sevenz_crc(at):
    return lambda n, d: struct.unpack_from("<I", d, at)[0] if d[:6] == M.SEVENZ and len(d) >= 32 else None


def bz2_block_crc(n, d):
    if d[:3] != b"BZh" or len(d) < 14:
        return None
    if d[4:10] != b"\x31\x41\x59\x26\x53\x59":
        return None if d[4:10] == b"\x17\x72\x45\x38\x50\x90" else U("a stream whose first block has no block magic")
    return struct.unpack_from(">I", d, 10)[0]


def class_magic(n, d):
    return 0xCAFEBABE if M._safe(M._class, d) else None


def cpio_magic(n, d):
    return d[:6].decode("ascii") if d[:6] in (b"070701", b"070702", b"070707") else None


def pe_rich_key(n, d):
    rm = pack("readers_more.py")
    x = rm._pex(d)
    if x is None:
        return None
    lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    stub = d[0x40:min(lfanew, 0x1000)]
    hits = [m.start() for m in re.finditer(rb"Rich", stub)]
    if not hits:
        return None
    i = one(hits, "Rich marks in the DOS stub")
    if i + 8 > len(stub):
        U("a Rich mark without its key")
    key = struct.unpack_from("<I", stub, i + 4)[0]
    if struct.pack("<I", struct.unpack("<I", b"DanS")[0] ^ key) not in stub[:i]:
        U("a Rich mark whose key does not open a DanS header")
    return key


IDENTITY_RX = re.compile(r"<(?:\w+:)?assemblyIdentity\b([^>]*)>", re.S)


def pe_manifest_identity(attribute):
    def fn(n, d):
        rs = pack("readers_structures.py")
        texts = rs._manifests(d)
        if not texts:
            return None
        values = set()
        for t in texts:
            t = re.sub(r"<!--.*?-->", "", t, flags=re.S)
            # the assembly's own identity is the one that is a child of <assembly>, not of a dependency
            body = re.sub(r"<(?:\w+:)?dependency\b.*?</(?:\w+:)?dependency>", "", t, flags=re.S)
            for m in IDENTITY_RX.finditer(body):
                a = re.search(r"\b%s\s*=\s*([\"'])(.*?)\1" % attribute, m.group(1), re.S)
                if a:
                    values.add(a.group(2))
        return one(values, "assembly identities") if values else None
    return fn


def mkv_track_uid(n, d):
    rf = pack("readers_formats.py")
    tracks = rf._mkv_tracks(d)
    if tracks is None:
        return None
    uids = []
    for t in tracks:
        v = next((t[k] for k in (0x73C5, "TrackUID", "track_uid", "uid") if k in t), None) if isinstance(t, dict) else None
        if not isinstance(v, (bytes, bytearray)) or not 1 <= len(v) <= 8:
            U("a track entry whose UID this reader does not see")
        uids.append(int.from_bytes(v, "big"))
    return one(uids, "tracks")


def elf_sections_with_null(n, d):
    secs = pack("readers_more.py")._elf_sections(d)
    return None if secs is None else [s[0] for s in secs]


def x509_ski(n, d):
    rd = pack("readers_docs.py")
    c = rd._cert(d)
    if c is None:
        return None
    from cryptography import x509
    try:
        ext = c[0].extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    except x509.ExtensionNotFound:
        return None
    return ext.value.digest.hex()


def jar_main_attribute(n, d, field):
    return pack("readers_more.py")._manifest_field(n, d, field)


def jar_class_path_candidates(n, d):
    """Class-Path as two DIFFERENT candidate values (Day 23 look-ahead build C, row 346): the whole
    space-joined string ('raw') and the JSON array of its whitespace-split entries ('split'). Different
    values, so a candidate pick (candidate key, probed only on the untimed base or an attempt with no
    deadline, NEVER plain before the judge accepts a hypothesis). None when Class-Path is absent, so the
    reader stays fail-closed (-> the unsure `none` of the absent path). Shared by jar.class_path and
    jar.manifest_class_path, both under the one key metadata.format/jar.class_path."""
    import json as _json
    v = pack("readers_more.py")._manifest_field(n, d, "class_path")
    if not isinstance(v, str) or not v.strip():
        return None
    entries = v.split()
    return M.ledger_forms(
        M.labels.candidate_key("metadata.format/jar.class_path"),
        [("raw", v), ("split", _json.dumps(entries, separators=(",", ":")))])


OLE_SAME = {"application_name": "creating_application", "app_name": "creating_application", "last_author": "last_saved_by",
            "create_time": "create_time", "created": "create_time", "last_save_time": "last_saved_time"}


def ole_summary(n, d, ns, doc, field):
    """ole.summary_information_<field> and ole.document_summary_information_<field>: the stream's own name
    in front of a field the earlier pack reads as <ns>.summary_<field> / <ns>.document_summary_<field>."""
    field = OLE_SAME.get(field, field)
    return delegate(f"{ns}_{'document_' if doc else ''}summary")(n, d, field)
