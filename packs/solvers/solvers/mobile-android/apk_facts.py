#!/usr/bin/env python3
"""Facts about an Android package, for a Mobile question that does not ask for the ANS- code.

  .venv/bin/python solvers/mobile-android/apk_facts.py <file.apk>      # prints every fact it reads

Days 1 to 8 asked one thing of every APK, the answer code. If a later day asks about the package
itself (its name, the exported component, the deep link, a permission, the signing certificate),
codec_search.solve_set hands those questions here. Everything is read with plain Python from the
bytes (apk_resources.py for the compiled manifest; no androguard, no aapt, no jadx):

  manifest   package, version code and name, min and target SDK, permissions, the application's
             label, allowBackup, debuggable, usesCleartextTraffic, networkSecurityConfig, meta-data,
             every component with its exported flag, permission, authorities and intent filters
             (actions, categories, scheme, host, port, path), the launcher activity, the deep link
  dex        the fixture's own strings: the control (DAY-NN:<control>:<mechanic>), the case
             reference (MOB-NN-...), the client secret (SECRET-...), the backend URL and its
             attempt id
  document   the codec the puzzle document names
  signature  the signing certificate's SHA-256, SHA-1 and MD5, subject and issuer common name,
             serial number (through `cryptography`, imported only when such a question is asked)
  bytes      SHA-256, SHA-1 and MD5 and the size of the package and of its dex, manifest and puzzle
             document; the number of members, permissions, activities, exported components

Never-guess (AGENTS.md, "Uncertain answers"). A question is answered only when its id (or, failing
that, its text) names exactly one fact. Nothing a judge has accepted exists for any of them, so:

  plain    only a hash or a size of the delivered package or of one named member, in lowercase hex
           or digits (upper-case hex when the question's syntax says so): the question's own format
           leaves one way to write it. And only when the question's id says nothing else: every
           word of it is the fact's own or a neutral one (`apk_sha256`, `d09_file_size_bytes`). An
           id with a word left over (`native_lib_sha256`, `key_size`, `answer_sha256`) names some
           other object's hash or size, and a sentence is never read that closely, so those are
           unsure under a key of their own (`mobile.apk_sha256/apk:lib-native`,
           `mobile.apk_size/apk:q=q2`)
  unsure  every other fact that was read: labels.pick('mobile.<fact>/apk', [(format, value), ...]),
           the formats being spellings of that one fact (a component as the manifest writes it, by
           its simple name, by its full class name). tools/verify.py probes them on the untimed
           base, one request each, and never on a clock. The key carries the id's left-over
           words (`c2_host` is `mobile.host/apk:c2`), so a name the judge accepts for one question
           never answers another that only shares a word with it
  None     a fact the package does not hold exactly once (two exported activities besides the
           launcher, several permissions), a question that names no fact or two, a value the
           question's own pattern refuses, and anything that is not an APK

It answers nothing about a delivery that is not an Android package (no compiled manifest and no
dex), so a lane this solver does not belong to can never be matched to it by these answers.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE.parent / "common", HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
import labels  # noqa: E402
import apk_resources as R  # noqa: E402
try:
    import proguard_mapping  # noqa: E402  (ProGuard/R8 mapping.txt deobfuscation reader)
except Exception:            # pragma: no cover - the reader is optional
    proguard_mapping = None

PUZZLE = "assets/huntress_puzzle.json"
COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")
_CERT = re.compile(r"META-INF/[^/]+\.(RSA|DSA|EC)$", re.I)


# ---------------------------------------------------------------------------- reading

def _dex_strings(d) -> list:
    import struct
    try:
        n, off = struct.unpack_from("<II", d, 0x38)
        out = []
        for i in range(min(n, 20000)):
            o = struct.unpack_from("<I", d, off + 4 * i)[0]
            while d[o] & 0x80:
                o += 1
            o += 1
            raw = d[o:d.index(b"\0", o)].replace(b"\xc0\x80", b"\0")
            value = raw.decode("utf-8", "surrogatepass")
            out.append(value.encode("utf-16le", "surrogatepass").decode("utf-16le", "surrogatepass"))
        return out
    except Exception:
        return []


def _full(package, name):
    if not isinstance(name, str) or not name:
        return None
    if name.startswith("."):
        return (package or "") + name
    return name if "." in name else ((package + "." + name) if package else name)


def manifest_facts(body) -> dict:
    """What the compiled manifest says, as plain Python values. {} when it cannot be read."""
    els = R.axml_tree(body)
    if not els or els[0]["tag"] != "manifest":
        return {}
    root = els[0]["attrs"]
    m = {"package": root.get("package"), "version_code": root.get("versionCode"),
         "version_name": root.get("versionName"), "permissions": [], "meta": {}, "components": [],
         "min_sdk": None, "target_sdk": None, "application": {}}
    current = flt = None
    for el in els[1:]:
        tag, a, depth = el["tag"], el["attrs"], el["depth"]
        if tag == "uses-sdk":
            m["min_sdk"], m["target_sdk"] = a.get("minSdkVersion"), a.get("targetSdkVersion")
        elif tag in ("uses-permission", "uses-permission-sdk-23") and isinstance(a.get("name"), str):
            m["permissions"].append(a["name"])
        elif tag == "application":
            m["application"] = dict(a)
        elif tag in COMPONENTS and depth == 2:
            current = {"kind": tag, "name": a.get("name"), "full": _full(m["package"], a.get("name")),
                       "exported": a.get("exported"), "permission": a.get("permission"),
                       "authorities": a.get("authorities"), "grant": a.get("grantUriPermissions"), "filters": []}
            m["components"].append(current)
            flt = None
        elif tag == "meta-data" and isinstance(a.get("name"), str):
            if depth == 2:
                m["meta"][a["name"]] = a.get("value")
        elif tag == "intent-filter" and current is not None and depth == 3:
            flt = {"actions": [], "categories": [], "data": []}
            current["filters"].append(flt)
        elif flt is not None and depth == 4:
            if tag == "action" and isinstance(a.get("name"), str):
                flt["actions"].append(a["name"])
            elif tag == "category" and isinstance(a.get("name"), str):
                flt["categories"].append(a["name"])
            elif tag == "data":
                flt["data"].append({k: a[k] for k in ("scheme", "host", "port", "path", "pathPrefix", "pathPattern",
                                                      "mimeType") if a.get(k) is not None})
    return m


_INFO_PLIST = re.compile(r"Payload/[^/]+\.app/Info\.plist$")


def ipa_facts(members) -> dict:
    """An iOS package's Info.plist in the manifest's shape, so the same questions are answered from
    it: bundle id as the package, the two version strings, the minimum OS, the display name, the
    URL scheme, App Transport Security's arbitrary loads as cleartext. {} when there is no one
    Payload/<name>.app/Info.plist that plistlib reads."""
    names = [n for n in members if _INFO_PLIST.match(n)]
    if len(names) != 1 or len(members[names[0]]) > (1 << 20):
        return {}
    try:
        import plistlib
        info = plistlib.loads(members[names[0]])
    except Exception:
        return {}
    if not isinstance(info, dict) or not isinstance(info.get("CFBundleIdentifier"), str):
        return {}
    ats = info.get("NSAppTransportSecurity")
    schemes = [s for t in (info.get("CFBundleURLTypes") or []) if isinstance(t, dict)
               for s in (t.get("CFBundleURLSchemes") or []) if isinstance(s, str)]
    link = {"kind": "activity", "name": None, "full": None, "exported": None, "permission": None, "authorities": None,
            "grant": None, "filters": [{"actions": ["android.intent.action.VIEW"], "categories": [],
                                        "data": [{"scheme": s} for s in schemes]}]}
    return {"package": info.get("CFBundleIdentifier"), "version_code": info.get("CFBundleVersion"),
            "version_name": info.get("CFBundleShortVersionString"), "min_sdk": info.get("MinimumOSVersion"),
            "target_sdk": None, "permissions": [], "meta": {}, "components": [link] if schemes else [],
            "application": {"label": info.get("CFBundleDisplayName") or info.get("CFBundleName"),
                            "usesCleartextTraffic": ats.get("NSAllowsArbitraryLoads") if isinstance(ats, dict) else None}}


def read(members, blob=b"") -> dict:
    """Every fact of one package: {"manifest": {...}, "dex": [...strings], "codec": str|None, ...}.
    {} for a delivery that is no Android package."""
    manifest = members.get("AndroidManifest.xml")
    dexes = sorted(n for n in members if n.endswith(".dex") and members[n][:4] == b"dex\n")
    if not (manifest and R.is_axml(manifest)) and not dexes:
        ios = ipa_facts(members)
        if not ios:
            return {}
        return {"manifest": ios, "dex": [], "members": members, "blob": bytes(blob), "dexes": [], "codec": None}
    f = {"manifest": manifest_facts(manifest) if manifest else {}, "dex": [], "members": members, "blob": bytes(blob),
         "dexes": dexes, "codec": None}
    for n in dexes:
        f["dex"] += _dex_strings(members[n])
    try:
        doc = json.loads(members[PUZZLE].decode("utf-8-sig")) if PUZZLE in members else None
        if isinstance(doc, dict) and isinstance(doc.get("codec"), str):
            f["codec"] = doc["codec"]
    except Exception:
        pass
    return f


def _one(values):
    """The one value of a list of candidates, or None when there is none or more than one."""
    uniq = list(dict.fromkeys(v for v in values if v not in (None, "")))
    return uniq[0] if len(uniq) == 1 else None


def _dex_match(f, pattern, group=0):
    rx = re.compile(pattern)
    return _one([m.group(group) for s in f["dex"] for m in [rx.search(s)] if m])


def _launcher(m):
    return _one([c["name"] for c in m.get("components", ()) if c["kind"].startswith("activity") and any(
        "android.intent.action.MAIN" in fl["actions"] and "android.intent.category.LAUNCHER" in fl["categories"]
        for fl in c["filters"])])


def _exported(m, kinds=COMPONENTS):
    """The one exported component of these kinds; the launcher activity is set aside when that leaves one."""
    cs = [c for c in m.get("components", ()) if c["kind"] in kinds and (c["exported"] is True or (
        c["exported"] is None and c["filters"]))]
    if len(cs) > 1:
        launcher = _launcher(m)
        rest = [c for c in cs if c["name"] != launcher]
        cs = rest if len(rest) == 1 else cs
    return cs[0] if len(cs) == 1 else None


def _links(m):
    """Every (component, data) of a VIEW intent filter that names a scheme."""
    return [(c, d) for c in m.get("components", ()) for fl in c["filters"]
            if "android.intent.action.VIEW" in fl["actions"] for d in fl["data"] if d.get("scheme")]


def _cert(f):
    """The one signing certificate (DER) of the package's v1 signature block, or None."""
    blocks = [f["members"][n] for n in f["members"] if _CERT.match(n)]
    if len(blocks) != 1:
        return None
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7, Encoding
        certs = pkcs7.load_der_pkcs7_certificates(blocks[0])
        return (certs[0], certs[0].public_bytes(Encoding.DER)) if len(certs) == 1 else None
    except Exception:
        return None


# ---------------------------------------------------------------------------- formats

def _name_forms(package, name):
    """A component as the manifest writes it, by its simple name, and by its full class name."""
    if not isinstance(name, str) or not name:
        return []
    full = _full(package, name)
    forms = [("as-written", name), ("full", full), ("simple", name.rsplit(".", 1)[-1])]
    return [(k, v) for i, (k, v) in enumerate(forms) if v and v not in [x for _, x in forms[:i]]]


def _bool_forms(v):
    if not isinstance(v, bool):
        return []
    return [("true-false", "true" if v else "false"), ("yes-no", "yes" if v else "no"),
            ("title", "True" if v else "False"), ("digit", "1" if v else "0")]


def _text(v):
    return [("as-written", str(v))] if v not in (None, "") and not isinstance(v, (bool, dict, list)) else []


def _digest_forms(hexdigest):
    up = hexdigest.upper()
    return [("hex", hexdigest), ("colons-upper", ":".join(up[i:i + 2] for i in range(0, len(up), 2))), ("hex-upper", up),
            ("colons", ":".join(hexdigest[i:i + 2] for i in range(0, len(hexdigest), 2)))]


# ---------------------------------------------------------------------------- the facts
#
# Each fact: (name, the word sets that name it, a function of the facts that returns its
# [(format, value)] options or a plain string, plain?). A word set matches when every word of it
# is among the words of the question's id. The most specific match wins (the largest word set),
# and two facts that match equally well are no match.

def _link_part(part):
    def get(f):
        return _text(_one([d.get(part) for _, d in _links(f["manifest"])]))
    return get


def _deep_link(f):
    links = _links(f["manifest"])
    if len(links) != 1:
        return []
    d = links[0][1]
    host = d.get("host") or ""
    port = ":%s" % d["port"] if d.get("port") else ""
    path = d.get("path") or d.get("pathPrefix") or d.get("pathPattern") or ""
    out = [("uri", "%s://%s%s%s" % (d["scheme"], host, port, path))]
    if path:
        out.append(("uri-no-path", "%s://%s%s" % (d["scheme"], host, port)))
    return out


def _component(kinds, exported=True):
    def get(f):
        m = f["manifest"]
        c = _exported(m, kinds) if exported else None
        if not exported:
            cs = [c for c in m.get("components", ()) if c["kind"] in kinds]
            c = cs[0] if len(cs) == 1 else None
        return _name_forms(m.get("package"), c["name"]) if c else []
    return get


def _permission(f):
    p = f["manifest"].get("permissions", [])
    if len(p) != 1:
        return []
    return [("as-written", p[0])] + ([("short", p[0].rsplit(".", 1)[-1])] if "." in p[0] else [])


def _secret(f):
    s = _dex_match(f, r"SECRET-[0-9A-Fa-f]{6,}")
    return [("as-written", s), ("value", s.split("-", 1)[1])] if s else []


def _backend(f):
    url = _dex_match(f, r"https?://[^\s\"'<>]+")
    if not url:
        return []
    m = re.match(r"(https?://[^/?#]+)([^?#]*)", url)
    out = [("as-written", url)]
    if m and m.group(1) + m.group(2) != url:
        out.append(("no-query", m.group(1) + m.group(2)))
    if m and m.group(1) != url:
        out.append(("origin", m.group(1)))
    return out


def _backend_part(part):
    def get(f):
        url = _dex_match(f, r"https?://[^\s\"'<>]+")
        m = re.match(r"https?://([^/:?#]+)(?::(\d+))?", url or "")
        if not m:
            return []
        return _text(m.group(1) if part == "host" else m.group(2))
    return get


def _cert_digest(algo):
    def get(f):
        got = _cert(f)
        return _digest_forms(hashlib.new(algo, got[1]).hexdigest()) if got else []
    return get


def _cert_name(which):
    def get(f):
        got = _cert(f)
        if not got:
            return []
        try:
            from cryptography.x509.oid import NameOID
            name = got[0].subject if which == "subject" else got[0].issuer
            cn = [a.value for a in name.get_attributes_for_oid(NameOID.COMMON_NAME)]
            out = [("common-name", cn[0])] if len(cn) == 1 else []
            return out + [("rfc4514", name.rfc4514_string())]
        except Exception:
            return []
    return get


def _cert_serial(f):
    got = _cert(f)
    if not got:
        return []
    n = got[0].serial_number
    return [("hex", "%x" % n), ("decimal", str(n)), ("hex-upper", "%X" % n)]


def _hash_of(which, algo):
    def get(f):
        if which == "apk":
            body = f["blob"] or None
        elif which == "dex":
            body = f["members"][f["dexes"][0]] if len(f["dexes"]) == 1 else None
        elif which == "puzzle":
            # "the asset" is the puzzle document only when it is the one asset the package has
            assets = [n for n in f["members"] if n.startswith("assets/")]
            body = f["members"].get(PUZZLE) if assets == [PUZZLE] else None
        else:
            body = f["members"].get("AndroidManifest.xml")
        return hashlib.new(algo, body).hexdigest() if body else None
    return get


def _size_of(which):
    def get(f):
        if which == "apk":
            return str(len(f["blob"])) if f["blob"] else None
        body = f["members"][f["dexes"][0]] if which == "dex" and len(f["dexes"]) == 1 else None
        return str(len(body)) if body else None
    return get


# ---- B-249: database_name / table_name (Day 13 readiness #16: both None on the real Day 12 APK). The app's SQLite
# database file and its one table, read from the bytes: a dex string that is a database file name (what a
# SQLiteOpenHelper or Room builder is handed) or a member that IS a SQLite database (its basename); a `CREATE TABLE`
# in a dex string, or the tables a SQLite member holds (read in memory with sqlite3, never written to disk). Only a
# fact the package holds exactly once is offered, and always unsure (labels.pick): no judge has accepted either.

_DB_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-]{0,63}\.(?:db|sqlite|sqlite3|db3)")
_CREATE_TABLE = re.compile(r"\bCREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"\[]?"
                           r"([A-Za-z_][A-Za-z0-9_]{0,63})", re.I)
_SQLITE_MAGIC = b"SQLite format 3\x00"
_SQLITE_MAX = 8 << 20
_SQLITE_INTERNAL = ("sqlite_", "android_metadata", "room_master_table")


def _user_table(name):
    """True for a table the app defines: not SQLite's own (sqlite_*) nor the framework's (android_metadata, Room's
    room_master_table). SQLite names are case-insensitive, so the test is too. Applied to the dex `CREATE TABLE`
    strings and the SQLite members alike (Room and SQLiteOpenHelper put the framework's CREATE TABLE in the dex)."""
    return isinstance(name, str) and not name.lower().startswith(_SQLITE_INTERNAL)


def _sqlite_members(f):
    return [(n, b) for n, b in f["members"].items()
            if isinstance(b, (bytes, bytearray)) and bytes(b[:16]) == _SQLITE_MAGIC and len(b) <= _SQLITE_MAX]


def _sqlite_tables(body):
    """The user tables of a SQLite database held in bytes (sqlite3 deserialize, in memory), or None when it does not
    read."""
    import sqlite3
    con = sqlite3.connect(":memory:")
    try:
        con.deserialize(bytes(body))
        rows = con.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    except Exception:
        return None
    finally:
        con.close()
    return [r[0] for r in rows if _user_table(r[0])]


def _database_name(f):
    names = [s for s in f["dex"] if _DB_NAME.fullmatch(s)]
    names += [n.rsplit("/", 1)[-1] for n, _b in _sqlite_members(f)]
    one = _one(names)
    if not one:
        return []
    stem = one.rsplit(".", 1)[0]
    return [("as-written", one)] + ([("stem", stem)] if stem and stem != one else [])


def _table_name(f):
    tables = [m.group(1) for s in f["dex"] for m in _CREATE_TABLE.finditer(s) if _user_table(m.group(1))]
    for _n, body in _sqlite_members(f):
        got = _sqlite_tables(body)
        if got is None:
            return []          # a database the package holds that does not read: its tables are not known
        tables += got
    one = _one(tables)
    return [("as-written", one)] if one else []


def _count(fn):
    def get(f):
        try:
            return [("count", str(fn(f)))]
        except Exception:
            return []
    return get


def _app(attr, kind="text"):
    def get(f):
        v = f["manifest"].get("application", {}).get(attr)
        return _bool_forms(v) if kind == "bool" else _text(v)
    return get


def _top(field):
    return lambda f: _text(f["manifest"].get(field))


def _meta(name):
    return lambda f: _text(f["manifest"].get("meta", {}).get(name))


W = lambda *sets: tuple(frozenset(s.split()) for s in sets)  # noqa: E731

FACTS = [
    ("package", W("package", "package name", "app id", "application id", "bundle id", "bundle identifier", "bundleid"),
     _top("package"), False),
    ("version_name", W("version name", "versionname"), _top("version_name"), False),
    ("version_code", W("version code", "versioncode"), _top("version_code"), False),
    ("min_sdk", W("min sdk", "minsdk", "minimum sdk", "min sdk version", "minsdkversion", "minimum os", "min os",
                  "minimum os version", "min os version"), _top("min_sdk"), False),
    ("target_sdk", W("target sdk", "targetsdk", "target sdk version", "targetsdkversion"), _top("target_sdk"), False),
    ("label", W("label", "app label", "app name", "application label", "application name"), _app("label"), False),
    ("allow_backup", W("allow backup", "allowbackup", "backup allowed", "backup enabled"), _app("allowBackup", "bool"), False),
    ("debuggable", W("debuggable"), _app("debuggable", "bool"), False),
    ("cleartext", W("cleartext", "uses cleartext traffic", "usescleartexttraffic", "cleartext traffic",
                    "cleartext permitted", "cleartext allowed"), _app("usesCleartextTraffic", "bool"), False),
    ("network_security_config", W("network security config", "networksecurityconfig"), _app("networkSecurityConfig"), False),
    ("permission", W("permission", "uses permission", "requested permission"), _permission, False),
    ("mechanic", W("mechanic"), _meta("huntress.mechanic"), False),
    ("day", W("huntress day", "fixture day"), _meta("huntress.day"), False),
    ("launcher_activity", W("launcher", "launcher activity", "main activity", "entry activity"),
     lambda f: _name_forms(f["manifest"].get("package"), _launcher(f["manifest"])), False),
    ("exported_component", W("exported", "exported component"), _component(COMPONENTS), False),
    ("exported_activity", W("exported activity"), _component(("activity", "activity-alias")), False),
    ("exported_service", W("exported service"), _component(("service",)), False),
    ("exported_receiver", W("exported receiver"), _component(("receiver",)), False),
    ("exported_provider", W("exported provider"), _component(("provider",)), False),
    ("provider", W("provider", "content provider", "provider name", "provider class"), _component(("provider",), False), False),
    ("authority", W("authority", "authorities", "provider authority", "content authority"),
     lambda f: _text(_one([c["authorities"] for c in f["manifest"].get("components", ()) if c["kind"] == "provider"])), False),
    ("scheme", W("scheme", "deep link scheme", "url scheme", "uri scheme", "deeplink scheme"), _link_part("scheme"), False),
    ("host", W("host", "deep link host", "deeplink host", "link host"), _link_part("host"), False),
    ("path", W("path", "path prefix", "pathprefix", "deep link path", "deeplink path"),
     lambda f: _text(_one([d.get("path") or d.get("pathPrefix") or d.get("pathPattern") for _, d in _links(f["manifest"])])),
     False),
    ("deep_link", W("deep link", "deeplink", "deep link uri", "deep link url", "deeplink uri", "deeplink url",
                    "link uri", "unlock uri", "unlock url"), _deep_link, False),
    ("deep_link_activity", W("deep link activity", "deeplink activity", "link handler", "browsable activity"),
     lambda f: _name_forms(f["manifest"].get("package"), _one([c["name"] for c, _ in _links(f["manifest"])])), False),
    ("control", W("control", "control name", "vulnerable control", "weakness"),
     lambda f: _text(_dex_match(f, r"^DAY-\d+:([a-z0-9_]+):", 1)), False),
    ("case_reference", W("case", "case reference", "case id", "case ref", "caseid"),
     lambda f: _text(_dex_match(f, r"MOB-\d+-[0-9A-F]+")), False),
    ("client_secret", W("secret", "client secret", "clientsecret"), _secret, False),
    ("backend_url", W("backend", "backend url", "backend uri", "evidence url", "endpoint", "backend endpoint",
                      "api url"), _backend, False),
    ("backend_host", W("backend host"), _backend_part("host"), False),
    ("backend_port", W("backend port", "port"), _backend_part("port"), False),
    ("attempt_ref", W("attempt id", "attempt ref", "evidence id", "backend attempt"),
     lambda f: _text(_dex_match(f, r"/attempt/([A-Za-z0-9\-]+)/", 1)), False),
    # named codec_name, not codec: mobile.codec/<name> is the key space of codec_search's routes
    ("codec_name", W("codec", "codec name", "puzzle codec", "encoding name"), lambda f: _text(f.get("codec")), False),
    ("cert_sha256", W("cert sha256", "certificate sha256", "signing sha256", "signer sha256", "signature sha256",
                      "cert fingerprint", "certificate fingerprint", "signing fingerprint"), _cert_digest("sha256"), False),
    ("cert_sha1", W("cert sha1", "certificate sha1", "signing sha1", "signer sha1", "signature sha1"), _cert_digest("sha1"), False),
    ("cert_md5", W("cert md5", "certificate md5", "signing md5", "signer md5", "signature md5"), _cert_digest("md5"), False),
    ("cert_subject", W("cert subject", "certificate subject", "signer", "signer name", "signing subject", "cert cn",
                       "certificate cn"), _cert_name("subject"), False),
    ("cert_issuer", W("cert issuer", "certificate issuer", "issuer"), _cert_name("issuer"), False),
    ("cert_serial", W("cert serial", "certificate serial", "serial"), _cert_serial, False),
    ("permission_count", W("permission count", "permissions count", "count permissions", "number permissions"),
     _count(lambda f: len(f["manifest"]["permissions"])), False),
    ("activity_count", W("activity count", "activities count", "count activities", "number activities"),
     _count(lambda f: sum(c["kind"] == "activity" for c in f["manifest"]["components"])), False),
    ("exported_count", W("exported count", "count exported", "number exported"),
     _count(lambda f: sum(1 for c in f["manifest"]["components"] if c["exported"] is True)), False),
    ("database_name", W("database", "database name", "db name", "database file", "db file", "sqlite database",
                        "sqlite db"), _database_name, False),
    ("table_name", W("table name", "sqlite table", "database table", "db table", "table"), _table_name, False),
    ("member_count", W("member count", "file count", "entry count", "count files", "count members", "count entries"),
     _count(lambda f: len(f["members"])), False),
]
for _algo in ("sha256", "sha1", "md5"):
    FACTS += [
        ("apk_" + _algo, W(_algo, "apk " + _algo, "file " + _algo, "package " + _algo, "artifact " + _algo),
         _hash_of("apk", _algo), True),
        ("dex_" + _algo, W("dex " + _algo, "classes " + _algo), _hash_of("dex", _algo), True),
        ("manifest_" + _algo, W("manifest " + _algo, "androidmanifest " + _algo), _hash_of("manifest", _algo), True),
        ("puzzle_" + _algo, W("puzzle " + _algo, "asset " + _algo), _hash_of("puzzle", _algo), True),
    ]
FACTS += [
    ("apk_size", W("size", "apk size", "file size", "size bytes", "apk size bytes", "file size bytes"), _size_of("apk"), True),
    ("dex_size", W("dex size", "dex size bytes", "classes size"), _size_of("dex"), True),
]

_STOP = {"the", "of", "a", "an", "in", "for", "this", "is", "what", "which", "value", "answer", "apk", "android",
         "app", "application", "d", "set", "mobile", "huntress", "name", "id", "string", "text"}


_NUMBERED = re.compile(r"(q|question|a|item|field|fact|n|part)?\d*")


def words(text) -> set:
    """The words of an id or a sentence: lower-case, camelCase and separators split, SHA-256 as sha256."""
    t = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", str(text))
    t = re.sub(r"(?i)\bsha[-_ ]?(1|256)\b", r"sha\1", t)
    t = re.sub(r"(?i)\bmd[-_ ]?5\b", "md5", t)
    return {w for w in re.split(r"[^a-z0-9]+", t.lower()) if w}


def match(text):
    """The one fact a text names: (name, getter, plain), or None when it names none or two.

    A word set matches when all its words are in the text. The largest matching set wins; a fact
    whose match is a subset of the winner's words is the same reading and is dropped; two facts
    left at the top are no match."""
    have = words(text)
    best = {}
    for name, sets, getter, plain in FACTS:
        size = max((len(s) for s in sets if s <= have), default=0)
        if size:
            best[name] = (size, max((s for s in sets if s <= have), key=len), getter, plain)
    if not best:
        return None
    top = max(v[0] for v in best.values())
    winners = [(n, v) for n, v in best.items() if v[0] == top]
    if len(winners) != 1:
        return None
    name, (_, _, getter, plain) = winners[0]
    return name, getter, plain


# Words that say nothing about WHICH object a hash or a size is of. Deliberately without `answer`,
# `value`, `string`, `text`, `name`, `id` (in _STOP for the unsure facts): `answer_sha256` is the
# hash of the answer, not of the package.
_PLAIN_NEUTRAL = {"the", "of", "a", "an", "this", "in", "apk", "ipa", "android", "ios", "app", "application", "package",
                  "file", "artifact", "delivery", "delivered", "sample", "evidence", "mobile", "huntress", "hash",
                  "digest", "hex", "bytes", "lower", "upper", "lowercase", "uppercase"}
_PLAIN_NUMBERED = re.compile(r"(d|day|q|question|set)?\d+")


def reading(text):
    """match(text) with the words of the text the match does not explain: (name, getter, plain, extra)
    or None. `extra` is every word outside the matched fact's own word sets."""
    got = match(text)
    if got is None:
        return None
    have = words(text)
    sets = next(s for n, s, _, _ in FACTS if n == got[0])
    explained = set().union(*[s for s in sets if s <= have])
    return got + (have - explained,)


def _scope(extra, plain) -> str:
    """'' when the left-over words say nothing more; else ':' and those words, for the label key."""
    if plain:
        loose = [w for w in extra if w not in _PLAIN_NEUTRAL and not _PLAIN_NUMBERED.fullmatch(w)]
    else:
        loose = [w for w in extra if w not in _STOP and not _NUMBERED.fullmatch(w)]
    return (":" + "-".join(sorted(loose))[:48]) if loose else ""


def _fits(q, value) -> bool:
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    rx = fmt.get("pattern") or fmt.get("regex")
    if isinstance(rx, str) and rx.strip():
        try:
            return re.fullmatch(rx, value) is not None
        except re.error:
            return False
    return True


def _syntax(q) -> str:
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    return str(fmt.get("syntax") or "")


def answer(q, facts):
    """The answer to one question: a plain value, labels.pick(...), or None. See the module text."""
    if not facts:
        return None
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    if str(fmt.get("kind") or "").lower() in ("json", "ordered_tokens", "mitre_attack_id"):
        return None     # a list or a structured value: no fact here is one
    qid = str(q.get("qid") or q.get("id") or "")
    got = reading(qid) or (reading(q.get("answer_id")) if q.get("answer_id") else None)
    scope = None
    if got is None and all(w in _STOP or _NUMBERED.fullmatch(w) for w in words(qid)):
        got = reading(q.get("question") or "")    # an id that says nothing (`q1`): the sentence is read instead
        # a sentence has many words no word set explains, so its reading is this question's own
        scope = ":q=" + (re.sub(r"[^a-z0-9_]+", "_", qid.lower()).strip("_")[:32] or "unnamed")
    if got is None:
        return None
    name, getter, plain, extra = got
    if scope is None:
        scope = _scope(extra, plain)
    key = "mobile.%s/apk%s" % (name, scope)
    try:
        value = getter(facts)
    except Exception:
        return None
    if plain:
        if not isinstance(value, str) or not value:
            return None
        if re.search(r"upper", _syntax(q), re.I) and not value.isdigit():
            value = value.upper()
        if not _fits(q, value):
            return None
        # plain only when the id names this object and nothing else (see the module text)
        return value if not scope else labels.pick(key, [("decimal" if value.isdigit() else "hex", value)])
    options = [(k, v) for k, v in (value or []) if isinstance(v, str) and v and _fits(q, v)]
    listed = [str(x) for key in ("options", "choices", "values", "enum") for x in (fmt.get(key) or [])
              if isinstance(fmt.get(key), list)]
    if listed:      # the question lists what may be answered: only a form it lists is offered
        options = [(k, v) for k, v in options if v in listed]
    return labels.pick(key, options) if options else None


def solve_questions(questions, members, blob=b"") -> dict:
    """{qid: answer} for the questions that do not ask for the ANS- code. {} for no APK.

    A ProGuard/R8 mapping.txt that ships in or beside the package is consulted FIRST, but only
    for a genuine deobfuscation question: proguard_mapping.answer returns non-None only when a
    direction word and exactly one resolvable symbol are present, so it never shadows a package
    fact. When no mapping ships (every saved fixture) the behaviour is exactly as before."""
    facts = read(members, blob)
    mapping = None
    if proguard_mapping is not None:
        try:
            mapping = proguard_mapping.read_members(members)
        except Exception:
            mapping = None
    if not facts and mapping is None:
        return {}
    out = {}
    for q in questions:
        qid = q.get("qid") or q.get("id")
        a = None
        if mapping is not None:
            try:
                a = proguard_mapping.answer(q, mapping)
            except Exception:
                a = None
        if a is None and facts:
            a = answer(q, facts)
        out[qid] = a
    return out


def main(argv) -> int:
    import io
    import zipfile
    if argv and argv[0] in ("-h", "--help"):
        print("usage: apk_facts.py <file.apk>")
        return 0
    if len(argv) != 1:
        print("apk_facts.py: expected exactly one APK", file=sys.stderr)
        return 2
    try:
        blob = Path(argv[0]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            members = {i.filename: zf.read(i) for i in zf.infolist() if not i.is_dir()}
        facts = read(members, blob)
        if not facts:
            print("not an Android package")
            return 1
        for name, _sets, getter, plain in FACTS:
            try:
                value = getter(facts)
            except Exception as e:
                value = "error %s" % type(e).__name__
            if value:
                print("%-24s %s %s" % (name, "plain " if plain else "unsure", value))
        return 0
    except Exception as exc:
        print(f"apk_facts.py: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
