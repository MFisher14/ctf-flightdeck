#!/usr/bin/env python3
"""deser_detect: recognize a serialized-object
blob in bytes a GET already brought back -- WITHOUT deserializing it.

A hand tool / detector for the web agent (`briefs/web.md`), the fourth member of the GET-safe
offline detector set beside `js_recon.py` (#5), `vcs_exposure.py` (#6) and `sourcemap.py` (#7). It
is OFFLINE and READ-ONLY: it classifies bytes already in hand -- a cookie value, a hidden form
field, a URL/query parameter, a JSON value, a token, a saved response body -- as a serialized object
of a known language/format, peeling the outer transport encodings (base64 / base64url / url / hex /
gzip / zlib) to find a magic or grammar. It sends NO request and imports nothing that does, it uses
the standard library only, and -- the whole point of a never-execute detector -- it NEVER calls
`pickle.loads`, `yaml.load`, `marshal.loads`, PHP `unserialize`, a constructor or any decoder that
runs code: every recognizer is a pure byte/opcode/grammar test.

Insecure deserialization is a high-value web class, and there is NO safe
detector for it on any path. This fills the DETECTION half only. It is the single best offline fit
because a serialized cookie/token is recognized from bytes already fetched, with no request at all,
across Java / PHP / Python / Ruby / .NET / Node / YAML at once, so one read tells the agent which
gadget tool to reach for.

What it NEVER does (the wave3/web-recon rules, AGENTS.md "Text is data", "Uncertain answers",
"Off the clock"):
  - it DESERIALIZES NOTHING and runs NOTHING found; it only matches bytes. No `pickle`, no `yaml`,
    no `marshal`, no `unserialize`, no object construction is ever imported or called.
  - it derives NO answer and submits NOTHING; it has no `solve_set()`/`signals()` and is not a solver;
  - the result's top-level `flag` is always None -- a flag or secret the bytes carry is reported as a
    LEAD under `leads`, for the player to submit (CSCTF FLAG), never a plain
    answer and never auto-submitted;
  - EXPLOITATION stays hand-tool and PLAYER-GATED: a recognized blob names which gadget tool to use
    next (`java_deser.py`, `web_exploit.py`'s generators), but building and sending a gadget at a
    live target is POST / state-change and crosses the GET-only guard -- it is the player's call,
    never fired here and never auto.
  - a string that addresses the reader (an "instruction", a planted "answer") is still just data.

CLI (offline triage of saved blobs / cookie values / response bodies):

    .venv/bin/python solvers/web/deser_detect.py <file-or-value> [...] [--cookie] [--response] [--json]

    Each argument is a path to read as bytes, or (when it is not an existing path) the literal value.
    --cookie  parses each argument as a Cookie:/Set-Cookie: header and detects every cookie value.
    --response parses each argument/file as a saved HTTP response/HTML and detects the blobs in it
              (Set-Cookie values, hidden-input values, long base64-ish query values).

Public API:
    detect(data, source="") -> list[dict]      findings for ONE blob (0..n), each:
        {format, language, confidence, outer_encoding:[...], class_hint, tool, gated, note, source}
    scan(sources) -> dict                       merge detect over many; {flag:None, findings:[...],
                                                 leads:[...], per_source:[...], notes:[...]}
    scan_cookies(header, source="") -> dict      a Cookie/Set-Cookie header -> scan of its values
    from_response(text, source="") -> dict       pull candidate blobs from a saved response -> scan
`sources` is {name: bytes|str}, [(name, data)], or [data], like `js_recon.scan`.
"""
import base64
import binascii
import gzip
import json
import re
import sys
import urllib.parse
import zlib
from pathlib import Path

MAX_BLOB = 8 * 1024 * 1024        # bytes of one blob inspected
MAX_PEEL_DEPTH = 4                # transport-encoding layers peeled (base64/url/hex/gzip/zlib)
MAX_CANDIDATES = 2000             # blobs pulled from one response
MAX_FINDINGS = 4000

# A recognized serialized blob always escalates to a hand/gated tool; detection itself is safe.
_GATED_NOTE = ("exploitation is POST/state-change and crosses the GET-only guard -- "
               "it is the player's call; this tool only recognizes the blob")


# ---- bytes / encoding peeling ----------------------------------------------------------------------

def _as_bytes(data):
    if isinstance(data, (bytes, bytearray)):
        return bytes(data[:MAX_BLOB])
    if isinstance(data, str):
        return data[:MAX_BLOB].encode("latin-1", "replace")
    return str(data or "")[:MAX_BLOB].encode("latin-1", "replace")


_B64_RX = re.compile(rb"^[A-Za-z0-9+/_\-]{8,}={0,2}$")
_HEX_RX = re.compile(rb"^[0-9A-Fa-f]{8,}$")


def _try_b64(s):
    """base64 and base64url decode of a blob that is entirely a base64 alphabet. None on any doubt."""
    t = s.strip()
    if not _B64_RX.match(t) or len(t) < 8:
        return []
    out = []
    for alt, name in ((False, "base64"), (True, "base64url")):
        canon = t.replace(b"-", b"+").replace(b"_", b"/") if alt else t
        pad = canon + b"=" * (-len(canon) % 4)
        try:
            dec = base64.b64decode(pad, validate=False)
        except (binascii.Error, ValueError):
            continue
        # require the decode to be non-trivial and to round-trip enough that it is really base64
        if len(dec) >= 3 and dec not in (s, t):
            out.append((dec, name))
    return out


def _try_url(s):
    if b"%" not in s and b"+" not in s:
        return []
    try:
        dec = urllib.parse.unquote_to_bytes(s.replace(b"+", b" "))
    except Exception:
        return []
    return [(dec, "url")] if dec and dec != s else []


def _try_hex(s):
    t = s.strip()
    if not _HEX_RX.match(t) or len(t) % 2:
        return []
    try:
        return [(binascii.unhexlify(t), "hex")]
    except (binascii.Error, ValueError):
        return []


def _try_decompress(s):
    out = []
    if s[:2] == b"\x1f\x8b":                      # gzip
        try:
            out.append((gzip.decompress(s), "gzip"))
        except (OSError, EOFError, zlib.error):
            pass
    if s[:1] in (b"\x78",):                       # zlib (common 0x78 0x9c / 0x01 / 0xda)
        try:
            out.append((zlib.decompress(s), "zlib"))
        except zlib.error:
            pass
    return out


def _peel(data):
    """Yield (bytes, [encoding chain]) for the raw blob and each transport decoding, bounded. The raw
    blob is first with an empty chain. Nothing here executes; it only decodes bytes-to-bytes."""
    raw = _as_bytes(data)
    seen = set()
    stack = [(raw, [])]
    while stack:
        cur, chain = stack.pop(0)
        key = (bytes(cur[:64]), len(cur))
        if key in seen:
            continue
        seen.add(key)
        yield cur, chain
        if len(chain) >= MAX_PEEL_DEPTH or not cur:
            continue
        nxt = []
        nxt += _try_decompress(cur)
        if not chain or chain[-1] not in ("base64", "base64url", "hex"):
            nxt += _try_b64(cur)
            nxt += _try_hex(cur)
            nxt += _try_url(cur)
        for dec, enc in nxt:
            if dec and dec != cur and len(dec) <= MAX_BLOB:
                stack.append((dec, chain + [enc]))


# ---- recognizers (pure byte/opcode/grammar tests; NONE deserialize) --------------------------------
# Each takes the already-peeled bytes `b` (stripped copy `s`) and returns a finding dict or None.

_PHP_OBJ_RX = re.compile(rb'^O:\d{1,6}:"[^"\x00]{1,256}":\d{1,6}:\{')
# A serialized CONTAINER only (array, or a length-verified string) -- lone scalars (N; b: i: d:) are
# ambiguous with ordinary text and are deliberately NOT matched, to keep the detector never-wrong.
_PHP_ARR_RX = re.compile(rb'^a:\d{1,6}:\{.*\}$', re.S)
_PHP_STR_RX = re.compile(rb'^s:(\d{1,6}):"')
_YAML_UNSAFE_RX = re.compile(
    rb'(!!python/(?:object|name|module)|!!python/object/(?:apply|new)|!ruby/(?:object|struct|hash)|'
    rb'!!(?:javax?|com\.sun|org\.(?:apache|springframework))[\w.$]*|!!map:|!<tag:[^>]+constructor)')
_JSONPICKLE_RX = re.compile(rb'"py/(?:object|reduce|type|id|newobj|function|repr|tuple|set|b64)"')
_PICKLE_PROTO = {2, 3, 4, 5}
# proto-0/1 pickle heuristic: a GLOBAL/STACK_GLOBAL or REDUCE, and the stream ends with STOP '.'
_PICKLE01_RX = re.compile(rb'(^|\n)(c[\w.]+\n[\w.]+\n|\x93|R\.|\x81)')


def _utf8_strings(b, limit=6):
    """A few readable class/token names from a Java/dotnet stream (TC_STRING-ish), for the lead only."""
    out, seen = [], set()
    for m in re.finditer(rb'[\x20-\x7e]{4,80}', b[:4096]):
        t = m.group().decode("latin-1")
        if re.search(r'[A-Za-z]', t) and t not in seen:
            seen.add(t)
            out.append(t)
            if len(out) >= limit:
                break
    return out


def _rec_java(b, s):
    # STREAM_MAGIC 0xACED + STREAM_VERSION 0x0005 -- the full 4-byte constant, which is the only
    # version Java has ever emitted; the bare 2-byte magic is too weak to be never-wrong.
    if s[:4] == b"\xac\xed\x00\x05":
        return {"format": "java_serialized_stream", "language": "java", "confidence": "high",
                "class_hint": _utf8_strings(s), "tool": "solvers/toolkits/java_deser.py (ysoserial gadget chains)",
                "note": "java serialized stream (AC ED 00 05); " + _GATED_NOTE}
    return None


def _rec_ruby(b, s):
    # Ruby Marshal major.minor = 4.8; require a plausible top type byte to cut false positives.
    if s[:2] == b"\x04\x08" and len(s) >= 3 and s[2:3] in (
            b"o", b"U", b"C", b"[", b"{", b"I", b"@", b":", b";", b"\"", b"i", b"f", b"l", b"T", b"F", b"0"):
        return {"format": "ruby_marshal", "language": "ruby", "confidence": "high",
                "class_hint": _utf8_strings(s), "tool": "ruby Marshal gadget (universal RCE chain); hand tool",
                "note": "Ruby Marshal 4.8; " + _GATED_NOTE}
    return None


def _rec_dotnet_bf(b, s):
    # BinaryFormatter SerializationHeaderRecord: 00 01 00 00 00 FF FF FF FF 01 00 00 00 00 00 00 00
    if s[:9] == b"\x00\x01\x00\x00\x00\xff\xff\xff\xff":
        return {"format": "dotnet_binaryformatter", "language": "dotnet", "confidence": "high",
                "class_hint": _utf8_strings(s),
                "tool": "ysoserial.net (gadget chains); hand tool",
                "note": ".NET BinaryFormatter stream; " + _GATED_NOTE}
    return None


def _rec_dotnet_viewstate(b, s):
    # ASP.NET __VIEWSTATE: base64 that begins /wE (0xFF 0x01 after decode). Often MAC-protected.
    if s[:3] == b"/wE":
        kind = "binary-serialized (LosFormatter/ObjectStateFormatter)" if s[:4] == b"/wEP" else "viewstate"
        return {"format": "aspnet_viewstate", "language": "dotnet", "confidence": "medium",
                "class_hint": [], "tool": "viewstate recon (check MAC/validationKey); hand tool",
                "note": f"ASP.NET {kind}; exploit only if __VIEWSTATEGENERATOR/MAC is weak or absent; " + _GATED_NOTE}
    return None


def _rec_python_pickle(b, s):
    if s[:1] == b"\x80" and len(s) >= 2 and s[1] in _PICKLE_PROTO and s[-1:] == b".":
        hints = []
        if b"\x93" in s or re.search(rb'c[\w.]+\n', s):
            hints.append("GLOBAL/STACK_GLOBAL (imports a callable)")
        if b"R" in s:
            hints.append("REDUCE (calls it)")
        return {"format": "python_pickle", "language": "python", "confidence": "high",
                "class_hint": hints or ["opcode stream"],
                "tool": "web_exploit.pickle_payload (byte generator); hand tool",
                "note": f"pickle protocol {s[1]}; " + _GATED_NOTE}
    # protocol 0/1 (text-ish) pickle: conservative -- ends with STOP, opens with a pickle opcode,
    # and parses cleanly as an opcode stream (pickletools.genops is symbolic -- it NEVER unpickles).
    if s[-1:] == b"." and s[:1] in (b"(", b"c", b"}", b"]", b")", b"\x80"):
        import pickletools
        try:
            ops = list(pickletools.genops(s))
            valid = bool(ops) and ops[-1][0].name == "STOP"
        except Exception:
            valid = False
        if valid:
            has_global = _PICKLE01_RX.search(s) is not None
            return {"format": "python_pickle", "language": "python", "confidence": "medium",
                    "class_hint": ["protocol 0/1 opcode stream"
                                   + (" with GLOBAL/REDUCE" if has_global else "")],
                    "tool": "web_exploit.pickle_payload (byte generator); hand tool",
                    "note": "pickle protocol 0/1 (opcode stream ends in STOP); " + _GATED_NOTE}
    return None


def _rec_php(b, s):
    if _PHP_OBJ_RX.match(s):
        m = re.match(rb'^O:\d+:"([^"]+)"', s)
        cls = m.group(1).decode("latin-1") if m else ""
        return {"format": "php_object_injection", "language": "php", "confidence": "high",
                "class_hint": [cls] if cls else [],
                "tool": "web_exploit.php_serialize / PhpObject / phar_payload (byte generators); hand tool",
                "note": f"PHP serialized OBJECT (class {cls!r}) -- object injection surface; " + _GATED_NOTE}
    if _PHP_ARR_RX.match(s):
        return {"format": "php_serialized", "language": "php", "confidence": "medium",
                "class_hint": [], "tool": "web_exploit.php_unserialize (parser, no construction); hand tool",
                "note": "PHP serialized array (a container, not an object by itself); " + _GATED_NOTE}
    m = _PHP_STR_RX.match(s)
    if m:
        decl = int(m.group(1))
        body = s[m.end():]
        if len(body) >= decl + 2 and body[decl:decl + 2] == b'";':
            return {"format": "php_serialized", "language": "php", "confidence": "medium",
                    "class_hint": [], "tool": "web_exploit.php_unserialize (parser, no construction); hand tool",
                    "note": "PHP serialized string (length-verified; not an object by itself); " + _GATED_NOTE}
    return None


def _rec_node(b, s):
    if b"_$$ND_FUNC$$_" in b:
        return {"format": "node_serialize", "language": "node", "confidence": "high",
                "class_hint": [], "tool": "web_exploit.node_serialize_payload (byte generator); hand tool",
                "note": "node-serialize IIFE marker (_$$ND_FUNC$$_) -- unserialize() RCE surface; " + _GATED_NOTE}
    return None


def _rec_yaml(b, s):
    m = _YAML_UNSAFE_RX.search(b)
    if m:
        return {"format": "unsafe_yaml", "language": "yaml", "confidence": "high",
                "class_hint": [m.group().decode("latin-1")],
                "tool": "web_exploit.yaml_payload (byte generator); hand tool",
                "note": "YAML unsafe constructor tag (SnakeYAML / PyYAML full load); " + _GATED_NOTE}
    if _JSONPICKLE_RX.search(b):
        return {"format": "jsonpickle", "language": "python", "confidence": "high",
                "class_hint": [], "tool": "jsonpickle object injection; hand tool",
                "note": "jsonpickle py/object marker; " + _GATED_NOTE}
    return None


_JWT_RX = re.compile(rb'^eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$')


def _rec_token_info(b, s):
    """A JWT is a TOKEN, not a serialized object: recognize it so we do NOT misfile it as deser, and
    point at the right tools. Informational only -- no action, no gate."""
    if _JWT_RX.match(s):
        return {"format": "jwt", "language": "jwt", "confidence": "high", "class_hint": [],
                "tool": "exploit_classes.classify_jwt_access / jwt_attacks (NOT deserialization)",
                "note": "JSON Web Token, not a serialized object; see the JWT tools, not the deser gadgets",
                "_informational": True}
    return None


_RECOGNIZERS = (_rec_java, _rec_ruby, _rec_dotnet_bf, _rec_dotnet_viewstate,
                _rec_python_pickle, _rec_php, _rec_node, _rec_yaml, _rec_token_info)


# ---- one blob --------------------------------------------------------------------------------------

def detect(data, source=""):
    """Classify ONE blob. Returns a list of findings (often one, sometimes zero). Never raises for
    ordinary input, never deserializes, and never derives an answer."""
    findings, seen = [], set()
    for layer, chain in _peel(data):
        s = layer.strip()
        if not s:
            continue
        for rec in _RECOGNIZERS:
            try:
                hit = rec(layer, s)
            except Exception:
                hit = None
            if not hit:
                continue
            key = (hit["format"], tuple(chain))
            if key in seen:
                continue
            seen.add(key)
            hit = dict(hit)
            hit["outer_encoding"] = list(chain)
            hit["source"] = source
            hit["gated"] = not hit.pop("_informational", False)
            findings.append(hit)
    return findings


# ---- a set of blobs --------------------------------------------------------------------------------

def _iter(sources):
    if isinstance(sources, dict):
        yield from sources.items()
    elif isinstance(sources, (list, tuple)):
        for item in sources:
            if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str):
                yield item
            else:
                yield "", item
    else:
        yield "", sources


def scan(sources):
    """Merge detect over several blobs. `flag` is always None. A finding whose `gated` is true is a
    serialized-object surface whose EXPLOITATION stays the player's; an informational one (a JWT) is
    just a pointer to the right tool."""
    findings, leads, per, notes = [], [], [], []
    for name, data in _iter(sources):
        try:
            fs = detect(data, name or "<blob>")
        except Exception as e:                      # one bad blob never sinks the rest
            notes.append(f"{name or '<blob>'}: detect error {type(e).__name__}")
            continue
        gated = [f for f in fs if f.get("gated")]
        per.append({"source": name or "<blob>", "findings": len(fs),
                    "serialized": len(gated),
                    "formats": sorted({f["format"] for f in fs})})
        findings.extend(fs)
        for f in gated:
            leads.append({"source": f["source"], "format": f["format"], "language": f["language"],
                          "confidence": f["confidence"], "outer_encoding": f["outer_encoding"],
                          "tool": f["tool"],
                          "note": "serialized-object surface; a flag/secret here is the player's for "
                                  "flag goes through the guard -- exploitation is player-gated, never auto"})
    return {
        "flag": None,                               # never derived; a serialized blob is a LEAD only
        "findings": findings[:MAX_FINDINGS],
        "leads": leads[:MAX_FINDINGS],
        "has_serialized": any(f.get("gated") for f in findings),
        "per_source": per,
        "notes": list(dict.fromkeys(notes)),
    }


# ---- cookies and saved responses -------------------------------------------------------------------

def _split_cookie_header(header):
    """Parse a Cookie:/Set-Cookie: header value into [(name, value)]. Set-Cookie attributes
    (Path, HttpOnly, Expires, ...) are dropped. Never raises."""
    text = header.decode("latin-1", "replace") if isinstance(header, (bytes, bytearray)) else str(header or "")
    text = re.sub(r'(?i)^\s*(?:set-)?cookie\s*:\s*', '', text.strip())
    pairs, attrs = [], {"path", "domain", "expires", "max-age", "samesite", "secure", "httponly",
                        "priority", "partitioned", "comment", "version"}
    for part in re.split(r'[;\n]', text):
        if "=" not in part:
            continue
        name, _, value = part.partition("=")
        name, value = name.strip(), value.strip().strip('"')
        if name and name.lower() not in attrs and value:
            pairs.append((name, value))
    return pairs


def scan_cookies(header, source=""):
    """Detect a serialized object in each cookie value of a Cookie/Set-Cookie header."""
    pairs = _split_cookie_header(header)
    return scan({f"{source}#{n}" if source else n: v for n, v in pairs})


_HIDDEN_RX = re.compile(rb'<input[^>]+type=["\']?hidden["\']?[^>]*>', re.I)
_VALUE_RX = re.compile(rb'value=["\']([^"\']{8,4000})["\']', re.I)
_NAME_RX = re.compile(rb'name=["\']([^"\']{1,120})["\']', re.I)
_SETCOOKIE_RX = re.compile(rb'(?im)^set-cookie:\s*([^\r\n]+)')
_QS_RX = re.compile(rb'[?&]([A-Za-z_][\w\-]{0,60})=([A-Za-z0-9+/_%\-]{16,4000})')


def from_response(text, source=""):
    """Pull candidate serialized blobs from a saved HTTP response / HTML (bytes a GET brought back):
    Set-Cookie values, hidden-input values, and long base64-ish query values. Offline; no request."""
    b = _as_bytes(text)
    cands = {}
    n = 0
    for m in _SETCOOKIE_RX.finditer(b):
        for name, value in _split_cookie_header(b"Set-Cookie: " + m.group(1)):
            if n >= MAX_CANDIDATES:
                break
            cands[f"{source}#cookie:{name}" if source else f"cookie:{name}"] = value
            n += 1
    for tag in _HIDDEN_RX.finditer(b):
        vm = _VALUE_RX.search(tag.group())
        nm = _NAME_RX.search(tag.group())
        if vm and n < MAX_CANDIDATES:
            key = (nm.group(1).decode("latin-1") if nm else f"hidden{n}")
            cands[f"{source}#input:{key}" if source else f"input:{key}"] = vm.group(1)
            n += 1
    for m in _QS_RX.finditer(b):
        if n >= MAX_CANDIDATES:
            break
        cands[f"{source}#qs:{m.group(1).decode('latin-1')}" if source else f"qs:{m.group(1).decode('latin-1')}"] = m.group(2)
        n += 1
    return scan(cands)


# ---- CLI -------------------------------------------------------------------------------------------

def _main(argv):
    flags = {a for a in argv if a.startswith("--")}
    args = [a for a in argv if not a.startswith("--")]
    as_json = "--json" in flags
    if not args:
        print(__doc__)
        return 64

    merged = {"flag": None, "findings": [], "leads": [], "per_source": [], "notes": []}
    for a in args:
        p = Path(a)
        try:
            data = p.read_bytes() if p.exists() else a.encode("latin-1", "replace")
            name = p.name if p.exists() else a[:40]
        except OSError as e:
            print(f"skip {a}: {e}", file=sys.stderr)
            continue
        if "--cookie" in flags:
            out = scan_cookies(data, name)
        elif "--response" in flags:
            out = from_response(data, name)
        else:
            out = scan({name: data})
        merged["findings"].extend(out["findings"])
        merged["leads"].extend(out["leads"])
        merged["per_source"].extend(out["per_source"])
        merged["notes"].extend(out["notes"])
    merged["has_serialized"] = any(f.get("gated") for f in merged["findings"])

    if as_json:
        print(json.dumps(merged, indent=2, default=str))
        return 0
    ser = sum(1 for f in merged["findings"] if f.get("gated"))
    print(f"DESER DETECT sources={len(merged['per_source'])} findings={len(merged['findings'])} "
          f"serialized={ser} flag=None")
    for f in merged["findings"]:
        enc = "+".join(f["outer_encoding"]) or "raw"
        tag = "SERIALIZED" if f.get("gated") else "info"
        print(f"  [{tag}] {f['source']}: {f['format']} ({f['language']}, {f['confidence']}) via {enc}")
        if f["class_hint"]:
            print(f"      class/hints: {', '.join(str(x) for x in f['class_hint'])}")
        print(f"      next: {f['tool']}")
        print(f"      {f['note']}")
    if merged["notes"]:
        for nt in dict.fromkeys(merged["notes"]):
            print(f"  note: {nt}")
    if ser:
        print("  (serialized-object surfaces are LEADS only -- exploitation is player-gated, "
              "never auto; a flag is the player's to submit)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
